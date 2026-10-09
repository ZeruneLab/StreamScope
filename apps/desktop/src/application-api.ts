import { invoke as nativeInvoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { AnalysisRun } from "./types";

// The same host-owned workbench is used by both builds. Core mode dispatches
// business operations only to installed, enabled and manifest-declared plugins.
const coreOnly = (import.meta as ImportMeta & { env: { MODE: string } }).env.MODE === "core";
const activeTasks = new Set<string>();
type Execution = { result: Record<string, any>; reportId: string };

async function execute(id: string, action: string, input: Record<string, unknown>): Promise<Execution> {
  const taskId = crypto.randomUUID();
  activeTasks.add(taskId);
  let unlisten = () => {};
  try {
    unlisten = await listen<{ taskId: string; progress: unknown }>("plugin-progress", (event) => {
      if (event.payload.taskId === taskId) window.dispatchEvent(new CustomEvent("workbench-progress", { detail: event.payload.progress }));
    });
    const executed = await nativeInvoke<Execution>("execute_plugin", { taskId, id: `org.streamscope.${id}`, action, input, continuation: null });
    if (executed.result.dataArtifactId) executed.result.data = await nativeInvoke("read_plugin_data", { reportId: executed.reportId, artifactId: executed.result.dataArtifactId });
    return executed;
  } finally { activeTasks.delete(taskId); unlisten(); }
}

async function readRun(reportDirectory: string, streamId?: string): Promise<AnalysisRun> {
  return nativeInvoke("read_analysis_report", { reportDirectory, streamId: streamId ?? null });
}

async function exportExecution(execution: Execution, destinationPath: string) {
  const block = execution.result.blocks?.find((item: any) => item.type === "download");
  if (!block?.artifactId) throw new Error("插件未返回可导出的产物");
  return nativeInvoke("export_plugin_artifact", { reportId: execution.reportId, artifactId: block.artifactId, destinationPath });
}

export async function invoke<T>(command: string, args: Record<string, any> = {}): Promise<T> {
  if (!coreOnly) return nativeInvoke<T>(command, args);
  if (command === "list_analysis_history") return nativeInvoke<T>("list_analysis_reports");
  if (command === "load_analysis_run") return await readRun(args.reportDirectory) as T;
  if (command === "open_report_directory" || command === "delete_report_directory") {
    return nativeInvoke<T>("manage_analysis_report", { reportDirectory: args.reportDirectory, operation: command === "open_report_directory" ? "open" : "delete" });
  }
  if (command === "cancel_analysis") {
    await Promise.all([...activeTasks].map((taskId) => nativeInvoke("cancel_plugin", { taskId })));
    return undefined as T;
  }
  if (["analyze_rtsp", "compare_rtsp", "analyze_h264_file", "analyze_h265_file", "analyze_audio_file", "analyze_pcap_file"].includes(command)) {
    const id = command.includes("rtsp") ? "rtsp" : command.split("_")[1];
    const input = id === "rtsp" ? { ...args.request, transport: command === "compare_rtsp" ? "compare" : args.request.transport }
      : { path: args.path, streamIds: (args.streamIds ?? []).join(",") };
    const executed = await execute(id, "analyze", input);
    if (command === "compare_rtsp") {
      if (!executed.result.tcpReportDirectory || !executed.result.udpReportDirectory) throw new Error("请更新 RTSP 插件以打开完整 TCP/UDP 对比工作台；对比 HTML 已保留在报告目录。");
      return { tcp: await readRun(executed.result.tcpReportDirectory), udp: await readRun(executed.result.udpReportDirectory), conclusions: executed.result.conclusions, report_directory: executed.result.reportDirectory, html: `${executed.result.reportDirectory}/comparison.html`, json: `${executed.result.reportDirectory}/comparison.json` } as T;
    }
    return await readRun(executed.result.reportDirectory) as T;
  }
  if (command === "discover_onvif") return (await execute("onvif", "discover", { timeoutSeconds: String(args.timeoutSeconds) })).result.data as T;
  if (command === "diagnose_onvif") {
    const request = args.request;
    return (await execute("onvif", "diagnose", { endpoint: request.endpoint, username: request.credentials?.username ?? "", password: request.credentials?.password ?? "", timeoutSeconds: String(request.timeout_seconds), acceptInvalidCertificates: String(request.accept_invalid_certificates) })).result.data as T;
  }
  if (command === "diagnose_sip_pcap") return (await execute("sip", "analyze", { path: args.path })).result.data as T;
  if (command === "preview_sip_replay" || command === "execute_sip_replay") {
    const sending = command === "execute_sip_replay";
    if (sending && !window.confirm(`确认向 ${args.target} 发送本次预览的 SIP 场景？`)) throw new Error("已取消发送");
    return (await execute("sip", sending ? "execute-replay" : "preview-replay", { path: args.path, callId: args.callId, captureSource: args.source, target: args.target, overrides: JSON.stringify(args.overrides ?? []), confirmSend: sending ? "true" : "false" })).result.data as T;
  }
  if (command === "probe_sip_target") return (await execute("sip", "probe", args)).result.data as T;
  if (command === "sip_simulator_status") return null as T;
  if (command === "export_sip_report" || command === "export_sip_replay_result") {
    const dataPath = await nativeInvoke<string>("stage_plugin_json", { data: args.report ?? args.result });
    const exported = await execute("sip", "export-evidence", { dataPath, redacted: String(args.redacted ?? false) });
    return await exportExecution(exported, args.path) as T;
  }
  if (command === "export_media") {
    const request = args.request;
    if (request.mediaType === "video") return nativeInvoke<T>("save_report_file", { sourcePath: request.sourcePath, destinationPath: request.destinationPath });
    return await exportExecution(await execute("audio", "export-audio", { path: request.sourcePath, format: request.format, startMs: request.startMs, endMs: request.endMs }), request.destinationPath) as T;
  }
  if (command === "export_audio_evidence") {
    const request = args.request;
    return await exportExecution(await execute("audio", "export-evidence", { format: request.format, issues: JSON.stringify(request.issues), intervals: JSON.stringify(request.intervals) }), request.destinationPath) as T;
  }
  if (["extract_video_frame", "analyze_video_frame_blocks", "load_video_frame_syntax", "export_video_block_csv", "compare_video_reference"].includes(command)) {
    const run = await readRun(args.reportDirectory, args.streamId);
    const execution = await execute("video-deep", "report-tools", {
      operation: command, path: run.result.request.source_path,
      reportPath: run.reports.json, displayIndex: args.displayIndex ?? 0, referencePath: args.referencePath ?? "",
      sourceReport: args.reportDirectory, sourceStream: args.streamId ?? "",
    });
    if (command === "export_video_block_csv") return await exportExecution(execution, args.destinationPath) as T;
    return execution.result.data as T;
  }
  if (command === "load_video_reference_comparison" || command === "load_video_reference_difference") {
    return nativeInvoke<T>("read_analysis_attachment", { reportDirectory: args.reportDirectory, streamId: args.streamId ?? "", kind: command === "load_video_reference_comparison" ? "comparison" : "difference" });
  }
  return nativeInvoke<T>(command, args);
}
