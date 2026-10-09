import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import type { Contribution, Installed } from "./PluginManager";
import { PluginResult, type ContinueAnalysis } from "./PluginResult";
import "./plugin-ui.css";

type Component =
  | { type: "text"; text: string }
  | { type: "input"; id: string; label: string; inputType: "text" | "password" | "number" | "file" | "checkbox"; required: boolean }
  | { type: "select"; id: string; label: string; options: string[]; required: boolean }
  | { type: "output"; title: string };
type UiDocument = { schemaVersion: number; views: { id: string; title: string; components: Component[] }[] };
type PluginExecution = { result: unknown; reportId: string };
export type PreparedContinuation = {
  reference: { reportId: string; actionId: string }; pluginId: string; contributionId: string;
  fields: Record<string, string>; context: string; nonce: string; sourcePage: string;
};
const fileExtensions: Record<string, string[]> = {
  "org.streamscope.pcap": ["pcap", "pcapng", "cap"],
  "org.streamscope.h264": ["h264", "264", "avc"],
  "org.streamscope.h265": ["h265", "265", "hevc"],
  "org.streamscope.audio": ["wav", "mp3", "aac", "m4a", "flac", "ogg", "opus", "pcm", "alaw", "mulaw", "g722", "g726", "g723", "g729"],
  "org.streamscope.video-deep": ["h264", "264", "avc", "h265", "265", "hevc", "mp4", "mkv", "ts", "avi"],
};

export function PluginFields({ components, fields, busy, onChange, onPickFile }: {
  components: Component[]; fields: Record<string, string>; busy: boolean;
  onChange: (id: string, value: string) => void; onPickFile: (id: string) => void;
}) {
  return <div className="plugin-form-grid">{components.map((component) => {
    if (component.type !== "input" && component.type !== "select") return null;
    const file = component.type === "input" && component.inputType === "file";
    const wide = file || (component.type === "input" && (component.inputType === "checkbox"
      || (component.inputType === "text" && /URL|URI|地址|路径/i.test(component.label))));
    return <label key={component.id} className={`plugin-field ${wide ? "plugin-field-wide" : ""}`}>
      <span>{component.label}{component.required && <em aria-label="必填">*</em>}</span>
      {component.type === "select" ?
        <select disabled={busy} value={fields[component.id] ?? ""} onChange={(event) => onChange(component.id, event.target.value)}>
          <option value="">请选择</option>{component.options.map((option) => <option key={option} value={option}>{option}</option>)}
        </select> : component.inputType === "checkbox" ?
        <span className="plugin-checkbox"><input disabled={busy} type="checkbox" checked={fields[component.id] === "true"} onChange={(event) => onChange(component.id, String(event.target.checked))} />允许</span> : file ?
        <span className="plugin-file-picker"><input disabled={busy} readOnly value={fields[component.id] ?? ""} placeholder="请选择要分析的文件" title={fields[component.id] ?? ""} />
          <button disabled={busy} type="button" onClick={() => onPickFile(component.id)}>选择文件</button></span> :
        <input disabled={busy} type={component.inputType} value={fields[component.id] ?? ""} onChange={(event) => onChange(component.id, event.target.value)} />}
    </label>;
  })}</div>;
}

export function PluginView({ plugin, contribution, onOpenAnalysis, onRunningChange, onContinue, continuation, active = true, onReturnToSource }: {
  plugin: Installed; contribution: Contribution; onOpenAnalysis?: (directory: string) => void; onRunningChange?: (running: boolean) => void;
  onContinue?: ContinueAnalysis; continuation?: PreparedContinuation | null; active?: boolean; onReturnToSource?: (page: string) => void;
}) {
  const [ui, setUi] = useState<UiDocument | null>(null);
  const [fields, setFields] = useState<Record<string, string>>({});
  const [output, setOutput] = useState<unknown>(null);
  const [reportId, setReportId] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [taskId, setTaskId] = useState("");
  const [progress, setProgress] = useState<{ percent?: number; stage?: string; detail?: string } | null>(null);
  const [source, setSource] = useState<PreparedContinuation | null>(null);
  const [appliedContinuation, setAppliedContinuation] = useState("");
  const previous = useRef<{ fields: Record<string, string>; output: unknown; reportId: string; source: PreparedContinuation | null }[]>([]);

  useEffect(() => { onRunningChange?.(busy); }, [busy, onRunningChange]);

  useEffect(() => {
    const unlisten = listen<{ taskId: string; progress: { percent?: number; stage?: string; detail?: string } }>("plugin-progress", (event) => {
      if (event.payload.taskId === taskId) setProgress(event.payload.progress);
    });
    return () => { void unlisten.then((dispose) => dispose()); };
  }, [taskId]);

  useEffect(() => {
    setUi(null);
    invoke<UiDocument>("load_plugin_ui", { id: plugin.manifest.id }).then(setUi).catch((reason) => setError(String(reason)));
  }, [plugin.manifest.id, contribution.id]);

  const view = ui?.views.find((candidate) => candidate.id === contribution.view);

  useEffect(() => {
    if (!continuation) return;
    if (output !== null) {
      const safeFields = { ...fields };
      view?.components.forEach((component) => { if (component.type === "input" && component.inputType === "password") delete safeFields[component.id]; });
      previous.current.push({ fields: safeFields, output, reportId, source });
      previous.current = previous.current.slice(-10);
    }
    setFields(continuation.fields); setSource(continuation); setAppliedContinuation(continuation.nonce); setOutput(null); setReportId(""); setError("");
  }, [continuation?.nonce]);

  useEffect(() => {
    if (active || !view) return;
    setFields((current) => {
      const next = { ...current };
      view.components.forEach((component) => { if (component.type === "input" && component.inputType === "password") next[component.id] = ""; });
      return next;
    });
  }, [active, view]);
  const preparingInput = Boolean(continuation && appliedContinuation !== continuation.nonce);

  async function execute() {
    if (!view || preparingInput) return;
    const required = view.components.filter((component): component is Extract<Component, { type: "input" | "select" }> => (component.type === "input" || component.type === "select") && component.required);
    const missing = required.find((component) => !fields[component.id]?.trim());
    if (missing) { setError(`请填写 ${missing.label}`); return; }
    setError("");
    setOutput(null);
    setBusy(true);
    setProgress(null);
    const startedTaskId = crypto.randomUUID();
    setTaskId(startedTaskId);
    try {
      const completed = await invoke<PluginExecution>("execute_plugin", { taskId: startedTaskId, id: plugin.manifest.id, action: contribution.action, input: fields, continuation: source?.reference ?? null });
      setOutput(completed.result);
      setReportId(completed.reportId);
    } catch (reason) { setError(String(reason)); }
    finally {
      setBusy(false);
      setTaskId("");
      const passwordFields = view.components.filter((component): component is Extract<Component, { type: "input" }> => component.type === "input" && component.inputType === "password");
      setFields((current) => {
        const next = { ...current };
        passwordFields.forEach((component) => { next[component.id] = ""; });
        return next;
      });
    }
  }

  return <>
    <section className="panel plugin-panel">
      <div className="panel-heading"><div><span className="step">01</span><h2>分析参数</h2></div>
        <span className="plugin-badge">插件 v{plugin.manifest.version}</span></div>
      <div className="plugin-meta"><span>{view?.title ?? contribution.title}</span><span>· {plugin.manifest.publisher.id}</span></div>
      {view?.components.filter((component) => component.type === "text").map((component, index) =>
        component.type === "text" && <p key={index} className="plugin-muted">{component.text}</p>)}
      {!ui && !error && <p role="status">正在加载分析参数…</p>}
      {source && <div className="plugin-workflow-source"><strong>已关联来源媒体流</strong><p>{source.context}</p>
        <span className="plugin-muted">输入为该流的只读任务产物；可调整帧序号或导出格式后执行。</span>
        {source.sourcePage !== `${plugin.manifest.id}:${contribution.id}` && <button type="button" disabled={busy} onClick={() => onReturnToSource?.(source.sourcePage)}>返回来源分析</button>}
      </div>}
      <PluginFields components={view?.components ?? []} fields={fields} busy={busy || preparingInput}
        onChange={(id, value) => setFields((current) => ({ ...current, [id]: value }))}
        onPickFile={(id) => { const extensions = fileExtensions[plugin.manifest.id]; void open({ multiple: false, directory: false,
          filters: extensions ? [{ name: "支持的分析文件", extensions }] : undefined }).then((path) => {
          if (path) { setFields((current) => ({ ...current, [id]: path })); setSource(null); }
        }).catch((reason) => setError(String(reason))); }} />
      {error && <p role="alert">{error}</p>}
      {busy && <div className="plugin-progress" role="status">
        <progress max={100} value={progress?.percent == null ? undefined : Math.max(0, Math.min(100, progress.percent))} />
        <p>{progress?.percent == null ? "执行中" : `${progress.percent}%`} · {progress?.stage ?? "正在分析"} {progress?.detail ?? ""}</p>
      </div>}
      <div className="plugin-actions">
        {previous.current.length > 0 && <button type="button" disabled={busy} onClick={() => {
          const saved = previous.current.pop();
          if (saved) { setFields(saved.fields); setOutput(saved.output); setReportId(saved.reportId); setSource(saved.source); setError(""); }
        }}>返回上一份分析结果</button>}
        {busy && <button type="button" onClick={() => { void invoke("cancel_plugin", { taskId }).catch((reason) => setError(String(reason))); }}>取消任务</button>}
        <button className="plugin-primary" type="button" disabled={busy || preparingInput || !view} onClick={() => { void execute(); }}>{busy ? "正在执行…" : preparingInput ? "正在关联样本…" : "▶ 开始执行"}</button>
      </div>
    </section>
    <section className="panel plugin-panel">
      <div className="panel-heading"><div><span className="step">02</span><h2>{view?.components.find((component) => component.type === "output")?.title ?? "分析结果"}</h2></div>
        {output !== null && <span className="plugin-badge">报告已保存</span>}</div>
      {output === null ? <div className="plugin-empty"><strong>{busy ? "分析正在进行" : "等待一次分析任务"}</strong><p>填写上方参数并执行，结果和报告将在此显示。</p></div> :
        <PluginResult value={output} reportId={reportId} onContinue={busy ? undefined : onContinue} />}
      {reportId && output !== null && <p className="plugin-muted">报告编号：{reportId}</p>}
      {onOpenAnalysis && output !== null && typeof output === "object" && typeof (output as Record<string, unknown>).reportDirectory === "string" &&
        <div className="plugin-actions"><button type="button" onClick={() => onOpenAnalysis?.((output as Record<string, string>).reportDirectory)}>打开完整分析报告</button></div>}
    </section>
  </>;
}
