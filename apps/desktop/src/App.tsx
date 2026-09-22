import { FormEvent, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { convertFileSrc, invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { open, save } from "@tauri-apps/plugin-dialog";
import { Activity, ArrowLeft, Cctv, FileVideo, Film, Maximize2, Minus, Music, Network, Play, X } from "lucide-react";
import { CaptureStreams } from "./CaptureStreams";
import OnvifDiagnostics from "./OnvifDiagnostics";
import type {
  AnalysisProgress,
  AnalysisRun,
  AnalysisStatus,
  ComparisonRun,
  RecentRun,
  VideoDeepAnalysis,
  VideoNaluEvidence,
  VideoParameterChange,
  VideoRecoveryWindow,
  VideoReferenceComparison,
  VideoSyntaxDocument,
  VideoWorkerFrame,
} from "./types";

type View = "overview" | "playback" | "audioQuality" | "protocol" | "stream" | "videoDeep" | "diagnostics" | "timeline" | "report" | "log";
type InputMode = "rtsp" | "h264" | "h265" | "audio" | "pcap" | "onvif";
type TransportMode = "tcp" | "udp" | "compare";
type AudioExportFormat = "wav" | "mp3" | "m4a" | "flac" | "ogg";

const audioExportFormats: Array<{ value: AudioExportFormat; label: string; extension: string }> = [
  { value: "wav", label: "WAV（无损 PCM）", extension: "wav" },
  { value: "mp3", label: "MP3", extension: "mp3" },
  { value: "m4a", label: "M4A（AAC）", extension: "m4a" },
  { value: "flac", label: "FLAC（无损）", extension: "flac" },
  { value: "ogg", label: "Ogg（Opus）", extension: "ogg" },
];

function saveHistory(run: AnalysisRun, previous: RecentRun[]): RecentRun[] {
  const next = [
    {
      generatedAt: run.result.generated_at,
      sourceUrl: run.result.request.source_url,
      status: run.result.status,
      reportDirectory: run.report_directory,
      criticalCount: [run.result, ...(run.result.streams ?? [])].reduce((count, result) => count + result.diagnostics.filter((item) => item.severity === "critical" || item.severity === "high").length, 0),
    },
    ...previous,
  ].slice(0, 8);
  return next;
}

function statusText(status: AnalysisStatus): string {
  return {
    completed: "分析完成",
    partial: "部分完成",
    failed: "分析失败",
  }[status];
}

function formatBitRate(value: number | null | undefined): string {
  if (!value) return "—";
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)} Mbps`;
  return `${Math.round(value / 1_000)} Kbps`;
}

function formatDuration(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return value >= 1_000 ? `${(value / 1_000).toFixed(2)} s` : `${value} ms`;
}

function App() {
  const [url, setUrl] = useState("");
  const [inputMode, setInputMode] = useState<InputMode>("rtsp");
  const [offlinePath, setOfflinePath] = useState("");
  const [transport, setTransport] = useState<TransportMode>("tcp");
  const [duration, setDuration] = useState(10);
  const [connectTimeout, setConnectTimeout] = useState(10);
  const [running, setRunning] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [error, setError] = useState("");
  const [run, setRun] = useState<AnalysisRun | null>(null);
  const [selectedStreamId, setSelectedStreamId] = useState<string | null>(null);
  const [comparison, setComparison] = useState<ComparisonRun | null>(null);
  const [reportHtml, setReportHtml] = useState("");
  const [view, setView] = useState<View>("overview");
  const [history, setHistory] = useState<RecentRun[]>([]);
  const [progress, setProgress] = useState<AnalysisProgress | null>(null);
  const [audioExportFormat, setAudioExportFormat] = useState<AudioExportFormat>("wav");
  const [exporting, setExporting] = useState(false);
  const [exportMessage, setExportMessage] = useState("");
  const [pendingAudioSeek, setPendingAudioSeek] = useState<number | null>(null);
  const [requestedVideoFrame, setRequestedVideoFrame] = useState(0);
  const [selectedAudioTrackId, setSelectedAudioTrackId] = useState<string | null>(null);
  const reportFrame = useRef<HTMLIFrameElement>(null);
  const previewVideo = useRef<HTMLVideoElement>(null);
  const previewAudio = useRef<HTMLAudioElement>(null);
  const navRef = useRef<HTMLElement>(null);
  const tabsRef = useRef<HTMLDivElement>(null);

  const isDesktop = "__TAURI_INTERNALS__" in window;
  // 切换输入源时清空上一模式的结果，保证每个入口的分析结果互不串台
  function switchMode(mode: InputMode) {
    if (mode === inputMode) return;
    setInputMode(mode);
    setOfflinePath("");
    setRun(null);
    setComparison(null);
    setReportHtml("");
    setProgress(null);
    setError("");
    setSelectedStreamId(null);
    setExportMessage("");
    setView("overview");
  }

  async function windowAction(action: "close" | "minimize" | "fullscreen") {
    if (!isDesktop) return;
    const win = getCurrentWindow();
    if (action === "close") await win.close();
    else if (action === "minimize") await win.minimize();
    else await win.setFullscreen(!(await win.isFullscreen()));
  }

  // 滑动指示器：测量活动项位置并写入容器 CSS 变量
  useLayoutEffect(() => {
    const syncIndicator = (container: HTMLElement | null, selector: string) => {
      if (!container) return;
      const active = container.querySelector<HTMLElement>(selector);
      if (!active) {
        container.style.setProperty("--indicator-opacity", "0");
        return;
      }
      container.style.setProperty("--indicator-x", `${active.offsetLeft}px`);
      container.style.setProperty("--indicator-y", `${active.offsetTop}px`);
      container.style.setProperty("--indicator-w", `${active.offsetWidth}px`);
      container.style.setProperty("--indicator-h", `${active.offsetHeight}px`);
      container.style.setProperty("--indicator-opacity", "1");
    };
    const syncAll = () => {
      syncIndicator(navRef.current, ".nav-item.active");
      syncIndicator(tabsRef.current, ".tabs button.active");
    };
    const frame = requestAnimationFrame(syncAll);
    window.addEventListener("resize", syncAll);
    return () => { cancelAnimationFrame(frame); window.removeEventListener("resize", syncAll); };
  }, [inputMode, view, run]);


  useEffect(() => {
    invoke<RecentRun[]>("list_analysis_history").then(setHistory).catch(() => undefined);
    const unlisten = listen<AnalysisProgress>("analysis-progress", (event) => setProgress(event.payload));
    return () => { void unlisten.then((dispose) => dispose()); };
  }, []);

  const health = useMemo(() => {
    if (!run) return { label: "等待分析", className: "neutral" };
    return {
      label: statusText(run.result.status),
      className: run.result.status,
    };
  }, [run]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    setRunning(true);
    setRun(null);
    setSelectedStreamId(null);
    setComparison(null);
    setReportHtml("");
    setProgress({ percent: 0, stage: "准备", detail: "正在启动分析任务" });
    setExportMessage("");
    setView("overview");
    try {
      let completed: AnalysisRun;
      if (inputMode === "rtsp" && transport === "compare") {
        const compared = await invoke<ComparisonRun>("compare_rtsp", {
          request: { url, transport: "tcp", durationSeconds: duration, connectTimeoutSeconds: connectTimeout },
        });
        setComparison(compared);
        completed = compared.tcp;
        setHistory((current) => saveHistory(compared.udp, saveHistory(compared.tcp, current)));
      } else if (inputMode === "rtsp") {
        completed = await invoke<AnalysisRun>("analyze_rtsp", {
          request: { url, transport, durationSeconds: duration, connectTimeoutSeconds: connectTimeout },
        });
        setHistory((current) => saveHistory(completed, current));
      } else {
        const command = inputMode === "h264" ? "analyze_h264_file" : inputMode === "h265" ? "analyze_h265_file" : inputMode === "audio" ? "analyze_audio_file" : "analyze_pcap_file";
        completed = await invoke<AnalysisRun>(command, { path: offlinePath });
        setHistory((current) => saveHistory(completed, current));
      }
      setRun(completed);
      if (completed.result.preview_video || completed.result.preview_audio) setView("playback");
    } catch (reason) {
      setError(String(reason));
    } finally {
      setRunning(false);
      setCancelling(false);
    }
  }

  async function cancelCurrentAnalysis() {
    if (!running || cancelling) return;
    setCancelling(true);
    setProgress((current) => ({
      percent: current?.percent ?? 0,
      stage: "正在取消",
      detail: "正在停止采集、解析和外部解码进程",
    }));
    try {
      await invoke("cancel_analysis");
    } catch (reason) {
      setCancelling(false);
      setError(`取消任务失败：${String(reason)}`);
    }
  }

  async function chooseOfflineFile() {
    setError("");
    try {
      const filter = inputMode === "h264"
        ? { name: "H.264 Annex B", extensions: ["h264", "264", "avc"] }
        : inputMode === "h265"
          ? { name: "H.265 / HEVC Annex B", extensions: ["h265", "265", "hevc"] }
          : inputMode === "audio"
            ? { name: "音频文件", extensions: ["wav", "flac", "aac", "m4a", "mp3", "ogg", "opus", "g722", "g723", "g7231", "g723_1", "g729", "g726", "g726le", "g726-16", "g726-24", "g726-32", "g726-40", "g726le-16", "g726le-24", "g726le-32", "g726le-40", "aal2-g726-16", "aal2-g726-24", "aal2-g726-32", "aal2-g726-40"] }
          : { name: "网络抓包", extensions: ["pcap", "pcapng"] };
      const selected = await open({ multiple: false, directory: false, filters: [filter] });
      if (selected) setOfflinePath(selected);
    } catch (reason) {
      setError(`无法打开文件选择器：${String(reason)}`);
    }
  }

  async function analyzeCaptureStreams(streamIds: string[]) {
    if (!run?.result.request.source_path || running) return;
    setError("");
    setRunning(true);
    setProgress({ percent: 0, stage: "深入分析", detail: "重新扫描抓包并依次解码所选流，生成新任务报告" });
    try {
      const completed = await invoke<AnalysisRun>("analyze_pcap_file", { path: run.result.request.source_path, streamIds });
      setRun(completed);
      setSelectedStreamId(streamIds.length === 1 && streamIds[0] !== "*" ? streamIds[0] : null);
      setReportHtml("");
      setView(streamIds.length === 1 && streamIds[0] !== "*" ? "playback" : "overview");
      setHistory((current) => saveHistory(completed, current));
    } catch (reason) {
      setError(`深入分析失败：${String(reason)}`);
    } finally {
      setRunning(false);
    }
  }

  async function showReport() {
    if (!run) return;
    setView("report");
    await previewReport(selectedStreamId);
  }

  async function previewReport(streamId: string | null) {
    if (!run) return;
    setReportHtml("");
    try {
      const html = await invoke<string>("load_report_html", {
        reportPath: streamId ? `${run.report_directory.replace(/[\\/]+$/, "")}\\streams\\${streamId}\\report.html` : comparison?.html ?? run.reports.html,
      });
      setSelectedStreamId(streamId);
      setReportHtml(html);
    } catch (reason) {
      setError(`无法加载报告：${String(reason)}`);
    }
  }

  async function openHistory(item: RecentRun) {
    setError("");
    setRunning(true);
    setReportHtml("");
    setComparison(null);
    setSelectedStreamId(null);
    setView("overview");
    try {
      const loaded = await invoke<AnalysisRun>("load_analysis_run", {
        reportDirectory: item.reportDirectory,
      });
      if (loaded.result.request.source_kind === "pcap") setInputMode("pcap");
      else if (loaded.result.request.source_kind === "h264") setInputMode("h264");
      else if (loaded.result.request.source_kind === "h265") setInputMode("h265");
      else if (loaded.result.request.source_kind === "audio") setInputMode("audio");
      else setInputMode("rtsp");
      setRun(loaded);
    } catch (reason) {
      setError(`无法打开历史报告：${String(reason)}`);
    } finally {
      setRunning(false);
    }
  }

  async function openReportDirectory() {
    if (!run) return;
    try {
      await invoke("open_report_directory", { reportDirectory: comparison?.report_directory ?? run.report_directory });
    } catch (reason) {
      setError(`无法打开报告目录：${String(reason)}`);
    }
  }

  async function deleteHistoryReport(item: RecentRun) {
    if (!window.confirm("确定删除这份诊断报告吗？报告目录及其中日志将被永久删除。")) return;
    try {
      await invoke("delete_report_directory", { reportDirectory: item.reportDirectory });
      setHistory((current) => current.filter((entry) => entry.reportDirectory !== item.reportDirectory));
      if (run?.report_directory === item.reportDirectory) {
        setRun(null);
        setComparison(null);
        setReportHtml("");
      }
    } catch (reason) {
      setError(`无法删除报告：${String(reason)}`);
    }
  }

  async function deleteCurrentReport() {
    if (!run) return;
    const directories = comparison
      ? [comparison.report_directory, comparison.tcp.report_directory, comparison.udp.report_directory]
      : [run.report_directory];
    const message = comparison
      ? "确定删除本次 TCP/UDP 对比及两份子报告吗？该操作不可恢复。"
      : "确定删除当前报告目录及其中日志吗？该操作不可恢复。";
    if (!window.confirm(message)) return;
    try {
      for (const reportDirectory of [...new Set(directories)]) {
        await invoke("delete_report_directory", { reportDirectory });
      }
      setHistory((current) => current.filter((entry) => !directories.includes(entry.reportDirectory)));
      setRun(null);
      setComparison(null);
      setReportHtml("");
      setView("overview");
    } catch (reason) {
      setError(`无法删除报告：${String(reason)}`);
    }
  }

  const selectedResult = run?.result.streams?.find((item) => item.capture_stream?.id === selectedStreamId);
  const result = selectedResult ?? run?.result;
  const capture = run?.result.capture_summary;
  const identity = selectedResult?.capture_stream;
  const captureOverview = Boolean(capture && !selectedResult);
  const legacyCapture = run?.result.request.source_kind === "pcap" && !capture && !run.result.capture_stream;
  const stream = result?.stream;
  const decode = result?.decode;
  const protocol = result?.protocol;
  const h264 = result?.h264;
  const h265 = result?.h265;
  const videoDeep = h264?.deep_analysis ?? h265?.deep_analysis;
  const audioTracks = result?.audio_tracks ?? [];
  const selectedAudioTrack = audioTracks.find((track) => track.id === selectedAudioTrackId) ?? audioTracks[0];
  const audio = selectedAudioTrack?.analysis ?? result?.audio;
  const audioQuality = audio?.quality;
  const quality = result?.data_quality;
  const previewSource = result?.preview_video ? convertFileSrc(result.preview_video) : null;
  const previewAudioPath = selectedAudioTrack?.preview_audio ?? result?.preview_audio;
  const audioExportSource = selectedAudioTrack?.export_source ?? previewAudioPath;
  const previewAudioSource = previewAudioPath ? convertFileSrc(previewAudioPath) : null;

  useEffect(() => {
    setSelectedAudioTrackId(null);
  }, [run?.report_directory, selectedStreamId]);

  useEffect(() => {
    if (view !== "playback" || pendingAudioSeek === null) return;
    const timer = window.setTimeout(() => {
      const player = previewAudio.current;
      if (!player) return;
      player.currentTime = pendingAudioSeek / 1_000;
      void player.play();
      setPendingAudioSeek(null);
    }, 0);
    return () => window.clearTimeout(timer);
  }, [view, pendingAudioSeek, previewAudioSource]);
  const playbackSync = result?.av_sync?.find((item) => item.offset_ms !== null && item.confidence_percent >= 80 && (!selectedAudioTrack || item.audio_stream_id === selectedAudioTrack.id));
  const rtspStatusSummary = (method: string) => {
    const statuses = protocol?.transactions.filter((item) => item.method === method).map((item) => item.status_code) ?? [];
    const unique = [...new Set(statuses)];
    if (unique.length === 0) return "—";
    const text = unique.map((status) => status === 0 ? "无响应" : status.toString()).join(" / ");
    return unique.length > 1 ? `${text}（不一致）` : text;
  };
  const protocolPacketCount = captureOverview
    ? (run?.result.streams ?? []).reduce((total, item) => total + (item.protocol?.rtp.packet_count ?? 0), 0)
    : protocol?.rtp.packet_count ?? 0;
  const videoClockRate = identity ? identity.clock_rate : protocol?.media.find((item) => item.media_type === "video")?.clock_rate ?? 90_000;
  const jitterMs = protocol && videoClockRate ? protocol.rtp.jitter * 1000 / videoClockRate : null;

  async function playWithRtcpClock() {
    const video = previewVideo.current;
    const audioElement = previewAudio.current;
    if (!video || !audioElement || playbackSync?.offset_ms === null || playbackSync?.offset_ms === undefined) return;
    const offsetSeconds = playbackSync.offset_ms / 1_000;
    video.pause();
    audioElement.pause();
    video.currentTime = Math.max(0, offsetSeconds);
    audioElement.currentTime = Math.max(0, -offsetSeconds);
    await Promise.allSettled([video.play(), audioElement.play()]);
  }

  function correctPreviewClock() {
    const video = previewVideo.current;
    const audioElement = previewAudio.current;
    if (!video || !audioElement || video.paused || audioElement.paused || playbackSync?.offset_ms === null || playbackSync?.offset_ms === undefined) return;
    const expectedVideoTime = audioElement.currentTime + playbackSync.offset_ms / 1_000;
    if (expectedVideoTime >= 0 && Math.abs(video.currentTime - expectedVideoTime) > 0.25) {
      video.currentTime = expectedVideoTime;
    }
  }

  async function exportVideoSample() {
    if (!result?.preview_video || exporting) return;
    setError("");
    setExportMessage("");
    const selected = await save({
      defaultPath: `StreamScope-${identity?.id ?? "video"}.mp4`,
      filters: [{ name: "MP4 视频", extensions: ["mp4"] }],
    });
    if (!selected) return;
    const destinationPath = selected.toLowerCase().endsWith(".mp4") ? selected : `${selected}.mp4`;
    setExporting(true);
    try {
      const exported = await invoke<string>("export_media", {
        request: { sourcePath: result.preview_video, destinationPath, mediaType: "video", format: "mp4" },
      });
      setExportMessage(`视频已导出：${exported}`);
    } catch (reason) {
      setError(`视频导出失败：${String(reason)}`);
    } finally {
      setExporting(false);
    }
  }

  async function exportAudioSample(range?: { startMs: number; endMs: number }) {
    if (!audioExportSource || exporting) return;
    setError("");
    setExportMessage("");
    const option = audioExportFormats.find((item) => item.value === audioExportFormat)!;
    const selected = await save({
      defaultPath: `StreamScope-${selectedAudioTrack?.id ?? identity?.id ?? "audio"}${range ? `-${range.startMs}-${range.endMs}ms` : ""}.${option.extension}`,
      filters: [{ name: option.label, extensions: [option.extension] }],
    });
    if (!selected) return;
    const suffix = `.${option.extension}`;
    const destinationPath = selected.toLowerCase().endsWith(suffix) ? selected : `${selected}${suffix}`;
    setExporting(true);
    try {
      const exported = await invoke<string>("export_media", {
        request: { sourcePath: audioExportSource, destinationPath, mediaType: "audio", format: audioExportFormat, startMs: range?.startMs, endMs: range?.endMs },
      });
      setExportMessage(`${range ? "异常区间" : "音频"}已导出：${exported}`);
    } catch (reason) {
      setError(`音频导出失败：${String(reason)}`);
    } finally {
      setExporting(false);
    }
  }

  async function exportAudioEvidence(
    issues: AudioIssueEvidence[],
    intervals: AudioQualityIntervalEvidence[],
    scope: string,
  ) {
    if (exporting || (issues.length === 0 && intervals.length === 0)) return;
    setError("");
    setExportMessage("");
    const selected = await save({
      defaultPath: `StreamScope-${selectedAudioTrack?.id ?? identity?.id ?? "audio"}-${scope}.csv`,
      filters: [
        { name: "CSV 表格", extensions: ["csv"] },
        { name: "JSON 证据", extensions: ["json"] },
      ],
    });
    if (!selected) return;
    const lower = selected.toLowerCase();
    const format = lower.endsWith(".json") ? "json" : "csv";
    const destinationPath = lower.endsWith(`.${format}`) ? selected : `${selected}.${format}`;
    setExporting(true);
    try {
      const exported = await invoke<string>("export_audio_evidence", {
        request: { destinationPath, format, issues, intervals },
      });
      setExportMessage(`音频证据已导出：${exported}`);
    } catch (reason) {
      setError(`音频证据导出失败：${String(reason)}`);
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="traffic-lights" data-tauri-drag-region>
          <button className="tl tl-close" type="button" title="关闭" aria-label="关闭窗口" onClick={() => { void windowAction("close"); }}><X size={9} strokeWidth={2.8} /></button>
          <button className="tl tl-min" type="button" title="最小化" aria-label="最小化窗口" onClick={() => { void windowAction("minimize"); }}><Minus size={9} strokeWidth={2.8} /></button>
          <button className="tl tl-max" type="button" title="全屏" aria-label="切换全屏" onClick={() => { void windowAction("fullscreen"); }}><Maximize2 size={8} strokeWidth={2.8} /></button>
          <span className="drag-spacer" data-tauri-drag-region />
        </div>
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            <i />
            <i />
            <i />
          </span>
          <div>
            <strong>StreamScope</strong>
            <small>智能码流诊断</small>
          </div>
        </div>

        <nav aria-label="主导航" ref={navRef}>
          <span className="nav-indicator" aria-hidden="true" />
          <button className={`nav-item ${inputMode === "rtsp" ? "active" : ""}`} type="button" onClick={() => switchMode("rtsp")}>
            <span className="nav-icon"><Activity size={17} strokeWidth={1.75} /></span>实时分析
          </button>
          <button className={`nav-item ${inputMode === "h264" ? "active" : ""}`} type="button" onClick={() => switchMode("h264")}>
            <span className="nav-icon"><FileVideo size={17} strokeWidth={1.75} /></span>H.264 文件
          </button>
          <button className={`nav-item ${inputMode === "h265" ? "active" : ""}`} type="button" onClick={() => switchMode("h265")}>
            <span className="nav-icon"><Film size={17} strokeWidth={1.75} /></span>H.265 / HEVC
          </button>
          <button className={`nav-item ${inputMode === "audio" ? "active" : ""}`} type="button" onClick={() => switchMode("audio")}>
            <span className="nav-icon"><Music size={17} strokeWidth={1.75} /></span>音频文件
          </button>
          <button className={`nav-item ${inputMode === "pcap" ? "active" : ""}`} type="button" onClick={() => switchMode("pcap")}>
            <span className="nav-icon"><Network size={17} strokeWidth={1.75} /></span>PCAP / PCAPNG
          </button>
          <button className={`nav-item ${inputMode === "onvif" ? "active" : ""}`} type="button" onClick={() => switchMode("onvif")}>
            <span className="nav-icon"><Cctv size={17} strokeWidth={1.75} /></span>ONVIF 诊断
          </button>
        </nav>

        <div className="history">
          <div className="section-label">最近任务</div>
          {history.length === 0 ? (
            <p className="history-empty">完成分析后，脱敏记录会显示在这里。</p>
          ) : (
            history.map((item, index) => (
              <div className="history-row" key={`${item.generatedAt}-${index}`} style={{ animationDelay: `${Math.min(index * 45, 320)}ms` }}>
                <button className="history-item" type="button" disabled={running} onClick={() => openHistory(item)} title="重新打开此报告">
                  <span className={`status-dot ${item.status}`} />
                  <div>
                    <strong>{item.sourceUrl}</strong>
                    <small>{new Date(item.generatedAt).toLocaleString("zh-CN")}</small>
                    {item.criticalCount > 0 && <small>{item.criticalCount} 项高风险</small>}
                  </div>
                </button>
                <button className="history-delete" type="button" disabled={running} onClick={() => deleteHistoryReport(item)} title="删除报告"><X size={13} strokeWidth={2} /></button>
              </div>
            ))
          )}
        </div>

        <div className="sidebar-footer">
          <span className="online-dot" />本机分析引擎
          <small>高级音画诊断 · v0.1.7</small>
        </div>
      </aside>

      <main>
        <header className="topbar" data-tauri-drag-region>
          <div data-tauri-drag-region>
            <p className="eyebrow">{inputMode === "onvif" ? "ONVIF DEVICE INSPECTOR" : "RTSP INSPECTOR"}</p>
            <h1>{inputMode === "onvif" ? "ONVIF 设备诊断" : inputMode === "pcap" ? "多流抓包诊断" : inputMode === "h264" ? "H.264 文件诊断" : inputMode === "h265" ? "H.265 文件诊断" : inputMode === "audio" ? "音频文件诊断" : "实时流诊断"}</h1>
            <p>{inputMode === "onvif" ? "按标准服务链验证设备能力，并把媒体入口交给现有 RTSP/RTP 分析器。" : inputMode === "pcap" ? "发现抓包中的媒体流，独立查看每路的网络与码流证据。" : "验证媒体参数与实际解码结果。"}</p>
          </div>
          <div className={`health-pill ${health.className} ${running ? "running" : ""}`}>
            <span />{health.label}
          </div>
        </header>

        <section className="workspace">
          {inputMode === "onvif" && <OnvifDiagnostics onAnalyzeRtsp={(streamUri) => { setUrl(streamUri); setInputMode("rtsp"); setRun(null); setError(""); }} />}
          <form className={`analysis-form panel ${inputMode === "onvif" ? "mode-hidden" : ""}`} onSubmit={submit}>
            <div className="panel-heading">
              <div>
                <span className="step">01</span>
                <h2>{inputMode === "rtsp" ? "连接参数" : "输入文件"}</h2>
              </div>
              <span className="secure-note">{inputMode === "rtsp" ? "密码仅用于本次连接" : "文件在本机分析"}</span>
            </div>

            {inputMode === "rtsp" ? (
              <label className="field url-field">
                <span>RTSP 地址</span>
                <div className="input-wrap">
                  <span className="protocol">RTSP</span>
                  <input autoFocus value={url} onChange={(event) => setUrl(event.target.value)} placeholder="rtsp://user:password@192.168.1.10/stream1" spellCheck={false} required />
                </div>
              </label>
            ) : (
              <div className="field file-field">
                <span>{inputMode === "h264" ? "Annex B H.264 文件" : inputMode === "h265" ? "Annex B H.265 / HEVC 文件" : inputMode === "audio" ? "WAV / FLAC / AAC / M4A / MP3 / Ogg / Opus" : "PCAP / PCAPNG 抓包文件"}</span>
                <div className="file-picker">
                  <code>{offlinePath || "尚未选择文件"}</code>
                  <button type="button" onClick={chooseOfflineFile}>选择文件</button>
                </div>
              </div>
            )}

            {inputMode === "rtsp" && <div className="form-grid">
              <fieldset className="field">
                <legend>传输模式</legend>
                <div className={`segmented seg-${(["tcp", "udp", "compare"] as TransportMode[]).indexOf(transport)}`}>
                  {(["tcp", "udp", "compare"] as TransportMode[]).map((item) => (
                    <button
                      className={transport === item ? "selected" : ""}
                      key={item}
                      type="button"
                      onClick={() => setTransport(item)}
                    >
                      {item === "compare" ? "对比" : item.toUpperCase()}
                      <small>{item === "tcp" ? "可靠传输" : item === "udp" ? "低延迟" : "TCP + UDP"}</small>
                    </button>
                  ))}
                </div>
              </fieldset>

              <label className="field compact-field">
                <span>分析时长</span>
                <div className="number-input">
                  <input
                    type="number"
                    min="1"
                    max="86400"
                    value={duration}
                    onChange={(event) => setDuration(Number(event.target.value))}
                  />
                  <span>秒</span>
                </div>
              </label>

              <label className="field compact-field">
                <span>连接超时</span>
                <div className="number-input">
                  <input
                    type="number"
                    min="1"
                    max="300"
                    value={connectTimeout}
                    onChange={(event) => setConnectTimeout(Number(event.target.value))}
                  />
                  <span>秒</span>
                </div>
              </label>
            </div>}

            <button className="analyze-button" type="submit" disabled={running || (inputMode !== "rtsp" && !offlinePath)}>
              {running ? (
                <><span className="spinner" />正在分析…</>
              ) : (
                <>{inputMode === "rtsp" ? "开始诊断" : inputMode === "pcap" ? "扫描媒体流" : "分析文件"}<span className="play-icon"><Play size={15} strokeWidth={2.2} fill="currentColor" /></span></>
              )}
            </button>
            {running && <button className="cancel-analysis-button" type="button" disabled={cancelling} onClick={() => { void cancelCurrentAnalysis(); }}>{cancelling ? "正在停止…" : "取消分析"}</button>}
            {running && progress && (
              <>
                <div className="progress-row" aria-live="polite">
                  <div><span style={{ width: `${progress.percent}%` }} /></div>
                  <strong>{progress.percent}% · {progress.stage}</strong>
                  <small>{progress.detail}</small>
                </div>
                {progress.live_audio_tracks && progress.live_audio_tracks.length > 0 && <div className="live-audio-progress">
                  {progress.live_audio_tracks.map((track) => <div key={track.track_index}>
                    <strong>音轨 {track.track_index + 1} · {track.codec.toUpperCase()}</strong>
                    <span>PT {track.payload_type} · {track.channels ?? "—"} 声道</span>
                    <span>{track.packet_count} 包 · {formatBitRate(track.elapsed_ms > 0 ? Math.round(track.payload_bytes * 8_000 / track.elapsed_ms) : null)}</span>
                    <span>Peak {formatMilli(track.peak_level_dbfs_milli, "dBFS")} · RMS {formatMilli(track.rms_level_dbfs_milli, "dBFS")}</span>
                    <LiveWaveform samples={track.waveform ?? []} decoding={track.live_decode_active} />
                  </div>)}
                </div>}
              </>
            )}
          </form>

          {inputMode !== "onvif" && error && <div className="error-banner"><strong>无法开始分析</strong>{error}</div>}

          <section className={`results panel ${run ? "has-result" : ""} ${inputMode === "onvif" ? "mode-hidden" : ""}`}>
            <div className="panel-heading results-heading">
              <div>
                <span className="step">02</span>
                <h2>分析结果</h2>
              </div>
              {run && <code>{run.result.request.source_url}</code>}
            </div>

            {!run || !result ? (
              <div className="empty-state">
                <div className="scope-graphic" aria-hidden="true"><span /></div>
                <h3>{running ? "正在采集证据" : "等待一次诊断任务"}</h3>
                <p>{running ? inputMode === "pcap" ? "正在扫描抓包，按媒体流独立统计与重组。完成后可选择需要深入解码的流。" : "正在分析同一来源的媒体数据。" : "填写上方参数，分析结果和报告会集中显示在这里。"}</p>
              </div>
            ) : (
              <>
                {legacyCapture && <div className="capture-legacy" role="alert"><strong>旧版抓包报告尚未按媒体流分组</strong><p>多路数据可能混入同一份统计和码流，请重新选择原抓包并扫描后再判断丢包、分片或解码问题。</p></div>}
                {identity && <div className="capture-selection">
                  <button type="button" onClick={() => { setSelectedStreamId(null); setView("overview"); }}><ArrowLeft size={13} strokeWidth={2} />所有媒体流（{capture?.stream_count}）</button>
                  <div><strong>当前流：{identity.id}</strong><code>{identity.source} → {identity.destination}</code><small>{identity.transport.toUpperCase()} · SSRC 0x{identity.ssrc.toString(16).padStart(8, "0")} · PT {identity.payload_types.join(", ")}{identity.channel !== null ? ` · Channel ${identity.channel}` : ""} · {identity.codec ?? "编码待确认"}</small></div>
                  <button type="button" disabled={running || !run.result.request.source_path} onClick={() => analyzeCaptureStreams([identity.id])}>深入分析此流</button>
                </div>}
                <div className="tabs" role="tablist" ref={tabsRef}>
                  <span className="tabs-indicator" aria-hidden="true" />
                  <button className={view === "overview" ? "active" : ""} onClick={() => setView("overview")} type="button">{captureOverview ? "媒体流总览" : "总览"}</button>
                  {!captureOverview && <>
                  <button className={view === "playback" ? "active" : ""} onClick={() => setView("playback")} type="button">音视频回放</button>
                  {audioQuality && <button className={view === "audioQuality" ? "active" : ""} onClick={() => setView("audioQuality")} type="button">音频质量</button>}
                  <button className={view === "protocol" ? "active" : ""} onClick={() => setView("protocol")} type="button">协议</button>
                  <button className={view === "stream" ? "active" : ""} onClick={() => setView("stream")} type="button">码流</button>
                  {(h264 || h265) && <button className={view === "videoDeep" ? "active" : ""} onClick={() => setView("videoDeep")} type="button">视频深度分析</button>}
                  <button className={view === "diagnostics" ? "active" : ""} onClick={() => setView("diagnostics")} type="button">诊断</button>
                  <button className={view === "timeline" ? "active" : ""} onClick={() => setView("timeline")} type="button">时间线</button>
                  </>}
                  {captureOverview && protocol && <button className={view === "protocol" ? "active" : ""} onClick={() => setView("protocol")} type="button">RTSP 协商</button>}
                  <button className={view === "report" ? "active" : ""} onClick={showReport} type="button">报告预览</button>
                  {!captureOverview && <button className={view === "log" ? "active" : ""} onClick={() => setView("log")} type="button">FFmpeg 日志</button>}
                </div>

                {view === "overview" && captureOverview && <>
                  <CaptureStreams key={run.report_directory} result={run.result} running={running} onSelect={(id) => { setSelectedStreamId(id); setView("overview"); }} onAnalyze={analyzeCaptureStreams} />
                  <div className="capture-report-actions report-location"><code>{run.report_directory}</code><button type="button" onClick={openReportDirectory}>打开报告位置</button><button className="delete-report" type="button" disabled={running} onClick={deleteCurrentReport}>删除整次抓包报告</button></div>
                </>}

                {view === "overview" && !captureOverview && (
                  <div className="overview">
                    {identity && <div className="capture-evidence"><span>抓包包号 #{identity.first_packet}–#{identity.last_packet}</span><span>抓包时间 +{identity.first_offset_ms}–{identity.last_offset_ms} ms</span><span>接口 {identity.interface_id}{identity.connection_id !== null ? ` · 连接 ${identity.connection_id}` : ""}</span><span>编码识别：{identity.codec_confidence}</span>{identity.sample_truncated && <strong>该流样本已截断</strong>}</div>}
                    {identity && !decode && <p className="capture-note">当前展示此流的扫描证据，尚无解码结果。深入分析会重新读取原抓包并生成一份新任务报告。</p>}
                    <div className="metrics">
                      <Metric label="编码" value={stream?.codec?.toUpperCase() ?? audio?.codec?.toUpperCase() ?? identity?.codec ?? "—"} detail={stream?.profile ?? identity?.codec_confidence ?? "未识别"} />
                      <Metric label="分辨率" value={stream?.width && stream.height ? `${stream.width} × ${stream.height}` : "—"} detail={stream?.pixel_format ?? "未识别"} />
                      <Metric label="观测帧率" value={stream?.frame_rate ?? "—"} detail={stream?.frame_rate_conflict ? "来源存在冲突" : "优先采用抓包观测值"} />
                      <Metric label="平均码率" value={formatBitRate(protocol?.rtp.average_bit_rate_bps ?? result.format_bit_rate)} detail="同次 RTP 样本" />
                      <Metric label="峰值码率" value={formatBitRate(protocol?.rtp.peak_bit_rate_bps)} detail="1 秒窗口" />
                      <Metric label={audio ? "音频时长" : "解码帧"} value={audio?.decoded_duration_ms != null ? `${(audio.decoded_duration_ms / 1000).toFixed(2)} s` : decode?.decoded_frames?.toString() ?? "—"} detail={audio ? audio.codec_supported_for_decode ? "已完成 PCM 级分析" : "仅 RTP 级分析" : decode ? decode.success ? "解码成功" : "未成功" : "尚无解码结果"} />
                    </div>

                    {audio && <div className="evidence-list">
                      <h3>音频分析：{audio.conclusion_reliable ? "样本满足质量判断条件" : "证据有限"}</h3>
                      <div className="protocol-facts">
                        <Metric label="采样率 / 声道" value={`${audio.sample_rate ?? audio.clock_rate} Hz / ${audio.channels ?? "—"}`} detail={audio.codec.toUpperCase()} />
                        <Metric label="峰值 / RMS" value={`${audio.peak_level_dbfs_milli != null ? (audio.peak_level_dbfs_milli / 1000).toFixed(1) : "—"} / ${audio.rms_level_dbfs_milli != null ? (audio.rms_level_dbfs_milli / 1000).toFixed(1) : "—"} dBFS`} detail="解码 PCM 采样统计" />
                        <Metric label="时间戳缺口 / 重叠" value={`${audio.timestamp_gap_count} / ${audio.timestamp_overlap_count}`} detail="独立于 RTP Sequence 统计" />
                        <Metric label="跨层映射" value={`${audio.sample_mappings?.length ?? 0} 条`} detail="RTP → AU → PCM 采样区间" />
                      </div>
                      {audio.issues.some((issue) => issue.kind === "timestamp_gap" || issue.kind === "timestamp_overlap") && <div className="audio-timestamp-evidence">
                        <div className="audio-evidence-heading">
                          <div><strong>RTP 时间轴异常位置</strong><span>按去重后的扩展 Sequence 顺序比较期望时间戳与实际时间戳</span></div>
                          <button type="button" disabled={exporting} onClick={() => { void exportAudioEvidence(audio.issues.filter((issue) => issue.kind === "timestamp_gap" || issue.kind === "timestamp_overlap"), [], "rtp-timestamp-issues"); }}>导出 CSV / JSON</button>
                        </div>
                        {audio.issues.filter((issue) => issue.kind === "timestamp_gap" || issue.kind === "timestamp_overlap").map((issue, index) => <div className="audio-timestamp-row" key={`${issue.kind}-${issue.first_packet}-${index}`}>
                          <strong>{issue.kind === "timestamp_gap" ? "缺口" : "重叠"} · 媒体 {formatDuration(issue.media_start_ms)}–{formatDuration(issue.media_end_ms)} · {formatDuration(issue.duration_ms)}</strong>
                          <span>抓包 #{issue.previous_packet ?? "—"} → #{issue.first_packet ?? "—"} · Seq {issue.previous_rtp_sequence ?? "—"} → {issue.current_rtp_sequence ?? "—"}</span>
                          <span>期望 TS {issue.expected_rtp_timestamp ?? "—"}，实际 TS {issue.actual_rtp_timestamp ?? "—"}，差值 {issue.delta_timestamp ?? "—"} clock ticks</span>
                          <small>到达偏移 {formatDuration(issue.previous_offset_ms)} → {formatDuration(issue.offset_ms)} · {issue.detail}</small>
                        </div>)}
                        <p className="capture-note">该定位对 PCMA/PCMU 使用“一码字一采样”精确推导；压缩编码只在具备可靠 AU 时长映射时才能作同等结论，零计数不代表压缩流一定没有时间轴异常。</p>
                      </div>}
                      {audio.issues.filter((issue) => issue.kind !== "timestamp_gap" && issue.kind !== "timestamp_overlap").map((issue, index) => <div className="evidence" key={`${issue.kind}-${index}`}><strong>{issue.kind}</strong><span>{issue.detail}</span></div>)}
                      {(audio.sample_mappings?.length ?? 0) > 0 && <details className="quality-method">
                        <summary>查看 RTP → Access Unit → PCM 映射</summary>
                        <div className="table-wrap"><table><thead><tr><th>包 / Seq</th><th>RTP 时间戳</th><th>AU</th><th>PCM 采样区间</th><th>精度</th></tr></thead><tbody>
                          {audio.sample_mappings.slice(0, 100).map((mapping, index) => <tr key={`${mapping.access_unit_index}-${index}`}><td>#{mapping.packet_number ?? "—"} / {mapping.rtp_sequence ?? "—"}</td><td>{mapping.rtp_timestamp}</td><td>{mapping.access_unit_index}{mapping.access_unit_in_packet ? `.${mapping.access_unit_in_packet}` : ""}</td><td>{mapping.pcm_start_sample}–{mapping.pcm_end_sample} @ {mapping.sample_rate} Hz</td><td>{mapping.precision}</td></tr>)}
                        </tbody></table></div>
                        {audio.sample_mappings.length > 100 && <p>界面仅展示前 100 条，完整映射保存在 JSON 报告。</p>}
                      </details>}
                    </div>}

                    {(result.av_sync?.length ?? 0) > 0 && <div className="evidence-list">
                      <h3>音画同步：时钟证据与内容事件</h3>
                      {result.av_sync!.map((sync, index) => <div className={sync.offset_ms == null ? "evidence error" : "evidence"} key={`${sync.audio_stream_id}-${sync.video_stream_id}-${index}`}>
                        <strong>{sync.audio_stream_id} ↔ {sync.video_stream_id}</strong>
                        <span>{sync.offset_ms == null ? "时钟证据不足" : `时钟：音频相对视频${sync.offset_ms > 0 ? "晚" : "早"} ${Math.abs(sync.offset_ms)} ms`} · 置信度 {sync.confidence_percent}%</span>
                        {sync.content_offset_ms != null && <span>内容：音频相对闪光{sync.content_offset_ms > 0 ? "晚" : "早"} {Math.abs(sync.content_offset_ms)} ms · 误差约 ±{sync.content_measurement_error_ms ?? "—"} ms · 置信度 {sync.content_confidence_percent ?? "—"}% · {sync.content_events?.length ?? 0} 组事件</span>}
                        <code>{sync.reasons.join("；")}</code>
                      </div>)}
                    </div>}

                    {quality?.assessed && (
                      <div className="evidence-list">
                        <h3>数据可信度：{quality.sufficient_for_diagnosis ? "满足现象诊断条件" : "证据条件受限，仅输出提示性结论"}</h3>
                        <div className="evidence quality-counts">
                          <strong>{result.request.transport?.toUpperCase() ?? "—"}</strong>
                          <span>RTP {quality.captured_rtp_packets} 包 → 目标负载 {quality.captured_payload_packets} 包 → NALU {quality.reassembled_nalus} 个 → 解析 {quality.parsed_frames} 帧 → 解码 {quality.decoded_frames ?? "—"} 帧</span>
                        </div>
                        {quality.reasons.map((item) => <div className="evidence error" key={item}>{item}</div>)}
                        {(quality.limitations ?? []).map((item) => <div className="evidence" key={item}><strong>适用边界</strong><span>{item}</span></div>)}
                      </div>
                    )}

                    {stream && (stream.sps_frame_rate || stream.probed_frame_rate || stream.observed_frame_rate) && (
                      <div className="evidence-list">
                        <h3>帧率证据{stream.frame_rate_conflict ? "：来源冲突" : ""}</h3>
                        <div className="evidence"><strong>SPS 声明</strong><span>{stream.sps_frame_rate ?? "—"} fps</span></div>
                        <div className="evidence"><strong>ffprobe 探测</strong><span>{stream.probed_frame_rate ?? "—"}</span></div>
                        <div className="evidence"><strong>抓包观测</strong><span>{stream.observed_frame_rate ?? "—"} fps</span></div>
                        {stream.frame_rate_conflict && <div className="evidence error">不同来源偏差超过 5% 或 0.5 fps，不能用单一帧率判断卡顿。</div>}
                      </div>
                    )}

                    <div className="protocol-facts">
                      <Metric label="RTSP 会话" value={formatDuration(result.module_timings.rtsp_session_ms)} detail="含控制与媒体采样" />
                      <Metric label="媒体覆盖" value={formatDuration(result.module_timings.media_sample_coverage_ms ?? result.module_timings.rtp_capture_ms)} detail="数据时间范围，不是处理耗时" />
                      <Metric label="抓包读取" value={formatDuration(result.module_timings.capture_read_ms)} detail="文件扫描处理耗时" />
                      <Metric label="H.264 分析" value={formatDuration(result.module_timings.h264_analysis_ms)} detail="重组与结构解析" />
                      <Metric label="H.265 分析" value={formatDuration(result.module_timings.h265_analysis_ms)} detail="重组与结构解析" />
                      <Metric label="ffprobe" value={formatDuration(result.module_timings.ffprobe_ms)} detail={`同源 ${h265 ? "sample.h265" : "sample.h264"}`} />
                      <Metric label="FFmpeg" value={formatDuration(result.module_timings.ffmpeg_decode_ms)} detail={`同源 ${h265 ? "sample.h265" : "sample.h264"}`} />
                    </div>

                    {comparison && (
                      <div className="comparison-panel">
                        <div><span>TCP</span><strong>{comparison.tcp.result.protocol?.rtp.packet_count ?? 0} 包</strong><small>丢包 {comparison.tcp.result.protocol?.rtp.lost_packets ?? 0} · {statusText(comparison.tcp.result.status)}</small><button type="button" onClick={() => { setRun(comparison.tcp); setReportHtml(""); }}>查看 TCP 详情</button></div>
                        <div><span>UDP</span><strong>{comparison.udp.result.protocol?.rtp.packet_count ?? 0} 包</strong><small>丢包 {comparison.udp.result.protocol?.rtp.lost_packets ?? 0} · {statusText(comparison.udp.result.status)}</small><button type="button" onClick={() => { setRun(comparison.udp); setReportHtml(""); }}>查看 UDP 详情</button></div>
                        <div className="comparison-conclusion"><span>对比结论</span>{comparison.conclusions.map((item) => <p key={item}>{item}</p>)}</div>
                      </div>
                    )}

                    <div className="finding-grid">
                      <div className="finding-card">
                        <h3>任务执行状态</h3>
                        <div className={`large-status ${result.status}`}>{statusText(result.status)}</div>
                        <p>{identity && !decode ? "扫描任务已完成，尚未实际解码，不能判断视频健康。" : decode && !decode.success ? "任务已执行，但实际解码失败。" : (decode?.issues.length ?? 0) > 0 ? `任务已完成，检测到 ${decode?.issues.length} 类解码异常。` : result.errors.length === 0 ? "任务执行完成，未报告执行错误；这不等同于视频一定正常。" : `任务结束，记录到 ${result.errors.length} 条执行提示。`}</p>
                      </div>
                      <div className="finding-card">
                        <h3>解码证据</h3>
                        <strong className="issue-count">{decode?.issues.length ?? 0}</strong>
                        <p>类解码错误或画面候选事件，仅作为证据，不单独认定根因。</p>
                      </div>
                      <div className="finding-card">
                        <h3>诊断结论</h3>
                        <strong className="issue-count">{result.diagnostics.length}</strong>
                        <p>{result.diagnostics.some((item) => item.severity === "critical" || item.severity === "high") ? "存在需要优先处理的高风险结论。" : "当前证据未触发高风险结论，请同时关注样本可信度。"}</p>
                      </div>
                      <div className="finding-card report-location">
                        <h3>报告目录</h3>
                        <code title={comparison?.report_directory ?? run.report_directory}>{comparison?.report_directory ?? run.report_directory}</code>
                        <p>{identity ? "整次抓包的 JSON、HTML 及各流独立产物。" : "已生成 JSON、HTML 和脱敏日志。"}</p>
                        <button type="button" onClick={openReportDirectory}>打开报告位置</button>
                        <button className="delete-report" type="button" disabled={running} onClick={deleteCurrentReport}>{identity ? "删除整次抓包报告" : "删除当前报告"}</button>
                      </div>
                    </div>

                    {(result.errors.length > 0 || (decode?.issues.length ?? 0) > 0 || (decode && !decode.success)) && (
                      <div className="evidence-list">
                        <h3>证据摘要</h3>
                        {result.errors.map((item) => <div className="evidence error" key={item}>{item}</div>)}
                        {decode?.issues.map((item) => (
                          <div className="evidence" key={item.kind}>
                            <strong>{item.kind}</strong><span>{item.count} 次{item.locations?.length ? ` · 候选帧 ${item.locations.map((location) => `#${location.frame_number}`).join(", ")}` : " · 时间未定位"}</span><code>{item.example}</code>
                          </div>
                        ))}
                        {decode && !decode.success && decode.log && <div className="evidence error"><strong>FFmpeg 实解失败：</strong>{decode.log.split(/\r?\n/).find(Boolean)}</div>}
                      </div>
                    )}
                  </div>
                )}

                {view === "playback" && !captureOverview && (
                  <div className="playback-view">
                    <div className="playback-heading">
                      <div><h3>同源样本音视频回放</h3><p>画面和声音都来自本次采集；在软件内播放，不启动 ffplay 或外部窗口。</p></div>
                      {decode?.visual_scan?.completed && <span className={decode.visual_scan.candidate_frames > 0 ? "scan-warning" : "scan-ok"}>{decode.visual_scan.candidate_frames > 0 ? `疑似花屏 ${decode.visual_scan.candidate_frames} 个抽样帧` : "抽样未见局部花屏候选"}</span>}
                    </div>
                    {audioTracks.length > 1 && <AudioTrackSelector tracks={audioTracks} selectedId={selectedAudioTrack?.id ?? ""} onChange={setSelectedAudioTrackId} />}
                    {previewSource && previewAudioSource && playbackSync && <div className="sync-playback-control">
                      <button type="button" onClick={playWithRtcpClock}>按 RTCP 时钟同步播放</button>
                      <div><strong>音频相对视频 {playbackSync.offset_ms! > 0 ? "晚" : playbackSync.offset_ms! < 0 ? "早" : ""} {Math.abs(playbackSync.offset_ms!)} ms</strong><small>置信度 {playbackSync.confidence_percent}% · 自动校正超过 250 ms 的播放器漂移；仅表示发送时钟对齐</small></div>
                    </div>}
                    {previewSource && previewAudioSource && !playbackSync && <p className="capture-note">缺少共同 RTCP 时钟证据，两个样本只能独立回放，软件不会用首包到达时间伪造同步结论。</p>}
                    {previewSource ? (
                      <>
                        <video ref={previewVideo} key={previewSource} controls controlsList="nodownload" preload="metadata" src={previewSource}>当前系统 WebView 不支持视频播放。</video>
                        <div className="media-export-bar"><span>视频样本</span><button type="button" disabled={exporting} onClick={exportVideoSample}>{exporting ? "正在导出…" : "导出 MP4"}</button></div>
                      </>
                    ) : (
                      <div className="playback-empty">
                        <strong>当前结果没有可播放预览</strong>
                        <p>{identity && !decode ? "请点击上方“深入分析此流”，软件会从该路抓包负载生成独立预览。" : "需要 FFmpeg 成功读取本次保留的 H.264/H.265 样本；具体原因请查看执行提示。"}</p>
                      </div>
                    )}
                    {previewAudioSource && <>
                      <audio ref={previewAudio} key={previewAudioSource} controls controlsList="nodownload" preload="metadata" src={previewAudioSource} onTimeUpdate={correctPreviewClock}>当前系统 WebView 不支持音频播放。</audio>
                      <div className="media-export-bar audio-export-bar">
                        <span>音频导出格式</span>
                        <select value={audioExportFormat} disabled={exporting} onChange={(event) => setAudioExportFormat(event.target.value as AudioExportFormat)}>
                          {audioExportFormats.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
                        </select>
                        <button type="button" disabled={exporting} onClick={() => { void exportAudioSample(); }}>{exporting ? "正在转换…" : "选择位置并导出"}</button>
                      </div>
                    </>}
                    {exportMessage && <p className="export-success">{exportMessage}</p>}
                    {decode?.visual_scan && <div className="scan-summary">
                      <strong>画面级异常扫描</strong>
                      <span>{decode.visual_scan.completed ? `${decode.visual_scan.sampled_frames} 帧 · ${decode.visual_scan.sampled_fps} fps · ${decode.visual_scan.scan_width}×${decode.visual_scan.scan_height}` : "未完成"}</span>
                      <p>{decode.visual_scan.note ?? "没有扫描说明"}</p>
                    </div>}
                  </div>
                )}

                {view === "audioQuality" && audioQuality && <>
                  {audioTracks.length > 1 && <AudioTrackSelector tracks={audioTracks} selectedId={selectedAudioTrack?.id ?? ""} onChange={setSelectedAudioTrackId} />}
                  <AudioQualityView
                    quality={audioQuality}
                    onSeek={(offsetMs) => {
                      setPendingAudioSeek(offsetMs);
                      setView("playback");
                    }}
                    onExport={(startMs, endMs) => { void exportAudioSample({ startMs, endMs }); }}
                    onExportEvidence={(intervals) => { void exportAudioEvidence([], intervals, "filtered-content-intervals"); }}
                    canExport={Boolean(audioExportSource) && !exporting}
                  />
                </>}

                {view === "videoDeep" && (h264 || h265) && (
                  <VideoDeepAnalysisView analysis={videoDeep ?? null} nalus={h265?.nalus ?? h264?.nalus ?? []} parameterChanges={h265?.parameter_changes ?? h264?.parameter_changes ?? []} recoveryWindows={h265?.recovery_windows ?? h264?.recovery_windows ?? []} initialDisplayIndex={requestedVideoFrame} codec={h265 ? "H.265 / HEVC" : "H.264 / AVC"} reportDirectory={run.report_directory} streamId={selectedStreamId} />
                )}

                {view === "protocol" && (
                  <div className="protocol-view">
                    {!protocol ? (
                      <div className="protocol-empty">本次任务没有取得自研 RTSP 协议数据，详情请查看执行错误。</div>
                    ) : (
                      <>
                        <div className="protocol-facts">
                          <Metric label="RTSP 服务端" value={protocol.server ?? "未声明"} detail={protocol.authenticated ? "已完成鉴权" : "无需鉴权"} />
                          <Metric label="Session" value={protocol.session_id ?? "—"} detail={`${protocol.transactions.length} 次事务`} />
                          <Metric label="SETUP / PLAY" value={`${rtspStatusSummary("SETUP")} / ${rtspStatusSummary("PLAY")}`} detail="显示全部响应状态；不一致时不按单次成功判定" />
                          <Metric label="传输" value={result.request.transport?.toUpperCase() ?? "—"} detail={protocol.negotiated_transport ?? (protocol.interleaved_rtp_channel !== null ? `Interleaved ${protocol.interleaved_rtp_channel}-${protocol.interleaved_rtcp_channel}` : "UDP RTP / RTCP")} />
                          <Metric label={captureOverview ? "已发现 RTP 包" : "RTP 包"} value={protocolPacketCount.toString()} detail={captureOverview ? `${run.result.streams?.length ?? 0} 个实际媒体流/候选` : `${protocol.rtp.payload_bytes} B 负载`} />
                          <Metric label="平均 / 峰值码率" value={`${formatBitRate(protocol.rtp.average_bit_rate_bps)} / ${formatBitRate(protocol.rtp.peak_bit_rate_bps)}`} detail={`${protocol.rtp.bit_rate_window_ms ?? 1_000} ms 峰值窗口`} />
                          <Metric label={identity ? "序列缺口" : "丢包"} value={protocol.rtp.lost_packets.toString()} detail={`${protocol.rtp.out_of_order_packets} 乱序 / ${protocol.rtp.duplicate_packets} 重复`} />
                          <Metric label="Jitter" value={jitterMs !== null ? `${jitterMs.toFixed(2)} ms` : "时钟未知"} detail={`${protocol.rtp.jitter.toFixed(2)} timestamp units`} />
                        </div>
                        <div className="transaction-table">
                          <div className="table-head"><span>方法</span><span>状态</span><span>CSeq</span><span>耗时</span><span>请求 URI</span></div>
                          {protocol.transactions.map((transaction, index) => (
                            <div className="table-row" key={`${transaction.method}-${transaction.cseq}-${index}`}>
                              <strong>{transaction.method}</strong>
                              <span className={transaction.status_code < 300 ? "ok" : "bad"}>{transaction.status_code} {transaction.reason}</span>
                              <span>{transaction.cseq ?? "—"}</span>
                              <span>{transaction.elapsed_ms} ms</span>
                              <code title={transaction.uri}>{transaction.uri}</code>
                            </div>
                          ))}
                        </div>
                        <div className="media-list">
                          {protocol.media.map((media, index) => (
                            <div className="media-track" key={`${media.media_type}-${index}`}>
                              <span>{media.media_type.toUpperCase()}</span>
                              <strong>{media.codec ?? "未知编码"}</strong>
                              <small>PT {media.payload_types.join(", ")} · {media.clock_rate ?? "—"} Hz</small>
                              <code>{media.resolved_control ?? media.control ?? "无 Control URI"}</code>
                            </div>
                          ))}
                        </div>
                      </>
                    )}
                  </div>
                )}

                {view === "stream" && (
                  <div className="protocol-view">
                    {!h264 && !h265 && !audio ? (
                      <div className="protocol-empty">本次任务没有取得可分析的音视频 RTP 负载。</div>
                    ) : audio && !h264 && !h265 ? (
                      <><div className="protocol-facts">
                        <Metric label="音频编码" value={audio.codec.toUpperCase()} detail={`${audio.clock_rate} Hz RTP 时钟`} />
                        <Metric label="RTP 包" value={audio.packet_count.toString()} detail={`${audio.decoded_samples} 个解码采样`} />
                        <Metric label="质量结论" value={audio.conclusion_reliable ? "可判断" : "证据不足"} detail={audio.codec_supported_for_decode ? "PCM 级" : "RTP 级"} />
                      </div></>
                    ) : h264 ? (
                      <>
                        <div className="protocol-facts">
                          <Metric label="NALU" value={h264.nalu_count.toString()} detail={`${h264.incomplete_nalus} 个不完整`} />
                          <Metric label="视频帧" value={h264.frame_count.toString()} detail={`${h264.idr_frames} 个 IDR`} />
                          <Metric label="SPS / PPS" value={`${h264.sps.length} / ${h264.pps.length}`} detail="参数集" />
                          <Metric label="平均 GOP" value={h264.average_gop_frames?.toString() ?? "—"} detail={`最大 ${h264.maximum_gop_frames ?? "—"}`} />
                          <Metric label="结构异常" value={h264.issues.length.toString()} detail="解析及封包证据" />
                        </div>
                        {h264.sps.map((sps) => (
                          <div className="parameter-card" key={sps.id}>
                            <span>SPS {sps.id}</span>
                            <strong>{sps.width} × {sps.height}</strong>
                            <small>Profile {sps.profile_idc} · Level {sps.level_idc === 11 && sps.constraint_set3_flag ? "1b" : (sps.level_idc / 10).toFixed(1)} · {sps.progressive ? "Progressive" : "Interlaced"}</small>
                            <small>{sps.bit_depth_luma}-bit · {sps.max_num_ref_frames} reference frames</small>
                            <small>{sps.nal_hrd || sps.vcl_hrd ? `HRD ${(sps.nal_hrd ?? sps.vcl_hrd)!.maximum_bit_rate_bps.toLocaleString()} bps · CPB ${(sps.nal_hrd ?? sps.vcl_hrd)!.maximum_cpb_size_bits.toLocaleString()} bits` : "未声明 HRD"}{sps.max_dec_frame_buffering != null ? ` · VUI DPB ${sps.max_dec_frame_buffering}` : ""}</small>
                          </div>
                        ))}
                        {h264.hrd_simulation && <div className="evidence-list">
                          <h3>HRD / CPB 逐 AU 仿真</h3>
                          <div className="protocol-facts">
                            <Metric label="状态" value={h264.hrd_simulation.status === "simulated_cbr_single_cpb" ? "已完成" : h264.hrd_simulation.status === "not_declared" ? "未声明 HRD" : "证据不足"} detail={h264.hrd_simulation.status === "simulated_cbr_single_cpb" ? `${h264.hrd_simulation.schedule.toUpperCase()} schedule · SPS ${h264.hrd_simulation.sps_id ?? "—"}` : "未输出确定性 CPB 结论"} />
                            <Metric label="SEI 证据" value={`${h264.hrd_simulation.buffering_period_count} / ${h264.hrd_simulation.pic_timing_count}`} detail="buffering_period / pic_timing" />
                            <Metric label="已仿真 AU" value={h264.hrd_simulation.simulated_aus.toLocaleString()} detail={h264.hrd_simulation.points_truncated ? "明细已截断" : "明细完整保留"} />
                            <Metric label="CPB fullness" value={`${h264.hrd_simulation.minimum_fullness_bits?.toLocaleString() ?? "—"} / ${h264.hrd_simulation.maximum_fullness_bits?.toLocaleString() ?? "—"}`} detail="最小 / 最大 bits" />
                            <Metric label="越界" value={`${h264.hrd_simulation.overflow_aus.length} / ${h264.hrd_simulation.underflow_aus.length}`} detail="溢出 / 下溢 AU" />
                            <Metric label="时序不连续" value={h264.hrd_simulation.delay_discontinuities.length.toString()} detail="cpb_removal_delay 零增量" />
                          </div>
                          {h264.hrd_simulation.points.length > 0 && <details>
                            <summary>逐 AU CPB 明细（显示前 200 条）</summary>
                            <div className="transaction-table">
                              <div className="table-head"><span>AU / SEI</span><span>AU bits</span><span>Removal / Output delay</span><span>移除前 / 后 fullness</span><span>状态</span></div>
                              {h264.hrd_simulation.points.slice(0, 200).map((point) => <div className="table-row" key={`${point.access_unit}-${point.sei_nalu}`}>
                                <strong>#{point.access_unit} / NALU #{point.sei_nalu}</strong>
                                <span>{point.access_unit_bits.toLocaleString()}</span>
                                <span>{point.cpb_removal_delay} / {point.dpb_output_delay}</span>
                                <span>{point.fullness_before_removal_bits.toLocaleString()} / {point.fullness_after_removal_bits.toLocaleString()}</span>
                                <code>{point.overflow ? "CPB 溢出" : point.underflow ? "CPB 下溢" : "正常"}</code>
                              </div>)}
                            </div>
                          </details>}
                          {h264.hrd_simulation.limitations.map((item) => <p className="capture-note" key={item}>{item}</p>)}
                        </div>}
                        <div className="nalu-grid">
                          {Object.entries(h264.nalu_types).map(([name, count]) => (
                            <div key={name}><span>{name}</span><strong>{count}</strong></div>
                          ))}
                        </div>
                        {h264.issues.length > 0 && (
                          <div className="evidence-list">
                            <h3>H.264 异常证据</h3>
                            {h264.issues.map((issue, index) => (
                              <div className="evidence" key={`${issue.kind}-${index}`}>
                                <strong>{issue.kind}</strong>
                                <span>{issue.sequence ?? "—"}</span>
                                <code>{issue.detail}</code>
                              </div>
                            ))}
                          </div>
                        )}
                      </>
                    ) : h265 ? (
                      <>
                        <div className="protocol-facts">
                          <Metric label="NALU" value={h265.nalu_count.toString()} detail={`${h265.incomplete_nalus} 个不完整`} />
                          <Metric label="视频帧" value={h265.frame_count.toString()} detail={`${h265.idr_frames} 个 IDR · ${h265.cra_frames} 个 CRA`} />
                          <Metric label="VPS / SPS / PPS" value={`${h265.vps_count} / ${h265.sps.length} / ${h265.pps.length}`} detail="参数集" />
                          <Metric label="平均 GOP" value={h265.average_gop_frames?.toString() ?? "—"} detail={`最大 ${h265.maximum_gop_frames ?? "—"}`} />
                          <Metric label="结构异常" value={h265.issues.length.toString()} detail="解析及封包证据" />
                        </div>
                        {h265.sps.map((sps) => (
                          <div className="parameter-card" key={sps.id}>
                            <span>H.265 SPS {sps.id} · VPS {sps.vps_id}</span>
                            <strong>{sps.width} × {sps.height}</strong>
                            <small>Profile {sps.profile_idc} · Level {(sps.level_idc / 30).toFixed(1)} · {sps.max_sub_layers} temporal layers</small>
                            <small>{sps.bit_depth_luma}-bit luma · {sps.bit_depth_chroma}-bit chroma</small>
                            <small>DPB {sps.max_dec_pic_buffering ?? "—"} frames · reorder {sps.max_num_reorder_pics ?? "—"}</small>
                          </div>
                        ))}
                        <div className="nalu-grid">
                          {Object.entries(h265.nalu_types).map(([name, count]) => (
                            <div key={name}><span>{name}</span><strong>{count}</strong></div>
                          ))}
                        </div>
                        {h265.issues.length > 0 && (
                          <div className="evidence-list">
                            <h3>H.265 异常证据</h3>
                            {h265.issues.map((issue, index) => (
                              <div className="evidence" key={`${issue.kind}-${index}`}>
                                <strong>{issue.kind}</strong>
                                <span>{issue.sequence ?? "—"}</span>
                                <code>{issue.detail}</code>
                              </div>
                            ))}
                          </div>
                        )}
                      </>
                    ) : null}
                  </div>
                )}

                {view === "diagnostics" && (
                  <div className="diagnostics-view">
                    {result.diagnostics.length === 0 ? (
                      <div className="protocol-empty">当前采集证据没有触发诊断规则。</div>
                    ) : result.diagnostics.map((finding) => (
                      <article className={`diagnostic-card ${finding.severity}`} key={finding.rule_id}>
                        <header>
                          <span className="severity-badge">{finding.severity.toUpperCase()}</span>
                          <code>{finding.rule_id}</code>
                          <strong>{finding.title}</strong>
                          <small>置信度 {finding.confidence_percent}%</small>
                        </header>
                        <p className="conclusion">{finding.conclusion}</p>
                        <div className="diagnostic-columns">
                          <div><h4>证据</h4>{finding.evidence.map((item) => <p key={`${item.label}-${item.value}`}><span>{item.label}</span>{item.value}</p>)}</div>
                          <div><h4>影响</h4><p>{finding.impact}</p></div>
                          <div><h4>处理建议</h4>{finding.suggestions.map((item) => <p key={item}>{item}</p>)}</div>
                          <div><h4>复验方法</h4>{finding.verification.map((item) => <p key={item}>{item}</p>)}</div>
                        </div>
                      </article>
                    ))}
                  </div>
                )}

                {view === "timeline" && (
                  <div className="timeline-view">
                    <TimelineChart events={result.timeline} />
                    {result.timeline.length === 0 ? (
                      <div className="protocol-empty">本次任务没有可展示的时间线事件。</div>
                    ) : result.timeline.map((event, index) => {
                      const mappedFrame = videoDeep && event.frame_number != null && !event.location_precision?.startsWith("visual_scan_")
                        ? videoDeep.frames.find((frame) => frame.decode_index === event.frame_number! - 1)
                        : videoDeep && event.offset_ms != null
                          ? videoDeep.frames.filter((frame) => frame.pts_ms != null).reduce<typeof videoDeep.frames[number] | null>((nearest, frame) => nearest == null || Math.abs(frame.pts_ms! - event.offset_ms!) < Math.abs(nearest.pts_ms! - event.offset_ms!) ? frame : nearest, null)
                          : null;
                      return <div className={`timeline-event ${event.severity}`} key={`${event.source}-${event.event_type}-${index}`}>
                        <span className="timeline-dot" />
                        <time>{event.offset_ms === null ? "时序未知" : `+${event.offset_ms} ms`}</time>
                        <strong>{event.source} · {event.event_type}</strong>
                        <p>{event.detail}</p>
                        {(event.frame_number != null || event.sequence !== null || event.rtp_timestamp !== null) && <code>帧 {event.frame_number ?? "—"} · 包 #{event.first_packet ?? "—"}{event.last_packet != null && event.last_packet !== event.first_packet ? `–#${event.last_packet}` : ""} · Seq {event.sequence ?? "—"} · TS {event.rtp_timestamp ?? "—"} · {event.location_precision ?? "位置未知"}</code>}
                        {mappedFrame && <button type="button" onClick={() => { setRequestedVideoFrame(mappedFrame.display_index); setView("videoDeep"); }}>定位显示帧 #{mappedFrame.display_index}</button>}
                      </div>;
                    })}
                  </div>
                )}

                {view === "report" && (
                  <div className="report-view">
                    {reportHtml ? <>
                      <div className="report-toolbar"><span>{capture ? "整次抓包总览及逐流报告" : "报告已在软件内安全预览"}</span><button type="button" onClick={() => reportFrame.current?.contentWindow?.print()}>打印 / 另存为 PDF</button></div>
                      <iframe ref={reportFrame} title="StreamScope HTML 报告" sandbox="allow-modals allow-same-origin" srcDoc={reportHtml} onLoad={() => {
                        reportFrame.current?.contentDocument?.querySelectorAll("a").forEach((link) => {
                          link.addEventListener("click", (event) => {
                            event.preventDefault();
                            const href = link.getAttribute("href") ?? "";
                            const id = /^streams\/([a-zA-Z0-9_-]+)\/report\.html$/.exec(href)?.[1];
                            if (id && run.result.streams?.some((item) => item.capture_stream?.id === id)) void previewReport(id);
                            else if (href === "../../report.html") void previewReport(null);
                            else if (href === "ffmpeg.log") setView("log");
                            else void openReportDirectory();
                          });
                        });
                      }} />
                    </> : <div className="loading-report"><span className="spinner" />正在加载报告…</div>}
                  </div>
                )}

                {view === "log" && (
                  <pre className="log-view">{decode?.log || result.errors.join("\n") || (identity ? "此流尚无 FFmpeg 解码日志，可使用“深入分析此流”生成。" : "FFmpeg 未输出日志。")}</pre>
                )}
              </>
            )}
          </section>
        </section>
      </main>
    </div>
  );
}

function Metric({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </div>
  );
}

function AudioTrackSelector({ tracks, selectedId, onChange }: { tracks: NonNullable<AnalysisRun["result"]["audio_tracks"]>; selectedId: string; onChange: (id: string) => void }) {
  return (
    <label className="audio-track-selector">
      <span>音频轨道</span>
      <select value={selectedId} onChange={(event) => onChange(event.target.value)}>
        {tracks.map((track) => <option key={track.id} value={track.id}>{track.id} · {track.codec.toUpperCase()} · PT {track.payload_type} · {track.clock_rate} Hz · {track.channels ?? 1} 声道</option>)}
      </select>
    </label>
  );
}

type AudioQuality = NonNullable<NonNullable<AnalysisRun["result"]["audio"]>["quality"]>;
type AudioIssueEvidence = NonNullable<AnalysisRun["result"]["audio"]>["issues"][number];
type AudioQualityIntervalEvidence = AudioQuality["intervals"][number];

function formatMilli(value: number | null | undefined, unit: string): string {
  return value === null || value === undefined ? "—" : `${(value / 1_000).toFixed(1)} ${unit}`;
}

function LiveWaveform({ samples, decoding }: { samples: number[]; decoding: boolean }) {
  if (samples.length < 2) return <small>{decoding ? "AAC/Opus 在线解码器已启动，等待 PCM 数据" : "等待音频采样"}</small>;
  const points = samples.map((sample, index) => {
    const x = index * 100 / Math.max(1, samples.length - 1);
    const y = 20 - sample / 32768 * 18;
    return `${x.toFixed(2)},${y.toFixed(2)}`;
  }).join(" ");
  return <svg aria-label="实时 PCM 波形" className="live-waveform" preserveAspectRatio="none" viewBox="0 0 100 40"><line x1="0" x2="100" y1="20" y2="20" /><polyline points={points} /></svg>;
}

function AudioQualityView({ quality, onSeek, onExport, onExportEvidence, canExport }: { quality: AudioQuality; onSeek: (offsetMs: number) => void; onExport: (startMs: number, endMs: number) => void; onExportEvidence: (intervals: AudioQualityIntervalEvidence[]) => void; canExport: boolean }) {
  const [intervalQuery, setIntervalQuery] = useState("");
  const [intervalKind, setIntervalKind] = useState("all");
  const [intervalChannel, setIntervalChannel] = useState("all");
  const [intervalStart, setIntervalStart] = useState("");
  const [intervalEnd, setIntervalEnd] = useState("");
  const intervalKinds = useMemo(() => [...new Set(quality.intervals.map((interval) => interval.kind))], [quality.intervals]);
  const intervalChannels = useMemo(() => [...new Set(quality.intervals.map((interval) => interval.channel).filter((channel): channel is number => channel != null))].sort((left, right) => left - right), [quality.intervals]);
  const filteredIntervals = useMemo(() => {
    const query = intervalQuery.trim().toLocaleLowerCase();
    const startMs = intervalStart.trim() === "" ? null : Number(intervalStart) * 1_000;
    const endMs = intervalEnd.trim() === "" ? null : Number(intervalEnd) * 1_000;
    return quality.intervals.filter((interval) => {
      if (intervalKind !== "all" && interval.kind !== intervalKind) return false;
      if (intervalChannel !== "all" && String(interval.channel ?? "all") !== intervalChannel) return false;
      if (startMs != null && Number.isFinite(startMs) && interval.end_ms < startMs) return false;
      if (endMs != null && Number.isFinite(endMs) && interval.start_ms > endMs) return false;
      if (!query) return true;
      const searchable = [
        audioIntervalLabel(interval.kind), interval.kind, interval.detail, interval.precision,
        interval.channel == null ? "全部声道" : `声道 ${interval.channel}`,
        interval.first_packet == null ? "" : `包 ${interval.first_packet} #${interval.first_packet}`,
        interval.last_packet == null ? "" : `包 ${interval.last_packet} #${interval.last_packet}`,
        interval.first_rtp_sequence == null ? "" : `seq ${interval.first_rtp_sequence}`,
        interval.last_rtp_sequence == null ? "" : `seq ${interval.last_rtp_sequence}`,
      ].join(" ").toLocaleLowerCase();
      return searchable.includes(query);
    });
  }, [quality.intervals, intervalQuery, intervalKind, intervalChannel, intervalStart, intervalEnd]);
  return (
    <div className="audio-quality-view">
      <div className="quality-summary metrics">
        <Metric label="分析覆盖" value={formatDuration(quality.analysis_coverage_ms)} detail={quality.scope === "decoded_pcm_full" ? "完整解码 PCM" : "本次保留的同源 PCM"} />
        <Metric label="综合响度" value={formatMilli(quality.integrated_loudness_lufs_milli, "LUFS")} detail="EBU R128 测量" />
        <Metric label="True Peak" value={formatMilli(quality.true_peak_dbtp_milli, "dBTP")} detail="码间峰值" />
        <Metric label="响度范围" value={formatMilli(quality.loudness_range_lu_milli, "LU")} detail={quality.analysis_coverage_ms != null && quality.analysis_coverage_ms < 3_000 ? "样本不足，仅供参考" : "LRA"} />
        <Metric label="动态范围" value={formatMilli(quality.dynamic_range_db_milli, "dB")} detail="活动窗口 P95/P10" />
        <Metric label="频谱滚降" value={quality.spectral_rolloff_hz == null ? "—" : `${quality.spectral_rolloff_hz} Hz`} detail="累计能量 85%" />
        <Metric label="声道电平差" value={formatMilli(quality.channel_level_difference_db_milli, "dB")} detail="各声道 RMS 最大差值" />
        <Metric label="立体声相关性" value={quality.stereo_correlation_milli == null ? "—" : (quality.stereo_correlation_milli / 1_000).toFixed(3)} detail="-1 反相 / +1 同相" />
      </div>

      <div className="audio-channel-grid">
        {quality.channels.map((channel) => <div className="audio-channel-card" key={channel.channel}>
          <strong>声道 {channel.channel}</strong>
          <span>Peak {formatMilli(channel.peak_level_dbfs_milli, "dBFS")}</span>
          <span>RMS {formatMilli(channel.rms_level_dbfs_milli, "dBFS")}</span>
          <span>峰均比 {channel.crest_factor_milli == null ? "—" : (channel.crest_factor_milli / 1_000).toFixed(2)}</span>
        </div>)}
      </div>

      <AudioLoudnessChart quality={quality} />
      <AudioLevelChart quality={quality} />
      <AudioSpectrumChart quality={quality} />
      <AudioSpectrogramChart quality={quality} />

      <div className="audio-intervals">
        <div className="audio-evidence-heading">
          <div><h3>内容异常区间</h3><span>{filteredIntervals.length} / {quality.intervals.length} 条</span></div>
          <button type="button" disabled={filteredIntervals.length === 0} onClick={() => onExportEvidence(filteredIntervals)}>导出筛选结果</button>
        </div>
        {quality.intervals.length > 0 && <div className="audio-interval-filters">
          <label className="interval-search">搜索<input type="search" value={intervalQuery} placeholder="类型、详情、包号或 Seq" onChange={(event) => setIntervalQuery(event.target.value)} /></label>
          <label>类型<select value={intervalKind} onChange={(event) => setIntervalKind(event.target.value)}><option value="all">全部类型</option>{intervalKinds.map((kind) => <option value={kind} key={kind}>{audioIntervalLabel(kind)}</option>)}</select></label>
          <label>声道<select value={intervalChannel} onChange={(event) => setIntervalChannel(event.target.value)}><option value="all">全部声道</option>{intervalChannels.map((channel) => <option value={String(channel)} key={channel}>声道 {channel}</option>)}</select></label>
          <label>开始秒<input type="number" min="0" step="0.1" value={intervalStart} placeholder="不限" onChange={(event) => setIntervalStart(event.target.value)} /></label>
          <label>结束秒<input type="number" min="0" step="0.1" value={intervalEnd} placeholder="不限" onChange={(event) => setIntervalEnd(event.target.value)} /></label>
          <button type="button" onClick={() => { setIntervalQuery(""); setIntervalKind("all"); setIntervalChannel("all"); setIntervalStart(""); setIntervalEnd(""); }}>清除筛选</button>
        </div>}
        {quality.intervals.length === 0 ? <p>当前分析范围内没有达到阈值的静音、削波或电平突变候选。</p> : filteredIntervals.length === 0 ? <p>没有符合当前搜索条件的异常区间。</p> : filteredIntervals.map((interval, index) => (
          <div className="audio-interval-row" key={`${interval.kind}-${interval.start_ms}-${index}`}>
            <button className="audio-interval-seek" type="button" onClick={() => onSeek(interval.start_ms)}>
              <strong>{audioIntervalLabel(interval.kind)} · 声道 {interval.channel ?? "全部"}</strong>
              <span>{formatDuration(interval.start_ms)}–{formatDuration(interval.end_ms)} · {interval.detail}{interval.first_packet != null ? ` · RTP 证据包 #${interval.first_packet}–#${interval.last_packet ?? interval.first_packet} / Seq ${interval.first_rtp_sequence ?? "—"}–${interval.last_rtp_sequence ?? interval.first_rtp_sequence ?? "—"}` : ""}</span>
              <small>点击跳转回听 · {interval.precision}</small>
            </button>
            <button className="audio-interval-export" type="button" disabled={!canExport} onClick={() => onExport(interval.start_ms, interval.end_ms)}>导出区间</button>
          </div>
        ))}
      </div>

      <details className="quality-method"><summary>测量口径与限制</summary><p>{quality.measurement_method}</p>{quality.limitations.map((item, index) => <p key={index}>{item}</p>)}</details>
    </div>
  );
}

function audioIntervalLabel(kind: string): string {
  if (kind === "silence") return "静音候选";
  if (kind === "clipping_candidate") return "削波候选";
  if (kind === "level_jump_candidate") return "音量突变候选";
  return kind;
}

function AudioLoudnessChart({ quality }: { quality: AudioQuality }) {
  const element = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!element.current || quality.loudness_series.length === 0) return;
    let disposed = false;
    let chart: { setOption: (option: unknown) => void; resize: () => void; dispose: () => void } | undefined;
    void Promise.all([import("echarts/core"), import("echarts/charts"), import("echarts/components"), import("echarts/renderers")]).then(([echarts, charts, components, renderers]) => {
      if (disposed || !element.current) return;
      echarts.use([charts.LineChart, components.GridComponent, components.TooltipComponent, components.LegendComponent, components.DataZoomComponent, renderers.CanvasRenderer]);
      chart = echarts.init(element.current);
      const data = (key: "momentary_lufs_milli" | "short_term_lufs_milli" | "integrated_lufs_milli") => quality.loudness_series.map((point) => [point.offset_ms / 1_000, point[key] == null ? null : point[key]! / 1_000]);
      chart.setOption({ animation: false, title: { text: "EBU R128 响度时间曲线", left: 12, textStyle: { fontSize: 13, color: "#2b3e55" } }, grid: { left: 58, right: 20, top: 62, bottom: 54 }, tooltip: { trigger: "axis" }, legend: { top: 30, textStyle: { fontSize: 9 } }, dataZoom: [{ type: "inside" }, { type: "slider", height: 17, bottom: 8 }], xAxis: { type: "value", name: "秒" }, yAxis: { type: "value", name: "LUFS", max: 0 }, series: [
        { name: "Momentary (400 ms)", type: "line", showSymbol: false, data: data("momentary_lufs_milli") },
        { name: "Short-term (3 s)", type: "line", showSymbol: false, data: data("short_term_lufs_milli") },
        { name: "Integrated", type: "line", showSymbol: false, lineStyle: { type: "dashed" }, data: data("integrated_lufs_milli") },
      ] });
    });
    const resize = () => chart?.resize();
    window.addEventListener("resize", resize);
    return () => { disposed = true; window.removeEventListener("resize", resize); chart?.dispose(); };
  }, [quality]);
  return <div className="audio-quality-chart" ref={element}>{quality.loudness_series.length === 0 ? "响度时间序列不可用" : ""}</div>;
}

function AudioLevelChart({ quality }: { quality: AudioQuality }) {
  const element = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!element.current || quality.level_series.length === 0) return;
    let disposed = false;
    let chart: { setOption: (option: unknown) => void; resize: () => void; dispose: () => void } | undefined;
    void Promise.all([import("echarts/core"), import("echarts/charts"), import("echarts/components"), import("echarts/renderers")]).then(([echarts, charts, components, renderers]) => {
      if (disposed || !element.current) return;
      echarts.use([charts.LineChart, components.GridComponent, components.TooltipComponent, components.LegendComponent, components.DataZoomComponent, renderers.CanvasRenderer]);
      chart = echarts.init(element.current);
      const series = quality.channels.flatMap((channel, channelIndex) => [
        { name: `声道 ${channel.channel} RMS`, type: "line", showSymbol: false, data: quality.level_series.map((point) => [point.offset_ms / 1_000, point.rms_level_dbfs_milli[channelIndex] == null ? null : point.rms_level_dbfs_milli[channelIndex]! / 1_000]) },
        { name: `声道 ${channel.channel} Peak`, type: "line", showSymbol: false, lineStyle: { type: "dashed", opacity: 0.65 }, data: quality.level_series.map((point) => [point.offset_ms / 1_000, point.peak_level_dbfs_milli[channelIndex] == null ? null : point.peak_level_dbfs_milli[channelIndex]! / 1_000]) },
      ]);
      chart.setOption({ animation: false, title: { text: `Peak / RMS 时间曲线（${quality.window_ms} ms 窗口）`, left: 12, textStyle: { fontSize: 13, color: "#2b3e55" } }, grid: { left: 58, right: 20, top: 62, bottom: 54 }, tooltip: { trigger: "axis" }, legend: { top: 30, textStyle: { fontSize: 9 } }, dataZoom: [{ type: "inside" }, { type: "slider", height: 17, bottom: 8 }], xAxis: { type: "value", name: "秒" }, yAxis: { type: "value", name: "dBFS", max: 0 }, series });
    });
    const resize = () => chart?.resize();
    window.addEventListener("resize", resize);
    return () => { disposed = true; window.removeEventListener("resize", resize); chart?.dispose(); };
  }, [quality]);
  return <div className="audio-quality-chart" ref={element}>{quality.level_series.length === 0 ? "没有可绘制的电平时间序列" : ""}</div>;
}

function AudioSpectrumChart({ quality }: { quality: AudioQuality }) {
  const element = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!element.current || quality.average_spectrum.length === 0) return;
    let disposed = false;
    let chart: { setOption: (option: unknown) => void; resize: () => void; dispose: () => void } | undefined;
    void Promise.all([import("echarts/core"), import("echarts/charts"), import("echarts/components"), import("echarts/renderers")]).then(([echarts, charts, components, renderers]) => {
      if (disposed || !element.current) return;
      echarts.use([charts.LineChart, components.GridComponent, components.TooltipComponent, renderers.CanvasRenderer]);
      chart = echarts.init(element.current);
      const data = quality.average_spectrum
        .filter((point) => point.frequency_hz >= 20)
        .map((point) => [point.frequency_hz, point.level_dbfs_milli / 1_000]);
      const maximumFrequency = data.at(-1)?.[0] ?? 20_000;
      chart.setOption({
        animation: false,
        title: { text: "平均频谱（对数频率）", left: 12, textStyle: { fontSize: 13, color: "#2b3e55" } },
        grid: { left: 58, right: 28, top: 48, bottom: 46 },
        tooltip: { trigger: "axis", axisPointer: { type: "cross" }, formatter: (items: unknown) => {
          const item = (items as Array<{ value: [number, number] }>)[0];
          if (!item) return "";
          return `<strong>${formatFrequency(item.value[0])} Hz</strong><br/>${item.value[1].toFixed(1)} dBFS`;
        } },
        xAxis: { type: "log", logBase: 10, min: 20, max: maximumFrequency, name: "Hz", minorTick: { show: true }, minorSplitLine: { show: true }, axisLabel: { formatter: (value: number) => formatFrequency(value) } },
        yAxis: { type: "value", name: "dBFS", min: -120, max: 0 },
        series: [{ type: "line", showSymbol: false, connectNulls: true, areaStyle: { opacity: 0.08 }, data }],
      });
    });
    const resize = () => chart?.resize();
    window.addEventListener("resize", resize);
    return () => { disposed = true; window.removeEventListener("resize", resize); chart?.dispose(); };
  }, [quality]);
  return <div className="audio-quality-chart spectrum" ref={element}>{quality.average_spectrum.length === 0 ? "样本太短，无法生成平均频谱" : ""}</div>;
}

function AudioSpectrogramChart({ quality }: { quality: AudioQuality }) {
  const element = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!element.current || quality.spectrogram.length === 0) return;
    let disposed = false;
    let chart: { setOption: (option: unknown) => void; resize: () => void; dispose: () => void } | undefined;
    void Promise.all([import("echarts/core"), import("echarts/charts"), import("echarts/components"), import("echarts/renderers")]).then(([echarts, charts, components, renderers]) => {
      if (disposed || !element.current) return;
      echarts.use([charts.HeatmapChart, components.GridComponent, components.TooltipComponent, components.VisualMapComponent, renderers.CanvasRenderer]);
      chart = echarts.init(element.current);
      const times = quality.spectrogram.map((frame) => frame.offset_ms / 1_000);
      const frequencies = quality.spectrogram_band_centers_hz;
      const observedLevels = quality.spectrogram.flatMap((frame) => frame.band_levels_dbfs_milli.map((level) => level / 1_000));
      const observedPeak = Math.max(...observedLevels);
      const visualMax = Math.min(0, Math.max(-100, Math.ceil(observedPeak / 5) * 5));
      const visualMin = Math.max(-120, visualMax - 80);
      const data = quality.spectrogram.flatMap((frame, timeIndex) => frame.band_levels_dbfs_milli.map((level, bandIndex) => {
        const rawLevel = level / 1_000;
        return [timeIndex, bandIndex, Math.max(visualMin, Math.min(visualMax, rawLevel)), rawLevel];
      }));
      chart.setOption({
        animation: false,
        title: { text: "Mel 时频图", subtext: `${visualMin.toFixed(0)}～${visualMax.toFixed(0)} dBFS`, left: 12, textStyle: { fontSize: 13, color: "#2b3e55" }, subtextStyle: { fontSize: 9, color: "#718095" } },
        grid: { left: 66, right: 78, top: 62, bottom: 50 },
        tooltip: { trigger: "item", confine: true, formatter: (item: unknown) => {
          const point = item as { value?: [number, number, number, number] };
          if (!point.value) return "";
          const time = times[point.value[0]] ?? 0;
          const frequency = frequencies[point.value[1]] ?? 0;
          return `<strong>${time.toFixed(2)} s</strong><br/>${formatFrequency(frequency)} Hz<br/>${point.value[3].toFixed(1)} dBFS`;
        } },
        visualMap: { min: visualMin, max: visualMax, dimension: 2, calculable: true, orient: "vertical", right: 4, top: 64, precision: 0, text: ["强", "弱"], inRange: { color: ["#000004", "#1b0c41", "#4f0a6d", "#812581", "#b5367a", "#e55964", "#fb8761", "#fec287", "#fcfdbf"] } },
        xAxis: { type: "category", data: times, name: "秒", axisLabel: { formatter: (value: number) => Number(value).toFixed(1), hideOverlap: true } },
        yAxis: { type: "category", data: frequencies, name: "Hz", axisLabel: { formatter: (value: number) => formatFrequency(Number(value)), hideOverlap: true } },
        series: [{ type: "heatmap", progressive: 0, data, emphasis: { itemStyle: { borderColor: "#ffffff", borderWidth: 1 } } }],
      });
    });
    const resize = () => chart?.resize();
    window.addEventListener("resize", resize);
    return () => { disposed = true; window.removeEventListener("resize", resize); chart?.dispose(); };
  }, [quality]);
  return <div className="audio-quality-chart spectrogram" ref={element}>{quality.spectrogram.length === 0 ? "样本太短，无法生成 Mel 时频图" : ""}</div>;
}

function formatFrequency(value: number): string {
  if (value >= 1_000) return `${Number((value / 1_000).toFixed(value >= 10_000 ? 0 : 1))}k`;
  return `${Math.round(value)}`;
}

function qpColor(value: number): string {
  const normalized = Math.max(0, Math.min(51, value));
  return `hsl(${(51 - normalized) * 2.35} 88% 50%)`;
}

function qpStatistics(qp: NonNullable<VideoWorkerFrame["qp"]> | null | undefined) {
  if (!qp || qp.blocks.length === 0) return null;
  let minimum = Number.POSITIVE_INFINITY;
  let maximum = Number.NEGATIVE_INFINITY;
  let weighted = 0;
  let area = 0;
  for (const block of qp.blocks) {
    const blockArea = Math.max(1, block.width * block.height);
    minimum = Math.min(minimum, block.value);
    maximum = Math.max(maximum, block.value);
    weighted += block.value * blockArea;
    area += blockArea;
  }
  return { minimum, maximum, average: weighted / area };
}

function VideoDeepAnalysisView({ analysis, nalus, parameterChanges, recoveryWindows, initialDisplayIndex, codec, reportDirectory, streamId }: { analysis: VideoDeepAnalysis | null; nalus: VideoNaluEvidence[]; parameterChanges: VideoParameterChange[]; recoveryWindows: VideoRecoveryWindow[]; initialDisplayIndex: number; codec: string; reportDirectory: string; streamId: string | null }) {
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [frameImage, setFrameImage] = useState("");
  const [frameImageError, setFrameImageError] = useState("");
  const [frameImageLoading, setFrameImageLoading] = useState(false);
  const [blockFrame, setBlockFrame] = useState<VideoWorkerFrame | null>(null);
  const [blockLoading, setBlockLoading] = useState(false);
  const [blockExporting, setBlockExporting] = useState(false);
  const [showQp, setShowQp] = useState(true);
  const [showMotion, setShowMotion] = useState(true);
  const [blockLayer, setBlockLayer] = useState(codec.toLowerCase().includes("264") ? "h264_macroblock" : "hevc_cu");
  const [selectedBlockDetail, setSelectedBlockDetail] = useState("");
  const [syntax, setSyntax] = useState<VideoSyntaxDocument | null>(null);
  const [syntaxNaluIndex, setSyntaxNaluIndex] = useState(0);
  const [syntaxLoading, setSyntaxLoading] = useState(false);
  const [hexFontSize, setHexFontSize] = useState(11);
  const [hexExpanded, setHexExpanded] = useState(false);
  const [packetLookup, setPacketLookup] = useState("");
  const [referenceComparison, setReferenceComparison] = useState<VideoReferenceComparison | null>(null);
  const [referenceDifference, setReferenceDifference] = useState("");
  const [referenceLoading, setReferenceLoading] = useState(false);
  const [referenceError, setReferenceError] = useState("");
  const frameImageRequest = useRef(0);
  const blockRequest = useRef(0);
  const syntaxRequest = useRef(0);
  const referenceRequest = useRef(0);
  useEffect(() => {
    frameImageRequest.current += 1;
    blockRequest.current += 1;
    syntaxRequest.current += 1;
    referenceRequest.current += 1;
    setSelectedIndex(Math.max(0, Math.min((analysis?.frames.length ?? 1) - 1, initialDisplayIndex)));
    setFrameImage(""); setFrameImageError(""); setFrameImageLoading(false);
    setBlockFrame(null); setBlockLoading(false); setSelectedBlockDetail("");
    setSyntax(null); setSyntaxLoading(false); setHexExpanded(false);
    setReferenceComparison(null); setReferenceDifference(""); setReferenceLoading(false); setReferenceError("");
  }, [analysis, initialDisplayIndex, reportDirectory, streamId]);
  useEffect(() => {
    if (!analysis) return;
    let disposed = false;
    const request = ++referenceRequest.current;
    void invoke<VideoReferenceComparison | null>("load_video_reference_comparison", { reportDirectory, streamId })
      .then((value) => { if (!disposed && referenceRequest.current === request) setReferenceComparison(value); })
      .catch(() => { /* No saved comparison is a normal initial state. */ });
    void invoke<string | null>("load_video_reference_difference", { reportDirectory, streamId })
      .then((value) => { if (!disposed && referenceRequest.current === request) setReferenceDifference(value ? convertFileSrc(value) : ""); })
      .catch(() => { /* No saved difference preview is a normal initial state. */ });
    return () => { disposed = true; };
  }, [analysis, reportDirectory, streamId]);
  if (!analysis) {
    return <div className="video-deep-view"><div className="protocol-empty">当前结果没有逐帧索引。请确认 ffprobe 可用，并对抓包流执行“深入分析此流”。</div></div>;
  }
  const frame = analysis.frames[selectedIndex];
  const visibleFrames = analysis.frames.slice(0, 1_000);
  const rangeStart = Math.max(0, selectedIndex - 20);
  const tableFrames = analysis.frames.slice(rangeStart, rangeStart + 41);
  const choose = (index: number) => {
    frameImageRequest.current += 1;
    blockRequest.current += 1;
    syntaxRequest.current += 1;
    setFrameImageLoading(false); setBlockLoading(false); setSyntaxLoading(false);
    setSelectedIndex(Math.max(0, Math.min(analysis.frames.length - 1, index))); setFrameImage(""); setFrameImageError(""); setBlockFrame(null); setSelectedBlockDetail(""); setSyntax(null); setSyntaxNaluIndex(0); setHexExpanded(false);
  };
  const loadFrameImage = async () => {
    const request = ++frameImageRequest.current;
    const displayIndex = selectedIndex;
    setFrameImageLoading(true);
    setFrameImageError("");
    try {
      const path = await invoke<string>("extract_video_frame", { reportDirectory, streamId, displayIndex });
      if (frameImageRequest.current === request) setFrameImage(convertFileSrc(path));
    } catch (reason) {
      if (frameImageRequest.current === request) setFrameImageError(String(reason));
    } finally {
      if (frameImageRequest.current === request) setFrameImageLoading(false);
    }
  };
  const loadBlockData = async () => {
    const request = ++blockRequest.current;
    const displayIndex = selectedIndex;
    setBlockLoading(true);
    setFrameImageError("");
    try {
      const [path, blocks] = await Promise.all([
        frameImage ? Promise.resolve("") : invoke<string>("extract_video_frame", { reportDirectory, streamId, displayIndex }),
        invoke<VideoWorkerFrame>("analyze_video_frame_blocks", { reportDirectory, streamId, displayIndex }),
      ]);
      if (blockRequest.current !== request) return;
      if (path) setFrameImage(convertFileSrc(path));
      setBlockFrame(blocks);
    } catch (reason) {
      if (blockRequest.current === request) setFrameImageError(String(reason));
    } finally {
      if (blockRequest.current === request) setBlockLoading(false);
    }
  };
  const loadSyntax = async () => {
    const request = ++syntaxRequest.current;
    const displayIndex = selectedIndex;
    setSyntaxLoading(true);
    setFrameImageError("");
    try {
      const document = await invoke<VideoSyntaxDocument>("load_video_frame_syntax", { reportDirectory, streamId, displayIndex });
      if (syntaxRequest.current !== request) return;
      setSyntax(document);
      setSyntaxNaluIndex(0);
    } catch (reason) {
      if (syntaxRequest.current === request) setFrameImageError(String(reason));
    } finally {
      if (syntaxRequest.current === request) setSyntaxLoading(false);
    }
  };
  const exportBlockCsv = async () => {
    setBlockExporting(true);
    setFrameImageError("");
    try {
      const destination = await save({
        defaultPath: `frame-${selectedIndex}-blocks.csv`,
        filters: [{ name: "CSV", extensions: ["csv"] }],
      });
      if (!destination) return;
      const path = await invoke<string>("export_video_block_csv", { reportDirectory, streamId, displayIndex: selectedIndex, destinationPath: destination });
      setSelectedBlockDetail(`块数据已导出：${path}`);
    } catch (reason) {
      setFrameImageError(String(reason));
    } finally {
      setBlockExporting(false);
    }
  };
  const compareReference = async () => {
    const request = ++referenceRequest.current;
    setReferenceLoading(true);
    setReferenceError("");
    try {
      const reference = await open({
        multiple: false,
        directory: false,
        filters: [{ name: "参考视频", extensions: ["h264", "264", "h265", "265", "hevc", "mp4", "mkv", "mov", "avi", "ts", "m2ts", "webm"] }],
      });
      if (typeof reference !== "string") return;
      const result = await invoke<VideoReferenceComparison>("compare_video_reference", { reportDirectory, streamId, referencePath: reference });
      if (referenceRequest.current !== request) return;
      setReferenceComparison(result);
      const difference = await invoke<string | null>("load_video_reference_difference", { reportDirectory, streamId });
      if (referenceRequest.current === request) setReferenceDifference(difference ? convertFileSrc(difference) : "");
    } catch (reason) {
      if (referenceRequest.current === request) setReferenceError(String(reason));
    } finally {
      if (referenceRequest.current === request) setReferenceLoading(false);
    }
  };
  const displayedVectors = blockFrame?.motion_vectors.filter((_, index, values) => index % Math.max(1, Math.ceil(values.length / 2_000)) === 0) ?? [];
  const internalBlocks = blockFrame?.block_observations ?? [];
  const internalMotion = internalBlocks.filter((block) => block.block_level === "hevc_pu" && block.prediction_flags !== 0);
  const selectedLayerBlocks = blockLayer ? internalBlocks.filter((block) => block.block_level === blockLayer) : [];
  const displayedLayerBlocks = selectedLayerBlocks.filter((_, index, values) => index % Math.max(1, Math.ceil(values.length / 5_000)) === 0);
  const hevcTreeCounts = codec.toLowerCase().includes("264") ? "" : ["hevc_ctu", "hevc_cu", "hevc_pu", "hevc_tu"].map((level) => `${level.slice(5).toUpperCase()} ${internalBlocks.filter((block) => block.block_level === level).length.toLocaleString()}`).join(" / ");
  const syntaxNalu = syntax?.nalus[syntaxNaluIndex];
  const qpStats = qpStatistics(blockFrame?.qp);
  const packetNumber = Number(packetLookup);
  const packetMatches = Number.isSafeInteger(packetNumber) && packetNumber > 0 ? nalus.filter((nalu) => nalu.packets.some((packet) => packet.packet_number === packetNumber)) : [];
  return <div className="video-deep-view">
    <div className="video-deep-heading">
      <div><h3>{codec} 帧工作台</h3><p>索引值来自本次实际 ffprobe 解码输出；未取得的块级数据不会显示为 0。</p></div>
      <span className={analysis.coverage_complete ? "scan-ok" : "scan-warning"}>{analysis.coverage_complete ? "索引覆盖完整" : "索引覆盖受限"}</span>
    </div>
    <div className="evidence-list parameter-change-list">
      <h3>参数集变更 · {parameterChanges.length}</h3>
      {parameterChanges.length === 0 ? <p className="capture-note">保留样本中没有发现同一参数集 ID 的字段变化。</p> : parameterChanges.map((change) => <div className="evidence" key={`${change.nalu_number}-${change.parameter_kind}-${change.parameter_id}`}>
        <strong>{change.parameter_kind.toUpperCase()} #{change.parameter_id}</strong>
        <span>NALU #{change.nalu_number} · 从 AU #{change.effective_access_unit ?? "未知"} 生效</span>
        <code>{change.changed_fields.join("、")}</code>
      </div>)}
    </div>
    <div className="evidence-list parameter-change-list">
      <h3>传播与恢复窗口 · {recoveryWindows.length}</h3>
      {recoveryWindows.length === 0 ? <p className="capture-note">当前覆盖范围内没有可关联到帧的结构或解码异常起点。</p> : recoveryWindows.slice(0, 200).map((window, index) => <div className="evidence" key={`${window.source_frame}-${window.source_kind}-${index}`}>
        <strong>异常帧 #{window.source_frame} · {window.source_kind}</strong>
        <span>{window.next_random_access_frame == null ? "覆盖范围内未观察到后续 IDR/CRA" : `下一随机接入帧 #${window.next_random_access_frame} · 等待 ${window.wait_frames ?? "未知"} 帧${window.wait_ms == null ? "" : ` / ${window.wait_ms} ms`}`}</span>
        <code>{window.visual_status === "post_access_anomaly_candidate" ? "随机接入点后仍有画面异常候选" : "未确认画面恢复"}</code>
        {window.first_packet != null && <small>抓包 #{window.first_packet}{window.last_packet != null && window.last_packet !== window.first_packet ? `–${window.last_packet}` : ""}</small>}
        {window.limitations.map((item) => <small key={item}>{item}</small>)}
      </div>)}
    </div>
    <div className="protocol-facts video-deep-facts">
      <Metric label="索引帧" value={analysis.indexed_frames.toLocaleString()} detail={analysis.status} />
      <Metric label="覆盖起点" value={formatDuration(analysis.coverage_start_ms)} detail="PTS/best effort" />
      <Metric label="覆盖终点" value={formatDuration(analysis.coverage_end_ms)} detail="PTS + duration" />
      <Metric label="关键帧" value={analysis.frames.filter((item) => item.key_frame).length.toLocaleString()} detail="ffprobe key_frame" />
      <Metric label="帧型" value={[...new Set(analysis.frames.map((item) => item.picture_type).filter(Boolean))].join(" / ") || "—"} detail="解码器报告" />
    </div>
    {analysis.coverage_reason && <div className="deep-warning">{analysis.coverage_reason}</div>}
    <div className="deep-capabilities">
      {analysis.capabilities.map((capability) => <div className={capability.status === "available" ? "available" : capability.status === "on_demand" ? "on-demand" : "unavailable"} key={capability.id}>
        <strong>{capability.label}</strong><span>{capability.status === "available" ? "可用" : capability.status === "on_demand" ? "按帧加载" : "尚不可用"}</span>{capability.reason && <small>{capability.reason}</small>}
      </div>)}
    </div>
    <div className="evidence-list parameter-change-list">
      <div className="video-deep-heading">
        <div><h3>参考视频质量对比</h3><p>按起始帧对齐，将参考画面缩放到当前视频尺寸，只比较共同有效帧。</p></div>
        <button type="button" disabled={referenceLoading} onClick={() => { void compareReference(); }}>{referenceLoading ? "正在计算 PSNR / SSIM…" : "选择参考视频并计算"}</button>
      </div>
      {referenceComparison && <>
        <div className="protocol-facts video-deep-facts">
          <Metric label="参考文件" value={referenceComparison.reference_name} detail="仅记录文件名" />
          <Metric label="PSNR" value={referenceComparison.psnr_identical ? "∞" : referenceComparison.psnr_average_db == null ? "—" : `${referenceComparison.psnr_average_db.toFixed(3)} dB`} detail={referenceComparison.psnr_identical ? "逐像素一致" : "平均值"} />
          <Metric label="SSIM" value={referenceComparison.ssim_all.toFixed(6)} detail="All" />
          <Metric label="VMAF" value={referenceComparison.vmaf_mean == null ? "不可用" : referenceComparison.vmaf_mean.toFixed(3)} detail="可选 libvmaf" />
          <Metric label="比较帧数" value={referenceComparison.compared_frames.toLocaleString()} detail="共同有效范围" />
          <Metric label="共同覆盖" value={formatDuration(referenceComparison.compared_duration_ms)} detail={referenceComparison.coverage_basis || "旧版结果未记录"} />
          <Metric label="主视频输入" value={referenceComparison.source_width && referenceComparison.source_height ? `${referenceComparison.source_width}×${referenceComparison.source_height}` : "—"} detail={`${referenceComparison.source_pixel_format ?? "像素格式未知"} · ${referenceComparison.source_frame_rate ?? "帧率未知"}`} />
          <Metric label="参考视频输入" value={referenceComparison.reference_width && referenceComparison.reference_height ? `${referenceComparison.reference_width}×${referenceComparison.reference_height}` : "—"} detail={`${referenceComparison.reference_pixel_format ?? "像素格式未知"} · ${referenceComparison.reference_frame_rate ?? "帧率未知"}`} />
          <Metric label="比较格式" value={referenceComparison.comparison_pixel_format || "旧版结果未记录"} detail={referenceComparison.alignment_method || "对齐方式未记录"} />
          <Metric label="内容对齐偏移" value={formatDuration(referenceComparison.detected_offset_ms)} detail={`置信度 ${referenceComparison.alignment_confidence_percent ?? 0}% · 指纹误差 ${referenceComparison.alignment_error_milli == null ? "—" : (referenceComparison.alignment_error_milli / 1000).toFixed(3)}`} />
        </div>
        <p className="capture-note">{referenceComparison.method}</p>
        {referenceComparison.limitations.map((item) => <p className="capture-note" key={item}>{item}</p>)}
        {referenceDifference && <video className="preview-player" controls preload="metadata" src={referenceDifference} />}
      </>}
      {referenceError && <p className="deep-frame-error">{referenceError}</p>}
    </div>
    {frame ? <>
      <div className="frame-navigator">
        <button type="button" disabled={selectedIndex === 0} onClick={() => choose(selectedIndex - 1)}>上一帧</button>
        <label>显示帧 <input type="number" min={0} max={analysis.frames.length - 1} value={selectedIndex} onChange={(event) => choose(Number(event.target.value))} /> / {analysis.frames.length - 1}</label>
        <button type="button" disabled={selectedIndex + 1 >= analysis.frames.length} onClick={() => choose(selectedIndex + 1)}>下一帧</button>
      </div>
      {nalus.some((nalu) => nalu.packets.length > 0) && <div className="packet-frame-lookup">
        <label>抓包号反查帧 <input type="number" min={1} value={packetLookup} placeholder="例如 1205" onChange={(event) => setPacketLookup(event.target.value)} /></label>
        {packetLookup && packetMatches.length === 0 && <span>该抓包号不属于当前流已保留的 NALU。</span>}
        {packetMatches.map((nalu) => {
          const mapped = nalu.access_unit_number == null ? undefined : analysis.frames.find((item) => item.decode_index === nalu.access_unit_number! - 1);
          return <button type="button" key={nalu.nalu_number} disabled={!mapped} onClick={() => mapped && choose(mapped.display_index)}>NALU #{nalu.nalu_number} · AU #{nalu.access_unit_number ?? "—"}{mapped ? ` · 显示帧 #${mapped.display_index}` : " · 无可靠显示帧映射"}</button>;
        })}
      </div>}
      <div className="gop-strip" aria-label="前 1000 帧 GOP 图">
        {visibleFrames.map((item) => <button type="button" title={`#${item.display_index} ${item.picture_type ?? "?"} ${formatDuration(item.pts_ms)}`} className={`${item.picture_type?.toLowerCase() ?? "unknown"} ${item.key_frame ? "key" : ""} ${item.display_index === selectedIndex ? "selected" : ""}`} key={item.display_index} onClick={() => choose(item.display_index)} />)}
      </div>
      {analysis.frames.length > visibleFrames.length && <p className="capture-note">GOP 条带仅绘制前 1,000 帧；帧号输入与下表仍可定位全部已索引帧。</p>}
      <div className="selected-frame-card">
        <div><span>显示序号</span><strong>#{frame.display_index}</strong></div>
        <div><span>编码序号</span><strong>{frame.decode_index ?? "—"}</strong><small>{frame.decode_index_precision}</small></div>
        <div><span>帧型</span><strong>{frame.picture_type ?? "—"}{frame.key_frame ? " · Key" : ""}</strong></div>
        <div><span>PTS / DTS</span><strong>{formatDuration(frame.pts_ms)} / {formatDuration(frame.dts_ms)}</strong></div>
        <div><span>包位置 / 大小</span><strong>{frame.packet_position ?? "—"} / {frame.packet_size ?? "—"} B</strong></div>
        <div><span>扫描方式</span><strong>{frame.interlaced == null ? "未知" : frame.interlaced ? `隔行${frame.top_field_first == null ? "" : frame.top_field_first ? " · TFF" : " · BFF"}` : "逐行"}</strong></div>
      </div>
      <div className="exact-frame-viewer">
        <div><strong>精确帧画面</strong><span>按显示序号从本次原始视频源解码，不使用预览视频 currentTime 近似定位。</span></div>
        <button type="button" disabled={frameImageLoading} onClick={() => { void loadFrameImage(); }}>{frameImageLoading ? "正在提取…" : `加载第 ${selectedIndex} 帧`}</button>
        <button type="button" disabled={blockLoading} onClick={() => { void loadBlockData(); }}>{blockLoading ? "正在分析块数据…" : "加载 QP / 运动矢量"}</button>
        <button type="button" disabled={syntaxLoading} onClick={() => { void loadSyntax(); }}>{syntaxLoading ? "正在读取语法…" : "加载语法树 / HEX"}</button>
        <button type="button" disabled={blockExporting} onClick={() => { void exportBlockCsv(); }}>{blockExporting ? "正在导出…" : "导出块数据 CSV"}</button>
        {blockFrame && <div className="block-layer-controls">
          <label><input type="checkbox" checked={showQp} onChange={(event) => setShowQp(event.target.checked)} />QP 热力图</label>
          <label title={blockFrame.motion_vectors.length === 0 ? "I 帧或当前解码器未提供运动矢量" : "显示或隐藏运动矢量"}><input type="checkbox" checked={showMotion && blockFrame.motion_vectors.length > 0} disabled={blockFrame.motion_vectors.length === 0} onChange={(event) => setShowMotion(event.target.checked)} />运动矢量{blockFrame.motion_vectors.length === 0 ? "（当前帧无数据）" : ""}</label>
          <label>块边界 <select value={blockLayer} onChange={(event) => setBlockLayer(event.target.value)}>
            <option value="">关闭</option>
            {codec.toLowerCase().includes("264") ? <option value="h264_macroblock">H.264 宏块</option> : <>
              <option value="hevc_ctu">HEVC CTU</option>
              <option value="hevc_cu">HEVC 叶子 CU</option>
              <option value="hevc_pu">HEVC PU</option>
              <option value="hevc_tu">HEVC 叶子 TU</option>
            </>}
          </select></label>
          <span>QP {blockFrame.qp?.blocks.length.toLocaleString() ?? 0} 块{qpStats ? ` · min ${qpStats.minimum} / avg ${qpStats.average.toFixed(2)} / max ${qpStats.maximum}` : ""} · MV {blockFrame.motion_vectors.length.toLocaleString()} 条{displayedVectors.length < blockFrame.motion_vectors.length ? `（显示抽样 ${displayedVectors.length.toLocaleString()} 条）` : ""}</span>
          {blockFrame.analyzer_version && <span>{blockFrame.analyzer_version}</span>}
          <span>内部块证据 {internalBlocks.length.toLocaleString()} 条 · HEVC 运动采样 {internalMotion.length.toLocaleString()} 条{hevcTreeCounts && ` · ${hevcTreeCounts}`}</span>
          {displayedLayerBlocks.length < selectedLayerBlocks.length && <span>块边界抽样显示 {displayedLayerBlocks.length.toLocaleString()} / {selectedLayerBlocks.length.toLocaleString()} 条；CSV 保留全部</span>}
          <span className="qp-color-legend"><i />低 QP <b />高 QP</span>
        </div>}
        {frameImage && <div className="video-block-canvas">
          <img src={frameImage} alt={`显示帧 ${selectedIndex}`} onError={() => { setFrameImage(""); setFrameImageError("帧图像加载失败，请重新加载该帧。"); }} />
          {blockFrame && <svg viewBox={`0 0 ${blockFrame.width} ${blockFrame.height}`} role="img" aria-label={`第 ${selectedIndex} 帧 QP 与运动矢量覆盖层`}>
            {showQp && blockFrame.qp?.blocks.map((block, index) => <rect key={`qp-${index}`} x={block.x} y={block.y} width={block.width} height={block.height} fill={qpColor(block.value)} fillOpacity="0.42" stroke="rgba(255,255,255,.18)" strokeWidth="0.35" onClick={() => setSelectedBlockDetail(`QP 块 #${index}：QP ${block.value}（base ${blockFrame.qp?.base}, delta ${block.delta}），坐标 ${block.x},${block.y}，尺寸 ${block.width}×${block.height}`)}><title>{`QP ${block.value}（base ${blockFrame.qp?.base}, delta ${block.delta}）· x=${block.x}, y=${block.y}, ${block.width}×${block.height}`}</title></rect>)}
            {displayedLayerBlocks.map((block, index) => <rect key={`tree-${block.block_level}-${index}`} x={block.x} y={block.y} width={block.width} height={block.height} fill="transparent" stroke={block.block_level === "hevc_ctu" ? "#ffbd3d" : block.block_level === "hevc_cu" ? "#00f0ff" : block.block_level === "hevc_pu" ? "#ff4fd8" : block.block_level === "hevc_tu" ? "#8cff66" : "#ffffff"} strokeWidth={block.block_level === "hevc_ctu" ? 1.8 : 1} vectorEffect="non-scaling-stroke" onClick={() => setSelectedBlockDetail(`${block.block_level}：坐标 ${block.x},${block.y}，尺寸 ${block.width}×${block.height}，分区 ${block.partition_mode ?? "不适用"}，预测 ${block.prediction_mode ?? "不适用"}，深度 ${block.tree_depth ?? "未知"}${block.transform_flags == null ? "" : `，CBF ${block.transform_flags & 1 ? "Y" : "-"}/${block.transform_flags & 2 ? "Cb" : "-"}/${block.transform_flags & 4 ? "Cr" : "-"}`}`)}><title>{`${block.block_level} · ${block.width}×${block.height} · ${block.partition_mode ?? block.prediction_mode ?? ""}`}</title></rect>)}
            {showMotion && displayedVectors.map((vector, index) => <line key={`mv-${index}`} x1={vector.destination_x} y1={vector.destination_y} x2={vector.source_x} y2={vector.source_y} stroke={vector.source_direction < 0 ? "#00f0ff" : "#ffbd3d"} strokeWidth="1.2" vectorEffect="non-scaling-stroke" onClick={() => setSelectedBlockDetail(`MV #${index}：参考方向 ${vector.source_direction}，目标 (${vector.destination_x},${vector.destination_y}) → 源 (${vector.source_x},${vector.source_y})，原始 (${vector.motion_x},${vector.motion_y}) / scale ${vector.motion_scale}，块 ${vector.width}×${vector.height}`)}><title>{`参考方向 ${vector.source_direction} · (${vector.destination_x},${vector.destination_y}) → (${vector.source_x},${vector.source_y}) · raw (${vector.motion_x},${vector.motion_y})/${vector.motion_scale}`}</title></line>)}
          </svg>}
        </div>}
        {selectedBlockDetail && <p className="selected-block-detail">{selectedBlockDetail}</p>}
        {blockFrame && !blockFrame.qp && <p className="deep-warning">该帧的解码器没有导出可验证的块级 QP；软件不会用 0 或推测值填充。</p>}
        {blockFrame && blockFrame.motion_vectors.length === 0 && <p className="capture-note">该帧没有导出运动矢量（I 帧或当前解码器不提供此 side data）。</p>}
        {blockFrame && internalBlocks.length > 0 && <details className="block-internal-evidence">
          <summary>解码器内部块证据（显示前 200 条）</summary>
          <p className="capture-note">H.264 记录实际宏块与子宏块分区及参考关系；HEVC 的 QP 网格单独显示，内部证据只列出解码器实际 CTU、叶子 CU、PU 和有变换语法的叶子 TU，避免重复输出最小网格。TU 的 CBF 位为 Y/Cb/Cr；无残差或 PCM CU 不伪造 TU。</p>
          <div className="frame-index-table">
            <div className="table-head"><span>层级</span><span>坐标/尺寸</span><span>QP/类型位</span><span>L0</span><span>L1</span><span>MV</span></div>
            {internalBlocks.slice(0, 200).map((block, index) => <button type="button" key={`${block.block_level}-${block.x}-${block.y}-${index}`} onClick={() => setSelectedBlockDetail(`${block.block_level} @ ${block.x},${block.y} ${block.width}×${block.height}；QP ${block.qp ?? "未知"}；分区 ${block.partition_mode ?? "不适用"}${(block.sub_partition_modes ?? []).some(Boolean) ? `；子分区 [${(block.sub_partition_modes ?? []).map((value) => value ?? "—").join(",")}]` : ""}${block.prediction_mode ? `；预测 ${block.prediction_mode}` : ""}${block.tree_depth != null ? `；深度 ${block.tree_depth}` : ""}${block.transform_flags != null ? `；CBF Y/Cb/Cr ${block.transform_flags & 1 ? 1 : 0}/${block.transform_flags & 2 ? 1 : 0}/${block.transform_flags & 4 ? 1 : 0}` : ""}；type 0x${block.type_flags.toString(16)}；L0 [${block.ref_index_l0.join(",")}] POC [${block.reference_poc_l0.map((value) => value ?? "未知").join(",")}]；L1 [${block.ref_index_l1.join(",")}] POC [${block.reference_poc_l1.map((value) => value ?? "未知").join(",")}]`)}>
              <span>{block.block_level}{block.partition_mode ? ` · ${block.partition_mode}${(block.sub_partition_modes ?? []).some(Boolean) ? ` [${(block.sub_partition_modes ?? []).map((value) => value ?? "—").join(",")}]` : ""}` : ""}{block.prediction_mode ? ` · ${block.prediction_mode}` : ""}{block.tree_depth != null ? ` · d${block.tree_depth}` : ""}</span><span>{block.x},{block.y} / {block.width}×{block.height}</span><span>{block.qp ?? "—"} / 0x{block.type_flags.toString(16)}</span><span>{block.ref_index_l0.join(",")} / POC {block.reference_poc_l0.map((value) => value ?? "—").join(",")}</span><span>{block.ref_index_l1.join(",")} / POC {block.reference_poc_l1.map((value) => value ?? "—").join(",")}</span><code>L0 {block.motion_l0_x ?? "—"},{block.motion_l0_y ?? "—"} · L1 {block.motion_l1_x ?? "—"},{block.motion_l1_y ?? "—"}</code>
            </button>)}
          </div>
        </details>}
        {frameImageError && <p className="deep-frame-error">{frameImageError}</p>}
      </div>
      {syntax && syntaxNalu && <div className="syntax-workbench">
        <div className="syntax-summary"><strong>访问单元 #{syntax.access_unit_index ?? "—"}</strong><span>{syntax.mapping_precision}</span></div>
        <div className="syntax-nalu-tabs">{syntax.nalus.map((nalu, index) => <button type="button" className={index === syntaxNaluIndex ? "selected" : ""} key={nalu.index} onClick={() => setSyntaxNaluIndex(index)}>NALU #{nalu.index} · {nalu.type_name} ({nalu.size} B) · RTP {nalu.packets.length}</button>)}</div>
        <div className={`syntax-columns${hexExpanded ? " hex-expanded" : ""}`}>
          <div className="syntax-tree"><h4>字段</h4>{syntaxNalu.fields.map((field) => <div key={`${field.source}-${field.name}`}><code>{field.name}</code><strong>{field.value}</strong><span>{field.source}</span></div>)}<h4>RTP 包映射 · {syntaxNalu.complete == null ? "离线文件" : syntaxNalu.complete ? "NALU 完整" : "NALU 不完整"}</h4>{syntaxNalu.packets.length === 0 ? <p className="syntax-empty">该输入没有包级来源信息。</p> : syntaxNalu.packets.map((packet) => <div key={`${packet.packet_number}-${packet.rtp_sequence}`}><code>抓包 #{packet.packet_number}</code><strong>Seq {packet.rtp_sequence}</strong><span>到达偏移 {packet.offset_ms} ms</span></div>)}</div>
          <div className="syntax-hex"><div className="syntax-hex-heading"><h4>HEX · offset {syntaxNalu.offset}</h4><div><button type="button" disabled={hexFontSize <= 9} onClick={() => setHexFontSize((value) => Math.max(9, value - 1))} aria-label="缩小 HEX 字号">−</button><span>{hexFontSize}px</span><button type="button" disabled={hexFontSize >= 20} onClick={() => setHexFontSize((value) => Math.min(20, value + 1))} aria-label="放大 HEX 字号">＋</button><button type="button" onClick={() => setHexExpanded((value) => !value)}>{hexExpanded ? "恢复双栏" : "放大显示"}</button></div></div><pre style={{ fontSize: `${hexFontSize}px` }}>{syntaxNalu.hex}</pre>{syntaxNalu.hex_truncated && <p>仅显示前 4,096 字节，原始 NALU 未被截断。</p>}</div>
        </div>
        <div className="syntax-limitations">{syntax.limitations.map((item) => <p key={item}>{item}</p>)}</div>
      </div>}
      <div className="frame-index-table">
        <div className="table-head"><span>显示序号</span><span>编码序号</span><span>类型</span><span>PTS</span><span>DTS</span><span>字节位置 / 大小</span></div>
        {tableFrames.map((item) => <button type="button" className={item.display_index === selectedIndex ? "selected" : ""} key={item.display_index} onClick={() => choose(item.display_index)}>
          <span>#{item.display_index}</span><span>{item.decode_index ?? "—"}</span><strong>{item.picture_type ?? "—"}{item.key_frame ? " · K" : ""}</strong><span>{formatDuration(item.pts_ms)}</span><span>{formatDuration(item.dts_ms)}</span><code>{item.packet_position ?? "—"} / {item.packet_size ?? "—"} B</code>
        </button>)}
      </div>
    </> : <div className="protocol-empty">ffprobe 没有返回可索引的视频帧。</div>}
    <div className="deep-limitations"><h4>当前能力边界</h4>{analysis.limitations.map((item) => <p key={item}>{item}</p>)}</div>
  </div>;
}

function TimelineChart({ events }: { events: AnalysisRun["result"]["timeline"] }) {
  const element = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!element.current) return;
    let disposed = false;
    let chart: { setOption: (option: unknown) => void; resize: () => void; dispose: () => void } | undefined;
    const timed = events.filter((event) => event.offset_ms !== null);
    const severityOrder = ["info", "low", "medium", "high", "critical"];
    const severityColors = ["#718095", "#3b82f6", "#e89028", "#dc4b54", "#b91c1c"];
    void Promise.all([
      import("echarts/core"), import("echarts/charts"), import("echarts/components"), import("echarts/renderers"),
    ]).then(([echarts, charts, components, renderers]) => {
      if (disposed || !element.current) return;
      echarts.use([charts.ScatterChart, components.GridComponent, components.TooltipComponent, renderers.CanvasRenderer]);
      chart = echarts.init(element.current);
      chart.setOption({
        animation: false,
        grid: { left: 48, right: 18, top: 28, bottom: 34 },
        tooltip: { trigger: "item", formatter: (item: unknown) => {
          const point = item as { data: { name: string; detail: string } };
          return `${point.data.name}<br/>${point.data.detail}`;
        } },
        xAxis: { type: "value", name: "ms", axisLabel: { color: "#718095" }, splitLine: { lineStyle: { color: "#edf1f5" } } },
        yAxis: { type: "category", data: ["Info", "Low", "Medium", "High", "Critical"], axisLabel: { color: "#718095" } },
        series: [{ type: "scatter", symbolSize: 12, data: timed.map((event) => {
          const severityIndex = Math.max(0, severityOrder.indexOf(event.severity));
          return { value: [event.offset_ms ?? 0, severityIndex], name: `${event.source} · ${event.event_type}`, detail: event.detail, itemStyle: { color: severityColors[severityIndex] } };
        }) }],
      });
    });
    const resize = () => chart?.resize();
    window.addEventListener("resize", resize);
    return () => { disposed = true; window.removeEventListener("resize", resize); chart?.dispose(); };
  }, [events]);
  return <div className="timeline-chart" ref={element} />;
}

export default App;
