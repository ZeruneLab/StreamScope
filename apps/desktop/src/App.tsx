import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { convertFileSrc, invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import { CaptureStreams } from "./CaptureStreams";
import type {
  AnalysisProgress,
  AnalysisRun,
  AnalysisStatus,
  ComparisonRun,
  RecentRun,
} from "./types";

type View = "overview" | "playback" | "audioQuality" | "protocol" | "stream" | "diagnostics" | "timeline" | "report" | "log";
type InputMode = "rtsp" | "h264" | "h265" | "audio" | "pcap";
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
  const [selectedAudioTrackId, setSelectedAudioTrackId] = useState<string | null>(null);
  const reportFrame = useRef<HTMLIFrameElement>(null);
  const previewVideo = useRef<HTMLVideoElement>(null);
  const previewAudio = useRef<HTMLAudioElement>(null);

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
  const finalRtspStatus = (method: string) => protocol?.transactions.filter((item) => item.method === method).at(-1)?.status_code;
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

  return (
    <div className="app-shell">
      <aside className="sidebar">
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

        <nav aria-label="主导航">
          <button className={`nav-item ${inputMode === "rtsp" ? "active" : ""}`} type="button" onClick={() => { setInputMode("rtsp"); setOfflinePath(""); }}>
            <span className="nav-icon">⌁</span>实时分析
          </button>
          <button className={`nav-item ${inputMode === "h264" ? "active" : ""}`} type="button" onClick={() => { setInputMode("h264"); setOfflinePath(""); }}>
            <span className="nav-icon">◇</span>H.264 文件
          </button>
          <button className={`nav-item ${inputMode === "h265" ? "active" : ""}`} type="button" onClick={() => { setInputMode("h265"); setOfflinePath(""); }}>
            <span className="nav-icon">◇</span>H.265 / HEVC
          </button>
          <button className={`nav-item ${inputMode === "audio" ? "active" : ""}`} type="button" onClick={() => { setInputMode("audio"); setOfflinePath(""); }}>
            <span className="nav-icon">♫</span>音频文件
          </button>
          <button className={`nav-item ${inputMode === "pcap" ? "active" : ""}`} type="button" onClick={() => { setInputMode("pcap"); setOfflinePath(""); }}>
            <span className="nav-icon">◫</span>PCAP / PCAPNG
          </button>
        </nav>

        <div className="history">
          <div className="section-label">最近任务</div>
          {history.length === 0 ? (
            <p className="history-empty">完成分析后，脱敏记录会显示在这里。</p>
          ) : (
            history.map((item, index) => (
              <div className="history-row" key={`${item.generatedAt}-${index}`}>
                <button className="history-item" type="button" disabled={running} onClick={() => openHistory(item)} title="重新打开此报告">
                  <span className={`status-dot ${item.status}`} />
                  <div>
                    <strong>{item.sourceUrl}</strong>
                    <small>{new Date(item.generatedAt).toLocaleString("zh-CN")}</small>
                    {item.criticalCount > 0 && <small>{item.criticalCount} 项高风险</small>}
                  </div>
                </button>
                <button className="history-delete" type="button" disabled={running} onClick={() => deleteHistoryReport(item)} title="删除报告">×</button>
              </div>
            ))
          )}
        </div>

        <div className="sidebar-footer">
          <span className="online-dot" />本机分析引擎
          <small>高级音画诊断 · v0.1.4</small>
        </div>
      </aside>

      <main>
        <header className="topbar">
          <div>
            <p className="eyebrow">RTSP INSPECTOR</p>
            <h1>{inputMode === "pcap" ? "多流抓包诊断" : inputMode === "h264" ? "H.264 文件诊断" : inputMode === "h265" ? "H.265 文件诊断" : inputMode === "audio" ? "音频文件诊断" : "实时流诊断"}</h1>
            <p>{inputMode === "pcap" ? "发现抓包中的媒体流，独立查看每路的网络与码流证据。" : "验证媒体参数与实际解码结果。"}</p>
          </div>
          <div className={`health-pill ${health.className}`}>
            <span />{health.label}
          </div>
        </header>

        <section className="workspace">
          <form className="analysis-form panel" onSubmit={submit}>
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
                <div className="segmented">
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
                <><span className="play-icon">▶</span>{inputMode === "rtsp" ? "开始诊断" : inputMode === "pcap" ? "扫描媒体流" : "分析文件"}</>
              )}
            </button>
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

          {error && <div className="error-banner"><strong>无法开始分析</strong>{error}</div>}

          <section className={`results panel ${run ? "has-result" : ""}`}>
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
                  <button type="button" onClick={() => { setSelectedStreamId(null); setView("overview"); }}>← 所有媒体流（{capture?.stream_count}）</button>
                  <div><strong>当前流：{identity.id}</strong><code>{identity.source} → {identity.destination}</code><small>{identity.transport.toUpperCase()} · SSRC 0x{identity.ssrc.toString(16).padStart(8, "0")} · PT {identity.payload_types.join(", ")}{identity.channel !== null ? ` · Channel ${identity.channel}` : ""} · {identity.codec ?? "编码待确认"}</small></div>
                  <button type="button" disabled={running || !run.result.request.source_path} onClick={() => analyzeCaptureStreams([identity.id])}>深入分析此流</button>
                </div>}
                <div className="tabs" role="tablist">
                  <button className={view === "overview" ? "active" : ""} onClick={() => setView("overview")} type="button">{captureOverview ? "媒体流总览" : "总览"}</button>
                  {!captureOverview && <>
                  <button className={view === "playback" ? "active" : ""} onClick={() => setView("playback")} type="button">音视频回放</button>
                  {audioQuality && <button className={view === "audioQuality" ? "active" : ""} onClick={() => setView("audioQuality")} type="button">音频质量</button>}
                  <button className={view === "protocol" ? "active" : ""} onClick={() => setView("protocol")} type="button">协议</button>
                  <button className={view === "stream" ? "active" : ""} onClick={() => setView("stream")} type="button">码流</button>
                  <button className={view === "diagnostics" ? "active" : ""} onClick={() => setView("diagnostics")} type="button">诊断</button>
                  <button className={view === "timeline" ? "active" : ""} onClick={() => setView("timeline")} type="button">时间线</button>
                  </>}
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
                      {audio.issues.map((issue, index) => <div className="evidence" key={`${issue.kind}-${index}`}><strong>{issue.kind}</strong><span>{issue.detail}</span></div>)}
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
                    canExport={Boolean(audioExportSource) && !exporting}
                  />
                </>}

                {view === "protocol" && (
                  <div className="protocol-view">
                    {!protocol ? (
                      <div className="protocol-empty">本次任务没有取得自研 RTSP 协议数据，详情请查看执行错误。</div>
                    ) : (
                      <>
                        <div className="protocol-facts">
                          <Metric label="RTSP 服务端" value={protocol.server ?? "未声明"} detail={protocol.authenticated ? "已完成鉴权" : "无需鉴权"} />
                          <Metric label="Session" value={protocol.session_id ?? "—"} detail={`${protocol.transactions.length} 次事务`} />
                          <Metric label="SETUP / PLAY" value={`${finalRtspStatus("SETUP") ?? "—"} / ${finalRtspStatus("PLAY") ?? "—"}`} detail={protocol.authenticated ? "401 为鉴权挑战，最终状态优先" : "最终事务状态"} />
                          <Metric label="传输" value={result.request.transport?.toUpperCase() ?? "—"} detail={protocol.negotiated_transport ?? (protocol.interleaved_rtp_channel !== null ? `Interleaved ${protocol.interleaved_rtp_channel}-${protocol.interleaved_rtcp_channel}` : "UDP RTP / RTCP")} />
                          <Metric label="RTP 包" value={protocol.rtp.packet_count.toString()} detail={`${protocol.rtp.payload_bytes} B 负载`} />
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
                            <small>Profile {sps.profile_idc} · Level {(sps.level_idc / 10).toFixed(1)} · {sps.progressive ? "Progressive" : "Interlaced"}</small>
                            <small>{sps.bit_depth_luma}-bit · {sps.max_num_ref_frames} reference frames</small>
                          </div>
                        ))}
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
                    ) : result.timeline.map((event, index) => (
                      <div className={`timeline-event ${event.severity}`} key={`${event.source}-${event.event_type}-${index}`}>
                        <span className="timeline-dot" />
                        <time>{event.offset_ms === null ? "时序未知" : `+${event.offset_ms} ms`}</time>
                        <strong>{event.source} · {event.event_type}</strong>
                        <p>{event.detail}</p>
                        {(event.frame_number != null || event.sequence !== null || event.rtp_timestamp !== null) && <code>帧 {event.frame_number ?? "—"} · 包 #{event.first_packet ?? "—"}{event.last_packet != null && event.last_packet !== event.first_packet ? `–#${event.last_packet}` : ""} · Seq {event.sequence ?? "—"} · TS {event.rtp_timestamp ?? "—"} · {event.location_precision ?? "位置未知"}</code>}
                      </div>
                    ))}
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

function AudioQualityView({ quality, onSeek, onExport, canExport }: { quality: AudioQuality; onSeek: (offsetMs: number) => void; onExport: (startMs: number, endMs: number) => void; canExport: boolean }) {
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
        <h3>内容异常区间</h3>
        {quality.intervals.length === 0 ? <p>当前分析范围内没有达到阈值的静音、削波或电平突变候选。</p> : quality.intervals.map((interval, index) => (
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
