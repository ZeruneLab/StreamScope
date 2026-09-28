import { getVersion } from "@tauri-apps/api/app";
import { relaunch } from "@tauri-apps/plugin-process";
import { check } from "@tauri-apps/plugin-updater";
import { useEffect, useState } from "react";

const AUTO_CHECK_KEY = "streamscope.updater.auto-check";
const SKIPPED_VERSION_KEY = "streamscope.updater.skipped-version";
const SESSION_CHECK_KEY = "streamscope.updater.checked-this-session";

type AvailableUpdate = Awaited<ReturnType<typeof check>>;
type UpdatePhase =
  | "idle"
  | "checking"
  | "available"
  | "downloading"
  | "downloaded"
  | "installing"
  | "current"
  | "error";

function formatBytes(value: number): string {
  if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${value} B`;
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

export function UpdateControl({ analysisRunning }: { analysisRunning: boolean }) {
  const [currentVersion, setCurrentVersion] = useState("—");
  const [phase, setPhase] = useState<UpdatePhase>("idle");
  const [update, setUpdate] = useState<AvailableUpdate>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [message, setMessage] = useState("");
  const [downloadedBytes, setDownloadedBytes] = useState(0);
  const [totalBytes, setTotalBytes] = useState<number | null>(null);
  const [autoCheck, setAutoCheck] = useState(
    () => localStorage.getItem(AUTO_CHECK_KEY) !== "false",
  );

  async function checkForUpdate(manual: boolean) {
    if (phase === "checking" || phase === "downloading" || phase === "installing") return;
    setPhase("checking");
    setMessage(manual ? "正在检查 GitHub Release…" : "");
    try {
      const candidate = await check();
      if (!candidate) {
        setUpdate(null);
        setPhase("current");
        setMessage(manual ? "当前已是最新版本" : "");
        return;
      }
      const skipped = localStorage.getItem(SKIPPED_VERSION_KEY);
      if (!manual && skipped === candidate.version) {
        setUpdate(null);
        setPhase("idle");
        return;
      }
      setUpdate(candidate);
      setPhase("available");
      setMessage(`发现新版本 v${candidate.version}`);
      setDialogOpen(true);
    } catch (error) {
      setPhase("error");
      setMessage(manual ? `检查更新失败：${errorMessage(error)}` : "");
    }
  }

  useEffect(() => {
    void getVersion().then(setCurrentVersion).catch(() => setCurrentVersion("未知"));
    if (!autoCheck || sessionStorage.getItem(SESSION_CHECK_KEY) === "true") return;
    sessionStorage.setItem(SESSION_CHECK_KEY, "true");
    const timer = window.setTimeout(() => { void checkForUpdate(false); }, 5_000);
    return () => window.clearTimeout(timer);
  }, []);

  function changeAutoCheck(enabled: boolean) {
    setAutoCheck(enabled);
    localStorage.setItem(AUTO_CHECK_KEY, String(enabled));
  }

  function dismiss() {
    setDialogOpen(false);
    if (phase === "available") setMessage(`可更新至 v${update?.version ?? "新版本"}`);
  }

  function skipVersion() {
    if (update) localStorage.setItem(SKIPPED_VERSION_KEY, update.version);
    setDialogOpen(false);
    setUpdate(null);
    setPhase("idle");
    setMessage("");
  }

  async function downloadUpdate() {
    if (!update || phase === "downloading") return;
    setPhase("downloading");
    setDownloadedBytes(0);
    setTotalBytes(null);
    setMessage(`正在下载 v${update.version}`);
    let received = 0;
    try {
      await update.download((event) => {
        if (event.event === "Started") {
          setTotalBytes(event.data.contentLength ?? null);
        } else if (event.event === "Progress") {
          received += event.data.chunkLength;
          setDownloadedBytes(received);
        } else if (event.event === "Finished") {
          setDownloadedBytes((current) => totalBytes ?? current);
        }
      });
      setPhase("downloaded");
      setMessage(`v${update.version} 已下载并通过签名校验`);
    } catch (error) {
      setPhase("error");
      setMessage(`下载更新失败：${errorMessage(error)}`);
    }
  }

  async function installUpdate() {
    if (!update || phase !== "downloaded" || analysisRunning) return;
    setPhase("installing");
    setMessage("正在安装更新，软件即将重启…");
    try {
      await update.install();
      await relaunch();
    } catch (error) {
      setPhase("error");
      setMessage(`安装更新失败：${errorMessage(error)}`);
    }
  }

  const progress = totalBytes && totalBytes > 0
    ? Math.min(100, Math.round(downloadedBytes * 100 / totalBytes))
    : null;
  const busy = phase === "checking" || phase === "downloading" || phase === "installing";

  return <>
    <div className="sidebar-footer updater-footer">
      <div><span className="online-dot" />本机分析引擎</div>
      <small>高级音画诊断 · v{currentVersion}</small>
      <button type="button" disabled={busy} onClick={() => { if (update) setDialogOpen(true); else void checkForUpdate(true); }}>
        {phase === "checking" ? "正在检查…" : phase === "available" || phase === "downloaded" ? "查看更新" : "检查更新"}
      </button>
      <label><input type="checkbox" checked={autoCheck} onChange={(event) => changeAutoCheck(event.target.checked)} />启动时检查更新</label>
      {message && <small className={phase === "error" ? "update-error" : "update-message"}>{message}</small>}
    </div>

    {dialogOpen && update && <div className="update-overlay" role="presentation">
      <section className="update-dialog" role="dialog" aria-modal="true" aria-labelledby="update-title">
        <div className="update-dialog-heading">
          <div><span>STREAMSCOPE UPDATE</span><h2 id="update-title">发现新版本 v{update.version}</h2></div>
          <button type="button" disabled={phase === "installing"} onClick={dismiss} aria-label="关闭更新窗口">×</button>
        </div>
        <div className="update-version-row">
          <div><span>当前版本</span><strong>v{currentVersion}</strong></div>
          <div><span>可用版本</span><strong>v{update.version}</strong></div>
          <div><span>发布时间</span><strong>{update.date ? new Date(update.date).toLocaleString("zh-CN") : "—"}</strong></div>
        </div>
        <div className="update-notes"><strong>更新内容</strong><pre>{update.body?.trim() || "此版本没有提供更新说明。"}</pre></div>
        {(phase === "downloading" || phase === "downloaded") && <div className="update-progress">
          <div><span style={{ width: `${progress ?? 100}%` }} /></div>
          <small>{phase === "downloaded" ? "下载完成，签名校验通过" : totalBytes == null ? `已下载 ${formatBytes(downloadedBytes)}` : `${formatBytes(downloadedBytes)} / ${formatBytes(totalBytes)} · ${progress}%`}</small>
        </div>}
        {analysisRunning && phase === "downloaded" && <p className="update-warning">当前存在分析任务。请等待任务结束、报告保存完成后再安装更新。</p>}
        {phase === "error" && <p className="update-warning error">{message}</p>}
        <div className="update-actions">
          {phase === "available" && <><button type="button" className="secondary" onClick={skipVersion}>跳过此版本</button><button type="button" className="secondary" onClick={dismiss}>暂不更新</button><button type="button" onClick={() => { void downloadUpdate(); }}>下载更新</button></>}
          {phase === "downloading" && <button type="button" disabled>正在下载…</button>}
          {phase === "downloaded" && <><button type="button" className="secondary" onClick={dismiss}>稍后安装</button><button type="button" disabled={analysisRunning} onClick={() => { void installUpdate(); }}>立即安装并重启</button></>}
          {phase === "error" && <><button type="button" className="secondary" onClick={dismiss}>关闭</button><button type="button" onClick={() => { void checkForUpdate(true); }}>重新检查</button></>}
        </div>
      </section>
    </div>}
  </>;
}
