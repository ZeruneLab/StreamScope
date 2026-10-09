import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type Report = { reportPath: string; generatedAt: string; status: string; kind: string };
export function ReportHistory({ onOpenAnalysis }: { onOpenAnalysis: (directory: string) => void }) {
  const [reports, setReports] = useState<Report[]>([]);
  const [html, setHtml] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function refresh() {
    setBusy(true); setError("");
    try { setReports(await invoke<Report[]>("list_legacy_reports")); }
    catch (reason) { setError(String(reason)); }
    finally { setBusy(false); }
  }
  useEffect(() => { void refresh(); }, []);
  async function preview(report: Report) {
    setBusy(true); setError(""); setHtml("");
    try { setHtml(await invoke<string>("load_report_html", { reportPath: report.reportPath })); }
    catch (reason) { setError(String(reason)); }
    finally { setBusy(false); }
  }
  return <section className="panel plugin-panel">
    <div className="panel-heading"><div><span className="step">01</span><h2>历史报告</h2></div><button disabled={busy} onClick={() => { void refresh(); }}>刷新</button></div>
    <p>原报告只读保留；分析报告可重新打开完整工作台。插件报告还可在插件管理中查看。</p>
    {reports.map((report) => <div className="plugin-report-row" key={report.reportPath}>
      <span>{report.kind === "comparison" ? "TCP/UDP 对比" : "分析报告"} · {report.status} · {new Date(report.generatedAt).toLocaleString("zh-CN")}</span>
      <div className="plugin-actions"><button disabled={busy} onClick={() => { void preview(report); }}>预览原报告</button>
        {report.kind === "analysis" && <button disabled={busy} onClick={() => onOpenAnalysis(report.reportPath.replace(/[\\/][^\\/]+$/, ""))}>打开分析工作台</button>}</div>
    </div>)}
    {reports.length === 0 && !busy && <p>暂无历史报告。</p>}
    {error && <p role="alert">{error}</p>}
    {html && <iframe title="历史分析报告" sandbox="allow-modals allow-same-origin" srcDoc={html} className="report-frame" />}
  </section>;
}
