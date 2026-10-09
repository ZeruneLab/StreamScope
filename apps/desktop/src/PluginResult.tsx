import { useEffect, useState } from "react";
import { convertFileSrc, invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import "./plugin-ui.css";

type TableBlock = { type: "table"; title: string; columns: string[]; rows: unknown[][] };
type TextBlock = { type: "text"; title?: string; text: string };
type SeriesBlock = { type: "series"; title: string; points: { x: number; y: number }[] };
type TimelineBlock = { type: "timeline"; title: string; events: { offsetMs: number; label: string; detail?: string }[] };
type HexBlock = { type: "hex"; title: string; bytesHex: string; byteOffset?: number; truncated?: boolean; fields?: { name: string; value: string }[] };
type MediaBlock = { type: "media"; title: string; artifactId: string; mediaType: "audio" | "video" };
type FrameOverlayBlock = { type: "frameOverlay"; title: string; width: number; height: number; qp: number[][]; motionVectors: number[][]; frameArtifactId?: string };
type ReportBlock = { type: "report"; title: string; reportPath: string };
type SyntaxTreeBlock = { type: "syntaxTree"; title: string; nodes: unknown[] };
type DownloadBlock = { type: "download"; title: string; artifactId: string; filename: string };
type ActionsBlock = { type: "actions"; title: string; actions: { id: string; title: string; pluginId: string }[] };
export type ContinueAnalysis = (reportId: string, actionId: string) => void;
type Block = TableBlock | TextBlock | SeriesBlock | TimelineBlock | HexBlock | MediaBlock | FrameOverlayBlock | ReportBlock | SyntaxTreeBlock | DownloadBlock | ActionsBlock;

function isBlock(value: unknown): value is Block {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  if (candidate.type === "text") return typeof candidate.text === "string";
  if (candidate.type === "table") return typeof candidate.title === "string" && Array.isArray(candidate.columns)
    && candidate.columns.every((column) => typeof column === "string") && Array.isArray(candidate.rows) && candidate.rows.every(Array.isArray);
  if (candidate.type === "series") return typeof candidate.title === "string" && Array.isArray(candidate.points);
  if (candidate.type === "timeline") return typeof candidate.title === "string" && Array.isArray(candidate.events);
  if (candidate.type === "hex") return typeof candidate.title === "string" && typeof candidate.bytesHex === "string";
  if (candidate.type === "media") return typeof candidate.title === "string" && typeof candidate.artifactId === "string" && (candidate.mediaType === "audio" || candidate.mediaType === "video");
  if (candidate.type === "frameOverlay") return typeof candidate.title === "string" && Number.isFinite(candidate.width) && Number.isFinite(candidate.height) && Array.isArray(candidate.qp) && Array.isArray(candidate.motionVectors);
  if (candidate.type === "report") return typeof candidate.title === "string" && typeof candidate.reportPath === "string";
  if (candidate.type === "syntaxTree") return typeof candidate.title === "string" && Array.isArray(candidate.nodes);
  if (candidate.type === "download") return typeof candidate.title === "string" && typeof candidate.artifactId === "string" && typeof candidate.filename === "string";
  if (candidate.type === "actions") return typeof candidate.title === "string" && Array.isArray(candidate.actions)
    && candidate.actions.every((action) => action && typeof action.id === "string" && typeof action.title === "string" && typeof action.pluginId === "string");
  return false;
}

function formatValue(value: unknown): string {
  if (value == null) return "—";
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}

function HostFrameOverlay({ block, reportId }: { block: FrameOverlayBlock; reportId?: string }) {
  const [showQp, setShowQp] = useState(true);
  const [showVectors, setShowVectors] = useState(true);
  const [showFrame, setShowFrame] = useState(true);
  const [frameSrc, setFrameSrc] = useState("");
  const [frameError, setFrameError] = useState("");
  const [zoom, setZoom] = useState(1);
  useEffect(() => {
    setFrameSrc("");
    setFrameError("");
    if (!reportId || !block.frameArtifactId) return;
    let active = true;
    invoke<string>("resolve_plugin_artifact", { reportId, artifactId: block.frameArtifactId })
      .then((path) => { if (active) setFrameSrc(convertFileSrc(path)); })
      .catch((reason) => { if (active) setFrameError(String(reason)); });
    return () => { active = false; };
  }, [reportId, block.frameArtifactId]);
  const width = Math.min(Math.max(block.width, 1), 8192);
  const height = Math.min(Math.max(block.height, 1), 8192);
  const qp = block.qp.slice(0, 2000).filter((row) => Array.isArray(row) && row.length >= 5 && row.every(Number.isFinite)
    && row[2] > 0 && row[3] > 0 && row[0] >= 0 && row[1] >= 0 && row[0] + row[2] <= width && row[1] + row[3] <= height);
  const vectors = block.motionVectors.slice(0, 1000).filter((row) => Array.isArray(row) && row.length >= 4 && row.every(Number.isFinite)
    && row[0] >= 0 && row[1] >= 0 && row[2] >= 0 && row[3] >= 0
    && row[0] <= width && row[2] <= width && row[1] <= height && row[3] <= height);
  const minQp = qp.length ? Math.min(...qp.map((row) => row[4])) : 0;
  const maxQp = qp.length ? Math.max(...qp.map((row) => row[4])) : 0;
  return <div>
    <div style={{ display: "flex", flexWrap: "wrap", gap: 16, alignItems: "center", marginBottom: 8 }}>
      {block.frameArtifactId && <label><input type="checkbox" checked={showFrame} onChange={(event) => setShowFrame(event.target.checked)} /> 解码画面</label>}
      <label><input type="checkbox" checked={showQp} onChange={(event) => setShowQp(event.target.checked)} /> QP 块（{qp.length}）</label>
      <label><input type="checkbox" checked={showVectors} onChange={(event) => setShowVectors(event.target.checked)} /> 运动矢量（{vectors.length}）</label>
      <label>缩放 <select value={zoom} onChange={(event) => setZoom(Number(event.target.value))}><option value={1}>100%</option><option value={2}>200%</option><option value={4}>400%</option></select></label>
      {qp.length > 0 && <span>QP {minQp}–{maxQp}，蓝色低、红色高</span>}
    </div>
    <div style={{ overflow: "auto", maxHeight: 600, background: "#111827" }}>
      <svg role="img" aria-label={`${block.title}，${width}×${height}`} viewBox={`0 0 ${width} ${height}`}
        style={{ display: "block", width: Math.min(width * zoom, 3200), height: "auto", minWidth: Math.min(width * zoom, 3200) }}>
        {showFrame && frameSrc && <image href={frameSrc} x="0" y="0" width={width} height={height} preserveAspectRatio="none" />}
        {showQp && qp.map((row, index) => <rect key={index} x={row[0]} y={row[1]} width={row[2]} height={row[3]}
          fill={`hsl(${220 - 220 * (row[4] - minQp) / Math.max(maxQp - minQp, 1)} 85% 50% / 0.8)`}
          stroke="#ffffff44" strokeWidth="1"><title>QP {row[4]} · ({row[0]}, {row[1]})</title></rect>)}
        {showVectors && vectors.map((row, index) => <line key={index} x1={row[0]} y1={row[1]} x2={row[2]} y2={row[3]}
          stroke="#f8fafc" strokeWidth={Math.max(width / 640, 1)}><title>({row[0]}, {row[1]}) → ({row[2]}, {row[3]})</title></line>)}
      </svg>
    </div>
    {frameError && <p role="alert">无法打开帧图像：{frameError}</p>}
    <p>坐标按解码帧原始像素绘制；仅显示前 2,000 个 QP 块与前 1,000 条运动矢量。QP 与运动矢量可叠加在解码画面上。</p>
  </div>;
}

function HostMedia({ block, reportId }: { block: MediaBlock; reportId?: string }) {
  const [src, setSrc] = useState("");
  const [error, setError] = useState("");
  useEffect(() => {
    setSrc("");
    setError("");
    if (!reportId) return;
    let active = true;
    invoke<string>("resolve_plugin_artifact", { reportId, artifactId: block.artifactId })
      .then((path) => { if (active) setSrc(convertFileSrc(path)); })
      .catch((reason) => { if (active) setError(String(reason)); });
    return () => { active = false; };
  }, [reportId, block.artifactId]);
  if (error) return <p role="alert">无法打开媒体产物：{error}</p>;
  if (!src) return <p>正在读取媒体产物…</p>;
  return <div>{block.mediaType === "audio" ? <audio controls controlsList="nodownload" src={src} style={{ width: "100%" }} />
    : <video controls controlsList="nodownload" src={src} style={{ width: "100%", maxHeight: 480 }} />}
    <HostDownload block={{ type: "download", title: "另存预览文件", artifactId: block.artifactId, filename: block.mediaType === "audio" ? "preview.wav" : "preview.mp4" }} reportId={reportId} />
  </div>;
}

function HostDownload({ block, reportId }: { block: DownloadBlock; reportId?: string }) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  useEffect(() => { setMessage(""); }, [block.artifactId, reportId]);
  async function download() {
    if (!reportId) return;
    setBusy(true);
    setMessage("");
    try {
      const filename = block.filename.replace(/[\\/:*?"<>|]/g, "_").slice(0, 128) || "artifact.bin";
      const destinationPath = await save({ defaultPath: filename });
      if (!destinationPath) return;
      const path = await invoke<string>("export_plugin_artifact", { reportId, artifactId: block.artifactId, destinationPath });
      setMessage(`已保存：${path}`);
    } catch (reason) { setMessage(`保存失败：${String(reason)}`); }
    finally { setBusy(false); }
  }
  return <div style={{ margin: "10px 0" }}><button type="button" disabled={busy || !reportId} onClick={() => { void download(); }}>
    {busy ? "正在保存…" : block.title}
  </button>{message && <p role="status">{message}</p>}</div>;
}

function HostReport({ block }: { block: ReportBlock }) {
  const [html, setHtml] = useState("");
  const [error, setError] = useState("");
  useEffect(() => { setHtml(""); setError(""); }, [block.reportPath]);
  async function load() {
    setError("");
    try { setHtml(await invoke<string>("load_report_html", { reportPath: block.reportPath })); }
    catch (reason) { setError(String(reason)); }
  }
  return <section><h4>{block.title}</h4>
    <button type="button" onClick={() => { void load(); }}>在软件内查看完整报告</button>
    {error && <p role="alert">无法读取报告：{error}</p>}
    {html && <iframe title={block.title} sandbox="allow-modals allow-same-origin" srcDoc={html}
      style={{ width: "100%", height: 700, border: "1px solid #d9e1ea", marginTop: 12 }} />}
  </section>;
}

function HostSeries({ block }: { block: SeriesBlock }) {
  const points = block.points.slice(0, 2000).filter((point) => point && Number.isFinite(point.x) && Number.isFinite(point.y));
  if (!points.length) return <p>没有可绘制的数据点。</p>;
  const minX = Math.min(...points.map((point) => point.x));
  const maxX = Math.max(...points.map((point) => point.x));
  const minY = Math.min(...points.map((point) => point.y));
  const maxY = Math.max(...points.map((point) => point.y));
  const line = points.map((point) => `${40 + 700 * (point.x - minX) / Math.max(maxX - minX, 1)},${180 - 150 * (point.y - minY) / Math.max(maxY - minY, 1)}`).join(" ");
  return <div style={{ overflowX: "auto" }}><svg role="img" aria-label={`${block.title}，${points.length} 个数据点`} width="760" height="210" viewBox="0 0 760 210">
    <path d="M40 30 V180 H740" fill="none" stroke="#94a3b8" />
    <polyline fill="none" stroke="#1785c1" strokeWidth="2" points={line} />
    <text x="40" y="202" fontSize="12">{minX}</text><text x="680" y="202" fontSize="12">{maxX}</text>
    <text x="3" y="34" fontSize="12">{maxY}</text><text x="3" y="180" fontSize="12">{minY}</text>
  </svg>{block.points.length > 2000 && <p>仅绘制前 2,000 个点；完整数据保留在报告中。</p>}</div>;
}

function HostHex({ block }: { block: HexBlock }) {
  const [fontSize, setFontSize] = useState(14);
  const clean = block.bytesHex.replace(/\s/g, "");
  const bytes = clean.length % 2 === 0 && /^[0-9a-fA-F]*$/.test(clean) ? clean.match(/.{2}/g)?.slice(0, 4096) ?? [] : [];
  const offset = typeof block.byteOffset === "number" && Number.isSafeInteger(block.byteOffset) && block.byteOffset >= 0 ? block.byteOffset : 0;
  return <div>
    <label>HEX 字号 <select value={fontSize} onChange={(event) => setFontSize(Number(event.target.value))}>
      {[12, 14, 16, 20, 24].map((size) => <option key={size} value={size}>{size} px</option>)}
    </select></label>
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 16, alignItems: "start", marginTop: 8 }}>
    <div style={{ maxHeight: 420, overflow: "auto", background: "#101820", color: "#d2f1eb", padding: 12, fontFamily: "monospace", fontSize, whiteSpace: "pre", lineHeight: 1.6 }}>
      {Array.from({ length: Math.ceil(bytes.length / 16) }, (_, row) => <div key={row}>{(offset + row * 16).toString(16).padStart(8, "0")} {bytes.slice(row * 16, row * 16 + 16).join(" ")}</div>)}
      {!bytes.length && <span>没有有效的十六进制字节。</span>}
    </div>
    <div style={{ maxHeight: 420, overflow: "auto" }}>{(Array.isArray(block.fields) ? block.fields : []).slice(0, 500)
      .filter((field) => field && typeof field.name === "string").map((field, index) =>
      <div key={index} style={{ padding: 6, borderBottom: "1px solid #e8edf2" }}><strong>{field.name}</strong>：{formatValue(field.value)}</div>)}</div>
    </div>
    {(clean.length > 8192 || block.truncated) && <p>仅展示前 4,096 字节；其余字节请查看原始文件。</p>}
  </div>;
}

function HostSyntaxTree({ block }: { block: SyntaxTreeBlock }) {
  const budget = { remaining: 2000, truncated: false };
  function nodes(values: unknown[], depth: number): React.ReactNode {
    if (depth > 16) { budget.truncated = true; return <p>更深层级请查看原始结构化结果。</p>; }
    const rendered: React.ReactNode[] = [];
    for (let index = 0; index < values.length; index++) {
      if (budget.remaining <= 0) { budget.truncated = true; break; }
      const value = values[index];
      if (!value || typeof value !== "object") continue;
      const node = value as Record<string, unknown>;
      if (typeof node.label !== "string") continue;
      budget.remaining--;
      const label = <span><strong>{node.label}</strong>{node.value != null && `：${formatValue(node.value)}`}
        {Number.isSafeInteger(node.byteOffset) && <small> · 字节 {String(node.byteOffset)}</small>}
      </span>;
      const children = Array.isArray(node.children) ? node.children : [];
      rendered.push(children.length ? <details key={index} open={depth < 2} style={{ margin: "6px 0 6px 16px" }}>
        <summary>{label}</summary>{nodes(children, depth + 1)}
      </details> : <div key={index} style={{ margin: "6px 0 6px 16px" }}>{label}</div>);
    }
    return rendered;
  }
  const tree = nodes(block.nodes, 0);
  return <div style={{ maxHeight: 500, overflow: "auto", overflowWrap: "anywhere", border: "1px solid #d9e1ea", padding: 12 }}>
    {tree}{budget.truncated && <p>树视图最多展示 2,000 个节点、17 层；完整数据保留在原始结果及报告中。</p>}
  </div>;
}

function HostBlock({ block, reportId, onContinue }: { block: Block; reportId?: string; onContinue?: ContinueAnalysis }) {
  if (block.type === "actions") return <section className="plugin-workflow-group"><h4>{block.title}</h4>
    <div className="plugin-toolbar">{block.actions.map((action) => <button key={action.id} type="button" disabled={!reportId || !onContinue}
      onClick={() => { if (reportId) onContinue?.(reportId, action.id); }}>{action.title}</button>)}</div>
  </section>;
  if (block.type === "text") return <section><h4>{block.title}</h4><p style={{ whiteSpace: "pre-wrap" }}>{block.text}</p></section>;
  if (block.type === "series") return <section><h4>{block.title}</h4><HostSeries block={block} /></section>;
  if (block.type === "hex") return <section><h4>{block.title}</h4><HostHex block={block} /></section>;
  if (block.type === "media") return <section><h4>{block.title}</h4><HostMedia block={block} reportId={reportId} /></section>;
  if (block.type === "frameOverlay") return <section><h4>{block.title}</h4><HostFrameOverlay block={block} reportId={reportId} /></section>;
  if (block.type === "report") return <HostReport block={block} />;
  if (block.type === "syntaxTree") return <section><h4>{block.title}</h4><HostSyntaxTree block={block} /></section>;
  if (block.type === "download") return <HostDownload block={block} reportId={reportId} />;
  if (block.type === "timeline") return <section><h4>{block.title}</h4><ol>{block.events.slice(0, 500)
    .filter((event) => event && Number.isFinite(event.offsetMs) && typeof event.label === "string")
    .map((event, index) => <li key={index}><strong>+{event.offsetMs} ms</strong> {event.label} {typeof event.detail === "string" && <span>— {event.detail}</span>}</li>)}
  </ol>{block.events.length > 500 && <p>仅展示前 500 个事件；完整数据保留在报告中。</p>}</section>;
  return <section style={{ margin: "20px 0" }}><h4>{block.title}</h4>
    <div style={{ overflowX: "auto", maxHeight: 500, overflowY: "auto" }}>
      <table style={{ borderCollapse: "collapse", width: "100%" }}>
        <thead><tr>{block.columns.slice(0, 30).map((column, columnIndex) => <th key={columnIndex} style={{ textAlign: "left", padding: 8, borderBottom: "1px solid #d9e1ea" }}>{column}</th>)}</tr></thead>
        <tbody>{block.rows.slice(0, 500).map((row, rowIndex) => <tr key={rowIndex}>{Array.isArray(row) && row.slice(0, 30).map((cell, columnIndex) => <td key={columnIndex} style={{ padding: 8, borderBottom: "1px solid #e8edf2" }}>{formatValue(cell)}</td>)}</tr>)}</tbody>
      </table>
    </div>
    {block.rows.length > 500 && <p>表格仅展示前 500 行；完整数据见下方 JSON 和已保存报告。</p>}
  </section>;
}

export function PluginResult({ value, reportId, onContinue }: { value: unknown; reportId?: string; onContinue?: ContinueAnalysis }) {
  const [search, setSearch] = useState("");
  useEffect(() => { setSearch(""); }, [reportId]);
  const record = value && typeof value === "object" ? value as Record<string, unknown> : null;
  const blocks = Array.isArray(record?.blocks) ? record.blocks.filter(isBlock) : [];
  const groups = blocks.filter((block): block is ActionsBlock => block.type === "actions");
  const matched = groups.filter((block) => block.title.toLowerCase().includes(search.trim().toLowerCase()));
  return <div className="plugin-result">
    {typeof record?.summary === "string" && <p>{record.summary}</p>}
    {typeof record?.hostWorkflowWarning === "string" && <p role="alert">{record.hostWorkflowWarning}</p>}
    {groups.length > 0 && <section className="plugin-workflows"><h3>媒体流与联合分析</h3>
      <p className="plugin-muted">先深入分析指定流，再继续视频逐帧、NALU 语法或音频质量分析。样本由宿主传递，不需要重新选择抓包文件。</p>
      {groups.length > 1 && <label className="plugin-field"><span>搜索流 ID / 编码 / 地址</span><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="例如 stream-0001、h265、192.168" /></label>}
      {matched.slice(0, 100).map((block) => <HostBlock key={block.title} block={block} reportId={reportId} onContinue={onContinue} />)}
      {matched.length > 100 && <p>匹配 {matched.length} 路，当前展示前 100 路；请缩小搜索范围。</p>}
      {matched.length === 0 && <p>没有匹配的流。</p>}
    </section>}
    {blocks.filter((block) => block.type !== "actions").slice(0, 50).map((block, index) => <HostBlock key={index} block={block} reportId={reportId} />)}
    <details><summary>原始结构化结果</summary><pre style={{ whiteSpace: "pre-wrap", overflow: "auto" }}>{JSON.stringify(value, null, 2)}</pre></details>
  </div>;
}
