import { useMemo, useState } from "react";
import type { AnalysisResult } from "./types";

function bitRate(value: number | null | undefined) {
  if (value === null || value === undefined) return "—";
  return value >= 1_000_000 ? `${(value / 1_000_000).toFixed(2)} Mbps` : `${(value / 1_000).toFixed(1)} Kbps`;
}

function riskLevel(result: AnalysisResult) {
  const levels = ["info", "low", "medium", "high", "critical"];
  return Math.max(0, ...result.diagnostics.map((finding) => levels.indexOf(finding.severity)),
    result.protocol?.rtp.lost_packets || result.h264?.incomplete_nalus || result.h265?.incomplete_nalus
      || result.audio?.timestamp_gap_count || result.audio?.timestamp_overlap_count || result.decode?.success === false ? 2 : 0);
}

export function CaptureStreams({ result, running, onSelect, onAnalyze }: {
  result: AnalysisResult;
  running: boolean;
  onSelect: (id: string) => void;
  onAnalyze: (ids: string[]) => void;
}) {
  const [search, setSearch] = useState("");
  const [transport, setTransport] = useState("all");
  const [onlyIssues, setOnlyIssues] = useState(false);
  const [order, setOrder] = useState("risk");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const summary = result.capture_summary!;
  const streams = useMemo(() => (result.streams ?? []).filter((item) => item.capture_stream), [result]);
  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    return streams.filter((item) => {
      const identity = item.capture_stream!;
      const searchable = [identity.id, identity.source, identity.destination, identity.ssrc,
        `0x${identity.ssrc.toString(16).padStart(8, "0")}`, identity.codec, identity.interface_id,
        identity.media_type, identity.transport, identity.channel, identity.payload_types.join(" ")].join(" ").toLowerCase();
      return (!query || searchable.includes(query)) && (transport === "all" || identity.transport === transport)
        && (!onlyIssues || riskLevel(item) >= 2);
    }).sort((a, b) => {
      if (order === "packets") return (b.protocol?.rtp.packet_count ?? 0) - (a.protocol?.rtp.packet_count ?? 0);
      if (order === "bitrate") return (b.protocol?.rtp.average_bit_rate_bps ?? 0) - (a.protocol?.rtp.average_bit_rate_bps ?? 0);
      if (order === "source") return a.capture_stream!.source.localeCompare(b.capture_stream!.source, undefined, { numeric: true });
      return riskLevel(b) - riskLevel(a) || a.capture_stream!.first_packet - b.capture_stream!.first_packet;
    });
  }, [streams, search, transport, onlyIssues, order]);
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const visible = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const pageChecked = visible.length > 0 && visible.every((item) => checked.has(item.capture_stream!.id));
  const transports = [...new Set(streams.map((item) => item.capture_stream!.transport.toUpperCase()))].join(" + ");
  const notes = [...new Set([...summary.warnings, ...result.errors])];

  function toggle(id: string) {
    setChecked((previous) => {
      const next = new Set(previous);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  return <div className="capture-overview">
    <div className="capture-title"><h3>发现 {summary.stream_count} 组媒体流</h3><span>每组独立统计与重组</span></div>
    <div className="capture-summary">
      <div><span>抓包帧数</span><strong>{summary.total_frames.toLocaleString()}</strong></div>
      <div><span>已解析传输帧</span><strong>{summary.parsed_transport_frames.toLocaleString()}</strong></div>
      <div><span>抓包覆盖时长</span><strong>{(summary.duration_ms / 1_000).toFixed(2)} s</strong></div>
      <div><span>传输模式</span><strong>{transports || "未识别"}</strong></div>
      <div><span>有异常证据的流</span><strong>{streams.filter((item) => riskLevel(item) >= 2).length}</strong></div>
      <div><span>已有解码结果</span><strong>{streams.filter((item) => item.decode).length} / {streams.length}</strong></div>
    </div>
    <p className="capture-note">扫描结果按端点、连接、通道和 SSRC 区分每路音视频。H.264/H.265 提供结构与画面证据；PCMA/PCMU、AAC-hbr 和 Opus 在深度分析后提供软件内试听，成功解码时给出 PCM 质量指标。勾选会跨页保留。</p>
    {notes.length > 0 && <details className="capture-notes"><summary>抓包范围与限制（{notes.length} 项）</summary>{notes.map((note) => <p key={note}>{note}</p>)}</details>}
    <div className="capture-filters">
      <label className="capture-search"><span>搜索媒体流</span><input type="search" value={search} placeholder="端点、SSRC、编码、PT 或流 ID" onChange={(event) => { setSearch(event.target.value); setPage(1); }} /></label>
      <label><span>传输</span><select value={transport} onChange={(event) => { setTransport(event.target.value); setPage(1); }}><option value="all">全部传输</option><option value="udp">UDP</option><option value="tcp">TCP</option></select></label>
      <label><span>排序</span><select value={order} onChange={(event) => { setOrder(event.target.value); setPage(1); }}><option value="risk">异常优先</option><option value="packets">包数从多到少</option><option value="bitrate">码率从高到低</option><option value="source">源地址</option></select></label>
      <label className="capture-checkbox"><input type="checkbox" checked={onlyIssues} onChange={(event) => { setOnlyIssues(event.target.checked); setPage(1); }} />仅看异常</label>
    </div>
    <div className="capture-actions">
      <span>已勾选 {checked.size} 路</span>
      <button type="button" disabled={!checked.size || running || !result.request.source_path} onClick={() => onAnalyze([...checked])}>深入分析勾选流</button>
      <button type="button" disabled={!streams.length || running || !result.request.source_path} onClick={() => onAnalyze(["*"])}>全部深入分析（{streams.length} 路）</button>
      <button type="button" disabled={!checked.size} onClick={() => setChecked(new Set())}>清空勾选</button>
    </div>
    <div className="capture-table-wrap">
      <table className="capture-table">
        <thead><tr><th><input type="checkbox" aria-label="勾选或取消本页所有流" checked={pageChecked} disabled={!visible.length} onChange={() => setChecked((previous) => {
          const next = new Set(previous);
          visible.forEach((item) => { if (pageChecked) next.delete(item.capture_stream!.id); else next.add(item.capture_stream!.id); });
          return next;
        })} /></th><th>媒体流 / 有方向端点</th><th>编码 / 标识</th><th>包数 / 时长</th><th>平均 / 峰值码率</th><th>异常证据</th><th>解码状态</th></tr></thead>
        <tbody>{visible.map((item) => {
          const identity = item.capture_stream!;
          const rtp = item.protocol?.rtp;
          const risk = riskLevel(item);
          return <tr key={identity.id}>
            <td><input type="checkbox" aria-label={`勾选 ${identity.id}`} checked={checked.has(identity.id)} onChange={() => toggle(identity.id)} /></td>
            <td><button type="button" className="capture-stream-link" onClick={() => onSelect(identity.id)}>{identity.id}</button><code>{identity.source}</code><code>→ {identity.destination}</code><small>{identity.transport.toUpperCase()}{identity.channel !== null ? ` · Channel ${identity.channel}` : ""}{identity.connection_id !== null ? ` · 连接 ${identity.connection_id}` : ""}</small></td>
            <td><strong>{identity.codec ?? "编码待确认"}</strong><small>{identity.media_type === "audio" ? "音频" : identity.media_type === "video" ? "视频" : "媒体类型待确认"}{identity.channels ? ` · ${identity.channels} 声道` : ""}</small><code>SSRC 0x{identity.ssrc.toString(16).padStart(8, "0")}</code><small>PT {identity.payload_types.join(", ")}</small><small>{identity.codec_confidence}</small></td>
            <td><strong>{rtp?.packet_count.toLocaleString() ?? "—"} 包</strong><small>{((identity.last_offset_ms - identity.first_offset_ms) / 1_000).toFixed(2)} s</small><small>抓包 #{identity.first_packet}–#{identity.last_packet}</small></td>
            <td><strong>{bitRate(rtp?.average_bit_rate_bps)}</strong><small>{bitRate(rtp?.peak_bit_rate_bps)}</small></td>
            <td><span className={`capture-risk risk-${risk}`}>{["未见显著异常", "提示", "需关注", "高风险", "严重"][risk]}</span><small>序列缺口 {rtp?.lost_packets ?? 0}</small><small>{item.audio ? `音频时间戳缺口 ${item.audio.timestamp_gap_count}` : `不完整 NALU ${item.h264?.incomplete_nalus ?? item.h265?.incomplete_nalus ?? "—"}`}</small>{identity.sample_truncated && <small>样本已截断</small>}</td>
            <td><span>{item.audio ? item.audio.codec_supported_for_decode ? "音频分析完成" : "仅 RTP 分析" : item.decode ? item.decode.success ? "解码完成" : "解码失败" : "尚无解码结果"}</span><small>{item.audio?.decoded_duration_ms != null ? `${(item.audio.decoded_duration_ms / 1000).toFixed(2)} s` : item.decode?.decoded_frames !== null && item.decode?.decoded_frames !== undefined ? `${item.decode.decoded_frames} 帧` : ""}</small><button type="button" className="capture-stream-link" onClick={() => onSelect(identity.id)}>查看详情</button></td>
          </tr>;
        })}</tbody>
      </table>
      {!visible.length && <p className="protocol-empty">{streams.length ? "没有符合当前筛选条件的媒体流。" : "没有识别到可分组的 RTP 媒体流，请查看抓包范围与限制。"}</p>}
    </div>
    <div className="capture-pagination"><span>筛选后 {filtered.length} / {streams.length} 路</span><label>每页 <select aria-label="每页媒体流数量" value={pageSize} onChange={(event) => { setPageSize(Number(event.target.value)); setPage(1); }}><option value={10}>10</option><option value={25}>25</option><option value={50}>50</option></select> 路</label><button type="button" disabled={currentPage <= 1} onClick={() => setPage(currentPage - 1)}>上一页</button><span>{currentPage} / {pageCount}</span><button type="button" disabled={currentPage >= pageCount} onClick={() => setPage(currentPage + 1)}>下一页</button></div>
  </div>;
}
