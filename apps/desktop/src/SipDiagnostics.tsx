import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import "./SipDiagnostics.css";

interface SipEvent { packet_number: number; timestamp_micros: number; source: string; destination: string; transport: string; method: string | null; status: number | null; call_id: string | null; }
interface SipTransaction { call_id: string; method: string; branch: string; request_packet: number | null; final_status: number | null; provisional_statuses: number[]; final_statuses: number[]; first_response_ms: number | null; final_response_ms: number | null; response_packets: number[]; request_retransmissions: number; outcome: string; }
interface SipCall { call_id: string; first_packet: number; last_packet: number; message_count: number; dialog_count: number; methods: string[]; }
interface SipDialog { call_id: string; first_tag: string; second_tag: string; first_packet: number; invite_success_packet: number | null; ack_packet: number | null; bye_packet: number | null; bye_success_packet: number | null; observed_state: string; }
interface SipMediaBinding { call_id: string; sdp_packet: number; media_type: string; address: string; port: number; payload_types: number[]; codecs: string[]; matched_rtp_packets: number; matched_ssrc: number[]; first_rtp_packet?: number | null; last_rtp_packet?: number | null; first_rtp_timestamp_micros?: number | null; last_rtp_timestamp_micros?: number | null; match_quality: string; }
interface SipSdpExchange { packet_number: number; call_id: string; cseq: string; method: string; message_kind: string; origin_session_id: string | null; origin_session_version: string | null; media: { media_type: string; address: string | null; port: number; protocol: string; payload_types: number[]; direction: string }[]; paired_packet: number | null; assessment: string; }
interface SipFinding { severity: string; code: string; packet_number: number | null; call_id: string | null; detail: string; }
interface SipReport { total_capture_frames: number; transport_packets_seen: number; skipped_network_frames: number; sip_messages: SipEvent[]; transactions: SipTransaction[]; calls: SipCall[]; dialogs: SipDialog[]; media: SipMediaBinding[]; sdp_exchanges: SipSdpExchange[]; findings: SipFinding[]; truncated: boolean; }
interface SipProbeResult { target: string; transport: string; status: number | null; latency_ms: number; error: string | null; }
interface SipReplayPlan { call_id: string; capture_source: string; capture_target: string; executable: boolean; warnings: string[]; steps: { packet_number: number; delay_ms: number; method: string; local_user: string; remote_user: string; expected_status: number | null; inactive_media: { kind: string; encoding: string } | null }[]; }
interface SipReplayResult { target: string; local: string; success: boolean; error: string | null; steps: { capture_packet: number; method: string; expected_status: number | null; actual_status: number | null; latency_ms: number; outcome: string }[]; }

export default function SipDiagnostics({ onAnalyzeMedia }: { onAnalyzeMedia: (path: string) => void }) {
  const [path, setPath] = useState("");
  const [report, setReport] = useState<SipReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [exportError, setExportError] = useState("");
  const [query, setQuery] = useState("");
  const [selectedCall, setSelectedCall] = useState("");
  const [simBind, setSimBind] = useState("127.0.0.1:5060");
  const [simScenario, setSimScenario] = useState("options");
  const [simTransport, setSimTransport] = useState("udp");
  const [simUsername, setSimUsername] = useState("");
  const [simPassword, setSimPassword] = useState("");
  const [simDigest, setSimDigest] = useState("sha256");
  const [simTlsCert, setSimTlsCert] = useState("");
  const [simTlsKey, setSimTlsKey] = useState("");
  const [simAddress, setSimAddress] = useState<string | null>(null);
  const [simBusy, setSimBusy] = useState(false);
  const [simError, setSimError] = useState("");
  const [simEvents, setSimEvents] = useState<string[]>([]);
  const [probeTarget, setProbeTarget] = useState("");
  const [probeTransport, setProbeTransport] = useState("udp");
  const [probeServerName, setProbeServerName] = useState("");
  const [probeCaCert, setProbeCaCert] = useState("");
  const [probeResult, setProbeResult] = useState<SipProbeResult | null>(null);
  const [probeBusy, setProbeBusy] = useState(false);
  const [probeError, setProbeError] = useState("");
  const [replaySource, setReplaySource] = useState("");
  const [replayTarget, setReplayTarget] = useState("");
  const [replayPlan, setReplayPlan] = useState<SipReplayPlan | null>(null);
  const [replayResult, setReplayResult] = useState<SipReplayResult | null>(null);
  const [replayBusy, setReplayBusy] = useState(false);
  const [replayError, setReplayError] = useState("");
  useEffect(() => {
    void invoke<string | null>("sip_simulator_status").then(setSimAddress).catch((error) => setSimError(String(error)));
    const unsubscribe = listen<Record<string, unknown>>("sip-simulator-event", (event) => {
      setSimEvents((previous) => [`${new Date().toLocaleTimeString()} ${JSON.stringify(event.payload)}`, ...previous].slice(0, 50));
    });
    return () => { void unsubscribe.then((unlisten) => unlisten()); };
  }, []);
  const calls = useMemo(() => report?.calls.filter((call) => call.call_id.toLowerCase().includes(query.toLowerCase())) ?? [], [report, query]);
  const transactions = useMemo(() => report?.transactions.filter((item) => !selectedCall || item.call_id === selectedCall) ?? [], [report, selectedCall]);
  const dialogs = useMemo(() => report?.dialogs.filter((item) => !selectedCall || item.call_id === selectedCall) ?? [], [report, selectedCall]);
  const events = useMemo(() => report?.sip_messages.filter((item) => !selectedCall || item.call_id === selectedCall).slice(0, 1000) ?? [], [report, selectedCall]);
  const media = useMemo(() => report?.media.filter((item) => !selectedCall || item.call_id === selectedCall) ?? [], [report, selectedCall]);
  const sdpExchanges = useMemo(() => report?.sdp_exchanges?.filter((item) => !selectedCall || item.call_id === selectedCall) ?? [], [report, selectedCall]);
  const findings = useMemo(() => report?.findings.filter((item) => !selectedCall || item.call_id === selectedCall || !item.call_id) ?? [], [report, selectedCall]);
  const replaySources = useMemo(() => [...new Set(report?.sip_messages.filter((item) => item.call_id === selectedCall && item.transport === "UDP" && item.status == null).map((item) => item.source) ?? [])], [report, selectedCall]);
  const selectedReplaySource = replaySources.includes(replaySource) ? replaySource : replaySources[0] ?? "";
  const replayEditsValid = replayPlan?.steps.every((step) => step.delay_ms >= 0 && step.delay_ms <= 10000 && (step.method === "ACK" ? step.expected_status == null : step.expected_status != null && step.expected_status >= 200 && step.expected_status <= 699)) && replayPlan.steps.reduce((total, step) => total + step.delay_ms, 0) <= 60000;

  async function chooseFile() {
    const selected = await open({ multiple: false, filters: [{ name: "PCAP / PCAPNG", extensions: ["pcap", "pcapng", "cap"] }] });
    if (typeof selected === "string") { setPath(selected); setReport(null); setSelectedCall(""); setReplayPlan(null); setReplayResult(null); setError(""); }
  }

  async function diagnose() {
    if (!path || busy) return;
    setBusy(true); setError(""); setReport(null); setReplayPlan(null); setReplayResult(null);
    try { setReport(await invoke<SipReport>("diagnose_sip_pcap", { path })); }
    catch (failure) { setError(String(failure)); }
    finally { setBusy(false); }
  }

  async function toggleSimulator() {
    if (simBusy) return;
    setSimBusy(true); setSimError("");
    try {
      if (simAddress) { await invoke("stop_sip_simulator"); setSimAddress(null); }
      else {
        setSimAddress(await invoke<string>("start_sip_simulator", { bind: simBind, scenario: simScenario, transport: simTransport, username: simUsername, password: simPassword, digest: simDigest, tlsCert: simTlsCert, tlsKey: simTlsKey }));
        setSimPassword("");
      }
    } catch (failure) { setSimError(String(failure)); }
    finally { setSimBusy(false); }
  }

  async function probe() {
    if (!probeTarget || probeBusy) return;
    setProbeBusy(true); setProbeError(""); setProbeResult(null);
    try { setProbeResult(await invoke<SipProbeResult>("probe_sip_target", { target: probeTarget, transport: probeTransport, serverName: probeServerName, caCert: probeCaCert })); }
    catch (failure) { setProbeError(String(failure)); }
    finally { setProbeBusy(false); }
  }

  async function exportReport(redacted: boolean) {
    if (!report) return;
    setExportError("");
    try {
      const destination = await save({ defaultPath: redacted ? "sip-diagnostics-redacted.json" : "sip-diagnostics.json", filters: [{ name: "JSON", extensions: ["json"] }] });
      if (destination) await invoke("export_sip_report", { path: destination, report, redacted });
    } catch (failure) { setExportError(String(failure)); }
  }

  async function previewReplay() {
    if (!path || !selectedCall || !selectedReplaySource || replayBusy) return;
    setReplayBusy(true); setReplayError(""); setReplayPlan(null); setReplayResult(null);
    try { setReplayPlan(await invoke<SipReplayPlan>("preview_sip_replay", { path, callId: selectedCall, source: selectedReplaySource })); }
    catch (failure) { setReplayError(String(failure)); }
    finally { setReplayBusy(false); }
  }

  async function executeReplay() {
    if (!path || !selectedCall || !selectedReplaySource || !replayTarget || !replayPlan?.executable || !replayEditsValid || replayBusy) return;
    setReplayBusy(true); setReplayError(""); setReplayResult(null);
    try { setReplayResult(await invoke<SipReplayResult>("execute_sip_replay", { path, callId: selectedCall, source: selectedReplaySource, target: replayTarget, overrides: replayPlan.steps.map((step) => ({ packet_number: step.packet_number, delay_ms: step.delay_ms, expected_status: step.expected_status })) })); }
    catch (failure) { setReplayError(String(failure)); }
    finally { setReplayBusy(false); }
  }

  async function exportReplay() {
    if (!replayResult) return;
    setReplayError("");
    try {
      const destination = await save({ defaultPath: "sip-replay-result.json", filters: [{ name: "JSON", extensions: ["json"] }] });
      if (destination) await invoke("export_sip_replay_result", { path: destination, result: replayResult });
    } catch (failure) { setReplayError(String(failure)); }
  }

  return <div className="sip-diagnostics">
    <section className="panel sip-input">
      <div className="panel-heading"><div><span className="step">01</span><h2>SIP 抓包信令诊断</h2></div><span className="secure-note">只读本地文件，不发送 SIP 请求</span></div>
      <p>解析 UDP/TCP SIP 消息，按 Call-ID、事务及 Dialog 关联，并把 SDP 公布的媒体端点与抓包中的 RTP 候选匹配。</p>
      <div className="file-picker"><code>{path || "尚未选择 PCAP / PCAPNG 文件"}</code><button type="button" onClick={chooseFile}>选择文件</button></div>
      <button className="analyze-button" type="button" disabled={!path || busy} onClick={diagnose}>{busy ? "分析中…" : "开始 SIP 诊断"}</button>
      {error && <div className="error-banner">{error}</div>}
    </section>
    {report && <section className="panel sip-results">
      <div className="panel-heading"><div><span className="step">02</span><h2>诊断结果</h2></div><span>{report.total_capture_frames} 抓包帧 · {report.transport_packets_seen} 传输包 · {report.sip_messages.length} SIP 消息 · {report.calls.length} 呼叫</span></div>
      <div className="sip-actions"><button type="button" onClick={() => exportReport(false)}>导出 SIP JSON</button><button type="button" onClick={() => exportReport(true)}>导出脱敏 JSON</button><button type="button" onClick={() => onAnalyzeMedia(path)}>用同一抓包分析媒体流 →</button></div>
      {exportError && <div className="error-banner">导出失败：{exportError}</div>}
      {report.truncated && <p className="sip-notice">达到安全上限，部分明细未保留；请按时间或设备缩小抓包范围。</p>}
      <div className="sip-section"><h3>呼叫</h3><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索 Call-ID" aria-label="搜索 Call-ID" />
        <div className="sip-call-list"><button className={!selectedCall ? "selected" : ""} onClick={() => { setSelectedCall(""); setReplayPlan(null); setReplayResult(null); }}>全部呼叫</button>{calls.map((call) => <button className={selectedCall === call.call_id ? "selected" : ""} key={call.call_id} onClick={() => { setSelectedCall(call.call_id); setReplayPlan(null); setReplayResult(null); }}><strong>{call.call_id}</strong><span>{call.message_count} 消息 · {call.dialog_count} Dialog · #{call.first_packet}–#{call.last_packet}</span></button>)}</div>
      </div>
      <div className="sip-section"><h3>从抓包生成主动 SIP 测试</h3><p className="sip-notice">选择呼叫和原发起端后先预览。执行时只向填写的目标 IP:端口发送新生成的 UDP SIP 信令；不复用抓包中的鉴权头、IP、Call-ID、tag 或 Via。INVITE 使用 inactive SDP，不接收或发送 RTP。</p>
        <div className="sip-simulator-controls"><label>抓包中的发起端 <select value={selectedReplaySource} onChange={(event) => { setReplaySource(event.target.value); setReplayPlan(null); setReplayResult(null); }}><option value="">请选择呼叫</option>{replaySources.map((source) => <option key={source} value={source}>{source}</option>)}</select></label><label>测试目标 IP:端口 <input value={replayTarget} onChange={(event) => setReplayTarget(event.target.value)} placeholder="例如 172.16.54.254:5060" /></label><button type="button" disabled={!selectedCall || !selectedReplaySource || replayBusy} onClick={previewReplay}>生成场景预览</button></div>
        {replayPlan && <><p>原目标：{replayPlan.capture_target} · {replayPlan.steps.length} 步 · {replayPlan.executable ? "可执行" : "存在不支持步骤，禁止执行"}</p><div className="sip-table-wrap"><table><thead><tr><th>抓包号</th><th>步骤间隔</th><th>发送方法</th><th>From 用户</th><th>目标用户</th><th>预期最终状态</th><th>媒体处理</th></tr></thead><tbody>{replayPlan.steps.map((step, index) => <tr key={step.packet_number}><td>#{step.packet_number}</td><td><input className="sip-step-input" type="number" min="0" max="10000" value={step.delay_ms} disabled={!replayPlan.executable} aria-label={`第 ${index + 1} 步间隔毫秒`} onChange={(event) => setReplayPlan((current) => current && ({ ...current, steps: current.steps.map((item, position) => position === index ? { ...item, delay_ms: Number(event.target.value) } : item) }))} /> ms</td><td>{step.method}</td><td>{step.local_user}</td><td>{step.remote_user || "设备地址"}</td><td>{step.method === "ACK" ? "无需响应" : <input className="sip-step-input" type="number" min="200" max="699" value={step.expected_status ?? ""} disabled={!replayPlan.executable} aria-label={`第 ${index + 1} 步预期状态`} onChange={(event) => setReplayPlan((current) => current && ({ ...current, steps: current.steps.map((item, position) => position === index ? { ...item, expected_status: Number(event.target.value) } : item) }))} />}</td><td>{step.inactive_media ? `${step.inactive_media.kind}/${step.inactive_media.encoding} · inactive` : "无"}</td></tr>)}</tbody></table></div>{replayPlan.warnings.map((warning, index) => <p className="sip-notice" key={index}>{warning}</p>)}{!replayEditsValid && <p className="sip-notice">步骤间隔须在 0–10000 ms，总间隔不超过 60 秒；预期状态须为 200–699。</p>}<button type="button" disabled={!replayPlan.executable || !replayEditsValid || !replayTarget || replayBusy} onClick={executeReplay}>{replayBusy ? "执行中…" : "向指定设备执行场景"}</button></>}
        {replayResult && <><p className="sip-running">{replayResult.success ? "场景通过" : "场景未通过"} · 本地 {replayResult.local} → {replayResult.target}</p>{replayResult.error && <div className="error-banner">{replayResult.error}</div>}<div className="sip-table-wrap"><table><thead><tr><th>抓包号</th><th>方法</th><th>预期</th><th>实际</th><th>耗时</th><th>结论</th></tr></thead><tbody>{replayResult.steps.map((step, index) => <tr key={`${step.capture_packet}-${index}`}><td>#{step.capture_packet}</td><td>{step.method}</td><td>{step.expected_status ?? "—"}</td><td>{step.actual_status ?? "—"}</td><td>{step.latency_ms} ms</td><td>{step.outcome}</td></tr>)}</tbody></table></div><button type="button" onClick={exportReplay}>导出场景结果 JSON</button></>}
        {replayError && <div className="error-banner">{replayError}</div>}
      </div>
      <div className="sip-section"><h3>诊断发现（{findings.length}）</h3>{findings.length ? findings.map((item, index) => <div className={`sip-finding ${item.severity}`} key={`${item.code}-${index}`}><strong>{item.code}</strong><span>{item.packet_number ? `包 #${item.packet_number} · ` : ""}{item.detail}</span></div>) : <p>当前样本未发现明确的 SIP 格式或最终响应错误；这不代表媒体质量正常。</p>}</div>
      <div className="sip-section"><h3>事务（{transactions.length}）</h3><div className="sip-table-wrap"><table><thead><tr><th>方法</th><th>请求包</th><th>临时响应</th><th>最终响应</th><th>首次/最终耗时</th><th>请求重传</th><th>结论</th></tr></thead><tbody>{transactions.map((item, index) => <tr key={`${item.call_id}-${item.branch}-${index}`}><td>{item.method}</td><td>{item.request_packet ?? "—"}</td><td>{item.provisional_statuses?.join(", ") || "—"}</td><td>{item.final_statuses?.join(", ") || "—"}</td><td>{item.first_response_ms ?? "—"} / {item.final_response_ms ?? "—"} ms</td><td>{item.request_retransmissions}</td><td>{item.outcome}</td></tr>)}</tbody></table></div></div>
      <div className="sip-section"><h3>Dialog（{dialogs.length}）</h3><div className="sip-table-wrap"><table><thead><tr><th>双方 Tag</th><th>INVITE 2xx</th><th>ACK</th><th>BYE</th><th>BYE 2xx</th><th>观察状态</th></tr></thead><tbody>{dialogs.map((item, index) => <tr key={`${item.call_id}-${item.first_tag}-${item.second_tag}-${index}`}><td>{item.first_tag} ↔ {item.second_tag}</td><td>{item.invite_success_packet ? `#${item.invite_success_packet}` : "—"}</td><td>{item.ack_packet ? `#${item.ack_packet}` : "—"}</td><td>{item.bye_packet ? `#${item.bye_packet}` : "—"}</td><td>{item.bye_success_packet ? `#${item.bye_success_packet}` : "—"}</td><td>{item.observed_state}</td></tr>)}</tbody></table></div></div>
      <div className="sip-section"><h3>SDP offer/answer（{sdpExchanges.length}）</h3><div className="sip-table-wrap"><table><thead><tr><th>抓包号</th><th>方法 / 方向</th><th>o= 版本</th><th>媒体</th><th>配对包</th><th>评估</th></tr></thead><tbody>{sdpExchanges.map((item) => <tr key={item.packet_number}><td>#{item.packet_number}</td><td>{item.method} / {item.message_kind === "request" ? "请求" : "响应"}</td><td>{item.origin_session_id ?? "—"} / {item.origin_session_version ?? "—"}</td><td>{item.media.map((entry) => `${entry.media_type} ${entry.address ?? "?"}:${entry.port} ${entry.direction}`).join("; ")}</td><td>{item.paired_packet ? `#${item.paired_packet}` : "—"}</td><td>{item.assessment}</td></tr>)}</tbody></table></div></div>
      <div className="sip-section"><h3>SDP 媒体关联（{media.length}）</h3><div className="sip-table-wrap"><table><thead><tr><th>媒体</th><th>SDP 包</th><th>目标端点</th><th>编码 / PT</th><th>候选 RTP 包</th><th>候选包号 / 时间范围</th><th>可信度</th></tr></thead><tbody>{media.map((item, index) => <tr key={`${item.sdp_packet}-${index}`}><td>{item.media_type}</td><td>#{item.sdp_packet}</td><td>{item.address}:{item.port}</td><td>{item.codecs.join(", ")} / {item.payload_types.join(", ")}</td><td>{item.matched_rtp_packets}</td><td>{item.first_rtp_packet != null && item.last_rtp_packet != null ? `#${item.first_rtp_packet}–#${item.last_rtp_packet} / ${item.first_rtp_timestamp_micros ?? "?"}–${item.last_rtp_timestamp_micros ?? "?"} µs` : "—"}</td><td>{item.match_quality}</td></tr>)}</tbody></table></div><p className="sip-notice">这里列出整个抓包中端点/PT 候选的首末包号与抓包时间，并非该呼叫独占区间；NAT、重协商、端口复用或未采到媒体时不能据此认定流归属或无流。媒体质量请用 PCAP 多流分析继续核对。</p></div>
      <div className="sip-section"><h3>信令时间线（显示前 {events.length} 条）</h3><div className="sip-table-wrap"><table><thead><tr><th>抓包号</th><th>时间戳 (µs)</th><th>消息</th><th>源 → 目标</th><th>传输</th></tr></thead><tbody>{events.map((item, index) => <tr key={`${item.packet_number}-${index}`}><td>#{item.packet_number}</td><td>{item.timestamp_micros}</td><td>{item.status ? `${item.status} ${item.method ?? ""}` : item.method ?? "—"}</td><td>{item.source} → {item.destination}</td><td>{item.transport}</td></tr>)}</tbody></table></div></div>
    </section>}
    <section className="panel sip-input">
      <div className="panel-heading"><div><span className="step">03</span><h2>实时 SIP 探测</h2></div><span className="secure-note">仅发送 OPTIONS，不注册或发起呼叫</span></div>
      <div className="sip-simulator-controls"><label>目标 IP:端口 <input value={probeTarget} onChange={(event) => setProbeTarget(event.target.value)} placeholder="192.168.1.10:5060" /></label><label>传输 <select value={probeTransport} onChange={(event) => setProbeTransport(event.target.value)}><option value="udp">UDP</option><option value="tcp">TCP</option><option value="tls">TLS</option></select></label>{probeTransport === "tls" && <><label>证书主机名 <input value={probeServerName} onChange={(event) => setProbeServerName(event.target.value)} placeholder="留空时使用目标 IP" /></label><label>自签 CA <input value={probeCaCert} readOnly placeholder="可选" /></label><button type="button" onClick={async () => { const file = await open({ multiple: false }); if (typeof file === "string") setProbeCaCert(file); }}>选择 CA</button></>}<button type="button" disabled={!probeTarget || probeBusy} onClick={probe}>{probeBusy ? "探测中…" : "发送 OPTIONS"}</button></div>
      {probeResult && <p className="sip-running">{probeResult.transport} {probeResult.target}：{probeResult.error ? `未确认 SIP 服务（${probeResult.error}）` : `SIP ${probeResult.status} · ${probeResult.latency_ms} ms`}</p>}
      {probeError && <div className="error-banner">探测失败：{probeError}</div>}
    </section>
    <section className="panel sip-input">
      <div className="panel-heading"><div><span className="step">04</span><h2>SIP 模拟器</h2></div><span className="secure-note">独立 Engine 进程</span></div>
      <p>可应答 OPTIONS；“忙线测试”对 INVITE 返回 486；Registrar 场景要求 Digest 测试账号并维护单个 Contact 绑定。“PCMU 测试呼叫”仅支持 UDP 信令及单向 8 kHz PCMU 测试音，会拒绝其他媒体，不接收对端音频。默认只监听本机，密码不保存。TLS 需要自行选择有效的 PEM 证书和私钥。</p>
      <div className="sip-simulator-controls"><label>监听地址 <input value={simBind} onChange={(event) => setSimBind(event.target.value)} disabled={!!simAddress} placeholder="127.0.0.1:5060" /></label><label>传输 <select value={simTransport} onChange={(event) => setSimTransport(event.target.value)} disabled={!!simAddress}><option value="udp">UDP</option><option value="tcp">TCP</option><option value="tls">TLS</option></select></label><label>场景 <select value={simScenario} onChange={(event) => setSimScenario(event.target.value)} disabled={!!simAddress}><option value="options">OPTIONS 应答</option><option value="busy">OPTIONS + INVITE 忙线 486</option><option value="registrar">OPTIONS + Digest REGISTER</option><option value="call">OPTIONS + PCMU 测试呼叫（仅 UDP）</option></select></label>{simScenario === "registrar" && <><label>测试账号 <input value={simUsername} onChange={(event) => setSimUsername(event.target.value)} disabled={!!simAddress} /></label><label>测试密码 <input type="password" value={simPassword} onChange={(event) => setSimPassword(event.target.value)} disabled={!!simAddress} autoComplete="new-password" /></label><label>Digest <select value={simDigest} onChange={(event) => setSimDigest(event.target.value)} disabled={!!simAddress}><option value="sha256">SHA-256</option><option value="md5">MD5 兼容</option></select></label></>}<button type="button" onClick={toggleSimulator} disabled={simBusy || (!simAddress && simScenario === "registrar" && (!simUsername || !simPassword)) || (!simAddress && simScenario === "call" && simTransport !== "udp") || (!simAddress && simTransport === "tls" && (!simTlsCert || !simTlsKey))}>{simBusy ? "处理中…" : simAddress ? "停止模拟器" : "启动模拟器"}</button></div>
      {simScenario === "call" && simTransport !== "udp" && <p className="sip-notice">测试呼叫只支持 UDP 信令，请先将传输切换为 UDP。</p>}
      {simTransport === "tls" && <div className="sip-simulator-controls"><label>PEM 证书 <input value={simTlsCert} readOnly placeholder="选择证书" /></label><button type="button" disabled={!!simAddress} onClick={async () => { const file = await open({ multiple: false }); if (typeof file === "string") setSimTlsCert(file); }}>选择证书</button><label>PEM 私钥 <input value={simTlsKey} readOnly placeholder="选择私钥" /></label><button type="button" disabled={!!simAddress} onClick={async () => { const file = await open({ multiple: false }); if (typeof file === "string") setSimTlsKey(file); }}>选择私钥</button></div>}
      {simAddress && <p className="sip-running">已监听 {simAddress}</p>}
      {simError && <div className="error-banner">{simError}</div>}
      {simEvents.length > 0 && <details><summary>最近事件（{simEvents.length}）</summary><pre className="sip-engine-events">{simEvents.join("\n")}</pre></details>}
    </section>
  </div>;
}
