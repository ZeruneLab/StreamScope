import { useState, type FormEvent } from "react";
import { invoke } from "@tauri-apps/api/core";

interface DiscoveredDevice {
  endpoint_reference: string | null;
  types: string[];
  scopes: string[];
  xaddrs: string[];
  metadata_version: string | null;
  source: string | null;
}

interface DeviceInformation {
  manufacturer: string | null;
  model: string | null;
  firmware_version: string | null;
  serial_number: string | null;
  hardware_id: string | null;
}

interface OnvifService {
  namespace: string;
  xaddr: string;
  version: string | null;
}

interface MediaProfile {
  token: string;
  name: string | null;
  video_source_token: string | null;
  video_encoding: string | null;
  audio_encoding: string | null;
  media_service: string;
}

interface StreamUri {
  profile_token: string;
  profile_name: string | null;
  uri: string;
  media_service: string;
}

interface OperationResult {
  service: string;
  operation: string;
  endpoint: string;
  status: string;
  http_status: number | null;
  elapsed_ms: number;
  detail: string;
  soap_fault_code: string | null;
  soap_fault_reason: string | null;
}

interface DiagnosticFinding {
  severity: string;
  title: string;
  evidence: string;
  suggestion: string;
}

interface OnvifDiagnosticResult {
  generated_at: string;
  endpoint: string;
  normalized_device_service: string;
  device_clock_offset_seconds: number | null;
  device_information: DeviceInformation | null;
  services: OnvifService[];
  profiles: MediaProfile[];
  stream_uris: StreamUri[];
  operations: OperationResult[];
  findings: DiagnosticFinding[];
  standards: string[];
}

function scopeName(scopes: string[]): string {
  const name = scopes.find((scope) => scope.includes("/name/"));
  if (!name) return "未命名 ONVIF 设备";
  try {
    return decodeURIComponent(name.slice(name.lastIndexOf("/name/") + 6));
  } catch {
    return name;
  }
}

function displayUri(uri: string): string {
  try {
    const value = new URL(uri);
    if (value.password) value.password = "REDACTED";
    return value.toString();
  } catch {
    return uri;
  }
}

function rtspUriWithCredentials(uri: string, username: string, password: string): string {
  if (!username) return uri;
  try {
    const value = new URL(uri);
    if (!value.username) value.username = username;
    if (!value.password && password) value.password = password;
    return value.toString();
  } catch {
    return uri;
  }
}

const operationStatusLabels: Record<string, string> = {
  passed: "通过",
  not_supported: "不支持",
  invalid_response: "回复不合法",
  failed: "失败",
  skipped: "未执行",
};

function operationEvidence(operation: OperationResult): string {
  const fault = [operation.soap_fault_code, operation.soap_fault_reason].filter(Boolean).join(" · ");
  return fault || operation.detail;
}

export default function OnvifDiagnostics({ onAnalyzeRtsp }: { onAnalyzeRtsp: (uri: string) => void }) {
  const [endpoint, setEndpoint] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [timeoutSeconds, setTimeoutSeconds] = useState(10);
  const [allowSelfSigned, setAllowSelfSigned] = useState(false);
  const [discovering, setDiscovering] = useState(false);
  const [running, setRunning] = useState(false);
  const [devices, setDevices] = useState<DiscoveredDevice[]>([]);
  const [result, setResult] = useState<OnvifDiagnosticResult | null>(null);
  const [error, setError] = useState("");
  const operationCounts = result?.operations.reduce<Record<string, number>>((counts, operation) => {
    counts[operation.status] = (counts[operation.status] ?? 0) + 1;
    return counts;
  }, {}) ?? {};

  async function discoverDevices() {
    setError("");
    setDiscovering(true);
    try {
      setDevices(await invoke<DiscoveredDevice[]>("discover_onvif", { timeoutSeconds: 3 }));
    } catch (reason) {
      setError(`设备发现失败：${String(reason)}`);
    } finally {
      setDiscovering(false);
    }
  }

  async function diagnose(event: FormEvent) {
    event.preventDefault();
    setError("");
    setResult(null);
    setRunning(true);
    try {
      const credentials = username ? { username, password } : null;
      const completed = await invoke<OnvifDiagnosticResult>("diagnose_onvif", {
        request: {
          endpoint,
          credentials,
          timeout_seconds: timeoutSeconds,
          accept_invalid_certificates: allowSelfSigned,
        },
      });
      setResult(completed);
    } catch (reason) {
      setError(`ONVIF 诊断失败：${String(reason)}`);
    } finally {
      setRunning(false);
    }
  }

  return <div className="onvif-workspace">
    <form className="analysis-form panel" onSubmit={diagnose}>
      <div className="panel-heading">
        <div><span className="step">01</span><h2>ONVIF 设备连接</h2></div>
        <span className="secure-note">凭据只用于本次诊断，不写入报告</span>
      </div>
      <label className="field url-field">
        <span>Device Service XAddr 或设备 IP</span>
        <div className="input-wrap"><span className="protocol">ONVIF</span><input autoFocus required value={endpoint} onChange={(event) => setEndpoint(event.target.value)} placeholder="192.168.1.10 或 http://192.168.1.10/onvif/device_service" spellCheck={false} /></div>
      </label>
      <div className="form-grid onvif-credentials">
        <label className="field"><span>用户名</span><input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" /></label>
        <label className="field"><span>密码</span><input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" /></label>
        <label className="field compact-field"><span>接口超时</span><div className="number-input"><input type="number" min="1" max="300" value={timeoutSeconds} onChange={(event) => setTimeoutSeconds(Number(event.target.value))} /><span>秒</span></div></label>
      </div>
      <label className="onvif-check"><input type="checkbox" checked={allowSelfSigned} onChange={(event) => setAllowSelfSigned(event.target.checked)} />允许当前设备使用无法验证的自签名 HTTPS 证书</label>
      <div className="onvif-actions">
        <button className="secondary-button" type="button" disabled={discovering || running} onClick={() => { void discoverDevices(); }}>{discovering ? "正在发现…" : "局域网发现设备"}</button>
        <button className="analyze-button" type="submit" disabled={running || discovering}>{running ? "正在执行标准接口诊断…" : "开始 ONVIF 诊断"}</button>
      </div>
      {devices.length > 0 && <div className="onvif-devices">
        <strong>WS-Discovery 发现 {devices.length} 台设备</strong>
        {devices.map((device, index) => <button type="button" key={device.endpoint_reference ?? `${device.source}-${index}`} onClick={() => setEndpoint(device.xaddrs[0] ?? "")}>
          <span>{scopeName(device.scopes)}</span><code>{device.xaddrs[0] ?? device.source ?? "未返回 XAddr"}</code>
        </button>)}
      </div>}
    </form>

    {error && <div className="error-banner"><strong>ONVIF 操作未完成</strong>{error}</div>}

    <section className={`results panel ${result ? "has-result" : ""}`}>
      <div className="panel-heading results-heading"><div><span className="step">02</span><h2>ONVIF 诊断结果</h2></div>{result && <code>{result.normalized_device_service}</code>}</div>
      {!result ? <div className="empty-state"><div className="scope-graphic" aria-hidden="true"><span /></div><h3>{running ? "正在逐项验证只读接口" : "等待 ONVIF 诊断"}</h3><p>将验证 Device、Media/Media2、Imaging、Events 与 DeviceIO 的安全只读接口；能力声明缺失或错误不会阻止后续独立验证。</p></div> : <div className="onvif-results">
        <div className="metrics">
          <div className="metric"><span>设备</span><strong>{result.device_information?.manufacturer ?? "—"} {result.device_information?.model ?? ""}</strong><small>固件 {result.device_information?.firmware_version ?? "未知"}</small></div>
          <div className="metric"><span>标准服务</span><strong>{result.services.length}</strong><small>GetServices / GetCapabilities</small></div>
          <div className="metric"><span>媒体 Profile</span><strong>{result.profiles.length}</strong><small>Media2 优先，兼容 Media</small></div>
          <div className="metric"><span>StreamUri</span><strong>{result.stream_uris.length}</strong><small>继续交给现有 RTSP/RTP 分析</small></div>
          <div className="metric"><span>设备时钟偏差</span><strong>{result.device_clock_offset_seconds == null ? "—" : `${result.device_clock_offset_seconds} s`}</strong><small>用于校正 WS-Security Created</small></div>
        </div>

        <div className="onvif-step-summary" aria-label="ONVIF 步骤状态汇总">
          <div className="passed"><span>通过</span><strong>{operationCounts.passed ?? 0}</strong><small>响应结构与关键字段有效</small></div>
          <div className="not-supported"><span>不支持</span><strong>{operationCounts.not_supported ?? 0}</strong><small>接口端点不存在或标准 Fault 明确拒绝</small></div>
          <div className="invalid-response"><span>回复不合法</span><strong>{operationCounts.invalid_response ?? 0}</strong><small>HTTP 成功但 SOAP/字段不符合标准</small></div>
          <div className="failed"><span>失败</span><strong>{operationCounts.failed ?? 0}</strong><small>网络、鉴权、HTTP 或 SOAP Fault 失败</small></div>
          <div className="skipped"><span>未执行</span><strong>{operationCounts.skipped ?? 0}</strong><small>缺少上游服务、Profile 或 Token</small></div>
        </div>

        {result.findings.length > 0 && <div className="onvif-section"><h3>诊断结论</h3>{result.findings.map((finding, index) => <div className={`onvif-finding ${finding.severity}`} key={`${finding.title}-${index}`}><strong>{finding.title}</strong><span>{finding.evidence}</span><small>{finding.suggestion}</small></div>)}</div>}

        <div className="onvif-section"><h3>媒体配置与 RTSP 入口</h3>{result.stream_uris.length === 0 ? <p>设备没有返回可用的 StreamUri。</p> : result.stream_uris.map((stream) => <div className="onvif-stream" key={`${stream.profile_token}-${stream.uri}`}><div><strong>{stream.profile_name ?? stream.profile_token}</strong><code>{displayUri(stream.uri)}</code></div><button type="button" onClick={() => onAnalyzeRtsp(rtspUriWithCredentials(stream.uri, username, password))}>转到 RTSP 深度分析</button></div>)}</div>

        <div className="onvif-section"><h3>服务目录</h3><div className="onvif-table"><div className="onvif-table-head"><span>命名空间</span><span>版本</span><span>XAddr</span></div>{result.services.map((service) => <div key={`${service.namespace}-${service.xaddr}`}><code>{service.namespace}</code><span>{service.version ?? "—"}</span><code>{service.xaddr}</code></div>)}</div></div>

        <div className="onvif-section"><h3>标准接口逐步骤诊断</h3><div className="onvif-operations">{result.operations.map((operation, index) => <div key={`${operation.service}-${operation.operation}-${index}`}><span className={`operation-status ${operation.status}`}>{operationStatusLabels[operation.status] ?? operation.status}</span><strong>{operation.service} / {operation.operation}</strong><span>{operation.elapsed_ms} ms · HTTP {operation.http_status ?? "—"}</span><small title={operation.endpoint}>{operationEvidence(operation)}</small></div>)}</div></div>

        <details className="quality-method"><summary>本次采用的标准边界</summary>{result.standards.map((standard) => <p key={standard}>{standard}</p>)}</details>
      </div>}
    </section>
  </div>;
}
