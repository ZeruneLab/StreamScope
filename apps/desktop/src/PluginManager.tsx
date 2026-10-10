import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { PluginResult, type ContinueAnalysis } from "./PluginResult";
import { planPluginInstallation } from "./pluginInstallPlan";
import "./plugin-ui.css";

type Permission = { name: string; scope: string[] };
export type Contribution = { id: string; title: string; action: string; view: string; kind?: string };
export type Manifest = {
  id: string; name: string; version: string; description?: string;
  publisher: { id: string; keyFingerprint: string };
  permissions: Permission[];
  dependencies: { id: string; version: string }[];
  contributions: Contribution[];
};
type Preview = { manifest: Manifest; fingerprint: string; packageSha256: string; nativeRisk: string };
export type Installed = { manifest: Manifest; fingerprint: string; enabled: boolean };
type PluginReport = { reportId: string; generatedAt: string; summary: string; pluginResults: Record<string, { pluginVersion: string; action: string; result: unknown }> };
type CatalogEntry = { id: string; version: string; packageSha256: string; publisherFingerprint: string };
type Catalog = { generatedAt: string; packages: CatalogEntry[] };
type Prepared = { token: string; preview: Preview };
type InstallNode = { manifest: Manifest; prepared?: Prepared; installed?: Installed };
type InstallPhase = "queued" | "preparing" | "ready" | "installing" | "success" | "failed" | "skipped" | "cancelled";
type InstallProgress = { id: string; name: string; version: string; phase: InstallPhase; detail?: string };
const phaseLabels: Record<InstallPhase, string> = { queued: "等待处理", preparing: "下载并校验", ready: "待确认", installing: "正在安装", success: "已完成", failed: "失败", skipped: "已跳过", cancelled: "已取消" };
const officialNames: Record<string, [string, string]> = {
  audio: ["音频分析", "音频质量、频谱、波形与格式导出"],
  ffmpeg: ["FFmpeg 共享运行时", "媒体插件共用的解码与转码依赖"],
  h264: ["H.264 视频分析", "码流诊断、NALU 语法与 HEX"],
  h265: ["H.265 / HEVC 视频分析", "码流诊断、NALU 语法与 HEX"],
  onvif: ["ONVIF 诊断", "设备发现、标准接口验证与 RTSP 联动"],
  pcap: ["PCAP / PCAPNG 抓包分析", "多路媒体流识别与音视频联合分析"],
  rtsp: ["RTSP 实时分析", "协商、传输与媒体质量诊断"],
  sample: ["示例插件", "用于验证插件机制，无需日常安装"],
  sip: ["SIP 诊断与模拟", "信令分析与面向指定设备的场景模拟"],
  "video-deep": ["视频深度分析", "精确帧、QP、运动矢量与内部块证据"],
};
function catalogInfo(entry: CatalogEntry): [string, string] {
  return officialNames[entry.id.replace(/^org\.streamscope\./, "")] ?? [entry.id, "官方签名插件"];
}

function InstallConsent({ nodes, onAnswer }: { nodes: InstallNode[]; onAnswer: (approved: boolean) => void }) {
  const [accepted, setAccepted] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { heading.current?.focus(); }, []);
  return <section className="plugin-consent" aria-label="安装前安全确认">
    <h3 ref={heading} tabIndex={-1}>安装前确认 · {nodes.length} 项变更</h3>
    <p>原生插件以当前 Windows 用户权限运行，没有系统级沙箱。签名证明来源和完整性，不证明代码安全。</p>
    <div className="plugin-consent-items" tabIndex={0} aria-label="待安装插件的发布者与权限详情">{nodes.map((node) => <details key={node.manifest.id} open>
      <summary>{node.prepared ? "安装" : "启用"} {node.manifest.name} · v{node.manifest.version}</summary>
      {node.prepared && <><dl><dt>发布者</dt><dd>{node.manifest.publisher.id}</dd>
        <dt>公钥指纹</dt><dd>{node.prepared.preview.fingerprint}</dd>
        <dt>包 SHA-256</dt><dd>{node.prepared.preview.packageSha256}</dd>
        <dt>宿主权限</dt><dd>{node.manifest.permissions.length ? node.manifest.permissions.map((permission) => <div key={permission.name}>{permission.name}: {permission.scope.join(", ") || "未指定范围"}</div>) : "未声明宿主权限"}</dd></dl>
        <p>{node.prepared.preview.nativeRisk}</p></>}
    </details>)}</div>
    <label className="plugin-checkbox"><input type="checkbox" checked={accepted} onChange={(event) => setAccepted(event.target.checked)} />我已核对发布者和权限，并信任以上所有插件</label>
    <div className="plugin-toolbar"><button className="plugin-primary" type="button" disabled={!accepted} onClick={() => onAnswer(true)}>确认并安装</button>
      <button type="button" onClick={() => onAnswer(false)}>取消本次安装</button></div>
    <small>按依赖顺序安装；若中途失败，已成功安装的插件保留，失败项可重试。</small>
  </section>;
}

export function PluginManager({ onChanged, coreOnly = false, onContinue, onOpenAnalysis }: { onChanged?: () => void; coreOnly?: boolean; onContinue?: ContinueAnalysis; onOpenAnalysis?: (directory: string) => void }) {
  const [plugins, setPlugins] = useState<Installed[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<unknown>(null);
  const [selectedReportId, setSelectedReportId] = useState("");
  const [reports, setReports] = useState<PluginReport[]>([]);
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [progress, setProgress] = useState<Record<string, InstallProgress>>({});
  const [consent, setConsent] = useState<{ nodes: InstallNode[]; resolve: (approved: boolean) => void } | null>(null);
  const mounted = useRef(true);
  const consentAnswer = useRef<((approved: boolean) => void) | null>(null);
  // The signed catalog is sorted newest-first. Only offer one version per plugin.
  const entries = catalog?.packages.filter((entry, index, packages) => packages.findIndex((item) => item.id === entry.id) === index) ?? [];
  const available = entries.filter((entry) => !plugins.some((plugin) => plugin.manifest.id === entry.id && plugin.manifest.version === entry.version));
  const selected = available.filter((entry) => selectedIds.includes(entry.id));
  const tasks = Object.values(progress);
  const finished = tasks.filter((task) => ["success", "failed", "skipped", "cancelled"].includes(task.phase)).length;
  const selectedReport = reports.find((report) => report.reportId === selectedReportId);
  const missingReportPlugins = selectedReport ? Object.keys(selectedReport.pluginResults)
    .filter((id) => !plugins.some((plugin) => plugin.manifest.id === id)) : [];

  async function refresh() {
    setPlugins(await invoke<Installed[]>("list_plugins"));
    setReports(await invoke<PluginReport[]>("list_plugin_reports"));
  }

  useEffect(() => { void refresh().catch((reason) => setError(String(reason))); }, []);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; consentAnswer.current?.(false); };
  }, []);

  async function checkOfficial() {
    setError("");
    setBusy(true);
    try { setCatalog(await invoke<Catalog>("check_official_plugins")); }
    catch (reason) { setError(String(reason)); }
    finally { setBusy(false); }
  }

  async function installOfficial(entries: CatalogEntry[]) {
    if (!entries.length) return;
    setError("");
    setBusy(true);
    setProgress(Object.fromEntries(entries.map((entry) => [entry.id, { id: entry.id, name: catalogInfo(entry)[0], version: entry.version, phase: "queued" }])));
    const pending: Prepared[] = [];
    const update = (id: string, patch: Partial<InstallProgress>) => setProgress((previous) => ({ ...previous, [id]: { ...previous[id], ...patch } }));
    try {
      const roots: InstallNode[] = [];
      for (const entry of entries) {
        update(entry.id, { phase: "preparing" });
        try {
          const prepared = await invoke<Prepared>("prepare_official_plugin", { id: entry.id, version: entry.version });
          pending.push(prepared);
          roots.push({ manifest: prepared.preview.manifest, prepared });
          update(entry.id, { name: prepared.preview.manifest.name, phase: "ready" });
        } catch (reason) { update(entry.id, { phase: "failed", detail: String(reason) }); }
      }
      if (!roots.length) return;
      const plan = await planPluginInstallation<InstallNode>(roots, async (id, requirements, selectedVersion) => {
        if (!selectedVersion) update(id, { id, name: id, version: "", phase: "preparing", detail: "检查共享依赖" });
        const resolution = await invoke<{ installed?: Installed; prepared?: Prepared }>("resolve_plugin_dependency", { id, requirements, selectedVersion: selectedVersion ?? null });
        if (resolution.prepared) {
          pending.push(resolution.prepared);
          update(id, { name: resolution.prepared.preview.manifest.name, version: resolution.prepared.preview.manifest.version, phase: "ready", detail: "自动添加的依赖" });
          return { manifest: resolution.prepared.preview.manifest, prepared: resolution.prepared };
        }
        if (resolution.installed) {
          update(id, { name: resolution.installed.manifest.name, version: resolution.installed.manifest.version, phase: resolution.installed.enabled ? "success" : "ready", detail: resolution.installed.enabled ? "复用已安装的依赖" : "需要启用依赖" });
          return { manifest: resolution.installed.manifest, installed: resolution.installed };
        }
        return undefined;
      });
      const changes = plan.filter((node) => node.prepared || !node.installed?.enabled);
      if (!mounted.current) return;
      const approved = await new Promise<boolean>((resolve) => {
        consentAnswer.current = resolve;
        setConsent({ nodes: changes, resolve });
      });
      consentAnswer.current = null;
      setConsent(null);
      if (!approved) {
        changes.forEach((node) => update(node.manifest.id, { phase: "cancelled", detail: "未执行安装" }));
        return;
      }
      const failed = new Set<string>();
      for (const node of changes) {
        const blocked = node.manifest.dependencies.filter((dependency) => failed.has(dependency.id));
        if (blocked.length) {
          failed.add(node.manifest.id);
          update(node.manifest.id, { phase: "skipped", detail: `依赖未完成：${blocked.map((dependency) => dependency.id).join("、")}` });
          continue;
        }
        update(node.manifest.id, { phase: "installing", detail: "" });
        try {
          if (node.prepared) {
            const { token, preview } = node.prepared;
            await invoke("install_prepared_plugin", { token, packageSha256: preview.packageSha256, fingerprint: preview.fingerprint });
          } else {
            await invoke("enable_plugin", { id: node.manifest.id, enabled: true });
          }
          update(node.manifest.id, { phase: "success" });
        } catch (reason) {
          failed.add(node.manifest.id);
          update(node.manifest.id, { phase: "failed", detail: String(reason) });
        }
      }
    } catch (reason) {
      setError(`依赖预检未通过，本批次未执行安装：${String(reason)}`);
      setProgress((previous) => Object.fromEntries(Object.entries(previous).map(([id, task]) => [id,
        ["queued", "preparing", "ready"].includes(task.phase) ? { ...task, phase: "skipped", detail: "依赖预检未通过，未执行安装" } : task])));
    }
    finally {
      await Promise.all(pending.map(({ token }) => invoke("discard_prepared_plugin", { token }).catch(() => undefined)));
      await refresh().catch((reason) => setError(String(reason)));
      onChanged?.();
      setBusy(false);
    }
  }

  async function importPackage() {
    setError("");
    const path = await open({ multiple: false, directory: false, filters: [{ name: "StreamScope 插件包", extensions: ["ssp"] }] });
    if (!path) return;
    setBusy(true);
    try {
      const preview = await invoke<Preview>("preview_plugin", { path });
      const permissions = preview.manifest.permissions.length
        ? preview.manifest.permissions.map((item) => `${item.name}${item.scope.length ? ` (${item.scope.join(", ")})` : ""}`).join("\n")
        : "未声明宿主权限";
      const approved = window.confirm(
        `安装 ${preview.manifest.name} ${preview.manifest.version}？\n` +
        `发布者：${preview.manifest.publisher.id}\n公钥指纹：${preview.fingerprint}\n` +
        `包 SHA-256：${preview.packageSha256}\n权限：\n${permissions}\n\n${preview.nativeRisk}\n\n确认信任该发布者和此包后安装。`,
      );
      if (!approved) return;
      await invoke("install_plugin", { path, packageSha256: preview.packageSha256, fingerprint: preview.fingerprint });
      await refresh();
      onChanged?.();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function changeEnabled(plugin: Installed, enabled: boolean) {
    setError("");
    setBusy(true);
    try {
      await invoke("enable_plugin", { id: plugin.manifest.id, enabled });
      await refresh();
      onChanged?.();
    } catch (reason) { setError(String(reason)); }
    finally { setBusy(false); }
  }

  async function remove(plugin: Installed) {
    if (!window.confirm(`卸载 ${plugin.manifest.name}？历史报告会保留。`)) return;
    setError("");
    setBusy(true);
    try {
      await invoke("uninstall_plugin", { id: plugin.manifest.id });
      await refresh();
      onChanged?.();
    } catch (reason) { setError(String(reason)); }
    finally { setBusy(false); }
  }

  return <section className="panel plugin-panel">
    <div className="panel-heading"><div><span className="step">01</span><h2>插件管理</h2></div></div>
    <p>{coreOnly ? "按需安装分析插件。已有任务和报告会保留；FFmpeg 随所需的媒体插件安装为共享运行时。" : "当前为插件宿主试运行版。旧分析功能仍保留在主程序中；迁移及等价回归完成前不会自动替换。"}</p>
    <div className="plugin-toolbar"><button className="plugin-primary" type="button" disabled={busy} onClick={() => { void importPackage(); }}>＋ 导入已签名 .ssp 插件包</button>
    <button type="button" disabled={busy} onClick={() => { void checkOfficial(); }}>检查官方插件目录</button></div>
    {catalog && <section className="plugin-catalog" aria-label="官方插件目录"><div className="plugin-section-heading"><div><h3>官方插件目录 <span className="plugin-badge">{entries.length} 个插件</span></h3>
      <p>依赖自动去重，按顺序安装；历史报告不受影响。</p></div><small>目录更新于 {new Date(catalog.generatedAt).toLocaleString("zh-CN")}</small></div>
      {entries.length === 0 ? <p>当前平台暂无可安装包。</p> : <>
        <div className="plugin-batch-toolbar"><label><input type="checkbox" aria-label="全选可安装插件" disabled={busy || !available.length}
          checked={available.length > 0 && selected.length === available.length} ref={(input) => { if (input) input.indeterminate = selected.length > 0 && selected.length < available.length; }}
          onChange={(event) => setSelectedIds(event.target.checked ? available.map((entry) => entry.id) : [])} />全选可安装项</label>
          <span>已选择 {selected.length} / {available.length} 项</span>
          <button className="plugin-primary" type="button" disabled={busy || !selected.length} onClick={() => { void installOfficial(selected); }}>批量下载安装{selected.length ? `（${selected.length}）` : ""}</button>
        </div>
        <div className="plugin-catalog-list">{entries.map((entry) => {
          const installed = plugins.find((plugin) => plugin.manifest.id === entry.id);
          const current = installed?.manifest.version === entry.version;
          const [name, description] = catalogInfo(entry);
          return <article className={`plugin-catalog-row${selected.some((item) => item.id === entry.id) ? " is-selected" : ""}`} key={entry.id}>
            <input type="checkbox" aria-label={`选择 ${name}`} disabled={busy || current} checked={!current && selectedIds.includes(entry.id)}
              onChange={(event) => setSelectedIds(event.target.checked ? [...selectedIds, entry.id] : selectedIds.filter((id) => id !== entry.id))} />
            <div className="plugin-catalog-info"><h4>{name} <span className="plugin-badge">{entry.id.endsWith(".ffmpeg") ? "共享依赖" : entry.id.endsWith(".sample") ? "示例" : "功能插件"}</span></h4><p>{description}</p><small>{entry.id}</small></div>
            <div className="plugin-catalog-version"><strong>v{entry.version}</strong><small>{installed ? `本机 v${installed.manifest.version}` : "尚未安装"}</small></div>
            <span className={`plugin-install-state ${current ? "success" : "ready"}`}>{current ? installed?.enabled ? "已安装" : "已禁用" : installed ? "版本不同" : "可安装"}</span>
            <button type="button" disabled={busy || current} onClick={() => { void installOfficial([entry]); }}>{current ? "已安装" : installed ? "更新" : "下载安装"}</button>
          </article>;
        })}</div>
      </>}
    </section>}
    {tasks.length > 0 && <section className="plugin-install-progress" aria-label="安装进度"><div className="plugin-section-heading"><h3>{busy ? "正在处理插件" : "本次处理结果"}</h3><span role="status">{finished} / {tasks.length} 项已处理</span></div>
      <progress aria-label="插件处理进度" max={tasks.length} value={finished} />
      <p className="plugin-muted">共享依赖只处理一次，安全确认后开始安装。</p>
      <ul>{tasks.map((task) => <li key={task.id}><div><strong>{task.name}</strong> <small>{task.version && `v${task.version}`}</small>{task.detail && <p>{task.detail}</p>}</div>
        <span className={`plugin-install-state ${task.phase}`}>{phaseLabels[task.phase]}</span></li>)}</ul>
    </section>}
    {consent && <InstallConsent nodes={consent.nodes} onAnswer={(approved) => consent.resolve(approved)} />}
    {error && <p role="alert" style={{ color: "#b91c1c" }}>{error}</p>}
    {plugins.length === 0 && <div className="plugin-empty"><strong>选择你需要的分析工具</strong><p>导入已签名插件包后，相应功能将出现在左侧导航。</p></div>}
    {plugins.length > 0 && <div className="plugin-section-heading plugin-installed-heading"><h3>已安装插件 <span className="plugin-badge">{plugins.length}</span></h3><span>{plugins.filter((plugin) => plugin.enabled).length} 个已启用</span></div>}
    <div className="plugin-card-grid">{plugins.map((plugin) => <article key={plugin.manifest.id} className="plugin-card">
      <h3>{plugin.manifest.name} <span className="plugin-badge">v{plugin.manifest.version}</span> <span className="plugin-badge">{plugin.enabled ? "已启用" : "已禁用"}</span></h3>
      <p>{plugin.manifest.id}</p>
      <details className="plugin-publisher"><summary>发布者与签名信息</summary><small>{plugin.manifest.publisher.id}</small><small>公钥指纹：{plugin.fingerprint}</small></details>
      <div className="plugin-toolbar">
        <button type="button" disabled={busy} onClick={() => { void changeEnabled(plugin, !plugin.enabled); }}>{plugin.enabled ? "禁用" : "启用"}</button>
        <button className="plugin-danger" type="button" disabled={busy} onClick={() => { void remove(plugin); }}>卸载</button>
      </div>
    </article>)}</div>
    <h3 style={{ marginTop: 24 }}>插件报告</h3>
    <p>即使卸载原插件，已保存的基础报告仍可查看。</p>
    {reports.length === 0 ? <p>暂无插件报告。</p> : <div className="plugin-report-list">{reports.map((report) =>
      <button key={report.reportId} type="button" className="plugin-report-row" disabled={busy} onClick={() => {
        setBusy(true); setError("");
        void invoke<PluginReport>("load_plugin_report", { reportId: report.reportId }).then((loaded) => {
          setResult(Object.values(loaded.pluginResults)[0]?.result ?? loaded); setSelectedReportId(loaded.reportId);
        }).catch((reason) => setError(String(reason))).finally(() => setBusy(false));
      }}>
        <span>{report.summary}</span><time>{new Date(report.generatedAt).toLocaleString("zh-CN")}</time>
      </button>)}</div>}
    {missingReportPlugins.length > 0 && <p role="status">原插件 {missingReportPlugins.join("、")} 已卸载；基础报告仍可查看。需要重新分析时，请在上方检查官方插件目录或导入已签名插件包。</p>}
    {result !== null && <PluginResult value={result} reportId={selectedReportId} onContinue={onContinue} />}
    {onOpenAnalysis && typeof (result as Record<string, unknown> | null)?.reportDirectory === "string" && (result as Record<string, unknown>).status != null &&
      <button type="button" onClick={() => onOpenAnalysis((result as Record<string, string>).reportDirectory)}>打开完整分析工作台</button>}
  </section>;
}
