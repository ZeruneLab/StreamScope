import { useEffect, useState } from "react";
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

export function PluginManager({ onChanged, coreOnly = false, onContinue, onOpenAnalysis }: { onChanged?: () => void; coreOnly?: boolean; onContinue?: ContinueAnalysis; onOpenAnalysis?: (directory: string) => void }) {
  const [plugins, setPlugins] = useState<Installed[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<unknown>(null);
  const [selectedReportId, setSelectedReportId] = useState("");
  const [reports, setReports] = useState<PluginReport[]>([]);
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const selectedReport = reports.find((report) => report.reportId === selectedReportId);
  const missingReportPlugins = selectedReport ? Object.keys(selectedReport.pluginResults)
    .filter((id) => !plugins.some((plugin) => plugin.manifest.id === id)) : [];

  async function refresh() {
    setPlugins(await invoke<Installed[]>("list_plugins"));
    setReports(await invoke<PluginReport[]>("list_plugin_reports"));
  }

  useEffect(() => { void refresh().catch((reason) => setError(String(reason))); }, []);

  async function checkOfficial() {
    setError("");
    setBusy(true);
    try { setCatalog(await invoke<Catalog>("check_official_plugins")); }
    catch (reason) { setError(String(reason)); }
    finally { setBusy(false); }
  }

  async function installOfficial(entry: CatalogEntry) {
    setError("");
    setBusy(true);
    const pending: Prepared[] = [];
    try {
      const prepared = await invoke<Prepared>("prepare_official_plugin", { id: entry.id, version: entry.version });
      pending.push(prepared);
      const plan = await planPluginInstallation<InstallNode>({ manifest: prepared.preview.manifest, prepared }, async (id, requirements, selectedVersion) => {
        const resolution = await invoke<{ installed?: Installed; prepared?: Prepared }>("resolve_plugin_dependency", { id, requirements, selectedVersion: selectedVersion ?? null });
        if (resolution.prepared) {
          pending.push(resolution.prepared);
          return { manifest: resolution.prepared.preview.manifest, prepared: resolution.prepared };
        }
        if (resolution.installed) return { manifest: resolution.installed.manifest, installed: resolution.installed };
        return undefined;
      });
      const changes = plan.filter((node) => node.prepared || !node.installed?.enabled);
      const details = changes.map((node) => {
        if (!node.prepared) return `启用 ${node.manifest.name} ${node.manifest.version}`;
        const preview = node.prepared.preview;
        const permissions = preview.manifest.permissions.map((permission) => `${permission.name}: ${permission.scope.join(", ")}`).join("\n") || "未声明";
        return `安装 ${preview.manifest.name} ${preview.manifest.version}\n发布者：${preview.manifest.publisher.id}\n公钥指纹：${preview.fingerprint}\n权限：\n${permissions}\n${preview.nativeRisk}`;
      }).join("\n\n");
      if (!window.confirm(`依赖已检查，按以下顺序安装或启用：\n\n${details}\n\n确认信任以上所有包？安装中断时已成功安装的依赖会保留。`)) return;
      for (const node of changes) {
        if (node.prepared) {
          const { token, preview } = node.prepared;
          await invoke("install_prepared_plugin", { token, packageSha256: preview.packageSha256, fingerprint: preview.fingerprint });
        } else {
          await invoke("enable_plugin", { id: node.manifest.id, enabled: true });
        }
      }
    } catch (reason) { setError(String(reason)); }
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
    {catalog && <div style={{ marginTop: 16 }}><h3>官方插件目录</h3>
      {catalog.packages.length === 0 ? <p>当前平台暂无可安装包。</p> : catalog.packages.map((entry) =>
        <div key={`${entry.id}-${entry.version}`} style={{ display: "flex", gap: 12, alignItems: "center", margin: "8px 0" }}>
          <span>{entry.id} · {entry.version}</span>
          <button type="button" disabled={busy || plugins.some((plugin) => plugin.manifest.id === entry.id && plugin.manifest.version === entry.version)}
            onClick={() => { void installOfficial(entry); }}>{plugins.some((plugin) => plugin.manifest.id === entry.id && plugin.manifest.version === entry.version) ? "已安装" : "下载并安装 / 更新"}</button>
        </div>)}
    </div>}
    {error && <p role="alert" style={{ color: "#b91c1c" }}>{error}</p>}
    {plugins.length === 0 && <div className="plugin-empty"><strong>选择你需要的分析工具</strong><p>导入已签名插件包后，相应功能将出现在左侧导航。</p></div>}
    <div className="plugin-card-grid">{plugins.map((plugin) => <article key={plugin.manifest.id} className="plugin-card">
      <h3>{plugin.manifest.name} <span className="plugin-badge">v{plugin.manifest.version}</span> <span className="plugin-badge">{plugin.enabled ? "已启用" : "已禁用"}</span></h3>
      <p>{plugin.manifest.id}</p>
      <small>发布者指纹：{plugin.fingerprint}</small>
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
