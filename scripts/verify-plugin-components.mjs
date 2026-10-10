import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const desktop = resolve(import.meta.dirname, "../apps/desktop");
const require = createRequire(resolve(desktop, "package.json"));
const { createServer } = await import(pathToFileURL(require.resolve("vite")).href);
const { createElement } = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const server = await createServer({ root: desktop, mode: "core", optimizeDeps: { noDiscovery: true, include: [] }, server: { middlewareMode: true }, appType: "custom" });
try {
  const { PluginResult } = await server.ssrLoadModule("/src/PluginResult.tsx");
  const { PluginFields } = await server.ssrLoadModule("/src/PluginView.tsx");
  const fieldsMarkup = renderToStaticMarkup(createElement(PluginFields, {
    components: [
      { type: "input", id: "path", label: "视频文件", inputType: "file", required: true },
      { type: "input", id: "frame", label: "显示帧序号", inputType: "number", required: false },
      { type: "input", id: "secret", label: "密码", inputType: "password", required: false },
      { type: "select", id: "transport", label: "传输", options: ["TCP", "UDP"], required: true },
      { type: "input", id: "allow", label: "允许", inputType: "checkbox", required: false },
    ], fields: { path: "C:\\视频\\sample.h264", frame: "0", transport: "UDP", allow: "true" },
    busy: true, onChange() {}, onPickFile() {},
  }));
  assert(fieldsMarkup.includes("plugin-form-grid"));
  assert(fieldsMarkup.includes("plugin-field-wide"));
  assert(fieldsMarkup.includes("plugin-file-picker"));
  assert(fieldsMarkup.includes('type="password"'));
  assert(fieldsMarkup.includes('value="UDP" selected=""'));
  assert(fieldsMarkup.includes('value="0"'));
  assert.equal((fieldsMarkup.match(/disabled=""/g) ?? []).length, 6);
  assert(fieldsMarkup.includes('checked=""'));
  const render = (blocks) => renderToStaticMarkup(createElement(PluginResult, { value: { blocks } }));
  const normal = render([
    { type: "syntaxTree", title: "NALU 语法树", nodes: [{ label: "SPS", children: [{ label: "profile_idc", value: 100, byteOffset: 1 }] }] },
    { type: "hex", title: "HEX", bytesHex: "000102ff", fields: [{ name: "nal_unit_type", value: 7 }] },
    { type: "download", title: "另存导出文件", artifactId: "sha256:test", filename: "audio.mp3" },
  ]);
  assert(normal.includes("profile_idc"));
  assert(normal.includes("字节 1"));
  assert(normal.includes("HEX 字号"));
  assert(normal.includes("00000000 00 01 02 ff"));
  assert(normal.includes("另存导出文件"));
  const workflow = renderToStaticMarkup(createElement(PluginResult, { reportId: "source-report", onContinue() {}, value: { blocks: [
    { type: "actions", title: "stream-0001 · h264", actions: [{ id: "stream-0001-frame", title: "视频深度分析", pluginId: "org.streamscope.video-deep" }] },
    { type: "actions", title: "坏动作", actions: [{ id: 1, title: {}, pluginId: null }] },
  ] } }));
  assert(workflow.includes("媒体流与联合分析"));
  assert(workflow.includes("视频深度分析"));
  assert(!workflow.includes("<h4>坏动作</h4>"));
  assert(render([{ type: "hex", title: "偏移", bytesHex: "68ce", byteOffset: 9, truncated: true }]).includes("00000009 68 ce"));
  const malformed = render([
    { type: "table", title: "坏列", columns: [{ unexpected: true }], rows: [[1]] },
    { type: "table", title: "结构化值", columns: ["值"], rows: [[{ toString: null, valueOf: null }]] },
    { type: "hex", title: "坏字段", bytesHex: "not hex", fields: { not: "an array" } },
    { type: "timeline", title: "坏事件", events: [null, { offsetMs: 1, label: "x", detail: { invalid: true } }] },
    { type: "syntaxTree", title: "第三方树", nodes: [null, { label: "<script>alert(1)</script>", value: { toString: null }, children: "wrong" }] },
  ]);
  assert(malformed.includes("没有有效的十六进制字节"));
  assert(!malformed.includes("<script>"));
  assert(!malformed.includes("[object Object]"));
  const many = render([{ type: "syntaxTree", title: "大树", nodes: Array.from({ length: 2100 }, (_, i) => ({ label: `node-${i}` })) }]);
  assert(many.includes("树视图最多展示"));
  assert.equal((many.match(/<strong>/g) ?? []).length, 2000);
  const { planPluginInstallation } = await server.ssrLoadModule("/src/pluginInstallPlan.ts");
  const node = (id, dependencies = []) => ({ manifest: { id, name: id, version: "1.0.0", dependencies: dependencies.map((id) => ({ id, version: "^1" })) } });
  const root = node("root", ["a", "b"]);
  const nodes = { a: node("a", ["runtime"]), b: node("b", ["runtime"]), runtime: node("runtime") };
  const requests = [];
  const plan = await planPluginInstallation(root, async (id, requirements, selectedVersion) => {
    requests.push({ id, requirements, selectedVersion });
    return selectedVersion ? undefined : nodes[id];
  });
  assert.deepEqual(plan.map(({ manifest }) => manifest.id), ["runtime", "a", "b", "root"]);
  assert.equal(requests.filter(({ id, selectedVersion }) => id === "runtime" && !selectedVersion).length, 1);
  assert(requests.some(({ id, selectedVersion }) => id === "runtime" && selectedVersion === "1.0.0"));
  const batchRequests = [];
  const batch = await planPluginInstallation([node("a", ["runtime"]), node("b", ["runtime"])], async (id, requirements, selectedVersion) => {
    batchRequests.push({ id, selectedVersion });
    return selectedVersion ? undefined : nodes[id];
  });
  assert.deepEqual(batch.map(({ manifest }) => manifest.id), ["runtime", "a", "b"]);
  assert.equal(batchRequests.filter(({ id, selectedVersion }) => id === "runtime" && !selectedVersion).length, 1);
  const selectedDependency = await planPluginInstallation([node("a", ["b"]), node("b")], async (_id, _requirements, selectedVersion) => {
    assert.equal(selectedVersion, "1.0.0");
    return undefined;
  });
  assert.deepEqual(selectedDependency.map(({ manifest }) => manifest.id), ["b", "a"]);
  assert.deepEqual(await planPluginInstallation([], async () => undefined), []);
  await assert.rejects(planPluginInstallation([node("a"), { manifest: { ...node("a").manifest, version: "2.0.0" } }], async () => undefined), /多个版本/);
  await assert.rejects(planPluginInstallation([node("a", ["b"]), node("b", ["a"])], async () => undefined), /循环/);
  await assert.rejects(planPluginInstallation([node("a", ["runtime"]), node("b", ["runtime"])], async (id, _requirements, version) => {
    if (version) throw new Error("批量依赖版本冲突");
    return nodes[id];
  }), /批量依赖版本冲突/);
  await assert.rejects(planPluginInstallation(node("root", ["root"]), async () => undefined), /循环/);
  await assert.rejects(planPluginInstallation(root, async (id, requirements, selectedVersion) => {
    if (selectedVersion) throw new Error("版本不满足，未执行安装");
    return nodes[id];
  }), /未执行安装/);
  await assert.rejects(planPluginInstallation(root, async () => undefined), /未返回/);
  console.log("宿主语法树、HEX 和畸形插件结果的后台渲染验证通过。");
  console.log("插件文件、数值、密码、下拉和复选框渲染及执行中禁用验证通过。");
  console.log("单项/批量依赖排序、共享依赖去重、选中依赖复用、循环与版本冲突预检通过。");
} finally {
  await server.close();
}
