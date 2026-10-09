// Uses existing signed packages read-only, with task outputs in a fresh temp directory.
import { spawn } from "node:child_process";
import { access, readdir, stat } from "node:fs/promises";
import { resolve, join } from "node:path";
import { homedir } from "node:os";

const root = resolve(import.meta.dirname, "..");
async function find(directory, name) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.isFile() && entry.name === name) return join(directory, entry.name);
    if (entry.isDirectory()) { const nested = await find(join(directory, entry.name), name); if (nested) return nested; }
  }
}
const capture = process.argv[2] && process.argv[2] !== '-' ? process.argv[2] : await find(join(homedir(), "Downloads", "周三下午视频卡顿问题测试"), "206卡顿问题(1).pcap");
if (!capture) throw new Error("请提供用于多路音视频联动回归的 PCAP 路径");
const store = process.argv[3] ? resolve(process.argv[3]) : join(process.env.LOCALAPPDATA, "StreamScope", "plugins");
await access(join(store, "registry.json"));
console.log(`只读样本：${capture}，${(await stat(capture)).size} B；不修改本机插件和已有报告。`);
const child = spawn("cargo", ["test", "-p", "streamscope-plugin-host", "--offline", "--test", "workflow_chain", "--", "--nocapture"], {
  cwd: root, stdio: "inherit", windowsHide: true,
  env: { ...process.env, STREAMSCOPE_TEST_CAPTURE: capture, STREAMSCOPE_TEST_PLUGIN_STORE: store },
});
child.on("error", (error) => { console.error(error); process.exitCode = 1; });
child.on("exit", (code) => { process.exitCode = code ?? 1; });
