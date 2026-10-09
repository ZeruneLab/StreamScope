import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const desktop = resolve(root, "apps/desktop");
const configPath = resolve(desktop, "src-tauri/tauri.core.conf.json");
const config = JSON.parse(await readFile(configPath, "utf8"));
if (config.build.frontendDist !== "../dist-core" || config.bundle.externalBin.length || config.bundle.resources.length) {
  throw new Error("核心构建配置包含旧前端或随包执行器");
}
const mode = process.argv[2] ?? "check";
const env = { ...process.env, TAURI_CONFIG: JSON.stringify(config), CARGO_TARGET_DIR: resolve(root, "target/core-host") };
const cargoArgs = ["-p", "streamscope-desktop", "--no-default-features", "--offline"];
let executable;
let args;
let cwd = root;
if (["check", "test", "tree"].includes(mode)) {
  executable = "cargo";
  args = [mode, ...cargoArgs];
  if (mode === "tree") args = ["tree", "-p", "streamscope-desktop", "-p", "streamscope", "--no-default-features", "--offline", "--prefix", "none", "--format", "{p}"];
} else if (["build", "package"].includes(mode)) {
  executable = process.execPath;
  args = [resolve(desktop, "node_modules/@tauri-apps/cli/tauri.js"), "build", "--config", configPath];
  if (mode === "build") args.push("--no-bundle");
  args.push("--", "--no-default-features", "--offline");
  cwd = desktop;
} else {
  throw new Error("用法：node scripts/core-host.mjs check|test|tree|build|package");
}
const child = spawn(executable, args, { cwd, env, stdio: mode === "tree" ? ["ignore", "pipe", "inherit"] : "inherit" });
let tree = "";
if (mode === "tree") child.stdout.on("data", (data) => { tree += data.toString(); });
child.on("error", (error) => { console.error(error.message); process.exitCode = 1; });
child.on("exit", (code) => {
  process.exitCode = code ?? 1;
  if (mode !== "tree" || code !== 0) return;
  const forbidden = /^streamscope-(?:analyzer|core|diagnostics|ffmpeg|h264|h265|onvif|sip|report|rtp|rtsp|sdp|audio|capture)\s/m;
  if (forbidden.test(tree)) {
    console.error("核心桌面或 CLI 仍依赖旧分析模块");
    process.exitCode = 1;
  } else {
    console.log("核心桌面与 CLI 的依赖树已验证：不包含旧分析器、协议模块或 FFmpeg 包装模块。");
  }
});
