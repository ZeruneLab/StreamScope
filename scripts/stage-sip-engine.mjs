import { copyFile, mkdir } from "node:fs/promises";
import { spawn, execFileSync } from "node:child_process";
import { resolve, dirname } from "node:path";

const root = resolve(import.meta.dirname, "..");
const targetDir = resolve(process.env.CARGO_TARGET_DIR || resolve(root, "target"));
const host = execFileSync("rustc", ["-vV"], { encoding: "utf8" }).match(/^host: (.+)$/m)?.[1];
if (!host) throw new Error("无法确定 Rust host target triple");
await new Promise((ok, fail) => {
  const child = spawn("cargo", ["build", "--release", "-p", "streams-sip-engine"], {
    cwd: root, env: process.env, stdio: "inherit",
  });
  child.on("error", fail);
  child.on("exit", (code) => code === 0 ? ok() : fail(new Error(`SIP Engine 构建失败：${code}`)));
});
const extension = host.includes("windows") ? ".exe" : "";
const source = resolve(targetDir, "release", `streams-sip-engine${extension}`);
const destination = resolve(root, "apps/desktop/src-tauri/binaries", `streams-sip-engine-${host}${extension}`);
await mkdir(dirname(destination), { recursive: true });
await copyFile(source, destination);
console.log(`已准备 SIP Engine sidecar：${destination}`);
if (host === "x86_64-pc-windows-gnu") {
  const bundleDestination = resolve(root, "apps/desktop/src-tauri/binaries/streams-sip-engine-x86_64-pc-windows-msvc.exe");
  await copyFile(source, bundleDestination);
  console.log(`已准备 NSIS 使用的 SIP Engine sidecar：${bundleDestination}`);
}
