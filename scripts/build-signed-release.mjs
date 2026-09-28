import { spawn } from "node:child_process";
import { access, copyFile, mkdir, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

function argument(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}

const root = resolve(import.meta.dirname, "..");
const keyArgument = argument("key");
if (!keyArgument) throw new Error("缺少发布者私钥路径：--key <路径>");
const keyPath = resolve(keyArgument);
const targetDir = resolve(argument("target", resolve(root, "target-release")));
const privateKey = (await readFile(keyPath, "utf8")).trim();
if (!privateKey) throw new Error(`签名私钥为空：${keyPath}`);

const tauriCli = resolve(root, "apps/desktop/node_modules/@tauri-apps/cli/tauri.js");
const tauriConfig = JSON.parse(await readFile(resolve(root, "apps/desktop/src-tauri/tauri.conf.json"), "utf8"));
const installerPath = resolve(
  targetDir,
  `release/bundle/nsis/StreamScope_${tauriConfig.version}_x64-setup.exe`,
);
const builtLoaderPath = resolve(targetDir, "release/WebView2Loader.dll");
const hookLoaderPath = resolve(root, "target/release/WebView2Loader.dll");
const unsignedConfig = JSON.stringify({ bundle: { createUpdaterArtifacts: false } });

function run(args, env = process.env) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(process.execPath, [tauriCli, ...args], {
      cwd: resolve(root, "apps/desktop"),
      env,
      stdio: "inherit",
    });
    child.on("error", rejectRun);
    child.on("exit", (code, signal) => {
      if (signal) rejectRun(new Error(`子进程被信号 ${signal} 终止`));
      else if (code !== 0) rejectRun(new Error(`Tauri 命令失败，退出码 ${code}`));
      else resolveRun();
    });
  });
}

const buildEnvironment = { ...process.env, CARGO_TARGET_DIR: targetDir };
await run(["build", "--no-bundle", "--config", unsignedConfig], buildEnvironment);
await access(builtLoaderPath);
await mkdir(dirname(hookLoaderPath), { recursive: true });
await copyFile(builtLoaderPath, hookLoaderPath);
await run(["bundle", "--bundles", "nsis", "--config", unsignedConfig], buildEnvironment);
await access(installerPath);
await run(["signer", "sign", "-f", keyPath, "--password=", installerPath]);

console.log(`签名安装包已生成：${installerPath}`);
