import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, lstat, mkdir, readFile, realpath, statfs, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const repository = resolve(import.meta.dirname, "..");
const config = JSON.parse(await readFile(join(repository, "apps/desktop/src-tauri/tauri.conf.json"), "utf8"));
const installer = join(repository, `target/core-host/release/bundle/nsis/StreamScope_${config.version}_x64-setup.exe`);
const key = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\StreamScope";
const registry = spawnSync("reg.exe", ["query", key], { encoding: "utf8", windowsHide: true });
if (registry.status !== 0) throw new Error("未找到机器级 StreamScope 安装，停止替换");
const installDirectory = registry.stdout.match(/InstallLocation\s+REG_SZ\s+([^\r\n]+)/)?.[1].trim().replace(/^"|"$/g, "");
const version = registry.stdout.match(/DisplayVersion\s+REG_SZ\s+([^\r\n]+)/)?.[1].trim();
const expectedDirectory = join(process.env.ProgramW6432 ?? process.env.ProgramFiles, "StreamScope");
if (!installDirectory || resolve(installDirectory).toLowerCase() !== resolve(expectedDirectory).toLowerCase()
    || (await realpath(installDirectory)).toLowerCase() !== resolve(expectedDirectory).toLowerCase()) {
  throw new Error("安装目录与确认过的 Program Files/StreamScope 不一致，停止替换");
}
const processes = spawnSync("tasklist.exe", ["/FO", "CSV", "/NH"], { encoding: "utf8", windowsHide: true });
if (processes.status !== 0) throw new Error("无法确认 StreamScope 是否关闭");
if (/^"streamscope-desktop\.exe"/im.test(processes.stdout)) throw new Error("请先关闭 StreamScope；不会强制结束正在运行的任务");

const verification = spawnSync(process.execPath, [join(repository, "scripts/verify-core-host.mjs")], { encoding: "utf8", windowsHide: true });
if (verification.status !== 0) throw new Error(`核心包核验失败：${verification.stderr || verification.stdout}`);
console.log(verification.stdout.trim());
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const installerDigest = verification.stdout.match(/SHA-256：([a-f0-9]{64})/)?.[1];
if (!installerDigest || digest(await readFile(installer)) !== installerDigest) throw new Error("安装包在核验后发生变化");

const destination = join(installDirectory, "streamscope-desktop.exe");
const oldDigest = digest(await readFile(destination));
const localRoot = join(process.env.LOCALAPPDATA, "StreamScope");
const backup = join(localRoot, "installation-backups", `compat-${version}-${Date.now()}`);
const disk = await statfs(process.env.LOCALAPPDATA);
if (disk.bavail * disk.bsize < 1024 ** 3) throw new Error("磁盘可用空间不足 1 GiB，停止备份和安装");
await mkdir(backup, { recursive: true });
await cp(installDirectory, join(backup, "program"), { recursive: true, errorOnExist: true, force: false,
  filter: async (source) => {
    if ((await lstat(source)).isSymbolicLink()) throw new Error("安装目录中含符号链接，停止备份");
    return true;
  },
});
await writeFile(join(backup, "backup.json"), JSON.stringify({ installDirectory, version, oldDigest, installerDigest }, null, 2));
console.log(`旧版程序已备份：${backup}`);
console.log("正在安装核心预览版；若出现 Windows 管理员确认，请点击“是”。不会卸载或清理报告。");
if (/["\r\n&|<>]/.test(installer)) throw new Error("安装包路径不能安全传给 Windows start");
const result = await new Promise((done, reject) => {
  const child = spawn("cmd.exe", ["/d", "/s", "/c", `start "" /wait "${installer}" /S /UPDATE`], {
    windowsHide: true, windowsVerbatimArguments: true, stdio: "inherit",
  });
  child.on("error", reject);
  child.on("exit", done);
});
if (result !== 0) throw new Error(`安装器退出码 ${result}；旧版备份保留在 ${backup}`);

const built = await readFile(join(repository, "target/core-host/release/streamscope-desktop.exe"));
const marker = Buffer.from("__TAURI_BUNDLE_TYPE_VAR_UNK");
const offset = built.indexOf(marker);
if (offset < 0 || built.indexOf(marker, offset + marker.length) !== -1) throw new Error("构建产物的 NSIS 标记无效");
Buffer.from("NSS").copy(built, offset + marker.length - 3);
const installed = await readFile(destination);
if (digest(installed) !== digest(built)) throw new Error(`安装后的主程序不是本次核心构建；旧版备份保留在 ${backup}`);
const loader = await readFile(join(installDirectory, "WebView2Loader.dll"));
if (digest(loader) !== digest(await readFile(join(repository, "target/core-host/release/WebView2Loader.dll")))) {
  throw new Error("安装后的 WebView2Loader 与构建产物不一致");
}
console.log(`本机核心版替换成功：${destination}`);
console.log(`主程序 SHA-256：${digest(installed)}；WebView2Loader 校验通过。历史报告和已安装插件未清理。`);
console.log("旧版随包运行时可能仍保留在安装目录，但核心宿主不会调用；保留以便验证期间回退。");
