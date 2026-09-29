import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { basename, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const config = JSON.parse(await readFile(resolve(root, "apps/desktop/src-tauri/tauri.conf.json"), "utf8"));
const releaseDir = resolve(root, "target-release/release");
const filename = `StreamScope_${config.version}_x64-setup.exe`;
const installer = await readFile(resolve(releaseDir, "bundle/nsis", filename));
const signature = (await readFile(resolve(releaseDir, "bundle/nsis", `${filename}.sig`), "utf8")).trim();
const manifest = JSON.parse(await readFile(resolve(releaseDir, "latest.json"), "utf8"));
const checksums = (await readFile(resolve(releaseDir, "SHA256SUMS.txt"), "utf8")).trim();
const publicKey = (await readFile(resolve(process.env.USERPROFILE, ".tauri/streamscope-updater.key.pub"), "utf8")).trim();
const digest = createHash("sha256").update(installer).digest("hex");
const platform = manifest.platforms?.["windows-x86_64"];

if (manifest.version !== config.version) throw new Error("更新清单与应用版本不一致");
if (platform?.signature !== signature) throw new Error("更新清单与签名文件不一致");
if (config.plugins.updater.pubkey !== publicKey) throw new Error("应用内置公钥与本机发布公钥不一致");
if (basename(new URL(platform.url).pathname) !== filename) throw new Error("更新清单中的安装包名称不一致");
if (checksums !== `${digest}  ${filename}`) throw new Error("安装包 SHA-256 与校验文件不一致");
console.log(`已核对 v${config.version} 更新清单、签名、公钥和 SHA-256：${digest}`);
