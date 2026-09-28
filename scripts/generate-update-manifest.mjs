import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { mkdir } from "node:fs/promises";

function argument(name, fallback = null) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}

function required(name) {
  const value = argument(name);
  if (!value) throw new Error(`缺少 --${name} 参数`);
  return resolve(value);
}

const root = resolve(import.meta.dirname, "..");
const installerPath = required("installer");
const signaturePath = required("signature");
const notesPath = required("notes");
const outputPath = required("output");
const repository = argument("repository", "ZeruneLab/StreamScope");
const publishedAt = argument("date", new Date().toISOString());

const packageJson = JSON.parse(await readFile(resolve(root, "apps/desktop/package.json"), "utf8"));
const tauriConfig = JSON.parse(await readFile(resolve(root, "apps/desktop/src-tauri/tauri.conf.json"), "utf8"));
const cargoManifest = await readFile(resolve(root, "Cargo.toml"), "utf8");
const cargoVersion = cargoManifest.match(/\[workspace\.package\][\s\S]*?\bversion\s*=\s*"([^"]+)"/)?.[1];
const versions = [packageJson.version, tauriConfig.version, cargoVersion];
if (!versions.every((version) => version === versions[0])) {
  throw new Error(`版本号不一致：npm=${versions[0]}，Tauri=${versions[1]}，Cargo=${versions[2]}`);
}
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(versions[0])) {
  throw new Error(`版本号不是有效 SemVer：${versions[0]}`);
}

const installer = await readFile(installerPath);
const signature = (await readFile(signaturePath, "utf8")).trim();
const notes = (await readFile(notesPath, "utf8")).trim();
if (!signature) throw new Error("签名文件为空");
if (!notes) throw new Error("更新说明为空");

const assetName = basename(installerPath);
const downloadUrl = `https://github.com/${repository}/releases/download/v${versions[0]}/${encodeURIComponent(assetName)}`;
const manifest = {
  version: versions[0],
  notes,
  pub_date: publishedAt,
  platforms: {
    "windows-x86_64": {
      signature,
      url: downloadUrl,
    },
  },
};
const sha256 = createHash("sha256").update(installer).digest("hex");

await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
await writeFile(resolve(dirname(outputPath), "SHA256SUMS.txt"), `${sha256}  ${assetName}\n`, "utf8");
console.log(JSON.stringify({ version: versions[0], installer: assetName, sha256, manifest: outputPath }, null, 2));
