import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { spawnSync } from "node:child_process";

function argument(name, fallback = null) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}

function required(name) {
  const value = argument(name);
  if (!value) throw new Error(`缺少 --${name} 参数`);
  return resolve(value);
}

function github(args, allowFailure = false) {
  const result = spawnSync("gh", args, { encoding: "utf8", shell: false });
  if (!allowFailure && result.status !== 0) {
    throw new Error(result.stderr.trim() || result.stdout.trim() || `gh ${args.join(" ")} 失败`);
  }
  return result;
}

const root = resolve(import.meta.dirname, "..");
const installer = required("installer");
const signature = required("signature");
const manifestPath = required("manifest");
const notes = required("notes");
const checksums = required("checksums");
const repository = argument("repository", "ZeruneLab/StreamScope");
const target = argument("target", "main");
const version = JSON.parse(await readFile(resolve(root, "apps/desktop/package.json"), "utf8")).version;
const tag = `v${version}`;

const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
if (manifest.version !== version) throw new Error(`latest.json 版本 ${manifest.version} 与应用版本 ${version} 不一致`);
if (!(await readFile(signature, "utf8")).trim()) throw new Error("签名文件为空");
const hash = createHash("sha256").update(await readFile(installer)).digest("hex");
const checksumText = await readFile(checksums, "utf8");
if (!checksumText.includes(`${hash}  ${basename(installer)}`)) throw new Error("SHA256SUMS.txt 与安装包不一致");

const existing = github(["release", "view", tag, "--repo", repository], true);
if (existing.status === 0) throw new Error(`${tag} 已存在；为避免覆盖已发布更新，发布已停止`);

github([
  "release", "create", tag,
  "--repo", repository,
  "--target", target,
  "--title", tag,
  "--notes-file", notes,
  "--draft",
  installer,
  signature,
  manifestPath,
  checksums,
]);

const release = github([
  "release", "view", tag,
  "--repo", repository,
  "--json", "assets,url,isDraft",
]);
const releaseInfo = JSON.parse(release.stdout);
const expectedAssets = [installer, signature, manifestPath, checksums].map(basename).sort();
const actualAssets = releaseInfo.assets.map((asset) => asset.name).sort();
if (JSON.stringify(expectedAssets) !== JSON.stringify(actualAssets)) {
  throw new Error(`Release 资产不完整：期望 ${expectedAssets.join(", ")}，实际 ${actualAssets.join(", ")}`);
}

github(["release", "edit", tag, "--repo", repository, "--draft=false", "--latest"]);
console.log(JSON.stringify({ tag, url: releaseInfo.url, assets: actualAssets, sha256: hash }, null, 2));
