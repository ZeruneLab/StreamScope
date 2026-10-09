import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const directory = resolve(process.argv[2] || "missing-packages");
const target = process.argv[3];
if (!target) throw new Error("用法：node scripts/publish-plugin-release.mjs <包目录> <插件仓库提交SHA>");
const repository = "ZeruneLab/StreamScope-Plugins";
const catalogBytes = readFileSync(join(directory, "catalog.json"));
const catalog = JSON.parse(catalogBytes);
const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"),
  Buffer.from(readFileSync(join(directory, "catalog.pub"), "utf8").trim(), "base64")]), format: "der", type: "spki" });
if (!verify(null, catalogBytes, key, Buffer.from(readFileSync(join(directory, "catalog.json.sig"), "utf8").trim(), "base64"))) {
  throw new Error("发布目录签名不匹配");
}
let tag;
const assets = [];
for (const item of catalog.packages) {
  const url = new URL(item.packageUrl);
  const parts = url.pathname.split("/");
  if (url.origin !== "https://github.com" || parts.slice(1, 5).join("/") !== `${repository}/releases/download`) {
    throw new Error("包地址不是独立官方插件仓库的固定 Release");
  }
  if (tag && tag !== parts[5]) throw new Error("一个发布批次不能混用 Release 标签");
  tag = parts[5];
  const path = join(directory, basename(url.pathname));
  const digest = `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
  if (digest !== item.packageSha256) throw new Error(`包摘要不一致：${item.id}`);
  assets.push(path);
}
if (!tag || !assets.length) throw new Error("发布包列表为空");

function gh(args, allowFailure = false) {
  const result = spawnSync("gh", args, { encoding: "utf8", shell: false, windowsHide: true });
  if (result.error) throw result.error;
  if (!allowFailure && result.status !== 0) throw new Error(result.stderr || result.stdout);
  return result;
}
if (gh(["release", "view", tag, "--repo", repository], true).status === 0) throw new Error("发布批次已存在，禁止覆盖");
gh(["release", "create", tag, "--repo", repository, "--target", target, "--draft", "--title", "首批官方签名插件（配套 v0.2.0）",
  "--notes-file", resolve(import.meta.dirname, "../docs/release-plugins-v0.2.0.md"), ...assets]);
const release = JSON.parse(gh(["release", "view", tag, "--repo", repository, "--json", "assets,url"]).stdout);
if (JSON.stringify(release.assets.map(item => item.name).sort()) !== JSON.stringify(assets.map(path => basename(path)).sort())) {
  throw new Error("上传资产不完整，保持草稿，不发布目录");
}
gh(["release", "edit", tag, "--repo", repository, "--draft=false"]);
console.log(`已发布 ${assets.length} 个签名插件：${release.url}；现在可以原子提交签名目录。`);
