import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const base = "https://raw.githubusercontent.com/ZeruneLab/StreamScope-Plugins/main";
const expectedCatalog = Buffer.from(readFileSync(join(process.env.USERPROFILE, ".tauri/streamscope-plugin-catalog.key.pub"), "utf8").trim(), "base64");
const ed25519 = bytes => createPublicKey({ key: Buffer.concat([
  Buffer.from("302a300506032b6570032100", "hex"), bytes,
]), format: "der", type: "spki" });

async function response(url) {
  // No GitHub token, cookies, or credentials: verify the public user path.
  const result = await fetch(url, { signal: AbortSignal.timeout(300000) });
  if (!result.ok) throw new Error(`匿名下载失败：HTTP ${result.status} ${url}`);
  return result;
}
async function bytes(url) { return Buffer.from(await (await response(url)).arrayBuffer()); }
async function digest(url) {
  const hash = createHash("sha256");
  for await (const chunk of (await response(url)).body) hash.update(chunk);
  return hash.digest("hex");
}

const directory = await bytes(`${base}/catalog.json`);
const signature = Buffer.from((await bytes(`${base}/catalog.json.sig`)).toString().trim(), "base64");
if (!verify(null, directory, ed25519(expectedCatalog), signature)) throw new Error("线上目录不是主程序配置的受信任密钥签名");
const catalog = JSON.parse(directory);
for (const item of catalog.packages) {
  const actual = `sha256:${await digest(item.packageUrl)}`;
  if (actual !== item.packageSha256) throw new Error(`线上包摘要错误：${item.id}`);
  console.log(`匿名下载与 SHA-256 通过：${item.id} ${item.version}`);
}
console.log("官方插件目录验签、全部包匿名下载和摘要校验通过。");

if (process.argv.includes("--app")) {
  const release = join(root, "target/core-host/release");
  const expected = JSON.parse(readFileSync(join(release, "latest.json"), "utf8"));
  const online = JSON.parse(await bytes("https://github.com/ZeruneLab/StreamScope/releases/latest/download/latest.json"));
  const platform = online.platforms?.["windows-x86_64"];
  if (online.version !== expected.version || JSON.stringify(platform) !== JSON.stringify(expected.platforms["windows-x86_64"])) {
    throw new Error("线上应用更新清单与本轮签名交付不一致");
  }
  const installer = await bytes(platform.url);
  const checksum = readFileSync(join(release, "SHA256SUMS.txt"), "utf8").trim().split(/\s+/)[0];
  if (createHash("sha256").update(installer).digest("hex") !== checksum) throw new Error("线上主程序安装包摘要不一致");
  const config = JSON.parse(readFileSync(join(root, "apps/desktop/src-tauri/tauri.conf.json"), "utf8"));
  const publicPacket = Buffer.from(Buffer.from(config.plugins.updater.pubkey, "base64").toString().trim().split(/\r?\n/)[1], "base64");
  const signaturePacket = Buffer.from(Buffer.from(platform.signature, "base64").toString().trim().split(/\r?\n/)[1], "base64");
  const algorithm = signaturePacket.subarray(0, 2).toString();
  if (publicPacket.length !== 42 || signaturePacket.length !== 74
      || !signaturePacket.subarray(2, 10).equals(publicPacket.subarray(2, 10))
      || !["ED", "Ed"].includes(algorithm)) throw new Error("Tauri 更新签名格式或密钥标识错误");
  const message = algorithm === "ED" ? createHash("blake2b512").update(installer).digest() : installer;
  if (!verify(null, message, ed25519(publicPacket.subarray(10)), signaturePacket.subarray(10))) {
    throw new Error("线上 Tauri 安装包签名无效");
  }
  console.log(`主程序 v${online.version} 匿名更新清单、安装包摘要和 Ed25519 更新签名验证通过。`);
}
