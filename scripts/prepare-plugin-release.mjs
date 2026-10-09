import { createHash, createPrivateKey, createPublicKey, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(import.meta.dirname, "..");
const keys = join(process.env.USERPROFILE, ".tauri");
const publisher = join(keys, "streamscope-plugin-publisher.key");
const catalog = join(keys, "streamscope-plugin-catalog.key");
const catalogUrl = "https://raw.githubusercontent.com/ZeruneLab/StreamScope-Plugins/main/catalog.json";
const tag = "plugins-2026.10.09.1";
const output = join(root, "dist", "official-plugins", tag);
const release = join(root, "target", "core-host", "release");
const version = JSON.parse(readFileSync(join(root, "apps/desktop/package.json"), "utf8")).version;

function publicKey(path) {
  const seed = Buffer.from(readFileSync(path, "utf8").trim(), "base64");
  if (seed.length !== 32) throw new Error("插件签名 seed 必须为 32 字节");
  const key = createPrivateKey({ key: Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"), seed,
  ]), format: "der", type: "pkcs8" });
  return createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32);
}

function run(script, args = [], env = process.env) {
  const result = spawnSync(process.execPath, [join(root, "scripts", script), ...args], {
    cwd: root, env, stdio: "inherit", windowsHide: true,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${script} 失败 (${result.status})`);
}

const mode = process.argv[2];
if (mode === "keys") {
  mkdirSync(keys, { recursive: true });
  for (const path of [publisher, catalog]) {
    // Persisted outside the repository; never rotate an existing release identity.
    if (!existsSync(path)) writeFileSync(path, randomBytes(32).toString("base64"), { flag: "wx", mode: 0o600 });
    writeFileSync(`${path}.pub`, publicKey(path).toString("base64"));
  }
  console.log(`正式发布者指纹：sha256:${createHash("sha256").update(publicKey(publisher)).digest("hex")}`);
  console.log("长期私钥保存在用户 .tauri 目录，请离线备份；不会上传或输出私钥内容。");
} else if (mode === "plugins") {
  if (existsSync(join(output, "catalog.json"))) throw new Error("该批次已经存在，请更换发布批次，禁止覆盖已发布包");
  run("build-official-plugins.mjs", [], {
    ...process.env,
    STREAMSCOPE_PLUGIN_PUBLISHER_KEY_FILE: publisher,
    STREAMSCOPE_PLUGIN_CATALOG_KEY_FILE: catalog,
    STREAMSCOPE_PLUGIN_BASE_URL: `https://github.com/ZeruneLab/StreamScope-Plugins/releases/download/${tag}`,
    STREAMSCOPE_PLUGIN_OUTPUT_DIR: output,
  });
} else if (mode === "core") {
  run("build-signed-release.mjs", ["--core", "--key", join(keys, "streamscope-updater.key")], {
    ...process.env,
    STREAMSCOPE_PLUGIN_CATALOG_URL: catalogUrl,
    STREAMSCOPE_PLUGIN_CATALOG_PUBLIC_KEY: publicKey(catalog).toString("base64"),
  });
  const installer = join(release, "bundle", "nsis", `StreamScope_${version}_x64-setup.exe`);
  run("generate-update-manifest.mjs", ["--installer", installer, "--signature", `${installer}.sig`,
    "--notes", join(root, "docs", `release-v${version}.md`), "--output", join(release, "latest.json")]);
  run("verify-release.mjs", [release]);
  run("verify-core-host.mjs");
} else {
  throw new Error("用法：node scripts/prepare-plugin-release.mjs keys|plugins|core；此脚本只构建，不发布或安装。");
}
