import { randomBytes } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";

const repository = resolve(import.meta.dirname, "..");
const temporary = await mkdtemp(join(tmpdir(), "streamscope-local-plugin-keys-"));
const output = join(process.env.USERPROFILE, "Downloads", `StreamScope-plugin-preview-${Date.now()}`);
try {
  const publisher = join(temporary, "publisher.key");
  const catalog = join(temporary, "catalog.key");
  await writeFile(publisher, randomBytes(32).toString("base64"));
  await writeFile(catalog, randomBytes(32).toString("base64"));
  await mkdir(output, { recursive: false });
  console.log(`准备本地离线验证包：${output}`);
  const code = await new Promise((done, reject) => {
    const child = spawn(process.execPath, [join(repository, "scripts/build-official-plugins.mjs"), "--skip-build"], {
      cwd: repository, stdio: "inherit", windowsHide: true, env: {
        ...process.env,
        STREAMSCOPE_PLUGIN_PUBLISHER_KEY_FILE: publisher,
        STREAMSCOPE_PLUGIN_CATALOG_KEY_FILE: catalog,
        STREAMSCOPE_PLUGIN_BASE_URL: "https://example.test/local-preview-not-published",
        STREAMSCOPE_PLUGIN_OUTPUT_DIR: output,
        STREAMSCOPE_PLUGIN_PROFILE: "debug",
      },
    });
    child.on("error", reject);
    child.on("exit", done);
  });
  if (code !== 0) throw new Error(`本地验证包生成失败 (${code})；不要导入未完成的目录 ${output}`);
  const catalogData = JSON.parse(await readFile(join(output, "catalog.json"), "utf8"));
  const names = catalogData.packages.map((entry) => `- ${entry.id} ${entry.version}`).join("\n");
  const fingerprint = catalogData.packages[0].publisherFingerprint;
  await writeFile(join(output, "先读我.md"), `# StreamScope 本地插件验证包\n\n本目录仅供本机迁移验证，使用本次生成的临时发布者密钥签名，不是正式官方发布。私钥已在打包后清理，不能用于持续升级或分享为正式 Release。\n\n发布者指纹：\`${fingerprint}\`。导入时请核对指纹，并阅读权限和原生 EXE 风险。\n\n## 如何验证\n\n1. 打开已替换的 StreamScope，进入“插件管理”。\n2. 点击“导入已签名 .ssp 插件包”，先选择 \`org.streamscope.ffmpeg-7.1.1-windows-x86_64.ssp\`，确认安装共享运行时；不需要给系统单独安装 FFmpeg。\n3. 按需导入 audio、h264、h265、pcap、rtsp、video-deep 等功能包。ONVIF、SIP 和 sample 不依赖 FFmpeg，可单独安装。\n4. 插件启用后，左侧出现对应分析入口。请用原来的样本验证分析、预览、另存、语法树与 HEX。\n5. 新结果存为 v2 插件报告，旧报告在“历史报告”中只读查看。\n\n正式目录尚未发布，“检查官方插件目录”提示未配置属于本次验证版的已知限制。本目录 catalog 的 example.test URL 是占位地址，不能在线下载。不要将其上传作为正式插件目录。\n\n## 包列表\n\n${names}\n`);
  console.log(`本地插件验证包已准备好：${output}`);
  console.log(`请通过软件导入，先读 ${join(output, "先读我.md")}；没有自动安装任何插件。`);
} finally {
  // This is only the exact temporary key directory created above, never an output/data directory.
  await rm(temporary, { recursive: true, force: true });
}
