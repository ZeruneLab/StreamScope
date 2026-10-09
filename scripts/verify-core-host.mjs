import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const desktop = resolve(root, "apps/desktop");
const config = JSON.parse(await readFile(resolve(desktop, "src-tauri/tauri.conf.json"), "utf8"));
const release = resolve(root, "target/core-host/release");
const installer = resolve(release, `bundle/nsis/StreamScope_${config.version}_x64-setup.exe`);
const sevenZip = process.env.STREAMSCOPE_7ZIP_EXE ?? resolve(process.env.ProgramFiles ?? "C:/Program Files", "7-Zip/7z.exe");

function run(executable, args) {
  return new Promise((done, reject) => {
    const child = spawn(executable, args, { cwd: root, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    child.stdout.on("data", (bytes) => { output += bytes.toString(); });
    child.stderr.on("data", (bytes) => { output += bytes.toString(); });
    child.on("error", reject);
    child.on("exit", (code) => code === 0 ? done(output) : reject(new Error(`${executable} 失败 (${code})：${output}`)));
  });
}

function digest(bytes) { return createHash("sha256").update(bytes).digest("hex"); }

const extracted = await mkdtemp(join(tmpdir(), "streamscope-core-package-check-"));
try {
  await run(sevenZip, ["x", "-y", `-o${extracted}`, installer]);
  const files = await readdir(extracted, { recursive: true });
  const payload = files.filter((file) => !file.startsWith("$PLUGINSDIR"));
  if (payload.length !== 2 || !payload.includes("streamscope-desktop.exe") || !payload.includes("WebView2Loader.dll")) {
    throw new Error(`核心安装包内容与预期不符：${payload.join(", ")}`);
  }
  for (const name of ["streamscope-desktop.exe", "WebView2Loader.dll"]) {
    const packed = await readFile(join(extracted, name));
    const built = await readFile(join(release, name));
    if (name === "streamscope-desktop.exe") {
      // Tauri stamps the bundled copy with NSS and restores UNK in the build output.
      const marker = Buffer.from("__TAURI_BUNDLE_TYPE_VAR_UNK");
      const index = built.indexOf(marker);
      if (index < 0 || built.indexOf(marker, index + marker.length) !== -1
          || packed.subarray(index, index + marker.length).toString() !== "__TAURI_BUNDLE_TYPE_VAR_NSS") {
        throw new Error("安装包缺少唯一的 Tauri NSIS 标记");
      }
      Buffer.from("NSS").copy(built, index + marker.length - 3);
    }
    if (!packed.length || digest(packed) !== digest(built)) {
      const differences = [];
      for (let i = 0; i < Math.min(packed.length, built.length) && differences.length < 16; i++) {
        if (packed[i] !== built[i]) differences.push(`${i}:${packed[i]}/${built[i]}`);
      }
      throw new Error(`安装包中的 ${name} 与构建产物不一致 (${packed.length}/${built.length} B；${differences.join(", ")})`);
    }
  }
  const dependencies = await run(process.execPath, [resolve(root, "scripts/core-host.mjs"), "tree"]);
  const adapter = await readFile(resolve(desktop, 'src/application-api.ts'), 'utf8');
  if (!adapter.includes('"execute_plugin"') || !adapter.includes('if (!coreOnly) return nativeInvoke<T>(command, args);')) {
    throw new Error('缺少核心插件业务适配器或兼容版隔离分支');
  }
  for (const view of ['App.tsx', 'OnvifDiagnostics.tsx', 'SipDiagnostics.tsx']) {
    const source = await readFile(resolve(desktop, 'src', view), 'utf8');
    if (!source.includes('import { invoke } from "./application-api";')) throw new Error(`${view} 未经插件宿主适配器调用业务动作`);
  }
  const assets = await readdir(resolve(desktop, "dist-core/assets"));
  for (const asset of assets.filter((name) => name.endsWith(".js"))) {
    const script = await readFile(resolve(desktop, "dist-core/assets", asset), "utf8");
    // Legacy UI action names are presentation identifiers, now dispatched by the
    // host API adapter. Native analysis remains absent from the core dependency tree.
    if (/start_sip_engine/.test(script)) throw new Error("核心前端仍直接启动旧业务执行器");
  }
  const bytes = await readFile(installer);
  console.log(dependencies.trim());
  console.log(`核心安装包已验收：${bytes.length} B；只含主程序、WebView2Loader 和安装器组件。`);
  console.log(`SHA-256：${digest(bytes)}`);
} finally {
  // Only the exact directory created by mkdtemp above is removed.
  await rm(extracted, { recursive: true, force: true });
}
