import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const repository = resolve(import.meta.dirname, "..");
const directory = join(process.env.ProgramW6432 ?? process.env.ProgramFiles, "StreamScope");
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const built = await readFile(join(repository, "target/core-host/release/streamscope-desktop.exe"));
const marker = Buffer.from("__TAURI_BUNDLE_TYPE_VAR_UNK");
const offset = built.indexOf(marker);
if (offset < 0 || built.indexOf(marker, offset + marker.length) !== -1) throw new Error("NSIS 标记无效");
Buffer.from("NSS").copy(built, offset + marker.length - 3);
const installed = await readFile(join(directory, "streamscope-desktop.exe"));
const loader = await readFile(join(directory, "WebView2Loader.dll"));
const expectedLoader = await readFile(join(repository, "target/core-host/release/WebView2Loader.dll"));
console.log(JSON.stringify({ directory, coreInstalled: digest(installed) === digest(built),
  loaderMatches: digest(loader) === digest(expectedLoader), installedSha256: digest(installed) }, null, 2));
