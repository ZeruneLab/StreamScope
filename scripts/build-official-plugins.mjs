import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { copyFileSync, createReadStream, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repository = resolve(fileURLToPath(new URL('..', import.meta.url)));
const publisherKey = process.env.STREAMSCOPE_PLUGIN_PUBLISHER_KEY_FILE;
const catalogKey = process.env.STREAMSCOPE_PLUGIN_CATALOG_KEY_FILE;
const baseUrl = process.env.STREAMSCOPE_PLUGIN_BASE_URL?.replace(/\/$/, '');
if (!publisherKey || !catalogKey || !baseUrl || !baseUrl.startsWith('https://')) {
  throw new Error('需要 STREAMSCOPE_PLUGIN_PUBLISHER_KEY_FILE、STREAMSCOPE_PLUGIN_CATALOG_KEY_FILE 和 HTTPS 的 STREAMSCOPE_PLUGIN_BASE_URL');
}
const profile = process.env.STREAMSCOPE_PLUGIN_PROFILE === 'debug' ? 'debug' : 'release';
const targetRoot = resolve(process.env.CARGO_TARGET_DIR || join(repository, 'target'));
const binRoot = join(targetRoot, profile);
const outputRoot = resolve(process.env.STREAMSCOPE_PLUGIN_OUTPUT_DIR || join(repository, 'dist', 'official-plugins'));
const bundled = join(repository, 'apps', 'desktop', 'src-tauri', 'binaries');
const staging = mkdtempSync(join(tmpdir(), 'streamscope-official-'));
const plugins = [
  ['plugin-sample', 'streamscope-plugin-sample.exe'],
  ['plugin-onvif', 'streamscope-plugin-onvif.exe'],
  ['plugin-sip', 'streamscope-plugin-sip.exe'],
  ['plugin-h264', 'streamscope-plugin-h264.exe'],
  ['plugin-h265', 'streamscope-plugin-h265.exe'],
  ['plugin-audio', 'streamscope-plugin-audio.exe'],
  ['plugin-rtsp', 'streamscope-plugin-rtsp.exe'],
  ['plugin-pcap', 'streamscope-plugin-pcap.exe'],
  ['plugin-video-deep', 'streamscope-plugin-video-deep.exe'],
];

function run(executable, args) {
  const result = spawnSync(executable, args, { cwd: repository, stdio: 'inherit', shell: false });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${basename(executable)} 失败，退出码 ${result.status}`);
}

function publicKey(keyFile) {
  const seed = Buffer.from(readFileSync(keyFile, 'utf8').trim(), 'base64');
  if (seed.length !== 32) throw new Error('签名私钥必须是 32 字节 seed 的 Base64');
  const privateKey = createPrivateKey({ key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'), seed,
  ]), format: 'der', type: 'pkcs8' });
  return createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32);
}

function copy(source, destination) {
  if (!existsSync(source)) throw new Error(`缺少构建产物：${source}`);
  copyFileSync(source, destination);
}

async function fileSha256(path) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return `sha256:${hash.digest('hex')}`;
}

try {
  if (!process.argv.includes('--skip-build')) {
    run('cargo', ['build', ...(profile === 'release' ? ['--release'] : []),
      '-p', 'streamscope-plugin-host', '-p', 'streamscope-plugin-sample',
      '-p', 'streamscope-plugin-onvif', '-p', 'streamscope-plugin-sip',
      '-p', 'streamscope-plugin-media', '-p', 'streams-sip-engine', '--bins']);
  }
  mkdirSync(outputRoot, { recursive: true });
  const publisherFingerprint = `sha256:${createHash('sha256').update(publicKey(publisherKey)).digest('hex')}`;
  const entries = [];
  for (const [example, executable] of [...plugins, ['plugin-ffmpeg', 'ffmpeg.exe']]) {
    const template = join(repository, 'examples', example, 'manifest-template.json');
    const manifest = JSON.parse(readFileSync(template, 'utf8'));
    const payload = join(staging, example);
    mkdirSync(join(payload, 'bin'), { recursive: true });
    copy(join(repository, 'examples', example, 'ui.json'), join(payload, 'ui.json'));
    if (example === 'plugin-ffmpeg') {
      for (const name of ['ffmpeg', 'ffprobe', 'video-worker']) {
        copy(join(bundled, `${name}-x86_64-pc-windows-msvc.exe`), join(payload, 'bin', `${name}.exe`));
      }
      for (const name of ['avcodec-63.dll', 'avformat-63.dll', 'avutil-61.dll', 'swresample-7.dll', 'swscale-10.dll']) {
        copy(join(bundled, name), join(payload, 'bin', name));
      }
      copy(join(bundled, 'FFmpeg-LICENSE.txt'), join(payload, 'FFmpeg-LICENSE.txt'));
    } else {
      copy(join(binRoot, executable), join(payload, 'bin', executable));
      if (example === 'plugin-sip') {
        copy(join(binRoot, 'streams-sip-engine.exe'), join(payload, 'bin', 'streams-sip-engine.exe'));
      }
    }
    const fileName = `${manifest.id}-${manifest.version}-windows-x86_64.ssp`;
    const packagePath = join(outputRoot, fileName);
    run(join(binRoot, 'plugin-pack.exe'), [template, payload, publisherKey, packagePath]);
    entries.push({
      id: manifest.id, version: manifest.version, packageUrl: `${baseUrl}/${fileName}`,
      packageSha256: await fileSha256(packagePath),
      publisherFingerprint, hostApi: manifest.hostApi, os: 'windows', arch: 'x86_64',
    });
  }
  const catalog = join(outputRoot, 'catalog.json');
  writeFileSync(catalog, `${JSON.stringify({ schemaVersion: 1, generatedAt: new Date().toISOString(), packages: entries }, null, 2)}\n`);
  run(join(binRoot, 'catalog-sign.exe'), [catalog, catalogKey]);
  writeFileSync(join(outputRoot, 'catalog.pub'), publicKey(catalogKey).toString('base64'));
  console.log(`已生成 ${entries.length} 个签名插件、catalog.json/.sig；目录公钥见 ${join(outputRoot, 'catalog.pub')}`);
} finally {
  rmSync(staging, { recursive: true, force: true });
}
