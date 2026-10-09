import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import { createReadStream, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repository = resolve(fileURLToPath(new URL('..', import.meta.url)));
const root = mkdtempSync(join(tmpdir(), 'streamscope-plugin-verify-'));
const publisherKey = join(root, 'publisher.key');
const catalogKey = join(root, 'catalog.key');
const output = join(root, 'packages');
async function fileSha256(path) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return `sha256:${hash.digest('hex')}`;
}
writeFileSync(publisherKey, randomBytes(32).toString('base64'));
writeFileSync(catalogKey, randomBytes(32).toString('base64'));
try {
  const result = spawnSync(process.execPath, [join(repository, 'scripts', 'build-official-plugins.mjs'), '--skip-build'], {
    cwd: repository, stdio: 'inherit', env: {
      ...process.env,
      STREAMSCOPE_PLUGIN_PUBLISHER_KEY_FILE: publisherKey,
      STREAMSCOPE_PLUGIN_CATALOG_KEY_FILE: catalogKey,
      STREAMSCOPE_PLUGIN_BASE_URL: 'https://example.test/streamscope-plugins',
      STREAMSCOPE_PLUGIN_OUTPUT_DIR: output,
      STREAMSCOPE_PLUGIN_PROFILE: 'debug',
    },
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`打包脚本失败：${result.status}`);
  const catalogBytes = readFileSync(join(output, 'catalog.json'));
  const catalog = JSON.parse(catalogBytes.toString('utf8'));
  if (catalog.packages.length !== 10 || readdirSync(output).filter((name) => name.endsWith('.ssp')).length !== 10) {
    throw new Error('官方插件包数量不完整');
  }
  const publicKey = createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(readFileSync(join(output, 'catalog.pub'), 'utf8'), 'base64')]),
    format: 'der', type: 'spki',
  });
  if (!verify(null, catalogBytes, publicKey, Buffer.from(readFileSync(join(output, 'catalog.json.sig'), 'utf8'), 'base64'))) {
    throw new Error('官方目录签名验证失败');
  }
  for (const entry of catalog.packages) {
    const filename = new URL(entry.packageUrl).pathname.split('/').pop();
    const digest = await fileSha256(join(output, filename));
    if (digest !== entry.packageSha256) throw new Error(`${entry.id} 包摘要不一致`);
  }
  const installed = spawnSync('cargo', ['test', '-p', 'streamscope-plugin-host', '--test', 'official_bundles', '--offline'], {
    cwd: repository, stdio: 'inherit', env: { ...process.env, STREAMSCOPE_TEST_PLUGIN_PACKAGES: output },
  });
  if (installed.error) throw installed.error;
  if (installed.status !== 0) throw new Error(`真实签名包安装/执行回归失败：${installed.status}`);
  console.log('十个插件包、目录签名及包摘要均已验证（临时测试密钥；未发布）。');
  console.log('十个真实包已安装至临时注册表；语法树动作与共享运行时 MP3 导出通过，未修改本机已安装插件。');
} finally {
  rmSync(root, { recursive: true, force: true });
}
