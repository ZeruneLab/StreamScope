// Uses a delivery's signed packages in an isolated registry, never the installed app.
import { spawn } from 'node:child_process';
import { resolve, join } from 'node:path';
import { access } from 'node:fs/promises';
const root = resolve(import.meta.dirname, '..');
const packages = resolve(process.argv[2] ?? 'missing-packages');
await access(join(packages, 'catalog.json'));
async function run(executable, args, env = {}) {
  await new Promise((done, reject) => {
    const child = spawn(executable, args, { cwd: root, stdio: 'inherit', windowsHide: true, env: { ...process.env, ...env } });
    child.on('error', reject);
    child.on('exit', code => code === 0 ? done() : reject(new Error(`回归失败：${code}`)));
  });
}
await run('cargo', ['test','-p','streamscope-plugin-host','--test','official_bundles','--offline','--','--nocapture'], { STREAMSCOPE_TEST_PLUGIN_PACKAGES: packages });
await run(process.execPath, [join(root,'scripts/verify-plugin-workflows.mjs'), process.argv[3] || '-', join(packages,'isolated-registry')]);
console.log('交付签名包安装、共享运行时与真实多路抓包工作流回归通过；本机软件未替换。');
