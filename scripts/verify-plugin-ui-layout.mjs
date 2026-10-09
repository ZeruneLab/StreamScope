// Isolated, headless layout checks; never attaches to the user's browser or desktop.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile, writeFile, mkdir, mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve, extname } from "node:path";

const root = resolve(import.meta.dirname, "..");
const build = join(root, "apps/desktop/dist-core");
const screenshots = join(root, "target/ui-preview");
const ids = ["rtsp", "h264", "h265", "audio", "pcap", "onvif", "sip", "video-deep", "ffmpeg"];
const plugins = [];
const ui = {};
for (const id of ids) {
  const directory = join(root, "examples", `plugin-${id}`);
  const manifest = JSON.parse(await readFile(join(directory, "manifest-template.json"), "utf8"));
  plugins.push({ manifest, enabled: true, fingerprint: "layout-test-only" });
  if (manifest.contributions.length) ui[manifest.id] = JSON.parse(await readFile(join(directory, "ui.json"), "utf8"));
}
// Official main entries use the rich workbench now; keep generic workflow coverage
// with a declarative third-party fixture instead of assuming all entries are generic.
const fixture = structuredClone(plugins.find(plugin => plugin.manifest.id === 'org.streamscope.pcap'));
fixture.manifest.id = 'org.example.pcap';
fixture.manifest.contributions[0].id = 'org.example.pcap.analyze';
fixture.manifest.contributions[0].title = '第三方抓包入口（测试）';
plugins.push(fixture); ui[fixture.manifest.id] = ui['org.streamscope.pcap'];
const mock = `<script>const plugins=${JSON.stringify(plugins)}, ui=${JSON.stringify(ui)};
localStorage.setItem('streamscope.updater.auto-check','false');
window.activePluginPage=()=>document.querySelector('.plugin-page:not([hidden])');
window.workflowCalls=[];
const group=(title,actions)=>({type:'actions',title,actions:actions.map(([id,title,pluginId])=>({id,title,pluginId}))});
window.__TAURI_INTERNALS__={transformCallback:()=>1,invoke:async(command,args)=>{
if(command==='list_plugins')return plugins;
if(['list_plugin_reports','list_legacy_reports','list_analysis_reports'].includes(command))return [];
if(command==='load_plugin_ui')return ui[args.id];
if(command==='plugin:dialog|open')return 'C:\\\\layout-test\\\\sample.'+(args.options?.filters?.[0]?.extensions?.includes('pcap')?'pcap':'h264');
if(command==='prepare_plugin_continuation'){
  const id=args.reference.actionId;
  let pluginId,action,fields;
  if(id.endsWith('-select')){pluginId='org.example.pcap';action='analyze';fields={path:'C:/artifacts/source.pcap',streamIds:id.startsWith('video')?'video':'audio'};}
  else if(id==='video-frame'){pluginId='org.streamscope.video-deep';action='inspect-frame';fields={path:'C:/artifacts/video.h264',displayIndex:'0'};}
  else if(id==='audio-quality'){pluginId='org.streamscope.audio';action='analyze';fields={path:'C:/artifacts/audio.wav'};}
  else if(id==='audio-export'){pluginId='org.streamscope.audio';action='export-audio';fields={path:'C:/artifacts/audio.wav',format:'wav'};}
  else throw new Error('Unexpected continuation');
  const plugin=plugins.find(item=>item.manifest.id===pluginId);
  return {reference:args.reference,pluginId,contributionId:plugin.manifest.contributions.find(item=>item.action===action).id,fields,context:id.startsWith('video')?'video · h264':'audio · pcmu'};
}
if(command==='execute_plugin'){
  window.workflowCalls.push(args);
  if(args.id==='org.example.pcap'){
    const blocks=args.input.streamIds==='video'?[group('video · h264',[['video-frame','视频逐帧深度分析 / QP / 运动矢量','org.streamscope.video-deep']])]:
      args.input.streamIds==='audio'?[group('audio · pcmu',[['audio-quality','音频深度 / 质量分析','org.streamscope.audio'],['audio-export','音频格式 / 区间导出','org.streamscope.audio']])]:
      [group('video · h264',[['video-select','深入分析视频流','org.streamscope.pcap']]),group('audio · pcmu',[['audio-select','深入分析音频流','org.streamscope.pcap']])];
    return {reportId:'pcap-'+(args.input.streamIds||'scan'),result:{summary:args.input.streamIds?'选流结果':'扫描结果',blocks}};
  }
  if(args.id==='org.streamscope.audio')return {reportId:'audio-result',result:{summary:args.action==='export-audio'?'MP3 导出验证':'音频质量验证',blocks:[{type:'text',text:'联动验证'}]}};
  if(args.id!=='org.streamscope.video-deep'||args.action!=='inspect-frame')throw new Error('Unexpected execution in layout test');
  await new Promise(done=>setTimeout(done,300));
  return {reportId:'layout-test-only',result:{summary:'布局验证数据，非真实分析',blocks:[
    {type:'table',title:'逐帧摘要',columns:['帧序号','宽','高','QP 块数','运动矢量'],rows:[[0,640,360,2,1]]},
    {type:'frameOverlay',title:'QP / 运动矢量叠加',width:640,height:360,qp:[[0,0,320,180,22],[320,180,320,180,35]],motionVectors:[[200,100,230,120]]},
    {type:'hex',title:'HEX',bytesHex:'000000016742001e',byteOffset:16,fields:[{name:'nal_unit_type',value:'7'}]}
  ]}};
}
if(command==='plugin:app|version')return '0.1.10';
if(command==='plugin:event|listen')return 1;
if(command==='plugin:event|unlisten')return;
throw new Error('Layout test forbids command: '+command);
}};window.__TAURI_EVENT_PLUGIN_INTERNALS__={unregisterListener:()=>{}};</script>`;
const server = createServer(async (request, response) => {
  try {
    const pathname = new URL(request.url, "http://localhost").pathname;
    const path = resolve(build, `.${pathname === "/" ? "/index.html" : pathname}`);
    if (!path.startsWith(`${build}\\`) && !path.startsWith(`${build}/`)) throw new Error("invalid path");
    const data = await readFile(path);
    const type = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript" }[extname(path)] ?? "application/octet-stream";
    response.setHeader("Content-Type", type);
    response.end(extname(path) === ".html" ? data.toString().replace("<head>", `<head>${mock}`) : data);
  } catch { response.writeHead(404).end(); }
});
await new Promise((done) => server.listen(0, "127.0.0.1", done));
const profile = await mkdtemp(join(tmpdir(), "streamscope-headless-layout-"));
let browser;
let socket;
try {
  browser = spawn(join(process.env["ProgramFiles(x86)"], "Microsoft/Edge/Application/msedge.exe"), [
    "--headless=new", "--no-first-run", "--disable-extensions", "--disable-background-networking",
    `--user-data-dir=${profile}`, "--remote-debugging-port=0", "--remote-debugging-address=127.0.0.1",
    "--window-size=1280,900", "--force-device-scale-factor=1", "about:blank",
  ], { windowsHide: true, stdio: "ignore" });
  let port;
  for (let i = 0; i < 100; i++) {
    try { port = (await readFile(join(profile, "DevToolsActivePort"), "utf8")).split("\n")[0]; break; }
    catch { await new Promise((done) => setTimeout(done, 100)); }
  }
  assert(port, "headless browser did not start");
  const tab = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: "PUT" })).json();
  socket = new WebSocket(tab.webSocketDebuggerUrl);
  await new Promise((done, reject) => { socket.addEventListener("open", done, { once: true }); socket.addEventListener("error", reject, { once: true }); });
  let sequence = 0;
  const pending = new Map();
  socket.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    if (pending.has(message.id)) {
      const { done, reject, timer } = pending.get(message.id);
      clearTimeout(timer); pending.delete(message.id);
      message.error ? reject(new Error(JSON.stringify(message.error))) : done(message.result);
    }
  });
  const call = (method, params = {}) => new Promise((done, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Timeout: ${method}`)); }, 15000);
    pending.set(id, { done, reject, timer }); socket.send(JSON.stringify({ id, method, params }));
  });
  const evaluate = async (expression) => {
    const result = await call("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  };
  await call("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
  await call("Page.navigate", { url: `http://127.0.0.1:${server.address().port}/` });
  await evaluate(`new Promise((done,reject)=>{let count=0;const poll=()=>{if(document.querySelectorAll('.plugin-card').length===10)done(true);else if(++count>100)reject('manager not ready');else setTimeout(poll,50)};poll()})`);
  await mkdir(screenshots, { recursive: true });
  const screenshot = async (name) => {
    const result = await call("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
    await writeFile(join(screenshots, `${name}.png`), Buffer.from(result.data, "base64"));
  };
  await screenshot("plugin-manager");
  await evaluate(`document.querySelectorAll('.nav-item').forEach(button=>{if(button.title==='视频逐帧深度分析（插件）')button.click()})`);
  await evaluate(`new Promise((done,reject)=>{let count=0;const poll=()=>{if(document.querySelector('.plugin-file-picker'))done(true);else if(++count>100)reject('form not ready');else setTimeout(poll,50)};poll()})`);
  const metrics = await evaluate(`(()=>{
    const input=activePluginPage().querySelector('.plugin-file-picker input'), action=activePluginPage().querySelector('.plugin-primary'), nav=document.querySelector('.sidebar nav');
    return {inputHeight:input.getBoundingClientRect().height, buttonHeight:action.getBoundingClientRect().height,
      buttonBackground:getComputedStyle(action).backgroundImage, overflow:document.documentElement.scrollWidth>innerWidth,
      navOverflow:getComputedStyle(nav).overflowY, titles:[...nav.querySelectorAll('.nav-item')].map(node=>node.textContent),
      panels:activePluginPage().querySelectorAll('.plugin-panel').length};
  })()`);
  assert.equal(metrics.inputHeight, 43);
  assert(metrics.buttonHeight >= 43);
  assert(metrics.buttonBackground.includes("linear-gradient"));
  assert.equal(metrics.overflow, false);
  assert.equal(metrics.navOverflow, "auto");
  assert.equal(metrics.panels, 2);
  assert(metrics.titles.every((title) => !title.endsWith("（插件）")));
  await screenshot("video-deep");
  await call("Emulation.setDeviceMetricsOverride", { width: 1000, height: 720, deviceScaleFactor: 1, mobile: false });
  assert.equal(await evaluate("document.documentElement.scrollWidth > innerWidth"), false);
  await screenshot("video-deep-1000");
  await evaluate("activePluginPage().querySelector('.plugin-file-picker button').click()");
  await evaluate(`new Promise((done,reject)=>{let count=0;const poll=()=>{if(document.querySelector('.plugin-file-picker input').value)done(true);else if(++count>100)reject('file not selected');else setTimeout(poll,25)};poll()})`);
  await evaluate("activePluginPage().querySelector('.plugin-primary').click()");
  assert.equal(await evaluate("activePluginPage().querySelector('.plugin-primary').disabled"), true);
  assert.equal(await evaluate("activePluginPage().querySelector('.plugin-field input').disabled"), true);
  await evaluate(`new Promise((done,reject)=>{let count=0;const poll=()=>{if(document.querySelector('.plugin-result table'))done(true);else if(++count>100)reject('result not ready');else setTimeout(poll,25)};poll()})`);
  assert.equal(await evaluate("activePluginPage().querySelector('.plugin-primary').disabled"), false);
  assert.equal(await evaluate("document.documentElement.scrollWidth > innerWidth"), false);
  assert.notEqual(await evaluate("getComputedStyle(document.querySelector('.plugin-result th')).backgroundColor"), "rgba(0, 0, 0, 0)");
  await evaluate("window.scrollTo(0,document.querySelector('.plugin-result').getBoundingClientRect().top+scrollY-100)");
  await screenshot("video-deep-result-1000");
  await evaluate("window.scrollTo(0,0)");
  await call("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
  let checkedViews = 0;
  for (const plugin of plugins) {
    for (const contribution of plugin.manifest.contributions) {
      if (contribution.kind === 'internal' || (plugin.manifest.id.startsWith('org.streamscope.') && ['analyze','diagnose'].includes(contribution.action))) continue;
      const title = contribution.title;
      const view = ui[plugin.manifest.id].views.find((view) => view.id === contribution.view);
      const fieldCount = view.components.filter((component) => ["input", "select"].includes(component.type)).length;
      await evaluate(`document.querySelectorAll('.nav-item').forEach(button=>{if(button.title===${JSON.stringify(title)})button.click()})`);
      await evaluate(`new Promise((done,reject)=>{let count=0;const poll=()=>{
        if(activePluginPage().querySelector('.plugin-meta span')?.textContent===${JSON.stringify(view.title)} && activePluginPage().querySelectorAll('.plugin-field').length===${fieldCount})done(true);
        else if(++count>100)reject('view not ready');else setTimeout(poll,50)};poll()})`);
      assert.equal(await evaluate("document.documentElement.scrollWidth > innerWidth"), false, title);
      assert.equal(await evaluate("activePluginPage().querySelectorAll('[role=alert]').length"), 0, title);
      checkedViews++;
      if (plugin.manifest.id === "org.streamscope.rtsp") await screenshot("rtsp-form");
      if (contribution.action === "export-audio") await screenshot("audio-export-form");
    }
  }
  const waitFor = (expression) => evaluate(`new Promise((done,reject)=>{let count=0;const poll=()=>{if(activePluginPage() && (${expression}))done(true);else if(++count>100)reject('workflow not ready');else setTimeout(poll,25)};poll()})`);
  const clickText = (text) => evaluate(`(()=>{const button=[...activePluginPage().querySelectorAll('button')].find(button=>button.textContent.trim()===${JSON.stringify(text)});if(!button)throw new Error('Missing button');button.click()})()`);
  const navigate = async (id, action) => {
    const contribution = plugins.find(plugin => plugin.manifest.id === id).manifest.contributions.find(item => item.action === action);
    await evaluate(`document.querySelectorAll('.nav-item').forEach(button=>{if(button.title===${JSON.stringify(contribution.title)})button.click()})`);
    await waitFor(`activePluginPage().querySelector('.plugin-meta')`);
  };
  await navigate('org.example.pcap', 'analyze');
  await clickText('选择文件');
  await waitFor(`activePluginPage().querySelector('.plugin-file-picker input').value`);
  await clickText('▶ 开始执行');
  await waitFor(`activePluginPage().querySelector('.plugin-result')?.textContent.includes('扫描结果')`);
  assert.equal(await evaluate("activePluginPage().querySelectorAll('.plugin-workflow-group').length"), 2);
  await clickText('深入分析视频流');
  await waitFor(`activePluginPage().querySelector('.plugin-workflow-source')`);
  assert.equal(await evaluate("activePluginPage().querySelectorAll('.plugin-field input')[1].value"), 'video');
  await clickText('▶ 开始执行');
  await waitFor(`activePluginPage().querySelector('.plugin-result')?.textContent.includes('选流结果')`);
  await clickText('视频逐帧深度分析 / QP / 运动矢量');
  await waitFor(`activePluginPage().querySelector('.plugin-file-picker input')?.value==='C:/artifacts/video.h264' && activePluginPage().querySelector('.plugin-workflow-source') && !activePluginPage().querySelector('.plugin-primary').disabled`);
  await clickText('▶ 开始执行');
  await waitFor(`activePluginPage().querySelector('.plugin-result table') && !activePluginPage().querySelector('.plugin-primary').disabled`);
  assert.equal(await evaluate("workflowCalls.at(-1).continuation.actionId"), 'video-frame');
  assert.equal(await evaluate("workflowCalls.at(-1).input.path.endsWith('.pcap')"), false);
  await clickText('返回来源分析');
  await waitFor(`activePluginPage().querySelector('.plugin-result')?.textContent.includes('选流结果')`);
  await clickText('返回上一份分析结果');
  await waitFor(`activePluginPage().querySelector('.plugin-result')?.textContent.includes('扫描结果')`);
  await clickText('深入分析音频流');
  await waitFor(`activePluginPage().querySelectorAll('.plugin-field input')[1]?.value==='audio'`);
  await clickText('▶ 开始执行');
  await waitFor(`activePluginPage().querySelector('.plugin-result')?.textContent.includes('音频深度')`);
  await clickText('音频深度 / 质量分析');
  await waitFor(`activePluginPage().querySelector('.plugin-file-picker input')?.value==='C:/artifacts/audio.wav' && activePluginPage().querySelector('.plugin-workflow-source') && !activePluginPage().querySelector('.plugin-primary').disabled`);
  await clickText('▶ 开始执行');
  await waitFor(`activePluginPage().querySelector('.plugin-result')?.textContent.includes('音频质量验证')`);
  await clickText('返回来源分析');
  await waitFor(`activePluginPage().querySelector('.plugin-result')?.textContent.includes('音频深度')`);
  await clickText('音频格式 / 区间导出');
  await waitFor(`activePluginPage().querySelector('select')?.value==='wav'`);
  await evaluate(`(()=>{const select=activePluginPage().querySelector('select');Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set.call(select,'mp3');select.dispatchEvent(new Event('change',{bubbles:true}))})()`);
  await clickText('▶ 开始执行');
  await waitFor(`activePluginPage().querySelector('.plugin-result')?.textContent.includes('MP3 导出验证')`);
  assert.equal(await evaluate("workflowCalls.at(-1).input.format"), 'mp3');
  assert.equal(await evaluate("workflowCalls.at(-1).continuation.actionId"), 'audio-export');
  await screenshot('pcap-audio-export-workflow');
  console.log('PCAP 选流→视频深度、音频质量/格式导出、页面切换保留结果与返回扫描结果的交互回归通过（模拟 IPC）。');
  console.log(`插件管理和视频深度分析后台布局验证通过：${JSON.stringify(metrics)}`);
  console.log(`所有 ${checkedViews} 个插件入口的参数渲染和页面宽度检查通过；没有执行设备分析或修改插件安装。`);
  console.log(`截图：${screenshots}`);
} finally {
  socket?.close();
  if (browser && browser.exitCode === null) {
    const exited = new Promise((done) => browser.once("exit", done));
    browser.kill(); await exited;
  }
  await new Promise((done) => server.close(done));
  // Only this test's freshly created browser profile is removed.
  await rm(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}
