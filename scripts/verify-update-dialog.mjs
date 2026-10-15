// Run after npm run build:core. Never controls the installed app or performs updates.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile, writeFile, mkdir, mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { join, resolve, extname } from 'node:path';
import { tmpdir } from 'node:os';

const root = resolve(import.meta.dirname, '..');
const build = resolve(root, 'apps/desktop/dist-core');
const output = join(root, 'target/ui-preview/update-dialog');
const plugins = [], ui = {};
for (const id of ['rtsp','h264','h265','audio','pcap','onvif','sip','video-deep','ffmpeg']) {
  const directory = join(root, `examples/plugin-${id}`);
  const manifest = JSON.parse(await readFile(join(directory, 'manifest-template.json'), 'utf8'));
  plugins.push({manifest, enabled:true, fingerprint:'diagnostic-fixture-only'});
  if (manifest.contributions.length) ui[manifest.id] = JSON.parse(await readFile(join(directory,'ui.json'),'utf8'));
}
const { version } = JSON.parse(await readFile(join(root, 'apps/desktop/package.json'), 'utf8'));
const notes = await readFile(join(root, `docs/release-v${version}.md`), 'utf8');
const mock = `<script>
localStorage.setItem('streamscope.updater.auto-check','false');
window.diagnosticCalls=[];window.diagnosticBeats=0;setInterval(()=>diagnosticBeats++,50);
const fixturePlugins=${JSON.stringify(plugins)},fixtureUi=${JSON.stringify(ui)};
window.__TAURI_INTERNALS__={transformCallback:()=>1,invoke:async(command,args)=>{
diagnosticCalls.push(command);
if(command==='list_plugins')return fixturePlugins;
if(['list_plugin_reports','list_legacy_reports','list_analysis_reports'].includes(command))return [];
if(command==='load_plugin_ui')return fixtureUi[args.id];
if(command==='sip_simulator_status')return null;
if(command==='plugin:app|version')return '0.2.0';
if(command==='plugin:event|listen')return 1;
if(command==='plugin:event|unlisten')return;
if(command==='plugin:updater|check')return {rid:1,currentVersion:'0.2.0',version:${JSON.stringify(version)},date:'2026-10-10T11:55:12Z',body:${JSON.stringify(notes)},rawJson:{}};
throw new Error('Diagnostic forbids command: '+command);
}};window.__TAURI_EVENT_PLUGIN_INTERNALS__={unregisterListener:()=>{}};
</script>`;
const server = createServer(async (request,response)=>{
  try {
    const pathname = new URL(request.url,'http://localhost').pathname;
    const path = resolve(build, '.'+(pathname==='/'?'/index.html':pathname));
    if(!path.startsWith(build+'\\'))throw new Error('Invalid path');
    const bytes=await readFile(path);
    response.setHeader('Content-Type', {'.html':'text/html; charset=utf-8','.css':'text/css','.js':'text/javascript'}[extname(path)]??'application/octet-stream');
    response.end(extname(path)==='.html'?bytes.toString().replace('<head>','<head>'+mock):bytes);
  } catch { response.writeHead(404).end(); }
});
await new Promise(done=>server.listen(0,'127.0.0.1',done));
const profile=await mkdtemp(join(tmpdir(),'streamscope-update-dialog-test-'));
let browser,socket;
try {
  browser=spawn(join(process.env['ProgramFiles(x86)'],'Microsoft/Edge/Application/msedge.exe'),[
    '--headless=new','--no-first-run','--disable-extensions','--disable-background-networking',
    '--remote-debugging-port=0','--remote-debugging-address=127.0.0.1',`--user-data-dir=${profile}`,'about:blank',
  ],{windowsHide:true,stdio:'ignore'});
  let port;
  for(let i=0;i<100;i++){try{port=(await readFile(join(profile,'DevToolsActivePort'),'utf8')).split('\n')[0];break;}catch{await new Promise(done=>setTimeout(done,100));}}
  assert(port);
  const tab=await(await fetch(`http://127.0.0.1:${port}/json/new?about:blank`,{method:'PUT'})).json();
  socket=new WebSocket(tab.webSocketDebuggerUrl);
  await new Promise((done,reject)=>{socket.addEventListener('open',done,{once:true});socket.addEventListener('error',reject,{once:true});});
  let sequence=0;const pending=new Map();
  socket.addEventListener('message',event=>{const message=JSON.parse(event.data);if(pending.has(message.id)){const item=pending.get(message.id);clearTimeout(item.timer);pending.delete(message.id);message.error?item.reject(new Error(JSON.stringify(message.error))):item.done(message.result);}});
  const call=(method,params={})=>new Promise((done,reject)=>{const id=++sequence;const timer=setTimeout(()=>{pending.delete(id);reject(new Error(method+' timed out'));},15000);pending.set(id,{done,reject,timer});socket.send(JSON.stringify({id,method,params}));});
  const evaluate=async expression=>{const result=await call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(result.exceptionDetails)throw new Error(JSON.stringify(result.exceptionDetails));return result.result.value;};
  const waitFor=expression=>evaluate(`new Promise((done,reject)=>{let n=0;const poll=()=>{if(${expression})done(true);else if(++n>200)reject('UI not ready: '+${JSON.stringify(expression)});else setTimeout(poll,50)};poll()})`);
  await call('Emulation.setDeviceMetricsOverride',{width:1280,height:820,deviceScaleFactor:1,mobile:false});
  await call('Page.navigate',{url:`http://127.0.0.1:${server.address().port}/`});
  await waitFor(`document.querySelectorAll('.plugin-card').length===9`);
  const routes=await evaluate(`[...document.querySelectorAll('.nav-item')].map((button,index)=>({index,title:button.title||button.textContent.trim()}))`);
  assert.equal(routes.length,16,'all nine main pages and seven official auxiliary entries must be present');
  console.log('Routes: '+JSON.stringify(routes));
  await mkdir(output,{recursive:true});
  const inspect=`(()=>{
    const overlay=document.querySelector('.update-overlay');
    const targets=[document.querySelector('.update-dialog-heading > button'),...document.querySelectorAll('.update-actions button')];
    const controls=targets.map(button=>{const r=button.getBoundingClientRect(),hit=document.elementFromPoint(r.x+r.width/2,r.y+r.height/2);return {label:button.getAttribute('aria-label')||button.textContent.trim(),receivesPointer:hit===button||button.contains(hit),hit:hit?.tagName,hitClass:typeof hit?.className==='string'?hit.className:'',y:Math.round(r.y)};});
    const r=overlay.getBoundingClientRect();return {controls,beats:diagnosticBeats,overlayRect:{x:r.x,y:r.y,width:r.width,height:r.height},overlayInsideSidebar:!!overlay.closest('.sidebar'),workspaceTransform:getComputedStyle(document.querySelector('.workspace')).transform};
  })()`;
  const results=[];
  for(const [width,height] of [[1280,820],[1000,720]]){
    await call('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});
    for(const route of routes){
      assert.equal(await evaluate(`!!document.querySelector('.update-overlay')`),false,'previous update dialog must be closed');
      await evaluate(`document.querySelectorAll('.nav-item')[${route.index}].click();window.scrollTo(0,0)`);
      await waitFor(`document.querySelectorAll('.nav-item')[${route.index}].classList.contains('active')`);
      if(route.index>=9)await waitFor(`document.querySelector('.plugin-page:not([hidden]) .plugin-meta')`);
      await evaluate(`document.querySelector('.updater-footer > button').click()`);
      await waitFor(`document.querySelector('.update-overlay')`);
      await evaluate('new Promise(done=>setTimeout(done,100))');
      const before=await evaluate(inspect);
      assert(before.controls.every(control=>control.receivesPointer),`${route.title} at ${width}x${height}: update controls covered: ${JSON.stringify(before.controls)}`);
      assert.equal(before.overlayInsideSidebar,false,'global update dialog must escape the fixed sidebar stacking context');
      assert.equal(before.overlayRect.x,0);assert.equal(before.overlayRect.y,0);
      assert.equal(before.overlayRect.height,height);
      assert.equal(await evaluate(`(()=>{const r=document.querySelector('.sidebar .brand').getBoundingClientRect();return !!document.elementFromPoint(r.x+r.width/2,r.y+r.height/2)?.closest('.update-overlay')})()`),true,'overlay must block background sidebar');
      const heartbeat=before.beats;
      await evaluate('new Promise(done=>setTimeout(done,100))');
      assert((await evaluate('diagnosticBeats'))>heartbeat,'renderer heartbeat stopped');
      const entry={title:route.title,width,height,controls:before.controls};
      results.push(entry);console.log(JSON.stringify(entry));
      if(width===1280 && [5,6,7,8,15].includes(route.index)){
        const shot=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});
        await writeFile(join(output,`route-${route.index}.png`),Buffer.from(shot.data,'base64'));
      }
      const point=await evaluate(`(()=>{const r=document.querySelector('.update-dialog-heading > button').getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()`);
      await call('Input.dispatchMouseEvent',{type:'mousePressed',button:'left',clickCount:1,...point});
      await call('Input.dispatchMouseEvent',{type:'mouseReleased',button:'left',clickCount:1,...point});
      await waitFor(`!document.querySelector('.update-overlay')`);
    }
  }
  const calls=await evaluate('diagnosticCalls');
  assert.equal(calls.filter(command=>command==='plugin:updater|check').length,1,'available update must reopen without checking again');
  assert(!calls.some(command=>/download|install|execute_plugin/.test(command)),'fixture must never download, install or execute analysis');
  await writeFile(join(output,'results.json'),JSON.stringify({scope:'actual compiled frontend; mocked updater/read-only IPC, not device or real update-install certification',results,calls},null,2));
  console.log(`更新弹窗回归通过：${routes.length} 个入口 × 2 种窗口尺寸；关闭、跳过、暂不更新、下载按钮均未被覆盖，真实指针关闭成功，渲染心跳正常。未执行实际更新或设备分析。证据：${output}`);
}finally{
  if(socket?.readyState===WebSocket.OPEN)socket.send(JSON.stringify({id:0,method:'Browser.close'}));socket?.close();
  if(browser&&browser.exitCode===null){const exited=new Promise(done=>browser.once('exit',done));const timer=setTimeout(()=>browser.kill(),5000);await exited;clearTimeout(timer);}
  server.closeAllConnections();await new Promise(done=>server.close(done));
  await rm(profile,{recursive:true,force:true,maxRetries:10,retryDelay:100}).catch(error=>console.warn(`Diagnostic profile retained: ${profile} ${error.code}`));
}
