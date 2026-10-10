// Isolated headless regression of the rich host UI; mocked IPC, not a device test.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile, readdir, mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir, homedir } from 'node:os';
import { join, resolve, extname } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const build = join(root, 'apps/desktop/dist-core');
const reports = join(homedir(), 'Documents/StreamScope/reports');
const bounded = (value) => Array.isArray(value) ? value.slice(0, 200).map(bounded) : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([key, value]) => [key, bounded(value)])) : value;
let video, audio;
for (const name of (await readdir(reports)).sort().reverse()) {
  if (!name.startsWith('report-')) continue;
  let result;
  try { result = bounded(JSON.parse(await readFile(join(reports, name, 'result.json'), 'utf8'))); } catch { continue; }
  for (const stream of [result, ...(result.streams ?? [])]) {
    if (!video && (stream.h264?.deep_analysis?.frames.length || stream.h265?.deep_analysis?.frames.length)) video = stream;
    if (!audio && stream.audio?.quality?.level_series.length) audio = stream;
  }
  if (video && audio) break;
}
assert(video && audio, '需要已保存的逐帧与音频质量报告用于只读 UI 回归');
const identity = (id, codec, media_type) => ({ id, codec, media_type, source:'192.0.2.1:5004',destination:'192.0.2.2:6000',transport:'udp',ssrc:42,channel:null,connection_id:null,interface_id:'test',payload_types:[media_type==='audio'?0:96],channels:media_type==='audio'?1:null,clock_rate:media_type==='audio'?8000:90000,codec_confidence:'fixture',first_packet:1,last_packet:100,first_offset_ms:0,last_offset_ms:1000,sample_truncated:false,events:[] });
video.capture_stream = identity('video-1', video.h264 ? 'h264' : 'h265', 'video');
audio.capture_stream = identity('audio-1', 'pcmu', 'audio');
const run = (result, name) => ({ result,report_directory:`C:/reports/${name}`,reports:{json:`C:/reports/${name}/result.json`,html:`C:/reports/${name}/report.html`,ffmpeg_log:`C:/reports/${name}/ffmpeg.log`,session_sdp:null} });
const pcap = structuredClone(video);
pcap.capture_stream = null; pcap.h264 = null; pcap.h265 = null; pcap.preview_video = null; pcap.preview_audio = null;
pcap.request = { ...pcap.request,source_kind:'pcap',source_path:'C:/fixtures/capture.pcap',source_url:'parity.pcap' };
pcap.streams = [video, audio]; pcap.capture_summary = { total_frames:200,parsed_transport_frames:200,ignored_frames:0,malformed_frames:0,stream_count:2,duration_ms:1000,warnings:[] };
const runs = { pcap:run(pcap,'pcap'),video:run(video,'video'),audio:run(audio,'audio') };
const ids = ['rtsp','h264','h265','audio','pcap','onvif','sip','video-deep','ffmpeg'];
const plugins = [];
const ui = {};
for (const id of ids) {
  const manifest = JSON.parse(await readFile(join(root,`examples/plugin-${id}/manifest-template.json`),'utf8'));
  plugins.push({ manifest, enabled:true, fingerprint:'headless-test-only' });
  ui[manifest.id] = JSON.parse(await readFile(join(root,`examples/plugin-${id}/ui.json`),'utf8'));
}
const image = 'data:image/svg+xml,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="640" height="360"><rect width="640" height="360" fill="#24364a"/></svg>');
const mock = `<script>const runs=${JSON.stringify(runs)},plugins=${JSON.stringify(plugins)},ui=${JSON.stringify(ui)};
localStorage.setItem('streamscope.updater.auto-check','false');window.calls=[];
window.__TAURI_INTERNALS__={transformCallback:()=>1,convertFileSrc:()=>${JSON.stringify(image)},invoke:async(command,args)=>{
 window.calls.push({command,args});
 if(command==='list_plugins')return plugins;
 if(['list_plugin_reports','list_analysis_reports','list_legacy_reports'].includes(command))return [];
 if(command==='load_plugin_ui')return ui[args.id];
 if(command==='plugin:dialog|open')return 'C:/fixtures/capture.pcap';
 if(command==='plugin:dialog|save')return 'C:/exports/evidence.csv';
 if(command==='read_analysis_report')return args.streamId==='audio-1'?runs.audio:args.streamId==='video-1'?runs.video:runs.pcap;
 if(command==='execute_plugin'){
  if(args.id==='org.streamscope.pcap')return {reportId:'fixture',result:{reportDirectory:'C:/reports/pcap'}};
  if(args.id==='org.streamscope.video-deep')return {reportId:'tool',result:{dataArtifactId:args.input.operation,blocks:[{type:'download',artifactId:'csv'}]}};
  if(args.id==='org.streamscope.audio')return {reportId:'audio',result:{blocks:[{type:'download',artifactId:'audio-export'}]}};
  throw new Error('Unexpected plugin '+args.id);
 }
 if(command==='read_plugin_data'){
  if(args.artifactId==='extract_video_frame')return 'frame.png';
  if(args.artifactId==='analyze_video_frame_blocks')return {width:640,height:360,display_index:0,qp:{base:26,blocks:[{x:0,y:0,width:16,height:16,value:33,delta:7}]},motion_vectors:[],block_observations:[],analyzer_version:'test'};
  if(args.artifactId==='load_video_frame_syntax')return {codec:'h264',display_index:0,access_unit_index:1,mapping_precision:'test-only',nalus:[{index:1,type_name:'idr_slice',offset:0,size:8,fields:[],packets:[],hex:'00000000  65 00',hex_truncated:false}],limitations:[]};
  return {};
 }
 if(command==='read_analysis_attachment')return null;
 if(command==='export_plugin_artifact')return args.destinationPath;
 if(command==='load_report_html')return '<html>只读测试报告</html>';
 if(command==='plugin:app|version')return '0.1.10';
 if(command==='plugin:event|listen')return 1;
 if(command==='plugin:event|unlisten')return;
 if(command==='sip_simulator_status')return null;
 throw new Error('Forbidden native business call: '+command);
}};window.__TAURI_EVENT_PLUGIN_INTERNALS__={unregisterListener:()=>{}};</script>`;
const server = createServer(async(request,response)=>{
  try {
    const pathname = new URL(request.url,'http://localhost').pathname;
    const path = resolve(build,`.${pathname==='/'?'/index.html':pathname}`);
    if (!path.startsWith(build+'\\')) throw new Error('invalid path');
    const data = await readFile(path);
    response.setHeader('Content-Type',({'.html':'text/html','.js':'text/javascript','.css':'text/css'})[extname(path)]??'application/octet-stream');
    response.end(extname(path)==='.html'?data.toString().replace('<head>',`<head>${mock}`):data);
  } catch { response.writeHead(404).end(); }
});
await new Promise(done=>server.listen(0,'127.0.0.1',done));
const profile = await mkdtemp(join(tmpdir(),'streamscope-parity-headless-'));
let browser, socket;
try {
  browser=spawn(join(process.env['ProgramFiles(x86)'],'Microsoft/Edge/Application/msedge.exe'),['--headless=new','--no-first-run','--disable-extensions','--disable-background-networking',`--user-data-dir=${profile}`,'--remote-debugging-port=0','--remote-debugging-address=127.0.0.1','--window-size=1280,900','about:blank'],{windowsHide:true,stdio:'ignore'});
  let port;
  for(let i=0;i<100;i++){try{port=(await readFile(join(profile,'DevToolsActivePort'),'utf8')).split('\n')[0];break;}catch{await new Promise(done=>setTimeout(done,100));}}
  assert(port);
  const tab=await(await fetch(`http://127.0.0.1:${port}/json/new?about:blank`,{method:'PUT'})).json();
  socket=new WebSocket(tab.webSocketDebuggerUrl);await new Promise(done=>socket.addEventListener('open',done,{once:true}));
  let sequence=0;const pending=new Map();
  socket.addEventListener('message',event=>{const message=JSON.parse(event.data);if(pending.has(message.id)){const{done,reject,timer}=pending.get(message.id);clearTimeout(timer);pending.delete(message.id);message.error?reject(new Error(JSON.stringify(message.error))):done(message.result);}});
  const call=(method,params={})=>new Promise((done,reject)=>{const id=++sequence;const timer=setTimeout(()=>{pending.delete(id);reject(new Error('Timeout '+method));},15000);pending.set(id,{done,reject,timer});socket.send(JSON.stringify({id,method,params}));});
  const evaluate=async(expression)=>{const result=await call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(result.exceptionDetails)throw new Error(JSON.stringify(result.exceptionDetails));return result.result.value;};
  const wait=expression=>evaluate(`new Promise((done,reject)=>{let n=0;const poll=()=>{if(${expression})done(true);else if(++n>150)reject('not ready: '+${JSON.stringify(expression)});else setTimeout(poll,40)};poll()})`);
  const click=(selector,text)=>evaluate(`(()=>{const button=[...document.querySelectorAll(${JSON.stringify(selector)})].find(b=>b.textContent.trim().endsWith(${JSON.stringify(text)}));if(!button)throw new Error('missing '+${JSON.stringify(text)});button.click()})()`);
  await call('Page.navigate',{url:`http://127.0.0.1:${server.address().port}/`});
  await wait(`document.querySelectorAll('.plugin-card').length===9`);
  await wait(`[...document.querySelectorAll('.nav-item')].some(b=>b.textContent.includes('PCAP / PCAPNG'))`);
  await click('.nav-item','PCAP / PCAPNG');await click('.analysis-form button','选择文件');
  await wait(`document.querySelector('.file-picker code')?.textContent.includes('capture.pcap')`);
  await evaluate(`document.querySelector('.analysis-form').requestSubmit()`);
  await wait(`document.querySelector('.capture-table')`);
  assert.equal(await evaluate(`document.querySelectorAll('.capture-table tbody tr').length`),2);
  await click('.capture-stream-link','video-1');await click('.tabs button','视频深度分析');
  await wait(`document.querySelector('.exact-frame-viewer')`);
  await click('.exact-frame-viewer button','加载第 0 帧');await wait(`document.querySelector('.video-block-canvas img')`);
  await click('.exact-frame-viewer button','加载 QP / 运动矢量');await wait(`document.querySelector('.block-layer-controls')`);
  assert.equal(await evaluate(`document.querySelectorAll('.video-block-canvas svg rect').length>0`),true);
  await click('.exact-frame-viewer button','加载语法树 / HEX');await wait(`document.querySelector('.syntax-hex')`);
  await click('.syntax-hex button','放大显示');assert.equal(await evaluate(`!!document.querySelector('.hex-expanded')`),true);
  await click('.exact-frame-viewer button','导出块数据 CSV');await wait(`window.calls.some(c=>c.command==='export_plugin_artifact')`);
  await mkdir(join(root,'target/ui-parity'),{recursive:true});
  const screenshot=await call('Page.captureScreenshot',{format:'png'});await writeFile(join(root,'target/ui-parity/video-workbench.png'),Buffer.from(screenshot.data,'base64'));
  await click('.capture-selection button',`← 所有媒体流（2）`);await click('.capture-stream-link','audio-1');
  await click('.tabs button','音频质量');await wait(`document.querySelector('.audio-quality-view')`);
  assert.equal(await evaluate(`document.body.textContent.includes('Mel')`),true);
  assert.equal(await evaluate(`document.querySelectorAll('input[type=search]').length>0`),true);
  const audioScreen=await call('Page.captureScreenshot',{format:'png'});await writeFile(join(root,'target/ui-parity/audio-workbench.png'),Buffer.from(audioScreen.data,'base64'));
  await click('.tabs button','报告预览');await wait(`document.querySelector('iframe')?.srcdoc.includes('只读测试报告')`);
  await click('.nav-item','ONVIF 诊断');assert.equal(await evaluate(`document.body.textContent.includes('ONVIF 设备连接')`),true);
  await click('.nav-item','SIP 诊断');assert.equal(await evaluate(`document.body.textContent.includes('实时 SIP 探测')`),true);
  assert.equal(await evaluate(`document.documentElement.scrollWidth>innerWidth`),false);
  console.log('完整工作台 UI 回归通过：多流选择、视频帧→QP 叠加、语法/HEX 放大、CSV 导出、音频图表/搜索、报告、ONVIF 与 SIP。IPC 为测试桩；不操作用户桌面。');
} finally {
  if(socket?.readyState===WebSocket.OPEN)socket.send(JSON.stringify({id:0,method:'Browser.close'}));
  socket?.close();
  if(browser && browser.exitCode===null){
    const exited=new Promise(done=>browser.once('exit',done));
    const forceExit=setTimeout(()=>browser.kill(),5000);
    await exited;clearTimeout(forceExit);
  }
  server.closeAllConnections();
  await new Promise(done=>server.close(done));
  await rm(profile,{recursive:true,force:true,maxRetries:10,retryDelay:100}).catch(error=>console.warn(`测试浏览器临时目录暂被占用，保留于 ${profile}: ${error.code}`));
}
