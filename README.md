# StreamScope

StreamScope 是面向摄像头、NVR 和嵌入式音视频设备开发者的 RTSP/RTP/H.264/H.265 诊断工具。本目录已实现开发计划的阶段 0～4 和阶段 5 的 MVP 离线分析范围。用户通过独立 Windows 软件界面即可分析实时流或离线文件、查看证据与报告，运行时不调用 PowerShell。

## 当前能力

- 校验 `rtsp://` / `rtsps://` 地址，并在所有输出中隐藏密码。
- 检查本机 `ffmpeg` 和 `ffprobe` 是否可用。
- 支持 RTSP over TCP 或 UDP 的流信息探测。
- 在指定时间内执行视频解码，统计解码帧数并归类常见错误。
- 每次分析生成独立目录，包含 `result.json`、`report.html`、`ffmpeg.log`，并在可提取时保存 `session.sdp`。
- 对网络连接和子进程执行设置超时，避免任务无限挂起。
- Tauri 2 + React Windows 桌面界面，用户运行时无需 PowerShell。
- 软件内查看参数概览、错误证据、FFmpeg 日志和完整 HTML 报告。
- 最近任务只保存脱敏 URL，并可在软件重启后重新打开报告。
- 自有 RTSP 状态机、Basic/Digest 鉴权、SDP 与 Control URI 解析。
- RTP 丢包、连续缺口、乱序、重复、时间戳、SSRC、Payload Type 与 Jitter 统计。
- H.264 Single NAL、STAP-A、FU-A、SPS、PPS、Slice、帧边界、IDR 和 GOP 分析。
- H.265/HEVC Single NAL、AP、FU、VPS、SPS、PPS、Slice、帧边界、IDR、CRA 和 GOP 分析。
- 55 条证据驱动诊断规则，包含音频时间轴、静音、削波、电平突变、声道失衡、立体声反相和高可信音画时钟偏差诊断，输出严重度、置信度、证据、影响、建议和复验方法。
- 统一异常时间线和 ECharts 图形视图。
- 通过软件文件选择器导入 Annex B H.264、Annex B H.265/HEVC、PCAP 或 PCAPNG。
- 对同一 RTSP 地址自动执行 TCP/UDP 对比，并生成独立对比报告。
- RTSP 会话可同时 SETUP 多条 H.264/H.265 视频轨和 PCMA/PCMU/AAC/Opus 音频轨；每条音频轨独立生成分析、预览和导出源，UI 可切换，纯音频会话也可完成分析。
- PCMA/PCMU 可直接解码为 PCM；AAC-hbr 和 Opus 可重组后由 FFmpeg 解码。支持完整解码范围内的逐声道 Peak/RMS、静音、削波、电平突变、声道电平差、立体声相关性、动态范围、频谱滚降、EBU R128 响度轨迹、平均频谱和 48 段 Mel 时频图，并可点击异常区间回听。
- 质量分析和播放预览相互独立：音频质量覆盖完整可解码样本，软件内试听样本最多保留 60 秒，报告会分别标明实际覆盖范围。
- 可直接导入 WAV、FLAC、AAC、M4A、MP3、Ogg 或 Opus 音频文件，独立分析和试听，不要求存在视频轨。
- 回放页可将当前音频轨另存为 WAV、MP3、M4A、FLAC 或 Ogg，也可按诊断区间单独导出；视频预览可另存为 MP4。导出在后台完成，不启动外部播放器或命令窗口。
- RTSP 采集过程中按音频轨实时显示 RTP 包数、负载量、平均码率和滚动 PCM 波形；PCMA/PCMU 直接解码，AAC/Opus 通过内置 FFmpeg 在线解码，均显示真实 Peak/RMS。完整频谱、Mel 时频图、响度和异常区间在采集结束后生成。
- PCAP/PCAPNG 中音频、视频按各自端点、通道和 SSRC 独立分流；有共同 RTCP CNAME 与 Sender Report 时计算音视频时钟偏差和多点漂移。
- ONVIF 设备诊断：支持 WS-Discovery、SOAP 1.2、WS-Addressing、WS-Security UsernameToken、HTTP Digest，以及 Device、Media/Media2、Imaging、Events 基础只读接口；可从 Profile 提取 StreamUri 并转入现有 RTSP/RTP 深度分析。

抓包多流分析：按捕获接口、方向端点、TCP 连接实例、Interleaved Channel 和 SSRC 分组，不限制为两路。每流独立统计序列缺口、时长、码率、H.264/H.265 和解码结果；不同 PT 不直接拆流，编码发生变化时停止混合解包并提示。支持 Ethernet/VLAN、原始 IP、Linux SLL/SLL2、IPv4/IPv6，以及 TCP 分段、乱序和重传重组。

当前限制：不重组 IP 分片；缺帧、截断和 TCP 重组缺口会明确降低证据可信度。未知动态编码仅作为 RTP 候选，只有发现足够的 H.264 或 H.265 参数集与帧证据后才推断编码；H.265 RTP 当前支持 RFC 7798 常见非交织模式，不支持 DONL/DOND 交织模式。MP4A-LATM 仅保留 RTP 证据。软件可依据高可信 RTCP 偏差协调两个预览播放器，并能在深入分析时配对明显闪光与蜂鸣/脉冲事件；普通节目内容没有足够显著事件时会保持“证据不足”，不能把 RTCP 时钟映射解释为内容同步。RTSPS、ONVIF 事件订阅/设备模拟、完整 RTCP Reception Report 统计和 PDF 直出尚未实现。HTML 报告可使用系统打印功能另存为 PDF。

### 多路抓包操作

1. 在桌面软件选择 PCAP/PCAPNG，先扫描所有流，不启动 FFmpeg。
2. 在多流总览搜索、筛选、排序或分页；点击某流查看独立统计与证据。
3. 勾选目标流后执行选中流分析，或执行全部深度分析。FFmpeg 逐流运行，仅分析已确认/有完整参数集证据的 H.264/H.265 样本。
4. 总报告链接到 `streams/stream-xxxx/report.html`，每流保留独立 JSON、日志和可提取的 `sample.h264` 或 `sample.h265`。`rtp-sample.bin` 是含原始包号、捕获时间、RTP 序列/时间戳与负载的内部索引，不是 PCAP 文件。

为控制大抓包资源，最多跟踪 4096 个流阶段、256 个 TCP 连接；每流保留最多 32 MiB/20 万包的负载索引，整次最多 1 GiB，达到样本限额后 RTP 统计继续。异常明细最多保留每流 256 项。触限会提示，不能据局部样本断言整流正常。平均/峰值码率仅计唯一 RTP 负载，峰值采用 1 秒桶；到达时最大序列缺口可能随后被乱序包补齐。旧版混流报告可查看，但需要重新分析原始抓包才能得到分流结果。

## 环境要求

### 安装版用户

- Windows 10/11 64 位系统。
- Microsoft Edge WebView2 Runtime。安装程序会在系统缺少它时联网下载安装；StreamScope 0.1.1 起同时随安装包部署匹配架构的 `WebView2Loader.dll`。
- StreamScope 0.1.2 安装包内置 `ffmpeg.exe` 和 `ffprobe.exe`，优先使用程序目录中的版本，用户无需单独安装或配置 `PATH`。软件不依赖 `ffplay`。
- 对报告目录（默认 `文档/StreamScope/reports/`）具有写入权限。实时 RTSP 分析还需要目标设备网络可达；使用 UDP 时，网络和防火墙需允许对应 UDP 媒体流量。

安装版运行不需要 PowerShell、Python、Rust、Cargo、Node.js 或 npm。详细检查和故障处理见 [`docs/runtime-requirements.md`](docs/runtime-requirements.md)。

### 开发构建

- Rust 1.85 或更高版本（edition 2024）。
- Node.js 与 npm。
- `ffmpeg` 和 `ffprobe` 位于系统 `PATH`。

检查开发环境：

```text
ffmpeg -version
ffprobe -version
cargo --version
node --version
npm --version
```

## 构建与运行

### 直接使用桌面版

已构建的程序位于：

```text
target/release/streamscope-desktop.exe
```

双击该程序即可启动，不需要打开 PowerShell。报告默认保存到：

```text
文档/StreamScope/reports/
```

正式安装包已经包含 `ffmpeg.exe` 和 `ffprobe.exe`。仅直接复制 `target/release/streamscope-desktop.exe` 作为便携版使用时，才需要同时复制这两个程序到主程序目录，或使用系统 `PATH` 中的版本。

### 开发桌面版

```text
cd apps/desktop
npm install
npm run tauri dev
```

生产构建：

```text
npm run build
npm run tauri build -- --no-bundle
```

### 命令行版

在项目根目录执行：

```text
cargo build --workspace
cargo run -p streamscope -- analyze --url "rtsp://admin:password@172.16.54.253/stream1" --transport tcp --duration 10 --output ./reports
cargo run -p streamscope -- analyze --h264 ./stream.h264 --output ./reports
cargo run -p streamscope -- analyze --h265 ./stream.h265 --output ./reports
cargo run -p streamscope -- analyze --audio ./recording.wav --output ./reports
cargo run -p streamscope -- analyze --pcap ./capture.pcapng --output ./reports
cargo run -p streamscope -- analyze --pcap ./capture.pcapng --streams stream-0001,stream-0002 --output ./reports
cargo run -p streamscope -- compare --url "rtsp://admin:password@172.16.54.253/stream1" --duration 30 --output ./reports
```

可选参数：

- `--transport tcp|udp`，默认 `tcp`
- `--duration <秒>`，范围 1～86400，默认 10
- `--connect-timeout <秒>`，范围 1～300，默认 10
- `--output <目录>`，默认 `./reports`

命令执行后会显示脱敏地址和报告路径。即使连接失败，也会尽可能输出一份包含失败证据的报告。

## 验证

```text
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p streamscope-analyzer --test pcap_multistream -- --include-ignored --nocapture
```

设计和边界说明见 [`docs/stage-0-design.md`](docs/stage-0-design.md)，实际完成与验证记录见 [`docs/stage-0-completion.md`](docs/stage-0-completion.md)、[`docs/stage-0.5-completion.md`](docs/stage-0.5-completion.md)、[`docs/stage-3-5-completion.md`](docs/stage-3-5-completion.md) 和 [`docs/audio-quality-completion.md`](docs/audio-quality-completion.md)。
