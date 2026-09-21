# StreamScope v0.1.6

[中文](#中文) | [English](#english)

## 中文

### 新增功能

- 新增 ONVIF 设备诊断工作台，支持手动输入设备服务地址、局域网设备发现、账号认证、服务能力查询和逐项诊断结果查看。
- 新增 WS-Discovery 2005/04 IPv4 多播发现，发送标准 `NetworkVideoTransmitter` Probe，并解析、去重 ProbeMatch 结果。
- 新增 SOAP 1.2、WS-Addressing 2005/08 和 WS-Security UsernameToken 1.0 PasswordDigest 请求链路；凭据不会以明文密码写入 SOAP 报文。
- 新增 HTTP Digest 认证重试，支持 MD5、MD5-sess 和 `qop=auth`。
- 新增 Device 服务诊断：GetSystemDateAndTime、GetDeviceInformation、GetServices、GetCapabilities、GetScopes 和 GetNetworkInterfaces。
- 新增 Media 1 / Media 2 诊断：GetProfiles 和 GetStreamUri，优先使用 Media2，缺失时回退 Media 1。
- 新增 Imaging、Events 和 DeviceIO 基础只读诊断：GetImagingSettings、GetOptions、GetEventProperties 和 GetServiceCapabilities。
- 新增 ONVIF Profile 与 StreamUri 展示，可一键把选定 RTSP 地址转入现有 RTSP → SDP → RTP/RTCP → H.264/H.265/音频分析链。

### 体验与诊断改进

- 每个 ONVIF 操作分别展示服务、操作名、端点、HTTP 状态、耗时、成功/失败状态和 SOAP Fault，便于定位服务发现、鉴权或设备实现问题。
- 自动比较设备 UTC 时间与本机时间；偏差超过阈值时生成分级诊断，并提示检查 NTP、时区和夏令时。
- HTTPS 默认校验证书；用户可显式允许当前设备的自签名证书，不会在默认状态下静默忽略证书错误。
- ONVIF 模块只负责发现、协商和会话关联，复用 StreamScope 已有 RTSP、SDP、RTP/RTCP 和音视频分析能力，避免重复媒体协议栈。
- 版本统一升级到 `0.1.6`。

### 质量验证

- 通过 156 项工作区与专项回归测试；另有 1 项需要专用 FFmpeg/libx264 环境的集成测试保持忽略。
- 通过 Rust 格式检查、严格 Clippy（warnings as errors）、前端 TypeScript/Vite 生产构建和 Windows NSIS 安装包构建。
- 新增 6 项 ONVIF 协议单元测试，覆盖标准 Probe、地址规范化、ProbeMatch、服务/Profile 解析、HTTP Digest 和 UsernameToken PasswordDigest。

### 已知限制

- 当前版本提供 ONVIF 设备发现与基础只读诊断，不包含事件订阅、PTZ、配置写入、固件升级或 ONVIF 设备模拟器。
- “符合标准”表示请求命名空间、SOAPAction、报文结构和字段解析以 ONVIF 官方规范/WSDL 为依据；本版本未取得 ONVIF 官方认证，正式合规声明仍需使用 ONVIF Client Test Tool / Device Test Tool 验证。
- StreamUri 获取成功只证明设备返回了媒体入口，不代表媒体链路正常；需要继续执行 RTSP/RTP 深度分析才能形成音视频结论。

### 下载与校验

- Windows x64 安装包：`StreamScope_0.1.6_x64-setup.exe`
- SHA-256：`83cb4a8bdd8025bb2fdbb8b453e6d6e2b1b1cd80907cc96d015ba864f883daaf`

## English

### New Features

- Added an ONVIF device diagnostics workspace with manual Device Service input, LAN discovery, authentication, service capability inspection, and per-operation results.
- Added WS-Discovery 2005/04 IPv4 multicast discovery with a standard `NetworkVideoTransmitter` Probe and deduplicated ProbeMatch parsing.
- Added SOAP 1.2, WS-Addressing 2005/08, and WS-Security UsernameToken 1.0 PasswordDigest requests without placing plaintext passwords in SOAP messages.
- Added HTTP Digest authentication retries with MD5, MD5-sess, and `qop=auth` support.
- Added Device Service diagnostics for GetSystemDateAndTime, GetDeviceInformation, GetServices, GetCapabilities, GetScopes, and GetNetworkInterfaces.
- Added Media 1 / Media 2 diagnostics for GetProfiles and GetStreamUri, preferring Media2 and falling back to Media 1 when needed.
- Added basic read-only Imaging, Events, and DeviceIO diagnostics: GetImagingSettings, GetOptions, GetEventProperties, and GetServiceCapabilities.
- Added ONVIF profile and StreamUri views with one-click handoff to the existing RTSP → SDP → RTP/RTCP → H.264/H.265/audio analysis pipeline.

### Diagnostics and UX Improvements

- Each ONVIF operation now records its service, operation, endpoint, HTTP status, elapsed time, outcome, and SOAP Fault evidence.
- Device UTC is compared with the local clock, producing severity-aware findings and NTP/time-zone/daylight-saving guidance when the offset is excessive.
- HTTPS certificates are validated by default; accepting a device self-signed certificate requires an explicit user choice.
- ONVIF is limited to discovery, negotiation, and session association while reusing StreamScope's existing RTSP, SDP, RTP/RTCP, and media analyzers.
- Bumped all package versions to `0.1.6`.

### Quality Verification

- Passed 156 workspace and focused regression tests; one dedicated FFmpeg/libx264 integration test remains ignored outside its required environment.
- Passed Rust formatting, strict Clippy with warnings denied, the TypeScript/Vite production build, and the Windows NSIS packaging build.
- Added six ONVIF protocol unit tests covering the standard Probe, endpoint normalization, ProbeMatch parsing, service/profile parsing, HTTP Digest, and UsernameToken PasswordDigest.

### Known Limitations

- This release provides ONVIF discovery and basic read-only diagnostics. Event subscriptions, PTZ, configuration writes, firmware updates, and an ONVIF device simulator are not included.
- “Standards-based” means namespaces, SOAP actions, request structures, and response fields follow the official ONVIF specifications/WSDLs. This release is not ONVIF-certified; a formal compliance claim still requires the ONVIF Client Test Tool / Device Test Tool.
- A returned StreamUri proves only that the device exposed a media endpoint. Run the RTSP/RTP deep analysis before drawing conclusions about media health.

### Download and Checksum

- Windows x64 installer: `StreamScope_0.1.6_x64-setup.exe`
- SHA-256: `83cb4a8bdd8025bb2fdbb8b453e6d6e2b1b1cd80907cc96d015ba864f883daaf`
