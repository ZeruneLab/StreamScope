# StreamScope v0.1.10

本版新增 SIP 抓包诊断与受控模拟，重点是从抓包提取信令步骤，向用户指定的设备执行可核验的测试。原有 RTSP、ONVIF、音视频和 PCAP 分析入口继续保留。

## 新增功能

- SIP 诊断页支持导入 PCAP/PCAPNG，解析明文 UDP/TCP SIP，按 Call-ID 查看消息、事务、Dialog、重传、响应耗时、SDP offer/answer 和媒体端点对应的 RTP 候选证据。
- 可导出完整或脱敏的 SIP JSON，并可将同一抓包转入现有多流媒体分析。
- 独立 SIP Engine 提供 OPTIONS 主动探测，以及需用户显式启动的 OPTIONS 应答、486 忙线、Digest 测试 Registrar 和单向 PCMU 测试音场景。
- 新增“从抓包生成主动 SIP 测试”：选择 Call-ID 与原发起端，预览 OPTIONS、REGISTER 或 INVITE→ACK→BYE 等安全步骤；可调整步骤间隔和预期最终状态，再向明确填写的 UDP 目标执行。逐步展示实际状态、耗时和失败原因，并可导出结果 JSON。

## 安全与分析边界

- 主动场景会生成新的 Call-ID、tag、Via branch、Contact 和目标 URI；不复用抓包中的 Authorization 或 Proxy-Authorization。INVITE 只生成 `a=inactive` SDP，不接收或发送 RTP。
- 抓包中的鉴权步骤、CANCEL 并发流程、对端主动请求、分叉、目标变化、缺少最终响应或不能安全提取发送身份的场景会被拦截，不会盲目发送原始报文。
- SDP/RTP 关联是候选证据，不代表媒体流已经唯一归属于某次呼叫。普通抓包中的 TLS 信令无法直接解密。
- 当前主动抓包场景只支持单目标明文 UDP 信令；尚不支持 Digest 客户端认证、TCP/TLS 主动场景、RTP 发送、并发压力测试或完整 SIPp 语法。

## 验证与安装

- 已通过前端构建、Rust 工作区编译与测试、格式检查和本地 UDP 场景集成测试；其中一个既有测试仍标记为忽略。
- 尚未完成与 `172.16.54.254` 的真实设备互通验收，不能据本地测试认定所有设备兼容。
- Windows x64 安装包为 `StreamScope_0.1.10_x64-setup.exe`。v0.1.9 用户可在应用中检查更新；安装时若需要系统权限，请按 Windows 提示确认。
- 安装包 SHA-256：`eb6f52def6d257666e753cba5d3119afa0da0d51d9b185df1fb3d9d53ef007b1`。Release 同时提供 `.sig`、`latest.json` 和 `SHA256SUMS.txt`。

## English summary

Adds SIP capture diagnostics, a separate SIP test engine, and a bounded capture-derived UDP UAC scenario runner. Active replay regenerates signaling identifiers, never copies captured authentication headers, and uses inactive SDP without RTP reception or transmission. TCP/TLS active replay, client Digest authentication, and load-test scenarios are not included in this release.
