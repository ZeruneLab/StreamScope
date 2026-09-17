# 阶段 3～5 实施记录

## 完成范围

- 阶段 3：统一诊断事件模型、32 条规则目录、证据驱动规则评估、跨层时间线、完整 JSON/HTML 诊断段落、URL 密码脱敏。
- 阶段 4：Tauri 2 Windows UI、实时阶段进度、总览/协议/码流/诊断/时间线/报告/日志页面、ECharts 时间线、磁盘报告历史、报告目录快捷入口。
- 阶段 5（MVP 范围）：Annex B H.264 导入、PCAP/PCAPNG 导入、UDP RTP/RTCP 与 TCP Interleaved 提取、`sample.h264` 生成及 FFmpeg 二次验证。

## 核心设计

- 所有协议、码流和规则逻辑位于独立 Rust crate，GUI 与 CLI 复用同一实现。
- 诊断规则没有写在界面中；没有足够证据的规则不会触发。
- FFmpeg 错误只作为关联证据，规则结论使用较低置信度，避免把单条日志当成根因。
- 报告目录是历史任务的事实来源；桌面端启动时扫描有效 `result.json`，无浏览器缓存依赖。
- 离线抓包解析执行长度、块边界、链路类型和文件大小检查。

## 已知限制

- 阶段 5 是增强阶段且原计划的 MVP 边界明确排除 H.265 和完整 ONVIF，因此本轮没有实现这两项。
- PCAP 当前只支持 Ethernet/IPv4；不执行完整 TCP 流重组，乱序或重传严重的 TCP 抓包可能只能得到部分 H.264 数据。
- RTCP 已识别 SR/RR/SDES/BYE 并统计数量，尚未输出所有 Reception Report 字段。
- 时间线保留真实可得的 RTSP 耗时、RTP序号/时间戳和 H.264 异常；无法从现有 FFmpeg 文本中可靠恢复的精确时间不会被编造。
- Windows NSIS 安装器仍依赖 Tauri 构建阶段下载 NSIS 工具；网络不可用时可直接使用 release EXE。

## 验证标准

交付前执行：

```text
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run build
```

测试结果必须以最后一次实际命令输出为准，不以本文件代替验证。

## 2026-09-07 实际验证结果

- `cargo fmt --check`：通过。
- `cargo clippy --workspace --all-targets -- -D warnings`：通过，零警告。
- `cargo test --workspace`：39 个 Rust 测试全部通过（含单元、集成和文档测试目标）。
- `npm run build`：通过，620 个前端模块完成生产构建；ECharts 使用按需异步分块。
- H.264 冒烟测试：生成 320×240、10 fps、1 秒 Annex B 样本；识别 13 个 NALU、10 帧、1 个 IDR、1 个 SPS，FFmpeg 实际解码成功。
- Windows release：`streamscope-desktop.exe` 编译成功并完成启动检查，窗口标题正确且进程响应正常。
- NSIS 安装器：应用编译成功后，Tauri 下载 NSIS 3.11 时出现全局网络超时，因此本次没有产出安装器文件；不影响便携 EXE。
