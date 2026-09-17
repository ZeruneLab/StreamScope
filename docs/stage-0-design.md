# 阶段 0 设计说明

## 范围

阶段 0 只验证“外部 FFmpeg 工具 + 安全编排 + 基础报告”这条链路，不实现自有 RTSP、RTP 或 H.264 解析器，也不创建桌面界面。

## 模块职责

- `streamscope-core`：跨模块数据模型、RTSP URL 校验、密码脱敏。
- `streamscope-ffmpeg`：检查 FFmpeg/ffprobe、执行限时探测和实际解码、归类已知日志证据。
- `streamscope-report`：输出结构化 JSON 和无需外部资源的 HTML。
- `streamscope`：解析命令行参数并编排一次分析任务。

## 数据与安全边界

原始 RTSP URL 只在 CLI 进程内存中用于启动 ffprobe/FFmpeg。报告模型仅接收脱敏后的 URL；子进程错误文本在进入结果前再次替换完整 URL 和密码。阶段 0 不保存抓包或裸流。

FFmpeg 日志属于“证据”，其中的错误类别不会在本阶段被直接提升为根因结论。

## 成功标准

1. 工具存在时可以启动 ffprobe 和 FFmpeg，并有硬超时保护。
2. 结果包含编码、分辨率、帧率、码率、解码状态、帧数和已知错误类别。
3. 无论探测成功或失败，均尽可能生成 `result.json` 与 `report.html`。
4. 单元测试覆盖 URL 脱敏、ffprobe JSON、FFmpeg 日志归类和报告生成。

## 已知限制

- 阶段 0 依赖 FFmpeg 自身的 RTSP 实现，没有独立 RTSP 会话时间线。
- 码率、帧率等字段是否存在取决于服务端和 ffprobe 输出。
- 未提供可访问的 RTSP 地址时，只能验证工具链、测试和失败路径，不能声称完成实机拉流验证。

