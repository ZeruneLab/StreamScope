# 阶段 0 完成记录

日期：2026-09-07

## 方案审阅结论

原方案的产品方向和分层方式可行，但“第一版功能范围”包含 RTSP 客户端、RTP/RTCP、H.264 位流、跨层规则引擎、离线抓包和桌面端，实际是多阶段产品范围。当前实现遵循计划末尾的约束，仅完成阶段 0，没有提前引入 GUI 或自研协议栈。

阶段 0 使用四个模块是合适的最小边界；计划中其余 crate 将等到对应阶段出现真实职责时再创建，避免空模块和过早抽象。

## 已完成功能

- Rust workspace、CLI、core、ffmpeg、report 四个模块。
- RTSP/RTSPS URL 校验与密码脱敏。
- ffmpeg、ffprobe 可用性和版本检查。
- TCP/UDP 参数化的 ffprobe 流信息读取。
- 指定时长的 FFmpeg 视频解码与硬超时。
- 编码、Profile、像素格式、分辨率、帧率、码率和解码帧数采集。
- 10 类常见 FFmpeg 解码错误的证据归类。
- 结构化 JSON 与自包含 HTML 报告。
- 单独保存脱敏后的 `ffmpeg.log`，并在 ffprobe 捕获到 SDP 时保存 `session.sdp`。
- 失败时尽可能生成报告；不把 FFmpeg 单条日志直接认定为根因。

## 验证结果

- `cargo fmt --check`：通过。
- `cargo clippy --workspace --all-targets -- -D warnings`：通过。
- `cargo test --workspace`：通过，共 9 个单元测试，0 失败。
- 不可达 RTSP 地址端到端测试：在约 1 秒内完成，状态为 `failed`，成功生成 JSON 和 HTML。
- 脱敏扫描：扫描上述 2 个报告文件，测试密码匹配数为 0。
- Release 构建：见最终验收运行结果。

## 覆盖率

已安装 `cargo-llvm-cov` 和 `llvm-tools-preview` 并实际尝试测量。当前默认工具链为 `stable-x86_64-pc-windows-gnu`，编译器报告缺少 `profiler_builtins`，因此本环境无法产生可信覆盖率数字。没有用“测试通过数”冒充覆盖率。

## 已知限制

- 用户未提供可访问的 RTSP 测试地址，因此尚未验证真实设备的成功探测和成功解码路径。
- 阶段 0 依赖 FFmpeg 的 RTSP 实现，尚不能给出自有 RTSP 会话、RTP 包或 H.264 NALU 级证据。
- 当前仅生成 HTML 和 JSON；原计划中的 PDF 属于后续桌面/报告阶段。

## 下一阶段建议

获得一个可测试的 RTSP 地址后，先补做 TCP、UDP 各一次实机基线并固化脱敏后的预期结果。确认阶段 0 后，再进入阶段 1 的 RTSP 状态机、鉴权、SDP 和 RTP 接收实现。
