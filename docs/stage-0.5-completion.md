# 阶段 0.5 桌面版完成记录

日期：2026-09-07

## 目标

在不提前实现阶段 1 协议栈的前提下，为阶段 0 分析能力提供独立 Windows UI。终端命令只用于开发和自动验证，最终用户通过桌面软件完成操作。

## 已完成功能

- Tauri 2 + React + TypeScript 桌面应用。
- RTSP 地址、TCP/UDP、分析时长和连接超时配置。
- 后台执行分析，耗时操作不阻塞 UI 线程。
- 编码、Profile、像素格式、分辨率、帧率、码率和解码帧数概览。
- 执行错误与 FFmpeg 证据分类展示。
- 软件内沙箱预览生成的 HTML 报告。
- 软件内查看脱敏 FFmpeg 日志。
- 最近任务使用本地存储，只保存脱敏 URL 和报告路径。
- 点击最近任务可以安全地重新载入 `Documents/StreamScope/reports` 下的报告。
- 独立应用图标和 Windows Release EXE。

## 架构调整

新增 `streamscope-analyzer` 共享编排库。CLI 和桌面端都调用此库，避免复制 ffprobe、FFmpeg、脱敏和报告生成逻辑。桌面端只负责参数收集、后台任务调用和结果呈现。

桌面 UI 通过 Tauri command 直接调用 Rust，不启动 PowerShell、CMD 或脚本。外部进程只包含分析所需的 `ffprobe.exe` 和 `ffmpeg.exe`。

## 实际验证

- `npm install`：成功，npm 审计 0 个漏洞。
- `npm run build`：成功，TypeScript 和 Vite 生产构建通过。
- `cargo fmt --check`：通过。
- `cargo clippy --workspace --all-targets -- -D warnings`：通过。
- `cargo test --workspace`：通过，共 11 个单元测试，0 失败。
- `tauri build --no-bundle`：通过。
- Release EXE：成功生成并启动。
- 运行时窗口标题：`StreamScope · 智能码流诊断`。
- WebView2：实际创建 1 个直接子进程。
- 不可达 RTSP 失败路径：生成 `result.json`、`report.html`、`ffmpeg.log`。
- 脱敏扫描：测试密码匹配数为 0。
- 前端视觉检查：连接配置、导航、运行按钮和结果空状态均正确渲染。

## 交付物

```text
target/release/streamscope-desktop.exe
```

## 已知限制

- 尚未提供真实 RTSP 测试地址，因此成功拉流的 UI 结果页仍需实机验证。
- 当前 EXE 从系统 `PATH` 查找 FFmpeg/ffprobe，尚未将二进制打包进安装包。
- NSIS 安装器依赖在本环境中连续两次下载超时，因此本次交付为直接可运行 EXE，不声称安装包已生成。
- 暂不支持取消正在运行的 FFmpeg 子进程；已有硬超时避免无限挂起。
- 原生 Windows 自动化 RPC 未配置，未取得原生窗口截图；已通过同源前端视觉检查、Release 进程启动和 WebView2 子进程三项验证。

## 下一步

1. 使用可访问的 RTSP 地址完成 TCP、UDP 成功路径实测。
2. 将固定版本 FFmpeg/ffprobe 作为随应用分发的工具，消除外部环境依赖。
3. 网络条件允许时生成 NSIS 安装包。
4. 用户确认阶段 0.5 后进入阶段 1。

