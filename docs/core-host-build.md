# 核心宿主独立构建

当前版本已准备为 v0.2.0 正式核心交付，公开插件目录、长期签名和主程序更新构建由 `scripts/prepare-plugin-release.mjs` 提供。下文 0.1.10 包、摘要及未发布事项为历史预览记录，最新发布范围见 `docs/release-v0.2.0.md` 和 `docs/plugin-catalog.md`。

核心宿主预览版已经可以独立构建及打包。仓库版本仍为 `0.1.10`；此包用于插件迁移验收，不作为正式 `v0.2.0` 发布，也不会自动安装或覆盖本机软件。

## 构建边界

桌面与 CLI 的旧分析器依赖均放入 `compat` Cargo feature。默认命令仍构建现有兼容版；核心构建关闭该 feature。核心桌面仅注册插件管理、执行、产物解析及只读报告命令；核心 CLI 仅提供 `plugin list/run`。核心依赖树不包含 analyzer、RTSP、SIP、ONVIF、音视频分析 crate。业务插件仍共用原有解析代码，避免重新实现协议。

`vite --mode core` 选择 `CoreApp.tsx`，输出到 `dist-core`；旧界面继续输出到 `dist`。核心侧栏只列出插件管理、历史报告和已启用插件的贡献入口。任务运行时阻止切换入口及安装主程序更新。

`tauri.core.conf.json` 清空固定 sidecar 与资源列表。关闭 `compat` 时，Rust 构建脚本跳过 FFmpeg、video-worker 和 SIP Engine 的准备，并验证配置确实使用核心前端及空执行器列表。核心包保留主程序和 Windows 必需的 WebView2Loader；FFmpeg 由插件运行时包提供。

## 命令

在项目根目录运行：

```text
node scripts/core-host.mjs check
node scripts/core-host.mjs test
node scripts/core-host.mjs tree
node scripts/core-host.mjs build
node scripts/core-host.mjs package
node scripts/verify-core-host.mjs
```

核心构建输出固定在 `target/core-host`，不会替换旧版 `target/release` 或 `target-release` 二进制。安装器钩子从核心输出目录取 WebView2Loader。`package` 当前生成未作更新签名的 NSIS 验收包；正式发布仍需发布签名、更新清单及官方目录配置。

`tree` 检查桌面与 CLI 不带入旧分析依赖。`verify-core-host` 使用本机 7-Zip 解包安装器，核对主程序和 WebView2Loader，排除其他应用负载，检查前端没有静态分析命令，并打印安装包 SHA-256。解包只在新建的临时目录进行，结束后删除该临时目录。7-Zip 不在默认安装位置时可设置 `STREAMSCOPE_7ZIP_EXE`。

核心 CLI 可用：

```text
cargo run -p streamscope --no-default-features --offline -- plugin list
```

设置 `STREAMSCOPE_CLI_EXE` 为核心 CLI 绝对路径，再运行 `cargo test -p streamscope-plugin-sample --test install_flow --offline`，会追加真实 CLI 的注册表读取、执行、产物保存及禁用拒绝验证；测试使用临时 `LOCALAPPDATA`，不会操作当前用户的插件安装目录。

## 已完成的验收（更新至 2026-10-09）

- 核心与兼容版前端构建通过。
- 核心及兼容版 Rust 检查通过；兼容版桌面包含旧功能与核心报告/导出共 9 项测试通过。
- 核心只读报告测试通过，原始 JSON/HTML 内容保持不变，越界读取被拒绝；TCP/UDP 对比分别显示状态。
- 核心 CLI 只暴露插件命令，签名示例包的真实 CLI 测试通过。
- 核心安装器生成并通过解包核验，只有主程序、WebView2Loader 及安装器组件，没有 FFmpeg/ffprobe/video-worker/SIP Engine。
- 宿主语法树、HEX 字号、畸形结果容错和多层依赖安装排序的后台渲染/逻辑验证通过；没有控制桌面。
- 音频五种格式经独立插件进程转码，并由 ffprobe 验证编解码格式；另存产物的内容及目录保护测试通过。
- 签名目录支持多平台与未来 API 条目；SemVer 选择、共享依赖冲突与循环预检、防止依赖升级破坏已安装插件的测试通过。
- H.264/H.265 的 `inspect-nalus` 独立进程动作可显示语法树、HEX 和绝对字节偏移，结果存入 v2 报告；共用原有解析器，范围最多 50 个 NALU/8 MiB。共享分析器 12 项回归通过。
- 十个真实签名包经临时密钥打包、目录验签、隔离注册表安装和独立进程执行通过；修复了目录摘要前缀与安装预览摘要之间的确认绑定差异。ONVIF 13 项、SIP 16 项协议回归通过。

当前验收包：`target/core-host/release/bundle/nsis/StreamScope_0.1.10_x64-setup.exe`（6,341,906 字节，包含插件 UI 样式与媒体联动修复，Host API 1.2）。本次 SHA-256：`9bbb5bb1b61a244ca4a701f2cb81093df11b6fd74be93551fc2778f73e119e2b`。后续重新构建可能改变摘要，应重新运行核验脚本；此包未作主程序更新签名、未发布。

2026-10-09 联动回归：真实 9 路抓包经过已安装签名插件的独立进程，完成指定视频→逐帧/QP→语法、指定音频→质量→MP3 导出；14 个入口和跨页结果保留的无头交互回归通过。详情见 `docs/plugin-workflow-regression.md`。用户关闭程序后，联动修复版已安装到原目录 `C:\Program Files\StreamScope`，主程序 SHA-256 `36179956d89b84fc5244eed1487e1cdf229de1d35a709d8a163bb4159673a78d`，与本次 NSIS 构建及 WebView2Loader 校验匹配。旧程序备份在 `%LOCALAPPDATA%\StreamScope\installation-backups\compat-0.1.10-1791511006051`；已有插件无需重新导入，报告保留。

本轮核心调试测试缓存曾导致磁盘空间不足，已清理本轮新建的 `target/core-host/debug`（可重建缓存），随后兼容版测试和核心打包均通过。源码、报告、已安装插件及现有安装版未删除。

## 发布前仍需完成

受控官方插件目录公钥与 HTTPS 地址、正式签名包和匿名下载验收；生产设备/各类旧抓包以及所有交互操作的等价回归；视频完整 Slice 语法、逐帧/RTP 自动关联及旧页面迁移中尚缺的交互（基础 NALU 语法树/HEX 组件和动作已完成）；最终 `v0.2.0` 版本和主程序更新验收。核心预览安装包与兼容版使用同一产品身份，当前不要把两者同时作为同一版本的 Release 资产发布。
