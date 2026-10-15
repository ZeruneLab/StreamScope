# StreamScope v0.2.2 — 修复更新弹窗遮挡与页面“假卡死”

## 问题修复

- 修复更新提示打开后，背景变暗但分析内容仍盖在弹窗上，导致关闭、跳过此版本、暂不更新及下载更新按钮不可见或无法点击的问题。
- 更新弹窗通过 React Portal 挂载到页面根层，不再受固定侧栏和分析工作区 transform 形成的层叠上下文限制。
- 修复适用于 RTSP、H.264、H.265、音频、PCAP、ONVIF、SIP、插件管理、历史报告，以及语法/HEX、音频导出、设备发现、SIP 模拟和视频深度分析辅助入口。

## 回归验证

- 新增独立的更新弹窗回归脚本 `scripts/verify-update-dialog.mjs`；修复前可复现按钮被工作区覆盖的失败，修复后要求所有控件可被指针命中。
- 在隔离后台浏览器中覆盖 16 个入口，分别以 1280×820 和 1000×720 窗口尺寸验证，共 32 组状态。
- 验证关闭、跳过、暂不更新及下载按钮不被遮挡，使用真实指针事件关闭弹窗，并检查渲染心跳及已有更新提示的重复打开。
- UI 验证使用模拟更新响应，不连接设备，不执行下载安装，也不等于全部真实网络及安装场景的端到端认证。
- TypeScript 检查、核心前端构建及核心报告保护 4 项测试通过；原完整工作台及插件批量安装交互回归通过。
- 安装包解包核对通过，仅包含核心主程序、WebView2Loader 与安装器组件；核心桌面和 CLI 的依赖树未引入旧媒体业务模块。

## 升级说明与范围

- 本次仅更新 Windows x64 核心宿主，不重新发布业务插件；保留已安装插件、任务和历史报告。
- 不修改媒体分析算法、抓包解析、插件签名策略或设备配置；插件批量安装功能继续保留。
- 此次修复的是已复现的更新弹窗层级错误，不宣称排除了网络等待、大报告渲染或后台任务引起的其他真正卡顿。
- 旧版本如果被更新弹窗遮挡而无法操作，可直接下载本 Release 安装包覆盖安装。安装到 Program Files 时可能需要 Windows UAC 管理员确认。
- 同时提供安装包 `.exe`、更新签名 `.sig`、自动更新清单 `latest.json` 和 `SHA256SUMS.txt` 校验文件。

## 下载与校验

- Windows x64 安装包：`StreamScope_0.2.2_x64-setup.exe`，6,788,273 字节。
- SHA-256：`021b92f52f7f84f2cf93d97f460cdfbcafda525e70ea4e6987cfe230548134ff`。
- 官方业务插件仍从独立仓库 `ZeruneLab/StreamScope-Plugins` 安装和更新，不需要因本次修复全部重装。

## English summary

Fixes the application update dialog being covered by analysis pages, which could make the application appear frozen and hide or block update controls. The shared dialog now renders through a React Portal outside the fixed sidebar stacking context. An isolated mocked-IPC regression covers all 16 official navigation entries at two window sizes. Existing plugins, reports and media analysis remain unchanged. This release addresses the reproduced overlay issue, not every possible network or analysis performance problem.
