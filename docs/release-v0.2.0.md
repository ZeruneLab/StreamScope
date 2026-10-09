# StreamScope v0.2.0 — 核心宿主与按需插件

## 新增功能

- 改为核心宿主 + 独立进程插件。RTSP、PCAP、H.264、H.265、音频、ONVIF、SIP 和视频深度分析按需安装，FFmpeg 由媒体插件共享，不需要用户另行安装。
- 插件管理支持签名 `.ssp` 导入、启停、卸载、依赖检查和官方签名目录安装；公开目录及插件包不要求登录 GitHub。
- 通过独立公开仓库 `ZeruneLab/StreamScope-Plugins` 发布插件，主程序与插件分别检查更新。核心安装包不再携带媒体和 SIP 执行器。
- 交付插件清单 Schema、Host API/管道协议规范、示例插件及 AI 开发提示模板。

## 体验优化

- 保留原完整分析工作台与侧栏风格，已启用插件决定功能入口，不再用简化页面替代原有结果。
- 恢复 PCAP 多流搜索、筛选、选流、深入分析和同结果中的视频/音频联动；无需手工把抓包文件交给裸视频分析器。
- 保留音视频回放、质量图表、异常区间检索、时间线、协议证据、报告预览、打印和格式/区间导出。
- 历史报告只读兼容，缺少原插件时仍能查看基础报告，卸载插件默认不删除报告。

## 问题修复

- 将完整分析结果及大视频块/语法数据放入带 SHA-256 的文件产物，避免插件摘要截断或管道大小限制导致数据缺失。
- 恢复精确帧、QP/运动矢量、内部块 CSV、NALU↔RTP 语法证据、HEX 放大和参考视频对比；验证先加载帧再加载 QP 的交互。
- 修复只读任务样本再次使用时的导入冲突；样本被篡改仍拒绝使用。
- 大 SIP 报告和脱敏导出通过文件引用传递，不通过逐消息 JSON 管道发送。
- 核心安装包保留并校验 WebView2Loader，防止缺少 DLL 无法启动。

## 安装和迁移须知

- 首次安装核心不自动安装全部功能。进入“插件管理”→“检查官方插件目录”，选择所需功能，确认权限后安装；依赖包按需安装。
- 从旧完整版升级会保留报告，但原有功能需选择安装对应插件。这是安装方式变化，不是移除联合分析能力。
- 本地测试版 0.1.10/0.1.11 插件使用临时密钥，不能自动信任正式发布者。请先备份插件目录，卸载测试功能插件，再卸载被它们依赖的测试 FFmpeg 包；随后从官方目录重新确认并安装。卸载不删除报告。不要手工修改注册表或已签名包。
- `.ssp` 签名保证来源与完整性，不保证代码安全。原生插件以当前 Windows 用户权限运行，没有系统级沙箱。
- 应用自动更新验证 Tauri 签名；安装到 Program Files 时可能出现 Windows UAC 提示。

## 验证范围与已知边界

- 本批正式 release 插件包的隔离安装/执行验证通过（74.28 秒），真实九路抓包联动回归通过（54.60 秒）；核心报告保护 4 项、插件宿主 24 项及媒体/SIP 单元和进程协议回归通过。
- Windows x64 核心安装包为 `StreamScope_0.2.0_x64-setup.exe`（6,781,403 字节），SHA-256：`950dd1de056f9f198e1adee512a145a701febc109582c4d6e79e20813a99fd5d`。主程序 Release 同时提供 `.sig`、`latest.json` 和 `SHA256SUMS.txt`。
- 已有回归覆盖九路真实抓包的扫描、指定视频流的精确帧/QP/语法/RTP 映射/CSV，以及 PCMU 音频质量和 MP3 导出；UI 回归在后台隔离浏览器进行，不控制用户桌面。
- SIP 支持抓包诊断、主动探测和受控的对设备场景，核心界面不提供接收型模拟器；不是完整 SIPp 压测或完整 SIP 协议栈替代品。
- 本轮恢复不等于所有设备、编码、浏览器播放组合和长时间采集已完成生产级互通认证。详细范围见 `docs/plugin-legacy-feature-parity.md`。
- 当前官方包面向 Windows x64；长期产物垃圾回收仍属于后续工作。

## English summary

StreamScope now ships as a small core host with signed, independently installed native plugins and a shared FFmpeg runtime. The full existing analysis workbench, multi-stream PCAP workflows, media diagnostics, report history, and cross-plugin deep-analysis actions are preserved. Plugins are published separately from application releases. Preview signing keys are not trusted automatically; native plugins are not OS-sandboxed. Device interoperability remains subject to the documented regression scope.
