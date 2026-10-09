# 首批官方签名插件 — 配套 StreamScope v0.2.0

## 新增功能

- 发布八个独立功能插件：RTSP、PCAP、H.264、H.265、音频、ONVIF、SIP、视频逐帧深度分析，版本均为 0.2.0。
- 发布一个共享 FFmpeg 运行时包（7.1.1；包版本不代表深度分析 worker 的 FFmpeg 库版本）和一个可选开发示例插件（1.0.0）。
- 所有 `.ssp` 使用固定的正式发布者 Ed25519 密钥签署，通过独立签名目录分发，下载无需 GitHub 登录。
- 原有完整工作台、抓包选流后的音视频深入分析、格式导出、语法/HEX、QP 和报告工具通过宿主与插件联动保留。

## 安装

推荐安装 StreamScope v0.2.0，在“插件管理”→“检查官方插件目录”按需安装。媒体功能需共享运行时，管理器会预检和安排依赖。

离线可下载本批次 `.ssp`，先导入共享 FFmpeg 包，再导入需要的媒体插件。ONVIF、SIP 可独立安装；示例不是必需功能。

正式发布者指纹：`sha256:8f1e1ccefc22442539ee9084cd16835ae4e211008a99a130f4dd1263b465bbbf`。

## 迁移与风险

临时预览签名不自动升级为正式签名。先备份并卸载旧测试功能插件，再卸载它们依赖的旧共享运行时，之后重新确认官方包安装；报告保留。普通后续升级使用同一正式密钥和更高版本。

签名只保证来源及完整性，原生 EXE 不具备系统级沙箱；安装时必须确认权限和风险。版本及测试范围以主程序更新说明和源仓库的验收记录为准，不宣称全面 ONVIF/SIP 合规认证或所有设备互通。

## English summary

First official signed Windows x64 plugin batch for StreamScope v0.2.0. Eight feature plugins, a shared media runtime, and an optional sample are distributed independently from application updates. Preview signing identities require an explicit uninstall/reinstall migration; reports are retained. Native plugins are trusted code, not sandboxed code.
