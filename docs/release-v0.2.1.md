# StreamScope v0.2.1 — 插件批量安装与管理体验优化

## 新增功能

- 官方插件目录支持多选、全选可安装项和批量下载安装，单项安装入口继续保留。
- 将所选插件及其依赖合并为一张安装图，共享依赖只处理一次；直接勾选的依赖也纳入同一计划，按依赖顺序安装。
- 安装前统一展示每个包的发布者、公钥指纹、SHA-256、权限和原生代码风险，用户勾选信任后再执行安装。
- 新增逐项处理结果和总体项目进度，显示下载并校验、待确认、安装、完成、失败及跳过原因，失败项可重新勾选重试。

## 体验优化

- 官方目录改为整齐的响应式列表，显示中文名称、功能用途、本机/远端版本和安装状态，区分功能插件、共享运行时及示例插件。
- 已安装插件使用统一卡片展示，发布者与完整签名指纹可展开查看，减少页面信息堆叠。
- 安全确认使用页面内的可滚动详情区，不再为官方安装弹出冗长的浏览器确认文本；保留清晰的信任勾选和取消操作。
- 安装成功的项目自动从可重试选择中排除；已有且满足要求的共享运行时直接复用。

## 问题修复

- 官方包安装的解压、校验和写入操作移至后台线程，保留状态锁、任务空闲检查、单包原子切换及失败回滚。
- 安装依赖失败时跳过依赖它的插件，其他独立项目继续处理；已成功安装的项目保留，不宣称整批事务回滚。
- 取消安全确认或确认前离开插件管理页时不执行安装，并清理已准备的临时下载包。
- 修复后台 UI 验证脚本的浏览器退出和连接清理，避免清理阶段掩盖断言失败。

## 升级说明与安全边界

- 本次仅更新 Windows x64 核心宿主。官方业务插件仍使用独立插件仓库中的现有版本，不需要全部重新下载。
- 升级保留已有插件、任务和报告；进入“插件管理”→“检查官方插件目录”即可使用批量操作。
- 本机此前安装的 v0.2.0 本地修订版已经包含本次主要功能；v0.2.1 将其作为正式版本提供签名更新。
- 不修改发布者密钥迁移策略。临时签名测试插件升级为正式签名时仍会被拦截，不会因为批量操作绕过签名、哈希或权限检查。
- 原生插件以当前 Windows 用户权限运行，没有系统级沙箱；签名证明来源和完整性，不证明代码安全。
- 此版本的后台线程调整针对插件安装，不代表此前“检查软件更新后整窗无响应”的反馈已完成专项定位和修复。若仍遇到该问题，可从本 Release 手动下载安装包。
- 程序安装到 Program Files 时可能需要 Windows UAC 管理员确认。

## 验证范围

- TypeScript 检查、核心前端构建与核心宿主编译通过。
- 单项/批量安装图验证覆盖共享依赖去重、已选依赖复用、循环及版本冲突。
- 隔离后台浏览器验证覆盖多选/全选、统一信任确认、取消/离开清理、冲突零写入、依赖失败隔离、失败重试、运行时复用、单项安装及密钥变更拦截。
- 原完整工作台交互回归覆盖 PCAP 多流选择、帧→QP、语法/HEX 放大、CSV 导出、音频图表/搜索、报告、ONVIF 和 SIP；1280 / 1000 像素宽度未发现横向溢出。
- 核心报告保护 4 项、插件宿主单元测试 24 项及示例插件包校验通过。
- UI 交互测试使用模拟 IPC，不等于本版本重新完成了真实设备、全部编码及在线下载的端到端认证。没有修改无关媒体分析算法或设备配置。

## 下载与校验

- Windows x64 安装包：`StreamScope_0.2.1_x64-setup.exe`（6,789,401 字节），SHA-256：`c4104e8936cadfd18348c243af98c4530a7e97ad4500a5c882aed951a54fa736`。
- 同时提供安装包更新签名 `.sig`、应用自动更新清单 `latest.json` 和安装包 SHA-256 校验文件 `SHA256SUMS.txt`。
- 插件目录仍位于独立公开仓库 `ZeruneLab/StreamScope-Plugins`，不会因本次主程序发布改变插件版本。

## English summary

This release adds multi-select and batch installation to the official plugin directory, deduplicates shared dependencies, and requests a single explicit trust confirmation before installation. The plugin manager now shows readable names, descriptions, local/remote versions, per-item progress and failure reasons. Independent items can proceed when another installation fails; dependent items are skipped. Existing analysis workflows, plugins and reports are preserved. Publisher-key migration and the separately reported application update-check freeze are not resolved by this release.
