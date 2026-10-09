# 官方插件目录发布约定

## v0.2.0 正式目录

已创建独立公开仓库 `ZeruneLab/StreamScope-Plugins`。固定入口为 `https://raw.githubusercontent.com/ZeruneLab/StreamScope-Plugins/main/catalog.json`，签名位于同地址加 `.sig`。包位于该仓库具体批次的 Release；主程序及 `latest.json` 仍在 `ZeruneLab/StreamScope`，不交叉使用最新 Release。

首批正式插件发布者指纹为 `sha256:8f1e1ccefc22442539ee9084cd16835ae4e211008a99a130f4dd1263b465bbbf`。目录和插件使用两个长期 Ed25519 密钥，存于发布机用户 `.tauri` 目录，必须离线备份；只公开 `.pub`，不提交私钥。此前临时预览密钥不再用于官方发布。

发布机可依次运行 `node scripts/prepare-plugin-release.mjs keys`、`plugins`、`core`；`keys` 不覆盖已有身份，`plugins` 构建签名包，`core` 注入目录及公钥、构建并签署核心安装包、生成并核对更新清单。这些命令不安装软件或自动发布。后续批次需修改批次标签并递增有变更的插件版本；合并目录时保留仍支持的旧版本条目，再签署合并后的原始字节，不直接把新批次目录覆盖旧版本历史。

首次正式迁移会拒绝临时预览包的发布者密钥。需要备份后手动卸载旧功能和运行时，再明确确认官方签名安装；没有静默换密钥或修改注册表。线上匿名下载验收结果以本次发布记录为准。

首批使用 `plugins-2026.10.09.1` 固定标签。`node scripts/publish-plugin-release.mjs <包目录> <插件仓库提交SHA>` 验证目录签名及所有包摘要，创建草稿并核对资产齐全后发布；随后在独立仓库一个提交内更新目录和签名。`node scripts/verify-published-plugins.mjs --app` 不携带账号凭据，逐个下载包核对摘要、验证目录签名，再核对主程序更新清单及安装包的 SHA-256/Ed25519 签名。上传失败保持草稿，不指向不完整发布。

## 通用规则与预览阶段记录

目录采用独立 HTTPS 地址，不使用主程序 GitHub `releases/latest`；`catalog.json` 的同目录 `catalog.json.sig` 是对 JSON 原始字节的 Ed25519 签名 Base64。每个条目绑定 `.ssp` 下载 URL、完整包 SHA-256、发布者公钥指纹、版本、平台与 Host API。宿主先验目录签名，再下载并复核包 SHA-256、包签名和条目身份，最后展示原生代码风险供用户确认。

同一 ID/版本可以发布不同平台的包；ID/版本/系统/架构完全相同的重复条目拒绝。签名目录允许未来 Host API 版本，当前宿主仅显示兼容的平台/API 条目。缺失依赖按 SemVer 范围选最高兼容版本，满足范围的已安装包优先复用；多层依赖预检后统一确认，按依赖顺序安装。循环和已选版本冲突会在写注册表前报错。单包失败回滚不会卸载先前已成功安装的依赖，管理页会刷新实际状态。

`examples/plugin-catalog/catalog.example.json` 只有占位 URL/摘要，**不能发布或安装**。正式发布者应在受控环境生成并保存目录签名 seed，不将私钥提交仓库。用 `cargo run -p streamscope-plugin-host --bin catalog-sign -- <catalog.json> <Base64 私钥文件>` 生成 `.sig`。同一目录公钥的 Base64 必须在构建主程序时作为 `STREAMSCOPE_PLUGIN_CATALOG_PUBLIC_KEY` 提供，目录 HTTPS URL 作为 `STREAMSCOPE_PLUGIN_CATALOG_URL` 提供。两者缺一时应用明确显示“官方目录未配置”，仍可离线导入已签名插件。

先上传 `.ssp`，再上传/替换 `catalog.json` 和 `.sig`；可使用静态网站或 GitHub 仓库原始文件地址，但不要让插件发布改变主程序最新 Release。发布前需从匿名网络验证 HTTPS 可访问、签名与摘要一致、目标平台可安装、主程序更新不受影响。当前仓库尚无正式目录地址与受控发布者密钥，因此一键安装流程尚未做线上验收。

Windows x64 官方包可由 `node scripts/build-official-plugins.mjs` 一次生成。运行前分别设置 `STREAMSCOPE_PLUGIN_PUBLISHER_KEY_FILE`（插件发布者 Ed25519 seed 文件）、`STREAMSCOPE_PLUGIN_CATALOG_KEY_FILE`（目录签名 seed 文件）和 `STREAMSCOPE_PLUGIN_BASE_URL`（未来上传 `.ssp` 的 HTTPS 目录）。默认编译 release 二进制并输出到 `dist/official-plugins`；`STREAMSCOPE_PLUGIN_OUTPUT_DIR` 可指定输出目录。两个密钥文件都不得提交或打进安装包。脚本还输出 `catalog.pub`，构建宿主时将其内容设为 `STREAMSCOPE_PLUGIN_CATALOG_PUBLIC_KEY`，并将目录地址 `.../catalog.json` 设为 `STREAMSCOPE_PLUGIN_CATALOG_URL`。先在离线测试环境验证，正式发布前再次确认目录公钥与宿主内置值一致。

离线回归：先编译 debug 插件及 `plugin-pack`/`catalog-sign`/`streams-sip-engine`，再运行 `node scripts/verify-official-plugins.mjs`。脚本使用随机临时密钥，生成十个真实包、验证目录签名和包摘要，再将全部包安装到隔离的临时注册表，执行 H.264/H.265 语法动作及共享运行时 MP3 导出。无论成功或失败，最终清理本次新建的临时目录；不操作当前用户的已安装插件，不作为正式发布。测试同时验证目录的 `sha256:` 摘要与预览纯十六进制摘要之间的规范化确认绑定。
