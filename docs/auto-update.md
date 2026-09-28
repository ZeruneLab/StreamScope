# StreamScope 自动更新发布说明

## 更新通道

客户端固定读取 ZeruneLab/StreamScope 最新正式 Release 中的 `latest.json`：

`https://github.com/ZeruneLab/StreamScope/releases/latest/download/latest.json`

预发布和草稿 Release 不应作为稳定通道发布。客户端只接受 SemVer 高于当前安装版本、平台为 `windows-x86_64` 且签名验证通过的安装包。

安装器使用 `perMachine` 模式，程序安装到系统级目录，同一台 Windows 电脑上的所有用户都可以使用软件并检查、下载更新。检查和下载更新不要求 GitHub 登录；安装或替换系统级程序文件时，Windows 仍可能要求管理员确认（UAC）。

## 签名密钥

- 公钥已写入 `apps/desktop/src-tauri/tauri.conf.json`，可以公开。
- 当前发布者机器上的私钥位于 `C:\Users\lenovo\.tauri\streamscope-updater.key`，不属于仓库文件；发布脚本通过 `--key` 接收路径，不要求其他机器或软件用户使用这个 Windows 账户。
- 私钥当前为无密码密钥，文件 ACL 仅允许发布者账号读取；这只保护发布权限，不限制任何终端用户检查和安装更新。
- 必须把私钥安全备份到离线介质。私钥丢失后，已经安装的客户端将无法验证后续版本。

## 构建

使用 `scripts/build-signed-release.mjs` 构建。脚本先编译应用并把本次构建生成的 `WebView2Loader.dll` 交给 NSIS 安装钩子，再生成安装包，避免独立 target 目录误打包旧 DLL；最后调用 Tauri 签名器读取 `--key` 指定的私钥文件。私钥内容不会出现在命令行或日志中；`--target` 可指定独立构建目录。

成功构建后，NSIS 目录应同时出现：

- `StreamScope_<version>_x64-setup.exe`
- `StreamScope_<version>_x64-setup.exe.sig`

缺少 `.sig` 时禁止发布。

## 生成更新清单

执行 `scripts/generate-update-manifest.mjs`，传入安装包、签名、版本说明和输出路径。脚本会：

1. 校验 Cargo、npm 和 Tauri 三处版本号一致。
2. 校验 SemVer、安装包、签名和说明文件。
3. 生成包含签名实际内容的 `latest.json`。
4. 生成 `SHA256SUMS.txt`。

## 发布

先将与安装包对应的源码和更新说明提交并推送到默认分支，再执行 `scripts/publish-update.mjs`，传入安装包、签名、`latest.json`、更新说明和 `SHA256SUMS.txt`。脚本会先创建 Draft Release，确认四项资产完整后才发布为 Latest Release。不要把新版本标签指向旧版源码提交。

发布资产固定为：

- Windows x64 安装包。
- 对应 `.sig`。
- `latest.json`。
- `SHA256SUMS.txt`。

已经发布的版本号不得覆盖或复用；修复错误更新时发布更高的补丁版本。

发布后用未登录的公开请求验证 `releases/latest/download/latest.json` 返回 JSON，且安装包下载地址可访问。若最新 Release 缺少 `latest.json`，客户端会提示无法获取有效更新清单；只上传安装包不足以启用应用内检查更新。

## 首次迁移

v0.1.8 及更早版本没有更新插件，无法自行发现 v0.1.9。用户需要手动安装一次 v0.1.9；之后版本即可通过软件内更新。
