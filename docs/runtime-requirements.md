# StreamScope 运行环境与故障处理

## 普通用户需要的环境

| 项目 | 是否必须 | 说明 |
| --- | --- | --- |
| Windows 10/11 x64 | 是 | 当前安装包为 64 位 Windows 安装包。 |
| Microsoft Edge WebView2 Runtime | 是 | 用于显示软件界面。安装程序会在缺失时联网下载安装。 |
| `WebView2Loader.dll` | 是 | StreamScope 0.1.1 起由安装程序放到主程序同一目录，用户不需要单独下载。 |
| `ffmpeg.exe`、`ffprobe.exe` | 安装包已内置 | 用于探测、解码、预览和格式导出；0.1.2 起用户无需单独安装或配置 `PATH`。 |
| `ffplay.exe` | 否 | 软件内回放不依赖外部 ffplay 窗口。 |
| PowerShell、Python、Rust、Node.js | 否 | 仅开发或构建源码时可能需要，安装版用户不需要。 |

报告默认写入 `文档/StreamScope/reports/`。实时分析还要求电脑能够访问 RTSP 设备；选择 UDP 传输时，网络和防火墙需要允许协商出的 UDP 端口。

## `WebView2Loader.dll` 缺失报错

旧版 0.1.0 安装包没有把 GNU 目标动态依赖的 `WebView2Loader.dll` 安装到程序目录，因此 Windows 会在软件界面启动前直接报错。该问题不是报告配置或 RTSP 地址导致的。

处理步骤：

1. 关闭正在运行的 StreamScope。
2. 使用 `StreamScope_0.1.2_x64-setup.exe` 覆盖安装；如 Windows 不允许覆盖，再先卸载旧版后安装新版。历史报告位于文档目录，正常卸载不会删除该目录。
3. 如果安装程序提示 WebView2 Runtime 安装失败，联网后重新运行安装包，或从微软官方页面安装 Evergreen WebView2 Runtime。
4. 安装后，程序安装目录中应同时存在 `streamscope-desktop.exe` 和 `WebView2Loader.dll`。不要从第三方 DLL 下载站单独下载文件。

## FFmpeg 检查

正式安装版会优先查找与 `streamscope-desktop.exe` 位于同一目录的 `ffmpeg.exe` 和 `ffprobe.exe`，仅在内置文件不存在时回退到系统 `PATH`。安装目录还包含 FFmpeg 的许可证和发行说明。

仅调试便携版或开发环境时，可在 Windows 命令提示符（cmd）执行：

```text
ffmpeg -version
ffprobe -version
```

两条命令都能显示版本信息，表示开发构建可以从 `PATH` 找到工具。安装版用户不需要执行这一步。

## 开发构建环境

从源码构建还需要 Rust 1.85 或更高版本、Node.js 和 npm；这些都不是安装版运行依赖。
