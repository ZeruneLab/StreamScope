# FFmpeg 共享运行时包模板

此模板尚未发布正式签名包。准备 `payload/bin/ffmpeg.exe`、`payload/bin/ffprobe.exe`、`payload/FFmpeg-LICENSE.txt`、`payload/FFmpeg-README.txt` 后用 `plugin-pack` 签名。当前仓库可从 `apps/desktop/src-tauri/binaries` 取得 FFmpeg 7.1.1 的 Windows x64 构建和随附许可文件；复制时选择单一目标架构版本并重命名为模板中的文件名。先核实重分发义务，再由官方发布者签名。

宿主已支持安装 `runtime` 类型包和校验获取包内文件，但现有分析器还未改用它；不能移除旧安装包内的 FFmpeg。完成所有媒体插件迁移后，再切换为按需安装并删去主程序 `externalBin` 项。
