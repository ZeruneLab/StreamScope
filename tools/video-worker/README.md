# StreamScope video-worker

`video-worker` 是 StreamScope 的隔离软件解码进程。发布构建固定使用 FFmpeg 9.0.1，并通过本目录补丁导出解码器已经确定的块级证据；损坏输入或解码器异常不会直接拖垮桌面 UI。

当前输出：

- H.264：公共 `AVVideoEncParams` QP、公共 `AVMotionVector`，以及补丁导出的实际 `mb_type`、宏块分区模式、四个 8×8 区域的实际子宏块模式、L0/L1 参考列表索引和解码当时解析出的参考 POC。
- 输出协议：`streamscope.video-worker.v4`；应用读取端仍兼容 v1 的单一参考 POC、v2 的旧块记录和 v3。
- H.265：单独的最小 CB QP 网格，以及解码器解析得到的实际 CTU、叶子 CU、实际 PU 和有变换语法的叶子 TU；包括 PredMode、PartMode、树深度、MV/参考索引/参考 POC 和 TU 的 Y/Cb/Cr CBF 位。worker 不再把重复的最小 CB/PU 兼容网格写入 `block_observations`，并省略各层不适用的空字段；真实 1080p Tiles I 帧结果由约 66 MB 降至约 17 MB，QP 与实际树记录未抽样。
- 所有数据都带帧号、坐标、尺寸和分析器版本；没有取得的字段输出 `null` 或空数组，不以 0 代替未知值。

边界：H.264 参考索引仍是 Slice 参考列表中的局部索引；worker 会同步输出解码该宏块时解析出的逐 8×8 参考 POC。当前已导出宏块/子宏块的实际分区形状，但还没有逐变换块和残差系数语法树。H.265 会导出实际叶子 CU/PU，以及解析过变换语法的叶子 TU；无残差和 PCM 块不会伪造 TU，且当前不导出残差系数值。

## 可复现构建

1. 获取官方 FFmpeg 9.0.1 源码包：`https://ffmpeg.org/releases/ffmpeg-9.0.1.tar.xz`。
2. 解压到一次性构建目录。
3. 在 Git Bash/MinGW 环境执行：

   `tools/video-worker/build-patched-ffmpeg.sh <源码目录> <构建目录> <安装目录>`

脚本会在尚未打补丁时应用 `ffmpeg-9.0.1-streamscope.patch`，以固定选项生成静态库。桌面端 `build.rs` 优先使用 `target/tool-cache/ffmpeg-9.0.1-streamscope-install` 编译 worker；没有该目录时才回退到公共 shared 开发包，回退构建不会声称拥有补丁字段。

## 许可与分发

FFmpeg 及补丁部分继续适用 FFmpeg 上游许可。发布时必须同时保留 FFmpeg 许可证、对应的 9.0.1 源码获取方式、本补丁、构建脚本和构建选项；不能只分发 worker 二进制。项目没有复制 VideoEye、H.264 Analysis 或 Elecard 的源码/二进制。
