# 示例业务插件

源码：`crates/plugin-sample`。此插件只验证宿主协议，不代替任何现有分析功能。

1. `cargo build -p streamscope-plugin-sample --release`
2. 在本目录建立 `payload/bin/`，复制编译出的 `streamscope-plugin-sample.exe` 到其中，并复制 `ui.json` 到 `payload/ui.json`。
3. 用可信随机源生成仅保存在发布者本机的 32 字节签名 seed，Base64 编码保存为独立文件。例如 OpenSSL：`openssl rand -base64 32`，将输出保存到受保护的文件。不要将私钥提交到仓库。
4. `cargo run -p streamscope-plugin-host --bin plugin-pack -- examples/plugin-sample/manifest-template.json examples/plugin-sample/payload <私钥文件> <输出.ssp>`。打包器填入公钥指纹及文件哈希、签名，并再验证完整包。
5. 在插件管理页导入 `.ssp`，核对公钥指纹与来源，再点“示例检查”。

此模板的发布者 ID 仅作演示，第三方发布请替换为自己的反向域名 ID、密钥与许可证。未经签名的目录不是可安装插件。
