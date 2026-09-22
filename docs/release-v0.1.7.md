# StreamScope v0.1.7

## 中文

### ONVIF 诊断增强

- ONVIF 能力声明缺失、错误或不完整时，不再提前终止诊断；继续验证可安全读取的 Device、Media2、Media、Imaging、Events 和 DeviceIO 接口。
- Media2 与 Media1 独立验证：Media2 失败不会阻止 Media1，便于识别设备只支持旧版媒体服务或单个服务实现异常的情况。
- 服务未返回 XAddr 时，按设备同主机常见路径尝试候选端点，并在证据中明确标记“推断端点”，避免把候选结果误认为设备声明。
- 仅在缺少必要 token 时跳过依赖该 token 的操作，并显示具体跳过原因；其他独立接口继续执行。

### 结论与证据

- 每个接口统一输出五类状态：通过、不支持、回复不合法、失败、未执行。
- 不再将 HTTP 200 直接判定为通过；同时校验 SOAP 1.2 Content-Type、Envelope/Body、预期响应元素、服务命名空间、XML 完整性以及关键字段。
- `GetStreamUri` 增加 URI 字段存在性及 `rtsp://` / `rtsps://` 格式校验。
- 改进 SOAP Fault 解析，保留嵌套错误码与原因；HTTP 404、405、501 归类为“不支持”。
- 汇总所有不支持、回复不合法和未执行的接口，并给出逐接口原因，方便区分协议不兼容、设备未实现与响应格式错误。

### AI 使用边界

- 接口通过/失败结论由确定性协议规则生成，不依赖 AI。
- 后续可将 AI 作为可选的报告解释层，但不得覆盖规则引擎结论，也不得接收明文设备密码。

### 质量验证

- Rust 工作区测试：163 项通过，1 项因需要专用 FFmpeg/libx264 环境而忽略。
- ONVIF 专项测试：13 项全部通过，包含能力声明缺失时继续探测和 404“不支持”分类。
- `cargo fmt`、`cargo clippy -D warnings`、前端生产构建及 Windows NSIS 安装包构建均通过。

### 已知边界

- 当前自动诊断只调用已实现的安全只读接口，不自动执行设备重启、恢复出厂、固件升级、配置写入或 PTZ 移动等有状态操作。
- 推断端点是兼容性探测策略，不代表设备按 ONVIF 响应正式声明了该服务。
- 本工具用于工程诊断，不替代 ONVIF 官方一致性认证。

### 下载

- Windows x64 安装包：`StreamScope_0.1.7_x64-setup.exe`
- SHA-256：`9a8efb4bae8bb14d0590e2f292f805d76bf1e2ba463e9ff766c1a44437013b9e`

---

## English

### ONVIF diagnostics

- Diagnostics no longer stop when capability declarations are missing, incorrect, or incomplete. Safe read-only operations are still tested for Device, Media2, Media, Imaging, Events, and DeviceIO.
- Media2 and Media1 are validated independently, so a Media2 failure does not hide a working Media1 implementation.
- When an XAddr is absent, StreamScope probes common same-host candidate endpoints and explicitly labels them as inferred evidence.
- Only token-dependent operations are skipped when a required token is unavailable; independent operations continue and each skip includes an exact reason.

### Results and evidence

- Every operation is classified as Passed, Not supported, Invalid response, Failed, or Skipped.
- HTTP 200 is no longer sufficient for success. Validation also checks SOAP 1.2 content type, Envelope/Body, the expected response element, service namespace, XML completeness, and required fields.
- `GetStreamUri` validates the URI field and the `rtsp://` or `rtsps://` scheme.
- SOAP Fault parsing preserves nested fault codes and reasons; HTTP 404, 405, and 501 are classified as Not supported.
- Reports summarize every unsupported, invalid, and skipped operation with its individual reason.

### AI boundary

- Pass/fail decisions are deterministic and do not depend on AI.
- AI may later be used as an optional explanation layer, but it must not override protocol-rule results or receive plaintext device passwords.

### Verification

- Rust workspace: 163 tests passed; 1 environment-specific FFmpeg/libx264 test ignored.
- ONVIF module: all 13 tests passed, including missing-capability probing and HTTP 404 classification.
- Rust formatting, Clippy with warnings denied, frontend production build, and the Windows NSIS installer build all passed.

### Known boundaries

- Automated diagnostics currently use implemented safe read-only operations only. Stateful actions such as reboot, factory reset, firmware upgrade, configuration writes, or PTZ movement are not invoked automatically.
- Inferred endpoints are compatibility probes, not proof that the device formally advertised a service.
- StreamScope is an engineering diagnostic tool and does not replace official ONVIF conformance certification.

### Download

- Windows x64 installer: `StreamScope_0.1.7_x64-setup.exe`
- SHA-256: `9a8efb4bae8bb14d0590e2f292f805d76bf1e2ba463e9ff766c1a44437013b9e`
