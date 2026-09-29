# SIP 模块实施状态

## 已实现

- `streamscope-sip`：SIP/2.0 请求与响应解析；UDP 消息和 TCP 字节流分帧；按 `Content-Length` 的字节数读取 SDP 正文。支持重复/紧凑头字段与折叠头行，单条消息上限 1 MiB。
- 复用 `streamscope-capture` 的 PCAP/PCAPNG、网络层和 TCP 重组读取，不再实现第二套抓包解析；复用 `streamscope-sdp` 的 SDP 解析和 `streamscope-rtp` 的 RTP 包解析。
- 根据 Call-ID、Via branch、CSeq 和 From/To tag 汇总消息、事务、Dialog 与呼叫；Dialog 单独显示 INVITE 2xx、ACK、BYE 与 BYE 2xx 的抓包证据。显示响应状态、重传、缺头、CSeq 方法不一致和 SDP 解析错误。401/407 标为认证挑战，不直接算设备故障。
- 提取 SDP 会话/媒体级 `c=` 地址、`m=` 端口、PT 和编码映射。以目的地址、端口和 PT 寻找抓包中的 RTP **候选**包；端点被多个呼叫复用时明确标记归属不可靠。
- SDP 媒体候选显示 RTP 首末抓包号和抓包时间，便于回查原始证据；这是整段抓包中的端点/PT 范围，不等于某个呼叫的独占媒体时间窗。
- 桌面端新增“SIP 诊断”页：选 PCAP/PCAPNG、按 Call-ID 筛选，查看事务、Dialog、媒体关联、诊断发现与信令时间线。可导出 SIP JSON，或把同一文件直接带入既有 PCAP 多流媒体分析入口。
- CLI：`streamscope sip --pcap input.pcap --output sip-report.json`。省略 `--output` 时打印 JSON。
- 独立的 `streams-sip-engine` 进程：支持 OPTIONS 应答与确定性 INVITE→486 Busy Here 负向场景，响应保留全部 Via 顺序并从请求生成稳定的 To tag。桌面端可显式启动、停止并查看 Engine 事件；默认监听 `127.0.0.1:5060`，端口占用会返回错误。安装包构建前自动编译并纳入 Engine sidecar，主程序崩溃或退出时标准输入关闭，Engine 随后退出。
- 事务视图增加 1xx/最终响应列表、首个/最终响应耗时，并给出 CANCEL 对应 INVITE、分叉 To-tag、重协商与 CSeq 回退的抓包证据；未见响应仍只表示观察窗口内未见。
- 复用共享 SDP 解析器保留 `o=` session id/version、媒体方向和每次 offer/answer，检查媒体顺序、PT 子集与方向冲突；重协商记录按次展示，不把首次 SDP 当成恒定端点。
- 增加脱敏 SIP JSON 导出：Call-ID、tag、branch、IP 与 SDP origin id 使用一致的别名，原报告不被修改。
- Engine 增加 TCP/TLS OPTIONS/486 场景，TCP/TLS 最多 32 条并发连接；TLS 要求用户选择 PEM 证书/私钥。测试 Registrar 支持单个 Contact 的 REGISTER/注销、SHA-256 或 MD5 Digest `qop=auth`、nonce-count 重放检查和应答重传缓存，账号密码仅传给 Engine 子进程，不落盘。
- 忙线负向场景按 Request-URI、顶层 Via、Call-ID、From/To 和 CSeq 关联 INVITE；同一 INVITE 重传复用 486，匹配的 CANCEL 返回 200、无匹配返回 481，匹配的非 2xx ACK 结束应答重传窗口。该场景始终不建立媒体会话。
- 增加实时 OPTIONS 主动探测：UDP 退避重试，TCP/TLS 超时，TLS 验证系统信任链或指定 CA；Via 使用实际本地监听端点（UDP 带 `rport`），校验响应顶层 Via branch、Call-ID、CSeq，跳过 1xx 并等待最终状态，显示最终状态与耗时。不会自动注册或发起呼叫。
- Engine 增加显式的 UDP PCMU 测试呼叫场景：收到同一主机的 `RTP/AVP` PCMU offer 后返回对应 SDP answer，仅接受一条音频 m-line，其他 m-line 以端口 0 拒绝；收到匹配的 ACK 后发出 8 kHz 单向测试音 RTP、RTCP SR/SDES，收到 BYE 后发送 RTCP BYE 并释放端口。未收到 ACK 时重发 INVITE 2xx 并在 32 秒后释放会话。本地集成测试验证信令、RTP、RTCP 和挂断。
- 主动 UAC 抓包场景（当前为 UDP 信令子集）：在报告中选 Call-ID 和原发起端，重新扫描抓包形成 OPTIONS/REGISTER 或 INVITE→ACK→BYE 步骤；桌面端先预览并可调整步骤间隔、预期最终状态，再指定目标 IP:端口执行并查看、导出逐步 JSON。Engine 每次重新编译和校验步骤，生成新的 Call-ID、tag、Via branch、Contact 和目标 URI；INVITE 只生成一条 `a=inactive` 媒体，保留空闲端口但不接收/发送 RTP。对 UDP 重传去重，响应需匹配目标、Call-ID、CSeq 和 Via branch。

## 结论边界

- “抓包未见最终响应”仅表示观察窗口内未见，不能等同于设备没有回复。
- 报告分别列出抓包总帧、成功识别的传输包、跳过的异常网络帧；若采到 5061/TCP，提示 SIP/TLS 无法从普通抓包直接解密。完全没有明文 SIP 时只给“未发现”而非“设备无 SIP”。
- SDP/RTP 匹配仅提供媒体候选，尚未依据完整 offer/answer、时窗、NAT 或 RTCP 建立唯一呼叫归属。
- TLS 加密信令不可从普通 PCAP 解密；当前支持明文 UDP/TCP SIP。
- 现有 Registrar 仅供可控测试，只有一个 Contact 绑定，不支持完整 RFC 3261 多绑定/代理/订阅；Digest 只覆盖 `qop=auth`，不支持 `auth-int` 和代理鉴权。TLS 服务端仅验证所选证书可用于握手，客户端校验目标证书；证书身份仍需使用者正确配置。
- PCMU 呼叫仅是受控测试：只支持 UDP 信令、同主机媒体端点、单向 PCMU 音频，不接收对端音频或建立视频。没有完整 SIP transaction/Dialog 生命周期、待决 INVITE 的 CANCEL→487、REFER、分叉、re-INVITE/UPDATE、route-set、认证呼叫及 TCP/TLS 成功呼叫。忙线场景仍只处理非 2xx ACK 和最终 486 之后的 CANCEL。只有用户在 UI 中显式启动后才会占用所选端口。
- 主动抓包场景不是原始报文/媒体逐包重放：当前只支持同一发起端、同一目标的 UDP 明文 SIP，最多 24 个请求步骤，自动等待匹配的最终响应；抓包中的 Authorization、代理鉴权、CANCEL 并发取消、对端主动请求、分叉或缺少最终响应的对话会标明原因并禁止执行。仅复制安全提取的用户部分，不复制抓包中的认证值和 SDP 地址。可编辑的是等待时间与预期状态，暂不能编辑消息模板或进行 Digest 客户端认证；也不支持 TCP/TLS 抓包场景、RTP 可选发送及压力/并发模式。
- SDP/RTP 仍是端点/PT 候选匹配，不包含完整 NAT/SSRC/RTCP 唯一归属或统一 SIP+媒体根因报告；主动诊断目前只发送 OPTIONS，不是完整实时呼叫诊断。
- 本地自动测试覆盖 UDP/TCP/TLS OPTIONS、TCP 拆包与并发、TLS 证书验证、Digest REGISTER/重传、脱敏、SDP/事务样例和 PCMU 成功呼叫。真实设备 `172.16.54.254` 在本机 HTTP/HTTPS、ICMP、SIP 5060 UDP/TCP 均超时，未完成真实设备互通验收。

## 下一阶段顺序

1. 按“向设备主动测试”的定位，优先完善抓包→安全场景→执行结果：加入 Digest 客户端认证、可选 RTP 发送、TCP/TLS 场景及更多可控消息模板；不规划媒体接收/解码或完整双向通话栈。
2. 补齐并发 CANCEL、重协商等用户实际抓包中出现的场景；对未实现流程继续阻止执行，而不是盲发原始报文。
3. 完成真实设备互通、长连接/异常断连与安装包回归后再提升版本并发布。当前阶段不应以“完整 SIPp 替代品”名义发布。
