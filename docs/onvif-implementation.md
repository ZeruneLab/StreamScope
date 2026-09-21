# ONVIF 实现边界

StreamScope 的 ONVIF 能力是设备发现与诊断入口，不重复实现已有的 RTSP、SDP、RTP、RTCP、H.264、H.265 和音频分析。

当前调用链：

```text
WS-Discovery
  -> Device Service / GetSystemDateAndTime
  -> Device Service / GetDeviceInformation
  -> Device Service / GetServices + GetCapabilities
  -> Media2（优先）或 Media / GetProfiles
  -> Media2 或 Media / GetStreamUri
  -> StreamScope 现有 RTSP -> SDP -> RTP/RTCP -> 音视频诊断
```

## 已实现的协议能力

- SOAP 1.2：`http://www.w3.org/2003/05/soap-envelope`
- WS-Addressing 2005/08：Action、MessageID、ReplyTo、To
- WS-Discovery 2005/04：IPv4 多播 Probe、NetworkVideoTransmitter 类型、ProbeMatch 解析和去重
- WS-Security UsernameToken 1.0：PasswordDigest、Nonce、Created；不发送明文密码
- HTTP Digest：支持 MD5 与 `qop=auth` 的 401 重试
- Device：GetSystemDateAndTime、GetDeviceInformation、GetServices、GetCapabilities、GetScopes、GetNetworkInterfaces
- Media 1：GetProfiles、GetStreamUri（RTP-Unicast / RTSP）
- Media 2：GetProfiles、GetStreamUri（Protocol=RTSP）
- Imaging：按 Profile 的 VideoSourceToken 调用 GetImagingSettings、GetOptions
- Events：GetEventProperties
- DeviceIO：发现服务后调用 GetServiceCapabilities
- HTTPS：默认校验证书，可由用户明确允许当前设备的自签名证书
- SOAP Fault：保留 fault code、reason、HTTP 状态和耗时作为诊断证据

## 标准来源

- [ONVIF Network Interface Specifications](https://www.onvif.org/profiles/specifications/)
- [ONVIF Core Specification](https://www.onvif.org/specs/2412/ONVIF-Core-Spec-v2412.pdf)
- [Device Management WSDL](https://www.onvif.org/ver10/device/wsdl/devicemgmt.wsdl)
- [Media Service WSDL](https://www.onvif.org/ver10/media/wsdl/media.wsdl)
- [Media2 Service WSDL](https://www.onvif.org/ver20/media/wsdl/media.wsdl)
- [Imaging Service WSDL](https://www.onvif.org/ver20/imaging/wsdl/imaging.wsdl)
- [Event Service WSDL](https://www.onvif.org/ver10/events/wsdl/event.wsdl)

## 合规声明

这里的“符合标准”指报文命名空间、SOAPAction、请求结构和响应字段以 ONVIF 官方规范/WSDL 为依据，并有本地协议测试。它不等同于 ONVIF 官方认证；正式宣称设备或客户端合规仍需运行对应版本的 ONVIF Client Test Tool / Device Test Tool 并满足适用 Profile 的测试规范。

当前版本不会在 ONVIF 模块中解析媒体包，也不会把 StreamUri 当成媒体已经正常。只有继续执行 RTSP/RTP/编解码诊断后，才能形成媒体链路结论。
