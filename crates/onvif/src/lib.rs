use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};
use md5::{Digest as _, Md5};
use quick_xml::{Reader, XmlVersion, events::Event};
use reqwest::blocking::{Client, Response};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::collections::{BTreeMap, BTreeSet};
use std::net::UdpSocket;
use std::time::{Duration, Instant};
use url::Url;
use uuid::Uuid;

pub const SOAP_ENVELOPE_NS: &str = "http://www.w3.org/2003/05/soap-envelope";
pub const WSA_NS: &str = "http://www.w3.org/2005/08/addressing";
pub const WSD_NS: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery";
pub const DEVICE_NS: &str = "http://www.onvif.org/ver10/device/wsdl";
pub const NETWORK_NS: &str = "http://www.onvif.org/ver10/network/wsdl";
pub const MEDIA_NS: &str = "http://www.onvif.org/ver10/media/wsdl";
pub const MEDIA2_NS: &str = "http://www.onvif.org/ver20/media/wsdl";
pub const IMAGING_NS: &str = "http://www.onvif.org/ver20/imaging/wsdl";
pub const EVENTS_NS: &str = "http://www.onvif.org/ver10/events/wsdl";
pub const DEVICE_IO_NS: &str = "http://www.onvif.org/ver10/deviceIO/wsdl";
pub const SCHEMA_NS: &str = "http://www.onvif.org/ver10/schema";

const WSSE_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
const WSU_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
const PASSWORD_DIGEST_TYPE: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest";
const NONCE_ENCODING_TYPE: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnvifCredentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnosticOptions {
    pub endpoint: String,
    pub credentials: Option<OnvifCredentials>,
    pub timeout_seconds: u64,
    pub accept_invalid_certificates: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryOptions {
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredDevice {
    pub endpoint_reference: Option<String>,
    pub types: Vec<String>,
    pub scopes: Vec<String>,
    pub xaddrs: Vec<String>,
    pub metadata_version: Option<String>,
    pub source: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceInformation {
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub firmware_version: Option<String>,
    pub serial_number: Option<String>,
    pub hardware_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnvifService {
    pub namespace: String,
    pub xaddr: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaProfile {
    pub token: String,
    pub name: Option<String>,
    pub video_source_token: Option<String>,
    pub video_encoding: Option<String>,
    pub audio_encoding: Option<String>,
    pub media_service: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamUri {
    pub profile_token: String,
    pub profile_name: Option<String>,
    pub uri: String,
    pub media_service: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationResult {
    pub service: String,
    pub operation: String,
    pub endpoint: String,
    pub status: String,
    pub http_status: Option<u16>,
    pub elapsed_ms: u64,
    pub detail: String,
    pub soap_fault_code: Option<String>,
    pub soap_fault_reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnosticFinding {
    pub severity: String,
    pub title: String,
    pub evidence: String,
    pub suggestion: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnvifDiagnosticResult {
    pub generated_at: String,
    pub endpoint: String,
    pub normalized_device_service: String,
    pub device_clock_offset_seconds: Option<i64>,
    pub device_information: Option<DeviceInformation>,
    pub services: Vec<OnvifService>,
    pub profiles: Vec<MediaProfile>,
    pub stream_uris: Vec<StreamUri>,
    pub operations: Vec<OperationResult>,
    pub findings: Vec<DiagnosticFinding>,
    pub standards: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum OnvifError {
    #[error("ONVIF 地址无效：{0}")]
    InvalidEndpoint(String),
    #[error("ONVIF 超时时间必须在 1 到 300 秒之间")]
    InvalidTimeout,
    #[error("网络错误：{0}")]
    Network(String),
    #[error("XML 解析错误：{0}")]
    Xml(String),
    #[error("设备没有返回可解析的 ONVIF 响应")]
    EmptyResponse,
}

#[derive(Debug, Clone, Default)]
struct XmlNode {
    name: String,
    attributes: BTreeMap<String, String>,
    text: String,
    children: Vec<XmlNode>,
}

impl XmlNode {
    fn descendants<'a>(&'a self, name: &str, output: &mut Vec<&'a XmlNode>) {
        if self.name == name {
            output.push(self);
        }
        for child in &self.children {
            child.descendants(name, output);
        }
    }

    fn first(&self, name: &str) -> Option<&XmlNode> {
        if self.name == name {
            return Some(self);
        }
        self.children.iter().find_map(|child| child.first(name))
    }

    fn value(&self, name: &str) -> Option<String> {
        self.first(name)
            .map(|node| node.text.trim().to_string())
            .filter(|value| !value.is_empty())
    }
}

#[derive(Debug)]
struct SoapResponse {
    status: u16,
    content_type: Option<String>,
    body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResponseAssessment {
    status: &'static str,
    detail: String,
    soap_fault_code: Option<String>,
    soap_fault_reason: Option<String>,
}

#[derive(Debug)]
struct SoapClient {
    http: Client,
    credentials: Option<OnvifCredentials>,
    clock_offset_seconds: i64,
}

#[derive(Debug, Clone)]
struct ServiceTarget {
    service: OnvifService,
    inferred: bool,
}

pub fn normalize_device_service(input: &str) -> Result<String, OnvifError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(OnvifError::InvalidEndpoint("地址为空".into()));
    }
    let candidate = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    let mut url =
        Url::parse(&candidate).map_err(|error| OnvifError::InvalidEndpoint(error.to_string()))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(OnvifError::InvalidEndpoint(
            "仅支持带主机名的 http:// 或 https:// 地址".into(),
        ));
    }
    if url.path().is_empty() || url.path() == "/" {
        url.set_path("/onvif/device_service");
    }
    Ok(url.to_string())
}

pub fn discovery_probe_xml(message_id: Uuid) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="{SOAP_ENVELOPE_NS}" xmlns:a="{WSA_NS}" xmlns:d="{WSD_NS}" xmlns:dn="{NETWORK_NS}">
  <s:Header>
    <a:Action s:mustUnderstand="1">{WSD_NS}/Probe</a:Action>
    <a:MessageID>urn:uuid:{message_id}</a:MessageID>
    <a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
    <a:To s:mustUnderstand="1">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
  </s:Header>
  <s:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></s:Body>
</s:Envelope>"#
    )
}

pub fn discover(options: DiscoveryOptions) -> Result<Vec<DiscoveredDevice>, OnvifError> {
    if !(1..=30).contains(&options.timeout_seconds) {
        return Err(OnvifError::InvalidTimeout);
    }
    let socket =
        UdpSocket::bind("0.0.0.0:0").map_err(|error| OnvifError::Network(error.to_string()))?;
    socket
        .set_multicast_ttl_v4(2)
        .map_err(|error| OnvifError::Network(error.to_string()))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .map_err(|error| OnvifError::Network(error.to_string()))?;
    let probe = discovery_probe_xml(Uuid::new_v4());
    let target = "239.255.255.250:3702";
    for _ in 0..3 {
        socket
            .send_to(probe.as_bytes(), target)
            .map_err(|error| OnvifError::Network(error.to_string()))?;
    }

    let deadline = Instant::now() + Duration::from_secs(options.timeout_seconds);
    let mut found = Vec::new();
    let mut keys = BTreeSet::new();
    let mut buffer = vec![0_u8; 65_535];
    while Instant::now() < deadline {
        match socket.recv_from(&mut buffer) {
            Ok((length, source)) => {
                let xml = String::from_utf8_lossy(&buffer[..length]);
                for mut device in parse_probe_matches(&xml)? {
                    device.source = Some(source.to_string());
                    let key = device
                        .endpoint_reference
                        .clone()
                        .or_else(|| device.xaddrs.first().cloned())
                        .unwrap_or_else(|| source.to_string());
                    if keys.insert(key) {
                        found.push(device);
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(OnvifError::Network(error.to_string())),
        }
    }
    Ok(found)
}

pub fn diagnose(options: DiagnosticOptions) -> Result<OnvifDiagnosticResult, OnvifError> {
    if !(1..=300).contains(&options.timeout_seconds) {
        return Err(OnvifError::InvalidTimeout);
    }
    let endpoint = normalize_device_service(&options.endpoint)?;
    let http = Client::builder()
        .timeout(Duration::from_secs(options.timeout_seconds))
        .danger_accept_invalid_certs(options.accept_invalid_certificates)
        .build()
        .map_err(|error| OnvifError::Network(error.to_string()))?;
    let mut client = SoapClient {
        http,
        credentials: None,
        clock_offset_seconds: 0,
    };
    let mut result = OnvifDiagnosticResult {
        generated_at: Utc::now().to_rfc3339(),
        endpoint: options.endpoint.clone(),
        normalized_device_service: endpoint.clone(),
        standards: vec![
            "ONVIF Core Specification 26.06".into(),
            "ONVIF Device Management WSDL".into(),
            "ONVIF Media Service / Media2 Service WSDL".into(),
            "ONVIF Imaging Service WSDL".into(),
            "ONVIF Event Service WSDL".into(),
            "WS-Discovery 2005/04 · SOAP 1.2 · WS-Addressing 2005/08 · WS-Security UsernameToken 1.0".into(),
        ],
        ..OnvifDiagnosticResult::default()
    };

    let time_body = format!("<tds:GetSystemDateAndTime xmlns:tds=\"{DEVICE_NS}\"/>");
    if let Some(xml) = call_and_record(
        &client,
        &mut result.operations,
        "Device",
        "GetSystemDateAndTime",
        &endpoint,
        &action(DEVICE_NS, "GetSystemDateAndTime"),
        &time_body,
    ) {
        let device_time = parse_xml(&xml)
            .ok()
            .and_then(|root| parse_device_utc(&root));
        if let Some(device_time) = device_time {
            let offset = device_time.timestamp() - Utc::now().timestamp();
            client.clock_offset_seconds = offset;
            result.device_clock_offset_seconds = Some(offset);
        } else {
            mark_last_invalid(
                &mut result.operations,
                "GetSystemDateAndTimeResponse 的 UTCDateTime 缺失或数值不合法",
            );
        }
    }
    client.credentials = options.credentials.clone();

    let info_body = format!("<tds:GetDeviceInformation xmlns:tds=\"{DEVICE_NS}\"/>");
    if let Some(xml) = call_and_record(
        &client,
        &mut result.operations,
        "Device",
        "GetDeviceInformation",
        &endpoint,
        &action(DEVICE_NS, "GetDeviceInformation"),
        &info_body,
    ) {
        result.device_information = parse_device_information(&xml).ok();
    }

    let services_body = format!(
        "<tds:GetServices xmlns:tds=\"{DEVICE_NS}\"><tds:IncludeCapability>false</tds:IncludeCapability></tds:GetServices>"
    );
    if let Some(xml) = call_and_record(
        &client,
        &mut result.operations,
        "Device",
        "GetServices",
        &endpoint,
        &action(DEVICE_NS, "GetServices"),
        &services_body,
    ) {
        match parse_services(&xml) {
            Ok(services) if !services.is_empty() => result.services = services,
            Ok(_) => mark_last_invalid(
                &mut result.operations,
                "GetServicesResponse 没有包含任何 Service",
            ),
            Err(error) => mark_last_invalid(
                &mut result.operations,
                &format!("GetServicesResponse 中的 Service 字段不完整：{error}"),
            ),
        }
    }

    let capabilities_body = format!(
        "<tds:GetCapabilities xmlns:tds=\"{DEVICE_NS}\"><tds:Category>All</tds:Category></tds:GetCapabilities>"
    );
    if let Some(xml) = call_and_record(
        &client,
        &mut result.operations,
        "Device",
        "GetCapabilities",
        &endpoint,
        &action(DEVICE_NS, "GetCapabilities"),
        &capabilities_body,
    ) {
        merge_capability_services(&mut result.services, &xml);
    }

    for operation in ["GetScopes", "GetNetworkInterfaces"] {
        let body = format!("<tds:{operation} xmlns:tds=\"{DEVICE_NS}\"/>");
        call_and_record(
            &client,
            &mut result.operations,
            "Device",
            operation,
            &endpoint,
            &action(DEVICE_NS, operation),
            &body,
        );
    }

    let media_targets = [
        (
            "Media2",
            MEDIA2_NS,
            "tr2",
            resolve_service_target(
                &result.services,
                MEDIA2_NS,
                &endpoint,
                "/onvif/media2_service",
            ),
        ),
        (
            "Media",
            MEDIA_NS,
            "trt",
            resolve_service_target(
                &result.services,
                MEDIA_NS,
                &endpoint,
                "/onvif/media_service",
            ),
        ),
    ];
    for (service_name, namespace, prefix, target) in media_targets {
        let service = &target.service;
        let profile_start = result.profiles.len();
        let capabilities_body =
            format!("<{prefix}:GetServiceCapabilities xmlns:{prefix}=\"{namespace}\"/>");
        call_service_operation(
            &client,
            &mut result.operations,
            &target,
            service_name,
            "GetServiceCapabilities",
            &action(namespace, "GetServiceCapabilities"),
            &capabilities_body,
        );
        let body = if namespace == MEDIA2_NS {
            format!(
                "<{prefix}:GetProfiles xmlns:{prefix}=\"{namespace}\"><{prefix}:Type>All</{prefix}:Type></{prefix}:GetProfiles>"
            )
        } else {
            format!("<{prefix}:GetProfiles xmlns:{prefix}=\"{namespace}\"/>")
        };
        if let Some(xml) = call_service_operation(
            &client,
            &mut result.operations,
            &target,
            service_name,
            "GetProfiles",
            &action(namespace, "GetProfiles"),
            &body,
        ) {
            match parse_profiles(&xml, namespace) {
                Ok(profiles) => result.profiles.extend(profiles),
                Err(error) => mark_last_invalid(
                    &mut result.operations,
                    &format!("GetProfilesResponse 中的 Profile 字段不完整：{error}"),
                ),
            }
        }

        let media_profiles = result.profiles[profile_start..].to_vec();
        if media_profiles.is_empty() {
            record_unavailable_operation(
                &mut result.operations,
                service_name,
                "GetStreamUri",
                &service.xaddr,
                "skipped",
                "该服务的 GetProfiles 未返回可用于请求 StreamUri 的 ProfileToken；其他服务仍继续验证",
            );
        }

        for profile in media_profiles {
            let body = if namespace == MEDIA2_NS {
                format!(
                    "<tr2:GetStreamUri xmlns:tr2=\"{MEDIA2_NS}\"><tr2:Protocol>RTSP</tr2:Protocol><tr2:ProfileToken>{}</tr2:ProfileToken></tr2:GetStreamUri>",
                    xml_escape(&profile.token)
                )
            } else {
                format!(
                    "<trt:GetStreamUri xmlns:trt=\"{MEDIA_NS}\" xmlns:tt=\"{SCHEMA_NS}\"><trt:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream><tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup><trt:ProfileToken>{}</trt:ProfileToken></trt:GetStreamUri>",
                    xml_escape(&profile.token)
                )
            };
            if let Some(xml) = call_service_operation(
                &client,
                &mut result.operations,
                &target,
                service_name,
                &format!("GetStreamUri [{}]", profile.token),
                &action(namespace, "GetStreamUri"),
                &body,
            ) && let Ok(root) = parse_xml(&xml)
                && let Some(uri) = root.value("Uri")
            {
                let valid_rtsp_uri = Url::parse(&uri)
                    .ok()
                    .is_some_and(|value| matches!(value.scheme(), "rtsp" | "rtsps"));
                if valid_rtsp_uri {
                    result.stream_uris.push(StreamUri {
                        profile_token: profile.token,
                        profile_name: profile.name,
                        uri,
                        media_service: namespace.into(),
                    });
                } else {
                    mark_last_invalid(
                        &mut result.operations,
                        "GetStreamUriResponse 的 Uri 不是合法的 rtsp:// 或 rtsps:// 地址",
                    );
                }
            }
        }
    }

    let imaging_target = resolve_service_target(
        &result.services,
        IMAGING_NS,
        &endpoint,
        "/onvif/imaging_service",
    );
    {
        let service = &imaging_target.service;
        let capabilities_body =
            format!("<timg:GetServiceCapabilities xmlns:timg=\"{IMAGING_NS}\"/>");
        call_service_operation(
            &client,
            &mut result.operations,
            &imaging_target,
            "Imaging",
            "GetServiceCapabilities",
            &action(IMAGING_NS, "GetServiceCapabilities"),
            &capabilities_body,
        );
        let tokens: BTreeSet<String> = result
            .profiles
            .iter()
            .filter_map(|profile| profile.video_source_token.clone())
            .collect();
        if tokens.is_empty() {
            record_unavailable_operation(
                &mut result.operations,
                "Imaging",
                "GetImagingSettings / GetOptions",
                &service.xaddr,
                "skipped",
                "没有可用 VideoSourceToken；已单独验证 Imaging/GetServiceCapabilities，但无法构造设置查询",
            );
        }
        for token in tokens {
            let body = format!(
                "<timg:GetImagingSettings xmlns:timg=\"{IMAGING_NS}\"><timg:VideoSourceToken>{}</timg:VideoSourceToken></timg:GetImagingSettings>",
                xml_escape(&token)
            );
            call_service_operation(
                &client,
                &mut result.operations,
                &imaging_target,
                "Imaging",
                &format!("GetImagingSettings [{token}]"),
                &action(IMAGING_NS, "GetImagingSettings"),
                &body,
            );
            let options_body = format!(
                "<timg:GetOptions xmlns:timg=\"{IMAGING_NS}\"><timg:VideoSourceToken>{}</timg:VideoSourceToken></timg:GetOptions>",
                xml_escape(&token)
            );
            call_service_operation(
                &client,
                &mut result.operations,
                &imaging_target,
                "Imaging",
                &format!("GetOptions [{token}]"),
                &action(IMAGING_NS, "GetOptions"),
                &options_body,
            );
        }
    }

    let device_io_target = resolve_service_target(
        &result.services,
        DEVICE_IO_NS,
        &endpoint,
        "/onvif/deviceio_service",
    );
    {
        let body = format!("<tmd:GetServiceCapabilities xmlns:tmd=\"{DEVICE_IO_NS}\"/>");
        call_service_operation(
            &client,
            &mut result.operations,
            &device_io_target,
            "DeviceIO",
            "GetServiceCapabilities",
            &action(DEVICE_IO_NS, "GetServiceCapabilities"),
            &body,
        );
    }

    let events_target = resolve_service_target(
        &result.services,
        EVENTS_NS,
        &endpoint,
        "/onvif/events_service",
    );
    {
        let body = format!("<tev:GetEventProperties xmlns:tev=\"{EVENTS_NS}\"/>");
        call_service_operation(
            &client,
            &mut result.operations,
            &events_target,
            "Events",
            "GetEventProperties",
            &action(EVENTS_NS, "GetEventProperties"),
            &body,
        );
    }

    build_findings(&mut result);
    Ok(result)
}

impl SoapClient {
    fn post(&self, endpoint: &str, action: &str, body: &str) -> Result<SoapResponse, OnvifError> {
        let envelope = soap_envelope(
            endpoint,
            action,
            body,
            self.credentials.as_ref(),
            self.clock_offset_seconds,
        );
        let first = self.send(endpoint, action, &envelope, None)?;
        if first.status().as_u16() != 401 {
            return response_body(first);
        }
        let Some(credentials) = &self.credentials else {
            return response_body(first);
        };
        let challenge = first
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let Some(authorization) = digest_authorization("POST", endpoint, credentials, &challenge)
        else {
            return response_body(first);
        };
        response_body(self.send(endpoint, action, &envelope, Some(&authorization))?)
    }

    fn send(
        &self,
        endpoint: &str,
        action: &str,
        envelope: &str,
        authorization: Option<&str>,
    ) -> Result<Response, OnvifError> {
        let content_type = format!("application/soap+xml; charset=utf-8; action=\"{action}\"");
        let mut request = self
            .http
            .post(endpoint)
            .header(CONTENT_TYPE, content_type)
            .body(envelope.to_string());
        if let Some(value) = authorization {
            request = request.header(AUTHORIZATION, value);
        }
        request
            .send()
            .map_err(|error| OnvifError::Network(error.to_string()))
    }
}

fn response_body(response: Response) -> Result<SoapResponse, OnvifError> {
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let body = response
        .text()
        .map_err(|error| OnvifError::Network(error.to_string()))?;
    Ok(SoapResponse {
        status,
        content_type,
        body,
    })
}

fn soap_envelope(
    endpoint: &str,
    action: &str,
    body: &str,
    credentials: Option<&OnvifCredentials>,
    clock_offset_seconds: i64,
) -> String {
    let security = credentials
        .map(|credentials| username_token(credentials, clock_offset_seconds))
        .unwrap_or_default();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="{SOAP_ENVELOPE_NS}" xmlns:a="{WSA_NS}">
  <s:Header>
    <a:Action s:mustUnderstand="1">{}</a:Action>
    <a:MessageID>urn:uuid:{}</a:MessageID>
    <a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
    <a:To s:mustUnderstand="1">{}</a:To>
    {}
  </s:Header>
  <s:Body>{body}</s:Body>
</s:Envelope>"#,
        xml_escape(action),
        Uuid::new_v4(),
        xml_escape(endpoint),
        security
    )
}

fn username_token(credentials: &OnvifCredentials, clock_offset_seconds: i64) -> String {
    let nonce = *Uuid::new_v4().as_bytes();
    let created = (Utc::now() + ChronoDuration::seconds(clock_offset_seconds))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    let mut sha1 = Sha1::new();
    sha1.update(nonce);
    sha1.update(created.as_bytes());
    sha1.update(credentials.password.as_bytes());
    let digest = BASE64.encode(sha1.finalize());
    format!(
        r#"<wsse:Security s:mustUnderstand="1" xmlns:wsse="{WSSE_NS}" xmlns:wsu="{WSU_NS}"><wsse:UsernameToken><wsse:Username>{}</wsse:Username><wsse:Password Type="{PASSWORD_DIGEST_TYPE}">{digest}</wsse:Password><wsse:Nonce EncodingType="{NONCE_ENCODING_TYPE}">{}</wsse:Nonce><wsu:Created>{created}</wsu:Created></wsse:UsernameToken></wsse:Security>"#,
        xml_escape(&credentials.username),
        BASE64.encode(nonce)
    )
}

fn digest_authorization(
    method: &str,
    endpoint: &str,
    credentials: &OnvifCredentials,
    challenge: &str,
) -> Option<String> {
    if !challenge.to_ascii_lowercase().starts_with("digest ") {
        return None;
    }
    let fields = parse_digest_fields(challenge.get(7..)?);
    let realm = fields.get("realm")?;
    let nonce = fields.get("nonce")?;
    let url = Url::parse(endpoint).ok()?;
    let uri = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    };
    let qop = fields.get("qop").and_then(|value| {
        value
            .split(',')
            .map(str::trim)
            .find(|value| *value == "auth")
    });
    let cnonce = Uuid::new_v4().simple().to_string();
    let nc = "00000001";
    let base_ha1 = md5_hex(&format!(
        "{}:{realm}:{}",
        credentials.username, credentials.password
    ));
    let ha1 = if fields
        .get("algorithm")
        .is_some_and(|value| value.eq_ignore_ascii_case("MD5-sess"))
    {
        md5_hex(&format!("{base_ha1}:{nonce}:{cnonce}"))
    } else {
        base_ha1
    };
    let ha2 = md5_hex(&format!("{method}:{uri}"));
    let response = if let Some(qop) = qop {
        md5_hex(&format!("{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}"))
    } else {
        md5_hex(&format!("{ha1}:{nonce}:{ha2}"))
    };
    let mut value = format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\"",
        credentials.username, realm, nonce, uri, response
    );
    if let Some(qop) = qop {
        value.push_str(&format!(", qop={qop}, nc={nc}, cnonce=\"{cnonce}\""));
    }
    if let Some(opaque) = fields.get("opaque") {
        value.push_str(&format!(", opaque=\"{opaque}\""));
    }
    Some(value)
}

fn parse_digest_fields(input: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut parts = Vec::new();
    for character in input.chars() {
        match character {
            '"' => {
                quoted = !quoted;
                current.push(character);
            }
            ',' if !quoted => parts.push(std::mem::take(&mut current)),
            _ => current.push(character),
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    for part in parts {
        if let Some((key, value)) = part.split_once('=') {
            fields.insert(
                key.trim().to_ascii_lowercase(),
                value.trim().trim_matches('"').to_string(),
            );
        }
    }
    fields
}

fn md5_hex(value: &str) -> String {
    let mut digest = Md5::new();
    digest.update(value.as_bytes());
    format!("{:x}", digest.finalize())
}

fn call_and_record(
    client: &SoapClient,
    operations: &mut Vec<OperationResult>,
    service: &str,
    operation: &str,
    endpoint: &str,
    action: &str,
    body: &str,
) -> Option<String> {
    let started = Instant::now();
    match client.post(endpoint, action, body) {
        Ok(response) => {
            let assessment = assess_response(&response, action, operation);
            let passed = assessment.status == "passed";
            operations.push(OperationResult {
                service: service.into(),
                operation: operation.into(),
                endpoint: endpoint.into(),
                status: assessment.status.into(),
                http_status: Some(response.status),
                elapsed_ms: started.elapsed().as_millis() as u64,
                detail: assessment.detail,
                soap_fault_code: assessment.soap_fault_code,
                soap_fault_reason: assessment.soap_fault_reason,
            });
            passed.then_some(response.body)
        }
        Err(error) => {
            operations.push(OperationResult {
                service: service.into(),
                operation: operation.into(),
                endpoint: endpoint.into(),
                status: "failed".into(),
                http_status: None,
                elapsed_ms: started.elapsed().as_millis() as u64,
                detail: error.to_string(),
                ..OperationResult::default()
            });
            None
        }
    }
}

fn assess_response(response: &SoapResponse, action: &str, operation: &str) -> ResponseAssessment {
    let parsed = parse_xml(&response.body);
    if let Ok(root) = &parsed
        && let Some((fault_code, fault_reason)) = parse_fault(root)
    {
        let unsupported = is_unsupported_fault(&fault_code, &fault_reason);
        return ResponseAssessment {
            status: if unsupported {
                "not_supported"
            } else {
                "failed"
            },
            detail: if fault_reason.is_empty() {
                format!("设备返回 SOAP Fault：{fault_code}")
            } else {
                format!("{fault_code}：{fault_reason}")
            },
            soap_fault_code: (!fault_code.is_empty()).then_some(fault_code),
            soap_fault_reason: (!fault_reason.is_empty()).then_some(fault_reason),
        };
    }

    if matches!(response.status, 404 | 405 | 501) {
        return ResponseAssessment {
            status: "not_supported",
            detail: format!("HTTP {}，目标端点没有实现该只读接口", response.status),
            soap_fault_code: None,
            soap_fault_reason: None,
        };
    }
    if !(200..300).contains(&response.status) {
        return ResponseAssessment {
            status: "failed",
            detail: format!("HTTP {}，响应中没有可识别的 SOAP Fault", response.status),
            soap_fault_code: None,
            soap_fault_reason: None,
        };
    }

    let root = match parsed {
        Ok(root) => root,
        Err(error) => {
            return invalid_response(format!("HTTP 成功，但 XML 无法解析：{error}"));
        }
    };
    let content_type = response.content_type.as_deref().unwrap_or_default();
    if !content_type
        .to_ascii_lowercase()
        .starts_with("application/soap+xml")
    {
        return invalid_response(format!(
            "HTTP 成功，但 Content-Type 不是 SOAP 1.2 application/soap+xml：{}",
            if content_type.is_empty() {
                "未返回"
            } else {
                content_type
            }
        ));
    }
    if !response.body.contains(SOAP_ENVELOPE_NS) {
        return invalid_response("回复未声明 SOAP 1.2 Envelope 命名空间".into());
    }
    let Some(envelope) = root.first("Envelope") else {
        return invalid_response("回复缺少 SOAP Envelope".into());
    };
    let Some(body) = envelope.first("Body") else {
        return invalid_response("回复缺少 SOAP Body".into());
    };
    let operation_name = operation_base_name(operation);
    let expected_response = format!("{operation_name}Response");
    if body.first(&expected_response).is_none() {
        return invalid_response(format!("SOAP Body 缺少标准响应元素 {expected_response}"));
    }
    if let Some(namespace) = action.strip_suffix(&format!("/{operation_name}"))
        && !response.body.contains(namespace)
    {
        return invalid_response(format!("回复未声明操作所属命名空间 {namespace}"));
    }
    if operation_name == "GetStreamUri" && body.value("Uri").is_none() {
        return invalid_response("GetStreamUriResponse 缺少必填 Uri".into());
    }

    ResponseAssessment {
        status: "passed",
        detail: format!("SOAP 1.2 结构合法，并返回 {expected_response}"),
        soap_fault_code: None,
        soap_fault_reason: None,
    }
}

fn invalid_response(detail: String) -> ResponseAssessment {
    ResponseAssessment {
        status: "invalid_response",
        detail,
        soap_fault_code: None,
        soap_fault_reason: None,
    }
}

fn operation_base_name(operation: &str) -> &str {
    operation
        .split_once([' ', '['])
        .map(|(name, _)| name)
        .unwrap_or(operation)
}

fn is_unsupported_fault(code: &str, reason: &str) -> bool {
    let evidence = format!("{code} {reason}").to_ascii_lowercase();
    evidence.contains("actionnotsupported")
        || evidence.contains("not supported")
        || evidence.contains("notsupported")
        || evidence.contains("optionalactionnotimplemented")
        || evidence.contains("unsupported")
}

fn record_unavailable_operation(
    operations: &mut Vec<OperationResult>,
    service: &str,
    operation: &str,
    endpoint: &str,
    status: &str,
    detail: &str,
) {
    operations.push(OperationResult {
        service: service.into(),
        operation: operation.into(),
        endpoint: endpoint.into(),
        status: status.into(),
        detail: detail.into(),
        ..OperationResult::default()
    });
}

fn resolve_service_target(
    services: &[OnvifService],
    namespace: &str,
    device_endpoint: &str,
    fallback_path: &str,
) -> ServiceTarget {
    if let Some(service) = services
        .iter()
        .find(|service| namespace_matches(&service.namespace, namespace))
        .cloned()
    {
        return ServiceTarget {
            service,
            inferred: false,
        };
    }
    let mut endpoint = Url::parse(device_endpoint).expect("normalized device endpoint is a URL");
    endpoint.set_path(fallback_path);
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    ServiceTarget {
        service: OnvifService {
            namespace: namespace.into(),
            xaddr: endpoint.to_string(),
            version: None,
        },
        inferred: true,
    }
}

fn call_service_operation(
    client: &SoapClient,
    operations: &mut Vec<OperationResult>,
    target: &ServiceTarget,
    service_name: &str,
    operation: &str,
    action: &str,
    body: &str,
) -> Option<String> {
    let response = call_and_record(
        client,
        operations,
        service_name,
        operation,
        &target.service.xaddr,
        action,
        body,
    );
    if target.inferred
        && let Some(record) = operations.last_mut()
    {
        record.detail = format!(
            "服务目录未提供 XAddr；已尝试同主机常见候选端点。{}",
            record.detail
        );
    }
    response
}

fn mark_last_invalid(operations: &mut [OperationResult], detail: &str) {
    if let Some(operation) = operations.last_mut()
        && operation.status == "passed"
    {
        operation.status = "invalid_response".into();
        operation.detail = detail.into();
    }
}

fn parse_xml(xml: &str) -> Result<XmlNode, OnvifError> {
    if xml.trim().is_empty() {
        return Err(OnvifError::EmptyResponse);
    }
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut stack = vec![XmlNode {
        name: "Document".into(),
        ..XmlNode::default()
    }];
    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                let mut node = XmlNode {
                    name: event.local_name().as_ref().to_string(),
                    ..XmlNode::default()
                };
                for attribute in event.attributes().flatten() {
                    let key = attribute.key.local_name().as_ref().to_string();
                    if let Ok(value) = attribute.normalized_value(XmlVersion::Implicit1_0) {
                        node.attributes.insert(key, value.into_owned());
                    }
                }
                stack.push(node);
            }
            Ok(Event::Empty(event)) => {
                let mut node = XmlNode {
                    name: event.local_name().as_ref().to_string(),
                    ..XmlNode::default()
                };
                for attribute in event.attributes().flatten() {
                    let key = attribute.key.local_name().as_ref().to_string();
                    if let Ok(value) = attribute.normalized_value(XmlVersion::Implicit1_0) {
                        node.attributes.insert(key, value.into_owned());
                    }
                }
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                }
            }
            Ok(Event::Text(event)) => {
                if let Some(node) = stack.last_mut() {
                    node.text
                        .push_str(&event.xml_content(XmlVersion::Implicit1_0));
                }
            }
            Ok(Event::GeneralRef(reference)) => {
                if let Some(node) = stack.last_mut() {
                    if let Ok(Some(character)) = reference.resolve_char_ref() {
                        node.text.push(character);
                    } else {
                        node.text.push_str(match reference.as_ref() {
                            "amp" => "&",
                            "lt" => "<",
                            "gt" => ">",
                            "quot" => "\"",
                            "apos" => "'",
                            _ => "",
                        });
                    }
                }
            }
            Ok(Event::End(_)) => {
                if stack.len() > 1 {
                    let node = stack.pop().expect("stack contains current XML node");
                    stack
                        .last_mut()
                        .expect("document node remains")
                        .children
                        .push(node);
                }
            }
            Ok(Event::Eof) => {
                if stack.len() != 1 {
                    return Err(OnvifError::Xml("XML 在元素闭合前结束".into()));
                }
                break;
            }
            Ok(_) => {}
            Err(error) => return Err(OnvifError::Xml(error.to_string())),
        }
    }
    stack.pop().ok_or(OnvifError::EmptyResponse)
}

fn parse_probe_matches(xml: &str) -> Result<Vec<DiscoveredDevice>, OnvifError> {
    let root = parse_xml(xml)?;
    let mut matches = Vec::new();
    root.descendants("ProbeMatch", &mut matches);
    Ok(matches
        .into_iter()
        .map(|node| DiscoveredDevice {
            endpoint_reference: node.value("Address"),
            types: split_values(node.value("Types")),
            scopes: split_values(node.value("Scopes")),
            xaddrs: split_values(node.value("XAddrs")),
            metadata_version: node.value("MetadataVersion"),
            source: None,
        })
        .collect())
}

fn parse_device_information(xml: &str) -> Result<DeviceInformation, OnvifError> {
    let root = parse_xml(xml)?;
    Ok(DeviceInformation {
        manufacturer: root.value("Manufacturer"),
        model: root.value("Model"),
        firmware_version: root.value("FirmwareVersion"),
        serial_number: root.value("SerialNumber"),
        hardware_id: root.value("HardwareId"),
    })
}

fn parse_services(xml: &str) -> Result<Vec<OnvifService>, OnvifError> {
    let root = parse_xml(xml)?;
    let mut nodes = Vec::new();
    root.descendants("Service", &mut nodes);
    nodes
        .into_iter()
        .map(|node| {
            Ok(OnvifService {
                namespace: node
                    .value("Namespace")
                    .ok_or_else(|| OnvifError::Xml("Service 缺少 Namespace".into()))?,
                xaddr: node
                    .value("XAddr")
                    .ok_or_else(|| OnvifError::Xml("Service 缺少 XAddr".into()))?,
                version: parse_version(node),
            })
        })
        .collect()
}

fn parse_version(node: &XmlNode) -> Option<String> {
    let version = node.first("Version")?;
    Some(format!(
        "{}.{}",
        version.value("Major")?,
        version.value("Minor")?
    ))
}

fn merge_capability_services(services: &mut Vec<OnvifService>, xml: &str) {
    let Ok(root) = parse_xml(xml) else { return };
    for (name, namespace) in [
        ("Device", DEVICE_NS),
        ("Events", EVENTS_NS),
        ("Imaging", IMAGING_NS),
        ("Media", MEDIA_NS),
    ] {
        let Some(node) = root.first(name) else {
            continue;
        };
        let Some(xaddr) = node.value("XAddr") else {
            continue;
        };
        if !services
            .iter()
            .any(|service| namespace_matches(&service.namespace, namespace))
        {
            services.push(OnvifService {
                namespace: namespace.into(),
                xaddr,
                version: None,
            });
        }
    }
}

fn parse_profiles(xml: &str, media_service: &str) -> Result<Vec<MediaProfile>, OnvifError> {
    let root = parse_xml(xml)?;
    let mut nodes = Vec::new();
    root.descendants("Profiles", &mut nodes);
    nodes
        .into_iter()
        .map(|node| {
            let token = node
                .attributes
                .get("token")
                .filter(|token| !token.trim().is_empty())
                .cloned()
                .ok_or_else(|| OnvifError::Xml("Profile 缺少非空 token".into()))?;
            let video_source_token = node
                .first("VideoSourceConfiguration")
                .or_else(|| node.first("VideoSource"))
                .and_then(|configuration| configuration.value("SourceToken"));
            let video_encoding = node
                .first("VideoEncoderConfiguration")
                .or_else(|| node.first("VideoEncoder"))
                .and_then(|configuration| configuration.value("Encoding"));
            let audio_encoding = node
                .first("AudioEncoderConfiguration")
                .or_else(|| node.first("AudioEncoder"))
                .and_then(|configuration| configuration.value("Encoding"));
            Ok(MediaProfile {
                token,
                name: node.value("Name"),
                video_source_token,
                video_encoding,
                audio_encoding,
                media_service: media_service.into(),
            })
        })
        .collect()
}

fn parse_device_utc(root: &XmlNode) -> Option<DateTime<Utc>> {
    let utc = root.first("UTCDateTime")?;
    let date = utc.first("Date")?;
    let time = utc.first("Time")?;
    Utc.with_ymd_and_hms(
        date.value("Year")?.parse().ok()?,
        date.value("Month")?.parse().ok()?,
        date.value("Day")?.parse().ok()?,
        time.value("Hour")?.parse().ok()?,
        time.value("Minute")?.parse().ok()?,
        time.value("Second")?.parse().ok()?,
    )
    .single()
}

fn parse_fault(root: &XmlNode) -> Option<(String, String)> {
    let fault = root.first("Fault")?;
    let mut values = Vec::new();
    fault
        .first("Code")
        .unwrap_or(fault)
        .descendants("Value", &mut values);
    let code = values
        .into_iter()
        .map(|node| node.text.trim())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join(" / ");
    let reason = fault
        .first("Reason")
        .and_then(|node| node.value("Text"))
        .unwrap_or_default();
    Some((code, reason))
}

fn build_findings(result: &mut OnvifDiagnosticResult) {
    if let Some(offset) = result.device_clock_offset_seconds
        && offset.abs() > 5
    {
        result.findings.push(DiagnosticFinding {
            severity: if offset.abs() > 60 { "high" } else { "medium" }.into(),
            title: "设备时钟与本机存在偏差".into(),
            evidence: format!("GetSystemDateAndTime 显示偏差 {offset} 秒"),
            suggestion: "检查设备 NTP、时区与夏令时设置；时钟偏差会影响 WS-Security 和事件时间线"
                .into(),
        });
    }
    for operation in &result.operations {
        match operation.status.as_str() {
            "failed" => result.findings.push(DiagnosticFinding {
                severity: if operation.service == "Device" {
                    "high"
                } else {
                    "medium"
                }
                .into(),
                title: format!("{} / {} 调用失败", operation.service, operation.operation),
                evidence: operation.detail.clone(),
                suggestion: "核对服务 XAddr、账号权限、设备时间及该接口是否由当前 Profile 声明"
                    .into(),
            }),
            "invalid_response" => result.findings.push(DiagnosticFinding {
                severity: "high".into(),
                title: format!(
                    "{} / {} 回复不符合标准",
                    operation.service, operation.operation
                ),
                evidence: operation.detail.clone(),
                suggestion: "保存该步骤的 HTTP/SOAP 证据并核对设备固件；不要把 HTTP 2xx 直接视为 ONVIF 操作成功"
                    .into(),
            }),
            _ => {}
        }
    }
    let unsupported = result
        .operations
        .iter()
        .filter(|operation| operation.status == "not_supported")
        .map(|operation| {
            format!(
                "{}/{}：{}",
                operation.service, operation.operation, operation.detail
            )
        })
        .collect::<Vec<_>>();
    if !unsupported.is_empty() {
        result.findings.push(DiagnosticFinding {
            severity: "low".into(),
            title: format!("{} 项只读接口不受支持", unsupported.len()),
            evidence: unsupported.join("；"),
            suggestion: "对照设备声明的 ONVIF Profile 和固件说明确认能力边界；不支持的可选接口不等于其他接口失败".into(),
        });
    }
    let skipped = result
        .operations
        .iter()
        .filter(|operation| operation.status == "skipped")
        .map(|operation| {
            format!(
                "{}/{}：{}",
                operation.service, operation.operation, operation.detail
            )
        })
        .collect::<Vec<_>>();
    if !skipped.is_empty() {
        result.findings.push(DiagnosticFinding {
            severity: "medium".into(),
            title: format!("{} 项接口因缺少必需输入未执行", skipped.len()),
            evidence: skipped.join("；"),
            suggestion: "先修复上游 ProfileToken、VideoSourceToken 或服务端点，再重新执行完整诊断"
                .into(),
        });
    }
    if !result.profiles.is_empty() && result.stream_uris.is_empty() {
        result.findings.push(DiagnosticFinding {
            severity: "high".into(),
            title: "媒体配置存在但无法取得 StreamUri".into(),
            evidence: format!(
                "发现 {} 个 Profile，成功取得 0 个 URI",
                result.profiles.len()
            ),
            suggestion: "检查 Media/Media2 权限、ProfileToken 有效性和设备 RTSP 配置".into(),
        });
    }
}

fn split_values(value: Option<String>) -> Vec<String> {
    value
        .map(|value| value.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

fn action(namespace: &str, operation: &str) -> String {
    format!("{namespace}/{operation}")
}

fn namespace_matches(actual: &str, expected: &str) -> bool {
    actual.trim_end_matches('/') == expected.trim_end_matches('/')
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_bare_device_address() {
        assert_eq!(
            normalize_device_service("192.0.2.20:8080").unwrap(),
            "http://192.0.2.20:8080/onvif/device_service"
        );
        assert_eq!(
            normalize_device_service("https://camera.test/custom").unwrap(),
            "https://camera.test/custom"
        );
    }

    #[test]
    fn probe_uses_onvif_network_video_transmitter_type() {
        let xml = discovery_probe_xml(Uuid::nil());
        assert!(xml.contains("dn:NetworkVideoTransmitter"));
        assert!(xml.contains(WSD_NS));
        assert!(xml.contains(SOAP_ENVELOPE_NS));
    }

    #[test]
    fn parses_probe_matches() {
        let xml = format!(
            r#"<s:Envelope xmlns:s="{SOAP_ENVELOPE_NS}" xmlns:d="{WSD_NS}" xmlns:a="{WSA_NS}"><s:Body><d:ProbeMatches><d:ProbeMatch><a:EndpointReference><a:Address>urn:uuid:device-1</a:Address></a:EndpointReference><d:Types>dn:NetworkVideoTransmitter</d:Types><d:Scopes>onvif://www.onvif.org/name/Camera%201 onvif://www.onvif.org/Profile/Streaming</d:Scopes><d:XAddrs>http://192.0.2.10/onvif/device_service</d:XAddrs><d:MetadataVersion>7</d:MetadataVersion></d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>"#
        );
        let parsed = parse_probe_matches(&xml).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed[0].endpoint_reference.as_deref(),
            Some("urn:uuid:device-1")
        );
        assert_eq!(parsed[0].xaddrs.len(), 1);
        assert_eq!(parsed[0].metadata_version.as_deref(), Some("7"));
    }

    #[test]
    fn parses_services_and_media_profiles() {
        let services = parse_services(&format!(
            r#"<Envelope><Body><GetServicesResponse><Service><Namespace>{MEDIA2_NS}</Namespace><XAddr>http://camera/onvif/media2</XAddr><Version><Major>2</Major><Minor>0</Minor></Version></Service></GetServicesResponse></Body></Envelope>"#
        ))
        .unwrap();
        assert_eq!(services[0].namespace, MEDIA2_NS);
        assert_eq!(services[0].version.as_deref(), Some("2.0"));

        let profiles = parse_profiles(
            r#"<Envelope><Body><GetProfilesResponse><Profiles token="profile-1"><Name>Main</Name><Configurations><VideoSource><SourceToken>source-1</SourceToken></VideoSource><VideoEncoder><Encoding>H265</Encoding></VideoEncoder></Configurations></Profiles></GetProfilesResponse></Body></Envelope>"#,
            MEDIA2_NS,
        )
        .unwrap();
        assert_eq!(profiles[0].token, "profile-1");
        assert_eq!(profiles[0].video_source_token.as_deref(), Some("source-1"));
        assert_eq!(profiles[0].video_encoding.as_deref(), Some("H265"));
    }

    #[test]
    fn username_token_contains_digest_not_plaintext_password() {
        let credentials = OnvifCredentials {
            username: "admin".into(),
            password: "secret-password".into(),
        };
        let token = username_token(&credentials, 0);
        assert!(token.contains("PasswordDigest"));
        assert!(token.contains("admin"));
        assert!(!token.contains("secret-password"));
    }

    #[test]
    fn builds_rfc7616_style_digest_auth_for_auth_qop() {
        let credentials = OnvifCredentials {
            username: "admin".into(),
            password: "pass".into(),
        };
        let header = digest_authorization(
            "POST",
            "http://camera/onvif/device_service",
            &credentials,
            "Digest realm=\"ONVIF\", nonce=\"abc\", qop=\"auth\", opaque=\"xyz\"",
        )
        .unwrap();
        assert!(header.starts_with("Digest username=\"admin\""));
        assert!(header.contains("qop=auth"));
        assert!(header.contains("uri=\"/onvif/device_service\""));
    }

    #[test]
    fn classifies_standard_soap_response_as_passed() {
        let response = SoapResponse {
            status: 200,
            content_type: Some("application/soap+xml; charset=utf-8".into()),
            body: format!(
                r#"<s:Envelope xmlns:s="{SOAP_ENVELOPE_NS}" xmlns:tds="{DEVICE_NS}"><s:Body><tds:GetDeviceInformationResponse><tds:Manufacturer>Acme</tds:Manufacturer></tds:GetDeviceInformationResponse></s:Body></s:Envelope>"#
            ),
        };
        let assessment = assess_response(
            &response,
            &action(DEVICE_NS, "GetDeviceInformation"),
            "GetDeviceInformation",
        );
        assert_eq!(assessment.status, "passed");
    }

    #[test]
    fn classifies_action_not_supported_fault_separately() {
        let response = SoapResponse {
            status: 500,
            content_type: Some("application/soap+xml".into()),
            body: format!(
                r#"<s:Envelope xmlns:s="{SOAP_ENVELOPE_NS}" xmlns:ter="{SCHEMA_NS}"><s:Body><s:Fault><s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value>ter:ActionNotSupported</s:Value></s:Subcode></s:Code><s:Reason><s:Text>Optional action not supported</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>"#
            ),
        };
        let assessment = assess_response(
            &response,
            &action(EVENTS_NS, "GetEventProperties"),
            "GetEventProperties",
        );
        assert_eq!(assessment.status, "not_supported");
        assert!(
            assessment
                .soap_fault_code
                .as_deref()
                .is_some_and(|code| code.contains("ActionNotSupported"))
        );
    }

    #[test]
    fn rejects_http_success_with_non_soap_body() {
        let response = SoapResponse {
            status: 200,
            content_type: Some("text/html".into()),
            body: "<html><body>camera web page</body></html>".into(),
        };
        let assessment =
            assess_response(&response, &action(DEVICE_NS, "GetServices"), "GetServices");
        assert_eq!(assessment.status, "invalid_response");
        assert!(assessment.detail.contains("Content-Type"));
    }

    #[test]
    fn rejects_stream_uri_response_without_uri() {
        let response = SoapResponse {
            status: 200,
            content_type: Some("application/soap+xml".into()),
            body: format!(
                r#"<s:Envelope xmlns:s="{SOAP_ENVELOPE_NS}" xmlns:trt="{MEDIA_NS}"><s:Body><trt:GetStreamUriResponse/></s:Body></s:Envelope>"#
            ),
        };
        let assessment = assess_response(
            &response,
            &action(MEDIA_NS, "GetStreamUri"),
            "GetStreamUri [profile-1]",
        );
        assert_eq!(assessment.status, "invalid_response");
        assert!(assessment.detail.contains("Uri"));
    }

    #[test]
    fn rejects_truncated_xml() {
        let error = parse_xml("<Envelope><Body>").unwrap_err();
        assert!(error.to_string().contains("闭合前结束"));
    }

    #[test]
    fn infers_service_endpoint_without_trusting_capability_list() {
        let target = resolve_service_target(
            &[],
            MEDIA_NS,
            "http://192.0.2.20:8080/onvif/device_service",
            "/onvif/media_service",
        );
        assert!(target.inferred);
        assert_eq!(
            target.service.xaddr,
            "http://192.0.2.20:8080/onvif/media_service"
        );

        let advertised = OnvifService {
            namespace: MEDIA_NS.into(),
            xaddr: "http://camera/custom/media".into(),
            version: Some("1.0".into()),
        };
        let target = resolve_service_target(
            std::slice::from_ref(&advertised),
            MEDIA_NS,
            "http://camera/onvif/device_service",
            "/onvif/media_service",
        );
        assert!(!target.inferred);
        assert_eq!(target.service, advertised);
    }

    #[test]
    fn classifies_missing_candidate_endpoint_as_not_supported() {
        let response = SoapResponse {
            status: 404,
            content_type: Some("text/html".into()),
            body: "not found".into(),
        };
        let assessment =
            assess_response(&response, &action(MEDIA2_NS, "GetProfiles"), "GetProfiles");
        assert_eq!(assessment.status, "not_supported");
        assert!(assessment.detail.contains("404"));
    }
}
