//! SIP signaling diagnostics. SDP, capture decoding and RTP parsing are owned by shared crates.
mod message;
mod replay;
mod simulator;

pub use message::{
    SipError, SipMessage, StartLine, message_length, parameter, parse_datagram, parse_message,
};
pub use replay::{
    ReplayMedia, ReplayOverride, ReplayPlan, ReplayStep, apply_replay_overrides,
    compile_replay_plan,
};
use sha1::{Digest, Sha1};
pub use simulator::{DigestAlgorithm, SipBusy, SipRegistrar};

/// Minimal OPTIONS UAS response for the isolated simulator engine.
/// A non-OPTIONS request is deliberately left to later scenario handlers.
pub fn options_response(input: &[u8]) -> Result<Option<Vec<u8>>, SipError> {
    let message = parse_message(input)?;
    if !matches!(&message.start, StartLine::Request { method, .. } if method.eq_ignore_ascii_case("OPTIONS"))
    {
        return Ok(None);
    }
    build_response(&message, 200, "OK", "OPTIONS", &[]).map(Some)
}

/// Deterministic negative INVITE test scenario. ACK/CANCEL are intentionally not handled here.
pub fn invite_busy_response(input: &[u8]) -> Result<Option<Vec<u8>>, SipError> {
    let message = parse_message(input)?;
    if !matches!(&message.start, StartLine::Request { method, .. } if method.eq_ignore_ascii_case("INVITE"))
    {
        return Ok(None);
    }
    build_response(&message, 486, "Busy Here", "OPTIONS, INVITE", &[]).map(Some)
}

pub(crate) fn build_response(
    message: &SipMessage,
    status: u16,
    reason: &str,
    allow: &str,
    extra_headers: &[(&str, &str)],
) -> Result<Vec<u8>, SipError> {
    build_response_with_body(message, status, reason, allow, extra_headers, None, &[])
}

/// Build a SIP response with a byte-counted body for offer/answer test sessions.
pub fn build_response_with_body(
    message: &SipMessage,
    status: u16,
    reason: &str,
    allow: &str,
    extra_headers: &[(&str, &str)],
    content_type: Option<&str>,
    body: &[u8],
) -> Result<Vec<u8>, SipError> {
    let required = ["From", "To", "Call-ID", "CSeq"];
    if required.iter().any(|name| message.header(name).is_none()) || message.header("Via").is_none()
    {
        return Err(SipError::Header);
    }
    if !message.header("CSeq").is_some_and(|value| {
        value.split_whitespace().nth(1).is_some_and(|method| {
            message
                .method()
                .is_some_and(|expected| method.eq_ignore_ascii_case(expected))
        })
    }) {
        return Err(SipError::Header);
    }
    let mut response = format!("SIP/2.0 {status} {reason}\r\n");
    for (name, value) in &message.headers {
        if name.eq_ignore_ascii_case("Via") || name.eq_ignore_ascii_case("v") {
            response.push_str("Via: ");
            response.push_str(value);
            response.push_str("\r\n");
        }
    }
    response.push_str("From: ");
    response.push_str(message.header("From").unwrap());
    response.push_str("\r\n");
    response.push_str("To: ");
    response.push_str(message.header("To").unwrap());
    if message
        .header("To")
        .and_then(|value| message::parameter(value, "tag"))
        .is_none()
    {
        let mut digest = Sha1::new();
        for value in [
            message.header("Call-ID"),
            message.header("CSeq"),
            message.header("From"),
            message.header("Via"),
        ] {
            digest.update(value.unwrap_or_default().as_bytes());
            digest.update([0]);
        }
        let tag = format!("{:x}", digest.finalize());
        response.push_str(";tag=ss-");
        response.push_str(&tag[..12]);
    }
    response.push_str("\r\nCall-ID: ");
    response.push_str(message.header("Call-ID").unwrap());
    response.push_str("\r\nCSeq: ");
    response.push_str(message.header("CSeq").unwrap());
    response.push_str("\r\nAllow: ");
    response.push_str(allow);
    for (name, value) in extra_headers {
        response.push_str("\r\n");
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
    }
    if let Some(content_type) = content_type {
        response.push_str("\r\nContent-Type: ");
        response.push_str(content_type);
    }
    response.push_str(&format!("\r\nContent-Length: {}\r\n\r\n", body.len()));
    let mut bytes = response.into_bytes();
    bytes.extend_from_slice(body);
    Ok(bytes)
}

use message::is_sip_start;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use streamscope_capture::{
    CaptureError, CaptureFrameMeta, TcpReassembly, TransportPayload, visit_transport_packets,
};
use streamscope_rtp::parse_rtp;
use streamscope_sdp::{SdpMedia, SdpSession, parse_sdp};

const MAX_MESSAGES: usize = 100_000;
const MAX_TCP_FLOWS: usize = 256;
const MAX_RTP_FLOWS: usize = 4_096;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SipEvent {
    pub packet_number: u64,
    pub timestamp_micros: u64,
    pub source: String,
    pub destination: String,
    pub transport: String,
    pub method: Option<String>,
    pub status: Option<u16>,
    pub call_id: Option<String>,
    pub from_tag: Option<String>,
    pub to_tag: Option<String>,
    pub branch: Option<String>,
    pub cseq: Option<String>,
    pub sdp_media: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SipTransaction {
    pub call_id: String,
    pub method: String,
    pub branch: String,
    pub request_packet: Option<u64>,
    pub final_status: Option<u16>,
    pub response_packets: Vec<u64>,
    pub request_retransmissions: u32,
    #[serde(default)]
    pub provisional_statuses: Vec<u16>,
    #[serde(default)]
    pub final_statuses: Vec<u16>,
    #[serde(default)]
    pub first_response_ms: Option<u64>,
    #[serde(default)]
    pub final_response_ms: Option<u64>,
    pub outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SipCall {
    pub call_id: String,
    pub first_packet: u64,
    pub last_packet: u64,
    pub message_count: u64,
    pub dialog_count: usize,
    pub methods: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SipDialog {
    pub call_id: String,
    pub first_tag: String,
    pub second_tag: String,
    pub first_packet: u64,
    pub invite_success_packet: Option<u64>,
    pub ack_packet: Option<u64>,
    pub bye_packet: Option<u64>,
    pub bye_success_packet: Option<u64>,
    pub observed_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SipMediaBinding {
    pub call_id: String,
    pub sdp_packet: u64,
    pub media_type: String,
    pub address: String,
    pub port: u16,
    pub payload_types: Vec<u8>,
    pub codecs: Vec<String>,
    pub matched_rtp_packets: u64,
    pub matched_ssrc: Vec<u32>,
    #[serde(default)]
    pub first_rtp_packet: Option<u64>,
    #[serde(default)]
    pub last_rtp_packet: Option<u64>,
    #[serde(default)]
    pub first_rtp_timestamp_micros: Option<u64>,
    #[serde(default)]
    pub last_rtp_timestamp_micros: Option<u64>,
    pub match_quality: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SipSdpMedia {
    pub media_type: String,
    pub address: Option<String>,
    pub port: u16,
    pub protocol: String,
    pub payload_types: Vec<u8>,
    pub direction: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SipSdpExchange {
    pub packet_number: u64,
    pub call_id: String,
    pub cseq: String,
    pub method: String,
    pub message_kind: String,
    pub origin_session_id: Option<String>,
    pub origin_session_version: Option<String>,
    pub media: Vec<SipSdpMedia>,
    pub paired_packet: Option<u64>,
    pub assessment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SipFinding {
    pub severity: String,
    pub code: String,
    pub packet_number: Option<u64>,
    pub call_id: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SipReport {
    pub total_capture_frames: u64,
    pub transport_packets_seen: u64,
    pub skipped_network_frames: u64,
    pub sip_messages: Vec<SipEvent>,
    pub transactions: Vec<SipTransaction>,
    pub calls: Vec<SipCall>,
    pub dialogs: Vec<SipDialog>,
    pub media: Vec<SipMediaBinding>,
    #[serde(default)]
    pub sdp_exchanges: Vec<SipSdpExchange>,
    pub findings: Vec<SipFinding>,
    pub truncated: bool,
}

impl SipReport {
    /// Remove identifiers from a copy while preserving equality relationships for diagnostics.
    pub fn redacted(&self) -> Self {
        let mut report = self.clone();
        let mut calls = HashMap::<String, String>::new();
        let mut branches = HashMap::<String, String>::new();
        let mut tags = HashMap::<String, String>::new();
        let mut addresses = HashMap::<String, String>::new();
        let mut origins = HashMap::<String, String>::new();
        for event in &mut report.sip_messages {
            redact_optional(&mut event.call_id, &mut calls, "call");
            redact_optional(&mut event.from_tag, &mut tags, "tag");
            redact_optional(&mut event.to_tag, &mut tags, "tag");
            redact_optional(&mut event.branch, &mut branches, "branch");
            event.source = redact_socket(&event.source, &mut addresses);
            event.destination = redact_socket(&event.destination, &mut addresses);
        }
        for transaction in &mut report.transactions {
            transaction.call_id = alias(&transaction.call_id, &mut calls, "call");
            transaction.branch = alias(&transaction.branch, &mut branches, "branch");
        }
        for call in &mut report.calls {
            call.call_id = alias(&call.call_id, &mut calls, "call");
        }
        for dialog in &mut report.dialogs {
            dialog.call_id = alias(&dialog.call_id, &mut calls, "call");
            dialog.first_tag = alias(&dialog.first_tag, &mut tags, "tag");
            dialog.second_tag = alias(&dialog.second_tag, &mut tags, "tag");
        }
        for media in &mut report.media {
            media.call_id = alias(&media.call_id, &mut calls, "call");
            media.address = alias(&media.address, &mut addresses, "ip");
        }
        for exchange in &mut report.sdp_exchanges {
            exchange.call_id = alias(&exchange.call_id, &mut calls, "call");
            redact_optional(&mut exchange.origin_session_id, &mut origins, "origin");
            for media in &mut exchange.media {
                redact_optional(&mut media.address, &mut addresses, "ip");
            }
        }
        for finding in &mut report.findings {
            redact_optional(&mut finding.call_id, &mut calls, "call");
            for (original, replacement) in calls.iter().chain(addresses.iter()) {
                finding.detail = finding.detail.replace(original, replacement);
            }
        }
        report
    }
}

fn alias(value: &str, aliases: &mut HashMap<String, String>, prefix: &str) -> String {
    if let Some(existing) = aliases.get(value) {
        return existing.clone();
    }
    let replacement = format!("{prefix}-{}", aliases.len() + 1);
    aliases.insert(value.to_string(), replacement.clone());
    replacement
}

fn redact_optional(
    value: &mut Option<String>,
    aliases: &mut HashMap<String, String>,
    prefix: &str,
) {
    if let Some(original) = value {
        *original = alias(original, aliases, prefix);
    }
}

fn redact_socket(value: &str, addresses: &mut HashMap<String, String>) -> String {
    match value.parse::<SocketAddr>() {
        Ok(socket) => format!(
            "{}:{}",
            alias(&socket.ip().to_string(), addresses, "ip"),
            socket.port()
        ),
        Err(_) => alias(value, addresses, "endpoint"),
    }
}

#[derive(Default)]
struct TcpFlow {
    reassembly: TcpReassembly,
    buffer: Vec<u8>,
    first_meta: Option<CaptureFrameMeta>,
    sip_confirmed: bool,
}

#[derive(Default)]
struct RtpFlow {
    packet_count: u64,
    ssrc: Vec<u32>,
    first_packet: Option<u64>,
    last_packet: Option<u64>,
    first_timestamp_micros: Option<u64>,
    last_timestamp_micros: Option<u64>,
}

fn min_some(current: Option<u64>, next: Option<u64>) -> Option<u64> {
    match (current, next) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (value, None) | (None, value) => value,
    }
}

fn max_some(current: Option<u64>, next: Option<u64>) -> Option<u64> {
    match (current, next) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (value, None) | (None, value) => value,
    }
}

fn finding(
    report: &mut SipReport,
    severity: &str,
    code: &str,
    packet: Option<u64>,
    call_id: Option<String>,
    detail: impl Into<String>,
) {
    if report.findings.len() < 10_000 {
        report.findings.push(SipFinding {
            severity: severity.into(),
            code: code.into(),
            packet_number: packet,
            call_id,
            detail: detail.into(),
        });
    } else {
        report.truncated = true;
    }
}

fn sdp_direction(session: &SdpSession, media: &SdpMedia) -> String {
    for attributes in [&media.attributes, &session.attributes] {
        for direction in ["sendrecv", "sendonly", "recvonly", "inactive"] {
            if attributes.contains_key(direction) {
                return direction.into();
            }
        }
    }
    "sendrecv".into()
}

fn assess_sdp_answer(offer: &SipSdpExchange, answer: &SipSdpExchange) -> Result<String, String> {
    if offer.media.len() != answer.media.len() {
        return Err(format!(
            "answer 的 m= 行数 {} 与 offer 的 {} 不一致",
            answer.media.len(),
            offer.media.len()
        ));
    }
    let mut accepted = 0;
    for (index, (offered, answered)) in offer.media.iter().zip(&answer.media).enumerate() {
        if offered.media_type != answered.media_type || offered.protocol != answered.protocol {
            return Err(format!("第 {} 路媒体类型或协议与 offer 不一致", index + 1));
        }
        if answered.port == 0 {
            continue;
        }
        if answered
            .payload_types
            .iter()
            .any(|pt| !offered.payload_types.contains(pt))
        {
            return Err(format!(
                "第 {} 路 answer 使用了 offer 未提供的 PT",
                index + 1
            ));
        }
        let directions_match = match offered.direction.as_str() {
            "sendonly" => matches!(answered.direction.as_str(), "recvonly" | "inactive"),
            "recvonly" => matches!(answered.direction.as_str(), "sendonly" | "inactive"),
            "inactive" => answered.direction == "inactive",
            _ => true,
        };
        if !directions_match {
            return Err(format!(
                "第 {} 路 answer 的媒体方向与 offer 冲突",
                index + 1
            ));
        }
        accepted += 1;
    }
    Ok(format!(
        "offer/answer 已配对；接受 {accepted}/{} 路媒体",
        offer.media.len()
    ))
}

fn record_message(
    report: &mut SipReport,
    bytes: &[u8],
    meta: &CaptureFrameMeta,
    source: SocketAddr,
    destination: SocketAddr,
    transport: &str,
) {
    if report.sip_messages.len() >= MAX_MESSAGES {
        report.truncated = true;
        return;
    }
    let message = match if transport == "UDP" {
        parse_datagram(bytes)
    } else {
        parse_message(bytes)
    } {
        Ok(message) => message,
        Err(error) => {
            finding(
                report,
                "warn",
                "sip_parse_error",
                Some(meta.number),
                None,
                format!("SIP 消息解析失败：{error}"),
            );
            return;
        }
    };
    let call_id = message.header("Call-ID").map(str::to_string);
    let from_tag = message
        .header("From")
        .and_then(|value| parameter(value, "tag"));
    let to_tag = message
        .header("To")
        .and_then(|value| parameter(value, "tag"));
    let branch = message
        .header("Via")
        .and_then(|value| parameter(value, "branch"));
    let cseq = message.header("CSeq").map(str::to_string);
    if let StartLine::Request { method, .. } = &message.start
        && cseq
            .as_deref()
            .and_then(|value| value.split_whitespace().nth(1))
            .is_some_and(|value| !value.eq_ignore_ascii_case(method))
    {
        finding(
            report,
            "warn",
            "cseq_method_mismatch",
            Some(meta.number),
            call_id.clone(),
            format!("请求行方法 {method} 与 CSeq 方法不一致"),
        );
    }
    for (name, value) in [
        ("Via", message.header("Via")),
        ("From", message.header("From")),
        ("To", message.header("To")),
        ("Call-ID", message.header("Call-ID")),
        ("CSeq", message.header("CSeq")),
    ] {
        if value.is_none() {
            finding(
                report,
                "warn",
                "missing_required_header",
                Some(meta.number),
                call_id.clone(),
                format!("SIP 消息缺少必需的 {name} 头"),
            );
        }
    }
    let mut sdp_media = 0;
    if message
        .header("Content-Type")
        .is_some_and(|value| value.to_ascii_lowercase().starts_with("application/sdp"))
    {
        match std::str::from_utf8(&message.body)
            .ok()
            .and_then(|body| parse_sdp(body).ok())
        {
            Some(sdp) => {
                sdp_media = sdp.media.len();
                if report.sdp_exchanges.len() < MAX_MESSAGES {
                    report.sdp_exchanges.push(SipSdpExchange {
                        packet_number: meta.number,
                        call_id: call_id.clone().unwrap_or_default(),
                        cseq: cseq.clone().unwrap_or_default(),
                        method: message.method().unwrap_or_default().to_string(),
                        message_kind: if matches!(message.start, StartLine::Request { .. }) {
                            "request"
                        } else {
                            "response"
                        }
                        .into(),
                        origin_session_id: sdp.origin_session_id.clone(),
                        origin_session_version: sdp.origin_session_version.clone(),
                        media: sdp
                            .media
                            .iter()
                            .map(|media| SipSdpMedia {
                                media_type: media.media_type.clone(),
                                address: media
                                    .connection_address
                                    .clone()
                                    .or_else(|| sdp.connection_address.clone()),
                                port: media.port,
                                protocol: media.protocol.clone(),
                                payload_types: media.payload_types.clone(),
                                direction: sdp_direction(&sdp, media),
                            })
                            .collect(),
                        paired_packet: None,
                        assessment: "尚未在抓包内配对 offer/answer".into(),
                    });
                } else {
                    report.truncated = true;
                }
                for media in sdp.media {
                    let address = media
                        .connection_address
                        .clone()
                        .or_else(|| sdp.connection_address.clone());
                    let Some(address) = address else {
                        finding(
                            report,
                            "warn",
                            "sdp_missing_connection",
                            Some(meta.number),
                            call_id.clone(),
                            format!("{} 媒体缺少 c= 地址", media.media_type),
                        );
                        continue;
                    };
                    if media.port == 0 {
                        continue;
                    }
                    let codecs = media
                        .payload_types
                        .iter()
                        .map(|pt| {
                            media
                                .rtp_maps
                                .get(pt)
                                .map(|map| map.encoding.clone())
                                .unwrap_or_else(|| format!("PT {pt}"))
                        })
                        .collect();
                    if report.media.len() < MAX_RTP_FLOWS {
                        report.media.push(SipMediaBinding {
                            call_id: call_id.clone().unwrap_or_default(),
                            sdp_packet: meta.number,
                            media_type: media.media_type,
                            address,
                            port: media.port,
                            payload_types: media.payload_types,
                            codecs,
                            matched_rtp_packets: 0,
                            matched_ssrc: Vec::new(),
                            first_rtp_packet: None,
                            last_rtp_packet: None,
                            first_rtp_timestamp_micros: None,
                            last_rtp_timestamp_micros: None,
                            match_quality: "待关联".into(),
                        });
                    } else {
                        report.truncated = true;
                    }
                }
            }
            None => finding(
                report,
                "warn",
                "invalid_sdp",
                Some(meta.number),
                call_id.clone(),
                "Content-Type 为 application/sdp，但 SDP 解析失败",
            ),
        }
    }
    let (method, status) = match &message.start {
        StartLine::Request { method, .. } => (Some(method.clone()), None),
        StartLine::Response { status, .. } => (message.method().map(str::to_string), Some(*status)),
    };
    report.sip_messages.push(SipEvent {
        packet_number: meta.number,
        timestamp_micros: meta.timestamp_micros,
        source: source.to_string(),
        destination: destination.to_string(),
        transport: transport.into(),
        method,
        status,
        call_id,
        from_tag,
        to_tag,
        branch,
        cseq,
        sdp_media,
    });
}

fn feed_tcp(
    report: &mut SipReport,
    flow: &mut TcpFlow,
    data: &[u8],
    meta: &CaptureFrameMeta,
    source: SocketAddr,
    destination: SocketAddr,
    discontinuity: bool,
) {
    if discontinuity {
        flow.buffer.clear();
        flow.first_meta = None;
    }
    if data.is_empty() {
        return;
    }
    if flow.buffer.is_empty() {
        flow.first_meta = Some(meta.clone());
    }
    flow.buffer.extend_from_slice(data);
    if flow.buffer.len() > 1024 * 1024 {
        finding(
            report,
            "warn",
            "sip_tcp_overflow",
            Some(meta.number),
            None,
            "TCP SIP 消息超过 1 MiB 或未找到完整边界",
        );
        flow.buffer.clear();
        flow.first_meta = None;
        return;
    }
    loop {
        if flow.buffer.is_empty() {
            break;
        }
        if !is_sip_start(&flow.buffer) {
            if flow.buffer.len() < 64 {
                break;
            }
            finding(
                report,
                "warn",
                "sip_tcp_sync",
                flow.first_meta.as_ref().map(|meta| meta.number),
                None,
                "TCP 流无法对齐 SIP 消息起始行，已停止解析该段",
            );
            flow.buffer.clear();
            flow.first_meta = None;
            break;
        }
        let length = match message::message_length(&flow.buffer) {
            Ok(Some(length)) => length,
            Ok(None) => break,
            Err(error) => {
                finding(
                    report,
                    "warn",
                    "sip_tcp_frame",
                    flow.first_meta.as_ref().map(|meta| meta.number),
                    None,
                    format!("TCP SIP 分帧失败：{error}"),
                );
                flow.buffer.clear();
                flow.first_meta = None;
                break;
            }
        };
        record_message(
            report,
            &flow.buffer[..length],
            flow.first_meta.as_ref().unwrap_or(meta),
            source,
            destination,
            "TCP",
        );
        flow.buffer.drain(..length);
        flow.first_meta = (!flow.buffer.is_empty()).then(|| meta.clone());
    }
}

pub fn analyze_pcap(path: &Path) -> Result<SipReport, CaptureError> {
    let mut report = SipReport::default();
    let mut tcp: HashMap<(SocketAddr, SocketAddr), TcpFlow> = HashMap::new();
    let mut rtp: HashMap<(IpAddr, u16, u8), RtpFlow> = HashMap::new();
    let mut possible_tls = 0_u64;
    let visit = visit_transport_packets(path, |packet| {
        report.transport_packets_seen += 1;
        match packet.payload {
            TransportPayload::Udp(data) => {
                if is_sip_start(data) {
                    record_message(
                        &mut report,
                        data,
                        &packet.meta,
                        packet.source,
                        packet.destination,
                        "UDP",
                    );
                } else if let Ok(parsed) = parse_rtp(data) {
                    if rtp.len() < MAX_RTP_FLOWS
                        || rtp.contains_key(&(
                            packet.destination.ip(),
                            packet.destination.port(),
                            parsed.payload_type,
                        ))
                    {
                        let flow = rtp
                            .entry((
                                packet.destination.ip(),
                                packet.destination.port(),
                                parsed.payload_type,
                            ))
                            .or_default();
                        flow.packet_count += 1;
                        flow.first_packet = Some(
                            flow.first_packet
                                .map_or(packet.meta.number, |first| first.min(packet.meta.number)),
                        );
                        flow.last_packet = Some(
                            flow.last_packet
                                .map_or(packet.meta.number, |last| last.max(packet.meta.number)),
                        );
                        flow.first_timestamp_micros = Some(
                            flow.first_timestamp_micros
                                .map_or(packet.meta.timestamp_micros, |first| {
                                    first.min(packet.meta.timestamp_micros)
                                }),
                        );
                        flow.last_timestamp_micros = Some(
                            flow.last_timestamp_micros
                                .map_or(packet.meta.timestamp_micros, |last| {
                                    last.max(packet.meta.timestamp_micros)
                                }),
                        );
                        if !flow.ssrc.contains(&parsed.ssrc) && flow.ssrc.len() < 32 {
                            flow.ssrc.push(parsed.ssrc);
                        }
                    } else {
                        report.truncated = true;
                    }
                }
            }
            TransportPayload::Tcp {
                sequence,
                flags,
                data,
            } => {
                if packet.source.port() == 5061 || packet.destination.port() == 5061 {
                    possible_tls += 1;
                }
                let key = (packet.source, packet.destination);
                if flags & 0x02 != 0 && tcp.contains_key(&key) {
                    tcp.remove(&key);
                }
                if !tcp.contains_key(&key) {
                    if tcp.len() >= MAX_TCP_FLOWS {
                        report.truncated = true;
                        return Ok(());
                    }
                    if packet.source.port() != 5060
                        && packet.destination.port() != 5060
                        && !is_sip_start(data)
                    {
                        return Ok(());
                    }
                }
                let flow = tcp.entry(key).or_default();
                if packet.source.port() == 5060
                    || packet.destination.port() == 5060
                    || is_sip_start(data)
                {
                    flow.sip_confirmed = true;
                }
                let chunks = flow
                    .reassembly
                    .push(sequence, flags & 0x02 != 0, data, &packet.meta);
                for chunk in chunks {
                    if flow.sip_confirmed {
                        feed_tcp(
                            &mut report,
                            flow,
                            &chunk.data,
                            &chunk.meta,
                            packet.source,
                            packet.destination,
                            chunk.discontinuity,
                        );
                    }
                }
                if flags & 0x05 != 0
                    && let Some(mut closed) = tcp.remove(&key)
                {
                    for chunk in closed.reassembly.finish() {
                        if closed.sip_confirmed {
                            feed_tcp(
                                &mut report,
                                &mut closed,
                                &chunk.data,
                                &chunk.meta,
                                packet.source,
                                packet.destination,
                                chunk.discontinuity,
                            );
                        }
                    }
                    if closed.sip_confirmed && !closed.buffer.is_empty() {
                        finding(
                            &mut report,
                            "info",
                            "sip_tcp_partial",
                            closed.first_meta.as_ref().map(|meta| meta.number),
                            None,
                            "TCP 连接结束时仍有不完整的 SIP 消息",
                        );
                    }
                }
            }
        }
        Ok(())
    })?;
    report.total_capture_frames = visit.total_frames;
    report.skipped_network_frames = visit.skipped_network_frames;
    if visit.skipped_network_frames > 0 {
        finding(
            &mut report,
            "info",
            "network_frames_skipped",
            None,
            None,
            format!(
                "{} 个网络帧未能解析，首个原因：{}；SIP 结论仅基于成功解析的数据",
                visit.skipped_network_frames,
                visit.first_skip_reason.unwrap_or("未知")
            ),
        );
    }
    if possible_tls > 0 {
        finding(
            &mut report,
            "info",
            "sip_tls_unavailable",
            None,
            None,
            format!(
                "抓包中有 {possible_tls} 个 TCP 包使用 5061 端口；普通抓包不能直接解析加密 SIP/TLS"
            ),
        );
    }
    for ((source, destination), flow) in &mut tcp {
        for chunk in flow.reassembly.finish() {
            if flow.sip_confirmed {
                feed_tcp(
                    &mut report,
                    flow,
                    &chunk.data,
                    &chunk.meta,
                    *source,
                    *destination,
                    chunk.discontinuity,
                );
            }
        }
        if flow.sip_confirmed && !flow.buffer.is_empty() {
            finding(
                &mut report,
                "info",
                "sip_tcp_partial",
                flow.first_meta.as_ref().map(|meta| meta.number),
                None,
                "抓包结束时仍有不完整的 TCP SIP 消息",
            );
        }
    }
    finish_report(&mut report, &rtp);
    if report.sip_messages.is_empty() {
        finding(
            &mut report,
            "info",
            "no_plaintext_sip",
            None,
            None,
            "抓包内未发现可解析的明文 SIP；请核对端口、抓包范围及 TLS 加密情况",
        );
    }
    Ok(report)
}

fn finish_report(report: &mut SipReport, rtp: &HashMap<(IpAddr, u16, u8), RtpFlow>) {
    let mut transactions: BTreeMap<(String, String, String, String), SipTransaction> =
        BTreeMap::new();
    let mut request_times: HashMap<(String, String, String, String), u64> = HashMap::new();
    let mut calls: BTreeMap<String, (SipCall, Vec<(String, String)>)> = BTreeMap::new();
    let mut dialogs: BTreeMap<(String, String, String), SipDialog> = BTreeMap::new();
    for event in &report.sip_messages {
        let Some(call_id) = &event.call_id else {
            continue;
        };
        let call = calls.entry(call_id.clone()).or_insert_with(|| {
            (
                SipCall {
                    call_id: call_id.clone(),
                    first_packet: event.packet_number,
                    last_packet: event.packet_number,
                    message_count: 0,
                    dialog_count: 0,
                    methods: Vec::new(),
                },
                Vec::new(),
            )
        });
        call.0.first_packet = call.0.first_packet.min(event.packet_number);
        call.0.last_packet = call.0.last_packet.max(event.packet_number);
        call.0.message_count += 1;
        if let Some(method) = &event.method
            && !call.0.methods.contains(method)
        {
            call.0.methods.push(method.clone());
        }
        if let (Some(from), Some(to)) = (&event.from_tag, &event.to_tag) {
            let pair = if from <= to {
                (from.clone(), to.clone())
            } else {
                (to.clone(), from.clone())
            };
            if !call.1.contains(&pair) {
                call.1.push(pair.clone());
            }
            let dialog = dialogs
                .entry((call_id.clone(), pair.0.clone(), pair.1.clone()))
                .or_insert_with(|| SipDialog {
                    call_id: call_id.clone(),
                    first_tag: pair.0,
                    second_tag: pair.1,
                    first_packet: event.packet_number,
                    invite_success_packet: None,
                    ack_packet: None,
                    bye_packet: None,
                    bye_success_packet: None,
                    observed_state: String::new(),
                });
            if event.method.as_deref() == Some("INVITE")
                && event
                    .status
                    .is_some_and(|status| (200..300).contains(&status))
            {
                dialog.invite_success_packet = Some(event.packet_number);
            }
            if event.method.as_deref() == Some("ACK") && event.status.is_none() {
                dialog.ack_packet = Some(event.packet_number);
            }
            if event.method.as_deref() == Some("BYE") {
                if event.status.is_none() {
                    dialog.bye_packet = Some(event.packet_number);
                }
                if event
                    .status
                    .is_some_and(|status| (200..300).contains(&status))
                {
                    dialog.bye_success_packet = Some(event.packet_number);
                }
            }
        }
        let (Some(branch), Some(method), Some(cseq)) = (&event.branch, &event.method, &event.cseq)
        else {
            continue;
        };
        let number = cseq.split_whitespace().next().unwrap_or("").to_string();
        let key = (call_id.clone(), branch.clone(), number, method.clone());
        let transaction = transactions
            .entry(key.clone())
            .or_insert_with(|| SipTransaction {
                call_id: call_id.clone(),
                method: method.clone(),
                branch: branch.clone(),
                request_packet: None,
                final_status: None,
                response_packets: Vec::new(),
                request_retransmissions: 0,
                provisional_statuses: Vec::new(),
                final_statuses: Vec::new(),
                first_response_ms: None,
                final_response_ms: None,
                outcome: String::new(),
            });
        if let Some(status) = event.status {
            transaction.response_packets.push(event.packet_number);
            if let Some(start) = request_times.get(&key) {
                let elapsed = event.timestamp_micros.saturating_sub(*start) / 1000;
                transaction.first_response_ms.get_or_insert(elapsed);
                if status >= 200 {
                    transaction.final_response_ms = Some(elapsed);
                }
            }
            if status >= 200 {
                transaction.final_status = Some(status);
                if !transaction.final_statuses.contains(&status) {
                    transaction.final_statuses.push(status);
                }
            } else if !transaction.provisional_statuses.contains(&status) {
                transaction.provisional_statuses.push(status);
            }
        } else if transaction.request_packet.is_some() {
            transaction.request_retransmissions += 1;
        } else {
            transaction.request_packet = Some(event.packet_number);
            request_times.insert(key, event.timestamp_micros);
        }
    }
    for (_, (mut call, dialogs)) in calls {
        call.dialog_count = dialogs.len();
        report.calls.push(call);
    }
    for (_, mut dialog) in dialogs {
        dialog.observed_state = if dialog.bye_success_packet.is_some() {
            "抓包内见 BYE 成功响应"
        } else if dialog.bye_packet.is_some() {
            "抓包内见 BYE 请求，未见成功响应"
        } else if dialog.ack_packet.is_some() {
            "抓包内见 ACK"
        } else if dialog.invite_success_packet.is_some() {
            "抓包内见 INVITE 2xx，未见 ACK"
        } else {
            "抓包内仅见早期/其他 Dialog 消息"
        }
        .into();
        report.dialogs.push(dialog);
    }
    for (_, mut transaction) in transactions {
        transaction.outcome = match (transaction.request_packet, transaction.final_status) {
            (None, _) => "抓包未见请求".into(),
            (Some(_), None) => "抓包未见最终响应".into(),
            (_, Some(status)) if (300..400).contains(&status) => format!("SIP {status} 重定向响应"),
            (_, Some(status)) if status >= 400 => format!("SIP {status} 非成功最终响应"),
            (_, Some(status)) => format!("SIP {status} 成功响应"),
        };
        if let Some(status) = transaction.final_status
            && status >= 300
        {
            let challenge = status == 401 || status == 407;
            let expected = challenge || (300..400).contains(&status) || status == 487;
            let code = if challenge {
                "sip_auth_challenge"
            } else if status < 400 {
                "sip_redirect"
            } else {
                "sip_negative_response"
            };
            finding(
                report,
                if expected { "info" } else { "warn" },
                code,
                transaction.response_packets.last().copied(),
                Some(transaction.call_id.clone()),
                format!(
                    "{} 收到 SIP {status} 最终响应{}",
                    transaction.method,
                    if challenge {
                        "（认证挑战不等于最终故障）"
                    } else if status == 487 {
                        "（通常与 CANCEL 相关）"
                    } else {
                        "；需结合业务场景判断"
                    }
                ),
            );
        }
        report.transactions.push(transaction);
    }
    let mut finding_after_calls = Vec::new();
    for call in &report.calls {
        if call.dialog_count > 1 {
            finding_after_calls.push((
                call.call_id.clone(),
                format!("同一 Call-ID 观察到 {} 个 To-tag Dialog，可能发生分叉；响应与媒体不能仅按 Call-ID 合并", call.dialog_count),
            ));
        }
    }
    for (call_id, detail) in finding_after_calls {
        finding(
            report,
            "info",
            "sip_fork_candidates",
            None,
            Some(call_id),
            detail,
        );
    }
    let invite_keys: HashSet<_> = report
        .sip_messages
        .iter()
        .filter(|event| event.status.is_none() && event.method.as_deref() == Some("INVITE"))
        .filter_map(|event| {
            Some((
                event.call_id.as_ref()?.clone(),
                event.branch.as_ref()?.clone(),
                event.cseq.as_ref()?.split_whitespace().next()?.to_string(),
            ))
        })
        .collect();
    let mut cseq_by_sender: HashMap<(String, String, String), u64> = HashMap::new();
    let mut extra_findings = Vec::new();
    for event in &report.sip_messages {
        if event.status.is_some() {
            continue;
        }
        let Some(call_id) = &event.call_id else {
            continue;
        };
        let method = event.method.as_deref().unwrap_or_default();
        if method == "CANCEL"
            && let (Some(branch), Some(number)) = (
                &event.branch,
                event
                    .cseq
                    .as_deref()
                    .and_then(|value| value.split_whitespace().next()),
            )
        {
            extra_findings.push((
                "info",
                "sip_cancel",
                event.packet_number,
                call_id.clone(),
                if invite_keys.contains(&(call_id.clone(), branch.clone(), number.to_string())) {
                    "抓包内 CANCEL 与同一 branch/CSeq 的 INVITE 对应；后续 487 通常是取消结果"
                        .to_string()
                } else {
                    "抓包内见 CANCEL，但未见对应 INVITE；可能从呼叫中途开始抓包".to_string()
                },
            ));
        }
        if (method == "INVITE" && event.to_tag.is_some()) || method == "UPDATE" {
            extra_findings.push((
                "info",
                "sip_renegotiation",
                event.packet_number,
                call_id.clone(),
                format!(
                    "观察到 Dialog 内 {method}；需以该次 SDP 协商结果为准，不能沿用首次媒体端点"
                ),
            ));
        }
        if matches!(method, "ACK" | "CANCEL") {
            continue;
        }
        if let (Some(from), Some(to), Some(number)) = (
            &event.from_tag,
            &event.to_tag,
            event
                .cseq
                .as_deref()
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse::<u64>().ok()),
        ) {
            let key = (call_id.clone(), from.clone(), to.clone());
            if let Some(previous) = cseq_by_sender.get(&key)
                && number < *previous
            {
                extra_findings.push((
                    "warn",
                    "sip_cseq_regression",
                    event.packet_number,
                    call_id.clone(),
                    format!(
                        "同一方向 Dialog 请求 CSeq 从 {previous} 回退到 {number}；也可能是抓包乱序"
                    ),
                ));
            }
            cseq_by_sender
                .entry(key)
                .and_modify(|old| *old = (*old).max(number))
                .or_insert(number);
        }
    }
    for (severity, code, packet, call_id, detail) in extra_findings {
        finding(report, severity, code, Some(packet), Some(call_id), detail);
    }
    let multi_final = report
        .transactions
        .iter()
        .filter(|transaction| {
            transaction.method == "INVITE" && transaction.final_statuses.len() > 1
        })
        .map(|transaction| {
            (
                transaction.call_id.clone(),
                transaction.request_packet,
                transaction.final_statuses.clone(),
            )
        })
        .collect::<Vec<_>>();
    for (call_id, packet, statuses) in multi_final {
        finding(
            report,
            "info",
            "sip_multiple_final_responses",
            packet,
            Some(call_id),
            format!(
                "同一 INVITE 事务观察到多个最终状态 {statuses:?}；可能是分叉响应，需按 To-tag 区分"
            ),
        );
    }
    let mut offers: HashMap<(String, String, String), usize> = HashMap::new();
    let mut sdp_findings = Vec::new();
    for index in 0..report.sdp_exchanges.len() {
        let exchange = &report.sdp_exchanges[index];
        let key = (
            exchange.call_id.clone(),
            exchange.cseq.clone(),
            exchange.method.clone(),
        );
        if exchange.message_kind == "request" {
            offers.entry(key).or_insert(index);
            continue;
        }
        let Some(&offer_index) = offers.get(&key) else {
            continue;
        };
        let offer = report.sdp_exchanges[offer_index].clone();
        let answer = report.sdp_exchanges[index].clone();
        let assessment = assess_sdp_answer(&offer, &answer);
        report.sdp_exchanges[index].paired_packet = Some(offer.packet_number);
        report.sdp_exchanges[index].assessment = match assessment {
            Ok(detail) => detail,
            Err(detail) => {
                sdp_findings.push((answer.packet_number, answer.call_id.clone(), detail.clone()));
                format!("offer/answer 异常：{detail}")
            }
        };
        report.sdp_exchanges[offer_index].paired_packet = Some(answer.packet_number);
        report.sdp_exchanges[offer_index].assessment =
            report.sdp_exchanges[index].assessment.clone();
    }
    for (packet, call_id, detail) in sdp_findings {
        finding(
            report,
            "warn",
            "sip_sdp_answer_mismatch",
            Some(packet),
            Some(call_id),
            detail,
        );
    }
    for media in &mut report.media {
        let Ok(address) = media.address.parse::<IpAddr>() else {
            media.match_quality = "SDP 地址非 IP，未关联".into();
            continue;
        };
        if address.is_unspecified() {
            media.match_quality = "SDP hold 地址，未关联".into();
            continue;
        }
        for payload_type in &media.payload_types {
            if let Some(flow) = rtp.get(&(address, media.port, *payload_type)) {
                media.matched_rtp_packets += flow.packet_count;
                media.first_rtp_packet = min_some(media.first_rtp_packet, flow.first_packet);
                media.last_rtp_packet = max_some(media.last_rtp_packet, flow.last_packet);
                media.first_rtp_timestamp_micros = min_some(
                    media.first_rtp_timestamp_micros,
                    flow.first_timestamp_micros,
                );
                media.last_rtp_timestamp_micros =
                    max_some(media.last_rtp_timestamp_micros, flow.last_timestamp_micros);
                for ssrc in &flow.ssrc {
                    if !media.matched_ssrc.contains(ssrc) {
                        media.matched_ssrc.push(*ssrc);
                    }
                }
            }
        }
        media.match_quality = if media.matched_rtp_packets > 0 {
            "SDP 地址/端口/PT 候选匹配，未证明呼叫独占"
        } else {
            "抓包内未见端点/PT 候选 RTP（可能未采到媒体或存在 NAT）"
        }
        .into();
    }
    let announced = report
        .media
        .iter()
        .map(|media| (media.call_id.clone(), media.address.clone(), media.port))
        .collect::<Vec<_>>();
    for media in &mut report.media {
        if announced.iter().any(|(call_id, address, port)| {
            call_id != &media.call_id && address == &media.address && port == &media.port
        }) {
            media.match_quality = "多个呼叫共用该 SDP 端点；RTP 不能可靠归属单一呼叫".into();
        }
    }
    if report.truncated {
        finding(
            report,
            "info",
            "limit_reached",
            None,
            None,
            "达到信令或流数量安全上限，部分明细未保留；结论仅基于已保存样本",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pcap_udp(payloads: &[(&[u8], u16, u16)]) -> Vec<u8> {
        let mut output = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0,
            0,
        ];
        for (index, (payload, source_port, destination_port)) in payloads.iter().enumerate() {
            let mut frame = vec![0; 14 + 20 + 8];
            frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
            frame[14] = 0x45;
            frame[16..18].copy_from_slice(&((20 + 8 + payload.len()) as u16).to_be_bytes());
            frame[23] = 17;
            frame[26..30].copy_from_slice(&[10, 0, 0, 1]);
            frame[30..34].copy_from_slice(&[10, 0, 0, 2]);
            frame[34..36].copy_from_slice(&source_port.to_be_bytes());
            frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
            frame[38..40].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
            frame.extend_from_slice(payload);
            output.extend_from_slice(&(index as u32).to_le_bytes());
            output.extend_from_slice(&0_u32.to_le_bytes());
            output.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            output.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            output.extend_from_slice(&frame);
        }
        output
    }

    fn pcap_tcp(parts: &[(&[u8], u32)]) -> Vec<u8> {
        let mut output = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0,
            0,
        ];
        for (index, (payload, sequence)) in parts.iter().enumerate() {
            let mut frame = vec![0; 14 + 20 + 20];
            frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
            frame[14] = 0x45;
            frame[16..18].copy_from_slice(&((20 + 20 + payload.len()) as u16).to_be_bytes());
            frame[23] = 6;
            frame[26..30].copy_from_slice(&[10, 0, 0, 1]);
            frame[30..34].copy_from_slice(&[10, 0, 0, 2]);
            frame[34..36].copy_from_slice(&5060_u16.to_be_bytes());
            frame[36..38].copy_from_slice(&5060_u16.to_be_bytes());
            frame[38..42].copy_from_slice(&sequence.to_be_bytes());
            frame[46] = 0x50;
            frame.extend_from_slice(payload);
            output.extend_from_slice(&(index as u32).to_le_bytes());
            output.extend_from_slice(&0_u32.to_le_bytes());
            output.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            output.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            output.extend_from_slice(&frame);
        }
        output
    }

    #[test]
    fn groups_invite_response_and_sdp_without_reimplementing_sdp() {
        let sdp = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=Call\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 12000 RTP/AVP 0\r\n";
        let invite = format!(
            "INVITE sip:b@host SIP/2.0\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-1\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>\r\nCall-ID: call-1\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
            sdp.len()
        );
        let response = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-1\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>;tag=b\r\nCall-ID: call-1\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n";
        let mut report = SipReport::default();
        let a = "10.0.0.1:5060".parse().unwrap();
        let b = "10.0.0.2:5060".parse().unwrap();
        record_message(
            &mut report,
            invite.as_bytes(),
            &CaptureFrameMeta {
                number: 1,
                timestamp_micros: 1,
                interface: "0".into(),
            },
            a,
            b,
            "UDP",
        );
        record_message(
            &mut report,
            response,
            &CaptureFrameMeta {
                number: 2,
                timestamp_micros: 2,
                interface: "0".into(),
            },
            b,
            a,
            "UDP",
        );
        finish_report(&mut report, &HashMap::new());
        assert_eq!(report.transactions.len(), 1);
        assert_eq!(report.transactions[0].final_status, Some(200));
        assert_eq!(report.calls[0].dialog_count, 1);
        assert_eq!(report.media[0].address, "10.0.0.1");
    }

    #[test]
    fn reads_pcap_and_matches_sdp_media_to_shared_rtp_parser() {
        let sdp = "v=0\r\ns=Call\r\nc=IN IP4 10.0.0.2\r\nm=audio 12000 RTP/AVP 0\r\n";
        let invite = format!(
            "INVITE sip:b@host SIP/2.0\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-2\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>\r\nCall-ID: call-2\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
            sdp.len()
        );
        let mut rtp = vec![0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 7];
        rtp.extend_from_slice(&[1, 2, 3]);
        let bytes = pcap_udp(&[(invite.as_bytes(), 5060, 5060), (&rtp, 14000, 12000)]);
        let path =
            std::env::temp_dir().join(format!("streamscope-sip-test-{}.pcap", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        let result = analyze_pcap(&path);
        std::fs::remove_file(&path).unwrap();
        let report = result.unwrap();
        assert_eq!(report.sip_messages.len(), 1);
        assert_eq!(report.transactions[0].outcome, "抓包未见最终响应");
        assert_eq!(report.media[0].matched_rtp_packets, 1);
        assert_eq!(report.media[0].matched_ssrc, [7]);
        assert_eq!(report.media[0].first_rtp_packet, Some(2));
        assert_eq!(report.media[0].last_rtp_packet, Some(2));
        assert_eq!(report.media[0].first_rtp_timestamp_micros, Some(1_000_000));
    }

    #[test]
    fn reassembles_split_tcp_sip_message() {
        let request = b"OPTIONS sip:b@host SIP/2.0\r\nVia: SIP/2.0/TCP a;branch=z9hG4bK-3\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>\r\nCall-ID: call-3\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
        let split = 20;
        let bytes = pcap_tcp(&[
            (&request[..split], 100),
            (&request[split..], 100 + split as u32),
        ]);
        let path = std::env::temp_dir().join(format!(
            "streamscope-sip-tcp-test-{}.pcap",
            std::process::id()
        ));
        std::fs::write(&path, bytes).unwrap();
        let result = analyze_pcap(&path);
        std::fs::remove_file(&path).unwrap();
        let report = result.unwrap();
        assert_eq!(report.sip_messages.len(), 1);
        assert_eq!(report.sip_messages[0].method.as_deref(), Some("OPTIONS"));
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.code != "sip_tcp_partial")
        );
    }

    #[test]
    fn options_simulator_echoes_transaction_headers() {
        let request = b"OPTIONS sip:b@host SIP/2.0\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-a\r\nVia: SIP/2.0/UDP proxy;branch=z9hG4bK-b\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>\r\nCall-ID: check-1\r\nCSeq: 7 OPTIONS\r\nContent-Length: 0\r\n\r\n";
        let response = options_response(request).unwrap().unwrap();
        let parsed = parse_message(&response).unwrap();
        assert_eq!(parsed.header("Call-ID"), Some("check-1"));
        assert_eq!(parsed.header("CSeq"), Some("7 OPTIONS"));
        assert_eq!(
            parsed
                .headers
                .iter()
                .filter(|(name, _)| name == "Via")
                .count(),
            2
        );
        assert!(matches!(
            parsed.start,
            StartLine::Response { status: 200, .. }
        ));
        assert_eq!(options_response(request).unwrap(), Some(response));
    }

    #[test]
    fn sdp_response_uses_body_byte_length() {
        let request = b"INVITE sip:b@host SIP/2.0\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-c\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>\r\nCall-ID: call-body\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n";
        let body = b"v=0\r\ns=Test\r\n";
        let response = build_response_with_body(
            &parse_datagram(request).unwrap(),
            200,
            "OK",
            "OPTIONS, INVITE, BYE",
            &[],
            Some("application/sdp"),
            body,
        )
        .unwrap();
        let parsed = parse_message(&response).unwrap();
        assert_eq!(parsed.header("Content-Length"), Some("13"));
        assert_eq!(parsed.body, body);
    }

    #[test]
    fn busy_scenario_returns_486_and_ignores_ack() {
        let invite = b"INVITE sip:b@host SIP/2.0\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-busy\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>\r\nCall-ID: busy-1\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n";
        let response = invite_busy_response(invite).unwrap().unwrap();
        assert!(matches!(
            parse_message(&response).unwrap().start,
            StartLine::Response { status: 486, .. }
        ));
        assert_eq!(invite_busy_response(invite).unwrap(), Some(response));
        let ack = b"ACK sip:b@host SIP/2.0\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-busy\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>;tag=b\r\nCall-ID: busy-1\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(invite_busy_response(ack).unwrap(), None);
    }

    #[test]
    fn tracks_dialog_ack_and_bye_in_both_directions() {
        let messages = [
            b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-i\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>;tag=b\r\nCall-ID: call-4\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"ACK sip:b@host SIP/2.0\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-a\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>;tag=b\r\nCall-ID: call-4\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"BYE sip:a@host SIP/2.0\r\nVia: SIP/2.0/UDP b;branch=z9hG4bK-b\r\nFrom: <sip:b@host>;tag=b\r\nTo: <sip:a@host>;tag=a\r\nCall-ID: call-4\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP b;branch=z9hG4bK-b\r\nFrom: <sip:b@host>;tag=b\r\nTo: <sip:a@host>;tag=a\r\nCall-ID: call-4\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n".as_slice(),
        ];
        let mut report = SipReport::default();
        let a = "10.0.0.1:5060".parse().unwrap();
        let b = "10.0.0.2:5060".parse().unwrap();
        for (index, message) in messages.into_iter().enumerate() {
            record_message(
                &mut report,
                message,
                &CaptureFrameMeta {
                    number: index as u64 + 1,
                    timestamp_micros: index as u64,
                    interface: "0".into(),
                },
                a,
                b,
                "UDP",
            );
        }
        finish_report(&mut report, &HashMap::new());
        assert_eq!(report.dialogs.len(), 1);
        assert_eq!(report.dialogs[0].invite_success_packet, Some(1));
        assert_eq!(report.dialogs[0].ack_packet, Some(2));
        assert_eq!(report.dialogs[0].bye_success_packet, Some(4));
        assert_eq!(report.calls[0].dialog_count, 1);
    }

    #[test]
    fn redacted_export_preserves_links_without_exposing_identifiers() {
        let mut report = SipReport::default();
        let request = b"OPTIONS sip:b@host SIP/2.0\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-private\r\nFrom: <sip:a@host>;tag=private-tag\r\nTo: <sip:b@host>\r\nCall-ID: private-call@example.test\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
        record_message(
            &mut report,
            request,
            &CaptureFrameMeta {
                number: 1,
                timestamp_micros: 1,
                interface: "0".into(),
            },
            "10.1.2.3:5060".parse().unwrap(),
            "10.4.5.6:5060".parse().unwrap(),
            "UDP",
        );
        finish_report(&mut report, &HashMap::new());
        let redacted = report.redacted();
        let json = serde_json::to_string(&redacted).unwrap();
        for secret in [
            "private-call",
            "private-tag",
            "z9hG4bK-private",
            "10.1.2.3",
            "10.4.5.6",
        ] {
            assert!(!json.contains(secret), "redacted report leaked {secret}");
        }
        assert_eq!(redacted.sip_messages[0].call_id.as_deref(), Some("call-1"));
        assert_eq!(redacted.transactions[0].call_id, "call-1");
        assert_eq!(report.transactions[0].call_id, "private-call@example.test");
    }

    #[test]
    fn observes_provisional_timing_cancel_and_fork_without_claiming_failure() {
        let messages = [
            "INVITE sip:b@host SIP/2.0\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-f\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>\r\nCall-ID: fork-call\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
            "SIP/2.0 180 Ringing\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-f\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>;tag=b1\r\nCall-ID: fork-call\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
            "CANCEL sip:b@host SIP/2.0\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-f\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>\r\nCall-ID: fork-call\r\nCSeq: 1 CANCEL\r\nContent-Length: 0\r\n\r\n",
            "SIP/2.0 487 Request Terminated\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-f\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>;tag=b1\r\nCall-ID: fork-call\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
            "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-f\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>;tag=b2\r\nCall-ID: fork-call\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
        ];
        let mut report = SipReport::default();
        let a = "10.0.0.1:5060".parse().unwrap();
        let b = "10.0.0.2:5060".parse().unwrap();
        for (index, message) in messages.iter().enumerate() {
            record_message(
                &mut report,
                message.as_bytes(),
                &CaptureFrameMeta {
                    number: index as u64 + 1,
                    timestamp_micros: index as u64 * 100_000,
                    interface: "0".into(),
                },
                a,
                b,
                "UDP",
            );
        }
        finish_report(&mut report, &HashMap::new());
        let invite = report
            .transactions
            .iter()
            .find(|item| item.method == "INVITE")
            .unwrap();
        assert_eq!(invite.provisional_statuses, [180]);
        assert_eq!(invite.final_statuses, [487, 200]);
        assert_eq!(invite.first_response_ms, Some(100));
        assert_eq!(invite.final_response_ms, Some(400));
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "sip_cancel")
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "sip_fork_candidates")
        );
    }

    #[test]
    fn validates_sdp_answer_media_order_pt_and_direction() {
        let offer = SipSdpExchange {
            packet_number: 1,
            call_id: "c".into(),
            cseq: "1 INVITE".into(),
            method: "INVITE".into(),
            message_kind: "request".into(),
            origin_session_id: Some("1".into()),
            origin_session_version: Some("1".into()),
            media: vec![SipSdpMedia {
                media_type: "audio".into(),
                address: Some("10.0.0.1".into()),
                port: 10000,
                protocol: "RTP/AVP".into(),
                payload_types: vec![0, 8],
                direction: "sendonly".into(),
            }],
            paired_packet: None,
            assessment: String::new(),
        };
        let mut answer = offer.clone();
        answer.media[0].payload_types = vec![8];
        answer.media[0].direction = "recvonly".into();
        assert!(
            assess_sdp_answer(&offer, &answer)
                .unwrap()
                .contains("接受 1/1")
        );
        answer.media[0].payload_types = vec![96];
        assert!(
            assess_sdp_answer(&offer, &answer)
                .unwrap_err()
                .contains("PT")
        );
        answer.media[0].port = 0;
        assert!(
            assess_sdp_answer(&offer, &answer)
                .unwrap()
                .contains("接受 0/1")
        );
    }
}
