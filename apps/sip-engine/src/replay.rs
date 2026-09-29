use serde::Serialize;
use std::error::Error;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};
use streamscope_sip::{ReplayMedia, ReplayPlan, SipMessage, StartLine, parameter, parse_datagram};
use uuid::Uuid;

#[derive(Serialize)]
pub struct ReplayResult {
    pub target: String,
    pub local: String,
    pub source_call_id: String,
    pub steps: Vec<StepResult>,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct StepResult {
    pub capture_packet: u64,
    pub method: String,
    pub expected_status: Option<u16>,
    pub actual_status: Option<u16>,
    pub latency_ms: u128,
    pub outcome: String,
}

pub fn execute(plan: &ReplayPlan, target: SocketAddr) -> Result<ReplayResult, Box<dyn Error>> {
    if !plan.executable || plan.steps.is_empty() {
        return Err("场景含不支持或不完整的步骤，不能执行".into());
    }
    if target.port() == 0
        || target.ip().is_unspecified()
        || target.ip().is_multicast()
        || target.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
    {
        return Err("目标必须是单播设备 IP 和非零端口".into());
    }
    let bind = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let signal = UdpSocket::bind(bind)?;
    signal.connect(target)?;
    let local = signal.local_addr()?;
    let local_host = sip_host(local);
    let local_ip_host = if local.is_ipv4() {
        local.ip().to_string()
    } else {
        format!("[{}]", local.ip())
    };
    let remote_host = sip_host(target);
    let call_id = format!("{}@{}", Uuid::new_v4().simple(), local.ip());
    let from_tag = Uuid::new_v4().simple().to_string();
    let mut remote_tag = None;
    let mut invite_cseq = None;
    let mut invite_branch = None;
    let mut invite_final_status = None;
    let mut next_cseq = 1_u32;
    let mut media_sockets = None;
    let mut result = ReplayResult {
        target: target.to_string(),
        local: local.to_string(),
        source_call_id: plan.call_id.clone(),
        steps: Vec::new(),
        success: false,
        error: None,
    };
    for step in &plan.steps {
        if step.delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(step.delay_ms));
        }
        let method = step.method.as_str();
        let cseq = if method == "ACK" {
            invite_cseq.ok_or("ACK 前没有已发送的 INVITE")?
        } else {
            let number = next_cseq;
            next_cseq += 1;
            if method == "INVITE" {
                invite_cseq = Some(number);
            }
            number
        };
        let branch = if method == "ACK"
            && !invite_final_status.is_some_and(|status| (200..300).contains(&status))
        {
            invite_branch.clone().ok_or("ACK 缺少原 INVITE branch")?
        } else {
            format!("z9hG4bK-{}", Uuid::new_v4().simple())
        };
        if method == "INVITE" {
            invite_branch = Some(branch.clone());
            invite_final_status = None;
            remote_tag = None;
        }
        let media = if let Some(media) = step.inactive_media.as_ref() {
            if media_sockets.is_none() {
                media_sockets = Some(crate::call::bind_media_pair(local.ip())?);
            }
            let port = media_sockets.as_ref().unwrap().0.local_addr()?.port();
            Some(inactive_sdp(media, local.ip(), port)?)
        } else {
            None
        };
        let request_uri = if method == "REGISTER" || step.remote_user.is_empty() {
            format!("sip:{remote_host}")
        } else {
            format!("sip:{}@{remote_host}", step.remote_user)
        };
        let to_user = if method == "REGISTER" {
            &step.local_user
        } else {
            &step.remote_user
        };
        let to_uri = if method == "REGISTER" || !step.remote_user.is_empty() {
            format!("sip:{to_user}@{remote_host}")
        } else {
            format!("sip:{remote_host}")
        };
        let to_tag = remote_tag
            .as_deref()
            .map_or(String::new(), |tag| format!(";tag={tag}"));
        let body = media.as_deref().unwrap_or("");
        let content_type = if media.is_some() {
            "Content-Type: application/sdp\r\n"
        } else {
            ""
        };
        let request = format!(
            "{method} {request_uri} SIP/2.0\r\nVia: SIP/2.0/UDP {local_host};branch={branch};rport\r\nMax-Forwards: 70\r\nFrom: <sip:{}@{}>;tag={from_tag}\r\nTo: <{to_uri}>{to_tag}\r\nCall-ID: {call_id}\r\nCSeq: {cseq} {method}\r\nContact: <sip:{}@{local_host};transport=udp>\r\n{content_type}Content-Length: {}\r\n\r\n{body}",
            step.local_user,
            local_ip_host,
            step.local_user,
            body.len()
        );
        let start = Instant::now();
        let response = if method == "ACK" {
            signal.send(request.as_bytes())?;
            None
        } else {
            match send_and_wait(&signal, request.as_bytes(), &call_id, cseq, method, &branch) {
                Ok(response) => Some(response),
                Err(error) => {
                    result.steps.push(StepResult {
                        capture_packet: step.packet_number,
                        method: step.method.clone(),
                        expected_status: step.expected_status,
                        actual_status: None,
                        latency_ms: start.elapsed().as_millis(),
                        outcome: "timeout_or_invalid_response".into(),
                    });
                    result.error = Some(error.to_string());
                    return Ok(result);
                }
            }
        };
        let actual_status = response.as_ref().and_then(|reply| match reply.start {
            StartLine::Response { status, .. } => Some(status),
            _ => None,
        });
        if method == "INVITE" {
            invite_final_status = actual_status;
        }
        let passed = method == "ACK" || actual_status == step.expected_status;
        result.steps.push(StepResult {
            capture_packet: step.packet_number,
            method: step.method.clone(),
            expected_status: step.expected_status,
            actual_status,
            latency_ms: start.elapsed().as_millis(),
            outcome: if passed { "passed" } else { "status_mismatch" }.into(),
        });
        if !passed {
            result.error = Some(format!(
                "抓包步骤 #{} 预期 {:?}，目标设备返回 {:?}",
                step.packet_number, step.expected_status, actual_status
            ));
            return Ok(result);
        }
        if method == "INVITE" {
            remote_tag = response
                .as_ref()
                .and_then(|reply| reply.header("To"))
                .and_then(|value| parameter(value, "tag"))
                .filter(|tag| valid_token(tag));
            if remote_tag.is_none() {
                result.steps.last_mut().unwrap().outcome = "invalid_dialog_tag".into();
                result.error = Some("INVITE 最终响应缺少有效 To tag，不能安全发送 ACK".into());
                return Ok(result);
            }
        }
    }
    result.success = true;
    Ok(result)
}

fn send_and_wait(
    socket: &UdpSocket,
    request: &[u8],
    call_id: &str,
    cseq: u32,
    method: &str,
    branch: &str,
) -> Result<SipMessage, Box<dyn Error>> {
    let mut buffer = [0_u8; 65_535];
    for timeout in [500, 1000, 2000] {
        socket.send(request)?;
        let deadline = Instant::now() + Duration::from_millis(timeout);
        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            socket.set_read_timeout(Some(remaining))?;
            match socket.recv(&mut buffer) {
                Ok(size) => {
                    let Ok(reply) = parse_datagram(&buffer[..size]) else {
                        continue;
                    };
                    let expected_cseq = format!("{cseq} {method}");
                    if reply.header("Call-ID") != Some(call_id)
                        || reply.header("CSeq") != Some(expected_cseq.as_str())
                        || reply
                            .header("Via")
                            .and_then(|via| parameter(via, "branch"))
                            .as_deref()
                            != Some(branch)
                    {
                        continue;
                    }
                    if matches!(
                        reply.start,
                        StartLine::Response {
                            status: 200..=699,
                            ..
                        }
                    ) {
                        return Ok(reply);
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
    Err("3.5 秒内未收到匹配的 SIP 最终响应".into())
}

fn inactive_sdp(
    media: &ReplayMedia,
    local_ip: std::net::IpAddr,
    port: u16,
) -> Result<String, Box<dyn Error>> {
    if !valid_token(&media.kind) || !valid_token(&media.encoding) || media.clock_rate == 0 {
        return Err("抓包中的媒体格式不适合生成 SDP".into());
    }
    let family = if local_ip.is_ipv4() { "IP4" } else { "IP6" };
    let id = Uuid::new_v4().as_u128() as u64;
    Ok(format!(
        "v=0\r\no=- {id} 1 IN {family} {local_ip}\r\ns=StreamScope signaling test\r\nc=IN {family} {local_ip}\r\nt=0 0\r\nm={} {port} RTP/AVP {}\r\na=rtpmap:{} {}/{}\r\na=inactive\r\n",
        media.kind, media.payload_type, media.payload_type, media.encoding, media.clock_rate
    ))
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.+".contains(&byte))
}

fn sip_host(address: SocketAddr) -> String {
    if address.is_ipv4() {
        address.to_string()
    } else {
        format!("[{}]:{}", address.ip(), address.port())
    }
}
