//! Bounded, signaling-only UAC scenarios derived from a selected UDP SIP dialog.
use crate::{SipMessage, StartLine, parse_datagram};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use streamscope_capture::{TransportPayload, visit_transport_packets};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayStep {
    pub packet_number: u64,
    pub delay_ms: u64,
    pub method: String,
    pub local_user: String,
    pub remote_user: String,
    pub expected_status: Option<u16>,
    pub inactive_media: Option<ReplayMedia>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayMedia {
    pub kind: String,
    pub payload_type: u8,
    pub clock_rate: u32,
    pub encoding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayPlan {
    pub call_id: String,
    pub capture_source: String,
    pub capture_target: String,
    pub steps: Vec<ReplayStep>,
    pub warnings: Vec<String>,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayOverride {
    pub packet_number: u64,
    pub delay_ms: u64,
    pub expected_status: Option<u16>,
}

pub fn apply_replay_overrides(
    plan: &mut ReplayPlan,
    overrides: &[ReplayOverride],
) -> Result<(), String> {
    if !plan.executable || overrides.len() != plan.steps.len() {
        return Err("场景不完整或编辑步骤数量不匹配".into());
    }
    let later_bye = plan
        .steps
        .iter()
        .enumerate()
        .map(|(index, _)| {
            plan.steps[index + 1..]
                .iter()
                .any(|later| later.method == "BYE")
        })
        .collect::<Vec<_>>();
    let mut total_delay = 0_u64;
    for (index, (step, edit)) in plan.steps.iter().zip(overrides).enumerate() {
        if step.packet_number != edit.packet_number || edit.delay_ms > 10_000 {
            return Err(format!("第 {} 步的抓包号或等待时间无效", index + 1));
        }
        total_delay += edit.delay_ms;
        if total_delay > 60_000 {
            return Err("场景总等待时间不得超过 60 秒".into());
        }
        if step.method == "ACK" {
            if edit.expected_status.is_some() {
                return Err("ACK 不等待最终响应".into());
            }
        } else if !edit
            .expected_status
            .is_some_and(|status| (200..=699).contains(&status))
        {
            return Err(format!(
                "第 {} 步必须设置 200–699 的预期最终状态",
                index + 1
            ));
        }
        if step.method == "INVITE"
            && later_bye[index]
            && !edit
                .expected_status
                .is_some_and(|status| (200..300).contains(&status))
        {
            return Err("包含 BYE 的呼叫场景必须预期 INVITE 成功（2xx）".into());
        }
    }
    for (step, edit) in plan.steps.iter_mut().zip(overrides) {
        step.delay_ms = edit.delay_ms;
        step.expected_status = edit.expected_status;
    }
    Ok(())
}

struct Captured {
    packet_number: u64,
    timestamp_micros: u64,
    source: SocketAddr,
    destination: SocketAddr,
    message: SipMessage,
}

pub fn compile_replay_plan(
    path: &Path,
    call_id: &str,
    capture_source: SocketAddr,
) -> Result<ReplayPlan, String> {
    if call_id.is_empty() || call_id.len() > 256 {
        return Err("需要选择有效的 Call-ID".into());
    }
    let mut captured = Vec::new();
    let mut truncated = false;
    visit_transport_packets(path, |packet| {
        if let TransportPayload::Udp(data) = packet.payload
            && let Ok(message) = parse_datagram(data)
            && message.header("Call-ID") == Some(call_id)
        {
            if captured.len() < 512 {
                captured.push(Captured {
                    packet_number: packet.meta.number,
                    timestamp_micros: packet.meta.timestamp_micros,
                    source: packet.source,
                    destination: packet.destination,
                    message,
                });
            } else {
                truncated = true;
            }
        }
        Ok(())
    })
    .map_err(|error| error.to_string())?;
    let first = captured
        .iter()
        .find(|item| {
            item.source == capture_source && matches!(item.message.start, StartLine::Request { .. })
        })
        .ok_or("选定 Call-ID 中没有来自所选源端点的 UDP 请求")?;
    let capture_target = first.destination;
    let mut warnings = Vec::new();
    if truncated {
        warnings.push("该 Call-ID 超过 512 条 UDP SIP 消息，场景已截断".into());
    }
    let mut steps = Vec::new();
    let mut previous_request_time = None;
    let mut seen_requests = HashSet::new();
    for (index, item) in captured.iter().enumerate() {
        if item.source != capture_source {
            if matches!(item.message.start, StartLine::Request { .. }) {
                warnings.push(format!(
                    "包 #{} 是对端主动请求，当前 UAC 执行器不支持",
                    item.packet_number
                ));
            }
            continue;
        }
        let StartLine::Request { method, uri } = &item.message.start else {
            continue;
        };
        if item.destination != capture_target {
            warnings.push(format!(
                "包 #{} 的目标端点发生变化，当前不支持跨目标路由",
                item.packet_number
            ));
            continue;
        }
        if !matches!(
            method.as_str(),
            "OPTIONS" | "INVITE" | "ACK" | "BYE" | "REGISTER"
        ) {
            warnings.push(format!(
                "包 #{} 的 {method} 尚无安全的主动执行模板",
                item.packet_number
            ));
            continue;
        }
        if item.message.header("Authorization").is_some()
            || item.message.header("Proxy-Authorization").is_some()
        {
            warnings.push(format!(
                "包 #{} 含认证头；不会重放抓包中的凭据",
                item.packet_number
            ));
            continue;
        }
        let cseq = item.message.header("CSeq").unwrap_or_default();
        let branch = item.message.header("Via").unwrap_or_default();
        let key = (method.as_str(), cseq, branch);
        if !seen_requests.insert(key) {
            continue;
        }
        let local_user = sip_user(item.message.header("From").unwrap_or_default());
        if local_user.is_none() {
            warnings.push(format!(
                "包 #{} 的 From 用户无法安全提取，禁止推测发送身份",
                item.packet_number
            ));
        }
        let local_user = local_user.unwrap_or_default().to_string();
        let remote_user = if method == "REGISTER" {
            local_user.clone()
        } else if method == "OPTIONS" {
            sip_user(uri).unwrap_or_default().to_string()
        } else {
            sip_user(uri)
                .or_else(|| sip_user(item.message.header("To").unwrap_or_default()))
                .unwrap_or_default()
                .to_string()
        };
        if method == "INVITE" && remote_user.is_empty() {
            warnings.push(format!(
                "包 #{} 的目标 SIP URI 缺少可安全提取的用户部分",
                item.packet_number
            ));
        }
        let inactive_media = if method == "INVITE" {
            match std::str::from_utf8(&item.message.body)
                .ok()
                .and_then(|body| streamscope_sdp::parse_sdp(body).ok())
            {
                Some(sdp) => sdp.media.iter().find_map(|media| {
                    if media.port == 0 || !media.protocol.eq_ignore_ascii_case("RTP/AVP") {
                        return None;
                    }
                    let pt = *media.payload_types.first()?;
                    let mapping = media.rtp_maps.get(&pt);
                    let (encoding, clock_rate) = match (pt, mapping) {
                        (_, Some(map)) => (map.encoding.clone(), map.clock_rate),
                        (0, None) => ("PCMU".into(), 8000),
                        (8, None) => ("PCMA".into(), 8000),
                        (9, None) => ("G722".into(), 8000),
                        _ => return None,
                    };
                    Some(ReplayMedia {
                        kind: media.media_type.clone(),
                        payload_type: pt,
                        clock_rate,
                        encoding,
                    })
                }),
                None => None,
            }
        } else {
            None
        };
        if method == "INVITE" && inactive_media.is_none() {
            warnings.push(format!(
                "包 #{} 的 INVITE 没有可构造 inactive 媒体的 RTP/AVP SDP",
                item.packet_number
            ));
        }
        let expected_status = if method == "ACK" {
            None
        } else {
            let final_responses = captured[index + 1..]
                .iter()
                .filter(|candidate| {
                    candidate.source == capture_target
                        && candidate.destination == capture_source
                        && candidate.message.header("CSeq") == Some(cseq)
                        && candidate.message.header("Via") == item.message.header("Via")
                        && matches!(
                            candidate.message.start,
                            StartLine::Response {
                                status: 200..=699,
                                ..
                            }
                        )
                })
                .collect::<Vec<_>>();
            let distinct = final_responses
                .iter()
                .map(|response| {
                    (
                        response.message.header("To"),
                        response.message.start.clone(),
                    )
                })
                .collect::<Vec<_>>();
            if method == "INVITE" && distinct.iter().any(|other| other != &distinct[0]) {
                warnings.push(format!(
                    "包 #{} 的 INVITE 有多个最终响应，可能存在分叉",
                    item.packet_number
                ));
            }
            final_responses
                .first()
                .and_then(|response| match response.message.start {
                    StartLine::Response { status, .. } => Some(status),
                    _ => None,
                })
        };
        if method != "ACK" && expected_status.is_none() {
            warnings.push(format!(
                "包 #{} 的 {method} 在抓包中没有匹配的最终响应",
                item.packet_number
            ));
        }
        let delay_ms = previous_request_time.map_or(0, |previous: u64| {
            item.timestamp_micros
                .saturating_sub(previous)
                .div_ceil(1000)
                .min(1000)
        });
        previous_request_time = Some(item.timestamp_micros);
        steps.push(ReplayStep {
            packet_number: item.packet_number,
            delay_ms,
            method: method.clone(),
            local_user,
            remote_user,
            expected_status,
            inactive_media,
        });
    }
    if steps.is_empty() {
        return Err("选定源端点没有可用的 SIP 请求步骤".into());
    }
    if steps.len() > 24 {
        warnings.push("场景超过 24 个请求步骤，需缩小抓包范围".into());
    }
    for pair in steps.windows(2) {
        if pair[0].method == "INVITE" && pair[1].method != "ACK" {
            warnings.push(format!(
                "包 #{} 的 INVITE 后缺少本端 ACK，不能安全继续",
                pair[0].packet_number
            ));
        }
    }
    if steps.last().is_some_and(|step| step.method == "INVITE") {
        warnings.push("抓包以 INVITE 结束，缺少本端 ACK".into());
    }
    for (index, step) in steps.iter().enumerate() {
        if step.method == "ACK"
            && !steps[..index]
                .iter()
                .any(|earlier| earlier.method == "INVITE")
        {
            warnings.push(format!(
                "包 #{} 的 ACK 没有对应的本端 INVITE",
                step.packet_number
            ));
        }
        if step.method == "BYE"
            && !steps[..index].iter().any(|earlier| {
                earlier.method == "INVITE"
                    && earlier
                        .expected_status
                        .is_some_and(|status| (200..300).contains(&status))
            })
        {
            warnings.push(format!(
                "包 #{} 的 BYE 没有已确认的成功 INVITE",
                step.packet_number
            ));
        }
        if step.method == "INVITE"
            && step
                .expected_status
                .is_some_and(|status| (200..300).contains(&status))
            && !steps[index + 1..].iter().any(|later| later.method == "BYE")
        {
            warnings.push(format!(
                "包 #{} 的成功呼叫没有本端 BYE，执行后无法主动结束",
                step.packet_number
            ));
        }
    }
    let executable = warnings.is_empty();
    Ok(ReplayPlan {
        call_id: call_id.into(),
        capture_source: capture_source.to_string(),
        capture_target: capture_target.to_string(),
        steps,
        warnings,
        executable,
    })
}

fn sip_user(value: &str) -> Option<&str> {
    let start = value.find("sip:")? + 4;
    let address = value[start..].split(['>', ';']).next()?;
    let (value, _) = address.split_once('@')?;
    (!value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.+".contains(&byte)))
    .then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_override_does_not_partially_change_plan() {
        let step = |packet_number| ReplayStep {
            packet_number,
            delay_ms: 0,
            method: "OPTIONS".into(),
            local_user: "alice".into(),
            remote_user: String::new(),
            expected_status: Some(200),
            inactive_media: None,
        };
        let mut plan = ReplayPlan {
            call_id: "test".into(),
            capture_source: String::new(),
            capture_target: String::new(),
            steps: vec![step(1), step(2)],
            warnings: Vec::new(),
            executable: true,
        };
        let edits = [
            ReplayOverride {
                packet_number: 1,
                delay_ms: 100,
                expected_status: Some(202),
            },
            ReplayOverride {
                packet_number: 99,
                delay_ms: 100,
                expected_status: Some(200),
            },
        ];
        assert!(apply_replay_overrides(&mut plan, &edits).is_err());
        assert_eq!(plan.steps[0].delay_ms, 0);
        assert_eq!(plan.steps[0].expected_status, Some(200));
    }
}
