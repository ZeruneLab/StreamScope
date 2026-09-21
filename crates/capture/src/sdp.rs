use crate::network::Endpoint;
use std::collections::BTreeMap;
use streamscope_core::{ProtocolAnalysis, RtspTransactionRecord, SdpMediaSummary};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Codec {
    pub name: String,
    pub clock_rate: u32,
    pub channels: Option<u16>,
    pub media_type: String,
    pub fmtp: BTreeMap<String, String>,
}

#[derive(Clone, Default)]
struct Track {
    control: String,
    media_type: String,
    port: u16,
    protocol: String,
    payload_types: Vec<u8>,
    codecs: BTreeMap<u8, Codec>,
    frame_rate: Option<String>,
    frame_size: Option<String>,
}
#[derive(Clone)]
struct Request {
    method: String,
    uri: String,
    transport: String,
    source: Endpoint,
    destination: Endpoint,
    timestamp_micros: u64,
}

#[derive(Clone)]
pub(crate) struct UdpBinding {
    pub source: Endpoint,
    pub destination: Endpoint,
    pub rtcp_source: Endpoint,
    pub rtcp_destination: Endpoint,
    pub source_port_known: bool,
    pub codecs: BTreeMap<u8, Codec>,
    pub session: Option<String>,
    pub control: String,
}

#[derive(Default)]
pub(crate) struct Session {
    tracks: Vec<Track>,
    requests: BTreeMap<String, Request>,
    pub channels: BTreeMap<u8, BTreeMap<u8, Codec>>,
    pub rtcp_channels: BTreeMap<u8, u8>,
    pub udp: Vec<UdpBinding>,
    pub session_id: Option<String>,
    pub codec_changed: bool,
    pub protocol: ProtocolAnalysis,
    pub sdp: Option<String>,
}

impl Session {
    pub fn observe(
        &mut self,
        text: &str,
        source: &Endpoint,
        destination: &Endpoint,
        timestamp_micros: u64,
    ) {
        let Some((header, body)) = text.split_once("\r\n\r\n") else {
            return;
        };
        let first = header.lines().next().unwrap_or_default();
        let cseq = field(header, "cseq").unwrap_or_default().to_string();
        if !first.starts_with("RTSP/") {
            let mut parts = first.split_whitespace();
            let method = parts.next().unwrap_or_default().to_string();
            let uri = parts.next().unwrap_or_default().to_string();
            if !cseq.is_empty() {
                if self.requests.len() >= 128 {
                    self.requests.pop_first();
                }
                self.requests.insert(
                    cseq,
                    Request {
                        method,
                        uri,
                        transport: field(header, "transport").unwrap_or_default().into(),
                        source: source.clone(),
                        destination: destination.clone(),
                        timestamp_micros,
                    },
                );
            }
            self.protocol.authenticated |= field(header, "authorization").is_some();
            if first.starts_with("ANNOUNCE ") {
                self.read_sdp(body);
            }
            return;
        }
        self.protocol.connected = true;
        let status_code = first
            .split_whitespace()
            .nth(1)
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(0);
        let mut reason = first.splitn(3, ' ').nth(2).unwrap_or_default().to_string();
        if field(header, "x-streamscope-truncated").is_some() {
            reason.push_str("（响应头未完整终止）");
            if !self
                .protocol
                .errors
                .iter()
                .any(|error| error.contains("响应头未完整终止"))
            {
                self.protocol
                    .errors
                    .push("至少一个 RTSP 响应头未完整终止，仅状态行和 CSeq 可验证".into());
            }
        }
        if let Some(server) = field(header, "server") {
            self.protocol.server = Some(server.into());
        }
        if let Some(content_base) = field(header, "content-base") {
            self.protocol.content_base = Some(content_base.into());
        }
        if status_code == 200
            && (body.starts_with("v=0")
                || field(header, "content-type")
                    .is_some_and(|value| value.to_ascii_lowercase().contains("application/sdp")))
        {
            self.read_sdp(body);
        }
        if let Some(public) = field(header, "public") {
            self.protocol.public_methods = public
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect();
        }
        if status_code < 300
            && let Some(id) = field(header, "session")
        {
            self.session_id = Some(id.split(';').next().unwrap_or_default().trim().into());
            self.protocol.session_id = self.session_id.clone();
        }
        let Some(request) = self.requests.remove(&cseq) else {
            return;
        };
        self.protocol.transactions.push(RtspTransactionRecord {
            method: request.method.clone(),
            uri: request.uri.clone(),
            status_code,
            reason,
            cseq: cseq.parse().ok(),
            elapsed_ms: timestamp_micros.saturating_sub(request.timestamp_micros) / 1_000,
        });
        if status_code != 200 || request.method != "SETUP" {
            return;
        }
        let track = self
            .tracks
            .iter()
            .find(|track| {
                !track.control.is_empty()
                    && track.control != "*"
                    && (request.uri == track.control
                        || request.uri.ends_with(&format!("/{}", track.control)))
            })
            .or_else(|| (self.tracks.len() == 1).then(|| &self.tracks[0]));
        let Some(track) = track else {
            return;
        };
        let codecs = track.codecs.clone();
        let transport = field(header, "transport").unwrap_or(&request.transport);
        self.protocol.negotiated_transport = Some(
            if transport.to_ascii_lowercase().contains("tcp") {
                "tcp"
            } else {
                "udp"
            }
            .into(),
        );
        if let Some((rtp, rtcp)) = parameter_pair(transport, "interleaved") {
            if rtp > u16::from(u8::MAX) {
                return;
            }
            if let Some(previous) = self.channels.insert(rtp as u8, codecs.clone()) {
                self.codec_changed |= previous != codecs;
            }
            if let Some(rtcp) = rtcp.filter(|value| *value <= u16::from(u8::MAX)) {
                self.rtcp_channels.insert(rtcp as u8, rtp as u8);
                self.protocol.interleaved_rtcp_channel = Some(rtcp as u8);
            }
            self.protocol.interleaved_rtp_channel = Some(rtp as u8);
        } else if let Some((client_port, client_rtcp_port)) =
            parameter_pair(transport, "client_port")
                .or_else(|| parameter_pair(&request.transport, "client_port"))
        {
            let server_ports = parameter_pair(transport, "server_port");
            let server_port = server_ports.map(|value| value.0);
            let server_rtcp_port = server_ports
                .and_then(|value| value.1)
                .or_else(|| server_port.and_then(|value| value.checked_add(1)))
                .unwrap_or(0);
            let client_rtcp_port = client_rtcp_port
                .or_else(|| client_port.checked_add(1))
                .unwrap_or(client_port);
            if self.udp.len() < 128 {
                self.udp.push(UdpBinding {
                    source: Endpoint {
                        ip: request.destination.ip,
                        port: server_port.unwrap_or(0),
                    },
                    destination: Endpoint {
                        ip: request.source.ip,
                        port: client_port,
                    },
                    rtcp_source: Endpoint {
                        ip: request.destination.ip,
                        port: server_rtcp_port,
                    },
                    rtcp_destination: Endpoint {
                        ip: request.source.ip,
                        port: client_rtcp_port,
                    },
                    source_port_known: server_port.is_some(),
                    codecs,
                    session: self.session_id.clone(),
                    control: track.control.clone(),
                });
            }
        }
    }

    fn read_sdp(&mut self, body: &str) {
        self.sdp = Some(body.to_string());
        let mut tracks = Vec::new();
        let mut track: Option<Track> = None;
        for line in body.lines().map(str::trim) {
            if let Some(media) = line.strip_prefix("m=") {
                if let Some(previous) = track.take() {
                    tracks.push(previous);
                }
                if tracks.len() >= 128 {
                    break;
                }
                let mut parts = media.split_whitespace();
                let media_type = parts.next().unwrap_or_default().to_string();
                let port = parts
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0);
                let protocol = parts.next().unwrap_or_default().to_string();
                let payload_types = parts.filter_map(|value| value.parse::<u8>().ok()).collect();
                track = Some(Track {
                    media_type,
                    port,
                    protocol,
                    payload_types,
                    ..Track::default()
                });
            } else if let Some(current) = track.as_mut() {
                if let Some(control) = line.strip_prefix("a=control:") {
                    current.control = control.into();
                }
                if let Some(mapping) = line.strip_prefix("a=rtpmap:") {
                    let Some((pt, descriptor)) = mapping.split_once(' ') else {
                        continue;
                    };
                    let Ok(pt) = pt.parse::<u8>() else {
                        continue;
                    };
                    let mut parts = descriptor.trim().split('/');
                    let name = parts.next().unwrap_or_default().to_ascii_uppercase();
                    let Some(clock_rate) = parts
                        .next()
                        .and_then(|value| value.parse::<u32>().ok())
                        .filter(|value| *value > 0)
                    else {
                        continue;
                    };
                    let channels = parts.next().and_then(|value| value.parse::<u16>().ok());
                    current.codecs.insert(
                        pt,
                        Codec {
                            name,
                            clock_rate,
                            channels,
                            media_type: current.media_type.clone(),
                            fmtp: BTreeMap::new(),
                        },
                    );
                }
                if let Some(mapping) = line.strip_prefix("a=fmtp:")
                    && let Some((pt, parameters)) = mapping.split_once(' ')
                    && let Ok(pt) = pt.parse::<u8>()
                    && let Some(codec) = current.codecs.get_mut(&pt)
                {
                    codec.fmtp = parameters
                        .split(';')
                        .filter_map(|parameter| {
                            let (key, value) = parameter.trim().split_once('=')?;
                            Some((key.to_ascii_lowercase(), value.trim().into()))
                        })
                        .collect();
                }
                if let Some(value) = line.strip_prefix("a=framerate:") {
                    current.frame_rate = Some(value.trim().into());
                }
                if let Some(value) = line.strip_prefix("a=framesize:") {
                    current.frame_size = value
                        .split_once(' ')
                        .map(|(_, size)| size.trim().to_string());
                }
            }
        }
        if let Some(current) = track {
            tracks.push(current);
        }
        if !tracks.is_empty() {
            self.tracks = tracks;
            self.protocol.media = self
                .tracks
                .iter()
                .map(|track| {
                    let first_codec = track
                        .payload_types
                        .iter()
                        .find_map(|payload_type| track.codecs.get(payload_type));
                    SdpMediaSummary {
                        media_type: track.media_type.clone(),
                        port: track.port,
                        protocol: track.protocol.clone(),
                        payload_types: track.payload_types.clone(),
                        codec: first_codec.map(|codec| codec.name.clone()),
                        clock_rate: first_codec.map(|codec| codec.clock_rate),
                        channels: first_codec.and_then(|codec| codec.channels),
                        fmtp: first_codec
                            .map(|codec| codec.fmtp.clone())
                            .unwrap_or_default(),
                        control: (!track.control.is_empty()).then(|| track.control.clone()),
                        resolved_control: self.resolve_control(&track.control),
                        frame_rate: track.frame_rate.clone(),
                        frame_size: track.frame_size.clone(),
                    }
                })
                .collect();
        }
    }

    fn resolve_control(&self, control: &str) -> Option<String> {
        if control.is_empty() {
            return None;
        }
        if control.starts_with("rtsp://") || control.starts_with("rtsps://") {
            return Some(control.into());
        }
        let base = self.protocol.content_base.as_deref()?;
        Some(format!(
            "{}/{}",
            base.trim_end_matches('/'),
            control.trim_start_matches('/')
        ))
    }

    pub fn finish_pending_transactions(&mut self) {
        for (cseq, request) in std::mem::take(&mut self.requests) {
            self.protocol.transactions.push(RtspTransactionRecord {
                method: request.method,
                uri: request.uri,
                status_code: 0,
                reason: "抓包中未见响应".into(),
                cseq: cseq.parse().ok(),
                elapsed_ms: 0,
            });
        }
        self.protocol
            .transactions
            .sort_by_key(|transaction| transaction.cseq);
    }

    pub fn codec(&self, channel: u8, pt: u8) -> Option<Codec> {
        if let Some(mapping) = self.channels.get(&channel) {
            return mapping.get(&pt).cloned();
        }
        let mut candidates = self.tracks.iter().filter_map(|track| track.codecs.get(&pt));
        let first = candidates.next()?;
        candidates
            .all(|other| other == first)
            .then(|| first.clone())
    }
}

fn field<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}
fn parameter_pair(transport: &str, name: &str) -> Option<(u16, Option<u16>)> {
    let value = transport.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        key.eq_ignore_ascii_case(name).then_some(value)
    })?;
    let mut ports = value.split('-');
    Some((
        ports.next()?.parse().ok()?,
        ports.next().and_then(|port| port.parse().ok()),
    ))
}

pub(crate) fn static_codec(pt: u8) -> Option<Codec> {
    let (name, clock_rate) = match pt {
        0 => ("PCMU", 8_000),
        3 => ("GSM", 8_000),
        4 => ("G723", 8_000),
        5 | 6 => ("DVI4", if pt == 5 { 8_000 } else { 16_000 }),
        8 => ("PCMA", 8_000),
        9 => ("G722", 8_000),
        10 | 11 => ("L16", 44_100),
        14 => ("MPA", 90_000),
        18 => ("G729", 8_000),
        26 => ("JPEG", 90_000),
        31 => ("H261", 90_000),
        32 => ("MPV", 90_000),
        33 => ("MP2T", 90_000),
        34 => ("H263", 90_000),
        _ => return None,
    };
    Some(Codec {
        name: name.into(),
        clock_rate,
        channels: matches!(pt, 0 | 3 | 4 | 5 | 6 | 8 | 9 | 10 | 11 | 14 | 18).then_some(1),
        media_type: if matches!(pt, 26 | 31 | 32 | 33 | 34) {
            "video"
        } else {
            "audio"
        }
        .into(),
        fmtp: BTreeMap::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn endpoint(last: u8, port: u16) -> Endpoint {
        Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)),
            port,
        }
    }

    #[test]
    fn retains_sdp_and_pairs_failed_play_by_cseq() {
        let client = endpoint(1, 40_000);
        let server = endpoint(2, 554);
        let mut session = Session::default();
        session.observe(
            "DESCRIBE rtsp://192.0.2.2/live RTSP/1.0\r\nCSeq: 1\r\n\r\n",
            &client,
            &server,
            1_000,
        );
        let sdp = "v=0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:track1\r\n";
        session.observe(
            &format!(
                "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Base: rtsp://192.0.2.2/live/\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
                sdp.len()
            ),
            &server,
            &client,
            3_000,
        );
        session.observe(
            "PLAY rtsp://192.0.2.2/live/track1 RTSP/1.0\r\nCSeq: 2\r\nSession: abc\r\n\r\n",
            &client,
            &server,
            4_000,
        );
        session.observe(
            "RTSP/1.0 400 Bad Request\r\nCSeq: 2\r\n\r\n",
            &server,
            &client,
            5_000,
        );

        assert_eq!(session.sdp.as_deref(), Some(sdp));
        assert_eq!(session.protocol.media.len(), 1);
        assert_eq!(session.protocol.media[0].codec.as_deref(), Some("H264"));
        assert_eq!(
            session.protocol.media[0].resolved_control.as_deref(),
            Some("rtsp://192.0.2.2/live/track1")
        );
        assert!(session.protocol.transactions.iter().any(|transaction| {
            transaction.method == "PLAY"
                && transaction.cseq == Some(2)
                && transaction.status_code == 400
        }));
    }
}
