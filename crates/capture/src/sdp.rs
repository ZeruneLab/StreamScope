use crate::network::Endpoint;
use std::collections::BTreeMap;

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
    codecs: BTreeMap<u8, Codec>,
}
#[derive(Clone)]
struct Request {
    uri: String,
    transport: String,
    source: Endpoint,
    destination: Endpoint,
}

#[derive(Clone)]
pub(crate) struct UdpBinding {
    pub source: Endpoint,
    pub destination: Endpoint,
    pub source_port_known: bool,
    pub codecs: BTreeMap<u8, Codec>,
    pub session: Option<String>,
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
}

impl Session {
    pub fn observe(&mut self, text: &str, source: &Endpoint, destination: &Endpoint) {
        let Some((header, body)) = text.split_once("\r\n\r\n") else {
            return;
        };
        let first = header.lines().next().unwrap_or_default();
        let cseq = field(header, "cseq").unwrap_or_default().to_string();
        if !first.starts_with("RTSP/") {
            if first.starts_with("SETUP ") {
                if self.requests.len() >= 128 {
                    self.requests.pop_first();
                }
                self.requests.insert(
                    cseq,
                    Request {
                        uri: first.split_whitespace().nth(1).unwrap_or_default().into(),
                        transport: field(header, "transport").unwrap_or_default().into(),
                        source: source.clone(),
                        destination: destination.clone(),
                    },
                );
            }
            if first.starts_with("ANNOUNCE ") {
                self.read_sdp(body);
            }
            return;
        }
        if first.split_whitespace().nth(1) != Some("200") {
            return;
        }
        if body.starts_with("v=0")
            || field(header, "content-type")
                .is_some_and(|value| value.to_ascii_lowercase().contains("application/sdp"))
        {
            self.read_sdp(body);
        }
        if let Some(id) = field(header, "session") {
            self.session_id = Some(id.split(';').next().unwrap_or_default().trim().into());
        }
        let Some(request) = self.requests.remove(&cseq) else {
            return;
        };
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
        if let Some((rtp, rtcp)) = parameter_pair(transport, "interleaved") {
            if rtp > u16::from(u8::MAX) {
                return;
            }
            if let Some(previous) = self.channels.insert(rtp as u8, codecs.clone()) {
                self.codec_changed |= previous != codecs;
            }
            if let Some(rtcp) = rtcp.filter(|value| *value <= u16::from(u8::MAX)) {
                self.rtcp_channels.insert(rtcp as u8, rtp as u8);
            }
        } else if let Some((client_port, _)) = parameter_pair(transport, "client_port")
            .or_else(|| parameter_pair(&request.transport, "client_port"))
        {
            let server_port = parameter_pair(transport, "server_port").map(|value| value.0);
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
                    source_port_known: server_port.is_some(),
                    codecs,
                    session: self.session_id.clone(),
                });
            }
        }
    }

    fn read_sdp(&mut self, body: &str) {
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
                track = Some(Track {
                    media_type: media.split_whitespace().next().unwrap_or_default().into(),
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
            }
        }
        if let Some(current) = track {
            tracks.push(current);
        }
        if !tracks.is_empty() {
            self.tracks = tracks;
        }
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
