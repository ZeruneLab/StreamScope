use std::error::Error;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use streamscope_audio::encode_mulaw;
use streamscope_rtp::{encode_rtcp_goodbye, encode_rtcp_sender_report, encode_rtp};
use streamscope_sdp::{SdpMedia, SdpSession, parse_sdp};
use streamscope_sip::{SipMessage, StartLine, build_response_with_body, parameter, parse_datagram};
use uuid::Uuid;

const RTP_INTERVAL: Duration = Duration::from_millis(20);
const RTCP_INTERVAL: Duration = Duration::from_secs(5);
const MAX_CALLS: usize = 16;
type CallReply = (Vec<u8>, u16);

struct CallSession {
    call_id: String,
    remote_tag: String,
    local_tag: String,
    invite_cseq: u32,
    invite_via: String,
    signaling_peer: SocketAddr,
    answer: Vec<u8>,
    acked: bool,
    expires_at: Instant,
    next_response: Instant,
    response_interval: Duration,
    rtp_socket: UdpSocket,
    rtcp_socket: UdpSocket,
    remote_rtp: SocketAddr,
    remote_rtcp: SocketAddr,
    sequence: u16,
    timestamp: u32,
    ssrc: u32,
    packet_count: u32,
    octet_count: u32,
    next_rtp: Instant,
    next_rtcp: Instant,
    tone: [u8; 160],
}

#[derive(Default)]
pub struct CallEngine {
    sessions: Vec<CallSession>,
}

impl CallEngine {
    pub fn on_packet(
        &mut self,
        data: &[u8],
        peer: SocketAddr,
        signaling_port: u16,
    ) -> Result<Option<CallReply>, Box<dyn Error>> {
        let message = parse_datagram(data)?;
        if !matches!(&message.start, StartLine::Request { .. }) {
            return Ok(None);
        }
        match message.method() {
            Some("INVITE") => self.invite(&message, peer, signaling_port).map(Some),
            Some("ACK") => {
                self.ack(&message, peer);
                Ok(None)
            }
            Some("BYE") => self.bye(&message, peer).map(Some),
            Some("CANCEL") => self.cancel(&message, peer).map(Some),
            _ => Ok(None),
        }
    }

    fn invite(
        &mut self,
        message: &SipMessage,
        peer: SocketAddr,
        signaling_port: u16,
    ) -> Result<(Vec<u8>, u16), Box<dyn Error>> {
        let call_id = message.header("Call-ID").ok_or("INVITE 缺少 Call-ID")?;
        let remote_tag = message
            .header("From")
            .and_then(|value| parameter(value, "tag"))
            .ok_or("INVITE 缺少 From tag")?;
        let cseq = cseq_number(message).ok_or("INVITE CSeq 无效")?;
        let via = message.header("Via").ok_or("INVITE 缺少 Via")?;
        if let Some(session) = self.sessions.iter().find(|session| {
            session.call_id == call_id
                && session.remote_tag == remote_tag
                && session.invite_cseq == cseq
                && session.invite_via == via
                && session.signaling_peer == peer
        }) {
            return Ok((session.answer.clone(), 200));
        }
        if self.sessions.len() >= MAX_CALLS || self.sessions.iter().any(|s| s.call_id == call_id) {
            return rejected(message, 486, "Busy Here");
        }
        let offer = match std::str::from_utf8(&message.body)
            .ok()
            .filter(|_| {
                message
                    .header("Content-Type")
                    .is_some_and(|value| value.eq_ignore_ascii_case("application/sdp"))
            })
            .and_then(|body| parse_sdp(body).ok())
        {
            Some(offer) => offer,
            None => return rejected(message, 488, "Not Acceptable Here"),
        };
        let Some((index, remote_rtp)) = select_pcmu(&offer, peer.ip()) else {
            return rejected(message, 488, "Not Acceptable Here");
        };
        let local_ip = routed_local_ip(peer)?;
        let (rtp_socket, rtcp_socket) = bind_media_pair(local_ip)?;
        let rtp_port = rtp_socket.local_addr()?.port();
        let remote_rtcp = SocketAddr::new(remote_rtp.ip(), remote_rtp.port() + 1);
        let host = sip_host(local_ip);
        let contact = format!("<sip:streamscope@{host}:{signaling_port};transport=udp>");
        let sdp = answer_sdp(&offer, index, local_ip, rtp_port);
        let answer = build_response_with_body(
            message,
            200,
            "OK",
            "OPTIONS, INVITE, ACK, BYE, CANCEL",
            &[("Contact", &contact)],
            Some("application/sdp"),
            sdp.as_bytes(),
        )?;
        let local_tag = parse_datagram(&answer)?
            .header("To")
            .and_then(|value| parameter(value, "tag"))
            .ok_or("200 OK 缺少 To tag")?;
        let random = Uuid::new_v4().as_u128();
        let now = Instant::now();
        let tone = std::array::from_fn(|index| {
            let phase = (index % 8) as f64 * std::f64::consts::TAU / 8.0;
            encode_mulaw((phase.sin() * 10_000.0) as i16)
        });
        self.sessions.push(CallSession {
            call_id: call_id.into(),
            remote_tag,
            local_tag,
            invite_cseq: cseq,
            invite_via: via.into(),
            signaling_peer: peer,
            answer: answer.clone(),
            acked: false,
            expires_at: now + Duration::from_secs(32),
            next_response: now + Duration::from_millis(500),
            response_interval: Duration::from_millis(500),
            rtp_socket,
            rtcp_socket,
            remote_rtp,
            remote_rtcp,
            sequence: random as u16,
            timestamp: (random >> 16) as u32,
            ssrc: (random >> 48) as u32,
            packet_count: 0,
            octet_count: 0,
            next_rtp: now,
            next_rtcp: now,
            tone,
        });
        Ok((answer, 200))
    }

    fn ack(&mut self, message: &SipMessage, peer: SocketAddr) {
        let Some(call_id) = message.header("Call-ID") else {
            return;
        };
        let from = message
            .header("From")
            .and_then(|value| parameter(value, "tag"));
        let to = message
            .header("To")
            .and_then(|value| parameter(value, "tag"));
        let number = cseq_number(message);
        if let Some(session) = self.sessions.iter_mut().find(|session| {
            session.call_id == call_id
                && session.signaling_peer == peer
                && from.as_deref() == Some(session.remote_tag.as_str())
                && to.as_deref() == Some(session.local_tag.as_str())
                && number == Some(session.invite_cseq)
        }) {
            session.acked = true;
            session.next_rtp = Instant::now();
            session.next_rtcp = Instant::now();
        }
    }

    fn bye(
        &mut self,
        message: &SipMessage,
        peer: SocketAddr,
    ) -> Result<(Vec<u8>, u16), Box<dyn Error>> {
        let call_id = message.header("Call-ID");
        let from = message
            .header("From")
            .and_then(|value| parameter(value, "tag"));
        let to = message
            .header("To")
            .and_then(|value| parameter(value, "tag"));
        let number = cseq_number(message);
        let index = self.sessions.iter().position(|session| {
            call_id == Some(session.call_id.as_str())
                && session.signaling_peer == peer
                && from.as_deref() == Some(session.remote_tag.as_str())
                && to.as_deref() == Some(session.local_tag.as_str())
                && number.is_some_and(|value| value > session.invite_cseq)
        });
        let Some(index) = index else {
            return rejected(message, 481, "Call/Transaction Does Not Exist");
        };
        let response = build_response_with_body(
            message,
            200,
            "OK",
            "OPTIONS, INVITE, ACK, BYE, CANCEL",
            &[],
            None,
            &[],
        )?;
        let session = self.sessions.remove(index);
        let _ = session
            .rtcp_socket
            .send_to(&encode_rtcp_goodbye(session.ssrc), session.remote_rtcp);
        Ok((response, 200))
    }

    fn cancel(
        &self,
        message: &SipMessage,
        peer: SocketAddr,
    ) -> Result<(Vec<u8>, u16), Box<dyn Error>> {
        let matched = self.sessions.iter().find(|session| {
            session.signaling_peer == peer
                && message.header("Call-ID") == Some(session.call_id.as_str())
                && message.header("Via") == Some(session.invite_via.as_str())
                && message
                    .header("From")
                    .and_then(|value| parameter(value, "tag"))
                    == Some(session.remote_tag.clone())
                && cseq_number(message) == Some(session.invite_cseq)
        });
        let (status, reason) = if matched.is_some() {
            (200, "OK")
        } else {
            (481, "Call/Transaction Does Not Exist")
        };
        let mut reply = message.clone();
        if let Some(session) = matched
            && let Some((_, to)) = reply
                .headers
                .iter_mut()
                .find(|(name, _)| name.eq_ignore_ascii_case("To") || name.eq_ignore_ascii_case("t"))
            && parameter(to, "tag").is_none()
        {
            to.push_str(&format!(";tag={}", session.local_tag));
        }
        rejected(&reply, status, reason)
    }

    pub fn tick(&mut self, signaling: &UdpSocket) -> io::Result<()> {
        let now = Instant::now();
        self.sessions
            .retain(|session| session.acked || session.expires_at > now);
        for session in &mut self.sessions {
            if !session.acked {
                if now >= session.next_response {
                    signaling.send_to(&session.answer, session.signaling_peer)?;
                    session.response_interval =
                        (session.response_interval * 2).min(Duration::from_secs(4));
                    session.next_response = now + session.response_interval;
                }
                continue;
            }
            if now >= session.next_rtp {
                let packet = encode_rtp(
                    0,
                    session.packet_count == 0,
                    session.sequence,
                    session.timestamp,
                    session.ssrc,
                    &session.tone,
                );
                session.rtp_socket.send_to(&packet, session.remote_rtp)?;
                session.sequence = session.sequence.wrapping_add(1);
                session.timestamp = session.timestamp.wrapping_add(160);
                session.packet_count = session.packet_count.wrapping_add(1);
                session.octet_count = session.octet_count.wrapping_add(160);
                session.next_rtp = now + RTP_INTERVAL;
            }
            if now >= session.next_rtcp {
                let since_epoch = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default();
                let ntp_seconds = (since_epoch.as_secs() + 2_208_988_800) as u32;
                let ntp_fraction =
                    ((u64::from(since_epoch.subsec_nanos()) << 32) / 1_000_000_000) as u32;
                let report = encode_rtcp_sender_report(
                    session.ssrc,
                    ntp_seconds,
                    ntp_fraction,
                    session.timestamp.wrapping_sub(160),
                    session.packet_count,
                    session.octet_count,
                    "streamscope-test",
                );
                session.rtcp_socket.send_to(&report, session.remote_rtcp)?;
                session.next_rtcp = now + RTCP_INTERVAL;
            }
        }
        Ok(())
    }
}

fn rejected(
    message: &SipMessage,
    status: u16,
    reason: &str,
) -> Result<(Vec<u8>, u16), Box<dyn Error>> {
    let response = build_response_with_body(
        message,
        status,
        reason,
        "OPTIONS, INVITE, ACK, BYE, CANCEL",
        &[],
        None,
        &[],
    )?;
    Ok((response, status))
}

fn cseq_number(message: &SipMessage) -> Option<u32> {
    message
        .header("CSeq")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn select_pcmu(offer: &SdpSession, peer_ip: IpAddr) -> Option<(usize, SocketAddr)> {
    offer.media.iter().enumerate().find_map(|(index, media)| {
        if !media.media_type.eq_ignore_ascii_case("audio")
            || !media.protocol.eq_ignore_ascii_case("RTP/AVP")
            || media.port == 0
            || media.port == u16::MAX
            || !media.payload_types.contains(&0)
            || !remote_can_receive(offer, media)
        {
            return None;
        }
        let address = media
            .connection_address
            .as_deref()
            .or(offer.connection_address.as_deref())?
            .parse::<IpAddr>()
            .ok()?;
        if address.is_unspecified() || address.is_multicast() || address != peer_ip {
            return None;
        }
        Some((index, SocketAddr::new(address, media.port)))
    })
}

fn remote_can_receive(offer: &SdpSession, media: &SdpMedia) -> bool {
    let media_direction = ["sendrecv", "sendonly", "recvonly", "inactive"]
        .into_iter()
        .find(|direction| media.attributes.contains_key(*direction));
    let direction = media_direction.or_else(|| {
        ["sendrecv", "sendonly", "recvonly", "inactive"]
            .into_iter()
            .find(|direction| offer.attributes.contains_key(*direction))
    });
    !matches!(direction, Some("sendonly" | "inactive"))
}

fn answer_sdp(offer: &SdpSession, selected: usize, local_ip: IpAddr, rtp_port: u16) -> String {
    let family = if local_ip.is_ipv4() { "IP4" } else { "IP6" };
    let id = Uuid::new_v4().as_u128() as u64;
    let mut answer = format!(
        "v=0\r\no=- {id} 1 IN {family} {local_ip}\r\ns=StreamScope Test Call\r\nc=IN {family} {local_ip}\r\nt=0 0\r\n"
    );
    for (index, media) in offer.media.iter().enumerate() {
        if index == selected {
            answer.push_str(&format!(
                "m=audio {rtp_port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendonly\r\na=ptime:20\r\n"
            ));
        } else {
            let formats = media
                .payload_types
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            answer.push_str(&format!(
                "m={} 0 {} {formats}\r\n",
                media.media_type, media.protocol
            ));
        }
    }
    answer
}

fn routed_local_ip(peer: SocketAddr) -> io::Result<IpAddr> {
    let bind = if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind)?;
    socket.connect(peer)?;
    Ok(socket.local_addr()?.ip())
}

pub(crate) fn bind_media_pair(local_ip: IpAddr) -> io::Result<(UdpSocket, UdpSocket)> {
    for _ in 0..64 {
        let rtp = UdpSocket::bind(SocketAddr::new(local_ip, 0))?;
        let port = rtp.local_addr()?.port();
        if port % 2 == 0
            && let Some(rtcp_port) = port.checked_add(1)
            && let Ok(rtcp) = UdpSocket::bind(SocketAddr::new(local_ip, rtcp_port))
        {
            return Ok((rtp, rtcp));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "无法分配相邻 RTP/RTCP 端口",
    ))
}

fn sip_host(ip: IpAddr) -> String {
    if ip.is_ipv4() {
        ip.to_string()
    } else {
        format!("[{ip}]")
    }
}
