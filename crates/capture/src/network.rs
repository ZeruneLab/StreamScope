use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}
impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.ip {
            IpAddr::V4(_) => write!(f, "{}:{}", self.ip, self.port),
            IpAddr::V6(_) => write!(f, "[{}]:{}", self.ip, self.port),
        }
    }
}

pub(crate) struct NetworkPacket<'a> {
    pub source: Endpoint,
    pub destination: Endpoint,
    pub transport: Payload<'a>,
}
pub(crate) enum Payload<'a> {
    Udp(&'a [u8]),
    Tcp {
        sequence: u32,
        flags: u8,
        data: &'a [u8],
    },
}

pub(crate) fn parse_network(
    frame: &[u8],
    link_type: u32,
) -> Result<Option<NetworkPacket<'_>>, &'static str> {
    let (mut offset, mut protocol) = match link_type {
        1 if frame.len() >= 14 => (14, be16(&frame[12..14])),
        101 if !frame.is_empty() => (0, if frame[0] >> 4 == 6 { 0x86dd } else { 0x0800 }),
        113 if frame.len() >= 16 => (16, be16(&frame[14..16])),
        276 if frame.len() >= 20 => (20, be16(&frame[..2])),
        1 | 101 | 113 | 276 => return Err("链路层帧被截断"),
        _ => return Err("不支持的链路类型（支持 Ethernet、Raw IP、Linux SLL/SLL2）"),
    };
    for _ in 0..4 {
        if !matches!(protocol, 0x8100 | 0x88a8 | 0x9100) {
            break;
        }
        if frame.len() < offset + 4 {
            return Err("VLAN 头被截断");
        }
        protocol = be16(&frame[offset + 2..offset + 4]);
        offset += 4;
    }
    let (source, destination, next, end, transport) = match protocol {
        0x0800 => {
            if frame.len() < offset + 20 || frame[offset] >> 4 != 4 {
                return Err("IPv4 头被截断或无效");
            }
            let header = usize::from(frame[offset] & 15) * 4;
            let length = usize::from(be16(&frame[offset + 2..offset + 4]));
            if header < 20 || length < header || offset + length > frame.len() {
                return Err("IPv4 包被截断或长度无效");
            }
            if be16(&frame[offset + 6..offset + 8]) & 0x3fff != 0 {
                return Err("IPv4 分片未重组，已跳过该片段");
            }
            (
                IpAddr::V4(Ipv4Addr::new(
                    frame[offset + 12],
                    frame[offset + 13],
                    frame[offset + 14],
                    frame[offset + 15],
                )),
                IpAddr::V4(Ipv4Addr::new(
                    frame[offset + 16],
                    frame[offset + 17],
                    frame[offset + 18],
                    frame[offset + 19],
                )),
                frame[offset + 9],
                offset + length,
                offset + header,
            )
        }
        0x86dd => {
            if frame.len() < offset + 40 || frame[offset] >> 4 != 6 {
                return Err("IPv6 头被截断或无效");
            }
            let end = offset + 40 + usize::from(be16(&frame[offset + 4..offset + 6]));
            if end > frame.len() {
                return Err("IPv6 包被截断");
            }
            let source = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[offset + 8..offset + 24]).unwrap(),
            ));
            let destination = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&frame[offset + 24..offset + 40]).unwrap(),
            ));
            let mut next = frame[offset + 6];
            let mut transport = offset + 40;
            for _ in 0..8 {
                if next == 44 {
                    return Err("IPv6 分片未重组，已跳过该片段");
                }
                if !matches!(next, 0 | 43 | 60 | 51) {
                    break;
                }
                if transport + 2 > end {
                    return Err("IPv6 扩展头被截断");
                }
                let length = if next == 51 {
                    (usize::from(frame[transport + 1]) + 2) * 4
                } else {
                    (usize::from(frame[transport + 1]) + 1) * 8
                };
                next = frame[transport];
                transport += length;
                if transport > end {
                    return Err("IPv6 扩展头长度无效");
                }
            }
            (source, destination, next, end, transport)
        }
        _ => return Ok(None),
    };
    let bytes = &frame[transport..end];
    let payload = match next {
        17 => {
            if bytes.len() < 8 {
                return Err("UDP 头被截断");
            }
            let length = usize::from(be16(&bytes[4..6]));
            if length < 8 || length > bytes.len() {
                return Err("UDP 负载被截断或长度无效");
            }
            Payload::Udp(&bytes[8..length])
        }
        6 => {
            if bytes.len() < 20 {
                return Err("TCP 头被截断");
            }
            let header = usize::from(bytes[12] >> 4) * 4;
            if header < 20 || header > bytes.len() {
                return Err("TCP 头长度无效");
            }
            Payload::Tcp {
                sequence: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
                flags: bytes[13],
                data: &bytes[header..],
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(NetworkPacket {
        source: Endpoint {
            ip: source,
            port: be16(&bytes[..2]),
        },
        destination: Endpoint {
            ip: destination,
            port: be16(&bytes[2..4]),
        },
        transport: payload,
    }))
}
fn be16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(bytes.try_into().unwrap())
}
