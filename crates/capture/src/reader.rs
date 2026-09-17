use crate::CaptureError;
use std::io::Read;

const MAX_BLOCK_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct FrameMeta {
    pub number: u64,
    pub timestamp_micros: u64,
    pub interface: String,
}

pub(crate) struct Frame {
    pub meta: FrameMeta,
    pub link_type: u32,
    pub truncated: bool,
    pub data: Vec<u8>,
}

#[derive(Clone)]
struct Interface {
    link_type: u32,
    resolution: u8,
    offset_seconds: i64,
}

pub(crate) fn read_capture<R: Read>(
    mut input: R,
    mut consume: impl FnMut(Frame) -> Result<(), CaptureError>,
) -> Result<(), CaptureError> {
    let mut magic = [0; 4];
    exact(&mut input, &mut magic, "抓包文件头被截断")?;
    if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
        read_pcapng(input, magic, &mut consume)
    } else {
        read_pcap(input, magic, &mut consume)
    }
}

fn read_pcap<R: Read>(
    mut input: R,
    magic: [u8; 4],
    consume: &mut impl FnMut(Frame) -> Result<(), CaptureError>,
) -> Result<(), CaptureError> {
    let (little, nanos) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        _ => return Err(CaptureError::Invalid("PCAP magic 不匹配")),
    };
    let mut header = [0; 20];
    exact(&mut input, &mut header, "PCAP 全局头被截断")?;
    let link_type = u32_at(&header[16..20], little) & 0xffff;
    let mut number = 0;
    loop {
        let mut packet = [0; 16];
        if !next_header(&mut input, &mut packet)? {
            break;
        }
        let seconds = u64::from(u32_at(&packet[..4], little));
        let fraction = u64::from(u32_at(&packet[4..8], little));
        let captured = u32_at(&packet[8..12], little) as usize;
        let original = u32_at(&packet[12..16], little) as usize;
        if captured > MAX_BLOCK_BYTES {
            return Err(CaptureError::Invalid("单个 PCAP 包超过 16 MiB 安全上限"));
        }
        let mut data = vec![0; captured];
        exact(&mut input, &mut data, "PCAP 包数据被截断")?;
        number += 1;
        consume(Frame {
            meta: FrameMeta {
                number,
                timestamp_micros: seconds.saturating_mul(1_000_000).saturating_add(if nanos {
                    fraction / 1_000
                } else {
                    fraction
                }),
                interface: "section-0/interface-0".into(),
            },
            link_type,
            truncated: captured < original,
            data,
        })?;
    }
    Ok(())
}

fn read_pcapng<R: Read>(
    mut input: R,
    first_magic: [u8; 4],
    consume: &mut impl FnMut(Frame) -> Result<(), CaptureError>,
) -> Result<(), CaptureError> {
    let mut first = true;
    let mut little = true;
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut section = 0_u64;
    let mut number = 0;
    loop {
        let mut header = [0; 12];
        if first {
            header[..4].copy_from_slice(&first_magic);
            exact(&mut input, &mut header[4..], "PCAPNG Section Header 被截断")?;
            first = false;
        } else if !next_header(&mut input, &mut header)? {
            break;
        }
        let is_section = header[..4] == [0x0a, 0x0d, 0x0d, 0x0a];
        if is_section {
            little = match &header[8..12] {
                [0x4d, 0x3c, 0x2b, 0x1a] => true,
                [0x1a, 0x2b, 0x3c, 0x4d] => false,
                _ => return Err(CaptureError::Invalid("PCAPNG 字节序无效")),
            };
            if !interfaces.is_empty() {
                section += 1;
            }
            interfaces.clear();
        }
        let length = u32_at(&header[4..8], little) as usize;
        if !(12..=MAX_BLOCK_BYTES).contains(&length) || !length.is_multiple_of(4) {
            return Err(CaptureError::Invalid(
                "PCAPNG block 长度无效或超过 16 MiB 上限",
            ));
        }
        let mut block = vec![0; length];
        block[..12].copy_from_slice(&header);
        exact(&mut input, &mut block[12..], "PCAPNG block 被截断")?;
        if u32_at(&block[length - 4..], little) as usize != length {
            return Err(CaptureError::Invalid("PCAPNG block 尾长度不匹配"));
        }
        match u32_at(&header[..4], little) {
            0x0a0d0d0a if length < 28 => {
                return Err(CaptureError::Invalid("PCAPNG Section Header 不完整"));
            }
            1 => {
                if length < 20 {
                    return Err(CaptureError::Invalid("PCAPNG Interface Header 不完整"));
                }
                let mut interface = Interface {
                    link_type: u32::from(u16_at(&block[8..10], little)),
                    resolution: 6,
                    offset_seconds: 0,
                };
                let mut cursor = 16;
                while cursor + 4 <= length - 4 {
                    let kind = u16_at(&block[cursor..cursor + 2], little);
                    let size = u16_at(&block[cursor + 2..cursor + 4], little) as usize;
                    cursor += 4;
                    if kind == 0 {
                        break;
                    }
                    if cursor + size > length - 4 {
                        return Err(CaptureError::Invalid("PCAPNG 接口选项越界"));
                    }
                    if kind == 9 && size == 1 {
                        interface.resolution = block[cursor];
                    }
                    if kind == 14 && size == 8 {
                        let bytes = block[cursor..cursor + 8].try_into().unwrap();
                        interface.offset_seconds = if little {
                            i64::from_le_bytes(bytes)
                        } else {
                            i64::from_be_bytes(bytes)
                        };
                    }
                    cursor += (size + 3) & !3;
                }
                if interfaces.len() >= 4096 {
                    return Err(CaptureError::Invalid("PCAPNG 接口数超过 4096 上限"));
                }
                interfaces.push(interface);
            }
            6 | 2 => {
                if length < 32 {
                    return Err(CaptureError::Invalid("PCAPNG Packet Header 不完整"));
                }
                let interface_id = if u32_at(&header[..4], little) == 2 {
                    u32::from(u16_at(&block[8..10], little))
                } else {
                    u32_at(&block[8..12], little)
                } as usize;
                let interface = interfaces
                    .get(interface_id)
                    .ok_or(CaptureError::Invalid("PCAPNG 接口索引无效"))?;
                let ticks = (u64::from(u32_at(&block[12..16], little)) << 32)
                    | u64::from(u32_at(&block[16..20], little));
                let captured = u32_at(&block[20..24], little) as usize;
                let original = u32_at(&block[24..28], little) as usize;
                if captured > length - 32 {
                    return Err(CaptureError::Invalid("PCAPNG packet 长度无效"));
                }
                number += 1;
                consume(Frame {
                    meta: FrameMeta {
                        number,
                        timestamp_micros: timestamp_micros(ticks, interface),
                        interface: format!("section-{section}/interface-{interface_id}"),
                    },
                    link_type: interface.link_type,
                    truncated: captured < original,
                    data: block[28..28 + captured].to_vec(),
                })?;
            }
            3 => {
                return Err(CaptureError::Invalid(
                    "PCAPNG Simple Packet Block 没有时间戳，无法可信计算时长和抖动；请保存为带时间戳的 Enhanced Packet Block",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn timestamp_micros(ticks: u64, interface: &Interface) -> u64 {
    let exponent = interface.resolution & 0x7f;
    let divisor = if interface.resolution & 0x80 != 0 {
        2_u128.checked_pow(u32::from(exponent))
    } else {
        10_u128.checked_pow(u32::from(exponent))
    };
    let micros = divisor
        .map(|value| u128::from(ticks).saturating_mul(1_000_000) / value)
        .unwrap_or(0)
        .min(u64::MAX as u128) as i128;
    (micros + i128::from(interface.offset_seconds) * 1_000_000).clamp(0, i128::from(u64::MAX))
        as u64
}

fn next_header<R: Read>(input: &mut R, output: &mut [u8]) -> Result<bool, CaptureError> {
    match input.read(&mut output[..1])? {
        0 => Ok(false),
        _ => {
            exact(input, &mut output[1..], "抓包包头被截断")?;
            Ok(true)
        }
    }
}

fn exact<R: Read>(
    input: &mut R,
    output: &mut [u8],
    reason: &'static str,
) -> Result<(), CaptureError> {
    input.read_exact(output).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            CaptureError::Invalid(reason)
        } else {
            CaptureError::Io(error)
        }
    })
}
fn u32_at(bytes: &[u8], little: bool) -> u32 {
    let bytes = bytes.try_into().unwrap();
    if little {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    }
}
fn u16_at(bytes: &[u8], little: bool) -> u16 {
    let bytes = bytes.try_into().unwrap();
    if little {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    }
}
