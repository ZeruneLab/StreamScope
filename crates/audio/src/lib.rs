use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::Path;
use streamscope_core::{
    AudioAnalysis, AudioChannelQuality, AudioIssue, AudioLevelPoint, AudioQualityAnalysis,
    AudioQualityInterval, AudioSampleMapping, AudioSpectrogramPoint, AudioSpectrumPoint,
};

#[derive(Debug, Clone)]
pub struct AudioRtpPayload {
    pub packet_number: Option<u64>,
    pub offset_ms: Option<u64>,
    pub sequence: Option<u16>,
    pub timestamp: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AudioWriteResult {
    pub units: u64,
    pub mappings: Vec<AudioSampleMapping>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawRtpAudioSpec {
    pub extension: &'static str,
    pub ffmpeg_format: &'static str,
    pub code_size: Option<u8>,
    pub decoded_sample_rate: u32,
}

pub fn raw_rtp_audio_spec(codec: &str, clock_rate: u32) -> Option<RawRtpAudioSpec> {
    let codec = codec.to_ascii_lowercase();
    let spec = match codec.as_str() {
        "g722" => RawRtpAudioSpec {
            extension: "g722",
            ffmpeg_format: "g722",
            code_size: None,
            decoded_sample_rate: 16_000,
        },
        "g723" | "g723.1" | "g7231" | "g723_1" => RawRtpAudioSpec {
            extension: "g723_1",
            ffmpeg_format: "g723_1",
            code_size: None,
            decoded_sample_rate: clock_rate,
        },
        "g729" | "g729a" => RawRtpAudioSpec {
            extension: "g729",
            ffmpeg_format: "g729",
            code_size: None,
            decoded_sample_rate: clock_rate,
        },
        "g726" => RawRtpAudioSpec {
            extension: "g726",
            ffmpeg_format: "g726",
            code_size: Some(4),
            decoded_sample_rate: clock_rate,
        },
        "g726le" => RawRtpAudioSpec {
            extension: "g726le",
            ffmpeg_format: "g726le",
            code_size: Some(4),
            decoded_sample_rate: clock_rate,
        },
        _ => {
            let (little_endian, rate) = codec
                .strip_prefix("aal2-g726-")
                .map(|rate| (true, rate))
                .or_else(|| codec.strip_prefix("g726le-").map(|rate| (true, rate)))
                .or_else(|| codec.strip_prefix("g726-").map(|rate| (false, rate)))?;
            let code_size = match rate {
                "16" => 2,
                "24" => 3,
                "32" => 4,
                "40" => 5,
                _ => return None,
            };
            RawRtpAudioSpec {
                extension: if little_endian { "g726le" } else { "g726" },
                ffmpeg_format: if little_endian { "g726le" } else { "g726" },
                code_size: Some(code_size),
                decoded_sample_rate: clock_rate,
            }
        }
    };
    Some(spec)
}

pub fn write_raw_rtp_audio(packets: &[AudioRtpPayload], path: &Path) -> std::io::Result<u64> {
    let mut writer = BufWriter::new(File::create(path)?);
    let mut units = 0_u64;
    for packet in packets.iter().filter(|packet| !packet.payload.is_empty()) {
        writer.write_all(&packet.payload)?;
        units += 1;
    }
    writer.flush()?;
    Ok(units)
}

pub fn rtp_packet_sample_mappings(
    packets: &[AudioRtpPayload],
    clock_rate: u32,
    sample_rate: u32,
    precision: &str,
) -> Vec<AudioSampleMapping> {
    let first_timestamp = packets.first().map(|packet| packet.timestamp).unwrap_or(0);
    let mut encoded_offset = 0_u64;
    packets
        .iter()
        .enumerate()
        .filter(|(_, packet)| !packet.payload.is_empty())
        .map(|(index, packet)| {
            let start_clock = u64::from(packet.timestamp.wrapping_sub(first_timestamp));
            let end_clock = packets
                .get(index + 1)
                .map(|next| u64::from(next.timestamp.wrapping_sub(first_timestamp)))
                .filter(|end| *end > start_clock)
                .unwrap_or_else(|| {
                    let previous_delta = index
                        .checked_sub(1)
                        .and_then(|previous| packets.get(previous))
                        .map(|previous| {
                            u64::from(packet.timestamp.wrapping_sub(previous.timestamp))
                        })
                        .filter(|delta| *delta > 0)
                        .unwrap_or(packet.payload.len() as u64);
                    start_clock.saturating_add(previous_delta)
                });
            let scale = |value: u64| {
                value
                    .saturating_mul(u64::from(sample_rate))
                    .checked_div(u64::from(clock_rate).max(1))
                    .unwrap_or(0)
            };
            let mapping = AudioSampleMapping {
                packet_number: packet.packet_number,
                packet_offset_ms: packet.offset_ms,
                rtp_sequence: packet.sequence,
                rtp_timestamp: packet.timestamp,
                access_unit_index: index as u64,
                access_unit_in_packet: 0,
                encoded_offset,
                encoded_size: packet.payload.len().min(u32::MAX as usize) as u32,
                pcm_start_sample: scale(start_clock),
                pcm_end_sample: scale(end_clock),
                sample_rate,
                precision: precision.into(),
            };
            encoded_offset = encoded_offset.saturating_add(packet.payload.len() as u64);
            mapping
        })
        .collect()
}

pub fn aac_adts_frames(
    payload: &[u8],
    fmtp: &BTreeMap<String, String>,
    clock_rate: u32,
    channels: Option<u16>,
) -> Vec<Vec<u8>> {
    let size_length = fmtp
        .get("sizelength")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(13);
    let index_length = fmtp
        .get("indexlength")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(3);
    let index_delta_length = fmtp
        .get("indexdeltalength")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(3);
    let config = fmtp
        .get("config")
        .and_then(|value| decode_hex(value))
        .unwrap_or_default();
    let object_type = config.first().map_or(2, |byte| byte >> 3).clamp(1, 4);
    let frequency_index = if config.len() >= 2 {
        ((config[0] & 7) << 1) | (config[1] >> 7)
    } else {
        sample_rate_index(clock_rate).unwrap_or(4)
    };
    let channel_config = if config.len() >= 2 {
        (config[1] >> 3) & 0x0f
    } else {
        channels.unwrap_or(2).min(7) as u8
    };
    if payload.len() < 2 || size_length == 0 {
        return Vec::new();
    }
    let header_bits = usize::from(u16::from_be_bytes([payload[0], payload[1]]));
    let header_bytes = header_bits.div_ceil(8);
    if payload.len() < 2 + header_bytes {
        return Vec::new();
    }
    let headers = &payload[2..2 + header_bytes];
    let mut bit = 0;
    let mut sizes = Vec::new();
    while bit + size_length <= header_bits {
        let Some(size) = read_bits(headers, bit, size_length) else {
            break;
        };
        bit += size_length;
        let skip = if sizes.is_empty() {
            index_length
        } else {
            index_delta_length
        };
        if bit + skip > header_bits {
            break;
        }
        bit += skip;
        sizes.push(size);
    }
    let mut cursor = 2 + header_bytes;
    let mut frames = Vec::new();
    for size in sizes {
        if size == 0 || cursor + size > payload.len() || size + 7 > 0x1fff {
            break;
        }
        let mut frame =
            adts_header(size + 7, object_type - 1, frequency_index, channel_config).to_vec();
        frame.extend_from_slice(&payload[cursor..cursor + size]);
        frames.push(frame);
        cursor += size;
    }
    frames
}

pub fn write_aac_adts(
    packets: &[AudioRtpPayload],
    fmtp: &BTreeMap<String, String>,
    clock_rate: u32,
    channels: Option<u16>,
    path: &Path,
) -> std::io::Result<u64> {
    write_aac_adts_mapped(packets, fmtp, clock_rate, channels, path).map(|result| result.units)
}

pub fn write_aac_adts_mapped(
    packets: &[AudioRtpPayload],
    fmtp: &BTreeMap<String, String>,
    clock_rate: u32,
    channels: Option<u16>,
    path: &Path,
) -> std::io::Result<AudioWriteResult> {
    let size_length = fmtp
        .get("sizelength")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(13);
    let index_length = fmtp
        .get("indexlength")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(3);
    let index_delta_length = fmtp
        .get("indexdeltalength")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(3);
    let config = fmtp
        .get("config")
        .and_then(|value| decode_hex(value))
        .unwrap_or_default();
    let object_type = config.first().map_or(2, |byte| byte >> 3).clamp(1, 4);
    let frequency_index = if config.len() >= 2 {
        ((config[0] & 7) << 1) | (config[1] >> 7)
    } else {
        sample_rate_index(clock_rate).unwrap_or(4)
    };
    let channel_config = if config.len() >= 2 {
        (config[1] >> 3) & 0x0f
    } else {
        channels.unwrap_or(2).min(7) as u8
    };
    let mut writer = BufWriter::new(File::create(path)?);
    let mut units = 0_u64;
    let mut encoded_offset = 0_u64;
    let mut mappings = Vec::new();
    let first_timestamp = packets.first().map(|packet| packet.timestamp).unwrap_or(0);
    for packet in packets {
        if packet.payload.len() < 2 {
            continue;
        }
        let header_bits = usize::from(u16::from_be_bytes([packet.payload[0], packet.payload[1]]));
        let header_bytes = header_bits.div_ceil(8);
        if packet.payload.len() < 2 + header_bytes || size_length == 0 {
            continue;
        }
        let headers = &packet.payload[2..2 + header_bytes];
        let mut bit = 0;
        let mut sizes = Vec::new();
        while bit + size_length <= header_bits {
            let Some(size) = read_bits(headers, bit, size_length) else {
                break;
            };
            bit += size_length;
            let skip = if sizes.is_empty() {
                index_length
            } else {
                index_delta_length
            };
            if bit + skip > header_bits {
                break;
            }
            bit += skip;
            sizes.push(size);
        }
        let mut cursor = 2 + header_bytes;
        for (in_packet, size) in sizes.into_iter().enumerate() {
            if size == 0 || cursor + size > packet.payload.len() || size + 7 > 0x1fff {
                break;
            }
            writer.write_all(&adts_header(
                size + 7,
                object_type - 1,
                frequency_index,
                channel_config,
            ))?;
            writer.write_all(&packet.payload[cursor..cursor + size])?;
            let pcm_start = u64::from(packet.timestamp.wrapping_sub(first_timestamp))
                .saturating_add(in_packet as u64 * 1_024);
            mappings.push(AudioSampleMapping {
                packet_number: packet.packet_number,
                packet_offset_ms: packet.offset_ms,
                rtp_sequence: packet.sequence,
                rtp_timestamp: packet.timestamp,
                access_unit_index: units,
                access_unit_in_packet: in_packet.min(u16::MAX as usize) as u16,
                encoded_offset,
                encoded_size: (size + 7) as u32,
                pcm_start_sample: pcm_start,
                pcm_end_sample: pcm_start.saturating_add(1_024),
                sample_rate: clock_rate,
                precision: "aac_rtp_au_1024_samples".into(),
            });
            cursor += size;
            encoded_offset = encoded_offset.saturating_add((size + 7) as u64);
            units += 1;
        }
    }
    writer.flush()?;
    Ok(AudioWriteResult { units, mappings })
}

pub fn write_opus_ogg(
    packets: &[AudioRtpPayload],
    channels: Option<u16>,
    path: &Path,
) -> std::io::Result<u64> {
    write_opus_ogg_mapped(packets, channels, path).map(|result| result.units)
}

pub fn write_opus_ogg_mapped(
    packets: &[AudioRtpPayload],
    channels: Option<u16>,
    path: &Path,
) -> std::io::Result<AudioWriteResult> {
    let mut writer = BufWriter::new(File::create(path)?);
    let serial = 0x5353_4f50;
    let mut sequence = 0_u32;
    let (head, tags) = opus_ogg_headers(channels);
    write_ogg_page(&mut writer, serial, sequence, 2, 0, &head)?;
    sequence += 1;
    write_ogg_page(&mut writer, serial, sequence, 0, 0, &tags)?;
    sequence += 1;
    let first_timestamp = packets.first().map(|packet| packet.timestamp).unwrap_or(0);
    let mut mappings = Vec::new();
    let mut encoded_offset = 0_u64;
    let mut units = 0_u64;
    for (index, packet) in packets.iter().enumerate() {
        if packet.payload.is_empty() {
            continue;
        }
        let end_timestamp = packets
            .get(index + 1)
            .map(|next| next.timestamp)
            .unwrap_or_else(|| {
                packet.timestamp.wrapping_add(
                    index
                        .checked_sub(1)
                        .and_then(|previous| {
                            Some(
                                packet
                                    .timestamp
                                    .wrapping_sub(packets.get(previous)?.timestamp),
                            )
                        })
                        .filter(|delta| *delta > 0 && *delta <= 5_760)
                        .unwrap_or(960),
                )
            });
        let granule = u64::from(end_timestamp.wrapping_sub(first_timestamp));
        let header_type = if index + 1 == packets.len() { 4 } else { 0 };
        write_ogg_page(
            &mut writer,
            serial,
            sequence,
            header_type,
            granule,
            &packet.payload,
        )?;
        let pcm_start = u64::from(packet.timestamp.wrapping_sub(first_timestamp));
        let pcm_end = u64::from(end_timestamp.wrapping_sub(first_timestamp));
        mappings.push(AudioSampleMapping {
            packet_number: packet.packet_number,
            packet_offset_ms: packet.offset_ms,
            rtp_sequence: packet.sequence,
            rtp_timestamp: packet.timestamp,
            access_unit_index: units,
            access_unit_in_packet: 0,
            encoded_offset,
            encoded_size: packet.payload.len().min(u32::MAX as usize) as u32,
            pcm_start_sample: pcm_start,
            pcm_end_sample: pcm_end
                .max(pcm_start.saturating_add(opus_packet_samples(&packet.payload))),
            sample_rate: 48_000,
            precision: "opus_rtp_timestamp_and_toc".into(),
        });
        encoded_offset = encoded_offset.saturating_add(packet.payload.len() as u64);
        units += 1;
        sequence += 1;
    }
    writer.flush()?;
    Ok(AudioWriteResult { units, mappings })
}

pub fn opus_ogg_headers(channels: Option<u16>) -> (Vec<u8>, Vec<u8>) {
    let channel_count = channels.unwrap_or(2).clamp(1, 2) as u8;
    let mut head = b"OpusHead".to_vec();
    head.extend_from_slice(&[1, channel_count]);
    head.extend_from_slice(&0_u16.to_le_bytes());
    head.extend_from_slice(&48_000_u32.to_le_bytes());
    head.extend_from_slice(&0_i16.to_le_bytes());
    head.push(0);
    let vendor = b"StreamScope";
    let mut tags = b"OpusTags".to_vec();
    tags.extend_from_slice(&(vendor.len() as u32).to_le_bytes());
    tags.extend_from_slice(vendor);
    tags.extend_from_slice(&0_u32.to_le_bytes());
    (head, tags)
}

pub fn opus_ogg_page(
    serial: u32,
    sequence: u32,
    header_type: u8,
    granule: u64,
    packet: &[u8],
) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    write_ogg_page(&mut bytes, serial, sequence, header_type, granule, packet)?;
    Ok(bytes)
}

pub fn opus_packet_samples(payload: &[u8]) -> u64 {
    let Some(toc) = payload.first().copied() else {
        return 0;
    };
    let config = toc >> 3;
    let samples_per_frame = if config >= 16 {
        120_u64 << (config & 3)
    } else if config >= 12 {
        480_u64 << (config & 1)
    } else {
        480_u64 << (config & 3)
    };
    let frames = match toc & 3 {
        0 => 1,
        1 | 2 => 2,
        _ => payload.get(1).map_or(0, |value| u64::from(value & 0x3f)),
    };
    samples_per_frame.saturating_mul(frames).min(5_760)
}

fn write_ogg_page(
    writer: &mut impl Write,
    serial: u32,
    sequence: u32,
    header_type: u8,
    granule: u64,
    packet: &[u8],
) -> std::io::Result<()> {
    let mut segments = Vec::new();
    let mut remaining = packet.len();
    while remaining >= 255 {
        segments.push(255);
        remaining -= 255;
    }
    segments.push(remaining as u8);
    if segments.len() > 255 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Opus RTP 包过大，无法写入单个 Ogg Page",
        ));
    }
    let mut page = b"OggS".to_vec();
    page.extend_from_slice(&[0, header_type]);
    page.extend_from_slice(&granule.to_le_bytes());
    page.extend_from_slice(&serial.to_le_bytes());
    page.extend_from_slice(&sequence.to_le_bytes());
    page.extend_from_slice(&0_u32.to_le_bytes());
    page.push(segments.len() as u8);
    page.extend_from_slice(&segments);
    page.extend_from_slice(packet);
    let crc = ogg_crc(&page);
    page[22..26].copy_from_slice(&crc.to_le_bytes());
    writer.write_all(&page)
}

fn ogg_crc(bytes: &[u8]) -> u32 {
    let mut crc = 0_u32;
    for byte in bytes {
        crc ^= u32::from(*byte) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0x04c1_1db7
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn read_bits(bytes: &[u8], offset: usize, length: usize) -> Option<usize> {
    if length > usize::BITS as usize || offset + length > bytes.len() * 8 {
        return None;
    }
    let mut value = 0;
    for index in offset..offset + length {
        value = (value << 1) | usize::from((bytes[index / 8] >> (7 - index % 8)) & 1);
    }
    Some(value)
}

fn adts_header(
    frame_length: usize,
    profile: u8,
    frequency_index: u8,
    channel_config: u8,
) -> [u8; 7] {
    [
        0xff,
        0xf1,
        (profile << 6) | (frequency_index << 2) | (channel_config >> 2),
        ((channel_config & 3) << 6) | ((frame_length >> 11) as u8 & 3),
        (frame_length >> 3) as u8,
        ((frame_length as u8 & 7) << 5) | 0x1f,
        0xfc,
    ]
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}

fn sample_rate_index(rate: u32) -> Option<u8> {
    [
        96_000, 88_200, 64_000, 48_000, 44_100, 32_000, 24_000, 22_050, 16_000, 12_000, 11_025,
        8_000, 7_350,
    ]
    .iter()
    .position(|candidate| *candidate == rate)
    .map(|index| index as u8)
}

pub fn analyze(
    codec: &str,
    clock_rate: u32,
    channels: Option<u16>,
    packets: &[AudioRtpPayload],
    truncated: bool,
    wav_path: Option<&Path>,
) -> std::io::Result<AudioAnalysis> {
    let codec = codec.to_ascii_lowercase();
    let channels = channels.unwrap_or(1).max(1);
    let supported = matches!(codec.as_str(), "pcma" | "pcmu");
    if !supported {
        let raw_spec = raw_rtp_audio_spec(&codec, clock_rate);
        let sample_rate = raw_spec.map_or(clock_rate, |spec| spec.decoded_sample_rate);
        return Ok(AudioAnalysis {
            codec,
            clock_rate,
            sample_rate: Some(sample_rate),
            channels: Some(channels),
            packet_count: packets.len() as u64,
            codec_supported_for_decode: false,
            conclusion_reliable: false,
            issues: vec![AudioIssue {
                kind: "decode_not_supported".into(),
                detail: if raw_spec.is_some() {
                    "已完成 RTP 连续性与码率统计；选择深入分析后将使用 FFmpeg 执行 PCM 级声音质量分析"
                } else {
                    "已完成 RTP 连续性与码率统计，但当前版本尚未对该编码执行 PCM 级声音质量分析"
                }
                .into(),
                ..AudioIssue::default()
            }],
            sample_mappings: rtp_packet_sample_mappings(
                packets,
                clock_rate,
                sample_rate,
                "rtp_timestamp_interval",
            ),
            ..AudioAnalysis::default()
        });
    }

    let mut pcm = Vec::new();
    let mut gap_count = 0_u64;
    let mut overlap_count = 0_u64;
    let mut issues = Vec::new();
    let mut expected_timestamp = None;
    let base_timestamp = packets.first().map_or(0, |packet| packet.timestamp);
    let mut previous_packet: Option<&AudioRtpPayload> = None;
    let mut mappings = Vec::with_capacity(packets.len());
    let mut encoded_offset = 0_u64;
    for (packet_index, packet) in packets.iter().enumerate() {
        if let Some(expected) = expected_timestamp {
            let delta = packet.timestamp.wrapping_sub(expected) as i32;
            let duration_ms = u64::from(delta.unsigned_abs()).saturating_mul(1_000)
                / u64::from(clock_rate.max(1));
            let expected_ms = u64::from(expected.wrapping_sub(base_timestamp))
                .saturating_mul(1_000)
                / u64::from(clock_rate.max(1));
            let actual_ms = u64::from(packet.timestamp.wrapping_sub(base_timestamp))
                .saturating_mul(1_000)
                / u64::from(clock_rate.max(1));
            if delta > 0 {
                gap_count += 1;
                if issues.len() < 128 {
                    issues.push(AudioIssue {
                        kind: "timestamp_gap".into(),
                        detail: format!(
                            "音频 RTP 时间戳缺口 {} 个采样时钟（约 {} ms）",
                            delta, duration_ms
                        ),
                        first_packet: packet.packet_number,
                        offset_ms: packet.offset_ms,
                        previous_packet: previous_packet.and_then(|value| value.packet_number),
                        previous_offset_ms: previous_packet.and_then(|value| value.offset_ms),
                        previous_rtp_sequence: previous_packet.and_then(|value| value.sequence),
                        current_rtp_sequence: packet.sequence,
                        expected_rtp_timestamp: Some(expected),
                        actual_rtp_timestamp: Some(packet.timestamp),
                        delta_timestamp: Some(i64::from(delta)),
                        duration_ms: Some(duration_ms),
                        media_start_ms: Some(expected_ms),
                        media_end_ms: Some(actual_ms),
                    });
                }
            } else if delta < 0 {
                overlap_count += 1;
                if issues.len() < 128 {
                    issues.push(AudioIssue {
                        kind: "timestamp_overlap".into(),
                        detail: format!(
                            "音频 RTP 时间戳回退或重叠 {} 个采样时钟（约 {} ms）",
                            delta.unsigned_abs(),
                            duration_ms
                        ),
                        first_packet: packet.packet_number,
                        offset_ms: packet.offset_ms,
                        previous_packet: previous_packet.and_then(|value| value.packet_number),
                        previous_offset_ms: previous_packet.and_then(|value| value.offset_ms),
                        previous_rtp_sequence: previous_packet.and_then(|value| value.sequence),
                        current_rtp_sequence: packet.sequence,
                        expected_rtp_timestamp: Some(expected),
                        actual_rtp_timestamp: Some(packet.timestamp),
                        delta_timestamp: Some(i64::from(delta)),
                        duration_ms: Some(duration_ms),
                        media_start_ms: Some(actual_ms),
                        media_end_ms: Some(expected_ms),
                    });
                }
            }
        }
        let pcm_start = (pcm.len() / usize::from(channels)) as u64;
        for byte in &packet.payload {
            pcm.push(if codec == "pcma" {
                decode_alaw(*byte)
            } else {
                decode_mulaw(*byte)
            });
        }
        let frames = (packet.payload.len() / usize::from(channels)) as u32;
        mappings.push(AudioSampleMapping {
            packet_number: packet.packet_number,
            packet_offset_ms: packet.offset_ms,
            rtp_sequence: packet.sequence,
            rtp_timestamp: packet.timestamp,
            access_unit_index: packet_index as u64,
            access_unit_in_packet: 0,
            encoded_offset,
            encoded_size: packet.payload.len().min(u32::MAX as usize) as u32,
            pcm_start_sample: pcm_start,
            pcm_end_sample: pcm_start.saturating_add(u64::from(frames)),
            sample_rate: clock_rate,
            precision: "g711_one_sample_per_codeword".into(),
        });
        encoded_offset = encoded_offset.saturating_add(packet.payload.len() as u64);
        expected_timestamp = Some(packet.timestamp.wrapping_add(frames));
        previous_packet = Some(packet);
    }

    if let Some(path) = wav_path {
        write_wav(path, clock_rate, channels, &pcm)?;
    }
    let mut analysis = AudioAnalysis {
        codec,
        clock_rate,
        sample_rate: Some(clock_rate),
        channels: Some(channels),
        packet_count: packets.len() as u64,
        access_unit_count: 0,
        timestamp_gap_count: gap_count,
        timestamp_overlap_count: overlap_count,
        issues,
        sample_mappings: mappings,
        ..AudioAnalysis::default()
    };
    apply_pcm_metrics(
        &mut analysis,
        &pcm,
        clock_rate,
        channels,
        truncated,
        "captured_rtp_payload",
    );
    Ok(analysis)
}

pub fn enrich_from_pcm_wav(
    analysis: &mut AudioAnalysis,
    path: &Path,
    truncated: bool,
) -> std::io::Result<()> {
    enrich_from_pcm_wav_with_scope(analysis, path, truncated, "decoded_pcm_sample")
}

pub fn enrich_from_pcm_wav_with_scope(
    analysis: &mut AudioAnalysis,
    path: &Path,
    truncated: bool,
    scope: &str,
) -> std::io::Result<()> {
    let mut bytes = Vec::new();
    File::open(path)?.read_to_end(&mut bytes)?;
    if bytes.len() < 12 || &bytes[..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "不是有效的 RIFF/WAVE 音频",
        ));
    }
    let mut cursor = 12_usize;
    let mut format = None;
    let mut data = None;
    while cursor.saturating_add(8) <= bytes.len() {
        let id = &bytes[cursor..cursor + 4];
        let size = u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
        let start = cursor + 8;
        let end = start.saturating_add(size);
        if end > bytes.len() {
            break;
        }
        if id == b"fmt " && size >= 16 {
            let audio_format = u16::from_le_bytes(bytes[start..start + 2].try_into().unwrap());
            let channels = u16::from_le_bytes(bytes[start + 2..start + 4].try_into().unwrap());
            let sample_rate = u32::from_le_bytes(bytes[start + 4..start + 8].try_into().unwrap());
            let bits = u16::from_le_bytes(bytes[start + 14..start + 16].try_into().unwrap());
            format = Some((audio_format, channels, sample_rate, bits));
        } else if id == b"data" {
            data = Some(&bytes[start..end]);
        }
        cursor = end.saturating_add(size & 1);
    }
    let Some((audio_format, channels, sample_rate, bits)) = format else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "WAVE 缺少 fmt 块",
        ));
    };
    if audio_format != 1 || bits != 16 || channels == 0 || sample_rate == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "WAVE 不是 PCM S16LE",
        ));
    }
    let data = data
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "WAVE 缺少 data 块"))?;
    let samples: Vec<i16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|value| i16::from_le_bytes(*value))
        .collect();
    apply_pcm_metrics(analysis, &samples, sample_rate, channels, truncated, scope);
    Ok(())
}

fn apply_pcm_metrics(
    analysis: &mut AudioAnalysis,
    pcm: &[i16],
    sample_rate: u32,
    channels: u16,
    truncated: bool,
    scope: &str,
) {
    let peak = pcm
        .iter()
        .map(|sample| i32::from(*sample).abs())
        .max()
        .unwrap_or(0);
    let squares = pcm
        .iter()
        .map(|sample| {
            let value = f64::from(*sample);
            value * value
        })
        .sum::<f64>();
    let rms = if pcm.is_empty() {
        0.0
    } else {
        (squares / pcm.len() as f64).sqrt()
    };
    let silent_samples = pcm
        .iter()
        .filter(|sample| i32::from(**sample).abs() <= 328)
        .count() as u64;
    let clipped_samples = pcm
        .iter()
        .filter(|sample| i32::from(**sample).abs() >= 32_600)
        .count() as u64;
    let duration_ms = (!pcm.is_empty()).then(|| {
        (pcm.len() as u64).saturating_mul(1_000).saturating_div(
            u64::from(sample_rate)
                .saturating_mul(u64::from(channels))
                .max(1),
        )
    });
    let level =
        |value: f64| (value > 0.0).then(|| (20_000.0 * (value / 32_768.0).log10()).round() as i32);
    let reliable = duration_ms.is_some_and(|value| value >= 1_000)
        && (analysis.packet_count == 0 || analysis.packet_count >= 20)
        && !truncated;
    analysis.issues.retain(|issue| {
        !matches!(
            issue.kind.as_str(),
            "decode_not_supported" | "insufficient_sample" | "near_silence" | "clipping"
        )
    });
    if !reliable {
        analysis.issues.push(AudioIssue {
            kind: "insufficient_sample".into(),
            detail: if analysis.packet_count == 0 {
                "音频样本不足 1 秒或已截断，禁止输出确定性声音质量结论"
            } else {
                "音频样本不足 1 秒、少于 20 个 RTP 包或已截断，禁止输出确定性声音质量结论"
            }
            .into(),
            ..AudioIssue::default()
        });
    }
    if reliable && !pcm.is_empty() && silent_samples.saturating_mul(100) / pcm.len() as u64 >= 95 {
        analysis.issues.push(AudioIssue {
            kind: "near_silence".into(),
            detail: "至少 95% 的采样低于 -40 dBFS，疑似静音；需结合现场声源复验".into(),
            ..AudioIssue::default()
        });
    }
    if reliable && clipped_samples.saturating_mul(10_000) / pcm.len() as u64 >= 10 {
        analysis.issues.push(AudioIssue {
            kind: "clipping".into(),
            detail: "至少 0.1% 的采样接近满幅，存在削波失真风险".into(),
            ..AudioIssue::default()
        });
    }
    analysis.sample_rate = Some(sample_rate);
    if analysis.clock_rate == 0 {
        analysis.clock_rate = sample_rate;
    }
    analysis.channels = Some(channels);
    analysis.decoded_samples = pcm.len() as u64;
    analysis.decoded_duration_ms = duration_ms;
    analysis.peak_level_dbfs_milli = level(f64::from(peak));
    analysis.rms_level_dbfs_milli = level(rms);
    analysis.silent_samples = silent_samples;
    analysis.clipped_samples = clipped_samples;
    analysis.codec_supported_for_decode = true;
    analysis.conclusion_reliable = reliable;
    let mut quality = analyze_pcm_quality(pcm, sample_rate, channels, scope);
    annotate_quality_intervals(&mut quality.intervals, &analysis.sample_mappings);
    analysis.quality = Some(quality);
}

fn annotate_quality_intervals(
    intervals: &mut [AudioQualityInterval],
    mappings: &[AudioSampleMapping],
) {
    for interval in intervals {
        let Some(sample_rate) = mappings.first().map(|mapping| mapping.sample_rate) else {
            continue;
        };
        let start_sample = interval.start_ms.saturating_mul(u64::from(sample_rate)) / 1_000;
        let end_sample = interval.end_ms.saturating_mul(u64::from(sample_rate)) / 1_000;
        let mut overlapping = mappings.iter().filter(|mapping| {
            mapping.pcm_end_sample > start_sample && mapping.pcm_start_sample < end_sample
        });
        let Some(first) = overlapping.next() else {
            continue;
        };
        let last = overlapping.next_back().unwrap_or(first);
        interval.first_packet = first.packet_number;
        interval.last_packet = last.packet_number;
        interval.first_rtp_sequence = first.rtp_sequence;
        interval.last_rtp_sequence = last.rtp_sequence;
        interval.precision = format!("{}+{}", interval.precision, first.precision);
    }
}

fn level_dbfs_milli(value: f64) -> Option<i32> {
    (value > 0.0).then(|| (20_000.0 * (value / 32_768.0).log10()).round() as i32)
}

fn analyze_pcm_quality(
    pcm: &[i16],
    sample_rate: u32,
    channels: u16,
    scope: &str,
) -> AudioQualityAnalysis {
    let channel_count = usize::from(channels.max(1));
    let frame_count = pcm.len() / channel_count;
    let coverage_ms =
        (frame_count > 0).then(|| frame_count as u64 * 1_000 / u64::from(sample_rate.max(1)));
    let mut sums = vec![0_f64; channel_count];
    let mut peaks = vec![0_i32; channel_count];
    let mut silent = vec![0_u64; channel_count];
    let mut clipped = vec![0_u64; channel_count];
    let mut crossings = 0_u64;
    let mut previous = vec![None; channel_count];
    for frame in pcm.chunks_exact(channel_count) {
        for (channel, sample) in frame.iter().enumerate() {
            let value = i32::from(*sample);
            sums[channel] += f64::from(value) * f64::from(value);
            peaks[channel] = peaks[channel].max(value.abs());
            silent[channel] += u64::from(value.abs() <= 328);
            clipped[channel] += u64::from(value.abs() >= 32_600);
            if let Some(last) = previous[channel]
                && (last < 0) != (value < 0)
            {
                crossings += 1;
            }
            previous[channel] = Some(value);
        }
    }
    let channel_metrics: Vec<AudioChannelQuality> = (0..channel_count)
        .map(|channel| {
            let rms = if frame_count == 0 {
                0.0
            } else {
                (sums[channel] / frame_count as f64).sqrt()
            };
            AudioChannelQuality {
                channel: channel as u16 + 1,
                peak_level_dbfs_milli: level_dbfs_milli(f64::from(peaks[channel])),
                rms_level_dbfs_milli: level_dbfs_milli(rms),
                crest_factor_milli: (rms > 0.0)
                    .then(|| (f64::from(peaks[channel]) / rms * 1_000.0).round() as u32),
                silent_samples: silent[channel],
                clipped_samples: clipped[channel],
            }
        })
        .collect();

    let display_window_ms = coverage_ms
        .map(|duration| duration.div_ceil(6_000).max(100).div_ceil(20) * 20)
        .unwrap_or(100);
    let display_frames = (u64::from(sample_rate) * display_window_ms / 1_000).max(1) as usize;
    let mut level_series = Vec::new();
    let mut aggregate_rms = Vec::new();
    for (window_index, window) in pcm
        .chunks(display_frames.saturating_mul(channel_count))
        .enumerate()
    {
        let frames = window.len() / channel_count;
        if frames == 0 {
            continue;
        }
        let mut window_peaks = vec![0_i32; channel_count];
        let mut window_sums = vec![0_f64; channel_count];
        for frame in window.chunks_exact(channel_count) {
            for (channel, sample) in frame.iter().enumerate() {
                let value = i32::from(*sample);
                window_peaks[channel] = window_peaks[channel].max(value.abs());
                window_sums[channel] += f64::from(value) * f64::from(value);
            }
        }
        let window_rms: Vec<f64> = window_sums
            .iter()
            .map(|sum| (sum / frames as f64).sqrt())
            .collect();
        aggregate_rms.push(
            (window_rms.iter().map(|value| value * value).sum::<f64>() / channel_count as f64)
                .sqrt(),
        );
        level_series.push(AudioLevelPoint {
            offset_ms: window_index as u64 * display_window_ms,
            peak_level_dbfs_milli: window_peaks
                .iter()
                .map(|value| level_dbfs_milli(f64::from(*value)))
                .collect(),
            rms_level_dbfs_milli: window_rms
                .iter()
                .map(|value| level_dbfs_milli(*value))
                .collect(),
        });
    }

    let mut intervals = detect_quality_intervals(pcm, sample_rate, channel_count);
    detect_level_jumps(&level_series, display_window_ms, &mut intervals);
    intervals.sort_by_key(|interval| (interval.start_ms, interval.channel));
    intervals.truncate(2_048);
    let mut active_rms: Vec<f64> = aggregate_rms
        .into_iter()
        .filter(|value| *value >= 32.768)
        .collect();
    active_rms.sort_by(f64::total_cmp);
    let dynamic_range_db_milli = if active_rms.len() >= 10 {
        let low = active_rms[active_rms.len() / 10];
        let high = active_rms[active_rms.len() * 95 / 100];
        (low > 0.0).then(|| (20_000.0 * (high / low).log10()).round() as i32)
    } else {
        None
    };
    let spectral = analyze_spectrum(pcm, sample_rate, channel_count);
    let spectral_rolloff_hz = spectral_rolloff(&spectral.average);
    let channel_level_difference_db_milli = channel_level_difference(&channel_metrics);
    let stereo_correlation_milli = stereo_correlation(pcm, channel_count);
    let denominator = frame_count
        .saturating_sub(1)
        .saturating_mul(channel_count)
        .max(1);

    AudioQualityAnalysis {
        analysis_coverage_ms: coverage_ms,
        window_ms: display_window_ms as u32,
        scope: scope.into(),
        channels: channel_metrics,
        level_series,
        intervals,
        average_spectrum: spectral.average,
        spectrogram_band_centers_hz: spectral.band_centers_hz,
        spectrogram: spectral.frames,
        dynamic_range_db_milli,
        spectral_rolloff_hz,
        zero_crossing_rate_ppm: (frame_count > 1)
            .then(|| (crossings.saturating_mul(1_000_000) / denominator as u64) as u32),
        channel_level_difference_db_milli,
        stereo_correlation_milli,
        measurement_method: "PCM S16LE；20 ms 异常窗口；Hann FFT 2048；48 段 Mel 时频分析".into(),
        limitations: vec![
            "内容指标仅覆盖成功解码的 PCM；错误隐藏或播放补偿可能影响观测结果".into(),
            "动态范围排除低于 -60 dBFS 的窗口，属于节目内容统计而非设备标定值".into(),
        ],
        ..AudioQualityAnalysis::default()
    }
}

fn detect_quality_intervals(
    pcm: &[i16],
    sample_rate: u32,
    channel_count: usize,
) -> Vec<AudioQualityInterval> {
    let window_ms = 20_u64;
    let frames_per_window = (u64::from(sample_rate) * window_ms / 1_000).max(1) as usize;
    let mut starts = vec![[None, None]; channel_count];
    let mut intervals = Vec::new();
    for (index, window) in pcm
        .chunks(frames_per_window.saturating_mul(channel_count))
        .enumerate()
    {
        let frames = window.len() / channel_count;
        if frames == 0 {
            continue;
        }
        let start_ms = index as u64 * window_ms;
        for channel in 0..channel_count {
            let samples = window
                .chunks_exact(channel_count)
                .map(|frame| frame[channel]);
            let mut count = 0_u64;
            let mut silent = 0_u64;
            let mut clipped = 0_u64;
            for sample in samples {
                count += 1;
                silent += u64::from(i32::from(sample).abs() <= 328);
                clipped += u64::from(i32::from(sample).abs() >= 32_600);
            }
            let flags = [
                silent.saturating_mul(100) >= count.saturating_mul(95),
                clipped.saturating_mul(1_000) >= count.max(1),
            ];
            for (kind_index, active) in flags.into_iter().enumerate() {
                if active && starts[channel][kind_index].is_none() {
                    starts[channel][kind_index] = Some(start_ms);
                } else if !active && let Some(interval_start) = starts[channel][kind_index].take() {
                    push_quality_interval(
                        &mut intervals,
                        kind_index,
                        interval_start,
                        start_ms,
                        channel,
                    );
                }
            }
        }
    }
    let end_ms =
        pcm.len() as u64 * 1_000 / u64::from(sample_rate.max(1)) / channel_count.max(1) as u64;
    for (channel, states) in starts.into_iter().enumerate() {
        for (kind_index, start) in states.into_iter().enumerate() {
            if let Some(start) = start {
                push_quality_interval(&mut intervals, kind_index, start, end_ms, channel);
            }
        }
    }
    intervals.sort_by_key(|interval| (interval.start_ms, interval.channel));
    intervals.truncate(2_048);
    intervals
}

fn detect_level_jumps(
    levels: &[AudioLevelPoint],
    window_ms: u64,
    intervals: &mut Vec<AudioQualityInterval>,
) {
    for pair in levels.windows(2) {
        for (channel, (before, after)) in pair[0]
            .rms_level_dbfs_milli
            .iter()
            .zip(&pair[1].rms_level_dbfs_milli)
            .enumerate()
        {
            let (Some(before), Some(after)) = (before, after) else {
                continue;
            };
            let delta = after - before;
            if *before > -50_000 && *after > -50_000 && delta.abs() >= 12_000 {
                intervals.push(AudioQualityInterval {
                    kind: "level_jump_candidate".into(),
                    start_ms: pair[1].offset_ms,
                    end_ms: pair[1].offset_ms.saturating_add(window_ms),
                    channel: Some(channel as u16 + 1),
                    detail: format!("相邻电平窗口变化 {:+.1} dB", delta as f64 / 1_000.0),
                    precision: format!("decoded_pcm_{window_ms}ms_window"),
                    ..AudioQualityInterval::default()
                });
            }
        }
    }
}

fn push_quality_interval(
    intervals: &mut Vec<AudioQualityInterval>,
    kind_index: usize,
    start_ms: u64,
    end_ms: u64,
    channel: usize,
) {
    let minimum_ms = if kind_index == 0 { 100 } else { 20 };
    if end_ms.saturating_sub(start_ms) < minimum_ms {
        return;
    }
    let (kind, detail) = if kind_index == 0 {
        ("silence", "至少 95% 的采样低于 -40 dBFS")
    } else {
        ("clipping_candidate", "至少 0.1% 的采样接近满幅")
    };
    intervals.push(AudioQualityInterval {
        kind: kind.into(),
        start_ms,
        end_ms,
        channel: Some(channel as u16 + 1),
        detail: detail.into(),
        precision: "decoded_pcm_20ms_window".into(),
        ..AudioQualityInterval::default()
    });
}

struct SpectralAnalysis {
    average: Vec<AudioSpectrumPoint>,
    band_centers_hz: Vec<u32>,
    frames: Vec<AudioSpectrogramPoint>,
}

fn analyze_spectrum(pcm: &[i16], sample_rate: u32, channel_count: usize) -> SpectralAnalysis {
    const FFT_SIZE: usize = 2_048;
    const OUTPUT_BINS: usize = 256;
    const MEL_BANDS: usize = 48;
    const FRAME_LIMIT: usize = 512;
    let frame_count = pcm.len() / channel_count.max(1);
    if frame_count < FFT_SIZE || sample_rate == 0 || channel_count == 0 {
        return SpectralAnalysis {
            average: Vec::new(),
            band_centers_hz: Vec::new(),
            frames: Vec::new(),
        };
    }
    let available = frame_count - FFT_SIZE;
    let wanted = (frame_count / (FFT_SIZE / 2)).clamp(1, FRAME_LIMIT);
    let starts: Vec<usize> = if wanted == 1 {
        vec![0]
    } else {
        (0..wanted)
            .map(|index| index * available / (wanted - 1))
            .collect()
    };
    let maximum_hz = f64::from(sample_rate) / 2.0;
    let maximum_mel = hz_to_mel(maximum_hz);
    let mel_edges: Vec<usize> = (0..MEL_BANDS + 2)
        .map(|index| {
            let mel = maximum_mel * index as f64 / (MEL_BANDS + 1) as f64;
            ((mel_to_hz(mel) * FFT_SIZE as f64 / f64::from(sample_rate)).round() as usize)
                .min(FFT_SIZE / 2)
        })
        .collect();
    let band_centers_hz = mel_edges[1..=MEL_BANDS]
        .iter()
        .map(|bin| (*bin as u64 * u64::from(sample_rate) / FFT_SIZE as u64) as u32)
        .collect();
    let mut power = vec![0_f64; FFT_SIZE / 2 + 1];
    let mut frames = Vec::with_capacity(starts.len());
    for start in starts {
        let mut frame_power = vec![0_f64; FFT_SIZE / 2 + 1];
        for channel in 0..channel_count {
            let mut real = vec![0_f64; FFT_SIZE];
            let mut imaginary = vec![0_f64; FFT_SIZE];
            for (index, value) in real.iter_mut().enumerate() {
                let sample = pcm[(start + index) * channel_count + channel];
                let window = 0.5
                    - 0.5 * (std::f64::consts::TAU * index as f64 / (FFT_SIZE - 1) as f64).cos();
                *value = f64::from(sample) / 32_768.0 * window;
            }
            fft_in_place(&mut real, &mut imaginary);
            for index in 0..frame_power.len() {
                let magnitude = real[index].hypot(imaginary[index]) / (FFT_SIZE as f64 * 0.5);
                frame_power[index] += magnitude * magnitude / channel_count as f64;
            }
        }
        for index in 0..power.len() {
            power[index] += frame_power[index];
        }
        frames.push(AudioSpectrogramPoint {
            offset_ms: start as u64 * 1_000 / u64::from(sample_rate),
            band_levels_dbfs_milli: mel_band_levels(&frame_power, &mel_edges),
        });
    }
    let analyzed = frames.len() as f64;
    let average = (0..OUTPUT_BINS)
        .map(|output| {
            let start = output * power.len() / OUTPUT_BINS;
            let end = ((output + 1) * power.len() / OUTPUT_BINS).max(start + 1);
            let mean = power[start..end].iter().sum::<f64>() / (end - start) as f64 / analyzed;
            AudioSpectrumPoint {
                frequency_hz: (((start + end - 1) as u64 * u64::from(sample_rate))
                    / 2
                    / FFT_SIZE as u64) as u32,
                level_dbfs_milli: (10_000.0 * mean.max(1e-20).log10()).round() as i32,
            }
        })
        .collect();
    SpectralAnalysis {
        average,
        band_centers_hz,
        frames,
    }
}

fn hz_to_mel(hz: f64) -> f64 {
    2_595.0 * (1.0 + hz / 700.0).log10()
}

fn mel_to_hz(mel: f64) -> f64 {
    700.0 * (10_f64.powf(mel / 2_595.0) - 1.0)
}

fn mel_band_levels(power: &[f64], edges: &[usize]) -> Vec<i32> {
    edges
        .windows(3)
        .map(|edge| {
            let left = edge[0];
            let center = edge[1].max(left + 1);
            let right = edge[2].max(center + 1).min(power.len());
            let mut weighted = 0.0;
            let mut weights = 0.0;
            for (bin, value) in power.iter().enumerate().take(center).skip(left) {
                let weight = (bin - left) as f64 / (center - left) as f64;
                weighted += value * weight;
                weights += weight;
            }
            for (bin, value) in power.iter().enumerate().take(right).skip(center) {
                let weight = (right - bin) as f64 / (right - center) as f64;
                weighted += value * weight;
                weights += weight;
            }
            (10_000.0 * (weighted / weights.max(1.0)).max(1e-20).log10()).round() as i32
        })
        .collect()
}

fn channel_level_difference(channels: &[AudioChannelQuality]) -> Option<i32> {
    if channels.len() < 2 {
        return None;
    }
    let mut levels = channels
        .iter()
        .filter_map(|channel| channel.rms_level_dbfs_milli);
    let first = levels.next()?;
    let (minimum, maximum) = levels.fold((first, first), |(minimum, maximum), value| {
        (minimum.min(value), maximum.max(value))
    });
    Some(maximum - minimum)
}

fn stereo_correlation(pcm: &[i16], channel_count: usize) -> Option<i32> {
    if channel_count < 2 {
        return None;
    }
    let mut product = 0_f64;
    let mut left_square = 0_f64;
    let mut right_square = 0_f64;
    for frame in pcm.chunks_exact(channel_count) {
        let left = f64::from(frame[0]);
        let right = f64::from(frame[1]);
        product += left * right;
        left_square += left * left;
        right_square += right * right;
    }
    let denominator = (left_square * right_square).sqrt();
    (denominator > 0.0).then(|| (product / denominator * 1_000.0).round() as i32)
}

fn fft_in_place(real: &mut [f64], imaginary: &mut [f64]) {
    let length = real.len();
    let mut target = 0_usize;
    for index in 1..length {
        let mut bit = length >> 1;
        while target & bit != 0 {
            target ^= bit;
            bit >>= 1;
        }
        target ^= bit;
        if index < target {
            real.swap(index, target);
            imaginary.swap(index, target);
        }
    }
    let mut size = 2;
    while size <= length {
        let angle = -std::f64::consts::TAU / size as f64;
        let (step_imaginary, step_real) = angle.sin_cos();
        for start in (0..length).step_by(size) {
            let mut twiddle_real = 1.0;
            let mut twiddle_imaginary = 0.0;
            for offset in 0..size / 2 {
                let left = start + offset;
                let right = left + size / 2;
                let value_real = real[right] * twiddle_real - imaginary[right] * twiddle_imaginary;
                let value_imaginary =
                    real[right] * twiddle_imaginary + imaginary[right] * twiddle_real;
                real[right] = real[left] - value_real;
                imaginary[right] = imaginary[left] - value_imaginary;
                real[left] += value_real;
                imaginary[left] += value_imaginary;
                let next_real = twiddle_real * step_real - twiddle_imaginary * step_imaginary;
                twiddle_imaginary = twiddle_real * step_imaginary + twiddle_imaginary * step_real;
                twiddle_real = next_real;
            }
        }
        size *= 2;
    }
}

fn spectral_rolloff(spectrum: &[AudioSpectrumPoint]) -> Option<u32> {
    let powers: Vec<f64> = spectrum
        .iter()
        .map(|point| 10_f64.powf(point.level_dbfs_milli as f64 / 10_000.0))
        .collect();
    let total = powers.iter().sum::<f64>();
    if total <= 0.0 {
        return None;
    }
    let target = total * 0.85;
    let mut cumulative = 0.0;
    powers.iter().enumerate().find_map(|(index, value)| {
        cumulative += value;
        (cumulative >= target).then_some(spectrum[index].frequency_hz)
    })
}

fn write_wav(path: &Path, sample_rate: u32, channels: u16, samples: &[i16]) -> std::io::Result<()> {
    let mut writer = BufWriter::new(File::create(path)?);
    let data_bytes = (samples.len() as u32).saturating_mul(2);
    writer.write_all(b"RIFF")?;
    writer.write_all(&(36_u32.saturating_add(data_bytes)).to_le_bytes())?;
    writer.write_all(b"WAVEfmt ")?;
    writer.write_all(&16_u32.to_le_bytes())?;
    writer.write_all(&1_u16.to_le_bytes())?;
    writer.write_all(&channels.to_le_bytes())?;
    writer.write_all(&sample_rate.to_le_bytes())?;
    writer.write_all(
        &sample_rate
            .saturating_mul(u32::from(channels))
            .saturating_mul(2)
            .to_le_bytes(),
    )?;
    writer.write_all(&channels.saturating_mul(2).to_le_bytes())?;
    writer.write_all(&16_u16.to_le_bytes())?;
    writer.write_all(b"data")?;
    writer.write_all(&data_bytes.to_le_bytes())?;
    for sample in samples {
        writer.write_all(&sample.to_le_bytes())?;
    }
    writer.flush()
}

fn decode_alaw(value: u8) -> i16 {
    let value = value ^ 0x55;
    let mut sample = i32::from(value & 0x0f) << 4;
    let segment = i32::from((value & 0x70) >> 4);
    sample += 8;
    if segment >= 1 {
        sample += 0x100;
    }
    if segment > 1 {
        sample <<= segment - 1;
    }
    if value & 0x80 != 0 {
        sample as i16
    } else {
        (-sample) as i16
    }
}

fn decode_mulaw(value: u8) -> i16 {
    let value = !value;
    let sign = value & 0x80;
    let exponent = (value >> 4) & 0x07;
    let mantissa = value & 0x0f;
    let sample = (((i32::from(mantissa) << 3) + 0x84) << exponent) - 0x84;
    if sign != 0 {
        (-sample) as i16
    } else {
        sample as i16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g711_analysis_detects_timestamp_gap_and_decodes_samples() {
        let packets = vec![
            AudioRtpPayload {
                packet_number: Some(1),
                offset_ms: Some(0),
                sequence: Some(10),
                timestamp: 0,
                payload: vec![0xd5; 160],
            },
            AudioRtpPayload {
                packet_number: Some(2),
                offset_ms: Some(40),
                sequence: Some(11),
                timestamp: 320,
                payload: vec![0xd5; 160],
            },
        ];
        let result = analyze("PCMA", 8_000, Some(1), &packets, false, None).unwrap();
        assert_eq!(result.decoded_samples, 320);
        assert_eq!(result.timestamp_gap_count, 1);
        assert_eq!(result.sample_mappings.len(), 2);
        assert_eq!(result.sample_mappings[0].pcm_start_sample, 0);
        assert_eq!(result.sample_mappings[0].pcm_end_sample, 160);
        assert_eq!(result.sample_mappings[1].rtp_sequence, Some(11));
        let gap = result
            .issues
            .iter()
            .find(|issue| issue.kind == "timestamp_gap")
            .unwrap();
        assert_eq!(gap.previous_packet, Some(1));
        assert_eq!(gap.first_packet, Some(2));
        assert_eq!(gap.previous_rtp_sequence, Some(10));
        assert_eq!(gap.current_rtp_sequence, Some(11));
        assert_eq!(gap.expected_rtp_timestamp, Some(160));
        assert_eq!(gap.actual_rtp_timestamp, Some(320));
        assert_eq!(gap.delta_timestamp, Some(160));
        assert_eq!(gap.duration_ms, Some(20));
        assert_eq!(gap.media_start_ms, Some(20));
        assert_eq!(gap.media_end_ms, Some(40));
        assert!(!result.conclusion_reliable);
    }

    #[test]
    fn g711_analysis_locates_timestamp_overlap() {
        let packets = vec![
            AudioRtpPayload {
                packet_number: Some(7),
                offset_ms: Some(100),
                sequence: Some(20),
                timestamp: 1_000,
                payload: vec![0xd5; 160],
            },
            AudioRtpPayload {
                packet_number: Some(8),
                offset_ms: Some(120),
                sequence: Some(21),
                timestamp: 1_080,
                payload: vec![0xd5; 160],
            },
        ];
        let result = analyze("PCMA", 8_000, Some(1), &packets, false, None).unwrap();
        let overlap = result
            .issues
            .iter()
            .find(|issue| issue.kind == "timestamp_overlap")
            .unwrap();
        assert_eq!(overlap.delta_timestamp, Some(-80));
        assert_eq!(overlap.duration_ms, Some(10));
        assert_eq!(overlap.media_start_ms, Some(10));
        assert_eq!(overlap.media_end_ms, Some(20));
    }

    #[test]
    fn unsupported_codec_never_claims_pcm_quality() {
        let result = analyze("MPEG4-GENERIC", 48_000, Some(2), &[], false, None).unwrap();
        assert!(!result.codec_supported_for_decode);
        assert!(!result.conclusion_reliable);
    }

    #[test]
    fn telephony_raw_formats_keep_rtp_and_pcm_rates_distinct() {
        let g722 = raw_rtp_audio_spec("G722", 8_000).unwrap();
        assert_eq!(g722.ffmpeg_format, "g722");
        assert_eq!(g722.decoded_sample_rate, 16_000);
        assert_eq!(
            analyze("G722", 8_000, Some(1), &[], false, None)
                .unwrap()
                .sample_rate,
            Some(16_000)
        );
        assert_eq!(
            raw_rtp_audio_spec("G723", 8_000).unwrap().extension,
            "g723_1"
        );
        assert_eq!(raw_rtp_audio_spec("G729", 8_000).unwrap().extension, "g729");
        assert_eq!(
            raw_rtp_audio_spec("G726-16", 8_000).unwrap().code_size,
            Some(2)
        );
        assert_eq!(
            raw_rtp_audio_spec("G726-40", 8_000).unwrap().code_size,
            Some(5)
        );
        let aal2 = raw_rtp_audio_spec("AAL2-G726-32", 8_000).unwrap();
        assert_eq!(aal2.ffmpeg_format, "g726le");
        assert_eq!(aal2.code_size, Some(4));
        assert_eq!(
            raw_rtp_audio_spec("G726LE-24", 8_000).unwrap().code_size,
            Some(3)
        );
        assert!(raw_rtp_audio_spec("G726-20", 8_000).is_none());
    }

    #[test]
    fn raw_telephony_writer_preserves_packet_order() {
        let directory =
            std::env::temp_dir().join(format!("streamscope-raw-audio-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("sample.g722");
        let packets = vec![
            AudioRtpPayload {
                packet_number: Some(1),
                offset_ms: Some(0),
                sequence: Some(1),
                timestamp: 0,
                payload: vec![1, 2],
            },
            AudioRtpPayload {
                packet_number: Some(2),
                offset_ms: Some(20),
                sequence: Some(2),
                timestamp: 160,
                payload: Vec::new(),
            },
            AudioRtpPayload {
                packet_number: Some(3),
                offset_ms: Some(40),
                sequence: Some(3),
                timestamp: 320,
                payload: vec![3, 4],
            },
        ];
        assert_eq!(write_raw_rtp_audio(&packets, &path).unwrap(), 2);
        assert_eq!(std::fs::read(path).unwrap(), [1, 2, 3, 4]);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn decoded_wav_enriches_compressed_audio_quality() {
        let directory =
            std::env::temp_dir().join(format!("streamscope-wav-test-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("decoded.wav");
        write_wav(&path, 8_000, 1, &vec![0; 8_000]).unwrap();
        let mut analysis = AudioAnalysis {
            codec: "opus".into(),
            clock_rate: 48_000,
            packet_count: 50,
            issues: vec![AudioIssue {
                kind: "decode_not_supported".into(),
                ..AudioIssue::default()
            }],
            ..AudioAnalysis::default()
        };
        enrich_from_pcm_wav(&mut analysis, &path, false).unwrap();
        assert!(analysis.codec_supported_for_decode);
        assert!(analysis.conclusion_reliable);
        assert_eq!(analysis.decoded_duration_ms, Some(1_000));
        assert!(
            analysis
                .issues
                .iter()
                .any(|issue| issue.kind == "near_silence")
        );
        assert!(
            !analysis
                .issues
                .iter()
                .any(|issue| issue.kind == "decode_not_supported")
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pcm_quality_keeps_channels_and_locates_content_intervals() {
        let sample_rate = 8_000_u32;
        let frames = sample_rate * 2;
        let mut samples = Vec::with_capacity(frames as usize * 2);
        for frame in 0..frames {
            let left = if frame < sample_rate / 5 { 0 } else { 2_000 };
            let right = if (sample_rate / 2..sample_rate * 7 / 10).contains(&frame) {
                32_767
            } else {
                500
            };
            samples.extend_from_slice(&[left, right]);
        }
        let directory = std::env::temp_dir().join(format!(
            "streamscope-audio-quality-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("stereo.wav");
        write_wav(&path, sample_rate, 2, &samples).unwrap();
        let mut analysis = AudioAnalysis::default();
        enrich_from_pcm_wav_with_scope(&mut analysis, &path, false, "test_full").unwrap();

        let quality = analysis.quality.unwrap();
        assert_eq!(quality.scope, "test_full");
        assert_eq!(quality.analysis_coverage_ms, Some(2_000));
        assert_eq!(quality.channels.len(), 2);
        assert!(quality.level_series.len() >= 20);
        assert!(!quality.average_spectrum.is_empty());
        assert!(!quality.spectrogram.is_empty());
        assert_eq!(quality.spectrogram_band_centers_hz.len(), 48);
        assert!(quality.channel_level_difference_db_milli.is_some());
        assert!(quality.stereo_correlation_milli.is_some());
        assert!(quality.intervals.iter().any(|interval| {
            interval.kind == "silence"
                && interval.channel == Some(1)
                && interval.start_ms == 0
                && interval.end_ms >= 200
        }));
        assert!(quality.intervals.iter().any(|interval| {
            interval.kind == "clipping_candidate"
                && interval.channel == Some(2)
                && interval.start_ms <= 500
                && interval.end_ms >= 700
        }));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn writes_mpeg4_generic_access_unit_as_adts() {
        let mut payload = vec![0, 16, 0, 32];
        payload.extend_from_slice(&[1, 2, 3, 4]);
        let packets = vec![AudioRtpPayload {
            packet_number: None,
            offset_ms: None,
            sequence: Some(7),
            timestamp: 0,
            payload,
        }];
        let directory =
            std::env::temp_dir().join(format!("streamscope-aac-test-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("sample.aac");
        let fmtp = BTreeMap::from([("config".into(), "1210".into())]);
        let written = write_aac_adts_mapped(&packets, &fmtp, 44_100, Some(2), &path).unwrap();
        assert_eq!(written.units, 1);
        assert_eq!(written.mappings[0].rtp_sequence, Some(7));
        assert_eq!(written.mappings[0].pcm_end_sample, 1_024);
        assert_eq!(written.mappings[0].encoded_size, 11);
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[..2], &[0xff, 0xf1]);
        assert_eq!(bytes.len(), 11);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn writes_opus_packets_as_ogg_pages() {
        let directory =
            std::env::temp_dir().join(format!("streamscope-opus-test-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("sample.ogg");
        let packets = vec![
            AudioRtpPayload {
                packet_number: None,
                offset_ms: None,
                sequence: Some(7),
                timestamp: 0,
                payload: vec![0xf8, 0xff, 0xfe],
            },
            AudioRtpPayload {
                packet_number: None,
                offset_ms: None,
                sequence: Some(8),
                timestamp: 960,
                payload: vec![0xf8, 0xff, 0xfe],
            },
        ];
        let written = write_opus_ogg_mapped(&packets, Some(1), &path).unwrap();
        assert_eq!(written.units, 2);
        assert_eq!(written.mappings.len(), 2);
        assert_eq!(written.mappings[0].pcm_start_sample, 0);
        assert_eq!(written.mappings[0].pcm_end_sample, 960);
        assert_eq!(written.mappings[1].rtp_sequence, Some(8));
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[..8], b"OggS\0\x02\0\0");
        assert!(bytes.windows(8).any(|window| window == b"OpusHead"));
        assert!(bytes.windows(8).any(|window| window == b"OpusTags"));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
