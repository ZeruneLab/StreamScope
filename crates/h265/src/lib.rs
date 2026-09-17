use std::collections::BTreeSet;
use streamscope_core::{H264FrameEvidence, H264Issue, H265Analysis, H265PpsInfo, H265SpsInfo};

const MAX_FRAME_EVIDENCE: usize = 50_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nalu {
    pub data: Vec<u8>,
    pub timestamp: Option<u32>,
    pub start_sequence: Option<u16>,
    pub end_sequence: Option<u16>,
    pub complete: bool,
    pub marker: bool,
}

impl Nalu {
    fn from_rtp(data: Vec<u8>, packet: &RtpPayload, start: u16, complete: bool) -> Self {
        Self {
            data,
            timestamp: Some(packet.timestamp),
            start_sequence: Some(start),
            end_sequence: Some(packet.sequence),
            complete,
            marker: packet.marker,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPayload {
    pub sequence: u16,
    pub timestamp: u32,
    pub marker: bool,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
struct FuAssembly {
    timestamp: u32,
    start_sequence: u16,
    last_sequence: u16,
    data: Vec<u8>,
    broken: bool,
}

#[derive(Debug, Default)]
pub struct Depacketizer {
    current: Option<FuAssembly>,
    pub issues: Vec<H264Issue>,
}

impl Depacketizer {
    pub fn push(&mut self, packet: RtpPayload) -> Vec<Nalu> {
        if packet.payload.len() < 2 || packet.payload[1] & 7 == 0 {
            self.issue(
                "h265_invalid_payload_header",
                "H.265 RTP 负载头无效",
                Some(&packet),
            );
            return Vec::new();
        }
        match (packet.payload[0] >> 1) & 0x3f {
            0..=47 => vec![Nalu::from_rtp(
                packet.payload.clone(),
                &packet,
                packet.sequence,
                true,
            )],
            48 => self.parse_ap(packet),
            49 => self.push_fu(packet),
            kind => {
                self.issue(
                    "h265_unsupported_packetization",
                    &format!("不支持的 H.265 RTP NAL 类型 {kind}"),
                    Some(&packet),
                );
                Vec::new()
            }
        }
    }

    pub fn finish(&mut self) -> Vec<Nalu> {
        self.current
            .take()
            .map(|current| {
                self.issues.push(H264Issue {
                    kind: "h265_fu_missing_end".into(),
                    detail: "H.265 FU 在流结束前未收到 End 分片".into(),
                    sequence: Some(current.last_sequence),
                    timestamp: Some(current.timestamp),
                });
                vec![Nalu {
                    data: current.data,
                    timestamp: Some(current.timestamp),
                    start_sequence: Some(current.start_sequence),
                    end_sequence: Some(current.last_sequence),
                    complete: false,
                    marker: false,
                }]
            })
            .unwrap_or_default()
    }

    fn parse_ap(&mut self, packet: RtpPayload) -> Vec<Nalu> {
        let mut cursor = 2;
        let mut nalus = Vec::new();
        while cursor < packet.payload.len() {
            if cursor + 2 > packet.payload.len() {
                self.issue("h265_ap_length", "H.265 AP 长度字段不完整", Some(&packet));
                break;
            }
            let length = usize::from(u16::from_be_bytes([
                packet.payload[cursor],
                packet.payload[cursor + 1],
            ]));
            cursor += 2;
            if length < 2 || cursor + length > packet.payload.len() {
                self.issue("h265_ap_length", "H.265 AP NALU 长度越界", Some(&packet));
                break;
            }
            let end = cursor + length;
            nalus.push(Nalu::from_rtp(
                packet.payload[cursor..end].to_vec(),
                &packet,
                packet.sequence,
                true,
            ));
            cursor = end;
        }
        for nalu in &mut nalus {
            nalu.marker = false;
        }
        if let Some(last) = nalus.last_mut() {
            last.marker = packet.marker;
        }
        nalus
    }

    fn push_fu(&mut self, packet: RtpPayload) -> Vec<Nalu> {
        if packet.payload.len() < 3 {
            self.issue("h265_fu_header", "H.265 FU 头部长度不足", Some(&packet));
            return Vec::new();
        }
        let fu_header = packet.payload[2];
        let start = fu_header & 0x80 != 0;
        let end = fu_header & 0x40 != 0;
        let reconstructed = [
            (packet.payload[0] & 0x81) | ((fu_header & 0x3f) << 1),
            packet.payload[1],
        ];
        let mut output = Vec::new();
        if start {
            if let Some(previous) = self.current.take() {
                self.issues.push(H264Issue {
                    kind: "h265_fu_missing_end".into(),
                    detail: "新的 H.265 FU Start 到达时上一 NALU 尚未结束".into(),
                    sequence: Some(previous.last_sequence),
                    timestamp: Some(previous.timestamp),
                });
                output.push(Nalu {
                    data: previous.data,
                    timestamp: Some(previous.timestamp),
                    start_sequence: Some(previous.start_sequence),
                    end_sequence: Some(previous.last_sequence),
                    complete: false,
                    marker: false,
                });
            }
            let mut data = reconstructed.to_vec();
            data.extend_from_slice(&packet.payload[3..]);
            self.current = Some(FuAssembly {
                timestamp: packet.timestamp,
                start_sequence: packet.sequence,
                last_sequence: packet.sequence,
                data,
                broken: false,
            });
        } else if let Some(current) = self.current.as_mut() {
            let timestamp_changed = current.timestamp != packet.timestamp;
            let sequence_gap = packet.sequence != current.last_sequence.wrapping_add(1);
            current.broken |= timestamp_changed || sequence_gap;
            current.last_sequence = packet.sequence;
            current.data.extend_from_slice(&packet.payload[3..]);
            if timestamp_changed {
                self.issue(
                    "h265_fu_timestamp_changed",
                    "H.265 FU 跨越 RTP Timestamp",
                    Some(&packet),
                );
            }
            if sequence_gap {
                self.issue(
                    "h265_fu_sequence_gap",
                    "H.265 FU Sequence 不连续",
                    Some(&packet),
                );
            }
        } else {
            self.issue(
                "h265_fu_missing_start",
                "收到 H.265 FU 中间或结束分片但没有 Start",
                Some(&packet),
            );
            return output;
        }
        if end && let Some(current) = self.current.take() {
            output.push(Nalu {
                data: current.data,
                timestamp: Some(current.timestamp),
                start_sequence: Some(current.start_sequence),
                end_sequence: Some(current.last_sequence),
                complete: !current.broken,
                marker: packet.marker,
            });
        }
        output
    }

    fn issue(&mut self, kind: &str, detail: &str, packet: Option<&RtpPayload>) {
        self.issues.push(H264Issue {
            kind: kind.into(),
            detail: detail.into(),
            sequence: packet.map(|packet| packet.sequence),
            timestamp: packet.map(|packet| packet.timestamp),
        });
    }
}

pub fn split_annex_b(input: &[u8]) -> Vec<Nalu> {
    let mut starts = Vec::new();
    let mut index = 0;
    while index + 3 <= input.len() {
        let length = if input[index..].starts_with(&[0, 0, 1]) {
            3
        } else if input[index..].starts_with(&[0, 0, 0, 1]) {
            4
        } else {
            index += 1;
            continue;
        };
        starts.push((index, length));
        index += length;
    }
    starts
        .iter()
        .enumerate()
        .filter_map(|(position, (start, length))| {
            let data_start = start + length;
            let data_end = starts
                .get(position + 1)
                .map(|value| value.0)
                .unwrap_or(input.len());
            (data_end >= data_start + 2).then(|| Nalu {
                data: input[data_start..data_end].to_vec(),
                timestamp: None,
                start_sequence: None,
                end_sequence: None,
                complete: true,
                marker: false,
            })
        })
        .collect()
}

pub fn analyze_annex_b(input: &[u8]) -> H265Analysis {
    analyze_nalus(split_annex_b(input), Vec::new())
}

pub fn analyze_nalus(nalus: Vec<Nalu>, mut issues: Vec<H264Issue>) -> H265Analysis {
    let mut analysis = H265Analysis::default();
    let mut seen_vps = false;
    let mut sps_ids = BTreeSet::new();
    let mut pps_ids = BTreeSet::new();
    let mut frame_timestamps = BTreeSet::new();
    let mut frame_index = 0_u64;
    let mut irap_positions = Vec::new();
    for (nalu_index, nalu) in nalus.iter().enumerate() {
        analysis.nalu_count += 1;
        if nalu.complete {
            analysis.complete_nalus += 1
        } else {
            analysis.incomplete_nalus += 1
        }
        if nalu.data.len() < 2 {
            issues.push(issue("h265_short_nalu", "H.265 NALU 少于 2 字节", nalu));
            continue;
        }
        if nalu.data[0] & 0x80 != 0 || nalu.data[1] & 7 == 0 {
            issues.push(issue("h265_invalid_nalu_header", "H.265 NALU 头无效", nalu));
        }
        let kind = (nalu.data[0] >> 1) & 0x3f;
        *analysis
            .nalu_types
            .entry(nalu_type_name(kind).into())
            .or_insert(0) += 1;
        match kind {
            32 => {
                seen_vps = true;
                analysis.vps_count += 1;
            }
            33 => match parse_sps(&nalu.data) {
                Ok(sps) => {
                    sps_ids.insert(sps.id);
                    if let Some(existing) = analysis.sps.iter_mut().find(|item| item.id == sps.id) {
                        if existing.width != sps.width || existing.height != sps.height {
                            issues.push(issue(
                                "h265_resolution_changed",
                                "H.265 SPS 分辨率发生变化",
                                nalu,
                            ));
                        }
                        *existing = sps;
                    } else {
                        analysis.sps.push(sps);
                    }
                }
                Err(error) => issues.push(issue("h265_invalid_sps", error, nalu)),
            },
            34 => match parse_pps(&nalu.data) {
                Ok(pps) => {
                    if !sps_ids.contains(&pps.sps_id) {
                        issues.push(issue(
                            "h265_pps_missing_sps",
                            "H.265 PPS 引用了尚未出现的 SPS",
                            nalu,
                        ));
                    }
                    pps_ids.insert(pps.id);
                    if let Some(existing) = analysis.pps.iter_mut().find(|item| item.id == pps.id) {
                        *existing = pps;
                    } else {
                        analysis.pps.push(pps);
                    }
                }
                Err(error) => issues.push(issue("h265_invalid_pps", error, nalu)),
            },
            0..=31 => {
                let first_slice = parse_first_slice(&nalu.data).ok();
                let starts_frame = first_slice.unwrap_or_else(|| {
                    nalu.timestamp
                        .map(|ts| frame_timestamps.insert(ts))
                        .unwrap_or(true)
                });
                if starts_frame {
                    frame_index += 1;
                    analysis.frame_count += 1;
                    let irap = (16..=23).contains(&kind);
                    let idr = matches!(kind, 19 | 20);
                    let cra = kind == 21;
                    analysis.first_frame_is_irap.get_or_insert(irap);
                    if irap {
                        analysis.irap_frames += 1;
                        analysis.idr_frames += u64::from(idr);
                        analysis.cra_frames += u64::from(cra);
                        irap_positions.push(frame_index);
                        if analysis.first_irap_frame.is_none() {
                            analysis.first_irap_frame = Some(frame_index);
                            analysis.vps_before_first_irap = seen_vps;
                            analysis.sps_before_first_irap = !sps_ids.is_empty();
                            analysis.pps_before_first_irap = !pps_ids.is_empty();
                        }
                    }
                    if analysis.frames.len() < MAX_FRAME_EVIDENCE {
                        analysis.frames.push(H264FrameEvidence {
                            frame_number: frame_index,
                            rtp_timestamp: nalu.timestamp,
                            first_sequence: nalu.start_sequence,
                            last_sequence: nalu.end_sequence,
                            first_nalu: nalu_index as u64 + 1,
                            last_nalu: nalu_index as u64 + 1,
                            first_packet: None,
                            last_packet: None,
                            first_offset_ms: None,
                            last_offset_ms: None,
                            sample_start_offset: None,
                            sample_end_offset: None,
                            idr: irap,
                            complete: nalu.complete,
                            boundary_confidence: if first_slice.is_some() {
                                "slice_header"
                            } else if nalu.timestamp.is_some() {
                                "rtp_timestamp"
                            } else {
                                "single_nalu"
                            }
                            .into(),
                        });
                    } else {
                        analysis.frame_evidence_truncated = true;
                    }
                } else if let Some(frame) = analysis.frames.last_mut()
                    && frame.frame_number == frame_index
                {
                    frame.last_nalu = nalu_index as u64 + 1;
                    frame.last_sequence = nalu.end_sequence.or(frame.last_sequence);
                    frame.idr |= (16..=23).contains(&kind);
                    frame.complete &= nalu.complete;
                }
            }
            _ => {}
        }
    }
    let intervals: Vec<_> = irap_positions
        .windows(2)
        .map(|pair| pair[1] - pair[0])
        .collect();
    if !intervals.is_empty() {
        analysis.average_gop_frames = Some(intervals.iter().sum::<u64>() / intervals.len() as u64);
        analysis.maximum_gop_frames = intervals.into_iter().max();
    }
    if !seen_vps {
        issues.push(H264Issue {
            kind: "h265_missing_vps".into(),
            detail: "码流中没有发现 VPS".into(),
            sequence: None,
            timestamp: None,
        });
    }
    if analysis.sps.is_empty() {
        issues.push(H264Issue {
            kind: "h265_missing_sps".into(),
            detail: "码流中没有发现 H.265 SPS".into(),
            sequence: None,
            timestamp: None,
        });
    }
    if analysis.pps.is_empty() {
        issues.push(H264Issue {
            kind: "h265_missing_pps".into(),
            detail: "码流中没有发现 H.265 PPS".into(),
            sequence: None,
            timestamp: None,
        });
    }
    analysis.issues = issues;
    analysis
}

fn issue(kind: &str, detail: &str, nalu: &Nalu) -> H264Issue {
    H264Issue {
        kind: kind.into(),
        detail: detail.into(),
        sequence: nalu.start_sequence,
        timestamp: nalu.timestamp,
    }
}

fn nalu_type_name(kind: u8) -> &'static str {
    match kind {
        0..=9 => "trail_slice",
        16..=18 => "bla_slice",
        19 | 20 => "idr_slice",
        21 => "cra_slice",
        22 | 23 => "irap_reserved",
        32 => "vps",
        33 => "sps",
        34 => "pps",
        35 => "aud",
        39 => "prefix_sei",
        40 => "suffix_sei",
        48 => "ap",
        49 => "fu",
        _ => "other",
    }
}

#[derive(Debug, thiserror::Error)]
enum ParseError {
    #[error("参数集或 Slice 数据不足")]
    End,
    #[error("Exp-Golomb 无效")]
    Golomb,
}

struct Bits {
    data: Vec<u8>,
    bit: usize,
}
impl Bits {
    fn new(ebsp: &[u8]) -> Self {
        let mut data = Vec::with_capacity(ebsp.len());
        let mut zeros = 0;
        for &byte in ebsp {
            if zeros >= 2 && byte == 3 {
                zeros = 0;
                continue;
            }
            data.push(byte);
            zeros = if byte == 0 { zeros + 1 } else { 0 };
        }
        Self { data, bit: 0 }
    }
    fn read(&mut self, count: usize) -> Result<u32, ParseError> {
        if count > 32 || self.bit + count > self.data.len() * 8 {
            return Err(ParseError::End);
        }
        let mut value = 0;
        for _ in 0..count {
            value = (value << 1) | u32::from((self.data[self.bit / 8] >> (7 - self.bit % 8)) & 1);
            self.bit += 1;
        }
        Ok(value)
    }
    fn flag(&mut self) -> Result<bool, ParseError> {
        Ok(self.read(1)? != 0)
    }
    fn ue(&mut self) -> Result<u32, ParseError> {
        let mut zeros = 0;
        while !self.flag()? {
            zeros += 1;
            if zeros > 31 {
                return Err(ParseError::Golomb);
            }
        }
        Ok(if zeros == 0 {
            0
        } else {
            (1_u32 << zeros) - 1 + self.read(zeros)?
        })
    }
}

fn skip_profile_tier_level(bits: &mut Bits, max_sub_layers: u8) -> Result<(u8, u8), ParseError> {
    bits.read(2)?;
    bits.read(1)?;
    let profile = bits.read(5)? as u8;
    bits.read(32)?;
    bits.read(32)?;
    bits.read(16)?;
    let level = bits.read(8)? as u8;
    let mut profile_present = [false; 7];
    let mut level_present = [false; 7];
    for index in 0..max_sub_layers as usize {
        profile_present[index] = bits.flag()?;
        level_present[index] = bits.flag()?;
    }
    if max_sub_layers > 0 {
        for _ in max_sub_layers..8 {
            bits.read(2)?;
        }
    }
    for index in 0..max_sub_layers as usize {
        if profile_present[index] {
            bits.read(32)?;
            bits.read(32)?;
            bits.read(16)?;
            bits.read(8)?;
        }
        if level_present[index] {
            bits.read(8)?;
        }
    }
    Ok((profile, level))
}

fn parse_sps(data: &[u8]) -> Result<H265SpsInfo, &'static str> {
    if data.len() < 4 {
        return Err("H.265 SPS 太短");
    }
    let mut bits = Bits::new(&data[2..]);
    let vps_id = bits.read(4).map_err(|_| "H.265 SPS 头不完整")? as u8;
    let max_sub_layers = bits.read(3).map_err(|_| "H.265 SPS 子层字段不完整")? as u8 + 1;
    bits.flag().map_err(|_| "H.265 SPS temporal nesting 缺失")?;
    let (profile_idc, level_idc) = skip_profile_tier_level(&mut bits, max_sub_layers - 1)
        .map_err(|_| "H.265 profile_tier_level 不完整")?;
    let id = bits.ue().map_err(|_| "H.265 SPS ID 无效")?;
    let chroma = bits.ue().map_err(|_| "H.265 chroma_format_idc 无效")?;
    if chroma == 3 {
        bits.flag()
            .map_err(|_| "H.265 separate_colour_plane_flag 缺失")?;
    }
    let mut width = bits.ue().map_err(|_| "H.265 宽度无效")?;
    let mut height = bits.ue().map_err(|_| "H.265 高度无效")?;
    if bits
        .flag()
        .map_err(|_| "H.265 conformance_window_flag 缺失")?
    {
        let left = bits.ue().map_err(|_| "H.265 crop_left 无效")?;
        let right = bits.ue().map_err(|_| "H.265 crop_right 无效")?;
        let top = bits.ue().map_err(|_| "H.265 crop_top 无效")?;
        let bottom = bits.ue().map_err(|_| "H.265 crop_bottom 无效")?;
        let (sub_width, sub_height) = match chroma {
            1 => (2, 2),
            2 => (2, 1),
            _ => (1, 1),
        };
        width = width.saturating_sub((left + right) * sub_width);
        height = height.saturating_sub((top + bottom) * sub_height);
    }
    let bit_depth_luma = bits
        .ue()
        .map_err(|_| "H.265 luma bit depth 无效")?
        .saturating_add(8) as u8;
    let bit_depth_chroma = bits
        .ue()
        .map_err(|_| "H.265 chroma bit depth 无效")?
        .saturating_add(8) as u8;
    if width == 0 || height == 0 {
        return Err("H.265 SPS 分辨率为零");
    }
    Ok(H265SpsInfo {
        id,
        vps_id,
        max_sub_layers,
        profile_idc,
        level_idc,
        chroma_format_idc: chroma,
        bit_depth_luma,
        bit_depth_chroma,
        width,
        height,
    })
}

fn parse_pps(data: &[u8]) -> Result<H265PpsInfo, &'static str> {
    if data.len() < 3 {
        return Err("H.265 PPS 太短");
    }
    let mut bits = Bits::new(&data[2..]);
    Ok(H265PpsInfo {
        id: bits.ue().map_err(|_| "H.265 PPS ID 无效")?,
        sps_id: bits.ue().map_err(|_| "H.265 PPS SPS ID 无效")?,
    })
}

fn parse_first_slice(data: &[u8]) -> Result<bool, ParseError> {
    if data.len() < 3 {
        return Err(ParseError::End);
    }
    Bits::new(&data[2..]).flag()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassembles_h265_fu() {
        let mut depacketizer = Depacketizer::default();
        let first = depacketizer.push(RtpPayload {
            sequence: 10,
            timestamp: 90_000,
            marker: false,
            payload: vec![98, 1, 0x93, 1, 2],
        });
        assert!(first.is_empty());
        let last = depacketizer.push(RtpPayload {
            sequence: 11,
            timestamp: 90_000,
            marker: true,
            payload: vec![98, 1, 0x53, 3, 4],
        });
        assert_eq!(last.len(), 1);
        assert_eq!((last[0].data[0] >> 1) & 0x3f, 19);
        assert!(last[0].complete);
    }

    #[test]
    fn splits_h265_aggregation_packet() {
        let mut depacketizer = Depacketizer::default();
        let nalus = depacketizer.push(RtpPayload {
            sequence: 20,
            timestamp: 180_000,
            marker: true,
            payload: vec![96, 1, 0, 3, 0x40, 1, 0xaa, 0, 3, 0x44, 1, 0xbb],
        });
        assert_eq!(nalus.len(), 2);
        assert_eq!((nalus[0].data[0] >> 1) & 0x3f, 32);
        assert_eq!((nalus[1].data[0] >> 1) & 0x3f, 34);
        assert!(!nalus[0].marker);
        assert!(nalus[1].marker);
        assert!(depacketizer.issues.is_empty());
    }

    #[test]
    fn splits_annex_b_and_counts_irap_frames() {
        let data = [0, 0, 1, 38, 1, 0x80, 0, 0, 0, 1, 2, 1, 0x80];
        let analysis = analyze_annex_b(&data);
        assert_eq!(analysis.frame_count, 2);
        assert_eq!(analysis.idr_frames, 1);
        assert_eq!(analysis.frames.len(), 2);
    }
}
