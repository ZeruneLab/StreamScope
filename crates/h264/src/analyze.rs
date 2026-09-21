use crate::{nalu_type_name, parse_pps, parse_slice_header, parse_sps};
use std::collections::BTreeSet;
use streamscope_core::{
    H264Analysis, H264FrameEvidence, H264HrdAuPoint, H264HrdInfo, H264HrdSimulation, H264Issue,
    H264SpsInfo, VideoNaluEvidence, VideoParameterChange, VideoSyntaxField, VideoSyntaxNalu,
};

use crate::{BitReader, ebsp_to_rbsp};

const MAX_FRAME_EVIDENCE: usize = 50_000;
const MAX_NALU_EVIDENCE: usize = 100_000;
const MAX_HRD_POINTS: usize = 50_000;

#[derive(Debug, Clone)]
struct HrdEpoch {
    schedule: &'static str,
    sps_id: u32,
    hrd: H264HrdInfo,
    num_units_in_tick: u32,
    time_scale: u32,
    initial_cpb_removal_delay: u32,
}

#[derive(Debug, Clone, Copy)]
struct HrdPicTiming {
    sei_nalu: u64,
    cpb_removal_delay: u32,
    dpb_output_delay: u32,
}

#[derive(Debug)]
struct HrdAuInput {
    access_unit: u64,
    bits: u64,
    complete: bool,
    epoch: Option<HrdEpoch>,
    timing: Option<HrdPicTiming>,
}

#[derive(Debug)]
struct HrdAuBuilder {
    access_unit: u64,
    bits: u64,
    complete: bool,
    epoch: Option<HrdEpoch>,
    timing: Option<HrdPicTiming>,
}

impl From<HrdAuBuilder> for HrdAuInput {
    fn from(value: HrdAuBuilder) -> Self {
        Self {
            access_unit: value.access_unit,
            bits: value.bits,
            complete: value.complete,
            epoch: value.epoch,
            timing: value.timing,
        }
    }
}

fn parse_sei_hrd(
    nalu: &[u8],
    nalu_number: u64,
    sps: &[H264SpsInfo],
    active_sps_id: &mut Option<u32>,
) -> (Vec<HrdEpoch>, Vec<HrdPicTiming>, Vec<String>) {
    let mut epochs = Vec::new();
    let mut timings = Vec::new();
    let mut limitations = Vec::new();
    if nalu.first().map(|value| value & 0x1f) != Some(6) {
        return (epochs, timings, limitations);
    }
    let rbsp = ebsp_to_rbsp(&nalu[1..]);
    let mut offset = 0_usize;
    while offset < rbsp.len() {
        if rbsp[offset] == 0x80 && rbsp[offset + 1..].iter().all(|byte| *byte == 0) {
            break;
        }
        let mut payload_type = 0_u32;
        while offset < rbsp.len() && rbsp[offset] == 0xff {
            payload_type = payload_type.saturating_add(255);
            offset += 1;
        }
        let Some(type_tail) = rbsp.get(offset).copied() else {
            limitations.push(format!("SEI NALU #{nalu_number} 的 payloadType 被截断"));
            break;
        };
        payload_type = payload_type.saturating_add(u32::from(type_tail));
        offset += 1;

        let mut payload_size = 0_usize;
        while offset < rbsp.len() && rbsp[offset] == 0xff {
            payload_size = payload_size.saturating_add(255);
            offset += 1;
        }
        let Some(size_tail) = rbsp.get(offset).copied() else {
            limitations.push(format!("SEI NALU #{nalu_number} 的 payloadSize 被截断"));
            break;
        };
        payload_size = payload_size.saturating_add(usize::from(size_tail));
        offset += 1;
        let Some(end) = offset.checked_add(payload_size) else {
            limitations.push(format!("SEI NALU #{nalu_number} 的 payloadSize 溢出"));
            break;
        };
        let Some(payload) = rbsp.get(offset..end) else {
            limitations.push(format!("SEI NALU #{nalu_number} 的 payload 数据不足"));
            break;
        };
        offset = end;

        match payload_type {
            0 => {
                let mut bits = BitReader::new(payload);
                let Ok(sps_id) = bits.read_ue() else {
                    limitations.push(format!(
                        "SEI NALU #{nalu_number} 的 buffering_period 无法解析 SPS ID"
                    ));
                    continue;
                };
                let Some(sps) = sps.iter().find(|value| value.id == sps_id) else {
                    limitations.push(format!(
                        "SEI NALU #{nalu_number} 的 buffering_period 引用未知 SPS {sps_id}"
                    ));
                    continue;
                };
                *active_sps_id = Some(sps_id);
                let mut selected = None;
                for (schedule, hrd) in
                    [("nal", sps.nal_hrd.as_ref()), ("vcl", sps.vcl_hrd.as_ref())]
                {
                    let Some(hrd) = hrd else { continue };
                    let mut first_delay = None;
                    let mut valid = true;
                    for index in 0..hrd.cpb_count {
                        let delay = bits.read_bits(hrd.initial_cpb_removal_delay_length);
                        let offset_value = bits.read_bits(hrd.initial_cpb_removal_delay_length);
                        match (delay, offset_value) {
                            (Ok(delay), Ok(_)) if index == 0 => first_delay = Some(delay),
                            (Ok(_), Ok(_)) => {}
                            _ => {
                                valid = false;
                                break;
                            }
                        }
                    }
                    if !valid {
                        limitations.push(format!(
                            "SEI NALU #{nalu_number} 的 {schedule} buffering_period 长度不足"
                        ));
                        continue;
                    }
                    if selected.is_none()
                        && let (Some(initial_delay), Some(num_units_in_tick), Some(time_scale)) =
                            (first_delay, sps.num_units_in_tick, sps.time_scale)
                    {
                        selected = Some(HrdEpoch {
                            schedule,
                            sps_id,
                            hrd: hrd.clone(),
                            num_units_in_tick,
                            time_scale,
                            initial_cpb_removal_delay: initial_delay,
                        });
                    }
                }
                if let Some(epoch) = selected {
                    epochs.push(epoch);
                } else {
                    limitations.push(format!(
                        "SEI NALU #{nalu_number} 缺少可仿真的 HRD 时钟或 CPB 参数"
                    ));
                }
            }
            1 => {
                let Some(sps_id) = *active_sps_id else {
                    limitations.push(format!(
                        "SEI NALU #{nalu_number} 的 pic_timing 之前没有可用 buffering_period"
                    ));
                    continue;
                };
                let Some(sps) = sps.iter().find(|value| value.id == sps_id) else {
                    limitations.push(format!(
                        "SEI NALU #{nalu_number} 的 pic_timing 对应 SPS {sps_id} 不可用"
                    ));
                    continue;
                };
                let Some(hrd) = sps.nal_hrd.as_ref().or(sps.vcl_hrd.as_ref()) else {
                    continue;
                };
                let mut bits = BitReader::new(payload);
                match (
                    bits.read_bits(hrd.cpb_removal_delay_length),
                    bits.read_bits(hrd.dpb_output_delay_length),
                ) {
                    (Ok(cpb_removal_delay), Ok(dpb_output_delay)) => {
                        timings.push(HrdPicTiming {
                            sei_nalu: nalu_number,
                            cpb_removal_delay,
                            dpb_output_delay,
                        });
                    }
                    _ => {
                        limitations.push(format!("SEI NALU #{nalu_number} 的 pic_timing 长度不足"))
                    }
                }
            }
            _ => {}
        }
    }
    (epochs, timings, limitations)
}

fn simulate_hrd(analysis: &mut H264HrdSimulation, access_units: Vec<HrdAuInput>, declared: bool) {
    analysis.status = if declared {
        "evidence_insufficient"
    } else {
        "not_declared"
    }
    .into();
    if !declared {
        analysis
            .limitations
            .push("SPS VUI 未声明 NAL/VCL HRD".into());
        return;
    }

    let mut active: Option<(HrdEpoch, u64, Option<u32>)> = None;
    for au in access_units {
        if let Some(epoch) = au.epoch {
            analysis.sps_id = Some(epoch.sps_id);
            analysis.schedule = epoch.schedule.into();
            analysis.cpb_entry_index = Some(0);
            let Some(entry) = epoch.hrd.entries.first() else {
                analysis.limitations.push(format!(
                    "AU #{} 的 HRD 没有逐 CPB 参数（旧报告兼容数据）",
                    au.access_unit
                ));
                active = None;
                continue;
            };
            if epoch.hrd.cpb_count != 1 || epoch.hrd.entries.len() != 1 {
                analysis.limitations.push(format!(
                    "AU #{} 起声明 {} 个 CPB；当前仅对单 CPB schedule 做确定性仿真",
                    au.access_unit, epoch.hrd.cpb_count
                ));
                active = None;
                continue;
            }
            if !entry.cbr {
                analysis.limitations.push(format!(
                    "AU #{} 起为 VBR CPB；缺少逐比特到达计划，未输出确定性 fullness",
                    au.access_unit
                ));
                active = None;
                continue;
            }
            if epoch.num_units_in_tick == 0 || epoch.time_scale == 0 {
                analysis
                    .limitations
                    .push(format!("AU #{} 起的 VUI timing_info 无效", au.access_unit));
                active = None;
                continue;
            }
            let initial_fullness = (u128::from(entry.bit_rate_bps)
                * u128::from(epoch.initial_cpb_removal_delay)
                / 90_000)
                .min(u128::from(u64::MAX)) as u64;
            active = Some((epoch, initial_fullness, None));
        }

        let Some((epoch, fullness_after_previous, previous_delay)) = active.take() else {
            continue;
        };
        if !au.complete {
            analysis.limitations.push(format!(
                "AU #{} 不完整，已中止该 HRD epoch 的连续仿真",
                au.access_unit
            ));
            continue;
        }
        let Some(timing) = au.timing else {
            analysis.limitations.push(format!(
                "AU #{} 缺少 pic_timing，已中止该 HRD epoch 的连续仿真",
                au.access_unit
            ));
            continue;
        };
        let entry = &epoch.hrd.entries[0];
        let fullness_before = if let Some(previous_delay) = previous_delay {
            let modulus = 1_u64 << epoch.hrd.cpb_removal_delay_length;
            let delta = (u64::from(timing.cpb_removal_delay) + modulus - u64::from(previous_delay))
                % modulus;
            if delta == 0 {
                analysis.delay_discontinuities.push(au.access_unit);
            }
            let arrived = (u128::from(entry.bit_rate_bps)
                * u128::from(delta)
                * u128::from(epoch.num_units_in_tick)
                / u128::from(epoch.time_scale))
            .min(u128::from(u64::MAX)) as u64;
            fullness_after_previous.saturating_add(arrived)
        } else {
            fullness_after_previous
        };
        let overflow = fullness_before > entry.cpb_size_bits;
        let underflow = fullness_before < au.bits;
        let fullness_after = fullness_before.saturating_sub(au.bits);
        if overflow {
            analysis.overflow_aus.push(au.access_unit);
        }
        if underflow {
            analysis.underflow_aus.push(au.access_unit);
        }
        analysis.minimum_fullness_bits = Some(
            analysis
                .minimum_fullness_bits
                .map_or(fullness_before, |value| value.min(fullness_before)),
        );
        analysis.maximum_fullness_bits = Some(
            analysis
                .maximum_fullness_bits
                .map_or(fullness_before, |value| value.max(fullness_before)),
        );
        analysis.simulated_aus += 1;
        if analysis.points.len() < MAX_HRD_POINTS {
            analysis.points.push(H264HrdAuPoint {
                access_unit: au.access_unit,
                sei_nalu: timing.sei_nalu,
                access_unit_bits: au.bits,
                cpb_removal_delay: timing.cpb_removal_delay,
                dpb_output_delay: timing.dpb_output_delay,
                fullness_before_removal_bits: fullness_before,
                fullness_after_removal_bits: fullness_after,
                overflow,
                underflow,
            });
        } else {
            analysis.points_truncated = true;
        }
        analysis.status = "simulated_cbr_single_cpb".into();
        active = Some((epoch, fullness_after, Some(timing.cpb_removal_delay)));
    }
    if analysis.simulated_aus == 0 && analysis.limitations.is_empty() {
        analysis
            .limitations
            .push("未同时取得 buffering_period、pic_timing 和完整访问单元".into());
    } else if analysis.simulated_aus > 0 {
        analysis
            .limitations
            .push("AU 位数按保留的 NALU 字节计算，不包含 RTP、容器和网络传输开销".into());
    }
}

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
    pub fn from_rtp(
        data: Vec<u8>,
        timestamp: u32,
        start_sequence: u16,
        end_sequence: u16,
        complete: bool,
        marker: bool,
    ) -> Self {
        Self {
            data,
            timestamp: Some(timestamp),
            start_sequence: Some(start_sequence),
            end_sequence: Some(end_sequence),
            complete,
            marker,
        }
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
                .map(|(next, _)| *next)
                .unwrap_or(input.len());
            (data_start < data_end).then(|| Nalu {
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

pub fn inspect_annex_b_range(
    input: &[u8],
    first_nalu: u64,
    last_nalu: u64,
) -> Vec<VideoSyntaxNalu> {
    const MAX_HEX_BYTES: usize = 4_096;
    annex_b_ranges(input)
        .into_iter()
        .enumerate()
        .filter_map(|(position, (offset, end))| {
            let index = position as u64 + 1;
            if index < first_nalu || index > last_nalu || offset >= end {
                return None;
            }
            let data = &input[offset..end];
            let header = data[0];
            let kind = header & 0x1f;
            let mut fields = vec![
                syntax_field("forbidden_zero_bit", header >> 7, "NALU header"),
                syntax_field("nal_ref_idc", (header >> 5) & 3, "NALU header"),
                syntax_field("nal_unit_type", kind, "NALU header"),
            ];
            match kind {
                7 => match super::parse_sps(data) {
                    Ok(sps) => {
                        fields.extend([
                            syntax_field("seq_parameter_set_id", sps.id, "SPS RBSP"),
                            syntax_field("profile_idc", sps.profile_idc, "SPS RBSP"),
                            syntax_field("level_idc", sps.level_idc, "SPS RBSP"),
                            syntax_field(
                                "constraint_set3_flag",
                                u8::from(sps.constraint_set3_flag),
                                "SPS RBSP",
                            ),
                            syntax_field("chroma_format_idc", sps.chroma_format_idc, "SPS RBSP"),
                            syntax_field("bit_depth_luma", sps.bit_depth_luma, "SPS RBSP"),
                            syntax_field("bit_depth_chroma", sps.bit_depth_chroma, "SPS RBSP"),
                            syntax_field("width", sps.width, "SPS RBSP"),
                            syntax_field("height", sps.height, "SPS RBSP"),
                            syntax_field("max_num_ref_frames", sps.max_num_ref_frames, "SPS RBSP"),
                        ]);
                        if let Some(hrd) = sps.nal_hrd.as_ref() {
                            fields.extend([
                                syntax_field("nal_hrd_cpb_count", hrd.cpb_count, "VUI HRD"),
                                syntax_field(
                                    "nal_hrd_maximum_bit_rate_bps",
                                    hrd.maximum_bit_rate_bps,
                                    "VUI HRD",
                                ),
                                syntax_field(
                                    "nal_hrd_maximum_cpb_size_bits",
                                    hrd.maximum_cpb_size_bits,
                                    "VUI HRD",
                                ),
                            ]);
                        }
                        if let Some(hrd) = sps.vcl_hrd.as_ref() {
                            fields.extend([
                                syntax_field("vcl_hrd_cpb_count", hrd.cpb_count, "VUI HRD"),
                                syntax_field(
                                    "vcl_hrd_maximum_bit_rate_bps",
                                    hrd.maximum_bit_rate_bps,
                                    "VUI HRD",
                                ),
                                syntax_field(
                                    "vcl_hrd_maximum_cpb_size_bits",
                                    hrd.maximum_cpb_size_bits,
                                    "VUI HRD",
                                ),
                            ]);
                        }
                        if let Some(value) = sps.max_num_reorder_frames {
                            fields.push(syntax_field(
                                "max_num_reorder_frames",
                                value,
                                "VUI bitstream restriction",
                            ));
                        }
                        if let Some(value) = sps.max_dec_frame_buffering {
                            fields.push(syntax_field(
                                "max_dec_frame_buffering",
                                value,
                                "VUI bitstream restriction",
                            ));
                        }
                    }
                    Err(error) => fields.push(VideoSyntaxField {
                        name: "parse_error".into(),
                        value: error.to_string(),
                        source: "SPS parser".into(),
                    }),
                },
                8 => match super::parse_pps(data) {
                    Ok(pps) => fields.extend([
                        syntax_field("pic_parameter_set_id", pps.id, "PPS RBSP"),
                        syntax_field("seq_parameter_set_id", pps.sps_id, "PPS RBSP"),
                        syntax_field(
                            "entropy_coding_mode_flag",
                            u8::from(pps.entropy_coding_mode),
                            "PPS RBSP",
                        ),
                        syntax_field("num_slice_groups", pps.slice_groups, "PPS RBSP"),
                        syntax_field(
                            "weighted_pred_flag",
                            u8::from(pps.weighted_prediction),
                            "PPS RBSP",
                        ),
                        syntax_field("initial_qp", pps.initial_qp, "PPS RBSP"),
                    ]),
                    Err(error) => fields.push(VideoSyntaxField {
                        name: "parse_error".into(),
                        value: error.to_string(),
                        source: "PPS parser".into(),
                    }),
                },
                1 | 5 => match super::parse_slice_header(data) {
                    Ok(slice) => fields.extend([
                        syntax_field("first_mb_in_slice", slice.first_mb_in_slice, "Slice header"),
                        syntax_field("slice_type", slice.slice_type, "Slice header"),
                        syntax_field("pic_parameter_set_id", slice.pps_id, "Slice header"),
                        syntax_field("idr", u8::from(slice.idr), "Slice header"),
                    ]),
                    Err(error) => fields.push(VideoSyntaxField {
                        name: "parse_error".into(),
                        value: error.to_string(),
                        source: "Slice header parser".into(),
                    }),
                },
                _ => {}
            }
            Some(VideoSyntaxNalu {
                index,
                offset: offset as u64,
                size: data.len() as u64,
                nalu_type: kind,
                type_name: super::nalu_type_name(kind).into(),
                fields,
                hex: hex_dump(data, offset, MAX_HEX_BYTES),
                hex_truncated: data.len() > MAX_HEX_BYTES,
                complete: None,
                access_unit_number: None,
                packets: Vec::new(),
            })
        })
        .collect()
}

fn annex_b_ranges(input: &[u8]) -> Vec<(usize, usize)> {
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
                .map(|(next, _)| *next)
                .unwrap_or(input.len());
            (data_start < data_end).then_some((data_start, data_end))
        })
        .collect()
}

fn syntax_field(name: &str, value: impl ToString, source: &str) -> VideoSyntaxField {
    VideoSyntaxField {
        name: name.into(),
        value: value.to_string(),
        source: source.into(),
    }
}

fn hex_dump(data: &[u8], base: usize, maximum: usize) -> String {
    data.iter()
        .take(maximum)
        .collect::<Vec<_>>()
        .chunks(16)
        .enumerate()
        .map(|(line, bytes)| {
            format!(
                "{:08X}  {}",
                base + line * 16,
                bytes
                    .iter()
                    .map(|byte| format!("{byte:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn analyze_annex_b(input: &[u8]) -> H264Analysis {
    analyze_nalus(split_annex_b(input), Vec::new())
}

pub fn analyze_nalus(nalus: Vec<Nalu>, issues: Vec<H264Issue>) -> H264Analysis {
    match analyze_nalu_results(
        nalus.into_iter().map(Ok::<_, std::convert::Infallible>),
        issues,
    ) {
        Ok(analysis) => analysis,
        Err(never) => match never {},
    }
}

pub fn analyze_nalu_results<I, E>(nalus: I, mut issues: Vec<H264Issue>) -> Result<H264Analysis, E>
where
    I: IntoIterator<Item = Result<Nalu, E>>,
{
    let mut analysis = H264Analysis::default();
    let mut sps_ids = BTreeSet::new();
    let mut pps_ids = BTreeSet::new();
    let mut seen_sps = false;
    let mut seen_pps = false;
    let mut frame_timestamps = BTreeSet::new();
    let mut frame_index = 0_u64;
    let mut idr_positions = Vec::new();
    let mut last_vcl_frame: Option<(u32, bool, Option<u16>)> = None;
    let mut active_hrd_sps_id = None;
    let mut pending_hrd_epoch = None;
    let mut pending_pic_timing = None;
    let mut pending_prefix_bits = 0_u64;
    let mut pending_prefix_complete = true;
    let mut current_hrd_au: Option<HrdAuBuilder> = None;
    let mut hrd_access_units = Vec::new();

    for (nalu_index, nalu) in nalus.into_iter().enumerate() {
        let nalu = nalu?;
        analysis.nalu_count += 1;
        if nalu.complete {
            analysis.complete_nalus += 1;
        } else {
            analysis.incomplete_nalus += 1;
        }
        let Some(header) = nalu.data.first().copied() else {
            issues.push(issue("empty_nalu", "NALU 为空", &nalu));
            continue;
        };
        if analysis.nalus.len() < MAX_NALU_EVIDENCE {
            let nalu_type = header & 0x1f;
            analysis.nalus.push(VideoNaluEvidence {
                nalu_number: nalu_index as u64 + 1,
                nalu_type,
                type_name: super::nalu_type_name(nalu_type).into(),
                complete: nalu.complete,
                rtp_timestamp: nalu.timestamp,
                first_sequence: nalu.start_sequence,
                last_sequence: nalu.end_sequence,
                ..VideoNaluEvidence::default()
            });
        } else {
            analysis.nalu_evidence_truncated = true;
        }
        if header & 0x80 != 0 {
            issues.push(issue(
                "forbidden_zero_bit",
                "forbidden_zero_bit 不为 0",
                &nalu,
            ));
        }
        let nalu_type = header & 0x1f;
        let nalu_bits = (nalu.data.len() as u64).saturating_mul(8);
        if !matches!(nalu_type, 1 | 5) {
            pending_prefix_bits = pending_prefix_bits.saturating_add(nalu_bits);
            pending_prefix_complete &= nalu.complete;
        }
        if nalu_type == 6 {
            let (epochs, timings, limitations) = parse_sei_hrd(
                &nalu.data,
                nalu_index as u64 + 1,
                &analysis.sps,
                &mut active_hrd_sps_id,
            );
            analysis.hrd_simulation.buffering_period_count = analysis
                .hrd_simulation
                .buffering_period_count
                .saturating_add(epochs.len() as u64);
            analysis.hrd_simulation.pic_timing_count = analysis
                .hrd_simulation
                .pic_timing_count
                .saturating_add(timings.len() as u64);
            if let Some(epoch) = epochs.into_iter().last() {
                pending_hrd_epoch = Some(epoch);
            }
            if let Some(timing) = timings.into_iter().last() {
                pending_pic_timing = Some(timing);
            }
            analysis.hrd_simulation.limitations.extend(limitations);
        }
        *analysis
            .nalu_types
            .entry(nalu_type_name(nalu_type).into())
            .or_insert(0) += 1;
        match nalu_type {
            7 => match parse_sps(&nalu.data) {
                Ok(sps) => {
                    seen_sps = true;
                    sps_ids.insert(sps.id);
                    if let Some(existing) = analysis.sps.iter_mut().find(|value| value.id == sps.id)
                    {
                        let changed_fields = h264_sps_changes(existing, &sps);
                        if existing.width != sps.width || existing.height != sps.height {
                            issues.push(issue(
                                "resolution_changed",
                                &format!(
                                    "SPS {} 分辨率从 {}x{} 变为 {}x{}",
                                    sps.id, existing.width, existing.height, sps.width, sps.height
                                ),
                                &nalu,
                            ));
                        }
                        let parameter_id = sps.id;
                        *existing = sps;
                        if !changed_fields.is_empty() {
                            analysis.parameter_changes.push(VideoParameterChange {
                                nalu_number: nalu_index as u64 + 1,
                                effective_access_unit: Some(frame_index + 1),
                                parameter_kind: "SPS".into(),
                                parameter_id,
                                changed_fields,
                            });
                        }
                    } else {
                        analysis.sps.push(sps);
                    }
                }
                Err(error) => issues.push(issue("invalid_sps", &error.to_string(), &nalu)),
            },
            8 => match parse_pps(&nalu.data) {
                Ok(pps) => {
                    seen_pps = true;
                    pps_ids.insert(pps.id);
                    if !sps_ids.contains(&pps.sps_id) {
                        issues.push(issue("pps_missing_sps", "PPS 引用了尚未出现的 SPS", &nalu));
                    }
                    if let Some(existing) = analysis.pps.iter_mut().find(|value| value.id == pps.id)
                    {
                        let changed_fields = h264_pps_changes(existing, &pps);
                        let parameter_id = pps.id;
                        *existing = pps;
                        if !changed_fields.is_empty() {
                            analysis.parameter_changes.push(VideoParameterChange {
                                nalu_number: nalu_index as u64 + 1,
                                effective_access_unit: Some(frame_index + 1),
                                parameter_kind: "PPS".into(),
                                parameter_id,
                                changed_fields,
                            });
                        }
                    } else {
                        analysis.pps.push(pps);
                    }
                }
                Err(error) => issues.push(issue("invalid_pps", &error.to_string(), &nalu)),
            },
            1 | 5 => {
                if let Some(timestamp) = nalu.timestamp {
                    match last_vcl_frame {
                        Some((previous, marker, sequence)) if previous != timestamp => {
                            if !marker {
                                issues.push(H264Issue {
                                    kind: "missing_marker".into(),
                                    detail: format!(
                                        "时间戳 {previous} 的访问单元未观察到 Marker 位"
                                    ),
                                    sequence,
                                    timestamp: Some(previous),
                                });
                            }
                            last_vcl_frame = Some((timestamp, nalu.marker, nalu.end_sequence));
                        }
                        Some((_, marker, _)) => {
                            last_vcl_frame =
                                Some((timestamp, marker || nalu.marker, nalu.end_sequence));
                        }
                        None => {
                            last_vcl_frame = Some((timestamp, nalu.marker, nalu.end_sequence));
                        }
                    }
                }
                let slice = parse_slice_header(&nalu.data).ok();
                let starts_frame = slice
                    .as_ref()
                    .map(|slice| slice.first_mb_in_slice == 0)
                    .unwrap_or_else(|| {
                        nalu.timestamp
                            .map(|timestamp| frame_timestamps.insert(timestamp))
                            .unwrap_or(true)
                    });
                if starts_frame {
                    if let Some(previous) = current_hrd_au.take() {
                        hrd_access_units.push(previous.into());
                    }
                    frame_index += 1;
                    analysis.frame_count += 1;
                    current_hrd_au = Some(HrdAuBuilder {
                        access_unit: frame_index,
                        bits: pending_prefix_bits.saturating_add(nalu_bits),
                        complete: pending_prefix_complete && nalu.complete,
                        epoch: pending_hrd_epoch.take(),
                        timing: pending_pic_timing.take(),
                    });
                    pending_prefix_bits = 0;
                    pending_prefix_complete = true;
                    analysis.first_frame_is_idr.get_or_insert(nalu_type == 5);
                    if nalu_type == 5 {
                        analysis.idr_frames += 1;
                        idr_positions.push(frame_index);
                        if analysis.idr_frames == 1 {
                            analysis.first_idr_frame = Some(frame_index);
                            analysis.sps_before_first_idr = seen_sps;
                            analysis.pps_before_first_idr = seen_pps;
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
                            idr: nalu_type == 5,
                            complete: nalu.complete,
                            boundary_confidence: if slice.is_some() {
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
                } else {
                    if let Some(frame) = analysis.frames.last_mut()
                        && frame.frame_number == frame_index
                    {
                        frame.last_nalu = nalu_index as u64 + 1;
                        frame.last_sequence = nalu.end_sequence.or(frame.last_sequence);
                        frame.idr |= nalu_type == 5;
                        frame.complete &= nalu.complete;
                    }
                    if let Some(access_unit) = current_hrd_au.as_mut() {
                        access_unit.bits = access_unit.bits.saturating_add(nalu_bits);
                        access_unit.complete &= nalu.complete;
                    }
                }
                if let Some(slice) = slice
                    && !pps_ids.contains(&slice.pps_id)
                {
                    issues.push(issue(
                        "slice_missing_pps",
                        "Slice 引用了尚未出现的 PPS",
                        &nalu,
                    ));
                }
            }
            0 | 30 | 31 => issues.push(issue("invalid_nalu_type", "NALU 类型非法或保留", &nalu)),
            _ => {}
        }
    }
    let intervals: Vec<_> = idr_positions
        .windows(2)
        .map(|window| window[1] - window[0])
        .collect();
    if !intervals.is_empty() {
        analysis.average_gop_frames = Some(intervals.iter().sum::<u64>() / intervals.len() as u64);
        analysis.maximum_gop_frames = intervals.into_iter().max();
    }
    if !seen_sps {
        issues.push(H264Issue {
            kind: "missing_sps".into(),
            detail: "码流中没有发现 SPS".into(),
            sequence: None,
            timestamp: None,
        });
    }
    if !seen_pps {
        issues.push(H264Issue {
            kind: "missing_pps".into(),
            detail: "码流中没有发现 PPS".into(),
            sequence: None,
            timestamp: None,
        });
    }
    if let Some(access_unit) = current_hrd_au.take() {
        hrd_access_units.push(access_unit.into());
    }
    let hrd_declared = analysis
        .sps
        .iter()
        .any(|sps| sps.nal_hrd.is_some() || sps.vcl_hrd.is_some());
    simulate_hrd(&mut analysis.hrd_simulation, hrd_access_units, hrd_declared);
    let mut frame_cursor = 0;
    for nalu in &mut analysis.nalus {
        let nalu_number = nalu.nalu_number;
        while analysis
            .frames
            .get(frame_cursor)
            .is_some_and(|frame| frame.last_nalu < nalu_number)
        {
            frame_cursor += 1;
        }
        nalu.access_unit_number = analysis.frames.get(frame_cursor).and_then(|frame| {
            (frame.first_nalu <= nalu_number && nalu_number <= frame.last_nalu)
                .then_some(frame.frame_number)
        });
    }
    analysis.issues = issues;
    Ok(analysis)
}

fn issue(kind: &str, detail: &str, nalu: &Nalu) -> H264Issue {
    H264Issue {
        kind: kind.into(),
        detail: detail.into(),
        sequence: nalu.start_sequence,
        timestamp: nalu.timestamp,
    }
}

fn h264_sps_changes(
    previous: &streamscope_core::H264SpsInfo,
    current: &streamscope_core::H264SpsInfo,
) -> Vec<String> {
    let mut fields = Vec::new();
    if (previous.width, previous.height) != (current.width, current.height) {
        fields.push("resolution".into());
    }
    if previous.profile_idc != current.profile_idc {
        fields.push("profile_idc".into());
    }
    if previous.level_idc != current.level_idc {
        fields.push("level_idc".into());
    }
    if previous.constraint_set3_flag != current.constraint_set3_flag {
        fields.push("constraint_set3_flag".into());
    }
    if previous.chroma_format_idc != current.chroma_format_idc {
        fields.push("chroma_format_idc".into());
    }
    if (previous.bit_depth_luma, previous.bit_depth_chroma)
        != (current.bit_depth_luma, current.bit_depth_chroma)
    {
        fields.push("bit_depth".into());
    }
    if previous.max_num_ref_frames != current.max_num_ref_frames {
        fields.push("max_num_ref_frames".into());
    }
    if previous.progressive != current.progressive {
        fields.push("scan_mode".into());
    }
    if previous.fps_milli != current.fps_milli {
        fields.push("frame_rate".into());
    }
    if previous.nal_hrd != current.nal_hrd {
        fields.push("nal_hrd".into());
    }
    if previous.vcl_hrd != current.vcl_hrd {
        fields.push("vcl_hrd".into());
    }
    if previous.max_num_reorder_frames != current.max_num_reorder_frames {
        fields.push("max_num_reorder_frames".into());
    }
    if previous.max_dec_frame_buffering != current.max_dec_frame_buffering {
        fields.push("max_dec_frame_buffering".into());
    }
    fields
}

fn h264_pps_changes(
    previous: &streamscope_core::H264PpsInfo,
    current: &streamscope_core::H264PpsInfo,
) -> Vec<String> {
    let mut fields = Vec::new();
    if previous.sps_id != current.sps_id {
        fields.push("seq_parameter_set_id".into());
    }
    if previous.entropy_coding_mode != current.entropy_coding_mode {
        fields.push("entropy_coding_mode".into());
    }
    if previous.slice_groups != current.slice_groups {
        fields.push("slice_groups".into());
    }
    if previous.weighted_prediction != current.weighted_prediction {
        fields.push("weighted_prediction".into());
    }
    if previous.initial_qp != current.initial_qp {
        fields.push("initial_qp".into());
    }
    if previous.deblocking_filter_control != current.deblocking_filter_control {
        fields.push("deblocking_filter_control".into());
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_three_and_four_byte_annex_b_start_codes() {
        let nalus = split_annex_b(&[0, 0, 0, 1, 0x67, 1, 0, 0, 1, 0x68, 2]);
        assert_eq!(nalus.len(), 2);
        assert_eq!(nalus[0].data, [0x67, 1]);
        assert_eq!(nalus[1].data, [0x68, 2]);
    }

    #[test]
    fn inspects_selected_nalu_with_absolute_hex_offsets() {
        let input = [0, 0, 0, 1, 0x67, 0x42, 0, 0, 1, 0x68, 0xce];
        let syntax = inspect_annex_b_range(&input, 2, 2);
        assert_eq!(syntax.len(), 1);
        assert_eq!(syntax[0].index, 2);
        assert_eq!(syntax[0].offset, 9);
        assert_eq!(syntax[0].nalu_type, 8);
        assert!(syntax[0].hex.starts_with("00000009  68 CE"));
    }

    #[test]
    fn reports_only_actual_h264_parameter_changes() {
        let previous = streamscope_core::H264SpsInfo {
            id: 0,
            width: 1280,
            height: 720,
            profile_idc: 100,
            level_idc: 40,
            constraint_set3_flag: false,
            chroma_format_idc: 1,
            bit_depth_luma: 8,
            bit_depth_chroma: 8,
            max_frame_num: 16,
            pic_order_cnt_type: 0,
            max_num_ref_frames: 4,
            progressive: true,
            fps_milli: Some(25_000),
            num_units_in_tick: Some(1),
            time_scale: Some(50),
            nal_hrd: None,
            vcl_hrd: None,
            max_num_reorder_frames: None,
            max_dec_frame_buffering: None,
        };
        let mut current = previous.clone();
        assert!(h264_sps_changes(&previous, &current).is_empty());
        current.width = 1920;
        current.height = 1080;
        current.bit_depth_luma = 10;
        assert_eq!(
            h264_sps_changes(&previous, &current),
            ["resolution", "bit_depth"]
        );
    }

    #[test]
    fn reports_missing_parameter_sets_for_slice_only_stream() {
        let analysis = analyze_annex_b(&[0, 0, 1, 0x65, 0b1011_0000]);
        assert!(analysis.first_frame_is_idr.unwrap());
        assert_eq!(analysis.first_idr_frame, Some(1));
        assert!(
            analysis
                .issues
                .iter()
                .any(|issue| issue.kind == "missing_sps")
        );
        assert!(
            analysis
                .issues
                .iter()
                .any(|issue| issue.kind == "missing_pps")
        );
    }

    #[test]
    fn reports_missing_marker_when_next_timestamp_starts() {
        let nalus = vec![
            Nalu::from_rtp(vec![0x41, 0b1011_0000], 90_000, 1, 1, true, false),
            Nalu::from_rtp(vec![0x41, 0b1011_0000], 93_600, 2, 2, true, true),
        ];
        let analysis = analyze_nalus(nalus, Vec::new());
        assert!(
            analysis
                .issues
                .iter()
                .any(|issue| issue.kind == "missing_marker")
        );
    }

    #[test]
    fn slice_boundaries_take_priority_when_rtp_timestamps_are_reused() {
        let nalus = vec![
            Nalu::from_rtp(vec![0x41, 0xbc], 90_000, 1, 1, true, false),
            Nalu::from_rtp(vec![0x41, 0x4f], 90_000, 2, 2, true, true),
            Nalu::from_rtp(vec![0x41, 0xbc], 90_000, 3, 3, true, true),
        ];
        let analysis = analyze_nalus(nalus, Vec::new());
        assert_eq!(analysis.frame_count, 2);
        assert_eq!(analysis.frames.len(), 2);
        assert_eq!(analysis.frames[0].first_nalu, 1);
        assert_eq!(analysis.frames[0].last_nalu, 2);
        assert_eq!(analysis.frames[0].first_sequence, Some(1));
        assert_eq!(analysis.frames[0].last_sequence, Some(2));
        assert_eq!(analysis.frames[1].first_nalu, 3);
        assert_eq!(analysis.frames[0].boundary_confidence, "slice_header");
    }

    #[test]
    fn simulates_single_cbr_cpb_and_reports_underflow() {
        let epoch = HrdEpoch {
            schedule: "nal",
            sps_id: 0,
            hrd: H264HrdInfo {
                cpb_count: 1,
                maximum_bit_rate_bps: 90_000,
                maximum_cpb_size_bits: 180_000,
                all_cbr: true,
                entries: vec![streamscope_core::H264CpbEntry {
                    bit_rate_bps: 90_000,
                    cpb_size_bits: 180_000,
                    cbr: true,
                }],
                initial_cpb_removal_delay_length: 16,
                cpb_removal_delay_length: 8,
                dpb_output_delay_length: 8,
                time_offset_length: 0,
            },
            num_units_in_tick: 1,
            time_scale: 1,
            initial_cpb_removal_delay: 90_000,
        };
        let access_units = vec![
            HrdAuInput {
                access_unit: 1,
                bits: 80_000,
                complete: true,
                epoch: Some(epoch),
                timing: Some(HrdPicTiming {
                    sei_nalu: 2,
                    cpb_removal_delay: 0,
                    dpb_output_delay: 0,
                }),
            },
            HrdAuInput {
                access_unit: 2,
                bits: 120_000,
                complete: true,
                epoch: None,
                timing: Some(HrdPicTiming {
                    sei_nalu: 4,
                    cpb_removal_delay: 1,
                    dpb_output_delay: 0,
                }),
            },
        ];
        let mut result = H264HrdSimulation::default();
        simulate_hrd(&mut result, access_units, true);
        assert_eq!(result.status, "simulated_cbr_single_cpb");
        assert_eq!(result.simulated_aus, 2);
        assert_eq!(result.points[0].fullness_before_removal_bits, 90_000);
        assert_eq!(result.points[0].fullness_after_removal_bits, 10_000);
        assert_eq!(result.points[1].fullness_before_removal_bits, 100_000);
        assert_eq!(result.underflow_aus, [2]);
    }

    #[test]
    fn parses_buffering_period_and_pic_timing_sei() {
        let sps = H264SpsInfo {
            id: 0,
            profile_idc: 66,
            level_idc: 30,
            constraint_set3_flag: false,
            chroma_format_idc: 1,
            bit_depth_luma: 8,
            bit_depth_chroma: 8,
            max_frame_num: 16,
            pic_order_cnt_type: 0,
            max_num_ref_frames: 1,
            width: 320,
            height: 240,
            progressive: true,
            fps_milli: Some(25_000),
            num_units_in_tick: Some(1),
            time_scale: Some(50),
            nal_hrd: Some(H264HrdInfo {
                cpb_count: 1,
                maximum_bit_rate_bps: 64_000,
                maximum_cpb_size_bits: 32_000,
                all_cbr: true,
                entries: vec![streamscope_core::H264CpbEntry {
                    bit_rate_bps: 64_000,
                    cpb_size_bits: 32_000,
                    cbr: true,
                }],
                initial_cpb_removal_delay_length: 8,
                cpb_removal_delay_length: 8,
                dpb_output_delay_length: 8,
                time_offset_length: 0,
            }),
            vcl_hrd: None,
            max_num_reorder_frames: Some(0),
            max_dec_frame_buffering: Some(1),
        };
        let buffering = [0xad, 0x05, 0x00];
        let mut nalu = vec![0x06, 0, buffering.len() as u8];
        nalu.extend(buffering);
        nalu.extend([1, 2, 5, 2, 0x80]);

        let mut active = None;
        let (epochs, timings, limitations) = parse_sei_hrd(&nalu, 7, &[sps], &mut active);
        assert!(limitations.is_empty(), "{limitations:?}");
        assert_eq!(active, Some(0));
        assert_eq!(epochs.len(), 1);
        assert_eq!(epochs[0].initial_cpb_removal_delay, 90);
        assert_eq!(timings.len(), 1);
        assert_eq!(timings[0].cpb_removal_delay, 5);
        assert_eq!(timings[0].dpb_output_delay, 2);
    }
}
