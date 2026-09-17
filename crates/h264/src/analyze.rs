use crate::{nalu_type_name, parse_pps, parse_slice_header, parse_sps};
use std::collections::BTreeSet;
use streamscope_core::{H264Analysis, H264FrameEvidence, H264Issue};

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

pub fn analyze_annex_b(input: &[u8]) -> H264Analysis {
    analyze_nalus(split_annex_b(input), Vec::new())
}

pub fn analyze_nalus(nalus: Vec<Nalu>, mut issues: Vec<H264Issue>) -> H264Analysis {
    let mut analysis = H264Analysis::default();
    let mut sps_ids = BTreeSet::new();
    let mut pps_ids = BTreeSet::new();
    let mut seen_sps = false;
    let mut seen_pps = false;
    let mut frame_timestamps = BTreeSet::new();
    let mut frame_index = 0_u64;
    let mut idr_positions = Vec::new();
    let mut last_vcl_frame: Option<(u32, bool, Option<u16>)> = None;

    for (nalu_index, nalu) in nalus.iter().enumerate() {
        analysis.nalu_count += 1;
        if nalu.complete {
            analysis.complete_nalus += 1;
        } else {
            analysis.incomplete_nalus += 1;
        }
        let Some(header) = nalu.data.first().copied() else {
            issues.push(issue("empty_nalu", "NALU 为空", nalu));
            continue;
        };
        if header & 0x80 != 0 {
            issues.push(issue(
                "forbidden_zero_bit",
                "forbidden_zero_bit 不为 0",
                nalu,
            ));
        }
        let nalu_type = header & 0x1f;
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
                        if existing.width != sps.width || existing.height != sps.height {
                            issues.push(issue(
                                "resolution_changed",
                                &format!(
                                    "SPS {} 分辨率从 {}x{} 变为 {}x{}",
                                    sps.id, existing.width, existing.height, sps.width, sps.height
                                ),
                                nalu,
                            ));
                        }
                        *existing = sps;
                    } else {
                        analysis.sps.push(sps);
                    }
                }
                Err(error) => issues.push(issue("invalid_sps", &error.to_string(), nalu)),
            },
            8 => match parse_pps(&nalu.data) {
                Ok(pps) => {
                    seen_pps = true;
                    pps_ids.insert(pps.id);
                    if !sps_ids.contains(&pps.sps_id) {
                        issues.push(issue("pps_missing_sps", "PPS 引用了尚未出现的 SPS", nalu));
                    }
                    if let Some(existing) = analysis.pps.iter_mut().find(|value| value.id == pps.id)
                    {
                        *existing = pps;
                    } else {
                        analysis.pps.push(pps);
                    }
                }
                Err(error) => issues.push(issue("invalid_pps", &error.to_string(), nalu)),
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
                    frame_index += 1;
                    analysis.frame_count += 1;
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
                } else if let Some(frame) = analysis.frames.last_mut()
                    && frame.frame_number == frame_index
                {
                    frame.last_nalu = nalu_index as u64 + 1;
                    frame.last_sequence = nalu.end_sequence.or(frame.last_sequence);
                    frame.idr |= nalu_type == 5;
                    frame.complete &= nalu.complete;
                }
                if let Some(slice) = slice
                    && !pps_ids.contains(&slice.pps_id)
                {
                    issues.push(issue(
                        "slice_missing_pps",
                        "Slice 引用了尚未出现的 PPS",
                        nalu,
                    ));
                }
            }
            0 | 30 | 31 => issues.push(issue("invalid_nalu_type", "NALU 类型非法或保留", nalu)),
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
}
