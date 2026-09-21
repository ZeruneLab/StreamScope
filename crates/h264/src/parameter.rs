use crate::bit::{BitError, BitReader, ebsp_to_rbsp};
use streamscope_core::{H264CpbEntry, H264HrdInfo, H264PpsInfo, H264SpsInfo};

#[derive(Debug, thiserror::Error)]
pub enum ParameterError {
    #[error("NALU 类型不符合参数集类型")]
    WrongNaluType,
    #[error(transparent)]
    Bits(#[from] BitError),
    #[error("SPS 图像尺寸溢出")]
    DimensionOverflow,
    #[error("PPS slice group map 不受支持")]
    UnsupportedSliceGroups,
    #[error("H.264 HRD cpb_cnt_minus1 超过标准上限 31")]
    InvalidHrdCpbCount,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceHeader {
    pub first_mb_in_slice: u32,
    pub slice_type: u32,
    pub pps_id: u32,
    pub idr: bool,
    pub nal_ref_idc: u8,
}

pub fn parse_sps(nalu: &[u8]) -> Result<H264SpsInfo, ParameterError> {
    if nalu.first().map(|value| value & 0x1f) != Some(7) {
        return Err(ParameterError::WrongNaluType);
    }
    let rbsp = ebsp_to_rbsp(&nalu[1..]);
    let mut bits = BitReader::new(&rbsp);
    let profile_idc = bits.read_bits(8)? as u8;
    let constraint_flags = bits.read_bits(8)? as u8;
    let level_idc = bits.read_bits(8)? as u8;
    let id = bits.read_ue()?;
    let mut chroma_format_idc = 1;
    let mut separate_colour_plane = false;
    let mut bit_depth_luma = 8;
    let mut bit_depth_chroma = 8;
    if matches!(
        profile_idc,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
    ) {
        chroma_format_idc = bits.read_ue()?;
        if chroma_format_idc == 3 {
            separate_colour_plane = bits.read_bit()?;
        }
        bit_depth_luma = (bits.read_ue()? + 8) as u8;
        bit_depth_chroma = (bits.read_ue()? + 8) as u8;
        let _qpprime_bypass = bits.read_bit()?;
        if bits.read_bit()? {
            let count = if chroma_format_idc == 3 { 12 } else { 8 };
            for index in 0..count {
                if bits.read_bit()? {
                    skip_scaling_list(&mut bits, if index < 6 { 16 } else { 64 })?;
                }
            }
        }
    }
    let log2_max_frame_num_minus4 = bits.read_ue()?;
    let max_frame_num = 1_u32
        .checked_shl(log2_max_frame_num_minus4 + 4)
        .ok_or(ParameterError::DimensionOverflow)?;
    let pic_order_cnt_type = bits.read_ue()?;
    if pic_order_cnt_type == 0 {
        let _log2_max_pic_order_cnt_lsb_minus4 = bits.read_ue()?;
    } else if pic_order_cnt_type == 1 {
        let _delta_pic_order_always_zero = bits.read_bit()?;
        let _offset_non_ref = bits.read_se()?;
        let _offset_top_bottom = bits.read_se()?;
        for _ in 0..bits.read_ue()? {
            let _offset = bits.read_se()?;
        }
    }
    let max_num_ref_frames = bits.read_ue()?;
    let _gaps_allowed = bits.read_bit()?;
    let width_in_mbs = bits.read_ue()? + 1;
    let height_in_map_units = bits.read_ue()? + 1;
    let frame_mbs_only = bits.read_bit()?;
    if !frame_mbs_only {
        let _mb_adaptive_frame_field = bits.read_bit()?;
    }
    let _direct_8x8_inference = bits.read_bit()?;
    let cropping = if bits.read_bit()? {
        Some((
            bits.read_ue()?,
            bits.read_ue()?,
            bits.read_ue()?,
            bits.read_ue()?,
        ))
    } else {
        None
    };
    let vui = if bits.read_bit()? {
        Some(parse_vui(&mut bits)?)
    } else {
        None
    };
    let frame_factor = if frame_mbs_only { 1 } else { 2 };
    let mut width = width_in_mbs
        .checked_mul(16)
        .ok_or(ParameterError::DimensionOverflow)?;
    let mut height = height_in_map_units
        .checked_mul(16 * frame_factor)
        .ok_or(ParameterError::DimensionOverflow)?;
    if let Some((left, right, top, bottom)) = cropping {
        let chroma_array_type = if separate_colour_plane {
            0
        } else {
            chroma_format_idc
        };
        let sub_width_c = if matches!(chroma_array_type, 1 | 2) {
            2
        } else {
            1
        };
        let sub_height_c = if chroma_array_type == 1 { 2 } else { 1 };
        let crop_unit_x = if chroma_array_type == 0 {
            1
        } else {
            sub_width_c
        };
        let crop_unit_y = if chroma_array_type == 0 {
            frame_factor
        } else {
            sub_height_c * frame_factor
        };
        width = width.saturating_sub((left + right) * crop_unit_x);
        height = height.saturating_sub((top + bottom) * crop_unit_y);
    }
    Ok(H264SpsInfo {
        id,
        profile_idc,
        level_idc,
        constraint_set3_flag: constraint_flags & 0x10 != 0,
        chroma_format_idc,
        bit_depth_luma,
        bit_depth_chroma,
        max_frame_num,
        pic_order_cnt_type,
        max_num_ref_frames,
        width,
        height,
        progressive: frame_mbs_only,
        fps_milli: vui.as_ref().and_then(|value| value.fps_milli),
        num_units_in_tick: vui.as_ref().and_then(|value| value.num_units_in_tick),
        time_scale: vui.as_ref().and_then(|value| value.time_scale),
        nal_hrd: vui.as_ref().and_then(|value| value.nal_hrd.clone()),
        vcl_hrd: vui.as_ref().and_then(|value| value.vcl_hrd.clone()),
        max_num_reorder_frames: vui.as_ref().and_then(|value| value.max_num_reorder_frames),
        max_dec_frame_buffering: vui.as_ref().and_then(|value| value.max_dec_frame_buffering),
    })
}

pub fn parse_pps(nalu: &[u8]) -> Result<H264PpsInfo, ParameterError> {
    if nalu.first().map(|value| value & 0x1f) != Some(8) {
        return Err(ParameterError::WrongNaluType);
    }
    let rbsp = ebsp_to_rbsp(&nalu[1..]);
    let mut bits = BitReader::new(&rbsp);
    let id = bits.read_ue()?;
    let sps_id = bits.read_ue()?;
    let entropy_coding_mode = bits.read_bit()?;
    let _bottom_field_poc_present = bits.read_bit()?;
    let slice_groups = bits.read_ue()? + 1;
    if slice_groups > 1 {
        skip_slice_groups(&mut bits, slice_groups)?;
    }
    let _num_ref_idx_l0 = bits.read_ue()?;
    let _num_ref_idx_l1 = bits.read_ue()?;
    let weighted_prediction = bits.read_bit()?;
    let _weighted_bipred_idc = bits.read_bits(2)?;
    let initial_qp = 26 + bits.read_se()?;
    let _initial_qs = 26 + bits.read_se()?;
    let _chroma_qp_offset = bits.read_se()?;
    let deblocking_filter_control = bits.read_bit()?;
    let _constrained_intra_pred = bits.read_bit()?;
    let _redundant_pic_count = bits.read_bit()?;
    Ok(H264PpsInfo {
        id,
        sps_id,
        entropy_coding_mode,
        slice_groups,
        weighted_prediction,
        initial_qp,
        deblocking_filter_control,
    })
}

pub fn parse_slice_header(nalu: &[u8]) -> Result<SliceHeader, ParameterError> {
    let header = *nalu.first().ok_or(BitError::EndOfData)?;
    let nalu_type = header & 0x1f;
    if !matches!(nalu_type, 1 | 5) {
        return Err(ParameterError::WrongNaluType);
    }
    let rbsp = ebsp_to_rbsp(&nalu[1..]);
    let mut bits = BitReader::new(&rbsp);
    Ok(SliceHeader {
        first_mb_in_slice: bits.read_ue()?,
        slice_type: bits.read_ue()? % 5,
        pps_id: bits.read_ue()?,
        idr: nalu_type == 5,
        nal_ref_idc: (header >> 5) & 0x03,
    })
}

fn skip_scaling_list(bits: &mut BitReader<'_>, size: usize) -> Result<(), BitError> {
    let mut last_scale = 8_i32;
    let mut next_scale = 8_i32;
    for _ in 0..size {
        if next_scale != 0 {
            next_scale = (last_scale + bits.read_se()? + 256) % 256;
        }
        last_scale = if next_scale == 0 {
            last_scale
        } else {
            next_scale
        };
    }
    Ok(())
}

fn skip_slice_groups(bits: &mut BitReader<'_>, groups: u32) -> Result<(), ParameterError> {
    match bits.read_ue()? {
        0 => {
            for _ in 0..groups {
                let _run_length = bits.read_ue()?;
            }
        }
        2 => {
            for _ in 0..groups - 1 {
                let _top_left = bits.read_ue()?;
                let _bottom_right = bits.read_ue()?;
            }
        }
        3..=5 => {
            let _direction = bits.read_bit()?;
            let _change_rate = bits.read_ue()?;
        }
        6 => {
            let map_units = bits.read_ue()? + 1;
            let width = u32::BITS - (groups - 1).leading_zeros();
            for _ in 0..map_units {
                let _group_id = bits.read_bits(width as u8)?;
            }
        }
        _ => return Err(ParameterError::UnsupportedSliceGroups),
    }
    Ok(())
}

#[derive(Default)]
struct ParsedVui {
    fps_milli: Option<u32>,
    num_units_in_tick: Option<u32>,
    time_scale: Option<u32>,
    nal_hrd: Option<H264HrdInfo>,
    vcl_hrd: Option<H264HrdInfo>,
    max_num_reorder_frames: Option<u32>,
    max_dec_frame_buffering: Option<u32>,
}

fn parse_vui(bits: &mut BitReader<'_>) -> Result<ParsedVui, ParameterError> {
    if bits.read_bit()? {
        let aspect_ratio_idc = bits.read_bits(8)?;
        if aspect_ratio_idc == 255 {
            let _sar_width = bits.read_bits(16)?;
            let _sar_height = bits.read_bits(16)?;
        }
    }
    if bits.read_bit()? {
        let _overscan_appropriate = bits.read_bit()?;
    }
    if bits.read_bit()? {
        let _video_format = bits.read_bits(3)?;
        let _full_range = bits.read_bit()?;
        if bits.read_bit()? {
            let _colour_primaries = bits.read_bits(8)?;
            let _transfer_characteristics = bits.read_bits(8)?;
            let _matrix_coefficients = bits.read_bits(8)?;
        }
    }
    if bits.read_bit()? {
        let _chroma_sample_loc_top = bits.read_ue()?;
        let _chroma_sample_loc_bottom = bits.read_ue()?;
    }
    let (fps_milli, num_units_in_tick, time_scale) = if bits.read_bit()? {
        let num_units_in_tick = bits.read_bits(32)?;
        let time_scale = bits.read_bits(32)?;
        let _fixed_frame_rate = bits.read_bit()?;
        (
            (num_units_in_tick != 0).then(|| {
                (u64::from(time_scale) * 1000 / (2 * u64::from(num_units_in_tick))) as u32
            }),
            Some(num_units_in_tick),
            Some(time_scale),
        )
    } else {
        (None, None, None)
    };
    let nal_hrd = bits.read_bit()?.then(|| parse_hrd(bits)).transpose()?;
    let vcl_hrd = bits.read_bit()?.then(|| parse_hrd(bits)).transpose()?;
    if nal_hrd.is_some() || vcl_hrd.is_some() {
        let _low_delay_hrd = bits.read_bit()?;
    }
    let _pic_struct_present = bits.read_bit()?;
    let (max_num_reorder_frames, max_dec_frame_buffering) = if bits.read_bit()? {
        let _motion_vectors_over_pic_boundaries = bits.read_bit()?;
        let _max_bytes_per_pic_denom = bits.read_ue()?;
        let _max_bits_per_mb_denom = bits.read_ue()?;
        let _log2_max_mv_length_horizontal = bits.read_ue()?;
        let _log2_max_mv_length_vertical = bits.read_ue()?;
        (Some(bits.read_ue()?), Some(bits.read_ue()?))
    } else {
        (None, None)
    };
    Ok(ParsedVui {
        fps_milli,
        num_units_in_tick,
        time_scale,
        nal_hrd,
        vcl_hrd,
        max_num_reorder_frames,
        max_dec_frame_buffering,
    })
}

fn parse_hrd(bits: &mut BitReader<'_>) -> Result<H264HrdInfo, ParameterError> {
    let cpb_count = bits.read_ue()?.saturating_add(1);
    if cpb_count > 32 {
        return Err(ParameterError::InvalidHrdCpbCount);
    }
    let bit_rate_scale = bits.read_bits(4)?;
    let cpb_size_scale = bits.read_bits(4)?;
    let mut maximum_bit_rate_bps = 0_u64;
    let mut maximum_cpb_size_bits = 0_u64;
    let mut all_cbr = true;
    let mut entries = Vec::with_capacity(cpb_count as usize);
    for _ in 0..cpb_count {
        let bit_rate_value = u64::from(bits.read_ue()?) + 1;
        let cpb_size_value = u64::from(bits.read_ue()?) + 1;
        let bit_rate_bps = bit_rate_value << (6 + bit_rate_scale);
        let cpb_size_bits = cpb_size_value << (4 + cpb_size_scale);
        let cbr = bits.read_bit()?;
        maximum_bit_rate_bps = maximum_bit_rate_bps.max(bit_rate_bps);
        maximum_cpb_size_bits = maximum_cpb_size_bits.max(cpb_size_bits);
        all_cbr &= cbr;
        entries.push(H264CpbEntry {
            bit_rate_bps,
            cpb_size_bits,
            cbr,
        });
    }
    Ok(H264HrdInfo {
        cpb_count,
        maximum_bit_rate_bps,
        maximum_cpb_size_bits,
        all_cbr,
        entries,
        initial_cpb_removal_delay_length: bits.read_bits(5)? as u8 + 1,
        cpb_removal_delay_length: bits.read_bits(5)? as u8 + 1,
        dpb_output_delay_length: bits.read_bits(5)? as u8 + 1,
        time_offset_length: bits.read_bits(5)? as u8,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_constructed_baseline_sps_dimensions() {
        let mut writer = BitWriter::default();
        writer.bits(66, 8);
        writer.bits(0, 8);
        writer.bits(30, 8);
        writer.ue(0);
        writer.ue(0);
        writer.ue(0);
        writer.ue(0);
        writer.ue(1);
        writer.bit(false);
        writer.ue(19);
        writer.ue(14);
        writer.bit(true);
        writer.bit(true);
        writer.bit(false);
        writer.bit(false);
        let mut nalu = vec![0x67];
        nalu.extend(writer.finish());
        let sps = parse_sps(&nalu).unwrap();
        assert_eq!((sps.width, sps.height), (320, 240));
        assert_eq!(sps.max_frame_num, 16);
        assert!(sps.progressive);
        assert!(!sps.constraint_set3_flag);
    }

    #[test]
    fn preserves_constraint_set3_for_level_1b() {
        let mut writer = BitWriter::default();
        writer.bits(66, 8);
        writer.bits(0x10, 8);
        writer.bits(11, 8);
        writer.ue(0);
        writer.ue(0);
        writer.ue(0);
        writer.ue(0);
        writer.ue(1);
        writer.bit(false);
        writer.ue(19);
        writer.ue(14);
        writer.bit(true);
        writer.bit(true);
        writer.bit(false);
        writer.bit(false);
        let mut nalu = vec![0x67];
        nalu.extend(writer.finish());

        let sps = parse_sps(&nalu).unwrap();
        assert_eq!(sps.level_idc, 11);
        assert!(sps.constraint_set3_flag);
    }

    #[test]
    fn parses_vui_hrd_and_bitstream_restrictions() {
        let mut writer = BitWriter::default();
        writer.bits(66, 8);
        writer.bits(0, 8);
        writer.bits(30, 8);
        writer.ue(0);
        writer.ue(0);
        writer.ue(0);
        writer.ue(0);
        writer.ue(1);
        writer.bit(false);
        writer.ue(19);
        writer.ue(14);
        writer.bit(true);
        writer.bit(true);
        writer.bit(false);
        writer.bit(true);
        writer.bit(false);
        writer.bit(false);
        writer.bit(false);
        writer.bit(false);
        writer.bit(true);
        writer.bits(1, 32);
        writer.bits(50, 32);
        writer.bit(true);
        writer.bit(true);
        writer.ue(0);
        writer.bits(0, 4);
        writer.bits(0, 4);
        writer.ue(999);
        writer.ue(1_999);
        writer.bit(true);
        writer.bits(23, 5);
        writer.bits(23, 5);
        writer.bits(23, 5);
        writer.bits(24, 5);
        writer.bit(false);
        writer.bit(false);
        writer.bit(false);
        writer.bit(true);
        writer.bit(true);
        writer.ue(2);
        writer.ue(1);
        writer.ue(16);
        writer.ue(16);
        writer.ue(0);
        writer.ue(1);
        let mut nalu = vec![0x67];
        nalu.extend(writer.finish());

        let sps = parse_sps(&nalu).unwrap();
        assert_eq!(sps.fps_milli, Some(25_000));
        let hrd = sps.nal_hrd.unwrap();
        assert_eq!(hrd.cpb_count, 1);
        assert_eq!(hrd.maximum_bit_rate_bps, 64_000);
        assert_eq!(hrd.maximum_cpb_size_bits, 32_000);
        assert!(hrd.all_cbr);
        assert_eq!(hrd.cpb_removal_delay_length, 24);
        assert_eq!(sps.max_num_reorder_frames, Some(0));
        assert_eq!(sps.max_dec_frame_buffering, Some(1));
    }

    #[test]
    fn parses_basic_slice_header() {
        let mut writer = BitWriter::default();
        writer.ue(0);
        writer.ue(2);
        writer.ue(0);
        let mut nalu = vec![0x65];
        nalu.extend(writer.finish());
        let slice = parse_slice_header(&nalu).unwrap();
        assert!(slice.idr);
        assert_eq!(slice.slice_type, 2);
        assert_eq!(slice.pps_id, 0);
    }

    #[derive(Default)]
    struct BitWriter {
        bits: Vec<bool>,
    }

    impl BitWriter {
        fn bit(&mut self, value: bool) {
            self.bits.push(value);
        }

        fn bits(&mut self, value: u32, count: usize) {
            for shift in (0..count).rev() {
                self.bit(value & (1 << shift) != 0);
            }
        }

        fn ue(&mut self, value: u32) {
            let code = value + 1;
            let width = u32::BITS - code.leading_zeros();
            for _ in 1..width {
                self.bit(false);
            }
            self.bits(code, width as usize);
        }

        fn finish(mut self) -> Vec<u8> {
            self.bit(true);
            while !self.bits.len().is_multiple_of(8) {
                self.bit(false);
            }
            self.bits
                .chunks(8)
                .map(|chunk| {
                    chunk
                        .iter()
                        .fold(0, |byte, bit| (byte << 1) | u8::from(*bit))
                })
                .collect()
        }
    }
}
