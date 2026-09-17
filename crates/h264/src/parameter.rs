use crate::bit::{BitError, BitReader, ebsp_to_rbsp};
use streamscope_core::{H264PpsInfo, H264SpsInfo};

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
    let _constraint_flags = bits.read_bits(8)?;
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
    let fps_milli = if bits.read_bit()? {
        parse_vui_fps(&mut bits)?
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
        chroma_format_idc,
        bit_depth_luma,
        bit_depth_chroma,
        max_frame_num,
        pic_order_cnt_type,
        max_num_ref_frames,
        width,
        height,
        progressive: frame_mbs_only,
        fps_milli,
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

fn parse_vui_fps(bits: &mut BitReader<'_>) -> Result<Option<u32>, BitError> {
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
    if !bits.read_bit()? {
        return Ok(None);
    }
    let num_units_in_tick = bits.read_bits(32)?;
    let time_scale = bits.read_bits(32)?;
    let _fixed_frame_rate = bits.read_bit()?;
    if num_units_in_tick == 0 {
        return Ok(None);
    }
    Ok(Some(
        (u64::from(time_scale) * 1000 / (2 * u64::from(num_units_in_tick))) as u32,
    ))
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
