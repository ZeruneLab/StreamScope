mod analyze;
mod bit;
mod packetization;
mod parameter;

pub use analyze::{
    Nalu, analyze_annex_b, analyze_nalu_results, analyze_nalus, inspect_annex_b_range,
    split_annex_b,
};
pub use bit::{BitError, BitReader, ebsp_to_rbsp};
pub use packetization::{Depacketizer, RtpPayload};
pub use parameter::{SliceHeader, parse_pps, parse_slice_header, parse_sps};

pub fn nalu_type_name(nalu_type: u8) -> &'static str {
    match nalu_type {
        1 => "non_idr_slice",
        5 => "idr_slice",
        6 => "sei",
        7 => "sps",
        8 => "pps",
        9 => "aud",
        10 => "end_of_sequence",
        11 => "end_of_stream",
        12 => "filler",
        24 => "stap_a",
        28 => "fu_a",
        _ => "unknown",
    }
}
