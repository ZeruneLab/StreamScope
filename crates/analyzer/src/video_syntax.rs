use std::io::{self, BufRead, BufReader};
use std::path::Path;
use streamscope_core::VideoSyntaxNalu;

pub fn read_annex_b_nalu_range(source: &Path, first: u64, last: u64) -> io::Result<Vec<(u64, u64, Vec<u8>)>> {
    read_range(BufReader::with_capacity(64 * 1024, std::fs::File::open(source)?), first, last, usize::MAX)
}

pub fn inspect_annex_b_file_syntax(source: &Path, codec: &str, first: u64, last: u64) -> io::Result<Vec<VideoSyntaxNalu>> {
    if first == 0 || last < first || last - first >= 50 || !matches!(codec, "h264" | "h265") {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "请选择 H.264/H.265 和最多 50 个 NALU 的有效范围（序号从 1 开始）"));
    }
    let selected = read_range(BufReader::with_capacity(64 * 1024, std::fs::File::open(source)?), first, last, 8 * 1024 * 1024)?;
    Ok(selected.into_iter().filter_map(|(index, offset, data)| {
        let mut sample = vec![0, 0, 1];
        sample.extend_from_slice(&data);
        let mut nalu = match codec {
            "h264" => streamscope_h264::inspect_annex_b_range(&sample, 1, 1),
            _ => streamscope_h265::inspect_annex_b_range(&sample, 1, 1),
        }.pop()?;
        nalu.index = index;
        nalu.offset = offset;
        nalu.size = data.len() as u64;
        nalu.hex = nalu.hex.lines().enumerate().map(|(line, value)| {
            let bytes = value.split_once("  ").map_or(value, |(_, bytes)| bytes);
            format!("{:08X}  {bytes}", offset + (line * 16) as u64)
        }).collect::<Vec<_>>().join("\n");
        Some(nalu)
    }).collect())
}

fn read_range(mut reader: impl BufRead, first: u64, last: u64, limit: usize) -> io::Result<Vec<(u64, u64, Vec<u8>)>> {
    let mut selected = Vec::new();
    let mut current = Vec::new();
    let mut pending_zeros = 0_usize;
    let mut active_index = 0_u64;
    let mut active_offset = 0_u64;
    let mut absolute = 0_u64;
    let mut retained = 0_usize;
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            if (first..=last).contains(&active_index) {
                if pending_zeros > limit.saturating_sub(retained) { return Err(too_large()); }
                current.extend(std::iter::repeat_n(0, pending_zeros));
                if !current.is_empty() { selected.push((active_index, active_offset, current)); }
            }
            return Ok(selected);
        }
        let mut consumed = 0;
        let mut complete = false;
        for &byte in buffer {
            let position = absolute + consumed as u64;
            consumed += 1;
            if byte == 0 { pending_zeros += 1; continue; }
            if byte == 1 && pending_zeros >= 2 {
                if (first..=last).contains(&active_index) && !current.is_empty() {
                    selected.push((active_index, active_offset, std::mem::take(&mut current)));
                } else { current.clear(); }
                if active_index >= last { complete = true; break; }
                active_index += 1;
                active_offset = position + 1;
                pending_zeros = 0;
                continue;
            }
            if (first..=last).contains(&active_index) {
                if pending_zeros >= limit.saturating_sub(retained) { return Err(too_large()); }
                retained += pending_zeros + 1;
                current.extend(std::iter::repeat_n(0, pending_zeros));
                current.push(byte);
            }
            pending_zeros = 0;
        }
        reader.consume(consumed);
        absolute += consumed as u64;
        if complete { return Ok(selected); }
    }
}

fn too_large() -> io::Error { io::Error::new(io::ErrorKind::InvalidData, "选中 NALU 数据超过语法查看大小限制，请缩小范围") }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn range_reader_preserves_offsets_across_buffer_boundaries() {
        let data = [0, 0, 0, 1, 0x67, 0x42, 0, 0, 1, 0x68, 0xce, 0, 0, 1, 0x65, 0x88];
        let selected = read_range(BufReader::with_capacity(2, io::Cursor::new(data)), 2, 2, 2).unwrap();
        assert_eq!(selected, vec![(2, 9, vec![0x68, 0xce])]);
        assert!(read_range(io::Cursor::new(data), 1, 3, 5).is_err());
    }
}
