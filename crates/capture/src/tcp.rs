use crate::reader::FrameMeta;
use std::collections::{BTreeMap, VecDeque};

const MAX_PENDING_BYTES: usize = 64 * 1024;
const MAX_PENDING_SEGMENTS: usize = 256;
const MAX_MESSAGE_BYTES: usize = 256 * 1024;

#[derive(Debug)]
pub(crate) struct Chunk {
    pub data: Vec<u8>,
    pub meta: FrameMeta,
    pub discontinuity: bool,
}

#[derive(Default)]
pub(crate) struct Reassembly {
    anchor: Option<u32>,
    expected: Option<i64>,
    pending: BTreeMap<i64, Chunk>,
    pending_bytes: usize,
    first_micros: Option<u64>,
    pub gaps: u64,
    pub retransmitted_bytes: u64,
    pub late_bytes: u64,
}

impl Reassembly {
    pub fn push(&mut self, sequence: u32, syn: bool, data: &[u8], meta: &FrameMeta) -> Vec<Chunk> {
        let sequence = sequence.wrapping_add(u32::from(syn));
        let anchor = *self.anchor.get_or_insert(sequence);
        let reference = self.expected.unwrap_or(0);
        let cycle = reference & !0xffff_ffff;
        let mut position = cycle + i64::from(sequence.wrapping_sub(anchor));
        if position - reference > i64::from(i32::MAX) {
            position -= 1_i64 << 32;
        }
        if reference - position > i64::from(i32::MAX) {
            position += 1_i64 << 32;
        }
        if syn {
            self.expected.get_or_insert(position);
        }
        if data.is_empty() {
            return Vec::new();
        }
        let mut start = 0;
        if let Some(expected) = self.expected
            && position < expected
        {
            start = usize::try_from(expected - position)
                .unwrap_or(usize::MAX)
                .min(data.len());
            self.retransmitted_bytes += start as u64;
            if self.gaps > 0 {
                self.late_bytes += start as u64;
            }
            position += start as i64;
        }
        if start == data.len() {
            return Vec::new();
        }
        self.first_micros.get_or_insert(meta.timestamp_micros);
        let chunk = Chunk {
            data: data[start..].to_vec(),
            meta: meta.clone(),
            discontinuity: false,
        };
        if let Some(previous) = self.pending.get(&position) {
            if previous.data.len() >= chunk.data.len() {
                self.retransmitted_bytes += chunk.data.len() as u64;
                return Vec::new();
            }
            self.pending_bytes -= previous.data.len();
        }
        self.pending_bytes += chunk.data.len();
        self.pending.insert(position, chunk);
        let age = meta
            .timestamp_micros
            .saturating_sub(self.first_micros.unwrap_or(meta.timestamp_micros));
        if self.expected.is_none()
            && (self.pending.len() >= 16 || self.pending_bytes >= 64 * 1024 || age >= 200_000)
        {
            self.expected = self
                .pending
                .first_key_value()
                .map(|(position, _)| *position);
        }
        let mut output = self.drain();
        if self.pending_bytes > MAX_PENDING_BYTES
            || self.pending.len() > MAX_PENDING_SEGMENTS
            || (age >= 2_000_000 && !self.pending.is_empty())
        {
            output.extend(self.skip_gap());
        }
        output
    }

    fn drain(&mut self) -> Vec<Chunk> {
        let mut output = Vec::new();
        while let (Some(expected), Some((&position, _))) =
            (self.expected, self.pending.first_key_value())
        {
            if position > expected {
                break;
            }
            let (_, mut chunk) = self.pending.pop_first().unwrap();
            self.pending_bytes -= chunk.data.len();
            let overlap = usize::try_from(expected - position)
                .unwrap_or(usize::MAX)
                .min(chunk.data.len());
            self.retransmitted_bytes += overlap as u64;
            chunk.data.drain(..overlap);
            if !chunk.data.is_empty() {
                self.expected = Some(expected + chunk.data.len() as i64);
                output.push(chunk);
            }
        }
        self.first_micros = self
            .pending
            .values()
            .map(|chunk| chunk.meta.timestamp_micros)
            .min();
        output
    }

    fn skip_gap(&mut self) -> Vec<Chunk> {
        let Some((&position, _)) = self.pending.first_key_value() else {
            return Vec::new();
        };
        let gap = self.expected.is_some_and(|expected| position > expected);
        self.expected = Some(position);
        if gap {
            self.gaps += 1;
        }
        let mut output = self.drain();
        if gap && let Some(chunk) = output.first_mut() {
            chunk.discontinuity = true;
        }
        output
    }

    pub fn finish(&mut self) -> Vec<Chunk> {
        let mut output = Vec::new();
        while !self.pending.is_empty() {
            output.extend(self.skip_gap());
        }
        output
    }
}

pub(crate) enum Message {
    Interleaved {
        channel: u8,
        payload: Vec<u8>,
        meta: FrameMeta,
    },
    Rtsp {
        text: String,
    },
}

#[derive(Default)]
pub(crate) struct Decoder {
    buffer: Vec<u8>,
    spans: VecDeque<(usize, FrameMeta)>,
    pub discarded_bytes: u64,
}

impl Decoder {
    pub fn push(&mut self, chunk: Chunk) -> Vec<Message> {
        if chunk.discontinuity {
            self.discarded_bytes += self.buffer.len() as u64;
            self.buffer.clear();
            self.spans.clear();
        }
        self.spans.push_back((chunk.data.len(), chunk.meta));
        self.buffer.extend_from_slice(&chunk.data);
        if self.buffer.len() > MAX_MESSAGE_BYTES {
            self.discarded_bytes += self.buffer.len() as u64;
            self.buffer.clear();
            self.spans.clear();
            return Vec::new();
        }
        let mut output = Vec::new();
        loop {
            if self.buffer.is_empty() {
                break;
            }
            if self.buffer[0] == b'$' {
                if self.buffer.len() < 4 {
                    break;
                }
                let length = usize::from(u16::from_be_bytes([self.buffer[2], self.buffer[3]]));
                if length < 4 {
                    self.discard(1);
                    self.discarded_bytes += 1;
                    continue;
                }
                // A resynchronization candidate must begin with RTP/RTCP version 2.
                if self.buffer.len() >= 5 && self.buffer[4] >> 6 != 2 {
                    self.discard(1);
                    self.discarded_bytes += 1;
                    continue;
                }
                if self.buffer.len() < length + 4 {
                    break;
                }
                output.push(Message::Interleaved {
                    channel: self.buffer[1],
                    payload: self.buffer[4..length + 4].to_vec(),
                    meta: self.spans.front().unwrap().1.clone(),
                });
                self.discard(length + 4);
            } else if starts_rtsp(&self.buffer) {
                let Some(header_end) = self
                    .buffer
                    .windows(4)
                    .position(|value| value == b"\r\n\r\n")
                    .map(|value| value + 4)
                else {
                    if self.buffer.len() > 64 * 1024 {
                        self.discarded_bytes += self.buffer.len() as u64;
                        self.buffer.clear();
                        self.spans.clear();
                    }
                    break;
                };
                let header = String::from_utf8_lossy(&self.buffer[..header_end]);
                let length = header
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                if length > MAX_MESSAGE_BYTES - header_end {
                    self.discarded_bytes += self.buffer.len() as u64;
                    self.buffer.clear();
                    self.spans.clear();
                    break;
                }
                if self.buffer.len() < header_end + length {
                    break;
                }
                output.push(Message::Rtsp {
                    text: String::from_utf8_lossy(&self.buffer[..header_end + length]).into_owned(),
                });
                self.discard(header_end + length);
            } else {
                // Keep a short suffix so a split RTSP method is not lost.
                if self.buffer.len() < 16 {
                    break;
                }
                let next = (1..self.buffer.len()).find(|&index| {
                    self.buffer[index] == b'$' || starts_rtsp(&self.buffer[index..])
                });
                let count = next.unwrap_or(self.buffer.len().saturating_sub(15));
                self.discarded_bytes += count as u64;
                self.discard(count);
            }
        }
        output
    }

    fn discard(&mut self, count: usize) {
        self.buffer.drain(..count);
        let mut remaining = count;
        while remaining > 0 {
            let Some((length, _)) = self.spans.front_mut() else {
                break;
            };
            if *length > remaining {
                *length -= remaining;
                break;
            }
            remaining -= *length;
            self.spans.pop_front();
        }
    }

    pub fn unfinished_bytes(&self) -> usize {
        self.buffer.len()
    }
}

fn starts_rtsp(bytes: &[u8]) -> bool {
    [
        b"RTSP/".as_slice(),
        b"OPTIONS ",
        b"DESCRIBE ",
        b"SETUP ",
        b"PLAY ",
        b"PAUSE ",
        b"TEARDOWN ",
        b"GET_PARAMETER ",
        b"SET_PARAMETER ",
        b"ANNOUNCE ",
        b"RECORD ",
    ]
    .iter()
    .any(|prefix| bytes.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn meta(number: u64) -> FrameMeta {
        FrameMeta {
            number,
            timestamp_micros: number * 1_000,
            interface: "0".into(),
        }
    }
    #[test]
    fn reorders_retransmission_and_overlapping_segments() {
        let mut tcp = Reassembly::default();
        tcp.push(99, true, &[], &meta(1));
        assert!(tcp.push(103, false, b"def", &meta(2)).is_empty());
        let chunks = tcp.push(100, false, b"abcd", &meta(3));
        assert_eq!(
            chunks
                .into_iter()
                .flat_map(|chunk| chunk.data)
                .collect::<Vec<_>>(),
            b"abcdef"
        );
        assert!(tcp.push(100, false, b"abcdef", &meta(4)).is_empty());
        assert_eq!(tcp.gaps, 0);
    }
    #[test]
    fn handles_sequence_wrap_and_missing_segment() {
        let mut tcp = Reassembly::default();
        tcp.push(u32::MAX - 2, true, &[], &meta(1));
        let first = tcp.push(u32::MAX - 1, false, b"abcd", &meta(2));
        assert_eq!(first[0].data, b"abcd");
        assert_eq!(tcp.push(2, false, b"ef", &meta(3))[0].data, b"ef");
        tcp.push(10, false, b"next", &meta(4));
        let tail = tcp.finish();
        assert_eq!(tcp.gaps, 1);
        assert!(tail[0].discontinuity);
    }
    #[test]
    fn does_not_decode_dollar_inside_rtsp_body() {
        let mut decoder = Decoder::default();
        let body = "$abc";
        let bytes = format!(
            "RTSP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        assert!(matches!(
            &decoder.push(Chunk {
                data: bytes.into_bytes(),
                meta: meta(1),
                discontinuity: false
            })[..],
            [Message::Rtsp { .. }]
        ));
    }
}
