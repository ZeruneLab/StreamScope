use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use streamscope_core::RtpStatistics;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPacket<'a> {
    pub marker: bool,
    pub payload_type: u8,
    pub sequence: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub csrc: Vec<u32>,
    pub extension: Option<HeaderExtension<'a>>,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderExtension<'a> {
    pub profile: u16,
    pub data: &'a [u8],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RtpError {
    #[error("RTP 数据短于固定头部")]
    TooShort,
    #[error("RTP 版本不是 2")]
    UnsupportedVersion,
    #[error("RTP CSRC 或扩展头越界")]
    HeaderTruncated,
    #[error("RTP Padding 长度无效")]
    InvalidPadding,
}

pub fn parse_rtp(input: &[u8]) -> Result<RtpPacket<'_>, RtpError> {
    if input.len() < 12 {
        return Err(RtpError::TooShort);
    }
    if input[0] >> 6 != 2 {
        return Err(RtpError::UnsupportedVersion);
    }
    let has_padding = input[0] & 0x20 != 0;
    let has_extension = input[0] & 0x10 != 0;
    let csrc_count = usize::from(input[0] & 0x0f);
    let mut cursor = 12 + csrc_count * 4;
    if cursor > input.len() {
        return Err(RtpError::HeaderTruncated);
    }
    let (csrc_chunks, _) = input[12..cursor].as_chunks::<4>();
    let csrc = csrc_chunks
        .iter()
        .map(|part| u32::from_be_bytes(*part))
        .collect();
    let extension = if has_extension {
        if cursor + 4 > input.len() {
            return Err(RtpError::HeaderTruncated);
        }
        let profile = u16::from_be_bytes([input[cursor], input[cursor + 1]]);
        let words = usize::from(u16::from_be_bytes([input[cursor + 2], input[cursor + 3]]));
        let data_start = cursor + 4;
        let data_end = data_start + words * 4;
        if data_end > input.len() {
            return Err(RtpError::HeaderTruncated);
        }
        cursor = data_end;
        Some(HeaderExtension {
            profile,
            data: &input[data_start..data_end],
        })
    } else {
        None
    };
    let payload_end = if has_padding {
        let padding = usize::from(*input.last().ok_or(RtpError::InvalidPadding)?);
        if padding == 0 || padding > input.len().saturating_sub(cursor) {
            return Err(RtpError::InvalidPadding);
        }
        input.len() - padding
    } else {
        input.len()
    };
    Ok(RtpPacket {
        marker: input[1] & 0x80 != 0,
        payload_type: input[1] & 0x7f,
        sequence: u16::from_be_bytes([input[2], input[3]]),
        timestamp: u32::from_be_bytes(input[4..8].try_into().expect("timestamp slice")),
        ssrc: u32::from_be_bytes(input[8..12].try_into().expect("SSRC slice")),
        csrc,
        extension,
        payload: &input[cursor..payload_end],
    })
}

#[derive(Debug)]
pub struct RtpTracker {
    statistics: RtpStatistics,
    seen_sequences: BTreeMap<u64, u64>,
    first_extended_sequence: Option<u64>,
    highest_extended_sequence: Option<u64>,
    last_timestamp: Option<u32>,
    start: Instant,
    previous_transit: Option<f64>,
    clock_rate: u32,
    bit_rate_bucket: u64,
    bit_rate_bytes: u64,
    peak_payload_bytes: u64,
}

impl RtpTracker {
    pub fn new(clock_rate: u32) -> Self {
        Self {
            statistics: RtpStatistics::default(),
            seen_sequences: BTreeMap::new(),
            first_extended_sequence: None,
            highest_extended_sequence: None,
            last_timestamp: None,
            start: Instant::now(),
            previous_transit: None,
            clock_rate,
            bit_rate_bucket: 0,
            bit_rate_bytes: 0,
            peak_payload_bytes: 0,
        }
    }

    pub fn observe(&mut self, packet: &RtpPacket<'_>, arrival: Instant) -> bool {
        if self.first_extended_sequence.is_none() {
            self.start = arrival;
        }
        let extended_sequence = self.extend_sequence(packet.sequence);
        let advances_sequence = self
            .highest_extended_sequence
            .is_none_or(|highest| extended_sequence > highest);
        // Pack 64 sequence numbers into each entry; retain only the recent
        // two sequence cycles, independently of capture length and stream count.
        let block = self
            .seen_sequences
            .entry(extended_sequence / 64)
            .or_default();
        let bit = 1_u64 << (extended_sequence % 64);
        if *block & bit != 0 {
            self.statistics.duplicate_packets += 1;
            return false;
        }
        *block |= bit;
        let highest = self
            .highest_extended_sequence
            .unwrap_or(extended_sequence)
            .max(extended_sequence);
        let keep_from = highest.saturating_sub(131_071) / 64;
        while self
            .seen_sequences
            .first_key_value()
            .is_some_and(|(key, _)| *key < keep_from)
        {
            self.seen_sequences.pop_first();
        }
        self.statistics.packet_count += 1;
        self.statistics.payload_bytes += packet.payload.len() as u64;
        let bucket = arrival.saturating_duration_since(self.start).as_secs();
        if bucket != self.bit_rate_bucket {
            self.bit_rate_bucket = bucket;
            self.bit_rate_bytes = 0;
        }
        self.bit_rate_bytes += packet.payload.len() as u64;
        self.peak_payload_bytes = self.peak_payload_bytes.max(self.bit_rate_bytes);
        self.statistics
            .first_sequence
            .get_or_insert(packet.sequence);
        self.statistics
            .first_timestamp
            .get_or_insert(packet.timestamp);

        if let Some(highest) = self.highest_extended_sequence {
            if extended_sequence > highest {
                let gap = extended_sequence.saturating_sub(highest).saturating_sub(1);
                if gap > 0 {
                    self.statistics.lost_packets = self.statistics.lost_packets.saturating_add(gap);
                    self.statistics.maximum_sequence_gap = self
                        .statistics
                        .maximum_sequence_gap
                        .max(gap.min(u64::from(u16::MAX)) as u16);
                }
                if extended_sequence / 65_536 > highest / 65_536 {
                    self.statistics.sequence_wraps += 1;
                }
                self.highest_extended_sequence = Some(extended_sequence);
                self.statistics.last_sequence = Some(packet.sequence);
            } else {
                self.statistics.out_of_order_packets += 1;
                if self
                    .first_extended_sequence
                    .is_some_and(|first| extended_sequence >= first)
                {
                    self.statistics.lost_packets = self.statistics.lost_packets.saturating_sub(1);
                }
            }
        } else {
            self.first_extended_sequence = Some(extended_sequence);
            self.highest_extended_sequence = Some(extended_sequence);
            self.statistics.last_sequence = Some(packet.sequence);
        }

        if advances_sequence && let Some(last) = self.last_timestamp {
            let backward = last.wrapping_sub(packet.timestamp);
            if packet.timestamp < last && backward < 0x8000_0000 {
                self.statistics.timestamp_rollbacks += 1;
            }
        }
        if advances_sequence {
            self.last_timestamp = Some(packet.timestamp);
        }

        if let Some(ssrc) = self.statistics.ssrc
            && ssrc != packet.ssrc
        {
            self.statistics.ssrc_changes += 1;
        }
        if let Some(payload_type) = self.statistics.payload_type
            && payload_type != packet.payload_type
        {
            self.statistics.payload_type_changes += 1;
        }
        self.statistics.ssrc = Some(packet.ssrc);
        self.statistics.payload_type = Some(packet.payload_type);
        if advances_sequence {
            self.statistics.last_timestamp = Some(packet.timestamp);
        }

        let arrival_units = arrival.saturating_duration_since(self.start).as_secs_f64()
            * f64::from(self.clock_rate.max(1));
        let transit = arrival_units - f64::from(packet.timestamp);
        if let Some(previous) = self.previous_transit {
            let difference = (transit - previous).abs();
            self.statistics.jitter += (difference - self.statistics.jitter) / 16.0;
        }
        self.previous_transit = Some(transit);
        true
    }

    fn extend_sequence(&self, sequence: u16) -> u64 {
        let Some(highest) = self.highest_extended_sequence else {
            // Leave a preceding cycle available for packets captured out of order
            // immediately across the initial 65535 -> 0 boundary.
            return 65_536 + u64::from(sequence);
        };
        let highest_sequence = highest as u16;
        let cycle = highest & !0xffff;
        if sequence < highest_sequence && highest_sequence - sequence > 0x8000 {
            cycle + 65_536 + u64::from(sequence)
        } else if sequence > highest_sequence
            && sequence - highest_sequence > 0x8000
            && cycle >= 65_536
        {
            cycle - 65_536 + u64::from(sequence)
        } else {
            cycle + u64::from(sequence)
        }
    }

    pub fn statistics(&self) -> &RtpStatistics {
        &self.statistics
    }

    pub fn into_statistics(self) -> RtpStatistics {
        let duration = self.start.elapsed();
        self.into_statistics_with_duration(duration)
    }

    pub fn into_statistics_with_duration(mut self, duration: Duration) -> RtpStatistics {
        let duration_ms = duration.as_millis().max(1) as u64;
        self.statistics.average_bit_rate_bps = Some(
            self.statistics
                .payload_bytes
                .saturating_mul(8)
                .saturating_mul(1_000)
                / duration_ms,
        );
        self.statistics.peak_bit_rate_bps =
            (self.statistics.packet_count > 0).then(|| self.peak_payload_bytes.saturating_mul(8));
        self.statistics.bit_rate_window_ms = Some(1_000);
        self.statistics
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterleavedFrame {
    pub channel: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct InterleavedDecoder {
    buffer: Vec<u8>,
}

impl InterleavedDecoder {
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    pub fn next_frame(&mut self) -> Option<InterleavedFrame> {
        let marker = self.buffer.iter().position(|byte| *byte == b'$')?;
        if marker > 0 {
            self.buffer.drain(..marker);
        }
        if self.buffer.len() < 4 {
            return None;
        }
        let length = usize::from(u16::from_be_bytes([self.buffer[2], self.buffer[3]]));
        if self.buffer.len() < 4 + length {
            return None;
        }
        let channel = self.buffer[1];
        let payload = self.buffer[4..4 + length].to_vec();
        self.buffer.drain(..4 + length);
        Some(InterleavedFrame { channel, payload })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtcpPacket {
    SenderReport {
        ssrc: u32,
        ntp_seconds: u32,
        ntp_fraction: u32,
        rtp_timestamp: u32,
        sender_packet_count: u32,
        sender_octet_count: u32,
    },
    ReceiverReport {
        ssrc: u32,
        report_count: u8,
    },
    SourceDescription {
        chunks: Vec<RtcpSdesChunk>,
    },
    Goodbye {
        sources: Vec<u32>,
    },
    Unknown {
        packet_type: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtcpSdesChunk {
    pub ssrc: u32,
    pub cname: Option<String>,
}

pub fn parse_rtcp_compound(input: &[u8]) -> Result<Vec<RtcpPacket>, RtpError> {
    let mut packets = Vec::new();
    let mut cursor = 0;
    while cursor < input.len() {
        if cursor + 4 > input.len() {
            return Err(RtpError::HeaderTruncated);
        }
        if input[cursor] >> 6 != 2 {
            return Err(RtpError::UnsupportedVersion);
        }
        let count = input[cursor] & 0x1f;
        let packet_type = input[cursor + 1];
        let words = usize::from(u16::from_be_bytes([input[cursor + 2], input[cursor + 3]]));
        let packet_length = (words + 1) * 4;
        if cursor + packet_length > input.len() || packet_length < 4 {
            return Err(RtpError::HeaderTruncated);
        }
        let body = &input[cursor + 4..cursor + packet_length];
        let packet = match packet_type {
            200 if body.len() >= 24 => RtcpPacket::SenderReport {
                ssrc: u32::from_be_bytes(body[0..4].try_into().expect("SSRC slice")),
                ntp_seconds: u32::from_be_bytes(body[4..8].try_into().expect("NTP seconds")),
                ntp_fraction: u32::from_be_bytes(body[8..12].try_into().expect("NTP fraction")),
                rtp_timestamp: u32::from_be_bytes(body[12..16].try_into().expect("RTP time")),
                sender_packet_count: u32::from_be_bytes(
                    body[16..20].try_into().expect("sender packet count"),
                ),
                sender_octet_count: u32::from_be_bytes(
                    body[20..24].try_into().expect("sender octet count"),
                ),
            },
            201 if body.len() >= 4 => RtcpPacket::ReceiverReport {
                ssrc: u32::from_be_bytes(body[0..4].try_into().expect("SSRC slice")),
                report_count: count,
            },
            202 => RtcpPacket::SourceDescription {
                chunks: parse_sdes_chunks(body, count),
            },
            203 if body.len() >= usize::from(count) * 4 => RtcpPacket::Goodbye {
                sources: body[..usize::from(count) * 4]
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|part| u32::from_be_bytes(*part))
                    .collect(),
            },
            _ => RtcpPacket::Unknown { packet_type },
        };
        packets.push(packet);
        cursor += packet_length;
    }
    Ok(packets)
}

fn parse_sdes_chunks(body: &[u8], count: u8) -> Vec<RtcpSdesChunk> {
    let mut chunks = Vec::new();
    let mut cursor = 0;
    for _ in 0..count {
        if cursor + 4 > body.len() {
            break;
        }
        let ssrc = u32::from_be_bytes(body[cursor..cursor + 4].try_into().expect("SSRC slice"));
        cursor += 4;
        let mut cname = None;
        while cursor < body.len() {
            let item_type = body[cursor];
            cursor += 1;
            if item_type == 0 {
                break;
            }
            if cursor >= body.len() {
                cursor = body.len();
                break;
            }
            let length = usize::from(body[cursor]);
            cursor += 1;
            if cursor + length > body.len() {
                cursor = body.len();
                break;
            }
            if item_type == 1 {
                cname = Some(String::from_utf8_lossy(&body[cursor..cursor + length]).into_owned());
            }
            cursor += length;
        }
        cursor = (cursor + 3) & !3;
        chunks.push(RtcpSdesChunk { ssrc, cname });
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(sequence: u16, timestamp: u32) -> Vec<u8> {
        let mut bytes = vec![0x80, 0xe0];
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.extend_from_slice(&timestamp.to_be_bytes());
        bytes.extend_from_slice(&0x1122_3344_u32.to_be_bytes());
        bytes.extend_from_slice(&[0x65, 1, 2, 3]);
        bytes
    }

    #[test]
    fn parses_rtp_header_and_payload() {
        let bytes = packet(42, 90_000);
        let parsed = parse_rtp(&bytes).unwrap();
        assert!(parsed.marker);
        assert_eq!(parsed.payload_type, 96);
        assert_eq!(parsed.sequence, 42);
        assert_eq!(parsed.payload, &[0x65, 1, 2, 3]);
    }

    #[test]
    fn tracker_counts_gap_duplicate_and_wrap() {
        let start = Instant::now();
        let mut tracker = RtpTracker::new(90_000);
        for (index, sequence) in [65_534, 65_535, 1, 1, 0].into_iter().enumerate() {
            let bytes = packet(sequence, index as u32 * 3_600);
            tracker.observe(
                &parse_rtp(&bytes).unwrap(),
                start + std::time::Duration::from_millis(index as u64 * 40),
            );
        }
        let stats = tracker.statistics();
        assert_eq!(stats.lost_packets, 0);
        assert_eq!(stats.maximum_sequence_gap, 1);
        assert_eq!(stats.duplicate_packets, 1);
        assert_eq!(stats.out_of_order_packets, 1);
        assert_eq!(stats.sequence_wraps, 1);
    }

    #[test]
    fn same_16_bit_sequence_after_wrap_is_not_a_duplicate() {
        let base = Instant::now();
        let mut tracker = RtpTracker::new(90_000);
        for (index, sequence) in [0_u16, 32_767, 65_535, 0].into_iter().enumerate() {
            let bytes = packet(sequence, index as u32 * 3_600);
            tracker.observe(
                &parse_rtp(&bytes).unwrap(),
                base + Duration::from_millis(index as u64 * 40),
            );
        }
        let stats = tracker.statistics();
        assert_eq!(stats.packet_count, 4);
        assert_eq!(stats.duplicate_packets, 0);
        assert_eq!(stats.sequence_wraps, 1);
    }

    #[test]
    fn decodes_fragmented_interleaved_frame() {
        let mut decoder = InterleavedDecoder::default();
        decoder.push(&[b'$', 0, 0]);
        assert!(decoder.next_frame().is_none());
        decoder.push(&[3, 1, 2, 3]);
        assert_eq!(
            decoder.next_frame(),
            Some(InterleavedFrame {
                channel: 0,
                payload: vec![1, 2, 3]
            })
        );
    }

    #[test]
    fn calculates_average_and_one_second_peak_bit_rate() {
        let base = Instant::now();
        let mut tracker = RtpTracker::new(90_000);
        for (index, offset_ms) in [100_u64, 500, 1_100].into_iter().enumerate() {
            let bytes = packet(index as u16, index as u32 * 3_600);
            tracker.observe(
                &parse_rtp(&bytes).unwrap(),
                base + Duration::from_millis(offset_ms),
            );
        }
        let stats = tracker.into_statistics_with_duration(Duration::from_secs(2));
        assert_eq!(stats.payload_bytes, 12);
        assert_eq!(stats.average_bit_rate_bps, Some(48));
        assert_eq!(stats.peak_bit_rate_bps, Some(64));
        assert_eq!(stats.bit_rate_window_ms, Some(1_000));
    }

    #[test]
    fn parses_rtcp_sender_report() {
        let mut bytes = vec![0x80, 200, 0, 6];
        bytes.extend_from_slice(&0x0102_0304_u32.to_be_bytes());
        bytes.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(&90_000_u32.to_be_bytes());
        bytes.extend_from_slice(&[0; 8]);
        assert_eq!(
            parse_rtcp_compound(&bytes).unwrap()[0],
            RtcpPacket::SenderReport {
                ssrc: 0x0102_0304,
                ntp_seconds: 0,
                ntp_fraction: 0,
                rtp_timestamp: 90_000,
                sender_packet_count: 0,
                sender_octet_count: 0,
            }
        );
    }

    #[test]
    fn parses_sdes_cname() {
        let mut bytes = vec![0x81, 202, 0, 3];
        bytes.extend_from_slice(&0x0102_0304_u32.to_be_bytes());
        bytes.extend_from_slice(&[1, 4]);
        bytes.extend_from_slice(b"cam1");
        bytes.extend_from_slice(&[0, 0]);
        assert_eq!(
            parse_rtcp_compound(&bytes).unwrap()[0],
            RtcpPacket::SourceDescription {
                chunks: vec![RtcpSdesChunk {
                    ssrc: 0x0102_0304,
                    cname: Some("cam1".into())
                }]
            }
        );
    }

    #[test]
    fn reordered_older_timestamp_is_not_a_sender_timestamp_rollback() {
        let mut tracker = RtpTracker::new(90_000);
        let base = Instant::now();
        for (index, (seq, ts)) in [(10, 900), (12, 2700), (11, 1800), (13, 3600)]
            .into_iter()
            .enumerate()
        {
            let bytes = packet(seq, ts);
            tracker.observe(
                &parse_rtp(&bytes).unwrap(),
                base + Duration::from_millis(index as u64),
            );
        }
        assert_eq!(tracker.statistics().timestamp_rollbacks, 0);
        assert_eq!(tracker.statistics().lost_packets, 0);
        assert_eq!(tracker.statistics().out_of_order_packets, 1);
    }

    #[test]
    fn capture_start_reordering_across_wrap_does_not_create_a_huge_gap() {
        let mut tracker = RtpTracker::new(90_000);
        let base = Instant::now();
        for seq in [0, 65535, 1] {
            let bytes = packet(seq, 100);
            tracker.observe(&parse_rtp(&bytes).unwrap(), base);
        }
        assert_eq!(tracker.statistics().lost_packets, 0);
        assert_eq!(tracker.statistics().out_of_order_packets, 1);
        assert_eq!(tracker.statistics().last_sequence, Some(1));
    }

    #[test]
    fn long_capture_uses_bounded_sequence_and_bit_rate_state() {
        let mut tracker = RtpTracker::new(90_000);
        let base = Instant::now();
        for index in 0..300_000_u64 {
            let bytes = packet(index as u16, index as u32 * 90);
            assert!(tracker.observe(
                &parse_rtp(&bytes).unwrap(),
                base + Duration::from_millis(index)
            ));
        }
        assert!(tracker.seen_sequences.len() <= 2_049);
        let bytes = packet(299_999_u64 as u16, 26_999_910);
        assert!(!tracker.observe(&parse_rtp(&bytes).unwrap(), base + Duration::from_secs(300)));
        let stats = tracker.into_statistics_with_duration(Duration::from_secs(300));
        assert_eq!(stats.packet_count, 300_000);
        assert_eq!(stats.lost_packets, 0);
        assert_eq!(stats.duplicate_packets, 1);
        assert_eq!(stats.average_bit_rate_bps, Some(32_000));
        assert_eq!(stats.peak_bit_rate_bps, Some(32_000));
    }
}
