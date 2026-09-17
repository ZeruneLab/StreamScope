use crate::analyze::Nalu;
use streamscope_core::H264Issue;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPayload {
    pub sequence: u16,
    pub timestamp: u32,
    pub marker: bool,
    pub payload: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct Depacketizer {
    current: Option<FuAssembly>,
    pub issues: Vec<H264Issue>,
}

#[derive(Debug)]
struct FuAssembly {
    timestamp: u32,
    start_sequence: u16,
    last_sequence: u16,
    data: Vec<u8>,
    broken: bool,
}

impl Depacketizer {
    pub fn push(&mut self, packet: RtpPayload) -> Vec<Nalu> {
        if packet.payload.is_empty() {
            self.issue("empty_rtp_payload", "RTP H.264 负载为空", Some(&packet));
            return Vec::new();
        }
        match packet.payload[0] & 0x1f {
            1..=23 => vec![Nalu::from_rtp(
                packet.payload,
                packet.timestamp,
                packet.sequence,
                packet.sequence,
                true,
                packet.marker,
            )],
            24 => self.parse_stap_a(packet),
            28 => self.push_fu_a(packet),
            kind => {
                self.issue(
                    "unsupported_packetization",
                    &format!("不支持的 H.264 RTP NAL 类型 {kind}"),
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
                    kind: "fua_missing_end".into(),
                    detail: "FU-A 在流结束前未收到 End 分片".into(),
                    sequence: Some(current.last_sequence),
                    timestamp: Some(current.timestamp),
                });
                vec![Nalu::from_rtp(
                    current.data,
                    current.timestamp,
                    current.start_sequence,
                    current.last_sequence,
                    false,
                    false,
                )]
            })
            .unwrap_or_default()
    }

    fn parse_stap_a(&mut self, packet: RtpPayload) -> Vec<Nalu> {
        let mut cursor = 1;
        let mut nalus = Vec::new();
        while cursor < packet.payload.len() {
            if cursor + 2 > packet.payload.len() {
                self.issue("stap_a_length", "STAP-A 长度字段不完整", Some(&packet));
                break;
            }
            let length = usize::from(u16::from_be_bytes([
                packet.payload[cursor],
                packet.payload[cursor + 1],
            ]));
            cursor += 2;
            if length == 0 || cursor + length > packet.payload.len() {
                self.issue("stap_a_length", "STAP-A NALU 长度越界", Some(&packet));
                break;
            }
            nalus.push(Nalu::from_rtp(
                packet.payload[cursor..cursor + length].to_vec(),
                packet.timestamp,
                packet.sequence,
                packet.sequence,
                true,
                packet.marker && cursor + length == packet.payload.len(),
            ));
            cursor += length;
        }
        nalus
    }

    fn push_fu_a(&mut self, packet: RtpPayload) -> Vec<Nalu> {
        if packet.payload.len() < 2 {
            self.issue("fua_header", "FU-A 头部长度不足", Some(&packet));
            return Vec::new();
        }
        let start = packet.payload[1] & 0x80 != 0;
        let end = packet.payload[1] & 0x40 != 0;
        let reconstructed_header = (packet.payload[0] & 0xe0) | (packet.payload[1] & 0x1f);
        let mut output = Vec::new();
        if start {
            if let Some(previous) = self.current.take() {
                self.issues.push(H264Issue {
                    kind: "fua_missing_end".into(),
                    detail: "新的 FU-A Start 到达时上一 NALU 尚未结束".into(),
                    sequence: Some(previous.last_sequence),
                    timestamp: Some(previous.timestamp),
                });
                output.push(Nalu::from_rtp(
                    previous.data,
                    previous.timestamp,
                    previous.start_sequence,
                    previous.last_sequence,
                    false,
                    false,
                ));
            }
            let mut data = vec![reconstructed_header];
            data.extend_from_slice(&packet.payload[2..]);
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
            if timestamp_changed {
                current.broken = true;
            }
            if sequence_gap {
                current.broken = true;
            }
            current.last_sequence = packet.sequence;
            current.data.extend_from_slice(&packet.payload[2..]);
            if timestamp_changed {
                self.issue(
                    "fua_timestamp_changed",
                    "FU-A 分片跨越 RTP Timestamp",
                    Some(&packet),
                );
            }
            if sequence_gap {
                self.issue(
                    "fua_sequence_gap",
                    "FU-A 分片 Sequence 不连续",
                    Some(&packet),
                );
            }
        } else {
            self.issue(
                "fua_missing_start",
                "收到 FU-A 中间或结束分片但没有 Start",
                Some(&packet),
            );
            return output;
        }
        if end && let Some(current) = self.current.take() {
            output.push(Nalu::from_rtp(
                current.data,
                current.timestamp,
                current.start_sequence,
                current.last_sequence,
                !current.broken,
                packet.marker,
            ));
        }
        output
    }

    fn issue(&mut self, kind: &str, detail: &str, packet: Option<&RtpPayload>) {
        self.issues.push(H264Issue {
            kind: kind.into(),
            detail: detail.into(),
            sequence: packet.map(|value| value.sequence),
            timestamp: packet.map(|value| value.timestamp),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(sequence: u16, data: &[u8]) -> RtpPayload {
        RtpPayload {
            sequence,
            timestamp: 90_000,
            marker: false,
            payload: data.into(),
        }
    }

    #[test]
    fn reassembles_complete_fu_a() {
        let mut decoder = Depacketizer::default();
        assert!(decoder.push(payload(10, &[0x7c, 0x85, 1, 2])).is_empty());
        let nalus = decoder.push(payload(11, &[0x7c, 0x45, 3, 4]));
        assert_eq!(nalus.len(), 1);
        assert_eq!(nalus[0].data, [0x65, 1, 2, 3, 4]);
        assert!(nalus[0].complete);
    }

    #[test]
    fn marks_fu_a_with_sequence_gap_incomplete() {
        let mut decoder = Depacketizer::default();
        decoder.push(payload(10, &[0x7c, 0x81, 1]));
        let nalus = decoder.push(payload(12, &[0x7c, 0x41, 2]));
        assert!(!nalus[0].complete);
        assert!(
            decoder
                .issues
                .iter()
                .any(|issue| issue.kind == "fua_sequence_gap")
        );
    }

    #[test]
    fn splits_stap_a() {
        let mut decoder = Depacketizer::default();
        let nalus = decoder.push(payload(7, &[24, 0, 2, 0x67, 1, 0, 2, 0x68, 2]));
        assert_eq!(nalus.len(), 2);
        assert_eq!(nalus[0].data, [0x67, 1]);
        assert_eq!(nalus[1].data, [0x68, 2]);
    }
}
