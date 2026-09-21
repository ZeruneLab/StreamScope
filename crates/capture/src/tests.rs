use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    directory: PathBuf,
    packets: Vec<(u64, Vec<u8>)>,
}
impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "streamscope-capture-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory).unwrap();
        Self {
            directory,
            packets: Vec::new(),
        }
    }
    fn add(&mut self, micros: u64, data: Vec<u8>) {
        self.packets.push((micros, data));
    }
    fn analyze(&self) -> CaptureAnalysis {
        let path = self.directory.join("input.pcap");
        let mut bytes = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        bytes.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(&65_535_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        for (micros, data) in &self.packets {
            bytes.extend_from_slice(&((micros / 1_000_000) as u32).to_le_bytes());
            bytes.extend_from_slice(&((micros % 1_000_000) as u32).to_le_bytes());
            bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
            bytes.extend_from_slice(data);
        }
        std::fs::write(&path, bytes).unwrap();
        analyze_capture_file(&path, &self.directory.join("reports")).unwrap()
    }
    fn setup(&mut self, server: u8, client_port: u16, transport: &str) -> u32 {
        self.setup_codec(server, client_port, transport, "H264")
    }
    fn setup_codec(&mut self, server: u8, client_port: u16, transport: &str, codec: &str) -> u32 {
        self.add(0, tcp_frame(server, client_port, true, 99, 2, &[]));
        self.add(1, tcp_frame(server, client_port, false, 999, 18, &[]));
        let (media_type, clock_rate) = if codec.to_ascii_lowercase().contains("g726") {
            ("audio", 8_000)
        } else {
            ("video", 90_000)
        };
        let sdp = format!(
            "v=0\r\nm={media_type} 0 RTP/AVP 96\r\na=rtpmap:96 {codec}/{clock_rate}\r\na=control:track1\r\n"
        );
        let describe = format!(
            "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
            sdp.len()
        );
        self.add(
            2,
            tcp_frame(server, client_port, false, 1000, 24, describe.as_bytes()),
        );
        let setup = format!(
            "SETUP rtsp://192.0.2.{server}/track1 RTSP/1.0\r\nCSeq: 2\r\nTransport: {transport}\r\n\r\n"
        );
        self.add(
            3,
            tcp_frame(server, client_port, true, 100, 24, setup.as_bytes()),
        );
        let reply = format!(
            "RTSP/1.0 200 OK\r\nCSeq: 2\r\nSession: test-{server}\r\nTransport: {transport}\r\n\r\n"
        );
        self.add(
            4,
            tcp_frame(
                server,
                client_port,
                false,
                1000 + describe.len() as u32,
                24,
                reply.as_bytes(),
            ),
        );
        1000 + describe.len() as u32 + reply.len() as u32
    }
}

#[test]
fn declared_h265_capture_produces_independent_hevc_analysis_and_sample() {
    let mut fixture = Fixture::new();
    fixture.setup_codec(
        1,
        45000,
        "RTP/AVP;unicast;client_port=6000-6001;server_port=5004-5005",
        "H265",
    );
    let nalus: [&[u8]; 4] = [
        &[
            0x40, 0x01, 0x0c, 0x01, 0xff, 0xff, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00, 0x90, 0x00,
            0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x1e, 0x95, 0x98, 0x09,
        ],
        &[
            0x42, 0x01, 0x01, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00, 0x90, 0x00, 0x00, 0x03, 0x00,
            0x00, 0x03, 0x00, 0x1e, 0xa0, 0x10, 0x20, 0x61, 0x65, 0x95, 0x9a, 0x49, 0x32, 0xbc,
            0x05, 0xa0, 0x20, 0x00, 0x00, 0x03, 0x00, 0x20, 0x00, 0x00, 0x03, 0x01, 0x41,
        ],
        &[0x44, 0x01, 0xc1, 0x72, 0xb4, 0x22, 0x40],
        &[0x26, 0x01, 0x80],
    ];
    for (index, nalu) in nalus.into_iter().enumerate() {
        fixture.add(
            1_000_000 + index as u64 * 40_000,
            udp(1, 6000, &rtp(42, index as u16 + 1, 90_000, 96, nalu)),
        );
    }

    let result = fixture.analyze();
    assert_eq!(result.streams.len(), 1);
    let stream = &result.streams[0];
    assert_eq!(stream.identity.codec.as_deref(), Some("h265"));
    assert!(stream.h264.is_none());
    let h265 = stream.h265.as_ref().unwrap();
    assert_eq!(h265.vps_count, 1);
    assert_eq!(h265.sps[0].width, 128);
    assert_eq!(h265.sps[0].height, 96);
    assert_eq!(h265.frame_count, 1);
    assert_eq!(h265.idr_frames, 1);
    assert_eq!(h265.nalus.len(), 4);
    assert!(h265.nalus.iter().all(|nalu| nalu.packets.len() == 1));
    assert_eq!(h265.nalus[3].access_unit_number, Some(1));
    assert_eq!(
        stream
            .sample_path
            .as_ref()
            .and_then(|path| path.extension())
            .and_then(|extension| extension.to_str()),
        Some("h265")
    );
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn network_frame(
    server: u8,
    client_port: u16,
    client_to_server: bool,
    tcp: bool,
    sequence: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let header = if tcp { 20 } else { 8 };
    let mut frame = vec![0; 14 + 20 + header];
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&((20 + header + payload.len()) as u16).to_be_bytes());
    frame[23] = if tcp { 6 } else { 17 };
    let server_ip = [192, 0, 2, server];
    let client_ip = [198, 51, 100, 1];
    frame[26..30].copy_from_slice(if client_to_server {
        &client_ip
    } else {
        &server_ip
    });
    frame[30..34].copy_from_slice(if client_to_server {
        &server_ip
    } else {
        &client_ip
    });
    let server_port = if tcp { 554_u16 } else { 5004 };
    frame[34..36].copy_from_slice(
        &(if client_to_server {
            client_port
        } else {
            server_port
        })
        .to_be_bytes(),
    );
    frame[36..38].copy_from_slice(
        &(if client_to_server {
            server_port
        } else {
            client_port
        })
        .to_be_bytes(),
    );
    if tcp {
        frame[38..42].copy_from_slice(&sequence.to_be_bytes());
        frame[46] = 0x50;
        frame[47] = flags;
    } else {
        frame[38..40].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    frame
}
fn udp(server: u8, port: u16, payload: &[u8]) -> Vec<u8> {
    network_frame(server, port, false, false, 0, 0, payload)
}
fn tcp_frame(server: u8, port: u16, reverse: bool, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    network_frame(server, port, reverse, true, seq, flags, payload)
}
fn rtp(ssrc: u32, seq: u16, ts: u32, pt: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, pt | 0x80];
    bytes.extend_from_slice(&seq.to_be_bytes());
    bytes.extend_from_slice(&ts.to_be_bytes());
    bytes.extend_from_slice(&ssrc.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
fn interleaved(channel: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![b'$', channel];
    bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn isolates_2_10_50_100_interleaved_udp_streams_with_identical_ssrc() {
    for count in [2_u8, 10, 50, 100] {
        let mut fixture = Fixture::new();
        for seq in 1..=10_u16 {
            for server in 1..=count {
                fixture.add(
                    u64::from(seq) * 500_000,
                    udp(
                        server,
                        6000,
                        &rtp(42, seq, u32::from(seq) * 4000, 0, &[1, 2, 3, 4]),
                    ),
                );
            }
        }
        let capture = fixture.analyze();
        assert_eq!(capture.streams.len(), count as usize);
        for stream in &capture.streams {
            assert_eq!(stream.protocol.rtp.packet_count, 10);
            assert_eq!(stream.protocol.rtp.lost_packets, 0);
            assert_eq!(stream.protocol.rtp.duplicate_packets, 0);
            assert_eq!(stream.protocol.rtp.ssrc_changes, 0);
            assert_eq!(stream.protocol.sample_duration_ms, Some(4500));
            assert!(stream.h264.is_none());
        }
        let mut single = Fixture::new();
        single.packets = fixture
            .packets
            .iter()
            .filter(|(_, data)| data[29] == 1)
            .cloned()
            .collect();
        assert_eq!(
            single.analyze().streams[0].protocol.rtp,
            capture.streams[0].protocol.rtp
        );
    }
}

#[test]
fn separates_same_endpoint_different_ssrc_and_keeps_payload_type_changes_in_one_stream() {
    let mut fixture = Fixture::new();
    for seq in 1..=5 {
        for ssrc in [10, 20] {
            fixture.add(
                u64::from(seq) * 1000,
                udp(
                    1,
                    6000,
                    &rtp(
                        ssrc,
                        seq,
                        u32::from(seq) * 800,
                        if seq < 3 { 0 } else { 8 },
                        &[1, 2],
                    ),
                ),
            );
        }
    }
    let result = fixture.analyze();
    assert_eq!(result.streams.len(), 2);
    for stream in &result.streams {
        assert_eq!(stream.protocol.rtp.packet_count, 5);
        assert_eq!(stream.identity.payload_types, [0, 8]);
        assert_eq!(stream.protocol.rtp.lost_packets, 0);
    }
}

#[test]
fn one_stream_loss_does_not_contaminate_another_and_udp_reorder_repairs_fu_a() {
    let mut fixture = Fixture::new();
    for server in [1, 2] {
        fixture.setup(
            server,
            45000,
            "RTP/AVP;unicast;client_port=6000-6001;server_port=5004-5005",
        );
    }
    for (seq, bytes) in [
        (10, vec![0x7c, 0x85, 1]),
        (12, vec![0x7c, 0x45, 3]),
        (11, vec![0x7c, 0x05, 2]),
    ] {
        fixture.add(
            1_000_000 + u64::from(seq) * 100,
            udp(1, 6000, &rtp(42, seq, 90000, 96, &bytes)),
        );
        if seq != 11 {
            fixture.add(
                1_000_000 + u64::from(seq) * 100,
                udp(2, 6000, &rtp(42, seq, 90000, 96, &bytes)),
            );
        }
    }
    let result = fixture.analyze();
    assert_eq!(result.streams.len(), 2);
    let a = &result.streams[0];
    let b = &result.streams[1];
    assert_eq!(a.protocol.rtp.lost_packets, 0);
    assert_eq!(a.protocol.rtp.out_of_order_packets, 1);
    assert_eq!(a.h264.as_ref().unwrap().incomplete_nalus, 0);
    assert_eq!(b.protocol.rtp.lost_packets, 1);
    assert_eq!(b.h264.as_ref().unwrap().incomplete_nalus, 1);
    let complete_nalu = &a.h264.as_ref().unwrap().nalus[0];
    assert_eq!(
        complete_nalu
            .packets
            .iter()
            .map(|packet| packet.rtp_sequence)
            .collect::<Vec<_>>(),
        [10, 11, 12]
    );
    assert_eq!(complete_nalu.access_unit_number, Some(1));
    assert!(complete_nalu.sample_start_offset.is_some());
    assert!(complete_nalu.sample_end_offset.is_some());
    assert_eq!(
        std::fs::read(a.sample_path.as_ref().unwrap()).unwrap(),
        [0, 0, 0, 1, 0x65, 1, 2, 3]
    );
    assert!(
        b.identity
            .events
            .iter()
            .any(|event| event.kind == "fua_sequence_gap" && event.packet_number > 0)
    );
}

#[test]
fn tcp_channels_connections_retransmissions_and_split_headers_are_independent() {
    let mut fixture = Fixture::new();
    for port in [45000, 45001] {
        let start = fixture.setup(1, port, "RTP/AVP/TCP;unicast;interleaved=0-1");
        let mut bytes = Vec::new();
        for seq in 1..=5 {
            for channel in [0, 2] {
                bytes.extend(interleaved(
                    channel,
                    &rtp(42, seq, u32::from(seq) * 3600, 96, &[0x65, 0xb0]),
                ));
            }
        }
        fixture.add(
            1_000_000,
            tcp_frame(1, port, false, start + 3, 24, &bytes[3..]),
        );
        fixture.add(1_001_000, tcp_frame(1, port, false, start, 24, &bytes[..3]));
        fixture.add(1_002_000, tcp_frame(1, port, false, start, 24, &bytes));
    }
    let result = fixture.analyze();
    assert_eq!(result.streams.len(), 4);
    for stream in result.streams {
        assert_eq!(stream.protocol.rtp.packet_count, 5);
        assert_eq!(stream.protocol.rtp.duplicate_packets, 0);
        assert_eq!(stream.protocol.rtp.lost_packets, 0);
    }
}

#[test]
fn tcp_missing_bytes_marks_evidence_incomplete_and_new_syn_splits_connection() {
    let mut fixture = Fixture::new();
    let start = fixture.setup(1, 45000, "RTP/AVP/TCP;unicast;interleaved=0-1");
    let first = interleaved(0, &rtp(42, 1, 90000, 96, &[0x65, 0xb0]));
    fixture.add(1_000_000, tcp_frame(1, 45000, false, start, 24, &first));
    fixture.add(
        2_000_000,
        tcp_frame(
            1,
            45000,
            false,
            start + first.len() as u32 + 10,
            24,
            &interleaved(0, &rtp(42, 2, 93600, 96, &[0x65, 0xb0])),
        ),
    );
    fixture.add(3_000_000, tcp_frame(1, 45000, true, 5000, 2, &[]));
    fixture.add(3_000_001, tcp_frame(1, 45000, false, 8000, 18, &[]));
    fixture.add(3_000_002, tcp_frame(1, 45000, false, 8001, 24, &first));
    let result = fixture.analyze();
    assert_eq!(result.streams.len(), 2);
    assert!(result.streams[0].identity.sample_truncated);
    assert_ne!(
        result.streams[0].identity.connection_id,
        result.streams[1].identity.connection_id
    );
}

#[test]
fn unknown_dynamic_audio_is_not_treated_as_h264_from_one_byte() {
    let mut fixture = Fixture::new();
    for seq in 1..=5 {
        fixture.add(
            u64::from(seq) * 10_000,
            udp(
                1,
                6000,
                &rtp(42, seq, u32::from(seq) * 800, 97, &[0x65, 0x42, 0x31]),
            ),
        );
    }
    let result = fixture.analyze();
    assert!(result.streams[0].h264.is_none());
    assert!(result.streams[0].sample_path.is_none());
    assert_eq!(result.streams[0].identity.codec_confidence, "unknown");
}

#[test]
fn static_pcma_is_grouped_as_audio_and_generates_pcm_preview() {
    let mut fixture = Fixture::new();
    for seq in 0..60_u16 {
        fixture.add(
            u64::from(seq) * 20_000,
            udp(
                1,
                6000,
                &rtp(42, seq, u32::from(seq) * 160, 8, &[0xd5; 160]),
            ),
        );
    }
    let result = fixture.analyze();
    assert_eq!(result.streams.len(), 1);
    let stream = &result.streams[0];
    assert_eq!(stream.identity.media_type, "audio");
    assert_eq!(stream.identity.codec.as_deref(), Some("pcma"));
    let audio = stream.audio.as_ref().unwrap();
    assert!(audio.codec_supported_for_decode);
    assert!(audio.conclusion_reliable);
    assert_eq!(audio.timestamp_gap_count, 0);
    assert_eq!(
        stream
            .sample_path
            .as_ref()
            .and_then(|path| path.extension())
            .and_then(|extension| extension.to_str()),
        Some("wav")
    );
}

#[test]
fn static_telephony_codecs_generate_independent_raw_samples() {
    for (payload_type, codec, extension) in [
        (9, "g722", "g722"),
        (4, "g723", "g723_1"),
        (18, "g729", "g729"),
    ] {
        let mut fixture = Fixture::new();
        for seq in 0..3_u16 {
            fixture.add(
                u64::from(seq) * 20_000,
                udp(
                    1,
                    6000,
                    &rtp(42, seq, u32::from(seq) * 160, payload_type, &[1, 2, 3, 4]),
                ),
            );
        }
        let result = fixture.analyze();
        let stream = &result.streams[0];
        assert_eq!(stream.identity.media_type, "audio");
        assert_eq!(stream.identity.codec.as_deref(), Some(codec));
        let sample = stream.sample_path.as_ref().unwrap();
        assert_eq!(
            sample.extension().and_then(|value| value.to_str()),
            Some(extension)
        );
        assert_eq!(std::fs::read(sample).unwrap(), [1, 2, 3, 4].repeat(3));
        if codec == "g722" {
            assert_eq!(stream.audio.as_ref().unwrap().sample_rate, Some(16_000));
        }
    }
}

#[test]
fn dynamic_g726_uses_sdp_mapping_and_preserves_rtp_payload() {
    let mut fixture = Fixture::new();
    fixture.setup_codec(
        1,
        45_000,
        "RTP/AVP;unicast;client_port=6000-6001;server_port=5004-5005",
        "G726-32",
    );
    for seq in 0..3_u16 {
        fixture.add(
            1_000_000 + u64::from(seq) * 20_000,
            udp(
                1,
                6000,
                &rtp(42, seq, u32::from(seq) * 160, 96, &[5, 6, 7, 8]),
            ),
        );
    }
    let result = fixture.analyze();
    let stream = &result.streams[0];
    assert_eq!(stream.identity.media_type, "audio");
    assert_eq!(stream.identity.codec.as_deref(), Some("g726-32"));
    let sample = stream.sample_path.as_ref().unwrap();
    assert_eq!(
        sample.extension().and_then(|value| value.to_str()),
        Some("g726")
    );
    assert_eq!(std::fs::read(sample).unwrap(), [5, 6, 7, 8].repeat(3));
}

#[test]
fn confirmed_sequence_restart_creates_an_explicit_uncertain_stage() {
    let mut fixture = Fixture::new();
    for (index, seq) in [40000, 40001, 1000, 1001, 1002].into_iter().enumerate() {
        fixture.add(
            index as u64 * 10000,
            udp(1, 6000, &rtp(42, seq, index as u32 * 800, 0, &[1])),
        );
    }
    let result = fixture.analyze();
    assert_eq!(result.streams.len(), 2);
    assert_eq!(result.streams[0].protocol.rtp.packet_count, 2);
    assert_eq!(result.streams[1].protocol.rtp.packet_count, 3);
    assert!(
        result
            .streams
            .iter()
            .all(|stream| !stream.warnings.is_empty() && stream.protocol.rtp.lost_packets == 0)
    );
}

#[test]
fn sample_limit_is_permanent_and_rtp_statistics_continue() {
    let fixture = Fixture::new();
    let mut capture = Capture {
        output: &fixture.directory,
        summary: CaptureSummary::default(),
        states: Vec::new(),
        routes: HashMap::new(),
        connections: HashMap::new(),
        completed_sessions: Vec::new(),
        udp_bindings: Vec::new(),
        next_connection: 0,
        first_micros: None,
        last_micros: 0,
        sample_bytes: MAX_TOTAL_SAMPLE_BYTES - 40,
        start: Instant::now(),
        spools: Spools::default(),
    };
    for (index, payload) in [vec![1; 10], vec![1]].into_iter().enumerate() {
        capture
            .frame(reader::Frame {
                meta: FrameMeta {
                    number: index as u64 + 1,
                    timestamp_micros: index as u64 * 1000,
                    interface: "0".into(),
                },
                data: udp(1, 6000, &rtp(42, index as u16, 0, 0, &payload)),
                link_type: 1,
                truncated: false,
            })
            .unwrap();
    }
    assert_eq!(capture.states[0].sample_packets, 0);
    assert!(capture.states[0].identity.sample_truncated);
    assert_eq!(capture.states[0].tracker.statistics().packet_count, 2);
}

#[test]
fn sender_reports_are_associated_by_endpoints_not_just_ssrc() {
    let mut fixture = Fixture::new();
    for server in [1, 2] {
        fixture.add(0, udp(server, 6000, &rtp(42, 1, 0, 0, &[1])));
    }
    let mut sr = vec![0x80, 200, 0, 6];
    sr.extend(42_u32.to_be_bytes());
    sr.extend([0; 20]);
    fixture.add(1000, udp(1, 6000, &sr));
    let result = fixture.analyze();
    assert_eq!(result.streams[0].protocol.rtcp_packet_count, 1);
    assert_eq!(result.streams[1].protocol.rtcp_packet_count, 0);
}

#[test]
fn rejects_truncated_capture_instead_of_returning_silent_success() {
    let fixture = Fixture::new();
    let path = fixture.directory.join("truncated.pcap");
    std::fs::write(&path, [0xd4, 0xc3, 0xb2, 0xa1]).unwrap();
    assert!(analyze_capture_file(&path, &fixture.directory.join("reports")).is_err());
}

#[test]
fn pcapng_interfaces_and_nanosecond_resolution_are_preserved() {
    fn block(kind: u32, mut body: Vec<u8>) -> Vec<u8> {
        while !body.len().is_multiple_of(4) {
            body.push(0);
        }
        let length = (body.len() + 12) as u32;
        let mut bytes = kind.to_le_bytes().to_vec();
        bytes.extend(length.to_le_bytes());
        bytes.extend(body);
        bytes.extend(length.to_le_bytes());
        bytes
    }
    let fixture = Fixture::new();
    let mut section = 0x1a2b3c4d_u32.to_le_bytes().to_vec();
    section.extend([1, 0, 0, 0]);
    section.extend([0xff; 8]);
    let mut bytes = block(0x0a0d0d0a, section);
    for _ in 0..2 {
        let mut interface = vec![1, 0, 0, 0];
        interface.extend(65535_u32.to_le_bytes());
        interface.extend([9, 0, 1, 0, 9, 0, 0, 0]);
        bytes.extend(block(1, interface));
    }
    for seq in 1..=2_u16 {
        for interface in 0..2_u32 {
            let data = udp(1, 6000, &rtp(42, seq, u32::from(seq) * 8000, 0, &[1]));
            let mut body = interface.to_le_bytes().to_vec();
            body.extend(0_u32.to_le_bytes());
            body.extend((u32::from(seq) * 1_000_000_000).to_le_bytes());
            body.extend((data.len() as u32).to_le_bytes());
            body.extend((data.len() as u32).to_le_bytes());
            body.extend(data);
            bytes.extend(block(6, body));
        }
    }
    let path = fixture.directory.join("input.pcapng");
    std::fs::write(&path, bytes).unwrap();
    let result = analyze_capture_file(&path, &fixture.directory.join("reports")).unwrap();
    assert_eq!(result.streams.len(), 2);
    assert_eq!(result.summary.duration_ms, 1000);
    assert_ne!(
        result.streams[0].identity.interface_id,
        result.streams[1].identity.interface_id
    );
}
