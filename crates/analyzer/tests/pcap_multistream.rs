use std::path::{Path, PathBuf};
use std::process::Command;
use streamscope_analyzer::{PcapFileOptions, analyze_pcap_file};
use streamscope_core::AnalysisResult;

fn directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "streamscope-integration-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}
fn udp(server: u8, sequence: u16, timestamp: u32, pt: u8, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 54];
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
    bytes[23] = 17;
    bytes[26..30].copy_from_slice(&[192, 0, 2, server]);
    bytes[30..34].copy_from_slice(&[198, 51, 100, 1]);
    bytes[34..36].copy_from_slice(&5004_u16.to_be_bytes());
    bytes[36..38].copy_from_slice(&6000_u16.to_be_bytes());
    bytes[38..40].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    bytes[42] = 0x80;
    bytes[43] = pt | if marker { 128 } else { 0 };
    bytes[44..46].copy_from_slice(&sequence.to_be_bytes());
    bytes[46..50].copy_from_slice(&timestamp.to_be_bytes());
    bytes[50..54].copy_from_slice(&42_u32.to_be_bytes());
    bytes.extend(payload);
    bytes
}
fn write_pcap(path: &Path, packets: &[(u64, Vec<u8>)]) {
    use std::io::Write;
    let mut output = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    output
        .write_all(&[0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        .unwrap();
    output.write_all(&65535_u32.to_le_bytes()).unwrap();
    output.write_all(&1_u32.to_le_bytes()).unwrap();
    for (micros, bytes) in packets {
        output
            .write_all(&((micros / 1_000_000) as u32).to_le_bytes())
            .unwrap();
        output
            .write_all(&((micros % 1_000_000) as u32).to_le_bytes())
            .unwrap();
        output
            .write_all(&(bytes.len() as u32).to_le_bytes())
            .unwrap();
        output
            .write_all(&(bytes.len() as u32).to_le_bytes())
            .unwrap();
        output.write_all(bytes).unwrap();
    }
}
fn options(path: &Path, root: &Path, ids: &[&str]) -> PcapFileOptions {
    PcapFileOptions {
        input: path.into(),
        output_root: root.into(),
        process_timeout_seconds: 30,
        stream_ids: ids.iter().map(|id| (*id).into()).collect(),
    }
}

#[test]
fn scan_has_independent_reports_no_decoder_and_old_json_remains_readable() {
    let root = directory();
    let path = root.join("100-streams.pcap");
    let mut packets = Vec::new();
    for seq in 1..=10_u16 {
        for server in 1..=100 {
            packets.push((
                u64::from(seq) * 500000,
                udp(server, seq, u32::from(seq) * 4000, 0, true, &[1, 2, 3]),
            ));
        }
    }
    write_pcap(&path, &packets);
    let run = analyze_pcap_file(options(&path, &root, &[])).unwrap();
    assert_eq!(run.result.streams.len(), 100);
    assert!(run.result.protocol.is_none());
    assert!(run.result.request.transport.is_none());
    for stream in &run.result.streams {
        let id = &stream.capture_stream.as_ref().unwrap().id;
        assert!(stream.decode.is_none() && stream.tools.is_empty());
        assert_eq!(stream.protocol.as_ref().unwrap().rtp.packet_count, 10);
        let child: AnalysisResult = serde_json::from_slice(
            &std::fs::read(
                Path::new(&run.report_directory)
                    .join("streams")
                    .join(id)
                    .join("result.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(child.capture_stream.as_ref().unwrap().id, *id);
    }
    let mut legacy = serde_json::to_value(&run.result.streams[0]).unwrap();
    for key in ["streams", "capture_stream", "capture_summary"] {
        legacy.as_object_mut().unwrap().remove(key);
    }
    assert!(serde_json::from_value::<AnalysisResult>(legacy).is_ok());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires ffmpeg with libx264; retains a QA capture and reports under target"]
fn real_h264_streams_decode_independently_and_selective_decode_is_respected() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "multistream-qa-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ));
    std::fs::create_dir_all(&root).unwrap();
    let mut nal_sets = Vec::new();
    for (name, size) in [("a", "320x240"), ("b", "640x360")] {
        let path = root.join(format!("{name}.h264"));
        let mut command = Command::new("ffmpeg");
        command
            .args([
                "-nostdin",
                "-v",
                "error",
                "-f",
                "lavfi",
                "-i",
                &format!("testsrc2=size={size}:rate=25"),
                "-frames:v",
                "100",
                "-c:v",
                "libx264",
                "-threads",
                "1",
                "-preset",
                "ultrafast",
                "-g",
                "25",
                "-bf",
                "0",
                "-f",
                "h264",
            ])
            .arg(&path);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        assert!(command.status().unwrap().success());
        nal_sets.push(streamscope_h264::split_annex_b(
            &std::fs::read(path).unwrap(),
        ));
    }
    let mut packets = Vec::new();
    let mut normalized = Vec::new();
    for server in 1..=10_u8 {
        let nalus = &nal_sets[(server as usize - 1) % 2];
        let mut sequence = 1_u16;
        let mut timestamp = 90_000;
        let mut frame = 0_u64;
        let mut expected = Vec::new();
        for nalu in nalus {
            expected.extend([0, 0, 0, 1]);
            expected.extend(&nalu.data);
            let vcl = matches!(nalu.data[0] & 31, 1 | 5);
            let payloads: Vec<Vec<u8>> = if nalu.data.len() <= 1200 {
                vec![nalu.data.clone()]
            } else {
                let chunks: Vec<_> = nalu.data[1..].chunks(1198).collect();
                chunks
                    .iter()
                    .enumerate()
                    .map(|(index, data)| {
                        let mut payload = vec![
                            (nalu.data[0] & 0xe0) | 28,
                            (nalu.data[0] & 31)
                                | if index == 0 { 0x80 } else { 0 }
                                | if index + 1 == chunks.len() { 0x40 } else { 0 },
                        ];
                        payload.extend(*data);
                        payload
                    })
                    .collect()
            };
            for (index, payload) in payloads.iter().enumerate() {
                packets.push((
                    frame * 40_000 + index as u64,
                    udp(
                        server,
                        sequence,
                        timestamp,
                        96,
                        vcl && index + 1 == payloads.len(),
                        payload,
                    ),
                ));
                sequence = sequence.wrapping_add(1);
            }
            if vcl {
                timestamp += 3600;
                frame += 1;
            }
        }
        normalized.push(expected);
    }
    packets.sort_by_key(|(micros, _)| *micros);
    let path = root.join("10-video-streams.pcap");
    write_pcap(&path, &packets);
    let scan = analyze_pcap_file(options(&path, &root, &[])).unwrap();
    assert_eq!(scan.result.streams.len(), 10);
    for (index, stream) in scan.result.streams.iter().enumerate() {
        assert!(stream.decode.is_none());
        assert_eq!(stream.protocol.as_ref().unwrap().rtp.lost_packets, 0);
        assert_eq!(stream.h264.as_ref().unwrap().frame_count, 100);
        let sample = Path::new(&scan.report_directory)
            .join("streams")
            .join(&stream.capture_stream.as_ref().unwrap().id)
            .join("sample.h264");
        assert_eq!(std::fs::read(sample).unwrap(), normalized[index]);
    }
    let deep = analyze_pcap_file(options(&path, &root, &["stream-0001", "stream-0002"])).unwrap();
    for (index, stream) in deep.result.streams.iter().enumerate() {
        if index < 2 {
            assert!(stream.decode.as_ref().unwrap().success);
            assert!(stream.decode.as_ref().unwrap().issues.is_empty());
            assert_eq!(stream.decode.as_ref().unwrap().decoded_frames, Some(100));
            assert!(
                stream
                    .preview_video
                    .as_deref()
                    .is_some_and(|path| Path::new(path).is_file())
            );
            assert_eq!(
                stream.stream.as_ref().unwrap().width,
                Some(if index == 0 { 320 } else { 640 })
            );
        } else {
            assert!(stream.decode.is_none());
            assert!(stream.preview_video.is_none());
        }
    }
    let all = analyze_pcap_file(options(&path, &root, &["*"])).unwrap();
    assert!(all.result.streams.iter().all(|stream| {
        stream
            .decode
            .as_ref()
            .is_some_and(|decode| decode.success && decode.decoded_frames == Some(100))
    }));
    assert!(all.result.streams.iter().all(|stream| {
        stream
            .preview_video
            .as_deref()
            .is_some_and(|path| Path::new(path).is_file())
    }));
    println!("QA capture: {}", path.canonicalize().unwrap().display());
    println!("QA report: {}", all.reports.html);
}
