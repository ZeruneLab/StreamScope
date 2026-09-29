use std::io::Write;
use std::net::UdpSocket;
use std::process::Command;
use std::time::Duration;
use streamscope_sip::{
    ReplayOverride, apply_replay_overrides, build_response_with_body, compile_replay_plan,
    parse_datagram,
};

fn pcap(messages: &[(&[u8], bool)]) -> Vec<u8> {
    let mut bytes = vec![
        0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0,
    ];
    for (index, (payload, from_caller)) in messages.iter().enumerate() {
        let mut frame = vec![0_u8; 14 + 20 + 8];
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&((20 + 8 + payload.len()) as u16).to_be_bytes());
        frame[23] = 17;
        frame[26..30].copy_from_slice(if *from_caller {
            &[10, 0, 0, 1]
        } else {
            &[10, 0, 0, 2]
        });
        frame[30..34].copy_from_slice(if *from_caller {
            &[10, 0, 0, 2]
        } else {
            &[10, 0, 0, 1]
        });
        frame[34..36].copy_from_slice(&5060_u16.to_be_bytes());
        frame[36..38].copy_from_slice(&5060_u16.to_be_bytes());
        frame[38..40].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&((index as u32) * 1000).to_le_bytes());
        bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&frame);
    }
    bytes
}

fn capture_file(messages: &[(&[u8], bool)]) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "streamscope-replay-{}-{}.pcap",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::File::create(&path)
        .unwrap()
        .write_all(&pcap(messages))
        .unwrap();
    path
}

#[test]
fn extracted_options_replays_with_fresh_identifiers_and_checks_response() {
    let request = b"OPTIONS sip:device@old.example SIP/2.0\r\nVia: SIP/2.0/UDP old;branch=z9hG4bK-old\r\nFrom: <sip:caller@old.example>;tag=old-tag\r\nTo: <sip:device@old.example>\r\nCall-ID: old-call\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
    let response = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP old;branch=z9hG4bK-old\r\nFrom: <sip:caller@old.example>;tag=old-tag\r\nTo: <sip:device@old.example>;tag=old-device\r\nCall-ID: old-call\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
    let path = capture_file(&[(request, true), (response, false)]);
    let mut plan =
        compile_replay_plan(&path, "old-call", "10.0.0.1:5060".parse().unwrap()).unwrap();
    assert!(plan.executable, "{:?}", plan.warnings);
    assert_eq!(plan.steps.len(), 1);
    let packet_number = plan.steps[0].packet_number;
    apply_replay_overrides(
        &mut plan,
        &[ReplayOverride {
            packet_number,
            delay_ms: 2,
            expected_status: Some(200),
        }],
    )
    .unwrap();
    let device = UdpSocket::bind("127.0.0.1:0").unwrap();
    device
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let target = device.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let mut data = [0_u8; 4096];
        let (length, peer) = device.recv_from(&mut data).unwrap();
        let received = parse_datagram(&data[..length]).unwrap();
        assert_eq!(received.method(), Some("OPTIONS"));
        assert_ne!(received.header("Call-ID"), Some("old-call"));
        assert!(!String::from_utf8_lossy(&data[..length]).contains("old.example"));
        let reply =
            build_response_with_body(&received, 200, "OK", "OPTIONS", &[], None, &[]).unwrap();
        device.send_to(&reply, peer).unwrap();
    });
    let output = Command::new(env!("CARGO_BIN_EXE_streams-sip-engine"))
        .arg("--replay-capture")
        .arg(&path)
        .args([
            "--replay-call-id",
            "old-call",
            "--replay-source",
            "10.0.0.1:5060",
            "--replay-target",
            &target.to_string(),
        ])
        .arg("--replay-overrides")
        .arg(
            serde_json::to_string(&[ReplayOverride {
                packet_number,
                delay_ms: 2,
                expected_status: Some(200),
            }])
            .unwrap(),
        )
        .output()
        .unwrap();
    worker.join().unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["success"], true, "{result}");
    assert_eq!(result["steps"][0]["actual_status"], 200);
}

#[test]
fn extracted_invite_uses_inactive_sdp_then_ack_and_bye() {
    let offer = "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=Old\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n";
    let invite = format!(
        "INVITE sip:device@old.example SIP/2.0\r\nVia: SIP/2.0/UDP old;branch=z9hG4bK-i\r\nFrom: <sip:caller@old.example>;tag=old\r\nTo: <sip:device@old.example>\r\nCall-ID: old-call\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{offer}",
        offer.len()
    );
    let answer = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP old;branch=z9hG4bK-i\r\nFrom: <sip:caller@old.example>;tag=old\r\nTo: <sip:device@old.example>;tag=old-device\r\nCall-ID: old-call\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n";
    let ack = b"ACK sip:device@old.example SIP/2.0\r\nVia: SIP/2.0/UDP old;branch=z9hG4bK-a\r\nFrom: <sip:caller@old.example>;tag=old\r\nTo: <sip:device@old.example>;tag=old-device\r\nCall-ID: old-call\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n";
    let bye = b"BYE sip:device@old.example SIP/2.0\r\nVia: SIP/2.0/UDP old;branch=z9hG4bK-b\r\nFrom: <sip:caller@old.example>;tag=old\r\nTo: <sip:device@old.example>;tag=old-device\r\nCall-ID: old-call\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n";
    let bye_ok = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP old;branch=z9hG4bK-b\r\nFrom: <sip:caller@old.example>;tag=old\r\nTo: <sip:device@old.example>;tag=old-device\r\nCall-ID: old-call\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n";
    let path = capture_file(&[
        (invite.as_bytes(), true),
        (answer, false),
        (ack, true),
        (bye, true),
        (bye_ok, false),
    ]);
    let mut plan =
        compile_replay_plan(&path, "old-call", "10.0.0.1:5060".parse().unwrap()).unwrap();
    assert!(plan.executable, "{:?}", plan.warnings);
    let mut invalid_edits = plan
        .steps
        .iter()
        .map(|step| ReplayOverride {
            packet_number: step.packet_number,
            delay_ms: step.delay_ms,
            expected_status: step.expected_status,
        })
        .collect::<Vec<_>>();
    invalid_edits[0].expected_status = Some(486);
    assert!(
        apply_replay_overrides(&mut plan, &invalid_edits).is_err(),
        "BYE 后续步骤要求成功 INVITE"
    );
    let device = UdpSocket::bind("127.0.0.1:0").unwrap();
    device
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let target = device.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let mut data = [0_u8; 4096];
        let (length, peer) = device.recv_from(&mut data).unwrap();
        let invite = parse_datagram(&data[..length]).unwrap();
        assert_eq!(invite.method(), Some("INVITE"));
        let body = std::str::from_utf8(&invite.body).unwrap();
        assert!(body.contains("a=inactive\r\n"));
        assert!(!body.contains("10.0.0.1"));
        let reply = build_response_with_body(&invite, 200, "OK", "INVITE", &[], None, &[]).unwrap();
        let response_tag = streamscope_sip::parameter(
            parse_datagram(&reply).unwrap().header("To").unwrap(),
            "tag",
        )
        .unwrap();
        device.send_to(&reply, peer).unwrap();
        let (length, _) = device.recv_from(&mut data).unwrap();
        let ack = parse_datagram(&data[..length]).unwrap();
        assert_eq!(ack.method(), Some("ACK"));
        assert!(
            ack.header("To")
                .unwrap()
                .contains(&format!("tag={response_tag}"))
        );
        let (length, _) = device.recv_from(&mut data).unwrap();
        let bye = parse_datagram(&data[..length]).unwrap();
        assert_eq!(bye.method(), Some("BYE"));
        let reply = build_response_with_body(&bye, 200, "OK", "BYE", &[], None, &[]).unwrap();
        device.send_to(&reply, peer).unwrap();
    });
    let output = Command::new(env!("CARGO_BIN_EXE_streams-sip-engine"))
        .arg("--replay-capture")
        .arg(&path)
        .args([
            "--replay-call-id",
            "old-call",
            "--replay-source",
            "10.0.0.1:5060",
            "--replay-target",
            &target.to_string(),
        ])
        .output()
        .unwrap();
    worker.join().unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["success"], true, "{result}");
    assert_eq!(result["steps"].as_array().unwrap().len(), 3);
}

#[test]
fn captured_retransmission_is_one_step_and_captured_credentials_block_execution() {
    let request = b"REGISTER sip:old.example SIP/2.0\r\nVia: SIP/2.0/UDP old;branch=z9hG4bK-r1\r\nFrom: <sip:alice@old.example>;tag=a\r\nTo: <sip:alice@old.example>\r\nCall-ID: register-call\r\nCSeq: 1 REGISTER\r\nContent-Length: 0\r\n\r\n";
    let challenge = b"SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP old;branch=z9hG4bK-r1\r\nFrom: <sip:alice@old.example>;tag=a\r\nTo: <sip:alice@old.example>;tag=b\r\nCall-ID: register-call\r\nCSeq: 1 REGISTER\r\nContent-Length: 0\r\n\r\n";
    let authorized = b"REGISTER sip:old.example SIP/2.0\r\nVia: SIP/2.0/UDP old;branch=z9hG4bK-r2\r\nFrom: <sip:alice@old.example>;tag=a\r\nTo: <sip:alice@old.example>\r\nCall-ID: register-call\r\nCSeq: 2 REGISTER\r\nAuthorization: Digest username=\"alice\",response=\"captured-secret\"\r\nContent-Length: 0\r\n\r\n";
    let path = capture_file(&[
        (request, true),
        (request, true),
        (challenge, false),
        (authorized, true),
    ]);
    let plan =
        compile_replay_plan(&path, "register-call", "10.0.0.1:5060".parse().unwrap()).unwrap();
    std::fs::remove_file(path).unwrap();
    assert_eq!(
        plan.steps.len(),
        1,
        "UDP retransmission must not become another action"
    );
    assert_eq!(plan.steps[0].expected_status, Some(401));
    assert!(!plan.executable);
    assert!(
        plan.warnings
            .iter()
            .any(|warning| warning.contains("认证头"))
    );
    assert!(
        !serde_json::to_string(&plan)
            .unwrap()
            .contains("captured-secret")
    );
}

#[test]
fn status_mismatch_returns_step_evidence_without_sending_followup() {
    let request = b"OPTIONS sip:old.example SIP/2.0\r\nVia: SIP/2.0/UDP old;branch=z9hG4bK-x\r\nFrom: <sip:a@old.example>;tag=a\r\nTo: <sip:b@old.example>\r\nCall-ID: mismatch-call\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
    let expected = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP old;branch=z9hG4bK-x\r\nFrom: <sip:a@old.example>;tag=a\r\nTo: <sip:b@old.example>;tag=b\r\nCall-ID: mismatch-call\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
    let path = capture_file(&[(request, true), (expected, false)]);
    let device = UdpSocket::bind("127.0.0.1:0").unwrap();
    device
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let target = device.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let mut bytes = [0_u8; 4096];
        let (size, peer) = device.recv_from(&mut bytes).unwrap();
        let received = parse_datagram(&bytes[..size]).unwrap();
        let response =
            build_response_with_body(&received, 486, "Busy Here", "OPTIONS", &[], None, &[])
                .unwrap();
        device.send_to(&response, peer).unwrap();
    });
    let output = Command::new(env!("CARGO_BIN_EXE_streams-sip-engine"))
        .arg("--replay-capture")
        .arg(&path)
        .args([
            "--replay-call-id",
            "mismatch-call",
            "--replay-source",
            "10.0.0.1:5060",
            "--replay-target",
            &target.to_string(),
        ])
        .output()
        .unwrap();
    worker.join().unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], false);
    assert_eq!(report["steps"][0]["expected_status"], 200);
    assert_eq!(report["steps"][0]["actual_status"], 486);
    assert_eq!(report["steps"][0]["outcome"], "status_mismatch");
}
