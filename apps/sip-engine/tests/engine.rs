use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, UdpSocket};
use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
fn call_scenario_answers_sdp_and_sends_real_pcmu_rtp_rtcp_until_bye() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_streams-sip-engine"));
    command
        .args(["--bind", "127.0.0.1:0", "--scenario", "call"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = command.spawn().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    let listening: serde_json::Value = serde_json::from_str(&line).unwrap();
    let address = listening["address"].as_str().unwrap();
    let signal = UdpSocket::bind("127.0.0.1:0").unwrap();
    signal
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (audio, rtcp) = loop {
        let audio = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = audio.local_addr().unwrap().port();
        if port.is_multiple_of(2)
            && let Some(rtcp_port) = port.checked_add(1)
            && let Ok(rtcp) = UdpSocket::bind(("127.0.0.1", rtcp_port))
        {
            break (audio, rtcp);
        }
    };
    audio
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    rtcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Test\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=recvonly\r\nm=video 50000 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n",
        audio.local_addr().unwrap().port()
    );
    let invite = format!(
        "INVITE sip:b@host SIP/2.0\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-call\r\nFrom: <sip:a@host>;tag=caller\r\nTo: <sip:b@host>\r\nCall-ID: call-test\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{offer}",
        offer.len()
    );
    signal.send_to(invite.as_bytes(), address).unwrap();
    let mut response = [0_u8; 4096];
    let (size, _) = signal.recv_from(&mut response).unwrap();
    let answer = streamscope_sip::parse_datagram(&response[..size]).unwrap();
    assert!(matches!(
        answer.start,
        streamscope_sip::StartLine::Response { status: 200, .. }
    ));
    let sdp = streamscope_sdp::parse_sdp(std::str::from_utf8(&answer.body).unwrap()).unwrap();
    assert_eq!(sdp.media.len(), 2);
    assert_eq!(sdp.media[0].payload_types, [0]);
    assert_ne!(sdp.media[0].port, 0);
    assert_eq!(sdp.media[1].port, 0);
    let tag = streamscope_sip::parameter(answer.header("To").unwrap(), "tag").unwrap();
    audio
        .set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    assert!(
        audio.recv_from(&mut response).is_err(),
        "ACK 前不得发送 RTP"
    );
    let (retry_size, _) = signal.recv_from(&mut response).unwrap();
    let retry = streamscope_sip::parse_datagram(&response[..retry_size]).unwrap();
    assert_eq!(
        retry.body, answer.body,
        "未收到 ACK 时应重发同一 SDP answer"
    );
    audio
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let ack = format!(
        "ACK sip:b@host SIP/2.0\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-ack\r\nFrom: <sip:a@host>;tag=caller\r\nTo: <sip:b@host>;tag={tag}\r\nCall-ID: call-test\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n"
    );
    signal.send_to(ack.as_bytes(), address).unwrap();
    let (size, sender) = audio.recv_from(&mut response).unwrap();
    let packet = streamscope_rtp::parse_rtp(&response[..size]).unwrap();
    assert_eq!(sender.port(), sdp.media[0].port);
    assert_eq!(packet.payload_type, 0);
    assert_eq!(packet.payload.len(), 160);
    let ssrc = packet.ssrc;
    let (size, sender) = rtcp.recv_from(&mut response).unwrap();
    assert_eq!(sender.port(), sdp.media[0].port + 1);
    assert!(
        matches!(streamscope_rtp::parse_rtcp_compound(&response[..size]).unwrap()[0], streamscope_rtp::RtcpPacket::SenderReport { ssrc: report_ssrc, .. } if report_ssrc == ssrc)
    );
    let bye = format!(
        "BYE sip:b@host SIP/2.0\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-bye\r\nFrom: <sip:a@host>;tag=caller\r\nTo: <sip:b@host>;tag={tag}\r\nCall-ID: call-test\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"
    );
    signal.send_to(bye.as_bytes(), address).unwrap();
    let (size, _) = signal.recv_from(&mut response).unwrap();
    let bye_response = streamscope_sip::parse_datagram(&response[..size]).unwrap();
    assert!(matches!(
        bye_response.start,
        streamscope_sip::StartLine::Response { status: 200, .. }
    ));
    assert_eq!(bye_response.header("CSeq"), Some("2 BYE"));
    let (size, _) = rtcp.recv_from(&mut response).unwrap();
    assert!(
        streamscope_rtp::parse_rtcp_compound(&response[..size])
            .unwrap()
            .iter()
            .any(|packet| matches!(packet, streamscope_rtp::RtcpPacket::Goodbye { .. }))
    );
    child.stdin.take().unwrap().write_all(b"stop\n").unwrap();
    assert!(child.wait().unwrap().success());
}

#[test]
fn isolated_engine_answers_options_and_releases_port() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_streams-sip-engine"));
    command
        .arg("--bind")
        .arg("127.0.0.1:0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = command.spawn().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    let status: serde_json::Value = serde_json::from_str(&line).unwrap();
    let address = status["address"].as_str().unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket.send_to(b"OPTIONS sip:b@host SIP/2.0\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-test\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>\r\nCall-ID: test-1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n", address).unwrap();
    let mut response = [0_u8; 2048];
    let (count, _) = socket.recv_from(&mut response).unwrap();
    let text = std::str::from_utf8(&response[..count]).unwrap();
    assert!(text.starts_with("SIP/2.0 200 OK\r\n"));
    assert!(text.contains("Call-ID: test-1\r\n"));
    let probe = Command::new(env!("CARGO_BIN_EXE_streams-sip-engine"))
        .args(["--probe", address, "--transport", "udp"])
        .output()
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&probe.stdout).unwrap();
    assert_eq!(result["status"], 200);
    child.stdin.take().unwrap().write_all(b"stop\n").unwrap();
    assert!(child.wait().unwrap().success());
    let rebound = UdpSocket::bind(address);
    assert!(rebound.is_ok(), "停止后应释放监听端口");
}

#[test]
fn busy_scenario_answers_invite_without_creating_a_dialog() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_streams-sip-engine"));
    command
        .args(["--bind", "127.0.0.1:0", "--scenario", "busy"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = command.spawn().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    let status: serde_json::Value = serde_json::from_str(&line).unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket.send_to(b"INVITE sip:b@host SIP/2.0\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-busy\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>\r\nCall-ID: busy-test\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n", status["address"].as_str().unwrap()).unwrap();
    let mut response = [0_u8; 2048];
    let (count, _) = socket.recv_from(&mut response).unwrap();
    let text = std::str::from_utf8(&response[..count]).unwrap();
    assert!(text.starts_with("SIP/2.0 486 Busy Here\r\n"));
    assert!(text.contains("To: <sip:b@host>;tag=ss-"));
    let reply = streamscope_sip::parse_datagram(&response[..count]).unwrap();
    let tag = reply.header("To").unwrap().split(";tag=").nth(1).unwrap();
    let cancel = b"CANCEL sip:b@host SIP/2.0\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-busy\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>\r\nCall-ID: busy-test\r\nCSeq: 1 CANCEL\r\nContent-Length: 0\r\n\r\n";
    socket
        .send_to(cancel, status["address"].as_str().unwrap())
        .unwrap();
    let (count, _) = socket.recv_from(&mut response).unwrap();
    let text = std::str::from_utf8(&response[..count]).unwrap();
    assert!(text.starts_with("SIP/2.0 200 OK\r\n"));
    assert!(text.contains(&format!(";tag={tag}\r\n")));
    let ack = format!(
        "ACK sip:b@host SIP/2.0\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-busy\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>;tag={tag}\r\nCall-ID: busy-test\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n"
    );
    socket
        .send_to(ack.as_bytes(), status["address"].as_str().unwrap())
        .unwrap();
    child.stdin.take().unwrap().write_all(b"stop\n").unwrap();
    assert!(child.wait().unwrap().success());
}

#[test]
fn tcp_engine_reassembles_split_requests_and_answers_two_messages() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_streams-sip-engine"));
    command
        .args(["--bind", "127.0.0.1:0", "--transport", "tcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = command.spawn().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    let status: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(status["transport"], "tcp");
    let mut stream = TcpStream::connect(status["address"].as_str().unwrap()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let request = b"OPTIONS sip:b@host SIP/2.0\r\nVia: SIP/2.0/TCP a;branch=z9hG4bK-tcp\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>\r\nCall-ID: tcp-test\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
    stream.write_all(&request[..24]).unwrap();
    stream.write_all(&request[24..]).unwrap();
    let mut response = [0_u8; 2048];
    use std::io::Read;
    let count = stream.read(&mut response).unwrap();
    assert!(
        std::str::from_utf8(&response[..count])
            .unwrap()
            .starts_with("SIP/2.0 200 OK\r\n")
    );
    let probe = Command::new(env!("CARGO_BIN_EXE_streams-sip-engine"))
        .args([
            "--probe",
            status["address"].as_str().unwrap(),
            "--transport",
            "tcp",
        ])
        .output()
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&probe.stdout).unwrap();
    assert_eq!(result["status"], 200);
    stream.write_all(request).unwrap();
    let count = stream.read(&mut response).unwrap();
    assert!(
        std::str::from_utf8(&response[..count])
            .unwrap()
            .starts_with("SIP/2.0 200 OK\r\n")
    );
    child.stdin.take().unwrap().write_all(b"stop\n").unwrap();
    assert!(child.wait().unwrap().success());
}

#[test]
fn isolated_registrar_challenges_register_without_exposing_password() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_streams-sip-engine"));
    command
        .args(["--bind", "127.0.0.1:0", "--scenario", "registrar"])
        .env("STREAMSCOPE_SIP_TEST_USERNAME", "alice")
        .env("STREAMSCOPE_SIP_TEST_PASSWORD", "test-secret")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = command.spawn().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    let status: serde_json::Value = serde_json::from_str(&line).unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket.send_to(b"REGISTER sip:example.test SIP/2.0\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK-r\r\nFrom: <sip:alice@example.test>;tag=a\r\nTo: <sip:alice@example.test>\r\nCall-ID: register-test\r\nCSeq: 1 REGISTER\r\nContact: <sip:alice@127.0.0.1>\r\nContent-Length: 0\r\n\r\n", status["address"].as_str().unwrap()).unwrap();
    let mut response = [0_u8; 2048];
    let (count, _) = socket.recv_from(&mut response).unwrap();
    let text = std::str::from_utf8(&response[..count]).unwrap();
    assert!(text.starts_with("SIP/2.0 401 Unauthorized\r\n"));
    assert!(text.contains("algorithm=SHA-256"));
    output.read_line(&mut line).unwrap();
    assert!(!line.contains("test-secret"));
    child.stdin.take().unwrap().write_all(b"stop\n").unwrap();
    assert!(child.wait().unwrap().success());
}

#[test]
fn tls_engine_answers_options_after_verified_handshake() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let folder = std::env::temp_dir().join(format!(
        "streamscope-sip-tls-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&folder).unwrap();
    let cert_path = folder.join("cert.pem");
    let key_path = folder.join("key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_streams-sip-engine"));
    command
        .arg("--bind")
        .arg("127.0.0.1:0")
        .arg("--transport")
        .arg("tls")
        .arg("--tls-cert")
        .arg(&cert_path)
        .arg("--tls-key")
        .arg(&key_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = command.spawn().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    let status: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(status["transport"], "tls");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connection =
        rustls::ClientConnection::new(std::sync::Arc::new(config), "localhost".try_into().unwrap())
            .unwrap();
    let socket = TcpStream::connect(status["address"].as_str().unwrap()).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut stream = rustls::StreamOwned::new(connection, socket);
    stream.write_all(b"OPTIONS sip:b@host SIP/2.0\r\nVia: SIP/2.0/TLS a;branch=z9hG4bK-tls\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>\r\nCall-ID: tls-test\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n").unwrap();
    let mut response = [0_u8; 2048];
    use std::io::Read;
    let count = stream.read(&mut response).unwrap();
    assert!(
        std::str::from_utf8(&response[..count])
            .unwrap()
            .starts_with("SIP/2.0 200 OK\r\n")
    );
    let probe = Command::new(env!("CARGO_BIN_EXE_streams-sip-engine"))
        .arg("--probe")
        .arg(status["address"].as_str().unwrap())
        .args(["--transport", "tls", "--server-name", "localhost"])
        .arg("--ca-cert")
        .arg(&cert_path)
        .output()
        .unwrap();
    assert!(
        probe.status.success(),
        "TLS probe stderr: {}",
        String::from_utf8_lossy(&probe.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&probe.stdout).unwrap();
    assert_eq!(result["status"], 200, "{result}");
    child.stdin.take().unwrap().write_all(b"stop\n").unwrap();
    assert!(child.wait().unwrap().success());
    std::fs::remove_file(cert_path).unwrap();
    std::fs::remove_file(key_path).unwrap();
    std::fs::remove_dir(folder).unwrap();
}
