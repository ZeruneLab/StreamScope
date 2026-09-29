mod call;
mod replay;

use clap::{Parser, ValueEnum};
use std::io::{self, BufRead, Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use std::time::Instant;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "streams-sip-engine", about = "隔离运行的 SIP 测试引擎")]
struct Args {
    /// 默认只监听本机；要供局域网设备访问时显式指定地址。
    #[arg(long, default_value = "127.0.0.1:0")]
    bind: SocketAddr,
    #[arg(long, value_enum, default_value_t = Scenario::Options)]
    scenario: Scenario,
    #[arg(long, value_enum, default_value_t = Transport::Udp)]
    transport: Transport,
    #[arg(long, value_enum, default_value_t = Digest::Sha256)]
    digest: Digest,
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    #[arg(long)]
    tls_key: Option<PathBuf>,
    /// Perform a one-shot OPTIONS diagnostic instead of listening.
    #[arg(long)]
    probe: Option<SocketAddr>,
    #[arg(long)]
    server_name: Option<String>,
    #[arg(long)]
    ca_cert: Option<PathBuf>,
    /// Analyze one captured UDP SIP call and actively replay its safe signaling steps.
    #[arg(long)]
    replay_capture: Option<PathBuf>,
    #[arg(long)]
    replay_call_id: Option<String>,
    #[arg(long)]
    replay_source: Option<SocketAddr>,
    #[arg(long)]
    replay_target: Option<SocketAddr>,
    #[arg(long)]
    replay_overrides: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Scenario {
    Options,
    Busy,
    Registrar,
    Call,
}

#[derive(Clone, Copy, ValueEnum)]
enum Transport {
    Udp,
    Tcp,
    Tls,
}

#[derive(Clone, Copy, ValueEnum)]
enum Digest {
    Sha256,
    Md5,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let args = Args::parse();
    if let Some(target) = args.probe {
        let result = probe_options(
            target,
            args.transport,
            args.server_name.as_deref(),
            args.ca_cert.as_deref(),
        );
        println!("{}", serde_json::to_string(&result)?);
        return Ok(());
    }
    if let Some(path) = args.replay_capture.as_deref() {
        let call_id = args
            .replay_call_id
            .as_deref()
            .ok_or("缺少 --replay-call-id")?;
        let source = args.replay_source.ok_or("缺少 --replay-source")?;
        let target = args.replay_target.ok_or("缺少 --replay-target")?;
        let mut plan = streamscope_sip::compile_replay_plan(path, call_id, source)?;
        if let Some(overrides) = args.replay_overrides.as_deref() {
            let overrides: Vec<streamscope_sip::ReplayOverride> = serde_json::from_str(overrides)?;
            streamscope_sip::apply_replay_overrides(&mut plan, &overrides)?;
        }
        let result = replay::execute(&plan, target)?;
        println!("{}", serde_json::to_string(&result)?);
        return Ok(());
    }
    if matches!(args.scenario, Scenario::Call) && !matches!(args.transport, Transport::Udp) {
        return Err("PCMU 测试呼叫当前只支持 UDP 信令".into());
    }
    let registrar = if matches!(args.scenario, Scenario::Registrar) {
        let username = std::env::var("STREAMSCOPE_SIP_TEST_USERNAME")?;
        let password = std::env::var("STREAMSCOPE_SIP_TEST_PASSWORD")?;
        if username.is_empty() || password.is_empty() {
            return Err("Registrar 测试账号与密码不能为空".into());
        }
        let algorithm = match args.digest {
            Digest::Sha256 => streamscope_sip::DigestAlgorithm::Sha256,
            Digest::Md5 => streamscope_sip::DigestAlgorithm::Md5,
        };
        Some(streamscope_sip::SipRegistrar::new(
            username, password, algorithm,
        ))
    } else {
        None
    };
    let stopped = Arc::new(AtomicBool::new(false));
    let stop = stopped.clone();
    std::thread::spawn(move || {
        let mut input = String::new();
        let mut stdin = io::stdin().lock();
        loop {
            input.clear();
            if stdin.read_line(&mut input).unwrap_or(0) == 0 || input.trim() == "stop" {
                break;
            }
        }
        stop.store(true, Ordering::Relaxed);
    });
    let registrar = Arc::new(Mutex::new(registrar));
    let busy = Arc::new(Mutex::new(streamscope_sip::SipBusy::default()));
    let call = Arc::new(Mutex::new(call::CallEngine::default()));
    match args.transport {
        Transport::Udp => {
            let socket = UdpSocket::bind(args.bind)?;
            socket.set_read_timeout(Some(Duration::from_millis(
                if matches!(args.scenario, Scenario::Call) {
                    20
                } else {
                    200
                },
            )))?;
            listening("udp", socket.local_addr()?, args.scenario);
            let mut buffer = [0_u8; 65_535];
            while !stopped.load(Ordering::Relaxed) {
                match socket.recv_from(&mut buffer) {
                    Ok((size, peer)) => {
                        if let Some(response) = handle(
                            &buffer[..size],
                            peer,
                            args.scenario,
                            &mut registrar.lock().expect("Registrar state poisoned"),
                            &mut busy.lock().expect("Busy state poisoned"),
                            &mut call.lock().expect("Call state poisoned"),
                            socket.local_addr()?.port(),
                        ) {
                            socket.send_to(&response, peer)?;
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(error) => return Err(error.into()),
                }
                if matches!(args.scenario, Scenario::Call) {
                    call.lock().expect("Call state poisoned").tick(&socket)?;
                }
            }
        }
        Transport::Tcp | Transport::Tls => {
            let tls_config = if matches!(args.transport, Transport::Tls) {
                let cert = args.tls_cert.as_deref().ok_or("TLS 需要 --tls-cert")?;
                let key = args.tls_key.as_deref().ok_or("TLS 需要 --tls-key")?;
                Some(load_tls_config(cert, key)?)
            } else {
                None
            };
            let listener = TcpListener::bind(args.bind)?;
            listener.set_nonblocking(true)?;
            listening(
                if tls_config.is_some() { "tls" } else { "tcp" },
                listener.local_addr()?,
                args.scenario,
            );
            let active = Arc::new(AtomicUsize::new(0));
            while !stopped.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, peer)) => {
                        if active.load(Ordering::Relaxed) >= 32 {
                            println!(
                                "{}",
                                serde_json::json!({"event":"connection_rejected","peer":peer.to_string(),"reason":"32 active connections limit"})
                            );
                            continue;
                        }
                        active.fetch_add(1, Ordering::Relaxed);
                        stream.set_read_timeout(Some(Duration::from_millis(200)))?;
                        let config = tls_config.clone();
                        let worker_stop = stopped.clone();
                        let worker_registrar = registrar.clone();
                        let worker_busy = busy.clone();
                        let worker_call = call.clone();
                        let worker_active = active.clone();
                        let scenario = args.scenario;
                        let signaling_port = stream.local_addr()?.port();
                        std::thread::spawn(move || {
                            let result = if let Some(config) = config {
                                match rustls::ServerConnection::new(config) {
                                    Ok(connection) => {
                                        let mut tls = rustls::StreamOwned::new(connection, stream);
                                        handle_stream(
                                            &mut tls,
                                            peer,
                                            scenario,
                                            &worker_stop,
                                            &worker_registrar,
                                            &worker_busy,
                                            &worker_call,
                                            signaling_port,
                                        )
                                    }
                                    Err(error) => Err(io::Error::other(error)),
                                }
                            } else {
                                handle_stream(
                                    &mut stream,
                                    peer,
                                    scenario,
                                    &worker_stop,
                                    &worker_registrar,
                                    &worker_busy,
                                    &worker_call,
                                    signaling_port,
                                )
                            };
                            if let Err(error) = result {
                                println!(
                                    "{}",
                                    serde_json::json!({"event":"connection_error","peer":peer.to_string(),"reason":error.to_string()})
                                );
                            }
                            worker_active.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(50))
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
    println!("{}", serde_json::json!({"event":"stopped"}));
    Ok(())
}

fn listening(transport: &str, address: SocketAddr, scenario: Scenario) {
    println!(
        "{}",
        serde_json::json!({"event":"listening","transport":transport,"address":address.to_string(),
        "scenario":match scenario { Scenario::Options => "OPTIONS", Scenario::Busy => "OPTIONS + INVITE 486", Scenario::Registrar => "OPTIONS + Digest REGISTER", Scenario::Call => "OPTIONS + PCMU test call" }})
    );
}

#[allow(clippy::too_many_arguments)] // Keep the TCP/TLS worker's shared scenario state explicit.
fn handle_stream<S: Read + Write>(
    stream: &mut S,
    peer: SocketAddr,
    scenario: Scenario,
    stopped: &AtomicBool,
    registrar: &Mutex<Option<streamscope_sip::SipRegistrar>>,
    busy: &Mutex<streamscope_sip::SipBusy>,
    call: &Mutex<call::CallEngine>,
    signaling_port: u16,
) -> io::Result<()> {
    let mut data = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        if stopped.load(Ordering::Relaxed) {
            return Ok(());
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(size) => data.extend_from_slice(&chunk[..size]),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
        if data.len() > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SIP TCP 消息超过 1 MiB",
            ));
        }
        loop {
            let length = match streamscope_sip::message_length(&data) {
                Ok(Some(length)) => length,
                Ok(None) => break,
                Err(error) => return Err(io::Error::new(io::ErrorKind::InvalidData, error)),
            };
            let response = handle(
                &data[..length],
                peer,
                scenario,
                &mut registrar.lock().expect("Registrar state poisoned"),
                &mut busy.lock().expect("Busy state poisoned"),
                &mut call.lock().expect("Call state poisoned"),
                signaling_port,
            );
            if let Some(response) = response {
                stream.write_all(&response)?;
            }
            data.drain(..length);
            if data.is_empty() {
                break;
            }
        }
    }
}

fn load_tls_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    let mut certificate = io::BufReader::new(std::fs::File::open(cert_path)?);
    let certificates = rustls_pemfile::certs(&mut certificate).collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        return Err("TLS 证书文件没有证书".into());
    }
    let mut key_file = io::BufReader::new(std::fs::File::open(key_path)?);
    let key = rustls_pemfile::private_key(&mut key_file)?.ok_or("TLS 私钥文件没有可用私钥")?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
    Ok(Arc::new(config))
}

fn probe_options(
    target: SocketAddr,
    transport: Transport,
    server_name: Option<&str>,
    ca_cert: Option<&Path>,
) -> serde_json::Value {
    let start = Instant::now();
    let transport_name = match transport {
        Transport::Udp => "UDP",
        Transport::Tcp => "TCP",
        Transport::Tls => "TLS",
    };
    let result = (|| -> Result<u16, Box<dyn std::error::Error>> {
        let call_id = format!("{}@streamscope.local", Uuid::new_v4());
        let branch = format!("z9hG4bK-{}", Uuid::new_v4().simple());
        let from_tag = Uuid::new_v4().simple().to_string();
        let target_host = if target.is_ipv4() {
            target.ip().to_string()
        } else {
            format!("[{}]", target.ip())
        };
        let request = |local: SocketAddr| {
            let rport = if matches!(transport, Transport::Udp) {
                ";rport"
            } else {
                ""
            };
            format!(
                "OPTIONS sip:{target_host} SIP/2.0\r\nVia: SIP/2.0/{transport_name} {local};branch={branch}{rport}\r\nMax-Forwards: 0\r\nFrom: <sip:probe@streamscope.local>;tag={from_tag}\r\nTo: <sip:{target_host}>\r\nCall-ID: {call_id}\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
            )
        };
        let status = match transport {
            Transport::Udp => {
                let bind = if target.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let socket = UdpSocket::bind(bind)?;
                socket.connect(target)?;
                let request = request(socket.local_addr()?);
                let mut response = [0_u8; 65_535];
                let mut received = None;
                for timeout in [500, 1000, 2000] {
                    let deadline = Instant::now() + Duration::from_millis(timeout);
                    socket.send(request.as_bytes())?;
                    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
                        socket.set_read_timeout(Some(remaining))?;
                        match socket.recv(&mut response) {
                            Ok(size) => {
                                if let Some(status) =
                                    probe_response_status(&response[..size], &call_id, &branch)?
                                {
                                    received = Some(status);
                                    break;
                                }
                            }
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                                ) =>
                            {
                                break;
                            }
                            Err(error) => return Err(error.into()),
                        }
                    }
                    if received.is_some() {
                        break;
                    }
                }
                received.ok_or("3.5 秒内未收到 SIP 响应")?
            }
            Transport::Tcp | Transport::Tls => {
                let socket = std::net::TcpStream::connect_timeout(&target, Duration::from_secs(3))?;
                socket.set_read_timeout(Some(Duration::from_secs(3)))?;
                socket.set_write_timeout(Some(Duration::from_secs(3)))?;
                let request = request(socket.local_addr()?);
                if matches!(transport, Transport::Tls) {
                    let mut roots = rustls::RootCertStore::empty();
                    for certificate in rustls_native_certs::load_native_certs().certs {
                        let _ = roots.add(certificate);
                    }
                    if let Some(path) = ca_cert {
                        let mut file = io::BufReader::new(std::fs::File::open(path)?);
                        for certificate in rustls_pemfile::certs(&mut file) {
                            roots.add(certificate?)?;
                        }
                    }
                    let name = server_name
                        .map(str::to_string)
                        .unwrap_or_else(|| target.ip().to_string());
                    let server_name = rustls::pki_types::ServerName::try_from(name)?;
                    let config = rustls::ClientConfig::builder()
                        .with_root_certificates(roots)
                        .with_no_client_auth();
                    let connection = rustls::ClientConnection::new(Arc::new(config), server_name)?;
                    let mut stream = rustls::StreamOwned::new(connection, socket);
                    stream.write_all(request.as_bytes())?;
                    read_sip_final_response(&mut stream, &call_id, &branch)?
                } else {
                    let mut stream = socket;
                    stream.write_all(request.as_bytes())?;
                    read_sip_final_response(&mut stream, &call_id, &branch)?
                }
            }
        };
        Ok(status)
    })();
    match result {
        Ok(status) => {
            serde_json::json!({"target":target.to_string(),"transport":transport_name,"status":status,"latency_ms":start.elapsed().as_millis(),"error":null})
        }
        Err(error) => {
            serde_json::json!({"target":target.to_string(),"transport":transport_name,"status":null,"latency_ms":start.elapsed().as_millis(),"error":error.to_string()})
        }
    }
}

fn probe_response_status(
    bytes: &[u8],
    call_id: &str,
    branch: &str,
) -> Result<Option<u16>, Box<dyn std::error::Error>> {
    let message = streamscope_sip::parse_datagram(bytes)?;
    let streamscope_sip::StartLine::Response { status, .. } = message.start else {
        return Err("收到的不是 SIP 响应".into());
    };
    let via_branch = message.header("Via").and_then(|via| {
        via.split(';')
            .skip(1)
            .filter_map(|part| part.trim().split_once('='))
            .find(|(name, _)| name.trim().eq_ignore_ascii_case("branch"))
            .map(|(_, value)| value.trim())
    });
    if message.header("Call-ID") != Some(call_id)
        || message.header("CSeq") != Some("1 OPTIONS")
        || via_branch != Some(branch)
    {
        return Err("响应的 Via branch、Call-ID 或 CSeq 与请求不一致".into());
    }
    Ok((status >= 200).then_some(status))
}

fn read_sip_final_response<S: Read>(
    stream: &mut S,
    call_id: &str,
    branch: &str,
) -> Result<u16, Box<dyn std::error::Error>> {
    let mut data = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let size = stream.read(&mut chunk)?;
        if size == 0 {
            return Err(
                io::Error::new(io::ErrorKind::UnexpectedEof, "SIP 响应前连接已关闭").into(),
            );
        }
        data.extend_from_slice(&chunk[..size]);
        if data.len() > 1024 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "SIP 响应超过 1 MiB").into());
        }
        while data.starts_with(b"\r\n") {
            data.drain(..2);
        }
        while let Some(length) = streamscope_sip::message_length(&data)? {
            if let Some(status) = probe_response_status(&data[..length], call_id, branch)? {
                return Ok(status);
            }
            data.drain(..length);
            while data.starts_with(b"\r\n") {
                data.drain(..2);
            }
        }
    }
}

fn handle(
    data: &[u8],
    peer: SocketAddr,
    scenario: Scenario,
    registrar: &mut Option<streamscope_sip::SipRegistrar>,
    busy: &mut streamscope_sip::SipBusy,
    call: &mut call::CallEngine,
    signaling_port: u16,
) -> Option<Vec<u8>> {
    let result = (|| -> Result<_, Box<dyn std::error::Error>> {
        let answer = streamscope_sip::options_response(data)?;
        if answer.is_some() || matches!(scenario, Scenario::Options) {
            Ok((answer, 200, "OPTIONS"))
        } else if matches!(scenario, Scenario::Busy) {
            Ok(busy.respond(data).map(|answer| match answer {
                Some((response, status)) => (Some(response), status, "INVITE/CANCEL"),
                None => (None, 0, "ACK"),
            })?)
        } else if matches!(scenario, Scenario::Call) {
            Ok(call
                .on_packet(data, peer, signaling_port)?
                .map_or((None, 0, "ACK/other"), |(response, status)| {
                    (Some(response), status, "INVITE/BYE/CANCEL")
                }))
        } else {
            Ok(registrar
                .as_mut()
                .expect("registrar scenario was initialized")
                .respond(data)
                .map(|answer| match answer {
                    Some((response, status)) => (Some(response), status, "REGISTER"),
                    None => (None, 0, "REGISTER"),
                })?)
        }
    })();
    match result {
        Ok((Some(response), status, method)) => {
            println!(
                "{}",
                serde_json::json!({"event":"response","peer":peer.to_string(),"status":status,"method":method})
            );
            Some(response)
        }
        Ok((None, _, _)) => {
            println!(
                "{}",
                serde_json::json!({"event":"ignored","peer":peer.to_string(),"reason":"method not enabled in this scenario"})
            );
            None
        }
        Err(error) => {
            println!(
                "{}",
                serde_json::json!({"event":"invalid","peer":peer.to_string(),"reason":error.to_string()})
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_probe_waits_for_final_response_in_same_tcp_read() {
        let response = |status, reason| {
            format!(
                "SIP/2.0 {status} {reason}\r\nVia: SIP/2.0/TCP host;branch=z9hG4bK-test\r\nFrom: <sip:a@host>;tag=a\r\nTo: <sip:b@host>;tag=b\r\nCall-ID: probe-call\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
            )
        };
        let combined = format!("{}\r\n{}", response(100, "Trying"), response(200, "OK"));
        let mut stream = io::Cursor::new(combined.into_bytes());
        assert_eq!(
            read_sip_final_response(&mut stream, "probe-call", "z9hG4bK-test").unwrap(),
            200
        );
        let mismatched = response(200, "OK");
        assert!(probe_response_status(mismatched.as_bytes(), "probe-call", "different").is_err());
    }

    #[test]
    fn udp_probe_advertises_reachable_via_with_rport() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let address = server.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let mut bytes = [0_u8; 2048];
            let (size, peer) = server.recv_from(&mut bytes).unwrap();
            let request = streamscope_sip::parse_datagram(&bytes[..size]).unwrap();
            let via = request.header("Via").unwrap();
            assert!(via.contains(&peer.to_string()));
            assert!(via.contains(";rport"));
            let reply = format!(
                "SIP/2.0 200 OK\r\nVia: {via}\r\nCall-ID: {}\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
                request.header("Call-ID").unwrap()
            );
            server.send_to(reply.as_bytes(), peer).unwrap();
        });
        let result = probe_options(address, Transport::Udp, None, None);
        worker.join().unwrap();
        assert_eq!(result["status"], 200, "{result}");
    }
}
