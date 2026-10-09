#![cfg(windows)]

use serde_json::json;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::time::Duration;
use streamscope_plugin_host::PluginProcess;

#[test]
fn confirmed_capture_replay_uses_packaged_engine_and_returns_step_evidence() {
    let plugin = PathBuf::from(env!("CARGO_BIN_EXE_streamscope-plugin-sip"));
    let engine = plugin.parent().unwrap().join("streams-sip-engine.exe");
    if !engine.is_file() { return; }
    let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let root = std::env::temp_dir().join(format!("streamscope-plugin-sip-replay-{unique}"));
    std::fs::create_dir_all(&root).unwrap();
    let plugin_copy = root.join("streamscope-plugin-sip.exe");
    std::fs::copy(plugin, &plugin_copy).unwrap();
    std::fs::copy(engine, root.join("streams-sip-engine.exe")).unwrap();
    let capture = root.join("options.pcap");
    let request = b"OPTIONS sip:device@old.example SIP/2.0\r\nVia: SIP/2.0/UDP old;branch=z9hG4bK-old\r\nFrom: <sip:caller@old.example>;tag=old\r\nTo: <sip:device@old.example>\r\nCall-ID: plugin-call\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
    let response = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP old;branch=z9hG4bK-old\r\nFrom: <sip:caller@old.example>;tag=old\r\nTo: <sip:device@old.example>;tag=device\r\nCall-ID: plugin-call\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
    let mut pcap = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0];
    for (index, (payload, caller)) in [(request.as_slice(), true), (response.as_slice(), false)].into_iter().enumerate() {
        let mut frame = vec![0_u8; 14 + 20 + 8];
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
        frame[23] = 17;
        frame[26..30].copy_from_slice(if caller { &[10, 0, 0, 1] } else { &[10, 0, 0, 2] });
        frame[30..34].copy_from_slice(if caller { &[10, 0, 0, 2] } else { &[10, 0, 0, 1] });
        frame[34..36].copy_from_slice(&5060_u16.to_be_bytes());
        frame[36..38].copy_from_slice(&5060_u16.to_be_bytes());
        frame[38..40].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        pcap.extend(0_u32.to_le_bytes());
        pcap.extend(((index as u32) * 1000).to_le_bytes());
        pcap.extend((frame.len() as u32).to_le_bytes());
        pcap.extend((frame.len() as u32).to_le_bytes());
        pcap.extend(frame);
    }
    std::fs::write(&capture, &pcap).unwrap();
    let device = UdpSocket::bind("127.0.0.1:0").unwrap();
    device.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let target = device.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let mut bytes = [0_u8; 4096];
        let (size, peer) = device.recv_from(&mut bytes).unwrap();
        let request = streamscope_sip::parse_datagram(&bytes[..size]).unwrap();
        assert_eq!(request.method(), Some("OPTIONS"));
        let reply = streamscope_sip::build_response_with_body(&request, 200, "OK", "OPTIONS", &[], None, &[]).unwrap();
        device.send_to(&reply, peer).unwrap();
    });
    let mut process = PluginProcess::spawn(&plugin_copy).unwrap();
    let result = process.request("execute", json!({"action":"execute-replay","input":{
        "path":capture,"callId":"plugin-call","captureSource":"10.0.0.1:5060",
        "target":target.to_string(),"confirmSend":"true"
    }}), Duration::from_secs(10), |_| {}).unwrap();
    worker.join().unwrap();
    assert_eq!(result["data"]["success"], true);
    assert_eq!(result["data"]["steps"][0]["actual_status"], 200);
    let export = process.request("execute", json!({"action":"export-evidence","input":{
        "data":serde_json::to_string(&result["data"]).unwrap(),"redacted":"true","_hostOutputRoot":root.join("reports")
    }}), Duration::from_secs(5), |_| {}).unwrap();
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(export["downloadFile"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(saved["steps"][0]["actual_status"], 200);
    let device = UdpSocket::bind("127.0.0.1:0").unwrap();
    device.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let target = device.local_addr().unwrap();
    let probe_device = std::thread::spawn(move || {
        let mut bytes = [0_u8; 4096];
        let (size, peer) = device.recv_from(&mut bytes).unwrap();
        let request = streamscope_sip::parse_datagram(&bytes[..size]).unwrap();
        assert_eq!(request.method(), Some("OPTIONS"));
        let reply = streamscope_sip::build_response_with_body(&request, 200, "OK", "OPTIONS", &[], None, &[]).unwrap();
        device.send_to(&reply, peer).unwrap();
    });
    let probe = process.request("execute", json!({"action":"probe","input":{"target":target.to_string(),"transport":"udp"}}), Duration::from_secs(10), |_| {}).unwrap();
    probe_device.join().unwrap();
    assert_eq!(probe["data"]["status"], 200);
    let large_capture = root.join("large.pcap");
    let mut large = pcap[..24].to_vec();
    for _ in 0..10_000 { large.extend_from_slice(&pcap[24..]); }
    std::fs::write(&large_capture, large).unwrap();
    let analysis = process.request("execute", json!({"action":"analyze","input":{
        "path":large_capture,"_hostOutputRoot":root.join("reports")
    }}), Duration::from_secs(30), |_| {}).unwrap();
    assert!(analysis["data"].is_null());
    let data_path = PathBuf::from(analysis["dataFile"].as_str().unwrap());
    assert!(std::fs::metadata(&data_path).unwrap().len() > 4 * 1024 * 1024);
    let complete: serde_json::Value = serde_json::from_reader(std::fs::File::open(&data_path).unwrap()).unwrap();
    assert_eq!(complete["sip_messages"].as_array().unwrap().len(), 20_000);
    let exported = process.request("execute", json!({"action":"export-evidence","input":{
        "dataPath":data_path,"redacted":"true","_hostOutputRoot":root.join("reports")
    }}), Duration::from_secs(30), |_| {}).unwrap();
    let exported: serde_json::Value = serde_json::from_reader(std::fs::File::open(exported["downloadFile"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(exported["sip_messages"].as_array().unwrap().len(), 20_000);
    drop(process);
    std::fs::remove_dir_all(root).unwrap();
}
