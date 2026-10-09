use std::path::{Path, PathBuf};
use std::time::Duration;
use streamscope_plugin_host::{PluginProcess, PluginStore, verify_catalog, verify_package};

#[test]
fn optional_real_signed_bundles_install_and_execute_from_isolated_registry() {
    let Ok(directory) = std::env::var("STREAMSCOPE_TEST_PLUGIN_PACKAGES") else { return; };
    let root = PathBuf::from(directory);
    let catalog = verify_catalog(&std::fs::read(root.join("catalog.json")).unwrap(),
        &std::fs::read_to_string(root.join("catalog.json.sig")).unwrap(),
        &std::fs::read_to_string(root.join("catalog.pub")).unwrap()).unwrap();
    assert_eq!(catalog.packages.len(), 10);
    let store = PluginStore::new(root.join("isolated-registry"));
    let mut entries = catalog.packages;
    let mut audio_package = None;
    entries.sort_by_key(|entry| entry.id != "org.streamscope.ffmpeg");
    for entry in entries {
        let url = url::Url::parse(&entry.package_url).unwrap();
        let package = root.join(url.path_segments().unwrap().next_back().unwrap());
        let verified = verify_package(&package).unwrap();
        if entry.id == "org.streamscope.audio" { audio_package = Some(package.clone()); }
        assert_eq!(format!("sha256:{}", verified.package_sha256), entry.package_sha256);
        assert_eq!(verified.manifest.host_api, entry.host_api);
        assert_eq!(verified.fingerprint, entry.publisher_fingerprint);
        assert!(entry.matches_confirmation(&verified.package_sha256, &verified.fingerprint));
        store.install(&package, &verified.package_sha256, &entry.publisher_fingerprint).unwrap();
    }
    assert_eq!(store.list().unwrap().len(), 10);
    let runtime = store.runtime_file("org.streamscope.ffmpeg", "bin/ffmpeg.exe").unwrap();
    store.runtime_file("org.streamscope.ffmpeg", "bin/ffprobe.exe").unwrap();
    let runtime = runtime.parent().unwrap();
    for (codec, data) in [("h264", vec![0,0,1,0x65,0x88]), ("h265", vec![0,0,1,0x26,1,0xe0])] {
        let input = root.join(format!("input.{codec}"));
        std::fs::write(&input, data).unwrap();
        let id = format!("org.streamscope.{codec}");
        let mut process = PluginProcess::spawn_with_runtime(&store.executable(&id).unwrap(), Some(runtime)).unwrap();
        let result = process.request("execute", serde_json::json!({"action":"inspect-nalus","input":{"path":input}}),
            Duration::from_secs(10), |_| {}).unwrap();
        assert_eq!(result["nalus"][0]["index"], 1);
        assert!(result["blocks"].as_array().unwrap().iter().any(|block| block["type"] == "syntaxTree"));
    }
    let audio = root.join("input.wav");
    write_silence(&audio);
    let mut process = PluginProcess::spawn_with_runtime(&store.executable("org.streamscope.audio").unwrap(), Some(runtime)).unwrap();
    let result = process.request("execute", serde_json::json!({"action":"export-audio","input":{
        "path":audio,"format":"mp3","_hostOutputRoot":root.join("reports")
    }}), Duration::from_secs(30), |_| {}).unwrap();
    assert!(Path::new(result["downloadFile"].as_str().unwrap()).is_file());
    drop(process);
    if store.list().unwrap().iter().any(|plugin| plugin.manifest.id == "org.streamscope.sip" && plugin.manifest.contributions.iter().any(|action| action.action == "export-evidence")) {
        let evidence = root.join("sip-result.json");
        std::fs::write(&evidence, br#"{"target":"127.0.0.1:5060","steps":[{"actual_status":200}]}"#).unwrap();
        let mut process = PluginProcess::spawn(&store.executable("org.streamscope.sip").unwrap()).unwrap();
        let result = process.request("execute", serde_json::json!({"action":"export-evidence","input":{
            "dataPath":evidence,"redacted":"true","_hostOutputRoot":root.join("reports")
        }}), Duration::from_secs(10), |_| {}).unwrap();
        let saved: serde_json::Value = serde_json::from_reader(std::fs::File::open(result["downloadFile"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(saved["steps"][0]["actual_status"], 200);
    }
    store.uninstall("org.streamscope.audio").unwrap();
    assert_eq!(store.list().unwrap().len(), 9);
    let package = audio_package.unwrap();
    let verified = verify_package(&package).unwrap();
    store.install(&package, &verified.package_sha256, &verified.fingerprint).unwrap();
}

fn write_silence(path: &Path) {
    let size = 8_000_u32 * 2;
    let mut wave = b"RIFF".to_vec();
    wave.extend((36 + size).to_le_bytes());
    wave.extend(b"WAVEfmt ");
    wave.extend(16_u32.to_le_bytes());
    wave.extend(1_u16.to_le_bytes());
    wave.extend(1_u16.to_le_bytes());
    wave.extend(8_000_u32.to_le_bytes());
    wave.extend(16_000_u32.to_le_bytes());
    wave.extend(2_u16.to_le_bytes());
    wave.extend(16_u16.to_le_bytes());
    wave.extend(b"data");
    wave.extend(size.to_le_bytes());
    wave.resize(wave.len() + size as usize, 0);
    std::fs::write(path, wave).unwrap();
}
