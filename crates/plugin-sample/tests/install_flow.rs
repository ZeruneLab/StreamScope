use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use streamscope_plugin_host::{Manifest, PluginProcess, PluginStore};
use zip::write::SimpleFileOptions;

#[test]
fn signed_package_installs_runs_and_uninstalls() {
    let root = std::env::temp_dir().join(format!("streamscope-plugin-e2e-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/plugin-sample");
    let mut manifest: Manifest = serde_json::from_slice(&fs::read(source.join("manifest-template.json")).unwrap()).unwrap();
    let executable = fs::read(env!("CARGO_BIN_EXE_streamscope-plugin-sample")).unwrap();
    let ui = fs::read(source.join("ui.json")).unwrap();
    let key = SigningKey::from_bytes(&[3_u8; 32]);
    manifest.publisher.key_fingerprint = format!("sha256:{:x}", Sha256::digest(key.verifying_key().to_bytes()));
    manifest.files.insert("bin/streamscope-plugin-sample.exe".into(), format!("sha256:{:x}", Sha256::digest(&executable)));
    manifest.files.insert("ui.json".into(), format!("sha256:{:x}", Sha256::digest(&ui)));
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let package = root.join("sample.ssp");
    let mut zip = zip::ZipWriter::new(File::create(&package).unwrap());
    for (name, bytes) in [
        ("manifest.json", manifest_bytes),
        ("publisher.pub", base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes()).into_bytes()),
        ("signature.ed25519", base64::engine::general_purpose::STANDARD.encode(key.sign(&serde_json::to_vec(&manifest).unwrap()).to_bytes()).into_bytes()),
        ("bin/streamscope-plugin-sample.exe", executable),
        ("ui.json", ui),
    ] {
        zip.start_file(name, SimpleFileOptions::default()).unwrap();
        zip.write_all(&bytes).unwrap();
    }
    zip.finish().unwrap();
    let store = PluginStore::new(root.join("local/StreamScope/plugins"));
    let preview = store.preview(&package).unwrap();
    store.install(&package, &preview.package_sha256, &preview.fingerprint).unwrap();
    let ui = store.ui_document(&manifest.id).unwrap();
    assert_eq!(ui.views[0].id, "main");
    let mut process = PluginProcess::spawn(&store.executable(&manifest.id).unwrap()).unwrap();
    let result = process.request("execute", json!({"action":"inspect","input":{"path":"test.pcap"}}), Duration::from_secs(2), |_| {}).unwrap();
    assert_eq!(result["input"]["path"], "test.pcap");
    drop(process);
    if let Some(cli) = std::env::var_os("STREAMSCOPE_CLI_EXE") {
        let input_path = root.join("test.pcap");
        fs::write(&input_path, b"capture evidence").unwrap();
        let input_json = root.join("input.json");
        fs::write(&input_json, serde_json::to_vec(&json!({"path":input_path})).unwrap()).unwrap();
        let output_root = root.join("reports");
        let list = std::process::Command::new(&cli).env("LOCALAPPDATA", root.join("local"))
            .args(["plugin", "list"]).output().unwrap();
        assert!(list.status.success());
        let stdout = String::from_utf8(list.stdout).unwrap();
        assert!(stdout.contains(&manifest.id));
        assert!(stdout.contains("inspect"));
        let executed = std::process::Command::new(&cli).env("LOCALAPPDATA", root.join("local"))
            .args(["plugin", "run", "--id", &manifest.id, "--action", "inspect", "--input"])
            .arg(&input_json).arg("--output").arg(&output_root).output().unwrap();
        assert!(executed.status.success(), "{}", String::from_utf8_lossy(&executed.stderr));
        let reports = streamscope_plugin_host::list_plugin_reports(&output_root.join("plugins-v2")).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].artifacts.len(), 1);
        assert!(streamscope_plugin_host::ArtifactStore::new(output_root)
            .resolve_reference(&reports[0].artifacts[0]).unwrap().is_file());
        store.set_enabled(&manifest.id, false).unwrap();
        let disabled = std::process::Command::new(cli).env("LOCALAPPDATA", root.join("local"))
            .args(["plugin", "run", "--id", &manifest.id, "--action", "inspect", "--input"])
            .arg(&input_json).output().unwrap();
        assert!(!disabled.status.success());
    }
    store.uninstall(&manifest.id).unwrap();
    assert!(store.list().unwrap().is_empty());
    fs::remove_dir_all(root).unwrap();
}
