use base64::Engine;
use std::fs;
use std::process::Command;
use streamscope_plugin_host::verify_package;

#[test]
fn example_manifests_produce_verified_packages() {
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = std::env::temp_dir().join(format!("streamscope-packager-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let key = root.join("key.txt");
    fs::write(&key, base64::engine::general_purpose::STANDARD.encode([5_u8; 32])).unwrap();
    for (example, executable) in [
        ("plugin-sample", "streamscope-plugin-sample.exe"),
        ("plugin-onvif", "streamscope-plugin-onvif.exe"),
        ("plugin-sip", "streamscope-plugin-sip.exe"),
        ("plugin-ffmpeg", "ffmpeg.exe"),
        ("plugin-h264", "streamscope-plugin-h264.exe"),
        ("plugin-h265", "streamscope-plugin-h265.exe"),
        ("plugin-audio", "streamscope-plugin-audio.exe"),
        ("plugin-rtsp", "streamscope-plugin-rtsp.exe"),
        ("plugin-pcap", "streamscope-plugin-pcap.exe"),
        ("plugin-video-deep", "streamscope-plugin-video-deep.exe"),
    ] {
        let source = repository.join("examples").join(example);
        let payload = root.join(example).join("payload");
        fs::create_dir_all(payload.join("bin")).unwrap();
        fs::copy(source.join("ui.json"), payload.join("ui.json")).unwrap();
        fs::write(payload.join("bin").join(executable), b"test executable").unwrap();
        if example == "plugin-sip" {
            fs::write(payload.join("bin/streams-sip-engine.exe"), b"test SIP engine").unwrap();
        }
        if example == "plugin-ffmpeg" {
            fs::write(payload.join("bin/ffprobe.exe"), b"test probe").unwrap();
            fs::write(payload.join("bin/video-worker.exe"), b"test worker").unwrap();
        }
        let package = root.join(format!("{example}.ssp"));
        let result = Command::new(env!("CARGO_BIN_EXE_plugin-pack"))
            .arg(source.join("manifest-template.json"))
            .arg(&payload).arg(&key).arg(&package).output().unwrap();
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        let verified = verify_package(&package).unwrap();
        let expected = match example {
            "plugin-ffmpeg" => 0,
            "plugin-sip" => 5,
            "plugin-audio" => 3,
            "plugin-onvif" | "plugin-h264" | "plugin-h265" | "plugin-video-deep" => 2,
            _ => 1,
        };
        assert_eq!(verified.manifest.contributions.len(), expected, "{example}");
        if example == "plugin-sip" {
            assert!(verified.manifest.files.contains_key("bin/streams-sip-engine.exe"));
        }
        if example == "plugin-ffmpeg" {
            let store = streamscope_plugin_host::PluginStore::new(root.join("installed-runtime"));
            let preview = store.preview(&package).unwrap();
            store.install(&package, &preview.package_sha256, &preview.fingerprint).unwrap();
            assert!(store.runtime_file("org.streamscope.ffmpeg", "bin/ffprobe.exe").unwrap().is_file());
            assert!(store.runtime_file("org.streamscope.ffmpeg", "bin/video-worker.exe").unwrap().is_file());
            assert!(store.executable("org.streamscope.ffmpeg").is_err());
            store.uninstall("org.streamscope.ffmpeg").unwrap();
        }
    }
    let store = streamscope_plugin_host::PluginStore::new(root.join("installed-dependencies"));
    let media_package = root.join("plugin-h264.ssp");
    let media = store.preview(&media_package).unwrap();
    assert!(store.install(&media_package, &media.package_sha256, &media.fingerprint).is_err());
    let runtime_package = root.join("plugin-ffmpeg.ssp");
    let runtime = store.preview(&runtime_package).unwrap();
    store.install(&runtime_package, &runtime.package_sha256, &runtime.fingerprint).unwrap();
    store.install(&media_package, &media.package_sha256, &media.fingerprint).unwrap();
    assert!(store.set_enabled("org.streamscope.ffmpeg", false).is_err());
    store.uninstall("org.streamscope.h264").unwrap();
    store.uninstall("org.streamscope.ffmpeg").unwrap();
    fs::remove_dir_all(root).unwrap();
}
