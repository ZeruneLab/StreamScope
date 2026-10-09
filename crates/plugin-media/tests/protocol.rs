use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::Duration;
use streamscope_plugin_host::{ArtifactStore, InstalledPlugin, Manifest, PluginProcess, UiDocument, load_plugin_report, save_plugin_report_with_artifacts, stage_file_inputs, stage_media_outputs};

#[test]
fn media_plugin_process_isolated_from_bad_input() {
    let executable = Path::new(env!("CARGO_BIN_EXE_streamscope-plugin-h264"));
    let mut process = PluginProcess::spawn(executable).unwrap();
    let error = process.request("execute", json!({"action":"analyze","input":{"path":"","_hostOutputRoot":"reports"}}), Duration::from_secs(2), |_| {}).unwrap_err();
    assert!(error.to_string().contains("请选择现有媒体文件"));
}

#[test]
fn h264_and_h265_syntax_actions_keep_offsets_and_save_v2_evidence() {
    let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let root = std::env::temp_dir().join(format!("streamscope-plugin-syntax-flow-{unique}"));
    std::fs::create_dir_all(&root).unwrap();
    for (codec, executable, data) in [
        ("h264", env!("CARGO_BIN_EXE_streamscope-plugin-h264"), vec![0,0,0,1,0x67,0x42,0,0,1,0x68,0xce,0,0,1,0x65,0x88]),
        ("h265", env!("CARGO_BIN_EXE_streamscope-plugin-h265"), vec![0,0,0,1,0x40,1,0,0,1,0x26,1,0xe0]),
    ] {
        let source = root.join(format!("sample.{codec}"));
        std::fs::write(&source, data).unwrap();
        let example = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../examples/plugin-{codec}"));
        let ui: UiDocument = serde_json::from_slice(&std::fs::read(example.join("ui.json")).unwrap()).unwrap();
        let manifest: Manifest = serde_json::from_slice(&std::fs::read(example.join("manifest-template.json")).unwrap()).unwrap();
        let item = InstalledPlugin { manifest, fingerprint: "test".into(), enabled: true };
        let mut input = serde_json::Map::new();
        input.insert("path".into(), json!(source));
        input.insert("firstNalu".into(), json!(2));
        input.insert("lastNalu".into(), json!(2));
        let references = stage_file_inputs(&ArtifactStore::new(root.clone()), &ui, "syntax", &mut input).unwrap();
        let mut process = PluginProcess::spawn(Path::new(executable)).unwrap();
        let result = process.request("execute", json!({"action":"inspect-nalus","input":input}), Duration::from_secs(10), |_| {}).unwrap();
        assert_eq!(result["nalus"][0]["index"], 2);
        assert_eq!(result["nalus"][0]["offset"], 9);
        assert!(result["blocks"].as_array().unwrap().iter().any(|block| block["type"] == "syntaxTree" && block["nodes"][0]["byteOffset"] == 9));
        assert!(result["blocks"].as_array().unwrap().iter().any(|block| block["type"] == "hex" && block["byteOffset"] == 9));
        assert!(result["nalus"][0]["hex"].as_str().unwrap().starts_with("00000009"));
        let directory = save_plugin_report_with_artifacts(&root.join("plugins-v2"), &item, "inspect-nalus", &result, &references).unwrap();
        assert!(directory.join("report.json").is_file());
        for (first, last) in [(json!(0), json!(1)), (json!(1), json!(51)), (json!(-1), json!(2))] {
            assert!(process.request("execute", json!({"action":"inspect-nalus","input":{"path":source,"firstNalu":first,"lastNalu":last}}),
                Duration::from_secs(5), |_| {}).is_err());
        }
        drop(process);
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn audio_formats_export_through_plugin_process_and_verified_download_artifacts() {
    if !streamscope_ffmpeg::check_tool("ffmpeg").available { return; }
    let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let root = std::env::temp_dir().join(format!("streamscope-audio-export-flow-{unique}"));
    std::fs::create_dir_all(&root).unwrap();
    let source = root.join("tone.wav");
    let generated = std::process::Command::new("ffmpeg").args([
        "-hide_banner", "-loglevel", "error", "-f", "lavfi", "-i", "sine=frequency=1000:sample_rate=16000", "-t", "1", "-y",
    ]).arg(&source).output().unwrap();
    assert!(generated.status.success(), "{}", String::from_utf8_lossy(&generated.stderr));
    let report_root = root.join("reports");
    let store = ArtifactStore::new(report_root.clone());
    let mut process = PluginProcess::spawn(Path::new(env!("CARGO_BIN_EXE_streamscope-plugin-audio"))).unwrap();
    for (format, expected_codec) in [("wav", "pcm_s16le"), ("mp3", "mp3"), ("m4a", "aac"), ("flac", "flac"), ("ogg", "opus")] {
        let mut result = process.request("execute", json!({"action":"export-audio","input":{
            "path":source,"format":format,"_hostOutputRoot":report_root
        }}), Duration::from_secs(30), |_| {}).unwrap();
        let exported = Path::new(result["downloadFile"].as_str().unwrap());
        assert!(exported.is_file());
        let probe = std::process::Command::new("ffprobe").args([
            "-v", "error", "-select_streams", "a:0", "-show_entries", "stream=codec_name", "-of", "json",
        ]).arg(exported).output().unwrap();
        assert!(probe.status.success());
        let probe: serde_json::Value = serde_json::from_slice(&probe.stdout).unwrap();
        assert_eq!(probe["streams"][0]["codec_name"], expected_codec);
        let mut references = Vec::new();
        stage_media_outputs(&store, &mut result, &mut references).unwrap();
        assert_eq!(references.len(), 1);
        assert_eq!(result["blocks"][0]["type"], "download");
        assert!(store.resolve_reference(&references[0]).unwrap().is_file());
    }
    assert!(process.request("execute", json!({"action":"export-audio","input":{
        "path":source,"format":"../../escape","_hostOutputRoot":report_root
    }}), Duration::from_secs(5), |_| {}).is_err());
    assert!(process.request("execute", json!({"action":"export-audio","input":{
        "path":source,"format":"wav","startMs":500,"endMs":400,"_hostOutputRoot":report_root
    }}), Duration::from_secs(5), |_| {}).is_err());
    drop(process);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn h264_file_flows_through_artifact_process_and_v2_report() {
    if !streamscope_ffmpeg::check_tool("ffmpeg").available { return; }
    let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let report_root = std::env::temp_dir().join(format!("streamscope-plugin-flow-{unique}"));
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/h264/generated-normal.h264");
    let ui: UiDocument = serde_json::from_str(include_str!("../../../examples/plugin-h264/ui.json")).unwrap();
    let manifest: Manifest = serde_json::from_str(include_str!("../../../examples/plugin-h264/manifest-template.json")).unwrap();
    let installed = InstalledPlugin { manifest, fingerprint: "test".into(), enabled: true };
    let store = ArtifactStore::new(report_root.clone());
    let mut input = serde_json::Map::new();
    input.insert("path".into(), json!(source));
    let mut references = stage_file_inputs(&store, &ui, "main", &mut input).unwrap();
    input.insert("_hostOutputRoot".into(), json!(report_root));
    let mut process = PluginProcess::spawn(Path::new(env!("CARGO_BIN_EXE_streamscope-plugin-h264"))).unwrap();
    let mut result = process.request("execute", json!({"action":"analyze","input":input}),
        Duration::from_secs(60), |_| {}).unwrap();
    stage_media_outputs(&store, &mut result, &mut references).unwrap();
    let directory = save_plugin_report_with_artifacts(&report_root.join("plugins-v2"), &installed, "analyze", &result, &references).unwrap();
    let id = directory.file_name().unwrap().to_string_lossy().trim_start_matches("plugin-report-").to_owned();
    let report = load_plugin_report(&report_root.join("plugins-v2"), &id).unwrap();
    assert_eq!(report.artifacts[0].id, references[0].id);
    assert!(store.resolve_reference(&report.artifacts[0]).unwrap().is_file());
    assert!(Path::new(result["reportDirectory"].as_str().unwrap()).join("result.json").is_file());
    std::fs::remove_dir_all(report_root).unwrap();
}

#[test]
fn optional_local_multistream_pcap_matches_existing_analyzer() {
    let Some(source) = std::env::var_os("STREAMSCOPE_LOCAL_PCAP").map(PathBuf::from) else { return; };
    let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let root = std::env::temp_dir().join(format!("streamscope-local-pcap-parity-{unique}"));
    let old = streamscope_analyzer::analyze_pcap_file(streamscope_analyzer::PcapFileOptions {
        input: source.clone(), output_root: root.join("old"), process_timeout_seconds: 300,
        stream_ids: Vec::new(),
    }).unwrap();
    let ui: UiDocument = serde_json::from_str(include_str!("../../../examples/plugin-pcap/ui.json")).unwrap();
    let artifacts = ArtifactStore::new(root.join("plugin"));
    let mut input = serde_json::Map::new();
    input.insert("path".into(), json!(source));
    let mut references = stage_file_inputs(&artifacts, &ui, "main", &mut input).unwrap();
    input.insert("_hostOutputRoot".into(), json!(root.join("plugin")));
    let mut process = PluginProcess::spawn(Path::new(env!("CARGO_BIN_EXE_streamscope-plugin-pcap"))).unwrap();
    let mut response = process.request("execute", json!({"action":"analyze","input":input}),
        Duration::from_secs(120), |_| {}).unwrap();
    stage_media_outputs(&artifacts, &mut response, &mut references).unwrap();
    let result: streamscope_core::AnalysisResult = serde_json::from_slice(&std::fs::read(
        PathBuf::from(response["reportDirectory"].as_str().unwrap()).join("result.json")
    ).unwrap()).unwrap();
    let streams = |result: &streamscope_core::AnalysisResult| result.streams.iter()
        .filter_map(|stream| stream.capture_stream.as_ref())
        .map(|stream| (stream.id.clone(), stream.codec.clone())).collect::<Vec<_>>();
    assert!(old.result.capture_summary.as_ref().unwrap().stream_count > 1);
    assert_eq!(old.result.capture_summary.as_ref().unwrap().stream_count,
        result.capture_summary.as_ref().unwrap().stream_count);
    assert_eq!(streams(&old.result), streams(&result));
    assert_eq!(old.result.diagnostics.iter().map(|item| &item.rule_id).collect::<Vec<_>>(),
        result.diagnostics.iter().map(|item| &item.rule_id).collect::<Vec<_>>());
    assert!(response["blocks"].as_array().unwrap().iter().any(|block| block["title"] == "抓包媒体流（流 ID 可复制到深入分析输入框）"));
    let selected_id = old.result.streams[0].capture_stream.as_ref().unwrap().id.clone();
    let old_deep = streamscope_analyzer::analyze_pcap_file(streamscope_analyzer::PcapFileOptions {
        input: source.clone(), output_root: root.join("old-deep"), process_timeout_seconds: 300,
        stream_ids: vec![selected_id.clone()],
    }).unwrap();
    let deep_input = json!({"path":artifacts.resolve_reference(&references[0]).unwrap(),
        "streamIds":selected_id,"_hostOutputRoot":root.join("plugin-deep")});
    let deep_response = process.request("execute", json!({"action":"analyze","input":deep_input}),
        Duration::from_secs(120), |_| {}).unwrap();
    let deep_result: streamscope_core::AnalysisResult = serde_json::from_slice(&std::fs::read(
        PathBuf::from(deep_response["reportDirectory"].as_str().unwrap()).join("result.json")
    ).unwrap()).unwrap();
    assert_eq!(streams(&old_deep.result), streams(&deep_result));
    assert_eq!(old_deep.result.diagnostics.iter().map(|item| &item.rule_id).collect::<Vec<_>>(),
        deep_result.diagnostics.iter().map(|item| &item.rule_id).collect::<Vec<_>>());
    drop(process);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(windows)]
#[test]
fn video_deep_plugin_returns_frame_overlay_from_worker() {
    let bundled = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../apps/desktop/src-tauri/binaries");
    let worker = bundled.join("video-worker-x86_64-pc-windows-msvc.exe");
    if !worker.is_file() { return; }
    let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let runtime = std::env::temp_dir().join(format!("streamscope-deep-runtime-{unique}"));
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::copy(worker, runtime.join("video-worker.exe")).unwrap();
    std::fs::copy(bundled.join("ffmpeg-x86_64-pc-windows-msvc.exe"), runtime.join("ffmpeg.exe")).unwrap();
    for library in ["avcodec-63.dll", "avformat-63.dll", "avutil-61.dll", "swresample-7.dll", "swscale-10.dll"] {
        std::fs::copy(bundled.join(library), runtime.join(library)).unwrap();
    }
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/h264/generated-normal.h264");
    let report_root = runtime.join("reports");
    let mut process = PluginProcess::spawn_with_runtime(
        Path::new(env!("CARGO_BIN_EXE_streamscope-plugin-video-deep")), Some(&runtime)
    ).unwrap();
    let result = process.request("execute", json!({"action":"inspect-frame","input":{
        "path":source,"displayIndex":0,"_hostOutputRoot":report_root
    }}), Duration::from_secs(30), |_| {}).unwrap();
    assert!(result["blocks"].as_array().unwrap().iter().any(|block| block["type"] == "frameOverlay"));
    assert!(result["summary"].as_str().unwrap().contains("0"));
    let mut result = result;
    let mut references = Vec::new();
    let store = ArtifactStore::new(report_root);
    stage_media_outputs(&store, &mut result, &mut references).unwrap();
    assert_eq!(references.len(), 1);
    assert_eq!(references[0].media_type, "image/png");
    assert_eq!(result["blocks"][0]["frameArtifactId"], references[0].id);
    let frame = store.resolve_reference(&references[0]).unwrap();
    assert!(std::fs::read(frame).unwrap().starts_with(&[0x89, b'P', b'N', b'G']));
    drop(process);
    std::fs::remove_dir_all(runtime).unwrap();
}

#[cfg(windows)]
#[test]
fn report_workbench_preserves_exact_frame_syntax_blocks_csv_and_reference_tools() {
    let bundled = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../apps/desktop/src-tauri/binaries");
    assert!(bundled.join("video-worker-x86_64-pc-windows-msvc.exe").is_file(), "此回归必须实际运行共享解码器");
    let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let root = std::env::temp_dir().join(format!("streamscope-workbench-parity-{unique}"));
    std::fs::create_dir_all(&root).unwrap();
    for name in ["ffmpeg", "ffprobe", "video-worker"] {
        std::fs::copy(bundled.join(format!("{name}-x86_64-pc-windows-msvc.exe")), root.join(format!("{name}.exe"))).unwrap();
    }
    for name in ["avcodec-63.dll", "avformat-63.dll", "avutil-61.dll", "swresample-7.dll", "swscale-10.dll"] { std::fs::copy(bundled.join(name), root.join(name)).unwrap(); }
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/h264/generated-normal.h264");
    let reports = root.join("reports");
    let mut analyzer = PluginProcess::spawn_with_runtime(Path::new(env!("CARGO_BIN_EXE_streamscope-plugin-h264")), Some(&root)).unwrap();
    let analyzed = analyzer.request("execute", json!({"action":"analyze","input":{"path":source,"_hostOutputRoot":reports}}), Duration::from_secs(60), |_| {}).unwrap();
    let report = Path::new(analyzed["reportDirectory"].as_str().unwrap()).join("result.json");
    let before = std::fs::read(&report).unwrap();
    let ui: UiDocument = serde_json::from_str(include_str!("../../../examples/plugin-video-deep/ui.json")).unwrap();
    let store = ArtifactStore::new(reports.clone());
    let mut process = PluginProcess::spawn_with_runtime(Path::new(env!("CARGO_BIN_EXE_streamscope-plugin-video-deep")), Some(&root)).unwrap();
    for operation in ["extract_video_frame", "analyze_video_frame_blocks", "load_video_frame_syntax", "export_video_block_csv", "compare_video_reference"] {
        let mut input = json!({"operation":operation,"path":source,"reportPath":report,"referencePath":source,"displayIndex":0,"_hostOutputRoot":reports}).as_object().unwrap().clone();
        let mut refs = stage_file_inputs(&store, &ui, "report-tools", &mut input).unwrap();
        let response = process.request("execute", json!({"action":"report-tools","input":input}), Duration::from_secs(120), |_| {});
        if operation == "load_video_frame_syntax" && response.is_err() {
            // This elementary-stream fixture does not retain packet-to-AU ranges.
            // The same safety boundary as the legacy viewer must reject guessing.
            assert!(response.unwrap_err().to_string().contains("不能唯一映射"));
            assert_eq!(std::fs::read(&report).unwrap(), before);
            continue;
        }
        let mut result = response.unwrap();
        stage_media_outputs(&store, &mut result, &mut refs).unwrap();
        let data_ref = refs.iter().find(|reference| reference.id == result["dataArtifactId"]).unwrap();
        let data: serde_json::Value = serde_json::from_slice(&std::fs::read(store.resolve_reference(data_ref).unwrap()).unwrap()).unwrap();
        match operation {
            "extract_video_frame" => assert!(std::fs::read(data.as_str().unwrap()).unwrap().starts_with(&[0x89, b'P', b'N', b'G'])),
            "analyze_video_frame_blocks" => assert!(data["qp"]["blocks"].as_array().is_some_and(|blocks| !blocks.is_empty())),
            "load_video_frame_syntax" => { assert!(data["access_unit_index"].is_number()); assert!(!data["nalus"].as_array().unwrap().is_empty()); },
            "export_video_block_csv" => {
                let csv = std::fs::read_to_string(result["downloadFile"].as_str().unwrap()).unwrap();
                assert_eq!(csv.lines().next().unwrap().split(',').count(), 30);
                assert!(csv.lines().skip(1).any(|row| row.starts_with("\"qp\",")));
            }
            "compare_video_reference" => assert!(data["limitations"].is_array()),
            _ => unreachable!(),
        }
        assert_eq!(std::fs::read(&report).unwrap(), before, "原报告必须只读");
    }
    drop(process); drop(analyzer);
    std::fs::remove_dir_all(root).unwrap();
}
