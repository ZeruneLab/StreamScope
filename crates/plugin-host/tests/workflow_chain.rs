//! Opt-in real capture test. Reads installed packages, never changes their registry.
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use streamscope_plugin_host::*;

fn run(store: &PluginStore, runtime: &Path, root: &Path, id: &str, operation: &str, input: Value,
    linked: BTreeMap<String, ArtifactReference>) -> PluginReportV2 {
    println!("执行：{id} / {operation}，选流 {}", input["streamIds"].as_str().unwrap_or("—"));
    let plugin = store.list().unwrap().into_iter().find(|plugin| plugin.manifest.id == id && plugin.enabled).unwrap();
    let contribution = plugin.manifest.contributions.iter().find(|entry| entry.action == operation).unwrap();
    let artifacts = ArtifactStore::new(root.into());
    let mut fields = input.as_object().unwrap().clone();
    let mut refs = stage_linked_file_inputs(&artifacts, &store.ui_document(id).unwrap(), &contribution.view,
        &mut fields, &linked, &mut |_, _, _| {}, &|| false).unwrap();
    validate_media_input(id, &Value::Object(fields.clone())).unwrap();
    fields.insert("_hostOutputRoot".into(), json!(root));
    let mut process = PluginProcess::spawn_with_runtime(&store.executable(id).unwrap(), Some(runtime)).unwrap();
    let mut result = process.request("execute", json!({"action":operation,"input":fields}), Duration::from_secs(600), |_| {}).unwrap();
    stage_media_outputs(&artifacts, &mut result, &mut refs).unwrap();
    attach_report_workflows(&artifacts, id, &mut result, &mut refs).unwrap();
    let directory = save_plugin_report_with_artifacts(&root.join("plugins-v2"), &plugin, operation, &result, &refs).unwrap();
    let report_id = directory.file_name().unwrap().to_string_lossy().trim_start_matches("plugin-report-").to_owned();
    load_plugin_report(&root.join("plugins-v2"), &report_id).unwrap()
}

fn continue_from(store: &PluginStore, runtime: &Path, root: &Path, source: &PluginReportV2, action_id: &str, extra: Value) -> PluginReportV2 {
    let action = workflow_action(source, action_id).unwrap();
    let mut input = serde_json::to_value(&action.input).unwrap();
    input.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    run(store, runtime, root, &action.plugin_id, &action.action, input, linked_references(source, &action).unwrap())
}

#[test]
fn optional_installed_plugins_preserve_pcap_video_audio_workflow() {
    let (Ok(capture), Ok(installed)) = (std::env::var("STREAMSCOPE_TEST_CAPTURE"), std::env::var("STREAMSCOPE_TEST_PLUGIN_STORE")) else { return; };
    let installed = PathBuf::from(installed);
    let registry_before = std::fs::read(installed.join("registry.json")).unwrap();
    let store = PluginStore::new(installed.clone());
    let ffmpeg = store.runtime_file("org.streamscope.ffmpeg", "bin/ffmpeg.exe").unwrap();
    store.runtime_file("org.streamscope.ffmpeg", "bin/ffprobe.exe").unwrap();
    store.runtime_file("org.streamscope.ffmpeg", "bin/video-worker.exe").unwrap();
    let runtime = ffmpeg.parent().unwrap();
    let root = std::env::temp_dir().join(format!("streamscope-plugin-chain-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let scan = run(&store, runtime, &root, "org.streamscope.pcap", "analyze", json!({"path":capture}), BTreeMap::new());
    let result = &scan.plugin_results["org.streamscope.pcap"].result;
    let directory = Path::new(result["reportDirectory"].as_str().unwrap());
    let data: Value = serde_json::from_reader(std::io::BufReader::new(std::fs::File::open(directory.join("result.json")).unwrap())).unwrap();
    let streams = data["streams"].as_array().unwrap();
    assert!(streams.len() > 2, "real fixture must exercise multiple streams");
    let video = streams.iter().find(|stream| matches!(stream["capture_stream"]["codec"].as_str(), Some("h264" | "h265" | "hevc"))).unwrap();
    let audio = streams.iter().find(|stream| matches!(stream["capture_stream"]["codec"].as_str(), Some("pcma" | "pcmu"))).unwrap();
    let video_id = video["capture_stream"]["id"].as_str().unwrap();
    let audio_id = audio["capture_stream"]["id"].as_str().unwrap();
    assert_eq!(result["hostActions"].as_array().unwrap().len(), streams.len());

    let selected_video = continue_from(&store, runtime, &root, &scan, &format!("{video_id}-select"), json!({}));
    let deep_action = workflow_action(&selected_video, &format!("{video_id}-frame")).unwrap();
    assert_ne!(deep_action.artifact_inputs["path"], scan.artifacts[0].id);
    let frame = continue_from(&store, runtime, &root, &selected_video, &deep_action.id, json!({"displayIndex":"0"}));
    let frame_result = &frame.plugin_results["org.streamscope.video-deep"].result;
    assert_eq!(frame_result["displayIndex"], 0);
    assert!(frame_result["blocks"].as_array().unwrap().iter().any(|block| block["type"] == "frameOverlay" && block["frameArtifactId"].is_string()));
    let syntax = continue_from(&store, runtime, &root, &selected_video, &format!("{video_id}-syntax"), json!({"firstNalu":"1","lastNalu":"4"}));
    assert!(syntax.plugin_results.values().next().unwrap().result["blocks"].as_array().unwrap().iter().any(|block| block["type"] == "syntaxTree"));

    if store.list().unwrap().iter().any(|plugin| plugin.manifest.id == "org.streamscope.video-deep" && plugin.manifest.contributions.iter().any(|action| action.action == "report-tools")) {
        let selected_result = &selected_video.plugin_results["org.streamscope.pcap"].result;
        let video_reference = selected_video.artifacts.iter().find(|artifact| artifact.id == deep_action.artifact_inputs["path"]).unwrap();
        let video_path = ArtifactStore::new(root.clone()).resolve_reference(video_reference).unwrap();
        let report_path = Path::new(selected_result["reportDirectory"].as_str().unwrap()).join("streams").join(video_id).join("result.json");
        let original = std::fs::read(&report_path).unwrap();
        for operation in ["extract_video_frame", "analyze_video_frame_blocks", "load_video_frame_syntax", "export_video_block_csv"] {
            let tool = run(&store, runtime, &root, "org.streamscope.video-deep", "report-tools", json!({
                "path":video_path, "reportPath":report_path, "displayIndex":0, "operation":operation,
            }), BTreeMap::new());
            let result = &tool.plugin_results["org.streamscope.video-deep"].result;
            let reference = tool.artifacts.iter().find(|artifact| artifact.id == result["dataArtifactId"].as_str().unwrap()).unwrap();
            let data: Value = serde_json::from_reader(std::fs::File::open(ArtifactStore::new(root.clone()).resolve_reference(reference).unwrap()).unwrap()).unwrap();
            if operation == "load_video_frame_syntax" {
                assert!(!data["nalus"].as_array().unwrap().is_empty());
                assert!(data["nalus"].as_array().unwrap().iter().any(|nalu| !nalu["packets"].as_array().unwrap().is_empty()));
            }
            if operation == "analyze_video_frame_blocks" { assert!(!data["qp"]["blocks"].as_array().unwrap().is_empty()); }
            if operation == "export_video_block_csv" { assert!(result["blocks"].as_array().unwrap().iter().any(|block| block["type"] == "download")); }
            assert_eq!(std::fs::read(&report_path).unwrap(), original);
        }
        println!("选中视频流的原工作台动作：精确帧/QP/逐帧语法+RTP映射/CSV 均通过，原报告未改写。");
    }

    let selected_audio = continue_from(&store, runtime, &root, &scan, &format!("{audio_id}-select"), json!({}));
    let quality = continue_from(&store, runtime, &root, &selected_audio, &format!("{audio_id}-audio"), json!({}));
    let quality_result = &quality.plugin_results["org.streamscope.audio"].result;
    let quality_data: Value = serde_json::from_reader(std::io::BufReader::new(std::fs::File::open(Path::new(quality_result["reportDirectory"].as_str().unwrap()).join("result.json")).unwrap())).unwrap();
    assert!(quality_data["audio"]["quality"].is_object(), "audio quality must be generated, not only replay");
    let exported = continue_from(&store, runtime, &root, &selected_audio, &format!("{audio_id}-export"), json!({"format":"mp3"}));
    assert!(exported.plugin_results["org.streamscope.audio"].result["blocks"].as_array().unwrap().iter().any(|block| block["type"] == "download" && block["filename"].as_str().unwrap().ends_with(".mp3")));
    assert_ne!(workflow_action(&selected_audio, &format!("{audio_id}-audio")).unwrap().artifact_inputs["path"], deep_action.artifact_inputs["path"]);
    assert_eq!(std::fs::read(installed.join("registry.json")).unwrap(), registry_before);
    println!("真实抓包 {} 路：视频选流→逐帧/QP→语法；音频选流→质量→MP3 导出全部通过。", streams.len());
    std::fs::remove_dir_all(root).unwrap();
}
