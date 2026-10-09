//! Bridges the existing report schema into host-managed plugin continuations.
//! No protocol parsing or media decoding belongs here.
use crate::{ArtifactReference, ArtifactStore, PluginError, PluginReportV2, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

// Deserialize only workflow metadata. RTP/NALU/sample evidence stays in the
// original report and is skipped by the streaming reader, not copied into memory.
#[derive(Deserialize)]
struct WorkflowReport {
    #[serde(default)] streams: Vec<WorkflowStream>,
    preview_audio: Option<String>,
    #[serde(default)] audio_tracks: Vec<WorkflowAudioTrack>,
}
#[derive(Deserialize)]
struct WorkflowStream {
    capture_stream: Option<WorkflowIdentity>,
    #[serde(default)] tools: Vec<Value>,
    preview_video: Option<String>,
    preview_audio: Option<String>,
}
#[derive(Deserialize)]
struct WorkflowIdentity {
    id: String,
    codec: Option<String>,
    #[serde(default)] source: String,
    #[serde(default)] destination: String,
}
#[derive(Deserialize)]
struct WorkflowAudioTrack {
    preview_audio: Option<String>,
    codec: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowAction {
    pub id: String,
    pub title: String,
    pub plugin_id: String,
    pub action: String,
    pub input: BTreeMap<String, String>,
    pub artifact_inputs: BTreeMap<String, String>,
    pub context: String,
}

pub fn workflow_action(report: &PluginReportV2, id: &str) -> Result<WorkflowAction> {
    if id.is_empty() || id.len() > 160 { return Err(invalid("联动动作 ID 无效")); }
    for result in report.plugin_results.values() {
        if let Some(actions) = result.result.get("hostActions").and_then(Value::as_array) {
            if let Some(value) = actions.iter().find(|action| action["id"].as_str() == Some(id)) {
                return Ok(serde_json::from_value(value.clone())?);
            }
        }
    }
    Err(invalid("来源报告未提供该联动动作"))
}

pub fn linked_references(report: &PluginReportV2, action: &WorkflowAction) -> Result<BTreeMap<String, ArtifactReference>> {
    action.artifact_inputs.iter().map(|(field, id)| {
        let reference = report.artifacts.iter().find(|reference| reference.id == *id)
            .ok_or_else(|| invalid("来源报告未引用该联动产物"))?;
        Ok((field.clone(), reference.clone()))
    }).collect()
}

fn action(id: &str, title: &str, plugin: &str, operation: &str, artifact: &ArtifactReference, context: &str) -> WorkflowAction {
    WorkflowAction { id: id.into(), title: title.into(), plugin_id: format!("org.streamscope.{plugin}"), action: operation.into(),
        input: BTreeMap::new(), artifact_inputs: BTreeMap::from([("path".into(), artifact.id.clone())]), context: context.into() }
}

fn register(store: &ArtifactStore, directory: &Path, path: &Path, kind: &str, refs: &mut Vec<ArtifactReference>) -> Result<ArtifactReference> {
    let artifact = store.import_report_file(directory, path)?;
    let reference = ArtifactReference { id: artifact.id, sha256: artifact.sha256, relative_path: artifact.relative_path, media_type: kind.into() };
    if !refs.iter().any(|existing| existing.id == reference.id) { refs.push(reference.clone()); }
    Ok(reference)
}

fn add_group(result: &mut Value, title: &str, actions: &[WorkflowAction]) {
    if actions.is_empty() { return; }
    result["blocks"].as_array_mut().unwrap().push(json!({"type":"actions","hostWorkflow":true,"title":title,
        "actions":actions.iter().map(|action| json!({"id":action.id,"title":action.title,"pluginId":action.plugin_id})).collect::<Vec<_>>()}));
}

fn video_actions(store: &ArtifactStore, directory: &Path, source: &Path, codec: &str, label: &str, id: &str, refs: &mut Vec<ArtifactReference>) -> Result<Vec<WorkflowAction>> {
    let reference = register(store, directory, source, &format!("video/{codec}"), refs)?;
    let mut deep = action(&format!("{id}-frame"), "视频逐帧深度分析 / QP / 运动矢量", "video-deep", "inspect-frame", &reference, label);
    deep.input.insert("displayIndex".into(), "0".into());
    Ok(vec![deep, action(&format!("{id}-syntax"), "NALU 语法 / HEX", codec, "inspect-nalus", &reference, label)])
}

fn audio_actions(store: &ArtifactStore, directory: &Path, source: &Path, label: &str, id: &str, refs: &mut Vec<ArtifactReference>) -> Result<Vec<WorkflowAction>> {
    let reference = register(store, directory, source, "audio/wav", refs)?;
    let mut export = action(&format!("{id}-export"), "音频格式 / 区间导出", "audio", "export-audio", &reference, label);
    export.input.insert("format".into(), "wav".into());
    Ok(vec![action(&format!("{id}-audio"), "音频深度 / 质量分析", "audio", "analyze", &reference, label), export])
}

pub fn attach_report_workflows(store: &ArtifactStore, plugin_id: &str, result: &mut Value, refs: &mut Vec<ArtifactReference>) -> Result<()> {
    // These adapters preserve workflows for already installed migration plugins;
    // they inspect their saved data, not their private implementation or processes.
    if !matches!(plugin_id, "org.streamscope.pcap" | "org.streamscope.rtsp" | "org.streamscope.h264" | "org.streamscope.h265" | "org.streamscope.audio") { return Ok(()); }
    let Some(directory) = result["reportDirectory"].as_str().map(std::path::PathBuf::from) else { return Ok(()); };
    let directory = store.report_directory(&directory)?;
    let path = directory.join("result.json");
    if !path.is_file() { return Ok(()); }
    let path = path.canonicalize()?;
    if !path.starts_with(&directory) || std::fs::metadata(&path)?.len() > 512 * 1024 * 1024 { return Err(invalid("联动报告路径越界或超过 512 MiB 上限")); }
    let analysis: WorkflowReport = serde_json::from_reader(std::io::BufReader::with_capacity(256 * 1024, std::fs::File::open(path)?))?;
    if !result["blocks"].is_array() { result["blocks"] = json!([]); }
    // Replace only host-generated groups when reopening a report; keep plugin blocks.
    result["blocks"].as_array_mut().unwrap().retain(|block| block["hostWorkflow"] != true);
    let input = refs.first().cloned();
    let mut all_actions = Vec::new();
    if plugin_id == "org.streamscope.pcap" {
        for stream in analysis.streams.iter().take(2000) {
            let Some(identity) = &stream.capture_stream else { continue; };
            let id = identity.id.as_str();
            if id.is_empty() || id.len() > 80 || !id.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')) { return Err(invalid("联动流 ID 无效")); }
            let codec = identity.codec.as_deref().unwrap_or("unknown");
            let codec = if codec.eq_ignore_ascii_case("hevc") { "h265" } else { codec };
            let label = format!("{id} · {codec} · {} → {}", identity.source, identity.destination);
            let mut actions = Vec::new();
            if let Some(input) = &input {
                let mut selected = action(&format!("{id}-select"), "深入分析此流（重组 / 解码 / 预览）", "pcap", "analyze", input, &label);
                selected.input.insert("streamIds".into(), id.into());
                actions.push(selected);
            }
            // Scan-only results must first use the original PCAP analyzer's selected-stream path.
            let analyzed = !stream.tools.is_empty();
            let sample = directory.join("streams").join(id).join(format!("sample.{codec}"));
            if analyzed && matches!(codec, "h264" | "h265") && sample.is_file() {
                actions.extend(video_actions(store, &directory, &sample, codec, &label, id, refs)?);
                if let Some(preview) = &stream.preview_video {
                    let reference = register(store, &directory, Path::new(preview), "video/mp4", refs)?;
                    result["blocks"].as_array_mut().unwrap().push(json!({"type":"media","hostWorkflow":true,"title":format!("{id} 视频预览"),"mediaType":"video","artifactId":reference.id}));
                }
            }
            if analyzed && let Some(preview) = &stream.preview_audio {
                actions.extend(audio_actions(store, &directory, Path::new(preview), &label, id, refs)?);
                let reference = register(store, &directory, Path::new(preview), "audio/wav", refs)?;
                result["blocks"].as_array_mut().unwrap().push(json!({"type":"media","hostWorkflow":true,"title":format!("{id} 音频预览"),"mediaType":"audio","artifactId":reference.id}));
            }
            add_group(result, &label, &actions);
            all_actions.extend(actions);
        }
    } else {
        let label = "同源媒体样本";
        if matches!(plugin_id, "org.streamscope.h264" | "org.streamscope.h265") && let Some(input) = &input {
            let codec = plugin_id.rsplit('.').next().unwrap();
            let mut deep = action("source-frame", "视频逐帧深度分析 / QP / 运动矢量", "video-deep", "inspect-frame", input, label);
            deep.input.insert("displayIndex".into(), "0".into());
            all_actions.push(deep);
            all_actions.push(action("source-syntax", "NALU 语法 / HEX", codec, "inspect-nalus", input, label));
        }
        if plugin_id == "org.streamscope.rtsp" {
            for codec in ["h264", "h265"] {
                let sample = directory.join(format!("sample.{codec}"));
                if sample.is_file() { all_actions.extend(video_actions(store, &directory, &sample, codec, label, "source", refs)?); }
            }
        }
        if let Some(preview) = &analysis.preview_audio {
            all_actions.extend(audio_actions(store, &directory, Path::new(preview), label, "source", refs)?);
        }
        for (index, track) in analysis.audio_tracks.iter().enumerate() {
            if let Some(preview) = &track.preview_audio {
                let id = format!("track-{index}");
                let label = format!("音频轨 {} · {}", index + 1, track.codec.as_deref().unwrap_or(""));
                let actions = audio_actions(store, &directory, Path::new(preview), &label, &id, refs)?;
                add_group(result, &label, &actions);
                all_actions.extend(actions);
            }
        }
        let source_actions = all_actions.iter().filter(|action| action.id.starts_with("source-")).cloned().collect::<Vec<_>>();
        add_group(result, "继续分析同源样本", &source_actions);
    }
    result["hostActions"] = serde_json::to_value(all_actions)?;
    Ok(())
}

fn invalid(message: &str) -> PluginError { PluginError::Invalid(message.into()) }

pub fn validate_media_input(plugin_id: &str, input: &Value) -> Result<()> {
    if !matches!(plugin_id, "org.streamscope.h264" | "org.streamscope.h265" | "org.streamscope.audio" | "org.streamscope.video-deep") { return Ok(()); }
    let Some(path) = input["path"].as_str() else { return Ok(()); };
    use std::io::Read;
    let mut bytes = [0_u8; 4];
    if std::fs::File::open(path)?.read(&mut bytes)? == 4 && matches!(bytes,
        [0xd4, 0xc3, 0xb2, 0xa1] | [0xa1, 0xb2, 0xc3, 0xd4] | [0x4d, 0x3c, 0xb2, 0xa1] | [0xa1, 0xb2, 0x3c, 0x4d] | [0x0a, 0x0d, 0x0d, 0x0a]) {
        return Err(invalid("抓包文件不能直接作为视频或音频解码输入。请在 PCAP 分析结果中选择媒体流，点击深入分析，再继续视频或音频深度分析。"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{UiDocument, stage_linked_file_inputs};

    #[test]
    fn mixed_streams_link_only_their_own_samples_and_keep_scan_input() {
        let root = std::env::temp_dir().join(format!("streamscope-workflow-{}", uuid::Uuid::new_v4()));
        let directory = root.join("report-mixed");
        std::fs::create_dir_all(directory.join("streams/video-a")).unwrap();
        std::fs::create_dir_all(directory.join("streams/video-b")).unwrap();
        std::fs::create_dir_all(directory.join("streams/audio-c")).unwrap();
        std::fs::create_dir_all(directory.join("streams/video-d")).unwrap();
        let capture = root.join("input.pcap");
        std::fs::write(&capture, [0xd4, 0xc3, 0xb2, 0xa1]).unwrap();
        std::fs::write(directory.join("streams/video-a/sample.h264"), [0, 0, 1, 0x65]).unwrap();
        std::fs::write(directory.join("streams/video-b/sample.h265"), [0, 0, 1, 0x26]).unwrap();
        std::fs::write(directory.join("streams/video-d/sample.h265"), [0, 0, 1, 0x26, 1]).unwrap();
        let audio = directory.join("streams/audio-c/preview.wav");
        std::fs::write(&audio, b"RIFFwave").unwrap();
        let data = json!({"streams":[
            {"capture_stream":{"id":"video-a","codec":"h264"},"tools":[{}]},
            {"capture_stream":{"id":"video-b","codec":"hevc"},"tools":[]},
            {"capture_stream":{"id":"audio-c","codec":"pcmu"},"tools":[{}],"preview_audio":audio},
            {"capture_stream":{"id":"video-d","codec":"hevc"},"tools":[{}]}
        ]});
        let bytes = serde_json::to_vec(&data).unwrap();
        std::fs::write(directory.join("result.json"), &bytes).unwrap();
        let store = ArtifactStore::new(root.clone());
        let initial = store.import_file(&capture).unwrap();
        let mut references = vec![ArtifactReference { id: initial.id, sha256: initial.sha256, relative_path: initial.relative_path, media_type: "application/octet-stream".into() }];
        let capture_id = references[0].id.clone();
        let mut result = json!({"reportDirectory":directory,"blocks":[{"type":"text","text":"retain"}]});
        attach_report_workflows(&store, "org.streamscope.pcap", &mut result, &mut references).unwrap();
        let actions: Vec<WorkflowAction> = serde_json::from_value(result["hostActions"].clone()).unwrap();
        assert_eq!(actions.len(), 10);
        assert!(actions.iter().filter(|action| action.action == "analyze" && action.plugin_id == "org.streamscope.pcap").all(|action| action.artifact_inputs["path"] == capture_id));
        assert!(!actions.iter().any(|action| action.id == "video-b-frame"));
        assert_eq!(actions.iter().find(|action| action.id == "video-d-syntax").unwrap().plugin_id, "org.streamscope.h265");
        let deep = actions.iter().find(|action| action.id == "video-a-frame").unwrap();
        let audio = actions.iter().find(|action| action.id == "audio-c-audio").unwrap();
        assert_ne!(deep.artifact_inputs["path"], capture_id);
        assert_ne!(deep.artifact_inputs["path"], audio.artifact_inputs["path"]);
        let block_count = result["blocks"].as_array().unwrap().len();
        attach_report_workflows(&store, "org.streamscope.pcap", &mut result, &mut references).unwrap();
        assert_eq!(result["blocks"].as_array().unwrap().len(), block_count);
        assert_eq!(references.len(), 4);
        assert_eq!(std::fs::read(directory.join("result.json")).unwrap(), bytes);

        let reference = references.iter().find(|reference| reference.id == deep.artifact_inputs["path"]).unwrap().clone();
        let ui: UiDocument = serde_json::from_value(json!({"schemaVersion":1,"views":[{"id":"main","title":"Frame","components":[
            {"type":"input","id":"path","label":"File","inputType":"file","required":true}]}]})).unwrap();
        let linked = BTreeMap::from([("path".into(), reference.clone())]);
        let mut fields = serde_json::Map::from_iter([("path".into(), json!(capture))]);
        stage_linked_file_inputs(&store, &ui, "main", &mut fields, &linked, &mut |_, _, _| {}, &|| false).unwrap();
        assert!(fields["path"].as_str().unwrap().ends_with(".h264"));
        validate_media_input("org.streamscope.video-deep", &Value::Object(fields.clone())).unwrap();
        assert!(validate_media_input("org.streamscope.video-deep", &json!({"path":capture})).unwrap_err().to_string().contains("PCAP"));
        let unsupported = BTreeMap::from([("undeclared".into(), reference.clone())]);
        fields.insert("path".into(), json!(capture));
        assert!(stage_linked_file_inputs(&store, &ui, "main", &mut fields, &unsupported, &mut |_, _, _| {}, &|| false).is_err());
        let path = store.resolve_reference(&reference).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(&path, permissions).unwrap();
        std::fs::write(&path, b"tampered").unwrap();
        assert!(stage_linked_file_inputs(&store, &ui, "main", &mut fields, &linked, &mut |_, _, _| {}, &|| false).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn many_streams_remain_individually_addressable_and_escape_is_rejected() {
        let root = std::env::temp_dir().join(format!("streamscope-workflow-many-{}", uuid::Uuid::new_v4()));
        let directory = root.join("report-scan");
        std::fs::create_dir_all(&directory).unwrap();
        let capture = root.join("input.pcapng");
        std::fs::write(&capture, [0x0a, 0x0d, 0x0d, 0x0a]).unwrap();
        let store = ArtifactStore::new(root.clone());
        let imported = store.import_file(&capture).unwrap();
        let mut references = vec![ArtifactReference { id: imported.id, sha256: imported.sha256, relative_path: imported.relative_path, media_type: "application/octet-stream".into() }];
        let streams = (0..600).map(|index| json!({"capture_stream":{"id":format!("stream-{index}"),"codec":"h264"},"tools":[]})).collect::<Vec<_>>();
        std::fs::write(directory.join("result.json"), serde_json::to_vec(&json!({"streams":streams})).unwrap()).unwrap();
        let mut result = json!({"reportDirectory":directory});
        attach_report_workflows(&store, "org.streamscope.pcap", &mut result, &mut references).unwrap();
        assert_eq!(result["hostActions"].as_array().unwrap().len(), 600);
        assert_eq!(result["hostActions"][599]["input"]["streamIds"], "stream-599");
        assert!(store.import_report_file(&directory, &capture).is_err());
        std::fs::write(directory.join("result.json"), br#"{"streams":[{"capture_stream":{"id":"../escape"}}]}"#).unwrap();
        assert!(attach_report_workflows(&store, "org.streamscope.pcap", &mut result, &mut references).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
