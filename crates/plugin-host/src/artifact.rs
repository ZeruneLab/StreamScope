use crate::{ArtifactReference, PluginError, Result, UiComponent, UiDocument};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskArtifact {
    pub id: String,
    pub sha256: String,
    pub byte_length: u64,
    pub relative_path: String,
    pub path: PathBuf,
}

pub struct ArtifactStore {
    report_root: PathBuf,
}

impl ArtifactStore {
    pub fn new(report_root: PathBuf) -> Self { Self { report_root } }

    pub fn report_directory(&self, directory: &Path) -> Result<PathBuf> {
        let directory = directory.canonicalize()?;
        if !directory.starts_with(self.report_root.canonicalize()?) || !directory.file_name().and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("report-")) { return Err(invalid("插件报告目录越界")); }
        Ok(directory)
    }

    pub fn import_report_file(&self, directory: &Path, source: &Path) -> Result<TaskArtifact> {
        let directory = self.report_directory(directory)?;
        let source = source.canonicalize()?;
        if !source.starts_with(directory) || !source.is_file() { return Err(invalid("联动样本文件越界")); }
        self.import_file(&source)
    }

    pub fn import_file(&self, source: &Path) -> Result<TaskArtifact> {
        self.import_file_with_progress(source, &mut |_, _| {})
    }

    pub fn import_file_with_progress(&self, source: &Path, progress: &mut dyn FnMut(u64, u64)) -> Result<TaskArtifact> {
        self.import_file_with_progress_and_cancel(source, progress, &|| false)
    }

    pub fn import_file_with_progress_and_cancel(&self, source: &Path, progress: &mut dyn FnMut(u64, u64), cancelled: &dyn Fn() -> bool) -> Result<TaskArtifact> {
        if cancelled() { return Err(invalid("任务已取消")); }
        let source = source.canonicalize()?;
        if !source.is_file() { return Err(invalid("所选输入不是常规文件")); }
        let size = fs::metadata(&source)?.len();
        if size > MAX_INPUT_BYTES { return Err(invalid("输入文件超过 16 GiB 上限")); }
        progress(0, size);
        if cancelled() { return Err(invalid("任务已取消")); }
        let directory = self.report_root.join(".artifacts");
        fs::create_dir_all(&directory)?;
        if source.starts_with(directory.canonicalize()?) {
            return Err(invalid("不能再次导入任务产物"));
        }
        let stage = directory.join(format!(".stage-{}", Uuid::new_v4()));
        let outcome = (|| {
            let mut input = File::open(&source)?;
            let mut output = OpenOptions::new().write(true).create_new(true).open(&stage)?;
            let mut hasher = Sha256::new();
            let mut copied = 0_u64;
            let mut last_reported = 0_u64;
            let mut buffer = [0_u8; 1024 * 1024];
            loop {
                if cancelled() { return Err(invalid("任务已取消")); }
                let count = input.read(&mut buffer)?;
                if count == 0 { break; }
                copied += count as u64;
                if copied > MAX_INPUT_BYTES { return Err(invalid("输入文件在复制期间超过 16 GiB 上限")); }
                hasher.update(&buffer[..count]);
                output.write_all(&buffer[..count])?;
                if copied.saturating_sub(last_reported) >= 64 * 1024 * 1024 || copied >= size {
                    progress(copied, size);
                    last_reported = copied;
                }
            }
            output.sync_all()?;
            drop(output);
            let hash = format!("{:x}", hasher.finalize());
            let extension = source.extension().and_then(|part| part.to_str())
                .filter(|part| part.len() <= 12 && part.bytes().all(|byte| byte.is_ascii_alphanumeric()))
                .map(str::to_ascii_lowercase).unwrap_or_else(|| "bin".into());
            let name = format!("sha256-{hash}.{extension}");
            let destination = directory.join(&name);
            if destination.exists() {
                verify_file(&destination, &hash, copied)?;
            } else if let Err(error) = fs::rename(&stage, &destination) {
                if destination.exists() { verify_file(&destination, &hash, copied)?; }
                else { return Err(error.into()); }
            }
            let mut permissions = fs::metadata(&destination)?.permissions();
            permissions.set_readonly(true);
            fs::set_permissions(&destination, permissions)?;
            Ok(TaskArtifact {
                id: format!("sha256:{hash}"), sha256: format!("sha256:{hash}"),
                byte_length: copied, relative_path: format!(".artifacts/{name}"), path: destination,
            })
        })();
        if stage.exists() { let _ = fs::remove_file(stage); }
        outcome
    }

    pub fn resolve(&self, artifact: &TaskArtifact) -> Result<PathBuf> {
        let expected = artifact.sha256.strip_prefix("sha256:").ok_or_else(|| invalid("产物摘要格式无效"))?;
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid("产物摘要格式无效"));
        }
        let path = self.report_root.join(&artifact.relative_path);
        let root = self.report_root.join(".artifacts").canonicalize()?;
        let actual = path.canonicalize()?;
        if !actual.starts_with(root) || !actual.is_file() { return Err(invalid("产物路径越界")); }
        verify_file(&actual, expected, artifact.byte_length)?;
        Ok(path)
    }

    pub fn resolve_reference(&self, reference: &ArtifactReference) -> Result<PathBuf> {
        if reference.id != reference.sha256 { return Err(invalid("产物 ID 与摘要不一致")); }
        let path = self.report_root.join(&reference.relative_path);
        let size = fs::metadata(&path)?.len();
        self.resolve(&TaskArtifact {
            id: reference.id.clone(), sha256: reference.sha256.clone(),
            byte_length: size, relative_path: reference.relative_path.clone(), path,
        })
    }

    // Reuse an immutable, content-addressed input returned by a prior task.
    // It is still rehashed; a path alone never bypasses integrity validation.
    pub fn existing_reference(&self, path: &Path) -> Result<Option<ArtifactReference>> {
        let directory = self.report_root.join(".artifacts");
        if !directory.exists() { return Ok(None); }
        let path = path.canonicalize()?;
        if path.parent() != Some(directory.canonicalize()?.as_path()) { return Ok(None); }
        let name = path.file_stem().and_then(|name| name.to_str()).and_then(|name| name.strip_prefix("sha256-"))
            .ok_or_else(|| invalid("任务产物名称无效"))?;
        if name.len() != 64 || !name.bytes().all(|byte| byte.is_ascii_hexdigit()) { return Err(invalid("任务产物摘要无效")); }
        verify_file(&path, name, fs::metadata(&path)?.len())?;
        Ok(Some(ArtifactReference {
            id: format!("sha256:{name}"), sha256: format!("sha256:{name}"), media_type: "application/octet-stream".into(),
            relative_path: format!(".artifacts/{}", path.file_name().unwrap().to_string_lossy()),
        }))
    }
}

pub fn stage_file_inputs(store: &ArtifactStore, ui: &UiDocument, view_id: &str, input: &mut Map<String, Value>) -> Result<Vec<ArtifactReference>> {
    stage_file_inputs_with_progress(store, ui, view_id, input, &mut |_, _, _| {})
}

pub fn stage_file_inputs_with_progress(store: &ArtifactStore, ui: &UiDocument, view_id: &str, input: &mut Map<String, Value>, progress: &mut dyn FnMut(&str, u64, u64)) -> Result<Vec<ArtifactReference>> {
    stage_file_inputs_with_progress_and_cancel(store, ui, view_id, input, progress, &|| false)
}

pub fn stage_file_inputs_with_progress_and_cancel(store: &ArtifactStore, ui: &UiDocument, view_id: &str, input: &mut Map<String, Value>, progress: &mut dyn FnMut(&str, u64, u64), cancelled: &dyn Fn() -> bool) -> Result<Vec<ArtifactReference>> {
    stage_linked_file_inputs(store, ui, view_id, input, &std::collections::BTreeMap::new(), progress, cancelled)
}

pub fn stage_linked_file_inputs(store: &ArtifactStore, ui: &UiDocument, view_id: &str, input: &mut Map<String, Value>, linked: &std::collections::BTreeMap<String, ArtifactReference>, progress: &mut dyn FnMut(&str, u64, u64), cancelled: &dyn Fn() -> bool) -> Result<Vec<ArtifactReference>> {
    let view = ui.views.iter().find(|view| view.id == view_id)
        .ok_or_else(|| invalid("插件界面视图不存在"))?;
    let mut references = Vec::new();
    let mut field_ids = Map::new();
    for component in &view.components {
        if let UiComponent::Input { id: field, input_type, required, .. } = component && input_type == "file" {
            if let Some(reference) = linked.get(field) {
                if cancelled() { return Err(invalid("任务已取消")); }
                let path = store.resolve_reference(reference)?;
                input.insert(field.clone(), Value::String(path.to_string_lossy().into_owned()));
                field_ids.insert(field.clone(), Value::String(reference.id.clone()));
                references.push(reference.clone());
                continue;
            }
            let source = input.get(field).and_then(Value::as_str).unwrap_or("");
            if source.is_empty() {
                if *required { return Err(invalid("缺少必需的文件输入")); }
                continue;
            }
            if let Some(reference) = store.existing_reference(Path::new(source))? {
                if cancelled() { return Err(invalid("任务已取消")); }
                field_ids.insert(field.clone(), Value::String(reference.id.clone()));
                references.push(reference);
                continue;
            }
            let artifact = store.import_file_with_progress_and_cancel(Path::new(source), &mut |copied, total| progress(field, copied, total), cancelled)?;
            let path = store.resolve(&artifact)?;
            input.insert(field.clone(), Value::String(path.to_string_lossy().into_owned()));
            field_ids.insert(field.clone(), Value::String(artifact.id.clone()));
            references.push(ArtifactReference {
                id: artifact.id, media_type: "application/octet-stream".into(),
                sha256: artifact.sha256, relative_path: artifact.relative_path,
            });
        }
    }
    if linked.keys().any(|field| !field_ids.contains_key(field)) { return Err(invalid("目标插件未声明联动文件输入")); }
    input.insert("_hostArtifacts".into(), Value::Object(field_ids));
    Ok(references)
}

pub fn stage_media_outputs(store: &ArtifactStore, result: &mut Value, references: &mut Vec<ArtifactReference>) -> Result<()> {
    let Some(report_directory) = result.get("reportDirectory").and_then(Value::as_str) else { return Ok(()); };
    let directory = Path::new(report_directory).canonicalize()?;
    let root = store.report_root.canonicalize()?;
    if !directory.starts_with(&root) || !directory.file_name().and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("report-")) {
        return Err(invalid("插件报告目录越界"));
    }
    let mut blocks = Vec::new();
    if let Some(source) = result.get("dataFile").and_then(Value::as_str).filter(|value| !value.is_empty()) {
        let path = Path::new(source).canonicalize()?;
        if !path.starts_with(&directory) || !path.is_file() { return Err(invalid("插件结果数据文件越界")); }
        let artifact = store.import_file(&path)?;
        result["dataArtifactId"] = serde_json::json!(artifact.id);
        references.push(ArtifactReference { id: artifact.id, media_type: "application/json".into(), sha256: artifact.sha256, relative_path: artifact.relative_path });
    }
    for (key, kind, title, media_type) in [
        ("previewAudio", "audio", "音频预览", "audio/wav"),
        ("previewVideo", "video", "视频预览", "video/mp4"),
    ] {
        let Some(source) = result.get(key).and_then(Value::as_str).filter(|value| !value.is_empty()) else { continue; };
        let path = Path::new(source).canonicalize()?;
        if !path.starts_with(&directory) || !path.is_file() { return Err(invalid("插件预览文件越界")); }
        let artifact = store.import_file(&path)?;
        blocks.push(serde_json::json!({"type":"media","title":title,"artifactId":artifact.id,"mediaType":kind}));
        references.push(ArtifactReference {
            id: artifact.id, media_type: media_type.into(), sha256: artifact.sha256,
            relative_path: artifact.relative_path,
        });
    }
    if let Some(source) = result.get("previewFrame").and_then(Value::as_str).filter(|value| !value.is_empty()) {
        let path = Path::new(source).canonicalize()?;
        if !path.starts_with(&directory) || !path.is_file() { return Err(invalid("插件帧图像越界")); }
        let artifact = store.import_file(&path)?;
        let object = result.as_object_mut().ok_or_else(|| invalid("插件结果必须是对象"))?;
        if let Some(blocks) = object.get_mut("blocks").and_then(Value::as_array_mut) {
            for block in blocks.iter_mut().filter(|block| block.get("type").and_then(Value::as_str) == Some("frameOverlay")) {
                if let Some(block) = block.as_object_mut() { block.insert("frameArtifactId".into(), Value::String(artifact.id.clone())); }
            }
        }
        references.push(ArtifactReference {
            id: artifact.id, media_type: "image/png".into(), sha256: artifact.sha256,
            relative_path: artifact.relative_path,
        });
    }
    if let Some(source) = result.get("downloadFile").and_then(Value::as_str).filter(|value| !value.is_empty()) {
        let path = Path::new(source).canonicalize()?;
        if !path.starts_with(&directory) || !path.is_file() { return Err(invalid("插件下载文件越界")); }
        let filename = path.file_name().and_then(|value| value.to_str()).unwrap_or("artifact.bin").to_owned();
        let artifact = store.import_file(&path)?;
        blocks.push(serde_json::json!({"type":"download","title":"另存导出文件","artifactId":artifact.id,"filename":filename}));
        references.push(ArtifactReference {
            id: artifact.id, media_type: "application/octet-stream".into(), sha256: artifact.sha256,
            relative_path: artifact.relative_path,
        });
    }
    if !blocks.is_empty() {
        let object = result.as_object_mut().ok_or_else(|| invalid("插件结果必须是对象"))?;
        if !object.get("blocks").is_some_and(Value::is_array) { object.insert("blocks".into(), Value::Array(Vec::new())); }
        object.get_mut("blocks").and_then(Value::as_array_mut).unwrap().extend(blocks);
    }
    Ok(())
}

fn verify_file(path: &Path, expected: &str, size: u64) -> Result<()> {
    let mut file = File::open(path)?;
    if file.metadata()?.len() != size { return Err(invalid("任务产物大小不一致")); }
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    if format!("{:x}", hasher.finalize()) != expected { return Err(invalid("任务产物摘要不一致")); }
    Ok(())
}

fn invalid(message: &str) -> PluginError { PluginError::Invalid(message.into()) }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UiView;

    #[test]
    fn imported_file_is_content_addressed_and_tampering_is_detected() {
        let root = std::env::temp_dir().join(format!("streamscope-artifact-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let source = root.join("source.pcap");
        fs::write(&source, b"capture").unwrap();
        let store = ArtifactStore::new(root.join("reports"));
        let first = store.import_file(&source).unwrap();
        let second = store.import_file(&source).unwrap();
        assert_eq!(first.path, second.path);
        assert_eq!(first.byte_length, 7);
        assert_eq!(store.resolve(&first).unwrap(), first.path);
        let mut permissions = fs::metadata(&first.path).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(&first.path, permissions).unwrap();
        fs::write(&first.path, b"changed").unwrap();
        assert!(store.resolve(&first).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn staging_replaces_user_path_and_returns_report_reference() {
        let root = std::env::temp_dir().join(format!("streamscope-artifact-stage-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let source = root.join("clip.h264");
        fs::write(&source, b"NALU").unwrap();
        let ui = UiDocument { schema_version: 1, views: vec![UiView {
            id: "main".into(), title: "Main".into(), components: vec![UiComponent::Input {
                id: "path".into(), label: "File".into(), input_type: "file".into(), required: true,
            }],
        }] };
        let mut input = Map::new();
        input.insert("path".into(), Value::String(source.to_string_lossy().into_owned()));
        let store = ArtifactStore::new(root.join("reports"));
        let mut progress = Vec::new();
        let refs = stage_file_inputs_with_progress(&store, &ui, "main", &mut input,
            &mut |field, copied, total| progress.push((field.to_owned(), copied, total))).unwrap();
        assert_eq!(refs.len(), 1);
        assert_ne!(input["path"], source.to_string_lossy().as_ref());
        assert!(Path::new(input["path"].as_str().unwrap()).is_file());
        assert!(refs[0].relative_path.starts_with(".artifacts/sha256-"));
        assert_eq!(input["_hostArtifacts"]["path"], refs[0].id);
        assert_eq!(progress.first(), Some(&("path".into(), 0, 4)));
        assert_eq!(progress.last(), Some(&("path".into(), 4, 4)));
        assert!(store.resolve_reference(&refs[0]).unwrap().is_file());
        let mut escaped = refs[0].clone();
        escaped.relative_path = "../clip.h264".into();
        assert!(store.resolve_reference(&escaped).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn repeated_workbench_input_reuses_verified_snapshot_but_rejects_modified_bytes() {
        let root = std::env::temp_dir().join(format!("streamscope-snapshot-reuse-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let source = root.join("capture.pcap"); fs::write(&source, b"capture").unwrap();
        let store = ArtifactStore::new(root.join("reports"));
        let artifact = store.import_file(&source).unwrap();
        let ui = UiDocument { schema_version: 1, views: vec![UiView { id: "main".into(), title: "Main".into(), components: vec![UiComponent::Input {
            id: "path".into(), label: "File".into(), input_type: "file".into(), required: true,
        }] }] };
        let mut input = Map::new(); input.insert("path".into(), serde_json::json!(artifact.path));
        let references = stage_file_inputs(&store, &ui, "main", &mut input).unwrap();
        assert_eq!(references[0].id, artifact.id);
        let mut permissions = fs::metadata(&artifact.path).unwrap().permissions(); permissions.set_readonly(false);
        fs::set_permissions(&artifact.path, permissions).unwrap(); fs::write(&artifact.path, b"changed").unwrap();
        assert!(stage_file_inputs(&store, &ui, "main", &mut input).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn complete_large_result_is_a_verified_artifact_and_cannot_escape_report() {
        let root = std::env::temp_dir().join(format!("streamscope-result-stage-{}", Uuid::new_v4()));
        let report = root.join("report-tool"); fs::create_dir_all(&report).unwrap();
        let file = report.join("data.json");
        let bytes = serde_json::to_vec(&serde_json::json!({"evidence":"x".repeat(5 * 1024 * 1024)})).unwrap();
        fs::write(&file, &bytes).unwrap();
        let store = ArtifactStore::new(root.clone());
        let mut result = serde_json::json!({"reportDirectory":report,"dataFile":file});
        let mut references = Vec::new();
        stage_media_outputs(&store, &mut result, &mut references).unwrap();
        assert_eq!(references[0].media_type, "application/json");
        assert_eq!(result["dataArtifactId"], references[0].id);
        assert_eq!(fs::read(store.resolve_reference(&references[0]).unwrap()).unwrap(), bytes);
        let outside = root.join("outside.json"); fs::write(&outside, b"{}").unwrap();
        result["dataFile"] = serde_json::json!(outside);
        assert!(stage_media_outputs(&store, &mut result, &mut Vec::new()).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn preview_is_imported_only_from_its_report_directory() {
        let root = std::env::temp_dir().join(format!("streamscope-preview-stage-{}", Uuid::new_v4()));
        let report = root.join("report-example");
        fs::create_dir_all(&report).unwrap();
        let audio = report.join("preview.wav");
        fs::write(&audio, b"RIFF").unwrap();
        let store = ArtifactStore::new(root.clone());
        let mut references = Vec::new();
        let mut result = serde_json::json!({"reportDirectory":report,"previewAudio":audio});
        stage_media_outputs(&store, &mut result, &mut references).unwrap();
        assert_eq!(references.len(), 1);
        assert_eq!(result["blocks"][0]["type"], "media");
        assert_eq!(result["blocks"][0]["artifactId"], references[0].id);
        result["previewAudio"] = serde_json::json!(root.join("other.wav"));
        fs::write(root.join("other.wav"), b"RIFF").unwrap();
        assert!(stage_media_outputs(&store, &mut result, &mut Vec::new()).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn frame_preview_requires_report_directory_and_is_bound_to_overlay() {
        let root = std::env::temp_dir().join(format!("streamscope-frame-stage-{}", Uuid::new_v4()));
        let report = root.join("report-example");
        fs::create_dir_all(&report).unwrap();
        let image = report.join("frame-0.png");
        fs::write(&image, [0x89, b'P', b'N', b'G']).unwrap();
        let store = ArtifactStore::new(root.clone());
        let mut result = serde_json::json!({"reportDirectory":report,"previewFrame":image,
            "blocks":[{"type":"frameOverlay","width":16,"height":16,"qp":[],"motionVectors":[]}]});
        let mut references = Vec::new();
        stage_media_outputs(&store, &mut result, &mut references).unwrap();
        assert_eq!(references.len(), 1);
        assert_eq!(result["blocks"][0]["frameArtifactId"], references[0].id);
        result["previewFrame"] = serde_json::json!(root.join("other.png"));
        fs::write(root.join("other.png"), [0x89, b'P', b'N', b'G']).unwrap();
        assert!(stage_media_outputs(&store, &mut result, &mut Vec::new()).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn download_output_is_bound_to_verified_artifact_and_cannot_escape_report() {
        let root = std::env::temp_dir().join(format!("streamscope-download-stage-{}", Uuid::new_v4()));
        let report = root.join("report-export");
        fs::create_dir_all(&report).unwrap();
        let file = report.join("audio.mp3");
        fs::write(&file, b"ID3").unwrap();
        let store = ArtifactStore::new(root.clone());
        let mut result = serde_json::json!({"reportDirectory":report,"downloadFile":file});
        let mut references = Vec::new();
        stage_media_outputs(&store, &mut result, &mut references).unwrap();
        assert_eq!(result["blocks"][0]["type"], "download");
        assert_eq!(result["blocks"][0]["artifactId"], references[0].id);
        assert_eq!(result["blocks"][0]["filename"], "audio.mp3");
        assert!(store.resolve_reference(&references[0]).unwrap().is_file());
        result["downloadFile"] = serde_json::json!(root.join("outside.mp3"));
        fs::write(root.join("outside.mp3"), b"ID3").unwrap();
        assert!(stage_media_outputs(&store, &mut result, &mut Vec::new()).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cancelled_import_does_not_leave_a_partial_artifact() {
        let root = std::env::temp_dir().join(format!("streamscope-artifact-cancel-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let source = root.join("clip.pcap");
        fs::write(&source, vec![1_u8; 2 * 1024 * 1024]).unwrap();
        let store = ArtifactStore::new(root.join("reports"));
        let calls = std::cell::Cell::new(0_u32);
        let result = store.import_file_with_progress_and_cancel(&source, &mut |_, _| calls.set(calls.get() + 1), &|| calls.get() > 0);
        assert!(result.unwrap_err().to_string().contains("取消"));
        assert!(!root.join("reports/.artifacts").exists());
        fs::remove_dir_all(root).unwrap();
    }
}
