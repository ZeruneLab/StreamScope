use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct LegacyReport {
    report_path: String,
    generated_at: String,
    status: String,
    kind: &'static str,
}

// Deserialize only the summary; unknown analysis data is skipped without rewriting it.
#[derive(Deserialize)]
struct Summary {
    generated_at: String,
    status: String,
}

#[derive(Deserialize)]
struct Comparison {
    tcp: Summary,
    udp: Summary,
}

fn scan(root: &Path) -> Result<Vec<LegacyReport>, String> {
    if !root.exists() { return Ok(Vec::new()); }
    let root = root.canonicalize().map_err(|error| error.to_string())?;
    let mut reports = Vec::new();
    for entry in std::fs::read_dir(&root).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if !entry.file_name().to_string_lossy().starts_with("report-") { continue; }
        let Ok(directory) = entry.path().canonicalize() else { continue; };
        if !directory.starts_with(&root) || !directory.is_dir() { continue; }
        let candidates = [("result.json", "report.html", "analysis"), ("comparison.json", "comparison.html", "comparison")];
        for (json, html, kind) in candidates {
            let path = directory.join(json);
            let html = directory.join(html);
            let Ok(html) = html.canonicalize() else { continue; };
            if !html.starts_with(&root) || !html.is_file() { continue; }
            let Ok(path) = path.canonicalize() else { continue; };
            if !path.starts_with(&root) { continue; }
            let Ok(file) = std::fs::File::open(path) else { continue; };
            let reader = std::io::BufReader::new(file);
            let summary = if kind == "analysis" {
                serde_json::from_reader::<_, Summary>(reader)
            } else {
                serde_json::from_reader::<_, Comparison>(reader).map(|value| Summary {
                    generated_at: value.tcp.generated_at,
                    status: format!("TCP {} / UDP {}", value.tcp.status, value.udp.status),
                })
            };
            if let Ok(summary) = summary {
                reports.push(LegacyReport {
                    report_path: super::frontend_file_path(&html),
                    generated_at: summary.generated_at,
                    status: summary.status,
                    kind,
                });
            }
        }
    }
    reports.sort_by(|left, right| right.generated_at.cmp(&left.generated_at));
    Ok(reports)
}

#[tauri::command]
pub(super) fn list_legacy_reports(app: tauri::AppHandle) -> Result<Vec<LegacyReport>, String> {
    scan(&super::default_report_root(&app)?)
}

fn read_html(root: &Path, path: &Path) -> Result<String, String> {
    let root = root.canonicalize().map_err(|error| format!("报告根目录不可用：{error}"))?;
    let path = path.canonicalize().map_err(|error| format!("报告文件不可用：{error}"))?;
    if !path.starts_with(root)
        || !matches!(path.file_name().and_then(|name| name.to_str()), Some("report.html" | "comparison.html"))
    {
        return Err("只能预览 StreamScope HTML 报告".into());
    }
    std::fs::read_to_string(path).map_err(|error| format!("读取报告失败：{error}"))
}

#[tauri::command]
pub(super) fn load_report_html(app: tauri::AppHandle, report_path: String) -> Result<String, String> {
    read_html(&super::default_report_root(&app)?, &PathBuf::from(report_path))
}

fn save_artifact(source: &Path, destination: &Path, report_root: &Path, plugin_root: &Path) -> Result<String, String> {
    if !destination.is_absolute() || destination.file_name().is_none() {
        return Err("请选择完整的保存文件路径".into());
    }
    let parent = destination.parent().unwrap().canonicalize().map_err(|error| format!("保存目录不可用：{error}"))?;
    let destination = parent.join(destination.file_name().unwrap());
    for protected in [report_root, plugin_root] {
        if let Ok(protected) = protected.canonicalize() {
            if parent.starts_with(protected) { return Err("导出文件不能覆盖报告或插件目录".into()); }
        }
    }
    if destination.is_dir() { return Err("保存目标必须是文件".into()); }
    let temporary = parent.join(format!(".streamscope-export-{}", uuid::Uuid::new_v4()));
    let outcome = (|| {
        let mut input = std::fs::File::open(source).map_err(|error| error.to_string())?;
        let mut output = std::fs::OpenOptions::new().write(true).create_new(true).open(&temporary).map_err(|error| error.to_string())?;
        std::io::copy(&mut input, &mut output).map_err(|error| error.to_string())?;
        output.sync_all().map_err(|error| error.to_string())?;
        drop(output);
        std::fs::rename(&temporary, &destination).map_err(|error| format!("保存文件失败：{error}"))?;
        Ok(super::frontend_file_path(&destination))
    })();
    if outcome.is_err() { let _ = std::fs::remove_file(temporary); }
    outcome
}

#[cfg(any(test, not(feature = "compat")))]
fn analysis_directory(root: &Path, directory: &str, stream: Option<&str>) -> Result<PathBuf, String> {
    let root = root.canonicalize().map_err(|error| error.to_string())?;
    let directory = Path::new(directory).canonicalize().map_err(|error| error.to_string())?;
    if directory.parent() != Some(root.as_path()) || !directory.file_name().and_then(|name| name.to_str()).is_some_and(|name| name.starts_with("report-")) {
        return Err("只能操作单个 StreamScope 分析报告".into());
    }
    let selected = if let Some(stream) = stream.filter(|value| !value.is_empty()) {
        if !stream.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')) { return Err("媒体流 ID 无效".into()); }
        directory.join("streams").join(stream).canonicalize().map_err(|error| error.to_string())?
    } else { directory.clone() };
    if !selected.starts_with(&directory) { return Err("报告目录越界".into()); }
    Ok(selected)
}

#[cfg(any(test, not(feature = "compat")))]
fn read_json(path: &Path) -> Result<serde_json::Value, String> {
    if std::fs::metadata(path).map_err(|error| error.to_string())?.len() > 512 * 1024 * 1024 { return Err("报告超过读取上限".into()); }
    serde_json::from_reader(std::io::BufReader::new(std::fs::File::open(path).map_err(|error| error.to_string())?)).map_err(|error| error.to_string())
}

#[cfg(any(test, not(feature = "compat")))]
fn read_run(root: &Path, directory: &str, stream: Option<&str>) -> Result<serde_json::Value, String> {
    let directory = analysis_directory(root, directory, stream)?;
    let json = directory.join("result.json").canonicalize().map_err(|error| error.to_string())?;
    if !json.starts_with(&directory) { return Err("报告文件越界".into()); }
    let mut result = read_json(&json)?;
    // Only the returned workbench input is adjusted. Original report bytes stay unchanged.
    for name in ["sample.h264", "sample.h265"] {
        let sample = directory.join(name);
        if sample.is_file() { result["request"]["source_path"] = serde_json::json!(super::frontend_file_path(&sample)); break; }
    }
    Ok(serde_json::json!({"result":result,"report_directory":super::frontend_file_path(&directory),"reports":{
        "json":super::frontend_file_path(&json),"html":super::frontend_file_path(&directory.join("report.html")),
        "ffmpeg_log":super::frontend_file_path(&directory.join("ffmpeg.log")),
        "session_sdp":directory.join("session.sdp").is_file().then(|| super::frontend_file_path(&directory.join("session.sdp")))
    }}))
}

#[tauri::command]
#[cfg(not(feature = "compat"))]
pub(super) async fn read_analysis_report(app: tauri::AppHandle, report_directory: String, stream_id: Option<String>) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || read_run(&super::default_report_root(&app)?, &report_directory, stream_id.as_deref())).await.map_err(|error| error.to_string())?
}

#[tauri::command]
#[cfg(not(feature = "compat"))]
pub(super) async fn list_analysis_reports(app: tauri::AppHandle) -> Result<Vec<serde_json::Value>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let root = super::default_report_root(&app)?;
        let mut entries = Vec::new();
        for report in scan(&root)?.into_iter().filter(|report| report.kind == "analysis").take(20) {
            let directory = Path::new(&report.report_path).parent().ok_or("报告路径无效")?;
            let Ok(result) = read_json(&directory.join("result.json")) else { continue; };
            let critical = |result: &serde_json::Value| result["diagnostics"].as_array().into_iter().flatten().filter(|item| matches!(item["severity"].as_str(), Some("critical" | "high"))).count();
            let count = critical(&result) + result["streams"].as_array().into_iter().flatten().map(critical).sum::<usize>();
            entries.push(serde_json::json!({"generatedAt":report.generated_at,"sourceUrl":result["request"]["source_url"],"status":report.status,"reportDirectory":super::frontend_file_path(directory),"criticalCount":count}));
        }
        Ok(entries)
    }).await.map_err(|error| error.to_string())?
}

#[tauri::command]
#[cfg(not(feature = "compat"))]
pub(super) fn manage_analysis_report(app: tauri::AppHandle, state: tauri::State<'_, super::PluginState>, report_directory: String, operation: String) -> Result<(), String> {
    let guard = state.0.lock().map_err(|_| "插件状态锁异常")?;
    super::ensure_plugins_idle(&guard)?;
    let directory = analysis_directory(&super::default_report_root(&app)?, &report_directory, None)?;
    if !directory.join("result.json").is_file() && !directory.join("comparison.json").is_file() { return Err("不是分析报告目录".into()); }
    match operation.as_str() {
        "open" => std::process::Command::new("explorer.exe").arg(directory).spawn().map(|_| ()).map_err(|error| error.to_string()),
        "delete" => std::fs::remove_dir_all(directory).map_err(|error| error.to_string()),
        _ => Err("未知报告操作".into()),
    }
}

#[tauri::command]
#[cfg(not(feature = "compat"))]
pub(super) async fn save_report_file(app: tauri::AppHandle, source_path: String, destination_path: String) -> Result<String, String> {
    use tauri::Manager;
    let root = super::default_report_root(&app)?;
    let plugin_root = app.path().local_data_dir().map_err(|error| error.to_string())?.join("StreamScope/plugins");
    tauri::async_runtime::spawn_blocking(move || {
        let source = Path::new(&source_path).canonicalize().map_err(|error| error.to_string())?;
        if !source.starts_with(root.canonicalize().map_err(|error| error.to_string())?) || !source.is_file() { return Err("只能导出报告产物".into()); }
        save_artifact(&source, Path::new(&destination_path), &root, &plugin_root)
    }).await.map_err(|error| error.to_string())?
}

#[tauri::command]
#[cfg(not(feature = "compat"))]
pub(super) async fn read_analysis_attachment(app: tauri::AppHandle, report_directory: String, stream_id: String, kind: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        analysis_directory(&super::default_report_root(&app)?, &report_directory, stream_id.as_str().into())?;
        let reports = streamscope_plugin_host::list_all_plugin_reports(&super::plugin_reports_root(&app)?).map_err(|error| error.to_string())?;
        for report in reports {
            for saved in report.plugin_results.values() {
                let result = &saved.result;
                if result["sourceReport"] == report_directory && result["sourceStream"] == stream_id && result["operation"] == "compare_video_reference" {
                    return Ok(if kind == "comparison" {
                        if let Some(id) = result["dataArtifactId"].as_str() { read_data(&super::default_report_root(&app)?, &report, id)? } else { result["data"].clone() }
                    } else { result["previewVideo"].clone() });
                }
            }
        }
        Ok(serde_json::Value::Null)
    }).await.map_err(|error| error.to_string())?
}

#[cfg(not(feature = "compat"))]
fn read_data(root: &Path, report: &streamscope_plugin_host::PluginReportV2, id: &str) -> Result<serde_json::Value, String> {
    let reference = report.artifacts.iter().find(|reference| reference.id == id && reference.media_type == "application/json").ok_or("报告没有引用该 JSON 产物")?;
    let path = streamscope_plugin_host::ArtifactStore::new(root.to_path_buf()).resolve_reference(reference).map_err(|error| error.to_string())?;
    read_json(&path)
}

#[tauri::command]
#[cfg(not(feature = "compat"))]
pub(super) async fn stage_plugin_json(app: tauri::AppHandle, data: serde_json::Value) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let root = super::default_report_root(&app)?;
        std::fs::create_dir_all(&root).map_err(|error| error.to_string())?;
        let bytes = serde_json::to_vec(&data).map_err(|error| error.to_string())?;
        if bytes.len() > 512 * 1024 * 1024 { return Err("JSON 证据超过 512 MiB 上限".into()); }
        let temporary = root.join(format!(".json-input-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&temporary, bytes).map_err(|error| error.to_string())?;
        let imported = streamscope_plugin_host::ArtifactStore::new(root).import_file(&temporary).map_err(|error| error.to_string());
        let _ = std::fs::remove_file(&temporary);
        imported.map(|artifact| super::frontend_file_path(&artifact.path))
    }).await.map_err(|error| error.to_string())?
}

#[tauri::command]
#[cfg(not(feature = "compat"))]
pub(super) async fn read_plugin_data(app: tauri::AppHandle, report_id: String, artifact_id: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let report = super::read_workflow_report(&app, &report_id)?;
        read_data(&super::default_report_root(&app)?, &report, &artifact_id)
    }).await.map_err(|error| error.to_string())?
}

#[tauri::command]
pub(super) async fn export_plugin_artifact(app: tauri::AppHandle, report_id: String, artifact_id: String, destination_path: String) -> Result<String, String> {
    let report_root = super::default_report_root(&app)?;
    use tauri::Manager;
    let plugin_root = app.path().local_data_dir().map_err(|error| error.to_string())?.join("StreamScope/plugins");
    tauri::async_runtime::spawn_blocking(move || {
        let report = super::read_workflow_report(&app, &report_id)?;
        let reference = report.artifacts.iter().find(|reference| reference.id == artifact_id)
            .ok_or_else(|| "报告未引用该产物".to_string())?;
        let source = streamscope_plugin_host::ArtifactStore::new(report_root.clone()).resolve_reference(reference)
            .map_err(|error| error.to_string())?;
        save_artifact(&source, Path::new(&destination_path), &report_root, &plugin_root)
    }).await.map_err(|error| error.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interactive_report_read_keeps_all_old_data_and_never_rewrites_it() {
        let root = std::env::temp_dir().join(format!("streamscope-workbench-read-{}", uuid::Uuid::new_v4()));
        let directory = root.join("report-old"); let stream = directory.join("streams/video-1");
        std::fs::create_dir_all(&stream).unwrap();
        let bytes = br#"{"request":{"source_path":"old.pcap"},"protocol":{"transactions":[{"method":"PLAY","status_code":500}]},"h264":{"deep_analysis":{"frames":[{"display_index":0}]}},"unknown":{"preserved":true}}"#;
        std::fs::write(stream.join("result.json"), bytes).unwrap(); std::fs::write(stream.join("sample.h264"), [0,0,1,0x65]).unwrap();
        let loaded = read_run(&root, directory.to_str().unwrap(), Some("video-1")).unwrap();
        assert_eq!(loaded["result"]["protocol"]["transactions"][0]["status_code"], 500);
        assert_eq!(loaded["result"]["h264"]["deep_analysis"]["frames"][0]["display_index"], 0);
        assert_eq!(loaded["result"]["unknown"]["preserved"], true);
        assert!(loaded["result"]["request"]["source_path"].as_str().unwrap().ends_with("sample.h264"));
        assert_eq!(std::fs::read(stream.join("result.json")).unwrap(), bytes);
        assert!(read_run(&root, directory.to_str().unwrap(), Some("../video-1")).is_err());
        assert!(read_run(&root, stream.to_str().unwrap(), None).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn old_reports_are_read_without_modification_and_outside_files_are_rejected() {
        let root = std::env::temp_dir().join(format!("streamscope-core-reports-{}", uuid::Uuid::new_v4()));
        let directory = root.join("report-old");
        std::fs::create_dir_all(&directory).unwrap();
        let json = br#"{"generated_at":"2026-09-30T00:00:00Z","status":"partial","unknown":{"preserve":true}}"#;
        let html = "<html>original report</html>";
        std::fs::write(directory.join("result.json"), json).unwrap();
        std::fs::write(directory.join("report.html"), html).unwrap();
        let comparison = root.join("report-comparison");
        std::fs::create_dir_all(&comparison).unwrap();
        std::fs::write(comparison.join("comparison.json"), br#"{"tcp":{"generated_at":"2026-09-30T01:00:00Z","status":"completed"},"udp":{"generated_at":"2026-09-30T01:00:01Z","status":"failed"},"conclusions":[]}"#).unwrap();
        std::fs::write(comparison.join("comparison.html"), html).unwrap();
        let reports = scan(&root).unwrap();
        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0].kind, "comparison");
        assert_eq!(reports[0].status, "TCP completed / UDP failed");
        assert_eq!(reports[1].status, "partial");
        assert_eq!(read_html(&root, &directory.join("report.html")).unwrap(), html);
        assert_eq!(std::fs::read(directory.join("result.json")).unwrap(), json);
        assert_eq!(std::fs::read_to_string(directory.join("report.html")).unwrap(), html);
        assert!(read_html(&directory, &comparison.join("comparison.html")).is_err());
        assert!(read_html(&root, &directory.join("result.json")).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn artifact_export_is_complete_and_cannot_replace_report_data() {
        let root = std::env::temp_dir().join(format!("streamscope-artifact-export-{}", uuid::Uuid::new_v4()));
        let reports = root.join("reports");
        let plugins = root.join("plugins");
        std::fs::create_dir_all(&reports).unwrap();
        std::fs::create_dir_all(&plugins).unwrap();
        let source = reports.join("source.wav");
        std::fs::write(&source, b"audio evidence").unwrap();
        let destination = root.join("export.wav");
        std::fs::write(&destination, b"old export").unwrap();
        save_artifact(&source, &destination, &reports, &plugins).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"audio evidence");
        assert!(save_artifact(&source, &source, &reports, &plugins).is_err());
        assert!(save_artifact(&source, &plugins.join("plugin.exe"), &reports, &plugins).is_err());
        assert!(save_artifact(&source, Path::new("relative.wav"), &reports, &plugins).is_err());
        assert_eq!(std::fs::read(&source).unwrap(), b"audio evidence");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn workflow_failure_keeps_analysis_and_does_not_publish_partial_links() {
        let root = std::env::temp_dir().join(format!("streamscope-workflow-failure-{}", uuid::Uuid::new_v4()));
        let directory = root.join("report-test");
        std::fs::create_dir_all(directory.join("streams/valid")).unwrap();
        std::fs::write(directory.join("streams/valid/sample.h264"), [0, 0, 1, 0x65]).unwrap();
        std::fs::write(directory.join("result.json"), br#"{"streams":[{"capture_stream":{"id":"valid","codec":"h264"},"tools":[{}]},{"capture_stream":{"id":"../bad"}}]}"#).unwrap();
        let store = streamscope_plugin_host::ArtifactStore::new(root.clone());
        let mut result = serde_json::json!({"reportDirectory":directory,"summary":"原分析完成","blocks":[{"type":"text","text":"原证据"}]});
        let mut references = Vec::new();
        super::super::enrich_workflow_result(&store, "org.streamscope.pcap", &mut result, &mut references);
        assert_eq!(result["summary"], "原分析完成");
        assert_eq!(result["blocks"].as_array().unwrap().len(), 1);
        assert_eq!(result["blocks"][0]["text"], "原证据");
        assert!(result["hostActions"].is_null());
        assert!(result["hostWorkflowWarning"].as_str().unwrap().contains("结果保留"));
        assert!(references.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }
}
