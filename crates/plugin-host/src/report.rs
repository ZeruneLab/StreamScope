use crate::{InstalledPlugin, PluginError, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginReportV2 {
    pub schema_version: u32,
    pub report_id: String,
    pub generated_at: String,
    pub summary: String,
    pub evidence: Vec<Value>,
    pub timeline: Vec<Value>,
    pub artifacts: Vec<ArtifactReference>,
    pub plugin_results: BTreeMap<String, VersionedPluginResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionedPluginResult {
    pub plugin_version: String,
    pub action: String,
    pub result: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactReference {
    pub id: String,
    pub media_type: String,
    pub sha256: String,
    pub relative_path: String,
}

pub fn save_plugin_report(root: &Path, plugin: &InstalledPlugin, action: &str, result: &Value) -> Result<PathBuf> {
    save_plugin_report_with_artifacts(root, plugin, action, result, &[])
}

pub fn save_plugin_report_with_artifacts(root: &Path, plugin: &InstalledPlugin, action: &str, result: &Value, artifacts: &[ArtifactReference]) -> Result<PathBuf> {
    fs::create_dir_all(root)?;
    let id = Uuid::new_v4().to_string();
    let directory = root.join(format!("plugin-report-{id}"));
    let stage = root.join(format!(".plugin-report-{id}"));
    fs::create_dir(&stage)?;
    let outcome = (|| {
        let mut plugin_results = BTreeMap::new();
        let mut redacted = result.clone();
        redact_secrets(&mut redacted);
        let summary = redacted.get("summary").and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .map(|text| text.chars().take(512).collect())
            .unwrap_or_else(|| format!("{} · {}", plugin.manifest.name, action));
        let evidence = redacted.get("evidence").and_then(Value::as_array)
            .map(|items| items.iter().take(10_000).cloned().collect()).unwrap_or_default();
        let timeline = redacted.get("timeline").and_then(Value::as_array)
            .map(|items| items.iter().take(10_000).cloned().collect()).unwrap_or_default();
        plugin_results.insert(plugin.manifest.id.clone(), VersionedPluginResult {
            plugin_version: plugin.manifest.version.clone(), action: action.into(), result: redacted,
        });
        let report = PluginReportV2 {
            schema_version: 2,
            report_id: id,
            generated_at: Utc::now().to_rfc3339(),
            summary, evidence, timeline, artifacts: artifacts.to_vec(), plugin_results,
        };
        let mut file = File::create(stage.join("report.json"))?;
        file.write_all(&serde_json::to_vec_pretty(&report)?)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&stage, &directory)?;
        Ok(directory.clone())
    })();
    if stage.exists() { let _ = fs::remove_dir_all(stage); }
    outcome
}

pub fn load_plugin_report(root: &Path, id: &str) -> Result<PluginReportV2> {
    Uuid::parse_str(id).map_err(|_| invalid("报告 ID 无效"))?;
    let path = root.join(format!("plugin-report-{id}")).join("report.json");
    let report: PluginReportV2 = serde_json::from_reader(File::open(path)?)?;
    if report.schema_version != 2 || report.report_id != id {
        return Err(invalid("报告容器版本或 ID 不匹配"));
    }
    Ok(report)
}

pub fn list_plugin_reports(root: &Path) -> Result<Vec<PluginReportV2>> {
    let mut reports = list_all_plugin_reports(root)?;
    reports.truncate(20);
    Ok(reports)
}

// Historical attachments must remain addressable beyond the recent-report list.
pub fn list_all_plugin_reports(root: &Path) -> Result<Vec<PluginReportV2>> {
    if !root.exists() { return Ok(Vec::new()); }
    let mut reports = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(id) = name.strip_prefix("plugin-report-") else { continue; };
        if let Ok(report) = load_plugin_report(root, id) { reports.push(report); }
    }
    reports.sort_by(|left, right| right.generated_at.cmp(&left.generated_at));
    Ok(reports)
}

fn redact_secrets(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let lower = key.to_ascii_lowercase();
                if lower.contains("password") || lower.contains("authorization") || lower.contains("secret") {
                    *child = Value::String("[REDACTED]".into());
                } else {
                    redact_secrets(child);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_secrets),
        Value::String(text) => {
            if let Ok(mut url) = url::Url::parse(text)
                && (url.password().is_some() || !url.username().is_empty()) {
                let _ = url.set_username("");
                let _ = url.set_password(None);
                *text = url.to_string();
            }
        }
        _ => {},
    }
}

fn invalid(message: &str) -> PluginError { PluginError::Invalid(message.into()) }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Manifest, Publisher, Ui};

    #[test]
    fn v2_report_survives_without_plugin_and_redacts_passwords() {
        let root = std::env::temp_dir().join(format!("streamscope-plugin-report-{}", Uuid::new_v4()));
        let plugin = InstalledPlugin {
            manifest: Manifest {
                schema_version: 1, kind: "feature".into(), id: "org.example.demo".into(), name: "Demo".into(), version: "1.0.0".into(),
                publisher: Publisher { id: "org.example".into(), key_fingerprint: String::new() }, host_api: "^1".into(),
                platforms: vec![], contributions: vec![], ui: Ui { kind: "declarative".into(), file: "ui.json".into() },
                permissions: vec![], dependencies: vec![], files: BTreeMap::new(), description: None, license: None,
            }, fingerprint: String::new(), enabled: true,
        };
        let path = save_plugin_report(&root, &plugin, "run", &serde_json::json!({
            "summary":"检查完成", "password":"abc", "uri":"rtsp://user:pass@camera/stream",
            "evidence":[{"authorization":"Digest secret"}], "timeline":[{"offsetMs":10,"label":"响应"}]
        })).unwrap();
        let id = path.file_name().unwrap().to_string_lossy().trim_start_matches("plugin-report-").to_owned();
        let loaded = load_plugin_report(&root, &id).unwrap();
        let data = &loaded.plugin_results["org.example.demo"].result;
        assert_eq!(data["password"], "[REDACTED]");
        assert_eq!(data["uri"], "rtsp://camera/stream");
        assert_eq!(loaded.summary, "检查完成");
        assert_eq!(loaded.evidence[0]["authorization"], "[REDACTED]");
        assert_eq!(loaded.timeline[0]["offsetMs"], 10);
        for _ in 0..20 { save_plugin_report(&root, &plugin, "later", &serde_json::json!({"summary":"后续任务"})).unwrap(); }
        assert_eq!(list_plugin_reports(&root).unwrap().len(), 20);
        let all = list_all_plugin_reports(&root).unwrap();
        assert_eq!(all.len(), 21);
        assert!(all.iter().any(|report| report.report_id == id));
        fs::remove_dir_all(root).unwrap();
    }
}
