use serde_json::json;
use std::path::Path;
use std::time::Duration;
use streamscope_plugin_host::PluginProcess;

#[test]
fn onvif_plugin_reports_validation_error_without_crashing_host() {
    let executable = Path::new(env!("CARGO_BIN_EXE_streamscope-plugin-onvif"));
    let mut process = PluginProcess::spawn(executable).unwrap();
    let error = process.request("execute", json!({"action":"diagnose","input":{"endpoint":""}}), Duration::from_secs(2), |_| {}).unwrap_err();
    assert!(error.to_string().contains("设备地址不能为空"));
}
