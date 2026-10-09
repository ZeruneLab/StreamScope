use serde_json::{Value, json};
use streamscope_onvif::{DiagnosticOptions, DiscoveryOptions, OnvifCredentials};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    streamscope_plugin_host::serve(execute)?;
    Ok(())
}

fn execute(action: &str, input: &Value) -> Result<Value, String> {
    let timeout_seconds = input["timeoutSeconds"].as_str().unwrap_or("10")
        .parse::<u64>().map_err(|_| "超时必须为整数秒".to_string())?;
    match action {
        "discover" => {
            let devices = streamscope_onvif::discover(DiscoveryOptions { timeout_seconds })
                .map_err(|error| error.to_string())?;
            let rows = devices.iter().map(|device| json!([
                device.endpoint_reference, device.xaddrs.join("; "), device.source
            ])).collect::<Vec<_>>();
            Ok(json!({
                "summary": format!("发现 {} 台设备", devices.len()),
                "blocks": [{"type":"table","title":"发现结果","columns":["设备 EPR","服务地址","来源"],"rows":rows}],
                "data": devices
            }))
        }
        "diagnose" => {
            let endpoint = input["endpoint"].as_str().unwrap_or("").trim().to_owned();
            if endpoint.is_empty() { return Err("设备地址不能为空".into()); }
            let username = input["username"].as_str().unwrap_or("").to_owned();
            let password = input["password"].as_str().unwrap_or("").to_owned();
            let credentials = (!username.is_empty()).then_some(OnvifCredentials { username, password });
            let result = streamscope_onvif::diagnose(DiagnosticOptions {
                endpoint,
                credentials,
                timeout_seconds,
                accept_invalid_certificates: input["acceptInvalidCertificates"].as_str() == Some("true"),
            }).map_err(|error| error.to_string())?;
            let operation_rows = result.operations.iter().map(|operation| json!([
                format!("{} / {}", operation.service, operation.operation), operation.status,
                operation.http_status, operation.elapsed_ms, operation.detail
            ])).collect::<Vec<_>>();
            let finding_rows = result.findings.iter().map(|finding| json!([
                finding.severity, finding.title, finding.evidence, finding.suggestion
            ])).collect::<Vec<_>>();
            Ok(json!({
                "summary": format!("验证 {} 个接口：{} 项诊断结论", result.operations.len(), result.findings.len()),
                "blocks": [
                    {"type":"table","title":"标准接口验证","columns":["接口","状态","HTTP","耗时 ms","原因"],"rows":operation_rows},
                    {"type":"table","title":"诊断结论","columns":["级别","问题","证据","建议"],"rows":finding_rows}
                ],
                "data": result
            }))
        }
        _ => Err("未声明的 ONVIF 动作".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_endpoint_fails_before_network() {
        assert!(execute("diagnose", &serde_json::json!({"endpoint":""})).is_err());
    }
}
