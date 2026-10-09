use serde_json::{Value, json};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};

#[cfg(windows)]
struct ChildJob(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl ChildJob {
    fn attach(child: &Child) -> Result<Self, String> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            SetInformationJobObject,
        };
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() { return Err(format!("无法创建 SIP 执行器作业：{}", std::io::Error::last_os_error())); }
        let job = Self(handle);
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe { SetInformationJobObject(handle, JobObjectExtendedLimitInformation,
            &limits as *const _ as *const _, std::mem::size_of_val(&limits) as u32) };
        if configured == 0 { return Err(format!("无法配置 SIP 执行器作业：{}", std::io::Error::last_os_error())); }
        let assigned = unsafe { AssignProcessToJobObject(handle, child.as_raw_handle()) };
        if assigned == 0 { return Err(format!("无法约束 SIP 执行器子进程：{}", std::io::Error::last_os_error())); }
        Ok(job)
    }
}

#[cfg(windows)]
impl Drop for ChildJob {
    fn drop(&mut self) { unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0); } }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    streamscope_plugin_host::serve(execute)?;
    Ok(())
}

fn execute(action: &str, input: &Value) -> Result<Value, String> {
    let mut result = execute_inner(action, input)?;
    if let Some(data) = result.get("data") && serde_json::to_vec(data).map_err(|error| error.to_string())?.len() > 512 * 1024 {
        let root = input["_hostOutputRoot"].as_str().ok_or("宿主未提供报告目录")?;
        let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|error| error.to_string())?.as_nanos();
        let directory = Path::new(root).join(format!("report-sip-data-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        let file = directory.join("data.json");
        std::fs::write(&file, serde_json::to_vec(data).map_err(|error| error.to_string())?).map_err(|error| error.to_string())?;
        result.as_object_mut().unwrap().remove("data");
        result["reportDirectory"] = json!(directory); result["dataFile"] = json!(file);
    }
    Ok(result)
}

fn execute_inner(action: &str, input: &Value) -> Result<Value, String> {
    if action == "probe" {
        let address: SocketAddr = input["target"].as_str().unwrap_or("").parse().map_err(|_| "目标地址必须是 IP:端口".to_string())?;
        let transport = input["transport"].as_str().unwrap_or("udp");
        if !matches!(transport, "udp" | "tcp" | "tls") { return Err("传输必须是 udp、tcp 或 tls".into()); }
        let mut args = vec!["--probe".to_string(), address.to_string(), "--transport".into(), transport.into()];
        for (field, flag) in [("serverName", "--server-name"), ("caCert", "--ca-cert")] {
            if let Some(value) = input[field].as_str().filter(|value| !value.is_empty()) { args.extend([flag.into(), value.into()]); }
        }
        return Ok(json!({"summary":"SIP OPTIONS 探测完成","data":run_engine(&args)?}));
    }
    if action == "export-evidence" {
        let data: Value = if let Some(path) = input["dataPath"].as_str() {
            serde_json::from_reader(std::io::BufReader::new(std::fs::File::open(path).map_err(|error| error.to_string())?)).map_err(|error| error.to_string())?
        } else { serde_json::from_str(input["data"].as_str().unwrap_or("")).map_err(|error| error.to_string())? };
        let data = if data.get("sip_messages").is_some() {
            let report: streamscope_sip::SipReport = serde_json::from_value(data).map_err(|error| error.to_string())?;
            json!(if input["redacted"].as_str() == Some("true") { report.redacted() } else { report })
        } else {
            if !data["steps"].as_array().is_some_and(|steps| steps.len() <= 24) || !data["target"].is_string() { return Err("SIP 场景结果格式无效".into()); }
            data
        };
        let root = input["_hostOutputRoot"].as_str().ok_or("宿主未提供报告目录")?;
        let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|error| error.to_string())?.as_nanos();
        let directory = Path::new(root).join(format!("report-sip-export-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        let file = directory.join("sip-evidence.json");
        std::fs::write(&file, serde_json::to_vec_pretty(&data).map_err(|error| error.to_string())?).map_err(|error| error.to_string())?;
        return Ok(json!({"summary":"SIP 证据导出完成","reportDirectory":directory,"downloadFile":file}));
    }
    let path = input["path"].as_str().unwrap_or("").trim();
    if path.is_empty() || !Path::new(path).is_file() {
        return Err("请选择现有 PCAP/PCAPNG 文件".into());
    }
    match action {
        "analyze" => {
            let report = streamscope_sip::analyze_pcap(Path::new(path))
                .map_err(|error| error.to_string())?;
            let transaction_rows = report.transactions.iter().take(500).map(|transaction| json!([
                transaction.call_id, transaction.method, transaction.final_status,
                transaction.request_retransmissions, transaction.outcome
            ])).collect::<Vec<_>>();
            let finding_rows = report.findings.iter().take(500).map(|finding| json!([
                finding.severity, finding.code, finding.packet_number, finding.detail
            ])).collect::<Vec<_>>();
            let first_micros = report.sip_messages.first().map(|event| event.timestamp_micros).unwrap_or(0);
            let timeline = report.sip_messages.iter().take(500).map(|event| json!({
                "offsetMs": event.timestamp_micros.saturating_sub(first_micros) / 1000,
                "label": event.method.clone().unwrap_or_else(|| format!("SIP {}", event.status.unwrap_or(0))),
                "detail": format!("抓包 #{} · {} → {}", event.packet_number, event.source, event.destination)
            })).collect::<Vec<_>>();
            let evidence = report.findings.iter().take(500).map(|finding| json!({
                "severity": finding.severity, "code": finding.code,
                "packetNumber": finding.packet_number, "detail": finding.detail
            })).collect::<Vec<_>>();
            Ok(json!({
                "summary": format!("{} 条 SIP 消息，{} 个呼叫，{} 项问题", report.sip_messages.len(), report.calls.len(), report.findings.len()),
                "evidence": evidence,
                "timeline": timeline,
                "blocks": [
                    {"type":"table","title":"事务（前 500 条；完整证据在工作台）","columns":["Call-ID","方法","最终状态","重传","结论"],"rows":transaction_rows},
                    {"type":"table","title":"诊断问题（前 500 条；完整证据在工作台）","columns":["级别","代码","包号","原因"],"rows":finding_rows},
                    {"type":"timeline","title":"SIP 消息时间线（前 500 条）","events":timeline}
                ],
                "data": report
            }))
        }
        "preview-replay" => {
            let call_id = input["callId"].as_str().unwrap_or("");
            let source: SocketAddr = input["captureSource"].as_str().unwrap_or("")
                .parse().map_err(|_| "抓包源端点必须是 IP:端口".to_string())?;
            let plan = streamscope_sip::compile_replay_plan(Path::new(path), call_id, source)?;
            let rows = plan.steps.iter().map(|step| json!([
                step.packet_number, step.delay_ms, step.method, step.expected_status
            ])).collect::<Vec<_>>();
            Ok(json!({
                "summary": if plan.executable { "场景可执行" } else { "场景存在限制，不能安全执行" },
                "blocks": [
                    {"type":"table","title":"模拟步骤","columns":["抓包包号","延迟 ms","方法","预期状态"],"rows":rows},
                    {"type":"text","title":"限制与提醒","text":plan.warnings.join("\n")}
                ],
                "data": plan
            }))
        }
        "execute-replay" => {
            if input["confirmSend"].as_str() != Some("true") { return Err("请先确认向目标设备发送 SIP 请求".into()); }
            let call_id = input["callId"].as_str().unwrap_or("");
            let source: SocketAddr = input["captureSource"].as_str().unwrap_or("")
                .parse().map_err(|_| "抓包源端点必须是 IP:端口".to_string())?;
            let target: SocketAddr = input["target"].as_str().unwrap_or("")
                .parse().map_err(|_| "目标设备地址必须是 IP:端口".to_string())?;
            let mut plan = streamscope_sip::compile_replay_plan(Path::new(path), call_id, source)?;
            let overrides = input["overrides"].as_str().filter(|value| !value.trim().is_empty())
                .map(|value| serde_json::from_str::<Vec<streamscope_sip::ReplayOverride>>(value)
                    .map_err(|error| format!("步骤调整 JSON 无效：{error}")))
                .transpose()?.unwrap_or_default();
            if !overrides.is_empty() { streamscope_sip::apply_replay_overrides(&mut plan, &overrides)?; }
            if !plan.executable { return Err(format!("抓包场景不可安全执行：{}", plan.warnings.join("；"))); }
            let result = run_replay_engine(path, call_id, source, target, &overrides)?;
            let rows = result["steps"].as_array().into_iter().flatten().map(|step| json!([
                step["capture_packet"], step["method"], step["expected_status"],
                step["actual_status"], step["latency_ms"], step["outcome"]
            ])).collect::<Vec<_>>();
            Ok(json!({
                "summary": if result["success"] == true { "SIP 模拟完成，所有步骤符合预期" }
                    else { "SIP 模拟发现状态不一致或设备未响应" },
                "blocks": [
                    {"type":"table","title":"模拟步骤结果","columns":["抓包包号","方法","预期状态","实际状态","耗时 ms","结果"],"rows":rows},
                    {"type":"text","title":"执行结论","text":result["error"].as_str().unwrap_or("无错误")}
                ],
                "data": result
            }))
        }
        _ => Err("未声明的 SIP 动作".into()),
    }
}

#[cfg(windows)]
fn run_replay_engine(path: &str, call_id: &str, source: SocketAddr, target: SocketAddr,
    overrides: &[streamscope_sip::ReplayOverride]) -> Result<Value, String> {
    let mut args = vec!["--replay-capture".into(), path.into(), "--replay-call-id".into(), call_id.into(),
        "--replay-source".into(), source.to_string(), "--replay-target".into(), target.to_string()];
    if !overrides.is_empty() { args.extend(["--replay-overrides".into(), serde_json::to_string(overrides).map_err(|error| error.to_string())?]); }
    run_engine(&args)
}

#[cfg(windows)]
fn run_engine(args: &[String]) -> Result<Value, String> {
    use std::os::windows::process::CommandExt;
    let executable = std::env::current_exe().map_err(|error| error.to_string())?
        .parent().ok_or_else(|| "插件目录无效".to_string())?.join("streams-sip-engine.exe");
    if !executable.is_file() { return Err("SIP 插件包缺少独立执行器".into()); }
    let mut command = Command::new(executable);
    command.args(args);
    let mut child = command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .creation_flags(0x0800_0000).spawn()
        .map_err(|error| format!("无法启动 SIP 执行器：{error}"))?;
    let job = match ChildJob::attach(&child) {
        Ok(job) => job,
        Err(error) => { let _ = child.kill(); let _ = child.wait(); return Err(error); }
    };
    let output = child.wait_with_output().map_err(|error| error.to_string())?;
    drop(job);
    if !output.status.success() {
        return Err(format!("SIP 场景执行失败：{}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| format!("SIP 执行结果无效：{error}"))
}

#[cfg(not(windows))]
fn run_engine(_: &[String]) -> Result<Value, String> { Err("当前平台暂不支持 SIP 执行器".into()) }

#[cfg(not(windows))]
fn run_replay_engine(_: &str, _: &str, _: SocketAddr, _: SocketAddr,
    _: &[streamscope_sip::ReplayOverride]) -> Result<Value, String> {
    Err("当前平台暂不支持 SIP 场景执行器".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_capture_fails_before_replay() {
        assert!(execute("preview-replay", &serde_json::json!({"path":""})).is_err());
    }

    #[test]
    fn active_replay_requires_explicit_confirmation() {
        let path = std::env::temp_dir().join(format!("streamscope-sip-confirm-{}.pcap", std::process::id()));
        std::fs::write(&path, [0_u8; 24]).unwrap();
        let result = execute("execute-replay", &serde_json::json!({"path":path,"target":"127.0.0.1:5060"}));
        assert!(result.unwrap_err().contains("确认"));
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn job_close_terminates_sip_child_process() {
        let mut child = Command::new("cmd").args(["/C", "ping -n 10 127.0.0.1 >NUL"])
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let job = ChildJob::attach(&child).unwrap();
        assert!(child.try_wait().unwrap().is_none());
        let started = std::time::Instant::now();
        drop(job);
        child.wait().unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }
}
