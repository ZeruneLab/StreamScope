use serde_json::json;
use std::path::Path;
use std::time::Duration;
use streamscope_plugin_host::PluginProcess;

fn executable() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_streamscope-plugin-sample"))
}

#[test]
fn isolated_sample_roundtrip_and_failure() {
    let mut process = PluginProcess::spawn(executable()).unwrap();
    let result = process.request("execute", json!({"action":"inspect","input":{"x":1}}), Duration::from_secs(2), |_| {}).unwrap();
    assert_eq!(result["input"]["x"], 1);
    assert!(process.request("execute", json!({"action":"test-crash"}), Duration::from_secs(1), |_| {}).is_err());
}

#[test]
fn timeout_does_not_block_host() {
    let mut process = PluginProcess::spawn(executable()).unwrap();
    assert!(process.request("execute", json!({"action":"test-timeout"}), Duration::from_millis(20), |_| {}).is_err());
}

#[test]
fn cancellation_terminates_running_plugin_only() {
    let mut process = PluginProcess::spawn(executable()).unwrap();
    let handle = process.cancel_handle();
    let worker = std::thread::spawn(move || process.request("execute", json!({"action":"test-timeout"}), Duration::from_secs(2), |_| {}));
    std::thread::sleep(Duration::from_millis(20));
    handle.cancel().unwrap();
    assert!(worker.join().unwrap().is_err());
}

#[cfg(windows)]
#[test]
fn cancelling_plugin_terminates_its_spawned_process() {
    use std::sync::mpsc;

    let mut process = PluginProcess::spawn(executable()).unwrap();
    let handle = process.cancel_handle();
    let (sender, receiver) = mpsc::channel();
    let worker = std::thread::spawn(move || process.request("execute", json!({"action":"test-child"}),
        Duration::from_secs(15), |event| {
            if let Some(pid) = event["childPid"].as_u64() { let _ = sender.send(pid as u32); }
        }));
    let pid = receiver.recv_timeout(Duration::from_secs(3)).unwrap();
    handle.cancel().unwrap();
    assert!(worker.join().unwrap().is_err());
    assert_process_exited(pid);
}

#[cfg(windows)]
#[test]
fn plugin_timeout_terminates_its_spawned_process_without_waiting_for_drop() {
    let mut process = PluginProcess::spawn(executable()).unwrap();
    let mut child_pid = None;
    let result = process.request("execute", json!({"action":"test-child"}), Duration::from_millis(200),
        |event| child_pid = event["childPid"].as_u64().map(|pid| pid as u32));
    assert!(result.unwrap_err().to_string().contains("超时"));
    assert_process_exited(child_pid.expect("child process started"));
}

#[cfg(windows)]
fn assert_process_exited(pid: u32) {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_INVALID_PARAMETER, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject};
    let child = unsafe { OpenProcess(0x0010_0000, 0, pid) };
    if child.is_null() {
        assert_eq!(unsafe { GetLastError() }, ERROR_INVALID_PARAMETER);
    } else {
        assert_eq!(unsafe { WaitForSingleObject(child, 2_000) }, WAIT_OBJECT_0);
        unsafe { CloseHandle(child); }
    }
}
