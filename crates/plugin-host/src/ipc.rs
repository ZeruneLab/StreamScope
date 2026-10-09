use crate::{PluginError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

const MAX_FRAME: usize = 4 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginRequest {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    pub params: Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginEvent {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

pub struct PluginProcess {
    child: Arc<Mutex<Child>>,
    #[cfg(windows)]
    job: Arc<ProcessJob>,
    stdin: ChildStdin,
    events: Receiver<Result<PluginEvent>>,
    next_id: u64,
}

#[derive(Clone)]
pub struct PluginCancelHandle {
    #[cfg(not(windows))]
    child: Arc<Mutex<Child>>,
    #[cfg(windows)]
    job: Arc<ProcessJob>,
}

impl PluginCancelHandle {
    pub fn cancel(&self) -> Result<()> {
        #[cfg(windows)]
        self.job.terminate()?;
        #[cfg(not(windows))]
        self.child.lock().map_err(|_| invalid("插件进程状态锁异常"))?.kill()?;
        Ok(())
    }
}

#[cfg(windows)]
struct ProcessJob(usize);

#[cfg(windows)]
impl ProcessJob {
    fn attach(child: &Child) -> Result<Self> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            SetInformationJobObject,
        };
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() { return Err(PluginError::Io(std::io::Error::last_os_error())); }
        let job = Self(handle as usize);
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe { SetInformationJobObject(handle, JobObjectExtendedLimitInformation,
            &limits as *const _ as *const _, std::mem::size_of_val(&limits) as u32) };
        if configured == 0 { return Err(PluginError::Io(std::io::Error::last_os_error())); }
        if unsafe { AssignProcessToJobObject(handle, child.as_raw_handle()) } == 0 {
            return Err(PluginError::Io(std::io::Error::last_os_error()));
        }
        Ok(job)
    }

    fn terminate(&self) -> Result<()> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;
        if unsafe { TerminateJobObject(self.0 as _, 1) } == 0 {
            return Err(PluginError::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for ProcessJob {
    fn drop(&mut self) { unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0 as _); } }
}

impl PluginProcess {
    pub fn spawn(executable: &Path) -> Result<Self> {
        Self::spawn_with_runtime(executable, None)
    }

    pub fn spawn_with_runtime(executable: &Path, runtime_directory: Option<&Path>) -> Result<Self> {
        let mut command = Command::new(executable);
        command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
        if let Some(directory) = runtime_directory {
            command.env("STREAMSCOPE_FFMPEG_RUNTIME_DIR", directory);
            command.env("STREAMSCOPE_VIDEO_WORKER_DIR", directory);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let mut child = command.spawn()?;
        #[cfg(windows)]
        let job = match ProcessJob::attach(&child) {
            Ok(job) => Arc::new(job),
            Err(error) => { let _ = child.kill(); let _ = child.wait(); return Err(error); }
        };
        let stdin = child.stdin.take().ok_or_else(|| invalid("插件标准输入不可用"))?;
        let mut stdout = child.stdout.take().ok_or_else(|| invalid("插件标准输出不可用"))?;
        let (sender, events) = mpsc::channel();
        thread::spawn(move || {
            loop {
                let event = read_frame(&mut stdout)
                    .and_then(|bytes| Ok(serde_json::from_slice::<PluginEvent>(&bytes)?));
                let stop = event.is_err();
                if sender.send(event).is_err() || stop {
                    break;
                }
            }
        });
        let mut process = Self {
            child: Arc::new(Mutex::new(child)),
            #[cfg(windows)] job,
            stdin, events, next_id: 1,
        };
        process.request("hello", serde_json::json!({"hostApi": crate::HOST_API_VERSION}), Duration::from_secs(5), |_| {})?;
        Ok(process)
    }

    pub fn cancel_handle(&self) -> PluginCancelHandle {
        PluginCancelHandle {
            #[cfg(not(windows))]
            child: self.child.clone(),
            #[cfg(windows)] job: self.job.clone(),
        }
    }

    pub fn request(
        &mut self,
        method: &str,
        params: Value,
        timeout: Duration,
        mut on_progress: impl FnMut(&Value),
    ) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        write_frame(&mut self.stdin, &PluginRequest {
            jsonrpc: "2.0".into(), id, method: method.into(), params,
        })?;
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let event = match self.events.recv_timeout(remaining) {
                Ok(Ok(event)) => event,
                Ok(Err(error)) => {
                    let _ = self.cancel_handle().cancel();
                    return Err(error);
                }
                Err(_) => {
                    let _ = self.cancel_handle().cancel();
                    return Err(invalid("插件执行超时或异常退出"));
                }
            };
            if event.jsonrpc != "2.0" || event.id != id {
                let _ = self.cancel_handle().cancel();
                return Err(invalid("插件协议响应 ID 无效"));
            }
            match event.method.as_str() {
                "progress" => on_progress(&event.params),
                "result" => return Ok(event.params),
                "error" => return Err(invalid(&format!("插件执行失败：{}", event.params))),
                _ => {
                    let _ = self.cancel_handle().cancel();
                    return Err(invalid("插件响应方法无效"));
                }
            }
        }
    }

    pub fn cancel(&mut self, task_id: u64) -> Result<()> {
        write_frame(&mut self.stdin, &PluginRequest {
            jsonrpc: "2.0".into(), id: self.next_id, method: "cancel".into(),
            params: serde_json::json!({"taskId": task_id}),
        })?;
        self.next_id += 1;
        Ok(())
    }
}

impl Drop for PluginProcess {
    fn drop(&mut self) {
        #[cfg(windows)]
        let _ = self.job.terminate();
        if let Ok(mut child) = self.child.lock() {
            #[cfg(not(windows))]
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub fn read_frame(input: &mut impl Read) -> Result<Vec<u8>> {
    let mut size = [0_u8; 4];
    input.read_exact(&mut size)?;
    let size = u32::from_le_bytes(size) as usize;
    if size == 0 || size > MAX_FRAME {
        return Err(invalid("插件协议帧大小无效"));
    }
    let mut payload = vec![0; size];
    input.read_exact(&mut payload)?;
    Ok(payload)
}

pub fn write_frame(output: &mut impl Write, value: &impl Serialize) -> Result<()> {
    let payload = serde_json::to_vec(value)?;
    if payload.is_empty() || payload.len() > MAX_FRAME {
        return Err(invalid("插件协议帧超出限制"));
    }
    output.write_all(&(payload.len() as u32).to_le_bytes())?;
    output.write_all(&payload)?;
    output.flush()?;
    Ok(())
}

/// Minimal public plugin-side protocol loop. stdout is reserved for framed JSON.
pub fn serve(mut execute: impl FnMut(&str, &Value) -> std::result::Result<Value, String>) -> Result<()> {
    serve_with_progress(|action, input, _progress| execute(action, input))
}

pub fn serve_with_progress(
    mut execute: impl FnMut(&str, &Value, &mut dyn FnMut(Value)) -> std::result::Result<Value, String>,
) -> Result<()> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    loop {
        let bytes = match read_frame(&mut input) {
            Ok(bytes) => bytes,
            Err(PluginError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(error),
        };
        let request: PluginRequest = serde_json::from_slice(&bytes)?;
        let response = if request.jsonrpc != "2.0" {
            Err("JSON-RPC 版本无效".into())
        } else {
            match request.method.as_str() {
                "hello" => Ok(serde_json::json!({"pluginApi":"1.0.0"})),
                "execute" => {
                    let mut progress = |params| {
                        let _ = write_frame(&mut output, &PluginEvent {
                            jsonrpc: "2.0".into(), id: request.id, method: "progress".into(), params,
                        });
                    };
                    execute(request.params["action"].as_str().unwrap_or(""), &request.params["input"], &mut progress)
                },
                "cancel" => Ok(serde_json::json!({"cancelled":true})),
                _ => Err("不支持的插件方法".into()),
            }
        };
        let (method, params) = match response {
            Ok(value) => ("result", value),
            Err(message) => ("error", serde_json::json!({"message":message})),
        };
        write_frame(&mut output, &PluginEvent {
            jsonrpc: "2.0".into(), id: request.id, method: method.into(), params,
        })?;
    }
    Ok(())
}

fn invalid(message: &str) -> PluginError {
    PluginError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_and_size_limit() {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &serde_json::json!({"method":"result","value":3})).unwrap();
        let payload = read_frame(&mut bytes.as_slice()).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&payload).unwrap()["value"], 3);
        assert!(read_frame(&mut [255, 255, 255, 255].as_slice()).is_err());
    }
}
