use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    streamscope_plugin_host::serve_with_progress(|action, input, progress| {
        match action {
            "inspect" => Ok(json!({"summary":"示例插件运行成功", "input":input})),
            "test-crash" => std::process::exit(2),
            "test-timeout" => {
                std::thread::sleep(std::time::Duration::from_millis(200));
                Ok(json!({"done":true}))
            },
            #[cfg(windows)]
            "test-child" => {
                let mut child = std::process::Command::new("ping")
                    .args(["-n", "20", "127.0.0.1"])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn().map_err(|error| error.to_string())?;
                progress(json!({"childPid":child.id()}));
                std::thread::sleep(std::time::Duration::from_secs(10));
                let _ = child.kill();
                let _ = child.wait();
                Ok(json!({"done":true}))
            },
            _ => Err("不支持的动作".into()),
        }
    })?;
    Ok(())
}
