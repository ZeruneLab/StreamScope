use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use streamscope_analyzer::{
    AnalysisRun, AnalyzeOptions, AudioFileOptions, GeneratedReports, H264FileOptions,
    H265FileOptions, PcapFileOptions,
};
use streamscope_core::{AnalysisResult, Transport};
use tauri::{Emitter, Manager};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AnalyzeCommand {
    url: String,
    transport: String,
    duration_seconds: u64,
    connect_timeout_seconds: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HistoryEntry {
    generated_at: String,
    source_url: String,
    status: streamscope_core::AnalysisStatus,
    report_directory: String,
    critical_count: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportMediaRequest {
    source_path: String,
    destination_path: String,
    media_type: String,
    format: String,
    start_ms: Option<u64>,
    end_ms: Option<u64>,
}

#[tauri::command]
async fn analyze_rtsp(
    app: tauri::AppHandle,
    request: AnalyzeCommand,
) -> Result<AnalysisRun, String> {
    let transport = match request.transport.as_str() {
        "tcp" => Transport::Tcp,
        "udp" => Transport::Udp,
        _ => return Err("传输模式仅支持 tcp 或 udp".into()),
    };
    let output_root = default_report_root(&app)?;
    let progress_app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        streamscope_analyzer::analyze_rtsp_with_progress(
            AnalyzeOptions {
                source_url: request.url,
                transport,
                duration_seconds: request.duration_seconds,
                connect_timeout_seconds: request.connect_timeout_seconds,
                output_root,
            },
            |progress| {
                let _ = progress_app.emit("analysis-progress", progress);
            },
        )
        .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("分析任务异常结束：{error}"))?
}

#[tauri::command]
async fn analyze_h264_file(app: tauri::AppHandle, path: String) -> Result<AnalysisRun, String> {
    let output_root = default_report_root(&app)?;
    let progress_app = app.clone();
    let _ = progress_app.emit(
        "analysis-progress",
        streamscope_analyzer::AnalysisProgress {
            percent: 10,
            stage: "文件".into(),
            detail: "正在解析 Annex B H.264 码流".into(),
            live_audio_tracks: Vec::new(),
        },
    );
    let run = tauri::async_runtime::spawn_blocking(move || {
        streamscope_analyzer::analyze_h264_file(H264FileOptions {
            input: PathBuf::from(path),
            output_root,
            process_timeout_seconds: 300,
        })
        .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("分析任务异常结束：{error}"))??;
    let _ = app.emit(
        "analysis-progress",
        streamscope_analyzer::AnalysisProgress {
            percent: 100,
            stage: "完成".into(),
            detail: "离线 H.264 报告已生成".into(),
            live_audio_tracks: Vec::new(),
        },
    );
    Ok(run)
}

#[tauri::command]
async fn analyze_h265_file(app: tauri::AppHandle, path: String) -> Result<AnalysisRun, String> {
    let output_root = default_report_root(&app)?;
    let progress_app = app.clone();
    let _ = progress_app.emit(
        "analysis-progress",
        streamscope_analyzer::AnalysisProgress {
            percent: 10,
            stage: "文件".into(),
            detail: "正在解析 Annex B H.265/HEVC 码流".into(),
            live_audio_tracks: Vec::new(),
        },
    );
    let run = tauri::async_runtime::spawn_blocking(move || {
        streamscope_analyzer::analyze_h265_file(H265FileOptions {
            input: PathBuf::from(path),
            output_root,
            process_timeout_seconds: 300,
        })
        .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("分析任务异常结束：{error}"))??;
    let _ = app.emit(
        "analysis-progress",
        streamscope_analyzer::AnalysisProgress {
            percent: 100,
            stage: "完成".into(),
            detail: "离线 H.265 报告已生成".into(),
            live_audio_tracks: Vec::new(),
        },
    );
    Ok(run)
}

#[tauri::command]
async fn analyze_audio_file(app: tauri::AppHandle, path: String) -> Result<AnalysisRun, String> {
    let output_root = default_report_root(&app)?;
    let _ = app.emit(
        "analysis-progress",
        streamscope_analyzer::AnalysisProgress {
            percent: 10,
            stage: "音频".into(),
            detail: "正在解码音频并扫描电平、静音和削波".into(),
            live_audio_tracks: Vec::new(),
        },
    );
    let run = tauri::async_runtime::spawn_blocking(move || {
        streamscope_analyzer::analyze_audio_file(AudioFileOptions {
            input: PathBuf::from(path),
            output_root,
            process_timeout_seconds: 300,
        })
        .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("分析任务异常结束：{error}"))??;
    let _ = app.emit(
        "analysis-progress",
        streamscope_analyzer::AnalysisProgress {
            percent: 100,
            stage: "完成".into(),
            detail: "离线音频报告已生成".into(),
            live_audio_tracks: Vec::new(),
        },
    );
    Ok(run)
}

#[tauri::command]
async fn analyze_pcap_file(
    app: tauri::AppHandle,
    path: String,
    stream_ids: Option<Vec<String>>,
) -> Result<AnalysisRun, String> {
    let output_root = default_report_root(&app)?;
    let _ = app.emit(
        "analysis-progress",
        streamscope_analyzer::AnalysisProgress {
            percent: 10,
            stage: "抓包".into(),
            detail: "正在解析 PCAP/PCAPNG 网络帧".into(),
            live_audio_tracks: Vec::new(),
        },
    );
    let progress_app = app.clone();
    let run = tauri::async_runtime::spawn_blocking(move || {
        streamscope_analyzer::analyze_pcap_file_with_progress(
            PcapFileOptions {
                input: PathBuf::from(path),
                output_root,
                process_timeout_seconds: 300,
                stream_ids: stream_ids.unwrap_or_default(),
            },
            |progress| {
                let _ = progress_app.emit("analysis-progress", progress);
            },
        )
        .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("分析任务异常结束：{error}"))??;
    let _ = app.emit(
        "analysis-progress",
        streamscope_analyzer::AnalysisProgress {
            percent: 100,
            stage: "完成".into(),
            detail: "抓包诊断报告已生成".into(),
            live_audio_tracks: Vec::new(),
        },
    );
    Ok(run)
}

#[tauri::command]
async fn compare_rtsp(
    app: tauri::AppHandle,
    request: AnalyzeCommand,
) -> Result<streamscope_analyzer::ComparisonRun, String> {
    let output_root = default_report_root(&app)?;
    let _ = app.emit(
        "analysis-progress",
        streamscope_analyzer::AnalysisProgress {
            percent: 5,
            stage: "对比".into(),
            detail: "将依次执行 TCP 与 UDP 诊断".into(),
            live_audio_tracks: Vec::new(),
        },
    );
    let run = tauri::async_runtime::spawn_blocking(move || {
        streamscope_analyzer::compare_rtsp(AnalyzeOptions {
            source_url: request.url,
            transport: Transport::Tcp,
            duration_seconds: request.duration_seconds,
            connect_timeout_seconds: request.connect_timeout_seconds,
            output_root,
        })
        .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("对比任务异常结束：{error}"))??;
    let _ = app.emit(
        "analysis-progress",
        streamscope_analyzer::AnalysisProgress {
            percent: 100,
            stage: "完成".into(),
            detail: "TCP/UDP 对比报告已生成".into(),
            live_audio_tracks: Vec::new(),
        },
    );
    Ok(run)
}

#[tauri::command]
async fn export_media(
    app: tauri::AppHandle,
    request: ExportMediaRequest,
) -> Result<String, String> {
    let report_root = default_report_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let root = report_root
            .canonicalize()
            .map_err(|error| format!("报告根目录不可用：{error}"))?;
        let source = PathBuf::from(request.source_path)
            .canonicalize()
            .map_err(|error| format!("导出源文件不可用：{error}"))?;
        if !source.starts_with(&root) || !source.is_file() {
            return Err("只能导出 StreamScope 报告中的音视频样本".into());
        }
        let destination = PathBuf::from(request.destination_path);
        if !destination.is_absolute() || destination == source {
            return Err("请选择不同于报告样本的绝对保存路径".into());
        }
        let parent = destination
            .parent()
            .filter(|path| path.is_dir())
            .ok_or_else(|| "保存目录不存在".to_string())?;
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |value| value.as_nanos());
        let temporary = parent.join(format!(
            ".streamscope-export-{}-{unique}.tmp",
            std::process::id()
        ));
        let range_ms = match (request.start_ms, request.end_ms) {
            (None, None) => Ok(None),
            (Some(start), Some(end)) if end > start && end - start <= 86_400_000 => {
                Ok(Some((start, end)))
            }
            (Some(_), Some(_)) => Err("导出区间无效或超过 24 小时".to_string()),
            _ => Err("导出区间必须同时提供开始和结束时间".to_string()),
        }?;
        let export_result = match request.media_type.as_str() {
            "video" if request.format == "mp4" => std::fs::copy(&source, &temporary)
                .map(|_| ())
                .map_err(|error| format!("视频导出失败：{error}")),
            "audio" => streamscope_ffmpeg::export_audio_segment(
                &source,
                &temporary,
                &request.format,
                range_ms,
                std::time::Duration::from_secs(300),
            )
            .map_err(|error| error.to_string()),
            _ => Err("不支持的媒体类型或导出格式".into()),
        };
        if let Err(error) = export_result {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        if destination.is_dir() {
            let _ = std::fs::remove_file(&temporary);
            return Err("目标路径是目录，无法保存媒体文件".into());
        }
        if destination.exists() {
            std::fs::remove_file(&destination)
                .map_err(|error| format!("无法覆盖已有文件：{error}"))?;
        }
        std::fs::rename(&temporary, &destination).map_err(|error| {
            let _ = std::fs::remove_file(&temporary);
            format!("无法完成媒体导出：{error}")
        })?;
        Ok(destination.display().to_string())
    })
    .await
    .map_err(|error| format!("导出任务异常结束：{error}"))?
}

#[tauri::command]
fn list_analysis_history(app: tauri::AppHandle) -> Result<Vec<HistoryEntry>, String> {
    let root = default_report_root(&app)?;
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for item in std::fs::read_dir(&root).map_err(|error| format!("读取历史目录失败：{error}"))?
    {
        let path = item
            .map_err(|error| format!("读取历史条目失败：{error}"))?
            .path();
        if !path.is_dir()
            || !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("report-"))
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path.join("result.json")) else {
            continue;
        };
        let Ok(result) = serde_json::from_str::<AnalysisResult>(&text) else {
            continue;
        };
        let critical_count = result
            .diagnostics
            .iter()
            .chain(
                result
                    .streams
                    .iter()
                    .flat_map(|stream| stream.diagnostics.iter()),
            )
            .filter(|finding| {
                matches!(
                    finding.severity,
                    streamscope_core::DiagnosticSeverity::Critical
                        | streamscope_core::DiagnosticSeverity::High
                )
            })
            .count();
        entries.push(HistoryEntry {
            generated_at: result.generated_at,
            source_url: result.request.source_url,
            status: result.status,
            report_directory: path.display().to_string(),
            critical_count,
        });
    }
    entries.sort_by(|left, right| right.generated_at.cmp(&left.generated_at));
    entries.truncate(20);
    Ok(entries)
}

#[tauri::command]
fn open_report_directory(app: tauri::AppHandle, report_directory: String) -> Result<(), String> {
    let root = default_report_root(&app)?
        .canonicalize()
        .map_err(|error| format!("报告根目录不可用：{error}"))?;
    let directory = PathBuf::from(report_directory)
        .canonicalize()
        .map_err(|error| format!("报告目录不可用：{error}"))?;
    if !directory.starts_with(root)
        || (!directory.join("report.html").is_file()
            && !directory.join("comparison.html").is_file())
    {
        return Err("只能打开 StreamScope 生成的报告目录".into());
    }
    std::process::Command::new("explorer.exe")
        .arg(&directory)
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("无法打开报告目录：{error}"))
}

#[tauri::command]
fn delete_report_directory(app: tauri::AppHandle, report_directory: String) -> Result<(), String> {
    let root = default_report_root(&app)?
        .canonicalize()
        .map_err(|error| format!("报告根目录不可用：{error}"))?;
    let directory = PathBuf::from(report_directory)
        .canonicalize()
        .map_err(|error| format!("报告目录不可用：{error}"))?;
    let valid_name = directory
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("report-"));
    let contains_report =
        directory.join("result.json").is_file() || directory.join("comparison.json").is_file();
    if !directory.starts_with(&root) || directory == root || !valid_name || !contains_report {
        return Err("只能删除 StreamScope 生成的单个报告目录".into());
    }
    std::fs::remove_dir_all(&directory).map_err(|error| format!("删除报告失败：{error}"))
}

#[tauri::command]
fn load_report_html(app: tauri::AppHandle, report_path: String) -> Result<String, String> {
    let root = default_report_root(&app)?
        .canonicalize()
        .map_err(|error| format!("报告根目录不可用：{error}"))?;
    let path = PathBuf::from(report_path)
        .canonicalize()
        .map_err(|error| format!("报告文件不可用：{error}"))?;
    if !path.starts_with(root)
        || !matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("report.html" | "comparison.html")
        )
    {
        return Err("只能预览 StreamScope HTML 报告".into());
    }
    std::fs::read_to_string(path).map_err(|error| format!("读取报告失败：{error}"))
}

#[tauri::command]
fn load_analysis_run(
    app: tauri::AppHandle,
    report_directory: String,
) -> Result<AnalysisRun, String> {
    let root = default_report_root(&app)?
        .canonicalize()
        .map_err(|error| format!("报告根目录不可用：{error}"))?;
    let directory = PathBuf::from(report_directory)
        .canonicalize()
        .map_err(|error| format!("报告目录不可用：{error}"))?;
    if !directory.starts_with(root)
        || !directory
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("report-"))
    {
        return Err("只能打开 StreamScope 报告目录中的任务".into());
    }
    let result_path = directory.join("result.json");
    let mut result: AnalysisResult = serde_json::from_str(
        &std::fs::read_to_string(&result_path)
            .map_err(|error| format!("读取 JSON 报告失败：{error}"))?,
    )
    .map_err(|error| format!("JSON 报告格式无效：{error}"))?;
    if result.capture_summary.is_none() {
        result.diagnostics = streamscope_diagnostics::evaluate(&result);
        result.timeline = streamscope_diagnostics::build_timeline(&result);
    }
    let html = directory.join("report.html");
    let ffmpeg_log = directory.join("ffmpeg.log");
    if !html.is_file() || !ffmpeg_log.is_file() {
        return Err("报告文件不完整".into());
    }
    std::fs::write(
        &result_path,
        serde_json::to_vec_pretty(&result)
            .map_err(|error| format!("更新 JSON 报告失败：{error}"))?,
    )
    .map_err(|error| format!("更新 JSON 报告失败：{error}"))?;
    std::fs::write(&html, streamscope_report::render_html(&result))
        .map_err(|error| format!("更新 HTML 报告失败：{error}"))?;
    let session_sdp = directory.join("session.sdp");
    Ok(AnalysisRun {
        result,
        report_directory: directory.display().to_string(),
        reports: GeneratedReports {
            json: result_path.display().to_string(),
            html: html.display().to_string(),
            ffmpeg_log: ffmpeg_log.display().to_string(),
            session_sdp: session_sdp
                .is_file()
                .then(|| session_sdp.display().to_string()),
        },
    })
}

fn default_report_root(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .document_dir()
        .map(|path| path.join("StreamScope").join("reports"))
        .map_err(|error| format!("无法确定文档目录：{error}"))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            analyze_rtsp,
            analyze_h264_file,
            analyze_h265_file,
            analyze_audio_file,
            analyze_pcap_file,
            compare_rtsp,
            export_media,
            list_analysis_history,
            load_report_html,
            load_analysis_run,
            open_report_directory,
            delete_report_directory
        ])
        .run(tauri::generate_context!())
        .expect("StreamScope 桌面程序启动失败");
}
