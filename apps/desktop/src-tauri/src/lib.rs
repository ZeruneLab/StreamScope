use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
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
    streamscope_core::reset_analysis_cancellation();
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
    streamscope_core::reset_analysis_cancellation();
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
    streamscope_core::reset_analysis_cancellation();
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
    streamscope_core::reset_analysis_cancellation();
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
    streamscope_core::reset_analysis_cancellation();
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
    streamscope_core::reset_analysis_cancellation();
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
fn cancel_analysis() {
    streamscope_core::request_analysis_cancellation();
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

fn resolve_report_video_source(
    report_root: &Path,
    report_directory: &str,
    stream_id: Option<&str>,
    display_index: u64,
) -> Result<(PathBuf, PathBuf, AnalysisResult), String> {
    let root = report_root
        .canonicalize()
        .map_err(|error| format!("报告根目录不可用：{error}"))?;
    let report = PathBuf::from(report_directory)
        .canonicalize()
        .map_err(|error| format!("报告目录不可用：{error}"))?;
    if !report.starts_with(&root) || !report.join("result.json").is_file() {
        return Err("只能分析 StreamScope 报告中的视频帧".into());
    }
    let directory = if let Some(stream_id) = stream_id {
        if stream_id.is_empty()
            || !stream_id.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
        {
            return Err("媒体流 ID 无效".into());
        }
        report
            .join("streams")
            .join(stream_id)
            .canonicalize()
            .map_err(|error| format!("媒体流报告目录不可用：{error}"))?
    } else {
        report
    };
    if !directory.starts_with(&root) {
        return Err("媒体流报告目录超出允许范围".into());
    }
    let result: AnalysisResult = serde_json::from_slice(
        &std::fs::read(directory.join("result.json"))
            .map_err(|error| format!("读取视频报告失败：{error}"))?,
    )
    .map_err(|error| format!("视频报告格式无效：{error}"))?;
    let deep = result
        .h264
        .as_ref()
        .and_then(|analysis| analysis.deep_analysis.as_ref())
        .or_else(|| {
            result
                .h265
                .as_ref()
                .and_then(|analysis| analysis.deep_analysis.as_ref())
        })
        .ok_or_else(|| "当前报告没有逐帧索引".to_string())?;
    if !deep
        .frames
        .iter()
        .any(|frame| frame.display_index == display_index)
    {
        return Err("所选帧不在已索引范围内".into());
    }
    let sample_h264 = directory.join("sample.h264");
    let sample_h265 = directory.join("sample.h265");
    let source = if sample_h264.is_file() {
        sample_h264
    } else if sample_h265.is_file() {
        sample_h265
    } else if matches!(
        result.request.source_kind,
        streamscope_core::SourceKind::H264 | streamscope_core::SourceKind::H265
    ) {
        result
            .request
            .source_path
            .as_deref()
            .map(PathBuf::from)
            .filter(|path| path.is_file())
            .ok_or_else(|| "原视频文件已移动或不可用".to_string())?
    } else {
        return Err("当前报告没有可用于逐帧分析的视频样本".into());
    };
    Ok((directory, source, result))
}

#[cfg(windows)]
fn frontend_file_path(path: &Path) -> String {
    let value = path.as_os_str().to_string_lossy();
    if let Some(path) = value.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{path}");
    }
    value.strip_prefix(r"\\?\").unwrap_or(&value).to_owned()
}

#[cfg(not(windows))]
fn frontend_file_path(path: &Path) -> String {
    path.display().to_string()
}

#[tauri::command]
async fn extract_video_frame(
    app: tauri::AppHandle,
    report_directory: String,
    stream_id: Option<String>,
    display_index: u64,
) -> Result<String, String> {
    let report_root = default_report_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let (directory, source, _) = resolve_report_video_source(
            &report_root,
            &report_directory,
            stream_id.as_deref(),
            display_index,
        )?;
        let frames = directory.join("frames");
        std::fs::create_dir_all(&frames).map_err(|error| format!("创建帧图像目录失败：{error}"))?;
        let destination = frames.join(format!("frame-{display_index}.png"));
        if !destination.is_file() {
            streamscope_ffmpeg::extract_video_frame(
                &source,
                &destination,
                display_index,
                std::time::Duration::from_secs(60),
            )
            .map_err(|error| error.to_string())?;
        }
        Ok(frontend_file_path(&destination))
    })
    .await
    .map_err(|error| format!("逐帧图像任务异常结束：{error}"))?
}

#[tauri::command]
async fn compare_video_reference(
    app: tauri::AppHandle,
    report_directory: String,
    stream_id: Option<String>,
    reference_path: String,
) -> Result<streamscope_ffmpeg::VideoReferenceComparison, String> {
    let report_root = default_report_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let (directory, source, _) =
            resolve_report_video_source(&report_root, &report_directory, stream_id.as_deref(), 0)?;
        let reference = PathBuf::from(reference_path);
        if !reference.is_absolute() || !reference.is_file() {
            return Err("请选择存在的参考视频文件".into());
        }
        let extension = reference
            .extension()
            .and_then(|value| value.to_str())
            .map(str::to_ascii_lowercase)
            .ok_or_else(|| "参考视频缺少可识别的扩展名".to_string())?;
        if !matches!(
            extension.as_str(),
            "h264"
                | "264"
                | "h265"
                | "265"
                | "hevc"
                | "mp4"
                | "mkv"
                | "mov"
                | "avi"
                | "ts"
                | "m2ts"
                | "webm"
        ) {
            return Err(format!("暂不支持 .{extension} 参考视频"));
        }
        let mut comparison = streamscope_ffmpeg::compare_video_reference(
            &source,
            &reference,
            std::time::Duration::from_secs(300),
        )
        .map_err(|error| error.to_string())?;
        let difference = directory.join("video-reference-difference.mp4");
        if difference.exists() {
            std::fs::remove_file(&difference)
                .map_err(|error| format!("清理旧参考视频差异预览失败：{error}"))?;
        }
        match streamscope_ffmpeg::create_video_reference_difference_preview(
            &source,
            &reference,
            &difference,
            std::time::Duration::from_secs(300),
        ) {
            Ok(()) => comparison.limitations.push(
                "差异预览将像素差绝对值做 4 倍对比度增强并增加少量亮度，仅用于定位，不参与 PSNR/SSIM/VMAF 数值计算；最长保存前 60 秒。"
                    .into(),
            ),
            Err(_) => comparison
                .limitations
                .push("差异增强预览生成失败；质量指标结果仍有效。".into()),
        }
        let destination = directory.join("video-reference-comparison.json");
        let temporary = directory.join(format!(
            "video-reference-comparison-{}.tmp",
            std::process::id()
        ));
        let json = serde_json::to_vec_pretty(&comparison)
            .map_err(|error| format!("序列化参考视频对比结果失败：{error}"))?;
        std::fs::write(&temporary, json)
            .map_err(|error| format!("写入参考视频对比结果失败：{error}"))?;
        if destination.exists() {
            std::fs::remove_file(&destination)
                .map_err(|error| format!("覆盖旧参考视频对比结果失败：{error}"))?;
        }
        std::fs::rename(&temporary, &destination).map_err(|error| {
            let _ = std::fs::remove_file(&temporary);
            format!("保存参考视频对比结果失败：{error}")
        })?;
        Ok(comparison)
    })
    .await
    .map_err(|error| format!("参考视频对比任务异常结束：{error}"))?
}

#[tauri::command]
async fn load_video_reference_comparison(
    app: tauri::AppHandle,
    report_directory: String,
    stream_id: Option<String>,
) -> Result<Option<streamscope_ffmpeg::VideoReferenceComparison>, String> {
    let report_root = default_report_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let (directory, _, _) =
            resolve_report_video_source(&report_root, &report_directory, stream_id.as_deref(), 0)?;
        let path = directory.join("video-reference-comparison.json");
        if !path.is_file() {
            return Ok(None);
        }
        let comparison = serde_json::from_slice(
            &std::fs::read(path).map_err(|error| format!("读取参考视频对比结果失败：{error}"))?,
        )
        .map_err(|error| format!("参考视频对比结果格式无效：{error}"))?;
        Ok(Some(comparison))
    })
    .await
    .map_err(|error| format!("读取参考视频对比结果任务异常结束：{error}"))?
}

#[tauri::command]
async fn load_video_reference_difference(
    app: tauri::AppHandle,
    report_directory: String,
    stream_id: Option<String>,
) -> Result<Option<String>, String> {
    let report_root = default_report_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let (directory, _, _) =
            resolve_report_video_source(&report_root, &report_directory, stream_id.as_deref(), 0)?;
        let path = directory.join("video-reference-difference.mp4");
        Ok(path.is_file().then(|| path.display().to_string()))
    })
    .await
    .map_err(|error| format!("读取参考视频差异预览任务异常结束：{error}"))?
}

#[tauri::command]
async fn analyze_video_frame_blocks(
    app: tauri::AppHandle,
    report_directory: String,
    stream_id: Option<String>,
    display_index: u64,
) -> Result<streamscope_ffmpeg::VideoWorkerFrame, String> {
    let report_root = default_report_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let (directory, source, _) = resolve_report_video_source(
            &report_root,
            &report_directory,
            stream_id.as_deref(),
            display_index,
        )?;
        let frames = directory.join("frames");
        std::fs::create_dir_all(&frames).map_err(|error| format!("创建块数据目录失败：{error}"))?;
        let output = frames.join(format!("blocks-{display_index}.json"));
        streamscope_ffmpeg::analyze_video_frame_blocks(
            &source,
            &output,
            display_index,
            std::time::Duration::from_secs(120),
        )
        .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("视频块分析任务异常结束：{error}"))?
}

fn read_annex_b_nalu_range(
    source: &Path,
    first_nalu: u64,
    last_nalu: u64,
) -> std::io::Result<Vec<(u64, u64, Vec<u8>)>> {
    let mut reader = BufReader::with_capacity(64 * 1024, std::fs::File::open(source)?);
    let mut selected = Vec::new();
    let mut current = Vec::new();
    let mut pending_zeros = 0_usize;
    let mut active_index = 0_u64;
    let mut active_offset = 0_u64;
    let mut absolute = 0_u64;

    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            if (first_nalu..=last_nalu).contains(&active_index) {
                current.extend(std::iter::repeat_n(0, pending_zeros));
                if !current.is_empty() {
                    selected.push((active_index, active_offset, current));
                }
            }
            return Ok(selected);
        }
        let mut consumed = 0_usize;
        let mut complete = false;
        for &byte in buffer {
            let position = absolute + consumed as u64;
            consumed += 1;
            if byte == 0 {
                pending_zeros += 1;
                continue;
            }
            if byte == 1 && pending_zeros >= 2 {
                if (first_nalu..=last_nalu).contains(&active_index) && !current.is_empty() {
                    selected.push((active_index, active_offset, std::mem::take(&mut current)));
                } else {
                    current.clear();
                }
                if active_index >= last_nalu {
                    complete = true;
                    pending_zeros = 0;
                    break;
                }
                active_index += 1;
                active_offset = position + 1;
                pending_zeros = 0;
                continue;
            }
            if (first_nalu..=last_nalu).contains(&active_index) {
                current.extend(std::iter::repeat_n(0, pending_zeros));
                current.push(byte);
            }
            pending_zeros = 0;
        }
        reader.consume(consumed);
        absolute += consumed as u64;
        if complete {
            return Ok(selected);
        }
    }
}

fn rebase_syntax_hex(hex: &str, offset: u64) -> String {
    hex.lines()
        .enumerate()
        .map(|(line, value)| {
            let bytes = value.split_once("  ").map_or(value, |(_, bytes)| bytes);
            format!("{:08X}  {bytes}", offset + (line * 16) as u64)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn inspect_selected_h264_nalus(
    selected: &[(u64, u64, Vec<u8>)],
) -> Vec<streamscope_core::VideoSyntaxNalu> {
    selected
        .iter()
        .filter_map(|(index, offset, data)| {
            let mut sample = vec![0, 0, 1];
            sample.extend_from_slice(data);
            let mut nalu = streamscope_h264::inspect_annex_b_range(&sample, 1, 1).pop()?;
            nalu.index = *index;
            nalu.offset = *offset;
            nalu.size = data.len() as u64;
            nalu.hex = rebase_syntax_hex(&nalu.hex, *offset);
            Some(nalu)
        })
        .collect()
}

fn inspect_selected_h265_nalus(
    selected: &[(u64, u64, Vec<u8>)],
) -> Vec<streamscope_core::VideoSyntaxNalu> {
    selected
        .iter()
        .filter_map(|(index, offset, data)| {
            let mut sample = vec![0, 0, 1];
            sample.extend_from_slice(data);
            let mut nalu = streamscope_h265::inspect_annex_b_range(&sample, 1, 1).pop()?;
            nalu.index = *index;
            nalu.offset = *offset;
            nalu.size = data.len() as u64;
            nalu.hex = rebase_syntax_hex(&nalu.hex, *offset);
            Some(nalu)
        })
        .collect()
}

fn resolve_frame_access_unit<'a>(
    indexed: &streamscope_core::VideoFrameIndex,
    evidence: &'a [streamscope_core::H264FrameEvidence],
) -> Result<(&'a streamscope_core::H264FrameEvidence, &'static str), String> {
    if let Some(decode_index) = indexed.decode_index {
        let access_unit_index = decode_index + 1;
        return evidence
            .iter()
            .find(|frame| frame.frame_number == access_unit_index)
            .map(|frame| (frame, "ffmpeg_coded_picture_number_to_parser_access_unit"))
            .ok_or_else(|| "没有找到与该编码序号对应的访问单元证据".to_string());
    }

    let packet_start = indexed.packet_position.ok_or_else(|| {
        "当前帧没有编码顺序号或码流字节位置，无法可靠地映射到访问单元".to_string()
    })?;
    let packet_end = packet_start
        .checked_add(indexed.packet_size.ok_or_else(|| {
            "当前帧没有编码顺序号或码流字节大小，无法可靠地映射到访问单元".to_string()
        })?)
        .ok_or_else(|| "当前帧的码流字节范围无效".to_string())?;
    let mut matches = evidence.iter().filter(|frame| {
        matches!(
            (frame.sample_start_offset, frame.sample_end_offset),
            (Some(start), Some(end))
                if packet_start <= start && start < end && end == packet_end
        )
    });
    let matched = matches
        .next()
        .ok_or_else(|| "当前帧的码流字节范围无法唯一映射到访问单元".to_string())?;
    if matches.next().is_some() {
        return Err("当前帧的码流字节范围匹配到多个访问单元，已拒绝猜测".into());
    }
    Ok((matched, "ffprobe_packet_byte_range_to_parser_access_unit"))
}

#[tauri::command]
async fn load_video_frame_syntax(
    app: tauri::AppHandle,
    report_directory: String,
    stream_id: Option<String>,
    display_index: u64,
) -> Result<streamscope_core::VideoSyntaxDocument, String> {
    let report_root = default_report_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let (_, source, result) = resolve_report_video_source(
            &report_root,
            &report_directory,
            stream_id.as_deref(),
            display_index,
        )?;
        let deep = result
            .h264
            .as_ref()
            .and_then(|analysis| analysis.deep_analysis.as_ref())
            .or_else(|| result.h265.as_ref().and_then(|analysis| analysis.deep_analysis.as_ref()))
            .ok_or_else(|| "当前报告没有逐帧索引".to_string())?;
        let indexed = deep
            .frames
            .iter()
            .find(|frame| frame.display_index == display_index)
            .ok_or_else(|| "所选显示帧不在索引中".to_string())?;
        let evidence_frames = result
            .h264
            .as_ref()
            .map(|analysis| analysis.frames.as_slice())
            .or_else(|| result.h265.as_ref().map(|analysis| analysis.frames.as_slice()))
            .ok_or_else(|| "当前报告没有访问单元证据".to_string())?;
        let (evidence, mapping_precision) =
            resolve_frame_access_unit(indexed, evidence_frames)?;
        let access_unit_index = evidence.frame_number;
        let selected = read_annex_b_nalu_range(
            &source,
            evidence.first_nalu,
            evidence.last_nalu,
        )
        .map_err(|error| format!("读取视频样本失败：{error}"))?;
        let (codec, mut nalus, limitations) = if result.h264.is_some() {
            (
                "h264",
                inspect_selected_h264_nalus(&selected),
                vec![
                    "字段树覆盖 NALU 头、SPS/PPS 和基础 Slice Header；不解析 Slice Data、CABAC/CAVLC 宏块语法。".into(),
                    "显示帧优先使用 FFmpeg coded_picture_number 映射；缺失时使用经过唯一性验证的码流字节范围，不按显示序号猜测。".into(),
                ],
            )
        } else {
            (
                "h265",
                inspect_selected_h265_nalus(&selected),
                vec![
                    "字段树覆盖 NALU 头、SPS/PPS、Slice 起始标志、IRAP no-output 标志和 PPS ID；尚未覆盖完整 HEVC Slice Header。".into(),
                    "显示帧优先使用 FFmpeg coded_picture_number 映射；缺失时使用经过唯一性验证的码流字节范围；CTU/CU/PU/TU 语法不在此基础树中。".into(),
                ],
            )
        };
        if nalus.is_empty() {
            return Err("访问单元范围内没有可读取的 Annex B NALU".into());
        }
        let evidence_nalus = result
            .h264
            .as_ref()
            .map(|analysis| analysis.nalus.as_slice())
            .or_else(|| result.h265.as_ref().map(|analysis| analysis.nalus.as_slice()))
            .unwrap_or_default();
        for nalu in &mut nalus {
            if let Some(evidence) = evidence_nalus
                .iter()
                .find(|evidence| evidence.nalu_number == nalu.index)
            {
                nalu.complete = Some(evidence.complete);
                nalu.access_unit_number = evidence.access_unit_number;
                nalu.packets = evidence.packets.clone();
            }
        }
        Ok(streamscope_core::VideoSyntaxDocument {
            codec: codec.into(),
            display_index,
            access_unit_index: Some(access_unit_index),
            mapping_precision: mapping_precision.into(),
            nalus,
            limitations,
        })
    })
    .await
    .map_err(|error| format!("视频语法读取任务异常结束：{error}"))?
}

#[tauri::command]
async fn export_video_block_csv(
    app: tauri::AppHandle,
    report_directory: String,
    stream_id: Option<String>,
    display_index: u64,
    destination_path: String,
) -> Result<String, String> {
    let report_root = default_report_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let (directory, source, _) = resolve_report_video_source(
            &report_root,
            &report_directory,
            stream_id.as_deref(),
            display_index,
        )?;
        let destination = PathBuf::from(destination_path);
        if !destination.is_absolute()
            || !destination.parent().is_some_and(Path::is_dir)
            || destination.extension().and_then(|value| value.to_str()) != Some("csv")
        {
            return Err("请选择扩展名为 .csv 的绝对保存路径".into());
        }
        let frames = directory.join("frames");
        std::fs::create_dir_all(&frames).map_err(|error| format!("创建块数据目录失败：{error}"))?;
        let worker_output = frames.join(format!("blocks-{display_index}.json"));
        let frame = streamscope_ffmpeg::analyze_video_frame_blocks(
            &source,
            &worker_output,
            display_index,
            std::time::Duration::from_secs(120),
        )
        .map_err(|error| error.to_string())?;
        let csv = render_video_block_csv(&frame);
        let temporary = destination.with_extension(format!("{}.tmp", std::process::id()));
        std::fs::write(&temporary, csv.as_bytes())
            .map_err(|error| format!("写入 CSV 失败：{error}"))?;
        if destination.exists() {
            std::fs::remove_file(&destination)
                .map_err(|error| format!("无法覆盖已有 CSV：{error}"))?;
        }
        std::fs::rename(&temporary, &destination).map_err(|error| {
            let _ = std::fs::remove_file(&temporary);
            format!("完成 CSV 导出失败：{error}")
        })?;
        Ok(destination.display().to_string())
    })
    .await
    .map_err(|error| format!("视频块 CSV 导出任务异常结束：{error}"))?
}

fn render_video_block_csv(frame: &streamscope_ffmpeg::VideoWorkerFrame) -> String {
    let mut csv = String::from(
        "record_type,index,x,y,width,height,qp_base,qp_delta,qp_value,source_direction,source_x,source_y,destination_x,destination_y,motion_x,motion_y,motion_scale,flags,block_level,type_flags,prediction_flags,ref_index_l0,ref_index_l1,reference_poc_l0,reference_poc_l1,partition_mode,sub_partition_modes,prediction_mode,tree_depth,transform_flags\r\n",
    );
    if let Some(qp) = &frame.qp {
        for (index, block) in qp.blocks.iter().enumerate() {
            csv.push_str(&format!(
                "qp,{index},{},{},{},{},{},{},{},,,,,,,,,,,,,,,,,,,,,\r\n",
                block.x, block.y, block.width, block.height, qp.base, block.delta, block.value
            ));
        }
    }
    for (index, vector) in frame.motion_vectors.iter().enumerate() {
        csv.push_str(&format!(
            "mv,{index},,,{},{},,,,{},{},{},{},{},{},{},{},{},,,,,,,,,,,,\r\n",
            vector.width,
            vector.height,
            vector.source_direction,
            vector.source_x,
            vector.source_y,
            vector.destination_x,
            vector.destination_y,
            vector.motion_x,
            vector.motion_y,
            vector.motion_scale,
            vector.flags
        ));
    }
    for (index, block) in frame.block_observations.iter().enumerate() {
        csv.push_str(&format!(
            "internal,{index},{},{},{},{},,,{},,,,,,{},{},,,{},{},{},\"{}\",\"{}\",{},{},\"{}\",\"{}\",\"{}\",{},{}\r\n",
            block.x,
            block.y,
            block.width,
            block.height,
            block.qp.map(|value| value.to_string()).unwrap_or_default(),
            block
                .motion_l0_x
                .map(|value| value.to_string())
                .unwrap_or_default(),
            block
                .motion_l0_y
                .map(|value| value.to_string())
                .unwrap_or_default(),
            block.block_level,
            block.type_flags,
            block.prediction_flags,
            block
                .ref_index_l0
                .iter()
                .map(i8::to_string)
                .collect::<Vec<_>>()
                .join(";"),
            block
                .ref_index_l1
                .iter()
                .map(i8::to_string)
                .collect::<Vec<_>>()
                .join(";"),
            block
                .reference_poc_l0
                .iter()
                .map(|value| value.map(|value| value.to_string()).unwrap_or_default())
                .collect::<Vec<_>>()
                .join(";"),
            block
                .reference_poc_l1
                .iter()
                .map(|value| value.map(|value| value.to_string()).unwrap_or_default())
                .collect::<Vec<_>>()
                .join(";"),
            block.partition_mode.as_deref().unwrap_or_default(),
            block
                .sub_partition_modes
                .iter()
                .map(|value| value.as_deref().unwrap_or_default())
                .collect::<Vec<_>>()
                .join(";"),
            block.prediction_mode.as_deref().unwrap_or_default(),
            block
                .tree_depth
                .map(|value| value.to_string())
                .unwrap_or_default(),
            block
                .transform_flags
                .map(|value| value.to_string())
                .unwrap_or_default(),
        ));
    }
    csv
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
            cancel_analysis,
            export_media,
            extract_video_frame,
            compare_video_reference,
            load_video_reference_comparison,
            load_video_reference_difference,
            analyze_video_frame_blocks,
            load_video_frame_syntax,
            export_video_block_csv,
            list_analysis_history,
            load_report_html,
            load_analysis_run,
            open_report_directory,
            delete_report_directory
        ])
        .run(tauri::generate_context!())
        .expect("StreamScope 桌面程序启动失败");
}

#[cfg(test)]
mod tests {
    use super::*;
    use streamscope_ffmpeg::{
        VideoBlockObservation, VideoMotionVector, VideoQpBlock, VideoQpData, VideoWorkerFrame,
    };

    #[cfg(windows)]
    #[test]
    fn frontend_media_paths_do_not_use_the_verbatim_prefix() {
        assert_eq!(
            frontend_file_path(Path::new(r"\\?\C:\reports\frames\frame-0.png")),
            r"C:\reports\frames\frame-0.png"
        );
        assert_eq!(
            frontend_file_path(Path::new(r"\\?\UNC\server\share\frame-0.png")),
            r"\\server\share\frame-0.png"
        );
    }

    fn frame_evidence(
        frame_number: u64,
        sample_start_offset: u64,
        sample_end_offset: u64,
    ) -> streamscope_core::H264FrameEvidence {
        streamscope_core::H264FrameEvidence {
            frame_number,
            rtp_timestamp: None,
            first_sequence: None,
            last_sequence: None,
            first_nalu: frame_number,
            last_nalu: frame_number,
            first_packet: None,
            last_packet: None,
            first_offset_ms: None,
            last_offset_ms: None,
            sample_start_offset: Some(sample_start_offset),
            sample_end_offset: Some(sample_end_offset),
            idr: frame_number == 1,
            complete: true,
            boundary_confidence: "slice_header".into(),
        }
    }

    #[test]
    fn maps_frame_to_access_unit_by_unique_packet_byte_range() {
        let indexed = streamscope_core::VideoFrameIndex {
            display_index: 0,
            decode_index: None,
            decode_index_precision: "unavailable".into(),
            packet_position: Some(0),
            packet_size: Some(38_137),
            ..Default::default()
        };
        let evidence = vec![
            frame_evidence(1, 31, 38_137),
            frame_evidence(2, 38_137, 39_285),
        ];
        let (matched, precision) = resolve_frame_access_unit(&indexed, &evidence).unwrap();
        assert_eq!(matched.frame_number, 1);
        assert_eq!(precision, "ffprobe_packet_byte_range_to_parser_access_unit");
    }

    #[test]
    fn packet_byte_range_mapping_rejects_ambiguous_access_units() {
        let indexed = streamscope_core::VideoFrameIndex {
            packet_position: Some(0),
            packet_size: Some(100),
            ..Default::default()
        };
        let evidence = vec![frame_evidence(1, 0, 100), frame_evidence(2, 50, 100)];
        assert!(
            resolve_frame_access_unit(&indexed, &evidence)
                .unwrap_err()
                .contains("多个访问单元")
        );
    }

    #[test]
    fn coded_picture_number_mapping_keeps_priority() {
        let indexed = streamscope_core::VideoFrameIndex {
            decode_index: Some(1),
            packet_position: Some(0),
            packet_size: Some(100),
            ..Default::default()
        };
        let evidence = vec![frame_evidence(1, 0, 100), frame_evidence(2, 100, 200)];
        let (matched, precision) = resolve_frame_access_unit(&indexed, &evidence).unwrap();
        assert_eq!(matched.frame_number, 2);
        assert_eq!(
            precision,
            "ffmpeg_coded_picture_number_to_parser_access_unit"
        );
    }

    #[test]
    fn selected_syntax_reader_does_not_require_loading_the_whole_file() {
        let path = std::env::temp_dir().join(format!(
            "streamscope-syntax-range-{}-{}.h264",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(
            &path,
            [
                &[0, 0, 0, 1, 0x67, 0x42][..],
                &[0, 0, 1, 0x68, 0xce][..],
                &[0, 0, 1, 0x65, 0x88][..],
            ]
            .concat(),
        )
        .unwrap();
        let selected = read_annex_b_nalu_range(&path, 2, 2).unwrap();
        assert_eq!(selected, vec![(2, 9, vec![0x68, 0xce])]);
        let syntax = inspect_selected_h264_nalus(&selected);
        assert_eq!(syntax[0].index, 2);
        assert_eq!(syntax[0].offset, 9);
        assert!(syntax[0].hex.starts_with("00000009"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn block_csv_has_stable_thirty_column_schema() {
        let frame = VideoWorkerFrame {
            display_index: 7,
            pts: 7,
            best_effort_timestamp: 7,
            time_base_num: 1,
            time_base_den: 25,
            width: 1920,
            height: 1080,
            key_frame: false,
            picture_type: "P".into(),
            interlaced: false,
            analyzer_version: Some("test-worker".into()),
            qp: Some(VideoQpData {
                base: 23,
                blocks: vec![VideoQpBlock {
                    x: 16,
                    y: 32,
                    width: 16,
                    height: 16,
                    delta: 2,
                    value: 25,
                }],
            }),
            motion_vectors: vec![VideoMotionVector {
                source_direction: -1,
                width: 16,
                height: 16,
                source_x: 18,
                source_y: 31,
                destination_x: 16,
                destination_y: 32,
                motion_x: 8,
                motion_y: -4,
                motion_scale: 4,
                flags: 0,
            }],
            block_observations: vec![VideoBlockObservation {
                x: 32,
                y: 48,
                width: 8,
                height: 8,
                block_level: "hevc_pu".into(),
                type_flags: 2,
                prediction_flags: 3,
                qp: Some(27),
                partition_mode: Some("2NxN".into()),
                sub_partition_modes: Vec::new(),
                prediction_mode: Some("inter".into()),
                tree_depth: Some(2),
                transform_flags: Some(5),
                ref_index_l0: vec![0],
                ref_index_l1: vec![1],
                reference_poc_l0: vec![Some(4), None, None, None],
                reference_poc_l1: vec![Some(8), None, None, None],
                motion_l0_x: Some(12),
                motion_l0_y: Some(-4),
                motion_l1_x: Some(-8),
                motion_l1_y: Some(2),
            }],
        };
        let csv = render_video_block_csv(&frame);
        let rows = csv.trim_end().lines().collect::<Vec<_>>();
        assert_eq!(rows.len(), 4);
        assert_eq!(
            rows.iter()
                .map(|row| row.split(',').count())
                .collect::<Vec<_>>(),
            [30, 30, 30, 30]
        );
        assert!(rows[1].starts_with("qp,0,16,32,16,16,23,2,25,"));
        assert!(rows[2].starts_with("mv,0,,,16,16,,,,-1,18,31,16,32,8,-4,4,0"));
        assert!(rows[3].starts_with("internal,0,32,48,8,8,,,27"));
        assert!(rows[3].ends_with(",\"2NxN\",\"\",\"inter\",2,5"));
    }
}
