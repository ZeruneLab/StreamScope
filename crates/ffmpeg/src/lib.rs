use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::Duration;
use streamscope_core::{
    AudioLoudnessPoint, AvSyncEventPair, DecodeIssue, DecodeIssueLocation, DecodeSummary,
    ToolAvailability, Transport, VideoStreamInfo, VisualScanSummary, redact_text,
};
use wait_timeout::ChildExt;

#[derive(Debug, thiserror::Error)]
pub enum FfmpegError {
    #[error("无法启动 {program}: {source}")]
    Start {
        program: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{program} 执行超时")]
    Timeout { program: String },
    #[error("ffprobe 探测失败: {message}")]
    ProbeFailed { message: String },
    #[error("ffprobe 输出不是有效 JSON: {0}")]
    InvalidProbeJson(#[from] serde_json::Error),
    #[error("ffprobe 未找到视频流")]
    NoVideoStream,
    #[error("预览视频生成失败: {message}")]
    PreviewFailed { message: String },
    #[error("不支持的音频导出格式: {0}")]
    UnsupportedAudioExportFormat(String),
    #[error("音频导出失败: {message}")]
    AudioExportFailed { message: String },
    #[error("音频响度测量失败: {message}")]
    LoudnessMeasurementFailed { message: String },
}

#[derive(Debug)]
struct ProcessOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct ProbeDocument {
    #[serde(default)]
    streams: Vec<ProbeStream>,
    format: Option<ProbeFormat>,
}

#[derive(Debug, Deserialize)]
struct ProbeStream {
    codec_type: Option<String>,
    codec_name: Option<String>,
    profile: Option<String>,
    pix_fmt: Option<String>,
    width: Option<u32>,
    height: Option<u32>,
    avg_frame_rate: Option<String>,
    bit_rate: Option<String>,
    level: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct ProbeFormat {
    bit_rate: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub stream: VideoStreamInfo,
    pub format_bit_rate: Option<u64>,
    pub session_sdp: Option<String>,
}

fn tool_command(name: &str) -> Command {
    if let Ok(current_executable) = std::env::current_exe()
        && let Some(directory) = current_executable.parent()
    {
        let file_name = if cfg!(windows) {
            format!("{name}.exe")
        } else {
            name.to_owned()
        };
        let bundled = directory.join(file_name);
        if bundled.is_file() {
            return Command::new(bundled);
        }
    }
    Command::new(name)
}

pub fn check_tool(name: &str) -> ToolAvailability {
    let mut command = tool_command(name);
    command.arg("-version");
    hide_console_window(&mut command);
    let output = command.output();
    match output {
        Ok(output) => {
            let first_line = String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .map(str::to_owned);
            ToolAvailability {
                name: name.to_owned(),
                available: output.status.success(),
                version: first_line,
            }
        }
        Err(_) => ToolAvailability {
            name: name.to_owned(),
            available: false,
            version: None,
        },
    }
}

pub fn probe_rtsp(
    source_url: &str,
    transport: Transport,
    timeout: Duration,
) -> Result<ProbeResult, FfmpegError> {
    let timeout_micros = timeout.as_micros().min(u128::from(u64::MAX)).to_string();
    let mut command = tool_command("ffprobe");
    command.args([
        "-v",
        "trace",
        "-rtsp_transport",
        &transport.to_string(),
        "-timeout",
        &timeout_micros,
        "-show_streams",
        "-show_format",
        "-of",
        "json",
        source_url,
    ]);
    let output = run_with_timeout(command, timeout + Duration::from_secs(2), "ffprobe")?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr);
        return Err(FfmpegError::ProbeFailed {
            message: redact_text(&message, source_url).trim().to_owned(),
        });
    }
    let mut result = parse_probe_json(&output.stdout)?;
    result.session_sdp = parse_sdp_trace(&String::from_utf8_lossy(&output.stderr));
    Ok(result)
}

pub fn probe_file(source: &Path, timeout: Duration) -> Result<ProbeResult, FfmpegError> {
    let mut command = tool_command("ffprobe");
    command
        .args([
            "-v",
            "error",
            "-show_streams",
            "-show_format",
            "-of",
            "json",
        ])
        .arg(source);
    let output = run_with_timeout(command, timeout, "ffprobe")?;
    if !output.status.success() {
        return Err(FfmpegError::ProbeFailed {
            message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    parse_probe_json(&output.stdout)
}

pub fn decode_rtsp(
    source_url: &str,
    transport: Transport,
    duration: Duration,
    connection_timeout: Duration,
) -> Result<DecodeSummary, FfmpegError> {
    let timeout_micros = connection_timeout
        .as_micros()
        .min(u128::from(u64::MAX))
        .to_string();
    let duration_text = duration.as_secs().max(1).to_string();
    let mut command = tool_command("ffmpeg");
    command.args([
        "-nostdin",
        "-hide_banner",
        "-loglevel",
        "warning",
        "-rtsp_transport",
        &transport.to_string(),
        "-timeout",
        &timeout_micros,
        "-i",
        source_url,
        "-t",
        &duration_text,
        "-map",
        "0:v:0",
        "-an",
        "-f",
        "null",
        "-progress",
        "pipe:1",
        "-nostats",
        "-",
    ]);
    let process_timeout = duration + connection_timeout + Duration::from_secs(5);
    let output = run_with_timeout(command, process_timeout, "ffmpeg")?;
    let log = redact_text(&String::from_utf8_lossy(&output.stderr), source_url);
    let progress = String::from_utf8_lossy(&output.stdout);
    Ok(DecodeSummary {
        success: output.status.success(),
        exit_code: output.status.code(),
        decoded_frames: parse_decoded_frames(&progress),
        issues: parse_decode_issues(&log),
        log,
        visual_scan: VisualScanSummary::default(),
    })
}

pub fn decode_file(source: &Path, timeout: Duration) -> Result<DecodeSummary, FfmpegError> {
    let mut command = tool_command("ffmpeg");
    command
        .args(["-nostdin", "-hide_banner", "-loglevel", "info", "-i"])
        .arg(source)
        .args([
            "-map",
            "0:v:0",
            "-an",
            "-vf",
            "showinfo,blackdetect=d=0.5:pix_th=0.10,freezedetect=n=-60dB:d=1",
            "-fps_mode",
            "passthrough",
            "-f",
            "null",
            "-progress",
            "pipe:1",
            "-nostats",
            "-",
        ]);
    let output = run_with_timeout(command, timeout, "ffmpeg")?;
    let raw_log = String::from_utf8_lossy(&output.stderr).into_owned();
    let progress = String::from_utf8_lossy(&output.stdout);
    let mut issues = parse_decode_issues(&raw_log);
    let visual_scan = match scan_visual_artifacts(source, timeout.min(Duration::from_secs(45))) {
        Ok((mut visual_issues, summary)) => {
            issues.append(&mut visual_issues);
            summary
        }
        Err(error) => VisualScanSummary {
            attempted: true,
            note: Some(error.to_string()),
            ..VisualScanSummary::default()
        },
    };
    Ok(DecodeSummary {
        success: output.status.success(),
        exit_code: output.status.code(),
        decoded_frames: parse_decoded_frames(&progress),
        issues,
        log: clean_decode_log(&raw_log),
        visual_scan,
    })
}

pub fn create_preview_video(
    source: &Path,
    destination: &Path,
    timeout: Duration,
) -> Result<(), FfmpegError> {
    let mut command = tool_command("ffmpeg");
    command
        .args([
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "warning",
            "-y",
            "-i",
        ])
        .arg(source)
        .args([
            "-map",
            "0:v:0",
            "-an",
            "-t",
            "60",
            "-vf",
            "scale=w='min(1280,iw)':h=-2:flags=lanczos",
            "-c:v",
            "libx264",
            "-preset",
            "veryfast",
            "-crf",
            "23",
            "-pix_fmt",
            "yuv420p",
            "-movflags",
            "+faststart",
        ])
        .arg(destination);
    let output = run_with_timeout(command, timeout.min(Duration::from_secs(90)), "ffmpeg")?;
    if output.status.success() && destination.is_file() {
        return Ok(());
    }
    let _ = std::fs::remove_file(destination);
    Err(FfmpegError::PreviewFailed {
        message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    })
}

pub fn create_preview_audio(
    source: &Path,
    destination: &Path,
    timeout: Duration,
) -> Result<(), FfmpegError> {
    create_pcm_audio(source, destination, timeout, Some(60), None, None)
}

pub fn create_preview_audio_with_input(
    source: &Path,
    destination: &Path,
    timeout: Duration,
    input_format: &str,
    code_size: Option<u8>,
) -> Result<(), FfmpegError> {
    create_pcm_audio(
        source,
        destination,
        timeout,
        Some(60),
        Some(input_format),
        code_size,
    )
}

pub fn create_analysis_audio(
    source: &Path,
    destination: &Path,
    timeout: Duration,
) -> Result<(), FfmpegError> {
    create_pcm_audio(source, destination, timeout, None, None, None)
}

pub fn create_analysis_audio_with_input(
    source: &Path,
    destination: &Path,
    timeout: Duration,
    input_format: &str,
    code_size: Option<u8>,
) -> Result<(), FfmpegError> {
    create_pcm_audio(
        source,
        destination,
        timeout,
        None,
        Some(input_format),
        code_size,
    )
}

fn create_pcm_audio(
    source: &Path,
    destination: &Path,
    timeout: Duration,
    limit_seconds: Option<u64>,
    input_format: Option<&str>,
    code_size: Option<u8>,
) -> Result<(), FfmpegError> {
    let mut command = tool_command("ffmpeg");
    command.args(["-nostdin", "-hide_banner", "-loglevel", "warning", "-y"]);
    if let Some(format) = input_format {
        command.args(["-f", format]);
    }
    let code_size = code_size.map(|value| value.to_string());
    if let Some(code_size) = code_size.as_deref() {
        command.args(["-code_size", code_size]);
    }
    command.arg("-i").arg(source).args(["-map", "0:a:0", "-vn"]);
    let limit = limit_seconds.map(|value| value.to_string());
    if let Some(limit) = limit.as_deref() {
        command.args(["-t", limit]);
    }
    command.args(["-c:a", "pcm_s16le"]).arg(destination);
    let maximum = if limit_seconds.is_some() { 90 } else { 3_600 };
    let output = run_with_timeout(command, timeout.min(Duration::from_secs(maximum)), "ffmpeg")?;
    if output.status.success() && destination.is_file() {
        return Ok(());
    }
    let _ = std::fs::remove_file(destination);
    Err(FfmpegError::PreviewFailed {
        message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AudioLoudnessMeasurement {
    pub integrated_loudness_lufs_milli: Option<i32>,
    pub loudness_range_lu_milli: Option<i32>,
    pub true_peak_dbtp_milli: Option<i32>,
    pub series: Vec<AudioLoudnessPoint>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentSyncMeasurement {
    pub offset_ms: Option<i64>,
    pub drift_ms: Option<i64>,
    pub measurement_error_ms: u32,
    pub confidence_percent: u8,
    pub video_event_count: usize,
    pub audio_event_count: usize,
    pub pairs: Vec<AvSyncEventPair>,
}

pub fn measure_content_av_sync(
    video: &Path,
    audio: &Path,
    timeout: Duration,
) -> Result<ContentSyncMeasurement, FfmpegError> {
    const WIDTH: usize = 32;
    const HEIGHT: usize = 18;
    const FPS: u64 = 20;
    const AUDIO_RATE: u64 = 8_000;
    let mut video_command = tool_command("ffmpeg");
    video_command
        .args(["-nostdin", "-hide_banner", "-loglevel", "error", "-i"])
        .arg(video)
        .args([
            "-map",
            "0:v:0",
            "-an",
            "-t",
            "60",
            "-vf",
            "fps=20,scale=32:18:flags=area,format=gray",
            "-f",
            "rawvideo",
            "-",
        ]);
    let video_output = run_with_timeout(video_command, timeout, "ffmpeg 闪光事件检测")?;
    if !video_output.status.success() {
        return Err(FfmpegError::PreviewFailed {
            message: String::from_utf8_lossy(&video_output.stderr)
                .trim()
                .to_owned(),
        });
    }
    let mut audio_command = tool_command("ffmpeg");
    audio_command
        .args(["-nostdin", "-hide_banner", "-loglevel", "error", "-i"])
        .arg(audio)
        .args([
            "-map", "0:a:0", "-vn", "-t", "60", "-ac", "1", "-ar", "8000", "-f", "s16le", "-",
        ]);
    let audio_output = run_with_timeout(audio_command, timeout, "ffmpeg 蜂鸣事件检测")?;
    if !audio_output.status.success() {
        return Err(FfmpegError::PreviewFailed {
            message: String::from_utf8_lossy(&audio_output.stderr)
                .trim()
                .to_owned(),
        });
    }
    let frame_bytes = WIDTH * HEIGHT;
    let video_levels: Vec<u32> = video_output
        .stdout
        .chunks_exact(frame_bytes)
        .map(|frame| frame.iter().map(|value| u32::from(*value)).sum::<u32>() / frame_bytes as u32)
        .collect();
    let samples: Vec<i16> = audio_output
        .stdout
        .as_chunks::<2>()
        .0
        .iter()
        .map(|bytes| i16::from_le_bytes(*bytes))
        .collect();
    let video_events = detect_flash_events(&video_levels, FPS);
    let audio_events = detect_beep_events(&samples, AUDIO_RATE);
    Ok(pair_content_events(&video_events, &audio_events))
}

fn detect_flash_events(levels: &[u32], fps: u64) -> Vec<(u64, u32)> {
    let mut events = Vec::new();
    let mut last_ms = None;
    for (index, pair) in levels.windows(2).enumerate() {
        let rise = pair[1] as i32 - pair[0] as i32;
        let offset_ms = (index as u64 + 1) * 1_000 / fps.max(1);
        if rise >= 40
            && pair[1] >= 120
            && last_ms.is_none_or(|last| offset_ms.saturating_sub(last) >= 200)
        {
            events.push((offset_ms, (rise as u32).saturating_mul(1_000) / 255));
            last_ms = Some(offset_ms);
        }
    }
    events
}

fn detect_beep_events(samples: &[i16], sample_rate: u64) -> Vec<(u64, u32)> {
    let window = (sample_rate / 100).max(1) as usize;
    let levels: Vec<f64> = samples
        .chunks(window)
        .filter(|chunk| chunk.len() == window)
        .map(|chunk| {
            (chunk
                .iter()
                .map(|sample| f64::from(*sample) * f64::from(*sample))
                .sum::<f64>()
                / chunk.len() as f64)
                .sqrt()
        })
        .collect();
    let mut events = Vec::new();
    let mut last_ms = None;
    for (index, pair) in levels.windows(2).enumerate() {
        let offset_ms = (index as u64 + 1) * 10;
        if pair[1] >= 4_000.0
            && pair[1] >= pair[0].max(200.0) * 3.0
            && last_ms.is_none_or(|last| offset_ms.saturating_sub(last) >= 200)
        {
            events.push((
                offset_ms,
                (pair[1] / 32_768.0 * 1_000.0).round().clamp(0.0, 1_000.0) as u32,
            ));
            last_ms = Some(offset_ms);
        }
    }
    events
}

fn pair_content_events(
    video_events: &[(u64, u32)],
    audio_events: &[(u64, u32)],
) -> ContentSyncMeasurement {
    let mut used = vec![false; audio_events.len()];
    let mut pairs = Vec::new();
    for &(video_offset_ms, video_strength_milli) in video_events {
        let candidate = audio_events
            .iter()
            .enumerate()
            .filter(|(index, _)| !used[*index])
            .filter_map(|(index, &(audio_offset_ms, audio_strength_milli))| {
                let distance = video_offset_ms.abs_diff(audio_offset_ms);
                (distance <= 2_000).then_some((
                    index,
                    distance,
                    audio_offset_ms,
                    audio_strength_milli,
                ))
            })
            .min_by_key(|(_, distance, _, _)| *distance);
        if let Some((index, _, audio_offset_ms, audio_strength_milli)) = candidate {
            used[index] = true;
            pairs.push(AvSyncEventPair {
                video_offset_ms,
                audio_offset_ms,
                offset_ms: audio_offset_ms as i64 - video_offset_ms as i64,
                video_strength_milli,
                audio_strength_milli,
            });
        }
    }
    let mut offsets: Vec<i64> = pairs.iter().map(|pair| pair.offset_ms).collect();
    offsets.sort_unstable();
    let offset_ms = offsets.get(offsets.len() / 2).copied();
    let drift_ms = pairs
        .first()
        .zip(pairs.last())
        .filter(|(first, last)| first.video_offset_ms != last.video_offset_ms)
        .map(|(first, last)| last.offset_ms - first.offset_ms);
    let confidence_percent = match pairs.len() {
        0 => 0,
        1 => 45,
        2 => 75,
        _ => {
            let spread =
                offsets.last().copied().unwrap_or(0) - offsets.first().copied().unwrap_or(0);
            if spread <= 80 { 95 } else { 80 }
        }
    };
    ContentSyncMeasurement {
        offset_ms,
        drift_ms,
        measurement_error_ms: 60,
        confidence_percent,
        video_event_count: video_events.len(),
        audio_event_count: audio_events.len(),
        pairs,
    }
}

pub fn measure_audio_loudness(
    source: &Path,
    timeout: Duration,
) -> Result<AudioLoudnessMeasurement, FfmpegError> {
    let mut command = tool_command("ffmpeg");
    command
        .args([
            "-nostdin",
            "-hide_banner",
            "-nostats",
            "-loglevel",
            "verbose",
            "-i",
        ])
        .arg(source)
        .args([
            "-map",
            "0:a:0",
            "-vn",
            "-af",
            "ebur128=peak=true:framelog=verbose",
            "-f",
            "null",
            "-",
        ]);
    let output = run_with_timeout(
        command,
        timeout.min(Duration::from_secs(3_600)),
        "ffmpeg 响度测量",
    )?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(FfmpegError::LoudnessMeasurementFailed {
            message: stderr.trim().to_owned(),
        });
    }
    let (integrated, range, true_peak) =
        parse_ebur128_summary(&stderr).ok_or_else(|| FfmpegError::LoudnessMeasurementFailed {
            message: "FFmpeg 未返回 EBU R128 汇总结果".into(),
        })?;
    Ok(AudioLoudnessMeasurement {
        integrated_loudness_lufs_milli: integrated,
        loudness_range_lu_milli: range,
        true_peak_dbtp_milli: true_peak,
        series: parse_ebur128_series(&stderr),
    })
}

fn parse_ebur128_summary(stderr: &str) -> Option<(Option<i32>, Option<i32>, Option<i32>)> {
    let summary = stderr.rsplit_once("Summary:")?.1;
    let mut section = "";
    let mut integrated = None;
    let mut range = None;
    let mut true_peak = None;
    for line in summary.lines() {
        let line = line.trim();
        if line == "Integrated loudness:" {
            section = "integrated";
        } else if line == "Loudness range:" {
            section = "range";
        } else if line == "True peak:" {
            section = "peak";
        } else if section == "integrated" && line.starts_with("I:") {
            integrated = parse_marker_milli(line, "I:");
        } else if section == "range" && line.starts_with("LRA:") {
            range = parse_marker_milli(line, "LRA:");
        } else if section == "peak" && line.starts_with("Peak:") {
            true_peak = parse_marker_milli(line, "Peak:");
        }
    }
    Some((integrated, range, true_peak))
}

fn parse_marker_milli(line: &str, marker: &str) -> Option<i32> {
    let value = line
        .split_once(marker)?
        .1
        .split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()?;
    value.is_finite().then(|| (value * 1_000.0).round() as i32)
}

fn parse_ebur128_series(stderr: &str) -> Vec<AudioLoudnessPoint> {
    let mut points: Vec<AudioLoudnessPoint> = stderr
        .lines()
        .filter(|line| line.contains("] t:") && line.contains(" M:") && line.contains(" S:"))
        .filter_map(|line| {
            let seconds = parse_marker_value(line, "t:")?;
            Some(AudioLoudnessPoint {
                offset_ms: (seconds * 1_000.0).round().max(0.0) as u64,
                momentary_lufs_milli: parse_series_lufs(line, "M:", -120.0),
                short_term_lufs_milli: parse_series_lufs(line, "S:", -120.0),
                integrated_lufs_milli: parse_series_lufs(line, "I:", -70.0),
            })
        })
        .collect();
    if points.len() > 6_000 {
        let step = points.len().div_ceil(6_000);
        points = points.into_iter().step_by(step).collect();
    }
    points
}

fn parse_marker_value(line: &str, marker: &str) -> Option<f64> {
    line.split_once(marker)?
        .1
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn parse_series_lufs(line: &str, marker: &str, sentinel: f64) -> Option<i32> {
    let value = parse_marker_value(line, marker)?;
    (value > sentinel + 0.05 && value.is_finite()).then(|| (value * 1_000.0).round() as i32)
}

pub fn export_audio(
    source: &Path,
    destination: &Path,
    format: &str,
    timeout: Duration,
) -> Result<(), FfmpegError> {
    export_audio_segment(source, destination, format, None, timeout)
}

pub fn export_audio_segment(
    source: &Path,
    destination: &Path,
    format: &str,
    range_ms: Option<(u64, u64)>,
    timeout: Duration,
) -> Result<(), FfmpegError> {
    let (codec_args, muxer): (&[&str], &str) = match format {
        "wav" => (&["-c:a", "pcm_s16le"], "wav"),
        "mp3" => (&["-c:a", "libmp3lame", "-q:a", "2"], "mp3"),
        "m4a" => (&["-c:a", "aac", "-b:a", "192k"], "ipod"),
        "flac" => (&["-c:a", "flac"], "flac"),
        "ogg" => (&["-c:a", "libopus", "-b:a", "128k"], "ogg"),
        other => return Err(FfmpegError::UnsupportedAudioExportFormat(other.into())),
    };
    let mut command = tool_command("ffmpeg");
    command
        .args([
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "warning",
            "-y",
            "-i",
        ])
        .arg(source);
    if let Some((start_ms, end_ms)) = range_ms {
        if end_ms <= start_ms {
            return Err(FfmpegError::AudioExportFailed {
                message: "导出区间结束时间必须晚于开始时间".into(),
            });
        }
        command.args([
            "-ss",
            &format!("{:.3}", start_ms as f64 / 1_000.0),
            "-t",
            &format!("{:.3}", end_ms.saturating_sub(start_ms) as f64 / 1_000.0),
        ]);
    }
    command
        .args(["-map", "0:a:0", "-vn", "-map_metadata", "-1"])
        .args(codec_args)
        .args(["-f", muxer, "-progress", "pipe:1", "-nostats"])
        .arg(destination);
    let output = run_with_timeout(command, timeout.min(Duration::from_secs(300)), "ffmpeg")?;
    if output.status.success()
        && std::fs::metadata(destination).is_ok_and(|metadata| metadata.len() > 0)
        && exported_audio_has_media(&output.stdout)
    {
        return Ok(());
    }
    let _ = std::fs::remove_file(destination);
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    Err(FfmpegError::AudioExportFailed {
        message: if stderr.is_empty() || output.status.success() {
            "所选区间没有可导出的音频数据".into()
        } else {
            stderr
        },
    })
}

fn exported_audio_has_media(progress: &[u8]) -> bool {
    String::from_utf8_lossy(progress).lines().any(|line| {
        line.strip_prefix("out_time_us=")
            .or_else(|| line.strip_prefix("out_time_ms="))
            .and_then(|value| value.trim().parse::<u64>().ok())
            .is_some_and(|value| value > 0)
    })
}

const VISUAL_SCAN_WIDTH: usize = 320;
const VISUAL_SCAN_HEIGHT: usize = 180;
const VISUAL_SCAN_FPS: u32 = 4;
const VISUAL_SCAN_BANDS: usize = 45;

#[derive(Debug, Clone, Copy)]
struct BandMetric {
    fragmentation: f64,
    boundary: f64,
}

fn scan_visual_artifacts(
    source: &Path,
    timeout: Duration,
) -> Result<(Vec<DecodeIssue>, VisualScanSummary), FfmpegError> {
    let mut command = tool_command("ffmpeg");
    command
        .args(["-nostdin", "-hide_banner", "-loglevel", "error", "-i"])
        .arg(source)
        .args([
            "-map",
            "0:v:0",
            "-an",
            "-t",
            "30",
            "-vf",
            "fps=4,scale=320:180:flags=fast_bilinear",
            "-pix_fmt",
            "rgb24",
            "-f",
            "rawvideo",
            "-",
        ]);
    let output = run_with_timeout(command, timeout, "ffmpeg 画面扫描")?;
    if !output.status.success() {
        return Err(FfmpegError::PreviewFailed {
            message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    let frame_bytes = VISUAL_SCAN_WIDTH * VISUAL_SCAN_HEIGHT * 3;
    let frames: Vec<&[u8]> = output.stdout.chunks_exact(frame_bytes).collect();
    let confirmed = find_visual_detections(&frames);
    let issues = confirmed.first().map_or_else(Vec::new, |strongest| {
        let strongest = confirmed
            .iter()
            .max_by(|left, right| left.2.total_cmp(&right.2))
            .unwrap_or(strongest);
        let first_time = confirmed
            .first()
            .map_or(0.0, |item| item.0 as f64 / VISUAL_SCAN_FPS as f64);
        let last_time = confirmed
            .last()
            .map_or(first_time, |item| item.0 as f64 / VISUAL_SCAN_FPS as f64);
        vec![DecodeIssue {
            kind: "visual_corruption_candidate".into(),
            count: confirmed.len(),
            example: format!(
                "画面抽样发现局部高频彩色破碎候选：约 +{first_time:.2}s–+{last_time:.2}s，纵向 {}–{}%，区域异常比 {:.1}x、边界突变比 {:.1}x；需结合内嵌回放确认",
                strongest.1 * 100 / VISUAL_SCAN_BANDS,
                (strongest.1 + 1) * 100 / VISUAL_SCAN_BANDS,
                strongest.2,
                strongest.3,
            ),
            locations: visual_detection_boundaries(&confirmed)
                .into_iter()
                .take(256)
                .map(|(frame, _, _, _)| DecodeIssueLocation {
                    frame_number: frame as u64 + 1,
                    pts_time: Some(format!("{:.3}", frame as f64 / VISUAL_SCAN_FPS as f64)),
                    precision: "visual_scan_4fps_candidate".into(),
                })
                .collect(),
        }]
    });
    Ok((
        issues,
        VisualScanSummary {
            attempted: true,
            completed: true,
            sampled_frames: frames.len() as u64,
            sampled_fps: VISUAL_SCAN_FPS,
            scan_width: VISUAL_SCAN_WIDTH as u32,
            scan_height: VISUAL_SCAN_HEIGHT as u32,
            candidate_frames: confirmed.len() as u64,
            note: Some(
                "启发式局部破碎扫描：命中表示疑似花屏候选，未命中不等同于保证画面正常".into(),
            ),
        },
    ))
}

fn find_visual_detections(frames: &[&[u8]]) -> Vec<(usize, usize, f64, f64)> {
    let mut detections = Vec::new();
    for (frame_index, frame) in frames.iter().enumerate() {
        let metrics = visual_band_metrics(frame);
        let mut background: Vec<f64> = metrics.iter().map(|metric| metric.fragmentation).collect();
        background.sort_by(f64::total_cmp);
        let median = background[background.len() / 2].max(1.0);
        let mut boundaries: Vec<f64> = metrics
            .iter()
            .skip(1)
            .map(|metric| metric.boundary)
            .collect();
        boundaries.sort_by(f64::total_cmp);
        let median_boundary = boundaries[boundaries.len() / 2].max(1.0);
        for (band, metric) in metrics.iter().enumerate().skip(1) {
            let ratio = metric.fragmentation / median;
            let boundary_ratio = metric.boundary / median_boundary;
            if metric.fragmentation >= median * 1.75 + 3.0
                && ratio >= 1.9
                && metric.boundary >= median_boundary * 1.2 + 3.0
                && boundary_ratio >= 1.35
            {
                detections.push((frame_index, band, ratio, boundary_ratio));
            }
        }
    }
    let mut confirmed = Vec::new();
    for detection in &detections {
        let adjacent = detections
            .iter()
            .any(|other| other.0.abs_diff(detection.0) == 1 && other.1.abs_diff(detection.1) <= 1);
        if adjacent || detection.2 >= 4.0 {
            confirmed.push(*detection);
        }
    }
    confirmed.sort_by_key(|item| item.0);
    confirmed.dedup_by_key(|item| item.0);
    confirmed
}

fn visual_detection_boundaries(
    detections: &[(usize, usize, f64, f64)],
) -> Vec<(usize, usize, f64, f64)> {
    let mut boundaries = Vec::new();
    for (index, detection) in detections.iter().copied().enumerate() {
        let begins = index == 0 || detections[index - 1].0 + 1 != detection.0;
        let ends = index + 1 == detections.len() || detection.0 + 1 != detections[index + 1].0;
        if begins || ends {
            boundaries.push(detection);
        }
    }
    boundaries
}

fn visual_band_metrics(frame: &[u8]) -> Vec<BandMetric> {
    let band_height = VISUAL_SCAN_HEIGHT / VISUAL_SCAN_BANDS;
    (0..VISUAL_SCAN_BANDS)
        .map(|band| {
            let start_y = band * band_height;
            let end_y = (start_y + band_height).min(VISUAL_SCAN_HEIGHT);
            let mut jumps = 0_u64;
            let mut saturated = 0_u64;
            let mut pixels = 0_u64;
            for y in start_y..end_y {
                for x in 0..VISUAL_SCAN_WIDTH {
                    let offset = (y * VISUAL_SCAN_WIDTH + x) * 3;
                    let rgb = &frame[offset..offset + 3];
                    if u8::max(rgb[0], u8::max(rgb[1], rgb[2]))
                        .saturating_sub(u8::min(rgb[0], u8::min(rgb[1], rgb[2])))
                        > 80
                    {
                        saturated += 1;
                    }
                    if x > 0 {
                        let left = offset - 3;
                        let difference = (0..3)
                            .map(|channel| {
                                frame[offset + channel].abs_diff(frame[left + channel]) as u32
                            })
                            .sum::<u32>()
                            / 3;
                        if difference > 45 {
                            jumps += 1;
                        }
                    }
                    pixels += 1;
                }
            }
            let fragmentation = if pixels == 0 {
                0.0
            } else {
                jumps as f64 * 100.0 / pixels as f64 + saturated as f64 * 45.0 / pixels as f64
            };
            let boundary = if start_y == 0 {
                0.0
            } else {
                let mut total = 0_u64;
                for x in 0..VISUAL_SCAN_WIDTH {
                    let current = (start_y * VISUAL_SCAN_WIDTH + x) * 3;
                    let above = ((start_y - 1) * VISUAL_SCAN_WIDTH + x) * 3;
                    total += (0..3)
                        .map(|channel| {
                            frame[current + channel].abs_diff(frame[above + channel]) as u64
                        })
                        .sum::<u64>()
                        / 3;
                }
                total as f64 / VISUAL_SCAN_WIDTH as f64
            };
            BandMetric {
                fragmentation,
                boundary,
            }
        })
        .collect()
}

fn run_with_timeout(
    mut command: Command,
    timeout: Duration,
    program: &str,
) -> Result<ProcessOutput, FfmpegError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    hide_console_window(&mut command);
    let mut child = command.spawn().map_err(|source| FfmpegError::Start {
        program: program.to_owned(),
        source,
    })?;
    let mut stdout = child.stdout.take().expect("stdout pipe configured");
    let mut stderr = child.stderr.take().expect("stderr pipe configured");
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.read_to_end(&mut bytes);
        bytes
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.read_to_end(&mut bytes);
        bytes
    });

    let status = match child.wait_timeout(timeout) {
        Ok(Some(status)) => status,
        Ok(None) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(FfmpegError::Timeout {
                program: program.to_owned(),
            });
        }
        Err(source) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(FfmpegError::Start {
                program: program.to_owned(),
                source,
            });
        }
    };
    Ok(ProcessOutput {
        status,
        stdout: stdout_reader.join().unwrap_or_default(),
        stderr: stderr_reader.join().unwrap_or_default(),
    })
}

#[cfg(windows)]
fn hide_console_window(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    command.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn hide_console_window(_command: &mut Command) {}

fn parse_probe_json(bytes: &[u8]) -> Result<ProbeResult, FfmpegError> {
    let document: ProbeDocument = serde_json::from_slice(bytes)?;
    let stream = document
        .streams
        .into_iter()
        .find(|stream| stream.codec_type.as_deref() == Some("video"))
        .ok_or(FfmpegError::NoVideoStream)?;
    let frame_rate = stream.avg_frame_rate.filter(|value| value != "0/0");
    Ok(ProbeResult {
        stream: VideoStreamInfo {
            codec: stream.codec_name,
            profile: stream.profile,
            pixel_format: stream.pix_fmt,
            width: stream.width,
            height: stream.height,
            frame_rate: frame_rate.clone(),
            probed_frame_rate: frame_rate,
            bit_rate: stream.bit_rate.and_then(|value| value.parse().ok()),
            level: stream.level,
            ..VideoStreamInfo::default()
        },
        format_bit_rate: document
            .format
            .and_then(|format| format.bit_rate)
            .and_then(|value| value.parse().ok()),
        session_sdp: None,
    })
}

fn parse_sdp_trace(log: &str) -> Option<String> {
    let mut collecting = false;
    let mut lines = Vec::new();
    for line in log.lines() {
        if !collecting {
            collecting = line.trim_end().ends_with("SDP:");
            continue;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() || trimmed.starts_with('[') {
            break;
        }
        if trimmed.len() >= 2 && trimmed.as_bytes()[1] == b'=' {
            lines.push(trimmed);
        } else {
            break;
        }
    }
    (!lines.is_empty()).then(|| format!("{}\n", lines.join("\n")))
}

fn parse_decoded_frames(progress: &str) -> Option<u64> {
    progress
        .lines()
        .filter_map(|line| line.strip_prefix("frame="))
        .filter_map(|value| value.trim().parse().ok())
        .next_back()
}

pub fn parse_decode_issues(log: &str) -> Vec<DecodeIssue> {
    const PATTERNS: [(&str, &str); 21] = [
        ("non-existing pps referenced", "missing_pps"),
        ("decode_slice_header error", "slice_header_error"),
        ("no frame", "no_frame"),
        ("concealing", "concealment"),
        ("cbp too large", "invalid_cbp"),
        ("error while decoding mb", "macroblock_error"),
        ("reference picture missing", "missing_reference"),
        ("corrupt decoded frame", "corrupt_frame"),
        ("invalid nal unit", "invalid_nal_unit"),
        ("rtp: missed", "rtp_missed_packets"),
        ("black_start:", "black_segment"),
        ("freeze_start:", "freeze_segment"),
        ("could not find ref with poc", "missing_reference"),
        ("missing reference picture", "missing_reference"),
        (
            "the first slice in a frame is missing",
            "slice_header_error",
        ),
        ("cabac decode of qscale diff failed", "macroblock_error"),
        ("error parsing nal unit", "invalid_nal_unit"),
        ("invalid short term rps", "invalid_nal_unit"),
        ("skipping invalid undecodable nalu", "invalid_nal_unit"),
        ("cabac_max_bin", "bitstream_syntax_error"),
        ("outside the valid range", "bitstream_syntax_error"),
    ];
    let lines: Vec<_> = log.lines().collect();
    let showinfo: Vec<_> = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            line.contains("showinfo")
                .then(|| {
                    parse_showinfo_field(line, "n:")
                        .and_then(|value| value.parse::<u64>().ok())
                        .map(|frame| {
                            (
                                index,
                                frame + 1,
                                parse_showinfo_field(line, "pts_time:").map(str::to_owned),
                            )
                        })
                })
                .flatten()
        })
        .collect();
    let mut grouped: BTreeMap<&str, (usize, String, Vec<DecodeIssueLocation>)> = BTreeMap::new();
    for (line_index, line) in lines
        .iter()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
    {
        let lowercase = line.to_ascii_lowercase();
        for (pattern, kind) in PATTERNS {
            if lowercase.contains(pattern) {
                let entry = grouped
                    .entry(kind)
                    .or_insert((0, line.trim().to_owned(), Vec::new()));
                entry.0 += 1;
                if let Some((_, frame_number, pts_time)) = showinfo
                    .iter()
                    .min_by_key(|(showinfo_index, _, _)| showinfo_index.abs_diff(line_index))
                    && entry.2.len() < 256
                    && !entry
                        .2
                        .iter()
                        .any(|location| location.frame_number == *frame_number)
                {
                    let filter_time = match kind {
                        "black_segment" => parse_showinfo_field(line, "black_start:"),
                        "freeze_segment" => parse_showinfo_field(line, "freeze_start:"),
                        _ => None,
                    };
                    entry.2.push(DecodeIssueLocation {
                        frame_number: *frame_number,
                        pts_time: filter_time.map(str::to_owned).or_else(|| pts_time.clone()),
                        precision: if filter_time.is_some() {
                            "filter_timestamp_nearest_frame"
                        } else {
                            "candidate_nearest_log_frame"
                        }
                        .into(),
                    });
                }
            }
        }
    }
    grouped
        .into_iter()
        .map(|(kind, (count, example, locations))| DecodeIssue {
            kind: kind.to_owned(),
            count,
            example,
            locations,
        })
        .collect()
}

fn parse_showinfo_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let (_, tail) = line.split_once(key)?;
    tail.split_whitespace().next()
}

fn clean_decode_log(log: &str) -> String {
    log.lines()
        .filter(|line| !line.contains("showinfo"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_test_wav(path: &Path) {
        let sample_rate = 8_000_u32;
        let sample_count = sample_rate / 10;
        let data_size = sample_count * 2;
        let mut wav = Vec::with_capacity(44 + data_size as usize);
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&(36 + data_size).to_le_bytes());
        wav.extend_from_slice(b"WAVEfmt ");
        wav.extend_from_slice(&16_u32.to_le_bytes());
        wav.extend_from_slice(&1_u16.to_le_bytes());
        wav.extend_from_slice(&1_u16.to_le_bytes());
        wav.extend_from_slice(&sample_rate.to_le_bytes());
        wav.extend_from_slice(&(sample_rate * 2).to_le_bytes());
        wav.extend_from_slice(&2_u16.to_le_bytes());
        wav.extend_from_slice(&16_u16.to_le_bytes());
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&data_size.to_le_bytes());
        wav.resize(44 + data_size as usize, 0);
        std::fs::write(path, wav).unwrap();
    }

    fn write_tone_wav(path: &Path) {
        let sample_rate = 48_000_u32;
        let samples: Vec<i16> = (0..sample_rate)
            .map(|index| {
                let phase = std::f64::consts::TAU * 1_000.0 * index as f64 / f64::from(sample_rate);
                (phase.sin() * 3_276.0).round() as i16
            })
            .collect();
        let data_size = samples.len() as u32 * 2;
        let mut wav = Vec::with_capacity(44 + data_size as usize);
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&(36 + data_size).to_le_bytes());
        wav.extend_from_slice(b"WAVEfmt ");
        wav.extend_from_slice(&16_u32.to_le_bytes());
        wav.extend_from_slice(&1_u16.to_le_bytes());
        wav.extend_from_slice(&1_u16.to_le_bytes());
        wav.extend_from_slice(&sample_rate.to_le_bytes());
        wav.extend_from_slice(&(sample_rate * 2).to_le_bytes());
        wav.extend_from_slice(&2_u16.to_le_bytes());
        wav.extend_from_slice(&16_u16.to_le_bytes());
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&data_size.to_le_bytes());
        for sample in samples {
            wav.extend_from_slice(&sample.to_le_bytes());
        }
        std::fs::write(path, wav).unwrap();
    }

    #[test]
    fn parses_video_stream_from_ffprobe_json() {
        let json = br#"{
          "streams": [{"codec_type":"audio","codec_name":"aac"},
                      {"codec_type":"video","codec_name":"h264","profile":"High","width":1920,
                       "height":1080,"avg_frame_rate":"25/1","bit_rate":"2100000","level":40}],
          "format": {"bit_rate":"2200000"}
        }"#;
        let result = parse_probe_json(json).unwrap();
        assert_eq!(result.stream.codec.as_deref(), Some("h264"));
        assert_eq!(result.stream.width, Some(1920));
        assert_eq!(result.stream.frame_rate.as_deref(), Some("25/1"));
        assert_eq!(result.format_bit_rate, Some(2_200_000));
    }

    #[test]
    fn extracts_sdp_block_from_ffprobe_trace() {
        let log = "[rtsp @ 0001] SDP:\nv=0\no=- 1 1 IN IP4 192.0.2.1\ns=Camera\nt=0 0\nm=video 0 RTP/AVP 96\n[rtsp @ 0001] setting jitter buffer size";
        let sdp = parse_sdp_trace(log).unwrap();
        assert!(sdp.starts_with("v=0\n"));
        assert!(sdp.contains("m=video 0 RTP/AVP 96"));
        assert!(!sdp.contains("jitter"));
    }

    #[test]
    fn groups_known_decoder_messages_without_claiming_root_cause() {
        let issues = parse_decode_issues(
            "[h264] non-existing PPS referenced\n[h264] error while decoding MB 1 2\n[h264] error while decoding MB 3 4",
        );
        assert_eq!(issues.len(), 2);
        assert!(issues.iter().any(|issue| issue.kind == "missing_pps"));
        assert_eq!(
            issues
                .iter()
                .find(|issue| issue.kind == "macroblock_error")
                .unwrap()
                .count,
            2
        );
    }

    #[test]
    fn classifies_hevc_reference_and_bitstream_errors_seen_in_real_streams() {
        let issues = parse_decode_issues(
            "[hevc] Could not find ref with POC 0\n[hevc] CABAC_MAX_BIN : 7\n[hevc] The cu_qp_delta 99 is outside the valid range [-26, 25].\n[hevc] Skipping invalid undecodable NALU: 19",
        );
        assert!(issues.iter().any(|issue| issue.kind == "missing_reference"));
        assert!(issues.iter().any(|issue| issue.kind == "invalid_nal_unit"));
        assert_eq!(
            issues
                .iter()
                .find(|issue| issue.kind == "bitstream_syntax_error")
                .unwrap()
                .count,
            2
        );
    }

    #[test]
    fn associates_decoder_message_with_nearby_showinfo_frame_as_candidate() {
        let issues = parse_decode_issues(
            "[Parsed_showinfo_0] n: 41 pts: 49200 pts_time:1.64\n[h264] error while decoding MB 1 2\n[Parsed_showinfo_0] n: 42 pts: 50400 pts_time:1.68",
        );
        let issue = issues
            .iter()
            .find(|issue| issue.kind == "macroblock_error")
            .unwrap();
        assert_eq!(issue.locations.len(), 1);
        assert_eq!(issue.locations[0].frame_number, 42);
        assert_eq!(issue.locations[0].pts_time.as_deref(), Some("1.64"));
        assert_eq!(issue.locations[0].precision, "candidate_nearest_log_frame");
    }

    #[test]
    fn reads_last_progress_frame_count() {
        assert_eq!(parse_decoded_frames("frame=1\nfps=0\nframe=42\n"), Some(42));
    }

    #[test]
    fn detects_and_pairs_flash_beep_events_with_known_offset() {
        let mut video = vec![30_u32; 100];
        video[20] = 220;
        video[60] = 230;
        let flashes = detect_flash_events(&video, 20);
        assert_eq!(
            flashes.iter().map(|event| event.0).collect::<Vec<_>>(),
            [1_000, 3_000]
        );

        let mut audio = vec![0_i16; 8_000 * 5];
        for start_ms in [1_120_usize, 3_120] {
            let start = start_ms * 8;
            for sample in &mut audio[start..start + 800] {
                *sample = 12_000;
            }
        }
        let beeps = detect_beep_events(&audio, 8_000);
        let result = pair_content_events(&flashes, &beeps);
        assert_eq!(result.pairs.len(), 2);
        assert_eq!(result.offset_ms, Some(120));
        assert_eq!(result.drift_ms, Some(0));
        assert_eq!(result.confidence_percent, 75);
    }

    #[test]
    fn rejects_unknown_audio_export_format_before_starting_ffmpeg() {
        let error = export_audio(
            Path::new("missing.wav"),
            Path::new("missing.tmp"),
            "unknown",
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            FfmpegError::UnsupportedAudioExportFormat(format) if format == "unknown"
        ));
    }

    #[test]
    fn parses_ebur128_log_and_measures_a_known_tone() {
        let log = "[Parsed_ebur128_0] t: 0.400 TARGET:-23 LUFS M: -23.4 S:-120.7 I: -24.5 LUFS LRA: 1.2 LU\n[Parsed_ebur128_0] Summary:\n\n Integrated loudness:\n I: -24.5 LUFS\n Threshold: -34.5 LUFS\n\n Loudness range:\n LRA: 1.2 LU\n\n True peak:\n Peak: -1.3 dBFS";
        let (integrated, range, peak) = parse_ebur128_summary(log).unwrap();
        assert_eq!(integrated, Some(-24_500));
        assert_eq!(range, Some(1_200));
        assert_eq!(peak, Some(-1_300));
        let series = parse_ebur128_series(log);
        assert_eq!(series.len(), 1);
        assert_eq!(series[0].offset_ms, 400);
        assert_eq!(series[0].momentary_lufs_milli, Some(-23_400));
        assert_eq!(series[0].short_term_lufs_milli, None);
        if !check_tool("ffmpeg").available {
            return;
        }
        let directory =
            std::env::temp_dir().join(format!("streamscope-loudness-test-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let source = directory.join("tone.wav");
        write_tone_wav(&source);
        let measurement = measure_audio_loudness(&source, Duration::from_secs(30)).unwrap();
        assert!(
            measurement
                .integrated_loudness_lufs_milli
                .is_some_and(|value| (-30_000..=-15_000).contains(&value))
        );
        assert!(
            measurement
                .true_peak_dbtp_milli
                .is_some_and(|value| (-21_000..=-19_000).contains(&value))
        );
        assert!(!measurement.series.is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn exports_each_supported_audio_format_with_forced_muxer() {
        if !check_tool("ffmpeg").available {
            return;
        }
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "streamscope-audio-export-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let source = directory.join("source.wav");
        write_test_wav(&source);

        for (format, signature) in [
            ("wav", b"RIFF".as_slice()),
            ("mp3", b"ID3".as_slice()),
            ("m4a", b"ftyp".as_slice()),
            ("flac", b"fLaC".as_slice()),
            ("ogg", b"OggS".as_slice()),
        ] {
            let destination = directory.join(format!("{format}.tmp"));
            export_audio(&source, &destination, format, Duration::from_secs(30)).unwrap();
            let bytes = std::fs::read(destination).unwrap();
            let signature_offset = usize::from(format == "m4a") * 4;
            assert_eq!(
                &bytes[signature_offset..signature_offset + signature.len()],
                signature,
                "unexpected {format} container signature"
            );
        }
        let segment = directory.join("segment.tmp");
        export_audio_segment(
            &source,
            &segment,
            "wav",
            Some((20, 70)),
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(std::fs::metadata(&segment).unwrap().len() > 256);
        let empty = directory.join("empty.tmp");
        assert!(
            export_audio_segment(
                &source,
                &empty,
                "wav",
                Some((1_000, 1_100)),
                Duration::from_secs(30),
            )
            .is_err()
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn decodes_supported_raw_telephony_formats_to_pcm() {
        if !check_tool("ffmpeg").available {
            return;
        }
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "streamscope-telephony-decode-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let cases = [
            ("g722", None, vec![0_u8; 8_000]),
            ("g726", Some(2), vec![0_u8; 2_000]),
            ("g726", Some(3), vec![0_u8; 3_000]),
            ("g726", Some(4), vec![0_u8; 4_000]),
            ("g726", Some(5), vec![0_u8; 5_000]),
            ("g726le", Some(2), vec![0_u8; 2_000]),
            ("g726le", Some(3), vec![0_u8; 3_000]),
            ("g726le", Some(4), vec![0_u8; 4_000]),
            ("g726le", Some(5), vec![0_u8; 5_000]),
            ("g723_1", None, vec![0_u8; 24 * 34]),
            ("g729", None, vec![0_u8; 10 * 100]),
        ];
        for (index, (format, code_size, bytes)) in cases.into_iter().enumerate() {
            let source = directory.join(format!("source-{index}.bin"));
            let destination = directory.join(format!("decoded-{index}.wav"));
            std::fs::write(&source, bytes).unwrap();
            create_analysis_audio_with_input(
                &source,
                &destination,
                Duration::from_secs(30),
                format,
                code_size,
            )
            .unwrap_or_else(|error| panic!("{format} decode failed: {error}"));
            assert!(std::fs::metadata(destination).unwrap().len() > 44);
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn visual_scan_detects_persistent_colored_corruption_strip() {
        let frame_bytes = VISUAL_SCAN_WIDTH * VISUAL_SCAN_HEIGHT * 3;
        let flat = vec![128_u8; frame_bytes];
        let mut corrupted = flat.clone();
        let start_y = VISUAL_SCAN_HEIGHT - VISUAL_SCAN_HEIGHT / VISUAL_SCAN_BANDS;
        for y in start_y..VISUAL_SCAN_HEIGHT {
            for x in 0..VISUAL_SCAN_WIDTH {
                let offset = (y * VISUAL_SCAN_WIDTH + x) * 3;
                let color = if (x / 2 + y / 2) % 2 == 0 {
                    [255, 0, 220]
                } else {
                    [0, 255, 20]
                };
                corrupted[offset..offset + 3].copy_from_slice(&color);
            }
        }
        assert!(find_visual_detections(&[&flat, &flat]).is_empty());
        let detections = find_visual_detections(&[&corrupted, &corrupted]);
        assert_eq!(detections.len(), 2);
        assert!(
            detections
                .iter()
                .all(|item| item.1 == VISUAL_SCAN_BANDS - 1)
        );
        assert_eq!(visual_detection_boundaries(&detections).len(), 2);
    }
}
