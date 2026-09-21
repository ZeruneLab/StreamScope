use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use streamscope_core::{
    AudioLoudnessPoint, AvSyncEventPair, DecodeIssue, DecodeIssueLocation, DecodeSummary,
    ToolAvailability, Transport, VideoAnalysisCapability, VideoDeepAnalysis, VideoFrameIndex,
    VideoStreamInfo, VisualScanSummary, redact_text,
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
    #[error("逐帧图像提取失败: {message}")]
    FrameExtractFailed { message: String },
    #[error("不支持的音频导出格式: {0}")]
    UnsupportedAudioExportFormat(String),
    #[error("音频导出失败: {message}")]
    AudioExportFailed { message: String },
    #[error("音频响度测量失败: {message}")]
    LoudnessMeasurementFailed { message: String },
    #[error("视频块分析失败: {message}")]
    VideoWorkerFailed { message: String },
    #[error("参考视频质量对比失败: {message}")]
    VideoComparisonFailed { message: String },
    #[error("分析任务已由用户取消")]
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VideoReferenceComparison {
    pub reference_name: String,
    pub psnr_average_db: Option<f64>,
    pub psnr_identical: bool,
    pub ssim_all: f64,
    #[serde(default)]
    pub vmaf_mean: Option<f64>,
    pub compared_frames: u64,
    #[serde(default)]
    pub compared_duration_ms: Option<u64>,
    #[serde(default)]
    pub source_width: Option<u32>,
    #[serde(default)]
    pub source_height: Option<u32>,
    #[serde(default)]
    pub reference_width: Option<u32>,
    #[serde(default)]
    pub reference_height: Option<u32>,
    #[serde(default)]
    pub source_pixel_format: Option<String>,
    #[serde(default)]
    pub reference_pixel_format: Option<String>,
    #[serde(default)]
    pub comparison_pixel_format: String,
    #[serde(default)]
    pub source_frame_rate: Option<String>,
    #[serde(default)]
    pub reference_frame_rate: Option<String>,
    #[serde(default)]
    pub alignment_method: String,
    #[serde(default)]
    pub detected_offset_ms: i64,
    #[serde(default)]
    pub alignment_confidence_percent: u8,
    #[serde(default)]
    pub alignment_error_milli: Option<u32>,
    #[serde(default)]
    pub coverage_basis: String,
    pub method: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VideoWorkerDocument {
    pub schema_version: String,
    pub ffmpeg_version: String,
    pub codec: String,
    pub requested_start: u64,
    pub requested_count: u64,
    pub frames: Vec<VideoWorkerFrame>,
    pub decoded_through: u64,
    pub emitted_frames: u64,
    pub window_complete: bool,
    pub source_eof_reached: bool,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VideoWorkerFrame {
    pub display_index: u64,
    pub pts: i64,
    pub best_effort_timestamp: i64,
    pub time_base_num: i32,
    pub time_base_den: i32,
    pub width: u32,
    pub height: u32,
    pub key_frame: bool,
    pub picture_type: String,
    pub interlaced: bool,
    #[serde(default)]
    pub analyzer_version: Option<String>,
    pub qp: Option<VideoQpData>,
    pub motion_vectors: Vec<VideoMotionVector>,
    #[serde(default)]
    pub block_observations: Vec<VideoBlockObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VideoBlockObservation {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub block_level: String,
    pub type_flags: u32,
    pub prediction_flags: u8,
    #[serde(default)]
    pub qp: Option<i32>,
    #[serde(default)]
    pub partition_mode: Option<String>,
    #[serde(default)]
    pub sub_partition_modes: Vec<Option<String>>,
    #[serde(default)]
    pub prediction_mode: Option<String>,
    #[serde(default)]
    pub tree_depth: Option<u8>,
    #[serde(default)]
    pub transform_flags: Option<u8>,
    #[serde(default)]
    pub ref_index_l0: Vec<i8>,
    #[serde(default)]
    pub ref_index_l1: Vec<i8>,
    #[serde(default, deserialize_with = "deserialize_reference_pocs")]
    pub reference_poc_l0: Vec<Option<i32>>,
    #[serde(default, deserialize_with = "deserialize_reference_pocs")]
    pub reference_poc_l1: Vec<Option<i32>>,
    #[serde(default)]
    pub motion_l0_x: Option<i16>,
    #[serde(default)]
    pub motion_l0_y: Option<i16>,
    #[serde(default)]
    pub motion_l1_x: Option<i16>,
    #[serde(default)]
    pub motion_l1_y: Option<i16>,
}

fn deserialize_reference_pocs<'de, D>(deserializer: D) -> Result<Vec<Option<i32>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ReferencePocs {
        Legacy(Option<i32>),
        Partitioned(Vec<Option<i32>>),
    }

    Ok(match ReferencePocs::deserialize(deserializer)? {
        ReferencePocs::Legacy(Some(value)) => vec![Some(value)],
        ReferencePocs::Legacy(None) => Vec::new(),
        ReferencePocs::Partitioned(values) => values,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VideoQpData {
    pub base: i32,
    pub blocks: Vec<VideoQpBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VideoQpBlock {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub delta: i32,
    pub value: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VideoMotionVector {
    pub source_direction: i32,
    pub width: u32,
    pub height: u32,
    pub source_x: i32,
    pub source_y: i32,
    pub destination_x: i32,
    pub destination_y: i32,
    pub motion_x: i32,
    pub motion_y: i32,
    pub motion_scale: u32,
    pub flags: u64,
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

#[derive(Debug, Deserialize)]
struct FrameProbeDocument {
    #[serde(default)]
    frames: Vec<FrameProbeRecord>,
}

#[derive(Debug, Deserialize)]
struct FrameProbeRecord {
    #[serde(default)]
    key_frame: Option<ProbeScalar>,
    #[serde(default)]
    pts_time: Option<ProbeScalar>,
    #[serde(default)]
    pkt_dts_time: Option<ProbeScalar>,
    #[serde(default)]
    best_effort_timestamp_time: Option<ProbeScalar>,
    #[serde(default)]
    pkt_duration_time: Option<ProbeScalar>,
    #[serde(default)]
    pkt_pos: Option<ProbeScalar>,
    #[serde(default)]
    pkt_size: Option<ProbeScalar>,
    #[serde(default)]
    pict_type: Option<String>,
    #[serde(default)]
    coded_picture_number: Option<ProbeScalar>,
    #[serde(default)]
    interlaced_frame: Option<ProbeScalar>,
    #[serde(default)]
    top_field_first: Option<ProbeScalar>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ProbeScalar {
    Text(String),
    Signed(i64),
    Unsigned(u64),
    Boolean(bool),
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

fn video_worker_command() -> Command {
    if let Some(directory) = std::env::var_os("STREAMSCOPE_VIDEO_WORKER_DIR") {
        let executable = Path::new(&directory).join(if cfg!(windows) {
            "video-worker.exe"
        } else {
            "video-worker"
        });
        if executable.is_file() {
            return Command::new(executable);
        }
    }
    tool_command("video-worker")
}

pub fn analyze_video_frame_blocks(
    source: &Path,
    output: &Path,
    display_index: u64,
    timeout: Duration,
) -> Result<VideoWorkerFrame, FfmpegError> {
    let mut command = video_worker_command();
    command
        .arg(source)
        .arg(output)
        .arg(display_index.to_string())
        .arg("1");
    let process = run_with_timeout(command, timeout, "video-worker")?;
    if !process.status.success() {
        let _ = std::fs::remove_file(output);
        return Err(FfmpegError::VideoWorkerFailed {
            message: String::from_utf8_lossy(&process.stderr).trim().to_owned(),
        });
    }
    let document: VideoWorkerDocument =
        serde_json::from_slice(&std::fs::read(output).map_err(|error| {
            FfmpegError::VideoWorkerFailed {
                message: format!("无法读取 worker 输出：{error}"),
            }
        })?)
        .map_err(FfmpegError::InvalidProbeJson)?;
    if !matches!(
        document.schema_version.as_str(),
        "streamscope.video-worker.v1"
            | "streamscope.video-worker.v2"
            | "streamscope.video-worker.v3"
            | "streamscope.video-worker.v4"
    ) {
        return Err(FfmpegError::VideoWorkerFailed {
            message: format!("不支持的 worker 数据版本：{}", document.schema_version),
        });
    }
    let analyzer_version = format!(
        "{} / FFmpeg {}",
        document.schema_version, document.ffmpeg_version
    );
    document
        .frames
        .into_iter()
        .find(|frame| frame.display_index == display_index)
        .map(|mut frame| {
            frame.analyzer_version = Some(analyzer_version);
            frame
        })
        .ok_or_else(|| FfmpegError::VideoWorkerFailed {
            message: format!("worker 未返回第 {display_index} 帧，视频可能已截断"),
        })
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

pub fn probe_video_frames(
    source: &Path,
    codec: &str,
    timeout: Duration,
) -> Result<VideoDeepAnalysis, FfmpegError> {
    const MAX_RETAINED_FRAMES: usize = 50_000;
    let mut command = tool_command("ffprobe");
    command
        .args([
            "-v",
            "error",
            "-select_streams",
            "v:0",
            "-show_frames",
            "-show_entries",
            "frame=key_frame,pts_time,pkt_dts_time,best_effort_timestamp_time,pkt_duration_time,pkt_pos,pkt_size,pict_type,coded_picture_number,interlaced_frame,top_field_first",
            "-of",
            "json",
        ])
        .arg(source);
    let output = run_with_timeout(command, timeout, "ffprobe 帧索引")?;
    if !output.status.success() {
        return Err(FfmpegError::ProbeFailed {
            message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    parse_frame_probe_json(&output.stdout, codec, MAX_RETAINED_FRAMES)
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

pub fn extract_video_frame(
    source: &Path,
    destination: &Path,
    display_index: u64,
    timeout: Duration,
) -> Result<(), FfmpegError> {
    let filter = format!("select=eq(n\\,{display_index})");
    let mut command = tool_command("ffmpeg");
    command
        .args(["-nostdin", "-hide_banner", "-loglevel", "error", "-y", "-i"])
        .arg(source)
        .args(["-map", "0:v:0", "-an", "-vf", &filter, "-frames:v", "1"])
        .arg(destination);
    let output = run_with_timeout(command, timeout, "ffmpeg 逐帧图像提取")?;
    if output.status.success()
        && destination
            .metadata()
            .is_ok_and(|metadata| metadata.len() > 0)
    {
        return Ok(());
    }
    let _ = std::fs::remove_file(destination);
    Err(FfmpegError::FrameExtractFailed {
        message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    })
}

pub fn compare_video_reference(
    source: &Path,
    reference: &Path,
    timeout: Duration,
) -> Result<VideoReferenceComparison, FfmpegError> {
    let source_probe = probe_file(source, timeout.min(Duration::from_secs(30)))?;
    let reference_probe = probe_file(reference, timeout.min(Duration::from_secs(30)))?;
    let width = source_probe
        .stream
        .width
        .ok_or_else(|| FfmpegError::VideoComparisonFailed {
            message: "无法取得主视频宽度".into(),
        })?;
    let height = source_probe
        .stream
        .height
        .ok_or_else(|| FfmpegError::VideoComparisonFailed {
            message: "无法取得主视频高度".into(),
        })?;
    let comparison_pixel_format = comparison_pixel_format(
        source_probe.stream.pixel_format.as_deref(),
        reference_probe.stream.pixel_format.as_deref(),
    );
    let alignment = detect_content_alignment(source, reference, timeout).unwrap_or_default();
    let filter_prefix =
        comparison_filter_prefix(width, height, comparison_pixel_format, alignment.offset_ms);
    let framesync = "shortest=1:eof_action=endall:repeatlast=0";
    let (ssim_log, compared_frames, compared_duration_ms) = run_video_metric(
        source,
        reference,
        &format!("{filter_prefix};[main][reference]ssim={framesync}"),
        timeout,
        "SSIM",
    )?;
    let ssim_all = parse_video_metric(&ssim_log, "All:").ok_or_else(|| {
        FfmpegError::VideoComparisonFailed {
            message: "FFmpeg 未返回 SSIM 汇总值，可能没有可对齐的视频帧".into(),
        }
    })?;
    let (psnr_log, psnr_frames, psnr_duration_ms) = run_video_metric(
        source,
        reference,
        &format!("{filter_prefix};[main][reference]psnr={framesync}"),
        timeout,
        "PSNR",
    )?;
    let psnr_value = parse_video_metric_token(&psnr_log, "average:").ok_or_else(|| {
        FfmpegError::VideoComparisonFailed {
            message: "FFmpeg 未返回 PSNR 汇总值，可能没有可对齐的视频帧".into(),
        }
    })?;
    let psnr_identical = psnr_value.eq_ignore_ascii_case("inf");
    let psnr_average_db = if psnr_identical {
        None
    } else {
        psnr_value
            .parse::<f64>()
            .ok()
            .filter(|value| value.is_finite())
    };
    if !psnr_identical && psnr_average_db.is_none() {
        return Err(FfmpegError::VideoComparisonFailed {
            message: format!("无法解析 FFmpeg 返回的 PSNR 值：{psnr_value}"),
        });
    }
    let compared_frames = compared_frames
        .or(psnr_frames)
        .filter(|value| *value > 0)
        .ok_or_else(|| FfmpegError::VideoComparisonFailed {
            message: "FFmpeg 没有比较任何视频帧".into(),
        })?;
    let compared_duration_ms = compared_duration_ms.or(psnr_duration_ms);
    let mut limitations = vec!["结果衡量像素差异，不直接等同于人眼主观画质或花屏诊断结论。".into()];
    if !alignment.reliable {
        limitations.push(
            "内容指纹没有得到可信的非零偏移；本次按两路起始 PTS 归零比较。静态或重复画面可能无法自动对齐。"
                .into(),
        );
    } else {
        limitations.push(
            "内容对齐使用前 120 秒、2 fps、32×18 灰度指纹在 ±30 秒内搜索；周期性或高度重复画面仍可能产生歧义。"
                .into(),
        );
    }
    if (reference_probe.stream.width, reference_probe.stream.height) != (Some(width), Some(height))
    {
        limitations.push("参考视频已使用 bicubic 缩放到主视频分辨率；缩放会影响客观指标。".into());
    }
    if source_probe.stream.pixel_format.as_deref() != Some(comparison_pixel_format)
        || reference_probe.stream.pixel_format.as_deref() != Some(comparison_pixel_format)
    {
        limitations.push(format!(
            "两路画面统一转换为 {comparison_pixel_format} 后比较；色度采样或位深转换可能影响指标。"
        ));
    }
    if source_probe.stream.frame_rate != reference_probe.stream.frame_rate {
        limitations
            .push("两路帧率不同；当前不插帧，按归零后的时间戳交由 FFmpeg framesync 配对。".into());
    }
    let vmaf_mean = match run_video_metric(
        source,
        reference,
        &format!("{filter_prefix};[main][reference]libvmaf={framesync}"),
        timeout,
        "VMAF",
    ) {
        Ok((log, _, _)) => parse_video_metric(&log, "score:"),
        Err(_) => None,
    };
    if vmaf_mean.is_none() {
        limitations.push("当前 FFmpeg 构建未返回 VMAF；PSNR/SSIM 结果仍有效。".into());
    }
    Ok(VideoReferenceComparison {
        reference_name: reference
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("reference-video")
            .to_owned(),
        psnr_average_db,
        psnr_identical,
        ssim_all,
        vmaf_mean,
        compared_frames,
        compared_duration_ms,
        source_width: source_probe.stream.width,
        source_height: source_probe.stream.height,
        reference_width: reference_probe.stream.width,
        reference_height: reference_probe.stream.height,
        source_pixel_format: source_probe.stream.pixel_format,
        reference_pixel_format: reference_probe.stream.pixel_format,
        comparison_pixel_format: comparison_pixel_format.into(),
        source_frame_rate: source_probe.stream.frame_rate,
        reference_frame_rate: reference_probe.stream.frame_rate,
        alignment_method: if alignment.reliable {
            "content_luma_fingerprint_2fps".into()
        } else {
            "start_pts_zero_fallback".into()
        },
        detected_offset_ms: alignment.offset_ms,
        alignment_confidence_percent: alignment.confidence_percent,
        alignment_error_milli: alignment.error_milli,
        coverage_basis: "shortest_common_decoded_frame_sequence".into(),
        method: "FFmpeg 软件解码；先做低分辨率内容指纹偏移搜索，再将对齐后的 PTS 归零；禁用末帧重复；参考画面按需缩放到主视频尺寸；只比较共同解码覆盖".into(),
        limitations,
    })
}

const ALIGNMENT_FPS: i64 = 2;
const ALIGNMENT_WIDTH: usize = 32;
const ALIGNMENT_HEIGHT: usize = 18;

#[derive(Debug, Clone, Copy, Default)]
struct ContentAlignment {
    offset_ms: i64,
    confidence_percent: u8,
    error_milli: Option<u32>,
    reliable: bool,
}

fn comparison_filter_prefix(width: u32, height: u32, pixel_format: &str, offset_ms: i64) -> String {
    let source_start = if offset_ms < 0 {
        -offset_ms as f64 / 1_000.0
    } else {
        0.0
    };
    let reference_start = if offset_ms > 0 {
        offset_ms as f64 / 1_000.0
    } else {
        0.0
    };
    format!(
        "[0:v]trim=start={source_start:.3},setpts=PTS-STARTPTS,scale={width}:{height}:flags=bicubic,format={pixel_format}[main];[1:v]trim=start={reference_start:.3},setpts=PTS-STARTPTS,scale={width}:{height}:flags=bicubic,format={pixel_format}[reference]"
    )
}

fn detect_content_alignment(
    source: &Path,
    reference: &Path,
    timeout: Duration,
) -> Result<ContentAlignment, FfmpegError> {
    let source_frames = extract_alignment_fingerprints(source, timeout)?;
    let reference_frames = extract_alignment_fingerprints(reference, timeout)?;
    Ok(find_content_alignment(&source_frames, &reference_frames))
}

fn extract_alignment_fingerprints(
    source: &Path,
    timeout: Duration,
) -> Result<Vec<Vec<u8>>, FfmpegError> {
    let mut command = tool_command("ffmpeg");
    command
        .args(["-nostdin", "-hide_banner", "-loglevel", "error", "-i"])
        .arg(source)
        .args([
            "-map",
            "0:v:0",
            "-an",
            "-t",
            "120",
            "-vf",
            "fps=2,scale=32:18:flags=area,format=gray",
            "-frames:v",
            "240",
            "-pix_fmt",
            "gray",
            "-f",
            "rawvideo",
            "pipe:1",
        ]);
    let output = run_with_timeout(
        command,
        timeout.min(Duration::from_secs(45)),
        "ffmpeg 内容指纹",
    )?;
    if !output.status.success() {
        return Err(FfmpegError::VideoComparisonFailed {
            message: format!(
                "内容指纹提取失败：{}",
                compact_process_error(&String::from_utf8_lossy(&output.stderr))
            ),
        });
    }
    let frame_size = ALIGNMENT_WIDTH * ALIGNMENT_HEIGHT;
    Ok(output
        .stdout
        .chunks_exact(frame_size)
        .map(|frame| frame.to_vec())
        .collect())
}

fn find_content_alignment(source: &[Vec<u8>], reference: &[Vec<u8>]) -> ContentAlignment {
    let shorter = source.len().min(reference.len());
    if shorter < 4 {
        return ContentAlignment::default();
    }
    let minimum_overlap = (shorter / 3).max(4);
    let maximum_shift = 60_i32.min((shorter - minimum_overlap) as i32);
    let score = |shift: i32| -> Option<f64> {
        let source_start = (-shift).max(0) as usize;
        let reference_start = shift.max(0) as usize;
        let overlap = (source.len() - source_start).min(reference.len() - reference_start);
        if overlap < minimum_overlap {
            return None;
        }
        let total = source[source_start..source_start + overlap]
            .iter()
            .zip(&reference[reference_start..reference_start + overlap])
            .map(|(left, right)| {
                left.iter()
                    .zip(right)
                    .map(|(left, right)| (*left as i16 - *right as i16).unsigned_abs() as u64)
                    .sum::<u64>()
            })
            .sum::<u64>();
        Some(total as f64 / (overlap * ALIGNMENT_WIDTH * ALIGNMENT_HEIGHT) as f64 / 255.0)
    };
    let zero_score = score(0).unwrap_or(1.0);
    let Some((best_shift, best_score)) = (-maximum_shift..=maximum_shift)
        .filter_map(|shift| score(shift).map(|value| (shift, value)))
        .min_by(|left, right| left.1.total_cmp(&right.1))
    else {
        return ContentAlignment::default();
    };
    let scene_activity = source
        .windows(2)
        .chain(reference.windows(2))
        .map(|frames| {
            frames[0]
                .iter()
                .zip(&frames[1])
                .map(|(left, right)| (*left as i16 - *right as i16).unsigned_abs() as u64)
                .sum::<u64>() as f64
                / (ALIGNMENT_WIDTH * ALIGNMENT_HEIGHT) as f64
        })
        .fold(0.0_f64, f64::max);
    let improvement = if zero_score > f64::EPSILON {
        ((zero_score - best_score) / zero_score).max(0.0)
    } else {
        1.0
    };
    let reliable =
        best_shift != 0 && scene_activity >= 2.0 && improvement >= 0.15 && best_score <= 0.25;
    ContentAlignment {
        offset_ms: if reliable {
            i64::from(best_shift) * 1_000 / ALIGNMENT_FPS
        } else {
            0
        },
        confidence_percent: if reliable {
            (improvement * 100.0).round().clamp(1.0, 100.0) as u8
        } else if best_shift == 0 && best_score <= 0.05 {
            100
        } else {
            0
        },
        error_milli: Some((best_score * 1_000.0).round().clamp(0.0, 1_000.0) as u32),
        reliable,
    }
}

fn comparison_pixel_format(source: Option<&str>, reference: Option<&str>) -> &'static str {
    let high_bit_depth = |format: Option<&str>| {
        format.is_some_and(|value| {
            value.contains("p10")
                || value.contains("p12")
                || value.contains("p14")
                || value.contains("p16")
                || value.starts_with("p010")
                || value.starts_with("p016")
        })
    };
    if high_bit_depth(source) || high_bit_depth(reference) {
        "yuv420p10le"
    } else {
        "yuv420p"
    }
}

pub fn create_video_reference_difference_preview(
    source: &Path,
    reference: &Path,
    destination: &Path,
    timeout: Duration,
) -> Result<(), FfmpegError> {
    let source_probe = probe_file(source, timeout.min(Duration::from_secs(30)))?;
    let width = source_probe
        .stream
        .width
        .ok_or_else(|| FfmpegError::VideoComparisonFailed {
            message: "无法取得主视频宽度".into(),
        })?;
    let height = source_probe
        .stream
        .height
        .ok_or_else(|| FfmpegError::VideoComparisonFailed {
            message: "无法取得主视频高度".into(),
        })?;
    let alignment = detect_content_alignment(source, reference, timeout).unwrap_or_default();
    let prefix = comparison_filter_prefix(width, height, "yuv420p", alignment.offset_ms);
    let filter = format!(
        "{prefix};[main][reference]blend=all_mode=difference:shortest=1,eq=contrast=4:brightness=0.02[difference]"
    );
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
        .arg("-i")
        .arg(reference)
        .args([
            "-filter_complex",
            &filter,
            "-map",
            "[difference]",
            "-an",
            "-shortest",
            "-t",
            "60",
            "-c:v",
            "libx264",
            "-preset",
            "veryfast",
            "-crf",
            "18",
            "-pix_fmt",
            "yuv420p",
            "-movflags",
            "+faststart",
        ])
        .arg(destination);
    let output = run_with_timeout(command, timeout, "ffmpeg 参考视频差异预览")?;
    if output.status.success()
        && destination
            .metadata()
            .is_ok_and(|metadata| metadata.len() > 0)
    {
        return Ok(());
    }
    let _ = std::fs::remove_file(destination);
    Err(FfmpegError::VideoComparisonFailed {
        message: format!(
            "差异预览生成失败：{}",
            compact_process_error(&String::from_utf8_lossy(&output.stderr))
        ),
    })
}

fn run_video_metric(
    source: &Path,
    reference: &Path,
    filter: &str,
    timeout: Duration,
    metric: &str,
) -> Result<(String, Option<u64>, Option<u64>), FfmpegError> {
    let mut command = tool_command("ffmpeg");
    command
        .args(["-nostdin", "-hide_banner", "-loglevel", "info", "-i"])
        .arg(source)
        .arg("-i")
        .arg(reference)
        .args([
            "-filter_complex",
            filter,
            "-an",
            "-shortest",
            "-progress",
            "pipe:1",
            "-nostats",
            "-f",
            "null",
            "-",
        ]);
    let output = run_with_timeout(command, timeout, &format!("ffmpeg {metric}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        return Err(FfmpegError::VideoComparisonFailed {
            message: format!("{metric} 计算未完成：{}", compact_process_error(&stderr)),
        });
    }
    let progress = String::from_utf8_lossy(&output.stdout);
    Ok((
        stderr,
        parse_decoded_frames(&progress),
        parse_progress_duration_ms(&progress),
    ))
}

fn parse_progress_duration_ms(progress: &str) -> Option<u64> {
    progress
        .lines()
        .filter_map(|line| line.strip_prefix("out_time_us="))
        .filter_map(|value| value.trim().parse::<u64>().ok())
        .next_back()
        .map(|value| value / 1_000)
}

fn parse_video_metric(log: &str, marker: &str) -> Option<f64> {
    parse_video_metric_token(log, marker)?
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite())
}

fn parse_video_metric_token<'a>(log: &'a str, marker: &str) -> Option<&'a str> {
    log.lines().rev().find_map(|line| {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        parts.iter().enumerate().find_map(|(index, part)| {
            let suffix = part.strip_prefix(marker)?;
            let value = if suffix.is_empty() {
                *parts.get(index + 1)?
            } else {
                suffix
            };
            Some(value.trim_matches(|character: char| character == ',' || character == ';'))
        })
    })
}

fn compact_process_error(log: &str) -> String {
    log.lines()
        .rev()
        .find(|line| {
            let line = line.trim();
            !line.is_empty()
                && !line.starts_with("Input #")
                && !line.starts_with("  Metadata:")
                && !line.starts_with("  Duration:")
        })
        .map(str::trim)
        .unwrap_or("FFmpeg 未提供错误详情")
        .to_owned()
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
const VISUAL_SCAN_FPS: u32 = 8;
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
            "fps=8,scale=320:180:flags=fast_bilinear",
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
                    precision: "visual_scan_8fps_candidate".into(),
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
                "8 fps 启发式局部破碎扫描：提高短暂花屏捕获率；命中表示疑似候选，未命中不等同于保证画面正常".into(),
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
            if metric.fragmentation >= median * 1.6 + 2.5
                && ratio >= 1.7
                && metric.boundary >= median_boundary * 1.15 + 2.5
                && boundary_ratio >= 1.25
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
        if adjacent || detection.2 >= 3.0 {
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

    let started = Instant::now();
    let status = loop {
        if streamscope_core::analysis_cancellation_requested() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(FfmpegError::Cancelled);
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(FfmpegError::Timeout {
                program: program.to_owned(),
            });
        }
        match child.wait_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(Some(status)) => break status,
            Ok(None) => {}
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

fn parse_frame_probe_json(
    bytes: &[u8],
    codec: &str,
    maximum_frames: usize,
) -> Result<VideoDeepAnalysis, FfmpegError> {
    let document: FrameProbeDocument = serde_json::from_slice(bytes)?;
    let total_frames = document.frames.len();
    let mut decode_index_counts = BTreeMap::<u64, usize>::new();
    for decode_index in document
        .frames
        .iter()
        .filter_map(|frame| scalar_u64(frame.coded_picture_number.as_ref()))
    {
        *decode_index_counts.entry(decode_index).or_default() += 1;
    }
    let frames: Vec<_> = document
        .frames
        .into_iter()
        .take(maximum_frames)
        .enumerate()
        .map(|(index, frame)| {
            let reported_decode_index = scalar_u64(frame.coded_picture_number.as_ref());
            let decode_index = reported_decode_index.filter(|value| {
                *value < total_frames as u64 && decode_index_counts.get(value).copied() == Some(1)
            });
            let pts_ms = scalar_milliseconds(
                frame
                    .pts_time
                    .as_ref()
                    .or(frame.best_effort_timestamp_time.as_ref()),
            );
            VideoFrameIndex {
                display_index: index as u64,
                decode_index,
                decode_index_precision: match (reported_decode_index, decode_index) {
                    (Some(_), Some(_)) => "ffmpeg_coded_picture_number",
                    (Some(_), None) => "unavailable_invalid_or_non_unique_coded_picture_number",
                    (None, _) => "unavailable",
                }
                .into(),
                pts_ms,
                dts_ms: scalar_milliseconds(frame.pkt_dts_time.as_ref()),
                duration_ms: scalar_milliseconds(frame.pkt_duration_time.as_ref())
                    .and_then(|value| u64::try_from(value).ok()),
                packet_position: scalar_u64(frame.pkt_pos.as_ref()),
                packet_size: scalar_u64(frame.pkt_size.as_ref()),
                picture_type: frame.pict_type,
                key_frame: scalar_bool(frame.key_frame.as_ref()).unwrap_or(false),
                interlaced: scalar_bool(frame.interlaced_frame.as_ref()),
                top_field_first: scalar_bool(frame.top_field_first.as_ref()),
            }
        })
        .collect();
    let coverage_start_ms = frames
        .iter()
        .filter_map(|frame| frame.pts_ms)
        .min()
        .and_then(|value| u64::try_from(value).ok());
    let coverage_end_ms = frames
        .iter()
        .filter_map(|frame| {
            frame
                .pts_ms
                .and_then(|value| u64::try_from(value).ok())
                .map(|value| value.saturating_add(frame.duration_ms.unwrap_or(0)))
        })
        .max();
    let coverage_complete = total_frames <= maximum_frames;
    let block_reason = if codec.eq_ignore_ascii_case("h264") {
        "由独立 video-worker 按所选帧导出实际 QP、MV、宏块类型和参考列表索引；未加载的帧不生成块数据"
    } else {
        "由定制 video-worker 按所选帧导出兼容的最小 CB/PU 网格，以及解码器解析得到的 CTU、叶子 CU/PU 和有变换语法的叶子 TU；无残差或 PCM 块不伪造 TU"
    };
    Ok(VideoDeepAnalysis {
        codec: codec.to_ascii_lowercase(),
        status: if frames.is_empty() {
            "unavailable"
        } else if coverage_complete {
            "indexed"
        } else {
            "partial"
        }
        .into(),
        indexed_frames: frames.len() as u64,
        coverage_start_ms,
        coverage_end_ms,
        coverage_complete,
        coverage_reason: (!coverage_complete)
            .then(|| format!("帧索引超过 {maximum_frames} 条，仅保留前 {maximum_frames} 帧")),
        frames,
        capabilities: vec![
            VideoAnalysisCapability {
                id: "frame_index".into(),
                label: "逐帧索引".into(),
                status: "available".into(),
                reason: None,
            },
            VideoAnalysisCapability {
                id: "block_qp".into(),
                label: "块级 QP".into(),
                status: "on_demand".into(),
                reason: Some(block_reason.into()),
            },
            VideoAnalysisCapability {
                id: "motion_vectors".into(),
                label: "运动矢量".into(),
                status: "on_demand".into(),
                reason: Some(block_reason.into()),
            },
            VideoAnalysisCapability {
                id: "motion_partition_geometry".into(),
                label: "运动分区几何".into(),
                status: "on_demand".into(),
                reason: Some(if codec.eq_ignore_ascii_case("h264") {
                    "宽高来自 AVMotionVector 的实际运动块；只覆盖导出 MV 的预测块，不等同于完整宏块类型树"
                } else {
                    "PU 宽高来自解码器实际 PartMode；同时保留最小 PU 采样网格用于兼容和交叉核验"
                }.into()),
            },
            VideoAnalysisCapability {
                id: "block_partition".into(),
                label: if codec.eq_ignore_ascii_case("h264") {
                    "宏块类型 / 参考列表"
                } else {
                    "CTU / CU / PU / TU 树"
                }
                .into(),
                status: "on_demand".into(),
                reason: Some(block_reason.into()),
            },
        ],
        limitations: vec![
            "显示序号来自 ffprobe 解码输出顺序；编码序号只在解码器提供 coded_picture_number 时可用"
                .into(),
            "裸码流缺少容器时间戳时，PTS/DTS、持续时间和字节位置可能为空".into(),
            "逐帧索引可用于定位与统计，但不等同于块级编码分析".into(),
        ],
    })
}

fn scalar_text(value: Option<&ProbeScalar>) -> Option<&str> {
    match value? {
        ProbeScalar::Text(value) => Some(value),
        _ => None,
    }
}

fn scalar_u64(value: Option<&ProbeScalar>) -> Option<u64> {
    match value? {
        ProbeScalar::Text(value) => value.parse().ok(),
        ProbeScalar::Signed(value) => u64::try_from(*value).ok(),
        ProbeScalar::Unsigned(value) => Some(*value),
        ProbeScalar::Boolean(value) => Some(u64::from(*value)),
    }
}

fn scalar_bool(value: Option<&ProbeScalar>) -> Option<bool> {
    match value? {
        ProbeScalar::Text(value) => match value.as_str() {
            "0" | "false" => Some(false),
            "1" | "true" => Some(true),
            _ => None,
        },
        ProbeScalar::Signed(value) => Some(*value != 0),
        ProbeScalar::Unsigned(value) => Some(*value != 0),
        ProbeScalar::Boolean(value) => Some(*value),
    }
}

fn scalar_milliseconds(value: Option<&ProbeScalar>) -> Option<i64> {
    let value = scalar_text(value)?;
    let seconds = value.parse::<f64>().ok()?;
    seconds
        .is_finite()
        .then(|| (seconds * 1_000.0).round() as i64)
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
    fn accepts_legacy_single_reference_poc_and_partitioned_pocs() {
        let legacy = serde_json::from_str::<VideoBlockObservation>(
            r#"{"x":0,"y":0,"width":16,"height":16,"block_level":"h264_macroblock","type_flags":1,"prediction_flags":0,"qp":24,"ref_index_l0":[0,-1,-1,-1],"ref_index_l1":[-1,-1,-1,-1],"reference_poc_l0":12,"reference_poc_l1":null,"motion_l0_x":null,"motion_l0_y":null,"motion_l1_x":null,"motion_l1_y":null}"#,
        )
        .unwrap();
        assert_eq!(legacy.reference_poc_l0, vec![Some(12)]);
        assert!(legacy.reference_poc_l1.is_empty());
        assert!(legacy.partition_mode.is_none());
        assert!(legacy.sub_partition_modes.is_empty());

        let partitioned = serde_json::from_str::<VideoBlockObservation>(
            r#"{"x":0,"y":0,"width":16,"height":16,"block_level":"h264_macroblock","type_flags":1,"prediction_flags":0,"qp":24,"partition_mode":"8x8","sub_partition_modes":["8x8","8x4","4x8","4x4"],"ref_index_l0":[0,1,-1,-1],"ref_index_l1":[-1,-1,-1,-1],"reference_poc_l0":[12,8,null,null],"reference_poc_l1":[null,null,null,null],"motion_l0_x":null,"motion_l0_y":null,"motion_l1_x":null,"motion_l1_y":null}"#,
        )
        .unwrap();
        assert_eq!(
            partitioned.reference_poc_l0,
            vec![Some(12), Some(8), None, None]
        );

        let sparse = serde_json::from_str::<VideoBlockObservation>(
            r#"{"x":0,"y":0,"width":64,"height":64,"block_level":"hevc_ctu","type_flags":0,"prediction_flags":0,"tree_depth":0}"#,
        )
        .unwrap();
        assert_eq!(sparse.block_level, "hevc_ctu");
        assert_eq!(sparse.qp, None);
        assert!(sparse.ref_index_l0.is_empty());
        assert_eq!(sparse.motion_l0_x, None);
        assert_eq!(partitioned.partition_mode.as_deref(), Some("8x8"));
        assert_eq!(
            partitioned.sub_partition_modes,
            vec![
                Some("8x8".into()),
                Some("8x4".into()),
                Some("4x8".into()),
                Some("4x4".into())
            ]
        );
    }

    #[test]
    fn builds_bounded_video_frame_index_without_inventing_block_data() {
        let json = br#"{
          "frames": [
            {"key_frame":1,"pts_time":"0.000000","pkt_dts_time":"0.000000",
             "pkt_duration_time":"0.040000","pkt_pos":"12","pkt_size":"900",
             "pict_type":"I","coded_picture_number":0,"interlaced_frame":0},
            {"key_frame":0,"best_effort_timestamp_time":"0.040000",
             "pkt_duration_time":"0.040000","pkt_pos":"912","pkt_size":"120",
             "pict_type":"P","coded_picture_number":1,"interlaced_frame":0}
          ]
        }"#;
        let analysis = parse_frame_probe_json(json, "h264", 1).unwrap();
        assert_eq!(analysis.status, "partial");
        assert_eq!(analysis.indexed_frames, 1);
        assert!(!analysis.coverage_complete);
        assert_eq!(analysis.frames[0].picture_type.as_deref(), Some("I"));
        assert_eq!(analysis.frames[0].packet_position, Some(12));
        assert_eq!(analysis.frames[0].duration_ms, Some(40));
        assert!(
            analysis.capabilities.iter().any(|capability| {
                capability.id == "block_qp" && capability.status == "on_demand"
            })
        );

        let hevc = parse_frame_probe_json(json, "h265", 2).unwrap();
        assert!(hevc.capabilities.iter().any(|capability| {
            capability.id == "block_qp"
                && capability.status == "on_demand"
                && capability
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("CTU"))
        }));
        assert!(hevc.capabilities.iter().any(|capability| {
            capability.id == "block_partition"
                && capability.label == "CTU / CU / PU / TU 树"
                && capability.status == "on_demand"
        }));
    }

    #[test]
    fn rejects_ambiguous_or_out_of_range_decode_indices() {
        let json = br#"{
          "frames": [
            {"coded_picture_number":0,"pict_type":"I"},
            {"coded_picture_number":0,"pict_type":"P"},
            {"coded_picture_number":9,"pict_type":"P"}
          ]
        }"#;
        let analysis = parse_frame_probe_json(json, "h264", 10).unwrap();
        assert!(
            analysis
                .frames
                .iter()
                .all(|frame| frame.decode_index.is_none())
        );
        assert!(analysis.frames.iter().all(|frame| {
            frame.decode_index_precision == "unavailable_invalid_or_non_unique_coded_picture_number"
        }));
    }

    #[test]
    fn extracts_an_exact_display_frame_to_png() {
        if !check_tool("ffmpeg").available {
            return;
        }
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/h264/generated-normal.h264");
        if !source.is_file() {
            return;
        }
        let directory = std::env::temp_dir().join(format!(
            "streamscope-frame-extract-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let destination = directory.join("frame-3.png");
        extract_video_frame(&source, &destination, 3, Duration::from_secs(30)).unwrap();
        let bytes = std::fs::read(&destination).unwrap();
        assert!(bytes.starts_with(&[0x89, b'P', b'N', b'G']));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn reads_real_h264_qp_blocks_and_motion_vectors_from_worker() {
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/h264/generated-normal.h264");
        if !source.is_file() {
            return;
        }
        let directory = std::env::temp_dir().join(format!(
            "streamscope-video-worker-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let output = directory.join("frame-3.json");
        let frame = match analyze_video_frame_blocks(&source, &output, 3, Duration::from_secs(30)) {
            Ok(frame) => frame,
            Err(FfmpegError::Start { .. }) => {
                std::fs::remove_dir_all(directory).unwrap();
                return;
            }
            Err(error) => panic!("video worker failed: {error}"),
        };
        assert_eq!(frame.display_index, 3);
        assert_eq!(frame.picture_type, "P");
        let qp = frame.qp.expect("H.264 decoder should export QP blocks");
        assert!(!qp.blocks.is_empty());
        assert!(
            qp.blocks
                .iter()
                .all(|block| (0..=63).contains(&block.value))
        );
        assert!(!frame.motion_vectors.is_empty());
        assert!(
            frame
                .motion_vectors
                .iter()
                .all(|vector| vector.motion_scale > 0)
        );
        let macroblocks = frame
            .block_observations
            .iter()
            .filter(|block| block.block_level == "h264_macroblock")
            .collect::<Vec<_>>();
        assert!(!macroblocks.is_empty());
        assert!(
            macroblocks
                .iter()
                .all(|block| block.partition_mode.is_some())
        );
        for block in macroblocks
            .iter()
            .filter(|block| block.partition_mode.as_deref() == Some("8x8"))
        {
            assert_eq!(block.sub_partition_modes.len(), 4);
            assert!(
                block
                    .sub_partition_modes
                    .iter()
                    .flatten()
                    .all(|mode| { matches!(mode.as_str(), "8x8" | "8x4" | "4x8" | "4x4") })
            );
        }
        let referenced = frame
            .block_observations
            .iter()
            .filter(|block| block.block_level == "h264_macroblock")
            .flat_map(|block| {
                block
                    .ref_index_l0
                    .iter()
                    .zip(&block.reference_poc_l0)
                    .chain(block.ref_index_l1.iter().zip(&block.reference_poc_l1))
            })
            .filter(|(index, _)| **index >= 0)
            .collect::<Vec<_>>();
        assert!(
            !referenced.is_empty(),
            "P frame should use a reference picture"
        );
        assert!(
            referenced.iter().all(|(_, poc)| poc.is_some()),
            "every used H.264 8x8 reference index must resolve to a POC"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn keeps_b_frame_identity_when_loading_worker_blocks() {
        if !check_tool("ffmpeg").available {
            return;
        }
        let directory = std::env::temp_dir().join(format!(
            "streamscope-video-worker-b-frame-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let source = directory.join("b-frames.h264");
        let mut encoder = tool_command("ffmpeg");
        encoder.args([
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=320x180:rate=25",
            "-frames:v",
            "30",
            "-c:v",
            "libx264",
            "-profile:v",
            "high",
            "-g",
            "15",
            "-bf",
            "2",
            "-x264-params",
            "partitions=all",
            "-pix_fmt",
            "yuv420p",
            "-f",
            "h264",
            "-y",
        ]);
        encoder.arg(&source);
        let encoded = run_with_timeout(encoder, Duration::from_secs(30), "ffmpeg test encoder")
            .expect("test encoder should start");
        assert!(
            encoded.status.success(),
            "test encoder failed: {}",
            String::from_utf8_lossy(&encoded.stderr)
        );
        let index = probe_video_frames(&source, "h264", Duration::from_secs(30)).unwrap();
        let b_frame = index
            .frames
            .iter()
            .find(|frame| frame.picture_type.as_deref() == Some("B"))
            .expect("generated stream should contain B frames");
        let output = directory.join("b-frame.json");
        let blocks = match analyze_video_frame_blocks(
            &source,
            &output,
            b_frame.display_index,
            Duration::from_secs(30),
        ) {
            Ok(frame) => frame,
            Err(FfmpegError::Start { .. }) => {
                std::fs::remove_dir_all(directory).unwrap();
                return;
            }
            Err(error) => panic!("video worker failed: {error}"),
        };
        assert_eq!(blocks.display_index, b_frame.display_index);
        assert_eq!(blocks.picture_type, "B");
        assert!(blocks.qp.is_some());
        assert!(!blocks.motion_vectors.is_empty());
        assert!(
            blocks
                .block_observations
                .iter()
                .filter(|block| block.block_level == "h264_macroblock")
                .all(|block| block.partition_mode.is_some())
        );
        assert!(blocks.block_observations.iter().any(|block| {
            block.partition_mode.as_deref() == Some("8x8")
                && block.sub_partition_modes.len() == 4
                && block.sub_partition_modes.iter().all(|mode| {
                    mode.as_deref()
                        .is_some_and(|value| matches!(value, "8x8" | "8x4" | "4x8" | "4x4"))
                })
        }));
        assert!(blocks.block_observations.iter().any(|block| {
            block
                .ref_index_l1
                .iter()
                .zip(&block.reference_poc_l1)
                .any(|(index, poc)| *index >= 0 && poc.is_some())
        }));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn reports_h265_internal_blocks_only_when_worker_exports_verified_data() {
        if !check_tool("ffmpeg").available {
            return;
        }
        let directory = std::env::temp_dir().join(format!(
            "streamscope-video-worker-h265-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let source = directory.join("sample.h265");
        let mut encoder = tool_command("ffmpeg");
        encoder.args([
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=160x96:rate=10",
            "-frames:v",
            "6",
            "-c:v",
            "libx265",
            "-x265-params",
            "log-level=error",
            "-pix_fmt",
            "yuv420p",
            "-f",
            "hevc",
            "-y",
        ]);
        encoder.arg(&source);
        let encoded = run_with_timeout(encoder, Duration::from_secs(30), "ffmpeg test encoder")
            .expect("test encoder should start");
        if !encoded.status.success() {
            std::fs::remove_dir_all(directory).unwrap();
            return;
        }
        let index = probe_video_frames(&source, "h265", Duration::from_secs(30)).unwrap();
        let predicted = index
            .frames
            .iter()
            .find(|frame| frame.picture_type.as_deref() != Some("I"))
            .expect("generated HEVC stream should contain a predicted frame");
        let output = directory.join("frame.json");
        let frame = match analyze_video_frame_blocks(
            &source,
            &output,
            predicted.display_index,
            Duration::from_secs(30),
        ) {
            Ok(frame) => frame,
            Err(FfmpegError::Start { .. }) => {
                std::fs::remove_dir_all(directory).unwrap();
                return;
            }
            Err(error) => panic!("video worker failed: {error}"),
        };
        assert_eq!(frame.display_index, predicted.display_index);
        if frame.block_observations.is_empty() {
            assert_eq!(frame.qp, None);
        } else {
            assert!(frame.qp.as_ref().is_some_and(|qp| !qp.blocks.is_empty()));
            assert!(
                frame
                    .block_observations
                    .iter()
                    .all(|block| block.block_level.starts_with("hevc_"))
            );
            assert!(
                frame
                    .block_observations
                    .iter()
                    .any(|block| block.block_level == "hevc_ctu")
            );
            assert!(frame.block_observations.iter().any(|block| {
                block.block_level == "hevc_cu"
                    && block.partition_mode.is_some()
                    && block.prediction_mode.is_some()
                    && block.tree_depth.is_some()
            }));
            assert!(frame.block_observations.iter().any(|block| {
                block.block_level == "hevc_pu"
                    && block.partition_mode.is_some()
                    && block.prediction_mode.is_some()
                    && block.prediction_flags != 0
            }));
            assert!(frame.block_observations.iter().any(|block| {
                block.block_level == "hevc_tu"
                    && block.tree_depth.is_some()
                    && block.transform_flags.is_some()
            }));
        }
        std::fs::remove_dir_all(directory).unwrap();
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
        assert_eq!(
            parse_progress_duration_ms(
                "out_time_us=40000\nprogress=continue\nout_time_us=1680000\n"
            ),
            Some(1_680)
        );
    }

    #[test]
    fn preserves_high_bit_depth_for_reference_metrics() {
        assert_eq!(
            comparison_pixel_format(Some("yuv420p"), Some("nv12")),
            "yuv420p"
        );
        assert_eq!(
            comparison_pixel_format(Some("yuv420p10le"), Some("yuv420p")),
            "yuv420p10le"
        );
    }

    #[test]
    fn parses_last_video_quality_metric() {
        let log = "[Parsed_ssim_0] SSIM Y:0.9 All:0.912345 (10.5)\n[Parsed_psnr_0] PSNR average:38.765 min:30 max:44\n";
        assert_eq!(parse_video_metric(log, "All:"), Some(0.912345));
        assert_eq!(parse_video_metric_token(log, "average:"), Some("38.765"));
        assert_eq!(
            parse_video_metric("[libvmaf] VMAF score: 99.125000", "score:"),
            Some(99.125)
        );
        assert_eq!(
            parse_video_metric_token("PSNR average:inf min:inf", "average:"),
            Some("inf")
        );
    }

    #[test]
    fn compares_identical_reference_video() {
        if !check_tool("ffmpeg").available {
            return;
        }
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("h264")
            .join("generated-normal.h264");
        let comparison = compare_video_reference(&source, &source, Duration::from_secs(60))
            .expect("identical reference comparison should succeed");
        assert!(comparison.ssim_all > 0.999_999);
        assert!(comparison.psnr_identical);
        assert!(comparison.psnr_average_db.is_none());
        if let Some(vmaf) = comparison.vmaf_mean {
            assert!(vmaf > 95.0);
        }
        assert!(comparison.compared_frames > 0);
        assert!(comparison.compared_duration_ms.is_some());
        assert_eq!(comparison.source_width, comparison.reference_width);
        assert_eq!(comparison.source_height, comparison.reference_height);
        assert!(!comparison.comparison_pixel_format.is_empty());
        assert_eq!(comparison.detected_offset_ms, 0);
        assert!(matches!(
            comparison.alignment_method.as_str(),
            "content_luma_fingerprint_2fps" | "start_pts_zero_fallback"
        ));
        assert_eq!(
            comparison.coverage_basis,
            "shortest_common_decoded_frame_sequence"
        );
        let preview = std::env::temp_dir().join(format!(
            "streamscope-reference-difference-{}.mp4",
            std::process::id()
        ));
        create_video_reference_difference_preview(
            &source,
            &source,
            &preview,
            Duration::from_secs(60),
        )
        .expect("difference preview should be generated");
        assert!(preview.metadata().unwrap().len() > 0);
        std::fs::remove_file(preview).unwrap();
    }

    #[test]
    fn reference_comparison_stops_at_shorter_input_without_repeating_last_frame() {
        if !check_tool("ffmpeg").available {
            return;
        }
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("h264")
            .join("generated-normal.h264");
        let directory = std::env::temp_dir().join(format!(
            "streamscope-short-reference-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let reference = directory.join("three-frames.mp4");
        let mut command = tool_command("ffmpeg");
        command
            .args(["-nostdin", "-hide_banner", "-loglevel", "error", "-y", "-i"])
            .arg(&source)
            .args([
                "-frames:v",
                "3",
                "-an",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
            ])
            .arg(&reference);
        let output =
            run_with_timeout(command, Duration::from_secs(30), "ffmpeg 测试参考视频").unwrap();
        assert!(output.status.success());

        let comparison = compare_video_reference(&source, &reference, Duration::from_secs(60))
            .expect("short reference comparison should succeed");
        assert_eq!(comparison.compared_frames, 3);
        assert_eq!(
            comparison.coverage_basis,
            "shortest_common_decoded_frame_sequence"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn finds_known_content_fingerprint_offset() {
        let frame = |value: u8| vec![value; ALIGNMENT_WIDTH * ALIGNMENT_HEIGHT];
        let source = (0..20).map(|index| frame(index * 10)).collect::<Vec<_>>();
        let mut reference = vec![frame(255), frame(240)];
        reference.extend(source.iter().cloned());

        let alignment = find_content_alignment(&source, &reference);
        assert!(alignment.reliable);
        assert_eq!(alignment.offset_ms, 1_000);
        assert_eq!(alignment.error_milli, Some(0));
        assert!(alignment.confidence_percent >= 90);
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

    #[test]
    fn visual_scan_does_not_flag_a_clean_static_lower_third() {
        let frame_bytes = VISUAL_SCAN_WIDTH * VISUAL_SCAN_HEIGHT * 3;
        let mut frame = vec![150_u8; frame_bytes];
        for y in VISUAL_SCAN_HEIGHT * 3 / 4..VISUAL_SCAN_HEIGHT {
            for x in 0..VISUAL_SCAN_WIDTH {
                let offset = (y * VISUAL_SCAN_WIDTH + x) * 3;
                frame[offset..offset + 3].copy_from_slice(&[30, 80, 180]);
            }
        }
        assert!(find_visual_detections(&[&frame, &frame]).is_empty());
    }
}
