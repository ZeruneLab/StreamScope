use chrono::Utc;
use serde::Serialize;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use streamscope_audio::{
    AudioRtpPayload, RawRtpAudioSpec, analyze as analyze_audio, enrich_from_pcm_wav_with_scope,
    raw_rtp_audio_spec, write_aac_adts_mapped, write_opus_ogg_mapped, write_raw_rtp_audio,
};
use streamscope_capture::{CapturedStream, analyze_capture_file_with_progress};
use streamscope_core::{
    AnalysisRequest, AnalysisResult, AnalysisStatus, AudioTrackResult, AvSyncAnalysis, DataQuality,
    ModuleTimings, RESULT_SCHEMA_VERSION, SourceKind, Transport, UrlSafetyError, VideoStreamInfo,
    redact_rtsp_url, redact_text, validate_rtsp_url,
};
use streamscope_diagnostics::{build_timeline, evaluate};
use streamscope_ffmpeg::{
    check_tool, create_analysis_audio, create_analysis_audio_with_input, create_preview_audio,
    create_preview_audio_with_input, create_preview_video, decode_file, measure_audio_loudness,
    measure_content_av_sync, probe_file,
};
use streamscope_h264::{Depacketizer, RtpPayload, analyze_annex_b, analyze_nalus};
use streamscope_h265::{
    Depacketizer as H265Depacketizer, RtpPayload as H265RtpPayload,
    analyze_annex_b as analyze_h265_annex_b, analyze_nalus as analyze_h265_nalus,
};
use streamscope_report::{ReportError, write_reports};
use streamscope_rtsp::{CapturedMediaTrack, RtspClientOptions, analyze_rtsp_capture_with_progress};

#[derive(Debug, Clone)]
pub struct AnalyzeOptions {
    pub source_url: String,
    pub transport: Transport,
    pub duration_seconds: u64,
    pub connect_timeout_seconds: u64,
    pub output_root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct H264FileOptions {
    pub input: PathBuf,
    pub output_root: PathBuf,
    pub process_timeout_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct H265FileOptions {
    pub input: PathBuf,
    pub output_root: PathBuf,
    pub process_timeout_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct AudioFileOptions {
    pub input: PathBuf,
    pub output_root: PathBuf,
    pub process_timeout_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct PcapFileOptions {
    pub input: PathBuf,
    pub output_root: PathBuf,
    pub process_timeout_seconds: u64,
    /// Empty scans all streams; "*" decodes all, otherwise decode the listed stream IDs.
    pub stream_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneratedReports {
    pub json: String,
    pub html: String,
    pub ffmpeg_log: String,
    pub session_sdp: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisRun {
    pub result: AnalysisResult,
    pub report_directory: String,
    pub reports: GeneratedReports,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisProgress {
    pub percent: u8,
    pub stage: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub live_audio_tracks: Vec<LiveAudioTrackProgress>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveAudioTrackProgress {
    pub track_index: usize,
    pub codec: String,
    pub payload_type: u8,
    pub channels: Option<u16>,
    pub packet_count: u64,
    pub payload_bytes: u64,
    pub elapsed_ms: u64,
    pub peak_level_dbfs_milli: Option<i32>,
    pub rms_level_dbfs_milli: Option<i32>,
    pub waveform: Vec<i16>,
    pub live_decode_active: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComparisonRun {
    pub tcp: AnalysisRun,
    pub udp: AnalysisRun,
    pub conclusions: Vec<String>,
    pub report_directory: String,
    pub json: String,
    pub html: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AnalyzerError {
    #[error(transparent)]
    InvalidUrl(#[from] UrlSafetyError),
    #[error("分析时长必须在 1 到 86400 秒之间")]
    InvalidDuration,
    #[error("连接超时必须在 1 到 300 秒之间")]
    InvalidConnectTimeout,
    #[error(transparent)]
    Report(#[from] ReportError),
    #[error("无法读取输入文件: {0}")]
    InputIo(#[from] std::io::Error),
    #[error("输入文件不能为空")]
    EmptyInput,
    #[error("输入文件超过 512 MiB 限制")]
    InputTooLarge,
    #[error("无法序列化对比报告: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn compare_rtsp(options: AnalyzeOptions) -> Result<ComparisonRun, AnalyzerError> {
    validate_options(&options)?;
    let mut tcp_options = options.clone();
    tcp_options.transport = Transport::Tcp;
    let tcp = analyze_rtsp(tcp_options)?;
    let mut udp_options = options.clone();
    udp_options.transport = Transport::Udp;
    let udp = analyze_rtsp(udp_options)?;
    let tcp_rtp = tcp.result.protocol.as_ref().map(|value| &value.rtp);
    let udp_rtp = udp.result.protocol.as_ref().map(|value| &value.rtp);
    let mut conclusions = Vec::new();
    if udp_rtp.is_some_and(|value| value.lost_packets > 0)
        && tcp_rtp.is_some_and(|value| value.lost_packets == 0 && value.packet_count > 0)
    {
        conclusions.push("UDP 检测到丢包而 TCP 未检测到，问题更可能位于 UDP 网络路径。".into());
    }
    if tcp
        .result
        .decode
        .as_ref()
        .is_some_and(|value| value.success)
        && !udp
            .result
            .decode
            .as_ref()
            .is_some_and(|value| value.success)
    {
        conclusions.push(
            "TCP 实际解码成功而 UDP 未成功，建议优先检查 UDP 防火墙、NAT、MTU 和丢包。".into(),
        );
    }
    if conclusions.is_empty() {
        conclusions
            .push("本次采样没有形成 TCP 明显优于 UDP 的确定证据，请结合两份详细报告判断。".into());
    }
    let report_directory = new_report_directory(&options.output_root);
    std::fs::create_dir_all(&report_directory)?;
    let json = report_directory.join("comparison.json");
    let html = report_directory.join("comparison.html");
    let comparison_document = serde_json::json!({
        "schema_version": "streamscope.compare.v1",
        "tcp": &tcp.result,
        "udp": &udp.result,
        "conclusions": &conclusions,
    });
    std::fs::write(&json, serde_json::to_vec_pretty(&comparison_document)?)
        .map_err(AnalyzerError::InputIo)?;
    std::fs::write(&html, render_comparison_html(&tcp, &udp, &conclusions))
        .map_err(AnalyzerError::InputIo)?;
    Ok(ComparisonRun {
        tcp,
        udp,
        conclusions,
        report_directory: report_directory.display().to_string(),
        json: json.display().to_string(),
        html: html.display().to_string(),
    })
}

fn render_comparison_html(tcp: &AnalysisRun, udp: &AnalysisRun, conclusions: &[String]) -> String {
    let row = |name: &str, run: &AnalysisRun| {
        let rtp = run.result.protocol.as_ref().map(|value| &value.rtp);
        format!(
            "<tr><th>{}</th><td>{:?}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            name,
            run.result.status,
            rtp.map_or(0, |value| value.packet_count),
            rtp.map_or(0, |value| value.lost_packets),
            rtp.map_or(0, |value| value.out_of_order_packets),
            if run
                .result
                .decode
                .as_ref()
                .is_some_and(|value| value.success)
            {
                "成功"
            } else {
                "失败/未执行"
            },
        )
    };
    let conclusions = conclusions
        .iter()
        .map(|item| format!("<li>{}</li>", escape_html(item)))
        .collect::<Vec<_>>()
        .join("");
    format!(
        r#"<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>StreamScope TCP/UDP 对比</title><style>body{{max-width:900px;margin:40px auto;padding:0 24px;font-family:system-ui,"Microsoft YaHei",sans-serif;color:#172033}}table{{width:100%;border-collapse:collapse}}th,td{{padding:12px;border-bottom:1px solid #dde3ec;text-align:left}}section{{margin:20px 0;padding:20px;border:1px solid #dde3ec;border-radius:10px}}</style></head><body><h1>StreamScope TCP / UDP 对比报告</h1><section><table><thead><tr><th>模式</th><th>状态</th><th>RTP 包</th><th>丢包</th><th>乱序</th><th>解码</th></tr></thead><tbody>{}{}</tbody></table></section><section><h2>对比结论</h2><ul>{}</ul></section></body></html>"#,
        row("TCP", tcp),
        row("UDP", udp),
        conclusions
    )
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn analyze_h264_file(options: H264FileOptions) -> Result<AnalysisRun, AnalyzerError> {
    let metadata = std::fs::metadata(&options.input)?;
    if metadata.len() == 0 {
        return Err(AnalyzerError::EmptyInput);
    }
    if metadata.len() > 512 * 1024 * 1024 {
        return Err(AnalyzerError::InputTooLarge);
    }
    let bytes = std::fs::read(&options.input)?;
    let analysis_started = Instant::now();
    let h264 = analyze_annex_b(&bytes);
    let h264_analysis_ms = elapsed_ms(analysis_started);
    let ffmpeg = check_tool("ffmpeg");
    let ffprobe = check_tool("ffprobe");
    let tools = vec![ffmpeg.clone(), ffprobe.clone()];
    let timeout = Duration::from_secs(options.process_timeout_seconds.clamp(1, 3_600));
    let mut errors = Vec::new();
    let probe_started = Instant::now();
    let (stream, format_bit_rate) = if ffprobe.available {
        match probe_file(&options.input, timeout) {
            Ok(probe) => (Some(probe.stream), probe.format_bit_rate),
            Err(error) => {
                errors.push(format!("文件信息探测失败：{error}"));
                (None, None)
            }
        }
    } else {
        errors.push("未找到 ffprobe，已跳过文件信息探测".into());
        (None, None)
    };
    let ffprobe_ms = ffprobe.available.then(|| elapsed_ms(probe_started));
    let decode_started = Instant::now();
    let decode = if ffmpeg.available {
        match decode_file(&options.input, timeout) {
            Ok(summary) => Some(summary),
            Err(error) => {
                errors.push(format!("文件解码失败：{error}"));
                None
            }
        }
    } else {
        errors.push("未找到 ffmpeg，已跳过文件解码".into());
        None
    };
    let ffmpeg_decode_ms = ffmpeg.available.then(|| elapsed_ms(decode_started));
    let status = if h264.nalu_count > 0 && decode.as_ref().is_some_and(|value| value.success) {
        AnalysisStatus::Completed
    } else if h264.nalu_count > 0 {
        AnalysisStatus::Partial
    } else {
        AnalysisStatus::Failed
    };
    let canonical = options.input.canonicalize()?;
    let display_name = canonical
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("H.264 文件")
        .to_owned();
    let mut result = AnalysisResult {
        schema_version: RESULT_SCHEMA_VERSION.into(),
        generated_at: Utc::now().to_rfc3339(),
        request: AnalysisRequest {
            source_kind: SourceKind::H264,
            source_url: display_name,
            source_path: Some(canonical.display().to_string()),
            transport: None,
            duration_seconds: 0,
        },
        tools,
        stream,
        format_bit_rate,
        session_sdp: None,
        protocol: None,
        h264: Some(h264),
        h265: None,
        audio: None,
        audio_tracks: Vec::new(),
        av_sync: Vec::new(),
        diagnostics: Vec::new(),
        timeline: Vec::new(),
        module_timings: ModuleTimings {
            h264_analysis_ms: Some(h264_analysis_ms),
            ffprobe_ms,
            ffmpeg_decode_ms,
            ..ModuleTimings::default()
        },
        data_quality: DataQuality::default(),
        decode,
        preview_video: None,
        preview_audio: None,
        status,
        errors,
        capture_summary: None,
        capture_stream: None,
        streams: Vec::new(),
    };
    if let Some(stream) = &mut result.stream {
        reconcile_frame_rates(
            stream,
            result.h264.as_ref(),
            result.h265.as_ref(),
            result.protocol.as_ref(),
        );
    }
    result.diagnostics = evaluate(&result);
    result.timeline = build_timeline(&result);
    finish_reports(options.output_root, result)
}

pub fn analyze_h265_file(options: H265FileOptions) -> Result<AnalysisRun, AnalyzerError> {
    let metadata = std::fs::metadata(&options.input)?;
    if metadata.len() == 0 {
        return Err(AnalyzerError::EmptyInput);
    }
    if metadata.len() > 512 * 1024 * 1024 {
        return Err(AnalyzerError::InputTooLarge);
    }
    let bytes = std::fs::read(&options.input)?;
    let analysis_started = Instant::now();
    let h265 = analyze_h265_annex_b(&bytes);
    let h265_analysis_ms = elapsed_ms(analysis_started);
    let ffmpeg = check_tool("ffmpeg");
    let ffprobe = check_tool("ffprobe");
    let tools = vec![ffmpeg.clone(), ffprobe.clone()];
    let timeout = Duration::from_secs(options.process_timeout_seconds.clamp(1, 3_600));
    let mut errors = Vec::new();
    let probe_started = Instant::now();
    let (probed_stream, format_bit_rate) = if ffprobe.available {
        match probe_file(&options.input, timeout) {
            Ok(probe) => (Some(probe.stream), probe.format_bit_rate),
            Err(error) => {
                errors.push(format!("H.265 文件信息探测失败：{error}"));
                (None, None)
            }
        }
    } else {
        errors.push("未找到 ffprobe，已跳过 H.265 文件信息探测".into());
        (None, None)
    };
    let ffprobe_ms = ffprobe.available.then(|| elapsed_ms(probe_started));
    let mut stream = probed_stream.or_else(|| stream_from_h265(&h265));
    let decode_started = Instant::now();
    let decode = if ffmpeg.available {
        match decode_file(&options.input, timeout) {
            Ok(summary) => Some(summary),
            Err(error) => {
                errors.push(format!("H.265 文件解码失败：{error}"));
                None
            }
        }
    } else {
        errors.push("未找到 ffmpeg，已跳过 H.265 文件解码".into());
        None
    };
    let ffmpeg_decode_ms = ffmpeg.available.then(|| elapsed_ms(decode_started));
    let status = if h265.nalu_count > 0 && decode.as_ref().is_some_and(|value| value.success) {
        AnalysisStatus::Completed
    } else if h265.nalu_count > 0 {
        AnalysisStatus::Partial
    } else {
        AnalysisStatus::Failed
    };
    let canonical = options.input.canonicalize()?;
    let display_name = canonical
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("H.265 文件")
        .to_owned();
    if let Some(stream) = &mut stream {
        reconcile_frame_rates(stream, None, Some(&h265), None);
    }
    let mut result = AnalysisResult {
        schema_version: RESULT_SCHEMA_VERSION.into(),
        generated_at: Utc::now().to_rfc3339(),
        request: AnalysisRequest {
            source_kind: SourceKind::H265,
            source_url: display_name,
            source_path: Some(canonical.display().to_string()),
            transport: None,
            duration_seconds: 0,
        },
        tools,
        stream,
        format_bit_rate,
        session_sdp: None,
        protocol: None,
        h264: None,
        h265: Some(h265),
        audio: None,
        audio_tracks: Vec::new(),
        av_sync: Vec::new(),
        diagnostics: Vec::new(),
        timeline: Vec::new(),
        module_timings: ModuleTimings {
            h265_analysis_ms: Some(h265_analysis_ms),
            ffprobe_ms,
            ffmpeg_decode_ms,
            ..ModuleTimings::default()
        },
        data_quality: DataQuality::default(),
        decode,
        preview_video: None,
        preview_audio: None,
        status,
        errors,
        capture_summary: None,
        capture_stream: None,
        streams: Vec::new(),
    };
    result.diagnostics = evaluate(&result);
    result.timeline = build_timeline(&result);
    finish_reports(options.output_root, result)
}

pub fn analyze_audio_file(options: AudioFileOptions) -> Result<AnalysisRun, AnalyzerError> {
    let metadata = std::fs::metadata(&options.input)?;
    if metadata.len() == 0 {
        return Err(AnalyzerError::EmptyInput);
    }
    if metadata.len() > 512 * 1024 * 1024 {
        return Err(AnalyzerError::InputTooLarge);
    }
    let canonical = options.input.canonicalize()?;
    let display_name = canonical
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("音频文件")
        .to_owned();
    let codec = canonical
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("audio")
        .to_ascii_lowercase();
    let raw_input = raw_rtp_audio_spec(&codec, 8_000);
    let report_directory = new_report_directory(&options.output_root);
    std::fs::create_dir_all(&report_directory)?;
    let ffmpeg = check_tool("ffmpeg");
    let timeout = Duration::from_secs(options.process_timeout_seconds.clamp(1, 3_600));
    let preview_path = report_directory.join("preview-audio.wav");
    let mut errors = Vec::new();
    let mut audio = streamscope_core::AudioAnalysis {
        codec,
        clock_rate: raw_input.map_or(0, |_| 8_000),
        sample_rate: raw_input.map(|spec| spec.decoded_sample_rate),
        channels: raw_input.map(|_| 1),
        issues: vec![streamscope_core::AudioIssue {
            kind: "decode_not_supported".into(),
            detail: "尚未完成音频文件 PCM 解码与质量扫描".into(),
            ..streamscope_core::AudioIssue::default()
        }],
        ..streamscope_core::AudioAnalysis::default()
    };
    let decode_started = Instant::now();
    let preview_audio = if ffmpeg.available {
        analyze_audio_source(
            &mut audio,
            &canonical,
            &preview_path,
            timeout,
            false,
            raw_input,
            "音频文件",
            &mut errors,
        )
    } else {
        errors.push("未找到 ffmpeg，无法解码音频文件".into());
        None
    };
    let ffmpeg_decode_ms = ffmpeg.available.then(|| elapsed_ms(decode_started));
    let mut data_quality = DataQuality {
        assessed: true,
        sufficient_for_diagnosis: audio.conclusion_reliable,
        limitations: vec![
            "文件输入没有 RTP/RTCP 传输与音画时钟证据，仅判断解码后的声音质量".into(),
        ],
        ..DataQuality::default()
    };
    if !audio.conclusion_reliable {
        data_quality
            .reasons
            .push("音频未成功解码，或有效样本不足 1 秒，禁止输出确定性声音质量结论".into());
    }
    let status = if audio.codec_supported_for_decode {
        AnalysisStatus::Completed
    } else {
        AnalysisStatus::Failed
    };
    let mut result = AnalysisResult {
        schema_version: RESULT_SCHEMA_VERSION.into(),
        generated_at: Utc::now().to_rfc3339(),
        request: AnalysisRequest {
            source_kind: SourceKind::Audio,
            source_url: display_name,
            source_path: Some(canonical.display().to_string()),
            transport: None,
            duration_seconds: audio.decoded_duration_ms.unwrap_or(0) / 1_000,
        },
        tools: vec![ffmpeg],
        stream: None,
        format_bit_rate: None,
        session_sdp: None,
        protocol: None,
        h264: None,
        h265: None,
        audio: Some(audio),
        audio_tracks: Vec::new(),
        av_sync: Vec::new(),
        diagnostics: Vec::new(),
        timeline: Vec::new(),
        module_timings: ModuleTimings {
            ffmpeg_decode_ms,
            media_sample_coverage_ms: None,
            ..ModuleTimings::default()
        },
        data_quality,
        decode: None,
        preview_video: None,
        preview_audio,
        status,
        errors,
        capture_summary: None,
        capture_stream: None,
        streams: Vec::new(),
    };
    result.module_timings.media_sample_coverage_ms = result
        .audio
        .as_ref()
        .and_then(|audio| audio.decoded_duration_ms);
    result.diagnostics = evaluate(&result);
    result.timeline = build_timeline(&result);
    finish_reports_in(report_directory, result)
}

#[allow(clippy::too_many_arguments)]
fn analyze_audio_source(
    audio: &mut streamscope_core::AudioAnalysis,
    source: &std::path::Path,
    preview_path: &std::path::Path,
    timeout: Duration,
    truncated: bool,
    raw_input: Option<RawRtpAudioSpec>,
    context: &str,
    errors: &mut Vec<String>,
) -> Option<String> {
    let analysis_path = preview_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("audio-analysis.wav");
    let analysis_result = if let Some(spec) = raw_input {
        create_analysis_audio_with_input(
            source,
            &analysis_path,
            timeout,
            spec.ffmpeg_format,
            spec.code_size,
        )
    } else {
        create_analysis_audio(source, &analysis_path, timeout)
    };
    match analysis_result {
        Ok(()) => {
            if let Err(error) =
                enrich_from_pcm_wav_with_scope(audio, &analysis_path, truncated, "decoded_pcm_full")
            {
                errors.push(format!("{context} PCM 质量扫描失败：{error}"));
            } else {
                apply_loudness_measurement(audio, &analysis_path, timeout, context, errors);
            }
        }
        Err(error) => errors.push(format!("{context}完整 PCM 解码失败：{error}")),
    }
    let _ = std::fs::remove_file(&analysis_path);
    let preview_result = if let Some(spec) = raw_input {
        create_preview_audio_with_input(
            source,
            preview_path,
            timeout,
            spec.ffmpeg_format,
            spec.code_size,
        )
    } else {
        create_preview_audio(source, preview_path, timeout)
    };
    match preview_result {
        Ok(()) => Some(preview_path.display().to_string()),
        Err(error) => {
            errors.push(format!("{context}播放预览生成失败：{error}"));
            None
        }
    }
}

fn apply_loudness_measurement(
    audio: &mut streamscope_core::AudioAnalysis,
    source: &std::path::Path,
    timeout: Duration,
    context: &str,
    errors: &mut Vec<String>,
) {
    match measure_audio_loudness(source, timeout) {
        Ok(measurement) => {
            if let Some(quality) = &mut audio.quality {
                quality.integrated_loudness_lufs_milli = measurement.integrated_loudness_lufs_milli;
                quality.loudness_range_lu_milli = measurement.loudness_range_lu_milli;
                quality.true_peak_dbtp_milli = measurement.true_peak_dbtp_milli;
                quality.loudness_series = measurement.series;
                quality
                    .measurement_method
                    .push_str("；FFmpeg ebur128（100 ms M/S/I 响度轨迹）");
                if quality
                    .analysis_coverage_ms
                    .is_some_and(|value| value < 3_000)
                {
                    quality
                        .limitations
                        .push("样本不足 3 秒，LRA 仅显示测量值，不用于确定性结论".into());
                }
            }
        }
        Err(error) => errors.push(format!("{context}响度测量未完成：{error}")),
    }
}

pub fn analyze_pcap_file(options: PcapFileOptions) -> Result<AnalysisRun, AnalyzerError> {
    analyze_pcap_file_with_progress(options, |_| {})
}

pub fn analyze_pcap_file_with_progress(
    options: PcapFileOptions,
    mut progress: impl FnMut(AnalysisProgress),
) -> Result<AnalysisRun, AnalyzerError> {
    let canonical = options.input.canonicalize()?;
    let display_name = canonical
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("抓包文件")
        .to_owned();
    let report_directory = new_report_directory(&options.output_root);
    std::fs::create_dir_all(&report_directory)?;
    let started = Instant::now();
    emit_progress(&mut progress, 5, "抓包", "正在发现媒体流并执行逐流统计");
    let capture =
        analyze_capture_file_with_progress(&canonical, &report_directory, |percent, detail| {
            emit_progress(&mut progress, 5 + percent.min(100) / 2, "分流", detail);
        })
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    let tools = if options.stream_ids.is_empty() {
        Vec::new()
    } else {
        vec![check_tool("ffmpeg"), check_tool("ffprobe")]
    };
    let count = capture.streams.len();
    let mut streams = Vec::with_capacity(count);
    for (index, mut captured) in capture.streams.into_iter().enumerate() {
        if capture.summary.malformed_frames > 0 {
            captured.warnings.push(format!(
                "原抓包存在 {} 个无法完整解析的网络帧，不能排除本流证据受捕获缺失影响",
                capture.summary.malformed_frames
            ));
        }
        let selected = options
            .stream_ids
            .iter()
            .any(|id| id == "*" || *id == captured.identity.id);
        emit_progress(
            &mut progress,
            55 + ((index * 40) / count.max(1)) as u8,
            "逐流分析",
            &format!(
                "{}/{} · {} · {}",
                index + 1,
                count,
                captured.identity.id,
                if selected {
                    "深入探测与解码（串行）"
                } else {
                    "整理独立统计"
                }
            ),
        );
        streams.push(analyze_captured_stream(
            captured,
            &canonical,
            &display_name,
            &tools,
            Duration::from_secs(options.process_timeout_seconds.clamp(1, 3_600)),
            selected,
        ));
    }
    let status = if streams.is_empty() {
        AnalysisStatus::Failed
    } else if streams
        .iter()
        .all(|stream| stream.status == AnalysisStatus::Completed)
    {
        AnalysisStatus::Completed
    } else {
        AnalysisStatus::Partial
    };
    let mut errors = capture.summary.warnings.clone();
    for id in options.stream_ids.iter().filter(|id| id.as_str() != "*") {
        if !streams.iter().any(|stream| {
            stream
                .capture_stream
                .as_ref()
                .is_some_and(|identity| identity.id == *id)
        }) {
            errors.push(format!(
                "未找到选中的流 {id}，输入文件可能已变化，请重新扫描"
            ));
        }
    }
    if streams.is_empty() {
        errors.push("未发现可分析的 RTP 流，请检查抓包协议、完整性及支持范围".into());
    }
    let mut av_sync = build_av_sync_pairs(&streams);
    enrich_pcap_content_sync(
        &mut av_sync,
        &streams,
        Duration::from_secs(options.process_timeout_seconds.clamp(1, 3_600)),
        &mut errors,
    );
    let result = AnalysisResult {
        schema_version: RESULT_SCHEMA_VERSION.into(),
        generated_at: Utc::now().to_rfc3339(),
        request: AnalysisRequest {
            source_kind: SourceKind::Pcap,
            source_url: display_name,
            source_path: Some(canonical.display().to_string()),
            transport: None,
            duration_seconds: 0,
        },
        tools,
        stream: None,
        format_bit_rate: None,
        session_sdp: None,
        protocol: None,
        h264: None,
        h265: None,
        audio: None,
        audio_tracks: Vec::new(),
        av_sync,
        diagnostics: Vec::new(),
        timeline: Vec::new(),
        module_timings: ModuleTimings {
            capture_read_ms: Some(elapsed_ms(started)),
            ..ModuleTimings::default()
        },
        data_quality: DataQuality::default(),
        decode: None,
        preview_video: None,
        preview_audio: None,
        status,
        errors,
        capture_summary: Some(capture.summary),
        capture_stream: None,
        streams,
    };
    emit_progress(&mut progress, 95, "报告", "正在写入总览和各流独立报告");
    let run = finish_reports_in(report_directory, result)?;
    emit_progress(&mut progress, 100, "完成", "多流抓包报告已生成");
    Ok(run)
}

fn analyze_captured_stream(
    mut captured: CapturedStream,
    input: &std::path::Path,
    display_name: &str,
    tools: &[streamscope_core::ToolAvailability],
    timeout: Duration,
    selected: bool,
) -> AnalysisResult {
    let identity = captured.identity;
    let mut errors = captured.warnings;
    let mut timings = ModuleTimings {
        rtp_capture_ms: captured.protocol.sample_duration_ms,
        media_sample_coverage_ms: captured.protocol.sample_duration_ms,
        h264_analysis_ms: captured.h264.as_ref().map(|_| captured.analysis_ms),
        h265_analysis_ms: captured.h265.as_ref().map(|_| captured.analysis_ms),
        ..ModuleTimings::default()
    };
    let mut stream = captured
        .h264
        .as_ref()
        .and_then(stream_from_h264)
        .or_else(|| captured.h265.as_ref().and_then(stream_from_h265));
    let mut decode = None;
    let mut preview_video = None;
    let mut preview_audio = None;
    let sample = captured.sample_path.as_ref().filter(|path| path.is_file());
    if selected {
        if let Some(sample) =
            sample.filter(|_| matches!(identity.codec.as_deref(), Some("h264" | "h265" | "hevc")))
        {
            if tools
                .iter()
                .any(|tool| tool.name == "ffprobe" && tool.available)
            {
                let started = Instant::now();
                match probe_file(sample, timeout) {
                    Ok(probe) => stream = Some(probe.stream),
                    Err(error) => errors.push(format!("本流样本探测失败：{error}")),
                }
                timings.ffprobe_ms = Some(elapsed_ms(started));
            } else {
                errors.push("未找到 ffprobe，跳过本流样本探测".into());
            }
            if tools
                .iter()
                .any(|tool| tool.name == "ffmpeg" && tool.available)
            {
                let started = Instant::now();
                match decode_file(sample, timeout) {
                    Ok(summary) => decode = Some(summary),
                    Err(error) => errors.push(format!("本流样本解码失败：{error}")),
                }
                if let Some(parent) = sample.parent() {
                    preview_video =
                        generate_preview(sample, &parent.join("preview.mp4"), timeout, &mut errors);
                }
                timings.ffmpeg_decode_ms = Some(elapsed_ms(started));
            } else {
                errors.push("未找到 ffmpeg，跳过本流解码".into());
            }
        } else if identity.media_type == "audio" {
            if let Some(sample) = sample {
                if sample.extension().and_then(|value| value.to_str()) == Some("wav") {
                    preview_audio = Some(sample.display().to_string());
                    if let Some(audio) = &mut captured.audio {
                        apply_loudness_measurement(
                            audio,
                            sample,
                            timeout,
                            "抓包音频流",
                            &mut errors,
                        );
                    }
                } else if tools
                    .iter()
                    .any(|tool| tool.name == "ffmpeg" && tool.available)
                    && let Some(parent) = sample.parent()
                {
                    let destination = parent.join("preview-audio.wav");
                    let raw_input = identity.codec.as_deref().and_then(|codec| {
                        raw_rtp_audio_spec(codec, identity.clock_rate.unwrap_or(8_000))
                    });
                    if let Some(audio) = &mut captured.audio {
                        preview_audio = analyze_audio_source(
                            audio,
                            sample,
                            &destination,
                            timeout,
                            identity.sample_truncated,
                            raw_input,
                            "抓包音频流",
                            &mut errors,
                        );
                    } else {
                        errors.push("本流缺少音频分析对象，无法执行 PCM 质量扫描".into());
                    }
                }
            }
        } else {
            errors
                .push("本流没有可解码的 H.264/H.265 样本；其他编码或未知编码仅做 RTP 统计".into());
        }
    }
    let bit_rate = captured.protocol.rtp.average_bit_rate_bps;
    if let Some(stream) = &mut stream {
        stream.bit_rate = bit_rate;
        reconcile_frame_rates(
            stream,
            captured.h264.as_ref(),
            captured.h265.as_ref(),
            Some(&captured.protocol),
        );
    }
    let mut quality = DataQuality {
        assessed: true,
        captured_rtp_packets: captured.protocol.rtp.packet_count,
        captured_payload_packets: captured.sample_payload_packets,
        captured_payload_bytes: captured.sample_payload_bytes,
        capture_truncated: identity.sample_truncated,
        reassembled_nalus: captured.h264.as_ref().map_or_else(
            || captured.h265.as_ref().map_or(0, |h265| h265.nalu_count),
            |h264| h264.nalu_count,
        ),
        parsed_frames: captured.h264.as_ref().map_or_else(
            || captured.h265.as_ref().map_or(0, |h265| h265.frame_count),
            |h264| h264.frame_count,
        ),
        decoded_frames: decode.as_ref().and_then(|decode| decode.decoded_frames),
        reasons: errors.clone(),
        ..DataQuality::default()
    };
    if captured.h265.is_some() {
        quality
            .limitations
            .push("H.265 RTP 按 RFC 7798 非交织模式解析；DONL/DOND 交织模式尚未支持".into());
    }
    if identity.codec_confidence != "confirmed" {
        let codec_evidence = if captured.audio.is_some() {
            "音频编码由 RTP Payload Type 静态映射或 RTSP/SDP 映射识别"
        } else if captured.h265.is_some() {
            "H.265 编码由 VPS/SPS/PPS 与可解析帧推断"
        } else {
            "H.264 编码由 SPS/PPS 与可解析帧推断"
        };
        quality.limitations.push(format!(
            "{codec_evidence}，未经 RTSP/SDP 会话协商确认；传输统计和解码现象仍有效，但编码归类不是会话级证明"
        ));
    }
    if !selected {
        quality
            .reasons
            .push("本流尚未执行 FFmpeg 深入解码，可在媒体流列表选择后执行".into());
    }
    if !captured.protocol.errors.is_empty() {
        quality.reasons.extend(captured.protocol.errors.clone());
    }
    if let Some(audio) = captured.audio.as_ref() {
        quality.sufficient_for_diagnosis = audio.conclusion_reliable;
        if !audio.conclusion_reliable {
            quality
                .reasons
                .push("音频质量样本不足，仅保留 RTP 与 PCM 指标，不输出确定性结论".into());
        }
    } else {
        assess_data_quality(
            &mut quality,
            Some(&captured.protocol),
            captured.h264.as_ref(),
            captured.h265.as_ref(),
        );
    }
    let status = if decode.as_ref().is_some_and(|summary| summary.success)
        || captured
            .audio
            .as_ref()
            .is_some_and(|audio| audio.codec_supported_for_decode)
    {
        AnalysisStatus::Completed
    } else {
        AnalysisStatus::Partial
    };
    let audio_tracks = captured
        .audio
        .as_ref()
        .map(|audio| AudioTrackResult {
            id: identity.id.clone(),
            track_index: 0,
            codec: identity
                .codec
                .clone()
                .unwrap_or_else(|| audio.codec.clone()),
            payload_type: identity.payload_types.first().copied().unwrap_or_default(),
            clock_rate: identity.clock_rate.unwrap_or(audio.clock_rate),
            channels: identity.channels.or(audio.channels),
            first_payload_offset_ms: Some(identity.first_offset_ms),
            analysis: audio.clone(),
            preview_audio: preview_audio.clone(),
            export_source: if identity.codec.as_deref().is_some_and(|codec| {
                raw_rtp_audio_spec(codec, identity.clock_rate.unwrap_or(8_000)).is_some()
            }) {
                preview_audio.clone()
            } else {
                sample.map(|path| path.display().to_string())
            },
        })
        .into_iter()
        .collect();
    let mut result = AnalysisResult {
        schema_version: RESULT_SCHEMA_VERSION.into(),
        generated_at: Utc::now().to_rfc3339(),
        request: AnalysisRequest {
            source_kind: SourceKind::Pcap,
            source_url: format!("{display_name} · {}", identity.id),
            source_path: Some(input.display().to_string()),
            transport: Some(identity.transport),
            duration_seconds: captured.protocol.sample_duration_ms.unwrap_or(0) / 1_000,
        },
        tools: if selected { tools.to_vec() } else { Vec::new() },
        stream,
        format_bit_rate: bit_rate,
        session_sdp: None,
        protocol: Some(captured.protocol),
        h264: captured.h264,
        h265: captured.h265,
        audio: captured.audio,
        audio_tracks,
        av_sync: Vec::new(),
        diagnostics: Vec::new(),
        timeline: Vec::new(),
        module_timings: timings,
        data_quality: quality,
        decode,
        preview_video,
        preview_audio,
        status,
        errors,
        capture_summary: None,
        capture_stream: Some(identity),
        streams: Vec::new(),
    };
    result.diagnostics = evaluate(&result);
    result.timeline = build_timeline(&result);
    result
}

pub fn analyze_rtsp(options: AnalyzeOptions) -> Result<AnalysisRun, AnalyzerError> {
    analyze_rtsp_with_progress(options, |_| {})
}

pub fn analyze_rtsp_with_progress(
    options: AnalyzeOptions,
    mut progress: impl FnMut(AnalysisProgress),
) -> Result<AnalysisRun, AnalyzerError> {
    validate_options(&options)?;
    let report_directory = new_report_directory(&options.output_root);
    std::fs::create_dir_all(&report_directory)?;
    emit_progress(&mut progress, 5, "准备", "参数校验完成");
    let safe_url = redact_rtsp_url(&options.source_url)?;
    let ffmpeg = check_tool("ffmpeg");
    let ffprobe = check_tool("ffprobe");
    let tools = vec![ffmpeg.clone(), ffprobe.clone()];
    let mut errors = Vec::new();
    let timeout = Duration::from_secs(options.connect_timeout_seconds);
    let process_timeout =
        Duration::from_secs(options.duration_seconds.saturating_add(10).clamp(10, 3_600));
    let mut timings = ModuleTimings::default();
    let mut data_quality = DataQuality {
        assessed: true,
        ..DataQuality::default()
    };

    emit_progress(&mut progress, 10, "协议", "正在执行 RTSP 会话与 RTP 采样");
    let rtsp_started = Instant::now();
    let (
        protocol,
        h264,
        h265,
        audio,
        audio_tracks,
        mut av_sync,
        video_origin_ms,
        preview_audio,
        session_sdp,
        sample,
        sample_extension,
    ) = match analyze_rtsp_capture_with_progress(
        RtspClientOptions {
            source_url: options.source_url.clone(),
            transport: options.transport,
            connect_timeout: timeout,
            receive_duration: Duration::from_secs(options.duration_seconds),
            user_agent: format!("StreamScope/{}", env!("CARGO_PKG_VERSION")),
            enable_live_compressed_audio: ffmpeg.available,
            spool_directory: Some(report_directory.join("rtsp-spool")),
        },
        |snapshot| {
            let percent = 10
                + snapshot
                    .elapsed_ms
                    .saturating_mul(25)
                    .checked_div(snapshot.duration_ms)
                    .unwrap_or(0)
                    .min(25) as u8;
            let live_audio_tracks = snapshot
                .audio_tracks
                .into_iter()
                .map(|track| LiveAudioTrackProgress {
                    track_index: track.track_index,
                    codec: track.codec,
                    payload_type: track.payload_type,
                    channels: track.channels,
                    packet_count: track.packet_count,
                    payload_bytes: track.payload_bytes,
                    elapsed_ms: snapshot.elapsed_ms,
                    peak_level_dbfs_milli: track.peak_level_dbfs_milli,
                    rms_level_dbfs_milli: track.rms_level_dbfs_milli,
                    waveform: track.waveform,
                    live_decode_active: track.live_decode_active,
                })
                .collect();
            progress(AnalysisProgress {
                percent,
                stage: "实时采集".into(),
                detail: format!(
                    "已采集 {:.1} / {:.1} 秒，正在更新音频 RTP 状态",
                    snapshot.elapsed_ms as f64 / 1_000.0,
                    snapshot.duration_ms as f64 / 1_000.0
                ),
                live_audio_tracks,
            });
        },
    ) {
        Ok(mut capture) => {
            timings.rtsp_session_ms = Some(elapsed_ms(rtsp_started));
            timings.rtp_capture_ms = capture.report.sample_duration_ms;
            timings.media_sample_coverage_ms = capture.report.sample_duration_ms;
            data_quality.captured_rtp_packets = capture.report.rtp.packet_count;
            let primary_track = capture
                .tracks
                .iter()
                .find(|track| track.media_type == "video")
                .or_else(|| capture.tracks.first());
            data_quality.captured_payload_packets =
                primary_track.map_or(0, |track| track.captured_payload_packets);
            data_quality.captured_payload_bytes =
                primary_track.map_or(0, |track| track.captured_payload_bytes);
            data_quality.capture_truncated = capture.capture_truncated;
            let av_sync = build_rtsp_sync_pairs(&capture.tracks);
            let audio_tracks: Vec<_> = capture
                .tracks
                .iter()
                .enumerate()
                .filter(|(_, track)| track.media_type == "audio")
                .filter_map(|(index, track)| {
                    analyze_rtsp_audio_track(
                        index,
                        track,
                        &report_directory,
                        ffmpeg.available,
                        process_timeout,
                        &mut errors,
                    )
                })
                .collect();
            let audio = audio_tracks.first().map(|track| track.analysis.clone());
            let preview_audio = audio_tracks
                .first()
                .and_then(|track| track.preview_audio.clone());
            let codec = capture
                .report
                .media
                .iter()
                .find(|media| media.media_type.eq_ignore_ascii_case("video"))
                .and_then(|media| media.codec.as_deref())
                .unwrap_or("H264")
                .to_ascii_lowercase();
            let video_origin_ms = capture
                .tracks
                .iter()
                .find(|track| track.media_type == "video")
                .and_then(|track| track.first_payload_offset_ms);
            let (video_payloads, video_sample_limited) = capture
                .tracks
                .iter()
                .find(|track| track.media_type == "video")
                .map(|track| collect_rtsp_track_payloads(track, 200_000, 256 * 1024 * 1024))
                .transpose()
                .unwrap_or_else(|error| {
                    errors.push(format!("实时视频落盘样本读取失败：{error}"));
                    None
                })
                .unwrap_or_default();
            if video_sample_limited {
                data_quality.capture_truncated = true;
                data_quality.limitations.push(
                    "实时采集已完整流式落盘；本次视频结构与解码分析使用前 20 万包或 256 MiB 的有界窗口"
                        .into(),
                );
            }
            redact_protocol(&mut capture.report, &options.source_url);
            let sdp = redact_text(&capture.session_sdp, &options.source_url);
            if codec == "h265" || codec == "hevc" {
                let h265_started = Instant::now();
                let mut depacketizer = H265Depacketizer::default();
                let mut nalus = Vec::new();
                for packet in video_payloads {
                    nalus.extend(depacketizer.push(H265RtpPayload {
                        sequence: packet.sequence,
                        timestamp: packet.timestamp,
                        marker: packet.marker,
                        payload: packet.payload,
                    }));
                }
                nalus.extend(depacketizer.finish());
                let mut sample = Vec::new();
                for nalu in nalus.iter().filter(|nalu| nalu.complete) {
                    sample.extend_from_slice(&[0, 0, 0, 1]);
                    sample.extend_from_slice(&nalu.data);
                }
                let h265 =
                    (!nalus.is_empty()).then(|| analyze_h265_nalus(nalus, depacketizer.issues));
                timings.h265_analysis_ms = Some(elapsed_ms(h265_started));
                data_quality.reassembled_nalus = h265.as_ref().map_or(0, |value| value.nalu_count);
                data_quality.parsed_frames = h265.as_ref().map_or(0, |value| value.frame_count);
                data_quality.limitations.push(
                    "H.265 RTP 按 RFC 7798 非交织模式解析；DONL/DOND 交织模式尚未支持".into(),
                );
                (
                    Some(capture.report),
                    None,
                    h265,
                    audio,
                    audio_tracks,
                    av_sync,
                    video_origin_ms,
                    preview_audio,
                    Some(sdp),
                    sample,
                    "h265",
                )
            } else {
                let h264_started = Instant::now();
                let mut depacketizer = Depacketizer::default();
                let mut nalus = Vec::new();
                for packet in video_payloads {
                    nalus.extend(depacketizer.push(RtpPayload {
                        sequence: packet.sequence,
                        timestamp: packet.timestamp,
                        marker: packet.marker,
                        payload: packet.payload,
                    }));
                }
                nalus.extend(depacketizer.finish());
                let mut sample = Vec::new();
                for nalu in nalus.iter().filter(|nalu| nalu.complete) {
                    sample.extend_from_slice(&[0, 0, 0, 1]);
                    sample.extend_from_slice(&nalu.data);
                }
                let h264 = (!nalus.is_empty()).then(|| analyze_nalus(nalus, depacketizer.issues));
                timings.h264_analysis_ms = Some(elapsed_ms(h264_started));
                data_quality.reassembled_nalus = h264.as_ref().map_or(0, |value| value.nalu_count);
                data_quality.parsed_frames = h264.as_ref().map_or(0, |value| value.frame_count);
                (
                    Some(capture.report),
                    h264,
                    None,
                    audio,
                    audio_tracks,
                    av_sync,
                    video_origin_ms,
                    preview_audio,
                    Some(sdp),
                    sample,
                    "h264",
                )
            }
        }
        Err(error) => {
            timings.rtsp_session_ms = Some(elapsed_ms(rtsp_started));
            errors.push(format!("RTSP 协议探测失败：{error}"));
            (
                None,
                None,
                None,
                None,
                Vec::new(),
                Vec::new(),
                None,
                None,
                None,
                Vec::new(),
                "h264",
            )
        }
    };
    emit_progress(&mut progress, 35, "协议", "RTSP/RTP 视频采样完成");

    let sample_path = report_directory.join(format!("sample.{sample_extension}"));
    if !sample.is_empty() {
        std::fs::write(&sample_path, &sample)?;
    }

    emit_progress(&mut progress, 40, "探测", "正在探测同次 RTP 采样生成的码流");
    let probe_started = Instant::now();
    let (probed_stream, probed_bit_rate) = if ffprobe.available && sample_path.is_file() {
        match probe_file(&sample_path, process_timeout) {
            Ok(result) => (Some(result.stream), result.format_bit_rate),
            Err(error) => {
                errors.push(format!("同源样本信息探测失败：{error}"));
                (None, None)
            }
        }
    } else if sample_path.is_file() {
        errors.push("未找到 ffprobe，已跳过同源样本信息探测".into());
        (None, None)
    } else {
        (None, None)
    };
    timings.ffprobe_ms =
        (ffprobe.available && sample_path.is_file()).then(|| elapsed_ms(probe_started));
    let format_bit_rate = protocol
        .as_ref()
        .and_then(|value| value.rtp.average_bit_rate_bps)
        .or(probed_bit_rate);
    let mut stream = probed_stream
        .or_else(|| h264.as_ref().and_then(stream_from_h264))
        .or_else(|| h265.as_ref().and_then(stream_from_h265));
    if let Some(stream) = &mut stream
        && stream.bit_rate.is_none()
    {
        stream.bit_rate = format_bit_rate;
    }
    if let Some(stream) = &mut stream {
        reconcile_frame_rates(stream, h264.as_ref(), h265.as_ref(), protocol.as_ref());
    }
    emit_progress(&mut progress, 58, "探测", "媒体声明信息处理完成");

    emit_progress(
        &mut progress,
        62,
        "解码与画面",
        "正在解码同次 RTP 样本、扫描画面异常并生成内嵌预览",
    );
    let decode_started = Instant::now();
    let decode = if ffmpeg.available && sample_path.is_file() {
        match decode_file(&sample_path, process_timeout) {
            Ok(summary) => Some(summary),
            Err(error) => {
                errors.push(format!("同源样本解码失败：{error}"));
                None
            }
        }
    } else if sample_path.is_file() {
        errors.push("未找到 ffmpeg，已跳过同源样本解码".into());
        None
    } else {
        None
    };
    let preview_video = if ffmpeg.available && sample_path.is_file() {
        generate_preview(
            &sample_path,
            &report_directory.join("preview.mp4"),
            process_timeout,
            &mut errors,
        )
    } else {
        None
    };
    if ffmpeg.available && sample_path.is_file() {
        enrich_rtsp_content_sync(
            &mut av_sync,
            &audio_tracks,
            &sample_path,
            video_origin_ms,
            process_timeout,
            &mut errors,
        );
    }
    timings.ffmpeg_decode_ms =
        (ffmpeg.available && sample_path.is_file()).then(|| elapsed_ms(decode_started));
    data_quality.decoded_frames = decode.as_ref().and_then(|value| value.decoded_frames);
    if h264.is_none() && h265.is_none() {
        if !audio_tracks.is_empty() {
            data_quality.sufficient_for_diagnosis = audio_tracks
                .iter()
                .any(|track| track.analysis.conclusion_reliable);
            if !data_quality.sufficient_for_diagnosis {
                data_quality.reasons.push(
                    "所有音频轨道均样本不足或仅完成结构重组，不输出确定性声音质量结论".into(),
                );
            }
        } else {
            assess_data_quality(&mut data_quality, protocol.as_ref(), None, None);
        }
    } else {
        assess_data_quality(
            &mut data_quality,
            protocol.as_ref(),
            h264.as_ref(),
            h265.as_ref(),
        );
    }
    emit_progress(
        &mut progress,
        90,
        "解码与画面",
        "解码、画面扫描与预览处理完成",
    );

    let status = if protocol.is_some()
        && (((h264.is_some() || h265.is_some())
            && decode.as_ref().is_some_and(|value| value.success))
            || audio_tracks
                .iter()
                .any(|track| track.analysis.codec_supported_for_decode))
    {
        AnalysisStatus::Completed
    } else if protocol.is_some()
        || stream.is_some()
        || decode.as_ref().is_some_and(|value| value.success)
    {
        AnalysisStatus::Partial
    } else {
        AnalysisStatus::Failed
    };
    let mut result = AnalysisResult {
        schema_version: RESULT_SCHEMA_VERSION.into(),
        generated_at: Utc::now().to_rfc3339(),
        request: AnalysisRequest {
            source_kind: SourceKind::Rtsp,
            source_url: safe_url,
            source_path: None,
            transport: Some(options.transport),
            duration_seconds: options.duration_seconds,
        },
        tools,
        stream,
        format_bit_rate,
        session_sdp,
        protocol,
        h264,
        h265,
        audio,
        audio_tracks,
        av_sync,
        diagnostics: Vec::new(),
        timeline: Vec::new(),
        module_timings: timings,
        data_quality,
        decode,
        preview_video,
        preview_audio,
        status,
        errors,
        capture_summary: None,
        capture_stream: None,
        streams: Vec::new(),
    };
    result.diagnostics = evaluate(&result);
    result.timeline = build_timeline(&result);
    emit_progress(&mut progress, 95, "诊断", "规则评估与时间线关联完成");

    let run = finish_reports_in(report_directory, result);
    emit_progress(&mut progress, 100, "完成", "报告已生成");
    run
}

fn collect_rtsp_track_payloads(
    track: &CapturedMediaTrack,
    maximum_packets: usize,
    maximum_bytes: usize,
) -> std::io::Result<(Vec<streamscope_rtsp::CapturedRtpPayload>, bool)> {
    let mut payloads = Vec::new();
    let mut bytes = 0_usize;
    let mut limited = false;
    track.for_each_payload(|payload| {
        if payloads.len() >= maximum_packets
            || bytes.saturating_add(payload.payload.len()) > maximum_bytes
        {
            limited = true;
            return Ok(());
        }
        bytes = bytes.saturating_add(payload.payload.len());
        payloads.push(payload);
        Ok(())
    })?;
    Ok((payloads, limited))
}

fn analyze_rtsp_audio_track(
    track_index: usize,
    track: &CapturedMediaTrack,
    report_directory: &std::path::Path,
    ffmpeg_available: bool,
    process_timeout: Duration,
    errors: &mut Vec<String>,
) -> Option<AudioTrackResult> {
    let track_id = format!("rtsp-track-{}", track_index + 1);
    let (captured_packets, analysis_limited) =
        match collect_rtsp_track_payloads(track, 200_000, 128 * 1024 * 1024) {
            Ok(value) => value,
            Err(error) => {
                errors.push(format!("{track_id} 实时音频落盘样本读取失败：{error}"));
                return None;
            }
        };
    let packets: Vec<_> = captured_packets
        .iter()
        .map(|packet| AudioRtpPayload {
            packet_number: Some(packet.packet_number),
            offset_ms: Some(packet.offset_ms),
            sequence: Some(packet.sequence),
            timestamp: packet.timestamp,
            payload: packet.payload.clone(),
        })
        .collect();
    let preview_path =
        report_directory.join(format!("preview-audio-track-{}.wav", track_index + 1));
    let codec = track.codec.to_ascii_lowercase();
    let decodable = matches!(codec.as_str(), "pcma" | "pcmu");
    let mut audio = match analyze_audio(
        &track.codec,
        track.clock_rate,
        track.channels,
        &packets,
        track.capture_truncated || analysis_limited,
        decodable.then_some(preview_path.as_path()),
    ) {
        Ok(audio) => audio,
        Err(error) => {
            errors.push(format!("{track_id} 实时音频样本分析失败：{error}"));
            return None;
        }
    };
    let mut preview_audio =
        (decodable && preview_path.is_file()).then(|| preview_path.display().to_string());
    let mut export_source = preview_audio.clone();
    if decodable && preview_path.is_file() && ffmpeg_available {
        apply_loudness_measurement(
            &mut audio,
            &preview_path,
            process_timeout,
            &format!("{track_id} 实时 G.711 音频"),
            errors,
        );
    }
    if matches!(codec.as_str(), "mpeg4-generic" | "aac") {
        let sample_path =
            report_directory.join(format!("sample-audio-track-{}.aac", track_index + 1));
        match write_aac_adts_mapped(
            &packets,
            &track.fmtp,
            track.clock_rate,
            track.channels,
            &sample_path,
        ) {
            Ok(written) if written.units > 0 => {
                audio.access_unit_count = written.units;
                audio.sample_mappings = written.mappings;
                export_source = Some(sample_path.display().to_string());
                if ffmpeg_available {
                    preview_audio = analyze_audio_source(
                        &mut audio,
                        &sample_path,
                        &preview_path,
                        process_timeout,
                        track.capture_truncated || analysis_limited,
                        None,
                        &format!("{track_id} 实时 AAC 音频"),
                        errors,
                    );
                }
            }
            Ok(_) => errors.push(format!("{track_id} AAC RTP 未能重组出完整 Access Unit")),
            Err(error) => errors.push(format!("{track_id} AAC 样本保存失败：{error}")),
        }
    } else if codec == "opus" {
        let sample_path =
            report_directory.join(format!("sample-audio-track-{}.ogg", track_index + 1));
        match write_opus_ogg_mapped(&packets, track.channels, &sample_path) {
            Ok(written) if written.units > 0 => {
                audio.access_unit_count = written.units;
                audio.sample_mappings = written.mappings;
                export_source = Some(sample_path.display().to_string());
                if ffmpeg_available {
                    preview_audio = analyze_audio_source(
                        &mut audio,
                        &sample_path,
                        &preview_path,
                        process_timeout,
                        track.capture_truncated || analysis_limited,
                        None,
                        &format!("{track_id} 实时 Opus 音频"),
                        errors,
                    );
                }
            }
            Ok(_) => errors.push(format!("{track_id} Opus RTP 没有有效音频负载")),
            Err(error) => errors.push(format!("{track_id} Opus 样本保存失败：{error}")),
        }
    } else if let Some(spec) = raw_rtp_audio_spec(&codec, track.clock_rate) {
        let sample_path = report_directory.join(format!(
            "sample-audio-track-{}.{}",
            track_index + 1,
            spec.extension
        ));
        match write_raw_rtp_audio(&packets, &sample_path) {
            Ok(units) if units > 0 => {
                if ffmpeg_available {
                    preview_audio = analyze_audio_source(
                        &mut audio,
                        &sample_path,
                        &preview_path,
                        process_timeout,
                        track.capture_truncated || analysis_limited,
                        Some(spec),
                        &format!("{track_id} 实时 {} 音频", track.codec),
                        errors,
                    );
                    export_source = preview_audio.clone();
                }
            }
            Ok(_) => errors.push(format!("{track_id} {} RTP 没有有效音频负载", track.codec)),
            Err(error) => errors.push(format!("{track_id} {} 样本保存失败：{error}", track.codec)),
        }
    }
    Some(AudioTrackResult {
        id: track_id,
        track_index,
        codec: track.codec.clone(),
        payload_type: track.payload_type,
        clock_rate: track.clock_rate,
        channels: track.channels,
        first_payload_offset_ms: track.first_payload_offset_ms,
        analysis: audio,
        preview_audio,
        export_source,
    })
}

fn finish_reports(
    output_root: PathBuf,
    mut result: AnalysisResult,
) -> Result<AnalysisRun, AnalyzerError> {
    let report_directory = new_report_directory(&output_root);
    if result.preview_video.is_none()
        && matches!(
            result.request.source_kind,
            SourceKind::H264 | SourceKind::H265
        )
        && result
            .tools
            .iter()
            .any(|tool| tool.name == "ffmpeg" && tool.available)
        && let Some(source) = result.request.source_path.as_deref()
    {
        result.preview_video = generate_preview(
            std::path::Path::new(source),
            &report_directory.join("preview.mp4"),
            Duration::from_secs(90),
            &mut result.errors,
        );
    }
    finish_reports_in(report_directory, result)
}

fn generate_preview(
    source: &std::path::Path,
    destination: &std::path::Path,
    timeout: Duration,
    errors: &mut Vec<String>,
) -> Option<String> {
    if let Some(parent) = destination.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        errors.push(format!("无法创建画面预览目录：{error}"));
        return None;
    }
    match create_preview_video(source, destination, timeout) {
        Ok(()) => Some(destination.display().to_string()),
        Err(error) => {
            errors.push(format!("画面预览生成失败：{error}"));
            None
        }
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

fn build_av_sync_pairs(streams: &[AnalysisResult]) -> Vec<AvSyncAnalysis> {
    let audio: Vec<_> = streams
        .iter()
        .filter(|stream| {
            stream
                .capture_stream
                .as_ref()
                .is_some_and(|id| id.media_type == "audio")
        })
        .collect();
    let video: Vec<_> = streams
        .iter()
        .filter(|stream| {
            stream
                .capture_stream
                .as_ref()
                .is_some_and(|id| id.media_type == "video")
                || stream.h264.is_some()
                || stream.h265.is_some()
        })
        .collect();
    let mut pairs = Vec::new();
    for audio_stream in audio {
        for video_stream in &video {
            if pairs.len() >= 256 {
                return pairs;
            }
            let (Some(audio_id), Some(video_id), Some(audio_protocol), Some(video_protocol)) = (
                audio_stream.capture_stream.as_ref(),
                video_stream.capture_stream.as_ref(),
                audio_stream.protocol.as_ref(),
                video_stream.protocol.as_ref(),
            ) else {
                continue;
            };
            if audio_protocol.session_id.is_some()
                && video_protocol.session_id.is_some()
                && audio_protocol.session_id != video_protocol.session_id
            {
                continue;
            }
            let mut result = AvSyncAnalysis {
                status: "insufficient_evidence".into(),
                basis: "rtcp_sender_report".into(),
                audio_stream_id: Some(audio_id.id.clone()),
                video_stream_id: Some(video_id.id.clone()),
                reasons: Vec::new(),
                ..AvSyncAnalysis::default()
            };
            let common_cname = audio_protocol.rtcp_sources.iter().find_map(|audio_source| {
                video_protocol
                    .rtcp_sources
                    .iter()
                    .any(|video_source| video_source.cname == audio_source.cname)
                    .then(|| audio_source.cname.clone())
            });
            if common_cname.is_none() {
                result.reasons.push(
                    "音频与视频没有共同 RTCP CNAME，无法证明两条 RTP 时钟来自同一同步源".into(),
                );
                pairs.push(result);
                continue;
            }
            let (Some(audio_sr), Some(video_sr)) = (
                audio_protocol.rtcp_sender_reports.first(),
                video_protocol.rtcp_sender_reports.first(),
            ) else {
                result
                    .reasons
                    .push("音频或视频缺少 RTCP Sender Report，无法建立 RTP 到 NTP 的映射".into());
                pairs.push(result);
                continue;
            };
            let (Some(audio_first), Some(video_first), Some(audio_rate), Some(video_rate)) = (
                audio_protocol.rtp.first_timestamp,
                video_protocol.rtp.first_timestamp,
                audio_id.clock_rate,
                video_id.clock_rate,
            ) else {
                result
                    .reasons
                    .push("缺少首个 RTP 时间戳或时钟率，无法计算同步偏移".into());
                pairs.push(result);
                continue;
            };
            let ntp_us = |seconds: u32, fraction: u32| {
                i128::from(seconds) * 1_000_000 + i128::from(fraction) * 1_000_000 / (1_i128 << 32)
            };
            let project_first =
                |first: u32, sr_rtp: u32, rate: u32, seconds: u32, fraction: u32| {
                    let ticks = i128::from(first.wrapping_sub(sr_rtp) as i32);
                    ntp_us(seconds, fraction) + ticks * 1_000_000 / i128::from(rate)
                };
            let audio_origin = project_first(
                audio_first,
                audio_sr.rtp_timestamp,
                audio_rate,
                audio_sr.ntp_seconds,
                audio_sr.ntp_fraction,
            );
            let video_origin = project_first(
                video_first,
                video_sr.rtp_timestamp,
                video_rate,
                video_sr.ntp_seconds,
                video_sr.ntp_fraction,
            );
            let offset_ms = ((audio_origin - video_origin) / 1_000) as i64;
            result.offset_ms = Some(offset_ms);
            result.confidence_percent = 85;
            result.status = if offset_ms.abs() <= 80 {
                "clock_aligned"
            } else if offset_ms > 0 {
                "audio_clock_late"
            } else {
                "audio_clock_early"
            }
            .into();
            result.reasons.push(format!(
                "共同 RTCP CNAME {}；偏移表示 RTP/NTP 时钟对齐，不等同于真实声音内容与画面事件的感知同步",
                common_cname.unwrap()
            ));
            if audio_protocol.rtcp_sender_reports.len() >= 2
                && video_protocol.rtcp_sender_reports.len() >= 2
            {
                let drift = |reports: &[streamscope_core::RtcpSenderReportEvidence], rate: u32| {
                    let first = reports.first()?;
                    let last = reports.last()?;
                    let ntp_delta = ntp_us(last.ntp_seconds, last.ntp_fraction)
                        - ntp_us(first.ntp_seconds, first.ntp_fraction);
                    if ntp_delta <= 0 {
                        return None;
                    }
                    let rtp_delta =
                        i128::from(last.rtp_timestamp.wrapping_sub(first.rtp_timestamp));
                    Some(
                        ((rtp_delta as f64 * 1_000_000.0 / (f64::from(rate) * ntp_delta as f64)
                            - 1.0)
                            * 1_000_000.0)
                            .round() as i64,
                    )
                };
                result.drift_ppm = drift(&audio_protocol.rtcp_sender_reports, audio_rate)
                    .zip(drift(&video_protocol.rtcp_sender_reports, video_rate))
                    .map(|(audio, video)| audio - video);
            }
            pairs.push(result);
        }
    }
    pairs
}

fn enrich_pcap_content_sync(
    syncs: &mut [AvSyncAnalysis],
    streams: &[AnalysisResult],
    timeout: Duration,
    errors: &mut Vec<String>,
) {
    for sync in syncs {
        let video = sync.video_stream_id.as_deref().and_then(|id| {
            streams.iter().find(|stream| {
                stream
                    .capture_stream
                    .as_ref()
                    .is_some_and(|identity| identity.id == id)
            })
        });
        let audio = sync.audio_stream_id.as_deref().and_then(|id| {
            streams.iter().find(|stream| {
                stream
                    .capture_stream
                    .as_ref()
                    .is_some_and(|identity| identity.id == id)
            })
        });
        let (Some(video_path), Some(audio_path)) = (
            video.and_then(|stream| stream.preview_video.as_deref()),
            audio.and_then(|stream| {
                stream
                    .audio_tracks
                    .first()
                    .and_then(|track| track.preview_audio.as_deref())
                    .or(stream.preview_audio.as_deref())
            }),
        ) else {
            continue;
        };
        let video_origin_ms = video
            .and_then(|stream| stream.capture_stream.as_ref())
            .map(|identity| identity.first_offset_ms);
        let audio_origin_ms = audio
            .and_then(|stream| stream.capture_stream.as_ref())
            .map(|identity| identity.first_offset_ms);
        apply_content_measurement(
            sync,
            video_path,
            audio_path,
            video_origin_ms,
            audio_origin_ms,
            timeout,
            errors,
        );
    }
}

fn enrich_rtsp_content_sync(
    syncs: &mut [AvSyncAnalysis],
    audio_tracks: &[AudioTrackResult],
    video_path: &std::path::Path,
    video_origin_ms: Option<u64>,
    timeout: Duration,
    errors: &mut Vec<String>,
) {
    for sync in syncs {
        let audio = sync.audio_stream_id.as_deref().and_then(|id| {
            audio_tracks
                .iter()
                .find(|track| track.id == id)
                .and_then(|track| track.preview_audio.as_deref())
        });
        if let Some(audio) = audio {
            let audio_origin_ms = sync.audio_stream_id.as_deref().and_then(|id| {
                audio_tracks
                    .iter()
                    .find(|track| track.id == id)
                    .and_then(|track| track.first_payload_offset_ms)
            });
            apply_content_measurement(
                sync,
                &video_path.display().to_string(),
                audio,
                video_origin_ms,
                audio_origin_ms,
                timeout,
                errors,
            );
        }
    }
}

fn apply_content_measurement(
    sync: &mut AvSyncAnalysis,
    video_path: &str,
    audio_path: &str,
    video_origin_ms: Option<u64>,
    audio_origin_ms: Option<u64>,
    timeout: Duration,
    errors: &mut Vec<String>,
) {
    match measure_content_av_sync(
        std::path::Path::new(video_path),
        std::path::Path::new(audio_path),
        timeout.min(Duration::from_secs(120)),
    ) {
        Ok(mut measurement) if measurement.offset_ms.is_some() => {
            let origin_delta =
                audio_origin_ms.unwrap_or(0) as i64 - video_origin_ms.unwrap_or(0) as i64;
            for pair in &mut measurement.pairs {
                pair.video_offset_ms = pair
                    .video_offset_ms
                    .saturating_add(video_origin_ms.unwrap_or(0));
                pair.audio_offset_ms = pair
                    .audio_offset_ms
                    .saturating_add(audio_origin_ms.unwrap_or(0));
                pair.offset_ms = pair.audio_offset_ms as i64 - pair.video_offset_ms as i64;
            }
            sync.content_offset_ms = measurement.offset_ms.map(|value| value + origin_delta);
            sync.content_drift_ms = measurement.drift_ms;
            sync.content_measurement_error_ms = Some(measurement.measurement_error_ms);
            sync.content_confidence_percent = Some(measurement.confidence_percent);
            sync.content_events = measurement.pairs;
            sync.basis = if sync.offset_ms.is_some() {
                "rtcp_sender_report+flash_beep_content".into()
            } else {
                "flash_beep_content".into()
            };
            sync.reasons.push(format!(
                "内容检测发现 {} 个闪光、{} 个蜂鸣候选，配对 {} 组；音频相对视频内容偏移 {} ms（测量误差约 ±{} ms）",
                measurement.video_event_count,
                measurement.audio_event_count,
                sync.content_events.len(),
                sync.content_offset_ms.unwrap_or_default(),
                measurement.measurement_error_ms
            ));
        }
        Ok(measurement) => sync.reasons.push(format!(
            "内容同步检测未形成有效配对：闪光候选 {} 个、蜂鸣候选 {} 个；未输出内容级结论",
            measurement.video_event_count, measurement.audio_event_count
        )),
        Err(error) => errors.push(format!("内容级音画同步检测失败：{error}")),
    }
}

fn build_rtsp_sync_pairs(tracks: &[CapturedMediaTrack]) -> Vec<AvSyncAnalysis> {
    let audio: Vec<_> = tracks
        .iter()
        .enumerate()
        .filter(|(_, track)| track.media_type == "audio")
        .collect();
    let video: Vec<_> = tracks
        .iter()
        .enumerate()
        .filter(|(_, track)| track.media_type == "video")
        .collect();
    let ntp_us = |seconds: u32, fraction: u32| {
        i128::from(seconds) * 1_000_000 + i128::from(fraction) * 1_000_000 / (1_i128 << 32)
    };
    let mut pairs = Vec::new();
    for (audio_index, audio_track) in audio {
        for (video_index, video_track) in &video {
            let mut result = AvSyncAnalysis {
                status: "insufficient_evidence".into(),
                basis: "rtcp_sender_report".into(),
                audio_stream_id: Some(format!("rtsp-track-{}", audio_index + 1)),
                video_stream_id: Some(format!("rtsp-track-{}", video_index + 1)),
                ..AvSyncAnalysis::default()
            };
            let common_cname = audio_track.rtcp_sources.iter().find_map(|audio_source| {
                video_track
                    .rtcp_sources
                    .iter()
                    .any(|video_source| video_source.cname == audio_source.cname)
                    .then(|| audio_source.cname.clone())
            });
            if common_cname.is_none() {
                result.reasons.push(
                    "实时音频与视频没有共同 RTCP CNAME，不能把独立 RTP 时间戳直接比较".into(),
                );
                pairs.push(result);
                continue;
            }
            let (Some(audio_sr), Some(video_sr), Some(audio_first), Some(video_first)) = (
                audio_track.rtcp_sender_reports.first(),
                video_track.rtcp_sender_reports.first(),
                audio_track.rtp.first_timestamp,
                video_track.rtp.first_timestamp,
            ) else {
                result
                    .reasons
                    .push("音频或视频缺少 RTCP Sender Report/首包时间戳，无法计算时钟偏移".into());
                pairs.push(result);
                continue;
            };
            let project = |first: u32, sr_rtp: u32, rate: u32, seconds: u32, fraction: u32| {
                ntp_us(seconds, fraction)
                    + i128::from(first.wrapping_sub(sr_rtp) as i32) * 1_000_000 / i128::from(rate)
            };
            let audio_origin = project(
                audio_first,
                audio_sr.rtp_timestamp,
                audio_track.clock_rate,
                audio_sr.ntp_seconds,
                audio_sr.ntp_fraction,
            );
            let video_origin = project(
                video_first,
                video_sr.rtp_timestamp,
                video_track.clock_rate,
                video_sr.ntp_seconds,
                video_sr.ntp_fraction,
            );
            let offset = ((audio_origin - video_origin) / 1_000) as i64;
            result.offset_ms = Some(offset);
            result.confidence_percent = 85;
            result.status = if offset.abs() <= 80 {
                "clock_aligned"
            } else if offset > 0 {
                "audio_clock_late"
            } else {
                "audio_clock_early"
            }
            .into();
            result.reasons.push(format!(
                "共同 RTCP CNAME {}；该值证明发送时钟关系，不直接证明声音内容与画面事件同步",
                common_cname.unwrap()
            ));
            pairs.push(result);
        }
    }
    pairs
}

fn assess_data_quality(
    quality: &mut DataQuality,
    protocol: Option<&streamscope_core::ProtocolAnalysis>,
    h264: Option<&streamscope_core::H264Analysis>,
    h265: Option<&streamscope_core::H265Analysis>,
) {
    let sample_duration_ms = protocol
        .and_then(|value| value.sample_duration_ms)
        .unwrap_or(0);
    if sample_duration_ms < 3_000 {
        quality
            .reasons
            .push("媒体采样不足 3 秒，只能作为现象提示".into());
    }
    if quality.captured_rtp_packets < 10 {
        quality
            .reasons
            .push("有效 RTP 包少于 10 个，无法代表稳定传输状态".into());
    }
    if quality.parsed_frames < 10 {
        quality
            .reasons
            .push("可解析视频帧少于 10 帧，无法可靠判断 GOP 与恢复能力".into());
    }
    if quality.capture_truncated {
        quality
            .reasons
            .push("采集样本或 TCP 重组证据不完整，H.264/FFmpeg 结论仅覆盖保留的有效负载；具体原因见本流警告".into());
    }
    if quality.captured_rtp_packets != quality.captured_payload_packets
        && !quality.capture_truncated
    {
        quality.reasons.push(format!(
            "RTP 计数与目标视频负载计数不一致（{} / {}），需核对 Payload Type 或 TCP Interleaved 通道",
            quality.captured_rtp_packets, quality.captured_payload_packets
        ));
    }
    if h264.is_none() && h265.is_none() {
        quality
            .reasons
            .push("没有重组出可分析的 H.264/H.265 NALU".into());
    }
    if let Some(decoded_frames) = quality.decoded_frames
        && quality.parsed_frames > 0
        && decoded_frames != quality.parsed_frames
    {
        quality.reasons.push(format!(
            "视频结构层按 Slice 边界（解析失败时回退 RTP 时间戳）统计 {} 帧，FFmpeg 按实际解码输出统计 {} 帧；差异可能来自访问单元边界异常、解析回退或解码器丢弃，不能混为同一计数",
            quality.parsed_frames, decoded_frames
        ));
    }
    quality.sufficient_for_diagnosis = quality.reasons.is_empty();
}

fn stream_from_h264(h264: &streamscope_core::H264Analysis) -> Option<VideoStreamInfo> {
    let sps = h264.sps.first()?;
    let sps_frame_rate = sps
        .fps_milli
        .map(|value| format!("{:.3}", value as f64 / 1_000.0));
    Some(VideoStreamInfo {
        codec: Some("h264".into()),
        profile: Some(
            match sps.profile_idc {
                66 => "Baseline",
                77 => "Main",
                88 => "Extended",
                100 => "High",
                _ => "Unknown",
            }
            .into(),
        ),
        width: Some(sps.width),
        height: Some(sps.height),
        frame_rate: sps_frame_rate.clone(),
        sps_frame_rate,
        level: Some(i32::from(sps.level_idc)),
        ..VideoStreamInfo::default()
    })
}

fn stream_from_h265(h265: &streamscope_core::H265Analysis) -> Option<VideoStreamInfo> {
    let sps = h265.sps.first()?;
    Some(VideoStreamInfo {
        codec: Some("hevc".into()),
        profile: Some(format!("Profile {}", sps.profile_idc)),
        width: Some(sps.width),
        height: Some(sps.height),
        level: Some(i32::from(sps.level_idc)),
        ..VideoStreamInfo::default()
    })
}

fn reconcile_frame_rates(
    stream: &mut VideoStreamInfo,
    h264: Option<&streamscope_core::H264Analysis>,
    h265: Option<&streamscope_core::H265Analysis>,
    protocol: Option<&streamscope_core::ProtocolAnalysis>,
) {
    if stream.probed_frame_rate.is_none() && stream.sps_frame_rate.is_none() {
        stream.probed_frame_rate = stream.frame_rate.clone();
    }
    if stream.sps_frame_rate.is_none() {
        stream.sps_frame_rate = h264
            .and_then(|analysis| analysis.sps.first())
            .and_then(|sps| sps.fps_milli)
            .map(|value| format!("{:.3}", value as f64 / 1_000.0));
    }
    stream.observed_frame_rate = protocol
        .and_then(|value| value.sample_duration_ms)
        .filter(|duration| *duration > 0)
        .zip(
            h264.map(|analysis| analysis.frame_count)
                .or_else(|| h265.map(|analysis| analysis.frame_count)),
        )
        .filter(|(_, frames)| *frames > 0)
        .map(|(duration, frames)| format!("{:.3}", frames as f64 * 1_000.0 / duration as f64));

    let rates: Vec<f64> = [
        stream.sps_frame_rate.as_deref(),
        stream.probed_frame_rate.as_deref(),
        stream.observed_frame_rate.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter_map(parse_frame_rate)
    .collect();
    stream.frame_rate_conflict = rates.iter().enumerate().any(|(index, left)| {
        rates[index + 1..]
            .iter()
            .any(|right| (left - right).abs() > 0.5_f64.max(left.max(*right) * 0.05))
    });
    stream.frame_rate = stream
        .observed_frame_rate
        .clone()
        .or_else(|| stream.sps_frame_rate.clone())
        .or_else(|| stream.probed_frame_rate.clone());
}

fn parse_frame_rate(value: &str) -> Option<f64> {
    if let Some((numerator, denominator)) = value.split_once('/') {
        let numerator: f64 = numerator.parse().ok()?;
        let denominator: f64 = denominator.parse().ok()?;
        return (denominator != 0.0).then_some(numerator / denominator);
    }
    value.parse().ok()
}

fn new_report_directory(output_root: &std::path::Path) -> PathBuf {
    output_root.join(format!("report-{}", Utc::now().format("%Y%m%d-%H%M%S-%3f")))
}

fn finish_reports_in(
    report_directory: PathBuf,
    result: AnalysisResult,
) -> Result<AnalysisRun, AnalyzerError> {
    let paths = write_reports(&report_directory, &result)?;
    Ok(AnalysisRun {
        result,
        report_directory: report_directory.display().to_string(),
        reports: GeneratedReports {
            json: paths.json.display().to_string(),
            html: paths.html.display().to_string(),
            ffmpeg_log: paths.ffmpeg_log.display().to_string(),
            session_sdp: paths.session_sdp.map(|path| path.display().to_string()),
        },
    })
}

fn emit_progress(
    callback: &mut impl FnMut(AnalysisProgress),
    percent: u8,
    stage: &str,
    detail: &str,
) {
    callback(AnalysisProgress {
        percent,
        stage: stage.into(),
        detail: detail.into(),
        live_audio_tracks: Vec::new(),
    });
}

fn redact_protocol(protocol: &mut streamscope_core::ProtocolAnalysis, source_url: &str) {
    if let Some(content_base) = &mut protocol.content_base {
        *content_base = redact_text(content_base, source_url);
    }
    for transaction in &mut protocol.transactions {
        transaction.uri = redact_text(&transaction.uri, source_url);
    }
    for media in &mut protocol.media {
        if let Some(control) = &mut media.control {
            *control = redact_text(control, source_url);
        }
        if let Some(resolved) = &mut media.resolved_control {
            *resolved = redact_text(resolved, source_url);
        }
    }
    for error in &mut protocol.errors {
        *error = redact_text(error, source_url);
    }
}

fn validate_options(options: &AnalyzeOptions) -> Result<(), AnalyzerError> {
    validate_rtsp_url(&options.source_url)?;
    if !(1..=86_400).contains(&options.duration_seconds) {
        return Err(AnalyzerError::InvalidDuration);
    }
    if !(1..=300).contains(&options.connect_timeout_seconds) {
        return Err(AnalyzerError::InvalidConnectTimeout);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> AnalyzeOptions {
        AnalyzeOptions {
            source_url: "rtsp://example.test/live".into(),
            transport: Transport::Tcp,
            duration_seconds: 10,
            connect_timeout_seconds: 10,
            output_root: PathBuf::from("reports"),
        }
    }

    #[test]
    fn rejects_zero_duration_before_starting_external_tools() {
        let mut value = options();
        value.duration_seconds = 0;
        assert!(matches!(
            validate_options(&value),
            Err(AnalyzerError::InvalidDuration)
        ));
    }

    #[test]
    fn rejects_excessive_connection_timeout() {
        let mut value = options();
        value.connect_timeout_seconds = 301;
        assert!(matches!(
            validate_options(&value),
            Err(AnalyzerError::InvalidConnectTimeout)
        ));
    }

    #[test]
    fn rtsp_audio_tracks_keep_independent_identity_and_preview_files() {
        let directory = std::env::temp_dir().join(format!(
            "streamscope-rtsp-audio-tracks-{}-{}",
            std::process::id(),
            Utc::now().timestamp_millis()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let make_track = |payload_type| CapturedMediaTrack {
            media_type: "audio".into(),
            codec: "PCMA".into(),
            clock_rate: 8_000,
            channels: Some(1),
            payload_type,
            fmtp: Default::default(),
            rtp_channel: None,
            rtcp_channel: None,
            rtp: Default::default(),
            rtcp_packet_count: 0,
            rtcp_sender_reports: Vec::new(),
            rtcp_sources: Vec::new(),
            payloads: vec![streamscope_rtsp::CapturedRtpPayload {
                packet_number: 1,
                offset_ms: 0,
                sequence: 1,
                timestamp: 0,
                marker: true,
                payload: vec![0xd5; 160],
            }],
            payload_spool_path: None,
            captured_payload_packets: 1,
            first_payload_offset_ms: Some(0),
            capture_truncated: false,
            captured_payload_bytes: 160,
        };
        let mut errors = Vec::new();
        let first = analyze_rtsp_audio_track(
            1,
            &make_track(8),
            &directory,
            false,
            Duration::from_secs(10),
            &mut errors,
        )
        .unwrap();
        let second = analyze_rtsp_audio_track(
            2,
            &make_track(0),
            &directory,
            false,
            Duration::from_secs(10),
            &mut errors,
        )
        .unwrap();
        assert_eq!(first.id, "rtsp-track-2");
        assert_eq!(second.id, "rtsp-track-3");
        assert_ne!(first.preview_audio, second.preview_audio);
        assert!(
            first
                .preview_audio
                .as_deref()
                .is_some_and(|path| std::path::Path::new(path).is_file())
        );
        assert!(
            second
                .preview_audio
                .as_deref()
                .is_some_and(|path| std::path::Path::new(path).is_file())
        );
        assert!(errors.is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn explains_structure_and_decoder_frame_count_difference() {
        let mut quality = DataQuality {
            captured_rtp_packets: 100,
            captured_payload_packets: 100,
            parsed_frames: 90,
            decoded_frames: Some(100),
            ..DataQuality::default()
        };
        let protocol = streamscope_core::ProtocolAnalysis {
            sample_duration_ms: Some(10_000),
            ..streamscope_core::ProtocolAnalysis::default()
        };
        assess_data_quality(
            &mut quality,
            Some(&protocol),
            Some(&streamscope_core::H264Analysis::default()),
            None,
        );
        assert!(!quality.sufficient_for_diagnosis);
        assert!(
            quality
                .reasons
                .iter()
                .any(|reason| reason.contains("结构层") && reason.contains("FFmpeg"))
        );
    }

    #[test]
    fn standalone_g722_uses_raw_demuxer_and_reports_16khz_pcm() {
        if !check_tool("ffmpeg").available {
            return;
        }
        let directory =
            std::env::temp_dir().join(format!("streamscope-g722-file-test-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let input = directory.join("sample.g722");
        std::fs::write(&input, vec![0_u8; 8_000]).unwrap();
        let run = analyze_audio_file(AudioFileOptions {
            input,
            output_root: directory.join("reports"),
            process_timeout_seconds: 30,
        })
        .unwrap();
        let audio = run.result.audio.as_ref().unwrap();
        assert_eq!(audio.sample_rate, Some(16_000));
        assert_eq!(audio.decoded_duration_ms, Some(1_000));
        assert!(audio.codec_supported_for_decode);
        assert!(audio.quality.is_some());
        assert!(run.result.preview_audio.is_some());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn standalone_wav_generates_preview_and_pcm_diagnostics() {
        if !check_tool("ffmpeg").available {
            return;
        }
        let directory = std::env::temp_dir().join(format!(
            "streamscope-audio-file-test-{}-{}",
            std::process::id(),
            Utc::now().timestamp_millis()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let input = directory.join("silence.wav");
        let samples = 8_000_u32;
        let data_bytes = samples * 2;
        let mut wave = b"RIFF".to_vec();
        wave.extend_from_slice(&(36 + data_bytes).to_le_bytes());
        wave.extend_from_slice(b"WAVEfmt ");
        wave.extend_from_slice(&16_u32.to_le_bytes());
        wave.extend_from_slice(&1_u16.to_le_bytes());
        wave.extend_from_slice(&1_u16.to_le_bytes());
        wave.extend_from_slice(&8_000_u32.to_le_bytes());
        wave.extend_from_slice(&16_000_u32.to_le_bytes());
        wave.extend_from_slice(&2_u16.to_le_bytes());
        wave.extend_from_slice(&16_u16.to_le_bytes());
        wave.extend_from_slice(b"data");
        wave.extend_from_slice(&data_bytes.to_le_bytes());
        wave.resize(wave.len() + data_bytes as usize, 0);
        std::fs::write(&input, wave).unwrap();

        let run = analyze_audio_file(AudioFileOptions {
            input,
            output_root: directory.join("reports"),
            process_timeout_seconds: 30,
        })
        .unwrap();
        assert_eq!(run.result.request.source_kind, SourceKind::Audio);
        assert!(
            run.result
                .preview_audio
                .as_deref()
                .is_some_and(|path| { std::path::Path::new(path).is_file() })
        );
        assert!(
            run.result
                .audio
                .as_ref()
                .is_some_and(|audio| audio.conclusion_reliable)
        );
        assert!(
            run.result
                .diagnostics
                .iter()
                .any(|finding| finding.rule_id == "AUD-043")
        );
        let report = std::fs::read_to_string(&run.reports.html).unwrap();
        assert!(report.contains("音频解码"));
        assert!(!report.contains("控制面未完成"));
        assert!(!report.contains("视频帧率证据来源"));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn standalone_audio_quality_uses_full_source_beyond_preview_limit() {
        if !check_tool("ffmpeg").available {
            return;
        }
        let directory = std::env::temp_dir().join(format!(
            "streamscope-long-audio-file-test-{}-{}",
            std::process::id(),
            Utc::now().timestamp_millis()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let input = directory.join("long-silence.wav");
        let sample_rate = 8_000_u32;
        let samples = sample_rate * 61;
        let data_bytes = samples * 2;
        let mut wave = b"RIFF".to_vec();
        wave.extend_from_slice(&(36 + data_bytes).to_le_bytes());
        wave.extend_from_slice(b"WAVEfmt ");
        wave.extend_from_slice(&16_u32.to_le_bytes());
        wave.extend_from_slice(&1_u16.to_le_bytes());
        wave.extend_from_slice(&1_u16.to_le_bytes());
        wave.extend_from_slice(&sample_rate.to_le_bytes());
        wave.extend_from_slice(&(sample_rate * 2).to_le_bytes());
        wave.extend_from_slice(&2_u16.to_le_bytes());
        wave.extend_from_slice(&16_u16.to_le_bytes());
        wave.extend_from_slice(b"data");
        wave.extend_from_slice(&data_bytes.to_le_bytes());
        wave.resize(wave.len() + data_bytes as usize, 0);
        std::fs::write(&input, wave).unwrap();

        let run = analyze_audio_file(AudioFileOptions {
            input: input.clone(),
            output_root: directory.join("reports"),
            process_timeout_seconds: 90,
        })
        .unwrap();
        let audio = run.result.audio.as_ref().unwrap();
        assert_eq!(audio.decoded_duration_ms, Some(61_000));
        let quality = audio.quality.as_ref().unwrap();
        assert_eq!(quality.analysis_coverage_ms, Some(61_000));
        assert_eq!(quality.scope, "decoded_pcm_full");

        let preview = std::path::Path::new(run.result.preview_audio.as_ref().unwrap());
        assert!(
            std::fs::metadata(preview).unwrap().len() < std::fs::metadata(&input).unwrap().len()
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
