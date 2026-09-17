use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use url::Url;

pub const RESULT_SCHEMA_VERSION: &str = "streamscope.multistream.v4";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    #[default]
    Rtsp,
    H264,
    H265,
    Audio,
    Pcap,
}

impl fmt::Display for Transport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => formatter.write_str("tcp"),
            Self::Udp => formatter.write_str("udp"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnalysisRequest {
    #[serde(default)]
    pub source_kind: SourceKind,
    pub source_url: String,
    #[serde(default)]
    pub source_path: Option<String>,
    pub transport: Option<Transport>,
    pub duration_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolAvailability {
    pub name: String,
    pub available: bool,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VideoStreamInfo {
    pub codec: Option<String>,
    pub profile: Option<String>,
    pub pixel_format: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub frame_rate: Option<String>,
    #[serde(default)]
    pub sps_frame_rate: Option<String>,
    #[serde(default)]
    pub probed_frame_rate: Option<String>,
    #[serde(default)]
    pub observed_frame_rate: Option<String>,
    #[serde(default)]
    pub frame_rate_conflict: bool,
    pub bit_rate: Option<u64>,
    pub level: Option<i32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecodeIssueLocation {
    pub frame_number: u64,
    #[serde(default)]
    pub pts_time: Option<String>,
    pub precision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecodeIssue {
    pub kind: String,
    pub count: usize,
    pub example: String,
    #[serde(default)]
    pub locations: Vec<DecodeIssueLocation>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecodeSummary {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub decoded_frames: Option<u64>,
    pub issues: Vec<DecodeIssue>,
    pub log: String,
    #[serde(default)]
    pub visual_scan: VisualScanSummary,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VisualScanSummary {
    pub attempted: bool,
    pub completed: bool,
    pub sampled_frames: u64,
    pub sampled_fps: u32,
    pub scan_width: u32,
    pub scan_height: u32,
    pub candidate_frames: u64,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RtpStatistics {
    pub packet_count: u64,
    pub payload_bytes: u64,
    pub lost_packets: u64,
    #[serde(default)]
    pub maximum_sequence_gap: u16,
    pub duplicate_packets: u64,
    pub out_of_order_packets: u64,
    pub sequence_wraps: u64,
    pub timestamp_rollbacks: u64,
    pub ssrc_changes: u64,
    pub payload_type_changes: u64,
    pub jitter: f64,
    pub first_sequence: Option<u16>,
    pub last_sequence: Option<u16>,
    pub first_timestamp: Option<u32>,
    pub last_timestamp: Option<u32>,
    pub ssrc: Option<u32>,
    pub payload_type: Option<u8>,
    #[serde(default)]
    pub average_bit_rate_bps: Option<u64>,
    #[serde(default)]
    pub peak_bit_rate_bps: Option<u64>,
    #[serde(default)]
    pub bit_rate_window_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RtspTransactionRecord {
    pub method: String,
    pub uri: String,
    pub status_code: u16,
    pub reason: String,
    pub cseq: Option<u32>,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SdpMediaSummary {
    pub media_type: String,
    pub port: u16,
    pub protocol: String,
    pub payload_types: Vec<u8>,
    pub codec: Option<String>,
    pub clock_rate: Option<u32>,
    #[serde(default)]
    pub channels: Option<u16>,
    #[serde(default)]
    pub fmtp: BTreeMap<String, String>,
    pub control: Option<String>,
    pub resolved_control: Option<String>,
    pub frame_rate: Option<String>,
    pub frame_size: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RtcpSenderReportEvidence {
    pub ssrc: u32,
    pub ntp_seconds: u32,
    pub ntp_fraction: u32,
    pub rtp_timestamp: u32,
    pub sender_packet_count: u32,
    pub sender_octet_count: u32,
    #[serde(default)]
    pub capture_offset_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RtcpSourceDescription {
    pub ssrc: u32,
    pub cname: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProtocolAnalysis {
    pub connected: bool,
    pub authenticated: bool,
    pub server: Option<String>,
    pub public_methods: Vec<String>,
    pub session_id: Option<String>,
    pub content_base: Option<String>,
    pub transactions: Vec<RtspTransactionRecord>,
    pub media: Vec<SdpMediaSummary>,
    pub rtp: RtpStatistics,
    #[serde(default)]
    pub sample_duration_ms: Option<u64>,
    #[serde(default)]
    pub negotiated_transport: Option<String>,
    #[serde(default)]
    pub interleaved_rtp_channel: Option<u8>,
    #[serde(default)]
    pub interleaved_rtcp_channel: Option<u8>,
    pub rtcp_packet_count: u64,
    #[serde(default)]
    pub rtcp_sender_reports: Vec<RtcpSenderReportEvidence>,
    #[serde(default)]
    pub rtcp_sources: Vec<RtcpSourceDescription>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AudioIssue {
    pub kind: String,
    pub detail: String,
    #[serde(default)]
    pub first_packet: Option<u64>,
    #[serde(default)]
    pub offset_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AudioSampleMapping {
    pub packet_number: Option<u64>,
    pub packet_offset_ms: Option<u64>,
    pub rtp_sequence: Option<u16>,
    pub rtp_timestamp: u32,
    pub access_unit_index: u64,
    pub access_unit_in_packet: u16,
    pub encoded_offset: u64,
    pub encoded_size: u32,
    pub pcm_start_sample: u64,
    pub pcm_end_sample: u64,
    pub sample_rate: u32,
    pub precision: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AudioChannelQuality {
    pub channel: u16,
    pub peak_level_dbfs_milli: Option<i32>,
    pub rms_level_dbfs_milli: Option<i32>,
    pub crest_factor_milli: Option<u32>,
    pub silent_samples: u64,
    pub clipped_samples: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AudioLevelPoint {
    pub offset_ms: u64,
    pub peak_level_dbfs_milli: Vec<Option<i32>>,
    pub rms_level_dbfs_milli: Vec<Option<i32>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AudioLoudnessPoint {
    pub offset_ms: u64,
    pub momentary_lufs_milli: Option<i32>,
    pub short_term_lufs_milli: Option<i32>,
    pub integrated_lufs_milli: Option<i32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AudioQualityInterval {
    pub kind: String,
    pub start_ms: u64,
    pub end_ms: u64,
    pub channel: Option<u16>,
    pub detail: String,
    pub precision: String,
    #[serde(default)]
    pub first_packet: Option<u64>,
    #[serde(default)]
    pub last_packet: Option<u64>,
    #[serde(default)]
    pub first_rtp_sequence: Option<u16>,
    #[serde(default)]
    pub last_rtp_sequence: Option<u16>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AudioSpectrumPoint {
    pub frequency_hz: u32,
    pub level_dbfs_milli: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AudioSpectrogramPoint {
    pub offset_ms: u64,
    pub band_levels_dbfs_milli: Vec<i32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AudioQualityAnalysis {
    pub analysis_coverage_ms: Option<u64>,
    pub window_ms: u32,
    pub scope: String,
    pub channels: Vec<AudioChannelQuality>,
    pub level_series: Vec<AudioLevelPoint>,
    pub loudness_series: Vec<AudioLoudnessPoint>,
    pub intervals: Vec<AudioQualityInterval>,
    pub average_spectrum: Vec<AudioSpectrumPoint>,
    #[serde(default)]
    pub spectrogram_band_centers_hz: Vec<u32>,
    #[serde(default)]
    pub spectrogram: Vec<AudioSpectrogramPoint>,
    pub integrated_loudness_lufs_milli: Option<i32>,
    pub loudness_range_lu_milli: Option<i32>,
    pub true_peak_dbtp_milli: Option<i32>,
    pub dynamic_range_db_milli: Option<i32>,
    pub spectral_rolloff_hz: Option<u32>,
    pub zero_crossing_rate_ppm: Option<u32>,
    #[serde(default)]
    pub channel_level_difference_db_milli: Option<i32>,
    #[serde(default)]
    pub stereo_correlation_milli: Option<i32>,
    pub measurement_method: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AudioAnalysis {
    pub codec: String,
    pub clock_rate: u32,
    pub sample_rate: Option<u32>,
    pub channels: Option<u16>,
    pub packet_count: u64,
    #[serde(default)]
    pub access_unit_count: u64,
    pub decoded_samples: u64,
    pub decoded_duration_ms: Option<u64>,
    pub peak_level_dbfs_milli: Option<i32>,
    pub rms_level_dbfs_milli: Option<i32>,
    pub silent_samples: u64,
    pub clipped_samples: u64,
    pub timestamp_gap_count: u64,
    pub timestamp_overlap_count: u64,
    pub codec_supported_for_decode: bool,
    pub conclusion_reliable: bool,
    pub issues: Vec<AudioIssue>,
    #[serde(default)]
    pub sample_mappings: Vec<AudioSampleMapping>,
    #[serde(default)]
    pub quality: Option<AudioQualityAnalysis>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AvSyncEventPair {
    pub video_offset_ms: u64,
    pub audio_offset_ms: u64,
    pub offset_ms: i64,
    pub video_strength_milli: u32,
    pub audio_strength_milli: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AvSyncAnalysis {
    pub status: String,
    pub basis: String,
    pub confidence_percent: u8,
    pub audio_stream_id: Option<String>,
    pub video_stream_id: Option<String>,
    pub offset_ms: Option<i64>,
    pub drift_ppm: Option<i64>,
    #[serde(default)]
    pub content_offset_ms: Option<i64>,
    #[serde(default)]
    pub content_drift_ms: Option<i64>,
    #[serde(default)]
    pub content_measurement_error_ms: Option<u32>,
    #[serde(default)]
    pub content_confidence_percent: Option<u8>,
    #[serde(default)]
    pub content_events: Vec<AvSyncEventPair>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleTimings {
    pub rtsp_session_ms: Option<u64>,
    pub rtp_capture_ms: Option<u64>,
    pub h264_analysis_ms: Option<u64>,
    #[serde(default)]
    pub h265_analysis_ms: Option<u64>,
    pub ffprobe_ms: Option<u64>,
    pub ffmpeg_decode_ms: Option<u64>,
    #[serde(default)]
    pub capture_read_ms: Option<u64>,
    #[serde(default)]
    pub media_sample_coverage_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataQuality {
    pub assessed: bool,
    pub sufficient_for_diagnosis: bool,
    pub reasons: Vec<String>,
    #[serde(default)]
    pub limitations: Vec<String>,
    pub captured_rtp_packets: u64,
    pub captured_payload_packets: u64,
    pub captured_payload_bytes: u64,
    pub capture_truncated: bool,
    pub reassembled_nalus: u64,
    pub parsed_frames: u64,
    pub decoded_frames: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct H264SpsInfo {
    pub id: u32,
    pub profile_idc: u8,
    pub level_idc: u8,
    pub chroma_format_idc: u32,
    pub bit_depth_luma: u8,
    pub bit_depth_chroma: u8,
    pub max_frame_num: u32,
    pub pic_order_cnt_type: u32,
    pub max_num_ref_frames: u32,
    pub width: u32,
    pub height: u32,
    pub progressive: bool,
    pub fps_milli: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct H264PpsInfo {
    pub id: u32,
    pub sps_id: u32,
    pub entropy_coding_mode: bool,
    pub slice_groups: u32,
    pub weighted_prediction: bool,
    pub initial_qp: i32,
    pub deblocking_filter_control: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct H264Issue {
    pub kind: String,
    pub detail: String,
    pub sequence: Option<u16>,
    pub timestamp: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct H264Analysis {
    pub nalu_count: u64,
    pub complete_nalus: u64,
    pub incomplete_nalus: u64,
    pub nalu_types: BTreeMap<String, u64>,
    pub sps: Vec<H264SpsInfo>,
    pub pps: Vec<H264PpsInfo>,
    pub frame_count: u64,
    pub idr_frames: u64,
    #[serde(default)]
    pub first_idr_frame: Option<u64>,
    pub first_frame_is_idr: Option<bool>,
    pub average_gop_frames: Option<u64>,
    pub maximum_gop_frames: Option<u64>,
    pub sps_before_first_idr: bool,
    pub pps_before_first_idr: bool,
    pub issues: Vec<H264Issue>,
    #[serde(default)]
    pub frames: Vec<H264FrameEvidence>,
    #[serde(default)]
    pub frame_evidence_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct H265SpsInfo {
    pub id: u32,
    pub vps_id: u8,
    pub max_sub_layers: u8,
    pub profile_idc: u8,
    pub level_idc: u8,
    pub chroma_format_idc: u32,
    pub bit_depth_luma: u8,
    pub bit_depth_chroma: u8,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct H265PpsInfo {
    pub id: u32,
    pub sps_id: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct H265Analysis {
    pub nalu_count: u64,
    pub complete_nalus: u64,
    pub incomplete_nalus: u64,
    pub nalu_types: BTreeMap<String, u64>,
    pub vps_count: u64,
    pub sps: Vec<H265SpsInfo>,
    pub pps: Vec<H265PpsInfo>,
    pub frame_count: u64,
    pub irap_frames: u64,
    pub idr_frames: u64,
    pub cra_frames: u64,
    pub first_irap_frame: Option<u64>,
    pub first_frame_is_irap: Option<bool>,
    pub average_gop_frames: Option<u64>,
    pub maximum_gop_frames: Option<u64>,
    pub vps_before_first_irap: bool,
    pub sps_before_first_irap: bool,
    pub pps_before_first_irap: bool,
    pub issues: Vec<H264Issue>,
    #[serde(default)]
    pub frames: Vec<H264FrameEvidence>,
    #[serde(default)]
    pub frame_evidence_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct H264FrameEvidence {
    pub frame_number: u64,
    pub rtp_timestamp: Option<u32>,
    pub first_sequence: Option<u16>,
    pub last_sequence: Option<u16>,
    pub first_nalu: u64,
    pub last_nalu: u64,
    pub first_packet: Option<u64>,
    pub last_packet: Option<u64>,
    pub first_offset_ms: Option<u64>,
    pub last_offset_ms: Option<u64>,
    pub sample_start_offset: Option<u64>,
    pub sample_end_offset: Option<u64>,
    pub idr: bool,
    pub complete: bool,
    pub boundary_confidence: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnosticEvidence {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnosticFinding {
    pub rule_id: String,
    pub title: String,
    pub category: String,
    pub severity: DiagnosticSeverity,
    pub confidence_percent: u8,
    pub conclusion: String,
    pub evidence: Vec<DiagnosticEvidence>,
    pub impact: String,
    pub suggestions: Vec<String>,
    pub verification: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimelineEvent {
    pub offset_ms: Option<u64>,
    pub source: String,
    pub event_type: String,
    pub severity: DiagnosticSeverity,
    pub sequence: Option<u16>,
    pub rtp_timestamp: Option<u32>,
    #[serde(default)]
    pub frame_number: Option<u64>,
    #[serde(default)]
    pub first_packet: Option<u64>,
    #[serde(default)]
    pub last_packet: Option<u64>,
    #[serde(default)]
    pub location_precision: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AnalysisStatus {
    Completed,
    Partial,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AudioTrackResult {
    pub id: String,
    pub track_index: usize,
    pub codec: String,
    pub payload_type: u8,
    pub clock_rate: u32,
    pub channels: Option<u16>,
    #[serde(default)]
    pub first_payload_offset_ms: Option<u64>,
    pub analysis: AudioAnalysis,
    #[serde(default)]
    pub preview_audio: Option<String>,
    #[serde(default)]
    pub export_source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnalysisResult {
    pub schema_version: String,
    pub generated_at: String,
    pub request: AnalysisRequest,
    pub tools: Vec<ToolAvailability>,
    pub stream: Option<VideoStreamInfo>,
    pub format_bit_rate: Option<u64>,
    pub session_sdp: Option<String>,
    #[serde(default)]
    pub protocol: Option<ProtocolAnalysis>,
    #[serde(default)]
    pub h264: Option<H264Analysis>,
    #[serde(default)]
    pub h265: Option<H265Analysis>,
    #[serde(default)]
    pub audio: Option<AudioAnalysis>,
    #[serde(default)]
    pub audio_tracks: Vec<AudioTrackResult>,
    #[serde(default)]
    pub av_sync: Vec<AvSyncAnalysis>,
    #[serde(default)]
    pub diagnostics: Vec<DiagnosticFinding>,
    #[serde(default)]
    pub timeline: Vec<TimelineEvent>,
    #[serde(default)]
    pub module_timings: ModuleTimings,
    #[serde(default)]
    pub data_quality: DataQuality,
    pub decode: Option<DecodeSummary>,
    #[serde(default)]
    pub preview_video: Option<String>,
    #[serde(default)]
    pub preview_audio: Option<String>,
    pub status: AnalysisStatus,
    pub errors: Vec<String>,
    #[serde(default)]
    pub capture_summary: Option<CaptureSummary>,
    #[serde(default)]
    pub capture_stream: Option<CaptureStreamIdentity>,
    #[serde(default)]
    pub streams: Vec<AnalysisResult>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureSummary {
    pub total_frames: u64,
    pub parsed_transport_frames: u64,
    pub ignored_frames: u64,
    pub malformed_frames: u64,
    pub stream_count: usize,
    pub duration_ms: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureStreamIdentity {
    pub id: String,
    pub source: String,
    pub destination: String,
    pub transport: Transport,
    pub ssrc: u32,
    pub channel: Option<u8>,
    pub interface_id: String,
    pub connection_id: Option<u64>,
    pub payload_types: Vec<u8>,
    pub codec: Option<String>,
    #[serde(default)]
    pub media_type: String,
    #[serde(default)]
    pub channels: Option<u16>,
    pub codec_confidence: String,
    pub clock_rate: Option<u32>,
    pub first_packet: u64,
    pub last_packet: u64,
    pub first_offset_ms: u64,
    pub last_offset_ms: u64,
    pub sample_truncated: bool,
    #[serde(default)]
    pub events: Vec<CapturePacketEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapturePacketEvent {
    pub packet_number: u64,
    pub offset_ms: u64,
    pub sequence: Option<u16>,
    pub rtp_timestamp: Option<u32>,
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, thiserror::Error)]
pub enum UrlSafetyError {
    #[error("RTSP URL 无效")]
    Invalid,
    #[error("仅支持 rtsp:// 或 rtsps:// URL")]
    UnsupportedScheme,
    #[error("RTSP URL 缺少主机名")]
    MissingHost,
}

pub fn validate_rtsp_url(input: &str) -> Result<Url, UrlSafetyError> {
    let url = Url::parse(input).map_err(|_| UrlSafetyError::Invalid)?;
    if !matches!(url.scheme(), "rtsp" | "rtsps") {
        return Err(UrlSafetyError::UnsupportedScheme);
    }
    if url.host_str().is_none() {
        return Err(UrlSafetyError::MissingHost);
    }
    Ok(url)
}

pub fn redact_rtsp_url(input: &str) -> Result<String, UrlSafetyError> {
    let mut url = validate_rtsp_url(input)?;
    if url.password().is_some() {
        url.set_password(Some("REDACTED"))
            .map_err(|_| UrlSafetyError::Invalid)?;
    }
    Ok(url.to_string())
}

pub fn redact_text(text: &str, source_url: &str) -> String {
    let Ok(url) = validate_rtsp_url(source_url) else {
        return text.replace(source_url, "<redacted-url>");
    };
    let redacted_url = redact_rtsp_url(source_url).unwrap_or_else(|_| "<redacted-url>".into());
    let mut safe = text.replace(source_url, &redacted_url);
    if let Some(password) = url.password() {
        safe = safe.replace(password, "REDACTED");
    }
    safe
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_password_but_keeps_useful_address_parts() {
        let safe = redact_rtsp_url("rtsp://admin:p%40ss@192.0.2.10:8554/live?channel=1").unwrap();
        assert!(safe.starts_with("rtsp://admin:REDACTED@192.0.2.10:8554/live"));
        assert!(safe.contains("channel=1"));
        assert!(!safe.contains("p%40ss"));
    }

    #[test]
    fn rejects_non_rtsp_urls() {
        assert!(matches!(
            validate_rtsp_url("https://example.com/live"),
            Err(UrlSafetyError::UnsupportedScheme)
        ));
    }

    #[test]
    fn removes_password_from_child_process_log() {
        let url = "rtsp://alice:secret@example.test/live";
        let safe = redact_text(&format!("failed to open {url}; password=secret"), url);
        assert!(!safe.contains("secret"));
        assert!(safe.contains("REDACTED"));
    }
}
