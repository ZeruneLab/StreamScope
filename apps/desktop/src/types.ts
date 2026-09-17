export type AnalysisStatus = "completed" | "partial" | "failed";
export type Transport = "tcp" | "udp";
export type DiagnosticSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface ToolAvailability {
  name: string;
  available: boolean;
  version: string | null;
}

export interface StreamInfo {
  codec: string | null;
  profile: string | null;
  pixel_format: string | null;
  width: number | null;
  height: number | null;
  frame_rate: string | null;
  sps_frame_rate: string | null;
  probed_frame_rate: string | null;
  observed_frame_rate: string | null;
  frame_rate_conflict: boolean;
  bit_rate: number | null;
  level: number | null;
}

export interface DecodeIssue {
  kind: string;
  count: number;
  example: string;
  locations: Array<{
    frame_number: number;
    pts_time: string | null;
    precision: string;
  }>;
}

export interface DecodeSummary {
  success: boolean;
  exit_code: number | null;
  decoded_frames: number | null;
  issues: DecodeIssue[];
  log: string;
  visual_scan: {
    attempted: boolean;
    completed: boolean;
    sampled_frames: number;
    sampled_fps: number;
    scan_width: number;
    scan_height: number;
    candidate_frames: number;
    note: string | null;
  };
}

export interface ProtocolAnalysis {
  connected: boolean;
  authenticated: boolean;
  server: string | null;
  public_methods: string[];
  session_id: string | null;
  content_base: string | null;
  transactions: Array<{
    method: string;
    uri: string;
    status_code: number;
    reason: string;
    cseq: number | null;
    elapsed_ms: number;
  }>;
  media: Array<{
    media_type: string;
    port: number;
    protocol: string;
    payload_types: number[];
    codec: string | null;
    clock_rate: number | null;
    channels: number | null;
    fmtp: Record<string, string>;
    control: string | null;
    resolved_control: string | null;
    frame_rate: string | null;
    frame_size: string | null;
  }>;
  rtp: {
    packet_count: number;
    payload_bytes: number;
    lost_packets: number;
    maximum_sequence_gap: number;
    duplicate_packets: number;
    out_of_order_packets: number;
    sequence_wraps: number;
    timestamp_rollbacks: number;
    ssrc_changes: number;
    payload_type_changes: number;
    jitter: number;
    first_sequence: number | null;
    last_sequence: number | null;
    first_timestamp: number | null;
    last_timestamp: number | null;
    ssrc: number | null;
    payload_type: number | null;
    average_bit_rate_bps: number | null;
    peak_bit_rate_bps: number | null;
    bit_rate_window_ms: number | null;
  };
  sample_duration_ms: number | null;
  negotiated_transport: string | null;
  interleaved_rtp_channel: number | null;
  interleaved_rtcp_channel: number | null;
  rtcp_packet_count: number;
  rtcp_sender_reports: Array<{
    ssrc: number;
    ntp_seconds: number;
    ntp_fraction: number;
    rtp_timestamp: number;
    sender_packet_count: number;
    sender_octet_count: number;
    capture_offset_ms: number | null;
  }>;
  rtcp_sources: Array<{ ssrc: number; cname: string }>;
  errors: string[];
}

export interface H264Analysis {
  nalu_count: number;
  complete_nalus: number;
  incomplete_nalus: number;
  nalu_types: Record<string, number>;
  sps: Array<{
    id: number;
    profile_idc: number;
    level_idc: number;
    chroma_format_idc: number;
    bit_depth_luma: number;
    bit_depth_chroma: number;
    max_frame_num: number;
    pic_order_cnt_type: number;
    max_num_ref_frames: number;
    width: number;
    height: number;
    progressive: boolean;
    fps_milli: number | null;
  }>;
  pps: Array<{
    id: number;
    sps_id: number;
    entropy_coding_mode: boolean;
    slice_groups: number;
    weighted_prediction: boolean;
    initial_qp: number;
    deblocking_filter_control: boolean;
  }>;
  frame_count: number;
  idr_frames: number;
  first_idr_frame: number | null;
  first_frame_is_idr: boolean | null;
  average_gop_frames: number | null;
  maximum_gop_frames: number | null;
  sps_before_first_idr: boolean;
  pps_before_first_idr: boolean;
  issues: Array<{
    kind: string;
    detail: string;
    sequence: number | null;
    timestamp: number | null;
  }>;
  frames: Array<{
    frame_number: number;
    rtp_timestamp: number | null;
    first_sequence: number | null;
    last_sequence: number | null;
    first_nalu: number;
    last_nalu: number;
    first_packet: number | null;
    last_packet: number | null;
    first_offset_ms: number | null;
    last_offset_ms: number | null;
    sample_start_offset: number | null;
    sample_end_offset: number | null;
    idr: boolean;
    complete: boolean;
    boundary_confidence: string;
  }>;
  frame_evidence_truncated: boolean;
}

export interface H265Analysis {
  nalu_count: number;
  complete_nalus: number;
  incomplete_nalus: number;
  nalu_types: Record<string, number>;
  vps_count: number;
  sps: Array<{
    id: number;
    vps_id: number;
    max_sub_layers: number;
    profile_idc: number;
    level_idc: number;
    chroma_format_idc: number;
    bit_depth_luma: number;
    bit_depth_chroma: number;
    width: number;
    height: number;
  }>;
  pps: Array<{ id: number; sps_id: number }>;
  frame_count: number;
  irap_frames: number;
  idr_frames: number;
  cra_frames: number;
  first_irap_frame: number | null;
  first_frame_is_irap: boolean | null;
  average_gop_frames: number | null;
  maximum_gop_frames: number | null;
  vps_before_first_irap: boolean;
  sps_before_first_irap: boolean;
  pps_before_first_irap: boolean;
  issues: H264Analysis["issues"];
  frames: H264Analysis["frames"];
  frame_evidence_truncated: boolean;
}

export interface DiagnosticFinding {
  rule_id: string;
  title: string;
  category: string;
  severity: DiagnosticSeverity;
  confidence_percent: number;
  conclusion: string;
  evidence: Array<{ label: string; value: string }>;
  impact: string;
  suggestions: string[];
  verification: string[];
}

export interface TimelineEvent {
  offset_ms: number | null;
  source: string;
  event_type: string;
  severity: DiagnosticSeverity;
  sequence: number | null;
  rtp_timestamp: number | null;
  frame_number: number | null;
  first_packet: number | null;
  last_packet: number | null;
  location_precision: string | null;
  detail: string;
}

export interface AnalysisResult {
  schema_version: string;
  generated_at: string;
  request: {
    source_kind: "rtsp" | "h264" | "h265" | "audio" | "pcap";
    source_url: string;
    source_path: string | null;
    transport: Transport | null;
    duration_seconds: number;
  };
  tools: ToolAvailability[];
  stream: StreamInfo | null;
  format_bit_rate: number | null;
  session_sdp: string | null;
  protocol: ProtocolAnalysis | null;
  h264: H264Analysis | null;
  h265: H265Analysis | null;
  audio?: {
    codec: string;
    clock_rate: number;
    sample_rate: number | null;
    channels: number | null;
    packet_count: number;
    access_unit_count: number;
    decoded_samples: number;
    decoded_duration_ms: number | null;
    peak_level_dbfs_milli: number | null;
    rms_level_dbfs_milli: number | null;
    silent_samples: number;
    clipped_samples: number;
    timestamp_gap_count: number;
    timestamp_overlap_count: number;
    codec_supported_for_decode: boolean;
    conclusion_reliable: boolean;
    issues: Array<{
      kind: string;
      detail: string;
      first_packet: number | null;
      offset_ms: number | null;
    }>;
    sample_mappings: Array<{
      packet_number: number | null;
      packet_offset_ms: number | null;
      rtp_sequence: number | null;
      rtp_timestamp: number;
      access_unit_index: number;
      access_unit_in_packet: number;
      encoded_offset: number;
      encoded_size: number;
      pcm_start_sample: number;
      pcm_end_sample: number;
      sample_rate: number;
      precision: string;
    }>;
    quality?: {
      analysis_coverage_ms: number | null;
      window_ms: number;
      scope: string;
      channels: Array<{
        channel: number;
        peak_level_dbfs_milli: number | null;
        rms_level_dbfs_milli: number | null;
        crest_factor_milli: number | null;
        silent_samples: number;
        clipped_samples: number;
      }>;
      level_series: Array<{
        offset_ms: number;
        peak_level_dbfs_milli: Array<number | null>;
        rms_level_dbfs_milli: Array<number | null>;
      }>;
      loudness_series: Array<{
        offset_ms: number;
        momentary_lufs_milli: number | null;
        short_term_lufs_milli: number | null;
        integrated_lufs_milli: number | null;
      }>;
      intervals: Array<{
        kind: string;
        start_ms: number;
        end_ms: number;
        channel: number | null;
        detail: string;
        precision: string;
        first_packet: number | null;
        last_packet: number | null;
        first_rtp_sequence: number | null;
        last_rtp_sequence: number | null;
      }>;
      average_spectrum: Array<{ frequency_hz: number; level_dbfs_milli: number }>;
      spectrogram_band_centers_hz: number[];
      spectrogram: Array<{
        offset_ms: number;
        band_levels_dbfs_milli: number[];
      }>;
      integrated_loudness_lufs_milli: number | null;
      loudness_range_lu_milli: number | null;
      true_peak_dbtp_milli: number | null;
      dynamic_range_db_milli: number | null;
      spectral_rolloff_hz: number | null;
      zero_crossing_rate_ppm: number | null;
      channel_level_difference_db_milli: number | null;
      stereo_correlation_milli: number | null;
      measurement_method: string;
      limitations: string[];
    } | null;
  } | null;
  audio_tracks?: Array<{
    id: string;
    track_index: number;
    codec: string;
    payload_type: number;
    clock_rate: number;
    channels: number | null;
    first_payload_offset_ms: number | null;
    analysis: NonNullable<AnalysisResult["audio"]>;
    preview_audio: string | null;
    export_source: string | null;
  }>;
  av_sync?: Array<{
    status: string;
    basis: string;
    confidence_percent: number;
    audio_stream_id: string | null;
    video_stream_id: string | null;
    offset_ms: number | null;
    drift_ppm: number | null;
    content_offset_ms: number | null;
    content_drift_ms: number | null;
    content_measurement_error_ms: number | null;
    content_confidence_percent: number | null;
    content_events: Array<{
      video_offset_ms: number;
      audio_offset_ms: number;
      offset_ms: number;
      video_strength_milli: number;
      audio_strength_milli: number;
    }>;
    reasons: string[];
  }>;
  diagnostics: DiagnosticFinding[];
  timeline: TimelineEvent[];
  module_timings: {
    rtsp_session_ms: number | null;
    rtp_capture_ms: number | null;
    h264_analysis_ms: number | null;
    h265_analysis_ms: number | null;
    ffprobe_ms: number | null;
    ffmpeg_decode_ms: number | null;
    capture_read_ms: number | null;
    media_sample_coverage_ms: number | null;
  };
  data_quality: {
    assessed: boolean;
    sufficient_for_diagnosis: boolean;
    reasons: string[];
    limitations: string[];
    captured_rtp_packets: number;
    captured_payload_packets: number;
    captured_payload_bytes: number;
    capture_truncated: boolean;
    reassembled_nalus: number;
    parsed_frames: number;
    decoded_frames: number | null;
  };
  decode: DecodeSummary | null;
  preview_video?: string | null;
  preview_audio?: string | null;
  status: AnalysisStatus;
  errors: string[];
  capture_summary?: CaptureSummary | null;
  capture_stream?: CaptureStreamIdentity | null;
  streams?: AnalysisResult[];
}

export interface CaptureSummary {
  total_frames: number;
  parsed_transport_frames: number;
  ignored_frames: number;
  malformed_frames: number;
  stream_count: number;
  duration_ms: number;
  warnings: string[];
}

export interface CaptureStreamIdentity {
  id: string;
  source: string;
  destination: string;
  transport: Transport;
  ssrc: number;
  channel: number | null;
  interface_id: string;
  connection_id: number | null;
  payload_types: number[];
  codec: string | null;
  media_type: string;
  channels: number | null;
  codec_confidence: string;
  clock_rate: number | null;
  first_packet: number;
  last_packet: number;
  first_offset_ms: number;
  last_offset_ms: number;
  sample_truncated: boolean;
  events: Array<{
    packet_number: number;
    offset_ms: number;
    sequence: number | null;
    rtp_timestamp: number | null;
    kind: string;
    detail: string;
  }>;
}

export interface AnalysisRun {
  result: AnalysisResult;
  report_directory: string;
  reports: {
    json: string;
    html: string;
    ffmpeg_log: string;
    session_sdp: string | null;
  };
}

export interface ComparisonRun {
  tcp: AnalysisRun;
  udp: AnalysisRun;
  conclusions: string[];
  report_directory: string;
  json: string;
  html: string;
}

export interface RecentRun {
  generatedAt: string;
  sourceUrl: string;
  status: AnalysisStatus;
  reportDirectory: string;
  criticalCount: number;
}

export interface AnalysisProgress {
  percent: number;
  stage: string;
  detail: string;
  live_audio_tracks?: Array<{
    track_index: number;
    codec: string;
    payload_type: number;
    channels: number | null;
    packet_count: number;
    payload_bytes: number;
    elapsed_ms: number;
    peak_level_dbfs_milli: number | null;
    rms_level_dbfs_milli: number | null;
    waveform: number[];
    live_decode_active: boolean;
  }>;
}
