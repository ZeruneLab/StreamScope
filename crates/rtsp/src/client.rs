use crate::auth::{Challenge, authorization, parse_challenge};
use crate::message::{MessageError, RtspResponse, build_request, parse_response};
use percent_encoding::percent_decode_str;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use streamscope_audio::{aac_adts_frames, opus_ogg_headers, opus_ogg_page, opus_packet_samples};
use streamscope_core::{
    ProtocolAnalysis, RtcpSenderReportEvidence, RtcpSourceDescription, RtpStatistics,
    RtspTransactionRecord, SdpMediaSummary, Transport,
};
use streamscope_rtp::{InterleavedFrame, RtpTracker, parse_rtcp_compound, parse_rtp};
use streamscope_sdp::{SdpSession, parse_sdp, resolve_control_uri};
use url::Url;

#[derive(Debug, Clone)]
pub struct RtspClientOptions {
    pub source_url: String,
    pub transport: Transport,
    pub connect_timeout: Duration,
    pub receive_duration: Duration,
    pub user_agent: String,
    pub enable_live_compressed_audio: bool,
    pub spool_directory: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedRtpPayload {
    pub packet_number: u64,
    pub offset_ms: u64,
    pub sequence: u16,
    pub timestamp: u32,
    pub marker: bool,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub struct RtspCapture {
    pub report: ProtocolAnalysis,
    pub tracks: Vec<CapturedMediaTrack>,
    pub video_payloads: Vec<CapturedRtpPayload>,
    pub session_sdp: String,
    pub capture_truncated: bool,
    pub captured_payload_bytes: u64,
}

#[derive(Debug)]
pub struct CapturedMediaTrack {
    pub media_type: String,
    pub codec: String,
    pub clock_rate: u32,
    pub channels: Option<u16>,
    pub payload_type: u8,
    pub fmtp: BTreeMap<String, String>,
    pub rtp_channel: Option<u8>,
    pub rtcp_channel: Option<u8>,
    pub rtp: RtpStatistics,
    pub rtcp_packet_count: u64,
    pub rtcp_sender_reports: Vec<RtcpSenderReportEvidence>,
    pub rtcp_sources: Vec<RtcpSourceDescription>,
    pub payloads: Vec<CapturedRtpPayload>,
    pub payload_spool_path: Option<PathBuf>,
    pub captured_payload_packets: u64,
    pub first_payload_offset_ms: Option<u64>,
    pub capture_truncated: bool,
    pub captured_payload_bytes: u64,
}

impl CapturedMediaTrack {
    pub fn for_each_payload(
        &self,
        mut visit: impl FnMut(CapturedRtpPayload) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        if let Some(path) = self.payload_spool_path.as_deref() {
            let mut reader = BufReader::new(File::open(path)?);
            while let Some(payload) = read_payload_record(&mut reader)? {
                visit(payload)?;
            }
            return Ok(());
        }
        for payload in &self.payloads {
            visit(payload.clone())?;
        }
        Ok(())
    }
}

fn write_payload_record(
    writer: &mut impl Write,
    payload: &CapturedRtpPayload,
) -> std::io::Result<()> {
    writer.write_all(&payload.packet_number.to_le_bytes())?;
    writer.write_all(&payload.offset_ms.to_le_bytes())?;
    writer.write_all(&payload.sequence.to_le_bytes())?;
    writer.write_all(&payload.timestamp.to_le_bytes())?;
    writer.write_all(&[u8::from(payload.marker)])?;
    writer.write_all(&(payload.payload.len() as u32).to_le_bytes())?;
    writer.write_all(&payload.payload)
}

fn read_payload_record(reader: &mut impl Read) -> std::io::Result<Option<CapturedRtpPayload>> {
    let mut header = [0_u8; 27];
    if reader.read(&mut header[..1])? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[1..])?;
    let length = u32::from_le_bytes(header[23..27].try_into().unwrap()) as usize;
    if length > 65_535 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "RTSP RTP 落盘记录长度无效",
        ));
    }
    let mut bytes = vec![0_u8; length];
    reader.read_exact(&mut bytes)?;
    Ok(Some(CapturedRtpPayload {
        packet_number: u64::from_le_bytes(header[..8].try_into().unwrap()),
        offset_ms: u64::from_le_bytes(header[8..16].try_into().unwrap()),
        sequence: u16::from_le_bytes(header[16..18].try_into().unwrap()),
        timestamp: u32::from_le_bytes(header[18..22].try_into().unwrap()),
        marker: header[22] != 0,
        payload: bytes,
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtspCaptureProgress {
    pub elapsed_ms: u64,
    pub duration_ms: u64,
    pub audio_tracks: Vec<RtspAudioTrackProgress>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtspAudioTrackProgress {
    pub track_index: usize,
    pub codec: String,
    pub payload_type: u8,
    pub channels: Option<u16>,
    pub packet_count: u64,
    pub payload_bytes: u64,
    pub peak_level_dbfs_milli: Option<i32>,
    pub rms_level_dbfs_milli: Option<i32>,
    pub waveform: Vec<i16>,
    pub live_decode_active: bool,
}

#[derive(Debug, Clone)]
struct TrackSpec {
    media_index: usize,
    media_type: String,
    codec: String,
    clock_rate: u32,
    channels: Option<u16>,
    payload_type: u8,
    fmtp: BTreeMap<String, String>,
}

struct TrackRuntime {
    spec: TrackSpec,
    rtp_channel: u8,
    rtcp_channel: u8,
    udp_pair: Option<(UdpSocket, UdpSocket)>,
    tracker: RtpTracker,
    rtcp_packet_count: u64,
    rtcp_sender_reports: Vec<RtcpSenderReportEvidence>,
    rtcp_sources: Vec<RtcpSourceDescription>,
    payload_capture: PayloadCapture,
    live_audio: Option<LiveAudioAccumulator>,
}

struct LiveAudioAccumulator {
    codec: String,
    samples: u64,
    sum_squares: f64,
    peak: i32,
    waveform: VecDeque<i16>,
    sample_stride: u64,
    waveform_bucket_count: u64,
    waveform_bucket_min: i16,
    waveform_bucket_max: i16,
    compressed: Option<LiveCompressedDecoder>,
}

#[derive(Debug)]
struct LivePcmState {
    samples: u64,
    sum_squares: f64,
    peak: i32,
    waveform: VecDeque<i16>,
    waveform_bucket_count: u64,
    waveform_bucket_min: i16,
    waveform_bucket_max: i16,
}

impl Default for LivePcmState {
    fn default() -> Self {
        Self {
            samples: 0,
            sum_squares: 0.0,
            peak: 0,
            waveform: VecDeque::with_capacity(200),
            waveform_bucket_count: 0,
            waveform_bucket_min: i16::MAX,
            waveform_bucket_max: i16::MIN,
        }
    }
}

struct LiveCompressedDecoder {
    child: Child,
    stdin: Option<ChildStdin>,
    state: Arc<Mutex<LivePcmState>>,
    codec: String,
    fmtp: BTreeMap<String, String>,
    clock_rate: u32,
    channels: Option<u16>,
    ogg_serial: u32,
    ogg_sequence: u32,
    first_timestamp: Option<u32>,
}

impl Drop for LiveCompressedDecoder {
    fn drop(&mut self) {
        self.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Debug)]
struct PayloadCapture {
    expected_payload_type: u8,
    items: Vec<CapturedRtpPayload>,
    packet_count: u64,
    first_offset_ms: Option<u64>,
    bytes: usize,
    truncated: bool,
    spool_path: Option<PathBuf>,
    spool: Option<BufWriter<File>>,
}

impl PayloadCapture {
    fn new(expected_payload_type: u8, spool_path: Option<PathBuf>) -> std::io::Result<Self> {
        let spool = spool_path
            .as_ref()
            .map(File::create)
            .transpose()?
            .map(BufWriter::new);
        Ok(Self {
            expected_payload_type,
            items: Vec::new(),
            packet_count: 0,
            first_offset_ms: None,
            bytes: 0,
            truncated: false,
            spool_path,
            spool,
        })
    }
}

impl LiveAudioAccumulator {
    fn new(spec: &TrackSpec, enable_compressed: bool) -> Self {
        let codec = spec.codec.to_ascii_lowercase();
        let compressed = (enable_compressed
            && matches!(codec.as_str(), "mpeg4-generic" | "aac" | "opus"))
        .then(|| LiveCompressedDecoder::start(spec))
        .flatten();
        Self {
            codec,
            samples: 0,
            sum_squares: 0.0,
            peak: 0,
            waveform: VecDeque::with_capacity(200),
            sample_stride: 40,
            waveform_bucket_count: 0,
            waveform_bucket_min: i16::MAX,
            waveform_bucket_max: i16::MIN,
            compressed,
        }
    }

    fn observe(&mut self, packet: &streamscope_rtp::RtpPacket<'_>) {
        if let Some(decoder) = &mut self.compressed {
            decoder.feed(packet.timestamp, packet.payload);
            return;
        }
        if !matches!(self.codec.as_str(), "pcma" | "pcmu") {
            return;
        }
        for byte in packet.payload {
            let sample = if self.codec == "pcma" {
                decode_alaw(*byte)
            } else {
                decode_mulaw(*byte)
            };
            let value = i32::from(sample);
            self.samples = self.samples.saturating_add(1);
            self.sum_squares += f64::from(value) * f64::from(value);
            self.peak = self.peak.max(value.abs());
            observe_waveform_sample(
                &mut self.waveform,
                sample,
                self.sample_stride,
                &mut self.waveform_bucket_count,
                &mut self.waveform_bucket_min,
                &mut self.waveform_bucket_max,
            );
        }
    }

    fn snapshot(&self) -> (Option<i32>, Option<i32>, Vec<i16>, bool) {
        if let Some(decoder) = &self.compressed
            && let Ok(state) = decoder.state.lock()
        {
            let rms =
                (state.samples > 0).then(|| (state.sum_squares / state.samples as f64).sqrt());
            return (
                level_dbfs_milli(f64::from(state.peak)),
                rms.and_then(level_dbfs_milli),
                state.waveform.iter().copied().collect(),
                true,
            );
        }
        let rms = (self.samples > 0).then(|| (self.sum_squares / self.samples as f64).sqrt());
        (
            level_dbfs_milli(f64::from(self.peak)),
            rms.and_then(level_dbfs_milli),
            self.waveform.iter().copied().collect(),
            false,
        )
    }
}

impl LiveCompressedDecoder {
    fn start(spec: &TrackSpec) -> Option<Self> {
        let codec = spec.codec.to_ascii_lowercase();
        let input_format = if codec == "opus" { "ogg" } else { "aac" };
        let mut command = ffmpeg_command();
        command.args([
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "error",
            "-probesize",
            "32",
            "-analyzeduration",
            "0",
            "-f",
            input_format,
            "-i",
            "pipe:0",
            "-map",
            "0:a:0",
            "-vn",
            "-ac",
            "1",
            "-ar",
            "8000",
            "-f",
            "s16le",
            "-flush_packets",
            "1",
            "pipe:1",
        ]);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        hide_console_window(&mut command);
        let mut child = command.spawn().ok()?;
        let mut stdin = child.stdin.take()?;
        let stdout = child.stdout.take()?;
        let state = Arc::new(Mutex::new(LivePcmState::default()));
        let reader_state = Arc::clone(&state);
        std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            let mut bytes = [0_u8; 4096];
            let mut pending = None;
            while let Ok(length) = reader.read(&mut bytes) {
                if length == 0 {
                    break;
                }
                let mut index = 0;
                if let Some(first) = pending.take()
                    && length > 0
                {
                    update_live_pcm(&reader_state, i16::from_le_bytes([first, bytes[0]]));
                    index = 1;
                }
                while index + 1 < length {
                    update_live_pcm(
                        &reader_state,
                        i16::from_le_bytes([bytes[index], bytes[index + 1]]),
                    );
                    index += 2;
                }
                if index < length {
                    pending = Some(bytes[index]);
                }
            }
        });
        let ogg_serial = 0x5353_4c49;
        let mut ogg_sequence = 0;
        if codec == "opus" {
            let (head, tags) = opus_ogg_headers(spec.channels);
            stdin
                .write_all(&opus_ogg_page(ogg_serial, ogg_sequence, 2, 0, &head).ok()?)
                .ok()?;
            ogg_sequence += 1;
            stdin
                .write_all(&opus_ogg_page(ogg_serial, ogg_sequence, 0, 0, &tags).ok()?)
                .ok()?;
            ogg_sequence += 1;
            stdin.flush().ok()?;
        }
        Some(Self {
            child,
            stdin: Some(stdin),
            state,
            codec,
            fmtp: spec.fmtp.clone(),
            clock_rate: spec.clock_rate,
            channels: spec.channels,
            ogg_serial,
            ogg_sequence,
            first_timestamp: None,
        })
    }

    fn feed(&mut self, timestamp: u32, payload: &[u8]) {
        let Some(stdin) = &mut self.stdin else {
            return;
        };
        let result = if self.codec == "opus" {
            let first = *self.first_timestamp.get_or_insert(timestamp);
            let granule = u64::from(timestamp.wrapping_sub(first))
                .saturating_add(opus_packet_samples(payload));
            let page = opus_ogg_page(self.ogg_serial, self.ogg_sequence, 0, granule, payload);
            self.ogg_sequence = self.ogg_sequence.saturating_add(1);
            page.and_then(|page| stdin.write_all(&page))
        } else {
            let frames = aac_adts_frames(payload, &self.fmtp, self.clock_rate, self.channels);
            frames
                .into_iter()
                .try_for_each(|frame| stdin.write_all(&frame))
        };
        if result.is_err() || stdin.flush().is_err() {
            self.stdin.take();
        }
    }
}

fn update_live_pcm(state: &Arc<Mutex<LivePcmState>>, sample: i16) {
    let Ok(mut state) = state.lock() else {
        return;
    };
    let value = i32::from(sample);
    state.samples = state.samples.saturating_add(1);
    state.sum_squares += f64::from(value) * f64::from(value);
    state.peak = state.peak.max(value.abs());
    let LivePcmState {
        waveform,
        waveform_bucket_count,
        waveform_bucket_min,
        waveform_bucket_max,
        ..
    } = &mut *state;
    observe_waveform_sample(
        waveform,
        sample,
        40,
        waveform_bucket_count,
        waveform_bucket_min,
        waveform_bucket_max,
    );
}

fn push_waveform(waveform: &mut VecDeque<i16>, sample: i16) {
    if waveform.len() == 200 {
        waveform.pop_front();
    }
    waveform.push_back(sample);
}

fn observe_waveform_sample(
    waveform: &mut VecDeque<i16>,
    sample: i16,
    stride: u64,
    bucket_count: &mut u64,
    bucket_min: &mut i16,
    bucket_max: &mut i16,
) {
    *bucket_count = bucket_count.saturating_add(1);
    *bucket_min = (*bucket_min).min(sample);
    *bucket_max = (*bucket_max).max(sample);
    if *bucket_count >= stride {
        push_waveform(waveform, *bucket_min);
        push_waveform(waveform, *bucket_max);
        *bucket_count = 0;
        *bucket_min = i16::MAX;
        *bucket_max = i16::MIN;
    }
}

fn ffmpeg_command() -> Command {
    if let Ok(executable) = std::env::current_exe()
        && let Some(directory) = executable.parent()
    {
        let name = if cfg!(windows) {
            "ffmpeg.exe"
        } else {
            "ffmpeg"
        };
        let bundled = directory.join(name);
        if bundled.is_file() {
            return Command::new(bundled);
        }
    }
    Command::new("ffmpeg")
}

#[cfg(windows)]
fn hide_console_window(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    command.creation_flags(0x0800_0000);
}

#[cfg(not(windows))]
fn hide_console_window(_command: &mut Command) {}

#[derive(Debug, thiserror::Error)]
pub enum RtspError {
    #[error("分析任务已由用户取消")]
    Cancelled,
    #[error("RTSP URL 无效")]
    InvalidUrl,
    #[error("阶段 1 暂不支持 RTSPS")]
    TlsUnsupported,
    #[error("无法解析 RTSP 主机地址")]
    AddressResolution,
    #[error("RTSP 连接失败: {0}")]
    Connect(#[source] std::io::Error),
    #[error("RTSP I/O 失败: {0}")]
    Io(#[from] std::io::Error),
    #[error("RTSP 响应解析失败: {0}")]
    Message(#[from] MessageError),
    #[error("RTSP 请求超时")]
    Timeout,
    #[error("RTSP {method} 失败: {status} {reason}")]
    RequestFailed {
        method: String,
        status: u16,
        reason: String,
    },
    #[error("RTSP 鉴权失败: {0}")]
    Authentication(String),
    #[error("DESCRIBE 响应没有有效 SDP: {0}")]
    InvalidSdp(String),
    #[error("SDP 中没有可用的视频轨道")]
    MissingVideoTrack,
    #[error("SETUP 响应缺少 Session")]
    MissingSession,
    #[error("无法绑定连续的 UDP RTP/RTCP 端口")]
    UdpPortPair,
}

pub fn analyze_rtsp(options: RtspClientOptions) -> Result<ProtocolAnalysis, RtspError> {
    analyze_rtsp_capture(options).map(|capture| capture.report)
}

pub fn analyze_rtsp_capture(options: RtspClientOptions) -> Result<RtspCapture, RtspError> {
    analyze_rtsp_capture_with_progress(options, |_| {})
}

pub fn analyze_rtsp_capture_with_progress(
    options: RtspClientOptions,
    mut progress: impl FnMut(RtspCaptureProgress),
) -> Result<RtspCapture, RtspError> {
    if streamscope_core::analysis_cancellation_requested() {
        return Err(RtspError::Cancelled);
    }
    if let Some(directory) = options.spool_directory.as_deref() {
        std::fs::create_dir_all(directory)?;
    }
    let parsed = Url::parse(&options.source_url).map_err(|_| RtspError::InvalidUrl)?;
    if parsed.scheme() == "rtsps" {
        return Err(RtspError::TlsUnsupported);
    }
    if parsed.scheme() != "rtsp" {
        return Err(RtspError::InvalidUrl);
    }
    let host = parsed.host_str().ok_or(RtspError::InvalidUrl)?;
    let port = parsed.port().unwrap_or(554);
    let address = resolve_address(host, port)?;
    let stream = TcpStream::connect_timeout(&address, options.connect_timeout)
        .map_err(RtspError::Connect)?;
    stream.set_read_timeout(Some(options.connect_timeout))?;
    stream.set_write_timeout(Some(options.connect_timeout))?;

    let username = percent_decode_str(parsed.username())
        .decode_utf8_lossy()
        .into_owned();
    let password = parsed
        .password()
        .map(|value| percent_decode_str(value).decode_utf8_lossy().into_owned())
        .unwrap_or_default();
    let credentials = (!username.is_empty()).then_some((username, password));
    let mut request_url = parsed;
    request_url
        .set_username("")
        .map_err(|_| RtspError::InvalidUrl)?;
    request_url
        .set_password(None)
        .map_err(|_| RtspError::InvalidUrl)?;
    let request_uri = request_url.to_string();

    let mut connection = Connection::new(stream, options.user_agent, credentials);
    let options_response = connection.request("OPTIONS", &request_uri, &[], &[])?;
    ensure_success("OPTIONS", &options_response)?;
    let public_methods = options_response
        .headers
        .get("public")
        .map(|value| value.split(',').map(|part| part.trim().into()).collect())
        .unwrap_or_default();

    let describe = connection.request(
        "DESCRIBE",
        &request_uri,
        &[("Accept", "application/sdp".into())],
        &[],
    )?;
    ensure_success("DESCRIBE", &describe)?;
    let sdp_text = std::str::from_utf8(&describe.body)
        .map_err(|error| RtspError::InvalidSdp(error.to_string()))?;
    let sdp = parse_sdp(sdp_text).map_err(|error| RtspError::InvalidSdp(error.to_string()))?;
    let content_base = describe
        .headers
        .get("content-base")
        .or_else(|| describe.headers.get("content-location"))
        .unwrap_or(&request_uri)
        .to_owned();
    let track_specs = find_media_tracks(&sdp)?;
    let mut session_id: Option<String> = None;
    let mut runtimes = Vec::new();
    let mut negotiated = Vec::new();
    let mut errors = Vec::new();
    for (position, spec) in track_specs.into_iter().enumerate() {
        let control = sdp.media[spec.media_index]
            .control
            .as_deref()
            .ok_or(RtspError::MissingVideoTrack)?;
        let track_uri = resolve_control_uri(&content_base, control)
            .map_err(|error| RtspError::InvalidSdp(error.to_string()))?;
        let udp_pair = if options.transport == Transport::Udp {
            Some(bind_udp_pair()?)
        } else {
            None
        };
        let requested_rtp_channel = (position.saturating_mul(2)).min(254) as u8;
        let transport_header = match &udp_pair {
            Some((rtp, rtcp)) => format!(
                "RTP/AVP;unicast;client_port={}-{}",
                rtp.local_addr()?.port(),
                rtcp.local_addr()?.port()
            ),
            None => format!(
                "RTP/AVP/TCP;unicast;interleaved={}-{}",
                requested_rtp_channel,
                requested_rtp_channel.saturating_add(1)
            ),
        };
        let mut setup_headers = vec![("Transport", transport_header)];
        if let Some(session) = &session_id {
            setup_headers.push(("Session", session.clone()));
        }
        let setup = match connection.request("SETUP", &track_uri, &setup_headers, &[]) {
            Ok(response) => response,
            Err(error) => {
                errors.push(format!("轨道 {} SETUP 失败：{error}", spec.media_type));
                continue;
            }
        };
        if let Err(error) = ensure_success("SETUP", &setup) {
            errors.push(format!("轨道 {} SETUP 失败：{error}", spec.media_type));
            continue;
        }
        let negotiated_transport = setup.headers.get("transport").map(str::to_owned);
        if let Some(value) = &negotiated_transport {
            negotiated.push(value.clone());
        }
        let (rtp_channel, rtcp_channel) = if options.transport == Transport::Tcp {
            negotiated_transport
                .as_deref()
                .and_then(parse_interleaved_channels)
                .unwrap_or((
                    requested_rtp_channel,
                    requested_rtp_channel.saturating_add(1),
                ))
        } else {
            (
                requested_rtp_channel,
                requested_rtp_channel.saturating_add(1),
            )
        };
        let response_session = setup
            .headers
            .get("session")
            .and_then(|value| value.split(';').next())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        if session_id.is_none() {
            session_id = response_session;
        }
        if session_id.is_none() {
            errors.push(format!("轨道 {} SETUP 响应缺少 Session", spec.media_type));
            continue;
        }
        let payload_type = spec.payload_type;
        let clock_rate = spec.clock_rate;
        let spool_path = options.spool_directory.as_ref().map(|directory| {
            directory.join(format!(
                "track-{}-pt-{payload_type}.rtp-spool",
                spec.media_index + 1
            ))
        });
        let live_audio = (spec.media_type == "audio")
            .then(|| LiveAudioAccumulator::new(&spec, options.enable_live_compressed_audio));
        runtimes.push(TrackRuntime {
            spec,
            rtp_channel,
            rtcp_channel,
            udp_pair,
            tracker: RtpTracker::new(clock_rate),
            rtcp_packet_count: 0,
            rtcp_sender_reports: Vec::new(),
            rtcp_sources: Vec::new(),
            payload_capture: PayloadCapture::new(payload_type, spool_path)?,
            live_audio,
        });
    }
    if runtimes.is_empty() {
        return Err(RtspError::MissingSession);
    }
    let session_id = session_id.ok_or(RtspError::MissingSession)?;
    let negotiated_transport = (!negotiated.is_empty()).then(|| negotiated.join(" | "));

    let play = connection.request(
        "PLAY",
        &request_uri,
        &[
            ("Session", session_id.clone()),
            ("Range", "npt=0.000-".into()),
        ],
        &[],
    )?;
    ensure_success("PLAY", &play)?;

    let receive_started = Instant::now();
    if options.transport == Transport::Udp {
        receive_udp_tracks(&mut runtimes, options.receive_duration, &mut progress)?;
    } else {
        connection.receive_interleaved_tracks(
            options.receive_duration,
            &mut runtimes,
            &mut progress,
        )?;
    }
    let sample_duration_ms = receive_started
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;

    let teardown = connection.request(
        "TEARDOWN",
        &request_uri,
        &[("Session", session_id.clone())],
        &[],
    );
    if let Err(error) = teardown {
        errors.push(format!("TEARDOWN 失败：{error}"));
    }
    let server = describe
        .headers
        .get("server")
        .or_else(|| options_response.headers.get("server"))
        .map(str::to_owned);
    let media = summarize_media(&sdp, &content_base);
    let mut tracks = Vec::new();
    for mut runtime in runtimes {
        if let Some(spool) = &mut runtime.payload_capture.spool
            && spool.flush().is_err()
        {
            runtime.payload_capture.truncated = true;
        }
        tracks.push(CapturedMediaTrack {
            media_type: runtime.spec.media_type,
            codec: runtime.spec.codec,
            clock_rate: runtime.spec.clock_rate,
            channels: runtime.spec.channels,
            payload_type: runtime.spec.payload_type,
            fmtp: runtime.spec.fmtp,
            rtp_channel: (options.transport == Transport::Tcp).then_some(runtime.rtp_channel),
            rtcp_channel: (options.transport == Transport::Tcp).then_some(runtime.rtcp_channel),
            rtp: runtime
                .tracker
                .into_statistics_with_duration(Duration::from_millis(sample_duration_ms)),
            rtcp_packet_count: runtime.rtcp_packet_count,
            rtcp_sender_reports: runtime.rtcp_sender_reports,
            rtcp_sources: runtime.rtcp_sources,
            payloads: runtime.payload_capture.items,
            payload_spool_path: runtime.payload_capture.spool_path,
            captured_payload_packets: runtime.payload_capture.packet_count,
            first_payload_offset_ms: runtime.payload_capture.first_offset_ms,
            capture_truncated: runtime.payload_capture.truncated,
            captured_payload_bytes: runtime.payload_capture.bytes as u64,
        });
    }
    let primary_index = tracks
        .iter()
        .position(|track| track.media_type == "video")
        .unwrap_or(0);
    let primary = &tracks[primary_index];
    let video_payloads = tracks
        .iter()
        .find(|track| track.media_type == "video")
        .map(|track| track.payloads.clone())
        .unwrap_or_default();
    let capture_truncated = tracks.iter().any(|track| track.capture_truncated);
    let captured_payload_bytes = tracks
        .iter()
        .map(|track| track.captured_payload_bytes)
        .sum();
    let rtcp_packet_count = tracks.iter().map(|track| track.rtcp_packet_count).sum();
    let rtcp_sender_reports = tracks
        .iter()
        .flat_map(|track| track.rtcp_sender_reports.clone())
        .collect();
    let rtcp_sources = tracks
        .iter()
        .flat_map(|track| track.rtcp_sources.clone())
        .collect();
    Ok(RtspCapture {
        report: ProtocolAnalysis {
            connected: true,
            authenticated: connection.authenticated,
            server,
            public_methods,
            session_id: Some(session_id),
            content_base: Some(content_base),
            transactions: connection.transactions,
            media,
            rtp: primary.rtp.clone(),
            sample_duration_ms: Some(sample_duration_ms),
            negotiated_transport,
            interleaved_rtp_channel: primary.rtp_channel,
            interleaved_rtcp_channel: primary.rtcp_channel,
            rtcp_packet_count,
            rtcp_sender_reports,
            rtcp_sources,
            errors,
        },
        tracks,
        video_payloads,
        session_sdp: sdp_text.to_owned(),
        capture_truncated,
        captured_payload_bytes,
    })
}

fn parse_interleaved_channels(transport: &str) -> Option<(u8, u8)> {
    transport.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        if !name.eq_ignore_ascii_case("interleaved") {
            return None;
        }
        let (rtp, rtcp) = value.trim().split_once('-')?;
        Some((rtp.parse().ok()?, rtcp.parse().ok()?))
    })
}

fn resolve_address(host: &str, port: u16) -> Result<SocketAddr, RtspError> {
    (host, port)
        .to_socket_addrs()
        .map_err(|_| RtspError::AddressResolution)?
        .next()
        .ok_or(RtspError::AddressResolution)
}

fn ensure_success(method: &str, response: &RtspResponse) -> Result<(), RtspError> {
    if (200..300).contains(&response.status_code) {
        Ok(())
    } else {
        Err(RtspError::RequestFailed {
            method: method.into(),
            status: response.status_code,
            reason: response.reason.clone(),
        })
    }
}

#[cfg(test)]
fn find_video_track(sdp: &SdpSession) -> Result<(usize, u8, u32), RtspError> {
    find_media_tracks(sdp)?
        .into_iter()
        .find(|track| track.media_type == "video")
        .map(|track| (track.media_index, track.payload_type, track.clock_rate))
        .ok_or(RtspError::MissingVideoTrack)
}

fn static_audio_codec(payload_type: u8) -> Option<(&'static str, u32, Option<u16>)> {
    match payload_type {
        0 => Some(("PCMU", 8_000, Some(1))),
        4 => Some(("G723", 8_000, Some(1))),
        8 => Some(("PCMA", 8_000, Some(1))),
        9 => Some(("G722", 8_000, Some(1))),
        18 => Some(("G729", 8_000, Some(1))),
        _ => None,
    }
}

fn supported_audio_codec(codec: &str) -> bool {
    let codec = codec.to_ascii_lowercase();
    matches!(
        codec.as_str(),
        "pcma"
            | "pcmu"
            | "mpeg4-generic"
            | "aac"
            | "opus"
            | "mp4a-latm"
            | "g722"
            | "g723"
            | "g723.1"
            | "g723_1"
            | "g729"
            | "g729a"
            | "g726"
    ) || codec.starts_with("g726-")
        || codec.starts_with("aal2-g726-")
}

fn find_media_tracks(sdp: &SdpSession) -> Result<Vec<TrackSpec>, RtspError> {
    let mut tracks = Vec::new();
    for (index, media) in sdp.media.iter().enumerate() {
        if !matches!(media.media_type.as_str(), "video" | "audio") {
            continue;
        }
        for payload in &media.payload_types {
            let mapped = media.rtp_maps.get(payload).map(|mapping| {
                (
                    mapping.encoding.clone(),
                    mapping.clock_rate,
                    mapping.channels,
                )
            });
            let fallback = static_audio_codec(*payload)
                .map(|(codec, clock_rate, channels)| (codec.into(), clock_rate, channels));
            let Some((codec, clock_rate, channels)) = mapped.or(fallback) else {
                continue;
            };
            let supported = if media.media_type == "video" {
                matches!(
                    codec.to_ascii_lowercase().as_str(),
                    "h264" | "h265" | "hevc"
                )
            } else {
                supported_audio_codec(&codec)
            };
            if supported {
                tracks.push(TrackSpec {
                    media_index: index,
                    media_type: media.media_type.clone(),
                    codec,
                    clock_rate,
                    channels,
                    payload_type: *payload,
                    fmtp: media.fmtp.get(payload).cloned().unwrap_or_default(),
                });
                break;
            }
        }
    }
    if tracks.is_empty() {
        Err(RtspError::MissingVideoTrack)
    } else {
        Ok(tracks)
    }
}

fn summarize_media(sdp: &SdpSession, base: &str) -> Vec<SdpMediaSummary> {
    sdp.media
        .iter()
        .map(|media| {
            let primary = media
                .payload_types
                .iter()
                .find_map(|payload| media.rtp_maps.get(payload));
            let static_audio = media
                .payload_types
                .first()
                .and_then(|payload| static_audio_codec(*payload));
            SdpMediaSummary {
                media_type: media.media_type.clone(),
                port: media.port,
                protocol: media.protocol.clone(),
                payload_types: media.payload_types.clone(),
                codec: primary
                    .map(|mapping| mapping.encoding.clone())
                    .or_else(|| static_audio.map(|value| value.0.into())),
                clock_rate: primary
                    .map(|mapping| mapping.clock_rate)
                    .or_else(|| static_audio.map(|value| value.1)),
                channels: primary
                    .and_then(|mapping| mapping.channels)
                    .or_else(|| static_audio.and_then(|value| value.2)),
                fmtp: media
                    .payload_types
                    .iter()
                    .find_map(|payload| media.fmtp.get(payload))
                    .cloned()
                    .unwrap_or_default(),
                control: media.control.clone(),
                resolved_control: media
                    .control
                    .as_deref()
                    .and_then(|control| resolve_control_uri(base, control).ok()),
                frame_rate: media.frame_rate.clone(),
                frame_size: media.frame_size.clone(),
            }
        })
        .collect()
}

fn bind_udp_pair() -> Result<(UdpSocket, UdpSocket), RtspError> {
    for _ in 0..20 {
        let rtp = UdpSocket::bind(("0.0.0.0", 0))?;
        let port = rtp.local_addr()?.port();
        if port == u16::MAX {
            continue;
        }
        if let Ok(rtcp) = UdpSocket::bind(("0.0.0.0", port + 1)) {
            return Ok((rtp, rtcp));
        }
    }
    Err(RtspError::UdpPortPair)
}

fn observe_live_audio(
    level: &mut Option<LiveAudioAccumulator>,
    packet: &streamscope_rtp::RtpPacket<'_>,
) {
    let Some(level) = level else {
        return;
    };
    level.observe(packet);
}

fn emit_capture_progress(
    elapsed: Duration,
    duration: Duration,
    tracks: &[TrackRuntime],
    progress: &mut impl FnMut(RtspCaptureProgress),
) {
    let audio_tracks = tracks
        .iter()
        .enumerate()
        .filter(|(_, track)| track.spec.media_type == "audio")
        .map(|(track_index, track)| {
            let (peak, rms, waveform, live_decode_active) = track.live_audio.as_ref().map_or(
                (None, None, Vec::new(), false),
                LiveAudioAccumulator::snapshot,
            );
            RtspAudioTrackProgress {
                track_index,
                codec: track.spec.codec.clone(),
                payload_type: track.spec.payload_type,
                channels: track.spec.channels,
                packet_count: track.tracker.statistics().packet_count,
                payload_bytes: track.tracker.statistics().payload_bytes,
                peak_level_dbfs_milli: peak,
                rms_level_dbfs_milli: rms,
                waveform,
                live_decode_active,
            }
        })
        .collect();
    progress(RtspCaptureProgress {
        elapsed_ms: elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
        duration_ms: duration.as_millis().min(u128::from(u64::MAX)) as u64,
        audio_tracks,
    });
}

fn level_dbfs_milli(value: f64) -> Option<i32> {
    (value > 0.0).then(|| (20_000.0 * (value / 32_768.0).log10()).round() as i32)
}

fn decode_alaw(value: u8) -> i16 {
    let value = value ^ 0x55;
    let mut sample = i32::from(value & 0x0f) << 4;
    let segment = i32::from((value & 0x70) >> 4);
    sample += 8;
    if segment >= 1 {
        sample += 0x100;
    }
    if segment > 1 {
        sample <<= segment - 1;
    }
    if value & 0x80 != 0 {
        sample as i16
    } else {
        (-sample) as i16
    }
}

fn decode_mulaw(value: u8) -> i16 {
    let value = !value;
    let sign = value & 0x80;
    let exponent = (value >> 4) & 0x07;
    let mantissa = value & 0x0f;
    let sample = (((i32::from(mantissa) << 3) + 0x84) << exponent) - 0x84;
    if sign != 0 {
        (-sample) as i16
    } else {
        sample as i16
    }
}

fn receive_udp_tracks(
    tracks: &mut [TrackRuntime],
    duration: Duration,
    progress: &mut impl FnMut(RtspCaptureProgress),
) -> Result<(), RtspError> {
    for track in tracks.iter_mut() {
        if let Some((rtp, rtcp)) = track.udp_pair.as_mut() {
            rtp.set_nonblocking(true)?;
            rtcp.set_nonblocking(true)?;
        }
    }
    let started = Instant::now();
    let deadline = started + duration;
    let mut next_progress = Duration::ZERO;
    let mut buffer = vec![0; 65_536];
    while Instant::now() < deadline {
        if streamscope_core::analysis_cancellation_requested() {
            return Err(RtspError::Cancelled);
        }
        let mut received_any = false;
        for track in tracks.iter_mut() {
            let mut rtcp_frames = Vec::new();
            let TrackRuntime {
                udp_pair,
                tracker,
                payload_capture,
                live_audio,
                ..
            } = track;
            let Some((rtp, rtcp)) = udp_pair.as_mut() else {
                continue;
            };
            loop {
                match rtp.recv_from(&mut buffer) {
                    Ok((length, _)) => {
                        received_any = true;
                        if let Ok(packet) = parse_rtp(&buffer[..length])
                            && tracker.observe(&packet, Instant::now())
                        {
                            observe_live_audio(live_audio, &packet);
                            capture_payload(
                                &packet,
                                payload_capture,
                                started.elapsed().as_millis() as u64,
                            );
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error.into()),
                }
            }
            loop {
                match rtcp.recv_from(&mut buffer) {
                    Ok((length, _)) => {
                        received_any = true;
                        rtcp_frames.push(buffer[..length].to_vec());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error.into()),
                }
            }
            for frame in rtcp_frames {
                observe_rtcp(&frame, started.elapsed().as_millis() as u64, track);
            }
        }
        if !received_any {
            std::thread::sleep(Duration::from_millis(2));
        }
        let elapsed = started.elapsed();
        if elapsed >= next_progress {
            emit_capture_progress(elapsed, duration, tracks, progress);
            next_progress = elapsed.saturating_add(Duration::from_millis(250));
        }
    }
    emit_capture_progress(started.elapsed(), duration, tracks, progress);
    Ok(())
}

fn observe_rtcp(bytes: &[u8], offset_ms: u64, track: &mut TrackRuntime) {
    let Ok(packets) = parse_rtcp_compound(bytes) else {
        return;
    };
    track.rtcp_packet_count += packets.len() as u64;
    for packet in packets {
        match packet {
            streamscope_rtp::RtcpPacket::SenderReport {
                ssrc,
                ntp_seconds,
                ntp_fraction,
                rtp_timestamp,
                sender_packet_count,
                sender_octet_count,
            } => track.rtcp_sender_reports.push(RtcpSenderReportEvidence {
                ssrc,
                ntp_seconds,
                ntp_fraction,
                rtp_timestamp,
                sender_packet_count,
                sender_octet_count,
                capture_offset_ms: Some(offset_ms),
            }),
            streamscope_rtp::RtcpPacket::SourceDescription { chunks } => {
                for chunk in chunks {
                    if let Some(cname) = chunk.cname
                        && !track
                            .rtcp_sources
                            .iter()
                            .any(|source| source.ssrc == chunk.ssrc && source.cname == cname)
                    {
                        track.rtcp_sources.push(RtcpSourceDescription {
                            ssrc: chunk.ssrc,
                            cname,
                        });
                    }
                }
            }
            _ => {}
        }
    }
}

struct Connection {
    stream: TcpStream,
    buffer: Vec<u8>,
    pending_frames: VecDeque<InterleavedFrame>,
    cseq: u32,
    user_agent: String,
    credentials: Option<(String, String)>,
    challenge: Option<Challenge>,
    nonce_count: u32,
    authenticated: bool,
    transactions: Vec<RtspTransactionRecord>,
}

impl Connection {
    fn new(stream: TcpStream, user_agent: String, credentials: Option<(String, String)>) -> Self {
        Self {
            stream,
            buffer: Vec::new(),
            pending_frames: VecDeque::new(),
            cseq: 1,
            user_agent,
            credentials,
            challenge: None,
            nonce_count: 0,
            authenticated: false,
            transactions: Vec::new(),
        }
    }

    fn request(
        &mut self,
        method: &str,
        uri: &str,
        headers: &[(&str, String)],
        body: &[u8],
    ) -> Result<RtspResponse, RtspError> {
        let response = self.send_once(method, uri, headers, body, false)?;
        if response.status_code != 401 {
            return Ok(response);
        }
        let challenge_header = response
            .headers
            .get("www-authenticate")
            .ok_or_else(|| RtspError::Authentication("401 响应缺少 WWW-Authenticate".into()))?;
        self.challenge = Some(
            parse_challenge(challenge_header)
                .map_err(|error| RtspError::Authentication(error.to_string()))?,
        );
        if self.credentials.is_none() {
            return Err(RtspError::Authentication("URL 中没有用户名".into()));
        }
        let retry = self.send_once(method, uri, headers, body, true)?;
        if retry.status_code == 401 {
            return Err(RtspError::Authentication("用户名或密码被拒绝".into()));
        }
        self.authenticated = true;
        Ok(retry)
    }

    fn send_once(
        &mut self,
        method: &str,
        uri: &str,
        headers: &[(&str, String)],
        body: &[u8],
        include_auth: bool,
    ) -> Result<RtspResponse, RtspError> {
        let cseq = self.cseq;
        self.cseq += 1;
        let mut request_headers = headers.to_vec();
        if include_auth {
            let (username, password) = self.credentials.as_ref().expect("credentials checked");
            let challenge = self.challenge.as_ref().expect("challenge checked");
            self.nonce_count += 1;
            request_headers.push((
                "Authorization",
                authorization(
                    challenge,
                    username,
                    password,
                    method,
                    uri,
                    self.nonce_count,
                    &cnonce(),
                ),
            ));
        }
        let bytes = build_request(method, uri, cseq, &self.user_agent, &request_headers, body);
        let started = Instant::now();
        self.stream.write_all(&bytes)?;
        let response = self.read_response()?;
        self.transactions.push(RtspTransactionRecord {
            method: method.into(),
            uri: uri.into(),
            status_code: response.status_code,
            reason: response.reason.clone(),
            cseq: response
                .headers
                .get("cseq")
                .and_then(|value| value.parse().ok()),
            elapsed_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        });
        Ok(response)
    }

    fn read_response(&mut self) -> Result<RtspResponse, RtspError> {
        loop {
            while self.buffer.first() == Some(&b'$') {
                if self.buffer.len() < 4 {
                    break;
                }
                let length = usize::from(u16::from_be_bytes([self.buffer[2], self.buffer[3]]));
                if self.buffer.len() < length + 4 {
                    break;
                }
                self.pending_frames.push_back(InterleavedFrame {
                    channel: self.buffer[1],
                    payload: self.buffer[4..4 + length].to_vec(),
                });
                self.buffer.drain(..4 + length);
            }
            if self.buffer.first() != Some(&b'$')
                && let Some((response, consumed)) = parse_response(&self.buffer)?
            {
                self.buffer.drain(..consumed);
                return Ok(response);
            }
            let mut bytes = [0; 8192];
            match self.stream.read(&mut bytes) {
                Ok(0) => return Err(RtspError::Io(std::io::ErrorKind::UnexpectedEof.into())),
                Ok(length) => self.buffer.extend_from_slice(&bytes[..length]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(RtspError::Timeout);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn receive_interleaved_tracks(
        &mut self,
        duration: Duration,
        tracks: &mut [TrackRuntime],
        progress: &mut impl FnMut(RtspCaptureProgress),
    ) -> Result<(), RtspError> {
        self.stream
            .set_read_timeout(Some(Duration::from_millis(100)))?;
        let started = Instant::now();
        let deadline = Instant::now() + duration;
        let mut next_progress = Duration::ZERO;
        while Instant::now() < deadline {
            if streamscope_core::analysis_cancellation_requested() {
                return Err(RtspError::Cancelled);
            }
            while let Some(frame) = self.next_interleaved_frame() {
                observe_interleaved_track(frame, started.elapsed().as_millis() as u64, tracks);
            }
            let mut bytes = [0; 8192];
            match self.stream.read(&mut bytes) {
                Ok(0) => break,
                Ok(length) => self.buffer.extend_from_slice(&bytes[..length]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => return Err(error.into()),
            }
            let elapsed = started.elapsed();
            if elapsed >= next_progress {
                emit_capture_progress(elapsed, duration, tracks, progress);
                next_progress = elapsed.saturating_add(Duration::from_millis(250));
            }
        }
        while let Some(frame) = self.next_interleaved_frame() {
            observe_interleaved_track(frame, started.elapsed().as_millis() as u64, tracks);
        }
        emit_capture_progress(started.elapsed(), duration, tracks, progress);
        Ok(())
    }

    fn next_interleaved_frame(&mut self) -> Option<InterleavedFrame> {
        if let Some(frame) = self.pending_frames.pop_front() {
            return Some(frame);
        }
        if self.buffer.first() != Some(&b'$') || self.buffer.len() < 4 {
            return None;
        }
        let length = usize::from(u16::from_be_bytes([self.buffer[2], self.buffer[3]]));
        if self.buffer.len() < 4 + length {
            return None;
        }
        let frame = InterleavedFrame {
            channel: self.buffer[1],
            payload: self.buffer[4..4 + length].to_vec(),
        };
        self.buffer.drain(..4 + length);
        Some(frame)
    }
}

fn observe_interleaved_track(frame: InterleavedFrame, offset_ms: u64, tracks: &mut [TrackRuntime]) {
    if let Some(track) = tracks
        .iter_mut()
        .find(|track| track.rtp_channel == frame.channel)
    {
        if let Ok(packet) = parse_rtp(&frame.payload)
            && track.tracker.observe(&packet, Instant::now())
        {
            observe_live_audio(&mut track.live_audio, &packet);
            capture_payload(&packet, &mut track.payload_capture, offset_ms);
        }
        return;
    }
    if let Some(track) = tracks
        .iter_mut()
        .find(|track| track.rtcp_channel == frame.channel)
    {
        observe_rtcp(&frame.payload, offset_ms, track);
    }
}

fn capture_payload(
    packet: &streamscope_rtp::RtpPacket<'_>,
    capture: &mut PayloadCapture,
    offset_ms: u64,
) {
    const MAX_CAPTURED_PACKETS: usize = 100_000;
    const MAX_CAPTURED_BYTES: usize = 64 * 1024 * 1024;
    if packet.payload_type != capture.expected_payload_type {
        return;
    }
    capture.packet_count = capture.packet_count.saturating_add(1);
    capture.first_offset_ms.get_or_insert(offset_ms);
    let captured = CapturedRtpPayload {
        packet_number: capture.packet_count,
        offset_ms,
        sequence: packet.sequence,
        timestamp: packet.timestamp,
        marker: packet.marker,
        payload: packet.payload.to_vec(),
    };
    capture.bytes = capture.bytes.saturating_add(packet.payload.len());
    if let Some(spool) = &mut capture.spool {
        if write_payload_record(spool, &captured).is_err() {
            capture.truncated = true;
            capture.spool = None;
        }
        return;
    }
    if capture.items.len() >= MAX_CAPTURED_PACKETS || capture.bytes > MAX_CAPTURED_BYTES {
        capture.truncated = true;
        return;
    }
    capture.items.push(captured);
}

fn cnonce() -> String {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{value:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn discovers_static_and_dynamic_telephony_audio_tracks() {
        let sdp = parse_sdp(
            "v=0\r\n\
             m=audio 0 RTP/AVP 9\r\n\
             a=control:g722\r\n\
             m=audio 0 RTP/AVP 4\r\n\
             a=control:g723\r\n\
             m=audio 0 RTP/AVP 18\r\n\
             a=control:g729\r\n\
             m=audio 0 RTP/AVP 96\r\n\
             a=rtpmap:96 G726-24/8000\r\n\
             a=control:g726\r\n",
        )
        .unwrap();
        let tracks = find_media_tracks(&sdp).unwrap();
        assert_eq!(tracks.len(), 4);
        assert_eq!(tracks[0].codec, "G722");
        assert_eq!(tracks[1].codec, "G723");
        assert_eq!(tracks[2].codec, "G729");
        assert_eq!(tracks[3].codec, "G726-24");
        assert!(tracks.iter().all(|track| track.clock_rate == 8_000));
    }

    #[test]
    fn completes_tcp_interleaved_session_against_mock_server() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let sdp = "v=0\r\ns=Mock\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:trackID=1\r\n".to_string();
            for step in 0..5 {
                let request = read_request(&mut socket);
                let cseq = header_value(&request, "CSeq").unwrap();
                let response = match step {
                    0 => format!(
                        "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\nServer: MockRTSP\r\n\r\n"
                    ),
                    1 => format!(
                        "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Type: application/sdp\r\nContent-Base: rtsp://127.0.0.1:{}/live/\r\nContent-Length: {}\r\n\r\n{sdp}",
                        address.port(),
                        sdp.len()
                    ),
                    2 => format!(
                        "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nSession: mock123;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=4-5\r\n\r\n"
                    ),
                    3 => format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nSession: mock123\r\n\r\n"),
                    _ => format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n\r\n"),
                };
                socket.write_all(response.as_bytes()).unwrap();
                if step == 3 {
                    let rtp = test_rtp_packet();
                    let mut wrong_channel = vec![b'$', 0];
                    wrong_channel.extend_from_slice(&(rtp.len() as u16).to_be_bytes());
                    wrong_channel.extend_from_slice(&rtp);
                    socket.write_all(&wrong_channel).unwrap();
                    let mut frame = vec![b'$', 4];
                    frame.extend_from_slice(&(rtp.len() as u16).to_be_bytes());
                    frame.extend_from_slice(&rtp);
                    socket.write_all(&frame).unwrap();
                }
            }
        });
        let capture = analyze_rtsp_capture(RtspClientOptions {
            source_url: format!("rtsp://{address}/live"),
            transport: Transport::Tcp,
            connect_timeout: Duration::from_secs(2),
            receive_duration: Duration::from_millis(120),
            user_agent: "StreamScope-Test".into(),
            enable_live_compressed_audio: false,
            spool_directory: None,
        })
        .unwrap();
        assert_eq!(capture.video_payloads.len(), 1);
        assert!(!capture.capture_truncated);
        assert!(capture.session_sdp.contains("H264/90000"));
        let result = capture.report;
        assert!(result.connected);
        assert_eq!(result.server.as_deref(), Some("MockRTSP"));
        assert_eq!(result.transactions.len(), 5);
        assert_eq!(result.rtp.packet_count, 1);
        assert_eq!(result.interleaved_rtp_channel, Some(4));
        assert_eq!(result.interleaved_rtcp_channel, Some(5));
        assert!(result.rtp.average_bit_rate_bps.is_some());
        assert_eq!(result.media[0].codec.as_deref(), Some("H264"));
        server.join().unwrap();
    }

    #[test]
    fn parses_negotiated_interleaved_channels() {
        assert_eq!(
            parse_interleaved_channels("RTP/AVP/TCP;unicast;interleaved=6-7;ssrc=1234"),
            Some((6, 7))
        );
        assert_eq!(parse_interleaved_channels("RTP/AVP;unicast"), None);
    }

    #[test]
    fn accepts_h265_and_hevc_video_tracks() {
        for codec in ["H265", "HEVC"] {
            let sdp = parse_sdp(&format!(
                "v=0\r\nm=video 0 RTP/AVP 98\r\na=rtpmap:98 {codec}/90000\r\na=control:trackID=1\r\n"
            ))
            .unwrap();
            assert_eq!(find_video_track(&sdp).unwrap(), (0, 98, 90_000));
        }
    }

    #[test]
    fn captures_video_audio_and_rtcp_sync_evidence_in_one_session() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let sdp = "v=0\r\ns=AV\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:trackID=1\r\nm=audio 0 RTP/AVP 8\r\na=control:trackID=2\r\n".to_string();
            for step in 0..6 {
                let request = read_request(&mut socket);
                let cseq = header_value(&request, "CSeq").unwrap();
                let response = match step {
                    0 => format!(
                        "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\n\r\n"
                    ),
                    1 => format!(
                        "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nContent-Type: application/sdp\r\nContent-Base: rtsp://127.0.0.1:{}/live/\r\nContent-Length: {}\r\n\r\n{sdp}",
                        address.port(),
                        sdp.len()
                    ),
                    2 => format!(
                        "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nSession: av1\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n"
                    ),
                    3 => {
                        assert!(request.contains("Session: av1"));
                        format!(
                            "RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nSession: av1\r\nTransport: RTP/AVP/TCP;unicast;interleaved=2-3\r\n\r\n"
                        )
                    }
                    4 => format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nSession: av1\r\n\r\n"),
                    _ => format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n\r\n"),
                };
                socket.write_all(response.as_bytes()).unwrap();
                if step == 4 {
                    write_interleaved(&mut socket, 0, &rtp_packet(96, 90_000, 0x1111, &[0x65, 1]));
                    write_interleaved(&mut socket, 2, &rtp_packet(8, 8_000, 0x2222, &[0xd5; 160]));
                    write_interleaved(&mut socket, 1, &rtcp_sync(0x1111, 90_000));
                    write_interleaved(&mut socket, 3, &rtcp_sync(0x2222, 8_000));
                }
            }
        });
        let mut progress = Vec::new();
        let capture = analyze_rtsp_capture_with_progress(
            RtspClientOptions {
                source_url: format!("rtsp://{address}/live"),
                transport: Transport::Tcp,
                connect_timeout: Duration::from_secs(2),
                receive_duration: Duration::from_millis(120),
                user_agent: "StreamScope-Test".into(),
                enable_live_compressed_audio: false,
                spool_directory: None,
            },
            |snapshot| progress.push(snapshot),
        )
        .unwrap();
        assert_eq!(capture.tracks.len(), 2);
        let audio = capture
            .tracks
            .iter()
            .find(|track| track.media_type == "audio")
            .unwrap();
        assert_eq!(audio.codec, "PCMA");
        assert_eq!(audio.payloads.len(), 1);
        assert_eq!(audio.rtcp_sender_reports.len(), 1);
        assert_eq!(audio.rtcp_sources[0].cname, "cam1");
        let live_audio = progress
            .iter()
            .flat_map(|snapshot| &snapshot.audio_tracks)
            .find(|track| track.codec == "PCMA" && track.packet_count == 1)
            .unwrap();
        assert_eq!(live_audio.payload_bytes, 160);
        assert!(live_audio.peak_level_dbfs_milli.is_some());
        assert!(live_audio.rms_level_dbfs_milli.is_some());
        assert!(!live_audio.waveform.is_empty());
        server.join().unwrap();
    }

    #[test]
    fn payload_capture_streams_to_disk_without_retaining_media_in_memory() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "streamscope-rtsp-spool-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("audio.rtp-spool");
        let mut capture = PayloadCapture::new(8, Some(path.clone())).unwrap();
        for (index, timestamp) in [0_u32, 160].into_iter().enumerate() {
            let bytes = rtp_packet(8, timestamp, 42, &[0xd5; 160]);
            let packet = parse_rtp(&bytes).unwrap();
            capture_payload(&packet, &mut capture, index as u64 * 20);
        }
        capture.spool.as_mut().unwrap().flush().unwrap();
        assert!(capture.items.is_empty());
        assert_eq!(capture.packet_count, 2);
        let mut reader = BufReader::new(File::open(path).unwrap());
        let first = read_payload_record(&mut reader).unwrap().unwrap();
        let second = read_payload_record(&mut reader).unwrap().unwrap();
        assert_eq!(first.packet_number, 1);
        assert_eq!(second.offset_ms, 20);
        assert!(read_payload_record(&mut reader).unwrap().is_none());
        drop(reader);
        drop(capture);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn aac_live_decoder_publishes_real_pcm_waveform_when_ffmpeg_is_available() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "streamscope-live-aac-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let source = directory.join("tone.aac");
        let mut command = ffmpeg_command();
        command.args([
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=997:duration=1",
            "-ar",
            "44100",
            "-ac",
            "1",
            "-c:a",
            "aac",
            "-f",
            "adts",
        ]);
        command.arg(&source);
        hide_console_window(&mut command);
        if !command.status().is_ok_and(|status| status.success()) {
            let _ = std::fs::remove_dir_all(directory);
            return;
        }
        let bytes = std::fs::read(&source).unwrap();
        let spec = TrackSpec {
            media_index: 0,
            media_type: "audio".into(),
            codec: "MPEG4-GENERIC".into(),
            clock_rate: 44_100,
            channels: Some(1),
            payload_type: 97,
            fmtp: BTreeMap::from([
                ("config".into(), "1208".into()),
                ("sizelength".into(), "13".into()),
                ("indexlength".into(), "3".into()),
                ("indexdeltalength".into(), "3".into()),
            ]),
        };
        let mut level = LiveAudioAccumulator::new(&spec, true);
        let Some(decoder) = &mut level.compressed else {
            std::fs::remove_dir_all(directory).unwrap();
            panic!("ffmpeg 可用但 AAC 实时解码器未启动");
        };
        let mut cursor = 0_usize;
        let mut timestamp = 0_u32;
        while cursor + 7 <= bytes.len() {
            let frame_length = (usize::from(bytes[cursor + 3] & 3) << 11)
                | (usize::from(bytes[cursor + 4]) << 3)
                | usize::from(bytes[cursor + 5] >> 5);
            if frame_length < 7 || cursor + frame_length > bytes.len() {
                break;
            }
            let au = &bytes[cursor + 7..cursor + frame_length];
            let au_header = (au.len() << 3) as u16;
            let mut payload = vec![0, 16];
            payload.extend_from_slice(&au_header.to_be_bytes());
            payload.extend_from_slice(au);
            decoder.feed(timestamp, &payload);
            timestamp = timestamp.wrapping_add(1_024);
            cursor += frame_length;
        }
        let mut waveform = Vec::new();
        for _ in 0..100 {
            waveform = level.snapshot().2;
            if !waveform.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!waveform.is_empty(), "AAC 在线解码没有产出 PCM 波形");
        drop(level);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn opus_live_decoder_publishes_real_pcm_waveform_when_ffmpeg_is_available() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "streamscope-live-opus-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let source = directory.join("tone.ogg");
        let mut command = ffmpeg_command();
        command.args([
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=997:duration=1",
            "-ar",
            "48000",
            "-ac",
            "1",
            "-c:a",
            "libopus",
            "-f",
            "ogg",
        ]);
        command.arg(&source);
        hide_console_window(&mut command);
        if !command.status().is_ok_and(|status| status.success()) {
            let _ = std::fs::remove_dir_all(directory);
            return;
        }
        let bytes = std::fs::read(&source).unwrap();
        let mut packets = Vec::new();
        let mut pending = Vec::new();
        let mut cursor = 0_usize;
        while cursor + 27 <= bytes.len() && &bytes[cursor..cursor + 4] == b"OggS" {
            let segment_count = bytes[cursor + 26] as usize;
            if cursor + 27 + segment_count > bytes.len() {
                break;
            }
            let laces = &bytes[cursor + 27..cursor + 27 + segment_count];
            let mut data = cursor + 27 + segment_count;
            for &lace in laces {
                let length = lace as usize;
                if data + length > bytes.len() {
                    break;
                }
                pending.extend_from_slice(&bytes[data..data + length]);
                data += length;
                if lace < 255 {
                    if !pending.starts_with(b"OpusHead") && !pending.starts_with(b"OpusTags") {
                        packets.push(std::mem::take(&mut pending));
                    } else {
                        pending.clear();
                    }
                }
            }
            cursor = data;
        }
        assert!(!packets.is_empty());
        let spec = TrackSpec {
            media_index: 0,
            media_type: "audio".into(),
            codec: "opus".into(),
            clock_rate: 48_000,
            channels: Some(1),
            payload_type: 111,
            fmtp: BTreeMap::new(),
        };
        let mut level = LiveAudioAccumulator::new(&spec, true);
        let decoder = level.compressed.as_mut().expect("Opus 实时解码器未启动");
        let mut timestamp = 0_u32;
        for packet in packets {
            decoder.feed(timestamp, &packet);
            timestamp = timestamp.wrapping_add(opus_packet_samples(&packet) as u32);
        }
        let mut waveform = Vec::new();
        for _ in 0..100 {
            waveform = level.snapshot().2;
            if !waveform.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!waveform.is_empty(), "Opus 在线解码没有产出 PCM 波形");
        drop(level);
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn read_request(socket: &mut TcpStream) -> String {
        let mut data = Vec::new();
        let mut byte = [0; 1];
        while !data.ends_with(b"\r\n\r\n") {
            socket.read_exact(&mut byte).unwrap();
            data.push(byte[0]);
        }
        String::from_utf8(data).unwrap()
    }

    fn header_value<'a>(request: &'a str, name: &str) -> Option<&'a str> {
        request.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then_some(value.trim())
        })
    }

    fn test_rtp_packet() -> Vec<u8> {
        let mut bytes = vec![0x80, 0xe0, 0, 1];
        bytes.extend_from_slice(&90_000_u32.to_be_bytes());
        bytes.extend_from_slice(&0x1122_3344_u32.to_be_bytes());
        bytes.extend_from_slice(&[0x65, 1, 2, 3]);
        bytes
    }

    fn rtp_packet(pt: u8, timestamp: u32, ssrc: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x80, pt | 0x80, 0, 1];
        bytes.extend_from_slice(&timestamp.to_be_bytes());
        bytes.extend_from_slice(&ssrc.to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn write_interleaved(socket: &mut TcpStream, channel: u8, payload: &[u8]) {
        let mut frame = vec![b'$', channel];
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        socket.write_all(&frame).unwrap();
    }

    fn rtcp_sync(ssrc: u32, timestamp: u32) -> Vec<u8> {
        let mut bytes = vec![0x80, 200, 0, 6];
        bytes.extend_from_slice(&ssrc.to_be_bytes());
        bytes.extend_from_slice(&100_u32.to_be_bytes());
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        bytes.extend_from_slice(&timestamp.to_be_bytes());
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(&160_u32.to_be_bytes());
        bytes.extend_from_slice(&[0x81, 202, 0, 3]);
        bytes.extend_from_slice(&ssrc.to_be_bytes());
        bytes.extend_from_slice(&[1, 4]);
        bytes.extend_from_slice(b"cam1");
        bytes.extend_from_slice(&[0, 0]);
        bytes
    }
}
