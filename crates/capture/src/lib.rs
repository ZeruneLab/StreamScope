mod network;
mod reader;
mod sdp;
mod tcp;

use network::{Endpoint, Payload};
use reader::FrameMeta;
use sdp::{Codec, Session, UdpBinding};
use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use streamscope_audio::{
    AudioRtpPayload, analyze as analyze_audio, raw_rtp_audio_spec, write_aac_adts_mapped,
    write_opus_ogg_mapped, write_raw_rtp_audio,
};
use streamscope_core::{
    AudioAnalysis, CapturePacketEvent, CaptureStreamIdentity, CaptureSummary, H264Analysis,
    H264FrameEvidence, H265Analysis, ProtocolAnalysis, RtcpSenderReportEvidence,
    RtcpSourceDescription, Transport, VideoNaluEvidence, VideoPacketAssociation,
};
use streamscope_h264::{Depacketizer, RtpPayload, analyze_nalus};
use streamscope_h265::{
    Depacketizer as H265Depacketizer, RtpPayload as H265RtpPayload,
    analyze_nalus as analyze_h265_nalus,
};
use streamscope_rtp::{RtpTracker, parse_rtcp_compound, parse_rtp};

const MAX_STREAMS: usize = 4096;
const MAX_TCP_CONNECTIONS: usize = 256;
const MAX_SAMPLE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_TOTAL_SAMPLE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_SAMPLE_PACKETS: u64 = 200_000;
const MAX_EVENTS: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("无法读取或保存抓包数据: {0}")]
    Io(#[from] std::io::Error),
    #[error("不支持或损坏的 PCAP/PCAPNG 文件: {0}")]
    Invalid(&'static str),
    #[error("分析任务已由用户取消")]
    Cancelled,
}

#[derive(Debug)]
pub struct CaptureAnalysis {
    pub summary: CaptureSummary,
    pub streams: Vec<CapturedStream>,
    pub protocol: Option<ProtocolAnalysis>,
    pub session_sdp: Option<String>,
}
#[derive(Debug)]
pub struct CapturedStream {
    pub identity: CaptureStreamIdentity,
    pub protocol: ProtocolAnalysis,
    pub h264: Option<H264Analysis>,
    pub h265: Option<H265Analysis>,
    pub audio: Option<AudioAnalysis>,
    pub sample_path: Option<PathBuf>,
    pub warnings: Vec<String>,
    pub sample_payload_packets: u64,
    pub sample_payload_bytes: u64,
    pub analysis_ms: u64,
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct FlowKey {
    interface: String,
    source: Endpoint,
    destination: Endpoint,
    tcp_connection: Option<u64>,
    channel: Option<u8>,
    ssrc: u32,
}
#[derive(Clone, Hash, PartialEq, Eq)]
struct ConnectionKey {
    interface: String,
    low: Endpoint,
    high: Endpoint,
}
struct Connection {
    id: u64,
    syn_sequence: Option<u32>,
    closed: bool,
    observed_payload: bool,
    directions: [tcp::Reassembly; 2],
    decoders: [tcp::Decoder; 2],
    loose_rtsp_decoders: [tcp::Decoder; 2],
    session: Session,
}
impl Connection {
    fn new(id: u64) -> Self {
        Self {
            id,
            syn_sequence: None,
            closed: false,
            observed_payload: false,
            directions: Default::default(),
            decoders: Default::default(),
            loose_rtsp_decoders: Default::default(),
            session: Session::default(),
        }
    }
}

struct StreamState {
    key: FlowKey,
    identity: CaptureStreamIdentity,
    tracker: RtpTracker,
    first_micros: u64,
    last_micros: u64,
    last_arrival: u64,
    highest_extended: i64,
    codec: Option<Codec>,
    mixed_codec: bool,
    sample_packets: u64,
    sample_bytes: u64,
    sample_limited: bool,
    warnings: Vec<String>,
    spool: PathBuf,
    pending_restart: Option<Record>,
    rtcp: u64,
    rtcp_sender_reports: Vec<RtcpSenderReportEvidence>,
    rtcp_sources: Vec<RtcpSourceDescription>,
    session_id: Option<String>,
}

#[derive(Clone)]
struct Record {
    number: u64,
    micros: u64,
    extended: i64,
    sequence: u16,
    timestamp: u32,
    pt: u8,
    marker: bool,
    payload: Vec<u8>,
}
impl Record {
    fn write(&self, writer: &mut impl Write) -> std::io::Result<()> {
        writer.write_all(&self.number.to_le_bytes())?;
        writer.write_all(&self.micros.to_le_bytes())?;
        writer.write_all(&self.extended.to_le_bytes())?;
        writer.write_all(&self.sequence.to_le_bytes())?;
        writer.write_all(&self.timestamp.to_le_bytes())?;
        writer.write_all(&[self.pt, u8::from(self.marker)])?;
        writer.write_all(&(self.payload.len() as u32).to_le_bytes())?;
        writer.write_all(&self.payload)
    }
    fn read(reader: &mut impl Read) -> std::io::Result<Option<Self>> {
        let mut header = [0; 36];
        if reader.read(&mut header[..1])? == 0 {
            return Ok(None);
        }
        reader.read_exact(&mut header[1..])?;
        let length = u32::from_le_bytes(header[32..36].try_into().unwrap()) as usize;
        if length > 65_535 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "RTP 样本记录长度无效",
            ));
        }
        let mut payload = vec![0; length];
        reader.read_exact(&mut payload)?;
        Ok(Some(Self {
            number: u64::from_le_bytes(header[..8].try_into().unwrap()),
            micros: u64::from_le_bytes(header[8..16].try_into().unwrap()),
            extended: i64::from_le_bytes(header[16..24].try_into().unwrap()),
            sequence: u16::from_le_bytes(header[24..26].try_into().unwrap()),
            timestamp: u32::from_le_bytes(header[26..30].try_into().unwrap()),
            pt: header[30],
            marker: header[31] != 0,
            payload,
        }))
    }
}

#[derive(Default)]
struct Spools {
    files: HashMap<usize, (u64, BufWriter<File>)>,
    tick: u64,
}
impl Spools {
    fn write(&mut self, index: usize, path: &Path, record: &Record) -> Result<(), CaptureError> {
        self.tick += 1;
        if !self.files.contains_key(&index) {
            if self.files.len() >= 128 {
                let oldest = *self
                    .files
                    .iter()
                    .min_by_key(|(_, (tick, _))| *tick)
                    .unwrap()
                    .0;
                if let Some((_, mut writer)) = self.files.remove(&oldest) {
                    writer.flush()?;
                }
            }
            self.files.insert(
                index,
                (
                    self.tick,
                    BufWriter::new(OpenOptions::new().create(true).append(true).open(path)?),
                ),
            );
        }
        let (tick, writer) = self.files.get_mut(&index).unwrap();
        *tick = self.tick;
        record.write(writer)?;
        Ok(())
    }
    fn finish(mut self) -> Result<(), CaptureError> {
        for (_, (_, mut writer)) in self.files.drain() {
            writer.flush()?;
        }
        Ok(())
    }
}

struct Capture<'a> {
    output: &'a Path,
    summary: CaptureSummary,
    states: Vec<StreamState>,
    routes: HashMap<FlowKey, usize>,
    connections: HashMap<ConnectionKey, Connection>,
    completed_sessions: Vec<(ProtocolAnalysis, Option<String>)>,
    udp_bindings: Vec<(String, UdpBinding)>,
    next_connection: u64,
    first_micros: Option<u64>,
    last_micros: u64,
    sample_bytes: u64,
    start: Instant,
    spools: Spools,
}

pub fn analyze_capture_file(
    path: &Path,
    output_dir: &Path,
) -> Result<CaptureAnalysis, CaptureError> {
    analyze_capture_file_with_progress(path, output_dir, |_, _| {})
}

pub fn analyze_capture_file_with_progress(
    path: &Path,
    output_dir: &Path,
    mut progress: impl FnMut(u8, &str),
) -> Result<CaptureAnalysis, CaptureError> {
    let mut capture = Capture {
        output: output_dir,
        summary: CaptureSummary::default(),
        states: Vec::new(),
        routes: HashMap::new(),
        connections: HashMap::new(),
        completed_sessions: Vec::new(),
        udp_bindings: Vec::new(),
        next_connection: 0,
        first_micros: None,
        last_micros: 0,
        sample_bytes: 0,
        start: Instant::now(),
        spools: Spools::default(),
    };
    std::fs::create_dir_all(output_dir.join("streams"))?;
    progress(0, "流式读取抓包，按端点、连接、通道和 SSRC 发现媒体流");
    reader::read_capture(BufReader::new(File::open(path)?), |frame| {
        if streamscope_core::analysis_cancellation_requested() {
            return Err(CaptureError::Cancelled);
        }
        capture.frame(frame)?;
        if capture.summary.total_frames.is_multiple_of(10_000) {
            progress(
                20,
                &format!(
                    "已扫描 {} 个网络帧，发现 {} 组 RTP 候选",
                    capture.summary.total_frames,
                    capture.states.len()
                ),
            );
        }
        Ok(())
    })?;
    let connections = std::mem::take(&mut capture.connections);
    let mut session_protocols = Vec::new();
    let mut session_sdps = Vec::new();
    for (protocol, sdp) in std::mem::take(&mut capture.completed_sessions) {
        session_protocols.push(protocol);
        if let Some(sdp) = sdp {
            session_sdps.push(sdp);
        }
    }
    for (key, mut connection) in connections {
        capture.finish_connection(&key, &mut connection)?;
        connection.session.finish_pending_transactions();
        if let Some(sdp) = connection.session.sdp.clone() {
            session_sdps.push(sdp);
        }
        if connection.session.protocol.connected
            || !connection.session.protocol.transactions.is_empty()
            || !connection.session.protocol.media.is_empty()
        {
            session_protocols.push(connection.session.protocol.clone());
        }
    }
    std::mem::take(&mut capture.spools).finish()?;
    let base = capture.first_micros.unwrap_or(0);
    capture.summary.duration_ms = capture.last_micros.saturating_sub(base) / 1_000;
    add_rtsp_capture_warnings(
        &mut capture.summary.warnings,
        &capture.udp_bindings,
        &capture.states,
        &session_protocols,
    );
    let count = capture.states.len();
    let mut streams = Vec::with_capacity(count);
    for (index, mut state) in capture.states.into_iter().enumerate() {
        if streamscope_core::analysis_cancellation_requested() {
            return Err(CaptureError::Cancelled);
        }
        progress(
            50 + ((index * 50) / count.max(1)) as u8,
            &format!(
                "整理 {}/{} · {} 的独立码流样本",
                index + 1,
                count,
                state.identity.id
            ),
        );
        if state.pending_restart.is_some() {
            add_warning(
                &mut state.warnings,
                "末尾存在未确认的序列大跳变包，未纳入连续性统计",
            );
        }
        state.identity.first_offset_ms = state.first_micros.saturating_sub(base) / 1_000;
        state.identity.last_offset_ms = state.last_micros.saturating_sub(base) / 1_000;
        for event in &mut state.identity.events {
            event.offset_ms = event.offset_ms.saturating_sub(base) / 1_000;
        }
        let mut stream = finish_stream(state, base)?;
        if let Some(session) = matching_session_protocol(&stream.protocol, &session_protocols) {
            apply_session_protocol(&mut stream.protocol, session);
        }
        streams.push(stream);
    }
    capture.summary.stream_count = streams.len();
    progress(100, &format!("已完成 {} 组媒体流的独立统计", streams.len()));
    Ok(CaptureAnalysis {
        summary: capture.summary,
        streams,
        protocol: merge_session_protocols(&session_protocols),
        session_sdp: (!session_sdps.is_empty()).then(|| session_sdps.join("\n\n")),
    })
}

fn matching_session_protocol<'a>(
    stream: &ProtocolAnalysis,
    sessions: &'a [ProtocolAnalysis],
) -> Option<&'a ProtocolAnalysis> {
    stream
        .session_id
        .as_ref()
        .and_then(|id| {
            sessions
                .iter()
                .find(|session| session.session_id.as_ref() == Some(id))
        })
        .or_else(|| (sessions.len() == 1).then(|| &sessions[0]))
}

fn apply_session_protocol(target: &mut ProtocolAnalysis, session: &ProtocolAnalysis) {
    target.connected = session.connected;
    target.authenticated = session.authenticated;
    target.server = session.server.clone();
    target.public_methods = session.public_methods.clone();
    target.session_id = target
        .session_id
        .clone()
        .or_else(|| session.session_id.clone());
    target.content_base = session.content_base.clone();
    target.transactions = session.transactions.clone();
    target.media = session.media.clone();
    if target.negotiated_transport.is_none() {
        target.negotiated_transport = session.negotiated_transport.clone();
    }
    target.errors.extend(session.errors.clone());
}

fn merge_session_protocols(sessions: &[ProtocolAnalysis]) -> Option<ProtocolAnalysis> {
    if sessions.is_empty() {
        return None;
    }
    let mut merged = ProtocolAnalysis::default();
    let mut session_ids = Vec::new();
    for session in sessions {
        merged.connected |= session.connected;
        merged.authenticated |= session.authenticated;
        if merged.server.is_none() {
            merged.server = session.server.clone();
        }
        if merged.content_base.is_none() {
            merged.content_base = session.content_base.clone();
        }
        if merged.negotiated_transport.is_none() {
            merged.negotiated_transport = session.negotiated_transport.clone();
        }
        for method in &session.public_methods {
            if !merged.public_methods.contains(method) {
                merged.public_methods.push(method.clone());
            }
        }
        for transaction in &session.transactions {
            if !merged.transactions.contains(transaction) {
                merged.transactions.push(transaction.clone());
            }
        }
        for media in &session.media {
            if !merged.media.contains(media) {
                merged.media.push(media.clone());
            }
        }
        for error in &session.errors {
            if !merged.errors.contains(error) {
                merged.errors.push(error.clone());
            }
        }
        if let Some(id) = &session.session_id
            && !session_ids.contains(id)
        {
            session_ids.push(id.clone());
        }
    }
    merged
        .transactions
        .sort_by_key(|transaction| transaction.cseq);
    if session_ids.len() == 1 {
        merged.session_id = session_ids.pop();
    } else if session_ids.len() > 1 {
        merged.errors.push(format!(
            "抓包包含 {} 个 RTSP Session；事务已汇总，逐流结果按 Session 分别关联",
            session_ids.len()
        ));
    }
    Some(merged)
}

fn add_rtsp_capture_warnings(
    warnings: &mut Vec<String>,
    bindings: &[(String, UdpBinding)],
    states: &[StreamState],
    sessions: &[ProtocolAnalysis],
) {
    for session in sessions {
        let play = session
            .transactions
            .iter()
            .filter(|transaction| transaction.method.eq_ignore_ascii_case("PLAY"))
            .collect::<Vec<_>>();
        let failed = play
            .iter()
            .any(|transaction| transaction.status_code >= 400);
        let succeeded = play
            .iter()
            .any(|transaction| (200..300).contains(&transaction.status_code));
        let missing = play.iter().any(|transaction| transaction.status_code == 0);
        if failed || missing {
            let statuses = play
                .iter()
                .map(|transaction| {
                    format!(
                        "CSeq {}={} {}",
                        transaction
                            .cseq
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "?".into()),
                        transaction.status_code,
                        transaction.reason
                    )
                })
                .collect::<Vec<_>>()
                .join("；");
            let conclusion = if failed && succeeded {
                "RTSP PLAY 响应状态不一致"
            } else if failed {
                "RTSP PLAY 失败"
            } else {
                "RTSP PLAY 响应缺失"
            };
            add_warning(warnings, &format!("{conclusion}：{statuses}"));
        }
    }

    for (_, binding) in bindings {
        let received = states.iter().any(|state| {
            state.key.tcp_connection.is_none()
                && state.key.source.ip == binding.source.ip
                && (!binding.source_port_known || state.key.source.port == binding.source.port)
                && state.key.destination == binding.destination
        });
        if received {
            continue;
        }
        let mut codecs = binding.codecs.values();
        let Some(first) = codecs.next() else {
            continue;
        };
        let payload_types = binding
            .codecs
            .keys()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let play_evidence = sessions
            .iter()
            .flat_map(|session| session.transactions.iter())
            .filter(|transaction| {
                transaction.method.eq_ignore_ascii_case("PLAY")
                    && (binding.control.is_empty()
                        || transaction.uri == binding.control
                        || transaction.uri.ends_with(&binding.control))
            })
            .map(|transaction| {
                format!(
                    "CSeq {}={} {}",
                    transaction
                        .cseq
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "?".into()),
                    transaction.status_code,
                    transaction.reason
                )
            })
            .collect::<Vec<_>>()
            .join("；");
        let play_evidence = if play_evidence.is_empty() {
            "该轨道未找到可配对的 PLAY 响应".to_string()
        } else {
            format!("该轨道 PLAY：{play_evidence}")
        };
        add_warning(
            warnings,
            &format!(
                "RTSP SETUP 已协商 {} {}（PT {}，{} → {}），但抓包中未见该媒体 RTP；{}；需判断是播放启动失败、设备未发送、网络阻断或抓包点遗漏",
                first.media_type,
                first.name,
                payload_types,
                binding.source,
                binding.destination,
                play_evidence
            ),
        );
    }
}

impl Capture<'_> {
    fn frame(&mut self, frame: reader::Frame) -> Result<(), CaptureError> {
        self.summary.total_frames += 1;
        self.first_micros = Some(
            self.first_micros
                .map_or(frame.meta.timestamp_micros, |first| {
                    first.min(frame.meta.timestamp_micros)
                }),
        );
        self.last_micros = self.last_micros.max(frame.meta.timestamp_micros);
        if frame.truncated {
            add_warning(
                &mut self.summary.warnings,
                "抓包含 snaplen 截断帧，缺口不一定代表网络丢包",
            );
        }
        let packet = match network::parse_network(&frame.data, frame.link_type) {
            Ok(Some(packet)) => packet,
            Ok(None) => {
                self.summary.ignored_frames += 1;
                return Ok(());
            }
            Err(reason) => {
                self.summary.malformed_frames += 1;
                add_warning(&mut self.summary.warnings, reason);
                return Ok(());
            }
        };
        self.summary.parsed_transport_frames += 1;
        match packet.transport {
            Payload::Udp(bytes) => {
                let rtcp_binding = self.udp_bindings.iter().rev().find(|(interface, binding)| {
                    *interface == frame.meta.interface
                        && binding.rtcp_source == packet.source
                        && binding.rtcp_destination == packet.destination
                });
                if rtcp_binding.is_some() && parse_rtcp_compound(bytes).is_err() {
                    add_warning(
                        &mut self.summary.warnings,
                        "协商的 RTCP 端口收到无法完整解析的报文；已按 RTCP 保留为控制面缺口，未误计为独立 RTP 流",
                    );
                    return Ok(());
                }
                let binding = self.udp_bindings.iter().rev().find(|(interface, binding)| {
                    *interface == frame.meta.interface
                        && binding.source.ip == packet.source.ip
                        && (!binding.source_port_known || binding.source.port == packet.source.port)
                        && binding.destination == packet.destination
                });
                let codec = bytes.get(1).and_then(|pt| {
                    binding.and_then(|(_, binding)| binding.codecs.get(&(pt & 127)).cloned())
                });
                let session_id = binding
                    .or(rtcp_binding)
                    .and_then(|(_, binding)| binding.session.clone());
                self.payload(
                    FlowKey {
                        interface: frame.meta.interface.clone(),
                        source: packet.source,
                        destination: packet.destination,
                        tcp_connection: None,
                        channel: None,
                        ssrc: 0,
                    },
                    bytes,
                    &frame.meta,
                    codec,
                    session_id,
                )?;
            }
            Payload::Tcp {
                sequence,
                flags,
                data,
            } => {
                let direction = usize::from(packet.source > packet.destination);
                let key = ConnectionKey {
                    interface: frame.meta.interface.clone(),
                    low: packet.source.clone().min(packet.destination.clone()),
                    high: packet.source.max(packet.destination),
                };
                if self.connections.len() >= MAX_TCP_CONNECTIONS {
                    self.connections.retain(|_, connection| !connection.closed);
                }
                if !self.connections.contains_key(&key)
                    && self.connections.len() >= MAX_TCP_CONNECTIONS
                {
                    add_warning(
                        &mut self.summary.warnings,
                        "同时跟踪的 TCP 连接达到 256 上限，额外连接被跳过；请按设备或时间范围拆分抓包",
                    );
                    return Ok(());
                }
                let mut connection = self.connections.remove(&key).unwrap_or_else(|| {
                    self.next_connection += 1;
                    Connection::new(self.next_connection)
                });
                let new_syn = flags & 2 != 0 && flags & 16 == 0;
                if new_syn
                    && (connection.closed
                        || ((connection.observed_payload || connection.syn_sequence.is_some())
                            && connection.syn_sequence != Some(sequence)))
                {
                    self.finish_connection(&key, &mut connection)?;
                    self.archive_session(&mut connection.session);
                    self.next_connection += 1;
                    connection = Connection::new(self.next_connection);
                }
                if new_syn {
                    connection.syn_sequence = Some(sequence);
                }
                connection.observed_payload |= !data.is_empty();
                for message in tcp::push_loose_rtsp(
                    &mut connection.loose_rtsp_decoders[direction],
                    data,
                    &frame.meta,
                ) {
                    self.message(&key, &mut connection, direction, message)?;
                }
                for chunk in connection.directions[direction].push(
                    sequence,
                    flags & 2 != 0,
                    data,
                    &frame.meta,
                ) {
                    for message in connection.decoders[direction].push(chunk) {
                        self.message(&key, &mut connection, direction, message)?;
                    }
                }
                if flags & 5 != 0 {
                    connection.closed = true;
                    self.finish_connection(&key, &mut connection)?;
                }
                self.connections.insert(key, connection);
            }
        }
        Ok(())
    }

    fn finish_connection(
        &mut self,
        key: &ConnectionKey,
        connection: &mut Connection,
    ) -> Result<(), CaptureError> {
        for direction in 0..2 {
            for chunk in connection.directions[direction].finish() {
                for message in connection.decoders[direction].push(chunk) {
                    self.message(key, connection, direction, message)?;
                }
            }
            let mut partial_rtsp = false;
            if let Some(message) = connection.decoders[direction].finish_partial_rtsp() {
                self.message(key, connection, direction, message)?;
                partial_rtsp = true;
            }
            if let Some(message) = connection.loose_rtsp_decoders[direction].finish_partial_rtsp() {
                self.message(key, connection, direction, message)?;
                partial_rtsp = true;
            }
            if partial_rtsp {
                add_warning(
                    &mut self.summary.warnings,
                    "RTSP 响应头未完整终止（可能来自抓包缺口或服务端格式异常）；已保留可验证的状态行和 CSeq，正文与后续头字段不作推断",
                );
            }
            let gaps = connection.directions[direction].gaps;
            let discarded = connection.decoders[direction].discarded_bytes
                + connection.decoders[direction].unfinished_bytes() as u64;
            if gaps > 0 || discarded > 0 {
                let reason = format!(
                    "TCP 连接 {} 方向 {}：{} 处重组缺口、{} 字节未解析，受影响流的证据不完整",
                    connection.id, direction, gaps, discarded
                );
                add_warning(&mut self.summary.warnings, &reason);
                for state in &mut self.states {
                    if state.key.tcp_connection == Some(connection.id)
                        && usize::from(state.key.source > state.key.destination) == direction
                    {
                        add_warning(&mut state.warnings, &reason);
                        state.identity.sample_truncated = true;
                    }
                }
            }
        }
        Ok(())
    }

    fn archive_session(&mut self, session: &mut Session) {
        session.finish_pending_transactions();
        if session.protocol.connected
            || !session.protocol.transactions.is_empty()
            || !session.protocol.media.is_empty()
        {
            self.completed_sessions
                .push((session.protocol.clone(), session.sdp.clone()));
        }
    }

    fn message(
        &mut self,
        key: &ConnectionKey,
        connection: &mut Connection,
        direction: usize,
        message: tcp::Message,
    ) -> Result<(), CaptureError> {
        let (source, destination) = if direction == 0 {
            (&key.low, &key.high)
        } else {
            (&key.high, &key.low)
        };
        match message {
            tcp::Message::Rtsp { text, meta } => {
                let previous_udp = connection.session.udp.len();
                connection
                    .session
                    .observe(&text, source, destination, meta.timestamp_micros);
                for binding in &connection.session.udp[previous_udp..] {
                    if self.udp_bindings.len() < MAX_STREAMS {
                        self.udp_bindings
                            .push((key.interface.clone(), binding.clone()));
                    } else {
                        add_warning(
                            &mut self.summary.warnings,
                            "UDP 会话映射达到 4096 上限，后续映射仅按端点识别",
                        );
                    }
                }
                if connection.session.codec_changed {
                    add_warning(
                        &mut self.summary.warnings,
                        "存在 TCP 通道编码映射变化，相关流将降低结论可信度",
                    );
                }
            }
            tcp::Message::Interleaved {
                channel,
                payload,
                meta,
            } => {
                let codec = payload
                    .get(1)
                    .and_then(|pt| connection.session.codec(channel, pt & 127));
                let rtp_channel = if payload.get(1).is_some_and(|pt| (192..=223).contains(pt)) {
                    connection
                        .session
                        .rtcp_channels
                        .get(&channel)
                        .copied()
                        .unwrap_or(channel)
                } else {
                    channel
                };
                self.payload(
                    FlowKey {
                        interface: key.interface.clone(),
                        source: source.clone(),
                        destination: destination.clone(),
                        tcp_connection: Some(connection.id),
                        channel: Some(rtp_channel),
                        ssrc: 0,
                    },
                    &payload,
                    &meta,
                    codec,
                    connection.session.session_id.clone(),
                )?;
            }
        }
        Ok(())
    }

    fn payload(
        &mut self,
        mut key: FlowKey,
        bytes: &[u8],
        meta: &FrameMeta,
        declared_codec: Option<Codec>,
        session: Option<String>,
    ) -> Result<(), CaptureError> {
        if bytes.len() >= 4
            && (192..=223).contains(&bytes[1])
            && let Ok(packets) = parse_rtcp_compound(bytes)
        {
            for packet in packets {
                let ssrc = match &packet {
                    streamscope_rtp::RtcpPacket::SenderReport { ssrc, .. } => Some(*ssrc),
                    streamscope_rtp::RtcpPacket::SourceDescription { chunks }
                        if chunks.len() == 1 =>
                    {
                        Some(chunks[0].ssrc)
                    }
                    _ => None,
                };
                if let Some(ssrc) = ssrc {
                    let candidates: Vec<_> = self
                        .states
                        .iter()
                        .enumerate()
                        .filter(|(_, state)| {
                            state.identity.ssrc == ssrc
                                && state.key.interface == key.interface
                                && state.key.tcp_connection == key.tcp_connection
                                && state.key.channel == key.channel
                                && state.key.source.ip == key.source.ip
                                && state.key.destination.ip == key.destination.ip
                                && (key.tcp_connection.is_some()
                                    || ((state.key.source.port == key.source.port
                                        || state.key.source.port.checked_add(1)
                                            == Some(key.source.port))
                                        && (state.key.destination.port == key.destination.port
                                            || state.key.destination.port.checked_add(1)
                                                == Some(key.destination.port))))
                        })
                        .map(|(index, _)| index)
                        .collect();
                    if let [index] = candidates[..] {
                        self.states[index].rtcp += 1;
                        match packet {
                            streamscope_rtp::RtcpPacket::SenderReport {
                                ssrc,
                                ntp_seconds,
                                ntp_fraction,
                                rtp_timestamp,
                                sender_packet_count,
                                sender_octet_count,
                            } => self.states[index].rtcp_sender_reports.push(
                                RtcpSenderReportEvidence {
                                    ssrc,
                                    ntp_seconds,
                                    ntp_fraction,
                                    rtp_timestamp,
                                    sender_packet_count,
                                    sender_octet_count,
                                    capture_offset_ms: self.first_micros.map(|base| {
                                        meta.timestamp_micros.saturating_sub(base) / 1_000
                                    }),
                                },
                            ),
                            streamscope_rtp::RtcpPacket::SourceDescription { chunks } => {
                                for chunk in chunks {
                                    if let Some(cname) = chunk.cname
                                        && !self.states[index].rtcp_sources.iter().any(|source| {
                                            source.ssrc == chunk.ssrc && source.cname == cname
                                        })
                                    {
                                        self.states[index].rtcp_sources.push(
                                            RtcpSourceDescription {
                                                ssrc: chunk.ssrc,
                                                cname,
                                            },
                                        );
                                    }
                                }
                            }
                            _ => {}
                        }
                    } else {
                        add_warning(
                            &mut self.summary.warnings,
                            "部分 RTCP Sender Report 无法唯一关联到媒体流，未计入任何单流",
                        );
                    }
                }
            }
            return Ok(());
        }
        let Ok(packet) = parse_rtp(bytes) else {
            return Ok(());
        };
        if packet.payload.is_empty() {
            return Ok(());
        }
        key.ssrc = packet.ssrc;
        let codec = declared_codec.or_else(|| sdp::static_codec(packet.payload_type));
        let mut record = Record {
            number: meta.number,
            micros: meta.timestamp_micros,
            extended: 0,
            sequence: packet.sequence,
            timestamp: packet.timestamp,
            pt: packet.payload_type,
            marker: packet.marker,
            payload: packet.payload.to_vec(),
        };
        let mut index = if let Some(index) = self.routes.get(&key) {
            *index
        } else {
            let Some(index) = self.new_stream(key.clone(), &record, codec.clone())? else {
                return Ok(());
            };
            index
        };
        if session.is_some() {
            self.states[index].session_id = session.clone();
        }
        let highest = self.states[index].tracker.statistics().last_sequence;
        if let Some(highest) = highest {
            let delta = record.sequence.wrapping_sub(highest);
            if (3_001..65_436).contains(&delta) {
                if let Some(previous) = self.states[index].pending_restart.take() {
                    if record.sequence == previous.sequence.wrapping_add(1) {
                        add_warning(
                            &mut self.states[index].warnings,
                            "观测到连续确认的序列大跳变，后续分为新的统计阶段；无法仅据此区分发送源重启和长区间缺包",
                        );
                        let Some(next) = self.new_stream(key.clone(), &previous, codec.clone())?
                        else {
                            return Ok(());
                        };
                        index = next;
                        self.states[index].session_id = session;
                        add_warning(
                            &mut self.states[index].warnings,
                            "本流为序列大跳变后的独立统计阶段，边界原因需要设备日志或完整抓包验证",
                        );
                        self.observe(index, previous, codec.clone())?;
                    } else {
                        add_warning(
                            &mut self.states[index].warnings,
                            "存在未确认的序列大跳变包，未纳入连续性统计",
                        );
                        self.states[index].pending_restart = Some(record);
                        return Ok(());
                    }
                } else {
                    self.states[index].pending_restart = Some(record);
                    return Ok(());
                }
            } else if self.states[index].pending_restart.take().is_some() {
                add_warning(
                    &mut self.states[index].warnings,
                    "存在孤立序列异常包，未纳入连续性统计",
                );
            }
        }
        record.extended = self.states[index].highest_extended
            + i64::from(
                record
                    .sequence
                    .wrapping_sub(self.states[index].highest_extended as u16)
                    as i16,
            );
        self.observe(index, record, codec)
    }

    fn new_stream(
        &mut self,
        key: FlowKey,
        record: &Record,
        codec: Option<Codec>,
    ) -> Result<Option<usize>, CaptureError> {
        if self.states.len() >= MAX_STREAMS {
            add_warning(
                &mut self.summary.warnings,
                "媒体流达到 4096 组资源上限，额外流被跳过；请拆分抓包后分析",
            );
            return Ok(None);
        }
        let index = self.states.len();
        let id = format!("stream-{:04}", index + 1);
        let directory = self.output.join("streams").join(&id);
        std::fs::create_dir_all(&directory)?;
        // Refuse to append an earlier analysis into this stream's evidence.
        File::options()
            .write(true)
            .create_new(true)
            .open(directory.join("rtp-sample.bin"))?;
        let identity = CaptureStreamIdentity {
            id,
            source: key.source.to_string(),
            destination: key.destination.to_string(),
            transport: if key.tcp_connection.is_some() {
                Transport::Tcp
            } else {
                Transport::Udp
            },
            ssrc: key.ssrc,
            channel: key.channel,
            interface_id: key.interface.clone(),
            connection_id: key.tcp_connection,
            payload_types: Vec::new(),
            codec: codec.as_ref().map(|codec| codec.name.to_ascii_lowercase()),
            media_type: codec
                .as_ref()
                .map_or_else(|| "unknown".into(), |codec| codec.media_type.clone()),
            channels: codec.as_ref().and_then(|codec| codec.channels),
            codec_confidence: if codec.is_some() {
                "confirmed"
            } else {
                "unknown"
            }
            .into(),
            clock_rate: codec.as_ref().map(|codec| codec.clock_rate),
            first_packet: record.number,
            last_packet: record.number,
            first_offset_ms: 0,
            last_offset_ms: 0,
            sample_truncated: false,
            events: Vec::new(),
        };
        self.states.push(StreamState {
            key: key.clone(),
            identity,
            tracker: RtpTracker::new(codec.as_ref().map_or(90_000, |codec| codec.clock_rate)),
            first_micros: record.micros,
            last_micros: record.micros,
            last_arrival: record.micros,
            highest_extended: i64::from(record.sequence),
            codec,
            mixed_codec: false,
            sample_packets: 0,
            sample_bytes: 0,
            sample_limited: false,
            warnings: Vec::new(),
            spool: directory.join("rtp-sample.bin"),
            pending_restart: None,
            rtcp: 0,
            rtcp_sender_reports: Vec::new(),
            rtcp_sources: Vec::new(),
            session_id: None,
        });
        self.routes.insert(key, index);
        Ok(Some(index))
    }

    fn observe(
        &mut self,
        index: usize,
        mut record: Record,
        codec: Option<Codec>,
    ) -> Result<(), CaptureError> {
        let state = &mut self.states[index];
        record.extended = state.highest_extended
            + i64::from(record.sequence.wrapping_sub(state.highest_extended as u16) as i16);
        state.highest_extended = state.highest_extended.max(record.extended);
        if let Some(codec) = codec {
            if let Some(previous) = &state.codec {
                if previous != &codec {
                    state.mixed_codec = true;
                    add_warning(
                        &mut state.warnings,
                        "本流出现不同编码或时钟率，保留整流 RTP 连续性统计，停止混合编码的 H.264 解包",
                    );
                }
            } else {
                state.identity.codec = Some(codec.name.to_ascii_lowercase());
                state.identity.codec_confidence = "confirmed".into();
                state.identity.clock_rate = Some(codec.clock_rate);
                state.identity.channels = codec.channels;
                state.identity.media_type = codec.media_type.clone();
                // Statistics before the mapping had no verified clock, so do not present jitter as calibrated.
                add_warning(
                    &mut state.warnings,
                    "编码映射在流开始之后才可用，抖动时钟未全程验证",
                );
            }
            state.codec = Some(codec);
        }
        if !state.identity.payload_types.contains(&record.pt) {
            state.identity.payload_types.push(record.pt);
        }
        state.identity.first_packet = state.identity.first_packet.min(record.number);
        state.identity.last_packet = state.identity.last_packet.max(record.number);
        state.first_micros = state.first_micros.min(record.micros);
        state.last_micros = state.last_micros.max(record.micros);
        if record.micros < state.last_arrival {
            add_warning(
                &mut state.warnings,
                "抓包时间戳或 TCP 重组输出顺序回退，抖动和峰值码率仅作参考",
            );
        }
        state.last_arrival = state.last_arrival.max(record.micros);
        let previous = state.tracker.statistics().last_sequence;
        let packet = streamscope_rtp::RtpPacket {
            marker: record.marker,
            payload_type: record.pt,
            sequence: record.sequence,
            timestamp: record.timestamp,
            ssrc: state.identity.ssrc,
            csrc: Vec::new(),
            extension: None,
            payload: &record.payload,
        };
        let arrival = self.start
            + Duration::from_micros(state.last_arrival.saturating_sub(state.first_micros));
        if !state.tracker.observe(&packet, arrival) {
            return Ok(());
        }
        if let Some(previous) = previous {
            let delta = record.sequence.wrapping_sub(previous);
            if delta > 1 && delta < 3_001 {
                push_event(
                    state,
                    &record,
                    "sequence_gap",
                    format!(
                        "#{} 到达时观测到序列 {}–{} 缺口（{} 包）；后续补到包以最终缺口计数为准",
                        record.number,
                        previous.wrapping_add(1),
                        record.sequence.wrapping_sub(1),
                        delta - 1
                    ),
                );
            }
        }
        let stored_bytes = record.payload.len() as u64 + 36;
        if state.sample_limited {
            return Ok(());
        }
        if self.sample_bytes.saturating_add(stored_bytes) > MAX_TOTAL_SAMPLE_BYTES {
            state.sample_limited = true;
            state.identity.sample_truncated = true;
            add_warning(
                &mut state.warnings,
                "整次任务的 RTP 流式落盘达到 16 GiB 安全上限；后续 RTP 统计继续，但媒体负载不再保存",
            );
            return Ok(());
        }
        self.spools.write(index, &state.spool, &record)?;
        state.sample_packets += 1;
        state.sample_bytes += record.payload.len() as u64;
        self.sample_bytes += stored_bytes;
        Ok(())
    }
}

fn push_event(state: &mut StreamState, record: &Record, kind: &str, detail: String) {
    if state.identity.events.len() < MAX_EVENTS {
        state.identity.events.push(CapturePacketEvent {
            packet_number: record.number,
            offset_ms: record.micros,
            sequence: Some(record.sequence),
            rtp_timestamp: Some(record.timestamp),
            kind: kind.into(),
            detail,
        });
    } else {
        add_warning(
            &mut state.warnings,
            "异常时间线仅保留前 256 项，完整计数请查看 RTP 统计",
        );
    }
}

fn add_warning(warnings: &mut Vec<String>, text: &str) {
    if !warnings.iter().any(|warning| warning == text) && warnings.len() < 128 {
        warnings.push(text.into());
    }
}

fn finish_stream(mut state: StreamState, base: u64) -> Result<CapturedStream, CaptureError> {
    let started = Instant::now();
    let mut records = Vec::new();
    let mut analysis_bytes = 0_u64;
    if state.spool.is_file() {
        let mut reader = BufReader::new(File::open(&state.spool)?);
        while let Some(record) = Record::read(&mut reader)? {
            if streamscope_core::analysis_cancellation_requested() {
                return Err(CaptureError::Cancelled);
            }
            if records.len() as u64 >= MAX_SAMPLE_PACKETS
                || analysis_bytes.saturating_add(record.payload.len() as u64) > MAX_SAMPLE_BYTES
            {
                state.identity.sample_truncated = true;
                add_warning(
                    &mut state.warnings,
                    "完整 RTP 负载已流式落盘；结构、解码和内容分析使用前 32 MiB/20 万包有界窗口，避免超长抓包耗尽内存",
                );
                break;
            }
            analysis_bytes = analysis_bytes.saturating_add(record.payload.len() as u64);
            records.push(record);
        }
    }
    records.sort_by_key(|record| record.extended);
    let mut h264 = None;
    let mut h265 = None;
    let mut audio = None;
    let mut sample_path = None;
    let audio_declared = state.identity.media_type == "audio"
        || matches!(
            state.identity.codec.as_deref(),
            Some(
                "pcma"
                    | "pcmu"
                    | "mpeg4-generic"
                    | "aac"
                    | "opus"
                    | "g722"
                    | "g723"
                    | "g723.1"
                    | "g723_1"
                    | "g729"
                    | "g729a"
                    | "g726"
            )
        );
    let h264_declared = state.identity.codec.as_deref() == Some("h264");
    if !audio_declared && !state.mixed_codec && (h264_declared || state.codec.is_none()) {
        let mut decoder = Depacketizer::default();
        let mut nalus = Vec::new();
        let mut invalid = 0;
        for record in &records {
            if record
                .payload
                .first()
                .is_none_or(|header| header & 0x80 != 0 || !matches!(header & 31, 1..=23 | 24 | 28))
            {
                invalid += 1;
            }
            nalus.extend(decoder.push(RtpPayload {
                sequence: record.sequence,
                timestamp: record.timestamp,
                marker: record.marker,
                payload: record.payload.clone(),
            }));
        }
        nalus.extend(decoder.finish());
        let mut candidate = analyze_nalus(nalus.clone(), decoder.issues.clone());
        if candidate.issues.len() > MAX_EVENTS {
            candidate.issues.truncate(MAX_EVENTS);
            add_warning(
                &mut state.warnings,
                "H.264 异常明细仅保留前 256 项，完整 NALU 计数不受影响",
            );
        }
        let inferred = !records.is_empty()
            && invalid * 20 <= records.len()
            && !candidate.sps.is_empty()
            && !candidate.pps.is_empty()
            && candidate.frame_count > 0;
        if h264_declared || inferred {
            if inferred && !h264_declared {
                state.identity.codec = Some("h264".into());
                state.identity.codec_confidence = "inferred".into();
                state.identity.clock_rate = Some(90_000);
            }
            let path = state.spool.with_file_name("sample.h264");
            let mut output = BufWriter::new(File::create(&path)?);
            let mut sample_offset = 0_u64;
            let mut sample_ranges = vec![None; nalus.len()];
            for (index, nalu) in nalus.iter().enumerate().filter(|(_, nalu)| nalu.complete) {
                let start = sample_offset;
                output.write_all(&[0, 0, 0, 1])?;
                output.write_all(&nalu.data)?;
                sample_offset = sample_offset.saturating_add(4 + nalu.data.len() as u64);
                sample_ranges[index] = Some((start, sample_offset));
            }
            output.flush()?;
            let locations: BTreeMap<_, _> = records
                .iter()
                .map(|record| ((record.timestamp, record.sequence), record))
                .collect();
            annotate_frames(&mut candidate.frames, &sample_ranges, &locations, base);
            annotate_nalus(&mut candidate.nalus, &sample_ranges, &records, base);
            for issue in &candidate.issues {
                if state.identity.events.len() >= MAX_EVENTS {
                    break;
                }
                if let Some(record) = issue
                    .timestamp
                    .zip(issue.sequence)
                    .and_then(|key| locations.get(&key))
                {
                    state.identity.events.push(CapturePacketEvent {
                        packet_number: record.number,
                        offset_ms: record.micros.saturating_sub(base) / 1_000,
                        sequence: issue.sequence,
                        rtp_timestamp: issue.timestamp,
                        kind: issue.kind.clone(),
                        detail: issue.detail.clone(),
                    });
                }
            }
            sample_path = Some(path);
            h264 = Some(candidate);
        }
    }
    let h265_declared = matches!(state.identity.codec.as_deref(), Some("h265" | "hevc"));
    if !audio_declared
        && h264.is_none()
        && !state.mixed_codec
        && (h265_declared || state.codec.is_none())
    {
        let mut decoder = H265Depacketizer::default();
        let mut nalus = Vec::new();
        let mut invalid = 0;
        for record in &records {
            if record.payload.len() < 2
                || record.payload[0] & 0x80 != 0
                || record.payload[1] & 7 == 0
            {
                invalid += 1;
            }
            nalus.extend(decoder.push(H265RtpPayload {
                sequence: record.sequence,
                timestamp: record.timestamp,
                marker: record.marker,
                payload: record.payload.clone(),
            }));
        }
        nalus.extend(decoder.finish());
        let mut candidate = analyze_h265_nalus(nalus.clone(), decoder.issues.clone());
        if candidate.issues.len() > MAX_EVENTS {
            candidate.issues.truncate(MAX_EVENTS);
            add_warning(
                &mut state.warnings,
                "H.265 异常明细仅保留前 256 项，完整 NALU 计数不受影响",
            );
        }
        let inferred = !records.is_empty()
            && invalid * 20 <= records.len()
            && candidate.vps_count > 0
            && !candidate.sps.is_empty()
            && !candidate.pps.is_empty()
            && candidate.frame_count > 0;
        if h265_declared || inferred {
            if inferred && !h265_declared {
                state.identity.codec = Some("h265".into());
                state.identity.codec_confidence = "inferred".into();
                state.identity.clock_rate = Some(90_000);
            }
            let path = state.spool.with_file_name("sample.h265");
            let mut output = BufWriter::new(File::create(&path)?);
            let mut sample_offset = 0_u64;
            let mut sample_ranges = vec![None; nalus.len()];
            for (index, nalu) in nalus.iter().enumerate().filter(|(_, nalu)| nalu.complete) {
                let start = sample_offset;
                output.write_all(&[0, 0, 0, 1])?;
                output.write_all(&nalu.data)?;
                sample_offset = sample_offset.saturating_add(4 + nalu.data.len() as u64);
                sample_ranges[index] = Some((start, sample_offset));
            }
            output.flush()?;
            let locations: BTreeMap<_, _> = records
                .iter()
                .map(|record| ((record.timestamp, record.sequence), record))
                .collect();
            annotate_frames(&mut candidate.frames, &sample_ranges, &locations, base);
            annotate_nalus(&mut candidate.nalus, &sample_ranges, &records, base);
            for issue in &candidate.issues {
                if state.identity.events.len() >= MAX_EVENTS {
                    break;
                }
                if let Some(record) = issue
                    .timestamp
                    .zip(issue.sequence)
                    .and_then(|key| locations.get(&key))
                {
                    state.identity.events.push(CapturePacketEvent {
                        packet_number: record.number,
                        offset_ms: record.micros.saturating_sub(base) / 1_000,
                        sequence: issue.sequence,
                        rtp_timestamp: issue.timestamp,
                        kind: issue.kind.clone(),
                        detail: issue.detail.clone(),
                    });
                }
            }
            sample_path = Some(path);
            h265 = Some(candidate);
        }
    }
    if audio_declared && !state.mixed_codec {
        let codec = state
            .identity
            .codec
            .clone()
            .unwrap_or_else(|| "unknown".into());
        let clock_rate = state.identity.clock_rate.unwrap_or(8_000);
        let wav_path = state.spool.with_file_name("preview.wav");
        let packets: Vec<_> = records
            .iter()
            .map(|record| AudioRtpPayload {
                packet_number: Some(record.number),
                offset_ms: Some(record.micros.saturating_sub(base) / 1_000),
                sequence: Some(record.sequence),
                timestamp: record.timestamp,
                payload: record.payload.clone(),
            })
            .collect();
        let decoded = matches!(codec.as_str(), "pcma" | "pcmu");
        audio = Some(analyze_audio(
            &codec,
            clock_rate,
            state.identity.channels,
            &packets,
            state.identity.sample_truncated,
            decoded.then_some(wav_path.as_path()),
        )?);
        if decoded {
            sample_path = Some(wav_path);
        } else if matches!(codec.as_str(), "mpeg4-generic" | "aac") {
            let path = state.spool.with_file_name("sample.aac");
            let fmtp = state
                .codec
                .as_ref()
                .map(|codec| &codec.fmtp)
                .cloned()
                .unwrap_or_default();
            let written =
                write_aac_adts_mapped(&packets, &fmtp, clock_rate, state.identity.channels, &path)?;
            let units = written.units;
            if let Some(audio) = &mut audio {
                audio.access_unit_count = units;
                audio.sample_mappings = written.mappings;
            }
            if units > 0 {
                sample_path = Some(path);
            } else {
                let _ = std::fs::remove_file(path);
                add_warning(
                    &mut state.warnings,
                    "AAC RTP 未能按 MPEG4-GENERIC AU Header 重组，未生成可播放样本",
                );
            }
        } else if codec == "opus" {
            let path = state.spool.with_file_name("sample.ogg");
            let written = write_opus_ogg_mapped(&packets, state.identity.channels, &path)?;
            let units = written.units;
            if let Some(audio) = &mut audio {
                audio.access_unit_count = units;
                audio.sample_mappings = written.mappings;
            }
            if units > 0 {
                sample_path = Some(path);
            } else {
                let _ = std::fs::remove_file(path);
            }
        } else if let Some(spec) = raw_rtp_audio_spec(&codec, clock_rate) {
            let path = state
                .spool
                .with_file_name(format!("sample.{}", spec.extension));
            if write_raw_rtp_audio(&packets, &path)? > 0 {
                sample_path = Some(path);
            } else {
                let _ = std::fs::remove_file(path);
            }
        }
    }
    if state.identity.codec.is_none() {
        add_warning(
            &mut state.warnings,
            "缺少可靠编码映射或有效参数集，本流仅作为 RTP 候选统计，未送 H.264/H.265 解码器",
        );
    }
    if state.mixed_codec {
        state.identity.codec_confidence = "unknown".into();
        state.identity.clock_rate = None;
    }
    let duration = Duration::from_micros(state.last_micros.saturating_sub(state.first_micros));
    let mut statistics = state.tracker.into_statistics_with_duration(duration);
    if duration.is_zero() {
        statistics.average_bit_rate_bps = None;
    }
    let protocol = ProtocolAnalysis {
        rtp: statistics,
        sample_duration_ms: Some(duration.as_millis() as u64),
        negotiated_transport: Some(state.identity.transport.to_string()),
        interleaved_rtp_channel: state.identity.channel,
        rtcp_packet_count: state.rtcp,
        rtcp_sender_reports: state.rtcp_sender_reports,
        rtcp_sources: state.rtcp_sources,
        session_id: state.session_id,
        ..ProtocolAnalysis::default()
    };
    // The retained binary index contains original packet numbers, timestamps and RTP payloads.
    Ok(CapturedStream {
        identity: state.identity,
        protocol,
        h264,
        h265,
        audio,
        sample_path,
        warnings: state.warnings,
        sample_payload_packets: state.sample_packets,
        sample_payload_bytes: state.sample_bytes,
        analysis_ms: started.elapsed().as_millis() as u64,
    })
}

fn annotate_frames(
    frames: &mut [H264FrameEvidence],
    sample_ranges: &[Option<(u64, u64)>],
    locations: &BTreeMap<(u32, u16), &Record>,
    base: u64,
) {
    for frame in frames {
        let first = frame
            .rtp_timestamp
            .zip(frame.first_sequence)
            .and_then(|key| locations.get(&key));
        let last = frame
            .rtp_timestamp
            .zip(frame.last_sequence)
            .and_then(|key| locations.get(&key));
        frame.first_packet = first.map(|record| record.number);
        frame.last_packet = last.map(|record| record.number);
        frame.first_offset_ms = first.map(|record| record.micros.saturating_sub(base) / 1_000);
        frame.last_offset_ms = last.map(|record| record.micros.saturating_sub(base) / 1_000);
        let start = frame.first_nalu.saturating_sub(1) as usize;
        let end = (frame.last_nalu as usize).min(sample_ranges.len());
        let mut ranges = sample_ranges[start.min(end)..end]
            .iter()
            .filter_map(|range| *range);
        if let Some((sample_start, sample_end)) = ranges.next() {
            frame.sample_start_offset = Some(sample_start);
            frame.sample_end_offset =
                Some(ranges.fold(sample_end, |maximum, (_, end)| maximum.max(end)));
        }
    }
}

fn annotate_nalus(
    nalus: &mut [VideoNaluEvidence],
    sample_ranges: &[Option<(u64, u64)>],
    records: &[Record],
    base: u64,
) {
    const MAX_PACKET_ASSOCIATIONS_PER_NALU: usize = 20_000;
    for nalu in nalus {
        if let Some((start, end)) = nalu
            .nalu_number
            .checked_sub(1)
            .and_then(|index| sample_ranges.get(index as usize))
            .and_then(|range| *range)
        {
            nalu.sample_start_offset = Some(start);
            nalu.sample_end_offset = Some(end);
        }
        let Some((timestamp, first, last)) = nalu
            .rtp_timestamp
            .zip(nalu.first_sequence)
            .zip(nalu.last_sequence)
            .map(|((timestamp, first), last)| (timestamp, first, last))
        else {
            continue;
        };
        let matches_sequence = |sequence: u16| {
            if first <= last {
                (first..=last).contains(&sequence)
            } else {
                sequence >= first || sequence <= last
            }
        };
        let mut matched = 0_usize;
        for record in records
            .iter()
            .filter(|record| record.timestamp == timestamp && matches_sequence(record.sequence))
        {
            matched += 1;
            if nalu.packets.len() < MAX_PACKET_ASSOCIATIONS_PER_NALU {
                nalu.packets.push(VideoPacketAssociation {
                    packet_number: record.number,
                    rtp_sequence: record.sequence,
                    offset_ms: record.micros.saturating_sub(base) / 1_000,
                });
            }
        }
        nalu.packet_associations_truncated = matched > MAX_PACKET_ASSOCIATIONS_PER_NALU;
    }
}

#[cfg(test)]
mod tests;
