use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use streamscope_core::{AnalysisResult, AnalysisStatus, DiagnosticSeverity, SourceKind};

#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("无法写入报告: {0}")]
    Io(#[from] std::io::Error),
    #[error("无法序列化 JSON 报告: {0}")]
    Json(#[from] serde_json::Error),
    #[error("媒体流报告结构无效: {0}")]
    InvalidStreams(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportPaths {
    pub json: PathBuf,
    pub html: PathBuf,
    pub ffmpeg_log: PathBuf,
    pub session_sdp: Option<PathBuf>,
}

pub fn write_reports(
    output_directory: &Path,
    result: &AnalysisResult,
) -> Result<ReportPaths, ReportError> {
    let mut stream_ids = HashSet::new();
    for stream in &result.streams {
        let identity = stream
            .capture_stream
            .as_ref()
            .ok_or_else(|| ReportError::InvalidStreams("缺少流标识".into()))?;
        if !valid_stream_id(&identity.id) || !stream_ids.insert(&identity.id) {
            return Err(ReportError::InvalidStreams("流 ID 无效或重复".into()));
        }
        if !stream.streams.is_empty() || stream.capture_summary.is_some() {
            return Err(ReportError::InvalidStreams("不支持嵌套媒体流总览".into()));
        }
    }
    fs::create_dir_all(output_directory)?;
    let root = output_directory.canonicalize()?;
    for stream in &result.streams {
        let directory = output_directory
            .join("streams")
            .join(&stream.capture_stream.as_ref().unwrap().id);
        // Check existing directories before creating or writing through a link.
        for ancestor in directory.ancestors().take(2) {
            if ancestor.exists() && !ancestor.canonicalize()?.starts_with(&root) {
                return Err(ReportError::InvalidStreams("流目录指向报告目录外部".into()));
            }
        }
        write_reports(&directory, stream)?;
    }
    let json = output_directory.join("result.json");
    let html = output_directory.join("report.html");
    let ffmpeg_log = output_directory.join("ffmpeg.log");
    fs::write(&json, serde_json::to_vec_pretty(result)?)?;
    fs::write(&html, render_html(result))?;
    let log = result
        .decode
        .as_ref()
        .map(|decode| decode.log.clone())
        .unwrap_or_else(|| result.errors.join("\n"));
    fs::write(&ffmpeg_log, log)?;
    let stream_info = result
        .stream
        .as_ref()
        .map(|stream| {
            format!(
                "codec={}\nprofile={}\nresolution={}x{}\nframe_rate={}\nbit_rate={}\n",
                stream.codec.as_deref().unwrap_or("unknown"),
                stream.profile.as_deref().unwrap_or("unknown"),
                stream
                    .width
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".into()),
                stream
                    .height
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".into()),
                stream.frame_rate.as_deref().unwrap_or("unknown"),
                stream
                    .bit_rate
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".into())
            )
        })
        .or_else(|| {
            result.audio.as_ref().map(|audio| {
                format!(
                    "media_type=audio\ncodec={}\nsample_rate={}\nchannels={}\ndecoded_samples={}\nduration_ms={}\n",
                    audio.codec,
                    audio.sample_rate.unwrap_or(audio.clock_rate),
                    audio
                        .channels
                        .map_or_else(|| "unknown".into(), |value| value.to_string()),
                    audio.decoded_samples,
                    audio
                        .decoded_duration_ms
                        .map_or_else(|| "unknown".into(), |value| value.to_string()),
                )
            })
        })
        .unwrap_or_else(|| "media stream information unavailable\n".into());
    fs::write(output_directory.join("stream-info.txt"), stream_info)?;
    let session_sdp = result
        .session_sdp
        .as_ref()
        .map(|sdp| {
            let path = output_directory.join("session.sdp");
            fs::write(&path, sdp).map(|()| path)
        })
        .transpose()?;
    Ok(ReportPaths {
        json,
        html,
        ffmpeg_log,
        session_sdp,
    })
}

pub fn render_html(result: &AnalysisResult) -> String {
    if result.capture_summary.is_some() {
        return render_capture_overview(result);
    }
    let title_status = match result.status {
        AnalysisStatus::Completed => "任务执行完成",
        AnalysisStatus::Partial => "任务部分完成",
        AnalysisStatus::Failed => "任务执行失败",
    };
    let stream = result.stream.as_ref();
    let dimensions = stream
        .and_then(|value| Some(format!("{} × {}", value.width?, value.height?)))
        .unwrap_or_else(|| "未知".into());
    let codec = stream
        .and_then(|value| value.codec.as_deref())
        .or_else(|| result.audio.as_ref().map(|audio| audio.codec.as_str()))
        .unwrap_or("未知");
    let frame_rate = stream
        .and_then(|value| value.frame_rate.as_deref())
        .unwrap_or("未知");
    let frame_rate_sources = stream
        .map(|stream| {
            format!(
                "<dl><dt>SPS 声明</dt><dd>{}</dd><dt>ffprobe 探测</dt><dd>{}</dd><dt>抓包观测</dt><dd>{}</dd><dt>一致性</dt><dd class=\"{}\">{}</dd></dl>",
                escape_html(stream.sps_frame_rate.as_deref().unwrap_or("—")),
                escape_html(stream.probed_frame_rate.as_deref().unwrap_or("—")),
                escape_html(stream.observed_frame_rate.as_deref().unwrap_or("—")),
                if stream.frame_rate_conflict { "bad" } else { "good" },
                if stream.frame_rate_conflict {
                    "来源偏差超过 5% 或 0.5 fps，不能用单一帧率判断卡顿"
                } else {
                    "现有来源未发现显著冲突"
                }
            )
        })
        .unwrap_or_default();
    let decode_text = result
        .decode
        .as_ref()
        .map(|decode| {
            if !decode.success {
                "执行失败".into()
            } else if decode.issues.is_empty() {
                "执行完成，未发现已知解码错误".into()
            } else {
                format!("执行完成，发现 {} 类解码异常", decode.issues.len())
            }
        })
        .unwrap_or_else(|| "未执行".into());
    let source_label = match result.request.source_kind {
        SourceKind::Rtsp => "RTSP 地址",
        SourceKind::H264 => "H.264 文件",
        SourceKind::H265 => "H.265 文件",
        SourceKind::Audio => "音频文件",
        SourceKind::Pcap => "抓包文件",
    };
    let mut health_score = result.diagnostics.iter().fold(100_i32, |score, finding| {
        score
            - match finding.severity {
                DiagnosticSeverity::Critical => 25,
                DiagnosticSeverity::High => 15,
                DiagnosticSeverity::Medium => 7,
                DiagnosticSeverity::Low => 2,
                DiagnosticSeverity::Info => 0,
            }
    });
    if result.decode.as_ref().is_some_and(|decode| !decode.success) {
        health_score -= 15;
    }
    health_score = health_score.max(0);
    let tool_versions = result
        .tools
        .iter()
        .map(|tool| {
            format!(
                "<li><strong>{}</strong>：{}</li>",
                escape_html(&tool.name),
                escape_html(tool.version.as_deref().unwrap_or(if tool.available {
                    "可用"
                } else {
                    "不可用"
                }))
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let final_rtsp_status = |method: &str| {
        result.protocol.as_ref().and_then(|protocol| {
            protocol
                .transactions
                .iter()
                .rev()
                .find(|transaction| transaction.method == method)
                .map(|transaction| transaction.status_code)
        })
    };
    let setup_ok = final_rtsp_status("SETUP").is_some_and(|status| status < 300);
    let play_ok = final_rtsp_status("PLAY").is_some_and(|status| status < 300);
    let rtp_packets = result
        .protocol
        .as_ref()
        .map_or(0, |protocol| protocol.rtp.packet_count);
    let decode_detail = result
        .decode
        .as_ref()
        .map(|decode| {
            if decode.success {
                format!(
                    "执行完成{}{}",
                    decode
                        .decoded_frames
                        .map(|frames| format!("，解码 {frames} 帧"))
                        .unwrap_or_default(),
                    if decode.issues.is_empty() {
                        "，未发现已知解码错误".into()
                    } else {
                        format!("，发现 {} 类解码异常", decode.issues.len())
                    }
                )
            } else {
                let first_line = decode.log.lines().next().unwrap_or("未提供失败信息");
                format!("失败：{}", escape_html(first_line))
            }
        })
        .unwrap_or_else(|| "未执行".into());
    let h264_summary = result
        .h264
        .as_ref()
        .map(|h264| {
            let resolution = h264
                .sps
                .first()
                .map(|sps| format!("{}×{}", sps.width, sps.height))
                .unwrap_or_else(|| "分辨率未知".into());
            format!(
                "{}，{} 帧 / {} 个 IDR，结构异常 {} 项",
                resolution,
                h264.frame_count,
                h264.idr_frames,
                h264.issues.len()
            )
        })
        .or_else(|| {
            result.h265.as_ref().map(|h265| {
                let resolution = h265
                    .sps
                    .first()
                    .map(|sps| format!("{}×{}", sps.width, sps.height))
                    .unwrap_or_else(|| "分辨率未知".into());
                format!(
                    "H.265 {}，{} 帧 / {} 个 IDR / {} 个 CRA，结构异常 {} 项",
                    resolution,
                    h265.frame_count,
                    h265.idr_frames,
                    h265.cra_frames,
                    h265.issues.len()
                )
            })
        })
        .or_else(|| {
            result.audio.as_ref().map(|audio| {
                format!(
                    "{}，{} 个 RTP 包 / {} 个解码采样 / {} 项音频证据",
                    audio.codec,
                    audio.packet_count,
                    audio.decoded_samples,
                    audio.issues.len()
                )
            })
        })
        .unwrap_or_else(|| "未取得可解析的音视频结构数据".into());
    let quality_reasons = if result.data_quality.reasons.is_empty() {
        "<li>采样时长、数据量与采集完整性满足当前诊断门槛。</li>".into()
    } else {
        result
            .data_quality
            .reasons
            .iter()
            .map(|reason| format!("<li>{}</li>", escape_html(reason)))
            .collect::<Vec<_>>()
            .join("")
    };
    let quality_limitations = result
        .data_quality
        .limitations
        .iter()
        .map(|reason| {
            format!(
                "<li><strong>适用边界：</strong>{}</li>",
                escape_html(reason)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let codec_label = if result.h265.is_some() {
        "H.265"
    } else if result.h264.is_some() {
        "H.264"
    } else if result.audio.is_some() {
        "音频"
    } else {
        "媒体"
    };
    let sample_file = if result.h265.is_some() {
        "sample.h265"
    } else if result.h264.is_some() {
        "sample.h264"
    } else if result.audio.is_some() {
        "preview.wav"
    } else {
        "媒体样本"
    };
    let data_quality_html = if result.request.source_kind == SourceKind::Audio {
        let audio = result.audio.as_ref();
        format!(
            "<section><h2>数据可信度</h2><p><strong class=\"{}\">{}</strong></p><dl><dt>解码 PCM 时长</dt><dd>{}</dd><dt>解码采样</dt><dd>{}</dd><dt>样本截断</dt><dd>否</dd></dl><ul>{}{}</ul></section>",
            if result.data_quality.sufficient_for_diagnosis {
                "good"
            } else {
                "bad"
            },
            if result.data_quality.sufficient_for_diagnosis {
                "满足声音质量判断条件"
            } else {
                "证据条件受限，仅输出提示性结论"
            },
            format_duration(audio.and_then(|value| value.decoded_duration_ms)),
            audio.map_or(0, |value| value.decoded_samples),
            quality_reasons,
            quality_limitations,
        )
    } else if result.data_quality.assessed {
        format!(
            "<section><h2>数据可信度</h2><p><strong class=\"{}\">{}</strong></p><p>RTP 包、NALU 和视频帧是不同层级的计量单位，不能要求数值相等。这里的 FFmpeg 不再重新连接 RTSP，而是解码同次 RTP 采样重组出的 {sample_file}，因此可以比较 {codec_label} 解析帧与解码帧。</p><dl><dt>RTP / 目标负载包</dt><dd>{} / {}</dd><dt>负载字节</dt><dd>{}</dd><dt>重组 NALU</dt><dd>{}</dd><dt>解析帧 / 解码帧</dt><dd>{} / {}</dd><dt>采集截断</dt><dd>{}</dd></dl><ul>{}{}</ul></section>",
            if result.data_quality.sufficient_for_diagnosis {
                "good"
            } else {
                "bad"
            },
            if result.data_quality.sufficient_for_diagnosis {
                "满足诊断条件"
            } else {
                "证据条件受限，仅输出提示性结论"
            },
            result.data_quality.captured_rtp_packets,
            result.data_quality.captured_payload_packets,
            result.data_quality.captured_payload_bytes,
            result.data_quality.reassembled_nalus,
            result.data_quality.parsed_frames,
            result
                .data_quality
                .decoded_frames
                .map(|value| value.to_string())
                .unwrap_or_else(|| "—".into()),
            if result.data_quality.capture_truncated {
                "是"
            } else {
                "否"
            },
            quality_reasons,
            quality_limitations
        )
    } else {
        "<section><h2>数据可信度</h2><p>旧版或离线报告未执行统一实时采样可信度评估。</p></section>"
            .into()
    };
    let timing_html = format!(
        "<section><h2>分析范围与处理耗时</h2><dl><dt>媒体数据覆盖范围</dt><dd>{}</dd><dt>抓包文件读取耗时</dt><dd>{}</dd><dt>RTSP 会话总耗时</dt><dd>{}</dd><dt>H.264 重组与解析耗时</dt><dd>{}</dd><dt>H.265 重组与解析耗时</dt><dd>{}</dd><dt>ffprobe 同源探测耗时</dt><dd>{}</dd><dt>FFmpeg 同源解码耗时</dt><dd>{}</dd></dl></section>",
        format_duration(
            result
                .module_timings
                .media_sample_coverage_ms
                .or(result.module_timings.rtp_capture_ms)
        ),
        format_duration(result.module_timings.capture_read_ms),
        format_duration(result.module_timings.rtsp_session_ms),
        format_duration(result.module_timings.h264_analysis_ms),
        format_duration(result.module_timings.h265_analysis_ms),
        format_duration(result.module_timings.ffprobe_ms),
        format_duration(result.module_timings.ffmpeg_decode_ms),
    );
    let summary_html = if result.request.source_kind == SourceKind::Pcap {
        format!(
            "<section class=\"executive\"><h2>本流分析</h2><p>观测到 {rtp_packets} 个 RTP 包；{}。</p><p>{codec_label}：{}。FFmpeg：{}。</p><p>抓包未包含 RTSP 事务不代表 SETUP 或 PLAY 失败。序列缺口只能证明抓包中缺少对应 RTP 包，需结合捕获完整性确认原因。</p></section>",
            result
                .protocol
                .as_ref()
                .and_then(|protocol| protocol.sample_duration_ms)
                .map(|duration| format!("本流覆盖 {:.2} 秒", duration as f64 / 1_000.0))
                .unwrap_or_else(|| "本流覆盖时长未知".into()),
            escape_html(&h264_summary),
            decode_detail,
        )
    } else if result.request.source_kind == SourceKind::Audio {
        let audio = result.audio.as_ref();
        format!(
            "<section class=\"executive\"><h2>一页结论</h2><div class=\"summary-grid\"><div><span>音频解码</span><strong class=\"{}\">{}</strong><small>软件内试听样本</small></div><div><span>有效时长</span><strong>{}</strong><small>{} 个 PCM 采样</small></div><div><span>峰值 / RMS</span><strong>{} / {} dBFS</strong><small>基于解码 PCM</small></div><div><span>诊断结论</span><strong>{} 项</strong><small>静音、削波与可信度门槛</small></div></div></section>",
            if result.preview_audio.is_some() {
                "good"
            } else {
                "bad"
            },
            if result.preview_audio.is_some() {
                "成功"
            } else {
                "失败"
            },
            format_duration(audio.and_then(|value| value.decoded_duration_ms)),
            audio.map_or(0, |value| value.decoded_samples),
            audio
                .and_then(|value| value.peak_level_dbfs_milli)
                .map(|value| format!("{:.1}", value as f64 / 1000.0))
                .unwrap_or_else(|| "—".into()),
            audio
                .and_then(|value| value.rms_level_dbfs_milli)
                .map(|value| format!("{:.1}", value as f64 / 1000.0))
                .unwrap_or_else(|| "—".into()),
            result.diagnostics.len(),
        )
    } else {
        format!(
            "<section class=\"executive\"><h2>一页结论</h2><div class=\"summary-grid\"><div><span>RTSP 连接</span><strong class=\"{}\">{}</strong><small>最终 SETUP={}，PLAY={}</small></div><div><span>媒体接收</span><strong class=\"{}\">{} 个 RTP 包</strong><small>{}</small></div><div><span>{codec_label} 结构</span><strong>{}</strong><small>参数集、帧和 GOP 来自实际 RTP 负载</small></div><div><span>FFmpeg 实解</span><strong class=\"{}\">{}</strong><small>失败不等同于 RTSP SETUP 失败</small></div></div></section>",
            if setup_ok && play_ok { "good" } else { "bad" },
            if setup_ok && play_ok {
                "控制面成功"
            } else {
                "控制面未完成"
            },
            final_rtsp_status("SETUP")
                .map(|status| status.to_string())
                .unwrap_or_else(|| "未执行".into()),
            final_rtsp_status("PLAY")
                .map(|status| status.to_string())
                .unwrap_or_else(|| "未执行".into()),
            if rtp_packets > 0 { "good" } else { "bad" },
            rtp_packets,
            result
                .protocol
                .as_ref()
                .and_then(|protocol| protocol.sample_duration_ms)
                .map(|duration| format!("协议采样 {:.2} 秒", duration as f64 / 1000.0))
                .unwrap_or_else(|| "采样时长未知".into()),
            escape_html(&h264_summary),
            if result.decode.as_ref().is_some_and(|decode| decode.success) {
                "good"
            } else {
                "bad"
            },
            decode_detail,
        )
    };
    let protocol_html = result
        .protocol
        .as_ref()
        .map(|protocol| {
            let transactions = protocol
                .transactions
                .iter()
                .enumerate()
                .map(|(index, transaction)| {
                    let challenge = transaction.status_code == 401
                        && protocol.transactions[index + 1..].iter().any(|later| {
                            later.method == transaction.method && later.status_code < 300
                        });
                    format!(
                        "<tr><td>{}</td><td>{} {}{}</td><td>{}</td><td>{} ms</td><td><code>{}</code></td></tr>",
                        escape_html(&transaction.method),
                        transaction.status_code,
                        escape_html(&transaction.reason),
                        if challenge { " <small>鉴权挑战，随后成功</small>" } else { "" },
                        transaction.cseq.map(|value| value.to_string()).unwrap_or_else(|| "—".into()),
                        transaction.elapsed_ms,
                        escape_html(&transaction.uri)
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            let media = protocol.media.iter().map(|track| format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
                escape_html(&track.media_type), escape_html(track.codec.as_deref().unwrap_or("未知")),
                track.payload_types.iter().map(u8::to_string).collect::<Vec<_>>().join(", "),
                track.clock_rate.map(|value| format!("{value} Hz")).unwrap_or_else(|| "—".into()),
                escape_html(track.resolved_control.as_deref().or(track.control.as_deref()).unwrap_or("—"))
            )).collect::<Vec<_>>().join("\n");
            let clock_rate = result.capture_stream.as_ref().and_then(|identity| identity.clock_rate)
                .or_else(|| protocol.media.iter().find(|track| track.media_type == "video").and_then(|track| track.clock_rate))
                .or_else(|| (result.request.source_kind != SourceKind::Pcap).then_some(90_000));
            let jitter = clock_rate.filter(|rate| *rate > 0)
                .map(|rate| format!("{:.2} ms（{:.2} timestamp units）", protocol.rtp.jitter * 1_000.0 / f64::from(rate), protocol.rtp.jitter))
                .unwrap_or_else(|| format!("{:.2} timestamp units（时钟频率未知）", protocol.rtp.jitter));
            let expected = protocol.rtp.packet_count + protocol.rtp.lost_packets;
            let loss_rate = if expected == 0 { 0.0 } else { protocol.rtp.lost_packets as f64 * 100.0 / expected as f64 };
            format!(
                "<section><h2>RTSP / RTP 协议探测</h2><dl><dt>服务端</dt><dd>{}</dd><dt>Session</dt><dd>{}</dd><dt>传输模式</dt><dd>{}</dd><dt>SETUP Transport 响应</dt><dd><code>{}</code></dd><dt>鉴权</dt><dd>{}</dd><dt>最终 SETUP / PLAY</dt><dd>{} / {}</dd><dt>RTP 包</dt><dd>{}（协议采样 {}）</dd><dt>平均 / 峰值码率</dt><dd>{} / {}（{} ms 窗口）</dd><dt>{}</dt><dd>{}（{:.3}%）</dd><dt>最大连续缺口</dt><dd>{}</dd><dt>乱序 / 重复</dt><dd>{} / {}</dd><dt>Jitter</dt><dd>{}</dd><dt>RTCP 包</dt><dd>{}</dd></dl><h3>RTSP 事务</h3><table><thead><tr><th>方法</th><th>状态</th><th>CSeq</th><th>耗时</th><th>URI</th></tr></thead><tbody>{transactions}</tbody></table><h3>SDP 媒体轨道</h3><table><thead><tr><th>类型</th><th>编码</th><th>PT</th><th>时钟</th><th>Control URI</th></tr></thead><tbody>{media}</tbody></table></section>",
                escape_html(protocol.server.as_deref().unwrap_or("未声明")),
                escape_html(protocol.session_id.as_deref().unwrap_or("未知")),
                match result.request.transport {
                    Some(streamscope_core::Transport::Tcp) => format!("TCP Interleaved（RTP/RTCP 通道 {}-{}）", protocol.interleaved_rtp_channel.map(|value| value.to_string()).unwrap_or_else(|| "—".into()), protocol.interleaved_rtcp_channel.map(|value| value.to_string()).unwrap_or_else(|| "—".into())),
                    Some(streamscope_core::Transport::Udp) => "UDP（独立 RTP/RTCP 端口）".into(),
                    None => "未知".into(),
                },
                escape_html(protocol.negotiated_transport.as_deref().unwrap_or("服务端未返回 Transport 头")),
                if protocol.authenticated { "已完成" } else if result.request.source_kind == SourceKind::Pcap { "未取得鉴权证据" } else { "无需鉴权" },
                final_rtsp_status("SETUP").map(|value| value.to_string()).unwrap_or_else(|| "—".into()),
                final_rtsp_status("PLAY").map(|value| value.to_string()).unwrap_or_else(|| "—".into()),
                protocol.rtp.packet_count,
                protocol.sample_duration_ms.map(|value| format!("{:.2} 秒", value as f64 / 1000.0)).unwrap_or_else(|| "未知时长".into()),
                format_bit_rate(protocol.rtp.average_bit_rate_bps),
                format_bit_rate(protocol.rtp.peak_bit_rate_bps),
                protocol.rtp.bit_rate_window_ms.unwrap_or(1_000),
                if result.request.source_kind == SourceKind::Pcap { "观测序列缺口" } else { "估算丢包" },
                protocol.rtp.lost_packets,
                loss_rate,
                protocol.rtp.maximum_sequence_gap,
                protocol.rtp.out_of_order_packets,
                protocol.rtp.duplicate_packets,
                jitter,
                format_args!("{}{}", protocol.rtcp_packet_count, if result.request.source_kind == SourceKind::Pcap { "（仅可唯一关联的 Sender Report，不代表全部 RTCP）" } else { "" }),
            )
        })
        .unwrap_or_else(|| "<section><h2>RTSP / RTP 协议探测</h2><p>未取得自研协议探测数据。</p></section>".into());
    let h264_html = result
        .h264
        .as_ref()
        .map(|h264| {
            let mapped_nalus = h264
                .nalus
                .iter()
                .filter(|nalu| !nalu.packets.is_empty())
                .count();
            let dimensions = h264
                .sps
                .first()
                .map(|sps| format!("{} × {}", sps.width, sps.height))
                .unwrap_or_else(|| "未知".into());
            let issues = h264
                .issues
                .iter()
                .map(|issue| {
                    format!(
                        "<li><strong>{}</strong>：{}</li>",
                        escape_html(&issue.kind),
                        escape_html(&issue.detail)
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            let parameter_changes = h264
                .parameter_changes
                .iter()
                .map(|change| {
                    format!(
                        "<li><strong>{} #{}</strong>：NALU #{}，从 AU #{} 生效；变化字段 {}</li>",
                        escape_html(&change.parameter_kind.to_uppercase()),
                        change.parameter_id,
                        change.nalu_number,
                        change
                            .effective_access_unit
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "未知".into()),
                        escape_html(&change.changed_fields.join("、")),
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            let hrd = &h264.hrd_simulation;
            let hrd_rows = hrd
                .points
                .iter()
                .take(100)
                .map(|point| {
                    format!(
                        "<tr><td>#{}</td><td>NALU #{}</td><td>{}</td><td>{} / {}</td><td>{} / {}</td><td>{}</td></tr>",
                        point.access_unit,
                        point.sei_nalu,
                        point.access_unit_bits,
                        point.cpb_removal_delay,
                        point.dpb_output_delay,
                        point.fullness_before_removal_bits,
                        point.fullness_after_removal_bits,
                        if point.overflow {
                            "CPB 溢出"
                        } else if point.underflow {
                            "CPB 下溢"
                        } else {
                            "正常"
                        },
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let hrd_limitations = hrd
                .limitations
                .iter()
                .map(|item| format!("<li>{}</li>", escape_html(item)))
                .collect::<Vec<_>>()
                .join("");
            let hrd_html = format!(
                "<h3>HRD / CPB 逐 AU 仿真</h3><dl><dt>状态</dt><dd>{}</dd><dt>Schedule / SPS</dt><dd>{} / {}</dd><dt>Buffering Period / Picture Timing</dt><dd>{} / {}</dd><dt>已仿真 AU</dt><dd>{}</dd><dt>最小 / 最大 fullness</dt><dd>{} / {} bits</dd><dt>溢出 / 下溢 / delay 不连续</dt><dd>{} / {} / {}</dd></dl><p>AU 大小按保留的 NALU 字节计算，不包含 RTP、容器及网络传输开销；证据不完整时不输出确定性 CPB 结论。</p><ul>{}</ul>{}",
                match hrd.status.as_str() {
                    "simulated_cbr_single_cpb" => "已完成单 CPB / CBR 仿真",
                    "not_declared" => "SPS 未声明 HRD",
                    _ => "证据不足",
                },
                escape_html(&hrd.schedule.to_uppercase()),
                hrd.sps_id
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "—".into()),
                hrd.buffering_period_count,
                hrd.pic_timing_count,
                hrd.simulated_aus,
                hrd.minimum_fullness_bits
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "—".into()),
                hrd.maximum_fullness_bits
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "—".into()),
                hrd.overflow_aus.len(),
                hrd.underflow_aus.len(),
                hrd.delay_discontinuities.len(),
                if hrd_limitations.is_empty() {
                    "<li>无额外限制</li>"
                } else {
                    &hrd_limitations
                },
                if hrd_rows.is_empty() {
                    String::new()
                } else {
                    format!("<table><thead><tr><th>AU</th><th>SEI</th><th>AU bits</th><th>Removal / Output delay</th><th>移除前 / 后 fullness</th><th>状态</th></tr></thead><tbody>{hrd_rows}</tbody></table>")
                },
            );
            format!(
                "<section><h2>H.264 码流分析</h2><dl><dt>NALU</dt><dd>{}（完整 {} / 不完整 {}）</dd><dt>RTP→NALU 精确映射</dt><dd>{} / {} 个已保留 NALU</dd><dt>帧 / IDR</dt><dd>{} / {}</dd><dt>SPS 分辨率</dt><dd>{}</dd><dt>平均 / 最大 GOP</dt><dd>{} / {}</dd></dl>{}<h3>参数集变更</h3><ul>{}</ul><h3>结构异常</h3><ul>{}</ul></section>",
                h264.nalu_count,
                h264.complete_nalus,
                h264.incomplete_nalus,
                mapped_nalus,
                h264.nalus.len(),
                h264.frame_count,
                h264.idr_frames,
                escape_html(&dimensions),
                h264.average_gop_frames.map(|value| value.to_string()).unwrap_or_else(|| "—".into()),
                h264.maximum_gop_frames.map(|value| value.to_string()).unwrap_or_else(|| "—".into()),
                hrd_html,
                if parameter_changes.is_empty() { "<li>保留样本中未发现同一参数集 ID 的字段变化</li>" } else { &parameter_changes },
                if issues.is_empty() { "<li>未发现 H.264 结构异常</li>" } else { &issues }
            )
        })
        .unwrap_or_default();
    let h265_html = result
        .h265
        .as_ref()
        .map(|h265| {
            let mapped_nalus = h265
                .nalus
                .iter()
                .filter(|nalu| !nalu.packets.is_empty())
                .count();
            let dimensions = h265
                .sps
                .first()
                .map(|sps| format!("{} × {}", sps.width, sps.height))
                .unwrap_or_else(|| "未知".into());
            let issues = h265
                .issues
                .iter()
                .map(|issue| format!("<li><strong>{}</strong>：{}</li>", escape_html(&issue.kind), escape_html(&issue.detail)))
                .collect::<Vec<_>>()
                .join("\n");
            let parameter_changes = h265
                .parameter_changes
                .iter()
                .map(|change| {
                    format!(
                        "<li><strong>{} #{}</strong>：NALU #{}，从 AU #{} 生效；变化字段 {}</li>",
                        escape_html(&change.parameter_kind.to_uppercase()),
                        change.parameter_id,
                        change.nalu_number,
                        change
                            .effective_access_unit
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "未知".into()),
                        escape_html(&change.changed_fields.join("、")),
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            format!(
                "<section><h2>H.265 / HEVC 码流分析</h2><dl><dt>NALU</dt><dd>{}（完整 {} / 不完整 {}）</dd><dt>RTP→NALU 精确映射</dt><dd>{} / {} 个已保留 NALU</dd><dt>帧 / IRAP</dt><dd>{} / {}</dd><dt>IDR / CRA</dt><dd>{} / {}</dd><dt>VPS / SPS / PPS</dt><dd>{} / {} / {}</dd><dt>SPS 分辨率</dt><dd>{}</dd><dt>平均 / 最大 GOP</dt><dd>{} / {}</dd></dl><h3>参数集变更</h3><ul>{}</ul><h3>结构异常</h3><ul>{}</ul></section>",
                h265.nalu_count,
                h265.complete_nalus,
                h265.incomplete_nalus,
                mapped_nalus,
                h265.nalus.len(),
                h265.frame_count,
                h265.irap_frames,
                h265.idr_frames,
                h265.cra_frames,
                h265.vps_count,
                h265.sps.len(),
                h265.pps.len(),
                escape_html(&dimensions),
                h265.average_gop_frames.map(|value| value.to_string()).unwrap_or_else(|| "—".into()),
                h265.maximum_gop_frames.map(|value| value.to_string()).unwrap_or_else(|| "—".into()),
                if parameter_changes.is_empty() { "<li>保留样本中未发现同一参数集 ID 的字段变化</li>" } else { &parameter_changes },
                if issues.is_empty() { "<li>未发现 H.265 结构异常</li>" } else { &issues }
            )
        })
        .unwrap_or_else(|| {
            if result.h264.is_none() {
                "<section><h2>视频码流分析</h2><p>未取得可分析的 H.264/H.265 RTP 负载。</p></section>".into()
            } else {
                String::new()
            }
        });
    let recovery_windows = result
        .h264
        .as_ref()
        .map(|analysis| analysis.recovery_windows.as_slice())
        .or_else(|| {
            result
                .h265
                .as_ref()
                .map(|analysis| analysis.recovery_windows.as_slice())
        })
        .unwrap_or_default();
    let recovery_windows_html = if recovery_windows.is_empty() {
        String::new()
    } else {
        let rows = recovery_windows
            .iter()
            .take(200)
            .map(|window| {
                format!(
                    "<tr><td>#{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    window.source_frame,
                    escape_html(&window.source_kind),
                    window
                        .next_random_access_frame
                        .map(|value| format!("#{value}"))
                        .unwrap_or_else(|| "未观察到".into()),
                    window
                        .wait_frames
                        .map(|value| format!("{value} 帧"))
                        .unwrap_or_else(|| "不可计算".into()),
                    window
                        .wait_ms
                        .map(|value| format!("{value} ms"))
                        .unwrap_or_else(|| "不可计算".into()),
                    if window.visual_status == "post_access_anomaly_candidate" {
                        "随机接入后仍有画面异常候选"
                    } else {
                        "未确认画面恢复"
                    },
                )
            })
            .collect::<Vec<_>>()
            .join("");
        format!(
            "<section><h2>传播与恢复窗口</h2><p>IDR/CRA 仅表示结构恢复机会；没有参考真值时不将其写成画面已恢复。</p><table><thead><tr><th>异常起点</th><th>证据类型</th><th>下一随机接入</th><th>等待帧数</th><th>等待时间</th><th>画面状态</th></tr></thead><tbody>{rows}</tbody></table></section>"
        )
    };
    let video_deep_html = result
        .h264
        .as_ref()
        .and_then(|analysis| analysis.deep_analysis.as_ref())
        .or_else(|| {
            result
                .h265
                .as_ref()
                .and_then(|analysis| analysis.deep_analysis.as_ref())
        })
        .map(|analysis| {
            let capabilities = analysis
                .capabilities
                .iter()
                .map(|capability| {
                    format!(
                        "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                        escape_html(&capability.label),
                        match capability.status.as_str() {
                            "available" => "可用",
                            "on_demand" => "按帧加载",
                            _ => "尚不可用",
                        },
                        escape_html(capability.reason.as_deref().unwrap_or("—")),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let frames = analysis
                .frames
                .iter()
                .take(200)
                .map(|frame| {
                    format!(
                        "<tr><td>#{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{} / {} B</td></tr>",
                        frame.display_index,
                        frame.decode_index.map(|value| value.to_string()).unwrap_or_else(|| "—".into()),
                        escape_html(frame.picture_type.as_deref().unwrap_or("—")),
                        frame.pts_ms.map(|value| format!("{value} ms")).unwrap_or_else(|| "—".into()),
                        frame.dts_ms.map(|value| format!("{value} ms")).unwrap_or_else(|| "—".into()),
                        frame.packet_position.map(|value| value.to_string()).unwrap_or_else(|| "—".into()),
                        frame.packet_size.map(|value| value.to_string()).unwrap_or_else(|| "—".into()),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            let limitations = analysis
                .limitations
                .iter()
                .map(|item| format!("<li>{}</li>", escape_html(item)))
                .collect::<Vec<_>>()
                .join("");
            format!(
                "<section><h2>视频深度分析</h2><dl><dt>编码</dt><dd>{}</dd><dt>已索引帧</dt><dd>{}</dd><dt>覆盖状态</dt><dd>{}</dd></dl><h3>能力声明</h3><table><thead><tr><th>能力</th><th>状态</th><th>说明</th></tr></thead><tbody>{}</tbody></table><h3>逐帧索引（前 200 帧）</h3><table><thead><tr><th>显示序号</th><th>编码序号</th><th>帧型</th><th>PTS</th><th>DTS</th><th>位置 / 大小</th></tr></thead><tbody>{}</tbody></table><ul>{}</ul></section>",
                escape_html(&analysis.codec),
                analysis.indexed_frames,
                if analysis.coverage_complete { "完整" } else { "受限" },
                capabilities,
                frames,
                limitations,
            )
        })
        .unwrap_or_default();
    let issues = result
        .decode
        .as_ref()
        .map(|decode| {
            decode
                .issues
                .iter()
                .map(|issue| {
                    let locations = if issue.locations.is_empty() {
                        "时间未定位".into()
                    } else {
                        format!(
                            "候选帧 {}（日志邻近关联）",
                            issue
                                .locations
                                .iter()
                                .map(|location| format!("#{}", location.frame_number))
                                .collect::<Vec<_>>()
                                .join("、")
                        )
                    };
                    format!(
                        "<li><strong>{}</strong>：{} 次 · {}<br><code>{}</code></li>",
                        escape_html(&issue.kind),
                        issue.count,
                        escape_html(&locations),
                        escape_html(&issue.example)
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .filter(|html| !html.is_empty())
        .unwrap_or_else(|| {
            if result.decode.is_some() {
                "<li>未发现已知 FFmpeg 解码错误</li>".into()
            } else {
                "<li>未执行 FFmpeg 解码，无法评价解码结果。</li>".into()
            }
        });
    let diagnostics = if result.diagnostics.is_empty() {
        "<p>当前证据没有触发诊断规则。</p>".into()
    } else {
        result
            .diagnostics
            .iter()
            .map(|finding| {
                let evidence = finding
                    .evidence
                    .iter()
                    .map(|item| format!("<li>{}：{}</li>", escape_html(&item.label), escape_html(&item.value)))
                    .collect::<Vec<_>>()
                    .join("");
                let suggestions = finding.suggestions.iter().map(|item| format!("<li>{}</li>", escape_html(item))).collect::<Vec<_>>().join("");
                let verification = finding.verification.iter().map(|item| format!("<li>{}</li>", escape_html(item))).collect::<Vec<_>>().join("");
                format!("<article class=\"finding\"><div><span class=\"severity {:?}\">{:?}</span><code>{}</code><strong>{}</strong><small>置信度 {}%</small></div><p>{}</p><h4>证据</h4><ul>{}</ul><h4>影响</h4><p>{}</p><h4>建议</h4><ul>{}</ul><h4>复验</h4><ul>{}</ul></article>", finding.severity, finding.severity, escape_html(&finding.rule_id), escape_html(&finding.title), finding.confidence_percent, escape_html(&finding.conclusion), evidence, escape_html(&finding.impact), suggestions, verification)
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let timeline = if result.timeline.is_empty() {
        "<li>没有可展示的时间线事件。</li>".into()
    } else {
        result
            .timeline
            .iter()
            .map(|event| {
                let location = if event.frame_number.is_some()
                    || event.first_packet.is_some()
                    || event.sequence.is_some()
                {
                    format!(
                        "<small>帧 {} · 包 {} · Seq {} · RTP TS {} · {}</small>",
                        event
                            .frame_number
                            .map(|value| format!("#{value}"))
                            .unwrap_or_else(|| "—".into()),
                        event
                            .first_packet
                            .map(|first| event
                                .last_packet
                                .filter(|last| *last != first)
                                .map(|last| format!("#{first}–#{last}"))
                                .unwrap_or_else(|| format!("#{first}")))
                            .unwrap_or_else(|| "—".into()),
                        event
                            .sequence
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "—".into()),
                        event
                            .rtp_timestamp
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "—".into()),
                        escape_html(event.location_precision.as_deref().unwrap_or("位置未知"))
                    )
                } else {
                    String::new()
                };
                format!(
                    "<li><time>{}</time><strong>{} · {}</strong><span>{}{}</span></li>",
                    event
                        .offset_ms
                        .map(|value| format!("+{value} ms"))
                        .unwrap_or_else(|| "时序未知".into()),
                    escape_html(&event.source),
                    escape_html(&event.event_type),
                    escape_html(&event.detail),
                    location
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let errors = if result.errors.is_empty() {
        "<li>无</li>".into()
    } else {
        result
            .errors
            .iter()
            .map(|error| format!("<li>{}</li>", escape_html(error)))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let visual_scan_html = result.decode.as_ref().map_or_else(
        || "<p>未执行画面级异常扫描。</p>".into(),
        |decode| {
            let scan = &decode.visual_scan;
            if scan.completed {
                format!(
                    "<p><strong>画面抽样：</strong>{} 帧，{} fps，{}×{}；疑似局部花屏/彩色破碎 {} 帧。</p><p>{}</p>",
                    scan.sampled_frames,
                    scan.sampled_fps,
                    scan.scan_width,
                    scan.scan_height,
                    scan.candidate_frames,
                    escape_html(scan.note.as_deref().unwrap_or("启发式候选需结合回放确认")),
                )
            } else if scan.attempted {
                format!(
                    "<p><strong>画面抽样未完成：</strong>{}</p>",
                    escape_html(scan.note.as_deref().unwrap_or("未提供原因")),
                )
            } else {
                "<p>该结果未执行画面级异常扫描。</p>".into()
            }
        },
    );
    let capture_identity_html = render_capture_identity(result);
    let audio_html = if result.audio_tracks.is_empty() {
        result.audio.as_ref().map_or_else(String::new, |audio| {
            render_audio_analysis(audio, "音频分析", None)
        })
    } else {
        result
            .audio_tracks
            .iter()
            .map(|track| {
                let heading = format!("音频分析 · {}", track.id);
                let detail = format!(
                    "轨道索引 {} · Payload Type {} · RTP 时钟 {} Hz · {} 声道",
                    track.track_index,
                    track.payload_type,
                    track.clock_rate,
                    track.channels.unwrap_or(1)
                );
                render_audio_analysis(&track.analysis, &heading, Some(&detail))
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let sync_html = if result.av_sync.is_empty() {
        String::new()
    } else {
        let rows = result
            .av_sync
            .iter()
            .map(|sync| {
                let content = sync.content_offset_ms.map_or_else(
                    || "未形成内容事件配对".into(),
                    |value| {
                        format!(
                            "{value} ms；{} 组；置信度 {}%；误差 ±{} ms",
                            sync.content_events.len(),
                            sync.content_confidence_percent.unwrap_or(0),
                            sync.content_measurement_error_ms.unwrap_or(0)
                        )
                    },
                );
                format!(
                    "<tr><td>{} ↔ {}</td><td>{}</td><td>{}</td><td>{}</td><td>{}%</td><td>{}</td></tr>",
                    escape_html(sync.audio_stream_id.as_deref().unwrap_or("未知音频")),
                    escape_html(sync.video_stream_id.as_deref().unwrap_or("未知视频")),
                    escape_html(&sync.status),
                    sync.offset_ms
                        .map(|value| format!("{value} ms"))
                        .unwrap_or_else(|| "—".into()),
                    escape_html(&content),
                    sync.confidence_percent,
                    escape_html(&sync.reasons.join("；")),
                )
            })
            .collect::<Vec<_>>()
            .join("");
        format!(
            "<section><h2>音画同步：时钟与内容证据</h2><table><thead><tr><th>配对</th><th>状态</th><th>时钟偏移</th><th>闪光/蜂鸣内容偏移</th><th>时钟置信度</th><th>证据边界</th></tr></thead><tbody>{rows}</tbody></table><p>时钟偏移来自 RTCP；内容偏移仅在检测到可配对的明显闪光和蜂鸣/脉冲时输出。</p></section>"
        )
    };
    let media_info_html = if result.request.source_kind == SourceKind::Audio {
        String::new()
    } else {
        format!(
            "<section><h2>媒体信息</h2><dl><dt>编码</dt><dd>{}</dd><dt>分辨率</dt><dd>{}</dd><dt>优先帧率</dt><dd>{}</dd><dt>视频实际解码</dt><dd>{}</dd></dl><h3>视频帧率证据来源</h3>{}</section>",
            escape_html(codec),
            escape_html(&dimensions),
            escape_html(frame_rate),
            decode_text,
            frame_rate_sources,
        )
    };
    let ffmpeg_evidence_html = if result.request.source_kind == SourceKind::Audio {
        String::new()
    } else {
        format!(
            "<section><h2>FFmpeg 解码与画面证据</h2>{visual_scan_html}<ul>{issues}</ul><p>黑屏、冻结与局部破碎均由阈值或启发式检测得到，只表示候选区间；请结合软件内同源样本回放确认，不据此单独认定根因。</p></section>"
        )
    };
    let health_text = if result.request.source_kind == SourceKind::Pcap
        && (!result.data_quality.sufficient_for_diagnosis || result.capture_stream.is_none())
    {
        "证据不足，暂不评分".into()
    } else {
        format!("健康评分 {health_score}/100")
    };
    format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>StreamScope 诊断报告</title>
  <style>
    :root {{ color-scheme: light; font-family: system-ui, "Microsoft YaHei", sans-serif; }}
    body {{ max-width: 960px; margin: 40px auto; padding: 0 24px; color: #172033; background: #f6f8fb; }}
    header, section {{ background: white; border: 1px solid #dde3ec; border-radius: 12px; padding: 22px; margin: 16px 0; }}
    h1, h2 {{ margin-top: 0; }} .status {{ color: #075985; font-weight: 700; }}
    h3 {{ margin: 22px 0 8px; font-size: 15px; }}
    dl {{ display: grid; grid-template-columns: 150px 1fr; gap: 9px 16px; }} dt {{ color: #526070; }} dd {{ margin: 0; }}
    table {{ width: 100%; margin-top: 18px; border-collapse: collapse; font-size: 13px; }} th, td {{ padding: 9px; border-bottom: 1px solid #e5e9ef; text-align: left; }} th {{ color: #526070; background: #f7f9fb; }}
    code {{ overflow-wrap: anywhere; }} li {{ margin: 8px 0; }}
    .finding {{ border-left: 4px solid #f59e0b; background: #f8fafc; padding: 14px 18px; margin: 14px 0; }}
    .finding > div {{ display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }} .finding h4 {{ margin-bottom: 4px; }}
    .severity {{ border-radius: 999px; padding: 3px 8px; background: #fee2e2; font-size: 12px; }}
    .timeline {{ list-style: none; padding: 0; }} .timeline li {{ display: grid; grid-template-columns: 90px 170px 1fr; gap: 12px; border-bottom: 1px solid #e5e9ef; padding: 10px 0; }}
    .summary-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }} .summary-grid > div {{ padding: 14px; border: 1px solid #dde3ec; border-radius: 8px; background: #f8fafc; }}
    .summary-grid span, .summary-grid small {{ display: block; color: #64748b; }} .summary-grid strong {{ display: block; margin: 7px 0; }} .good {{ color: #07805d; }} .bad {{ color: #b4232c; }}
    .chart-svg {{ width: 100%; height: auto; border: 1px solid #e5e9ef; border-radius: 8px; background: #fbfcfd; }} .chart-line {{ fill: none; stroke: #1778cf; stroke-width: 2; }} .spectrogram-cell:hover {{ stroke: #fff; stroke-width: 1; }}
  </style>
</head>
<body>
  <header><h1>StreamScope 诊断报告</h1><p class="status">{title_status} · {health_text}</p><p>{generated_at}</p></header>
  {capture_identity_html}
  {summary_html}
  <section><h2>任务</h2><dl><dt>{source_label}</dt><dd><code>{url}</code></dd><dt>传输</dt><dd>{transport}</dd><dt>分析时长</dt><dd>{duration} 秒</dd></dl></section>
  {data_quality_html}
  {timing_html}
  {audio_html}
  {sync_html}
  {media_info_html}
  {protocol_html}
  {h264_html}
  {h265_html}
  {recovery_windows_html}
  {video_deep_html}
  <section><h2>诊断结论</h2>{diagnostics}</section>
  <section><h2>统一时间线</h2><ol class="timeline">{timeline}</ol></section>
  {ffmpeg_evidence_html}
  <section><h2>执行错误</h2><ul>{errors}</ul></section>
  <section><h2>工具版本与分析参数</h2><ul>{tool_versions}</ul><p>结果格式：<code>{schema_version}</code></p></section>
</body>
</html>"#,
        generated_at = escape_html(&result.generated_at),
        url = escape_html(&result.request.source_url),
        transport = result
            .request
            .transport
            .map(|transport| transport.to_string())
            .unwrap_or_else(|| "不适用".into()),
        duration = result.request.duration_seconds,
        schema_version = escape_html(&result.schema_version),
    )
}

fn valid_stream_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 80
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn render_audio_analysis(
    audio: &streamscope_core::AudioAnalysis,
    heading: &str,
    track_detail: Option<&str>,
) -> String {
    let issues = audio
        .issues
        .iter()
        .map(|issue| {
            let location = if matches!(issue.kind.as_str(), "timestamp_gap" | "timestamp_overlap") {
                format!(
                    "<br><small>媒体 +{}–+{} ms（{} ms）；抓包 #{}→#{}；Seq {}→{}；期望/实际 RTP TS {} / {}；到达 +{}→+{} ms</small>",
                    issue.media_start_ms.unwrap_or_default(),
                    issue.media_end_ms.unwrap_or_default(),
                    issue.duration_ms.unwrap_or_default(),
                    issue.previous_packet.map(|value| value.to_string()).unwrap_or_else(|| "—".into()),
                    issue.first_packet.map(|value| value.to_string()).unwrap_or_else(|| "—".into()),
                    issue.previous_rtp_sequence.map(|value| value.to_string()).unwrap_or_else(|| "—".into()),
                    issue.current_rtp_sequence.map(|value| value.to_string()).unwrap_or_else(|| "—".into()),
                    issue.expected_rtp_timestamp.map(|value| value.to_string()).unwrap_or_else(|| "—".into()),
                    issue.actual_rtp_timestamp.map(|value| value.to_string()).unwrap_or_else(|| "—".into()),
                    issue.previous_offset_ms.map(|value| value.to_string()).unwrap_or_else(|| "—".into()),
                    issue.offset_ms.map(|value| value.to_string()).unwrap_or_else(|| "—".into()),
                )
            } else {
                String::new()
            };
            format!(
                "<li><strong>{}</strong>：{}{}</li>",
                escape_html(&issue.kind),
                escape_html(&issue.detail),
                location,
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let quality_html = render_audio_quality(audio);
    let mapping_rows = audio
        .sample_mappings
        .iter()
        .take(100)
        .map(|mapping| {
            format!(
                "<tr><td>#{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}–{} @ {} Hz</td><td>{}</td></tr>",
                mapping.packet_number.map(|value| value.to_string()).unwrap_or_else(|| "—".into()),
                mapping.rtp_sequence.map(|value| value.to_string()).unwrap_or_else(|| "—".into()),
                mapping.rtp_timestamp,
                mapping.access_unit_index,
                mapping.pcm_start_sample,
                mapping.pcm_end_sample,
                mapping.sample_rate,
                escape_html(&mapping.precision),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let mapping_html = if mapping_rows.is_empty() {
        String::new()
    } else {
        format!(
            "<h3>RTP → Access Unit → PCM 映射</h3><p>共 {} 条；表格显示前 100 条，完整数据位于 JSON 报告。</p><table><thead><tr><th>抓包/采集包</th><th>RTP Seq</th><th>RTP 时间戳</th><th>AU</th><th>PCM 采样区间</th><th>精度</th></tr></thead><tbody>{mapping_rows}</tbody></table>",
            audio.sample_mappings.len()
        )
    };
    let track_detail = track_detail
        .map(|detail| format!("<p>{}</p>", escape_html(detail)))
        .unwrap_or_default();
    let timestamp_scope = if audio.codec.eq_ignore_ascii_case("pcma")
        || audio.codec.eq_ignore_ascii_case("pcmu")
    {
        "时间轴缺口/重叠按相邻 RTP 包的 Sequence、时间戳和 G.711 负载采样数精确定位。"
    } else {
        "当前仅对 PCMA/PCMU 提供精确 RTP 时间轴缺口/重叠定位；压缩编码的零计数不代表不存在异常。"
    };
    format!(
        "<section><h2>{}</h2>{}<dl><dt>编码</dt><dd>{}</dd><dt>采样率 / 声道</dt><dd>{} Hz / {}</dd><dt>解码采样 / 时长</dt><dd>{} / {}</dd><dt>峰值 / RMS</dt><dd>{} / {} dBFS</dd><dt>RTP 时间戳缺口 / 重叠</dt><dd>{} / {}</dd><dt>跨层映射</dt><dd>{} 条</dd><dt>结论可信度</dt><dd class=\"{}\">{}</dd></dl><p><small>{}</small></p><ul>{}</ul>{}{}</section>",
        escape_html(heading),
        track_detail,
        escape_html(&audio.codec),
        audio.sample_rate.unwrap_or(audio.clock_rate),
        audio
            .channels
            .map(|value| value.to_string())
            .unwrap_or_else(|| "—".into()),
        audio.decoded_samples,
        format_duration(audio.decoded_duration_ms),
        audio
            .peak_level_dbfs_milli
            .map(|value| format!("{:.1}", value as f64 / 1000.0))
            .unwrap_or_else(|| "—".into()),
        audio
            .rms_level_dbfs_milli
            .map(|value| format!("{:.1}", value as f64 / 1000.0))
            .unwrap_or_else(|| "—".into()),
        audio.timestamp_gap_count,
        audio.timestamp_overlap_count,
        audio.sample_mappings.len(),
        if audio.conclusion_reliable {
            "good"
        } else {
            "bad"
        },
        if audio.conclusion_reliable {
            "满足音频质量判断条件"
        } else {
            "证据不足，不输出确定性结论"
        },
        timestamp_scope,
        issues,
        mapping_html,
        quality_html,
    )
}

fn render_audio_quality(audio: &streamscope_core::AudioAnalysis) -> String {
    let Some(quality) = &audio.quality else {
        return String::new();
    };
    let metric = |value: Option<i32>, unit: &str| {
        value
            .map(|value| format!("{:.1} {unit}", value as f64 / 1_000.0))
            .unwrap_or_else(|| "—".into())
    };
    let channels = quality
        .channels
        .iter()
        .map(|channel| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                channel.channel,
                metric(channel.peak_level_dbfs_milli, "dBFS"),
                metric(channel.rms_level_dbfs_milli, "dBFS"),
                channel
                    .crest_factor_milli
                    .map(|value| format!("{:.2}", value as f64 / 1_000.0))
                    .unwrap_or_else(|| "—".into()),
                channel.silent_samples,
                channel.clipped_samples,
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let intervals = quality
        .intervals
        .iter()
        .map(|interval| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>+{}–+{} ms</td><td>{}</td><td>{}</td></tr>",
                match interval.kind.as_str() {
                    "silence" => "静音候选",
                    "clipping_candidate" => "削波候选",
                    "level_jump_candidate" => "音量突变候选",
                    _ => interval.kind.as_str(),
                },
                interval
                    .channel
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "全部".into()),
                interval.start_ms,
                interval.end_ms,
                escape_html(&interval.detail),
                interval.first_packet.map_or_else(
                    || "—".into(),
                    |first| format!(
                        "包 #{first}–#{} / Seq {}–{}",
                        interval.last_packet.unwrap_or(first),
                        interval
                            .first_rtp_sequence
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "—".into()),
                        interval
                            .last_rtp_sequence
                            .or(interval.first_rtp_sequence)
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "—".into())
                    )
                ),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let limitations = quality
        .limitations
        .iter()
        .map(|value| format!("<li>{}</li>", escape_html(value)))
        .collect::<Vec<_>>()
        .join("");
    format!(
        "<h3>PCM 内容质量</h3><dl><dt>实际分析覆盖</dt><dd>{}</dd><dt>综合响度</dt><dd>{}</dd><dt>True Peak</dt><dd>{}</dd><dt>响度范围</dt><dd>{}</dd><dt>动态范围</dt><dd>{}</dd><dt>频谱滚降</dt><dd>{}</dd><dt>声道电平差</dt><dd>{}</dd><dt>立体声相关性</dt><dd>{}</dd><dt>测量方法</dt><dd>{}</dd></dl><h3>每声道统计</h3><table><thead><tr><th>声道</th><th>Peak</th><th>RMS</th><th>峰均比</th><th>静音采样</th><th>近满幅采样</th></tr></thead><tbody>{}</tbody></table>{}{}<h3>平均频谱</h3>{}<h3>Mel 时频图</h3>{}<h3>内容异常区间</h3>{}<table><thead><tr><th>类型</th><th>声道</th><th>范围</th><th>证据</th><th>RTP 反查</th></tr></thead><tbody>{}</tbody></table><h3>测量限制</h3><ul>{}</ul>",
        format_duration(quality.analysis_coverage_ms),
        metric(quality.integrated_loudness_lufs_milli, "LUFS"),
        metric(quality.true_peak_dbtp_milli, "dBTP"),
        metric(quality.loudness_range_lu_milli, "LU"),
        metric(quality.dynamic_range_db_milli, "dB"),
        quality
            .spectral_rolloff_hz
            .map(|value| format!("{value} Hz"))
            .unwrap_or_else(|| "—".into()),
        metric(quality.channel_level_difference_db_milli, "dB"),
        quality
            .stereo_correlation_milli
            .map(|value| format!("{:.3}", value as f64 / 1_000.0))
            .unwrap_or_else(|| "—".into()),
        escape_html(&quality.measurement_method),
        channels,
        render_loudness_svg(quality),
        render_level_svg(quality),
        render_spectrum_svg(quality),
        render_spectrogram_svg(quality),
        if intervals.is_empty() {
            "<p>当前分析范围没有达到阈值的静音、削波或电平突变候选。</p>"
        } else {
            ""
        },
        intervals,
        limitations,
    )
}

fn render_loudness_svg(quality: &streamscope_core::AudioQualityAnalysis) -> String {
    let values: Vec<i32> = quality
        .loudness_series
        .iter()
        .filter_map(|point| point.momentary_lufs_milli)
        .collect();
    if values.len() < 2 {
        return "<p>没有足够的 EBU R128 响度时间序列。</p>".into();
    }
    let points = values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let x = index as f64 * 800.0 / (values.len() - 1) as f64;
            let y = 205.0 - ((*value as f64 / 1_000.0).clamp(-70.0, 0.0) + 70.0) * 2.75;
            format!("{x:.1},{y:.1}")
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "<h3>Momentary 响度时间曲线</h3><svg class=\"chart-svg\" viewBox=\"0 0 800 220\" role=\"img\" aria-label=\"Momentary 响度时间曲线\"><polyline class=\"chart-line\" points=\"{points}\"/></svg>"
    )
}

fn render_level_svg(quality: &streamscope_core::AudioQualityAnalysis) -> String {
    let values: Vec<i32> = quality
        .level_series
        .iter()
        .filter_map(|point| point.rms_level_dbfs_milli.first().copied().flatten())
        .collect();
    if values.len() < 2 {
        return "<p>没有足够的电平时间序列。</p>".into();
    }
    let points = values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let x = index as f64 * 800.0 / (values.len() - 1) as f64;
            let y = 205.0 - ((*value as f64 / 1_000.0).clamp(-80.0, 0.0) + 80.0) * 2.4;
            format!("{x:.1},{y:.1}")
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "<h3>声道 1 RMS 时间曲线</h3><svg class=\"chart-svg\" viewBox=\"0 0 800 220\" role=\"img\" aria-label=\"RMS 时间曲线\"><polyline class=\"chart-line\" points=\"{points}\"/></svg>"
    )
}

fn render_spectrum_svg(quality: &streamscope_core::AudioQualityAnalysis) -> String {
    let values = quality
        .average_spectrum
        .iter()
        .filter(|point| point.frequency_hz >= 20)
        .collect::<Vec<_>>();
    if values.len() < 2 {
        return "<p>样本太短，无法生成平均频谱。</p>".into();
    }
    let minimum_hz = f64::from(values.first().unwrap().frequency_hz.max(1));
    let maximum_hz = f64::from(values.last().unwrap().frequency_hz.max(2));
    let frequency_span = (maximum_hz.ln() - minimum_hz.ln()).max(f64::EPSILON);
    let points = values
        .iter()
        .map(|point| {
            let x = 52.0
                + (f64::from(point.frequency_hz.max(1)).ln() - minimum_hz.ln()) / frequency_span
                    * 724.0;
            let y = 202.0
                - ((point.level_dbfs_milli as f64 / 1_000.0).clamp(-120.0, 0.0) + 120.0) / 120.0
                    * 184.0;
            format!("{x:.1},{y:.1}")
        })
        .collect::<Vec<_>>()
        .join(" ");
    let horizontal_grid = [-120, -90, -60, -30, 0]
        .into_iter()
        .map(|level| {
            let y = 202.0 - f64::from(level + 120) / 120.0 * 184.0;
            format!("<line x1=\"52\" y1=\"{y:.1}\" x2=\"776\" y2=\"{y:.1}\" stroke=\"#e5e9ef\"/><text x=\"46\" y=\"{:.1}\" text-anchor=\"end\" font-size=\"10\" fill=\"#64748b\">{level}</text>", y + 3.0)
        })
        .collect::<String>();
    let frequency_grid = [20_u32, 50, 100, 200, 500, 1_000, 2_000, 5_000, 10_000, 20_000]
        .into_iter()
        .filter(|frequency| f64::from(*frequency) >= minimum_hz && f64::from(*frequency) <= maximum_hz)
        .map(|frequency| {
            let x = 52.0 + (f64::from(frequency).ln() - minimum_hz.ln()) / frequency_span * 724.0;
            format!("<line x1=\"{x:.1}\" y1=\"18\" x2=\"{x:.1}\" y2=\"202\" stroke=\"#edf1f5\"/><text x=\"{x:.1}\" y=\"217\" text-anchor=\"middle\" font-size=\"10\" fill=\"#64748b\">{}</text>", format_frequency(frequency))
        })
        .collect::<String>();
    format!(
        "<svg class=\"chart-svg\" viewBox=\"0 0 800 230\" role=\"img\" aria-label=\"对数频率平均频谱\">{horizontal_grid}{frequency_grid}<text x=\"8\" y=\"15\" font-size=\"10\" fill=\"#64748b\">dBFS</text><text x=\"780\" y=\"217\" font-size=\"10\" fill=\"#64748b\">Hz</text><polyline class=\"chart-line\" points=\"{points}\"/></svg>"
    )
}

fn render_spectrogram_svg(quality: &streamscope_core::AudioQualityAnalysis) -> String {
    if quality.spectrogram.is_empty() || quality.spectrogram_band_centers_hz.is_empty() {
        return "<p>样本太短，无法生成 Mel 时频图。</p>".into();
    }
    let peak = quality
        .spectrogram
        .iter()
        .flat_map(|frame| frame.band_levels_dbfs_milli.iter())
        .copied()
        .max()
        .unwrap_or(-100_000) as f64
        / 1_000.0;
    let visual_max = ((peak / 5.0).ceil() * 5.0).clamp(-100.0, 0.0);
    let visual_min = (visual_max - 80.0).max(-120.0);
    let plot_x = 54.0;
    let plot_y = 14.0;
    let plot_width = 678.0;
    let plot_height = 204.0;
    let width = plot_width / quality.spectrogram.len() as f64;
    let height = plot_height / quality.spectrogram_band_centers_hz.len() as f64;
    let rectangles = quality
        .spectrogram
        .iter()
        .enumerate()
        .flat_map(|(time, frame)| {
            frame
                .band_levels_dbfs_milli
                .iter()
                .enumerate()
                .map(move |(band, level)| {
                    let raw_db = *level as f64 / 1_000.0;
                    let color_db = raw_db.clamp(visual_min, visual_max);
                    let normalized = ((color_db - visual_min) / (visual_max - visual_min).max(1.0)).clamp(0.0, 1.0);
                    let color = spectrogram_color(normalized);
                    let x = plot_x + time as f64 * width;
                    let y = plot_y + plot_height - (band + 1) as f64 * height;
                    let seconds = quality.spectrogram[time].offset_ms as f64 / 1_000.0;
                    let frequency = quality.spectrogram_band_centers_hz.get(band).copied().unwrap_or(0);
                    format!("<rect class=\"spectrogram-cell\" x=\"{x:.2}\" y=\"{y:.2}\" width=\"{:.2}\" height=\"{:.2}\" fill=\"{color}\"><title>{seconds:.2} s · {frequency} Hz · {raw_db:.1} dBFS</title></rect>", width + 0.2, height + 0.2)
                })
        })
        .collect::<String>();
    let frequency_labels = quality
        .spectrogram_band_centers_hz
        .iter()
        .enumerate()
        .filter(|(index, _)| index % 8 == 0 || *index + 1 == quality.spectrogram_band_centers_hz.len())
        .map(|(index, frequency)| {
            let y = plot_y + plot_height - (index as f64 + 0.5) * height;
            format!("<text x=\"48\" y=\"{:.1}\" text-anchor=\"end\" font-size=\"10\" fill=\"#64748b\">{}</text>", y + 3.0, format_frequency(*frequency))
        })
        .collect::<String>();
    let first_time = quality
        .spectrogram
        .first()
        .map_or(0.0, |frame| frame.offset_ms as f64 / 1_000.0);
    let last_time = quality
        .spectrogram
        .last()
        .map_or(0.0, |frame| frame.offset_ms as f64 / 1_000.0);
    format!(
        "<svg class=\"chart-svg\" viewBox=\"0 0 800 250\" role=\"img\" aria-label=\"Mel 时频图\"><defs><linearGradient id=\"magma-scale\" x1=\"0\" y1=\"1\" x2=\"0\" y2=\"0\"><stop offset=\"0%\" stop-color=\"#000004\"/><stop offset=\"25%\" stop-color=\"#4f0a6d\"/><stop offset=\"50%\" stop-color=\"#b5367a\"/><stop offset=\"75%\" stop-color=\"#fb8761\"/><stop offset=\"100%\" stop-color=\"#fcfdbf\"/></linearGradient></defs><rect x=\"{plot_x}\" y=\"{plot_y}\" width=\"{plot_width}\" height=\"{plot_height}\" fill=\"#000004\"/>{rectangles}{frequency_labels}<text x=\"8\" y=\"12\" font-size=\"10\" fill=\"#64748b\">Hz</text><text x=\"{plot_x}\" y=\"235\" font-size=\"10\" fill=\"#64748b\">{first_time:.1} s</text><text x=\"{:.1}\" y=\"235\" text-anchor=\"end\" font-size=\"10\" fill=\"#64748b\">{last_time:.1} s</text><rect x=\"748\" y=\"14\" width=\"14\" height=\"204\" fill=\"url(#magma-scale)\"/><text x=\"768\" y=\"22\" font-size=\"10\" fill=\"#64748b\">{visual_max:.0}</text><text x=\"768\" y=\"218\" font-size=\"10\" fill=\"#64748b\">{visual_min:.0}</text><text x=\"748\" y=\"235\" font-size=\"10\" fill=\"#64748b\">dBFS</text></svg>",
        plot_x + plot_width
    )
}

fn format_frequency(frequency: u32) -> String {
    if frequency >= 1_000 {
        let value = frequency as f64 / 1_000.0;
        if frequency >= 10_000 || frequency.is_multiple_of(1_000) {
            format!("{value:.0}k")
        } else {
            format!("{value:.1}k")
        }
    } else {
        frequency.to_string()
    }
}

fn spectrogram_color(normalized: f64) -> String {
    const COLORS: [(u8, u8, u8); 9] = [
        (0, 0, 4),
        (27, 12, 65),
        (79, 10, 109),
        (129, 37, 129),
        (181, 54, 122),
        (229, 89, 100),
        (251, 135, 97),
        (254, 194, 135),
        (252, 253, 191),
    ];
    let position = normalized.clamp(0.0, 1.0) * (COLORS.len() - 1) as f64;
    let lower = position.floor() as usize;
    let upper = (lower + 1).min(COLORS.len() - 1);
    let mix = position - lower as f64;
    let interpolate = |left: u8, right: u8| {
        (f64::from(left) + (f64::from(right) - f64::from(left)) * mix).round() as u8
    };
    let (lr, lg, lb) = COLORS[lower];
    let (ur, ug, ub) = COLORS[upper];
    format!(
        "#{:02x}{:02x}{:02x}",
        interpolate(lr, ur),
        interpolate(lg, ug),
        interpolate(lb, ub)
    )
}

fn render_capture_identity(result: &AnalysisResult) -> String {
    let Some(identity) = &result.capture_stream else {
        return if result.request.source_kind == SourceKind::Pcap {
            "<section><h2>旧版抓包报告：未按媒体流分组</h2><p>此报告可能将多路 RTP 的统计与码流合并，请重新分析原始抓包。现有丢包、视频结构和解码结论不应用于多流故障定位。</p></section>".into()
        } else {
            String::new()
        };
    };
    format!(
        "<section><p><a href=\"../../report.html\">返回抓包总览</a> · <a href=\"result.json\">本流 JSON</a> · <a href=\"ffmpeg.log\">本流解码日志</a></p><h2>媒体流 {}</h2><dl><dt>源 → 目标</dt><dd><code>{} → {}</code></dd><dt>传输 / SSRC</dt><dd>{} / 0x{:08X}</dd><dt>接口 / TCP 连接</dt><dd>{} / {}</dd><dt>Interleaved Channel</dt><dd>{}</dd><dt>Payload Type</dt><dd>{}</dd><dt>编码 / 识别依据</dt><dd>{} / {}</dd><dt>媒体类型 / 声道</dt><dd>{} / {}</dd><dt>RTP 时钟</dt><dd>{}</dd><dt>抓包包号范围</dt><dd>#{} – #{}（包含本流以外的包）</dd><dt>抓包时间偏移</dt><dd>+{} ms – +{} ms</dd><dt>本流覆盖时长</dt><dd>{}</dd><dt>码流样本截断</dt><dd>{}</dd></dl><p>包号和时间偏移相对于原始抓包；RTP 与音视频结构数据仅来自本流。观测序列缺口不等同于已证实的网络丢包。</p></section>",
        escape_html(&identity.id),
        escape_html(&identity.source),
        escape_html(&identity.destination),
        identity.transport,
        identity.ssrc,
        escape_html(&identity.interface_id),
        identity
            .connection_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "—".into()),
        identity
            .channel
            .map(|channel| channel.to_string())
            .unwrap_or_else(|| "—".into()),
        identity
            .payload_types
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        escape_html(identity.codec.as_deref().unwrap_or("未知")),
        escape_html(&identity.codec_confidence),
        escape_html(if identity.media_type.is_empty() {
            "未知"
        } else {
            &identity.media_type
        }),
        identity
            .channels
            .map(|value| value.to_string())
            .unwrap_or_else(|| "—".into()),
        identity
            .clock_rate
            .map(|rate| format!("{rate} Hz"))
            .unwrap_or_else(|| "未知".into()),
        identity.first_packet,
        identity.last_packet,
        identity.first_offset_ms,
        identity.last_offset_ms,
        format_duration(Some(
            identity
                .last_offset_ms
                .saturating_sub(identity.first_offset_ms)
        )),
        if identity.sample_truncated {
            "是"
        } else {
            "否"
        },
    )
}

fn render_capture_overview(result: &AnalysisResult) -> String {
    let summary = result.capture_summary.as_ref().unwrap();
    let sync_rows = result
        .av_sync
        .iter()
        .map(|sync| {
            format!(
                "<tr><td>{} ↔ {}</td><td>{}</td><td>{}</td><td>{}</td><td>{}%</td><td>{}</td></tr>",
                escape_html(sync.audio_stream_id.as_deref().unwrap_or("未知音频")),
                escape_html(sync.video_stream_id.as_deref().unwrap_or("未知视频")),
                escape_html(&sync.status),
                sync.offset_ms
                    .map(|value| format!("{value} ms"))
                    .unwrap_or_else(|| "—".into()),
                sync.content_offset_ms
                    .map(|value| format!("{value} ms / {} 组事件", sync.content_events.len()))
                    .unwrap_or_else(|| "—".into()),
                sync.confidence_percent,
                escape_html(&sync.reasons.join("；")),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let sync_html = if sync_rows.is_empty() {
        "<p>未形成音视频配对，或抓包中没有同时发现音频和视频。</p>".into()
    } else {
        format!(
            "<div class=\"table-scroll\"><table><thead><tr><th>配对</th><th>状态</th><th>时钟偏移</th><th>内容偏移</th><th>时钟置信度</th><th>证据边界</th></tr></thead><tbody>{sync_rows}</tbody></table></div><p>时钟偏移来自 RTCP；内容偏移来自深入分析生成的同源闪光/蜂鸣事件配对。</p>"
        )
    };
    let rows = result.streams.iter().map(|stream| {
        let Some(identity) = &stream.capture_stream else {
            return "<tr><td colspan=\"12\">流标识缺失，无法关联逐流报告。</td></tr>".into();
        };
        let name = if valid_stream_id(&identity.id) {
            format!("<a href=\"streams/{}/report.html\">{}</a>", identity.id, escape_html(&identity.id))
        } else {
            format!("{}（流 ID 无效）", escape_html(&identity.id))
        };
        let rtp = stream.protocol.as_ref().map(|protocol| &protocol.rtp);
        let analysis_status = match stream.status {
            AnalysisStatus::Completed => "完成",
            AnalysisStatus::Partial => "部分完成",
            AnalysisStatus::Failed => "失败",
        };
        let decode_status = if let Some(audio) = &stream.audio {
            if audio.codec_supported_for_decode {
                "音频 PCM 分析完成"
            } else {
                "音频仅 RTP 分析"
            }
        } else {
            match stream.decode.as_ref() {
                Some(decode) if decode.success => "解码成功",
                Some(_) => "解码失败",
                None => "解码未执行",
            }
        };
        let severity = stream.diagnostics.iter().map(|finding| finding.severity).max();
        let severity = match severity {
            Some(DiagnosticSeverity::Critical) => "严重",
            Some(DiagnosticSeverity::High) => "高",
            Some(DiagnosticSeverity::Medium) => "中",
            Some(DiagnosticSeverity::Low) => "低",
            Some(DiagnosticSeverity::Info) => "提示",
            None => "无诊断项",
        };
        let quality = if !stream.data_quality.assessed { "未评估" }
            else if stream.data_quality.sufficient_for_diagnosis { "满足诊断条件" }
            else { "样本不足" };
        format!(
            "<tr><td>{name}</td><td><code>{} → {}</code><small>接口 {} / 连接 {}</small></td><td>0x{:08X}<small>Channel {}</small></td><td>{}</td><td>{}<small>{}</small></td><td>{}</td><td>{}</td><td>{}<small>+{} – +{} ms</small></td><td>{}<small>峰值 {}</small></td><td>{}<small>缺口 / 乱序 / 重复：{} / {} / {}</small></td><td>{analysis_status}<small>{decode_status}</small></td><td>{quality}<small>最高诊断等级：{severity}</small></td></tr>",
            escape_html(&identity.source), escape_html(&identity.destination),
            escape_html(&identity.interface_id), identity.connection_id.map(|id| id.to_string()).unwrap_or_else(|| "—".into()),
            identity.ssrc, identity.channel.map(|channel| channel.to_string()).unwrap_or_else(|| "—".into()),
            identity.payload_types.iter().map(u8::to_string).collect::<Vec<_>>().join(", "),
            escape_html(identity.codec.as_deref().unwrap_or("未知")), escape_html(&identity.codec_confidence),
            identity.transport, rtp.map_or(0, |rtp| rtp.packet_count),
            format_duration(Some(identity.last_offset_ms.saturating_sub(identity.first_offset_ms))),
            identity.first_offset_ms, identity.last_offset_ms,
            format_bit_rate(rtp.and_then(|rtp| rtp.average_bit_rate_bps)), format_bit_rate(rtp.and_then(|rtp| rtp.peak_bit_rate_bps)),
            stream.diagnostics.len(), rtp.map_or(0, |rtp| rtp.lost_packets), rtp.map_or(0, |rtp| rtp.out_of_order_packets), rtp.map_or(0, |rtp| rtp.duplicate_packets),
        )
    }).collect::<Vec<String>>().join("\n");
    let rows = if rows.is_empty() {
        "<tr><td colspan=\"12\">未发现可分组的 RTP 媒体流，请查看捕获提示与执行错误。</td></tr>"
            .into()
    } else {
        rows
    };
    let warnings = summary
        .warnings
        .iter()
        .chain(result.errors.iter())
        .map(|warning| format!("<li>{}</li>", escape_html(warning)))
        .collect::<Vec<_>>()
        .join("");
    let warnings = if warnings.is_empty() {
        "<li>无</li>".into()
    } else {
        warnings
    };
    let status = match result.status {
        AnalysisStatus::Completed => "分析完成",
        AnalysisStatus::Partial => "部分完成",
        AnalysisStatus::Failed => "分析失败",
    };
    format!(
        r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>StreamScope 多流抓包报告</title>
<style>:root {{color-scheme:light;font-family:system-ui,"Microsoft YaHei",sans-serif}}body {{margin:32px auto;padding:0 24px;max-width:1600px;color:#172033;background:#f6f8fb}}header,section {{background:white;border:1px solid #dde3ec;border-radius:12px;padding:22px;margin:16px 0}}h1,h2 {{margin-top:0}}a {{color:#075985}}dl {{display:grid;grid-template-columns:170px 1fr;gap:8px}}dd {{margin:0}}.table-scroll {{overflow-x:auto}}table {{width:100%;border-collapse:collapse;font-size:13px}}th,td {{padding:10px;text-align:left;vertical-align:top;border-bottom:1px solid #dde3ec}}th {{background:#f7f9fb;white-space:nowrap}}small {{display:block;color:#526070;margin-top:5px}}code {{overflow-wrap:anywhere}}li {{margin:8px 0}}</style></head>
<body><header><h1>StreamScope 多流抓包报告</h1><p>{status} · 发现 {stream_count} 组媒体流</p><p>{generated_at}</p><p><a href="result.json">完整 JSON（含各流结果）</a></p></header>
<section><h2>抓包总览</h2><dl><dt>来源</dt><dd><code>{source}</code></dd><dt>抓包覆盖时长</dt><dd>{duration}</dd><dt>总抓包帧数</dt><dd>{total}</dd><dt>已解析传输层帧</dt><dd>{parsed}</dd><dt>忽略 / 异常帧</dt><dd>{ignored} / {malformed}</dd></dl><p>各媒体流独立统计、重组和解码。传输方式、码率和可信度请逐流查看；总览不合并各流的序列、NALU 或视频帧。抓包中的序列缺口需结合捕获完整性核验。</p></section>
<section><h2>媒体流列表</h2><div class="table-scroll"><table><thead><tr><th>流 / 详情</th><th>端点</th><th>SSRC / Channel</th><th>PT</th><th>编码 / 识别依据</th><th>传输</th><th>RTP 包</th><th>覆盖时长</th><th>平均码率</th><th>诊断项</th><th>执行状态</th><th>数据可信度</th></tr></thead><tbody>{rows}</tbody></table></div></section>
<section><h2>音画同步时钟证据</h2>{sync_html}</section>
<section><h2>捕获提示与执行错误</h2><ul>{warnings}</ul></section><footer>结果格式：<code>{schema}</code></footer></body></html>"#,
        stream_count = result.streams.len(),
        generated_at = escape_html(&result.generated_at),
        source = escape_html(&result.request.source_url),
        duration = format_duration(Some(summary.duration_ms)),
        total = summary.total_frames,
        parsed = summary.parsed_transport_frames,
        ignored = summary.ignored_frames,
        malformed = summary.malformed_frames,
        schema = escape_html(&result.schema_version),
    )
}

fn format_duration(value: Option<u64>) -> String {
    value
        .map(|milliseconds| {
            if milliseconds >= 1_000 {
                format!("{:.2} 秒", milliseconds as f64 / 1_000.0)
            } else {
                format!("{milliseconds} ms")
            }
        })
        .unwrap_or_else(|| "未执行".into())
}

fn format_bit_rate(value: Option<u64>) -> String {
    value
        .map(|bps| {
            if bps >= 1_000_000 {
                format!("{:.2} Mbps", bps as f64 / 1_000_000.0)
            } else {
                format!("{:.0} Kbps", bps as f64 / 1_000.0)
            }
        })
        .unwrap_or_else(|| "—".into())
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use streamscope_core::{
        AnalysisRequest, AnalysisStatus, RESULT_SCHEMA_VERSION, ToolAvailability, Transport,
    };

    fn sample_result() -> AnalysisResult {
        AnalysisResult {
            schema_version: RESULT_SCHEMA_VERSION.into(),
            generated_at: "2026-09-07T12:00:00Z".into(),
            request: AnalysisRequest {
                source_kind: streamscope_core::SourceKind::Rtsp,
                source_url: "rtsp://admin:REDACTED@example.test/live?x=<unsafe>".into(),
                source_path: None,
                transport: Some(Transport::Tcp),
                duration_seconds: 10,
            },
            tools: vec![ToolAvailability {
                name: "ffmpeg".into(),
                available: true,
                version: Some("ffmpeg version test".into()),
            }],
            stream: None,
            format_bit_rate: None,
            session_sdp: Some("v=0\ns=Test\n".into()),
            protocol: None,
            h264: None,
            h265: None,
            audio: None,
            audio_tracks: Vec::new(),
            av_sync: Vec::new(),
            diagnostics: Vec::new(),
            timeline: Vec::new(),
            module_timings: streamscope_core::ModuleTimings::default(),
            data_quality: streamscope_core::DataQuality::default(),
            decode: None,
            preview_video: None,
            preview_audio: None,
            status: AnalysisStatus::Partial,
            errors: vec!["example <error>".into()],
            capture_summary: None,
            capture_stream: None,
            streams: Vec::new(),
        }
    }

    fn capture_result(count: usize) -> AnalysisResult {
        let mut result = sample_result();
        result.request.source_kind = SourceKind::Pcap;
        result.request.source_url = "capture<test>.pcapng".into();
        result.request.transport = None;
        result.capture_summary = Some(streamscope_core::CaptureSummary {
            stream_count: count,
            total_frames: count as u64 * 100,
            duration_ms: 5_000,
            warnings: vec!["warning <untrusted>".into()],
            ..Default::default()
        });
        result.streams = (0..count)
            .map(|index| {
                let mut stream = sample_result();
                stream.request.source_kind = SourceKind::Pcap;
                stream.request.transport = Some(Transport::Udp);
                stream.capture_stream = Some(streamscope_core::CaptureStreamIdentity {
                    id: format!("stream-{index}"),
                    source: format!("192.0.2.{}:5004", index + 1),
                    destination: "198.51.100.1:6000".into(),
                    transport: Transport::Udp,
                    ssrc: 42,
                    channel: None,
                    interface_id: "interface-0".into(),
                    connection_id: None,
                    payload_types: vec![96],
                    codec: Some("H264".into()),
                    media_type: "video".into(),
                    channels: None,
                    codec_confidence: "SDP".into(),
                    clock_rate: Some(90_000),
                    first_packet: index as u64 + 1,
                    last_packet: index as u64 + 101,
                    first_offset_ms: 200,
                    last_offset_ms: 5_200,
                    sample_truncated: false,
                    events: Vec::new(),
                });
                stream.protocol = Some(streamscope_core::ProtocolAnalysis {
                    rtp: streamscope_core::RtpStatistics {
                        packet_count: 100,
                        lost_packets: index as u64,
                        ..Default::default()
                    },
                    ..Default::default()
                });
                stream.decode = Some(streamscope_core::DecodeSummary {
                    success: true,
                    log: format!("stream {index} decode log"),
                    ..Default::default()
                });
                stream
            })
            .collect();
        result
    }

    #[test]
    fn html_is_self_contained_and_escapes_dynamic_values() {
        let html = render_html(&sample_result());
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("&lt;unsafe&gt;"));
        assert!(html.contains("example &lt;error&gt;"));
        assert!(!html.contains("<unsafe>"));
        assert!(html.contains("数据可信度"));
        assert!(html.contains("分析范围与处理耗时"));
    }

    #[test]
    fn writes_both_report_formats() {
        let directory =
            std::env::temp_dir().join(format!("streamscope-report-test-{}", std::process::id()));
        let paths = write_reports(&directory, &sample_result()).unwrap();
        assert!(paths.json.is_file());
        assert!(paths.html.is_file());
        assert!(paths.session_sdp.unwrap().is_file());
        assert!(paths.ffmpeg_log.is_file());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn renders_each_rtsp_audio_track_separately() {
        let mut result = sample_result();
        result.audio_tracks = (0..2)
            .map(|index| streamscope_core::AudioTrackResult {
                id: format!("rtsp-track-{}", index + 2),
                track_index: index + 1,
                codec: if index == 0 { "PCMA" } else { "opus" }.into(),
                payload_type: if index == 0 { 8 } else { 111 },
                clock_rate: if index == 0 { 8_000 } else { 48_000 },
                channels: Some(if index == 0 { 1 } else { 2 }),
                first_payload_offset_ms: Some(0),
                analysis: streamscope_core::AudioAnalysis {
                    codec: if index == 0 { "PCMA" } else { "opus" }.into(),
                    clock_rate: if index == 0 { 8_000 } else { 48_000 },
                    ..Default::default()
                },
                preview_audio: None,
                export_source: None,
            })
            .collect();
        let html = render_html(&result);
        assert!(html.contains("音频分析 · rtsp-track-2"));
        assert!(html.contains("音频分析 · rtsp-track-3"));
        assert!(html.contains("Payload Type 8"));
        assert!(html.contains("Payload Type 111"));
        assert!(html.contains("G.711 负载采样数精确定位"));
        assert!(html.contains("压缩编码的零计数不代表不存在异常"));
    }

    #[test]
    fn renders_structural_recovery_without_claiming_visual_recovery() {
        let mut result = sample_result();
        result.h264 = Some(streamscope_core::H264Analysis {
            recovery_windows: vec![streamscope_core::VideoRecoveryWindow {
                source_frame: 10,
                source_kind: "missing_reference".into(),
                next_random_access_frame: Some(140),
                wait_frames: Some(130),
                wait_ms: Some(5_200),
                structural_status: "random_access_observed".into(),
                visual_status: "not_confirmed".into(),
                ..streamscope_core::VideoRecoveryWindow::default()
            }],
            ..streamscope_core::H264Analysis::default()
        });
        let html = render_html(&result);
        assert!(html.contains("传播与恢复窗口"));
        assert!(html.contains("#140"));
        assert!(html.contains("5200 ms"));
        assert!(html.contains("未确认画面恢复"));
    }

    #[test]
    fn renders_h264_hrd_simulation_and_its_evidence_boundary() {
        let mut result = sample_result();
        result.h264 = Some(streamscope_core::H264Analysis {
            hrd_simulation: streamscope_core::H264HrdSimulation {
                status: "simulated_cbr_single_cpb".into(),
                schedule: "nal".into(),
                sps_id: Some(0),
                buffering_period_count: 1,
                pic_timing_count: 2,
                simulated_aus: 2,
                minimum_fullness_bits: Some(10_000),
                maximum_fullness_bits: Some(90_000),
                underflow_aus: vec![2],
                points: vec![streamscope_core::H264HrdAuPoint {
                    access_unit: 2,
                    sei_nalu: 4,
                    access_unit_bits: 120_000,
                    cpb_removal_delay: 1,
                    fullness_before_removal_bits: 100_000,
                    underflow: true,
                    ..streamscope_core::H264HrdAuPoint::default()
                }],
                ..streamscope_core::H264HrdSimulation::default()
            },
            ..streamscope_core::H264Analysis::default()
        });
        let html = render_html(&result);
        assert!(html.contains("已完成单 CPB / CBR 仿真"));
        assert!(html.contains("AU 大小按保留的 NALU 字节计算"));
        assert!(html.contains("CPB 下溢"));
    }

    #[test]
    fn writes_independent_child_reports_without_overwriting_samples() {
        let directory = std::env::temp_dir().join(format!(
            "streamscope-multistream-report-test-{}",
            std::process::id()
        ));
        let result = capture_result(3);
        for index in 0..3 {
            let sample = directory.join(format!("streams/stream-{index}/sample.h264"));
            fs::create_dir_all(sample.parent().unwrap()).unwrap();
            fs::write(&sample, [index as u8]).unwrap();
        }
        let paths = write_reports(&directory, &result).unwrap();
        let root: AnalysisResult = serde_json::from_slice(&fs::read(paths.json).unwrap()).unwrap();
        assert_eq!(root.streams.len(), 3);
        assert!(root.protocol.is_none());
        let overview = fs::read_to_string(paths.html).unwrap();
        for index in 0..3 {
            let child_dir = directory.join(format!("streams/stream-{index}"));
            let child: AnalysisResult =
                serde_json::from_slice(&fs::read(child_dir.join("result.json")).unwrap()).unwrap();
            assert_eq!(child.capture_stream.unwrap().id, format!("stream-{index}"));
            assert_eq!(child.protocol.unwrap().rtp.lost_packets, index as u64);
            assert_eq!(
                fs::read_to_string(child_dir.join("ffmpeg.log")).unwrap(),
                format!("stream {index} decode log")
            );
            assert_eq!(
                fs::read(child_dir.join("sample.h264")).unwrap(),
                [index as u8]
            );
            assert!(overview.contains(&format!("streams/stream-{index}/report.html")));
            let detail = fs::read_to_string(child_dir.join("report.html")).unwrap();
            assert!(detail.contains("观测序列缺口"));
            assert!(!detail.contains("估算丢包"));
            assert!(detail.contains("+200 ms – +5200 ms"));
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn renders_many_streams_and_escapes_capture_metadata() {
        let mut result = capture_result(100);
        let identity = result.streams[0].capture_stream.as_mut().unwrap();
        identity.source = "<img src=x onerror=alert(1)>".into();
        identity.codec_confidence = "<script>untrusted</script>".into();
        let html = render_html(&result);
        assert!(html.contains("发现 100 组媒体流"));
        assert!(html.contains("streams/stream-99/report.html"));
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(html.contains("&lt;script&gt;untrusted&lt;/script&gt;"));
        assert!(html.contains("warning &lt;untrusted&gt;"));
        assert!(!html.contains("<script>"));
        assert!(!html.contains("健康评分"));
        assert!(!html.contains("控制面未完成"));
        let detail = render_html(&result.streams[0]);
        assert!(!detail.contains("<img"));
        assert!(!detail.contains("<script>"));
    }

    #[test]
    fn rejects_unsafe_or_duplicate_ids_before_writing() {
        let directory = std::env::temp_dir().join(format!(
            "streamscope-invalid-report-test-{}",
            std::process::id()
        ));
        for id in ["../outside", "..\\outside", "C:\\outside", "", "<script>"] {
            let mut result = capture_result(1);
            result.streams[0].capture_stream.as_mut().unwrap().id = id.into();
            assert!(matches!(
                write_reports(&directory, &result),
                Err(ReportError::InvalidStreams(_))
            ));
            assert!(!directory.exists());
            assert!(!render_html(&result).contains(&format!("href=\"streams/{id}/")));
        }
        let mut result = capture_result(2);
        result.streams[1].capture_stream.as_mut().unwrap().id = "stream-0".into();
        assert!(matches!(
            write_reports(&directory, &result),
            Err(ReportError::InvalidStreams(_))
        ));
        assert!(!directory.exists());
    }

    #[test]
    fn empty_and_legacy_captures_have_explicit_limitations() {
        let html = render_html(&capture_result(0));
        assert!(html.contains("发现 0 组媒体流"));
        assert!(html.contains("未发现可分组的 RTP"));
        assert!(!html.contains("健康评分"));
        let mut legacy = serde_json::to_value(sample_result()).unwrap();
        legacy["request"]["source_kind"] = "pcap".into();
        for key in ["capture_summary", "capture_stream", "streams"] {
            legacy.as_object_mut().unwrap().remove(key);
        }
        let legacy: AnalysisResult = serde_json::from_value(legacy).unwrap();
        let html = render_html(&legacy);
        assert!(html.contains("旧版抓包报告：未按媒体流分组"));
        assert!(html.contains("暂不评分"));
        assert!(html.contains("未执行 FFmpeg 解码"));
        assert!(!html.contains("控制面未完成"));
    }

    #[test]
    fn renders_log_spectrum_and_hoverable_magma_spectrogram() {
        let quality = streamscope_core::AudioQualityAnalysis {
            average_spectrum: vec![
                streamscope_core::AudioSpectrumPoint {
                    frequency_hz: 20,
                    level_dbfs_milli: -80_000,
                },
                streamscope_core::AudioSpectrumPoint {
                    frequency_hz: 1_000,
                    level_dbfs_milli: -30_000,
                },
                streamscope_core::AudioSpectrumPoint {
                    frequency_hz: 4_000,
                    level_dbfs_milli: -60_000,
                },
            ],
            spectrogram_band_centers_hz: vec![100, 1_000],
            spectrogram: vec![
                streamscope_core::AudioSpectrogramPoint {
                    offset_ms: 0,
                    band_levels_dbfs_milli: vec![-100_000, -60_000],
                },
                streamscope_core::AudioSpectrogramPoint {
                    offset_ms: 500,
                    band_levels_dbfs_milli: vec![-80_000, -20_000],
                },
            ],
            ..Default::default()
        };

        let spectrum = render_spectrum_svg(&quality);
        assert!(spectrum.contains("对数频率平均频谱"));
        assert!(spectrum.contains(">1k</text>"));
        let spectrogram = render_spectrogram_svg(&quality);
        assert!(spectrogram.contains("magma-scale"));
        assert!(spectrogram.contains("spectrogram-cell"));
        assert!(spectrogram.contains("0.50 s · 1000 Hz · -20.0 dBFS"));
    }
}
