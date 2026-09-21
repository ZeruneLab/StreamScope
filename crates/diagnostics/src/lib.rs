use streamscope_core::{
    AnalysisResult, DiagnosticEvidence, DiagnosticFinding, DiagnosticSeverity, TimelineEvent,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleDefinition {
    pub id: &'static str,
    pub title: &'static str,
    pub category: &'static str,
    pub severity: DiagnosticSeverity,
    pub impact: &'static str,
    pub suggestion: &'static str,
    pub verification: &'static str,
}

const RULES: [RuleDefinition; 55] = [
    rule(
        "RTSP-001",
        "RTSP 服务不可达",
        "连接",
        DiagnosticSeverity::Critical,
        "无法建立诊断会话。",
        "检查地址、端口、路由和设备监听状态。",
        "确认目标端口可达后重新诊断。",
    ),
    rule(
        "RTSP-002",
        "RTSP 请求超时",
        "连接",
        DiagnosticSeverity::High,
        "连接或请求响应超出允许时间。",
        "检查链路时延、设备负载并适当增加连接超时。",
        "重新诊断并比较各 RTSP 事务耗时。",
    ),
    rule(
        "RTSP-003",
        "RTSP 鉴权失败",
        "鉴权",
        DiagnosticSeverity::Critical,
        "客户端无法继续获取媒体。",
        "核对用户名、密码和设备支持的鉴权方式。",
        "使用同一账号重新连接并确认 DESCRIBE 成功。",
    ),
    rule(
        "RTSP-004",
        "SDP 无效或缺失",
        "会话",
        DiagnosticSeverity::High,
        "媒体参数和控制地址无法可靠建立。",
        "检查服务端 DESCRIBE 响应及 SDP 内容。",
        "确认 SDP 至少包含有效的视频 m=、rtpmap 和 control。",
    ),
    rule(
        "RTSP-005",
        "Control URI 异常",
        "会话",
        DiagnosticSeverity::High,
        "SETUP 可能发往错误地址。",
        "修正 SDP 的 a=control 或 Content-Base。",
        "核对报告中的解析后 Control URI。",
    ),
    rule(
        "RTSP-006",
        "SETUP 失败",
        "会话",
        DiagnosticSeverity::Critical,
        "媒体传输通道未建立。",
        "核对 Transport 协商和设备支持的 TCP/UDP 模式。",
        "改用另一传输模式复测。",
    ),
    rule(
        "RTSP-007",
        "PLAY 成功但无 RTP",
        "会话",
        DiagnosticSeverity::Critical,
        "控制面正常但没有媒体数据。",
        "检查服务端推流状态、防火墙和 Transport 返回参数。",
        "观察 PLAY 后 RTP 包计数是否增长。",
    ),
    rule(
        "RTSP-008",
        "RTSP Session 中断",
        "会话",
        DiagnosticSeverity::High,
        "长连接可能提前失效。",
        "检查 Session 超时、服务端负载和链路稳定性。",
        "延长采样并观察会话是否仍中断。",
    ),
    rule(
        "RTSP-009",
        "Keepalive 缺失",
        "会话",
        DiagnosticSeverity::Medium,
        "长时间播放可能被服务端回收。",
        "按 Session timeout 周期发送 GET_PARAMETER 或 OPTIONS。",
        "执行长时诊断确认会话不再被回收。",
    ),
    rule(
        "SDP-010",
        "SDP 分辨率无效",
        "SDP",
        DiagnosticSeverity::High,
        "播放器可能无法预分配正确的解码表面。",
        "修正 framesize 或由有效 SPS 提供分辨率。",
        "确认 SDP 和 SPS 中分辨率均为非零值。",
    ),
    rule(
        "SDP-011",
        "SDP 帧率无效",
        "SDP",
        DiagnosticSeverity::Medium,
        "时序和缓冲策略可能不准确。",
        "修正 framerate 属性或由码流提供稳定时序。",
        "确认报告中的帧率大于零。",
    ),
    rule(
        "H264-012",
        "缺少 SPS 或 PPS",
        "H.264",
        DiagnosticSeverity::Critical,
        "解码器无法可靠初始化。",
        "在首个 IDR 前发送 SPS 和 PPS，并定期重复参数集。",
        "重新采样并确认 SPS、PPS 均可解析。",
    ),
    rule(
        "H264-013",
        "SPS 或 PPS 无效",
        "H.264",
        DiagnosticSeverity::Critical,
        "参数集解析失败，码流结构不可信。",
        "检查编码器参数集生成和 RTP 分片完整性。",
        "保存原始码流并验证参数集 RBSP。",
    ),
    rule(
        "H264-014",
        "SDP 与 SPS 分辨率不一致",
        "一致性",
        DiagnosticSeverity::High,
        "播放器可能按错误分辨率初始化。",
        "让 SDP framesize 与实际 SPS 保持一致。",
        "对比修正后的 SDP 和 SPS 分辨率。",
    ),
    rule(
        "RTP-015",
        "检测到 RTP 丢包",
        "RTP",
        DiagnosticSeverity::High,
        "缺失负载可能造成花屏、卡顿或解码错误。",
        "检查网络拥塞、MTU、交换机丢包和接收缓冲。",
        "在相同场景复测并确认丢包计数为零。",
    ),
    rule(
        "RTP-016",
        "连续 RTP 丢包",
        "RTP",
        DiagnosticSeverity::Critical,
        "连续缺包更容易破坏完整帧或 GOP。",
        "优先排查突发拥塞、无线干扰和接收端阻塞。",
        "复测并观察最大序列缺口是否下降。",
    ),
    rule(
        "RTP-017",
        "RTP 包乱序",
        "RTP",
        DiagnosticSeverity::Medium,
        "乱序超出缓冲能力时会表现为丢包。",
        "检查多路径转发并调整接收端重排序缓冲。",
        "比较乱序数和实际解码异常时间点。",
    ),
    rule(
        "RTP-018",
        "RTP 重复包",
        "RTP",
        DiagnosticSeverity::Low,
        "重复数据浪费带宽并可能干扰统计。",
        "检查网关重发或链路复制配置。",
        "复测确认重复包计数不再增长。",
    ),
    rule(
        "RTP-019",
        "RTP 时间戳回退",
        "RTP",
        DiagnosticSeverity::High,
        "播放时钟可能跳变或冻结。",
        "检查编码器时间基和会话重启处理。",
        "确认同一 SSRC 下时间戳保持合理递增。",
    ),
    rule(
        "RTP-020",
        "RTP SSRC 变化",
        "RTP",
        DiagnosticSeverity::Medium,
        "流源可能发生切换或重启。",
        "确认设备是否预期切流，并重置接收端状态。",
        "对照设备日志确认 SSRC 变化原因。",
    ),
    rule(
        "RTP-021",
        "RTP Marker 异常",
        "RTP",
        DiagnosticSeverity::Medium,
        "帧边界识别可能不可靠。",
        "确保每个 H.264 访问单元末包设置 Marker。",
        "复测并确认连续帧边界均有 Marker。",
    ),
    rule(
        "H264-022",
        "FU-A 分片不完整",
        "H.264",
        DiagnosticSeverity::Critical,
        "NALU 无法完整重组。",
        "排查 RTP 丢包并检查 FU-A Start/End 标志。",
        "复测确认不完整 NALU 为零。",
    ),
    rule(
        "H264-023",
        "首帧不是 IDR",
        "H.264",
        DiagnosticSeverity::High,
        "中途加入的客户端可能长时间无法出图。",
        "让会话开始处发送 IDR，并在其前发送参数集。",
        "重新连接确认首个视频帧为 IDR。",
    ),
    rule(
        "H264-024",
        "首个 IDR 等待过长",
        "H.264",
        DiagnosticSeverity::Medium,
        "首画面时间过长。",
        "缩短关键帧间隔或连接时主动请求 IDR。",
        "重新连接并测量首个 IDR 帧位置。",
    ),
    rule(
        "H264-025",
        "GOP 过长",
        "H.264",
        DiagnosticSeverity::Medium,
        "丢包后的画面恢复时间可能较长。",
        "根据实时性要求缩短 GOP。",
        "复测确认最大 GOP 落在目标范围。",
    ),
    rule(
        "H264-026",
        "IDR 前缺少参数集",
        "H.264",
        DiagnosticSeverity::Critical,
        "客户端可能无法解码首个关键帧。",
        "在首个 IDR 前发送 SPS 和 PPS。",
        "确认报告中两项前置参数集均为是。",
    ),
    rule(
        "H264-027",
        "运行中分辨率变化",
        "H.264",
        DiagnosticSeverity::High,
        "未正确重建解码器会导致花屏或停止。",
        "变更分辨率时发送新参数集和 IDR。",
        "确认播放器能在变化点重新初始化。",
    ),
    rule(
        "DEC-028",
        "缺失参考帧",
        "解码",
        DiagnosticSeverity::High,
        "预测帧无法正确重建。",
        "结合 RTP 丢包和 GOP 证据定位丢失点。",
        "网络恢复后确认解码日志不再出现参考帧错误。",
    ),
    rule(
        "DEC-029",
        "宏块解码错误",
        "解码",
        DiagnosticSeverity::High,
        "画面可能出现块状失真或错误隐藏。",
        "排查损坏 NALU、丢包和编码器稳定性。",
        "保存同时间段码流并用另一解码器复核。",
    ),
    rule(
        "CMP-030",
        "UDP 异常而 TCP 正常",
        "对比",
        DiagnosticSeverity::High,
        "问题更可能位于 UDP 网络路径。",
        "检查 UDP 防火墙、NAT、MTU 和丢包。",
        "分别以 TCP、UDP 对同一流做相同时长复测。",
    ),
    rule(
        "REC-031",
        "下一随机接入机会等待过长",
        "恢复",
        DiagnosticSeverity::Medium,
        "预测链受损后可能持续到较晚的 IDR/CRA 才获得结构恢复机会。",
        "缩短 GOP，并确保参数集随 IDR 重发。",
        "注入一次可控丢包并区分测量随机接入机会与实际画面恢复时间。",
    ),
    rule(
        "CMP-032",
        "兼容性风险",
        "兼容性",
        DiagnosticSeverity::Medium,
        "部分播放器可能拒绝或错误解释该流。",
        "修正 SDP、参数集和标准封包后再做播放器矩阵验证。",
        "至少使用两种独立播放器复测。",
    ),
    rule(
        "VIS-033",
        "疑似黑屏区间",
        "画面",
        DiagnosticSeverity::Medium,
        "视频可能在该时间段保持近黑画面。",
        "结合设备场景、曝光和编码器日志确认是否为非预期黑屏。",
        "回放关联帧及前后 2 秒画面，正常暗场应排除为故障。",
    ),
    rule(
        "VIS-034",
        "疑似画面冻结",
        "画面",
        DiagnosticSeverity::Medium,
        "视频内容可能持续不变，但网络和解码仍可能正常。",
        "对照 RTP 到达间隔、设备采集日志和场景运动情况。",
        "回放关联区间，正常静止场景应排除为故障。",
    ),
    rule(
        "VID-035",
        "帧率证据冲突",
        "视频",
        DiagnosticSeverity::Medium,
        "使用单一帧率可能误判卡顿、GOP 时长和恢复时间。",
        "核对编码器 SPS 时序信息、RTP 时间戳步进和容器探测口径。",
        "以抓包观测帧率复测，并确认播放器实际呈现节奏。",
    ),
    rule(
        "H265-036",
        "H.265 参数集缺失",
        "H.265",
        DiagnosticSeverity::Critical,
        "缺少 VPS、SPS 或 PPS 会使客户端无法可靠初始化解码。",
        "在随机接入点前发送完整 VPS/SPS/PPS。",
        "重新采样并确认三类参数集均存在。",
    ),
    rule(
        "H265-037",
        "H.265 NALU 重组不完整",
        "H.265",
        DiagnosticSeverity::Critical,
        "受影响帧可能花屏、丢失或触发参考帧错误。",
        "核对 RTP 序列缺口及 FU Start/End 完整性。",
        "按时间线包号过滤原始抓包复核。",
    ),
    rule(
        "H265-038",
        "首帧不是 H.265 随机接入帧",
        "H.265",
        DiagnosticSeverity::Medium,
        "客户端在采样起点可能无法立即显示画面。",
        "使新会话从 IDR 或 CRA 及参数集开始。",
        "重新连接并测量首个 IRAP 位置。",
    ),
    rule(
        "H265-039",
        "H.265 GOP 过长",
        "H.265",
        DiagnosticSeverity::Medium,
        "传输或解码异常后的恢复机会可能过晚。",
        "按实时性要求缩短随机接入间隔。",
        "确认最大 IRAP 间隔满足目标。",
    ),
    rule(
        "H265-040",
        "H.265 运行中分辨率变化",
        "H.265",
        DiagnosticSeverity::High,
        "未重新初始化解码器可能导致花屏或停画。",
        "变更参数时发送新参数集和随机接入帧。",
        "在变化点验证播放器是否重新初始化。",
    ),
    rule(
        "H264-049",
        "H.264 参数集字段变化",
        "H.264",
        DiagnosticSeverity::Medium,
        "Profile、位深、参考帧或编码工具变化时，未重新配置的解码器可能产生兼容性问题。",
        "在参数变化点发送完整 SPS/PPS 和 IDR，并确认接收端重新初始化。",
        "按报告中的 NALU、AU 和字段列表复核码流，并在变化点连续回放。",
    ),
    rule(
        "H265-050",
        "H.265 参数集字段变化",
        "H.265",
        DiagnosticSeverity::Medium,
        "Profile、层级、位深或编码结构变化时，未重新配置的解码器可能产生兼容性问题。",
        "在参数变化点发送完整 VPS/SPS/PPS 和随机接入帧，并确认接收端重新初始化。",
        "按报告中的 NALU、AU 和字段列表复核码流，并在变化点连续回放。",
    ),
    rule(
        "H264-051",
        "H.264 SPS 参考帧数超过 Level DPB 上限",
        "H.264",
        DiagnosticSeverity::High,
        "严格按 SPS Level 分配解码缓冲的播放器可能拒绝该流、丢弃参考帧或解码异常。",
        "降低 max_num_ref_frames，或为当前分辨率声明并满足更高的 Level。",
        "用标准校验器复核 SPS，并在目标硬件解码器上验证连续播放和随机接入。",
    ),
    rule(
        "H265-052",
        "H.265 SPS 解码图像缓冲超过 Level 上限",
        "H.265",
        DiagnosticSeverity::High,
        "严格按 SPS Level 分配解码缓冲的播放器可能拒绝该流或无法保留完整参考图像集合。",
        "降低 sps_max_dec_pic_buffering，或为当前分辨率声明并满足更高的 Level。",
        "用 HEVC 标准校验器复核 SPS，并在目标硬件解码器上验证参考帧密集场景。",
    ),
    rule(
        "H264-053",
        "H.264 VUI 解码缓冲约束矛盾",
        "H.264",
        DiagnosticSeverity::High,
        "播放器无法同时满足相互矛盾的参考帧、重排序帧和解码缓冲声明，可能拒绝码流或出现不一致的帧输出。",
        "修正 SPS VUI bitstream_restriction 参数，使 max_dec_frame_buffering 不小于参考帧数且不小于 max_num_reorder_frames。",
        "重新编码后复核 SPS，并在严格硬件解码器上验证启动、随机接入和连续播放。",
    ),
    rule(
        "H264-054",
        "H.264 实测平均码率超过 HRD 声明",
        "H.264",
        DiagnosticSeverity::High,
        "按 SPS HRD 配置缓冲的接收端可能发生 CPB 溢出、丢帧或播放不连续。",
        "提高 HRD bit_rate_value 声明或限制编码器输出码率，并保留足够的 CPB 容量。",
        "用至少一秒的完整样本复测；如需证明瞬时 CPB 溢出，再结合 Buffering Period/Picture Timing SEI 做逐 AU 仿真。",
    ),
    rule(
        "H264-055",
        "H.264 HRD CPB 逐 AU 仿真越界",
        "H.264",
        DiagnosticSeverity::High,
        "按 SPS HRD 参数和 SEI 时序运行的接收端可能发生 CPB 溢出或下溢，表现为丢帧、停顿或播放失败。",
        "核对编码器 HRD、VBV/CPB 和码率控制配置，并确保每个访问单元的 Buffering Period/Picture Timing SEI 连续有效。",
        "使用相同参数重新编码后复测，确认完整仿真范围内不再出现 CPB 溢出、下溢或 removal delay 不连续。",
    ),
    rule(
        "VIS-041",
        "疑似局部花屏或彩色破碎",
        "画面",
        DiagnosticSeverity::High,
        "局部破碎可能遮挡有效画面，并提示传输、参考帧或解码链路异常。",
        "优先核对同一时间点的 RTP 序列缺口、FU 完整性和 FFmpeg 参考帧错误。",
        "在软件内回放候选时间点，并用正常流复测排除高纹理场景误报。",
    ),
    rule(
        "AUD-042",
        "音频 RTP 时间轴不连续",
        "音频",
        DiagnosticSeverity::High,
        "时间戳缺口或重叠可能表现为丢音、爆音、重复播放或音画同步漂移。",
        "核对音频 RTP 序列号、时间戳增量、抓包完整性和设备音频发送节奏。",
        "按音频 SSRC 过滤并复核异常包前后的序列号与 RTP 时间戳。",
    ),
    rule(
        "AUD-043",
        "疑似持续静音",
        "音频",
        DiagnosticSeverity::Medium,
        "音轨存在但有效声音能量极低，可能来自静音配置、采集链路或现场本身无声。",
        "检查设备麦克风、增益、静音配置，并结合现场声源复测。",
        "制造可辨识声音后重新采样，确认 RMS 电平和静音采样比例恢复。",
    ),
    rule(
        "AUD-044",
        "音频存在削波风险",
        "音频",
        DiagnosticSeverity::High,
        "接近满幅的采样过多会产生明显失真、爆音并降低语音可懂度。",
        "降低前端或编码器增益，并检查模拟输入是否过载。",
        "使用相同声源复测，确认削波采样比例低于阈值且波形不再削顶。",
    ),
    rule(
        "AUD-046",
        "音频电平突变",
        "音频",
        DiagnosticSeverity::Medium,
        "短时间内超过 12 dB 的电平变化可能表现为声音忽大忽小、爆音或增益控制异常。",
        "检查设备自动增益、编码前处理、输入接触和异常点附近的 RTP 连续性。",
        "点击异常区间回听，并关闭自动增益后使用稳定声源复测。",
    ),
    rule(
        "AUD-047",
        "多声道电平失衡",
        "音频",
        DiagnosticSeverity::Medium,
        "声道间长期电平差过大可能导致声像偏移、单边声音过弱或采集链路异常。",
        "检查各声道增益、布线和声源位置，确认声道配置与现场一致。",
        "使用同电平测试信号复测，确认各声道 RMS 差值低于 6 dB。",
    ),
    rule(
        "AUD-048",
        "立体声疑似反相",
        "音频",
        DiagnosticSeverity::High,
        "左右声道高度负相关时，合并为单声道可能发生明显抵消，降低语音可懂度。",
        "检查左右声道极性、平衡接线和编码前的声道处理。",
        "用同相测试信号复测，确认相关系数不再接近 -1。",
    ),
    rule(
        "AVS-045",
        "音画同步偏差超限",
        "音画同步",
        DiagnosticSeverity::High,
        "内容事件或共同 RTCP 时钟下的音视频偏差超过 80 ms，可能形成可感知的不同步。",
        "核对发送端音视频时间戳基准、RTCP SR 生成和接收端缓冲策略。",
        "同一 CNAME 下重新采样并比较偏差与漂移；再用闪光/脉冲事件验证内容级同步。",
    ),
];

const fn rule(
    id: &'static str,
    title: &'static str,
    category: &'static str,
    severity: DiagnosticSeverity,
    impact: &'static str,
    suggestion: &'static str,
    verification: &'static str,
) -> RuleDefinition {
    RuleDefinition {
        id,
        title,
        category,
        severity,
        impact,
        suggestion,
        verification,
    }
}

pub fn rule_catalog() -> &'static [RuleDefinition] {
    &RULES
}

pub fn evaluate(result: &AnalysisResult) -> Vec<DiagnosticFinding> {
    if result.capture_summary.is_some() {
        return Vec::new();
    }
    RULES
        .iter()
        .filter(|definition| result.request.source_kind == streamscope_core::SourceKind::Rtsp || !definition.id.starts_with("RTSP-"))
        .filter_map(|definition| {
            evidence_for(definition.id, result).map(|(confidence, conclusion, evidence)| {
                let mut finding = DiagnosticFinding {
                    rule_id: definition.id.into(),
                    title: definition.title.into(),
                    category: definition.category.into(),
                    severity: definition.severity,
                    confidence_percent: confidence,
                    conclusion,
                    evidence,
                    impact: definition.impact.into(),
                    suggestions: vec![definition.suggestion.into()],
                    verification: vec![definition.verification.into()],
                };
                if result.request.source_kind == streamscope_core::SourceKind::Pcap {
                    if matches!(definition.id, "RTP-015" | "RTP-016") {
                        finding.title = "抓包中观测到 RTP 序列缺口".into();
                        finding.conclusion = "本流在抓包覆盖范围内存在序列缺口；需结合抓包完整性与收发端证据判断是否为网络丢包。".into();
                        finding.verification = vec!["按本流端点和 SSRC 过滤原始抓包，对照缺口前后包号，并在收发两端同步抓包复核。".into()];
                    }
                    if let Some(identity) = &result.capture_stream {
                        finding.evidence.push(DiagnosticEvidence {
                            label: "媒体流 / 抓包范围".into(),
                            value: format!("{} · {} → {} · SSRC {:08x} · #{}–#{}", identity.id, identity.source, identity.destination, identity.ssrc, identity.first_packet, identity.last_packet),
                        });
                    }
                }
                if result.data_quality.assessed
                    && !result.data_quality.sufficient_for_diagnosis
                    && (definition.id == "RTSP-007"
                        || matches!(
                            definition.id.split_once('-').map(|value| value.0),
                            Some("RTP" | "H264" | "H265" | "DEC" | "CMP" | "AUD" | "AVS")
                        ))
                {
                    finding.confidence_percent = finding.confidence_percent.min(55);
                    finding.severity = finding.severity.min(DiagnosticSeverity::Medium);
                    finding.conclusion = format!("样本不足，仅观察到：{}", finding.conclusion);
                    finding.evidence.push(DiagnosticEvidence {
                        label: "数据可信度".into(),
                        value: result.data_quality.reasons.join("；"),
                    });
                }
                finding
            })
        })
        .collect()
}

pub fn build_timeline(result: &AnalysisResult) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    let mut offset = 0_u64;
    if let Some(protocol) = &result.protocol {
        for (index, transaction) in protocol.transactions.iter().enumerate() {
            offset = offset.saturating_add(transaction.elapsed_ms);
            let authentication_challenge = transaction.status_code == 401
                && protocol.transactions[index + 1..]
                    .iter()
                    .any(|later| later.method == transaction.method && later.status_code < 300);
            events.push(TimelineEvent {
                offset_ms: Some(offset),
                source: "RTSP".into(),
                event_type: transaction.method.clone(),
                severity: if transaction.status_code >= 400 && !authentication_challenge {
                    DiagnosticSeverity::High
                } else {
                    DiagnosticSeverity::Info
                },
                sequence: None,
                rtp_timestamp: None,
                frame_number: None,
                first_packet: None,
                last_packet: None,
                location_precision: None,
                detail: if authentication_challenge {
                    format!(
                        "{} {}（鉴权挑战，随后成功；{} ms）",
                        transaction.status_code, transaction.reason, transaction.elapsed_ms
                    )
                } else {
                    format!(
                        "{} {}（{} ms）",
                        transaction.status_code, transaction.reason, transaction.elapsed_ms
                    )
                },
            });
        }
    }
    if let Some(h264) = &result.h264 {
        for issue in &h264.issues {
            if result.capture_stream.as_ref().is_some_and(|identity| {
                identity.events.iter().any(|event| {
                    event.kind == issue.kind
                        && event.sequence == issue.sequence
                        && event.rtp_timestamp == issue.timestamp
                })
            }) {
                continue;
            }
            events.push(TimelineEvent {
                offset_ms: None,
                source: "H264".into(),
                event_type: issue.kind.clone(),
                severity: severity_for_h264_issue(&issue.kind),
                sequence: issue.sequence,
                rtp_timestamp: issue.timestamp,
                frame_number: None,
                first_packet: None,
                last_packet: None,
                location_precision: None,
                detail: issue.detail.clone(),
            });
        }
        for change in &h264.parameter_changes {
            let nalu = h264
                .nalus
                .iter()
                .find(|nalu| nalu.nalu_number == change.nalu_number);
            events.push(TimelineEvent {
                offset_ms: nalu
                    .and_then(|nalu| nalu.packets.first().map(|packet| packet.offset_ms)),
                source: "H264".into(),
                event_type: "parameter_set_changed".into(),
                severity: DiagnosticSeverity::Medium,
                sequence: nalu.and_then(|nalu| nalu.first_sequence),
                rtp_timestamp: nalu.and_then(|nalu| nalu.rtp_timestamp),
                frame_number: change.effective_access_unit,
                first_packet: nalu
                    .and_then(|nalu| nalu.packets.first().map(|packet| packet.packet_number)),
                last_packet: nalu
                    .and_then(|nalu| nalu.packets.last().map(|packet| packet.packet_number)),
                location_precision: Some(
                    if nalu.is_some_and(|nalu| !nalu.packets.is_empty()) {
                        "exact_capture_packet_and_access_unit"
                    } else {
                        "exact_nalu_and_access_unit"
                    }
                    .into(),
                ),
                detail: format!(
                    "{} #{} 在 NALU #{} 更新，从 AU #{} 生效；变化字段：{}",
                    change.parameter_kind.to_uppercase(),
                    change.parameter_id,
                    change.nalu_number,
                    change
                        .effective_access_unit
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "未知".into()),
                    change.changed_fields.join("、")
                ),
            });
        }
        for point in h264.hrd_simulation.points.iter().filter(|point| {
            h264.hrd_simulation.status == "simulated_cbr_single_cpb"
                && (point.overflow || point.underflow)
        }) {
            let frame = h264
                .frames
                .iter()
                .find(|frame| frame.frame_number == point.access_unit);
            for (event_type, detail) in [
                (
                    point.overflow.then_some("cpb_overflow"),
                    format!(
                        "AU #{} 移除前 CPB fullness {} bits 超过声明容量",
                        point.access_unit, point.fullness_before_removal_bits
                    ),
                ),
                (
                    point.underflow.then_some("cpb_underflow"),
                    format!(
                        "AU #{} 需要 {} bits，但移除前 CPB fullness 仅 {} bits",
                        point.access_unit,
                        point.access_unit_bits,
                        point.fullness_before_removal_bits
                    ),
                ),
            ] {
                let Some(event_type) = event_type else {
                    continue;
                };
                events.push(TimelineEvent {
                    offset_ms: frame.and_then(|frame| frame.first_offset_ms),
                    source: "H264 HRD".into(),
                    event_type: event_type.into(),
                    severity: DiagnosticSeverity::High,
                    sequence: frame.and_then(|frame| frame.first_sequence),
                    rtp_timestamp: frame.and_then(|frame| frame.rtp_timestamp),
                    frame_number: Some(point.access_unit),
                    first_packet: frame.and_then(|frame| frame.first_packet),
                    last_packet: frame.and_then(|frame| frame.last_packet),
                    location_precision: Some(
                        if frame.and_then(|frame| frame.first_packet).is_some() {
                            "exact_access_unit_and_capture_packet"
                        } else {
                            "exact_access_unit"
                        }
                        .into(),
                    ),
                    detail,
                });
            }
        }
    }
    if let Some(h265) = &result.h265 {
        for issue in &h265.issues {
            if result.capture_stream.as_ref().is_some_and(|identity| {
                identity.events.iter().any(|event| {
                    event.kind == issue.kind
                        && event.sequence == issue.sequence
                        && event.rtp_timestamp == issue.timestamp
                })
            }) {
                continue;
            }
            events.push(TimelineEvent {
                offset_ms: None,
                source: "H265".into(),
                event_type: issue.kind.clone(),
                severity: severity_for_h265_issue(&issue.kind),
                sequence: issue.sequence,
                rtp_timestamp: issue.timestamp,
                frame_number: None,
                first_packet: None,
                last_packet: None,
                location_precision: None,
                detail: issue.detail.clone(),
            });
        }
        for change in &h265.parameter_changes {
            let nalu = h265
                .nalus
                .iter()
                .find(|nalu| nalu.nalu_number == change.nalu_number);
            events.push(TimelineEvent {
                offset_ms: nalu
                    .and_then(|nalu| nalu.packets.first().map(|packet| packet.offset_ms)),
                source: "H265".into(),
                event_type: "parameter_set_changed".into(),
                severity: DiagnosticSeverity::Medium,
                sequence: nalu.and_then(|nalu| nalu.first_sequence),
                rtp_timestamp: nalu.and_then(|nalu| nalu.rtp_timestamp),
                frame_number: change.effective_access_unit,
                first_packet: nalu
                    .and_then(|nalu| nalu.packets.first().map(|packet| packet.packet_number)),
                last_packet: nalu
                    .and_then(|nalu| nalu.packets.last().map(|packet| packet.packet_number)),
                location_precision: Some(
                    if nalu.is_some_and(|nalu| !nalu.packets.is_empty()) {
                        "exact_capture_packet_and_access_unit"
                    } else {
                        "exact_nalu_and_access_unit"
                    }
                    .into(),
                ),
                detail: format!(
                    "{} #{} 在 NALU #{} 更新，从 AU #{} 生效；变化字段：{}",
                    change.parameter_kind.to_uppercase(),
                    change.parameter_id,
                    change.nalu_number,
                    change
                        .effective_access_unit
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "未知".into()),
                    change.changed_fields.join("、")
                ),
            });
        }
    }
    if let Some(audio) = &result.audio {
        for issue in &audio.issues {
            if matches!(
                issue.kind.as_str(),
                "insufficient_sample" | "decode_not_supported"
            ) {
                continue;
            }
            events.push(TimelineEvent {
                offset_ms: issue.offset_ms,
                source: "Audio".into(),
                event_type: issue.kind.clone(),
                severity: severity_for_audio_issue(&issue.kind),
                sequence: None,
                rtp_timestamp: None,
                frame_number: None,
                first_packet: issue.first_packet,
                last_packet: issue.first_packet,
                location_precision: issue
                    .first_packet
                    .map(|_| "exact_capture_packet".into())
                    .or_else(|| issue.offset_ms.map(|_| "capture_time".into())),
                detail: issue.detail.clone(),
            });
        }
        if let Some(quality) = &audio.quality {
            for interval in &quality.intervals {
                events.push(TimelineEvent {
                    offset_ms: Some(interval.start_ms),
                    source: "Audio PCM".into(),
                    event_type: interval.kind.clone(),
                    severity: if audio.conclusion_reliable {
                        if interval.kind == "clipping_candidate" {
                            DiagnosticSeverity::High
                        } else {
                            DiagnosticSeverity::Medium
                        }
                    } else {
                        DiagnosticSeverity::Low
                    },
                    sequence: interval.first_rtp_sequence,
                    rtp_timestamp: None,
                    frame_number: None,
                    first_packet: interval.first_packet,
                    last_packet: interval.last_packet,
                    location_precision: Some(interval.precision.clone()),
                    detail: format!(
                        "声道 {} · +{}–+{} ms · {}",
                        interval
                            .channel
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "全部".into()),
                        interval.start_ms,
                        interval.end_ms,
                        interval.detail
                    ),
                });
            }
        }
    }
    if let Some(identity) = &result.capture_stream {
        for event in &identity.events {
            events.push(TimelineEvent {
                offset_ms: Some(event.offset_ms),
                source: if event.kind == "sequence_gap" {
                    "RTP"
                } else {
                    if event.kind.starts_with("h265_") {
                        "H265"
                    } else {
                        "H264"
                    }
                }
                .into(),
                event_type: event.kind.clone(),
                severity: if event.kind == "sequence_gap" {
                    DiagnosticSeverity::Medium
                } else {
                    if event.kind.starts_with("h265_") {
                        severity_for_h265_issue(&event.kind)
                    } else {
                        severity_for_h264_issue(&event.kind)
                    }
                    .min(DiagnosticSeverity::Medium)
                },
                sequence: event.sequence,
                rtp_timestamp: event.rtp_timestamp,
                frame_number: None,
                first_packet: Some(event.packet_number),
                last_packet: Some(event.packet_number),
                location_precision: Some("exact_capture_packet".into()),
                detail: format!(
                    "{} · 抓包 #{} · {}",
                    identity.id, event.packet_number, event.detail
                ),
            });
        }
    }
    if let Some(decode) = &result.decode {
        for issue in &decode.issues {
            if issue.locations.is_empty() {
                events.push(TimelineEvent {
                    offset_ms: None,
                    source: "FFmpeg".into(),
                    event_type: issue.kind.clone(),
                    severity: severity_for_decode_issue(&issue.kind),
                    sequence: None,
                    rtp_timestamp: None,
                    frame_number: None,
                    first_packet: None,
                    last_packet: None,
                    location_precision: Some("unlocated".into()),
                    detail: format!(
                        "{} 次；FFmpeg 未提供可关联的帧位置：{}",
                        issue.count, issue.example
                    ),
                });
                continue;
            }
            for location in &issue.locations {
                let visual_candidate = location.precision.starts_with("visual_scan_");
                let frame = (!visual_candidate)
                    .then(|| frame_evidence(result, location.frame_number))
                    .flatten();
                let offset_ms = frame.and_then(|frame| frame.first_offset_ms).or_else(|| {
                    location
                        .pts_time
                        .as_deref()
                        .and_then(|value| value.parse::<f64>().ok())
                        .filter(|value| value.is_finite() && *value >= 0.0)
                        .map(|value| (value * 1_000.0) as u64)
                });
                let packet_range = frame
                    .and_then(|frame| frame.first_packet.zip(frame.last_packet))
                    .map(|(first, last)| format!("，关联抓包 #{}–#{}", first, last))
                    .unwrap_or_default();
                let location_note = if visual_candidate {
                    "按 8 fps 缩略画面扫描定位，仅代表候选时间点"
                } else if location.precision == "filter_timestamp_nearest_frame" {
                    "按画面检测器时间戳关联到邻近帧，属于候选区间"
                } else {
                    "按 FFmpeg 日志邻近位置关联，不作为精确根因证明"
                };
                events.push(TimelineEvent {
                    offset_ms,
                    source: "FFmpeg".into(),
                    event_type: issue.kind.clone(),
                    severity: severity_for_decode_issue(&issue.kind),
                    sequence: frame.and_then(|frame| frame.first_sequence),
                    rtp_timestamp: frame.and_then(|frame| frame.rtp_timestamp),
                    frame_number: Some(location.frame_number),
                    first_packet: frame.and_then(|frame| frame.first_packet),
                    last_packet: frame.and_then(|frame| frame.last_packet),
                    location_precision: Some(location.precision.clone()),
                    detail: format!(
                        "候选帧 #{}{}；{}：{}",
                        location.frame_number, packet_range, location_note, issue.example
                    ),
                });
                if !visual_candidate
                    && !matches!(issue.kind.as_str(), "black_segment" | "freeze_segment")
                    && let Some(next_idr) = next_random_access_frame(result, location.frame_number)
                    && !events.iter().any(|event| {
                        event.event_type == "next_random_access_opportunity"
                            && event.frame_number == Some(next_idr.frame_number)
                            && event
                                .detail
                                .contains(&format!("源候选帧 #{}", location.frame_number))
                    })
                {
                    let frame_gap = next_idr.frame_number.saturating_sub(location.frame_number);
                    let time_gap = frame
                        .and_then(|current| current.first_offset_ms)
                        .zip(next_idr.first_offset_ms)
                        .map(|(current, next)| next.saturating_sub(current));
                    events.push(TimelineEvent {
                        offset_ms: next_idr.first_offset_ms,
                        source: if result.h265.is_some() { "H265" } else { "H264" }.into(),
                        event_type: "next_random_access_opportunity".into(),
                        severity: DiagnosticSeverity::Info,
                        sequence: next_idr.first_sequence,
                        rtp_timestamp: next_idr.rtp_timestamp,
                        frame_number: Some(next_idr.frame_number),
                        first_packet: next_idr.first_packet,
                        last_packet: next_idr.last_packet,
                        location_precision: Some("exact_h264_frame_index".into()),
                        detail: format!(
                            "源候选帧 #{} 后 {} 帧出现下一张 IDR/CRA{}；这是解码恢复机会，不等于已经恢复",
                            location.frame_number, frame_gap,
                            time_gap
                                .map(|value| format!("（约 {value} ms）"))
                                .unwrap_or_default()
                        ),
                    });
                }
            }
        }
    }
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
    for window in recovery_windows {
        let Some(frame_number) = window.next_random_access_frame else {
            continue;
        };
        if events.iter().any(|event| {
            event.event_type == "next_random_access_opportunity"
                && event.frame_number == Some(frame_number)
                && event.detail.contains(&format!("#{}", window.source_frame))
        }) {
            continue;
        }
        events.push(TimelineEvent {
            offset_ms: window.next_random_access_offset_ms,
            source: if result.h265.is_some() {
                "H265"
            } else {
                "H264"
            }
            .into(),
            event_type: "next_random_access_opportunity".into(),
            severity: DiagnosticSeverity::Info,
            sequence: None,
            rtp_timestamp: None,
            frame_number: Some(frame_number),
            first_packet: window.first_packet,
            last_packet: window.last_packet,
            location_precision: Some("structured_recovery_window".into()),
            detail: format!(
                "异常起点 #{}（{}）后观察到随机接入帧 #{}，等待 {} 帧{}；画面恢复状态：{}",
                window.source_frame,
                window.source_kind,
                frame_number,
                window.wait_frames.unwrap_or(0),
                window
                    .wait_ms
                    .map(|value| format!(" / {value} ms"))
                    .unwrap_or_default(),
                if window.visual_status == "post_access_anomaly_candidate" {
                    "随机接入后仍有异常候选"
                } else {
                    "未确认"
                }
            ),
        });
    }
    for error in &result.errors {
        events.push(TimelineEvent {
            offset_ms: None,
            source: "运行时".into(),
            event_type: "execution_error".into(),
            severity: DiagnosticSeverity::High,
            sequence: None,
            rtp_timestamp: None,
            frame_number: None,
            first_packet: None,
            last_packet: None,
            location_precision: None,
            detail: error.clone(),
        });
    }
    events.sort_by_key(|event| event.offset_ms.unwrap_or(u64::MAX));
    events
}

fn frame_evidence(
    result: &AnalysisResult,
    frame_number: u64,
) -> Option<&streamscope_core::H264FrameEvidence> {
    result
        .h264
        .as_ref()
        .and_then(|analysis| {
            analysis
                .frames
                .iter()
                .find(|frame| frame.frame_number == frame_number)
        })
        .or_else(|| {
            result.h265.as_ref().and_then(|analysis| {
                analysis
                    .frames
                    .iter()
                    .find(|frame| frame.frame_number == frame_number)
            })
        })
}

fn next_random_access_frame(
    result: &AnalysisResult,
    frame_number: u64,
) -> Option<&streamscope_core::H264FrameEvidence> {
    result
        .h264
        .as_ref()
        .and_then(|analysis| {
            analysis
                .frames
                .iter()
                .find(|frame| frame.idr && frame.frame_number > frame_number)
        })
        .or_else(|| {
            result.h265.as_ref().and_then(|analysis| {
                analysis
                    .frames
                    .iter()
                    .find(|frame| frame.idr && frame.frame_number > frame_number)
            })
        })
}

fn severity_for_decode_issue(kind: &str) -> DiagnosticSeverity {
    match kind {
        "corrupt_frame"
        | "missing_reference"
        | "invalid_nal_unit"
        | "bitstream_syntax_error"
        | "visual_corruption_candidate" => DiagnosticSeverity::High,
        "macroblock_error" | "concealment" | "slice_header_error" | "missing_pps" => {
            DiagnosticSeverity::Medium
        }
        _ => DiagnosticSeverity::Low,
    }
}

fn h264_level_max_reference_frames(sps: &streamscope_core::H264SpsInfo) -> Option<u32> {
    let max_dpb_mbs = match sps.level_idc {
        10 => 396,
        11 if sps.constraint_set3_flag => 396,
        11 => 900,
        12 | 13 | 20 => 2_376,
        21 => 4_752,
        22 | 30 => 8_100,
        31 => 18_000,
        32 => 20_480,
        40 | 41 => 32_768,
        42 => 34_816,
        50 => 110_400,
        51 | 52 => 184_320,
        60..=62 => 696_320,
        _ => return None,
    };
    let picture_mbs = sps
        .width
        .div_ceil(16)
        .checked_mul(sps.height.div_ceil(16))?;
    if picture_mbs == 0 {
        return None;
    }
    let maximum = (max_dpb_mbs / picture_mbs).min(16);
    let declared_buffering = sps
        .max_dec_frame_buffering
        .unwrap_or(sps.max_num_ref_frames);
    (sps.max_num_ref_frames > maximum || declared_buffering > maximum).then_some(maximum)
}

fn h265_level_max_dpb_frames(sps: &streamscope_core::H265SpsInfo) -> Option<u32> {
    let max_luma_samples = match sps.level_idc {
        30 => 36_864_u64,
        60 => 122_880,
        63 => 245_760,
        90 => 552_960,
        93 => 983_040,
        120 | 123 => 2_228_224,
        150 | 153 | 156 => 8_912_896,
        180 | 183 | 186 => 35_651_584,
        _ => return None,
    };
    let picture_samples = u64::from(sps.width).checked_mul(u64::from(sps.height))?;
    if picture_samples == 0 || picture_samples > max_luma_samples {
        return None;
    }
    let maximum = if picture_samples <= max_luma_samples / 4 {
        16
    } else if picture_samples <= max_luma_samples / 2 {
        12
    } else if picture_samples <= max_luma_samples * 3 / 4 {
        8
    } else {
        6
    };
    sps.max_dec_pic_buffering
        .filter(|declared| *declared > maximum)
        .map(|_| maximum)
}

fn evidence_for(
    id: &str,
    result: &AnalysisResult,
) -> Option<(u8, String, Vec<DiagnosticEvidence>)> {
    let protocol = result.protocol.as_ref();
    let h264 = result.h264.as_ref();
    let h265 = result.h265.as_ref();
    let audio = result.audio.as_ref();
    let errors = result.errors.join("\n").to_lowercase();
    let h264_has =
        |kind: &str| h264.is_some_and(|value| value.issues.iter().any(|issue| issue.kind == kind));
    let h265_has =
        |kind: &str| h265.is_some_and(|value| value.issues.iter().any(|issue| issue.kind == kind));
    let h265_starts = |prefix: &str| {
        h265.is_some_and(|value| {
            value
                .issues
                .iter()
                .any(|issue| issue.kind.starts_with(prefix))
        })
    };
    let one = |label: &str, value: String| {
        vec![DiagnosticEvidence {
            label: label.into(),
            value,
        }]
    };
    match id {
        "RTSP-001"
            if protocol.is_none()
                && (errors.contains("connect")
                    || errors.contains("连接")
                    || errors.contains("refused")) =>
        {
            Some((
                80,
                "未能建立 RTSP 协议会话。".into(),
                one("执行错误", result.errors.join("；")),
            ))
        }
        "RTSP-002" if errors.contains("timeout") || errors.contains("超时") => Some((
            85,
            "至少一个 RTSP 或媒体操作发生超时。".into(),
            one("执行错误", result.errors.join("；")),
        )),
        "RTSP-003"
            if errors.contains("401")
                || errors.contains("鉴权")
                || errors.contains("unauthorized") =>
        {
            Some((
                90,
                "服务端拒绝了鉴权。".into(),
                one("执行错误", result.errors.join("；")),
            ))
        }
        "RTSP-004" if errors.contains("sdp") => Some((
            75,
            "SDP 未能被可靠解析。".into(),
            one("执行错误", result.errors.join("；")),
        )),
        "RTSP-005" if errors.contains("control uri") => Some((
            85,
            "媒体 Control URI 无法解析。".into(),
            one("执行错误", result.errors.join("；")),
        )),
        "RTSP-006"
            if errors.contains("setup")
                || protocol
                    .and_then(|p| {
                        p.transactions
                            .iter()
                            .rev()
                            .find(|transaction| transaction.method == "SETUP")
                    })
                    .is_some_and(|transaction| transaction.status_code >= 400) =>
        {
            Some((
                90,
                "RTSP SETUP 最终未成功完成。".into(),
                one("最终 SETUP", "返回失败状态或执行错误".into()),
            ))
        }
        "RTSP-007"
            if protocol.is_some_and(|p| {
                p.transactions
                    .iter()
                    .any(|t| t.method == "PLAY" && t.status_code < 300)
                    && p.rtp.packet_count == 0
            }) =>
        {
            Some((
                95,
                "PLAY 已成功响应，但采样窗口内没有收到 RTP。".into(),
                one("RTP 包数", "0".into()),
            ))
        }
        "SDP-010"
            if protocol.is_some_and(|p| {
                p.media
                    .iter()
                    .any(|m| m.frame_size.as_deref().is_some_and(invalid_dimensions))
            }) =>
        {
            Some((
                90,
                "SDP 声明了零值或无效分辨率。".into(),
                one("framesize", "包含零值或非法格式".into()),
            ))
        }
        "SDP-011"
            if protocol.is_some_and(|p| {
                p.media
                    .iter()
                    .any(|m| m.frame_rate.as_deref().is_some_and(invalid_rate))
            }) =>
        {
            Some((
                85,
                "SDP 声明的帧率无效。".into(),
                one("framerate", "零值或无法解析".into()),
            ))
        }
        "H264-012" if h264_has("missing_sps") || h264_has("missing_pps") => Some((
            95,
            "采样码流缺少 SPS 或 PPS。".into(),
            one(
                "参数集",
                format!("SPS {} / PPS {}", h264?.sps.len(), h264?.pps.len()),
            ),
        )),
        "H264-013" if h264_has("invalid_sps") || h264_has("invalid_pps") => Some((
            95,
            "至少一个参数集解析失败。".into(),
            one("H.264 异常", "invalid_sps / invalid_pps".into()),
        )),
        "H264-014" => resolution_mismatch(result),
        "RTP-015" if protocol.is_some_and(|p| p.rtp.lost_packets > 0) => Some((
            95,
            "RTP 序列号显示存在缺包。".into(),
            one("估算丢包", protocol?.rtp.lost_packets.to_string()),
        )),
        "RTP-016"
            if protocol
                .is_some_and(|p| p.rtp.maximum_sequence_gap > 1 && p.rtp.lost_packets > 0) =>
        {
            Some((
                95,
                "到达时曾观测到连续序列缺口，且最终仍有未补齐缺包；最大缺口可能包含后续补到包。"
                    .into(),
                one(
                    "最大到达时缺口",
                    protocol?.rtp.maximum_sequence_gap.to_string(),
                ),
            ))
        }
        "RTP-017" if protocol.is_some_and(|p| p.rtp.out_of_order_packets > 0) => Some((
            95,
            "检测到 RTP 包乱序。".into(),
            one("乱序包", protocol?.rtp.out_of_order_packets.to_string()),
        )),
        "RTP-018" if protocol.is_some_and(|p| p.rtp.duplicate_packets > 0) => Some((
            95,
            "检测到重复 RTP 序列号。".into(),
            one("重复包", protocol?.rtp.duplicate_packets.to_string()),
        )),
        "RTP-019" if protocol.is_some_and(|p| p.rtp.timestamp_rollbacks > 0) => Some((
            95,
            "同一采样中 RTP 时间戳发生回退。".into(),
            one("时间戳回退", protocol?.rtp.timestamp_rollbacks.to_string()),
        )),
        "RTP-020" if protocol.is_some_and(|p| p.rtp.ssrc_changes > 0) => Some((
            90,
            "采样期间 RTP SSRC 发生变化。".into(),
            one("SSRC 变化", protocol?.rtp.ssrc_changes.to_string()),
        )),
        "RTP-021" if h264_has("missing_marker") => Some((
            90,
            "至少一个访问单元未观察到 RTP Marker。".into(),
            one("H.264 异常", "missing_marker".into()),
        )),
        "H264-022" if h264.is_some_and(|v| v.incomplete_nalus > 0) => {
            let analysis = h264?;
            let mut evidence = one("不完整 NALU", analysis.incomplete_nalus.to_string());
            if let Some(nalu) = analysis.nalus.iter().find(|nalu| !nalu.complete) {
                evidence.push(DiagnosticEvidence {
                    label: "首个不完整 NALU".into(),
                    value: format!(
                        "#{} {}，AU {}，RTP Seq {}→{}",
                        nalu.nalu_number,
                        nalu.type_name,
                        nalu.access_unit_number
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "未知".into()),
                        nalu.first_sequence
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "未知".into()),
                        nalu.last_sequence
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "未知".into())
                    ),
                });
                if !nalu.packets.is_empty() {
                    evidence.push(DiagnosticEvidence {
                        label: "已捕获包".into(),
                        value: nalu
                            .packets
                            .iter()
                            .take(20)
                            .map(|packet| {
                                format!("#{}(Seq {})", packet.packet_number, packet.rtp_sequence)
                            })
                            .collect::<Vec<_>>()
                            .join("、"),
                    });
                }
            }
            Some((95, "存在未完整重组的 H.264 NALU。".into(), evidence))
        }
        "H264-023" if h264.is_some_and(|v| v.first_frame_is_idr == Some(false)) => Some((
            95,
            "采样到的首个视频帧不是 IDR。".into(),
            one("首帧 IDR", "否".into()),
        )),
        "H264-024"
            if h264.is_some_and(|v| v.first_idr_frame.is_some_and(|position| position > 30)) =>
        {
            Some((
                85,
                "首个 IDR 出现在第 30 帧之后。".into(),
                one("首个 IDR 帧", h264?.first_idr_frame?.to_string()),
            ))
        }
        "H264-025" if h264.is_some_and(|v| v.maximum_gop_frames.is_some_and(|gop| gop > 100)) => {
            Some((
                85,
                "采样到的最大 GOP 超过 100 帧。".into(),
                one("最大 GOP", h264?.maximum_gop_frames?.to_string()),
            ))
        }
        "H264-026"
            if h264.is_some_and(|v| {
                v.idr_frames > 0 && (!v.sps_before_first_idr || !v.pps_before_first_idr)
            }) =>
        {
            Some((
                95,
                "首个 IDR 前没有同时观察到 SPS 和 PPS。".into(),
                one(
                    "IDR 前参数集",
                    format!(
                        "SPS={}，PPS={}",
                        h264?.sps_before_first_idr, h264?.pps_before_first_idr
                    ),
                ),
            ))
        }
        "H264-027" if h264_has("resolution_changed") => Some((
            95,
            "同一 SPS ID 在采样中声明了不同分辨率。".into(),
            one("H.264 异常", "resolution_changed".into()),
        )),
        "DEC-028" if decode_has(result, &["missing_reference", "reference", "ref pic"]) => Some((
            80,
            "FFmpeg 日志包含参考帧缺失证据。".into(),
            decode_evidence(result, &["missing_reference", "reference", "ref pic"]),
        )),
        "DEC-029" if decode_has(result, &["macroblock", "concealment", "mb_type"]) => Some((
            80,
            "FFmpeg 日志包含宏块或错误隐藏证据。".into(),
            decode_evidence(result, &["macroblock", "concealment", "mb_type"]),
        )),
        "REC-031" => {
            let source_location = result
                .decode
                .as_ref()?
                .issues
                .iter()
                .filter(|issue| {
                    !matches!(
                        issue.kind.as_str(),
                        "black_segment" | "freeze_segment" | "visual_corruption_candidate"
                    )
                })
                .flat_map(|issue| issue.locations.iter())
                .find(|location| {
                    next_random_access_frame(result, location.frame_number).is_some()
                })?;
            let source_frame = frame_evidence(result, source_location.frame_number)?;
            let recovery = next_random_access_frame(result, source_location.frame_number)?;
            let frame_gap = recovery
                .frame_number
                .saturating_sub(source_location.frame_number);
            let time_gap = source_frame
                .first_offset_ms
                .zip(recovery.first_offset_ms)
                .map(|(start, end)| end.saturating_sub(start));
            if frame_gap <= 100 && time_gap.is_none_or(|value| value <= 3_000) {
                None
            } else {
                Some((
                    75,
                    "解码异常候选之后，下一处 IDR/CRA 随机接入机会等待较长；这不等同于已确认画面恢复。".into(),
                    vec![
                        DiagnosticEvidence {
                            label: "异常候选帧".into(),
                            value: format!("#{}", source_location.frame_number),
                        },
                        DiagnosticEvidence {
                            label: "下一随机接入帧".into(),
                            value: format!("#{}", recovery.frame_number),
                        },
                        DiagnosticEvidence {
                            label: "等待范围".into(),
                            value: format!(
                                "{} 帧{}",
                                frame_gap,
                                time_gap
                                    .map(|value| format!("，约 {value} ms"))
                                    .unwrap_or_default()
                            ),
                        },
                    ],
                ))
            }
        }
        "VIS-033" if decode_has(result, &["black_segment"]) => Some((
            65,
            "画面检测器发现疑似黑屏区间；暗场也可能触发，不能单独认定故障。".into(),
            decode_evidence(result, &["black_segment"]),
        )),
        "VIS-034" if decode_has(result, &["freeze_segment"]) => Some((
            65,
            "画面检测器发现疑似冻结区间；静止场景也可能触发，不能单独认定故障。".into(),
            decode_evidence(result, &["freeze_segment"]),
        )),
        "VID-035"
            if result
                .stream
                .as_ref()
                .is_some_and(|stream| stream.frame_rate_conflict) =>
        {
            let stream = result.stream.as_ref()?;
            Some((
                95,
                "SPS、ffprobe 或抓包观测帧率之间存在显著偏差。".into(),
                vec![
                    DiagnosticEvidence {
                        label: "SPS 声明".into(),
                        value: stream.sps_frame_rate.clone().unwrap_or_else(|| "—".into()),
                    },
                    DiagnosticEvidence {
                        label: "ffprobe 探测".into(),
                        value: stream
                            .probed_frame_rate
                            .clone()
                            .unwrap_or_else(|| "—".into()),
                    },
                    DiagnosticEvidence {
                        label: "抓包观测".into(),
                        value: stream
                            .observed_frame_rate
                            .clone()
                            .unwrap_or_else(|| "—".into()),
                    },
                ],
            ))
        }
        "H265-036"
            if h265_has("h265_missing_vps")
                || h265_has("h265_missing_sps")
                || h265_has("h265_missing_pps")
                || h265.is_some_and(|analysis| {
                    analysis.irap_frames > 0
                        && (!analysis.vps_before_first_irap
                            || !analysis.sps_before_first_irap
                            || !analysis.pps_before_first_irap)
                }) =>
        {
            Some((
                95,
                "采样码流缺少 H.265 VPS、SPS 或 PPS，或首个随机接入帧前参数集不完整。".into(),
                one(
                    "参数集",
                    format!(
                        "VPS {} / SPS {} / PPS {}",
                        h265?.vps_count,
                        h265?.sps.len(),
                        h265?.pps.len()
                    ),
                ),
            ))
        }
        "H265-037"
            if h265.is_some_and(|analysis| analysis.incomplete_nalus > 0)
                || h265_starts("h265_fu_")
                || h265_has("h265_ap_length") =>
        {
            let analysis = h265?;
            let mut evidence = one("不完整 NALU", analysis.incomplete_nalus.to_string());
            if let Some(nalu) = analysis.nalus.iter().find(|nalu| !nalu.complete) {
                evidence.push(DiagnosticEvidence {
                    label: "首个不完整 NALU".into(),
                    value: format!(
                        "#{} {}，AU {}，RTP Seq {}→{}",
                        nalu.nalu_number,
                        nalu.type_name,
                        nalu.access_unit_number
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "未知".into()),
                        nalu.first_sequence
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "未知".into()),
                        nalu.last_sequence
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "未知".into())
                    ),
                });
            }
            Some((
                95,
                "存在未完整重组的 H.265 NALU 或 RTP 封包结构异常。".into(),
                evidence,
            ))
        }
        "H265-038" if h265.is_some_and(|analysis| analysis.first_frame_is_irap == Some(false)) => {
            Some((
                90,
                "采样到的首个 H.265 视频帧不是 IDR/CRA/BLA。".into(),
                one("首帧 IRAP", "否".into()),
            ))
        }
        "H265-039"
            if h265.is_some_and(|analysis| {
                analysis.maximum_gop_frames.is_some_and(|gop| gop > 100)
            }) =>
        {
            Some((
                85,
                "H.265 最大随机接入间隔超过 100 帧。".into(),
                one("最大 GOP", h265?.maximum_gop_frames?.to_string()),
            ))
        }
        "H265-040" if h265_has("h265_resolution_changed") => Some((
            95,
            "同一 H.265 SPS ID 在采样中声明了不同分辨率。".into(),
            one("H.265 异常", "h265_resolution_changed".into()),
        )),
        "H264-049"
            if h264.is_some_and(|analysis| {
                analysis.parameter_changes.iter().any(|change| {
                    change
                        .changed_fields
                        .iter()
                        .any(|field| field != "resolution")
                })
            }) =>
        {
            let changes = h264?
                .parameter_changes
                .iter()
                .filter(|change| {
                    change
                        .changed_fields
                        .iter()
                        .any(|field| field != "resolution")
                })
                .take(8)
                .map(|change| DiagnosticEvidence {
                    label: format!(
                        "{} #{}",
                        change.parameter_kind.to_uppercase(),
                        change.parameter_id
                    ),
                    value: format!(
                        "NALU #{}，从 AU #{} 生效：{}",
                        change.nalu_number,
                        change
                            .effective_access_unit
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "未知".into()),
                        change.changed_fields.join("、")
                    ),
                })
                .collect();
            Some((85, "检测到同一参数集 ID 的实际字段变化。".into(), changes))
        }
        "H265-050"
            if h265.is_some_and(|analysis| {
                analysis.parameter_changes.iter().any(|change| {
                    change
                        .changed_fields
                        .iter()
                        .any(|field| field != "resolution")
                })
            }) =>
        {
            let changes = h265?
                .parameter_changes
                .iter()
                .filter(|change| {
                    change
                        .changed_fields
                        .iter()
                        .any(|field| field != "resolution")
                })
                .take(8)
                .map(|change| DiagnosticEvidence {
                    label: format!(
                        "{} #{}",
                        change.parameter_kind.to_uppercase(),
                        change.parameter_id
                    ),
                    value: format!(
                        "NALU #{}，从 AU #{} 生效：{}",
                        change.nalu_number,
                        change
                            .effective_access_unit
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "未知".into()),
                        change.changed_fields.join("、")
                    ),
                })
                .collect();
            Some((85, "检测到同一参数集 ID 的实际字段变化。".into(), changes))
        }
        "H264-051" => {
            let (sps, maximum) = h264?.sps.iter().find_map(|sps| {
                h264_level_max_reference_frames(sps).map(|maximum| (sps, maximum))
            })?;
            Some((
                95,
                "SPS 声明的参考帧数或 VUI 解码缓冲帧数超过该 Level 在当前分辨率下可容纳的最大帧数。".into(),
                vec![
                    DiagnosticEvidence {
                        label: "SPS / Level".into(),
                        value: format!("SPS #{} / level_idc {}", sps.id, sps.level_idc),
                    },
                    DiagnosticEvidence {
                        label: "分辨率".into(),
                        value: format!("{}×{}", sps.width, sps.height),
                    },
                    DiagnosticEvidence {
                        label: "参考帧 / VUI 缓冲 / Level DPB 上限".into(),
                        value: format!(
                            "{} / {} / {} 帧",
                            sps.max_num_ref_frames,
                            sps.max_dec_frame_buffering
                                .map(|value| value.to_string())
                                .unwrap_or_else(|| "未声明".into()),
                            maximum
                        ),
                    },
                ],
            ))
        }
        "H265-052" => {
            let (sps, declared, maximum) = h265?.sps.iter().find_map(|sps| {
                h265_level_max_dpb_frames(sps)
                    .zip(sps.max_dec_pic_buffering)
                    .map(|(maximum, declared)| (sps, declared, maximum))
            })?;
            Some((
                95,
                "SPS 声明的解码图像缓冲帧数超过该 Level 在当前分辨率下的上限。".into(),
                vec![
                    DiagnosticEvidence {
                        label: "SPS / Level".into(),
                        value: format!("SPS #{} / level_idc {}", sps.id, sps.level_idc),
                    },
                    DiagnosticEvidence {
                        label: "分辨率".into(),
                        value: format!("{}×{}", sps.width, sps.height),
                    },
                    DiagnosticEvidence {
                        label: "解码图像缓冲声明 / DPB 上限".into(),
                        value: format!("{} / {} 帧", declared, maximum),
                    },
                ],
            ))
        }
        "H264-053" => {
            let sps = h264?.sps.iter().find(|sps| {
                sps.max_dec_frame_buffering.is_some_and(|buffering| {
                    buffering < sps.max_num_ref_frames
                        || sps
                            .max_num_reorder_frames
                            .is_some_and(|reorder| reorder > buffering)
                })
            })?;
            let buffering = sps.max_dec_frame_buffering?;
            Some((
                100,
                "SPS VUI 的 bitstream restriction 字段存在可确定的内部矛盾。".into(),
                vec![DiagnosticEvidence {
                    label: format!("SPS #{} 缓冲约束", sps.id),
                    value: format!(
                        "max_num_ref_frames={}，max_num_reorder_frames={}，max_dec_frame_buffering={}",
                        sps.max_num_ref_frames,
                        sps.max_num_reorder_frames
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "未声明".into()),
                        buffering
                    ),
                }],
            ))
        }
        "H264-054" => {
            let protocol = protocol?;
            let duration_ms = protocol.sample_duration_ms?;
            if duration_ms < 1_000 || result.data_quality.capture_truncated {
                return None;
            }
            let observed = protocol.rtp.average_bit_rate_bps?;
            let (sps, declared) = h264?.sps.iter().find_map(|sps| {
                let declared = [sps.nal_hrd.as_ref(), sps.vcl_hrd.as_ref()]
                    .into_iter()
                    .flatten()
                    .map(|hrd| hrd.maximum_bit_rate_bps)
                    .max()?;
                (observed > declared.saturating_mul(105) / 100).then_some((sps, declared))
            })?;
            Some((
                95,
                "完整样本中的 RTP 视频载荷平均码率超过 SPS HRD 声明的最大码率。".into(),
                vec![
                    DiagnosticEvidence {
                        label: "实测平均载荷码率".into(),
                        value: format!("{} bps（样本 {} ms）", observed, duration_ms),
                    },
                    DiagnosticEvidence {
                        label: format!("SPS #{} HRD 最大码率", sps.id),
                        value: format!("{} bps", declared),
                    },
                    DiagnosticEvidence {
                        label: "判定边界".into(),
                        value: "该规则证明平均码率越界；瞬时 CPB 溢出仍需 SEI 时序仿真。".into(),
                    },
                ],
            ))
        }
        "H264-055" => {
            let simulation = &h264?.hrd_simulation;
            if simulation.status != "simulated_cbr_single_cpb"
                || (simulation.overflow_aus.is_empty() && simulation.underflow_aus.is_empty())
            {
                return None;
            }
            let overflow = simulation
                .overflow_aus
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join("、");
            let underflow = simulation
                .underflow_aus
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join("、");
            let first = simulation
                .points
                .iter()
                .find(|point| point.overflow || point.underflow);
            let mut evidence = vec![
                DiagnosticEvidence {
                    label: "仿真范围".into(),
                    value: format!(
                        "{} schedule，SPS #{}，{} 个 AU",
                        simulation.schedule.to_uppercase(),
                        simulation
                            .sps_id
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "—".into()),
                        simulation.simulated_aus
                    ),
                },
                DiagnosticEvidence {
                    label: "CPB 溢出 AU".into(),
                    value: if overflow.is_empty() {
                        "无".into()
                    } else {
                        overflow
                    },
                },
                DiagnosticEvidence {
                    label: "CPB 下溢 AU".into(),
                    value: if underflow.is_empty() {
                        "无".into()
                    } else {
                        underflow
                    },
                },
            ];
            if let Some(point) = first {
                evidence.push(DiagnosticEvidence {
                    label: format!("首个越界 AU #{}", point.access_unit),
                    value: format!(
                        "AU={} bits，移除前/后 fullness={}/{} bits，cpb_removal_delay={}",
                        point.access_unit_bits,
                        point.fullness_before_removal_bits,
                        point.fullness_after_removal_bits,
                        point.cpb_removal_delay
                    ),
                });
            }
            evidence.push(DiagnosticEvidence {
                label: "判定边界".into(),
                value: "基于保留 NALU 字节、SPS HRD 和 SEI 时序；不包含 RTP、容器及网络传输开销。"
                    .into(),
            });
            Some((
                98,
                "单 CPB、CBR 的逐访问单元 HRD 仿真已观察到 CPB fullness 越界。".into(),
                evidence,
            ))
        }
        "VIS-041" if decode_has(result, &["visual_corruption_candidate"]) => Some((
            78,
            "画面级抽样发现疑似局部花屏或彩色破碎；这是启发式候选，需用内嵌回放确认。".into(),
            decode_evidence(result, &["visual_corruption_candidate"]),
        )),
        "AUD-042"
            if audio.is_some_and(|value| {
                value.timestamp_gap_count > 0 || value.timestamp_overlap_count > 0
            }) =>
        {
            Some((
                90,
                "音频 RTP 时间轴存在缺口或重叠。".into(),
                vec![
                    DiagnosticEvidence {
                        label: "时间戳缺口".into(),
                        value: audio?.timestamp_gap_count.to_string(),
                    },
                    DiagnosticEvidence {
                        label: "时间戳重叠".into(),
                        value: audio?.timestamp_overlap_count.to_string(),
                    },
                ],
            ))
        }
        "AUD-043"
            if audio.is_some_and(|value| {
                value.conclusion_reliable
                    && value
                        .issues
                        .iter()
                        .any(|issue| issue.kind == "near_silence")
            }) =>
        {
            Some((
                85,
                "可信样本中至少 95% 的 PCM 采样低于 -40 dBFS，疑似持续静音。".into(),
                one(
                    "RMS 电平",
                    audio?
                        .rms_level_dbfs_milli
                        .map(|value| format!("{:.1} dBFS", f64::from(value) / 1_000.0))
                        .unwrap_or_else(|| "无法计算".into()),
                ),
            ))
        }
        "AUD-044"
            if audio.is_some_and(|value| {
                value.conclusion_reliable
                    && value.issues.iter().any(|issue| issue.kind == "clipping")
            }) =>
        {
            Some((
                90,
                "可信样本中至少 0.1% 的 PCM 采样接近满幅，存在削波失真风险。".into(),
                one("削波采样", audio?.clipped_samples.to_string()),
            ))
        }
        "AUD-046"
            if audio.is_some_and(|value| {
                value.conclusion_reliable
                    && value.quality.as_ref().is_some_and(|quality| {
                        quality
                            .intervals
                            .iter()
                            .any(|interval| interval.kind == "level_jump_candidate")
                    })
            }) =>
        {
            let quality = audio?.quality.as_ref()?;
            let count = quality
                .intervals
                .iter()
                .filter(|interval| interval.kind == "level_jump_candidate")
                .count();
            Some((
                80,
                "可信 PCM 样本中发现相邻分析窗口超过 12 dB 的电平突变。".into(),
                one("突变候选区间", count.to_string()),
            ))
        }
        "AUD-047"
            if audio.is_some_and(|value| {
                value.conclusion_reliable
                    && value.quality.as_ref().is_some_and(|quality| {
                        quality
                            .channel_level_difference_db_milli
                            .is_some_and(|difference| difference >= 6_000)
                    })
            }) =>
        {
            Some((
                85,
                "可信 PCM 样本中，各声道 RMS 最大差值达到或超过 6 dB。".into(),
                one(
                    "声道 RMS 最大差值",
                    format!(
                        "{:.1} dB",
                        f64::from(audio?.quality.as_ref()?.channel_level_difference_db_milli?)
                            / 1_000.0
                    ),
                ),
            ))
        }
        "AUD-048"
            if audio.is_some_and(|value| {
                value.conclusion_reliable
                    && value.quality.as_ref().is_some_and(|quality| {
                        quality
                            .stereo_correlation_milli
                            .is_some_and(|correlation| correlation <= -800)
                    })
            }) =>
        {
            Some((
                88,
                "可信双声道 PCM 样本的左右声道相关系数不高于 -0.8，疑似反相。".into(),
                one(
                    "左右声道相关系数",
                    format!(
                        "{:.3}",
                        f64::from(audio?.quality.as_ref()?.stereo_correlation_milli?) / 1_000.0
                    ),
                ),
            ))
        }
        "AVS-045"
            if result.av_sync.iter().any(|sync| {
                (sync
                    .content_confidence_percent
                    .is_some_and(|confidence| confidence >= 75)
                    && sync
                        .content_offset_ms
                        .is_some_and(|offset| offset.abs() > 80))
                    || (sync.confidence_percent >= 80
                        && matches!(
                            sync.status.as_str(),
                            "audio_clock_late" | "audio_clock_early"
                        )
                        && sync.offset_ms.is_some_and(|offset| offset.abs() > 80))
            }) =>
        {
            let sync = result.av_sync.iter().find(|sync| {
                (sync
                    .content_confidence_percent
                    .is_some_and(|confidence| confidence >= 75)
                    && sync
                        .content_offset_ms
                        .is_some_and(|offset| offset.abs() > 80))
                    || (sync.confidence_percent >= 80
                        && matches!(
                            sync.status.as_str(),
                            "audio_clock_late" | "audio_clock_early"
                        )
                        && sync.offset_ms.is_some_and(|offset| offset.abs() > 80))
            })?;
            let content = sync
                .content_confidence_percent
                .filter(|confidence| *confidence >= 75)
                .zip(sync.content_offset_ms);
            let (confidence, conclusion, label, offset) = content.map_or_else(
                || (
                    sync.confidence_percent,
                    "共同 RTCP 时钟证据显示音视频时钟偏差超过 80 ms；这不等同于内容级口型同步结论。".into(),
                    "音频相对视频时钟偏差",
                    sync.offset_ms.unwrap_or_default(),
                ),
                |(confidence, offset)| (
                    confidence,
                    "闪光/蜂鸣内容事件配对显示音视频内容偏差超过 80 ms。".into(),
                    "音频相对视频内容偏差",
                    offset,
                ),
            );
            Some((
                confidence,
                conclusion,
                vec![
                    DiagnosticEvidence {
                        label: label.into(),
                        value: format!("{offset} ms"),
                    },
                    DiagnosticEvidence {
                        label: "配对".into(),
                        value: format!(
                            "{} ↔ {}",
                            sync.audio_stream_id.as_deref().unwrap_or("音频"),
                            sync.video_stream_id.as_deref().unwrap_or("视频")
                        ),
                    },
                    DiagnosticEvidence {
                        label: "依据".into(),
                        value: sync.basis.clone(),
                    },
                ],
            ))
        }
        "CMP-032"
            if protocol.is_some_and(|p| {
                p.media
                    .iter()
                    .any(|m| m.frame_size.as_deref().is_some_and(invalid_dimensions))
            }) && result.decode.as_ref().is_some_and(|d| d.success) =>
        {
            Some((
                65,
                "实际解码成功，但 SDP 元数据可能使严格播放器失败。".into(),
                one("兼容性证据", "FFmpeg 可解码，SDP 元数据异常".into()),
            ))
        }
        _ => None,
    }
}

fn resolution_mismatch(result: &AnalysisResult) -> Option<(u8, String, Vec<DiagnosticEvidence>)> {
    let protocol = result.protocol.as_ref()?;
    let sps = result.h264.as_ref()?.sps.first()?;
    let declared = protocol
        .media
        .iter()
        .find_map(|media| parse_dimensions(media.frame_size.as_deref()?))?;
    if declared == (sps.width, sps.height) {
        return None;
    }
    Some((
        95,
        "SDP framesize 与 H.264 SPS 分辨率不一致。".into(),
        vec![
            DiagnosticEvidence {
                label: "SDP".into(),
                value: format!("{}x{}", declared.0, declared.1),
            },
            DiagnosticEvidence {
                label: "SPS".into(),
                value: format!("{}x{}", sps.width, sps.height),
            },
        ],
    ))
}

fn parse_dimensions(value: &str) -> Option<(u32, u32)> {
    let normalized = value.replace(['-', '×'], "x");
    let (_, dimensions) = normalized.rsplit_once(' ').unwrap_or(("", &normalized));
    let (width, height) = dimensions.split_once('x')?;
    Some((width.trim().parse().ok()?, height.trim().parse().ok()?))
}

fn invalid_dimensions(value: &str) -> bool {
    parse_dimensions(value).is_none_or(|(width, height)| width == 0 || height == 0)
}

fn invalid_rate(value: &str) -> bool {
    value
        .parse::<f64>()
        .map_or(true, |rate| !rate.is_finite() || rate <= 0.0)
}

fn decode_has(result: &AnalysisResult, needles: &[&str]) -> bool {
    result.decode.as_ref().is_some_and(|decode| {
        decode.issues.iter().any(|issue| {
            let text = format!("{} {}", issue.kind, issue.example).to_lowercase();
            needles.iter().any(|needle| text.contains(needle))
        })
    })
}

fn decode_evidence(result: &AnalysisResult, needles: &[&str]) -> Vec<DiagnosticEvidence> {
    result
        .decode
        .as_ref()
        .into_iter()
        .flat_map(|decode| decode.issues.iter())
        .filter_map(|issue| {
            let text = format!("{} {}", issue.kind, issue.example).to_lowercase();
            needles
                .iter()
                .any(|needle| text.contains(needle))
                .then(|| DiagnosticEvidence {
                    label: issue.kind.clone(),
                    value: format!(
                        "{} 次{}：{}",
                        issue.count,
                        if issue.locations.is_empty() {
                            "，时间未定位".into()
                        } else {
                            format!(
                                "，候选帧 {}",
                                issue
                                    .locations
                                    .iter()
                                    .map(|location| format!("#{}", location.frame_number))
                                    .collect::<Vec<_>>()
                                    .join("、")
                            )
                        },
                        issue.example
                    ),
                })
        })
        .collect()
}

fn severity_for_h264_issue(kind: &str) -> DiagnosticSeverity {
    match kind {
        "invalid_sps" | "invalid_pps" | "missing_sps" | "missing_pps" | "fu_a_sequence_gap"
        | "fu_a_missing_end" => DiagnosticSeverity::Critical,
        "resolution_changed" | "slice_missing_pps" | "forbidden_zero_bit" => {
            DiagnosticSeverity::High
        }
        _ => DiagnosticSeverity::Medium,
    }
}

fn severity_for_h265_issue(kind: &str) -> DiagnosticSeverity {
    match kind {
        "h265_invalid_vps"
        | "h265_invalid_sps"
        | "h265_invalid_pps"
        | "h265_missing_vps"
        | "h265_missing_sps"
        | "h265_missing_pps"
        | "h265_fu_sequence_gap"
        | "h265_fu_missing_end" => DiagnosticSeverity::Critical,
        "h265_resolution_changed" | "h265_slice_missing_pps" | "forbidden_zero_bit" => {
            DiagnosticSeverity::High
        }
        _ => DiagnosticSeverity::Medium,
    }
}

fn severity_for_audio_issue(kind: &str) -> DiagnosticSeverity {
    match kind {
        "timestamp_gap" | "timestamp_overlap" | "clipping" => DiagnosticSeverity::High,
        "near_silence" => DiagnosticSeverity::Medium,
        _ => DiagnosticSeverity::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use streamscope_core::{
        AnalysisRequest, AnalysisStatus, AudioAnalysis, AudioIssue, AvSyncAnalysis,
        ProtocolAnalysis, RtpStatistics, SourceKind, Transport,
    };

    fn result_with_protocol(protocol: ProtocolAnalysis) -> AnalysisResult {
        AnalysisResult {
            schema_version: "test".into(),
            generated_at: "2026-09-07T00:00:00Z".into(),
            request: AnalysisRequest {
                source_kind: SourceKind::Rtsp,
                source_url: "rtsp://example.test/live".into(),
                source_path: None,
                transport: Some(Transport::Udp),
                duration_seconds: 10,
            },
            tools: Vec::new(),
            stream: None,
            format_bit_rate: None,
            session_sdp: None,
            protocol: Some(protocol),
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
            errors: Vec::new(),
            capture_summary: None,
            capture_stream: None,
            streams: Vec::new(),
        }
    }

    #[test]
    fn catalog_has_55_unique_rules() {
        assert_eq!(rule_catalog().len(), 55);
        let ids: HashSet<_> = rule_catalog().iter().map(|rule| rule.id).collect();
        assert_eq!(ids.len(), 55);
    }

    #[test]
    fn parses_common_framesize_forms() {
        assert_eq!(parse_dimensions("96 1920-1080"), Some((1920, 1080)));
        assert_eq!(parse_dimensions("1280x720"), Some((1280, 720)));
        assert!(invalid_dimensions("0x720"));
    }

    #[test]
    fn triggers_loss_and_consecutive_loss_from_measured_statistics() {
        let result = result_with_protocol(ProtocolAnalysis {
            rtp: RtpStatistics {
                packet_count: 50,
                lost_packets: 3,
                maximum_sequence_gap: 2,
                ..RtpStatistics::default()
            },
            ..ProtocolAnalysis::default()
        });
        let findings = evaluate(&result);
        assert!(findings.iter().any(|finding| finding.rule_id == "RTP-015"));
        assert!(findings.iter().any(|finding| finding.rule_id == "RTP-016"));
        assert!(!findings.iter().any(|finding| finding.rule_id == "RTP-018"));
    }

    #[test]
    fn recovered_reordering_does_not_report_packet_loss() {
        let mut result = result_with_protocol(ProtocolAnalysis {
            rtp: RtpStatistics {
                packet_count: 100,
                maximum_sequence_gap: 5,
                out_of_order_packets: 5,
                ..RtpStatistics::default()
            },
            ..ProtocolAnalysis::default()
        });
        result.request.source_kind = streamscope_core::SourceKind::Pcap;
        let findings = evaluate(&result);
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f.rule_id.as_str(), "RTP-015" | "RTP-016")
                    || f.rule_id.starts_with("RTSP-"))
        );
        assert!(findings.iter().any(|f| f.rule_id == "RTP-017"));
    }

    #[test]
    fn insufficient_sample_downgrades_stream_conclusions() {
        let mut result = result_with_protocol(ProtocolAnalysis {
            rtp: RtpStatistics {
                packet_count: 3,
                lost_packets: 1,
                ..RtpStatistics::default()
            },
            ..ProtocolAnalysis::default()
        });
        result.data_quality = streamscope_core::DataQuality {
            assessed: true,
            sufficient_for_diagnosis: false,
            reasons: vec!["媒体采样不足 3 秒".into()],
            ..streamscope_core::DataQuality::default()
        };
        let finding = evaluate(&result)
            .into_iter()
            .find(|finding| finding.rule_id == "RTP-015")
            .unwrap();
        assert_eq!(finding.confidence_percent, 55);
        assert_eq!(finding.severity, DiagnosticSeverity::Medium);
        assert!(finding.conclusion.starts_with("样本不足，仅观察到"));
    }

    #[test]
    fn play_without_rtp_is_reported_as_confirmed_session_failure() {
        let result = result_with_protocol(ProtocolAnalysis {
            transactions: vec![streamscope_core::RtspTransactionRecord {
                method: "PLAY".into(),
                uri: "rtsp://example.test/live".into(),
                status_code: 200,
                reason: "OK".into(),
                cseq: Some(4),
                elapsed_ms: 12,
            }],
            ..ProtocolAnalysis::default()
        });
        let findings = evaluate(&result);
        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == "RTSP-007")
            .unwrap();
        assert_eq!(finding.confidence_percent, 95);
    }

    #[test]
    fn authenticated_setup_challenge_is_not_reported_as_failure() {
        let transaction =
            |status_code, reason: &str, cseq| streamscope_core::RtspTransactionRecord {
                method: "SETUP".into(),
                uri: "rtsp://example.test/live/trackID=1".into(),
                status_code,
                reason: reason.into(),
                cseq: Some(cseq),
                elapsed_ms: 2,
            };
        let result = result_with_protocol(ProtocolAnalysis {
            authenticated: true,
            transactions: vec![
                transaction(401, "Unauthorized", 3),
                transaction(200, "OK", 4),
            ],
            rtp: RtpStatistics {
                packet_count: 10,
                ..RtpStatistics::default()
            },
            ..ProtocolAnalysis::default()
        });
        assert!(
            !evaluate(&result)
                .iter()
                .any(|finding| finding.rule_id == "RTSP-006")
        );
        let timeline = build_timeline(&result);
        assert_eq!(timeline[0].severity, DiagnosticSeverity::Info);
        assert!(timeline[0].detail.contains("鉴权挑战，随后成功"));
    }

    #[test]
    fn audio_findings_require_reliable_pcm_quality_but_keep_timestamp_evidence() {
        let mut result = result_with_protocol(ProtocolAnalysis::default());
        result.audio = Some(AudioAnalysis {
            codec: "PCMA".into(),
            timestamp_gap_count: 1,
            conclusion_reliable: false,
            issues: vec![
                AudioIssue {
                    kind: "timestamp_gap".into(),
                    detail: "gap".into(),
                    first_packet: Some(42),
                    offset_ms: Some(120),
                },
                AudioIssue {
                    kind: "near_silence".into(),
                    detail: "silence".into(),
                    ..AudioIssue::default()
                },
            ],
            ..AudioAnalysis::default()
        });

        let findings = evaluate(&result);
        assert!(findings.iter().any(|finding| finding.rule_id == "AUD-042"));
        assert!(!findings.iter().any(|finding| finding.rule_id == "AUD-043"));
        let event = build_timeline(&result)
            .into_iter()
            .find(|event| event.event_type == "timestamp_gap")
            .unwrap();
        assert_eq!(event.offset_ms, Some(120));
        assert_eq!(event.first_packet, Some(42));
    }

    #[test]
    fn audio_quality_findings_cover_level_jump_balance_and_phase() {
        let mut result = result_with_protocol(ProtocolAnalysis::default());
        result.audio = Some(AudioAnalysis {
            conclusion_reliable: true,
            quality: Some(streamscope_core::AudioQualityAnalysis {
                intervals: vec![streamscope_core::AudioQualityInterval {
                    kind: "level_jump_candidate".into(),
                    start_ms: 1_000,
                    end_ms: 1_100,
                    channel: Some(1),
                    ..streamscope_core::AudioQualityInterval::default()
                }],
                channel_level_difference_db_milli: Some(7_000),
                stereo_correlation_milli: Some(-900),
                ..streamscope_core::AudioQualityAnalysis::default()
            }),
            ..AudioAnalysis::default()
        });

        let findings = evaluate(&result);
        for rule_id in ["AUD-046", "AUD-047", "AUD-048"] {
            assert!(findings.iter().any(|finding| finding.rule_id == rule_id));
        }
        assert!(
            build_timeline(&result)
                .iter()
                .any(|event| event.event_type == "level_jump_candidate")
        );
    }

    #[test]
    fn av_sync_finding_requires_high_confidence_and_large_offset() {
        let mut result = result_with_protocol(ProtocolAnalysis::default());
        result.av_sync = vec![AvSyncAnalysis {
            status: "audio_clock_late".into(),
            basis: "RTCP SR + CNAME".into(),
            confidence_percent: 90,
            audio_stream_id: Some("audio-1".into()),
            video_stream_id: Some("video-1".into()),
            offset_ms: Some(125),
            ..AvSyncAnalysis::default()
        }];
        assert!(
            evaluate(&result)
                .iter()
                .any(|finding| finding.rule_id == "AVS-045")
        );

        result.av_sync[0].confidence_percent = 60;
        assert!(
            !evaluate(&result)
                .iter()
                .any(|finding| finding.rule_id == "AVS-045")
        );

        result.av_sync[0].status = "clock_aligned".into();
        result.av_sync[0].offset_ms = Some(0);
        result.av_sync[0].content_offset_ms = Some(140);
        result.av_sync[0].content_confidence_percent = Some(95);
        let finding = evaluate(&result)
            .into_iter()
            .find(|finding| finding.rule_id == "AVS-045")
            .unwrap();
        assert!(finding.conclusion.contains("内容事件"));
    }

    #[test]
    fn h265_incomplete_fu_triggers_critical_structural_rule() {
        let mut result = result_with_protocol(ProtocolAnalysis {
            rtp: RtpStatistics {
                packet_count: 100,
                ..RtpStatistics::default()
            },
            sample_duration_ms: Some(10_000),
            ..ProtocolAnalysis::default()
        });
        result.h265 = Some(streamscope_core::H265Analysis {
            incomplete_nalus: 1,
            issues: vec![streamscope_core::H264Issue {
                kind: "h265_fu_sequence_gap".into(),
                detail: "test".into(),
                sequence: Some(12),
                timestamp: Some(90_000),
            }],
            ..streamscope_core::H265Analysis::default()
        });
        result.data_quality = streamscope_core::DataQuality {
            assessed: true,
            sufficient_for_diagnosis: true,
            ..streamscope_core::DataQuality::default()
        };

        let finding = evaluate(&result)
            .into_iter()
            .find(|finding| finding.rule_id == "H265-037")
            .unwrap();
        assert_eq!(finding.severity, DiagnosticSeverity::Critical);
        assert!(
            build_timeline(&result)
                .iter()
                .any(|event| event.source == "H265" && event.sequence == Some(12))
        );
    }

    #[test]
    fn parameter_change_keeps_exact_nalu_au_and_packet_evidence() {
        let mut result = result_with_protocol(ProtocolAnalysis::default());
        result.h264 = Some(streamscope_core::H264Analysis {
            nalus: vec![streamscope_core::VideoNaluEvidence {
                nalu_number: 8,
                access_unit_number: Some(4),
                rtp_timestamp: Some(180_000),
                first_sequence: Some(300),
                last_sequence: Some(300),
                packets: vec![streamscope_core::VideoPacketAssociation {
                    packet_number: 77,
                    rtp_sequence: 300,
                    offset_ms: 2_000,
                }],
                ..streamscope_core::VideoNaluEvidence::default()
            }],
            parameter_changes: vec![streamscope_core::VideoParameterChange {
                nalu_number: 8,
                effective_access_unit: Some(4),
                parameter_kind: "sps".into(),
                parameter_id: 0,
                changed_fields: vec!["bit_depth".into()],
            }],
            ..streamscope_core::H264Analysis::default()
        });

        let finding = evaluate(&result)
            .into_iter()
            .find(|finding| finding.rule_id == "H264-049")
            .unwrap();
        assert!(finding.evidence[0].value.contains("NALU #8"));
        let event = build_timeline(&result)
            .into_iter()
            .find(|event| event.event_type == "parameter_set_changed")
            .unwrap();
        assert_eq!(event.offset_ms, Some(2_000));
        assert_eq!(event.frame_number, Some(4));
        assert_eq!(event.first_packet, Some(77));
        assert_eq!(
            event.location_precision.as_deref(),
            Some("exact_capture_packet_and_access_unit")
        );
    }

    #[test]
    fn reports_only_definite_h264_level_dpb_overflow() {
        let mut result = result_with_protocol(ProtocolAnalysis::default());
        result.h264 = Some(streamscope_core::H264Analysis {
            sps: vec![streamscope_core::H264SpsInfo {
                id: 0,
                profile_idc: 100,
                level_idc: 31,
                constraint_set3_flag: false,
                chroma_format_idc: 1,
                bit_depth_luma: 8,
                bit_depth_chroma: 8,
                max_frame_num: 16,
                pic_order_cnt_type: 0,
                max_num_ref_frames: 4,
                width: 1_920,
                height: 1_080,
                progressive: true,
                fps_milli: Some(25_000),
                num_units_in_tick: Some(1),
                time_scale: Some(50),
                nal_hrd: None,
                vcl_hrd: None,
                max_num_reorder_frames: None,
                max_dec_frame_buffering: None,
            }],
            ..streamscope_core::H264Analysis::default()
        });
        let finding = evaluate(&result)
            .into_iter()
            .find(|finding| finding.rule_id == "H264-051")
            .unwrap();
        assert!(
            finding
                .evidence
                .iter()
                .any(|item| item.value == "4 / 未声明 / 2 帧")
        );

        result.h264.as_mut().unwrap().sps[0].max_num_ref_frames = 2;
        assert!(
            evaluate(&result)
                .iter()
                .all(|finding| finding.rule_id != "H264-051")
        );
        result.h264.as_mut().unwrap().sps[0].level_idc = 0;
        result.h264.as_mut().unwrap().sps[0].max_num_ref_frames = 16;
        assert!(
            evaluate(&result)
                .iter()
                .all(|finding| finding.rule_id != "H264-051")
        );

        let sps = &mut result.h264.as_mut().unwrap().sps[0];
        sps.level_idc = 11;
        sps.width = 176;
        sps.height = 144;
        sps.max_num_ref_frames = 5;
        sps.constraint_set3_flag = false;
        assert!(
            evaluate(&result)
                .iter()
                .all(|finding| finding.rule_id != "H264-051")
        );
        result.h264.as_mut().unwrap().sps[0].constraint_set3_flag = true;
        let finding = evaluate(&result)
            .into_iter()
            .find(|finding| finding.rule_id == "H264-051")
            .unwrap();
        assert!(
            finding
                .evidence
                .iter()
                .any(|item| item.value == "5 / 未声明 / 4 帧")
        );
    }

    #[test]
    fn reports_h264_vui_buffering_inconsistency() {
        let mut result = result_with_protocol(ProtocolAnalysis::default());
        result.h264 = Some(streamscope_core::H264Analysis {
            sps: vec![streamscope_core::H264SpsInfo {
                id: 2,
                profile_idc: 100,
                level_idc: 40,
                constraint_set3_flag: false,
                chroma_format_idc: 1,
                bit_depth_luma: 8,
                bit_depth_chroma: 8,
                max_frame_num: 16,
                pic_order_cnt_type: 0,
                max_num_ref_frames: 4,
                width: 1_920,
                height: 1_080,
                progressive: true,
                fps_milli: Some(25_000),
                num_units_in_tick: Some(1),
                time_scale: Some(50),
                nal_hrd: None,
                vcl_hrd: None,
                max_num_reorder_frames: Some(3),
                max_dec_frame_buffering: Some(2),
            }],
            ..streamscope_core::H264Analysis::default()
        });

        let finding = evaluate(&result)
            .into_iter()
            .find(|finding| finding.rule_id == "H264-053")
            .unwrap();
        assert_eq!(finding.confidence_percent, 100);
        assert!(
            finding.evidence[0]
                .value
                .contains("max_dec_frame_buffering=2")
        );

        let sps = &mut result.h264.as_mut().unwrap().sps[0];
        sps.max_dec_frame_buffering = Some(4);
        sps.max_num_reorder_frames = Some(4);
        assert!(
            evaluate(&result)
                .iter()
                .all(|finding| finding.rule_id != "H264-053")
        );
    }

    #[test]
    fn reports_hrd_rate_overflow_only_for_long_complete_samples() {
        let protocol = ProtocolAnalysis {
            sample_duration_ms: Some(2_000),
            rtp: RtpStatistics {
                average_bit_rate_bps: Some(2_000_000),
                ..RtpStatistics::default()
            },
            ..ProtocolAnalysis::default()
        };
        let mut result = result_with_protocol(protocol);
        result.h264 = Some(streamscope_core::H264Analysis {
            sps: vec![streamscope_core::H264SpsInfo {
                id: 0,
                profile_idc: 100,
                level_idc: 40,
                constraint_set3_flag: false,
                chroma_format_idc: 1,
                bit_depth_luma: 8,
                bit_depth_chroma: 8,
                max_frame_num: 16,
                pic_order_cnt_type: 0,
                max_num_ref_frames: 4,
                width: 1_920,
                height: 1_080,
                progressive: true,
                fps_milli: Some(25_000),
                num_units_in_tick: Some(1),
                time_scale: Some(50),
                nal_hrd: Some(streamscope_core::H264HrdInfo {
                    cpb_count: 1,
                    maximum_bit_rate_bps: 1_500_000,
                    maximum_cpb_size_bits: 3_000_000,
                    all_cbr: true,
                    entries: vec![streamscope_core::H264CpbEntry {
                        bit_rate_bps: 1_500_000,
                        cpb_size_bits: 3_000_000,
                        cbr: true,
                    }],
                    initial_cpb_removal_delay_length: 24,
                    cpb_removal_delay_length: 24,
                    dpb_output_delay_length: 24,
                    time_offset_length: 24,
                }),
                vcl_hrd: None,
                max_num_reorder_frames: Some(2),
                max_dec_frame_buffering: Some(4),
            }],
            ..streamscope_core::H264Analysis::default()
        });

        assert!(
            evaluate(&result)
                .iter()
                .any(|finding| finding.rule_id == "H264-054")
        );
        result.protocol.as_mut().unwrap().sample_duration_ms = Some(999);
        assert!(
            evaluate(&result)
                .iter()
                .all(|finding| finding.rule_id != "H264-054")
        );
        result.protocol.as_mut().unwrap().sample_duration_ms = Some(2_000);
        result.data_quality.capture_truncated = true;
        assert!(
            evaluate(&result)
                .iter()
                .all(|finding| finding.rule_id != "H264-054")
        );
    }

    #[test]
    fn reports_only_evidence_backed_per_au_hrd_violations() {
        let mut result = result_with_protocol(ProtocolAnalysis::default());
        result.h264 = Some(streamscope_core::H264Analysis {
            frames: vec![streamscope_core::H264FrameEvidence {
                frame_number: 4,
                rtp_timestamp: Some(180_000),
                first_sequence: Some(20),
                last_sequence: Some(22),
                first_nalu: 8,
                last_nalu: 10,
                first_packet: Some(100),
                last_packet: Some(102),
                first_offset_ms: Some(2_000),
                last_offset_ms: Some(2_040),
                sample_start_offset: Some(1_000),
                sample_end_offset: Some(6_000),
                idr: false,
                complete: true,
                boundary_confidence: "test".into(),
            }],
            hrd_simulation: streamscope_core::H264HrdSimulation {
                status: "simulated_cbr_single_cpb".into(),
                schedule: "nal".into(),
                sps_id: Some(0),
                simulated_aus: 4,
                overflow_aus: vec![4],
                points: vec![streamscope_core::H264HrdAuPoint {
                    access_unit: 4,
                    sei_nalu: 9,
                    access_unit_bits: 40_000,
                    cpb_removal_delay: 4,
                    fullness_before_removal_bits: 60_000,
                    fullness_after_removal_bits: 20_000,
                    overflow: true,
                    ..streamscope_core::H264HrdAuPoint::default()
                }],
                ..streamscope_core::H264HrdSimulation::default()
            },
            ..streamscope_core::H264Analysis::default()
        });

        let finding = evaluate(&result)
            .into_iter()
            .find(|finding| finding.rule_id == "H264-055")
            .unwrap();
        assert_eq!(finding.confidence_percent, 98);
        assert!(finding.evidence.iter().any(|item| item.value == "4"));
        let event = build_timeline(&result)
            .into_iter()
            .find(|event| event.event_type == "cpb_overflow")
            .unwrap();
        assert_eq!(event.offset_ms, Some(2_000));
        assert_eq!(event.first_packet, Some(100));

        let simulation = &mut result.h264.as_mut().unwrap().hrd_simulation;
        simulation.status = "evidence_insufficient".into();
        assert!(
            evaluate(&result)
                .iter()
                .all(|finding| finding.rule_id != "H264-055")
        );
    }

    #[test]
    fn reports_only_definite_h265_level_dpb_overflow() {
        let mut result = result_with_protocol(ProtocolAnalysis::default());
        result.h265 = Some(streamscope_core::H265Analysis {
            sps: vec![streamscope_core::H265SpsInfo {
                id: 0,
                vps_id: 0,
                max_sub_layers: 1,
                profile_idc: 1,
                level_idc: 120,
                chroma_format_idc: 1,
                bit_depth_luma: 8,
                bit_depth_chroma: 8,
                width: 1_920,
                height: 1_080,
                max_dec_pic_buffering: Some(8),
                max_num_reorder_pics: Some(2),
            }],
            ..streamscope_core::H265Analysis::default()
        });
        let finding = evaluate(&result)
            .into_iter()
            .find(|finding| finding.rule_id == "H265-052")
            .unwrap();
        assert!(finding.evidence.iter().any(|item| item.value == "8 / 6 帧"));

        result.h265.as_mut().unwrap().sps[0].max_dec_pic_buffering = Some(6);
        assert!(
            evaluate(&result)
                .iter()
                .all(|finding| finding.rule_id != "H265-052")
        );
        result.h265.as_mut().unwrap().sps[0].level_idc = 0;
        result.h265.as_mut().unwrap().sps[0].max_dec_pic_buffering = Some(16);
        assert!(
            evaluate(&result)
                .iter()
                .all(|finding| finding.rule_id != "H265-052")
        );
    }

    #[test]
    fn long_random_access_wait_is_reported_as_opportunity_not_confirmed_recovery() {
        let frame = |frame_number, offset_ms, idr| streamscope_core::H264FrameEvidence {
            frame_number,
            rtp_timestamp: None,
            first_sequence: None,
            last_sequence: None,
            first_nalu: frame_number,
            last_nalu: frame_number,
            first_packet: None,
            last_packet: None,
            first_offset_ms: Some(offset_ms),
            last_offset_ms: Some(offset_ms),
            sample_start_offset: None,
            sample_end_offset: None,
            idr,
            complete: true,
            boundary_confidence: "test".into(),
        };
        let mut result = result_with_protocol(ProtocolAnalysis::default());
        result.h264 = Some(streamscope_core::H264Analysis {
            frames: vec![frame(10, 1_000, false), frame(140, 6_200, true)],
            ..streamscope_core::H264Analysis::default()
        });
        result.decode = Some(streamscope_core::DecodeSummary {
            issues: vec![streamscope_core::DecodeIssue {
                kind: "missing_reference".into(),
                count: 1,
                example: "reference missing".into(),
                locations: vec![streamscope_core::DecodeIssueLocation {
                    frame_number: 10,
                    pts_time: None,
                    precision: "candidate_nearest_log_frame".into(),
                }],
            }],
            ..streamscope_core::DecodeSummary::default()
        });

        let finding = evaluate(&result)
            .into_iter()
            .find(|finding| finding.rule_id == "REC-031")
            .unwrap();
        assert!(finding.conclusion.contains("不等同于已确认画面恢复"));
        assert!(
            finding
                .evidence
                .iter()
                .any(|item| item.value.contains("5200 ms"))
        );
    }
}
