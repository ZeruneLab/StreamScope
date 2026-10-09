use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use streamscope_analyzer::{AnalyzeOptions, AudioFileOptions, H264FileOptions, H265FileOptions, PcapFileOptions};
use streamscope_core::Transport;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
mod report_tools;

pub fn execute(mode: &str, action: &str, input: &Value, progress: &mut dyn FnMut(Value)) -> Result<Value, String> {
    if matches!(mode, "h264" | "h265") && action == "inspect-nalus" { return inspect_nalus(mode, input, progress); }
    if mode == "audio" && action == "export-audio" { return export_audio(input, progress); }
    if mode == "audio" && action == "export-evidence" {
        let issues: Vec<streamscope_core::AudioIssue> = serde_json::from_str(input["issues"].as_str().unwrap_or("[]")).map_err(|error| error.to_string())?;
        let intervals: Vec<streamscope_core::AudioQualityInterval> = serde_json::from_str(input["intervals"].as_str().unwrap_or("[]")).map_err(|error| error.to_string())?;
        let format = input["format"].as_str().unwrap_or("");
        let bytes = match format {
            "csv" => report_tools::audio_csv(&issues, &intervals).into_bytes(),
            "json" => serde_json::to_vec_pretty(&json!({"timestamp_issues":issues,"content_intervals":intervals})).map_err(|error| error.to_string())?,
            _ => return Err("证据格式仅支持 CSV 或 JSON".into()),
        };
        let directory = output_directory(input, "audio-evidence")?;
        let file = directory.join(format!("evidence.{format}"));
        std::fs::write(&file, bytes).map_err(|error| error.to_string())?;
        return Ok(json!({"summary":"音频异常证据导出完成","reportDirectory":directory,"downloadFile":file}));
    }
    if action != "analyze" { return Err("未声明的媒体分析动作".into()); }
    let output_root = input["_hostOutputRoot"].as_str().filter(|value| !value.is_empty())
        .map(PathBuf::from).ok_or_else(|| "宿主未提供报告目录".to_string())?;
    let run = match mode {
        "h264" | "h265" | "audio" | "pcap" => {
            let path = input["path"].as_str().unwrap_or("");
            if !Path::new(path).is_file() { return Err("请选择现有媒体文件".into()); }
            let input_path = PathBuf::from(path);
            progress(json!({"percent":5,"stage":"准备","detail":"正在读取输入文件"}));
            match mode {
                "h264" => streamscope_analyzer::analyze_h264_file(H264FileOptions { input: input_path, output_root, process_timeout_seconds: 300 }),
                "h265" => streamscope_analyzer::analyze_h265_file(H265FileOptions { input: input_path, output_root, process_timeout_seconds: 300 }),
                "audio" => streamscope_analyzer::analyze_audio_file(AudioFileOptions { input: input_path, output_root, process_timeout_seconds: 300 }),
                _ => {
                    let stream_ids = input["streamIds"].as_str().unwrap_or("")
                        .split(',').map(str::trim).filter(|value| !value.is_empty()).map(str::to_owned).collect();
                    return finish(streamscope_analyzer::analyze_pcap_file_with_progress(PcapFileOptions {
                        input: input_path, output_root, process_timeout_seconds: 300, stream_ids,
                    }, |event| progress(json!(event))).map_err(|error| error.to_string())?, progress);
                }
            }.map_err(|error| error.to_string())?
        }
        "rtsp" => {
            let source_url = input["url"].as_str().unwrap_or("").to_owned();
            let duration_seconds = number(input, "durationSeconds", 10)?;
            let connect_timeout_seconds = number(input, "connectTimeoutSeconds", 10)?;
            if input["transport"].as_str() == Some("compare") {
                progress(json!({"percent":5,"stage":"传输对比","detail":"依次执行 TCP 与 UDP 诊断"}));
                let compared = streamscope_analyzer::compare_rtsp(AnalyzeOptions {
                    source_url, transport: Transport::Tcp, duration_seconds, connect_timeout_seconds, output_root,
                }).map_err(|error| error.to_string())?;
                progress(json!({"percent":100,"stage":"完成","detail":"TCP/UDP 对比报告已生成"}));
                return Ok(json!({
                    "summary":"TCP/UDP 对比完成，请查看两次采集的结论与完整证据。",
                    "reportDirectory":compared.report_directory,
                    "tcpReportDirectory":compared.tcp.report_directory,
                    "udpReportDirectory":compared.udp.report_directory,
                    "conclusions":compared.conclusions,
                    "blocks":[
                        {"type":"table","title":"传输对比","columns":["传输","状态","报告"],"rows":[
                            ["TCP",compared.tcp.result.status,compared.tcp.reports.html],
                            ["UDP",compared.udp.result.status,compared.udp.reports.html]
                        ]},
                        {"type":"report","title":"完整 TCP/UDP 对比报告","reportPath":compared.html}
                    ]
                }));
            }
            let transport = match input["transport"].as_str().filter(|value| !value.is_empty()).unwrap_or("tcp") {
                "tcp" => Transport::Tcp,
                "udp" => Transport::Udp,
                _ => return Err("传输模式仅支持 tcp、udp 或 compare".into()),
            };
            streamscope_analyzer::analyze_rtsp_with_progress(AnalyzeOptions {
                source_url, transport, duration_seconds, connect_timeout_seconds, output_root,
            }, |event| progress(json!(event))).map_err(|error| error.to_string())?
        }
        _ => return Err("未知媒体插件模式".into()),
    };
    finish(run, progress)
}

fn inspect_nalus(codec: &str, input: &Value, progress: &mut dyn FnMut(Value)) -> Result<Value, String> {
    let source = Path::new(input["path"].as_str().unwrap_or(""));
    if !source.is_file() { return Err("请选择现有 Annex B 裸码流文件".into()); }
    let first = number(input, "firstNalu", 1)?;
    let last = number(input, "lastNalu", first)?;
    progress(json!({"percent":5,"stage":"语法查看","detail":"流式读取选中 NALU 范围"}));
    let nalus = streamscope_analyzer::inspect_annex_b_file_syntax(source, codec, first, last).map_err(|error| error.to_string())?;
    if nalus.is_empty() { return Err("选中范围未找到可解析 NALU；请检查编码、Annex B 格式和序号".into()); }
    let nodes = nalus.iter().map(|nalu| json!({
        "label":format!("NALU #{} · {} · {} B", nalu.index, nalu.type_name, nalu.size), "byteOffset":nalu.offset,
        "children":nalu.fields.iter().map(|field| json!({"label":format!("{} ({})", field.name, field.source),"value":field.value})).collect::<Vec<_>>()
    })).collect::<Vec<_>>();
    let mut blocks = vec![json!({"type":"text","title":"解析边界","text":"仅展示现有解析器可确认的 NALU 头、参数集与 Slice 前缀，不宣称完整解码 Slice 语法或推测 RTP/帧映射。HEX 最多显示每个 NALU 前 4,096 字节。"}),
        json!({"type":"syntaxTree","title":"NALU 语法树","nodes":nodes})];
    for nalu in &nalus {
        let bytes = nalu.hex.lines().filter_map(|line| line.split_once("  ").map(|(_, bytes)| bytes))
            .collect::<Vec<_>>().join(" ");
        blocks.push(json!({"type":"hex","title":format!("NALU #{} · 文件偏移 {} · {}", nalu.index, nalu.offset, nalu.type_name),
            "bytesHex":bytes,"fields":nalu.fields,"byteOffset":nalu.offset,"truncated":nalu.hex_truncated}));
    }
    progress(json!({"percent":100,"stage":"完成","detail":"语法与字节证据已生成"}));
    Ok(json!({"summary":format!("{codec} NALU #{first}–#{last} 语法查看完成"),"nalus":nalus,"blocks":blocks}))
}

fn export_audio(input: &Value, progress: &mut dyn FnMut(Value)) -> Result<Value, String> {
    let source = Path::new(input["path"].as_str().unwrap_or(""));
    if !source.is_file() { return Err("请选择现有音频文件".into()); }
    let format = input["format"].as_str().unwrap_or("");
    if !matches!(format, "wav" | "mp3" | "m4a" | "flac" | "ogg") { return Err("音频格式支持 wav、mp3、m4a、flac、ogg".into()); }
    let specified = |key: &str| input[key].as_str().is_some_and(|value| !value.is_empty()) || input[key].is_number();
    let range = if specified("startMs") || specified("endMs") {
        let start = number(input, "startMs", 0)?;
        let end = number(input, "endMs", 0)?;
        if end <= start { return Err("导出结束时间必须晚于开始时间".into()); }
        Some((start, end))
    } else { None };
    let output_root = input["_hostOutputRoot"].as_str().filter(|value| !value.is_empty())
        .map(PathBuf::from).ok_or_else(|| "宿主未提供报告目录".to_string())?;
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|error| error.to_string())?.as_nanos();
    let directory = output_root.join(format!("report-audio-export-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let file = directory.join(format!("audio.{format}"));
    progress(json!({"percent":10,"stage":"音频导出","detail":format!("正在生成 {format} 文件")}));
    if let Err(error) = streamscope_ffmpeg::export_audio_segment(source, &file, format, range, Duration::from_secs(300)) {
        let _ = std::fs::remove_dir_all(&directory);
        return Err(error.to_string());
    }
    progress(json!({"percent":100,"stage":"完成","detail":"点击另存导出文件选择保存位置"}));
    Ok(json!({"summary":format!("{format} 音频导出完成"),"reportDirectory":directory,"downloadFile":file,"format":format,"rangeMs":range}))
}

fn number(input: &Value, key: &str, default: u64) -> Result<u64, String> {
    if let Some(value) = input[key].as_u64() { return Ok(value); }
    match input[key].as_str() {
        Some("") => Ok(default),
        None if input[key].is_null() => Ok(default),
        None => Err(format!("{key} 必须是非负整数")),
        Some(value) => value.parse().map_err(|_| format!("{key} 必须是整数")),
    }
}

fn finish(run: streamscope_analyzer::AnalysisRun, progress: &mut dyn FnMut(Value)) -> Result<Value, String> {
    let stream_rows = run.result.streams.iter().filter_map(|stream| stream.capture_stream.as_ref())
        .take(500).map(|stream| json!([
            stream.id, stream.source, stream.destination, stream.transport.to_string(),
            stream.codec, stream.first_offset_ms, stream.last_offset_ms,
            stream.first_packet, stream.last_packet
        ])).collect::<Vec<_>>();
    let findings = run.result.diagnostics.iter()
        .chain(run.result.streams.iter().flat_map(|stream| &stream.diagnostics))
        .take(100).collect::<Vec<_>>();
    let events = run.result.timeline.iter()
        .chain(run.result.streams.iter().flat_map(|stream| &stream.timeline))
        .filter_map(|event| event.offset_ms.map(|offset_ms| json!({
            "offsetMs":offset_ms, "label":event.event_type, "detail":event.detail.chars().take(300).collect::<String>()
        }))).take(200).collect::<Vec<_>>();
    let evidence = findings.iter().map(|finding| json!({
        "ruleId":finding.rule_id, "title":finding.title, "severity":finding.severity,
        "confidencePercent":finding.confidence_percent, "conclusion":finding.conclusion,
        "evidence":finding.evidence, "suggestions":finding.suggestions, "verification":finding.verification
    })).collect::<Vec<_>>();
    let rows = findings.iter().map(|finding| json!([
        finding.rule_id, finding.title, format!("{:?}", finding.severity),
        finding.confidence_percent, finding.conclusion.chars().take(300).collect::<String>()
    ])).collect::<Vec<_>>();
    let mut blocks = Vec::new();
    if !stream_rows.is_empty() {
        blocks.push(json!({"type":"table","title":"抓包媒体流（流 ID 可复制到深入分析输入框）",
            "columns":["流 ID","源","目的","传输","编码","开始 ms","结束 ms","首包","末包"],"rows":stream_rows}));
    }
    blocks.extend([
        json!({"type":"table","title":"诊断结论（前 100 条）","columns":["规则","标题","级别","可信度 %","结论"],"rows":rows}),
        json!({"type":"timeline","title":"跨层时间线（前 200 条）","events":events}),
        json!({"type":"report","title":"完整分析报告","reportPath":run.reports.html}),
    ]);
    progress(json!({"percent":100,"stage":"完成","detail":"分析报告已生成"}));
    Ok(json!({
        "summary": "媒体分析完成，点击打开完整分析报告查看证据。",
        "reportDirectory": run.report_directory,
        "previewAudio": run.result.preview_audio,
        "previewVideo": run.result.preview_video,
        "status": run.result.status,
        "diagnosticCount": findings.len(),
        "evidence": evidence,
        "timeline": events,
        "blocks": blocks
    }))
}

pub fn execute_deep(action: &str, input: &Value, progress: &mut dyn FnMut(Value)) -> Result<Value, String> {
    if action == "report-tools" { return report_tools::execute(input, progress); }
    if action != "inspect-frame" { return Err("未声明的视频深度分析动作".into()); }
    let source = Path::new(input["path"].as_str().unwrap_or(""));
    if !source.is_file() { return Err("请选择现有视频文件".into()); }
    let display_index = number(input, "displayIndex", 0)?;
    if display_index > 1_000_000 { return Err("显示帧序号超出上限".into()); }
    progress(json!({"percent":5,"stage":"逐帧分析","detail":format!("正在读取第 {display_index} 帧")}));
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|error| error.to_string())?.as_nanos();
    let output = std::env::temp_dir().join(format!("streamscope-deep-{}-{unique}.json", std::process::id()));
    let analyzed = streamscope_ffmpeg::analyze_video_frame_blocks(source, &output, display_index, Duration::from_secs(120));
    let _ = std::fs::remove_file(&output);
    let frame = analyzed.map_err(|error| error.to_string())?;
    let output_root = input["_hostOutputRoot"].as_str().filter(|value| !value.is_empty())
        .map(PathBuf::from).ok_or_else(|| "宿主未提供报告目录".to_string())?;
    let report_directory = output_root.join(format!("report-deep-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&report_directory).map_err(|error| error.to_string())?;
    let frame_image = report_directory.join(format!("frame-{display_index}.png"));
    if let Err(error) = streamscope_ffmpeg::extract_video_frame(source, &frame_image, display_index, Duration::from_secs(120)) {
        let _ = std::fs::remove_dir_all(&report_directory);
        return Err(format!("逐帧证据已取得，但画面提取失败：{error}"));
    }
    let qp_rows = frame.qp.as_ref().map(|qp| qp.blocks.iter().take(500).map(|block| json!([
        block.x, block.y, block.width, block.height, block.value, block.delta
    ])).collect::<Vec<_>>()).unwrap_or_default();
    let mv_rows = frame.motion_vectors.iter().take(500).map(|vector| json!([
        vector.source_x, vector.source_y, vector.destination_x, vector.destination_y,
        vector.motion_x, vector.motion_y, vector.motion_scale
    ])).collect::<Vec<_>>();
    let observation_rows = frame.block_observations.iter().take(500).map(|block| json!([
        block.x, block.y, block.width, block.height, block.block_level,
        block.qp, block.partition_mode, block.prediction_mode
    ])).collect::<Vec<_>>();
    let qp_overlay = frame.qp.as_ref().map(|qp| qp.blocks.iter().take(2_000).map(|block| json!([
        block.x, block.y, block.width, block.height, block.value
    ])).collect::<Vec<_>>()).unwrap_or_default();
    let mv_overlay = frame.motion_vectors.iter().take(1_000).map(|vector| json!([
        vector.source_x, vector.source_y, vector.destination_x, vector.destination_y
    ])).collect::<Vec<_>>();
    progress(json!({"percent":100,"stage":"完成","detail":"逐帧块证据已生成"}));
    Ok(json!({
        "summary": format!("第 {display_index} 帧：{}×{}，QP 块 {}，运动矢量 {}，内部块 {}",
            frame.width, frame.height, frame.qp.as_ref().map_or(0, |qp| qp.blocks.len()),
            frame.motion_vectors.len(), frame.block_observations.len()),
        "displayIndex": display_index,
        "analyzerVersion": frame.analyzer_version,
        "reportDirectory": report_directory,
        "previewFrame": frame_image,
        "blocks": [
            {"type":"frameOverlay","title":"QP / 运动矢量空间分布","width":frame.width,"height":frame.height,
                "qp":qp_overlay,"motionVectors":mv_overlay},
            {"type":"table","title":"QP 块（前 500 条）","columns":["X","Y","宽","高","QP","ΔQP"],"rows":qp_rows},
            {"type":"table","title":"运动矢量（前 500 条）","columns":["源 X","源 Y","目标 X","目标 Y","MV X","MV Y","Scale"],"rows":mv_rows},
            {"type":"table","title":"解码器内部块（前 500 条）","columns":["X","Y","宽","高","层级","QP","分区","预测"],"rows":observation_rows}
        ]
    }))
}

fn output_directory(input: &Value, suffix: &str) -> Result<PathBuf, String> {
    let root = input["_hostOutputRoot"].as_str().filter(|value| !value.is_empty()).ok_or("宿主未提供报告目录")?;
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|error| error.to_string())?.as_nanos();
    let directory = Path::new(root).join(format!("report-{suffix}-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_missing_file_without_touching_old_analyzer() {
        let result = execute("h264", "analyze", &json!({"path":"", "_hostOutputRoot":"reports"}), &mut |_| {});
        assert!(result.is_err());
    }

    #[test]
    fn rtsp_compare_uses_shared_option_validation() {
        let error = execute("rtsp", "analyze", &json!({
            "url":"rtsp://127.0.0.1/test", "transport":"compare", "durationSeconds":0,
            "_hostOutputRoot":"unused-report-root",
        }), &mut |_| {}).unwrap_err();
        assert!(error.contains("分析时长"));
    }

    #[test]
    fn audio_plugin_matches_existing_analysis_for_wav() {
        if !streamscope_ffmpeg::check_tool("ffmpeg").available { return; }
        let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!("streamscope-plugin-audio-parity-{unique}"));
        std::fs::create_dir_all(&directory).unwrap();
        let input = directory.join("silence.wav");
        let data_bytes = 8_000_u32 * 2;
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

        let old = streamscope_analyzer::analyze_audio_file(AudioFileOptions {
            input: input.clone(), output_root: directory.join("old"), process_timeout_seconds: 300,
        }).unwrap();
        let plugin = execute("audio", "analyze", &json!({
            "path": input, "_hostOutputRoot": directory.join("plugin")
        }), &mut |_| {}).unwrap();
        let plugin_report = PathBuf::from(plugin["reportDirectory"].as_str().unwrap());
        let result: streamscope_core::AnalysisResult = serde_json::from_slice(
            &std::fs::read(plugin_report.join("result.json")).unwrap()
        ).unwrap();
        let rules = |run: &streamscope_core::AnalysisResult| {
            run.diagnostics.iter().map(|item| item.rule_id.clone()).collect::<Vec<_>>()
        };
        assert_eq!(rules(&old.result), rules(&result));
        assert_eq!(old.result.status, result.status);
        assert!(plugin_report.join("report.html").is_file());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn h264_plugin_matches_existing_fixture_report() {
        if !streamscope_ffmpeg::check_tool("ffmpeg").available { return; }
        let input = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/h264/generated-normal.h264");
        let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!("streamscope-plugin-h264-parity-{unique}"));
        let old = streamscope_analyzer::analyze_h264_file(H264FileOptions {
            input: input.clone(), output_root: directory.join("old"), process_timeout_seconds: 300,
        }).unwrap();
        let plugin = execute("h264", "analyze", &json!({
            "path": input, "_hostOutputRoot": directory.join("plugin")
        }), &mut |_| {}).unwrap();
        let plugin_report = PathBuf::from(plugin["reportDirectory"].as_str().unwrap());
        let result: streamscope_core::AnalysisResult = serde_json::from_slice(
            &std::fs::read(plugin_report.join("result.json")).unwrap()
        ).unwrap();
        assert_eq!(old.result.status, result.status);
        assert_eq!(old.result.h264.as_ref().map(|value| value.nalu_count), result.h264.as_ref().map(|value| value.nalu_count));
        assert_eq!(old.result.diagnostics.iter().map(|item| item.rule_id.clone()).collect::<Vec<_>>(),
            result.diagnostics.iter().map(|item| item.rule_id.clone()).collect::<Vec<_>>());
        assert!(plugin_report.join("report.html").is_file());
        assert!(plugin["blocks"].as_array().unwrap().iter().any(|block| block["type"] == "report"
            && Path::new(block["reportPath"].as_str().unwrap()).is_file()));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn h265_plugin_matches_existing_analysis_for_generated_stream() {
        if !streamscope_ffmpeg::check_tool("ffmpeg").available { return; }
        let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!("streamscope-plugin-h265-parity-{unique}"));
        std::fs::create_dir_all(&directory).unwrap();
        let input = directory.join("generated.h265");
        let encoded = std::process::Command::new("ffmpeg").args([
            "-hide_banner", "-loglevel", "error", "-f", "lavfi", "-i",
            "testsrc2=duration=1:size=64x64:rate=5", "-threads", "1", "-c:v", "libx265",
            "-x265-params", "pools=1:frame-threads=1:log-level=error", "-f", "hevc", "-y"
        ]).arg(&input).status().unwrap();
        assert!(encoded.success());
        let old = streamscope_analyzer::analyze_h265_file(H265FileOptions {
            input: input.clone(), output_root: directory.join("old"), process_timeout_seconds: 300,
        }).unwrap();
        let plugin = execute("h265", "analyze", &json!({
            "path": input, "_hostOutputRoot": directory.join("plugin")
        }), &mut |_| {}).unwrap();
        let result: streamscope_core::AnalysisResult = serde_json::from_slice(&std::fs::read(
            PathBuf::from(plugin["reportDirectory"].as_str().unwrap()).join("result.json")
        ).unwrap()).unwrap();
        assert_eq!(old.result.status, result.status);
        assert_eq!(old.result.h265.as_ref().map(|value| value.nalu_count), result.h265.as_ref().map(|value| value.nalu_count));
        assert_eq!(old.result.diagnostics.iter().map(|item| item.rule_id.clone()).collect::<Vec<_>>(),
            result.diagnostics.iter().map(|item| item.rule_id.clone()).collect::<Vec<_>>());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pcap_plugin_matches_existing_analysis_for_pcmu_packets() {
        let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!("streamscope-plugin-pcap-parity-{unique}"));
        std::fs::create_dir_all(&directory).unwrap();
        let input = directory.join("audio.pcap");
        let mut pcap = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        pcap.extend([0; 8]);
        pcap.extend(65_535_u32.to_le_bytes());
        pcap.extend(1_u32.to_le_bytes());
        for sequence in 0..3_u16 {
            let mut frame = vec![0_u8; 14 + 20 + 8];
            frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
            frame[14] = 0x45;
            frame[16..18].copy_from_slice(&200_u16.to_be_bytes());
            frame[23] = 17;
            frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
            frame[30..34].copy_from_slice(&[198, 51, 100, 1]);
            frame[34..36].copy_from_slice(&5004_u16.to_be_bytes());
            frame[36..38].copy_from_slice(&6000_u16.to_be_bytes());
            frame[38..40].copy_from_slice(&180_u16.to_be_bytes());
            frame.extend([0x80, 0, (sequence >> 8) as u8, sequence as u8]);
            frame.extend((u32::from(sequence) * 160).to_be_bytes());
            frame.extend(42_u32.to_be_bytes());
            frame.extend([0xff; 160]);
            pcap.extend(0_u32.to_le_bytes());
            pcap.extend((u32::from(sequence) * 20_000).to_le_bytes());
            pcap.extend((frame.len() as u32).to_le_bytes());
            pcap.extend((frame.len() as u32).to_le_bytes());
            pcap.extend(frame);
        }
        std::fs::write(&input, pcap).unwrap();
        let old = streamscope_analyzer::analyze_pcap_file(PcapFileOptions {
            input: input.clone(), output_root: directory.join("old"), process_timeout_seconds: 300,
            stream_ids: Vec::new(),
        }).unwrap();
        let plugin = execute("pcap", "analyze", &json!({
            "path":input,"_hostOutputRoot":directory.join("plugin")
        }), &mut |_| {}).unwrap();
        let result: streamscope_core::AnalysisResult = serde_json::from_slice(&std::fs::read(
            PathBuf::from(plugin["reportDirectory"].as_str().unwrap()).join("result.json")
        ).unwrap()).unwrap();
        assert_eq!(old.result.status, result.status);
        assert_eq!(old.result.capture_summary.as_ref().map(|item| item.stream_count),
            result.capture_summary.as_ref().map(|item| item.stream_count));
        assert_eq!(old.result.streams.len(), result.streams.len());
        assert_eq!(old.result.streams[0].capture_stream.as_ref().and_then(|item| item.codec.as_deref()),
            result.streams[0].capture_stream.as_ref().and_then(|item| item.codec.as_deref()));
        let stream_id = result.streams[0].capture_stream.as_ref().unwrap().id.as_str();
        assert!(plugin["blocks"].as_array().unwrap().iter().any(|block| block["title"] == "抓包媒体流（流 ID 可复制到深入分析输入框）"
            && block["rows"].as_array().unwrap().iter().any(|row| row[0] == stream_id)));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
