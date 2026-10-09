use serde_json::{Value, json};
use std::path::Path;
use std::time::Duration;
use streamscope_core::{AnalysisResult, H264FrameEvidence, VideoFrameIndex, VideoSyntaxDocument};

fn frame_evidence<'a>(indexed: &VideoFrameIndex, evidence: &'a [H264FrameEvidence]) -> Result<(&'a H264FrameEvidence, &'static str), String> {
    if let Some(index) = indexed.decode_index {
        return evidence.iter().find(|frame| frame.frame_number == index + 1)
            .map(|frame| (frame, "ffmpeg_coded_picture_number_to_parser_access_unit"))
            .ok_or_else(|| "没有对应的编码顺序访问单元证据".into());
    }
    let start = indexed.packet_position.ok_or("当前帧没有可靠码流位置")?;
    let end = start.checked_add(indexed.packet_size.ok_or("当前帧没有码流大小")?).ok_or("码流范围溢出")?;
    let mut matches = evidence.iter().filter(|frame| matches!((frame.sample_start_offset, frame.sample_end_offset),
        (Some(a), Some(b)) if start <= a && a < b && b == end));
    let frame = matches.next().ok_or("当前帧字节范围不能唯一映射到访问单元")?;
    if matches.next().is_some() { return Err("访问单元映射不唯一，已拒绝猜测".into()); }
    Ok((frame, "ffprobe_packet_byte_range_to_parser_access_unit"))
}

fn syntax(source: &Path, result: &AnalysisResult, display_index: u64) -> Result<VideoSyntaxDocument, String> {
    let deep = result.h264.as_ref().and_then(|analysis| analysis.deep_analysis.as_ref())
        .or_else(|| result.h265.as_ref().and_then(|analysis| analysis.deep_analysis.as_ref())).ok_or("报告没有逐帧索引")?;
    let indexed = deep.frames.iter().find(|frame| frame.display_index == display_index).ok_or("帧号不在索引中")?;
    let (codec, frames, evidence_nalus) = if let Some(analysis) = &result.h264 { ("h264", &analysis.frames, &analysis.nalus) }
        else if let Some(analysis) = &result.h265 { ("h265", &analysis.frames, &analysis.nalus) } else { return Err("报告不是视频结果".into()); };
    let (evidence, precision) = frame_evidence(indexed, frames)?;
    let mut nalus = Vec::new();
    for first in (evidence.first_nalu..=evidence.last_nalu).step_by(50) {
        nalus.extend(streamscope_analyzer::inspect_annex_b_file_syntax(source, codec, first, first.saturating_add(49).min(evidence.last_nalu)).map_err(|error| error.to_string())?);
    }
    if nalus.is_empty() { return Err("访问单元没有可读取的 NALU".into()); }
    for nalu in &mut nalus {
        if let Some(evidence) = evidence_nalus.iter().find(|evidence| evidence.nalu_number == nalu.index) {
            nalu.complete = Some(evidence.complete); nalu.access_unit_number = evidence.access_unit_number; nalu.packets = evidence.packets.clone();
        }
    }
    Ok(VideoSyntaxDocument { codec: codec.into(), display_index, access_unit_index: Some(evidence.frame_number),
        mapping_precision: precision.into(), nalus,
        limitations: vec!["复用共享解析器的 NALU/参数集/Slice 前缀；不猜测完整 CABAC/CAVLC 语法。".into(), "优先使用编码序号，否则验证唯一字节范围；不把显示帧号当成访问单元号。".into()] })
}

pub fn execute(input: &Value, progress: &mut dyn FnMut(Value)) -> Result<Value, String> {
    let source = Path::new(input["path"].as_str().unwrap_or(""));
    let report = Path::new(input["reportPath"].as_str().unwrap_or(""));
    if !source.is_file() || !report.is_file() { return Err("缺少同路视频样本或报告".into()); }
    let result: AnalysisResult = serde_json::from_reader(std::io::BufReader::new(std::fs::File::open(report).map_err(|error| error.to_string())?)).map_err(|error| error.to_string())?;
    let index = super::number(input, "displayIndex", 0)?;
    let deep = result.h264.as_ref().and_then(|analysis| analysis.deep_analysis.as_ref())
        .or_else(|| result.h265.as_ref().and_then(|analysis| analysis.deep_analysis.as_ref())).ok_or("报告没有逐帧索引")?;
    if !deep.frames.iter().any(|frame| frame.display_index == index) { return Err("帧号不在已索引范围内".into()); }
    let operation = input["operation"].as_str().unwrap_or("");
    if !matches!(operation, "extract_video_frame" | "analyze_video_frame_blocks" | "load_video_frame_syntax" | "export_video_block_csv" | "compare_video_reference") { return Err("未知视频报告动作".into()); }
    let directory = super::output_directory(input, "video-tools")?;
    progress(json!({"percent":5,"stage":"视频证据","detail":format!("正在处理显示帧 {index}")}));
    let mut output = json!({"summary":"视频证据处理完成","reportDirectory":directory,"operation":operation,"sourceReport":input["sourceReport"],"sourceStream":input["sourceStream"]});
    match operation {
        "extract_video_frame" => {
            let image = directory.join(format!("frame-{index}.png"));
            streamscope_ffmpeg::extract_video_frame(source, &image, index, Duration::from_secs(120)).map_err(|error| error.to_string())?;
            output["previewFrame"] = json!(image); output["data"] = json!(frontend_path(&image));
        }
        "analyze_video_frame_blocks" | "export_video_block_csv" => {
            let frame = streamscope_ffmpeg::analyze_video_frame_blocks(source, &directory.join("blocks.json"), index, Duration::from_secs(120)).map_err(|error| error.to_string())?;
            output["data"] = json!(frame);
            if operation == "export_video_block_csv" {
                let file = directory.join("blocks.csv"); std::fs::write(&file, block_csv(&frame)).map_err(|error| error.to_string())?;
                output["downloadFile"] = json!(file);
            }
        }
        "load_video_frame_syntax" => { output["data"] = json!(syntax(source, &result, index)?); }
        "compare_video_reference" => {
            let reference = Path::new(input["referencePath"].as_str().unwrap_or(""));
            if !reference.is_file() { return Err("请选择现有参考视频".into()); }
            let mut comparison = streamscope_ffmpeg::compare_video_reference(source, reference, Duration::from_secs(300)).map_err(|error| error.to_string())?;
            let difference = directory.join("video-reference-difference.mp4");
            match streamscope_ffmpeg::create_video_reference_difference_preview(source, reference, &difference, Duration::from_secs(300)) {
                Ok(()) => { output["previewVideo"] = json!(frontend_path(&difference)); comparison.limitations.push("差异预览增强像素差，仅用于定位，不参与质量指标计算。".into()); }
                Err(_) => comparison.limitations.push("差异预览未生成；质量指标结果保留。".into()),
            }
            output["data"] = json!(comparison);
        }
        _ => unreachable!(),
    }
    // Full block/packet evidence can exceed the pipe's 4 MiB frame limit.
    // Keep it in an artifact; do not truncate the evidence to fit JSON-RPC.
    let data = output.as_object_mut().unwrap().remove("data").unwrap();
    let file = directory.join("tool-result.json");
    std::fs::write(&file, serde_json::to_vec(&data).map_err(|error| error.to_string())?).map_err(|error| error.to_string())?;
    output["dataFile"] = json!(file);
    progress(json!({"percent":100,"stage":"完成","detail":"证据已生成，原报告未修改"}));
    Ok(output)
}

fn frontend_path(path: &Path) -> String {
    let path = path.to_string_lossy();
    if let Some(path) = path.strip_prefix(r"\\?\UNC\") { return format!(r"\\{path}"); }
    path.strip_prefix(r"\\?\").unwrap_or(&path).to_owned()
}

fn row(values: &[String]) -> String { format!("{}\r\n", values.iter().map(|value| format!("\"{}\"", value.replace('"', "\"\""))).collect::<Vec<_>>().join(",")) }
fn optional<T: ToString>(value: Option<T>) -> String { value.map(|value| value.to_string()).unwrap_or_default() }

pub(super) fn block_csv(frame: &streamscope_ffmpeg::VideoWorkerFrame) -> String {
    let mut csv = String::from("record_type,index,x,y,width,height,qp_base,qp_delta,qp_value,source_direction,source_x,source_y,destination_x,destination_y,motion_x,motion_y,motion_scale,flags,block_level,type_flags,prediction_flags,ref_index_l0,ref_index_l1,reference_poc_l0,reference_poc_l1,partition_mode,sub_partition_modes,prediction_mode,tree_depth,transform_flags\r\n");
    if let Some(qp) = &frame.qp { for (index, block) in qp.blocks.iter().enumerate() {
        let mut values = vec![String::new(); 30];
        values[..9].clone_from_slice(&["qp".into(), index.to_string(), block.x.to_string(), block.y.to_string(), block.width.to_string(), block.height.to_string(), qp.base.to_string(), block.delta.to_string(), block.value.to_string()]);
        csv.push_str(&row(&values));
    } }
    for (index, vector) in frame.motion_vectors.iter().enumerate() {
        let mut values = vec![String::new(); 30]; values[0] = "mv".into(); values[1] = index.to_string(); values[4] = vector.width.to_string(); values[5] = vector.height.to_string();
        values[9..18].clone_from_slice(&[vector.source_direction.to_string(), vector.source_x.to_string(), vector.source_y.to_string(), vector.destination_x.to_string(), vector.destination_y.to_string(), vector.motion_x.to_string(), vector.motion_y.to_string(), vector.motion_scale.to_string(), vector.flags.to_string()]);
        csv.push_str(&row(&values));
    }
    for (index, block) in frame.block_observations.iter().enumerate() {
        let mut values = vec![String::new(); 30];
        values[..6].clone_from_slice(&["internal".into(), index.to_string(), block.x.to_string(), block.y.to_string(), block.width.to_string(), block.height.to_string()]);
        values[8] = optional(block.qp); values[14] = optional(block.motion_l0_x); values[15] = optional(block.motion_l0_y);
        values[18..30].clone_from_slice(&[block.block_level.clone(), block.type_flags.to_string(), block.prediction_flags.to_string(),
            block.ref_index_l0.iter().map(ToString::to_string).collect::<Vec<_>>().join(";"), block.ref_index_l1.iter().map(ToString::to_string).collect::<Vec<_>>().join(";"),
            block.reference_poc_l0.iter().map(|value| optional(*value)).collect::<Vec<_>>().join(";"), block.reference_poc_l1.iter().map(|value| optional(*value)).collect::<Vec<_>>().join(";"),
            block.partition_mode.clone().unwrap_or_default(), block.sub_partition_modes.iter().map(|value| value.clone().unwrap_or_default()).collect::<Vec<_>>().join(";"), block.prediction_mode.clone().unwrap_or_default(), optional(block.tree_depth), optional(block.transform_flags)]);
        csv.push_str(&row(&values));
    }
    csv
}

pub(super) fn audio_csv(issues: &[streamscope_core::AudioIssue], intervals: &[streamscope_core::AudioQualityInterval]) -> String {
    let mut csv = String::from("\u{feff}record_type,kind,start_ms,end_ms,duration_ms,channel,previous_packet,current_packet,last_packet,previous_seq,current_seq,last_seq,expected_rtp_timestamp,actual_rtp_timestamp,delta_timestamp,previous_arrival_ms,current_arrival_ms,detail,precision\r\n");
    for issue in issues {
        csv.push_str(&row(&["timestamp_issue".into(),issue.kind.clone(), optional(issue.media_start_ms), optional(issue.media_end_ms), optional(issue.duration_ms), String::new(), optional(issue.previous_packet), optional(issue.first_packet), String::new(), optional(issue.previous_rtp_sequence),optional(issue.current_rtp_sequence),String::new(), optional(issue.expected_rtp_timestamp),optional(issue.actual_rtp_timestamp),optional(issue.delta_timestamp),optional(issue.previous_offset_ms),optional(issue.offset_ms),issue.detail.clone(),"rtp_timestamp+sequence_order".into()]));
    }
    for interval in intervals {
        csv.push_str(&row(&["content_interval".into(),interval.kind.clone(), interval.start_ms.to_string(),interval.end_ms.to_string(),interval.end_ms.saturating_sub(interval.start_ms).to_string(),optional(interval.channel),String::new(),optional(interval.first_packet),optional(interval.last_packet),String::new(),optional(interval.first_rtp_sequence),optional(interval.last_rtp_sequence),String::new(),String::new(),String::new(),String::new(),String::new(),interval.detail.clone(),interval.precision.clone()]));
    }
    csv
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_samples_cannot_run_report_tools() { assert!(execute(&json!({}), &mut |_| {}).is_err()); }
    #[test]
    fn csv_quotes_multiline_and_comma_evidence() { assert_eq!(row(&["a,\"b\"\nc".into()]), "\"a,\"\"b\"\"\nc\"\r\n"); }
}
