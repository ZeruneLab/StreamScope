use clap::{Parser, Subcommand};
#[cfg(feature = "compat")]
use clap::{ArgGroup, ValueEnum};
use std::path::{Path, PathBuf};
use std::time::Duration;
#[cfg(feature = "compat")]
use streamscope_analyzer::{
    AnalysisRun, AnalyzeOptions, AudioFileOptions, H264FileOptions, H265FileOptions,
    PcapFileOptions, analyze_audio_file, analyze_h264_file, analyze_h265_file, analyze_pcap_file,
    analyze_rtsp, compare_rtsp,
};
#[cfg(feature = "compat")]
use streamscope_core::{Transport, redact_rtsp_url};

#[derive(Debug, Parser)]
#[command(
    name = "streamscope",
    version,
    about = "StreamScope 诊断与功能插件宿主"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// 列出或执行当前用户已安装并启用的功能插件
    Plugin {
        #[command(subcommand)]
        command: PluginCommand,
    },
    #[cfg(feature = "compat")]
    /// 分析 PCAP/PCAPNG 中的 SIP 信令、事务、呼叫和 SDP 媒体关联
    Sip {
        #[arg(long)]
        pcap: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    #[cfg(feature = "compat")]
    /// 分析 RTSP 地址、Annex B H.264/H.265、音频或抓包文件并生成报告
    #[command(group(ArgGroup::new("input").required(true).multiple(false).args(["url", "h264", "h265", "audio", "pcap"])))]
    Analyze {
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        h264: Option<PathBuf>,
        #[arg(long)]
        h265: Option<PathBuf>,
        #[arg(long)]
        audio: Option<PathBuf>,
        #[arg(long)]
        pcap: Option<PathBuf>,
        /// PCAP 深入解码流 ID（逗号分隔），* 表示全部；省略时仅扫描统计
        #[arg(long, value_delimiter = ',', requires = "pcap")]
        streams: Vec<String>,
        #[arg(long, value_enum, default_value_t = TransportArgument::Tcp)]
        transport: TransportArgument,
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=86_400))]
        duration: u64,
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=300))]
        connect_timeout: u64,
        #[arg(long, default_value = "./reports")]
        output: PathBuf,
    },
    #[cfg(feature = "compat")]
    /// 对同一 RTSP 地址依次执行 TCP 与 UDP 诊断
    Compare {
        #[arg(long)]
        url: String,
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=86_400))]
        duration: u64,
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=300))]
        connect_timeout: u64,
        #[arg(long, default_value = "./reports")]
        output: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum PluginCommand {
    List,
    Run {
        #[arg(long)]
        id: String,
        #[arg(long)]
        action: String,
        /// JSON 输入文件，避免在命令行参数中直接暴露凭据
        #[arg(long)]
        input: PathBuf,
        #[arg(long, default_value = "./reports")]
        output: PathBuf,
    },
}

#[cfg(feature = "compat")]
#[derive(Debug, Clone, Copy, ValueEnum)]
enum TransportArgument {
    Tcp,
    Udp,
}

#[cfg(feature = "compat")]
impl From<TransportArgument> for Transport {
    fn from(value: TransportArgument) -> Self {
        match value {
            TransportArgument::Tcp => Self::Tcp,
            TransportArgument::Udp => Self::Udp,
        }
    }
}

fn main() {
    let exit_code = match Cli::parse().command {
        Commands::Plugin { command } => plugin_command(command),
        #[cfg(feature = "compat")]
        Commands::Sip { pcap, output } => {
            let result = streamscope_sip::analyze_pcap(&pcap)
                .map_err(|error| error.to_string())
                .and_then(|report| {
                    serde_json::to_string_pretty(&report).map_err(|error| error.to_string())
                });
            result.and_then(|json| {
                if let Some(path) = output {
                    std::fs::write(&path, json).map_err(|error| error.to_string())?;
                    println!("SIP JSON：{}", path.display());
                } else {
                    println!("{json}");
                }
                Ok(())
            })
        }
        #[cfg(feature = "compat")]
        Commands::Analyze {
            url,
            h264,
            h265,
            audio,
            pcap,
            streams,
            transport,
            duration,
            connect_timeout,
            output,
        } => match (url, h264, h265, audio, pcap) {
            (Some(url), None, None, None, None) => {
                analyze(&url, transport.into(), duration, connect_timeout, &output)
            }
            (None, Some(input), None, None, None) => analyze_h264(&input, &output),
            (None, None, Some(input), None, None) => analyze_h265(&input, &output),
            (None, None, None, Some(input), None) => analyze_audio(&input, &output),
            (None, None, None, None, Some(input)) => analyze_pcap(&input, &output, streams),
            _ => unreachable!("clap input group enforces exactly one input"),
        },
        #[cfg(feature = "compat")]
        Commands::Compare {
            url,
            duration,
            connect_timeout,
            output,
        } => compare(&url, duration, connect_timeout, &output),
    };
    if let Err(message) = exit_code {
        eprintln!("错误：{message}");
        std::process::exit(2);
    }
}

fn plugin_command(command: PluginCommand) -> Result<(), String> {
    use streamscope_plugin_host::{ArtifactStore, PluginProcess, PluginStore, save_plugin_report_with_artifacts, stage_file_inputs_with_progress, stage_media_outputs};
    let local_data = std::env::var_os("LOCALAPPDATA")
        .ok_or_else(|| "无法确定当前用户的 LOCALAPPDATA 目录".to_string())?;
    let store = PluginStore::new(PathBuf::from(local_data).join("StreamScope").join("plugins"));
    match command {
        PluginCommand::List => {
            for item in store.list().map_err(|error| error.to_string())? {
                println!("{} {} [{}]", item.manifest.id, item.manifest.version,
                    if item.enabled { "已启用" } else { "已禁用" });
                if item.enabled {
                    for contribution in &item.manifest.contributions {
                        println!("  {} — {}", contribution.action, contribution.title);
                    }
                }
            }
        }
        PluginCommand::Run { id, action, input, output } => {
            let item = store.list().map_err(|error| error.to_string())?.into_iter()
                .find(|item| item.manifest.id == id && item.enabled)
                .ok_or_else(|| "插件未安装或已禁用".to_string())?;
            let contribution = item.manifest.contributions.iter().find(|entry| entry.action == action)
                .ok_or_else(|| "插件未声明该动作".to_string())?;
            let mut values: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(
                &std::fs::read(input).map_err(|error| error.to_string())?
            ).map_err(|error| format!("插件输入必须是 JSON 对象：{error}"))?;
            let ui = store.ui_document(&id).map_err(|error| error.to_string())?;
            let artifacts = ArtifactStore::new(output.clone());
            let mut references = stage_file_inputs_with_progress(&artifacts, &ui, &contribution.view, &mut values, &mut |field, copied, total| {
                eprintln!("准备产物 {field}：{copied}/{total} B");
            })
                .map_err(|error| error.to_string())?;
            if item.manifest.permissions.iter().any(|permission| permission.name == "report-write") {
                values.insert("_hostOutputRoot".into(), output.to_string_lossy().into_owned().into());
            } else {
                values.remove("_hostOutputRoot");
            }
            let executable = store.executable(&id).map_err(|error| error.to_string())?;
            let ffmpeg_dir = if item.manifest.dependencies.iter().any(|dependency| dependency.id == "org.streamscope.ffmpeg") {
                let ffmpeg = store.runtime_file("org.streamscope.ffmpeg", "bin/ffmpeg.exe")
                    .map_err(|error| error.to_string())?;
                store.runtime_file("org.streamscope.ffmpeg", "bin/ffprobe.exe")
                    .map_err(|error| error.to_string())?;
                if id == "org.streamscope.video-deep" {
                    store.runtime_file("org.streamscope.ffmpeg", "bin/video-worker.exe")
                        .map_err(|error| error.to_string())?;
                }
                ffmpeg.parent().map(Path::to_path_buf)
            } else { None };
            let mut process = PluginProcess::spawn_with_runtime(&executable, ffmpeg_dir.as_deref())
                .map_err(|error| error.to_string())?;
            let mut result = process.request("execute", serde_json::json!({"action":action,"input":values}),
                Duration::from_secs(600), |progress| eprintln!("进度：{progress}"))
                .map_err(|error| error.to_string())?;
            stage_media_outputs(&artifacts, &mut result, &mut references).map_err(|error| error.to_string())?;
            let report = save_plugin_report_with_artifacts(&output.join("plugins-v2"), &item, &action, &result, &references)
                .map_err(|error| error.to_string())?;
            println!("插件报告：{}", report.display());
        }
    }
    Ok(())
}

#[cfg(feature = "compat")]
fn compare(
    source_url: &str,
    duration_seconds: u64,
    connect_timeout_seconds: u64,
    output_root: &Path,
) -> Result<(), String> {
    println!(
        "开始 TCP/UDP 对比：{}",
        redact_rtsp_url(source_url).map_err(|error| error.to_string())?
    );
    let result = compare_rtsp(AnalyzeOptions {
        source_url: source_url.into(),
        transport: Transport::Tcp,
        duration_seconds,
        connect_timeout_seconds,
        output_root: output_root.into(),
    })
    .map_err(|error| error.to_string())?;
    for conclusion in result.conclusions {
        println!("结论：{conclusion}");
    }
    println!("对比 JSON：{}", result.json);
    println!("对比 HTML：{}", result.html);
    Ok(())
}

#[cfg(feature = "compat")]
fn analyze(
    source_url: &str,
    transport: Transport,
    duration_seconds: u64,
    connect_timeout_seconds: u64,
    output_root: &Path,
) -> Result<(), String> {
    let safe_url = redact_rtsp_url(source_url).map_err(|error| error.to_string())?;
    println!("开始分析：{safe_url}");
    let run = analyze_rtsp(AnalyzeOptions {
        source_url: source_url.into(),
        transport,
        duration_seconds,
        connect_timeout_seconds,
        output_root: output_root.into(),
    })
    .map_err(|error| error.to_string())?;
    print_run(run);
    Ok(())
}

#[cfg(feature = "compat")]
fn analyze_h264(input: &Path, output_root: &Path) -> Result<(), String> {
    println!("开始分析 H.264 文件：{}", input.display());
    let run = analyze_h264_file(H264FileOptions {
        input: input.into(),
        output_root: output_root.into(),
        process_timeout_seconds: 300,
    })
    .map_err(|error| error.to_string())?;
    print_run(run);
    Ok(())
}

#[cfg(feature = "compat")]
fn analyze_h265(input: &Path, output_root: &Path) -> Result<(), String> {
    println!("开始分析 H.265 文件：{}", input.display());
    let run = analyze_h265_file(H265FileOptions {
        input: input.into(),
        output_root: output_root.into(),
        process_timeout_seconds: 300,
    })
    .map_err(|error| error.to_string())?;
    print_run(run);
    Ok(())
}

#[cfg(feature = "compat")]
fn analyze_audio(input: &Path, output_root: &Path) -> Result<(), String> {
    println!("开始分析音频文件：{}", input.display());
    let run = analyze_audio_file(AudioFileOptions {
        input: input.into(),
        output_root: output_root.into(),
        process_timeout_seconds: 300,
    })
    .map_err(|error| error.to_string())?;
    print_run(run);
    Ok(())
}

#[cfg(feature = "compat")]
fn analyze_pcap(input: &Path, output_root: &Path, stream_ids: Vec<String>) -> Result<(), String> {
    println!("开始分析抓包文件：{}", input.display());
    let run = analyze_pcap_file(PcapFileOptions {
        input: input.into(),
        output_root: output_root.into(),
        process_timeout_seconds: 300,
        stream_ids,
    })
    .map_err(|error| error.to_string())?;
    print_run(run);
    Ok(())
}

#[cfg(feature = "compat")]
fn print_run(run: AnalysisRun) {
    println!("状态：{:?}", run.result.status);
    println!("JSON：{}", run.reports.json);
    println!("HTML：{}", run.reports.html);
    println!("FFmpeg 日志：{}", run.reports.ffmpeg_log);
    if let Some(path) = run.reports.session_sdp {
        println!("SDP：{path}");
    }
}
