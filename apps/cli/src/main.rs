use clap::{ArgGroup, Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};
use streamscope_analyzer::{
    AnalysisRun, AnalyzeOptions, AudioFileOptions, H264FileOptions, H265FileOptions,
    PcapFileOptions, analyze_audio_file, analyze_h264_file, analyze_h265_file, analyze_pcap_file,
    analyze_rtsp, compare_rtsp,
};
use streamscope_core::{Transport, redact_rtsp_url};

#[derive(Debug, Parser)]
#[command(
    name = "streamscope",
    version,
    about = "RTSP/RTP/H.264/H.265/音频智能诊断工具"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TransportArgument {
    Tcp,
    Udp,
}

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

fn print_run(run: AnalysisRun) {
    println!("状态：{:?}", run.result.status);
    println!("JSON：{}", run.reports.json);
    println!("HTML：{}", run.reports.html);
    println!("FFmpeg 日志：{}", run.reports.ffmpeg_log);
    if let Some(path) = run.reports.session_sdp {
        println!("SDP：{path}");
    }
}
