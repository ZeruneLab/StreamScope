use std::path::{Path, PathBuf};

fn find_distribution(target: &str) -> PathBuf {
    let suffix = if target.contains("windows") {
        ".exe"
    } else {
        ""
    };
    let configured = std::env::var_os("STREAMSCOPE_FFMPEG_DIR")
        .map(PathBuf::from)
        .into_iter();
    let path = std::env::var_os("PATH")
        .map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter();
    configured
        .chain(path)
        .find(|directory| {
            directory.join(format!("ffmpeg{suffix}")).is_file()
                && directory.join(format!("ffprobe{suffix}")).is_file()
                && directory
                    .parent()
                    .is_some_and(|parent| parent.join("LICENSE").is_file())
                && directory
                    .parent()
                    .is_some_and(|parent| parent.join("README.txt").is_file())
        })
        .unwrap_or_else(|| {
            panic!(
                "未找到包含 ffmpeg、ffprobe、LICENSE 和 README.txt 的发行目录；构建机需将 FFmpeg bin 目录加入 PATH，或设置 STREAMSCOPE_FFMPEG_DIR"
            )
        })
}

fn copy_required(source: &Path, destination: &Path) {
    std::fs::copy(source, destination).unwrap_or_else(|error| {
        panic!(
            "无法暂存 {} 到 {}：{error}",
            source.display(),
            destination.display()
        )
    });
}

fn stage_ffmpeg() {
    let target = std::env::var("TARGET").expect("TARGET is set by Cargo");
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let output = manifest.join("binaries");
    std::fs::create_dir_all(&output).expect("无法创建 FFmpeg 暂存目录");

    let distribution_bin = find_distribution(&target);
    let suffix = if target.contains("windows") {
        ".exe"
    } else {
        ""
    };
    let ffmpeg = distribution_bin.join(format!("ffmpeg{suffix}"));
    let ffprobe = distribution_bin.join(format!("ffprobe{suffix}"));
    let mut sidecar_targets = vec![target.clone()];
    if target == "x86_64-pc-windows-gnu" {
        sidecar_targets.push("x86_64-pc-windows-msvc".into());
    }
    for sidecar_target in sidecar_targets {
        copy_required(
            &ffmpeg,
            &output.join(format!("ffmpeg-{sidecar_target}.exe")),
        );
        copy_required(
            &ffprobe,
            &output.join(format!("ffprobe-{sidecar_target}.exe")),
        );
    }

    let distribution = distribution_bin.parent().expect("FFmpeg 目录结构无效");
    copy_required(
        &distribution.join("LICENSE"),
        &output.join("FFmpeg-LICENSE.txt"),
    );
    copy_required(
        &distribution.join("README.txt"),
        &output.join("FFmpeg-README.txt"),
    );
}

fn main() {
    println!("cargo:rerun-if-env-changed=PATH");
    println!("cargo:rerun-if-env-changed=STREAMSCOPE_FFMPEG_DIR");
    stage_ffmpeg();
    tauri_build::build()
}
