use std::path::{Path, PathBuf};
use std::process::Command;

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

fn find_video_worker_distribution(manifest: &Path) -> PathBuf {
    let configured = std::env::var_os("STREAMSCOPE_VIDEO_WORKER_FFMPEG_DIR")
        .map(PathBuf::from)
        .map(|path| {
            if path.join("include").is_dir() {
                path
            } else {
                path.parent().map(Path::to_path_buf).unwrap_or(path)
            }
        });
    configured
        .or_else(|| {
            let patched = manifest
                .join("../../../target/tool-cache/ffmpeg-9.0.1-streamscope-install");
            if patched.join("include").is_dir() {
                return Some(patched);
            }
            let cached = manifest
                .join("../../../target/tool-cache/ffmpeg-9.0.1-full_build-shared");
            cached.join("include").is_dir().then_some(cached)
        })
        .filter(|distribution| {
            distribution.join("include/libavcodec/avcodec.h").is_file()
                && (distribution.join("lib/libavcodec.a").is_file()
                    || (distribution.join("lib/libavcodec.dll.a").is_file()
                        && distribution.join("bin/avcodec-63.dll").is_file()))
        })
        .unwrap_or_else(|| {
            panic!(
                "未找到 FFmpeg 9.0.1 shared 开发包；设置 STREAMSCOPE_VIDEO_WORKER_FFMPEG_DIR 指向包含 include、lib、bin 的发行目录"
            )
        })
}

fn stage_video_worker() {
    let target = std::env::var("TARGET").expect("TARGET is set by Cargo");
    if !target.contains("windows") {
        return;
    }
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let output = manifest.join("binaries");
    let distribution = find_video_worker_distribution(&manifest);
    let source = manifest.join("../../../tools/video-worker/main.c");
    let staged = output.join(format!("video-worker-{target}.exe"));
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "gcc".into());
    let static_patched = distribution.join("lib/libavcodec.a").is_file();
    let mut command = Command::new(compiler);
    command
        .args([
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-municode",
            "-static-libgcc",
        ])
        .arg(format!("-I{}", distribution.join("include").display()))
        .arg(&source)
        .arg(format!("-L{}", distribution.join("lib").display()))
        .args(["-lavformat", "-lavcodec", "-lavutil"]);
    if static_patched {
        command.args([
            "-DSTREAMSCOPE_PATCHED_FFMPEG=1",
            "-static",
            "-lws2_32",
            "-lsecur32",
            "-lbcrypt",
            "-lstrmiids",
            "-lole32",
            "-luuid",
            "-lm",
        ]);
    }
    let status = command
        .arg("-o")
        .arg(&staged)
        .status()
        .unwrap_or_else(|error| panic!("无法启动 video-worker C 编译器：{error}"));
    assert!(status.success(), "video-worker 编译失败");
    if target == "x86_64-pc-windows-gnu" {
        copy_required(
            &staged,
            &output.join("video-worker-x86_64-pc-windows-msvc.exe"),
        );
    }
    if !static_patched {
        for library in [
            "avcodec-63.dll",
            "avformat-63.dll",
            "avutil-61.dll",
            "swresample-7.dll",
            "swscale-10.dll",
        ] {
            copy_required(
                &distribution.join("bin").join(library),
                &output.join(library),
            );
        }
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=PATH");
    println!("cargo:rerun-if-env-changed=STREAMSCOPE_FFMPEG_DIR");
    println!("cargo:rerun-if-env-changed=STREAMSCOPE_VIDEO_WORKER_FFMPEG_DIR");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-changed=../../../tools/video-worker/main.c");
    println!(
        "cargo:rerun-if-changed=../../../target/tool-cache/ffmpeg-9.0.1-streamscope-install/lib/libavcodec.a"
    );
    println!(
        "cargo:rerun-if-changed=../../../target/tool-cache/ffmpeg-9.0.1-streamscope-install/include/libavutil/video_enc_params.h"
    );
    stage_ffmpeg();
    stage_video_worker();
    tauri_build::build()
}
