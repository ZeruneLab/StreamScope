#!/usr/bin/env bash
set -euo pipefail

source_dir="${1:?FFmpeg source directory is required}"
build_dir="${2:?build directory is required}"
prefix_dir="${3:?install prefix is required}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$build_dir" "$prefix_dir"
# The Windows-native MinGW make cannot resolve MSYS /c/... source paths in an
# out-of-tree makefile, so build in the disposable fixed-source directory.
cd "$source_dir"

if grep -q "streamscope_sub_mb_type" libavcodec/h264dec.h && \
   grep -q "streamscope_tu_log2_size" libavcodec/hevc/hevcdec.h && \
   grep -q "pending_export" libavcodec/hevc/refs.c; then
  :
elif grep -q "AV_VIDEO_ENC_PARAMS_H265" libavutil/video_enc_params.h || \
     grep -q "streamscope_sub_mb_type" libavcodec/h264dec.h; then
  echo "FFmpeg source contains an older StreamScope patch; use a clean 9.0.1 source tree." >&2
  exit 1
else
  patch -p1 < "$script_dir/ffmpeg-9.0.1-streamscope.patch"
fi

./configure \
  --prefix="$prefix_dir" \
  --disable-everything \
  --disable-autodetect \
  --disable-programs \
  --disable-doc \
  --disable-debug \
  --disable-shared \
  --enable-static \
  --enable-avcodec \
  --enable-avformat \
  --enable-avutil \
  --enable-decoder=h264,hevc,mpeg2video \
  --enable-parser=h264,hevc \
  --enable-demuxer=h264,hevc,mov,matroska \
  --enable-protocol=file \
  --enable-small \
  --extra-cflags="-O2"

mingw32-make -j4
mingw32-make install
