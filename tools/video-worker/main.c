#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/avutil.h>
#include <libavutil/frame.h>
#include <libavutil/motion_vector.h>
#include <libavutil/video_enc_params.h>

static char *wide_to_utf8(const wchar_t *value) {
    int size = WideCharToMultiByte(CP_UTF8, 0, value, -1, NULL, 0, NULL, NULL);
    if (size <= 0) return NULL;
    char *result = (char *)malloc((size_t)size);
    if (!result) return NULL;
    if (!WideCharToMultiByte(CP_UTF8, 0, value, -1, result, size, NULL, NULL)) {
        free(result);
        return NULL;
    }
    return result;
}

static void print_error(const char *operation, int code) {
    char message[AV_ERROR_MAX_STRING_SIZE] = {0};
    av_strerror(code, message, sizeof(message));
    fprintf(stderr, "%s: %s\n", operation, message);
}

static uint64_t parse_u64(const wchar_t *value, uint64_t fallback) {
    wchar_t *end = NULL;
    errno = 0;
    unsigned long long parsed = wcstoull(value, &end, 10);
    if (errno || !end || *end != L'\0') return fallback;
    return (uint64_t)parsed;
}

#ifdef STREAMSCOPE_PATCHED_FFMPEG
#define STREAMSCOPE_MB_INTRA4X4   (1U << 0)
#define STREAMSCOPE_MB_INTRA16X16 (1U << 1)
#define STREAMSCOPE_MB_PCM        (1U << 2)
#define STREAMSCOPE_MB_16X16      (1U << 3)
#define STREAMSCOPE_MB_16X8       (1U << 4)
#define STREAMSCOPE_MB_8X16       (1U << 5)
#define STREAMSCOPE_MB_8X8        (1U << 6)
#define STREAMSCOPE_MB_8X8DCT     (1U << 24)

static const char *h264_partition_mode(uint32_t flags) {
    if (flags & STREAMSCOPE_MB_PCM) return "pcm";
    if (flags & STREAMSCOPE_MB_INTRA16X16) return "intra16x16";
    if (flags & STREAMSCOPE_MB_INTRA4X4)
        return flags & STREAMSCOPE_MB_8X8DCT ? "intra8x8" : "intra4x4";
    if (flags & STREAMSCOPE_MB_16X16) return "16x16";
    if (flags & STREAMSCOPE_MB_16X8) return "16x8";
    if (flags & STREAMSCOPE_MB_8X16) return "8x16";
    if (flags & STREAMSCOPE_MB_8X8) return "8x8";
    return "unknown";
}

static const char *h264_sub_partition_mode(uint16_t flags) {
    if (flags & STREAMSCOPE_MB_16X16) return "8x8";
    if (flags & STREAMSCOPE_MB_16X8) return "8x4";
    if (flags & STREAMSCOPE_MB_8X16) return "4x8";
    if (flags & STREAMSCOPE_MB_8X8) return "4x4";
    return NULL;
}

static const char *hevc_prediction_mode(uint8_t mode) {
    switch (mode) {
        case 0: return "inter";
        case 1: return "intra";
        case 2: return "skip";
        default: return "unknown";
    }
}

static const char *hevc_partition_mode(uint8_t mode) {
    static const char *const modes[] = {
        "2Nx2N", "2NxN", "Nx2N", "NxN",
        "2NxnU", "2NxnD", "nLx2N", "nRx2N"
    };
    return mode < sizeof(modes) / sizeof(modes[0]) ? modes[mode] : "unknown";
}
#endif

static void emit_frame(FILE *output, const AVFrame *frame, uint64_t display_index,
                       AVRational time_base, int first) {
    const AVFrameSideData *encoding =
        av_frame_get_side_data(frame, AV_FRAME_DATA_VIDEO_ENC_PARAMS);
    const AVFrameSideData *vectors =
        av_frame_get_side_data(frame, AV_FRAME_DATA_MOTION_VECTORS);
    const AVVideoEncParams *params = encoding ? (const AVVideoEncParams *)encoding->data : NULL;
    const size_t vector_count = vectors ? vectors->size / sizeof(AVMotionVector) : 0;
    const AVMotionVector *motion = vectors ? (const AVMotionVector *)vectors->data : NULL;
    const char picture_type = av_get_picture_type_char(frame->pict_type);

    if (!first) fputc(',', output);
    fprintf(output,
            "{\"display_index\":%" PRIu64
            ",\"pts\":%" PRId64
            ",\"best_effort_timestamp\":%" PRId64
            ",\"time_base_num\":%d,\"time_base_den\":%d"
            ",\"width\":%d,\"height\":%d,\"key_frame\":%s"
            ",\"picture_type\":\"%c\",\"interlaced\":%s",
            display_index, frame->pts, frame->best_effort_timestamp,
            time_base.num, time_base.den, frame->width, frame->height,
            (frame->flags & AV_FRAME_FLAG_KEY) ? "true" : "false",
            picture_type ? picture_type : '?',
            (frame->flags & AV_FRAME_FLAG_INTERLACED) ? "true" : "false");

    if (params && (params->type == AV_VIDEO_ENC_PARAMS_H264
#ifdef STREAMSCOPE_PATCHED_FFMPEG
                   || params->type == AV_VIDEO_ENC_PARAMS_H265
#endif
                  )) {
        fprintf(output, ",\"qp\":{\"base\":%d,\"blocks\":[", params->qp);
        unsigned int qp_emitted = 0;
        for (unsigned int index = 0; index < params->nb_blocks; ++index) {
            const AVVideoBlockParams *block = av_video_enc_params_block((AVVideoEncParams *)params, index);
#ifdef STREAMSCOPE_PATCHED_FFMPEG
            if (block->block_level != 1 && block->block_level != 2) continue;
#endif
            if (qp_emitted++) fputc(',', output);
            fprintf(output,
                    "{\"x\":%d,\"y\":%d,\"width\":%d,\"height\":%d,"
                    "\"delta\":%d,\"value\":%d}",
                    block->src_x, block->src_y, block->w, block->h,
                    block->delta_qp, params->qp + block->delta_qp);
        }
        fputs("]}", output);
    } else {
        fputs(",\"qp\":null", output);
    }

    fputs(",\"motion_vectors\":[", output);
    for (size_t index = 0; index < vector_count; ++index) {
        const AVMotionVector *vector = &motion[index];
        if (index) fputc(',', output);
        fprintf(output,
                "{\"source_direction\":%d,\"width\":%u,\"height\":%u,"
                "\"source_x\":%d,\"source_y\":%d,\"destination_x\":%d,"
                "\"destination_y\":%d,\"motion_x\":%d,\"motion_y\":%d,"
                "\"motion_scale\":%u,\"flags\":%" PRIu64 "}",
                vector->source, vector->w, vector->h, vector->src_x, vector->src_y,
                vector->dst_x, vector->dst_y, vector->motion_x, vector->motion_y,
                vector->motion_scale, vector->flags);
    }
    fputs("]", output);

#ifdef STREAMSCOPE_PATCHED_FFMPEG
    fputs(",\"block_observations\":[", output);
    if (params) {
        unsigned int block_emitted = 0;
        for (unsigned int index = 0; index < params->nb_blocks; ++index) {
            const AVVideoBlockParams *block =
                av_video_enc_params_block((AVVideoEncParams *)params, index);
            if (block->block_level == 2 || block->block_level == 3) continue;
            const char *level = block->block_level == 1 ? "h264_macroblock" :
                                block->block_level == 2 ? "hevc_min_cb_qp" :
                                block->block_level == 3 ? "hevc_min_pu_sample" :
                                block->block_level == 4 ? "hevc_ctu" :
                                block->block_level == 5 ? "hevc_cu" :
                                block->block_level == 6 ? "hevc_pu" :
                                block->block_level == 7 ? "hevc_tu" : "unknown";
            if (block_emitted++) fputc(',', output);
            fprintf(output,
                    "{\"x\":%d,\"y\":%d,\"width\":%d,\"height\":%d,"
                    "\"block_level\":\"%s\",\"type_flags\":%u,"
                    "\"prediction_flags\":%u",
                    block->src_x, block->src_y, block->w, block->h, level,
                    block->type_flags, block->prediction_flags);
            if (block->block_level == 1 || block->block_level == 5)
                fprintf(output, ",\"qp\":%d", params->qp + block->delta_qp);
            if (block->block_level == 1) {
                fprintf(output, ",\"partition_mode\":\"%s\",\"sub_partition_modes\":[",
                        h264_partition_mode(block->type_flags));
                for (int i = 0; i < 4; i++) {
                    const char *mode = h264_sub_partition_mode(block->sub_type_flags[i]);
                    if (i) fputc(',', output);
                    if (mode) fprintf(output, "\"%s\"", mode);
                    else fputs("null", output);
                }
                fputc(']', output);
            } else if (block->block_level == 5 || block->block_level == 6) {
                fprintf(output, ",\"partition_mode\":\"%s\"",
                        hevc_partition_mode(block->partition_mode));
            }
            if (block->block_level == 5 || block->block_level == 6)
                fprintf(output, ",\"prediction_mode\":\"%s\"",
                        hevc_prediction_mode(block->prediction_mode));
            if (block->block_level >= 4 && block->block_level <= 7)
                fprintf(output, ",\"tree_depth\":%u", block->tree_depth);
            if (block->block_level == 7)
                fprintf(output, ",\"transform_flags\":%u", block->transform_flags);
            if (block->block_level == 1 ||
                (block->block_level == 6 && block->prediction_flags)) {
                fputs(",\"ref_index_l0\":[", output);
                for (int i = 0; i < 4; i++) {
                    if (i) fputc(',', output);
                    fprintf(output, "%d", block->ref_idx[0][i]);
                }
                fputs("],\"ref_index_l1\":[", output);
                for (int i = 0; i < 4; i++) {
                    if (i) fputc(',', output);
                    fprintf(output, "%d", block->ref_idx[1][i]);
                }
                fputs("],\"reference_poc_l0\":[", output);
                for (int i = 0; i < 4; i++) {
                    if (i) fputc(',', output);
                    if (block->ref_poc[0][i] == INT32_MIN) fputs("null", output);
                    else fprintf(output, "%d", block->ref_poc[0][i]);
                }
                fputs("],\"reference_poc_l1\":[", output);
                for (int i = 0; i < 4; i++) {
                    if (i) fputc(',', output);
                    if (block->ref_poc[1][i] == INT32_MIN) fputs("null", output);
                    else fprintf(output, "%d", block->ref_poc[1][i]);
                }
                fputc(']', output);
            }
            if (block->block_level == 6 && block->prediction_flags) {
                fprintf(output,
                        ",\"motion_l0_x\":%d,\"motion_l0_y\":%d,"
                        "\"motion_l1_x\":%d,\"motion_l1_y\":%d",
                        block->motion[0][0], block->motion[0][1],
                        block->motion[1][0], block->motion[1][1]);
            }
            fputc('}', output);
        }
    }
    fputc(']', output);
#else
    fputs(",\"block_observations\":[]", output);
#endif
    fputc('}', output);
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 3 || argc > 5) {
        fprintf(stderr, "usage: video-worker <input> <output.json> [start_frame] [frame_count]\n");
        return 2;
    }

    const uint64_t start_frame = argc >= 4 ? parse_u64(argv[3], 0) : 0;
    uint64_t frame_count = argc >= 5 ? parse_u64(argv[4], 500) : 500;
    if (frame_count == 0 || frame_count > 2000) {
        fprintf(stderr, "frame_count must be between 1 and 2000\n");
        return 2;
    }

    char *input_path = wide_to_utf8(argv[1]);
    FILE *output = _wfopen(argv[2], L"wb");
    if (!input_path || !output) {
        fprintf(stderr, "cannot open input or output\n");
        free(input_path);
        if (output) fclose(output);
        return 3;
    }

    AVFormatContext *format = NULL;
    AVCodecContext *decoder = NULL;
    AVPacket *packet = NULL;
    AVFrame *frame = NULL;
    int result = avformat_open_input(&format, input_path, NULL, NULL);
    if (result < 0) {
        print_error("avformat_open_input", result);
        goto fail;
    }
    result = avformat_find_stream_info(format, NULL);
    if (result < 0) {
        print_error("avformat_find_stream_info", result);
        goto fail;
    }
    const int stream_index = av_find_best_stream(format, AVMEDIA_TYPE_VIDEO, -1, -1, NULL, 0);
    if (stream_index < 0) {
        print_error("av_find_best_stream", stream_index);
        result = stream_index;
        goto fail;
    }
    AVStream *stream = format->streams[stream_index];
    const AVCodec *codec = avcodec_find_decoder(stream->codecpar->codec_id);
    if (!codec) {
        fprintf(stderr, "video decoder not found\n");
        result = AVERROR_DECODER_NOT_FOUND;
        goto fail;
    }
    decoder = avcodec_alloc_context3(codec);
    if (!decoder) {
        result = AVERROR(ENOMEM);
        goto fail;
    }
    result = avcodec_parameters_to_context(decoder, stream->codecpar);
    if (result < 0) {
        print_error("avcodec_parameters_to_context", result);
        goto fail;
    }
    decoder->pkt_timebase = stream->time_base;
    decoder->export_side_data |= AV_CODEC_EXPORT_DATA_MVS | AV_CODEC_EXPORT_DATA_VIDEO_ENC_PARAMS;
    result = avcodec_open2(decoder, codec, NULL);
    if (result < 0) {
        print_error("avcodec_open2", result);
        goto fail;
    }
    packet = av_packet_alloc();
    frame = av_frame_alloc();
    if (!packet || !frame) {
        result = AVERROR(ENOMEM);
        goto fail;
    }

    fprintf(output,
            "{\"schema_version\":\"streamscope.video-worker.v4\","
            "\"ffmpeg_version\":\"%s\",\"codec\":\"%s\","
            "\"requested_start\":%" PRIu64 ",\"requested_count\":%" PRIu64
            ",\"frames\":[",
            av_version_info(), codec->name, start_frame, frame_count);

    uint64_t decoded = 0;
    uint64_t emitted = 0;
    int truncated = 0;
    int reached_eof = 0;
    while ((result = av_read_frame(format, packet)) >= 0) {
        if (packet->stream_index != stream_index) {
            av_packet_unref(packet);
            continue;
        }
        result = avcodec_send_packet(decoder, packet);
        av_packet_unref(packet);
        if (result < 0) {
            print_error("avcodec_send_packet", result);
            goto fail_after_header;
        }
        while ((result = avcodec_receive_frame(decoder, frame)) >= 0) {
            if (decoded >= start_frame && emitted < frame_count) {
                emit_frame(output, frame, decoded, stream->time_base, emitted == 0);
                ++emitted;
            }
            ++decoded;
            av_frame_unref(frame);
            if (emitted >= frame_count) {
                truncated = 1;
                goto complete;
            }
        }
        if (result != AVERROR(EAGAIN) && result != AVERROR_EOF) {
            print_error("avcodec_receive_frame", result);
            goto fail_after_header;
        }
    }
    if (result != AVERROR_EOF) {
        print_error("av_read_frame", result);
        goto fail_after_header;
    }
    result = avcodec_send_packet(decoder, NULL);
    if (result < 0) goto fail_after_header;
    while ((result = avcodec_receive_frame(decoder, frame)) >= 0) {
        if (decoded >= start_frame && emitted < frame_count) {
            emit_frame(output, frame, decoded, stream->time_base, emitted == 0);
            ++emitted;
        }
        ++decoded;
        av_frame_unref(frame);
        if (emitted >= frame_count) {
            truncated = 1;
            break;
        }
    }
    reached_eof = !truncated;

complete:
    fprintf(output,
            "],\"decoded_through\":%" PRIu64 ",\"emitted_frames\":%" PRIu64
            ",\"window_complete\":%s,\"source_eof_reached\":%s,\"truncated\":%s}",
            decoded, emitted, emitted == frame_count ? "true" : "false",
            reached_eof ? "true" : "false", truncated ? "true" : "false");
    fclose(output);
    av_frame_free(&frame);
    av_packet_free(&packet);
    avcodec_free_context(&decoder);
    avformat_close_input(&format);
    free(input_path);
    return 0;

fail_after_header:
    fputs("],\"worker_error\":true}", output);
fail:
    fclose(output);
    av_frame_free(&frame);
    av_packet_free(&packet);
    avcodec_free_context(&decoder);
    avformat_close_input(&format);
    free(input_path);
    return result < 0 ? 4 : 3;
}
