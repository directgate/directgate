/*
 * The libavcodec half of fake_libav.h: the GPU H.264 encoders the agent looks
 * for, their contexts, and packets as fake_av()->packets scripts them.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <libavcodec/avcodec.h>

#include "fake_libav.h"

/* Every encoder the agent knows of; the script decides which of them this build has */
static const AVCodec g_codecs[] = {
    { .name = "h264_nvenc", .long_name = "NVIDIA NVENC H.264 encoder", .type = AVMEDIA_TYPE_VIDEO },
    { .name = "h264_vaapi", .long_name = "H.264/AVC (VAAPI)", .type = AVMEDIA_TYPE_VIDEO },
    { .name = "h264_qsv", .long_name = "H.264 (Intel Quick Sync Video acceleration)", .type = AVMEDIA_TYPE_VIDEO },
    { .name = "h264_amf", .long_name = "AMD AMF H.264 Encoder", .type = AVMEDIA_TYPE_VIDEO },
    { .name = "h264_v4l2m2m", .long_name = NULL, .type = AVMEDIA_TYPE_VIDEO },
};

/* Annex-B parameter sets, and the same two in the length-prefixed form */
static const uint8_t g_annexB[] = { 0, 0, 0, 1, 0x67, 0x42, 0xc0, 0x1f, 0, 0, 0, 1, 0x68, 0xce, 0x3c, 0x80 };
static const uint8_t g_avcc[] = { 0x01, 0x42, 0xc0, 0x1f, 0xff, 0xe1, 0x00, 0x04, 0x67, 0x42, 0xc0, 0x1f };

unsigned avcodec_version(void)
{
    unsigned nMajor = fake_av()->nCodecMajor ? fake_av()->nCodecMajor : LIBAVCODEC_VERSION_MAJOR;
    return (nMajor << 16) | (LIBAVCODEC_VERSION_MINOR << 8) | LIBAVCODEC_VERSION_MICRO;
}

const AVCodec* avcodec_find_encoder_by_name(const char *name)
{
    int bHave = 0;
    for (int i = 0; i < FAKE_AV_MAX && !bHave; i++)
    {
        const char *pEncoder = __atomic_load_n(&fake_av()->pEncoders[i], __ATOMIC_SEQ_CST);
        if (pEncoder == NULL) break;
        bHave = strcmp(pEncoder, name) == 0;
    }

    for (size_t i = 0; i < sizeof(g_codecs) / sizeof(g_codecs[0]) && bHave; i++)
    {
        if (strcmp(g_codecs[i].name, name) == 0) return &g_codecs[i];
    }

    return NULL;
}

AVCodecContext* avcodec_alloc_context3(const AVCodec *codec)
{
    if (fake_av_should_fail("avcodec_alloc_context3")) return NULL;

    AVCodecContext *pCtx = (AVCodecContext*)calloc(1, sizeof(*pCtx));
    if (pCtx == NULL) return NULL;

    pCtx->codec = codec;
    fake_av_count(1);
    return pCtx;
}

void avcodec_free_context(AVCodecContext **avctx)
{
    if (avctx == NULL || *avctx == NULL) return;

    free((*avctx)->extradata);
    av_buffer_unref(&(*avctx)->hw_frames_ctx);
    av_buffer_unref(&(*avctx)->hw_device_ctx);
    free(*avctx);
    *avctx = NULL;
    fake_av_count(-1);
}

int avcodec_open2(AVCodecContext *avctx, const AVCodec *codec, AVDictionary **options)
{
    (void)options;
    fake_av_t *pAv = fake_av();
    fake_av_bump(&pAv->nOpens);
    if (fake_av_should_fail("avcodec_open2")) return AVERROR(EINVAL);

    strncpy(pAv->sLastOpened, codec->name, sizeof(pAv->sLastOpened) - 1);
    pAv->nLastBitrate = avctx->bit_rate;
    pAv->nLastFps = avctx->framerate.num;
    pAv->eLastPixFmt = avctx->pix_fmt;

    const uint8_t *pExtra = pAv->bAvccExtradata ? g_avcc : (pAv->bExtradata ? g_annexB : NULL);
    size_t nExtra = pAv->bAvccExtradata ? sizeof(g_avcc) : sizeof(g_annexB);

    if (pExtra != NULL)
    {
        avctx->extradata = (uint8_t*)calloc(1, nExtra + AV_INPUT_BUFFER_PADDING_SIZE);
        if (avctx->extradata == NULL) return AVERROR(ENOMEM);

        memcpy(avctx->extradata, pExtra, nExtra);
        avctx->extradata_size = (int)nExtra;
    }

    return 0;
}

int avcodec_send_frame(AVCodecContext *avctx, const AVFrame *frame)
{
    if (fake_av_should_fail("avcodec_send_frame")) return AVERROR(EIO);
    if (fake_av_take(&fake_av()->nFailSends)) return AVERROR(EIO);

    fake_av_bump(&fake_av()->nSends);
    fake_av()->eLastPict = frame->pict_type;
    fake_av()->nSendBitrate = avctx->bit_rate;
    return 0;
}

int avcodec_receive_packet(AVCodecContext *avctx, AVPacket *avpkt)
{
    (void)avctx;
    fake_av_t *pAv = fake_av();
    fake_av_packet_t eNext = FAKE_AV_DELTA;

    if (pAv->nPackets > 0)
    {
        eNext = pAv->packets[0];
        memmove(&pAv->packets[0], &pAv->packets[1], sizeof(pAv->packets[0]) * (size_t)(--pAv->nPackets));
    }

    if (eNext == FAKE_AV_AGAIN) return AVERROR(EAGAIN);
    if (eNext == FAKE_AV_FAIL) return AVERROR(EIO);
    if (eNext == FAKE_AV_EMPTY) return 0;

    static const uint8_t delta[] = { 0, 0, 0, 1, 0x41, 0x9a, 0x02, 0x04 };
    static const uint8_t key[] = { 0, 0, 2, 0, 0, 1, 0x65, 0x88, 0x84, 0x00, 0x21 };
    static const uint8_t keySps[] = { 0, 0, 0, 1, 0x67, 0x42, 0xc0, 0x1f, 0, 0, 0, 1, 0x65, 0x88, 0x84, 0x00 };

    static const uint8_t keyAud[] = { 0, 0, 0, 1, 0x09, 0xf0, 0, 0, 0, 1, 0x67, 0x42, 0, 0, 1, 0x65, 0x88, 0x84 };
    static const uint8_t keyBare[] = { 0x65, 0x88, 0x84, 0x00, 0x21, 0x10 };

    const uint8_t *pData = delta;
    size_t nSize = sizeof(delta);
    if (eNext == FAKE_AV_KEY) { pData = key; nSize = sizeof(key); }
    else if (eNext == FAKE_AV_KEY_SPS) { pData = keySps; nSize = sizeof(keySps); }
    else if (eNext == FAKE_AV_KEY_AUD) { pData = keyAud; nSize = sizeof(keyAud); }
    else if (eNext == FAKE_AV_KEY_BARE) { pData = keyBare; nSize = sizeof(keyBare); }

    avpkt->data = (uint8_t*)malloc(nSize);
    if (avpkt->data == NULL) return AVERROR(ENOMEM);

    memcpy(avpkt->data, pData, nSize);
    avpkt->size = (int)nSize;
    avpkt->flags = eNext == FAKE_AV_DELTA ? 0 : AV_PKT_FLAG_KEY;
    return 0;
}

AVPacket* av_packet_alloc(void)
{
    if (fake_av_should_fail("av_packet_alloc")) return NULL;

    AVPacket *pPacket = (AVPacket*)calloc(1, sizeof(*pPacket));
    if (pPacket != NULL) fake_av_count(1);
    return pPacket;
}

void av_packet_unref(AVPacket *pkt)
{
    free(pkt->data);
    pkt->data = NULL;
    pkt->size = 0;
    pkt->flags = 0;
}

void av_packet_free(AVPacket **pkt)
{
    if (pkt == NULL || *pkt == NULL) return;

    av_packet_unref(*pkt);
    free(*pkt);
    *pkt = NULL;
    fake_av_count(-1);
}
