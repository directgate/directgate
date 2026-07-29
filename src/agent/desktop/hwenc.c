/*!
 * @file directgate-agent/src/agent/desktop/hwenc.c
 * @brief Runtime-loaded GPU H.264 encoder (NVENC / VAAPI / QSV / AMF) for desktop streaming.
 *
 *  Copyright (c) 2025-2026 DirectGate. All rights reserved.
 *  Author: Sandro Kalatozishvili (sandro@directgate.io)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "hwenc.h"

#ifdef DIRECTGATE_HAVE_HWENC

#include <dlfcn.h>

#include <libavcodec/avcodec.h>
#include <libavutil/avutil.h>
#include <libavutil/dict.h>
#include <libavutil/frame.h>
#include <libavutil/hwcontext.h>
#include <libavutil/opt.h>

/* Reconfiguration policy for adaptive bitrate. NVENC can apply AVCodecContext
 * rate-control changes to its live session; the other hardware backends need
 * a context rebuild. Both paths force an IDR, so coalesce small changes and
 * rate-limit the rest to avoid answering congestion with keyframe bursts. */
#define DIRECTGATE_HWENC_RECONFIG_MIN_PCT   20U
#define DIRECTGATE_HWENC_RECONFIG_MIN_US    3000000ULL

/* Number of /dev/dri/renderD* nodes probed when the default VAAPI/QSV device
 * cannot open the encoder. A box with a discrete card plus an integrated GPU
 * routinely has one node that decodes only and another that encodes. */
#define DIRECTGATE_HWENC_MAX_RENDER_NODES   8U

typedef struct directgate_hwenc_lib_ {
    void *pCodecHandle;
    void *pUtilHandle;
    xbool_t bLoadAttempted;
    xbool_t bLoaded;
    char sVersion[64];

    /* libavcodec */
    unsigned (*avcodec_version)(void);
    const AVCodec* (*avcodec_find_encoder_by_name)(const char*);
    AVCodecContext* (*avcodec_alloc_context3)(const AVCodec*);
    void (*avcodec_free_context)(AVCodecContext**);
    int (*avcodec_open2)(AVCodecContext*, const AVCodec*, AVDictionary**);
    int (*avcodec_send_frame)(AVCodecContext*, const AVFrame*);
    int (*avcodec_receive_packet)(AVCodecContext*, AVPacket*);
    AVPacket* (*av_packet_alloc)(void);
    void (*av_packet_free)(AVPacket**);
    void (*av_packet_unref)(AVPacket*);

    /* libavutil */
    unsigned (*avutil_version)(void);
    AVFrame* (*av_frame_alloc)(void);
    void (*av_frame_free)(AVFrame**);
    int (*av_frame_get_buffer)(AVFrame*, int);
    int (*av_frame_make_writable)(AVFrame*);
    void (*av_frame_unref)(AVFrame*);
    AVBufferRef* (*av_buffer_ref)(const AVBufferRef*);
    void (*av_buffer_unref)(AVBufferRef**);
    int (*av_hwdevice_ctx_create)(AVBufferRef**, enum AVHWDeviceType, const char*, AVDictionary*, int);
    AVBufferRef* (*av_hwframe_ctx_alloc)(AVBufferRef*);
    int (*av_hwframe_ctx_init)(AVBufferRef*);
    int (*av_hwframe_get_buffer)(AVBufferRef*, AVFrame*, int);
    int (*av_hwframe_transfer_data)(AVFrame*, const AVFrame*, int);
    int (*av_opt_set)(void*, const char*, const char*, int);
    int (*av_strerror)(int, char*, size_t);
} directgate_hwenc_lib_t;

static directgate_hwenc_lib_t g_hwenc;

/* Process-wide GPU device cache.
 *
 * A hardware device context is a handle on the GPU, not per-encoder state,
 * and opening one is expensive: av_hwdevice_ctx_create runs the vendor's
 * vaInitialize/driver load, tens of milliseconds each time. Every encoder
 * rebuild - a preset change, a resolution change, an adaptive bitrate step -
 * would otherwise pay that again and leak whatever the vendor driver does
 * not release on close (the Intel driver keeps ~2 KB per initialisation).
 * Opening each device once and handing out references makes rebuilds cheap
 * and bounds the driver's own book-keeping to a fixed cost. Entries live for
 * the process lifetime, exactly like the dlopen'd library handles. */
#define DIRECTGATE_HWENC_MAX_DEVICES 8U

typedef struct directgate_hwenc_device_ {
    enum AVHWDeviceType eType;
    char sDevice[64];
    AVBufferRef *pRef;
    xbool_t bFailed;   /* creation already tried and failed; do not retry */
} directgate_hwenc_device_t;

static directgate_hwenc_device_t g_hwencDevices[DIRECTGATE_HWENC_MAX_DEVICES];
static uint32_t g_nHwencDevices;

/* Returns a new reference to a cached device, opening it on first use.
 * pDevice may be NULL for "the library default". */
static AVBufferRef* DirectGate_HWEnc_AcquireDevice(enum AVHWDeviceType eType,
                                                   const char *pDevice,
                                                   int *pError)
{
    const char *pKey = (pDevice != NULL) ? pDevice : "";
    *pError = 0;

    for (uint32_t i = 0; i < g_nHwencDevices; i++)
    {
        directgate_hwenc_device_t *pEntry = &g_hwencDevices[i];
        if (pEntry->eType != eType || !xstrcmp(pEntry->sDevice, pKey)) continue;

        if (pEntry->bFailed)
        {
            *pError = AVERROR(ENODEV);
            return NULL;
        }

        return g_hwenc.av_buffer_ref(pEntry->pRef);
    }

    AVBufferRef *pRef = NULL;
    int nRet = g_hwenc.av_hwdevice_ctx_create(&pRef, eType, pDevice, NULL, 0);

    if (g_nHwencDevices < DIRECTGATE_HWENC_MAX_DEVICES)
    {
        directgate_hwenc_device_t *pEntry = &g_hwencDevices[g_nHwencDevices++];
        xstrncpy(pEntry->sDevice, sizeof(pEntry->sDevice), pKey);
        pEntry->bFailed = (nRet >= 0) ? XFALSE : XTRUE;
        pEntry->pRef = (nRet >= 0) ? pRef : NULL;
        pEntry->eType = eType;
    }

    if (nRet < 0)
    {
        *pError = nRet;
        return NULL;
    }

    /* One reference stays in the cache, one goes to the caller. */
    return g_hwenc.av_buffer_ref(pRef);
}

/* Probe order. NVENC first so a machine with a discrete NVIDIA card plus an
 * integrated GPU uses the dedicated encode silicon; VAAPI then covers both
 * Intel and AMD through Mesa, with the vendor-specific paths after it and
 * the ARM/SBC memory-to-memory encoder last. */
typedef struct directgate_hwenc_candidate_ {
    const char *pName;
    enum AVHWDeviceType eDevice;  /* AV_HWDEVICE_TYPE_NONE = system memory */
} directgate_hwenc_candidate_t;

static const directgate_hwenc_candidate_t g_hwencCandidates[] = {
    { "h264_nvenc",    AV_HWDEVICE_TYPE_NONE },  /* NVIDIA, system-memory NV12 */
    { "h264_vaapi",    AV_HWDEVICE_TYPE_VAAPI }, /* Intel + AMD via libva */
    { "h264_qsv",      AV_HWDEVICE_TYPE_QSV },   /* Intel Quick Sync */
    { "h264_amf",      AV_HWDEVICE_TYPE_NONE },  /* AMD proprietary runtime */
    { "h264_v4l2m2m",  AV_HWDEVICE_TYPE_NONE },  /* ARM SBC / Raspberry Pi */
};

struct directgate_hwenc_ {
    const AVCodec *pCodec;
    AVCodecContext *pCtx;
    AVFrame *pSwFrame;               /* NV12 staging, always allocated */
    AVFrame *pHwFrame;               /* GPU surface; NULL for system-memory encoders */
    AVPacket *pPacket;
    AVBufferRef *pHwDevice;
    AVBufferRef *pHwFrames;
    enum AVHWDeviceType eDevice;

    uint32_t nWidth;
    uint32_t nHeight;
    uint32_t nFps;
    uint32_t nGopFrames;
    uint32_t nBitrateKbps;           /* rate currently applied to the encoder */
    uint32_t nTargetKbps;            /* the preset's full rate (recovery goal) */
    uint32_t nPendingBitrateKbps;    /* requested by the adaptive controller */
    uint64_t nLastReconfigUs;
    xbool_t bForceNextKeyframe;

    uint8_t *pSeqHeader;             /* cached Annex-B SPS/PPS from extradata */
    size_t nSeqHeaderSize;

    char sName[96];
    char sDevice[64];                /* VAAPI/QSV render node actually used */
};

static void DirectGate_HWEnc_SetError(char *pErrBuf, size_t nErrSize, const char *pFmt, ...)
{
    if (pErrBuf == NULL || !nErrSize) return;
    va_list args;
    va_start(args, pFmt);
    vsnprintf(pErrBuf, nErrSize, pFmt, args);
    va_end(args);
}

static const char* DirectGate_HWEnc_ErrStr(int nErr, char *pBuf, size_t nBufSize)
{
    if (g_hwenc.av_strerror == NULL || g_hwenc.av_strerror(nErr, pBuf, nBufSize) < 0)
        snprintf(pBuf, nBufSize, "error %d", nErr);

    return pBuf;
}

static uint64_t DirectGate_HWEnc_MonotonicUs(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return 0;
    return (uint64_t)now.tv_sec * 1000000ULL + (uint64_t)now.tv_nsec / 1000ULL;
}

#define DIRECTGATE_HWENC_SYM(pHandle, pField, pName)            \
    do {                                                        \
        *(void**)(&pLib->pField) = dlsym((pHandle), (pName));   \
        if (pLib->pField == NULL) pMissing = (pName);           \
    } while (0)

int DirectGate_HWEnc_Load(char *pErrBuf, size_t nErrSize)
{
    directgate_hwenc_lib_t *pLib = &g_hwenc;
    if (pLib->bLoadAttempted)
    {
        if (pLib->bLoaded) return XSTDOK;
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize,
            "libavcodec is not available; using the software H.264 encoder.");
        return XSTDERR;
    }

    pLib->bLoadAttempted = XTRUE;

    /* Only the soname this build was compiled against is acceptable: struct
     * layouts come from the build-time headers and FFmpeg reorganises them
     * on every soname bump. */
    char sCodecName[64];
    char sUtilName[64];
    snprintf(sCodecName, sizeof(sCodecName), "libavcodec.so.%d", LIBAVCODEC_VERSION_MAJOR);
    snprintf(sUtilName, sizeof(sUtilName), "libavutil.so.%d", LIBAVUTIL_VERSION_MAJOR);

    const char *pEnvCodec = getenv("DIRECTGATE_HWENC_LIB");
    void *pCodec = dlopen(xstrused(pEnvCodec) ? pEnvCodec : sCodecName, RTLD_NOW | RTLD_LOCAL);
    void *pUtil = dlopen(sUtilName, RTLD_NOW | RTLD_LOCAL);

    if (pCodec == NULL || pUtil == NULL)
    {
        if (pCodec != NULL) dlclose(pCodec);
        if (pUtil != NULL) dlclose(pUtil);

        DirectGate_HWEnc_SetError(pErrBuf, nErrSize,
            "libavcodec/libavutil (%s, %s) are not installed; using the software H.264 encoder.",
            sCodecName, sUtilName);

        return XSTDERR;
    }

    const char *pMissing = NULL;
    DIRECTGATE_HWENC_SYM(pCodec, avcodec_version, "avcodec_version");
    DIRECTGATE_HWENC_SYM(pCodec, avcodec_find_encoder_by_name, "avcodec_find_encoder_by_name");
    DIRECTGATE_HWENC_SYM(pCodec, avcodec_alloc_context3, "avcodec_alloc_context3");
    DIRECTGATE_HWENC_SYM(pCodec, avcodec_free_context, "avcodec_free_context");
    DIRECTGATE_HWENC_SYM(pCodec, avcodec_open2, "avcodec_open2");
    DIRECTGATE_HWENC_SYM(pCodec, avcodec_send_frame, "avcodec_send_frame");
    DIRECTGATE_HWENC_SYM(pCodec, avcodec_receive_packet, "avcodec_receive_packet");
    DIRECTGATE_HWENC_SYM(pCodec, av_packet_alloc, "av_packet_alloc");
    DIRECTGATE_HWENC_SYM(pCodec, av_packet_free, "av_packet_free");
    DIRECTGATE_HWENC_SYM(pCodec, av_packet_unref, "av_packet_unref");

    DIRECTGATE_HWENC_SYM(pUtil, avutil_version, "avutil_version");
    DIRECTGATE_HWENC_SYM(pUtil, av_frame_alloc, "av_frame_alloc");
    DIRECTGATE_HWENC_SYM(pUtil, av_frame_free, "av_frame_free");
    DIRECTGATE_HWENC_SYM(pUtil, av_frame_get_buffer, "av_frame_get_buffer");
    DIRECTGATE_HWENC_SYM(pUtil, av_frame_make_writable, "av_frame_make_writable");
    DIRECTGATE_HWENC_SYM(pUtil, av_frame_unref, "av_frame_unref");
    DIRECTGATE_HWENC_SYM(pUtil, av_buffer_ref, "av_buffer_ref");
    DIRECTGATE_HWENC_SYM(pUtil, av_buffer_unref, "av_buffer_unref");
    DIRECTGATE_HWENC_SYM(pUtil, av_hwdevice_ctx_create, "av_hwdevice_ctx_create");
    DIRECTGATE_HWENC_SYM(pUtil, av_hwframe_ctx_alloc, "av_hwframe_ctx_alloc");
    DIRECTGATE_HWENC_SYM(pUtil, av_hwframe_ctx_init, "av_hwframe_ctx_init");
    DIRECTGATE_HWENC_SYM(pUtil, av_hwframe_get_buffer, "av_hwframe_get_buffer");
    DIRECTGATE_HWENC_SYM(pUtil, av_hwframe_transfer_data, "av_hwframe_transfer_data");
    DIRECTGATE_HWENC_SYM(pUtil, av_opt_set, "av_opt_set");
    DIRECTGATE_HWENC_SYM(pUtil, av_strerror, "av_strerror");

    if (pMissing != NULL)
    {
        dlclose(pCodec);
        dlclose(pUtil);

        DirectGate_HWEnc_SetError(pErrBuf, nErrSize,
            "libavcodec is missing the %s entry point.", pMissing);

        return XSTDERR;
    }

    /* Guard against a runtime library from a different ABI generation. */
    unsigned nCodecVer = pLib->avcodec_version();
    unsigned nUtilVer = pLib->avutil_version();

    if ((nCodecVer >> 16) != LIBAVCODEC_VERSION_MAJOR ||
        (nUtilVer >> 16) != LIBAVUTIL_VERSION_MAJOR)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize,
            "libavcodec %u/libavutil %u do not match the %d/%d this build expects; "
            "using the software H.264 encoder.",
            nCodecVer >> 16, nUtilVer >> 16,
            LIBAVCODEC_VERSION_MAJOR, LIBAVUTIL_VERSION_MAJOR);

        dlclose(pCodec);
        dlclose(pUtil);
        return XSTDERR;
    }

    pLib->pCodecHandle = pCodec;
    pLib->pUtilHandle = pUtil;
    pLib->bLoaded = XTRUE;

    snprintf(pLib->sVersion, sizeof(pLib->sVersion), "libavcodec %u.%u.%u",
        nCodecVer >> 16, (nCodecVer >> 8) & 0xFFU, nCodecVer & 0xFFU);

    return XSTDOK;
}

const char* DirectGate_HWEnc_Version(void)
{
    return g_hwenc.bLoaded ? g_hwenc.sVersion : "unloaded";
}

/* True when the access unit already carries an SPS NAL before the first
 * slice (both 3- and 4-byte Annex-B start codes). Same guarantee the
 * OpenH264 and Media Foundation paths give: every keyframe is decodable on
 * its own, so a viewer that joins mid-stream never waits for a later SPS. */
static xbool_t DirectGate_HWEnc_HasParameterSets(const uint8_t *pData, size_t nSize)
{
    size_t i = 0;
    while (i + 4U < nSize)
    {
        if (pData[i] != 0 || pData[i + 1U] != 0)
        {
            i++;
            continue;
        }

        size_t nNal = 0;
        if (pData[i + 2U] == 1U) nNal = i + 3U;
        else if (pData[i + 2U] == 0 && pData[i + 3U] == 1U) nNal = i + 4U;
        else { i++; continue; }

        uint8_t nType = pData[nNal] & 0x1FU;
        if (nType == 7U) return XTRUE;                 /* SPS */
        if (nType == 1U || nType == 5U) return XFALSE; /* slice before any SPS */
        i = nNal + 1U;
    }

    return XFALSE;
}

static void DirectGate_HWEnc_CacheSeqHeader(directgate_hwenc_t *pEnc)
{
    free(pEnc->pSeqHeader);
    pEnc->pSeqHeader = NULL;
    pEnc->nSeqHeaderSize = 0;

    const AVCodecContext *pCtx = pEnc->pCtx;
    if (pCtx->extradata == NULL || pCtx->extradata_size <= 4) return;

    /* Without AV_CODEC_FLAG_GLOBAL_HEADER the encoders emit Annex-B, so the
     * extradata is already start-code prefixed. Anything else (AVCC) would
     * need a length-prefix rewrite and is simply not cached. */
    const uint8_t *pData = pCtx->extradata;
    if (pData[0] != 0 || pData[1] != 0 ||
        (pData[2] != 1U && (pData[2] != 0 || pData[3] != 1U))) return;

    pEnc->pSeqHeader = (uint8_t*)malloc((size_t)pCtx->extradata_size);
    if (pEnc->pSeqHeader == NULL) return;

    memcpy(pEnc->pSeqHeader, pData, (size_t)pCtx->extradata_size);
    pEnc->nSeqHeaderSize = (size_t)pCtx->extradata_size;
}

/* Interactive-latency knobs. Every one is best-effort: each encoder exposes a
 * different subset and a missing option must never fail the open (same
 * philosophy as the CODECAPI knobs in mfenc.c). */
static void DirectGate_HWEnc_ApplyLatencyOptions(directgate_hwenc_t *pEnc, const char *pEncoderName)
{
    AVCodecContext *pCtx = pEnc->pCtx;
    int nFlags = AV_OPT_SEARCH_CHILDREN;

    if (xstrcmp(pEncoderName, "h264_nvenc"))
    {
        /* p4 (medium), not p1. The NVENC presets trade encode effort for
         * quality, and p1 is the fastest and worst of them - measurably
         * softer than the software encoder at the same rate, which is not a
         * trade worth making when the encode happens on dedicated silicon
         * and costs a fraction of a millisecond either way. `ull` is what
         * actually buys the latency: it disables lookahead and B-frames so
         * output stays one frame behind input. */
        g_hwenc.av_opt_set(pCtx, "preset", "p4", nFlags);
        g_hwenc.av_opt_set(pCtx, "tune", "ull", nFlags);
        g_hwenc.av_opt_set(pCtx, "rc", "cbr", nFlags);
        g_hwenc.av_opt_set(pCtx, "zerolatency", "1", nFlags);
        g_hwenc.av_opt_set(pCtx, "delay", "0", nFlags);
        g_hwenc.av_opt_set(pCtx, "b_ref_mode", "disabled", nFlags);
        g_hwenc.av_opt_set(pCtx, "forced-idr", "1", nFlags);
    }
    else if (xstrcmp(pEncoderName, "h264_vaapi"))
    {
        g_hwenc.av_opt_set(pCtx, "rc_mode", "CBR", nFlags);
        /* One frame in flight: the default lets the driver queue ahead. */
        g_hwenc.av_opt_set(pCtx, "async_depth", "1", nFlags);
    }
    else if (xstrcmp(pEncoderName, "h264_qsv"))
    {
        g_hwenc.av_opt_set(pCtx, "preset", "faster", nFlags);
        g_hwenc.av_opt_set(pCtx, "async_depth", "1", nFlags);
        g_hwenc.av_opt_set(pCtx, "low_delay_brc", "1", nFlags);
    }
    else if (xstrcmp(pEncoderName, "h264_amf"))
    {
        g_hwenc.av_opt_set(pCtx, "usage", "ultralowlatency", nFlags);
        g_hwenc.av_opt_set(pCtx, "rc", "cbr", nFlags);
        g_hwenc.av_opt_set(pCtx, "preanalysis", "0", nFlags);
    }
}

static void DirectGate_HWEnc_CloseContext(directgate_hwenc_t *pEnc)
{
    /* Deliberately no drain-flush here. Sending the end-of-stream NULL frame
     * to release what the encoder still holds looks like the tidy thing to
     * do, but on the VAAPI path it faults inside
     * ff_hw_base_encode_receive_packet during teardown - which would take
     * the agent down every time a desktop session ends. It also buys
     * nothing measurable: a pure-libavcodec open/encode/close loop leaks the
     * same few hundred bytes per context with or without the flush, so the
     * residue is FFmpeg's own book-keeping, not something we are holding.
     * avcodec_free_context releases everything we are responsible for. */
    if (pEnc->pCtx != NULL) g_hwenc.avcodec_free_context(&pEnc->pCtx);
    if (pEnc->pHwFrame != NULL) g_hwenc.av_frame_free(&pEnc->pHwFrame);
    if (pEnc->pHwFrames != NULL) g_hwenc.av_buffer_unref(&pEnc->pHwFrames);
}

/* Builds the GPU frame pool a hardware-surface encoder (VAAPI, QSV) uploads
 * into. System-memory encoders (NVENC, AMF, V4L2) skip this entirely. */
static int DirectGate_HWEnc_InitHwFrames(directgate_hwenc_t *pEnc)
{
    pEnc->pHwFrames = g_hwenc.av_hwframe_ctx_alloc(pEnc->pHwDevice);
    if (pEnc->pHwFrames == NULL) return XSTDERR;

    AVHWFramesContext *pFrames = (AVHWFramesContext*)pEnc->pHwFrames->data;
    pFrames->format = (pEnc->eDevice == AV_HWDEVICE_TYPE_QSV) ? AV_PIX_FMT_QSV : AV_PIX_FMT_VAAPI;
    pFrames->sw_format = AV_PIX_FMT_NV12;
    pFrames->width = (int)pEnc->nWidth;
    pFrames->height = (int)pEnc->nHeight;
    /* The encoder keeps its reference pictures in this pool on top of the
     * frame in flight, and the exact count is driver-specific. Too small a
     * pool makes av_hwframe_get_buffer fail under load, which used to cost
     * the session its GPU encoder entirely - so leave real headroom. At
     * 720p NV12 a surface is ~1.4 MB, so this is a few tens of megabytes. */
    pFrames->initial_pool_size = 16;

    if (g_hwenc.av_hwframe_ctx_init(pEnc->pHwFrames) < 0) return XSTDERR;

    pEnc->pCtx->pix_fmt = pFrames->format;
    pEnc->pCtx->hw_frames_ctx = g_hwenc.av_buffer_ref(pEnc->pHwFrames);
    if (pEnc->pCtx->hw_frames_ctx == NULL) return XSTDERR;

    pEnc->pHwFrame = g_hwenc.av_frame_alloc();
    if (pEnc->pHwFrame == NULL) return XSTDERR;

    return XSTDOK;
}

/* Opens one AVCodecContext for the already-selected codec and device. Split
 * out of Create so an adaptive-bitrate step can rebuild it in place. */
static int DirectGate_HWEnc_OpenContext(directgate_hwenc_t *pEnc, const char *pEncoderName,
                                        char *pErrBuf, size_t nErrSize)
{
    pEnc->pCtx = g_hwenc.avcodec_alloc_context3(pEnc->pCodec);
    if (pEnc->pCtx == NULL)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize, "Failed to allocate the %s context.", pEncoderName);
        return XSTDERR;
    }

    AVCodecContext *pCtx = pEnc->pCtx;
    uint32_t nBitrate = pEnc->nBitrateKbps ? pEnc->nBitrateKbps : 4000U;

    pCtx->width = (int)pEnc->nWidth;
    pCtx->height = (int)pEnc->nHeight;
    pCtx->pix_fmt = AV_PIX_FMT_NV12;
    /* Microsecond timestamps: the capture pipeline skips unchanged frames,
     * so the encoder must see the real irregular cadence rather than a
     * synthetic frame counter. framerate still tells rate control what to
     * budget for. */
    pCtx->time_base.num = 1;
    pCtx->time_base.den = 1000000;
    pCtx->framerate.num = (int)(pEnc->nFps ? pEnc->nFps : 30U);
    pCtx->framerate.den = 1;
    pCtx->bit_rate = (int64_t)nBitrate * 1000;
    /* Peak == average, with a ~250 ms buffer. The rate the adaptive
     * controller picked is the rate the link was measured to carry, so the
     * encoder has to actually hit it: allowing a 1.5x peak (the headroom the
     * OpenH264 path gives itself) measured 16-28% over target on NVENC,
     * which quietly saturates the link and turns into queueing delay - the
     * stream stays sharp and goes minutes behind. The extra headroom was
     * worth only ~0.002 SSIM next to simply raising the encoder preset, so
     * accuracy wins. */
    pCtx->rc_max_rate = pCtx->bit_rate;
    pCtx->rc_buffer_size = (int)(pCtx->bit_rate / 4);
    pCtx->gop_size = (int)(pEnc->nGopFrames ? pEnc->nGopFrames : 300U);
    pCtx->max_b_frames = 0;   /* B-frames would add a frame of reorder delay */
    pCtx->thread_count = 1;
    pCtx->flags |= AV_CODEC_FLAG_LOW_DELAY;

    DirectGate_HWEnc_ApplyLatencyOptions(pEnc, pEncoderName);

    if (pEnc->eDevice != AV_HWDEVICE_TYPE_NONE &&
        DirectGate_HWEnc_InitHwFrames(pEnc) != XSTDOK)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize,
            "%s: GPU frame pool initialization failed.", pEncoderName);

        DirectGate_HWEnc_CloseContext(pEnc);
        return XSTDERR;
    }

    int nRet = g_hwenc.avcodec_open2(pCtx, pEnc->pCodec, NULL);
    if (nRet < 0)
    {
        char sErr[128];
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize, "%s: %s.", pEncoderName,
            DirectGate_HWEnc_ErrStr(nRet, sErr, sizeof(sErr)));

        DirectGate_HWEnc_CloseContext(pEnc);
        return XSTDERR;
    }

    DirectGate_HWEnc_CacheSeqHeader(pEnc);
    pEnc->bForceNextKeyframe = XTRUE;
    return XSTDOK;
}

/* Tries one candidate against one device string (NULL = the library's
 * default device). Leaves pEnc clean on failure so the next candidate can
 * reuse it. */
static int DirectGate_HWEnc_TryOpen(directgate_hwenc_t *pEnc,
                                    const directgate_hwenc_candidate_t *pCandidate,
                                    const char *pDevice,
                                    char *pErrBuf, size_t nErrSize)
{
    pEnc->eDevice = pCandidate->eDevice;

    if (pCandidate->eDevice != AV_HWDEVICE_TYPE_NONE)
    {
        int nRet = 0;
        pEnc->pHwDevice = DirectGate_HWEnc_AcquireDevice(pCandidate->eDevice, pDevice, &nRet);

        if (pEnc->pHwDevice == NULL)
        {
            char sErr[128];
            DirectGate_HWEnc_SetError(pErrBuf, nErrSize, "%s: cannot open %s (%s).",
                pCandidate->pName, pDevice != NULL ? pDevice : "the default GPU device",
                DirectGate_HWEnc_ErrStr(nRet, sErr, sizeof(sErr)));

            return XSTDERR;
        }
    }

    if (DirectGate_HWEnc_OpenContext(pEnc, pCandidate->pName, pErrBuf, nErrSize) != XSTDOK)
    {
        if (pEnc->pHwDevice != NULL) g_hwenc.av_buffer_unref(&pEnc->pHwDevice);
        return XSTDERR;
    }

    xstrncpy(pEnc->sDevice, sizeof(pEnc->sDevice), pDevice != NULL ? pDevice : "default");
    return XSTDOK;
}

/* Walks the candidate list, and for GPU-surface encoders every render node,
 * until something opens. Returns XSTDOK with pEnc live, or XSTDERR with the
 * last failure reason (the caller then uses the software encoder). */
static int DirectGate_HWEnc_Probe(directgate_hwenc_t *pEnc, const char *pForced,
                                  char *pErrBuf, size_t nErrSize)
{
    size_t nCount = sizeof(g_hwencCandidates) / sizeof(g_hwencCandidates[0]);
    xbool_t bAnyCodec = XFALSE;

    for (size_t i = 0; i < nCount; i++)
    {
        const directgate_hwenc_candidate_t *pCandidate = &g_hwencCandidates[i];
        if (xstrused(pForced) && !xstrcmp(pForced, pCandidate->pName)) continue;

        pEnc->pCodec = g_hwenc.avcodec_find_encoder_by_name(pCandidate->pName);
        if (pEnc->pCodec == NULL) continue; /* not built into this libavcodec */

        bAnyCodec = XTRUE;
        if (DirectGate_HWEnc_TryOpen(pEnc, pCandidate, NULL, pErrBuf, nErrSize) == XSTDOK)
            return XSTDOK;

        /* The default device is frequently the wrong one: on a hybrid box
         * the first render node may only decode while a second one encodes.
         * Walk the nodes before giving up on this codec. */
        if (pCandidate->eDevice == AV_HWDEVICE_TYPE_NONE) continue;

        for (uint32_t n = 0; n < DIRECTGATE_HWENC_MAX_RENDER_NODES; n++)
        {
            char sNode[32];
            snprintf(sNode, sizeof(sNode), "/dev/dri/renderD%u", 128U + n);
            if (access(sNode, R_OK | W_OK) != 0) continue;

            if (DirectGate_HWEnc_TryOpen(pEnc, pCandidate, sNode, pErrBuf, nErrSize) == XSTDOK)
                return XSTDOK;
        }
    }

    if (!bAnyCodec)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize,
            "this libavcodec build has no GPU H.264 encoder; using the software encoder.");
    }

    return XSTDERR;
}

directgate_hwenc_t* DirectGate_HWEnc_Create(uint32_t nWidth, uint32_t nHeight,
                                            const directgate_desktop_quality_t *pQuality,
                                            char *pErrBuf, size_t nErrSize)
{
    XCHECK_NL((pQuality != NULL), NULL);
    XCHECK_NL((nWidth >= 16 && nHeight >= 16), NULL);
    XCHECK_NL(((nWidth & 1U) == 0 && (nHeight & 1U) == 0), NULL);

    const char *pDisable = getenv("DIRECTGATE_HWENC");
    if (xstrused(pDisable) && pDisable[0] == '0')
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize,
            "GPU encoding disabled by DIRECTGATE_HWENC=0.");
        return NULL;
    }

    if (DirectGate_HWEnc_Load(pErrBuf, nErrSize) != XSTDOK) return NULL;

    directgate_hwenc_t *pEnc = (directgate_hwenc_t*)calloc(1, sizeof(*pEnc));
    if (pEnc == NULL)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize, "Failed to allocate the GPU encoder context.");
        return NULL;
    }

    pEnc->nWidth = nWidth;
    pEnc->nHeight = nHeight;
    pEnc->nFps = pQuality->nFps ? pQuality->nFps : 30U;
    pEnc->nGopFrames = pQuality->nKeyframeFrames ? pQuality->nKeyframeFrames : 300U;
    pEnc->nBitrateKbps = pQuality->nBitrateKbps ? pQuality->nBitrateKbps : 4000U;
    pEnc->nTargetKbps = pEnc->nBitrateKbps;

    if (DirectGate_HWEnc_Probe(pEnc, getenv("DIRECTGATE_HWENC_ENCODER"), pErrBuf, nErrSize) != XSTDOK)
    {
        free(pEnc);
        return NULL;
    }

    pEnc->pSwFrame = g_hwenc.av_frame_alloc();
    pEnc->pPacket = g_hwenc.av_packet_alloc();

    if (pEnc->pSwFrame == NULL || pEnc->pPacket == NULL)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize, "Failed to allocate GPU encoder frame buffers.");
        DirectGate_HWEnc_Destroy(pEnc);
        return NULL;
    }

    pEnc->pSwFrame->format = AV_PIX_FMT_NV12;
    pEnc->pSwFrame->width = (int)nWidth;
    pEnc->pSwFrame->height = (int)nHeight;

    if (g_hwenc.av_frame_get_buffer(pEnc->pSwFrame, 0) < 0)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize, "Failed to allocate the NV12 staging frame.");
        DirectGate_HWEnc_Destroy(pEnc);
        return NULL;
    }

    snprintf(pEnc->sName, sizeof(pEnc->sName), "%s (%s)",
        pEnc->pCodec->name,
        xstrused(pEnc->pCodec->long_name) ? pEnc->pCodec->long_name : "GPU H.264 encoder");

    return pEnc;
}

void DirectGate_HWEnc_Destroy(directgate_hwenc_t *pEncoder)
{
    if (pEncoder == NULL) return;

    DirectGate_HWEnc_CloseContext(pEncoder);
    if (pEncoder->pSwFrame != NULL) g_hwenc.av_frame_free(&pEncoder->pSwFrame);
    if (pEncoder->pPacket != NULL) g_hwenc.av_packet_free(&pEncoder->pPacket);
    if (pEncoder->pHwDevice != NULL) g_hwenc.av_buffer_unref(&pEncoder->pHwDevice);

    free(pEncoder->pSeqHeader);
    free(pEncoder);
}

const char* DirectGate_HWEnc_Describe(const directgate_hwenc_t *pEncoder)
{
    if (pEncoder == NULL || !xstrused(pEncoder->sName)) return "unloaded";
    return pEncoder->sName;
}

/* Re-opens hardware encoders which do not expose a reliable live bitrate update through libavcodec. */
static int DirectGate_HWEnc_Reconfigure(directgate_hwenc_t *pEnc, uint32_t nBitrateKbps)
{
    char sError[DIRECTGATE_DESKTOP_REASON_LEN] = { 0 };
    const char *pName = pEnc->pCodec->name;

    DirectGate_HWEnc_CloseContext(pEnc);
    pEnc->nBitrateKbps = nBitrateKbps;

    if (DirectGate_HWEnc_OpenContext(pEnc, pName, sError, sizeof(sError)) != XSTDOK)
    {
        xlogw("GPU encoder rebuild for a bitrate step failed: encoder(%s), reason(%s)",
            pName, sError[0] ? sError : "unknown");

        return XSTDERR;
    }

    pEnc->nLastReconfigUs = DirectGate_HWEnc_MonotonicUs();
    return XSTDOK;
}

/* FFmpeg's NVENC wrapper notices changes to these public AVCodecContext
 * fields in avcodec_send_frame and calls nvEncReconfigureEncoder on the
 * existing NVIDIA session. This avoids destroying the encoder, its surfaces
 * and rate-control history for every ABR step. NVENC still forces one IDR,
 * hence the coalescing/rate limit in MaybeReconfigure remains useful. */
static int DirectGate_HWEnc_ReconfigureNvenc(directgate_hwenc_t *pEnc,
                                             uint32_t nBitrateKbps)
{
    XCHECK((pEnc != NULL && pEnc->pCtx != NULL), XSTDERR);

    int64_t nBitrate = (int64_t)nBitrateKbps * 1000;
    pEnc->pCtx->bit_rate = nBitrate;
    pEnc->pCtx->rc_max_rate = nBitrate;
    pEnc->pCtx->rc_buffer_size = (int)(nBitrate / 4);
    pEnc->nBitrateKbps = nBitrateKbps;
    pEnc->nLastReconfigUs = DirectGate_HWEnc_MonotonicUs();
    return XSTDOK;
}

static int DirectGate_HWEnc_MaybeReconfigure(directgate_hwenc_t *pEnc)
{
    uint32_t nWanted = pEnc->nPendingBitrateKbps;
    if (!nWanted || nWanted == pEnc->nBitrateKbps) return XSTDOK;

    uint32_t nCurrent = pEnc->nBitrateKbps ? pEnc->nBitrateKbps : 1U;
    uint32_t nDelta = (nWanted > nCurrent) ? nWanted - nCurrent : nCurrent - nWanted;

    /* Ignore small steps outright, and rate-limit the rest - except for the
     * step that restores the preset's full rate. The adaptive controller
     * walks back up toward the target in ~10% increments, so its final step
     * is always under the threshold; dropping it would leave the encoder
     * parked just below full quality for the rest of the session, with no
     * way back short of rebuilding the pipeline. */
    if (nWanted != pEnc->nTargetKbps &&
        (nDelta * 100U) / nCurrent < DIRECTGATE_HWENC_RECONFIG_MIN_PCT) return XSTDOK;

    uint64_t nNowUs = DirectGate_HWEnc_MonotonicUs();
    if (pEnc->nLastReconfigUs &&
        nNowUs - pEnc->nLastReconfigUs < DIRECTGATE_HWENC_RECONFIG_MIN_US) return XSTDOK;

    pEnc->nPendingBitrateKbps = 0;
    if (xstrcmp(pEnc->pCodec->name, "h264_nvenc"))
        return DirectGate_HWEnc_ReconfigureNvenc(pEnc, nWanted);

    return DirectGate_HWEnc_Reconfigure(pEnc, nWanted);
}

int DirectGate_HWEnc_Encode(directgate_hwenc_t *pEncoder,
                            const uint8_t *pNV12,
                            uint64_t nPtsUs,
                            xbool_t bForceKeyframe,
                            xbyte_buffer_t *pOut,
                            xbool_t *pKeyframe)
{
    XCHECK((pEncoder != NULL && pEncoder->pCtx != NULL), XSTDERR);
    XCHECK((pNV12 != NULL && pOut != NULL), XSTDERR);

    if (pKeyframe != NULL) *pKeyframe = XFALSE;
    pOut->nUsed = 0;

    if (DirectGate_HWEnc_MaybeReconfigure(pEncoder) != XSTDOK) return XSTDERR;

    AVFrame *pSw = pEncoder->pSwFrame;
    uint32_t nWidth = pEncoder->nWidth;
    uint32_t nHeight = pEncoder->nHeight;

    /* The encoder may still hold a reference to the buffers of the frame we
     * submitted last time (system-memory encoders routinely do). Writing the
     * new capture straight into them would corrupt a frame that is still
     * being encoded; make_writable clones only when that is actually the
     * case, so the common path stays copy-free. */
    int nWritable = g_hwenc.av_frame_make_writable(pSw);
    if (nWritable < 0)
    {
        char sErr[128];
        xloge("GPU encoder staging frame is not writable: encoder(%s), reason(%s)",
            pEncoder->sName, DirectGate_HWEnc_ErrStr(nWritable, sErr, sizeof(sErr)));

        return XSTDERR;
    }

    /* Copy row by row: the frame's linesize is alignment-padded and will not
     * generally match our tightly packed capture buffer. */
    for (uint32_t y = 0; y < nHeight; y++)
        memcpy(pSw->data[0] + (size_t)y * pSw->linesize[0], pNV12 + (size_t)y * nWidth, nWidth);

    const uint8_t *pChroma = pNV12 + (size_t)nWidth * nHeight;
    for (uint32_t y = 0; y < nHeight / 2U; y++)
        memcpy(pSw->data[1] + (size_t)y * pSw->linesize[1], pChroma + (size_t)y * nWidth, nWidth);

    pSw->pts = (int64_t)nPtsUs;

    AVFrame *pInput = pSw;
    if (pEncoder->pHwFrame != NULL)
    {
        /* av_hwframe_get_buffer requires a blank frame and hands back a fresh
         * reference into the pool, so last frame's reference has to be
         * dropped first - otherwise every frame permanently retains a GPU
         * surface and the pool grows without bound. */
        g_hwenc.av_frame_unref(pEncoder->pHwFrame);

        int nRet = g_hwenc.av_hwframe_get_buffer(pEncoder->pHwFrames, pEncoder->pHwFrame, 0);
        if (nRet < 0 || pEncoder->pHwFrame->buf[0] == NULL)
        {
            xloge("GPU surface acquisition failed: encoder(%s)", pEncoder->sName);
            return XSTDERR;
        }

        nRet = g_hwenc.av_hwframe_transfer_data(pEncoder->pHwFrame, pSw, 0);
        if (nRet < 0)
        {
            char sErr[128];
            xloge("GPU frame upload failed: encoder(%s), reason(%s)", pEncoder->sName,
                DirectGate_HWEnc_ErrStr(nRet, sErr, sizeof(sErr)));

            return XSTDERR;
        }

        pEncoder->pHwFrame->pts = pSw->pts;
        pInput = pEncoder->pHwFrame;
    }

    /* pict_type is how libavcodec spells "force an IDR here" for every
     * hardware encoder; a fresh context already starts with one. */
    xbool_t bWantKey = (bForceKeyframe || pEncoder->bForceNextKeyframe) ? XTRUE : XFALSE;
    pInput->pict_type = bWantKey ? AV_PICTURE_TYPE_I : AV_PICTURE_TYPE_NONE;

    int nRet = g_hwenc.avcodec_send_frame(pEncoder->pCtx, pInput);

    /* pict_type must not leak into the pooled surface's next use. */
    pInput->pict_type = AV_PICTURE_TYPE_NONE;

    /* send_frame took its own reference to whatever it needs; ours goes back
     * to the pool now rather than being held until the next frame. */
    if (pInput == pEncoder->pHwFrame) g_hwenc.av_frame_unref(pEncoder->pHwFrame);

    if (nRet < 0)
    {
        char sErr[128];
        xloge("GPU encoder rejected a frame: encoder(%s), reason(%s)", pEncoder->sName,
            DirectGate_HWEnc_ErrStr(nRet, sErr, sizeof(sErr)));

        return XSTDERR;
    }

    pEncoder->bForceNextKeyframe = XFALSE;

    nRet = g_hwenc.avcodec_receive_packet(pEncoder->pCtx, pEncoder->pPacket);
    if (nRet == AVERROR(EAGAIN)) return XSTDNON; /* pipelined: no output yet */

    if (nRet < 0)
    {
        char sErr[128];
        xloge("GPU encoder output failed: encoder(%s), reason(%s)", pEncoder->sName,
            DirectGate_HWEnc_ErrStr(nRet, sErr, sizeof(sErr)));

        return XSTDERR;
    }

    int nResult = XSTDOK;
    xbool_t bKey = (pEncoder->pPacket->flags & AV_PKT_FLAG_KEY) ? XTRUE : XFALSE;

    if (pEncoder->pPacket->data != NULL && pEncoder->pPacket->size > 0)
    {
        if (bKey && pEncoder->pSeqHeader != NULL &&
            !DirectGate_HWEnc_HasParameterSets(pEncoder->pPacket->data, (size_t)pEncoder->pPacket->size))
            XByteBuffer_Add(pOut, pEncoder->pSeqHeader, pEncoder->nSeqHeaderSize);

        if (XByteBuffer_Add(pOut, pEncoder->pPacket->data, (size_t)pEncoder->pPacket->size) <= 0)
            nResult = XSTDERR;
    }
    else nResult = XSTDNON;

    g_hwenc.av_packet_unref(pEncoder->pPacket);
    if (pKeyframe != NULL) *pKeyframe = bKey;

    return (nResult == XSTDOK && pOut->nUsed > 0) ? XSTDOK : nResult;
}

int DirectGate_HWEnc_SetBitrate(directgate_hwenc_t *pEncoder, uint32_t nBitrateKbps)
{
    XCHECK((pEncoder != NULL), XSTDERR);
    XCHECK((nBitrateKbps > 0), XSTDERR);

    pEncoder->nPendingBitrateKbps = nBitrateKbps;
    return XSTDOK;
}

int DirectGate_HWEnc_ApplyQuality(directgate_hwenc_t *pEncoder,
                                  const directgate_desktop_quality_t *pQuality)
{
    XCHECK((pEncoder != NULL && pQuality != NULL), XSTDERR);

    uint32_t nFps = pQuality->nFps ? pQuality->nFps : 30U;
    uint32_t nGop = pQuality->nKeyframeFrames ? pQuality->nKeyframeFrames : 300U;
    uint32_t nBitrate = pQuality->nBitrateKbps ? pQuality->nBitrateKbps : 4000U;

    /* A new preset moves the goal the adaptive controller recovers toward. */
    pEncoder->nTargetKbps = nBitrate;

    /* fps and GOP are open-time properties of a hardware encoder, so a preset
     * that changes them needs the context rebuilt. Dimension changes are
     * handled a level up, by rebuilding the whole pipeline. */
    if (nFps != pEncoder->nFps || nGop != pEncoder->nGopFrames)
    {
        pEncoder->nFps = nFps;
        pEncoder->nGopFrames = nGop;
        pEncoder->nPendingBitrateKbps = 0;
        return DirectGate_HWEnc_Reconfigure(pEncoder, nBitrate);
    }

    return DirectGate_HWEnc_SetBitrate(pEncoder, nBitrate);
}

#endif /* DIRECTGATE_HAVE_HWENC */
