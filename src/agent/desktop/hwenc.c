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

/*
 * Compiled once per libavcodec major when DIRECTGATE_HWENC_ABI is set (the
 * package builds do this; see hwenc_abi.c for why). Each variant is an
 * ordinary copy of this file built against that major's headers, so its
 * struct offsets are right for exactly one runtime library - which is the
 * whole point, since that is what a soname bump changes.
 *
 * The renaming happens before hwenc.h is included so the declarations and the
 * definitions move together and the variants cannot collide at link time. A
 * plain source build defines nothing here and keeps the unsuffixed names.
 */
#if defined(DIRECTGATE_HWENC_ABI)
#define DIRECTGATE_HWENC_PASTE(a, b) a##b
#define DIRECTGATE_HWENC_NAME(name, abi) DIRECTGATE_HWENC_PASTE(name##_abi, abi)
#define DIRECTGATE_HWENC_ABI_SYM(name) DIRECTGATE_HWENC_NAME(name, DIRECTGATE_HWENC_ABI)

#define DirectGate_HWEnc_Load         DIRECTGATE_HWENC_ABI_SYM(DirectGate_HWEnc_Load)
#define DirectGate_HWEnc_Version      DIRECTGATE_HWENC_ABI_SYM(DirectGate_HWEnc_Version)
#define DirectGate_HWEnc_Create       DIRECTGATE_HWENC_ABI_SYM(DirectGate_HWEnc_Create)
#define DirectGate_HWEnc_Destroy      DIRECTGATE_HWENC_ABI_SYM(DirectGate_HWEnc_Destroy)
#define DirectGate_HWEnc_Describe     DIRECTGATE_HWENC_ABI_SYM(DirectGate_HWEnc_Describe)
#define DirectGate_HWEnc_Encode       DIRECTGATE_HWENC_ABI_SYM(DirectGate_HWEnc_Encode)
#define DirectGate_HWEnc_ApplyQuality DIRECTGATE_HWENC_ABI_SYM(DirectGate_HWEnc_ApplyQuality)
#define DirectGate_HWEnc_SetBitrate   DIRECTGATE_HWENC_ABI_SYM(DirectGate_HWEnc_SetBitrate)
#define DirectGate_HWEnc_ImportAvailable DIRECTGATE_HWENC_ABI_SYM(DirectGate_HWEnc_ImportAvailable)
#define DirectGate_HWEnc_CreateImport DIRECTGATE_HWENC_ABI_SYM(DirectGate_HWEnc_CreateImport)
#define DirectGate_HWEnc_EncodeImport DIRECTGATE_HWENC_ABI_SYM(DirectGate_HWEnc_EncodeImport)
#endif

#include "hwenc.h"

#ifdef DIRECTGATE_HAVE_HWENC

#include <dlfcn.h>

/* A variant must be built against the headers it claims: a mismatch would put
 * the right soname behind the wrong struct offsets, which is precisely the
 * corruption the soname check exists to prevent. */
#if defined(DIRECTGATE_HWENC_ABI)
#include <libavcodec/version.h>
#if LIBAVCODEC_VERSION_MAJOR != DIRECTGATE_HWENC_ABI
#error "DIRECTGATE_HWENC_ABI does not match the libavcodec headers on the include path"
#endif
#endif

#include <libavcodec/avcodec.h>
#include <libavutil/avutil.h>
#include <libavutil/dict.h>
#include <libavutil/frame.h>
#include <libavutil/hwcontext.h>
#include <libavutil/hwcontext_drm.h>
#include <libavutil/opt.h>

/* libavfilter is what turns an imported DMA-BUF into something an H.264
 * encoder will take: scale_vaapi drives the GPU's post-processor for the
 * colour conversion and the resize. It is optional at build time - a build
 * image without the headers simply has no zero-copy path, and every other
 * part of this file is unchanged. */
#ifdef DIRECTGATE_HWENC_HAS_FILTER
#include <libavfilter/avfilter.h>
#include <libavfilter/buffersrc.h>
#include <libavfilter/buffersink.h>
#endif

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

#ifdef DIRECTGATE_HWENC_HAS_FILTER

/* DRM format codes, spelled out rather than taken from libdrm: this file
 * needs four constants from it and nothing else, and adding drm.h to the
 * build would make a header package mandatory for every agent build on
 * every distribution. The codes are ABI, not API - they are what crosses
 * the wire between a compositor and a GPU driver, so they cannot change. */
#define DIRECTGATE_DRM_FOURCC(a, b, c, d) \
    ((uint32_t)(a) | ((uint32_t)(b) << 8) | ((uint32_t)(c) << 16) | ((uint32_t)(d) << 24))

#define DIRECTGATE_DRM_FORMAT_XRGB8888  DIRECTGATE_DRM_FOURCC('X', 'R', '2', '4')
#define DIRECTGATE_DRM_FORMAT_ARGB8888  DIRECTGATE_DRM_FOURCC('A', 'R', '2', '4')

/* av_buffer_create took an int length until libavutil 57 (FFmpeg 5.0) and a
 * size_t after it. Each variant of this file is compiled against the headers
 * of the major it talks to, so the pointer type simply follows them. */
#if LIBAVUTIL_VERSION_MAJOR >= 57
#define DIRECTGATE_HWENC_BUFSIZE size_t
#else
#define DIRECTGATE_HWENC_BUFSIZE int
#endif

/* Loaded separately from libavcodec and allowed to be absent: a host with no
 * libavfilter, or one whose FFmpeg was built without VAAPI filters, keeps
 * every other GPU path. Nothing here is ever required for a session to run. */
typedef struct directgate_hwenc_filter_lib_ {
    void *pHandle;
    xbool_t bLoadAttempted;
    xbool_t bLoaded;
    char sError[192];

    /* libavfilter */
    unsigned (*avfilter_version)(void);
    const AVFilter* (*avfilter_get_by_name)(const char*);
    AVFilterGraph* (*avfilter_graph_alloc)(void);
    void (*avfilter_graph_free)(AVFilterGraph**);
    AVFilterContext* (*avfilter_graph_alloc_filter)(AVFilterGraph*, const AVFilter*, const char*);
    int (*avfilter_graph_create_filter)(AVFilterContext**, const AVFilter*, const char*,
                                        const char*, void*, AVFilterGraph*);
    int (*avfilter_init_str)(AVFilterContext*, const char*);
    int (*avfilter_link)(AVFilterContext*, unsigned, AVFilterContext*, unsigned);
    int (*avfilter_graph_config)(AVFilterGraph*, void*);
    AVBufferSrcParameters* (*av_buffersrc_parameters_alloc)(void);
    int (*av_buffersrc_parameters_set)(AVFilterContext*, AVBufferSrcParameters*);
    int (*av_buffersrc_add_frame_flags)(AVFilterContext*, AVFrame*, int);
    int (*av_buffersink_get_frame)(AVFilterContext*, AVFrame*);
    AVBufferRef* (*av_buffersink_get_hw_frames_ctx)(const AVFilterContext*);

    /* libavutil, but only the import path needs them - keeping them here
     * means a libavutil without one of them costs the zero-copy path and
     * not GPU encoding as a whole. */
    int (*av_hwframe_map)(AVFrame*, const AVFrame*, int);
    int (*av_frame_ref)(AVFrame*, const AVFrame*);
    AVBufferRef* (*av_buffer_create)(uint8_t*, DIRECTGATE_HWENC_BUFSIZE,
                                     void (*)(void*, uint8_t*), void*, int);
    void (*av_free)(void*);
} directgate_hwenc_filter_lib_t;

static directgate_hwenc_filter_lib_t g_hwfilter;

#endif /* DIRECTGATE_HWENC_HAS_FILTER */

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

#ifdef DIRECTGATE_HWENC_HAS_FILTER
/* The zero-copy probe order, which is a list of one. VAAPI is the only
 * backend libavcodec will hand a DRM object to, so an import encoder is a
 * VAAPI encoder or it is nothing - and when it is nothing the caller opens
 * an ordinary one from the list above and asks for mapped frames instead. */
static const directgate_hwenc_candidate_t g_hwencImportCandidates[] = {
    { "h264_vaapi",    AV_HWDEVICE_TYPE_VAAPI },
};
#endif

struct directgate_hwenc_ {
    const AVCodec *pCodec;
    AVCodecContext *pCtx;
    AVFrame *pSwFrame;               /* NV12 staging, always allocated */
    AVFrame *pHwFrame;               /* GPU surface; NULL for system-memory encoders */
    AVPacket *pPacket;
    AVBufferRef *pHwDevice;
    AVBufferRef *pHwFrames;
    enum AVHWDeviceType eDevice;

#ifdef DIRECTGATE_HWENC_HAS_FILTER
    /* The zero-copy chain, present only on an encoder opened by CreateImport.
     * pMapFrames is what the compositor's DRM object becomes - a VAAPI
     * surface over memory nobody copied - and the graph is the driver's
     * post-processor doing the colour conversion and the resize that the CPU
     * does on the ordinary path. pSinkFrames is the NV12 pool the graph
     * produces into, and it is the encoder's input pool too: opening the
     * encoder on the filter's own pool is what keeps the frame on the GPU
     * from one end to the other. */
    xbool_t bImport;
    AVBufferRef *pMapFrames;
    AVBufferRef *pSinkFrames;
    AVFilterGraph *pGraph;
    AVFilterContext *pSrcFilter;
    AVFilterContext *pSinkFilter;
    AVFrame *pDrmFrame;       /* the descriptor, wrapped as an AVFrame */
    AVFrame *pMapped;         /* the DRM object as a VAAPI surface */
    AVFrame *pFiltered;       /* NV12 out of the post-processor */
    AVFrame *pLastFiltered;   /* kept so a keyframe on a still screen has one */
    uint32_t nSrcWidth;
    uint32_t nSrcHeight;
    uint32_t nSrcFourCC;
    uint64_t nSrcModifier;
    xbool_t bDriverMatrix;    /* colour options refused; driver default used */
#endif

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

    char sCodecError[160] = { 0 };
    char sUtilError[160] = { 0 };
    const char *pEnvCodec = getenv("DIRECTGATE_HWENC_LIB");

    dlerror();
    void *pCodec = dlopen(xstrused(pEnvCodec) ? pEnvCodec : sCodecName, RTLD_NOW | RTLD_LOCAL);
    if (pCodec == NULL)
    {
        const char *pError = dlerror();
        if (pError != NULL) xstrncpy(sCodecError, sizeof(sCodecError), pError);
    }

    void *pUtil = dlopen(sUtilName, RTLD_NOW | RTLD_LOCAL);
    if (pUtil == NULL)
    {
        const char *pError = dlerror();
        if (pError != NULL) xstrncpy(sUtilError, sizeof(sUtilError), pError);
    }

    if (pCodec == NULL || pUtil == NULL)
    {
        if (pCodec != NULL) dlclose(pCodec);
        if (pUtil != NULL) dlclose(pUtil);

        const char *pFailed = (pCodec == NULL) ? sCodecName : sUtilName;
        const char *pReason = (pCodec == NULL) ? sCodecError : sUtilError;

        DirectGate_HWEnc_SetError(pErrBuf, nErrSize, "%s could not be loaded: %s",
            pFailed, xstrused(pReason) ? pReason : "no reason reported");

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

#ifdef DIRECTGATE_HWENC_HAS_FILTER

#define DIRECTGATE_HWFILTER_SYM(pHandle, pField, pName)          \
    do {                                                         \
        *(void**)(&pLib->pField) = dlsym((pHandle), (pName));    \
        if (pLib->pField == NULL) pMissing = (pName);            \
    } while (0)

/* Same contract as DirectGate_HWEnc_Load, one library later: the soname is
 * pinned to the major this variant was compiled against, and a miss is a
 * feature that is unavailable rather than an error anybody has to act on. */
static int DirectGate_HWEnc_LoadFilter(void)
{
    directgate_hwenc_filter_lib_t *pLib = &g_hwfilter;
    if (pLib->bLoadAttempted) return pLib->bLoaded ? XSTDOK : XSTDERR;

    pLib->bLoadAttempted = XTRUE;
    if (!g_hwenc.bLoaded)
    {
        xstrncpy(pLib->sError, sizeof(pLib->sError), "libavcodec is not loaded");
        return XSTDERR;
    }

    char sName[64];
    snprintf(sName, sizeof(sName), "libavfilter.so.%d", LIBAVFILTER_VERSION_MAJOR);

    dlerror();
    void *pHandle = dlopen(sName, RTLD_NOW | RTLD_LOCAL);
    if (pHandle == NULL)
    {
        const char *pError = dlerror();
        snprintf(pLib->sError, sizeof(pLib->sError), "%s could not be loaded: %s",
            sName, (pError != NULL) ? pError : "no reason reported");

        return XSTDERR;
    }

    const char *pMissing = NULL;
    DIRECTGATE_HWFILTER_SYM(pHandle, avfilter_version, "avfilter_version");
    DIRECTGATE_HWFILTER_SYM(pHandle, avfilter_get_by_name, "avfilter_get_by_name");
    DIRECTGATE_HWFILTER_SYM(pHandle, avfilter_graph_alloc, "avfilter_graph_alloc");
    DIRECTGATE_HWFILTER_SYM(pHandle, avfilter_graph_free, "avfilter_graph_free");
    DIRECTGATE_HWFILTER_SYM(pHandle, avfilter_graph_alloc_filter, "avfilter_graph_alloc_filter");
    DIRECTGATE_HWFILTER_SYM(pHandle, avfilter_graph_create_filter, "avfilter_graph_create_filter");
    DIRECTGATE_HWFILTER_SYM(pHandle, avfilter_init_str, "avfilter_init_str");
    DIRECTGATE_HWFILTER_SYM(pHandle, avfilter_link, "avfilter_link");
    DIRECTGATE_HWFILTER_SYM(pHandle, avfilter_graph_config, "avfilter_graph_config");
    DIRECTGATE_HWFILTER_SYM(pHandle, av_buffersrc_parameters_alloc, "av_buffersrc_parameters_alloc");
    DIRECTGATE_HWFILTER_SYM(pHandle, av_buffersrc_parameters_set, "av_buffersrc_parameters_set");
    DIRECTGATE_HWFILTER_SYM(pHandle, av_buffersrc_add_frame_flags, "av_buffersrc_add_frame_flags");
    DIRECTGATE_HWFILTER_SYM(pHandle, av_buffersink_get_frame, "av_buffersink_get_frame");
    DIRECTGATE_HWFILTER_SYM(pHandle, av_buffersink_get_hw_frames_ctx, "av_buffersink_get_hw_frames_ctx");

    DIRECTGATE_HWFILTER_SYM(g_hwenc.pUtilHandle, av_hwframe_map, "av_hwframe_map");
    DIRECTGATE_HWFILTER_SYM(g_hwenc.pUtilHandle, av_frame_ref, "av_frame_ref");
    DIRECTGATE_HWFILTER_SYM(g_hwenc.pUtilHandle, av_buffer_create, "av_buffer_create");
    DIRECTGATE_HWFILTER_SYM(g_hwenc.pUtilHandle, av_free, "av_free");

    unsigned nVersion = (pLib->avfilter_version != NULL) ? pLib->avfilter_version() : 0;

    if (pMissing != NULL || (nVersion >> 16) != LIBAVFILTER_VERSION_MAJOR)
    {
        if (pMissing != NULL)
        {
            snprintf(pLib->sError, sizeof(pLib->sError),
                "%s is missing the %s entry point", sName, pMissing);
        }
        else
        {
            snprintf(pLib->sError, sizeof(pLib->sError),
                "libavfilter %u does not match the %d this build expects",
                nVersion >> 16, LIBAVFILTER_VERSION_MAJOR);
        }

        dlclose(pHandle);
        memset(pLib, 0, sizeof(*pLib));
        pLib->bLoadAttempted = XTRUE;

        return XSTDERR;
    }

    pLib->pHandle = pHandle;
    pLib->bLoaded = XTRUE;

    return XSTDOK;
}

/* AVPixelFormat the DRM code has to be presented as. FFmpeg maps a DRM
 * fourcc to a VA one and then to a pixel format, and the frames context has
 * to already say the same thing or the import is refused - so these two pairs
 * are exactly the ones its own tables spell out, not a guess about byte
 * order. */
static enum AVPixelFormat DirectGate_HWEnc_PixelFromFourCC(uint32_t nFourCC)
{
    if (nFourCC == DIRECTGATE_DRM_FORMAT_XRGB8888) return AV_PIX_FMT_BGR0;
    if (nFourCC == DIRECTGATE_DRM_FORMAT_ARGB8888) return AV_PIX_FMT_BGRA;

    return AV_PIX_FMT_NONE;
}

#endif /* DIRECTGATE_HWENC_HAS_FILTER */

xbool_t DirectGate_HWEnc_ImportAvailable(char *pErrBuf, size_t nErrSize)
{
#ifndef DIRECTGATE_HWENC_HAS_FILTER
    DirectGate_HWEnc_SetError(pErrBuf, nErrSize,
        "this agent was built without the libavfilter headers zero-copy needs.");

    return XFALSE;
#else
    const char *pDisable = getenv("DIRECTGATE_HWENC_ZEROCOPY");
    if (xstrused(pDisable) && pDisable[0] == '0')
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize,
            "zero-copy disabled by DIRECTGATE_HWENC_ZEROCOPY=0.");

        return XFALSE;
    }

    const char *pOff = getenv("DIRECTGATE_HWENC");
    if (xstrused(pOff) && pOff[0] == '0')
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize, "GPU encoding disabled by DIRECTGATE_HWENC=0.");
        return XFALSE;
    }

    /* A pinned encoder is a deliberate choice and this path is VAAPI only, so
     * honouring the pin means not asking the compositor for an export the
     * encoder that was asked for could not take. */
    const char *pForced = getenv("DIRECTGATE_HWENC_ENCODER");
    if (xstrused(pForced) && !xstrcmp(pForced, "h264_vaapi"))
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize,
            "DIRECTGATE_HWENC_ENCODER pins %s, and only h264_vaapi can import.", pForced);

        return XFALSE;
    }

    if (DirectGate_HWEnc_Load(pErrBuf, nErrSize) != XSTDOK) return XFALSE;

    if (DirectGate_HWEnc_LoadFilter() != XSTDOK)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize, "%s.", g_hwfilter.sError);
        return XFALSE;
    }

    /* An FFmpeg built without VAAPI has the library and not the filter. */
    if (g_hwfilter.avfilter_get_by_name("scale_vaapi") == NULL)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize,
            "this FFmpeg has no scale_vaapi filter, so an imported frame "
            "could not be converted on the GPU.");

        return XFALSE;
    }

    /* Asked here rather than left to the encoder, because the answer decides
     * what the compositor is asked to export. A machine with no VAAPI device
     * at all - an NVIDIA-only box, most often - would otherwise negotiate an
     * export nothing can take and pay a renegotiation to find out, once per
     * session. The device cache makes this free after the first call. */
    int nError = 0;
    AVBufferRef *pDevice = DirectGate_HWEnc_AcquireDevice(AV_HWDEVICE_TYPE_VAAPI, NULL, &nError);

    for (uint32_t n = 0; pDevice == NULL && n < DIRECTGATE_HWENC_MAX_RENDER_NODES; n++)
    {
        char sNode[32];
        snprintf(sNode, sizeof(sNode), "/dev/dri/renderD%u", 128U + n);
        if (access(sNode, R_OK | W_OK) != 0) continue;

        pDevice = DirectGate_HWEnc_AcquireDevice(AV_HWDEVICE_TYPE_VAAPI, sNode, &nError);
    }

    if (pDevice == NULL)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize,
            "no VAAPI device on this machine can take an exported frame.");

        return XFALSE;
    }

    g_hwenc.av_buffer_unref(&pDevice);
    return XTRUE;
#endif
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
        g_hwenc.av_opt_set(pCtx, "forced_idr", "1", nFlags);
    }
    else if (xstrcmp(pEncoderName, "h264_amf"))
    {
        g_hwenc.av_opt_set(pCtx, "usage", "ultralowlatency", nFlags);
        g_hwenc.av_opt_set(pCtx, "rc", "cbr", nFlags);
        g_hwenc.av_opt_set(pCtx, "preanalysis", "0", nFlags);
    }
}

#ifdef DIRECTGATE_HWENC_HAS_FILTER

/* Survives a context rebuild: an adaptive-bitrate step re-opens the encoder,
 * and the frames it will be fed have to keep coming from the same pool. */
static void DirectGate_HWEnc_FreeImport(directgate_hwenc_t *pEnc)
{
    if (pEnc->pGraph != NULL) g_hwfilter.avfilter_graph_free(&pEnc->pGraph);
    pEnc->pSrcFilter = NULL;
    pEnc->pSinkFilter = NULL;

    if (pEnc->pSinkFrames != NULL) g_hwenc.av_buffer_unref(&pEnc->pSinkFrames);
    if (pEnc->pMapFrames != NULL) g_hwenc.av_buffer_unref(&pEnc->pMapFrames);
    if (pEnc->pDrmFrame != NULL) g_hwenc.av_frame_free(&pEnc->pDrmFrame);
    if (pEnc->pMapped != NULL) g_hwenc.av_frame_free(&pEnc->pMapped);
    if (pEnc->pFiltered != NULL) g_hwenc.av_frame_free(&pEnc->pFiltered);
    if (pEnc->pLastFiltered != NULL) g_hwenc.av_frame_free(&pEnc->pLastFiltered);
}

/* Builds DRM object -> VAAPI surface -> post-processor -> NV12 surface.
 * @p pScaleArgs is the post-processor's option string; the caller tries a
 * rich one and then a plain one, because the colour options are newer than
 * some of the libavfilters this agent supports. Cleans up after itself, so a
 * failure leaves nothing to unwind. */
static int DirectGate_HWEnc_BuildImport(directgate_hwenc_t *pEnc, const char *pScaleArgs,
                                        char *pErrBuf, size_t nErrSize)
{
    enum AVPixelFormat eSwFormat = DirectGate_HWEnc_PixelFromFourCC(pEnc->nSrcFourCC);
    if (eSwFormat == AV_PIX_FMT_NONE)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize,
            "the compositor exports a frame format this agent cannot import (%c%c%c%c).",
            (char)(pEnc->nSrcFourCC & 0xFFU), (char)((pEnc->nSrcFourCC >> 8) & 0xFFU),
            (char)((pEnc->nSrcFourCC >> 16) & 0xFFU), (char)((pEnc->nSrcFourCC >> 24) & 0xFFU));

        return XSTDERR;
    }

    /* A frames context that allocates nothing of its own: every surface in it
     * is one the compositor already owns, which is what a zero pool size
     * means to libavutil and what the DRM mapping requires. */
    pEnc->pMapFrames = g_hwenc.av_hwframe_ctx_alloc(pEnc->pHwDevice);
    if (pEnc->pMapFrames == NULL)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize, "failed to allocate the import frame context.");
        return XSTDERR;
    }

    AVHWFramesContext *pMapCtx = (AVHWFramesContext*)pEnc->pMapFrames->data;
    pMapCtx->format = AV_PIX_FMT_VAAPI;
    pMapCtx->sw_format = eSwFormat;
    pMapCtx->width = (int)pEnc->nSrcWidth;
    pMapCtx->height = (int)pEnc->nSrcHeight;
    pMapCtx->initial_pool_size = 0;

    int nRet = g_hwenc.av_hwframe_ctx_init(pEnc->pMapFrames);
    if (nRet < 0)
    {
        char sErr[128];
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize, "the GPU refused an import frame context: %s.",
            DirectGate_HWEnc_ErrStr(nRet, sErr, sizeof(sErr)));

        DirectGate_HWEnc_FreeImport(pEnc);
        return XSTDERR;
    }

    const AVFilter *pSourceFilter = g_hwfilter.avfilter_get_by_name("buffer");
    const AVFilter *pScaleFilter = g_hwfilter.avfilter_get_by_name("scale_vaapi");
    const AVFilter *pSinkFilter = g_hwfilter.avfilter_get_by_name("buffersink");

    pEnc->pGraph = g_hwfilter.avfilter_graph_alloc();

    if (pSourceFilter == NULL || pScaleFilter == NULL || pSinkFilter == NULL || pEnc->pGraph == NULL)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize, "this FFmpeg cannot build a GPU conversion graph.");
        DirectGate_HWEnc_FreeImport(pEnc);
        return XSTDERR;
    }

    /* Microseconds, matching the encoder: the capture cadence is irregular
     * and a synthetic frame counter would misreport it to rate control. */
    char sArgs[192];
    snprintf(sArgs, sizeof(sArgs),
        "video_size=%ux%u:pix_fmt=%d:time_base=1/1000000:pixel_aspect=1/1",
        pEnc->nSrcWidth, pEnc->nSrcHeight, (int)AV_PIX_FMT_VAAPI);

    if (g_hwfilter.avfilter_graph_create_filter(&pEnc->pSrcFilter, pSourceFilter, "in", sArgs, NULL, pEnc->pGraph) < 0)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize, "failed to open the GPU graph input.");
        DirectGate_HWEnc_FreeImport(pEnc);
        return XSTDERR;
    }

    /* The option string above can only say "a GPU surface"; which GPU, and
     * which layout on it, comes from the frames context. */
    AVBufferSrcParameters *pParams = g_hwfilter.av_buffersrc_parameters_alloc();
    if (pParams == NULL)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize, "failed to allocate GPU graph parameters.");
        DirectGate_HWEnc_FreeImport(pEnc);
        return XSTDERR;
    }

    pParams->format = AV_PIX_FMT_VAAPI;
    pParams->width = (int)pEnc->nSrcWidth;
    pParams->height = (int)pEnc->nSrcHeight;
    pParams->time_base.num = 1;
    pParams->time_base.den = 1000000;
    pParams->hw_frames_ctx = pEnc->pMapFrames;   /* the setter takes its own reference */

    nRet = g_hwfilter.av_buffersrc_parameters_set(pEnc->pSrcFilter, pParams);
    g_hwfilter.av_free(pParams);

    if (nRet < 0)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize, "the GPU graph refused the imported frame format.");
        DirectGate_HWEnc_FreeImport(pEnc);
        return XSTDERR;
    }

    /* Allocated and initialised in two steps, unlike the others: the device
     * has to be attached before the filter initialises on it. */
    AVFilterContext *pScaleCtx = g_hwfilter.avfilter_graph_alloc_filter(pEnc->pGraph, pScaleFilter, "csc");
    if (pScaleCtx == NULL)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize, "failed to allocate the GPU post-processor.");
        DirectGate_HWEnc_FreeImport(pEnc);
        return XSTDERR;
    }

    pScaleCtx->hw_device_ctx = g_hwenc.av_buffer_ref(pEnc->pHwDevice);

    if (g_hwfilter.avfilter_init_str(pScaleCtx, pScaleArgs) < 0)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize,
            "the GPU post-processor rejected its options (%s).", pScaleArgs);

        DirectGate_HWEnc_FreeImport(pEnc);
        return XSTDERR;
    }

    if (g_hwfilter.avfilter_graph_create_filter(&pEnc->pSinkFilter, pSinkFilter, "out", NULL, NULL, pEnc->pGraph) < 0)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize, "failed to open the GPU graph output.");
        DirectGate_HWEnc_FreeImport(pEnc);
        return XSTDERR;
    }

    if (g_hwfilter.avfilter_link(pEnc->pSrcFilter, 0, pScaleCtx, 0) < 0 ||
        g_hwfilter.avfilter_link(pScaleCtx, 0, pEnc->pSinkFilter, 0) < 0 ||
        g_hwfilter.avfilter_graph_config(pEnc->pGraph, NULL) < 0)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize,
            "the GPU could not be configured to convert %ux%u into %ux%u NV12.",
            pEnc->nSrcWidth, pEnc->nSrcHeight, pEnc->nWidth, pEnc->nHeight);

        DirectGate_HWEnc_FreeImport(pEnc);
        return XSTDERR;
    }

    /* Borrowed from the link, so it is referenced rather than kept: this pool
     * is what the encoder is opened on, and it has to outlive the frame that
     * happens to be in flight. */
    AVBufferRef *pSinkFrames = g_hwfilter.av_buffersink_get_hw_frames_ctx(pEnc->pSinkFilter);
    if (pSinkFrames != NULL) pEnc->pSinkFrames = g_hwenc.av_buffer_ref(pSinkFrames);

    pEnc->pDrmFrame = g_hwenc.av_frame_alloc();
    pEnc->pMapped = g_hwenc.av_frame_alloc();
    pEnc->pFiltered = g_hwenc.av_frame_alloc();
    pEnc->pLastFiltered = g_hwenc.av_frame_alloc();

    if (pEnc->pSinkFrames == NULL || pEnc->pDrmFrame == NULL || pEnc->pMapped == NULL ||
        pEnc->pFiltered == NULL || pEnc->pLastFiltered == NULL)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize, "the GPU graph produced no usable frame pool.");
        DirectGate_HWEnc_FreeImport(pEnc);
        return XSTDERR;
    }

    return XSTDOK;
}

#endif /* DIRECTGATE_HWENC_HAS_FILTER */

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

#ifdef DIRECTGATE_HWENC_HAS_FILTER
    if (pEnc->bImport)
    {
        /* Opened on the post-processor's own output pool rather than a pool
         * of its own: the surface the GPU conversion writes is then the exact
         * surface the encoder reads, which is the last place a copy could
         * still have crept back in.
         *
         * The colour description is written here too. The CPU converter is
         * BT.709 limited and declares nothing, because that is what a viewer
         * assumes for a stream this size anyway; the GPU is asked for the
         * same and, unlike the CPU path, can say so in the bitstream. */
        pCtx->pix_fmt = AV_PIX_FMT_VAAPI;
        pCtx->hw_frames_ctx = g_hwenc.av_buffer_ref(pEnc->pSinkFrames);
        pCtx->colorspace = AVCOL_SPC_BT709;
        pCtx->color_primaries = AVCOL_PRI_BT709;
        pCtx->color_trc = AVCOL_TRC_BT709;
        pCtx->color_range = AVCOL_RANGE_MPEG;

        if (pCtx->hw_frames_ctx == NULL)
        {
            DirectGate_HWEnc_SetError(pErrBuf, nErrSize,
                "%s: the GPU conversion pool could not be attached.", pEncoderName);

            DirectGate_HWEnc_CloseContext(pEnc);
            return XSTDERR;
        }
    }
    else
#endif
    if (pEnc->eDevice != AV_HWDEVICE_TYPE_NONE && DirectGate_HWEnc_InitHwFrames(pEnc) != XSTDOK)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize, "%s: GPU frame pool initialization failed.", pEncoderName);
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

#ifdef DIRECTGATE_HWENC_HAS_FILTER
    if (pEnc->bImport)
    {
        /* Asked for the colour handling first. These options are newer than
         * some of the libavfilters this agent supports, and losing them costs
         * the declared matrix rather than the picture - worth one retry
         * before this device is given up on entirely. */
        char sScale[192];
        snprintf(sScale, sizeof(sScale),
            "w=%u:h=%u:format=nv12:out_range=tv:out_color_matrix=bt709",
            pEnc->nWidth, pEnc->nHeight);

        if (DirectGate_HWEnc_BuildImport(pEnc, sScale, pErrBuf, nErrSize) != XSTDOK)
        {
            snprintf(sScale, sizeof(sScale), "w=%u:h=%u:format=nv12", pEnc->nWidth, pEnc->nHeight);
            pEnc->bDriverMatrix = XTRUE;

            if (DirectGate_HWEnc_BuildImport(pEnc, sScale, pErrBuf, nErrSize) != XSTDOK)
            {
                pEnc->bDriverMatrix = XFALSE;
                if (pEnc->pHwDevice != NULL) g_hwenc.av_buffer_unref(&pEnc->pHwDevice);

                return XSTDERR;
            }
        }
    }
#endif

    if (DirectGate_HWEnc_OpenContext(pEnc, pCandidate->pName, pErrBuf, nErrSize) != XSTDOK)
    {
#ifdef DIRECTGATE_HWENC_HAS_FILTER
        if (pEnc->bImport)
        {
            DirectGate_HWEnc_FreeImport(pEnc);
            pEnc->bDriverMatrix = XFALSE;
        }
#endif
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
    const directgate_hwenc_candidate_t *pCandidates = g_hwencCandidates;
    size_t nCount = sizeof(g_hwencCandidates) / sizeof(g_hwencCandidates[0]);
    xbool_t bAnyCodec = XFALSE;

#ifdef DIRECTGATE_HWENC_HAS_FILTER
    if (pEnc->bImport)
    {
        pCandidates = g_hwencImportCandidates;
        nCount = sizeof(g_hwencImportCandidates) / sizeof(g_hwencImportCandidates[0]);
    }
#endif

    for (size_t i = 0; i < nCount; i++)
    {
        const directgate_hwenc_candidate_t *pCandidate = &pCandidates[i];
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

/* Both entry points, which differ only in what the encoder is fed: an
 * ordinary one takes NV12 out of system memory, an import one takes handles
 * to frames that never left the GPU. Everything else - the probe, the render
 * node walk, the packet plumbing - is the same, and keeping it in one place
 * is what stops the zero-copy path from quietly drifting away from the one
 * that has to work everywhere. */
static directgate_hwenc_t* DirectGate_HWEnc_Open(uint32_t nSrcWidth, uint32_t nSrcHeight,
                                                 uint32_t nFourCC, uint64_t nModifier,
                                                 uint32_t nWidth, uint32_t nHeight,
                                                 const directgate_desktop_quality_t *pQuality,
                                                 xbool_t bImport,
                                                 char *pErrBuf, size_t nErrSize)
{
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

#ifdef DIRECTGATE_HWENC_HAS_FILTER
    /* Set before the probe: the candidate list, and the chain each candidate
     * has to build before its context can be opened, both follow this. */
    pEnc->bImport = bImport;
    pEnc->nSrcWidth = nSrcWidth;
    pEnc->nSrcHeight = nSrcHeight;
    pEnc->nSrcFourCC = nFourCC;
    pEnc->nSrcModifier = nModifier;
#else
    (void)nSrcWidth; (void)nSrcHeight; (void)nFourCC; (void)nModifier; (void)bImport;
#endif

    if (DirectGate_HWEnc_Probe(pEnc, getenv("DIRECTGATE_HWENC_ENCODER"), pErrBuf, nErrSize) != XSTDOK)
    {
        free(pEnc);
        return NULL;
    }

    pEnc->pPacket = g_hwenc.av_packet_alloc();
    if (pEnc->pPacket == NULL)
    {
        DirectGate_HWEnc_SetError(pErrBuf, nErrSize, "Failed to allocate GPU encoder frame buffers.");
        DirectGate_HWEnc_Destroy(pEnc);
        return NULL;
    }

    /* The staging frame is where a CPU frame is laid out before it is
     * uploaded, so an import encoder - which is handed a GPU surface - has no
     * use for one and does not pay for it. */
    if (!bImport)
    {
        pEnc->pSwFrame = g_hwenc.av_frame_alloc();
        if (pEnc->pSwFrame == NULL)
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
    }

#ifdef DIRECTGATE_HWENC_HAS_FILTER
    if (pEnc->bImport)
    {
        snprintf(pEnc->sName, sizeof(pEnc->sName), "%s, zero-copy DMA-BUF%s",
            pEnc->pCodec->name, pEnc->bDriverMatrix ? " (driver colour matrix)" : "");
    }
    else
#endif
    snprintf(pEnc->sName, sizeof(pEnc->sName), "%s (%s)",
        pEnc->pCodec->name,
        xstrused(pEnc->pCodec->long_name) ? pEnc->pCodec->long_name : "GPU H.264 encoder");

    return pEnc;
}

directgate_hwenc_t* DirectGate_HWEnc_Create(uint32_t nWidth, uint32_t nHeight,
                                            const directgate_desktop_quality_t *pQuality,
                                            char *pErrBuf, size_t nErrSize)
{
    XCHECK_NL((pQuality != NULL), NULL);
    XCHECK_NL((nWidth >= 16 && nHeight >= 16), NULL);
    XCHECK_NL(((nWidth & 1U) == 0 && (nHeight & 1U) == 0), NULL);

    return DirectGate_HWEnc_Open(0, 0, 0, 0, nWidth, nHeight, pQuality, XFALSE, pErrBuf, nErrSize);
}

directgate_hwenc_t* DirectGate_HWEnc_CreateImport(uint32_t nSrcWidth, uint32_t nSrcHeight,
                                                  uint32_t nFourCC, uint64_t nModifier,
                                                  uint32_t nWidth, uint32_t nHeight,
                                                  const directgate_desktop_quality_t *pQuality,
                                                  char *pErrBuf, size_t nErrSize)
{
    XCHECK_NL((pQuality != NULL), NULL);
    XCHECK_NL((nWidth >= 16 && nHeight >= 16), NULL);
    XCHECK_NL(((nWidth & 1U) == 0 && (nHeight & 1U) == 0), NULL);
    XCHECK_NL((nSrcWidth >= 16 && nSrcHeight >= 16), NULL);

    if (!DirectGate_HWEnc_ImportAvailable(pErrBuf, nErrSize)) return NULL;

    return DirectGate_HWEnc_Open(nSrcWidth, nSrcHeight, nFourCC, nModifier,
        nWidth, nHeight, pQuality, XTRUE, pErrBuf, nErrSize);
}

void DirectGate_HWEnc_Destroy(directgate_hwenc_t *pEncoder)
{
    if (pEncoder == NULL) return;

    DirectGate_HWEnc_CloseContext(pEncoder);

#ifdef DIRECTGATE_HWENC_HAS_FILTER
    DirectGate_HWEnc_FreeImport(pEncoder);
#endif

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

/* Everything a frame goes through once it is a surface the encoder accepts,
 * whichever way it got there: the CPU path uploads into it, the zero-copy
 * path had it handed over by the compositor. @p bReleaseInput drops the
 * caller's reference once send_frame has taken its own, which is what returns
 * a pooled surface for reuse - the persistent staging frame must not be. */
static int DirectGate_HWEnc_Submit(directgate_hwenc_t *pEncoder, AVFrame *pInput,
                                   xbool_t bForceKeyframe, xbool_t bReleaseInput,
                                   xbyte_buffer_t *pOut, xbool_t *pKeyframe)
{
    /* pict_type is how libavcodec spells "force an IDR here" for every
     * hardware encoder; a fresh context already starts with one. */
    xbool_t bWantKey = (bForceKeyframe || pEncoder->bForceNextKeyframe) ? XTRUE : XFALSE;
    pInput->pict_type = bWantKey ? AV_PICTURE_TYPE_I : AV_PICTURE_TYPE_NONE;

    int nRet = g_hwenc.avcodec_send_frame(pEncoder->pCtx, pInput);

    /* pict_type must not leak into the pooled surface's next use. */
    pInput->pict_type = AV_PICTURE_TYPE_NONE;

    /* send_frame took its own reference to whatever it needs; ours goes back
     * to the pool now rather than being held until the next frame. */
    if (bReleaseInput) g_hwenc.av_frame_unref(pInput);

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

int DirectGate_HWEnc_Encode(directgate_hwenc_t *pEncoder,
                            const uint8_t *pNV12,
                            uint64_t nPtsUs,
                            xbool_t bForceKeyframe,
                            xbyte_buffer_t *pOut,
                            xbool_t *pKeyframe)
{
    XCHECK((pEncoder != NULL && pEncoder->pCtx != NULL), XSTDERR);
    XCHECK((pNV12 != NULL && pOut != NULL), XSTDERR);

    /* An import encoder has no staging frame and takes handles, not pixels. */
    XCHECK((pEncoder->pSwFrame != NULL), XSTDERR);

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

    return DirectGate_HWEnc_Submit(pEncoder, pInput, bForceKeyframe,
        (pInput == pEncoder->pHwFrame) ? XTRUE : XFALSE, pOut, pKeyframe);
}

#ifdef DIRECTGATE_HWENC_HAS_FILTER

/* The descriptor crosses into libavutil as an AVFrame, and the mapping takes
 * a reference to that frame for as long as it lives - which it can only do
 * if the frame owns refcounted memory. Hence this wrapper: it owns the
 * descriptor and nothing else. The file descriptors inside it belong to the
 * compositor's buffer and are handed back with it, so they are never closed
 * here. */
static void DirectGate_HWEnc_FreeDescriptor(void *pOpaque, uint8_t *pData)
{
    (void)pOpaque;
    free(pData);
}

/* Compositor frame -> VAAPI surface -> post-processor -> NV12 in pFiltered.
 * XSTDNON when the graph has taken the frame but has nothing out yet. */
static int DirectGate_HWEnc_ImportFrame(directgate_hwenc_t *pEnc,
                                        const directgate_desktop_dmabuf_t *pFrame,
                                        uint64_t nPtsUs)
{
    /* One object is what libavutil is able to map, and a packed RGB screen
     * cast is exactly one. Anything else is a compositor doing something this
     * path was not built for, and the answer is to stop asking it to export. */
    if (pFrame->nPlanes != 1 || pFrame->nFds[0] < 0)
    {
        xlogw("The compositor exported a frame in %u planes, which cannot be imported: encoder(%s)",
            pFrame->nPlanes, pEnc->sName);

        return XSTDERR;
    }

    /* The whole chain was built for one shape, and the encoder was opened on
     * its output. A frame of another shape is a renegotiation nobody told the
     * pipeline about, so it is refused rather than mapped into the wrong
     * surface. */
    if (pFrame->nWidth != pEnc->nSrcWidth || pFrame->nHeight != pEnc->nSrcHeight ||
        pFrame->nFourCC != pEnc->nSrcFourCC)
    {
        xlogw("The exported frame no longer matches the imported format: encoder(%s)", pEnc->sName);
        return XSTDERR;
    }

    AVDRMFrameDescriptor *pDesc = (AVDRMFrameDescriptor*)calloc(1, sizeof(*pDesc));
    if (pDesc == NULL) return XSTDERR;

    pDesc->nb_objects = 1;
    pDesc->objects[0].fd = pFrame->nFds[0];
    pDesc->objects[0].size = (size_t)pFrame->nSize;
    pDesc->objects[0].format_modifier = pFrame->nModifier;

    pDesc->nb_layers = 1;
    pDesc->layers[0].format = pFrame->nFourCC;
    pDesc->layers[0].nb_planes = 1;
    pDesc->layers[0].planes[0].object_index = 0;
    pDesc->layers[0].planes[0].offset = (ptrdiff_t)pFrame->nOffsets[0];
    pDesc->layers[0].planes[0].pitch = (ptrdiff_t)pFrame->nStrides[0];

    g_hwenc.av_frame_unref(pEnc->pDrmFrame);
    pEnc->pDrmFrame->buf[0] = g_hwfilter.av_buffer_create((uint8_t*)pDesc,
        (DIRECTGATE_HWENC_BUFSIZE)sizeof(*pDesc), DirectGate_HWEnc_FreeDescriptor, NULL, 0);

    if (pEnc->pDrmFrame->buf[0] == NULL)
    {
        free(pDesc);
        return XSTDERR;
    }

    pEnc->pDrmFrame->data[0] = (uint8_t*)pDesc;
    pEnc->pDrmFrame->format = AV_PIX_FMT_DRM_PRIME;
    pEnc->pDrmFrame->width = (int)pFrame->nWidth;
    pEnc->pDrmFrame->height = (int)pFrame->nHeight;

    g_hwenc.av_frame_unref(pEnc->pMapped);
    pEnc->pMapped->format = AV_PIX_FMT_VAAPI;
    pEnc->pMapped->hw_frames_ctx = g_hwenc.av_buffer_ref(pEnc->pMapFrames);

    if (pEnc->pMapped->hw_frames_ctx == NULL)
    {
        g_hwenc.av_frame_unref(pEnc->pDrmFrame);
        return XSTDERR;
    }

    int nRet = g_hwfilter.av_hwframe_map(pEnc->pMapped, pEnc->pDrmFrame, AV_HWFRAME_MAP_READ);

    /* The mapping holds its own reference to the descriptor from here on. */
    g_hwenc.av_frame_unref(pEnc->pDrmFrame);

    if (nRet < 0)
    {
        char sErr[128];
        xlogw("The GPU could not take the compositor's frame: encoder(%s), reason(%s)",
            pEnc->sName, DirectGate_HWEnc_ErrStr(nRet, sErr, sizeof(sErr)));

        g_hwenc.av_frame_unref(pEnc->pMapped);
        return XSTDERR;
    }

    pEnc->pMapped->pts = (int64_t)nPtsUs;

    /* The graph takes the frame; what comes back is NV12 at the encode size,
     * converted and resized by the driver rather than by a core of the
     * machine somebody is trying to work on. */
    nRet = g_hwfilter.av_buffersrc_add_frame_flags(pEnc->pSrcFilter, pEnc->pMapped, 0);
    if (nRet < 0)
    {
        char sErr[128];
        xlogw("The GPU conversion refused a frame: encoder(%s), reason(%s)",
            pEnc->sName, DirectGate_HWEnc_ErrStr(nRet, sErr, sizeof(sErr)));

        g_hwenc.av_frame_unref(pEnc->pMapped);
        return XSTDERR;
    }

    g_hwenc.av_frame_unref(pEnc->pFiltered);
    nRet = g_hwfilter.av_buffersink_get_frame(pEnc->pSinkFilter, pEnc->pFiltered);

    if (nRet == AVERROR(EAGAIN)) return XSTDNON;

    if (nRet < 0)
    {
        char sErr[128];
        xlogw("The GPU conversion produced nothing: encoder(%s), reason(%s)",
            pEnc->sName, DirectGate_HWEnc_ErrStr(nRet, sErr, sizeof(sErr)));

        return XSTDERR;
    }

    return XSTDOK;
}

#endif /* DIRECTGATE_HWENC_HAS_FILTER */

int DirectGate_HWEnc_EncodeImport(directgate_hwenc_t *pEncoder,
                                  const directgate_desktop_dmabuf_t *pFrame,
                                  uint64_t nPtsUs,
                                  xbool_t bForceKeyframe,
                                  xbyte_buffer_t *pOut,
                                  xbool_t *pKeyframe)
{
#ifndef DIRECTGATE_HWENC_HAS_FILTER
    (void)pEncoder; (void)pFrame; (void)nPtsUs; (void)bForceKeyframe; (void)pOut; (void)pKeyframe;
    return XSTDERR;
#else
    XCHECK((pEncoder != NULL && pEncoder->pCtx != NULL && pOut != NULL), XSTDERR);
    XCHECK((pEncoder->bImport), XSTDERR);

    if (pKeyframe != NULL) *pKeyframe = XFALSE;
    pOut->nUsed = 0;

    if (DirectGate_HWEnc_MaybeReconfigure(pEncoder) != XSTDOK) return XSTDERR;

    AVFrame *pInput = NULL;
    xbool_t bRelease = XFALSE;

    if (pFrame != NULL)
    {
        int nStatus = DirectGate_HWEnc_ImportFrame(pEncoder, pFrame, nPtsUs);
        if (nStatus != XSTDOK) return nStatus;

        /* Kept because a keyframe can be asked for on a screen that has
         * stopped changing, and this path has no CPU copy of the picture to
         * answer with - the compositor will not send it again. */
        g_hwenc.av_frame_unref(pEncoder->pLastFiltered);
        if (g_hwfilter.av_frame_ref(pEncoder->pLastFiltered, pEncoder->pFiltered) < 0)
            g_hwenc.av_frame_unref(pEncoder->pLastFiltered);

        pInput = pEncoder->pFiltered;
        bRelease = XTRUE;
    }
    else
    {
        if (pEncoder->pLastFiltered == NULL || pEncoder->pLastFiltered->buf[0] == NULL) return XSTDNON;

        pInput = pEncoder->pLastFiltered;
        pInput->pts = (int64_t)nPtsUs;
    }

    return DirectGate_HWEnc_Submit(pEncoder, pInput, bForceKeyframe, bRelease, pOut, pKeyframe);
#endif
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
