/*!
 * @file directgate-agent/src/agent/desktop/wayland_capture.c
 * @brief PipeWire video capture for the Wayland desktop backend.
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

#include "wayland.h"

#ifdef DIRECTGATE_DESKTOP_HAS_WAYLAND

#include <dlfcn.h>
#include <unistd.h>

#include <pipewire/pipewire.h>
#include <spa/param/video/format-utils.h>

/* libpipewire is opened at runtime, so every entry point used here is reached
 * through this table rather than by name. SPA contributes nothing to it: its
 * headers are entirely static inline, which is what makes runtime loading
 * practical at all - the whole dependency is these few functions. */
typedef void (*directgate_pw_init_fn)(int*, char***);
typedef const char* (*directgate_pw_libver_fn)(void);
typedef struct pw_thread_loop* (*directgate_pw_tl_new_fn)(const char*, const struct spa_dict*);
typedef void (*directgate_pw_tl_destroy_fn)(struct pw_thread_loop*);
typedef int (*directgate_pw_tl_start_fn)(struct pw_thread_loop*);
typedef void (*directgate_pw_tl_stop_fn)(struct pw_thread_loop*);
typedef void (*directgate_pw_tl_lock_fn)(struct pw_thread_loop*);
typedef void (*directgate_pw_tl_unlock_fn)(struct pw_thread_loop*);
typedef void (*directgate_pw_tl_signal_fn)(struct pw_thread_loop*, bool);
typedef int (*directgate_pw_tl_timedwait_fn)(struct pw_thread_loop*, int);
typedef struct pw_loop* (*directgate_pw_tl_getloop_fn)(struct pw_thread_loop*);
typedef struct pw_context* (*directgate_pw_ctx_new_fn)(struct pw_loop*, struct pw_properties*, size_t);
typedef void (*directgate_pw_ctx_destroy_fn)(struct pw_context*);
typedef struct pw_core* (*directgate_pw_ctx_connect_fd_fn)(struct pw_context*, int, struct pw_properties*, size_t);
typedef int (*directgate_pw_core_disconnect_fn)(struct pw_core*);
typedef struct pw_properties* (*directgate_pw_props_new_fn)(const char*, ...);
typedef struct pw_stream* (*directgate_pw_stream_new_fn)(struct pw_core*, const char*, struct pw_properties*);
typedef void (*directgate_pw_stream_destroy_fn)(struct pw_stream*);
typedef void (*directgate_pw_stream_addl_fn)(struct pw_stream*, struct spa_hook*, const struct pw_stream_events*, void*);
typedef int (*directgate_pw_stream_connect_fn)(struct pw_stream*, enum pw_direction, uint32_t, enum pw_stream_flags, const struct spa_pod**, uint32_t);
typedef int (*directgate_pw_stream_disconnect_fn)(struct pw_stream*);
typedef int (*directgate_pw_stream_update_fn)(struct pw_stream*, const struct spa_pod**, uint32_t);
typedef struct pw_buffer* (*directgate_pw_stream_deq_fn)(struct pw_stream*);
typedef int (*directgate_pw_stream_queue_fn)(struct pw_stream*, struct pw_buffer*);
typedef const char* (*directgate_pw_stream_state_str_fn)(enum pw_stream_state);

typedef struct directgate_pw_lib_ {
    void *pHandle;
    directgate_pw_init_fn init;
    directgate_pw_libver_fn libVersion;
    directgate_pw_tl_new_fn loopNew;
    directgate_pw_tl_destroy_fn loopDestroy;
    directgate_pw_tl_start_fn loopStart;
    directgate_pw_tl_stop_fn loopStop;
    directgate_pw_tl_lock_fn loopLock;
    directgate_pw_tl_unlock_fn loopUnlock;
    directgate_pw_tl_signal_fn loopSignal;
    directgate_pw_tl_timedwait_fn loopTimedWait;
    directgate_pw_tl_getloop_fn loopGet;
    directgate_pw_ctx_new_fn ctxNew;
    directgate_pw_ctx_destroy_fn ctxDestroy;
    directgate_pw_ctx_connect_fd_fn ctxConnectFd;
    directgate_pw_core_disconnect_fn coreDisconnect;
    directgate_pw_props_new_fn propsNew;
    directgate_pw_stream_new_fn streamNew;
    directgate_pw_stream_destroy_fn streamDestroy;
    directgate_pw_stream_addl_fn streamAddListener;
    directgate_pw_stream_connect_fn streamConnect;
    directgate_pw_stream_disconnect_fn streamDisconnect;
    directgate_pw_stream_update_fn streamUpdateParams;
    directgate_pw_stream_deq_fn streamDequeue;
    directgate_pw_stream_queue_fn streamQueue;
    directgate_pw_stream_state_str_fn streamStateStr;
    xbool_t bLoadAttempted;
    xbool_t bLoaded;
} directgate_pw_lib_t;

static directgate_pw_lib_t g_pw;

/* Soname first: the -devel symlink is not present on end-user machines. */
static const char *g_pPipeWireNames[] = {
    "libpipewire-0.3.so.0",
    "libpipewire-0.3.so",
    NULL
};

struct directgate_wl_capture_ {
    struct pw_thread_loop *pLoop;
    struct pw_context *pContext;
    struct pw_core *pCore;
    struct pw_stream *pStream;
    struct spa_hook streamHook;
    struct spa_video_info_raw format;

    directgate_wl_frame_cb_t fnFrame;
    void *pUserCtx;

    xbool_t bHaveFormat;
    xbool_t bFailed;
    char sError[256];

    /* Diagnostics that answer the two questions a black stream raises. */
    uint64_t nFrames;
    uint32_t nUnmappable;
    xbool_t bWarnedUnmappable;
};

static void DirectGate_WL_SetError(char *pErrBuf, size_t nErrSize, const char *pFmt, ...)
{
    if (pErrBuf == NULL || !nErrSize) return;

    va_list args;
    va_start(args, pFmt);
    vsnprintf(pErrBuf, nErrSize, pFmt, args);
    va_end(args);
}

int DirectGate_WL_PipeWireLoad(char *pErrBuf, size_t nErrSize)
{
    directgate_pw_lib_t *pLib = &g_pw;

    if (pLib->bLoadAttempted)
    {
        if (pLib->bLoaded) return XSTDOK;

        DirectGate_WL_SetError(pErrBuf, nErrSize,
            "PipeWire is not available on this host (install the pipewire runtime libraries).");

        return XSTDERR;
    }

    pLib->bLoadAttempted = XTRUE;

    void *pHandle = NULL;
    for (int i = 0; g_pPipeWireNames[i] != NULL && pHandle == NULL; i++)
        pHandle = dlopen(g_pPipeWireNames[i], RTLD_NOW | RTLD_LOCAL);

    if (pHandle == NULL)
    {
        DirectGate_WL_SetError(pErrBuf, nErrSize,
            "PipeWire is not available on this host (install the pipewire runtime libraries).");

        return XSTDERR;
    }

    pLib->init = (directgate_pw_init_fn)dlsym(pHandle, "pw_init");
    pLib->libVersion = (directgate_pw_libver_fn)dlsym(pHandle, "pw_get_library_version");
    pLib->loopNew = (directgate_pw_tl_new_fn)dlsym(pHandle, "pw_thread_loop_new");
    pLib->loopDestroy = (directgate_pw_tl_destroy_fn)dlsym(pHandle, "pw_thread_loop_destroy");
    pLib->loopStart = (directgate_pw_tl_start_fn)dlsym(pHandle, "pw_thread_loop_start");
    pLib->loopStop = (directgate_pw_tl_stop_fn)dlsym(pHandle, "pw_thread_loop_stop");
    pLib->loopLock = (directgate_pw_tl_lock_fn)dlsym(pHandle, "pw_thread_loop_lock");
    pLib->loopUnlock = (directgate_pw_tl_unlock_fn)dlsym(pHandle, "pw_thread_loop_unlock");
    pLib->loopSignal = (directgate_pw_tl_signal_fn)dlsym(pHandle, "pw_thread_loop_signal");
    pLib->loopTimedWait = (directgate_pw_tl_timedwait_fn)dlsym(pHandle, "pw_thread_loop_timed_wait");
    pLib->loopGet = (directgate_pw_tl_getloop_fn)dlsym(pHandle, "pw_thread_loop_get_loop");
    pLib->ctxNew = (directgate_pw_ctx_new_fn)dlsym(pHandle, "pw_context_new");
    pLib->ctxDestroy = (directgate_pw_ctx_destroy_fn)dlsym(pHandle, "pw_context_destroy");
    pLib->ctxConnectFd = (directgate_pw_ctx_connect_fd_fn)dlsym(pHandle, "pw_context_connect_fd");
    pLib->coreDisconnect = (directgate_pw_core_disconnect_fn)dlsym(pHandle, "pw_core_disconnect");
    pLib->propsNew = (directgate_pw_props_new_fn)dlsym(pHandle, "pw_properties_new");
    pLib->streamNew = (directgate_pw_stream_new_fn)dlsym(pHandle, "pw_stream_new");
    pLib->streamDestroy = (directgate_pw_stream_destroy_fn)dlsym(pHandle, "pw_stream_destroy");
    pLib->streamAddListener = (directgate_pw_stream_addl_fn)dlsym(pHandle, "pw_stream_add_listener");
    pLib->streamConnect = (directgate_pw_stream_connect_fn)dlsym(pHandle, "pw_stream_connect");
    pLib->streamDisconnect = (directgate_pw_stream_disconnect_fn)dlsym(pHandle, "pw_stream_disconnect");
    pLib->streamUpdateParams = (directgate_pw_stream_update_fn)dlsym(pHandle, "pw_stream_update_params");
    pLib->streamDequeue = (directgate_pw_stream_deq_fn)dlsym(pHandle, "pw_stream_dequeue_buffer");
    pLib->streamQueue = (directgate_pw_stream_queue_fn)dlsym(pHandle, "pw_stream_queue_buffer");
    pLib->streamStateStr = (directgate_pw_stream_state_str_fn)dlsym(pHandle, "pw_stream_state_as_string");

    if (pLib->init == NULL || pLib->loopNew == NULL || pLib->loopStart == NULL ||
        pLib->loopLock == NULL || pLib->loopUnlock == NULL || pLib->loopGet == NULL ||
        pLib->ctxNew == NULL || pLib->ctxConnectFd == NULL || pLib->propsNew == NULL ||
        pLib->streamNew == NULL || pLib->streamAddListener == NULL ||
        pLib->streamConnect == NULL || pLib->streamUpdateParams == NULL ||
        pLib->streamDequeue == NULL || pLib->streamQueue == NULL ||
        pLib->loopSignal == NULL || pLib->loopTimedWait == NULL)
    {
        dlclose(pHandle);
        memset(pLib, 0, sizeof(*pLib));
        pLib->bLoadAttempted = XTRUE;

        DirectGate_WL_SetError(pErrBuf, nErrSize,
            "The installed PipeWire library is missing entry points this agent needs.");

        return XSTDERR;
    }

    pLib->init(NULL, NULL);
    pLib->pHandle = pHandle;
    pLib->bLoaded = XTRUE;

    xlogi("PipeWire loaded for Wayland desktop capture: version(%s)",
        pLib->libVersion != NULL ? pLib->libVersion() : "unknown");

    return XSTDOK;
}

static void DirectGate_WL_OnStreamState(void *pCtx, enum pw_stream_state eOld,
                                        enum pw_stream_state eState, const char *pError)
{
    directgate_wl_capture_t *pCap = (directgate_wl_capture_t*)pCtx;
    (void)eOld;

    if (eState == PW_STREAM_STATE_ERROR)
    {
        xstrncpy(pCap->sError, sizeof(pCap->sError),
            xstrused(pError) ? pError : "PipeWire stream failed.");

        pCap->bFailed = XTRUE;
        xloge("Wayland capture stream failed: reason(%s)", pCap->sError);

        /* Unblock a WaitFormat that would otherwise sit out its full timeout
         * on a stream that has already given up. */
        g_pw.loopSignal(pCap->pLoop, false);
        return;
    }

    xlogd("Wayland capture stream state: state(%s)",
        g_pw.streamStateStr != NULL ? g_pw.streamStateStr(eState) : "?");
}

static void DirectGate_WL_OnParamChanged(void *pCtx, uint32_t nId, const struct spa_pod *pParam)
{
    directgate_wl_capture_t *pCap = (directgate_wl_capture_t*)pCtx;
    uint32_t nMediaType = 0, nMediaSubtype = 0;

    if (pParam == NULL || nId != SPA_PARAM_Format) return;
    if (spa_format_parse(pParam, &nMediaType, &nMediaSubtype) < 0) return;
    if (nMediaType != SPA_MEDIA_TYPE_video || nMediaSubtype != SPA_MEDIA_SUBTYPE_raw) return;
    if (spa_format_video_raw_parse(pParam, &pCap->format) < 0) return;

    uint8_t buffer[512];
    struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(buffer, sizeof(buffer));
    const struct spa_pod *params[1];

    /* The load-bearing constraint. A GPU compositor's natural answer is a
     * DMA-BUF, which arrives with data == NULL in a process that has not
     * imported it through EGL, so every frame is skipped and the viewer sees
     * a black screen rather than an error. Excluding SPA_DATA_DmaBuf here
     * makes the compositor do the GPU-to-CPU copy and hand back memory that
     * can simply be mapped. Importing DMA-BUF directly would be faster and is
     * the natural next step, but correct beats fast for the first frame. */
    params[0] = spa_pod_builder_add_object(&builder,
        SPA_TYPE_OBJECT_ParamBuffers, SPA_PARAM_Buffers,
        SPA_PARAM_BUFFERS_dataType, SPA_POD_CHOICE_FLAGS_Int(
            (1 << SPA_DATA_MemFd) | (1 << SPA_DATA_MemPtr)));

    g_pw.streamUpdateParams(pCap->pStream, params, 1);
    pCap->bHaveFormat = XTRUE;

    xlogi("Wayland capture negotiated a format: size(%ux%u), rate(%u/%u)",
        pCap->format.size.width, pCap->format.size.height,
        pCap->format.framerate.num, pCap->format.framerate.denom);

    g_pw.loopSignal(pCap->pLoop, false);
}

static void DirectGate_WL_OnProcess(void *pCtx)
{
    directgate_wl_capture_t *pCap = (directgate_wl_capture_t*)pCtx;
    struct pw_buffer *pBuffer = g_pw.streamDequeue(pCap->pStream);
    if (pBuffer == NULL) return;

    struct spa_data *pData = &pBuffer->buffer->datas[0];
    if (pData->data == NULL)
    {
        /* Should not happen given the dataType constraint above, but a
         * compositor that ignores it would otherwise stream black in
         * silence. Once is enough to say so. */
        pCap->nUnmappable++;

        if (!pCap->bWarnedUnmappable)
        {
            pCap->bWarnedUnmappable = XTRUE;
            xlogw("Wayland capture received a buffer it cannot map (type %u); "
                  "the compositor ignored the memory-type constraint", pData->type);
        }
    }
    else if (pCap->fnFrame != NULL && pCap->bHaveFormat)
    {
        uint32_t nStride = pData->chunk != NULL ? (uint32_t)pData->chunk->stride : 0;
        /* A zero stride means packed rows; anything smaller than a packed row
         * would make the frame read past its own buffer. */
        if (nStride == 0) nStride = pCap->format.size.width * 4U;

        if (nStride >= pCap->format.size.width * 4U)
        {
            directgate_wl_frame_t frame;
            frame.pPixels = (const uint8_t*)pData->data + (pData->chunk != NULL ? pData->chunk->offset : 0);
            frame.nWidth = pCap->format.size.width;
            frame.nHeight = pCap->format.size.height;
            frame.nStride = nStride;

            pCap->nFrames++;
            pCap->fnFrame(pCap->pUserCtx, &frame);
        }
    }

    g_pw.streamQueue(pCap->pStream, pBuffer);
}

static const struct pw_stream_events g_streamEvents = {
    PW_VERSION_STREAM_EVENTS,
    .state_changed = DirectGate_WL_OnStreamState,
    .param_changed = DirectGate_WL_OnParamChanged,
    .process = DirectGate_WL_OnProcess,
};

directgate_wl_capture_t* DirectGate_WL_CaptureStart(int nPipeWireFd,
                                                    uint32_t nNodeId,
                                                    directgate_wl_frame_cb_t fnFrame,
                                                    void *pUserCtx,
                                                    char *pErrBuf,
                                                    size_t nErrSize)
{
    if (DirectGate_WL_PipeWireLoad(pErrBuf, nErrSize) != XSTDOK)
    {
        if (nPipeWireFd >= 0) close(nPipeWireFd);
        return NULL;
    }

    directgate_wl_capture_t *pCap = (directgate_wl_capture_t*)calloc(1, sizeof(*pCap));
    if (pCap == NULL)
    {
        if (nPipeWireFd >= 0) close(nPipeWireFd);
        DirectGate_WL_SetError(pErrBuf, nErrSize, "Out of memory starting Wayland capture.");
        return NULL;
    }

    pCap->fnFrame = fnFrame;
    pCap->pUserCtx = pUserCtx;

    pCap->pLoop = g_pw.loopNew("directgate-capture", NULL);
    if (pCap->pLoop == NULL)
    {
        if (nPipeWireFd >= 0) close(nPipeWireFd);
        free(pCap);
        DirectGate_WL_SetError(pErrBuf, nErrSize, "Failed to create the PipeWire loop.");
        return NULL;
    }

    g_pw.loopLock(pCap->pLoop);

    /* Start the loop before connecting, not after. The core handshake and the
     * format negotiation are asynchronous and only make progress while this
     * thread runs, so connecting first leaves the stream waiting for a
     * negotiation that nothing is driving. */
    if (g_pw.loopStart(pCap->pLoop) < 0)
    {
        g_pw.loopUnlock(pCap->pLoop);
        if (nPipeWireFd >= 0) close(nPipeWireFd);
        DirectGate_WL_CaptureStop(pCap);
        DirectGate_WL_SetError(pErrBuf, nErrSize, "Failed to start the PipeWire loop.");
        return NULL;
    }

    pCap->pContext = g_pw.ctxNew(g_pw.loopGet(pCap->pLoop), NULL, 0);
    if (pCap->pContext == NULL)
    {
        g_pw.loopUnlock(pCap->pLoop);
        if (nPipeWireFd >= 0) close(nPipeWireFd);
        DirectGate_WL_CaptureStop(pCap);
        DirectGate_WL_SetError(pErrBuf, nErrSize, "Failed to create the PipeWire context.");
        return NULL;
    }

    /* connect_fd consumes the descriptor the portal opened for us, which is
     * how this process reaches PipeWire without any socket of its own. */
    pCap->pCore = g_pw.ctxConnectFd(pCap->pContext, nPipeWireFd, NULL, 0);
    if (pCap->pCore == NULL)
    {
        g_pw.loopUnlock(pCap->pLoop);
        if (nPipeWireFd >= 0) close(nPipeWireFd);
        DirectGate_WL_CaptureStop(pCap);
        DirectGate_WL_SetError(pErrBuf, nErrSize, "Failed to connect to PipeWire through the portal descriptor.");
        return NULL;
    }

    pCap->pStream = g_pw.streamNew(pCap->pCore, "directgate-desktop",
        g_pw.propsNew(
            PW_KEY_MEDIA_TYPE, "Video",
            PW_KEY_MEDIA_CATEGORY, "Capture",
            PW_KEY_MEDIA_ROLE, "Screen",
            NULL));

    if (pCap->pStream == NULL)
    {
        g_pw.loopUnlock(pCap->pLoop);
        DirectGate_WL_CaptureStop(pCap);
        DirectGate_WL_SetError(pErrBuf, nErrSize, "Failed to create the PipeWire stream.");
        return NULL;
    }

    g_pw.streamAddListener(pCap->pStream, &pCap->streamHook, &g_streamEvents, pCap);

    uint8_t buffer[1024];
    struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(buffer, sizeof(buffer));
    const struct spa_pod *params[1];

    params[0] = spa_pod_builder_add_object(&builder,
        SPA_TYPE_OBJECT_Format, SPA_PARAM_EnumFormat,
        SPA_FORMAT_mediaType,       SPA_POD_Id(SPA_MEDIA_TYPE_video),
        SPA_FORMAT_mediaSubtype,    SPA_POD_Id(SPA_MEDIA_SUBTYPE_raw),
        /* BGRx/BGRA only: both are byte-order identical to what the X11 path
         * produces, so the existing scale and I420 conversion are reused with
         * no swizzle. A compositor offering only RGB-order formats would fail
         * negotiation rather than stream wrong colours. */
        SPA_FORMAT_VIDEO_format,    SPA_POD_CHOICE_ENUM_Id(3,
                                        SPA_VIDEO_FORMAT_BGRx,
                                        SPA_VIDEO_FORMAT_BGRx,
                                        SPA_VIDEO_FORMAT_BGRA),
        SPA_FORMAT_VIDEO_size,      SPA_POD_CHOICE_RANGE_Rectangle(
                                        &SPA_RECTANGLE(1920, 1080),
                                        &SPA_RECTANGLE(1, 1),
                                        &SPA_RECTANGLE(8192, 8192)),
        /* The minimum must be 0/1. A screen is a variable-rate source and
         * advertises exactly that; asking for 1/1 as the floor matches
         * nothing and the stream reports that it has no more input formats. */
        SPA_FORMAT_VIDEO_framerate, SPA_POD_CHOICE_RANGE_Fraction(
                                        &SPA_FRACTION(60, 1),
                                        &SPA_FRACTION(0, 1),
                                        &SPA_FRACTION(240, 1)));

    int nStatus = g_pw.streamConnect(pCap->pStream, PW_DIRECTION_INPUT, nNodeId,
        PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS, params, 1);

    g_pw.loopUnlock(pCap->pLoop);

    if (nStatus < 0)
    {
        DirectGate_WL_CaptureStop(pCap);
        DirectGate_WL_SetError(pErrBuf, nErrSize,
            "Failed to subscribe to the portal's PipeWire node %u.", nNodeId);

        return NULL;
    }

    return pCap;
}

int DirectGate_WL_CaptureWaitFormat(directgate_wl_capture_t *pCapture, uint32_t nTimeoutMs)
{
    XCHECK((pCapture != NULL), XSTDERR);

    g_pw.loopLock(pCapture->pLoop);

    while (!pCapture->bHaveFormat && !pCapture->bFailed)
    {
        if (g_pw.loopTimedWait(pCapture->pLoop, (int)((nTimeoutMs + 999U) / 1000U)) != 0) break;
    }

    xbool_t bReady = pCapture->bHaveFormat;
    g_pw.loopUnlock(pCapture->pLoop);

    return bReady ? XSTDOK : XSTDERR;
}

xbool_t DirectGate_WL_CaptureSize(directgate_wl_capture_t *pCapture,
                                  uint32_t *pWidth, uint32_t *pHeight)
{
    XCHECK_NL((pCapture != NULL), XFALSE);

    g_pw.loopLock(pCapture->pLoop);
    xbool_t bReady = pCapture->bHaveFormat;

    if (bReady)
    {
        if (pWidth != NULL) *pWidth = pCapture->format.size.width;
        if (pHeight != NULL) *pHeight = pCapture->format.size.height;
    }

    g_pw.loopUnlock(pCapture->pLoop);
    return bReady;
}

void DirectGate_WL_CaptureStop(directgate_wl_capture_t *pCapture)
{
    if (pCapture == NULL) return;

    /* Stop the thread before touching anything it runs on: the callbacks
     * dereference this struct, and freeing it underneath them is the one
     * teardown mistake that turns a clean stop into a crash. */
    if (pCapture->pLoop != NULL && g_pw.loopStop != NULL) g_pw.loopStop(pCapture->pLoop);

    if (pCapture->pStream != NULL)
    {
        if (g_pw.streamDisconnect != NULL) g_pw.streamDisconnect(pCapture->pStream);
        if (g_pw.streamDestroy != NULL) g_pw.streamDestroy(pCapture->pStream);
        pCapture->pStream = NULL;
    }

    if (pCapture->pCore != NULL && g_pw.coreDisconnect != NULL)
    {
        g_pw.coreDisconnect(pCapture->pCore);
        pCapture->pCore = NULL;
    }

    if (pCapture->pContext != NULL && g_pw.ctxDestroy != NULL)
    {
        g_pw.ctxDestroy(pCapture->pContext);
        pCapture->pContext = NULL;
    }

    if (pCapture->pLoop != NULL && g_pw.loopDestroy != NULL)
    {
        g_pw.loopDestroy(pCapture->pLoop);
        pCapture->pLoop = NULL;
    }

    if (pCapture->nUnmappable > 0)
    {
        xlogw("Wayland capture dropped unmappable buffers: frames(%llu), dropped(%u)",
            (unsigned long long)pCapture->nFrames, pCapture->nUnmappable);
    }

    free(pCapture);
}

#endif /* DIRECTGATE_DESKTOP_HAS_WAYLAND */
