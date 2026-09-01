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

/* DRM format codes and layout modifiers, spelled out rather than taken from
 * libdrm: four constants are not worth a build dependency on every
 * distribution, and these are ABI - what a compositor and a GPU driver agree
 * on between themselves - so they cannot change. */
#define DIRECTGATE_WL_FOURCC(a, b, c, d) \
    ((uint32_t)(a) | ((uint32_t)(b) << 8) | ((uint32_t)(c) << 16) | ((uint32_t)(d) << 24))

#define DIRECTGATE_WL_DRM_XRGB8888   DIRECTGATE_WL_FOURCC('X', 'R', '2', '4')
#define DIRECTGATE_WL_DRM_ARGB8888   DIRECTGATE_WL_FOURCC('A', 'R', '2', '4')
#define DIRECTGATE_WL_DRM_MOD_INVALID 0x00ffffffffffffffULL
#define DIRECTGATE_WL_DRM_MOD_LINEAR  0ULL

/* Two POD property flags this file needs by name. They are part of the pod
 * wire format and their values have never moved, but SPA only gave them
 * names in 0.3.30 and 0.3.36 - and the header on a build image is whatever
 * that distribution froze years ago. Naming them here when they are absent
 * costs nothing and lets one source build against every SPA in the field. */
#ifndef SPA_POD_PROP_FLAG_MANDATORY
#define SPA_POD_PROP_FLAG_MANDATORY    (1u << 3)
#endif

#ifndef SPA_POD_PROP_FLAG_DONT_FIXATE
#define SPA_POD_PROP_FLAG_DONT_FIXATE  (1u << 4)
#endif

/* The layouts this agent offers to import.
 *
 * INVALID means "whatever the driver would have chosen on its own", which is
 * the one layout a GPU can always import back on the device that produced it;
 * LINEAR is the universal fallback any compositor can produce. Naming the
 * tiled layouts a particular GPU supports would mean querying them through
 * EGL, and linking a GL stack into an agent to save the compositor a detiling
 * pass is not a trade worth making. A layout that is not on this list is not
 * a failure: the offer simply does not match and the compositor keeps sending
 * memory this process can read. */
static const uint64_t g_wlModifiers[] = {
    DIRECTGATE_WL_DRM_MOD_INVALID,
    DIRECTGATE_WL_DRM_MOD_LINEAR,
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

    /* Export state. bWantDmaBuf is what the caller asked for, bDmaBuf is what
     * the compositor agreed to, and bDroppedDmaBuf is a door that only closes:
     * once the export has proved unusable the offer is never made again on
     * this stream, or a compositor that keeps agreeing to it would put the
     * session in a renegotiation loop. */
    xbool_t bWantDmaBuf;
    xbool_t bDmaBuf;
    xbool_t bDroppedDmaBuf;
    uint32_t nFourCC;
    uint64_t nModifier;
    xbool_t bWarnedExport;

    /* Diagnostics that answer the two questions a black stream raises. */
    uint64_t nFrames;
    uint64_t nSkipped;   /* overtaken before they could be converted */
    uint64_t nEmpty;     /* buffers that reported no data at all */
    uint32_t nUnmappable;
    xbool_t bWarnedUnmappable;
    xbool_t bWarnedShort;
    xbool_t bWarnedEmpty;
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

    /* A stream that had a format and is now unconnected is the compositor
     * taking the screen back: someone pressed "Stop sharing", the session was
     * revoked, or the compositor restarted. Nothing arrives after this, and
     * without noticing it the viewer is left looking at the last frame for as
     * long as they care to wait - a frozen picture that looks like the
     * network died. */
    if (eState == PW_STREAM_STATE_UNCONNECTED && pCap->bHaveFormat && !pCap->bFailed)
    {
        xstrncpy(pCap->sError, sizeof(pCap->sError),
            "Screen sharing was stopped on the remote computer.");

        pCap->bFailed = XTRUE;
        xlogw("Wayland capture stream was disconnected by the compositor");

        g_pw.loopSignal(pCap->pLoop, false);
        return;
    }

    xlogd("Wayland capture stream state: state(%s)",
        g_pw.streamStateStr != NULL ? g_pw.streamStateStr(eState) : "?");
}

/* One EnumFormat entry. With no modifiers this is the memory offer that has
 * always been made; with them it is the same picture as something the GPU
 * keeps, and the two are offered together so the compositor picks whichever
 * it can actually do. */
static const struct spa_pod* DirectGate_WL_BuildFormat(struct spa_pod_builder *pBuilder,
                                                       uint32_t nFormat,
                                                       const uint64_t *pModifiers,
                                                       uint32_t nModifiers)
{
    struct spa_pod_frame frames[2];

    spa_pod_builder_push_object(pBuilder, &frames[0], SPA_TYPE_OBJECT_Format, SPA_PARAM_EnumFormat);
    spa_pod_builder_add(pBuilder,
        SPA_FORMAT_mediaType,       SPA_POD_Id(SPA_MEDIA_TYPE_video),
        SPA_FORMAT_mediaSubtype,    SPA_POD_Id(SPA_MEDIA_SUBTYPE_raw),
        SPA_FORMAT_VIDEO_format,    SPA_POD_Id(nFormat), 0);

    if (pModifiers != NULL && nModifiers > 0)
    {
        /* Mandatory, because a producer that ignored it would hand back
         * memory this entry promised to import. Not fixated while there is
         * still a choice to make: the producer picks from the list and then
         * asks which one it may use, and answering that is what turns the
         * offer into an export. */
        uint32_t nFlags = SPA_POD_PROP_FLAG_MANDATORY;
        if (nModifiers > 1) nFlags |= SPA_POD_PROP_FLAG_DONT_FIXATE;

        spa_pod_builder_prop(pBuilder, SPA_FORMAT_VIDEO_modifier, nFlags);
        spa_pod_builder_push_choice(pBuilder, &frames[1], SPA_CHOICE_Enum, 0);
        spa_pod_builder_long(pBuilder, (int64_t)pModifiers[0]);

        for (uint32_t i = 0; i < nModifiers; i++)
            spa_pod_builder_long(pBuilder, (int64_t)pModifiers[i]);

        spa_pod_builder_pop(pBuilder, &frames[1]);
    }

    spa_pod_builder_add(pBuilder,
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
                                        &SPA_FRACTION(240, 1)), 0);

    return (const struct spa_pod*)spa_pod_builder_pop(pBuilder, &frames[0]);
}

/* The whole offer, in the order it is preferred: exported entries first when
 * there is an encoder that can take one, and the memory entry always last so
 * that a compositor which will not export still has something to agree to.
 *
 * @p pModifiers is the list to offer (NULL when not exporting, and a single
 * fixated value when answering the producer's choice). */
static uint32_t DirectGate_WL_BuildFormats(directgate_wl_capture_t *pCap,
                                           struct spa_pod_builder *pBuilder,
                                           const struct spa_pod **pParams,
                                           uint32_t nMax,
                                           const uint64_t *pModifiers,
                                           uint32_t nModifiers)
{
    uint32_t nCount = 0;

    if (pCap->bWantDmaBuf && !pCap->bDroppedDmaBuf && pModifiers != NULL && nModifiers > 0)
    {
        /* One entry per format: a modifier list belongs to a single format,
         * so the two cannot share a pod the way the memory offer does. */
        if (nCount < nMax)
            pParams[nCount++] = DirectGate_WL_BuildFormat(pBuilder, SPA_VIDEO_FORMAT_BGRx, pModifiers, nModifiers);

        if (nCount < nMax)
            pParams[nCount++] = DirectGate_WL_BuildFormat(pBuilder, SPA_VIDEO_FORMAT_BGRA, pModifiers, nModifiers);
    }

    /* BGRx/BGRA only: both are byte-order identical to what the X11 path
     * produces, so the existing scale and I420 conversion are reused with no
     * swizzle. A compositor offering only RGB-order formats would fail
     * negotiation rather than stream wrong colours. */
    if (nCount < nMax)
        pParams[nCount++] = DirectGate_WL_BuildFormat(pBuilder, SPA_VIDEO_FORMAT_BGRx, NULL, 0);

    if (nCount < nMax)
        pParams[nCount++] = DirectGate_WL_BuildFormat(pBuilder, SPA_VIDEO_FORMAT_BGRA, NULL, 0);

    return nCount;
}

/* The layout the stream negotiated, read out of the format itself.
 *
 * Not out of the parsed struct: spa_video_info_raw only grew the fields that
 * report a layout in PipeWire 0.3.65, while the property they report has been
 * in the format all along - so asking the format works on every version and
 * asking the struct does not build on half of them.
 *
 * Returns XFALSE when there is no layout at all, which is the memory path.
 * @p pbFixate comes back true when the producer has narrowed the list down
 * but not chosen yet, and is waiting to be told which one it may use. */
static xbool_t DirectGate_WL_FormatModifier(const struct spa_pod *pFormat,
                                            uint64_t *pModifier, xbool_t *pbFixate)
{
    if (pbFixate != NULL) *pbFixate = XFALSE;

    const struct spa_pod_prop *pProp = spa_pod_find_prop(pFormat, NULL, SPA_FORMAT_VIDEO_modifier);
    if (pProp == NULL) return XFALSE;

    if (pbFixate != NULL) *pbFixate = ((pProp->flags & SPA_POD_PROP_FLAG_DONT_FIXATE) != 0) ? XTRUE : XFALSE;

    /* A choice while the producer is still deciding and a plain value once it
     * has decided. The first entry of a choice is its default, which is the
     * one the producer would rather have out of what it was offered. */
    const struct spa_pod *pValue = &pProp->value;
    if (SPA_POD_TYPE(pValue) == SPA_TYPE_Choice) pValue = SPA_POD_CHOICE_CHILD(pValue);

    int64_t nValue = 0;
    if (spa_pod_get_long(pValue, &nValue) < 0) return XFALSE;

    if (pModifier != NULL) *pModifier = (uint64_t)nValue;
    return XTRUE;
}

/* Whether a layout is one of the two this agent said it could import. The
 * producer can only choose from what was offered, so this should always be
 * true - but a compositor that ignored the offer would have the agent promise
 * the GPU something it never agreed to take. */
static xbool_t DirectGate_WL_ModifierOffered(uint64_t nModifier)
{
    for (uint32_t i = 0; i < sizeof(g_wlModifiers) / sizeof(g_wlModifiers[0]); i++)
    {
        if (g_wlModifiers[i] == nModifier) return XTRUE;
    }

    return XFALSE;
}

/* DRM code for what the stream negotiated. Only the two formats offered above
 * can appear here; anything else means the export cannot be described. */
static uint32_t DirectGate_WL_FourCCFromFormat(uint32_t nFormat)
{
    if (nFormat == SPA_VIDEO_FORMAT_BGRx) return DIRECTGATE_WL_DRM_XRGB8888;
    if (nFormat == SPA_VIDEO_FORMAT_BGRA) return DIRECTGATE_WL_DRM_ARGB8888;

    return 0;
}

/* Re-offers without the exported entries, which makes the stream renegotiate
 * for memory in place. The portal grant is not involved - only the format
 * offer changes - so nobody is prompted again. Stream thread only. */
static void DirectGate_WL_CaptureFallbackLocked(directgate_wl_capture_t *pCap, const char *pReason)
{
    if (pCap->bDroppedDmaBuf || pCap->pStream == NULL) return;

    pCap->bDroppedDmaBuf = XTRUE;
    pCap->bDmaBuf = XFALSE;

    xlogw("Exported desktop frames cannot be used, asking the compositor for mapped memory: reason(%s)",
        xstrused(pReason) ? pReason : "unknown");

    uint8_t buffer[4096];
    struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(buffer, sizeof(buffer));
    const struct spa_pod *params[4];

    uint32_t nCount = DirectGate_WL_BuildFormats(pCap, &builder, params, 4, NULL, 0);
    if (nCount > 0) g_pw.streamUpdateParams(pCap->pStream, params, nCount);
}

static void DirectGate_WL_OnParamChanged(void *pCtx, uint32_t nId, const struct spa_pod *pParam)
{
    directgate_wl_capture_t *pCap = (directgate_wl_capture_t*)pCtx;
    uint32_t nMediaType = 0, nMediaSubtype = 0;

    if (pParam == NULL || nId != SPA_PARAM_Format) return;
    if (spa_format_parse(pParam, &nMediaType, &nMediaSubtype) < 0) return;
    if (nMediaType != SPA_MEDIA_TYPE_video || nMediaSubtype != SPA_MEDIA_SUBTYPE_raw) return;
    if (spa_format_video_raw_parse(pParam, &pCap->format) < 0) return;

    uint64_t nModifier = 0;
    xbool_t bFixate = XFALSE;
    xbool_t bExported = DirectGate_WL_FormatModifier(pParam, &nModifier, &bFixate);

    /* Every value the producer can pick came from ours, because it can only
     * choose from what was offered - but one that ignored that would have
     * this agent promise the GPU something it never agreed to take. */
    if (bExported && !DirectGate_WL_ModifierOffered(nModifier))
    {
        DirectGate_WL_CaptureFallbackLocked(pCap, "the compositor picked a buffer layout that was not offered");
        return;
    }

    /* The producer has narrowed the list down and is asking which layout it
     * may use. Nothing is allocated until that is answered with a single
     * value, so this round of negotiation ends here and the next one carries
     * the format the buffers are actually made in. */
    if (bExported && bFixate)
    {
        uint8_t fixate[4096];
        struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(fixate, sizeof(fixate));
        const struct spa_pod *params[4];

        uint32_t nCount = DirectGate_WL_BuildFormats(pCap, &builder, params, 4, &nModifier, 1);
        if (nCount > 0) g_pw.streamUpdateParams(pCap->pStream, params, nCount);

        return;
    }

    uint32_t nFourCC = bExported ? DirectGate_WL_FourCCFromFormat(pCap->format.format) : 0;

    /* Agreed to export something that cannot be described to the encoder:
     * better to say so now, while a renegotiation costs nothing, than to
     * discover it one frame at a time. */
    if (bExported && nFourCC == 0)
    {
        DirectGate_WL_CaptureFallbackLocked(pCap, "the exported buffer is not in a format this agent imports");
        return;
    }

    uint8_t buffer[512];
    struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(buffer, sizeof(buffer));
    const struct spa_pod *params[1];

    if (bExported)
    {
        /* The encoder is handed the compositor's own buffer and holds it
         * until the frame has been through the GPU, so one is out of
         * circulation for as long as an encode takes. Asking for a few more
         * than the default means the compositor never has to wait for one
         * back, which is what a shortage would look like: dropped frames on
         * a screen that is changing fast. */
        params[0] = spa_pod_builder_add_object(&builder,
            SPA_TYPE_OBJECT_ParamBuffers, SPA_PARAM_Buffers,
            SPA_PARAM_BUFFERS_dataType, SPA_POD_CHOICE_FLAGS_Int(1 << SPA_DATA_DmaBuf),
            SPA_PARAM_BUFFERS_buffers, SPA_POD_CHOICE_RANGE_Int(4, 2, 16));
    }
    else
    {
        /* The load-bearing constraint on the memory path. A GPU compositor's
         * natural answer is a DMA-BUF, which arrives with data == NULL in a
         * process that has not imported it, so every frame would be skipped
         * and the viewer would see a black screen rather than an error.
         * Excluding SPA_DATA_DmaBuf makes the compositor do the GPU-to-CPU
         * copy and hand back memory that can simply be mapped. */
        params[0] = spa_pod_builder_add_object(&builder,
            SPA_TYPE_OBJECT_ParamBuffers, SPA_PARAM_Buffers,
            SPA_PARAM_BUFFERS_dataType, SPA_POD_CHOICE_FLAGS_Int(
                (1 << SPA_DATA_MemFd) | (1 << SPA_DATA_MemPtr)));
    }

    g_pw.streamUpdateParams(pCap->pStream, params, 1);

    pCap->bDmaBuf = bExported;
    pCap->nFourCC = nFourCC;
    pCap->nModifier = bExported ? nModifier : 0;
    pCap->bHaveFormat = XTRUE;

    xlogi("Wayland capture negotiated a format: size(%ux%u), rate(%u/%u), frames(%s)",
        pCap->format.size.width, pCap->format.size.height,
        pCap->format.framerate.num, pCap->format.framerate.denom,
        bExported ? "exported by the GPU" : "mapped memory");

    g_pw.loopSignal(pCap->pLoop, false);
}

/* Everything the compositor says about a buffer is checked before a byte of
 * it is read. These numbers cross a process boundary, and a frame that is
 * shorter than its own stride says it is - a partial update, a resize that
 * raced the format change, a compositor bug - would otherwise be read past
 * the end of the mapping. */
static xbool_t DirectGate_WL_FrameFromBuffer(directgate_wl_capture_t *pCap,
                                             struct pw_buffer *pBuffer,
                                             directgate_wl_frame_t *pFrame)
{
    struct spa_buffer *pBuf = pBuffer->buffer;
    if (pBuf == NULL || pBuf->n_datas < 1) return XFALSE;

    struct spa_data *pData = &pBuf->datas[0];
    if (pData->data == NULL)
    {
        /* Should not happen given the dataType constraint, but a compositor
         * that ignores it would otherwise stream black in silence. Once is
         * enough to say so. */
        pCap->nUnmappable++;

        if (!pCap->bWarnedUnmappable)
        {
            pCap->bWarnedUnmappable = XTRUE;
            xlogw("Wayland capture received a buffer it cannot map (type %u); "
                  "the compositor ignored the memory-type constraint", pData->type);
        }

        return XFALSE;
    }

    if (pCap->fnFrame == NULL || !pCap->bHaveFormat) return XFALSE;

    uint32_t nWidth = pCap->format.size.width;
    uint32_t nHeight = pCap->format.size.height;
    if (nWidth == 0 || nHeight == 0) return XFALSE;

    uint32_t nOffset = 0, nStride = 0;
    if (pData->chunk != NULL)
    {
        /* Nothing was written into this one. The compositor sends such a
         * buffer when only metadata changed, and on the very first one the
         * mapping still holds whatever was in that memory - which is a frame
         * of garbage, not a picture of the desktop. */
        if (pData->chunk->size == 0)
        {
            /* Unless that is all it ever sends, in which case skipping them
             * is the reason the screen is black and the log should say so
             * rather than leaving it to be guessed. */
            if (++pCap->nEmpty > 60U && pCap->nFrames == 0 && !pCap->bWarnedEmpty)
            {
                pCap->bWarnedEmpty = XTRUE;
                xlogw("Wayland capture has received %llu buffers that report no data and no frames at all; "
                      "this compositor may not be setting the chunk size",
                      (unsigned long long)pCap->nEmpty);
            }

            return XFALSE;
        }

        nOffset = (uint32_t)pData->chunk->offset;
        nStride = (uint32_t)pData->chunk->stride;
    }

    /* A zero stride means packed rows; anything smaller than a packed row
     * would make the frame read past its own buffer. */
    if (nStride == 0) nStride = nWidth * 4U;
    if (nStride < nWidth * 4U) return XFALSE;

    /* The last row only needs its own width, not a full stride, which is what
     * a tightly-sized final row in the mapping relies on. */
    size_t nNeeded = (size_t)nOffset + (size_t)nStride * (nHeight - 1U) + (size_t)nWidth * 4U;
    if (nNeeded > (size_t)pData->maxsize)
    {
        if (!pCap->bWarnedShort)
        {
            pCap->bWarnedShort = XTRUE;
            xlogw("Wayland capture received a buffer shorter than the format it announced: "
                  "size(%ux%u), stride(%u), offset(%u), mapped(%u)",
                  nWidth, nHeight, nStride, nOffset, (unsigned)pData->maxsize);
        }

        return XFALSE;
    }

    pFrame->eKind = DIRECTGATE_WL_FRAME_MAPPED;
    pFrame->pPixels = (const uint8_t*)pData->data + nOffset;
    pFrame->nWidth = nWidth;
    pFrame->nHeight = nHeight;
    pFrame->nStride = nStride;

    return XTRUE;
}

/* The exported equivalent: nothing in the buffer is read, only described.
 * The same suspicion applies to every number, because they still cross a
 * process boundary - but a bad one here means an import the GPU refuses
 * rather than a read past the end of a mapping. */
static xbool_t DirectGate_WL_FrameFromDmaBuf(directgate_wl_capture_t *pCap,
                                             struct pw_buffer *pBuffer,
                                             directgate_wl_frame_t *pFrame)
{
    struct spa_buffer *pBuf = pBuffer->buffer;
    if (pBuf == NULL || pBuf->n_datas < 1) return XFALSE;

    /* One object is what libavutil is able to map, and a packed RGB frame is
     * one. A compositor that splits it across several is answered by going
     * back to memory rather than by importing part of a picture. */
    if (pBuf->n_datas != 1 || pBuf->datas[0].type != SPA_DATA_DmaBuf || pBuf->datas[0].fd < 0)
    {
        if (!pCap->bWarnedExport)
        {
            pCap->bWarnedExport = XTRUE;
            xlogw("Wayland capture received an export it cannot describe: planes(%u), type(%u)",
                pBuf->n_datas, pBuf->datas[0].type);
        }

        return XFALSE;
    }

    uint32_t nWidth = pCap->format.size.width;
    uint32_t nHeight = pCap->format.size.height;
    if (nWidth == 0 || nHeight == 0 || pCap->nFourCC == 0) return XFALSE;

    struct spa_data *pData = &pBuf->datas[0];
    uint32_t nOffset = 0, nStride = 0;

    if (pData->chunk != NULL)
    {
        nOffset = (uint32_t)pData->chunk->offset;
        nStride = (uint32_t)pData->chunk->stride;
    }

    /* A zero stride means packed rows, the same as on the memory path;
     * anything shorter than a packed row describes a frame that does not
     * fit in the object it claims to live in. */
    if (nStride == 0) nStride = nWidth * 4U;
    if (nStride < nWidth * 4U) return XFALSE;

    /* Compositors do not always fill maxsize in for an exported buffer, and
     * the driver needs a size for the import; the packed extent of what was
     * announced is the honest answer when there is nothing better. */
    uint64_t nSize = (uint64_t)pData->maxsize;
    uint64_t nNeeded = (uint64_t)nOffset + (uint64_t)nStride * nHeight;
    if (nSize < nNeeded) nSize = nNeeded;

    memset(&pFrame->dmabuf, 0, sizeof(pFrame->dmabuf));
    pFrame->dmabuf.nWidth = nWidth;
    pFrame->dmabuf.nHeight = nHeight;
    pFrame->dmabuf.nFourCC = pCap->nFourCC;
    pFrame->dmabuf.nModifier = pCap->nModifier;
    pFrame->dmabuf.nPlanes = 1;
    pFrame->dmabuf.nSize = nSize;
    pFrame->dmabuf.nFds[0] = (int)pData->fd;
    pFrame->dmabuf.nOffsets[0] = nOffset;
    pFrame->dmabuf.nStrides[0] = nStride;

    pFrame->eKind = DIRECTGATE_WL_FRAME_EXPORTED;
    pFrame->nWidth = nWidth;
    pFrame->nHeight = nHeight;

    return XTRUE;
}

static void DirectGate_WL_OnProcess(void *pCtx)
{
    directgate_wl_capture_t *pCap = (directgate_wl_capture_t*)pCtx;
    struct pw_buffer *pBuffer = NULL;
    struct pw_buffer *pNewest = NULL;

    /* Drain to the newest and give the rest straight back. A frame that has
     * already been overtaken is of no use to a live stream, and converting it
     * first would put its whole encode time in front of the frame the viewer
     * is actually waiting for - latency the session never gets back. */
    while ((pBuffer = g_pw.streamDequeue(pCap->pStream)) != NULL)
    {
        if (pNewest != NULL)
        {
            pCap->nSkipped++;
            g_pw.streamQueue(pCap->pStream, pNewest);
        }

        pNewest = pBuffer;
    }

    if (pNewest == NULL) return;

    directgate_wl_frame_t frame;
    memset(&frame, 0, sizeof(frame));

    if (pCap->bDmaBuf)
    {
        if (!DirectGate_WL_FrameFromDmaBuf(pCap, pNewest, &frame))
        {
            /* Nothing can be done with this one, and nothing will be done
             * with the next either: the export is refused as a whole rather
             * than one silent frame at a time. */
            g_pw.streamQueue(pCap->pStream, pNewest);
            DirectGate_WL_CaptureFallbackLocked(pCap, "the exported buffer cannot be described");

            return;
        }

        /* The buffer goes with the frame. It cannot be given back here: the
         * compositor would be free to draw into it while the GPU is still
         * reading, and a torn frame is exactly what that looks like. */
        pCap->nFrames++;
        frame.pHandle = pNewest;
        frame.pCapture = pCap;
        pCap->fnFrame(pCap->pUserCtx, &frame);

        return;
    }

    if (DirectGate_WL_FrameFromBuffer(pCap, pNewest, &frame))
    {
        pCap->nFrames++;
        frame.pCapture = pCap;
        pCap->fnFrame(pCap->pUserCtx, &frame);
    }

    g_pw.streamQueue(pCap->pStream, pNewest);
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
                                                    xbool_t bWantDmaBuf,
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
    pCap->bWantDmaBuf = bWantDmaBuf;

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
     * how this process reaches PipeWire without any socket of its own.
     *
     * It owns it from here on either way - "the socket will be closed
     * automatically on disconnect or error" - so the failure path must not
     * close it as well. Closing a descriptor twice does not fail quietly in a
     * threaded process: the number is free by then, and the second close can
     * take out whatever another thread has just opened on it. */
    pCap->pCore = g_pw.ctxConnectFd(pCap->pContext, nPipeWireFd, NULL, 0);
    if (pCap->pCore == NULL)
    {
        g_pw.loopUnlock(pCap->pLoop);
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

    uint8_t buffer[4096];
    struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(buffer, sizeof(buffer));
    const struct spa_pod *params[4];

    uint32_t nParams = DirectGate_WL_BuildFormats(pCap, &builder, params, 4,
        bWantDmaBuf ? g_wlModifiers : NULL,
        bWantDmaBuf ? (uint32_t)(sizeof(g_wlModifiers) / sizeof(g_wlModifiers[0])) : 0);

    /* MAP_BUFFERS stays on for the memory entries; it does nothing to an
     * exported buffer, which is not mappable and is never read here. */
    int nStatus = g_pw.streamConnect(pCap->pStream, PW_DIRECTION_INPUT, nNodeId,
        PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS, params, nParams);

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

    /* An offer to export is the only thing here that has ever been new, so it
     * is also the only thing a silence like this is likely to be about: a
     * compositor that answers the modifier question with nothing at all would
     * otherwise cost the session, when withdrawing the offer costs a second.
     * Once only - bDroppedDmaBuf sees to that - and never on a stream that
     * was not offered one. */
    if (!pCapture->bHaveFormat && !pCapture->bFailed &&
        pCapture->bWantDmaBuf && !pCapture->bDroppedDmaBuf)
    {
        DirectGate_WL_CaptureFallbackLocked(pCapture, "the compositor did not answer the export offer");

        while (!pCapture->bHaveFormat && !pCapture->bFailed)
        {
            if (g_pw.loopTimedWait(pCapture->pLoop, (int)((nTimeoutMs + 999U) / 1000U)) != 0) break;
        }
    }

    xbool_t bReady = pCapture->bHaveFormat;
    g_pw.loopUnlock(pCapture->pLoop);

    return bReady ? XSTDOK : XSTDERR;
}

xbool_t DirectGate_WL_CaptureLost(directgate_wl_capture_t *pCapture, char *pErrBuf, size_t nErrSize)
{
    XCHECK_NL((pCapture != NULL), XFALSE);

    g_pw.loopLock(pCapture->pLoop);
    xbool_t bFailed = pCapture->bFailed;

    if (bFailed && pErrBuf != NULL && nErrSize > 0)
        xstrncpy(pErrBuf, nErrSize, pCapture->sError);

    g_pw.loopUnlock(pCapture->pLoop);
    return bFailed;
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

xbool_t DirectGate_WL_CaptureIsDmaBuf(directgate_wl_capture_t *pCapture,
                                      uint32_t *pFourCC, uint64_t *pModifier)
{
    XCHECK_NL((pCapture != NULL), XFALSE);

    g_pw.loopLock(pCapture->pLoop);
    xbool_t bDmaBuf = pCapture->bDmaBuf;

    if (bDmaBuf)
    {
        if (pFourCC != NULL) *pFourCC = pCapture->nFourCC;
        if (pModifier != NULL) *pModifier = pCapture->nModifier;
    }

    g_pw.loopUnlock(pCapture->pLoop);
    return bDmaBuf;
}

void DirectGate_WL_CaptureRelease(directgate_wl_capture_t *pCapture, void *pHandle)
{
    XCHECK_VOID_NL((pCapture != NULL && pHandle != NULL));

    /* Locking the loop is how another thread reaches a stream safely. The
     * caller must therefore not be holding anything DirectGate_WL_OnProcess
     * takes on its way in, or the two threads wait for each other; the frame
     * slot is handed over before the encode starts for exactly that reason. */
    g_pw.loopLock(pCapture->pLoop);
    if (pCapture->pStream != NULL) g_pw.streamQueue(pCapture->pStream, (struct pw_buffer*)pHandle);
    g_pw.loopUnlock(pCapture->pLoop);
}

void DirectGate_WL_CaptureDrop(directgate_wl_capture_t *pCapture, void *pHandle)
{
    XCHECK_VOID_NL((pCapture != NULL && pHandle != NULL));

    /* Already on the loop thread: taking its lock here would be a thread
     * waiting for itself. */
    if (pCapture->pStream != NULL) g_pw.streamQueue(pCapture->pStream, (struct pw_buffer*)pHandle);
}

void DirectGate_WL_CaptureDisableDmaBuf(directgate_wl_capture_t *pCapture)
{
    XCHECK_VOID_NL((pCapture != NULL));

    g_pw.loopLock(pCapture->pLoop);
    DirectGate_WL_CaptureFallbackLocked(pCapture, "the GPU could not take the exported frames");
    g_pw.loopUnlock(pCapture->pLoop);
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

    /* Overtaken frames are normal under load - it is the encoder keeping the
     * stream live rather than falling behind - but the count is the first
     * thing worth knowing when someone reports a laggy desktop. */
    xlogd("Wayland capture finished: frames(%llu), overtaken(%llu)",
        (unsigned long long)pCapture->nFrames, (unsigned long long)pCapture->nSkipped);

    free(pCapture);
}

#endif /* DIRECTGATE_DESKTOP_HAS_WAYLAND */
