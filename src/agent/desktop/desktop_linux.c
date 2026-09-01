/*!
 * @file directgate-agent/src/agent/desktop/desktop_linux.c
 * @brief Linux X11 (XShm) capture + OpenH264 encoder for desktop streaming.
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

#if defined(__linux__)

#include "desktop.h"
#include "session.h"
#include "openh264.h"
#include "hwenc.h"
#include "priv.h"
#include "yuv.h"

#ifdef DIRECTGATE_DESKTOP_HAS_WAYLAND
#include "wayland.h"
#endif

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/timerfd.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/XShm.h>

/* Consecutive capture/encode failures before the pipeline reports itself
 * broken and desktop.c falls back to raw RGBA (~1s at 30 fps). */
#define DIRECTGATE_X11ENC_MAX_FAILURES 30U

/* Consecutive GPU encode failures before giving up on the GPU for this
 * pipeline and continuing on the CPU. Deliberately generous: the software
 * encoder is a visible quality drop that lasts until the pipeline is
 * rebuilt, so it must answer a GPU that is genuinely broken, not one that
 * stuttered for a couple of frames. */
#define DIRECTGATE_X11ENC_MAX_HW_FAILURES 30U

/* The same idea for the zero-copy path, but a shorter fuse. What it falls
 * back to is not a worse picture, only a busier CPU, so there is far less to
 * lose by giving up early - and what it gives up is regained on the next
 * pipeline rebuild. A quarter of a second at 30 fps. */
#define DIRECTGATE_X11ENC_MAX_IMPORT_FAILURES 8U

/* Poll interval while the mailbox is still occupied or the data channel is
 * backed up. Linux nanosleep honours this granularity, so it costs at most
 * half a millisecond of extra latency on a busy hand-off. */
#define DIRECTGATE_X11ENC_BUSY_WAIT_US 500ULL

/* How long a keyframe is allowed to keep settling on a screen that has gone
 * still. Only reached after an actual keyframe, so an idle desktop costs
 * nothing until one happens; see the reasoning where it is armed. */
#define DIRECTGATE_X11ENC_REFINE_MS    1500U

/* A frame that sat in the mailbox longer than this never goes on the wire
 * (see DrainMain). */
#define DIRECTGATE_X11ENC_MIN_AGE_US   50000ULL

/* Cross-thread control flags. Taking a request is a read-modify-write on
 * both sides, so plain volatile is not enough: the worker's "handled" store
 * could clobber a request the main loop raised while the encoder was still
 * running, and a lost keyframe request means the viewer stares at a broken
 * picture until the next PLI. desktop_win.c uses InterlockedExchange for
 * exactly this; these builtins are the gcc/clang equivalent. */
#define DIRECTGATE_X11ENC_LOAD(pFlag)       __atomic_load_n((pFlag), __ATOMIC_ACQUIRE)
#define DIRECTGATE_X11ENC_SET(pFlag, nVal)  __atomic_store_n((pFlag), (nVal), __ATOMIC_RELEASE)
#define DIRECTGATE_X11ENC_TAKE(pFlag)       __atomic_exchange_n((pFlag), 0, __ATOMIC_ACQ_REL)
#define DIRECTGATE_X11ENC_PEEK(pFlag)       __atomic_load_n((pFlag), __ATOMIC_ACQUIRE)

/* True while the GPU encoder is the active backend. Collapses to XFALSE on
 * builds without libavcodec headers so the call sites stay #ifdef-free. */
#ifdef DIRECTGATE_HAVE_HWENC
#define DIRECTGATE_X11ENC_HAS_HW(pEnc)  ((pEnc)->pHwEncoder != NULL ? XTRUE : XFALSE)
#else
#define DIRECTGATE_X11ENC_HAS_HW(pEnc)  (XFALSE)
#endif

typedef struct directgate_x11enc_ {
    directgate_session_t *pSession;   /* backpressure checks only */
    directgate_desktop_t *pDesktop;

    /* Exactly one of these is live. The GPU encoder is preferred and the
     * software one is the guaranteed fallback: if no GPU encoder opens - or
     * a live one starts failing - the session keeps streaming on the CPU
     * rather than losing desktop mode. */
    directgate_openh264_t *pEncoder;
#ifdef DIRECTGATE_HAVE_HWENC
    directgate_hwenc_t *pHwEncoder;
    xbool_t bHwDisabled;              /* GPU gave up for good; stay on the CPU */
    uint32_t nHwFailures;             /* consecutive GPU encode failures */
#ifdef DIRECTGATE_DESKTOP_HAS_WAYLAND
    /* The compositor exports its frames and the encoder takes them as they
     * are: nothing between the screen and the bitstream is read, converted or
     * copied by this process. The buffers below stay allocated all the same,
     * because the way back to the copied path is to rebuild the encoder in
     * place rather than to restart the session. */
    xbool_t bZeroCopy;
#endif
#endif

    /* Private X11 connection owned by the capture thread. */
    Display *pDisplay;

    /* XShm-backed capture image; NULL when the slow XGetImage path is used
     * (e.g. remote DISPLAY where MIT-SHM is not usable). */
    XImage *pShmImage;
    XShmSegmentInfo shmInfo;
    xbool_t bShmAttached;

    int32_t nCaptureX;
    int32_t nCaptureY;
    uint32_t nCaptureWidth;
    uint32_t nCaptureHeight;
    uint32_t nEncodeWidth;
    uint32_t nEncodeHeight;

    /* Pixel normalization decided from the first captured XImage. */
    xbool_t bFormatChecked;
    xbool_t bDirectBGRA;    /* 32bpp little-endian BGRA: rows are memcpy-able */
    uint32_t nRedShift;
    uint32_t nGreenShift;
    uint32_t nBlueShift;

    uint8_t *pCaptureBGRA;  /* capture-size BGRA; only allocated when scaling */
    uint8_t *pFrameBGRA;    /* encode-size BGRA fed into the converter */
    uint8_t *pPrevBGRA;     /* previous encode-size BGRA for change detection */
    /* A picture has gone out at least once, so a keyframe can be answered
     * from what the encoder already holds instead of waiting for the screen
     * to change. True on both paths; bHavePrev says the same thing about the
     * BGRA buffers, which the zero-copy path never fills. */
    xbool_t bSentFrame;
    /* OpenH264 takes planar I420, every GPU encoder takes NV12; only the
     * plane buffer for the active encoder is allocated. */
    uint8_t *pI420;
    uint8_t *pNV12;
    xbool_t bHavePrev;
    uint32_t nRefineLeft;   /* frames still owed to a settling keyframe */
    uint64_t nStartUs;
    xbyte_buffer_t encoded; /* encoder output scratch (capture thread) */

    /* Thread control. The main loop only touches the flags below, the
     * mailbox, and nFailures; everything else belongs to the worker. All of
     * these are accessed through the atomic helpers above. */
    xthread_t thread;
    xbool_t bThreadRunning;
    uint32_t bStop;
    uint32_t bForceKeyframe;
    uint32_t bApplyQuality;       /* preset knobs waiting for the worker */
    uint32_t nPendingBitrateKbps; /* 0 = no pending step */
    uint32_t nFailures;

    /* Duplicate of the session's desktop timerfd. dup(2) shares the timer
     * itself, so re-arming this descriptor wakes the event loop exactly
     * like the periodic tick does - and because the worker owns the
     * descriptor, the event loop closing its own copy can never turn this
     * into a write to a recycled fd. */
    int nWakeFd;

    /* Single-slot mailbox: capture thread (producer) -> main loop
     * (consumer). Buffers are swapped under the lock, never copied. */
    xsync_mutex_t lock;
    xbyte_buffer_t mailbox;
    xbyte_buffer_t drain;
    uint32_t nMailboxWidth;
    uint32_t nMailboxHeight;
    xbool_t bMailboxKeyframe;
    uint64_t nMailboxPtsUs;
    uint64_t nMailboxCapturedUs;
    xbool_t bMailboxHasFrame;

    char sLastError[DIRECTGATE_DESKTOP_REASON_LEN];
} directgate_x11enc_t;

static void DirectGate_Desktop_X11Enc_EncodeAndPublish(directgate_x11enc_t *pEnc,
                                                       uint32_t nFps, uint64_t nCapturedUs,
                                                       const directgate_desktop_dmabuf_t *pDmaBuf);

static directgate_x11enc_t* DirectGate_Desktop_X11Enc(const directgate_desktop_t *pDesktop)
{
    XCHECK_NL((pDesktop != NULL), NULL);
    return (directgate_x11enc_t*)pDesktop->pEncoder;
}

static void DirectGate_Desktop_X11Enc_SetError(directgate_x11enc_t *pEnc,
                                               directgate_desktop_t *pDesktop,
                                               const char *pError)
{
    XCHECK_VOID_NL((xstrused(pError)));
    if (pEnc != NULL) xstrncpy(pEnc->sLastError, sizeof(pEnc->sLastError), pError);
    if (pDesktop != NULL) xstrncpy(pDesktop->sReason, sizeof(pDesktop->sReason), pError);
}

static uint64_t DirectGate_Desktop_X11Enc_MonotonicUs(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return 0;
    return (uint64_t)now.tv_sec * 1000000ULL + (uint64_t)now.tv_nsec / 1000ULL;
}

static void DirectGate_Desktop_X11Enc_PickSize(const directgate_desktop_t *pDesktop,
                                               uint32_t nSrcW, uint32_t nSrcH,
                                               uint32_t *pWidth, uint32_t *pHeight)
{
    uint32_t nWidth = nSrcW;
    uint32_t nHeight = nSrcH;
    DirectGate_Desktop_ComputeOutputSize(pDesktop, nSrcW, nSrcH, &nWidth, &nHeight);

    nWidth &= ~1U;
    nHeight &= ~1U;

    if (nWidth < 16U) nWidth = 16U;
    if (nHeight < 16U) nHeight = 16U;

    *pWidth = nWidth;
    *pHeight = nHeight;
}

static xbool_t DirectGate_Desktop_X11Enc_HostIsLittleEndian(void)
{
    const uint16_t nOne = 1;
    return (*(const uint8_t*)&nOne == 1) ? XTRUE : XFALSE;
}

static uint32_t DirectGate_Desktop_X11Enc_MaskShift(unsigned long nMask)
{
    uint32_t nShift = 0;
    if (!nMask) return 0;

    while ((nMask & 1UL) == 0)
    {
        nShift++;
        nMask >>= 1;
    }

    return nShift;
}

static uint8_t DirectGate_Desktop_X11Enc_Component(uint32_t nPixel, unsigned long nMask, uint32_t nShift)
{
    unsigned long nMax = nMask >> nShift;
    if (!nMask || !nMax) return 0;

    unsigned long nValue = (nPixel & nMask) >> nShift;
    return (uint8_t)((nValue * 255UL) / nMax);
}

static int DirectGate_Desktop_X11Enc_CheckFormat(directgate_x11enc_t *pEnc,
                                                directgate_desktop_t *pDesktop,
                                                const XImage *pImage)
{
    if (pEnc->bFormatChecked) return XSTDOK;

    if (pImage->bits_per_pixel != 32)
    {
        char sError[DIRECTGATE_DESKTOP_REASON_LEN];
        snprintf(sError, sizeof(sError),
            "Unsupported X11 pixel format for H.264 capture (%d bpp, need 32).",
            pImage->bits_per_pixel);

        DirectGate_Desktop_X11Enc_SetError(pEnc, pDesktop, sError);
        return XSTDERR;
    }

    pEnc->nRedShift = DirectGate_Desktop_X11Enc_MaskShift(pImage->red_mask);
    pEnc->nGreenShift = DirectGate_Desktop_X11Enc_MaskShift(pImage->green_mask);
    pEnc->nBlueShift = DirectGate_Desktop_X11Enc_MaskShift(pImage->blue_mask);

    /* The dominant case (Xorg on little-endian hosts) stores pixels as
     * B,G,R,X bytes which is exactly the BGRA layout the converter wants. */
    pEnc->bDirectBGRA = (pImage->byte_order == LSBFirst &&
                         DirectGate_Desktop_X11Enc_HostIsLittleEndian() &&
                         pImage->red_mask == 0xFF0000UL &&
                         pImage->green_mask == 0x00FF00UL &&
                         pImage->blue_mask == 0x0000FFUL) ? XTRUE : XFALSE;

    pEnc->bFormatChecked = XTRUE;
    return XSTDOK;
}

static void DirectGate_Desktop_X11Enc_Normalize(const directgate_x11enc_t *pEnc,
                                                const XImage *pImage,
                                                uint8_t *pDst)
{
    uint32_t nWidth = (uint32_t)pImage->width;
    uint32_t nHeight = (uint32_t)pImage->height;
    size_t nSrcStride = (size_t)pImage->bytes_per_line;
    size_t nDstStride = (size_t)nWidth * 4U;

    if (pEnc->bDirectBGRA)
    {
        for (uint32_t y = 0; y < nHeight; y++)
        {
            memcpy(pDst + (size_t)y * nDstStride,
                (const uint8_t*)pImage->data + (size_t)y * nSrcStride, nDstStride);
        }

        return;
    }

    xbool_t bLSBFirst = (pImage->byte_order == LSBFirst) ? XTRUE : XFALSE;
    for (uint32_t y = 0; y < nHeight; y++)
    {
        const uint8_t *pSrc = (const uint8_t*)pImage->data + (size_t)y * nSrcStride;
        uint8_t *pOut = pDst + (size_t)y * nDstStride;

        for (uint32_t x = 0; x < nWidth; x++)
        {
            const uint8_t *p = pSrc + (size_t)x * 4U;
            uint32_t nPixel = bLSBFirst ?
                ((uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                 ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24)) :
                ((uint32_t)p[3] | ((uint32_t)p[2] << 8) |
                 ((uint32_t)p[1] << 16) | ((uint32_t)p[0] << 24));

            pOut[0] = DirectGate_Desktop_X11Enc_Component(nPixel, pImage->blue_mask, pEnc->nBlueShift);
            pOut[1] = DirectGate_Desktop_X11Enc_Component(nPixel, pImage->green_mask, pEnc->nGreenShift);
            pOut[2] = DirectGate_Desktop_X11Enc_Component(nPixel, pImage->red_mask, pEnc->nRedShift);
            pOut[3] = 255U;
            pOut += 4;
        }
    }
}

static void DirectGate_Desktop_X11Enc_TeardownShm(directgate_x11enc_t *pEnc)
{
    Display *pDisplay = pEnc->pDisplay;

    if (pEnc->bShmAttached)
    {
        if (pDisplay != NULL)
        {
            XShmDetach(pDisplay, &pEnc->shmInfo);
            XSync(pDisplay, False);
        }

        shmdt(pEnc->shmInfo.shmaddr);
        pEnc->bShmAttached = XFALSE;
    }

    if (pEnc->pShmImage != NULL)
    {
        pEnc->pShmImage->data = NULL;
        XDestroyImage(pEnc->pShmImage);
        pEnc->pShmImage = NULL;
    }
}

static int DirectGate_Desktop_X11Enc_SetupShm(directgate_x11enc_t *pEnc, Display *pDisplay)
{
    if (!XShmQueryExtension(pDisplay))
        return XSTDNON;

    int nScreen = DefaultScreen(pDisplay);
    XImage *pImage = XShmCreateImage(pDisplay, DefaultVisual(pDisplay, nScreen),
        (unsigned int)DefaultDepth(pDisplay, nScreen), ZPixmap, NULL, &pEnc->shmInfo,
        pEnc->nCaptureWidth, pEnc->nCaptureHeight);
    if (pImage == NULL) return XSTDNON;

    size_t nBytes = (size_t)pImage->bytes_per_line * (size_t)pImage->height;
    pEnc->shmInfo.shmid = shmget(IPC_PRIVATE, nBytes, IPC_CREAT | 0600);
    if (pEnc->shmInfo.shmid < 0)
    {
        XDestroyImage(pImage);
        return XSTDNON;
    }

    pEnc->shmInfo.shmaddr = (char*)shmat(pEnc->shmInfo.shmid, NULL, 0);
    if (pEnc->shmInfo.shmaddr == (char*)-1)
    {
        shmctl(pEnc->shmInfo.shmid, IPC_RMID, NULL);
        XDestroyImage(pImage);
        return XSTDNON;
    }

    pEnc->shmInfo.readOnly = False;
    pImage->data = pEnc->shmInfo.shmaddr;

    if (!XShmAttach(pDisplay, &pEnc->shmInfo))
    {
        shmdt(pEnc->shmInfo.shmaddr);
        shmctl(pEnc->shmInfo.shmid, IPC_RMID, NULL);
        pImage->data = NULL;
        XDestroyImage(pImage);
        return XSTDNON;
    }

    XSync(pDisplay, False);

    /* Mark the segment for removal now: it stays alive while attached and
     * cannot leak if the agent dies without a clean teardown. */
    shmctl(pEnc->shmInfo.shmid, IPC_RMID, NULL);

    pEnc->pShmImage = pImage;
    pEnc->bShmAttached = XTRUE;
    return XSTDOK;
}

static void DirectGate_Desktop_X11Enc_Free(directgate_x11enc_t *pEnc)
{
    XCHECK_VOID_NL((pEnc != NULL));

    if (pEnc->bThreadRunning)
    {
        DIRECTGATE_X11ENC_SET(&pEnc->bStop, 1U);
        XThread_Join(&pEnc->thread);
        pEnc->bThreadRunning = XFALSE;
    }

    DirectGate_Desktop_X11Enc_TeardownShm(pEnc);
    DirectGate_OpenH264_Destroy(pEnc->pEncoder);

#ifdef DIRECTGATE_HAVE_HWENC
    DirectGate_HWEnc_Destroy(pEnc->pHwEncoder);
#endif

    if (pEnc->pDisplay != NULL)
    {
        XCloseDisplay(pEnc->pDisplay);
        pEnc->pDisplay = NULL;
    }

    if (pEnc->nWakeFd >= 0)
    {
        close(pEnc->nWakeFd);
        pEnc->nWakeFd = -1;
    }

    XSync_Destroy(&pEnc->lock);
    XByteBuffer_Clear(&pEnc->encoded);
    XByteBuffer_Clear(&pEnc->mailbox);
    XByteBuffer_Clear(&pEnc->drain);

    free(pEnc->pCaptureBGRA);
    free(pEnc->pFrameBGRA);
    free(pEnc->pPrevBGRA);
    free(pEnc->pI420);
    free(pEnc->pNV12);
    free(pEnc);
}

void DirectGate_Desktop_LinuxEncoder_StopDesktop(directgate_desktop_t *pDesktop)
{
    XCHECK_VOID_NL((pDesktop != NULL));
    directgate_x11enc_t *pEnc = DirectGate_Desktop_X11Enc(pDesktop);
    if (pEnc == NULL) return;

    /* Detach first: the join below runs on the main loop, and nothing must
     * be able to reach a half-freed pipeline in the meantime. */
    pDesktop->pEncoder = NULL;
    DirectGate_Desktop_X11Enc_Free(pEnc);
}

void DirectGate_Desktop_LinuxEncoder_Stop(directgate_session_t *pSession)
{
    XCHECK_VOID_NL((pSession != NULL));
    DirectGate_Desktop_LinuxEncoder_StopDesktop(&pSession->desktop);
}

static void DirectGate_Desktop_X11Enc_SleepUs(uint64_t nUs)
{
    struct timespec delay;
    delay.tv_sec = (time_t)(nUs / 1000000ULL);
    delay.tv_nsec = (long)((nUs % 1000000ULL) * 1000ULL);
    nanosleep(&delay, NULL);
}

/* Wakes the agent event loop so it drains the mailbox now instead of at the
 * next periodic tick. Re-arming the timerfd is the only cross-thread signal
 * available here (a timerfd cannot be written to), and it is exactly what
 * the loop already waits on. it_interval is restated so the periodic
 * heartbeat survives, re-anchored to this frame - which is the behaviour we
 * want anyway: "wake on a frame, or after one frame period of silence". */
static void DirectGate_Desktop_X11Enc_WakeMainLoop(const directgate_x11enc_t *pEnc, uint32_t nFps)
{
    if (pEnc->nWakeFd < 0) return;
    uint64_t nNs = 1000000000ULL / (nFps ? nFps : DIRECTGATE_DESKTOP_DEFAULT_FPS);

    struct itimerspec spec;
    memset(&spec, 0, sizeof(spec));
    spec.it_interval.tv_sec = (time_t)(nNs / 1000000000ULL);
    spec.it_interval.tv_nsec = (long)(nNs % 1000000000ULL);
    spec.it_value.tv_sec = 0;
    spec.it_value.tv_nsec = 1; /* fire immediately */

    (void)timerfd_settime(pEnc->nWakeFd, 0, &spec, NULL);
}

static xbool_t DirectGate_Desktop_X11Enc_MailboxBusy(directgate_x11enc_t *pEnc)
{
    XSync_Lock(&pEnc->lock);
    xbool_t bBusy = pEnc->bMailboxHasFrame;
    XSync_Unlock(&pEnc->lock);
    return bBusy;
}

/* Applies the control steps the main loop marshalled to this thread.
 * OpenH264's SetOption is not safe to call concurrently with EncodeFrame,
 * so the bitrate controller only ever leaves a pending value behind. */
static void DirectGate_Desktop_X11Enc_ApplyPendingControls(directgate_x11enc_t *pEnc)
{
    xbool_t bApplyQuality = DIRECTGATE_X11ENC_TAKE(&pEnc->bApplyQuality) ? XTRUE : XFALSE;
    uint32_t nBitrateKbps = DIRECTGATE_X11ENC_TAKE(&pEnc->nPendingBitrateKbps);

#ifdef DIRECTGATE_HAVE_HWENC
    if (pEnc->pHwEncoder != NULL)
    {
        if (bApplyQuality) DirectGate_HWEnc_ApplyQuality(pEnc->pHwEncoder, &pEnc->pDesktop->quality);
        else if (nBitrateKbps) DirectGate_HWEnc_SetBitrate(pEnc->pHwEncoder, nBitrateKbps);
        return;
    }
#endif

    if (bApplyQuality) DirectGate_OpenH264_ApplyQuality(pEnc->pEncoder, &pEnc->pDesktop->quality);
    if (nBitrateKbps) DirectGate_OpenH264_SetBitrate(pEnc->pEncoder, nBitrateKbps);
}

/* Allocates the plane buffer the active encoder consumes. Called whenever
 * the encoder backend changes, including the mid-session GPU -> CPU
 * fallback. */
static int DirectGate_Desktop_X11Enc_AllocPlanes(directgate_x11enc_t *pEnc)
{
    size_t nPlaneBytes = (size_t)pEnc->nEncodeWidth * pEnc->nEncodeHeight * 3U / 2U;

#ifdef DIRECTGATE_HAVE_HWENC
    if (pEnc->pHwEncoder != NULL)
    {
        if (pEnc->pNV12 == NULL) pEnc->pNV12 = (uint8_t*)malloc(nPlaneBytes);
        return (pEnc->pNV12 != NULL) ? XSTDOK : XSTDERR;
    }
#endif

    if (pEnc->pI420 == NULL) pEnc->pI420 = (uint8_t*)malloc(nPlaneBytes);
    return (pEnc->pI420 != NULL) ? XSTDOK : XSTDERR;
}

#ifdef DIRECTGATE_HAVE_HWENC
/* Drops the GPU encoder and continues on the CPU. The viewer keeps its
 * session: a GPU that stops accepting frames (driver reset, suspend/resume,
 * another process taking the encode engine) must degrade the picture, not
 * end desktop mode. Latched so a broken GPU is not retried every frame. */
static int DirectGate_Desktop_X11Enc_FallBackToSoftware(directgate_x11enc_t *pEnc)
{
    xlogw("GPU H.264 encoder failed, falling back to the software encoder: sid(%u), encoder(%s)",
        pEnc->pDesktop->nSessionId, DirectGate_HWEnc_Describe(pEnc->pHwEncoder));

    DirectGate_HWEnc_Destroy(pEnc->pHwEncoder);
    pEnc->pHwEncoder = NULL;
    pEnc->bHwDisabled = XTRUE;

    char sError[DIRECTGATE_DESKTOP_REASON_LEN] = { 0 };
    pEnc->pEncoder = DirectGate_OpenH264_Create(pEnc->nEncodeWidth, pEnc->nEncodeHeight,
        &pEnc->pDesktop->quality, sError, sizeof(sError));

    if (pEnc->pEncoder == NULL || DirectGate_Desktop_X11Enc_AllocPlanes(pEnc) != XSTDOK)
    {
        DirectGate_Desktop_X11Enc_SetError(pEnc, NULL,
            sError[0] ? sError : "Software H.264 encoder unavailable after GPU failure.");

        return XSTDERR;
    }

    /* New encoder, new reference chain. */
    DIRECTGATE_X11ENC_SET(&pEnc->bForceKeyframe, 1U);
    return XSTDOK;
}

#ifdef DIRECTGATE_DESKTOP_HAS_WAYLAND
/* Gives up on zero-copy without giving up the session. The compositor is
 * asked to go back to memory this process can read, and the encoder is
 * rebuilt as the ordinary GPU one - or, failing that, the software one, by
 * the same path a GPU failure already takes. Both ends change together, and
 * nothing above this restarts: the pipeline, the video track and the viewer's
 * session all carry on.
 *
 * Unlike a GPU hiccup this is not retried. The frames arrive in a shape the
 * driver has refused, and it will go on refusing it. */
static int DirectGate_Desktop_X11Enc_FallBackFromZeroCopy(directgate_x11enc_t *pEnc)
{
    xlogw("The GPU could not encode the compositor's own frames, falling back to copied ones: sid(%u)",
        pEnc->pDesktop->nSessionId);

    if (pEnc->pDesktop->pWayland != NULL)
        DirectGate_WL_SourceDisableDmaBuf((directgate_wl_source_t*)pEnc->pDesktop->pWayland);

    DirectGate_HWEnc_Destroy(pEnc->pHwEncoder);
    pEnc->pHwEncoder = NULL;
    pEnc->bZeroCopy = XFALSE;
    pEnc->nHwFailures = 0;

    /* Nothing was ever written into the frame buffers on this path, so the
     * unchanged-frame check has nothing to compare against yet - and the new
     * encoder holds no last picture to answer a keyframe from either. */
    pEnc->bHavePrev = XFALSE;
    pEnc->bSentFrame = XFALSE;

    char sError[DIRECTGATE_DESKTOP_REASON_LEN] = { 0 };
    pEnc->pHwEncoder = DirectGate_HWEnc_Create(pEnc->nEncodeWidth, pEnc->nEncodeHeight,
        &pEnc->pDesktop->quality, sError, sizeof(sError));

    if (pEnc->pHwEncoder == NULL)
    {
        xlogi("No GPU encoder after the zero-copy fallback, using the software encoder: sid(%u), reason(%s)",
            pEnc->pDesktop->nSessionId, sError[0] ? sError : "unknown");

        pEnc->pEncoder = DirectGate_OpenH264_Create(pEnc->nEncodeWidth, pEnc->nEncodeHeight,
            &pEnc->pDesktop->quality, sError, sizeof(sError));

        if (pEnc->pEncoder == NULL)
        {
            DirectGate_Desktop_X11Enc_SetError(pEnc, NULL,
                sError[0] ? sError : "No encoder left after the zero-copy fallback.");

            return XSTDERR;
        }
    }

    if (DirectGate_Desktop_X11Enc_AllocPlanes(pEnc) != XSTDOK)
    {
        DirectGate_Desktop_X11Enc_SetError(pEnc, NULL, "Failed to allocate frame planes after the zero-copy fallback.");
        return XSTDERR;
    }

    DIRECTGATE_X11ENC_SET(&pEnc->bForceKeyframe, 1U);
    return XSTDOK;
}
#endif
#endif

/* Converts the captured BGRA into whatever the active encoder wants and
 * encodes it. Returns the encoder's XSTDOK/XSTDNON/XSTDERR verdict.
 *
 * @p pDmaBuf is the exported frame on the zero-copy path, where there is no
 * BGRA to convert at all - and NULL there means "the last picture again",
 * which is how a keyframe is answered on a screen that has stopped. */
static int DirectGate_Desktop_X11Enc_Encode(directgate_x11enc_t *pEnc,
                                            const directgate_desktop_dmabuf_t *pDmaBuf,
                                            uint64_t nPtsUs,
                                            xbool_t bForceKeyframe,
                                            xbool_t *pKeyframe)
{
    uint32_t nWidth = pEnc->nEncodeWidth;
    uint32_t nHeight = pEnc->nEncodeHeight;

#if defined(DIRECTGATE_HAVE_HWENC) && defined(DIRECTGATE_DESKTOP_HAS_WAYLAND)
    if (pEnc->bZeroCopy)
    {
        int nStatus = DirectGate_HWEnc_EncodeImport(pEnc->pHwEncoder, pDmaBuf,
            nPtsUs, bForceKeyframe, &pEnc->encoded, pKeyframe);

        if (nStatus != XSTDERR)
        {
            pEnc->nHwFailures = 0;
            return nStatus;
        }

        /* A buffer layout the driver will not import fails on the very first
         * frame and on every one after it, so there is nothing to wait for:
         * fall back at once and let the session start on the copied path.
         * Once frames have been going out, though, an error is far more
         * likely to be the passing kind the GPU path already tolerates - a
         * drained surface pool, a driver busy elsewhere - and answering that
         * by giving up zero-copy for the rest of the session would cost more
         * than it saves. */
        if (pEnc->bSentFrame && ++pEnc->nHwFailures < DIRECTGATE_X11ENC_MAX_IMPORT_FAILURES)
        {
            xlogd("Zero-copy frame encode failed, retrying on the GPU: sid(%u), failures(%u)",
                pEnc->pDesktop->nSessionId, pEnc->nHwFailures);

            return XSTDNON;
        }

        if (DirectGate_Desktop_X11Enc_FallBackFromZeroCopy(pEnc) != XSTDOK) return XSTDERR;

        /* This frame is gone with the encoder that could not take it; the
         * keyframe the rebuild asked for brings the picture straight back. */
        return XSTDNON;
    }
#else
    (void)pDmaBuf;
#endif

#ifdef DIRECTGATE_HAVE_HWENC
    if (pEnc->pHwEncoder != NULL)
    {
        DirectGate_YUV_BGRAToNV12(pEnc->pNV12, pEnc->pNV12 + (size_t)nWidth * nHeight,
            pEnc->pFrameBGRA, nWidth, nHeight);

        int nStatus = DirectGate_HWEnc_Encode(pEnc->pHwEncoder, pEnc->pNV12,
            nPtsUs, bForceKeyframe, &pEnc->encoded, pKeyframe);

        if (nStatus != XSTDERR)
        {
            pEnc->nHwFailures = 0;
            return nStatus;
        }

        /* A GPU encoder hiccups for reasons that pass: the surface pool is
         * momentarily drained, the driver is busy, a compositor grabbed the
         * encode engine. Abandoning the GPU on the first error would drop
         * the whole session onto the software encoder - visibly worse, and
         * latched until the pipeline is rebuilt - so only a sustained
         * failure counts. Skipping the frame is safe: nothing reached the
         * encoder, so its reference chain is intact. */
        if (++pEnc->nHwFailures < DIRECTGATE_X11ENC_MAX_HW_FAILURES)
        {
            xlogd("GPU frame encode failed, retrying on the GPU: sid(%u), failures(%u)",
                pEnc->pDesktop->nSessionId, pEnc->nHwFailures);

            return XSTDNON;
        }

        /* Retry this frame on the CPU so the fallback costs no visible gap. */
        if (DirectGate_Desktop_X11Enc_FallBackToSoftware(pEnc) != XSTDOK) return XSTDERR;
        bForceKeyframe = XTRUE;
    }
#endif

    /* The zero-copy fallback can leave a pipeline with no encoder at all
     * when neither a replacement GPU encoder nor the software one would
     * open. Failing every frame from here is what stops the pipeline; going
     * on would convert into a buffer that was never allocated. */
    if (pEnc->pEncoder == NULL || pEnc->pI420 == NULL) return XSTDERR;

    DirectGate_YUV_BGRAToI420(pEnc->pI420,
        pEnc->pI420 + (size_t)nWidth * nHeight,
        pEnc->pI420 + (size_t)nWidth * nHeight * 5U / 4U,
        pEnc->pFrameBGRA, nWidth, nHeight);

    return DirectGate_OpenH264_Encode(pEnc->pEncoder, pEnc->pI420,
        nPtsUs, bForceKeyframe, &pEnc->encoded, pKeyframe);
}

/* One capture -> convert -> encode -> publish pass. Runs on the worker. */
static void DirectGate_Desktop_X11Enc_CaptureFrame(directgate_x11enc_t *pEnc, uint32_t nFps)
{
    XCHECK_VOID((pEnc != NULL));
    Display *pDisplay = pEnc->pDisplay;
    XImage *pImage = NULL;

#ifdef DIRECTGATE_DESKTOP_HAS_WAYLAND
    /* On Wayland the frame is pushed to us by PipeWire instead of being
     * pulled from a display server, so only this step differs. Everything
     * below - the unchanged-frame skip, the encoder, the mailbox the main
     * loop drains - is shared, which is the whole point of splitting here
     * rather than giving Wayland a pipeline of its own. */
    if (pEnc->pDesktop != NULL && pEnc->pDesktop->pWayland != NULL)
    {
        directgate_wl_source_t *pSource = (directgate_wl_source_t*)pEnc->pDesktop->pWayland;
        size_t nFrameBytes = (size_t)pEnc->nEncodeWidth * pEnc->nEncodeHeight * 4U;

#ifdef DIRECTGATE_HAVE_HWENC
        if (pEnc->bZeroCopy)
        {
            directgate_desktop_dmabuf_t dmabuf;
            void *pHandle = NULL;

            int nExported = DirectGate_WL_SourceTakeDmaBuf(pSource, &dmabuf, &pHandle);

            /* Same rule as below, and the same reason: nothing new is an
             * idle screen, and an owed keyframe is answered from the last
             * picture the GPU converted rather than skipped. */
            if (nExported != XSTDOK)
            {
                if (!DIRECTGATE_X11ENC_PEEK(&pEnc->bForceKeyframe)) return;

                DirectGate_Desktop_X11Enc_EncodeAndPublish(pEnc, nFps,
                    DirectGate_Desktop_X11Enc_MonotonicUs(), NULL);

                return;
            }

            uint64_t nExportedUs = DirectGate_Desktop_X11Enc_MonotonicUs();
            DirectGate_Desktop_X11Enc_EncodeAndPublish(pEnc, nFps, nExportedUs, &dmabuf);

            /* Only now. The compositor is free to draw into this buffer the
             * moment it is back, and the encode above is what the GPU had to
             * finish reading it for. */
            DirectGate_WL_SourceReleaseFrame(pSource, pHandle);
            return;
        }
#endif

        int nTaken = DirectGate_WL_SourceTakeFrame(pSource, &pEnc->pFrameBGRA,
            nFrameBytes, pEnc->nEncodeWidth, pEnc->nEncodeHeight);

        /* No new frame is the idle desktop, not a failure: the compositor
         * sends nothing while nothing changes. A pending keyframe request
         * still has to go out - a viewer who joins a screen that is standing
         * still would otherwise wait for it to move - and the only picture
         * there is to answer it with is the last one that went out. The
         * frame buffer itself does not hold it: the publish below exchanges
         * that buffer for the previous one, so what it holds now is a frame
         * older still, or nothing at all when none has been sent yet. */
        if (nTaken != XSTDOK)
        {
            if (!DIRECTGATE_X11ENC_PEEK(&pEnc->bForceKeyframe) || !pEnc->bHavePrev) return;
            memcpy(pEnc->pFrameBGRA, pEnc->pPrevBGRA, nFrameBytes);
        }

        uint64_t nWlCapturedUs = DirectGate_Desktop_X11Enc_MonotonicUs();
        DirectGate_Desktop_X11Enc_EncodeAndPublish(pEnc, nFps, nWlCapturedUs, NULL);
        return;
    }
#endif

    if (pEnc->pShmImage != NULL)
    {
        if (XShmGetImage(pDisplay, DefaultRootWindow(pDisplay), pEnc->pShmImage,
            pEnc->nCaptureX, pEnc->nCaptureY, AllPlanes)) pImage = pEnc->pShmImage;
    }
    else
    {
        pImage = XGetImage(pDisplay, DefaultRootWindow(pDisplay),
            pEnc->nCaptureX, pEnc->nCaptureY,
            pEnc->nCaptureWidth, pEnc->nCaptureHeight, AllPlanes, ZPixmap);
    }

    if (pImage == NULL)
    {
        uint32_t nFailures = __atomic_add_fetch(&pEnc->nFailures, 1U, __ATOMIC_ACQ_REL);
        xlogw("Failed to capture X11 frame: sid(%u), failures(%u)", pEnc->pDesktop->nSessionId, nFailures);

        return;
    }

    uint64_t nCapturedUs = DirectGate_Desktop_X11Enc_MonotonicUs();

    /* Normalize into BGRA, scaling to the encode size when needed. */
    if (pEnc->pCaptureBGRA != NULL)
    {
        DirectGate_Desktop_X11Enc_Normalize(pEnc, pImage, pEnc->pCaptureBGRA);
        DirectGate_YUV_ScaleBGRA(pEnc->pFrameBGRA, pEnc->nEncodeWidth, pEnc->nEncodeHeight,
            pEnc->pCaptureBGRA, pEnc->nCaptureWidth, pEnc->nCaptureHeight,
            (size_t)pEnc->nCaptureWidth * 4U);
    }
    else
    {
        DirectGate_Desktop_X11Enc_Normalize(pEnc, pImage, pEnc->pFrameBGRA);
    }

    if (pImage != pEnc->pShmImage) XDestroyImage(pImage);

    DirectGate_Desktop_X11Enc_EncodeAndPublish(pEnc, nFps, nCapturedUs, NULL);
}

/* Everything a captured frame goes through once it is BGRA at the encode
 * size, regardless of where it came from. Runs on the worker. */
static void DirectGate_Desktop_X11Enc_EncodeAndPublish(directgate_x11enc_t *pEnc,
                                                      uint32_t nFps, uint64_t nCapturedUs,
                                                      const directgate_desktop_dmabuf_t *pDmaBuf)
{
    /* Idle desktops are the common case for a remote-admin agent: skip the
     * whole convert+encode+send pass when nothing changed on screen. A
     * pending keyframe request always goes through (new viewer / PLI). */
    size_t nFrameBytes = (size_t)pEnc->nEncodeWidth * pEnc->nEncodeHeight * 4U;

    /* On the zero-copy path there is no copy of the picture in this process
     * to compare, and no need for one: the compositor sends a frame only when
     * something changed, which is the question this check exists to answer. */
    xbool_t bCompare = XTRUE;

#if defined(DIRECTGATE_HAVE_HWENC) && defined(DIRECTGATE_DESKTOP_HAS_WAYLAND)
    if (pEnc->bZeroCopy) bCompare = XFALSE;
#else
    (void)pDmaBuf;
#endif

    /* Claim the pending request now: any request raised from here on is a
     * new one and stays pending for the next pass. */
    xbool_t bForceKeyframe = DIRECTGATE_X11ENC_TAKE(&pEnc->bForceKeyframe) ? XTRUE : XFALSE;

    if (bCompare && !bForceKeyframe && pEnc->bHavePrev && memcmp(pEnc->pFrameBGRA, pEnc->pPrevBGRA, nFrameBytes) == 0)
    {
        /* Nothing changed. Normally that ends the pass - but not while a
         * keyframe is still settling (see nRefineLeft). */
        if (pEnc->nRefineLeft == 0) return;
        pEnc->nRefineLeft--;
    }

    uint64_t nPtsUs = nCapturedUs - pEnc->nStartUs;
    xbool_t bKeyframe = XFALSE;

    int nStatus = DirectGate_Desktop_X11Enc_Encode(pEnc, pDmaBuf, nPtsUs, bForceKeyframe, &bKeyframe);
    if (nStatus == XSTDERR)
    {
        __atomic_add_fetch(&pEnc->nFailures, 1U, __ATOMIC_ACQ_REL);
        DirectGate_Desktop_X11Enc_SetError(pEnc, NULL, "OpenH264 frame encoding failed.");

        if (bForceKeyframe) DIRECTGATE_X11ENC_SET(&pEnc->bForceKeyframe, 1U);
        return;
    }

    DIRECTGATE_X11ENC_SET(&pEnc->nFailures, 0U);

    if (nStatus == XSTDNON)
    {
        /* Rate controller skipped the frame: the request was not answered. */
        if (bForceKeyframe) DIRECTGATE_X11ENC_SET(&pEnc->bForceKeyframe, 1U);
        return;
    }

    /* Keep asking until the encoder actually emits an IDR. */
    if (bForceKeyframe && !bKeyframe) DIRECTGATE_X11ENC_SET(&pEnc->bForceKeyframe, 1U);

    if (bKeyframe)
    {
        uint32_t nRefine = (nFps ? nFps : DIRECTGATE_DESKTOP_DEFAULT_FPS) *
            DIRECTGATE_X11ENC_REFINE_MS / 1000U;

        pEnc->nRefineLeft = nRefine ? nRefine : 1U;
    }

    /* Remember what was sent for the next unchanged-frame check. Nothing to
     * remember when the picture was never in this process's memory. */
    if (bCompare)
    {
        uint8_t *pSwap = pEnc->pPrevBGRA;
        pEnc->pPrevBGRA = pEnc->pFrameBGRA;
        pEnc->pFrameBGRA = pSwap;
        pEnc->bHavePrev = XTRUE;
    }

    /* Publish: swap the encoded scratch into the mailbox slot (no copy). */
    XSync_Lock(&pEnc->lock);
    xbyte_buffer_t swap = pEnc->mailbox;
    pEnc->mailbox = pEnc->encoded;
    pEnc->encoded = swap;
    pEnc->encoded.nUsed = 0;
    pEnc->nMailboxWidth = pEnc->nEncodeWidth;
    pEnc->nMailboxHeight = pEnc->nEncodeHeight;
    pEnc->bMailboxKeyframe = bKeyframe;
    pEnc->nMailboxPtsUs = nPtsUs;
    pEnc->nMailboxCapturedUs = DirectGate_Desktop_X11Enc_MonotonicUs();
    pEnc->bMailboxHasFrame = XTRUE;
    pEnc->bSentFrame = XTRUE;
    XSync_Unlock(&pEnc->lock);

    DirectGate_Desktop_X11Enc_WakeMainLoop(pEnc, nFps);
}

static void* DirectGate_Desktop_X11Enc_Worker(void *pArg)
{
    directgate_x11enc_t *pEnc = (directgate_x11enc_t*)pArg;
    XCHECK((pEnc != NULL), NULL);

    uint64_t nNextDueUs = DirectGate_Desktop_X11Enc_MonotonicUs();

#ifdef DIRECTGATE_DESKTOP_HAS_WAYLAND
    /* Fixed for the life of the pipeline: the source is built before the
     * pipeline starts and destroyed after it is joined. */
    xbool_t bWayland = (pEnc->pDesktop != NULL && pEnc->pDesktop->pWayland != NULL) ? XTRUE : XFALSE;
#endif

    while (!DIRECTGATE_X11ENC_LOAD(&pEnc->bStop))
    {
        /* Read the rate live: a set-preset control message changes fps
         * without rebuilding the encoder. */
        uint32_t nFps = pEnc->pDesktop->quality.nFps;
        if (!nFps) nFps = DIRECTGATE_DESKTOP_DEFAULT_FPS;
        uint64_t nIntervalUs = 1000000ULL / nFps;

        DirectGate_Desktop_X11Enc_ApplyPendingControls(pEnc);

        /* Mailbox still occupied or transport backed up: skip the capture
         * entirely. Nothing entered the encoder, so its reference chain is
         * untouched and no keyframe is needed on resume. */
        if (DirectGate_Desktop_X11Enc_MailboxBusy(pEnc) ||
            DirectGate_Desktop_ShouldSkipForBackpressure(pEnc->pSession))
        {
            DirectGate_Desktop_X11Enc_SleepUs(DIRECTGATE_X11ENC_BUSY_WAIT_US);
            continue;
        }

        uint64_t nNowUs = DirectGate_Desktop_X11Enc_MonotonicUs();
        if (nNextDueUs > nNowUs)
        {
            /* Bound the sleep by one frame period so a stop request is
             * observed promptly even on the slowest preset. */
            uint64_t nWaitUs = nNextDueUs - nNowUs;
            if (nWaitUs > nIntervalUs) nWaitUs = nIntervalUs;

            DirectGate_Desktop_X11Enc_SleepUs(nWaitUs);
            if (DIRECTGATE_X11ENC_LOAD(&pEnc->bStop)) break;
            nNowUs = DirectGate_Desktop_X11Enc_MonotonicUs();
        }

        nNextDueUs = (nNextDueUs + nIntervalUs > nNowUs) ?
            nNextDueUs + nIntervalUs : nNowUs + nIntervalUs;

#ifdef DIRECTGATE_DESKTOP_HAS_WAYLAND
        /* X11 is pulled: being due and capturing are the same instant, and
         * what comes back is the screen as it is right now. PipeWire is
         * pushed on the compositor's clock instead, so a tick that finds
         * nothing has not proved the desktop is idle - the change may land a
         * millisecond later and then wait out the whole frame period for the
         * next tick to notice it. Waiting for it here costs no extra frames,
         * because the tick that let us in has already spaced this encode a
         * full period from the last one, and it is what makes a Wayland
         * session answer a keystroke as promptly as an Xorg one.
         *
         * Skipped when a keyframe is owed and there is a picture to answer
         * it with: that request must not wait on a screen that may never
         * change again. */
        if (bWayland && !(DIRECTGATE_X11ENC_PEEK(&pEnc->bForceKeyframe) && pEnc->bSentFrame))
        {
            DirectGate_WL_SourceWaitFrame((directgate_wl_source_t*)pEnc->pDesktop->pWayland, nIntervalUs);
            if (DIRECTGATE_X11ENC_LOAD(&pEnc->bStop)) break;
        }
#endif

        DirectGate_Desktop_X11Enc_CaptureFrame(pEnc, nFps);
    }

    return NULL;
}

int DirectGate_Desktop_LinuxEncoder_Start(directgate_session_t *pSession,
                                          int32_t nX, int32_t nY,
                                          uint32_t nWidth, uint32_t nHeight)
{
    XCHECK((pSession != NULL), XSTDERR);
    directgate_desktop_t *pDesktop = &pSession->desktop;
    DirectGate_Desktop_LinuxEncoder_StopDesktop(pDesktop);

    /* A Wayland session has no display connection at all; its frames come
     * from PipeWire, so the display is only required for the X11 path. */
    xbool_t bWayland = XFALSE;

#ifdef DIRECTGATE_DESKTOP_HAS_WAYLAND
    bWayland = (pDesktop->pWayland != NULL) ? XTRUE : XFALSE;
#endif

#ifdef DIRECTGATE_DESKTOP_HAS_WAYLAND
    /* Point the capture at the screen that was picked. The monitor entries
     * carry the PipeWire node the portal granted for each one, so this is a
     * stream change and never a permission one. */
    if (bWayland)
    {
        uint32_t nPrevNode = DirectGate_WL_SourceActiveNode((directgate_wl_source_t*)pDesktop->pWayland);

        for (uint32_t i = 0; i < pDesktop->nMonitorCount; i++)
        {
            if (!xstrcmp(pDesktop->monitors[i].sId, pDesktop->sSelectedMonitor)) continue;
            if (pDesktop->monitors[i].nNativeId == 0) break;

            /* A screen that will not open leaves the session on the one that
             * works, which is right but the viewer picked the other one, so
             * being told beats watching the wrong desktop and wondering. */
            if (DirectGate_WL_SourceSelect((directgate_wl_source_t*)pDesktop->pWayland,
                (uint32_t)pDesktop->monitors[i].nNativeId) != XSTDOK)
            {
                DirectGate_Desktop_SetFallbackReason(pDesktop,
                    "That screen could not be opened; still showing the previous one.");
            }

            break;
        }

        /* The tracked pointer position is measured in the capture rectangle,
         * so on another screen it means somewhere else entirely. Restarting
         * the pipeline on the same screen leaves it alone: the pointer did
         * not move, and forgetting it would jerk a captured mouse to the
         * middle of the screen for a preset change. */
        if (DirectGate_WL_SourceActiveNode((directgate_wl_source_t*)pDesktop->pWayland) != nPrevNode)
            pDesktop->bWlPointerValid = XFALSE;
    }
#endif

    if ((pDesktop->pDisplay == NULL && !bWayland) || nWidth == 0 || nHeight == 0)
    {
        DirectGate_Desktop_X11Enc_SetError(NULL, pDesktop, "Empty desktop capture rectangle.");
        return XSTDERR;
    }

    directgate_x11enc_t *pEnc = (directgate_x11enc_t*)calloc(1, sizeof(*pEnc));
    if (pEnc == NULL)
    {
        DirectGate_Desktop_X11Enc_SetError(NULL, pDesktop, "Failed to allocate X11 encoder pipeline.");
        return XSTDERR;
    }

    XByteBuffer_Init(&pEnc->encoded, XSTDNON, XFALSE);
    XByteBuffer_Init(&pEnc->mailbox, XSTDNON, XFALSE);
    XByteBuffer_Init(&pEnc->drain, XSTDNON, XFALSE);
    XSync_Init(&pEnc->lock);

    pEnc->pSession = pSession;
    pEnc->pDesktop = pDesktop;
    pEnc->nWakeFd = -1;
    pEnc->nCaptureX = nX;
    pEnc->nCaptureY = nY;
    pEnc->nCaptureWidth = nWidth;
    pEnc->nCaptureHeight = nHeight;

    /* The worker must not share the main loop's Xlib connection: input
     * injection runs on that one from the event loop. A Wayland session has
     * no connection to open at all - its frames are pushed by PipeWire and
     * asking Xlib for one named "wayland" is exactly how this used to fail
     * after the monitor had already been picked. */
    if (!bWayland)
    {
        pEnc->pDisplay = XOpenDisplay(xstrused(pDesktop->sDisplay) ? pDesktop->sDisplay : NULL);
        if (pEnc->pDisplay == NULL)
        {
            DirectGate_Desktop_X11Enc_SetError(pEnc, pDesktop,
                "Failed to open a second X11 connection for the capture thread.");

            DirectGate_Desktop_X11Enc_Free(pEnc);
            return XSTDERR;
        }
    }

    Display *pDisplay = pEnc->pDisplay;

    DirectGate_Desktop_X11Enc_PickSize(pDesktop, nWidth, nHeight, &pEnc->nEncodeWidth, &pEnc->nEncodeHeight);

    /* The preset's bitrate assumes a ~1080p encode; streaming a much larger
     * monitor at its native size needs proportionally more to stay readable. */
    DirectGate_Desktop_ApplyBitrateForSize(pDesktop, pEnc->nEncodeWidth, pEnc->nEncodeHeight);

    /* GPU encoder first; the CPU encoder is the guaranteed fallback so a
     * host with no usable GPU keeps full desktop functionality. */
    char sError[DIRECTGATE_DESKTOP_REASON_LEN] = {0};

#ifdef DIRECTGATE_HAVE_HWENC
    char sHwError[DIRECTGATE_DESKTOP_REASON_LEN] = {0};

#ifdef DIRECTGATE_DESKTOP_HAS_WAYLAND
    /* A compositor that agreed to export its frames gets the encoder that can
     * take them as they are. That encoder also does the colour conversion and
     * the resize on the GPU, so nothing between the screen and the bitstream
     * is read, converted or copied by this process - which is the whole point
     * of asking. A refusal is not a failure of the session: the compositor is
     * told to go back to memory and the ordinary encoder opens below. */
    uint32_t nSrcFourCC = 0;
    uint64_t nSrcModifier = 0;

    if (bWayland && DirectGate_WL_SourceIsDmaBuf((directgate_wl_source_t*)pDesktop->pWayland, &nSrcFourCC, &nSrcModifier))
    {
        uint32_t nSrcWidth = 0;
        uint32_t nSrcHeight = 0;

        if (DirectGate_WL_SourceSize((directgate_wl_source_t*)pDesktop->pWayland, &nSrcWidth, &nSrcHeight))
        {
            pEnc->pHwEncoder = DirectGate_HWEnc_CreateImport(nSrcWidth, nSrcHeight,
                nSrcFourCC, nSrcModifier, pEnc->nEncodeWidth, pEnc->nEncodeHeight,
                &pDesktop->quality, sHwError, sizeof(sHwError));
        }

        if (pEnc->pHwEncoder != NULL) pEnc->bZeroCopy = XTRUE;
        else
        {
            xlogi("The exported desktop frames cannot be encoded here, asking for copied ones: sid(%u), reason(%s)",
                pSession->nSessionId, sHwError[0] ? sHwError : "unknown");

            DirectGate_WL_SourceDisableDmaBuf((directgate_wl_source_t*)pDesktop->pWayland);
            sHwError[0] = '\0';
        }
    }
#endif

    if (pEnc->pHwEncoder == NULL)
    {
        pEnc->pHwEncoder = DirectGate_HWEnc_Create(pEnc->nEncodeWidth, pEnc->nEncodeHeight,
                                                   &pDesktop->quality, sHwError, sizeof(sHwError));
        if (pEnc->pHwEncoder == NULL)
        {
            xlogi("No GPU H.264 encoder available, using the software encoder: sid(%u), reason(%s)",
                pSession->nSessionId, sHwError[0] ? sHwError : "unknown");
        }
    }
#endif

    if (DIRECTGATE_X11ENC_HAS_HW(pEnc) == XFALSE)
    {
        pEnc->pEncoder = DirectGate_OpenH264_Create(pEnc->nEncodeWidth, pEnc->nEncodeHeight,
                                                    &pDesktop->quality, sError, sizeof(sError));
        if (pEnc->pEncoder == NULL)
        {
            DirectGate_Desktop_X11Enc_SetError(pEnc, pDesktop,
                sError[0] ? sError : "OpenH264 encoder initialization failed.");

            DirectGate_Desktop_X11Enc_Free(pEnc);
            return XSTDERR;
        }
    }

    size_t nFrameBytes = (size_t)pEnc->nEncodeWidth * pEnc->nEncodeHeight * 4U;
    pEnc->pFrameBGRA = (uint8_t*)malloc(nFrameBytes);
    pEnc->pPrevBGRA = (uint8_t*)malloc(nFrameBytes);

    xbool_t bScaling = (pEnc->nEncodeWidth != nWidth || pEnc->nEncodeHeight != nHeight) ? XTRUE : XFALSE;
    if (bScaling) pEnc->pCaptureBGRA = (uint8_t*)malloc((size_t)nWidth * nHeight * 4U);

    if (pEnc->pFrameBGRA == NULL || pEnc->pPrevBGRA == NULL ||
        DirectGate_Desktop_X11Enc_AllocPlanes(pEnc) != XSTDOK ||
        (bScaling && pEnc->pCaptureBGRA == NULL))
    {
        DirectGate_Desktop_X11Enc_SetError(pEnc, pDesktop, "Failed to allocate desktop frame buffers.");
        DirectGate_Desktop_X11Enc_Free(pEnc);
        return XSTDERR;
    }

    /* Shared memory and the capture probe are both X11 notions. The Wayland
     * source has already proved itself by negotiating a format before the
     * pipeline was allowed to start, so there is nothing left to probe. */
    if (!bWayland)
    {
        if (DirectGate_Desktop_X11Enc_SetupShm(pEnc, pDisplay) == XSTDNON)
            xlogw("MIT-SHM unavailable for desktop capture, using XGetImage: sid(%u)", pSession->nSessionId);

        /* Probe one capture now so a broken setup fails at start (and
         * desktop.c falls back to raw RGBA) instead of during the loop. */
        XImage *pProbe = NULL;
        if (pEnc->pShmImage != NULL)
        {
            if (XShmGetImage(pDisplay, DefaultRootWindow(pDisplay), pEnc->pShmImage,
                pEnc->nCaptureX, pEnc->nCaptureY, AllPlanes)) pProbe = pEnc->pShmImage;
        }
        else
        {
            pProbe = XGetImage(pDisplay, DefaultRootWindow(pDisplay),
                pEnc->nCaptureX, pEnc->nCaptureY,
                pEnc->nCaptureWidth, pEnc->nCaptureHeight, AllPlanes, ZPixmap);
        }

        if (pProbe == NULL)
        {
            DirectGate_Desktop_X11Enc_SetError(pEnc, pDesktop, "X11 screen capture probe failed.");
            DirectGate_Desktop_X11Enc_Free(pEnc);
            return XSTDERR;
        }

        int nFormat = DirectGate_Desktop_X11Enc_CheckFormat(pEnc, pDesktop, pProbe);
        if (pProbe != pEnc->pShmImage) XDestroyImage(pProbe);
        if (nFormat != XSTDOK)
        {
            DirectGate_Desktop_X11Enc_Free(pEnc);
            return XSTDERR;
        }
    }

    DIRECTGATE_X11ENC_SET(&pEnc->bForceKeyframe, 1U);
    pEnc->nStartUs = DirectGate_Desktop_X11Enc_MonotonicUs();

    /* Own copy of the event loop's wake-up descriptor (see nWakeFd). The
     * pipeline still works without it - the periodic tick would just drain
     * the mailbox a fraction of a frame later - so this is not fatal. */
    int nTimerFd = DirectGate_Desktop_GetTimerFd(pDesktop);
    if (nTimerFd >= 0)
    {
        pEnc->nWakeFd = fcntl(nTimerFd, F_DUPFD_CLOEXEC, 0);
        if (pEnc->nWakeFd < 0)
        {
            xlogw("Failed to duplicate desktop timer fd, frames will wait for the periodic tick: sid(%u)",
                pSession->nSessionId);
        }
    }

    if (XThread_Create(&pEnc->thread, DirectGate_Desktop_X11Enc_Worker, pEnc, 0) != XSTDOK)
    {
        DirectGate_Desktop_X11Enc_SetError(pEnc, pDesktop, "Failed to start desktop capture thread.");
        DirectGate_Desktop_X11Enc_Free(pEnc);
        return XSTDERR;
    }

    pEnc->bThreadRunning = XTRUE;
    pDesktop->pEncoder = pEnc;

    /* The encoder field is the first thing to look at when a session feels
     * slow: "software (openh264 ...)" on a machine with a GPU means the
     * probe found nothing usable and a full core is being spent encoding. */
    const char *pEncoderName = DirectGate_OpenH264_Version();
    const char *pEncoderKind = "software";

#ifdef DIRECTGATE_HAVE_HWENC
    if (pEnc->pHwEncoder != NULL)
    {
        pEncoderName = DirectGate_HWEnc_Describe(pEnc->pHwEncoder);
        pEncoderKind = "hardware";
    }
#endif

    /* Named for the backend that produced the frames, because "X11" on a
     * Wayland session is exactly the line someone reads when they are trying
     * to work out which path a slow desktop took. */
    xlogi("%s H.264 pipeline started: sid(%u), capture(%d,%d %ux%u), encode(%ux%u), "
        "shm(%s), encoder(%s: %s), preset(%s)",
        bWayland ? "Wayland" : "X11",
        pSession->nSessionId, nX, nY, nWidth, nHeight,
        pEnc->nEncodeWidth, pEnc->nEncodeHeight,
        pEnc->bShmAttached ? "yes" : (bWayland ? "n/a" : "no"),
        pEncoderKind, pEncoderName,
        DirectGate_Desktop_PresetName(pDesktop->quality.ePreset));

    return XSTDOK;
}

void DirectGate_Desktop_LinuxEncoder_ApplyQuality(directgate_session_t *pSession)
{
    XCHECK_VOID_NL((pSession != NULL));
    directgate_desktop_t *pDesktop = &pSession->desktop;
    directgate_x11enc_t *pEnc = DirectGate_Desktop_X11Enc(pDesktop);
    XCHECK_VOID_NL((pEnc != NULL));

    uint32_t nWidth = 0U;
    uint32_t nHeight = 0U;
    DirectGate_Desktop_X11Enc_PickSize(pDesktop, pEnc->nCaptureWidth, pEnc->nCaptureHeight, &nWidth, &nHeight);

    /* A resolution change needs a full encoder + buffer rebuild; bitrate,
     * frame rate and GOP updates go through without re-initialization. */
    if (nWidth != pEnc->nEncodeWidth || nHeight != pEnc->nEncodeHeight)
    {
        int32_t nX = pEnc->nCaptureX;
        int32_t nY = pEnc->nCaptureY;
        uint32_t nCaptureWidth = pEnc->nCaptureWidth;
        uint32_t nCaptureHeight = pEnc->nCaptureHeight;

        if (DirectGate_Desktop_LinuxEncoder_Start(pSession, nX, nY, nCaptureWidth, nCaptureHeight) != XSTDOK)
        {
            xlogw("Failed to rebuild X11 H.264 pipeline for preset change: sid(%u), reason(%s)",
                pSession->nSessionId, DirectGate_Desktop_GetReason(pDesktop));
        }

        return;
    }

    /* Marshalled like the bitrate step: the worker owns the encoder. */
    DIRECTGATE_X11ENC_SET(&pEnc->bApplyQuality, 1U);
    DIRECTGATE_X11ENC_SET(&pEnc->bForceKeyframe, 1U);
}

void DirectGate_Desktop_LinuxEncoder_SetBitrate(directgate_session_t *pSession, uint32_t nBitrateKbps)
{
    XCHECK_VOID_NL((pSession != NULL));
    directgate_x11enc_t *pEnc = DirectGate_Desktop_X11Enc(&pSession->desktop);
    XCHECK_VOID_NL((pEnc != NULL && nBitrateKbps > 0));
    DIRECTGATE_X11ENC_SET(&pEnc->nPendingBitrateKbps, nBitrateKbps);
}

void DirectGate_Desktop_LinuxEncoder_RequestKeyframe(directgate_session_t *pSession)
{
    XCHECK_VOID_NL((pSession != NULL));
    directgate_x11enc_t *pEnc = DirectGate_Desktop_X11Enc(&pSession->desktop);
    XCHECK_VOID_NL((pEnc != NULL));
    DIRECTGATE_X11ENC_SET(&pEnc->bForceKeyframe, 1U);
}

const char* DirectGate_Desktop_LinuxEncoder_LastError(const directgate_session_t *pSession)
{
    if (pSession == NULL) return "no session";
    const directgate_x11enc_t *pEnc = DirectGate_Desktop_X11Enc(&pSession->desktop);
    if (pEnc != NULL && xstrused(pEnc->sLastError)) return pEnc->sLastError;
    if (xstrused(pSession->desktop.sReason)) return pSession->desktop.sReason;
    return "unknown";
}

xbool_t DirectGate_Desktop_LinuxEncoder_HasFailed(const directgate_session_t *pSession)
{
    XCHECK_NL((pSession != NULL), XFALSE);
    const directgate_x11enc_t *pEnc = DirectGate_Desktop_X11Enc(&pSession->desktop);
    if (pEnc == NULL) return XTRUE;
    return (DIRECTGATE_X11ENC_LOAD(&pEnc->nFailures) >= DIRECTGATE_X11ENC_MAX_FAILURES) ? XTRUE : XFALSE;
}

int DirectGate_Desktop_LinuxEncoder_DrainMain(directgate_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;
    directgate_x11enc_t *pEnc = DirectGate_Desktop_X11Enc(pDesktop);
    XCHECK_NL((pEnc != NULL), XAPI_CONTINUE);

    /* A preset change asks for a fresh keyframe through the desktop struct;
     * hand it to the capture thread and clear it here on the main loop. */
    if (pDesktop->bRequestKeyframe)
    {
        pDesktop->bRequestKeyframe = XFALSE;
        DIRECTGATE_X11ENC_SET(&pEnc->bForceKeyframe, 1U);
    }

    uint32_t nFps = pDesktop->quality.nFps ? pDesktop->quality.nFps : DIRECTGATE_DESKTOP_DEFAULT_FPS;
    uint64_t nNowUs = DirectGate_Desktop_X11Enc_MonotonicUs();
    uint64_t nMaxAgeUs = (1000000ULL / nFps) * 3ULL;
    if (nMaxAgeUs < DIRECTGATE_X11ENC_MIN_AGE_US) nMaxAgeUs = DIRECTGATE_X11ENC_MIN_AGE_US;

    uint32_t nWidth = 0, nHeight = 0;
    xbool_t bKeyframe = XFALSE, bHasFrame = XFALSE, bDroppedStale = XFALSE;
    uint64_t nPtsUs = 0, nDroppedAgeUs = 0;

    XSync_Lock(&pEnc->lock);
    if (pEnc->bMailboxHasFrame)
    {
        uint64_t nAgeUs = (nNowUs >= pEnc->nMailboxCapturedUs) ? nNowUs - pEnc->nMailboxCapturedUs : 0U;
        if (pEnc->nMailboxCapturedUs && nAgeUs > nMaxAgeUs)
        {
            pEnc->mailbox.nUsed = 0;
            DIRECTGATE_X11ENC_SET(&pEnc->bForceKeyframe, 1U);
            nDroppedAgeUs = nAgeUs;
            bDroppedStale = XTRUE;
        }
        else
        {
            xbyte_buffer_t swap = pEnc->drain;
            pEnc->drain = pEnc->mailbox;
            pEnc->mailbox = swap;
            pEnc->mailbox.nUsed = 0;
            nWidth = pEnc->nMailboxWidth;
            nHeight = pEnc->nMailboxHeight;
            bKeyframe = pEnc->bMailboxKeyframe;
            nPtsUs = pEnc->nMailboxPtsUs;
            bHasFrame = XTRUE;
        }

        pEnc->bMailboxHasFrame = XFALSE;
    }

    XSync_Unlock(&pEnc->lock);

    if (bDroppedStale)
    {
        xlogd("Dropping stale X11 desktop frame: sid(%u), ageUs(%llu), maxUs(%llu)",
            pSession->nSessionId, (unsigned long long)nDroppedAgeUs,
            (unsigned long long)nMaxAgeUs);
    }

    if (!bHasFrame || !pEnc->drain.nUsed) return XAPI_CONTINUE;

    return DirectGate_Desktop_SendEncodedFrame(pSession, pEnc->drain.pData,
        pEnc->drain.nUsed, nWidth, nHeight, bKeyframe, nPtsUs);
}

#endif /* __linux__ */
