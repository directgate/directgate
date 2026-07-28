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

/* Poll interval while the mailbox is still occupied or the data channel is
 * backed up. Linux nanosleep honours this granularity, so it costs at most
 * half a millisecond of extra latency on a busy hand-off. */
#define DIRECTGATE_X11ENC_BUSY_WAIT_US 500ULL

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
    /* OpenH264 takes planar I420, every GPU encoder takes NV12; only the
     * plane buffer for the active encoder is allocated. */
    uint8_t *pI420;
    uint8_t *pNV12;
    xbool_t bHavePrev;
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
#endif

/* Converts the captured BGRA into whatever the active encoder wants and
 * encodes it. Returns the encoder's XSTDOK/XSTDNON/XSTDERR verdict. */
static int DirectGate_Desktop_X11Enc_Encode(directgate_x11enc_t *pEnc,
                                            uint64_t nPtsUs,
                                            xbool_t bForceKeyframe,
                                            xbool_t *pKeyframe)
{
    uint32_t nWidth = pEnc->nEncodeWidth;
    uint32_t nHeight = pEnc->nEncodeHeight;

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
    Display *pDisplay = pEnc->pDisplay;
    XImage *pImage = NULL;

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

    /* Idle desktops are the common case for a remote-admin agent: skip the
     * whole convert+encode+send pass when nothing changed on screen. A
     * pending keyframe request always goes through (new viewer / PLI). */
    size_t nFrameBytes = (size_t)pEnc->nEncodeWidth * pEnc->nEncodeHeight * 4U;

    /* Claim the pending request now: any request raised from here on is a
     * new one and stays pending for the next pass. */
    xbool_t bForceKeyframe = DIRECTGATE_X11ENC_TAKE(&pEnc->bForceKeyframe) ? XTRUE : XFALSE;

    if (!bForceKeyframe && pEnc->bHavePrev &&
        memcmp(pEnc->pFrameBGRA, pEnc->pPrevBGRA, nFrameBytes) == 0) return;

    uint64_t nPtsUs = nCapturedUs - pEnc->nStartUs;
    xbool_t bKeyframe = XFALSE;

    int nStatus = DirectGate_Desktop_X11Enc_Encode(pEnc, nPtsUs, bForceKeyframe, &bKeyframe);

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

    /* Remember what was sent for the next unchanged-frame check. */
    uint8_t *pSwap = pEnc->pPrevBGRA;
    pEnc->pPrevBGRA = pEnc->pFrameBGRA;
    pEnc->pFrameBGRA = pSwap;
    pEnc->bHavePrev = XTRUE;

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
    XSync_Unlock(&pEnc->lock);

    DirectGate_Desktop_X11Enc_WakeMainLoop(pEnc, nFps);
}

static void* DirectGate_Desktop_X11Enc_Worker(void *pArg)
{
    directgate_x11enc_t *pEnc = (directgate_x11enc_t*)pArg;
    XCHECK((pEnc != NULL), NULL);

    uint64_t nNextDueUs = DirectGate_Desktop_X11Enc_MonotonicUs();

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

    if (pDesktop->pDisplay == NULL || nWidth == 0 || nHeight == 0)
    {
        DirectGate_Desktop_X11Enc_SetError(NULL, pDesktop, "Empty X11 capture rectangle.");
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
     * injection runs on that one from the event loop. */
    pEnc->pDisplay = XOpenDisplay(xstrused(pDesktop->sDisplay) ? pDesktop->sDisplay : NULL);
    if (pEnc->pDisplay == NULL)
    {
        DirectGate_Desktop_X11Enc_SetError(pEnc, pDesktop,
            "Failed to open a second X11 connection for the capture thread.");

        DirectGate_Desktop_X11Enc_Free(pEnc);
        return XSTDERR;
    }

    Display *pDisplay = pEnc->pDisplay;

    DirectGate_Desktop_X11Enc_PickSize(pDesktop, nWidth, nHeight, &pEnc->nEncodeWidth, &pEnc->nEncodeHeight);

    /* GPU encoder first; the CPU encoder is the guaranteed fallback so a
     * host with no usable GPU keeps full desktop functionality. */
    char sError[DIRECTGATE_DESKTOP_REASON_LEN] = {0};

#ifdef DIRECTGATE_HAVE_HWENC
    char sHwError[DIRECTGATE_DESKTOP_REASON_LEN] = {0};
    pEnc->pHwEncoder = DirectGate_HWEnc_Create(pEnc->nEncodeWidth, pEnc->nEncodeHeight,
                                               &pDesktop->quality, sHwError, sizeof(sHwError));
    if (pEnc->pHwEncoder == NULL)
    {
        xlogi("No GPU H.264 encoder available, using the software encoder: sid(%u), reason(%s)",
            pSession->nSessionId, sHwError[0] ? sHwError : "unknown");
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

    if (DirectGate_Desktop_X11Enc_SetupShm(pEnc, pDisplay) == XSTDNON)
        xlogw("MIT-SHM unavailable for desktop capture, using XGetImage: sid(%u)", pSession->nSessionId);

    /* Probe one capture now so a broken setup fails at start (and desktop.c
     * falls back to raw RGBA) instead of during the streaming loop. */
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

    xlogi("X11 H.264 pipeline started: sid(%u), capture(%d,%d %ux%u), encode(%ux%u), "
        "shm(%s), encoder(%s: %s), preset(%s)",
        pSession->nSessionId, nX, nY, nWidth, nHeight,
        pEnc->nEncodeWidth, pEnc->nEncodeHeight,
        pEnc->bShmAttached ? "yes" : "no",
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
