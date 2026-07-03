/*!
 * @file directgate-agent/src/agent/desktop_linux.c
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
#include "yuv.h"

#include <sys/ipc.h>
#include <sys/shm.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/XShm.h>

/* Counterpart of desktop_mac.m: desktop.c drives this pipeline from the
 * main loop. Unlike ScreenCaptureKit there is no push-style capture on
 * Linux, so everything runs synchronously per timer tick:
 *
 *   timerfd tick -> XShmGetImage -> normalize/scale BGRA -> unchanged-frame
 *   check -> BGRA->I420 -> OpenH264 -> DirectGate_Desktop_SendEncodedFrame
 *
 * Keeping the pipeline on the main loop means no locking, and the existing
 * WebRTC backpressure guard naturally turns into an adaptive frame rate. */

/* Consecutive capture/encode failures before the pipeline reports itself
 * broken and desktop.c falls back to raw RGBA (~1s at 30 fps). */
#define DIRECTGATE_X11ENC_MAX_FAILURES 30U

typedef struct directgate_x11enc_ {
    directgate_openh264_t *pEncoder;

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
    uint8_t *pI420;         /* encode-size planar YUV for the encoder */
    xbool_t bHavePrev;
    xbool_t bForceKeyframe;
    uint32_t nFailures;
    uint64_t nStartUs;
    xbyte_buffer_t encoded;
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
    if (pEnc != NULL)
        xstrncpy(pEnc->sLastError, sizeof(pEnc->sLastError), pError);
    if (pDesktop != NULL)
        xstrncpy(pDesktop->sReason, sizeof(pDesktop->sReason), pError);
}

static uint64_t DirectGate_Desktop_X11Enc_MonotonicUs(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return 0;
    return (uint64_t)now.tv_sec * 1000000ULL + (uint64_t)now.tv_nsec / 1000ULL;
}

/* Same policy as DirectGateDesktopEncoder_PickEncodeDim on macOS: fit the
 * longest capture edge into the preset budget, keep dimensions even (H.264
 * requirement) and never collapse below 16 pixels. */
static uint32_t DirectGate_Desktop_X11Enc_PickDim(uint32_t nValue, uint32_t nMaxEdge,
                                              uint32_t nSrcW, uint32_t nSrcH)
{
    uint32_t nEdge = nSrcW > nSrcH ? nSrcW : nSrcH;
    uint32_t nResult = nValue;

    if (nEdge > 0 && nMaxEdge > 0 && nEdge > nMaxEdge)
        nResult = (uint32_t)(((uint64_t)nValue * nMaxEdge) / nEdge);

    nResult &= ~1U;
    if (nResult < 16U) nResult = 16U;
    return nResult;
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
            memcpy(pDst + (size_t)y * nDstStride,
                (const uint8_t*)pImage->data + (size_t)y * nSrcStride, nDstStride);
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

static void DirectGate_Desktop_X11Enc_TeardownShm(directgate_x11enc_t *pEnc, Display *pDisplay)
{
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

static void DirectGate_Desktop_X11Enc_Free(directgate_x11enc_t *pEnc, Display *pDisplay)
{
    XCHECK_VOID_NL((pEnc != NULL));

    DirectGate_Desktop_X11Enc_TeardownShm(pEnc, pDisplay);
    DirectGate_OpenH264_Destroy(pEnc->pEncoder);
    XByteBuffer_Clear(&pEnc->encoded);

    free(pEnc->pCaptureBGRA);
    free(pEnc->pFrameBGRA);
    free(pEnc->pPrevBGRA);
    free(pEnc->pI420);
    free(pEnc);
}

void DirectGate_Desktop_LinuxEncoder_StopDesktop(directgate_desktop_t *pDesktop)
{
    XCHECK_VOID_NL((pDesktop != NULL));
    directgate_x11enc_t *pEnc = DirectGate_Desktop_X11Enc(pDesktop);
    if (pEnc == NULL) return;

    pDesktop->pEncoder = NULL;
    DirectGate_Desktop_X11Enc_Free(pEnc, (Display*)pDesktop->pDisplay);
}

void DirectGate_Desktop_LinuxEncoder_Stop(directgate_session_t *pSession)
{
    XCHECK_VOID_NL((pSession != NULL));
    DirectGate_Desktop_LinuxEncoder_StopDesktop(&pSession->desktop);
}

int DirectGate_Desktop_LinuxEncoder_Start(directgate_session_t *pSession,
                                      int32_t nX, int32_t nY,
                                      uint32_t nWidth, uint32_t nHeight)
{
    XCHECK((pSession != NULL), XSTDERR);
    directgate_desktop_t *pDesktop = &pSession->desktop;
    Display *pDisplay = (Display*)pDesktop->pDisplay;

    DirectGate_Desktop_LinuxEncoder_StopDesktop(pDesktop);

    if (pDisplay == NULL || nWidth == 0 || nHeight == 0)
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
    pEnc->nCaptureX = nX;
    pEnc->nCaptureY = nY;
    pEnc->nCaptureWidth = nWidth;
    pEnc->nCaptureHeight = nHeight;

    uint32_t nMaxEdge = pDesktop->quality.nMaxEdge ? pDesktop->quality.nMaxEdge : 1920U;
    pEnc->nEncodeWidth = DirectGate_Desktop_X11Enc_PickDim(nWidth, nMaxEdge, nWidth, nHeight);
    pEnc->nEncodeHeight = DirectGate_Desktop_X11Enc_PickDim(nHeight, nMaxEdge, nWidth, nHeight);

    char sError[DIRECTGATE_DESKTOP_REASON_LEN] = {0};
    pEnc->pEncoder = DirectGate_OpenH264_Create(pEnc->nEncodeWidth, pEnc->nEncodeHeight,
        &pDesktop->quality, sError, sizeof(sError));
    if (pEnc->pEncoder == NULL)
    {
        DirectGate_Desktop_X11Enc_SetError(pEnc, pDesktop,
            sError[0] ? sError : "OpenH264 encoder initialization failed.");
        DirectGate_Desktop_X11Enc_Free(pEnc, pDisplay);
        return XSTDERR;
    }

    size_t nFrameBytes = (size_t)pEnc->nEncodeWidth * pEnc->nEncodeHeight * 4U;
    pEnc->pFrameBGRA = (uint8_t*)malloc(nFrameBytes);
    pEnc->pPrevBGRA = (uint8_t*)malloc(nFrameBytes);
    pEnc->pI420 = (uint8_t*)malloc((size_t)pEnc->nEncodeWidth * pEnc->nEncodeHeight * 3U / 2U);

    xbool_t bScaling = (pEnc->nEncodeWidth != nWidth || pEnc->nEncodeHeight != nHeight) ?
        XTRUE : XFALSE;
    if (bScaling)
        pEnc->pCaptureBGRA = (uint8_t*)malloc((size_t)nWidth * nHeight * 4U);

    if (pEnc->pFrameBGRA == NULL || pEnc->pPrevBGRA == NULL || pEnc->pI420 == NULL ||
        (bScaling && pEnc->pCaptureBGRA == NULL))
    {
        DirectGate_Desktop_X11Enc_SetError(pEnc, pDesktop, "Failed to allocate desktop frame buffers.");
        DirectGate_Desktop_X11Enc_Free(pEnc, pDisplay);
        return XSTDERR;
    }

    if (DirectGate_Desktop_X11Enc_SetupShm(pEnc, pDisplay) == XSTDNON)
        xlogw("MIT-SHM unavailable for desktop capture, using XGetImage: sid(%u)",
            pSession->nSessionId);

    /* Probe one capture now so a broken setup fails at start (and desktop.c
     * falls back to raw RGBA) instead of during the streaming loop. */
    XImage *pProbe = NULL;
    if (pEnc->pShmImage != NULL)
    {
        if (XShmGetImage(pDisplay, DefaultRootWindow(pDisplay), pEnc->pShmImage,
            pEnc->nCaptureX, pEnc->nCaptureY, AllPlanes))
            pProbe = pEnc->pShmImage;
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
        DirectGate_Desktop_X11Enc_Free(pEnc, pDisplay);
        return XSTDERR;
    }

    int nFormat = DirectGate_Desktop_X11Enc_CheckFormat(pEnc, pDesktop, pProbe);
    if (pProbe != pEnc->pShmImage) XDestroyImage(pProbe);
    if (nFormat != XSTDOK)
    {
        DirectGate_Desktop_X11Enc_Free(pEnc, pDisplay);
        return XSTDERR;
    }

    pEnc->bForceKeyframe = XTRUE;
    pEnc->nStartUs = DirectGate_Desktop_X11Enc_MonotonicUs();
    pDesktop->pEncoder = pEnc;

    xlogi("X11 H.264 pipeline started: sid(%u), capture(%d,%d %ux%u), encode(%ux%u), "
        "shm(%s), codec(%s), preset(%s)",
        pSession->nSessionId, nX, nY, nWidth, nHeight,
        pEnc->nEncodeWidth, pEnc->nEncodeHeight,
        pEnc->bShmAttached ? "yes" : "no",
        DirectGate_OpenH264_Version(),
        DirectGate_Desktop_PresetName(pDesktop->quality.ePreset));

    return XSTDOK;
}

void DirectGate_Desktop_LinuxEncoder_ApplyQuality(directgate_session_t *pSession)
{
    XCHECK_VOID_NL((pSession != NULL));
    directgate_desktop_t *pDesktop = &pSession->desktop;
    directgate_x11enc_t *pEnc = DirectGate_Desktop_X11Enc(pDesktop);
    XCHECK_VOID_NL((pEnc != NULL));

    uint32_t nMaxEdge = pDesktop->quality.nMaxEdge ? pDesktop->quality.nMaxEdge : 1920U;
    uint32_t nWidth = DirectGate_Desktop_X11Enc_PickDim(pEnc->nCaptureWidth, nMaxEdge,
        pEnc->nCaptureWidth, pEnc->nCaptureHeight);
    uint32_t nHeight = DirectGate_Desktop_X11Enc_PickDim(pEnc->nCaptureHeight, nMaxEdge,
        pEnc->nCaptureWidth, pEnc->nCaptureHeight);

    /* A resolution change needs a full encoder + buffer rebuild; bitrate,
     * frame rate and GOP updates go through without re-initialization. */
    if (nWidth != pEnc->nEncodeWidth || nHeight != pEnc->nEncodeHeight)
    {
        int32_t nX = pEnc->nCaptureX;
        int32_t nY = pEnc->nCaptureY;
        uint32_t nCaptureWidth = pEnc->nCaptureWidth;
        uint32_t nCaptureHeight = pEnc->nCaptureHeight;

        if (DirectGate_Desktop_LinuxEncoder_Start(pSession, nX, nY,
            nCaptureWidth, nCaptureHeight) != XSTDOK)
        {
            xlogw("Failed to rebuild X11 H.264 pipeline for preset change: sid(%u), reason(%s)",
                pSession->nSessionId, DirectGate_Desktop_GetReason(pDesktop));
        }

        return;
    }

    DirectGate_OpenH264_ApplyQuality(pEnc->pEncoder, &pDesktop->quality);
    pEnc->bForceKeyframe = XTRUE;
}

void DirectGate_Desktop_LinuxEncoder_RequestKeyframe(directgate_session_t *pSession)
{
    XCHECK_VOID_NL((pSession != NULL));
    directgate_x11enc_t *pEnc = DirectGate_Desktop_X11Enc(&pSession->desktop);
    XCHECK_VOID_NL((pEnc != NULL));
    pEnc->bForceKeyframe = XTRUE;
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
    return (pEnc->nFailures >= DIRECTGATE_X11ENC_MAX_FAILURES) ? XTRUE : XFALSE;
}

int DirectGate_Desktop_LinuxEncoder_ProcessTick(directgate_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;
    directgate_x11enc_t *pEnc = DirectGate_Desktop_X11Enc(pDesktop);
    Display *pDisplay = (Display*)pDesktop->pDisplay;
    XCHECK_NL((pEnc != NULL && pDisplay != NULL), XAPI_CONTINUE);

    /* Transport backpressure: skipping the whole capture keeps the encoder
     * reference chain untouched, so no keyframe is needed on resume (same
     * reasoning as the macOS SCK callback). */
    if (DirectGate_Desktop_ShouldSkipForBackpressure(pSession))
        return XAPI_CONTINUE;

    XImage *pImage = NULL;
    if (pEnc->pShmImage != NULL)
    {
        if (XShmGetImage(pDisplay, DefaultRootWindow(pDisplay), pEnc->pShmImage,
            pEnc->nCaptureX, pEnc->nCaptureY, AllPlanes))
            pImage = pEnc->pShmImage;
    }
    else
    {
        pImage = XGetImage(pDisplay, DefaultRootWindow(pDisplay),
            pEnc->nCaptureX, pEnc->nCaptureY,
            pEnc->nCaptureWidth, pEnc->nCaptureHeight, AllPlanes, ZPixmap);
    }

    if (pImage == NULL)
    {
        pEnc->nFailures++;
        xlogw("Failed to capture X11 frame: sid(%u), failures(%u)",
            pSession->nSessionId, pEnc->nFailures);
        return XAPI_CONTINUE;
    }

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
    xbool_t bForceKeyframe = (pEnc->bForceKeyframe || pDesktop->bRequestKeyframe) ? XTRUE : XFALSE;

    if (!bForceKeyframe && pEnc->bHavePrev &&
        memcmp(pEnc->pFrameBGRA, pEnc->pPrevBGRA, nFrameBytes) == 0)
        return XAPI_CONTINUE;

    DirectGate_YUV_BGRAToI420(pEnc->pI420,
        pEnc->pI420 + (size_t)pEnc->nEncodeWidth * pEnc->nEncodeHeight,
        pEnc->pI420 + (size_t)pEnc->nEncodeWidth * pEnc->nEncodeHeight * 5U / 4U,
        pEnc->pFrameBGRA, pEnc->nEncodeWidth, pEnc->nEncodeHeight);

    uint64_t nPtsUs = DirectGate_Desktop_X11Enc_MonotonicUs() - pEnc->nStartUs;
    xbool_t bKeyframe = XFALSE;

    int nStatus = DirectGate_OpenH264_Encode(pEnc->pEncoder, pEnc->pI420,
        nPtsUs, bForceKeyframe, &pEnc->encoded, &bKeyframe);

    if (nStatus == XSTDERR)
    {
        pEnc->nFailures++;
        DirectGate_Desktop_X11Enc_SetError(pEnc, NULL, "OpenH264 frame encoding failed.");
        return XAPI_CONTINUE;
    }

    pEnc->nFailures = 0;
    if (nStatus == XSTDNON) return XAPI_CONTINUE; /* rate controller skip */

    pEnc->bForceKeyframe = XFALSE;
    pDesktop->bRequestKeyframe = XFALSE;

    /* Remember what was sent for the next unchanged-frame check. */
    uint8_t *pSwap = pEnc->pPrevBGRA;
    pEnc->pPrevBGRA = pEnc->pFrameBGRA;
    pEnc->pFrameBGRA = pSwap;
    pEnc->bHavePrev = XTRUE;

    return DirectGate_Desktop_SendEncodedFrame(pSession, pEnc->encoded.pData,
        pEnc->encoded.nUsed, pEnc->nEncodeWidth, pEnc->nEncodeHeight,
        bKeyframe, nPtsUs);
}

#endif /* __linux__ */
