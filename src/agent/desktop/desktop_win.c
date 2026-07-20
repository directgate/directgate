/*!
 * @file directgate-agent/src/agent/desktop/desktop_win.c
 * @brief Windows DXGI Desktop Duplication capture + Media Foundation H.264 encoder.
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

#if defined(_WIN32)

#define COBJMACROS

#include "desktop.h"
#include "session.h"
#include "mfenc.h"
#include "yuv.h"

#include <d3d11.h>
#include <dxgi1_2.h>

/* Counterpart of desktop_mac.m: a push-model pipeline on a dedicated
 * capture thread (the main loop must not block in AcquireNextFrame or the
 * hardware encoder), publishing into a single-slot mailbox:
 *
 *   capture thread: AcquireNextFrame -> staging copy -> scale BGRA ->
 *   BGRA->NV12 -> Media Foundation H.264 -> mailbox -> wake byte on the
 *   timer socket pair
 *
 *   main loop: DirectGate_Desktop_Process -> WinEncoder_DrainMain ->
 *   DirectGate_Desktop_SendEncodedFrame
 *
 * Desktop Duplication only wakes the thread when pixels actually changed,
 * so idle desktops cost nothing (the Linux pipeline needs a memcmp for
 * that). When duplication is unavailable - "all displays" spanning
 * several monitors, rotated outputs, RDP sessions, another duplication
 * client - the thread falls back to paced GDI BitBlt capture with the
 * same encoder behind it. */

/* Consecutive capture/encode failure duration before the pipeline reports
 * itself broken. Longer than the Linux threshold on purpose: a UAC
 * secure-desktop prompt legitimately blocks duplication for a few seconds
 * and must not permanently demote the session to raw RGBA. */
#define DIRECTGATE_WINENC_FAILURE_SECONDS  5U

/* DuplicateOutput re-init duration before flipping to GDI. */
#define DIRECTGATE_WINENC_REINIT_SECONDS   3U

/* How long DirectGate_Desktop_WinEncoder_Start waits for the capture thread
 * to bring the pipeline up. First-ever MFT activation can spin up GPU
 * driver components, so this is generous. */
#define DIRECTGATE_WINENC_INIT_WAIT_MS     10000U

typedef struct directgate_winenc_ {
    directgate_session_t *pSession;   /* backpressure checks only (thread-safe) */
    directgate_desktop_t *pDesktop;

    int32_t nCaptureX;
    int32_t nCaptureY;
    uint32_t nCaptureWidth;
    uint32_t nCaptureHeight;
    uint32_t nEncodeWidth;
    uint32_t nEncodeHeight;
    uint32_t nFps;

    /* Thread control. The main thread only touches the volatile flags and
     * the mailbox; everything else below is owned by the capture thread. */
    HANDLE hThread;
    HANDLE hInitDone;
    volatile LONG bRunning;
    volatile LONG bForceKeyframe;
    volatile LONG nPendingBitrateKbps;  /* 0 = no pending step */
    volatile LONG bApplyQuality;
    volatile LONG nFailures;
    xbool_t bInitOk;

    /* DXGI Desktop Duplication chain (NULL while the GDI path is active). */
    ID3D11Device *pDevice;
    ID3D11DeviceContext *pContext;
    IDXGIOutput1 *pOutput;              /* kept for ACCESS_LOST re-init */
    IDXGIOutputDuplication *pDuplication;
    ID3D11Texture2D *pStaging;
    uint32_t nDxgiReinitFails;
    xbool_t bUseGdi;

    /* GDI BitBlt fallback capture. */
    HDC hScreenDC;
    HDC hMemDC;
    HBITMAP hDib;
    HGDIOBJ hOldBitmap;
    uint8_t *pDibBits;                  /* owned by hDib */

    /* CPU frame pipeline. */
    uint8_t *pFrameBGRA;                /* encode-size BGRA */
    uint8_t *pPrevBGRA;                 /* GDI unchanged-frame detection */
    uint8_t *pNV12;
    xbool_t bHavePrev;
    xbool_t bHaveFrame;                 /* pFrameBGRA holds a valid image */
    uint64_t nFrameCapturedUs;          /* absolute QPC time of freshest pixels */

    directgate_mfenc_t *pEncoder;
    xbyte_buffer_t encoded;             /* encoder output scratch */

    /* Single-slot mailbox: capture thread (producer) -> main loop
     * (consumer). Buffers are swapped under the lock, never copied. */
    SRWLOCK mailboxLock;
    xbyte_buffer_t mailbox;
    xbyte_buffer_t drain;
    uint32_t nMailboxWidth;
    uint32_t nMailboxHeight;
    xbool_t bMailboxKeyframe;
    uint64_t nMailboxPtsUs;
    uint64_t nMailboxCapturedUs;
    xbool_t bMailboxHasFrame;

    uint64_t nQpcFrequency;
    uint64_t nStartUs;
    HANDLE hWaitTimer;                  /* high-resolution pacing timer */
    char sLastError[DIRECTGATE_DESKTOP_REASON_LEN];
} directgate_winenc_t;

static directgate_winenc_t* DirectGate_Desktop_WinEnc(const directgate_desktop_t *pDesktop)
{
    XCHECK_NL((pDesktop != NULL), NULL);
    return (directgate_winenc_t*)pDesktop->pEncoder;
}

static void DirectGate_Desktop_WinEnc_SetError(directgate_winenc_t *pEnc, const char *pError)
{
    XCHECK_VOID_NL((pEnc != NULL && xstrused(pError)));
    xstrncpy(pEnc->sLastError, sizeof(pEnc->sLastError), pError);
}

static uint64_t DirectGate_Desktop_WinEnc_MonotonicUs(const directgate_winenc_t *pEnc)
{
    LARGE_INTEGER counter;
    if (!pEnc->nQpcFrequency || !QueryPerformanceCounter(&counter)) return 0;
    return (uint64_t)counter.QuadPart * 1000000ULL / pEnc->nQpcFrequency;
}

/* Same policy as the Linux/macOS pipelines: fit the longest capture edge
 * into the preset budget, keep dimensions even (H.264 requirement) and
 * never collapse below 16 pixels. */
static void DirectGate_Desktop_WinEnc_PickSize(const directgate_desktop_t *pDesktop,
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

static void DirectGate_Desktop_WinEnc_SleepUs(directgate_winenc_t *pEnc, uint64_t nUs)
{
    if (!nUs) return;

    if (pEnc->hWaitTimer != NULL)
    {
        LARGE_INTEGER due;
        due.QuadPart = -(LONGLONG)(nUs * 10ULL); /* relative, 100 ns units */
        if (SetWaitableTimer(pEnc->hWaitTimer, &due, 0, NULL, NULL, FALSE))
        {
            WaitForSingleObject(pEnc->hWaitTimer, (DWORD)(nUs / 1000ULL) + 20U);
            return;
        }
    }

    Sleep((DWORD)(nUs / 1000ULL) + 1U);
}

static void DirectGate_Desktop_WinEnc_ReleaseDuplication(directgate_winenc_t *pEnc)
{
    if (pEnc->pStaging != NULL)
    {
        ID3D11Texture2D_Release(pEnc->pStaging);
        pEnc->pStaging = NULL;
    }

    if (pEnc->pDuplication != NULL)
    {
        IDXGIOutputDuplication_Release(pEnc->pDuplication);
        pEnc->pDuplication = NULL;
    }
}

static void DirectGate_Desktop_WinEnc_ReleaseDxgi(directgate_winenc_t *pEnc)
{
    DirectGate_Desktop_WinEnc_ReleaseDuplication(pEnc);

    if (pEnc->pOutput != NULL)
    {
        IDXGIOutput1_Release(pEnc->pOutput);
        pEnc->pOutput = NULL;
    }

    if (pEnc->pContext != NULL)
    {
        ID3D11DeviceContext_Release(pEnc->pContext);
        pEnc->pContext = NULL;
    }

    if (pEnc->pDevice != NULL)
    {
        ID3D11Device_Release(pEnc->pDevice);
        pEnc->pDevice = NULL;
    }
}

/* Desktop switches (UAC prompt, lock screen, fast user switching) drop the
 * duplication with ACCESS_LOST; re-duplication only succeeds once this
 * thread is attached to the current input desktop. Best-effort. */
static void DirectGate_Desktop_WinEnc_AttachInputDesktop(void)
{
    HDESK hDesktop = OpenInputDesktop(0, FALSE, GENERIC_ALL);
    if (hDesktop == NULL) return;

    SetThreadDesktop(hDesktop);
    CloseDesktop(hDesktop);
}

static int DirectGate_Desktop_WinEnc_Duplicate(directgate_winenc_t *pEnc)
{
    DirectGate_Desktop_WinEnc_ReleaseDuplication(pEnc);
    XCHECK_NL((pEnc->pOutput != NULL && pEnc->pDevice != NULL), XSTDERR);

    HRESULT hr = IDXGIOutput1_DuplicateOutput(pEnc->pOutput,
        (IUnknown*)pEnc->pDevice, &pEnc->pDuplication);
    if (FAILED(hr) || pEnc->pDuplication == NULL)
    {
        pEnc->pDuplication = NULL;
        return XSTDERR;
    }

    DXGI_OUTDUPL_DESC desc;
    memset(&desc, 0, sizeof(desc));
    IDXGIOutputDuplication_GetDesc(pEnc->pDuplication, &desc);
    if (desc.Rotation != DXGI_MODE_ROTATION_IDENTITY &&
        desc.Rotation != DXGI_MODE_ROTATION_UNSPECIFIED)
    {
        /* Rotated outputs would need a GPU or CPU rotation pass; the GDI
         * path returns correctly oriented pixels instead. */
        DirectGate_Desktop_WinEnc_ReleaseDuplication(pEnc);
        return XSTDERR;
    }

    return XSTDOK;
}

/* Brings up D3D11 + IDXGIOutputDuplication for the output whose desktop
 * rectangle exactly matches the capture rectangle. XSTDNON means "use the
 * GDI path" (multi-monitor capture, rotated output, duplication denied) -
 * not a failure. */
static int DirectGate_Desktop_WinEnc_InitDxgi(directgate_winenc_t *pEnc)
{
    IDXGIFactory1 *pFactory = NULL;
    IDXGIAdapter *pAdapter = NULL;
    IDXGIOutput *pOutput = NULL;
    IDXGIAdapter *pFoundAdapter = NULL;
    IDXGIOutput1 *pFoundOutput = NULL;

    if (FAILED(CreateDXGIFactory1(&IID_IDXGIFactory1, (void**)&pFactory)) || pFactory == NULL) return XSTDNON;

    for (UINT a = 0; pFoundOutput == NULL && IDXGIFactory1_EnumAdapters(pFactory, a, &pAdapter) == S_OK; a++)
    {
        for (UINT o = 0; IDXGIAdapter_EnumOutputs(pAdapter, o, &pOutput) == S_OK; o++)
        {
            DXGI_OUTPUT_DESC desc;
            memset(&desc, 0, sizeof(desc));

            if (SUCCEEDED(IDXGIOutput_GetDesc(pOutput, &desc)) &&
                desc.AttachedToDesktop &&
                desc.DesktopCoordinates.left == pEnc->nCaptureX &&
                desc.DesktopCoordinates.top == pEnc->nCaptureY &&
                (uint32_t)(desc.DesktopCoordinates.right - desc.DesktopCoordinates.left) == pEnc->nCaptureWidth &&
                (uint32_t)(desc.DesktopCoordinates.bottom - desc.DesktopCoordinates.top) == pEnc->nCaptureHeight &&
                SUCCEEDED(IDXGIOutput_QueryInterface(pOutput, &IID_IDXGIOutput1, (void**)&pFoundOutput)))
            {
                pFoundAdapter = pAdapter;
                IDXGIAdapter_AddRef(pFoundAdapter);
                IDXGIOutput_Release(pOutput);
                break;
            }

            IDXGIOutput_Release(pOutput);
        }

        IDXGIAdapter_Release(pAdapter);
    }

    IDXGIFactory1_Release(pFactory);
    if (pFoundOutput == NULL) return XSTDNON;

    /* The duplication must live on the adapter that owns the output
     * (multi-GPU laptops render each output on a specific adapter). */
    HRESULT hr = D3D11CreateDevice(pFoundAdapter, D3D_DRIVER_TYPE_UNKNOWN, NULL, 0,
        NULL, 0, D3D11_SDK_VERSION, &pEnc->pDevice, NULL, &pEnc->pContext);
    IDXGIAdapter_Release(pFoundAdapter);

    if (FAILED(hr) || pEnc->pDevice == NULL)
    {
        IDXGIOutput1_Release(pFoundOutput);
        pEnc->pDevice = NULL;
        pEnc->pContext = NULL;
        return XSTDNON;
    }

    pEnc->pOutput = pFoundOutput;
    if (DirectGate_Desktop_WinEnc_Duplicate(pEnc) != XSTDOK)
    {
        DirectGate_Desktop_WinEnc_ReleaseDxgi(pEnc);
        return XSTDNON;
    }

    return XSTDOK;
}

/* Copies the acquired frame into pFrameBGRA (scaling to the encode size
 * when needed). Returns XSTDOK on a new frame, XSTDNON when nothing
 * changed on screen, XSTDERR on a lost/failed duplication. */
static int DirectGate_Desktop_WinEnc_CaptureDxgi(directgate_winenc_t *pEnc, uint32_t nTimeoutMs)
{
    DXGI_OUTDUPL_FRAME_INFO frameInfo;
    IDXGIResource *pResource = NULL;
    memset(&frameInfo, 0, sizeof(frameInfo));

    HRESULT hr = IDXGIOutputDuplication_AcquireNextFrame(pEnc->pDuplication, nTimeoutMs, &frameInfo, &pResource);
    if (hr == DXGI_ERROR_WAIT_TIMEOUT) return XSTDNON;
    if (FAILED(hr) || pResource == NULL) return XSTDERR;

    /* Cursor-only updates carry no new pixels. */
    if (frameInfo.LastPresentTime.QuadPart == 0)
    {
        IDXGIResource_Release(pResource);
        IDXGIOutputDuplication_ReleaseFrame(pEnc->pDuplication);
        return XSTDNON;
    }

    uint64_t nCapturedUs = DirectGate_Desktop_WinEnc_MonotonicUs(pEnc);

    ID3D11Texture2D *pTexture = NULL;
    hr = IDXGIResource_QueryInterface(pResource, &IID_ID3D11Texture2D, (void**)&pTexture);
    IDXGIResource_Release(pResource);
    if (FAILED(hr) || pTexture == NULL)
    {
        IDXGIOutputDuplication_ReleaseFrame(pEnc->pDuplication);
        return XSTDERR;
    }

    D3D11_TEXTURE2D_DESC desc;
    ID3D11Texture2D_GetDesc(pTexture, &desc);

    /* The staging texture is created lazily from the first frame's
     * descriptor so mode changes never leave a mismatched copy target. */
    if (pEnc->pStaging == NULL)
    {
        D3D11_TEXTURE2D_DESC staging = desc;
        staging.Usage = D3D11_USAGE_STAGING;
        staging.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        staging.BindFlags = 0;
        staging.MiscFlags = 0;
        staging.MipLevels = 1;
        staging.ArraySize = 1;

        if (FAILED(ID3D11Device_CreateTexture2D(pEnc->pDevice, &staging, NULL, &pEnc->pStaging)))
        {
            pEnc->pStaging = NULL;
            ID3D11Texture2D_Release(pTexture);
            IDXGIOutputDuplication_ReleaseFrame(pEnc->pDuplication);
            return XSTDERR;
        }
    }

    ID3D11DeviceContext_CopyResource(pEnc->pContext, (ID3D11Resource*)pEnc->pStaging, (ID3D11Resource*)pTexture);
    ID3D11Texture2D_Release(pTexture);
    IDXGIOutputDuplication_ReleaseFrame(pEnc->pDuplication);

    D3D11_MAPPED_SUBRESOURCE mapped;
    memset(&mapped, 0, sizeof(mapped));
    if (FAILED(ID3D11DeviceContext_Map(pEnc->pContext, (ID3D11Resource*)pEnc->pStaging,
        0, D3D11_MAP_READ, 0, &mapped)) || mapped.pData == NULL) return XSTDERR;

    if (desc.Width == pEnc->nEncodeWidth && desc.Height == pEnc->nEncodeHeight)
    {
        size_t nRowBytes = (size_t)pEnc->nEncodeWidth * 4U;
        for (uint32_t y = 0; y < pEnc->nEncodeHeight; y++)
        {
            memcpy(pEnc->pFrameBGRA + (size_t)y * nRowBytes,
                (const uint8_t*)mapped.pData + (size_t)y * mapped.RowPitch, nRowBytes);
        }
    }
    else
    {
        DirectGate_YUV_ScaleBGRA(pEnc->pFrameBGRA, pEnc->nEncodeWidth, pEnc->nEncodeHeight,
            (const uint8_t*)mapped.pData, desc.Width, desc.Height, mapped.RowPitch);
    }

    ID3D11DeviceContext_Unmap(pEnc->pContext, (ID3D11Resource*)pEnc->pStaging, 0);
    pEnc->bHaveFrame = XTRUE;
    pEnc->nFrameCapturedUs = nCapturedUs;
    return XSTDOK;
}

static void DirectGate_Desktop_WinEnc_ReleaseGdi(directgate_winenc_t *pEnc)
{
    if (pEnc->hMemDC != NULL)
    {
        if (pEnc->hOldBitmap != NULL)
        {
            SelectObject(pEnc->hMemDC, pEnc->hOldBitmap);
            pEnc->hOldBitmap = NULL;
        }

        DeleteDC(pEnc->hMemDC);
        pEnc->hMemDC = NULL;
    }

    if (pEnc->hDib != NULL)
    {
        DeleteObject(pEnc->hDib);
        pEnc->hDib = NULL;
        pEnc->pDibBits = NULL;
    }

    if (pEnc->hScreenDC != NULL)
    {
        ReleaseDC(NULL, pEnc->hScreenDC);
        pEnc->hScreenDC = NULL;
    }
}

static int DirectGate_Desktop_WinEnc_InitGdi(directgate_winenc_t *pEnc)
{
    pEnc->hScreenDC = GetDC(NULL);
    if (pEnc->hScreenDC == NULL) return XSTDERR;

    pEnc->hMemDC = CreateCompatibleDC(pEnc->hScreenDC);
    if (pEnc->hMemDC == NULL)
    {
        DirectGate_Desktop_WinEnc_ReleaseGdi(pEnc);
        return XSTDERR;
    }

    BITMAPINFO info;
    memset(&info, 0, sizeof(info));
    info.bmiHeader.biSize = sizeof(info.bmiHeader);
    info.bmiHeader.biWidth = (LONG)pEnc->nCaptureWidth;
    info.bmiHeader.biHeight = -(LONG)pEnc->nCaptureHeight; /* top-down rows */
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;

    void *pBits = NULL;
    pEnc->hDib = CreateDIBSection(pEnc->hScreenDC, &info, DIB_RGB_COLORS, &pBits, NULL, 0);
    if (pEnc->hDib == NULL || pBits == NULL)
    {
        DirectGate_Desktop_WinEnc_ReleaseGdi(pEnc);
        return XSTDERR;
    }

    pEnc->pDibBits = (uint8_t*)pBits;
    pEnc->hOldBitmap = SelectObject(pEnc->hMemDC, pEnc->hDib);

    if (pEnc->pPrevBGRA == NULL)
    {
        pEnc->pPrevBGRA = (uint8_t*)malloc((size_t)pEnc->nEncodeWidth * pEnc->nEncodeHeight * 4U);
        if (pEnc->pPrevBGRA == NULL)
        {
            DirectGate_Desktop_WinEnc_ReleaseGdi(pEnc);
            return XSTDERR;
        }
    }

    pEnc->bHavePrev = XFALSE;
    return XSTDOK;
}

/* BitBlt capture with the same unchanged-frame skip the Linux pipeline
 * uses (GDI has no "did anything change" signal like duplication). */
static int DirectGate_Desktop_WinEnc_CaptureGdi(directgate_winenc_t *pEnc, xbool_t bForceKeyframe)
{
    if (!BitBlt(pEnc->hMemDC, 0, 0, (int)pEnc->nCaptureWidth, (int)pEnc->nCaptureHeight,
        pEnc->hScreenDC, pEnc->nCaptureX, pEnc->nCaptureY, SRCCOPY)) return XSTDERR;

    GdiFlush();
    DirectGate_YUV_ScaleBGRA(pEnc->pFrameBGRA, pEnc->nEncodeWidth, pEnc->nEncodeHeight,
        pEnc->pDibBits, pEnc->nCaptureWidth, pEnc->nCaptureHeight,
        (size_t)pEnc->nCaptureWidth * 4U);

    pEnc->bHaveFrame = XTRUE;
    pEnc->nFrameCapturedUs = DirectGate_Desktop_WinEnc_MonotonicUs(pEnc);

    size_t nFrameBytes = (size_t)pEnc->nEncodeWidth * pEnc->nEncodeHeight * 4U;
    if (!bForceKeyframe && pEnc->bHavePrev &&
        memcmp(pEnc->pFrameBGRA, pEnc->pPrevBGRA, nFrameBytes) == 0)
        return XSTDNON;

    return XSTDOK;
}

static void DirectGate_Desktop_WinEnc_WakeMainLoop(directgate_winenc_t *pEnc)
{
    XSOCKET nWriteFd = pEnc->pDesktop->nTimerWriteFd;
    if (nWriteFd == XSOCK_INVALID) return;

    const char cWake = 'f';
    send(nWriteFd, &cWake, sizeof(cWake), 0);
}

static int DirectGate_Desktop_WinEnc_EncodeFrame(directgate_winenc_t *pEnc, xbool_t bForceKeyframe)
{
    DirectGate_YUV_BGRAToNV12(pEnc->pNV12,
        pEnc->pNV12 + (size_t)pEnc->nEncodeWidth * pEnc->nEncodeHeight,
        pEnc->pFrameBGRA, pEnc->nEncodeWidth, pEnc->nEncodeHeight);

    uint64_t nCapturedUs = pEnc->nFrameCapturedUs ? pEnc->nFrameCapturedUs :
        DirectGate_Desktop_WinEnc_MonotonicUs(pEnc);
    uint64_t nPtsUs = nCapturedUs - pEnc->nStartUs;
    xbool_t bKeyframe = XFALSE;

    int nStatus = DirectGate_MFEnc_Encode(pEnc->pEncoder, pEnc->pNV12,
        nPtsUs, bForceKeyframe, &pEnc->encoded, &bKeyframe);

    if (nStatus == XSTDERR)
    {
        DirectGate_Desktop_WinEnc_SetError(pEnc, "Media Foundation frame encoding failed.");
        return XSTDERR;
    }

    if (nStatus == XSTDNON) return XSTDNON; /* encoder warm-up buffering */

    /* Publish: swap the encoded scratch into the mailbox slot (no copy)
     * and wake the main loop through the timer socket pair. */
    AcquireSRWLockExclusive(&pEnc->mailboxLock);
    xbyte_buffer_t swap = pEnc->mailbox;
    pEnc->mailbox = pEnc->encoded;
    pEnc->encoded = swap;
    pEnc->nMailboxWidth = pEnc->nEncodeWidth;
    pEnc->nMailboxHeight = pEnc->nEncodeHeight;
    pEnc->bMailboxKeyframe = bKeyframe;
    pEnc->nMailboxPtsUs = nPtsUs;
    pEnc->nMailboxCapturedUs = nCapturedUs;
    pEnc->bMailboxHasFrame = XTRUE;
    ReleaseSRWLockExclusive(&pEnc->mailboxLock);

    DirectGate_Desktop_WinEnc_WakeMainLoop(pEnc);
    return XSTDOK;
}

static int DirectGate_Desktop_WinEnc_InitPipeline(directgate_winenc_t *pEnc)
{
    LARGE_INTEGER frequency;
    if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0)
    {
        DirectGate_Desktop_WinEnc_SetError(pEnc, "QueryPerformanceFrequency failed.");
        return XSTDERR;
    }

    pEnc->nQpcFrequency = (uint64_t)frequency.QuadPart;
    pEnc->nStartUs = DirectGate_Desktop_WinEnc_MonotonicUs(pEnc);

    /* CREATE_WAITABLE_TIMER_HIGH_RESOLUTION (Win10 1803+) gives sub-ms
     * pacing; older systems silently fall back to the regular timer. */
    pEnc->hWaitTimer = CreateWaitableTimerExW(NULL, NULL,
        CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    if (pEnc->hWaitTimer == NULL)
        pEnc->hWaitTimer = CreateWaitableTimerExW(NULL, NULL, 0, TIMER_ALL_ACCESS);

    char sError[DIRECTGATE_DESKTOP_REASON_LEN] = { 0 };
    pEnc->pEncoder = DirectGate_MFEnc_Create(pEnc->nEncodeWidth, pEnc->nEncodeHeight,
        &pEnc->pDesktop->quality, sError, sizeof(sError));
    if (pEnc->pEncoder == NULL)
    {
        DirectGate_Desktop_WinEnc_SetError(pEnc,
            sError[0] ? sError : "Media Foundation H.264 encoder initialization failed.");
        return XSTDERR;
    }

    pEnc->pFrameBGRA = (uint8_t*)malloc((size_t)pEnc->nEncodeWidth * pEnc->nEncodeHeight * 4U);
    pEnc->pNV12 = (uint8_t*)malloc((size_t)pEnc->nEncodeWidth * pEnc->nEncodeHeight * 3U / 2U);
    if (pEnc->pFrameBGRA == NULL || pEnc->pNV12 == NULL)
    {
        DirectGate_Desktop_WinEnc_SetError(pEnc, "Failed to allocate desktop frame buffers.");
        return XSTDERR;
    }

    pEnc->bUseGdi = (DirectGate_Desktop_WinEnc_InitDxgi(pEnc) != XSTDOK) ? XTRUE : XFALSE;

    /* GDI is both the fallback capture and the source of the guaranteed
     * first frame: duplication only delivers frames on screen updates, and
     * an idle desktop would otherwise leave the viewer black until
     * something repaints. */
    if (DirectGate_Desktop_WinEnc_InitGdi(pEnc) != XSTDOK)
    {
        DirectGate_Desktop_WinEnc_SetError(pEnc, "GDI screen capture initialization failed.");
        return XSTDERR;
    }

    if (DirectGate_Desktop_WinEnc_CaptureGdi(pEnc, XTRUE) == XSTDERR)
    {
        DirectGate_Desktop_WinEnc_SetError(pEnc, "GDI screen capture probe failed.");
        return XSTDERR;
    }

    return XSTDOK;
}

static void DirectGate_Desktop_WinEnc_ApplyPendingControls(directgate_winenc_t *pEnc)
{
    LONG nBitrateKbps = InterlockedExchange(&pEnc->nPendingBitrateKbps, 0);
    if (nBitrateKbps > 0)
        DirectGate_MFEnc_SetBitrate(pEnc->pEncoder, (uint32_t)nBitrateKbps);

    if (InterlockedExchange(&pEnc->bApplyQuality, 0))
    {
        DirectGate_MFEnc_ApplyQuality(pEnc->pEncoder, &pEnc->pDesktop->quality);
        InterlockedExchange(&pEnc->bForceKeyframe, 1);
    }
}

static DWORD WINAPI DirectGate_Desktop_WinEnc_Thread(LPVOID pArg)
{
    directgate_winenc_t *pEnc = (directgate_winenc_t*)pArg;
    HRESULT hrCom = CoInitializeEx(NULL, COINIT_MULTITHREADED);

#ifdef DIRECTGATE_HAVE_AVRT_THREAD_PRIORITY
    /* Lift the capture/encode thread into the multimedia scheduler class so
     * Game Mode cannot starve it behind the foreground game: MMCSS-registered
     * threads are exempt from the background/EcoQoS throttling Game Mode
     * applies and keep a guaranteed CPU slice. avrt.dll ships with every
     * desktop Windows; load it dynamically and fail soft. "Capture" is the
     * profile intended for real-time frame producers. */
    HMODULE hAvrt = LoadLibraryW(L"avrt.dll");
    HANDLE hMmcss = NULL;
    if (hAvrt != NULL)
    {
        typedef HANDLE (WINAPI *directgate_av_set_fn)(LPCWSTR, LPDWORD);
        typedef BOOL (WINAPI *directgate_av_prio_fn)(HANDLE, int);
        directgate_av_set_fn pAvSet = (directgate_av_set_fn)(void*)GetProcAddress(hAvrt, "AvSetMmThreadCharacteristicsW");
        directgate_av_prio_fn pAvPrio = (directgate_av_prio_fn)(void*)GetProcAddress(hAvrt, "AvSetMmThreadPriority");

        DWORD nMmTaskIndex = 0;
        if (pAvSet != NULL) hMmcss = pAvSet(L"Capture", &nMmTaskIndex);
        if (hMmcss != NULL)
        {
            /* AVRT_PRIORITY_HIGH (1): top of the Capture task's band without
             * the AVRT_PRIORITY_CRITICAL risk of monopolising a core. */
            if (pAvPrio != NULL) pAvPrio(hMmcss, 1);
        }
        else xlogw("MMCSS registration failed for capture thread: err(%lu)", (unsigned long)GetLastError());
    }
#endif /* DIRECTGATE_HAVE_AVRT_THREAD_PRIORITY */

    /* Do not use TIME_CRITICAL: the agent main loop must still inject input
     * and drain RTP. ABOVE_NORMAL gives capture/encode an edge over ordinary
     * background work without starving those latency-critical consumers. */
    if (pEnc->pDesktop->quality.ePreset == DIRECTGATE_DESKTOP_PRESET_LOW_LATENCY)
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);

    pEnc->bInitOk = (DirectGate_Desktop_WinEnc_InitPipeline(pEnc) == XSTDOK) ? XTRUE : XFALSE;
    SetEvent(pEnc->hInitDone);

    uint64_t nIntervalUs = 1000000ULL / (pEnc->nFps ? pEnc->nFps : 30U);
    uint64_t nNextDueUs = DirectGate_Desktop_WinEnc_MonotonicUs(pEnc);

    while (pEnc->bInitOk && InterlockedCompareExchange(&pEnc->bRunning, 0, 0))
    {
        DirectGate_Desktop_WinEnc_ApplyPendingControls(pEnc);

        /* Mailbox still occupied or transport backed up: skip the capture
         * entirely. Nothing entered the encoder, so its reference chain is
         * untouched and no keyframe is needed on resume (same reasoning as
         * the macOS SCK callback). Duplication keeps accumulating damage,
         * so the next acquired frame is the current screen, not a stale
         * queue. */
        xbool_t bBusy = XFALSE;
        AcquireSRWLockExclusive(&pEnc->mailboxLock);
        bBusy = pEnc->bMailboxHasFrame;
        ReleaseSRWLockExclusive(&pEnc->mailboxLock);

        if (bBusy || DirectGate_Desktop_ShouldSkipForBackpressure(pEnc->pSession))
        {
            DirectGate_Desktop_WinEnc_SleepUs(pEnc, 2000ULL);
            continue;
        }

        xbool_t bForceKeyframe = InterlockedExchange(&pEnc->bForceKeyframe, 0) ? XTRUE : XFALSE;
        uint64_t nNowUs = DirectGate_Desktop_WinEnc_MonotonicUs(pEnc);
        int nCapture;

        if (!pEnc->bUseGdi)
        {
            /* AcquireNextFrame wakes on every host present. Merely passing a
             * deadline as its timeout does NOT cap FPS: a 144/240 Hz game
             * returns early every time and can overwhelm a 60 Hz encoder.
             * Wait to the pacing boundary first, then acquire the newest
             * accumulated desktop image. A one-frame timeout preserves the
             * event-driven low-latency path when no image is pending yet. */
            if (nNextDueUs > nNowUs)
                DirectGate_Desktop_WinEnc_SleepUs(pEnc, nNextDueUs - nNowUs);
            nNowUs = DirectGate_Desktop_WinEnc_MonotonicUs(pEnc);
            uint32_t nTimeoutMs = (uint32_t)(nIntervalUs / 1000ULL);
            nCapture = DirectGate_Desktop_WinEnc_CaptureDxgi(pEnc,
                nTimeoutMs ? nTimeoutMs : 1U);

            if (nCapture == XSTDERR)
            {
                /* Lost duplication (desktop switch, mode change, another
                 * duplication client). Re-duplicate against the current
                 * input desktop; after too many failed attempts fall back
                 * to GDI so the operator keeps a picture. */
                InterlockedIncrement(&pEnc->nFailures);
                if (bForceKeyframe) InterlockedExchange(&pEnc->bForceKeyframe, 1);

                DirectGate_Desktop_WinEnc_AttachInputDesktop();
                if (DirectGate_Desktop_WinEnc_Duplicate(pEnc) == XSTDOK)
                {
                    pEnc->nDxgiReinitFails = 0;
                }
                else if (++pEnc->nDxgiReinitFails >=
                    (pEnc->nFps ? pEnc->nFps : 30U) * DIRECTGATE_WINENC_REINIT_SECONDS)
                {
                    xlogw("Desktop Duplication lost for good, switching to GDI capture: sid(%u)",
                        pEnc->pDesktop->nSessionId);
                    DirectGate_Desktop_WinEnc_ReleaseDxgi(pEnc);
                    pEnc->bUseGdi = XTRUE;
                }

                DirectGate_Desktop_WinEnc_SleepUs(pEnc, nIntervalUs);
                continue;
            }
        }
        else
        {
            /* GDI has no change notification: sleep to the deadline, then
             * capture and skip unchanged frames via memcmp (Linux model). */
            if (nNextDueUs > nNowUs)
                DirectGate_Desktop_WinEnc_SleepUs(pEnc, nNextDueUs - nNowUs);
            nCapture = DirectGate_Desktop_WinEnc_CaptureGdi(pEnc, bForceKeyframe);
        }

        nNowUs = DirectGate_Desktop_WinEnc_MonotonicUs(pEnc);
        nNextDueUs = (nNextDueUs + nIntervalUs > nNowUs) ? nNextDueUs + nIntervalUs : nNowUs + nIntervalUs;

        if (nCapture == XSTDERR)
        {
            InterlockedIncrement(&pEnc->nFailures);
            if (bForceKeyframe) InterlockedExchange(&pEnc->bForceKeyframe, 1);
            continue;
        }

        /* No new pixels: still honour a pending keyframe request (new
         * viewer / PLI recovery) by re-encoding the last frame as an IDR. */
        if (nCapture == XSTDNON && (!bForceKeyframe || !pEnc->bHaveFrame))
        {
            if (bForceKeyframe) InterlockedExchange(&pEnc->bForceKeyframe, 1);
            continue;
        }

        int nEncode = DirectGate_Desktop_WinEnc_EncodeFrame(pEnc, bForceKeyframe);
        if (nEncode == XSTDERR)
        {
            InterlockedIncrement(&pEnc->nFailures);
            if (bForceKeyframe) InterlockedExchange(&pEnc->bForceKeyframe, 1);
            continue;
        }

        InterlockedExchange(&pEnc->nFailures, 0);

        /* Remember what was sent for the GDI unchanged-frame check. */
        if (pEnc->bUseGdi && nEncode == XSTDOK)
        {
            uint8_t *pSwap = pEnc->pPrevBGRA;
            pEnc->pPrevBGRA = pEnc->pFrameBGRA;
            pEnc->pFrameBGRA = pSwap;
            pEnc->bHavePrev = XTRUE;
            pEnc->bHaveFrame = XFALSE;
        }
    }

    /* COM objects are apartment-bound: release everything the thread owns
     * before CoUninitialize. Plain buffers are freed after the join. */
    DirectGate_MFEnc_Destroy(pEnc->pEncoder);
    pEnc->pEncoder = NULL;

    DirectGate_Desktop_WinEnc_ReleaseDxgi(pEnc);
    DirectGate_Desktop_WinEnc_ReleaseGdi(pEnc);

    if (pEnc->hWaitTimer != NULL)
    {
        CloseHandle(pEnc->hWaitTimer);
        pEnc->hWaitTimer = NULL;
    }

#ifdef DIRECTGATE_HAVE_AVRT_THREAD_PRIORITY
    if (hMmcss != NULL)
    {
        typedef BOOL (WINAPI *directgate_av_revert_fn)(HANDLE);
        directgate_av_revert_fn pAvRevert = (directgate_av_revert_fn)(void*)GetProcAddress(hAvrt, "AvRevertMmThreadCharacteristics");
        if (pAvRevert != NULL) pAvRevert(hMmcss);
    }

    if (hAvrt != NULL) FreeLibrary(hAvrt);
#endif /* DIRECTGATE_HAVE_AVRT_THREAD_PRIORITY */

    if (SUCCEEDED(hrCom)) CoUninitialize();
    return 0;
}

static void DirectGate_Desktop_WinEnc_Free(directgate_winenc_t *pEnc)
{
    XCHECK_VOID_NL((pEnc != NULL));

    if (pEnc->hThread != NULL)
    {
        InterlockedExchange(&pEnc->bRunning, 0);

        /* A healthy loop iteration is bounded by the frame interval plus
         * the encoder waits (< 1s). If the thread is wedged inside a GPU
         * driver or MFT call, leaking this pipeline is the only safe move:
         * freeing buffers under a live thread would be a use-after-free,
         * TerminateThread would corrupt the COM apartment, and blocking
         * forever would freeze every session on the main loop. */
        if (WaitForSingleObject(pEnc->hThread, 10000) != WAIT_OBJECT_0)
        {
            xloge("Desktop capture thread is not responding, leaking its pipeline: sid(%u)",
                pEnc->pDesktop != NULL ? pEnc->pDesktop->nSessionId : 0U);
            CloseHandle(pEnc->hThread);
            return;
        }

        CloseHandle(pEnc->hThread);
        pEnc->hThread = NULL;
    }

    if (pEnc->hInitDone != NULL)
    {
        CloseHandle(pEnc->hInitDone);
        pEnc->hInitDone = NULL;
    }

    XByteBuffer_Clear(&pEnc->encoded);
    XByteBuffer_Clear(&pEnc->mailbox);
    XByteBuffer_Clear(&pEnc->drain);

    free(pEnc->pFrameBGRA);
    free(pEnc->pPrevBGRA);
    free(pEnc->pNV12);
    free(pEnc);
}

void DirectGate_Desktop_WinEncoder_StopDesktop(directgate_desktop_t *pDesktop)
{
    XCHECK_VOID_NL((pDesktop != NULL));
    directgate_winenc_t *pEnc = DirectGate_Desktop_WinEnc(pDesktop);
    if (pEnc == NULL) return;

    pDesktop->pEncoder = NULL;
    DirectGate_Desktop_WinEnc_Free(pEnc);
}

int DirectGate_Desktop_WinEncoder_Start(directgate_session_t *pSession,
                                    int32_t nX, int32_t nY,
                                    uint32_t nWidth, uint32_t nHeight)
{
    XCHECK((pSession != NULL), XSTDERR);
    directgate_desktop_t *pDesktop = &pSession->desktop;

    DirectGate_Desktop_WinEncoder_StopDesktop(pDesktop);

    if (nWidth == 0 || nHeight == 0)
    {
        xstrncpy(pDesktop->sReason, sizeof(pDesktop->sReason), "Empty Windows capture rectangle.");
        return XSTDERR;
    }

    directgate_winenc_t *pEnc = (directgate_winenc_t*)calloc(1, sizeof(*pEnc));
    if (pEnc == NULL)
    {
        xstrncpy(pDesktop->sReason, sizeof(pDesktop->sReason), "Failed to allocate Windows encoder pipeline.");
        return XSTDERR;
    }

    pEnc->pSession = pSession;
    pEnc->pDesktop = pDesktop;
    pEnc->nCaptureX = nX;
    pEnc->nCaptureY = nY;
    pEnc->nCaptureWidth = nWidth;
    pEnc->nCaptureHeight = nHeight;
    pEnc->nFps = pDesktop->quality.nFps ? pDesktop->quality.nFps : 30U;
    DirectGate_Desktop_WinEnc_PickSize(pDesktop, nWidth, nHeight, &pEnc->nEncodeWidth, &pEnc->nEncodeHeight);

    InitializeSRWLock(&pEnc->mailboxLock);
    XByteBuffer_Init(&pEnc->encoded, XSTDNON, XFALSE);
    XByteBuffer_Init(&pEnc->mailbox, XSTDNON, XFALSE);
    XByteBuffer_Init(&pEnc->drain, XSTDNON, XFALSE);

    pEnc->hInitDone = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (pEnc->hInitDone == NULL)
    {
        xstrncpy(pDesktop->sReason, sizeof(pDesktop->sReason), "Failed to create encoder init event.");
        DirectGate_Desktop_WinEnc_Free(pEnc);
        return XSTDERR;
    }

    InterlockedExchange(&pEnc->bRunning, 1);
    InterlockedExchange(&pEnc->bForceKeyframe, 1);

    pEnc->hThread = CreateThread(NULL, 0, DirectGate_Desktop_WinEnc_Thread, pEnc, 0, NULL);
    if (pEnc->hThread == NULL)
    {
        xstrncpy(pDesktop->sReason, sizeof(pDesktop->sReason), "Failed to start desktop capture thread.");
        DirectGate_Desktop_WinEnc_Free(pEnc);
        return XSTDERR;
    }

    if (WaitForSingleObject(pEnc->hInitDone, DIRECTGATE_WINENC_INIT_WAIT_MS) != WAIT_OBJECT_0 ||
        !pEnc->bInitOk)
    {
        xstrncpy(pDesktop->sReason, sizeof(pDesktop->sReason),
            xstrused(pEnc->sLastError) ? pEnc->sLastError :
            "Desktop capture pipeline initialization timed out.");

        DirectGate_Desktop_WinEnc_Free(pEnc);
        return XSTDERR;
    }

    pDesktop->pEncoder = pEnc;

    xlogi("Windows H.264 pipeline started: sid(%u), capture(%d,%d %ux%u), encode(%ux%u), "
        "backend(%s), encoder(%s), preset(%s)",
        pSession->nSessionId, nX, nY, nWidth, nHeight,
        pEnc->nEncodeWidth, pEnc->nEncodeHeight,
        pEnc->bUseGdi ? "gdi" : "dxgi-duplication",
        DirectGate_MFEnc_Describe(pEnc->pEncoder),
        DirectGate_Desktop_PresetName(pDesktop->quality.ePreset));

    return XSTDOK;
}

void DirectGate_Desktop_WinEncoder_ApplyQuality(directgate_session_t *pSession)
{
    XCHECK_VOID_NL((pSession != NULL));
    directgate_desktop_t *pDesktop = &pSession->desktop;
    directgate_winenc_t *pEnc = DirectGate_Desktop_WinEnc(pDesktop);
    XCHECK_VOID_NL((pEnc != NULL));

    uint32_t nWidth = 0U;
    uint32_t nHeight = 0U;
    DirectGate_Desktop_WinEnc_PickSize(pDesktop, pEnc->nCaptureWidth, pEnc->nCaptureHeight, &nWidth, &nHeight);

    /* A resolution change needs a full pipeline rebuild; bitrate and GOP
     * updates are marshalled to the capture thread and applied live. */
    if (nWidth != pEnc->nEncodeWidth || nHeight != pEnc->nEncodeHeight ||
        pEnc->nFps != pDesktop->quality.nFps)
    {
        int32_t nX = pEnc->nCaptureX;
        int32_t nY = pEnc->nCaptureY;
        uint32_t nCaptureWidth = pEnc->nCaptureWidth;
        uint32_t nCaptureHeight = pEnc->nCaptureHeight;

        if (DirectGate_Desktop_WinEncoder_Start(pSession, nX, nY,
            nCaptureWidth, nCaptureHeight) != XSTDOK)
        {
            xlogw("Failed to rebuild Windows H.264 pipeline for preset change: sid(%u), reason(%s)",
                pSession->nSessionId, DirectGate_Desktop_GetReason(pDesktop));
        }

        return;
    }

    InterlockedExchange(&pEnc->bApplyQuality, 1);
}

void DirectGate_Desktop_WinEncoder_SetBitrate(directgate_session_t *pSession, uint32_t nBitrateKbps)
{
    XCHECK_VOID_NL((pSession != NULL));
    directgate_winenc_t *pEnc = DirectGate_Desktop_WinEnc(&pSession->desktop);
    XCHECK_VOID_NL((pEnc != NULL && nBitrateKbps > 0));

    /* Deliberately no keyframe request: the encoder keeps its reference
     * chain and converges to the new rate, so a congested link is not hit
     * with an IDR burst on top of the loss that triggered the step. */
    InterlockedExchange(&pEnc->nPendingBitrateKbps, (LONG)nBitrateKbps);
}

void DirectGate_Desktop_WinEncoder_RequestKeyframe(directgate_session_t *pSession)
{
    XCHECK_VOID_NL((pSession != NULL));
    directgate_winenc_t *pEnc = DirectGate_Desktop_WinEnc(&pSession->desktop);
    XCHECK_VOID_NL((pEnc != NULL));
    InterlockedExchange(&pEnc->bForceKeyframe, 1);
}

const char* DirectGate_Desktop_WinEncoder_LastError(const directgate_session_t *pSession)
{
    if (pSession == NULL) return "no session";
    const directgate_winenc_t *pEnc = DirectGate_Desktop_WinEnc(&pSession->desktop);
    if (pEnc != NULL && xstrused(pEnc->sLastError)) return pEnc->sLastError;
    if (xstrused(pSession->desktop.sReason)) return pSession->desktop.sReason;
    return "unknown";
}

xbool_t DirectGate_Desktop_WinEncoder_HasFailed(const directgate_session_t *pSession)
{
    XCHECK_NL((pSession != NULL), XFALSE);
    const directgate_winenc_t *pEnc = DirectGate_Desktop_WinEnc(&pSession->desktop);
    if (pEnc == NULL) return XTRUE;
    LONG nMaxFailures = (LONG)((pEnc->nFps ? pEnc->nFps : 30U) *
        DIRECTGATE_WINENC_FAILURE_SECONDS);
    return (pEnc->nFailures >= nMaxFailures) ? XTRUE : XFALSE;
}

int DirectGate_Desktop_WinEncoder_DrainMain(directgate_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_winenc_t *pEnc = DirectGate_Desktop_WinEnc(&pSession->desktop);
    XCHECK_NL((pEnc != NULL), XAPI_CONTINUE);

    uint32_t nWidth = 0, nHeight = 0;
    xbool_t bKeyframe = XFALSE, bHasFrame = XFALSE;
    uint64_t nPtsUs = 0;
    uint64_t nNowUs = DirectGate_Desktop_WinEnc_MonotonicUs(pEnc);
    uint64_t nIntervalUs = 1000000ULL / (pEnc->nFps ? pEnc->nFps : 30U);
    uint64_t nMaxAgeUs = nIntervalUs * 3U;
    uint64_t nDroppedAgeUs = 0U;
    xbool_t bDroppedStale = XFALSE;
    if (nMaxAgeUs < 50000ULL) nMaxAgeUs = 50000ULL;

    AcquireSRWLockExclusive(&pEnc->mailboxLock);
    if (pEnc->bMailboxHasFrame)
    {
        uint64_t nAgeUs = (nNowUs >= pEnc->nMailboxCapturedUs) ? nNowUs - pEnc->nMailboxCapturedUs : 0U;
        if (pEnc->nMailboxCapturedUs && nAgeUs > nMaxAgeUs)
        {
            /* Never put an already-obsolete frame on the wire. Dropping an
             * encoded P-frame breaks the decoder reference chain, therefore
             * the very next fresh capture is explicitly made an IDR. */
            pEnc->mailbox.nUsed = 0;
            InterlockedExchange(&pEnc->bForceKeyframe, 1);
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

    ReleaseSRWLockExclusive(&pEnc->mailboxLock);

    if (bDroppedStale)
    {
        xlogd("Dropping stale Windows desktop frame: sid(%u), ageUs(%llu), maxUs(%llu)",
            pSession->nSessionId, (unsigned long long)nDroppedAgeUs,
            (unsigned long long)nMaxAgeUs);
    }

    if (!bHasFrame || !pEnc->drain.nUsed) return XAPI_CONTINUE;

    return DirectGate_Desktop_SendEncodedFrame(pSession, pEnc->drain.pData,
        pEnc->drain.nUsed, nWidth, nHeight, bKeyframe, nPtsUs);
}

#endif /* _WIN32 */
