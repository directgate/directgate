/*!
 * @file directgate-agent/src/agent/desktop/audio_win.c
 * @brief Windows system-audio capture backend (WASAPI loopback).
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

#include "audio.h"

#ifdef DIRECTGATE_DESKTOP_HAS_AUDIO

/* initguid.h before the WASAPI headers instantiates CLSID_MMDeviceEnumerator
 * and the IAudioClient/IAudioCaptureClient IIDs in this translation unit, so no
 * extra import library is needed (mirrors mfenc.c). This is the only unit that
 * touches the multimedia-device GUIDs, so there is no duplicate definition. */
#include <initguid.h>
#include <windows.h>
#include <mmreg.h>
#include <mmdeviceapi.h>
#include <audioclient.h>

/* KSDATAFORMAT_SUBTYPE_IEEE_FLOAT lives in ksmedia.h, whose availability and
 * include order are fragile across MinGW toolchains. Instantiate the value
 * locally instead (mirrors mfenc.c's GUID handling). */
static const GUID g_DirectGateSubtypeFloat =
    { 0x00000003, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71 } };

/* All WASAPI work runs on a private capture thread that owns its own MTA COM
 * apartment: loopback capture on the default render endpoint, converted to the
 * fixed 48 kHz stereo S16 the Opus encoder wants and pushed into a ring that
 * DirectGate_Audio_BackendRead drains. Keeping COM off the shared audio worker
 * thread avoids cross-apartment marshalling of the capture client. */

#define DIRECTGATE_WASAPI_RING_FRAMES  (DIRECTGATE_AUDIO_SAMPLE_RATE * 2U) /* ~2 s of stereo S16 */
#define DIRECTGATE_WASAPI_POLL_MS      8U      /* loopback packet poll cadence */
#define DIRECTGATE_WASAPI_INIT_WAIT_MS 3000U   /* how long BackendOpen waits for readiness */

typedef struct directgate_wasapi_ {
    uint32_t nChannels;            /* output channel count (matches request) */

    HANDLE hThread;
    HANDLE hStopEvent;             /* signalled to stop the capture thread */
    volatile LONG bReady;          /* capture thread initialised successfully */
    volatile LONG bFailed;         /* capture thread hit a fatal init error */
    HANDLE hInitEvent;             /* set once bReady/bFailed is known */
    char sInitError[160];

    CRITICAL_SECTION lock;         /* guards the ring below */
    CONDITION_VARIABLE dataCv;     /* signalled when samples are pushed */
    int16_t *pRing;                /* interleaved S16 output samples */
    uint32_t nRingCap;             /* capacity in samples (frames * channels) */
    uint32_t nRingHead;
    uint32_t nRingTail;
    uint32_t nRingCount;

    /* Linear-resampler state (mix rate -> 48 kHz), owned by the capture thread. */
    double dRatio;                 /* input samples consumed per output sample */
    double dFrac;                  /* fractional input position in [0,1) */
    float fPrevL;
    float fPrevR;
    xbool_t bPrimed;
} directgate_wasapi_t;

static void DirectGate_WASAPI_Push(directgate_wasapi_t *pCtx, int16_t nL, int16_t nR)
{
    EnterCriticalSection(&pCtx->lock);

    /* Drop the oldest stereo pair when full so latency stays bounded. */
    if (pCtx->nRingCount + 2U > pCtx->nRingCap)
    {
        pCtx->nRingTail = (pCtx->nRingTail + 2U) % pCtx->nRingCap;
        pCtx->nRingCount -= 2U;
    }

    pCtx->pRing[pCtx->nRingHead] = nL;
    pCtx->pRing[(pCtx->nRingHead + 1U) % pCtx->nRingCap] = nR;
    pCtx->nRingHead = (pCtx->nRingHead + 2U) % pCtx->nRingCap;
    pCtx->nRingCount += 2U;

    LeaveCriticalSection(&pCtx->lock);
    WakeConditionVariable(&pCtx->dataCv);
}

static int16_t DirectGate_WASAPI_ClampS16(float fSample)
{
    float fScaled = fSample * 32767.0f;
    if (fScaled > 32767.0f) fScaled = 32767.0f;
    else if (fScaled < -32768.0f) fScaled = -32768.0f;
    return (int16_t)fScaled;
}

static xbool_t DirectGate_WASAPI_IsFloat(const WAVEFORMATEX *pFmt)
{
    if (pFmt->wFormatTag == WAVE_FORMAT_IEEE_FLOAT) return XTRUE;
    if (pFmt->wFormatTag == WAVE_FORMAT_EXTENSIBLE &&
        pFmt->cbSize >= sizeof(WAVEFORMATEXTENSIBLE) - sizeof(WAVEFORMATEX))
    {
        const WAVEFORMATEXTENSIBLE *pExt = (const WAVEFORMATEXTENSIBLE*)pFmt;
        return IsEqualGUID(&pExt->SubFormat, &g_DirectGateSubtypeFloat) ? XTRUE : XFALSE;
    }

    return XFALSE;
}

/* Reads channel nCh of input frame nFrame as a normalized float. */
static float DirectGate_WASAPI_Sample(const BYTE *pData, uint32_t nFrame, uint32_t nCh,
                                      uint32_t nInChannels, uint16_t nBits, xbool_t bFloat)
{
    size_t nSampleBytes = (size_t)(nBits / 8U);
    const BYTE *p = pData + ((size_t)nFrame * nInChannels + nCh) * nSampleBytes;

    if (bFloat && nBits == 32U)
    {
        float f;
        memcpy(&f, p, sizeof(f));
        return f;
    }

    if (nBits == 16U)
    {
        int16_t s;
        memcpy(&s, p, sizeof(s));
        return (float)s / 32768.0f;
    }

    if (nBits == 32U)
    {
        int32_t s;
        memcpy(&s, p, sizeof(s));
        return (float)s / 2147483648.0f;
    }

    return 0.0f;
}

/* Resamples one input packet (mix rate) to 48 kHz stereo S16 into the ring. */
static void DirectGate_WASAPI_Resample(directgate_wasapi_t *pCtx, const BYTE *pData,
                                       uint32_t nFrames, uint32_t nInChannels,
                                       uint16_t nBits, xbool_t bFloat, xbool_t bSilent)
{
    for (uint32_t i = 0; i < nFrames; i++)
    {
        float fL, fR;
        if (bSilent)
        {
            fL = 0.0f;
            fR = 0.0f;
        }
        else
        {
            fL = DirectGate_WASAPI_Sample(pData, i, 0, nInChannels, nBits, bFloat);
            fR = (nInChannels >= 2U)
                ? DirectGate_WASAPI_Sample(pData, i, 1, nInChannels, nBits, bFloat)
                : fL;
        }

        if (!pCtx->bPrimed)
        {
            pCtx->fPrevL = fL;
            pCtx->fPrevR = fR;
            pCtx->bPrimed = XTRUE;
        }

        /* Emit every output sample whose position falls inside [prev, cur). */
        while (pCtx->dFrac < 1.0)
        {
            float t = (float)pCtx->dFrac;
            float oL = pCtx->fPrevL + (fL - pCtx->fPrevL) * t;
            float oR = pCtx->fPrevR + (fR - pCtx->fPrevR) * t;
            DirectGate_WASAPI_Push(pCtx, DirectGate_WASAPI_ClampS16(oL), DirectGate_WASAPI_ClampS16(oR));
            pCtx->dFrac += pCtx->dRatio;
        }

        pCtx->dFrac -= 1.0;
        pCtx->fPrevL = fL;
        pCtx->fPrevR = fR;
    }
}

static void DirectGate_WASAPI_SignalInit(directgate_wasapi_t *pCtx, xbool_t bOk, const char *pErr)
{
    if (!bOk)
    {
        InterlockedExchange(&pCtx->bFailed, 1);
        if (pErr != NULL) xstrncpy(pCtx->sInitError, sizeof(pCtx->sInitError), pErr);
    }
    else
    {
        InterlockedExchange(&pCtx->bReady, 1);
    }

    SetEvent(pCtx->hInitEvent);
}

static DWORD WINAPI DirectGate_WASAPI_Thread(LPVOID pArg)
{
    directgate_wasapi_t *pCtx = (directgate_wasapi_t*)pArg;

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    xbool_t bCoInit = (hr == S_OK || hr == S_FALSE) ? XTRUE : XFALSE;

    IMMDeviceEnumerator *pEnum = NULL;
    IMMDevice *pDevice = NULL;
    IAudioClient *pClient = NULL;
    IAudioCaptureClient *pCapture = NULL;
    WAVEFORMATEX *pFmt = NULL;

    do
    {
        hr = CoCreateInstance(&CLSID_MMDeviceEnumerator, NULL, CLSCTX_ALL, &IID_IMMDeviceEnumerator, (void**)&pEnum);
        if (FAILED(hr)) { DirectGate_WASAPI_SignalInit(pCtx, XFALSE, "no audio device enumerator"); break; }

        hr = pEnum->lpVtbl->GetDefaultAudioEndpoint(pEnum, eRender, eConsole, &pDevice);
        if (FAILED(hr)) { DirectGate_WASAPI_SignalInit(pCtx, XFALSE, "no default output device"); break; }

        hr = pDevice->lpVtbl->Activate(pDevice, &IID_IAudioClient, CLSCTX_ALL, NULL, (void**)&pClient);
        if (FAILED(hr)) { DirectGate_WASAPI_SignalInit(pCtx, XFALSE, "failed to activate audio client"); break; }

        hr = pClient->lpVtbl->GetMixFormat(pClient, &pFmt);
        if (FAILED(hr) || pFmt == NULL) { DirectGate_WASAPI_SignalInit(pCtx, XFALSE, "no mix format"); break; }

        uint32_t nInChannels = pFmt->nChannels ? pFmt->nChannels : 2U;
        uint16_t nBits = pFmt->wBitsPerSample ? pFmt->wBitsPerSample : 32U;
        xbool_t bFloat = DirectGate_WASAPI_IsFloat(pFmt);
        pCtx->dRatio = (double)pFmt->nSamplesPerSec / (double)DIRECTGATE_AUDIO_SAMPLE_RATE;
        if (pCtx->dRatio <= 0.0) pCtx->dRatio = 1.0;

        /* 200 ms shared-mode loopback buffer, timer-driven (no event handle). */
        REFERENCE_TIME nBufDuration = 2000000; /* 100-ns units */
        hr = pClient->lpVtbl->Initialize(pClient, AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_LOOPBACK, nBufDuration, 0, pFmt, NULL);
        if (FAILED(hr)) { DirectGate_WASAPI_SignalInit(pCtx, XFALSE, "failed to initialise loopback capture"); break; }

        hr = pClient->lpVtbl->GetService(pClient, &IID_IAudioCaptureClient, (void**)&pCapture);
        if (FAILED(hr)) { DirectGate_WASAPI_SignalInit(pCtx, XFALSE, "no capture service"); break; }

        hr = pClient->lpVtbl->Start(pClient);
        if (FAILED(hr)) { DirectGate_WASAPI_SignalInit(pCtx, XFALSE, "failed to start capture"); break; }

        DirectGate_WASAPI_SignalInit(pCtx, XTRUE, NULL);

        while (WaitForSingleObject(pCtx->hStopEvent, DIRECTGATE_WASAPI_POLL_MS) == WAIT_TIMEOUT)
        {
            UINT32 nPacket = 0;
            while (SUCCEEDED(pCapture->lpVtbl->GetNextPacketSize(pCapture, &nPacket)) && nPacket > 0)
            {
                BYTE *pData = NULL;
                UINT32 nFrames = 0;
                DWORD nFlags = 0;
                if (FAILED(pCapture->lpVtbl->GetBuffer(pCapture, &pData, &nFrames, &nFlags, NULL, NULL))) break;

                xbool_t bSilent = (nFlags & AUDCLNT_BUFFERFLAGS_SILENT) ? XTRUE : XFALSE;
                if (nFrames > 0) DirectGate_WASAPI_Resample(pCtx, pData, nFrames, nInChannels, nBits, bFloat, bSilent);

                pCapture->lpVtbl->ReleaseBuffer(pCapture, nFrames);
            }
        }
    } while (0);

    if (pClient != NULL) pClient->lpVtbl->Stop(pClient);
    if (pFmt != NULL) CoTaskMemFree(pFmt);
    if (pCapture != NULL) pCapture->lpVtbl->Release(pCapture);
    if (pClient != NULL) pClient->lpVtbl->Release(pClient);
    if (pDevice != NULL) pDevice->lpVtbl->Release(pDevice);
    if (pEnum != NULL) pEnum->lpVtbl->Release(pEnum);
    if (bCoInit) CoUninitialize();

    /* Make sure a caller blocked in BackendOpen is always released. */
    if (!InterlockedCompareExchange(&pCtx->bReady, 0, 0) &&
        !InterlockedCompareExchange(&pCtx->bFailed, 0, 0))
        DirectGate_WASAPI_SignalInit(pCtx, XFALSE, "audio capture thread exited");

    (void)bCoInit;
    return 0;
}

void* DirectGate_Audio_BackendOpen(uint32_t nSampleRate, uint32_t nChannels, char *pErr, size_t nErrSize)
{
    (void)nSampleRate; /* always resampled to DIRECTGATE_AUDIO_SAMPLE_RATE */

    directgate_wasapi_t *pCtx = (directgate_wasapi_t*)calloc(1, sizeof(*pCtx));
    if (pCtx == NULL)
    {
        if (pErr != NULL) xstrncpy(pErr, nErrSize, "Out of memory starting audio.");
        return NULL;
    }

    pCtx->nChannels = nChannels;
    pCtx->nRingCap = DIRECTGATE_WASAPI_RING_FRAMES * DIRECTGATE_AUDIO_CHANNELS;
    pCtx->pRing = (int16_t*)malloc((size_t)pCtx->nRingCap * sizeof(int16_t));

    InitializeCriticalSection(&pCtx->lock);
    InitializeConditionVariable(&pCtx->dataCv);

    pCtx->hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    pCtx->hInitEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    if (pCtx->pRing == NULL || pCtx->hStopEvent == NULL || pCtx->hInitEvent == NULL)
    {
        if (pErr != NULL) xstrncpy(pErr, nErrSize, "Failed to allocate audio capture resources.");
        DirectGate_Audio_BackendClose(pCtx);
        return NULL;
    }

    pCtx->hThread = CreateThread(NULL, 0, DirectGate_WASAPI_Thread, pCtx, 0, NULL);
    if (pCtx->hThread == NULL)
    {
        if (pErr != NULL) xstrncpy(pErr, nErrSize, "Failed to start audio capture thread.");
        DirectGate_Audio_BackendClose(pCtx);
        return NULL;
    }

    /* Report device/init failures synchronously, like the other backends. */
    WaitForSingleObject(pCtx->hInitEvent, DIRECTGATE_WASAPI_INIT_WAIT_MS);
    if (!InterlockedCompareExchange(&pCtx->bReady, 0, 0))
    {
        if (pErr != NULL)
        {
            xstrncpy(pErr, nErrSize, pCtx->sInitError[0] ?
                pCtx->sInitError : "WASAPI loopback capture did not start.");
        }

        DirectGate_Audio_BackendClose(pCtx);
        return NULL;
    }

    xlogi("Opened desktop audio WASAPI loopback: rate(%u), channels(%u)", DIRECTGATE_AUDIO_SAMPLE_RATE, nChannels);
    return pCtx;
}

int DirectGate_Audio_BackendRead(void *pBackend, int16_t *pBuf, uint32_t nFrames, uint32_t nChannels)
{
    directgate_wasapi_t *pCtx = (directgate_wasapi_t*)pBackend;
    XCHECK((pCtx != NULL && pBuf != NULL), XSTDERR);
    XCHECK((nFrames > 0 && nChannels > 0), XSTDERR);

    uint32_t nNeeded = nFrames * nChannels;
    uint32_t nGot = 0;

    EnterCriticalSection(&pCtx->lock);

    /* Wait up to two frame periods for real samples; loopback delivers nothing
     * during silence, so pad the remainder with silence to keep a continuous
     * 20 ms cadence (and let the worker observe a stop between reads). */
    uint32_t nWaited = 0;

    while (pCtx->nRingCount < nNeeded && nWaited < 2U * DIRECTGATE_AUDIO_FRAME_MS)
    {
        if (!SleepConditionVariableCS(&pCtx->dataCv, &pCtx->lock, DIRECTGATE_AUDIO_FRAME_MS))
            nWaited += DIRECTGATE_AUDIO_FRAME_MS;
    }

    while (nGot < nNeeded && pCtx->nRingCount > 0)
    {
        pBuf[nGot++] = pCtx->pRing[pCtx->nRingTail];
        pCtx->nRingTail = (pCtx->nRingTail + 1U) % pCtx->nRingCap;
        pCtx->nRingCount--;
    }

    LeaveCriticalSection(&pCtx->lock);

    while (nGot < nNeeded) pBuf[nGot++] = 0; /* silence pad */
    return XSTDOK;
}

void DirectGate_Audio_BackendClose(void *pBackend)
{
    directgate_wasapi_t *pCtx = (directgate_wasapi_t*)pBackend;
    if (pCtx == NULL) return;

    if (pCtx->hThread != NULL)
    {
        if (pCtx->hStopEvent != NULL) SetEvent(pCtx->hStopEvent);
        WaitForSingleObject(pCtx->hThread, INFINITE);
        CloseHandle(pCtx->hThread);
    }

    if (pCtx->hStopEvent != NULL) CloseHandle(pCtx->hStopEvent);
    if (pCtx->hInitEvent != NULL) CloseHandle(pCtx->hInitEvent);

    DeleteCriticalSection(&pCtx->lock);
    free(pCtx->pRing);
    free(pCtx);
}

#endif /* DIRECTGATE_DESKTOP_HAS_AUDIO */
