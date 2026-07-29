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

/* WASAPI has no separate capture thread here: the shared audio worker calls
 * BackendRead, which drains the loopback endpoint directly (like Linux's
 * blocking pa_simple_read) and resamples to 48 kHz stereo S16 on the fly. That
 * removes the extra producer thread and its ring buffer, whose FIFO backlog
 * used to sit between capture and encode as constant audio-behind-video delay.
 * The IAudioClient is created in the (COM-free) main thread's MTA at open and
 * used from the worker thread, which joins the same process MTA - both legal in
 * the multi-threaded apartment, no marshalling.
 *
 * Loopback capture cannot use event-driven notifications, so BackendRead polls;
 * a high-resolution waitable timer keeps the poll wait near 2 ms (a plain
 * Sleep would round up to the ~15 ms system tick and add latency). */

#define DIRECTGATE_WASAPI_POLL_MS       2U    /* inter-poll wait while a frame fills */
#define DIRECTGATE_WASAPI_BUFFER_100NS  500000LL /* 50 ms shared capture buffer */
/* Freshest-audio cap: if the consumer briefly falls behind, drop the stale head
 * so latency never accumulates. 2 frames (~40 ms) keeps a small jitter margin.
 * With direct reads paced by the encoder this almost never triggers. */
#define DIRECTGATE_WASAPI_MAX_BACKLOG_FRAMES 2U
/* Carry buffer capacity (resampled S16 not yet returned): sized for a worst-case
 * loopback burst plus margin; the backlog cap keeps the live level tiny. */
#define DIRECTGATE_WASAPI_CARRY_FRAMES  32U

typedef struct directgate_wasapi_ {
    /* WASAPI objects (created in BackendOpen on the main thread's MTA). */
    IAudioClient *pClient;
    IAudioCaptureClient *pCapture;
    xbool_t bMainCom;              /* main-thread CoInitialize succeeded */

    /* Source mix format (resolved once at open). */
    uint32_t nInChannels;
    uint16_t nBits;
    xbool_t bFloat;
    double dRatio;                 /* input samples per 48 kHz output sample */

    /* Linear-resampler state + output carry, owned by the worker (BackendRead). */
    double dFrac;
    float fPrevL;
    float fPrevR;
    xbool_t bPrimed;
    int16_t *pCarry;               /* interleaved S16 awaiting return */
    uint32_t nCarryCap;
    uint32_t nCarryCount;

    /* Worker-thread one-time setup. */
    xbool_t bWorkerInit;
    xbool_t bWorkerCom;
    HANDLE hTimer;                 /* high-resolution poll timer */

    /* Real-time frame pacing. Unlike a PulseAudio monitor (which streams silence
     * as real samples at the sink rate), WASAPI loopback delivers nothing during
     * silence, so silent frames must be emitted on a wall clock or the audio
     * timeline would drift behind video the longer it stays quiet. */
    LONGLONG nQpcFreq;
    LONGLONG nNextDueQpc;
} directgate_wasapi_t;

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

static int16_t DirectGate_WASAPI_ClampS16(float fSample)
{
    float fScaled = fSample * 32767.0f;
    if (fScaled > 32767.0f) fScaled = 32767.0f;
    else if (fScaled < -32768.0f) fScaled = -32768.0f;
    return (int16_t)fScaled;
}

/* Appends one interleaved stereo pair to the carry, dropping the oldest if the
 * buffer is somehow full (the read-time backlog cap normally prevents this). */
static void DirectGate_WASAPI_CarryPush(directgate_wasapi_t *pCtx, int16_t nL, int16_t nR)
{
    if (pCtx->nCarryCount + 2U > pCtx->nCarryCap)
    {
        memmove(pCtx->pCarry, pCtx->pCarry + 2U, (size_t)(pCtx->nCarryCount - 2U) * sizeof(int16_t));
        pCtx->nCarryCount -= 2U;
    }

    pCtx->pCarry[pCtx->nCarryCount++] = nL;
    pCtx->pCarry[pCtx->nCarryCount++] = nR;
}

/* Resamples one input packet (mix rate) to 48 kHz stereo S16 into the carry. */
static void DirectGate_WASAPI_Resample(directgate_wasapi_t *pCtx, const BYTE *pData,
                                       uint32_t nFrames, xbool_t bSilent)
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
            fL = DirectGate_WASAPI_Sample(pData, i, 0, pCtx->nInChannels, pCtx->nBits, pCtx->bFloat);
            fR = (pCtx->nInChannels >= 2U)
                ? DirectGate_WASAPI_Sample(pData, i, 1, pCtx->nInChannels, pCtx->nBits, pCtx->bFloat)
                : fL;
        }

        if (!pCtx->bPrimed)
        {
            pCtx->fPrevL = fL;
            pCtx->fPrevR = fR;
            pCtx->bPrimed = XTRUE;
        }

        while (pCtx->dFrac < 1.0)
        {
            float t = (float)pCtx->dFrac;
            float oL = pCtx->fPrevL + (fL - pCtx->fPrevL) * t;
            float oR = pCtx->fPrevR + (fR - pCtx->fPrevR) * t;
            DirectGate_WASAPI_CarryPush(pCtx, DirectGate_WASAPI_ClampS16(oL), DirectGate_WASAPI_ClampS16(oR));
            pCtx->dFrac += pCtx->dRatio;
        }

        pCtx->dFrac -= 1.0;
        pCtx->fPrevL = fL;
        pCtx->fPrevR = fR;
    }
}

static void DirectGate_Audio_SetError(char *pErr, size_t nErrSize, const char *pFmt, ...)
{
    if (pErr == NULL || !nErrSize) return;
    va_list args;
    va_start(args, pFmt);
    vsnprintf(pErr, nErrSize, pFmt, args);
    va_end(args);
}

static int DirectGate_WASAPI_Open(directgate_wasapi_t *pCtx, char *pErr, size_t nErrSize)
{
    IMMDeviceEnumerator *pEnum = NULL;
    IMMDevice *pDevice = NULL;
    WAVEFORMATEX *pFmt = NULL;
    HRESULT hr;

    do
    {
        hr = CoCreateInstance(&CLSID_MMDeviceEnumerator, NULL, CLSCTX_ALL, &IID_IMMDeviceEnumerator, (void**)&pEnum);
        if (FAILED(hr)) { DirectGate_Audio_SetError(pErr, nErrSize, "no audio device enumerator."); break; }

        hr = pEnum->lpVtbl->GetDefaultAudioEndpoint(pEnum, eRender, eConsole, &pDevice);
        if (FAILED(hr)) { DirectGate_Audio_SetError(pErr, nErrSize, "no default output device."); break; }

        hr = pDevice->lpVtbl->Activate(pDevice, &IID_IAudioClient, CLSCTX_ALL, NULL, (void**)&pCtx->pClient);
        if (FAILED(hr)) { DirectGate_Audio_SetError(pErr, nErrSize, "failed to activate audio client."); break; }

        hr = pCtx->pClient->lpVtbl->GetMixFormat(pCtx->pClient, &pFmt);
        if (FAILED(hr) || pFmt == NULL) { DirectGate_Audio_SetError(pErr, nErrSize, "no mix format."); break; }

        pCtx->nInChannels = pFmt->nChannels ? pFmt->nChannels : 2U;
        pCtx->nBits = pFmt->wBitsPerSample ? pFmt->wBitsPerSample : 32U;
        pCtx->bFloat = DirectGate_WASAPI_IsFloat(pFmt);
        pCtx->dRatio = (double)pFmt->nSamplesPerSec / (double)DIRECTGATE_AUDIO_SAMPLE_RATE;
        if (pCtx->dRatio <= 0.0) pCtx->dRatio = 1.0;

        hr = pCtx->pClient->lpVtbl->Initialize(pCtx->pClient, AUDCLNT_SHAREMODE_SHARED,
            AUDCLNT_STREAMFLAGS_LOOPBACK, DIRECTGATE_WASAPI_BUFFER_100NS, 0, pFmt, NULL);
        if (FAILED(hr)) { DirectGate_Audio_SetError(pErr, nErrSize, "failed to initialise loopback capture."); break; }

        hr = pCtx->pClient->lpVtbl->GetService(pCtx->pClient, &IID_IAudioCaptureClient, (void**)&pCtx->pCapture);
        if (FAILED(hr)) { DirectGate_Audio_SetError(pErr, nErrSize, "no capture service."); break; }

        hr = pCtx->pClient->lpVtbl->Start(pCtx->pClient);
        if (FAILED(hr)) { DirectGate_Audio_SetError(pErr, nErrSize, "failed to start capture."); break; }

        CoTaskMemFree(pFmt);
        if (pDevice != NULL) pDevice->lpVtbl->Release(pDevice);
        if (pEnum != NULL) pEnum->lpVtbl->Release(pEnum);

        return XSTDOK;
    } while (0);

    if (pFmt != NULL) CoTaskMemFree(pFmt);
    if (pDevice != NULL) pDevice->lpVtbl->Release(pDevice);
    if (pEnum != NULL) pEnum->lpVtbl->Release(pEnum);

    if (pCtx->pCapture != NULL) { pCtx->pCapture->lpVtbl->Release(pCtx->pCapture); pCtx->pCapture = NULL; }
    if (pCtx->pClient != NULL) { pCtx->pClient->lpVtbl->Release(pCtx->pClient); pCtx->pClient = NULL; }
    return XSTDERR;
}

static void DirectGate_WASAPI_WorkerInit(directgate_wasapi_t *pCtx)
{
    pCtx->bWorkerInit = XTRUE;
    HANDLE hThread = GetCurrentThread();

    /* Join the process MTA so the worker can call the capture client that the
     * main thread created. No CoUninitialize: balanced by the thread exit. */
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    pCtx->bWorkerCom = (hr == S_OK || hr == S_FALSE) ? XTRUE : XFALSE;

#if defined(THREAD_POWER_THROTTLING_CURRENT_VERSION) && defined(THREAD_POWER_THROTTLING_EXECUTION_SPEED)
    THREAD_POWER_THROTTLING_STATE PowerThrottling;
    ZeroMemory(&PowerThrottling, sizeof(PowerThrottling));

    PowerThrottling.Version = THREAD_POWER_THROTTLING_CURRENT_VERSION;
    PowerThrottling.ControlMask = THREAD_POWER_THROTTLING_EXECUTION_SPEED;
    PowerThrottling.StateMask = 0;

    if (!SetThreadInformation(hThread, ThreadPowerThrottling, &PowerThrottling, sizeof(PowerThrottling)))
    {
        xlogw("Failed to configure audio capture thread as HighQoS: err(%lu)",
            (unsigned long)GetLastError());
    }
#endif

    /* Prevent Windows from applying execution-speed power throttling
     * to the latency-sensitive desktop capture thread. */
    DWORD nPriorityClass = GetPriorityClass(GetCurrentProcess());
    int nThreadPriority = THREAD_PRIORITY_ABOVE_NORMAL;

    if (nPriorityClass == NORMAL_PRIORITY_CLASS)
    {
        /* HIGHEST is base priority 10 in NORMAL_PRIORITY_CLASS, but can become
         * excessively aggressive if the process priority class is raised. */
        nThreadPriority = THREAD_PRIORITY_HIGHEST;
    }

    if (!SetThreadPriority(hThread, nThreadPriority))
    {
        xlogw("Failed to configure audio capture thread priority: class(%lu), priority(%d), err(%lu)",
            (unsigned long)nPriorityClass, nThreadPriority, (unsigned long)GetLastError());
    }

    /* High-resolution timer so the poll wait is ~2 ms, not the ~15 ms a plain
     * Sleep rounds to. Falls back to a normal timer on pre-1803 Windows. */
    pCtx->hTimer = CreateWaitableTimerExW(NULL, NULL, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    if (pCtx->hTimer == NULL) pCtx->hTimer = CreateWaitableTimerW(NULL, FALSE, NULL);

    LARGE_INTEGER nFreq;
    if (QueryPerformanceFrequency(&nFreq)) pCtx->nQpcFreq = nFreq.QuadPart;
}

static LONGLONG DirectGate_WASAPI_QpcNow(void)
{
    LARGE_INTEGER n;
    QueryPerformanceCounter(&n);
    return n.QuadPart;
}

static void DirectGate_WASAPI_PollWait(directgate_wasapi_t *pCtx)
{
    if (pCtx->hTimer != NULL)
    {
        LARGE_INTEGER due;
        due.QuadPart = -(LONGLONG)DIRECTGATE_WASAPI_POLL_MS * 10000LL;

        if (SetWaitableTimer(pCtx->hTimer, &due, 0, NULL, NULL, FALSE))
        {
            WaitForSingleObject(pCtx->hTimer, DIRECTGATE_WASAPI_POLL_MS + 5U);
            return;
        }
    }

    Sleep(DIRECTGATE_WASAPI_POLL_MS);
}

void* DirectGate_Audio_BackendOpen(uint32_t nSampleRate, uint32_t nChannels, char *pErr, size_t nErrSize)
{
    (void)nSampleRate; /* always resampled to DIRECTGATE_AUDIO_SAMPLE_RATE */
    (void)nChannels;

    directgate_wasapi_t *pCtx = (directgate_wasapi_t*)calloc(1, sizeof(*pCtx));
    if (pCtx == NULL)
    {
        DirectGate_Audio_SetError(pErr, nErrSize, "Out of memory starting audio.");
        return NULL;
    }

    pCtx->nCarryCap = DIRECTGATE_WASAPI_CARRY_FRAMES * DIRECTGATE_AUDIO_FRAME_SAMPLES * DIRECTGATE_AUDIO_CHANNELS;
    pCtx->pCarry = (int16_t*)malloc((size_t)pCtx->nCarryCap * sizeof(int16_t));
    if (pCtx->pCarry == NULL)
    {
        DirectGate_Audio_SetError(pErr, nErrSize, "Failed to allocate audio capture buffer.");
        free(pCtx);
        return NULL;
    }

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    pCtx->bMainCom = (hr == S_OK || hr == S_FALSE) ? XTRUE : XFALSE;

    char sWhy[128];
    sWhy[0] = '\0';

    if (DirectGate_WASAPI_Open(pCtx, sWhy, sizeof(sWhy)) != XSTDOK)
    {
        DirectGate_Audio_SetError(pErr, nErrSize, "Failed to open WASAPI loopback capture (%s).", sWhy[0] ? sWhy : "unknown error");
        DirectGate_Audio_BackendClose(pCtx);
        return NULL;
    }

    xlogi("Opened desktop audio WASAPI loopback (direct read): rate(%u), channels(%u)",
        DIRECTGATE_AUDIO_SAMPLE_RATE, DIRECTGATE_AUDIO_CHANNELS);

    return pCtx;
}

int DirectGate_Audio_BackendRead(void *pBackend, int16_t *pBuf, uint32_t nFrames, uint32_t nChannels)
{
    directgate_wasapi_t *pCtx = (directgate_wasapi_t*)pBackend;
    XCHECK((pCtx != NULL && pBuf != NULL), XSTDERR);
    XCHECK((nFrames > 0 && nChannels > 0), XSTDERR);

    if (!pCtx->bWorkerInit) DirectGate_WASAPI_WorkerInit(pCtx);

    uint32_t nNeeded = nFrames * nChannels;
    uint32_t nMaxBacklog = nNeeded * DIRECTGATE_WASAPI_MAX_BACKLOG_FRAMES;

    /* Real-time cadence: one frame every DIRECTGATE_AUDIO_FRAME_MS of wall time.
     * Returning on a wall-clock deadline (not just on data) makes silent frames
     * track real time, so the stream never drifts behind video during quiet
     * stretches - matching how a PulseAudio monitor paces silence. */
    LONGLONG nFrameTicks = pCtx->nQpcFreq ? (pCtx->nQpcFreq * (LONGLONG)DIRECTGATE_AUDIO_FRAME_MS) / 1000LL : 0;
    LONGLONG nNow = pCtx->nQpcFreq ? DirectGate_WASAPI_QpcNow() : 0;

    if (nFrameTicks > 0 && (pCtx->nNextDueQpc == 0 || pCtx->nNextDueQpc > nNow + 4 * nFrameTicks))
        pCtx->nNextDueQpc = nNow + nFrameTicks; /* (re)anchor the clock */

    /* Pull directly from the loopback endpoint (no lock: capture + resample both
     * run on this worker thread) until the frame is due. */
    for (;;)
    {
        UINT32 nPacket = 0;
        while (SUCCEEDED(pCtx->pCapture->lpVtbl->GetNextPacketSize(pCtx->pCapture, &nPacket)) && nPacket > 0)
        {
            BYTE *pData = NULL;
            UINT32 nAvail = 0;
            DWORD nFlags = 0;

            if (FAILED(pCtx->pCapture->lpVtbl->GetBuffer(pCtx->pCapture, &pData, &nAvail, &nFlags, NULL, NULL))) break;
            if (nAvail > 0) DirectGate_WASAPI_Resample(pCtx, pData, nAvail, (nFlags & AUDCLNT_BUFFERFLAGS_SILENT) ? XTRUE : XFALSE);
            pCtx->pCapture->lpVtbl->ReleaseBuffer(pCtx->pCapture, nAvail);
        }

        /* Keep only the freshest audio so latency never accumulates. */
        if (pCtx->nCarryCount > nMaxBacklog)
        {
            uint32_t nDrop = pCtx->nCarryCount - nMaxBacklog;
            memmove(pCtx->pCarry, pCtx->pCarry + nDrop, (size_t)(pCtx->nCarryCount - nDrop) * sizeof(int16_t));
            pCtx->nCarryCount -= nDrop;
        }

        if (nFrameTicks <= 0)
        {
            /* No high-res clock: fall back to data-or-one-frame-timeout. */
            if (pCtx->nCarryCount >= nNeeded) break;
        }
        else
        {
            nNow = DirectGate_WASAPI_QpcNow();
            if (nNow >= pCtx->nNextDueQpc) break; /* frame is due: return real audio or pad */
        }

        DirectGate_WASAPI_PollWait(pCtx);
        if (nFrameTicks <= 0 && pCtx->nCarryCount >= nNeeded) break;
    }

    /* Advance the deadline by exactly one frame; re-anchor if we fell behind
     * (a burst of real audio can push us past the due time). */
    if (nFrameTicks > 0)
    {
        pCtx->nNextDueQpc += nFrameTicks;
        nNow = DirectGate_WASAPI_QpcNow();
        if (pCtx->nNextDueQpc < nNow) pCtx->nNextDueQpc = nNow + nFrameTicks;
    }

    uint32_t nGot = (pCtx->nCarryCount < nNeeded) ? pCtx->nCarryCount : nNeeded;
    memcpy(pBuf, pCtx->pCarry, (size_t)nGot * sizeof(int16_t));
    if (pCtx->nCarryCount > nGot)
        memmove(pCtx->pCarry, pCtx->pCarry + nGot, (size_t)(pCtx->nCarryCount - nGot) * sizeof(int16_t));
    pCtx->nCarryCount -= nGot;

    for (uint32_t i = nGot; i < nNeeded; i++) pBuf[i] = 0; /* silence pad */
    return XSTDOK;
}

void DirectGate_Audio_BackendClose(void *pBackend)
{
    directgate_wasapi_t *pCtx = (directgate_wasapi_t*)pBackend;
    if (pCtx == NULL) return;

    /* The worker has already joined by the time AudioStop calls this, so all
     * WASAPI objects (created on the main thread's MTA) are released here. */
    if (pCtx->pClient != NULL) pCtx->pClient->lpVtbl->Stop(pCtx->pClient);
    if (pCtx->pCapture != NULL) pCtx->pCapture->lpVtbl->Release(pCtx->pCapture);
    if (pCtx->pClient != NULL) pCtx->pClient->lpVtbl->Release(pCtx->pClient);
    if (pCtx->hTimer != NULL) CloseHandle(pCtx->hTimer);
    if (pCtx->bMainCom) CoUninitialize();

    free(pCtx->pCarry);
    free(pCtx);
}

#endif /* DIRECTGATE_DESKTOP_HAS_AUDIO */
