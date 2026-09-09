/*!
 * @file directgate-agent/src/agent/desktop/audio_linux.c
 * @brief Linux system-audio capture backend (PulseAudio / PipeWire monitor).
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

#include <dlfcn.h>

/* Keep PulseAudio optional at runtime. These declarations are the stable
 * public libpulse ABI (pulse/{sample,def,mainloop,context,stream}.h). The
 * nonblocking mainloop avoids pa_simple_read's unbounded wait when a source
 * or server stops delivering samples. No PulseAudio callbacks retain us. */
typedef struct pa_mainloop pa_mainloop;
typedef struct pa_mainloop_api pa_mainloop_api;
typedef struct pa_context pa_context;
typedef struct pa_stream pa_stream;
typedef struct pa_spawn_api pa_spawn_api;
typedef struct pa_channel_map pa_channel_map;
typedef enum pa_sample_format { DG_PA_S16LE = 3 } pa_sample_format_t;
typedef enum pa_context_flags { DG_PA_NOAUTOSPAWN = 1 } pa_context_flags_t;
typedef enum pa_stream_flags { DG_PA_STREAM_NOFLAGS = 0 } pa_stream_flags_t;
typedef enum pa_context_state { DG_PA_CONTEXT_READY = 4 } pa_context_state_t;
typedef enum pa_stream_state { DG_PA_STREAM_READY = 2 } pa_stream_state_t;

typedef struct pa_sample_spec {
    pa_sample_format_t format;
    uint32_t rate;
    uint8_t channels;
} pa_sample_spec;

typedef struct pa_buffer_attr {
    uint32_t maxlength, tlength, prebuf, minreq, fragsize;
} pa_buffer_attr;

#define DG_PULSE_FUNCTIONS(X) \
    X(pa_mainloop*, mainloop_new, (void)) \
    X(void, mainloop_free, (pa_mainloop*)) \
    X(pa_mainloop_api*, mainloop_get_api, (pa_mainloop*)) \
    X(int, mainloop_iterate, (pa_mainloop*, int, int*)) \
    X(pa_context*, context_new, (pa_mainloop_api*, const char*)) \
    X(int, context_connect, (pa_context*, const char*, pa_context_flags_t, const pa_spawn_api*)) \
    X(pa_context_state_t, context_get_state, (const pa_context*)) \
    X(void, context_disconnect, (pa_context*)) \
    X(void, context_unref, (pa_context*)) \
    X(pa_stream*, stream_new, (pa_context*, const char*, const pa_sample_spec*, const pa_channel_map*)) \
    X(int, stream_connect_record, (pa_stream*, const char*, const pa_buffer_attr*, pa_stream_flags_t)) \
    X(pa_stream_state_t, stream_get_state, (const pa_stream*)) \
    X(int, stream_peek, (pa_stream*, const void**, size_t*)) \
    X(int, stream_drop, (pa_stream*)) \
    X(int, stream_disconnect, (pa_stream*)) \
    X(void, stream_unref, (pa_stream*))

#define DG_PULSE_DECLARE(ret, name, args) ret (*name) args;
static struct directgate_pulse_lib_ {
    void *pLib;
    xbool_t bLoadAttempted;
    xbool_t bLoaded;
    DG_PULSE_FUNCTIONS(DG_PULSE_DECLARE)
} g_pulse;
#undef DG_PULSE_DECLARE

typedef struct directgate_pulse_ {
    pa_mainloop *pLoop;
    pa_context *pContext;
    pa_stream *pStream;
    const void *pFragment;
    size_t nFragmentSize;
    size_t nFragmentOffset;
} directgate_pulse_t;

static void DirectGate_Audio_SetError(char *pErr, size_t nErrSize, const char *pReason)
{
    if (pErr != NULL && nErrSize)
        snprintf(pErr, nErrSize, "%s", pReason);
}

static int DirectGate_Audio_LoadPulse(char *pErr, size_t nErrSize)
{
    if (g_pulse.bLoaded) return XSTDOK;

    if (!g_pulse.bLoadAttempted)
    {
        g_pulse.bLoadAttempted = XTRUE;
        g_pulse.pLib = dlopen("libpulse.so.0", RTLD_NOW | RTLD_LOCAL);

        if (g_pulse.pLib == NULL) g_pulse.pLib = dlopen("libpulse.so", RTLD_NOW | RTLD_LOCAL);
        if (g_pulse.pLib != NULL)
        {
            xbool_t bComplete = XTRUE;
            /* POSIX guarantees dlsym function addresses are representable.
             * memcpy avoids type-punning a function-pointer lvalue. */
#define DG_PULSE_LOAD(ret, name, args) do { \
                void *pSymbol = dlsym(g_pulse.pLib, "pa_" #name); \
                _Static_assert(sizeof(pSymbol) == sizeof(g_pulse.name), "dlsym pointer size"); \
                memcpy(&g_pulse.name, &pSymbol, sizeof(pSymbol)); \
                if (pSymbol == NULL) bComplete = XFALSE; \
            } while (0);
            DG_PULSE_FUNCTIONS(DG_PULSE_LOAD)
#undef DG_PULSE_LOAD
            if (bComplete)
            {
                g_pulse.bLoaded = XTRUE;
                return XSTDOK;
            }

            dlclose(g_pulse.pLib);
            g_pulse.pLib = NULL;
        }
    }

    DirectGate_Audio_SetError(pErr, nErrSize, "PulseAudio client library is unavailable or missing required symbols.");
    return XSTDERR;
}
#undef DG_PULSE_FUNCTIONS

static uint64_t DirectGate_Audio_MonotonicUs(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (uint64_t)now.tv_sec * 1000000ULL + (uint64_t)now.tv_nsec / 1000U;
}

/* One nonblocking dispatch, followed by at most 2ms sleep when idle. Returns
 * XSTDNON on deadline, XSTDERR on a failed server/mainloop. */
static int DirectGate_Audio_PulseStep(directgate_pulse_t *pCtx, uint64_t nDeadline)
{
    uint64_t nNow = DirectGate_Audio_MonotonicUs();
    if (!nNow) return XSTDERR;
    if (nNow >= nDeadline) return XSTDNON;

    int nEvents = g_pulse.mainloop_iterate(pCtx->pLoop, 0, NULL);
    if (nEvents < 0 || g_pulse.context_get_state(pCtx->pContext) > DG_PA_CONTEXT_READY) return XSTDERR;

    if (nEvents == 0)
    {
        nNow = DirectGate_Audio_MonotonicUs();
        if (nNow < nDeadline)
            xusleep((unsigned int)((nDeadline - nNow < 2000U) ? nDeadline - nNow : 2000U));
    }

    return XSTDOK;
}

void DirectGate_Audio_BackendClose(void *pBackend)
{
    directgate_pulse_t *pCtx = pBackend;
    if (pCtx == NULL) return;

    if (pCtx->pStream != NULL)
    {
        g_pulse.stream_disconnect(pCtx->pStream);
        g_pulse.stream_unref(pCtx->pStream);
    }

    if (pCtx->pContext != NULL)
    {
        g_pulse.context_disconnect(pCtx->pContext);
        g_pulse.context_unref(pCtx->pContext);
    }

    if (pCtx->pLoop != NULL) g_pulse.mainloop_free(pCtx->pLoop);
    free(pCtx);
}

void* DirectGate_Audio_BackendOpen(uint32_t nSampleRate, uint32_t nChannels, char *pErr, size_t nErrSize)
{
    if (nSampleRate != DIRECTGATE_AUDIO_SAMPLE_RATE || nChannels != DIRECTGATE_AUDIO_CHANNELS)
    {
        DirectGate_Audio_SetError(pErr, nErrSize, "Unsupported system audio capture format.");
        return NULL;
    }

    if (DirectGate_Audio_LoadPulse(pErr, nErrSize) != XSTDOK) return NULL;
    directgate_pulse_t *pCtx = calloc(1, sizeof(*pCtx));
    do
    {
        if (pCtx == NULL) break;

        pCtx->pLoop = g_pulse.mainloop_new();
        if (pCtx->pLoop == NULL) break;

        pCtx->pContext = g_pulse.context_new(g_pulse.mainloop_get_api(pCtx->pLoop), "directgate");
        if (pCtx->pContext == NULL) break;

        const char *pDevice = getenv("DIRECTGATE_AUDIO_SOURCE");
        if (!xstrused(pDevice)) pDevice = "@DEFAULT_MONITOR@";

        const char *pServer = getenv("DIRECTGATE_AUDIO_SERVER");
        char sServer[4096];

        if (!xstrused(pServer))
        {
            pServer = NULL; /* honor PULSE_SERVER when provided */
            if (!xstrused(getenv("PULSE_SERVER")))
            {
                const char *pRuntime = getenv("XDG_RUNTIME_DIR");
                int n = xstrused(pRuntime)
                    ? snprintf(sServer, sizeof(sServer), "unix:%s/pulse/native", pRuntime)
                    : snprintf(sServer, sizeof(sServer), "unix:/run/user/%u/pulse/native", (unsigned)getuid());
                if (n < 0 || (size_t)n >= sizeof(sServer)) break;
                pServer = sServer;
            }
        }
        uint64_t nNow = DirectGate_Audio_MonotonicUs();
        if (!nNow) break;

        uint64_t nDeadline = nNow + 3000000ULL;
        if (g_pulse.context_connect(pCtx->pContext, pServer, DG_PA_NOAUTOSPAWN, NULL) < 0) break;
        int nStatus = XSTDOK;

        while (g_pulse.context_get_state(pCtx->pContext) != DG_PA_CONTEXT_READY)
        {
            nStatus = DirectGate_Audio_PulseStep(pCtx, nDeadline);
            if (nStatus != XSTDOK) break;
        }

        if (nStatus != XSTDOK) break;

        pa_sample_spec spec = { DG_PA_S16LE, nSampleRate, (uint8_t)nChannels };
        pa_buffer_attr attr = { UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX,
            DIRECTGATE_AUDIO_FRAME_SAMPLES * nChannels * (uint32_t)sizeof(int16_t) };

        attr.maxlength = attr.fragsize * 4U;
        pCtx->pStream = g_pulse.stream_new(pCtx->pContext, "desktop", &spec, NULL);

        if (pCtx->pStream == NULL ||
            g_pulse.stream_connect_record(pCtx->pStream, pDevice, &attr, DG_PA_STREAM_NOFLAGS) < 0) break;

        while (g_pulse.stream_get_state(pCtx->pStream) != DG_PA_STREAM_READY)
        {
            if (g_pulse.stream_get_state(pCtx->pStream) > DG_PA_STREAM_READY)
            {
                nStatus = XSTDERR;
                break;
            }

            nStatus = DirectGate_Audio_PulseStep(pCtx, nDeadline);
            if (nStatus != XSTDOK) break;
        }

        if (nStatus != XSTDOK) break;

        xlogi("Opened desktop audio monitor source: device(%s), server(%s), rate(%u), channels(%u)",
            pDevice, pServer ? pServer : "default", nSampleRate, nChannels);

        return pCtx;
    } while (0);

    DirectGate_Audio_BackendClose(pCtx);
    DirectGate_Audio_SetError(pErr, nErrSize, "System audio monitor is unavailable or connection timed out.");
    return NULL;
}

int DirectGate_Audio_BackendRead(void *pBackend, int16_t *pBuf, uint32_t nFrames, uint32_t nChannels)
{
    directgate_pulse_t *pCtx = pBackend;
    XCHECK((pCtx != NULL && pBuf != NULL), XSTDERR);
    XCHECK((nFrames > 0 && nFrames <= DIRECTGATE_AUDIO_FRAME_SAMPLES &&
            nChannels == DIRECTGATE_AUDIO_CHANNELS), XSTDERR);

    uint64_t nNow = DirectGate_Audio_MonotonicUs();
    if (!nNow) return XSTDERR;

    size_t nBytes = (size_t)nFrames * nChannels * sizeof(int16_t), nDone = 0;
    uint64_t nDeadline = nNow + (uint64_t)nFrames * 1000000ULL / DIRECTGATE_AUDIO_SAMPLE_RATE;

    while (nDone < nBytes)
    {
        if (g_pulse.context_get_state(pCtx->pContext) != DG_PA_CONTEXT_READY ||
            g_pulse.stream_get_state(pCtx->pStream) != DG_PA_STREAM_READY) return XSTDERR;

        if (pCtx->nFragmentSize == 0)
        {
            if (g_pulse.stream_peek(pCtx->pStream, &pCtx->pFragment, &pCtx->nFragmentSize) < 0)
                return XSTDERR;

            pCtx->nFragmentOffset = 0;
            if (pCtx->nFragmentSize == 0)
            {
                int nRet = DirectGate_Audio_PulseStep(pCtx, nDeadline);
                if (nRet == XSTDERR) return XSTDERR;
                if (nRet == XSTDNON) break;
                continue;
            }
        }

        size_t nTake = pCtx->nFragmentSize - pCtx->nFragmentOffset;
        if (nTake > nBytes - nDone) nTake = nBytes - nDone;

        if (pCtx->pFragment != NULL)
            memcpy((uint8_t*)pBuf + nDone, (const uint8_t*)pCtx->pFragment + pCtx->nFragmentOffset, nTake);
        else
            memset((uint8_t*)pBuf + nDone, 0, nTake); /* PulseAudio holes represent silence and must also be dropped. */

        nDone += nTake;
        pCtx->nFragmentOffset += nTake;

        if (pCtx->nFragmentOffset == pCtx->nFragmentSize)
        {
            pCtx->nFragmentSize = 0;
            pCtx->pFragment = NULL;
            if (g_pulse.stream_drop(pCtx->pStream) < 0) return XSTDERR;
        }
    }

    memset((uint8_t*)pBuf + nDone, 0, nBytes - nDone);
    return XSTDOK;
}

#endif /* DIRECTGATE_DESKTOP_HAS_AUDIO */
