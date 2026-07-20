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
#include <unistd.h>

/* libpulse-simple is dlopen'd at runtime (like OpenH264 and libopus): the
 * agent must keep streaming video on hosts without PulseAudio/PipeWire. The
 * blocking simple API is all we need - the special "@DEFAULT_MONITOR@" device
 * resolves to the default sink's monitor source on both PulseAudio and the
 * PipeWire pulse shim, so no async introspection is required. Capturing a
 * monitor source never touches a microphone. */

typedef struct pa_simple pa_simple;

/* pa_sample_spec / pa_buffer_attr have a frozen ABI; declare only what we set.
 * PA_SAMPLE_S16LE == 3, PA_STREAM_RECORD == 2 (pulse/sample.h, pulse/def.h). */
#define DG_PA_SAMPLE_S16LE   3
#define DG_PA_STREAM_RECORD  2

typedef struct dg_pa_sample_spec_ {
    int format;
    uint32_t rate;
    uint8_t channels;
} dg_pa_sample_spec;

typedef struct dg_pa_buffer_attr_ {
    uint32_t maxlength;
    uint32_t tlength;
    uint32_t prebuf;
    uint32_t minreq;
    uint32_t fragsize;
} dg_pa_buffer_attr;

typedef pa_simple* (*dg_pa_simple_new_fn)(const char*, const char*, int, const char*,
    const char*, const dg_pa_sample_spec*, const void*, const dg_pa_buffer_attr*, int*);
typedef int  (*dg_pa_simple_read_fn)(pa_simple*, void*, size_t, int*);
typedef void (*dg_pa_simple_free_fn)(pa_simple*);
typedef const char* (*dg_pa_strerror_fn)(int);

static struct directgate_pulse_lib_ {
    void *pSimpleLib;
    void *pPulseLib;
    dg_pa_simple_new_fn  simpleNew;
    dg_pa_simple_read_fn simpleRead;
    dg_pa_simple_free_fn simpleFree;
    dg_pa_strerror_fn    strError;
    xbool_t bLoadAttempted;
    xbool_t bLoaded;
} g_pulse;

static const char *g_pSimpleNames[] = { "libpulse-simple.so.0", "libpulse-simple.so", NULL };
static const char *g_pPulseNames[]  = { "libpulse.so.0", "libpulse.so", NULL };

static void DirectGate_Audio_SetError(char *pErr, size_t nErrSize, const char *pFmt, ...)
{
    if (pErr == NULL || !nErrSize) return;
    va_list args;
    va_start(args, pFmt);
    vsnprintf(pErr, nErrSize, pFmt, args);
    va_end(args);
}

static int DirectGate_Audio_LoadPulse(char *pErr, size_t nErrSize)
{
    struct directgate_pulse_lib_ *pLib = &g_pulse;
    if (pLib->bLoadAttempted)
    {
        if (pLib->bLoaded) return XSTDOK;
        DirectGate_Audio_SetError(pErr, nErrSize, "PulseAudio client library is not available (install libpulse).");
        return XSTDERR;
    }

    pLib->bLoadAttempted = XTRUE;

    for (int i = 0; pLib->pSimpleLib == NULL && g_pSimpleNames[i] != NULL; i++)
        pLib->pSimpleLib = dlopen(g_pSimpleNames[i], RTLD_NOW | RTLD_GLOBAL);
    for (int i = 0; pLib->pPulseLib == NULL && g_pPulseNames[i] != NULL; i++)
        pLib->pPulseLib = dlopen(g_pPulseNames[i], RTLD_NOW | RTLD_GLOBAL);

    if (pLib->pSimpleLib == NULL)
    {
        DirectGate_Audio_SetError(pErr, nErrSize, "PulseAudio client library is not available (install libpulse).");
        return XSTDERR;
    }

    pLib->simpleNew  = (dg_pa_simple_new_fn)dlsym(pLib->pSimpleLib, "pa_simple_new");
    pLib->simpleRead = (dg_pa_simple_read_fn)dlsym(pLib->pSimpleLib, "pa_simple_read");
    pLib->simpleFree = (dg_pa_simple_free_fn)dlsym(pLib->pSimpleLib, "pa_simple_free");
    if (pLib->pPulseLib != NULL) pLib->strError = (dg_pa_strerror_fn)dlsym(pLib->pPulseLib, "pa_strerror");

    if (pLib->simpleNew == NULL || pLib->simpleRead == NULL || pLib->simpleFree == NULL)
    {
        DirectGate_Audio_SetError(pErr, nErrSize, "PulseAudio client library is missing required symbols.");
        return XSTDERR;
    }

    pLib->bLoaded = XTRUE;
    xlogi("Loaded PulseAudio client library for desktop audio capture");
    return XSTDOK;
}

void* DirectGate_Audio_BackendOpen(uint32_t nSampleRate, uint32_t nChannels,
                                   char *pErr, size_t nErrSize)
{
    if (DirectGate_Audio_LoadPulse(pErr, nErrSize) != XSTDOK)
        return NULL;

    dg_pa_sample_spec spec;
    spec.format = DG_PA_SAMPLE_S16LE;
    spec.rate = nSampleRate;
    spec.channels = (uint8_t)nChannels;

    /* Small fragment (one frame) for low capture latency; leave the rest at the
     * server default (-1). */
    dg_pa_buffer_attr attr;
    attr.maxlength = (uint32_t)-1;
    attr.tlength = (uint32_t)-1;
    attr.prebuf = (uint32_t)-1;
    attr.minreq = (uint32_t)-1;
    attr.fragsize = DIRECTGATE_AUDIO_FRAME_SAMPLES * nChannels * (uint32_t)sizeof(int16_t);

    const char *pDevice = getenv("DIRECTGATE_AUDIO_SOURCE");
    if (!xstrused(pDevice)) pDevice = "@DEFAULT_MONITOR@";

    char sRuntimeDir[128];
    const char *pRuntimeDir = getenv("XDG_RUNTIME_DIR");

    if (!xstrused(pRuntimeDir))
    {
        snprintf(sRuntimeDir, sizeof(sRuntimeDir), "/run/user/%u", (unsigned)getuid());
        pRuntimeDir = sRuntimeDir;
        setenv("XDG_RUNTIME_DIR", pRuntimeDir, 0);
    }

    char sServer[192];
    const char *pServer = getenv("DIRECTGATE_AUDIO_SERVER");
    if (!xstrused(pServer))
    {
        if (xstrused(getenv("PULSE_SERVER")))
        {
            /* libpulse reads PULSE_SERVER itself */
            pServer = NULL;
        }
        else
        {
            snprintf(sServer, sizeof(sServer), "unix:%s/pulse/native", pRuntimeDir);
            pServer = sServer;
        }
    }

    int nError = 0;
    pa_simple *pSimple = g_pulse.simpleNew(pServer, "directgate", DG_PA_STREAM_RECORD,
        pDevice, "desktop", &spec, NULL, &attr, &nError);

    if (pSimple == NULL)
    {
        DirectGate_Audio_SetError(pErr, nErrSize, "Failed to open system audio source %s via %s (%s).",
            pDevice, xstrused(pServer) ? pServer : "default server",
            (g_pulse.strError != NULL) ? g_pulse.strError(nError) : "error");

        return NULL;
    }

    xlogi("Opened desktop audio monitor source: device(%s), server(%s), rate(%u), channels(%u)",
        pDevice, xstrused(pServer) ? pServer : "default", nSampleRate, nChannels);

    return (void*)pSimple;
}

int DirectGate_Audio_BackendRead(void *pBackend, int16_t *pBuf,
                                 uint32_t nFrames, uint32_t nChannels)
{
    XCHECK((pBackend != NULL && pBuf != NULL), XSTDERR);
    XCHECK((nFrames > 0 && nChannels > 0), XSTDERR);

    size_t nBytes = (size_t)nFrames * nChannels * sizeof(int16_t);
    int nError = 0;
    if (g_pulse.simpleRead((pa_simple*)pBackend, pBuf, nBytes, &nError) < 0)
    {
        xlogw("Desktop audio read failed: %s",
            (g_pulse.strError != NULL) ? g_pulse.strError(nError) : "error");
        return XSTDERR;
    }

    return XSTDOK;
}

void DirectGate_Audio_BackendClose(void *pBackend)
{
    if (pBackend != NULL && g_pulse.simpleFree != NULL)
        g_pulse.simpleFree((pa_simple*)pBackend);
}

#endif /* DIRECTGATE_DESKTOP_HAS_AUDIO */
