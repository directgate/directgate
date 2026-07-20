/*!
 * @file directgate-agent/src/agent/desktop/opus.c
 * @brief Runtime-loaded Opus audio encoder wrapper for desktop streaming.
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

#include "opus.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

/* ---- minimal libopus ABI ------------------------------------------------
 * libopus exposes a small, long-stable C ABI. Rather than vendoring the
 * upstream header tree (as OpenH264 needs for its version-sensitive frame
 * structs), declare only the symbols and CTL request codes the encoder uses.
 * Values are from opus_defines.h and are ABI-frozen across every 1.x release. */
typedef struct DirectGateOpusEncoder DirectGateOpusEncoder;

typedef DirectGateOpusEncoder* (*directgate_opus_create_fn)(int32_t, int, int, int*);
typedef void (*directgate_opus_destroy_fn)(DirectGateOpusEncoder*);
typedef int32_t(*directgate_opus_encode_fn)(DirectGateOpusEncoder*, const int16_t*, int, unsigned char*, int32_t);
typedef int (*directgate_opus_ctl_fn)(DirectGateOpusEncoder*, int, ...);
typedef const char* (*directgate_opus_strerror_fn)(int);
typedef const char* (*directgate_opus_version_fn)(void);

#define DIRECTGATE_OPUS_OK                       0
#define DIRECTGATE_OPUS_APPLICATION_AUDIO        2049
#define DIRECTGATE_OPUS_APPLICATION_LOWDELAY     2051
#define DIRECTGATE_OPUS_SIGNAL_MUSIC             3002
#define DIRECTGATE_OPUS_SET_BITRATE_REQUEST      4002
#define DIRECTGATE_OPUS_SET_VBR_REQUEST          4006
#define DIRECTGATE_OPUS_SET_COMPLEXITY_REQUEST   4010
#define DIRECTGATE_OPUS_SET_INBAND_FEC_REQUEST   4012
#define DIRECTGATE_OPUS_SET_PACKET_LOSS_PERC_REQUEST 4014
#define DIRECTGATE_OPUS_SET_DTX_REQUEST          4016
#define DIRECTGATE_OPUS_SET_SIGNAL_REQUEST       4024
#define DIRECTGATE_OPUS_GET_LOOKAHEAD_REQUEST    4027
#define DIRECTGATE_OPUS_SET_LSB_DEPTH_REQUEST    4036

typedef struct directgate_opus_lib_ {
    void *pHandle;
    directgate_opus_create_fn createEncoder;
    directgate_opus_destroy_fn destroyEncoder;
    directgate_opus_encode_fn encode;
    directgate_opus_ctl_fn ctl;
    directgate_opus_strerror_fn strError;
    directgate_opus_version_fn version;
    char sVersion[64];
    xbool_t bLoadAttempted;
    xbool_t bLoaded;
} directgate_opus_lib_t;

struct directgate_opus_ {
    DirectGateOpusEncoder *pEncoder;
    uint32_t nSampleRate;
    uint32_t nChannels;
    uint32_t nLookahead;
};

static directgate_opus_lib_t g_opus;

/* Sonames libopus binary releases ship under, newest first. Windows uses the
 * plain "opus.dll"; macOS resolves the versioned dylib through dlopen too. */
static const char *g_pOpusNames[] = {
#ifdef _WIN32
    "opus.dll",
    "libopus-0.dll",
    "libopus.dll",
#elif defined(__APPLE__)
    "libopus.0.dylib",
    "libopus.dylib",
#else
    "libopus.so.0",
    "libopus.so",
#endif
    NULL
};

static void DirectGate_Opus_SetError(char *pErrBuf, size_t nErrSize, const char *pFmt, ...)
{
    if (pErrBuf == NULL || !nErrSize) return;
    va_list args;
    va_start(args, pFmt);
    vsnprintf(pErrBuf, nErrSize, pFmt, args);
    va_end(args);
}

#ifdef _WIN32
static void* DirectGate_Opus_DlOpen(const char *pName) { return (void*)LoadLibraryA(pName); }
static void* DirectGate_Opus_DlSym(void *pHandle, const char *pSym)
{ return (void*)GetProcAddress((HMODULE)pHandle, pSym); }
static void DirectGate_Opus_DlClose(void *pHandle) { if (pHandle) FreeLibrary((HMODULE)pHandle); }
#else
static void* DirectGate_Opus_DlOpen(const char *pName) { return dlopen(pName, RTLD_NOW | RTLD_LOCAL); }
static void* DirectGate_Opus_DlSym(void *pHandle, const char *pSym) { return dlsym(pHandle, pSym); }
static void DirectGate_Opus_DlClose(void *pHandle) { if (pHandle) dlclose(pHandle); }
#endif

int DirectGate_Opus_Load(char *pErrBuf, size_t nErrSize)
{
    directgate_opus_lib_t *pLib = &g_opus;
    if (pLib->bLoadAttempted)
    {
        if (pLib->bLoaded) return XSTDOK;
        DirectGate_Opus_SetError(pErrBuf, nErrSize,
            "Opus library is not available (install libopus or set DIRECTGATE_OPUS_LIB).");
        return XSTDERR;
    }

    pLib->bLoadAttempted = XTRUE;
    void *pHandle = NULL;
    const char *pLoadedName = NULL;

    const char *pEnvPath = getenv("DIRECTGATE_OPUS_LIB");
    if (xstrused(pEnvPath))
    {
        pHandle = DirectGate_Opus_DlOpen(pEnvPath);
        pLoadedName = pEnvPath;
        if (pHandle == NULL)
        {
            DirectGate_Opus_SetError(pErrBuf, nErrSize,
                "Failed to load Opus from DIRECTGATE_OPUS_LIB (%s).", pEnvPath);
            return XSTDERR;
        }
    }

    for (int i = 0; pHandle == NULL && g_pOpusNames[i] != NULL; i++)
    {
        pHandle = DirectGate_Opus_DlOpen(g_pOpusNames[i]);
        pLoadedName = g_pOpusNames[i];
    }

    if (pHandle == NULL)
    {
        DirectGate_Opus_SetError(pErrBuf, nErrSize, "Opus library is not available (install libopus or set DIRECTGATE_OPUS_LIB).");
        return XSTDERR;
    }

    pLib->createEncoder = (directgate_opus_create_fn)DirectGate_Opus_DlSym(pHandle, "opus_encoder_create");
    pLib->destroyEncoder = (directgate_opus_destroy_fn)DirectGate_Opus_DlSym(pHandle, "opus_encoder_destroy");
    pLib->encode = (directgate_opus_encode_fn)DirectGate_Opus_DlSym(pHandle, "opus_encode");
    pLib->ctl = (directgate_opus_ctl_fn)DirectGate_Opus_DlSym(pHandle, "opus_encoder_ctl");
    pLib->strError = (directgate_opus_strerror_fn)DirectGate_Opus_DlSym(pHandle, "opus_strerror");
    pLib->version = (directgate_opus_version_fn)DirectGate_Opus_DlSym(pHandle, "opus_get_version_string");

    if (pLib->createEncoder == NULL || pLib->destroyEncoder == NULL || pLib->encode == NULL || pLib->ctl == NULL)
    {
        DirectGate_Opus_SetError(pErrBuf, nErrSize, "Opus library %s is missing required encoder symbols.", pLoadedName);
        DirectGate_Opus_DlClose(pHandle);
        return XSTDERR;
    }

    pLib->pHandle = pHandle;
    pLib->bLoaded = XTRUE;
    const char *pVersion = (pLib->version != NULL) ? pLib->version() : NULL;
    xstrncpy(pLib->sVersion, sizeof(pLib->sVersion), xstrused(pVersion) ? pVersion : "libopus");

    xlogi("Loaded Opus encoder library: name(%s), version(%s)", pLoadedName, pLib->sVersion);
    return XSTDOK;
}

const char* DirectGate_Opus_Version(void)
{
    return g_opus.bLoaded ? g_opus.sVersion : "unloaded";
}

static int DirectGate_Opus_Ctl(directgate_opus_t *pEnc, int nRequest, int32_t nValue)
{
    /* Every CTL setter the encoder uses takes a single int32 argument. */
    return g_opus.ctl(pEnc->pEncoder, nRequest, nValue);
}

directgate_opus_t* DirectGate_Opus_Create(uint32_t nSampleRate,
                                          uint32_t nChannels,
                                          uint32_t nBitrateKbps,
                                          char *pErrBuf,
                                          size_t nErrSize)
{
    XCHECK_NL((nSampleRate == 8000U || nSampleRate == 12000U || nSampleRate == 16000U ||
               nSampleRate == 24000U || nSampleRate == 48000U), NULL);
    XCHECK_NL((nChannels == 1U || nChannels == 2U), NULL);

    if (DirectGate_Opus_Load(pErrBuf, nErrSize) != XSTDOK)
        return NULL;

    directgate_opus_t *pEnc = (directgate_opus_t*)calloc(1, sizeof(*pEnc));
    if (pEnc == NULL)
    {
        DirectGate_Opus_SetError(pErrBuf, nErrSize, "Out of memory allocating Opus encoder.");
        return NULL;
    }

    int nError = DIRECTGATE_OPUS_OK;
    pEnc->pEncoder = g_opus.createEncoder((int32_t)nSampleRate, (int)nChannels, DIRECTGATE_OPUS_APPLICATION_AUDIO, &nError);

    if (pEnc->pEncoder == NULL || nError != DIRECTGATE_OPUS_OK)
    {
        DirectGate_Opus_SetError(pErrBuf, nErrSize, "opus_encoder_create failed (%s).",
            (g_opus.strError != NULL) ? g_opus.strError(nError) : "error");

        free(pEnc);
        return NULL;
    }

    pEnc->nSampleRate = nSampleRate;
    pEnc->nChannels = nChannels;

    uint32_t nBitrate = (nBitrateKbps ? nBitrateKbps : 128U) * 1000U;

    /* Tuned for interactive, continuous system audio: full VBR for fidelity,
     * music signal hint, in-band FEC so isolated packet loss is concealed
     * without retransmission latency, DTX off (system audio is continuous and
     * gaps would desync the RTP clock), and a moderate complexity that keeps
     * per-frame encode cost well under the 20 ms budget. */
    DirectGate_Opus_Ctl(pEnc, DIRECTGATE_OPUS_SET_BITRATE_REQUEST, (int32_t)nBitrate);
    DirectGate_Opus_Ctl(pEnc, DIRECTGATE_OPUS_SET_VBR_REQUEST, 1);
    DirectGate_Opus_Ctl(pEnc, DIRECTGATE_OPUS_SET_SIGNAL_REQUEST, DIRECTGATE_OPUS_SIGNAL_MUSIC);
    DirectGate_Opus_Ctl(pEnc, DIRECTGATE_OPUS_SET_INBAND_FEC_REQUEST, 1);
    DirectGate_Opus_Ctl(pEnc, DIRECTGATE_OPUS_SET_PACKET_LOSS_PERC_REQUEST, 5);
    DirectGate_Opus_Ctl(pEnc, DIRECTGATE_OPUS_SET_DTX_REQUEST, 0);
    DirectGate_Opus_Ctl(pEnc, DIRECTGATE_OPUS_SET_COMPLEXITY_REQUEST, 8);
    DirectGate_Opus_Ctl(pEnc, DIRECTGATE_OPUS_SET_LSB_DEPTH_REQUEST, 16);

    int32_t nLookahead = 0;
    if (g_opus.ctl(pEnc->pEncoder, DIRECTGATE_OPUS_GET_LOOKAHEAD_REQUEST, &nLookahead) == DIRECTGATE_OPUS_OK &&
        nLookahead > 0) pEnc->nLookahead = (uint32_t)nLookahead;

    xlogi("Created Opus encoder: rate(%u), channels(%u), bitrate(%ukbps), lookahead(%u)",
        nSampleRate, nChannels, nBitrate / 1000U, pEnc->nLookahead);

    return pEnc;
}

void DirectGate_Opus_Destroy(directgate_opus_t *pEnc)
{
    if (pEnc == NULL) return;
    if (pEnc->pEncoder != NULL && g_opus.destroyEncoder != NULL)
        g_opus.destroyEncoder(pEnc->pEncoder);
    free(pEnc);
}

int DirectGate_Opus_Encode(directgate_opus_t *pEnc,
                           const int16_t *pPcm,
                           uint32_t nFrameSamples,
                           uint8_t *pOut,
                           size_t nOutMax)
{
    XCHECK((pEnc != NULL && pEnc->pEncoder != NULL), XSTDERR);
    XCHECK((pPcm != NULL && pOut != NULL), XSTDERR);
    XCHECK((nFrameSamples > 0 && nOutMax > 0), XSTDERR);

    int32_t nBytes = g_opus.encode(pEnc->pEncoder, pPcm, (int)nFrameSamples, pOut, (int32_t)nOutMax);
    if (nBytes < 0)
    {
        xlogw("opus_encode failed: ret(%d, %s)", nBytes,
            (g_opus.strError != NULL) ? g_opus.strError(nBytes) : "error");
        return XSTDERR;
    }

    /* 0/1 bytes is a DTX/comfort-noise packet: nothing meaningful to send. */
    if (nBytes <= 1) return XSTDNON;
    return (int)nBytes;
}

int DirectGate_Opus_SetBitrate(directgate_opus_t *pEnc, uint32_t nBitrateKbps)
{
    XCHECK((pEnc != NULL && pEnc->pEncoder != NULL), XSTDERR);
    if (!nBitrateKbps) return XSTDNON;
    return (DirectGate_Opus_Ctl(pEnc, DIRECTGATE_OPUS_SET_BITRATE_REQUEST,
        (int32_t)(nBitrateKbps * 1000U)) == DIRECTGATE_OPUS_OK) ? XSTDOK : XSTDERR;
}

uint32_t DirectGate_Opus_GetLookahead(const directgate_opus_t *pEnc)
{
    return (pEnc != NULL) ? pEnc->nLookahead : 0U;
}

uint32_t DirectGate_Opus_GetSampleRate(const directgate_opus_t *pEnc)
{
    return (pEnc != NULL) ? pEnc->nSampleRate : 0U;
}

uint32_t DirectGate_Opus_GetChannels(const directgate_opus_t *pEnc)
{
    return (pEnc != NULL) ? pEnc->nChannels : 0U;
}
