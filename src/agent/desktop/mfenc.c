/*!
 * @file directgate-agent/src/agent/desktop/mfenc.c
 * @brief Runtime-loaded Media Foundation H.264 encoder wrapper for desktop streaming.
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

#include "mfenc.h"

#include <initguid.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mftransform.h>
#include <mferror.h>
#include <strmif.h>
#include <codecapi.h>

/* codecapi.h exposes the CODECAPI GUID values only through STATIC_ macros
 * in C mode (the named constants resolve via __uuidof and need C++), so the
 * handful used here are instantiated locally from those values. The
 * variadic indirection lets the STATIC_ macro expand into the eleven GUID
 * components before the inner macro collects them. */
#define DIRECTGATE_MFENC_GUID_(name, d1, d2, d3, b0, b1, b2, b3, b4, b5, b6, b7) \
    static const GUID name = { d1, d2, d3, { b0, b1, b2, b3, b4, b5, b6, b7 } }
#define DIRECTGATE_MFENC_GUID(name, ...) DIRECTGATE_MFENC_GUID_(name, __VA_ARGS__)

DIRECTGATE_MFENC_GUID(g_MFEncRateControlMode, STATIC_CODECAPI_AVEncCommonRateControlMode);
DIRECTGATE_MFENC_GUID(g_MFEncMeanBitRate, STATIC_CODECAPI_AVEncCommonMeanBitRate);
DIRECTGATE_MFENC_GUID(g_MFEncLowLatencyMode, STATIC_CODECAPI_AVLowLatencyMode);
DIRECTGATE_MFENC_GUID(g_MFEncCommonRealTime, STATIC_CODECAPI_AVEncCommonRealTime);
DIRECTGATE_MFENC_GUID(g_MFEncForceKeyFrame, STATIC_CODECAPI_AVEncVideoForceKeyFrame);
DIRECTGATE_MFENC_GUID(g_MFEncGopSize, STATIC_CODECAPI_AVEncMPVGOPSize);
DIRECTGATE_MFENC_GUID(g_MFEncBPictureCount, STATIC_CODECAPI_AVEncMPVDefaultBPictureCount);

/* How long Encode waits for the asynchronous MFT before giving up: an input
 * credit that never arrives means the encoder is wedged (XSTDERR feeds the
 * caller's failure counter), while missing output right after an input is
 * normal warm-up buffering (XSTDNON skips the frame). */
#define DIRECTGATE_MFENC_INPUT_WAIT_MS  250U
#define DIRECTGATE_MFENC_OUTPUT_WAIT_MS 100U

/* Poll interval while waiting for an MFT event credit. Sleep(1) cannot be
 * used here: it is quantised to the system timer period, which is ~15.6 ms
 * unless some other process happens to have raised the global resolution.
 * A hardware MFT answers in single-digit milliseconds, so that quantisation
 * alone would add up to a full 60 fps frame of latency to every encode and
 * cap the achievable frame rate at ~64. */
#define DIRECTGATE_MFENC_POLL_US        200ULL

/* Consecutive stalls tolerated from an encoder that has produced frames
 * before. One stall is a hiccup worth riding out; three in a row means the
 * encode session is gone and the frames are never coming back. */
#define DIRECTGATE_MFENC_MAX_STALLS 3

typedef HRESULT (WINAPI *directgate_mf_startup_fn)(ULONG, DWORD);
typedef HRESULT (WINAPI *directgate_mf_enum_fn)(GUID, UINT32,
    const MFT_REGISTER_TYPE_INFO*, const MFT_REGISTER_TYPE_INFO*,
    IMFActivate***, UINT32*);
typedef HRESULT (WINAPI *directgate_mf_create_type_fn)(IMFMediaType**);
typedef HRESULT (WINAPI *directgate_mf_create_sample_fn)(IMFSample**);
typedef HRESULT (WINAPI *directgate_mf_create_buffer_fn)(DWORD, IMFMediaBuffer**);

typedef struct directgate_mfplat_ {
    HMODULE hModule;
    directgate_mf_startup_fn startup;
    directgate_mf_enum_fn enumEx;
    directgate_mf_create_type_fn createMediaType;
    directgate_mf_create_sample_fn createSample;
    directgate_mf_create_buffer_fn createMemoryBuffer;
    xbool_t bLoadAttempted;
    xbool_t bLoaded;
} directgate_mfplat_t;

static directgate_mfplat_t g_mfplat;

struct directgate_mfenc_ {
    IMFTransform *pTransform;
    ICodecAPI *pCodecApi;                /* optional: dynamic bitrate / keyframe */
    IMFMediaEventGenerator *pEventGen;   /* asynchronous (hardware) MFTs only */
    DWORD nInputStreamId;
    DWORD nOutputStreamId;
    DWORD nOutputBufferSize;
    uint32_t nNeedInput;                 /* pending METransformNeedInput credits */
    uint32_t nHaveOutput;                /* pending METransformHaveOutput events */
    xbool_t bAsync;
    xbool_t bProvidesSamples;            /* MFT allocates its own output samples */
    xbool_t bBitrateLiveFailed;          /* dynamic bitrate rejected; logged once */
    /* Configuring proves nothing about a GPU encoder; only output does. Until
     * this is set the MFT is on trial and a single stall retires it. */
    xbool_t bProven;
    uint32_t nStallCount;                /* consecutive unanswered credit waits */
    uint32_t nWidth;
    uint32_t nHeight;
    uint32_t nFps;
    uint8_t *pSeqHeader;                 /* cached Annex-B SPS/PPS */
    size_t nSeqHeaderSize;
    HANDLE hPollTimer;                   /* sub-ms waits for MFT event credits */
    char sName[96];
    char sRawName[DIRECTGATE_MFENC_NAME_LEN]; /* MFT_FRIENDLY_NAME, reject key */
};

static void DirectGate_MFEnc_SetError(char *pErrBuf, size_t nErrSize, const char *pFmt, ...)
{
    if (pErrBuf == NULL || !nErrSize) return;
    va_list args;
    va_start(args, pFmt);
    vsnprintf(pErrBuf, nErrSize, pFmt, args);
    va_end(args);
}

int DirectGate_MFEnc_Load(char *pErrBuf, size_t nErrSize)
{
    directgate_mfplat_t *pLib = &g_mfplat;
    if (pLib->bLoadAttempted)
    {
        if (pLib->bLoaded) return XSTDOK;
        DirectGate_MFEnc_SetError(pErrBuf, nErrSize,
            "Media Foundation is not available on this Windows edition "
            "(N editions need the Media Feature Pack).");
        return XSTDERR;
    }

    pLib->bLoadAttempted = XTRUE;
    HMODULE hModule = LoadLibraryW(L"mfplat.dll");
    if (hModule == NULL)
    {
        DirectGate_MFEnc_SetError(pErrBuf, nErrSize,
            "Media Foundation is not available on this Windows edition "
            "(N editions need the Media Feature Pack).");
        return XSTDERR;
    }

    pLib->startup = (directgate_mf_startup_fn)(void*)GetProcAddress(hModule, "MFStartup");
    pLib->enumEx = (directgate_mf_enum_fn)(void*)GetProcAddress(hModule, "MFTEnumEx");
    pLib->createMediaType = (directgate_mf_create_type_fn)(void*)GetProcAddress(hModule, "MFCreateMediaType");
    pLib->createSample = (directgate_mf_create_sample_fn)(void*)GetProcAddress(hModule, "MFCreateSample");
    pLib->createMemoryBuffer = (directgate_mf_create_buffer_fn)(void*)GetProcAddress(hModule, "MFCreateMemoryBuffer");

    if (pLib->startup == NULL || pLib->enumEx == NULL ||
        pLib->createMediaType == NULL || pLib->createSample == NULL ||
        pLib->createMemoryBuffer == NULL)
    {
        FreeLibrary(hModule);
        DirectGate_MFEnc_SetError(pErrBuf, nErrSize, "mfplat.dll is missing required Media Foundation entry points.");
        return XSTDERR;
    }

    HRESULT hr = pLib->startup(MF_VERSION, MFSTARTUP_LITE);
    if (FAILED(hr))
    {
        FreeLibrary(hModule);
        DirectGate_MFEnc_SetError(pErrBuf, nErrSize, "MFStartup failed (hr=0x%08lX).", (unsigned long)hr);
        return XSTDERR;
    }

    /* Stays loaded and started for the process lifetime (like OpenH264). */
    pLib->hModule = hModule;
    pLib->bLoaded = XTRUE;
    return XSTDOK;
}

/* VT_UI4 / VT_BOOL setters for the optional ICodecAPI knobs. Every call is
 * best-effort: hardware MFTs support different subsets and a missing knob
 * must not fail encoder creation. */
static HRESULT DirectGate_MFEnc_SetCodecU32(directgate_mfenc_t *pEnc, const GUID *pGuid, uint32_t nValue)
{
    if (pEnc->pCodecApi == NULL) return E_NOINTERFACE;

    VARIANT var;
    VariantInit(&var);
    var.vt = VT_UI4;
    var.ulVal = nValue;
    return ICodecAPI_SetValue(pEnc->pCodecApi, pGuid, &var);
}

static HRESULT DirectGate_MFEnc_SetCodecBool(directgate_mfenc_t *pEnc, const GUID *pGuid, xbool_t bValue)
{
    if (pEnc->pCodecApi == NULL) return E_NOINTERFACE;

    VARIANT var;
    VariantInit(&var);
    var.vt = VT_BOOL;
    var.boolVal = bValue ? VARIANT_TRUE : VARIANT_FALSE;
    return ICodecAPI_SetValue(pEnc->pCodecApi, pGuid, &var);
}

/* Caches the Annex-B SPS/PPS blob the encoder attached to its output media
 * type; prepended to IDR payloads that arrive without in-band parameter
 * sets so every keyframe stays self-contained (matching OpenH264 and the
 * desktop_mac.m Annex-B emitter). */
static void DirectGate_MFEnc_CacheSeqHeader(directgate_mfenc_t *pEnc)
{
    IMFMediaType *pType = NULL;
    if (FAILED(IMFTransform_GetOutputCurrentType(pEnc->pTransform,
        pEnc->nOutputStreamId, &pType)) || pType == NULL) return;

    UINT32 nSize = 0;
    if (SUCCEEDED(IMFMediaType_GetBlobSize(pType, &MF_MT_MPEG_SEQUENCE_HEADER, &nSize)) && nSize > 0)
    {
        uint8_t *pBlob = (uint8_t*)malloc(nSize);
        if (pBlob != NULL && SUCCEEDED(IMFMediaType_GetBlob(pType, &MF_MT_MPEG_SEQUENCE_HEADER, pBlob, nSize, &nSize)))
        {
            free(pEnc->pSeqHeader);
            pEnc->pSeqHeader = pBlob;
            pEnc->nSeqHeaderSize = nSize;
        }
        else free(pBlob);
    }

    IMFMediaType_Release(pType);
}

/* True when the access unit already carries an SPS NAL before the first
 * slice (both 3- and 4-byte Annex-B start codes). */
static xbool_t DirectGate_MFEnc_HasParameterSets(const uint8_t *pData, size_t nSize)
{
    size_t i = 0;
    while (i + 4U < nSize)
    {
        if (pData[i] != 0 || pData[i + 1U] != 0)
        {
            i++;
            continue;
        }

        size_t nNal = 0;
        if (pData[i + 2U] == 1U) nNal = i + 3U;
        else if (pData[i + 2U] == 0 && pData[i + 3U] == 1U) nNal = i + 4U;
        else
        {
            i++;
            continue;
        }

        uint8_t nType = pData[nNal] & 0x1FU;
        if (nType == 7U) return XTRUE;               /* SPS */
        if (nType == 1U || nType == 5U) return XFALSE; /* slice before any SPS */
        i = nNal + 1U;
    }

    return XFALSE;
}

/* Builds an H.264 or NV12 video media type shared by the output/input
 * configuration below. */
static HRESULT DirectGate_MFEnc_BuildType(IMFMediaType **ppType, const GUID *pSubtype,
                                          uint32_t nWidth, uint32_t nHeight, uint32_t nFps)
{
    IMFMediaType *pType = NULL;
    HRESULT hr = g_mfplat.createMediaType(&pType);
    if (FAILED(hr)) return hr;

    IMFMediaType_SetGUID(pType, &MF_MT_MAJOR_TYPE, &MFMediaType_Video);
    IMFMediaType_SetGUID(pType, &MF_MT_SUBTYPE, pSubtype);
    IMFMediaType_SetUINT64(pType, &MF_MT_FRAME_SIZE, ((UINT64)nWidth << 32) | nHeight);
    IMFMediaType_SetUINT64(pType, &MF_MT_FRAME_RATE, ((UINT64)nFps << 32) | 1U);
    IMFMediaType_SetUINT32(pType, &MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);

    *ppType = pType;
    return S_OK;
}

/* Configures one activated MFT: async unlock, codec knobs, output then
 * input media type (that order is mandatory for encoders), streaming
 * start. Returns XSTDOK when the MFT is ready to encode. */
static int DirectGate_MFEnc_Configure(directgate_mfenc_t *pEnc,
                                      const directgate_desktop_quality_t *pQuality,
                                      char *pErrBuf, size_t nErrSize)
{
    IMFTransform *pTransform = pEnc->pTransform;
    uint32_t nBitrateKbps = pQuality->nBitrateKbps ? pQuality->nBitrateKbps : 4000U;
    uint32_t nKeyEvery = pQuality->nKeyframeFrames ? pQuality->nKeyframeFrames : 60U;
    xbool_t bLowLatency = (pQuality->ePreset == DIRECTGATE_DESKTOP_PRESET_LOW_LATENCY);

    IMFAttributes *pAttrs = NULL;
    if (SUCCEEDED(IMFTransform_GetAttributes(pTransform, &pAttrs)) && pAttrs != NULL)
    {
        UINT32 nAsync = 0;
        if (SUCCEEDED(IMFAttributes_GetUINT32(pAttrs, &MF_TRANSFORM_ASYNC, &nAsync)) && nAsync)
        {
            pEnc->bAsync = XTRUE;
            IMFAttributes_SetUINT32(pAttrs, &MF_TRANSFORM_ASYNC_UNLOCK, TRUE);
        }

        IMFAttributes_SetUINT32(pAttrs, &MF_LOW_LATENCY, TRUE);
        IMFAttributes_Release(pAttrs);
    }

    if (FAILED(IMFTransform_GetStreamIDs(pTransform, 1, &pEnc->nInputStreamId, 1, &pEnc->nOutputStreamId)))
    {
        /* E_NOTIMPL: the MFT uses fixed stream identifiers 0/0. */
        pEnc->nInputStreamId = 0;
        pEnc->nOutputStreamId = 0;
    }

    if (FAILED(IMFTransform_QueryInterface(pTransform, &IID_ICodecAPI, (void**)&pEnc->pCodecApi)))
        pEnc->pCodecApi = NULL;

    /* Interactive-latency knobs. CBR keeps frame sizes predictable for the
     * WebRTC pacer, B-frames would add a frame of reordering delay, and the
     * GOP mirrors the other platforms (recovery is PLI-driven, see
     * DirectGate_Desktop_ApplyPreset). */
    DirectGate_MFEnc_SetCodecU32(pEnc, &g_MFEncRateControlMode, eAVEncCommonRateControlMode_CBR);
    DirectGate_MFEnc_SetCodecU32(pEnc, &g_MFEncMeanBitRate, nBitrateKbps * 1000U);
    DirectGate_MFEnc_SetCodecBool(pEnc, &g_MFEncLowLatencyMode, XTRUE);
    DirectGate_MFEnc_SetCodecU32(pEnc, &g_MFEncBPictureCount, 0);
    DirectGate_MFEnc_SetCodecU32(pEnc, &g_MFEncGopSize, nKeyEvery);
    if (pQuality->bRealtime) DirectGate_MFEnc_SetCodecBool(pEnc, &g_MFEncCommonRealTime, XTRUE);

    IMFMediaType *pOutType = NULL;
    HRESULT hr = DirectGate_MFEnc_BuildType(&pOutType, &MFVideoFormat_H264, pEnc->nWidth, pEnc->nHeight, pEnc->nFps);
    if (FAILED(hr))
    {
        DirectGate_MFEnc_SetError(pErrBuf, nErrSize, "MFCreateMediaType failed (hr=0x%08lX).", (unsigned long)hr);
        return XSTDERR;
    }

    IMFMediaType_SetUINT32(pOutType, &MF_MT_AVG_BITRATE, nBitrateKbps * 1000U);
    /* Main+CABAC everywhere except low-latency, matching the profile choice
     * of the macOS VideoToolbox and Linux OpenH264 pipelines. */
    IMFMediaType_SetUINT32(pOutType, &MF_MT_MPEG2_PROFILE,
        bLowLatency ? eAVEncH264VProfile_Base : eAVEncH264VProfile_Main);

    hr = IMFTransform_SetOutputType(pTransform, pEnc->nOutputStreamId, pOutType, 0);
    IMFMediaType_Release(pOutType);

    if (FAILED(hr))
    {
        DirectGate_MFEnc_SetError(pErrBuf, nErrSize,
            "H.264 output type rejected: size(%ux%u), hr(0x%08lX)",
            pEnc->nWidth, pEnc->nHeight, (unsigned long)hr);

        return XSTDERR;
    }

    IMFMediaType *pInType = NULL;
    hr = DirectGate_MFEnc_BuildType(&pInType, &MFVideoFormat_NV12, pEnc->nWidth, pEnc->nHeight, pEnc->nFps);
    if (FAILED(hr))
    {
        DirectGate_MFEnc_SetError(pErrBuf, nErrSize,
            "MFCreateMediaType failed (hr=0x%08lX).", (unsigned long)hr);

        return XSTDERR;
    }

    hr = IMFTransform_SetInputType(pTransform, pEnc->nInputStreamId, pInType, 0);
    IMFMediaType_Release(pInType);

    if (FAILED(hr))
    {
        DirectGate_MFEnc_SetError(pErrBuf, nErrSize,
            "NV12 input type rejected: size(%ux%u), hr(0x%08lX)",
            pEnc->nWidth, pEnc->nHeight, (unsigned long)hr);

        return XSTDERR;
    }

    MFT_OUTPUT_STREAM_INFO streamInfo;
    memset(&streamInfo, 0, sizeof(streamInfo));

    if (SUCCEEDED(IMFTransform_GetOutputStreamInfo(pTransform, pEnc->nOutputStreamId, &streamInfo)))
        pEnc->bProvidesSamples = (streamInfo.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES) ? XTRUE : XFALSE;

    pEnc->nOutputBufferSize = streamInfo.cbSize ? streamInfo.cbSize :
        (DWORD)(pEnc->nWidth * pEnc->nHeight * 2U);

    if (pEnc->bAsync && FAILED(IMFTransform_QueryInterface(pTransform, &IID_IMFMediaEventGenerator, (void**)&pEnc->pEventGen)))
    {
        DirectGate_MFEnc_SetError(pErrBuf, nErrSize, "Asynchronous encoder MFT has no event generator.");
        return XSTDERR;
    }

    /* These two are what put an asynchronous MFT into the state where it
     * starts issuing input credits. Ignoring their result meant a refusal
     * here surfaced much later, and unrecognisably, as "credit timed out". */
    hr = IMFTransform_ProcessMessage(pTransform, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
    if (FAILED(hr))
    {
        DirectGate_MFEnc_SetError(pErrBuf, nErrSize,
            "MFT refused BEGIN_STREAMING: hr(0x%08lX)", (unsigned long)hr);

        return XSTDERR;
    }

    hr = IMFTransform_ProcessMessage(pTransform, MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
    if (FAILED(hr))
    {
        DirectGate_MFEnc_SetError(pErrBuf, nErrSize,
            "MFT refused START_OF_STREAM: hr(0x%08lX)", (unsigned long)hr);

        return XSTDERR;
    }

    DirectGate_MFEnc_CacheSeqHeader(pEnc);
    return XSTDOK;
}

static void DirectGate_MFEnc_ReleaseTransform(directgate_mfenc_t *pEnc)
{
    if (pEnc->pEventGen != NULL)
    {
        IMFMediaEventGenerator_Release(pEnc->pEventGen);
        pEnc->pEventGen = NULL;
    }

    if (pEnc->pCodecApi != NULL)
    {
        ICodecAPI_Release(pEnc->pCodecApi);
        pEnc->pCodecApi = NULL;
    }

    if (pEnc->pTransform != NULL)
    {
        IMFTransform_Release(pEnc->pTransform);
        pEnc->pTransform = NULL;
    }

    free(pEnc->pSeqHeader);
    pEnc->pSeqHeader = NULL;
    pEnc->nSeqHeaderSize = 0;
    pEnc->bAsync = XFALSE;
    pEnc->nNeedInput = 0;
    pEnc->nHaveOutput = 0;
}

static xbool_t DirectGate_MFEnc_IsRejected(const directgate_mfenc_rejects_t *pRejects,
                                           const char *pName)
{
    if (pRejects == NULL || !xstrused(pName)) return XFALSE;

    for (uint32_t i = 0; i < pRejects->nCount; i++)
    {
        if (xstrcmp(pRejects->names[i], pName)) return XTRUE;
    }

    return XFALSE;
}

static void DirectGate_MFEnc_ActivateName(IMFActivate *pActivate, char *pName, size_t nSize)
{
    WCHAR wsName[DIRECTGATE_MFENC_NAME_LEN] = { 0 };
    UINT32 nNameLen = 0;

    pName[0] = '\0';

    if (SUCCEEDED(IMFActivate_GetString(pActivate, &MFT_FRIENDLY_NAME_Attribute,
        wsName, (UINT32)(sizeof(wsName) / sizeof(wsName[0])), &nNameLen)) && nNameLen > 0)
        WideCharToMultiByte(CP_UTF8, 0, wsName, -1, pName, (int)nSize - 1, NULL, NULL);

    if (!pName[0]) xstrncpy(pName, nSize, "unnamed H.264 encoder MFT");
}

/* Tries every MFT the enumeration returned (best match first thanks to
 * MFT_ENUM_FLAG_SORTANDFILTER) until one activates and configures, skipping
 * any that a previous attempt retired. */
static int DirectGate_MFEnc_CreateFromCategory(directgate_mfenc_t *pEnc, UINT32 nFlags, xbool_t bHardware,
                                               const directgate_desktop_quality_t *pQuality,
                                               const directgate_mfenc_rejects_t *pRejects,
                                               char *pErrBuf, size_t nErrSize)
{
    MFT_REGISTER_TYPE_INFO inputInfo = { { 0 }, { 0 } };
    MFT_REGISTER_TYPE_INFO outputInfo = { { 0 }, { 0 } };
    inputInfo.guidMajorType = MFMediaType_Video;
    inputInfo.guidSubtype = MFVideoFormat_NV12;
    outputInfo.guidMajorType = MFMediaType_Video;
    outputInfo.guidSubtype = MFVideoFormat_H264;

    IMFActivate **ppActivate = NULL;
    UINT32 nCount = 0;

    HRESULT hr = g_mfplat.enumEx(MFT_CATEGORY_VIDEO_ENCODER,
        nFlags | MFT_ENUM_FLAG_SORTANDFILTER, &inputInfo, &outputInfo,
        &ppActivate, &nCount);

    if (FAILED(hr) || nCount == 0)
    {
        if (ppActivate != NULL) CoTaskMemFree(ppActivate);
        DirectGate_MFEnc_SetError(pErrBuf, nErrSize,
            "No %s H.264 encoder MFT is registered.", bHardware ? "hardware" : "software");
        return XSTDERR;
    }

    /* The whole inventory, before anything is chosen. Which encoders a machine
     * actually offers is the first question every encoder problem raises, and
     * the selection loop below cannot answer it: it stops at the first
     * candidate that works and never names the rest. */
    for (UINT32 i = 0; i < nCount; i++)
    {
        char sCandidate[DIRECTGATE_MFENC_NAME_LEN];
        DirectGate_MFEnc_ActivateName(ppActivate[i], sCandidate, sizeof(sCandidate));

        xlogi("Available %s H.264 encoder MFT: index(%u/%u), encoder(%s)",
            bHardware ? "hardware" : "software", i + 1U, nCount, sCandidate);
    }

    int nStatus = XSTDERR;
    UINT32 nRetired = 0, nUnreachable = 0, nRefused = 0;

    for (UINT32 i = 0; i < nCount && nStatus != XSTDOK; i++)
    {
        /* Read the name first: it is the key a previously-failed MFT is
         * remembered by, and skipping one must not cost an activation. */
        char sName[DIRECTGATE_MFENC_NAME_LEN];
        DirectGate_MFEnc_ActivateName(ppActivate[i], sName, sizeof(sName));

        if (DirectGate_MFEnc_IsRejected(pRejects, sName))
        {
            xlogw("Skipping H.264 encoder MFT that already failed: encoder(%s)", sName);
            nRetired++;
            continue;
        }

        /* Activation is where a hardware MFT that the process cannot reach
         * drops out - an encoder belonging to the GPU this process was not
         * assigned to, or one whose vendor-imposed concurrent session limit is
         * already used up. Passing over it silently made it look like the
         * candidate had never been in the list at all. */
        IMFTransform *pTransform = NULL;
        HRESULT hrActivate = IMFActivate_ActivateObject(ppActivate[i],
            &IID_IMFTransform, (void**)&pTransform);

        if (FAILED(hrActivate) || pTransform == NULL)
        {
            xlogw("H.264 encoder MFT could not be activated: encoder(%s), hr(0x%08lX)",
                sName, (unsigned long)hrActivate);

            nUnreachable++;
            continue;
        }

        pEnc->pTransform = pTransform;
        xstrncpy(pEnc->sRawName, sizeof(pEnc->sRawName), sName);
        snprintf(pEnc->sName, sizeof(pEnc->sName), "%s (%s)",
            bHardware ? "hardware" : "software", sName);

        nStatus = DirectGate_MFEnc_Configure(pEnc, pQuality, pErrBuf, nErrSize);
        if (nStatus != XSTDOK)
        {
            xlogw("H.264 encoder MFT rejected during setup: encoder(%s), reason(%s)",
                pEnc->sName, (pErrBuf != NULL && pErrBuf[0]) ? pErrBuf : "unspecified");

            DirectGate_MFEnc_ReleaseTransform(pEnc);
            IMFActivate_ShutdownObject(ppActivate[i]);

            pEnc->sRawName[0] = '\0';
            pEnc->sName[0] = '\0';
            nRefused++;
            continue;
        }

        xlogi("Selected H.264 encoder MFT: encoder(%s), size(%ux%u), fps(%u)",
            pEnc->sName, pEnc->nWidth, pEnc->nHeight, pEnc->nFps);
    }

    if (nStatus != XSTDOK)
    {
        /* "None registered" would be a lie here: candidates existed and every
         * one of them was tried. The breakdown says which wall each hit. */
        DirectGate_MFEnc_SetError(pErrBuf, nErrSize,
            "All %u %s H.264 encoder MFTs exhausted: retired(%u), unreachable(%u), refused(%u)",
            nCount, bHardware ? "hardware" : "software", nRetired, nUnreachable, nRefused);

        xlogw("Exhausted %s H.264 encoder MFTs: total(%u), retired(%u), unreachable(%u), refused(%u)",
            bHardware ? "hardware" : "software", nCount, nRetired, nUnreachable, nRefused);
    }

    for (UINT32 i = 0; i < nCount; i++)
        IMFActivate_Release(ppActivate[i]);

    CoTaskMemFree(ppActivate);
    return nStatus;
}

directgate_mfenc_t* DirectGate_MFEnc_Create(uint32_t nWidth, uint32_t nHeight,
                                            const directgate_desktop_quality_t *pQuality,
                                            const directgate_mfenc_rejects_t *pRejects,
                                            char *pErrBuf, size_t nErrSize)
{
    XCHECK_NL((pQuality != NULL), NULL);
    XCHECK_NL((nWidth >= 16 && nHeight >= 16), NULL);
    XCHECK_NL(((nWidth & 1U) == 0 && (nHeight & 1U) == 0), NULL);

    if (DirectGate_MFEnc_Load(pErrBuf, nErrSize) != XSTDOK)
        return NULL;

    directgate_mfenc_t *pEnc = (directgate_mfenc_t*)calloc(1, sizeof(*pEnc));
    if (pEnc == NULL)
    {
        DirectGate_MFEnc_SetError(pErrBuf, nErrSize, "Failed to allocate encoder context.");
        return NULL;
    }

    pEnc->nWidth = nWidth;
    pEnc->nHeight = nHeight;
    pEnc->nFps = pQuality->nFps ? pQuality->nFps : 30U;

    /* CREATE_WAITABLE_TIMER_HIGH_RESOLUTION (Win10 1803+) is what makes the
     * sub-millisecond credit polling actually sub-millisecond; older systems
     * fall back to yielding. */
    pEnc->hPollTimer = CreateWaitableTimerExW(NULL, NULL,
        CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);

    /* GPU vendor encoder first (Quick Sync / NVENC / AMF), Microsoft
     * software H.264 encoder as the fallback. Retired candidates are skipped,
     * so a re-create after a wedged encoder walks down this same order
     * instead of picking the liar again. */
    if (DirectGate_MFEnc_CreateFromCategory(pEnc, MFT_ENUM_FLAG_HARDWARE, XTRUE,
            pQuality, pRejects, pErrBuf, nErrSize) == XSTDOK ||
        DirectGate_MFEnc_CreateFromCategory(pEnc,
            MFT_ENUM_FLAG_SYNCMFT | MFT_ENUM_FLAG_ASYNCMFT | MFT_ENUM_FLAG_LOCALMFT,
            XFALSE, pQuality, pRejects, pErrBuf, nErrSize) == XSTDOK)
        return pEnc;

    if (pEnc->hPollTimer != NULL) CloseHandle(pEnc->hPollTimer);
    free(pEnc);
    return NULL;
}

void DirectGate_MFEnc_Destroy(directgate_mfenc_t *pEncoder)
{
    if (pEncoder == NULL) return;

    if (pEncoder->pTransform != NULL)
        IMFTransform_ProcessMessage(pEncoder->pTransform, MFT_MESSAGE_COMMAND_FLUSH, 0);

    DirectGate_MFEnc_ReleaseTransform(pEncoder);
    if (pEncoder->hPollTimer != NULL) CloseHandle(pEncoder->hPollTimer);
    free(pEncoder);
}

const char* DirectGate_MFEnc_Describe(const directgate_mfenc_t *pEncoder)
{
    if (pEncoder == NULL || !xstrused(pEncoder->sName)) return "unloaded";
    return pEncoder->sName;
}

/* Consumes one pending MFT event if any. Returns XSTDOK when an event was
 * processed, XSTDNON when the queue is empty, XSTDERR on failure. */
static int DirectGate_MFEnc_PumpEvent(directgate_mfenc_t *pEnc)
{
    IMFMediaEvent *pEvent = NULL;
    HRESULT hr = IMFMediaEventGenerator_GetEvent(pEnc->pEventGen,
        MF_EVENT_FLAG_NO_WAIT, &pEvent);
    if (hr == MF_E_NO_EVENTS_AVAILABLE) return XSTDNON;
    if (FAILED(hr) || pEvent == NULL) return XSTDERR;

    MediaEventType eType = MEUnknown;
    HRESULT hrStatus = S_OK;

    IMFMediaEvent_GetType(pEvent, &eType);
    IMFMediaEvent_GetStatus(pEvent, &hrStatus);
    IMFMediaEvent_Release(pEvent);

    if (eType == METransformNeedInput) pEnc->nNeedInput++;
    else if (eType == METransformHaveOutput) pEnc->nHaveOutput++;
    else if (eType == MEError)
    {
        /* The MFT's own explanation of why it went quiet. Discarding this is
         * what used to leave "credit timed out" as the only clue. */
        xloge("MF encoder reported an error event: encoder(%s), hr(0x%08lX)",
            pEnc->sName, (unsigned long)hrStatus);
    }
    else
    {
        xlogd("MF encoder event ignored: encoder(%s), event(%lu), hr(0x%08lX)",
            pEnc->sName, (unsigned long)eType, (unsigned long)hrStatus);
    }

    return XSTDOK;
}

/* Sub-millisecond backoff between event pumps. See
 * DIRECTGATE_MFENC_POLL_US for why Sleep() is not usable here. */
static void DirectGate_MFEnc_PollWait(directgate_mfenc_t *pEnc)
{
    if (pEnc->hPollTimer != NULL)
    {
        LARGE_INTEGER due;
        due.QuadPart = -(LONGLONG)(DIRECTGATE_MFENC_POLL_US * 10ULL); /* 100 ns units */

        if (SetWaitableTimer(pEnc->hPollTimer, &due, 0, NULL, NULL, FALSE) &&
            WaitForSingleObject(pEnc->hPollTimer, 2U) == WAIT_OBJECT_0) return;
    }

    /* No high-resolution timer (pre-1803, or handle creation failed): yield
     * the remaining slice rather than sleeping a whole timer period. */
    SwitchToThread();
}

/* Pumps until at least one credit of the requested kind is pending or the
 * deadline passes. pCounter points at nNeedInput or nHaveOutput. */
static int DirectGate_MFEnc_WaitCredit(directgate_mfenc_t *pEnc, const uint32_t *pCounter, uint32_t nTimeoutMs)
{
    ULONGLONG nDeadline = GetTickCount64() + nTimeoutMs;
    while (*pCounter == 0)
    {
        int nStatus = DirectGate_MFEnc_PumpEvent(pEnc);
        if (nStatus == XSTDERR) return XSTDERR;
        if (nStatus == XSTDOK) continue;
        if (GetTickCount64() >= nDeadline) return XSTDNON;
        DirectGate_MFEnc_PollWait(pEnc);
    }

    return XSTDOK;
}

/* Runs one ProcessOutput round and appends the produced access unit to
 * pOut (keyframes are made self-contained first). Returns XSTDOK on a
 * produced frame, XSTDNON when the MFT needs more input, XSTDERR on
 * failure. pPtsUs, when given, receives the timestamp the frame was
 * submitted with - the encoder carries it across, which is the only way a
 * drained frame can be timestamped correctly. */
static int DirectGate_MFEnc_ProcessOutput(directgate_mfenc_t *pEnc, xbyte_buffer_t *pOut,
                                          xbool_t *pKeyframe, uint64_t *pPtsUs)
{
    MFT_OUTPUT_DATA_BUFFER outputData;
    memset(&outputData, 0, sizeof(outputData));
    outputData.dwStreamID = pEnc->nOutputStreamId;

    IMFSample *pOwnSample = NULL;
    if (!pEnc->bProvidesSamples)
    {
        IMFMediaBuffer *pBuffer = NULL;
        if (FAILED(g_mfplat.createSample(&pOwnSample)) ||
            FAILED(g_mfplat.createMemoryBuffer(pEnc->nOutputBufferSize, &pBuffer)))
        {
            if (pOwnSample != NULL) IMFSample_Release(pOwnSample);
            return XSTDERR;
        }

        IMFSample_AddBuffer(pOwnSample, pBuffer);
        IMFMediaBuffer_Release(pBuffer);
        outputData.pSample = pOwnSample;
    }

    DWORD nStatus = 0;
    HRESULT hr = IMFTransform_ProcessOutput(pEnc->pTransform, 0, 1, &outputData, &nStatus);
    if (outputData.pEvents != NULL) IMFCollection_Release(outputData.pEvents);

    if (hr == MF_E_TRANSFORM_STREAM_CHANGE)
    {
        /* The encoder renegotiates its output type (typical for hardware
         * MFTs right after start). Accept the first offered type and let
         * the caller retry. */
        IMFMediaType *pType = NULL;
        if (SUCCEEDED(IMFTransform_GetOutputAvailableType(pEnc->pTransform,
            pEnc->nOutputStreamId, 0, &pType)) && pType != NULL)
        {
            IMFTransform_SetOutputType(pEnc->pTransform, pEnc->nOutputStreamId, pType, 0);
            IMFMediaType_Release(pType);
            DirectGate_MFEnc_CacheSeqHeader(pEnc);
        }

        if (pOwnSample != NULL) IMFSample_Release(pOwnSample);
        return XSTDNON;
    }

    if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT || FAILED(hr))
    {
        if (pOwnSample != NULL) IMFSample_Release(pOwnSample);
        return (hr == MF_E_TRANSFORM_NEED_MORE_INPUT) ? XSTDNON : XSTDERR;
    }

    IMFSample *pProduced = outputData.pSample;
    if (pProduced == NULL)
    {
        if (pOwnSample != NULL) IMFSample_Release(pOwnSample);
        return XSTDERR;
    }

    UINT32 nCleanPoint = 0;
    IMFSample_GetUINT32(pProduced, &MFSampleExtension_CleanPoint, &nCleanPoint);
    if (pKeyframe != NULL) *pKeyframe = nCleanPoint ? XTRUE : XFALSE;

    if (pPtsUs != NULL)
    {
        LONGLONG nSampleTime = 0;
        if (SUCCEEDED(IMFSample_GetSampleTime(pProduced, &nSampleTime)) && nSampleTime > 0)
            *pPtsUs = (uint64_t)nSampleTime / 10ULL; /* MF works in 100 ns units */
    }

    int nResult = XSTDERR;
    IMFMediaBuffer *pContiguous = NULL;

    if (SUCCEEDED(IMFSample_ConvertToContiguousBuffer(pProduced, &pContiguous)) && pContiguous != NULL)
    {
        BYTE *pData = NULL;
        DWORD nLength = 0;

        if (SUCCEEDED(IMFMediaBuffer_Lock(pContiguous, &pData, NULL, &nLength)) && pData != NULL && nLength > 0)
        {
            if (nCleanPoint && !DirectGate_MFEnc_HasParameterSets(pData, nLength))
            {
                if (pEnc->pSeqHeader == NULL) DirectGate_MFEnc_CacheSeqHeader(pEnc);
                if (pEnc->pSeqHeader != NULL)
                    XByteBuffer_Add(pOut, pEnc->pSeqHeader, pEnc->nSeqHeaderSize);
            }

            nResult = (XByteBuffer_Add(pOut, pData, nLength) > 0) ? XSTDOK : XSTDERR;
            IMFMediaBuffer_Unlock(pContiguous);
        }

        IMFMediaBuffer_Release(pContiguous);
    }

    if (pProduced != pOwnSample) IMFSample_Release(pProduced);
    if (pOwnSample != NULL) IMFSample_Release(pOwnSample);
    return nResult;
}

/* Wraps one tightly packed NV12 frame into an IMFSample (one copy: the MFT
 * keeps a reference to the buffer while encoding, so the caller's frame
 * buffer must stay reusable). */
static IMFSample* DirectGate_MFEnc_BuildInputSample(directgate_mfenc_t *pEnc, const uint8_t *pNV12, uint64_t nPtsUs)
{
    DWORD nFrameBytes = (DWORD)((size_t)pEnc->nWidth * pEnc->nHeight * 3U / 2U);
    IMFSample *pSample = NULL;
    IMFMediaBuffer *pBuffer = NULL;

    if (FAILED(g_mfplat.createSample(&pSample))) return NULL;
    if (FAILED(g_mfplat.createMemoryBuffer(nFrameBytes, &pBuffer)))
    {
        IMFSample_Release(pSample);
        return NULL;
    }

    BYTE *pData = NULL;
    if (FAILED(IMFMediaBuffer_Lock(pBuffer, &pData, NULL, NULL)) || pData == NULL)
    {
        IMFMediaBuffer_Release(pBuffer);
        IMFSample_Release(pSample);
        return NULL;
    }

    memcpy(pData, pNV12, nFrameBytes);
    IMFMediaBuffer_Unlock(pBuffer);
    IMFMediaBuffer_SetCurrentLength(pBuffer, nFrameBytes);
    IMFSample_AddBuffer(pSample, pBuffer);
    IMFMediaBuffer_Release(pBuffer);

    /* MF timestamps are in 100 ns units. */
    IMFSample_SetSampleTime(pSample, (LONGLONG)(nPtsUs * 10ULL));
    IMFSample_SetSampleDuration(pSample, (LONGLONG)(10000000ULL / (pEnc->nFps ? pEnc->nFps : 30U)));
    return pSample;
}

int DirectGate_MFEnc_Encode(directgate_mfenc_t *pEncoder,
                            const uint8_t *pNV12,
                            uint64_t nPtsUs,
                            xbool_t bForceKeyframe,
                            xbyte_buffer_t *pOut,
                            xbool_t *pKeyframe)
{
    XCHECK((pEncoder != NULL && pEncoder->pTransform != NULL), XSTDERR);
    XCHECK((pNV12 != NULL && pOut != NULL), XSTDERR);

    if (pKeyframe != NULL) *pKeyframe = XFALSE;
    pOut->nUsed = 0;

    if (bForceKeyframe)
        DirectGate_MFEnc_SetCodecU32(pEncoder, &g_MFEncForceKeyFrame, 1);

    IMFSample *pSample = DirectGate_MFEnc_BuildInputSample(pEncoder, pNV12, nPtsUs);
    if (pSample == NULL)
    {
        xloge("Failed to build MF input sample: size(%ux%u)",
            pEncoder->nWidth, pEncoder->nHeight);
        return XSTDERR;
    }

    if (pEncoder->bAsync)
    {
        /* Asynchronous (hardware) model: input goes in only against a
         * METransformNeedInput credit, output comes out only after a
         * METransformHaveOutput event. */
        int nStatus = DirectGate_MFEnc_WaitCredit(pEncoder, &pEncoder->nNeedInput, DIRECTGATE_MFENC_INPUT_WAIT_MS);
        if (nStatus != XSTDOK)
        {
            IMFSample_Release(pSample);
            pEncoder->nStallCount++;

            /* Two different failures used to share one message. XSTDERR means
             * the event queue itself broke; XSTDNON means the MFT simply never
             * asked for the frame. */
            if (nStatus == XSTDERR)
            {
                xloge("MF encoder event queue failed: encoder(%s), proven(%s), stalls(%u)",
                    pEncoder->sName, pEncoder->bProven ? "yes" : "no", pEncoder->nStallCount);
            }
            else
            {
                xloge("MF encoder did not ask for input within %ums: encoder(%s), proven(%s), stalls(%u)",
                    DIRECTGATE_MFENC_INPUT_WAIT_MS, pEncoder->sName,
                    pEncoder->bProven ? "yes" : "no", pEncoder->nStallCount);
            }

            return XSTDERR;
        }

        HRESULT hr = IMFTransform_ProcessInput(pEncoder->pTransform, pEncoder->nInputStreamId, pSample, 0);
        IMFSample_Release(pSample);
        pEncoder->nNeedInput--;

        if (FAILED(hr))
        {
            xloge("MF encoder ProcessInput failed: hr(0x%08lX)", (unsigned long)hr);
            return XSTDERR;
        }

        /* The frame was accepted, so the encoder is answering even if this
         * particular output has not surfaced yet. */
        pEncoder->nStallCount = 0;

        if (DirectGate_MFEnc_WaitCredit(pEncoder, &pEncoder->nHaveOutput,
            DIRECTGATE_MFENC_OUTPUT_WAIT_MS) != XSTDOK)
            return XSTDNON; /* still buffered; DirectGate_MFEnc_Drain collects it */

        pEncoder->nHaveOutput--;
        nStatus = DirectGate_MFEnc_ProcessOutput(pEncoder, pOut, pKeyframe, NULL);
        if (nStatus == XSTDOK && pOut->nUsed > 0) pEncoder->bProven = XTRUE;

        return nStatus;
    }

    /* Synchronous (software) model: feed the frame, then drain until the
     * MFT reports it needs more input. */
    HRESULT hr = IMFTransform_ProcessInput(pEncoder->pTransform, pEncoder->nInputStreamId, pSample, 0);
    if (hr == MF_E_NOTACCEPTING)
    {
        xbool_t bPendingKeyframe = XFALSE;
        int nPending = DirectGate_MFEnc_ProcessOutput(pEncoder, pOut, &bPendingKeyframe, NULL);

        hr = IMFTransform_ProcessInput(pEncoder->pTransform, pEncoder->nInputStreamId, pSample, 0);
        IMFSample_Release(pSample);

        if (nPending == XSTDOK && pOut->nUsed > 0)
        {
            if (pKeyframe != NULL) *pKeyframe = bPendingKeyframe;
            return XSTDOK;
        }

        pOut->nUsed = 0;
        if (FAILED(hr))
        {
            xloge("MF encoder ProcessInput failed: hr(0x%08lX)", (unsigned long)hr);
            return XSTDERR;
        }

        return XSTDNON;
    }

    IMFSample_Release(pSample);
    if (FAILED(hr))
    {
        xloge("MF encoder ProcessInput failed: hr(0x%08lX)", (unsigned long)hr);
        return XSTDERR;
    }

    int nStatus = DirectGate_MFEnc_ProcessOutput(pEncoder, pOut, pKeyframe, NULL);
    if (nStatus == XSTDERR) return XSTDERR;
    return (nStatus == XSTDOK && pOut->nUsed > 0) ? XSTDOK : XSTDNON;
}

int DirectGate_MFEnc_Drain(directgate_mfenc_t *pEncoder,
                           xbyte_buffer_t *pOut,
                           xbool_t *pKeyframe,
                           uint64_t *pPtsUs)
{
    XCHECK((pEncoder != NULL && pEncoder->pTransform != NULL), XSTDERR);
    XCHECK((pOut != NULL), XSTDERR);

    if (pKeyframe != NULL) *pKeyframe = XFALSE;
    pOut->nUsed = 0;

    if (pEncoder->bAsync)
    {
        /* Non-blocking: consume whatever events are already queued, then take
         * an output only against a credit. Asking an asynchronous MFT for
         * output it has not announced is a protocol violation. */
        while (pEncoder->nHaveOutput == 0)
        {
            int nEvent = DirectGate_MFEnc_PumpEvent(pEncoder);
            if (nEvent == XSTDERR) return XSTDERR;
            if (nEvent == XSTDNON) return XSTDNON;
        }

        pEncoder->nHaveOutput--;
    }

    int nStatus = DirectGate_MFEnc_ProcessOutput(pEncoder, pOut, pKeyframe, pPtsUs);
    if (nStatus == XSTDERR) return XSTDERR;

    if (nStatus == XSTDOK && pOut->nUsed > 0)
    {
        /* A drained frame is proof just like an inline one:
         * the encoder is alive and producing. */
        pEncoder->bProven = XTRUE;
        pEncoder->nStallCount = 0;
        return XSTDOK;
    }

    return XSTDNON;
}

xbool_t DirectGate_MFEnc_IsWedged(const directgate_mfenc_t *pEncoder)
{
    XCHECK_NL((pEncoder != NULL), XFALSE);
    if (pEncoder->nStallCount == 0) return XFALSE;

    /* An encoder that has never produced anything gets no second chance: it
     * configured, claimed to be ready and then ignored the first frame, which
     * is exactly the lie this whole path exists to catch. One that has been
     * working may just have hit a driver hiccup, so it gets a few tries. */
    if (!pEncoder->bProven) return XTRUE;
    return (pEncoder->nStallCount >= DIRECTGATE_MFENC_MAX_STALLS) ? XTRUE : XFALSE;
}

void DirectGate_MFEnc_Reject(directgate_mfenc_rejects_t *pRejects,
                             const directgate_mfenc_t *pEncoder)
{
    XCHECK_VOID_NL((pRejects != NULL && pEncoder != NULL));
    XCHECK_VOID_NL((pRejects->nCount < DIRECTGATE_MFENC_MAX_REJECTED));
    XCHECK_VOID_NL((pEncoder->sRawName[0] != '\0'));

    for (uint32_t i = 0; i < pRejects->nCount; i++)
    {
        if (xstrcmp(pRejects->names[i], pEncoder->sRawName)) return;
    }

    xstrncpy(pRejects->names[pRejects->nCount], DIRECTGATE_MFENC_NAME_LEN, pEncoder->sRawName);
    pRejects->nCount++;
}

int DirectGate_MFEnc_SetBitrate(directgate_mfenc_t *pEncoder, uint32_t nBitrateKbps)
{
    XCHECK((pEncoder != NULL), XSTDERR);
    XCHECK((nBitrateKbps > 0), XSTDERR);

    HRESULT hr = DirectGate_MFEnc_SetCodecU32(pEncoder, &g_MFEncMeanBitRate, nBitrateKbps * 1000U);
    if (FAILED(hr) && !pEncoder->bBitrateLiveFailed)
    {
        /* Some hardware MFTs reject mid-stream bitrate changes; the adaptive
         * controller then simply has no effect on this encoder. */
        pEncoder->bBitrateLiveFailed = XTRUE;
        xlogw("MF encoder rejects dynamic bitrate: encoder(%s), hr(0x%08lX)",
            pEncoder->sName, (unsigned long)hr);
    }

    return SUCCEEDED(hr) ? XSTDOK : XSTDERR;
}

int DirectGate_MFEnc_ApplyQuality(directgate_mfenc_t *pEncoder, const directgate_desktop_quality_t *pQuality)
{
    XCHECK((pEncoder != NULL && pQuality != NULL), XSTDERR);

    DirectGate_MFEnc_SetBitrate(pEncoder, pQuality->nBitrateKbps ? pQuality->nBitrateKbps : 4000U);
    DirectGate_MFEnc_SetCodecU32(pEncoder, &g_MFEncGopSize, pQuality->nKeyframeFrames ? pQuality->nKeyframeFrames : 60U);

    return XSTDOK;
}

#endif /* _WIN32 */
