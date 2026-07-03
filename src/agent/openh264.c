/*!
 * @file directgate-agent/src/agent/openh264.c
 * @brief Runtime-loaded OpenH264 encoder wrapper for desktop streaming.
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

#include "openh264.h"

#include <dlfcn.h>
#include <wels/codec_api.h>
#include <wels/codec_ver.h>

typedef int (*directgate_wels_create_fn)(ISVCEncoder**);
typedef void (*directgate_wels_destroy_fn)(ISVCEncoder*);
typedef void (*directgate_wels_version_fn)(OpenH264Version*);

typedef struct directgate_openh264_lib_ {
    void *pHandle;
    directgate_wels_create_fn createEncoder;
    directgate_wels_destroy_fn destroyEncoder;
    OpenH264Version version;
    char sVersion[32];
    xbool_t bLoadAttempted;
    xbool_t bLoaded;
} directgate_openh264_lib_t;

struct directgate_openh264_ {
    ISVCEncoder *pEncoder;
    uint32_t nWidth;
    uint32_t nHeight;
    uint32_t nFps;
};

static directgate_openh264_lib_t g_openh264;

/* Sonames the Cisco/openh264 binary releases have shipped under. Newest
 * first; the vendored headers are 2.x so any 2.x soname is ABI-compatible. */
static const char *g_pOpenH264Names[] = {
    "libopenh264.so.8",
    "libopenh264.so.7",
    "libopenh264.so.6",
    "libopenh264.so",
    NULL
};

static void DirectGate_OpenH264_SetError(char *pErrBuf, size_t nErrSize, const char *pFmt, ...)
{
    if (pErrBuf == NULL || !nErrSize) return;
    va_list args;
    va_start(args, pFmt);
    vsnprintf(pErrBuf, nErrSize, pFmt, args);
    va_end(args);
}

int DirectGate_OpenH264_Load(char *pErrBuf, size_t nErrSize)
{
    directgate_openh264_lib_t *pLib = &g_openh264;
    if (pLib->bLoadAttempted)
    {
        if (pLib->bLoaded) return XSTDOK;
        DirectGate_OpenH264_SetError(pErrBuf, nErrSize,
            "OpenH264 library is not available (install the Cisco openh264 binary "
            "or set DIRECTGATE_OPENH264_LIB).");
        return XSTDERR;
    }

    pLib->bLoadAttempted = XTRUE;
    void *pHandle = NULL;
    const char *pLoadedName = NULL;

    const char *pEnvPath = getenv("DIRECTGATE_OPENH264_LIB");
    if (xstrused(pEnvPath))
    {
        pHandle = dlopen(pEnvPath, RTLD_NOW | RTLD_LOCAL);
        pLoadedName = pEnvPath;
        if (pHandle == NULL)
        {
            DirectGate_OpenH264_SetError(pErrBuf, nErrSize,
                "Failed to load OpenH264 from DIRECTGATE_OPENH264_LIB (%s).", pEnvPath);
            return XSTDERR;
        }
    }

    for (int i = 0; pHandle == NULL && g_pOpenH264Names[i] != NULL; i++)
    {
        pHandle = dlopen(g_pOpenH264Names[i], RTLD_NOW | RTLD_LOCAL);
        pLoadedName = g_pOpenH264Names[i];
    }

    if (pHandle == NULL)
    {
        DirectGate_OpenH264_SetError(pErrBuf, nErrSize,
            "OpenH264 library is not available (install the Cisco openh264 binary "
            "or set DIRECTGATE_OPENH264_LIB).");
        return XSTDERR;
    }

    directgate_wels_create_fn createFn =
        (directgate_wels_create_fn)dlsym(pHandle, "WelsCreateSVCEncoder");
    directgate_wels_destroy_fn destroyFn =
        (directgate_wels_destroy_fn)dlsym(pHandle, "WelsDestroySVCEncoder");
    directgate_wels_version_fn versionFn =
        (directgate_wels_version_fn)dlsym(pHandle, "WelsGetCodecVersionEx");

    if (createFn == NULL || destroyFn == NULL || versionFn == NULL)
    {
        dlclose(pHandle);
        DirectGate_OpenH264_SetError(pErrBuf, nErrSize,
            "OpenH264 library %s is missing required encoder symbols.", pLoadedName);
        return XSTDERR;
    }

    OpenH264Version version;
    memset(&version, 0, sizeof(version));
    versionFn(&version);

    /* The vtable layout is only guaranteed within the same major version
     * as the vendored headers; refuse anything else (see codec_api.h). */
    if (version.uMajor != OPENH264_MAJOR)
    {
        dlclose(pHandle);
        DirectGate_OpenH264_SetError(pErrBuf, nErrSize,
            "OpenH264 %u.%u is incompatible with this build (need major %u).",
            version.uMajor, version.uMinor, (unsigned)OPENH264_MAJOR);
        return XSTDERR;
    }

    pLib->pHandle = pHandle;
    pLib->createEncoder = createFn;
    pLib->destroyEncoder = destroyFn;
    pLib->version = version;
    pLib->bLoaded = XTRUE;
    snprintf(pLib->sVersion, sizeof(pLib->sVersion), "openh264 %u.%u.%u",
        version.uMajor, version.uMinor, version.uRevision);

    xlogi("Loaded OpenH264 encoder library: name(%s), version(%u.%u.%u)",
        pLoadedName, version.uMajor, version.uMinor, version.uRevision);

    return XSTDOK;
}

const char* DirectGate_OpenH264_Version(void)
{
    return g_openh264.bLoaded ? g_openh264.sVersion : "unloaded";
}

directgate_openh264_t* DirectGate_OpenH264_Create(uint32_t nWidth,
                                          uint32_t nHeight,
                                          const directgate_desktop_quality_t *pQuality,
                                          char *pErrBuf,
                                          size_t nErrSize)
{
    XCHECK_NL((pQuality != NULL), NULL);
    XCHECK_NL((nWidth >= 16 && nHeight >= 16), NULL);
    XCHECK_NL(((nWidth & 1U) == 0 && (nHeight & 1U) == 0), NULL);

    if (DirectGate_OpenH264_Load(pErrBuf, nErrSize) != XSTDOK)
        return NULL;

    ISVCEncoder *pWels = NULL;
    if (g_openh264.createEncoder(&pWels) != 0 || pWels == NULL)
    {
        DirectGate_OpenH264_SetError(pErrBuf, nErrSize, "WelsCreateSVCEncoder failed.");
        return NULL;
    }

    SEncParamExt param;
    memset(&param, 0, sizeof(param));
    if ((*pWels)->GetDefaultParams(pWels, &param) != 0)
    {
        g_openh264.destroyEncoder(pWels);
        DirectGate_OpenH264_SetError(pErrBuf, nErrSize, "OpenH264 GetDefaultParams failed.");
        return NULL;
    }

    uint32_t nFps = pQuality->nFps ? pQuality->nFps : 30U;
    uint32_t nBitrateKbps = pQuality->nBitrateKbps ? pQuality->nBitrateKbps : 4000U;
    uint32_t nKeyEvery = pQuality->nKeyframeFrames ? pQuality->nKeyframeFrames : 60U;
    xbool_t bLowLatency = (pQuality->ePreset == DIRECTGATE_DESKTOP_PRESET_LOW_LATENCY);

    param.iUsageType = SCREEN_CONTENT_REAL_TIME;
    param.iPicWidth = (int)nWidth;
    param.iPicHeight = (int)nHeight;
    param.iTargetBitrate = (int)(nBitrateKbps * 1000U);
    /* Same burst budget as the macOS encoder's data-rate cap: 1.5x average
     * so busy frames don't blow past the WebRTC backpressure threshold. */
    param.iMaxBitrate = (int)(nBitrateKbps * 1500U);
    /* Timestamp-based rate control: the capture pipeline skips unchanged
     * frames, so the encoder sees an irregular cadence. RC_BITRATE_MODE
     * budgets for a fixed fps and bursts after idle gaps; the timestamp
     * mode derives the actual rate from uiTimeStamp. */
    param.iRCMode = RC_TIMESTAMP_MODE;
    param.fMaxFrameRate = (float)nFps;
    param.iTemporalLayerNum = 1;
    param.iSpatialLayerNum = 1;
    param.uiIntraPeriod = nKeyEvery;
    param.eSpsPpsIdStrategy = CONSTANT_ID;
    /* Frame skip trades transient quality for latency; only wanted on the
     * realtime presets (mirrors quality.bRealtime on the macOS side). */
    param.bEnableFrameSkip = pQuality->bRealtime ? true : false;
    param.iComplexityMode = bLowLatency ? LOW_COMPLEXITY : MEDIUM_COMPLEXITY;
    param.iMultipleThreadIdc = 0; /* auto: scale slices to available cores */
    param.iEntropyCodingModeFlag = bLowLatency ? 0 : 1;

    SSpatialLayerConfig *pLayer = &param.sSpatialLayers[0];
    pLayer->iVideoWidth = (int)nWidth;
    pLayer->iVideoHeight = (int)nHeight;
    pLayer->fFrameRate = (float)nFps;
    pLayer->iSpatialBitrate = param.iTargetBitrate;
    pLayer->iMaxSpatialBitrate = param.iMaxBitrate;
    /* Main+CABAC everywhere except low-latency, matching the profile choice
     * the macOS VideoToolbox pipeline makes for WebCodecs decoders. */
    pLayer->uiProfileIdc = bLowLatency ? PRO_BASELINE : PRO_MAIN;

    /* Pin BT.709 limited range in the SPS VUI so the browser decoder does
     * not guess the colour space (yuv.c converts with the same
     * coefficients). */
    pLayer->bVideoSignalTypePresent = true;
    pLayer->uiVideoFormat = 5; /* unspecified video format */
    pLayer->bFullRange = false;
    pLayer->bColorDescriptionPresent = true;
    pLayer->uiColorPrimaries = 1;          /* bt709 */
    pLayer->uiTransferCharacteristics = 1; /* bt709 */
    pLayer->uiColorMatrix = 1;             /* bt709 */

    int nRet = (*pWels)->InitializeExt(pWels, &param);
    if (nRet != 0)
    {
        g_openh264.destroyEncoder(pWels);
        DirectGate_OpenH264_SetError(pErrBuf, nErrSize,
            "OpenH264 InitializeExt failed: size(%ux%u), ret(%d)", nWidth, nHeight, nRet);
        return NULL;
    }

    directgate_openh264_t *pEncoder = (directgate_openh264_t*)calloc(1, sizeof(*pEncoder));
    if (pEncoder == NULL)
    {
        (*pWels)->Uninitialize(pWels);
        g_openh264.destroyEncoder(pWels);
        DirectGate_OpenH264_SetError(pErrBuf, nErrSize, "Failed to allocate encoder context.");
        return NULL;
    }

    pEncoder->pEncoder = pWels;
    pEncoder->nWidth = nWidth;
    pEncoder->nHeight = nHeight;
    pEncoder->nFps = nFps;
    return pEncoder;
}

void DirectGate_OpenH264_Destroy(directgate_openh264_t *pEncoder)
{
    if (pEncoder == NULL) return;

    if (pEncoder->pEncoder != NULL)
    {
        (*pEncoder->pEncoder)->Uninitialize(pEncoder->pEncoder);
        g_openh264.destroyEncoder(pEncoder->pEncoder);
        pEncoder->pEncoder = NULL;
    }

    free(pEncoder);
}

int DirectGate_OpenH264_Encode(directgate_openh264_t *pEncoder,
                           const uint8_t *pI420,
                           uint64_t nPtsUs,
                           xbool_t bForceKeyframe,
                           xbyte_buffer_t *pOut,
                           xbool_t *pKeyframe)
{
    XCHECK((pEncoder != NULL && pEncoder->pEncoder != NULL), XSTDERR);
    XCHECK((pI420 != NULL && pOut != NULL), XSTDERR);
    if (pKeyframe != NULL) *pKeyframe = XFALSE;

    ISVCEncoder *pWels = pEncoder->pEncoder;
    if (bForceKeyframe)
        (*pWels)->ForceIntraFrame(pWels, true);

    size_t nLumaSize = (size_t)pEncoder->nWidth * pEncoder->nHeight;
    SSourcePicture picture;
    memset(&picture, 0, sizeof(picture));
    picture.iColorFormat = videoFormatI420;
    picture.iPicWidth = (int)pEncoder->nWidth;
    picture.iPicHeight = (int)pEncoder->nHeight;
    picture.iStride[0] = (int)pEncoder->nWidth;
    picture.iStride[1] = (int)(pEncoder->nWidth / 2U);
    picture.iStride[2] = (int)(pEncoder->nWidth / 2U);
    picture.pData[0] = (unsigned char*)pI420;
    picture.pData[1] = (unsigned char*)pI420 + nLumaSize;
    picture.pData[2] = (unsigned char*)pI420 + nLumaSize + nLumaSize / 4U;
    picture.uiTimeStamp = (long long)(nPtsUs / 1000ULL);

    SFrameBSInfo info;
    memset(&info, 0, sizeof(info));

    int nRet = (*pWels)->EncodeFrame(pWels, &picture, &info);
    if (nRet != 0)
    {
        xloge("OpenH264 EncodeFrame failed: size(%ux%u), ret(%d)",
            pEncoder->nWidth, pEncoder->nHeight, nRet);
        return XSTDERR;
    }

    if (info.eFrameType == videoFrameTypeSkip || info.iLayerNum <= 0)
        return XSTDNON;

    pOut->nUsed = 0;

    for (int i = 0; i < info.iLayerNum; i++)
    {
        const SLayerBSInfo *pLayer = &info.sLayerInfo[i];
        size_t nLayerSize = 0;

        for (int j = 0; j < pLayer->iNalCount; j++)
            nLayerSize += (size_t)pLayer->pNalLengthInByte[j];

        /* Each layer buffer already carries Annex-B start codes. */
        if (nLayerSize > 0 &&
            XByteBuffer_Add(pOut, pLayer->pBsBuf, nLayerSize) <= 0)
        {
            xloge("Failed to buffer encoded frame: bytes(%zu)", nLayerSize);
            return XSTDERR;
        }
    }

    if (!pOut->nUsed) return XSTDNON;

    if (pKeyframe != NULL)
    {
        *pKeyframe = (info.eFrameType == videoFrameTypeIDR ||
                      info.eFrameType == videoFrameTypeI) ?
                      XTRUE : XFALSE;
    }

    return XSTDOK;
}

int DirectGate_OpenH264_SetBitrate(directgate_openh264_t *pEncoder, uint32_t nBitrateKbps)
{
    XCHECK((pEncoder != NULL && pEncoder->pEncoder != NULL), XSTDERR);
    XCHECK((nBitrateKbps > 0), XSTDERR);

    ISVCEncoder *pWels = pEncoder->pEncoder;
    SBitrateInfo bitrate;
    memset(&bitrate, 0, sizeof(bitrate));
    bitrate.iLayer = SPATIAL_LAYER_ALL;
    bitrate.iBitrate = (int)(nBitrateKbps * 1000U);
    (*pWels)->SetOption(pWels, ENCODER_OPTION_BITRATE, &bitrate);

    bitrate.iBitrate = (int)(nBitrateKbps * 1500U);
    (*pWels)->SetOption(pWels, ENCODER_OPTION_MAX_BITRATE, &bitrate);

    return XSTDOK;
}

int DirectGate_OpenH264_ApplyQuality(directgate_openh264_t *pEncoder,
                                 const directgate_desktop_quality_t *pQuality)
{
    XCHECK((pEncoder != NULL && pEncoder->pEncoder != NULL), XSTDERR);
    XCHECK((pQuality != NULL), XSTDERR);

    ISVCEncoder *pWels = pEncoder->pEncoder;
    DirectGate_OpenH264_SetBitrate(pEncoder,
        pQuality->nBitrateKbps ? pQuality->nBitrateKbps : 4000U);

    float fFps = (float)(pQuality->nFps ? pQuality->nFps : 30U);
    (*pWels)->SetOption(pWels, ENCODER_OPTION_FRAME_RATE, &fFps);
    pEncoder->nFps = (uint32_t)fFps;

    int nIdrInterval = (int)(pQuality->nKeyframeFrames ? pQuality->nKeyframeFrames : 60U);
    (*pWels)->SetOption(pWels, ENCODER_OPTION_IDR_INTERVAL, &nIdrInterval);

    return XSTDOK;
}

uint32_t DirectGate_OpenH264_GetWidth(const directgate_openh264_t *pEncoder)
{
    XCHECK_NL((pEncoder != NULL), 0);
    return pEncoder->nWidth;
}

uint32_t DirectGate_OpenH264_GetHeight(const directgate_openh264_t *pEncoder)
{
    XCHECK_NL((pEncoder != NULL), 0);
    return pEncoder->nHeight;
}
