/*!
 * @file directgate-agent/src/agent/desktop/hwenc_abi.c
 * @brief Runtime selection between the per-libavcodec-major GPU encoder variants.
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

/*
 * Why there is more than one encoder in the binary
 * ------------------------------------------------
 * hwenc.c dlopen's libavcodec, but the struct offsets it reads come from the
 * headers it was compiled against, and FFmpeg rearranges those on every
 * soname bump. One build can therefore only ever talk to one major - and the
 * major a stable build image happens to ship is not the one most hosts run.
 * Built against libavcodec 58 (Debian 11, EL8) the agent would silently drop
 * to software encoding on Debian 12, Ubuntu 24.04, EL9 and Fedora.
 *
 * So hwenc.c is compiled once per major it may meet, each against that
 * major's headers and with its entry points renamed, and this file picks the
 * one whose library is actually installed. Nothing is linked or shipped: the
 * host's own FFmpeg is still what gets loaded, so VAAPI and QSV keep using
 * the drivers that distribution configured.
 *
 * Only one variant is ever active. The first Load that succeeds wins and every
 * later call goes to it, so the encoder handles a caller holds always belong
 * to the variant that created them.
 */

#include "hwenc.h"

#ifdef DIRECTGATE_HAVE_HWENC

typedef struct directgate_hwenc_abi_ {
    int nMajor;
    int (*pLoad)(char*, size_t);
    const char* (*pVersion)(void);
    directgate_hwenc_t* (*pCreate)(uint32_t, uint32_t, const directgate_desktop_quality_t*, char*, size_t);
    void (*pDestroy)(directgate_hwenc_t*);
    const char* (*pDescribe)(const directgate_hwenc_t*);
    int (*pEncode)(directgate_hwenc_t*, const uint8_t*, uint64_t, xbool_t, xbyte_buffer_t*, xbool_t*);
    int (*pApplyQuality)(directgate_hwenc_t*, const directgate_desktop_quality_t*);
    int (*pSetBitrate)(directgate_hwenc_t*, uint32_t);
} directgate_hwenc_abi_t;

/* Mirrors the renaming hwenc.c applies to itself under DIRECTGATE_HWENC_ABI. */
#define DIRECTGATE_HWENC_DECLARE(v)                                                     \
    int DirectGate_HWEnc_Load_abi##v(char*, size_t);                                    \
    const char* DirectGate_HWEnc_Version_abi##v(void);                                  \
    directgate_hwenc_t* DirectGate_HWEnc_Create_abi##v(uint32_t, uint32_t,              \
        const directgate_desktop_quality_t*, char*, size_t);                            \
    void DirectGate_HWEnc_Destroy_abi##v(directgate_hwenc_t*);                          \
    const char* DirectGate_HWEnc_Describe_abi##v(const directgate_hwenc_t*);            \
    int DirectGate_HWEnc_Encode_abi##v(directgate_hwenc_t*, const uint8_t*, uint64_t,   \
        xbool_t, xbyte_buffer_t*, xbool_t*);                                            \
    int DirectGate_HWEnc_ApplyQuality_abi##v(directgate_hwenc_t*,                       \
        const directgate_desktop_quality_t*);                                           \
    int DirectGate_HWEnc_SetBitrate_abi##v(directgate_hwenc_t*, uint32_t)

#define DIRECTGATE_HWENC_ENTRY(v) {                 \
    (v),                                            \
    DirectGate_HWEnc_Load_abi##v,                   \
    DirectGate_HWEnc_Version_abi##v,                \
    DirectGate_HWEnc_Create_abi##v,                 \
    DirectGate_HWEnc_Destroy_abi##v,                \
    DirectGate_HWEnc_Describe_abi##v,               \
    DirectGate_HWEnc_Encode_abi##v,                 \
    DirectGate_HWEnc_ApplyQuality_abi##v,           \
    DirectGate_HWEnc_SetBitrate_abi##v              \
}

/* CMake defines DIRECTGATE_HWENC_HAS_<major> for each variant it built, so the
 * set follows whatever header trees the build image provided. Adding a major
 * is another header tree plus a pair of blocks here; see docs/building.md. */
#if defined(DIRECTGATE_HWENC_HAS_62)
DIRECTGATE_HWENC_DECLARE(62);
#endif
#if defined(DIRECTGATE_HWENC_HAS_61)
DIRECTGATE_HWENC_DECLARE(61);
#endif
#if defined(DIRECTGATE_HWENC_HAS_60)
DIRECTGATE_HWENC_DECLARE(60);
#endif
#if defined(DIRECTGATE_HWENC_HAS_59)
DIRECTGATE_HWENC_DECLARE(59);
#endif
#if defined(DIRECTGATE_HWENC_HAS_58)
DIRECTGATE_HWENC_DECLARE(58);
#endif

/* Newest first: a host with a compat package for an older major installed
 * alongside the current one should use the current one. */
static const directgate_hwenc_abi_t g_hwencAbis[] = {
#if defined(DIRECTGATE_HWENC_HAS_62)
    DIRECTGATE_HWENC_ENTRY(62),
#endif
#if defined(DIRECTGATE_HWENC_HAS_61)
    DIRECTGATE_HWENC_ENTRY(61),
#endif
#if defined(DIRECTGATE_HWENC_HAS_60)
    DIRECTGATE_HWENC_ENTRY(60),
#endif
#if defined(DIRECTGATE_HWENC_HAS_59)
    DIRECTGATE_HWENC_ENTRY(59),
#endif
#if defined(DIRECTGATE_HWENC_HAS_58)
    DIRECTGATE_HWENC_ENTRY(58),
#endif
};

static const directgate_hwenc_abi_t *g_pHwencAbi = NULL;

int DirectGate_HWEnc_Load(char *pErrBuf, size_t nErrSize)
{
    if (g_pHwencAbi != NULL) return XSTDOK;

    char sTried[128] = { 0 };
    size_t nTried = 0;

    for (size_t i = 0; i < XARR_SIZE(g_hwencAbis); i++)
    {
        /* Each variant caches its own attempt, so a repeated call after a
         * failure costs nothing beyond this loop. */
        char sError[DIRECTGATE_DESKTOP_REASON_LEN] = { 0 };

        if (g_hwencAbis[i].pLoad(sError, sizeof(sError)) == XSTDOK)
        {
            g_pHwencAbi = &g_hwencAbis[i];
            return XSTDOK;
        }

        nTried += (size_t)snprintf(sTried + nTried, sizeof(sTried) - nTried,
            "%s%d", nTried ? "/" : "", g_hwencAbis[i].nMajor);

        if (nTried >= sizeof(sTried)) break;
    }

    if (pErrBuf != NULL && nErrSize > 0)
    {
        snprintf(pErrBuf, nErrSize,
            "no libavcodec this build understands (%s) is installed; "
            "using the software H.264 encoder.", sTried);
    }

    return XSTDERR;
}

const char* DirectGate_HWEnc_Version(void)
{
    return (g_pHwencAbi != NULL) ? g_pHwencAbi->pVersion() : "unloaded";
}

directgate_hwenc_t* DirectGate_HWEnc_Create(uint32_t nWidth,
                                            uint32_t nHeight,
                                            const directgate_desktop_quality_t *pQuality,
                                            char *pErrBuf,
                                            size_t nErrSize)
{
    /* Callers are allowed to go straight to Create, so the selection happens
     * here as well rather than depending on the order of the first two calls. */
    if (DirectGate_HWEnc_Load(pErrBuf, nErrSize) != XSTDOK) return NULL;
    return g_pHwencAbi->pCreate(nWidth, nHeight, pQuality, pErrBuf, nErrSize);
}

void DirectGate_HWEnc_Destroy(directgate_hwenc_t *pEncoder)
{
    if (pEncoder == NULL || g_pHwencAbi == NULL) return;
    g_pHwencAbi->pDestroy(pEncoder);
}

const char* DirectGate_HWEnc_Describe(const directgate_hwenc_t *pEncoder)
{
    if (pEncoder == NULL || g_pHwencAbi == NULL) return "none";
    return g_pHwencAbi->pDescribe(pEncoder);
}

int DirectGate_HWEnc_Encode(directgate_hwenc_t *pEncoder,
                            const uint8_t *pNV12,
                            uint64_t nPtsUs,
                            xbool_t bForceKeyframe,
                            xbyte_buffer_t *pOut,
                            xbool_t *pKeyframe)
{
    XCHECK_NL((pEncoder != NULL && g_pHwencAbi != NULL), XSTDERR);
    return g_pHwencAbi->pEncode(pEncoder, pNV12, nPtsUs, bForceKeyframe, pOut, pKeyframe);
}

int DirectGate_HWEnc_ApplyQuality(directgate_hwenc_t *pEncoder,
                                  const directgate_desktop_quality_t *pQuality)
{
    XCHECK_NL((pEncoder != NULL && g_pHwencAbi != NULL), XSTDERR);
    return g_pHwencAbi->pApplyQuality(pEncoder, pQuality);
}

int DirectGate_HWEnc_SetBitrate(directgate_hwenc_t *pEncoder, uint32_t nBitrateKbps)
{
    XCHECK_NL((pEncoder != NULL && g_pHwencAbi != NULL), XSTDERR);
    return g_pHwencAbi->pSetBitrate(pEncoder, nBitrateKbps);
}

#endif /* DIRECTGATE_HAVE_HWENC */
