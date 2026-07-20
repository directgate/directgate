/*!
 * @file directgate-agent/src/agent/desktop/mfenc.h
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

#ifndef __DIRECTGATE_MFENC_H__
#define __DIRECTGATE_MFENC_H__

#include "includes.h"
#include "desktop.h"

#ifdef __cplusplus
extern "C" {
#endif

/* mfplat.dll is loaded at runtime (like OpenH264 on Linux) instead of being
 * linked: Windows N editions ship without Media Foundation, and the agent
 * must keep working with the raw-RGBA fallback there instead of failing to
 * start with STATUS_DLL_NOT_FOUND before main().
 *
 * The wrapper prefers a hardware H.264 encoder MFT (Quick Sync, NVENC, AMF -
 * whatever the GPU vendor registered) and falls back to the Microsoft
 * software encoder. Hardware MFTs are asynchronous; both processing models
 * are handled internally so the caller sees one synchronous Encode call.
 *
 * Not thread-safe: every function including Load must be called from the
 * single capture/encode thread that owns the encoder (desktop_win.c). */

typedef struct directgate_mfenc_ directgate_mfenc_t;

/* Loads mfplat.dll and starts Media Foundation once per process
 * (idempotent). Returns XSTDOK on success; on failure writes a
 * human-readable reason into pErrBuf and returns XSTDERR. */
int DirectGate_MFEnc_Load(char *pErrBuf, size_t nErrSize);

/* Creates and initializes an encoder for NV12 input of nWidth x nHeight
 * (both must be even) using the given quality settings. Returns NULL on
 * failure with the reason in pErrBuf. */
directgate_mfenc_t* DirectGate_MFEnc_Create(uint32_t nWidth,
                                    uint32_t nHeight,
                                    const directgate_desktop_quality_t *pQuality,
                                    char *pErrBuf,
                                    size_t nErrSize);

void DirectGate_MFEnc_Destroy(directgate_mfenc_t *pEncoder);

/* Friendly name of the active encoder MFT prefixed with "hardware"/"software"
 * (for logs), or "unloaded" before the first successful Create. */
const char* DirectGate_MFEnc_Describe(const directgate_mfenc_t *pEncoder);

/* Encodes one NV12 frame (contiguous Y+UV planes, tightly packed) into an
 * Annex-B access unit appended to pOut (pOut is reset first). Keyframe
 * payloads are made self-contained by prepending the cached SPS/PPS when
 * the encoder did not attach them itself. Returns XSTDOK when pOut holds a
 * frame, XSTDNON when the encoder buffered the input without producing
 * output yet, XSTDERR on encoder failure. *pKeyframe is set when the
 * output is an intra frame. */
int DirectGate_MFEnc_Encode(directgate_mfenc_t *pEncoder,
                        const uint8_t *pNV12,
                        uint64_t nPtsUs,
                        xbool_t bForceKeyframe,
                        xbyte_buffer_t *pOut,
                        xbool_t *pKeyframe);

/* Applies bitrate/GOP updates that do not change the encode dimensions.
 * A dimension change requires Destroy + Create by the caller. */
int DirectGate_MFEnc_ApplyQuality(directgate_mfenc_t *pEncoder,
                              const directgate_desktop_quality_t *pQuality);

/* Live bitrate step without forcing a keyframe; used by the adaptive
 * bitrate controller. Silently ignored when the MFT rejects dynamic
 * bitrate changes. */
int DirectGate_MFEnc_SetBitrate(directgate_mfenc_t *pEncoder, uint32_t nBitrateKbps);

#ifdef __cplusplus
}
#endif

#endif
