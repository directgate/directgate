/*!
 * @file directgate-agent/src/agent/openh264.h
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

#ifndef __DIRECTGATE_OPENH264_H__
#define __DIRECTGATE_OPENH264_H__

#include "includes.h"
#include "desktop.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OpenH264 is dlopen'd at runtime (like libXtst) instead of being linked:
 * the Cisco-licensed binary may legitimately be absent, and the agent must
 * keep working with the raw-RGBA fallback in that case. Only the API headers
 * are vendored (src/agent/openh264/wels), pinned to the OPENH264_MAJOR the
 * loader accepts. */

typedef struct directgate_openh264_ directgate_openh264_t;

/* Loads the shared library once per process (idempotent, not thread-safe:
 * call from the main loop only). Search order: DIRECTGATE_OPENH264_LIB env
 * override, then well-known sonames. Returns XSTDOK on success; on failure
 * writes a human-readable reason into pErrBuf and returns XSTDERR. */
int DirectGate_OpenH264_Load(char *pErrBuf, size_t nErrSize);

/* Version string of the loaded library ("openh264 X.Y.Z"), or "unloaded". */
const char* DirectGate_OpenH264_Version(void);

/* Creates and initializes an encoder for I420 input of nWidth x nHeight
 * (both must be even) using the given quality settings. Returns NULL on
 * failure with the reason in pErrBuf. */
directgate_openh264_t* DirectGate_OpenH264_Create(uint32_t nWidth,
                                          uint32_t nHeight,
                                          const directgate_desktop_quality_t *pQuality,
                                          char *pErrBuf,
                                          size_t nErrSize);

void DirectGate_OpenH264_Destroy(directgate_openh264_t *pEncoder);

/* Encodes one I420 frame (contiguous Y+U+V planes, tightly packed) into an
 * Annex-B access unit appended to pOut (pOut is reset first). OpenH264
 * attaches SPS/PPS to every IDR, so keyframe payloads are self-contained.
 * Returns XSTDOK when pOut holds a frame, XSTDNON when the rate controller
 * skipped the frame, XSTDERR on encoder failure. *pKeyframe is set when the
 * output is an intra frame. */
int DirectGate_OpenH264_Encode(directgate_openh264_t *pEncoder,
                           const uint8_t *pI420,
                           uint64_t nPtsUs,
                           xbool_t bForceKeyframe,
                           xbyte_buffer_t *pOut,
                           xbool_t *pKeyframe);

/* Applies bitrate/fps/GOP updates that do not change the encode dimensions.
 * A dimension change requires Destroy + Create by the caller. */
int DirectGate_OpenH264_ApplyQuality(directgate_openh264_t *pEncoder,
                                 const directgate_desktop_quality_t *pQuality);

/* Live bitrate step (target + 1.5x burst cap) without touching fps/GOP and
 * without forcing a keyframe; used by the adaptive bitrate controller. */
int DirectGate_OpenH264_SetBitrate(directgate_openh264_t *pEncoder, uint32_t nBitrateKbps);

uint32_t DirectGate_OpenH264_GetWidth(const directgate_openh264_t *pEncoder);
uint32_t DirectGate_OpenH264_GetHeight(const directgate_openh264_t *pEncoder);

#ifdef __cplusplus
}
#endif

#endif
