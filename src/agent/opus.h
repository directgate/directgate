/*!
 * @file directgate-agent/src/agent/opus.h
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

#ifndef __DIRECTGATE_OPUS_H__
#define __DIRECTGATE_OPUS_H__

#include "includes.h"

#ifdef __cplusplus
extern "C" {
#endif

/* libopus is dlopen'd at runtime (like OpenH264 and libpulse): the desktop
 * audio track is strictly additive, so a missing library must degrade to
 * "audio unavailable" without ever disturbing the video pipeline. Its C ABI
 * is small and stable, so the loader declares the handful of symbols it needs
 * inline rather than vendoring a header tree. */

typedef struct directgate_opus_ directgate_opus_t;

/* Loads libopus once per process (idempotent, not thread-safe: call from the
 * main loop only). Search order: DIRECTGATE_OPUS_LIB env override, then
 * well-known sonames. Returns XSTDOK on success; on failure writes a
 * human-readable reason into pErrBuf and returns XSTDERR. */
int DirectGate_Opus_Load(char *pErrBuf, size_t nErrSize);

/* Version string of the loaded library ("libopus X.Y.Z"), or "unloaded". */
const char* DirectGate_Opus_Version(void);

/* Creates an encoder for interleaved S16 PCM at nSampleRate (48000) with
 * nChannels (1 or 2), configured for low-latency desktop audio at the given
 * average bitrate. Returns NULL on failure with the reason in pErrBuf. */
directgate_opus_t* DirectGate_Opus_Create(uint32_t nSampleRate,
                                          uint32_t nChannels,
                                          uint32_t nBitrateKbps,
                                          char *pErrBuf,
                                          size_t nErrSize);

void DirectGate_Opus_Destroy(directgate_opus_t *pEnc);

/* Encodes one frame of interleaved S16 PCM (nFrameSamples per channel; must be
 * a valid Opus frame size, e.g. 960 for 20 ms at 48 kHz) into pOut. Returns the
 * encoded byte count (>0) on success, XSTDNON when the encoder produced no
 * output (e.g. DTX), or XSTDERR on failure. */
int DirectGate_Opus_Encode(directgate_opus_t *pEnc,
                           const int16_t *pPcm,
                           uint32_t nFrameSamples,
                           uint8_t *pOut,
                           size_t nOutMax);

/* Live bitrate update for the adaptive controller (no encoder rebuild). */
int DirectGate_Opus_SetBitrate(directgate_opus_t *pEnc, uint32_t nBitrateKbps);

/* Reports the encoder algorithmic look-ahead in samples per channel (used to
 * initialise the RTP timestamp base so audio/video presentation stays aligned). */
uint32_t DirectGate_Opus_GetLookahead(const directgate_opus_t *pEnc);

uint32_t DirectGate_Opus_GetSampleRate(const directgate_opus_t *pEnc);
uint32_t DirectGate_Opus_GetChannels(const directgate_opus_t *pEnc);

#ifdef __cplusplus
}
#endif

#endif
