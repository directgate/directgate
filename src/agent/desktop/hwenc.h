/*!
 * @file directgate-agent/src/agent/desktop/hwenc.h
 * @brief Runtime-loaded GPU H.264 encoder (NVENC / VAAPI / QSV / AMF) for desktop streaming.
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

#ifndef __DIRECTGATE_HWENC_H__
#define __DIRECTGATE_HWENC_H__

#include "includes.h"
#include "desktop.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DIRECTGATE_HAVE_HWENC

/* GPU video encoders on Linux are reached through libavcodec, which is
 * dlopen'd at runtime exactly like OpenH264, libopus and libpulse: a host
 * without it (or without a usable GPU) simply keeps the CPU pipeline, and
 * nothing about the packaging changes.
 *
 * Why libavcodec rather than libva/NVENC directly: VAAPI is a low-level
 * codec API where the *application* owns SPS/PPS bitstream packing,
 * emulation prevention, POC/frame_num and the whole reference picture list,
 * and NVENC needs a CUDA context plus its vendored API header. Driving them
 * by hand is a few thousand lines whose failure mode is subtly corrupt
 * output that differs per GPU generation. libavcodec gives one uniform
 * AVCodecContext across every vendor's encoder and is the same layer OBS and
 * GStreamer sit on.
 *
 * ABI safety: struct layouts come from the build-time headers, so the loader
 * accepts only a runtime libavcodec whose *major* soname matches the one the
 * agent was compiled against (FFmpeg bumps the soname on every ABI break).
 * A mismatch is treated exactly like "not installed" - the agent falls back
 * to OpenH264 rather than risk reading a struct that moved. This mirrors the
 * OPENH264_MAJOR check in openh264.c. */

typedef struct directgate_hwenc_ directgate_hwenc_t;

/* Loads libavcodec/libavutil once per process (idempotent, main loop only).
 * Search order: DIRECTGATE_HWENC_LIB env override, then the soname of the
 * major version this build was compiled against. Returns XSTDOK on success,
 * XSTDERR with a human-readable reason in pErrBuf otherwise. */
int DirectGate_HWEnc_Load(char *pErrBuf, size_t nErrSize);

/* "libavcodec 61.19.101" once loaded, otherwise "unloaded". */
const char* DirectGate_HWEnc_Version(void);

/* Opens the first GPU H.264 encoder that actually initialises, trying
 * NVENC -> VAAPI -> QSV -> AMF -> V4L2 M2M so a machine with both a
 * discrete NVIDIA card and an integrated GPU uses the dedicated silicon.
 * DIRECTGATE_HWENC_ENCODER pins one by name ("h264_vaapi"), and
 * DIRECTGATE_HWENC=0 disables hardware encoding entirely.
 *
 * Input is NV12 of nWidth x nHeight (both even). Returns NULL when no
 * encoder could be opened, with the reason in pErrBuf - the caller is
 * expected to continue with the software encoder. */
directgate_hwenc_t* DirectGate_HWEnc_Create(uint32_t nWidth,
                                            uint32_t nHeight,
                                            const directgate_desktop_quality_t *pQuality,
                                            char *pErrBuf,
                                            size_t nErrSize);

void DirectGate_HWEnc_Destroy(directgate_hwenc_t *pEncoder);

/* Name of the encoder that opened, e.g. "h264_nvenc (NVIDIA NVENC H.264
 * encoder)"; surfaced in the pipeline start log. */
const char* DirectGate_HWEnc_Describe(const directgate_hwenc_t *pEncoder);

/* Encodes one NV12 frame (contiguous Y plane followed by interleaved CbCr,
 * tightly packed) into an Annex-B access unit appended to pOut (reset
 * first). Keyframes are made self-contained: when the encoder emits an IDR
 * without in-band parameter sets, the cached SPS/PPS is prepended, matching
 * the OpenH264 and Media Foundation paths.
 *
 * Returns XSTDOK when pOut holds a frame, XSTDNON when the encoder buffered
 * the input and has no output yet, XSTDERR on failure - on XSTDERR the
 * caller should drop back to the software encoder. */
int DirectGate_HWEnc_Encode(directgate_hwenc_t *pEncoder,
                            const uint8_t *pNV12,
                            uint64_t nPtsUs,
                            xbool_t bForceKeyframe,
                            xbyte_buffer_t *pOut,
                            xbool_t *pKeyframe);

/* Applies bitrate/fps/GOP updates that do not change the encode dimensions. */
int DirectGate_HWEnc_ApplyQuality(directgate_hwenc_t *pEncoder,
                                  const directgate_desktop_quality_t *pQuality);

/* Live bitrate step for the adaptive controller. Hardware encoders cannot
 * retarget mid-stream through libavcodec, so this records the request and
 * the next Encode call re-opens the encoder - see the coalescing rules in
 * hwenc.c, which keep that to at most one rebuild every few seconds. */
int DirectGate_HWEnc_SetBitrate(directgate_hwenc_t *pEncoder, uint32_t nBitrateKbps);

#endif /* DIRECTGATE_HAVE_HWENC */

#ifdef __cplusplus
}
#endif

#endif
