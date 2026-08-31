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

/* --- Zero-copy import (Wayland/PipeWire DMA-BUF -> GPU encoder) ----------
 *
 * The frames the pipeline normally hands over have made a round trip nobody
 * wanted: the compositor read them back out of the GPU, the CPU turned BGRA
 * into NV12, and the encoder uploaded them again. When the compositor is
 * willing to export the frame as a DMA-BUF instead, none of that has to
 * happen - the buffer is already a GPU image, and the encoder is on the same
 * GPU.
 *
 * The import is VAAPI only. It is the one backend that can take a DRM object
 * as an encode surface through libavcodec (av_hwframe_map), and the colour
 * conversion and the resize are then done by the driver's video
 * post-processor through libavfilter's scale_vaapi. NVENC and AMF have no
 * equivalent path here, so a host that encodes on those keeps the existing
 * pipeline - which is why the caller must be prepared for this to decline. */

/* Whether this build and this host can import at all: libavfilter present,
 * loadable, with a scale_vaapi filter in it. Says nothing about whether a
 * VAAPI encoder will open - CreateImport answers that - and nothing about
 * whether the compositor will offer DMA-BUF. DIRECTGATE_HWENC_ZEROCOPY=0
 * turns it off. Cached, safe to call often. */
xbool_t DirectGate_HWEnc_ImportAvailable(char *pErrBuf, size_t nErrSize);

/* Opens a VAAPI encoder that takes DMA-BUF handles of @a nSrcWidth x
 * @a nSrcHeight in DRM format @a nFourCC / @a nModifier and emits
 * @a nWidth x @a nHeight H.264 - the scale is part of the GPU pass, so the
 * two sizes may differ freely.
 *
 * Returns NULL (with the reason) when anything in that chain will not build,
 * which is not a failure of the session: the caller opens an ordinary
 * encoder instead and asks the capture for mapped frames. */
directgate_hwenc_t* DirectGate_HWEnc_CreateImport(uint32_t nSrcWidth, uint32_t nSrcHeight,
                                                  uint32_t nFourCC, uint64_t nModifier,
                                                  uint32_t nWidth, uint32_t nHeight,
                                                  const directgate_desktop_quality_t *pQuality,
                                                  char *pErrBuf, size_t nErrSize);

/* Encodes one exported frame. The descriptors in @p pFrame are borrowed for
 * the duration of the call and are not stored: when this returns, the buffer
 * they came from can go back to the compositor.
 *
 * @p pFrame may be NULL to re-encode the last picture, which is how a
 * keyframe is answered on a screen that has stopped changing - there is no
 * CPU copy of it to fall back on. XSTDNON then means there is no last
 * picture yet.
 *
 * Return values match DirectGate_HWEnc_Encode. XSTDERR means the import
 * chain itself failed: the caller should stop asking the compositor for
 * DMA-BUF and rebuild on the ordinary encoder. */
int DirectGate_HWEnc_EncodeImport(directgate_hwenc_t *pEncoder,
                                  const directgate_desktop_dmabuf_t *pFrame,
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
