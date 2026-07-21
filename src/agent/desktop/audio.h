/*!
 * @file directgate-agent/src/agent/desktop/audio.h
 * @brief Internal interface for desktop system-audio capture + Opus streaming.
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

/* Cross-unit interface between the cross-platform audio orchestrator
 * (desktop/audio.c) and the per-platform capture backend (audio_linux.c /
 * audio_win.c / audio_mac.m). Not part of the public desktop API. */

#ifndef __DIRECTGATE_DESKTOP_AUDIO_H__
#define __DIRECTGATE_DESKTOP_AUDIO_H__

#include "desktop.h"

#ifdef DIRECTGATE_DESKTOP_HAS_AUDIO

#ifdef __cplusplus
extern "C" {
#endif

/* Fixed capture format shared by every backend and the Opus encoder. 48 kHz
 * stereo S16 in 20 ms frames matches the WebRTC Opus RTP clock and needs no
 * resampling from the common desktop mix rate. */
#define DIRECTGATE_AUDIO_SAMPLE_RATE   48000U
#define DIRECTGATE_AUDIO_FRAME_MS      20U
#define DIRECTGATE_AUDIO_FRAME_SAMPLES ((DIRECTGATE_AUDIO_SAMPLE_RATE / 1000U) * DIRECTGATE_AUDIO_FRAME_MS)
#define DIRECTGATE_AUDIO_BITRATE_KBPS  128U
#define DIRECTGATE_AUDIO_CHANNELS      2U

/* Opens the platform's system-output loopback source at the requested format
 * (always 48 kHz stereo S16). Returns an opaque backend handle, or NULL with a
 * human-readable reason written into pErr. The backend must deliver only the
 * default output device's mix (never a microphone). */
void* DirectGate_Audio_BackendOpen(uint32_t nSampleRate, uint32_t nChannels, char *pErr, size_t nErrSize);

/* Blocking read of exactly nFrames samples per channel (interleaved S16) into
 * pBuf. Returns XSTDOK on a full frame, or XSTDERR on a fatal source error
 * (the capture thread then exits and audio is marked unavailable). Should
 * return roughly every frame period so the thread can observe a stop request. */
int DirectGate_Audio_BackendRead(void *pBackend, int16_t *pBuf, uint32_t nFrames, uint32_t nChannels);

void DirectGate_Audio_BackendClose(void *pBackend);

#ifdef __cplusplus
}
#endif

#endif /* DIRECTGATE_DESKTOP_HAS_AUDIO */
#endif
