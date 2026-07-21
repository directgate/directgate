/*!
 * @file directgate-agent/src/agent/desktop/audio.c
 * @brief Cross-platform desktop system-audio capture + Opus WebRTC streaming.
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

#include "audio.h"

#ifdef DIRECTGATE_DESKTOP_HAS_AUDIO

#include "session.h"
#include "webrtc.h"
#include "opus.h"
#include "priv.h"

/* Largest byte count a 20 ms stereo Opus frame can occupy (RFC 6716 upper
 * bound); the RTP payload limit is larger so a whole frame is always one
 * packet. */
#define DIRECTGATE_AUDIO_MAX_PACKET   1275U
/* ~1.28 s of encoded frames. The main loop drains every capture/encode tick,
 * so occupancy stays near zero; the ring only absorbs a stalled main loop and
 * drops the oldest frame under sustained overflow to bound added latency. */
#define DIRECTGATE_AUDIO_RING_FRAMES  64U

typedef struct directgate_audio_packet_ {
    uint8_t data[DIRECTGATE_AUDIO_MAX_PACKET];
    uint32_t nLen;
    uint64_t nPtsUs;
} directgate_audio_packet_t;

typedef struct directgate_audio_ {
    directgate_opus_t *pEncoder;   /* owned Opus encoder */
    void *pBackend;                /* platform capture handle */
    xthread_t thread;              /* capture + encode worker */
    xbool_t bThreadRunning;
    volatile xbool_t bStop;        /* worker exit request */

    xsync_mutex_t lock;            /* guards the ring below */
    directgate_audio_packet_t ring[DIRECTGATE_AUDIO_RING_FRAMES];
    uint32_t nHead;                /* next write slot */
    uint32_t nTail;                /* next read slot */
    uint32_t nCount;

    uint64_t nSamplePos;           /* per-channel samples captured (PTS base) */
    uint64_t nFramesEncoded;
    uint64_t nFramesDropped;
} directgate_audio_t;

static void DirectGate_Audio_SetReason(directgate_desktop_t *pDesktop, const char *pReason)
{
    if (pDesktop == NULL) return;
    xstrncpy(pDesktop->sAudioReason, sizeof(pDesktop->sAudioReason),
        xstrused(pReason) ? pReason : "System audio is unavailable.");
}

/* Producer (capture thread): appends one encoded frame, dropping the oldest
 * when the ring is full so the queue can never grow the audio latency. */
static void DirectGate_Audio_Push(directgate_audio_t *pAudio, const uint8_t *pData,
                                  uint32_t nLen, uint64_t nPtsUs)
{
    if (nLen == 0 || nLen > DIRECTGATE_AUDIO_MAX_PACKET) return;

    XSync_Lock(&pAudio->lock);

    if (pAudio->nCount == DIRECTGATE_AUDIO_RING_FRAMES)
    {
        pAudio->nTail = (pAudio->nTail + 1U) % DIRECTGATE_AUDIO_RING_FRAMES;
        pAudio->nCount--;
        pAudio->nFramesDropped++;
    }

    directgate_audio_packet_t *pPkt = &pAudio->ring[pAudio->nHead];
    memcpy(pPkt->data, pData, nLen);
    pPkt->nLen = nLen;
    pPkt->nPtsUs = nPtsUs;
    pAudio->nHead = (pAudio->nHead + 1U) % DIRECTGATE_AUDIO_RING_FRAMES;
    pAudio->nCount++;

    XSync_Unlock(&pAudio->lock);
}

/* Consumer (main loop): pops the oldest frame. Returns XFALSE when empty. */
static xbool_t DirectGate_Audio_Pop(directgate_audio_t *pAudio, directgate_audio_packet_t *pOut)
{
    xbool_t bHas = XFALSE;
    XSync_Lock(&pAudio->lock);

    if (pAudio->nCount > 0)
    {
        *pOut = pAudio->ring[pAudio->nTail];
        pAudio->nTail = (pAudio->nTail + 1U) % DIRECTGATE_AUDIO_RING_FRAMES;
        pAudio->nCount--;
        bHas = XTRUE;
    }

    XSync_Unlock(&pAudio->lock);
    return bHas;
}

static void* DirectGate_Audio_Worker(void *pArg)
{
    directgate_audio_t *pAudio = (directgate_audio_t*)pArg;
    XCHECK((pAudio != NULL), NULL);

    int16_t pcm[DIRECTGATE_AUDIO_FRAME_SAMPLES * DIRECTGATE_AUDIO_CHANNELS];
    uint8_t packet[DIRECTGATE_AUDIO_MAX_PACKET];

    while (!pAudio->bStop)
    {
        /* Blocking read of exactly one 20 ms frame; returns each frame period,
         * so the stop flag is observed within ~20 ms. */
        if (DirectGate_Audio_BackendRead(pAudio->pBackend, pcm,
            DIRECTGATE_AUDIO_FRAME_SAMPLES, DIRECTGATE_AUDIO_CHANNELS) != XSTDOK)
        {
            xlogw("Desktop audio capture read failed; stopping audio thread");
            break;
        }

        /* Sample-position PTS: exact, monotonic, and independent of wall clock.
         * A frame dropped downstream leaves a matching timestamp gap so the
         * browser inserts the right amount of silence and stays A/V aligned. */
        uint64_t nPtsUs = (pAudio->nSamplePos * 1000000ULL) / DIRECTGATE_AUDIO_SAMPLE_RATE;
        pAudio->nSamplePos += DIRECTGATE_AUDIO_FRAME_SAMPLES;

        int nBytes = DirectGate_Opus_Encode(pAudio->pEncoder, pcm,
            DIRECTGATE_AUDIO_FRAME_SAMPLES, packet, sizeof(packet));
        if (nBytes <= 0) continue; /* DTX/skip or transient error: drop frame */

        DirectGate_Audio_Push(pAudio, packet, (uint32_t)nBytes, nPtsUs);
        pAudio->nFramesEncoded++;
    }

    return NULL;
}

int DirectGate_Desktop_AudioStart(directgate_session_t *pSession)
{
    XCHECK((pSession != NULL), XSTDERR);
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (pDesktop->pAudio != NULL)
    {
        pDesktop->bAudioReady = XTRUE;
        return XSTDOK; /* already capturing */
    }

    char sErr[DIRECTGATE_DESKTOP_REASON_LEN];
    sErr[0] = '\0';

    directgate_audio_t *pAudio = (directgate_audio_t*)calloc(1, sizeof(*pAudio));
    if (pAudio == NULL)
    {
        DirectGate_Audio_SetReason(pDesktop, "Out of memory starting audio.");
        return XSTDERR;
    }

    pAudio->pEncoder = DirectGate_Opus_Create(DIRECTGATE_AUDIO_SAMPLE_RATE,
        DIRECTGATE_AUDIO_CHANNELS, DIRECTGATE_AUDIO_BITRATE_KBPS, sErr, sizeof(sErr));

    if (pAudio->pEncoder == NULL)
    {
        DirectGate_Audio_SetReason(pDesktop, xstrused(sErr) ? sErr : "Opus encoder unavailable.");
        free(pAudio);
        return XSTDERR;
    }

    pAudio->pBackend = DirectGate_Audio_BackendOpen(DIRECTGATE_AUDIO_SAMPLE_RATE,
        DIRECTGATE_AUDIO_CHANNELS, sErr, sizeof(sErr));

    if (pAudio->pBackend == NULL)
    {
        DirectGate_Audio_SetReason(pDesktop, xstrused(sErr) ? sErr : "System audio source unavailable.");
        DirectGate_Opus_Destroy(pAudio->pEncoder);
        free(pAudio);
        return XSTDERR;
    }

    XSync_Init(&pAudio->lock);
    pAudio->bStop = XFALSE;

    if (XThread_Create(&pAudio->thread, DirectGate_Audio_Worker, pAudio, 0) != XSTDOK)
    {
        DirectGate_Audio_SetReason(pDesktop, "Failed to start audio capture thread.");
        DirectGate_Audio_BackendClose(pAudio->pBackend);
        DirectGate_Opus_Destroy(pAudio->pEncoder);
        XSync_Destroy(&pAudio->lock);
        free(pAudio);
        return XSTDERR;
    }

    pAudio->bThreadRunning = XTRUE;
    pDesktop->pAudio = pAudio;
    pDesktop->bAudioReady = XTRUE;
    pDesktop->sAudioReason[0] = '\0';

    xlogi("Desktop system audio started: sid(%u), opus(%s), rate(%u), channels(%u)",
        pSession->nSessionId, DirectGate_Opus_Version(),
        DIRECTGATE_AUDIO_SAMPLE_RATE, DIRECTGATE_AUDIO_CHANNELS);

    return XSTDOK;
}

void DirectGate_Desktop_AudioStop(directgate_desktop_t *pDesktop)
{
    XCHECK_VOID((pDesktop != NULL));
    directgate_audio_t *pAudio = (directgate_audio_t*)pDesktop->pAudio;

    pDesktop->bAudioReady = XFALSE;
    if (pAudio == NULL) return;

    /* Detach first so a concurrent drain on the main loop (same thread as this
     * call) never touches a half-freed instance. */
    pDesktop->pAudio = NULL;
    pAudio->bStop = XTRUE;

    if (pAudio->bThreadRunning)
    {
        XThread_Join(&pAudio->thread);
        pAudio->bThreadRunning = XFALSE;
    }

    if (pAudio->pBackend != NULL) DirectGate_Audio_BackendClose(pAudio->pBackend);
    if (pAudio->pEncoder != NULL) DirectGate_Opus_Destroy(pAudio->pEncoder);
    XSync_Destroy(&pAudio->lock);

    xlogi("Desktop system audio stopped: sid(%u), encoded(%llu), dropped(%llu)",
        pDesktop->nSessionId, (unsigned long long)pAudio->nFramesEncoded,
        (unsigned long long)pAudio->nFramesDropped);

    free(pAudio);
}

void DirectGate_Desktop_AudioDrainMain(directgate_session_t *pSession)
{
    XCHECK_VOID((pSession != NULL));
    directgate_audio_t *pAudio = (directgate_audio_t*)pSession->desktop.pAudio;
    if (pAudio == NULL) return;

    /* Only send once the browser's Opus track is open. While it is not, drain
     * and discard so a burst of stale frames never lands the moment it opens. */
    xbool_t bOpen = DirectGate_WebRTC_IsAudioOpen(&pSession->webrtc);

    directgate_audio_packet_t pkt;
    while (DirectGate_Audio_Pop(pAudio, &pkt))
    {
        if (!bOpen) continue;
        (void)DirectGate_WebRTC_SendOpus(&pSession->webrtc, pkt.data, pkt.nLen, pkt.nPtsUs);
    }
}

#endif /* DIRECTGATE_DESKTOP_HAS_AUDIO */
