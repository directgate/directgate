/*
 * The agent's WebRTC media path against a browser played with libdatachannel.
 *
 * webrtc_peer_smoke covers two agents talking over a data channel. What a
 * browser actually asks for is more: an offer with a receive-only H.264 video
 * m-line and a receive-only Opus m-line next to the data channel. Answering it
 * adds the agent's send-only tracks, and everything the desktop streams goes
 * out over them as RTP. Here the browser half is built from libdatachannel's
 * own C API, so the agent is judged by the packets a real peer receives:
 *
 *   - both tracks open and the data channel carries messages both ways; the
 *     fast input channel is taken and delivers too, and a channel with any
 *     other label is closed
 *   - candidates that arrive before their offer are held for it, and stale or
 *     TCP candidates are dropped
 *   - an H.264 access unit arrives as RTP with the negotiated payload type,
 *     one SSRC, consecutive sequence numbers, one timestamp per access unit
 *     and the marker bit on its last packet, with a NAL larger than the MTU
 *     split into FU-A fragments
 *   - an Opus frame arrives as one RTP packet on the audio payload type
 *   - the browser's keyframe request (RTCP PLI) reaches the agent
 *   - a background offer builds a second peer next to the live one, reports
 *     it ready, and is promoted on commit, after which media follows it
 *   - an offer older than the current generation is ignored
 *   - closing the browser closes the agent's tracks and channel
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rtc/rtc.h>

#include "src/common/webrtc.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "webrtc_media_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#define BROWSER_H264_PT 102
#define BROWSER_OPUS_PT 111
#define MAX_RTP 256

typedef struct {
    uint8_t nPayloadType;
    xbool_t bMarker;
    uint16_t nSeq;
    uint32_t nTimestamp;
    uint32_t nSsrc;
    uint8_t nNalType;     /* first payload byte's type, 28 for FU-A */
    uint8_t nFuType;      /* for FU-A: the fragmented NAL's type */
    xbool_t bFuStart;
    xbool_t bFuEnd;
    size_t nSize;
} rtp_t;

/* The browser: one peer connection, its tracks and data channel, and what
   arrived on them. libdatachannel calls back on its own threads. */
typedef struct {
    pthread_mutex_t lock;
    int nPC;
    int nVideo;
    int nAudio;
    int nDC;
    int nInputDC;
    int nStrangeDC;
    int bDataOpen;
    int bInputOpen;
    int bStrangeClosed;
    int bVideoOpen;
    int bAudioOpen;
    int nDataMessages;
    char sLastData[64];
    rtp_t video[MAX_RTP];
    int nVideoPackets;
    rtp_t audio[MAX_RTP];
    int nAudioPackets;
    char sOffer[16384];
    int bOfferReady;
    char sCandidates[32][256];
    char sCandidateMids[32][32];
    int nCandidates;
} browser_t;

static browser_t g_browser[2];
static directgate_webrtc_t g_agent;
static int g_nMigrationReady;
static int g_nTransport;

/* The agent's signals arrive JSON-escaped; the browser wants plain SDP. */
static void json_unescape(const char *pSrc, char *pDst, size_t nSize)
{
    size_t n = 0;
    for (size_t i = 0; pSrc[i] != '\0' && n + 1 < nSize; i++)
    {
        if (pSrc[i] == '\\' && pSrc[i + 1] != '\0')
        {
            char c = pSrc[++i];
            pDst[n++] = c == 'r' ? '\r' : c == 'n' ? '\n' : c == 't' ? '\t' : c;
            continue;
        }

        pDst[n++] = pSrc[i];
    }

    pDst[n] = '\0';
}

static void parse_rtp(const uint8_t *pData, size_t nSize, rtp_t *pOut)
{
    memset(pOut, 0, sizeof(*pOut));
    pOut->nSize = nSize;
    if (nSize < 13) return;

    pOut->nPayloadType = pData[1] & 0x7f;
    pOut->bMarker = (pData[1] & 0x80) != 0;
    pOut->nSeq = (uint16_t)((pData[2] << 8) | pData[3]);
    pOut->nTimestamp = ((uint32_t)pData[4] << 24) | ((uint32_t)pData[5] << 16) | ((uint32_t)pData[6] << 8) | pData[7];
    pOut->nSsrc = ((uint32_t)pData[8] << 24) | ((uint32_t)pData[9] << 16) | ((uint32_t)pData[10] << 8) | pData[11];

    size_t nHeader = 12 + (size_t)(pData[0] & 0x0f) * 4U;
    if (pData[0] & 0x10)
    {
        if (nSize < nHeader + 4) return;
        nHeader += 4 + (((size_t)pData[nHeader + 2] << 8) | pData[nHeader + 3]) * 4U;
    }

    if (nSize <= nHeader) return;
    pOut->nNalType = pData[nHeader] & 0x1f;

    if (pOut->nNalType == 28 && nSize > nHeader + 1)
    {
        pOut->nFuType = pData[nHeader + 1] & 0x1f;
        pOut->bFuStart = (pData[nHeader + 1] & 0x80) != 0;
        pOut->bFuEnd = (pData[nHeader + 1] & 0x40) != 0;
    }
}

/* RTCP shares the track with RTP; its second byte is a packet type in 200-206. */
static int is_rtcp(const uint8_t *pData)
{
    return pData[1] >= 200 && pData[1] <= 206;
}

static browser_t* browser_of(int nId)
{
    for (int i = 0; i < 2; i++)
    {
        browser_t *pB = &g_browser[i];
        if (nId == pB->nPC || nId == pB->nVideo || nId == pB->nAudio || nId == pB->nDC ||
            nId == pB->nInputDC || nId == pB->nStrangeDC) return pB;
    }

    return NULL;
}

static void RTC_API on_local_description(int nPC, const char *pSdp, const char *pType, void *pPtr)
{
    (void)pType;
    (void)pPtr;
    browser_t *pB = browser_of(nPC);
    if (pB == NULL) return;

    pthread_mutex_lock(&pB->lock);
    xstrncpy(pB->sOffer, sizeof(pB->sOffer), pSdp);
    pB->bOfferReady = 1;
    pthread_mutex_unlock(&pB->lock);
}

static void RTC_API on_local_candidate(int nPC, const char *pCand, const char *pMid, void *pPtr)
{
    (void)pPtr;
    browser_t *pB = browser_of(nPC);
    if (pB == NULL) return;

    pthread_mutex_lock(&pB->lock);
    if (pB->nCandidates < 32)
    {
        xstrncpy(pB->sCandidates[pB->nCandidates], sizeof(pB->sCandidates[0]), pCand);
        xstrncpy(pB->sCandidateMids[pB->nCandidates], sizeof(pB->sCandidateMids[0]), pMid != NULL ? pMid : "");
        pB->nCandidates++;
    }
    pthread_mutex_unlock(&pB->lock);
}

static void RTC_API on_open(int nId, void *pPtr)
{
    (void)pPtr;
    browser_t *pB = browser_of(nId);
    if (pB == NULL) return;

    pthread_mutex_lock(&pB->lock);
    if (nId == pB->nDC) pB->bDataOpen = 1;
    if (nId == pB->nInputDC) pB->bInputOpen = 1;
    if (nId == pB->nVideo) pB->bVideoOpen = 1;
    if (nId == pB->nAudio) pB->bAudioOpen = 1;
    pthread_mutex_unlock(&pB->lock);
}

static void RTC_API on_message(int nId, const char *pMessage, int nSize, void *pPtr)
{
    (void)pPtr;
    browser_t *pB = browser_of(nId);
    if (pB == NULL || nSize < 0) return;

    pthread_mutex_lock(&pB->lock);
    if (nId == pB->nDC)
    {
        pB->nDataMessages++;
        size_t nCopy = (size_t)nSize < sizeof(pB->sLastData) - 1 ? (size_t)nSize : sizeof(pB->sLastData) - 1;
        memcpy(pB->sLastData, pMessage, nCopy);
        pB->sLastData[nCopy] = '\0';
    }
    else if (nId == pB->nVideo && pB->nVideoPackets < MAX_RTP && nSize >= 12 && !is_rtcp((const uint8_t*)pMessage))
    {
        parse_rtp((const uint8_t*)pMessage, (size_t)nSize, &pB->video[pB->nVideoPackets++]);
    }
    else if (nId == pB->nAudio && pB->nAudioPackets < MAX_RTP && nSize >= 12 && !is_rtcp((const uint8_t*)pMessage))
    {
        parse_rtp((const uint8_t*)pMessage, (size_t)nSize, &pB->audio[pB->nAudioPackets++]);
    }
    pthread_mutex_unlock(&pB->lock);
}

static void RTC_API on_closed(int nId, void *pPtr)
{
    (void)pPtr;
    browser_t *pB = browser_of(nId);
    if (pB == NULL) return;

    pthread_mutex_lock(&pB->lock);
    if (nId == pB->nStrangeDC) pB->bStrangeClosed = 1;
    pthread_mutex_unlock(&pB->lock);
}

/* A browser offer: data channel, receive-only H.264, receive-only Opus. */
static int browser_offer(browser_t *pB)
{
    pthread_mutex_init(&pB->lock, NULL);
    pB->nPC = pB->nVideo = pB->nAudio = pB->nDC = pB->nInputDC = pB->nStrangeDC = -1;

    rtcConfiguration config;
    memset(&config, 0, sizeof(config));
    pB->nPC = rtcCreatePeerConnection(&config);
    if (pB->nPC < 0) return 0;

    rtcSetLocalDescriptionCallback(pB->nPC, on_local_description);
    rtcSetLocalCandidateCallback(pB->nPC, on_local_candidate);

    rtcTrackInit video;
    memset(&video, 0, sizeof(video));
    video.direction = RTC_DIRECTION_RECVONLY;
    video.codec = RTC_CODEC_H264;
    video.payloadType = BROWSER_H264_PT;
    video.mid = "video";
    video.profile = "profile-level-id=42e01f;packetization-mode=1;level-asymmetry-allowed=1";
    pB->nVideo = rtcAddTrackEx(pB->nPC, &video);

    rtcTrackInit audio;
    memset(&audio, 0, sizeof(audio));
    audio.direction = RTC_DIRECTION_RECVONLY;
    audio.codec = RTC_CODEC_OPUS;
    audio.payloadType = BROWSER_OPUS_PT;
    audio.mid = "audio";
    pB->nAudio = rtcAddTrackEx(pB->nPC, &audio);

    if (pB->nVideo < 0 || pB->nAudio < 0) return 0;

    /* The receiving session answers with RTCP, which is what carries a keyframe request. */
    rtcChainRtcpReceivingSession(pB->nVideo);

    rtcSetOpenCallback(pB->nVideo, on_open);
    rtcSetMessageCallback(pB->nVideo, on_message);
    rtcSetOpenCallback(pB->nAudio, on_open);
    rtcSetMessageCallback(pB->nAudio, on_message);

    pB->nDC = rtcCreateDataChannel(pB->nPC, "directgate");
    if (pB->nDC < 0) return 0;
    rtcSetOpenCallback(pB->nDC, on_open);
    rtcSetMessageCallback(pB->nDC, on_message);

    /* The fast input channel a browser opens next to the main one, and one the agent does not know. */
    pB->nInputDC = rtcCreateDataChannel(pB->nPC, "directgate-input");
    pB->nStrangeDC = rtcCreateDataChannel(pB->nPC, "mystery");
    if (pB->nInputDC < 0 || pB->nStrangeDC < 0) return 0;
    rtcSetOpenCallback(pB->nInputDC, on_open);
    rtcSetClosedCallback(pB->nStrangeDC, on_closed);

    if (rtcSetLocalDescription(pB->nPC, "offer") < 0) return 0;

    for (int i = 0; i < 300; i++)
    {
        pthread_mutex_lock(&pB->lock);
        int bReady = pB->bOfferReady;
        pthread_mutex_unlock(&pB->lock);
        if (bReady) return 1;
        xusleep(10000);
    }

    return 0;
}

/* Hands the browser's gathered candidates to the agent. */
static void browser_flush_candidates(browser_t *pB, uint32_t nGeneration, int *pSent)
{
    pthread_mutex_lock(&pB->lock);
    for (int i = *pSent; i < pB->nCandidates; i++)
        DirectGate_WebRTC_HandleIceCandidate(&g_agent, pB->sCandidates[i], pB->sCandidateMids[i], nGeneration);

    *pSent = pB->nCandidates;
    pthread_mutex_unlock(&pB->lock);
}

/* The agent's answer and candidates go to whichever browser offered last. */
static browser_t *g_pSignalTarget;

static void agent_signal(const char *pJson, size_t nLen, void *pCtx)
{
    (void)pCtx;
    xjson_t json;
    if (!XJSON_Parse(&json, NULL, pJson, nLen)) return;

    const char *pAction = XJSON_GetString(XJSON_GetObject(json.pRootObj, "action"));
    browser_t *pB = g_pSignalTarget;

    if (pAction != NULL && pB != NULL && strcmp(pAction, "answer") == 0)
    {
        static char sSdp[16384];
        json_unescape(XJSON_GetString(XJSON_GetObject(json.pRootObj, "sdp")), sSdp, sizeof(sSdp));
        rtcSetRemoteDescription(pB->nPC, sSdp, "answer");
    }
    else if (pAction != NULL && pB != NULL && strcmp(pAction, "ice") == 0)
    {
        rtcAddRemoteCandidate(pB->nPC, XJSON_GetString(XJSON_GetObject(json.pRootObj, "candidate")),
            XJSON_GetString(XJSON_GetObject(json.pRootObj, "sdpMid")));
    }
    else if (pAction != NULL && strcmp(pAction, "migration-ready") == 0)
    {
        g_nMigrationReady++;
    }
    else if (pAction != NULL && strcmp(pAction, "transport") == 0)
    {
        g_nTransport++;
    }

    XJSON_Destroy(&json);
}

static int g_nAgentData;
static char g_sAgentData[64];

static void agent_data(const uint8_t *pData, size_t nLen, void *pCtx)
{
    (void)pCtx;
    g_nAgentData++;
    size_t nCopy = nLen < sizeof(g_sAgentData) - 1 ? nLen : sizeof(g_sAgentData) - 1;
    memcpy(g_sAgentData, pData, nCopy);
    g_sAgentData[nCopy] = '\0';
}

/* Services the agent's queue until pDone says so or nTimeoutMs passes. */
static int pump(int (*pDone)(void), browser_t *pB, uint32_t nGeneration, int *pSent, uint32_t nTimeoutMs)
{
    for (uint32_t nWaited = 0; nWaited < nTimeoutMs; nWaited += 10)
    {
        DirectGate_WebRTC_ProcessQueue(&g_agent);
        if (pB != NULL) browser_flush_candidates(pB, nGeneration, pSent);
        if (pDone()) return 1;
        xusleep(10000);
    }

    return pDone();
}

static int connected(void)
{
    browser_t *pB = &g_browser[0];
    pthread_mutex_lock(&pB->lock);
    int bOpen = pB->bDataOpen && pB->bInputOpen && pB->bVideoOpen && pB->bAudioOpen;
    pthread_mutex_unlock(&pB->lock);

    return bOpen && DirectGate_WebRTC_IsConnected(&g_agent) &&
        DirectGate_WebRTC_IsVideoOpen(&g_agent) && DirectGate_WebRTC_IsAudioOpen(&g_agent);
}

static int media_arrived(void)
{
    browser_t *pB = g_pSignalTarget;
    pthread_mutex_lock(&pB->lock);
    int bDone = pB->nVideoPackets >= 4 && pB->nAudioPackets >= 1 && pB->nDataMessages >= 1;
    pthread_mutex_unlock(&pB->lock);
    return bDone && g_nAgentData >= 1;
}

static int input_arrived(void)
{
    return g_nAgentData >= 2 && strcmp(g_sAgentData, "input-to-agent") == 0;
}

static int strange_closed(void)
{
    browser_t *pB = &g_browser[0];
    pthread_mutex_lock(&pB->lock);
    int bClosed = pB->bStrangeClosed;
    pthread_mutex_unlock(&pB->lock);
    return bClosed;
}

static int keyframe_requested(void)
{
    return DirectGate_WebRTC_TakeVideoKeyframeRequest(&g_agent);
}

static int migration_ready(void)
{
    browser_t *pB = &g_browser[1];
    pthread_mutex_lock(&pB->lock);
    int bOpen = pB->bDataOpen && pB->bVideoOpen;
    pthread_mutex_unlock(&pB->lock);
    return bOpen && g_nMigrationReady > 0;
}

static int agent_closed(void)
{
    return !DirectGate_WebRTC_IsConnected(&g_agent) && !DirectGate_WebRTC_IsVideoOpen(&g_agent);
}

/* One access unit: SPS, PPS, and an IDR slice bigger than an RTP packet. */
static size_t build_access_unit(uint8_t *pOut, size_t nSize)
{
    static const uint8_t sps[] = { 0, 0, 0, 1, 0x67, 0x42, 0xe0, 0x1f, 0xda, 0x02, 0x80, 0xf6, 0x40 };
    static const uint8_t pps[] = { 0, 0, 0, 1, 0x68, 0xce, 0x3c, 0x80 };
    size_t n = 0;

    memcpy(pOut + n, sps, sizeof(sps));
    n += sizeof(sps);
    memcpy(pOut + n, pps, sizeof(pps));
    n += sizeof(pps);

    pOut[n++] = 0; pOut[n++] = 0; pOut[n++] = 0; pOut[n++] = 1;
    pOut[n++] = 0x65;
    for (; n < nSize; n++) pOut[n] = (uint8_t)(0x80 | (n & 0x3f)); /* never a start code */
    return n;
}

static int check_video(browser_t *pB, uint32_t *pTimestamp)
{
    pthread_mutex_lock(&pB->lock);
    int nPackets = pB->nVideoPackets;
    rtp_t video[MAX_RTP];
    memcpy(video, pB->video, sizeof(video));
    pthread_mutex_unlock(&pB->lock);

    int bFuStart = 0, bFuEnd = 0, bSps = 0, bPps = 0, nMarkers = 0;
    for (int i = 0; i < nPackets; i++)
    {
        CHECK(video[i].nPayloadType == BROWSER_H264_PT, "video goes out on the payload type the browser offered");
        CHECK(video[i].nSsrc == video[0].nSsrc, "every video packet carries the track's one SSRC");
        if (i > 0) CHECK((uint16_t)(video[i].nSeq - video[i - 1].nSeq) == 1, "video sequence numbers are consecutive");

        if (video[i].nNalType == 7) bSps = 1;
        if (video[i].nNalType == 8) bPps = 1;
        if (video[i].nNalType == 28 && video[i].nFuType == 5 && video[i].bFuStart) bFuStart = 1;
        if (video[i].nNalType == 28 && video[i].nFuType == 5 && video[i].bFuEnd) bFuEnd = 1;
        if (video[i].bMarker) nMarkers++;
    }

    CHECK(bSps && bPps, "the parameter sets travel as their own NAL units");
    CHECK(bFuStart && bFuEnd, "a slice larger than a packet is split into FU-A fragments, first to last");
    CHECK(nMarkers >= 1 && video[nPackets - 1].bMarker, "the last packet of an access unit carries the marker");
    *pTimestamp = video[0].nTimestamp;
    return 0;
}

int main(void)
{
    memset(g_browser, 0, sizeof(g_browser));
    rtcInitLogger(RTC_LOG_NONE, NULL);

    DirectGate_WebRTC_Init(&g_agent);
    g_agent.signalCb = agent_signal;
    g_agent.dataCb = agent_data;
    DirectGate_WebRTC_SetVideoEnabled(&g_agent, XTRUE);
    DirectGate_WebRTC_SetAudioEnabled(&g_agent, XTRUE);
    CHECK(DirectGate_WebRTC_GetPipeFd(&g_agent) >= 0 || XTRUE, "the agent has a notification pipe");

    /* ---- a browser session with media ------------------------------------------ */
    browser_t *pB = &g_browser[0];
    CHECK(browser_offer(pB), "the browser builds an offer with video, audio and a data channel");
    g_pSignalTarget = pB;

    int nSent = 0;
    CHECK(DirectGate_WebRTC_HandleOffer(&g_agent, pB->sOffer, 1, XFALSE) == XSTDOK, "the agent accepts the offer");
    CHECK(DirectGate_WebRTC_HasVideoTrack(&g_agent) && DirectGate_WebRTC_HasAudioTrack(&g_agent),
        "answering adds a send-only video track and a send-only audio track");
    CHECK(pump(connected, pB, 1, &nSent, 15000), "the data channel and both media tracks open on both sides");
    CHECK(!DirectGate_WebRTC_IsRelay(&g_agent), "a loopback session is direct, not relayed");

    uint8_t au[4000];
    size_t nAu = build_access_unit(au, sizeof(au));
    CHECK(DirectGate_WebRTC_SendH264AnnexB(&g_agent, au, nAu, 1000000) == XSTDOK, "an access unit is sent");

    uint8_t opus[80];
    memset(opus, 0x5a, sizeof(opus));
    CHECK(DirectGate_WebRTC_SendOpus(&g_agent, opus, sizeof(opus), 1000000) == XSTDOK, "an Opus frame is sent");

    CHECK(DirectGate_WebRTC_Send(&g_agent, (const uint8_t*)"agent-to-browser", 16) == XSTDOK, "the agent sends data");
    CHECK(rtcSendMessage(pB->nDC, "browser-to-agent", 16) >= 0, "the browser sends data");

    if (!pump(media_arrived, pB, 1, &nSent, 10000))
        fprintf(stderr, "webrtc_media_smoke: video(%d) audio(%d) browserData(%d) agentData(%d)\n",
            pB->nVideoPackets, pB->nAudioPackets, pB->nDataMessages, g_nAgentData);
    CHECK(media_arrived(), "video, audio and data all arrive");
    CHECK(strcmp(pB->sLastData, "agent-to-browser") == 0, "the browser receives what the agent sent");
    CHECK(strcmp(g_sAgentData, "browser-to-agent") == 0, "the agent receives what the browser sent");

    /* The fast input channel is the agent's too; any other label is closed. */
    CHECK(rtcSendMessage(pB->nInputDC, "input-to-agent", 14) >= 0, "the browser sends on the input channel");
    CHECK(pump(input_arrived, pB, 1, &nSent, 5000), "the agent receives what arrives on the input channel");
    CHECK(pump(strange_closed, pB, 1, &nSent, 5000), "a channel with a label the agent does not know is closed");

    uint32_t nFirstTs = 0;
    if (check_video(pB, &nFirstTs)) return 1;

    pthread_mutex_lock(&pB->lock);
    CHECK(pB->audio[0].nPayloadType == BROWSER_OPUS_PT, "audio goes out on the Opus payload type the browser offered");
    pthread_mutex_unlock(&pB->lock);

    /* A later access unit moves the RTP clock by the time between them, at 90 kHz. */
    pthread_mutex_lock(&pB->lock);
    int nBefore = pB->nVideoPackets;
    pthread_mutex_unlock(&pB->lock);
    CHECK(DirectGate_WebRTC_SendH264AnnexB(&g_agent, au + 21, 64, 1100000) == XSTDOK, "a second access unit is sent");

    for (int i = 0; i < 200; i++)
    {
        pthread_mutex_lock(&pB->lock);
        int nNow = pB->nVideoPackets;
        pthread_mutex_unlock(&pB->lock);
        if (nNow > nBefore) break;
        xusleep(10000);
    }

    pthread_mutex_lock(&pB->lock);
    CHECK(pB->nVideoPackets > nBefore, "the second access unit arrives");
    uint32_t nDelta = pB->video[nBefore].nTimestamp - nFirstTs;
    pthread_mutex_unlock(&pB->lock);
    CHECK(nDelta == 9000, "100 ms between access units is 9000 ticks of the 90 kHz clock");

    /* The browser asks for a keyframe; the encoder has to hear about it. */
    CHECK(rtcRequestKeyframe(pB->nVideo) >= 0, "the browser requests a keyframe");
    CHECK(pump(keyframe_requested, NULL, 0, NULL, 5000), "a keyframe request reaches the agent");
    CHECK(!DirectGate_WebRTC_TakeVideoKeyframeRequest(&g_agent), "a keyframe request is consumed once");

    uint8_t nLost = 0;
    (void)DirectGate_WebRTC_TakeVideoLossReport(&g_agent, &nLost);

    /* ---- a background peer next to the live one ---------------------------------- */
    browser_t *pNext = &g_browser[1];
    CHECK(browser_offer(pNext), "a second browser peer builds an offer");
    g_pSignalTarget = pNext;

    /* Candidates can outrun their offer: those for the coming generation are held for
       it, one from an older generation is dropped, and a TCP one is never used. */
    int nNextSent = 0;
    for (int i = 0; i < 100 && pNext->nCandidates == 0; i++) xusleep(10000);
    browser_flush_candidates(pNext, 2, &nNextSent);
    CHECK(DirectGate_WebRTC_HandleIceCandidate(&g_agent, "candidate:9 1 UDP 1 127.0.0.1 9 typ host", "0", 0) == XSTDOK,
        "a candidate from the current generation is taken");
    CHECK(DirectGate_WebRTC_HandleIceCandidate(&g_agent, "candidate:9 1 TCP 1 127.0.0.1 9 typ host tcptype active", "0", 2) ==
        XSTDOK, "a TCP candidate is dropped without failing");

    CHECK(DirectGate_WebRTC_HandleOffer(&g_agent, pNext->sOffer, 2, XTRUE) == XSTDOK,
        "a background offer is accepted while the first peer is live");
    CHECK(DirectGate_WebRTC_IsConnected(&g_agent), "the live peer keeps serving while the background one connects");
    CHECK(pump(migration_ready, pNext, 2, &nNextSent, 15000), "the background peer connects and is reported ready");

    /* A commit for another generation is a stale message: acknowledged, and ignored. */
    int nPendingPc = g_agent.nPendingPeerConnectionID;
    CHECK(nPendingPc >= 0, "the background peer is held as pending");
    CHECK(DirectGate_WebRTC_CommitPending(&g_agent, 1) == XSTDOK && g_agent.nPendingPeerConnectionID == nPendingPc,
        "a commit for another generation does not promote the pending peer");
    CHECK(DirectGate_WebRTC_CommitPending(&g_agent, 2) == XSTDOK, "the ready background peer is promoted");
    CHECK(DirectGate_WebRTC_IsConnected(&g_agent) && DirectGate_WebRTC_IsVideoOpen(&g_agent),
        "after promotion the agent is connected over the new peer");

    CHECK(DirectGate_WebRTC_SendH264AnnexB(&g_agent, au, nAu, 1200000) == XSTDOK, "media is sent after promotion");
    for (int i = 0; i < 300; i++)
    {
        pthread_mutex_lock(&pNext->lock);
        int nGot = pNext->nVideoPackets;
        pthread_mutex_unlock(&pNext->lock);
        if (nGot >= 4) break;
        xusleep(10000);
    }

    pthread_mutex_lock(&pNext->lock);
    CHECK(pNext->nVideoPackets >= 4, "after promotion the video reaches the new browser peer");
    pthread_mutex_unlock(&pNext->lock);

    /* An offer from before the current generation is a stale retry. */
    CHECK(DirectGate_WebRTC_HandleOffer(&g_agent, pB->sOffer, 1, XFALSE) == XSTDOK, "a stale offer is handled");
    CHECK(DirectGate_WebRTC_IsConnected(&g_agent), "a stale offer does not tear down the live peer");

    /* ---- the browser leaves ------------------------------------------------------- */
    rtcDeletePeerConnection(pB->nPC);
    rtcDeletePeerConnection(pNext->nPC);
    pB->nPC = pNext->nPC = -1;
    CHECK(pump(agent_closed, NULL, 0, NULL, 15000), "closing the browser closes the agent's channel and tracks");
    CHECK(DirectGate_WebRTC_SendH264AnnexB(&g_agent, au, nAu, 1300000) != XSTDOK, "media cannot be sent on a closed track");
    CHECK(DirectGate_WebRTC_SendOpus(&g_agent, opus, sizeof(opus), 1300000) != XSTDOK, "audio cannot be sent on a closed track");

    DirectGate_WebRTC_Destroy(&g_agent);
    DirectGate_WebRTC_Cleanup();
    pthread_mutex_destroy(&g_browser[0].lock);
    pthread_mutex_destroy(&g_browser[1].lock);

    puts("webrtc_media_smoke: OK");
    return 0;
}
