/* What the WebRTC transport refuses or ignores: missing objects and arguments on every entry point, libdatachannel
 * callbacks for connections, channels and tracks it does not know (late ones from a connection already replaced),
 * media sent before its track is open, payloads too large to packetize, and RTCP too short to read. Each refusal
 * is checked to leave the transport as it was. Includes webrtc.c, as webrtc_static_smoke does, for the callbacks. */

#include <stdio.h>
#include "src/common/webrtc.c"

#define CHECK(c, msg) \
    do { if (!(c)) { fprintf(stderr, "webrtc_guards_smoke: %s (line %d)\n", msg, __LINE__); return 1; } } while (0)

static int g_nDispatched;
static char g_sFirst[32], g_sSecond[32];

static void record_strings(const directgate_webrtc_event_t *pEvt, void *pCtx)
{
    (void)pCtx;
    g_nDispatched++;
    const char *pFirst = (const char*)pEvt->pData;
    xstrncpy(g_sFirst, sizeof(g_sFirst), pFirst);
    xstrncpy(g_sSecond, sizeof(g_sSecond), pFirst + strlen(pFirst) + 1);
}

/* Nothing about the connection changed */
static int untouched(const directgate_webrtc_t *pRTC)
{
    return pRTC->nPeerConnectionID == -1 && pRTC->nDataChannelID == -1 && pRTC->nVideoTrackID == -1 &&
        !pRTC->bConnected && pRTC->pQueueHead == NULL && !pRTC->bQueueFailed;
}

static int check_accessors(directgate_webrtc_t *pRTC)
{
    CHECK(DirectGate_WebRTC_GetPC(NULL) == XSTDERR && DirectGate_WebRTC_GetDC(NULL) == XSTDERR &&
          DirectGate_WebRTC_GetVideoTrack(NULL) == XSTDERR && DirectGate_WebRTC_GetAudioTrack(NULL) == XSTDERR &&
          DirectGate_WebRTC_GetPipe(NULL) == XSTDERR && DirectGate_WebRTC_GetPipeFd(NULL) == XSTDERR,
        "no transport has no handles");
    CHECK(!DirectGate_WebRTC_IsCurrentPeerConnection(NULL, 1) && !DirectGate_WebRTC_IsPendingPeerConnection(NULL, 1) &&
          !DirectGate_WebRTC_IsCurrentPeerConnection(pRTC, -1) && !DirectGate_WebRTC_IsPendingPeerConnection(pRTC, -1),
        "and no connection is current or pending on it");
    CHECK(!DirectGate_WebRTC_IsConnected(NULL) && !DirectGate_WebRTC_IsRelay(NULL) &&
          !DirectGate_WebRTC_HasVideoTrack(NULL) && !DirectGate_WebRTC_IsVideoOpen(NULL) &&
          !DirectGate_WebRTC_HasAudioTrack(NULL) && !DirectGate_WebRTC_IsAudioOpen(NULL), "nor anything open");
    CHECK(DirectGate_WebRTC_GetBufferedAmount(NULL) == XSTDERR && DirectGate_WebRTC_GetBufferedAmount(pRTC) == XSTDERR,
        "a transport without a data channel has nothing buffered");

    DirectGate_WebRTC_NoteSendFailure(NULL);
    DirectGate_WebRTC_SetVideoEnabled(NULL, XTRUE);
    DirectGate_WebRTC_SetAudioEnabled(NULL, XTRUE);
    DirectGate_WebRTC_Init(NULL);
    DirectGate_WebRTC_Destroy(NULL);
    DirectGate_WebRTC_Clear(NULL);
    return 0;
}

static int check_sdp(void)
{
    uint8_t nPt = 0;
    char sMid[16], sProfile[64];
    const char *pSdp = "m=video 9 UDP/TLS/RTP/SAVPF 102\r\na=mid:0\r\na=rtpmap:102 H264/90000\r\n";

    CHECK(!DirectGate_WebRTC_ParseRemoteH264(NULL, &nPt, sMid, sizeof(sMid), sProfile, sizeof(sProfile)) &&
          !DirectGate_WebRTC_ParseRemoteH264("", &nPt, sMid, sizeof(sMid), sProfile, sizeof(sProfile)) &&
          !DirectGate_WebRTC_ParseRemoteH264(pSdp, NULL, sMid, sizeof(sMid), sProfile, sizeof(sProfile)) &&
          !DirectGate_WebRTC_ParseRemoteH264(pSdp, &nPt, NULL, sizeof(sMid), sProfile, sizeof(sProfile)) &&
          !DirectGate_WebRTC_ParseRemoteH264(pSdp, &nPt, sMid, 0, sProfile, sizeof(sProfile)) &&
          !DirectGate_WebRTC_ParseRemoteH264(pSdp, &nPt, sMid, sizeof(sMid), NULL, sizeof(sProfile)) &&
          !DirectGate_WebRTC_ParseRemoteH264(pSdp, &nPt, sMid, sizeof(sMid), sProfile, 0),
        "an H.264 answer needs an SDP and every place to put it");
    CHECK(DirectGate_WebRTC_ParseRemoteH264(pSdp, &nPt, sMid, sizeof(sMid), sProfile, sizeof(sProfile)) && nPt == 102,
        "and with them it is found");

    const char *pOpus = "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=rtpmap:111 opus/48000/2\r\n";
    CHECK(!DirectGate_WebRTC_ParseRemoteOpus(pOpus, NULL, sMid, sizeof(sMid)) &&
          !DirectGate_WebRTC_ParseRemoteOpus(pOpus, &nPt, NULL, sizeof(sMid)) &&
          !DirectGate_WebRTC_ParseRemoteOpus(pOpus, &nPt, sMid, 0), "Opus needs every place to put it too");

    char sLine[8] = "kept";
    DirectGate_WebRTC_CopySdpLine(NULL, sizeof(sLine), "x", 1);
    DirectGate_WebRTC_CopySdpLine(sLine, 0, "x", 1);
    CHECK(strcmp(sLine, "kept") == 0, "a line is copied nowhere without room");

    CHECK(DirectGate_JSON_Unescape(NULL) == NULL && DirectGate_JSON_Unescape("") == NULL, "nothing to unescape");
    return 0;
}

static int check_queue(directgate_webrtc_t *pRTC)
{
    CHECK(DirectGate_WebRTC_NotifyPipe(NULL) == XSTDERR && XSell_WebRTC_DetachQueue(NULL) == NULL, "no transport, no queue");
    DirectGate_WebRTC_DrainPipe(NULL);
    CHECK(!DirectGate_WebRTC_EnqueueCallback(NULL, DIRECTGATE_WEBRTC_CALLBACK, 1, NULL, 0, 0, record_strings),
        "a callback for no transport is not queued");

    /* Two strings travel as one event; a missing second one is an empty one */
    DirectGate_WebRTC_QueueStrings(1, NULL, "x", pRTC, record_strings);
    DirectGate_WebRTC_QueueStrings(1, "x", "y", NULL, record_strings);
    CHECK(untouched(pRTC), "strings without a first or a transport are not queued");
    DirectGate_WebRTC_QueueStrings(7, "first", NULL, pRTC, record_strings);
    DirectGate_WebRTC_ProcessQueue(pRTC);
    CHECK(g_nDispatched == 1 && strcmp(g_sFirst, "first") == 0 && g_sSecond[0] == '\0', "a missing second string arrives empty");

    /* A dispatch already running is not entered again */
    xbool_t bAlive = XTRUE;
    DirectGate_WebRTC_QueueStrings(8, "again", "x", pRTC, record_strings);
    pRTC->pDispatchAlive = &bAlive;
    DirectGate_WebRTC_ProcessQueue(pRTC);
    CHECK(g_nDispatched == 1, "a queue is not drained from inside its own dispatch");
    pRTC->pDispatchAlive = NULL;
    DirectGate_WebRTC_ProcessQueue(pRTC);
    CHECK(g_nDispatched == 2, "and is drained once that dispatch is over");
    DirectGate_WebRTC_ProcessQueue(NULL);

    directgate_webrtc_event_t evt = { 0 };
    DirectGate_WebRTC_DispatchDataCb(NULL, &evt);
    DirectGate_WebRTC_DispatchDataCb(pRTC, NULL);
    DirectGate_WebRTC_DispatchDataCb(pRTC, &evt);
    DirectGate_WebRTC_DispatchSignalCb(NULL, &evt);
    DirectGate_WebRTC_DispatchSignalCb(pRTC, NULL);
    DirectGate_WebRTC_DispatchSignalCb(pRTC, &evt);
    CHECK(untouched(pRTC), "dispatching to nobody does nothing");
    return 0;
}

static int check_ice(directgate_webrtc_t *pRTC)
{
    CHECK(DirectGate_WebRTC_BufferIce(NULL, "candidate:1", "0", 1) == XSTDERR &&
          DirectGate_WebRTC_BufferIce(pRTC, "", "0", 1) == XSTDERR && pRTC->pPendingIce == NULL,
        "no candidate is buffered for no transport, or without a candidate");
    DirectGate_WebRTC_FlushPendingIce(NULL);
    DirectGate_WebRTC_ClearPendingIce(NULL);

    directgate_ice_server_t servers[DIRECTGATE_MAX_ICE_SERVERS];
    uint8_t nCount = 9;
    xjson_t json;
    const char *pDoc = "{\"iceServers\":\"stun:not-a-list\"}";
    CHECK(XJSON_Parse(&json, NULL, pDoc, strlen(pDoc)), "parse ICE servers that are not a list");
    CHECK(!DirectGate_WebRTC_LoadIceServers(NULL, &nCount, json.pRootObj) &&
          !DirectGate_WebRTC_LoadIceServers(servers, NULL, json.pRootObj) &&
          !DirectGate_WebRTC_LoadIceServers(servers, &nCount, NULL), "loading ICE servers needs every part");
    CHECK(DirectGate_WebRTC_LoadIceServers(servers, &nCount, json.pRootObj) && nCount > 0 &&
          strcmp(servers[0], g_pIceServers[0]) == 0, "ICE servers that are not a list fall back to the built-in ones");
    XJSON_Destroy(&json);

    DirectGate_WebRTC_SetIceServers(NULL, servers, 1);
    DirectGate_WebRTC_SetIceServers(pRTC, NULL, 1);
    DirectGate_WebRTC_SetIceServers(pRTC, servers, 0);
    CHECK(pRTC->nIceSrvCount == 0, "and setting none sets none");

    CHECK(DirectGate_WebRTC_HandleIceCandidate(NULL, "candidate:1", "0", 1) == XSTDERR &&
          DirectGate_WebRTC_HandleIceCandidate(pRTC, NULL, "0", 1) == XSTDERR, "a candidate needs a transport");
    return 0;
}

static int check_negotiation(directgate_webrtc_t *pRTC)
{
    CHECK(DirectGate_WebRTC_CreateOffer(NULL) == XSTDERR && DirectGate_WebRTC_CommitPending(NULL, 1) == XSTDERR,
        "no transport makes no offer and commits nothing");
    CHECK(DirectGate_WebRTC_HandleAnswer(NULL, "v=0") == XSTDERR && DirectGate_WebRTC_HandleAnswer(pRTC, NULL) == XSTDERR,
        "an answer needs a transport and an SDP");
    CHECK(DirectGate_WebRTC_HandleOffer(NULL, "v=0", 1, XFALSE) == XSTDERR &&
          DirectGate_WebRTC_HandleOffer(pRTC, NULL, 1, XFALSE) == XSTDERR, "so does an offer");

    DirectGate_WebRTC_DestroyPending(NULL);
    DirectGate_WebRTC_PromotePending(NULL);

    /* A pending connection is promoted only once it has everything; any one thing missing keeps it pending */
    DirectGate_WebRTC_PromotePending(pRTC);
    pRTC->nPendingPeerConnectionID = 900;
    DirectGate_WebRTC_PromotePending(pRTC);
    pRTC->bPendingDataOpen = XTRUE;
    DirectGate_WebRTC_PromotePending(pRTC);
    pRTC->bPendingDirect = XTRUE;
    pRTC->bVideoEnabled = XTRUE;
    DirectGate_WebRTC_PromotePending(pRTC);
    pRTC->bPendingVideoOpen = XTRUE;
    DirectGate_WebRTC_PromotePending(pRTC);
    CHECK(pRTC->nPendingPeerConnectionID == 900 && pRTC->nPeerConnectionID == -1, "an incomplete connection stays pending");
    pRTC->nPendingPeerConnectionID = -1;
    pRTC->bPendingDataOpen = pRTC->bPendingDirect = pRTC->bVideoEnabled = pRTC->bPendingVideoOpen = XFALSE;

    DirectGate_WebRTC_SendSignal(NULL, "{}", 2);
    DirectGate_WebRTC_SendSignal(pRTC, NULL, 2);
    DirectGate_WebRTC_SendSignal(pRTC, "{}", 0);
    DirectGate_WebRTC_NotifyTransport(NULL, 1);
    DirectGate_WebRTC_NotifyPendingReady(NULL);
    CHECK(untouched(pRTC), "no signal is sent for no transport, or without one");

    CHECK(DirectGate_WebRTC_AddDesktopVideoTrack(NULL, 1, "", XFALSE) == XSTDERR &&
          DirectGate_WebRTC_AddDesktopVideoTrack(pRTC, -1, "", XFALSE) == XSTDERR &&
          DirectGate_WebRTC_AddDesktopVideoTrack(pRTC, 1, "", XFALSE) == XSTDERR, "no video track without video");
    CHECK(DirectGate_WebRTC_AddDesktopAudioTrack(NULL, 1, "", XFALSE) == XSTDERR &&
          DirectGate_WebRTC_AddDesktopAudioTrack(pRTC, -1, "", XFALSE) == XSTDERR &&
          DirectGate_WebRTC_AddDesktopAudioTrack(pRTC, 1, "", XFALSE) == XSTDERR, "no audio track without audio");
    return 0;
}

/* libdatachannel reporting on things this transport does not hold, as a replaced connection still does */
static int check_callbacks(directgate_webrtc_t *pRTC)
{
    DirectGate_WebRTC_OnLocalDescription(1, NULL, "offer", pRTC);
    DirectGate_WebRTC_OnLocalDescription(1, "v=0", NULL, pRTC);
    DirectGate_WebRTC_OnLocalDescription(1, "v=0", "offer", NULL);
    DirectGate_WebRTC_OnLocalDescription(900, "v=0", "offer", pRTC);
    DirectGate_WebRTC_OnLocalCandidate(1, NULL, "0", pRTC);
    DirectGate_WebRTC_OnLocalCandidate(1, "candidate:1", "0", NULL);
    DirectGate_WebRTC_OnLocalCandidate(900, "candidate:1", "0", pRTC);
    DirectGate_WebRTC_OnGatheringStateChange(900, RTC_GATHERING_COMPLETE, pRTC);
    DirectGate_WebRTC_OnStateChange(900, RTC_CONNECTED, pRTC);
    DirectGate_WebRTC_OnIceStateChange(900, RTC_ICE_CONNECTED, pRTC);
    DirectGate_WebRTC_OnSignalingStateChange(900, RTC_SIGNALING_STABLE, pRTC);
    CHECK(untouched(pRTC), "connection events for an unknown connection are ignored");

    DirectGate_WebRTC_OnDataChannelOpen(1, NULL);
    DirectGate_WebRTC_OnDataChannelClosed(1, NULL);
    DirectGate_WebRTC_OnDataChannelError(1, "error", NULL);
    DirectGate_WebRTC_OnDataChannelError(900, NULL, pRTC);
    DirectGate_WebRTC_QueueDataChannelMessage(1, "x", 1, NULL);
    DirectGate_WebRTC_QueueDataChannelMessage(1, NULL, 1, pRTC);
    DirectGate_WebRTC_QueueDataChannelMessage(1, "x", 0, pRTC);
    DirectGate_WebRTC_OnDataChannel(1, -1, NULL);
    DirectGate_WebRTC_OnDataChannel(900, -1, pRTC);
    CHECK(untouched(pRTC), "and so are channel events");

    DirectGate_WebRTC_OnVideoTrackOpen(1, NULL);
    DirectGate_WebRTC_OnVideoTrackClosed(1, NULL);
    DirectGate_WebRTC_OnAudioTrackOpen(1, NULL);
    DirectGate_WebRTC_OnAudioTrackClosed(1, NULL);
    DirectGate_WebRTC_OnVideoTrackError(1, "error", NULL);
    DirectGate_WebRTC_OnVideoTrackMessage(1, "x", 1, NULL);
    DirectGate_WebRTC_OnVideoTrackMessage(1, NULL, 1, pRTC);
    DirectGate_WebRTC_OnVideoTrackMessage(1, "x", 0, pRTC);
    CHECK(untouched(pRTC), "and track events");
    return 0;
}

/* Events for a channel or track this transport has since replaced arrive after the replacement and change nothing */
static int check_stale(directgate_webrtc_t *pRTC)
{
    pRTC->nDataChannelID = 5;
    pRTC->nVideoTrackID = 6;
    pRTC->nAudioTrackID = 7;

    DirectGate_WebRTC_OnDataChannelOpen(9, pRTC);
    DirectGate_WebRTC_OnDataChannelClosed(9, pRTC);
    DirectGate_WebRTC_OnDataChannelError(9, "error", pRTC);
    DirectGate_WebRTC_OnVideoTrackOpen(9, pRTC);
    DirectGate_WebRTC_OnVideoTrackClosed(9, pRTC);
    DirectGate_WebRTC_OnVideoTrackError(9, "error", pRTC);
    DirectGate_WebRTC_OnVideoTrackMessage(9, "x", 1, pRTC);
    DirectGate_WebRTC_OnAudioTrackOpen(9, pRTC);
    DirectGate_WebRTC_OnAudioTrackClosed(9, pRTC);
    CHECK(pRTC->pQueueHead == NULL && !pRTC->bQueueFailed, "events for replaced channels and tracks queue nothing");

    DirectGate_WebRTC_OnDataChannelError(5, NULL, pRTC);
    DirectGate_WebRTC_OnVideoTrackError(6, NULL, pRTC);
    CHECK(pRTC->pQueueHead == NULL, "and an error on a current one is reported, not queued");

    pRTC->nDataChannelID = -1;
    pRTC->nVideoTrackID = -1;
    pRTC->nAudioTrackID = -1;
    return 0;
}

static int check_media(directgate_webrtc_t *pRTC)
{
    uint8_t payload[DIRECTGATE_RTC_RTP_MAX_PAYLOAD + 1] = { 0, 0, 0, 1, 0x65 };

    const uint8_t byte = 'x';
    CHECK(DirectGate_WebRTC_Send(NULL, &byte, 1) == XSTDERR && DirectGate_WebRTC_Send(pRTC, NULL, 1) == XSTDERR &&
          DirectGate_WebRTC_Send(pRTC, &byte, 0) == XSTDERR && DirectGate_WebRTC_Send(pRTC, &byte, 1) == XSTDERR,
        "nothing is sent without a transport, data, or a connection");

    CHECK(DirectGate_WebRTC_SendRtpPacket(NULL, payload, 1, 0, XFALSE, XFALSE) == XSTDERR &&
          DirectGate_WebRTC_SendRtpPacket(pRTC, NULL, 1, 0, XFALSE, XFALSE) == XSTDERR &&
          DirectGate_WebRTC_SendRtpPacket(pRTC, payload, 0, 0, XFALSE, XFALSE) == XSTDERR &&
          DirectGate_WebRTC_SendRtpPacket(pRTC, payload, sizeof(payload), 0, XFALSE, XFALSE) == XSTDERR &&
          DirectGate_WebRTC_SendRtpPacket(pRTC, payload, 1, 0, XFALSE, XFALSE) == XSTDERR &&
          DirectGate_WebRTC_SendRtpPacket(pRTC, payload, 1, 0, XFALSE, XTRUE) == XSTDERR,
        "an RTP packet needs a transport, a payload that fits, and a track");
    CHECK(DirectGate_WebRTC_SendH264Nal(NULL, payload, 1, 0, XFALSE, XFALSE) == XSTDERR &&
          DirectGate_WebRTC_SendH264Nal(pRTC, NULL, 1, 0, XFALSE, XFALSE) == XSTDERR &&
          DirectGate_WebRTC_SendH264Nal(pRTC, payload, 0, 0, XFALSE, XFALSE) == XSTDERR, "and so does a NAL");
    CHECK(DirectGate_WebRTC_SendH264AnnexBToPeer(NULL, payload, 5, 0, XFALSE) == XSTDERR &&
          DirectGate_WebRTC_SendH264AnnexBToPeer(pRTC, NULL, 5, 0, XFALSE) == XSTDERR &&
          DirectGate_WebRTC_SendH264AnnexBToPeer(pRTC, payload, 0, 0, XFALSE) == XSTDERR &&
          DirectGate_WebRTC_SendH264AnnexBToPeer(pRTC, payload, 5, 0, XFALSE) == XSTDERR,
        "a frame needs a transport, a frame and an open video track");
    CHECK(DirectGate_WebRTC_SendOpusToPeer(NULL, payload, 1, 0, XFALSE) == XSTDERR &&
          DirectGate_WebRTC_SendOpusToPeer(pRTC, NULL, 1, 0, XFALSE) == XSTDERR &&
          DirectGate_WebRTC_SendOpusToPeer(pRTC, payload, 0, 0, XFALSE) == XSTDERR &&
          DirectGate_WebRTC_SendOpusToPeer(pRTC, payload, sizeof(payload), 0, XFALSE) == XSTDERR &&
          DirectGate_WebRTC_SendOpusToPeer(pRTC, payload, 1, 0, XFALSE) == XSTDERR &&
          DirectGate_WebRTC_SendOpusToPeer(pRTC, payload, 1, 0, XTRUE) == XSTDERR,
        "and audio an open audio track");

    (void)DirectGate_WebRTC_NextAudioTimestamp(pRTC, 1000, XFALSE, NULL);

    /* RTCP: too short to read, and a PLI or loss report nobody asked about */
    xbool_t bKey = XTRUE;
    int nLost = 5;
    const uint8_t pli[] = { 0x81, 206, 0x00, 0x02, 0, 0, 0, 1, 0, 0, 0, 2 };
    uint8_t rr[32] = { 0x81, 201, 0x00, 0x07, 0, 0, 0, 1, 0, 0, 0, 9, 64 };
    DirectGate_WebRTC_ParseRtcp(NULL, 0, 0, &bKey, &nLost);
    CHECK(!bKey && nLost == -1, "no RTCP is no keyframe request and no loss");
    DirectGate_WebRTC_ParseRtcp(pli, 3, 0, &bKey, &nLost);
    CHECK(!bKey, "nor is a packet too short to have a header");
    DirectGate_WebRTC_ParseRtcp(pli, sizeof(pli), 0, NULL, NULL);
    DirectGate_WebRTC_ParseRtcp(rr, sizeof(rr), 0, NULL, NULL);
    DirectGate_WebRTC_ParseRtcp(rr, sizeof(rr), 0, &bKey, &nLost);
    CHECK(!bKey && nLost == 64, "a loss report is read whoever asks");
    return 0;
}

int main(void)
{
    directgate_webrtc_t rtc;
    DirectGate_WebRTC_Init(&rtc);

    int nFailed = check_accessors(&rtc) || check_sdp() || check_queue(&rtc) || check_ice(&rtc) ||
        check_negotiation(&rtc) || check_callbacks(&rtc) || check_stale(&rtc) || check_media(&rtc);

    DirectGate_WebRTC_Clear(&rtc);
    DirectGate_WebRTC_Cleanup();
    if (nFailed) return 1;

    puts("webrtc_guards_smoke: OK");
    return 0;
}
