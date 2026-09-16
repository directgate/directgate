#include <stdio.h>
#include "src/common/webrtc.c"
#define CHECK(c, msg) do { if (!(c)) { fprintf(stderr, "webrtc_static_smoke: %s\n", msg); return 1; } } while (0)

static int negotiation(void)
{
    char mid[64], profile[128];
    uint8_t pt;
    const char *sdp = "m=video 9 UDP/TLS/RTP/SAVPF 102\r\na=mid:first\r\n"
        "a=rtpmap:102 H264/90000\r\na=fmtp:102 profile-level-id=42e01f\r\n"
        "m=video 9 UDP/TLS/RTP/SAVPF 103\r\na=mid:second\r\n"
        "a=rtpmap:103 H264/90000\r\na=fmtp:102 profile-level-id=wrong\r\n";
    CHECK(DirectGate_WebRTC_ParseRemoteH264(sdp, &pt, mid, sizeof(mid), profile, sizeof(profile)), "H264 present");
    CHECK(pt == 102 && !strcmp(mid, "first") && !strcmp(profile, "profile-level-id=42e01f"), "H264 section isolation");
    sdp = "m=audio 9 UDP/TLS/RTP/SAVPF 111\na=mid:one\na=rtpmap:111 opus/48000/2\n"
          "m=audio 9 UDP/TLS/RTP/SAVPF 112\na=mid:two\na=rtpmap:112 opus/48000/2\n";
    CHECK(DirectGate_WebRTC_ParseRemoteOpus(sdp, &pt, mid, sizeof(mid)), "Opus present");
    CHECK(pt == 111 && !strcmp(mid, "one"), "Opus section isolation");
    sdp = "m=audio 9 UDP/TLS/RTP/SAVPF 8\na=mid:other\na=rtpmap:8 PCMA/8000\n"
          "m=audio 9 UDP/TLS/RTP/SAVPF 111\na=rtpmap:111 opus/48000/2\n";
    CHECK(DirectGate_WebRTC_ParseRemoteOpus(sdp, &pt, mid, sizeof(mid)) && !strcmp(mid, "0"), "no previous mid inheritance");
    const char *invalid[] = { "4294967407", "9999999999999999999999", "111x", "-1", "128" };
    char data[256];
    for (size_t i = 0; i < sizeof(invalid)/sizeof(*invalid); i++)
    {
        snprintf(data, sizeof(data), "m=audio 9 UDP/TLS/RTP/SAVPF 111\na=rtpmap:%s opus/48000/2\n", invalid[i]);
        CHECK(!DirectGate_WebRTC_ParseRemoteOpus(data, &pt, mid, sizeof(mid)), "invalid payload rejected");
    }
    return 0;
}

static int handles(void)
{
    directgate_webrtc_t rtc;
    DirectGate_WebRTC_Init(&rtc);
    rtcConfiguration cfg = {0};
    /* This fixture checks C handle ownership. Automatic negotiation starts
     * an ICE worker while we immediately close/recreate those handles, which
     * makes teardown depend on upstream network-thread scheduling. The real
     * negotiation path is covered separately by webrtc_peer_smoke. */
    cfg.disableAutoNegotiation = true;
    int pc = rtcCreatePeerConnection(&cfg);
    CHECK(pc >= 0, "create peer");
    int dc = rtcCreateDataChannel(pc, "directgate");
    CHECK(dc >= 0, "create data channel");
    rtc.nPeerConnectionID = pc;
    rtc.nDataChannelID = dc;
    DirectGate_WebRTC_Enqueue(&rtc, DIRECTGATE_WEBRTC_CLOSED, dc, NULL, 0);
    DirectGate_WebRTC_ProcessQueue(&rtc);
    char label[64];
    CHECK(rtc.nDataChannelID == -1 && rtcGetDataChannelLabel(dc, label, sizeof(label)) < 0,
        "closed channel handle deleted before forgetting ID");
    dc = rtcCreateDataChannel(pc, "unclaimed");
    CHECK(dc >= 0, "create unclaimed channel");
    DirectGate_WebRTC_QueueDataChannel(pc, dc, &rtc);
    DirectGate_WebRTC_Clear(&rtc);
    CHECK(rtcGetDataChannelLabel(dc, label, sizeof(label)) < 0, "queued unclaimed channel deleted on clear");

    DirectGate_WebRTC_Init(&rtc);
    for (size_t i = 0; i < DIRECTGATE_RTC_QUEUE_MAX_EVENTS + 1; i++)
        DirectGate_WebRTC_Enqueue(&rtc, DIRECTGATE_WEBRTC_DATA, -1, NULL, 0);
    CHECK(rtc.bQueueFailed && rtc.nQueuedEvents == DIRECTGATE_RTC_QUEUE_MAX_EVENTS,
        "event count bounded");
    DirectGate_WebRTC_ProcessQueue(&rtc);
    CHECK(!rtc.bQueueFailed && !rtc.pQueueHead && !rtc.nQueuedEvents, "overflow tears down and clears queue");
    DirectGate_WebRTC_Enqueue(&rtc, DIRECTGATE_WEBRTC_DATA, -1, (const uint8_t*)"x",
        (size_t)DIRECTGATE_RTC_QUEUE_MAX_BYTES + 1);
    CHECK(rtc.bQueueFailed && !rtc.pQueueHead, "oversized event rejected before copying");
    DirectGate_WebRTC_ProcessQueue(&rtc);
    for (size_t i = 0; i < DIRECTGATE_RTC_MAX_PENDING_ICE; i++)
    {
        char candidate[128];
        snprintf(candidate, sizeof(candidate), "candidate:%zu 1 udp 1 127.0.0.1 1234 typ host", i);
        CHECK(DirectGate_WebRTC_BufferIce(&rtc, candidate, "0", 1) == XSTDOK, "candidate fits bounded buffer");
    }
    CHECK(DirectGate_WebRTC_BufferIce(&rtc, "candidate:overflow", "0", 1) == XSTDERR,
        "pending candidate count bounded");
    DirectGate_WebRTC_Clear(&rtc);
    DirectGate_WebRTC_Cleanup();
    return 0;
}

/* The Annex-B scanner and the RTP header the video track is built from. Both
 * run once per NAL on the capture->encode->send path, so a wrong answer here
 * is not a dropped frame, it is a picture the browser cannot decode at all. */
static int framing(void)
{
    static const uint8_t threeByte[] = { 0x00, 0x00, 0x01, 0x67, 0x42 };
    static const uint8_t fourByte[]  = { 0x00, 0x00, 0x00, 0x01, 0x67 };
    static const uint8_t leading[]   = { 0x09, 0x10, 0x00, 0x00, 0x01, 0x67 };
    static const uint8_t extraZero[] = { 0x00, 0x00, 0x00, 0x00, 0x01, 0x67 };
    static const uint8_t none[]      = { 0x00, 0x00, 0x02, 0x03 };
    static const uint8_t tooShort[]  = { 0x00, 0x00 };

    size_t nLen = 0;
    const uint8_t *pFound;

    pFound = DirectGate_WebRTC_FindStartCode(threeByte, threeByte + sizeof(threeByte), &nLen);
    CHECK(pFound == threeByte && nLen == 3, "a three-byte start code is found at the front");

    pFound = DirectGate_WebRTC_FindStartCode(fourByte, fourByte + sizeof(fourByte), &nLen);
    CHECK(pFound == fourByte && nLen == 4, "a four-byte start code is not mistaken for a three-byte one");

    pFound = DirectGate_WebRTC_FindStartCode(leading, leading + sizeof(leading), &nLen);
    CHECK(pFound == leading + 2 && nLen == 3, "a start code after other bytes is found where it is");

    /* The extra zero belongs to the previous NAL's trailing padding, so the
     * start code is the last four bytes, not the first three. */
    pFound = DirectGate_WebRTC_FindStartCode(extraZero, extraZero + sizeof(extraZero), &nLen);
    CHECK(pFound == extraZero + 1 && nLen == 4, "a run of zeros resolves to the four-byte start code");

    CHECK(DirectGate_WebRTC_FindStartCode(none, none + sizeof(none), &nLen) == NULL,
        "a buffer with no start code reports none");
    CHECK(DirectGate_WebRTC_FindStartCode(tooShort, tooShort + sizeof(tooShort), &nLen) == NULL,
        "a buffer too short to hold a start code reports none");
    CHECK(DirectGate_WebRTC_FindStartCode(threeByte, threeByte, &nLen) == NULL,
        "an empty range reports no start code");
    CHECK(DirectGate_WebRTC_FindStartCode(threeByte, threeByte + sizeof(threeByte), NULL) == threeByte,
        "the start code is found even when its length is not wanted");

    uint8_t packet[12];
    memset(packet, 0xAA, sizeof(packet));
    DirectGate_WebRTC_WriteRtpHeader(packet, 102U, 0x11223344U, 0xBEEFU, 0x01020304U, XTRUE);

    CHECK(packet[0] == 0x80, "the RTP header declares version 2 with no padding or extension");
    CHECK(packet[1] == (0x80U | 102U), "the marker bit rides with the payload type");
    CHECK(packet[2] == 0xBE && packet[3] == 0xEF, "the sequence number is big endian");
    CHECK(packet[4] == 0x01 && packet[5] == 0x02 && packet[6] == 0x03 && packet[7] == 0x04,
        "the timestamp is big endian");
    CHECK(packet[8] == 0x11 && packet[9] == 0x22 && packet[10] == 0x33 && packet[11] == 0x44,
        "the SSRC is big endian");

    DirectGate_WebRTC_WriteRtpHeader(packet, 102U, 0U, 0U, 0U, XFALSE);
    CHECK(packet[1] == 102U, "an unmarked packet carries the payload type alone");

    /* The RTP clock is what paces playback. A first frame must not advance it,
     * and a later one must advance by its own presentation delta. */
    directgate_webrtc_t rtc;
    memset(&rtc, 0, sizeof(rtc));

    CHECK(DirectGate_WebRTC_NextVideoTimestamp(NULL, 0, XFALSE) == 0,
        "a missing peer produces no video timestamp");

    uint32_t nFirst = DirectGate_WebRTC_NextVideoTimestamp(&rtc, 1000000ULL, XFALSE);
    CHECK(rtc.bVideoHasTimestamp, "the first video frame arms the clock");

    uint32_t nSecond = DirectGate_WebRTC_NextVideoTimestamp(&rtc, 1033333ULL, XFALSE);
    CHECK(nSecond - nFirst == (33333ULL * 90000ULL) / 1000000ULL,
        "a video frame advances the clock by its own presentation delta");

    /* A stalled or backwards clock still has to move forward by one frame, or
     * the browser treats every later frame as arriving at the same instant. */
    uint32_t nThird = DirectGate_WebRTC_NextVideoTimestamp(&rtc, 1033333ULL, XFALSE);
    CHECK(nThird - nSecond == 90000U / 30U,
        "a video frame with no presentation advance still moves the clock one frame");

    uint32_t nFourth = DirectGate_WebRTC_NextVideoTimestamp(&rtc, 1ULL, XFALSE);
    CHECK(nFourth - nThird == 90000U / 30U,
        "a video frame whose presentation time went backwards never rewinds the clock");

    /* The pending peer keeps its own clock, so a P2P upgrade does not inherit
     * the relayed peer's timeline. */
    uint32_t nPending = DirectGate_WebRTC_NextVideoTimestamp(&rtc, 5000000ULL, XTRUE);
    CHECK(rtc.bPendingVideoHasTimestamp, "the pending peer arms its own video clock");
    CHECK(DirectGate_WebRTC_NextVideoTimestamp(&rtc, 5033333ULL, XTRUE) - nPending ==
        (33333ULL * 90000ULL) / 1000000ULL, "the pending peer advances its own video clock");

    xbool_t bFirst = XFALSE;
    uint32_t nAudio = DirectGate_WebRTC_NextAudioTimestamp(&rtc, 1000000ULL, XFALSE, &bFirst);
    CHECK(bFirst, "the first audio frame is reported as the first");

    bFirst = XTRUE;
    uint32_t nAudio2 = DirectGate_WebRTC_NextAudioTimestamp(&rtc, 1020000ULL, XFALSE, &bFirst);
    CHECK(!bFirst, "a later audio frame is not reported as the first");
    CHECK(nAudio2 - nAudio == (20000ULL * 48000ULL) / 1000000ULL,
        "an audio frame advances the clock by its own presentation delta");
    CHECK(DirectGate_WebRTC_NextAudioTimestamp(&rtc, 1020000ULL, XFALSE, NULL) - nAudio2 == 960U,
        "an audio frame with no presentation advance moves the clock one Opus frame");
    CHECK(DirectGate_WebRTC_NextAudioTimestamp(NULL, 0, XFALSE, NULL) == 0,
        "a missing peer produces no audio timestamp");

    /* Keyframe requests and loss reports are one-shot: reading one must clear
     * it, or the encoder keeps reacting to a report it already handled. */
    memset(&rtc, 0, sizeof(rtc));
    CHECK(!DirectGate_WebRTC_TakeVideoKeyframeRequest(&rtc),
        "no keyframe is requested before the viewer asks");
    rtc.bVideoKeyframeRequested = XTRUE;
    CHECK(DirectGate_WebRTC_TakeVideoKeyframeRequest(&rtc), "a keyframe request is delivered once");
    CHECK(!DirectGate_WebRTC_TakeVideoKeyframeRequest(&rtc), "a keyframe request is not delivered twice");
    CHECK(!DirectGate_WebRTC_TakeVideoKeyframeRequest(NULL), "a missing peer requests no keyframe");

    uint8_t nFractionLost = 0xFF;
    CHECK(!DirectGate_WebRTC_TakeVideoLossReport(&rtc, &nFractionLost),
        "no loss report is pending before one arrives");

    rtc.nVideoFractionLost = 12;
    rtc.bVideoLossUpdated = XTRUE;
    CHECK(DirectGate_WebRTC_TakeVideoLossReport(&rtc, &nFractionLost) && nFractionLost == 12,
        "a loss report is delivered once with its fraction");
    CHECK(!DirectGate_WebRTC_TakeVideoLossReport(&rtc, &nFractionLost),
        "a loss report is not delivered twice");

    /* The RTCP field is eight bits wide; a larger value would wrap into a
       small one and read as a clean link, so it saturates instead. */
    rtc.nVideoFractionLost = 4096;
    rtc.bVideoLossUpdated = XTRUE;
    CHECK(DirectGate_WebRTC_TakeVideoLossReport(&rtc, &nFractionLost) && nFractionLost == 255,
        "an out-of-range loss fraction saturates rather than wrapping to a clean link");

    /* A negative fraction means the report carried nothing usable; it must
       clear the flag without being read as zero loss. */
    rtc.nVideoFractionLost = -1;
    rtc.bVideoLossUpdated = XTRUE;
    nFractionLost = 0xFF;
    CHECK(!DirectGate_WebRTC_TakeVideoLossReport(&rtc, &nFractionLost),
        "a report with no usable fraction is not delivered as zero loss");
    CHECK(nFractionLost == 0xFF, "a refused loss report leaves the caller's value alone");
    CHECK(!rtc.bVideoLossUpdated, "a refused loss report is still consumed");

    rtc.nVideoFractionLost = 7;
    rtc.bVideoLossUpdated = XTRUE;
    CHECK(DirectGate_WebRTC_TakeVideoLossReport(&rtc, NULL),
        "a loss report is consumed even when the fraction is not wanted");
    CHECK(!DirectGate_WebRTC_TakeVideoLossReport(NULL, &nFractionLost),
        "a missing peer reports no loss");

    return 0;
}

int main(void)
{
    if (negotiation() || handles() || framing()) return 1;
    puts("webrtc_static_smoke: OK");
    return 0;
}
