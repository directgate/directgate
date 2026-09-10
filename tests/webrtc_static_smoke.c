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

int main(void)
{
    if (negotiation() || handles()) return 1;
    puts("webrtc_static_smoke: OK");
    return 0;
}
