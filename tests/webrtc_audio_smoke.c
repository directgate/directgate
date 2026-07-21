/* Smoke test for the desktop audio SDP negotiation helper
 * (DirectGate_WebRTC_ParseRemoteOpus in src/common/webrtc.c): it must find the
 * recv-only Opus m-line's payload type and mid, and reject an offer that
 * advertises no Opus audio. Pure string parsing, no peer connection. */

#include <stdio.h>
#include <string.h>

#include "src/common/webrtc.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "webrtc_audio_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

/* A minimal browser-style offer with a video m-line and a recv-only Opus
 * audio m-line (payload type 111, mid "1"). */
static const char *g_pOfferWithAudio =
    "v=0\r\n"
    "o=- 1 2 IN IP4 127.0.0.1\r\n"
    "s=-\r\n"
    "t=0 0\r\n"
    "m=video 9 UDP/TLS/RTP/SAVPF 102\r\n"
    "a=mid:0\r\n"
    "a=recvonly\r\n"
    "a=rtpmap:102 H264/90000\r\n"
    "m=audio 9 UDP/TLS/RTP/SAVPF 111 63\r\n"
    "a=mid:1\r\n"
    "a=recvonly\r\n"
    "a=rtpmap:111 opus/48000/2\r\n"
    "a=fmtp:111 minptime=10;useinbandfec=1\r\n";

/* Same session, but the audio m-line offers only a non-Opus codec. */
static const char *g_pOfferNoOpus =
    "v=0\r\n"
    "m=video 9 UDP/TLS/RTP/SAVPF 102\r\n"
    "a=mid:0\r\n"
    "a=rtpmap:102 H264/90000\r\n"
    "m=audio 9 UDP/TLS/RTP/SAVPF 8\r\n"
    "a=mid:1\r\n"
    "a=rtpmap:8 PCMA/8000\r\n";

int main(void)
{
    uint8_t nPt = 0;
    char sMid[32] = {0};

    /* Opus is present: expect the right payload type and mid. */
    CHECK(DirectGate_WebRTC_ParseRemoteOpus(g_pOfferWithAudio, &nPt, sMid, sizeof(sMid)),
        "failed to parse an offer that advertises Opus");
    CHECK(nPt == 111, "wrong Opus payload type");
    CHECK(!strcmp(sMid, "1"), "wrong audio mid");

    /* No Opus: must be rejected so no audio track is added. */
    nPt = 0;
    sMid[0] = '\0';
    CHECK(!DirectGate_WebRTC_ParseRemoteOpus(g_pOfferNoOpus, &nPt, sMid, sizeof(sMid)),
        "accepted an offer with no Opus audio");

    /* Empty / malformed input must be rejected, not crash. */
    CHECK(!DirectGate_WebRTC_ParseRemoteOpus("", &nPt, sMid, sizeof(sMid)),
        "accepted an empty SDP");

    printf("webrtc_audio_smoke: Opus m-line negotiation parsed correctly\n");
    return 0;
}
