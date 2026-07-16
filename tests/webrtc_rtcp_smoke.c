/* Smoke test for the compound RTCP parser (src/common/webrtc.c):
 * PLI/FIR detection anywhere in a compound datagram and fraction-lost
 * extraction from RR/SR report blocks. Feeds hand-built packets, no
 * network or peer connection involved. */

#include <stdio.h>
#include <string.h>

#include "src/common/webrtc.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "webrtc_rtcp_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

/* Builds an RR with one report block; returns the packet size. */
static size_t build_rr(uint8_t *pOut, uint8_t nFractionLost)
{
    memset(pOut, 0, 32);
    pOut[0] = 0x81; /* V=2, RC=1 */
    pOut[1] = 201;  /* RR */
    pOut[2] = 0;
    pOut[3] = 7;    /* length: 8 words - 1 */
    /* reporter SSRC: bytes 4..7, block source SSRC: bytes 8..11 */
    pOut[12] = nFractionLost;
    return 32;
}

/* Builds a PLI feedback packet; returns the packet size. */
static size_t build_pli(uint8_t *pOut)
{
    memset(pOut, 0, 12);
    pOut[0] = 0x81; /* V=2, FMT=1 */
    pOut[1] = 206;  /* PSFB */
    pOut[2] = 0;
    pOut[3] = 2;    /* length: 3 words - 1 */
    return 12;
}

int main(void)
{
    uint8_t buffer[128];
    xbool_t bKeyframe = XTRUE;
    int nFraction = 0;

    /* Plain RR without loss: no keyframe request, fraction 0. */
    size_t nSize = build_rr(buffer, 0);
    DirectGate_WebRTC_ParseRtcp(buffer, nSize, &bKeyframe, &nFraction);
    CHECK(!bKeyframe, "plain RR must not request a keyframe");
    CHECK(nFraction == 0, "plain RR must report zero fraction lost");

    /* Compound RR(loss) + PLI: both signals must be seen. */
    nSize = build_rr(buffer, 64); /* 25% loss */
    nSize += build_pli(buffer + nSize);
    DirectGate_WebRTC_ParseRtcp(buffer, nSize, &bKeyframe, &nFraction);
    CHECK(bKeyframe, "PLI behind an RR must be detected");
    CHECK(nFraction == 64, "fraction lost must come from the RR block");

    /* FIR as PSFB FMT=4. */
    nSize = build_pli(buffer);
    buffer[0] = 0x84; /* FMT=4 */
    DirectGate_WebRTC_ParseRtcp(buffer, nSize, &bKeyframe, &nFraction);
    CHECK(bKeyframe, "FIR (PSFB FMT=4) must be detected");
    CHECK(nFraction == -1, "no report block means fraction -1");

    /* SR with one report block: blocks start after the sender info. */
    memset(buffer, 0, sizeof(buffer));
    buffer[0] = 0x81; /* V=2, RC=1 */
    buffer[1] = 200;  /* SR */
    buffer[2] = 0;
    buffer[3] = 12;   /* length: 13 words - 1 = 4+4+20+24 bytes */
    buffer[32] = 128; /* fraction lost of block 0 (offset 28 + 4) */
    DirectGate_WebRTC_ParseRtcp(buffer, 52, &bKeyframe, &nFraction);
    CHECK(!bKeyframe, "SR must not request a keyframe");
    CHECK(nFraction == 128, "SR report block fraction lost must be parsed");

    /* Truncated / hostile input must not report anything. */
    nSize = build_rr(buffer, 200);
    DirectGate_WebRTC_ParseRtcp(buffer, 10, &bKeyframe, &nFraction);
    CHECK(!bKeyframe && nFraction == -1, "truncated RR must be ignored");

    buffer[0] = 0x41; /* wrong RTCP version */
    DirectGate_WebRTC_ParseRtcp(buffer, 32, &bKeyframe, &nFraction);
    CHECK(!bKeyframe && nFraction == -1, "non-RTCP data must be ignored");

    DirectGate_WebRTC_ParseRtcp(NULL, 0, &bKeyframe, &nFraction);
    CHECK(!bKeyframe && nFraction == -1, "NULL input must be ignored");

    printf("webrtc_rtcp_smoke: OK\n");
    return 0;
}
