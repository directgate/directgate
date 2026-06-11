/* WebSocket send path framing: DirectGate_WebSock_Send appends a binary
 * WS frame to the session TX buffer. Verifies the produced frame parses
 * back losslessly, that client sessions mask (RFC 6455 requires it) while
 * agent/peer sessions do not, and that the guard clauses hold. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "src/common/websock.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "websock_frame_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static int check_frame(xapi_session_t *pSession, const uint8_t *pPayload,
                       size_t nLen, xbool_t bExpectMask, const char *pLabel)
{
    XByteBuffer_Reset(&pSession->txBuffer);
    DirectGate_WebSock_Send(pSession, pPayload, nLen);

    if (pSession->txBuffer.nUsed <= nLen) {
        fprintf(stderr, "websock_frame_smoke: %s: no frame in tx buffer\n", pLabel);
        return 1;
    }

    xbool_t bWireMask = (pSession->txBuffer.pData[1] & 0x80) ? XTRUE : XFALSE;
    xws_frame_t frame;
    xws_status_t status = XWebFrame_ParseData(&frame,
        pSession->txBuffer.pData, pSession->txBuffer.nUsed);

    if (status != XWS_FRAME_COMPLETE || !frame.bComplete) {
        fprintf(stderr, "websock_frame_smoke: %s: frame did not parse (%s)\n",
            pLabel, XWebSock_GetStatusStr(status));
        XWebFrame_Clear(&frame);
        return 1;
    }

    int nFailed = 0;
    if (frame.eType != XWS_BINARY) nFailed = 1;
    if (!frame.bFin) nFailed = 1;
    if (bWireMask != bExpectMask) nFailed = 1;
    if (frame.bMask != XFALSE) nFailed = 1;
    if (XWebFrame_GetPayloadLength(&frame) != nLen) nFailed = 1;
    if (memcmp(XWebFrame_GetPayload(&frame), pPayload, nLen) != 0) nFailed = 1;

    if (nFailed)
        fprintf(stderr, "websock_frame_smoke: %s: frame fields mismatch\n", pLabel);

    XWebFrame_Clear(&frame);
    return nFailed;
}

int main(void)
{
    xapi_session_t session;
    memset(&session, 0, sizeof(session));
    XByteBuffer_Init(&session.txBuffer, XSTDNON, XFALSE);

    uint8_t small[16];
    for (size_t i = 0; i < sizeof(small); i++) small[i] = (uint8_t)(0x30 + i);

    /* 64 KB payload exercises the 8-byte extended-length header path */
    size_t nBigLen = 70000;
    uint8_t *pBig = (uint8_t*)malloc(nBigLen);
    CHECK(pBig != NULL, "alloc big payload");
    for (size_t i = 0; i < nBigLen; i++) pBig[i] = (uint8_t)(i * 13);

    /* Client role: frames must be masked */
    session.eRole = XAPI_CLIENT;
    CHECK(check_frame(&session, small, sizeof(small), XTRUE, "client small") == 0,
        "client small frame");
    CHECK(check_frame(&session, pBig, nBigLen, XTRUE, "client big") == 0,
        "client big frame");

    /* Peer (agent side): frames go unmasked */
    session.eRole = XAPI_PEER;
    CHECK(check_frame(&session, small, sizeof(small), XFALSE, "peer small") == 0,
        "peer small frame");
    CHECK(check_frame(&session, pBig, nBigLen, XFALSE, "peer big") == 0,
        "peer big frame");

    /* Medium size: 16-bit extended length header path */
    session.eRole = XAPI_CLIENT;
    CHECK(check_frame(&session, pBig, 1000, XTRUE, "client medium") == 0,
        "client medium frame");

    free(pBig);

    /* Guards: NULL payload and zero length must not touch the buffer */
    XByteBuffer_Reset(&session.txBuffer);
    CHECK(DirectGate_WebSock_Send(&session, NULL, 4) == XAPI_CONTINUE,
        "NULL payload guard");
    CHECK(DirectGate_WebSock_Send(&session, small, 0) == XAPI_CONTINUE,
        "zero length guard");
    CHECK(session.txBuffer.nUsed == 0, "guards leave tx buffer untouched");
    CHECK(DirectGate_WebSock_Send(NULL, small, sizeof(small)) == XAPI_DISCONNECT,
        "NULL session guard");

    /* SendBuff wrapper goes through the same path */
    xbyte_buffer_t pkgBuf;
    XByteBuffer_Init(&pkgBuf, XSTDNON, XFALSE);
    CHECK(XByteBuffer_Add(&pkgBuf, small, sizeof(small)) > 0, "fill pkg buffer");
    DirectGate_WebSock_SendBuff(&session, &pkgBuf);
    CHECK(session.txBuffer.nUsed > sizeof(small), "sendbuff produced a frame");

    XByteBuffer_Clear(&pkgBuf);
    XByteBuffer_Clear(&session.txBuffer);

    puts("websock_frame_smoke: OK");
    return 0;
}
