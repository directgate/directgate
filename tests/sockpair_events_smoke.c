/* XSock_CreatePair + XEvents engine integration.
 *
 * The socket pair is the notification primitive behind the WebRTC and
 * search wakeups (and the Windows ConPTY bridge); the event engine is
 * the heart of the agent. This test drives the pair through the real
 * event loop: readability wakeups, write/drain cycles, timers and the
 * eventfd-style user event, then verifies clean teardown. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "libxutils/src/net/sock.h"
#include "libxutils/src/net/event.h"
#include "libxutils/src/sys/xtime.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "sockpair_events_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

typedef struct {
    int nReadEvents;
    int nTimerEvents;
    int nUserEvents;
    char cLastByte;
} test_ctx_t;

static int event_callback(void *pEvents, void *pData, XSOCKET nFD, xevent_cb_type_t eReason)
{
    xevents_t *pEv = (xevents_t*)pEvents;
    test_ctx_t *pCtx = (test_ctx_t*)pEv->pUserSpace;
    xevent_data_t *pEvData = (xevent_data_t*)pData;
    (void)nFD;

    switch (eReason)
    {
        case XEVENT_CB_READ:
            if (pEvData != NULL && pEvData->nType == XEVENT_TYPE_EVENT)
            {
                uint64_t nValue = 0;
                XEvent_ReadU64(pEvData, &nValue);
                pCtx->nUserEvents++;
                break;
            }

            pCtx->nReadEvents++;
            XEvent_ReadByte(pEvData, &pCtx->cLastByte);
            break;
        case XEVENT_CB_TIMEOUT:
            pCtx->nTimerEvents++;
            break;
        default:
            break;
    }

    return XEVENTS_CONTINUE;
}

int main(void)
{
    /* ---- raw pair mechanics ---- */
    XSOCKET aPair[2] = { XSOCK_INVALID, XSOCK_INVALID };
    CHECK(XSock_CreatePair(aPair) == XSTDOK, "create pair");
    CHECK(aPair[0] != XSOCK_INVALID && aPair[1] != XSOCK_INVALID, "pair fds valid");

#ifndef _WIN32
    /* The pair must not leak into exec'd children (PTY shells) */
    CHECK((fcntl(aPair[0], F_GETFD) & FD_CLOEXEC) != 0, "pair[0] cloexec");
    CHECK((fcntl(aPair[1], F_GETFD) & FD_CLOEXEC) != 0, "pair[1] cloexec");
#endif

    /* Bidirectional transfer */
    char sBuf[64];
    CHECK(send(aPair[0], "ping", 4, 0) == 4, "send a->b");
    CHECK(recv(aPair[1], sBuf, sizeof(sBuf), 0) == 4 && !memcmp(sBuf, "ping", 4),
        "recv a->b");
    CHECK(send(aPair[1], "pong!", 5, 0) == 5, "send b->a");
    CHECK(recv(aPair[0], sBuf, sizeof(sBuf), 0) == 5 && !memcmp(sBuf, "pong!", 5),
        "recv b->a");

    /* Half-close semantics drive the PTY EOF path */
    CHECK(shutdown(aPair[1], SHUT_WR) == 0, "shutdown writer");
    CHECK(recv(aPair[0], sBuf, sizeof(sBuf), 0) == 0, "EOF after shutdown");

    xclosesock(aPair[0]);
    xclosesock(aPair[1]);

    /* ---- pair driven by the event engine ---- */
    test_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    xevents_t events;
    memset(&events, 0, sizeof(events));
    CHECK(XEvents_Create(&events, 64, &ctx, event_callback, XTRUE) == XEVENTS_SUCCESS,
        "create events");

    CHECK(XSock_CreatePair(aPair) == XSTDOK, "create loop pair");

    xevent_data_t *pPairData = XEvents_RegisterEvent(&events, NULL, aPair[0],
        XPOLLIN, XEVENT_TYPE_CUSTOM);
    CHECK(pPairData != NULL, "register pair in loop");

    /* No traffic: a service pass must not report events */
    CHECK(XEvents_Service(&events, 10) == XEVENTS_SUCCESS, "idle service");
    CHECK(ctx.nReadEvents == 0, "no spurious read events");

    /* One byte in -> exactly one read wakeup with that byte */
    CHECK(send(aPair[1], "\x07", 1, 0) == 1, "notify byte");
    CHECK(XEvents_Service(&events, 100) == XEVENTS_SUCCESS, "service after notify");
    CHECK(ctx.nReadEvents == 1, "read wakeup fired");
    CHECK(ctx.cLastByte == 0x07, "read wakeup byte");

    /* Drained socket: the next pass is quiet again */
    CHECK(XEvents_Service(&events, 10) == XEVENTS_SUCCESS, "service after drain");
    CHECK(ctx.nReadEvents == 1, "level-triggered drain");

    /* ---- timer events ---- */
    xevent_data_t *pTimer = XEvents_AddTimer(&events, NULL, 20);
    CHECK(pTimer != NULL, "add timer");

    uint64_t nStart = XTime_GetMs();
    while (ctx.nTimerEvents == 0 && XTime_GetMs() - nStart < 2000)
        CHECK(XEvents_Service(&events, 50) == XEVENTS_SUCCESS, "timer service");

    CHECK(ctx.nTimerEvents == 1, "timer fired once");

    /* Re-arm the same timer through the extend API */
    CHECK(XEvents_ExtendTimer(&events, pTimer, 20) == XEVENTS_SUCCESS, "extend timer");

    nStart = XTime_GetMs();
    while (ctx.nTimerEvents == 1 && XTime_GetMs() - nStart < 2000)
        CHECK(XEvents_Service(&events, 50) == XEVENTS_SUCCESS, "extend service");

    CHECK(ctx.nTimerEvents == 2, "extended timer fired");
    XEvents_Delete(&events, pTimer);

    /* ---- user event (eventfd wakeup on Linux) ---- */
    xevent_data_t *pUser = XEvents_CreateEvent(&events, NULL);
#if defined(__linux__)
    CHECK(pUser != NULL, "create user event");

    /* eventfd counters only accept 8-byte writes */
    uint64_t nSignal = 1;
    CHECK(write(pUser->nFD, &nSignal, sizeof(nSignal)) == (ssize_t)sizeof(nSignal),
        "write user event");

    nStart = XTime_GetMs();
    while (ctx.nUserEvents == 0 && XTime_GetMs() - nStart < 2000)
        CHECK(XEvents_Service(&events, 50) == XEVENTS_SUCCESS, "user event service");

    CHECK(ctx.nUserEvents >= 1, "user event fired");
    XEvents_Delete(&events, pUser);
#else
    (void)pUser;
#endif

    /* ---- teardown: pair endpoint removed, then engine destroyed ---- */
    XEvents_Delete(&events, pPairData);
    XEvents_Destroy(&events);

    xclosesock(aPair[0]);
    xclosesock(aPair[1]);

    puts("sockpair_events_smoke: OK");
    return 0;
}
