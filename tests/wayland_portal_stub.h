/*
 * The xdg-desktop-portal boundary of the Wayland desktop, played by the test.
 *
 * Defines every DirectGate_WL_Portal* function the Wayland source and input
 * code call, so a test that links those sources without wayland_portal.c gets
 * a portal it scripts: what each request is answered with, the screens it
 * grants, whether its PipeWire descriptor opens, and a record of the input it
 * was asked to inject. wayland_portal_bus_smoke covers the real D-Bus client;
 * this covers what the agent does with its answers. Include in one file only.
 */

#ifndef DIRECTGATE_TESTS_WAYLAND_PORTAL_STUB_H
#define DIRECTGATE_TESTS_WAYLAND_PORTAL_STUB_H

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "src/agent/desktop/wayland.h"

typedef enum {
    STUB_GRANT = 0,     /* granted, with stub.sNewToken as the token to keep */
    STUB_REFUSE,        /* failed without anybody saying no */
    STUB_DECLINE,       /* somebody said no */
    STUB_HOLD_GRANT,    /* waits for the cancel flag, then grants */
    STUB_HOLD_REFUSE,   /* waits for the cancel flag, then fails */
    STUB_WAIT           /* a prompt nobody has answered: waits for stub.bRelease, then gives stub.eAfterWait */
} stub_answer_t;

struct directgate_wl_portal_ {
    int nId;
};

typedef struct {
    xsync_mutex_t lock;
    stub_answer_t answers[4];
    int nOpens;                 /* requests made, the answer to the n-th is answers[n] */
    int bHolding;               /* a request is waiting for its cancel or its release */
    int bRelease;
    stub_answer_t eAfterWait;
    char sRestore[4][64];       /* the token each request presented, empty for none */
    char sNewToken[64];
    int nFailPipeWire;          /* this many descriptor requests fail before they work again */
    int nPipeWire;
    int nClosed;
    xbool_t bHasInput;
    xbool_t bKeysymRefused;
    directgate_wl_stream_t streams[DIRECTGATE_WL_MAX_STREAMS];
    uint32_t nStreams;

    /* Input it was asked to inject */
    int nMotions, nRelative, nButtons, nAxes, nKeysyms, nKeycodes;
    uint32_t nLastStream;
    double nLastX, nLastY;
    int32_t nLastButton, nLastKeysym, nLastKeycode;
    xbool_t bLastPressed;
    int nInputResult;           /* what every injection returns */
} stub_portal_t;

static stub_portal_t stub;

/* Everything but the lock, which stays as it is from the first reset on */
static void stub_portal_reset(void)
{
    static int bInit;
    if (!bInit) XSync_Init(&stub.lock);
    bInit = 1;

    memset((char*)&stub + sizeof(stub.lock), 0, sizeof(stub) - sizeof(stub.lock));

    stub.bHasInput = XTRUE;
    stub.nInputResult = XSTDOK;
    stub.nStreams = 1;
    stub.streams[0].nNodeId = 31;
    stub.streams[0].nWidth = 64;
    stub.streams[0].nHeight = 32;
}

static int stub_portal_get(const int *pCounter)
{
    XSync_Lock(&stub.lock);
    int nValue = *pCounter;
    XSync_Unlock(&stub.lock);
    return nValue;
}

directgate_wl_portal_t* DirectGate_WL_PortalOpen(const char *pRestoreToken,
                                                 char *pNewToken, size_t nTokenSize,
                                                 xbool_t *pDeclined, xvolatile_t *pCancel,
                                                 char *pErrBuf, size_t nErrSize)
{
    XSync_Lock(&stub.lock);
    int nIndex = stub.nOpens < 4 ? stub.nOpens : 3;
    stub_answer_t eAnswer = stub.answers[nIndex];
    xstrncpy(stub.sRestore[nIndex], sizeof(stub.sRestore[nIndex]), pRestoreToken != NULL ? pRestoreToken : "");
    stub.nOpens++;
    XSync_Unlock(&stub.lock);

    if (pDeclined != NULL) *pDeclined = XFALSE;

    if (eAnswer == STUB_WAIT)
    {
        XSync_Lock(&stub.lock);
        stub.bHolding = 1;
        XSync_Unlock(&stub.lock);

        while (!stub_portal_get(&stub.bRelease) && !XSYNC_ATOMIC_GET(pCancel)) usleep(1000);
        eAnswer = stub.eAfterWait;
    }

    if (eAnswer == STUB_HOLD_GRANT || eAnswer == STUB_HOLD_REFUSE)
    {
        XSync_Lock(&stub.lock);
        stub.bHolding = 1;
        XSync_Unlock(&stub.lock);

        while (!XSYNC_ATOMIC_GET(pCancel)) usleep(1000);
        eAnswer = eAnswer == STUB_HOLD_GRANT ? STUB_GRANT : STUB_REFUSE;
    }

    if (eAnswer == STUB_DECLINE)
    {
        if (pDeclined != NULL) *pDeclined = XTRUE;
        xstrncpy(pErrBuf, nErrSize, "Screen sharing was declined.");
        return NULL;
    }

    if (eAnswer == STUB_REFUSE)
    {
        xstrncpy(pErrBuf, nErrSize, "The portal refused the request.");
        return NULL;
    }

    xstrncpy(pNewToken, nTokenSize, stub.sNewToken);
    directgate_wl_portal_t *pPortal = (directgate_wl_portal_t*)calloc(1, sizeof(*pPortal));
    if (pPortal != NULL) pPortal->nId = nIndex;
    return pPortal;
}

int DirectGate_WL_PortalOpenPipeWire(directgate_wl_portal_t *pPortal, char *pErrBuf, size_t nErrSize)
{
    (void)pPortal;
    XSync_Lock(&stub.lock);
    stub.nPipeWire++;
    int bFail = stub.nFailPipeWire > 0;
    if (bFail) stub.nFailPipeWire--;
    XSync_Unlock(&stub.lock);

    if (bFail)
    {
        xstrncpy(pErrBuf, nErrSize, "The portal did not open PipeWire.");
        return -1;
    }

    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0) return -1;
    close(pair[1]);
    return pair[0];
}

uint32_t DirectGate_WL_PortalNodeId(const directgate_wl_portal_t *pPortal)
{
    return (pPortal != NULL && stub.nStreams > 0) ? stub.streams[0].nNodeId : 0;
}

uint32_t DirectGate_WL_PortalStreamCount(const directgate_wl_portal_t *pPortal)
{
    return pPortal != NULL ? stub.nStreams : 0;
}

const directgate_wl_stream_t* DirectGate_WL_PortalStream(const directgate_wl_portal_t *pPortal, uint32_t nIndex)
{
    return (pPortal != NULL && nIndex < stub.nStreams) ? &stub.streams[nIndex] : NULL;
}

xbool_t DirectGate_WL_PortalHasInput(const directgate_wl_portal_t *pPortal)
{
    return (pPortal != NULL && stub.bHasInput) ? XTRUE : XFALSE;
}

xbool_t DirectGate_WL_PortalKeysymRefused(const directgate_wl_portal_t *pPortal)
{
    return (pPortal != NULL && stub.bKeysymRefused) ? XTRUE : XFALSE;
}

void DirectGate_WL_PortalClose(directgate_wl_portal_t *pPortal)
{
    if (pPortal == NULL) return;

    XSync_Lock(&stub.lock);
    stub.nClosed++;
    XSync_Unlock(&stub.lock);
    free(pPortal);
}

int DirectGate_WL_PortalPointerMotion(directgate_wl_portal_t *pPortal, uint32_t nStream, double nX, double nY)
{
    (void)pPortal;
    stub.nMotions++;
    stub.nLastStream = nStream;
    stub.nLastX = nX;
    stub.nLastY = nY;
    return stub.nInputResult;
}

int DirectGate_WL_PortalPointerMotionRelative(directgate_wl_portal_t *pPortal, double nDx, double nDy)
{
    (void)pPortal;
    stub.nRelative++;
    stub.nLastX = nDx;
    stub.nLastY = nDy;
    return stub.nInputResult;
}

int DirectGate_WL_PortalPointerButton(directgate_wl_portal_t *pPortal, int32_t nButton, xbool_t bPressed)
{
    (void)pPortal;
    stub.nButtons++;
    stub.nLastButton = nButton;
    stub.bLastPressed = bPressed;
    return stub.nInputResult;
}

int DirectGate_WL_PortalPointerAxis(directgate_wl_portal_t *pPortal, double nDx, double nDy)
{
    (void)pPortal;
    stub.nAxes++;
    stub.nLastX = nDx;
    stub.nLastY = nDy;
    return stub.nInputResult;
}

int DirectGate_WL_PortalKeysym(directgate_wl_portal_t *pPortal, int32_t nKeysym, xbool_t bPressed)
{
    (void)pPortal;
    stub.nKeysyms++;
    stub.nLastKeysym = nKeysym;
    stub.bLastPressed = bPressed;
    return stub.nInputResult;
}

int DirectGate_WL_PortalKeycode(directgate_wl_portal_t *pPortal, int32_t nKeycode, xbool_t bPressed)
{
    (void)pPortal;
    stub.nKeycodes++;
    stub.nLastKeycode = nKeycode;
    stub.bLastPressed = bPressed;
    return stub.nInputResult;
}

int32_t DirectGate_WL_PortalButtonCode(uint32_t nX11Button)
{
    switch (nX11Button)
    {
        case 1: return 0x110;
        case 2: return 0x112;
        case 3: return 0x111;
        case 8: return 0x113;
        case 9: return 0x114;
        default: return 0;
    }
}

#endif /* DIRECTGATE_TESTS_WAYLAND_PORTAL_STUB_H */
