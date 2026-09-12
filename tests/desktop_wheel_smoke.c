/* Exercise real wheel JSON through the X11 handler without a display server.
 * Only the X server boundary is stubbed; parsing and accumulation are real. */
#include <math.h>
#include <stdio.h>
#include <string.h>

#define XFlush TestXFlush
#define XQueryPointer TestXQueryPointer
#include "src/agent/desktop/input.c"

static unsigned int g_nPress[8], g_nRelease[8];

int TestXFlush(Display *pDisplay)
{
    (void)pDisplay;
    return 0;
}

Bool TestXQueryPointer(Display *pDisplay, Window window, Window *pRoot, Window *pChild,
                      int *pRootX, int *pRootY, int *pWindowX, int *pWindowY, unsigned int *pMask)
{
    (void)pDisplay; (void)window; (void)pRoot; (void)pChild;
    (void)pRootX; (void)pRootY; (void)pWindowX; (void)pWindowY; (void)pMask;
    return False;
}

static Bool TestMotion(Display *pDisplay, int nScreen, int nX, int nY, unsigned long nDelay)
{
    (void)pDisplay; (void)nScreen; (void)nX; (void)nY; (void)nDelay;
    return True;
}

static Bool TestButton(Display *pDisplay, unsigned int nButton, Bool bDown, unsigned long nDelay)
{
    (void)pDisplay; (void)nDelay;
    if (nButton < 8) (bDown ? g_nPress : g_nRelease)[nButton]++;
    return True;
}

xbool_t DirectGate_Desktop_ClampCursorToCapture(const directgate_desktop_t *pDesktop, int *pX, int *pY)
{
    (void)pDesktop; (void)pX; (void)pY;
    return XFALSE;
}

void DirectGate_Desktop_SendCursorPosition(directgate_session_t *pSession, int nX, int nY, uint32_t nSequence)
{
    (void)pSession; (void)nX; (void)nY; (void)nSequence;
}

static int CheckWheel(directgate_session_t *pSession, const char *pDeltas, unsigned int nRepeat,
                     xbool_t bRelative, int nExpectedX, int nExpectedY)
{
    char sPayload[512];
    int nLength = snprintf(sPayload, sizeof(sPayload),
        "{\"action\":\"pointer\",\"event\":\"wheel\",\"relative\":%s,\"x\":960,\"y\":540,%s}",
        bRelative ? "true" : "false", pDeltas);
    if (nLength < 0 || (size_t)nLength >= sizeof(sPayload)) return 1;

    memset(g_nPress, 0, sizeof(g_nPress));
    memset(g_nRelease, 0, sizeof(g_nRelease));
    pSession->desktop.nWheelAccumX = pSession->desktop.nWheelAccumY = 0;
    for (unsigned int i = 0; i < nRepeat; i++)
        DirectGate_Desktop_HandleInput(pSession, (const uint8_t*)sPayload, (size_t)nLength);

    unsigned int nExpected[8] = {0};
    nExpected[nExpectedY < 0 ? 4 : 5] = (unsigned int)abs(nExpectedY);
    nExpected[nExpectedX < 0 ? 6 : 7] = (unsigned int)abs(nExpectedX);
    if (memcmp(g_nPress, nExpected, sizeof(nExpected)) != 0 ||
        memcmp(g_nRelease, nExpected, sizeof(nExpected)) != 0)
    {
        fprintf(stderr, "desktop_wheel_smoke: %s (%s, repeat %u): got (%d,%d), expected (%d,%d)\n",
            pDeltas, bRelative ? "locked" : "unlocked", nRepeat,
            (int)g_nPress[7] - (int)g_nPress[6], (int)g_nPress[5] - (int)g_nPress[4],
            nExpectedX, nExpectedY);
        return 1;
    }
    return 0;
}

int main(void)
{
    static directgate_session_t session;
    _XPrivDisplay pDisplay = calloc(1, sizeof(*pDisplay));
    if (pDisplay == NULL) return 1;
    Screen screen = {0};
    pDisplay->screens = &screen;
    session.desktop.pDisplay = pDisplay;
    session.desktop.pFakeMotion = (void*)TestMotion;
    session.desktop.pFakeButton = (void*)TestButton;
    session.desktop.bRunning = session.desktop.bInputReady = XTRUE;
    session.desktop.nFrameWidth = session.desktop.nCaptureWidth = 1920;
    session.desktop.nFrameHeight = session.desktop.nCaptureHeight = 1080;

    int nFailures = 0;
    for (int nRelative = 0; nRelative <= 1; nRelative++)
    {
        /* Ordinary mouse notches keep their distance and direction. */
        nFailures += CheckWheel(&session, "\"deltaY\":120,\"deltaX\":-100", 1, nRelative, -1, 1);
        nFailures += CheckWheel(&session, "\"deltaY\":-120,\"deltaX\":100", 5, nRelative, 5, -6);
        /* Decimal and exponential JSON values must not be discarded. */
        nFailures += CheckWheel(&session, "\"deltaY\":100.0,\"deltaX\":-1e2", 1, nRelative, -1, 1);
        nFailures += CheckWheel(&session, "\"deltaY\":2.5,\"deltaX\":-1.25", 80, nRelative, -1, 2);
        nFailures += CheckWheel(&session, "\"deltaY\":0.25,\"deltaX\":-0.5", 400, nRelative, -2, 1);
        nFailures += CheckWheel(&session, "\"deltaY\":-2.5e-1", 400, nRelative, 0, -1);
        nFailures += CheckWheel(&session, "\"deltaY\":0,\"deltaX\":0", 1, nRelative, 0, 0);
        /* Values from the wire remain bounded before any integer cast. */
        nFailures += CheckWheel(&session, "\"deltaY\":2147483647,\"deltaX\":-2147483648", 1, nRelative, -1000, 1000);
        nFailures += CheckWheel(&session, "\"deltaY\":1e100,\"deltaX\":-1e100", 1, nRelative, -1000, 1000);
        nFailures += CheckWheel(&session, "\"deltaY\":1e999,\"deltaX\":-1e999", 1, nRelative, 0, 0);
        nFailures += CheckWheel(&session, "\"deltaY\":\"100\",\"deltaX\":true", 1, nRelative, 0, 0);
        nFailures += CheckWheel(&session, "\"deltaY\":null,\"deltaX\":{}", 1, nRelative, 0, 0);
        session.desktop.bInputReady = XFALSE;
        nFailures += CheckWheel(&session, "\"deltaY\":100", 1, nRelative, 0, 0);
        session.desktop.bInputReady = XTRUE;
    }

    free(pDisplay);
    if (nFailures != 0) return 1;
    puts("desktop_wheel_smoke: OK");
    return 0;
}
