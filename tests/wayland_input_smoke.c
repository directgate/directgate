/* Browser wheel JSON must reach the Wayland portal in native axis units,
 * including subpixel samples. No desktop session is needed for this test. */
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "src/agent/desktop/input.c"

struct directgate_wl_portal_ { int unused; };
struct directgate_wl_source_ { directgate_wl_portal_t portal; };

static unsigned int g_nAxisCalls;
static double g_nAxisX, g_nAxisY;

directgate_wl_portal_t* DirectGate_WL_SourcePortal(directgate_wl_source_t *pSource)
{
    return &pSource->portal;
}

xbool_t DirectGate_WL_SourceSize(directgate_wl_source_t *pSource, uint32_t *pWidth, uint32_t *pHeight)
{
    (void)pSource;
    *pWidth = 1920;
    *pHeight = 1080;
    return XTRUE;
}

uint32_t DirectGate_WL_SourceActiveNode(directgate_wl_source_t *pSource)
{
    (void)pSource;
    return 1;
}

int DirectGate_WL_PortalPointerAxis(directgate_wl_portal_t *pPortal, double nDx, double nDy)
{
    (void)pPortal;
    g_nAxisCalls++;
    g_nAxisX += nDx;
    g_nAxisY += nDy;
    return XSTDOK;
}

int DirectGate_WL_PortalPointerMotion(directgate_wl_portal_t *pPortal, uint32_t nStream, double nX, double nY)
{
    (void)pPortal; (void)nStream; (void)nX; (void)nY;
    return XSTDOK;
}

int DirectGate_WL_PortalPointerMotionRelative(directgate_wl_portal_t *pPortal, double nDx, double nDy)
{
    (void)pPortal; (void)nDx; (void)nDy;
    return XSTDOK;
}

int DirectGate_WL_PortalPointerButton(directgate_wl_portal_t *pPortal, int32_t nButton, xbool_t bPressed)
{
    (void)pPortal; (void)nButton; (void)bPressed;
    return XSTDOK;
}

int32_t DirectGate_WL_PortalButtonCode(uint32_t nButton)
{
    (void)nButton;
    return 0;
}

int DirectGate_WL_PortalKeysym(directgate_wl_portal_t *pPortal, int32_t nKeysym, xbool_t bPressed)
{
    (void)pPortal; (void)nKeysym; (void)bPressed;
    return XSTDOK;
}

int DirectGate_WL_PortalKeycode(directgate_wl_portal_t *pPortal, int32_t nKeycode, xbool_t bPressed)
{
    (void)pPortal; (void)nKeycode; (void)bPressed;
    return XSTDOK;
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
                     xbool_t bRelative, double nExpectedX, double nExpectedY)
{
    char sPayload[512];
    int nLength = snprintf(sPayload, sizeof(sPayload),
        "{\"action\":\"pointer\",\"event\":\"wheel\",\"relative\":%s,\"x\":960,\"y\":540,%s}",
        bRelative ? "true" : "false", pDeltas);
    if (nLength < 0 || (size_t)nLength >= sizeof(sPayload)) return 1;

    g_nAxisCalls = 0;
    g_nAxisX = g_nAxisY = 0.0;
    for (unsigned int i = 0; i < nRepeat; i++)
        DirectGate_Desktop_HandleInput(pSession, (const uint8_t*)sPayload, (size_t)nLength);

    unsigned int nExpectedCalls = (nExpectedX != 0.0 || nExpectedY != 0.0) ? nRepeat : 0;
    if (g_nAxisCalls != nExpectedCalls || !isfinite(g_nAxisX) || !isfinite(g_nAxisY) ||
        fabs(g_nAxisX - nExpectedX) > 1e-9 || fabs(g_nAxisY - nExpectedY) > 1e-9)
    {
        fprintf(stderr, "wayland_input_smoke: %s (%s, repeat %u): "
            "got (%g,%g) in %u calls, expected (%g,%g) in %u\n", pDeltas,
            bRelative ? "locked" : "unlocked", nRepeat, g_nAxisX, g_nAxisY, g_nAxisCalls,
            nExpectedX, nExpectedY, nExpectedCalls);
        return 1;
    }
    return 0;
}

int main(void)
{
    static directgate_session_t session;
    directgate_wl_source_t source = {0};
    session.desktop.pWayland = &source;
    session.desktop.bRunning = session.desktop.bInputReady = XTRUE;
    session.desktop.nFrameWidth = session.desktop.nCaptureWidth = 1920;
    session.desktop.nFrameHeight = session.desktop.nCaptureHeight = 1080;

    int nFailures = 0;
    for (int nRelative = 0; nRelative <= 1; nRelative++)
    {
        /* Our wire convention is 100 browser pixels per notch; Mutter's
         * smooth axis API uses 10 units per notch. Preserve both axes. */
        nFailures += CheckWheel(&session, "\"deltaY\":100,\"deltaX\":0", 1, nRelative, 0, 10);
        nFailures += CheckWheel(&session, "\"deltaY\":-120,\"deltaX\":99", 1, nRelative, 9.9, -12);
        nFailures += CheckWheel(&session, "\"deltaY\":100.0,\"deltaX\":1e2", 1, nRelative, 10, 10);
        /* Every tiny sample must be sent, with no rounding or batching. */
        nFailures += CheckWheel(&session, "\"deltaY\":0.25,\"deltaX\":-0.5", 40, nRelative, -2, 1);
        nFailures += CheckWheel(&session, "\"deltaY\":-0.25", 1, nRelative, 0, -0.025);
        nFailures += CheckWheel(&session, "\"deltaY\":0,\"deltaX\":0", 1, nRelative, 0, 0);
        /* Untrusted numeric values stay bounded; non-numbers and infinities
         * never reach the compositor. */
        nFailures += CheckWheel(&session, "\"deltaY\":2147483647,\"deltaX\":-2147483648", 1, nRelative, -10000, 10000);
        nFailures += CheckWheel(&session, "\"deltaY\":1e100,\"deltaX\":-1e100", 1, nRelative, -10000, 10000);
        nFailures += CheckWheel(&session, "\"deltaY\":1e999,\"deltaX\":-1e999", 1, nRelative, 0, 0);
        nFailures += CheckWheel(&session, "\"deltaY\":\"100\",\"deltaX\":true", 1, nRelative, 0, 0);
        nFailures += CheckWheel(&session, "\"deltaY\":null,\"deltaX\":{}", 1, nRelative, 0, 0);
    }

    if (nFailures != 0) return 1;
    puts("wayland_input_smoke: OK");
    return 0;
}
