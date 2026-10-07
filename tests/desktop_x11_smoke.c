/*
 * The X11 desktop against a real X server.
 *
 * Everything else in the suite runs the desktop on raw RGBA with no display
 * behind it. This starts a private Xvfb and drives the real path end to end:
 * opening the display and enumerating its monitors, the H.264 capture thread
 * and the raw capture, preset, resolution and display-mode changes, and every
 * kind of input - with a second X connection checking that the input landed.
 *
 * Xvfb comes from DIRECTGATE_XVFB or PATH; without one this skips. It never
 * touches the display the test was started from: DISPLAY is replaced by the
 * private server's, the session type is pinned to x11, and the server gets a
 * display number nothing else holds.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <X11/Xlib.h>
#include <X11/XKBlib.h>
#include <X11/keysym.h>
#include <X11/extensions/Xrandr.h>

#include "src/agent/desktop/desktop.h"
#include "src/agent/desktop/priv.h"
#include "src/agent/session.h"
#include "src/agent/config.h"

#include "xvfb_fixture.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "desktop_x11_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#define SCREEN_W XVFB_SCREEN_W
#define SCREEN_H XVFB_SCREEN_H

/* What the desktop sent, by kind. */
typedef struct {
    int nStatuses;
    int nRawChunks;
    int nEncoded;
    int nCursors;
    int nErrors;
    char sStatus[64];
    char sLastStatus[4096];
} sent_t;

static sent_t g_sent;
static directgate_session_t g_session;

/* Where the test is, for the watchdog: a hang says where instead of waiting out ctest. */
static const char *volatile g_pPhase = "starting";

static void on_watchdog(int nSignal)
{
    (void)nSignal;
    const char *pPhase = g_pPhase;
    static const char sLead[] = "desktop_x11_smoke: stuck in ";
    ssize_t nIgnored = write(STDERR_FILENO, sLead, sizeof(sLead) - 1);
    nIgnored = write(STDERR_FILENO, pPhase, strlen(pPhase));
    nIgnored = write(STDERR_FILENO, "\n", 1);
    (void)nIgnored;
    _exit(1);
}

static void copy_field(const char *pJson, const char *pKey, char *pOut, size_t nSize)
{
    pOut[0] = '\0';
    char sNeedle[64];
    snprintf(sNeedle, sizeof(sNeedle), "\"%s\":\"", pKey);

    const char *pAt = strstr(pJson, sNeedle);
    if (pAt == NULL) return;
    pAt += strlen(sNeedle);

    size_t i = 0;
    while (pAt[i] != '\0' && pAt[i] != '"' && i + 1 < nSize) { pOut[i] = pAt[i]; i++; }
    pOut[i] = '\0';
}

int DirectGate_Session_Send(directgate_session_t *pSession, xjson_obj_t *pHeader,
                            const uint8_t *pPayload, size_t nPayloadLength)
{
    (void)pSession;
    const char *pType = XJSON_GetString(XJSON_GetObject(pHeader, "payloadType"));

    if (pType != NULL && strcmp(pType, "desktop-frame-chunk") == 0) g_sent.nRawChunks++;
    else if (pType != NULL && strcmp(pType, "desktop-frame-encoded") == 0) g_sent.nEncoded++;
    else if (pType != NULL && strcmp(pType, "desktop-cursor") == 0) g_sent.nCursors++;
    else if (pType != NULL && strcmp(pType, "desktop-status") == 0 && pPayload != NULL)
    {
        size_t nLen = nPayloadLength < sizeof(g_sent.sLastStatus) - 1 ? nPayloadLength : sizeof(g_sent.sLastStatus) - 1;
        memcpy(g_sent.sLastStatus, pPayload, nLen);
        g_sent.sLastStatus[nLen] = '\0';
        copy_field(g_sent.sLastStatus, "status", g_sent.sStatus, sizeof(g_sent.sStatus));
        g_sent.nStatuses++;
    }

    return XSTDOK;
}

int DirectGate_Session_SendErrorMsg(directgate_session_t *pSession, const char *pReason)
{
    (void)pSession; (void)pReason;
    g_sent.nErrors++;
    return XSTDOK;
}

/* ---- driving the session ---- */

static int control(const char *pJson)
{
    return DirectGate_Desktop_HandleControl(&g_session, (const uint8_t*)pJson, strlen(pJson));
}

/* Input goes out on the agent's own X connection and the checks read it back on another one. The server
   orders requests per connection only, so a round trip on the agent's makes sure it acted before we look. */
static void settle(void)
{
    if (g_session.desktop.pDisplay != NULL) XSync((Display*)g_session.desktop.pDisplay, False);
}

static int input(const char *pJson)
{
    int nStatus = DirectGate_Desktop_HandleInput(&g_session, (const uint8_t*)pJson, strlen(pJson));
    settle();
    return nStatus;
}

/* Runs the session's tick until pDone says so or the time is up. */
static int pump_until(int (*pDone)(void), int nTimeoutMs)
{
    for (int nWaited = 0; nWaited < nTimeoutMs; nWaited += 10)
    {
        int nFd = DirectGate_Desktop_GetTimerFd(&g_session.desktop);
        if (nFd >= 0)
        {
            struct pollfd pfd = { nFd, POLLIN, 0 };
            (void)poll(&pfd, 1, 10);
        }
        else usleep(10000);

        (void)DirectGate_Desktop_Process(&g_session);
        if (pDone()) return 1;
    }

    return 0;
}

static uint32_t g_nBitrateBefore;
static int bitrate_lowered(void)
{
    uint32_t nNow = g_session.desktop.nCurrentBitrateKbps;
    return nNow != 0 && nNow < g_nBitrateBefore;
}

static int demoted(void) { return g_session.desktop.ePipeline == DIRECTGATE_DESKTOP_PIPELINE_RAW; }

static int g_nWantEncoded;
static int g_nWantRaw;
static int enough_encoded(void) { return g_sent.nEncoded >= g_nWantEncoded; }
static int enough_raw(void) { return g_sent.nRawChunks >= g_nWantRaw; }

static const char* first_monitor(void)
{
    for (uint32_t i = 0; i < g_session.desktop.nMonitorCount; i++)
        if (strcmp(g_session.desktop.monitors[i].sId, "all") != 0) return g_session.desktop.monitors[i].sId;

    return "all";
}

static int key_is_down(Display *pObserver, KeySym sym)
{
    char keys[32];
    XQueryKeymap(pObserver, keys);
    KeyCode code = XKeysymToKeycode(pObserver, sym);
    return code != 0 && (keys[code / 8] & (1 << (code % 8))) != 0;
}

static void pointer_at(Display *pObserver, int *pX, int *pY, unsigned int *pMask)
{
    Window root, child;
    int nWinX, nWinY;
    XQueryPointer(pObserver, DefaultRootWindow(pObserver), &root, &child, pX, pY, &nWinX, &nWinY, pMask);
}

/* Gives the X11 capture a second mode to switch to, the way xrandr --addmode does. */
static int add_output_mode(Display *pObserver, uint32_t nWidth, uint32_t nHeight)
{
    Window root = DefaultRootWindow(pObserver);
    XRRScreenResources *pRes = XRRGetScreenResources(pObserver, root);
    if (pRes == NULL || pRes->noutput < 1) return 0;

    XRRModeInfo mode;
    memset(&mode, 0, sizeof(mode));
    char sName[32];
    snprintf(sName, sizeof(sName), "%ux%u_test", nWidth, nHeight);
    mode.width = nWidth;
    mode.height = nHeight;
    mode.dotClock = (unsigned long)nWidth * nHeight * 60UL;
    mode.hSyncStart = nWidth + 8; mode.hSyncEnd = nWidth + 16; mode.hTotal = nWidth + 24;
    mode.vSyncStart = nHeight + 1; mode.vSyncEnd = nHeight + 2; mode.vTotal = nHeight + 3;
    mode.name = sName;
    mode.nameLength = (unsigned int)strlen(sName);

    RRMode nMode = XRRCreateMode(pObserver, root, &mode);
    if (nMode != None) XRRAddOutputMode(pObserver, pRes->outputs[0], nMode);
    XRRFreeScreenResources(pRes);
    XSync(pObserver, False);
    return nMode != None;
}

static int start_and_pick(uint32_t nSessionId)
{
    memset(&g_session, 0, sizeof(g_session));
    memset(&g_sent, 0, sizeof(g_sent));
    g_session.nSessionId = nSessionId;

    CHECK(DirectGate_Desktop_Start(&g_session) >= 0, "the desktop starts");
    char sJson[256];
    snprintf(sJson, sizeof(sJson), "{\"action\":\"select-monitor\",\"monitorId\":\"%s\"}", first_monitor());
    CHECK(control(sJson) == XAPI_CONTINUE, "pick the monitor");
    return 0;
}

static int test_no_display(const char *pGood)
{
    g_pPhase = "no display";
    /* A display nobody serves: refused with a reason, and nothing left running. */
    char sBad[16];
    snprintf(sBad, sizeof(sBad), ":%d", free_display(400));
    setenv("DISPLAY", sBad, 1);

    memset(&g_session, 0, sizeof(g_session));
    memset(&g_sent, 0, sizeof(g_sent));
    g_session.nSessionId = 20;
    CHECK(DirectGate_Desktop_Start(&g_session) < 0, "a display that cannot be opened fails the start");
    CHECK(strcmp(g_sent.sStatus, "error") == 0 && g_sent.nErrors == 1, "and the viewer is told why");
    CHECK(strstr(DirectGate_Desktop_GetReason(&g_session.desktop), "X11") != NULL, "the reason names X11");
    DirectGate_Desktop_Clear(&g_session.desktop);

    /* A Wayland session, on a build without Wayland streaming, says so. */
    setenv("DISPLAY", pGood, 1);
    setenv("XDG_SESSION_TYPE", "wayland", 1);
    memset(&g_sent, 0, sizeof(g_sent));
    CHECK(DirectGate_Desktop_Start(&g_session) < 0, "a Wayland session without Wayland support fails the start");
    CHECK(strcmp(g_session.desktop.sBackend, "wayland") == 0, "and names the backend it found");
    DirectGate_Desktop_Clear(&g_session.desktop);
    setenv("XDG_SESSION_TYPE", "x11", 1);
    return 0;
}

static int test_h264(Display *pObserver)
{
    g_pPhase = "h264";
    memset(&g_session, 0, sizeof(g_session));
    memset(&g_sent, 0, sizeof(g_sent));
    g_session.nSessionId = 21;

    CHECK(DirectGate_Desktop_Start(&g_session) >= 0, "the desktop starts on the private display");
    directgate_desktop_t *pDesktop = &g_session.desktop;
    CHECK(strcmp(g_sent.sStatus, "ready") == 0, "a started desktop reports ready");
    CHECK(strcmp(pDesktop->sBackend, "x11") == 0, "the backend is X11");
    CHECK(pDesktop->nScreenWidth == SCREEN_W && pDesktop->nScreenHeight == SCREEN_H,
        "the screen size is read from the root window");
    CHECK(pDesktop->bInputReady, "XTest is loaded for input");
    CHECK(pDesktop->nMonitorCount >= 2, "the RandR monitor is listed next to all displays");
    CHECK(DirectGate_Desktop_Start(&g_session) == XAPI_CONTINUE, "starting a running desktop again is a no-op");

    /* Nothing is captured until a screen is picked. */
    CHECK(DirectGate_Desktop_Process(&g_session) == XAPI_CONTINUE && g_sent.nRawChunks == 0 && g_sent.nEncoded == 0,
        "no screen picked, nothing captured");

    char sJson[256];
    snprintf(sJson, sizeof(sJson), "{\"action\":\"select-monitor\",\"monitorId\":\"%s\"}", first_monitor());
    CHECK(control(sJson) == XAPI_CONTINUE, "pick the monitor");
    CHECK(strcmp(g_sent.sStatus, "streaming") == 0, "picking a monitor starts the stream");
    CHECK(pDesktop->bCaptureReady, "the capture is ready");

    if (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_H264_DC)
    {
        g_nWantEncoded = 3;
        CHECK(pump_until(enough_encoded, 10000), "the H.264 capture thread delivers frames");

        CHECK(control("{\"action\":\"request-keyframe\"}") == XAPI_CONTINUE, "ask for a keyframe");
        CHECK(control("{\"action\":\"set-preset\",\"preset\":\"quality\"}") == XAPI_CONTINUE, "switch to the quality preset");
        CHECK(pDesktop->quality.ePreset == DIRECTGATE_DESKTOP_PRESET_QUALITY, "the preset is applied");
        CHECK(control("{\"action\":\"set-preset\",\"preset\":\"low-latency\"}") == XAPI_CONTINUE, "switch to low latency");
        CHECK(control("{\"action\":\"set-resolution\",\"mode\":\"scale\",\"width\":640,\"height\":360}") == XAPI_CONTINUE,
            "scale the stream down");
        CHECK(strcmp(g_sent.sStatus, "streaming") == 0, "a scaled stream keeps streaming");
        CHECK(control("{\"action\":\"fallback-datachannel\"}") == XAPI_CONTINUE, "a data channel fallback is accepted");

        g_nWantEncoded = g_sent.nEncoded + 3;
        CHECK(pump_until(enough_encoded, 10000), "frames keep coming after the changes");

        /* A relay socket that cannot drain: the encoder steps down rather than queue further behind. */
        static xapi_session_t relay;
        memset(&relay, 0, sizeof(relay));
        relay.sock.nFD = XSOCK_INVALID;
        relay.txBuffer.nUsed = 4U * 1024U * 1024U;
        g_session.pWsSession = &relay;
        g_nBitrateBefore = pDesktop->nCurrentBitrateKbps ? pDesktop->nCurrentBitrateKbps : pDesktop->quality.nBitrateKbps;
        CHECK(pump_until(bitrate_lowered, 5000), "a backed-up relay steps the bitrate down");
        g_session.pWsSession = NULL;
    }
    else
    {
        fprintf(stderr, "desktop_x11_smoke: no H.264 encoder here (%s), checking the raw fallback only\n",
            pDesktop->sFallbackReason);
        CHECK(pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_RAW, "without an encoder the pipeline is raw");
    }

    /* A display mode the monitor has, and back again. */
    int bModeAdded = add_output_mode(pObserver, 1024, 576);
    snprintf(sJson, sizeof(sJson), "{\"action\":\"select-monitor\",\"monitorId\":\"%s\",\"mode\":\"display\","
        "\"width\":1024,\"height\":576}", first_monitor());
    CHECK(control(sJson) == XAPI_CONTINUE, "pick the monitor at another display mode");
    if (bModeAdded && pDesktop->bDisplayModeChanged)
    {
        /* RandR 1.2 changes the CRTC, not the screen: the monitor is what shrinks. */
        const directgate_desktop_monitor_t *pMonitor = DirectGate_Desktop_FindMonitor(pDesktop, first_monitor());
        CHECK(pMonitor != NULL && pMonitor->nWidth == 1024 && pMonitor->nHeight == 576,
            "the display mode is changed on the server");
        CHECK(pDesktop->nCaptureWidth == 1024 && pDesktop->nCaptureHeight == 576, "the capture follows the new mode");

        CHECK(control("{\"action\":\"set-resolution\",\"mode\":\"display\",\"width\":1280,\"height\":720}") == XAPI_CONTINUE,
            "ask for the original size as a display mode");
        CHECK(control("{\"action\":\"set-resolution\",\"mode\":\"scale\"}") == XAPI_CONTINUE, "go back to scaling");
        CHECK(!pDesktop->bDisplayModeChanged, "leaving display mode restores the original mode");
    }

    /* The whole desktop cannot take a display mode: it falls back to scaling, with a reason. */
    CHECK(control("{\"action\":\"select-monitor\",\"monitorId\":\"all\",\"mode\":\"display\",\"width\":800,\"height\":600}")
        == XAPI_CONTINUE, "pick all displays at a display mode");
    CHECK(pDesktop->eResizeMode == DIRECTGATE_DESKTOP_RESIZE_SCALE, "all displays fall back to scaling");
    CHECK(control("{\"action\":\"select-monitor\",\"monitorId\":\"monitor-99\"}") == XAPI_CONTINUE,
        "pick a monitor that is not there");
    CHECK(strcmp(g_sent.sStatus, "error") == 0, "a monitor that is not there is an error");

    DirectGate_Desktop_Clear(pDesktop);
    CHECK(!pDesktop->bRunning, "clearing the desktop stops it");
    return 0;
}

/* The screen shrinks under a running capture: every grab fails, the H.264
   pipeline gives up and the stream steps down to raw, which fails quietly too
   until the viewer picks the screen again. */
static int test_capture_lost(Display *pObserver)
{
    g_pPhase = "capture lost";
    if (start_and_pick(26)) return 1;
    directgate_desktop_t *pDesktop = &g_session.desktop;
    if (pDesktop->ePipeline != DIRECTGATE_DESKTOP_PIPELINE_H264_DC)
    {
        DirectGate_Desktop_Clear(pDesktop);
        return 0;
    }

    Window root = DefaultRootWindow(pObserver);
    XRRScreenResources *pRes = XRRGetScreenResources(pObserver, root);
    CHECK(pRes != NULL && pRes->ncrtc > 0 && pRes->noutput > 0, "read the screen resources");
    XRRCrtcInfo *pCrtc = XRRGetCrtcInfo(pObserver, pRes, pRes->crtcs[0]);
    CHECK(pCrtc != NULL, "read the CRTC");
    RRMode nOriginal = pCrtc->mode;

    CHECK(add_output_mode(pObserver, 640, 360), "add a small mode");
    XRRScreenResources *pNow = XRRGetScreenResources(pObserver, root);
    RRMode nSmall = None;
    for (int i = 0; pNow != NULL && i < pNow->nmode; i++)
        if (pNow->modes[i].width == 640 && pNow->modes[i].height == 360) nSmall = pNow->modes[i].id;
    CHECK(nSmall != None, "find the small mode");

    RROutput output = pRes->outputs[0];
    CHECK(XRRSetCrtcConfig(pObserver, pNow, pRes->crtcs[0], CurrentTime, 0, 0, nSmall, RR_Rotate_0, &output, 1) == Success,
        "switch the CRTC to the small mode");
    XRRSetScreenSize(pObserver, root, 640, 360, 169, 95);
    XSync(pObserver, False);

    CHECK(pump_until(demoted, 10000), "a capture that keeps failing steps down to raw");
    for (int i = 0; i < 5; i++) (void)DirectGate_Desktop_Process(&g_session);
    CHECK(strcmp(g_sent.sStatus, "streaming") == 0, "and the viewer is told the stream goes on");

    XRRSetScreenSize(pObserver, root, SCREEN_W, SCREEN_H, 338, 190);
    CHECK(XRRSetCrtcConfig(pObserver, pNow, pRes->crtcs[0], CurrentTime, 0, 0, nOriginal, RR_Rotate_0, &output, 1) == Success,
        "restore the original mode");
    XSync(pObserver, False);

    XRRFreeCrtcInfo(pCrtc);
    XRRFreeScreenResources(pNow);
    XRRFreeScreenResources(pRes);
    DirectGate_Desktop_Clear(pDesktop);
    return 0;
}

/* Everything around the stream that is not the stream. */
static int test_edges(Display *pObserver)
{
    g_pPhase = "edges";
    char sHome[] = "/tmp/directgate_x11_home.XXXXXX";
    CHECK(mkdtemp(sHome) != NULL, "create a shell home");
    char sAuth[128];
    snprintf(sAuth, sizeof(sAuth), "%s/.Xauthority", sHome);
    FILE *pAuth = fopen(sAuth, "w");
    CHECK(pAuth != NULL, "create an empty .Xauthority");
    fclose(pAuth);

    /* The shell user's .Xauthority is used when nothing else names one. */
    static directgate_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.sShellHome, sizeof(cfg.sShellHome), "%s", sHome);
    unsetenv("XAUTHORITY");

    memset(&g_session, 0, sizeof(g_session));
    memset(&g_sent, 0, sizeof(g_sent));
    g_session.nSessionId = 27;
    g_session.pCfg = &cfg;
    CHECK(DirectGate_Desktop_Start(&g_session) >= 0, "the desktop starts with the shell user's .Xauthority");
    CHECK(getenv("XAUTHORITY") != NULL && strcmp(getenv("XAUTHORITY"), sAuth) == 0, "XAUTHORITY points at the shell user's file");
    directgate_desktop_t *pDesktop = &g_session.desktop;

    /* Protocol errors from anything in the process are logged and survived. */
    for (int i = 0; i < 7; i++)
    {
        XMapWindow(pObserver, (Window)0x1fffffffUL);
        XSync(pObserver, False);
    }

    /* A mode bigger than the screen can hold: RandR says no, and the stream scales instead. */
    char sJson[256];
    int bHuge = add_output_mode(pObserver, 4096, 2304);
    snprintf(sJson, sizeof(sJson), "{\"action\":\"select-monitor\",\"monitorId\":\"%s\",\"mode\":\"display\","
        "\"width\":4096,\"height\":2304}", first_monitor());
    CHECK(control(sJson) == XAPI_CONTINUE, "ask for a mode the screen cannot hold");
    if (bHuge && !pDesktop->bDisplayModeChanged)
        CHECK(strstr(g_sent.sLastStatus, "XRandR") != NULL || pDesktop->eResizeMode == DIRECTGATE_DESKTOP_RESIZE_SCALE,
            "a refused mode falls back to scaling");
    if (pDesktop->bDisplayModeChanged) DirectGate_Desktop_RestoreDisplayMode(pDesktop);

    /* Display mode on a monitor, then scaling: picking again restores the mode first. */
    snprintf(sJson, sizeof(sJson), "{\"action\":\"select-monitor\",\"monitorId\":\"%s\",\"mode\":\"display\","
        "\"width\":1024,\"height\":576}", first_monitor());
    CHECK(control(sJson) == XAPI_CONTINUE, "pick a display mode");
    snprintf(sJson, sizeof(sJson), "{\"action\":\"select-monitor\",\"monitorId\":\"%s\",\"mode\":\"scale\"}", first_monitor());
    CHECK(control(sJson) == XAPI_CONTINUE, "pick the same monitor scaled");
    CHECK(!pDesktop->bDisplayModeChanged, "scaling puts the original mode back");

    /* All displays cannot take a display mode through set-resolution either. */
    CHECK(control("{\"action\":\"select-monitor\",\"monitorId\":\"all\"}") == XAPI_CONTINUE, "pick all displays");
    CHECK(control("{\"action\":\"set-resolution\",\"mode\":\"display\",\"width\":800,\"height\":600}") == XAPI_CONTINUE,
        "ask all displays for a display mode");
    CHECK(pDesktop->eResizeMode == DIRECTGATE_DESKTOP_RESIZE_SCALE, "all displays stay scaled");

    /* Junk and the audio switch turned off. */
    CHECK(control("not json") == XAPI_CONTINUE, "a control body that is not JSON is dropped");
    CHECK(control("{\"action\":\"audio\",\"enabled\":false}") == XAPI_CONTINUE, "audio off is accepted");
    CHECK(!pDesktop->bAudioRequested, "audio stays off");

    DirectGate_Desktop_Clear(pDesktop);
    g_session.pCfg = NULL;
    unsetenv("XAUTHORITY");
    unlink(sAuth);
    rmdir(sHome);

    /* How a Wayland session is recognised when XDG_SESSION_TYPE says nothing. */
    char sRuntime[] = "/tmp/directgate_x11_runtime.XXXXXX";
    CHECK(mkdtemp(sRuntime) != NULL, "create a runtime directory");
    unsetenv("XDG_SESSION_TYPE");
    setenv("WAYLAND_DISPLAY", "wayland-9", 1);
    CHECK(DirectGate_Desktop_Start(&g_session) < 0 && strcmp(g_session.desktop.sBackend, "wayland") == 0,
        "WAYLAND_DISPLAY marks a Wayland session");
    DirectGate_Desktop_Clear(&g_session.desktop);
    unsetenv("WAYLAND_DISPLAY");

    char sSocket[128];
    snprintf(sSocket, sizeof(sSocket), "%s/wayland-2", sRuntime);
    FILE *pSocket = fopen(sSocket, "w");
    CHECK(pSocket != NULL, "create a Wayland socket stand-in");
    fclose(pSocket);
    setenv("XDG_RUNTIME_DIR", sRuntime, 1);
    CHECK(DirectGate_Desktop_Start(&g_session) < 0 && strcmp(g_session.desktop.sBackend, "wayland") == 0,
        "a wayland socket in the runtime directory marks a Wayland session");
    DirectGate_Desktop_Clear(&g_session.desktop);

    unlink(sSocket);
    CHECK(DirectGate_Desktop_Start(&g_session) >= 0 && strcmp(g_session.desktop.sBackend, "x11") == 0,
        "a runtime directory with no Wayland socket is X11");
    DirectGate_Desktop_Clear(&g_session.desktop);

    unsetenv("XDG_RUNTIME_DIR");
    CHECK(DirectGate_Desktop_Start(&g_session) >= 0, "no runtime directory at all is X11");
    DirectGate_Desktop_Clear(&g_session.desktop);

    rmdir(sRuntime);
    setenv("XDG_SESSION_TYPE", "x11", 1);
    return 0;
}

static int test_raw(void)
{
    g_pPhase = "raw";
    memset(&g_session, 0, sizeof(g_session));
    memset(&g_sent, 0, sizeof(g_sent));
    g_session.nSessionId = 22;

    setenv("DIRECTGATE_DESKTOP_FORCE_RAW", "1", 1);
    CHECK(DirectGate_Desktop_Start(&g_session) >= 0, "the raw desktop starts");
    unsetenv("DIRECTGATE_DESKTOP_FORCE_RAW");

    directgate_desktop_t *pDesktop = &g_session.desktop;
    CHECK(pDesktop->bForceRaw, "the raw pipeline is forced");

    char sJson[256];
    snprintf(sJson, sizeof(sJson), "{\"action\":\"select-monitor\",\"monitorId\":\"%s\"}", first_monitor());
    CHECK(control(sJson) == XAPI_CONTINUE && pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_RAW, "the raw stream starts");

    g_nWantRaw = 2;
    CHECK(pump_until(enough_raw, 5000), "the raw capture reads the screen and sends it in chunks");

    CHECK(control("{\"action\":\"set-preset\",\"preset\":\"balanced\"}") == XAPI_CONTINUE, "change the preset on a raw stream");
    CHECK(control("{\"action\":\"set-resolution\",\"mode\":\"scale\",\"width\":320,\"height\":180}") == XAPI_CONTINUE,
        "scale a raw stream");
    g_nWantRaw = g_sent.nRawChunks + 1;
    CHECK(pump_until(enough_raw, 5000), "the scaled raw stream keeps coming");

    DirectGate_Desktop_Clear(pDesktop);
    return 0;
}

static int test_input(Display *pObserver)
{
    g_pPhase = "input";
    memset(&g_session, 0, sizeof(g_session));
    memset(&g_sent, 0, sizeof(g_sent));
    g_session.nSessionId = 23;

    setenv("DIRECTGATE_DESKTOP_FORCE_RAW", "1", 1);
    CHECK(DirectGate_Desktop_Start(&g_session) >= 0, "the desktop for input starts");
    unsetenv("DIRECTGATE_DESKTOP_FORCE_RAW");

    CHECK(control("{\"action\":\"select-monitor\",\"monitorId\":\"all\"}") == XAPI_CONTINUE, "pick all displays");
    directgate_desktop_t *pDesktop = &g_session.desktop;

    /* Absolute moves land where the frame says, scaled to the screen. */
    char sJson[256];
    snprintf(sJson, sizeof(sJson), "{\"action\":\"pointer\",\"event\":\"move\",\"x\":%u,\"y\":%u,\"sequence\":5}",
        pDesktop->nFrameWidth / 2, pDesktop->nFrameHeight / 2);
    CHECK(input(sJson) == XAPI_CONTINUE, "move the pointer");
    int nX = 0, nY = 0;
    unsigned int nMask = 0;
    pointer_at(pObserver, &nX, &nY, &nMask);
    CHECK(abs(nX - SCREEN_W / 2) <= 2 && abs(nY - SCREEN_H / 2) <= 2, "the pointer is where the viewer put it");

    /* An old sequence number is a reordered packet and is dropped. */
    CHECK(input("{\"action\":\"pointer\",\"event\":\"move\",\"x\":1,\"y\":1,\"sequence\":4}") == XAPI_CONTINUE,
        "a stale move is taken");
    pointer_at(pObserver, &nX, &nY, &nMask);
    CHECK(abs(nX - SCREEN_W / 2) <= 2, "a stale move does not move the pointer");

    /* A button goes down and comes up. */
    CHECK(input("{\"action\":\"pointer\",\"event\":\"button\",\"button\":1,\"down\":true,\"x\":10,\"y\":10}") == XAPI_CONTINUE,
        "press the left button");
    pointer_at(pObserver, &nX, &nY, &nMask);
    CHECK((nMask & Button1Mask) != 0, "the left button is down on the server");
    CHECK(input("{\"action\":\"pointer\",\"event\":\"button\",\"button\":1,\"down\":false,\"x\":10,\"y\":10}") == XAPI_CONTINUE,
        "release the left button");
    pointer_at(pObserver, &nX, &nY, &nMask);
    CHECK((nMask & Button1Mask) == 0, "the left button is up again");
    CHECK(input("{\"action\":\"pointer\",\"event\":\"button\",\"button\":2,\"down\":false,\"x\":10,\"y\":10}") == XAPI_CONTINUE,
        "a release with no press is dropped");

    /* Wheel both ways on both axes, and relative motion with the cursor reported back. */
    CHECK(input("{\"action\":\"pointer\",\"event\":\"wheel\",\"deltaY\":250,\"deltaX\":-120,\"x\":10,\"y\":10}") == XAPI_CONTINUE,
        "scroll");
    CHECK(input("{\"action\":\"pointer\",\"event\":\"wheel\",\"deltaY\":-300,\"deltaX\":\"bogus\",\"x\":10,\"y\":10}")
        == XAPI_CONTINUE, "scroll back");
    int nCursorsBefore = g_sent.nCursors;
    CHECK(input("{\"action\":\"pointer\",\"event\":\"move\",\"relative\":true,\"dx\":30,\"dy\":-5,\"sequence\":9}")
        == XAPI_CONTINUE, "move relatively");
    CHECK(g_sent.nCursors == nCursorsBefore + 1, "a relative move reports where the cursor ended up");
    CHECK(input("{\"action\":\"pointer\",\"event\":\"move\",\"relative\":true,\"dx\":-100000,\"dy\":-100000}") == XAPI_CONTINUE,
        "move relatively far off the screen");
    pointer_at(pObserver, &nX, &nY, &nMask);
    CHECK(nX >= 0 && nY >= 0, "the pointer stays on the screen");

    /* Keys by position, by name, by character, modifiers, out-of-layout characters. */
    CHECK(input("{\"action\":\"key\",\"code\":\"KeyA\",\"key\":\"a\",\"down\":true}") == XAPI_CONTINUE, "press A");
    CHECK(key_is_down(pObserver, XK_a), "A is down on the server");
    CHECK(input("{\"action\":\"key\",\"code\":\"KeyA\",\"key\":\"a\",\"down\":false}") == XAPI_CONTINUE, "release A");
    CHECK(!key_is_down(pObserver, XK_a), "A is up again");

    static const char *pKeys[] = {
        "{\"action\":\"key\",\"code\":\"ShiftLeft\",\"key\":\"Shift\",\"down\":%s}",
        "{\"action\":\"key\",\"code\":\"ControlRight\",\"key\":\"Control\",\"down\":%s}",
        "{\"action\":\"key\",\"code\":\"\",\"key\":\"Enter\",\"down\":%s}",
        "{\"action\":\"key\",\"code\":\"\",\"key\":\"F5\",\"down\":%s}",
        /* Browsers send non-ASCII as raw UTF-8, and the parser keeps \\u escapes literal. */
        "{\"action\":\"key\",\"code\":\"\",\"key\":\"\xc3\xa9\",\"down\":%s}",
        "{\"action\":\"key\",\"code\":\"KeyA\",\"key\":\"\xe1\x83\x90\",\"down\":%s}",
        "{\"action\":\"key\",\"code\":\"\",\"key\":\"\xe2\x82\xac\",\"down\":%s}",
        "{\"action\":\"key\",\"code\":\"KeyA\",\"key\":\"\xe1\x83\x90\",\"down\":%s}",
        "{\"action\":\"key\",\"code\":\"\",\"key\":\"ShiftLeft\",\"down\":%s}",
        "{\"action\":\"key\",\"code\":\"Key1\",\"key\":\"Unidentified\",\"down\":%s}",
        "{\"action\":\"key\",\"code\":\"DigitZ\",\"key\":\"Dead\",\"down\":%s}",
        "{\"action\":\"key\",\"code\":\"KeyQ\",\"key\":\"Unidentified\",\"down\":%s}",
        "{\"action\":\"key\",\"code\":\"Digit7\",\"key\":\"Dead\",\"down\":%s}",
        "{\"action\":\"key\",\"code\":\"NumpadEnter\",\"key\":\"Unidentified\",\"down\":%s}",
        "{\"action\":\"key\",\"code\":\"Nonsense\",\"key\":\"Nonsense\",\"down\":%s}"
    };

    for (size_t i = 0; i < sizeof(pKeys) / sizeof(pKeys[0]); i++)
    {
        snprintf(sJson, sizeof(sJson), pKeys[i], "true");
        CHECK(input(sJson) == XAPI_CONTINUE, "press a key");
        snprintf(sJson, sizeof(sJson), pKeys[i], "false");
        CHECK(input(sJson) == XAPI_CONTINUE, "release the key");
    }

    /* A character no key on the host layout carries is bound to a spare keycode. */
    Window root = DefaultRootWindow(pObserver);
    (void)root;
    int nMin = 0, nMax = 0, nPer = 0;
    XDisplayKeycodes(pObserver, &nMin, &nMax);
    KeySym *pMap = XGetKeyboardMapping(pObserver, (KeyCode)nMin, nMax - nMin + 1, &nPer);
    int bBound = 0;
    for (int i = 0; pMap != NULL && i < (nMax - nMin + 1) * nPer; i++) bBound |= (pMap[i] == (KeySym)(0x10D0 | 0x01000000UL));
    if (pMap != NULL) XFree(pMap);
    CHECK(bBound, "the Georgian letter was bound to a spare keycode on the server");

    /* Typed text: two to four byte characters, a newline and a tab, and stops at broken UTF-8. */
    CHECK(input("{\"action\":\"text\",\"text\":\"Hi \xe1\x83\x92\xe1\x83\x90\xe1\x83\x9b\xe1\x83\x90\xe1\x83\xa0\xe1\x83\xaf"
        "\xe1\x83\x9d\xe1\x83\x91\xe1\x83\x90 \xc3\xa9 \xf0\x9f\x99\x82!\\n\\t\"}") == XAPI_CONTINUE, "type text");
    CHECK(input("{\"action\":\"text\",\"text\":\"ok\xe1\x28\xa1 never typed\"}") == XAPI_CONTINUE, "type broken UTF-8");
    CHECK(input("{\"action\":\"text\",\"text\":\"\"}") == XAPI_CONTINUE, "type nothing");

    char *pLong = (char*)malloc(2200);
    CHECK(pLong != NULL, "allocate a long text");
    int nLen = snprintf(pLong, 2200, "{\"action\":\"text\",\"text\":\"");
    memset(pLong + nLen, 'x', 1100);
    snprintf(pLong + nLen + 1100, 2200 - (size_t)nLen - 1100, "\"}");
    CHECK(input(pLong) == XAPI_CONTINUE, "text past the limit is dropped");
    free(pLong);

    /* More keys held than the table keeps: the oldest go, and a repeat just updates its entry. */
    for (int i = 0; i < 36; i++)
    {
        snprintf(sJson, sizeof(sJson), "{\"action\":\"key\",\"code\":\"%s%c\",\"key\":\"%c\",\"down\":true}",
            i < 26 ? "Key" : "Digit", i < 26 ? 'A' + i : '0' + (i - 26), i < 26 ? 'a' + i : '0' + (i - 26));
        CHECK(input(sJson) == XAPI_CONTINUE, "hold another key");
    }

    CHECK(pDesktop->nHeldKeyCount == DIRECTGATE_DESKTOP_MAX_HELD_KEYS, "the held table stays at its limit");
    CHECK(!key_is_down(pObserver, XK_a) && !key_is_down(pObserver, XK_d), "the keys pushed out of the table were let go");
    CHECK(key_is_down(pObserver, XK_e) && key_is_down(pObserver, XK_9), "the keys still in the table are still down");
    CHECK(input("{\"action\":\"key\",\"code\":\"Digit9\",\"key\":\"9\",\"down\":true}") == XAPI_CONTINUE, "repeat a held key");
    CHECK(pDesktop->nHeldKeyCount == DIRECTGATE_DESKTOP_MAX_HELD_KEYS, "a repeat does not take another entry");
    DirectGate_Desktop_ReleaseHeldKeys(pDesktop);
    settle();
    CHECK(pDesktop->nHeldKeyCount == 0 && !key_is_down(pObserver, XK_9), "every held key is released");

    /* Without relative XTest motion the pointer is warped instead; off the capture it is pulled back. */
    void *pRelative = pDesktop->pFakeRelativeMotion;
    pDesktop->pFakeRelativeMotion = NULL;
    CHECK(input("{\"action\":\"pointer\",\"event\":\"move\",\"relative\":true,\"dx\":5,\"dy\":5}") == XAPI_CONTINUE,
        "move relatively by warping");
    pDesktop->pFakeRelativeMotion = pRelative;

    DirectGate_Desktop_SetCapture(pDesktop, "all", 0, 0, 640, 360);
    CHECK(input("{\"action\":\"pointer\",\"event\":\"move\",\"relative\":true,\"dx\":100000,\"dy\":100000}") == XAPI_CONTINUE,
        "move relatively past the capture");
    pointer_at(pObserver, &nX, &nY, &nMask);
    CHECK(nX < 640 && nY < 360, "the pointer is pulled back into the capture");

    /* Lock keys as state. */
    CHECK(input("{\"action\":\"lock\",\"caps\":true,\"num\":false}") == XAPI_CONTINUE, "set the locks");
    unsigned int nState = 0;
    XkbGetIndicatorState(pObserver, XkbUseCoreKbd, &nState);
    CHECK(input("{\"action\":\"lock\",\"caps\":false}") == XAPI_CONTINUE, "clear caps lock");

    /* A key still held when the session goes is released, not left down on the host. */
    CHECK(input("{\"action\":\"key\",\"code\":\"KeyS\",\"key\":\"s\",\"down\":true}") == XAPI_CONTINUE, "hold S");
    CHECK(key_is_down(pObserver, XK_s), "S is held");
    pDesktop->nLastInputMs = 1;
    CHECK(DirectGate_Desktop_ExpireHeldKeys(pDesktop), "a key held through a long silence is released");
    settle();
    CHECK(!key_is_down(pObserver, XK_s), "S is up again");

    CHECK(input("{\"action\":\"key\",\"code\":\"KeyD\",\"key\":\"d\",\"down\":true}") == XAPI_CONTINUE, "hold D");
    DirectGate_Desktop_ReleaseHeldKeys(pDesktop);
    settle();
    CHECK(!key_is_down(pObserver, XK_d), "releasing held keys lets D go");

    CHECK(input("not json") == XAPI_CONTINUE && input("{\"action\":\"juggle\"}") == XAPI_CONTINUE, "junk input is dropped");
    CHECK(DirectGate_Desktop_HandleInput(&g_session, NULL, 5) == XAPI_CONTINUE, "no payload is dropped");

    /* A desktop with no display connection behind it takes input and does nothing with it. */
    void *pDisplay = pDesktop->pDisplay;
    pDesktop->pDisplay = NULL;
    CHECK(input("{\"action\":\"key\",\"code\":\"KeyA\",\"key\":\"a\",\"down\":true}") == XAPI_CONTINUE, "no display, no input");
    pDesktop->pDisplay = pDisplay;

    pDesktop->bRunning = XFALSE;
    CHECK(input("{\"action\":\"key\",\"code\":\"KeyA\",\"key\":\"a\",\"down\":true}") == XAPI_CONTINUE,
        "a stopped desktop takes no input");
    CHECK(!key_is_down(pObserver, XK_a), "and presses nothing");
    pDesktop->bRunning = XTRUE;

    DirectGate_Desktop_Clear(pDesktop);
    return 0;
}

/* A 30-bit screen without MIT-SHM: every frame by XGetImage, and pixels that
   are not the BGRX layout the fast path copies, so each is converted. */
static int test_deep_no_shm(void)
{
    g_pPhase = "30-bit without MIT-SHM";
    if (start_and_pick(24)) return 1;
    directgate_desktop_t *pDesktop = &g_session.desktop;

    if (pDesktop->ePipeline != DIRECTGATE_DESKTOP_PIPELINE_H264_DC)
    {
        fprintf(stderr, "desktop_x11_smoke: no H.264 encoder on the 30-bit screen (%s)\n", pDesktop->sFallbackReason);
        DirectGate_Desktop_Clear(pDesktop);
        return 0;
    }

    g_nWantEncoded = 2;
    CHECK(pump_until(enough_encoded, 10000), "a 30-bit screen without shared memory still encodes");

    /* The bitrate step and the error text, as the ABR controller and the fallback read them. */
    DirectGate_Desktop_LinuxEncoder_SetBitrate(&g_session, 1500);
    DirectGate_Desktop_LinuxEncoder_SetBitrate(&g_session, 0);
    DirectGate_Desktop_LinuxEncoder_SetBitrate(NULL, 1500);
    CHECK(strcmp(DirectGate_Desktop_LinuxEncoder_LastError(NULL), "no session") == 0, "no session has no encoder error");
    CHECK(DirectGate_Desktop_LinuxEncoder_LastError(&g_session) != NULL, "a running encoder has an error text to give");

    /* A frame left in the mailbox past its age is dropped, not shown late. */
    usleep(600000);
    int nBefore = g_sent.nEncoded;
    (void)DirectGate_Desktop_Process(&g_session);
    CHECK(g_sent.nEncoded <= nBefore + 1, "a stale frame is not sent late");
    g_nWantEncoded = g_sent.nEncoded + 1;
    CHECK(pump_until(enough_encoded, 10000), "and frames resume after it");

    /* Starts that cannot work: an empty rectangle, and a display the thread cannot open. */
    CHECK(DirectGate_Desktop_LinuxEncoder_Start(&g_session, 0, 0, 0, 0) < 0, "an empty capture rectangle is refused");
    CHECK(strstr(DirectGate_Desktop_LinuxEncoder_LastError(&g_session), "Empty") != NULL, "and says so");

    char sSaved[DIRECTGATE_DESKTOP_DISPLAY_LEN];
    snprintf(sSaved, sizeof(sSaved), "%s", pDesktop->sDisplay);
    snprintf(pDesktop->sDisplay, sizeof(pDesktop->sDisplay), ":%d", free_display(400));
    CHECK(DirectGate_Desktop_LinuxEncoder_Start(&g_session, 0, 0, 64, 64) < 0, "a capture thread without a display is refused");
    CHECK(strstr(DirectGate_Desktop_LinuxEncoder_LastError(&g_session), "second X11 connection") != NULL, "and says why");
    snprintf(pDesktop->sDisplay, sizeof(pDesktop->sDisplay), "%s", sSaved);

    DirectGate_Desktop_Clear(pDesktop);
    return 0;
}

/* A 16-bit screen: nothing the H.264 capture can take, so the stream steps
   down to raw RGBA and says why, and the raw path unpacks 5-6-5 pixels. */
static int test_shallow(void)
{
    g_pPhase = "16-bit";
    if (start_and_pick(25)) return 1;
    directgate_desktop_t *pDesktop = &g_session.desktop;

    CHECK(pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_RAW && pDesktop->bForceRaw, "a 16-bit screen streams raw");
    CHECK(strcmp(g_sent.sStatus, "streaming") == 0, "and still reports streaming");

    g_nWantRaw = 1;
    CHECK(pump_until(enough_raw, 5000), "the 16-bit screen is captured raw");

    DirectGate_Desktop_Clear(pDesktop);
    return 0;
}

/* A server without RandR has no monitors to list: all displays is the only
   choice, and it cannot take a display mode. */
static int test_no_randr(void)
{
    g_pPhase = "no RandR";
    memset(&g_session, 0, sizeof(g_session));
    memset(&g_sent, 0, sizeof(g_sent));
    g_session.nSessionId = 29;

    setenv("DIRECTGATE_DESKTOP_FORCE_RAW", "1", 1);
    CHECK(DirectGate_Desktop_Start(&g_session) >= 0, "a server without RandR starts");
    unsetenv("DIRECTGATE_DESKTOP_FORCE_RAW");

    directgate_desktop_t *pDesktop = &g_session.desktop;
    CHECK(pDesktop->nMonitorCount == 1 && strcmp(pDesktop->monitors[0].sId, "all") == 0, "only all displays is offered");
    CHECK(control("{\"action\":\"select-monitor\",\"monitorId\":\"all\",\"mode\":\"display\",\"width\":800,\"height\":600}")
        == XAPI_CONTINUE, "ask for a display mode");
    CHECK(pDesktop->eResizeMode == DIRECTGATE_DESKTOP_RESIZE_SCALE && strcmp(g_sent.sStatus, "streaming") == 0,
        "without RandR the stream scales");

    DirectGate_Desktop_Clear(pDesktop);
    return 0;
}

static int write_text(const char *pPath, const char *pText)
{
    int nFd = open(pPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (nFd < 0) return 0;

    ssize_t nLen = (ssize_t)strlen(pText);
    int nOk = write(nFd, pText, (size_t)nLen) == nLen;
    return (close(nFd) == 0) && nOk;
}

/* With no DISPLAY the agent looks in /tmp/.X11-unix. This runs in a child with
   private user and mount namespaces and an empty tmpfs over that directory, so
   the real one - and the displays of whoever runs the test - is never seen. */
static int scan_child(int nDisplay)
{
    g_pPhase = "display scan";
    uid_t nUid = getuid();
    gid_t nGid = getgid();
    if (access("/tmp/.X11-unix", F_OK) != 0 || unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) return 77;

    char sMap[64];
    snprintf(sMap, sizeof(sMap), "%u %u 1\n", (unsigned)nUid, (unsigned)nUid);
    if (!write_text("/proc/self/uid_map", sMap)) return 77;
    snprintf(sMap, sizeof(sMap), "%u %u 1\n", (unsigned)nGid, (unsigned)nGid);
    if (!write_text("/proc/self/setgroups", "deny") || !write_text("/proc/self/gid_map", sMap)) return 77;
    /* "none" rather than NULL, as mount(8) passes: a propagation change ignores both, and valgrind 3.22 (Ubuntu
       24.04's) reports a NULL type as an unaddressable syscall argument */
    if (mount("none", "/", "none", MS_REC | MS_PRIVATE, NULL) != 0) return 77;
    if (mount("tmpfs", "/tmp/.X11-unix", "tmpfs", 0, "mode=1777") != 0) return 77;
    unsetenv("DISPLAY");

    memset(&g_session, 0, sizeof(g_session));
    g_session.nSessionId = 28;
    CHECK(DirectGate_Desktop_Start(&g_session) < 0 && strcmp(g_session.desktop.sBackend, "none") == 0,
        "with no DISPLAY and nothing in /tmp/.X11-unix there is no display");
    DirectGate_Desktop_Clear(&g_session.desktop);

    /* Only the name is read: entries that are not X<n> are passed over. */
    char sEntry[64], sWant[16];
    snprintf(sEntry, sizeof(sEntry), "/tmp/.X11-unix/X%d", nDisplay);
    snprintf(sWant, sizeof(sWant), ":%d", nDisplay);
    CHECK(write_text("/tmp/.X11-unix/X", "") && write_text("/tmp/.X11-unix/README", "") && write_text(sEntry, ""),
        "create the socket stand-ins");

    (void)DirectGate_Desktop_Start(&g_session);
    CHECK(strcmp(g_session.desktop.sDisplay, sWant) == 0, "the display is found by its socket name");
    DirectGate_Desktop_Clear(&g_session.desktop);
    return 0;
}

/* The X server goes away under an open connection: the agent logs why before
   Xlib ends the process. Run in a child, since that end is exit(). */
static int test_connection_lost(xvfb_t *pX)
{
    g_pPhase = "connection lost";
    int toChild[2], toParent[2];
    CHECK(pipe(toChild) == 0 && pipe(toParent) == 0, "create the pipes");

    pid_t nPid = fork();
    CHECK(nPid >= 0, "fork the connection child");
    if (nPid == 0)
    {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        DirectGate_Desktop_InstallX11ErrorHandlers();
        Display *pDisplay = XOpenDisplay(pX->sDisplay);
        if (pDisplay == NULL) exit(3);

        char c = 'r';
        if (write(toParent[1], &c, 1) != 1 || read(toChild[0], &c, 1) != 1) exit(4);
        XNoOp(pDisplay);
        XSync(pDisplay, False);
        exit(0);
    }

    char c = 0;
    CHECK(read(toParent[0], &c, 1) == 1, "the child is connected");
    xvfb_stop(pX);
    CHECK(write(toChild[1], &c, 1) == 1, "tell the child to use the connection");

    int nStatus = 0;
    CHECK(waitpid(nPid, &nStatus, 0) == nPid, "wait for the connection child");
    close(toChild[0]); close(toChild[1]); close(toParent[0]); close(toParent[1]);
    CHECK(WIFEXITED(nStatus) && WEXITSTATUS(nStatus) == 1, "a lost X connection is logged, then Xlib exits");
    return 0;
}

int main(void)
{
    signal(SIGALRM, on_watchdog);
    alarm(170);

    char sXvfb[4096];
    if (!find_xvfb(sXvfb, sizeof(sXvfb)))
    {
        puts("desktop_x11_smoke: no Xvfb (set DIRECTGATE_XVFB or put it on PATH), skipping");
        return 77;
    }

    xvfb_t xvfb;
    if (!xvfb_start(&xvfb, sXvfb, 24, NULL))
    {
        puts("desktop_x11_smoke: Xvfb would not start, skipping");
        return 77;
    }

    /* Only ever the private server, and only ever as X11. */
    setenv("DISPLAY", xvfb.sDisplay, 1);
    setenv("XDG_SESSION_TYPE", "x11", 1);
    unsetenv("WAYLAND_DISPLAY");
    unsetenv("XAUTHORITY");
    unsetenv("DIRECTGATE_DESKTOP_FORCE_RAW");
    unsetenv("DIRECTGATE_DESKTOP_PRESET");

    int nResult = 1;
    Display *pObserver = XOpenDisplay(xvfb.sDisplay);

    if (pObserver == NULL) fprintf(stderr, "desktop_x11_smoke: cannot open %s to observe it\n", xvfb.sDisplay);
    else if (!test_no_display(xvfb.sDisplay) && !test_h264(pObserver) && !test_capture_lost(pObserver) &&
             !test_edges(pObserver) && !test_raw() && !test_input(pObserver))
        nResult = 0;

    if (pObserver != NULL) XCloseDisplay(pObserver);
    xvfb_stop(&xvfb);

    /* The same capture against screens that are not the common 24-bit, shared-memory kind. */
    static const struct { int nDepth; const char *pWithout; int (*pTest)(void); } variants[] = {
        { 30, "MIT-SHM", test_deep_no_shm },
        { 16, NULL, test_shallow },
        { 24, "RANDR", test_no_randr }
    };

    for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]) && !nResult; i++)
    {
        if (!xvfb_start(&xvfb, sXvfb, variants[i].nDepth, variants[i].pWithout))
        {
            fprintf(stderr, "desktop_x11_smoke: Xvfb would not start at depth %d\n", variants[i].nDepth);
            nResult = 1;
            break;
        }

        setenv("DISPLAY", xvfb.sDisplay, 1);
        nResult = variants[i].pTest();
        xvfb_stop(&xvfb);
    }

    /* Finding the display by its socket, and losing it. */
    if (!nResult)
    {
        nResult = !xvfb_start(&xvfb, sXvfb, 24, NULL);
        if (nResult) fprintf(stderr, "desktop_x11_smoke: Xvfb would not start for the last cases\n");
    }

    if (!nResult)
    {
        g_pPhase = "display scan";
        pid_t nPid = fork();
        if (nPid == 0)
        {
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            exit(scan_child(xvfb.nDisplay));
        }

        int nStatus = 0;
        if (nPid < 0 || waitpid(nPid, &nStatus, 0) != nPid || !WIFEXITED(nStatus)) nResult = 1;
        else if (WEXITSTATUS(nStatus) == 77) puts("desktop_x11_smoke: no private mount namespace, display scan not checked");
        else if (WEXITSTATUS(nStatus) != 0) nResult = 1;

        if (!nResult) nResult = test_connection_lost(&xvfb);
        xvfb_stop(&xvfb);
    }

    if (nResult) return 1;
    puts("desktop_x11_smoke: OK");
    return 0;
}
