/*!
 * @file directgate-agent/src/agent/desktop/display.c
 * @brief Agent-side desktop display open, monitor enumeration and mode switching.
 *
 *  Copyright (c) 2025-2026 DirectGate. All rights reserved.
 *  Author: Sandro Kalatozishvili (sandro@directgate.io)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "desktop.h"
#include "session.h"
#include "priv.h"

#if defined(__linux__)
#include <dlfcn.h>
#include <dirent.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/Xrandr.h>
#ifdef DIRECTGATE_DESKTOP_HAS_WAYLAND
#include "common.h"
#include "wayland.h"
#endif
#elif defined(__APPLE__)
#include <stdbool.h>
#include <ApplicationServices/ApplicationServices.h>
#include <Carbon/Carbon.h>
#endif

#if defined(__linux__)

#ifdef DIRECTGATE_DESKTOP_HAS_WAYLAND

/* How long the event loop is held waiting for the portal. Long enough for
 * someone already looking at the prompt to answer it, short enough that the
 * rest of the agent's work is not visibly stalled. */
#define DIRECTGATE_DESKTOP_WAYLAND_WAIT_MS 5000

/* The portal grant belongs to the process, not to one desktop session.
 *
 * A grant that is still waiting on a human must survive the session that
 * asked for it: the prompt is on screen, and tearing the source down when the
 * first attempt gives up would cancel it just as they reach for Allow - and
 * the next attempt would put up a second prompt. So a pending source is
 * parked here, and the next attempt adopts it instead of starting over. */
static directgate_wl_source_t *g_pPendingWayland;

#endif /* DIRECTGATE_DESKTOP_HAS_WAYLAND */

/* Xlib kills the process on an X error unless the application says otherwise:
 * the default protocol-error handler prints and calls exit(), and so does the
 * default I/O-error handler. That is fatal here in the most ordinary
 * circumstances - unplugging a monitor, changing a resolution or switching
 * users races the geometry this pipeline captured, and the next XGetImage /
 * XShmGetImage against the now-invalid rectangle answers BadMatch. Losing the
 * agent takes every other session with it: PTYs, file transfers, the lot.
 *
 * Protocol errors are recoverable - the call that raised one simply fails, and
 * the capture path already handles a failed grab - so log and carry on. The
 * handler is process-wide rather than per-connection, so installing it once
 * covers the capture thread's private display too. */
static uint32_t g_nX11ErrorCount;

static int DirectGate_Desktop_X11ErrorHandler(Display *pDisplay, XErrorEvent *pEvent)
{
    /* Errors arrive in bursts while a monitor is being reconfigured, and this
     * runs on the capture path - keep it to the first few and then one in a
     * hundred so a persistent fault stays visible without flooding the log or
     * costing frames. */
    uint32_t nSeen = ++g_nX11ErrorCount;
    if (nSeen <= 5U || (nSeen % 100U) == 0U)
    {
        char sText[128];
        sText[0] = '\0';
        if (pDisplay != NULL) XGetErrorText(pDisplay, pEvent->error_code, sText, (int)sizeof(sText));

        xlogw("X11 protocol error ignored: code(%u), request(%u.%u), resource(0x%lx), total(%u), text(%s)",
            (unsigned)pEvent->error_code, (unsigned)pEvent->request_code,
            (unsigned)pEvent->minor_code, (unsigned long)pEvent->resourceid,
            nSeen, sText[0] ? sText : "unknown");
    }

    return 0;
}

/* An I/O error means the connection itself is gone (server exit, user logout).
 * Xlib gives no way to return from this - it exits once the handler does - so
 * the only thing worth doing is making sure the reason reaches the log instead
 * of the process dying silently. */
static int DirectGate_Desktop_X11IOErrorHandler(Display *pDisplay)
{
    (void)pDisplay;
    xloge("X11 connection lost; the display server went away");
    return 0;
}

void DirectGate_Desktop_InstallX11ErrorHandlers(void)
{
    static xbool_t bInstalled = XFALSE;
    if (bInstalled) return;

    bInstalled = XTRUE;
    XSetErrorHandler(DirectGate_Desktop_X11ErrorHandler);
    XSetIOErrorHandler(DirectGate_Desktop_X11IOErrorHandler);
}

static void DirectGate_Desktop_EnumerateMonitors(directgate_desktop_t *pDesktop)
{
    Display *pDisplay = (Display*)pDesktop->pDisplay;
    int nScreen = DefaultScreen(pDisplay);
    Window root = RootWindow(pDisplay, nScreen);

    DirectGate_Desktop_AddMonitor(pDesktop, "all", "All displays", 0, 0,
        pDesktop->nScreenWidth, pDesktop->nScreenHeight, XFALSE);

    int nMonitorCount = 0;
    XRRMonitorInfo *pMonitors = XRRGetMonitors(pDisplay, root, XTRUE, &nMonitorCount);
    XRRScreenResources *pResources = XRRGetScreenResourcesCurrent(pDisplay, root);
    if (pMonitors == NULL || nMonitorCount <= 0)
    {
        if (pResources != NULL) XRRFreeScreenResources(pResources);
        return;
    }

    for (int i = 0; i < nMonitorCount && pDesktop->nMonitorCount < DIRECTGATE_DESKTOP_MAX_MONITORS; i++)
    {
        XRRMonitorInfo *pInfo = &pMonitors[i];
        char sId[DIRECTGATE_DESKTOP_MONITOR_ID_LEN];
        char sName[DIRECTGATE_DESKTOP_MONITOR_NAME_LEN];
        char *pAtomName = XGetAtomName(pDisplay, pInfo->name);

        snprintf(sId, sizeof(sId), "monitor-%d", i + 1);
        if (xstrused(pAtomName)) xstrncpy(sName, sizeof(sName), pAtomName);
        else snprintf(sName, sizeof(sName), "Monitor %d", i + 1);

        uint32_t nBefore = pDesktop->nMonitorCount;
        DirectGate_Desktop_AddMonitor(pDesktop, sId, sName, pInfo->x, pInfo->y,
            (uint32_t)pInfo->width, (uint32_t)pInfo->height, pInfo->primary ? XTRUE : XFALSE);

        if (pInfo->noutput > 0 && pDesktop->nMonitorCount > nBefore)
        {
            directgate_desktop_monitor_t *pAdded = &pDesktop->monitors[pDesktop->nMonitorCount - 1U];
            pAdded->nNativeId = (uint64_t)pInfo->outputs[0];
            snprintf(pAdded->sDeviceId, sizeof(pAdded->sDeviceId), "%lu", (unsigned long)pInfo->outputs[0]);

            XRROutputInfo *pOutput = pResources != NULL ? XRRGetOutputInfo(pDisplay, pResources, pInfo->outputs[0]) : NULL;
            if (pOutput != NULL)
            {
                for (int modeIndex = 0; modeIndex < pOutput->nmode; modeIndex++)
                {
                    for (int resourceIndex = 0; resourceIndex < pResources->nmode; resourceIndex++)
                    {
                        const XRRModeInfo *pMode = &pResources->modes[resourceIndex];
                        if (pMode->id != pOutput->modes[modeIndex]) continue;

                        DirectGate_Desktop_AddMonitorMode(pAdded, (uint32_t)pMode->width, (uint32_t)pMode->height);
                        break;
                    }
                }

                XRRFreeOutputInfo(pOutput);
            }
        }

        if (pAtomName != NULL) XFree(pAtomName);
    }

    XRRFreeMonitors(pMonitors);
    if (pResources != NULL) XRRFreeScreenResources(pResources);
}

static void DirectGate_Desktop_RefreshLinuxMonitors(directgate_desktop_t *pDesktop)
{
    Display *pDisplay = (Display*)pDesktop->pDisplay;
    if (pDisplay == NULL) return;

    int nScreen = DefaultScreen(pDisplay);
    Window root = RootWindow(pDisplay, nScreen);
    XWindowAttributes attrs;

    if (XGetWindowAttributes(pDisplay, root, &attrs) && attrs.width > 0 && attrs.height > 0)
    {
        pDesktop->nScreenWidth = (uint32_t)attrs.width;
        pDesktop->nScreenHeight = (uint32_t)attrs.height;
    }

    pDesktop->nMonitorCount = 0;
    memset(pDesktop->monitors, 0, sizeof(pDesktop->monitors));
    DirectGate_Desktop_EnumerateMonitors(pDesktop);
}

static RRMode DirectGate_Desktop_ClosestXrandrMode(const XRRScreenResources *pResources,
                                                    const XRROutputInfo *pOutput,
                                                    uint32_t nWidth, uint32_t nHeight)
{
    RRMode nBest = None;
    uint64_t nBestScore = UINT64_MAX;
    if (pResources == NULL || pOutput == NULL) return None;

    for (int i = 0; i < pOutput->nmode; i++)
    {
        const XRRModeInfo *pMode = NULL;
        for (int j = 0; j < pResources->nmode; j++)
        {
            if (pResources->modes[j].id == pOutput->modes[i])
            {
                pMode = &pResources->modes[j];
                break;
            }
        }

        if (pMode == NULL) continue;
        uint64_t nDx = pMode->width > nWidth ? pMode->width - nWidth : nWidth - pMode->width;
        uint64_t nDy = pMode->height > nHeight ? pMode->height - nHeight : nHeight - pMode->height;
        uint64_t nAspect = (uint64_t)llabs((long long)pMode->width * nHeight - (long long)nWidth * pMode->height);
        uint64_t nScore = (nDx + nDy) * 1000000ULL + nAspect;

        if (nScore < nBestScore)
        {
            nBestScore = nScore;
            nBest = pMode->id;
        }
    }

    return nBest;
}

int DirectGate_Desktop_SetDisplayResolution(directgate_desktop_t *pDesktop,
                                            const directgate_desktop_monitor_t *pMonitor,
                                            uint32_t nWidth, uint32_t nHeight)
{
#ifdef DIRECTGATE_DESKTOP_HAS_WAYLAND
    /* Checked before anything else: on a Wayland session nNativeId is the
     * PipeWire node the portal granted, not an XRandR output, so it must
     * never reach the calls below and the portal offers no way to change a
     * display mode in any case. */
    if (pDesktop != NULL && pDesktop->pWayland != NULL)
    {
        DirectGate_Desktop_SetReason(pDesktop,
            "This desktop cannot have its resolution changed from here: Wayland "
            "leaves display modes to the compositor. The picture is scaled instead.");

        return XSTDERR;
    }
#endif

    Display *pDisplay = (Display*)pDesktop->pDisplay;
    if (pDisplay == NULL || pMonitor == NULL || pMonitor->nNativeId == 0U)
    {
        DirectGate_Desktop_SetReason(pDesktop,
            "Display mode requires one physical monitor; All displays cannot be resized.");
        return XSTDERR;
    }

    Window root = RootWindow(pDisplay, DefaultScreen(pDisplay));
    XRRScreenResources *pResources = XRRGetScreenResourcesCurrent(pDisplay, root);
    if (pResources == NULL)
    {
        DirectGate_Desktop_SetReason(pDesktop, "Failed to read XRandR display modes.");
        return XSTDERR;
    }

    XRROutputInfo *pOutput = XRRGetOutputInfo(pDisplay, pResources, (RROutput)pMonitor->nNativeId);
    XRRCrtcInfo *pCrtc = (pOutput != NULL && pOutput->crtc != None) ? XRRGetCrtcInfo(pDisplay, pResources, pOutput->crtc) : NULL;
    RRMode nMode = DirectGate_Desktop_ClosestXrandrMode(pResources, pOutput, nWidth, nHeight);

    if (pOutput == NULL || pCrtc == NULL || nMode == None)
    {
        if (pCrtc != NULL) XRRFreeCrtcInfo(pCrtc);
        if (pOutput != NULL) XRRFreeOutputInfo(pOutput);

        XRRFreeScreenResources(pResources);
        DirectGate_Desktop_SetReason(pDesktop, "No usable XRandR mode is available for this monitor.");

        return XSTDERR;
    }

    if (!pDesktop->bDisplayModeChanged)
    {
        pDesktop->nOriginalModeId = (uint64_t)pCrtc->mode;
        pDesktop->nOriginalModeX = pCrtc->x;
        pDesktop->nOriginalModeY = pCrtc->y;
        pDesktop->nOriginalModeRotation = (uint32_t)pCrtc->rotation;
        pDesktop->nModeNativeId = (uint64_t)pOutput->crtc;
        xstrncpy(pDesktop->sModeMonitorId, sizeof(pDesktop->sModeMonitorId), pMonitor->sId);
        xstrncpy(pDesktop->sModeDeviceId, sizeof(pDesktop->sModeDeviceId), pMonitor->sDeviceId);
    }

    Status nStatus = XRRSetCrtcConfig(pDisplay, pResources, pOutput->crtc, CurrentTime,
        pCrtc->x, pCrtc->y, nMode, pCrtc->rotation, pCrtc->outputs, pCrtc->noutput);

    XRRFreeCrtcInfo(pCrtc);
    XRRFreeOutputInfo(pOutput);
    XRRFreeScreenResources(pResources);

    if (nStatus != Success)
    {
        DirectGate_Desktop_SetReason(pDesktop, "XRandR rejected the requested display mode.");
        return XSTDERR;
    }

    pDesktop->bDisplayModeChanged = XTRUE;
    XSync(pDisplay, XFALSE);
    DirectGate_Desktop_RefreshLinuxMonitors(pDesktop);

    return XSTDOK;
}

void DirectGate_Desktop_RestoreDisplayMode(directgate_desktop_t *pDesktop)
{
    Display *pDisplay = pDesktop != NULL ? (Display*)pDesktop->pDisplay : NULL;
    if (pDisplay == NULL || !pDesktop->bDisplayModeChanged) return;

    Window root = RootWindow(pDisplay, DefaultScreen(pDisplay));
    XRRScreenResources *pResources = XRRGetScreenResourcesCurrent(pDisplay, root);
    XRRCrtcInfo *pCrtc = pResources != NULL ? XRRGetCrtcInfo(pDisplay, pResources, (RRCrtc)pDesktop->nModeNativeId) : NULL;

    if (pResources != NULL && pCrtc != NULL)
    {
        (void)XRRSetCrtcConfig(pDisplay, pResources, (RRCrtc)pDesktop->nModeNativeId,
            CurrentTime, pDesktop->nOriginalModeX, pDesktop->nOriginalModeY,
            (RRMode)pDesktop->nOriginalModeId, (Rotation)pDesktop->nOriginalModeRotation,
            pCrtc->outputs, pCrtc->noutput);

        XSync(pDisplay, XFALSE);
    }

    if (pCrtc != NULL) XRRFreeCrtcInfo(pCrtc);
    if (pResources != NULL) XRRFreeScreenResources(pResources);

    pDesktop->bDisplayModeChanged = XFALSE;
    pDesktop->nModeNativeId = 0U;
    pDesktop->nOriginalModeId = 0U;
    DirectGate_Desktop_RefreshLinuxMonitors(pDesktop);
}

static void DirectGate_Desktop_LoadXTest(directgate_desktop_t *pDesktop)
{
    pDesktop->pXtst = dlopen("libXtst.so.6", RTLD_LAZY | RTLD_LOCAL);
    if (pDesktop->pXtst == NULL)
    {
        xlogw("Desktop input disabled: libXtst.so.6 not found");
        xstrncpy(pDesktop->sInputReason, sizeof(pDesktop->sInputReason),
            "Remote control is disabled: the XTest library (libXtst) is not "
            "installed on this host. Install it and restart the agent.");
        return;
    }

    pDesktop->pFakeMotion = dlsym(pDesktop->pXtst, "XTestFakeMotionEvent");
    pDesktop->pFakeRelativeMotion = dlsym(pDesktop->pXtst, "XTestFakeRelativeMotionEvent");
    pDesktop->pFakeButton = dlsym(pDesktop->pXtst, "XTestFakeButtonEvent");
    pDesktop->pFakeKey = dlsym(pDesktop->pXtst, "XTestFakeKeyEvent");

    pDesktop->bInputReady = (pDesktop->pFakeMotion != NULL &&
                            pDesktop->pFakeButton != NULL &&
                            pDesktop->pFakeKey != NULL);

    if (!pDesktop->bInputReady)
    {
        xlogw("Desktop input disabled: XTest symbols are unavailable");
        xstrncpy(pDesktop->sInputReason, sizeof(pDesktop->sInputReason),
            "Remote control is disabled: the XTest extension is unavailable "
            "on this host's X server.");
    }
}

static const char* DirectGate_Desktop_FindX11Display(char *pBuf, size_t nBufSize)
{
    const char *pEnvDisplay = getenv("DISPLAY");
    if (xstrused(pEnvDisplay)) return pEnvDisplay;

    DIR *pDir = opendir("/tmp/.X11-unix");
    if (pDir == NULL) return NULL;

    struct dirent *pEntry = NULL;
    while ((pEntry = readdir(pDir)) != NULL)
    {
        if (pEntry->d_name[0] != 'X' || !pEntry->d_name[1]) continue;

        xstrncpy(pBuf, nBufSize, ":");
        strncat(pBuf, pEntry->d_name + 1, nBufSize - strlen(pBuf) - 1U);
        break;
    }

    closedir(pDir);
    return xstrused(pBuf) ? pBuf : NULL;
}

static xbool_t DirectGate_Desktop_SessionIsWayland(void)
{
    const char *pSessionType = getenv("XDG_SESSION_TYPE");
    if (xstrused(pSessionType)) return xstrcmp(pSessionType, "wayland") ? XTRUE : XFALSE;
    if (xstrused(getenv("WAYLAND_DISPLAY"))) return XTRUE;

    const char *pRuntimeDir = getenv("XDG_RUNTIME_DIR");
    if (!xstrused(pRuntimeDir)) return XFALSE;

    for (int i = 0; i < 4; i++)
    {
        char sSocket[XPATH_MAX];
        snprintf(sSocket, sizeof(sSocket), "%s/wayland-%d", pRuntimeDir, i);
        if (access(sSocket, F_OK) == 0) return XTRUE;
    }

    return XFALSE;
}

#ifdef DIRECTGATE_DESKTOP_HAS_WAYLAND

/* Where the permission token that skips the prompt on a reconnect is kept. */
static void DirectGate_Desktop_WaylandTokenPath(char *pBuf, size_t nSize)
{
    char sHome[XPATH_MAX];
    DirectGate_GetHomeDir(sHome, sizeof(sHome));
    pBuf[0] = '\0';

    /* A home path long enough to leave no room for the file name would give a
     * silently truncated one, which is worse than having no token at all. */
    if (xstrused(sHome) && strlen(sHome) + sizeof("/.config/directgate/wayland.token") <= nSize)
        snprintf(pBuf, nSize, "%s/.config/directgate/wayland.token", sHome);
}

/* Everything that follows a granted portal session: geometry, the monitor
 * list, and whether input came with it. Reached either from the start, when
 * the grant was already stored or answered quickly, or from the tick that
 * was waiting for someone to answer the prompt. */
static int DirectGate_Desktop_FinishWayland(directgate_session_t *pSession,
                                            directgate_wl_source_t *pSource)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;

    uint32_t nWidth = 0, nHeight = 0;
    if (!DirectGate_WL_SourceSize(pSource, &nWidth, &nHeight) || nWidth == 0 || nHeight == 0)
    {
        DirectGate_Desktop_SetReason(pDesktop, "The Wayland desktop stream reported no size.");
        DirectGate_WL_SourceDestroy(pSource);
        g_pPendingWayland = NULL;
        return XSTDERR;
    }

    /* Ownership moves to the session now that it is usable; ending that
     * session is what closes the portal grant. */
    g_pPendingWayland = NULL;
    pDesktop->pWayland = pSource;
    pDesktop->nScreenWidth = nWidth;
    pDesktop->nScreenHeight = nHeight;
    xstrncpy(pDesktop->sDisplay, sizeof(pDesktop->sDisplay), "wayland");

    /* One entry per screen the person allowed. The portal never volunteers a
     * screen they did not pick, so this list is the grant, not the hardware -
     * a second monitor appears here only once it has been shared. */
    uint32_t nScreens = DirectGate_WL_SourceScreenCount(pSource);

    for (uint32_t i = 0; i < nScreens; i++)
    {
        const directgate_wl_stream_t *pStream = DirectGate_WL_SourceScreen(pSource, i);
        if (pStream == NULL) continue;

        char sId[DIRECTGATE_DESKTOP_MONITOR_ID_LEN];
        char sName[DIRECTGATE_DESKTOP_MONITOR_NAME_LEN];

        snprintf(sId, sizeof(sId), "wayland-%u", pStream->nNodeId);
        if (nScreens > 1) snprintf(sName, sizeof(sName), "Shared screen %u", i + 1U);
        else xstrncpy(sName, sizeof(sName), "Shared screen");

        /* Fall back to the negotiated size when the compositor did not say. */
        uint32_t nScreenW = pStream->nWidth ? pStream->nWidth : nWidth;
        uint32_t nScreenH = pStream->nHeight ? pStream->nHeight : nHeight;

        uint32_t nBefore = pDesktop->nMonitorCount;
        DirectGate_Desktop_AddMonitor(pDesktop, sId, sName, pStream->nX, pStream->nY, nScreenW, nScreenH, i == 0 ? XTRUE : XFALSE);

        /* The node id is what selecting this entry has to switch the capture
         * to, so it travels with the monitor rather than being re-derived. */
        if (pDesktop->nMonitorCount > nBefore)
            pDesktop->monitors[pDesktop->nMonitorCount - 1U].nNativeId = pStream->nNodeId;
    }

    if (!nScreens) DirectGate_Desktop_AddMonitor(pDesktop, "wayland-0", "Shared screen", 0, 0, nWidth, nHeight, XTRUE);
    xlogi("Wayland desktop offers %u shared screen(s)", nScreens ? nScreens : 1U);

    /* Nothing else sets this on Wayland: the X11 path raises it when XTest
     * loads, and there is no XTest here. Without it the session reports that
     * it has no input and the viewer refuses to send any - which is what
     * "remote control is disabled" means. */
    pDesktop->bInputReady = DirectGate_WL_SourceHasInput(pSource);
    if (!pDesktop->bInputReady)
    {
        DirectGate_Desktop_SetFallbackReason(pDesktop,
            "Remote control is disabled: this desktop portal shared the screen "
            "but did not grant keyboard and pointer control.");

        xlogw("Wayland desktop granted capture without input; the session is view-only");
    }

    xlogi("Wayland desktop capture is ready: size(%ux%u), input(%s)",
        nWidth, nHeight, pDesktop->bInputReady ? "yes" : "no");

    return XSTDOK;
}

/* Brings up the Wayland backend, or reports that it is not up yet.
 *
 * The grant is negotiated on the source's own thread, because it waits for a
 * person. This only blocks for as long as it is reasonable to hold the
 * agent's event loop - a stored grant completes far inside that, and so does
 * a prompt someone is already looking at.
 *
 * XSTDNON means the prompt is still on their screen. That is not a failure:
 * the source keeps waiting on its own thread and the session waits with it,
 * which is the whole point - the answer arrives minutes later, long after any
 * call could have stayed here for it. */
static int DirectGate_Desktop_OpenWayland(directgate_session_t *pSession)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;
    xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "wayland");

    if (g_pPendingWayland == NULL)
    {
        char sTokenPath[XPATH_MAX + 64];
        DirectGate_Desktop_WaylandTokenPath(sTokenPath, sizeof(sTokenPath));

        g_pPendingWayland = DirectGate_WL_SourceCreate(sTokenPath);
        if (g_pPendingWayland == NULL)
        {
            DirectGate_Desktop_SetReason(pDesktop, "Failed to start Wayland desktop capture.");
            return XSTDERR;
        }
    }

    directgate_wl_source_t *pSource = g_pPendingWayland;

    for (int i = 0; i < DIRECTGATE_DESKTOP_WAYLAND_WAIT_MS / 100 &&
         DirectGate_WL_SourceState(pSource) == DIRECTGATE_WL_PENDING; i++)
    {
        xusleep(100000);
    }

    directgate_wl_state_t eState = DirectGate_WL_SourceState(pSource);
    if (eState == DIRECTGATE_WL_FAILED)
    {
        DirectGate_Desktop_SetReason(pDesktop, DirectGate_WL_SourceError(pSource));

        /* A refusal is final for this grant; the next attempt starts a new
         * one rather than reporting the same failure forever. */
        DirectGate_WL_SourceDestroy(pSource);
        g_pPendingWayland = NULL;

        return XSTDERR;
    }

    if (eState == DIRECTGATE_WL_PENDING)
    {
        DirectGate_Desktop_SetReason(pDesktop,
            "Waiting for screen sharing to be allowed on the remote computer. "
            "Allow it there and this screen starts on its own.");

        xlogi("Wayland desktop capture is still waiting for permission");
        return XSTDNON;
    }

    return DirectGate_Desktop_FinishWayland(pSession, pSource);
}

/* Called from the tick while the prompt is unanswered. XSTDNON keeps waiting,
 * XSTDOK means the desktop is up, XSTDERR that the grant will never come. */
int DirectGate_Desktop_ResumeWayland(directgate_session_t *pSession)
{
    XCHECK((pSession != NULL), XSTDERR);
    directgate_desktop_t *pDesktop = &pSession->desktop;

    directgate_wl_source_t *pSource = g_pPendingWayland;
    if (pSource == NULL)
    {
        DirectGate_Desktop_SetReason(pDesktop, "The Wayland desktop grant was dropped.");
        return XSTDERR;
    }

    directgate_wl_state_t eState = DirectGate_WL_SourceState(pSource);
    if (eState == DIRECTGATE_WL_PENDING) return XSTDNON;

    if (eState == DIRECTGATE_WL_FAILED)
    {
        DirectGate_Desktop_SetReason(pDesktop, DirectGate_WL_SourceError(pSource));
        DirectGate_WL_SourceDestroy(pSource);
        g_pPendingWayland = NULL;

        return XSTDERR;
    }

    return DirectGate_Desktop_FinishWayland(pSession, pSource);
}
#endif

static void DirectGate_Desktop_SetXAuthority(const directgate_session_t *pSession)
{
    if (xstrused(getenv("XAUTHORITY"))) return;
    if (pSession == NULL || pSession->pCfg == NULL ||
        !xstrused(pSession->pCfg->sShellHome)) return;

    char sPath[XPATH_MAX + XSTR_MICRO];
    if (strlen(pSession->pCfg->sShellHome) + sizeof("/.Xauthority") > sizeof(sPath))
        return;

    snprintf(sPath, sizeof(sPath), "%s/.Xauthority", pSession->pCfg->sShellHome);
    if (access(sPath, R_OK) == 0) setenv("XAUTHORITY", sPath, 0);
}

int DirectGate_Desktop_OpenX11(directgate_session_t *pSession)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (DirectGate_Desktop_SessionIsWayland())
    {
#ifdef DIRECTGATE_DESKTOP_HAS_WAYLAND
        return DirectGate_Desktop_OpenWayland(pSession);
#else
        xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "wayland");
        DirectGate_Desktop_SetReason(pDesktop,
            "This agent was built without Wayland desktop streaming. "
            "Log in with an Xorg session to stream this desktop.");

        return XSTDERR;
#endif
    }

    char sDisplay[DIRECTGATE_DESKTOP_DISPLAY_LEN];
    memset(sDisplay, 0, sizeof(sDisplay));
    const char *pDisplayName = DirectGate_Desktop_FindX11Display(sDisplay, sizeof(sDisplay));

    if (!xstrused(pDisplayName))
    {
        xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "none");
        DirectGate_Desktop_SetReason(pDesktop,
            "No display is available on this host. Headless servers without "
            "a graphical session cannot stream a desktop.");

        return XSTDERR;
    }

    XInitThreads();
    DirectGate_Desktop_InstallX11ErrorHandlers();
    DirectGate_Desktop_SetXAuthority(pSession);

    Display *pDisplay = XOpenDisplay(pDisplayName);
    if (pDisplay == NULL)
    {
        xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "x11");
        xstrncpy(pDesktop->sDisplay, sizeof(pDesktop->sDisplay), pDisplayName);
        DirectGate_Desktop_SetReason(pDesktop, "Failed to open X11 display. Check DISPLAY and XAUTHORITY for the directgate service user.");
        return XSTDERR;
    }

    int nScreen = DefaultScreen(pDisplay);
    Window root = RootWindow(pDisplay, nScreen);
    XWindowAttributes attrs;

    if (!XGetWindowAttributes(pDisplay, root, &attrs) || attrs.width <= 0 || attrs.height <= 0)
    {
        XCloseDisplay(pDisplay);
        xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "x11");
        xstrncpy(pDesktop->sDisplay, sizeof(pDesktop->sDisplay), pDisplayName);
        DirectGate_Desktop_SetReason(pDesktop, "Failed to read X11 root window size.");
        return XSTDERR;
    }

    pDesktop->pDisplay = pDisplay;
    pDesktop->nScreenWidth = (uint32_t)attrs.width;
    pDesktop->nScreenHeight = (uint32_t)attrs.height;

    xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "x11");
    xstrncpy(pDesktop->sDisplay, sizeof(pDesktop->sDisplay), pDisplayName);

    DirectGate_Desktop_EnumerateMonitors(pDesktop);
    DirectGate_Desktop_LoadXTest(pDesktop);

    return XSTDOK;
}

#elif defined(__APPLE__)

static uint32_t DirectGate_Desktop_RectWidth(CGRect rect)
{
    return rect.size.width > 0 ? (uint32_t)ceil(rect.size.width) : 0;
}

static uint32_t DirectGate_Desktop_RectHeight(CGRect rect)
{
    return rect.size.height > 0 ? (uint32_t)ceil(rect.size.height) : 0;
}

static void DirectGate_Desktop_AddMacModes(directgate_desktop_monitor_t *pMonitor,
                                           CGDirectDisplayID nDisplay)
{
    CFArrayRef pModes = CGDisplayCopyAllDisplayModes(nDisplay, NULL);
    if (pModes == NULL) return;

    CFIndex nCount = CFArrayGetCount(pModes);
    for (CFIndex i = 0; i < nCount; i++)
    {
        CGDisplayModeRef pMode = (CGDisplayModeRef)CFArrayGetValueAtIndex(pModes, i);
        DirectGate_Desktop_AddMonitorMode(pMonitor,
            (uint32_t)CGDisplayModeGetWidth(pMode),
            (uint32_t)CGDisplayModeGetHeight(pMode));
    }

    CFRelease(pModes);
}

int DirectGate_Desktop_OpenMacOS(directgate_session_t *pSession)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;
    CGDirectDisplayID displays[DIRECTGATE_DESKTOP_MAX_MONITORS];
    uint32_t nDisplayCount = 0;

    CGError err = CGGetActiveDisplayList(DIRECTGATE_DESKTOP_MAX_MONITORS, displays, &nDisplayCount);
    if (err != kCGErrorSuccess || nDisplayCount == 0)
    {
        xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "macos");
        DirectGate_Desktop_SetReason(pDesktop, "No active macOS display is available.");
        return XSTDERR;
    }

    CGRect unionRect = CGRectNull;
    for (uint32_t i = 0; i < nDisplayCount; i++)
    {
        CGRect rect = CGDisplayBounds(displays[i]);
        unionRect = CGRectIsNull(unionRect) ? rect : CGRectUnion(unionRect, rect);
    }

    if (CGRectIsNull(unionRect) ||
        DirectGate_Desktop_RectWidth(unionRect) == 0 ||
        DirectGate_Desktop_RectHeight(unionRect) == 0)
    {
        xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "macos");
        DirectGate_Desktop_SetReason(pDesktop, "Failed to read macOS display bounds.");
        return XSTDERR;
    }

    pDesktop->nScreenWidth = DirectGate_Desktop_RectWidth(unionRect);
    pDesktop->nScreenHeight = DirectGate_Desktop_RectHeight(unionRect);
    xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "macos");
    xstrncpy(pDesktop->sDisplay, sizeof(pDesktop->sDisplay), "CoreGraphics");

    DirectGate_Desktop_AddMonitor(pDesktop, "all", "All displays",
        (int32_t)floor(unionRect.origin.x), (int32_t)floor(unionRect.origin.y),
        DirectGate_Desktop_RectWidth(unionRect),
        DirectGate_Desktop_RectHeight(unionRect), XFALSE);

    for (uint32_t i = 0; i < nDisplayCount && pDesktop->nMonitorCount < DIRECTGATE_DESKTOP_MAX_MONITORS; i++)
    {
        CGRect rect = CGDisplayBounds(displays[i]);
        char sId[DIRECTGATE_DESKTOP_MONITOR_ID_LEN];
        char sName[DIRECTGATE_DESKTOP_MONITOR_NAME_LEN];

        snprintf(sId, sizeof(sId), "display-%u", i + 1);
        snprintf(sName, sizeof(sName), "Display %u", i + 1);

        DirectGate_Desktop_AddMonitor(pDesktop, sId, sName,
            (int32_t)floor(rect.origin.x), (int32_t)floor(rect.origin.y),
            DirectGate_Desktop_RectWidth(rect), DirectGate_Desktop_RectHeight(rect),
            CGDisplayIsMain(displays[i]) ? XTRUE : XFALSE);

        directgate_desktop_monitor_t *pAdded = &pDesktop->monitors[pDesktop->nMonitorCount - 1U];
        pAdded->nNativeId = (uint64_t)displays[i];
        snprintf(pAdded->sDeviceId, sizeof(pAdded->sDeviceId), "%u", displays[i]);
        DirectGate_Desktop_AddMacModes(pAdded, displays[i]);
    }

#if defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && __MAC_OS_X_VERSION_MAX_ALLOWED >= 101500
    if (!CGPreflightScreenCaptureAccess())
    {
        xlogw("macOS desktop capture requires Screen Recording permission for directgate");
        DirectGate_Desktop_SetReason(pDesktop,
            "macOS requires Screen Recording permission for desktop streaming. "
            "Grant it to the DirectGate agent process in System Settings > Privacy & Security > Screen Recording, "
            "then restart the agent.");
        if (!CGRequestScreenCaptureAccess())
        {
            xlogw("macOS Screen Recording permission was not granted for directgate");
            return XSTDERR;
        }
    }
#endif

    pDesktop->bInputReady = AXIsProcessTrusted() ? XTRUE : XFALSE;
    if (!pDesktop->bInputReady)
    {
        xlogw("macOS desktop input disabled: grant Accessibility permission to directgate");
        xstrncpy(pDesktop->sInputReason, sizeof(pDesktop->sInputReason),
            "macOS blocks remote control until the DirectGate agent has Accessibility "
            "permission. Grant it in System Settings > Privacy & Security > Accessibility.");

        /* Fire the system permission prompt so the person at the host (or the
         * remote user watching the stream) sees the request immediately.
         * Input recovers without a restart: the input handler rechecks
         * AXIsProcessTrusted once the permission is granted. */
        const void *pKeys[] = { (const void*)kAXTrustedCheckOptionPrompt };
        const void *pValues[] = { (const void*)kCFBooleanTrue };
        CFDictionaryRef pOptions = CFDictionaryCreate(kCFAllocatorDefault, pKeys, pValues, 1,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (pOptions != NULL)
        {
            (void)AXIsProcessTrustedWithOptions(pOptions);
            CFRelease(pOptions);
        }
    }

    return XSTDOK;
}

static void DirectGate_Desktop_RefreshMacMonitors(directgate_desktop_t *pDesktop)
{
    CGDirectDisplayID displays[DIRECTGATE_DESKTOP_MAX_MONITORS];
    uint32_t nDisplayCount = 0;

    if (CGGetActiveDisplayList(DIRECTGATE_DESKTOP_MAX_MONITORS, displays,
        &nDisplayCount) != kCGErrorSuccess || nDisplayCount == 0) return;

    CGRect unionRect = CGRectNull;
    for (uint32_t i = 0; i < nDisplayCount; i++)
    {
        CGRect rect = CGDisplayBounds(displays[i]);
        unionRect = CGRectIsNull(unionRect) ? rect : CGRectUnion(unionRect, rect);
    }

    memset(pDesktop->monitors, 0, sizeof(pDesktop->monitors));
    pDesktop->nScreenWidth = DirectGate_Desktop_RectWidth(unionRect);
    pDesktop->nScreenHeight = DirectGate_Desktop_RectHeight(unionRect);
    pDesktop->nMonitorCount = 0;

    DirectGate_Desktop_AddMonitor(pDesktop, "all", "All displays",
        (int32_t)floor(unionRect.origin.x), (int32_t)floor(unionRect.origin.y),
        DirectGate_Desktop_RectWidth(unionRect), DirectGate_Desktop_RectHeight(unionRect), XFALSE);

    for (uint32_t i = 0; i < nDisplayCount && pDesktop->nMonitorCount < DIRECTGATE_DESKTOP_MAX_MONITORS; i++)
    {
        CGRect rect = CGDisplayBounds(displays[i]);
        char sId[DIRECTGATE_DESKTOP_MONITOR_ID_LEN];
        char sName[DIRECTGATE_DESKTOP_MONITOR_NAME_LEN];
        snprintf(sId, sizeof(sId), "display-%u", i + 1U);
        snprintf(sName, sizeof(sName), "Display %u", i + 1U);

        DirectGate_Desktop_AddMonitor(pDesktop, sId, sName,
            (int32_t)floor(rect.origin.x), (int32_t)floor(rect.origin.y),
            DirectGate_Desktop_RectWidth(rect), DirectGate_Desktop_RectHeight(rect),
            CGDisplayIsMain(displays[i]) ? XTRUE : XFALSE);

        directgate_desktop_monitor_t *pAdded = &pDesktop->monitors[pDesktop->nMonitorCount - 1U];
        pAdded->nNativeId = (uint64_t)displays[i];
        snprintf(pAdded->sDeviceId, sizeof(pAdded->sDeviceId), "%u", displays[i]);
        DirectGate_Desktop_AddMacModes(pAdded, displays[i]);
    }
}

int DirectGate_Desktop_SetDisplayResolution(directgate_desktop_t *pDesktop,
                                            const directgate_desktop_monitor_t *pMonitor,
                                            uint32_t nWidth, uint32_t nHeight)
{
    if (pMonitor == NULL || pMonitor->nNativeId == 0U)
    {
        DirectGate_Desktop_SetReason(pDesktop,
            "Display mode requires one physical monitor; All displays cannot be resized.");
        return XSTDERR;
    }

    CGDirectDisplayID nDisplay = (CGDirectDisplayID)pMonitor->nNativeId;
    CGDisplayModeRef pCurrent = CGDisplayCopyDisplayMode(nDisplay);
    CFArrayRef pModes = CGDisplayCopyAllDisplayModes(nDisplay, NULL);

    if (pCurrent == NULL || pModes == NULL)
    {
        if (pCurrent != NULL) CGDisplayModeRelease(pCurrent);
        if (pModes != NULL) CFRelease(pModes);
        DirectGate_Desktop_SetReason(pDesktop, "Failed to read macOS display modes.");
        return XSTDERR;
    }

    CGDisplayModeRef pBest = NULL;
    uint64_t nBestScore = UINT64_MAX;
    CFIndex nCount = CFArrayGetCount(pModes);

    for (CFIndex i = 0; i < nCount; i++)
    {
        CGDisplayModeRef pMode = (CGDisplayModeRef)CFArrayGetValueAtIndex(pModes, i);
        uint32_t nModeWidth = (uint32_t)CGDisplayModeGetWidth(pMode);
        uint32_t nModeHeight = (uint32_t)CGDisplayModeGetHeight(pMode);
        uint64_t nDx = nModeWidth > nWidth ? nModeWidth - nWidth : nWidth - nModeWidth;
        uint64_t nDy = nModeHeight > nHeight ? nModeHeight - nHeight : nHeight - nModeHeight;
        uint64_t nAspect = (uint64_t)llabs((long long)nModeWidth * nHeight - (long long)nWidth * nModeHeight);
        uint64_t nScore = (nDx + nDy) * 1000000ULL + nAspect;

        if (nScore < nBestScore)
        {
            nBestScore = nScore;
            pBest = pMode;
        }
    }

    if (pBest != NULL) CGDisplayModeRetain(pBest);
    CFRelease(pModes);

    if (pBest == NULL || CGDisplaySetDisplayMode(nDisplay, pBest, NULL) != kCGErrorSuccess)
    {
        if (pBest != NULL) CGDisplayModeRelease(pBest);
        CGDisplayModeRelease(pCurrent);
        DirectGate_Desktop_SetReason(pDesktop, "macOS rejected the requested display mode.");
        return XSTDERR;
    }

    CGDisplayModeRelease(pBest);

    if (!pDesktop->bDisplayModeChanged)
    {
        pDesktop->pOriginalDisplayMode = pCurrent;
        pDesktop->nModeNativeId = (uint64_t)nDisplay;
        xstrncpy(pDesktop->sModeMonitorId, sizeof(pDesktop->sModeMonitorId), pMonitor->sId);
    }
    else
    {
        CGDisplayModeRelease(pCurrent);
    }

    pDesktop->bDisplayModeChanged = XTRUE;
    DirectGate_Desktop_RefreshMacMonitors(pDesktop);
    return XSTDOK;
}

void DirectGate_Desktop_RestoreDisplayMode(directgate_desktop_t *pDesktop)
{
    if (pDesktop == NULL || !pDesktop->bDisplayModeChanged ||
        pDesktop->pOriginalDisplayMode == NULL) return;

    CGDisplayModeRef pMode = (CGDisplayModeRef)pDesktop->pOriginalDisplayMode;
    (void)CGDisplaySetDisplayMode((CGDirectDisplayID)pDesktop->nModeNativeId, pMode, NULL);
    CGDisplayModeRelease(pMode);

    pDesktop->pOriginalDisplayMode = NULL;
    pDesktop->bDisplayModeChanged = XFALSE;
    pDesktop->nModeNativeId = 0U;
    DirectGate_Desktop_RefreshMacMonitors(pDesktop);
}

#elif defined(_WIN32)

static void DirectGate_Desktop_AddWindowsModes(directgate_desktop_monitor_t *pMonitor)
{
    DEVMODEA current;
    memset(&current, 0, sizeof(current));
    current.dmSize = sizeof(current);
    if (!EnumDisplaySettingsExA(pMonitor->sDeviceId, ENUM_CURRENT_SETTINGS, &current, 0)) return;

    for (DWORD i = 0;; i++)
    {
        DEVMODEA candidate;
        memset(&candidate, 0, sizeof(candidate));
        candidate.dmSize = sizeof(candidate);

        if (!EnumDisplaySettingsExA(pMonitor->sDeviceId, i, &candidate, 0)) break;
        if (candidate.dmBitsPerPel != current.dmBitsPerPel) continue;

        DirectGate_Desktop_AddMonitorMode(pMonitor, candidate.dmPelsWidth, candidate.dmPelsHeight);
    }
}

static BOOL CALLBACK DirectGate_Desktop_MonitorEnumProc(HMONITOR hMonitor, HDC hDC,
                                                        LPRECT pRect, LPARAM lParam)
{
    (void)hDC;
    (void)pRect;
    directgate_desktop_t *pDesktop = (directgate_desktop_t*)lParam;

    MONITORINFOEXA info;
    memset(&info, 0, sizeof(info));
    info.cbSize = sizeof(info);
    if (!GetMonitorInfoA(hMonitor, (LPMONITORINFO)&info)) return TRUE;

    char sId[DIRECTGATE_DESKTOP_MONITOR_ID_LEN];
    char sName[DIRECTGATE_DESKTOP_MONITOR_NAME_LEN];
    uint32_t nIndex = pDesktop->nMonitorCount; /* slot 0 is "all" */
    snprintf(sId, sizeof(sId), "display-%u", nIndex);
    snprintf(sName, sizeof(sName), "Display %u", nIndex);

    DirectGate_Desktop_AddMonitor(pDesktop, sId, sName,
        (int32_t)info.rcMonitor.left, (int32_t)info.rcMonitor.top,
        (uint32_t)(info.rcMonitor.right - info.rcMonitor.left),
        (uint32_t)(info.rcMonitor.bottom - info.rcMonitor.top),
        (info.dwFlags & MONITORINFOF_PRIMARY) ? XTRUE : XFALSE);

    directgate_desktop_monitor_t *pAdded = &pDesktop->monitors[pDesktop->nMonitorCount - 1U];
    xstrncpy(pAdded->sDeviceId, sizeof(pAdded->sDeviceId), info.szDevice);
    pAdded->nNativeId = (uint64_t)(uintptr_t)hMonitor;
    DirectGate_Desktop_AddWindowsModes(pAdded);

    return (pDesktop->nMonitorCount < DIRECTGATE_DESKTOP_MAX_MONITORS) ? TRUE : FALSE;
}

static void DirectGate_Desktop_RefreshWindowsMonitors(directgate_desktop_t *pDesktop)
{
    int32_t nVirtualX = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int32_t nVirtualY = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int32_t nVirtualWidth = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int32_t nVirtualHeight = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (nVirtualWidth <= 0 || nVirtualHeight <= 0) return;

    pDesktop->nScreenWidth = (uint32_t)nVirtualWidth;
    pDesktop->nScreenHeight = (uint32_t)nVirtualHeight;
    pDesktop->nMonitorCount = 0;
    memset(pDesktop->monitors, 0, sizeof(pDesktop->monitors));

    DirectGate_Desktop_AddMonitor(pDesktop, "all", "All displays", nVirtualX, nVirtualY,
        (uint32_t)nVirtualWidth, (uint32_t)nVirtualHeight, XFALSE);
    EnumDisplayMonitors(NULL, NULL, DirectGate_Desktop_MonitorEnumProc, (LPARAM)pDesktop);
}

int DirectGate_Desktop_SetDisplayResolution(directgate_desktop_t *pDesktop,
                                            const directgate_desktop_monitor_t *pMonitor,
                                            uint32_t nWidth, uint32_t nHeight)
{
    if (pMonitor == NULL || !xstrused(pMonitor->sDeviceId))
    {
        DirectGate_Desktop_SetReason(pDesktop,
            "Display mode requires one physical monitor; All displays cannot be resized.");
        return XSTDERR;
    }

    DEVMODEA current;
    memset(&current, 0, sizeof(current));
    current.dmSize = sizeof(current);

    if (!EnumDisplaySettingsExA(pMonitor->sDeviceId, ENUM_CURRENT_SETTINGS, &current, 0))
    {
        DirectGate_Desktop_SetReason(pDesktop, "Failed to read the current Windows display mode.");
        return XSTDERR;
    }

    DEVMODEA best;
    memset(&best, 0, sizeof(best));
    uint64_t nBestScore = UINT64_MAX;

    for (DWORD i = 0;; i++)
    {
        DEVMODEA candidate;
        memset(&candidate, 0, sizeof(candidate));
        candidate.dmSize = sizeof(candidate);

        if (!EnumDisplaySettingsExA(pMonitor->sDeviceId, i, &candidate, 0)) break;
        if (candidate.dmBitsPerPel != current.dmBitsPerPel) continue;

        uint64_t nDx = candidate.dmPelsWidth > nWidth ? candidate.dmPelsWidth - nWidth : nWidth - candidate.dmPelsWidth;
        uint64_t nDy = candidate.dmPelsHeight > nHeight ? candidate.dmPelsHeight - nHeight : nHeight - candidate.dmPelsHeight;
        uint64_t nAspect = (uint64_t)llabs((long long)candidate.dmPelsWidth * nHeight - (long long)nWidth * candidate.dmPelsHeight);
        uint64_t nScore = (nDx + nDy) * 1000000ULL + nAspect;

        if (nScore < nBestScore)
        {
            nBestScore = nScore;
            best = candidate;
        }
    }

    if (nBestScore == UINT64_MAX)
    {
        DirectGate_Desktop_SetReason(pDesktop, "No usable Windows display mode is available.");
        return XSTDERR;
    }

    if (!pDesktop->bDisplayModeChanged)
    {
        xstrncpy(pDesktop->sModeMonitorId, sizeof(pDesktop->sModeMonitorId), pMonitor->sId);
        xstrncpy(pDesktop->sModeDeviceId, sizeof(pDesktop->sModeDeviceId), pMonitor->sDeviceId);
        pDesktop->nOriginalModeX = current.dmPosition.x;
        pDesktop->nOriginalModeY = current.dmPosition.y;
        pDesktop->nOriginalModeWidth = current.dmPelsWidth;
        pDesktop->nOriginalModeHeight = current.dmPelsHeight;
        pDesktop->nOriginalModeRefresh = current.dmDisplayFrequency;
        pDesktop->nOriginalModeRotation = current.dmDisplayOrientation;
        pDesktop->nOriginalModeId = current.dmBitsPerPel;
    }

    LONG nResult = ChangeDisplaySettingsExA(pMonitor->sDeviceId, &best, NULL, CDS_FULLSCREEN, NULL);
    if (nResult != DISP_CHANGE_SUCCESSFUL)
    {
        DirectGate_Desktop_SetReason(pDesktop, "Windows rejected the requested display mode.");
        return XSTDERR;
    }

    pDesktop->bDisplayModeChanged = XTRUE;
    DirectGate_Desktop_RefreshWindowsMonitors(pDesktop);
    return XSTDOK;
}

void DirectGate_Desktop_RestoreDisplayMode(directgate_desktop_t *pDesktop)
{
    if (pDesktop == NULL || !pDesktop->bDisplayModeChanged ||
        !xstrused(pDesktop->sModeDeviceId)) return;

    DEVMODEA mode;
    memset(&mode, 0, sizeof(mode));
    mode.dmSize = sizeof(mode);
    mode.dmFields = DM_POSITION | DM_PELSWIDTH | DM_PELSHEIGHT |
        DM_BITSPERPEL | DM_DISPLAYFREQUENCY | DM_DISPLAYORIENTATION;
    mode.dmPosition.x = pDesktop->nOriginalModeX;
    mode.dmPosition.y = pDesktop->nOriginalModeY;
    mode.dmPelsWidth = pDesktop->nOriginalModeWidth;
    mode.dmPelsHeight = pDesktop->nOriginalModeHeight;
    mode.dmBitsPerPel = (DWORD)pDesktop->nOriginalModeId;
    mode.dmDisplayFrequency = pDesktop->nOriginalModeRefresh;
    mode.dmDisplayOrientation = pDesktop->nOriginalModeRotation;
    (void)ChangeDisplaySettingsExA(pDesktop->sModeDeviceId, &mode, NULL, CDS_FULLSCREEN, NULL);
    pDesktop->bDisplayModeChanged = XFALSE;
    pDesktop->sModeDeviceId[0] = '\0';
    DirectGate_Desktop_RefreshWindowsMonitors(pDesktop);
}

/* Physical-pixel coordinates everywhere: without per-monitor DPI awareness
 * Windows virtualizes GetSystemMetrics/monitor rects on scaled displays and
 * the capture rectangle no longer matches what duplication/BitBlt return.
 * Resolved dynamically - the API needs Win10 1703+ and may already have
 * been applied by the application manifest. */
typedef BOOL (WINAPI *directgate_dpi_context_fn)(DPI_AWARENESS_CONTEXT);

static void DirectGate_Desktop_EnableDpiAwareness(void)
{
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    if (hUser32 != NULL)
    {
        directgate_dpi_context_fn setContext = (directgate_dpi_context_fn)(void*)
            GetProcAddress(hUser32, "SetProcessDpiAwarenessContext");
        if (setContext != NULL &&
            setContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) return;
    }

    SetProcessDPIAware();
}

int DirectGate_Desktop_OpenWindows(directgate_session_t *pSession)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;
    DirectGate_Desktop_EnableDpiAwareness();

    int32_t nVirtualX = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int32_t nVirtualY = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int32_t nVirtualWidth = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int32_t nVirtualHeight = GetSystemMetrics(SM_CYVIRTUALSCREEN);

    xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "windows");
    if (nVirtualWidth <= 0 || nVirtualHeight <= 0)
    {
        DirectGate_Desktop_SetReason(pDesktop,
            "No interactive desktop session is available for the agent process. "
            "Desktop streaming requires a logged-on user session.");
        return XSTDERR;
    }

    /* Informational only: the name of the desktop this process runs on
     * (normally "Default" in the interactive window station). */
    char sDesktopName[64] = { 0 };
    DWORD nNameLen = 0;
    HDESK hDesktop = GetThreadDesktop(GetCurrentThreadId());
    if (hDesktop == NULL ||
        !GetUserObjectInformationA(hDesktop, UOI_NAME, sDesktopName, sizeof(sDesktopName), &nNameLen) ||
        !xstrused(sDesktopName)) xstrncpy(sDesktopName, sizeof(sDesktopName), "Default");

    xstrncpy(pDesktop->sDisplay, sizeof(pDesktop->sDisplay), sDesktopName);
    pDesktop->nScreenWidth = (uint32_t)nVirtualWidth;
    pDesktop->nScreenHeight = (uint32_t)nVirtualHeight;

    DirectGate_Desktop_AddMonitor(pDesktop, "all", "All displays",
        nVirtualX, nVirtualY, (uint32_t)nVirtualWidth, (uint32_t)nVirtualHeight, XFALSE);
    EnumDisplayMonitors(NULL, NULL, DirectGate_Desktop_MonitorEnumProc, (LPARAM)pDesktop);

    /* SendInput works on the interactive desktop the launcher started the
     * agent in; there is no runtime permission to probe (unlike macOS). */
    pDesktop->bInputReady = XTRUE;
    return XSTDOK;
}

#endif
