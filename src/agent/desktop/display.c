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
#elif defined(__APPLE__)
#include <stdbool.h>
#include <ApplicationServices/ApplicationServices.h>
#include <Carbon/Carbon.h>
#endif

#if defined(__linux__)

static void DirectGate_Desktop_EnumerateMonitors(directgate_desktop_t *pDesktop)
{
    Display *pDisplay = (Display*)pDesktop->pDisplay;
    int nScreen = DefaultScreen(pDisplay);
    Window root = RootWindow(pDisplay, nScreen);

    DirectGate_Desktop_AddMonitor(pDesktop, "all", "All displays", 0, 0,
        pDesktop->nScreenWidth, pDesktop->nScreenHeight, XFALSE);

    int nMonitorCount = 0;
    XRRMonitorInfo *pMonitors = XRRGetMonitors(pDisplay, root, XTRUE, &nMonitorCount);
    if (pMonitors == NULL || nMonitorCount <= 0) return;

    for (int i = 0; i < nMonitorCount && pDesktop->nMonitorCount < DIRECTGATE_DESKTOP_MAX_MONITORS; i++)
    {
        XRRMonitorInfo *pInfo = &pMonitors[i];
        char sId[DIRECTGATE_DESKTOP_MONITOR_ID_LEN];
        char sName[DIRECTGATE_DESKTOP_MONITOR_NAME_LEN];
        char *pAtomName = XGetAtomName(pDisplay, pInfo->name);

        snprintf(sId, sizeof(sId), "monitor-%d", i + 1);
        if (xstrused(pAtomName)) xstrncpy(sName, sizeof(sName), pAtomName);
        else snprintf(sName, sizeof(sName), "Monitor %d", i + 1);

        DirectGate_Desktop_AddMonitor(pDesktop, sId, sName, pInfo->x, pInfo->y,
            (uint32_t)pInfo->width, (uint32_t)pInfo->height, pInfo->primary ? XTRUE : XFALSE);

        if (pInfo->noutput > 0)
        {
            directgate_desktop_monitor_t *pAdded = &pDesktop->monitors[pDesktop->nMonitorCount - 1U];
            pAdded->nNativeId = (uint64_t)pInfo->outputs[0];
            snprintf(pAdded->sDeviceId, sizeof(pAdded->sDeviceId), "%lu", (unsigned long)pInfo->outputs[0]);
        }

        if (pAtomName != NULL)
            XFree(pAtomName);
    }

    XRRFreeMonitors(pMonitors);
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

static void DirectGate_Desktop_SetXAuthority(const directgate_session_t *pSession)
{
    if (xstrused(getenv("XAUTHORITY"))) return;
    if (pSession == NULL || pSession->pCfg == NULL ||
        !xstrused(pSession->pCfg->sShellHome)) return;

    char sPath[XPATH_MAX];
    if (strlen(pSession->pCfg->sShellHome) + sizeof("/.Xauthority") > sizeof(sPath))
        return;

    snprintf(sPath, sizeof(sPath), "%s/.Xauthority", pSession->pCfg->sShellHome);
    if (access(sPath, R_OK) == 0) setenv("XAUTHORITY", sPath, 0);
}

int DirectGate_Desktop_OpenX11(directgate_session_t *pSession)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;
    char sDisplay[DIRECTGATE_DESKTOP_DISPLAY_LEN];
    memset(sDisplay, 0, sizeof(sDisplay));
    const char *pDisplayName = DirectGate_Desktop_FindX11Display(sDisplay, sizeof(sDisplay));

    if (!xstrused(pDisplayName))
    {
        if (xstrused(getenv("WAYLAND_DISPLAY")) ||
            (xstrused(getenv("XDG_SESSION_TYPE")) && xstrcmp(getenv("XDG_SESSION_TYPE"), "wayland")))
        {
            xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "wayland");
            DirectGate_Desktop_SetReason(pDesktop, "Wayland desktop streaming is not implemented yet.");
            return XSTDERR;
        }

        xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "none");
        DirectGate_Desktop_SetReason(pDesktop,
            "No display is available on this host. Headless servers without "
            "a graphical session cannot stream a desktop.");

        return XSTDERR;
    }

    XInitThreads();
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
