/*!
 * @file directgate-agent/src/agent/desktop/input.c
 * @brief Agent-side desktop pointer and keyboard input injection.
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
#include "priv.h"
#include "session.h"

#if defined(__linux__)
#include <ctype.h>
#include <X11/Xlib.h>
#include <X11/keysym.h>

typedef Bool (*directgate_xtest_motion_fn)(Display*, int, int, int, unsigned long);
typedef Bool (*directgate_xtest_relative_motion_fn)(Display*, int, int, unsigned long);
typedef Bool (*directgate_xtest_button_fn)(Display*, unsigned int, Bool, unsigned long);
typedef Bool (*directgate_xtest_key_fn)(Display*, unsigned int, Bool, unsigned long);
#elif defined(__APPLE__)
#include <stdbool.h>
#include <ApplicationServices/ApplicationServices.h>
#include <Carbon/Carbon.h>
#endif

#if defined(__linux__) || defined(__APPLE__) || defined(_WIN32)

static int DirectGate_Desktop_FrameToScreenX(const directgate_desktop_t *pDesktop, int nX)
{
#if defined(__linux__)
    if (pDesktop->nFrameWidth <= 1) return 0;
#else
    if (pDesktop->nFrameWidth <= 1) return pDesktop->nCaptureX;
#endif
    if (nX < 0) nX = 0;
    if ((uint32_t)nX >= pDesktop->nFrameWidth) nX = (int)pDesktop->nFrameWidth - 1;
    return pDesktop->nCaptureX + (int)(((uint64_t)(uint32_t)nX * pDesktop->nCaptureWidth) / pDesktop->nFrameWidth);
}

static int DirectGate_Desktop_FrameToScreenY(const directgate_desktop_t *pDesktop, int nY)
{
#if defined(__linux__)
    if (pDesktop->nFrameHeight <= 1) return 0;
#else
    if (pDesktop->nFrameHeight <= 1) return pDesktop->nCaptureY;
#endif
    if (nY < 0) nY = 0;
    if ((uint32_t)nY >= pDesktop->nFrameHeight) nY = (int)pDesktop->nFrameHeight - 1;
    return pDesktop->nCaptureY + (int)(((uint64_t)(uint32_t)nY * pDesktop->nCaptureHeight) / pDesktop->nFrameHeight);
}

#endif /* __linux__ || __APPLE__ || _WIN32 */

#if defined(__linux__)

static KeySym DirectGate_Desktop_KeySymFromJson(xjson_obj_t *pRoot)
{
    const char *pKey = XJSON_GetString(XJSON_GetObject(pRoot, "key"));
    const char *pCode = XJSON_GetString(XJSON_GetObject(pRoot, "code"));

    if (xstrused(pKey))
    {
        if (strlen(pKey) == 1)
        {
            char sKey[2] = { pKey[0], '\0' };
            KeySym sym = XStringToKeysym(sKey);
            if (sym != NoSymbol) return sym;
        }

        if (xstrcmp(pKey, " ")) return XK_space;
        if (xstrcmp(pKey, "Enter")) return XK_Return;
        if (xstrcmp(pKey, "Backspace")) return XK_BackSpace;
        if (xstrcmp(pKey, "Tab")) return XK_Tab;
        if (xstrcmp(pKey, "Escape")) return XK_Escape;
        if (xstrcmp(pKey, "Delete")) return XK_Delete;
        if (xstrcmp(pKey, "Home")) return XK_Home;
        if (xstrcmp(pKey, "End")) return XK_End;
        if (xstrcmp(pKey, "PageUp")) return XK_Page_Up;
        if (xstrcmp(pKey, "PageDown")) return XK_Page_Down;
        if (xstrcmp(pKey, "ArrowLeft")) return XK_Left;
        if (xstrcmp(pKey, "ArrowRight")) return XK_Right;
        if (xstrcmp(pKey, "ArrowUp")) return XK_Up;
        if (xstrcmp(pKey, "ArrowDown")) return XK_Down;
        if (xstrcmp(pKey, "Shift")) return XK_Shift_L;
        if (xstrcmp(pKey, "Control")) return XK_Control_L;
        if (xstrcmp(pKey, "Alt")) return XK_Alt_L;
        if (xstrcmp(pKey, "Meta")) return XK_Super_L;
    }

    if (xstrused(pCode) && strlen(pCode) == 4 && !strncmp(pCode, "Key", 3))
    {
        char sKey[2] = { (char)tolower((unsigned char)pCode[3]), '\0' };
        return XStringToKeysym(sKey);
    }

    if (xstrused(pCode) && strlen(pCode) == 6 && !strncmp(pCode, "Digit", 5))
    {
        char sKey[2] = { pCode[5], '\0' };
        return XStringToKeysym(sKey);
    }

    return NoSymbol;
}

int DirectGate_Desktop_HandleInput(directgate_session_t *pSession, const uint8_t *pPayload, size_t nPayloadLength)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (!pDesktop->bRunning || pDesktop->pDisplay == NULL || !pDesktop->bInputReady)
        return XAPI_CONTINUE;

    if (pPayload == NULL || !nPayloadLength)
        return XAPI_CONTINUE;

    char *pJsonText = (char*)calloc(1, nPayloadLength + 1U);
    XCHECK((pJsonText != NULL), XAPI_CONTINUE);
    memcpy(pJsonText, pPayload, nPayloadLength);

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, pJsonText, nPayloadLength))
    {
        free(pJsonText);
        return XAPI_CONTINUE;
    }

    xjson_obj_t *pRoot = json.pRootObj;
    const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
    const char *pEvent = XJSON_GetString(XJSON_GetObject(pRoot, "event"));
    Display *pDisplay = (Display*)pDesktop->pDisplay;
    int nScreen = DefaultScreen(pDisplay);

    if (xstrcmp(pAction, "pointer"))
    {
        uint32_t nSequence = XJSON_GetU32(XJSON_GetObject(pRoot, "sequence"));
        if (nSequence != 0U && pDesktop->nPointerSequence != 0U &&
            (int32_t)(nSequence - pDesktop->nPointerSequence) <= 0)
        {
            XJSON_Destroy(&json);
            free(pJsonText);
            return XAPI_CONTINUE;
        }

        if (nSequence != 0U) pDesktop->nPointerSequence = nSequence;

        xbool_t bRelative = XJSON_GetBool(XJSON_GetObject(pRoot, "relative"));
        if (bRelative)
        {
            int nDx = XJSON_GetInt(XJSON_GetObject(pRoot, "dx"));
            int nDy = XJSON_GetInt(XJSON_GetObject(pRoot, "dy"));

            if (nDx != 0 || nDy != 0)
            {
                if (pDesktop->pFakeRelativeMotion != NULL)
                {
                    ((directgate_xtest_relative_motion_fn)pDesktop->pFakeRelativeMotion)(
                        pDisplay, nDx, nDy, CurrentTime);
                }
                else
                {
                    XWarpPointer(pDisplay, None, None, 0, 0, 0, 0, nDx, nDy);
                }
            }
        }
        else
        {
            int nX = XJSON_GetInt(XJSON_GetObject(pRoot, "x"));
            int nY = XJSON_GetInt(XJSON_GetObject(pRoot, "y"));
            int nScreenX = DirectGate_Desktop_FrameToScreenX(pDesktop, nX);
            int nScreenY = DirectGate_Desktop_FrameToScreenY(pDesktop, nY);
            ((directgate_xtest_motion_fn)pDesktop->pFakeMotion)(
                pDisplay, nScreen, nScreenX, nScreenY, CurrentTime);
        }

        if (xstrcmp(pEvent, "button"))
        {
            uint32_t nButton = XJSON_GetU32(XJSON_GetObject(pRoot, "button"));
            xbool_t bDown = XJSON_GetBool(XJSON_GetObject(pRoot, "down"));
            if (nButton >= 1 && nButton <= 5)
                ((directgate_xtest_button_fn)pDesktop->pFakeButton)(pDisplay, nButton, bDown ? XTRUE : XFALSE, CurrentTime);
        }
        else if (xstrcmp(pEvent, "wheel"))
        {
            int nDeltaY = XJSON_GetInt(XJSON_GetObject(pRoot, "deltaY"));
            uint32_t nButton = nDeltaY < 0 ? 4U : 5U;
            ((directgate_xtest_button_fn)pDesktop->pFakeButton)(pDisplay, nButton, XTRUE, CurrentTime);
            ((directgate_xtest_button_fn)pDesktop->pFakeButton)(pDisplay, nButton, XFALSE, CurrentTime);
        }

        if (bRelative)
        {
            Window rootReturn, childReturn;
            int nRootX = 0, nRootY = 0, nWindowX = 0, nWindowY = 0;
            unsigned int nMask = 0;

            if (XQueryPointer(pDisplay, RootWindow(pDisplay, nScreen),
                &rootReturn, &childReturn, &nRootX, &nRootY,
                &nWindowX, &nWindowY, &nMask))
            {
                if (DirectGate_Desktop_ClampCursorToCapture(
                    pDesktop, &nRootX, &nRootY))
                {
                    ((directgate_xtest_motion_fn)pDesktop->pFakeMotion)(
                        pDisplay, nScreen, nRootX, nRootY, CurrentTime);
                    XFlush(pDisplay);
                }

                DirectGate_Desktop_SendCursorPosition(
                    pSession, nRootX, nRootY, nSequence);
            }
        }
    }
    else if (xstrcmp(pAction, "key"))
    {
        KeySym sym = DirectGate_Desktop_KeySymFromJson(pRoot);
        if (sym != NoSymbol)
        {
            KeyCode code = XKeysymToKeycode(pDisplay, sym);
            xbool_t bDown = XJSON_GetBool(XJSON_GetObject(pRoot, "down"));
            if (code != 0) ((directgate_xtest_key_fn)pDesktop->pFakeKey)(pDisplay, code, bDown ? XTRUE : XFALSE, CurrentTime);
        }
    }

    XFlush(pDisplay);
    XJSON_Destroy(&json);
    free(pJsonText);
    return XAPI_CONTINUE;
}

#elif defined(__APPLE__)

static CGEventType DirectGate_Desktop_MacMouseEvent(uint32_t nButton, xbool_t bDown)
{
    if (nButton == 3) return bDown ? kCGEventRightMouseDown : kCGEventRightMouseUp;
    if (nButton == 2) return bDown ? kCGEventOtherMouseDown : kCGEventOtherMouseUp;
    return bDown ? kCGEventLeftMouseDown : kCGEventLeftMouseUp;
}

static CGEventType DirectGate_Desktop_MacDragEvent(uint32_t nButtons)
{
    if (nButtons & (1U << 2U)) return kCGEventRightMouseDragged;
    if (nButtons & (1U << 1U)) return kCGEventOtherMouseDragged;
    if (nButtons & 1U) return kCGEventLeftMouseDragged;
    return kCGEventMouseMoved;
}

static CGMouseButton DirectGate_Desktop_MacMouseButton(uint32_t nButton)
{
    if (nButton == 3) return kCGMouseButtonRight;
    if (nButton == 2) return kCGMouseButtonCenter;
    return kCGMouseButtonLeft;
}

static CGPoint DirectGate_Desktop_MacRelativePoint(int nDx, int nDy)
{
    CGPoint point = CGPointZero;
    CGEventRef current = CGEventCreate(NULL);
    if (current != NULL)
    {
        point = CGEventGetLocation(current);
        CFRelease(current);
    }

    point.x += (CGFloat)nDx;
    point.y += (CGFloat)nDy;

    return point;
}

static void DirectGate_Desktop_MacSetRelativeDelta(CGEventRef event, int nDx, int nDy)
{
    if (event == NULL) return;
    CGEventSetIntegerValueField(event, kCGMouseEventDeltaX, (int64_t)nDx);
    CGEventSetIntegerValueField(event, kCGMouseEventDeltaY, (int64_t)nDy);
}

typedef struct directgate_mac_key_ {
    const char *pCode;
    CGKeyCode nKeyCode;
} directgate_mac_key_t;

static const directgate_mac_key_t g_MacKeys[] = {
    { "KeyA", kVK_ANSI_A }, { "KeyB", kVK_ANSI_B }, { "KeyC", kVK_ANSI_C },
    { "KeyD", kVK_ANSI_D }, { "KeyE", kVK_ANSI_E }, { "KeyF", kVK_ANSI_F },
    { "KeyG", kVK_ANSI_G }, { "KeyH", kVK_ANSI_H }, { "KeyI", kVK_ANSI_I },
    { "KeyJ", kVK_ANSI_J }, { "KeyK", kVK_ANSI_K }, { "KeyL", kVK_ANSI_L },
    { "KeyM", kVK_ANSI_M }, { "KeyN", kVK_ANSI_N }, { "KeyO", kVK_ANSI_O },
    { "KeyP", kVK_ANSI_P }, { "KeyQ", kVK_ANSI_Q }, { "KeyR", kVK_ANSI_R },
    { "KeyS", kVK_ANSI_S }, { "KeyT", kVK_ANSI_T }, { "KeyU", kVK_ANSI_U },
    { "KeyV", kVK_ANSI_V }, { "KeyW", kVK_ANSI_W }, { "KeyX", kVK_ANSI_X },
    { "KeyY", kVK_ANSI_Y }, { "KeyZ", kVK_ANSI_Z },
    { "Digit0", kVK_ANSI_0 }, { "Digit1", kVK_ANSI_1 }, { "Digit2", kVK_ANSI_2 },
    { "Digit3", kVK_ANSI_3 }, { "Digit4", kVK_ANSI_4 }, { "Digit5", kVK_ANSI_5 },
    { "Digit6", kVK_ANSI_6 }, { "Digit7", kVK_ANSI_7 }, { "Digit8", kVK_ANSI_8 },
    { "Digit9", kVK_ANSI_9 },
    { "Backquote", kVK_ANSI_Grave }, { "Minus", kVK_ANSI_Minus },
    { "Equal", kVK_ANSI_Equal }, { "BracketLeft", kVK_ANSI_LeftBracket },
    { "BracketRight", kVK_ANSI_RightBracket }, { "Backslash", kVK_ANSI_Backslash },
    { "Semicolon", kVK_ANSI_Semicolon }, { "Quote", kVK_ANSI_Quote },
    { "Comma", kVK_ANSI_Comma }, { "Period", kVK_ANSI_Period },
    { "Slash", kVK_ANSI_Slash },
    { "Enter", kVK_Return }, { "NumpadEnter", kVK_Return },
    { "Backspace", kVK_Delete }, { "Delete", kVK_ForwardDelete },
    { "Tab", kVK_Tab }, { "Escape", kVK_Escape }, { "Space", kVK_Space },
    { "ArrowLeft", kVK_LeftArrow }, { "ArrowRight", kVK_RightArrow },
    { "ArrowUp", kVK_UpArrow }, { "ArrowDown", kVK_DownArrow },
    { "Home", kVK_Home }, { "End", kVK_End },
    { "PageUp", kVK_PageUp }, { "PageDown", kVK_PageDown },
    { "ShiftLeft", kVK_Shift }, { "ShiftRight", kVK_RightShift },
    { "ControlLeft", kVK_Control }, { "ControlRight", kVK_RightControl },
    { "AltLeft", kVK_Option }, { "AltRight", kVK_RightOption },
    { "MetaLeft", kVK_Command }, { "MetaRight", kVK_Command },
    { "F1", kVK_F1 }, { "F2", kVK_F2 }, { "F3", kVK_F3 }, { "F4", kVK_F4 },
    { "F5", kVK_F5 }, { "F6", kVK_F6 }, { "F7", kVK_F7 }, { "F8", kVK_F8 },
    { "F9", kVK_F9 }, { "F10", kVK_F10 }, { "F11", kVK_F11 }, { "F12", kVK_F12 },
};

static CGKeyCode DirectGate_Desktop_MacKeyCodeFromJson(xjson_obj_t *pRoot, xbool_t *pFound)
{
    const char *pCode = XJSON_GetString(XJSON_GetObject(pRoot, "code"));
    const char *pKey = XJSON_GetString(XJSON_GetObject(pRoot, "key"));
    *pFound = XFALSE;

    if (xstrused(pCode))
    {
        for (size_t i = 0; i < sizeof(g_MacKeys) / sizeof(g_MacKeys[0]); i++)
        {
            if (xstrcmp(g_MacKeys[i].pCode, pCode))
            {
                *pFound = XTRUE;
                return g_MacKeys[i].nKeyCode;
            }
        }
    }

    if (xstrused(pKey))
    {
        if (xstrcmp(pKey, " ")) { *pFound = XTRUE; return kVK_Space; }
        if (xstrcmp(pKey, "Enter")) { *pFound = XTRUE; return kVK_Return; }
        if (xstrcmp(pKey, "Backspace")) { *pFound = XTRUE; return kVK_Delete; }
        if (xstrcmp(pKey, "Tab")) { *pFound = XTRUE; return kVK_Tab; }
        if (xstrcmp(pKey, "Escape")) { *pFound = XTRUE; return kVK_Escape; }
        if (xstrcmp(pKey, "Delete")) { *pFound = XTRUE; return kVK_ForwardDelete; }
        if (xstrcmp(pKey, "Home")) { *pFound = XTRUE; return kVK_Home; }
        if (xstrcmp(pKey, "End")) { *pFound = XTRUE; return kVK_End; }
        if (xstrcmp(pKey, "PageUp")) { *pFound = XTRUE; return kVK_PageUp; }
        if (xstrcmp(pKey, "PageDown")) { *pFound = XTRUE; return kVK_PageDown; }
        if (xstrcmp(pKey, "ArrowLeft")) { *pFound = XTRUE; return kVK_LeftArrow; }
        if (xstrcmp(pKey, "ArrowRight")) { *pFound = XTRUE; return kVK_RightArrow; }
        if (xstrcmp(pKey, "ArrowUp")) { *pFound = XTRUE; return kVK_UpArrow; }
        if (xstrcmp(pKey, "ArrowDown")) { *pFound = XTRUE; return kVK_DownArrow; }
    }

    return 0;
}

int DirectGate_Desktop_HandleInput(directgate_session_t *pSession, const uint8_t *pPayload, size_t nPayloadLength)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (!pDesktop->bRunning || !pDesktop->bInputReady) return XAPI_CONTINUE;
    if (pPayload == NULL || !nPayloadLength) return XAPI_CONTINUE;

    char *pJsonText = (char*)calloc(1, nPayloadLength + 1U);
    XCHECK((pJsonText != NULL), XAPI_CONTINUE);
    memcpy(pJsonText, pPayload, nPayloadLength);

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, pJsonText, nPayloadLength))
    {
        free(pJsonText);
        return XAPI_CONTINUE;
    }

    xjson_obj_t *pRoot = json.pRootObj;
    const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
    const char *pEvent = XJSON_GetString(XJSON_GetObject(pRoot, "event"));

    if (xstrcmp(pAction, "pointer"))
    {
        /* Unordered SCTP can deliver an older motion sample after a newer
         * one. Sequence arithmetic is wrap-safe for any realistic in-flight
         * window and prevents the cursor from jumping backwards. */
        uint32_t nSequence = XJSON_GetU32(XJSON_GetObject(pRoot, "sequence"));
        if (nSequence != 0U && pDesktop->nPointerSequence != 0U &&
            (int32_t)(nSequence - pDesktop->nPointerSequence) <= 0)
        {
            XJSON_Destroy(&json);
            free(pJsonText);
            return XAPI_CONTINUE;
        }

        if (nSequence != 0U) pDesktop->nPointerSequence = nSequence;
        xbool_t bRelative = XJSON_GetBool(XJSON_GetObject(pRoot, "relative"));
        int nDx = XJSON_GetInt(XJSON_GetObject(pRoot, "dx"));
        int nDy = XJSON_GetInt(XJSON_GetObject(pRoot, "dy"));
        CGPoint point;

        if (bRelative)
        {
            point = DirectGate_Desktop_MacRelativePoint(nDx, nDy);
        }
        else
        {
            int nX = XJSON_GetInt(XJSON_GetObject(pRoot, "x"));
            int nY = XJSON_GetInt(XJSON_GetObject(pRoot, "y"));
            point = CGPointMake((CGFloat)DirectGate_Desktop_FrameToScreenX(pDesktop, nX),
                (CGFloat)DirectGate_Desktop_FrameToScreenY(pDesktop, nY));
        }

        if (bRelative)
        {
            int nPointX = (int)point.x;
            int nPointY = (int)point.y;

            (void)DirectGate_Desktop_ClampCursorToCapture(pDesktop, &nPointX, &nPointY);
            point = CGPointMake((CGFloat)nPointX, (CGFloat)nPointY);
        }

        if (xstrcmp(pEvent, "button"))
        {
            uint32_t nButton = XJSON_GetU32(XJSON_GetObject(pRoot, "button"));
            xbool_t bDown = XJSON_GetBool(XJSON_GetObject(pRoot, "down"));

            if (nButton >= 1 && nButton <= 3)
            {
                if (bDown) pDesktop->nPointerButtons |= (1U << (nButton - 1U));
                else pDesktop->nPointerButtons &= ~(1U << (nButton - 1U));

                CGEventRef event = CGEventCreateMouseEvent(NULL,
                    DirectGate_Desktop_MacMouseEvent(nButton, bDown),
                    point, DirectGate_Desktop_MacMouseButton(nButton));

                if (event != NULL)
                {
                    if (bRelative) DirectGate_Desktop_MacSetRelativeDelta(event, nDx, nDy);
                    CGEventPost(kCGHIDEventTap, event);
                    CFRelease(event);
                }
            }
        }
        else if (xstrcmp(pEvent, "wheel"))
        {
            int nDeltaY = XJSON_GetInt(XJSON_GetObject(pRoot, "deltaY"));
            CGEventRef event = CGEventCreateScrollWheelEvent(NULL,
                kCGScrollEventUnitPixel, 1, -nDeltaY);
            if (event != NULL)
            {
                CGEventPost(kCGHIDEventTap, event);
                CFRelease(event);
            }
        }
        else
        {
            CGEventRef event = CGEventCreateMouseEvent(NULL,
                DirectGate_Desktop_MacDragEvent(pDesktop->nPointerButtons),
                point, DirectGate_Desktop_MacMouseButton(1));
            if (event != NULL)
            {
                if (bRelative) DirectGate_Desktop_MacSetRelativeDelta(event, nDx, nDy);
                CGEventPost(kCGHIDEventTap, event);
                CFRelease(event);
            }
        }

        if (bRelative)
        {
            DirectGate_Desktop_SendCursorPosition(pSession,
                (int)point.x, (int)point.y, nSequence);
        }
    }
    else if (xstrcmp(pAction, "key"))
    {
        xbool_t bFound = XFALSE;
        CGKeyCode keyCode = DirectGate_Desktop_MacKeyCodeFromJson(pRoot, &bFound);
        if (bFound)
        {
            xbool_t bDown = XJSON_GetBool(XJSON_GetObject(pRoot, "down"));
            CGEventRef event = CGEventCreateKeyboardEvent(NULL, keyCode, bDown ? true : false);
            if (event != NULL)
            {
                CGEventPost(kCGHIDEventTap, event);
                CFRelease(event);
            }
        }
    }

    XJSON_Destroy(&json);
    free(pJsonText);
    return XAPI_CONTINUE;
}

#elif defined(_WIN32)

/* Absolute pointer injection over the whole virtual desktop: SendInput
 * expects 0..65535 normalized coordinates with MOUSEEVENTF_VIRTUALDESK. */
static void DirectGate_Desktop_SendMouseInput(DWORD nFlags, DWORD nMouseData, int nScreenX, int nScreenY)
{
    int nVirtualX = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int nVirtualY = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int nVirtualWidth = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int nVirtualHeight = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (nVirtualWidth <= 1 || nVirtualHeight <= 1) return;

    INPUT input;
    memset(&input, 0, sizeof(input));
    input.type = INPUT_MOUSE;
    input.mi.dx = (LONG)(((int64_t)(nScreenX - nVirtualX) * 65535LL) / (nVirtualWidth - 1));
    input.mi.dy = (LONG)(((int64_t)(nScreenY - nVirtualY) * 65535LL) / (nVirtualHeight - 1));
    input.mi.mouseData = nMouseData;
    input.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK | nFlags;
    SendInput(1, &input, sizeof(input));
}

static void DirectGate_Desktop_SendMouseRelative(DWORD nFlags, DWORD nMouseData, int nDx, int nDy)
{
    INPUT input;
    memset(&input, 0, sizeof(input));
    input.type = INPUT_MOUSE;
    input.mi.dx = (LONG)nDx;
    input.mi.dy = (LONG)nDy;
    input.mi.mouseData = nMouseData;
    input.mi.dwFlags = nFlags | ((nDx != 0 || nDy != 0) ?
        (MOUSEEVENTF_MOVE | MOUSEEVENTF_MOVE_NOCOALESCE) : 0U);
    SendInput(1, &input, sizeof(input));
}

static DWORD DirectGate_Desktop_MouseButtonFlag(uint32_t nButton, xbool_t bDown)
{
    if (nButton == 3) return bDown ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP;
    if (nButton == 2) return bDown ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP;
    return bDown ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP;
}

typedef struct directgate_win_key_ {
    const char *pCode;
    WORD nVirtualKey;
    xbool_t bExtended;
} directgate_win_key_t;

static const directgate_win_key_t g_WinKeys[] = {
    { "KeyA", 'A', XFALSE }, { "KeyB", 'B', XFALSE }, { "KeyC", 'C', XFALSE },
    { "KeyD", 'D', XFALSE }, { "KeyE", 'E', XFALSE }, { "KeyF", 'F', XFALSE },
    { "KeyG", 'G', XFALSE }, { "KeyH", 'H', XFALSE }, { "KeyI", 'I', XFALSE },
    { "KeyJ", 'J', XFALSE }, { "KeyK", 'K', XFALSE }, { "KeyL", 'L', XFALSE },
    { "KeyM", 'M', XFALSE }, { "KeyN", 'N', XFALSE }, { "KeyO", 'O', XFALSE },
    { "KeyP", 'P', XFALSE }, { "KeyQ", 'Q', XFALSE }, { "KeyR", 'R', XFALSE },
    { "KeyS", 'S', XFALSE }, { "KeyT", 'T', XFALSE }, { "KeyU", 'U', XFALSE },
    { "KeyV", 'V', XFALSE }, { "KeyW", 'W', XFALSE }, { "KeyX", 'X', XFALSE },
    { "KeyY", 'Y', XFALSE }, { "KeyZ", 'Z', XFALSE },
    { "Digit0", '0', XFALSE }, { "Digit1", '1', XFALSE }, { "Digit2", '2', XFALSE },
    { "Digit3", '3', XFALSE }, { "Digit4", '4', XFALSE }, { "Digit5", '5', XFALSE },
    { "Digit6", '6', XFALSE }, { "Digit7", '7', XFALSE }, { "Digit8", '8', XFALSE },
    { "Digit9", '9', XFALSE },
    { "Backquote", VK_OEM_3, XFALSE }, { "Minus", VK_OEM_MINUS, XFALSE },
    { "Equal", VK_OEM_PLUS, XFALSE }, { "BracketLeft", VK_OEM_4, XFALSE },
    { "BracketRight", VK_OEM_6, XFALSE }, { "Backslash", VK_OEM_5, XFALSE },
    { "Semicolon", VK_OEM_1, XFALSE }, { "Quote", VK_OEM_7, XFALSE },
    { "Comma", VK_OEM_COMMA, XFALSE }, { "Period", VK_OEM_PERIOD, XFALSE },
    { "Slash", VK_OEM_2, XFALSE },
    { "Enter", VK_RETURN, XFALSE }, { "NumpadEnter", VK_RETURN, XTRUE },
    { "Backspace", VK_BACK, XFALSE }, { "Delete", VK_DELETE, XTRUE },
    { "Insert", VK_INSERT, XTRUE }, { "CapsLock", VK_CAPITAL, XFALSE },
    { "Tab", VK_TAB, XFALSE }, { "Escape", VK_ESCAPE, XFALSE }, { "Space", VK_SPACE, XFALSE },
    { "ArrowLeft", VK_LEFT, XTRUE }, { "ArrowRight", VK_RIGHT, XTRUE },
    { "ArrowUp", VK_UP, XTRUE }, { "ArrowDown", VK_DOWN, XTRUE },
    { "Home", VK_HOME, XTRUE }, { "End", VK_END, XTRUE },
    { "PageUp", VK_PRIOR, XTRUE }, { "PageDown", VK_NEXT, XTRUE },
    { "ShiftLeft", VK_LSHIFT, XFALSE }, { "ShiftRight", VK_RSHIFT, XFALSE },
    { "ControlLeft", VK_LCONTROL, XFALSE }, { "ControlRight", VK_RCONTROL, XTRUE },
    { "AltLeft", VK_LMENU, XFALSE }, { "AltRight", VK_RMENU, XTRUE },
    { "MetaLeft", VK_LWIN, XTRUE }, { "MetaRight", VK_RWIN, XTRUE },
    { "ContextMenu", VK_APPS, XTRUE },
    { "F1", VK_F1, XFALSE }, { "F2", VK_F2, XFALSE }, { "F3", VK_F3, XFALSE },
    { "F4", VK_F4, XFALSE }, { "F5", VK_F5, XFALSE }, { "F6", VK_F6, XFALSE },
    { "F7", VK_F7, XFALSE }, { "F8", VK_F8, XFALSE }, { "F9", VK_F9, XFALSE },
    { "F10", VK_F10, XFALSE }, { "F11", VK_F11, XFALSE }, { "F12", VK_F12, XFALSE },
};

static WORD DirectGate_Desktop_WinKeyFromJson(xjson_obj_t *pRoot, xbool_t *pExtended, xbool_t *pFound)
{
    const char *pCode = XJSON_GetString(XJSON_GetObject(pRoot, "code"));
    const char *pKey = XJSON_GetString(XJSON_GetObject(pRoot, "key"));
    *pExtended = XFALSE;
    *pFound = XFALSE;

    if (xstrused(pCode))
    {
        for (size_t i = 0; i < sizeof(g_WinKeys) / sizeof(g_WinKeys[0]); i++)
        {
            if (xstrcmp(g_WinKeys[i].pCode, pCode))
            {
                *pExtended = g_WinKeys[i].bExtended;
                *pFound = XTRUE;
                return g_WinKeys[i].nVirtualKey;
            }
        }
    }

    if (xstrused(pKey))
    {
        if (xstrcmp(pKey, " ")) { *pFound = XTRUE; return VK_SPACE; }
        if (xstrcmp(pKey, "Enter")) { *pFound = XTRUE; return VK_RETURN; }
        if (xstrcmp(pKey, "Backspace")) { *pFound = XTRUE; return VK_BACK; }
        if (xstrcmp(pKey, "Tab")) { *pFound = XTRUE; return VK_TAB; }
        if (xstrcmp(pKey, "Escape")) { *pFound = XTRUE; return VK_ESCAPE; }
        if (xstrcmp(pKey, "Delete")) { *pExtended = XTRUE; *pFound = XTRUE; return VK_DELETE; }
        if (xstrcmp(pKey, "Home")) { *pExtended = XTRUE; *pFound = XTRUE; return VK_HOME; }
        if (xstrcmp(pKey, "End")) { *pExtended = XTRUE; *pFound = XTRUE; return VK_END; }
        if (xstrcmp(pKey, "PageUp")) { *pExtended = XTRUE; *pFound = XTRUE; return VK_PRIOR; }
        if (xstrcmp(pKey, "PageDown")) { *pExtended = XTRUE; *pFound = XTRUE; return VK_NEXT; }
        if (xstrcmp(pKey, "ArrowLeft")) { *pExtended = XTRUE; *pFound = XTRUE; return VK_LEFT; }
        if (xstrcmp(pKey, "ArrowRight")) { *pExtended = XTRUE; *pFound = XTRUE; return VK_RIGHT; }
        if (xstrcmp(pKey, "ArrowUp")) { *pExtended = XTRUE; *pFound = XTRUE; return VK_UP; }
        if (xstrcmp(pKey, "ArrowDown")) { *pExtended = XTRUE; *pFound = XTRUE; return VK_DOWN; }
        if (xstrcmp(pKey, "Shift")) { *pFound = XTRUE; return VK_LSHIFT; }
        if (xstrcmp(pKey, "Control")) { *pFound = XTRUE; return VK_LCONTROL; }
        if (xstrcmp(pKey, "Alt")) { *pFound = XTRUE; return VK_LMENU; }
        if (xstrcmp(pKey, "Meta")) { *pExtended = XTRUE; *pFound = XTRUE; return VK_LWIN; }
    }

    return 0;
}

static void DirectGate_Desktop_SendKeyInput(WORD nVirtualKey, xbool_t bExtended, xbool_t bDown)
{
    INPUT input;
    memset(&input, 0, sizeof(input));
    input.type = INPUT_KEYBOARD;
    input.ki.wVk = nVirtualKey;
    input.ki.wScan = (WORD)MapVirtualKeyW(nVirtualKey, MAPVK_VK_TO_VSC);
    input.ki.dwFlags = (bExtended ? KEYEVENTF_EXTENDEDKEY : 0) | (bDown ? 0 : KEYEVENTF_KEYUP);
    SendInput(1, &input, sizeof(input));
}

int DirectGate_Desktop_HandleInput(directgate_session_t *pSession, const uint8_t *pPayload, size_t nPayloadLength)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (!pDesktop->bRunning || !pDesktop->bInputReady) return XAPI_CONTINUE;
    if (pPayload == NULL || !nPayloadLength) return XAPI_CONTINUE;

    char *pJsonText = (char*)calloc(1, nPayloadLength + 1U);
    XCHECK((pJsonText != NULL), XAPI_CONTINUE);
    memcpy(pJsonText, pPayload, nPayloadLength);

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, pJsonText, nPayloadLength))
    {
        free(pJsonText);
        return XAPI_CONTINUE;
    }

    xjson_obj_t *pRoot = json.pRootObj;
    const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
    const char *pEvent = XJSON_GetString(XJSON_GetObject(pRoot, "event"));

    if (xstrcmp(pAction, "pointer"))
    {
        /* Unordered SCTP can deliver an older motion sample after a newer
         * one. Sequence arithmetic is wrap-safe for any realistic in-flight
         * window and prevents the cursor from jumping backwards. */
        uint32_t nSequence = XJSON_GetU32(XJSON_GetObject(pRoot, "sequence"));
        if (nSequence != 0U && pDesktop->nPointerSequence != 0U &&
            (int32_t)(nSequence - pDesktop->nPointerSequence) <= 0)
        {
            XJSON_Destroy(&json);
            free(pJsonText);
            return XAPI_CONTINUE;
        }

        if (nSequence != 0U) pDesktop->nPointerSequence = nSequence;
        xbool_t bRelative = XJSON_GetBool(XJSON_GetObject(pRoot, "relative"));
        int nScreenX = 0, nScreenY = 0;
        int nDx = XJSON_GetInt(XJSON_GetObject(pRoot, "dx"));
        int nDy = XJSON_GetInt(XJSON_GetObject(pRoot, "dy"));

        if (!bRelative)
        {
            int nX = XJSON_GetInt(XJSON_GetObject(pRoot, "x"));
            int nY = XJSON_GetInt(XJSON_GetObject(pRoot, "y"));
            nScreenX = DirectGate_Desktop_FrameToScreenX(pDesktop, nX);
            nScreenY = DirectGate_Desktop_FrameToScreenY(pDesktop, nY);
        }

        if (xstrcmp(pEvent, "button"))
        {
            uint32_t nButton = XJSON_GetU32(XJSON_GetObject(pRoot, "button"));
            xbool_t bDown = XJSON_GetBool(XJSON_GetObject(pRoot, "down"));
            if (nButton >= 1 && nButton <= 3)
            {
                DWORD nFlag = DirectGate_Desktop_MouseButtonFlag(nButton, bDown);
                if (bRelative) DirectGate_Desktop_SendMouseRelative(nFlag, 0, nDx, nDy);
                else DirectGate_Desktop_SendMouseInput(nFlag, 0, nScreenX, nScreenY);
            }
        }
        else if (xstrcmp(pEvent, "wheel"))
        {
            /* One notch per event, like the Linux X11 button-4/5 mapping. */
            int nDeltaY = XJSON_GetInt(XJSON_GetObject(pRoot, "deltaY"));
            DWORD nWheel = (DWORD)(nDeltaY < 0 ? WHEEL_DELTA : -WHEEL_DELTA);

            if (bRelative) DirectGate_Desktop_SendMouseRelative(MOUSEEVENTF_WHEEL, nWheel, nDx, nDy);
            else DirectGate_Desktop_SendMouseInput(MOUSEEVENTF_WHEEL, nWheel, nScreenX, nScreenY);
        }
        else
        {
            if (bRelative) DirectGate_Desktop_SendMouseRelative(0, 0, nDx, nDy);
            else DirectGate_Desktop_SendMouseInput(0, 0, nScreenX, nScreenY);
        }

        if (bRelative)
        {
            POINT cursorPoint;
            if (GetCursorPos(&cursorPoint))
            {
                int nCursorX = (int)cursorPoint.x;
                int nCursorY = (int)cursorPoint.y;

                if (DirectGate_Desktop_ClampCursorToCapture(pDesktop, &nCursorX, &nCursorY))
                    SetCursorPos(nCursorX, nCursorY);

                DirectGate_Desktop_SendCursorPosition(pSession, nCursorX, nCursorY, nSequence);
            }
        }
    }
    else if (xstrcmp(pAction, "key"))
    {
        xbool_t bExtended = XFALSE, bFound = XFALSE;
        WORD nVirtualKey = DirectGate_Desktop_WinKeyFromJson(pRoot, &bExtended, &bFound);
        if (bFound)
        {
            xbool_t bDown = XJSON_GetBool(XJSON_GetObject(pRoot, "down"));
            DirectGate_Desktop_SendKeyInput(nVirtualKey, bExtended, bDown);
        }
    }

    XJSON_Destroy(&json);
    free(pJsonText);
    return XAPI_CONTINUE;
}

#else

int DirectGate_Desktop_HandleInput(directgate_session_t *pSession, const uint8_t *pPayload, size_t nPayloadLength)
{
    (void)pPayload;
    (void)nPayloadLength;
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    return XAPI_CONTINUE;
}

#endif
