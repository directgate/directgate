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
#include "session.h"
#include "priv.h"

#if defined(__linux__)
#include <ctype.h>
#include <X11/Xlib.h>
#include <X11/XKBlib.h>
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

#if defined(__linux__) || defined(_WIN32)
/* Browsers report wheel motion in pixels: a discrete mouse notch is ~100px
 * while trackpads emit a stream of 1-10px samples. Platforms that inject
 * discrete wheel clicks (X11 buttons 4-7, Windows WHEEL_DELTA) accumulate
 * the pixels and emit whole notches, so a trackpad swipe no longer turns
 * every sample into a full click. (macOS scrolls in pixel units natively.) */
static int DirectGate_Desktop_WheelNotches(int32_t *pAccum, int nDelta)
{
    /* A direction flip discards the leftover from the previous direction
     * so scrolling reverses immediately instead of eating the first input. */
    if ((nDelta > 0 && *pAccum < 0) || (nDelta < 0 && *pAccum > 0)) *pAccum = 0;
    *pAccum += nDelta;

    int nNotches = *pAccum / 100;
    *pAccum -= nNotches * 100;
    return nNotches;
}
#endif /* __linux__ || _WIN32 */

#endif /* __linux__ || __APPLE__ || _WIN32 */

#if defined(__linux__)

/* Decodes exactly one UTF-8 codepoint. Returns consumed bytes, 0 on error. */
static size_t DirectGate_Desktop_UTF8Decode(const char *pText, uint32_t *pCodepoint)
{
    const uint8_t *pBytes = (const uint8_t*)pText;
    if (pBytes[0] < 0x80U)
    {
        *pCodepoint = pBytes[0];
        return 1;
    }

    size_t nLength = 0;
    uint32_t nCodepoint = 0;

    if ((pBytes[0] & 0xE0U) == 0xC0U) { nLength = 2; nCodepoint = pBytes[0] & 0x1FU; }
    else if ((pBytes[0] & 0xF0U) == 0xE0U) { nLength = 3; nCodepoint = pBytes[0] & 0x0FU; }
    else if ((pBytes[0] & 0xF8U) == 0xF0U) { nLength = 4; nCodepoint = pBytes[0] & 0x07U; }
    else return 0;

    for (size_t i = 1; i < nLength; i++)
    {
        if ((pBytes[i] & 0xC0U) != 0x80U) return 0;
        nCodepoint = (nCodepoint << 6) | (pBytes[i] & 0x3FU);
    }

    *pCodepoint = nCodepoint;
    return nLength;
}

/* X11 keysym for one Unicode codepoint: Latin-1 keysyms equal the codepoint,
 * everything else uses the standard 0x01000000 Unicode keysym offset. This is
 * what makes punctuation (".", ",", "!") and non-Latin characters work — the
 * previous XStringToKeysym(".") lookup expected keysym *names* ("period") and
 * silently failed for every non-alphanumeric key. */
static KeySym DirectGate_Desktop_KeySymFromCodepoint(uint32_t nCodepoint)
{
    if (nCodepoint == (uint32_t)'\n' || nCodepoint == (uint32_t)'\r') return XK_Return;
    if (nCodepoint == (uint32_t)'\t') return XK_Tab;
    if (nCodepoint < 0x20U || nCodepoint == 0x7FU) return NoSymbol;
    if (nCodepoint < 0x100U) return (KeySym)nCodepoint;
    return (KeySym)(nCodepoint | 0x01000000UL);
}

typedef struct directgate_x11_key_ {
    const char *pName;
    KeySym sym;
} directgate_x11_key_t;

static const directgate_x11_key_t g_X11NamedKeys[] = {
    { "Enter", XK_Return }, { "NumpadEnter", XK_KP_Enter },
    { "Backspace", XK_BackSpace }, { "Tab", XK_Tab },
    { "Escape", XK_Escape }, { "Delete", XK_Delete },
    { "Insert", XK_Insert }, { "Home", XK_Home }, { "End", XK_End },
    { "PageUp", XK_Page_Up }, { "PageDown", XK_Page_Down },
    { "ArrowLeft", XK_Left }, { "ArrowRight", XK_Right },
    { "ArrowUp", XK_Up }, { "ArrowDown", XK_Down },
    { "CapsLock", XK_Caps_Lock }, { "NumLock", XK_Num_Lock },
    { "ScrollLock", XK_Scroll_Lock }, { "PrintScreen", XK_Print },
    { "Pause", XK_Pause }, { "ContextMenu", XK_Menu },
    { "AltGraph", XK_ISO_Level3_Shift },
};

/* Physical-code fallback for punctuation keys whose browser `key` value is
 * unusable (most notably `Dead`). The active Shift key still determines the
 * shifted symbol, so Quote resolves to apostrophe / double quote exactly like
 * the physical key on a standard layout instead of dropping the event. */
static const directgate_x11_key_t g_X11CodeFallbackKeys[] = {
    { "Backquote", XK_grave },
    { "Minus", XK_minus }, { "Equal", XK_equal },
    { "BracketLeft", XK_bracketleft }, { "BracketRight", XK_bracketright },
    { "Backslash", XK_backslash }, { "Semicolon", XK_semicolon },
    { "Quote", XK_apostrophe }, { "Comma", XK_comma },
    { "Period", XK_period }, { "Slash", XK_slash },
    { "Space", XK_space },
};

static xbool_t DirectGate_Desktop_IsModifierName(const char *pName, const char *pBase)
{
    size_t nBase;
    if (!xstrused(pName)) return XFALSE;
    if (xstrcmp(pName, pBase)) return XTRUE;

    nBase = strlen(pBase);
    if (strncmp(pName, pBase, nBase) != 0) return XFALSE;
    return (xstrcmp(pName + nBase, "Left") || xstrcmp(pName + nBase, "Right")) ? XTRUE : XFALSE;
}

static KeySym DirectGate_Desktop_ModifierKeySymFor(const char *pName, xbool_t bRight)
{
    if (DirectGate_Desktop_IsModifierName(pName, "Shift")) return bRight ? XK_Shift_R : XK_Shift_L;
    if (DirectGate_Desktop_IsModifierName(pName, "Control")) return bRight ? XK_Control_R : XK_Control_L;
    if (DirectGate_Desktop_IsModifierName(pName, "Alt")) return bRight ? XK_Alt_R : XK_Alt_L;
    if (DirectGate_Desktop_IsModifierName(pName, "Meta")) return bRight ? XK_Super_R : XK_Super_L;
    return NoSymbol;
}

/* Modifier side (left/right) comes from the physical `code`; the `key`
 * value is just "Shift"/"Control"/"Alt"/"Meta" for both sides. */
static KeySym DirectGate_Desktop_ModifierKeySym(const char *pKey, const char *pCode)
{
    const char *pSide = xstrused(pCode) ? pCode : pKey;
    xbool_t bRight = xstrused(pSide) && strstr(pSide, "Right") != NULL;
    return DirectGate_Desktop_ModifierKeySymFor(pKey, bRight);
}

static KeySym DirectGate_Desktop_KeySymFromJson(xjson_obj_t *pRoot)
{
    const char *pKey = XJSON_GetString(XJSON_GetObject(pRoot, "key"));
    const char *pCode = XJSON_GetString(XJSON_GetObject(pRoot, "code"));

    if (xstrused(pKey))
    {
        KeySym sym = DirectGate_Desktop_ModifierKeySym(pKey, pCode);
        if (sym != NoSymbol) return sym;

        uint32_t nCodepoint = 0;
        size_t nUsed = DirectGate_Desktop_UTF8Decode(pKey, &nCodepoint);
        if (nUsed > 0 && pKey[nUsed] == '\0')
            return DirectGate_Desktop_KeySymFromCodepoint(nCodepoint);

        for (size_t i = 0; i < sizeof(g_X11NamedKeys) / sizeof(g_X11NamedKeys[0]); i++)
        {
            if (xstrcmp(g_X11NamedKeys[i].pName, pKey))
                return g_X11NamedKeys[i].sym;
        }

        /* Function keys and other W3C names that match keysym names
         * ("F1".."F24", "Cancel", ...) resolve directly. */
        KeySym named = XStringToKeysym(pKey);
        if (named != NoSymbol) return named;
    }

    if (xstrused(pCode))
    {
        KeySym sym = DirectGate_Desktop_ModifierKeySymFor(pCode, strstr(pCode, "Right") != NULL);
        if (sym != NoSymbol) return sym;
    }

    /* Fallback when `key` is unusable ("Unidentified", "Dead", IME): use the
     * physical code for the alphanumeric block. */
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

    if (xstrused(pCode))
    {
        for (size_t i = 0; i < sizeof(g_X11CodeFallbackKeys) / sizeof(g_X11CodeFallbackKeys[0]); i++)
        {
            if (xstrcmp(g_X11CodeFallbackKeys[i].pName, pCode))
                return g_X11CodeFallbackKeys[i].sym;
        }
    }

    return NoSymbol;
}

/* Finds (or creates) a spare keycode and binds the requested keysym to it.
 * Used for keysyms missing from the active host layout, e.g. typing Georgian
 * text into a host that only has a US keymap. The binding is cached until a
 * different keysym needs the slot and restored in DirectGate_Desktop_Clear. */
static KeyCode DirectGate_Desktop_X11BindScratch(directgate_desktop_t *pDesktop, KeySym sym)
{
    Display *pDisplay = (Display*)pDesktop->pDisplay;

    if (pDesktop->nScratchKeycode == 0U)
    {
        int nMinCode = 0, nMaxCode = 0, nSymsPerCode = 0;
        XDisplayKeycodes(pDisplay, &nMinCode, &nMaxCode);

        KeySym *pMap = XGetKeyboardMapping(pDisplay, (KeyCode)nMinCode,
            nMaxCode - nMinCode + 1, &nSymsPerCode);
        if (pMap == NULL || nSymsPerCode <= 0)
        {
            if (pMap != NULL) XFree(pMap);
            return 0;
        }

        for (int i = nMaxCode; i >= nMinCode && pDesktop->nScratchKeycode == 0U; i--)
        {
            xbool_t bFree = XTRUE;
            for (int j = 0; j < nSymsPerCode; j++)
            {
                if (pMap[(i - nMinCode) * nSymsPerCode + j] != NoSymbol)
                {
                    bFree = XFALSE;
                    break;
                }
            }

            if (bFree) pDesktop->nScratchKeycode = (uint32_t)i;
        }

        XFree(pMap);
        if (pDesktop->nScratchKeycode == 0U) return 0;
    }

    if (pDesktop->nScratchKeysym != (uint64_t)sym)
    {
        KeySym syms[2] = { sym, sym };
        XChangeKeyboardMapping(pDisplay, (int)pDesktop->nScratchKeycode, 2, syms, 1);
        XSync(pDisplay, XFALSE);
        pDesktop->nScratchKeysym = (uint64_t)sym;
    }

    return (KeyCode)pDesktop->nScratchKeycode;
}

/* Resolves a keysym to a keycode reachable in the ACTIVE layout group.
 * Injected keycodes are interpreted with the host's current group, so a
 * match found in another group (e.g. a Georgian symbol on a host whose
 * active layout is US) would type the wrong character — such keysyms go
 * through the scratch binding instead. When the keysym only exists on the
 * shifted level (e.g. "!" on the "1" key), *pNeedShift is set so the
 * caller can synthesize Shift when the client is not physically holding it. */
static KeyCode DirectGate_Desktop_X11ResolveKeysym(directgate_desktop_t *pDesktop,
                                                   KeySym sym, xbool_t *pNeedShift)
{
    Display *pDisplay = (Display*)pDesktop->pDisplay;
    *pNeedShift = XFALSE;

    int nGroup = 0;
    XkbStateRec state;
    if (XkbGetState(pDisplay, XkbUseCoreKbd, &state) == Success)
        nGroup = state.group;

    int nMinCode = 0, nMaxCode = 0;
    XDisplayKeycodes(pDisplay, &nMinCode, &nMaxCode);

    KeyCode shiftedMatch = 0;
    for (int i = nMinCode; i <= nMaxCode; i++)
    {
        /* XkbKeycodeToKeysym wraps the group for single-group keys, so
         * Return/arrows/modifiers resolve in every layout group. */
        if (XkbKeycodeToKeysym(pDisplay, (KeyCode)i, nGroup, 0) == sym)
            return (KeyCode)i;

        if (shiftedMatch == 0 &&
            XkbKeycodeToKeysym(pDisplay, (KeyCode)i, nGroup, 1) == sym)
            shiftedMatch = (KeyCode)i;
    }

    if (shiftedMatch != 0)
    {
        *pNeedShift = XTRUE;
        return shiftedMatch;
    }

    return DirectGate_Desktop_X11BindScratch(pDesktop, sym);
}

static xbool_t DirectGate_Desktop_X11ShiftDown(Display *pDisplay)
{
    Window rootReturn, childReturn;
    int nRootX = 0, nRootY = 0, nWindowX = 0, nWindowY = 0;
    unsigned int nMask = 0;

    XQueryPointer(pDisplay, DefaultRootWindow(pDisplay), &rootReturn, &childReturn,
        &nRootX, &nRootY, &nWindowX, &nWindowY, &nMask);
    return (nMask & ShiftMask) ? XTRUE : XFALSE;
}

static void DirectGate_Desktop_X11RememberKey(directgate_desktop_t *pDesktop,
                                              const char *pCode, KeyCode code)
{
    if (!xstrused(pCode)) return;

    for (uint32_t i = 0; i < pDesktop->nHeldKeyCount; i++)
    {
        if (xstrcmp(pDesktop->heldKeys[i].sCode, pCode))
        {
            pDesktop->heldKeys[i].nKeycode = code;
            return;
        }
    }

    if (pDesktop->nHeldKeyCount >= DIRECTGATE_DESKTOP_MAX_HELD_KEYS)
    {
        memmove(&pDesktop->heldKeys[0], &pDesktop->heldKeys[1],
            sizeof(pDesktop->heldKeys[0]) * (DIRECTGATE_DESKTOP_MAX_HELD_KEYS - 1U));
        pDesktop->nHeldKeyCount = DIRECTGATE_DESKTOP_MAX_HELD_KEYS - 1U;
    }

    directgate_desktop_held_key_t *pSlot = &pDesktop->heldKeys[pDesktop->nHeldKeyCount++];
    xstrncpy(pSlot->sCode, sizeof(pSlot->sCode), pCode);
    pSlot->nKeycode = code;
}

static KeyCode DirectGate_Desktop_X11ForgetKey(directgate_desktop_t *pDesktop,
                                               const char *pCode)
{
    if (!xstrused(pCode)) return 0;

    for (uint32_t i = 0; i < pDesktop->nHeldKeyCount; i++)
    {
        if (!xstrcmp(pDesktop->heldKeys[i].sCode, pCode)) continue;

        KeyCode code = (KeyCode)pDesktop->heldKeys[i].nKeycode;
        memmove(&pDesktop->heldKeys[i], &pDesktop->heldKeys[i + 1U],
            sizeof(pDesktop->heldKeys[0]) * (pDesktop->nHeldKeyCount - i - 1U));
        pDesktop->nHeldKeyCount--;
        return code;
    }

    return 0;
}

static KeyCode DirectGate_Desktop_X11SendKeysym(directgate_desktop_t *pDesktop,
                                                KeySym sym, xbool_t bDown)
{
    Display *pDisplay = (Display*)pDesktop->pDisplay;
    xbool_t bNeedShift = XFALSE;

    KeyCode code = DirectGate_Desktop_X11ResolveKeysym(pDesktop, sym, &bNeedShift);
    if (code == 0) return 0;

    directgate_xtest_key_fn pKeyFn = (directgate_xtest_key_fn)pDesktop->pFakeKey;
    KeyCode shiftCode = XKeysymToKeycode(pDisplay, XK_Shift_L);

    /* Wrap only the press: the character is produced at press time, and a
     * physically held client Shift already arrives as its own key event. */
    xbool_t bWrapShift = bDown && bNeedShift && shiftCode != 0 &&
        !DirectGate_Desktop_X11ShiftDown(pDisplay);

    if (bWrapShift) pKeyFn(pDisplay, shiftCode, XTRUE, CurrentTime);
    pKeyFn(pDisplay, code, bDown ? XTRUE : XFALSE, CurrentTime);
    if (bWrapShift) pKeyFn(pDisplay, shiftCode, XFALSE, CurrentTime);

    return code;
}

static void DirectGate_Desktop_X11HandleKey(directgate_desktop_t *pDesktop,
                                            xjson_obj_t *pRoot)
{
    const char *pCode = XJSON_GetString(XJSON_GetObject(pRoot, "code"));
    xbool_t bDown = XJSON_GetBool(XJSON_GetObject(pRoot, "down"));

    if (!bDown)
    {
        KeyCode tracked = DirectGate_Desktop_X11ForgetKey(pDesktop, pCode);
        if (tracked != 0)
        {
            ((directgate_xtest_key_fn)pDesktop->pFakeKey)(
                (Display*)pDesktop->pDisplay, tracked, XFALSE, CurrentTime);
            return;
        }
    }

    KeySym sym = DirectGate_Desktop_KeySymFromJson(pRoot);
    if (sym == NoSymbol) return;

    KeyCode used = DirectGate_Desktop_X11SendKeysym(pDesktop, sym, bDown);
    if (bDown && used != 0) DirectGate_Desktop_X11RememberKey(pDesktop, pCode, used);
}

void DirectGate_Desktop_ReleaseHeldKeys(directgate_desktop_t *pDesktop)
{
    XCHECK_VOID_NL((pDesktop != NULL));
    if (pDesktop->pDisplay == NULL || pDesktop->pFakeKey == NULL) return;

    Display *pDisplay = (Display*)pDesktop->pDisplay;
    directgate_xtest_key_fn pKeyFn = (directgate_xtest_key_fn)pDesktop->pFakeKey;

    for (uint32_t i = 0; i < pDesktop->nHeldKeyCount; i++)
        pKeyFn(pDisplay, (KeyCode)pDesktop->heldKeys[i].nKeycode, XFALSE, CurrentTime);

    pDesktop->nHeldKeyCount = 0;
    XFlush(pDisplay);
}

static void DirectGate_Desktop_X11SetLock(Display *pDisplay, KeySym sym, xjson_obj_t *pValue)
{
    if (pValue == NULL) return;

    unsigned int nMask = XkbKeysymToModifiers(pDisplay, sym);
    if (nMask == 0U) return;

    XkbLockModifiers(pDisplay, XkbUseCoreKbd, nMask,
        XJSON_GetBool(pValue) ? nMask : 0U);
}

/* Types a UTF-8 string by pressing one key per codepoint. Used by the
 * browser's text input path (mobile on-screen keyboards / IME input that
 * never produces usable KeyboardEvent codes). */
static void DirectGate_Desktop_X11TypeText(directgate_desktop_t *pDesktop, const char *pText)
{
    size_t nOffset = 0;
    size_t nLength = strlen(pText);

    while (nOffset < nLength)
    {
        uint32_t nCodepoint = 0;
        size_t nUsed = DirectGate_Desktop_UTF8Decode(pText + nOffset, &nCodepoint);
        if (nUsed == 0) break;
        nOffset += nUsed;

        KeySym sym = DirectGate_Desktop_KeySymFromCodepoint(nCodepoint);
        if (sym == NoSymbol) continue;

        DirectGate_Desktop_X11SendKeysym(pDesktop, sym, XTRUE);
        DirectGate_Desktop_X11SendKeysym(pDesktop, sym, XFALSE);
    }
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

            /* 1-3 = left/middle/right, 8/9 = back/forward (X11 button ids;
             * 4-7 are reserved for wheel emulation below). */
            if ((nButton >= 1 && nButton <= 3) || nButton == 8 || nButton == 9)
                ((directgate_xtest_button_fn)pDesktop->pFakeButton)(pDisplay, nButton, bDown ? XTRUE : XFALSE, CurrentTime);
        }
        else if (xstrcmp(pEvent, "wheel"))
        {
            directgate_xtest_button_fn pButtonFn = (directgate_xtest_button_fn)pDesktop->pFakeButton;
            int nDeltaY = XJSON_GetInt(XJSON_GetObject(pRoot, "deltaY"));
            int nDeltaX = XJSON_GetInt(XJSON_GetObject(pRoot, "deltaX"));
            int nNotchesY = DirectGate_Desktop_WheelNotches(&pDesktop->nWheelAccumY, nDeltaY);
            int nNotchesX = DirectGate_Desktop_WheelNotches(&pDesktop->nWheelAccumX, nDeltaX);

            uint32_t nButtonY = nNotchesY < 0 ? 4U : 5U;
            for (int i = 0; i < abs(nNotchesY); i++)
            {
                pButtonFn(pDisplay, nButtonY, XTRUE, CurrentTime);
                pButtonFn(pDisplay, nButtonY, XFALSE, CurrentTime);
            }

            uint32_t nButtonX = nNotchesX < 0 ? 6U : 7U;
            for (int i = 0; i < abs(nNotchesX); i++)
            {
                pButtonFn(pDisplay, nButtonX, XTRUE, CurrentTime);
                pButtonFn(pDisplay, nButtonX, XFALSE, CurrentTime);
            }
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
        DirectGate_Desktop_X11HandleKey(pDesktop, pRoot);
    }
    else if (xstrcmp(pAction, "text"))
    {
        const char *pText = XJSON_GetString(XJSON_GetObject(pRoot, "text"));
        if (xstrused(pText)) DirectGate_Desktop_X11TypeText(pDesktop, pText);
    }
    else if (xstrcmp(pAction, "lock"))
    {
        DirectGate_Desktop_X11SetLock(pDisplay, XK_Caps_Lock, XJSON_GetObject(pRoot, "caps"));
        DirectGate_Desktop_X11SetLock(pDisplay, XK_Num_Lock, XJSON_GetObject(pRoot, "num"));
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
    if (nButton == 2 || nButton == 8 || nButton == 9)
        return bDown ? kCGEventOtherMouseDown : kCGEventOtherMouseUp;
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
    /* Back/forward map to the HID button numbers apps expect (3/4). */
    if (nButton == 8) return (CGMouseButton)3;
    if (nButton == 9) return (CGMouseButton)4;
    return kCGMouseButtonLeft;
}

/* macOS applications only treat a click sequence as a double/triple click
 * when the event carries kCGMouseEventClickState; without it every injected
 * click is a fresh single click and double-click never registers. */
static uint32_t DirectGate_Desktop_MacClickCount(directgate_desktop_t *pDesktop,
                                                 uint32_t nButton, CGPoint point,
                                                 xbool_t bDown)
{
    if (!bDown) return pDesktop->nClickCount ? pDesktop->nClickCount : 1U;

    uint64_t nNowMs = XTime_GetMs();
    int nX = (int)point.x, nY = (int)point.y;

    xbool_t bNearby = abs(nX - (int)pDesktop->nLastClickX) <= 5 &&
                      abs(nY - (int)pDesktop->nLastClickY) <= 5;

    if (nButton == pDesktop->nLastClickButton && bNearby &&
        pDesktop->nLastClickMs != 0 && nNowMs - pDesktop->nLastClickMs <= 500)
        pDesktop->nClickCount++;
    else
        pDesktop->nClickCount = 1U;

    pDesktop->nLastClickMs = nNowMs;
    pDesktop->nLastClickX = (int32_t)nX;
    pDesktop->nLastClickY = (int32_t)nY;
    pDesktop->nLastClickButton = nButton;
    return pDesktop->nClickCount;
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
    { "CapsLock", kVK_CapsLock },
    { "Numpad0", kVK_ANSI_Keypad0 }, { "Numpad1", kVK_ANSI_Keypad1 },
    { "Numpad2", kVK_ANSI_Keypad2 }, { "Numpad3", kVK_ANSI_Keypad3 },
    { "Numpad4", kVK_ANSI_Keypad4 }, { "Numpad5", kVK_ANSI_Keypad5 },
    { "Numpad6", kVK_ANSI_Keypad6 }, { "Numpad7", kVK_ANSI_Keypad7 },
    { "Numpad8", kVK_ANSI_Keypad8 }, { "Numpad9", kVK_ANSI_Keypad9 },
    { "NumpadDecimal", kVK_ANSI_KeypadDecimal }, { "NumpadAdd", kVK_ANSI_KeypadPlus },
    { "NumpadSubtract", kVK_ANSI_KeypadMinus }, { "NumpadMultiply", kVK_ANSI_KeypadMultiply },
    { "NumpadDivide", kVK_ANSI_KeypadDivide }, { "NumpadEqual", kVK_ANSI_KeypadEquals },
    { "NumLock", kVK_ANSI_KeypadClear },
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

/* Sends one keyboard event pair carrying a literal UTF-16 chunk. Keycode 0
 * with an attached unicode string is the standard CGEvent "type text" path
 * and works for any script without depending on the host keyboard layout. */
static void DirectGate_Desktop_MacTypeChunk(const UniChar *pChunk, size_t nLength)
{
    if (nLength == 0) return;

    CGEventRef down = CGEventCreateKeyboardEvent(NULL, 0, true);
    if (down != NULL)
    {
        CGEventKeyboardSetUnicodeString(down, nLength, pChunk);
        CGEventPost(kCGHIDEventTap, down);
        CFRelease(down);
    }

    CGEventRef up = CGEventCreateKeyboardEvent(NULL, 0, false);
    if (up != NULL)
    {
        CGEventKeyboardSetUnicodeString(up, nLength, pChunk);
        CGEventPost(kCGHIDEventTap, up);
        CFRelease(up);
    }
}

static void DirectGate_Desktop_MacTapKey(CGKeyCode keyCode)
{
    CGEventRef down = CGEventCreateKeyboardEvent(NULL, keyCode, true);
    if (down != NULL)
    {
        CGEventPost(kCGHIDEventTap, down);
        CFRelease(down);
    }

    CGEventRef up = CGEventCreateKeyboardEvent(NULL, keyCode, false);
    if (up != NULL)
    {
        CGEventPost(kCGHIDEventTap, up);
        CFRelease(up);
    }
}

static void DirectGate_Desktop_MacTypeText(const char *pText)
{
    CFStringRef pString = CFStringCreateWithCString(kCFAllocatorDefault, pText,
        kCFStringEncodingUTF8);
    if (pString == NULL) return;

    CFIndex nLength = CFStringGetLength(pString);
    /* CGEventKeyboardSetUnicodeString caps a single event at 20 UTF-16
     * units; batch printable runs and press real keys for control chars. */
    UniChar chunk[20];
    size_t nChunkLen = 0;

    for (CFIndex i = 0; i < nLength; i++)
    {
        UniChar ch = CFStringGetCharacterAtIndex(pString, i);

        if (ch == (UniChar)'\n' || ch == (UniChar)'\r' || ch == (UniChar)'\t')
        {
            DirectGate_Desktop_MacTypeChunk(chunk, nChunkLen);
            nChunkLen = 0;

            if (ch == (UniChar)'\t') DirectGate_Desktop_MacTapKey(kVK_Tab);
            else DirectGate_Desktop_MacTapKey(kVK_Return);

            /* Swallow the LF of a CRLF pair. */
            if (ch == (UniChar)'\r' && i + 1 < nLength &&
                CFStringGetCharacterAtIndex(pString, i + 1) == (UniChar)'\n') i++;
            continue;
        }

        /* Flush at 19 of 20 units, except when the next unit is a low
         * surrogate: the reserved slot keeps its pair in one event. */
        xbool_t bLowSurrogate = (ch >= 0xDC00U && ch <= 0xDFFFU) ? XTRUE : XFALSE;
        if (nChunkLen >= sizeof(chunk) / sizeof(chunk[0]) - 1U && !bLowSurrogate)
        {
            DirectGate_Desktop_MacTypeChunk(chunk, nChunkLen);
            nChunkLen = 0;
        }

        chunk[nChunkLen++] = ch;
    }

    DirectGate_Desktop_MacTypeChunk(chunk, nChunkLen);
    CFRelease(pString);
}

/* Accessibility permission can be granted while a session is already
 * streaming; recheck lazily (rate limited) so input starts working without
 * an agent restart, and push a status update so the browser clears its
 * "input disabled" notice. */
static xbool_t DirectGate_Desktop_MacEnsureInput(directgate_session_t *pSession)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;
    if (pDesktop->bInputReady) return XTRUE;

    uint64_t nNowMs = XTime_GetMs();
    if (pDesktop->nInputRecheckMs != 0 && nNowMs - pDesktop->nInputRecheckMs < 2000) return XFALSE;
    pDesktop->nInputRecheckMs = nNowMs;

    if (!AXIsProcessTrusted()) return XFALSE;

    pDesktop->bInputReady = XTRUE;
    pDesktop->sInputReason[0] = '\0';
    DirectGate_Desktop_SendStatus(pSession, "streaming", NULL);
    return XTRUE;
}

int DirectGate_Desktop_HandleInput(directgate_session_t *pSession, const uint8_t *pPayload, size_t nPayloadLength)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (!pDesktop->bRunning) return XAPI_CONTINUE;
    if (!DirectGate_Desktop_MacEnsureInput(pSession)) return XAPI_CONTINUE;
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

            if ((nButton >= 1 && nButton <= 3) || nButton == 8 || nButton == 9)
            {
                if (bDown) pDesktop->nPointerButtons |= (1U << (nButton - 1U));
                else pDesktop->nPointerButtons &= ~(1U << (nButton - 1U));

                CGEventRef event = CGEventCreateMouseEvent(NULL,
                    DirectGate_Desktop_MacMouseEvent(nButton, bDown),
                    point, DirectGate_Desktop_MacMouseButton(nButton));

                if (event != NULL)
                {
                    uint32_t nClicks = DirectGate_Desktop_MacClickCount(pDesktop, nButton, point, bDown);
                    CGEventSetIntegerValueField(event, kCGMouseEventClickState, (int64_t)nClicks);
                    if (bRelative) DirectGate_Desktop_MacSetRelativeDelta(event, nDx, nDy);
                    CGEventPost(kCGHIDEventTap, event);
                    CFRelease(event);
                }
            }
        }
        else if (xstrcmp(pEvent, "wheel"))
        {
            int nDeltaY = XJSON_GetInt(XJSON_GetObject(pRoot, "deltaY"));
            int nDeltaX = XJSON_GetInt(XJSON_GetObject(pRoot, "deltaX"));
            CGEventRef event = CGEventCreateScrollWheelEvent(NULL, kCGScrollEventUnitPixel, 2, -nDeltaY, -nDeltaX);
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
    else if (xstrcmp(pAction, "text"))
    {
        const char *pText = XJSON_GetString(XJSON_GetObject(pRoot, "text"));
        if (xstrused(pText)) DirectGate_Desktop_MacTypeText(pText);
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

static DWORD DirectGate_Desktop_MouseButtonFlag(uint32_t nButton, xbool_t bDown, DWORD *pMouseData)
{
    *pMouseData = 0;
    if (nButton == 3) return bDown ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP;
    if (nButton == 2) return bDown ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP;

    if (nButton == 8 || nButton == 9)
    {
        *pMouseData = (nButton == 8) ? XBUTTON1 : XBUTTON2;
        return bDown ? MOUSEEVENTF_XDOWN : MOUSEEVENTF_XUP;
    }

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
    { "Numpad0", VK_NUMPAD0, XFALSE }, { "Numpad1", VK_NUMPAD1, XFALSE },
    { "Numpad2", VK_NUMPAD2, XFALSE }, { "Numpad3", VK_NUMPAD3, XFALSE },
    { "Numpad4", VK_NUMPAD4, XFALSE }, { "Numpad5", VK_NUMPAD5, XFALSE },
    { "Numpad6", VK_NUMPAD6, XFALSE }, { "Numpad7", VK_NUMPAD7, XFALSE },
    { "Numpad8", VK_NUMPAD8, XFALSE }, { "Numpad9", VK_NUMPAD9, XFALSE },
    { "NumpadDecimal", VK_DECIMAL, XFALSE }, { "NumpadAdd", VK_ADD, XFALSE },
    { "NumpadSubtract", VK_SUBTRACT, XFALSE }, { "NumpadMultiply", VK_MULTIPLY, XFALSE },
    { "NumpadDivide", VK_DIVIDE, XTRUE },
    { "NumLock", VK_NUMLOCK, XFALSE }, { "ScrollLock", VK_SCROLL, XFALSE },
    { "PrintScreen", VK_SNAPSHOT, XTRUE }, { "Pause", VK_PAUSE, XFALSE },
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

static void DirectGate_Desktop_WinSetLock(WORD nVirtualKey, xjson_obj_t *pValue)
{
    if (pValue == NULL) return;

    xbool_t bWanted = XJSON_GetBool(pValue);
    xbool_t bCurrent = (GetKeyState(nVirtualKey) & 1) ? XTRUE : XFALSE;
    if (bWanted == bCurrent) return;

    DirectGate_Desktop_SendKeyInput(nVirtualKey, XFALSE, XTRUE);
    DirectGate_Desktop_SendKeyInput(nVirtualKey, XFALSE, XFALSE);
}

static void DirectGate_Desktop_WinTypeText(const char *pText)
{
    int nWide = MultiByteToWideChar(CP_UTF8, 0, pText, -1, NULL, 0);
    if (nWide <= 1) return;

    WCHAR *pWide = (WCHAR*)malloc((size_t)nWide * sizeof(WCHAR));
    if (pWide == NULL) return;

    if (!MultiByteToWideChar(CP_UTF8, 0, pText, -1, pWide, nWide))
    {
        free(pWide);
        return;
    }

    for (int i = 0; pWide[i] != L'\0'; i++)
    {
        WCHAR wch = pWide[i];

        if (wch == L'\n' || wch == L'\r' || wch == L'\t')
        {
            WORD nVirtualKey = (wch == L'\t') ? VK_TAB : VK_RETURN;
            DirectGate_Desktop_SendKeyInput(nVirtualKey, XFALSE, XTRUE);
            DirectGate_Desktop_SendKeyInput(nVirtualKey, XFALSE, XFALSE);

            /* Swallow the LF of a CRLF pair. */
            if (wch == L'\r' && pWide[i + 1] == L'\n') i++;
            continue;
        }

        INPUT inputs[2];
        memset(inputs, 0, sizeof(inputs));
        inputs[0].type = INPUT_KEYBOARD;
        inputs[0].ki.wScan = (WORD)wch;
        inputs[0].ki.dwFlags = KEYEVENTF_UNICODE;
        inputs[1] = inputs[0];
        inputs[1].ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
        SendInput(2, inputs, sizeof(INPUT));
    }

    free(pWide);
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
            if ((nButton >= 1 && nButton <= 3) || nButton == 8 || nButton == 9)
            {
                DWORD nMouseData = 0;
                DWORD nFlag = DirectGate_Desktop_MouseButtonFlag(nButton, bDown, &nMouseData);
                if (bRelative) DirectGate_Desktop_SendMouseRelative(nFlag, nMouseData, nDx, nDy);
                else DirectGate_Desktop_SendMouseInput(nFlag, nMouseData, nScreenX, nScreenY);
            }
        }
        else if (xstrcmp(pEvent, "wheel"))
        {
            /* Same pixel->notch accumulation as the X11 button-4..7 mapping. */
            int nDeltaY = XJSON_GetInt(XJSON_GetObject(pRoot, "deltaY"));
            int nDeltaX = XJSON_GetInt(XJSON_GetObject(pRoot, "deltaX"));
            int nNotchesY = DirectGate_Desktop_WheelNotches(&pDesktop->nWheelAccumY, nDeltaY);
            int nNotchesX = DirectGate_Desktop_WheelNotches(&pDesktop->nWheelAccumX, nDeltaX);

            if (nNotchesY != 0)
            {
                DWORD nWheel = (DWORD)(-nNotchesY * WHEEL_DELTA);
                if (bRelative) DirectGate_Desktop_SendMouseRelative(MOUSEEVENTF_WHEEL, nWheel, nDx, nDy);
                else DirectGate_Desktop_SendMouseInput(MOUSEEVENTF_WHEEL, nWheel, nScreenX, nScreenY);
            }

            if (nNotchesX != 0)
            {
                DWORD nWheel = (DWORD)(nNotchesX * WHEEL_DELTA);
                if (bRelative) DirectGate_Desktop_SendMouseRelative(MOUSEEVENTF_HWHEEL, nWheel, nDx, nDy);
                else DirectGate_Desktop_SendMouseInput(MOUSEEVENTF_HWHEEL, nWheel, nScreenX, nScreenY);
            }
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
    else if (xstrcmp(pAction, "text"))
    {
        const char *pText = XJSON_GetString(XJSON_GetObject(pRoot, "text"));
        if (xstrused(pText)) DirectGate_Desktop_WinTypeText(pText);
    }
    else if (xstrcmp(pAction, "lock"))
    {
        DirectGate_Desktop_WinSetLock(VK_CAPITAL, XJSON_GetObject(pRoot, "caps"));
        DirectGate_Desktop_WinSetLock(VK_NUMLOCK, XJSON_GetObject(pRoot, "num"));
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
