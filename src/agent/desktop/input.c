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

#ifdef DIRECTGATE_DESKTOP_HAS_WAYLAND
#include "wayland.h"
#endif

#if defined(_WIN32)
#include "elevated.h"
#endif

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
/* Largest pixel delta a single wheel event may contribute. A real notch is
 * ~100px and a trackpad sample is a handful, so this only ever clips input
 * that was never going to be a scroll. */
#define DIRECTGATE_DESKTOP_MAX_WHEEL_DELTA 100000

/* Browsers report wheel motion in pixels: a discrete mouse notch is ~100px
 * while trackpads emit a stream of 1-10px samples. Platforms that inject
 * discrete wheel clicks (X11 buttons 4-7, Windows WHEEL_DELTA) accumulate
 * the pixels and emit whole notches, so a trackpad swipe no longer turns
 * every sample into a full click. (macOS scrolls in pixel units natively.) */
static int DirectGate_Desktop_WheelNotches(int32_t *pAccum, int nDelta)
{
    /* The delta arrives straight off the wire, so it cannot be trusted to be
     * a plausible scroll: accumulating an arbitrary int overflows the counter,
     * which is undefined behaviour and traps on a hardened build. A single
     * event is never worth more than a few hundred notches. */
    if (nDelta > DIRECTGATE_DESKTOP_MAX_WHEEL_DELTA) nDelta = DIRECTGATE_DESKTOP_MAX_WHEEL_DELTA;
    else if (nDelta < -DIRECTGATE_DESKTOP_MAX_WHEEL_DELTA) nDelta = -DIRECTGATE_DESKTOP_MAX_WHEEL_DELTA;

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

/* Which side decides what a keystroke types.
 *
 * A browser reports both what a key IS (`code`, the physical position) and
 * what it PRODUCED (`key`, after the viewer's own layout). Sending the
 * character makes the viewer's layout win; sending the position makes the
 * host's layout win. Neither is right on its own: a host set to Georgian
 * would never type Georgian for a viewer on a Latin keyboard, and a viewer
 * on a Georgian keyboard would never get Georgian out of a Latin host.
 *
 * So the choice is made per keystroke, by asking whether the viewer's layout
 * did anything to this key. If the character is exactly what the position
 * would give on a plain US layout - or the key produces no character at all,
 * like Enter or F5 - the position is sent and the host's layout decides,
 * which is what makes a Georgian host type Georgian. If the character
 * differs, the viewer's layout produced it deliberately and the character is
 * sent instead, which is what keeps a Georgian (or German, or AZERTY)
 * keyboard typing what it says on the keycaps. */
typedef struct directgate_evdev_key_ {
    const char *pCode;   /* W3C KeyboardEvent.code */
    uint16_t nEvdev;     /* Linux input-event-codes.h KEY_* */
    char cPlain;         /* what a US layout types unshifted, 0 if nothing */
    char cShifted;       /* ... and with Shift */
} directgate_evdev_key_t;

static const directgate_evdev_key_t g_EvdevKeys[] = {
    { "Escape", 1, 0, 0 },
    { "Digit1", 2, '1', '!' }, { "Digit2", 3, '2', '@' }, { "Digit3", 4, '3', '#' },
    { "Digit4", 5, '4', '$' }, { "Digit5", 6, '5', '%' }, { "Digit6", 7, '6', '^' },
    { "Digit7", 8, '7', '&' }, { "Digit8", 9, '8', '*' }, { "Digit9", 10, '9', '(' },
    { "Digit0", 11, '0', ')' },
    { "Minus", 12, '-', '_' }, { "Equal", 13, '=', '+' },
    { "Backspace", 14, 0, 0 }, { "Tab", 15, 0, 0 },
    { "KeyQ", 16, 'q', 'Q' }, { "KeyW", 17, 'w', 'W' }, { "KeyE", 18, 'e', 'E' },
    { "KeyR", 19, 'r', 'R' }, { "KeyT", 20, 't', 'T' }, { "KeyY", 21, 'y', 'Y' },
    { "KeyU", 22, 'u', 'U' }, { "KeyI", 23, 'i', 'I' }, { "KeyO", 24, 'o', 'O' },
    { "KeyP", 25, 'p', 'P' },
    { "BracketLeft", 26, '[', '{' }, { "BracketRight", 27, ']', '}' },
    { "Enter", 28, 0, 0 }, { "ControlLeft", 29, 0, 0 },
    { "KeyA", 30, 'a', 'A' }, { "KeyS", 31, 's', 'S' }, { "KeyD", 32, 'd', 'D' },
    { "KeyF", 33, 'f', 'F' }, { "KeyG", 34, 'g', 'G' }, { "KeyH", 35, 'h', 'H' },
    { "KeyJ", 36, 'j', 'J' }, { "KeyK", 37, 'k', 'K' }, { "KeyL", 38, 'l', 'L' },
    { "Semicolon", 39, ';', ':' }, { "Quote", 40, '\'', '"' }, { "Backquote", 41, '`', '~' },
    { "ShiftLeft", 42, 0, 0 }, { "Backslash", 43, '\\', '|' },
    { "KeyZ", 44, 'z', 'Z' }, { "KeyX", 45, 'x', 'X' }, { "KeyC", 46, 'c', 'C' },
    { "KeyV", 47, 'v', 'V' }, { "KeyB", 48, 'b', 'B' }, { "KeyN", 49, 'n', 'N' },
    { "KeyM", 50, 'm', 'M' },
    { "Comma", 51, ',', '<' }, { "Period", 52, '.', '>' }, { "Slash", 53, '/', '?' },
    { "ShiftRight", 54, 0, 0 }, { "NumpadMultiply", 55, '*', '*' },
    { "AltLeft", 56, 0, 0 }, { "Space", 57, ' ', ' ' }, { "CapsLock", 58, 0, 0 },
    { "F1", 59, 0, 0 }, { "F2", 60, 0, 0 }, { "F3", 61, 0, 0 }, { "F4", 62, 0, 0 },
    { "F5", 63, 0, 0 }, { "F6", 64, 0, 0 }, { "F7", 65, 0, 0 }, { "F8", 66, 0, 0 },
    { "F9", 67, 0, 0 }, { "F10", 68, 0, 0 },
    { "NumLock", 69, 0, 0 }, { "ScrollLock", 70, 0, 0 },
    { "Numpad7", 71, '7', '7' }, { "Numpad8", 72, '8', '8' }, { "Numpad9", 73, '9', '9' },
    { "NumpadSubtract", 74, '-', '-' },
    { "Numpad4", 75, '4', '4' }, { "Numpad5", 76, '5', '5' }, { "Numpad6", 77, '6', '6' },
    { "NumpadAdd", 78, '+', '+' },
    { "Numpad1", 79, '1', '1' }, { "Numpad2", 80, '2', '2' }, { "Numpad3", 81, '3', '3' },
    { "Numpad0", 82, '0', '0' }, { "NumpadDecimal", 83, '.', '.' },
    { "IntlBackslash", 86, '\\', '|' }, { "F11", 87, 0, 0 }, { "F12", 88, 0, 0 },
    { "IntlRo", 89, 0, 0 }, { "Convert", 92, 0, 0 }, { "KanaMode", 93, 0, 0 },
    { "NonConvert", 94, 0, 0 }, { "NumpadEnter", 96, 0, 0 }, { "ControlRight", 97, 0, 0 },
    { "NumpadDivide", 98, '/', '/' }, { "PrintScreen", 99, 0, 0 }, { "AltRight", 100, 0, 0 },
    { "Home", 102, 0, 0 }, { "ArrowUp", 103, 0, 0 }, { "PageUp", 104, 0, 0 },
    { "ArrowLeft", 105, 0, 0 }, { "ArrowRight", 106, 0, 0 }, { "End", 107, 0, 0 },
    { "ArrowDown", 108, 0, 0 }, { "PageDown", 109, 0, 0 }, { "Insert", 110, 0, 0 },
    { "Delete", 111, 0, 0 }, { "NumpadEqual", 117, '=', '=' }, { "Pause", 119, 0, 0 },
    { "NumpadComma", 121, ',', ',' }, { "Lang1", 122, 0, 0 }, { "Lang2", 123, 0, 0 },
    { "IntlYen", 124, 0, 0 }, { "MetaLeft", 125, 0, 0 }, { "MetaRight", 126, 0, 0 },
    { "ContextMenu", 127, 0, 0 },
    { "F13", 183, 0, 0 }, { "F14", 184, 0, 0 }, { "F15", 185, 0, 0 }, { "F16", 186, 0, 0 },
    { "F17", 187, 0, 0 }, { "F18", 188, 0, 0 }, { "F19", 189, 0, 0 }, { "F20", 190, 0, 0 },
    { "F21", 191, 0, 0 }, { "F22", 192, 0, 0 }, { "F23", 193, 0, 0 }, { "F24", 194, 0, 0 },
};

static const directgate_evdev_key_t* DirectGate_Desktop_EvdevKey(const char *pCode)
{
    if (!xstrused(pCode)) return NULL;

    for (size_t i = 0; i < sizeof(g_EvdevKeys) / sizeof(g_EvdevKeys[0]); i++)
    {
        /* First byte before the call: this runs on every keystroke, and it
         * turns a hundred string comparisons into a handful. */
        if (g_EvdevKeys[i].pCode[0] != pCode[0]) continue;
        if (xstrcmp(g_EvdevKeys[i].pCode, pCode)) return &g_EvdevKeys[i];
    }

    return NULL;
}

/* The evdev code to send for this event, or 0 when the character has to be
 * sent instead. See the note above for which is which. */
static uint16_t DirectGate_Desktop_PhysicalKey(xjson_obj_t *pRoot)
{
    const char *pCode = XJSON_GetString(XJSON_GetObject(pRoot, "code"));
    const directgate_evdev_key_t *pKey = DirectGate_Desktop_EvdevKey(pCode);
    if (pKey == NULL) return 0;

    const char *pChar = XJSON_GetString(XJSON_GetObject(pRoot, "key"));
    uint32_t nCodepoint = 0;
    size_t nUsed = xstrused(pChar) ? DirectGate_Desktop_UTF8Decode(pChar, &nCodepoint) : 0;

    /* No single character to compare: a named key ("Enter", "F5", "Shift")
     * means the same thing under every layout, so position it is. An unusable
     * value ("Dead", "Unidentified", "Process") is the IME talking, and the
     * physical key is the only honest thing left to send. */
    if (!nUsed || pChar[nUsed] != '\0') return pKey->nEvdev;

    /* Anything the viewer's layout renamed goes as a character. This is the
     * whole non-Latin case - a Georgian keyboard reports "ა" where the US one
     * reports "a" - and equally the Latin layouts that move keys around, so a
     * German "z" is not typed as the "y" its position holds. */
    if (nCodepoint > 0x7FU) return 0;
    if ((char)nCodepoint != pKey->cPlain && (char)nCodepoint != pKey->cShifted) return 0;

    return pKey->nEvdev;
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

/* Collects the unassigned keycodes of the host keymap into the scratch pool.
 * Runs once per session; a keymap with no free slot leaves the pool empty and
 * out-of-layout keysyms are then simply unreachable, as before. */
static void DirectGate_Desktop_X11ProbeScratch(directgate_desktop_t *pDesktop)
{
    Display *pDisplay = (Display*)pDesktop->pDisplay;
    pDesktop->bScratchProbed = XTRUE;

    int nMinCode = 0, nMaxCode = 0, nSymsPerCode = 0;
    XDisplayKeycodes(pDisplay, &nMinCode, &nMaxCode);
    if (nMaxCode < nMinCode) return;

    KeySym *pMap = XGetKeyboardMapping(pDisplay, (KeyCode)nMinCode,
        nMaxCode - nMinCode + 1, &nSymsPerCode);
    if (pMap == NULL || nSymsPerCode <= 0)
    {
        if (pMap != NULL) XFree(pMap);
        return;
    }

    /* Walk down from the top: the high keycodes are the ones layouts leave
     * empty, so the pool stays clear of anything the host actually uses. */
    for (int i = nMaxCode; i >= nMinCode &&
         pDesktop->nScratchCount < DIRECTGATE_DESKTOP_MAX_SCRATCH_KEYS; i--)
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

        if (!bFree) continue;

        directgate_desktop_scratch_key_t *pSlot =
            &pDesktop->scratchKeys[pDesktop->nScratchCount++];

        pSlot->nKeycode = (uint32_t)i;
        pSlot->nKeysym = NoSymbol;
        pSlot->nUsedSeq = 0;
        pSlot->bHeld = XFALSE;
    }

    XFree(pMap);
}

/* Returns the keycode a previous call already bound to this keysym, or 0.
 * Refreshes the slot's recency so a character in active use is never picked
 * as the one to recycle. */
static KeyCode DirectGate_Desktop_X11FindScratch(directgate_desktop_t *pDesktop, KeySym sym)
{
    /* Deliberately does not probe. An empty pool simply finds nothing, so a
       session that only ever types characters its host layout already has
       never pays for the keymap round trip. */
    for (uint32_t i = 0; i < pDesktop->nScratchCount; i++)
    {
        directgate_desktop_scratch_key_t *pSlot = &pDesktop->scratchKeys[i];
        if (pSlot->nKeysym != (uint64_t)sym) continue;

        pSlot->nUsedSeq = ++pDesktop->nScratchSeq;
        return (KeyCode)pSlot->nKeycode;
    }

    return 0;
}

/* Binds a keysym missing from the host layout to a spare keycode.
 *
 * Rebinding one shared keycode per keystroke is what made fast typing lose
 * characters: XChangeKeyboardMapping is asynchronous from the receiving
 * application's point of view. Toolkits reload their keymap when the server
 * announces the change, and a synthetic press that lands inside that reload
 * resolves against a keymap in flux - the keystroke arrives, resolves to
 * nothing, and is dropped. Typing a non-Latin script through a single slot
 * triggers that race on every single letter.
 *
 * Each distinct keysym therefore keeps its own slot, and the caller looks the
 * pool up before coming here. An alphabet is bound once during warm-up and
 * reused from then on, so the steady state issues no keymap changes at all,
 * and the rare rebind lands on the least recently used slot - many keystrokes
 * away from anything an application is still processing. Slots with an
 * outstanding injected press are never reused, so a key can never change
 * meaning while it is down. */
static KeyCode DirectGate_Desktop_X11BindScratch(directgate_desktop_t *pDesktop, KeySym sym)
{
    Display *pDisplay = (Display*)pDesktop->pDisplay;
    directgate_desktop_scratch_key_t *pVictim = NULL;

    /* First keysym the host layout cannot reach pays for the pool, once. */
    if (!pDesktop->bScratchProbed) DirectGate_Desktop_X11ProbeScratch(pDesktop);

    for (uint32_t i = 0; i < pDesktop->nScratchCount; i++)
    {
        directgate_desktop_scratch_key_t *pSlot = &pDesktop->scratchKeys[i];
        if (pSlot->bHeld) continue;

        /* Prefer a never-used slot, then the coldest one. Used slots always
           carry a non-zero sequence, so the recency test alone never picks a
           used slot over a free one. */
        if (pVictim == NULL) pVictim = pSlot;
        else if (pSlot->nKeysym == NoSymbol && pVictim->nKeysym != NoSymbol) pVictim = pSlot;
        else if (pSlot->nUsedSeq < pVictim->nUsedSeq) pVictim = pSlot;
    }

    /* No pool at all, or every slot is holding a physically-down key.
     * Refusing is correct: any rebind here would silently change what that
     * held key produces. */
    if (pVictim == NULL) return 0;

    KeySym syms[2] = { sym, sym };
    XChangeKeyboardMapping(pDisplay, (int)pVictim->nKeycode, 2, syms, 1);
    XSync(pDisplay, XFALSE);

    pVictim->nKeysym = (uint64_t)sym;
    pVictim->nUsedSeq = ++pDesktop->nScratchSeq;

    return (KeyCode)pVictim->nKeycode;
}

static void DirectGate_Desktop_X11MarkScratchHeld(directgate_desktop_t *pDesktop,
                                                  KeyCode code, xbool_t bHeld)
{
    for (uint32_t i = 0; i < pDesktop->nScratchCount; i++)
    {
        if (pDesktop->scratchKeys[i].nKeycode != (uint32_t)code) continue;
        pDesktop->scratchKeys[i].bHeld = bHeld;
        return;
    }
}

/* Resolves a keysym to a keycode reachable in the ACTIVE layout group.
 * Injected keycodes are interpreted with the host's current group, so a
 * match found in another group (e.g. a Georgian symbol on a host whose
 * active layout is US) would type the wrong character — such keysyms go
 * through the scratch binding instead. When the keysym only exists on the
 * shifted level (e.g. "!" on the "1" key), *pNeedShift is set so the
 * caller can synthesize Shift when the client is not physically holding it. */
static KeyCode DirectGate_Desktop_X11ResolveKeysym(directgate_desktop_t *pDesktop,
                                                   KeySym sym, xbool_t *pNeedShift,
                                                   xbool_t bAllowBind)
{
    Display *pDisplay = (Display*)pDesktop->pDisplay;
    *pNeedShift = XFALSE;

    /* A keysym the pool already holds resolves straight from there: that
     * binding is what the injected keycode will be interpreted with anyway,
     * and short-circuiting keeps the per-keystroke cost flat instead of
     * rescanning the whole keymap for every non-Latin character. */
    KeyCode bound = DirectGate_Desktop_X11FindScratch(pDesktop, sym);
    if (bound != 0) return bound;

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

    /* Releases never allocate: the pool lookup above already returned if this
     * keysym owns a slot, so there is nothing left to release. Binding one
     * here would rewrite the keymap for a key that was never pressed. */
    if (!bAllowBind) return 0;

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

/* What the browser code that is currently down was injected as: an X11
 * keycode on an Xorg session, a keysym on a Wayland one. Both backends need
 * the same bookkeeping - a key that went down must be releasable by the code
 * that pressed it, and everything still down must be released when the
 * session ends - so the table is shared and only the value differs. */
static void DirectGate_Desktop_RememberKey(directgate_desktop_t *pDesktop,
                                           const char *pCode, uint32_t nValue,
                                           xbool_t bPhysical)
{
    if (!xstrused(pCode)) return;

    for (uint32_t i = 0; i < pDesktop->nHeldKeyCount; i++)
    {
        if (xstrcmp(pDesktop->heldKeys[i].sCode, pCode))
        {
            pDesktop->heldKeys[i].nKeycode = nValue;
            pDesktop->heldKeys[i].bPhysical = bPhysical;
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
    pSlot->nKeycode = nValue;
    pSlot->bPhysical = bPhysical;
}

/* @p pPhysical (may be NULL) receives how the value was injected, which is
 * what tells a Wayland release which portal call to make. */
static uint32_t DirectGate_Desktop_ForgetKey(directgate_desktop_t *pDesktop,
                                             const char *pCode,
                                             xbool_t *pPhysical)
{
    if (!xstrused(pCode)) return 0;

    for (uint32_t i = 0; i < pDesktop->nHeldKeyCount; i++)
    {
        if (!xstrcmp(pDesktop->heldKeys[i].sCode, pCode)) continue;

        uint32_t nValue = pDesktop->heldKeys[i].nKeycode;
        if (pPhysical != NULL) *pPhysical = pDesktop->heldKeys[i].bPhysical;

        memmove(&pDesktop->heldKeys[i], &pDesktop->heldKeys[i + 1U],
            sizeof(pDesktop->heldKeys[0]) * (pDesktop->nHeldKeyCount - i - 1U));

        pDesktop->nHeldKeyCount--;
        return nValue;
    }

    return 0;
}

static KeyCode DirectGate_Desktop_X11SendKeysym(directgate_desktop_t *pDesktop,
                                                KeySym sym, xbool_t bDown)
{
    Display *pDisplay = (Display*)pDesktop->pDisplay;
    xbool_t bNeedShift = XFALSE;

    KeyCode code = DirectGate_Desktop_X11ResolveKeysym(pDesktop, sym, &bNeedShift, bDown);
    if (code == 0) return 0;

    directgate_xtest_key_fn pKeyFn = (directgate_xtest_key_fn)pDesktop->pFakeKey;
    KeyCode shiftCode = XKeysymToKeycode(pDisplay, XK_Shift_L);

    /* Wrap only the press: the character is produced at press time, and a
     * physically held client Shift already arrives as its own key event. */
    xbool_t bWrapShift = bDown && bNeedShift && shiftCode != 0 &&
        !DirectGate_Desktop_X11ShiftDown(pDisplay);

    /* Pin the slot for as long as the injected key is down, so a keysym typed
     * meanwhile cannot take this keycode over and change what is being held. */
    DirectGate_Desktop_X11MarkScratchHeld(pDesktop, code, bDown);

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
        KeyCode tracked = (KeyCode)DirectGate_Desktop_ForgetKey(pDesktop, pCode, NULL);
        if (tracked != 0)
        {
            DirectGate_Desktop_X11MarkScratchHeld(pDesktop, tracked, XFALSE);
            ((directgate_xtest_key_fn)pDesktop->pFakeKey)((Display*)pDesktop->pDisplay, tracked, XFALSE, CurrentTime);
            return;
        }
    }

    /* The host's own layout decides this one. X11 keycodes are the evdev code
     * plus 8 under the evdev rules every Linux Xorg uses, so the key goes in
     * at its position and the server applies the layout - the same path a
     * keyboard plugged into that machine takes. */
    uint16_t nEvdev = DirectGate_Desktop_PhysicalKey(pRoot);
    if (nEvdev != 0)
    {
        KeyCode code = (KeyCode)(nEvdev + 8U);
        ((directgate_xtest_key_fn)pDesktop->pFakeKey)((Display*)pDesktop->pDisplay, code, bDown ? XTRUE : XFALSE, CurrentTime);

        if (bDown) DirectGate_Desktop_RememberKey(pDesktop, pCode, code, XTRUE);
        return;
    }

    KeySym sym = DirectGate_Desktop_KeySymFromJson(pRoot);
    if (sym == NoSymbol) return;

    KeyCode used = DirectGate_Desktop_X11SendKeysym(pDesktop, sym, bDown);
    if (bDown && used != 0) DirectGate_Desktop_RememberKey(pDesktop, pCode, used, XFALSE);
}

void DirectGate_Desktop_ReleaseHeldKeys(directgate_desktop_t *pDesktop)
{
    XCHECK_VOID_NL((pDesktop != NULL));

#ifdef DIRECTGATE_DESKTOP_HAS_WAYLAND
    /* A Wayland session has no display connection, and skipping it here is
     * how a key that went down without its release stayed down: the portal's
     * virtual keyboard holds it for the life of the session, so a lost Shift
     * release turned the whole machine upper-case until the agent itself was
     * restarted. */
    if (pDesktop->pWayland != NULL)
    {
        directgate_wl_portal_t *pPortal = DirectGate_WL_SourcePortal((directgate_wl_source_t*)pDesktop->pWayland);
        if (pPortal != NULL)
        {
            for (uint32_t i = 0; i < pDesktop->nHeldKeyCount; i++)
            {
                const directgate_desktop_held_key_t *pHeld = &pDesktop->heldKeys[i];
                if (pHeld->bPhysical) DirectGate_WL_PortalKeycode(pPortal, (int32_t)pHeld->nKeycode, XFALSE);
                else DirectGate_WL_PortalKeysym(pPortal, (int32_t)pHeld->nKeycode, XFALSE);
            }
        }

        pDesktop->nHeldKeyCount = 0;
        return;
    }
#endif

    if (pDesktop->pDisplay == NULL || pDesktop->pFakeKey == NULL) return;

    Display *pDisplay = (Display*)pDesktop->pDisplay;
    directgate_xtest_key_fn pKeyFn = (directgate_xtest_key_fn)pDesktop->pFakeKey;

    for (uint32_t i = 0; i < pDesktop->nHeldKeyCount; i++)
        pKeyFn(pDisplay, (KeyCode)pDesktop->heldKeys[i].nKeycode, XFALSE, CurrentTime);

    pDesktop->nHeldKeyCount = 0;
    for (uint32_t i = 0; i < pDesktop->nScratchCount; i++)
        pDesktop->scratchKeys[i].bHeld = XFALSE;

    XFlush(pDisplay);
}

/* How long a key may stay down with nothing else arriving before it is taken
 * to be stuck. Nothing legitimate looks like this: a key held on purpose is
 * held while something else is happening - the mouse moves, another key
 * repeats - and every one of those refreshes the clock. What does look like
 * this is a release that never arrived, and the cost of getting it wrong in
 * that direction is a machine that types in capitals until it is rebooted. */
#define DIRECTGATE_DESKTOP_HELD_KEY_IDLE_MS 30000

xbool_t DirectGate_Desktop_ExpireHeldKeys(directgate_desktop_t *pDesktop)
{
    XCHECK_NL((pDesktop != NULL), XFALSE);
    if (!pDesktop->nHeldKeyCount || !pDesktop->nLastInputMs) return XFALSE;

    uint64_t nNowMs = XTime_GetMs();
    if (nNowMs <= pDesktop->nLastInputMs) return XFALSE;
    if (nNowMs - pDesktop->nLastInputMs < DIRECTGATE_DESKTOP_HELD_KEY_IDLE_MS) return XFALSE;

    xlogw("Releasing %u desktop key(s) still held after %u seconds of silence: sid(%u)",
        pDesktop->nHeldKeyCount, DIRECTGATE_DESKTOP_HELD_KEY_IDLE_MS / 1000U, pDesktop->nSessionId);

    DirectGate_Desktop_ReleaseHeldKeys(pDesktop);
    return XTRUE;
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

#ifdef DIRECTGATE_DESKTOP_HAS_WAYLAND
/* Input on Wayland goes back through the same portal session the screen is
 * being captured from. Nothing here can reach the compositor directly - that
 * is the point of the design - so every event is a D-Bus notification against
 * the granted session, and the coordinates are the stream's, which on this
 * backend is also the screen because the portal grants exactly one.
 *
 * The keysyms are XKB keysyms, the same values the X11 path resolves, so the
 * whole key-resolution layer above is reused rather than rewritten. */
static int DirectGate_Desktop_WaylandHandleInput(directgate_session_t *pSession, xjson_obj_t *pRoot)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;
    directgate_wl_portal_t *pPortal = DirectGate_WL_SourcePortal((directgate_wl_source_t*)pDesktop->pWayland);
    if (pPortal == NULL) return XAPI_CONTINUE;

    const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
    const char *pEvent = XJSON_GetString(XJSON_GetObject(pRoot, "event"));

    if (xstrcmp(pAction, "pointer"))
    {
        uint32_t nSequence = XJSON_GetU32(XJSON_GetObject(pRoot, "sequence"));
        if (nSequence != 0U && pDesktop->nPointerSequence != 0U &&
            (int32_t)(nSequence - pDesktop->nPointerSequence) <= 0)
            return XAPI_CONTINUE;

        if (nSequence != 0U) pDesktop->nPointerSequence = nSequence;

        /* The capture rectangle is the frame of reference for both branches
         * below: the browser's relative deltas are host pixels of it, and the
         * cursor position echoed back is measured in it. */
        uint32_t nCaptureW = pDesktop->nCaptureWidth ? pDesktop->nCaptureWidth : 1U;
        uint32_t nCaptureH = pDesktop->nCaptureHeight ? pDesktop->nCaptureHeight : 1U;

        xbool_t bRelative = XJSON_GetBool(XJSON_GetObject(pRoot, "relative"));
        xbool_t bMoved = XFALSE;

        if (bRelative)
        {
            /* Mouse capture. The portal does have relative motion, but the
             * compositor accelerates it, so the pointer would outrun the
             * cursor the browser draws from these same deltas and clicks
             * would land where nothing appears to be. Integrating them here
             * and sending the result as absolute motion keeps the two
             * identical. */
            int nDx = XJSON_GetInt(XJSON_GetObject(pRoot, "dx"));
            int nDy = XJSON_GetInt(XJSON_GetObject(pRoot, "dy"));

            /* Capture starts from wherever the pointer was last put, which is
             * the click that asked for the lock. A session that has not moved
             * the pointer at all has nothing to start from, and there the
             * pointer really is moved to the middle rather than merely
             * assumed to be there: the position echoed below is what the
             * browser draws its cursor at, and a guess would put that cursor
             * somewhere the clicks do not land. */
            if (!pDesktop->bWlPointerValid)
            {
                pDesktop->nWlPointerX = (double)nCaptureW / 2.0;
                pDesktop->nWlPointerY = (double)nCaptureH / 2.0;
                pDesktop->bWlPointerValid = XTRUE;
                bMoved = XTRUE;
            }

            if (nDx != 0 || nDy != 0)
            {
                pDesktop->nWlPointerX += (double)nDx;
                pDesktop->nWlPointerY += (double)nDy;
                bMoved = XTRUE;
            }
        }
        else
        {
            int nX = XJSON_GetInt(XJSON_GetObject(pRoot, "x"));
            int nY = XJSON_GetInt(XJSON_GetObject(pRoot, "y"));

            if (nX < 0) nX = 0;
            if (nY < 0) nY = 0;

            if (pDesktop->nFrameWidth > 0 && (uint32_t)nX >= pDesktop->nFrameWidth)
                nX = (int)pDesktop->nFrameWidth - 1;
            if (pDesktop->nFrameHeight > 0 && (uint32_t)nY >= pDesktop->nFrameHeight)
                nY = (int)pDesktop->nFrameHeight - 1;

            /* Frame pixels are the encoded size, which is not the captured
             * size whenever the stream was scaled down to fit the preset. */
            pDesktop->nWlPointerX = (pDesktop->nFrameWidth > 1) ? ((double)nX * (double)nCaptureW) / (double)pDesktop->nFrameWidth : 0.0;
            pDesktop->nWlPointerY = (pDesktop->nFrameHeight > 1) ? ((double)nY * (double)nCaptureH) / (double)pDesktop->nFrameHeight : 0.0;

            pDesktop->bWlPointerValid = XTRUE;
            bMoved = XTRUE;
        }

        /* Off the edge of the shared screen there is nothing to click, and a
         * position that keeps growing would take seconds of mouse movement to
         * walk back onto the screen. */
        if (pDesktop->nWlPointerX < 0.0) pDesktop->nWlPointerX = 0.0;
        if (pDesktop->nWlPointerY < 0.0) pDesktop->nWlPointerY = 0.0;

        if (pDesktop->nWlPointerX > (double)(nCaptureW - 1U)) pDesktop->nWlPointerX = (double)(nCaptureW - 1U);
        if (pDesktop->nWlPointerY > (double)(nCaptureH - 1U)) pDesktop->nWlPointerY = (double)(nCaptureH - 1U);

        if (bMoved)
        {
            /* Stream-relative, not desktop-relative. FrameToScreenX adds the
             * monitor's position on the desktop, which is right for XTest and
             * wrong here: the portal measures from the corner of the stream
             * it granted. On a second monitor that offset is the whole width
             * of the first one, so every click landed off-screen.
             *
             * Scale against the size PipeWire actually negotiated, not the
             * size the portal described. With display scaling the two differ
             * the portal reports logical pixels while the stream carries
             * physical ones - and the pointer then lands short of where it
             * was put, by exactly the scale factor. */
            uint32_t nStreamW = nCaptureW;
            uint32_t nStreamH = nCaptureH;
            DirectGate_WL_SourceSize((directgate_wl_source_t*)pDesktop->pWayland, &nStreamW, &nStreamH);

            /* The portal stack does not agree with itself about which of the
             * two sizes an absolute coordinate is in, and under a display
             * scale that costs the screen its far edges.
             *
             * xdg-desktop-portal's check_position accepts a coordinate only
             * while it is inside the size the *portal* advertised for the
             * stream - the compositor's logical pixels, 1536x864 on a 1920
             * panel at 125% - and refuses anything else as "Invalid
             * position". The compositor then reads that same number as
             * *stream* pixels and divides it by the scale to get back to
             * logical. So the largest coordinate that survives the first
             * step lands at 1/scale of the way across the screen, and no
             * absolute coordinate exists that reaches the bottom-right
             * corner at all.
             *
             * The absolute call therefore carries as much as it can, and the
             * rest is added as one relative motion, which has no position to
             * check. A virtual pointer is not accelerated - mutter passes the
             * delta through as its own unaccelerated value - so the two
             * together land on the requested pixel exactly. Without display
             * scaling the two sizes are equal, the residual is zero, and this
             * is the plain absolute call it has always been. */
            double nStreamX = (pDesktop->nWlPointerX * (double)nStreamW) / (double)nCaptureW;
            double nStreamY = (pDesktop->nWlPointerY * (double)nStreamH) / (double)nCaptureH;

            /* The check is exclusive, so the far edge is refused as well. */
            if (nStreamX > (double)(nCaptureW - 1U)) nStreamX = (double)(nCaptureW - 1U);
            if (nStreamY > (double)(nCaptureH - 1U)) nStreamY = (double)(nCaptureH - 1U);

            /* Where that puts the pointer by the compositor's own arithmetic,
             * and how far short of the target it leaves it. Never negative:
             * the clamp above only ever lowers the coordinate. */
            double nResidualX = pDesktop->nWlPointerX - (nStreamX * (double)nCaptureW) / (double)nStreamW;
            double nResidualY = pDesktop->nWlPointerY - (nStreamY * (double)nCaptureH) / (double)nStreamH;

            /* Says what the three frames of reference actually were, at the
             * one moment it matters: the pointer pushed into the far edge.
             * A display scale makes the encoded picture, the rectangle the
             * portal described and the stream PipeWire negotiated three
             * different sizes, and when the pointer stops short of an edge
             * the only question is which of them the arithmetic used. Once
             * every two seconds, and only at the edge, so an ordinary
             * session never prints it at all. */
            xbool_t bAtEdge = ((pDesktop->nWlPointerX >= (double)(nCaptureW - 2U)) ||
                               (pDesktop->nWlPointerY >= (double)(nCaptureH - 2U))) ? XTRUE : XFALSE;

            if (bAtEdge)
            {
                uint64_t nNowMs = XTime_GetMs();
                if (nNowMs - pDesktop->nWlPointerLogMs >= 2000ULL)
                {
                    pDesktop->nWlPointerLogMs = nNowMs;
                    xlogi("Wayland pointer reached an edge: sid(%u), frame(%ux%u), capture(%ux%u), "
                        "stream(%ux%u), pointer(%.1f,%.1f), sent(%.1f,%.1f), residual(%.1f,%.1f)",
                        pDesktop->nSessionId, pDesktop->nFrameWidth, pDesktop->nFrameHeight,
                        nCaptureW, nCaptureH, nStreamW, nStreamH,
                        pDesktop->nWlPointerX, pDesktop->nWlPointerY, nStreamX, nStreamY,
                        nResidualX, nResidualY);
                }
            }

            /* Addressed to the screen actually being watched, not to whichever
             * one the portal happened to list first. */
            DirectGate_WL_PortalPointerMotion(pPortal,
                DirectGate_WL_SourceActiveNode((directgate_wl_source_t*)pDesktop->pWayland), nStreamX, nStreamY);

            /* Whatever the absolute call could not express. Half a pixel is
             * the threshold because anything smaller cannot move the pointer
             * anyway, and sending it every frame would be noise on the bus. */
            if (nResidualX >= 0.5 || nResidualY >= 0.5)
                DirectGate_WL_PortalPointerMotionRelative(pPortal, nResidualX, nResidualY);
        }

        if (xstrcmp(pEvent, "button"))
        {
            uint32_t nButton = XJSON_GetU32(XJSON_GetObject(pRoot, "button"));
            int32_t nCode = DirectGate_WL_PortalButtonCode(nButton);

            if (nCode != 0)
                DirectGate_WL_PortalPointerButton(pPortal, nCode,
                    XJSON_GetBool(XJSON_GetObject(pRoot, "down")) ? XTRUE : XFALSE);
        }
        else if (xstrcmp(pEvent, "wheel"))
        {
            /* The portal takes scroll distance, not the wheel-button clicks
             * X11 emulates, so the notch accumulator is bypassed and the
             * deltas go through as they arrived. */
            double nDx = (double)XJSON_GetInt(XJSON_GetObject(pRoot, "deltaX"));
            double nDy = (double)XJSON_GetInt(XJSON_GetObject(pRoot, "deltaY"));
            if (nDx != 0.0 || nDy != 0.0) DirectGate_WL_PortalPointerAxis(pPortal, nDx, nDy);
        }

        /* Under mouse capture the browser has hidden its own pointer and is
         * drawing the host cursor itself, so it has to be told where that
         * cursor now is - including when the clamp above refused to move it
         * any further. Absolute motion needs no echo: the browser already
         * knows, its own pointer is the cursor. */
        if (bRelative)
        {
            DirectGate_Desktop_SendCursorPosition(pSession,
                pDesktop->nCaptureX + (int)pDesktop->nWlPointerX,
                pDesktop->nCaptureY + (int)pDesktop->nWlPointerY, nSequence);
        }

        return XAPI_CONTINUE;
    }

    if (xstrcmp(pAction, "key"))
    {
        const char *pCode = XJSON_GetString(XJSON_GetObject(pRoot, "code"));
        xbool_t bDown = XJSON_GetBool(XJSON_GetObject(pRoot, "down")) ? XTRUE : XFALSE;

        /* Release exactly what was pressed, which is why the code that
         * pressed it is what the release is looked up by.
         *
         * The browser reports the character a key produced, so typing a
         * capital and letting Shift go first - which is how anyone types
         * fast - sends "A" down and "a" up. The portal reaches a shifted
         * keysym by pressing Shift itself, so releasing "a" released the
         * letter and left the compositor's own Shift down: from there the
         * whole machine typed in capitals, and nothing the viewer pressed
         * could clear it because that Shift was not theirs to release. */
        if (!bDown)
        {
            xbool_t bWasPhysical = XFALSE;
            uint32_t nTracked = DirectGate_Desktop_ForgetKey(pDesktop, pCode, &bWasPhysical);

            if (nTracked != 0)
            {
                if (bWasPhysical) DirectGate_WL_PortalKeycode(pPortal, (int32_t)nTracked, XFALSE);
                else DirectGate_WL_PortalKeysym(pPortal, (int32_t)nTracked, XFALSE);

                return XAPI_CONTINUE;
            }
        }

        /* The host's own layout decides this one; see the note on
         * DirectGate_Desktop_PhysicalKey. */
        uint16_t nEvdev = DirectGate_Desktop_PhysicalKey(pRoot);
        if (nEvdev != 0)
        {
            DirectGate_WL_PortalKeycode(pPortal, (int32_t)nEvdev, bDown);
            if (bDown) DirectGate_Desktop_RememberKey(pDesktop, pCode, nEvdev, XTRUE);

            return XAPI_CONTINUE;
        }

        KeySym sym = DirectGate_Desktop_KeySymFromJson(pRoot);
        if (sym == NoSymbol) return XAPI_CONTINUE;

        DirectGate_WL_PortalKeysym(pPortal, (int32_t)sym, bDown);

        /* Tracked so the session cannot end with a key still down; the portal
         * keyboard outlives any single keystroke. */
        if (bDown) DirectGate_Desktop_RememberKey(pDesktop, pCode, (uint32_t)sym, XFALSE);

        return XAPI_CONTINUE;
    }

    /* Whole strings arrive as their own action - that is how anything the
     * browser cannot express as a keystroke gets typed, which is most of a
     * non-Latin keyboard. Handling only "key" meant those characters were
     * dropped without a trace, and the keyboard looked dead. */
    if (xstrcmp(pAction, "text"))
    {
        const char *pText = XJSON_GetString(XJSON_GetObject(pRoot, "text"));
        if (!xstrused(pText)) return XAPI_CONTINUE;

        for (size_t i = 0; pText[i] != '\0'; )
        {
            uint32_t nCodepoint = 0;
            size_t nUsed = DirectGate_Desktop_UTF8Decode(&pText[i], &nCodepoint);

            if (!nUsed) break;
            i += nUsed;

            KeySym sym = DirectGate_Desktop_KeySymFromCodepoint(nCodepoint);
            if (sym == NoSymbol) continue;

            DirectGate_WL_PortalKeysym(pPortal, (int32_t)sym, XTRUE);
            DirectGate_WL_PortalKeysym(pPortal, (int32_t)sym, XFALSE);
        }
    }

    return XAPI_CONTINUE;
}
#endif

int DirectGate_Desktop_HandleInput(directgate_session_t *pSession, const uint8_t *pPayload, size_t nPayloadLength)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (!pDesktop->bRunning || !pDesktop->bInputReady)
        return XAPI_CONTINUE;

    if (pPayload == NULL || !nPayloadLength)
        return XAPI_CONTINUE;

    /* Feeds the held-key watchdog: any event at all, not just a keystroke,
     * proves the viewer is still there and that a key they are holding is
     * being held on purpose. */
    pDesktop->nLastInputMs = XTime_GetMs();

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

#ifdef DIRECTGATE_DESKTOP_HAS_WAYLAND
    if (pDesktop->pWayland != NULL)
    {
        int nWlStatus = DirectGate_Desktop_WaylandHandleInput(pSession, pRoot);
        XJSON_Destroy(&json);
        free(pJsonText);
        return nWlStatus;
    }
#endif

    /* Past here is the X11 path, which needs a display connection. */
    if (pDesktop->pDisplay == NULL)
    {
        XJSON_Destroy(&json);
        free(pJsonText);
        return XAPI_CONTINUE;
    }

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

/*
 * Windows refuses synthesized input from this process in two situations the
 * operator hits constantly, and the two refusals do not behave alike - which
 * is the whole reason this is not a one-liner.
 *
 *   - The secure desktop (a UAC prompt, the lock screen). SendInput returns
 *     zero, because the calling thread's desktop is not the one receiving
 *     input. The return value is a usable signal, so the direct call goes
 *     first and only what it rejected is re-sent through the helper.
 *
 *   - A higher-integrity foreground window (Task Manager, an elevated app) on
 *     the ordinary desktop. UIPI drops the event and says nothing: MSDN is
 *     explicit that SendInput "fails when it is blocked by UIPI" and that
 *     "neither GetLastError nor the return value will indicate the failure".
 *     Nothing after the call can detect it, so it has to be decided before,
 *     and the direct SendInput is then skipped entirely - issuing it as well
 *     would double every event on any window that does accept input.
 *
 * Both used to fail silently, because none of these calls looked at the return
 * value at all; that is what "the screen froze" was.
 */
static void DirectGate_Desktop_WinSendInput(INPUT *pInputs, UINT nCount)
{
    /* Latched so a blocked drag logs once instead of hundreds of times, and
     * clears again as soon as input flows, which makes each transition into
     * and out of privileged UI visible in the log exactly once. */
    static xbool_t bRefused = XFALSE;

    if (DirectGate_Elevated_Ready() && DirectGate_Elevated_ForegroundOutranksAgent())
    {
        if (!bRefused)
        {
            bRefused = XTRUE;
            xlogi("Elevated window has focus, routing input through the elevated helper");
        }

        for (UINT i = 0; i < nCount; i++)
            (void)DirectGate_Elevated_SendInput(&pInputs[i]);

        return;
    }

    UINT nSent = SendInput(nCount, pInputs, sizeof(INPUT));
    if (nSent == nCount)
    {
        bRefused = XFALSE;
        return;
    }

    DWORD nError = GetLastError();
    if (!DirectGate_Elevated_Ready())
    {
        if (!bRefused)
        {
            const char *pReason = DirectGate_Elevated_Reason();
            bRefused = XTRUE;

            xlogw("Windows refused injected input and no elevated helper is available: "
                "err(%lu), reason(%s)", (unsigned long)nError, pReason ? pReason : "unknown");
        }

        return;
    }

    if (!bRefused)
    {
        bRefused = XTRUE;
        xlogi("Secure desktop is up, routing input through the elevated helper: err(%lu)", (unsigned long)nError);
    }

    for (UINT i = nSent; i < nCount; i++)
        (void)DirectGate_Elevated_SendInput(&pInputs[i]);
}

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
    DirectGate_Desktop_WinSendInput(&input, 1);
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
    DirectGate_Desktop_WinSendInput(&input, 1);
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
    DirectGate_Desktop_WinSendInput(&input, 1);
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
        DirectGate_Desktop_WinSendInput(inputs, 2);
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
            /* Both calls are desktop-scoped and refused while the secure
               desktop is up; the helper is on that desktop, so it answers
               with the real position and moves the real pointer. */
            POINT cursorPoint;
            int nCursorX = 0, nCursorY = 0;
            xbool_t bHavePos = XFALSE;

            if (GetCursorPos(&cursorPoint))
            {
                nCursorX = (int)cursorPoint.x;
                nCursorY = (int)cursorPoint.y;
                bHavePos = XTRUE;
            }
            else bHavePos = DirectGate_Elevated_GetCursorPos(&nCursorX, &nCursorY);

            if (bHavePos)
            {
                if (DirectGate_Desktop_ClampCursorToCapture(pDesktop, &nCursorX, &nCursorY))
                {
                    /* Same split as DirectGate_Desktop_WinSendInput: an
                       elevated foreground window has to be decided before the
                       call, the secure desktop reports itself after it. */
                    if (DirectGate_Elevated_Ready() && DirectGate_Elevated_ForegroundOutranksAgent())
                        (void)DirectGate_Elevated_SetCursorPos(nCursorX, nCursorY);
                    else if (!SetCursorPos(nCursorX, nCursorY))
                        (void)DirectGate_Elevated_SetCursorPos(nCursorX, nCursorY);
                }

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
    else if (xstrcmp(pAction, "sas"))
    {
        /* Ctrl+Alt+Del cannot be synthesized at all - the secure attention
         * sequence is reserved by the kernel precisely so that nothing can
         * fake it. The only legitimate route is SendSAS from a LocalSystem
         * service, which is the launcher; this just asks it. */
        if (!DirectGate_Elevated_SendSAS())
            xlogw("Ctrl+Alt+Del requested but the DirectGate service could not be reached");
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
