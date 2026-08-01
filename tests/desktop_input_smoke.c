/*!
 * @file directgate-agent/tests/desktop_input_smoke.c
 * @brief Keyboard mapping tests for the X11 desktop input path.
 *
 * Exercises the browser-key -> X11 keysym translation without an X server:
 * punctuation and non-Latin characters must resolve through the Unicode
 * codepoint rule (the old XStringToKeysym(".") lookup silently dropped
 * every non-alphanumeric key), and named/function/modifier keys must map
 * to their dedicated keysyms.
 */

#include <stdio.h>
#include <string.h>

#include "src/agent/desktop/input.c"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "desktop_input_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

/* input.c references these desktop.c/priv.h symbols; the keysym mapping
 * under test never reaches them. */
xbool_t DirectGate_Desktop_ClampCursorToCapture(const directgate_desktop_t *pDesktop,
                                                int *pScreenX, int *pScreenY)
{
    (void)pDesktop; (void)pScreenX; (void)pScreenY;
    return XFALSE;
}

void DirectGate_Desktop_SendCursorPosition(directgate_session_t *pSession,
                                           int nScreenX, int nScreenY,
                                           uint32_t nSequence)
{
    (void)pSession; (void)nScreenX; (void)nScreenY; (void)nSequence;
}

static KeySym MapKey(const char *pKey, const char *pCode)
{
    xjson_obj_t *pRoot = XJSON_NewObject(NULL, NULL, XFALSE);
    if (pRoot == NULL) return NoSymbol;

    if (pKey != NULL) XJSON_AddString(pRoot, "key", pKey);
    if (pCode != NULL) XJSON_AddString(pRoot, "code", pCode);

    KeySym sym = DirectGate_Desktop_KeySymFromJson(pRoot);
    XJSON_FreeObject(pRoot);
    return sym;
}

int main(void)
{
    /* UTF-8 decoding. */
    uint32_t nCodepoint = 0;
    CHECK(DirectGate_Desktop_UTF8Decode(".", &nCodepoint) == 1 && nCodepoint == 0x2EU,
        "ASCII decode failed");
    CHECK(DirectGate_Desktop_UTF8Decode("\xC3\xA9", &nCodepoint) == 2 && nCodepoint == 0xE9U,
        "2-byte decode failed (e-acute)");
    CHECK(DirectGate_Desktop_UTF8Decode("\xE1\x83\x90", &nCodepoint) == 3 && nCodepoint == 0x10D0U,
        "3-byte decode failed (Georgian an)");
    CHECK(DirectGate_Desktop_UTF8Decode("\xF0\x9F\x98\x80", &nCodepoint) == 4 && nCodepoint == 0x1F600U,
        "4-byte decode failed (emoji)");
    CHECK(DirectGate_Desktop_UTF8Decode("\xFF", &nCodepoint) == 0,
        "invalid lead byte accepted");
    CHECK(DirectGate_Desktop_UTF8Decode("\xC3\x28", &nCodepoint) == 0,
        "invalid continuation byte accepted");

    /* Codepoint -> keysym rule. */
    CHECK(DirectGate_Desktop_KeySymFromCodepoint('a') == XK_a, "letter keysym");
    CHECK(DirectGate_Desktop_KeySymFromCodepoint('.') == XK_period, "period keysym");
    CHECK(DirectGate_Desktop_KeySymFromCodepoint(0x10D0U) == (KeySym)0x010010D0UL,
        "unicode keysym offset");
    CHECK(DirectGate_Desktop_KeySymFromCodepoint('\n') == XK_Return, "newline keysym");
    CHECK(DirectGate_Desktop_KeySymFromCodepoint('\t') == XK_Tab, "tab keysym");
    CHECK(DirectGate_Desktop_KeySymFromCodepoint(0x1BU) == NoSymbol, "control chars rejected");

    /* Punctuation from the browser `key` value (the reported Ubuntu bug). */
    CHECK(MapKey(".", "Period") == XK_period, "key '.' did not map");
    CHECK(MapKey(",", "Comma") == XK_comma, "key ',' did not map");
    CHECK(MapKey(";", "Semicolon") == XK_semicolon, "key ';' did not map");
    CHECK(MapKey("/", "Slash") == XK_slash, "key '/' did not map");
    CHECK(MapKey("!", "Digit1") == XK_exclam, "key '!' did not map");
    CHECK(MapKey("?", "Slash") == XK_question, "key '?' did not map");
    CHECK(MapKey("-", "Minus") == XK_minus, "key '-' did not map");
    CHECK(MapKey("'", "Quote") == XK_apostrophe, "key '\\'' did not map");
    CHECK(MapKey("\"", "Quote") == XK_quotedbl, "key '\"' did not map");
    CHECK(MapKey("Dead", "Quote") == XK_apostrophe,
        "dead Quote key did not fall back to its physical key");

    /* Letters, digits, space keep working. */
    CHECK(MapKey("a", "KeyA") == XK_a, "key 'a' did not map");
    CHECK(MapKey("A", "KeyA") == XK_A, "key 'A' did not map");
    CHECK(MapKey("5", "Digit5") == XK_5, "key '5' did not map");
    CHECK(MapKey(" ", "Space") == XK_space, "space did not map");

    /* Non-Latin characters map through the Unicode keysym offset. */
    CHECK(MapKey("\xE1\x83\x90", "KeyA") == (KeySym)0x010010D0UL,
        "Georgian character did not map");

    /* Named editing/navigation keys. */
    CHECK(MapKey("Enter", "Enter") == XK_Return, "Enter did not map");
    CHECK(MapKey("Backspace", "Backspace") == XK_BackSpace, "Backspace did not map");
    CHECK(MapKey("Insert", "Insert") == XK_Insert, "Insert did not map");
    CHECK(MapKey("CapsLock", "CapsLock") == XK_Caps_Lock, "CapsLock did not map");
    CHECK(MapKey("ContextMenu", "ContextMenu") == XK_Menu, "ContextMenu did not map");
    CHECK(MapKey("PrintScreen", "PrintScreen") == XK_Print, "PrintScreen did not map");

    /* Function keys resolve through the keysym-name fallback. */
    CHECK(MapKey("F1", "F1") == XK_F1, "F1 did not map");
    CHECK(MapKey("F5", "F5") == XK_F5, "F5 did not map");
    CHECK(MapKey("F12", "F12") == XK_F12, "F12 did not map");

    /* Modifier side selection follows the physical code. */
    CHECK(MapKey("Shift", "ShiftLeft") == XK_Shift_L, "ShiftLeft did not map");
    CHECK(MapKey("Shift", "ShiftRight") == XK_Shift_R, "ShiftRight did not map");
    CHECK(MapKey("Control", "ControlRight") == XK_Control_R, "ControlRight did not map");
    CHECK(MapKey("Alt", "AltLeft") == XK_Alt_L, "AltLeft did not map");
    CHECK(MapKey("Meta", "MetaLeft") == XK_Super_L, "MetaLeft did not map");
    CHECK(MapKey("AltGraph", "AltRight") == XK_ISO_Level3_Shift, "AltGraph did not map");

    /* Modifiers must also resolve from their `code` spelling: a client that
     * lets go of every held key after the browser swallowed a keyup has no
     * `key` value to report. Dropping those releases left the modifier
     * latched down for the rest of the session. */
    CHECK(MapKey("ControlLeft", "ControlLeft") == XK_Control_L, "code-named ControlLeft did not map");
    CHECK(MapKey("ShiftRight", "ShiftRight") == XK_Shift_R, "code-named ShiftRight did not map");
    CHECK(MapKey("AltLeft", "AltLeft") == XK_Alt_L, "code-named AltLeft did not map");
    CHECK(MapKey("MetaRight", "MetaRight") == XK_Super_R, "code-named MetaRight did not map");
    CHECK(MapKey(NULL, "ControlRight") == XK_Control_R, "code-only ControlRight did not map");
    CHECK(MapKey("Unidentified", "ShiftLeft") == XK_Shift_L, "code-only ShiftLeft did not map");

    /* Unusable key values fall back to the physical code. */
    CHECK(MapKey("Unidentified", "KeyQ") == XK_q, "code fallback KeyQ failed");
    CHECK(MapKey("Unidentified", "Digit3") == XK_3, "code fallback Digit3 failed");
    CHECK(MapKey("Unidentified", "F24") == NoSymbol, "unexpected mapping for unknown code");
    CHECK(MapKey(NULL, NULL) == NoSymbol, "empty event mapped to a keysym");

    /* Held-key bookkeeping: a release must target the keycode the press
     * used, keyed by the physical `code`, so a shifted press and unshifted
     * release cannot leave the key stuck and auto-repeating. */
    directgate_desktop_t desktop;
    memset(&desktop, 0, sizeof(desktop));
    DirectGate_Desktop_X11RememberKey(&desktop, "ShiftRight", 62);
    DirectGate_Desktop_X11RememberKey(&desktop, "KeyA", 38);
    CHECK(desktop.nHeldKeyCount == 2, "held keys not tracked");
    /* A repeat press of the same code overwrites, never grows the table. */
    DirectGate_Desktop_X11RememberKey(&desktop, "KeyA", 38);
    CHECK(desktop.nHeldKeyCount == 2, "repeat press grew the held-key table");
    /* Release resolves to the exact keycode the press recorded. */
    CHECK(DirectGate_Desktop_X11ForgetKey(&desktop, "KeyA") == 38, "wrong keycode for release");
    CHECK(desktop.nHeldKeyCount == 1, "released key still tracked");
    CHECK(DirectGate_Desktop_X11ForgetKey(&desktop, "KeyA") == 0, "double release returned a keycode");
    /* An unknown code (press never seen) reports no keycode. */
    CHECK(DirectGate_Desktop_X11ForgetKey(&desktop, "KeyZ") == 0, "unknown code returned a keycode");
    CHECK(DirectGate_Desktop_X11ForgetKey(&desktop, "ShiftRight") == 62, "wrong keycode for ShiftRight");
    CHECK(desktop.nHeldKeyCount == 0, "held-key table not empty after releases");
    /* No display attached: teardown release is a guarded no-op, not a crash,
     * and cannot inject, so it leaves the table for the real teardown. */
    DirectGate_Desktop_X11RememberKey(&desktop, "ShiftLeft", 50);
    DirectGate_Desktop_ReleaseHeldKeys(&desktop);
    CHECK(desktop.nHeldKeyCount == 1, "guarded teardown must not drop untracked keys");

    /* The table drops the oldest entry instead of overflowing. */
    memset(&desktop, 0, sizeof(desktop));
    for (int i = 0; i < DIRECTGATE_DESKTOP_MAX_HELD_KEYS + 4; i++)
    {
        char sCode[DIRECTGATE_DESKTOP_KEY_CODE_LEN];
        snprintf(sCode, sizeof(sCode), "K%d", i);
        DirectGate_Desktop_X11RememberKey(&desktop, sCode, (KeyCode)(8 + (i & 0xFF)));
    }
    CHECK(desktop.nHeldKeyCount == DIRECTGATE_DESKTOP_MAX_HELD_KEYS,
        "held-key table overflowed its bound");

    /* Wheel accumulation: trackpad samples collect into whole notches. */
    int32_t nAccum = 0;
    int nTotal = 0;
    for (int i = 0; i < 25; i++) nTotal += DirectGate_Desktop_WheelNotches(&nAccum, 8);
    CHECK(nTotal == 2, "trackpad accumulation produced wrong notch count");

    nAccum = 0;
    CHECK(DirectGate_Desktop_WheelNotches(&nAccum, 120) == 1, "mouse notch did not pass through");
    CHECK(DirectGate_Desktop_WheelNotches(&nAccum, -120) == -1, "direction flip lost a notch");

    /* Scratch keycodes for keysyms outside the host layout. Only the paths
     * that resolve without rewriting the keymap are reachable here: an actual
     * rebind needs a live X server. Those are exactly the paths that keep
     * fast typing intact, so they are the ones worth pinning down. */
    memset(&desktop, 0, sizeof(desktop));
    desktop.bScratchProbed = XTRUE;
    desktop.nScratchCount = 3;
    for (uint32_t i = 0; i < desktop.nScratchCount; i++)
        desktop.scratchKeys[i].nKeycode = 200 + i;

    const KeySym georgianAn = (KeySym)(0x10D0U | 0x01000000UL);
    const KeySym georgianBan = (KeySym)(0x10D1U | 0x01000000UL);

    /* Nothing bound yet: the lookup must not claim a slot. It is what keeps a
     * release from rewriting the keymap for a key that was never pressed. */
    CHECK(DirectGate_Desktop_X11FindScratch(&desktop, georgianAn) == 0,
        "lookup allocated a scratch keycode");
    CHECK(desktop.scratchKeys[0].nKeysym == NoSymbol,
        "lookup bound a keysym to a scratch slot");

    /* A slot already carrying the keysym is reused as-is. This is what makes
     * repeat typing in a non-Latin script issue no keymap changes at all, and
     * therefore stop losing characters to the asynchronous remap. */
    desktop.scratchKeys[1].nKeysym = (uint64_t)georgianAn;
    CHECK(DirectGate_Desktop_X11FindScratch(&desktop, georgianAn) == 201,
        "bound keysym did not reuse its slot");
    CHECK(desktop.scratchKeys[1].nUsedSeq > desktop.scratchKeys[0].nUsedSeq,
        "reuse did not refresh the slot's recency");

    /* A slot whose injected press is still outstanding must never be handed
     * to another keysym: the held key would change meaning mid-press. With
     * every slot pinned there is no safe choice, so binding is refused. */
    for (uint32_t i = 0; i < desktop.nScratchCount; i++)
    {
        desktop.scratchKeys[i].nKeysym = (uint64_t)(georgianAn + i);
        desktop.scratchKeys[i].bHeld = XTRUE;
    }
    CHECK(DirectGate_Desktop_X11FindScratch(&desktop, georgianBan) == 201,
        "held slot holding the keysym was not reused");
    CHECK(DirectGate_Desktop_X11BindScratch(&desktop, (KeySym)0x0100FFFFUL) == 0,
        "rebound a scratch slot while its key was held");

    DirectGate_Desktop_X11MarkScratchHeld(&desktop, 201, XFALSE);
    CHECK(desktop.scratchKeys[1].bHeld == XFALSE, "release did not unpin the slot");
    CHECK(desktop.scratchKeys[0].bHeld == XTRUE, "release unpinned the wrong slot");

    printf("desktop_input_smoke: OK\n");
    return 0;
}
