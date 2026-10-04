/* The continuity-counter replay shield, on its own and through the packet
 * header check that every encrypted package passes.
 *
 * A session's counters do not arrive on one wire: they move between the relay
 * WebSocket, the reliable data channel and a post-upgrade peer connection, and
 * the input channel is unordered by design. The window therefore has to accept
 * a counter that was merely overtaken while still refusing one that was already
 * used - the exact boundary between those two is what this test pins down.
 *
 * The scoped half locks the per-scope isolation, the session-epoch reset and
 * the header fields a peer must supply before its counter is even considered. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "src/common/e2e.h"
#include "src/common/protocol.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "e2e_ccwin_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#define SESSION_ID 5U

/* Build the decrypted inner package DirectGate_Proto_CheckCC is handed, with
 * the counter fields spelled out so a test can leave any of them off. */
static int build_scoped(xbyte_buffer_t *pOut, const char *pScope, uint32_t nCC,
                        uint32_t nScopedCC, xbool_t bWithEpoch, uint32_t nEpoch)
{
    xjson_obj_t *pHeader = DirectGate_Proto_BuildData(SESSION_ID);
    CHECK(pHeader != NULL, "build a data header");

    if (xstrused(pScope)) XJSON_AddString(pHeader, "ccScope", pScope);
    if (nScopedCC > 0) XJSON_AddU32(pHeader, "sc", nScopedCC);
    if (bWithEpoch) XJSON_AddU32(pHeader, "ce", nEpoch);
    if (nCC > 0) XJSON_AddU32(pHeader, "cc", nCC);

    XByteBuffer_Reset(pOut);
    xbool_t bOk = DirectGate_Proto_Build(pOut, pHeader, NULL, 0, XFALSE);
    XJSON_FreeObject(pHeader);
    CHECK(bOk, "serialize the inner package");

    return 0;
}

static int test_window_basics(void)
{
    directgate_ccwin_t win;
    DirectGate_E2E_ResetCCWindow(&win);

    CHECK(!DirectGate_E2E_AcceptCC(NULL, 1), "a NULL window accepts nothing");
    CHECK(!DirectGate_E2E_AcceptCC(&win, 0), "counter zero is never a valid counter");
    CHECK(win.nHighest == 0, "a refused counter must not arm an empty window");

    CHECK(DirectGate_E2E_AcceptCC(&win, 1), "the first counter of a scope is accepted");
    CHECK(win.nHighest == 1, "the first counter becomes the high-water mark");
    CHECK(!DirectGate_E2E_AcceptCC(&win, 1), "replaying the first counter is refused");

    CHECK(DirectGate_E2E_AcceptCC(&win, 2), "the next counter in order is accepted");
    CHECK(DirectGate_E2E_AcceptCC(&win, 4), "a counter that skips a gap is accepted");
    CHECK(win.nHighest == 4, "the high-water mark follows the newest counter");
    CHECK(DirectGate_E2E_AcceptCC(&win, 3), "a packet that was merely overtaken is accepted");
    CHECK(!DirectGate_E2E_AcceptCC(&win, 3), "filling the same gap twice is a replay");
    CHECK(!DirectGate_E2E_AcceptCC(&win, 4), "replaying the high-water mark is refused");
    CHECK(win.nHighest == 4, "accepting a late packet must not move the high-water mark");

    DirectGate_E2E_ResetCCWindow(&win);
    CHECK(win.nHighest == 0 && win.nBitmap == 0, "a reset window forgets every counter");
    CHECK(DirectGate_E2E_AcceptCC(&win, 4), "a reset window accepts a counter it just refused");

    DirectGate_E2E_ResetCCWindow(NULL);
    return 0;
}

static int test_window_edges(void)
{
    directgate_ccwin_t win;
    DirectGate_E2E_ResetCCWindow(&win);

    /* Arm the window high enough that the whole span below it is expressible. */
    CHECK(DirectGate_E2E_AcceptCC(&win, 1000), "arm the window");

    CHECK(DirectGate_E2E_AcceptCC(&win, 1000 - (XE2E_CC_WINDOW_SIZE - 1)),
        "the oldest counter still inside the window is accepted");
    CHECK(!DirectGate_E2E_AcceptCC(&win, 1000 - XE2E_CC_WINDOW_SIZE),
        "a counter one step older than the window is refused");
    CHECK(!DirectGate_E2E_AcceptCC(&win, 1),
        "a counter far below the window is refused");

    /* A jump of exactly the window size drops the seen-bitmap, which is only
     * safe because everything it recorded is now out of range anyway. The gap
     * the jump opened is genuinely unseen, so it has to stay usable. */
    DirectGate_E2E_ResetCCWindow(&win);
    CHECK(DirectGate_E2E_AcceptCC(&win, 1000), "arm the window again");
    CHECK(DirectGate_E2E_AcceptCC(&win, 999), "record a second counter below the mark");
    CHECK(DirectGate_E2E_AcceptCC(&win, 1000 + XE2E_CC_WINDOW_SIZE),
        "a jump of exactly the window size is accepted");
    CHECK(!DirectGate_E2E_AcceptCC(&win, 1000),
        "a seen counter is not resurrected by a full-size jump");
    CHECK(!DirectGate_E2E_AcceptCC(&win, 999),
        "a counter below the old mark stays refused after a full-size jump");
    CHECK(DirectGate_E2E_AcceptCC(&win, 1001),
        "the gap a full-size jump opened is unseen and stays usable");

    /* One step short of that, the previous high-water mark is the last bit. */
    DirectGate_E2E_ResetCCWindow(&win);
    CHECK(DirectGate_E2E_AcceptCC(&win, 1000), "arm the window once more");
    CHECK(DirectGate_E2E_AcceptCC(&win, 1000 + XE2E_CC_WINDOW_SIZE - 1),
        "a jump one short of the window size is accepted");
    CHECK(!DirectGate_E2E_AcceptCC(&win, 1000),
        "a jump one short of the window size still remembers the old mark");
    CHECK(DirectGate_E2E_AcceptCC(&win, 1001),
        "a jump one short of the window size keeps the rest of the window open");

    /* The whole window, filled out of order, then replayed in full. */
    DirectGate_E2E_ResetCCWindow(&win);
    CHECK(DirectGate_E2E_AcceptCC(&win, 2000), "arm a window to fill completely");
    for (uint32_t i = 1; i < XE2E_CC_WINDOW_SIZE; i++)
        CHECK(DirectGate_E2E_AcceptCC(&win, 2000 - i), "every counter inside the window is accepted once");
    for (uint32_t i = 0; i < XE2E_CC_WINDOW_SIZE; i++)
        CHECK(!DirectGate_E2E_AcceptCC(&win, 2000 - i), "a full window replays nothing");

    /* The counter is a uint32; the arithmetic must not wrap near its top. */
    DirectGate_E2E_ResetCCWindow(&win);
    CHECK(DirectGate_E2E_AcceptCC(&win, UINT32_MAX), "the largest counter is accepted");
    CHECK(DirectGate_E2E_AcceptCC(&win, UINT32_MAX - 1),
        "a late packet below the largest counter is accepted");
    CHECK(!DirectGate_E2E_AcceptCC(&win, UINT32_MAX),
        "the largest counter cannot be replayed");
    CHECK(!DirectGate_E2E_AcceptCC(&win, 1),
        "a counter from the bottom of the range cannot pass a window at the top");

    DirectGate_E2E_ResetCCWindow(&win);
    CHECK(DirectGate_E2E_AcceptCC(&win, 1), "arm a window at the bottom of the range");
    CHECK(DirectGate_E2E_AcceptCC(&win, UINT32_MAX),
        "a jump across the whole range is accepted, not treated as a wrap");
    CHECK(!DirectGate_E2E_AcceptCC(&win, 1),
        "the bottom of the range is outside the window after that jump");

    return 0;
}

static int test_scoped_header(void)
{
    directgate_e2e_t e2e;
    xbyte_buffer_t pkg;

    DirectGate_E2E_Init(&e2e);
    XByteBuffer_Init(&pkg, 0, 0);

    /* Unscoped packets fall back to the legacy single counter. */
    if (build_scoped(&pkg, NULL, 5, 0, XFALSE, 0)) return 1;
    CHECK(DirectGate_Proto_CheckCC(&pkg, &e2e), "an unscoped counter is accepted");
    CHECK(!DirectGate_Proto_CheckCC(&pkg, &e2e), "an unscoped counter is not accepted twice");

    if (build_scoped(&pkg, NULL, 0, 0, XFALSE, 0)) return 1;
    CHECK(!DirectGate_Proto_CheckCC(&pkg, &e2e), "a packet with no counter at all is refused");

    if (build_scoped(&pkg, "wobble", 6, 1, XTRUE, 0)) return 1;
    CHECK(!DirectGate_Proto_CheckCC(&pkg, &e2e), "an unknown counter scope is refused");

    if (build_scoped(&pkg, "session", 6, 0, XTRUE, 0)) return 1;
    CHECK(!DirectGate_Proto_CheckCC(&pkg, &e2e), "a scoped packet without its scoped counter is refused");

    /* Each scope carries its own window, so the same scoped counter value is
     * fresh in all three. */
    if (build_scoped(&pkg, "session", 10, 1, XTRUE, 0)) return 1;
    CHECK(DirectGate_Proto_CheckCC(&pkg, &e2e), "the first session counter is accepted");
    CHECK(!DirectGate_Proto_CheckCC(&pkg, &e2e), "a session counter is not accepted twice");

    if (build_scoped(&pkg, "input", 11, 1, XTRUE, 0)) return 1;
    CHECK(DirectGate_Proto_CheckCC(&pkg, &e2e), "the input scope has its own window");

    if (build_scoped(&pkg, "signal", 12, 1, XFALSE, 0)) return 1;
    CHECK(DirectGate_Proto_CheckCC(&pkg, &e2e), "the signal scope has its own window");
    CHECK(!DirectGate_Proto_CheckCC(&pkg, &e2e), "a signal counter is not accepted twice");

    /* Signalling outlives a session, so its window must not be reset by one. */
    if (build_scoped(&pkg, "session", 13, 1, XTRUE, 1)) return 1;
    CHECK(DirectGate_Proto_CheckCC(&pkg, &e2e), "a new session epoch restarts the session counter");

    if (build_scoped(&pkg, "input", 14, 1, XTRUE, 1)) return 1;
    CHECK(DirectGate_Proto_CheckCC(&pkg, &e2e), "a new session epoch restarts the input counter");

    if (build_scoped(&pkg, "signal", 15, 1, XFALSE, 0)) return 1;
    CHECK(!DirectGate_Proto_CheckCC(&pkg, &e2e), "a new session epoch must not reopen the signal window");

    /* An epoch below the active one is a replayed session, not a new one. */
    if (build_scoped(&pkg, "session", 16, 2, XTRUE, 0)) return 1;
    CHECK(!DirectGate_Proto_CheckCC(&pkg, &e2e), "a packet from a stale session epoch is refused");

    if (build_scoped(&pkg, "session", 17, 1, XTRUE, 1)) return 1;
    CHECK(!DirectGate_Proto_CheckCC(&pkg, &e2e), "the stale epoch did not disturb the active window");

    XByteBuffer_Clear(&pkg);
    DirectGate_E2E_Clear(&e2e);
    return 0;
}

/* The scope has to be one of the three names exactly, a scoped packet still needs its packet counter, and
 * accepting it records that counter in the legacy window as well. */
static int test_scoped_edges(void)
{
    directgate_e2e_t e2e;
    xbyte_buffer_t pkg;
    DirectGate_E2E_Init(&e2e);
    XByteBuffer_Init(&pkg, 0, 0);

    const char *pNearMisses[] = { "sessions", "signal ", "inputs", "sessio", "Signal", "input\\u0000" };
    for (size_t i = 0; i < sizeof(pNearMisses) / sizeof(pNearMisses[0]); i++)
    {
        if (build_scoped(&pkg, pNearMisses[i], 20 + (uint32_t)i, 1, XTRUE, 0)) return 1;
        CHECK(!DirectGate_Proto_CheckCC(&pkg, &e2e), "a scope that only resembles a known one is refused");
    }

    if (build_scoped(&pkg, "session", 0, 1, XTRUE, 0)) return 1;
    CHECK(!DirectGate_Proto_CheckCC(&pkg, &e2e), "a scoped packet without its packet counter is refused");
    if (build_scoped(&pkg, "signal", 0, 1, XFALSE, 0)) return 1;
    CHECK(!DirectGate_Proto_CheckCC(&pkg, &e2e), "a signal packet without its packet counter is refused");
    CHECK(e2e.rxSessionWindow.nHighest == 0 && e2e.rxSignalWindow.nHighest == 0 && e2e.rxWindow.nHighest == 0,
        "the refusals left every window as it was");

    if (build_scoped(&pkg, "session", 40, 1, XTRUE, 0)) return 1;
    CHECK(DirectGate_Proto_CheckCC(&pkg, &e2e), "a complete scoped packet is accepted");
    CHECK(e2e.rxSessionWindow.nHighest == 1 && e2e.rxWindow.nHighest == 40, "both its counters are recorded");

    if (build_scoped(&pkg, "signal", 41, 1, XFALSE, 0)) return 1;
    CHECK(DirectGate_Proto_CheckCC(&pkg, &e2e), "a complete signal packet is accepted");
    CHECK(e2e.rxSignalWindow.nHighest == 1 && e2e.rxWindow.nHighest == 41, "both of its counters are recorded too");

    XByteBuffer_Clear(&pkg);
    DirectGate_E2E_Clear(&e2e);
    return 0;
}

/* The counters the agent emits have to be the ones the window expects: an
 * off-by-one between the two sides drops every packet of a session. */
static int test_emitted_counters(void)
{
    directgate_e2e_t tx;
    directgate_e2e_t rx;
    xbyte_buffer_t pkg;

    DirectGate_E2E_Init(&tx);
    DirectGate_E2E_Init(&rx);
    XByteBuffer_Init(&pkg, 0, 0);

    for (uint32_t i = 0; i < 200; i++)
    {
        xjson_obj_t *pHeader = DirectGate_Proto_BuildData(SESSION_ID);
        CHECK(pHeader != NULL, "build a header to count");
        CHECK(DirectGate_Proto_AddCC(pHeader, &tx, 0), "stamp the header with its counters");

        XByteBuffer_Reset(&pkg);
        xbool_t bOk = DirectGate_Proto_Build(&pkg, pHeader, NULL, 0, XFALSE);
        XJSON_FreeObject(pHeader);
        CHECK(bOk, "serialize the stamped package");

        CHECK(DirectGate_Proto_CheckCC(&pkg, &rx), "every counter the sender emits is accepted once");
    }

    CHECK(tx.nTxPacketId == 200 && tx.nTxSessionPacketId == 200,
        "the sender's counters advance once per package");
    CHECK(rx.rxSessionWindow.nHighest == 200,
        "the receiver's session window tracks the sender's counter");

    /* A session restart resets the sender's scoped counter; the receiver has to
     * follow the epoch rather than treat the restart as a flood of replays. */
    xjson_obj_t *pHeader = DirectGate_Proto_BuildData(SESSION_ID);
    CHECK(pHeader != NULL, "build a header for the next epoch");
    CHECK(DirectGate_Proto_AddCC(pHeader, &tx, 1), "stamp a header in a new epoch");

    XByteBuffer_Reset(&pkg);
    xbool_t bOk = DirectGate_Proto_Build(&pkg, pHeader, NULL, 0, XFALSE);
    XJSON_FreeObject(pHeader);
    CHECK(bOk, "serialize the new-epoch package");

    CHECK(tx.nTxSessionPacketId == 1, "a new epoch restarts the sender's scoped counter");
    CHECK(DirectGate_Proto_CheckCC(&pkg, &rx), "the receiver accepts the restarted counter");

    XByteBuffer_Clear(&pkg);
    DirectGate_E2E_Clear(&tx);
    DirectGate_E2E_Clear(&rx);
    return 0;
}

/* Wraps a header written out by hand in the preamble CheckCC reads */
static int build_raw(xbyte_buffer_t *pOut, const char *pHeader)
{
    uint32_t nLength = (uint32_t)strlen(pHeader);
    uint8_t preamble[4] = { (uint8_t)nLength, (uint8_t)(nLength >> 8), (uint8_t)(nLength >> 16), (uint8_t)(nLength >> 24) };

    XByteBuffer_Reset(pOut);
    CHECK(XByteBuffer_Add(pOut, preamble, sizeof(preamble)) > 0, "add the preamble");
    CHECK(XByteBuffer_Add(pOut, (const uint8_t*)pHeader, nLength) > 0, "add the header");
    return 0;
}

static char g_sLogged[4096];
static size_t g_nLogged;

static int collect_log(const char *pLog, size_t nLength, xlog_flag_t eFlag, void *pCtx)
{
    (void)eFlag;
    (void)pCtx;
    if (g_nLogged + nLength < sizeof(g_sLogged))
    {
        memcpy(g_sLogged + g_nLogged, pLog, nLength);
        g_nLogged += nLength;
        g_sLogged[g_nLogged] = '\0';
    }
    return 0;
}

/* A refusal names the scope the peer sent. The header tree it came from used to be freed before the
 * message was formatted, so the log read freed memory: garbage at best, a crash under ASan. */
static int test_refusal_logs(void)
{
    directgate_e2e_t e2e;
    xbyte_buffer_t pkg;
    DirectGate_E2E_Init(&e2e);
    XByteBuffer_Init(&pkg, 0, 0);

    xlog_init("e2e_ccwin_smoke", XLOG_ALL, XFALSE);
    xlog_screen(XFALSE);
    xlog_callback(collect_log, NULL);

    /* Flat headers take the scan, the nested member sends the same header through the parser */
    const char *pPads[] = { "", ",\"pad\":{}" };
    for (size_t i = 0; i < sizeof(pPads) / sizeof(pPads[0]); i++)
    {
        char sHeader[256];
        snprintf(sHeader, sizeof(sHeader), "{\"cc\":7,\"ccScope\":\"a-scope-from-a-newer-peer\",\"sc\":1%s}", pPads[i]);
        if (build_raw(&pkg, sHeader)) return 1;

        g_nLogged = 0;
        g_sLogged[0] = '\0';
        CHECK(!DirectGate_Proto_CheckCC(&pkg, &e2e), "an unknown scope is refused");
        CHECK(strstr(g_sLogged, "Unknown CC scope: a-scope-from-a-newer-peer") != NULL, "the refusal names the unknown scope");

        snprintf(sHeader, sizeof(sHeader), "{\"cc\":8,\"ccScope\":\"session\",\"ce\":0%s}", pPads[i]);
        if (build_raw(&pkg, sHeader)) return 1;

        g_nLogged = 0;
        g_sLogged[0] = '\0';
        CHECK(!DirectGate_Proto_CheckCC(&pkg, &e2e), "a scope without its counter is refused");
        CHECK(strstr(g_sLogged, "Missing scoped CC for scope(session)") != NULL, "the refusal names the scope");
    }

    xlog_destroy();
    XByteBuffer_Clear(&pkg);
    DirectGate_E2E_Clear(&e2e);
    return 0;
}

/* CheckCC reads a flat header in place and parses anything else. Every header here goes to one receiver as it
 * is and to another with a nested member the scan refuses: both readings have to take the same decisions. */
static int test_scan_matches_parse(void)
{
    static const char *pCounters[] = { "0", "1", "2", "3", "63", "64", "65", "66", "200", "4294967295", "4294967296",
        "18446744073709551616", "-1", "-0", "1.0", "1e2", "\"5\"", "true", "null" };
    static const char *pScopes[] = { NULL, "\"session\"", "\"input\"", "\"signal\"", "\"\"", "\"Session\"", "\"sess\\u0069on\"",
        "\"signal \"", "5", "true", "null" };

    directgate_e2e_t scanned, parsed;
    xbyte_buffer_t pkg;
    DirectGate_E2E_Init(&scanned);
    DirectGate_E2E_Init(&parsed);
    XByteBuffer_Init(&pkg, 0, 0);

    uint32_t nState = 0x9E3779B9u;
    int nAccepted = 0, nNewEpochs = 0;

    for (int i = 0; i < 20000; i++)
    {
        nState = nState * 1664525u + 1013904223u;
        uint32_t r = nState;
        size_t nCounters = sizeof(pCounters) / sizeof(pCounters[0]);

        /* A new session now and then: the odd counters push a window to the top of the range quickly */
        if (i % 250 == 0)
        {
            DirectGate_E2E_Init(&scanned);
            DirectGate_E2E_Init(&parsed);
        }

        const char *pScope = pScopes[(r >> 3) % (sizeof(pScopes) / sizeof(pScopes[0]))];
        if (!(r & 0x40000000)) pScope = pScopes[1 + (r >> 9) % 3];
        const directgate_ccwin_t *pWindow = pScope == pScopes[2] ? &scanned.rxInputWindow :
            pScope == pScopes[3] ? &scanned.rxSignalWindow : &scanned.rxSessionWindow;

        /* Mostly plausible counters, close to what each window last saw */
        char sCC[32], sSC[32], sCE[32];
        snprintf(sCC, sizeof(sCC), "%u", scanned.rxWindow.nHighest + (r & 3));
        snprintf(sSC, sizeof(sSC), "%u", pWindow->nHighest + ((r >> 2) & 7) - 2);
        snprintf(sCE, sizeof(sCE), "%u", scanned.nRxSessionEpoch + ((r >> 5) % 9 == 0));
        const char *pCC = (r >> 8) % 16 ? sCC : pCounters[(r >> 11) % nCounters];
        const char *pSC = (r >> 16) % 12 ? sSC : pCounters[(r >> 19) % nCounters];
        const char *pCE = (r >> 24) % 12 ? sCE : pCounters[(r >> 27) % nCounters];

        /* Each member is left out of one header in eight */
        nState = nState * 1664525u + 1013904223u;
        uint32_t nAbsent = nState >> 16;
        xbool_t bCC = (nAbsent & 7) != 0, bSC = (nAbsent & 0x38) != 0, bCE = (nAbsent & 0x1c0) != 0;

        char sMembers[256];
        int nLength = snprintf(sMembers, sizeof(sMembers), "\"type\":\"data\"%s%s%s%s%s%s%s%s%s",
            bCC ? ",\"cc\":" : "", bCC ? pCC : "",
            pScope == NULL ? "" : ",\"ccScope\":", pScope == NULL ? "" : pScope,
            bSC ? ",\"sc\":" : "", bSC ? pSC : "",
            bCE ? ",\"ce\":" : "", bCE ? pCE : "",
            (nAbsent & 0x200) ? "" : ",\"sessionId\":5");
        CHECK(nLength > 0 && (size_t)nLength < sizeof(sMembers), "write the members");

        char sFlat[300], sNested[320];
        snprintf(sFlat, sizeof(sFlat), "{%s}", sMembers);
        snprintf(sNested, sizeof(sNested), "{\"pad\":{\"cc\":1},%s}", sMembers);

        xjson_field_t field[1] = { { "cc", NULL, 0, 0 } };
        CHECK(XJSON_ScanFlat(sFlat, strlen(sFlat), field, 1), "the flat header is read in place");
        CHECK(!XJSON_ScanFlat(sNested, strlen(sNested), field, 1), "the nested header is parsed");

        uint32_t nEpoch = scanned.nRxSessionEpoch;
        if (build_raw(&pkg, sFlat)) return 1;
        xbool_t bScanned = DirectGate_Proto_CheckCC(&pkg, &scanned);
        nNewEpochs += scanned.nRxSessionEpoch != nEpoch;
        if (build_raw(&pkg, sNested)) return 1;
        xbool_t bParsed = DirectGate_Proto_CheckCC(&pkg, &parsed);

        if (bScanned != bParsed || memcmp(&scanned, &parsed, sizeof(scanned)))
        {
            fprintf(stderr, "e2e_ccwin_smoke: scan(%d) and parse(%d) disagree on %s\n", bScanned, bParsed, sFlat);
            return 1;
        }

        nAccepted += bScanned;
    }

    CHECK(nAccepted > 5000, "enough of the headers were accepted for the comparison to cover the windows");
    CHECK(nNewEpochs > 500, "and enough of them opened a new session epoch");

    XByteBuffer_Clear(&pkg);
    DirectGate_E2E_Clear(&scanned);
    DirectGate_E2E_Clear(&parsed);
    return 0;
}

int main(void)
{
    if (test_window_basics()) return 1;
    if (test_window_edges()) return 1;
    if (test_scoped_header()) return 1;
    if (test_scoped_edges()) return 1;
    if (test_emitted_counters()) return 1;
    if (test_refusal_logs()) return 1;
    if (test_scan_matches_parse()) return 1;

    puts("e2e_ccwin_smoke: OK");
    return 0;
}
