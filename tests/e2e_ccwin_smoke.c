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

int main(void)
{
    if (test_window_basics()) return 1;
    if (test_window_edges()) return 1;
    if (test_scoped_header()) return 1;
    if (test_emitted_counters()) return 1;

    puts("e2e_ccwin_smoke: OK");
    return 0;
}
