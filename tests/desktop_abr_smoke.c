/*!
 * @file directgate-agent/tests/desktop_abr_smoke.c
 * @brief Adaptive bitrate policy tests for the desktop video pipeline.
 *
 * DirectGate_Desktop_AbrStep is the whole congestion response: it decides,
 * once per encoded frame, what rate the platform encoder should run at. The
 * cases below drive it with synthetic receiver reports, because the failure
 * that motivated them is invisible in a single step and only shows up over
 * minutes of session time - a link that loses a few percent every second or
 * two used to ratchet the rate down to the floor and pin it there, so the
 * picture stayed unreadable on a link that could carry the full preset.
 */

#include <stdio.h>
#include <string.h>

#include "src/agent/desktop/desktop.c"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "desktop_abr_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

/* desktop.c reaches into the session, capture and encoder units for teardown
 * and status reporting; the bitrate policy under test touches none of them. */
void DirectGate_Desktop_AudioStop(directgate_desktop_t *pDesktop) { (void)pDesktop; }
void DirectGate_Desktop_LinuxEncoder_StopDesktop(directgate_desktop_t *pDesktop) { (void)pDesktop; }
void DirectGate_Desktop_RestoreDisplayMode(directgate_desktop_t *pDesktop) { (void)pDesktop; }
void DirectGate_Desktop_ReleaseHeldKeys(directgate_desktop_t *pDesktop) { (void)pDesktop; }

int DirectGate_Session_Send(directgate_session_t *pSession, xjson_obj_t *pHeader,
                            const uint8_t *pPayload, size_t nPayloadLength)
{
    (void)pSession; (void)pHeader; (void)pPayload; (void)nPayloadLength;
    return 0;
}

#define ABR_TICKS_PER_SEC   30U     /* the pipeline calls this per frame */
#define ABR_TARGET_KBPS     6000U

/* Sets up a desktop struct the way ApplyPreset leaves it: live rate at the
 * preset target, no history. */
static void DirectGate_AbrTest_Init(directgate_desktop_t *pDesktop)
{
    memset(pDesktop, 0, sizeof(*pDesktop));
    pDesktop->quality.nBitrateKbps = ABR_TARGET_KBPS;
    pDesktop->quality.nBaseBitrateKbps = ABR_TARGET_KBPS;
    pDesktop->nCurrentBitrateKbps = ABR_TARGET_KBPS;
}

/* Runs nSeconds of ticks, delivering one receiver report per second carrying
 * nFractionLost - except every nCleanEvery'th second, which reports clean.
 * nCleanEvery of 0 means every report is lossy. */
static uint32_t DirectGate_AbrTest_Run(directgate_desktop_t *pDesktop, uint32_t nSeconds,
                                       uint8_t nFractionLost, uint32_t nCleanEvery)
{
    uint32_t nRate = pDesktop->nCurrentBitrateKbps;

    for (uint32_t nSecond = 0; nSecond < nSeconds; nSecond++)
    {
        xbool_t bClean = (nCleanEvery && (nSecond % nCleanEvery) == 0) ? XTRUE : XFALSE;

        for (uint32_t nTick = 0; nTick < ABR_TICKS_PER_SEC; nTick++)
        {
            /* Reports arrive about once a second, not once a frame. */
            xbool_t bReport = (nTick == 0) ? XTRUE : XFALSE;
            nRate = DirectGate_Desktop_AbrStep(pDesktop, bReport,
                bClean ? 0 : nFractionLost, XFALSE);
        }
    }

    return nRate;
}

/* Sustained congestion must still be answered quickly: the rate has to come
 * down within a couple of seconds, and keep coming down to the floor. */
static int DirectGate_AbrTest_SustainedLoss(void)
{
    directgate_desktop_t desktop;
    DirectGate_AbrTest_Init(&desktop);

    uint32_t nRate = DirectGate_AbrTest_Run(&desktop, 3, 40, 0);
    CHECK(nRate < ABR_TARGET_KBPS, "sustained loss did not reduce the bitrate");
    CHECK(nRate <= (ABR_TARGET_KBPS * 3U) / 4U, "sustained loss cut by less than one step");

    nRate = DirectGate_AbrTest_Run(&desktop, 60, 40, 0);
    CHECK(nRate == DIRECTGATE_DESKTOP_MIN_BITRATE_KBPS, "sustained loss did not reach the floor");

    /* The floor is a floor, not a waypoint. */
    nRate = DirectGate_AbrTest_Run(&desktop, 30, 40, 0);
    CHECK(nRate == DIRECTGATE_DESKTOP_MIN_BITRATE_KBPS, "bitrate fell through the floor");
    return 0;
}

/* A single lossy report is not congestion. NACK repairs that much loss
 * without any rate change, so the rate must not move at all. */
static int DirectGate_AbrTest_IsolatedLossIgnored(void)
{
    directgate_desktop_t desktop;
    DirectGate_AbrTest_Init(&desktop);

    for (uint32_t nSecond = 0; nSecond < 20; nSecond++)
    {
        for (uint32_t nTick = 0; nTick < ABR_TICKS_PER_SEC; nTick++)
        {
            xbool_t bReport = (nTick == 0) ? XTRUE : XFALSE;
            uint8_t nLost = (bReport && nSecond == 7) ? 40 : 0;
            DirectGate_Desktop_AbrStep(&desktop, bReport, nLost, XFALSE);
        }
    }

    CHECK(desktop.nCurrentBitrateKbps == ABR_TARGET_KBPS,
        "an isolated lossy report moved the bitrate");
    return 0;
}

/* The regression this file exists for: intermittent loss - one lossy report
 * every few seconds, never two in a row - on a link that is otherwise fine.
 * The old controller zeroed its clean-tick counter on every such report, so
 * the five clean seconds recovery needs never elapsed and the rate ratcheted
 * to the floor. It must now converge back to the preset target instead. */
static int DirectGate_AbrTest_IntermittentLossRecovers(void)
{
    directgate_desktop_t desktop;
    DirectGate_AbrTest_Init(&desktop);
    desktop.nCurrentBitrateKbps = DIRECTGATE_DESKTOP_MIN_BITRATE_KBPS;

    /* Five minutes of a link that hiccups every fourth second. */
    for (uint32_t nSecond = 0; nSecond < 300; nSecond++)
    {
        for (uint32_t nTick = 0; nTick < ABR_TICKS_PER_SEC; nTick++)
        {
            xbool_t bReport = (nTick == 0) ? XTRUE : XFALSE;
            uint8_t nLost = (bReport && (nSecond % 4) == 0) ? 40 : 0;
            DirectGate_Desktop_AbrStep(&desktop, bReport, nLost, XFALSE);
        }
    }

    CHECK(desktop.nCurrentBitrateKbps == ABR_TARGET_KBPS,
        "intermittent loss pinned the bitrate below target");
    return 0;
}

/* A clean link that was throttled earlier has to climb all the way back,
 * and stop at the target rather than overshooting it. */
static int DirectGate_AbrTest_CleanLinkRecovers(void)
{
    directgate_desktop_t desktop;
    DirectGate_AbrTest_Init(&desktop);
    desktop.nCurrentBitrateKbps = DIRECTGATE_DESKTOP_MIN_BITRATE_KBPS;

    uint32_t nRate = DirectGate_AbrTest_Run(&desktop, 10, 0, 1);
    CHECK(nRate > DIRECTGATE_DESKTOP_MIN_BITRATE_KBPS, "clean link did not raise the bitrate");
    CHECK(nRate < ABR_TARGET_KBPS, "clean link jumped straight to target");

    nRate = DirectGate_AbrTest_Run(&desktop, 300, 0, 1);
    CHECK(nRate == ABR_TARGET_KBPS, "clean link did not recover to target");
    return 0;
}

/* Data-channel backpressure is the fallback pipeline's only congestion
 * signal and has no report behind it, so it must act immediately. */
static int DirectGate_AbrTest_Backpressure(void)
{
    directgate_desktop_t desktop;
    DirectGate_AbrTest_Init(&desktop);

    uint32_t nRate = DirectGate_Desktop_AbrStep(&desktop, XFALSE, 0, XTRUE);
    CHECK(nRate == (ABR_TARGET_KBPS * 3U) / 4U, "backpressure did not cut the bitrate");

    /* ...and then respect the hold, so one stall is not punished repeatedly. */
    uint32_t nHeld = nRate;
    for (uint32_t nTick = 0; nTick < DIRECTGATE_DESKTOP_ABR_HOLD_TICKS - 1U; nTick++)
        nRate = DirectGate_Desktop_AbrStep(&desktop, XFALSE, 0, XTRUE);

    CHECK(nRate == nHeld, "backpressure cut again inside the hold window");
    nRate = DirectGate_Desktop_AbrStep(&desktop, XFALSE, 0, XTRUE);
    CHECK(nRate < nHeld, "backpressure did not cut again after the hold window");
    return 0;
}

/* Presets below the floor (and a NULL desktop) must not produce a rate the
 * encoder cannot honour. */
static int DirectGate_AbrTest_Bounds(void)
{
    CHECK(DirectGate_Desktop_AbrStep(NULL, XTRUE, 40, XFALSE) == 0, "NULL desktop was not rejected");

    directgate_desktop_t desktop;
    DirectGate_AbrTest_Init(&desktop);
    desktop.quality.nBitrateKbps = DIRECTGATE_DESKTOP_MIN_BITRATE_KBPS / 2U;
    desktop.nCurrentBitrateKbps = desktop.quality.nBitrateKbps;

    uint32_t nRate = DirectGate_AbrTest_Run(&desktop, 30, 40, 0);
    CHECK(nRate == desktop.quality.nBitrateKbps,
        "a preset below the floor was throttled below its own target");

    DirectGate_AbrTest_Init(&desktop);
    desktop.quality.nBitrateKbps = 0;
    CHECK(DirectGate_Desktop_AbrStep(&desktop, XTRUE, 0, XFALSE) == 0,
        "a zero target did not yield a zero rate");
    return 0;
}

int main(void)
{
    if (DirectGate_AbrTest_SustainedLoss()) return 1;
    if (DirectGate_AbrTest_IsolatedLossIgnored()) return 1;
    if (DirectGate_AbrTest_IntermittentLossRecovers()) return 1;
    if (DirectGate_AbrTest_CleanLinkRecovers()) return 1;
    if (DirectGate_AbrTest_Backpressure()) return 1;
    if (DirectGate_AbrTest_Bounds()) return 1;

    printf("desktop_abr_smoke: ok\n");
    return 0;
}
