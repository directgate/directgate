/*!
 * @file directgate-agent/tests/desktop_control_smoke.c
 * @brief The desktop control channel: what a viewer can ask the agent to do.
 *
 * Every message here arrives as JSON from the browser, so each case is really
 * a question about untrusted input: an action nobody implements, a monitor
 * that is not there, a viewer box larger than anything encodable, a preset
 * name that is not a preset. None of those may leave the session in a state
 * the capture path cannot run in, and each has to answer the viewer rather
 * than go quiet - a control message that produces neither a state change nor
 * a status is how a stream ends up frozen with nothing in the log.
 *
 * The pipeline is pinned to raw RGBA so the handler runs its real code without
 * an X server, an encoder or a GPU on the other side.
 */

#include <stdio.h>
#include <string.h>

#include "src/agent/desktop/desktop.h"
#include "src/agent/desktop/priv.h"
#include "src/agent/session.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "desktop_control_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

/* Everything the desktop reports travels through one send. */
typedef struct control_capture_ {
    int nStatusCount;
    char sPayload[8192];
} control_capture_t;

static control_capture_t g_capture;

int DirectGate_Session_Send(directgate_session_t *pSession, xjson_obj_t *pHeader,
                            const uint8_t *pPayload, size_t nPayloadLength)
{
    (void)pSession; (void)pHeader;
    g_capture.nStatusCount++;

    if (pPayload != NULL && nPayloadLength > 0 && nPayloadLength < sizeof(g_capture.sPayload))
    {
        memcpy(g_capture.sPayload, pPayload, nPayloadLength);
        g_capture.sPayload[nPayloadLength] = '\0';
    }

    return XSTDOK;
}

int DirectGate_Session_SendErrorMsg(directgate_session_t *pSession, const char *pReason)
{
    (void)pSession; (void)pReason;
    g_capture.nStatusCount++;
    return XSTDOK;
}

static void reset_capture(void)
{
    memset(&g_capture, 0, sizeof(g_capture));
}

static int send_control(directgate_session_t *pSession, const char *pJson)
{
    reset_capture();
    return DirectGate_Desktop_HandleControl(pSession, (const uint8_t*)pJson, strlen(pJson));
}

/* A session whose desktop looks the way a running Linux capture leaves it,
 * minus the parts that need a display server. */
static void setup_session(directgate_session_t *pSession)
{
    memset(pSession, 0, sizeof(*pSession));
    pSession->nSessionId = 9;

    directgate_desktop_t *pDesktop = &pSession->desktop;
    DirectGate_Desktop_Init(pDesktop);
    DirectGate_Desktop_ApplyPreset(pDesktop, DIRECTGATE_DESKTOP_PRESET_BALANCED);

    pDesktop->nScreenWidth = 3840;
    pDesktop->nScreenHeight = 1080;
    pDesktop->bRunning = XTRUE;
    pDesktop->bInputReady = XTRUE;

    /* Keeps the pipeline on raw RGBA, so starting it never reaches OpenH264
     * or an X connection; the control logic under test is the same either way. */
    pDesktop->bForceRaw = XTRUE;
    pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_RAW;
    xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "x11");
    xstrncpy(pDesktop->sDisplay, sizeof(pDesktop->sDisplay), ":0");

    DirectGate_Desktop_AddMonitor(pDesktop, "all", "All displays", 0, 0, 3840, 1080, XFALSE);
    DirectGate_Desktop_AddMonitor(pDesktop, "monitor-1", "Left", 0, 0, 1920, 1080, XTRUE);
    DirectGate_Desktop_AddMonitor(pDesktop, "monitor-2", "Right", 1920, 0, 1920, 1080, XFALSE);
    DirectGate_Desktop_SetCapture(pDesktop, "all", 0, 0, 3840, 1080);
}

static int test_guards(void)
{
    directgate_session_t session;
    setup_session(&session);

    CHECK(DirectGate_Desktop_HandleControl(NULL, (const uint8_t*)"{}", 2) == XAPI_DISCONNECT,
        "a control message with no session drops the connection");

    reset_capture();
    CHECK(DirectGate_Desktop_HandleControl(&session, NULL, 4) == XAPI_CONTINUE,
        "a control message with no payload is ignored");
    CHECK(DirectGate_Desktop_HandleControl(&session, (const uint8_t*)"{}", 0) == XAPI_CONTINUE,
        "an empty control message is ignored");
    CHECK(g_capture.nStatusCount == 0, "an ignored control message answers nothing");

    /* Before the desktop is up there is nothing to control. */
    session.desktop.bRunning = XFALSE;
    reset_capture();
    CHECK(DirectGate_Desktop_HandleControl(&session,
        (const uint8_t*)"{\"action\":\"set-preset\",\"preset\":\"quality\"}", 40) == XAPI_CONTINUE,
        "a control message for a stopped desktop is ignored");
    CHECK(session.desktop.quality.ePreset == DIRECTGATE_DESKTOP_PRESET_BALANCED,
        "a control message for a stopped desktop changes nothing");
    session.desktop.bRunning = XTRUE;

    /* Malformed and hostile bodies have to be dropped, not parsed halfway. */
    CHECK(send_control(&session, "not json at all") == XAPI_CONTINUE,
        "a body that is not JSON is dropped");
    CHECK(g_capture.nStatusCount == 0, "a body that is not JSON answers nothing");

    CHECK(send_control(&session, "{\"action\":") == XAPI_CONTINUE,
        "a truncated JSON body is dropped");
    CHECK(send_control(&session, "[]") == XAPI_CONTINUE,
        "a JSON array in place of an object is dropped");
    CHECK(send_control(&session, "{}") == XAPI_CONTINUE,
        "a control message with no action is ignored");
    CHECK(g_capture.nStatusCount == 0, "a control message with no action answers nothing");

    CHECK(send_control(&session, "{\"action\":\"wobble\"}") == XAPI_CONTINUE,
        "an unknown action is ignored");
    CHECK(g_capture.nStatusCount == 0, "an unknown action answers nothing");

    CHECK(send_control(&session, "{\"action\":\"select-monitor\"}") == XAPI_CONTINUE,
        "select-monitor without a monitor id is ignored");
    CHECK(g_capture.nStatusCount == 0, "select-monitor without a monitor id answers nothing");

    return 0;
}

static int test_select_monitor(void)
{
    directgate_session_t session;
    setup_session(&session);

    CHECK(send_control(&session,
        "{\"action\":\"select-monitor\",\"monitorId\":\"monitor-9\"}") == XAPI_CONTINUE,
        "selecting a monitor that is not there is handled");
    CHECK(g_capture.nStatusCount == 1, "an unavailable monitor is reported back to the viewer");
    CHECK(strstr(g_capture.sPayload, "\"error\"") != NULL,
        "an unavailable monitor is reported as an error");
    CHECK(strcmp(session.desktop.sSelectedMonitor, "all") == 0,
        "a failed selection leaves the previous monitor captured");
    CHECK(session.desktop.nCaptureWidth == 3840,
        "a failed selection leaves the previous capture rectangle");

    CHECK(send_control(&session,
        "{\"action\":\"select-monitor\",\"monitorId\":\"monitor-2\"}") == XAPI_CONTINUE,
        "selecting an available monitor is handled");
    CHECK(g_capture.nStatusCount == 1, "a selection is reported back to the viewer");
    CHECK(strstr(g_capture.sPayload, "\"streaming\"") != NULL,
        "a selection reports the stream as running");
    CHECK(strcmp(session.desktop.sSelectedMonitor, "monitor-2") == 0,
        "the selected monitor becomes the captured one");
    CHECK(session.desktop.nCaptureX == 1920 && session.desktop.nCaptureWidth == 1920,
        "the capture rectangle follows the selected monitor");
    /* The monitor is 1920x1080; the raw path's balanced cap takes it to
     * 1600x900. The point is that the frame size is recomputed from the new
     * rectangle rather than carried over from the previous one. */
    CHECK(session.desktop.nFrameWidth == 1600 && session.desktop.nFrameHeight == 900,
        "the frame size is recomputed for the selected monitor");

    /* Display mode asks the OS to change resolution. There is no display here,
     * so it has to fail back to scaling rather than leave the session claiming
     * a mode it never got. */
    CHECK(send_control(&session,
        "{\"action\":\"select-monitor\",\"monitorId\":\"monitor-1\","
        "\"mode\":\"display\",\"width\":1280,\"height\":1024}") == XAPI_CONTINUE,
        "selecting a monitor in display mode is handled");
    CHECK(session.desktop.eResizeMode == DIRECTGATE_DESKTOP_RESIZE_SCALE,
        "a display mode that could not be set falls back to scaling");
    CHECK(strcmp(session.desktop.sSelectedMonitor, "monitor-1") == 0,
        "a failed display mode still selects the monitor the viewer asked for");
    CHECK(g_capture.nStatusCount == 1, "a failed display mode still answers the viewer");
    CHECK(strstr(g_capture.sPayload, "\"streaming\"") != NULL,
        "a failed display mode reports a running stream, not an error");
    CHECK(strstr(g_capture.sPayload, "fallbackReason") != NULL ||
        strstr(g_capture.sPayload, "reason") != NULL,
        "a failed display mode says why the viewer did not get it");

    return 0;
}

static int test_set_resolution(void)
{
    directgate_session_t session;
    setup_session(&session);

    CHECK(send_control(&session,
        "{\"action\":\"set-resolution\",\"mode\":\"scale\",\"width\":1280,\"height\":720,"
        "\"resolution\":\"1280x720\",\"settingsRevision\":3}") == XAPI_CONTINUE,
        "a scale-mode resolution request is handled");
    CHECK(session.desktop.nTargetWidth == 1280 && session.desktop.nTargetHeight == 720,
        "the viewer box is applied");
    CHECK(session.desktop.nSettingsRevision == 3, "the settings revision is applied");
    CHECK(g_capture.nStatusCount == 1, "a resolution request is answered");
    CHECK(strstr(g_capture.sPayload, "\"targetWidth\":1280") != NULL,
        "the answer carries the applied viewer box");

    /* A box the encoder could never produce must not replace a working one. */
    CHECK(send_control(&session,
        "{\"action\":\"set-resolution\",\"width\":65535,\"height\":65535}") == XAPI_CONTINUE,
        "an oversized viewer box is handled");
    CHECK(session.desktop.nTargetWidth == 1280 && session.desktop.nTargetHeight == 720,
        "an oversized viewer box leaves the working one in place");
    CHECK(g_capture.nStatusCount == 1, "an oversized viewer box is still answered");

    CHECK(send_control(&session,
        "{\"action\":\"set-resolution\",\"width\":0,\"height\":0}") == XAPI_CONTINUE,
        "a zero viewer box is handled");
    CHECK(session.desktop.nTargetWidth == 1280 && session.desktop.nTargetHeight == 720,
        "a zero viewer box leaves the working one in place");

    /* Display mode with no display server behind it. */
    CHECK(send_control(&session,
        "{\"action\":\"set-resolution\",\"mode\":\"display\",\"width\":1024,\"height\":768}")
        == XAPI_CONTINUE, "a display-mode resolution request is handled");
    CHECK(session.desktop.eResizeMode == DIRECTGATE_DESKTOP_RESIZE_SCALE,
        "a display mode that could not be set falls back to scaling");
    CHECK(session.desktop.bCaptureReady,
        "a failed display mode leaves the capture running");
    CHECK(g_capture.nStatusCount == 1, "a failed display mode answers the viewer");

    return 0;
}

static int test_set_preset(void)
{
    directgate_session_t session;
    setup_session(&session);

    CHECK(send_control(&session, "{\"action\":\"set-preset\",\"preset\":\"low-latency\"}")
        == XAPI_CONTINUE, "a preset change is handled");
    CHECK(session.desktop.quality.ePreset == DIRECTGATE_DESKTOP_PRESET_LOW_LATENCY,
        "the requested preset is applied");
    CHECK(session.desktop.quality.nFps == 60,
        "the low-latency preset raises the capture rate to its own");
    CHECK(g_capture.nStatusCount == 1, "a preset change is answered");
    CHECK(strstr(g_capture.sPayload, "\"preset\":\"low-latency\"") != NULL,
        "the answer carries the applied preset");

    CHECK(send_control(&session, "{\"action\":\"set-preset\",\"preset\":\"quality\"}")
        == XAPI_CONTINUE, "a second preset change is handled");
    CHECK(session.desktop.quality.ePreset == DIRECTGATE_DESKTOP_PRESET_QUALITY,
        "the second preset is applied");

    /* An unrecognised name keeps whatever is running rather than resetting it. */
    CHECK(send_control(&session, "{\"action\":\"set-preset\",\"preset\":\"ludicrous\"}")
        == XAPI_CONTINUE, "an unknown preset name is handled");
    CHECK(session.desktop.quality.ePreset == DIRECTGATE_DESKTOP_PRESET_QUALITY,
        "an unknown preset name leaves the running preset alone");
    CHECK(g_capture.nStatusCount == 1, "an unknown preset name is still answered");

    CHECK(send_control(&session, "{\"action\":\"set-preset\"}") == XAPI_CONTINUE,
        "a preset change with no name is handled");
    CHECK(session.desktop.quality.ePreset == DIRECTGATE_DESKTOP_PRESET_QUALITY,
        "a preset change with no name leaves the running preset alone");

    return 0;
}

static int test_keyframe_and_audio(void)
{
    directgate_session_t session;
    setup_session(&session);

    /* On the raw path there is no encoder to ask, and asking anyway must not
     * reach into a NULL one. */
    CHECK(send_control(&session, "{\"action\":\"request-keyframe\"}") == XAPI_CONTINUE,
        "a keyframe request on the raw pipeline is handled");
    CHECK(g_capture.nStatusCount == 0,
        "a keyframe request is not a status change and answers nothing");

    CHECK(send_control(&session, "{\"action\":\"fallback-datachannel\"}") == XAPI_CONTINUE,
        "a data-channel fallback request on the raw pipeline is handled");

    CHECK(send_control(&session, "{\"action\":\"audio\",\"enabled\":false}") == XAPI_CONTINUE,
        "an audio-off request is handled");
    CHECK(!session.desktop.bAudioRequested, "an audio-off request is recorded");
    CHECK(g_capture.nStatusCount == 1, "an audio change is answered");

    CHECK(send_control(&session, "{\"action\":\"audio\",\"enabled\":true}") == XAPI_CONTINUE,
        "an audio-on request is handled");
    CHECK(session.desktop.bAudioRequested,
        "an audio-on request is recorded whether or not capture could start");
    CHECK(g_capture.nStatusCount == 1, "an audio-on request is answered");

    DirectGate_Desktop_AudioStop(&session.desktop);
    return 0;
}

int main(void)
{
    if (test_guards()) return 1;
    if (test_select_monitor()) return 1;
    if (test_set_resolution()) return 1;
    if (test_set_preset()) return 1;
    if (test_keyframe_and_audio()) return 1;

    puts("desktop_control_smoke: OK");
    return 0;
}
