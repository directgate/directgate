/*
 * The desktop on a Wayland session, end to end, without a compositor.
 *
 * The same module set desktop_x11_smoke runs, built with Wayland streaming:
 * the portal is wayland_portal_stub.h and PipeWire is fake_pipewire.h, with a
 * thread playing the compositor that answers every stream's format as soon as
 * it is subscribed. Covers a grant that is already there and one that waits
 * for somebody to answer the prompt, the shared screens as monitors, switching
 * between them, frames through the real encoder thread, input through the
 * portal, the things Wayland refuses (raw capture, display modes), and the
 * screen being taken back mid-session.
 */

#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "src/agent/desktop/desktop.h"
#include "src/agent/desktop/priv.h"
#include "src/agent/session.h"

#include "wayland_portal_stub.h"
#include "wayland_stream_fixture.h"

#ifdef DIRECTGATE_HAVE_HWENC
#include "fake_libav.h"
#include "src/agent/desktop/openh264.h"

/* The encoder bumps these on its own thread */
#define AV(field) fake_av_get(&fake_av()->field)
#endif

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "desktop_wayland_smoke: %s (line %d)\n", msg, __LINE__); \
            return 1; \
        } \
    } while (0)

/* What the desktop sent, by kind */
typedef struct {
    int nStatuses;
    int nStreaming;     /* statuses that said "streaming" */
    int nEncoded;
    int nRawChunks;
    int nErrors;
    char sStatus[64];
    char sLastStatus[4096];
} sent_t;

static sent_t g_sent;
static directgate_session_t g_session;

static void copy_field(const char *pJson, const char *pKey, char *pOut, size_t nSize)
{
    pOut[0] = '\0';
    char sNeedle[64];
    snprintf(sNeedle, sizeof(sNeedle), "\"%s\":\"", pKey);

    const char *pAt = strstr(pJson, sNeedle);
    if (pAt == NULL) return;
    pAt += strlen(sNeedle);

    size_t i = 0;
    while (pAt[i] != '\0' && pAt[i] != '"' && i + 1 < nSize) { pOut[i] = pAt[i]; i++; }
    pOut[i] = '\0';
}

int DirectGate_Session_Send(directgate_session_t *pSession, xjson_obj_t *pHeader,
                            const uint8_t *pPayload, size_t nPayloadLength)
{
    (void)pSession;
    const char *pType = XJSON_GetString(XJSON_GetObject(pHeader, "payloadType"));

    if (pType != NULL && strcmp(pType, "desktop-frame-encoded") == 0) g_sent.nEncoded++;
    else if (pType != NULL && strcmp(pType, "desktop-frame-chunk") == 0) g_sent.nRawChunks++;
    else if (pType != NULL && strcmp(pType, "desktop-status") == 0 && pPayload != NULL)
    {
        size_t nLen = nPayloadLength < sizeof(g_sent.sLastStatus) - 1 ? nPayloadLength : sizeof(g_sent.sLastStatus) - 1;
        memcpy(g_sent.sLastStatus, pPayload, nLen);
        g_sent.sLastStatus[nLen] = '\0';
        copy_field(g_sent.sLastStatus, "status", g_sent.sStatus, sizeof(g_sent.sStatus));
        if (strcmp(g_sent.sStatus, "streaming") == 0) g_sent.nStreaming++;
        g_sent.nStatuses++;
    }

    return XSTDOK;
}

int DirectGate_Session_SendErrorMsg(directgate_session_t *pSession, const char *pReason)
{
    (void)pSession; (void)pReason;
    g_sent.nErrors++;
    return XSTDOK;
}

/* ---------------- the compositor ---------------- */

typedef struct {
    pthread_t thread;
    xatomic_t bStop;
    xatomic_t nWidth;
    xatomic_t nHeight;
    xatomic_t bExport;      /* answer with an exported format, whatever was offered */
    fake_pw_stream_t *pServed[16];
    int nServed;
} compositor_t;

static compositor_t g_comp;

static int served(fake_pw_stream_t *pStream)
{
    for (int i = 0; i < g_comp.nServed; i++)
    {
        if (g_comp.pServed[i] == pStream) return 1;
    }

    return 0;
}

/* Answers every new subscription with a format, the way a compositor does once the portal has handed over a node */
static void* compositor_thread(void *pArg)
{
    (void)pArg;
    while (!XSYNC_ATOMIC_GET(&g_comp.bStop))
    {
        /* A portal that listed no screens still streams one, on node 0 */
        uint32_t nNodes = stub.nStreams ? stub.nStreams : 1U;
        for (uint32_t i = 0; i < nNodes && g_comp.nServed < 16; i++)
        {
            fake_pw_stream_t *pStream = fake_pw_stream_for_node(stub.nStreams ? stub.streams[i].nNodeId : 0U);
            if (pStream == NULL || fake_pw_destroyed(pStream) || served(pStream)) continue;

            uint8_t pod[1024];
            g_comp.pServed[g_comp.nServed++] = pStream;
            emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video,
                SPA_VIDEO_FORMAT_BGRx, (uint32_t)XSYNC_ATOMIC_GET(&g_comp.nWidth),
                (uint32_t)XSYNC_ATOMIC_GET(&g_comp.nHeight),
                XSYNC_ATOMIC_GET(&g_comp.bExport) ? MODIFIER_FIXED : MODIFIER_NONE, MOD_LINEAR));
        }

        usleep(1000);
    }

    return NULL;
}

static void compositor_start(uint32_t nWidth, uint32_t nHeight)
{
    memset(&g_comp, 0, sizeof(g_comp));
    XSYNC_ATOMIC_SET(&g_comp.nWidth, nWidth);
    XSYNC_ATOMIC_SET(&g_comp.nHeight, nHeight);
    pthread_create(&g_comp.thread, NULL, compositor_thread, NULL);
}

static void compositor_stop(void)
{
    XSYNC_ATOMIC_SET(&g_comp.bStop, 1);
    pthread_join(g_comp.thread, NULL);
}

/* ---------------- driving the session ---------------- */

static int control(const char *pJson)
{
    return DirectGate_Desktop_HandleControl(&g_session, (const uint8_t*)pJson, strlen(pJson));
}

static int input(const char *pJson)
{
    return DirectGate_Desktop_HandleInput(&g_session, (const uint8_t*)pJson, strlen(pJson));
}

/* One tick of the session, with a new picture from the active screen first when pBuffer is given */
static void tick(buffer_t *pBuffer)
{
    if (pBuffer != NULL)
    {
        fake_pw_stream_t *pStream = fake_pw_stream_for_node(g_session.desktop.pWayland != NULL ?
            DirectGate_WL_SourceActiveNode((directgate_wl_source_t*)g_session.desktop.pWayland) : 0);
        if (pStream != NULL && !fake_pw_destroyed(pStream)) emit_buffer(pStream, pBuffer);
    }

    int nFd = DirectGate_Desktop_GetTimerFd(&g_session.desktop);
    if (nFd >= 0)
    {
        struct pollfd pfd = { nFd, POLLIN, 0 };
        (void)poll(&pfd, 1, 10);
    }
    else usleep(10000);

    (void)DirectGate_Desktop_Process(&g_session);
}

static int status_is(const char *pStatus)
{
    return strcmp(g_sent.sStatus, pStatus) == 0;
}

static void begin(uint32_t nSessionId)
{
    memset(&g_session, 0, sizeof(g_session));
    memset(&g_sent, 0, sizeof(g_sent));
    g_session.nSessionId = nSessionId;
}

static void reset_world(uint32_t nScreens)
{
    fake_pw_reset();
    stub_portal_reset();
    stub.nStreams = nScreens;
    for (uint32_t i = 0; i < nScreens; i++)
    {
        stub.streams[i].nNodeId = 31 + i;
        stub.streams[i].nX = (int32_t)(64 * i);
        stub.streams[i].nWidth = i == 0 ? 64 : 0;
        stub.streams[i].nHeight = i == 0 ? 32 : 0;
    }
}

/* ---------------- scenarios ---------------- */

static int test_streaming(void)
{
    reset_world(2);
    compositor_start(64, 32);
    begin(41);

    CHECK(DirectGate_Desktop_Start(&g_session) >= 0, "the Wayland desktop starts");
    directgate_desktop_t *pDesktop = &g_session.desktop;
    CHECK(status_is("ready") && strcmp(pDesktop->sBackend, "wayland") == 0, "on the Wayland backend");
    CHECK(pDesktop->nScreenWidth == 64 && pDesktop->nScreenHeight == 32 && pDesktop->bInputReady,
        "at the stream's size, with input");
    CHECK(pDesktop->nMonitorCount >= 2, "every shared screen is a monitor");

    const directgate_desktop_monitor_t *pSecond = DirectGate_Desktop_FindMonitor(pDesktop, "wayland-32");
    CHECK(pSecond != NULL && pSecond->nNativeId == 32 && pSecond->nWidth == 64 && pSecond->nX == 64,
        "a screen the portal gave no size for takes the stream's");
    CHECK(control("{\"action\":\"request-keyframe\"}") == XAPI_CONTINUE, "nothing streams before a pick");

    /* Picking the other screen moves the capture there, and frames go out through the encoder */
    CHECK(control("{\"action\":\"select-monitor\",\"monitorId\":\"wayland-32\",\"mode\":\"display\","
        "\"width\":32,\"height\":16}") == XAPI_CONTINUE, "pick the second screen, asking for a display mode");
    CHECK(DirectGate_WL_SourceActiveNode((directgate_wl_source_t*)pDesktop->pWayland) == 32, "the capture moved");

    if (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_RAW)
    {
        /* No H.264 encoder on this machine: Wayland has no raw path, and says so rather than streaming black */
        CHECK(status_is("error"), "a Wayland desktop without an encoder fails rather than go blank");
    }
    else
    {
        CHECK(status_is("streaming") && strstr(g_sent.sLastStatus, "Wayland") != NULL,
            "streaming, scaled, because Wayland leaves display modes alone");

        buffer_t frame;
        buffer_mapped(&frame, 0, 0, 1, sizeof(frame.pixels));
        for (int i = 0; i < 300 && g_sent.nEncoded < 3; i++)
        {
            frame.pixels[0] = (uint8_t)i;
            tick(&frame);
        }
        CHECK(g_sent.nEncoded >= 3, "pictures from the compositor go out encoded");

        /* A keyframe on a screen that is standing still is the last picture again */
        int nBefore = g_sent.nEncoded;
        CHECK(control("{\"action\":\"request-keyframe\"}") == XAPI_CONTINUE, "ask for a keyframe");
        for (int i = 0; i < 300 && g_sent.nEncoded == nBefore; i++) tick(NULL);
        CHECK(g_sent.nEncoded > nBefore, "a still screen still answers a keyframe request");

        CHECK(control("{\"action\":\"set-resolution\",\"mode\":\"display\",\"width\":32,\"height\":16}") ==
            XAPI_CONTINUE, "ask for a display mode again");
        CHECK(strstr(DirectGate_Desktop_GetReason(pDesktop), "Wayland") != NULL, "which Wayland refuses");
    }

    /* Input goes to the portal */
    CHECK(input("{\"action\":\"pointer\",\"event\":\"move\",\"x\":5,\"y\":6}") == XAPI_CONTINUE &&
          input("{\"action\":\"pointer\",\"event\":\"button\",\"button\":1,\"down\":true,\"x\":5,\"y\":6}") == XAPI_CONTINUE &&
          input("{\"action\":\"pointer\",\"event\":\"button\",\"button\":1,\"down\":false,\"x\":5,\"y\":6}") == XAPI_CONTINUE &&
          input("{\"action\":\"key\",\"code\":\"KeyA\",\"key\":\"a\",\"down\":true}") == XAPI_CONTINUE &&
          input("{\"action\":\"key\",\"code\":\"KeyA\",\"key\":\"a\",\"down\":false}") == XAPI_CONTINUE,
        "pointer and keys");
    CHECK(stub.nMotions > 0 && stub.nButtons == 2 && stub.nKeysyms + stub.nKeycodes >= 2, "reach the portal");

    /* A portal that will not type characters is said once */
    stub.bKeysymRefused = XTRUE;
    int nStatuses = g_sent.nStatuses;
    int nStreaming = g_sent.nStreaming;
    tick(NULL);
    tick(NULL);
    if (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_RAW)
    {
        CHECK(pDesktop->bWaylandNoKeysym && g_sent.nStreaming == nStreaming && status_is("error"),
            "a session that has already failed is not told it streams because of it");
    }
    else
    {
        CHECK(pDesktop->bWaylandNoKeysym && g_sent.nStatuses == nStatuses + 1, "a portal refusing characters is reported once");
    }

    /* A compositor exporting frames it was never asked to: no picture, and no buffer is kept from it */
    fake_pw_stream_t *pStream = fake_pw_stream_for_node(32);
    CHECK(pStream != NULL, "the active stream");
    uint8_t pod[1024];
    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRx,
        64, 32, MODIFIER_FIXED, MOD_LINEAR));
    static buffer_t exported[2];    /* never at the address of a buffer given back before */
    buffer_exported(&exported[0], 70, 0, 0, 0);
    buffer_exported(&exported[1], 71, 0, 0, 0);
    tick(&exported[0]);
    tick(&exported[1]);
    CHECK(fake_pw_returned(pStream, &exported[0].pw) == 1, "an unasked-for export goes back when the next one comes");

    /* The screen is taken back: the session says so and stops */
    emit_state(pStream, PW_STREAM_STATE_UNCONNECTED, NULL);
    tick(NULL);
    CHECK(status_is("error") && g_sent.nErrors == 1 && pDesktop->bWaylandLost, "a screen taken back ends the stream");
    tick(NULL);
    CHECK(g_sent.nErrors == 1, "once");

    DirectGate_Desktop_Clear(pDesktop);
    compositor_stop();
    CHECK(stub.nClosed == 1 && fake_pw_live() == 0 && fake_pw_open_fds() == 0, "and nothing is left of it");
    CHECK(fake_pw_returned(pStream, &exported[1].pw) == 1, "the last export went back with it");
    return 0;
}

static int test_prompt(void)
{
    /* Nobody has answered yet: the session starts waiting, and comes up on its own once they allow it */
    reset_world(1);
    stub.answers[0] = STUB_WAIT;
    compositor_start(64, 32);
    begin(42);

    CHECK(DirectGate_Desktop_Start(&g_session) >= 0 && status_is("starting"), "a session waits for the prompt");
    CHECK(control("{\"action\":\"select-monitor\",\"monitorId\":\"wayland-31\"}") == XAPI_CONTINUE &&
          status_is("starting"), "and has nothing to select while it does");
    tick(NULL);
    CHECK(status_is("starting") && g_session.desktop.bAwaitingGrant, "still waiting");

    XSync_Lock(&stub.lock);
    stub.bRelease = 1;
    XSync_Unlock(&stub.lock);
    for (int i = 0; i < 500 && !status_is("ready"); i++) tick(NULL);
    CHECK(status_is("ready") && !g_session.desktop.bAwaitingGrant, "allowed later, it is ready");
    CHECK(DirectGate_Desktop_FindMonitor(&g_session.desktop, "wayland-31") != NULL, "with its one screen");
    DirectGate_Desktop_Clear(&g_session.desktop);
    compositor_stop();

    /* Refused after a wait: an error, once */
    reset_world(1);
    stub.answers[0] = STUB_WAIT;
    stub.eAfterWait = STUB_DECLINE;
    begin(43);
    CHECK(DirectGate_Desktop_Start(&g_session) >= 0 && status_is("starting"), "another waits");
    XSync_Lock(&stub.lock);
    stub.bRelease = 1;
    XSync_Unlock(&stub.lock);
    for (int i = 0; i < 500 && !status_is("error"); i++) tick(NULL);
    CHECK(status_is("error") && g_sent.nErrors == 1, "a prompt answered no is an error");
    DirectGate_Desktop_Clear(&g_session.desktop);

    /* A session that gives up while the prompt is up leaves it for the next one, which does not ask twice */
    reset_world(1);
    stub.answers[0] = STUB_WAIT;
    compositor_start(64, 32);
    begin(44);
    CHECK(DirectGate_Desktop_Start(&g_session) >= 0 && status_is("starting"), "a third waits");
    DirectGate_Desktop_Clear(&g_session.desktop);

    begin(45);
    CHECK(DirectGate_Desktop_Start(&g_session) >= 0 && status_is("starting"), "the next session adopts the prompt");
    XSync_Lock(&stub.lock);
    stub.bRelease = 1;
    XSync_Unlock(&stub.lock);
    for (int i = 0; i < 500 && !status_is("ready"); i++) tick(NULL);
    CHECK(status_is("ready") && stub.nOpens == 1, "and is ready without a second prompt");
    DirectGate_Desktop_Clear(&g_session.desktop);
    compositor_stop();
    return 0;
}

static int test_refusals(void)
{
    /* Refused outright */
    reset_world(1);
    stub.answers[0] = STUB_REFUSE;
    begin(46);
    CHECK(DirectGate_Desktop_Start(&g_session) < 0 && status_is("error") && g_sent.nErrors == 1,
        "a refused portal fails the start");
    CHECK(strcmp(g_session.desktop.sBackend, "wayland") == 0, "on the Wayland backend");
    DirectGate_Desktop_Clear(&g_session.desktop);

    /* A stream with no size */
    reset_world(1);
    compositor_start(0, 0);
    begin(47);
    CHECK(DirectGate_Desktop_Start(&g_session) < 0 && strstr(DirectGate_Desktop_GetReason(&g_session.desktop), "size"),
        "a stream that reports no size fails the start");
    DirectGate_Desktop_Clear(&g_session.desktop);
    compositor_stop();

    /* Shared without input, and with no screen list: one screen, view only - and raw RGBA forced, which Wayland
       cannot do */
    reset_world(0);
    stub.bHasInput = XFALSE;
    compositor_start(64, 32);
    begin(48);
    setenv("DIRECTGATE_DESKTOP_FORCE_RAW", "1", 1);
    CHECK(DirectGate_Desktop_Start(&g_session) >= 0 && !g_session.desktop.bInputReady, "a grant without input is view only");
    unsetenv("DIRECTGATE_DESKTOP_FORCE_RAW");
    CHECK(DirectGate_Desktop_FindMonitor(&g_session.desktop, "wayland-0") != NULL, "on the one screen there is");
    CHECK(strstr(g_session.desktop.sFallbackReason, "Remote control") != NULL, "and says so");
    CHECK(control("{\"action\":\"select-monitor\",\"monitorId\":\"wayland-0\"}") == XAPI_CONTINUE && status_is("error"),
        "raw capture is refused on Wayland");
    DirectGate_Desktop_Clear(&g_session.desktop);
    compositor_stop();

    /* A home too long to hold the permission file still streams, without remembering it */
    char sLongHome[4100];
    memset(sLongHome, 'h', sizeof(sLongHome) - 1);
    sLongHome[0] = '/';
    sLongHome[sizeof(sLongHome) - 1] = '\0';
    const char *pHome = getenv("HOME");
    char sHome[1024];
    snprintf(sHome, sizeof(sHome), "%s", pHome != NULL ? pHome : "/tmp");
    setenv("HOME", sLongHome, 1);

    reset_world(1);
    xstrncpy(stub.sNewToken, sizeof(stub.sNewToken), "tok");
    compositor_start(64, 32);
    begin(49);
    CHECK(DirectGate_Desktop_Start(&g_session) >= 0 && status_is("ready"), "a home with no room for the file still works");
    DirectGate_Desktop_Clear(&g_session.desktop);
    compositor_stop();
    setenv("HOME", sHome, 1);
    return 0;
}

#ifdef DIRECTGATE_HAVE_HWENC
/* Bounded by the clock rather than by ticks: under valgrind an encode takes many of them */
static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}

static int stream_until(int nEncoded, buffer_t *pFrame)
{
    for (uint64_t nEnd = now_ms() + 30000; g_sent.nEncoded < nEncoded && now_ms() < nEnd;)
    {
        pFrame->pixels[0]++;
        tick(pFrame);
    }

    return g_sent.nEncoded >= nEncoded;
}

/* Whether there is a software encoder to fall back on: a CI image without OpenH264 has none */
static xbool_t g_bSoftware = XTRUE;

/* Without one, a session whose GPU gave up ends, and says why */
static int ends_with_reason(buffer_t *pFrame, const char *pWhy)
{
    for (uint64_t nEnd = now_ms() + 30000; !status_is("error") && now_ms() < nEnd;)
    {
        if (pFrame != NULL) pFrame->pixels[0]++;
        tick(pFrame);
    }

    return status_is("error") && strstr(DirectGate_Desktop_GetReason(&g_session.desktop), pWhy) != NULL;
}

static int test_gpu(void)
{
    /* A GPU encoder takes the frames, follows a preset change, and hands over to the software encoder when it
       stops taking them, without the session noticing */
    reset_world(1);
    fake_av_reset();
    fake_av()->pEncoders[0] = "h264_nvenc";
    fake_av()->bExtradata = 1;
    compositor_start(64, 32);
    begin(50);

    CHECK(DirectGate_Desktop_Start(&g_session) >= 0, "a desktop with a GPU starts");
    CHECK(control("{\"action\":\"select-monitor\",\"monitorId\":\"wayland-31\"}") == XAPI_CONTINUE &&
          status_is("streaming"), "and streams");
    CHECK(AV(nOpens) == 1 && strcmp(fake_av()->sLastOpened, "h264_nvenc") == 0, "on the GPU encoder");

    buffer_t frame;
    buffer_mapped(&frame, 0, 0, 1, sizeof(frame.pixels));
    CHECK(stream_until(3, &frame) && AV(nSends) >= 3, "frames go through the GPU");

    CHECK(control("{\"action\":\"set-preset\",\"preset\":\"low-latency\"}") == XAPI_CONTINUE, "change the preset");
    CHECK(stream_until(g_sent.nEncoded + 2, &frame) && AV(nOpens) == 2, "the GPU encoder is rebuilt for it");

    fake_av_set(&fake_av()->nFailSends, 40);
    int nSends = AV(nSends);
    if (g_bSoftware)
    {
        CHECK(stream_until(g_sent.nEncoded + 3, &frame), "a GPU that stops taking frames is replaced");
        CHECK(AV(nSends) == nSends && AV(nFailSends) < 40, "by the software encoder, which carries on");
    }
    else CHECK(ends_with_reason(&frame, "OpenH264"), "a GPU that stops taking frames, with nothing to replace it, ends it");

    DirectGate_Desktop_Clear(&g_session.desktop);
    compositor_stop();

    /* A compositor that exports its frames to an agent that cannot import them is asked for memory instead */
    reset_world(1);
    fake_av_reset();
    fake_av()->pEncoders[0] = "h264_nvenc";
    compositor_start(64, 32);
    XSYNC_ATOMIC_SET(&g_comp.bExport, 1);
    begin(51);

    CHECK(DirectGate_Desktop_Start(&g_session) >= 0, "a desktop whose compositor exports starts");
    fake_pw_stream_t *pStream = fake_pw_stream_for_node(31);
    CHECK(pStream != NULL, "its stream");
    int nUpdates = fake_pw_updates(pStream);
    CHECK(control("{\"action\":\"select-monitor\",\"monitorId\":\"wayland-31\"}") == XAPI_CONTINUE &&
          status_is("streaming"), "and streams");
    CHECK(fake_pw_updates(pStream) > nUpdates, "after asking the compositor for memory");
    CHECK(AV(nOpens) == 1, "on the ordinary GPU encoder");

    DirectGate_Desktop_Clear(&g_session.desktop);
    compositor_stop();
    fake_av_reset();
    return 0;
}

#ifdef DIRECTGATE_HWENC_HAS_FILTER
/* The compositor's pool: a buffer is drawn into again only once the agent has given it back */
static buffer_t g_exports[8];
static int g_nExported[8];

static void export_tick(void)
{
    fake_pw_stream_t *pStream = fake_pw_stream_for_node(31);
    for (int i = 0; i < 8; i++)
    {
        if (fake_pw_returned(pStream, &g_exports[i].pw) != g_nExported[i]) continue;

        buffer_exported(&g_exports[i], 100 + i, 0, 64 * 4, 64 * 4 * 32);
        g_nExported[i]++;
        tick(&g_exports[i]);
        return;
    }

    tick(NULL);
}

/* Until this many exports were mapped onto the GPU and as many frames went out: a frame can also go out without a
   new map, when a keyframe is answered from the last picture */
static int export_until(int nMapped)
{
    for (uint64_t nEnd = now_ms() + 30000; now_ms() < nEnd;)
    {
        if (AV(nMaps) >= nMapped && g_sent.nEncoded >= nMapped) return 1;
        export_tick();
    }

    return 0;
}

/* Until every export handed out is back: none is waiting in the slot or being encoded */
static int exports_settled(void)
{
    fake_pw_stream_t *pStream = fake_pw_stream_for_node(31);
    for (uint64_t nEnd = now_ms() + 30000; now_ms() < nEnd;)
    {
        int bSettled = 1;
        for (int i = 0; i < 8; i++)
        {
            if (fake_pw_returned(pStream, &g_exports[i].pw) != g_nExported[i]) bSettled = 0;
        }

        if (bSettled) return 1;
        tick(NULL);
    }

    return 0;
}

/* Exports until the agent asks the compositor for memory, which is how it gives up on zero-copy */
static int export_until_memory(fake_pw_stream_t *pStream)
{
    int nUpdates = fake_pw_updates(pStream);
    for (uint64_t nEnd = now_ms() + 30000; fake_pw_updates(pStream) == nUpdates && now_ms() < nEnd;) export_tick();
    return fake_pw_updates(pStream) > nUpdates;
}

/* The encoder thread asks the compositor for memory first and rebuilds the encoder after */
static int reopened_since(int nBefore)
{
    for (uint64_t nEnd = now_ms() + 30000; AV(nOpens) <= nBefore && now_ms() < nEnd;) tick(NULL);
    return AV(nOpens) > nBefore;
}

static void zero_copy_session(uint32_t nSessionId)
{
    reset_world(1);
    fake_av_reset();
    fake_av()->pEncoders[0] = "h264_vaapi";
    fake_av()->pDevices[0] = "vaapi:";
    fake_av()->bExtradata = 1;
    memset(g_exports, 0, sizeof(g_exports));
    memset(g_nExported, 0, sizeof(g_nExported));
    compositor_start(64, 32);
    XSYNC_ATOMIC_SET(&g_comp.bExport, 1);
    begin(nSessionId);
}

static int test_zero_copy(void)
{
    /* A compositor that exports its frames to a VAAPI GPU with a post-processor: they reach the encoder without a
       copy, a still screen's keyframe is the last converted picture, and a GPU that starts refusing them is given a
       few more before the session moves to copied frames - without noticing */
    zero_copy_session(53);
    CHECK(DirectGate_Desktop_Start(&g_session) >= 0, "a desktop whose compositor exports starts");
    fake_pw_stream_t *pStream = fake_pw_stream_for_node(31);
    CHECK(pStream != NULL, "its stream");
    int nUpdates = fake_pw_updates(pStream);
    CHECK(control("{\"action\":\"select-monitor\",\"monitorId\":\"wayland-31\"}") == XAPI_CONTINUE &&
          status_is("streaming"), "and streams");
    CHECK(fake_pw_updates(pStream) == nUpdates && fake_av()->eLastPixFmt == AV_PIX_FMT_VAAPI && fake_av()->sScaleArgs[0] != '\0',
        "from the compositor's own buffers, converted on the GPU");

    CHECK(export_until(3), "exported frames go to the encoder as they are");
    CHECK(exports_settled(), "and every one of them comes back to the compositor");

    int nMaps = AV(nMaps);
    int nBefore = g_sent.nEncoded;
    CHECK(control("{\"action\":\"request-keyframe\"}") == XAPI_CONTINUE, "ask for a keyframe");
    for (int i = 0; i < 300 && g_sent.nEncoded == nBefore; i++) tick(NULL);
    CHECK(g_sent.nEncoded > nBefore && AV(nMaps) == nMaps, "a still screen answers it from the last converted picture");

    int nOpens = AV(nOpens);
    fake_av_set(&fake_av()->nFailMaps, 1000);
    CHECK(export_until_memory(pStream), "a GPU that keeps refusing the compositor's frames has it send memory instead");
    /* At least: the rate controller may reopen the encoder on its own clock as well */
    CHECK(reopened_since(nOpens) && AV(nMaps) > nMaps + 1, "after a few tries, on a rebuilt encoder");
    CHECK(status_is("streaming"), "and the session carries on");

    uint8_t pod[1024];
    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRx,
        64, 32, MODIFIER_NONE, MOD_LINEAR));
    buffer_t frame;
    buffer_mapped(&frame, 0, 0, 1, sizeof(frame.pixels));
    nMaps = AV(nMaps);
    int nSends = AV(nSends);
    CHECK(stream_until(g_sent.nEncoded + 3, &frame) && AV(nSends) > nSends && AV(nMaps) == nMaps,
        "copied frames go to the GPU encoder from then on");

    DirectGate_Desktop_Clear(&g_session.desktop);
    compositor_stop();
    CHECK(fake_pw_live() == 0, "and nothing is left of the session");

    /* Refused from the very first frame: no retries, and with no GPU encoder left, the software one */
    zero_copy_session(54);
    CHECK(DirectGate_Desktop_Start(&g_session) >= 0, "a second exporting desktop starts");
    pStream = fake_pw_stream_for_node(31);
    CHECK(pStream != NULL && control("{\"action\":\"select-monitor\",\"monitorId\":\"wayland-31\"}") == XAPI_CONTINUE &&
          status_is("streaming"), "and streams");
    fake_av_set(&fake_av()->nFailMaps, 1000);
    fake_av_set_encoder(0, NULL);
    CHECK(export_until_memory(pStream) && AV(nMaps) == 1, "a GPU that refuses the first frame is not asked again");

    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRx,
        64, 32, MODIFIER_NONE, MOD_LINEAR));
    nSends = AV(nSends);
    if (g_bSoftware)
    {
        CHECK(stream_until(g_sent.nEncoded + 3, &frame) && AV(nSends) == nSends && status_is("streaming"),
            "and the software encoder takes the copied frames");
    }
    else CHECK(ends_with_reason(&frame, "OpenH264"), "and without a software encoder the session ends, saying why");

    DirectGate_Desktop_Clear(&g_session.desktop);
    compositor_stop();
    fake_av_reset();
    return 0;
}

/* No encoder left at all: the GPU refuses the compositor's frames and there is no OpenH264. The session ends with
   the reason - which lives in the encoder being stopped, so it has to be copied out first. In a child, so that a
   missing OpenH264 is all it ever sees. */
static int no_encoder_left(void)
{
    setenv("DIRECTGATE_OPENH264_LIB", "/nonexistent/libopenh264.so", 1);
    zero_copy_session(55);
    CHECK(DirectGate_Desktop_Start(&g_session) >= 0, "an exporting desktop starts");
    CHECK(control("{\"action\":\"select-monitor\",\"monitorId\":\"wayland-31\"}") == XAPI_CONTINUE &&
          status_is("streaming"), "and streams");

    fake_pw_stream_t *pStream = fake_pw_stream_for_node(31);
    fake_av_set(&fake_av()->nFailMaps, 1000);
    fake_av_set_encoder(0, NULL);
    CHECK(pStream != NULL && export_until_memory(pStream), "a GPU that refuses the frames has the compositor send memory");

    uint8_t pod[1024];
    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRx,
        64, 32, MODIFIER_NONE, MOD_LINEAR));
    buffer_t frame;
    buffer_mapped(&frame, 0, 0, 1, sizeof(frame.pixels));
    CHECK(ends_with_reason(&frame, "DIRECTGATE_OPENH264_LIB"), "and with no encoder left the session ends, saying why");

    DirectGate_Desktop_Clear(&g_session.desktop);
    compositor_stop();
    return 0;
}

static int in_child(int (*fnCheck)(void))
{
    fflush(NULL);
    pid_t nPid = fork();
    /* exit, not _exit: the child's coverage is written by its exit handlers */
    if (nPid == 0) exit(fnCheck());

    int nStatus = 0;
    return nPid > 0 && waitpid(nPid, &nStatus, 0) == nPid && WIFEXITED(nStatus) && WEXITSTATUS(nStatus) == 0;
}
#endif
#endif

int main(void)
{
    signal(SIGPIPE, SIG_IGN);

    char sHome[] = "/tmp/directgate_wl_desktop.XXXXXX";
    CHECK(mkdtemp(sHome) != NULL, "make a home");
    setenv("HOME", sHome, 1);
    setenv("XDG_SESSION_TYPE", "wayland", 1);
    unsetenv("DIRECTGATE_DESKTOP_FORCE_RAW");
    unsetenv("DIRECTGATE_DESKTOP_PRESET");

    /* Zero-copy first: whether to offer the compositor exports is asked of the GPU from the first session on, and
       the device cache keeps a device that would not open for the life of the process */
    int nFailed = 0;
#ifdef DIRECTGATE_HWENC_HAS_FILTER
    /* Before this process has any thread a child could inherit a held lock from */
    nFailed = !in_child(no_encoder_left);
#endif
#ifdef DIRECTGATE_HAVE_HWENC
    g_bSoftware = DirectGate_OpenH264_Load(NULL, 0) == XSTDOK ? XTRUE : XFALSE;
    if (!g_bSoftware) puts("desktop_wayland_smoke: no OpenH264 here, GPU failures are checked to end the session");
#endif
#ifdef DIRECTGATE_HWENC_HAS_FILTER
    nFailed = nFailed || test_zero_copy();
#endif
    nFailed = nFailed || test_streaming() || test_prompt() || test_refusals();
#ifdef DIRECTGATE_HAVE_HWENC
    nFailed = nFailed || test_gpu();
#endif

    char sPath[256];
    snprintf(sPath, sizeof(sPath), "%s/.config/directgate/wayland.token", sHome);
    unlink(sPath);
    snprintf(sPath, sizeof(sPath), "%s/.config/directgate", sHome);
    rmdir(sPath);
    snprintf(sPath, sizeof(sPath), "%s/.config", sHome);
    rmdir(sPath);
    rmdir(sHome);

    if (nFailed) return 1;
    puts("desktop_wayland_smoke: OK");
    return 0;
}
