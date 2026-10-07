/* The Wayland desktop source: a scripted portal (wayland_portal_stub.h) in front of the real PipeWire capture on
 * fake_pipewire.h. The remembered permission - kept, presented, refreshed, dropped when it stops working and kept
 * when somebody said no - every way setup can fail or be abandoned, the newest-frame slot in memory and as an
 * export, and moving to another screen without losing or leaking a buffer on the way. */

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "wayland_portal_stub.h"
#include "wayland_stream_fixture.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "wayland_source_smoke: %s (line %d)\n", msg, __LINE__); \
            return 1; \
        } \
    } while (0)

static char g_sRoot[] = "/tmp/directgate_wl_source.XXXXXX";
static char g_sToken[256];

/* ---------------- helpers ---------------- */

static int write_file(const char *pPath, const char *pText, mode_t nMode)
{
    FILE *pFile = fopen(pPath, "w");
    if (pFile == NULL) return 0;

    fputs(pText, pFile);
    fclose(pFile);
    return chmod(pPath, nMode) == 0;
}

static int read_file(const char *pPath, char *pBuf, size_t nSize)
{
    FILE *pFile = fopen(pPath, "r");
    if (pFile == NULL) return 0;

    size_t nRead = fread(pBuf, 1, nSize - 1, pFile);
    fclose(pFile);
    pBuf[nRead] = '\0';
    return 1;
}

static fake_pw_stream_t* wait_node(uint32_t nNode)
{
    for (int i = 0; i < 2000; i++)
    {
        fake_pw_stream_t *pStream = fake_pw_stream_for_node(nNode);
        if (pStream != NULL && !fake_pw_destroyed(pStream)) return pStream;
        usleep(1000);
    }

    return NULL;
}

static int wait_state(directgate_wl_source_t *pSource, directgate_wl_state_t eState)
{
    for (int i = 0; i < 8000; i++)
    {
        if (DirectGate_WL_SourceState(pSource) == eState) return 1;
        usleep(1000);
    }

    return 0;
}

static void serve(fake_pw_stream_t *pStream, int eModifier)
{
    uint8_t pod[1024];
    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRx,
        64, 32, eModifier, MOD_LINEAR));
}

/* A granted source on screen 31, ready */
static directgate_wl_source_t* ready_source(xbool_t bDmaBuf, fake_pw_stream_t **ppStream)
{
    fake_pw_reset();
    stub_portal_reset();
    stub.streams[1].nNodeId = 32;
    stub.streams[1].nWidth = 64;
    stub.streams[1].nHeight = 32;
    stub.nStreams = 2;

    directgate_wl_source_t *pSource = DirectGate_WL_SourceCreate(NULL, bDmaBuf);
    fake_pw_stream_t *pStream = pSource != NULL ? wait_node(31) : NULL;
    if (pStream == NULL) return pSource;

    serve(pStream, bDmaBuf ? MODIFIER_FIXED : MODIFIER_NONE);
    if (!wait_state(pSource, DIRECTGATE_WL_READY)) return pSource;

    *ppStream = pStream;
    return pSource;
}

/* ---------------- the remembered permission ---------------- */

static int check_fresh_grant(void)
{
    char sDeep[300], sText[128];
    snprintf(sDeep, sizeof(sDeep), "%s/never/made/token", g_sRoot);

    fake_pw_reset();
    stub_portal_reset();
    xstrncpy(stub.sNewToken, sizeof(stub.sNewToken), "tok-1");

    directgate_wl_source_t *pSource = DirectGate_WL_SourceCreate(sDeep, XFALSE);
    CHECK(pSource != NULL, "create a source");
    CHECK(DirectGate_WL_SourceState(pSource) != DIRECTGATE_WL_FAILED, "it starts out pending");

    fake_pw_stream_t *pStream = wait_node(31);
    CHECK(pStream != NULL, "the granted screen is subscribed to");
    serve(pStream, MODIFIER_NONE);
    CHECK(wait_state(pSource, DIRECTGATE_WL_READY), "and ready once it has a format");

    CHECK(stub.nOpens == 1 && stub.sRestore[0][0] == '\0', "nothing was presented the first time");
    CHECK(read_file(sDeep, sText, sizeof(sText)) && strcmp(sText, "tok-1") == 0,
        "the permission is kept, even where its directory did not exist");

    struct stat info;
    CHECK(stat(sDeep, &info) == 0 && (info.st_mode & 0777) == 0600, "readable by its owner only");

    uint32_t nWidth = 0, nHeight = 0;
    CHECK(DirectGate_WL_SourceSize(pSource, &nWidth, &nHeight) && nWidth == 64 && nHeight == 32, "it has a size");
    CHECK(DirectGate_WL_SourceActiveNode(pSource) == 31 && DirectGate_WL_SourceHasInput(pSource), "screen and input");
    CHECK(DirectGate_WL_SourceScreenCount(pSource) == 1 && DirectGate_WL_SourceScreen(pSource, 0)->nNodeId == 31,
        "and the screens it was given");
    CHECK(DirectGate_WL_SourcePortal(pSource) != NULL && !DirectGate_WL_SourceLost(pSource, NULL, 0), "nothing lost");
    CHECK(strstr(DirectGate_WL_SourceError(pSource), "failed") != NULL, "no error of its own");

    DirectGate_WL_SourceDestroy(pSource);
    CHECK(stub.nClosed == 1 && fake_pw_live() == 0 && fake_pw_open_fds() == 0, "destroyed whole");
    return 0;
}

static int check_remembered(void)
{
    char sText[128];

    /* Presented as it was kept, without the newline an editor leaves, and replaced by the one that comes back */
    CHECK(write_file(g_sToken, "tok-1\r\n", 0600), "remember a permission");
    fake_pw_reset();
    stub_portal_reset();
    xstrncpy(stub.sNewToken, sizeof(stub.sNewToken), "tok-2");

    directgate_wl_source_t *pSource = DirectGate_WL_SourceCreate(g_sToken, XFALSE);
    fake_pw_stream_t *pStream = wait_node(31);
    CHECK(pSource != NULL && pStream != NULL, "create a source");
    serve(pStream, MODIFIER_NONE);
    CHECK(wait_state(pSource, DIRECTGATE_WL_READY), "ready");
    CHECK(stub.nOpens == 1 && strcmp(stub.sRestore[0], "tok-1") == 0, "the kept permission was presented");
    CHECK(read_file(g_sToken, sText, sizeof(sText)) && strcmp(sText, "tok-2") == 0, "and the new one kept");
    DirectGate_WL_SourceDestroy(pSource);

    /* A kept permission that no longer works is dropped and the person is asked again */
    stub_portal_reset();
    fake_pw_reset();
    stub.answers[0] = STUB_REFUSE;
    xstrncpy(stub.sNewToken, sizeof(stub.sNewToken), "fresh");

    pSource = DirectGate_WL_SourceCreate(g_sToken, XFALSE);
    pStream = wait_node(31);
    CHECK(pSource != NULL && pStream != NULL, "create another");
    serve(pStream, MODIFIER_NONE);
    CHECK(wait_state(pSource, DIRECTGATE_WL_READY), "ready on the second request");
    CHECK(stub.nOpens == 2 && strcmp(stub.sRestore[0], "tok-2") == 0 && stub.sRestore[1][0] == '\0',
        "the stale permission was tried, then nothing was presented");
    CHECK(read_file(g_sToken, sText, sizeof(sText)) && strcmp(sText, "fresh") == 0, "and the fresh one kept");
    DirectGate_WL_SourceDestroy(pSource);

    /* A grant with nothing to remember drops what was kept */
    stub_portal_reset();
    fake_pw_reset();
    pSource = DirectGate_WL_SourceCreate(g_sToken, XFALSE);
    pStream = wait_node(31);
    CHECK(pSource != NULL && pStream != NULL, "create a third");
    serve(pStream, MODIFIER_NONE);
    CHECK(wait_state(pSource, DIRECTGATE_WL_READY), "ready");
    CHECK(access(g_sToken, F_OK) != 0, "a permission the portal did not renew is forgotten");
    DirectGate_WL_SourceDestroy(pSource);

    /* No means no: nobody is asked again, and the permission stays for next time */
    CHECK(write_file(g_sToken, "kept", 0600), "remember one again");
    stub_portal_reset();
    fake_pw_reset();
    stub.answers[0] = STUB_DECLINE;

    pSource = DirectGate_WL_SourceCreate(g_sToken, XFALSE);
    CHECK(pSource != NULL && wait_state(pSource, DIRECTGATE_WL_FAILED), "a refusal fails the source");
    CHECK(stub.nOpens == 1 && strstr(DirectGate_WL_SourceError(pSource), "declined") != NULL, "once, and says so");
    CHECK(access(g_sToken, F_OK) == 0, "and the kept permission stays");
    CHECK(!DirectGate_WL_SourceLost(pSource, NULL, 0) && !DirectGate_WL_SourceSize(pSource, NULL, NULL),
        "a failed source has no picture to lose");
    DirectGate_WL_SourceDestroy(pSource);

    /* A file with nothing in it is no permission */
    const char *pEmpty[] = { "", "\n" };
    for (size_t i = 0; i < 2; i++)
    {
        CHECK(write_file(g_sToken, pEmpty[i], 0600), "keep an empty permission");
        stub_portal_reset();
        fake_pw_reset();
        stub.answers[0] = STUB_REFUSE;

        pSource = DirectGate_WL_SourceCreate(g_sToken, XFALSE);
        CHECK(pSource != NULL && wait_state(pSource, DIRECTGATE_WL_FAILED), "a refused request fails the source");
        CHECK(stub.nOpens == 1 && stub.sRestore[0][0] == '\0', "an empty permission is not presented or retried");
        DirectGate_WL_SourceDestroy(pSource);
    }

    return 0;
}

static int check_unwritable(void)
{
    if (geteuid() == 0) return 0;

    /* A permission that cannot be replaced or removed costs a prompt, never the session */
    char sDir[300], sPath[320];
    snprintf(sDir, sizeof(sDir), "%s/locked", g_sRoot);
    snprintf(sPath, sizeof(sPath), "%s/token", sDir);
    CHECK(mkdir(sDir, 0700) == 0 && write_file(sPath, "old", 0400) && chmod(sDir, 0500) == 0, "lock a permission");

    stub_portal_reset();
    fake_pw_reset();
    stub.answers[0] = STUB_REFUSE;
    xstrncpy(stub.sNewToken, sizeof(stub.sNewToken), "new");

    directgate_wl_source_t *pSource = DirectGate_WL_SourceCreate(sPath, XFALSE);
    fake_pw_stream_t *pStream = wait_node(31);
    CHECK(pSource != NULL && pStream != NULL, "create a source");
    serve(pStream, MODIFIER_NONE);
    CHECK(wait_state(pSource, DIRECTGATE_WL_READY), "the session goes ahead");
    CHECK(stub.nOpens == 2 && access(sPath, F_OK) == 0, "though the stale permission could not be removed");
    DirectGate_WL_SourceDestroy(pSource);

    CHECK(chmod(sDir, 0700) == 0 && unlink(sPath) == 0 && rmdir(sDir) == 0, "unlock it");

    /* A permission file that is a directory is unreadable and unwritable */
    snprintf(sPath, sizeof(sPath), "%s/directory", g_sRoot);
    CHECK(mkdir(sPath, 0700) == 0, "put a directory where the permission goes");
    stub_portal_reset();
    fake_pw_reset();
    xstrncpy(stub.sNewToken, sizeof(stub.sNewToken), "new");
    pSource = DirectGate_WL_SourceCreate(sPath, XFALSE);
    pStream = wait_node(31);
    CHECK(pSource != NULL && pStream != NULL, "create another");
    serve(pStream, MODIFIER_NONE);
    CHECK(wait_state(pSource, DIRECTGATE_WL_READY) && stub.sRestore[0][0] == '\0', "nothing is presented from it");
    DirectGate_WL_SourceDestroy(pSource);
    CHECK(rmdir(sPath) == 0, "remove the directory");
    return 0;
}

/* ---------------- setup that fails or is abandoned ---------------- */

static int check_setup_failures(void)
{
    /* The portal descriptor does not open */
    stub_portal_reset();
    fake_pw_reset();
    stub.nFailPipeWire = 1;
    directgate_wl_source_t *pSource = DirectGate_WL_SourceCreate(NULL, XFALSE);
    CHECK(pSource != NULL && wait_state(pSource, DIRECTGATE_WL_FAILED), "no PipeWire descriptor fails the source");
    CHECK(strstr(DirectGate_WL_SourceError(pSource), "PipeWire") != NULL, "and says why");
    DirectGate_WL_SourceDestroy(pSource);

    /* A permission with nowhere to keep it is simply not kept */
    stub_portal_reset();
    fake_pw_reset();
    xstrncpy(stub.sNewToken, sizeof(stub.sNewToken), "unkept");
    pSource = DirectGate_WL_SourceCreate("", XFALSE);
    fake_pw_stream_t *pStream = wait_node(31);
    CHECK(pSource != NULL && pStream != NULL, "a source with no permission file");
    serve(pStream, MODIFIER_NONE);
    CHECK(wait_state(pSource, DIRECTGATE_WL_READY), "works all the same");
    DirectGate_WL_SourceDestroy(pSource);

    /* The capture does not start */
    stub_portal_reset();
    fake_pw_reset();
    fake_pw_fail_next("pw_stream_new");
    pSource = DirectGate_WL_SourceCreate(NULL, XFALSE);
    CHECK(pSource != NULL && wait_state(pSource, DIRECTGATE_WL_FAILED), "a capture that will not start fails it");
    DirectGate_WL_SourceDestroy(pSource);
    CHECK(fake_pw_live() == 0 && fake_pw_open_fds() == 0 && stub.nClosed == 1, "and leaves nothing");

    /* Abandoned while the portal waits for an answer: both before and after it comes */
    const stub_answer_t holds[] = { STUB_HOLD_GRANT, STUB_HOLD_REFUSE };
    for (size_t i = 0; i < 2; i++)
    {
        CHECK(write_file(g_sToken, "kept", 0600), "remember a permission");
        stub_portal_reset();
        fake_pw_reset();
        stub.answers[0] = holds[i];

        pSource = DirectGate_WL_SourceCreate(g_sToken, XFALSE);
        CHECK(pSource != NULL, "create a source");
        while (!stub_portal_get(&stub.bHolding)) usleep(1000);
        DirectGate_WL_SourceDestroy(pSource);
        CHECK(stub.nOpens == 1 && stub.nPipeWire == 0, "an abandoned request is neither retried nor streamed");
    }

    /* A format that never comes */
    stub_portal_reset();
    fake_pw_reset();
    pSource = DirectGate_WL_SourceCreate(NULL, XFALSE);
    CHECK(pSource != NULL && wait_state(pSource, DIRECTGATE_WL_FAILED), "a stream without a format fails the source");
    CHECK(strstr(DirectGate_WL_SourceError(pSource), "format") != NULL, "and says why");
    CHECK(!DirectGate_WL_SourceLost(pSource, NULL, 0), "a source that never started cannot lose its stream");
    DirectGate_WL_SourceDestroy(pSource);
    return 0;
}

/* ---------------- the newest-frame slot ---------------- */

static int check_mapped_frames(void)
{
    fake_pw_stream_t *pStream = NULL;
    directgate_wl_source_t *pSource = ready_source(XFALSE, &pStream);
    CHECK(pSource != NULL && pStream != NULL, "a ready source");

    uint8_t *pDst = (uint8_t*)calloc(1, 64 * 32 * 4);
    CHECK(pDst != NULL, "allocate a frame");
    CHECK(DirectGate_WL_SourceWaitFrame(pSource, 1000) == XSTDNON, "no frame yet is a timeout");
    CHECK(DirectGate_WL_SourceTakeFrame(pSource, &pDst, 64 * 32 * 4, 64, 32) == XSTDNON, "nothing to take");

    buffer_t buffer;
    buffer_mapped(&buffer, 0, 64 * 4 + 64, 1, sizeof(buffer.pixels));
    buffer.pixels[(64 * 4 + 64) * 31] = 0x7e;
    emit_buffer(pStream, &buffer);
    CHECK(DirectGate_WL_SourceWaitFrame(pSource, 1000000) == XSTDOK, "a frame wakes the encoder");
    CHECK(fake_pw_returned(pStream, &buffer.pw) == 1, "and its buffer went back as soon as it was copied");

    /* Same size: handed over without a copy, packed */
    uint8_t *pBefore = pDst;
    CHECK(DirectGate_WL_SourceTakeFrame(pSource, &pDst, 64 * 32 * 4, 64, 32) == XSTDOK, "take it");
    CHECK(pDst != pBefore && pDst[0] == 0x5a && pDst[64 * 4 * 31] == 0x7e, "packed rows, swapped in");
    CHECK(DirectGate_WL_SourceTakeFrame(pSource, &pDst, 64 * 32 * 4, 64, 32) == XSTDNON, "taken once");
    CHECK(DirectGate_WL_SourceTakeDmaBuf(pSource, &(directgate_desktop_dmabuf_t){ 0 }, &(void*){ NULL }) == XSTDNON,
        "a mapped frame is no export");

    /* Another size: scaled into what was asked for */
    emit_buffer(pStream, &buffer);
    CHECK(DirectGate_WL_SourceTakeFrame(pSource, NULL, 64 * 32 * 4, 64, 32) == XSTDERR &&
          DirectGate_WL_SourceTakeFrame(pSource, &pDst, 64 * 32 * 4, 64, 0) == XSTDERR, "a frame needs a place and size");
    CHECK(DirectGate_WL_SourceTakeDmaBuf(pSource, &(directgate_desktop_dmabuf_t){ 0 }, NULL) == XSTDERR,
        "an export needs a place for its buffer");
    CHECK(DirectGate_WL_SourceTakeFrame(pSource, &pDst, 64 * 32 * 4, 64, 16) == XSTDOK, "a shorter frame is scaled");
    emit_buffer(pStream, &buffer);
    CHECK(DirectGate_WL_SourceTakeFrame(pSource, &pDst, 64 * 32 * 4, 32, 16) == XSTDOK, "a smaller frame is scaled");
    CHECK(DirectGate_WL_SourceWaitFrame(pSource, 1000) == XSTDNON, "and is not fresh any more");

    char sError[128] = { 0 };
    emit_state(pStream, PW_STREAM_STATE_ERROR, "gone");
    CHECK(DirectGate_WL_SourceLost(pSource, sError, sizeof(sError)) && strcmp(sError, "gone") == 0, "lost with a reason");

    free(pDst);
    DirectGate_WL_SourceDestroy(pSource);
    CHECK(fake_pw_live() == 0, "nothing left");
    return 0;
}

static int check_exported_frames(void)
{
    fake_pw_stream_t *pStream = NULL;
    directgate_wl_source_t *pSource = ready_source(XTRUE, &pStream);
    CHECK(pSource != NULL && pStream != NULL, "a ready exporting source");

    uint32_t nFourCC = 0;
    CHECK(DirectGate_WL_SourceIsDmaBuf(pSource, &nFourCC, NULL) && nFourCC == DRM_XRGB8888, "it exports");

    directgate_desktop_dmabuf_t frame;
    void *pHandle = NULL;
    uint8_t *pDst = (uint8_t*)calloc(1, 64 * 32 * 4);
    CHECK(pDst != NULL, "allocate a frame");
    DirectGate_WL_SourceReleaseFrame(pSource, &pHandle);
    DirectGate_WL_SourceReleaseFrame(pSource, NULL);

    buffer_t first, second, third;
    buffer_exported(&first, 90, 0, 0, 0);
    buffer_exported(&second, 91, 0, 0, 0);
    buffer_exported(&third, 92, 0, 0, 0);

    emit_buffer(pStream, &first);
    CHECK(DirectGate_WL_SourceTakeFrame(pSource, &pDst, 64 * 32 * 4, 64, 32) == XSTDNON, "an export is not memory");
    CHECK(DirectGate_WL_SourceTakeDmaBuf(pSource, &frame, &pHandle) == XSTDOK && pHandle == &first.pw &&
          frame.nFds[0] == 90, "it is taken as an export");
    CHECK(DirectGate_WL_SourceTakeDmaBuf(pSource, &frame, &pHandle) == XSTDNON, "once");
    CHECK(fake_pw_returned(pStream, &first.pw) == 0, "and stays out while it is encoded");
    DirectGate_WL_SourceReleaseFrame(pSource, pHandle);
    CHECK(fake_pw_returned(pStream, &first.pw) == 1, "until the encoder gives it back");

    /* Overtaken in the slot: the older export goes back without ever being taken */
    emit_buffer(pStream, &second);
    emit_buffer(pStream, &third);
    CHECK(fake_pw_returned(pStream, &second.pw) == 1 && fake_pw_returned(pStream, &third.pw) == 0,
        "an overtaken export goes back, the newest stays");

    /* A renegotiation to memory hands back the export waiting in the slot */
    uint8_t pod[1024];
    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRx,
        64, 32, MODIFIER_NONE, 0));
    buffer_t mapped;
    buffer_mapped(&mapped, 0, 0, 1, sizeof(mapped.pixels));
    emit_buffer(pStream, &mapped);
    CHECK(fake_pw_returned(pStream, &third.pw) == 1, "a mapped frame sends the waiting export back");
    CHECK(DirectGate_WL_SourceTakeFrame(pSource, &pDst, 64 * 32 * 4, 64, 32) == XSTDOK, "and takes its place");

    /* Back to exporting, then the encoder refuses exports with one waiting */
    serve(pStream, MODIFIER_FIXED);
    buffer_t fourth;
    buffer_exported(&fourth, 93, 0, 0, 0);
    emit_buffer(pStream, &fourth);
    int nUpdates = fake_pw_updates(pStream);
    DirectGate_WL_SourceDisableDmaBuf(pSource);
    CHECK(fake_pw_returned(pStream, &fourth.pw) == 1, "refusing exports gives the waiting one back");
    CHECK(fake_pw_updates(pStream) == nUpdates + 1, "and asks the compositor for memory");
    CHECK(DirectGate_WL_SourceTakeDmaBuf(pSource, &frame, &pHandle) == XSTDNON, "nothing is left to take");

    /* One still waiting when the source goes is given back before its stream is torn down */
    serve(pStream, MODIFIER_FIXED);
    buffer_t fifth;
    buffer_exported(&fifth, 94, 0, 0, 0);
    emit_buffer(pStream, &fifth);
    DirectGate_WL_SourceDestroy(pSource);
    CHECK(fake_pw_returned(pStream, &fifth.pw) == 1, "the last export goes back on the way out");

    free(pDst);
    CHECK(fake_pw_live() == 0, "nothing left");
    return 0;
}

/* ---------------- moving to another screen ---------------- */

typedef struct {
    uint32_t nNode;
    int eModifier;
    fake_pw_stream_t *pStream;
    buffer_t *pEarly;       /* delivered with the format, before the switch can finish */
} later_t;

static void serve_with_frame(void *pArg)
{
    later_t *pLater = (later_t*)pArg;
    uint8_t pod[1024];
    fake_pw_emit_param(pLater->pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video,
        SPA_VIDEO_FORMAT_BGRx, 64, 32, pLater->eModifier, MOD_LINEAR));

    if (pLater->pEarly == NULL) return;
    fake_pw_queue(pLater->pStream, &pLater->pEarly->pw);
    fake_pw_emit_process(pLater->pStream);
}

static void* serve_later(void *pArg)
{
    later_t *pLater = (later_t*)pArg;
    pLater->pStream = wait_node(pLater->nNode);
    if (pLater->pStream != NULL) fake_pw_run(pLater->pStream, serve_with_frame, pLater);
    return NULL;
}

static void set_on_stop(void *pArg)
{
    later_t *pLater = (later_t*)pArg;
    pLater->pStream->pOnStopArg = pLater;
    pLater->pStream->fnOnStop = serve_with_frame;
}

/* The stream gets its format and a frame only as its loop stops; set on the loop, which reads it there */
static void* arm_on_stop(void *pArg)
{
    later_t *pLater = (later_t*)pArg;
    pLater->pStream = wait_node(pLater->nNode);
    if (pLater->pStream != NULL) fake_pw_run(pLater->pStream, set_on_stop, pLater);
    return NULL;
}

static int switch_to(directgate_wl_source_t *pSource, uint32_t nNode, int eModifier, buffer_t *pEarly)
{
    later_t format = { nNode, eModifier, NULL, pEarly };
    pthread_t thread;
    if (pthread_create(&thread, NULL, serve_later, &format) != 0) return XSTDERR;

    int nStatus = DirectGate_WL_SourceSelect(pSource, nNode);
    pthread_join(thread, NULL);
    return nStatus;
}

typedef struct {
    fake_pw_stream_t *pStream;
    buffer_t *pBuffer;
} late_t;

static void deliver_late(void *pArg)
{
    late_t *pLate = (late_t*)pArg;
    fake_pw_queue(pLate->pStream, &pLate->pBuffer->pw);
    fake_pw_emit_process(pLate->pStream);
}

static int check_select(void)
{
    fake_pw_stream_t *pOld = NULL;
    directgate_wl_source_t *pSource = ready_source(XTRUE, &pOld);
    CHECK(pSource != NULL && pOld != NULL, "a ready exporting source on screen 31");
    CHECK(DirectGate_WL_SourceScreenCount(pSource) == 2, "with two screens granted");

    CHECK(DirectGate_WL_SourceSelect(pSource, 0) == XSTDOK && DirectGate_WL_SourceSelect(pSource, 31) == XSTDOK &&
          fake_pw_stream_count() == 1, "no screen or the same screen changes nothing");

    stub.nFailPipeWire = 1;
    CHECK(DirectGate_WL_SourceSelect(pSource, 32) == XSTDERR, "a screen whose descriptor does not open is refused");
    fake_pw_fail_next("pw_stream_new");
    CHECK(DirectGate_WL_SourceSelect(pSource, 32) == XSTDERR, "and one whose capture does not start");

    /* The format comes just after the wait gave up, with an export, while the refused stream stops */
    static buffer_t leftover;
    buffer_exported(&leftover, 99, 0, 0, 0);
    later_t tooLate = { 32, MODIFIER_FIXED, NULL, &leftover };
    pthread_t lateThread;
    CHECK(pthread_create(&lateThread, NULL, arm_on_stop, &tooLate) == 0, "watch for the refused screen's stream");
    CHECK(DirectGate_WL_SourceSelect(pSource, 32) == XSTDERR, "and one that never agrees on a format");
    pthread_join(lateThread, NULL);
    CHECK(tooLate.pStream != NULL && fake_pw_returned(tooLate.pStream, &leftover.pw) == 1,
        "an export it delivered as it stopped went back to it before it was freed");

    directgate_desktop_dmabuf_t taken;
    void *pTaken = NULL;
    CHECK(DirectGate_WL_SourceTakeDmaBuf(pSource, &taken, &pTaken) == XSTDNON, "and nothing of it is left to take");
    CHECK(DirectGate_WL_SourceActiveNode(pSource) == 31 && !pOld->bDestroyed, "the session stays where it was");

    /* An export is waiting from the old screen, and another is on its way when that stream stops */
    buffer_t waiting, late, next;
    buffer_exported(&waiting, 95, 0, 0, 0);
    buffer_exported(&late, 96, 0, 0, 0);
    buffer_exported(&next, 97, 0, 0, 0);
    emit_buffer(pOld, &waiting);

    late_t onStop = { pOld, &late };
    pOld->fnOnStop = deliver_late;
    pOld->pOnStopArg = &onStop;

    /* The new screen's first export lands while the switch is still waiting for its format */
    buffer_t early;
    buffer_exported(&early, 98, 0, 0, 0);
    CHECK(switch_to(pSource, 32, MODIFIER_FIXED, &early) == XSTDOK, "the other screen is switched to");

    fake_pw_stream_t *pNew = fake_pw_stream_for_node(32);
    CHECK(pNew != NULL && DirectGate_WL_SourceActiveNode(pSource) == 32, "it is the active one");
    CHECK(pOld->bDestroyed, "and the old stream is gone");
    CHECK(fake_pw_returned(pOld, &waiting.pw) == 1, "the export that was waiting went back to the old stream");
    CHECK(fake_pw_returned(pOld, &late.pw) == 1, "and so did the one that arrived while it stopped");
    CHECK(fake_pw_returned(pNew, &early.pw) == 1, "the new screen's early export went back to the new stream");

    /* The new screen's frames take the slot and nothing of the old one is touched again */
    emit_buffer(pNew, &next);
    directgate_desktop_dmabuf_t frame;
    void *pHandle = NULL;
    CHECK(DirectGate_WL_SourceTakeDmaBuf(pSource, &frame, &pHandle) == XSTDOK && pHandle == &next.pw,
        "the new screen's export is the one taken");
    DirectGate_WL_SourceReleaseFrame(pSource, pHandle);
    CHECK(fake_pw_returned(pNew, &next.pw) == 1, "and goes back to the new stream");

    /* Back again with nothing waiting, then once more from a picture in memory */
    CHECK(switch_to(pSource, 31, MODIFIER_NONE, NULL) == XSTDOK && DirectGate_WL_SourceActiveNode(pSource) == 31,
        "back to the first screen");
    fake_pw_stream_t *pBack = fake_pw_stream_for_node(31);
    buffer_t mapped;
    buffer_mapped(&mapped, 0, 0, 1, sizeof(mapped.pixels));
    CHECK(pBack != NULL, "its stream");
    emit_buffer(pBack, &mapped);
    CHECK(switch_to(pSource, 32, MODIFIER_NONE, NULL) == XSTDOK && DirectGate_WL_SourceWaitFrame(pSource, 1000) == XSTDNON,
        "a picture in memory from the old screen is not shown on the new one");

    DirectGate_WL_SourceDestroy(pSource);
    CHECK(fake_pw_live() == 0 && fake_pw_open_fds() == 0, "nothing left of either screen");
    return 0;
}

static int check_guards(void)
{
    CHECK(DirectGate_WL_SourceState(NULL) == DIRECTGATE_WL_FAILED && DirectGate_WL_SourceError(NULL) != NULL,
        "no source has failed");
    CHECK(!DirectGate_WL_SourceSize(NULL, NULL, NULL) && DirectGate_WL_SourceActiveNode(NULL) == 0 &&
          !DirectGate_WL_SourceHasInput(NULL) && !DirectGate_WL_SourceLost(NULL, NULL, 0), "and has nothing");
    CHECK(DirectGate_WL_SourceScreenCount(NULL) == 0 && DirectGate_WL_SourceScreen(NULL, 0) == NULL &&
          DirectGate_WL_SourcePortal(NULL) == NULL && !DirectGate_WL_SourceIsDmaBuf(NULL, NULL, NULL), "no screens");
    CHECK(DirectGate_WL_SourceSelect(NULL, 1) == XSTDERR && DirectGate_WL_SourceWaitFrame(NULL, 1) == XSTDERR,
        "nothing to select or wait for");

    uint8_t *pDst = NULL;
    directgate_desktop_dmabuf_t frame;
    void *pHandle = NULL;
    CHECK(DirectGate_WL_SourceTakeFrame(NULL, &pDst, 0, 1, 1) == XSTDERR &&
          DirectGate_WL_SourceTakeDmaBuf(NULL, &frame, &pHandle) == XSTDERR, "nothing to take");

    /* A source still being set up has no picture, and a frame cannot be taken into nothing */
    stub_portal_reset();
    fake_pw_reset();
    stub.answers[0] = STUB_HOLD_REFUSE;
    directgate_wl_source_t *pSource = DirectGate_WL_SourceCreate(NULL, XFALSE);
    CHECK(pSource != NULL, "create a source that waits");
    uint8_t byte = 0, *pByte = &byte;
    CHECK(DirectGate_WL_SourceTakeFrame(pSource, &pDst, 1, 1, 1) == XSTDERR &&
          DirectGate_WL_SourceTakeFrame(pSource, &pByte, 1, 0, 1) == XSTDERR, "a frame needs somewhere to go");
    CHECK(DirectGate_WL_SourceTakeDmaBuf(pSource, NULL, &pHandle) == XSTDERR, "an export needs somewhere too");
    CHECK(!DirectGate_WL_SourceLost(pSource, NULL, 0) && !DirectGate_WL_SourceIsDmaBuf(pSource, NULL, NULL),
        "a pending source has lost nothing and exports nothing");
    CHECK(DirectGate_WL_SourceSelect(pSource, 32) == XSTDERR, "and cannot change screens");
    DirectGate_WL_SourceDisableDmaBuf(pSource);
    DirectGate_WL_SourceDisableDmaBuf(NULL);
    DirectGate_WL_SourceReleaseFrame(NULL, &pHandle);
    DirectGate_WL_SourceDestroy(pSource);
    DirectGate_WL_SourceDestroy(NULL);
    return 0;
}

/* ---------------- both screens delivering at once ---------------- */

typedef struct {
    fake_pw_stream_t *pOld;
    fake_pw_stream_t *pNew;
    buffer_t oldFrame;
    buffer_t newFrame;
    xatomic_t bOldHolds;        /* the old screen's loop is in a callback, holding its lock */
    xatomic_t bNewDelivers;     /* the new screen's loop is about to deliver, holding its own */
} crossing_t;

static crossing_t g_crossing;

static void old_delivers(void *pArg)
{
    crossing_t *pCross = (crossing_t*)pArg;
    XSYNC_ATOMIC_SET(&pCross->bOldHolds, 1);
    for (int i = 0; i < 2000 && !XSYNC_ATOMIC_GET(&pCross->bNewDelivers); i++) usleep(1000);

    /* Long enough for the new loop to be waiting for this one's lock, if that is where it goes */
    usleep(50000);
    fake_pw_queue(pCross->pOld, &pCross->oldFrame.pw);
    fake_pw_emit_process(pCross->pOld);
}

static void* hold_old_loop(void *pArg)
{
    crossing_t *pCross = (crossing_t*)pArg;
    fake_pw_run(pCross->pOld, old_delivers, pCross);
    return NULL;
}

static void new_delivers(void *pArg)
{
    crossing_t *pCross = (crossing_t*)pArg;
    uint8_t pod[1024];
    fake_pw_emit_param(pCross->pNew, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video,
        SPA_VIDEO_FORMAT_BGRx, 64, 32, MODIFIER_FIXED, MOD_LINEAR));

    XSYNC_ATOMIC_SET(&pCross->bNewDelivers, 1);
    fake_pw_queue(pCross->pNew, &pCross->newFrame.pw);
    fake_pw_emit_process(pCross->pNew);
}

static void* serve_new_loop(void *pArg)
{
    crossing_t *pCross = (crossing_t*)pArg;
    pCross->pNew = wait_node(32);
    if (pCross->pNew != NULL) fake_pw_run(pCross->pNew, new_delivers, pCross);
    return NULL;
}

/* While a switch waits for the new screen's format, the old screen still streams, and each loop delivers holding
   its own lock. A loop handing the other stream's export back would take that stream's lock: two of them doing it
   at once wait for each other for good, and the switch waiting for the old loop to stop waits with them. */
static int check_crossing(void)
{
    fake_pw_stream_t *pOld = NULL;
    directgate_wl_source_t *pSource = ready_source(XTRUE, &pOld);
    CHECK(pSource != NULL && pOld != NULL, "a ready exporting source on screen 31");

    static buffer_t waiting;
    buffer_exported(&waiting, 101, 0, 0, 0);
    emit_buffer(pOld, &waiting);

    crossing_t *pCross = &g_crossing;
    pCross->pOld = pOld;
    buffer_exported(&pCross->oldFrame, 102, 0, 0, 0);
    buffer_exported(&pCross->newFrame, 103, 0, 0, 0);

    pthread_t oldThread, newThread;
    CHECK(pthread_create(&oldThread, NULL, hold_old_loop, pCross) == 0, "start the old screen's delivery");
    for (int i = 0; i < 2000 && !XSYNC_ATOMIC_GET(&pCross->bOldHolds); i++) usleep(1000);
    CHECK(pthread_create(&newThread, NULL, serve_new_loop, pCross) == 0, "and the new screen's");

    CHECK(DirectGate_WL_SourceSelect(pSource, 32) == XSTDOK, "the switch goes through");
    pthread_join(oldThread, NULL);
    pthread_join(newThread, NULL);

    CHECK(fake_pw_returned(pOld, &waiting.pw) == 1 && fake_pw_returned(pOld, &pCross->oldFrame.pw) == 1,
        "every export of the old screen went back to it");
    CHECK(fake_pw_returned(pCross->pNew, &pCross->newFrame.pw) == 1, "and the new screen's to the new one");

    DirectGate_WL_SourceDestroy(pSource);
    return 0;
}

int main(void)
{
    CHECK(mkdtemp(g_sRoot) != NULL, "make a scratch directory");
    snprintf(g_sToken, sizeof(g_sToken), "%s/token", g_sRoot);

    /* First, before this process has any thread to copy into a child: a deadlock can only be seen from outside */
    fflush(NULL);
    pid_t nChild = fork();
    CHECK(nChild >= 0, "fork the crossing check");
    if (nChild == 0) exit(check_crossing());

    int nStatus = -1;
    for (int i = 0; i < 1000 && waitpid(nChild, &nStatus, WNOHANG) == 0; i++) usleep(10000);
    if (waitpid(nChild, NULL, WNOHANG) == 0)
    {
        kill(nChild, SIGKILL);
        waitpid(nChild, NULL, 0);
        nStatus = -1;
    }

    CHECK(nStatus == 0, "two screens delivering at once during a switch do not deadlock it");

    int nFailed = check_fresh_grant() || check_remembered() || check_unwritable() || check_setup_failures() ||
        check_mapped_frames() || check_exported_frames() || check_select() || check_guards();

    unlink(g_sToken);
    char sDeep[300];
    snprintf(sDeep, sizeof(sDeep), "%s/never/made/token", g_sRoot);
    unlink(sDeep);
    snprintf(sDeep, sizeof(sDeep), "%s/never/made", g_sRoot);
    rmdir(sDeep);
    snprintf(sDeep, sizeof(sDeep), "%s/never", g_sRoot);
    rmdir(sDeep);
    rmdir(g_sRoot);

    if (nFailed) return 1;
    puts("wayland_source_smoke: OK");
    return 0;
}
