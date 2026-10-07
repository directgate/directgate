/* The Wayland PipeWire capture against fake_pipewire.h: every way starting it can fail, the format it offers and
 * what it settles on, each check a buffer from the compositor has to pass before a byte of it is read, the
 * export path and every way back from it to mapped memory, a stream the compositor takes away, and a stop that
 * leaves nothing behind. */

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "src/agent/desktop/wayland.h"
#include "wayland_stream_fixture.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "wayland_capture_smoke: %s (line %d)\n", msg, __LINE__); \
            return 1; \
        } \
    } while (0)

/* ---------------- what the agent was handed ---------------- */

typedef struct {
    int nFrames;
    directgate_wl_frame_t last;
    uint8_t nFirstByte;
    int bDropOnArrival;     /* give an exported frame straight back from the callback */
} frames_t;

static void on_frame(void *pCtx, const directgate_wl_frame_t *pFrame)
{
    frames_t *pFrames = (frames_t*)pCtx;
    pFrames->nFrames++;
    pFrames->last = *pFrame;
    if (pFrame->eKind == DIRECTGATE_WL_FRAME_MAPPED) pFrames->nFirstByte = pFrame->pPixels[0];
    if (pFrames->bDropOnArrival && pFrame->pHandle != NULL) DirectGate_WL_CaptureDrop(pFrame->pCapture, pFrame->pHandle);
}

/* The modifiers a param offers: -1 for none, else how many values its choice holds */
static int offered_modifiers(const uint8_t *pParam, uint32_t *pFlags)
{
    const struct spa_pod_prop *pProp = spa_pod_find_prop((const struct spa_pod*)pParam, NULL, SPA_FORMAT_VIDEO_modifier);
    if (pProp == NULL) return -1;
    if (pFlags != NULL) *pFlags = pProp->flags;

    uint32_t nValues = 0, nChoice = 0;
    spa_pod_get_values(&pProp->value, &nValues, &nChoice);
    return (int)nValues;
}

/* The memory types a Buffers param allows */
static int buffer_types(const uint8_t *pParam)
{
    const struct spa_pod_prop *pProp = spa_pod_find_prop((const struct spa_pod*)pParam, NULL, SPA_PARAM_BUFFERS_dataType);
    if (pProp == NULL) return -1;

    const struct spa_pod *pValue = &pProp->value;
    if (SPA_POD_TYPE(pValue) == SPA_TYPE_Choice) pValue = SPA_POD_CHOICE_CHILD(pValue);

    int32_t nTypes = 0;
    return spa_pod_get_int(pValue, &nTypes) < 0 ? -1 : nTypes;
}

static int fd_closed(int nFd)
{
    return fcntl(nFd, F_GETFD) < 0 && errno == EBADF;
}

static directgate_wl_capture_t* start(uint32_t nNode, frames_t *pFrames, xbool_t bDmaBuf, fake_pw_stream_t **ppStream)
{
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return NULL;
    close(pair[1]);

    char sError[256] = { 0 };
    directgate_wl_capture_t *pCap = DirectGate_WL_CaptureStart(pair[0], nNode, on_frame, pFrames, bDmaBuf,
        sError, sizeof(sError));

    *ppStream = pCap != NULL ? fake_pw_stream_for_node(nNode) : NULL;
    return pCap;
}

/* ---------------- scenarios ---------------- */

static int check_start_failures(void)
{
    const char *pSteps[] = { "pw_thread_loop_new", "pw_thread_loop_start", "pw_context_new",
                             "pw_context_connect_fd", "pw_stream_new", "pw_stream_connect" };

    for (size_t i = 0; i < sizeof(pSteps) / sizeof(pSteps[0]); i++)
    {
        int pair[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "make a portal descriptor");
        close(pair[1]);

        char sError[256] = { 0 };
        fake_pw_fail_next(pSteps[i]);
        CHECK(DirectGate_WL_CaptureStart(pair[0], 7, on_frame, NULL, XFALSE, sError, sizeof(sError)) == NULL,
            "a failing step fails the start");
        CHECK(sError[0] != '\0', "and says why");
        CHECK(fd_closed(pair[0]), "the portal descriptor is closed exactly once on every failure");
        CHECK(fake_pw_live() == 0 && fake_pw_open_fds() == 0, "nothing of a failed start is left");

        /* Without a descriptor or a place for the reason, the same */
        fake_pw_fail_next(pSteps[i]);
        CHECK(DirectGate_WL_CaptureStart(-1, 7, on_frame, NULL, XFALSE, NULL, 0) == NULL, "a failing step fails it");
        CHECK(fake_pw_live() == 0, "and leaves nothing");
    }

    return 0;
}

static int check_memory_path(void)
{
    frames_t frames = { 0 };
    fake_pw_stream_t *pStream = NULL;
    directgate_wl_capture_t *pCap = start(42, &frames, XFALSE, &pStream);
    CHECK(pCap != NULL && pStream != NULL, "start a mapped-memory capture");

    CHECK(pStream->nConnectParams == 2, "two memory formats are offered");
    CHECK(offered_modifiers(pStream->connectParams[0], NULL) < 0 && offered_modifiers(pStream->connectParams[1], NULL) < 0,
        "without any buffer layout");
    CHECK((pStream->nFlags & PW_STREAM_FLAG_AUTOCONNECT) && (pStream->nFlags & PW_STREAM_FLAG_MAP_BUFFERS),
        "the stream maps what it receives");

    uint32_t nWidth = 0, nHeight = 0;
    char sError[256] = { 0 };
    CHECK(!DirectGate_WL_CaptureSize(pCap, &nWidth, &nHeight) && !DirectGate_WL_CaptureIsDmaBuf(pCap, NULL, NULL),
        "nothing is known before a format");
    CHECK(!DirectGate_WL_CaptureLost(pCap, sError, sizeof(sError)), "nor is anything lost");

    /* Not a format, not video, not parseable: none of it is taken for one */
    uint8_t pod[1024];
    buffer_t early;
    buffer_mapped(&early, 0, 0, 64 * 32 * 4, sizeof(early.pixels));
    emit_buffer(pStream, &early);
    CHECK(frames.nFrames == 0 && fake_pw_returned(pStream, &early.pw) == 1, "a buffer before a format is given back");

    emit_param(pStream, SPA_PARAM_Format, NULL);
    emit_param(pStream, SPA_PARAM_Buffers, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video,
        SPA_VIDEO_FORMAT_BGRx, 64, 32, MODIFIER_NONE, 0));
    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_audio,
        SPA_VIDEO_FORMAT_BGRx, 64, 32, MODIFIER_NONE, 0));

    struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(pod, sizeof(pod));
    spa_pod_builder_int(&builder, 5);
    emit_param(pStream, SPA_PARAM_Format, (const struct spa_pod*)pod);

    struct spa_pod_frame frame;
    builder = SPA_POD_BUILDER_INIT(pod, sizeof(pod));
    spa_pod_builder_push_object(&builder, &frame, SPA_TYPE_OBJECT_Format, SPA_PARAM_Format);
    spa_pod_builder_add(&builder, SPA_FORMAT_mediaType, SPA_POD_Id(SPA_MEDIA_TYPE_video),
        SPA_FORMAT_mediaSubtype, SPA_POD_Id(SPA_MEDIA_SUBTYPE_h264), 0);
    emit_param(pStream, SPA_PARAM_Format, (const struct spa_pod*)spa_pod_builder_pop(&builder, &frame));
    CHECK(pStream->nUpdates == 0 && !DirectGate_WL_CaptureSize(pCap, NULL, NULL), "none of those is a format");

    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video,
        SPA_VIDEO_FORMAT_BGRx, 64, 32, MODIFIER_NONE, 0));
    CHECK(pStream->nUpdates == 1 && pStream->nUpdateParams == 1, "a format is answered with the buffers it needs");
    CHECK(buffer_types(pStream->updateParams[0]) == ((1 << SPA_DATA_MemFd) | (1 << SPA_DATA_MemPtr)),
        "which is memory that can be mapped, never an export");
    CHECK(DirectGate_WL_CaptureWaitFormat(pCap, 1000) == XSTDOK, "the format is there");
    CHECK(DirectGate_WL_CaptureSize(pCap, &nWidth, &nHeight) && nWidth == 64 && nHeight == 32, "at its size");
    CHECK(DirectGate_WL_CaptureSize(pCap, NULL, NULL) && !DirectGate_WL_CaptureIsDmaBuf(pCap, NULL, NULL), "in memory");

    /* Every buffer that cannot be read goes back untouched */
    event_t idle = { .pStream = pStream };
    fake_pw_run(pStream, run_process, &idle);
    CHECK(frames.nFrames == 0, "a wake-up with no buffer is nothing");

    buffer_t bad;
    buffer_mapped(&bad, 0, 0, 64 * 32 * 4, sizeof(bad.pixels));
    bad.pw.buffer = NULL;
    emit_buffer(pStream, &bad);
    buffer_mapped(&bad, 0, 0, 64 * 32 * 4, sizeof(bad.pixels));
    bad.spa.n_datas = 0;
    emit_buffer(pStream, &bad);
    CHECK(frames.nFrames == 0 && fake_pw_returned(pStream, &bad.pw) == 2, "a buffer with no data");

    for (int i = 0; i < 2; i++)
    {
        buffer_mapped(&bad, 0, 0, 64 * 32 * 4, sizeof(bad.pixels));
        bad.data[0].data = NULL;
        emit_buffer(pStream, &bad);
    }
    CHECK(frames.nFrames == 0 && fake_pw_returned(pStream, &bad.pw) == 4, "a buffer that is not mapped");

    for (int i = 0; i < 62; i++)
    {
        buffer_mapped(&bad, 0, 0, 0, sizeof(bad.pixels));
        emit_buffer(pStream, &bad);
    }
    CHECK(frames.nFrames == 0 && fake_pw_returned(pStream, &bad.pw) == 66, "buffers that report nothing written");

    buffer_mapped(&bad, 0, 64 * 4 - 4, 64 * 32 * 4, sizeof(bad.pixels));
    emit_buffer(pStream, &bad);
    CHECK(frames.nFrames == 0, "rows shorter than the picture is wide");

    for (int i = 0; i < 2; i++)
    {
        buffer_mapped(&bad, 16, 64 * 4, 64 * 32 * 4, 64 * 32 * 4);
        emit_buffer(pStream, &bad);
    }
    CHECK(frames.nFrames == 0 && fake_pw_returned(pStream, &bad.pw) == 69, "a picture that runs past its mapping");

    /* What can be read is handed over where it starts, at the stride it has, and given back after */
    buffer_t good;
    buffer_mapped(&good, 64, 64 * 4 + 32, 64 * 32 * 4, sizeof(good.pixels));
    emit_buffer(pStream, &good);
    CHECK(frames.nFrames == 1 && frames.last.eKind == DIRECTGATE_WL_FRAME_MAPPED, "a readable buffer is a frame");
    CHECK(frames.last.nWidth == 64 && frames.last.nHeight == 32 && frames.last.nStride == 64 * 4 + 32,
        "at the stride the compositor gave");
    CHECK(frames.nFirstByte == 0x5a && frames.last.pCapture == pCap, "from where its picture starts");
    CHECK(fake_pw_returned(pStream, &good.pw) == 1, "and goes back once it was read");

    buffer_mapped(&good, 0, 0, 64 * 32 * 4, sizeof(good.pixels));
    good.data[0].chunk = NULL;
    emit_buffer(pStream, &good);
    CHECK(frames.nFrames == 2 && frames.last.nStride == 64 * 4, "no chunk is a packed picture");

    /* Two waiting: the newer one is the frame, the older goes back unread */
    buffer_t older, newer;
    buffer_mapped(&older, 0, 0, 64 * 32 * 4, sizeof(older.pixels));
    buffer_mapped(&newer, 0, 0, 64 * 32 * 4, sizeof(newer.pixels));
    older.pixels[0] = 1;
    newer.pixels[0] = 2;
    event_t both = { .pStream = pStream, .nBuffers = 2 };
    both.pBuffers[0] = &older;
    both.pBuffers[1] = &newer;
    fake_pw_run(pStream, run_process, &both);
    CHECK(frames.nFrames == 3 && frames.nFirstByte == 2, "the newest buffer is the frame");
    CHECK(fake_pw_returned(pStream, &older.pw) == 1 && fake_pw_returned(pStream, &newer.pw) == 1, "both go back");

    /* Empty buffers once pictures have come are just the screen standing still */
    buffer_t still;
    for (int i = 0; i < 62; i++)
    {
        buffer_mapped(&still, 0, 0, 0, sizeof(still.pixels));
        emit_buffer(pStream, &still);
    }
    CHECK(frames.nFrames == 3 && fake_pw_returned(pStream, &still.pw) == 62, "a still screen sends empty buffers");

    DirectGate_WL_CaptureRelease(pCap, NULL);
    DirectGate_WL_CaptureDrop(pCap, NULL);
    CHECK(fake_pw_returned(pStream, NULL) == 0, "no buffer is no buffer to give back");

    emit_state(pStream, PW_STREAM_STATE_STREAMING, NULL);
    CHECK(!DirectGate_WL_CaptureLost(pCap, NULL, 0), "streaming is not a loss");

    /* The compositor taking the screen back is the end of the stream, with a reason the viewer can read */
    emit_state(pStream, PW_STREAM_STATE_UNCONNECTED, NULL);
    CHECK(DirectGate_WL_CaptureLost(pCap, sError, sizeof(sError)) && strstr(sError, "stopped") != NULL,
        "a stream taken away after it had a format is lost");
    CHECK(DirectGate_WL_CaptureLost(pCap, NULL, 0) && DirectGate_WL_CaptureLost(pCap, sError, 0), "and stays lost");
    emit_state(pStream, PW_STREAM_STATE_UNCONNECTED, NULL);

    DirectGate_WL_CaptureStop(pCap);
    CHECK(pStream->nDisconnects == 1 && pStream->bDestroyed, "the stream is disconnected and destroyed");
    CHECK(fake_pw_live() == 0 && fake_pw_open_fds() == 0, "and nothing is left of it");
    return 0;
}

typedef struct {
    fake_pw_stream_t *pStream;
    const struct spa_pod *pFormat;
    int nAfterUpdates;      /* wait for this many param updates first */
} late_t;

static void* send_late(void *pArg)
{
    late_t *pLate = (late_t*)pArg;
    for (int i = 0; i < 400 && fake_pw_updates(pLate->pStream) < pLate->nAfterUpdates; i++) usleep(10000);
    usleep(50000);
    emit_param(pLate->pStream, SPA_PARAM_Format, pLate->pFormat);
    return NULL;
}

static int check_waits(void)
{
    uint8_t pod[1024];

    /* A format that comes while the caller waits for it ends the wait */
    frames_t frames = { 0 };
    fake_pw_stream_t *pStream = NULL;
    directgate_wl_capture_t *pCap = start(43, &frames, XFALSE, &pStream);
    CHECK(pCap != NULL, "start a capture");

    late_t late = { pStream, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRA, 32, 16,
        MODIFIER_NONE, 0), 0 };
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, send_late, &late) == 0, "send the format later");
    CHECK(DirectGate_WL_CaptureWaitFormat(pCap, 3000) == XSTDOK, "the wait ends with the format");
    pthread_join(thread, NULL);
    DirectGate_WL_CaptureStop(pCap);

    /* A stream that fails while the caller waits ends the wait too, and says why */
    pCap = start(44, &frames, XFALSE, &pStream);
    CHECK(pCap != NULL, "start another");
    emit_state(pStream, PW_STREAM_STATE_ERROR, "no more screen");
    CHECK(DirectGate_WL_CaptureWaitFormat(pCap, 3000) == XSTDERR, "a failed stream has no format to wait for");

    char sError[256] = { 0 };
    CHECK(DirectGate_WL_CaptureLost(pCap, sError, sizeof(sError)) && strcmp(sError, "no more screen") == 0,
        "and is lost for the reason PipeWire gave");
    DirectGate_WL_CaptureStop(pCap);

    pCap = start(45, &frames, XFALSE, &pStream);
    CHECK(pCap != NULL, "start one more");
    emit_state(pStream, PW_STREAM_STATE_UNCONNECTED, NULL);
    CHECK(!DirectGate_WL_CaptureLost(pCap, NULL, 0), "going unconnected before a format is not a loss");
    emit_state(pStream, PW_STREAM_STATE_ERROR, NULL);
    CHECK(DirectGate_WL_CaptureLost(pCap, sError, sizeof(sError)) && sError[0] != '\0', "an error with no reason still has one");
    DirectGate_WL_CaptureStop(pCap);

    /* Silence on a memory-only offer is just a timeout */
    pCap = start(46, &frames, XFALSE, &pStream);
    CHECK(pCap != NULL, "start a silent one");
    CHECK(DirectGate_WL_CaptureWaitFormat(pCap, 1) == XSTDERR && pStream->nUpdates == 0,
        "a format that never comes is a timeout, and nothing is renegotiated");
    DirectGate_WL_CaptureStop(pCap);

    /* Silence on an export offer withdraws it once, and an answer to the memory offer is taken */
    pCap = start(47, &frames, XTRUE, &pStream);
    CHECK(pCap != NULL, "start an exporting one");
    late_t answer = { pStream, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRx, 32, 16,
        MODIFIER_NONE, 0), 1 };
    CHECK(pthread_create(&thread, NULL, send_late, &answer) == 0, "answer only the memory offer");
    CHECK(DirectGate_WL_CaptureWaitFormat(pCap, 1) == XSTDOK, "the memory offer is answered");
    pthread_join(thread, NULL);
    CHECK(pStream->nUpdates == 2 && pStream->nUpdateParams == 1, "after one withdrawal of the export offer");
    CHECK(!DirectGate_WL_CaptureIsDmaBuf(pCap, NULL, NULL), "and the frames come in memory");
    DirectGate_WL_CaptureStop(pCap);

    pCap = start(48, &frames, XTRUE, &pStream);
    CHECK(pCap != NULL, "start an exporting one nobody answers");
    CHECK(DirectGate_WL_CaptureWaitFormat(pCap, 1) == XSTDERR && pStream->nUpdates == 1,
        "the export offer is withdrawn once, then the wait gives up");
    DirectGate_WL_CaptureStop(pCap);

    /* An offer the encoder already withdrew is not withdrawn again by the wait */
    pCap = start(49, &frames, XTRUE, &pStream);
    CHECK(pCap != NULL, "start an exporting one the encoder refuses");
    DirectGate_WL_CaptureDisableDmaBuf(pCap);
    CHECK(DirectGate_WL_CaptureWaitFormat(pCap, 1) == XSTDERR && pStream->nUpdates == 1, "a withdrawn offer is only waited for");
    DirectGate_WL_CaptureStop(pCap);
    return 0;
}

static int check_export_path(void)
{
    uint8_t pod[1024];
    frames_t frames = { 0 };
    fake_pw_stream_t *pStream = NULL;
    directgate_wl_capture_t *pCap = start(50, &frames, XTRUE, &pStream);
    CHECK(pCap != NULL, "start an exporting capture");

    /* Exported entries first, each with every layout, then the memory ones */
    uint32_t nFlags = 0;
    CHECK(pStream->nConnectParams == 4, "four formats are offered");
    CHECK(offered_modifiers(pStream->connectParams[0], &nFlags) == 3 &&
          (nFlags & SPA_POD_PROP_FLAG_MANDATORY) && (nFlags & SPA_POD_PROP_FLAG_DONT_FIXATE),
        "the first with both layouts, left for the compositor to choose from");
    CHECK(offered_modifiers(pStream->connectParams[1], NULL) == 3, "the second too");
    CHECK(offered_modifiers(pStream->connectParams[2], NULL) < 0 && offered_modifiers(pStream->connectParams[3], NULL) < 0,
        "and memory last");

    /* The compositor narrows it down and asks; the answer is the one it would rather have */
    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRx,
        64, 32, MODIFIER_CHOICE, MOD_LINEAR));
    CHECK(pStream->nUpdates == 1 && pStream->nUpdateParams == 4, "the choice is answered");
    CHECK(offered_modifiers(pStream->updateParams[0], &nFlags) == 2 && !(nFlags & SPA_POD_PROP_FLAG_DONT_FIXATE),
        "with that one layout, fixed");
    CHECK(!DirectGate_WL_CaptureSize(pCap, NULL, NULL), "a question is not yet a format");

    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRx,
        64, 32, MODIFIER_FIXED, MOD_LINEAR));
    CHECK(pStream->nUpdates == 2 && buffer_types(pStream->updateParams[0]) == (1 << SPA_DATA_DmaBuf),
        "the export is asked to come as DMA-BUFs");

    uint32_t nFourCC = 0;
    uint64_t nModifier = 99;
    CHECK(DirectGate_WL_CaptureIsDmaBuf(pCap, &nFourCC, &nModifier) && nFourCC == DRM_XRGB8888 && nModifier == MOD_LINEAR,
        "the stream exports XRGB8888 in the linear layout");
    CHECK(DirectGate_WL_CaptureIsDmaBuf(pCap, NULL, NULL), "whoever asks");

    /* An export is described, kept by whoever took it, and given back by them */
    buffer_t exported;
    buffer_exported(&exported, 77, 128, 0, 0);
    emit_buffer(pStream, &exported);
    CHECK(frames.nFrames == 1 && frames.last.eKind == DIRECTGATE_WL_FRAME_EXPORTED, "an export is a frame");
    CHECK(frames.last.dmabuf.nFds[0] == 77 && frames.last.dmabuf.nOffsets[0] == 128 &&
          frames.last.dmabuf.nStrides[0] == 64 * 4 && frames.last.dmabuf.nSize == 128 + 64 * 4 * 32,
        "described from what the compositor said, with a size even when it gave none");
    CHECK(frames.last.dmabuf.nFourCC == DRM_XRGB8888 && frames.last.pHandle == &exported.pw, "and its buffer");
    CHECK(fake_pw_returned(pStream, &exported.pw) == 0, "which stays out until it is given back");
    DirectGate_WL_CaptureRelease(pCap, frames.last.pHandle);
    CHECK(fake_pw_returned(pStream, &exported.pw) == 1, "given back from another thread");

    /* Halted, the stream delivers nothing more, but what is out can still go back to it */
    buffer_t held;
    buffer_exported(&held, 86, 0, 0, 0);
    emit_buffer(pStream, &held);
    DirectGate_WL_CaptureHalt(pCap);
    DirectGate_WL_CaptureHalt(pCap);
    DirectGate_WL_CaptureRelease(pCap, frames.last.pHandle);
    CHECK(frames.last.pHandle == &held.pw && fake_pw_returned(pStream, &held.pw) == 1,
        "an export can be given back to a halted stream");
    CHECK(!pStream->bDestroyed, "which is still there until it is stopped");

    buffer_t packed;
    buffer_exported(&packed, 78, 0, 64 * 4, 64 * 4 * 32);
    packed.data[0].chunk = NULL;
    frames.bDropOnArrival = 1;
    emit_buffer(pStream, &packed);
    CHECK(frames.nFrames == 3 && frames.last.dmabuf.nSize == 64 * 4 * 32, "an export without a chunk is packed");
    CHECK(fake_pw_returned(pStream, &packed.pw) == 1, "and dropped from its own thread");
    frames.bDropOnArrival = 0;

    /* One that cannot be described is refused as a whole: the export offer is withdrawn for good */
    buffer_t shorter;
    buffer_exported(&shorter, 79, 0, 64 * 4 - 4, 0);
    emit_buffer(pStream, &shorter);
    CHECK(frames.nFrames == 3 && fake_pw_returned(pStream, &shorter.pw) == 1, "a short export goes back unused");
    CHECK(pStream->nUpdates == 3 && pStream->nUpdateParams == 2, "and only memory is offered from then on");
    CHECK(offered_modifiers(pStream->updateParams[0], NULL) < 0, "without any layout");
    CHECK(!DirectGate_WL_CaptureIsDmaBuf(pCap, NULL, NULL), "the stream no longer exports");

    DirectGate_WL_CaptureDisableDmaBuf(pCap);
    CHECK(pStream->nUpdates == 3, "withdrawing again changes nothing");
    DirectGate_WL_CaptureStop(pCap);
    CHECK(fake_pw_live() == 0, "nothing is left");
    return 0;
}

static int check_export_refusals(void)
{
    uint8_t pod[1024];
    frames_t frames = { 0 };
    fake_pw_stream_t *pStream = NULL;

    /* A layout that was never offered */
    directgate_wl_capture_t *pCap = start(60, &frames, XTRUE, &pStream);
    CHECK(pCap != NULL, "start an exporting capture");
    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRx,
        64, 32, MODIFIER_FIXED, 0x1234));
    CHECK(pStream->nUpdates == 1 && pStream->nUpdateParams == 2 && !DirectGate_WL_CaptureSize(pCap, NULL, NULL),
        "a layout that was not offered withdraws the export");
    DirectGate_WL_CaptureStop(pCap);

    /* A format the encoder cannot be told about */
    pCap = start(61, &frames, XTRUE, &pStream);
    CHECK(pCap != NULL, "start another");
    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_RGBx,
        64, 32, MODIFIER_FIXED, MOD_INVALID));
    CHECK(pStream->nUpdates == 1 && pStream->nUpdateParams == 2, "an export in an unknown format is withdrawn");
    DirectGate_WL_CaptureStop(pCap);

    /* ARGB, then exports the compositor describes wrongly */
    pCap = start(62, &frames, XTRUE, &pStream);
    CHECK(pCap != NULL, "start a third");
    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRA,
        64, 32, MODIFIER_FIXED, MOD_INVALID));
    uint32_t nFourCC = 0;
    CHECK(DirectGate_WL_CaptureIsDmaBuf(pCap, &nFourCC, NULL) && nFourCC == DRM_ARGB8888, "BGRA exports as ARGB8888");

    buffer_t exported;
    buffer_exported(&exported, 80, 0, 0, 0);
    exported.spa.n_datas = 2;
    emit_buffer(pStream, &exported);
    CHECK(frames.nFrames == 0 && fake_pw_returned(pStream, &exported.pw) == 1, "an export in two planes is refused");
    CHECK(!DirectGate_WL_CaptureIsDmaBuf(pCap, NULL, NULL), "and the stream goes back to memory");
    DirectGate_WL_CaptureStop(pCap);

    pCap = start(63, &frames, XTRUE, &pStream);
    CHECK(pCap != NULL, "start a fourth");
    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRx,
        64, 32, MODIFIER_FIXED, MOD_LINEAR));
    buffer_exported(&exported, -1, 0, 0, 0);
    emit_buffer(pStream, &exported);
    buffer_exported(&exported, 81, 0, 0, 0);
    exported.spa.n_datas = 0;
    emit_buffer(pStream, &exported);
    CHECK(frames.nFrames == 0 && fake_pw_returned(pStream, &exported.pw) == 2, "nor without a descriptor or data");
    DirectGate_WL_CaptureStop(pCap);

    pCap = start(67, &frames, XTRUE, &pStream);
    CHECK(pCap != NULL, "start one more");
    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRx,
        64, 32, MODIFIER_FIXED, MOD_LINEAR));
    buffer_exported(&exported, 84, 0, 0, 0);
    exported.pw.buffer = NULL;
    emit_buffer(pStream, &exported);
    CHECK(frames.nFrames == 0 && fake_pw_returned(pStream, &exported.pw) == 1, "nor an export with no buffer behind it");
    DirectGate_WL_CaptureStop(pCap);

    /* A layout spelled as something other than a 64-bit value is no layout: the frames come in memory */
    pCap = start(68, &frames, XTRUE, &pStream);
    CHECK(pCap != NULL, "start yet another");
    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRx,
        64, 32, MODIFIER_INT, 0));
    CHECK(pStream->nUpdates == 1 && buffer_types(pStream->updateParams[0]) == ((1 << SPA_DATA_MemFd) | (1 << SPA_DATA_MemPtr)),
        "a layout that cannot be read is memory");
    CHECK(DirectGate_WL_CaptureSize(pCap, NULL, NULL) && !DirectGate_WL_CaptureIsDmaBuf(pCap, NULL, NULL), "not export");

    /* A picture with no height is no frame either way */
    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRx,
        64, 0, MODIFIER_NONE, 0));
    buffer_t flat;
    buffer_mapped(&flat, 0, 0, 16, sizeof(flat.pixels));
    emit_buffer(pStream, &flat);
    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRx,
        64, 0, MODIFIER_FIXED, MOD_LINEAR));
    buffer_exported(&exported, 85, 0, 0, 0);
    emit_buffer(pStream, &exported);
    CHECK(frames.nFrames == 0, "a picture without height is no frame");
    DirectGate_WL_CaptureStop(pCap);

    pCap = start(64, &frames, XTRUE, &pStream);
    CHECK(pCap != NULL, "start a fifth");
    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRx,
        64, 32, MODIFIER_FIXED, MOD_LINEAR));
    buffer_exported(&exported, 82, 0, 0, 0);
    exported.data[0].type = SPA_DATA_MemFd;
    emit_buffer(pStream, &exported);
    CHECK(frames.nFrames == 0, "nor in memory it claims to be an export");

    /* The encoder can refuse the export too, and the stream goes back to memory for it */
    DirectGate_WL_CaptureStop(pCap);
    pCap = start(65, &frames, XTRUE, &pStream);
    CHECK(pCap != NULL, "start a sixth");
    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRx,
        64, 32, MODIFIER_FIXED, MOD_LINEAR));
    DirectGate_WL_CaptureDisableDmaBuf(pCap);
    CHECK(pStream->nUpdates == 2 && pStream->nUpdateParams == 2, "an encoder that cannot take it withdraws it");

    /* A zero-sized format is a format, but no frame */
    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRx,
        0, 0, MODIFIER_FIXED, MOD_LINEAR));
    buffer_exported(&exported, 83, 0, 0, 0);
    emit_buffer(pStream, &exported);
    CHECK(frames.nFrames == 0, "a zero-sized export is no frame");
    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRx,
        0, 0, MODIFIER_NONE, 0));
    buffer_t mapped;
    buffer_mapped(&mapped, 0, 0, 16, sizeof(mapped.pixels));
    emit_buffer(pStream, &mapped);
    CHECK(frames.nFrames == 0, "and neither is a zero-sized picture");
    DirectGate_WL_CaptureStop(pCap);

    /* Frames with nowhere to go are given back */
    pCap = DirectGate_WL_CaptureStart(-1, 66, NULL, NULL, XFALSE, NULL, 0);
    CHECK(pCap != NULL && (pStream = fake_pw_stream_for_node(66)) != NULL, "start one nobody listens to");
    emit_param(pStream, SPA_PARAM_Format, make_format(pod, sizeof(pod), SPA_MEDIA_TYPE_video, SPA_VIDEO_FORMAT_BGRx,
        64, 32, MODIFIER_NONE, 0));
    buffer_mapped(&mapped, 0, 0, 64 * 32 * 4, sizeof(mapped.pixels));
    emit_buffer(pStream, &mapped);
    CHECK(fake_pw_returned(pStream, &mapped.pw) == 1, "a frame nobody wants goes back");
    DirectGate_WL_CaptureStop(pCap);

    CHECK(fake_pw_live() == 0 && fake_pw_open_fds() == 0, "nothing is left of any of them");
    return 0;
}

static int check_guards(void)
{
    CHECK(DirectGate_WL_CaptureWaitFormat(NULL, 1) == XSTDERR, "no capture has no format");
    CHECK(!DirectGate_WL_CaptureLost(NULL, NULL, 0) && !DirectGate_WL_CaptureSize(NULL, NULL, NULL) &&
          !DirectGate_WL_CaptureIsDmaBuf(NULL, NULL, NULL), "no capture is neither lost, sized nor exporting");

    int nHandle = 0;
    DirectGate_WL_CaptureRelease(NULL, &nHandle);
    DirectGate_WL_CaptureDrop(NULL, &nHandle);
    DirectGate_WL_CaptureDisableDmaBuf(NULL);
    DirectGate_WL_CaptureHalt(NULL);
    DirectGate_WL_CaptureStop(NULL);
    return 0;
}

int main(void)
{
    char sError[256] = { 0 };
    CHECK(DirectGate_WL_PipeWireLoad(sError, sizeof(sError)) == XSTDOK && fake_pw_inits() == 1, "load PipeWire");
    CHECK(DirectGate_WL_PipeWireLoad(sError, sizeof(sError)) == XSTDOK && fake_pw_inits() == 1, "once");

    if (check_start_failures()) return 1;
    if (check_memory_path()) return 1;
    if (check_waits()) return 1;
    if (check_export_path()) return 1;
    if (check_export_refusals()) return 1;
    if (check_guards()) return 1;

    puts("wayland_capture_smoke: OK");
    return 0;
}
