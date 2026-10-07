/*
 * The GPU H.264 encoder against fake_libav.h, so every path runs on any machine - a CI runner has no GPU, and
 * hwenc_smoke there only reaches the probes. Loading and the version guard, each encoder candidate and the
 * options it is opened with, the GPU device cache and the render-node fallback, every allocation that can fail,
 * the frame pool and upload, what a packet becomes (parameter sets in front of a keyframe that lacks them), and
 * the bitrate and preset changes a live session makes, both the in-place and the rebuild kind. With libavfilter's
 * headers, the Wayland zero-copy chain too: the GPU conversion graph and each step of it that can fail, what a
 * mapped compositor frame is described as, and the frames that chain has to refuse.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "src/agent/desktop/hwenc.h"
#include "fake_libav.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "hwenc_fake_smoke: %s (line %d)\n", msg, __LINE__); \
            return 1; \
        } \
    } while (0)

#define W 64
#define H 32

static uint8_t g_nv12[W * H * 3 / 2];
static xbyte_buffer_t g_out;

static void quality(directgate_desktop_quality_t *pQuality, uint32_t nFps, uint32_t nKbps, uint32_t nGop)
{
    memset(pQuality, 0, sizeof(*pQuality));
    pQuality->nMaxEdge = W;
    pQuality->nFps = nFps;
    pQuality->nBitrateKbps = nKbps;
    pQuality->nBaseBitrateKbps = nKbps;
    pQuality->nKeyframeFrames = nGop;
    pQuality->bRealtime = XTRUE;
}

static void script(const fake_av_packet_t *pPackets, int nCount)
{
    for (int i = 0; i < nCount; i++) fake_av()->packets[i] = pPackets[i];
    fake_av()->nPackets = nCount;
}

static int encode(directgate_hwenc_t *pEnc, xbool_t bKey, xbool_t *pKeyframe)
{
    return DirectGate_HWEnc_Encode(pEnc, g_nv12, 1000, bKey, &g_out, pKeyframe);
}

static void have(const char *pEncoder)
{
    fake_av_reset();
    fake_av()->pEncoders[0] = pEncoder;
    fake_av()->pDevices[0] = "vaapi:";
    fake_av()->bExtradata = 1;
}

static directgate_hwenc_t* create(char *pErr, size_t nErrSize)
{
    directgate_desktop_quality_t q;
    quality(&q, 30, 3000, 120);
    pErr[0] = '\0';
    return DirectGate_HWEnc_Create(W, H, &q, pErr, nErrSize);
}

/* ---------------- before the library is loaded ---------------- */

static int in_child(int (*fnCheck)(void))
{
    fflush(NULL);
    pid_t nPid = fork();
    /* exit, not _exit: the child's coverage is written by its exit handlers */
    if (nPid == 0) exit(fnCheck());

    int nStatus = 0;
    return nPid > 0 && waitpid(nPid, &nStatus, 0) == nPid && WIFEXITED(nStatus) && WEXITSTATUS(nStatus) == 0;
}

static int load_in_child(unsigned nCodecMajor, unsigned nUtilMajor, const char *pLib, const char *pExpect)
{
    pid_t nPid = fork();
    if (nPid == 0)
    {
        fake_av()->nCodecMajor = nCodecMajor;
        fake_av()->nUtilMajor = nUtilMajor;
        if (pLib != NULL) setenv("DIRECTGATE_HWENC_LIB", pLib, 1);

        char sErr[256] = { 0 };
        int bFailed = DirectGate_HWEnc_Load(sErr, sizeof(sErr)) < 0 && strstr(sErr, pExpect) != NULL;
        bFailed = bFailed && DirectGate_HWEnc_Load(sErr, sizeof(sErr)) < 0 && strstr(sErr, "software") != NULL;
        exit(bFailed ? 0 : 1);
    }

    int nStatus = 0;
    return nPid > 0 && waitpid(nPid, &nStatus, 0) == nPid && WIFEXITED(nStatus) && WEXITSTATUS(nStatus) == 0;
}

static int check_loading(void)
{
    CHECK(load_in_child(1, 0, NULL, "do not match"), "a libavcodec of another major is refused, and stays refused");
    CHECK(load_in_child(0, 1, NULL, "do not match"), "so is a libavutil of another major");
    CHECK(load_in_child(0, 0, "/nonexistent/libavcodec.so", "could not be loaded"), "and one that is not there");

    char sErr[256];
    CHECK(DirectGate_HWEnc_Load(sErr, sizeof(sErr)) == XSTDOK && DirectGate_HWEnc_Load(NULL, 0) == XSTDOK,
        "the libraries load, once");
    CHECK(strstr(DirectGate_HWEnc_Version(), "libavcodec") != NULL, "and report their version");
    return 0;
}

/* ---------------- refusals ---------------- */

static int check_refusals(void)
{
    char sErr[256];
    directgate_desktop_quality_t q;
    quality(&q, 30, 3000, 120);

    have(NULL);
    CHECK(DirectGate_HWEnc_Create(8, 8, &q, sErr, sizeof(sErr)) == NULL &&
          DirectGate_HWEnc_Create(W + 1, H, &q, sErr, sizeof(sErr)) == NULL &&
          DirectGate_HWEnc_Create(W, H, NULL, sErr, sizeof(sErr)) == NULL, "sizes and presets an encoder cannot take");
    CHECK(create(sErr, sizeof(sErr)) == NULL && strstr(sErr, "no GPU") != NULL, "a libavcodec without GPU encoders");

    setenv("DIRECTGATE_HWENC", "0", 1);
    have("h264_nvenc");
    CHECK(create(sErr, sizeof(sErr)) == NULL && strstr(sErr, "disabled") != NULL && fake_av()->nOpens == 0,
        "switched off, nothing is opened");
    unsetenv("DIRECTGATE_HWENC");

    setenv("DIRECTGATE_HWENC_ENCODER", "h264_does_not_exist", 1);
    CHECK(create(sErr, sizeof(sErr)) == NULL && fake_av()->nOpens == 0, "a forced encoder nobody has");
    unsetenv("DIRECTGATE_HWENC_ENCODER");

#ifndef DIRECTGATE_HWENC_HAS_FILTER
    CHECK(!DirectGate_HWEnc_ImportAvailable(sErr, sizeof(sErr)) && sErr[0] != '\0', "no zero-copy in this build");
    CHECK(DirectGate_HWEnc_CreateImport(W, H, 0x34325258U, 0, W, H, &q, sErr, sizeof(sErr)) == NULL &&
          DirectGate_HWEnc_CreateImport(8, 8, 0x34325258U, 0, W, H, &q, sErr, sizeof(sErr)) == NULL &&
          DirectGate_HWEnc_CreateImport(W, H, 0x34325258U, 0, W, H, NULL, sErr, sizeof(sErr)) == NULL &&
          DirectGate_HWEnc_CreateImport(W, H, 0x34325258U, 0, W + 1, H, &q, sErr, sizeof(sErr)) == NULL &&
          DirectGate_HWEnc_CreateImport(W, H, 0x34325258U, 0, 8, 8, &q, sErr, sizeof(sErr)) == NULL,
        "so no importing encoder either");
#endif

    CHECK(DirectGate_HWEnc_Encode(NULL, g_nv12, 0, XFALSE, &g_out, NULL) == XSTDERR &&
          DirectGate_HWEnc_SetBitrate(NULL, 1) == XSTDERR && DirectGate_HWEnc_ApplyQuality(NULL, &q) == XSTDERR,
        "no encoder does nothing");
    CHECK(DirectGate_HWEnc_EncodeImport(NULL, NULL, 0, XFALSE, &g_out, NULL) == XSTDERR, "nor imports");
    CHECK(strcmp(DirectGate_HWEnc_Describe(NULL), "unloaded") == 0, "and describes itself as nothing");
    DirectGate_HWEnc_Destroy(NULL);
    return 0;
}

/* ---------------- NVENC: system memory, changes applied in place ---------------- */

static int check_nvenc(void)
{
    char sErr[256];
    int nLive = fake_av_live();
    have("h264_nvenc");

    directgate_hwenc_t *pEnc = create(sErr, sizeof(sErr));
    CHECK(pEnc != NULL, "NVENC opens");
    CHECK(strstr(DirectGate_HWEnc_Describe(pEnc), "NVIDIA") != NULL, "and describes itself");
    CHECK(fake_av()->nLastBitrate == 3000000 && fake_av()->nOptions >= 7 && fake_av()->nDeviceCreates == 0,
        "at the asked rate, tuned for latency, with no GPU device of its own");

    /* A keyframe without parameter sets gets the cached ones in front; the first frame is always one */
    const fake_av_packet_t first[] = { FAKE_AV_KEY, FAKE_AV_DELTA, FAKE_AV_KEY_SPS };
    script(first, 3);

    xbool_t bKey = XFALSE;
    CHECK(encode(pEnc, XFALSE, &bKey) == XSTDOK && bKey && fake_av()->eLastPict == AV_PICTURE_TYPE_I,
        "the first frame is asked for as a keyframe");
    CHECK(g_out.nUsed == 16 + 11 && memcmp(g_out.pData + 4, "\x67", 1) == 0, "and carries the parameter sets");
    CHECK(encode(pEnc, XFALSE, &bKey) == XSTDOK && !bKey && g_out.nUsed == 8 && fake_av()->eLastPict == AV_PICTURE_TYPE_NONE,
        "the next is a plain frame");
    CHECK(encode(pEnc, XTRUE, &bKey) == XSTDOK && bKey && g_out.nUsed == 16 && fake_av()->eLastPict == AV_PICTURE_TYPE_I,
        "a forced keyframe that brings its own parameter sets is left as it is");
    const fake_av_packet_t more[] = { FAKE_AV_KEY_AUD, FAKE_AV_KEY_BARE, FAKE_AV_AGAIN, FAKE_AV_EMPTY, FAKE_AV_FAIL };
    script(more, 5);
    CHECK(encode(pEnc, XFALSE, &bKey) == XSTDOK && bKey && g_out.nUsed == 18,
        "parameter sets after a delimiter are found where they are");
    CHECK(encode(pEnc, XFALSE, &bKey) == XSTDOK && bKey && g_out.nUsed == 16 + 6,
        "a keyframe with no start code at all gets them in front");
    CHECK(encode(pEnc, XFALSE, NULL) == XSTDNON, "no output yet");
    CHECK(encode(pEnc, XFALSE, &bKey) == XSTDNON && g_out.nUsed == 0, "an empty packet");
    CHECK(encode(pEnc, XFALSE, &bKey) == XSTDERR, "a failed packet");

    fake_av_fail_next("avcodec_send_frame");
    CHECK(encode(pEnc, XFALSE, &bKey) == XSTDERR, "a refused frame");
    fake_av_fail_next("av_frame_make_writable");
    CHECK(encode(pEnc, XFALSE, &bKey) == XSTDERR, "a staging frame that cannot be written");
    CHECK(DirectGate_HWEnc_Encode(pEnc, NULL, 0, XFALSE, &g_out, NULL) == XSTDERR &&
          DirectGate_HWEnc_Encode(pEnc, g_nv12, 0, XFALSE, NULL, NULL) == XSTDERR, "a frame needs pixels and a place to go");

    /* Rate changes: a small one is coalesced, a large one is applied in place, and not again too soon */
    CHECK(DirectGate_HWEnc_SetBitrate(pEnc, 0) == XSTDERR, "no rate is no rate");
    CHECK(DirectGate_HWEnc_SetBitrate(pEnc, 3200) == XSTDOK && encode(pEnc, XFALSE, NULL) == XSTDOK &&
          fake_av()->nSendBitrate == 3000000, "a small change waits for more");
    CHECK(DirectGate_HWEnc_SetBitrate(pEnc, 2000) == XSTDOK && encode(pEnc, XFALSE, NULL) == XSTDOK &&
          fake_av()->nSendBitrate == 2000000 && fake_av()->nOpens == 1, "a large one goes into the live session");
    CHECK(DirectGate_HWEnc_SetBitrate(pEnc, 1000) == XSTDOK && encode(pEnc, XFALSE, NULL) == XSTDOK &&
          fake_av()->nSendBitrate == 2000000, "and the next waits its turn");
    CHECK(DirectGate_HWEnc_SetBitrate(pEnc, 2000) == XSTDOK && encode(pEnc, XFALSE, NULL) == XSTDOK,
        "back to where it is changes nothing");

    directgate_desktop_quality_t q;
    quality(&q, 30, 3000, 120);
    CHECK(DirectGate_HWEnc_ApplyQuality(pEnc, &q) == XSTDOK, "a preset with the same timing only moves the rate");
    usleep(3100000);
    CHECK(encode(pEnc, XFALSE, NULL) == XSTDOK && fake_av()->nSendBitrate == 3000000 && fake_av()->nOpens == 1,
        "which goes in once its turn comes, without a rebuild");

    /* A preset with other timing reopens the encoder */
    quality(&q, 60, 2500, 60);
    CHECK(DirectGate_HWEnc_ApplyQuality(pEnc, &q) == XSTDOK && fake_av()->nOpens == 2 && fake_av()->nLastFps == 60,
        "new timing rebuilds the encoder");
    memset(&q, 0, sizeof(q));
    fake_av_fail_next("avcodec_open2");
    CHECK(DirectGate_HWEnc_ApplyQuality(pEnc, &q) == XSTDERR, "a rebuild that fails says so");
    CHECK(encode(pEnc, XFALSE, NULL) == XSTDERR, "and the encoder is spent");

    DirectGate_HWEnc_Destroy(pEnc);
    CHECK(fake_av_live() == nLive, "nothing of it is left");
    return 0;
}

/* ---------------- what can fail while opening ---------------- */

static int check_open_failures(void)
{
    char sErr[256];
    int nLive = fake_av_live();
    have("h264_nvenc");

    const struct { const char *pName; const char *pExpect; } failures[] = {
        { "avcodec_alloc_context3", "context" },
        { "avcodec_open2", "fake error" },
        { "av_packet_alloc", "frame buffers" },
        { "av_frame_alloc", "frame buffers" },
        { "av_frame_get_buffer", "NV12" },
    };

    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); i++)
    {
        fake_av_fail_next(failures[i].pName);
        CHECK(create(sErr, sizeof(sErr)) == NULL && strstr(sErr, failures[i].pExpect) != NULL,
            "an allocation that fails while opening is reported");
        CHECK(fake_av_live() == nLive, "and leaves nothing behind");
    }

    fake_av()->bStrerrorFails = 1;
    fake_av_fail_next("avcodec_open2");
    CHECK(create(sErr, sizeof(sErr)) == NULL && strstr(sErr, "error -") != NULL, "an error FFmpeg cannot name is a number");
    return 0;
}

/* ---------------- VAAPI: a GPU device and a surface pool ---------------- */

static int check_vaapi(void)
{
    char sErr[256];
    have("h264_vaapi");

    directgate_hwenc_t *pEnc = create(sErr, sizeof(sErr));
    CHECK(pEnc != NULL && fake_av()->nDeviceCreates == 1, "VAAPI opens on the default device");
    CHECK(fake_av()->eLastPixFmt == AV_PIX_FMT_VAAPI, "and encodes from GPU surfaces");
    int nLive = fake_av_live();

    xbool_t bKey = XTRUE;
    CHECK(encode(pEnc, XFALSE, &bKey) == XSTDOK && !bKey && fake_av()->eLastPict == AV_PICTURE_TYPE_I,
        "a frame is uploaded and encoded, the first asked for as a keyframe");

    fake_av_fail_next("av_hwframe_get_buffer");
    CHECK(encode(pEnc, XFALSE, NULL) == XSTDERR, "no surface for it");
    fake_av()->bNoHwBuffer = 1;
    CHECK(encode(pEnc, XFALSE, NULL) == XSTDERR, "a surface with nothing behind it");
    fake_av()->bNoHwBuffer = 0;
    fake_av_fail_next("av_hwframe_transfer_data");
    CHECK(encode(pEnc, XFALSE, NULL) == XSTDERR, "an upload that fails");

    /* Here a rate change rebuilds the encoder, and the first one can happen at once */
    CHECK(DirectGate_HWEnc_SetBitrate(pEnc, 1500) == XSTDOK && encode(pEnc, XFALSE, NULL) == XSTDOK &&
          fake_av()->nOpens == 2 && fake_av()->nLastBitrate == 1500000, "a rate change reopens VAAPI");
    CHECK(fake_av_live() == nLive, "with nothing of the old context left");

    /* A second encoder shares the device the first one opened */
    directgate_hwenc_t *pOther = create(sErr, sizeof(sErr));
    CHECK(pOther != NULL && fake_av()->nDeviceCreates == 1, "a second encoder reuses the open device");
    DirectGate_HWEnc_Destroy(pOther);
    DirectGate_HWEnc_Destroy(pEnc);

    /* Every way the surface pool can fail to come up: the device reference is the first av_buffer_ref and the
       pool's the second. No render node can stand in, as only the default device opens here. */
    nLive = fake_av_live();
    const struct { const char *pName; int nNth; } pool[] = {
        { "av_hwframe_ctx_alloc", 1 }, { "av_hwframe_ctx_init", 1 }, { "av_frame_alloc", 1 },
        { "av_buffer_ref", 2 }, { "av_buffer_ref", 1 }
    };

    for (size_t i = 0; i < sizeof(pool) / sizeof(pool[0]); i++)
    {
        fake_av_fail_nth(pool[i].pName, pool[i].nNth);
        CHECK(create(sErr, sizeof(sErr)) == NULL && sErr[0] != '\0', "a pool that will not come up fails the open");
        CHECK(fake_av_live() == nLive, "and leaves nothing behind");
    }

    return 0;
}

/* ---------------- QSV: a device that will not open ---------------- */

static int check_qsv(void)
{
    char sErr[256];
    have("h264_qsv");
    fake_av()->pDevices[0] = "qsv:/dev/dri/renderD128";
    int bNode = access("/dev/dri/renderD128", R_OK | W_OK) == 0;

    /* The default device fails and is remembered as failing; a render node that opens is used instead */
    directgate_hwenc_t *pEnc = create(sErr, sizeof(sErr));
    CHECK((pEnc != NULL) == bNode, "QSV opens on a render node, where there is one");
    CHECK(bNode || strstr(sErr, "cannot open") != NULL, "and otherwise says the device would not open");

    int nCreates = fake_av()->nDeviceCreates;
    directgate_hwenc_t *pAgain = create(sErr, sizeof(sErr));
    CHECK(fake_av()->nDeviceCreates == nCreates && (pAgain != NULL) == bNode, "no device is tried twice");

    DirectGate_HWEnc_Destroy(pAgain);
    DirectGate_HWEnc_Destroy(pEnc);
    return 0;
}

/* ---------------- the encoders with nothing to open but themselves ---------------- */

static int check_others(void)
{
    char sErr[256];
    const char *pNames[] = { "h264_amf", "h264_v4l2m2m" };

    for (size_t i = 0; i < 2; i++)
    {
        have(pNames[i]);
        directgate_hwenc_t *pEnc = create(sErr, sizeof(sErr));
        CHECK(pEnc != NULL && strstr(DirectGate_HWEnc_Describe(pEnc), pNames[i]) != NULL, "it opens");
        CHECK(encode(pEnc, XFALSE, NULL) == XSTDOK, "and encodes");
        DirectGate_HWEnc_Destroy(pEnc);
    }

    CHECK(fake_av()->nOptions == 0, "the memory-to-memory encoder is given no options it does not have");

    /* A forced encoder is the only one tried */
    have("h264_nvenc");
    fake_av()->pEncoders[1] = "h264_amf";
    setenv("DIRECTGATE_HWENC_ENCODER", "h264_amf", 1);
    directgate_hwenc_t *pEnc = create(sErr, sizeof(sErr));
    CHECK(pEnc != NULL && strcmp(fake_av()->sLastOpened, "h264_amf") == 0 && fake_av()->nOpens == 1,
        "the forced encoder is opened and nothing before it");
    DirectGate_HWEnc_Destroy(pEnc);
    unsetenv("DIRECTGATE_HWENC_ENCODER");

    /* One that fails hands over to the next */
    fake_av_fail_next("avcodec_open2");
    pEnc = create(sErr, sizeof(sErr));
    CHECK(pEnc != NULL && strcmp(fake_av()->sLastOpened, "h264_amf") == 0 && fake_av()->nOpens == 3,
        "an encoder that will not open hands over to the next");
    DirectGate_HWEnc_Destroy(pEnc);

    /* Parameter sets that are not Annex-B are not cached, and none at all is nothing to prepend */
    const fake_av_packet_t key[] = { FAKE_AV_KEY };
    for (int i = 0; i < 2; i++)
    {
        have("h264_amf");
        fake_av()->bExtradata = 0;
        fake_av()->bAvccExtradata = i;
        pEnc = create(sErr, sizeof(sErr));
        CHECK(pEnc != NULL, "open one");
        script(key, 1);
        CHECK(encode(pEnc, XFALSE, NULL) == XSTDOK && g_out.nUsed == 11, "a keyframe goes out as it came");
        DirectGate_HWEnc_Destroy(pEnc);
    }

    return 0;
}

/* ---------------- the Wayland zero-copy chain ---------------- */

#define SRC_W       128
#define SRC_H       64
#define XR24        0x34325258U     /* DRM_FORMAT_XRGB8888 */
#define AR24        0x34325241U     /* DRM_FORMAT_ARGB8888 */
#define NV12        0x3231564eU
#define MODIFIER    0x0100000000000002ULL

static directgate_desktop_dmabuf_t g_dmabuf;

static void dmabuf(void)
{
    memset(&g_dmabuf, 0, sizeof(g_dmabuf));
    g_dmabuf.nWidth = SRC_W;
    g_dmabuf.nHeight = SRC_H;
    g_dmabuf.nFourCC = XR24;
    g_dmabuf.nModifier = MODIFIER;
    g_dmabuf.nPlanes = 1;
    g_dmabuf.nSize = SRC_W * 4 * SRC_H;
    g_dmabuf.nStrides[0] = SRC_W * 4;
    g_dmabuf.nFds[0] = 42;
}

static directgate_hwenc_t* create_import(uint32_t nFourCC, char *pErr, size_t nErrSize)
{
    directgate_desktop_quality_t q;
    quality(&q, 60, 6000, 120);
    pErr[0] = '\0';
    return DirectGate_HWEnc_CreateImport(SRC_W, SRC_H, nFourCC, MODIFIER, W, H, &q, pErr, nErrSize);
}

static int import_refused(const char *pWhy)
{
    char sErr[256] = { 0 };
    return !DirectGate_HWEnc_ImportAvailable(sErr, sizeof(sErr)) && strstr(sErr, pWhy) != NULL ? 0 : 1;
}

#ifdef DIRECTGATE_HWENC_HAS_FILTER
static int import_without_device(void)
{
    have("h264_vaapi");
    fake_av()->pDevices[0] = NULL;
    return import_refused("no VAAPI device");
}

static int import_other_major(void)
{
    have("h264_vaapi");
    fake_av()->nFilterMajor = 1;
    return import_refused("does not match") || import_refused("does not match");
}
#endif

/* Before any GPU device is open: the device cache keeps what it found for the life of the process */
static int check_import_refusals(void)
{
    const struct { const char *pName; const char *pValue; const char *pWhy; } env[] = {
        { "DIRECTGATE_HWENC_ZEROCOPY", "0", "DIRECTGATE_HWENC_ZEROCOPY=0" },
        { "DIRECTGATE_HWENC", "0", "DIRECTGATE_HWENC=0" },
        { "DIRECTGATE_HWENC_ENCODER", "h264_nvenc", "only h264_vaapi can import" }
    };

#ifdef DIRECTGATE_HWENC_HAS_FILTER
    for (size_t i = 0; i < sizeof(env) / sizeof(env[0]); i++)
    {
        setenv(env[i].pName, env[i].pValue, 1);
        int nFailed = import_refused(env[i].pWhy);
        unsetenv(env[i].pName);
        CHECK(!nFailed, "an import switched off or pinned elsewhere is not offered");
    }

    CHECK(in_child(import_without_device), "a machine without a VAAPI device cannot import");
    CHECK(in_child(import_other_major), "nor one whose libavfilter is another major, asked once or twice");
#else
    (void)env;
    CHECK(!import_refused("without the libavfilter headers"), "a build without libavfilter cannot import");
#endif

    char sErr[64];
    directgate_desktop_quality_t q;
    quality(&q, 30, 3000, 120);
    CHECK(DirectGate_HWEnc_CreateImport(8, SRC_H, XR24, 0, W, H, &q, sErr, sizeof(sErr)) == NULL &&
          DirectGate_HWEnc_CreateImport(SRC_W, SRC_H, XR24, 0, W, H, NULL, sErr, sizeof(sErr)) == NULL &&
          DirectGate_HWEnc_CreateImport(SRC_W, SRC_H, XR24, 0, 8, H, &q, sErr, sizeof(sErr)) == NULL &&
          DirectGate_HWEnc_CreateImport(SRC_W, SRC_H, XR24, 0, W + 1, H, &q, sErr, sizeof(sErr)) == NULL,
        "an import needs a quality, sizes it can encode and a source of some size");

    dmabuf();
    CHECK(DirectGate_HWEnc_EncodeImport(NULL, &g_dmabuf, 0, XFALSE, &g_out, NULL) == XSTDERR, "no encoder imports nothing");
    return 0;
}

#ifdef DIRECTGATE_HWENC_HAS_FILTER

/* The n-th call of each of the two graph builds fails: the rich option string first, then the plain retry */
static void fail_both_builds(const char *pName, int nPerBuild, int nNth)
{
    fake_av_fail_nth(pName, nNth);
    fake_av_fail_nth(pName, nPerBuild + nNth - 1);
}

static int check_import_frames(directgate_hwenc_t *pEnc, int nLive)
{
    /* What the chain refuses to map, and each step after the mapping that can fail */
    const struct { int nField; const char *pFail; } bad[] = {
        { 1, NULL }, { 2, NULL }, { 3, NULL }, { 4, NULL }, { 0, "av_buffer_create" }, { 0, "av_buffer_ref" },
        { 0, "av_hwframe_map" }, { 0, "av_buffersrc_add_frame_flags" }, { 0, "av_buffersink_get_frame" },
        { 0, "av_hwframe_get_buffer" }
    };

    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    {
        dmabuf();
        if (bad[i].nField == 1) g_dmabuf.nPlanes = 2;
        if (bad[i].nField == 2) g_dmabuf.nFds[0] = -1;
        if (bad[i].nField == 3) g_dmabuf.nWidth = SRC_W * 2;
        if (bad[i].nField == 4) g_dmabuf.nFourCC = AR24;
        if (bad[i].pFail != NULL) fake_av_fail_next(bad[i].pFail);

        CHECK(DirectGate_HWEnc_EncodeImport(pEnc, &g_dmabuf, 9000, XFALSE, &g_out, NULL) == XSTDERR,
            "a frame the chain cannot take, or a step of it that fails, ends the import");
        CHECK(fake_av_live() == nLive, "and leaves nothing of the frame behind");
    }

    /* A frame that could not be kept costs the still-screen keyframe, not the frame */
    dmabuf();
    fake_av_fail_next("av_frame_ref");
    CHECK(DirectGate_HWEnc_EncodeImport(pEnc, &g_dmabuf, 9500, XFALSE, &g_out, NULL) == XSTDOK,
        "a frame is encoded even when it cannot be kept");
    CHECK(DirectGate_HWEnc_EncodeImport(pEnc, NULL, 9600, XTRUE, &g_out, NULL) == XSTDNON,
        "and then there is no last picture to re-encode");
    CHECK(fake_av_live() == nLive - 1, "and the picture it held before is let go as well");
    return 0;
}

static int check_import(void)
{
    char sErr[256];
    have("h264_vaapi");
    int nLive = fake_av_live();

    fake_av()->bNoScaleFilter = 1;
    CHECK(!import_refused("no scale_vaapi filter"), "an FFmpeg without the VAAPI post-processor cannot import");
    fake_av()->bNoScaleFilter = 0;
    CHECK(DirectGate_HWEnc_ImportAvailable(sErr, sizeof(sErr)), "one with it can");

    /* The whole chain: a DMA-BUF in, the post-processor's NV12 at the encode size out, encoded on the GPU */
    directgate_hwenc_t *pEnc = create_import(XR24, sErr, sizeof(sErr));
    CHECK(pEnc != NULL, "an import encoder opens");
    CHECK(strstr(DirectGate_HWEnc_Describe(pEnc), "zero-copy DMA-BUF") != NULL &&
          strstr(DirectGate_HWEnc_Describe(pEnc), "driver colour") == NULL, "and says what it is");
    CHECK(strcmp(fake_av()->sScaleArgs, "w=64:h=32:format=nv12:out_range=tv:out_color_matrix=bt709") == 0,
        "the post-processor scales to the encode size and converts to limited-range BT.709");
    CHECK(fake_av()->eLastPixFmt == AV_PIX_FMT_VAAPI, "and the encoder reads the surfaces it writes");
    int nOpen = fake_av_live();

    xbool_t bKey = XFALSE;
    dmabuf();
    CHECK(DirectGate_HWEnc_EncodeImport(pEnc, &g_dmabuf, 5000, XTRUE, &g_out, &bKey) == XSTDOK && g_out.nUsed > 0,
        "an exported frame is mapped, converted and encoded");
    CHECK(fake_av()->nMaps == 1 && fake_av()->nLastMapFd == 42 && fake_av()->nLastMapModifier == MODIFIER &&
          fake_av()->nLastMapPitch == SRC_W * 4, "the mapping describes the compositor's buffer as it is");
    CHECK(fake_av()->nLastSourcePts == 5000 && fake_av()->eLastPict == AV_PICTURE_TYPE_I,
        "with the capture time, and as the keyframe that was asked for");
    CHECK(fake_av_live() == nOpen + 1, "the last picture is kept, and nothing else of the frame");
    nOpen = fake_av_live();

    /* A still screen's keyframe is the last picture again, without the compositor */
    CHECK(DirectGate_HWEnc_EncodeImport(pEnc, NULL, 6000, XTRUE, &g_out, &bKey) == XSTDOK && fake_av()->nMaps == 1,
        "a keyframe on a still screen re-encodes the last picture");

    fake_av()->nSinkAgain = 1;
    CHECK(DirectGate_HWEnc_EncodeImport(pEnc, &g_dmabuf, 7000, XFALSE, &g_out, NULL) == XSTDNON,
        "a frame the graph holds back has nothing to encode yet");
    CHECK(DirectGate_HWEnc_EncodeImport(pEnc, &g_dmabuf, 8000, XFALSE, &g_out, NULL) == XSTDOK, "and comes out later");
    CHECK(fake_av_live() == nOpen, "frames in flight are all given back");

    if (check_import_frames(pEnc, nOpen)) return 1;

    /* A rate change re-opens the encoder on the same conversion graph */
    int nOpens = fake_av()->nOpens;
    CHECK(DirectGate_HWEnc_SetBitrate(pEnc, 2000) == XSTDOK &&
          DirectGate_HWEnc_EncodeImport(pEnc, &g_dmabuf, 10000, XFALSE, &g_out, NULL) == XSTDOK &&
          fake_av()->nOpens == nOpens + 1 && fake_av()->nLastBitrate == 2000000, "a rate change reopens the encoder");
    CHECK(fake_av_live() == nOpen, "and the chain it reads from is the same one");

    DirectGate_HWEnc_Destroy(pEnc);
    CHECK(fake_av_live() == nLive, "nothing of the chain outlives the encoder");

    /* An older scale_vaapi has no colour options: one retry without them, and the driver picks the matrix */
    fake_av()->bScaleRejectsColour = 1;
    pEnc = create_import(AR24, sErr, sizeof(sErr));
    CHECK(pEnc != NULL && strstr(DirectGate_HWEnc_Describe(pEnc), "driver colour matrix") != NULL &&
          strcmp(fake_av()->sScaleArgs, "w=64:h=32:format=nv12") == 0, "an older post-processor is asked without them");
    DirectGate_HWEnc_Destroy(pEnc);
    fake_av()->bScaleRejectsColour = 0;

    /* The reason is the last device's: on a host with render nodes, that is one of them failing to open */
    CHECK(create_import(NV12, sErr, sizeof(sErr)) == NULL && sErr[0] != '\0' && fake_av_live() == nLive,
        "a frame format the post-processor does not take opens nothing");

    /* Each step of building the graph that can fail, failing on both attempts; the encoder is not opened */
    const struct { const char *pName; int nPerBuild; int nNth; } steps[] = {
        { "av_hwframe_ctx_alloc", 1, 1 }, { "av_hwframe_ctx_init", 1, 1 }, { "avfilter_get_by_name", 3, 2 },
        { "avfilter_graph_alloc", 1, 1 }, { "avfilter_graph_create_filter", 2, 1 },
        { "avfilter_graph_create_filter", 2, 2 }, { "av_buffersrc_parameters_alloc", 1, 1 },
        { "av_buffersrc_parameters_set", 1, 1 }, { "avfilter_graph_alloc_filter", 1, 1 },
        { "avfilter_init_str", 2, 2 }, { "avfilter_link", 2, 1 }, { "avfilter_link", 2, 2 },
        { "avfilter_graph_config", 1, 1 }
    };

    for (size_t i = 0; i < sizeof(steps) / sizeof(steps[0]); i++)
    {
        fail_both_builds(steps[i].pName, steps[i].nPerBuild, steps[i].nNth);
        int nOpensBefore = fake_av()->nOpens;
        CHECK(create_import(XR24, sErr, sizeof(sErr)) == NULL && sErr[0] != '\0' && fake_av()->nOpens == nOpensBefore,
            "a conversion graph that cannot be built opens no encoder");
        CHECK(fake_av_live() == nLive, "and leaves nothing of itself behind");
    }

    fake_av()->bNoSinkFrames = 1;
    int nOpensBefore = fake_av()->nOpens;
    CHECK(create_import(XR24, sErr, sizeof(sErr)) == NULL && fake_av()->nOpens == nOpensBefore,
        "a graph whose output has no frame pool cannot feed an encoder");
    fake_av()->bNoSinkFrames = 0;
    CHECK(fake_av_live() == nLive, "and is gone again");

    fake_av_fail_next("avcodec_open2");
    CHECK(create_import(XR24, sErr, sizeof(sErr)) == NULL && fake_av_live() == nLive,
        "an encoder that will not open on a built graph takes the graph with it");

    /* The sixth reference an import open takes - after the availability check's and the open's own to the device,
       the graph input's, the post-processor's and the one kept to the graph's output pool - is the encoder's own to
       that pool */
    fake_av_fail_nth("av_buffer_ref", 6);
    nOpensBefore = fake_av()->nOpens;
    CHECK(create_import(XR24, sErr, sizeof(sErr)) == NULL && fake_av()->nOpens == nOpensBefore &&
          fake_av_live() == nLive, "an encoder that cannot hold the graph's output pool is not opened");
    return 0;
}
#endif

int main(void)
{
    XByteBuffer_Init(&g_out, XSTDNON, XFALSE);
    memset(g_nv12, 0x80, sizeof(g_nv12));

    int nFailed = check_import_refusals() || check_loading() || check_refusals() || check_nvenc() ||
        check_open_failures() || check_vaapi() || check_qsv() || check_others();

#ifdef DIRECTGATE_HWENC_HAS_FILTER
    nFailed = nFailed || check_import();
#endif

    XByteBuffer_Clear(&g_out);
    if (nFailed) return 1;

    puts("hwenc_fake_smoke: OK");
    return 0;
}
