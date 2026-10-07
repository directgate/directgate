/*
 * The software H.264 encoder against fake_openh264.c, for what a working OpenH264 never does: a library that will not
 * load, lacks the encoder's entry points or is another major; an encoder that will not be created, configured or
 * initialised; and frames whose metadata does not add up - too many layers, a negative NAL count, NALs without a
 * bitstream or of no length - each refused rather than read. Both frame layouts are checked, the one OpenH264 2.6
 * brought and the one before it. The library is loaded once per process, so every library runs in a child of its own.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "src/agent/desktop/openh264.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "openh264_fake_smoke: %s (line %d)\n", msg, __LINE__); \
            return 1; \
        } \
    } while (0)

#define W 64
#define H 32

static uint8_t g_i420[W * H * 3 / 2];
static xbyte_buffer_t g_out;
static const char *g_pVersion;

static directgate_openh264_t* create(char *pErr, size_t nErrSize)
{
    directgate_desktop_quality_t q;
    memset(&q, 0, sizeof(q));
    q.nFps = 30;
    q.nBitrateKbps = 2000;
    q.ePreset = DIRECTGATE_DESKTOP_PRESET_LOW_LATENCY;
    pErr[0] = '\0';
    return DirectGate_OpenH264_Create(W, H, &q, pErr, nErrSize);
}

static directgate_openh264_t* create_failing(const char *pStep, char *pErr, size_t nErrSize)
{
    setenv("FAKE_OPENH264_FAIL", pStep, 1);
    directgate_openh264_t *pEncoder = create(pErr, nErrSize);
    unsetenv("FAKE_OPENH264_FAIL");
    return pEncoder;
}

static int encode(directgate_openh264_t *pEncoder, const char *pFrame, xbool_t bKey, xbool_t *pKeyframe)
{
    if (pFrame != NULL) setenv("FAKE_OPENH264_FRAME", pFrame, 1);
    int nStatus = DirectGate_OpenH264_Encode(pEncoder, g_i420, 1000, bKey, &g_out, pKeyframe);
    unsetenv("FAKE_OPENH264_FRAME");
    return nStatus;
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

/* ---------------- libraries that cannot be used ---------------- */

static int check_no_file(void)
{
    char sErr[256];
    setenv("DIRECTGATE_OPENH264_LIB", "/nonexistent/libopenh264.so", 1);
    CHECK(create(sErr, sizeof(sErr)) == NULL && strstr(sErr, "DIRECTGATE_OPENH264_LIB") != NULL,
        "a library that is not where it was said to be is named");
    CHECK(create(sErr, sizeof(sErr)) == NULL && strstr(sErr, "not available") != NULL, "and not looked for again");
    return 0;
}

static int check_no_encoder(void)
{
    char sErr[256];
    setenv("DIRECTGATE_OPENH264_LIB", "libc.so.6", 1);
    CHECK(create(sErr, sizeof(sErr)) == NULL && strstr(sErr, "missing required encoder symbols") != NULL,
        "a library without the encoder's entry points is refused");
    return 0;
}

static int check_other_major(void)
{
    char sErr[256];
    setenv("DIRECTGATE_OPENH264_LIB", FAKE_OPENH264_PATH, 1);
    setenv("FAKE_OPENH264_VERSION", "1.9", 1);
    CHECK(create(sErr, sizeof(sErr)) == NULL && strstr(sErr, "incompatible") != NULL,
        "an OpenH264 of another major is refused: its encoder table may differ");
    CHECK(strcmp(DirectGate_OpenH264_Version(), "unloaded") == 0, "and nothing of it is kept");
    return 0;
}

/* ---------------- a library that loads ---------------- */

static int check_library(void)
{
    char sErr[256];
    setenv("DIRECTGATE_OPENH264_LIB", FAKE_OPENH264_PATH, 1);
    setenv("FAKE_OPENH264_VERSION", g_pVersion, 1);

    CHECK(create_failing("create", sErr, sizeof(sErr)) == NULL && strstr(sErr, "WelsCreateSVCEncoder") != NULL,
        "an encoder the library will not create");
    CHECK(create_failing("null", sErr, sizeof(sErr)) == NULL && strstr(sErr, "WelsCreateSVCEncoder") != NULL,
        "or creates as nothing");
    CHECK(create_failing("defaults", sErr, sizeof(sErr)) == NULL && strstr(sErr, "GetDefaultParams") != NULL,
        "one without defaults");
    CHECK(create_failing("init", sErr, sizeof(sErr)) == NULL && strstr(sErr, "InitializeExt") != NULL,
        "and one that will not take its configuration");

    directgate_openh264_t *pEnc = create(sErr, sizeof(sErr));
    CHECK(pEnc != NULL, "an encoder opens");
    char sVersion[32];
    snprintf(sVersion, sizeof(sVersion), "openh264 %s.0", g_pVersion);
    CHECK(strcmp(DirectGate_OpenH264_Version(), sVersion) == 0, "on the version the library reports");
    CHECK(DirectGate_OpenH264_GetWidth(pEnc) == W && DirectGate_OpenH264_GetHeight(pEnc) == H, "at its size");

    xbool_t bKey = XTRUE;
    CHECK(encode(pEnc, NULL, XFALSE, &bKey) == XSTDOK && g_out.nUsed == 16 && !bKey, "a frame comes out whole");
    CHECK(encode(pEnc, NULL, XTRUE, &bKey) == XSTDOK && bKey, "and a keyframe asked for is one");
    CHECK(encode(pEnc, NULL, XFALSE, NULL) == XSTDOK, "with nobody asking whether it was");

    CHECK(encode(pEnc, "skip", XFALSE, &bKey) == XSTDNON && encode(pEnc, "empty", XFALSE, &bKey) == XSTDNON,
        "a skipped frame, or one with nothing in it, sends nothing");

    /* Metadata that does not add up is refused before anything is read through it */
    const char *bad[] = { "layers", "nals", "nullbits", "zero" };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        CHECK(encode(pEnc, bad[i], XFALSE, &bKey) == XSTDERR, "a frame whose metadata does not add up is refused");

    setenv("FAKE_OPENH264_FAIL", "encode", 1);
    CHECK(encode(pEnc, NULL, XFALSE, &bKey) == XSTDERR, "and so is a frame the encoder failed");
    unsetenv("FAKE_OPENH264_FAIL");

    directgate_desktop_quality_t q;
    memset(&q, 0, sizeof(q));
    CHECK(DirectGate_OpenH264_SetBitrate(pEnc, 1500) == XSTDOK && DirectGate_OpenH264_ApplyQuality(pEnc, &q) == XSTDOK,
        "rate and preset changes go to the encoder, with defaults for what a preset leaves out");

    CHECK(DirectGate_OpenH264_Encode(NULL, g_i420, 0, XFALSE, &g_out, NULL) == XSTDERR &&
          DirectGate_OpenH264_Encode(pEnc, NULL, 0, XFALSE, &g_out, NULL) == XSTDERR &&
          DirectGate_OpenH264_Encode(pEnc, g_i420, 0, XFALSE, NULL, NULL) == XSTDERR &&
          DirectGate_OpenH264_SetBitrate(NULL, 1) == XSTDERR && DirectGate_OpenH264_SetBitrate(pEnc, 0) == XSTDERR &&
          DirectGate_OpenH264_ApplyQuality(NULL, &q) == XSTDERR && DirectGate_OpenH264_ApplyQuality(pEnc, NULL) == XSTDERR &&
          DirectGate_OpenH264_GetWidth(NULL) == 0 && DirectGate_OpenH264_GetHeight(NULL) == 0,
        "no encoder, no picture or nowhere to put it does nothing");
    CHECK(DirectGate_OpenH264_Create(W, H, NULL, sErr, sizeof(sErr)) == NULL &&
          DirectGate_OpenH264_Create(8, H, &q, sErr, sizeof(sErr)) == NULL &&
          DirectGate_OpenH264_Create(W + 1, H, &q, sErr, sizeof(sErr)) == NULL, "nor does an encoder of no size");

    DirectGate_OpenH264_Destroy(pEnc);
    DirectGate_OpenH264_Destroy(NULL);
    return 0;
}

int main(void)
{
    XByteBuffer_Init(&g_out, XSTDNON, XFALSE);
    memset(g_i420, 0x80, sizeof(g_i420));
    unsetenv("FAKE_OPENH264_FAIL");
    unsetenv("FAKE_OPENH264_FRAME");

    int nFailed = !in_child(check_no_file) || !in_child(check_no_encoder) || !in_child(check_other_major);

    /* The frame layout OpenH264 2.6 brought, and the one before it (Ubuntu 24.04 ships 2.4) */
    g_pVersion = "2.6";
    nFailed = nFailed || !in_child(check_library);
    g_pVersion = "2.4";
    nFailed = nFailed || !in_child(check_library);

    XByteBuffer_Clear(&g_out);
    if (nFailed) return 1;

    puts("openh264_fake_smoke: OK");
    return 0;
}
