/*
 * The GPU H.264 encoder (desktop/hwenc.c) on this machine's real hardware.
 *
 * Nothing else in the suite opens a hardware encoder, so its whole lifecycle
 * went untested: loading libavcodec at run time, walking the encoders and
 * render nodes until one opens, uploading NV12, pulling packets, honouring a
 * forced keyframe, and changing bitrate and preset on a live encoder. Each
 * encoder the host has is driven through the same frames, and what it
 * produces is checked as H.264: Annex B start codes, an IDR slice and the
 * parameter sets on every keyframe, plain slices in between.
 *
 * A host without libavcodec or without any usable GPU encoder skips (77): the
 * software path is what serves it, and that has its own tests.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "src/agent/desktop/hwenc.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "hwenc_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#define HW_WIDTH  640U
#define HW_HEIGHT 360U

/* The NAL unit types present in an Annex B stream, as a bit mask. */
static uint32_t nal_types(const uint8_t *pData, size_t nSize, size_t *pStartCodes)
{
    uint32_t nMask = 0;
    size_t nCodes = 0;

    for (size_t i = 0; i + 3 < nSize; i++)
    {
        if (pData[i] != 0 || pData[i + 1] != 0) continue;

        size_t nHeader = 0;
        if (pData[i + 2] == 1) nHeader = i + 3;
        else if (pData[i + 2] == 0 && pData[i + 3] == 1 && i + 4 < nSize) nHeader = i + 4;
        if (!nHeader || nHeader >= nSize) continue;

        nMask |= 1U << (pData[nHeader] & 0x1f);
        nCodes++;
        i = nHeader;
    }

    if (pStartCodes != NULL) *pStartCodes = nCodes;
    return nMask;
}

/* A moving gradient, so consecutive frames differ and the encoder has
 * something to predict. */
static void fill_frame(uint8_t *pNV12, uint32_t nIndex)
{
    for (uint32_t y = 0; y < HW_HEIGHT; y++)
        for (uint32_t x = 0; x < HW_WIDTH; x++)
            pNV12[(size_t)y * HW_WIDTH + x] = (uint8_t)(x + y + nIndex * 4U);

    uint8_t *pChroma = pNV12 + (size_t)HW_WIDTH * HW_HEIGHT;
    for (uint32_t y = 0; y < HW_HEIGHT / 2U; y++)
        for (uint32_t x = 0; x < HW_WIDTH; x++)
            pChroma[(size_t)y * HW_WIDTH + x] = (uint8_t)(128 + ((x + nIndex) & 31));
}

static void quality(directgate_desktop_quality_t *pQuality, uint32_t nFps, uint32_t nKbps, uint32_t nGop)
{
    memset(pQuality, 0, sizeof(*pQuality));
    pQuality->nMaxEdge = HW_WIDTH;
    pQuality->nFps = nFps;
    pQuality->nBitrateKbps = nKbps;
    pQuality->nBaseBitrateKbps = nKbps;
    pQuality->nKeyframeFrames = nGop;
    pQuality->bRealtime = XTRUE;
}

/* Drives one encoder through keyframes, deltas, a forced keyframe and live
 * rate and preset changes. Returns 1 on failure, 0 on success. */
static int drive_encoder(directgate_hwenc_t *pEnc)
{
    uint8_t *pFrame = (uint8_t*)malloc((size_t)HW_WIDTH * HW_HEIGHT * 3U / 2U);
    CHECK(pFrame != NULL, "allocate a frame");

    xbyte_buffer_t out;
    XByteBuffer_Init(&out, XSTDNON, XFALSE);

    uint32_t nKeyframes = 0, nDeltas = 0, nPackets = 0;
    int nResult = 0;

    for (uint32_t i = 0; i < 90 && !nResult; i++)
    {
        /* A new bitrate mid-stream, and a new preset later, as the adaptive
           controller and the browser's quality menu do. */
        if (i == 30) CHECK(DirectGate_HWEnc_SetBitrate(pEnc, 1500) == XSTDOK, "a live bitrate change is accepted");

        if (i == 60)
        {
            directgate_desktop_quality_t next;
            quality(&next, 60, 2500, 120);
            CHECK(DirectGate_HWEnc_ApplyQuality(pEnc, &next) == XSTDOK, "a new preset is applied to a live encoder");
        }

        fill_frame(pFrame, i);
        xbool_t bKeyframe = XFALSE;
        xbool_t bForce = (i == 45) ? XTRUE : XFALSE;

        int nStatus = DirectGate_HWEnc_Encode(pEnc, pFrame, (uint64_t)i * 33333ULL, bForce, &out, &bKeyframe);
        if (nStatus < 0)
        {
            fprintf(stderr, "hwenc_smoke: frame %u did not encode\n", i);
            nResult = 1;
            break;
        }

        /* A hardware encoder may hold a frame or two back before it emits. */
        if (!out.nUsed) continue;
        nPackets++;

        size_t nCodes = 0;
        uint32_t nTypes = nal_types(out.pData, out.nUsed, &nCodes);
        if (!nCodes)
        {
            fprintf(stderr, "hwenc_smoke: packet %u is not Annex B\n", nPackets);
            nResult = 1;
            break;
        }

        if (bKeyframe)
        {
            nKeyframes++;

            /* A decoder joining at any keyframe needs the parameter sets there. */
            if (!(nTypes & (1U << 5)) || !(nTypes & (1U << 7)) || !(nTypes & (1U << 8)))
            {
                fprintf(stderr, "hwenc_smoke: keyframe %u lacks IDR, SPS or PPS (types 0x%x)\n", nKeyframes, nTypes);
                nResult = 1;
                break;
            }
        }
        else
        {
            nDeltas++;
            if (nTypes & (1U << 5))
            {
                fprintf(stderr, "hwenc_smoke: a packet not flagged as a keyframe carries an IDR slice\n");
                nResult = 1;
                break;
            }
        }
    }

    XByteBuffer_Clear(&out);
    free(pFrame);
    if (nResult) return 1;

    CHECK(nPackets >= 80, "the encoder emits a packet for nearly every frame it is given");
    CHECK(nKeyframes >= 2, "the stream opens on a keyframe and the forced one arrives too");
    CHECK(nDeltas > nKeyframes, "between keyframes the encoder emits predicted frames");
    return 0;
}

/* Loads libavcodec from a path that does not exist, in a child so the parent's
   successfully loaded library is not disturbed. */
static int load_failure_in_child(void)
{
    pid_t nPid = fork();
    if (nPid < 0) return -1;

    if (nPid == 0)
    {
        setenv("DIRECTGATE_HWENC_LIB", "/nonexistent/libavcodec.so.61", 1);
        char sErr[256] = { 0 };
        int nLoaded = DirectGate_HWEnc_Load(sErr, sizeof(sErr));
        exit((nLoaded < 0 && sErr[0] != '\0') ? 0 : 1);
    }

    int nStatus = 0;
    waitpid(nPid, &nStatus, 0);
    return WIFEXITED(nStatus) ? WEXITSTATUS(nStatus) : -1;
}

int main(void)
{
    char sErr[512];

    CHECK(load_failure_in_child() == 0, "a libavcodec that cannot be loaded is reported with a reason");

    if (DirectGate_HWEnc_Load(sErr, sizeof(sErr)) < 0)
    {
        printf("hwenc_smoke: libavcodec is not available (%s), skipping\n", sErr);
        return 77;
    }

    CHECK(DirectGate_HWEnc_Load(sErr, sizeof(sErr)) >= 0, "loading an already loaded library succeeds again");
    CHECK(DirectGate_HWEnc_Version() != NULL && DirectGate_HWEnc_Version()[0] != '\0',
        "the loaded library reports its version");

    directgate_desktop_quality_t q;
    quality(&q, 30, 3000, 60);

    /* Nothing is created for sizes an encoder cannot take. */
    CHECK(DirectGate_HWEnc_Create(0, 0, &q, sErr, sizeof(sErr)) == NULL, "a zero-sized encoder is refused");
    CHECK(DirectGate_HWEnc_Create(HW_WIDTH, HW_HEIGHT, NULL, sErr, sizeof(sErr)) == NULL,
        "an encoder without a quality preset is refused");

    /* The switch that turns the GPU path off wins over everything. */
    setenv("DIRECTGATE_HWENC", "0", 1);
    sErr[0] = '\0';
    CHECK(DirectGate_HWEnc_Create(HW_WIDTH, HW_HEIGHT, &q, sErr, sizeof(sErr)) == NULL,
        "a disabled GPU encoder is never opened");
    CHECK(sErr[0] != '\0', "a disabled GPU encoder says why");
    unsetenv("DIRECTGATE_HWENC");

    /* An encoder this libavcodec does not have is reported, not crashed on. */
    setenv("DIRECTGATE_HWENC_ENCODER", "h264_does_not_exist", 1);
    CHECK(DirectGate_HWEnc_Create(HW_WIDTH, HW_HEIGHT, &q, sErr, sizeof(sErr)) == NULL,
        "a forced encoder that does not exist is refused");
    unsetenv("DIRECTGATE_HWENC_ENCODER");

    /* Every encoder the host actually has, and then the automatic choice. */
    const char *encoders[] = { "h264_nvenc", "h264_vaapi", "h264_qsv", "h264_amf", NULL };
    int nOpened = 0;

    for (size_t i = 0; i < sizeof(encoders) / sizeof(encoders[0]); i++)
    {
        if (encoders[i] != NULL) setenv("DIRECTGATE_HWENC_ENCODER", encoders[i], 1);
        else unsetenv("DIRECTGATE_HWENC_ENCODER");

        sErr[0] = '\0';
        directgate_hwenc_t *pEnc = DirectGate_HWEnc_Create(HW_WIDTH, HW_HEIGHT, &q, sErr, sizeof(sErr));
        const char *pName = encoders[i] != NULL ? encoders[i] : "automatic";

        if (pEnc == NULL)
        {
            printf("hwenc_smoke: %s is not usable here: %s\n", pName, sErr[0] ? sErr : "no reason");
            continue;
        }

        const char *pDescribed = DirectGate_HWEnc_Describe(pEnc);
        CHECK(pDescribed != NULL && pDescribed[0] != '\0', "an open encoder describes itself");
        printf("hwenc_smoke: driving %s (%s)\n", pName, pDescribed);

        int nFailed = drive_encoder(pEnc);
        DirectGate_HWEnc_Destroy(pEnc);
        CHECK(!nFailed, "a GPU encoder produces a valid H.264 stream");
        nOpened++;
    }

    unsetenv("DIRECTGATE_HWENC_ENCODER");

    /* The zero-copy import path: it either exists and opens, or says why not. */
    sErr[0] = '\0';
    xbool_t bImport = DirectGate_HWEnc_ImportAvailable(sErr, sizeof(sErr));
    printf("hwenc_smoke: zero-copy import is %s%s%s\n", bImport ? "available" : "unavailable",
        sErr[0] ? ": " : "", sErr);
    CHECK(DirectGate_HWEnc_CreateImport(HW_WIDTH, HW_HEIGHT, 0, 0, HW_WIDTH, HW_HEIGHT, &q, sErr, sizeof(sErr)) == NULL,
        "an import encoder for an unknown pixel format is refused");

    /* Misuse of a missing encoder is refused, not dereferenced. */
    xbyte_buffer_t out;
    XByteBuffer_Init(&out, XSTDNON, XFALSE);
    uint8_t pixel[16] = { 0 };
    CHECK(DirectGate_HWEnc_Encode(NULL, pixel, 0, XFALSE, &out, NULL) < 0, "encoding with no encoder fails");
    CHECK(DirectGate_HWEnc_SetBitrate(NULL, 1000) < 0, "a bitrate change with no encoder fails");
    CHECK(DirectGate_HWEnc_ApplyQuality(NULL, &q) < 0, "a preset change with no encoder fails");
    DirectGate_HWEnc_Destroy(NULL);
    XByteBuffer_Clear(&out);

    if (!nOpened)
    {
        printf("hwenc_smoke: no GPU encoder could be opened on this host, skipping\n");
        return 77;
    }

    puts("hwenc_smoke: OK");
    return 0;
}
