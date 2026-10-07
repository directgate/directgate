/*
 * A stand-in for Cisco's OpenH264, loaded by path through DIRECTGATE_OPENH264_LIB, for what the real library never
 * does on a machine with a working one: report another version, fail to create, configure or encode, or hand back
 * frame metadata that does not add up. It reads what to do from the environment on every call, so one process can go
 * through several of these; the version is read when the library is loaded, which the agent does once per process.
 *
 *   FAKE_OPENH264_VERSION  "major.minor", the vendored headers' when unset; before 2.6 a frame comes back in the
 *                          older layout openh264.c keeps for it
 *   FAKE_OPENH264_FAIL     create, null, defaults, init or encode: that step fails (null: creates nothing, says yes)
 *   FAKE_OPENH264_FRAME    skip, empty, layers, nals, nullbits or zero: a skipped frame, a layer with no NALs, more
 *                          layers than a frame has room for, a negative NAL count, NALs without a bitstream, a NAL
 *                          of no length
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wels/codec_api.h>
#include <wels/codec_ver.h>

/* The frame layout before 2.6, field for field as openh264.c declares it */
typedef struct {
    unsigned char uiTemporalId;
    unsigned char uiSpatialId;
    unsigned char uiQualityId;
    EVideoFrameType eFrameType;
    unsigned char uiLayerType;
    int iSubSeqId;
    int iNalCount;
    int *pNalLengthInByte;
    unsigned char *pBsBuf;
} fake_layer_pre26_t;

typedef struct {
    int iLayerNum;
    fake_layer_pre26_t sLayerInfo[MAX_LAYER_NUM_OF_FRAME];
    EVideoFrameType eFrameType;
    int iFrameSizeInBytes;
    long long uiTimeStamp;
} fake_frame_pre26_t;

/* An SPS and an IDR slice, each with its start code */
static unsigned char g_bits[] = { 0, 0, 0, 1, 0x67, 0x42, 0xc0, 0x1f, 0, 0, 0, 1, 0x65, 0x88, 0x84, 0x00 };
static int g_lengths[] = { 8, 8 };
static int g_zero[] = { 0 };
static int g_bIntra;

static int fails(const char *pStep)
{
    const char *pFail = getenv("FAKE_OPENH264_FAIL");
    return pFail != NULL && strcmp(pFail, pStep) == 0;
}

static void version(unsigned *pMajor, unsigned *pMinor)
{
    *pMajor = OPENH264_MAJOR;
    *pMinor = OPENH264_MINOR;

    const char *pVersion = getenv("FAKE_OPENH264_VERSION");
    if (pVersion != NULL && sscanf(pVersion, "%u.%u", pMajor, pMinor) != 2)
    {
        *pMajor = OPENH264_MAJOR;
        *pMinor = OPENH264_MINOR;
    }
}

static int fake_initialize(ISVCEncoder *pEncoder, const SEncParamBase *pParam)
{
    (void)pEncoder;
    (void)pParam;
    return 0;
}

static int fake_initialize_ext(ISVCEncoder *pEncoder, const SEncParamExt *pParam)
{
    (void)pEncoder;
    return (fails("init") || pParam->iPicWidth <= 0 || pParam->iPicHeight <= 0) ? 1 : 0;
}

static int fake_get_default_params(ISVCEncoder *pEncoder, SEncParamExt *pParam)
{
    (void)pEncoder;
    if (fails("defaults")) return 1;

    memset(pParam, 0, sizeof(*pParam));
    return 0;
}

static int fake_uninitialize(ISVCEncoder *pEncoder)
{
    (void)pEncoder;
    return 0;
}

static int fake_encode_frame(ISVCEncoder *pEncoder, const SSourcePicture *pPicture, SFrameBSInfo *pInfo)
{
    (void)pEncoder;
    (void)pPicture;
    if (fails("encode")) return 1;

    const char *pFrame = getenv("FAKE_OPENH264_FRAME");
    if (pFrame == NULL) pFrame = "";

    int nLayers = 1;
    int nNals = 2;
    int *pLengths = g_lengths;
    unsigned char *pBits = g_bits;
    EVideoFrameType eType = g_bIntra ? videoFrameTypeIDR : videoFrameTypeP;
    g_bIntra = 0;

    if (strcmp(pFrame, "skip") == 0) eType = videoFrameTypeSkip;
    else if (strcmp(pFrame, "empty") == 0) nNals = 0;
    else if (strcmp(pFrame, "layers") == 0) nLayers = MAX_LAYER_NUM_OF_FRAME + 1;
    else if (strcmp(pFrame, "nals") == 0) nNals = -1;
    else if (strcmp(pFrame, "nullbits") == 0) pBits = NULL;
    else if (strcmp(pFrame, "zero") == 0)
    {
        pLengths = g_zero;
        nNals = 1;
    }

    unsigned nMajor, nMinor;
    version(&nMajor, &nMinor);

    if (nMajor == 2 && nMinor < 6)
    {
        fake_frame_pre26_t *pOld = (fake_frame_pre26_t*)pInfo;
        pOld->iLayerNum = nLayers;
        pOld->eFrameType = eType;
        pOld->sLayerInfo[0].eFrameType = eType;
        pOld->sLayerInfo[0].iNalCount = nNals;
        pOld->sLayerInfo[0].pNalLengthInByte = pLengths;
        pOld->sLayerInfo[0].pBsBuf = pBits;
        return 0;
    }

    pInfo->iLayerNum = nLayers;
    pInfo->eFrameType = eType;
    pInfo->sLayerInfo[0].eFrameType = eType;
    pInfo->sLayerInfo[0].iNalCount = nNals;
    pInfo->sLayerInfo[0].pNalLengthInByte = pLengths;
    pInfo->sLayerInfo[0].pBsBuf = pBits;
    return 0;
}

static int fake_encode_parameter_sets(ISVCEncoder *pEncoder, SFrameBSInfo *pInfo)
{
    (void)pEncoder;
    (void)pInfo;
    return 0;
}

static int fake_force_intra_frame(ISVCEncoder *pEncoder, bool bIDR)
{
    (void)pEncoder;
    g_bIntra = bIDR ? 1 : 0;
    return 0;
}

static int fake_option(ISVCEncoder *pEncoder, ENCODER_OPTION eOptionId, void *pOption)
{
    (void)pEncoder;
    (void)eOptionId;
    (void)pOption;
    return 0;
}

static const ISVCEncoderVtbl g_vtbl = {
    fake_initialize,
    fake_initialize_ext,
    fake_get_default_params,
    fake_uninitialize,
    fake_encode_frame,
    fake_encode_parameter_sets,
    fake_force_intra_frame,
    fake_option,
    fake_option
};

int WelsCreateSVCEncoder(ISVCEncoder **ppEncoder)
{
    *ppEncoder = NULL;
    if (fails("create")) return 1;
    if (fails("null")) return 0;

    ISVCEncoder *pEncoder = (ISVCEncoder*)malloc(sizeof(*pEncoder));
    if (pEncoder == NULL) return 1;

    *pEncoder = &g_vtbl;
    *ppEncoder = pEncoder;
    return 0;
}

void WelsDestroySVCEncoder(ISVCEncoder *pEncoder)
{
    free(pEncoder);
}

void WelsGetCodecVersionEx(OpenH264Version *pVersion)
{
    unsigned nMajor, nMinor;
    version(&nMajor, &nMinor);

    pVersion->uMajor = nMajor;
    pVersion->uMinor = nMinor;
    pVersion->uRevision = 0;
    pVersion->uReserved = 0;
}
