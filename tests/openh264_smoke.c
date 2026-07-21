/* Runtime OpenH264 ABI smoke test.
 *
 * In particular this exercises both the pre-2.6 and 2.6+ SFrameBSInfo
 * layouts selected by openh264.c. Set DIRECTGATE_OPENH264_LIB to run the
 * same binary against a specific distro library. */

#include "src/agent/desktop/openh264.h"

static int fail(const char *pMessage)
{
    fprintf(stderr, "openh264_smoke: %s\n", pMessage);
    return 1;
}

int main(void)
{
    char sError[DIRECTGATE_DESKTOP_REASON_LEN] = {0};
    if (DirectGate_OpenH264_Load(sError, sizeof(sError)) != XSTDOK)
    {
        fprintf(stderr, "openh264_smoke: skipped: %s\n", sError);
        return 77;
    }

    directgate_desktop_quality_t quality;
    memset(&quality, 0, sizeof(quality));
    quality.ePreset = DIRECTGATE_DESKTOP_PRESET_BALANCED;
    quality.nFps = 30U;
    quality.nBitrateKbps = 1000U;
    quality.nKeyframeFrames = 60U;
    quality.bRealtime = XTRUE;

    const uint32_t nWidth = 320U;
    const uint32_t nHeight = 180U;
    directgate_openh264_t *pEncoder = DirectGate_OpenH264_Create(
        nWidth, nHeight, &quality, sError, sizeof(sError));
    if (pEncoder == NULL)
        return fail(sError[0] ? sError : "failed to create encoder");

    size_t nLuma = (size_t)nWidth * nHeight;
    size_t nFrameBytes = nLuma * 3U / 2U;
    uint8_t *pI420 = (uint8_t*)malloc(nFrameBytes);
    if (pI420 == NULL)
    {
        DirectGate_OpenH264_Destroy(pEncoder);
        return fail("failed to allocate I420 frame");
    }

    memset(pI420, 16, nLuma);
    memset(pI420 + nLuma, 128, nFrameBytes - nLuma);

    xbyte_buffer_t output;
    XByteBuffer_Init(&output, XSTDNON, XFALSE);
    xbool_t bKeyframe = XFALSE;
    int nStatus = DirectGate_OpenH264_Encode(
        pEncoder, pI420, 0U, XTRUE, &output, &bKeyframe);

    xbool_t bSps = XFALSE;
    xbool_t bPps = XFALSE;
    xbool_t bIdr = XFALSE;
    for (size_t i = 0; i + 4U < output.nUsed; i++)
    {
        size_t nHeader = 0U;
        if (output.pData[i] == 0U && output.pData[i + 1U] == 0U &&
            output.pData[i + 2U] == 1U)
            nHeader = i + 3U;
        else if (i + 5U < output.nUsed && output.pData[i] == 0U &&
            output.pData[i + 1U] == 0U && output.pData[i + 2U] == 0U &&
            output.pData[i + 3U] == 1U)
            nHeader = i + 4U;

        if (!nHeader || nHeader >= output.nUsed) continue;
        uint8_t nType = output.pData[nHeader] & 0x1FU;
        if (nType == 7U) bSps = XTRUE;
        else if (nType == 8U) bPps = XTRUE;
        else if (nType == 5U) bIdr = XTRUE;
    }

    free(pI420);
    DirectGate_OpenH264_Destroy(pEncoder);
    XByteBuffer_Clear(&output);

    if (nStatus != XSTDOK) return fail("first forced frame was not encoded");
    if (!bKeyframe) return fail("first forced frame was not marked as a keyframe");
    if (!bSps || !bPps || !bIdr)
        return fail("encoded access unit does not contain SPS, PPS, and IDR NALs");

    printf("openh264_smoke: %s layout encoded a complete IDR access unit\n",
        DirectGate_OpenH264_Version());
    return 0;
}
