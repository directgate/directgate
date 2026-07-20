/* Runtime Opus encoder smoke test (src/agent/desktop/opus.c).
 *
 * Skips (exit 77) when libopus is not installed, matching openh264_smoke. Set
 * DIRECTGATE_OPUS_LIB to run against a specific library. Encodes a couple of
 * 20 ms 48 kHz stereo frames of a sine tone and checks the wrapper produces a
 * non-empty Opus packet and reports a sane sample rate / channel count. */

#include "src/agent/desktop/opus.h"

#include <math.h>

#define DIRECTGATE_TEST_FRAME_SAMPLES 960U   /* 20 ms at 48 kHz */
#define DIRECTGATE_TEST_CHANNELS      2U

static int fail(const char *pMessage)
{
    fprintf(stderr, "opus_smoke: %s\n", pMessage);
    return 1;
}

int main(void)
{
    char sError[256] = {0};
    if (DirectGate_Opus_Load(sError, sizeof(sError)) != XSTDOK)
    {
        fprintf(stderr, "opus_smoke: skipped: %s\n", sError);
        return 77;
    }

    directgate_opus_t *pEnc = DirectGate_Opus_Create(48000U, DIRECTGATE_TEST_CHANNELS,
        128U, sError, sizeof(sError));
    if (pEnc == NULL)
        return fail(sError[0] ? sError : "failed to create Opus encoder");

    if (DirectGate_Opus_GetSampleRate(pEnc) != 48000U)
    {
        DirectGate_Opus_Destroy(pEnc);
        return fail("encoder reports the wrong sample rate");
    }
    if (DirectGate_Opus_GetChannels(pEnc) != DIRECTGATE_TEST_CHANNELS)
    {
        DirectGate_Opus_Destroy(pEnc);
        return fail("encoder reports the wrong channel count");
    }

    int16_t pcm[DIRECTGATE_TEST_FRAME_SAMPLES * DIRECTGATE_TEST_CHANNELS];
    uint8_t packet[1275];

    /* A couple of frames of a 440 Hz tone: the first frame primes the encoder,
     * the second must yield a real (non-DTX) packet. */
    int nBytes = 0;
    for (uint32_t f = 0; f < 2U; f++)
    {
        for (uint32_t i = 0; i < DIRECTGATE_TEST_FRAME_SAMPLES; i++)
        {
            double t = (double)(f * DIRECTGATE_TEST_FRAME_SAMPLES + i) / 48000.0;
            int16_t s = (int16_t)(sin(2.0 * 3.14159265358979 * 440.0 * t) * 12000.0);
            pcm[i * 2U] = s;
            pcm[i * 2U + 1U] = s;
        }

        nBytes = DirectGate_Opus_Encode(pEnc, pcm, DIRECTGATE_TEST_FRAME_SAMPLES,
            packet, sizeof(packet));
        if (nBytes < 0)
        {
            DirectGate_Opus_Destroy(pEnc);
            return fail("Opus encode returned an error");
        }
    }

    if (nBytes <= 1)
    {
        DirectGate_Opus_Destroy(pEnc);
        return fail("Opus encode produced no audible packet");
    }

    if (DirectGate_Opus_SetBitrate(pEnc, 96U) != XSTDOK)
    {
        DirectGate_Opus_Destroy(pEnc);
        return fail("live bitrate update failed");
    }

    printf("opus_smoke: %s encoded a %d-byte frame (lookahead %u)\n",
        DirectGate_Opus_Version(), nBytes, DirectGate_Opus_GetLookahead(pEnc));

    DirectGate_Opus_Destroy(pEnc);
    return 0;
}
