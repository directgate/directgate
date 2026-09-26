/* Runtime Opus encoder smoke test (src/agent/desktop/opus.c).
 *
 * Skips (exit 77) when libopus is not installed, matching openh264_smoke. Set
 * DIRECTGATE_OPUS_LIB to run against a specific library. Encodes a couple of
 * 20 ms 48 kHz stereo frames of a sine tone and checks the wrapper produces a
 * non-empty Opus packet and reports a sane sample rate / channel count. First,
 * in child processes since the library loads once per process, a path that
 * does not load and a library that is not Opus are refused with the reason. */

#include "src/agent/desktop/opus.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define DIRECTGATE_TEST_FRAME_SAMPLES 960U   /* 20 ms at 48 kHz */
#define DIRECTGATE_TEST_CHANNELS      2U

static int fail(const char *pMessage)
{
    fprintf(stderr, "opus_smoke: %s\n", pMessage);
    return 1;
}

static int child_refuses(const char *pLibrary, const char *pExpect)
{
    char sError[256] = {0};
    setenv("DIRECTGATE_OPUS_LIB", pLibrary, 1);

    if (DirectGate_Opus_Load(sError, sizeof(sError)) == XSTDOK) return fail("an unusable library was loaded");
    if (strstr(sError, pExpect) == NULL) return fail(sError);

    sError[0] = '\0';
    if (DirectGate_Opus_Create(48000U, 2U, 64U, sError, sizeof(sError)) != NULL || strstr(sError, "not available") == NULL)
        return fail("a failed load is not retried, and an encoder is not made without it");

    return 0;
}

/* Run in a child: the library is loaded once per process. */
static int refuses(const char *pLibrary, const char *pExpect)
{
    pid_t nPid = fork();
    if (nPid < 0) return fail("fork");

    /* exit, not _exit: the child's coverage is written by its exit handlers. */
    if (nPid == 0) exit(child_refuses(pLibrary, pExpect));

    int nStatus = 0;
    if (waitpid(nPid, &nStatus, 0) != nPid || !WIFEXITED(nStatus) || WEXITSTATUS(nStatus) != 0)
        return fail("an unusable Opus library is refused with the reason");

    return 0;
}

int main(void)
{
    /* A path that does not load, and a library that is not Opus. */
    if (refuses("/nonexistent/libopus.so", "DIRECTGATE_OPUS_LIB")) return 1;
    if (refuses("libm.so.6", "missing required encoder symbols")) return 1;

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

    /* Opus takes 2.5 to 60 ms frames; seven samples is none of them. */
    if (DirectGate_Opus_Encode(pEnc, pcm, 7U, packet, sizeof(packet)) >= 0)
    {
        DirectGate_Opus_Destroy(pEnc);
        return fail("a frame size Opus does not take is an error");
    }

    if (DirectGate_Opus_Create(44100U, 2U, 64U, sError, sizeof(sError)) != NULL ||
        DirectGate_Opus_Create(48000U, 3U, 64U, sError, sizeof(sError)) != NULL)
    {
        DirectGate_Opus_Destroy(pEnc);
        return fail("a rate or channel count Opus does not take is refused");
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
