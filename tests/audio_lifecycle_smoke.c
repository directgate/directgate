/* Exercise the real audio worker/ring/stop logic with deterministic sources. */
#include <stdio.h>
#include "src/agent/desktop/audio.c"
#define CHECK(c, msg) do { if (!(c)) { fprintf(stderr, "audio_lifecycle_smoke: %s\n", msg); return 1; } } while (0)
static int opened, closed, encoders, encode_calls, fail_open, fail_encoder;
/* Read by the audio worker while the test flips them */
static xvolatile_t fail_read, pending_read, pending_calls;
void* DirectGate_Audio_BackendOpen(uint32_t rate, uint32_t channels, char *err, size_t len)
{
    (void)rate; (void)channels;
    if (fail_open) { snprintf(err, len, "no audio source here"); return NULL; }
    opened++;
    return malloc(1);
}
int DirectGate_Audio_BackendRead(void *ctx, int16_t *out, uint32_t frames, uint32_t channels)
{
    (void)ctx;
    xusleep(1000);
    if (XSYNC_ATOMIC_GET(&fail_read)) return XSTDERR;
    if (XSYNC_ATOMIC_GET(&pending_read))
    {
        XSYNC_ATOMIC_SET(&pending_calls, XSYNC_ATOMIC_GET(&pending_calls) + 1);
        return XSTDNON;
    }
    memset(out, 0, frames * channels * sizeof(*out));
    return XSTDOK;
}
void DirectGate_Audio_BackendClose(void *ctx) { free(ctx); closed++; }
directgate_opus_t* DirectGate_Opus_Create(uint32_t rate, uint32_t channels, uint32_t bitrate, char *err, size_t len)
{
    (void)rate; (void)channels; (void)bitrate; (void)err; (void)len;
    if (fail_encoder) return NULL;
    encoders++;
    return (directgate_opus_t*)malloc(1);
}
void DirectGate_Opus_Destroy(directgate_opus_t *ctx) { free(ctx); encoders--; }
const char* DirectGate_Opus_Version(void) { return "test encoder"; }
int DirectGate_Opus_Encode(directgate_opus_t *ctx, const int16_t *pcm, uint32_t frames, uint8_t *out, size_t len)
{ (void)ctx; (void)pcm; (void)frames; (void)len; encode_calls++; out[0] = 1; return 1; }
int main(void)
{
    directgate_session_t session = {0};
    XSYNC_ATOMIC_SET(&fail_read, 1);
    CHECK(DirectGate_Desktop_AudioStart(&session) == XSTDOK, "worker starts");
    directgate_audio_t *audio = session.desktop.pAudio;
    for (int i = 0; i < 1000 && !XSYNC_ATOMIC_GET(&audio->nFinished); i++) xusleep(1000);
    CHECK(XSYNC_ATOMIC_GET(&audio->nFinished), "failed source exits worker");
    DirectGate_Desktop_AudioDrainMain(&session);
    CHECK(!session.desktop.pAudio && !session.desktop.bAudioReady && session.desktop.sAudioReason[0],
        "main loop exposes failure and releases resources");
    CHECK(opened == closed && encoders == 0, "failure cleans capture and encoder");
    XSYNC_ATOMIC_SET(&fail_read, 0);
    XSYNC_ATOMIC_SET(&pending_read, 1);
    CHECK(DirectGate_Desktop_AudioStart(&session) == XSTDOK, "pending source starts");
    audio = session.desktop.pAudio;
    for (int i = 0; i < 1000 && XSYNC_ATOMIC_GET(&pending_calls) < 3 &&
        !XSYNC_ATOMIC_GET(&audio->nFinished); i++) xusleep(1000);
    DirectGate_Desktop_AudioStop(&session.desktop);
    CHECK(XSYNC_ATOMIC_GET(&pending_calls) >= 3, "pending frames keep the worker alive");
    CHECK(encode_calls == 0, "pending PCM is never encoded as silence");
    CHECK(opened == closed && encoders == 0, "Stop joins a stalled source before freeing it");
    XSYNC_ATOMIC_SET(&pending_read, 0);
    for (int i = 0; i < 50; i++)
    {
        CHECK(DirectGate_Desktop_AudioStart(&session) == XSTDOK, "restart after failure");
        xusleep(2000);
        DirectGate_Desktop_AudioDrainMain(&session);
        DirectGate_Desktop_AudioStop(&session.desktop);
        CHECK(!session.desktop.pAudio && !session.desktop.bAudioReady, "stop clears readiness");
    }
    CHECK(opened == closed && encoders == 0, "repeated stop joins before freeing");

    /* Nothing to encode with, or nothing to capture: the start fails with the reason and holds nothing. */
    fail_encoder = 1;
    CHECK(DirectGate_Desktop_AudioStart(&session) == XSTDERR && !session.desktop.pAudio &&
        session.desktop.sAudioReason[0], "no encoder is a failed start with a reason");
    fail_encoder = 0;
    fail_open = 1;
    CHECK(DirectGate_Desktop_AudioStart(&session) == XSTDERR && !session.desktop.pAudio &&
        strstr(session.desktop.sAudioReason, "no audio source") != NULL, "no source is a failed start with its reason");
    CHECK(encoders == 0, "a failed start frees the encoder it made");
    fail_open = 0;

    /* A running worker is kept; one that already gave up is replaced. */
    CHECK(DirectGate_Desktop_AudioStart(&session) == XSTDOK, "audio starts");
    directgate_audio_t *running = session.desktop.pAudio;
    CHECK(DirectGate_Desktop_AudioStart(&session) == XSTDOK && session.desktop.pAudio == running,
        "starting running audio keeps the same worker");

    /* Nobody drains: the ring keeps the newest frames and counts what it dropped. */
    uint32_t dropped = 0;
    for (int i = 0; i < 2000 && dropped == 0; i++)
    {
        xusleep(1000);
        XSync_Lock(&running->lock);
        dropped = (uint32_t)running->nFramesDropped;
        XSync_Unlock(&running->lock);
    }

    CHECK(dropped > 0, "a full ring drops its oldest frame rather than growing");

    XSYNC_ATOMIC_SET(&fail_read, 1);
    for (int i = 0; i < 1000 && !XSYNC_ATOMIC_GET(&running->nFinished); i++) xusleep(1000);
    CHECK(XSYNC_ATOMIC_GET(&running->nFinished), "the worker gives up on a failing source");
    XSYNC_ATOMIC_SET(&fail_read, 0);
    int opened_before = opened;
    CHECK(DirectGate_Desktop_AudioStart(&session) == XSTDOK && opened == opened_before + 1 && closed == opened_before,
        "starting over a finished worker replaces it");
    DirectGate_Desktop_AudioStop(&session.desktop);
    CHECK(opened == closed && encoders == 0, "every start and stop is balanced");
    puts("audio_lifecycle_smoke: OK");
    return 0;
}
