/* Exercise the real audio worker/ring/stop logic with deterministic sources. */
#include <stdio.h>
#include "src/agent/desktop/audio.c"
#define CHECK(c, msg) do { if (!(c)) { fprintf(stderr, "audio_lifecycle_smoke: %s\n", msg); return 1; } } while (0)
static int fail_read, opened, closed, encoders;
void* DirectGate_Audio_BackendOpen(uint32_t rate, uint32_t channels, char *err, size_t len)
{ (void)rate; (void)channels; (void)err; (void)len; opened++; return malloc(1); }
int DirectGate_Audio_BackendRead(void *ctx, int16_t *out, uint32_t frames, uint32_t channels)
{ (void)ctx; xusleep(1000); if (fail_read) return XSTDERR; memset(out, 0, frames * channels * sizeof(*out)); return XSTDOK; }
void DirectGate_Audio_BackendClose(void *ctx) { free(ctx); closed++; }
directgate_opus_t* DirectGate_Opus_Create(uint32_t rate, uint32_t channels, uint32_t bitrate, char *err, size_t len)
{ (void)rate; (void)channels; (void)bitrate; (void)err; (void)len; encoders++; return (directgate_opus_t*)malloc(1); }
void DirectGate_Opus_Destroy(directgate_opus_t *ctx) { free(ctx); encoders--; }
const char* DirectGate_Opus_Version(void) { return "test encoder"; }
int DirectGate_Opus_Encode(directgate_opus_t *ctx, const int16_t *pcm, uint32_t frames, uint8_t *out, size_t len)
{ (void)ctx; (void)pcm; (void)frames; (void)len; out[0] = 1; return 1; }
int main(void)
{
    directgate_session_t session = {0};
    fail_read = 1;
    CHECK(DirectGate_Desktop_AudioStart(&session) == XSTDOK, "worker starts");
    directgate_audio_t *audio = session.desktop.pAudio;
    for (int i = 0; i < 1000 && !XSYNC_ATOMIC_GET(&audio->nFinished); i++) xusleep(1000);
    CHECK(XSYNC_ATOMIC_GET(&audio->nFinished), "failed source exits worker");
    DirectGate_Desktop_AudioDrainMain(&session);
    CHECK(!session.desktop.pAudio && !session.desktop.bAudioReady && session.desktop.sAudioReason[0],
        "main loop exposes failure and releases resources");
    CHECK(opened == closed && encoders == 0, "failure cleans capture and encoder");
    fail_read = 0;
    for (int i = 0; i < 50; i++)
    {
        CHECK(DirectGate_Desktop_AudioStart(&session) == XSTDOK, "restart after failure");
        xusleep(2000);
        DirectGate_Desktop_AudioDrainMain(&session);
        DirectGate_Desktop_AudioStop(&session.desktop);
        CHECK(!session.desktop.pAudio && !session.desktop.bAudioReady, "stop clears readiness");
    }
    CHECK(opened == closed && encoders == 0, "repeated stop joins before freeing");
    puts("audio_lifecycle_smoke: OK");
    return 0;
}
