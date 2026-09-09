/* Deterministic PulseAudio read tests: no audio device is opened. */
#include <stdio.h>
#include "src/agent/desktop/audio_linux.c"

#define CHECK(c, msg) do { if (!(c)) { fprintf(stderr, "audio_linux_smoke: %s\n", msg); return 1; } } while (0)

static unsigned char bytes[8000];
static size_t fragment_size;
static int holes, drops, failed, idle_calls;
static pa_context_state_t context_state(const pa_context *ctx)
{ (void)ctx; return failed ? (pa_context_state_t)5 : DG_PA_CONTEXT_READY; }
static pa_stream_state_t stream_state(const pa_stream *s)
{ (void)s; return DG_PA_STREAM_READY; }
static int iterate(pa_mainloop *m, int block, int *retval)
{ (void)m; (void)retval; if (block) abort(); idle_calls++; return 0; }
static int peek(pa_stream *s, const void **data, size_t *len)
{ (void)s; *data = holes || !fragment_size ? NULL : bytes; *len = fragment_size; return 0; }
static int drop(pa_stream *s)
{ (void)s; drops++; fragment_size = 0; return 0; }

int main(void)
{
    g_pulse.context_get_state = context_state;
    g_pulse.stream_get_state = stream_state;
    g_pulse.mainloop_iterate = iterate;
    g_pulse.stream_peek = peek;
    g_pulse.stream_drop = drop;
    directgate_pulse_t ctx = {0};
    int16_t output[DIRECTGATE_AUDIO_FRAME_SAMPLES * DIRECTGATE_AUDIO_CHANNELS];
    for (size_t i = 0; i < sizeof(bytes); i++) bytes[i] = (unsigned char)i;

    fragment_size = sizeof(output) * 2;
    CHECK(DirectGate_Audio_BackendRead(&ctx, output, 960, 2) == XSTDOK, "first half read");
    CHECK(!memcmp(output, bytes, sizeof(output)) && drops == 0, "unconsumed fragment retained");
    CHECK(DirectGate_Audio_BackendRead(&ctx, output, 960, 2) == XSTDOK, "second half read");
    CHECK(!memcmp(output, bytes + sizeof(output), sizeof(output)) && drops == 1, "fragment dropped exactly once");

    holes = 1;
    fragment_size = sizeof(output);
    memset(output, 1, sizeof(output));
    CHECK(DirectGate_Audio_BackendRead(&ctx, output, 960, 2) == XSTDOK, "hole read");
    for (size_t i = 0; i < sizeof(output) / sizeof(*output); i++) CHECK(output[i] == 0, "hole is silence");
    CHECK(drops == 2, "hole dropped");

    holes = 0;
    fragment_size = 12;
    uint64_t start = DirectGate_Audio_MonotonicUs();
    CHECK(DirectGate_Audio_BackendRead(&ctx, output, 960, 2) == XSTDOK, "stalled source padded");
    uint64_t elapsed = DirectGate_Audio_MonotonicUs() - start;
    CHECK(elapsed >= 18000 && elapsed < 500000, "stalled source returns at frame deadline");
    CHECK(idle_calls > 0 && idle_calls < 200, "idle polling is paced");
    CHECK(!memcmp(output, bytes, 12), "partial fragment preserved");
    for (size_t i = 12; i < sizeof(output); i++) CHECK(((unsigned char*)output)[i] == 0, "partial frame silence pad");
    CHECK(drops == 3, "empty buffer is never dropped");
    failed = 1;
    CHECK(DirectGate_Audio_BackendRead(&ctx, output, 960, 2) == XSTDERR, "server failure surfaced");
    CHECK(DirectGate_Audio_BackendRead(&ctx, output, UINT32_MAX, 2) == XSTDERR, "frame overflow rejected");
    CHECK(DirectGate_Audio_BackendRead(&ctx, output, 960, UINT32_MAX) == XSTDERR, "channel overflow rejected");
    puts("audio_linux_smoke: OK");
    return 0;
}
