/* A local listening socket queues PulseAudio's connection but never answers.
 * This tests the real dynamically loaded API and timeout without capturing
 * audio. No child process is needed to keep the connection open. */
#include <stdio.h>
#include <sys/un.h>
#include "src/agent/desktop/audio_linux.c"
#define CHECK(c, msg) do { if (!(c)) { fprintf(stderr, "audio_linux_connection_smoke: %s\n", msg); return 1; } } while (0)
int main(void)
{
    char error[256];
    if (DirectGate_Audio_LoadPulse(error, sizeof(error)) != XSTDOK)
    {
        fprintf(stderr, "audio_linux_connection_smoke: SKIP: %s\n", error);
        return 77;
    }
    char root[] = "/tmp/dg-pulse-test-XXXXXX";
    CHECK(mkdtemp(root) != NULL, "temporary directory");
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/socket", root);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0 && bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0 && listen(fd, 1) == 0, "fake server");
    char cookie[256];
    snprintf(cookie, sizeof(cookie), "%s/cookie", root);
    FILE *file = fopen(cookie, "wb");
    CHECK(file != NULL, "test cookie file");
    unsigned char zeros[256] = {0};
    CHECK(fwrite(zeros, 1, sizeof(zeros), file) == sizeof(zeros) && fclose(file) == 0, "test cookie bytes");
    CHECK(setenv("PULSE_COOKIE", cookie, 1) == 0, "isolated cookie");
    char server[256];
    snprintf(server, sizeof(server), "unix:%s", addr.sun_path);
    CHECK(setenv("DIRECTGATE_AUDIO_SERVER", server, 1) == 0, "isolated server");
    uint64_t start = DirectGate_Audio_MonotonicUs();
    void *capture = DirectGate_Audio_BackendOpen(48000, 2, error, sizeof(error));
    uint64_t elapsed = DirectGate_Audio_MonotonicUs() - start;
    /* The pending connection proves we exercised the real handshake rather
     * than an immediate connection/configuration failure. */
    int peer = accept(fd, NULL, NULL);
    if (peer >= 0) close(peer);
    close(fd);
    if (capture) DirectGate_Audio_BackendClose(capture);
    unlink(addr.sun_path); unlink(cookie); rmdir(root);
    CHECK(peer >= 0, "PulseAudio connected to the stalled server");
    CHECK(capture == NULL, "stalled server cannot open a capture");
    /* This includes libpulse's first-use initialization and Valgrind's code
     * translation. Check that the handshake actually waited; CTest's process
     * timeout supplies the upper bound even if BackendOpen never returns. */
    CHECK(elapsed >= 2500000, "real PulseAudio handshake waits for its deadline");
    puts("audio_linux_connection_smoke: OK");
    return 0;
}
