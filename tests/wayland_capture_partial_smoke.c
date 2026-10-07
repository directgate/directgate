/* A PipeWire that is installed but lacks an entry point the capture needs: it is refused once and for all, the
 * portal's descriptor is still closed, and nothing is started on it. Linked against the FAKE_PW_PARTIAL build of
 * fake_pipewire.c, which leaves out pw_stream_queue_buffer. */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "src/agent/desktop/wayland.h"
#include "fake_pipewire.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "wayland_capture_partial_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

int main(void)
{
    char sError[256] = { 0 };
    CHECK(DirectGate_WL_PipeWireLoad(sError, sizeof(sError)) == XSTDERR && strstr(sError, "missing") != NULL,
        "a PipeWire without every entry point is refused");
    CHECK(fake_pw_inits() == 0, "without being initialized");

    sError[0] = '\0';
    CHECK(DirectGate_WL_PipeWireLoad(sError, sizeof(sError)) == XSTDERR && sError[0] != '\0', "and is not tried again");

    int pair[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "make a portal descriptor");
    close(pair[1]);

    sError[0] = '\0';
    CHECK(DirectGate_WL_CaptureStart(pair[0], 7, NULL, NULL, XFALSE, sError, sizeof(sError)) == NULL &&
          sError[0] != '\0', "no capture starts on it");
    CHECK(fcntl(pair[0], F_GETFD) < 0 && errno == EBADF, "and the portal descriptor is closed");
    CHECK(DirectGate_WL_CaptureStart(-1, 7, NULL, NULL, XFALSE, NULL, 0) == NULL, "with or without one");
    CHECK(fake_pw_live() == 0, "nothing was made");

    puts("wayland_capture_partial_smoke: OK");
    return 0;
}
