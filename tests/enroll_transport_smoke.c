#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "src/common/includes.h"
#include "src/agent/config.h"
#include "src/agent/enroll.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "enroll_transport_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#define PORT_BASE   45180
#define PORT_TRIES  32
#define WIRE_MAX    8192

/* Renders the request exactly as it would go on the wire, without dialing
 * anything. Assembly is pure, so the header assertions below hold in release
 * builds too - where the endpoint policy refuses plaintext URLs and a stub
 * HTTP server could never be reached. */
static int render_request(char *pOut, size_t nOutSize, const char *pUrl, const char *pPath)
{
    xhttp_t handle;
    if (!DirectGate_Enroll_BuildRequest(&handle, pUrl, pPath)) return -1;

    /* The receive timeout is part of the contract: without it a connection
     * that opens and goes silent parks the agent on recv() forever. */
    if (!handle.nTimeout) { XHTTP_Clear(&handle); return -1; }

    xbyte_buffer_t *pBuffer = XHTTP_Assemble(&handle, NULL, 0);
    if (pBuffer == NULL || pBuffer->nUsed == 0 || pBuffer->nUsed >= nOutSize)
    {
        XHTTP_Clear(&handle);
        return -1;
    }

    memcpy(pOut, pBuffer->pData, pBuffer->nUsed);
    pOut[pBuffer->nUsed] = '\0';

    XHTTP_Clear(&handle);
    return 0;
}

/*
 * The agent reaches the API through XHTTP_EasyPerform(), which synthesizes no
 * request headers, and libxutils defaults requests to HTTP/1.0 where Host is
 * optional. That left the request routable by TLS SNI alone: plain nginx
 * accepted it, but a CDN or WAF edge answers 403 before the origin is reached,
 * so moving api.* behind one would have broken every enrollment at once.
 * Nothing guarded the header, which is how it went missing to begin with.
 */
static int test_request_carries_host_header(void)
{
    char sWire[WIRE_MAX];

    CHECK(render_request(sWire, sizeof(sWire), "https://api.example.test",
        "/api/v1/devices/pair") == 0, "render the pair request");

    CHECK(strstr(sWire, "\r\nHost: api.example.test\r\n") != NULL,
        "the request must carry a Host header");
    CHECK(strstr(sWire, "POST /api/v1/devices/pair") != NULL,
        "the request must target the pair route");
    CHECK(strstr(sWire, "\r\nContent-Type: application/json\r\n") != NULL,
        "the request must declare JSON");
    CHECK(strstr(sWire, "\r\nAccept: application/json\r\n") != NULL,
        "the request must accept JSON");
    CHECK(strstr(sWire, "\r\nUser-Agent: directgate-agent/") != NULL,
        "the request must identify the agent");

    /* The default port must stay out of the header: edges match it against the
     * certificate name, and "host:443" is not that name. */
    CHECK(strstr(sWire, "Host: api.example.test:443") == NULL,
        "the default port must not appear in Host");

    CHECK(render_request(sWire, sizeof(sWire), "http://api.example.test",
        "/api/v1/devices/refresh") == 0, "render over plain http");
    CHECK(strstr(sWire, "Host: api.example.test:80") == NULL,
        "the default http port must not appear in Host either");

    /* A non-default port is part of the authority and must be carried. */
    CHECK(render_request(sWire, sizeof(sWire), "https://api.example.test:8443",
        "/api/v1/devices/refresh") == 0, "render against a custom port");
    CHECK(strstr(sWire, "\r\nHost: api.example.test:8443\r\n") != NULL,
        "a non-default port must appear in Host");

    /* Guards that reject bad input rather than emitting a header-less request */
    CHECK(render_request(sWire, sizeof(sWire), "", "/x") != 0, "reject an empty URL");
    CHECK(render_request(sWire, sizeof(sWire), "https://api.example.test", "") != 0,
        "reject an empty path");

    return 0;
}

/* Returns a loopback port with nothing listening on it. */
static int find_dead_port(uint16_t *pPort)
{
    uint16_t nPort;

    for (nPort = PORT_BASE; nPort < PORT_BASE + PORT_TRIES; nPort++)
    {
        xsock_t probe;
        if (XSock_Create(&probe, XSOCK_TCP_SERVER, "127.0.0.1", nPort) == XSOCK_INVALID) continue;

        /* Binding proved it was free; closing makes connects refuse instantly
         * instead of hanging, which is what keeps this test bounded. */
        XSock_Close(&probe);
        *pPort = nPort;
        return 0;
    }

    return -1;
}

/*
 * Pairing runs after the operator has typed the pairing token and set the auth
 * password, so a single refused connection used to throw all of that away. The
 * retry is observable in the time the call takes: three attempts sleep 1s and
 * then 2s between them, where a single attempt returns as fast as the kernel
 * can refuse the connection.
 *
 * https, not http, so the endpoint policy accepts the URL in release builds
 * too - DIRECTGATE_DEBUG is OFF by default and CI builds with it off.
 */
static int test_pair_retries_transient_failures(void)
{
    uint16_t nDeadPort = 0;
    CHECK(find_dead_port(&nDeadPort) == 0, "find a free loopback port");

    char sCfgPath[] = "/tmp/directgate_enroll_transport_smoke.XXXXXX";
    int nFd = mkstemp(sCfgPath);
    CHECK(nFd >= 0, "mkstemp");
    close(nFd);
    unlink(sCfgPath);

    char sApiUrl[128];
    snprintf(sApiUrl, sizeof(sApiUrl), "https://127.0.0.1:%u", (unsigned int)nDeadPort);

    directgate_cfg_t cfg;
    DirectGate_InitConfig(&cfg);
    xstrncpy(cfg.sCfgPath, sizeof(cfg.sCfgPath), sCfgPath);
    xstrncpy(cfg.sDeviceId, sizeof(cfg.sDeviceId), "dev-transport");
    xstrncpy(cfg.enroll.sApiUrl, sizeof(cfg.enroll.sApiUrl), sApiUrl);

    uint64_t nStartMs = XTime_GetMs();
    xbool_t bPaired = DirectGate_Enroll_Pair(&cfg, "pairing-token-1");
    uint64_t nElapsedMs = XTime_GetMs() - nStartMs;

    unlink(sCfgPath);

    CHECK(!bPaired, "pair against a dead port must fail");
    CHECK(!cfg.enroll.bEnrolled, "a failed pair must not mark the agent enrolled");

    /* 1000 ms + 2000 ms of backoff, with slack so a loaded runner cannot flake. */
    CHECK(nElapsedMs >= 2500, "three attempts must spend the backoff between them");
    CHECK(nElapsedMs < 120000, "the retry must stay bounded");

    return 0;
}

int main(void)
{
    if (test_request_carries_host_header() != 0) return 1;
    if (test_pair_retries_transient_failures() != 0) return 1;

    printf("enroll_transport_smoke: ok\n");
    return 0;
}
