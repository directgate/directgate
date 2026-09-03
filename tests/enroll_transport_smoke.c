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

#define STUB_PORT_BASE      45180
#define STUB_PORT_TRIES     32
#define STUB_REQUEST_MAX    8192

static const char *g_pPairResponse =
    "{"
        "\"deviceId\":\"dev-transport\","
        "\"accessToken\":\"access-1\","
        "\"accessTokenExpiresAt\":\"2026-04-01T12:00:00.000Z\","
        "\"refreshToken\":\"refresh-1\","
        "\"refreshTokenExpiresAt\":\"2026-05-01T12:00:00.000Z\","
        "\"enrollmentExpiresAt\":\"2026-05-01T12:00:00.000Z\","
        "\"relayUrl\":\"wss://relay.example.test/websock\","
        "\"routingKey\":\"rk-1\""
    "}";

typedef struct {
    xsock_t srv;
    uint16_t nPort;
    char sRequest[STUB_REQUEST_MAX];
    size_t nRequestLen;
} enroll_stub_t;

/* Accepts exactly one connection, records the raw request bytes and answers
 * with a well formed pair response. */
static void* stub_serve(void *pArg)
{
    enroll_stub_t *pStub = (enroll_stub_t*)pArg;

    xsock_t peer;
    if (XSock_Accept(&pStub->srv, &peer) == XSOCK_INVALID) return NULL;

    while (pStub->nRequestLen + 1 < sizeof(pStub->sRequest))
    {
        int nRead = XSock_Read(&peer, pStub->sRequest + pStub->nRequestLen,
            sizeof(pStub->sRequest) - pStub->nRequestLen - 1);

        if (nRead <= 0) break;
        pStub->nRequestLen += (size_t)nRead;
        pStub->sRequest[pStub->nRequestLen] = '\0';

        if (strstr(pStub->sRequest, "\r\n\r\n") != NULL) break;
    }

    char sResponse[1024];
    int nLength = snprintf(sResponse, sizeof(sResponse),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %u\r\n"
        "Connection: close\r\n"
        "\r\n%s",
        (unsigned int)strlen(g_pPairResponse), g_pPairResponse);

    if (nLength > 0) XSock_Write(&peer, sResponse, (size_t)nLength);
    XSock_Close(&peer);

    return NULL;
}

static xbool_t stub_listen(enroll_stub_t *pStub)
{
    uint16_t nPort;
    memset(pStub, 0, sizeof(*pStub));

    for (nPort = STUB_PORT_BASE; nPort < STUB_PORT_BASE + STUB_PORT_TRIES; nPort++)
    {
        if (XSock_Create(&pStub->srv, XSOCK_TCP_SERVER, "127.0.0.1", nPort) != XSOCK_INVALID)
        {
            pStub->nPort = nPort;
            return XTRUE;
        }
    }

    return XFALSE;
}

static void cfg_init(directgate_cfg_t *pCfg, const char *pCfgPath, const char *pApiUrl)
{
    DirectGate_InitConfig(pCfg);
    xstrncpy(pCfg->sCfgPath, sizeof(pCfg->sCfgPath), pCfgPath);
    xstrncpy(pCfg->sDeviceId, sizeof(pCfg->sDeviceId), "dev-transport");
    xstrncpy(pCfg->enroll.sApiUrl, sizeof(pCfg->enroll.sApiUrl), pApiUrl);
}

/*
 * The agent reaches the API through XHTTP_EasyPerform(), which never
 * synthesizes request headers, and libxutils defaults requests to HTTP/1.0
 * where Host is optional. That combination left the request routable only by
 * TLS SNI: plain nginx accepted it, but a CDN or WAF edge answers 403 before
 * the origin is reached, so moving api.* behind one would have broken every
 * enrollment. Nothing guarded the header, which is how it went missing in the
 * first place.
 */
static int test_pair_sends_host_header(const char *pCfgPath)
{
    enroll_stub_t stub;
    CHECK(stub_listen(&stub), "bind the stub API listener");

    char sApiUrl[128];
    snprintf(sApiUrl, sizeof(sApiUrl), "http://127.0.0.1:%u", (unsigned int)stub.nPort);

    xthread_t thread;
    XThread_Init(&thread);
    CHECK(XThread_Create(&thread, stub_serve, &stub, XFALSE) > 0, "start the stub API thread");

    directgate_cfg_t cfg;
    cfg_init(&cfg, pCfgPath, sApiUrl);

    xbool_t bPaired = DirectGate_Enroll_Pair(&cfg, "pairing-token-1");
    XThread_Join(&thread);
    XSock_Close(&stub.srv);

    CHECK(bPaired, "pair against the stub API must succeed");
    CHECK(stub.nRequestLen > 0, "the stub must have captured a request");

    char sExpectedHost[128];
    snprintf(sExpectedHost, sizeof(sExpectedHost), "Host: 127.0.0.1:%u\r\n", (unsigned int)stub.nPort);

    CHECK(strstr(stub.sRequest, sExpectedHost) != NULL, "the request must carry a Host header");
    CHECK(strstr(stub.sRequest, "POST /api/v1/devices/pair") != NULL, "the request must target the pair route");
    CHECK(strstr(stub.sRequest, "Content-Type: application/json") != NULL, "the request must declare JSON");

    /* The token travels in the body and must never leak into the request line. */
    CHECK(strstr(stub.sRequest, "POST /api/v1/devices/pair?") == NULL, "the pairing token must not ride in the URI");

    CHECK(cfg.enroll.bEnrolled, "a successful pair must mark the agent enrolled");
    CHECK(strcmp(cfg.sRoutingKey, "rk-1") == 0, "a successful pair must store the routing key");

    return 0;
}

/*
 * Pairing runs after the operator has typed the pairing token and set the auth
 * password, so a single refused connection used to throw all of that away. The
 * retry is observable in the time the call takes: three attempts sleep 1s and
 * then 2s between them, where a single attempt returns as fast as the kernel
 * can refuse the connection.
 */
static int test_pair_retries_transient_failures(const char *pCfgPath)
{
    enroll_stub_t stub;
    CHECK(stub_listen(&stub), "bind a port to find a free one");

    uint16_t nDeadPort = stub.nPort;
    XSock_Close(&stub.srv);

    char sApiUrl[128];
    snprintf(sApiUrl, sizeof(sApiUrl), "http://127.0.0.1:%u", (unsigned int)nDeadPort);

    directgate_cfg_t cfg;
    cfg_init(&cfg, pCfgPath, sApiUrl);

    uint64_t nStartMs = XTime_GetMs();
    xbool_t bPaired = DirectGate_Enroll_Pair(&cfg, "pairing-token-2");
    uint64_t nElapsedMs = XTime_GetMs() - nStartMs;

    CHECK(!bPaired, "pair against a dead port must fail");
    CHECK(!cfg.enroll.bEnrolled, "a failed pair must not mark the agent enrolled");

    /* 1000 ms + 2000 ms of backoff, with slack so a loaded machine cannot flake. */
    CHECK(nElapsedMs >= 2500, "three attempts must spend the backoff between them");
    CHECK(nElapsedMs < 60000, "the retry must stay bounded");

    return 0;
}

int main(void)
{
    char sCfgPath[] = "/tmp/directgate_enroll_transport_smoke.XXXXXX";
    int nFd = mkstemp(sCfgPath);
    CHECK(nFd >= 0, "mkstemp");
    close(nFd);
    unlink(sCfgPath);

    if (test_pair_sends_host_header(sCfgPath) != 0) return 1;
    if (test_pair_retries_transient_failures(sCfgPath) != 0) return 1;

    unlink(sCfgPath);
    printf("enroll_transport_smoke: ok\n");
    return 0;
}
