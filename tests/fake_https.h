/*
 * One HTTPS endpoint in the test process that answers every request with the
 * reply the test set last, and remembers the request it answered.
 *
 * For dgcli code that reaches the API through the real TLS client: it serves
 * the tls_fixture.h identity, and fake_https_begin() points SSL_CERT_FILE at
 * that certificate so normal verification accepts it. The server thread only
 * runs XAPI_Service; the reply and the record are shared with the test thread
 * under one mutex.
 */

#ifndef DIRECTGATE_TESTS_FAKE_HTTPS_H
#define DIRECTGATE_TESTS_FAKE_HTTPS_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "src/common/includes.h"
#include "tls_fixture.h"

typedef struct {
    tls_fixture_t tls;
    xapi_t api;
    xthread_t thread;
    xsync_mutex_t lock;
    xatomic_t bStop;
    int bRunning;
    char sUrl[64];

    /* The reply to every request until the test changes it. */
    uint16_t nCode;
    char sType[64];           /* Content-Type; empty sends none */
    char sReply[8192];

    /* The last request answered. */
    int nRequests;
    char sUri[256];
    char sHost[128];
    char sAuth[2048];
    char sApiKey[256];
    char sBody[2048];
} fake_https_t;

static void fake_https_copy(char *pDst, size_t nSize, const char *pSrc)
{
    snprintf(pDst, nSize, "%s", pSrc != NULL ? pSrc : "");
}

static int fake_https_answer(fake_https_t *pFake, xapi_session_t *pSession)
{
    xhttp_t *pRequest = (xhttp_t*)pSession->pPacket;
    if (pRequest == NULL) return XAPI_DISCONNECT;

    XSync_Lock(&pFake->lock);
    pFake->nRequests++;
    fake_https_copy(pFake->sUri, sizeof(pFake->sUri), pRequest->sUri);
    fake_https_copy(pFake->sHost, sizeof(pFake->sHost), XHTTP_GetHeader(pRequest, "Host"));
    fake_https_copy(pFake->sAuth, sizeof(pFake->sAuth), XHTTP_GetHeader(pRequest, "Authorization"));
    fake_https_copy(pFake->sApiKey, sizeof(pFake->sApiKey), XHTTP_GetHeader(pRequest, "apikey"));

    const uint8_t *pBody = XHTTP_GetBody(pRequest);
    size_t nBody = XHTTP_GetBodySize(pRequest);
    if (nBody >= sizeof(pFake->sBody)) nBody = sizeof(pFake->sBody) - 1;
    if (pBody != NULL) memcpy(pFake->sBody, pBody, nBody);
    pFake->sBody[pBody != NULL ? nBody : 0] = '\0';

    xhttp_t reply;
    int nStatus = XAPI_DISCONNECT;

    if (XHTTP_InitResponse(&reply, pFake->nCode, NULL) > 0)
    {
        if ((pFake->sType[0] == '\0' || XHTTP_AddHeader(&reply, "Content-Type", "%s", pFake->sType) >= 0) &&
            XHTTP_Assemble(&reply, (const uint8_t*)pFake->sReply, strlen(pFake->sReply)) != NULL)
        {
            XByteBuffer_AddBuff(&pSession->txBuffer, &reply.rawData);
            nStatus = XAPI_EnableEvent(pSession, XPOLLOUT);
        }

        XHTTP_Clear(&reply);
    }

    XSync_Unlock(&pFake->lock);
    return nStatus;
}

static int fake_https_callback(xapi_ctx_t *pCtx, xapi_session_t *pSession)
{
    fake_https_t *pFake = (fake_https_t*)pCtx->pApi->pUserCtx;

    switch (pCtx->eCbType)
    {
        case XAPI_CB_ACCEPTED: return XAPI_SetEvents(pSession, XPOLLIN);
        case XAPI_CB_READ: return fake_https_answer(pFake, pSession);
        case XAPI_CB_COMPLETE: return XAPI_DISCONNECT;
        default: break;
    }

    return XAPI_CONTINUE;
}

static void* fake_https_thread(void *pArg)
{
    fake_https_t *pFake = (fake_https_t*)pArg;
    while (!XSYNC_ATOMIC_GET(&pFake->bStop)) XAPI_Service(&pFake->api, 20);
    return NULL;
}

static uint16_t fake_https_reserve_port(void)
{
    int nFd = socket(AF_INET, SOCK_STREAM, 0);
    if (nFd < 0) return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    socklen_t nLen = sizeof(addr);
    uint16_t nPort = 0;
    if (bind(nFd, (struct sockaddr*)&addr, sizeof(addr)) == 0 && getsockname(nFd, (struct sockaddr*)&addr, &nLen) == 0)
        nPort = ntohs(addr.sin_port);

    close(nFd);
    return nPort;
}

/* Sets the reply to every request from now on. */
static void fake_https_reply(fake_https_t *pFake, uint16_t nCode, const char *pType, const char *pBody)
{
    XSync_Lock(&pFake->lock);
    pFake->nCode = nCode;
    fake_https_copy(pFake->sType, sizeof(pFake->sType), pType);
    fake_https_copy(pFake->sReply, sizeof(pFake->sReply), pBody);
    XSync_Unlock(&pFake->lock);
}

/* Copies out the last request, so the test never reads what the server thread writes. */
static int fake_https_last(fake_https_t *pFake, fake_https_t *pOut)
{
    XSync_Lock(&pFake->lock);
    int nRequests = pFake->nRequests;
    if (pOut != NULL)
    {
        fake_https_copy(pOut->sUri, sizeof(pOut->sUri), pFake->sUri);
        fake_https_copy(pOut->sHost, sizeof(pOut->sHost), pFake->sHost);
        fake_https_copy(pOut->sAuth, sizeof(pOut->sAuth), pFake->sAuth);
        fake_https_copy(pOut->sApiKey, sizeof(pOut->sApiKey), pFake->sApiKey);
        fake_https_copy(pOut->sBody, sizeof(pOut->sBody), pFake->sBody);
    }

    XSync_Unlock(&pFake->lock);
    return nRequests;
}

/* Returns 1 with the endpoint listening at pFake->sUrl, 0 on any failure. */
static int fake_https_begin(fake_https_t *pFake)
{
    memset(pFake, 0, sizeof(*pFake));
    XSync_Init(&pFake->lock);
    pFake->nCode = 200;
    fake_https_copy(pFake->sType, sizeof(pFake->sType), "application/json");
    fake_https_copy(pFake->sReply, sizeof(pFake->sReply), "{}");

    if (!tls_fixture_begin(&pFake->tls)) return 0;
    setenv("SSL_CERT_FILE", pFake->tls.sCert, 1);
    unsetenv("SSL_CERT_DIR");

    uint16_t nPort = fake_https_reserve_port();
    if (nPort == 0) return 0;
    snprintf(pFake->sUrl, sizeof(pFake->sUrl), "https://127.0.0.1:%u", (unsigned)nPort);

    XAPI_Init(&pFake->api, fake_https_callback, pFake);
    xapi_endpoint_t endpt;
    XAPI_InitEndpoint(&endpt);
    endpt.eType = XAPI_HTTP;
    endpt.eRole = XAPI_SERVER;
    endpt.pAddr = "127.0.0.1";
    endpt.nPort = nPort;
    endpt.bTLS = XTRUE;
    endpt.bForce = XTRUE;
    endpt.certs.pCertPath = pFake->tls.sCert;
    endpt.certs.pKeyPath = pFake->tls.sKey;
    if (XAPI_AddEndpoint(&pFake->api, &endpt) < 0) return 0;

    if (XThread_Create(&pFake->thread, fake_https_thread, pFake, XFALSE) != XSTDOK) return 0;
    pFake->bRunning = 1;
    return 1;
}

static void fake_https_end(fake_https_t *pFake)
{
    if (pFake->bRunning)
    {
        XSYNC_ATOMIC_SET(&pFake->bStop, 1);
        XThread_Join(&pFake->thread);
        pFake->bRunning = 0;
    }

    XAPI_Destroy(&pFake->api);
    XSync_Destroy(&pFake->lock);
    tls_fixture_end(&pFake->tls);
}

#endif /* DIRECTGATE_TESTS_FAKE_HTTPS_H */
