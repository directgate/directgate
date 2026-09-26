#include <stdio.h>
#include <string.h>

#include "src/client/relay.h"

#include "fake_https.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "client_relay_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

/* What the API answers, against what dgcli keeps of it. */
static int test_envelopes(fake_https_t *pApi)
{
    directgate_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    xstrncpy(cfg.sApiUrl, sizeof(cfg.sApiUrl), pApi->sUrl);
    xstrncpy(cfg.sApiToken, sizeof(cfg.sApiToken), "api-token");
    xstrncpy(cfg.sDeviceId, sizeof(cfg.sDeviceId), "dev-42");
    xstrncpy(cfg.sSignalingUrl, sizeof(cfg.sSignalingUrl), "wss://configured.example.test/websock");

    /* A refusal is a failure, and nothing of the old envelope is touched. */
    fake_https_reply(pApi, 403, "application/json", "{\"message\":\"not your device\"}");
    CHECK(!DirectGate_Relay_FetchEnvelope(&cfg), "a refused session connect fails");

    fake_https_t last;
    CHECK(fake_https_last(pApi, &last) == 1, "the API was asked once");
    CHECK(strcmp(last.sUri, "/api/v1/sessions/connect") == 0, "the merged session-connect endpoint is used");
    CHECK(strcmp(last.sAuth, "Bearer api-token") == 0, "the API token goes as a bearer token");
    CHECK(strstr(last.sBody, "\"deviceId\": \"dev-42\"") != NULL, "the device is named in the body");

    /* Each part the relay socket needs is required. */
    static const struct { const char *pBody; const char *pWhy; } broken[] = {
        { "{\"relay\":{\"browserJwt\":\"j\",\"routingKey\":\"r\"}}", "an envelope without a sessionId is refused" },
        { "{\"sessionId\":\"\",\"relay\":{\"browserJwt\":\"j\",\"routingKey\":\"r\"}}", "an empty sessionId is refused" },
        { "{\"sessionId\":\"s-1\"}", "an envelope without the relay part is refused" },
        { "{\"sessionId\":\"s-1\",\"relay\":{\"routingKey\":\"r\"}}", "a relay part without a browserJwt is refused" },
        { "{\"sessionId\":\"s-1\",\"relay\":{\"browserJwt\":\"j\",\"routingKey\":\"\"}}", "an empty routingKey is refused" }
    };

    for (size_t i = 0; i < sizeof(broken) / sizeof(broken[0]); i++)
    {
        fake_https_reply(pApi, 200, "application/json", broken[i].pBody);
        CHECK(!DirectGate_Relay_FetchEnvelope(&cfg), broken[i].pWhy);
        CHECK(cfg.sAccessToken[0] == '\0' && cfg.sRoutingKey[0] == '\0', "a refused envelope leaves no credentials behind");
    }

    /* No relayUrl keeps the configured relay; ICE servers past the limit are dropped, blanks skipped. */
    char sReply[2048];
    size_t nLen = (size_t)snprintf(sReply, sizeof(sReply),
        "{\"sessionId\":\"s-2\",\"relay\":{\"browserJwt\":\"jwt-2\",\"routingKey\":\"rk-2\",\"iceServers\":[\"\",7");
    for (int i = 0; i < DIRECTGATE_MAX_ICE_SERVERS + 3; i++)
        nLen += (size_t)snprintf(sReply + nLen, sizeof(sReply) - nLen, ",\"stun:ice%d.example.test:3478\"", i);
    snprintf(sReply + nLen, sizeof(sReply) - nLen, "]}}");

    fake_https_reply(pApi, 200, "application/json", sReply);
    CHECK(DirectGate_Relay_FetchEnvelope(&cfg), "a complete envelope is taken");
    CHECK(strcmp(cfg.sAccessToken, "jwt-2") == 0 && strcmp(cfg.sRoutingKey, "rk-2") == 0, "the relay credentials are kept");
    CHECK(strcmp(cfg.sSignalingUrl, "wss://configured.example.test/websock") == 0,
        "without a relayUrl the configured relay stays");
    CHECK(cfg.nIceSrvCount == DIRECTGATE_MAX_ICE_SERVERS - 2, "only the first entries up to the limit count, blanks skipped");
    CHECK(strcmp(cfg.sIceServers[0], "stun:ice0.example.test:3478") == 0, "the first real ICE server is first");

    /* A relayUrl replaces it; ICE servers that are not a list, or only blanks, leave the ones there are. */
    fake_https_reply(pApi, 200, "application/json",
        "{\"sessionId\":\"s-3\",\"relay\":{\"relayUrl\":\"wss://relay3.example.test/websock\",\"browserJwt\":\"jwt-3\","
        "\"routingKey\":\"rk-3\",\"iceServers\":\"stun:not-a-list\"}}");
    CHECK(DirectGate_Relay_FetchEnvelope(&cfg), "an envelope with a relayUrl is taken");
    CHECK(strcmp(cfg.sSignalingUrl, "wss://relay3.example.test/websock") == 0, "the relayUrl replaces the configured relay");
    CHECK(cfg.nIceSrvCount == DIRECTGATE_MAX_ICE_SERVERS - 2, "ICE servers that are not a list change nothing");

    fake_https_reply(pApi, 200, "application/json",
        "{\"sessionId\":\"s-4\",\"relay\":{\"browserJwt\":\"jwt-4\",\"routingKey\":\"rk-4\",\"iceServers\":[\"\",null]}}");
    CHECK(DirectGate_Relay_FetchEnvelope(&cfg), "an envelope with only blank ICE servers is taken");
    CHECK(cfg.nIceSrvCount == DIRECTGATE_MAX_ICE_SERVERS - 2, "blank ICE servers do not wipe the ones there are");
    return 0;
}

int main(void)
{
    CHECK(!DirectGate_Relay_FetchEnvelope(NULL), "reject NULL config");

    directgate_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    CHECK(!DirectGate_Relay_FetchEnvelope(&cfg), "reject missing API URL");

    xstrncpy(cfg.sApiUrl, sizeof(cfg.sApiUrl), "https://api.example.test");
    CHECK(!DirectGate_Relay_FetchEnvelope(&cfg), "reject missing API token");

    xstrncpy(cfg.sApiToken, sizeof(cfg.sApiToken), "token");
    CHECK(!DirectGate_Relay_FetchEnvelope(&cfg), "reject missing device ID");

    xstrncpy(cfg.sDeviceId, sizeof(cfg.sDeviceId), "device-id");
    xstrncpy(cfg.sApiUrl, sizeof(cfg.sApiUrl), "wss://api.example.test");
    CHECK(!DirectGate_Relay_FetchEnvelope(&cfg), "reject non-HTTP API scheme");
    CHECK(cfg.sAccessToken[0] == '\0' && cfg.sRoutingKey[0] == '\0' &&
          cfg.sSignalingUrl[0] == '\0', "failed fetch preserves relay envelope");

    xstrncpy(cfg.sApiUrl, sizeof(cfg.sApiUrl), "https://");
    CHECK(!DirectGate_Relay_FetchEnvelope(&cfg), "reject API URL without host");

    fake_https_t api;
    CHECK(fake_https_begin(&api), "start the API");
    int nResult = test_envelopes(&api);
    fake_https_end(&api);
    if (nResult) return 1;

    puts("client_relay_smoke: OK");
    return 0;
}
