#include <stdio.h>
#include <string.h>
#include <time.h>

#include "src/agent/config.h"
#include "src/agent/enroll.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "enroll_edge_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static int check_terminal_failure(directgate_cfg_t *pCfg, const char *pCode,
                                  const char *pExpectedReason)
{
    char sBody[256];
    char sReason[XSTR_TINY];
    xstrncpy(sReason, sizeof(sReason), "stale");

    int nLen = snprintf(sBody, sizeof(sBody),
        "{\"code\":\"%s\",\"message\":\"failure\"}", pCode);
    CHECK(nLen > 0 && (size_t)nLen < sizeof(sBody), "failure JSON fits");

    directgate_enroll_status_t eStatus = DirectGate_Enroll_ClassifyRefreshFailure(
        pCfg, 401, (const uint8_t*)sBody, strlen(sBody),
        sReason, sizeof(sReason));

    CHECK(eStatus == DIRECTGATE_ENROLL_REFRESH_TERMINAL,
        "terminal refresh failure status");
    CHECK(strcmp(sReason, pExpectedReason) == 0,
        "terminal refresh failure reason");
    return 0;
}

int main(void)
{
    directgate_cfg_t cfg;
    DirectGate_InitConfig(&cfg);
    xstrncpy(cfg.sDeviceId, sizeof(cfg.sDeviceId), "device-edge");
    xstrncpy(cfg.enroll.sApiUrl, sizeof(cfg.enroll.sApiUrl), "https://api.example.test");

    CHECK(!DirectGate_Enroll_ApplyPairResponse(&cfg, (const uint8_t*)"{", 1),
        "invalid pair JSON must fail");

    const char *pMissingRefresh =
        "{"
            "\"accessToken\":\"access\","
            "\"accessTokenExpiresIn\":3600,"
            "\"refreshTokenExpiresAt\":\"2099-01-01T00:00:00.000Z\","
            "\"enrollmentExpiresAt\":\"2099-01-01T00:00:00.000Z\","
            "\"relayUrl\":\"wss://relay.example.test/websock\","
            "\"routingKey\":\"rk\""
        "}";
    CHECK(!DirectGate_Enroll_ApplyPairResponse(&cfg,
        (const uint8_t*)pMissingRefresh, strlen(pMissingRefresh)),
        "pair response must require refresh token");

    /* Every field the agent needs to reach the relay is required; a response without one changes nothing. */
    static const char *pRequired[] = { "accessToken", "enrollmentExpiresAt", "routingKey", "relayUrl" };
    for (size_t i = 0; i < sizeof(pRequired) / sizeof(pRequired[0]); i++)
    {
        char sBody[1024];
        size_t nLen = (size_t)snprintf(sBody, sizeof(sBody), "{\"refreshToken\":\"refresh\",\"accessTokenExpiresIn\":3600,"
            "\"refreshTokenExpiresAt\":\"2099-01-01T00:00:00.000Z\"");
        if (strcmp(pRequired[i], "accessToken") != 0)
            nLen += (size_t)snprintf(sBody + nLen, sizeof(sBody) - nLen, ",\"accessToken\":\"access\"");
        if (strcmp(pRequired[i], "enrollmentExpiresAt") != 0)
            nLen += (size_t)snprintf(sBody + nLen, sizeof(sBody) - nLen, ",\"enrollmentExpiresAt\":\"2099-01-01T00:00:00.000Z\"");
        if (strcmp(pRequired[i], "routingKey") != 0)
            nLen += (size_t)snprintf(sBody + nLen, sizeof(sBody) - nLen, ",\"routingKey\":\"rk\"");
        if (strcmp(pRequired[i], "relayUrl") != 0)
            nLen += (size_t)snprintf(sBody + nLen, sizeof(sBody) - nLen, ",\"relayUrl\":\"wss://relay.example.test/websock\"");
        nLen += (size_t)snprintf(sBody + nLen, sizeof(sBody) - nLen, "}");

        CHECK(!DirectGate_Enroll_ApplyPairResponse(&cfg, (const uint8_t*)sBody, nLen),
            "a pair response without a required field must fail");
        CHECK(!cfg.enroll.bEnrolled && cfg.enroll.sAccessToken[0] == '\0', "a refused pair response stores nothing");
    }

    time_t tBefore = time(NULL);
    const char *pPairJson =
        "{"
            "\"deviceId\":\"device-from-api\","
            "\"accessToken\":\"access-edge\","
            "\"accessTokenExpiresIn\":3600,"
            "\"refreshToken\":\"refresh-edge\","
            "\"refreshTokenExpiresAt\":\"2099-01-01T00:00:00.000Z\","
            "\"enrollmentExpiresAt\":\"2099-01-01T00:00:00.000Z\","
            "\"signalingUrl\":\"wss://legacy-relay.example.test/websock\","
            "\"routingKey\":\"rk-edge\","
            "\"iceServers\":["
                "\"turn:one.example.test\","
                "\"turn:two.example.test\","
                "\"turn:three.example.test\","
                "\"turn:four.example.test\","
                "\"turn:five.example.test\","
                "\"turn:six.example.test\","
                "\"turn:seven.example.test\","
                "\"turn:eight.example.test\","
                "\"turn:nine.example.test\""
            "]"
        "}";

    CHECK(DirectGate_Enroll_ApplyPairResponse(&cfg,
        (const uint8_t*)pPairJson, strlen(pPairJson)),
        "pair response with signalingUrl fallback should parse");
    CHECK(strcmp(cfg.sDeviceId, "device-from-api") == 0,
        "pair response should accept API device id");
    CHECK(strcmp(cfg.sRelayUrl, "wss://legacy-relay.example.test/websock") == 0,
        "pair response should use signalingUrl fallback");
    CHECK(strcmp(cfg.sRoutingKey, "rk-edge") == 0,
        "pair response should store routing key");
    CHECK(cfg.nIceSrvCount == DIRECTGATE_MAX_ICE_SERVERS,
        "pair response should cap ICE server count");
    CHECK(strcmp(cfg.sIceServers[DIRECTGATE_MAX_ICE_SERVERS - 1],
        "turn:eight.example.test") == 0,
        "pair response should keep capped eighth ICE server");
    CHECK(cfg.enroll.nAccessTokenExp >= (uint64_t)tBefore + 3500,
        "accessTokenExpiresIn should set future expiry");
    CHECK(DirectGate_Enroll_IsEnrolled(&cfg), "complete pair response should be enrolled");
    CHECK(DirectGate_Enroll_AccessTokenIsUsable(&cfg),
        "fresh access token should be usable");
    CHECK(!DirectGate_Enroll_NeedsRefresh(&cfg),
        "fresh access token should not need refresh");

    cfg.enroll.nAccessTokenExp = (uint64_t)time(NULL) + cfg.enroll.nRefreshSkewSec - 1;
    CHECK(DirectGate_Enroll_NeedsRefresh(&cfg),
        "token inside refresh skew should need refresh");
    cfg.enroll.nAccessTokenExp = (uint64_t)time(NULL) - 1;
    CHECK(!DirectGate_Enroll_AccessTokenIsUsable(&cfg),
        "expired access token should not be usable");
    CHECK(DirectGate_Enroll_NeedsRefresh(&cfg),
        "expired access token should need refresh");

    directgate_cfg_t refreshOnly;
    DirectGate_InitConfig(&refreshOnly);
    xstrncpy(refreshOnly.sDeviceId, sizeof(refreshOnly.sDeviceId), "device-edge");
    const char *pRefreshNoStoredToken =
        "{"
            "\"accessToken\":\"access-refresh\","
            "\"accessTokenExpiresIn\":300,"
            "\"refreshTokenRotated\":false,"
            "\"enrollmentExpiresAt\":\"2099-01-01T00:00:00.000Z\","
            "\"relayUrl\":\"wss://relay.example.test/websock\","
            "\"routingKey\":\"rk-edge\""
        "}";
    CHECK(!DirectGate_Enroll_ApplyRefreshResponse(&refreshOnly,
        (const uint8_t*)pRefreshNoStoredToken, strlen(pRefreshNoStoredToken)),
        "stable refresh without stored refresh token must fail");

    uint64_t nStoredRefreshExp = cfg.enroll.nRefreshTokenExp;
    char sStoredRefresh[XSTR_MIN];
    xstrncpy(sStoredRefresh, sizeof(sStoredRefresh), cfg.enroll.sRefreshToken);

    const char *pUnexpectedRefresh =
        "{"
            "\"accessToken\":\"access-refresh-2\","
            "\"accessTokenExpiresIn\":300,"
            "\"refreshTokenRotated\":false,"
            "\"refreshToken\":\"unexpected-refresh\","
            "\"refreshTokenExpiresAt\":\"2099-02-01T00:00:00.000Z\","
            "\"enrollmentExpiresAt\":\"2099-01-01T00:00:00.000Z\","
            "\"relayUrl\":\"wss://relay.example.test/websock\","
            "\"routingKey\":\"rk-edge\""
        "}";
    CHECK(DirectGate_Enroll_ApplyRefreshResponse(&cfg,
        (const uint8_t*)pUnexpectedRefresh, strlen(pUnexpectedRefresh)),
        "stable refresh with unexpected refresh token should still parse");
    CHECK(strcmp(cfg.enroll.sRefreshToken, sStoredRefresh) == 0,
        "stable refresh must keep stored refresh token");
    CHECK(cfg.enroll.nRefreshTokenExp == nStoredRefreshExp,
        "stable refresh must keep stored refresh expiry");

    const char *pRotatedMissingExpiry =
        "{"
            "\"accessToken\":\"access-refresh-3\","
            "\"accessTokenExpiresIn\":300,"
            "\"refreshTokenRotated\":true,"
            "\"refreshToken\":\"refresh-rotated\","
            "\"enrollmentExpiresAt\":\"2099-01-01T00:00:00.000Z\","
            "\"relayUrl\":\"wss://relay.example.test/websock\","
            "\"routingKey\":\"rk-edge\""
        "}";
    CHECK(!DirectGate_Enroll_ApplyRefreshResponse(&cfg,
        (const uint8_t*)pRotatedMissingExpiry, strlen(pRotatedMissingExpiry)),
        "rotated refresh must require refreshTokenExpiresAt");

    CHECK(check_terminal_failure(&cfg, "DEVICE_ENROLLMENT_EXPIRED",
        "device-enrollment-expired") == 0, "expired mapping");
    CHECK(check_terminal_failure(&cfg, "DEVICE_ENROLLMENT_REVOKED",
        "device-revoked") == 0, "revoked mapping");
    CHECK(check_terminal_failure(&cfg, "REFRESH_TOKEN_REUSE_DETECTED",
        "refresh-token-reuse") == 0, "reuse mapping");
    CHECK(check_terminal_failure(&cfg, "INVALID_REFRESH_TOKEN",
        "invalid-refresh-token") == 0, "invalid refresh mapping");

    char sReason[XSTR_TINY];
    xstrncpy(sReason, sizeof(sReason), "stale");
    directgate_enroll_status_t eStatus = DirectGate_Enroll_ClassifyRefreshFailure(
        &cfg, 500, (const uint8_t*)"{\"code\":\"UNKNOWN\"}",
        strlen("{\"code\":\"UNKNOWN\"}"), sReason, sizeof(sReason));
    CHECK(eStatus == DIRECTGATE_ENROLL_REFRESH_TRANSIENT,
        "unknown failure code should be transient");
    CHECK(sReason[0] == '\0', "transient unknown failure should clear reason");

    xstrncpy(sReason, sizeof(sReason), "stale");
    eStatus = DirectGate_Enroll_ClassifyRefreshFailure(
        &cfg, 500, (const uint8_t*)"{", 1, sReason, sizeof(sReason));
    CHECK(eStatus == DIRECTGATE_ENROLL_REFRESH_TRANSIENT,
        "invalid failure JSON should be transient");
    CHECK(sReason[0] == '\0', "invalid failure JSON should clear reason");

    puts("enroll_edge_smoke: OK");
    return 0;
}
