/* Enrollment against an API on the other end of a real TLS connection: what the agent keeps when its configuration
 * cannot be saved, what it makes of error bodies it cannot read, and how many ICE servers it takes. */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "src/agent/config.h"
#include "src/agent/enroll.h"
#include "fake_https.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "enroll_api_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static const char *g_pPairJson =
    "{"
        "\"deviceId\":\"device-api\","
        "\"accessToken\":\"access-1\","
        "\"accessTokenExpiresAt\":\"2099-04-01T12:00:00.000Z\","
        "\"refreshToken\":\"refresh-1\","
        "\"refreshTokenExpiresAt\":\"2099-05-01T12:00:00.000Z\","
        "\"enrollmentExpiresAt\":\"2099-05-01T12:00:00.000Z\","
        "\"relayUrl\":\"wss://relay.example.test/websock\","
        "\"routingKey\":\"rk-1\","
        "\"iceServers\":[\"stun:a.test\",\"\",\"stun:c.test\",\"stun:d.test\",\"stun:e.test\",\"stun:f.test\","
            "\"stun:g.test\",\"stun:h.test\",\"stun:i.test\",\"stun:j.test\"]"
    "}";

static const char *g_pRotatedJson =
    "{"
        "\"deviceId\":\"device-api\","
        "\"accessToken\":\"access-2\","
        "\"accessTokenExpiresAt\":\"2099-04-01T12:10:00.000Z\","
        "\"refreshTokenRotated\":true,"
        "\"refreshToken\":\"refresh-2\","
        "\"refreshTokenExpiresAt\":\"2099-06-01T12:00:00.000Z\","
        "\"enrollmentExpiresAt\":\"2099-06-01T12:00:00.000Z\","
        "\"relayUrl\":\"wss://relay.example.test/websock\","
        "\"routingKey\":\"rk-1\""
    "}";

static void init_cfg(directgate_cfg_t *pCfg, const char *pApiUrl, const char *pCfgPath)
{
    DirectGate_InitConfig(pCfg);
    xstrncpy(pCfg->sDeviceId, sizeof(pCfg->sDeviceId), "device-api");
    xstrncpy(pCfg->enroll.sApiUrl, sizeof(pCfg->enroll.sApiUrl), pApiUrl);
    xstrncpy(pCfg->sCfgPath, sizeof(pCfg->sCfgPath), pCfgPath);
}

static int file_has(const char *pPath, const char *pText)
{
    char sData[8192];
    FILE *pFile = fopen(pPath, "rb");
    if (pFile == NULL) return 0;

    size_t nRead = fread(sData, 1, sizeof(sData) - 1, pFile);
    fclose(pFile);
    sData[nRead] = '\0';
    return strstr(sData, pText) != NULL;
}

int main(void)
{
    char sRoot[] = "/tmp/directgate_enroll_api.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "create the scratch directory");

    char sCfgPath[128], sBlocker[128], sBlockedPath[160];
    snprintf(sCfgPath, sizeof(sCfgPath), "%s/agent.json", sRoot);
    snprintf(sBlocker, sizeof(sBlocker), "%s/not-a-directory", sRoot);
    snprintf(sBlockedPath, sizeof(sBlockedPath), "%s/agent.json", sBlocker);

    FILE *pBlocker = fopen(sBlocker, "w");
    CHECK(pBlocker != NULL, "create a file to stand where a directory should be");
    fclose(pBlocker);

    fake_https_t api;
    if (!fake_https_begin(&api))
    {
        fake_https_end(&api);
        fprintf(stderr, "enroll_api_smoke: no TLS endpoint could be started, skipping\n");
        return 77;
    }

    /* A pairing the API accepted but that could not be saved is a failed pairing: nothing survives a restart */
    directgate_cfg_t cfg;
    init_cfg(&cfg, api.sUrl, sBlockedPath);
    fake_https_reply(&api, 200, "application/json", g_pPairJson);
    CHECK(!DirectGate_Enroll_Pair(&cfg, "pairing-token"), "a pairing that cannot be saved should fail");

    /* Saved, it is enrolled; of more ICE servers than it keeps it takes the first ones that are there */
    init_cfg(&cfg, api.sUrl, sCfgPath);
    CHECK(DirectGate_Enroll_Pair(&cfg, "pairing-token"), "a pairing that is saved should succeed");
    CHECK(cfg.enroll.bEnrolled && file_has(sCfgPath, "refresh-1"), "the pairing should be on disk");
    CHECK(cfg.nIceSrvCount == DIRECTGATE_MAX_ICE_SERVERS - 1, "an empty ICE server should be skipped within the limit");
    CHECK(!strcmp(cfg.sIceServers[0], "stun:a.test") && !strcmp(cfg.sIceServers[1], "stun:c.test") &&
          !strcmp(cfg.sIceServers[DIRECTGATE_MAX_ICE_SERVERS - 2], "stun:h.test"), "the ICE servers should keep their order");

    fake_https_t request;
    CHECK(fake_https_last(&api, &request) > 0 && strstr(request.sUri, "/pair") != NULL, "the pairing went to the API");

    /* A rotated refresh token that cannot be saved stays in use, and the save stays pending */
    char sReason[XSTR_TINY];
    xstrncpy(cfg.sCfgPath, sizeof(cfg.sCfgPath), sBlockedPath);
    fake_https_reply(&api, 200, "application/json", g_pRotatedJson);
    CHECK(DirectGate_Enroll_Refresh(&cfg, sReason, sizeof(sReason)) == DIRECTGATE_ENROLL_REFRESH_OK,
        "a refresh the API accepted should succeed even when it cannot be saved");
    CHECK(!strcmp(cfg.enroll.sRefreshToken, "refresh-2") && !strcmp(cfg.enroll.sAccessToken, "access-2"),
        "the rotated tokens should be kept in memory");
    CHECK(cfg.bSavePending, "an unsaved rotation should leave the save pending");
    CHECK(file_has(sCfgPath, "refresh-1"), "the configuration on disk is the one that could not be replaced");

    /* Saved, nothing is pending */
    xstrncpy(cfg.sCfgPath, sizeof(cfg.sCfgPath), sCfgPath);
    CHECK(DirectGate_Enroll_Refresh(&cfg, sReason, sizeof(sReason)) == DIRECTGATE_ENROLL_REFRESH_OK,
        "a saved refresh should succeed");
    CHECK(!cfg.bSavePending && file_has(sCfgPath, "refresh-2"), "a saved refresh should leave nothing pending");

    /* A server error with a body that is not JSON, and a success that is not a token response, are transient */
    fake_https_reply(&api, 502, "text/html", "<html>bad gateway</html>");
    CHECK(DirectGate_Enroll_Refresh(&cfg, sReason, sizeof(sReason)) == DIRECTGATE_ENROLL_REFRESH_TRANSIENT,
        "a server error should be transient");
    fake_https_reply(&api, 200, "application/json", "{");
    CHECK(DirectGate_Enroll_Refresh(&cfg, sReason, sizeof(sReason)) == DIRECTGATE_ENROLL_REFRESH_TRANSIENT,
        "an unreadable token response should be transient");
    CHECK(!strcmp(cfg.enroll.sRefreshToken, "refresh-2") && cfg.enroll.bEnrolled,
        "a failed refresh should keep the tokens it had");

    /* The agent key rotation reports what the API said */
    xstrncpy(cfg.keyauth.sIdentityPubB64, sizeof(cfg.keyauth.sIdentityPubB64), "AGENTPUB");
    fake_https_reply(&api, 200, "application/json", "{}");
    CHECK(DirectGate_Enroll_RotateAgentKey(&cfg), "an accepted key rotation should succeed");
    CHECK(fake_https_last(&api, &request) > 0 && strstr(request.sBody, "AGENTPUB") != NULL,
        "the rotation should carry the new key");
    fake_https_reply(&api, 409, "application/json", "{\"code\":\"CONFLICT\",\"message\":\"no\"}");
    CHECK(!DirectGate_Enroll_RotateAgentKey(&cfg), "a refused key rotation should fail");
    fake_https_reply(&api, 500, "text/plain", "oops");
    CHECK(!DirectGate_Enroll_RotateAgentKey(&cfg), "a key rotation the server failed should fail");

    fake_https_end(&api);
    unlink(sCfgPath);
    unlink(sBlocker);
    rmdir(sRoot);

    puts("enroll_api_smoke: OK");
    return 0;
}
