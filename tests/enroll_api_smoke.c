/* Enrollment against an API on the other end of a real TLS connection: what the agent keeps when its configuration
 * cannot be saved, what it makes of error bodies it cannot read, and how many ICE servers it takes. */

#include <errno.h>
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

#define ORG_ID "33333333-3333-3333-3333-333333333333"

static const char *g_pOrgPairJson =
    "{"
        "\"deviceId\":\"device-api\","
        "\"accessToken\":\"access-org\","
        "\"accessTokenExpiresAt\":\"2099-04-01T12:00:00.000Z\","
        "\"refreshToken\":\"refresh-org\","
        "\"refreshTokenExpiresAt\":\"2099-05-01T12:00:00.000Z\","
        "\"enrollmentExpiresAt\":\"2099-05-01T12:00:00.000Z\","
        "\"relayUrl\":\"wss://relay.example.test/websock\","
        "\"routingKey\":\"rk-org\","
        "\"organizationId\":\"" ORG_ID "\""
    "}";

static const char *g_pOrgRefreshJson =
    "{"
        "\"deviceId\":\"device-api\","
        "\"accessToken\":\"access-org-2\","
        "\"accessTokenExpiresAt\":\"2099-04-01T12:10:00.000Z\","
        "\"refreshTokenRotated\":false,"
        "\"enrollmentExpiresAt\":\"2099-05-01T12:00:00.000Z\","
        "\"relayUrl\":\"wss://relay.example.test/websock\","
        "\"routingKey\":\"rk-org\","
        "\"organizationId\":\"" ORG_ID "\""
    "}";

/* The last enrollment failure logged. Only those lines are kept: the API thread logs as well, and nothing of its is
 * shared with the test thread then. */
static char g_sFailure[XSTR_MID];

static int keep_failure(const char *pLog, size_t nLength, xlog_flag_t eFlag, void *pCtx)
{
    (void)nLength;
    (void)eFlag;
    (void)pCtx;
    if (strstr(pLog, "oserr(") != NULL) xstrncpy(g_sFailure, sizeof(g_sFailure), pLog);
    return 0;
}

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

    /* Organization-managed keys are the operator's -m <organization id> and never the API's: a pairing without -m
     * switches nothing on, a pairing with it saves the allowance in the config it creates, and the allowance only
     * applies to an enrollment in that same organization. */
    {
        char sOrgCfgPath[160];
        char sPersonalCfgPath[160];
        snprintf(sOrgCfgPath, sizeof(sOrgCfgPath), "%s/org-agent.json", sRoot);
        snprintf(sPersonalCfgPath, sizeof(sPersonalCfgPath), "%s/personal-agent.json", sRoot);

        /* The first pairing creates the config: there is no file before it, so -m travels on the command line */
        char sArg0[] = "directgate", sArgC[] = "-c", sArgS[] = "-s", sArgE[] = "-e", sArgT[] = "-t";
        char sArgM[] = "-m", sToken[] = "pairing-token", sOrg[] = ORG_ID, sEmpty[] = "", sBad[] = "not-a-uuid";
        char *pPairArgv[] = { sArg0, sArgC, sOrgCfgPath, sArgE, sArgT, sToken, sArgM, sOrg, NULL };

        directgate_cfg_t cfg2;
        CHECK(DirectGate_ParseArgs(&cfg2, 8, pPairArgv) && cfg2.bSetManagedOrg && !strcmp(cfg2.keyauth.sManagedOrgId, ORG_ID),
            "-m should parse with no config file yet");
        xstrncpy(cfg2.sDeviceId, sizeof(cfg2.sDeviceId), "device-api");
        xstrncpy(cfg2.enroll.sApiUrl, sizeof(cfg2.enroll.sApiUrl), api.sUrl);
        CHECK(DirectGate_AuthGenerateRecord(&cfg2.auth, "org-password"), "an SRP record for the organization device");

        fake_https_reply(&api, 200, "application/json", g_pOrgPairJson);
        CHECK(DirectGate_ApplyConfig(&cfg2) == XSTDNON, "a pairing into an organization with -m should succeed");
        CHECK(file_has(sOrgCfgPath, "\"organizationId\": \"" ORG_ID "\"") &&
            file_has(sOrgCfgPath, "\"managedOrganizationId\": \"" ORG_ID "\""),
            "the pairing should save the organization and the operator's allowance into the config it creates");

        /* Pairing again without -m changes nothing about it */
        char *pRepairArgv[] = { sArg0, sArgC, sOrgCfgPath, sArgE, sArgT, sToken, NULL };
        CHECK(DirectGate_ParseArgs(&cfg2, 6, pRepairArgv) && !cfg2.bSetManagedOrg, "a pairing without -m should parse");
        CHECK(DirectGate_ApplyConfig(&cfg2) == XSTDNON, "pairing again without -m should succeed");
        CHECK(file_has(sOrgCfgPath, "\"managedOrganizationId\": \"" ORG_ID "\""),
            "a pairing without -m should leave the allowance as it was");

        /* -m on its own: an empty value takes the allowance back, an organization id puts it in place */
        char *pClearArgv[] = { sArg0, sArgC, sOrgCfgPath, sArgM, sEmpty, NULL };
        CHECK(DirectGate_ParseArgs(&cfg2, 5, pClearArgv) && cfg2.bSetManagedOrg && cfg2.keyauth.sManagedOrgId[0] == '\0',
            "-m with an empty value should parse");
        CHECK(DirectGate_ApplyConfig(&cfg2) == XSTDNON && !file_has(sOrgCfgPath, "managedOrganizationId"),
            "-m with an empty value should take the allowance back");

        char *pSetArgv[] = { sArg0, sArgC, sOrgCfgPath, sArgM, sOrg, NULL };
        CHECK(DirectGate_ParseArgs(&cfg2, 5, pSetArgv) && DirectGate_ApplyConfig(&cfg2) == XSTDNON,
            "-m with an organization id on its own should succeed");
        CHECK(file_has(sOrgCfgPath, "\"managedOrganizationId\": \"" ORG_ID "\""), "and save the allowance");

        directgate_cfg_t reloaded;
        DirectGate_InitConfig(&reloaded);
        CHECK(DirectGate_LoadConfig(&reloaded, sOrgCfgPath) && !strcmp(reloaded.keyauth.sManagedOrgId, ORG_ID),
            "the allowance should load back from the config");

        /* The Manager's unticked box: pairing with an empty -m takes the allowance back and keeps the enrollment */
        char *pPairClearArgv[] = { sArg0, sArgC, sOrgCfgPath, sArgE, sArgT, sToken, sArgM, sEmpty, NULL };
        CHECK(DirectGate_ParseArgs(&cfg2, 8, pPairClearArgv) && cfg2.bSetManagedOrg && cfg2.keyauth.sManagedOrgId[0] == '\0',
            "a pairing with an empty -m should parse");
        fake_https_reply(&api, 200, "application/json", g_pOrgPairJson);
        CHECK(DirectGate_ApplyConfig(&cfg2) == XSTDNON, "a pairing with an empty -m should succeed");
        CHECK(!file_has(sOrgCfgPath, "managedOrganizationId") && file_has(sOrgCfgPath, "\"organizationId\": \"" ORG_ID "\""),
            "a pairing with an empty -m should take the allowance back and still record the organization");

        /* A typo fails before the pairing token is spent, and leaves the config alone */
        char *pBadArgv[] = { sArg0, sArgC, sPersonalCfgPath, sArgS, sArgE, sArgT, sToken, sArgM, sBad, NULL };
        int nRequests = fake_https_last(&api, NULL);
        CHECK(!DirectGate_ParseArgs(&cfg2, 9, pBadArgv), "an organization id that is not a UUID should be refused");
        CHECK(fake_https_last(&api, NULL) == nRequests && access(sPersonalCfgPath, F_OK) != 0,
            "a refused -m should make no request and write no config");

        /* A personal device: pairing without -m allows nothing, and a refresh naming an organization allows nothing */
        directgate_cfg_t personal;
        init_cfg(&personal, api.sUrl, sPersonalCfgPath);
        CHECK(DirectGate_AuthGenerateRecord(&personal.auth, "personal-password"), "an SRP record for the personal device");
        xstrncpy(personal.sPairingToken, sizeof(personal.sPairingToken), "pairing-token");
        personal.bEnroll = XTRUE;

        fake_https_reply(&api, 200, "application/json", g_pPairJson);
        CHECK(DirectGate_ApplyConfig(&personal) == XSTDNON, "a personal pairing should succeed");
        CHECK(!file_has(sPersonalCfgPath, "managedOrganizationId") && !file_has(sPersonalCfgPath, "organizationId"),
            "a personal pairing should record no organization and allow nothing");

        DirectGate_InitConfig(&personal);
        CHECK(DirectGate_LoadConfig(&personal, sPersonalCfgPath), "load the paired personal device");
        fake_https_reply(&api, 200, "application/json", g_pOrgRefreshJson);
        CHECK(DirectGate_Enroll_Refresh(&personal, sReason, sizeof(sReason)) == DIRECTGATE_ENROLL_REFRESH_OK,
            "a refresh naming an organization should succeed");
        CHECK(!strcmp(personal.enroll.sOrganizationId, ORG_ID) && personal.keyauth.sManagedOrgId[0] == '\0',
            "the organization the refresh names should be recorded without being allowed");

        unlink(sOrgCfgPath);
        unlink(sPersonalCfgPath);
    }

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

    /* A failed call reports the OS error its socket saved when the system call failed. A certificate the agent does
     * not trust ends the handshake with none, where errno read afterwards reported whatever an earlier call left. */
    xlog_init("enroll_api_smoke", XLOG_ALL, XTRUE);
    xlog_screen(XFALSE);
    xlog_callback(keep_failure, NULL);

    setenv("SSL_CERT_FILE", "/nonexistent/directgate-enroll-ca.pem", 1);
    errno = ENOENT;
    g_sFailure[0] = '\0';
    directgate_enroll_status_t eUntrusted = DirectGate_Enroll_Refresh(&cfg, sReason, sizeof(sReason));
    int bNoOsError = strstr(g_sFailure, "oserr(0/none)") != NULL;
    setenv("SSL_CERT_FILE", api.tls.sCert, 1);

    fake_https_end(&api);

    /* An API that is gone refuses the connection, and the failure says so */
    char sRefused[64];
    snprintf(sRefused, sizeof(sRefused), "oserr(%d/ECONNREFUSED/", ECONNREFUSED);
    g_sFailure[0] = '\0';
    directgate_enroll_status_t eGone = DirectGate_Enroll_Refresh(&cfg, sReason, sizeof(sReason));
    int bRefused = strstr(g_sFailure, sRefused) != NULL;
    xlog_destroy();

    CHECK(eUntrusted == DIRECTGATE_ENROLL_REFRESH_TRANSIENT, "an API the agent does not trust should be a transient failure");
    CHECK(bNoOsError, "and one with no OS error behind it");
    CHECK(eGone == DIRECTGATE_ENROLL_REFRESH_TRANSIENT, "an API that is gone should be a transient failure");
    CHECK(bRefused, "and the refused connection should be named");

    unlink(sCfgPath);
    unlink(sBlocker);
    rmdir(sRoot);

    puts("enroll_api_smoke: OK");
    return 0;
}
