#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "src/agent/config.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "config_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static int write_file(const char *pPath, const char *pData)
{
    FILE *pFile = fopen(pPath, "wb");
    if (pFile == NULL) return 0;

    size_t nLen = strlen(pData);
    int nOk = fwrite(pData, 1, nLen, pFile) == nLen;
    fclose(pFile);
    return nOk;
}

int main(void)
{
    const char *pSalt = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    char sRoot[] = "/tmp/directgate_config_smoke.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "mkdtemp root");

    char sConfigDir[512];
    snprintf(sConfigDir, sizeof(sConfigDir), "%s/.config", sRoot);
    CHECK(mkdir(sConfigDir, 0700) == 0, "mkdir .config");
    snprintf(sConfigDir, sizeof(sConfigDir), "%s/.config/directgate", sRoot);
    CHECK(mkdir(sConfigDir, 0700) == 0, "mkdir .config/directgate");

    char sDefaultPath[512];
    char sExplicitPath[512];
    char sKeyPath[512];
    char sMissingPath[512];
    snprintf(sDefaultPath, sizeof(sDefaultPath), "%s/.config/directgate/agent.json", sRoot);
    snprintf(sExplicitPath, sizeof(sExplicitPath), "%s/explicit-agent.json", sRoot);
    snprintf(sKeyPath, sizeof(sKeyPath), "%s/client-key.json", sRoot);
    snprintf(sMissingPath, sizeof(sMissingPath), "%s/missing-agent.json", sRoot);

    char sDefaultJson[1024];
    int nDefault = snprintf(sDefaultJson, sizeof(sDefaultJson),
        "{"
            "\"relayUrl\":\"wss://default.example.test/websock\","
            "\"routingKey\":\"default-routing-key\","
            "\"deviceId\":\"default-device\","
            "\"auth\":{\"srp\":{\"salt\":\"%s\",\"verifier\":\"abcd\"}},"
            "\"enrollment\":{"
                "\"apiUrl\":\"https://api.default.example.test\","
                "\"accessToken\":\"default-access\","
                "\"refreshToken\":\"default-refresh\","
                "\"enrolled\":true"
            "}"
        "}",
        pSalt);
    CHECK(nDefault > 0 && (size_t)nDefault < sizeof(sDefaultJson),
        "default JSON fits");
    CHECK(write_file(sDefaultPath, sDefaultJson), "write default config");

    char sExplicitJson[512];
    int nExplicit = snprintf(sExplicitJson, sizeof(sExplicitJson),
        "{"
            "\"deviceId\":\"explicit-device\","
            "\"auth\":{\"srp\":{\"salt\":\"%s\",\"verifier\":\"ef01\"}}"
        "}",
        pSalt);
    CHECK(nExplicit > 0 && (size_t)nExplicit < sizeof(sExplicitJson),
        "explicit JSON fits");
    CHECK(write_file(sExplicitPath, sExplicitJson), "write explicit config");

    CHECK(setenv("HOME", sRoot, 1) == 0, "set HOME");

    directgate_cfg_t cfg;
    char *pDefaultArgv[] = { "xagent", "-g", sKeyPath, NULL };
    CHECK(DirectGate_ParseArgs(&cfg, 3, pDefaultArgv),
        "default config parse");
    CHECK(cfg.bGenKey == XTRUE, "default parse genkey flag");
    CHECK(strcmp(cfg.sDeviceId, "default-device") == 0,
        "default config device");
    CHECK(strcmp(cfg.sRelayUrl, "wss://default.example.test/websock") == 0,
        "default config relay");
    CHECK(strcmp(cfg.sRoutingKey, "default-routing-key") == 0,
        "default config routing key");

    char *pExplicitArgv[] = { "xagent", "-c", sExplicitPath, "-g", sKeyPath, NULL };
    CHECK(DirectGate_ParseArgs(&cfg, 5, pExplicitArgv),
        "explicit config parse");
    CHECK(strcmp(cfg.sCfgPath, sExplicitPath) == 0,
        "explicit config path");
    CHECK(strcmp(cfg.sDeviceId, "explicit-device") == 0,
        "explicit config device");
    CHECK(cfg.sRelayUrl[0] == '\0',
        "explicit config must not inherit default relay");
    CHECK(cfg.sRoutingKey[0] == '\0',
        "explicit config must not inherit default routing key");
    CHECK(cfg.enroll.sAccessToken[0] == '\0',
        "explicit config must not inherit default access token");

    char sCompactConfigArg[1024];
    snprintf(sCompactConfigArg, sizeof(sCompactConfigArg), "-c%s", sExplicitPath);
    char *pCompactArgv[] = { "xagent", sCompactConfigArg, "-g", sKeyPath, NULL };
    CHECK(DirectGate_ParseArgs(&cfg, 4, pCompactArgv),
        "compact -c config parse");
    CHECK(strcmp(cfg.sCfgPath, sExplicitPath) == 0,
        "compact -c config path");
    CHECK(strcmp(cfg.sDeviceId, "explicit-device") == 0,
        "compact -c device");
    CHECK(cfg.sRelayUrl[0] == '\0',
        "compact -c must not inherit default relay");

    unlink(sDefaultPath);
    char *pEnrollArgv[] = { "xagent", "-e", "-d", "web-device", "-t", "setup-token", NULL };
    CHECK(DirectGate_ParseArgs(&cfg, 6, pEnrollArgv),
        "enroll with inline token should parse without existing config");
    CHECK(cfg.bEnroll == XTRUE, "enroll parse flag");
    CHECK(strcmp(cfg.sDeviceId, "web-device") == 0,
        "enroll parse device id");
    CHECK(strcmp(cfg.sPairingToken, "setup-token") == 0,
        "enroll parse pairing token");

    char sCwd[512];
    CHECK(getcwd(sCwd, sizeof(sCwd)) != NULL, "getcwd before relative config");
    CHECK(chdir(sRoot) == 0, "chdir relative config root");

    char *pRelativeEnrollArgv[] = {
        "xagent", "-sed", "relative-device", "-t", "setup-token", "-c", "test.conf", NULL
    };
    CHECK(DirectGate_ParseArgs(&cfg, 7, pRelativeEnrollArgv),
        "relative missing explicit config should parse for enrollment");
    CHECK(cfg.bEnroll == XTRUE, "relative enroll parse flag");
    CHECK(cfg.bSetSRP == XTRUE, "relative enroll set srp flag");
    CHECK(strcmp(cfg.sDeviceId, "relative-device") == 0,
        "relative enroll compact device id");
    CHECK(strcmp(cfg.sCfgPath, "test.conf") == 0,
        "relative enroll config path");

    CHECK(chdir(sCwd) == 0, "restore cwd after relative config");

    char *pCBeforeEnrollArgv[] = {
        "xagent", "-c", "test.conf", "-e", "-d", "relative-device", "-t", "setup-token", NULL
    };
    CHECK(chdir(sRoot) == 0, "chdir relative config root for reordered args");
    CHECK(DirectGate_ParseArgs(&cfg, 8, pCBeforeEnrollArgv),
        "relative missing explicit config should parse when -c comes before -e");
    CHECK(cfg.bEnroll == XTRUE, "reordered enroll parse flag");
    CHECK(strcmp(cfg.sCfgPath, "test.conf") == 0,
        "reordered enroll config path");
    CHECK(chdir(sCwd) == 0, "restore cwd after reordered relative config");

    char *pDashedTokenArgv[] = {
        "xagent", "-c", sMissingPath, "-t", "-evil-token", NULL
    };
    CHECK(!DirectGate_ParseArgs(&cfg, 5, pDashedTokenArgv),
        "option arguments beginning with -e must not enable missing config");

    char *pMissingArgv[] = { "xagent", "-c", sMissingPath, "-g", sKeyPath, NULL };
    CHECK(!DirectGate_ParseArgs(&cfg, 5, pMissingArgv),
        "explicit missing config must fail");

    char *pMissingValueArgv[] = { "xagent", "-c", NULL };
    CHECK(!DirectGate_ParseArgs(&cfg, 2, pMissingValueArgv),
        "missing -c value must fail");

    /* -m alone saves into an existing config: missing, it is refused rather than starting from an empty one */
    char *pManagedMissingArgv[] = { "xagent", "-c", sMissingPath, "-m", "11111111-2222-3333-4444-555555555555", NULL };
    CHECK(!DirectGate_ParseArgs(&cfg, 5, pManagedMissingArgv), "-m with a missing explicit config must fail");

    /* The organization id is checked as a UUID and kept in lowercase, the way the API reports it */
    char *pManagedUpperArgv[] = { "xagent", "-c", sMissingPath, "-e", "-m", "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE", NULL };
    CHECK(DirectGate_ParseArgs(&cfg, 6, pManagedUpperArgv) && cfg.bSetManagedOrg &&
        !strcmp(cfg.keyauth.sManagedOrgId, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"), "-m should normalize the id to lowercase");

    static const char *pBadOrgIds[] = {
        "11111111-2222-3333-4444-55555555555",
        "11111111-2222-3333-4444-5555555555555",
        "11111111+2222-3333-4444-555555555555",
        "1111111g-2222-3333-4444-555555555555",
        "111111112222333344445555555555555555"
    };

    for (size_t i = 0; i < sizeof(pBadOrgIds) / sizeof(pBadOrgIds[0]); i++)
    {
        char *pBadArgv[] = { "xagent", "-c", sMissingPath, "-e", "-m", (char*)pBadOrgIds[i], NULL };
        CHECK(!DirectGate_ParseArgs(&cfg, 6, pBadArgv), "an -m value that is not a UUID must fail");
    }

    /* The managed-key allowance only loads whole: one that does not fit is dropped, never cut into another id */
    char sManagedPath[600];
    char sManagedJson[XSTR_TINY + 256];
    char sLongOrg[XSTR_TINY + 16];
    memset(sLongOrg, 'o', sizeof(sLongOrg) - 1);
    sLongOrg[sizeof(sLongOrg) - 1] = '\0';
    snprintf(sManagedPath, sizeof(sManagedPath), "%s/managed.json", sRoot);

    snprintf(sManagedJson, sizeof(sManagedJson), "{\"auth\":{\"key\":{\"managedOrganizationId\":\"org-a\"}}}");
    CHECK(write_file(sManagedPath, sManagedJson), "write a config with a managed-key allowance");
    DirectGate_InitConfig(&cfg);
    CHECK(DirectGate_LoadConfig(&cfg, sManagedPath) && !strcmp(cfg.keyauth.sManagedOrgId, "org-a"),
        "a managed-key allowance should load");

    snprintf(sManagedJson, sizeof(sManagedJson), "{\"auth\":{\"key\":{\"managedOrganizationId\":\"%s\"}}}", sLongOrg);
    CHECK(write_file(sManagedPath, sManagedJson), "write a config with an oversized managed-key allowance");
    DirectGate_InitConfig(&cfg);
    CHECK(DirectGate_LoadConfig(&cfg, sManagedPath) && cfg.keyauth.sManagedOrgId[0] == '\0',
        "an oversized managed-key allowance should be dropped, not truncated");
    unlink(sManagedPath);

    unlink(sExplicitPath);
    unlink(sKeyPath);
    rmdir(sConfigDir);
    snprintf(sConfigDir, sizeof(sConfigDir), "%s/.config", sRoot);
    rmdir(sConfigDir);
    rmdir(sRoot);

    puts("config_smoke: OK");
    return 0;
}
