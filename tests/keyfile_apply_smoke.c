#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "src/common/keyauth.h"
#include "src/agent/config.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "keyfile_apply_smoke: %s\n", msg); \
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

static int check_key_file(const char *pPath, char *pPubOut, size_t nPubOutSize)
{
    xbyte_buffer_t buffer;
    CHECK(XPath_LoadBuffer(pPath, &buffer) > 0, "load generated key file");

    xjson_t json;
    CHECK(XJSON_Parse(&json, NULL, (const char*)buffer.pData, buffer.nUsed),
        "generated key file should be JSON");

    xjson_obj_t *pRoot = json.pRootObj;
    CHECK(strcmp(XJSON_GetString(XJSON_GetObject(pRoot, "type")),
        "directgate-client-key-v2") == 0, "generated key type");

    const char *pPub = XJSON_GetString(XJSON_GetObject(pRoot, "clientPub"));
    const char *pSeed = XJSON_GetString(XJSON_GetObject(pRoot, "clientSeed"));
    CHECK(xstrused(pPub), "generated key should contain clientPub");
    CHECK(xstrused(pSeed), "generated key should contain clientSeed");

    uint8_t raw[DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE];
    size_t nRawLen = 0;
    CHECK(DirectGate_KeyAuth_Base64Decode(pPub, raw, sizeof(raw), &nRawLen),
        "clientPub should decode");
    CHECK(nRawLen == DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE,
        "clientPub decoded length");
    CHECK(DirectGate_KeyAuth_Base64Decode(pSeed, raw, sizeof(raw), &nRawLen),
        "clientSeed should decode");
    CHECK(nRawLen == DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE,
        "clientSeed decoded length");

    xstrncpy(pPubOut, nPubOutSize, pPub);
    XJSON_Destroy(&json);
    XByteBuffer_Clear(&buffer);
    return 0;
}

int main(void)
{
    char sRoot[] = "/tmp/directgate_agent_keyfile_apply.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "mkdtemp root");

    char sCfgPath[512];
    char sCfgPath2[512];
    char sKeyPath[512];
    char sBadKeyPath[512];
    char sMissingKeyPath[512];
    snprintf(sCfgPath, sizeof(sCfgPath), "%s/agent.json", sRoot);
    snprintf(sCfgPath2, sizeof(sCfgPath2), "%s/agent2.json", sRoot);
    snprintf(sKeyPath, sizeof(sKeyPath), "%s/keys/client.json", sRoot);
    snprintf(sBadKeyPath, sizeof(sBadKeyPath), "%s/bad-key.json", sRoot);
    snprintf(sMissingKeyPath, sizeof(sMissingKeyPath), "%s/missing-key.json", sRoot);

    directgate_cfg_t cfg;
    DirectGate_InitConfig(&cfg);
    xstrncpy(cfg.sCfgPath, sizeof(cfg.sCfgPath), sCfgPath);
    xstrncpy(cfg.sGenKeyPath, sizeof(cfg.sGenKeyPath), sKeyPath);
    xstrncpy(cfg.sDeviceId, sizeof(cfg.sDeviceId), "keyfile-device");
    cfg.bGenKey = XTRUE;

    CHECK(DirectGate_ApplyConfig(&cfg) == XSTDNON,
        "genkey apply should perform one-shot action");
    CHECK(access(sCfgPath, F_OK) == 0, "genkey should save agent config");
    CHECK(access(sKeyPath, F_OK) == 0, "genkey should write client key");

    struct stat st;
    CHECK(stat(sKeyPath, &st) == 0, "stat generated key");
    CHECK((st.st_mode & 0777) == 0600, "generated key permissions should be 0600");

    char sClientPub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    CHECK(check_key_file(sKeyPath, sClientPub, sizeof(sClientPub)) == 0,
        "validate generated key file");

    directgate_cfg_t loaded;
    DirectGate_InitConfig(&loaded);
    xstrncpy(loaded.sCfgPath, sizeof(loaded.sCfgPath), sCfgPath);
    CHECK(DirectGate_LoadConfig(&loaded, sCfgPath), "load generated agent config");
    CHECK(xstrused(loaded.keyauth.sIdentitySeedB64),
        "genkey should create agent identity seed");
    CHECK(xstrused(loaded.keyauth.sIdentityPubB64),
        "genkey should create agent identity pub");
    CHECK(loaded.keyauth.nAuthorizedKeyCount == 1,
        "genkey should authorize generated client key");
    CHECK(strcmp(loaded.keyauth.sAuthorizedKeys[0], sClientPub) == 0,
        "generated client pub should be authorized");

    CHECK(DirectGate_ApplyConfig(&cfg) == XSTDERR,
        "genkey should not overwrite an existing key file");

    directgate_cfg_t enrollCfg;
    DirectGate_InitConfig(&enrollCfg);
    xstrncpy(enrollCfg.sCfgPath, sizeof(enrollCfg.sCfgPath), sCfgPath2);
    xstrncpy(enrollCfg.sEnrollKeyPath, sizeof(enrollCfg.sEnrollKeyPath), sKeyPath);
    xstrncpy(enrollCfg.sDeviceId, sizeof(enrollCfg.sDeviceId), "keyfile-device-2");
    enrollCfg.bEnrollKey = XTRUE;
    CHECK(DirectGate_ApplyConfig(&enrollCfg) == XSTDNON,
        "enroll-key apply should perform one-shot action");

    directgate_cfg_t loaded2;
    DirectGate_InitConfig(&loaded2);
    xstrncpy(loaded2.sCfgPath, sizeof(loaded2.sCfgPath), sCfgPath2);
    CHECK(DirectGate_LoadConfig(&loaded2, sCfgPath2), "load enrolled agent config");
    CHECK(loaded2.keyauth.nAuthorizedKeyCount == 1,
        "enroll-key should authorize existing client key");
    CHECK(strcmp(loaded2.keyauth.sAuthorizedKeys[0], sClientPub) == 0,
        "enroll-key should store existing client pub");

    CHECK(write_file(sBadKeyPath,
        "{\"type\":\"wrong\",\"clientPub\":\"abc\",\"clientSeed\":\"def\"}"),
        "write bad key file");
    directgate_cfg_t badCfg;
    DirectGate_InitConfig(&badCfg);
    char sBadAgentPath[512];
    snprintf(sBadAgentPath, sizeof(sBadAgentPath), "%s/bad-agent.json", sRoot);
    xstrncpy(badCfg.sCfgPath, sizeof(badCfg.sCfgPath), sBadAgentPath);
    xstrncpy(badCfg.sEnrollKeyPath, sizeof(badCfg.sEnrollKeyPath), sBadKeyPath);
    badCfg.bEnrollKey = XTRUE;
    CHECK(DirectGate_ApplyConfig(&badCfg) == XSTDERR,
        "wrong key file type should fail enroll-key");

    directgate_cfg_t missingCfg;
    DirectGate_InitConfig(&missingCfg);
    xstrncpy(missingCfg.sCfgPath, sizeof(missingCfg.sCfgPath), sCfgPath);
    xstrncpy(missingCfg.sEnrollKeyPath, sizeof(missingCfg.sEnrollKeyPath), sMissingKeyPath);
    missingCfg.bEnrollKey = XTRUE;
    CHECK(DirectGate_ApplyConfig(&missingCfg) == XSTDERR,
        "missing key file should fail enroll-key");

    /* With every authorized slot taken, no further key is authorized, and a generated one is not even written */
    directgate_cfg_t fullCfg;
    DirectGate_InitConfig(&fullCfg);
    xstrncpy(fullCfg.sCfgPath, sizeof(fullCfg.sCfgPath), sCfgPath2);
    xstrncpy(fullCfg.sDeviceId, sizeof(fullCfg.sDeviceId), "keyfile-device-full");
    for (int i = 0; i < DIRECTGATE_MAX_AUTHORIZED_KEYS; i++)
    {
        uint8_t raw[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
        memset(raw, i + 1, sizeof(raw));
        CHECK(DirectGate_KeyAuth_Base64Encode(raw, sizeof(raw), fullCfg.keyauth.sAuthorizedKeys[i],
            sizeof(fullCfg.keyauth.sAuthorizedKeys[i])), "fill an authorized slot");
    }
    fullCfg.keyauth.nAuthorizedKeyCount = DIRECTGATE_MAX_AUTHORIZED_KEYS;

    fullCfg.bEnrollKey = XTRUE;
    xstrncpy(fullCfg.sEnrollKeyPath, sizeof(fullCfg.sEnrollKeyPath), sKeyPath);
    CHECK(DirectGate_ApplyConfig(&fullCfg) == XSTDERR, "a full authorized list should refuse an existing key");

    char sFullKeyPath[512];
    snprintf(sFullKeyPath, sizeof(sFullKeyPath), "%s/full-key.json", sRoot);
    fullCfg.bEnrollKey = XFALSE;
    fullCfg.bGenKey = XTRUE;
    xstrncpy(fullCfg.sGenKeyPath, sizeof(fullCfg.sGenKeyPath), sFullKeyPath);
    CHECK(DirectGate_ApplyConfig(&fullCfg) == XSTDERR && access(sFullKeyPath, F_OK) != 0,
        "a full authorized list should refuse a new key and not write it");

    /* A key that cannot be persisted as authorized is not reported as authorized */
    char sBlocker[512], sBlockedCfg[600];
    snprintf(sBlocker, sizeof(sBlocker), "%s/blocker", sRoot);
    snprintf(sBlockedCfg, sizeof(sBlockedCfg), "%s/agent.json", sBlocker);
    CHECK(write_file(sBlocker, "not a directory"), "create a file where a directory should be");

    directgate_cfg_t blockedCfg;
    DirectGate_InitConfig(&blockedCfg);
    xstrncpy(blockedCfg.sCfgPath, sizeof(blockedCfg.sCfgPath), sBlockedCfg);
    xstrncpy(blockedCfg.sDeviceId, sizeof(blockedCfg.sDeviceId), "keyfile-device-blocked");
    xstrncpy(blockedCfg.sEnrollKeyPath, sizeof(blockedCfg.sEnrollKeyPath), sKeyPath);
    blockedCfg.bEnrollKey = XTRUE;
    CHECK(DirectGate_ApplyConfig(&blockedCfg) == XSTDERR, "an authorization that cannot be saved should fail");

    blockedCfg.bEnrollKey = XFALSE;
    blockedCfg.bGenKey = XTRUE;
    xstrncpy(blockedCfg.sGenKeyPath, sizeof(blockedCfg.sGenKeyPath), sFullKeyPath);
    CHECK(DirectGate_ApplyConfig(&blockedCfg) == XSTDERR && access(sFullKeyPath, F_OK) != 0,
        "a generated key whose authorization cannot be saved should not be written");

    /* Rotating the agent identity needs the API, the device and a live enrollment */
    directgate_cfg_t rotateCfg;
    DirectGate_InitConfig(&rotateCfg);
    xstrncpy(rotateCfg.sCfgPath, sizeof(rotateCfg.sCfgPath), sCfgPath);
    rotateCfg.bRotateAgentKey = XTRUE;
    rotateCfg.enroll.sApiUrl[0] = '\0';
    CHECK(DirectGate_ApplyConfig(&rotateCfg) == XSTDERR, "a rotation without an API should fail");
    xstrncpy(rotateCfg.enroll.sApiUrl, sizeof(rotateCfg.enroll.sApiUrl), "https://api.example.test");
    rotateCfg.sDeviceId[0] = '\0';
    CHECK(DirectGate_ApplyConfig(&rotateCfg) == XSTDERR, "a rotation without a device should fail");
    xstrncpy(rotateCfg.sDeviceId, sizeof(rotateCfg.sDeviceId), "keyfile-device");
    CHECK(DirectGate_ApplyConfig(&rotateCfg) == XSTDERR, "a rotation without an enrollment should fail");
    CHECK(DirectGate_ApplyConfig(NULL) == XSTDERR, "nothing is applied without a config");
    unlink(sBlocker);

    unlink(sCfgPath);
    unlink(sCfgPath2);
    unlink(sKeyPath);
    unlink(sBadKeyPath);
    char sKeysDir[512];
    snprintf(sKeysDir, sizeof(sKeysDir), "%s/keys", sRoot);
    rmdir(sKeysDir);
    rmdir(sRoot);

    puts("keyfile_apply_smoke: OK");
    return 0;
}
