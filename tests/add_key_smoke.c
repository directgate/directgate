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
            fprintf(stderr, "add_key_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static int build_test_pubkey_b64(char *pOut, size_t nOutSize, uint8_t nSeed)
{
    uint8_t raw[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    for (size_t i = 0; i < sizeof(raw); i++) raw[i] = (uint8_t)(nSeed + i);
    return DirectGate_KeyAuth_Base64Encode(raw, sizeof(raw), pOut, nOutSize) ? 0 : 1;
}

/* ---- scopes: what a key may open, as names and as JSON ---- */
static int test_scopes(void)
{
    uint8_t nScope = 0xFF;
    CHECK(DirectGate_KeyScope_Parse("exec", &nScope) && nScope == DIRECTGATE_KEY_SCOPE_EXEC, "one mode");
    CHECK(DirectGate_KeyScope_Parse("desktop,exec,files,terminal", &nScope) &&
        nScope == (DIRECTGATE_KEY_SCOPE_EXEC | DIRECTGATE_KEY_SCOPE_FILES | DIRECTGATE_KEY_SCOPE_TERMINAL |
                   DIRECTGATE_KEY_SCOPE_DESKTOP), "every mode, in any order");
    CHECK(DirectGate_KeyScope_Parse("full", &nScope) && nScope == DIRECTGATE_KEY_SCOPE_FULL, "full alone");

    const char *pBad[] = { "", ",", "exec,", ",exec", "exec,exec", "full,exec", "exec,full", "admin", "Exec", "exec files",
                           "files,terminal,nope" };
    for (size_t i = 0; i < sizeof(pBad) / sizeof(pBad[0]); i++)
    {
        nScope = 0x5A;
        CHECK(!DirectGate_KeyScope_Parse(pBad[i], &nScope) && nScope == 0x5A, "a list that is no scope is refused, untouched");
    }
    CHECK(!DirectGate_KeyScope_Parse(NULL, &nScope) && !DirectGate_KeyScope_Parse("exec", NULL), "nothing to read or keep");

    char sOut[64];
    CHECK(DirectGate_KeyScope_Format(DIRECTGATE_KEY_SCOPE_FULL, sOut, sizeof(sOut)) == 4 && !strcmp(sOut, "full"), "full");
    CHECK(DirectGate_KeyScope_Format(DIRECTGATE_KEY_SCOPE_DESKTOP | DIRECTGATE_KEY_SCOPE_EXEC, sOut, sizeof(sOut)) == 12 &&
        !strcmp(sOut, "exec,desktop"), "the modes in their fixed order");
    CHECK(DirectGate_KeyScope_Format(DIRECTGATE_KEY_SCOPE_EXEC | DIRECTGATE_KEY_SCOPE_FILES, sOut, 7) == 6 &&
        !strcmp(sOut, "exec,f"), "cut short, never past the buffer");
    CHECK(DirectGate_KeyScope_Format(DIRECTGATE_KEY_SCOPE_EXEC, NULL, 8) == 0, "no buffer, nothing written");

    /* As JSON, read back the way the agent reads add-key and agent.json */
    const char *pJson[] = { "{\"s\":[\"files\",\"terminal\"]}", "{\"s\":[\"full\"]}" };
    uint8_t nWant[] = { DIRECTGATE_KEY_SCOPE_FILES | DIRECTGATE_KEY_SCOPE_TERMINAL, DIRECTGATE_KEY_SCOPE_FULL };
    for (size_t i = 0; i < 2; i++)
    {
        xjson_t json;
        CHECK(XJSON_Parse(&json, NULL, pJson[i], strlen(pJson[i])), "parse a scope");
        CHECK(DirectGate_KeyScope_FromJson(XJSON_GetObject(json.pRootObj, "s"), &nScope) && nScope == nWant[i],
            "a scope read from JSON");

        xjson_obj_t *pOut = XJSON_NewObject(NULL, NULL, XFALSE);
        CHECK(pOut != NULL && DirectGate_KeyScope_AddJson(pOut, "s", nScope), "write it back");
        uint8_t nBack = 0xFF;
        CHECK(DirectGate_KeyScope_FromJson(XJSON_GetObject(pOut, "s"), &nBack) && nBack == nScope, "and it reads the same");
        XJSON_FreeObject(pOut);
        XJSON_Destroy(&json);
    }

    const char *pBadJson[] = { "{\"s\":[]}", "{\"s\":\"exec\"}", "{\"s\":[1]}", "{\"s\":[\"exec\",\"exec\"]}",
                               "{\"s\":[\"full\",\"exec\"]}", "{\"s\":[\"root\"]}", "{\"s\":{}}" };
    for (size_t i = 0; i < sizeof(pBadJson) / sizeof(pBadJson[0]); i++)
    {
        xjson_t json;
        CHECK(XJSON_Parse(&json, NULL, pBadJson[i], strlen(pBadJson[i])), "parse a bad scope");
        CHECK(!DirectGate_KeyScope_FromJson(XJSON_GetObject(json.pRootObj, "s"), &nScope), "a bad scope is no scope");
        XJSON_Destroy(&json);
    }
    CHECK(!DirectGate_KeyScope_FromJson(NULL, &nScope), "no scope at all is not one either");
    CHECK(!DirectGate_KeyScope_AddJson(NULL, "s", 0) && !DirectGate_KeyScope_AddJson(NULL, NULL, 0), "nowhere to add it");

    /* Labels: text for people, never a control character in any spelling */
    char sLong[DIRECTGATE_KEY_LABEL_MAX + 2];
    memset(sLong, 'a', sizeof(sLong));
    sLong[DIRECTGATE_KEY_LABEL_MAX] = '\0';
    CHECK(DirectGate_KeyLabel_IsValid(sLong), "a label of the most bytes allowed");
    sLong[DIRECTGATE_KEY_LABEL_MAX] = 'a';
    sLong[DIRECTGATE_KEY_LABEL_MAX + 1] = '\0';
    CHECK(!DirectGate_KeyLabel_IsValid(sLong), "one byte more is too long");
    CHECK(DirectGate_KeyLabel_IsValid("") && DirectGate_KeyLabel_IsValid("claude on the laptop") &&
        DirectGate_KeyLabel_IsValid("\xe1\x83\x9a\xe1\x83\x90\xe1\x83\x9e\xe1\x83\xa2\xe1\x83\x9d\xe1\x83\x9e\xe1\x83\x98") &&
        DirectGate_KeyLabel_IsValid("\xf0\x9f\x94\x91 key"), "ascii and UTF-8 text");

    /* Right next to each refused range: the last and first characters that are still text */
    const char *pEdgeLabels[] = { "nbsp\xc2\xa0", "u800 \xe0\xa0\x80", "ud7ff \xed\x9f\xbf", "u10000 \xf0\x90\x80\x80",
                                  "u10ffff \xf4\x8f\xbf\xbf", "u2027 \xe2\x80\xa7", "u202f \xe2\x80\xaf",
                                  "u2065 \xe2\x81\xa5", "u206a \xe2\x81\xaa" };
    for (size_t i = 0; i < sizeof(pEdgeLabels) / sizeof(pEdgeLabels[0]); i++)
        CHECK(DirectGate_KeyLabel_IsValid(pEdgeLabels[i]), "text right next to a refused range is a label");

    const char *pBadLabels[] = { "a\x1b]52;c;eA==\x07", "tab\there", "new\nline", "del\x7f", "c1\xc2\x9b", "lone\x9b",
                                 "cut\xe1\x83", "lead\xc3", "over\xc0\x9b", "over\xe0\x82\x9b", "over\xf0\x80\x82\x9b",
                                 "big\xf5\x80\x80\x80", "five\xf8\x88\x80\x80\x80", "bad\xc3\x28",
                                 "surrogate \xed\xa0\x80", "surrogate \xed\xbf\xbf", "past \xf4\x90\x80\x80",
                                 "line \xe2\x80\xa8", "rlo \xe2\x80\xae", "lri \xe2\x81\xa6", "pdi \xe2\x81\xa9" };
    for (size_t i = 0; i < sizeof(pBadLabels) / sizeof(pBadLabels[0]); i++)
        CHECK(!DirectGate_KeyLabel_IsValid(pBadLabels[i]), "a label with a control character or broken UTF-8 is refused");
    CHECK(!DirectGate_KeyLabel_IsValid(NULL), "no label is not a valid one");
    return 0;
}

/* ---- keys with a scope and a label, on the list and on disk ---- */
static int test_scoped_keys(const char *pPath, const char *pKey1, const char *pKey2)
{
    directgate_cfg_t cfg;
    DirectGate_InitConfig(&cfg);
    xstrncpy(cfg.sCfgPath, sizeof(cfg.sCfgPath), pPath);

    char sKey3[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    CHECK(build_test_pubkey_b64(sKey3, sizeof(sKey3), 77) == 0, "a third key");

    /* A full key as -a adds it, a scoped one with a label, a scoped one without */
    CHECK(DirectGate_AddAuthorizedKey(&cfg, pKey1) == DIRECTGATE_ADD_KEY_ADDED, "a full key");
    CHECK(DirectGate_PutAuthorizedKey(&cfg, pKey2, XTRUE, DIRECTGATE_KEY_SCOPE_EXEC | DIRECTGATE_KEY_SCOPE_FILES,
        "claude on the laptop", 1795400000ULL) == DIRECTGATE_ADD_KEY_ADDED, "a scoped key with a label");
    CHECK(DirectGate_PutAuthorizedKey(&cfg, sKey3, XTRUE, DIRECTGATE_KEY_SCOPE_DESKTOP, NULL, 0) == DIRECTGATE_ADD_KEY_ADDED,
        "a scoped key without one");
    CHECK(cfg.keyauth.nAuthorizedKeyScopes[0] == DIRECTGATE_KEY_SCOPE_FULL && cfg.keyauth.nAuthorizedKeyAdded[0] > 0 &&
        cfg.keyauth.nAuthorizedKeyScopes[1] == (DIRECTGATE_KEY_SCOPE_EXEC | DIRECTGATE_KEY_SCOPE_FILES) &&
        !strcmp(cfg.keyauth.sAuthorizedKeyLabels[1], "claude on the laptop") &&
        cfg.keyauth.nAuthorizedKeyAdded[1] == 1795400000ULL, "each kept with what it was given");

    /* Only what a request names changes: left out, a scope neither widens nor narrows */
    CHECK(DirectGate_AddAuthorizedKey(&cfg, pKey2) == DIRECTGATE_ADD_KEY_ALREADY &&
        cfg.keyauth.nAuthorizedKeyScopes[1] == (DIRECTGATE_KEY_SCOPE_EXEC | DIRECTGATE_KEY_SCOPE_FILES),
        "a key added again without a scope keeps its own");
    CHECK(DirectGate_PutAuthorizedKey(&cfg, pKey2, XTRUE, DIRECTGATE_KEY_SCOPE_EXEC | DIRECTGATE_KEY_SCOPE_FILES,
        "claude on the laptop", 1) == DIRECTGATE_ADD_KEY_ALREADY && cfg.keyauth.nAuthorizedKeyAdded[1] == 1795400000ULL,
        "the same scope and label again change nothing, the time it came included");
    CHECK(DirectGate_PutAuthorizedKey(&cfg, pKey2, XTRUE, DIRECTGATE_KEY_SCOPE_EXEC, NULL, 1) == DIRECTGATE_ADD_KEY_UPDATED &&
        cfg.keyauth.nAuthorizedKeyScopes[1] == DIRECTGATE_KEY_SCOPE_EXEC &&
        !strcmp(cfg.keyauth.sAuthorizedKeyLabels[1], "claude on the laptop"), "a new scope narrows it, the label stays");
    CHECK(DirectGate_PutAuthorizedKey(&cfg, pKey2, XFALSE, 0, "ci runner", 1) == DIRECTGATE_ADD_KEY_UPDATED &&
        !strcmp(cfg.keyauth.sAuthorizedKeyLabels[1], "ci runner") &&
        cfg.keyauth.nAuthorizedKeyScopes[1] == DIRECTGATE_KEY_SCOPE_EXEC, "a new label renames it, the scope stays");
    CHECK(DirectGate_PutAuthorizedKey(&cfg, sKey3, XFALSE, 0, "", 1) == DIRECTGATE_ADD_KEY_ALREADY,
        "an empty label on a key without one changes nothing");
    CHECK(DirectGate_PutAuthorizedKey(&cfg, pKey1, XTRUE, DIRECTGATE_KEY_SCOPE_FULL, NULL, 1) == DIRECTGATE_ADD_KEY_ALREADY,
        "full again on a full key changes nothing");
    CHECK(DirectGate_PutAuthorizedKey(&cfg, pKey2, XFALSE, 0, "bad\x1b[2J", 1) == DIRECTGATE_ADD_KEY_INVALID &&
        !strcmp(cfg.keyauth.sAuthorizedKeyLabels[1], "ci runner"), "a label that is not text is refused, nothing changed");
    CHECK(DirectGate_PutAuthorizedKey(&cfg, "short", XTRUE, DIRECTGATE_KEY_SCOPE_EXEC, NULL, 1) == DIRECTGATE_ADD_KEY_INVALID &&
        DirectGate_PutAuthorizedKey(NULL, pKey1, XFALSE, 0, NULL, 1) == DIRECTGATE_ADD_KEY_INVALID, "no key, no list");

    char sLong[DIRECTGATE_KEYAUTH_PUB_B64_SIZE + 8];
    memset(sLong, 'A', sizeof(sLong) - 1);
    sLong[sizeof(sLong) - 1] = '\0';
    CHECK(DirectGate_PutAuthorizedKey(&cfg, sLong, XFALSE, 0, NULL, 1) == DIRECTGATE_ADD_KEY_INVALID, "a key too long to hold");

    /* Found by the key it decodes to */
    CHECK(DirectGate_FindAuthorizedKey(&cfg, pKey1) == 0 && DirectGate_FindAuthorizedKey(&cfg, pKey2) == 1 &&
        DirectGate_FindAuthorizedKey(&cfg, sKey3) == 2, "each key is where it was put");
    CHECK(DirectGate_FindAuthorizedKey(&cfg, "nope") < 0 && DirectGate_FindAuthorizedKey(&cfg, NULL) < 0 &&
        DirectGate_FindAuthorizedKey(NULL, pKey1) < 0, "nothing found for a malformed key or no list");

    /* On disk: a full key is the bare key an older agent reads; a scoped one is an object it skips */
    CHECK(DirectGate_SaveConfig(&cfg), "save the keys");
    xbyte_buffer_t saved;
    XByteBuffer_Init(&saved, 0, XFALSE);
    CHECK(XPath_LoadBuffer(pPath, &saved) > 0, "read the saved config");
    xjson_t json;
    CHECK(XJSON_Parse(&json, NULL, (const char*)saved.pData, saved.nUsed), "parse it");
    xjson_obj_t *pKeyAuth = XJSON_GetObject(XJSON_GetObject(json.pRootObj, "auth"), "key");
    xjson_obj_t *pKeys = XJSON_GetObject(pKeyAuth, "authorizedKeys");
    xjson_obj_t *pDetails = XJSON_GetObject(pKeyAuth, "keyDetails");
    CHECK(pKeys != NULL && XJSON_GetArrayLength(pKeys) == 3 &&
        !strcmp(XJSON_GetString(XJSON_GetArrayItem(pKeys, 0)), pKey1), "the full key stays a bare key, rolled back or not");

    xjson_obj_t *pScoped = XJSON_GetArrayItem(pKeys, 1);
    uint8_t nScope = 0;
    CHECK(pScoped != NULL && pScoped->nType == XJSON_TYPE_OBJECT && !xstrused(XJSON_GetString(pScoped)) &&
        !strcmp(XJSON_GetString(XJSON_GetObject(pScoped, "key")), pKey2) &&
        DirectGate_KeyScope_FromJson(XJSON_GetObject(pScoped, "scope"), &nScope) && nScope == DIRECTGATE_KEY_SCOPE_EXEC,
        "a scoped key is an object an older agent cannot take for a bare key");
    CHECK(XJSON_GetObject(pScoped, "label") == NULL, "nothing else of it is in the list itself");

    xjson_obj_t *pDetail = XJSON_GetObject(pDetails, pKey2);
    CHECK(pDetails != NULL && pDetail != NULL && !strcmp(XJSON_GetString(XJSON_GetObject(pDetail, "label")), "ci runner") &&
        XJSON_GetU64(XJSON_GetObject(pDetail, "added")) == 1795400000ULL, "its label and the time it came are beside it");
    CHECK(XJSON_GetObject(pDetails, sKey3) == NULL, "a key with neither has no details");
    CHECK(XJSON_GetObject(pDetails, pKey1) != NULL && XJSON_GetObject(XJSON_GetObject(pDetails, pKey1), "label") == NULL,
        "a full key keeps only when it came");
    XJSON_Destroy(&json);
    XByteBuffer_Clear(&saved);

    directgate_cfg_t reloaded;
    DirectGate_InitConfig(&reloaded);
    CHECK(DirectGate_LoadConfig(&reloaded, pPath) && reloaded.keyauth.nAuthorizedKeyCount == 3, "reload the keys");
    CHECK(reloaded.keyauth.nAuthorizedKeyScopes[0] == DIRECTGATE_KEY_SCOPE_FULL &&
        reloaded.keyauth.nAuthorizedKeyScopes[1] == DIRECTGATE_KEY_SCOPE_EXEC &&
        reloaded.keyauth.nAuthorizedKeyScopes[2] == DIRECTGATE_KEY_SCOPE_DESKTOP &&
        !strcmp(reloaded.keyauth.sAuthorizedKeyLabels[1], "ci runner") && reloaded.keyauth.sAuthorizedKeyLabels[2][0] == '\0' &&
        reloaded.keyauth.nAuthorizedKeyAdded[1] == 1795400000ULL && reloaded.keyauth.nAuthorizedKeyAdded[2] == 0,
        "every key reloads with its scope, label and time");

    /* Removed: the rest move up, the slot it leaves is empty */
    CHECK(DirectGate_RemoveAuthorizedKey(&reloaded, pKey2) && reloaded.keyauth.nAuthorizedKeyCount == 2 &&
        !strcmp(reloaded.keyauth.sAuthorizedKeys[1], sKey3) &&
        reloaded.keyauth.nAuthorizedKeyScopes[1] == DIRECTGATE_KEY_SCOPE_DESKTOP &&
        reloaded.keyauth.sAuthorizedKeys[2][0] == '\0' && reloaded.keyauth.sAuthorizedKeyLabels[2][0] == '\0' &&
        reloaded.keyauth.nAuthorizedKeyScopes[2] == DIRECTGATE_KEY_SCOPE_FULL && reloaded.keyauth.nAuthorizedKeyAdded[2] == 0,
        "a removed key leaves no gap and nothing of itself");
    CHECK(DirectGate_FindAuthorizedKey(&reloaded, pKey2) < 0 && !DirectGate_RemoveAuthorizedKey(&reloaded, pKey2),
        "a removed key is gone, and removing it again does nothing");
    CHECK(DirectGate_RemoveAuthorizedKey(&reloaded, sKey3) && DirectGate_RemoveAuthorizedKey(&reloaded, pKey1) &&
        reloaded.keyauth.nAuthorizedKeyCount == 0, "the last ones go too");

    /* A scope this agent cannot read leaves the key out - never in with more than it was given */
    char sJson[1024];
    int nLen = snprintf(sJson, sizeof(sJson), "{\"auth\":{\"key\":{\"authorizedKeys\":[\"%s\",{\"key\":\"%s\",\"scope\":"
        "[\"exec\",\"admin\"]},{\"key\":\"%s\",\"scope\":[\"files\"]},{\"scope\":[\"exec\"]},{\"key\":7},42],"
        "\"keyDetails\":{\"%s\":{\"label\":\"bad\\u001b[2J\",\"added\":5},\"%s\":[]}}}}", pKey1, pKey2, sKey3, sKey3, pKey1);
    CHECK(nLen > 0 && (size_t)nLen < sizeof(sJson) && XPath_Write(pPath, (uint8_t*)sJson, (size_t)nLen, "cwt") > 0,
        "write a config with entries this agent must not take");

    directgate_cfg_t mixed;
    DirectGate_InitConfig(&mixed);
    CHECK(DirectGate_LoadConfig(&mixed, pPath), "load it");
    CHECK(mixed.keyauth.nAuthorizedKeyCount == 2 && !strcmp(mixed.keyauth.sAuthorizedKeys[0], pKey1) &&
        !strcmp(mixed.keyauth.sAuthorizedKeys[1], sKey3), "a key with a scope it does not know is left out, and the malformed");
    CHECK(mixed.keyauth.nAuthorizedKeyScopes[0] == DIRECTGATE_KEY_SCOPE_FULL &&
        mixed.keyauth.nAuthorizedKeyScopes[1] == DIRECTGATE_KEY_SCOPE_FILES, "the rest keep the scopes they have");
    CHECK(mixed.keyauth.sAuthorizedKeyLabels[1][0] == '\0' && mixed.keyauth.nAuthorizedKeyAdded[1] == 5 &&
        mixed.keyauth.nAuthorizedKeyAdded[0] == 0, "a label that is not text is dropped, details that are no object too");
    return 0;
}

int main(void)
{
    const char *srpSalt = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const char *srpVerifier = "1234abcd";
    char sTmpPath[] = "/tmp/directgate_add_key_smoke.XXXXXX";
    int nFd = mkstemp(sTmpPath);
    CHECK(nFd >= 0, "mkstemp");
    close(nFd);
    unlink(sTmpPath);

    directgate_cfg_t cfg;
    DirectGate_InitConfig(&cfg);
    xstrncpy(cfg.sCfgPath, sizeof(cfg.sCfgPath), sTmpPath);
    xstrncpy(cfg.sDeviceId, sizeof(cfg.sDeviceId), "dev-smoke");

    /* --- Invalid input rejected --- */
    CHECK(DirectGate_AddAuthorizedKey(&cfg, NULL) == DIRECTGATE_ADD_KEY_INVALID,
        "NULL pubkey must be rejected");
    CHECK(DirectGate_AddAuthorizedKey(&cfg, "") == DIRECTGATE_ADD_KEY_INVALID,
        "empty pubkey must be rejected");
    CHECK(DirectGate_AddAuthorizedKey(&cfg, "not-a-real-key") == DIRECTGATE_ADD_KEY_INVALID,
        "non-base64 pubkey must be rejected");
    CHECK(cfg.keyauth.nAuthorizedKeyCount == 0,
        "invalid keys must not be stored");

    /* --- Append first valid key, preserving the full 44-char base64 value --- */
    const char *key1 = "G8tzS4EVKlvTqIPkKxTV/jJMHCvQkQCnYJO1B4EFRzE=";
    CHECK(strlen(key1) == 44, "reported key fixture must be 44 chars");
    CHECK(DirectGate_AddAuthorizedKey(&cfg, key1) == DIRECTGATE_ADD_KEY_ADDED,
        "first key must be ADDED");
    CHECK(cfg.keyauth.nAuthorizedKeyCount == 1,
        "count after first add");
    CHECK(xstrcmp(cfg.keyauth.sAuthorizedKeys[0], key1),
        "first key stored verbatim");

    /* --- Duplicate returns ALREADY without mutating state --- */
    CHECK(DirectGate_AddAuthorizedKey(&cfg, key1) == DIRECTGATE_ADD_KEY_ALREADY,
        "duplicate must return ALREADY");
    CHECK(cfg.keyauth.nAuthorizedKeyCount == 1,
        "duplicate must not grow list");

    /* --- Distinct key appended --- */
    char key2[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    CHECK(build_test_pubkey_b64(key2, sizeof(key2), 0x42) == 0, "build key2");
    CHECK(DirectGate_AddAuthorizedKey(&cfg, key2) == DIRECTGATE_ADD_KEY_ADDED,
        "second key must be ADDED");
    CHECK(cfg.keyauth.nAuthorizedKeyCount == 2,
        "count after second add");

    /* --- Fill to capacity --- */
    for (uint8_t i = 2; i < DIRECTGATE_MAX_AUTHORIZED_KEYS; i++)
    {
        char sKey[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
        CHECK(build_test_pubkey_b64(sKey, sizeof(sKey), (uint8_t)(0x80 + i)) == 0,
            "build filler key");
        CHECK(DirectGate_AddAuthorizedKey(&cfg, sKey) == DIRECTGATE_ADD_KEY_ADDED,
            "filler key must be ADDED");
    }
    CHECK(cfg.keyauth.nAuthorizedKeyCount == DIRECTGATE_MAX_AUTHORIZED_KEYS,
        "filled to capacity");

    /* --- Capacity exhausted --- */
    char overflow[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    CHECK(build_test_pubkey_b64(overflow, sizeof(overflow), 0xF0) == 0,
        "build overflow key");
    CHECK(DirectGate_AddAuthorizedKey(&cfg, overflow) == DIRECTGATE_ADD_KEY_FULL,
        "overflow must return FULL");
    CHECK(cfg.keyauth.nAuthorizedKeyCount == DIRECTGATE_MAX_AUTHORIZED_KEYS,
        "overflow must not extend list");

    char agentSeed[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char agentPub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    CHECK(build_test_pubkey_b64(agentSeed, sizeof(agentSeed), 0x21) == 0,
        "build agent identity seed fixture");
    CHECK(build_test_pubkey_b64(agentPub, sizeof(agentPub), 0x31) == 0,
        "build agent identity pub fixture");
    xstrncpy(cfg.auth.sSaltHex, sizeof(cfg.auth.sSaltHex), srpSalt);
    xstrncpy(cfg.auth.sVerifierHex, sizeof(cfg.auth.sVerifierHex), srpVerifier);
    xstrncpy(cfg.keyauth.sIdentitySeedB64, sizeof(cfg.keyauth.sIdentitySeedB64), agentSeed);
    xstrncpy(cfg.keyauth.sIdentityPubB64, sizeof(cfg.keyauth.sIdentityPubB64), agentPub);

    /* --- Persist + reload preserves authorizedKeys --- */
    CHECK(DirectGate_SaveConfig(&cfg), "SaveConfig must succeed");
    struct stat st;
    CHECK(stat(sTmpPath, &st) == 0, "saved config stat");
    CHECK((st.st_mode & 0777) == 0600,
        "saved config should be private");

    xbyte_buffer_t saved;
    CHECK(XPath_LoadBuffer(sTmpPath, &saved) > 0, "saved config must be readable");

    xjson_t json;
    CHECK(XJSON_Parse(&json, NULL, (const char*)saved.pData, saved.nUsed),
        "saved config must be valid JSON");
    xjson_obj_t *pRoot = json.pRootObj;
    CHECK(XJSON_GetObject(pRoot, "agentIdentity") == NULL,
        "saved config must not write legacy root agentIdentity");
    CHECK(XJSON_GetObject(pRoot, "authorizedKeys") == NULL,
        "saved config must not write legacy root authorizedKeys");

    xjson_obj_t *pAuth = XJSON_GetObject(pRoot, "auth");
    CHECK(pAuth != NULL && pAuth->nType == XJSON_TYPE_OBJECT,
        "saved config must contain auth object");
    CHECK(XJSON_GetObject(pAuth, "salt") == NULL,
        "saved config must not write legacy auth.salt");
    CHECK(XJSON_GetObject(pAuth, "verifier") == NULL,
        "saved config must not write legacy auth.verifier");

    xjson_obj_t *pSrp = XJSON_GetObject(pAuth, "srp");
    CHECK(pSrp != NULL && pSrp->nType == XJSON_TYPE_OBJECT,
        "saved config must contain auth.srp");
    CHECK(xstrcmp(XJSON_GetString(XJSON_GetObject(pSrp, "salt")), srpSalt),
        "saved config must write auth.srp.salt");
    CHECK(xstrcmp(XJSON_GetString(XJSON_GetObject(pSrp, "verifier")), srpVerifier),
        "saved config must write auth.srp.verifier");

    xjson_obj_t *pKey = XJSON_GetObject(pAuth, "key");
    CHECK(pKey != NULL && pKey->nType == XJSON_TYPE_OBJECT,
        "saved config must contain auth.key");
    xjson_obj_t *pIdentity = XJSON_GetObject(pKey, "agentIdentity");
    CHECK(pIdentity != NULL && pIdentity->nType == XJSON_TYPE_OBJECT,
        "saved config must contain auth.key.agentIdentity");
    CHECK(xstrcmp(XJSON_GetString(XJSON_GetObject(pIdentity, "seed")), agentSeed),
        "saved config must write auth.key.agentIdentity.seed");
    CHECK(xstrcmp(XJSON_GetString(XJSON_GetObject(pIdentity, "pub")), agentPub),
        "saved config must write auth.key.agentIdentity.pub");

    xjson_obj_t *pKeys = XJSON_GetObject(pKey, "authorizedKeys");
    CHECK(pKeys != NULL && pKeys->nType == XJSON_TYPE_ARRAY,
        "saved config must contain auth.key.authorizedKeys");
    CHECK(XJSON_GetArrayLength(pKeys) == DIRECTGATE_MAX_AUTHORIZED_KEYS,
        "saved config must preserve authorized key count");
    CHECK(xstrcmp(XJSON_GetString(XJSON_GetArrayItem(pKeys, 0)), key1),
        "saved config must preserve full first authorized key");
    XJSON_Destroy(&json);
    XByteBuffer_Clear(&saved);

    directgate_cfg_t reloaded;
    DirectGate_InitConfig(&reloaded);
    CHECK(DirectGate_LoadConfig(&reloaded, sTmpPath),
        "LoadConfig must succeed");
    CHECK(reloaded.keyauth.nAuthorizedKeyCount == DIRECTGATE_MAX_AUTHORIZED_KEYS,
        "reloaded authorized key count must match");
    CHECK(xstrcmp(reloaded.keyauth.sAuthorizedKeys[0], key1),
        "reloaded key 0 must match key1");
    CHECK(xstrcmp(reloaded.keyauth.sAuthorizedKeys[1], key2),
        "reloaded key 1 must match key2");
    CHECK(strcmp(reloaded.auth.sSaltHex, srpSalt) == 0,
        "reloaded SRP salt must match");
    CHECK(strcmp(reloaded.auth.sVerifierHex, srpVerifier) == 0,
        "reloaded SRP verifier must match");
    CHECK(strcmp(reloaded.keyauth.sIdentitySeedB64, agentSeed) == 0,
        "reloaded agent identity seed must match");
    CHECK(strcmp(reloaded.keyauth.sIdentityPubB64, agentPub) == 0,
        "reloaded agent identity pub must match");

    /* --- Duplicate detection survives reload --- */
    CHECK(DirectGate_AddAuthorizedKey(&reloaded, key1) == DIRECTGATE_ADD_KEY_ALREADY,
        "reloaded duplicate must return ALREADY");

    /* --- Legacy auth layout still loads for migration compatibility --- */
    char legacyJson[1024];
    int nLegacyLen = snprintf(legacyJson, sizeof(legacyJson),
        "{"
            "\"auth\":{\"salt\":\"%s\",\"verifier\":\"%s\"},"
            "\"agentIdentity\":{\"seed\":\"%s\",\"pub\":\"%s\"},"
            "\"authorizedKeys\":[\"%s\"]"
        "}",
        srpSalt, srpVerifier, agentSeed, agentPub, key1);
    CHECK(nLegacyLen > 0 && (size_t)nLegacyLen < sizeof(legacyJson),
        "legacy JSON fixture must fit");
    CHECK(XPath_Write(sTmpPath, (uint8_t*)legacyJson, (size_t)nLegacyLen, "cwt") > 0,
        "legacy config fixture must be writable");

    directgate_cfg_t legacy;
    DirectGate_InitConfig(&legacy);
    CHECK(DirectGate_LoadConfig(&legacy, sTmpPath),
        "legacy config must load");
    CHECK(strcmp(legacy.auth.sSaltHex, srpSalt) == 0,
        "legacy auth.salt must load into SRP auth");
    CHECK(strcmp(legacy.auth.sVerifierHex, srpVerifier) == 0,
        "legacy auth.verifier must load into SRP auth");
    CHECK(strcmp(legacy.keyauth.sIdentityPubB64, agentPub) == 0,
        "legacy agentIdentity must load into key auth");
    CHECK(legacy.keyauth.nAuthorizedKeyCount == 1 &&
        strcmp(legacy.keyauth.sAuthorizedKeys[0], key1) == 0,
        "legacy authorizedKeys must load into key auth");

    if (test_scopes()) return 1;
    if (test_scoped_keys(sTmpPath, key1, key2)) return 1;

    unlink(sTmpPath);
    printf("agent_add_key_smoke: OK\n");
    return 0;
}
