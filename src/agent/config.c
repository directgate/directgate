/*!
 * @file directgate-agent/src/agent/config.c
 * @brief Agent config and CLI parsing.
 *
 *  Copyright (c) 2025-2026 DirectGate. All rights reserved.
 *  Author: Sandro Kalatozishvili (sandro@directgate.io)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "common.h"
#include "config.h"
#include "enroll.h"
#include "keyauth.h"
#include "version.h"

extern char *optarg;
extern int optind;
extern int opterr;
extern int optopt;

#define DIRECTGATE_AGENT_CONFIG     ".config/directgate/agent.json"
#define DIRECTGATE_RELAY_URL        "wss://relay1.directgate.io/websock"
#define DIRECTGATE_API_URL          "https://api.directgate.io"
#define DIRECTGATE_HOST_OPTSTRING   "a:c:d:g:l:t:v:w:e1:i1:r1:s1:v:h1"

static xbool_t DirectGate_EnsureagentIdentity(directgate_cfg_t *pCfg);

static void DirectGate_LogRestartHint(void)
{
    printf("\nYou might need to restart the running directgate to apply the new enrollment.\n");
#ifdef __APPLE__
    printf("Try running: %sbrew services restart directgate%s\n", XSTR_FMT_DIM, XSTR_FMT_RESET);
#elif defined(__linux__)
    printf("Try running: %ssudo systemctl restart directgate-agent%s\n", XSTR_FMT_DIM, XSTR_FMT_RESET);
#endif
}

void DirectGate_DisplayUsage(const char *pName)
{
    printf("DirectGate agent: v%s\n", DirectGate_GetVersionShort());
    printf("XUtils library: v%s\n", XUtils_VersionShort());
    printf("WebRTC library: v%s\n\n", RTC_VERSION);

    printf("Usage: %s [options]\n", pName);
    printf("Options are:\n");
    printf("  -d <id>              # Device ID for this agent\n");
    printf("  -w <url>             # WebSocket relay URL\n");
    printf("  -c <path>            # Config JSON path\n");
    printf("  -l <path>            # Log directory path\n");
    printf("  -t <token>           # Pairing token for enrollment\n");
    printf("  -v <number>          # Set/override verbosity level\n");
    printf("  -g <path>            # Generate a client key file and exit\n");
    printf("  -a <path>            # Authorize this agent against an existing key file and exit\n");
    printf("  -r                   # Rotate agent identity keypair and push new pub to API, then exit\n");
    printf("  -i                   # Init config and exit\n");
    printf("  -e                   # Enroll device and exit\n");
    printf("  -s                   # Init SRP verifier and exit\n");
    printf("  -h                   # Version and usage\n\n");
}

static void DirectGate_SetDefaultConfigPath(directgate_cfg_t *pCfg)
{
#ifdef _WIN32
    /* Windows convention: per-user roaming application data. Forward
       slashes keep the path JSON-safe wherever it gets serialized. */
    const char *pAppData = getenv("APPDATA");
    if (xstrused(pAppData))
    {
        xstrncpyf(pCfg->sCfgPath, sizeof(pCfg->sCfgPath),
            "%s/directgate/agent.json", pAppData);

        DirectGate_PathToSlash(pCfg->sCfgPath);
        return;
    }
#endif

    char sHomeDir[XPATH_MAX];
    DirectGate_GetHomeDir(sHomeDir, sizeof(sHomeDir));

    if (!xstrused(sHomeDir)) xstrncpy(pCfg->sCfgPath, sizeof(pCfg->sCfgPath), "./agent.json");
    else xstrncpyf(pCfg->sCfgPath, sizeof(pCfg->sCfgPath), "%s/%s", sHomeDir, DIRECTGATE_AGENT_CONFIG);
}

static xbool_t DirectGate_PromptAPIUrl(directgate_cfg_t *pCfg)
{
    return DirectGate_PromptString("API URL", pCfg->enroll.sApiUrl,
        sizeof(pCfg->enroll.sApiUrl), DIRECTGATE_API_URL, XTRUE);
}

static xbool_t DirectGate_PromptRelayUrl(directgate_cfg_t *pCfg)
{
    return DirectGate_PromptString("Relay URL", pCfg->sRelayUrl,
        sizeof(pCfg->sRelayUrl), DIRECTGATE_RELAY_URL, XTRUE);
}

static xbool_t DirectGate_PromptDeviceId(directgate_cfg_t *pCfg)
{
    return DirectGate_PromptString("Device ID", pCfg->sDeviceId,
        sizeof(pCfg->sDeviceId), pCfg->sDeviceId, XTRUE);
}

static xbool_t DirectGate_PromptAuth(directgate_cfg_t *pCfg, xbool_t bForce)
{
    XCHECK((pCfg != NULL), XFALSE);

    if (!xstrused(pCfg->sDeviceId) && !DirectGate_PromptDeviceId(pCfg))
    {
        xloge("SRP auth setup requires device id: cfg(%s)", pCfg->sCfgPath);
        return XFALSE;
    }

    if (bForce)
    {
        pCfg->auth.sSaltHex[0] = XSTR_NUL;
        pCfg->auth.sVerifierHex[0] = XSTR_NUL;
    }
    else if (DirectGate_AuthIsConfigured(&pCfg->auth))
    {
        xlogd("SRP auth already configured: cfg(%s), dev(%s)", pCfg->sCfgPath, pCfg->sDeviceId);
        return XTRUE;
    }

    char sPassword1[XSTR_MID];
    char sPassword2[XSTR_MID];

    if (XCLI_GetPass("Set new auth password: ", sPassword1, sizeof(sPassword1)) <= 0)
    {
        xloge("Failed to read SRP password from CLI: cfg(%s), dev(%s)", pCfg->sCfgPath, pCfg->sDeviceId);
        OPENSSL_cleanse(sPassword1, sizeof(sPassword1));
        return XFALSE;
    }

    if (XCLI_GetPass("Repeat password: ", sPassword2, sizeof(sPassword2)) <= 0)
    {
        xloge("Failed to read SRP password confirmation from CLI: cfg(%s), dev(%s)", pCfg->sCfgPath, pCfg->sDeviceId);
        OPENSSL_cleanse(sPassword1, sizeof(sPassword1));
        OPENSSL_cleanse(sPassword2, sizeof(sPassword2));
        return XFALSE;
    }

    if (strcmp(sPassword1, sPassword2) != 0)
    {
        xloge("SRP password mismatch: cfg(%s), dev(%s)", pCfg->sCfgPath, pCfg->sDeviceId);
        OPENSSL_cleanse(sPassword1, sizeof(sPassword1));
        OPENSSL_cleanse(sPassword2, sizeof(sPassword2));
        return XFALSE;
    }

    if (!DirectGate_AuthGenerateRecord(&pCfg->auth, sPassword1))
    {
        xloge("Failed to generate SRP auth record: cfg(%s), dev(%s)", pCfg->sCfgPath, pCfg->sDeviceId);
        OPENSSL_cleanse(sPassword1, sizeof(sPassword1));
        OPENSSL_cleanse(sPassword2, sizeof(sPassword2));
        return XFALSE;
    }

    OPENSSL_cleanse(sPassword1, sizeof(sPassword1));
    OPENSSL_cleanse(sPassword2, sizeof(sPassword2));
    return XTRUE;
}

static int DirectGate_StoreAuthFromPrompt(directgate_cfg_t *pCfg)
{
    XCHECK((pCfg != NULL), XSTDERR);

    XCHECK(DirectGate_PromptAuth(pCfg, XTRUE), XSTDERR);
    XCHECK(DirectGate_SaveConfig(pCfg), XSTDERR);

    xlogn("SRP auth updated: cfg(%s), dev(%s)", pCfg->sCfgPath, pCfg->sDeviceId);
    return XSTDOK;
}

static int DirectGate_EnrollFromPrompt(const directgate_cfg_t *pCfg)
{
    XCHECK((pCfg != NULL), XSTDERR);
    directgate_cfg_t cfg = *pCfg;

    if (!xstrused(cfg.enroll.sApiUrl) && !DirectGate_PromptAPIUrl(&cfg))
    {
        xloge("Enrollment requires API URL: cfg(%s), dev(%s)", cfg.sCfgPath, cfg.sDeviceId);
        return XSTDERR;
    }

    if (!xstrused(cfg.sDeviceId) && !DirectGate_PromptDeviceId(&cfg))
    {
        xloge("Enrollment requires device id: cfg(%s), api(%s)", cfg.sCfgPath, cfg.enroll.sApiUrl);
        return XSTDERR;
    }

    char sPairingToken[XSTR_MID];
    sPairingToken[0] = XSTR_NUL;

    if (xstrused(cfg.sPairingToken))
    {
        xstrncpy(sPairingToken, sizeof(sPairingToken), cfg.sPairingToken);
        cfg.sPairingToken[0] = XSTR_NUL;
    }
    else if (XCLI_GetPass("Pairing token: ", sPairingToken, sizeof(sPairingToken)) <= 0)
    {
        xloge("Failed to read pairing token from CLI: cfg(%s), dev(%s), api(%s)",
            cfg.sCfgPath, cfg.sDeviceId, cfg.enroll.sApiUrl);

        return XSTDERR;
    }

    if (!DirectGate_AuthIsConfigured(&cfg.auth) || cfg.bSetSRP)
    {
        if (DirectGate_StoreAuthFromPrompt(&cfg) != XSTDOK)
        {
            xloge("Failed to store SRP auth credentials: cfg(%s), dev(%s), api(%s)",
                cfg.sCfgPath, cfg.sDeviceId, cfg.enroll.sApiUrl);

            OPENSSL_cleanse(sPairingToken, sizeof(sPairingToken));
            return XSTDERR;
        }
    }

    if (!DirectGate_EnsureagentIdentity(&cfg))
    {
        OPENSSL_cleanse(sPairingToken, sizeof(sPairingToken));
        return XSTDERR;
    }

    if (!DirectGate_Enroll_Pair(&cfg, sPairingToken))
    {
        xloge("Device enrollment failed: cfg(%s), dev(%s), api(%s)",
            cfg.sCfgPath, cfg.sDeviceId, cfg.enroll.sApiUrl);

        OPENSSL_cleanse(sPairingToken, sizeof(sPairingToken));
        return XSTDERR;
    }

    xlogn("Device enrolled and config saved: cfg(%s), dev(%s), relay(%s)",
        cfg.sCfgPath, cfg.sDeviceId, cfg.sRelayUrl);

    OPENSSL_cleanse(sPairingToken, sizeof(sPairingToken));
    DirectGate_LogRestartHint();

    return XSTDOK;
}

static xbool_t DirectGate_GenerateagentIdentity(directgate_cfg_t *pCfg)
{
    XCHECK((pCfg != NULL), XFALSE);

    uint8_t seed[DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE];
    uint8_t pub[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];

    if (!DirectGate_KeyAuth_Ed25519Generate(pub, seed))
    {
        OPENSSL_cleanse(seed, sizeof(seed));
        xloge("Failed to generate agent identity keypair: cfg(%s)", pCfg->sCfgPath);
        return XFALSE;
    }

    if (!DirectGate_KeyAuth_Base64Encode(seed, sizeof(seed),
            pCfg->keyauth.sIdentitySeedB64, sizeof(pCfg->keyauth.sIdentitySeedB64)) ||
        !DirectGate_KeyAuth_Base64Encode(pub, sizeof(pub),
            pCfg->keyauth.sIdentityPubB64, sizeof(pCfg->keyauth.sIdentityPubB64)))
    {
        pCfg->keyauth.sIdentitySeedB64[0] = XSTR_NUL;
        pCfg->keyauth.sIdentityPubB64[0] = XSTR_NUL;
        OPENSSL_cleanse(seed, sizeof(seed));

        xloge("Failed to encode agent identity keypair: cfg(%s)", pCfg->sCfgPath);
        return XFALSE;
    }

    OPENSSL_cleanse(seed, sizeof(seed));
    return XTRUE;
}

static xbool_t DirectGate_EnsureagentIdentity(directgate_cfg_t *pCfg)
{
    XCHECK((pCfg != NULL), XFALSE);
    if (xstrused(pCfg->keyauth.sIdentitySeedB64) &&
        xstrused(pCfg->keyauth.sIdentityPubB64)) return XTRUE;

    return DirectGate_GenerateagentIdentity(pCfg);
}

static void DirectGate_LoadKeyAuthConfig(directgate_keyauth_cfg_t *pKeyAuth, xjson_obj_t *pRoot)
{
    XCHECK_VOID_NL((pKeyAuth != NULL));
    XCHECK_VOID_NL((pRoot != NULL));

    xjson_obj_t *pAuth = XJSON_GetObject(pRoot, "auth");
    xjson_obj_t *pKeyAuthObj = NULL;
    if (pAuth != NULL && pAuth->nType == XJSON_TYPE_OBJECT)
    {
        pKeyAuthObj = XJSON_GetObject(pAuth, "key");
        if (pKeyAuthObj != NULL && pKeyAuthObj->nType != XJSON_TYPE_OBJECT)
            pKeyAuthObj = NULL;
    }

    xjson_obj_t *pIdentity = NULL;
    xjson_obj_t *pAuthKeys = NULL;
    if (pKeyAuthObj != NULL)
    {
        pIdentity = XJSON_GetObject(pKeyAuthObj, "agentIdentity");
        pAuthKeys = XJSON_GetObject(pKeyAuthObj, "authorizedKeys");
    }

    /* Backward compatibility for configs written before auth.key existed. */
    if (pIdentity == NULL) pIdentity = XJSON_GetObject(pRoot, "agentIdentity");
    if (pAuthKeys == NULL) pAuthKeys = XJSON_GetObject(pRoot, "authorizedKeys");

    if (pIdentity != NULL && pIdentity->nType == XJSON_TYPE_OBJECT)
    {
        const char *pSeed = XJSON_GetString(XJSON_GetObject(pIdentity, "seed"));
        if (xstrused(pSeed)) xstrncpy(pKeyAuth->sIdentitySeedB64,
            sizeof(pKeyAuth->sIdentitySeedB64), pSeed);

        const char *pPub = XJSON_GetString(XJSON_GetObject(pIdentity, "pub"));
        if (xstrused(pPub)) xstrncpy(pKeyAuth->sIdentityPubB64,
            sizeof(pKeyAuth->sIdentityPubB64), pPub);
    }

    if (pAuthKeys != NULL && pAuthKeys->nType == XJSON_TYPE_ARRAY)
    {
        pKeyAuth->nAuthorizedKeyCount = 0;
        size_t nEntries = XJSON_GetArrayLength(pAuthKeys);

        for (size_t i = 0; i < nEntries && pKeyAuth->nAuthorizedKeyCount < DIRECTGATE_MAX_AUTHORIZED_KEYS; i++)
        {
            const char *pKey = XJSON_GetString(XJSON_GetArrayItem(pAuthKeys, i));
            if (!xstrused(pKey)) continue;

            xstrncpy(pKeyAuth->sAuthorizedKeys[pKeyAuth->nAuthorizedKeyCount],
                sizeof(pKeyAuth->sAuthorizedKeys[0]), pKey);

            pKeyAuth->nAuthorizedKeyCount++;
        }
    }
}

static int DirectGate_RotateagentIdentity(const directgate_cfg_t *pCfg)
{
    XCHECK((pCfg != NULL), XSTDERR);

    if (!xstrused(pCfg->enroll.sApiUrl))
    {
        xloge("Agent key rotation requires API URL: cfg(%s), dev(%s)",
            pCfg->sCfgPath, pCfg->sDeviceId);
        return XSTDERR;
    }

    if (!xstrused(pCfg->sDeviceId))
    {
        xloge("Agent key rotation requires device id: cfg(%s), api(%s)",
            pCfg->sCfgPath, pCfg->enroll.sApiUrl);
        return XSTDERR;
    }

    if (!xstrused(pCfg->enroll.sRefreshToken))
    {
        xloge("Agent key rotation requires an active enrollment refresh token: cfg(%s), dev(%s)",
            pCfg->sCfgPath, pCfg->sDeviceId);
        return XSTDERR;
    }

    directgate_cfg_t cfg = *pCfg;
    char sPrevSeed[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sPrevPub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    xstrncpy(sPrevSeed, sizeof(sPrevSeed), cfg.keyauth.sIdentitySeedB64);
    xstrncpy(sPrevPub, sizeof(sPrevPub), cfg.keyauth.sIdentityPubB64);

    cfg.keyauth.sIdentitySeedB64[0] = XSTR_NUL;
    cfg.keyauth.sIdentityPubB64[0] = XSTR_NUL;

    if (!DirectGate_GenerateagentIdentity(&cfg))
    {
        OPENSSL_cleanse(sPrevSeed, sizeof(sPrevSeed));
        xstrncpy(cfg.keyauth.sIdentitySeedB64, sizeof(cfg.keyauth.sIdentitySeedB64), sPrevSeed);
        xstrncpy(cfg.keyauth.sIdentityPubB64, sizeof(cfg.keyauth.sIdentityPubB64), sPrevPub);
        return XSTDERR;
    }

    if (!DirectGate_Enroll_RotateAgentKey(&cfg))
    {
        OPENSSL_cleanse(sPrevSeed, sizeof(sPrevSeed));
        xloge("Agent key rotation failed; keeping previous identity: cfg(%s), dev(%s), api(%s)",
            cfg.sCfgPath, cfg.sDeviceId, cfg.enroll.sApiUrl);
        return XSTDERR;
    }

    if (!DirectGate_SaveConfig(&cfg))
    {
        OPENSSL_cleanse(sPrevSeed, sizeof(sPrevSeed));
        xloge("Failed to persist rotated agent identity: cfg(%s), dev(%s)",
            cfg.sCfgPath, cfg.sDeviceId);
        return XSTDERR;
    }

    OPENSSL_cleanse(sPrevSeed, sizeof(sPrevSeed));

    xlogn("Agent identity rotated and persisted: cfg(%s), dev(%s), api(%s)",
        cfg.sCfgPath, cfg.sDeviceId, cfg.enroll.sApiUrl);

    return XSTDOK;
}

directgate_add_key_result_t DirectGate_AddAuthorizedKey(directgate_cfg_t *pCfg, const char *pClientPubB64)
{
    XCHECK((pCfg != NULL && xstrused(pClientPubB64)), DIRECTGATE_ADD_KEY_INVALID);

    uint8_t raw[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    size_t nRawLen = 0;

    if (!DirectGate_KeyAuth_Base64Decode(pClientPubB64, raw, sizeof(raw), &nRawLen) ||
        nRawLen != DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE)
    {
        return DIRECTGATE_ADD_KEY_INVALID;
    }

    for (uint8_t i = 0; i < pCfg->keyauth.nAuthorizedKeyCount; i++)
    {
        if (xstrcmp(pCfg->keyauth.sAuthorizedKeys[i], pClientPubB64))
            return DIRECTGATE_ADD_KEY_ALREADY;
    }

    if (pCfg->keyauth.nAuthorizedKeyCount >= DIRECTGATE_MAX_AUTHORIZED_KEYS)
        return DIRECTGATE_ADD_KEY_FULL;

    xstrncpy(pCfg->keyauth.sAuthorizedKeys[pCfg->keyauth.nAuthorizedKeyCount],
        sizeof(pCfg->keyauth.sAuthorizedKeys[0]), pClientPubB64);

    pCfg->keyauth.nAuthorizedKeyCount++;
    return DIRECTGATE_ADD_KEY_ADDED;
}

static xbool_t DirectGate_AppendAuthorizedKey(directgate_cfg_t *pCfg, const char *pClientPubB64)
{
    directgate_add_key_result_t eResult = DirectGate_AddAuthorizedKey(pCfg, pClientPubB64);
    if (eResult == DIRECTGATE_ADD_KEY_FULL)
    {
        xloge("authorizedKeys is full: cfg(%s), max(%d)",
            pCfg->sCfgPath, DIRECTGATE_MAX_AUTHORIZED_KEYS);
        return XFALSE;
    }

    if (eResult == DIRECTGATE_ADD_KEY_INVALID) return XFALSE;
    return XTRUE;
}

#define DIRECTGATE_CLIENT_KEY_FILE_TYPE "directgate-client-key-v2"

typedef struct directgate_client_key_file_ {
    char sClientPubB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sClientSeedB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
} directgate_client_key_file_t;

static void DirectGate_KeyFile_Cleanse(directgate_client_key_file_t *pFile)
{
    if (pFile == NULL) return;
    OPENSSL_cleanse(pFile->sClientSeedB64, sizeof(pFile->sClientSeedB64));
    OPENSSL_cleanse(pFile, sizeof(*pFile));
}

static int DirectGate_KeyFile_Read(const char *pPath, directgate_client_key_file_t *pOut)
{
    XCHECK((xstrused(pPath) && pOut != NULL), XSTDERR);
    memset(pOut, 0, sizeof(*pOut));

    xbyte_buffer_t buffer;
    if (XPath_LoadBuffer(pPath, &buffer) <= 0)
    {
        xloge("Failed to load client key file: path(%s), errno(%d)", pPath, errno);
        return XSTDERR;
    }

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, (const char*)buffer.pData, buffer.nUsed))
    {
        char sError[256];
        XJSON_GetErrorStr(&json, sError, sizeof(sError));
        xloge("Failed to parse client key file: path(%s), error(%s)", pPath, sError);

        XByteBuffer_Clear(&buffer);
        XJSON_Destroy(&json);
        return XSTDERR;
    }

    xjson_obj_t *pRoot = json.pRootObj;
    const char *pType = XJSON_GetString(XJSON_GetObject(pRoot, "type"));

    if (!xstrused(pType) || !xstrcmp(pType, DIRECTGATE_CLIENT_KEY_FILE_TYPE))
    {
        xloge("Unsupported client key file type: path(%s), type(%s)", pPath, pType ? pType : "(null)");
        XByteBuffer_Clear(&buffer);
        XJSON_Destroy(&json);
        return XSTDERR;
    }

    const char *pClientPub = XJSON_GetString(XJSON_GetObject(pRoot, "clientPub"));
    const char *pClientSeed = XJSON_GetString(XJSON_GetObject(pRoot, "clientSeed"));

    if (!xstrused(pClientPub) || !xstrused(pClientSeed))
    {
        xloge("Client key file missing clientPub/clientSeed: path(%s)", pPath);
        XByteBuffer_Clear(&buffer);
        XJSON_Destroy(&json);
        return XSTDERR;
    }

    xstrncpy(pOut->sClientPubB64, sizeof(pOut->sClientPubB64), pClientPub);
    xstrncpy(pOut->sClientSeedB64, sizeof(pOut->sClientSeedB64), pClientSeed);

    OPENSSL_cleanse(buffer.pData, buffer.nUsed);
    XByteBuffer_Clear(&buffer);
    XJSON_Destroy(&json);
    return XSTDOK;
}

static int DirectGate_KeyFile_Write(const char *pPath, const directgate_client_key_file_t *pFile)
{
    XCHECK((xstrused(pPath) && pFile != NULL), XSTDERR);
    XCHECK((xstrused(pFile->sClientPubB64) && xstrused(pFile->sClientSeedB64)), XSTDERR);

    if (!DirectGate_EnsurePrivateFileParent(pPath))
    {
        xloge("Failed to create private client key directory: path(%s), errno(%d)",
            pPath, errno);

        return XSTDERR;
    }

    xjson_obj_t *pRoot = XJSON_NewObject(NULL, NULL, XFALSE);
    XCHECK((pRoot != NULL), xthrowr(XSTDERR, "Failed to allocate key-file JSON"));

    XJSON_AddString(pRoot, "type", DIRECTGATE_CLIENT_KEY_FILE_TYPE);
    XJSON_AddString(pRoot, "clientPub", pFile->sClientPubB64);
    XJSON_AddString(pRoot, "clientSeed", pFile->sClientSeedB64);

    size_t nLength = 0;
    char *pDump = XJSON_DumpObj(pRoot, 2, &nLength);
    XJSON_FreeObject(pRoot);

    XCHECK((pDump != NULL && nLength > 0),
        xthrowr(XSTDERR, "Failed to serialize client key JSON: path(%s)", pPath));

    xbool_t bWrote = DirectGate_WritePrivateFile(pPath, (uint8_t*)pDump, nLength);

    OPENSSL_cleanse(pDump, nLength);
    free(pDump);

    if (!bWrote)
    {
        xloge("Failed to write client key file: path(%s), errno(%d)", pPath, errno);
        return XSTDERR;
    }

    return XSTDOK;
}

static int DirectGate_GenKeyFile(const directgate_cfg_t *pCfg)
{
    XCHECK((pCfg != NULL), XSTDERR);
    XCHECK((xstrused(pCfg->sGenKeyPath)),
        xthrowr(XSTDERR, "Client key generation requires output path"));

    if (XPath_Exists(pCfg->sGenKeyPath))
    {
        xloge("Client key file already exists: path(%s). "
            "Use -a <path> to authorize this agent against an existing key.",
            pCfg->sGenKeyPath);
        return XSTDERR;
    }

    directgate_cfg_t cfg = *pCfg;
    if (!DirectGate_EnsureagentIdentity(&cfg)) return XSTDERR;

    uint8_t seed[DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE];
    uint8_t pub[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];

    if (!DirectGate_KeyAuth_Ed25519Generate(pub, seed))
    {
        OPENSSL_cleanse(seed, sizeof(seed));
        xloge("Failed to generate client keypair: cfg(%s)", cfg.sCfgPath);
        return XSTDERR;
    }

    directgate_client_key_file_t file;
    memset(&file, 0, sizeof(file));

    if (!DirectGate_KeyAuth_Base64Encode(pub, sizeof(pub),
            file.sClientPubB64, sizeof(file.sClientPubB64)) ||
        !DirectGate_KeyAuth_Base64Encode(seed, sizeof(seed),
            file.sClientSeedB64, sizeof(file.sClientSeedB64)))
    {
        OPENSSL_cleanse(seed, sizeof(seed));
        DirectGate_KeyFile_Cleanse(&file);
        xloge("Failed to encode client keypair: cfg(%s)", cfg.sCfgPath);
        return XSTDERR;
    }

    OPENSSL_cleanse(seed, sizeof(seed));

    if (!DirectGate_AppendAuthorizedKey(&cfg, file.sClientPubB64))
    {
        DirectGate_KeyFile_Cleanse(&file);
        return XSTDERR;
    }

    if (!DirectGate_SaveConfig(&cfg))
    {
        DirectGate_KeyFile_Cleanse(&file);
        xloge("Failed to persist updated agent config: cfg(%s)", cfg.sCfgPath);
        return XSTDERR;
    }

    int nStatus = DirectGate_KeyFile_Write(cfg.sGenKeyPath, &file);
    DirectGate_KeyFile_Cleanse(&file);
    if (nStatus != XSTDOK) return nStatus;

    xlogn("Client key file written: path(%s), dev(%s), cfg(%s)",
        cfg.sGenKeyPath, cfg.sDeviceId, cfg.sCfgPath);

    return XSTDOK;
}

static int DirectGate_EnrollKeyFile(const directgate_cfg_t *pCfg)
{
    XCHECK((pCfg != NULL), XSTDERR);
    XCHECK((xstrused(pCfg->sEnrollKeyPath)),
        xthrowr(XSTDERR, "Key enrollment requires existing key file path"));

    if (!XPath_Exists(pCfg->sEnrollKeyPath))
    {
        xloge("Client key file not found: path(%s). "
            "Use -g <path> to generate a new key first.",
            pCfg->sEnrollKeyPath);

        return XSTDERR;
    }

    directgate_cfg_t cfg = *pCfg;
    if (!DirectGate_EnsureagentIdentity(&cfg)) return XSTDERR;

    directgate_client_key_file_t file;
    if (DirectGate_KeyFile_Read(cfg.sEnrollKeyPath, &file) != XSTDOK) return XSTDERR;

    if (!DirectGate_AppendAuthorizedKey(&cfg, file.sClientPubB64))
    {
        DirectGate_KeyFile_Cleanse(&file);
        return XSTDERR;
    }

    if (!DirectGate_SaveConfig(&cfg))
    {
        DirectGate_KeyFile_Cleanse(&file);
        xloge("Failed to persist updated agent config: cfg(%s)", cfg.sCfgPath);
        return XSTDERR;
    }

    DirectGate_KeyFile_Cleanse(&file);

    xlogn("Agent authorized against existing key file: key(%s), dev(%s), cfg(%s)",
        cfg.sEnrollKeyPath, cfg.sDeviceId, cfg.sCfgPath);

    return XSTDOK;
}

void DirectGate_InitConfig(directgate_cfg_t *pCfg)
{
    XCHECK_VOID_NL((pCfg != NULL));
    memset(pCfg, 0, sizeof(*pCfg));

    DirectGate_AuthInit(&pCfg->auth);
    DirectGate_LogInit(&pCfg->log, "directgate-agent", (uint16_t)XLOG_DEFAULT);

    pCfg->nKAInterval = DIRECTGATE_KA_INTERVAL_SEC;
    pCfg->bRotateAgentKey = XFALSE;
    pCfg->bAllowTCP = XFALSE;
    pCfg->nVerbose = XSTDNON;
    pCfg->bSetSRP = XFALSE;
    pCfg->bEnroll = XFALSE;
    pCfg->bHelp = XFALSE;
    pCfg->bInit = XFALSE;

    xstrncpy(pCfg->enroll.sApiUrl, sizeof(pCfg->enroll.sApiUrl), DIRECTGATE_API_URL);
    pCfg->enroll.nRefreshSkewSec = DIRECTGATE_JWT_REFRESH_SKEW_SEC;
    pCfg->enroll.bEnrolled = XFALSE;

#ifdef _WIN32
    DirectGate_GetUserName(pCfg->sShellUser, sizeof(pCfg->sShellUser));
    DirectGate_GetHomeDir(pCfg->sShellHome, sizeof(pCfg->sShellHome));
#else
    struct passwd *pUser = getpwuid(getuid());
    if (pUser != NULL)
    {
        if (xstrused(pUser->pw_name))
            xstrncpy(pCfg->sShellUser, sizeof(pCfg->sShellUser), pUser->pw_name);

        if (xstrused(pUser->pw_dir))
            xstrncpy(pCfg->sShellHome, sizeof(pCfg->sShellHome), pUser->pw_dir);
    }

    if (!xstrused(pCfg->sShellHome))
    {
        const char *pHomeDir = getenv("HOME");
        if (xstrused(pHomeDir))
            xstrncpy(pCfg->sShellHome, sizeof(pCfg->sShellHome), pHomeDir);
    }
#endif

    DirectGate_SetDefaultConfigPath(pCfg);
}

xbool_t DirectGate_LoadConfig(directgate_cfg_t *pCfg, const char *pPath)
{
    XCHECK((pCfg != NULL), XFALSE);
    XCHECK((xstrused(pCfg->sCfgPath)), XFALSE);

    xbyte_buffer_t buffer;
    if (XPath_LoadBuffer(pPath, &buffer) <= 0)
    {
        xloge("Failed to load agent config: path(%s), errno(%d)", pPath, errno);
        return XFALSE;
    }

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, (const char*)buffer.pData, buffer.nUsed))
    {
        char sError[256];
        XJSON_GetErrorStr(&json, sError, sizeof(sError));
        xloge("Failed to parse agent config: path(%s), error(%s)", pPath, sError);

        XByteBuffer_Clear(&buffer);
        XJSON_Destroy(&json);
        return XFALSE;
    }

    xjson_obj_t *pRoot = json.pRootObj;
    const char *pRelayUrl = XJSON_GetString(XJSON_GetObject(pRoot, "relayUrl"));
    if (xstrused(pRelayUrl)) xstrncpy(pCfg->sRelayUrl, sizeof(pCfg->sRelayUrl), pRelayUrl);

    const char *pRoutingKey = XJSON_GetString(XJSON_GetObject(pRoot, "routingKey"));
    if (xstrused(pRoutingKey)) xstrncpy(pCfg->sRoutingKey, sizeof(pCfg->sRoutingKey), pRoutingKey);

    const char *pUrl = XJSON_GetString(XJSON_GetObject(pRoot, "signalingUrl"));
    if (!xstrused(pCfg->sRelayUrl) && xstrused(pUrl))
        xstrncpy(pCfg->sRelayUrl, sizeof(pCfg->sRelayUrl), pUrl);

    const char *pDeviceId = XJSON_GetString(XJSON_GetObject(pRoot, "deviceId"));
    if (xstrused(pDeviceId)) xstrncpy(pCfg->sDeviceId, sizeof(pCfg->sDeviceId), pDeviceId);

    uint16_t nKAInterval = XJSON_GetU16(XJSON_GetObject(pRoot, "kaInterval"));
    if (nKAInterval > 0) pCfg->nKAInterval = nKAInterval;

    xbool_t bAllowTCP = XJSON_GetBool(XJSON_GetObject(pRoot, "allowTCP"));
    if (bAllowTCP) pCfg->bAllowTCP = bAllowTCP;

    DirectGate_AuthLoad(&pCfg->auth, pRoot);
    DirectGate_LogLoad(&pCfg->log, pRoot);
    DirectGate_WebRTC_LoadIceServers(pCfg->sIceServers, &pCfg->nIceSrvCount, pRoot);
    DirectGate_LoadKeyAuthConfig(&pCfg->keyauth, pRoot);

    xjson_obj_t *pShell = XJSON_GetObject(pRoot, "shell");
    if (pShell != NULL && pShell->nType == XJSON_TYPE_OBJECT)
    {
        const char *pUser = XJSON_GetString(XJSON_GetObject(pShell, "user"));
        if (xstrused(pUser)) xstrncpy(pCfg->sShellUser, sizeof(pCfg->sShellUser), pUser);

        const char *pHome = XJSON_GetString(XJSON_GetObject(pShell, "home"));
        if (xstrused(pHome)) xstrncpy(pCfg->sShellHome, sizeof(pCfg->sShellHome), pHome);
    }

    xjson_obj_t *pEnroll = XJSON_GetObject(pRoot, "enrollment");
    if (pEnroll != NULL && pEnroll->nType == XJSON_TYPE_OBJECT)
    {
        const char *pApiUrl = XJSON_GetString(XJSON_GetObject(pEnroll, "apiUrl"));
        if (xstrused(pApiUrl)) xstrncpy(pCfg->enroll.sApiUrl, sizeof(pCfg->enroll.sApiUrl), pApiUrl);

        const char *pAccToken = XJSON_GetString(XJSON_GetObject(pEnroll, "accessToken"));
        if (xstrused(pAccToken)) xstrncpy(pCfg->enroll.sAccessToken, sizeof(pCfg->enroll.sAccessToken), pAccToken);

        const char *pRefToken = XJSON_GetString(XJSON_GetObject(pEnroll, "refreshToken"));
        if (xstrused(pRefToken)) xstrncpy(pCfg->enroll.sRefreshToken, sizeof(pCfg->enroll.sRefreshToken), pRefToken);

        const char *pAccExp = XJSON_GetString(XJSON_GetObject(pEnroll, "accessTokenExp"));
        if (xstrused(pAccExp)) pCfg->enroll.nAccessTokenExp = (uint64_t)strtoull(pAccExp, NULL, 10);

        const char *pRefExp = XJSON_GetString(XJSON_GetObject(pEnroll, "refreshTokenExp"));
        if (xstrused(pRefExp)) pCfg->enroll.nRefreshTokenExp = (uint64_t)strtoull(pRefExp, NULL, 10);

        const char *pExpAt = XJSON_GetString(XJSON_GetObject(pEnroll, "enrollmentExpiresAt"));
        if (xstrused(pExpAt)) xstrncpy(pCfg->enroll.sEnrollExpiresAt, sizeof(pCfg->enroll.sEnrollExpiresAt), pExpAt);

        uint16_t nSkew = XJSON_GetU16(XJSON_GetObject(pEnroll, "refreshSkewSec"));
        if (nSkew > 0) pCfg->enroll.nRefreshSkewSec = nSkew;

        xjson_obj_t *pEnrolled = XJSON_GetObject(pEnroll, "enrolled");
        if (pEnrolled != NULL) pCfg->enroll.bEnrolled = XJSON_GetBool(pEnrolled);
    }

    XByteBuffer_Clear(&buffer);
    XJSON_Destroy(&json);
    return XTRUE;
}

xbool_t DirectGate_SaveConfig(const directgate_cfg_t *pCfg)
{
    XCHECK((pCfg != NULL), XFALSE);
    XCHECK((xstrused(pCfg->sCfgPath)), XFALSE);

    if (!DirectGate_EnsurePrivateFileParent(pCfg->sCfgPath))
    {
        xloge("Failed to create private agent config directory: cfg(%s), errno(%d)",
            pCfg->sCfgPath, errno);

        return XFALSE;
    }

    xjson_obj_t *pRoot = XJSON_NewObject(NULL, NULL, XFALSE);
    XCHECK((pRoot != NULL), xthrowr(XFALSE, "Failed to create JSON object for config"));

    if (xstrused(pCfg->sRelayUrl)) XJSON_AddString(pRoot, "relayUrl", pCfg->sRelayUrl);
    if (xstrused(pCfg->sRoutingKey)) XJSON_AddString(pRoot, "routingKey", pCfg->sRoutingKey);
    if (xstrused(pCfg->sDeviceId)) XJSON_AddString(pRoot, "deviceId", pCfg->sDeviceId);
    if (pCfg->nKAInterval) XJSON_AddU16(pRoot, "kaInterval", pCfg->nKAInterval);
    if (pCfg->bAllowTCP) XJSON_AddBool(pRoot, "allowTCP", pCfg->bAllowTCP);

    if (pCfg->nIceSrvCount > 0)
    {
        xjson_obj_t *pIce = XJSON_GetOrCreateArray(pRoot, "iceServers", 1);
        if (pIce != NULL)
        {
            for (uint8_t i = 0; i < pCfg->nIceSrvCount; i++)
            {
                xjson_obj_t *pItem = XJSON_NewString(pIce->pPool, NULL, pCfg->sIceServers[i]);
                if (pItem != NULL) XJSON_AddObject(pIce, pItem);
            }
        }
    }

    xbool_t bHasSrpAuth = xstrused(pCfg->auth.sSaltHex) ||
        xstrused(pCfg->auth.sVerifierHex);
    xbool_t bHasKeyAuth = xstrused(pCfg->keyauth.sIdentitySeedB64) ||
        xstrused(pCfg->keyauth.sIdentityPubB64) ||
        pCfg->keyauth.nAuthorizedKeyCount > 0;

    if (bHasSrpAuth || bHasKeyAuth)
    {
        xjson_obj_t *pAuth = XJSON_GetOrCreateObject(pRoot, "auth", 1);
        if (pAuth != NULL && bHasSrpAuth)
        {
            xjson_obj_t *pSrp = XJSON_GetOrCreateObject(pAuth, "srp", 1);
            if (pSrp != NULL)
            {
                if (xstrused(pCfg->auth.sVerifierHex))
                    XJSON_AddString(pSrp, "verifier", pCfg->auth.sVerifierHex);
                if (xstrused(pCfg->auth.sSaltHex))
                    XJSON_AddString(pSrp, "salt", pCfg->auth.sSaltHex);
                if (pCfg->auth.nSuite != XSTDNON)
                    XJSON_AddU32(pSrp, "suite", pCfg->auth.nSuite);
            }
        }

        if (pAuth != NULL && bHasKeyAuth)
        {
            xjson_obj_t *pKeyAuth = XJSON_GetOrCreateObject(pAuth, "key", 1);
            if (pKeyAuth != NULL)
            {
                if (xstrused(pCfg->keyauth.sIdentitySeedB64) ||
                    xstrused(pCfg->keyauth.sIdentityPubB64))
                {
                    xjson_obj_t *pIdentity = XJSON_GetOrCreateObject(pKeyAuth, "agentIdentity", 1);
                    if (pIdentity != NULL)
                    {
                        if (xstrused(pCfg->keyauth.sIdentitySeedB64))
                            XJSON_AddString(pIdentity, "seed", pCfg->keyauth.sIdentitySeedB64);
                        if (xstrused(pCfg->keyauth.sIdentityPubB64))
                            XJSON_AddString(pIdentity, "pub", pCfg->keyauth.sIdentityPubB64);
                    }
                }

                if (pCfg->keyauth.nAuthorizedKeyCount > 0)
                {
                    xjson_obj_t *pKeys = XJSON_GetOrCreateArray(pKeyAuth, "authorizedKeys", 1);
                    if (pKeys != NULL)
                    {
                        for (uint8_t i = 0; i < pCfg->keyauth.nAuthorizedKeyCount; i++)
                        {
                            const char *pKey = pCfg->keyauth.sAuthorizedKeys[i];
                            if (!xstrused(pKey)) continue;

                            xjson_obj_t *pItem = XJSON_NewString(pKeys->pPool, NULL, pKey);
                            if (pItem != NULL) XJSON_AddObject(pKeys, pItem);
                        }
                    }
                }
            }
        }
    }

    if (xstrused(pCfg->sShellUser) || xstrused(pCfg->sShellHome))
    {
        xjson_obj_t *pShell = XJSON_GetOrCreateObject(pRoot, "shell", 1);
        if (pShell != NULL)
        {
            if (xstrused(pCfg->sShellUser)) XJSON_AddString(pShell, "user", pCfg->sShellUser);
            if (xstrused(pCfg->sShellHome)) XJSON_AddString(pShell, "home", pCfg->sShellHome);
        }
    }

    if (xstrused(pCfg->enroll.sApiUrl) ||
        xstrused(pCfg->enroll.sAccessToken) ||
        xstrused(pCfg->enroll.sRefreshToken) ||
        xstrused(pCfg->enroll.sEnrollExpiresAt) ||
        pCfg->enroll.nAccessTokenExp > 0 ||
        pCfg->enroll.nRefreshTokenExp > 0 ||
        pCfg->enroll.nRefreshSkewSec > 0 ||
        pCfg->enroll.bEnrolled)
    {
        xjson_obj_t *pEnroll = XJSON_GetOrCreateObject(pRoot, "enrollment", 1);
        if (pEnroll != NULL)
        {
            if (xstrused(pCfg->enroll.sApiUrl))
                XJSON_AddString(pEnroll, "apiUrl", pCfg->enroll.sApiUrl);

            if (xstrused(pCfg->enroll.sAccessToken))
                XJSON_AddString(pEnroll, "accessToken", pCfg->enroll.sAccessToken);

            if (xstrused(pCfg->enroll.sRefreshToken))
                XJSON_AddString(pEnroll, "refreshToken", pCfg->enroll.sRefreshToken);

            if (xstrused(pCfg->enroll.sEnrollExpiresAt))
                XJSON_AddString(pEnroll, "enrollmentExpiresAt", pCfg->enroll.sEnrollExpiresAt);

            if (pCfg->enroll.nAccessTokenExp > 0)
            {
                char sExp[32];
                snprintf(sExp, sizeof(sExp), "%" PRIu64, pCfg->enroll.nAccessTokenExp);
                XJSON_AddString(pEnroll, "accessTokenExp", sExp);
            }

            if (pCfg->enroll.nRefreshTokenExp > 0)
            {
                char sExp[32];
                snprintf(sExp, sizeof(sExp), "%" PRIu64, pCfg->enroll.nRefreshTokenExp);
                XJSON_AddString(pEnroll, "refreshTokenExp", sExp);
            }

            XJSON_AddU16(pEnroll, "refreshSkewSec", pCfg->enroll.nRefreshSkewSec);
            XJSON_AddBool(pEnroll, "enrolled", pCfg->enroll.bEnrolled);
        }
    }

    DirectGate_LogSave(&pCfg->log, pRoot);
    size_t nLength = 0;
    char *pDump;

    pDump = XJSON_DumpObj(pRoot, 2, &nLength);
    XJSON_FreeObject(pRoot);

    XCHECK((pDump != NULL), xthrowr(XFALSE, "Failed to serialize config to JSON"));
    XCHECK((nLength > 0), xthrowr(XFALSE, "Invalid serialized config JSON length"));

    xbool_t bOk = DirectGate_WritePrivateFile(pCfg->sCfgPath, (uint8_t*)pDump, nLength);
    free(pDump);

    return bOk;
}

static xbool_t DirectGate_FindConfigArg(int argc, char *argv[], directgate_cfg_t *pCfg, xbool_t *pExplicit)
{
    XCHECK((pCfg != NULL), XFALSE);
    XCHECK((pExplicit != NULL), XFALSE);
    *pExplicit = XFALSE;

    char *pSavedOptarg = optarg;
    int nSavedOptind = optind;
    int nSavedOpterr = opterr;
    int nSavedOptopt = optopt;
    int nChar = XSTDNON;

    optind = 1;
    opterr = 0;
    while ((nChar = getopt(argc, argv, ":" DIRECTGATE_HOST_OPTSTRING)) != -1)
    {
        if (nChar == 'c')
        {
            xstrncpy(pCfg->sCfgPath, sizeof(pCfg->sCfgPath), optarg);
            *pExplicit = XTRUE;
            break;
        }

        if (nChar == ':' && optopt == 'c')
        {
            optind = nSavedOptind;
            opterr = nSavedOpterr;
            optarg = pSavedOptarg;
            optopt = nSavedOptopt;
            return XFALSE;
        }
    }

    optind = nSavedOptind;
    opterr = nSavedOpterr;
    optarg = pSavedOptarg;
    optopt = nSavedOptopt;
    return XTRUE;
}

static xbool_t DirectGate_ArgsAllowMissingConfig(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++)
    {
        const char *pArg = argv[i];
        if (!xstrused(pArg)) continue;
        if (xstrcmp(pArg, "--")) break;
        if (pArg[0] != '-' || pArg[1] == XSTR_NUL) continue;
        if (pArg[1] == '-') continue;

        for (size_t j = 1; pArg[j] != XSTR_NUL; j++)
        {
            char ch = pArg[j];
            if (ch == 'e' || ch == 'i') return XTRUE;

            if (ch == 'a' || ch == 'c' || ch == 'd' || ch == 'g' ||
                ch == 'l' || ch == 't' || ch == 'v' || ch == 'w')
            {
                if (pArg[j + 1] == XSTR_NUL && i + 1 < argc)
                    i++;

                break;
            }
        }
    }

    return XFALSE;
}

xbool_t DirectGate_ParseArgs(directgate_cfg_t *pCfg, int argc, char *argv[])
{
    DirectGate_InitConfig(pCfg);
    xbool_t bConfigLoaded = XFALSE;
    xbool_t bExplicit = XFALSE;
    int nChar = XSTDNON;

    if (!DirectGate_FindConfigArg(argc, argv, pCfg, &bExplicit))
        return XFALSE;

    xbool_t bConfigExists = XPath_Exists(pCfg->sCfgPath);
    if (bConfigExists || (bExplicit && !DirectGate_ArgsAllowMissingConfig(argc, argv)))
    {
        if (!DirectGate_LoadConfig(pCfg, pCfg->sCfgPath)) return XFALSE;
        bConfigLoaded = XTRUE;
    }

    optind = 1;
    while ((nChar = getopt(argc, argv, DIRECTGATE_HOST_OPTSTRING)) != -1)
    {
        switch (nChar)
        {
            case 'w':
                xstrncpy(pCfg->sRelayUrl, sizeof(pCfg->sRelayUrl), optarg);
                break;
            case 'd':
                xstrncpy(pCfg->sDeviceId, sizeof(pCfg->sDeviceId), optarg);
                break;
            case 't':
                xstrncpy(pCfg->sPairingToken, sizeof(pCfg->sPairingToken), optarg);
                break;
            case 'l':
                xstrncpy(pCfg->log.sPath, sizeof(pCfg->log.sPath), optarg);
                break;
            case 'g':
                xstrncpy(pCfg->sGenKeyPath, sizeof(pCfg->sGenKeyPath), optarg);
                pCfg->bGenKey = XTRUE;
                break;
            case 'a':
                xstrncpy(pCfg->sEnrollKeyPath, sizeof(pCfg->sEnrollKeyPath), optarg);
                pCfg->bEnrollKey = XTRUE;
                break;
            case 'v':
                pCfg->nVerbose = (uint16_t)atoi(optarg);
                break;
            case 'e':
                pCfg->bEnroll = XTRUE;
                break;
            case 'r':
                pCfg->bRotateAgentKey = XTRUE;
                break;
            case 's':
                pCfg->bSetSRP = XTRUE;
                break;
            case 'i':
                pCfg->bInit = XTRUE;
                break;
            case 'c':
                break;
            case 'h':
            default:
                DirectGate_DisplayUsage(argv[0]);
                pCfg->bHelp = XTRUE;
                return XFALSE;
        }
    }

    if (pCfg->nVerbose != XSTDNON)
    {
        pCfg->log.bToScreen = XTRUE;
        pCfg->log.nFlags = XLOG_FATAL | XLOG_ERROR;
        pCfg->log.nFlags |= XLOG_WARN | XLOG_NONE;

        if (pCfg->nVerbose > 1) pCfg->log.nFlags |= XLOG_NOTE;
        if (pCfg->nVerbose > 2) pCfg->log.nFlags |= XLOG_INFO;
        if (pCfg->nVerbose > 3) pCfg->log.nFlags |= XLOG_DEBUG;
        if (pCfg->nVerbose > 4) pCfg->log.nFlags |= XLOG_TRACE;

        if (pCfg->nVerbose > 1) pCfg->log.bLogRTC = XTRUE;
        pCfg->log.nRTCLevel = DirectGate_LogGetRTCLevel(&pCfg->log);

        xlog_setfl(pCfg->log.nFlags);
        xlog_screen(XTRUE);
    }

    if (pCfg->bEnroll ||
        pCfg->bSetSRP ||
        pCfg->bGenKey ||
        pCfg->bEnrollKey ||
        pCfg->bRotateAgentKey)
    {
        if (pCfg->bEnroll) return XTRUE;
        if (bConfigLoaded) return XTRUE;
        return DirectGate_LoadConfig(pCfg, pCfg->sCfgPath);
    }

    if (pCfg->bInit)
    {
        xlog_timing(XLOG_DISABLE);
        if (!DirectGate_PromptRelayUrl(pCfg)) return XFALSE;
        if (!DirectGate_PromptDeviceId(pCfg)) return XFALSE;
        if (!DirectGate_PromptAuth(pCfg, XTRUE)) return XFALSE;

        if (!DirectGate_PromptU16("KA Interval", &pCfg->nKAInterval)) return XFALSE;
        if (!DirectGate_PromptBool("Log to screen", &pCfg->log.bToScreen)) return XFALSE;
        if (!DirectGate_PromptBool("Log to file", &pCfg->log.bToFile)) return XFALSE;

        if (pCfg->log.bToFile)
        {
            if (!DirectGate_PromptString("Log path", pCfg->log.sPath,
                sizeof(pCfg->log.sPath), pCfg->log.sPath, XFALSE))
                return XFALSE;
        }

        if (!DirectGate_PromptString("Shell user", pCfg->sShellUser,
            sizeof(pCfg->sShellUser), pCfg->sShellUser, XFALSE))
            return XFALSE;

        if (!DirectGate_PromptString("Shell home", pCfg->sShellHome,
            sizeof(pCfg->sShellHome), pCfg->sShellHome, XFALSE))
            return XFALSE;

        if (!DirectGate_SaveConfig(pCfg))
        {
            xloge("Failed to create initial agent config: cfg(%s), dev(%s), relay(%s)",
                pCfg->sCfgPath, pCfg->sDeviceId, pCfg->sRelayUrl);
            return XFALSE;
        }

        return XTRUE;
    }

    if (!xstrused(pCfg->sRelayUrl) && !DirectGate_PromptRelayUrl(pCfg))
    {
        xloge("Relay URL is not configured: cfg(%s), dev(%s)", pCfg->sCfgPath, pCfg->sDeviceId);
        return XFALSE;
    }

    if (!xstrused(pCfg->sDeviceId) && !DirectGate_PromptDeviceId(pCfg))
    {
        xloge("Device id is not configured: cfg(%s), relay(%s)", pCfg->sCfgPath, pCfg->sRelayUrl);
        return XFALSE;
    }

    if (!DirectGate_PromptAuth(pCfg, XFALSE))
    {
        xloge("Failed to prepare SRP auth credentials: cfg(%s), dev(%s)", pCfg->sCfgPath, pCfg->sDeviceId);
        return XSTDERR;
    }

    if (!DirectGate_AuthIsConfigured(&pCfg->auth))
    {
        xloge("SRP auth is not configured: cfg(%s), dev(%s)", pCfg->sCfgPath, pCfg->sDeviceId);
        return XSTDERR;
    }

    if (!DirectGate_Enroll_IsEnrolled(pCfg))
    {
        xloge("Agent is not enrolled or routing data is missing: dev(%s), cfg(%s)", pCfg->sDeviceId, pCfg->sCfgPath);
        return XSTDERR;
    }

    return XTRUE;
}

XSTATUS DirectGate_ApplyConfig(const directgate_cfg_t *pCfg)
{
    XCHECK((pCfg != NULL), XSTDERR);
    if (pCfg->bInit) return XSTDNON;

    if (pCfg->bEnroll)
    {
        xlog_timing(XLOG_DISABLE);
        if (DirectGate_EnrollFromPrompt(pCfg) != XSTDOK) return XSTDERR;
        return XSTDNON;
    }

    if (pCfg->bSetSRP)
    {
        directgate_cfg_t cfg = *pCfg;
        xlog_timing(XLOG_DISABLE);
        if (DirectGate_StoreAuthFromPrompt(&cfg) != XSTDOK) return XSTDERR;
        return XSTDNON;
    }

    if (pCfg->bGenKey)
    {
        xlog_timing(XLOG_DISABLE);
        if (DirectGate_GenKeyFile(pCfg) != XSTDOK) return XSTDERR;
        return XSTDNON;
    }

    if (pCfg->bEnrollKey)
    {
        xlog_timing(XLOG_DISABLE);
        if (DirectGate_EnrollKeyFile(pCfg) != XSTDOK) return XSTDERR;
        return XSTDNON;
    }

    if (pCfg->bRotateAgentKey)
    {
        xlog_timing(XLOG_DISABLE);
        if (DirectGate_RotateagentIdentity(pCfg) != XSTDOK) return XSTDERR;
        return XSTDNON;
    }

    DirectGate_LogApply(&pCfg->log);
    return XSTDOK;
}
