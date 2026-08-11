/*!
 * @file directgate-agent/src/client/config.c
 * @brief Client config and CLI parsing.
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
#include "devices.h"
#include "common.h"
#include "config.h"

extern char *optarg;
extern int optind;

#define DIRECTGATE_CLIENT_CONFIG    ".config/directgate/client.json"
#define DIRECTGATE_CLIENT_DEVICES   ".config/directgate/devices"
#define DIRECTGATE_CLIENT_AUTH      ".config/directgate/auth.json"
#define DIRECTGATE_CLIENT_KEY       ".config/directgate/auth/key.json"
#define DIRECTGATE_SIGNALING_URL    "wss://directgate.io/websock"

/* Control-plane endpoints. Overridable at build time so a self-hosted or
 * staging deployment ships a binary that points at its own stack, and at
 * run time through the matching environment variables. */
#ifndef DIRECTGATE_API_URL
#define DIRECTGATE_API_URL          "https://api.directgate.io"
#endif

#ifndef DIRECTGATE_WEB_URL
#define DIRECTGATE_WEB_URL          "https://directgate.io"
#endif

void DirectGate_DisplayUsage(const char *pName)
{
    printf("Usage: %s [command] [options] [device]\n\n", pName);
    printf("Run without arguments to pick a device from your account and connect.\n");
    printf("A device may also be given by id, exact name or unique name prefix.\n\n");
    printf("Commands are:\n");
    printf("  login                # Sign in through the browser\n");
    printf("  logout               # Forget the stored session\n");
    printf("  devices              # List the devices on your account\n");
    printf("  whoami               # Show the signed in account\n\n");
    printf("Options are:\n");
    printf("  -d <id|name>         # Device to connect to\n");
    printf("  -k <path>            # Client key file, tried before the password\n");
    printf("  -a <url>             # API base URL\n");
    printf("  -w <url>             # WebSocket signaling URL\n");
    printf("  -c <path>            # Config JSON path\n");
    printf("  -p <path>            # Device list file path\n");
    printf("  -n <name>            # Device name for the local device list\n");
    printf("  -l <path>            # Log directory path\n");
    printf("  -v <level>           # Verbose level (0-5)\n");
    printf("  -g                   # Generate a client key and exit\n");
    printf("  -B                   # Sign in without opening a browser\n");
    printf("  -f                   # Force overwrite device in list\n");
    printf("  -s                   # Save device in the list file\n");
    printf("  -i                   # Init config and exit\n");
    printf("  -h                   # Version and usage\n\n");
}

xbool_t DirectGate_ParseCommand(const char *pArg, directgate_cmd_t *pCommand)
{
    XCHECK_NL((xstrused(pArg) && pCommand != NULL), XFALSE);

    if (!strcmp(pArg, "login")) *pCommand = DIRECTGATE_CMD_LOGIN;
    else if (!strcmp(pArg, "logout")) *pCommand = DIRECTGATE_CMD_LOGOUT;
    else if (!strcmp(pArg, "devices") || !strcmp(pArg, "ls")) *pCommand = DIRECTGATE_CMD_DEVICES;
    else if (!strcmp(pArg, "whoami")) *pCommand = DIRECTGATE_CMD_WHOAMI;
    else return XFALSE;

    return XTRUE;
}

void DirectGate_ApplyEnvConfig(directgate_cfg_t *pCfg)
{
    XCHECK_VOID_NL((pCfg != NULL));

    static const struct {
        const char *pName;
        size_t nOffset;
        size_t nSize;
    } fields[] = {
        { "DIRECTGATE_API_URL", offsetof(directgate_cfg_t, sApiUrl), sizeof(pCfg->sApiUrl) },
        { "DIRECTGATE_WEB_URL", offsetof(directgate_cfg_t, sWebUrl), sizeof(pCfg->sWebUrl) }
    };

    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
    {
        const char *pValue = getenv(fields[i].pName);
        if (!xstrused(pValue)) continue;

        xstrncpy((char*)pCfg + fields[i].nOffset, fields[i].nSize, pValue);
    }
}

static void DirectGate_SetDefaultConfigPath(directgate_cfg_t *pCfg)
{
#ifdef _WIN32
    /* Windows convention: per-user roaming application data. Forward
       slashes keep the paths JSON-safe wherever they get serialized. */
    const char *pAppData = getenv("APPDATA");
    if (xstrused(pAppData))
    {
        xstrncpyf(pCfg->sCfgPath, sizeof(pCfg->sCfgPath), "%s/directgate/client.json", pAppData);
        xstrncpyf(pCfg->sDeviceList, sizeof(pCfg->sDeviceList), "%s/directgate/devices", pAppData);
        xstrncpyf(pCfg->sAuthPath, sizeof(pCfg->sAuthPath), "%s/directgate/auth.json", pAppData);
        xstrncpyf(pCfg->sKeyPath, sizeof(pCfg->sKeyPath), "%s/directgate/auth/key.json", pAppData);

        DirectGate_PathToSlash(pCfg->sCfgPath);
        DirectGate_PathToSlash(pCfg->sDeviceList);
        DirectGate_PathToSlash(pCfg->sAuthPath);
        DirectGate_PathToSlash(pCfg->sKeyPath);
        return;
    }
#endif

    char sHomeDir[XPATH_MAX];
    DirectGate_GetHomeDir(sHomeDir, sizeof(sHomeDir));

    if (!xstrused(sHomeDir))
    {
        xstrncpy(pCfg->sCfgPath, sizeof(pCfg->sCfgPath), "./client.json");
        xstrncpyf(pCfg->sDeviceList, sizeof(pCfg->sDeviceList), "./devices");
        xstrncpy(pCfg->sAuthPath, sizeof(pCfg->sAuthPath), "./auth.json");
        xstrncpy(pCfg->sKeyPath, sizeof(pCfg->sKeyPath), "./key.json");
    }
    else
    {
        xstrncpyf(pCfg->sCfgPath, sizeof(pCfg->sCfgPath), "%s/%s", sHomeDir, DIRECTGATE_CLIENT_CONFIG);
        xstrncpyf(pCfg->sDeviceList, sizeof(pCfg->sDeviceList), "%s/%s", sHomeDir, DIRECTGATE_CLIENT_DEVICES);
        xstrncpyf(pCfg->sAuthPath, sizeof(pCfg->sAuthPath), "%s/%s", sHomeDir, DIRECTGATE_CLIENT_AUTH);
        xstrncpyf(pCfg->sKeyPath, sizeof(pCfg->sKeyPath), "%s/%s", sHomeDir, DIRECTGATE_CLIENT_KEY);
    }
}

static xbool_t DirectGate_PromptApiUrl(directgate_cfg_t *pCfg)
{
    return DirectGate_PromptString("API URL", pCfg->sApiUrl,
        sizeof(pCfg->sApiUrl), DIRECTGATE_API_URL, XTRUE);
}

static xbool_t DirectGate_PromptSignalingUrl(directgate_cfg_t *pCfg)
{
    return DirectGate_PromptString("Signaling URL", pCfg->sSignalingUrl,
        sizeof(pCfg->sSignalingUrl), DIRECTGATE_SIGNALING_URL, XTRUE);
}

static xbool_t DirectGate_PromptDevicesPath(directgate_cfg_t *pCfg)
{
    return DirectGate_PromptString("Device list path", pCfg->sDeviceList,
        sizeof(pCfg->sDeviceList), DIRECTGATE_CLIENT_DEVICES, XTRUE);
}

static xbool_t DirectGate_PromptDeviceId(directgate_cfg_t *pCfg)
{
    return DirectGate_PromptString("Device ID", pCfg->sDeviceId,
        sizeof(pCfg->sDeviceId), pCfg->sDeviceId, XTRUE);
}

static xbool_t DirectGate_PromptDeviceName(directgate_cfg_t *pCfg)
{
    return DirectGate_PromptString("Device name", pCfg->sDeviceName,
        sizeof(pCfg->sDeviceName), pCfg->sDeviceName, XTRUE);
}

void DirectGate_InitConfig(directgate_cfg_t *pCfg)
{
    XCHECK_VOID_NL((pCfg != NULL));
    memset(pCfg, 0, sizeof(*pCfg));

    DirectGate_AuthInit(&pCfg->auth);
    DirectGate_LogInit(&pCfg->log, "directgate-client", XLOG_DEFAULT);
    pCfg->log.bToScreen = XTRUE;

    DirectGate_SetDefaultConfigPath(pCfg);

    xstrncpy(pCfg->sApiUrl, sizeof(pCfg->sApiUrl), DIRECTGATE_API_URL);
    xstrncpy(pCfg->sWebUrl, sizeof(pCfg->sWebUrl), DIRECTGATE_WEB_URL);

    pCfg->eCommand = DIRECTGATE_CMD_CONNECT;
    pCfg->nVerbose = XSTDNON;
    pCfg->bSaveDevice = XFALSE;
    pCfg->bNoBrowser = XFALSE;
    pCfg->bKeyRequired = XFALSE;
    pCfg->bGenKey = XFALSE;
    pCfg->bForce = XFALSE;
    pCfg->bInit = XFALSE;
}

xbool_t DirectGate_LoadConfig(directgate_cfg_t *pCfg, const char *pPath)
{
    XCHECK((pCfg != NULL), XFALSE);
    XCHECK((xstrused(pPath)), XFALSE);

    xbyte_buffer_t buffer;
    if (XPath_LoadBuffer(pPath, &buffer) <= 0)
    {
        xloge("Failed to load config: %s (%s)", pPath, XSTRERR);
        return XFALSE;
    }

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, (const char*)buffer.pData, buffer.nUsed))
    {
        char sError[256];
        XJSON_GetErrorStr(&json, sError, sizeof(sError));
        xloge("Failed to parse config: %s (%s)", pPath, sError);

        XByteBuffer_Clear(&buffer);
        XJSON_Destroy(&json);
        return XFALSE;
    }

    xjson_obj_t *pRoot = json.pRootObj;
    const char *pList = XJSON_GetString(XJSON_GetObject(pRoot, "deviceList"));
    if (xstrused(pList)) xstrncpy(pCfg->sDeviceList, sizeof(pCfg->sDeviceList), pList);

    const char *pUrl = XJSON_GetString(XJSON_GetObject(pRoot, "signalingUrl"));
    if (xstrused(pUrl)) xstrncpy(pCfg->sSignalingUrl, sizeof(pCfg->sSignalingUrl), pUrl);

    const char *pRoutingKey = XJSON_GetString(XJSON_GetObject(pRoot, "routingKey"));
    if (xstrused(pRoutingKey)) xstrncpy(pCfg->sRoutingKey, sizeof(pCfg->sRoutingKey), pRoutingKey);

    const char *pAccessToken = XJSON_GetString(XJSON_GetObject(pRoot, "accessToken"));
    if (xstrused(pAccessToken)) xstrncpy(pCfg->sAccessToken, sizeof(pCfg->sAccessToken), pAccessToken);

    const char *pApiUrl = XJSON_GetString(XJSON_GetObject(pRoot, "apiUrl"));
    if (xstrused(pApiUrl)) xstrncpy(pCfg->sApiUrl, sizeof(pCfg->sApiUrl), pApiUrl);

    const char *pApiToken = XJSON_GetString(XJSON_GetObject(pRoot, "apiToken"));
    if (xstrused(pApiToken)) xstrncpy(pCfg->sApiToken, sizeof(pCfg->sApiToken), pApiToken);

    const char *pWebUrl = XJSON_GetString(XJSON_GetObject(pRoot, "webUrl"));
    if (xstrused(pWebUrl)) xstrncpy(pCfg->sWebUrl, sizeof(pCfg->sWebUrl), pWebUrl);

    const char *pAuthPath = XJSON_GetString(XJSON_GetObject(pRoot, "authPath"));
    if (xstrused(pAuthPath)) xstrncpy(pCfg->sAuthPath, sizeof(pCfg->sAuthPath), pAuthPath);

    const char *pKeyPath = XJSON_GetString(XJSON_GetObject(pRoot, "keyPath"));
    if (xstrused(pKeyPath)) xstrncpy(pCfg->sKeyPath, sizeof(pCfg->sKeyPath), pKeyPath);

    DirectGate_LogLoad(&pCfg->log, pRoot);
    DirectGate_AuthLoad(&pCfg->auth, pRoot);
    DirectGate_WebRTC_LoadIceServers(pCfg->sIceServers, &pCfg->nIceSrvCount, pRoot);

    XByteBuffer_Clear(&buffer);
    XJSON_Destroy(&json);
    return XTRUE;
}

static xbool_t DirectGate_SaveConfig(const directgate_cfg_t *pCfg)
{
    XCHECK((pCfg != NULL), XFALSE);
    XCHECK((xstrused(pCfg->sCfgPath)), XFALSE);

    if (!DirectGate_EnsurePrivateFileParent(pCfg->sCfgPath))
    {
        xloge("Failed to create private client config directory: cfg(%s), errno(%d)",
            pCfg->sCfgPath, errno);

        return XFALSE;
    }

    xjson_obj_t *pRoot = XJSON_NewObject(NULL, NULL, 4);
    XCHECK((pRoot != NULL), xthrowr(XFALSE, "Failed to create JSON object for config"));

    if (xstrused(pCfg->sSignalingUrl)) XJSON_AddString(pRoot, "signalingUrl", pCfg->sSignalingUrl);
    if (xstrused(pCfg->sDeviceList)) XJSON_AddString(pRoot, "deviceList", pCfg->sDeviceList);
    if (xstrused(pCfg->sRoutingKey)) XJSON_AddString(pRoot, "routingKey", pCfg->sRoutingKey);
    if (xstrused(pCfg->sAccessToken)) XJSON_AddString(pRoot, "accessToken", pCfg->sAccessToken);
    if (xstrused(pCfg->sApiUrl)) XJSON_AddString(pRoot, "apiUrl", pCfg->sApiUrl);
    if (xstrused(pCfg->sApiToken)) XJSON_AddString(pRoot, "apiToken", pCfg->sApiToken);
    if (xstrused(pCfg->sWebUrl)) XJSON_AddString(pRoot, "webUrl", pCfg->sWebUrl);

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

    DirectGate_LogSave(&pCfg->log, pRoot);

    size_t nLength = 0;
    char *pDump = XJSON_DumpObj(pRoot, 2, &nLength);
    XJSON_FreeObject(pRoot);

    if (pDump == NULL || !nLength) return XFALSE;
    xbool_t bOk = DirectGate_WritePrivateFile(pCfg->sCfgPath, (uint8_t*)pDump, nLength);

    free(pDump);
    return bOk;
}

static void DirectGate_ClearDevicePair(xmap_pair_t *pPair)
{
    XCHECK_VOID_NL((pPair != NULL));

    if (pPair->pKey != NULL)
    {
        free(pPair->pKey);
        pPair->pKey = NULL;
    }

    if (pPair->pData != NULL)
    {
        free(pPair->pData);
        pPair->pData = NULL;
    }
}

XSTATUS DirectGate_ParseArgs(directgate_cfg_t *pCfg, int argc, char *argv[])
{
    DirectGate_InitConfig(pCfg);
    int nChar = XSTDNON;

    if (XPath_Exists(pCfg->sCfgPath))
    {
        if (!DirectGate_LoadConfig(pCfg, pCfg->sCfgPath))
            return XSTDNON;
    }

    for (int i = 1; i + 1 < argc; ++i)
    {
        if (!strcmp(argv[i], "-c") && (i + 1) < argc)
        {
            xstrncpy(pCfg->sCfgPath, sizeof(pCfg->sCfgPath), argv[i + 1]);
            if (!DirectGate_LoadConfig(pCfg, argv[i + 1])) return XSTDNON;
            break;
        }
    }

    DirectGate_ApplyEnvConfig(pCfg);

    /* A leading verb selects the command; everything after it is parsed
     * as usual, so "dgcli login -v 3" and "dgcli laptop" both work. */
    int nFirst = 1;
    if (argc > 1 && DirectGate_ParseCommand(argv[1], &pCfg->eCommand)) nFirst = 2;

    optind = nFirst;
    while ((nChar = getopt(argc, argv, "n:d:a:c:p:l:v:w:k:fgsiBh")) != -1)
    {
        switch (nChar)
        {
            case 'a':
                xstrncpy(pCfg->sApiUrl, sizeof(pCfg->sApiUrl), optarg);
                break;
            case 'n':
                xstrncpy(pCfg->sDeviceName, sizeof(pCfg->sDeviceName), optarg);
                break;
            case 'w':
                xstrncpy(pCfg->sSignalingUrl, sizeof(pCfg->sSignalingUrl), optarg);
                break;
            case 'k':
                xstrncpy(pCfg->sKeyPath, sizeof(pCfg->sKeyPath), optarg);
                pCfg->bKeyRequired = XTRUE;
                break;
            case 'd':
                xstrncpy(pCfg->sDeviceId, sizeof(pCfg->sDeviceId), optarg);
                xstrncpy(pCfg->sDeviceQuery, sizeof(pCfg->sDeviceQuery), optarg);
                break;
            case 'p':
                xstrncpy(pCfg->sDeviceList, sizeof(pCfg->sDeviceList), optarg);
                break;
            case 'l':
                xstrncpy(pCfg->log.sPath, sizeof(pCfg->log.sPath), optarg);
                break;
            case 'v':
                pCfg->nVerbose = (uint16_t)atoi(optarg);
                break;
            case 'B':
                pCfg->bNoBrowser = XTRUE;
                break;
            case 'g':
                pCfg->bGenKey = XTRUE;
                break;
            case 's':
                pCfg->bSaveDevice = XTRUE;
                break;
            case 'f':
                pCfg->bForce = XTRUE;
                break;
            case 'i':
                pCfg->bInit = XTRUE;
                break;
            case 'c':
                break;
            case 'h':
            default:
                return XSTDERR;
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

        xlog_setfl(pCfg->log.nFlags);
        xlog_screen(XTRUE);
    }

    if (pCfg->bInit)
    {
        if (!DirectGate_PromptApiUrl(pCfg)) return XSTDNON;
        if (!DirectGate_PromptSignalingUrl(pCfg)) return XSTDNON;
        if (!DirectGate_PromptDevicesPath(pCfg)) return XSTDNON;

        if (!DirectGate_PromptBool("Log to screen", &pCfg->log.bToScreen)) return XSTDNON;
        if (!DirectGate_PromptBool("Log to file", &pCfg->log.bToFile)) return XSTDNON;

        if (pCfg->log.bToFile)
        {
            if (!DirectGate_PromptString("Log path", pCfg->log.sPath,
                sizeof(pCfg->log.sPath), pCfg->log.sPath, XFALSE))
                return XSTDNON;
        }

        if (!DirectGate_SaveConfig(pCfg))
        {
            xloge("Failed to create config: %s", pCfg->sCfgPath);
            return XSTDNON;
        }

        return XSTDNON;
    }

    DirectGate_LogApply(&pCfg->log);

    /* Whatever is left after the options is the device to connect to */
    if (optind < argc && xstrused(argv[optind]))
        xstrncpy(pCfg->sDeviceQuery, sizeof(pCfg->sDeviceQuery), argv[optind]);

    xmap_t deviceMap;
    XMap_Init(&deviceMap, NULL, XMAP_INITIAL_SIZE);
    deviceMap.clearCb = DirectGate_ClearDevicePair;

    if (xstrused(pCfg->sDeviceList) &&
        DirectGate_Devices_Load(&deviceMap, pCfg->sDeviceList))
        xlogi("Loaded device list from: %s", pCfg->sDeviceList);

    if (xstrused(pCfg->sDeviceName) && !xstrused(pCfg->sDeviceId) && deviceMap.nCount > 0 &&
        DirectGate_Devices_Search(&deviceMap, pCfg->sDeviceName, pCfg->sDeviceId, sizeof(pCfg->sDeviceId)))
        xlogi("Using device ID from list: %s", pCfg->sDeviceId);

    if (pCfg->bSaveDevice)
    {
        if (!xstrused(pCfg->sDeviceId) && !DirectGate_PromptDeviceId(pCfg))
        {
            xloge("Missing device ID");
            XMap_Destroy(&deviceMap);
            return XSTDNON;
        }

        if (!xstrused(pCfg->sDeviceName) && !DirectGate_PromptDeviceName(pCfg))
        {
            xloge("Missing device name");
            XMap_Destroy(&deviceMap);
            return XSTDNON;
        }

        if (!xstrused(pCfg->sDeviceList) && !DirectGate_PromptDevicesPath(pCfg))
        {
            xloge("Missing device list path");
            XMap_Destroy(&deviceMap);
            return XSTDNON;
        }

        if (!DirectGate_Devices_Add(&deviceMap, pCfg->sDeviceName, pCfg->sDeviceId, pCfg->bForce))
        {
            xloge("Failed to add device to list: %s", pCfg->sDeviceList);
            XMap_Destroy(&deviceMap);
            return XSTDNON;
        }

        if (!DirectGate_Devices_Write(&deviceMap, pCfg->sDeviceList))
        {
            xloge("Failed to save device list: %s", pCfg->sDeviceList);
            XMap_Destroy(&deviceMap);
            return XSTDNON;
        }

        XMap_Destroy(&deviceMap);
        return XSTDNON;
    }

    // No longer needed
    XMap_Destroy(&deviceMap);

    /* The device secret is only prompted for once a device is actually
     * chosen, which happens after the account device list is fetched. */
    return XSTDOK;
}

xbool_t DirectGate_PromptDeviceSecret(directgate_cfg_t *pCfg, const char *pDeviceName)
{
    XCHECK((pCfg != NULL), XFALSE);
    if (xstrused(pCfg->sSecret)) return XTRUE;

    char sPrompt[XSTR_TINY];
    xstrncpyf(sPrompt, sizeof(sPrompt), "Password for %s: ", xstrused(pDeviceName) ? pDeviceName : "device");

    return XCLI_GetPass(sPrompt, pCfg->sSecret, sizeof(pCfg->sSecret)) > 0 ? XTRUE : XFALSE;
}
