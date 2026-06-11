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
#define DIRECTGATE_SIGNALING_URL    "wss://directgate.io/websock"

void DirectGate_DisplayUsage(const char *pName)
{
    printf("Usage: %s [options]\n\n", pName);
    printf("Options are:\n");
    printf("  -n <name>            # Device name for device ID\n");
    printf("  -w <url>             # WebSocket signaling URL\n");
    printf("  -d <id>              # Device ID for this client\n");
    printf("  -c <path>            # Config JSON path\n");
    printf("  -p <path>            # Device list file path\n");
    printf("  -l <path>            # Log directory path\n");
    printf("  -v <level>           # Verbose level (0-5)\n");
    printf("  -f                   # Force overwrite device in list\n");
    printf("  -s                   # Save device in the list file\n");
    printf("  -i                   # Init config and exit\n");
    printf("  -h                   # Version and usage\n\n");
}

static void DirectGate_SetDefaultConfigPath(directgate_cfg_t *pCfg)
{
#ifdef _WIN32
    /* Windows convention: per-user roaming application data. Forward
       slashes keep the paths JSON-safe wherever they get serialized. */
    const char *pAppData = getenv("APPDATA");
    if (xstrused(pAppData))
    {
        xstrncpyf(pCfg->sCfgPath, sizeof(pCfg->sCfgPath),
            "%s/directgate/client.json", pAppData);
        xstrncpyf(pCfg->sDeviceList, sizeof(pCfg->sDeviceList),
            "%s/directgate/devices", pAppData);

        DirectGate_PathToSlash(pCfg->sCfgPath);
        DirectGate_PathToSlash(pCfg->sDeviceList);
        return;
    }
#endif

    char sHomeDir[XPATH_MAX];
    DirectGate_GetHomeDir(sHomeDir, sizeof(sHomeDir));

    if (!xstrused(sHomeDir))
    {
        xstrncpy(pCfg->sCfgPath, sizeof(pCfg->sCfgPath), "./client.json");
        xstrncpyf(pCfg->sDeviceList, sizeof(pCfg->sDeviceList), "./devices");
    }
    else
    {
        xstrncpyf(pCfg->sCfgPath, sizeof(pCfg->sCfgPath), "%s/%s", sHomeDir, DIRECTGATE_CLIENT_CONFIG);
        xstrncpyf(pCfg->sDeviceList, sizeof(pCfg->sDeviceList), "%s/%s", sHomeDir, DIRECTGATE_CLIENT_DEVICES);
    }
}

static xbool_t DirectGate_PromptAuth(directgate_cfg_t *pCfg, xbool_t bForce)
{
    XCHECK((pCfg != NULL), XFALSE);

    if (bForce)
    {
        pCfg->sSecret[0] = XSTR_NUL;
        return XTRUE;
    }
    else if (xstrused(pCfg->sDeviceId) && xstrused(pCfg->sSecret))
    {
        xlogd("Client auth is already configured");
        return XTRUE;
    }

    if (XCLI_GetPass("Auth password: ", pCfg->sSecret,
        sizeof(pCfg->sSecret)) <= 0) return XFALSE;

    return XTRUE;
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
    pCfg->nVerbose = XSTDNON;
    pCfg->bSaveDevice = XFALSE;
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

    optind = 1;
    while ((nChar = getopt(argc, argv, "n:d:c:p:l:v:w:f1:s1:ih")) != -1)
    {
        switch (nChar)
        {
            case 'n':
                xstrncpy(pCfg->sDeviceName, sizeof(pCfg->sDeviceName), optarg);
                break;
            case 'w':
                xstrncpy(pCfg->sSignalingUrl, sizeof(pCfg->sSignalingUrl), optarg);
                break;
            case 'd':
                xstrncpy(pCfg->sDeviceId, sizeof(pCfg->sDeviceId), optarg);
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
        if (!DirectGate_PromptSignalingUrl(pCfg)) return XSTDNON;
        if (!DirectGate_PromptDevicesPath(pCfg)) return XSTDNON;
        if (!DirectGate_PromptAuth(pCfg, XTRUE)) return XSTDNON;

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

    xmap_t deviceMap;
    XMap_Init(&deviceMap, NULL, XMAP_INITIAL_SIZE);
    deviceMap.clearCb = DirectGate_ClearDevicePair;

    if (xstrused(pCfg->sDeviceList) &&
        DirectGate_Devices_Load(&deviceMap, pCfg->sDeviceList))
        xlogi("Loaded device list from: %s", pCfg->sDeviceList);

    if (xstrused(pCfg->sDeviceName) && !xstrused(pCfg->sDeviceId) && deviceMap.nCount > 0 &&
        DirectGate_Devices_Search(&deviceMap, pCfg->sDeviceName, pCfg->sDeviceId, sizeof(pCfg->sDeviceId)))
        xlogi("Using device ID from list: %s", pCfg->sDeviceId);

    if (!xstrused(pCfg->sSignalingUrl) && !DirectGate_PromptSignalingUrl(pCfg))
    {
        xloge("Missing signaling URL");
        XMap_Destroy(&deviceMap);
        return XSTDNON;
    }

    if (!xstrused(pCfg->sDeviceId) && !DirectGate_PromptDeviceId(pCfg))
    {
        xloge("Missing device ID");
        XMap_Destroy(&deviceMap);
        return XSTDNON;
    }

    if (pCfg->bSaveDevice)
    {
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

    if (!DirectGate_PromptAuth(pCfg, XFALSE))
    {
        xloge("Failed to get auth credentials");
        return XSTDNON;
    }

    return XSTDOK;
}
