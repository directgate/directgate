/*!
 * @file directgate-agent/src/client/devices.c
 * @brief Client devices management.
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
#include "webapi.h"
#include "devices.h"

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

typedef enum {
    XPICK_NONE = 0,
    XPICK_UP,
    XPICK_DOWN,
    XPICK_HOME,
    XPICK_END,
    XPICK_ENTER,
    XPICK_QUIT
} directgate_pick_key_t;

#define DIRECTGATE_PICK_MIN_ROWS    3

static xbool_t DirectGate_ParseDeviceLine(const char *pLine,
                                          char *pNameOut, size_t nNameOutSize,
                                          char *pIdOut, size_t nIdOutSize)
{
    XCHECK_NL((pLine != NULL), XFALSE);
    XCHECK_NL((pNameOut != NULL), XFALSE);
    XCHECK_NL((pIdOut != NULL), XFALSE);
    XCHECK_NL((nNameOutSize > 0), XFALSE);
    XCHECK_NL((nIdOutSize > 0), XFALSE);

    pNameOut[0] = '\0';
    pIdOut[0] = '\0';

    const char *ptr = DirectGate_JumpWiteSpace(pLine);
    if (*ptr == '\0') return XFALSE;

    const char *pNameBeg = ptr;
    const char *pNameEnd = DirectGate_SkipToken(pNameBeg);
    size_t nNameLen = (size_t)(pNameEnd - pNameBeg);
    if (!nNameLen || nNameLen + 1 > nNameOutSize) return XFALSE;

    memcpy(pNameOut, pNameBeg, nNameLen);
    pNameOut[nNameLen] = '\0';

    ptr = DirectGate_JumpWiteSpace(pNameEnd);
    if (*ptr == '\0') return XFALSE;

    const char *pIdBeg = ptr;
    const char *pIdEnd = DirectGate_SkipToken(pIdBeg);
    size_t nIdLen = (size_t)(pIdEnd - pIdBeg);
    if (!nIdLen || nIdLen + 1 > nIdOutSize) return XFALSE;

    memcpy(pIdOut, pIdBeg, nIdLen);
    pIdOut[nIdLen] = '\0';

    DirectGate_TrimStringRight(pNameOut);
    DirectGate_TrimStringRight(pIdOut);

    return XTRUE;
}

xbool_t DirectGate_Devices_Add(xmap_t *pMap, const char *pDeviceName, const char *pDeviceId, xbool_t bForce)
{
    XCHECK((pMap != NULL), XFALSE);
    XCHECK_NL((xstrused(pDeviceName)), XFALSE);
    XCHECK_NL((xstrused(pDeviceId)), XFALSE);

    xmap_pair_t *pExisting = XMap_GetPair(pMap, pDeviceName);
    if (pExisting != NULL)
    {
        if (!bForce)
        {
            xloge("Duplicate device name in list: %s", pDeviceName);
            return XFALSE;
        }

        // Remove existing entry to allow overwriting with new ID
        XMap_Remove(pMap, pDeviceName);
    }

    char *pNameCopy = xstrdup(pDeviceName);
    char *pIdCopy = xstrdup(pDeviceId);

    if (pNameCopy == NULL || pIdCopy == NULL)
    {
        free(pNameCopy);
        free(pIdCopy);

        xloge("Failed to duplicate device entry: %s  %s", pDeviceName, pDeviceId);
        return XFALSE;
    }

    if (XMap_Put(pMap, pNameCopy, pIdCopy) != XMAP_OK)
    {
        free(pNameCopy);
        free(pIdCopy);

        xloge("Failed to add device to map: %s  %s", pDeviceName, pDeviceId);
        return XFALSE;
    }

    return XTRUE;
}

xbool_t DirectGate_Devices_Load(xmap_t *pMap, const char *pPath)
{
    XCHECK((pMap != NULL), XFALSE);
    XCHECK_NL((xstrused(pPath)), XFALSE);
    XCHECK_NL((XPath_Exists(pPath)), XFALSE);

    xfile_t file;
    XCHECK_NL((XFile_Open(&file, pPath, "r", NULL) >= 0),
        xthrowr(XFALSE, "Failed to open device list: %s (%s)", pPath, XSTRERR));

    char sLine[XLINE_MAX];
    while (XFile_GetLine(&file, sLine, sizeof(sLine)) > 0)
    {
        char sDeviceName[XSTR_TINY];
        char sDeviceId[XSTR_TINY];

        xbool_t bParsed = DirectGate_ParseDeviceLine(sLine,
            sDeviceName, sizeof(sDeviceName),
            sDeviceId, sizeof(sDeviceId));

        if (bParsed && !DirectGate_Devices_Add(pMap, sDeviceName, sDeviceId, XTRUE))
        {
            xloge("Failed to add device from list: %s  %s", sDeviceName, sDeviceId);
            continue;
        }
    }

    XFile_Close(&file);
    return pMap->nCount ? XTRUE : XFALSE;
}

static int DirectGate_Devices_WriteIt(xmap_pair_t *pPair, void *pContext)
{
    xfile_t *pFile = (xfile_t*)pContext;
    const char *pName = pPair->pKey;
    const char *pId = (const char*)pPair->pData;

    char sLine[XLINE_MAX];
    size_t nLineLen = xstrncpyf(sLine, sizeof(sLine), "%s  %s\n", pName, pId);
    if (!nLineLen || XFile_Write(pFile, sLine, nLineLen) <= 0) return XMAP_STOP;

    return XMAP_OK;
}

xbool_t DirectGate_Devices_Write(xmap_t *pMap, const char *pPath)
{
    XCHECK((pMap != NULL), XFALSE);
    XCHECK_NL((xstrused(pPath)), XFALSE);
    XCHECK_NL((pMap->nCount > 0), XFALSE);

    xfile_t file;
    XCHECK((XFile_Open(&file, pPath, "cwt", NULL) >= 0),
        xthrowr(XFALSE, "Failed to open device list for writing: %s (%s)", pPath, XSTRERR));

    XMap_Iterate(pMap, DirectGate_Devices_WriteIt, &file);
    XFile_Close(&file);
    return XTRUE;
}

xbool_t DirectGate_Devices_Search(xmap_t *pMap, const char *pDeviceName, char *pDeviceId, size_t nIdSize)
{
    XCHECK((pMap != NULL), XFALSE);
    XCHECK_NL((xstrused(pDeviceName)), XFALSE);

    xmap_pair_t *pPair = XMap_GetPair(pMap, pDeviceName);
    if (pPair == NULL) return XFALSE;

    const char *pId = (const char*)pPair->pData;
    if (!xstrused(pId))
    {
        xloge("Invalid device ID for device '%s'", pDeviceName);
        return XFALSE;
    }

    xstrncpy(pDeviceId, nIdSize, pId);
    return XTRUE;
}

static xbool_t DirectGate_Devices_Connectable(xjson_obj_t *pItem, char *pReason, size_t nReasonSize)
{
    const char *pStatus = XJSON_GetString(XJSON_GetObject(pItem, "status"));
    const char *pEnroll = XJSON_GetString(XJSON_GetObject(pItem, "enrollmentStatus"));
    const char *pShare = XJSON_GetString(XJSON_GetObject(pItem, "shareStatus"));

    xjson_obj_t *pPairing = XJSON_GetObject(pItem, "requiresPairing");
    xbool_t bRequiresPairing = pPairing != NULL ? XJSON_GetBool(pPairing) : XFALSE;

    const char *pWhy = NULL;

    if (xstrused(pShare) && !strcmp(pShare, "PENDING")) pWhy = "invite pending";
    else if (!xstrused(pStatus) || strcmp(pStatus, "PAIRED")) pWhy = "not paired";
    else if (xstrused(pEnroll) && !strcmp(pEnroll, "EXPIRED")) pWhy = "enrollment expired";
    else if (!xstrused(pEnroll) || (strcmp(pEnroll, "ACTIVE") && strcmp(pEnroll, "EXTENDED"))) pWhy = "enrollment inactive";
    else if (bRequiresPairing) pWhy = "needs re-pairing";

    if (pReason != NULL && nReasonSize)
        xstrncpy(pReason, nReasonSize, pWhy != NULL ? pWhy : "");

    return pWhy == NULL ? XTRUE : XFALSE;
}

xbool_t DirectGate_Devices_ParseList(directgate_device_list_t *pList, xjson_obj_t *pRoot)
{
    XCHECK((pList != NULL), XFALSE);
    memset(pList, 0, sizeof(*pList));
    XCHECK((pRoot != NULL), XFALSE);

    xjson_obj_t *pDevices = XJSON_GetObject(pRoot, "devices");
    XCHECK((pDevices != NULL && pDevices->nType == XJSON_TYPE_ARRAY),
        xthrowr(XFALSE, "Device list response has no devices array"));

    size_t nItems = XJSON_GetArrayLength(pDevices);

    for (size_t i = 0; i < nItems && pList->nCount < DIRECTGATE_DEVICES_MAX; i++)
    {
        xjson_obj_t *pItem = XJSON_GetArrayItem(pDevices, i);
        if (pItem == NULL) continue;

        const char *pId = XJSON_GetString(XJSON_GetObject(pItem, "id"));
        if (!xstrused(pId)) continue;

        /* Hard-revoked devices are gone for good and the workspace hides
         * them too, so they never reach the picker. */
        const char *pRevoked = XJSON_GetString(XJSON_GetObject(pItem, "revokedAt"));
        if (xstrused(pRevoked)) continue;

        directgate_device_t *pDevice = &pList->devices[pList->nCount++];
        memset(pDevice, 0, sizeof(*pDevice));

        const char *pName = XJSON_GetString(XJSON_GetObject(pItem, "name"));
        xstrncpy(pDevice->sId, sizeof(pDevice->sId), pId);
        xstrncpy(pDevice->sName, sizeof(pDevice->sName), xstrused(pName) ? pName : pId);

        xjson_obj_t *pOnline = XJSON_GetObject(pItem, "isOnline");
        xjson_obj_t *pOwner = XJSON_GetObject(pItem, "isOwner");

        pDevice->bOnline = pOnline != NULL ? XJSON_GetBool(pOnline) : XFALSE;
        pDevice->bOwned = pOwner != NULL ? XJSON_GetBool(pOwner) : XTRUE;

        if (!pDevice->bOwned)
        {
            const char *pOwnerEmail = XJSON_GetString(XJSON_GetObject(pItem, "ownerEmail"));
            if (xstrused(pOwnerEmail)) xstrncpy(pDevice->sOwner, sizeof(pDevice->sOwner), pOwnerEmail);
        }

        /* Served over TLS by the API, so this is the authoritative host
         * identity - key auth pins against it and never trusts the key the
         * host presents on the wire. */
        const char *pAgentPub = XJSON_GetString(XJSON_GetObject(pItem, "agentPub"));
        if (xstrused(pAgentPub)) xstrncpy(pDevice->sAgentPub, sizeof(pDevice->sAgentPub), pAgentPub);

        pDevice->bConnectable = DirectGate_Devices_Connectable(pItem, pDevice->sReason, sizeof(pDevice->sReason));
    }

    return XTRUE;
}

xbool_t DirectGate_Devices_Fetch(directgate_device_list_t *pList,
                                 const char *pApiUrl,
                                 const char *pAccessToken,
                                 char *pErr, size_t nErrSize)
{
    XCHECK((pList != NULL), XFALSE);
    memset(pList, 0, sizeof(*pList));

    if (pErr != NULL && nErrSize) pErr[0] = XSTR_NUL;
    XCHECK((xstrused(pApiUrl) && xstrused(pAccessToken)), XFALSE);

    directgate_webapi_res_t res;
    xbool_t bOk = DirectGate_WebApi_Request(&res, XHTTP_GET, pApiUrl, "/api/v1/devices", pAccessToken, NULL, NULL);
    if (!bOk)
    {
        if (pErr != NULL && nErrSize) xstrncpy(pErr, nErrSize, res.sError);
        DirectGate_WebApi_Clear(&res);
        return XFALSE;
    }

    bOk = DirectGate_Devices_ParseList(pList, res.pRoot);
    if (!bOk && pErr != NULL && nErrSize) xstrncpy(pErr, nErrSize, "device list response could not be parsed");

    DirectGate_WebApi_Clear(&res);
    return bOk;
}

int DirectGate_Devices_Find(const directgate_device_list_t *pList, const char *pQuery)
{
    XCHECK((pList != NULL), DIRECTGATE_DEVICE_NO_PICK);
    XCHECK_NL((xstrused(pQuery)), DIRECTGATE_DEVICE_NO_PICK);

    for (size_t i = 0; i < pList->nCount; i++)
        if (!strcmp(pList->devices[i].sId, pQuery)) return (int)i;

    for (size_t i = 0; i < pList->nCount; i++)
        if (!strcmp(pList->devices[i].sName, pQuery)) return (int)i;

    size_t nQueryLen = strlen(pQuery);
    int nMatch = DIRECTGATE_DEVICE_NO_PICK;

    for (size_t i = 0; i < pList->nCount; i++)
    {
        if (!xstrncasecmp(pList->devices[i].sName, pQuery, nQueryLen)) continue;

        /* An ambiguous prefix must not silently pick the first hit */
        if (nMatch != DIRECTGATE_DEVICE_NO_PICK) return DIRECTGATE_DEVICE_NO_PICK;
        nMatch = (int)i;
    }

    return nMatch;
}

static const char* DirectGate_Devices_StateText(const directgate_device_t *pDevice)
{
    if (!pDevice->bConnectable)
        return xstrused(pDevice->sReason) ? pDevice->sReason : "unavailable";

    return pDevice->bOnline ? "online" : "offline";
}

void DirectGate_Devices_Print(const directgate_device_list_t *pList)
{
    XCHECK_VOID_NL((pList != NULL));

    for (size_t i = 0; i < pList->nCount; i++)
    {
        const directgate_device_t *pDevice = &pList->devices[i];

        printf("  %-28s  %-18s  %s%s\n", pDevice->sName,
            DirectGate_Devices_StateText(pDevice), pDevice->sId,
            pDevice->bOwned ? "" : " (shared)");
    }
}

#ifdef _WIN32
typedef struct directgate_pick_io_ {
    DWORD nSavedOutMode;
    xbool_t bSavedOut;
} directgate_pick_io_t;

static xbool_t DirectGate_Pick_Enter(directgate_pick_io_t *pIO)
{
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!GetConsoleMode(hStdout, &pIO->nSavedOutMode)) return XFALSE;

    pIO->bSavedOut = XTRUE;
    DWORD nMode = pIO->nSavedOutMode |
        ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING;

    return SetConsoleMode(hStdout, nMode) ? XTRUE : XFALSE;
}

static void DirectGate_Pick_Leave(directgate_pick_io_t *pIO)
{
    if (pIO->bSavedOut) SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), pIO->nSavedOutMode);
    pIO->bSavedOut = XFALSE;
}

static directgate_pick_key_t DirectGate_Pick_ReadKey(void)
{
    int nChar = _getch();

    /* Arrows arrive as a 0x00/0xE0 prefix followed by a scan code */
    if (nChar == 0x00 || nChar == 0xE0)
    {
        switch (_getch())
        {
            case 72: return XPICK_UP;
            case 80: return XPICK_DOWN;
            case 71: return XPICK_HOME;
            case 79: return XPICK_END;
            default: return XPICK_NONE;
        }
    }

    switch (nChar)
    {
        case '\r': case '\n': return XPICK_ENTER;
        case 'k': case 'K': return XPICK_UP;
        case 'j': case 'J': return XPICK_DOWN;
        case 'q': case 'Q': case 0x1B: case 0x03: return XPICK_QUIT;
        default: return XPICK_NONE;
    }
}
#else
typedef struct directgate_pick_io_ {
    struct termios saved;
    xbool_t bSaved;
} directgate_pick_io_t;

static xbool_t DirectGate_Pick_Enter(directgate_pick_io_t *pIO)
{
    if (tcgetattr(STDIN_FILENO, &pIO->saved) < 0) return XFALSE;
    pIO->bSaved = XTRUE;

    struct termios raw = pIO->saved;
    raw.c_lflag &= (tcflag_t)~(ICANON | ECHO);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;

    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) < 0)
    {
        pIO->bSaved = XFALSE;
        return XFALSE;
    }

    return XTRUE;
}

static void DirectGate_Pick_Leave(directgate_pick_io_t *pIO)
{
    if (pIO->bSaved) tcsetattr(STDIN_FILENO, TCSANOW, &pIO->saved);
    pIO->bSaved = XFALSE;
}

static directgate_pick_key_t DirectGate_Pick_ReadKey(void)
{
    char nChar = 0;
    if (read(STDIN_FILENO, &nChar, 1) != 1) return XPICK_QUIT;

    if (nChar == 0x1B)
    {
        /*
            Escape either starts a CSI sequence or is a bare Escape key
            press. Only a sequence has more bytes already buffered, so a
            short non-blocking peek separates the two without blocking on
            a user who just pressed Escape to back out.
        */
        char sSeq[2] = { 0, 0 };
        int nFlags = fcntl(STDIN_FILENO, F_GETFL, 0);

        if (nFlags >= 0) fcntl(STDIN_FILENO, F_SETFL, nFlags | O_NONBLOCK);
        ssize_t nRead = read(STDIN_FILENO, sSeq, sizeof(sSeq));
        if (nFlags >= 0) fcntl(STDIN_FILENO, F_SETFL, nFlags);

        if (nRead < 2 || sSeq[0] != '[') return XPICK_QUIT;

        switch (sSeq[1])
        {
            case 'A': return XPICK_UP;
            case 'B': return XPICK_DOWN;
            case 'H': return XPICK_HOME;
            case 'F': return XPICK_END;
            default: return XPICK_NONE;
        }
    }

    switch (nChar)
    {
        case '\r': case '\n': return XPICK_ENTER;
        case 'k': case 'K': return XPICK_UP;
        case 'j': case 'J': return XPICK_DOWN;
        case 'g': return XPICK_HOME;
        case 'G': return XPICK_END;
        case 'q': case 'Q': case 0x03: case 0x04: return XPICK_QUIT;
        default: return XPICK_NONE;
    }
}
#endif

static size_t DirectGate_Pick_Viewport(size_t nCount)
{
    xcli_size_t size;
    size_t nRows = nCount;

    if (XCLI_GetWindowSize(&size) == XSTDOK && size.nRows > 0)
    {
        /* Header, blank line, hint line and the status line stay visible */
        size_t nAvailable = size.nRows > 6 ? (size_t)size.nRows - 5 : DIRECTGATE_PICK_MIN_ROWS;
        if (nRows > nAvailable) nRows = nAvailable;
    }

    return nRows < DIRECTGATE_PICK_MIN_ROWS ? XSTD_MIN(nCount, DIRECTGATE_PICK_MIN_ROWS) : nRows;
}

static void DirectGate_Pick_Render(const directgate_device_list_t *pList, size_t nCursor,
                                   size_t nOffset, size_t nRows, const char *pStatus)
{
    for (size_t i = 0; i < nRows; i++)
    {
        size_t nIndex = nOffset + i;
        if (nIndex >= pList->nCount) break;

        const directgate_device_t *pDevice = &pList->devices[nIndex];
        xbool_t bActive = nIndex == nCursor ? XTRUE : XFALSE;

        const char *pOnlineMark = XSTR_CLR_GREEN "*" XSTR_CLR_NONE;
        const char *pOfflineMark = XSTR_FMT_DIM "*" XSTR_CLR_NONE;
        const char *pUnreachable = XSTR_CLR_RED "x" XSTR_CLR_NONE;
        const char *pMark = pDevice->bConnectable ? (pDevice->bOnline ? pOnlineMark : pOfflineMark) : pUnreachable;

        char sLabel[XSTR_MIN];
        xstrncpyf(sLabel, sizeof(sLabel), "%-26.26s %s%s%s", pDevice->sName,
            DirectGate_Devices_StateText(pDevice),
            xstrused(pDevice->sOwner) ? " - shared by " : XSTR_EMPTY,
            xstrused(pDevice->sOwner) ? pDevice->sOwner : XSTR_EMPTY);

        printf("\x1b[2K  %s %s %s%s\n",
            bActive ? XSTR_CLR_CYAN ">" XSTR_CLR_NONE : XSTR_SPACE, pMark,
            bActive ? XSTR_FMT_BOLD : XSTR_FMT_DIM, sLabel);

        printf(XSTR_CLR_NONE);
    }

    printf("\x1b[2K\n");
    printf("\x1b[2K  " XSTR_FMT_DIM
        "up/down select, enter confirm, q quit" XSTR_CLR_NONE "\n");

    printf("\x1b[2K  " XSTR_FMT_DIM
        "run dgcli with '-h' for additional help" XSTR_CLR_NONE "%s%s\n",
        xstrused(pStatus) ? "  -  " : XSTR_EMPTY,
        xstrused(pStatus) ? pStatus : XSTR_EMPTY);

    fflush(stdout);
}

/* Numbered prompt for pipes, CI and terminals we cannot drive with escape
 * sequences; keeps `dgcli` usable when stdin is not a TTY. */
static int DirectGate_Pick_Numbered(const directgate_device_list_t *pList, const char *pPurpose)
{
    printf("\n  Select a device to %s:\n", pPurpose);

    for (size_t i = 0; i < pList->nCount; i++)
    {
        const directgate_device_t *pDevice = &pList->devices[i];
        printf("  %2zu) %-28s %s\n", i + 1, pDevice->sName, DirectGate_Devices_StateText(pDevice));
    }

    char sInput[XSTR_MICRO];
    printf("\n  Select a device [1-%zu]: ", pList->nCount);
    fflush(stdout);

    if (fgets(sInput, sizeof(sInput), stdin) == NULL) return DIRECTGATE_DEVICE_ABORTED;

    char *pEnd = NULL;
    long nChoice = strtol(sInput, &pEnd, 10);

    if (nChoice < 1 || (size_t)nChoice > pList->nCount)
    {
        xloge("Invalid device selection");
        return DIRECTGATE_DEVICE_ABORTED;
    }

    size_t nIndex = (size_t)nChoice - 1;
    if (!pList->devices[nIndex].bConnectable)
    {
        xloge("Device is not connectable: %s (%s)",
            pList->devices[nIndex].sName,
            pList->devices[nIndex].sReason);

        return DIRECTGATE_DEVICE_ABORTED;
    }

    return (int)nIndex;
}

int DirectGate_Devices_Select(const directgate_device_list_t *pList, const char *pPurpose)
{
    XCHECK((pList != NULL), DIRECTGATE_DEVICE_ABORTED);
    XCHECK((pList->nCount > 0), DIRECTGATE_DEVICE_ABORTED);

    if (!xstrused(pPurpose)) pPurpose = "connect to";
    if (pList->nCount == 1 && pList->devices[0].bConnectable) return 0;

#ifdef _WIN32
    xbool_t bTty = _isatty(_fileno(stdin)) && _isatty(_fileno(stdout));
#else
    xbool_t bTty = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
#endif
    if (!bTty) return DirectGate_Pick_Numbered(pList, pPurpose);

    directgate_pick_io_t io;
    memset(&io, 0, sizeof(io));

    if (!DirectGate_Pick_Enter(&io)) return DirectGate_Pick_Numbered(pList, pPurpose);

    /* Start on the first device that can actually be connected */
    size_t nCursor = 0;
    for (size_t i = 0; i < pList->nCount; i++)
    {
        if (!pList->devices[i].bConnectable) continue;
        nCursor = i;
        break;
    }

    size_t nRows = DirectGate_Pick_Viewport(pList->nCount);
    size_t nOffset = nCursor >= nRows ? nCursor - nRows + 1 : 0;
    int nResult = DIRECTGATE_DEVICE_ABORTED;
    const char *pStatus = NULL;
    xbool_t bDrawn = XFALSE;

    printf("\n  Select a device to %s:\n\n", pPurpose);
    printf("\x1b[?25l");

    for (;;)
    {
        if (bDrawn) printf("\x1b[%zuA", nRows + 3);
        DirectGate_Pick_Render(pList, nCursor, nOffset, nRows, pStatus);
        bDrawn = XTRUE;

        directgate_pick_key_t eKey = DirectGate_Pick_ReadKey();
        pStatus = NULL;

        if (eKey == XPICK_QUIT) break;

        if (eKey == XPICK_ENTER)
        {
            if (pList->devices[nCursor].bConnectable)
            {
                nResult = (int)nCursor;
                break;
            }

            pStatus = XSTR_CLR_YELLOW "cannot connect to this device" XSTR_CLR_NONE;
            continue;
        }

        if (eKey == XPICK_UP && nCursor > 0) nCursor--;
        else if (eKey == XPICK_DOWN && nCursor + 1 < pList->nCount) nCursor++;
        else if (eKey == XPICK_HOME) nCursor = 0;
        else if (eKey == XPICK_END) nCursor = pList->nCount - 1;

        if (nCursor < nOffset) nOffset = nCursor;
        else if (nCursor >= nOffset + nRows) nOffset = nCursor - nRows + 1;
    }

    printf("\x1b[?25h");
    DirectGate_Pick_Leave(&io);
    fflush(stdout);

    return nResult;
}
