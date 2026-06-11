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
#include "devices.h"

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
