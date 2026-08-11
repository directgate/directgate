/*!
 * @file directgate-agent/src/client/devices.h
 * @brief Client device management
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

#ifndef __DIRECTGATE_CLIENT_DEVICES_H__
#define __DIRECTGATE_CLIENT_DEVICES_H__

#include "includes.h"
#include "keyauth.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DIRECTGATE_DEVICES_MAX      128
#define DIRECTGATE_DEVICE_ID_SIZE   64
#define DIRECTGATE_DEVICE_NO_PICK   (-1)
#define DIRECTGATE_DEVICE_ABORTED   (-2)

/* The whole list lives on the stack in the connect path, so the field sizes
 * are kept tight: Windows gives the main thread a 1 MB stack by default. */
typedef struct directgate_device_ {
    char sId[DIRECTGATE_DEVICE_ID_SIZE];    /* UUID, 36 characters */
    char sName[XSTR_TINY];
    char sOwner[XSTR_TINY];                 /* Owner email, empty when owned */
    char sReason[XSTR_MICRO];               /* Why it cannot be connected */
    /* Host Ed25519 identity published during enrollment, base64. Empty on
     * devices that never published one; key auth needs it to pin the host. */
    char sAgentPub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    xbool_t bOnline;
    xbool_t bOwned;
    xbool_t bConnectable;
} directgate_device_t;

typedef struct directgate_device_list_ {
    directgate_device_t devices[DIRECTGATE_DEVICES_MAX];
    size_t nCount;
} directgate_device_list_t;

xbool_t DirectGate_Devices_Load(xmap_t *pMap, const char *pPath);
xbool_t DirectGate_Devices_Write(xmap_t *pMap, const char *pPath);
xbool_t DirectGate_Devices_Add(xmap_t *pMap, const char *pDeviceName, const char *pDeviceId, xbool_t bForce);
xbool_t DirectGate_Devices_Search(xmap_t *pMap, const char *pDeviceName, char *pDeviceId, size_t nIdSize);

/* GET /api/v1/devices with the account access token */
xbool_t DirectGate_Devices_Fetch(directgate_device_list_t *pList,
                                 const char *pApiUrl,
                                 const char *pAccessToken,
                                 char *pErr, size_t nErrSize);

/* Maps a "{devices:[...]}" body onto the list, applying the same
 * connectability rules the workspace UI uses. Exposed for tests. */
xbool_t DirectGate_Devices_ParseList(directgate_device_list_t *pList, xjson_obj_t *pRoot);

/* Resolves a device by exact id, then by exact name, then by unique
 * case-insensitive name prefix. Returns the index or DIRECTGATE_DEVICE_NO_PICK. */
int DirectGate_Devices_Find(const directgate_device_list_t *pList, const char *pQuery);

void DirectGate_Devices_Print(const directgate_device_list_t *pList);

/* Full-screen arrow-key picker. Returns the chosen index, or
 * DIRECTGATE_DEVICE_ABORTED when the user quits. Falls back to a numbered
 * prompt when stdin or stdout is not a terminal. */
int DirectGate_Devices_Select(const directgate_device_list_t *pList);

#ifdef __cplusplus
}
#endif

#endif
