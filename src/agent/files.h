/*!
 * @file directgate-agent/src/agent/files.h
 * @brief File manager utilities for directory listing and file operations.
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

#ifndef __DIRECTGATE_FILES_H__
#define __DIRECTGATE_FILES_H__

#include "session.h"
#include "protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Build a JSON object with "path" and "entries" array for the given directory.
   Each entry: {name, type, permissions, owner, group, sizeBytes, modified}.
   Returns xjson_obj_t* that caller must free via XJSON_FreeObject, or NULL on error. */
xjson_obj_t* DirectGate_Files_ListDir(const char *pPath);
xjson_obj_t* DirectGate_Files_CreateEntryJson(const char *pName, const char *pDirPath, const xstat_t *pStat);

/* Delete a file or empty directory, or recursively if forced. Returns XSTDOK or XSTDERR. */
XSTATUS DirectGate_Files_Delete(const char *pPath, xbool_t bForce);
XSTATUS DirectGate_Files_CreateDir(const char *pPath);

/* Create a symlink at pPath pointing at pTargetPath. Never replaces an
   existing entry. Returns XSTDOK or XSTDERR. */
XSTATUS DirectGate_Files_CreateSymlink(const char *pPath, const char *pTargetPath);
XSTATUS DirectGate_Files_Rename(const char *pPath, const char *pTargetPath);

/* File transfer send callback for transfer.c */
int DirectGate_Files_TransferSendCb(xjson_obj_t *pHeader, const uint8_t *pPayload,
                                    size_t nLen, void *pCtx);
void DirectGate_Files_ProcessTransfer(directgate_session_t *pSession);

/* Message handlers */
int DirectGate_Files_HandleManager(xapi_session_t *pApiSession, directgate_pkg_t *pPkg);
int DirectGate_Files_HandleFile(xapi_session_t *pApiSession, directgate_pkg_t *pPkg);

#ifdef __cplusplus
}
#endif

#endif /* __DIRECTGATE_FILES_H__ */
