/*!
 * @file directgate-agent/src/common/common.h
 * @brief Common utility functions.
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

#ifndef __DIRECTGATE_COMMON_H__
#define __DIRECTGATE_COMMON_H__

#include "includes.h"

size_t DirectGate_GetQueryValue(const char *pUri, const char *pKey, char *pBuffer, size_t nSize);

void DirectGate_TrimStringRight(char *pStr);
const char* DirectGate_SkipToken(const char *pStr);
const char* DirectGate_JumpWiteSpace(const char *pStr);
int DirectGate_RemoveNewLine(char *pStr, size_t *pLen);

xbool_t DirectGate_FindCRLF(const uint8_t *pData, size_t nSize, size_t *pOffset);
xbool_t DirectGate_ParseI64(const uint8_t *pData, size_t nLength, int64_t *pValue);
xbool_t DirectGate_IsAPIEndpointAllowed(const char *pUrl);
xbool_t DirectGate_EnsurePrivateFileParent(const char *pPath);
xbool_t DirectGate_WritePrivateFile(const char *pPath, const uint8_t *pData, size_t nSize);

/* Convert backslash separators to forward slashes in place (Windows
   only, no-op elsewhere). Every Windows API accepts forward slashes,
   while raw backslashes inside generated JSON configs are invalid
   escape sequences - so every path the agent produces must use '/'. */
void DirectGate_PathToSlash(char *pPath);

/* Home directory and account name of the current user
   (POSIX: $HOME / passwd db, Windows: %USERPROFILE% / GetUserName) */
size_t DirectGate_GetHomeDir(char *pBuf, size_t nSize);
size_t DirectGate_GetUserName(char *pBuf, size_t nSize);

xbool_t DirectGate_PromptBool(const char *pLabel, xbool_t *pValue);
xbool_t DirectGate_PromptU16(const char *pLabel, uint16_t *pValue);
xbool_t DirectGate_PromptU32(const char *pLabel, uint32_t *pValue);
xbool_t DirectGate_PromptString(const char *pLabel, char *pOut, size_t nSize, const char *pDefault, xbool_t bRequired);

#endif
