/*!
 * @file directgate-agent/src/common/common.c
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

#include "includes.h"
#include "common.h"

size_t DirectGate_GetQueryValue(const char *pUri, const char *pKey, char *pBuffer, size_t nSize)
{
    XCHECK((pBuffer != NULL && nSize > 0), XSTDNON);
    pBuffer[0] = XSTR_NUL;

    XCHECK_NL((xstrused(pUri) && xstrused(pKey)), XSTDNON);
    int nQueryPos = xstrsrc(pUri, "?");
    XCHECK_NL((nQueryPos >= 0), XSTDNON);

    const char *pQuery = &pUri[nQueryPos + 1];
    size_t nKeyLen = strlen(pKey);

    while (*pQuery != XSTR_NUL)
    {
        while (*pQuery == '&') pQuery++;
        if (*pQuery == XSTR_NUL) break;

        const char *pItem = pQuery;
        while (*pQuery != XSTR_NUL && *pQuery != '&') pQuery++;

        size_t nItemLen = (size_t)(pQuery - pItem);
        if (nItemLen > nKeyLen + 1 &&
            xstrncmp(pItem, pKey, nKeyLen) &&
            pItem[nKeyLen] == '=')
        {
            const char *pValue = &pItem[nKeyLen + 1];
            size_t nValueLen = nItemLen - nKeyLen - 1;
            return xstrncpys(pBuffer, nSize, pValue, nValueLen);
        }
    }

    return XSTDNON;
}

int DirectGate_RemoveNewLine(char *pStr, size_t *pLen)
{
    if (pStr == NULL || pLen == NULL || *pLen == 0) return -1;
    size_t nLen = *pLen;

    if (pStr[nLen - 1] == '\n')
    {
        pStr[nLen - 1] = '\0';
        --nLen;
    }

    if (nLen > 0 && pStr[nLen - 1] == '\r')
    {
        pStr[nLen - 1] = '\0';
        --nLen;
    }

    *pLen = nLen;
    return nLen;
}

const char* DirectGate_JumpWiteSpace(const char *pStr)
{
    XCHECK((pStr != NULL), NULL);
    while (*pStr != '\0' && isspace((unsigned char)*pStr)) pStr++;
    return pStr;
}

const char* DirectGate_SkipToken(const char *pStr)
{
    XCHECK((pStr != NULL), NULL);
    while (*pStr != '\0' && !isspace((unsigned char)*pStr)) pStr++;
    return pStr;
}

void DirectGate_TrimStringRight(char *pStr)
{
    XCHECK_VOID((pStr != NULL));
    size_t nLen = strlen(pStr);
    while (nLen > 0)
    {
        unsigned char c = (unsigned char)pStr[nLen - 1];
        if (!isspace(c)) break;
        pStr[nLen - 1] = '\0';
        nLen--;
    }
}

xbool_t DirectGate_FindCRLF(const uint8_t *pData, size_t nSize, size_t *pOffset)
{
    XCHECK_NL((pData != NULL), XFALSE);

    for (size_t i = 0; i + 1 < nSize; i++)
    {
        if (pData[i] == '\r' && pData[i + 1] == '\n')
        {
            if (pOffset != NULL) *pOffset = i;
            return XTRUE;
        }
    }

    return XFALSE;
}

xbool_t DirectGate_ParseI64(const uint8_t *pData, size_t nLength, int64_t *pValue)
{
    XCHECK_NL((pData != NULL), XFALSE);
    XCHECK_NL((pValue != NULL), XFALSE);
    XCHECK_NL((nLength > 0 && nLength < 64), XFALSE);

    char sNumber[64];
    xstrncpys(sNumber, sizeof(sNumber), (const char*)pData, nLength);

    errno = 0;
    char *pEnd = NULL;
    long long nParsed = strtoll(sNumber, &pEnd, 10);
    XCHECK_NL((errno != ERANGE && pEnd != NULL && pEnd != sNumber && *pEnd == XSTR_NUL), XFALSE);

    *pValue = (int64_t)nParsed;
    return XTRUE;
}

xbool_t DirectGate_IsAPIEndpointAllowed(const char *pUrl)
{
    XCHECK_NL((xstrused(pUrl)), XFALSE);

    xlink_t link;
    XCHECK_NL((XLink_Parse(&link, pUrl) >= 0), XFALSE);
    XCHECK_NL((xstrused(link.sAddr) && link.nPort), XFALSE);

    /*
    * In debug builds, both HTTP and HTTPS endpoints are allowed to simplify
    * local development and testing. Production builds require HTTPS only.
    *
    * For transparency, the agent always reports whether it is running in a
    * debug or production build, allowing users to verify that transport
    * security requirements have not been relaxed.
    */
#ifdef DIRECTGATE_DEBUG
    return (xstrcmp(link.sProtocol, "http") ||
            xstrcmp(link.sProtocol, "https"));
#else
    return xstrcmp(link.sProtocol, "https");
#endif
}

#ifdef _WIN32
/*
    Windows counterpart of the POSIX 0600/0700 private-file model.

    The DACL is built from SDDL and is protected (P), so nothing is
    inherited from the parent directory. Access is granted only to:
      SY - LocalSystem (the agent may run as a service)
      BA - builtin Administrators (they can take ownership anyway,
           granting it openly keeps the ACL honest)
      OW - the object owner, i.e. the creating user
    Directories add OICI so files created inside them inherit the
    same private ACL even when written by other tooling.
*/
static xbool_t DirectGate_BuildPrivateSecAttrs(SECURITY_ATTRIBUTES *pSecAttrs,
                                               PSECURITY_DESCRIPTOR *ppDescriptor,
                                               xbool_t bDirectory)
{
    XCHECK_NL((pSecAttrs != NULL && ppDescriptor != NULL), XFALSE);

    const char *pSDDL = bDirectory ?
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)" :
        "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)";

    *ppDescriptor = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            pSDDL, SDDL_REVISION_1, ppDescriptor, NULL))
    {
        xloge("Failed to build private security descriptor: error(%lu)", GetLastError());
        return XFALSE;
    }

    pSecAttrs->nLength = sizeof(SECURITY_ATTRIBUTES);
    pSecAttrs->lpSecurityDescriptor = *ppDescriptor;
    pSecAttrs->bInheritHandle = FALSE;
    return XTRUE;
}

xbool_t DirectGate_EnsurePrivateFileParent(const char *pPath)
{
    XCHECK((xstrused(pPath)), XFALSE);

    char sDir[XPATH_MAX];
    xstrncpy(sDir, sizeof(sDir), pPath);

    char *pSlash = strrchr(sDir, '/');
    char *pBackSlash = strrchr(sDir, '\\');
    if (pBackSlash != NULL && (pSlash == NULL || pBackSlash > pSlash)) pSlash = pBackSlash;
    XCHECK_NL((pSlash != NULL), XTRUE);

    if (pSlash == sDir)
        return XTRUE;

    *pSlash = XSTR_NUL;
    if (!xstrused(sDir) || xstrcmp(sDir, "."))
        return XTRUE;

    /* Drive root like "C:" needs no creation or tightening */
    size_t nDirLen = strlen(sDir);
    if (nDirLen == 2 && sDir[1] == ':')
        return XTRUE;

    DWORD nAttrs = GetFileAttributesA(sDir);
    if (nAttrs != INVALID_FILE_ATTRIBUTES)
        return (nAttrs & FILE_ATTRIBUTE_DIRECTORY) ? XTRUE : XFALSE;

    SECURITY_ATTRIBUTES secAttrs;
    PSECURITY_DESCRIPTOR pDescriptor = NULL;
    if (!DirectGate_BuildPrivateSecAttrs(&secAttrs, &pDescriptor, XTRUE))
        return XFALSE;

    BOOL bCreated = CreateDirectoryA(sDir, &secAttrs);
    DWORD nError = bCreated ? 0 : GetLastError();
    LocalFree(pDescriptor);

    if (!bCreated && nError != ERROR_ALREADY_EXISTS)
    {
        xloge("Failed to create private directory: dir(%s), error(%lu)", sDir, nError);
        return XFALSE;
    }

    return XTRUE;
}

xbool_t DirectGate_WritePrivateFile(const char *pPath, const uint8_t *pData, size_t nSize)
{
    XCHECK((xstrused(pPath)), XFALSE);
    XCHECK((pData != NULL), XFALSE);
    XCHECK((nSize > 0), XFALSE);

    /* Refuse to follow links: writing through a planted reparse point
       would let an attacker redirect private data to a path they chose. */
    DWORD nAttrs = GetFileAttributesA(pPath);
    if (nAttrs != INVALID_FILE_ATTRIBUTES && (nAttrs & FILE_ATTRIBUTE_REPARSE_POINT))
        return XFALSE;

    if (!DirectGate_EnsurePrivateFileParent(pPath))
        return XFALSE;

    SECURITY_ATTRIBUTES secAttrs;
    PSECURITY_DESCRIPTOR pDescriptor = NULL;
    if (!DirectGate_BuildPrivateSecAttrs(&secAttrs, &pDescriptor, XFALSE))
        return XFALSE;

    /* mkstemp equivalent: random suffix + CREATE_NEW (O_EXCL semantics),
       created with the private DACL and no sharing from the first byte */
    HANDLE hFile = INVALID_HANDLE_VALUE;
    char sTempPath[XPATH_MAX];
    int nAttempt = 0;

    for (nAttempt = 0; nAttempt < 16 && hFile == INVALID_HANDLE_VALUE; nAttempt++)
    {
        uint8_t nRandom[6];
        if (RAND_bytes(nRandom, sizeof(nRandom)) != 1) break;

        int nTempLen = snprintf(sTempPath, sizeof(sTempPath), "%s.tmp.%02x%02x%02x%02x%02x%02x",
            pPath, nRandom[0], nRandom[1], nRandom[2], nRandom[3], nRandom[4], nRandom[5]);

        if (nTempLen < 0 || (size_t)nTempLen >= sizeof(sTempPath)) break;

        hFile = CreateFileA(sTempPath, GENERIC_WRITE, 0, &secAttrs,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

        if (hFile == INVALID_HANDLE_VALUE && GetLastError() != ERROR_FILE_EXISTS) break;
    }

    LocalFree(pDescriptor);
    if (hFile == INVALID_HANDLE_VALUE) return XFALSE;

    size_t nWritten = 0;
    while (nWritten < nSize)
    {
        DWORD nChunk = (DWORD)XSTD_MIN(nSize - nWritten, (size_t)UINT32_MAX);
        DWORD nDone = 0;

        if (!WriteFile(hFile, pData + nWritten, nChunk, &nDone, NULL) || nDone == 0)
        {
            CloseHandle(hFile);
            DeleteFileA(sTempPath);
            return XFALSE;
        }

        nWritten += (size_t)nDone;
    }

    /* fsync equivalent before the atomic swap */
    if (!FlushFileBuffers(hFile))
    {
        CloseHandle(hFile);
        DeleteFileA(sTempPath);
        return XFALSE;
    }

    CloseHandle(hFile);

    /* rename() refuses existing targets on Windows; MoveFileEx with
       REPLACE_EXISTING is the documented atomic replace on NTFS */
    if (!MoveFileExA(sTempPath, pPath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        DeleteFileA(sTempPath);
        return XFALSE;
    }

    return XTRUE;
}
#else
xbool_t DirectGate_EnsurePrivateFileParent(const char *pPath)
{
    XCHECK((xstrused(pPath)), XFALSE);

    char sDir[XPATH_MAX];
    xstrncpy(sDir, sizeof(sDir), pPath);

    char *pSlash = strrchr(sDir, '/');
    XCHECK_NL((pSlash != NULL), XTRUE);

    if (pSlash == sDir)
        return XTRUE;

    *pSlash = XSTR_NUL;
    if (!xstrused(sDir) || xstrcmp(sDir, "."))
        return XTRUE;

    xstat_t before;
    xbool_t bExisted = (xstat(sDir, &before) == XSTDOK);
    if (bExisted && !S_ISDIR(before.st_mode))
        return XFALSE;

    if (!XDir_Create(sDir, 0700))
        return XFALSE;

    xstat_t after;
    if (xstat(sDir, &after) != XSTDOK || !S_ISDIR(after.st_mode))
        return XFALSE;

#ifdef S_ISVTX
    if (after.st_mode & S_ISVTX)
        return XTRUE;
#endif

    if (!bExisted && xchmod(sDir, 0700) < 0)
        return XFALSE;

    return XTRUE;
}

xbool_t DirectGate_WritePrivateFile(const char *pPath, const uint8_t *pData, size_t nSize)
{
    XCHECK((xstrused(pPath)), XFALSE);
    XCHECK((pData != NULL), XFALSE);
    XCHECK((nSize > 0), XFALSE);

    struct stat target;
    if (xstat(pPath, &target) == XSTDOK)
    {
        if (S_ISLNK(target.st_mode))
            return XFALSE;
    }
    else if (errno != ENOENT)
    {
        xloge("Failed to stat file: path(%s), errno(%d)", pPath, errno);
        return XFALSE;
    }

    if (!DirectGate_EnsurePrivateFileParent(pPath))
        return XFALSE;

    char sTempPath[XPATH_MAX];
    int nTempLen = snprintf(sTempPath, sizeof(sTempPath), "%s.tmp.XXXXXX", pPath);
    if (nTempLen < 0 || (size_t)nTempLen >= sizeof(sTempPath)) return XFALSE;

    /* mkstemp automatically creates file with 0600 permissions.
       Then we anyway set it to 0600 for defense in depth. */
    int nFd = mkstemp(sTempPath);
    if (nFd < 0) return XFALSE;

    int nFdFlags = fcntl(nFd, F_GETFD);
    if (nFdFlags >= 0) (void)fcntl(nFd, F_SETFD, nFdFlags | FD_CLOEXEC);

    if (fchmod(nFd, 0600) != 0)
    {
        close(nFd);
        unlink(sTempPath);
        return XFALSE;
    }

    size_t nWritten = 0;
    while (nWritten < nSize)
    {
        ssize_t nRet = write(nFd, pData + nWritten, nSize - nWritten);
        if (nRet < 0 && errno == EINTR) continue;

        if (nRet <= 0)
        {
            close(nFd);
            unlink(sTempPath);
            return XFALSE;
        }

        nWritten += (size_t)nRet;
    }

    while (fsync(nFd) != 0)
    {
        if (errno == EINTR) continue;

        close(nFd);
        unlink(sTempPath);
        return XFALSE;
    }

    if (close(nFd) != 0)
    {
        unlink(sTempPath);
        return XFALSE;
    }

    if (rename(sTempPath, pPath) != 0)
    {
        unlink(sTempPath);
        return XFALSE;
    }

    return XTRUE;
}
#endif /* _WIN32 */


void DirectGate_PathToSlash(char *pPath)
{
#ifdef _WIN32
    XCHECK_VOID((pPath != NULL));
    for (; *pPath != XSTR_NUL; pPath++)
        if (*pPath == '\\') *pPath = '/';
#else
    (void)pPath;
#endif
}

size_t DirectGate_GetHomeDir(char *pBuf, size_t nSize)
{
    XCHECK((pBuf != NULL && nSize > 0), XSTDNON);
    pBuf[0] = XSTR_NUL;

#ifdef _WIN32
    /* Forward slashes keep the value JSON-safe when it lands in a
       generated config (the JSON writer does not escape backslashes) */
    size_t nLen = XSTDNON;

    const char *pHomeDir = getenv("USERPROFILE");
    if (xstrused(pHomeDir)) nLen = xstrncpy(pBuf, nSize, pHomeDir);

    if (!nLen)
    {
        const char *pDrive = getenv("HOMEDRIVE");
        const char *pPath = getenv("HOMEPATH");
        if (xstrused(pDrive) && xstrused(pPath))
            nLen = xstrncpyf(pBuf, nSize, "%s%s", pDrive, pPath);
    }

    DirectGate_PathToSlash(pBuf);
    return nLen;
#else
    const char *pHomeDir = getenv("HOME");
    if (xstrused(pHomeDir)) return xstrncpy(pBuf, nSize, pHomeDir);

    struct passwd *pUser = getpwuid(getuid());
    if (pUser != NULL && xstrused(pUser->pw_dir))
        return xstrncpy(pBuf, nSize, pUser->pw_dir);

    return XSTDNON;
#endif
}

size_t DirectGate_GetUserName(char *pBuf, size_t nSize)
{
    XCHECK((pBuf != NULL && nSize > 0), XSTDNON);
    pBuf[0] = XSTR_NUL;

#ifdef _WIN32
    char sName[256];
    DWORD nNameLen = (DWORD)sizeof(sName);
    if (GetUserNameA(sName, &nNameLen) && xstrused(sName))
        return xstrncpy(pBuf, nSize, sName);

    const char *pUserEnv = getenv("USERNAME");
    if (xstrused(pUserEnv)) return xstrncpy(pBuf, nSize, pUserEnv);

    return XSTDNON;
#else
    struct passwd *pUser = getpwuid(getuid());
    if (pUser != NULL && xstrused(pUser->pw_name))
        return xstrncpy(pBuf, nSize, pUser->pw_name);

    const char *pUserEnv = getenv("USER");
    if (xstrused(pUserEnv)) return xstrncpy(pBuf, nSize, pUserEnv);

    return XSTDNON;
#endif
}

xbool_t DirectGate_PromptString(const char *pLabel, char *pOut, size_t nSize,
                                const char *pDefault, xbool_t bRequired)
{
    XCHECK((pLabel != NULL), XFALSE);
    XCHECK((pOut != NULL), XFALSE);

    for (;;)
    {
        char sDefault[XPATH_MAX] = {0};
        char sInput[XPATH_MAX] = {0};
        char sPrompt[256] = {0};

        const char *pShow = xstrused(pOut) ? pOut : pDefault;
        if (xstrused(pShow)) xstrncpy(sDefault, sizeof(sDefault), pShow);

        if (!xstrused(sDefault)) xstrncpyf(sPrompt, sizeof(sPrompt), "%s: ", pLabel);
        else xstrncpyf(sPrompt, sizeof(sPrompt), "%s [%s]: ", pLabel, sDefault);

        XSTATUS nStatus = XCLI_GetInput(sPrompt, sInput, sizeof(sInput), XTRUE);
        if (nStatus < 0) return XFALSE;

        if (!xstrused(sInput))
        {
            if (xstrused(sDefault))
            {
                xstrncpy(pOut, nSize, sDefault);
                return bRequired ? xstrused(pOut) : XTRUE;
            }

            if (!bRequired) return XTRUE;
            continue;
        }

        xstrncpy(pOut, nSize, sInput);
        return XTRUE;
    }
}

xbool_t DirectGate_PromptBool(const char *pLabel, xbool_t *pValue)
{
    XCHECK((pLabel != NULL), XFALSE);
    XCHECK((pValue != NULL), XFALSE);

    char sInput[16];
    char sPrompt[128];
    const char *pDefault = (*pValue) ? "y" : "n";

    xstrncpyf(sPrompt, sizeof(sPrompt), "%s [%s]: ", pLabel, pDefault);
    XSTATUS nStatus = XCLI_GetInput(sPrompt, sInput, sizeof(sInput), XTRUE);
    if (nStatus < 0) return XFALSE;
    if (!xstrused(sInput)) return XTRUE;

    if (sInput[0] == 'y' || sInput[0] == 'Y' || sInput[0] == '1') *pValue = XTRUE;
    else if (sInput[0] == 'n' || sInput[0] == 'N' || sInput[0] == '0') *pValue = XFALSE;
    else return XFALSE;

    return XTRUE;
}

xbool_t DirectGate_PromptU16(const char *pLabel, uint16_t *pValue)
{
    XCHECK((pLabel != NULL), XFALSE);
    XCHECK((pValue != NULL), XFALSE);

    char sInput[32];
    char sPrompt[128];

    uint16_t nDefault = *pValue;
    if (nDefault) xstrncpyf(sPrompt, sizeof(sPrompt), "%s [%u]: ", pLabel, nDefault);
    else xstrncpyf(sPrompt, sizeof(sPrompt), "%s: ", pLabel);

    XSTATUS nStatus = XCLI_GetInput(sPrompt, sInput, sizeof(sInput), XTRUE);
    if (nStatus < 0) return XFALSE;
    if (!xstrused(sInput)) return XTRUE;

    char *pEnd = NULL;
    uint16_t nVal = (uint16_t)strtoul(sInput, &pEnd, 10);
    if (pEnd == sInput) return XFALSE;

    *pValue = nVal;
    return XTRUE;
}

xbool_t DirectGate_PromptU32(const char *pLabel, uint32_t *pValue)
{
    XCHECK((pLabel != NULL), XFALSE);
    XCHECK((pValue != NULL), XFALSE);

    char sInput[32];
    char sPrompt[128];

    uint32_t nDefault = *pValue;
    if (nDefault) xstrncpyf(sPrompt, sizeof(sPrompt), "%s [%u]: ", pLabel, nDefault);
    else xstrncpyf(sPrompt, sizeof(sPrompt), "%s: ", pLabel);

    XSTATUS nStatus = XCLI_GetInput(sPrompt, sInput, sizeof(sInput), XTRUE);
    if (nStatus < 0) return XFALSE;
    if (!xstrused(sInput)) return XTRUE;

    char *pEnd = NULL;
    uint32_t nVal = (uint32_t)strtoul(sInput, &pEnd, 10);
    if (pEnd == sInput) return XFALSE;

    *pValue = nVal;
    return XTRUE;
}
