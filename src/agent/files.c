/*!
 * @file directgate-agent/src/agent/files.c
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

#include "includes.h"
#include "common.h"
#include "transfer.h"
#include "directgate.h"
#include "files.h"

#define DIRECTGATE_UPLOAD_TEMP_RANDOM_SIZE 16
#define DIRECTGATE_UPLOAD_TEMP_ATTEMPTS    16

static const char* DirectGate_Files_LastError(void)
{
    if (errno == 0) return "operation failed";
    const char *pReason = strerror(errno);
    return xstrused(pReason) ? pReason : "operation failed";
}

static xbool_t DirectGate_Files_PathStartsWith(const char *pPath, const char *pPrefix)
{
    XCHECK_NL((xstrused(pPath) && xstrused(pPrefix)), XFALSE);

    size_t nPrefixLen = strlen(pPrefix);
    if (strncmp(pPath, pPrefix, nPrefixLen) != 0) return XFALSE;

    if (pPath[nPrefixLen] == '\0') return XTRUE;
    if (nPrefixLen == 1 && pPrefix[0] == '/') return XTRUE;

    return pPath[nPrefixLen] == '/';
}

static xbool_t DirectGate_Files_IsNestedTarget(const char *pPath, const char *pTargetPath)
{
    XCHECK_NL((xstrused(pPath) && xstrused(pTargetPath)), XFALSE);
    if (xstrcmp(pPath, pTargetPath)) return XFALSE;
    return DirectGate_Files_PathStartsWith(pTargetPath, pPath);
}

static int DirectGate_Files_ResolvePasteTarget(char *pOutput, size_t nSize, const char *pTargetPath)
{
    XCHECK((pOutput != NULL), XSTDERR);
    XCHECK((nSize > 0), XSTDERR);
    XCHECK((xstrused(pTargetPath)), XSTDERR);

    if (!XPath_Exists(pTargetPath))
    {
        xstrncpy(pOutput, nSize, pTargetPath);
        return XSTDOK;
    }

    char sDir[XFILE_PATH_SIZE];
    char sName[XFILE_NAME_SIZE];
    xstrncpy(sDir, sizeof(sDir), pTargetPath);

    char *pSlash = strrchr(sDir, '/');
    if (pSlash == NULL)
    {
        xstrncpy(sName, sizeof(sName), sDir);
        xstrncpy(sDir, sizeof(sDir), ".");
    }
    else
    {
        xstrncpy(sName, sizeof(sName), pSlash + 1);
        if (pSlash == sDir) pSlash[1] = '\0';
        else *pSlash = '\0';
    }

    const char *pDot = strrchr(sName, '.');
    if (pDot == sName) pDot = NULL;

    char sStem[XFILE_NAME_SIZE];
    char sExt[XFILE_NAME_SIZE];
    size_t nStemLen = pDot ? (size_t)(pDot - sName) : strlen(sName);

    snprintf(sStem, sizeof(sStem), "%.*s", (int)nStemLen, sName);
    xstrncpy(sExt, sizeof(sExt), pDot ? pDot : "");

    for (unsigned int i = 2; i < 100000; ++i)
    {
        int nWritten;
        if (xstrcmp(sDir, "/"))
            nWritten = snprintf(pOutput, nSize, "/%s(%u)%s", sStem, i, sExt);
        else
            nWritten = snprintf(pOutput, nSize, "%s/%s(%u)%s", sDir, sStem, i, sExt);

        if (nWritten <= 0 || (size_t)nWritten >= nSize) return XSTDERR;
        if (!XPath_Exists(pOutput)) return XSTDOK;
    }

    errno = EEXIST;
    return XSTDERR;
}

static const char* DirectGate_Files_TypeStr(xfile_type_t eType)
{
    if (eType & XF_DIRECTORY) return "directory";
    if (eType & XF_SYMLINK) return "symlink";
    if (eType & XF_REGULAR) return "file";
    if (eType & XF_BLOCK_DEVICE) return "block";
    if (eType & XF_CHAR_DEVICE) return "char";
    if (eType & XF_SOCKET) return "socket";
    if (eType & XF_PIPE) return "pipe";
    return "unknown";
}

static void DirectGate_Files_NormalizeDirPath(char *pOutput, size_t nSize, const char *pPath)
{
    XCHECK_VOID_NL((pOutput != NULL && nSize > 0));

    if (!xstrused(pPath))
    {
        xstrncpy(pOutput, nSize, "/");
        return;
    }

    xstrncpy(pOutput, nSize, pPath);
    size_t nLen = strlen(pOutput);

    while (nLen > 1 && pOutput[nLen - 1] == '/')
        pOutput[--nLen] = '\0';

    if (!nLen)
        xstrncpy(pOutput, nSize, "/");
}

static int DirectGate_Files_BuildFullPath(char *pOutput, size_t nSize, const char *pDirPath, const char *pName)
{
    XCHECK((pOutput != NULL), XSTDERR);
    XCHECK((nSize > 0), XSTDERR);
    XCHECK((xstrused(pDirPath)), XSTDERR);
    XCHECK((xstrused(pName)), XSTDERR);

    char sDir[XFILE_PATH_SIZE];
    DirectGate_Files_NormalizeDirPath(sDir, sizeof(sDir), pDirPath);

    int nWritten = xstrcmp(sDir, "/")
        ? snprintf(pOutput, nSize, "/%s", pName)
        : snprintf(pOutput, nSize, "%s/%s", sDir, pName);

    return (nWritten > 0 && (size_t)nWritten < nSize) ? XSTDOK : XSTDERR;
}

xjson_obj_t* DirectGate_Files_CreateEntryJson(const char *pName, const char *pDirPath, const xstat_t *pStat)
{
    XCHECK((xstrused(pName)), NULL);
    XCHECK((xstrused(pDirPath)), NULL);
    XCHECK((pStat != NULL), NULL);

    char sDirPath[XFILE_PATH_SIZE];
    char sFullPath[XFILE_PATH_SIZE];
    DirectGate_Files_NormalizeDirPath(sDirPath, sizeof(sDirPath), pDirPath);
    XCHECK((DirectGate_Files_BuildFullPath(sFullPath, sizeof(sFullPath), sDirPath, pName) == XSTDOK), NULL);

    xjson_obj_t *pEntry = XJSON_NewObject(NULL, NULL, XFALSE);
    XCHECK((pEntry != NULL), NULL);

    XJSON_AddString(pEntry, "name", pName);
    XJSON_AddString(pEntry, "path", sFullPath);
    XJSON_AddString(pEntry, "directoryPath", sDirPath);

    xfile_type_t eType = XFile_GetType((xmode_t)pStat->st_mode);
    XJSON_AddString(pEntry, "type", DirectGate_Files_TypeStr(eType));

    char sPerm[16], sFullPerm[32];
    char cTypeChar = XFile_GetTypeChar(eType);

    XPath_ModeToPerm(sPerm, sizeof(sPerm), (xmode_t)pStat->st_mode);
    snprintf(sFullPerm, sizeof(sFullPerm), "%c%s", cTypeChar, sPerm);
    XJSON_AddString(pEntry, "permissions", sFullPerm);

#ifdef _WIN32
    /* st_uid/st_gid carry no meaning on Windows: ownership lives in the
       file ACL. Report the agent account, which is what every entry the
       session can touch effectively runs as. */
    char sOwner[XSTR_MID] = {0};
    DirectGate_GetUserName(sOwner, sizeof(sOwner));

    XJSON_AddString(pEntry, "owner", xstrused(sOwner) ? sOwner : "unknown");
    XJSON_AddString(pEntry, "group", "none");
#else
    /* Reentrant lookups: this runs on both the main thread and the async
       search worker thread, so the static buffers behind getpwuid/getgrgid/
       localtime would race. Use the _r variants. */
    struct passwd pwd, *pw = NULL;
    struct group grp, *gr = NULL;
    char sPwBuf[XSTR_MID];
    char sGrBuf[XSTR_MID];

    if (getpwuid_r(pStat->st_uid, &pwd, sPwBuf, sizeof(sPwBuf), &pw) != 0) pw = NULL;
    if (getgrgid_r(pStat->st_gid, &grp, sGrBuf, sizeof(sGrBuf), &gr) != 0) gr = NULL;

    XJSON_AddString(pEntry, "owner", (pw != NULL) ? pw->pw_name : "unknown");
    XJSON_AddString(pEntry, "group", (gr != NULL) ? gr->gr_name : "unknown");
#endif
    XJSON_AddU64(pEntry, "sizeBytes", (uint64_t)pStat->st_size);

    char sTime[32];
    struct tm tmBuf;
#ifdef _WIN32
    /* localtime_s is the Windows CRT spelling of localtime_r */
    struct tm *tm = (localtime_s(&tmBuf, &pStat->st_mtime) == 0) ? &tmBuf : NULL;
#else
    struct tm *tm = localtime_r(&pStat->st_mtime, &tmBuf);
#endif
    if (tm == NULL) xstrncpy(sTime, sizeof(sTime), "unknown");
    else strftime(sTime, sizeof(sTime), "%Y-%m-%dT%H:%M:%S", tm);

    XJSON_AddString(pEntry, "modified", sTime);
    return pEntry;
}

static xbool_t DirectGate_Files_DirectoryHasEntries(const char *pPath)
{
    xdir_t dir;
    int nSavedErrno = errno;

    if (XDir_Open(&dir, pPath) < 0)
    {
        errno = nSavedErrno;
        return XFALSE;
    }

    int nRead = XDir_Read(&dir, NULL, 0);
    XDir_Close(&dir);
    errno = nSavedErrno;

    return nRead > 0;
}

static XSTATUS DirectGate_Files_RenameNoReplace(const char *pPath, const char *pTargetPath)
{
    XCHECK((xstrused(pPath)), XSTDERR);
    XCHECK((xstrused(pTargetPath)), XSTDERR);

#if defined(__linux__) && defined(SYS_renameat2) && defined(RENAME_NOREPLACE)
    if (syscall(SYS_renameat2, AT_FDCWD, pPath, AT_FDCWD, pTargetPath, RENAME_NOREPLACE) == 0)
        return XSTDOK;

    if (errno != ENOSYS && errno != EINVAL)
        return XSTDERR;
#endif

    xstat_t st;
    if (xstat(pTargetPath, &st) == XSTDOK)
    {
        errno = EEXIST;
        return XSTDERR;
    }

    return rename(pPath, pTargetPath) == 0 ? XSTDOK : XSTDERR;
}

#ifdef _WIN32
static void DirectGate_Files_SetErrnoFromWin32(DWORD nError)
{
    switch (nError)
    {
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
        case ERROR_INVALID_DRIVE:
            errno = ENOENT;
            break;

        case ERROR_ACCESS_DENIED:
        case ERROR_SHARING_VIOLATION:
        case ERROR_LOCK_VIOLATION:
        case ERROR_WRITE_PROTECT:
            errno = EACCES;
            break;

        case ERROR_FILE_EXISTS:
        case ERROR_ALREADY_EXISTS:
            errno = EEXIST;
            break;

        case ERROR_NOT_SAME_DEVICE:
            errno = EXDEV;
            break;

        case ERROR_DISK_FULL:
        case ERROR_HANDLE_DISK_FULL:
            errno = ENOSPC;
            break;

        case ERROR_DIR_NOT_EMPTY:
            errno = ENOTEMPTY;
            break;

        case ERROR_FILENAME_EXCED_RANGE:
        case ERROR_BUFFER_OVERFLOW:
            errno = ENAMETOOLONG;
            break;

        case ERROR_DIRECTORY:
            errno = ENOTDIR;
            break;

        case ERROR_INVALID_NAME:
        case ERROR_INVALID_PARAMETER:
            errno = EINVAL;
            break;

        default:
            errno = EIO;
            break;
    }
}
#endif

static XSTATUS DirectGate_Files_RenameReplace(const char *pPath, const char *pTargetPath)
{
    XCHECK((xstrused(pPath)), XSTDERR);
    XCHECK((xstrused(pTargetPath)), XSTDERR);

#ifdef _WIN32
    if (MoveFileExA(pPath, pTargetPath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        return XSTDOK;

    DirectGate_Files_SetErrnoFromWin32(GetLastError());
    return XSTDERR;
#else
    return rename(pPath, pTargetPath) == 0 ? XSTDOK : XSTDERR;
#endif
}

#ifdef _WIN32
/*
    Windows has no single filesystem root: the virtual path "/" lists the
    mounted drives instead. Every other path travels in native form with
    forward slashes ("C:/Users/..."), which all Windows APIs accept.
*/
static xjson_obj_t* DirectGate_Files_ListDrives(void)
{
    xjson_obj_t *pRoot = XJSON_NewObject(NULL, NULL, XFALSE);
    XCHECK((pRoot != NULL), NULL);

    XJSON_AddString(pRoot, "path", "/");

    xjson_obj_t *pEntries = XJSON_NewArray(NULL, "entries", XFALSE);
    if (pEntries == NULL)
    {
        XJSON_FreeObject(pRoot);
        return NULL;
    }

    char sOwner[XSTR_MID] = {0};
    DirectGate_GetUserName(sOwner, sizeof(sOwner));

    DWORD nDrives = GetLogicalDrives();
    char cLetter;

    for (cLetter = 'A'; cLetter <= 'Z'; cLetter++)
    {
        if (!(nDrives & (1U << (cLetter - 'A')))) continue;

        char sDrivePath[8];
        snprintf(sDrivePath, sizeof(sDrivePath), "%c:/", cLetter);

        /* Skip media-less removable drives instead of erroring later */
        UINT nType = GetDriveTypeA(sDrivePath);
        if (nType == DRIVE_NO_ROOT_DIR || nType == DRIVE_UNKNOWN) continue;

        xjson_obj_t *pEntry = XJSON_NewObject(NULL, NULL, XFALSE);
        if (pEntry == NULL) continue;

        char sName[4];
        snprintf(sName, sizeof(sName), "%c:", cLetter);

        XJSON_AddString(pEntry, "name", sName);
        XJSON_AddString(pEntry, "path", sDrivePath);
        XJSON_AddString(pEntry, "directoryPath", "/");
        XJSON_AddString(pEntry, "type", "directory");
        XJSON_AddString(pEntry, "permissions", "drwxr-xr-x");
        XJSON_AddString(pEntry, "owner", xstrused(sOwner) ? sOwner : "unknown");
        XJSON_AddString(pEntry, "group", "none");
        XJSON_AddU64(pEntry, "sizeBytes", 0);
        XJSON_AddString(pEntry, "modified", "unknown");
        XJSON_AddObject(pEntries, pEntry);
    }

    XJSON_AddObject(pRoot, pEntries);
    return pRoot;
}
#endif

xjson_obj_t* DirectGate_Files_ListDir(const char *pPath)
{
    XCHECK(xstrused(pPath), xthrowp(NULL, "Path is empty"));

#ifdef _WIN32
    if (!strcmp(pPath, "/") || !strcmp(pPath, "\\"))
        return DirectGate_Files_ListDrives();

    /* A bare "X:" means cwd-on-drive in Win32; the drive root is "X:/" */
    char sDriveFix[4];
    if (isalpha((unsigned char)pPath[0]) && pPath[1] == ':' && pPath[2] == '\0')
    {
        snprintf(sDriveFix, sizeof(sDriveFix), "%s/", pPath);
        pPath = sDriveFix;
    }
#endif

    xdir_t dir;
    if (XDir_Open(&dir, pPath) < 0)
    {
        xloge("Failed to open directory listing target: path(%s), errno(%d)", pPath, errno);
        return NULL;
    }

    xjson_obj_t *pRoot = XJSON_NewObject(NULL, NULL, XFALSE);
    if (pRoot == NULL)
    {
        XDir_Close(&dir);
        return NULL;
    }

    XJSON_AddString(pRoot, "path", pPath);

    xjson_obj_t *pEntries = XJSON_NewArray(NULL, "entries", XFALSE);
    if (pEntries == NULL)
    {
        XJSON_FreeObject(pRoot);
        XDir_Close(&dir);
        return NULL;
    }

    char sFullPath[XPATH_MAX];
    char sName[XNAME_MAX];

    while (XDir_Read(&dir, sName, sizeof(sName)) > 0)
    {
        xstat_t st;
        snprintf(sFullPath, sizeof(sFullPath), "%s/%s", pPath, sName);
        if (xstat(sFullPath, &st) < 0) continue;

        xjson_obj_t *pEntry = DirectGate_Files_CreateEntryJson(sName, pPath, &st);
        if (pEntry == NULL)
        {
            xloge("Failed to allocate JSON object for directory entry: path(%s), entry(%s)", pPath, sName);
            XJSON_FreeObject(pEntries);
            XJSON_FreeObject(pRoot);
            XDir_Close(&dir);
            return NULL;
        }

        XJSON_AddObject(pEntries, pEntry);
    }

    XJSON_AddObject(pRoot, pEntries);
    XDir_Close(&dir);

    return pRoot;
}

XSTATUS DirectGate_Files_Delete(const char *pPath, xbool_t bForce)
{
    XCHECK(xstrused(pPath), xthrowr(XSTDERR, "Path is empty"));

    xstat_t st;
    if (xstat(pPath, &st) < 0)
    {
        xloge("Delete target does not exist: path(%s)", pPath);
        return XSTDERR;
    }

    int nStatus = bForce ? XPath_Remove(pPath) : remove(pPath);
    if (nStatus != 0)
    {
        int nDeleteErrno = errno;

        if (!bForce && S_ISDIR(st.st_mode) &&
            (nDeleteErrno == ENOENT || nDeleteErrno == EEXIST) &&
            DirectGate_Files_DirectoryHasEntries(pPath))
        {
            errno = ENOTEMPTY;
        }
        else
        {
            errno = nDeleteErrno;
        }

        if (bForce && !XPath_Exists(pPath))
        {
            xlogi("File manager target deleted: path(%s), recursive(%s)", pPath, "true");
            return XSTDOK;
        }

        xloge("Failed to delete file manager target: path(%s), errno(%d)", pPath, errno);
        return XSTDERR;
    }

    xlogi("File manager target deleted: path(%s), recursive(%s)", pPath, bForce ? "true" : "false");
    return XSTDOK;
}

XSTATUS DirectGate_Files_CreateDir(const char *pPath)
{
    XCHECK(xstrused(pPath), xthrowr(XSTDERR, "Path is empty"));

    if (XPath_Exists(pPath))
    {
        errno = EEXIST;
        xloge("Directory create target already exists: path(%s)", pPath);
        return XSTDERR;
    }

    if (XDir_Create(pPath, 0755) <= 0)
    {
        xloge("Failed to create directory: path(%s), errno(%d)", pPath, errno);
        return XSTDERR;
    }

    xlogi("File manager directory created: path(%s)", pPath);
    return XSTDOK;
}

static XSTATUS DirectGate_Files_CopyPath(const char *pPath, const char *pTargetPath)
{
    XCHECK(xstrused(pPath), xthrowr(XSTDERR, "Source path is empty"));
    XCHECK(xstrused(pTargetPath), xthrowr(XSTDERR, "Target path is empty"));

    if (xstrcmp(pPath, pTargetPath))
    {
        errno = EINVAL;
        return XSTDERR;
    }

    xstat_t st;
    if (xstat(pPath, &st) < 0) return XSTDERR;

    xstat_t dstSt;
    if (xstat(pTargetPath, &dstSt) == XSTDOK)
    {
        errno = EEXIST;
        return XSTDERR;
    }

    if (S_ISDIR(st.st_mode))
    {
        if (DirectGate_Files_IsNestedTarget(pPath, pTargetPath))
        {
            errno = EINVAL;
            return XSTDERR;
        }

        if (XDir_Create(pTargetPath, st.st_mode & 0777) <= 0)
            return XSTDERR;

        xdir_t dir;
        if (XDir_Open(&dir, pPath) < 0) return XSTDERR;

        char sName[XNAME_MAX];
        char sSrcChild[XFILE_PATH_SIZE];
        char sDstChild[XFILE_PATH_SIZE];

        while (XDir_Read(&dir, sName, sizeof(sName)) > 0)
        {
            snprintf(sSrcChild, sizeof(sSrcChild), "%s/%s", pPath, sName);
            snprintf(sDstChild, sizeof(sDstChild), "%s/%s", pTargetPath, sName);

            if (DirectGate_Files_CopyPath(sSrcChild, sDstChild) < 0)
            {
                XDir_Close(&dir);
                XDir_Remove(pTargetPath);
                return XSTDERR;
            }
        }

        XDir_Close(&dir);
        return XSTDOK;
    }

    return XPath_CopyFile(pPath, pTargetPath) >= 0 ? XSTDOK : XSTDERR;
}

XSTATUS DirectGate_Files_Rename(const char *pPath, const char *pTargetPath)
{
    XCHECK(xstrused(pPath), xthrowr(XSTDERR, "Source path is empty"));
    XCHECK(xstrused(pTargetPath), xthrowr(XSTDERR, "Target path is empty"));

    if (xstrcmp(pPath, pTargetPath)) return XSTDOK;

    xstat_t st;
    if (xstat(pPath, &st) < 0) return XSTDERR;

    if (S_ISDIR(st.st_mode) && DirectGate_Files_IsNestedTarget(pPath, pTargetPath))
    {
        errno = EINVAL;
        return XSTDERR;
    }

    if (DirectGate_Files_RenameNoReplace(pPath, pTargetPath) != XSTDOK)
    {
        if (errno == EEXIST)
        {
            xloge("Rename target already exists: path(%s)", pTargetPath);
        }
        else
        {
            xloge("Failed to rename file manager target: src(%s), dst(%s), errno(%d)", pPath, pTargetPath, errno);
        }

        return XSTDERR;
    }

    xlogi("File manager target renamed: src(%s), dst(%s)", pPath, pTargetPath);
    return XSTDOK;
}

static int DirectGate_Files_SendTransferCancel(directgate_session_t *pSession,
                                           const char *pTransferId,
                                           const char *pReason)
{
    XCHECK((pSession != NULL), XSTDERR);

    xjson_obj_t *pHeader = DirectGate_Proto_BuildFileCancel(pTransferId, pReason);
    XCHECK((pHeader != NULL), XSTDERR);

    int nStatus = DirectGate_Session_Send(pSession, pHeader, NULL, XSTDNON);
    XJSON_FreeObject(pHeader);
    return nStatus;
}

static int DirectGate_Files_SendTransferAck(directgate_session_t *pSession,
                                        const char *pTransferId,
                                        uint32_t nChunkIndex)
{
    XCHECK((pSession != NULL), XSTDERR);

    xjson_obj_t *pHeader = DirectGate_Proto_BuildFileAck(pTransferId, nChunkIndex);
    XCHECK((pHeader != NULL), XSTDERR);

    int nStatus = DirectGate_Session_Send(pSession, pHeader, NULL, XSTDNON);
    XJSON_FreeObject(pHeader);
    return nStatus;
}

static void DirectGate_Files_ClearPendingSave(directgate_session_t *pSession)
{
    XCHECK_VOID_NL((pSession != NULL));
    pSession->sSavePath[0] = '\0';
    pSession->sSaveTempPath[0] = '\0';
    pSession->sSavePermissions[0] = '\0';
    pSession->bSaveForce = XFALSE;
}

static int DirectGate_Files_BuildTempPath(char *pOutput, size_t nSize, const char *pPath)
{
    XCHECK((pOutput != NULL), XSTDERR);
    XCHECK((nSize > 0), XSTDERR);
    XCHECK((xstrused(pPath)), XSTDERR);

    char sDir[XFILE_PATH_SIZE];
    xstrncpy(sDir, sizeof(sDir), pPath);

    char *pSlash = strrchr(sDir, '/');
    const char *pName = pSlash ? pSlash + 1 : pPath;

    if (pSlash == NULL) xstrncpy(sDir, sizeof(sDir), ".");
    else if (pSlash == sDir) pSlash[1] = '\0';
    else *pSlash = '\0';

    for (int i = 0; i < DIRECTGATE_UPLOAD_TEMP_ATTEMPTS; i++)
    {
        uint8_t sRandom[DIRECTGATE_UPLOAD_TEMP_RANDOM_SIZE];
        char sRandomHex[(DIRECTGATE_UPLOAD_TEMP_RANDOM_SIZE * 2) + 1];

        if (RAND_bytes(sRandom, sizeof(sRandom)) != 1)
            return XSTDERR;

        for (size_t j = 0; j < sizeof(sRandom); j++)
            snprintf(&sRandomHex[j * 2], sizeof(sRandomHex) - (j * 2), "%02x", sRandom[j]);

        int nWritten = snprintf(pOutput, nSize, "%s/.directgate-upload-%s-%s.part",
            sDir, sRandomHex, pName);

        if (nWritten <= 0 || (size_t)nWritten >= nSize)
            return XSTDERR;

        if (!XPath_Exists(pOutput))
            return XSTDOK;
    }

    errno = EEXIST;
    return XSTDERR;
}

/* File transfer send callback: header comes from transfer.c, we handle cc/build/encrypt/route */
int DirectGate_Files_TransferSendCb(xjson_obj_t *pHeader, const uint8_t *pPayload,
                                size_t nLen, void *pCtx)
{
    directgate_session_t *pSession = (directgate_session_t*)pCtx;
    XCHECK((pSession != NULL), xthrowr(XSTDERR, "Invalid session data"));
    XCHECK((pHeader != NULL), xthrowr(XSTDERR, "Invalid header for file transfer"));

    if (!pSession->bAuthenticated)
    {
        int nWsFd = pSession->pWsSession != NULL ? (int)pSession->pWsSession->sock.nFD : (int)XSOCK_INVALID;
        xloge("File transfer rejected, session is not authenticated: sid(%u), wsfd(%d)", pSession->nSessionId, nWsFd);

        DirectGate_Session_Close(pSession, "session not authenticated for files action");
        return XSTDERR;
    }

    int nStatus = DirectGate_Session_Send(pSession, pHeader, pPayload, nLen);
    return (nStatus >= 0) ? XSTDOK : XSTDERR;
}

void DirectGate_Files_ProcessTransfer(directgate_session_t *pSession)
{
    XCHECK_VOID_NL((pSession != NULL));
    if (pSession->transfer.eState != XTRANSFER_STATE_SENDING) return;

    if (DirectGate_Transfer_SendNext(&pSession->transfer, DirectGate_Files_TransferSendCb, pSession) >= 0)
        return;

    char sTransferId[XFILE_ID_SIZE];
    int nWsFd = pSession->pWsSession != NULL ? (int)pSession->pWsSession->sock.nFD : (int)XSOCK_INVALID;

    xstrncpy(sTransferId, sizeof(sTransferId), pSession->transfer.sId);
    xloge("Failed to advance outbound file transfer: sid(%u), wsfd(%d), transferId(%s), chunk(%u)",
        pSession->nSessionId, nWsFd, xstrused(sTransferId) ? sTransferId : "N/A",
        pSession->transfer.nCurrentChunk);

    if (xstrused(sTransferId))
        DirectGate_Files_SendTransferCancel(pSession, sTransferId, "file transfer failed");

    DirectGate_Transfer_Destroy(&pSession->transfer);
}

int DirectGate_Files_HandleManager(xapi_session_t *pApiSession, directgate_pkg_t *pPkg)
{
    XCHECK((pPkg != NULL && pPkg->pPackage != NULL), XAPI_CONTINUE);
    const directgate_pkg_manager_t *pMgrPkg = (const directgate_pkg_manager_t*)pPkg->pPackage;

    directgate_conn_t *pConn = (directgate_conn_t*)pApiSession->pSessionData;
    XCHECK((pConn != NULL), xthrowr(XAPI_DISCONNECT, "Invalid connection"));

    directgate_session_t *pSession = DirectGate_SessionMgr_Find(&pConn->mgr, pPkg->header.nSessionId);
    XCHECK_NL((pSession != NULL), XAPI_CONTINUE);

    if (DirectGate_Session_EnsureMode(pSession, DIRECTGATE_SESSION_MODE_FILE_MANAGER,
        "file manager session not started") != XSTDOK) return XAPI_CONTINUE;

    if (!xstrused(pMgrPkg->pAction))
    {
        int nWsFd = pSession->pWsSession != NULL ? (int)pSession->pWsSession->sock.nFD : (int)XSOCK_INVALID;
        xlogw("Manager message is missing action: sid(%u), wsfd(%d)", pSession->nSessionId, nWsFd);
        return XAPI_CONTINUE;
    }

    if (!xstrused(pMgrPkg->pPath))
    {
        return DirectGate_Session_SendManagerResp(pSession,
            pMgrPkg->pAction, "failed", "missing path", NULL);
    }

    if (xstrcmp(pMgrPkg->pAction, "list"))
    {
        xjson_obj_t *pList = DirectGate_Files_ListDir(pMgrPkg->pPath);
        if (pList == NULL)
        {
            return DirectGate_Session_SendManagerResp(pSession, "list",
                "failed", "failed to read directory", pMgrPkg->pPath);
        }

        size_t nJsonLen = 0;
        char *pJson = XJSON_DumpObj(pList, 0, &nJsonLen);
        XJSON_FreeObject(pList);

        if (pJson == NULL || nJsonLen == 0)
        {
            free(pJson);
            return DirectGate_Session_SendManagerResp(pSession, "list",
                "failed", "failed to serialize listing", pMgrPkg->pPath);
        }

        int nRet = DirectGate_Session_SendManagerData(pSession, "list", "ok",
            pMgrPkg->pPath, (const uint8_t*)pJson, nJsonLen);

        free(pJson);
        return nRet;
    }

    if (xstrcmp(pMgrPkg->pAction, "search"))
    {
        if (pMgrPkg->bCancel)
        {
            int nCancel = DirectGate_Search_Cancel(&pSession->search);
            if (nCancel < 0)
            {
                return DirectGate_Session_SendManagerResp(pSession, "search",
                    "failed", DirectGate_Search_GetReason(&pSession->search), pMgrPkg->pPath);
            }

            if (nCancel == XSTDNON)
            {
                return DirectGate_Session_SendManagerResp(pSession, "search",
                    "cancelled", DirectGate_Search_GetReason(&pSession->search), pMgrPkg->pPath);
            }

            int nWsFd = pSession->pWsSession != NULL ? (int)pSession->pWsSession->sock.nFD : (int)XSOCK_INVALID;
            xlogi("Search cancellation requested: sid(%u), wsfd(%d), path(%s)",
                pSession->nSessionId, nWsFd, pMgrPkg->pPath);

            return XAPI_CONTINUE;
        }

        if (DirectGate_Search_Start(&pSession->search, pMgrPkg) < 0)
        {
            return DirectGate_Session_SendManagerResp(pSession, "search",
                "failed", DirectGate_Search_GetReason(&pSession->search), pMgrPkg->pPath);
        }

        int nWsFd = pSession->pWsSession != NULL ? (int)pSession->pWsSession->sock.nFD : (int)XSOCK_INVALID;
        xlogi("Search started: sid(%u), wsfd(%d), path(%s), pattern(%s)",
            pSession->nSessionId, nWsFd, pMgrPkg->pPath,
            xstrused(pMgrPkg->pFileName) ? pMgrPkg->pFileName : "*");

        return XAPI_CONTINUE;
    }

    if (xstrcmp(pMgrPkg->pAction, "open"))
    {
        xstat_t st;
        if (xstat(pMgrPkg->pPath, &st) < 0 || !S_ISREG(st.st_mode))
        {
            return DirectGate_Session_SendManagerResp(pSession, "open",
                "failed", "file not found or not a regular file", pMgrPkg->pPath);
        }

        if (DirectGate_Transfer_IsActive(&pSession->transfer))
        {
            return DirectGate_Session_SendManagerResp(pSession, "open",
                "failed", "transfer already in progress", pMgrPkg->pPath);
        }

        if (DirectGate_Transfer_Send(&pSession->transfer, pMgrPkg->pPath, DirectGate_Files_TransferSendCb, pSession) < 0)
        {
            DirectGate_Transfer_Destroy(&pSession->transfer);
            return DirectGate_Session_SendManagerResp(pSession, "open",
                "failed", "failed to start file transfer", pMgrPkg->pPath);
        }

        return DirectGate_Session_SendManagerResp(pSession, "open", "ok", NULL, pMgrPkg->pPath);
    }

    if (xstrcmp(pMgrPkg->pAction, "save"))
    {
        if (DirectGate_Transfer_IsActive(&pSession->transfer))
        {
            return DirectGate_Session_SendManagerResp(pSession, "save",
                "failed", "transfer already in progress", pMgrPkg->pPath);
        }

        if (!pMgrPkg->bForce)
        {
            xstat_t st;
            if (xstat(pMgrPkg->pPath, &st) == XSTDOK)
            {
                return DirectGate_Session_SendManagerResp(pSession, "save",
                    "exists", "file already exists", pMgrPkg->pPath);
            }
        }

        xstrncpy(pSession->sSavePath, sizeof(pSession->sSavePath), pMgrPkg->pPath);
        if (DirectGate_Files_BuildTempPath(pSession->sSaveTempPath,
            sizeof(pSession->sSaveTempPath), pMgrPkg->pPath) < 0)
        {
            DirectGate_Files_ClearPendingSave(pSession);
            return DirectGate_Session_SendManagerResp(pSession, "save",
                "failed", "failed to create temporary upload path", pMgrPkg->pPath);
        }

        pSession->bSaveForce = pMgrPkg->bForce;
        if (!xstrused(pMgrPkg->pPermissions)) pSession->sSavePermissions[0] = '\0';
        else xstrncpy(pSession->sSavePermissions, sizeof(pSession->sSavePermissions), pMgrPkg->pPermissions);

        return DirectGate_Session_SendManagerResp(pSession, "save", "ok", NULL, pMgrPkg->pPath);
    }

    if (xstrcmp(pMgrPkg->pAction, "mkdir"))
    {
        if (DirectGate_Files_CreateDir(pMgrPkg->pPath) < 0)
        {
            return DirectGate_Session_SendManagerResp(pSession, "mkdir",
                "failed", DirectGate_Files_LastError(), pMgrPkg->pPath);
        }

        if (xstrused(pMgrPkg->pPermissions))
        {
            if (XPath_SetPerm(pMgrPkg->pPath, pMgrPkg->pPermissions) == XSTDOK)
            {
                xlogd("Applied source permissions to directory: path(%s), perm(%s)",
                    pMgrPkg->pPath, pMgrPkg->pPermissions);
            }
            else
            {
                xloge("Failed to apply source permissions to directory: path(%s), perm(%s), errno(%d)",
                    pMgrPkg->pPath, pMgrPkg->pPermissions, errno);
            }
        }

        return DirectGate_Session_SendManagerResp(pSession, "mkdir", "ok", NULL, pMgrPkg->pPath);
    }

    if (xstrcmp(pMgrPkg->pAction, "rename"))
    {
        if (!xstrused(pMgrPkg->pTargetPath))
        {
            return DirectGate_Session_SendManagerResp(pSession, "rename",
                "failed", "missing target path", pMgrPkg->pPath);
        }

        if (DirectGate_Files_Rename(pMgrPkg->pPath, pMgrPkg->pTargetPath) < 0)
        {
            return DirectGate_Session_SendManagerResp(pSession, "rename",
                "failed", DirectGate_Files_LastError(), pMgrPkg->pPath);
        }

        return DirectGate_Session_SendManagerResp(pSession, "rename", "ok", NULL, pMgrPkg->pTargetPath);
    }

    if (xstrcmp(pMgrPkg->pAction, "copy"))
    {
        char sResolvedTarget[XFILE_PATH_SIZE];
        if (!xstrused(pMgrPkg->pTargetPath))
        {
            return DirectGate_Session_SendManagerResp(pSession, "copy",
                "failed", "missing target path", pMgrPkg->pPath);
        }

        if (DirectGate_Files_ResolvePasteTarget(sResolvedTarget,
            sizeof(sResolvedTarget), pMgrPkg->pTargetPath) < 0)
        {
            return DirectGate_Session_SendManagerResp(pSession, "copy",
                "failed", DirectGate_Files_LastError(), pMgrPkg->pPath);
        }

        if (DirectGate_Files_CopyPath(pMgrPkg->pPath, sResolvedTarget) < 0)
        {
            return DirectGate_Session_SendManagerResp(pSession, "copy",
                "failed", DirectGate_Files_LastError(), pMgrPkg->pPath);
        }

        return DirectGate_Session_SendManagerResp(pSession, "copy", "ok", NULL, sResolvedTarget);
    }

    if (xstrcmp(pMgrPkg->pAction, "move"))
    {
        char sResolvedTarget[XFILE_PATH_SIZE];
        if (!xstrused(pMgrPkg->pTargetPath))
        {
            return DirectGate_Session_SendManagerResp(pSession, "move",
                "failed", "missing target path", pMgrPkg->pPath);
        }

        if (xstrcmp(pMgrPkg->pPath, pMgrPkg->pTargetPath))
        {
            return DirectGate_Session_SendManagerResp(pSession, "move", "ok", NULL, pMgrPkg->pPath);
        }

        if (DirectGate_Files_ResolvePasteTarget(sResolvedTarget,
            sizeof(sResolvedTarget), pMgrPkg->pTargetPath) < 0)
        {
            return DirectGate_Session_SendManagerResp(pSession, "move",
                "failed", DirectGate_Files_LastError(), pMgrPkg->pPath);
        }

        if (DirectGate_Files_Rename(pMgrPkg->pPath, sResolvedTarget) < 0)
        {
            return DirectGate_Session_SendManagerResp(pSession, "move",
                "failed", DirectGate_Files_LastError(), pMgrPkg->pPath);
        }

        return DirectGate_Session_SendManagerResp(pSession, "move", "ok", NULL, sResolvedTarget);
    }

    if (xstrcmp(pMgrPkg->pAction, "delete"))
    {
        if (DirectGate_Files_Delete(pMgrPkg->pPath, pMgrPkg->bForce) < 0)
        {
            return DirectGate_Session_SendManagerResp(pSession, "delete",
                "failed", DirectGate_Files_LastError(), pMgrPkg->pPath);
        }

        return DirectGate_Session_SendManagerResp(pSession, "delete", "ok", NULL, pMgrPkg->pPath);
    }

    {
        int nWsFd = pSession->pWsSession != NULL ? (int)pSession->pWsSession->sock.nFD : (int)XSOCK_INVALID;
        xlogw("Unknown manager action: sid(%u), wsfd(%d), action(%s)", pSession->nSessionId, nWsFd, pMgrPkg->pAction);
    }

    return DirectGate_Session_SendManagerResp(pSession, pMgrPkg->pAction,
        "failed", "unknown action", pMgrPkg->pPath);
}

int DirectGate_Files_HandleFile(xapi_session_t *pApiSession, directgate_pkg_t *pPkg)
{
    XCHECK((pPkg != NULL && pPkg->pPackage != NULL), XAPI_CONTINUE);
    const directgate_pkg_file_t *pFilePkg = (const directgate_pkg_file_t*)pPkg->pPackage;

    directgate_conn_t *pConn = (directgate_conn_t*)pApiSession->pSessionData;
    XCHECK((pConn != NULL), xthrowr(XAPI_DISCONNECT, "Invalid connection"));

    directgate_session_t *pSession = DirectGate_SessionMgr_Find(&pConn->mgr, pPkg->header.nSessionId);
    XCHECK_NL((pSession != NULL), XAPI_CONTINUE);

    if (DirectGate_Session_EnsureMode(pSession, DIRECTGATE_SESSION_MODE_FILE_MANAGER,
        "file manager session not started") != XSTDOK) return XAPI_CONTINUE;

    if (!xstrused(pFilePkg->pAction))
    {
        int nWsFd = pSession->pWsSession != NULL ? (int)pSession->pWsSession->sock.nFD : (int)XSOCK_INVALID;
        xlogw("File transfer message is missing action: sid(%u), wsfd(%d)", pSession->nSessionId, nWsFd);
        return XAPI_CONTINUE;
    }

    directgate_transfer_t *pFT = &pSession->transfer;

    if (xstrcmp(pFilePkg->pAction, "start"))
    {
        const char *pTransferId = pFilePkg->transfer.pTransferId;
        const char *pSavePath = xstrused(pSession->sSaveTempPath)
            ? pSession->sSaveTempPath
            : (xstrused(pSession->sSavePath) ? pSession->sSavePath : NULL);

        if (pSavePath != NULL
            ? DirectGate_Transfer_HandleStartPath(pFT, pPkg, pSavePath) < 0
            : DirectGate_Transfer_HandleStart(pFT, pPkg, ".") < 0)
        {
            int nWsFd = pSession->pWsSession != NULL ? (int)pSession->pWsSession->sock.nFD : (int)XSOCK_INVALID;
            xloge("Failed to start inbound file transfer: sid(%u), wsfd(%d), transferId(%s), path(%s)",
                pSession->nSessionId, nWsFd, pTransferId, xstrused(pSavePath) ? pSavePath : ".");

            DirectGate_Files_SendTransferCancel(pSession, pTransferId, DirectGate_Files_LastError());
            DirectGate_Files_ClearPendingSave(pSession);
        }
    }
    else if (xstrcmp(pFilePkg->pAction, "chunk"))
    {
        if (DirectGate_Transfer_HandleChunk(pFT, pPkg) < 0)
        {
            int nWsFd = pSession->pWsSession != NULL ? (int)pSession->pWsSession->sock.nFD : (int)XSOCK_INVALID;
            xloge("Failed to handle inbound file chunk: sid(%u), wsfd(%d), transferId(%s), chunk(%u)",
                pSession->nSessionId, nWsFd, pFilePkg->transfer.pTransferId, pFilePkg->transfer.nChunkIndex);

            DirectGate_Files_SendTransferCancel(pSession, pFilePkg->transfer.pTransferId, DirectGate_Files_LastError());
            DirectGate_Transfer_HandleCancel(pFT);
            DirectGate_Files_ClearPendingSave(pSession);
        }
    }
    else if (xstrcmp(pFilePkg->pAction, "end"))
    {
        if (DirectGate_Transfer_HandleEnd(pFT, pPkg, NULL, NULL) < 0)
        {
            int nWsFd = pSession->pWsSession != NULL ? (int)pSession->pWsSession->sock.nFD : (int)XSOCK_INVALID;
            xloge("Failed to finalize inbound file transfer: sid(%u), wsfd(%d), transferId(%s)",
                pSession->nSessionId, nWsFd, pFilePkg->transfer.pTransferId);

            DirectGate_Files_SendTransferCancel(pSession, pFilePkg->transfer.pTransferId, DirectGate_Files_LastError());
            if (xstrused(pFT->sPath)) remove(pFT->sPath);
            DirectGate_Files_ClearPendingSave(pSession);
        }
        else if (xstrused(pSession->sSaveTempPath) && xstrused(pSession->sSavePath))
        {
            xstat_t st;
            xbool_t bHasOrigPerms = (xstat(pSession->sSavePath, &st) == XSTDOK);

            if (bHasOrigPerms && !pSession->bSaveForce)
            {
                errno = EEXIST;
                int nWsFd = pSession->pWsSession != NULL ? (int)pSession->pWsSession->sock.nFD : (int)XSOCK_INVALID;
                xloge("Save target appeared during upload: sid(%u), wsfd(%d), path(%s)", pSession->nSessionId, nWsFd, pSession->sSavePath);

                DirectGate_Files_SendTransferCancel(pSession, pFilePkg->transfer.pTransferId, DirectGate_Files_LastError());
                remove(pSession->sSaveTempPath);
                DirectGate_Files_ClearPendingSave(pSession);
                return XAPI_CONTINUE;
            }

            /* Commit the upload. Non-force saves use an atomic no-replace
               rename so a file that appears between the xstat() above and
               this rename cannot be silently overwritten (TOCTOU). Force
               saves intentionally replace the existing target. */
            int nCommit = pSession->bSaveForce
                ? DirectGate_Files_RenameReplace(pSession->sSaveTempPath, pSession->sSavePath)
                : DirectGate_Files_RenameNoReplace(pSession->sSaveTempPath, pSession->sSavePath);

            if (nCommit != XSTDOK)
            {
                int nWsFd = pSession->pWsSession != NULL ? (int)pSession->pWsSession->sock.nFD : (int)XSOCK_INVALID;
                xloge("Failed to commit uploaded file: sid(%u), wsfd(%d), tmp(%s), dst(%s), errno(%d)",
                    pSession->nSessionId, nWsFd, pSession->sSaveTempPath, pSession->sSavePath, errno);

                DirectGate_Files_SendTransferCancel(pSession, pFilePkg->transfer.pTransferId, DirectGate_Files_LastError());
                remove(pSession->sSaveTempPath);
                DirectGate_Files_ClearPendingSave(pSession);
                return XAPI_CONTINUE;
            }

            if (bHasOrigPerms)
            {
                char sPerm[XPERM_LEN + 1];
                XPath_ModeToPerm(sPerm, sizeof(sPerm), st.st_mode);

                if (XPath_SetPerm(pSession->sSavePath, sPerm) == XSTDOK)
                {
                    xlogd("Restored original file permissions: path(%s), perm(%s)",
                        pSession->sSavePath, sPerm);
                }
                else
                {
                    xloge("Failed to restore original file permissions: path(%s), perm(%s), errno(%d)",
                        pSession->sSavePath, sPerm, errno);
                }
            }
            else if (xstrused(pSession->sSavePermissions))
            {
                if (XPath_SetPerm(pSession->sSavePath, pSession->sSavePermissions) == XSTDOK)
                {
                    xlogd("Applied source permissions to uploaded file: path(%s), perm(%s)",
                        pSession->sSavePath, pSession->sSavePermissions);
                }
                else
                {
                    xloge("Failed to apply source permissions to uploaded file: path(%s), perm(%s), errno(%d)",
                        pSession->sSavePath, pSession->sSavePermissions, errno);
                }
            }

            xstrncpy(pFT->sPath, sizeof(pFT->sPath), pSession->sSavePath);
            DirectGate_Files_SendTransferAck(pSession, pFilePkg->transfer.pTransferId, pFT->nCurrentChunk);
            DirectGate_Files_ClearPendingSave(pSession);
        }
        else
        {
            DirectGate_Files_SendTransferAck(pSession, pFilePkg->transfer.pTransferId, pFT->nCurrentChunk);
            DirectGate_Files_ClearPendingSave(pSession);
        }
    }
    else if (xstrcmp(pFilePkg->pAction, "ack"))
    {
        int nWsFd = pSession->pWsSession != NULL ? (int)pSession->pWsSession->sock.nFD : (int)XSOCK_INVALID;
        xlogd("Received file transfer ack: sid(%u), wsfd(%d), transferId(%s), chunk(%u)",
            pSession->nSessionId, nWsFd, pFilePkg->transfer.pTransferId, pFilePkg->transfer.nChunkIndex);
    }
    else if (xstrcmp(pFilePkg->pAction, "cancel"))
    {
        DirectGate_Transfer_HandleCancel(pFT);
        DirectGate_Files_ClearPendingSave(pSession);
    }

    return XAPI_CONTINUE;
}
