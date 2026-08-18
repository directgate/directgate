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

/* How much of the target name the temp file keeps. The temp name also carries
   a fixed 19-char prefix, 32 hex characters of random material, a separator
   and a ".part" suffix, and the whole thing has to fit in one filesystem
   component (255 bytes on every filesystem we run on). Without the cap a long
   upload name pushed the temp name past that limit and the upload failed at
   file/start with a bare ENAMETOOLONG. */
#define DIRECTGATE_UPLOAD_TEMP_NAME_MAX    64

#ifndef _WIN32
/* getpwuid_r/getgrgid_r are a name-service call each, and a listing makes two
   per entry - on a plain /etc/passwd host that is an open-and-scan per lookup,
   and on a host wired to LDAP or SSSD it can be a network round trip. A
   directory is almost always owned by one or two accounts, so a tiny memo
   collapses thousands of lookups into a handful.

   Thread-local because DirectGate_Files_CreateEntryJson runs on both the main
   loop and the async search worker. The whole memo is dropped once it ages
   out, so a renamed account is picked up on the next listing rather than at
   the next restart. */
#define DIRECTGATE_FILES_ID_CACHE_SIZE   8
#define DIRECTGATE_FILES_ID_CACHE_TTL_MS 60000ULL
#define DIRECTGATE_FILES_ID_NAME_SIZE    64

#if defined(__GNUC__) || defined(__clang__)
#define DIRECTGATE_FILES_TLS __thread
#else
#define DIRECTGATE_FILES_TLS _Thread_local
#endif

typedef struct directgate_files_id_cache_ {
    struct {
        char sName[DIRECTGATE_FILES_ID_NAME_SIZE];
        uint32_t nId;
        xbool_t bUsed;
    } entries[DIRECTGATE_FILES_ID_CACHE_SIZE];

    unsigned int nNextSlot;
    uint64_t nStampMs;
    xbool_t bStamped;
} directgate_files_id_cache_t;

static void DirectGate_Files_ExpireIdCache(directgate_files_id_cache_t *pCache)
{
    uint64_t nNowMs = XTime_GetMs();

    if (pCache->bStamped &&
        nNowMs - pCache->nStampMs < DIRECTGATE_FILES_ID_CACHE_TTL_MS) return;

    memset(pCache->entries, 0, sizeof(pCache->entries));
    pCache->nNextSlot = 0;
    pCache->nStampMs = nNowMs;
    pCache->bStamped = XTRUE;
}

static const char* DirectGate_Files_FindCachedId(const directgate_files_id_cache_t *pCache, uint32_t nId)
{
    unsigned int i;

    for (i = 0; i < DIRECTGATE_FILES_ID_CACHE_SIZE; i++)
    {
        if (pCache->entries[i].bUsed && pCache->entries[i].nId == nId)
            return pCache->entries[i].sName;
    }

    return NULL;
}

static void DirectGate_Files_StoreCachedId(directgate_files_id_cache_t *pCache, uint32_t nId, const char *pName)
{
    /* A name that does not fit is not cached at all, so a hit can never answer
       with a shorter string than the miss that filled it. */
    if (strlen(pName) >= sizeof(pCache->entries[0].sName)) return;

    /* Round-robin eviction: the working set of a listing is one or two ids,
       so anything smarter would only cost more than it saves. */
    unsigned int nSlot = pCache->nNextSlot % DIRECTGATE_FILES_ID_CACHE_SIZE;

    xstrncpy(pCache->entries[nSlot].sName, sizeof(pCache->entries[nSlot].sName), pName);
    pCache->entries[nSlot].nId = nId;
    pCache->entries[nSlot].bUsed = XTRUE;
    pCache->nNextSlot = nSlot + 1;
}

static const char* DirectGate_Files_UserName(uid_t nUid, char *pOutput, size_t nSize)
{
    static DIRECTGATE_FILES_TLS directgate_files_id_cache_t cache;
    DirectGate_Files_ExpireIdCache(&cache);

    const char *pCached = DirectGate_Files_FindCachedId(&cache, (uint32_t)nUid);
    if (pCached != NULL) return pCached;

    struct passwd pwd, *pw = NULL;
    char sBuf[XSTR_MID];

    if (getpwuid_r(nUid, &pwd, sBuf, sizeof(sBuf), &pw) != 0) pw = NULL;
    const char *pName = (pw != NULL && xstrused(pw->pw_name)) ? pw->pw_name : "unknown";

    /* Copied out before caching: pw points into sBuf, which dies with this
       frame, and the caller's buffer keeps a name too long for the memo. */
    xstrncpy(pOutput, nSize, pName);
    DirectGate_Files_StoreCachedId(&cache, (uint32_t)nUid, pName);

    return pOutput;
}

static const char* DirectGate_Files_GroupName(gid_t nGid, char *pOutput, size_t nSize)
{
    static DIRECTGATE_FILES_TLS directgate_files_id_cache_t cache;
    DirectGate_Files_ExpireIdCache(&cache);

    const char *pCached = DirectGate_Files_FindCachedId(&cache, (uint32_t)nGid);
    if (pCached != NULL) return pCached;

    struct group grp, *gr = NULL;
    char sBuf[XSTR_MID];

    if (getgrgid_r(nGid, &grp, sBuf, sizeof(sBuf), &gr) != 0) gr = NULL;
    const char *pName = (gr != NULL && xstrused(gr->gr_name)) ? gr->gr_name : "unknown";

    xstrncpy(pOutput, nSize, pName);
    DirectGate_Files_StoreCachedId(&cache, (uint32_t)nGid, pName);

    return pOutput;
}
#endif /* !_WIN32 */

/* Whether anything sits at this path, a link with a missing target included.
   XPath_Exists() stats through a link and answers "no" for one of those, which
   would have a caller pick a name that is already taken and then fail on the
   exclusive create that follows. */
static xbool_t DirectGate_Files_EntryExists(const char *pPath)
{
    xstat_t st;
    if (xstat(pPath, &st) == XSTDOK) return XTRUE;

    /* xstat() is an lstat on POSIX and has already answered; on Windows
       it followed the link, so a dangling one needs the attribute. */
    return XPath_IsLink(pPath);
}

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

    if (!DirectGate_Files_EntryExists(pTargetPath))
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
        if (!DirectGate_Files_EntryExists(pOutput)) return XSTDOK;
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

#ifndef _WIN32
/* A symlink stays a symlink in the listing, but the client cannot act on one
   without knowing what it resolves to: a link to a directory has to be
   enterable and a link to a file downloadable, and the lstat behind the entry
   cannot say which it is. A dangling link simply carries no target fields.

   Windows needs none of this - xstat() there is a stat() that already follows,
   so a link is reported as whatever it points at. */
static void DirectGate_Files_AddLinkTarget(xjson_obj_t *pEntry, const char *pFullPath)
{
    char sTarget[XFILE_PATH_SIZE];
    ssize_t nLength = readlink(pFullPath, sTarget, sizeof(sTarget) - 1);

    if (nLength > 0)
    {
        sTarget[nLength] = XSTR_NUL;
        XJSON_AddString(pEntry, "target", sTarget);
    }

    /* stat() rather than xstat(), which is an lstat: this one has to follow. */
    xstat_t targetSt;
    if (stat(pFullPath, &targetSt) != 0) return;

    xfile_type_t eTargetType = XFile_GetType((xmode_t)targetSt.st_mode);
    XJSON_AddString(pEntry, "targetType", DirectGate_Files_TypeStr(eTargetType));
    XJSON_AddU64(pEntry, "targetSizeBytes", (uint64_t)targetSt.st_size);

    char sPerm[16], sFullPerm[32];
    XPath_ModeToPerm(sPerm, sizeof(sPerm), (xmode_t)targetSt.st_mode);
    snprintf(sFullPerm, sizeof(sFullPerm), "%c%s", XFile_GetTypeChar(eTargetType), sPerm);

    XJSON_AddString(pEntry, "targetPermissions", sFullPerm);
}
#endif

/* Resolves a symlink to the real path behind it, or NULL when the path is not
   a link and can be used as it stands. The caller frees the result. */
static char* DirectGate_Files_ResolveLink(const char *pPath)
{
#ifdef _WIN32
    /* xstat() is a stat() here and the CRT opens through a reparse point, so
       there is nothing to resolve by hand. */
    (void)pPath;
    return NULL;
#else
    xstat_t linkSt;
    if (xstat(pPath, &linkSt) != XSTDOK || !S_ISLNK(linkSt.st_mode)) return NULL;

    /* realpath() allocates its own buffer here rather than writing into one
       sized against PATH_MAX, which is not a bound this code can assume. */
    char *pResolved = realpath(pPath, NULL);
    if (pResolved == NULL)
    {
        xlogw("Failed to resolve symlink: path(%s), errno(%d)", pPath, errno);
        return NULL;
    }

    return pResolved;
#endif
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

#ifndef _WIN32
    if (eType & XF_SYMLINK) DirectGate_Files_AddLinkTarget(pEntry, sFullPath);
#endif

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
       localtime would race. Use the _r variants, memoised per thread. */
    char sOwner[XSTR_MID];
    char sGroup[XSTR_MID];

    XJSON_AddString(pEntry, "owner", DirectGate_Files_UserName(pStat->st_uid, sOwner, sizeof(sOwner)));
    XJSON_AddString(pEntry, "group", DirectGate_Files_GroupName(pStat->st_gid, sGroup, sizeof(sGroup)));
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

        /* A truncated join names a different, shorter path - one that can exist and
           would then be reported with another file's stat. Skip the entry instead. */
        int nPathLen = snprintf(sFullPath, sizeof(sFullPath), "%s/%s", pPath, sName);
        if (nPathLen <= 0 || (size_t)nPathLen >= sizeof(sFullPath)) continue;
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

        if (bForce && !DirectGate_Files_EntryExists(pPath))
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

    if (DirectGate_Files_EntryExists(pPath))
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

/* Applies the source mode to a path this copy just created. Best effort: a
   copy whose bytes are in place is not failed over a mode that would not set. */
static void DirectGate_Files_ApplyMode(const char *pPath, xmode_t nMode)
{
    char sPerm[XPERM_LEN + 1];
    int nSavedErrno = errno;

    if (XPath_ModeToPerm(sPerm, sizeof(sPerm), nMode) == XPERM_LEN &&
        XPath_SetPerm(pPath, sPerm) != XSTDOK)
    {
        xlogw("Failed to apply source permissions to copy: path(%s), perm(%s), errno(%d)",
            pPath, sPerm, errno);
    }

    errno = nSavedErrno;
}

/* Whether a directory entry has anything a copy can reproduce: directories are
   walked, regular files are read, and a link is recreated as a link - so where
   it points, or whether it points anywhere at all, does not matter. Sockets,
   FIFOs and device nodes have no content and no equivalent to recreate. */
static xbool_t DirectGate_Files_IsCopyableEntry(const char *pPath, const xstat_t *pLinkStat)
{
#ifdef S_ISLNK
    (void)pPath;
    if (S_ISLNK(pLinkStat->st_mode)) return XTRUE;
#else
    /* Windows stats through a reparse point, so a junction looks like the
       directory it points at, and there is no symlink() to reproduce it with.
       Skipped rather than walked into: copying it would pull a whole tree in
       from outside the folder being copied. */
    if (XPath_IsLink(pPath)) return XFALSE;
#endif

    return (S_ISDIR(pLinkStat->st_mode) || S_ISREG(pLinkStat->st_mode))
        ? XTRUE : XFALSE;
}

#ifdef S_ISLNK
/* Recreates a symlink at the destination, pointing exactly where the source
   one points. Copying the content instead would turn one entry into a whole
   tree, and a link back up the tree into an endless one. Defined only where
   links exist: the Windows CRT reports nothing as one, so nothing calls it. */
static XSTATUS DirectGate_Files_CopyLink(const char *pPath, const char *pTargetPath)
{
    char sTarget[XFILE_PATH_SIZE];
    ssize_t nLength = readlink(pPath, sTarget, sizeof(sTarget) - 1);

    if (nLength <= 0) return XSTDERR;

    /* A target that filled the buffer may have been cut short, and a link to
       half a path is worse than no link at all. */
    if ((size_t)nLength >= sizeof(sTarget) - 1)
    {
        errno = ENAMETOOLONG;
        return XSTDERR;
    }

    sTarget[nLength] = XSTR_NUL;
    return symlink(sTarget, pTargetPath) == 0 ? XSTDOK : XSTDERR;
}
#endif /* S_ISLNK */

/* Copies one regular file. The library does the reading, the writing and the
   permissions; what is added here is an exclusive create, so the destination
   this session already checked was absent cannot be swapped for a symlink or
   another file between that check and the write. */
static XSTATUS DirectGate_Files_CopyRegularFile(const char *pPath, const char *pTargetPath)
{
    /* Non-blocking: a FIFO would otherwise park the whole agent loop inside
       open() until someone writes to it. The type is then checked through the
       descriptor, so the check and the reads apply to the same object. */
    xfile_t srcFile;
    if (XFile_Open(&srcFile, pPath, "rni", NULL) < 0) return XSTDERR;

    if (XFile_GetStats(&srcFile) < 0 || !S_ISREG(srcFile.nMode))
    {
        int nSavedErrno = S_ISREG(srcFile.nMode) ? errno : EINVAL;
        XFile_Close(&srcFile);
        errno = nSavedErrno;
        return XSTDERR;
    }

    /* Created 0600 and exclusive: the bytes land before anyone but this
       account can read them, and the source mode is applied once they have. */
    xfile_t dstFile;
    if (XFile_OpenM(&dstFile, pTargetPath, "cwtei", 0600) < 0)
    {
        int nSavedErrno = errno;
        XFile_Close(&srcFile);
        errno = nSavedErrno;
        return XSTDERR;
    }

    int nCopied = XFile_Copy(&srcFile, &dstFile);
    int nSavedErrno = errno;

    XFile_Close(&dstFile);
    XFile_Close(&srcFile);

    if (nCopied < 0)
    {
        xunlink(pTargetPath);
        errno = nSavedErrno;
        return XSTDERR;
    }

    /* The mode of the object behind the descriptor, so a symlinked source
       copies the permissions of the file it points at rather than the 0777
       the link itself reports. */
    DirectGate_Files_ApplyMode(pTargetPath, srcFile.nMode);
    return XSTDOK;
}

/* Takes the source stat the caller already has: the recursive walk below has
   to classify every entry anyway, and re-reading it here would put a second
   lstat on the path of every file in the tree. */
static XSTATUS DirectGate_Files_CopyEntry(const char *pPath, const char *pTargetPath,
                                          const xstat_t *pSrcStat)
{
    XCHECK(xstrused(pPath), xthrowr(XSTDERR, "Source path is empty"));
    XCHECK(xstrused(pTargetPath), xthrowr(XSTDERR, "Target path is empty"));

    if (xstrcmp(pPath, pTargetPath))
    {
        errno = EINVAL;
        return XSTDERR;
    }

    const xstat_t st = *pSrcStat;
    xstat_t dstSt;
    if (xstat(pTargetPath, &dstSt) == XSTDOK)
    {
        errno = EEXIST;
        return XSTDERR;
    }

#ifdef S_ISLNK
    /* Before the directory branch on purpose: a link to a directory is a link,
       not a directory to walk into. */
    if (S_ISLNK(st.st_mode)) return DirectGate_Files_CopyLink(pPath, pTargetPath);
#else
    /* No symlink() to reproduce one with, and following it would copy a tree
       from outside the source. */
    if (XPath_IsLink(pPath))
    {
        errno = ENOSYS;
        return XSTDERR;
    }
#endif

    if (S_ISDIR(st.st_mode))
    {
        if (DirectGate_Files_IsNestedTarget(pPath, pTargetPath))
        {
            errno = EINVAL;
            return XSTDERR;
        }

        /* Created writable and traversable for us first: a source directory
           without the owner write bit (say r-xr-xr-x) would otherwise refuse
           the children about to be copied into it. mkdir is also subject to
           the umask, so the source mode is applied by hand once the directory
           is populated. */
        if (XDir_Create(pTargetPath, (st.st_mode & 0777) | 0700) <= 0)
            return XSTDERR;

        xdir_t dir;
        if (XDir_Open(&dir, pPath) < 0)
        {
            int nSavedErrno = errno;
            XPath_Remove(pTargetPath);
            errno = nSavedErrno;
            return XSTDERR;
        }

        char sName[XNAME_MAX];
        char sSrcChild[XFILE_PATH_SIZE];
        char sDstChild[XFILE_PATH_SIZE];

        while (XDir_Read(&dir, sName, sizeof(sName)) > 0)
        {
            int nSrcLen = snprintf(sSrcChild, sizeof(sSrcChild), "%s/%s", pPath, sName);
            int nDstLen = snprintf(sDstChild, sizeof(sDstChild), "%s/%s", pTargetPath, sName);
            int nTruncated = (nSrcLen <= 0 || (size_t)nSrcLen >= sizeof(sSrcChild) ||
                              nDstLen <= 0 || (size_t)nDstLen >= sizeof(sDstChild));

            /* A truncated child path names something else entirely, so it is
               a failure rather than an entry to skip over. */
            if (nTruncated) errno = ENAMETOOLONG;

            /* One lstat per entry, shared by the classification and the copy
               that follows it. */
            xstat_t childSt;
            if (!nTruncated && (xstat(sSrcChild, &childSt) != XSTDOK ||
                !DirectGate_Files_IsCopyableEntry(sSrcChild, &childSt)))
            {
                xlogw("Skipping entry with no copyable content: path(%s)", sSrcChild);
                continue;
            }

            if (nTruncated || DirectGate_Files_CopyEntry(sSrcChild, sDstChild, &childSt) < 0)
            {
                int nSavedErrno = errno;
                XDir_Close(&dir);

                /* Recursive: the target was created by this copy and nothing
                   else has written to it, and the plain rmdir left every
                   half-copied tree behind. */
                XPath_Remove(pTargetPath);
                errno = nSavedErrno;
                return XSTDERR;
            }
        }

        XDir_Close(&dir);
        DirectGate_Files_ApplyMode(pTargetPath, st.st_mode);
        return XSTDOK;
    }

    return DirectGate_Files_CopyRegularFile(pPath, pTargetPath);
}

XSTATUS DirectGate_Files_CreateSymlink(const char *pPath, const char *pTargetPath)
{
    XCHECK(xstrused(pPath), xthrowr(XSTDERR, "Link path is empty"));
    XCHECK(xstrused(pTargetPath), xthrowr(XSTDERR, "Link target is empty"));

#ifdef S_ISLNK
    /* A link is created, never replaced: an existing entry here is the
       caller's to resolve, exactly like mkdir. */
    if (DirectGate_Files_EntryExists(pPath))
    {
        errno = EEXIST;
        xloge("Symlink target already exists: path(%s)", pPath);
        return XSTDERR;
    }

    if (symlink(pTargetPath, pPath) != 0)
    {
        xloge("Failed to create symlink: path(%s), target(%s), errno(%d)",
            pPath, pTargetPath, errno);

        return XSTDERR;
    }

    xlogi("File manager symlink created: path(%s), target(%s)", pPath, pTargetPath);
    return XSTDOK;
#else
    errno = ENOSYS;
    xloge("Symlink creation is not supported on this platform: path(%s)", pPath);
    return XSTDERR;
#endif
}

static XSTATUS DirectGate_Files_CopyPath(const char *pPath, const char *pTargetPath)
{
    XCHECK(xstrused(pPath), xthrowr(XSTDERR, "Source path is empty"));

    xstat_t st;
    if (xstat(pPath, &st) < 0) return XSTDERR;

    return DirectGate_Files_CopyEntry(pPath, pTargetPath, &st);
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

    /* Taken before sDir is cut down to the parent directory: the name lives
       inside that same buffer, and truncating a target directly under "/"
       used to leave it empty. */
    char sName[DIRECTGATE_UPLOAD_TEMP_NAME_MAX + 1];
    xstrncpy(sName, sizeof(sName), pSlash ? pSlash + 1 : pPath);

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
            sDir, sRandomHex, sName);

        if (nWritten <= 0 || (size_t)nWritten >= nSize)
            return XSTDERR;

        if (!DirectGate_Files_EntryExists(pOutput))
            return XSTDOK;
    }

    errno = EEXIST;
    return XSTDERR;
}

/* File transfer send callback: header comes from transfer.c, we handle cc/build/encrypt/route */
int DirectGate_Files_TransferSendCb(xjson_obj_t *pHeader, const uint8_t *pPayload, size_t nLen, void *pCtx)
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
        /* stat() rather than xstat(), which is an lstat: opening a link the
           user picked means opening what it points at. */
        struct stat st;
        if (stat(pMgrPkg->pPath, &st) != 0 || !S_ISREG(st.st_mode))
        {
            return DirectGate_Session_SendManagerResp(pSession, "open",
                "failed", "file not found or not a regular file", pMgrPkg->pPath);
        }

        if (DirectGate_Transfer_IsActive(&pSession->transfer))
        {
            return DirectGate_Session_SendManagerResp(pSession, "open",
                "failed", "transfer already in progress", pMgrPkg->pPath);
        }

        /* The transfer opens its source with O_NOFOLLOW so a link planted
           between the check above and the read cannot redirect it, which also
           means it will not open a link the user asked for on purpose. The
           link is resolved here instead, so the transfer still sees a real
           file and keeps that guarantee. */
        char *pResolved = DirectGate_Files_ResolveLink(pMgrPkg->pPath);
        const char *pSource = pResolved != NULL ? pResolved : pMgrPkg->pPath;

        int nStarted = DirectGate_Transfer_Send(&pSession->transfer, pSource, DirectGate_Files_TransferSendCb, pSession);
        free(pResolved);

        if (nStarted < 0)
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

    if (xstrcmp(pMgrPkg->pAction, "symlink"))
    {
        if (!xstrused(pMgrPkg->pTargetPath))
        {
            return DirectGate_Session_SendManagerResp(pSession, "symlink",
                "failed", "missing target path", pMgrPkg->pPath);
        }

        if (DirectGate_Files_CreateSymlink(pMgrPkg->pPath, pMgrPkg->pTargetPath) < 0)
        {
            return DirectGate_Session_SendManagerResp(pSession, "symlink",
                "failed", DirectGate_Files_LastError(), pMgrPkg->pPath);
        }

        return DirectGate_Session_SendManagerResp(pSession, "symlink", "ok", NULL, pMgrPkg->pPath);
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
        /* Captured before the call, because the cleanup below is only ever
           right for a transfer that was still running. A duplicate or replayed
           file/end finds the transfer already finished, and sPath then names
           the committed destination - removing it would delete the file the
           first end had just saved. */
        xbool_t bReceiving = (pFT->eState == XTRANSFER_STATE_RECEIVING);

        if (DirectGate_Transfer_HandleEnd(pFT, pPkg, NULL, NULL) < 0)
        {
            int nWsFd = pSession->pWsSession != NULL ? (int)pSession->pWsSession->sock.nFD : (int)XSOCK_INVALID;
            xloge("Failed to finalize inbound file transfer: sid(%u), wsfd(%d), transferId(%s), receiving(%s)",
                pSession->nSessionId, nWsFd, pFilePkg->transfer.pTransferId, bReceiving ? "true" : "false");

            DirectGate_Files_SendTransferCancel(pSession, pFilePkg->transfer.pTransferId, DirectGate_Files_LastError());

            if (bReceiving)
            {
                if (xstrused(pFT->sPath)) remove(pFT->sPath);
                DirectGate_Files_ClearPendingSave(pSession);
            }
        }
        else if (xstrused(pSession->sSaveTempPath) && xstrused(pSession->sSavePath))
        {
            /* A save aimed at a symlink writes through it. The link is what the
               user picked and expects to still be there afterwards, and the
               bytes belong in the file it points at - renaming onto the link
               would replace it with a regular file and leave the real one
               untouched. Resolving here also means the permissions restored
               below are the target's rather than the 0777 every link reports
               for itself. Only for an overwrite: a new file is a new file. */
            char sCommitPath[XFILE_PATH_SIZE];
            xstrncpy(sCommitPath, sizeof(sCommitPath), pSession->sSavePath);

            if (pSession->bSaveForce)
            {
                char *pResolved = DirectGate_Files_ResolveLink(pSession->sSavePath);
                if (pResolved != NULL)
                {
                    xstrncpy(sCommitPath, sizeof(sCommitPath), pResolved);
                    free(pResolved);
                }
            }

            xstat_t st;
            xbool_t bHasOrigPerms = (xstat(sCommitPath, &st) == XSTDOK);

            if (bHasOrigPerms && !pSession->bSaveForce)
            {
                errno = EEXIST;
                int nWsFd = pSession->pWsSession != NULL ? (int)pSession->pWsSession->sock.nFD : (int)XSOCK_INVALID;
                xloge("Save target appeared during upload: sid(%u), wsfd(%d), path(%s)", pSession->nSessionId, nWsFd, sCommitPath);

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
                ? DirectGate_Files_RenameReplace(pSession->sSaveTempPath, sCommitPath)
                : DirectGate_Files_RenameNoReplace(pSession->sSaveTempPath, sCommitPath);

            if (nCommit != XSTDOK)
            {
                int nWsFd = pSession->pWsSession != NULL ? (int)pSession->pWsSession->sock.nFD : (int)XSOCK_INVALID;
                xloge("Failed to commit uploaded file: sid(%u), wsfd(%d), tmp(%s), dst(%s), errno(%d)",
                    pSession->nSessionId, nWsFd, pSession->sSaveTempPath, sCommitPath, errno);

                DirectGate_Files_SendTransferCancel(pSession, pFilePkg->transfer.pTransferId, DirectGate_Files_LastError());
                remove(pSession->sSaveTempPath);
                DirectGate_Files_ClearPendingSave(pSession);
                return XAPI_CONTINUE;
            }

            if (bHasOrigPerms)
            {
                char sPerm[XPERM_LEN + 1];
                XPath_ModeToPerm(sPerm, sizeof(sPerm), st.st_mode);

                if (XPath_SetPerm(sCommitPath, sPerm) == XSTDOK)
                {
                    xlogd("Restored original file permissions: path(%s), perm(%s)",
                        sCommitPath, sPerm);
                }
                else
                {
                    xloge("Failed to restore original file permissions: path(%s), perm(%s), errno(%d)",
                        sCommitPath, sPerm, errno);
                }
            }
            else if (xstrused(pSession->sSavePermissions))
            {
                if (XPath_SetPerm(sCommitPath, pSession->sSavePermissions) == XSTDOK)
                {
                    xlogd("Applied source permissions to uploaded file: path(%s), perm(%s)",
                        sCommitPath, pSession->sSavePermissions);
                }
                else
                {
                    xloge("Failed to apply source permissions to uploaded file: path(%s), perm(%s), errno(%d)",
                        sCommitPath, pSession->sSavePermissions, errno);
                }
            }

            xstrncpy(pFT->sPath, sizeof(pFT->sPath), sCommitPath);
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
