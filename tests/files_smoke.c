#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "src/agent/files.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "files_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

int DirectGate_Session_Send(directgate_session_t *pSession, xjson_obj_t *pHeader,
                        const uint8_t *pPayload, size_t nPayloadLength)
{
    (void)pSession;
    (void)pHeader;
    (void)pPayload;
    (void)nPayloadLength;
    return XSTDOK;
}

int DirectGate_Session_SendManagerResp(directgate_session_t *pSession,
                                   const char *pAction, const char *pStatus,
                                   const char *pReason, const char *pPath)
{
    (void)pSession;
    (void)pAction;
    (void)pStatus;
    (void)pReason;
    (void)pPath;
    return XSTDOK;
}

int DirectGate_Session_SendManagerData(directgate_session_t *pSession, const char *pAction,
                                   const char *pStatus, const char *pPath,
                                   const uint8_t *pPayload, size_t nPayloadLen)
{
    (void)pSession;
    (void)pAction;
    (void)pStatus;
    (void)pPath;
    (void)pPayload;
    (void)nPayloadLen;
    return XSTDOK;
}

int DirectGate_Session_Close(directgate_session_t *pSession, const char *pReason)
{
    (void)pSession;
    (void)pReason;
    return XSTDOK;
}

int DirectGate_Session_EnsureMode(directgate_session_t *pSession,
                              directgate_session_mode_t eMode,
                              const char *pReason)
{
    (void)pSession;
    (void)eMode;
    (void)pReason;
    return XSTDOK;
}

directgate_session_t* DirectGate_SessionMgr_Find(directgate_session_mgr_t *pMgr,
                                         uint32_t nSessionId)
{
    (void)pMgr;
    (void)nSessionId;
    return NULL;
}

int DirectGate_Search_Start(directgate_search_t *pSearch, const directgate_pkg_manager_t *pMgrPkg)
{
    (void)pSearch;
    (void)pMgrPkg;
    return XSTDERR;
}

int DirectGate_Search_Cancel(directgate_search_t *pSearch)
{
    (void)pSearch;
    return XSTDNON;
}

const char* DirectGate_Search_GetReason(const directgate_search_t *pSearch)
{
    (void)pSearch;
    return "search failed";
}

static int write_file(const char *pPath, const char *pData)
{
    FILE *pFile = fopen(pPath, "wb");
    if (pFile == NULL) return 0;

    size_t nLen = strlen(pData);
    int nOk = fwrite(pData, 1, nLen, pFile) == nLen;
    fclose(pFile);
    return nOk;
}

static int entry_exists(xjson_obj_t *pList, const char *pName, const char *pType)
{
    xjson_obj_t *pEntries = XJSON_GetObject(pList, "entries");
    if (pEntries == NULL || pEntries->nType != XJSON_TYPE_ARRAY) return 0;

    size_t nCount = XJSON_GetArrayLength(pEntries);
    for (size_t i = 0; i < nCount; i++)
    {
        xjson_obj_t *pItem = XJSON_GetArrayItem(pEntries, i);
        const char *pItemName = XJSON_GetString(XJSON_GetObject(pItem, "name"));
        const char *pItemType = XJSON_GetString(XJSON_GetObject(pItem, "type"));
        if (xstrused(pItemName) && xstrused(pItemType) &&
            strcmp(pItemName, pName) == 0 &&
            strcmp(pItemType, pType) == 0)
        {
            return 1;
        }
    }

    return 0;
}

int main(void)
{
    char sRoot[] = "/tmp/directgate_files_smoke.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "mkdtemp root");

    char sFile[512];
    char sRenamed[512];
    char sDir[512];
    char sNested[512];
    char sCreated[512];
    char sDirLink[512];
    char sExternal[] = "/tmp/directgate_files_external.XXXXXX";
    char sExternalFile[512];
    snprintf(sFile, sizeof(sFile), "%s/alpha.txt", sRoot);
    snprintf(sRenamed, sizeof(sRenamed), "%s/beta.txt", sRoot);
    snprintf(sDir, sizeof(sDir), "%s/dir", sRoot);
    snprintf(sNested, sizeof(sNested), "%s/dir/child", sRoot);
    snprintf(sCreated, sizeof(sCreated), "%s/created", sRoot);
    snprintf(sDirLink, sizeof(sDirLink), "%s/dir-link", sRoot);
    CHECK(mkdtemp(sExternal) != NULL, "mkdtemp external");
    snprintf(sExternalFile, sizeof(sExternalFile), "%s/external.txt", sExternal);

    CHECK(write_file(sFile, "alpha"), "write alpha file");
    CHECK(write_file(sExternalFile, "external"), "write external file");
    CHECK(mkdir(sDir, 0755) == 0, "mkdir dir");
    CHECK(symlink(sExternal, sDirLink) == 0, "symlink external dir");

    xstat_t st;
    CHECK(xstat(sFile, &st) == XSTDOK, "stat alpha file");
    xjson_obj_t *pEntry = DirectGate_Files_CreateEntryJson("alpha.txt", sRoot, &st);
    CHECK(pEntry != NULL, "create file entry JSON");
    CHECK(strcmp(XJSON_GetString(XJSON_GetObject(pEntry, "name")), "alpha.txt") == 0,
        "entry name");
    CHECK(strcmp(XJSON_GetString(XJSON_GetObject(pEntry, "path")), sFile) == 0,
        "entry full path");
    CHECK(strcmp(XJSON_GetString(XJSON_GetObject(pEntry, "directoryPath")), sRoot) == 0,
        "entry directory path");
    CHECK(strcmp(XJSON_GetString(XJSON_GetObject(pEntry, "type")), "file") == 0,
        "entry type");
    CHECK(XJSON_GetU64(XJSON_GetObject(pEntry, "sizeBytes")) == 5,
        "entry size");
    XJSON_FreeObject(pEntry);

    /* A symlink stays a symlink, but the entry says what it resolves to so the
       client can enter a linked directory and download a linked file. */
    {
        xstat_t linkSt;
        CHECK(xstat(sDirLink, &linkSt) == XSTDOK, "lstat the directory link");

        xjson_obj_t *pLink = DirectGate_Files_CreateEntryJson("dir-link", sRoot, &linkSt);
        CHECK(pLink != NULL, "create link entry JSON");
        CHECK(strcmp(XJSON_GetString(XJSON_GetObject(pLink, "type")), "symlink") == 0,
            "link entry keeps the symlink type");
        CHECK(strcmp(XJSON_GetString(XJSON_GetObject(pLink, "targetType")), "directory") == 0,
            "link entry reports the target type");
        CHECK(strcmp(XJSON_GetString(XJSON_GetObject(pLink, "target")), sExternal) == 0,
            "link entry reports the target path");
        XJSON_FreeObject(pLink);

        char sFileLink[512];
        snprintf(sFileLink, sizeof(sFileLink), "%s/file-link", sRoot);
        CHECK(symlink(sExternalFile, sFileLink) == 0, "symlink external file");
        CHECK(xstat(sFileLink, &linkSt) == XSTDOK, "lstat the file link");

        pLink = DirectGate_Files_CreateEntryJson("file-link", sRoot, &linkSt);
        CHECK(pLink != NULL, "create file link entry JSON");
        CHECK(strcmp(XJSON_GetString(XJSON_GetObject(pLink, "targetType")), "file") == 0,
            "file link reports a file target");
        CHECK(XJSON_GetU64(XJSON_GetObject(pLink, "targetSizeBytes")) == strlen("external"),
            "file link reports the target size, not the length of the link");
        XJSON_FreeObject(pLink);

        /* A dangling link carries no target type at all rather than a wrong one. */
        char sDangling[512];
        snprintf(sDangling, sizeof(sDangling), "%s/dangling", sRoot);
        CHECK(symlink("/nonexistent-directgate-target", sDangling) == 0, "dangling symlink");
        CHECK(xstat(sDangling, &linkSt) == XSTDOK, "lstat the dangling link");

        pLink = DirectGate_Files_CreateEntryJson("dangling", sRoot, &linkSt);
        CHECK(pLink != NULL, "create dangling entry JSON");
        CHECK(XJSON_GetObject(pLink, "targetType") == NULL,
            "a dangling link reports no target type");
        XJSON_FreeObject(pLink);

        CHECK(unlink(sFileLink) == 0, "cleanup file link");
        CHECK(unlink(sDangling) == 0, "cleanup dangling link");
    }

    xjson_obj_t *pList = DirectGate_Files_ListDir(sRoot);
    CHECK(pList != NULL, "list directory");
    CHECK(strcmp(XJSON_GetString(XJSON_GetObject(pList, "path")), sRoot) == 0,
        "list path");
    CHECK(entry_exists(pList, "alpha.txt", "file"),
        "list contains alpha file");
    CHECK(entry_exists(pList, "dir", "directory"),
        "list contains dir");
    XJSON_FreeObject(pList);

    CHECK(DirectGate_Files_CreateDir(sCreated) == XSTDOK,
        "create directory");
    CHECK(DirectGate_Files_CreateDir(sCreated) == XSTDERR,
        "duplicate directory create fails");

    CHECK(DirectGate_Files_Rename(sFile, sRenamed) == XSTDOK,
        "rename file");
    CHECK(access(sFile, F_OK) != 0, "source file gone after rename");
    CHECK(access(sRenamed, F_OK) == 0, "renamed file exists");
    CHECK(DirectGate_Files_Rename(sRenamed, sRenamed) == XSTDOK,
        "rename same path succeeds");
    CHECK(DirectGate_Files_Rename(sDir, sNested) == XSTDERR,
        "rename directory into itself fails");

    CHECK(DirectGate_Files_Delete(sRenamed, XFALSE) == XSTDOK,
        "delete regular file");
    errno = 0;
    CHECK(DirectGate_Files_Delete(sRoot, XFALSE) == XSTDERR,
        "non-recursive delete of non-empty dir fails");
    CHECK(errno == ENOTEMPTY,
        "non-recursive delete of non-empty dir reports ENOTEMPTY");
    CHECK(DirectGate_Files_Delete(sRoot, XTRUE) == XSTDOK,
        "recursive delete of root dir");
    CHECK(access(sRoot, F_OK) != 0, "root removed");
    CHECK(access(sExternalFile, F_OK) == 0,
        "recursive delete unlinks directory symlink without touching target");
    CHECK(unlink(sExternalFile) == 0, "cleanup external file");
    CHECK(rmdir(sExternal) == 0, "cleanup external dir");

    puts("files_smoke: OK");
    return 0;
}
