#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "src/agent/files.c"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "files_static_smoke: %s\n", msg); \
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

static int read_file(const char *pPath, char *pOut, size_t nOutSize)
{
    FILE *pFile = fopen(pPath, "rb");
    if (pFile == NULL) return 0;

    size_t nRead = fread(pOut, 1, nOutSize - 1, pFile);
    int nErr = ferror(pFile);
    fclose(pFile);
    if (nErr) return 0;

    pOut[nRead] = '\0';
    return 1;
}

int main(void)
{
    char sRoot[] = "/tmp/directgate_files_static.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "mkdtemp root");

    char sFile[512];
    char sFileCopy[512];
    char sFileCopy2[512];
    char sHidden[512];
    char sHidden2[512];
    char sDir[512];
    char sDirChild[512];
    char sDirCopy[512];
    char sDirCopyChild[512];
    char sNestedTarget[512];
    char sTempPath[512];
    char sTempPath2[512];
    char sCommitTemp[512];
    char sCommitTarget[512];
    char sPortableDir[512];
    char sPortableChild[512];
    char sPortableFile[512];
    char sResolved[512];
    char sRead[64];

    snprintf(sFile, sizeof(sFile), "%s/report.txt", sRoot);
    snprintf(sFileCopy, sizeof(sFileCopy), "%s/report-copy.txt", sRoot);
    snprintf(sFileCopy2, sizeof(sFileCopy2), "%s/report-copy(2).txt", sRoot);
    snprintf(sHidden, sizeof(sHidden), "%s/.env", sRoot);
    snprintf(sHidden2, sizeof(sHidden2), "%s/.env(2)", sRoot);
    snprintf(sDir, sizeof(sDir), "%s/dir", sRoot);
    snprintf(sDirChild, sizeof(sDirChild), "%s/dir/child.txt", sRoot);
    snprintf(sDirCopy, sizeof(sDirCopy), "%s/dir-copy", sRoot);
    snprintf(sDirCopyChild, sizeof(sDirCopyChild), "%s/dir-copy/child.txt", sRoot);
    snprintf(sNestedTarget, sizeof(sNestedTarget), "%s/dir/nested", sRoot);
    snprintf(sCommitTemp, sizeof(sCommitTemp), "%s/upload.part", sRoot);
    snprintf(sCommitTarget, sizeof(sCommitTarget), "%s/editor-save.txt", sRoot);
    snprintf(sPortableDir, sizeof(sPortableDir), "%s/windows-portable-dir", sRoot);
    snprintf(sPortableChild, sizeof(sPortableChild), "%s/windows-portable-dir/child.txt", sRoot);
    snprintf(sPortableFile, sizeof(sPortableFile), "%s/windows-portable-file.txt", sRoot);

    CHECK(write_file(sFile, "report-data"), "write source file");
    CHECK(write_file(sHidden, "secret"), "write hidden file");
    CHECK(XDir_Create(sDir, 0755) > 0, "mkdir source dir");
    CHECK(write_file(sDirChild, "child-data"), "write source dir child");

    CHECK(DirectGate_Files_ResolvePasteTarget(sResolved, sizeof(sResolved), sFileCopy) == XSTDOK,
        "resolve non-existing paste target");
    CHECK(strcmp(sResolved, sFileCopy) == 0,
        "non-existing paste target should remain unchanged");

    CHECK(write_file(sFileCopy, "existing"), "write existing paste target");
    CHECK(DirectGate_Files_ResolvePasteTarget(sResolved, sizeof(sResolved), sFileCopy) == XSTDOK,
        "resolve existing paste target");
    CHECK(strcmp(sResolved, sFileCopy2) == 0,
        "existing paste target should receive numeric suffix");

    CHECK(DirectGate_Files_ResolvePasteTarget(sResolved, sizeof(sResolved), sHidden) == XSTDOK,
        "resolve hidden paste target");
    CHECK(strcmp(sResolved, sHidden2) == 0,
        "hidden paste target should suffix whole name");

    CHECK(DirectGate_Files_CopyPath(sFile, sResolved) == XSTDOK,
        "copy file to resolved target");
    CHECK(read_file(sResolved, sRead, sizeof(sRead)), "read copied file");
    CHECK(strcmp(sRead, "report-data") == 0, "copied file bytes");
    errno = 0;
    CHECK(DirectGate_Files_CopyPath(sFile, sResolved) == XSTDERR,
        "copy should not replace existing target");
    CHECK(errno == EEXIST, "copy to existing target should report EEXIST");

    CHECK(DirectGate_Files_CopyPath(sDir, sDirCopy) == XSTDOK,
        "copy directory recursively");
    CHECK(read_file(sDirCopyChild, sRead, sizeof(sRead)),
        "read copied directory child");
    CHECK(strcmp(sRead, "child-data") == 0,
        "copied directory child bytes");

    errno = 0;
    CHECK(DirectGate_Files_CopyPath(sDir, sNestedTarget) == XSTDERR,
        "copy directory into itself should fail");
    CHECK(errno == EINVAL, "copy directory into itself should report EINVAL");

    CHECK(DirectGate_Files_BuildTempPath(sTempPath, sizeof(sTempPath), sFile) == XSTDOK,
        "build upload temp path");
    CHECK(strstr(sTempPath, "/.directgate-upload-") != NULL,
        "temp path should use hidden upload prefix in parent dir");
    CHECK(strstr(sTempPath, "-report.txt.part") != NULL,
        "temp path should keep target name suffix");
    CHECK(access(sTempPath, F_OK) != 0,
        "temp path builder should not create the file");
    CHECK(DirectGate_Files_BuildTempPath(sTempPath2, sizeof(sTempPath2), sFile) == XSTDOK,
        "build second upload temp path");
    CHECK(strcmp(sTempPath, sTempPath2) != 0,
        "upload temp path should include random material");

    CHECK(write_file(sCommitTemp, "new-data"), "write no-replace commit source");
    CHECK(write_file(sCommitTarget, "old-data"), "write no-replace commit target");
    errno = 0;
    CHECK(DirectGate_Files_RenameNoReplace(sCommitTemp, sCommitTarget) == XSTDERR,
        "no-replace commit should reject existing target");
    CHECK(errno == EEXIST, "no-replace commit should report EEXIST");
    CHECK(read_file(sCommitTemp, sRead, sizeof(sRead)), "read rejected commit source");
    CHECK(strcmp(sRead, "new-data") == 0, "rejected commit should preserve source");
    CHECK(read_file(sCommitTarget, sRead, sizeof(sRead)), "read rejected commit target");
    CHECK(strcmp(sRead, "old-data") == 0, "rejected commit should preserve target");

    CHECK(DirectGate_Files_RenameReplace(sCommitTemp, sCommitTarget) == XSTDOK,
        "forced editor save should replace existing target");
    CHECK(access(sCommitTemp, F_OK) != 0, "replace commit should consume source");
    CHECK(read_file(sCommitTarget, sRead, sizeof(sRead)), "read replaced commit target");
    CHECK(strcmp(sRead, "new-data") == 0, "replace commit should install source bytes");

    xstat_t commitStat;
    char sCommitPerm[XPERM_LEN + 1];
    CHECK(xstat(sCommitTarget, &commitStat) == XSTDOK, "stat replaced commit target");
    memset(sCommitPerm, '?', sizeof(sCommitPerm));
    CHECK(XPath_ModeToPerm(sCommitPerm, sizeof(sCommitPerm), commitStat.st_mode) == XPERM_LEN,
        "format replaced target permissions");
    CHECK(strlen(sCommitPerm) == XPERM_LEN,
        "formatted permissions should always be complete");
    CHECK(strchr(sCommitPerm, '?') == NULL,
        "formatted permissions should initialize every character");
    CHECK(XPath_SetPerm(sCommitTarget, sCommitPerm) == XSTDOK,
        "restore replaced target permissions");
    CHECK(write_file(sCommitTarget, "second-save"),
        "restored target should remain writable for repeated editor save");

    xstat_t beforeInvalidPerm;
    xstat_t afterInvalidPerm;
    CHECK(xstat(sCommitTarget, &beforeInvalidPerm) == XSTDOK,
        "stat target before invalid permission");
    CHECK(XPath_SetPerm(sCommitTarget, "rw") == XSTDERR,
        "invalid permission string should be rejected");
    CHECK(xstat(sCommitTarget, &afterInvalidPerm) == XSTDOK,
        "stat target after invalid permission");
    CHECK(beforeInvalidPerm.st_mode == afterInvalidPerm.st_mode,
        "invalid permission string should preserve target mode");
    CHECK(write_file(sCommitTarget, "third-save"),
        "invalid permission string should not make target read-only");

    CHECK(XDir_Create(sPortableDir, 0755) > 0,
        "create destination for portable Windows permissions");
    CHECK(XPath_SetPerm(sPortableDir, "rwx------") == XSTDOK,
        "apply portable Windows directory permissions");
    CHECK(write_file(sPortableChild, "portable"),
        "portable Windows directory permissions should allow child creation");
    xstat_t portableStat;
    CHECK(xstat(sPortableDir, &portableStat) == XSTDOK &&
        (portableStat.st_mode & 0777) == 0700,
        "portable Windows directory permissions should be 0700");
    CHECK(write_file(sPortableFile, "portable"),
        "create portable Windows file destination");
    CHECK(XPath_SetPerm(sPortableFile, "rw-------") == XSTDOK,
        "apply portable Windows file permissions");
    CHECK(xstat(sPortableFile, &portableStat) == XSTDOK &&
        (portableStat.st_mode & 0777) == 0600,
        "portable Windows file permissions should be 0600");

#ifdef _WIN32
    char sWinPerm[XPERM_LEN + 1];
    char sWinMode[4];

    CHECK(XPath_ModeToPerm(sWinPerm, sizeof(sWinPerm),
        _S_IFDIR | _S_IREAD | _S_IWRITE) == XPERM_LEN &&
        strcmp(sWinPerm, "rwx------") == 0,
        "writable Windows directory should project to portable 0700");
    CHECK(XPath_ModeToChmod(sWinMode, sizeof(sWinMode),
        _S_IFDIR | _S_IREAD | _S_IWRITE) == 3 &&
        strcmp(sWinMode, "700") == 0,
        "writable Windows directory chmod projection");

    CHECK(XPath_ModeToPerm(sWinPerm, sizeof(sWinPerm),
        _S_IFREG | _S_IREAD | _S_IWRITE) == XPERM_LEN &&
        strcmp(sWinPerm, "rw-------") == 0,
        "writable Windows file should project to portable 0600");
    CHECK(XPath_ModeToChmod(sWinMode, sizeof(sWinMode),
        _S_IFREG | _S_IREAD | _S_IWRITE) == 3 &&
        strcmp(sWinMode, "600") == 0,
        "writable Windows file chmod projection");

    CHECK(XPath_ModeToPerm(sWinPerm, sizeof(sWinPerm),
        _S_IFDIR | _S_IREAD) == XPERM_LEN &&
        strcmp(sWinPerm, "rwx------") == 0,
        "Windows directory attributes should still project to writable 0700");
    CHECK(XPath_ModeToChmod(sWinMode, sizeof(sWinMode),
        _S_IFDIR | _S_IREAD) == 3 &&
        strcmp(sWinMode, "700") == 0,
        "Windows directory attributes chmod projection");
    CHECK(XPath_ModeToPerm(sWinPerm, sizeof(sWinPerm),
        _S_IFREG | _S_IREAD) == XPERM_LEN &&
        strcmp(sWinPerm, "r--------") == 0,
        "read-only Windows file should project to portable 0400");
    CHECK(XPath_ModeToChmod(sWinMode, sizeof(sWinMode),
        _S_IFREG | _S_IREAD) == 3 &&
        strcmp(sWinMode, "400") == 0,
        "read-only Windows file chmod projection");
#endif

    CHECK(DirectGate_Files_Delete(sDirCopy, XTRUE) == XSTDOK,
        "cleanup copied directory");
    CHECK(DirectGate_Files_Delete(sRoot, XTRUE) == XSTDOK,
        "cleanup root recursively");

    puts("files_static_smoke: OK");
    return 0;
}
