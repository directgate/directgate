#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "src/agent/files.h"
#include "src/agent/search.h"
#include "src/agent/session.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "search_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

typedef struct search_capture_ {
    int nPartial;
    int nOk;
    int nFailed;
    int nCancelled;
    char sLastReason[XSTR_MID];
    char sPayload[16384];
} search_capture_t;

static search_capture_t g_capture;

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
    (void)pPath;

    if (xstrcmp(pStatus, "failed")) g_capture.nFailed++;
    if (xstrcmp(pStatus, "cancelled")) g_capture.nCancelled++;
    xstrncpy(g_capture.sLastReason, sizeof(g_capture.sLastReason),
        xstrused(pReason) ? pReason : "");
    return XAPI_CONTINUE;
}

int DirectGate_Session_SendManagerData(directgate_session_t *pSession, const char *pAction,
                                   const char *pStatus, const char *pPath,
                                   const uint8_t *pPayload, size_t nPayloadLen)
{
    (void)pSession;
    (void)pAction;
    (void)pPath;

    if (xstrcmp(pStatus, "partial")) g_capture.nPartial++;
    if (xstrcmp(pStatus, "ok")) g_capture.nOk++;

    if (pPayload != NULL && nPayloadLen > 0)
    {
        size_t nCopy = nPayloadLen < sizeof(g_capture.sPayload) - strlen(g_capture.sPayload) - 1
            ? nPayloadLen
            : sizeof(g_capture.sPayload) - strlen(g_capture.sPayload) - 1;
        strncat(g_capture.sPayload, (const char*)pPayload, nCopy);
    }

    return XAPI_CONTINUE;
}

int DirectGate_Session_Close(directgate_session_t *pSession, const char *pReason)
{
    (void)pSession;
    (void)pReason;
    return XAPI_CONTINUE;
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

static int write_file(const char *pPath, const char *pData)
{
    FILE *pFile = fopen(pPath, "wb");
    if (pFile == NULL) return 0;

    size_t nLen = strlen(pData);
    int nOk = fwrite(pData, 1, nLen, pFile) == nLen;
    fclose(pFile);
    return nOk;
}

static int wait_for_search(directgate_session_t *pSession)
{
    for (int i = 0; i < 200; i++)
    {
        DirectGate_Search_Process(pSession);
        if (g_capture.nOk > 0 || g_capture.nFailed > 0 || g_capture.nCancelled > 0)
            return XSTDOK;
        usleep(10000);
    }

    return XSTDERR;
}

static void reset_capture(void)
{
    memset(&g_capture, 0, sizeof(g_capture));
}

int main(void)
{
    char sRoot[] = "/tmp/directgate_search.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "mkdtemp root");

    char sNested[512];
    char sAlpha[512];
    char sBeta[512];
    char sGamma[512];
    snprintf(sNested, sizeof(sNested), "%s/nested", sRoot);
    snprintf(sAlpha, sizeof(sAlpha), "%s/alpha.txt", sRoot);
    snprintf(sBeta, sizeof(sBeta), "%s/beta.log", sRoot);
    snprintf(sGamma, sizeof(sGamma), "%s/nested/GAMMA.TXT", sRoot);

    CHECK(mkdir(sNested, 0755) == 0, "mkdir nested");
    CHECK(write_file(sAlpha, "first needle\nsecond\n"), "write alpha");
    CHECK(write_file(sBeta, "no match here\n"), "write beta");
    CHECK(write_file(sGamma, "another needle\n"), "write gamma");

    /* A link inside the tree pointing back at its own root. A recursive search
       that followed it would report every file again under a path leading
       through it, and would keep doing so until the path stopped growing -
       then never stop. */
    char sLoop[512];
    snprintf(sLoop, sizeof(sLoop), "%s/loop", sNested);
    CHECK(symlink(sRoot, sLoop) == 0, "link back to the search root");

    directgate_session_t session;
    memset(&session, 0, sizeof(session));
    session.nSessionId = 7;
    DirectGate_Search_Init(&session.search);
    CHECK(DirectGate_Search_GetPipeFd(&session.search) >= 0,
        "search pipe should be available after init");
    CHECK(DirectGate_Search_Cancel(&session.search) == XSTDNON,
        "idle search cancel should report no running search");
    CHECK(strcmp(DirectGate_Search_GetReason(&session.search), "search is not running") == 0,
        "idle cancel should set reason");

    directgate_pkg_manager_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.pPath = sRoot;
    CHECK(DirectGate_Search_Start(&session.search, &mgr) == XSTDERR,
        "search with no criteria should fail");
    CHECK(strcmp(DirectGate_Search_GetReason(&session.search), "missing search criteria") == 0,
        "search with no criteria should set reason");

    mgr.pPath = sAlpha;
    mgr.pFileName = "*.txt";
    CHECK(DirectGate_Search_Start(&session.search, &mgr) == XSTDERR,
        "search path must be a directory");
    CHECK(strcmp(DirectGate_Search_GetReason(&session.search), "search path is not a directory") == 0,
        "file search path should set reason");

    reset_capture();
    memset(&mgr, 0, sizeof(mgr));
    mgr.pPath = sRoot;
    mgr.pFileName = "*.txt";
    mgr.bRecursive = XTRUE;
    mgr.bInsensitive = XTRUE;
    CHECK(DirectGate_Search_Start(&session.search, &mgr) == XSTDOK,
        "filename search should start");
    CHECK(wait_for_search(&session) == XSTDOK,
        "filename search should finish");
    CHECK(g_capture.nFailed == 0, "filename search should not fail");
    CHECK(g_capture.nOk == 1, "filename search should complete once");
    CHECK(g_capture.nPartial >= 2, "filename search should produce partial results");
    CHECK(strstr(g_capture.sPayload, "alpha.txt") != NULL,
        "filename search should include alpha");
    CHECK(strstr(g_capture.sPayload, "GAMMA.TXT") != NULL,
        "filename search should include insensitive nested match");
    CHECK(strstr(g_capture.sPayload, "beta.log") == NULL,
        "filename search should exclude beta");

    /* A search that walked into the link back to the root would report the same
       files again under a path leading through it - and would keep doing so
       until the path stopped growing, then never stop. */
    CHECK(strstr(g_capture.sPayload, "/loop/") == NULL,
        "the search never descended into the link back to its own root");

    reset_capture();
    memset(&mgr, 0, sizeof(mgr));
    mgr.pPath = sRoot;
    mgr.pText = "needle";
    mgr.bRecursive = XTRUE;
    mgr.bInsensitive = XTRUE;
    mgr.bSearchLines = XTRUE;
    CHECK(DirectGate_Search_Start(&session.search, &mgr) == XSTDOK,
        "text search should start");
    CHECK(wait_for_search(&session) == XSTDOK,
        "text search should finish");
    CHECK(g_capture.nFailed == 0, "text search should not fail");
    CHECK(g_capture.nOk == 1, "text search should complete once");
    CHECK(strstr(g_capture.sPayload, "alpha.txt") != NULL,
        "text search should include alpha");
    CHECK(strstr(g_capture.sPayload, "GAMMA.TXT") != NULL,
        "text search should include gamma");

    reset_capture();
    memset(&mgr, 0, sizeof(mgr));
    mgr.pPath = sRoot;
    mgr.pTypes = "z";
    CHECK(DirectGate_Search_Start(&session.search, &mgr) == XSTDOK,
        "invalid criteria should fail asynchronously");
    CHECK(wait_for_search(&session) == XSTDOK,
        "invalid criteria search should finish");
    CHECK(g_capture.nFailed == 1, "invalid criteria should send failure");
    CHECK(strcmp(g_capture.sLastReason, "invalid search criteria") == 0,
        "invalid criteria failure reason");

    DirectGate_Search_Clear(&session.search);
    CHECK(DirectGate_Search_GetPipeFd(&session.search) == XSTDERR,
        "search pipe should be closed after clear");

    DirectGate_Files_Delete(sRoot, XTRUE);
    puts("search_smoke: OK");
    return 0;
}
