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
    int nBadPayloads;
    size_t nEntries;
    size_t nLargestPayload;
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

    /* Every payload is the shape the browser parses: {"path":..,"entries":[..]},
       however many matches were joined into it. */
    if (pPayload != NULL && nPayloadLen > 0)
    {
        xjson_t json;
        xjson_obj_t *pEntries = NULL;

        if (XJSON_Parse(&json, NULL, (const char*)pPayload, nPayloadLen))
        {
            pEntries = XJSON_GetObject(json.pRootObj, "entries");
            if (pEntries != NULL && pEntries->nType == XJSON_TYPE_ARRAY &&
                XJSON_GetString(XJSON_GetObject(json.pRootObj, "path")) != NULL)
                g_capture.nEntries += XJSON_GetArrayLength(pEntries);
            else
                g_capture.nBadPayloads++;
        }
        else g_capture.nBadPayloads++;

        XJSON_Destroy(&json);
        if (nPayloadLen > g_capture.nLargestPayload) g_capture.nLargestPayload = nPayloadLen;
    }

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
    CHECK(g_capture.nPartial >= 1, "filename search should produce partial results");
    CHECK(g_capture.nEntries == 2 && g_capture.nBadPayloads == 0,
        "every match arrives exactly once inside well-formed batches");
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

    /* A broad search outruns a busy main loop. The worker used to give up with
       "failed to queue search results" once 1024 matches were waiting; it has
       to wait for the loop instead and deliver every match, batched into
       messages that still fit a data channel message. */
    {
        char sMany[600];
        snprintf(sMany, sizeof(sMany), "%s/many", sRoot);
        CHECK(mkdir(sMany, 0755) == 0, "mkdir many");

        for (int i = 0; i < 5000; i++)
        {
            char sFile[700];
            snprintf(sFile, sizeof(sFile), "%s/match-%04d.dat", sMany, i);
            CHECK(write_file(sFile, "x"), "write one of many files");
        }

        reset_capture();
        memset(&mgr, 0, sizeof(mgr));
        mgr.pPath = sMany;
        mgr.pFileName = "match-*";

        CHECK(DirectGate_Search_Start(&session.search, &mgr) == XSTDOK, "the broad search starts");

        /* The loop only comes round every 30 ms - long enough for the worker
           to fill any fixed backlog many times over. */
        for (int i = 0; i < 1000 && g_capture.nOk == 0 && g_capture.nFailed == 0; i++)
        {
            usleep(30000);
            DirectGate_Search_Process(&session);
        }

        CHECK(g_capture.nFailed == 0, "a broad search does not fail on a slow main loop");
        CHECK(g_capture.nOk == 1, "a broad search completes");
        CHECK(g_capture.nEntries == 5000, "every match of a broad search is delivered");
        CHECK(g_capture.nBadPayloads == 0, "every batch is well-formed JSON");
        CHECK(g_capture.nPartial < 5000, "matches are batched rather than sent one message each");
        CHECK(g_capture.nLargestPayload <= 100U * 1024U, "a batch stays within a data channel message");
    }

    /* A deep tree, searched by the worker thread on the stack it really gets.
       Two path buffers per level used to overflow it about forty directories
       down and take the whole agent with it. */
    {
        char sDeep[4096];
        size_t nLen = (size_t)snprintf(sDeep, sizeof(sDeep), "%s/deep", sRoot);
        CHECK(mkdir(sDeep, 0755) == 0, "mkdir deep");

        for (int i = 0; i < 240; i++)
        {
            nLen += (size_t)snprintf(sDeep + nLen, sizeof(sDeep) - nLen, "/d");
            CHECK(mkdir(sDeep, 0755) == 0, "mkdir one deep level");
        }

        snprintf(sDeep + nLen, sizeof(sDeep) - nLen, "/bottom.dat");
        CHECK(write_file(sDeep, "x"), "write the file at the bottom");

        char sDeepRoot[600];
        snprintf(sDeepRoot, sizeof(sDeepRoot), "%s/deep", sRoot);

        reset_capture();
        memset(&mgr, 0, sizeof(mgr));
        mgr.pPath = sDeepRoot;
        mgr.pFileName = "bottom.dat";
        mgr.bRecursive = XTRUE;

        CHECK(DirectGate_Search_Start(&session.search, &mgr) == XSTDOK, "the deep search starts");
        CHECK(wait_for_search(&session) == XSTDOK, "the deep search finishes");
        CHECK(g_capture.nOk == 1 && g_capture.nEntries == 1, "the file at the bottom of a deep tree is found");
    }

    /* Cancelling while the worker is waiting for room ends the wait. */
    {
        char sMany[600];
        snprintf(sMany, sizeof(sMany), "%s/many", sRoot);

        reset_capture();
        memset(&mgr, 0, sizeof(mgr));
        mgr.pPath = sMany;
        mgr.pFileName = "match-*";

        CHECK(DirectGate_Search_Start(&session.search, &mgr) == XSTDOK, "a search to cancel starts");
        usleep(50000);
        CHECK(DirectGate_Search_Cancel(&session.search) >= 0, "the search accepts a cancel");

        for (int i = 0; i < 500 && g_capture.nOk == 0 && g_capture.nCancelled == 0 && g_capture.nFailed == 0; i++)
        {
            usleep(10000);
            DirectGate_Search_Process(&session);
        }

        CHECK(g_capture.nCancelled == 1 || g_capture.nOk == 1, "a cancelled search reports how it ended");
        CHECK(g_capture.nFailed == 0, "a cancelled search is not reported as a failure");
    }

    DirectGate_Search_Clear(&session.search);
    CHECK(DirectGate_Search_GetPipeFd(&session.search) == XSTDERR,
        "search pipe should be closed after clear");

    DirectGate_Files_Delete(sRoot, XTRUE);
    puts("search_smoke: OK");
    return 0;
}
