/*!
 * @file directgate-agent/src/agent/search.c
 * @brief Async file-manager search worker for agent sessions.
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

#include "search.h"
#include "common.h"
#include "files.h"
#include "session.h"

/* Queue bounds between the worker and the main loop. A full queue makes the
 * worker wait for the main loop rather than fail the search: a broad search
 * outruns the loop as a matter of course. */
#define DIRECTGATE_SEARCH_QUEUE_EVENTS  4096U
#define DIRECTGATE_SEARCH_QUEUE_BYTES   (16U * 1024U * 1024U)
#define DIRECTGATE_SEARCH_QUEUE_WAIT_US 2000U

/* Matches are sent in batches of whatever queued up between two passes of the
 * main loop, each message kept under this size so it still fits a data channel
 * message (a browser accepts 256 KB) with room for framing and encryption. */
#define DIRECTGATE_SEARCH_BATCH_BYTES   (96U * 1024U)

/* Content search reads at most this much of each file: the whole file used to
 * be loaded, and one multi-gigabyte file in the tree could exhaust memory. */
#define DIRECTGATE_SEARCH_TEXT_MAX_BYTES (32U * 1024U * 1024U)

typedef struct directgate_search_build_ {
    directgate_search_t *pSearch;
    char sWarning[XSTR_MID];
    char sError[XSTR_MID];
} directgate_search_build_t;

static int DirectGate_Search_GetWsFd(const directgate_session_t *pSession)
{
    XCHECK_NL((pSession != NULL), (int)XSOCK_INVALID);
    XCHECK_NL((pSession->pWsSession != NULL), (int)XSOCK_INVALID);
    return (int)pSession->pWsSession->sock.nFD;
}

static void DirectGate_Search_FreeEvent(directgate_search_event_t *pEvent)
{
    XCHECK_VOID_NL((pEvent != NULL));
    free(pEvent->pPayload);
    free(pEvent);
}

static void DirectGate_Search_ClearEvents(directgate_search_t *pSearch)
{
    XCHECK_VOID_NL((pSearch != NULL));

    directgate_search_event_t *pEvent = pSearch->pEventHead;
    while (pEvent != NULL)
    {
        directgate_search_event_t *pNext = pEvent->pNext;
        DirectGate_Search_FreeEvent(pEvent);
        pEvent = pNext;
    }

    pSearch->pEventHead = NULL;
    pSearch->pEventTail = NULL;
    pSearch->nQueuedBytes = 0;
    pSearch->nQueuedEvents = 0;
    pSearch->bPending = XFALSE;
}

const char* DirectGate_Search_GetReason(const directgate_search_t *pSearch)
{
    XCHECK_NL((pSearch != NULL), "search failed");
    return xstrused(pSearch->sReason) ? pSearch->sReason : "search failed";
}

static void DirectGate_Search_ResetResult(directgate_search_t *pSearch)
{
    XCHECK_VOID_NL((pSearch != NULL));

    DirectGate_Search_ClearEvents(pSearch);
    pSearch->sReason[0] = '\0';
}

static void DirectGate_Search_NormalizePath(char *pOutput, size_t nSize, const char *pPath)
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

    if (!nLen) xstrncpy(pOutput, nSize, "/");
}

static void DirectGate_Search_DrainPipe(directgate_search_t *pSearch)
{
    XCHECK_VOID_NL((pSearch != NULL));
    if (pSearch->nPipeFds[0] == XSOCK_INVALID) return;

    char sBuf[64];
#ifdef _WIN32
    while (recv(pSearch->nPipeFds[0], sBuf, sizeof(sBuf), 0) > 0) {}
#else
    while (read(pSearch->nPipeFds[0], sBuf, sizeof(sBuf)) > 0) {}
#endif
}

static void DirectGate_Search_JoinWorker(directgate_search_t *pSearch)
{
    XCHECK_VOID_NL((pSearch != NULL));

    if (pSearch->worker.nStatus == XTHREAD_SUCCESS && !pSearch->worker.nDetached)
    {
        XThread_Join(&pSearch->worker);
        XThread_Init(&pSearch->worker);
    }
}

static int DirectGate_Search_Notify(directgate_search_t *pSearch)
{
    XCHECK((pSearch != NULL), XSTDERR);
    if (pSearch->nPipeFds[1] == XSOCK_INVALID) return XSTDERR;

    const char cValue = 1;
#ifdef _WIN32
    if (send(pSearch->nPipeFds[1], &cValue, sizeof(cValue), 0) < 0 &&
        WSAGetLastError() != WSAEWOULDBLOCK)
    {
        xlogw("Failed to notify search pipe: error(%d)", WSAGetLastError());
        return XSTDERR;
    }
#else
    if (write(pSearch->nPipeFds[1], &cValue, sizeof(cValue)) < 0 &&
        errno != EAGAIN && errno != EWOULDBLOCK)
    {
        xlogw("Failed to notify search pipe: errno(%d)", errno);
        return XSTDERR;
    }
#endif

    return XSTDOK;
}

static int DirectGate_Search_QueueEventUnlocked(directgate_search_t *pSearch,
                                                directgate_search_event_type_t eType,
                                                char *pPayload, size_t nPayloadLen,
                                                const char *pReason)
{
    XCHECK((pSearch != NULL), XSTDERR);

    directgate_search_event_t *pEvent = (directgate_search_event_t*)calloc(1, sizeof(*pEvent));
    if (pEvent == NULL)
    {
        xloge("Failed to allocate search event: errno(%d)", errno);
        free(pPayload);
        return XSTDERR;
    }

    pEvent->eType = eType;
    pEvent->pPayload = pPayload;
    pEvent->nPayloadLen = nPayloadLen;
    xstrncpy(pEvent->sReason, sizeof(pEvent->sReason), xstrused(pReason) ? pReason : "");

    if (pSearch->pEventTail != NULL) pSearch->pEventTail->pNext = pEvent;
    else pSearch->pEventHead = pEvent;

    pSearch->pEventTail = pEvent;
    pSearch->nQueuedBytes += nPayloadLen;
    pSearch->nQueuedEvents++;
    pSearch->bPending = XTRUE;
    return XSTDOK;
}

static xbool_t DirectGate_Search_QueueFull(const directgate_search_t *pSearch, size_t nPayloadLen)
{
    return (pSearch->nQueuedEvents >= DIRECTGATE_SEARCH_QUEUE_EVENTS ||
            nPayloadLen > DIRECTGATE_SEARCH_QUEUE_BYTES - pSearch->nQueuedBytes) ? XTRUE : XFALSE;
}

static int DirectGate_Search_QueueEvent(directgate_search_t *pSearch,
                                        directgate_search_event_type_t eType,
                                        char *pPayload, size_t nPayloadLen,
                                        const char *pReason, xbool_t bStopRunning)
{
    XCHECK((pSearch != NULL), XSTDERR);
    XSync_Lock(&pSearch->lock);

    /* Results wait for room; a cancel or a teardown ends the wait. The terminal
       events carry no payload and always get in, so a search can always finish. */
    while (nPayloadLen && DirectGate_Search_QueueFull(pSearch, nPayloadLen))
    {
        XSync_Unlock(&pSearch->lock);

        if (XSYNC_ATOMIC_GET(&pSearch->nInterrupted))
        {
            free(pPayload);
            errno = ECANCELED;
            return XSTDERR;
        }

        DirectGate_Search_Notify(pSearch);
        xusleep(DIRECTGATE_SEARCH_QUEUE_WAIT_US);
        XSync_Lock(&pSearch->lock);
    }

    if (bStopRunning) pSearch->bRunning = XFALSE;
    int nStatus = DirectGate_Search_QueueEventUnlocked(pSearch, eType, pPayload, nPayloadLen, pReason);
    XSync_Unlock(&pSearch->lock);

    if (nStatus == XSTDOK)
        DirectGate_Search_Notify(pSearch);

    return nStatus;
}

static void DirectGate_Search_Finish(directgate_search_t *pSearch,
                                     directgate_search_event_type_t eType,
                                     char *pPayload, size_t nPayloadLen,
                                     const char *pReason)
{
    XCHECK_VOID_NL((pSearch != NULL));
    DirectGate_Search_QueueEvent(pSearch, eType, pPayload, nPayloadLen, pReason, XTRUE);
}

static int DirectGate_Search_ParseFileTypes(const char *pTypes)
{
    XCHECK((xstrused(pTypes)), XSTDERR);

    int nTypes = 0;
    size_t nLen = strlen(pTypes);

    for (size_t i = 0; i < nLen; ++i)
    {
        switch ((char)tolower((unsigned char)pTypes[i]))
        {
            case 'b': nTypes |= XF_BLOCK_DEVICE; break;
            case 'c': nTypes |= XF_CHAR_DEVICE; break;
            case 'd': nTypes |= XF_DIRECTORY; break;
            case 'f': nTypes |= XF_REGULAR; break;
            case 'l': nTypes |= XF_SYMLINK; break;
            case 'p': nTypes |= XF_PIPE; break;
            case 's': nTypes |= XF_SOCKET; break;
            case 'x': nTypes |= XF_EXEC; break;
            case ' ': case '\t': case ',': case ';': break;
            default:
                return XSTDERR;
        }
    }

    return nTypes;
}

static int DirectGate_Search_ParsePermissions(const char *pPerm)
{
    XCHECK((xstrused(pPerm)), XSTDERR);

    /* XPath_PermToMode reads any nine characters and treats everything that is
       not the expected letter as a cleared bit, so a string that is not a mode
       at all parses as 000 - and 000 is how the search spells "no permission
       filter". A browser typo would silently widen the result set, so the shape
       is checked here, where the value arrives from the wire. */
    static const char sLetters[XPERM_LEN] = { 'r', 'w', 'x', 'r', 'w', 'x', 'r', 'w', 'x' };
    XCHECK_NL((strlen(pPerm) == XPERM_LEN), XSTDERR);

    for (size_t i = 0; i < XPERM_LEN; i++)
        XCHECK_NL((pPerm[i] == sLetters[i] || pPerm[i] == '-'), XSTDERR);

    xmode_t nMode = 0;
    char sChmod[XSTR_MICRO];

    if (XPath_PermToMode(pPerm, &nMode) < 0) return XSTDERR;
    XPath_ModeToChmod(sChmod, sizeof(sChmod), nMode);
    return atoi(sChmod);
}

static int DirectGate_Search_ParseCount(const char *pValue, int *pOutput)
{
    XCHECK((pOutput != NULL), XSTDERR);
    XCHECK((xstrused(pValue)), XSTDERR);

    char *pEnd = NULL;
    errno = 0;
    long nValue = strtol(pValue, &pEnd, 10);

    while (pEnd != NULL && *pEnd && isspace((unsigned char)*pEnd)) ++pEnd;
    if (pEnd == pValue || (pEnd != NULL && *pEnd != '\0')) return XSTDERR;
    if (errno == ERANGE || nValue < INT_MIN || nValue > INT_MAX) return XSTDERR;

    *pOutput = (int)nValue;
    return XSTDOK;
}

static int DirectGate_Search_ParseSize(const char *pValue, size_t *pOutput)
{
    XCHECK((pOutput != NULL), XSTDERR);
    XCHECK((xstrused(pValue)), XSTDERR);
    XCHECK((isdigit((unsigned char)*pValue)), XSTDERR);

    char *pEnd = NULL;
    errno = 0;
    unsigned long long nValue = strtoull(pValue, &pEnd, 10);

    while (pEnd != NULL && *pEnd && isspace((unsigned char)*pEnd)) ++pEnd;
    if (pEnd == pValue || errno == ERANGE) return XSTDERR;

    if (pEnd != NULL && *pEnd)
    {
        char cSize = (char)tolower((unsigned char)*pEnd);
        unsigned long long nUnit;

        if (cSize == 'k') nUnit = 1024ULL;
        else if (cSize == 'm') nUnit = 1024ULL * 1024ULL;
        else if (cSize == 'g') nUnit = 1024ULL * 1024ULL * 1024ULL;
        else return XSTDERR;

        if (nValue > ULLONG_MAX / nUnit) return XSTDERR;
        nValue *= nUnit;

        ++pEnd;
        while (pEnd != NULL && *pEnd && isspace((unsigned char)*pEnd)) ++pEnd;
        if (pEnd != NULL && *pEnd != '\0') return XSTDERR;
    }

    /* Same reason on the 32-bit packages, where size_t is narrower than the
       value strtoull just produced. */
    if (nValue > (unsigned long long)SIZE_MAX) return XSTDERR;

    *pOutput = (size_t)nValue;
    return XSTDOK;
}

/* Queues one match on its own: serialized here, off the main loop, and joined
   into batches there (DirectGate_Search_Process), so a match is on its way the
   moment the loop next runs however slowly the rest of the tree follows. */
static int DirectGate_Search_QueueEntry(directgate_search_build_t *pBuild, xsearch_entry_t *pEntry)
{
    XCHECK((pBuild != NULL), XSTDERR);
    XCHECK((pEntry != NULL), XSTDERR);

    xstat_t st;
    memset(&st, 0, sizeof(st));
    st.st_mode = pEntry->nMode;
    st.st_uid = pEntry->nUID;
    st.st_gid = pEntry->nGID;
    st.st_size = (off_t)pEntry->nSize;
    st.st_mtime = pEntry->nTime;

    xjson_obj_t *pJson = DirectGate_Files_CreateEntryJson(pEntry->sName, pEntry->sPath, &st);
    if (pJson == NULL)
    {
        xstrncpy(pBuild->sError, sizeof(pBuild->sError), "failed to serialize search results");
        return XSTDERR;
    }

    size_t nLength = 0;
    char *pPayload = XJSON_DumpObj(pJson, 0, &nLength);
    XJSON_FreeObject(pJson);

    if (pPayload == NULL || !nLength)
    {
        free(pPayload);
        xstrncpy(pBuild->sError, sizeof(pBuild->sError), "failed to serialize search results");
        return XSTDERR;
    }

    if (DirectGate_Search_QueueEvent(pBuild->pSearch, DIRECTGATE_SEARCH_EVENT_PARTIAL,
        pPayload, nLength, NULL, XFALSE) < 0)
    {
        if (errno != ECANCELED)
            xstrncpy(pBuild->sError, sizeof(pBuild->sError), "failed to queue search results");

        return XSTDERR;
    }

    return XSTDOK;
}

static int DirectGate_Search_ResultCb(xsearch_t *pSearchCtx, xsearch_entry_t *pEntry, const char *pMsg)
{
    XCHECK((pSearchCtx != NULL), XSTDERR);
    directgate_search_build_t *pBuild = (directgate_search_build_t*)pSearchCtx->pUserCtx;
    XCHECK((pBuild != NULL), XSTDERR);

    if (xstrused(pMsg))
    {
        if (!xstrused(pBuild->sWarning))
            xstrncpy(pBuild->sWarning, sizeof(pBuild->sWarning), pMsg);

        xlogd("Search warning: %s", pMsg);
        return XSTDNON;
    }

    if (pEntry == NULL)
        return XSTDNON;

    return (DirectGate_Search_QueueEntry(pBuild, pEntry) == XSTDOK) ? XSTDNON : XSTDERR;
}

static int DirectGate_Search_HasCriteria(const directgate_search_t *pSearch)
{
    XCHECK((pSearch != NULL), XFALSE);

    return xstrused(pSearch->sFileName) ||
           xstrused(pSearch->sText) ||
           xstrused(pSearch->sPermissions) ||
           xstrused(pSearch->sTypes) ||
           xstrused(pSearch->sMinSize) ||
           xstrused(pSearch->sMaxSize) ||
           xstrused(pSearch->sFileSize) ||
           xstrused(pSearch->sLinkCount);
}

static int DirectGate_Search_ApplyCriteria(directgate_search_t *pSearch, xsearch_t *pSearchCtx)
{
    XCHECK((pSearch != NULL), XSTDERR);
    XCHECK((pSearchCtx != NULL), XSTDERR);

    pSearchCtx->bRecursive = pSearch->bRecursive;
    pSearchCtx->bInsensitive = pSearch->bInsensitive;
    pSearchCtx->bSearchLines = pSearch->bSearchLines;
    pSearchCtx->bMatchOnly = pSearch->bMatchOnly || xstrused(pSearch->sText);
    pSearchCtx->nBufferSize = DIRECTGATE_SEARCH_TEXT_MAX_BYTES;
    pSearchCtx->pInterrupted = &pSearch->nInterrupted;

    if (xstrused(pSearch->sText))
        xstrncpy(pSearchCtx->sText, sizeof(pSearchCtx->sText), pSearch->sText);

    if (xstrused(pSearch->sPermissions))
    {
        int nPerm = DirectGate_Search_ParsePermissions(pSearch->sPermissions);
        if (nPerm < 0) return XSTDERR;
        pSearchCtx->nPermissions = nPerm;
    }

    if (xstrused(pSearch->sTypes))
    {
        int nTypes = DirectGate_Search_ParseFileTypes(pSearch->sTypes);
        if (nTypes < 0) return XSTDERR;
        pSearchCtx->nFileTypes = nTypes;
    }

    if (xstrused(pSearch->sMinSize) &&
        DirectGate_Search_ParseSize(pSearch->sMinSize, &pSearchCtx->nMinSize) < 0)
        return XSTDERR;

    if (xstrused(pSearch->sMaxSize) &&
        DirectGate_Search_ParseSize(pSearch->sMaxSize, &pSearchCtx->nMaxSize) < 0)
        return XSTDERR;

    if (xstrused(pSearch->sFileSize))
    {
        size_t nFileSize = 0;
        if (DirectGate_Search_ParseSize(pSearch->sFileSize, &nFileSize) < 0)
            return XSTDERR;

        if (nFileSize > (size_t)INT_MAX) return XSTDERR;
        pSearchCtx->nFileSize = (int)nFileSize;
    }

    if (xstrused(pSearch->sLinkCount) &&
        DirectGate_Search_ParseCount(pSearch->sLinkCount, &pSearchCtx->nLinkCount) < 0)
        return XSTDERR;

    return XSTDOK;
}

static void* DirectGate_Search_Worker(void *pArg)
{
    directgate_search_t *pSearch = (directgate_search_t*)pArg;
    XCHECK((pSearch != NULL), NULL);

    char sReason[XSTR_MID];
    xstrncpy(sReason, sizeof(sReason), "search failed");

    directgate_search_build_t build;
    memset(&build, 0, sizeof(build));
    build.pSearch = pSearch;

    xsearch_t searchCtx;
    XSearch_Init(&searchCtx, pSearch->sFileName);
    searchCtx.callback = DirectGate_Search_ResultCb;
    searchCtx.pUserCtx = &build;

    if (DirectGate_Search_ApplyCriteria(pSearch, &searchCtx) < 0)
    {
        XSearch_Destroy(&searchCtx);
        DirectGate_Search_Finish(pSearch, DIRECTGATE_SEARCH_EVENT_FAILED, NULL, 0, "invalid search criteria");
        return NULL;
    }

#ifdef _WIN32
    int nStatus = XSTDOK;

    /* The virtual root "/" spans every mounted drive on Windows */
    if (!strcmp(pSearch->sRootPath, "/"))
    {
        DWORD nDrives = GetLogicalDrives();
        char cLetter;

        for (cLetter = 'A'; cLetter <= 'Z' && nStatus >= 0; cLetter++)
        {
            if (!(nDrives & (1U << (cLetter - 'A')))) continue;
            if (XSYNC_ATOMIC_GET(&pSearch->nCancelRequested)) break;

            char sDrivePath[8];
            snprintf(sDrivePath, sizeof(sDrivePath), "%c:/", cLetter);

            UINT nType = GetDriveTypeA(sDrivePath);
            if (nType == DRIVE_NO_ROOT_DIR || nType == DRIVE_UNKNOWN) continue;

            nStatus = XSearch(&searchCtx, sDrivePath);
        }
    }
    else
    {
        nStatus = XSearch(&searchCtx, pSearch->sRootPath);
    }
#else
    int nStatus = XSearch(&searchCtx, pSearch->sRootPath);
#endif

    xbool_t bCancelRequested = XSYNC_ATOMIC_GET(&pSearch->nCancelRequested);
    XSearch_Destroy(&searchCtx);

    if (bCancelRequested)
    {
        DirectGate_Search_Finish(pSearch, DIRECTGATE_SEARCH_EVENT_CANCELLED, NULL, 0, "search cancelled");
        return NULL;
    }

    if (nStatus < 0)
    {
        if (xstrused(build.sError)) xstrncpy(sReason, sizeof(sReason), build.sError);
        else if (xstrused(build.sWarning)) xstrncpy(sReason, sizeof(sReason), build.sWarning);

        DirectGate_Search_Finish(pSearch, DIRECTGATE_SEARCH_EVENT_FAILED, NULL, 0, sReason);
        return NULL;
    }

    /* Every match already went out as it was found; the completion carries none. */
    DirectGate_Search_Finish(pSearch, DIRECTGATE_SEARCH_EVENT_COMPLETE, NULL, 0, NULL);
    return NULL;
}

void DirectGate_Search_Init(directgate_search_t *pSearch)
{
    XCHECK_VOID_NL((pSearch != NULL));
    memset(pSearch, 0, sizeof(*pSearch));

    XThread_Init(&pSearch->worker);
    XSync_Init(&pSearch->lock);
    pSearch->bLockInit = XTRUE;

    pSearch->nPipeFds[0] = XSOCK_INVALID;
    pSearch->nPipeFds[1] = XSOCK_INVALID;
    pSearch->bRecursive = XTRUE;

    if (DirectGate_CreateNotifyPair(pSearch->nPipeFds) != XSTDOK)
        xloge("Failed to create nonblocking notification descriptors");
}

void DirectGate_Search_Clear(directgate_search_t *pSearch)
{
    XCHECK_VOID_NL((pSearch != NULL));

    XSYNC_ATOMIC_SET(&pSearch->nCancelRequested, 1);
    XSYNC_ATOMIC_SET(&pSearch->nInterrupted, 1);
    DirectGate_Search_JoinWorker(pSearch);

    if (pSearch->bLockInit)
    {
        XSync_Lock(&pSearch->lock);
        DirectGate_Search_ResetResult(pSearch);
        pSearch->bRunning = XFALSE;
        XSync_Unlock(&pSearch->lock);
        XSync_Destroy(&pSearch->lock);
        pSearch->bLockInit = XFALSE;
    }

    if (pSearch->nPipeFds[0] != XSOCK_INVALID)
    {
        xclosesock(pSearch->nPipeFds[0]);
        pSearch->nPipeFds[0] = XSOCK_INVALID;
    }

    if (pSearch->nPipeFds[1] != XSOCK_INVALID)
    {
        xclosesock(pSearch->nPipeFds[1]);
        pSearch->nPipeFds[1] = XSOCK_INVALID;
    }
}

int DirectGate_Search_GetPipeFd(const directgate_search_t *pSearch)
{
    XCHECK_NL((pSearch != NULL), XSTDERR);
    /* SOCKET values fit in 32 bits (WinAPI interop guarantee) and
       INVALID_SOCKET casts to -1, matching the POSIX convention */
    return (int)pSearch->nPipeFds[0];
}

int DirectGate_Search_Start(directgate_search_t *pSearch, const directgate_pkg_manager_t *pMgrPkg)
{
    XCHECK((pSearch != NULL), XSTDERR);
    XCHECK((pMgrPkg != NULL), XSTDERR);

    if (pSearch->nPipeFds[0] == XSOCK_INVALID || pSearch->nPipeFds[1] == XSOCK_INVALID)
    {
        xstrncpy(pSearch->sReason, sizeof(pSearch->sReason), "search pipe is not available");
        return XSTDERR;
    }

    xstat_t st;
    if (!xstrused(pMgrPkg->pPath) || xstat(pMgrPkg->pPath, &st) < 0 || !S_ISDIR(st.st_mode))
    {
        xstrncpy(pSearch->sReason, sizeof(pSearch->sReason), "search path is not a directory");
        return XSTDERR;
    }

    XSync_Lock(&pSearch->lock);

    if (pSearch->bRunning)
    {
        const char *pReason = XSYNC_ATOMIC_GET(&pSearch->nCancelRequested) ?
            "search cancellation in progress" : "search already in progress";

        xstrncpy(pSearch->sReason, sizeof(pSearch->sReason), pReason);
        XSync_Unlock(&pSearch->lock);
        return XSTDERR;
    }

    xbool_t bNeedJoin = (pSearch->worker.nStatus == XTHREAD_SUCCESS && !pSearch->worker.nDetached);
    XSync_Unlock(&pSearch->lock);

    if (bNeedJoin)
        DirectGate_Search_JoinWorker(pSearch);

    XSync_Lock(&pSearch->lock);

    XThread_Init(&pSearch->worker);
    DirectGate_Search_ResetResult(pSearch);
    XSYNC_ATOMIC_SET(&pSearch->nCancelRequested, 0);
    XSYNC_ATOMIC_SET(&pSearch->nInterrupted, 0);

    DirectGate_Search_NormalizePath(pSearch->sRootPath, sizeof(pSearch->sRootPath), pMgrPkg->pPath);
    xstrncpy(pSearch->sFileName, sizeof(pSearch->sFileName), xstrused(pMgrPkg->pFileName) ? pMgrPkg->pFileName : "");
    xstrncpy(pSearch->sText, sizeof(pSearch->sText), xstrused(pMgrPkg->pText) ? pMgrPkg->pText : "");
    xstrncpy(pSearch->sTypes, sizeof(pSearch->sTypes), xstrused(pMgrPkg->pTypes) ? pMgrPkg->pTypes : "");
    xstrncpy(pSearch->sMinSize, sizeof(pSearch->sMinSize), xstrused(pMgrPkg->pMinSize) ? pMgrPkg->pMinSize : "");
    xstrncpy(pSearch->sMaxSize, sizeof(pSearch->sMaxSize), xstrused(pMgrPkg->pMaxSize) ? pMgrPkg->pMaxSize : "");
    xstrncpy(pSearch->sFileSize, sizeof(pSearch->sFileSize), xstrused(pMgrPkg->pFileSize) ? pMgrPkg->pFileSize : "");
    xstrncpy(pSearch->sLinkCount, sizeof(pSearch->sLinkCount), xstrused(pMgrPkg->pLinkCount) ? pMgrPkg->pLinkCount : "");
    xstrncpy(pSearch->sPermissions, sizeof(pSearch->sPermissions), xstrused(pMgrPkg->pPermissions) ? pMgrPkg->pPermissions : "");

    pSearch->bRecursive = pMgrPkg->bRecursive;
    pSearch->bInsensitive = pMgrPkg->bInsensitive;
    pSearch->bSearchLines = pMgrPkg->bSearchLines;
    pSearch->bMatchOnly = pMgrPkg->bMatchOnly;

    if (!DirectGate_Search_HasCriteria(pSearch))
    {
        xstrncpy(pSearch->sReason, sizeof(pSearch->sReason), "missing search criteria");
        XSync_Unlock(&pSearch->lock);
        return XSTDERR;
    }

    pSearch->bRunning = XTRUE;
    pSearch->sReason[0] = '\0';
    DirectGate_Search_DrainPipe(pSearch);

    if (XThread_Create(&pSearch->worker, DirectGate_Search_Worker, pSearch, 0) != XSTDOK)
    {
        pSearch->bRunning = XFALSE;
        xstrncpy(pSearch->sReason, sizeof(pSearch->sReason), "failed to start search worker");
        XSync_Unlock(&pSearch->lock);
        return XSTDERR;
    }

    XSync_Unlock(&pSearch->lock);
    return XSTDOK;
}

int DirectGate_Search_Cancel(directgate_search_t *pSearch)
{
    XCHECK((pSearch != NULL), XSTDERR);

    XSync_Lock(&pSearch->lock);

    if (pSearch->bRunning)
    {
        XSYNC_ATOMIC_SET(&pSearch->nCancelRequested, 1);
        XSYNC_ATOMIC_SET(&pSearch->nInterrupted, 1);
        xstrncpy(pSearch->sReason, sizeof(pSearch->sReason), "search cancelled");
        XSync_Unlock(&pSearch->lock);
        return XSTDOK;
    }

    if (pSearch->bPending)
    {
        XSync_Unlock(&pSearch->lock);
        return XSTDOK;
    }

    if (!pSearch->bRunning)
    {
        xstrncpy(pSearch->sReason, sizeof(pSearch->sReason), "search is not running");
        XSync_Unlock(&pSearch->lock);
        return XSTDNON;
    }

    XSync_Unlock(&pSearch->lock);
    return XSTDNON;
}

/* Starts or extends the batch of matches the main loop is about to send. The
   payload shape is the one a single message always had, {"path":..,"entries":[..]},
   built by joining the entries the worker serialized. */
static xbool_t DirectGate_Search_AppendBatch(xbyte_buffer_t *pBatch, const char *pRootPath,
                                             const char *pEntry, size_t nEntryLen)
{
    if (!pBatch->nUsed)
    {
        xjson_obj_t *pRoot = XJSON_NewObject(NULL, NULL, XFALSE);
        if (pRoot == NULL) return XFALSE;

        XJSON_AddString(pRoot, "path", pRootPath);
        size_t nLength = 0;
        char *pPrefix = XJSON_DumpObj(pRoot, 0, &nLength);
        XJSON_FreeObject(pRoot);

        /* {"path":"..."} without its closing brace, then the array. */
        xbool_t bOk = (pPrefix != NULL && nLength > 1 &&
            XByteBuffer_Add(pBatch, (const uint8_t*)pPrefix, nLength - 1) > 0 &&
            XByteBuffer_Add(pBatch, (const uint8_t*)",\"entries\":[", 12) > 0);

        free(pPrefix);
        if (!bOk) return XFALSE;
    }
    else if (XByteBuffer_Add(pBatch, (const uint8_t*)",", 1) <= 0) return XFALSE;

    return XByteBuffer_Add(pBatch, (const uint8_t*)pEntry, nEntryLen) > 0;
}

static int DirectGate_Search_SendBatch(directgate_session_t *pSession, xbyte_buffer_t *pBatch, const char *pPath)
{
    XCHECK_NL((pBatch->nUsed > 0), XAPI_CONTINUE);

    int nStatus = XByteBuffer_Add(pBatch, (const uint8_t*)"]}", 2) > 0 ?
        DirectGate_Session_SendManagerData(pSession, "search", "partial", pPath, pBatch->pData, pBatch->nUsed) :
        DirectGate_Session_SendManagerResp(pSession, "search", "failed", "failed to serialize search results", pPath);

    XByteBuffer_Reset(pBatch);
    return nStatus;
}

int DirectGate_Search_Process(directgate_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_CONTINUE);

    directgate_search_t *pSearch = &pSession->search;
    DirectGate_Search_DrainPipe(pSearch);

    char sPath[XFILE_PATH_SIZE];
    xstrncpy(sPath, sizeof(sPath), pSearch->sRootPath);

    xbyte_buffer_t batch;
    XByteBuffer_Init(&batch, XSTDNON, XFALSE);

    int nStatus = XAPI_CONTINUE;
    while (XTRUE)
    {
        XSync_Lock(&pSearch->lock);

        directgate_search_event_t *pEvent = pSearch->pEventHead;
        if (pEvent == NULL)
        {
            pSearch->bPending = XFALSE;
            XSync_Unlock(&pSearch->lock);
            break;
        }

        pSearch->pEventHead = pEvent->pNext;
        if (pSearch->pEventHead == NULL)
            pSearch->pEventTail = NULL;

        pSearch->nQueuedBytes -= pEvent->nPayloadLen;
        pSearch->nQueuedEvents--;
        pSearch->bPending = (pSearch->pEventHead != NULL);
        XSync_Unlock(&pSearch->lock);

        if (pEvent->eType == DIRECTGATE_SEARCH_EVENT_PARTIAL)
        {
            if (batch.nUsed && batch.nUsed + pEvent->nPayloadLen + 3 > DIRECTGATE_SEARCH_BATCH_BYTES)
                nStatus = DirectGate_Search_SendBatch(pSession, &batch, sPath);

            if (nStatus >= 0 && pEvent->pPayload != NULL && pEvent->nPayloadLen > 0 &&
                !DirectGate_Search_AppendBatch(&batch, sPath, pEvent->pPayload, pEvent->nPayloadLen))
            {
                xloge("Failed to batch search results: sid(%u), bytes(%zu)", pSession->nSessionId, batch.nUsed);
                XByteBuffer_Reset(&batch);
            }

            DirectGate_Search_FreeEvent(pEvent);
            if (nStatus < 0) break;
            continue;
        }

        /* Everything found so far goes out ahead of the search's final word. */
        nStatus = DirectGate_Search_SendBatch(pSession, &batch, sPath);
        if (nStatus < 0)
        {
            DirectGate_Search_FreeEvent(pEvent);
            break;
        }

        switch (pEvent->eType)
        {
            case DIRECTGATE_SEARCH_EVENT_COMPLETE:
            {
                xlogi("Search completed: sid(%u), wsfd(%d), path(%s), bytes(%zu)",
                    pSession->nSessionId, DirectGate_Search_GetWsFd(pSession), sPath, pEvent->nPayloadLen);

                nStatus = DirectGate_Session_SendManagerData(pSession, "search", "ok",
                    sPath, (const uint8_t*)pEvent->pPayload, pEvent->nPayloadLen);
                break;
            }
            case DIRECTGATE_SEARCH_EVENT_CANCELLED:
            {
                const char *pReason = xstrused(pEvent->sReason) ? pEvent->sReason : "search cancelled";
                xlogi("Search cancelled: sid(%u), wsfd(%d), path(%s), reason(%s)",
                    pSession->nSessionId, DirectGate_Search_GetWsFd(pSession), sPath, pReason);

                nStatus = DirectGate_Session_SendManagerResp(pSession, "search", "cancelled", pReason, sPath);
                break;
            }
            case DIRECTGATE_SEARCH_EVENT_FAILED:
            default:
            {
                const char *pReason = xstrused(pEvent->sReason) ? pEvent->sReason : "search failed";
                xlogw("Search failed: sid(%u), wsfd(%d), path(%s), reason(%s)",
                    pSession->nSessionId, DirectGate_Search_GetWsFd(pSession), sPath, pReason);

                nStatus = DirectGate_Session_SendManagerResp(pSession, "search", "failed", pReason, sPath);
                break;
            }
        }

        DirectGate_Search_FreeEvent(pEvent);
        if (nStatus < 0) break;
    }

    if (nStatus >= 0) nStatus = DirectGate_Search_SendBatch(pSession, &batch, sPath);
    XByteBuffer_Clear(&batch);

    XSync_Lock(&pSearch->lock);
    xbool_t bRunning = pSearch->bRunning;
    XSync_Unlock(&pSearch->lock);

    if (!bRunning)
        DirectGate_Search_JoinWorker(pSearch);

    return nStatus;
}
