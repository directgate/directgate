/*!
 * @file directgate-agent/src/agent/search.h
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

#ifndef __DIRECTGATE_SEARCH_H__
#define __DIRECTGATE_SEARCH_H__

#include "includes.h"
#include "protocol.h"
#include "thread.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct directgate_session_ directgate_session_t;

typedef enum directgate_search_event_type_ {
    DIRECTGATE_SEARCH_EVENT_PARTIAL = 0,
    DIRECTGATE_SEARCH_EVENT_COMPLETE,
    DIRECTGATE_SEARCH_EVENT_FAILED,
    DIRECTGATE_SEARCH_EVENT_CANCELLED
} directgate_search_event_type_t;

typedef struct directgate_search_event_ {
    directgate_search_event_type_t eType;
    char *pPayload;
    size_t nPayloadLen;
    char sReason[XSTR_MID];
    struct directgate_search_event_ *pNext;
} directgate_search_event_t;

typedef struct directgate_search_ {
    xthread_t worker;
    xsync_mutex_t lock;
    xbool_t bLockInit;
    xbool_t bRunning;
    xbool_t bPending;
    xvolatile_t nCancelRequested;
    xvolatile_t nInterrupted;

    /* [0]=read (main loop), [1]=write (worker thread).
       POSIX: a pipe (XSOCKET == int there). Windows: a private socket
       pair from XSock_CreatePair(), since WSAPoll only polls sockets. */
    XSOCKET nPipeFds[2];
    char sRootPath[XPATH_MAX];
    char sFileName[XPATH_MAX];
    char sText[XSTR_BIG];
    char sTypes[XSTR_MICRO];
    char sMinSize[XSTR_MICRO];
    char sMaxSize[XSTR_MICRO];
    char sFileSize[XSTR_MICRO];
    char sLinkCount[XSTR_MICRO];
    char sPermissions[XPERM_LEN + 1];
    xbool_t bRecursive;
    xbool_t bInsensitive;
    xbool_t bSearchLines;
    xbool_t bMatchOnly;
    directgate_search_event_t *pEventHead;
    directgate_search_event_t *pEventTail;
    char sReason[XSTR_MID];
} directgate_search_t;

void DirectGate_Search_Init(directgate_search_t *pSearch);
void DirectGate_Search_Clear(directgate_search_t *pSearch);
int DirectGate_Search_Start(directgate_search_t *pSearch, const directgate_pkg_manager_t *pMgrPkg);
int DirectGate_Search_Cancel(directgate_search_t *pSearch);
int DirectGate_Search_Process(directgate_session_t *pSession);
int DirectGate_Search_GetPipeFd(const directgate_search_t *pSearch);
const char* DirectGate_Search_GetReason(const directgate_search_t *pSearch);

#ifdef __cplusplus
}
#endif

#endif
