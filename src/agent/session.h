/*!
 * @file directgate-agent/src/agent/session.h
 * @brief Agent-side PTY session manager for multi-session support.
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

#ifndef __DIRECTGATE_SESSION_H__
#define __DIRECTGATE_SESSION_H__

#include "includes.h"
#include "protocol.h"
#include "transfer.h"
#include "config.h"
#include "webrtc.h"
#include "term.h"
#include "search.h"
#include "desktop.h"
#include "e2e.h"
#include "srp.h"
#include "keyauth.h"

typedef struct directgate_cfg_ directgate_cfg_t;

#ifdef __cplusplus
extern "C" {
#endif

#define DIRECTGATE_MAX_SESSIONS 32
#define DIRECTGATE_AUTH_TIMEOUT_MS 30000ULL
#define DIRECTGATE_AUTH_RATE_WINDOW_MS 60000ULL
#define DIRECTGATE_AUTH_RATE_MAX_ATTEMPTS DIRECTGATE_MAX_SESSIONS
#define DIRECTGATE_AUTH_MAX_MESSAGES 4

typedef enum directgate_session_mode_ {
    DIRECTGATE_SESSION_MODE_NONE = 0,
    DIRECTGATE_SESSION_MODE_TERMINAL,
    DIRECTGATE_SESSION_MODE_FILE_MANAGER,
    DIRECTGATE_SESSION_MODE_DESKTOP,
} directgate_session_mode_t;

typedef struct directgate_session_ {
    directgate_session_mode_t eRequestedMode;
    directgate_session_mode_t eActiveMode;
    struct directgate_session_mgr_ *pMgr;
    const directgate_cfg_t *pCfg;
    xapi_session_t *pPipeSession;
    xapi_session_t *pSearchSession;
    xapi_session_t *pDesktopSession;
    xapi_session_t *pWsSession;
    directgate_transfer_t transfer;
    directgate_search_t search;
    directgate_desktop_t desktop;
    directgate_webrtc_t webrtc;
    directgate_term_t term;
    directgate_e2e_t e2e;
    directgate_srp_t srp;
    directgate_keyauth_t keyauth;
    xbool_t bKeyAuthActive;
    uint32_t nSessionId;
    uint64_t nCreatedMs;
    uint64_t nLastKAPingMs;
    uint64_t nLastKAPongMs;
    uint8_t nAuthMessages;
    xbool_t bAuthenticated;
    xbool_t bDesktopShare;
    xbool_t bDesktopSharePending;
    uint64_t nDesktopShareExpiresMs;
    xbool_t bClosing;
    char sDesktopShareId[XSTR_MID];
    char sSavePath[XFILE_PATH_SIZE];
    char sSaveTempPath[XFILE_PATH_SIZE];
    char sSavePermissions[XPERM_LEN + 1];
    xbool_t bSaveForce;
} directgate_session_t;

typedef struct directgate_session_mgr_ {
    directgate_session_t *pSessions[DIRECTGATE_MAX_SESSIONS];
    const directgate_cfg_t *pCfg;
    uint64_t nAuthWindowStartMs;
    uint32_t nAuthAttempts;
} directgate_session_mgr_t;

void DirectGate_SessionMgr_Init(directgate_session_mgr_t *pMgr, const directgate_cfg_t *pCfg);
void DirectGate_SessionMgr_Destroy(directgate_session_mgr_t *pMgr);
xbool_t DirectGate_SessionMgr_IsEmpty(const directgate_session_mgr_t *pMgr);

directgate_session_t* DirectGate_SessionMgr_GetOrCreate(directgate_session_mgr_t *pMgr, xapi_session_t *pApiSession, uint32_t nSessionId);
directgate_session_t* DirectGate_SessionMgr_Create(directgate_session_mgr_t *pMgr, uint32_t nSessionId);
directgate_session_t* DirectGate_SessionMgr_Find(directgate_session_mgr_t *pMgr, uint32_t nSessionId);

int DirectGate_SessionMgr_Close(directgate_session_mgr_t *pMgr, uint32_t nSessionId, const char *pReason);
void DirectGate_SessionMgr_Remove(directgate_session_mgr_t *pMgr, directgate_session_t *pSession);
void DirectGate_SessionMgr_RemoveWithId(directgate_session_mgr_t *pMgr, uint32_t nSessionId);
size_t DirectGate_SessionMgr_ExpireUnauthenticated(directgate_session_mgr_t *pMgr, uint64_t nNowMs);

// Session-level operations
int DirectGate_Session_Send(directgate_session_t *pSession, xjson_obj_t *pHeader,
                            const uint8_t *pPayload, size_t nPayloadLength);

int DirectGate_Session_SendAuthResp(directgate_session_t *pSession, const char *pStatus,
                                    const char *pM2, const char *pReason);

int DirectGate_Session_SendManagerResp(directgate_session_t *pSession,
                                       const char *pAction, const char *pStatus,
                                       const char *pReason, const char *pPath);

int DirectGate_Session_SendManagerData(directgate_session_t *pSession, const char *pAction,
                                       const char *pStatus, const char *pPath,
                                       const uint8_t *pPayload, size_t nPayloadLen);

int DirectGate_Session_SendKeepalive(directgate_session_t *pSession, const char *pAction);
int DirectGate_Session_SendErrorMsg(directgate_session_t *pSession, const char *pReason);

directgate_session_mode_t DirectGate_SessionMode_FromString(const char *pMode);
const char* DirectGate_SessionMode_ToString(directgate_session_mode_t eMode);

int DirectGate_Session_EnsureMode(directgate_session_t *pSession, directgate_session_mode_t eMode, const char *pReason);
int DirectGate_Session_StartMode(directgate_session_t *pSession, directgate_session_mode_t eMode);
int DirectGate_Session_StartTerminal(directgate_session_t *pSession);
xbool_t DirectGate_Session_ConsumeAuthMessage(directgate_session_t *pSession);

int DirectGate_Session_DeriveE2EFromKey(directgate_session_t *pSession, const char *pDeviceId);
int DirectGate_Session_DeriveE2EFromSRP(directgate_session_t *pSession, const char *pDeviceId);

int DirectGate_Session_Close(directgate_session_t *pSession, const char *pReason);
void DirectGate_Session_Remove(directgate_session_t *pSession);

#ifdef __cplusplus
}
#endif

#endif
