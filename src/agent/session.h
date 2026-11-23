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
#include "command.h"

typedef struct directgate_cfg_ directgate_cfg_t;

#ifdef __cplusplus
extern "C" {
#endif

#define DIRECTGATE_MAX_SESSIONS 32
#define DIRECTGATE_AUTH_TIMEOUT_MS 30000ULL
#define DIRECTGATE_AUTH_RATE_WINDOW_MS 60000ULL
#define DIRECTGATE_AUTH_RATE_MAX_ATTEMPTS DIRECTGATE_MAX_SESSIONS
#define DIRECTGATE_AUTH_MAX_MESSAGES 4

/* Consecutive failed proofs the agent answers at full speed before it starts making the next attempt wait. A few
 * are ordinary, a mistyped password, a client retrying, so the grace keeps the honest case unpunished, while the
 * doubling past it turns a sustained guessing run from tens of thousands of tries a day into a few hundred. */
#define DIRECTGATE_AUTH_FAILURE_GRACE 5
#define DIRECTGATE_AUTH_LOCKOUT_BASE_MS 2000ULL
#define DIRECTGATE_AUTH_LOCKOUT_MAX_MS 300000ULL

/* How long a session may live on its data channel alone once its relay route is gone. The relay ends a client it
   signs out by closing its socket, which a detached session may no longer hear of, so this bounds how long that can
   go unheard: the same minute a dead relay link already went unnoticed before. */
#define DIRECTGATE_SESSION_DETACHED_MAX_MS 60000ULL

/* A resumed session still takes, for this long, what its client put on the data channel under its old id before
   the new one reached it: input in flight across the switch is not lost. */
#define DIRECTGATE_SESSION_RESUME_ALIAS_MS 10000ULL

/* The most a resume proof may decode to: a sealed auth header carries a few ids and counters, nothing more. */
#define DIRECTGATE_SESSION_RESUME_PROOF_MAX 1024U

/* How long bulk data - file transfer chunks, command output - waits for a WebRTC data channel before the relay is
   taken as the only way left. A client that knows sooner, its own ICE having failed, says so (webrtc/unavailable)
   and the wait ends there. The relay carries bulk data only when WebRTC cannot be established at all. */
#define DIRECTGATE_BULK_CHANNEL_WAIT_MS 15000ULL

/*
    The relay limits what each client session moves through it (its "limit" status: a rate after a burst) and stops
    reading the agent's whole link when one session goes past it. What can wait - bulk data on the relay - keeps below
    it instead: each session counts what it sends the relay in a bucket of its own, at a sixteenth less than the
    relay's rate and half its burst, so the relay's bucket always holds more than the agent's. In thousandths of a
    byte, like the relay's: a millisecond of any rate is a whole number of them. The floor keeps a debt in range.
*/
#define DIRECTGATE_RELAY_PACE_UNIT      1000
#define DIRECTGATE_RELAY_PACE_SHARE     16
#define DIRECTGATE_RELAY_PACE_FLOOR     (-(INT64_MAX / 2))

/* Where a session's bulk data may go (DirectGate_Session_GetBulkRoute) */
typedef enum directgate_bulk_route_ {
    DIRECTGATE_BULK_WAIT = 0,       /* Nowhere yet: the data channel is coming, or coming back */
    DIRECTGATE_BULK_CHANNEL,        /* The WebRTC data channel, direct or through TURN */
    DIRECTGATE_BULK_RELAY           /* The relay: WebRTC could not be established for this session */
} directgate_bulk_route_t;

typedef enum directgate_session_mode_ {
    DIRECTGATE_SESSION_MODE_NONE = 0,
    DIRECTGATE_SESSION_MODE_TERMINAL,
    DIRECTGATE_SESSION_MODE_FILE_MANAGER,
    DIRECTGATE_SESSION_MODE_DESKTOP,
    DIRECTGATE_SESSION_MODE_EXEC,
    /* Commands and file operations on one session, one command at a time, for as long as the client keeps it: the
       persistent connection an AI agent's tools hold to a device, so signalling and authentication happen once */
    DIRECTGATE_SESSION_MODE_REMOTE,
} directgate_session_mode_t;

typedef struct directgate_session_ {
    directgate_session_mode_t eRequestedMode;
    directgate_session_mode_t eActiveMode;
    struct directgate_session_mgr_ *pMgr;
    struct directgate_fileop_ *pFileOp;
    const directgate_cfg_t *pCfg;
    xapi_session_t *pPipeSession;
    xapi_session_t *pSearchSession;
    xapi_session_t *pDesktopSession;
    xapi_session_t *pFileOpSession;
    xapi_session_t *pWsSession;
    directgate_transfer_t transfer;
    directgate_search_t search;
    directgate_desktop_t desktop;
    directgate_webrtc_t webrtc;
    directgate_term_t term;
    directgate_command_t command;
    directgate_e2e_t e2e;
    directgate_srp_t srp;
    directgate_keyauth_t keyauth;
    xbool_t bKeyAuthActive;
    xbool_t bManagedKeyPending;     /* Key-auth hello matched the organization lease, not a local key */
    xbool_t bManagedKeySession;     /* Authenticated by a managed key: no admin actions, closed when the lease drops it */
    uint32_t nManagedKeyGen;        /* Lease generation this session's key was last found in */
    uint8_t managedClientPub[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    uint32_t nSessionId;
    uint64_t nCreatedMs;
    uint64_t nLastKAPingMs;
    uint64_t nLastKAPongMs;
    xbool_t bWebRTCWasUp;           /* Data channel up at the last pass, so a drop is seen once */
    uint64_t nBulkWaitMs;           /* When bulk data began waiting for a data channel; 0 while it is not waiting */
    xbool_t bBulkRelay;             /* WebRTC is not possible for this session: bulk data may take the relay */
    directgate_bulk_route_t eBulkPin; /* What the bulk data in progress started on; WAIT while there is none */
    xbool_t bPendingOpen;           /* A download asked for while no route was known, started once one is */
    char sPendingOpenPath[XFILE_PATH_SIZE];
    int64_t nRelayTokens;           /* What it may still send the relay: see DIRECTGATE_RELAY_PACE_UNIT */
    uint64_t nRelayTokensMs;        /* When that was counted; 0 before anything was, the bucket full */
    /* The relay route is gone and the session lives on its data channel alone, for a bounded time while its client
       reconnects. It never sends to the relay, and no relay message reaches it: see DirectGate_DetachSession. */
    xbool_t bDetached;
    uint64_t nDetachedMs;
    /* The id the session had before its client resumed it under a new relay socket, and until when data-channel
       messages still sealed under that id are taken as this session's: see DirectGate_Session_HandleResume. */
    uint32_t nPrevSessionId;
    uint64_t nPrevSessionUntilMs;
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
    uint32_t nAuthFailures;
    uint64_t nAuthLockoutUntilMs;
    uint32_t nRelayRateBytes;       /* The relay's limit, from its "limit" status; 0: the relay has none */
    uint32_t nRelayBurstBytes;
} directgate_session_mgr_t;

void DirectGate_SessionMgr_Init(directgate_session_mgr_t *pMgr, const directgate_cfg_t *pCfg);
void DirectGate_SessionMgr_Destroy(directgate_session_mgr_t *pMgr);
xbool_t DirectGate_SessionMgr_IsEmpty(const directgate_session_mgr_t *pMgr);

directgate_session_t* DirectGate_SessionMgr_GetOrCreate(directgate_session_mgr_t *pMgr, xapi_session_t *pApiSession, uint32_t nSessionId);
directgate_session_t* DirectGate_SessionMgr_Create(directgate_session_mgr_t *pMgr, uint32_t nSessionId);
directgate_session_t* DirectGate_SessionMgr_Find(directgate_session_mgr_t *pMgr, uint32_t nSessionId);
directgate_session_t* DirectGate_SessionMgr_FindResumed(directgate_session_mgr_t *pMgr, uint32_t nPrevId, uint64_t nNowMs);

int DirectGate_SessionMgr_Close(directgate_session_mgr_t *pMgr, uint32_t nSessionId, const char *pReason);
void DirectGate_SessionMgr_Remove(directgate_session_mgr_t *pMgr, directgate_session_t *pSession);
void DirectGate_SessionMgr_RemoveWithId(directgate_session_mgr_t *pMgr, uint32_t nSessionId);
size_t DirectGate_SessionMgr_ExpireUnauthenticated(directgate_session_mgr_t *pMgr, uint64_t nNowMs);

/*!
 * @brief Report the outcome of a cryptographic proof so repeated failures are throttled.
 *
 * Only a proof that was actually verified and rejected counts. A client whose key is simply not authorized falls
 * back to the password by design, and punishing that would throttle the normal path instead of an attacker.
 */
void DirectGate_SessionMgr_NoteAuthFailure(directgate_session_mgr_t *pMgr);
void DirectGate_SessionMgr_NoteAuthSuccess(directgate_session_mgr_t *pMgr);
xbool_t DirectGate_SessionMgr_IsAuthLocked(directgate_session_mgr_t *pMgr, uint64_t *pRemainMs);

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

/*!
 * @brief Where the session's bulk data may go now.
 *
 * The data channel when it is open. The relay only once WebRTC has proved impossible: the client said so, or no data
 * channel came up within DIRECTGATE_BULK_CHANNEL_WAIT_MS of bulk data starting to wait for one. Otherwise WAIT, and
 * the caller holds its data back - nothing bulky reaches the relay while a channel is coming or coming back.
 * Bulk data that started on the relay stays there until it is done (see DirectGate_Session_SendBulk), so that no
 * message of it can be overtaken by a later one sent over the channel.
 */
directgate_bulk_route_t DirectGate_Session_GetBulkRoute(directgate_session_t *pSession, uint64_t nNowMs);

/*!
 * @brief How long the event loop may sleep before the wait for a data channel runs out, so that the relay is taken
 *        on time, or before bulk data on the relay may send again (DirectGate_Session_GetRelayWaitMs).
 *        DIRECTGATE_COMMAND_WAIT_NONE when nothing waits: the channel opening is an event of its own.
 */
uint32_t DirectGate_Session_GetBulkWaitMs(const directgate_session_t *pSession, uint64_t nNowMs);

/*!
 * @brief Sends bulk data on @p eRoute (CHANNEL or RELAY, never WAIT) and pins the session's bulk data to that route
 *        until DirectGate_Session_ReleaseBulk. A channel send that fails falls back to the relay, as every send does.
 */
int DirectGate_Session_SendBulk(directgate_session_t *pSession, directgate_bulk_route_t eRoute,
                                xjson_obj_t *pHeader, const uint8_t *pPayload, size_t nPayloadLength);

/*!
 * @brief The bulk data in progress is done: what comes next chooses its route afresh.
 */
void DirectGate_Session_ReleaseBulk(directgate_session_t *pSession);

/*!
 * @brief Whether bulk data is in progress or waiting to start: a download, one held until its route is known, or a
 *        command whose output may still come.
 */
xbool_t DirectGate_Session_HasBulk(const directgate_session_t *pSession);

/*!
 * @brief The client found WebRTC impossible (webrtc/unavailable): bulk data may take the relay at once.
 */
void DirectGate_Session_SetBulkRelay(directgate_session_t *pSession);

/*!
 * @brief Whether the session's bulk data goes to the relay now: where DirectGate_Session_GetBulkRoute says RELAY.
 */
xbool_t DirectGate_Session_IsBulkOnRelay(const directgate_session_t *pSession);

/*!
 * @brief The relay's limit, from its "limit" status on the relay link; 0 when the relay has none, as a new link has
 *        until told otherwise.
 */
void DirectGate_SessionMgr_SetRelayLimit(directgate_session_mgr_t *pMgr, uint32_t nRateBytes, uint32_t nBurstBytes);

/*!
 * @brief How long bulk data on the relay waits before it may send more without going past the relay's limit; 0 when
 *        it may send now, or the relay has no limit. Never DIRECTGATE_COMMAND_WAIT_NONE.
 */
uint32_t DirectGate_Session_GetRelayWaitMs(const directgate_session_t *pSession, uint64_t nNowMs);

#ifdef DIRECTGATE_TESTING
/* The session's relay bucket at nNowMs, in thousandths of a byte, counting nothing */
int64_t DirectGate_Session_TestRelayLevel(const directgate_session_t *pSession, uint64_t nNowMs);
#endif

int DirectGate_Session_SendKeepalive(directgate_session_t *pSession, const char *pAction);
int DirectGate_Session_SendErrorMsg(directgate_session_t *pSession, const char *pReason);

directgate_session_mode_t DirectGate_SessionMode_FromString(const char *pMode);
const char* DirectGate_SessionMode_ToString(directgate_session_mode_t eMode);

void DirectGate_Session_SetPreLogon(xbool_t bPreLogon);
xbool_t DirectGate_Session_IsPreLogon(void);

/*!
 * @brief Gate a handler on the session being authenticated and in @p eMode.
 * @return XSTDOK to proceed. Anything else is a refusal the caller must return on without touching @p pSession
 *         again: an unauthenticated session has already been closed and freed by the time this returns.
 */
int DirectGate_Session_EnsureMode(directgate_session_t *pSession, directgate_session_mode_t eMode, const char *pReason);
int DirectGate_Session_StartMode(directgate_session_t *pSession, directgate_session_mode_t eMode);
int DirectGate_Session_StartTerminal(directgate_session_t *pSession);
xbool_t DirectGate_Session_ConsumeAuthMessage(directgate_session_t *pSession);

int DirectGate_Session_DeriveE2EFromKey(directgate_session_t *pSession, const char *pDeviceId);
int DirectGate_Session_DeriveE2EFromSRP(directgate_session_t *pSession, const char *pDeviceId);

int DirectGate_Session_Close(directgate_session_t *pSession, const char *pReason);
void DirectGate_Session_Remove(directgate_session_t *pSession);

/*!
 * @brief Whether the session may outlive its relay route on its data channel, and so be resumed under a new one.
 */
xbool_t DirectGate_Session_CanDetach(const directgate_session_t *pSession);

/*!
 * @brief Answer an auth "resume" that arrived on the relay link @p pRelay.
 *
 * The client proves, on the socket that replaced the one it lost, that it holds a live desktop session's keys. On a
 * valid proof the session carries on under the new socket's id - same keys, counters, data channel and desktop - and
 * the answer is a plaintext "ok" carrying a proof of the agent's own. Anything else is answered "failed" and leaves
 * every session as it was, so the client authenticates afresh.
 */
int DirectGate_Session_HandleResume(directgate_session_mgr_t *pMgr, xapi_session_t *pRelay, const directgate_pkg_t *pPkg);

#ifdef __cplusplus
}
#endif

#endif
