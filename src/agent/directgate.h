/*!
 * @file directgate-agent/src/agent/directgate.h
 * @brief Agent-side WS client that exposes a PTY over the bridge server.
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

#ifndef __DIRECTGATE_H__
#define __DIRECTGATE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "includes.h"
#include "session.h"
#include "config.h"

#define DIRECTGATE_TEMPORARY_DESKTOP_SHARE_MAX_FAILURES 5
#define DIRECTGATE_MAX_TEMPORARY_DESKTOP_SHARES         8

typedef char xstr_tiny_t[XSTR_TINY];

typedef struct directgate_temporary_desktop_share_ {
    directgate_auth_t auth;
    xstr_mid_t sShareId;
    uint64_t nExpiresMs;
    uint8_t nFailedAttempts;
    xbool_t bUsed;
} directgate_temporary_desktop_share_t;

typedef struct directgate_conn_ {
    xlink_t relayLink;
    directgate_cfg_t *pCfg;
    directgate_session_mgr_t mgr;
    xapi_session_t *pWsSession;
    uint32_t nReconnectAttempt;
    uint64_t nNextReconnectMs;
    uint64_t nLastRelayRecvMs;
    /* Timestamp of the last liveness PING we sent to the relay. Compared
     * against nLastRelayRecvMs so exactly one probe goes out per silent
     * stretch instead of one per event loop tick. */
    uint64_t nLastRelayProbeMs;
    /* Force one API refresh before the first connect of this process so relay
     * assignment is re-evaluated on agent startup instead of blindly reusing
     * the relayUrl persisted in the config. */
    xbool_t bStartupRelayRefreshDone;
    /* Throttle window for re-resolving the relay URL via the API after
     * sustained connect failures. Set to "now + cooldown" right after a
     * probe so we don't hammer the API on every backoff tick. */
    uint64_t nNextRefreshProbeMs;
    xstr_tiny_t sDisconnectReason;
    xbool_t bReconnectSuppressed;
    /* A relay error frame claimed this device is no longer enrolled.
       Unauthenticated, so it only forces the next connect to ask the API.
       DirectGate_HandleRefreshStatus is what may then clear the enrollment. */
    xbool_t bEnrollmentDoubt;
    xbool_t bRoleSent;

    /* Temporary desktop share with one time access, limited fail attempts and expiration time window */
    directgate_temporary_desktop_share_t temporaryDesktopShares[DIRECTGATE_MAX_TEMPORARY_DESKTOP_SHARES];
} directgate_conn_t;

#ifdef DIRECTGATE_TESTING
int DirectGate_TestHandleTransportMessage(xapi_session_t *pApiSession,
                                          const uint8_t *pPayload,
                                          size_t nPayload);
void DirectGate_TestCheckWebRTCKeepalive(directgate_conn_t *pConn);
#endif

#ifdef __cplusplus
}
#endif

#endif
