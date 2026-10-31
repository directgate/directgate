/*!
 * @file directgate-agent/src/agent/enroll.h
 * @brief Device enrollment via API (pair/refresh).
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

#ifndef __DIRECTGATE_HOST_ENROLL_H__
#define __DIRECTGATE_HOST_ENROLL_H__

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum directgate_enroll_refresh_status_ {
    DIRECTGATE_ENROLL_REFRESH_TERMINAL = -1,
    DIRECTGATE_ENROLL_REFRESH_TRANSIENT = 0,
    DIRECTGATE_ENROLL_REFRESH_OK = 1
} directgate_enroll_status_t;

xbool_t DirectGate_Enroll_ApplyPairResponse(directgate_cfg_t *pCfg, const uint8_t *pBody, size_t nBodyLen);
xbool_t DirectGate_Enroll_ApplyRefreshResponse(directgate_cfg_t *pCfg, const uint8_t *pBody, size_t nBodyLen);

/*!
 * @brief Build an enrollment API request: Host, User-Agent, JSON headers and
 *        the receive timeout. Does not perform any I/O.
 *
 * Exposed only so the Host header stays under test. libxutils defaults
 * requests to HTTP/1.0 and XHTTP_EasyPerform() synthesizes no headers, so
 * without it the request is routable by TLS SNI alone - which plain nginx
 * accepts and a CDN or WAF edge answers 403 to, before the origin is reached.
 */
xbool_t DirectGate_Enroll_BuildRequest(xhttp_t *pHandle, const char *pUrl, const char *pPath);

typedef struct directgate_enroll_field_ {
    const char *pKey;
    const char *pValue;
} directgate_enroll_field_t;

/* Serializes a request body with the JSON writer instead of interpolating values into a format string. Every value
   here is operator-supplied rather than attacker-supplied, so this is about not producing a body the API can only
   reject: a device id or token carrying a quote or a backslash comes out escaped. Fields with an empty value are
   left out, which is what makes agentPub optional. Returns a malloc'd buffer the caller cleanses and frees. */
char* DirectGate_Enroll_BuildBody(const directgate_enroll_field_t *pFields, size_t nCount, size_t *pLength);

xbool_t DirectGate_Enroll_Pair(directgate_cfg_t *pCfg, const char *pPairingToken);
xbool_t DirectGate_Enroll_RotateAgentKey(directgate_cfg_t *pCfg);
xbool_t DirectGate_Enroll_AccessTokenIsUsable(const directgate_cfg_t *pCfg);
xbool_t DirectGate_Enroll_NeedsRefresh(const directgate_cfg_t *pCfg);
xbool_t DirectGate_Enroll_IsEnrolled(const directgate_cfg_t *pCfg);

directgate_enroll_status_t DirectGate_Enroll_Refresh(directgate_cfg_t *pCfg, char *pReason, size_t nReasonSize);

/*
 * A refresh with its request on a worker thread. The active-session refresh used to run the HTTPS round trip on the
 * relay event loop, and that froze every live session for as long as the API took to answer: about a second and a
 * half every hour, 15 s when the API timed out, and longer while a connect or a TLS handshake could hang.
 *
 * Only the request runs on the worker. Reading the configuration into it, applying the answer and saving it all stay
 * on the event loop, in the calls below, so nothing of directgate_cfg_t is shared across threads. A caller must keep
 * at most one refresh in flight - this or DirectGate_Enroll_Refresh() - since two requests with one refresh token
 * read as reuse to the API the moment it rotates that token, and it revokes the device for it.
 */
typedef struct directgate_enroll_job_ directgate_enroll_job_t;

/* Builds the request and starts the worker. Returns NULL when nothing was sent, with *pStatus the status that refresh
   ends in: the refusals DirectGate_Enroll_Refresh() makes up front, or transient for a worker that could not start. */
directgate_enroll_job_t* DirectGate_Enroll_StartRefresh(const directgate_cfg_t *pCfg, directgate_enroll_status_t *pStatus,
                                                        char *pReason, size_t nReasonSize);

/* XTRUE once the answer, or the transport failure, is in. Never blocks. */
xbool_t DirectGate_Enroll_RefreshDone(directgate_enroll_job_t *pJob);

/* Takes a finished job and frees it. The answer is applied and saved exactly as DirectGate_Enroll_Refresh() does,
   unless the enrollment was cleared or its refresh token changed while the request was out: then it is dropped. */
directgate_enroll_status_t DirectGate_Enroll_FinishRefresh(directgate_cfg_t *pCfg, directgate_enroll_job_t *pJob,
                                                           char *pReason, size_t nReasonSize);

/* Takes a job that may still be running. Waits up to nWaitMs and finishes it if the answer comes in time: an answer
   can carry a rotated refresh token, and losing it makes the next start present the spent one. Otherwise the worker
   is left to free the job on its own and nothing is applied. */
directgate_enroll_status_t DirectGate_Enroll_AwaitRefresh(directgate_cfg_t *pCfg, directgate_enroll_job_t *pJob,
                                                          uint32_t nWaitMs, char *pReason, size_t nReasonSize);

directgate_enroll_status_t DirectGate_Enroll_ClassifyRefreshFailure(const directgate_cfg_t *pCfg, uint16_t nStatusCode,
                                                                    const uint8_t *pBody, size_t nBodyLen,
                                                                    char *pReason, size_t nReasonSize);

#ifdef __cplusplus
}
#endif

#endif
