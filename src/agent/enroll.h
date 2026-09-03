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

xbool_t DirectGate_Enroll_Pair(directgate_cfg_t *pCfg, const char *pPairingToken);
xbool_t DirectGate_Enroll_RotateAgentKey(directgate_cfg_t *pCfg);
xbool_t DirectGate_Enroll_AccessTokenIsUsable(const directgate_cfg_t *pCfg);
xbool_t DirectGate_Enroll_NeedsRefresh(const directgate_cfg_t *pCfg);
xbool_t DirectGate_Enroll_IsEnrolled(const directgate_cfg_t *pCfg);

directgate_enroll_status_t DirectGate_Enroll_Refresh(directgate_cfg_t *pCfg, char *pReason, size_t nReasonSize);
directgate_enroll_status_t DirectGate_Enroll_ClassifyRefreshFailure(const directgate_cfg_t *pCfg, uint16_t nStatusCode,
                                                                    const uint8_t *pBody, size_t nBodyLen,
                                                                    char *pReason, size_t nReasonSize);

#ifdef __cplusplus
}
#endif

#endif
