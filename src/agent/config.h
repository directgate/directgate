/*!
 * @file directgate-agent/src/agent/config.h
 * @brief Agent config and CLI parsing.
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

#ifndef __DIRECTGATE_AGENT_CONFIG_H__
#define __DIRECTGATE_AGENT_CONFIG_H__

#include "includes.h"
#include "logger.h"
#include "webrtc.h"
#include "keyauth.h"
#include "auth.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DIRECTGATE_JWT_REFRESH_SKEW_SEC 120
#define DIRECTGATE_MAX_AUTHORIZED_KEYS  16

typedef char directgate_auth_key_t[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];

typedef enum {
    DIRECTGATE_ADD_KEY_ADDED = 0,
    DIRECTGATE_ADD_KEY_ALREADY,
    DIRECTGATE_ADD_KEY_FULL,
    DIRECTGATE_ADD_KEY_INVALID
} directgate_add_key_result_t;

typedef struct directgate_enroll_ {
    char sApiUrl[XPATH_MAX];
    char sAccessToken[XSTR_MID];
    char sRefreshToken[XSTR_MIN];
    char sEnrollExpiresAt[XSTR_TINY];
    uint64_t nAccessTokenExp;
    uint64_t nRefreshTokenExp;
    uint16_t nRefreshSkewSec;
    xbool_t bEnrolled;
} directgate_enroll_t;

/*!
 * Agent identity keypair + authorized client pubkeys for the public-key
 * authentication path ("method=key"). The private seed is persisted in the
 * agent config on disk (it is a local secret; never transmitted). Each entry
 * in authorizedKeys is a standard base64 encoding of a 32-byte Ed25519
 * public key produced at `-g` genkey time.
 */
typedef struct directgate_keyauth_cfg_ {
    directgate_auth_key_t sAuthorizedKeys[DIRECTGATE_MAX_AUTHORIZED_KEYS];
    char sIdentitySeedB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sIdentityPubB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    uint8_t nAuthorizedKeyCount;
} directgate_keyauth_cfg_t;

/*
 * Remote desktop policy. Only Windows reads these today: they gate the SYSTEM
 * helper that makes UAC prompts, elevated windows (Task Manager and friends)
 * and the lock screen reachable from a remote session.
 *
 * Both default to enabled, which is a deliberate and consequential choice: an
 * operator who can approve a UAC prompt is effectively an administrator on the
 * host, and one who can drive the lock screen can log in. Deployments that do
 * not want that set "desktop": { "elevatedInput": false } and get exactly the
 * pre-existing behaviour - privileged UI stays visible but frozen.
 */
typedef struct directgate_desktop_cfg_ {
    xbool_t bElevatedInput;
    xbool_t bLockScreen;
    xbool_t bPreLogon;
} directgate_desktop_cfg_t;

typedef struct directgate_cfg_ {
    directgate_ice_server_t sIceServers[DIRECTGATE_MAX_ICE_SERVERS];
    char sRelayUrl[XPATH_MAX];
    char sRoutingKey[XSTR_MID];
    char sShellHome[XPATH_MAX];
    char sShellUser[XSTR_MID];
    char sDeviceId[XSTR_MID];
    char sCfgPath[XPATH_MAX];
    char sPairingToken[XSTR_MID];
    char sGenKeyPath[XPATH_MAX];
    char sEnrollKeyPath[XPATH_MAX];
    directgate_enroll_t enroll;
    directgate_keyauth_cfg_t keyauth;
    directgate_desktop_cfg_t desktop;
    directgate_auth_t auth;
    directgate_log_t log;
    uint8_t nIceSrvCount;
    uint16_t nKAInterval;
    uint16_t nVerbose;
    xbool_t bWebRTCVerbose;
    xbool_t bSetSRP;
    xbool_t bGenKey;
    xbool_t bEnrollKey;
    xbool_t bEnroll;
    xbool_t bRotateAgentKey;
    xbool_t bAllowTCP;
    xbool_t bHelp;
    xbool_t bInit;
} directgate_cfg_t;

void DirectGate_DisplayUsage(const char *pName);
void DirectGate_InitConfig(directgate_cfg_t *pCfg);

xbool_t DirectGate_ParseArgs(directgate_cfg_t *pCfg, int argc, char *argv[]);
xbool_t DirectGate_LoadConfig(directgate_cfg_t *pCfg, const char *pPath);
XSTATUS DirectGate_ApplyConfig(const directgate_cfg_t *pCfg);
xbool_t DirectGate_SaveConfig(const directgate_cfg_t *pCfg);

directgate_add_key_result_t DirectGate_AddAuthorizedKey(directgate_cfg_t *pCfg, const char *pClientPubB64);

#ifdef __cplusplus
}
#endif

#endif
