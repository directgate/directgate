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
    DIRECTGATE_ADD_KEY_INVALID,
    DIRECTGATE_ADD_KEY_UPDATED      /* Already there, and its scope or label changed */
} directgate_add_key_result_t;

typedef struct directgate_enroll_ {
    char sApiUrl[XPATH_MAX];
    char sOrganizationId[XSTR_TINY];
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

    /* The organization the device operator allowed to authorize client keys here through the managed-key lease,
       as typed with -m <organization id>. Nothing but -m changes it: not an API response, not a re-pairing without
       -m, not a revoked enrollment. The lease applies only while the enrollment's organizationId is this same id,
       so the API alone can never switch managed keys on or move them to another organization. Empty: off. */
    char sManagedOrgId[XSTR_TINY];

    /* Per entry of sAuthorizedKeys: what the key may open (DIRECTGATE_KEY_SCOPE_*, FULL for a key added before
       scopes), what people call it, and when it was added (Unix seconds; 0 when that was before it was kept) */
    uint8_t nAuthorizedKeyScopes[DIRECTGATE_MAX_AUTHORIZED_KEYS];
    char sAuthorizedKeyLabels[DIRECTGATE_MAX_AUTHORIZED_KEYS][DIRECTGATE_KEY_LABEL_MAX + 1];
    uint64_t nAuthorizedKeyAdded[DIRECTGATE_MAX_AUTHORIZED_KEYS];
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
    xbool_t bSetManagedOrg;
    xbool_t bRotateAgentKey;
    xbool_t bAllowTCP;
    xbool_t bHelp;
    xbool_t bInit;

    /* Runtime only, never persisted: refreshed tokens that are live in memory but
     * could not be written out yet. The event loop keeps retrying the save,
     * because a rotated refresh token lost at the next restart revokes the device. */
    xbool_t bSavePending;
} directgate_cfg_t;

void DirectGate_DisplayUsage(const char *pName);
void DirectGate_InitConfig(directgate_cfg_t *pCfg);

xbool_t DirectGate_ParseArgs(directgate_cfg_t *pCfg, int argc, char *argv[]);
xbool_t DirectGate_LoadConfig(directgate_cfg_t *pCfg, const char *pPath);
XSTATUS DirectGate_ApplyConfig(const directgate_cfg_t *pCfg);
xbool_t DirectGate_SaveConfig(const directgate_cfg_t *pCfg);

/* A key with no scope or label, as -a and older clients add one: an existing entry is left as it is */
directgate_add_key_result_t DirectGate_AddAuthorizedKey(directgate_cfg_t *pCfg, const char *pClientPubB64);

/* Puts a client key on the list, or changes the entry already there: bSetScope sets its scope to nScope, and a
   pLabel - checked with DirectGate_KeyLabel_IsValid, INVALID otherwise - its label. A new key without bSetScope
   opens everything. Nothing is persisted here. */
directgate_add_key_result_t DirectGate_PutAuthorizedKey(directgate_cfg_t *pCfg, const char *pClientPubB64, xbool_t bSetScope,
                                                        uint8_t nScope, const char *pLabel, uint64_t nAddedSec);

/* The entry the key is, compared as the key it decodes to, or XSTDERR for none or a malformed key */
int DirectGate_FindAuthorizedKey(const directgate_cfg_t *pCfg, const char *pClientPubB64);

/* Takes the key off the list; XTRUE when it was on it. Nothing is persisted here. */
xbool_t DirectGate_RemoveAuthorizedKey(directgate_cfg_t *pCfg, const char *pClientPubB64);

#ifdef __cplusplus
}
#endif

#endif
