/*!
 * @file directgate-agent/src/agent/keymgr.h
 * @brief Volatile organization-managed client-key leases.
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

#ifndef __DIRECTGATE_KEYMGR_H__
#define __DIRECTGATE_KEYMGR_H__

#include "includes.h"
#include "keyauth.h"
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DIRECTGATE_KEYMGR_MAX             2000U
#define DIRECTGATE_KEYMGR_LEASE_MAX_MS    (300U * 1000U)
#define DIRECTGATE_KEYMGR_POLL_MS         (60U * 1000U)
#define DIRECTGATE_KEYMGR_RETRY_MS        (15U * 1000U)
#define DIRECTGATE_KEYMGR_BODY_MAX        (256U * 1024U)

typedef uint8_t directgate_keymgr_key_t[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];

typedef enum {
    DIRECTGATE_KEYMGR_POLL_NONE = 0,
    DIRECTGATE_KEYMGR_POLL_LEASE,      /* A lease was parsed and waits to be installed */
    DIRECTGATE_KEYMGR_POLL_TRANSIENT,  /* Network, 5xx, an uncoded 4xx or an unreadable body: keep the lease to its deadline */
    DIRECTGATE_KEYMGR_POLL_DENIED      /* The API refused the device by code, or the endpoint is not allowed: drop it now */
} directgate_keymgr_poll_t;

/* A lease as it came off the wire, before the event loop installs it. Whoever holds the struct owns pKeys. */
typedef struct directgate_keymgr_lease_ {
    directgate_keymgr_key_t *pKeys;
    char sPolicyId[XSTR_TINY];
    char sExpiresAt[XSTR_TINY];
    uint32_t nRejected;
    uint32_t nTtlMs;
    uint16_t nKeyCount;
} directgate_keymgr_lease_t;

typedef struct directgate_keymgr_worker_ directgate_keymgr_worker_t;

/*
 * The installed lease. Only the event loop thread reads or writes this struct, so the key-auth path and the
 * per-session checks take no lock. The worker thread fetches leases into its own heap context, and
 * DirectGate_KeyManager_Sync() moves them over. The deadline is monotonic and never later than
 * DIRECTGATE_KEYMGR_LEASE_MAX_MS after the response arrived, so neither a wrong host clock nor an
 * API that cannot be reached keeps a key alive past that.
 */
typedef struct directgate_keymgr_ {
    directgate_keymgr_worker_t *pWorker;
    directgate_keymgr_key_t *pKeys;
    directgate_keymgr_poll_t eLastPoll; /* Last worker result, so a failure that repeats is logged once */
    char sOrganizationId[XSTR_TINY];
    uint64_t nDeadlineMs;               /* XTime_GetMonoMs() deadline, 0 while no lease is installed */
    uint32_t nGeneration;               /* Bumped every time the authorized set changes or is dropped */
    uint16_t nKeyCount;
    xbool_t bWorkerAllowed;
} directgate_keymgr_t;

void DirectGate_KeyManager_Init(directgate_keymgr_t *pKeyMgr);
void DirectGate_KeyManager_Clear(directgate_keymgr_t *pKeyMgr);

/* Lets Sync() start the lease worker once an organization enrollment needs one; only DirectGate_RunAgent()
   calls it, so tests drive the lease directly. Devices outside an organization never get the thread. */
void DirectGate_KeyManager_AllowWorker(directgate_keymgr_t *pKeyMgr);

/* Stops the worker and drops the lease. A worker still inside a request is waited for a bounded time and then
   left to release its own context when the request returns, so shutdown never hangs on the network. */
void DirectGate_KeyManager_Destroy(directgate_keymgr_t *pKeyMgr);

/* Event loop housekeeping: follows enrollment changes, installs what the worker fetched, applies refusals and
   expires the lease. Cheap enough to run on every loop iteration. */
void DirectGate_KeyManager_Sync(directgate_keymgr_t *pKeyMgr, const directgate_cfg_t *pCfg, uint64_t nNowMs);

/* True when pClientPub is in the unexpired lease of organization pOrganizationId. */
xbool_t DirectGate_KeyManager_IsAuthorized(const directgate_keymgr_t *pKeyMgr, const char *pOrganizationId,
                                           const uint8_t *pClientPub, uint64_t nNowMs);

/* Session check: rescans the lease only when its generation moved since *pGeneration, which it then updates. */
xbool_t DirectGate_KeyManager_Recheck(const directgate_keymgr_t *pKeyMgr, const uint8_t *pClientPub, uint32_t *pGeneration,
                                      uint64_t nNowMs);

/* Parsing runs on the worker thread, installing on the event loop. nWallNow is only used when the response
   carries no expiresIn and the lifetime has to be derived from expiresAt. */
xbool_t DirectGate_KeyManager_ParseLease(const uint8_t *pBody, size_t nBodyLen, uint64_t nWallNow,
                                         directgate_keymgr_lease_t *pLease);

/* Takes ownership of pLease->pKeys when the lease belongs to the current organization. */
xbool_t DirectGate_KeyManager_Install(directgate_keymgr_t *pKeyMgr, directgate_keymgr_lease_t *pLease, uint64_t nNowMs);
void DirectGate_KeyManager_FreeLease(directgate_keymgr_lease_t *pLease);

/* Classifies a completed response. A 4xx is a refusal only when its body carries one of the API's device codes. */
directgate_keymgr_poll_t DirectGate_KeyManager_Classify(uint16_t nCode, const uint8_t *pBody, size_t nBodyLen, char *pReason,
                                                        size_t nReasonSize);

#ifdef __cplusplus
}
#endif

#endif
