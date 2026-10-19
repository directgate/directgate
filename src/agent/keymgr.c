/*!
 * @file directgate-agent/src/agent/keymgr.c
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

#include "includes.h"
#include "keymgr.h"
#include "enroll.h"
#include "common.h"

#define DIRECTGATE_KEYMGR_PATH            "/api/v1/devices/managed-keys"
#define DIRECTGATE_KEYMGR_IDLE            UINT32_MAX  /* Worker wait: until the inputs change */
#define DIRECTGATE_KEYMGR_SLICE_MS        250U        /* Worker wait granularity for stop and wake */
#define DIRECTGATE_KEYMGR_STOP_WAIT_MS    2000U       /* How long Destroy() waits for a busy worker */
#define DIRECTGATE_KEYMGR_STOP_POLL_MS    25U
#define DIRECTGATE_KEYMGR_USEC_PER_MS     1000U

/*
 * What the event loop and the worker share, under one lock. It lives on the heap rather than in the
 * connection so that a worker stuck in a request can outlive DirectGate_KeyManager_Destroy(): the owner
 * marks it orphaned and the worker frees it on its way out, so shutdown never waits on the network.
 */
struct directgate_keymgr_worker_ {
    xsync_mutex_t lock;
    xthread_t thread;

    /* Inputs, written by the event loop. Every change bumps nInputVersion, which retires older results. */
    char sApiUrl[XPATH_MAX];
    char sRefreshToken[XSTR_MIN];
    char sOrganizationId[XSTR_TINY];
    char sAppliedPolicyId[XSTR_TINY];
    char sAppliedExpiresAt[XSTR_TINY];
    uint32_t nInputVersion;

    /* The latest result, written by the worker and taken by the event loop. */
    directgate_keymgr_lease_t lease;
    directgate_keymgr_poll_t eResult;
    char sResultReason[XSTR_TINY];
    uint32_t nResultVersion;
    uint16_t nResultCode;

    xbool_t bWake;
    xbool_t bStop;
    xbool_t bDone;
    xbool_t bOrphaned;
};

/* The API codes that are its answer about this device, as opposed to a gateway in front of it refusing. */
static const char *g_pKeyManagerDenyCodes[] = {
    "DEVICE_ENROLLMENT_EXPIRED",
    "DEVICE_ENROLLMENT_REVOKED",
    "DEVICE_NOT_ORGANIZATION_MANAGED",
    "INVALID_REFRESH_TOKEN",
    "REFRESH_TOKEN_REUSE_DETECTED"
};

static const char* DirectGate_KeyManager_OrgName(const directgate_keymgr_t *pKeyMgr)
{
    return xstrused(pKeyMgr->sOrganizationId) ? pKeyMgr->sOrganizationId : "N/A";
}

void DirectGate_KeyManager_FreeLease(directgate_keymgr_lease_t *pLease)
{
    XCHECK_VOID_NL((pLease != NULL));
    free(pLease->pKeys);
    memset(pLease, 0, sizeof(*pLease));
}

void DirectGate_KeyManager_Init(directgate_keymgr_t *pKeyMgr)
{
    XCHECK_VOID_NL((pKeyMgr != NULL));
    memset(pKeyMgr, 0, sizeof(*pKeyMgr));
}

void DirectGate_KeyManager_Clear(directgate_keymgr_t *pKeyMgr)
{
    XCHECK_VOID_NL((pKeyMgr != NULL));
    free(pKeyMgr->pKeys);

    pKeyMgr->pKeys = NULL;
    pKeyMgr->nKeyCount = 0;
    pKeyMgr->nDeadlineMs = 0;
    pKeyMgr->nGeneration++;
}

void DirectGate_KeyManager_AllowWorker(directgate_keymgr_t *pKeyMgr)
{
    XCHECK_VOID_NL((pKeyMgr != NULL));
    pKeyMgr->bWorkerAllowed = XTRUE;
}

static xbool_t DirectGate_KeyManager_Find(const directgate_keymgr_t *pKeyMgr, const uint8_t *pClientPub)
{
    xbool_t bFound = XFALSE;

    /* Every entry is compared, so the time taken does not tell where in the lease a key sits. */
    for (uint16_t i = 0; i < pKeyMgr->nKeyCount; i++)
        if (CRYPTO_memcmp(pKeyMgr->pKeys[i], pClientPub, sizeof(directgate_keymgr_key_t)) == 0) bFound = XTRUE;

    return bFound;
}

xbool_t DirectGate_KeyManager_IsAuthorized(const directgate_keymgr_t *pKeyMgr, const char *pOrganizationId,
                                           const uint8_t *pClientPub, uint64_t nNowMs)
{
    XCHECK_NL((pKeyMgr != NULL && pClientPub != NULL), XFALSE);
    XCHECK_NL((xstrused(pOrganizationId) && xstrcmp(pKeyMgr->sOrganizationId, pOrganizationId)), XFALSE);
    XCHECK_NL((pKeyMgr->nDeadlineMs > 0 && nNowMs < pKeyMgr->nDeadlineMs), XFALSE);
    return DirectGate_KeyManager_Find(pKeyMgr, pClientPub);
}

xbool_t DirectGate_KeyManager_Recheck(const directgate_keymgr_t *pKeyMgr, const uint8_t *pClientPub, uint32_t *pGeneration,
                                      uint64_t nNowMs)
{
    XCHECK_NL((pKeyMgr != NULL && pClientPub != NULL && pGeneration != NULL), XFALSE);
    XCHECK_NL((pKeyMgr->nDeadlineMs > 0 && nNowMs < pKeyMgr->nDeadlineMs), XFALSE);

    if (*pGeneration == pKeyMgr->nGeneration) return XTRUE;
    XCHECK_NL((DirectGate_KeyManager_Find(pKeyMgr, pClientPub)), XFALSE);

    *pGeneration = pKeyMgr->nGeneration;
    return XTRUE;
}

directgate_keymgr_poll_t DirectGate_KeyManager_Classify(uint16_t nCode, const uint8_t *pBody, size_t nBodyLen, char *pReason, size_t nReasonSize)
{
    if (pReason != NULL && nReasonSize > 0) xstrncpyf(pReason, nReasonSize, "http-%u", (unsigned int)nCode);
    if (nCode >= 200 && nCode < 300) return DIRECTGATE_KEYMGR_POLL_LEASE;

    /* A 4xx is a refusal only when the API names it: a CDN or WAF edge answers 403 as well, and dropping every
       managed session over that would let anything in the path cut access. Everything else waits for expiry. */
    if (nCode < 400 || nCode >= 500 || pBody == NULL || !nBodyLen) return DIRECTGATE_KEYMGR_POLL_TRANSIENT;

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, (const char*)pBody, nBodyLen))
    {
        XJSON_Destroy(&json);
        return DIRECTGATE_KEYMGR_POLL_TRANSIENT;
    }

    directgate_keymgr_poll_t eResult = DIRECTGATE_KEYMGR_POLL_TRANSIENT;
    const char *pApiCode = XJSON_GetString(XJSON_GetObject(json.pRootObj, "code"));

    for (size_t i = 0; i < XARR_SIZE(g_pKeyManagerDenyCodes); i++)
    {
        if (!xstrcmp(pApiCode, g_pKeyManagerDenyCodes[i])) continue;
        if (pReason != NULL && nReasonSize > 0) xstrncpy(pReason, nReasonSize, pApiCode);
        eResult = DIRECTGATE_KEYMGR_POLL_DENIED;
        break;
    }

    XJSON_Destroy(&json);
    return eResult;
}

xbool_t DirectGate_KeyManager_ParseLease(const uint8_t *pBody, size_t nBodyLen, uint64_t nWallNow, directgate_keymgr_lease_t *pLease)
{
    XCHECK_NL((pLease != NULL), XFALSE);
    memset(pLease, 0, sizeof(*pLease));
    XCHECK_NL((pBody != NULL && nBodyLen > 0), XFALSE);

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, (const char*)pBody, nBodyLen))
    {
        XJSON_Destroy(&json);
        return XFALSE;
    }

    xbool_t bParsed = XFALSE;

    do
    {
        xjson_obj_t *pRoot = json.pRootObj;
        xjson_obj_t *pArray = XJSON_GetObject(pRoot, "publicKeys");
        const char *pPolicyId = XJSON_GetString(XJSON_GetObject(pRoot, "policyId"));
        const char *pExpiresAt = XJSON_GetString(XJSON_GetObject(pRoot, "expiresAt"));

        if (pArray == NULL || pArray->nType != XJSON_TYPE_ARRAY) break;
        if (!xstrused(pPolicyId) || strlen(pPolicyId) >= sizeof(pLease->sPolicyId)) break;
        if (xstrused(pExpiresAt) && strlen(pExpiresAt) >= sizeof(pLease->sExpiresAt)) break;

        /* The relative lifetime is what counts: it does not depend on the host clock agreeing with the API's.
           expiresAt is the fallback for an API that does not send it, and both are capped to the lease maximum. */
        uint64_t nTtlSec = XJSON_GetU32(XJSON_GetObject(pRoot, "expiresIn"));
        if (!nTtlSec)
        {
            xtime_t expiry;
            if (!xstrused(pExpiresAt) || XTime_FromISO(&expiry, pExpiresAt) <= 0) break;

            uint64_t nExpiresAt = XTime_ToEpochUTC(&expiry);
            nTtlSec = nExpiresAt > nWallNow ? nExpiresAt - nWallNow : 0;
        }

        uint64_t nTtlMs = nTtlSec * 1000ULL;
        if (nTtlMs > DIRECTGATE_KEYMGR_LEASE_MAX_MS) nTtlMs = DIRECTGATE_KEYMGR_LEASE_MAX_MS;
        pLease->nTtlMs = (uint32_t)nTtlMs;

        size_t nItems = XJSON_GetArrayLength(pArray);
        size_t nSlots = nItems < DIRECTGATE_KEYMGR_MAX ? nItems : DIRECTGATE_KEYMGR_MAX;

        if (nSlots > 0)
        {
            pLease->pKeys = (directgate_keymgr_key_t*)calloc(nSlots, sizeof(directgate_keymgr_key_t));
            if (pLease->pKeys == NULL) break;
        }

        /* Decoded once here, off the event loop, so key-auth compares raw bytes instead of decoding 2,000
           base64 strings per hello. An entry that is not exactly one Ed25519 key is skipped and counted. */
        for (size_t i = 0; i < nItems; i++)
        {
            const char *pKey = XJSON_GetString(XJSON_GetArrayItem(pArray, i));
            size_t nDecoded = 0;

            if (pLease->nKeyCount >= nSlots || !xstrused(pKey) || strlen(pKey) >= DIRECTGATE_KEYAUTH_PUB_B64_SIZE ||
                !DirectGate_KeyAuth_Base64Decode(pKey, pLease->pKeys[pLease->nKeyCount], sizeof(directgate_keymgr_key_t), &nDecoded) ||
                nDecoded != DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE)
            {
                pLease->nRejected++;
                continue;
            }

            pLease->nKeyCount++;
        }

        xstrncpy(pLease->sPolicyId, sizeof(pLease->sPolicyId), pPolicyId);
        xstrncpy(pLease->sExpiresAt, sizeof(pLease->sExpiresAt), pExpiresAt);
        bParsed = XTRUE;
    } while (0);

    XJSON_Destroy(&json);
    if (!bParsed) DirectGate_KeyManager_FreeLease(pLease);
    return bParsed;
}

xbool_t DirectGate_KeyManager_Install(directgate_keymgr_t *pKeyMgr, directgate_keymgr_lease_t *pLease, uint64_t nNowMs)
{
    XCHECK_NL((pKeyMgr != NULL && pLease != NULL), XFALSE);

    if (!xstrused(pKeyMgr->sOrganizationId) || !xstrcmp(pKeyMgr->sOrganizationId, pLease->sPolicyId))
    {
        xlogw("Managed-key lease ignored, it belongs to another organization: org(%s), policy(%s)",
            DirectGate_KeyManager_OrgName(pKeyMgr), pLease->sPolicyId);

        return XFALSE;
    }

    if (!pLease->nTtlMs)
    {
        xlogw("Managed-key lease arrived already expired, check the host clock: org(%s), keys(%u)",
            DirectGate_KeyManager_OrgName(pKeyMgr), (unsigned int)pLease->nKeyCount);

        DirectGate_KeyManager_Clear(pKeyMgr);
        return XFALSE;
    }

    size_t nBytes = (size_t)pLease->nKeyCount * sizeof(directgate_keymgr_key_t);
    xbool_t bSame = pKeyMgr->nDeadlineMs > 0 && pKeyMgr->nKeyCount == pLease->nKeyCount &&
        (!nBytes || !memcmp(pKeyMgr->pKeys, pLease->pKeys, nBytes));

    /* A renewal of the same set only moves the deadline; sessions rescan the lease only when its generation moves. */
    if (!bSame)
    {
        free(pKeyMgr->pKeys);
        pKeyMgr->pKeys = pLease->pKeys;
        pKeyMgr->nKeyCount = pLease->nKeyCount;
        pKeyMgr->nGeneration++;

        pLease->pKeys = NULL;
        pLease->nKeyCount = 0;

        if (pLease->nRejected > 0)
        {
            xlogw("Managed-key lease applied without its malformed entries: org(%s), keys(%u), skipped(%u), ttlMs(%u)",
                DirectGate_KeyManager_OrgName(pKeyMgr), (unsigned int)pKeyMgr->nKeyCount, pLease->nRejected, pLease->nTtlMs);
        }
        else
        {
            xlogi("Managed-key lease applied: org(%s), keys(%u), ttlMs(%u)",
                DirectGate_KeyManager_OrgName(pKeyMgr), (unsigned int)pKeyMgr->nKeyCount, pLease->nTtlMs);
        }
    }

    pKeyMgr->nDeadlineMs = nNowMs + pLease->nTtlMs;
    return XTRUE;
}

static uint32_t DirectGate_KeyManager_Jitter(uint32_t nIntervalMs)
{
    /* Devices that lost the API together must not all come back in the same second. */
    uint32_t nSpread = nIntervalMs / 4U;
    return (nIntervalMs - nSpread / 2U) + (uint32_t)(XTime_GetMs() % (uint64_t)(nSpread + 1U));
}

static directgate_keymgr_poll_t DirectGate_KeyManager_Fetch(const char *pApiUrl, const char *pRefreshToken,
                                                            const char *pAppliedPolicyId, const char *pAppliedExpiresAt,
                                                            directgate_keymgr_lease_t *pLease, uint16_t *pCode, char *pReason,
                                                            size_t nReasonSize)
{
    memset(pLease, 0, sizeof(*pLease));
    xstrncpy(pReason, nReasonSize, "request-build-failed");
    *pCode = 0;

    const directgate_enroll_field_t fields[] = {
        { "refreshToken", pRefreshToken },
        { "appliedPolicyId", pAppliedPolicyId },
        { "appliedExpiresAt", pAppliedExpiresAt }
    };

    size_t nReqLen = 0;
    char *pReqBody = DirectGate_Enroll_BuildBody(fields, XARR_SIZE(fields), &nReqLen);
    XCHECK_NL((pReqBody != NULL), DIRECTGATE_KEYMGR_POLL_TRANSIENT);

    char sUrl[XPATH_MAX + 64];
    xstrncpyf(sUrl, sizeof(sUrl), "%s%s", pApiUrl, DIRECTGATE_KEYMGR_PATH);

    xhttp_t handle;
    xbool_t bBuilt = DirectGate_Enroll_BuildRequest(&handle, sUrl, DIRECTGATE_KEYMGR_PATH);
    xhttp_status_t eStatus = XHTTP_EINIT;

    if (bBuilt)
    {
        /* 2,000 keys come to about 100 KB; anything far beyond that is not a lease. */
        handle.nContentMax = DIRECTGATE_KEYMGR_BODY_MAX;
        eStatus = XHTTP_EasyPerform(&handle, sUrl, (const uint8_t*)pReqBody, nReqLen);
    }

    OPENSSL_cleanse(pReqBody, nReqLen);
    free(pReqBody);

    directgate_keymgr_poll_t eResult = DIRECTGATE_KEYMGR_POLL_TRANSIENT;
    if (eStatus != XHTTP_COMPLETE) xstrncpy(pReason, nReasonSize, XHTTP_GetStatusStr(eStatus));

    if (eStatus == XHTTP_COMPLETE)
    {
        const uint8_t *pBody = XHTTP_GetBody(&handle);
        size_t nBodyLen = XHTTP_GetBodySize(&handle);

        *pCode = handle.nStatusCode;
        eResult = DirectGate_KeyManager_Classify(handle.nStatusCode, pBody, nBodyLen, pReason, nReasonSize);

        if (eResult == DIRECTGATE_KEYMGR_POLL_LEASE &&
            !DirectGate_KeyManager_ParseLease(pBody, nBodyLen, (uint64_t)time(NULL), pLease))
        {
            xstrncpy(pReason, nReasonSize, "invalid-lease");
            eResult = DIRECTGATE_KEYMGR_POLL_TRANSIENT;
        }
    }

    if (bBuilt)
    {
        /* The request was assembled in this buffer with the refresh token in it. Best effort: a reply that
           outgrew the request may already have moved the buffer, and realloc() leaves the old block as it was. */
        if (handle.rawData.pData != NULL) OPENSSL_cleanse(handle.rawData.pData, handle.rawData.nSize);
        XHTTP_Clear(&handle);
    }

    return eResult;
}

static uint32_t DirectGate_KeyManager_WorkerPoll(directgate_keymgr_worker_t *pWorker)
{
    char sApiUrl[XPATH_MAX];
    char sRefreshToken[XSTR_MIN];
    char sAppliedPolicyId[XSTR_TINY];
    char sAppliedExpiresAt[XSTR_TINY];

    XSync_Lock(&pWorker->lock);
    pWorker->bWake = XFALSE;
    uint32_t nVersion = pWorker->nInputVersion;
    xstrncpy(sApiUrl, sizeof(sApiUrl), pWorker->sApiUrl);
    xstrncpy(sRefreshToken, sizeof(sRefreshToken), pWorker->sRefreshToken);
    xstrncpy(sAppliedPolicyId, sizeof(sAppliedPolicyId), pWorker->sAppliedPolicyId);
    xstrncpy(sAppliedExpiresAt, sizeof(sAppliedExpiresAt), pWorker->sAppliedExpiresAt);
    XSync_Unlock(&pWorker->lock);

    if (!xstrused(sApiUrl) || !xstrused(sRefreshToken)) return DIRECTGATE_KEYMGR_IDLE;

    directgate_keymgr_lease_t lease;
    directgate_keymgr_poll_t eResult;
    char sReason[XSTR_TINY];
    uint32_t nNextMs;
    uint16_t nCode = 0;

    /* The lease decides who gets a shell here, so it travels under the same transport rule as pairing does. */
    if (!DirectGate_IsAPIEndpointAllowed(sApiUrl))
    {
        memset(&lease, 0, sizeof(lease));
        xstrncpy(sReason, sizeof(sReason), "api-endpoint-not-allowed");
        eResult = DIRECTGATE_KEYMGR_POLL_DENIED;
        nNextMs = DIRECTGATE_KEYMGR_IDLE;
    }
    else
    {
        eResult = DirectGate_KeyManager_Fetch(sApiUrl, sRefreshToken, sAppliedPolicyId, sAppliedExpiresAt,
            &lease, &nCode, sReason, sizeof(sReason));

        nNextMs = DirectGate_KeyManager_Jitter(eResult == DIRECTGATE_KEYMGR_POLL_LEASE ?
            DIRECTGATE_KEYMGR_POLL_MS : DIRECTGATE_KEYMGR_RETRY_MS);
    }

    OPENSSL_cleanse(sRefreshToken, sizeof(sRefreshToken));

    XSync_Lock(&pWorker->lock);
    DirectGate_KeyManager_FreeLease(&pWorker->lease);
    pWorker->lease = lease;
    pWorker->eResult = eResult;
    pWorker->nResultVersion = nVersion;
    pWorker->nResultCode = nCode;
    xstrncpy(pWorker->sResultReason, sizeof(pWorker->sResultReason), sReason);
    XSync_Unlock(&pWorker->lock);

    return nNextMs;
}

/* Returns XFALSE once the worker has to stop, XTRUE when it is time to poll. */
static xbool_t DirectGate_KeyManager_WorkerWait(directgate_keymgr_worker_t *pWorker, uint32_t nWaitMs)
{
    uint64_t nStartMs = XTime_GetMonoMs();

    for (;;)
    {
        XSync_Lock(&pWorker->lock);
        xbool_t bStop = pWorker->bStop;
        xbool_t bWake = pWorker->bWake;
        XSync_Unlock(&pWorker->lock);

        if (bStop) return XFALSE;
        if (bWake) return XTRUE;
        if (nWaitMs != DIRECTGATE_KEYMGR_IDLE && XTime_GetMonoMs() - nStartMs >= nWaitMs) return XTRUE;

        xusleep(DIRECTGATE_KEYMGR_SLICE_MS * DIRECTGATE_KEYMGR_USEC_PER_MS);
    }
}

static void DirectGate_KeyManager_FreeWorker(directgate_keymgr_worker_t *pWorker)
{
    DirectGate_KeyManager_FreeLease(&pWorker->lease);
    XSync_Destroy(&pWorker->lock);
    OPENSSL_cleanse(pWorker, sizeof(*pWorker));
    free(pWorker);
}

static void* DirectGate_KeyManager_Worker(void *pArg)
{
    directgate_keymgr_worker_t *pWorker = (directgate_keymgr_worker_t*)pArg;
    uint32_t nWaitMs = 0;

    while (DirectGate_KeyManager_WorkerWait(pWorker, nWaitMs))
        nWaitMs = DirectGate_KeyManager_WorkerPoll(pWorker);

    XSync_Lock(&pWorker->lock);
    xbool_t bOrphaned = pWorker->bOrphaned;
    pWorker->bDone = XTRUE;
    XSync_Unlock(&pWorker->lock);

    if (bOrphaned) DirectGate_KeyManager_FreeWorker(pWorker);
    return NULL;
}

static directgate_keymgr_worker_t* DirectGate_KeyManager_StartWorker(void)
{
    directgate_keymgr_worker_t *pWorker = (directgate_keymgr_worker_t*)calloc(1, sizeof(directgate_keymgr_worker_t));
    XCHECK_NL((pWorker != NULL), NULL);

    /* XSync_Init() exits the process when the mutex cannot be created, and this runs on the live event loop. */
    if (XSync_InitAdv(&pWorker->lock, XFALSE) != XSTDOK)
    {
        free(pWorker);
        return NULL;
    }

    /* Detached: nobody joins it. Stop and exit hand over through bDone and bOrphaned under the lock, which also
       covers the worker a stuck request keeps past Destroy(), whose thread would otherwise never be reaped. */
    if (XThread_Create(&pWorker->thread, DirectGate_KeyManager_Worker, pWorker, XTRUE) != XSTDOK)
    {
        XSync_Destroy(&pWorker->lock);
        free(pWorker);
        return NULL;
    }

    return pWorker;
}

static xbool_t DirectGate_KeyManager_WorkerDone(directgate_keymgr_worker_t *pWorker)
{
    XSync_Lock(&pWorker->lock);
    xbool_t bDone = pWorker->bDone;
    XSync_Unlock(&pWorker->lock);
    return bDone;
}

static void DirectGate_KeyManager_StopWorker(directgate_keymgr_worker_t *pWorker)
{
    XSync_Lock(&pWorker->lock);
    pWorker->bStop = XTRUE;
    XSync_Unlock(&pWorker->lock);

    uint64_t nDeadlineMs = XTime_GetMonoMs() + DIRECTGATE_KEYMGR_STOP_WAIT_MS;
    while (!DirectGate_KeyManager_WorkerDone(pWorker) && XTime_GetMonoMs() < nDeadlineMs)
        xusleep(DIRECTGATE_KEYMGR_STOP_POLL_MS * DIRECTGATE_KEYMGR_USEC_PER_MS);

    /* Decided under the lock, so exactly one side frees the context: here, or the worker when it returns. */
    XSync_Lock(&pWorker->lock);
    xbool_t bDone = pWorker->bDone;
    if (!bDone) pWorker->bOrphaned = XTRUE;
    XSync_Unlock(&pWorker->lock);

    if (!bDone)
    {
        xlogw("Managed-key worker is still inside a request, leaving it to exit on its own: waitMs(%u)",
            DIRECTGATE_KEYMGR_STOP_WAIT_MS);

        return;
    }

    /* The worker set bDone in its last critical section and touches nothing of the context after it. */
    DirectGate_KeyManager_FreeWorker(pWorker);
}

void DirectGate_KeyManager_Destroy(directgate_keymgr_t *pKeyMgr)
{
    XCHECK_VOID_NL((pKeyMgr != NULL));
    directgate_keymgr_worker_t *pWorker = pKeyMgr->pWorker;

    pKeyMgr->pWorker = NULL;
    pKeyMgr->bWorkerAllowed = XFALSE;

    if (pWorker != NULL) DirectGate_KeyManager_StopWorker(pWorker);
    DirectGate_KeyManager_Clear(pKeyMgr);
}

static void DirectGate_KeyManager_SetInputs(directgate_keymgr_worker_t *pWorker, const char *pApiUrl,
                                            const char *pRefreshToken, const char *pOrganizationId)
{
    /* A rotated refresh token is still the same enrollment, so what it last applied is still what it enforces. */
    if (!xstrcmp(pWorker->sApiUrl, pApiUrl) || !xstrcmp(pWorker->sOrganizationId, pOrganizationId))
    {
        pWorker->sAppliedPolicyId[0] = XSTR_NUL;
        pWorker->sAppliedExpiresAt[0] = XSTR_NUL;
    }

    OPENSSL_cleanse(pWorker->sRefreshToken, sizeof(pWorker->sRefreshToken));
    xstrncpy(pWorker->sApiUrl, sizeof(pWorker->sApiUrl), pApiUrl);
    xstrncpy(pWorker->sRefreshToken, sizeof(pWorker->sRefreshToken), pRefreshToken);
    xstrncpy(pWorker->sOrganizationId, sizeof(pWorker->sOrganizationId), pOrganizationId);

    pWorker->nInputVersion++;
    pWorker->bWake = XTRUE;
}

static void DirectGate_KeyManager_HandleResult(directgate_keymgr_t *pKeyMgr, directgate_keymgr_poll_t eResult,
                                               directgate_keymgr_lease_t *pLease, uint16_t nCode, const char *pReason,
                                               uint64_t nNowMs)
{
    directgate_keymgr_poll_t eLast = pKeyMgr->eLastPoll;
    pKeyMgr->eLastPoll = eResult;

    if (eResult == DIRECTGATE_KEYMGR_POLL_LEASE)
    {
        if (!DirectGate_KeyManager_Install(pKeyMgr, pLease, nNowMs) || pKeyMgr->pWorker == NULL) return;

        /* Tells the API what this device now enforces, on the next poll. */
        XSync_Lock(&pKeyMgr->pWorker->lock);
        xstrncpy(pKeyMgr->pWorker->sAppliedPolicyId, sizeof(pKeyMgr->pWorker->sAppliedPolicyId), pLease->sPolicyId);
        xstrncpy(pKeyMgr->pWorker->sAppliedExpiresAt, sizeof(pKeyMgr->pWorker->sAppliedExpiresAt), pLease->sExpiresAt);
        XSync_Unlock(&pKeyMgr->pWorker->lock);
        return;
    }

    if (eResult == DIRECTGATE_KEYMGR_POLL_DENIED)
    {
        if (eLast != DIRECTGATE_KEYMGR_POLL_DENIED || pKeyMgr->nDeadlineMs > 0)
        {
            xlogw("Managed-key lease refused, dropping it: org(%s), keys(%u), code(%u), reason(%s)",
                DirectGate_KeyManager_OrgName(pKeyMgr), (unsigned int)pKeyMgr->nKeyCount, (unsigned int)nCode, pReason);
        }

        if (pKeyMgr->nDeadlineMs > 0 || pKeyMgr->nKeyCount > 0) DirectGate_KeyManager_Clear(pKeyMgr);
        return;
    }

    uint64_t nRemainingMs = pKeyMgr->nDeadlineMs > nNowMs ? pKeyMgr->nDeadlineMs - nNowMs : 0;
    if (eLast != DIRECTGATE_KEYMGR_POLL_TRANSIENT)
    {
        xlogw("Managed-key lease poll failed, the current lease holds until it expires: org(%s), keys(%u), "
            "remainingMs(%" PRIu64 "), code(%u), reason(%s)", DirectGate_KeyManager_OrgName(pKeyMgr),
            (unsigned int)pKeyMgr->nKeyCount, nRemainingMs, (unsigned int)nCode, pReason);
    }
}

static void DirectGate_KeyManager_SyncWorker(directgate_keymgr_t *pKeyMgr, const directgate_cfg_t *pCfg, uint64_t nNowMs)
{
    const directgate_enroll_t *pEnroll = &pCfg->enroll;
    xbool_t bWanted = pEnroll->bEnrolled && xstrused(pEnroll->sOrganizationId) &&
        xstrused(pEnroll->sApiUrl) && xstrused(pEnroll->sRefreshToken);

    if (pKeyMgr->pWorker == NULL)
    {
        if (!bWanted || !pKeyMgr->bWorkerAllowed) return;

        pKeyMgr->pWorker = DirectGate_KeyManager_StartWorker();
        if (pKeyMgr->pWorker == NULL)
        {
            /* Not retried on every loop iteration: the agent keeps running with local keys and SRP. */
            xloge("Failed to start the managed-key lease worker: org(%s), errno(%d)", pEnroll->sOrganizationId, errno);
            pKeyMgr->bWorkerAllowed = XFALSE;
            return;
        }
    }

    directgate_keymgr_worker_t *pWorker = pKeyMgr->pWorker;
    const char *pApiUrl = bWanted ? pEnroll->sApiUrl : XSTR_EMPTY;
    const char *pRefreshToken = bWanted ? pEnroll->sRefreshToken : XSTR_EMPTY;
    const char *pOrganizationId = bWanted ? pEnroll->sOrganizationId : XSTR_EMPTY;

    directgate_keymgr_poll_t eResult = DIRECTGATE_KEYMGR_POLL_NONE;
    directgate_keymgr_lease_t lease;
    char sReason[XSTR_TINY];
    uint16_t nCode = 0;

    memset(&lease, 0, sizeof(lease));
    sReason[0] = XSTR_NUL;

    XSync_Lock(&pWorker->lock);

    if (!xstrcmp(pWorker->sApiUrl, pApiUrl) ||
        !xstrcmp(pWorker->sRefreshToken, pRefreshToken) ||
        !xstrcmp(pWorker->sOrganizationId, pOrganizationId))
        DirectGate_KeyManager_SetInputs(pWorker, pApiUrl, pRefreshToken, pOrganizationId);

    /* A result fetched with inputs that have since changed (a rotated token, another organization) is dropped
       unread; the wake above already asked for a new one. */
    if (pWorker->eResult != DIRECTGATE_KEYMGR_POLL_NONE)
    {
        if (pWorker->nResultVersion == pWorker->nInputVersion)
        {
            eResult = pWorker->eResult;
            lease = pWorker->lease;
            nCode = pWorker->nResultCode;
            xstrncpy(sReason, sizeof(sReason), pWorker->sResultReason);
            memset(&pWorker->lease, 0, sizeof(pWorker->lease));
        }

        DirectGate_KeyManager_FreeLease(&pWorker->lease);
        pWorker->eResult = DIRECTGATE_KEYMGR_POLL_NONE;
    }

    XSync_Unlock(&pWorker->lock);

    if (eResult != DIRECTGATE_KEYMGR_POLL_NONE)
        DirectGate_KeyManager_HandleResult(pKeyMgr, eResult, &lease, nCode, sReason, nNowMs);

    DirectGate_KeyManager_FreeLease(&lease);
}

void DirectGate_KeyManager_Sync(directgate_keymgr_t *pKeyMgr, const directgate_cfg_t *pCfg, uint64_t nNowMs)
{
    XCHECK_VOID_NL((pKeyMgr != NULL && pCfg != NULL));
    const char *pOrganizationId = pCfg->enroll.sOrganizationId;

    /* A lease belongs to one organization enrollment. Leaving it, being revoked out of it or re-pairing into
       another one drops it before any key-auth can see it again. */
    if (!xstrcmp(pKeyMgr->sOrganizationId, pOrganizationId))
    {
        if (pKeyMgr->nDeadlineMs > 0)
        {
            xlogi("Managed-key lease dropped, the organization enrollment changed: org(%s), keys(%u)",
                DirectGate_KeyManager_OrgName(pKeyMgr), (unsigned int)pKeyMgr->nKeyCount);
        }

        DirectGate_KeyManager_Clear(pKeyMgr);
        xstrncpy(pKeyMgr->sOrganizationId, sizeof(pKeyMgr->sOrganizationId), pOrganizationId);
        pKeyMgr->eLastPoll = DIRECTGATE_KEYMGR_POLL_NONE;
    }

    if (pKeyMgr->nDeadlineMs > 0 && nNowMs >= pKeyMgr->nDeadlineMs)
    {
        xlogw("Managed-key lease expired without a renewal: org(%s), keys(%u)",
            DirectGate_KeyManager_OrgName(pKeyMgr), (unsigned int)pKeyMgr->nKeyCount);

        DirectGate_KeyManager_Clear(pKeyMgr);
    }

    DirectGate_KeyManager_SyncWorker(pKeyMgr, pCfg, nNowMs);
}
