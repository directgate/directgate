/*!
 * @file directgate-agent/src/agent/managed_keys.c
 * @brief Volatile organization-managed client-key leases.
 */

#include "includes.h"
#include "managed_keys.h"
#include "enroll.h"
#include "common.h"

#define DIRECTGATE_MANAGED_KEYS_POLL_SECONDS 60U
#define DIRECTGATE_MANAGED_KEYS_SLEEP_USEC   1000000U

static void DirectGate_ManagedKeys_ClearLocked(directgate_managed_keys_t *pKeys)
{
    OPENSSL_cleanse(pKeys->keys, sizeof(pKeys->keys));
    pKeys->nKeyCount = 0;
    pKeys->nExpiresAt = 0;
    xstrnul(pKeys->sPolicyId);
    xstrnul(pKeys->sExpiresAt);
}

void DirectGate_ManagedKeys_Init(directgate_managed_keys_t *pKeys, const directgate_cfg_t *pCfg)
{
    XCHECK_VOID((pKeys != NULL));
    memset(pKeys, 0, sizeof(*pKeys));
    XThread_Init(&pKeys->thread);
    XSync_Init(&pKeys->lock);
    DirectGate_ManagedKeys_UpdateEnrollment(pKeys, pCfg);
}

void DirectGate_ManagedKeys_UpdateEnrollment(directgate_managed_keys_t *pKeys, const directgate_cfg_t *pCfg)
{
    XCHECK_VOID((pKeys != NULL && pCfg != NULL));
    XSync_Lock(&pKeys->lock);

    if (!xstrcmp(pKeys->sOrganizationId, pCfg->enroll.sOrganizationId))
        DirectGate_ManagedKeys_ClearLocked(pKeys);

    xstrncpy(pKeys->sApiUrl, sizeof(pKeys->sApiUrl), pCfg->enroll.sApiUrl);
    xstrncpy(pKeys->sRefreshToken, sizeof(pKeys->sRefreshToken), pCfg->enroll.sRefreshToken);
    xstrncpy(pKeys->sOrganizationId, sizeof(pKeys->sOrganizationId), pCfg->enroll.sOrganizationId);
    XSync_Unlock(&pKeys->lock);
}

static xbool_t DirectGate_ManagedKeys_ShouldStop(directgate_managed_keys_t *pKeys)
{
    XSync_Lock(&pKeys->lock);
    xbool_t bStop = pKeys->bStop;
    XSync_Unlock(&pKeys->lock);
    return bStop;
}

void DirectGate_ManagedKeys_ApplyFailure(directgate_managed_keys_t *pKeys, uint64_t nNow)
{
    XCHECK_VOID((pKeys != NULL));
    XSync_Lock(&pKeys->lock);
    if (pKeys->nExpiresAt > 0 && nNow >= pKeys->nExpiresAt)
        DirectGate_ManagedKeys_ClearLocked(pKeys);
    XSync_Unlock(&pKeys->lock);
}

xbool_t DirectGate_ManagedKeys_ApplyResponse(directgate_managed_keys_t *pKeys,
                                             const uint8_t *pBody, size_t nBodyLen)
{
    XCHECK((pKeys != NULL && pBody != NULL && nBodyLen > 0), XFALSE);
    xjson_t json;
    if (!XJSON_Parse(&json, NULL, (const char*)pBody, nBodyLen))
    {
        XJSON_Destroy(&json);
        return XFALSE;
    }

    xjson_obj_t *pRoot = json.pRootObj;
    xjson_obj_t *pArray = XJSON_GetObject(pRoot, "publicKeys");
    const char *pPolicyId = XJSON_GetString(XJSON_GetObject(pRoot, "policyId"));
    const char *pExpiresAt = XJSON_GetString(XJSON_GetObject(pRoot, "expiresAt"));
    xtime_t expiry;

    if (pArray == NULL || pArray->nType != XJSON_TYPE_ARRAY ||
        !xstrused(pPolicyId) || !xstrused(pExpiresAt) ||
        XTime_FromISO(&expiry, pExpiresAt) <= 0)
    {
        XJSON_Destroy(&json);
        return XFALSE;
    }

    directgate_auth_key_t *pParsed = calloc(DIRECTGATE_MAX_MANAGED_KEYS, sizeof(*pParsed));
    if (pParsed == NULL)
    {
        XJSON_Destroy(&json);
        return XFALSE;
    }

    uint16_t nCount = 0;
    size_t nItems = XJSON_GetArrayLength(pArray);
    for (size_t i = 0; i < nItems && nCount < DIRECTGATE_MAX_MANAGED_KEYS; i++)
    {
        const char *pKey = XJSON_GetString(XJSON_GetArrayItem(pArray, i));
        if (!xstrused(pKey) || strlen(pKey) >= sizeof(*pParsed)) continue;
        xstrncpy(pParsed[nCount++], sizeof(*pParsed), pKey);
    }

    XSync_Lock(&pKeys->lock);
    if (!xstrcmp(pKeys->sOrganizationId, pPolicyId))
    {
        XSync_Unlock(&pKeys->lock);
        OPENSSL_cleanse(pParsed, DIRECTGATE_MAX_MANAGED_KEYS * sizeof(*pParsed));
        free(pParsed);
        XJSON_Destroy(&json);
        return XFALSE;
    }
    DirectGate_ManagedKeys_ClearLocked(pKeys);
    memcpy(pKeys->keys, pParsed, (size_t)nCount * sizeof(*pParsed));
    pKeys->nKeyCount = nCount;
    pKeys->nExpiresAt = XTime_ToEpochUTC(&expiry);
    xstrncpy(pKeys->sPolicyId, sizeof(pKeys->sPolicyId), pPolicyId);
    xstrncpy(pKeys->sExpiresAt, sizeof(pKeys->sExpiresAt), pExpiresAt);
    XSync_Unlock(&pKeys->lock);

    OPENSSL_cleanse(pParsed, DIRECTGATE_MAX_MANAGED_KEYS * sizeof(*pParsed));
    free(pParsed);
    XJSON_Destroy(&json);
    return XTRUE;
}

xbool_t DirectGate_ManagedKeys_IsAuthorized(directgate_managed_keys_t *pKeys,
                                            const uint8_t *pClientPubKey)
{
    XCHECK((pKeys != NULL && pClientPubKey != NULL), XFALSE);
    const char *pPtrs[DIRECTGATE_MAX_MANAGED_KEYS];
    XSync_Lock(&pKeys->lock);
    if (pKeys->nExpiresAt == 0 || (uint64_t)time(NULL) >= pKeys->nExpiresAt)
        DirectGate_ManagedKeys_ClearLocked(pKeys);
    for (uint16_t i = 0; i < pKeys->nKeyCount; i++) pPtrs[i] = pKeys->keys[i];
    xbool_t bAuthorized = DirectGate_KeyAuth_IsClientAuthorized(pClientPubKey, pPtrs, pKeys->nKeyCount);
    XSync_Unlock(&pKeys->lock);
    return bAuthorized;
}

xbool_t DirectGate_ManagedKeys_Contains(directgate_managed_keys_t *pKeys, const char *pClientPub)
{
    XCHECK((pKeys != NULL && xstrused(pClientPub)), XFALSE);
    xbool_t bFound = XFALSE;
    XSync_Lock(&pKeys->lock);
    if (pKeys->nExpiresAt == 0 || (uint64_t)time(NULL) >= pKeys->nExpiresAt)
        DirectGate_ManagedKeys_ClearLocked(pKeys);
    for (uint16_t i = 0; i < pKeys->nKeyCount; i++)
        if (xstrcmp(pKeys->keys[i], pClientPub)) { bFound = XTRUE; break; }
    XSync_Unlock(&pKeys->lock);
    return bFound;
}

static void DirectGate_ManagedKeys_Poll(directgate_managed_keys_t *pKeys)
{
    char sApiUrl[XPATH_MAX];
    char sRefreshToken[XSTR_MIN];
    char sOrganizationId[XSTR_MID];
    char sAppliedPolicyId[XSTR_MID];
    char sAppliedExpiresAt[XSTR_TINY];

    XSync_Lock(&pKeys->lock);
    xstrncpy(sApiUrl, sizeof(sApiUrl), pKeys->sApiUrl);
    xstrncpy(sRefreshToken, sizeof(sRefreshToken), pKeys->sRefreshToken);
    xstrncpy(sOrganizationId, sizeof(sOrganizationId), pKeys->sOrganizationId);
    xstrncpy(sAppliedPolicyId, sizeof(sAppliedPolicyId), pKeys->sPolicyId);
    xstrncpy(sAppliedExpiresAt, sizeof(sAppliedExpiresAt), pKeys->sExpiresAt);
    XSync_Unlock(&pKeys->lock);

    if (!xstrused(sOrganizationId) || !xstrused(sApiUrl) || !xstrused(sRefreshToken)) return;

    xjson_obj_t *pRoot = XJSON_NewObject(NULL, NULL, XTRUE);
    if (pRoot == NULL) return;
    XJSON_AddString(pRoot, "refreshToken", sRefreshToken);
    if (xstrused(sAppliedPolicyId)) XJSON_AddString(pRoot, "appliedPolicyId", sAppliedPolicyId);
    if (xstrused(sAppliedExpiresAt)) XJSON_AddString(pRoot, "appliedExpiresAt", sAppliedExpiresAt);
    size_t nBodyLen = 0;
    char *pBody = XJSON_DumpObj(pRoot, 0, &nBodyLen);
    XJSON_FreeObject(pRoot);
    if (pBody == NULL) return;

    char sUrl[XPATH_MAX + 64];
    xstrncpyf(sUrl, sizeof(sUrl), "%s/api/v1/devices/managed-keys", sApiUrl);
    xhttp_t handle;
    xbool_t bBuilt = DirectGate_Enroll_BuildRequest(&handle, sUrl, "/api/v1/devices/managed-keys");
    xhttp_status_t eStatus = bBuilt
        ? XHTTP_EasyPerform(&handle, sUrl, (const uint8_t*)pBody, nBodyLen)
        : XHTTP_EINIT;

    OPENSSL_cleanse(pBody, nBodyLen);
    free(pBody);

    xbool_t bApplied = XFALSE;
    if (eStatus == XHTTP_COMPLETE && XHTTP_IsSuccessCode(&handle))
        bApplied = DirectGate_ManagedKeys_ApplyResponse(pKeys, XHTTP_GetBody(&handle), XHTTP_GetBodySize(&handle));
    if (bBuilt) XHTTP_Clear(&handle);
    if (!bApplied) DirectGate_ManagedKeys_ApplyFailure(pKeys, (uint64_t)time(NULL));

    OPENSSL_cleanse(sRefreshToken, sizeof(sRefreshToken));
}

static void* DirectGate_ManagedKeys_Worker(void *pArg)
{
    directgate_managed_keys_t *pKeys = (directgate_managed_keys_t*)pArg;
    while (!DirectGate_ManagedKeys_ShouldStop(pKeys))
    {
        DirectGate_ManagedKeys_Poll(pKeys);
        for (uint32_t i = 0; i < DIRECTGATE_MANAGED_KEYS_POLL_SECONDS; i++)
        {
            if (DirectGate_ManagedKeys_ShouldStop(pKeys)) return NULL;
            xusleep(DIRECTGATE_MANAGED_KEYS_SLEEP_USEC);
        }
    }
    return NULL;
}

xbool_t DirectGate_ManagedKeys_Start(directgate_managed_keys_t *pKeys)
{
    XCHECK((pKeys != NULL), XFALSE);
    if (XThread_Create(&pKeys->thread, DirectGate_ManagedKeys_Worker, pKeys, XFALSE) != XSTDOK)
        return XFALSE;
    pKeys->bStarted = XTRUE;
    return XTRUE;
}

void DirectGate_ManagedKeys_Stop(directgate_managed_keys_t *pKeys)
{
    XCHECK_VOID((pKeys != NULL));
    XSync_Lock(&pKeys->lock);
    pKeys->bStop = XTRUE;
    XSync_Unlock(&pKeys->lock);
    if (pKeys->bStarted) XThread_Join(&pKeys->thread);
    XSync_Destroy(&pKeys->lock);
    OPENSSL_cleanse(pKeys, sizeof(*pKeys));
}
