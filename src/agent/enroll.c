/*!
 * @file directgate-agent/src/agent/enroll.c
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

#include "includes.h"
#include "common.h"
#include "enroll.h"
#include "version.h"

#define DIRECTGATE_ENROLL_HTTP_TIMEOUT      20U     /* Receive timeout, seconds. */
#define DIRECTGATE_ENROLL_RETRY_ATTEMPTS    3U      /* Attempts for CLI-driven calls. */
#define DIRECTGATE_ENROLL_RETRY_DELAY_MS    1000U   /* Doubled after every failed attempt. */
#define DIRECTGATE_ENROLL_USEC_PER_MS       1000U

/* Refresh runs on the relay event loop, where the in-line backoff of a retry
 * would stall every live session. It gets one attempt and the caller's own
 * transient handling drives the next one. */
#define DIRECTGATE_ENROLL_ONESHOT           1U

static const char* DirectGate_Enroll_GetDeviceId(const directgate_cfg_t *pCfg)
{
    XCHECK_NL((pCfg != NULL), NULL);
    return xstrused(pCfg->sDeviceId) ? pCfg->sDeviceId : "N/A";
}

static const char* DirectGate_Enroll_GetApiUrl(const directgate_cfg_t *pCfg)
{
    XCHECK_NL((pCfg != NULL), NULL);
    return xstrused(pCfg->enroll.sApiUrl) ? pCfg->enroll.sApiUrl : "N/A";
}

static const char* DirectGate_Enroll_GetRelayUrl(const directgate_cfg_t *pCfg)
{
    XCHECK_NL((pCfg != NULL), NULL);
    return xstrused(pCfg->sRelayUrl) ? pCfg->sRelayUrl : "N/A";
}

static xbool_t DirectGate_Enroll_ValidateAPIEndpoint(const directgate_cfg_t *pCfg)
{
    XCHECK((pCfg != NULL), XFALSE);
    if (DirectGate_IsAPIEndpointAllowed(pCfg->enroll.sApiUrl)) return XTRUE;

    xloge("Invalid or unencrypted API endpoint not allowed: dev(%s), api(%s)",
        DirectGate_Enroll_GetDeviceId(pCfg), DirectGate_Enroll_GetApiUrl(pCfg));

    return XFALSE;
}

typedef struct directgate_enroll_trace_ {
    char sPeer[XHTTP_OPTION_MAX];
} directgate_enroll_trace_t;

/* XHTTP_Connect() reports the address it resolved just before it dials it.
 * Keeping that string is what makes a transport failure diagnosable after the
 * fact: the status string alone cannot separate a blackholed route from a
 * refused port or a firewall drop. */
static int DirectGate_Enroll_TraceCb(xhttp_t *pHttp, xhttp_ctx_t *pCbCtx)
{
    XCHECK_NL((pHttp != NULL && pCbCtx != NULL), XSTDOK);
    directgate_enroll_trace_t *pTrace = (directgate_enroll_trace_t*)pHttp->pUserCtx;

    XCHECK_NL((pTrace != NULL), XSTDOK);
    XCHECK_NL((pCbCtx->eStatus == XHTTP_RESOLVED), XSTDOK);
    XCHECK_NL((pCbCtx->pData != NULL), XSTDOK);

    xstrncpy(pTrace->sPeer, sizeof(pTrace->sPeer), (const char*)pCbCtx->pData);
    return XSTDOK;
}

/* Only failures that a later attempt can plausibly clear. A malformed link or
 * an unsupported protocol is a configuration fault and retrying it just delays
 * the error the operator needs to see. */
static xbool_t DirectGate_Enroll_IsTransientTransport(xhttp_status_t eStatus)
{
    switch (eStatus)
    {
        case XHTTP_ERESOLVE:
        case XHTTP_ECONNECT:
        case XHTTP_EWRITE:
        case XHTTP_EREAD:
        case XHTTP_ETIMEO:
        case XHTTP_INCOMPLETE:
            return XTRUE;
        default:
            break;
    }

    return XFALSE;
}

/*!
 * @brief Perform one enrollment API call, retrying transient transport errors.
 *
 * On return the handle is initialized and owned by the caller, which must
 * XHTTP_Clear() it on every path - including the failure paths.
 *
 * @param nAttempts Total attempts. Must be 1 on any caller that runs on the
 *                  event loop, since the backoff sleeps in-line.
 */
xbool_t DirectGate_Enroll_BuildRequest(xhttp_t *pHandle, const char *pUrl, const char *pPath)
{
    XCHECK((pHandle != NULL), XFALSE);
    XCHECK((xstrused(pUrl) && xstrused(pPath)), XFALSE);

    xlink_t link;
    XCHECK((XLink_Parse(&link, pUrl) >= 0), XFALSE);
    XCHECK((XHTTP_InitRequest(pHandle, XHTTP_POST, pPath, NULL) >= 0), XFALSE);

    /* Without a receive timeout a connection that opens and then goes silent
     * parks the caller on recv() forever, so a dropped NAT entry hangs
     * enrollment instead of failing it. */
    pHandle->nTimeout = DIRECTGATE_ENROLL_HTTP_TIMEOUT;

    /*
        XHTTP_EasyPerform() uses the link only to dial, it never synthesizes
        request headers and libxutils defaults requests to HTTP/1.0, where
        Host is optional. That combination leaves the request routable only by
        TLS SNI. Plain nginx accepts it, but a CDN or WAF edge answers 403
        before the origin is ever reached, so the header is set by hand here.

        XLink_Parse() folds the default port into sHost. Carrying that port
        into the header makes the value differ from the certificate name the
        edge matches on, so it is kept only when it is not the scheme default.
    */
    xbool_t bDefaultPort = (xstrcmp(link.sProtocol, "https") && link.nPort == 443) ||
                           (xstrcmp(link.sProtocol, "http") && link.nPort == 80);

    if (bDefaultPort) XHTTP_AddHeader(pHandle, "Host", "%s", link.sAddr);
    else XHTTP_AddHeader(pHandle, "Host", "%s:%d", link.sAddr, link.nPort);

    XHTTP_AddHeader(pHandle, "User-Agent", "directgate-agent/%s", DirectGate_GetVersionShort());
    XHTTP_AddHeader(pHandle, "Content-Type", "application/json");
    XHTTP_AddHeader(pHandle, "Accept", "application/json");

    return XTRUE;
}

static xhttp_status_t DirectGate_Enroll_Perform(xhttp_t *pHandle, directgate_enroll_trace_t *pTrace,
                                                const char *pUrl, const char *pPath, const uint8_t *pBody,
                                                size_t nBodyLen, uint32_t nAttempts)
{
    XCHECK((pHandle != NULL && pTrace != NULL), XHTTP_EINIT);

    /* Cleared before any early return, since every caller logs it afterwards. */
    xstrnul(pTrace->sPeer);
    XCHECK((xstrused(pUrl) && xstrused(pPath)), XHTTP_ELINK);

    xlink_t link;
    XCHECK((XLink_Parse(&link, pUrl) >= 0), XHTTP_ELINK);

    uint32_t nDelayMs = DIRECTGATE_ENROLL_RETRY_DELAY_MS;
    xhttp_status_t eStatus = XHTTP_EINIT;
    uint32_t nAttempt;

    for (nAttempt = 0; nAttempt < nAttempts; nAttempt++)
    {
        XCHECK((DirectGate_Enroll_BuildRequest(pHandle, pUrl, pPath)), XHTTP_EINIT);
        XHTTP_SetCallback(pHandle, DirectGate_Enroll_TraceCb, pTrace, XHTTP_STATUS);

        eStatus = XHTTP_EasyPerform(pHandle, pUrl, pBody, nBodyLen);

        if (eStatus == XHTTP_COMPLETE) break;
        if (!DirectGate_Enroll_IsTransientTransport(eStatus)) break;
        if (nAttempt + 1 >= nAttempts) break;

        xlogw("Enrollment request failed, retrying: url(%s), peer(%s), attempt(%u/%u), status(%s), delay(%ums)",
            pUrl, xstrused(pTrace->sPeer) ? pTrace->sPeer : "N/A",
            (unsigned int)(nAttempt + 1), (unsigned int)nAttempts,
            XHTTP_GetStatusStr(eStatus), (unsigned int)nDelayMs);

        /* The next attempt rebuilds the request from scratch. */
        XHTTP_Clear(pHandle);
        xusleep(nDelayMs * DIRECTGATE_ENROLL_USEC_PER_MS);
        nDelayMs *= 2;
    }

    return eStatus;
}

static void DirectGate_Enroll_SetReason(char *pReason, size_t nReasonSize, const char *pValue)
{
    xstrnul(pReason);
    XCHECK_VOID_NL((pReason != NULL));
    XCHECK_VOID_NL((nReasonSize > 0));
    XCHECK_VOID_NL((xstrused(pValue)));
    xstrncpy(pReason, nReasonSize, pValue);
}

/* Log an API error body without dumping raw bytes: a misbehaving or
   compromised endpoint could echo tokens back in the body. Only the
   documented diagnostic fields (code/message) are surfaced; unparseable
   bodies are reduced to a byte count. */
static void DirectGate_Enroll_LogErrorBody(const char *pLabel, const uint8_t *pBody, size_t nBodyLen)
{
    XCHECK_VOID_NL((xstrused(pLabel)));
    XCHECK_VOID_NL((pBody != NULL && nBodyLen > 0));

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, (const char*)pBody, nBodyLen))
    {
        XJSON_Destroy(&json);
        xloge("%s: unparseable body, bytes(%zu)", pLabel, nBodyLen);
        return;
    }

    const char *pCode = XJSON_GetString(XJSON_GetObject(json.pRootObj, "code"));
    const char *pMessage = XJSON_GetString(XJSON_GetObject(json.pRootObj, "message"));

    xloge("%s: code(%s), message(%s)", pLabel,
        xstrused(pCode) ? pCode : "N/A",
        xstrused(pMessage) ? pMessage : "N/A");

    XJSON_Destroy(&json);
}

typedef struct directgate_enroll_field_ {
    const char *pKey;
    const char *pValue;
} directgate_enroll_field_t;

/* Serializes a request body with the JSON writer instead of interpolating values into a format string. Every value
   here is operator-supplied rather than attacker-supplied, so this is about not producing a body the API can only
   reject: a device id or token carrying a quote or a backslash comes out escaped. Fields with an empty value are
   left out, which is what makes agentPub optional. Returns a malloc'd buffer the caller frees. */
static char* DirectGate_Enroll_BuildBody(const directgate_enroll_field_t *pFields, size_t nCount, size_t *pLength)
{
    XCHECK_NL((pFields != NULL && nCount > 0 && pLength != NULL), NULL);
    *pLength = 0;

    xjson_obj_t *pRoot = XJSON_NewObject(NULL, NULL, XTRUE);
    XCHECK_NL((pRoot != NULL), NULL);

    for (size_t i = 0; i < nCount; i++)
        XJSON_AddStrIfUsed(pRoot, pFields[i].pKey, pFields[i].pValue);

    char *pDump = XJSON_DumpObj(pRoot, 0, pLength);
    XJSON_FreeObject(pRoot);

    return pDump;
}

static xbool_t DirectGate_Enroll_ParseExpiry(const xjson_obj_t *pRoot, const char *pExpiresAtKey, uint64_t *pExpiry)
{
    XCHECK((pRoot != NULL), XFALSE);
    XCHECK((pExpiry != NULL), XFALSE);

    xjson_obj_t *pObj = XJSON_GetObject((xjson_obj_t*)pRoot, pExpiresAtKey);
    const char *pExpiresAt = XJSON_GetString(pObj);
    XCHECK_NL(xstrused(pExpiresAt), XFALSE);

    xtime_t expTime;
    XCHECK_NL((XTime_FromISO(&expTime, pExpiresAt) > 0), XFALSE);

    *pExpiry = XTime_ToEpochUTC(&expTime);
    return (*pExpiry > 0);
}

static void DirectGate_Enroll_LoadIceServers(directgate_cfg_t *pCfg, xjson_obj_t *pRoot)
{
    XCHECK_VOID_NL((pCfg != NULL));
    XCHECK_VOID_NL((pRoot != NULL));

    xjson_obj_t *pIce = XJSON_GetObject(pRoot, "iceServers");
    XCHECK_VOID_NL((pIce != NULL && pIce->nType == XJSON_TYPE_ARRAY));

    size_t nItems = XJSON_GetArrayLength(pIce);
    uint8_t nCount = 0;

    if (nItems > DIRECTGATE_MAX_ICE_SERVERS)
        nItems = DIRECTGATE_MAX_ICE_SERVERS;

    for (size_t i = 0; i < nItems; i++)
    {
        xjson_obj_t *pItem = XJSON_GetArrayItem(pIce, i);
        const char *pIceServer = XJSON_GetString(pItem);
        if (!xstrused(pIceServer)) continue;

        char *pDstIceServer = pCfg->sIceServers[nCount++];
        xstrncpy(pDstIceServer, DIRECTGATE_ICE_URL_SIZE, pIceServer);
    }

    if (!nCount) return;
    pCfg->nIceSrvCount = nCount;
}

static xbool_t DirectGate_Enroll_ApplyTokenResponse(directgate_cfg_t *pCfg,
                                                    const uint8_t *pBody,
                                                    size_t nBodyLen,
                                                    xbool_t bRequireRefreshToken)
{
    XCHECK((pCfg != NULL), XFALSE);
    XCHECK((pBody != NULL), XFALSE);
    XCHECK((nBodyLen > 0), XFALSE);

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, (const char*)pBody, nBodyLen))
    {
        xloge("Failed to parse enrollment API response JSON: dev(%s), api(%s), bytes(%zu)",
            DirectGate_Enroll_GetDeviceId(pCfg), DirectGate_Enroll_GetApiUrl(pCfg), nBodyLen);

        XJSON_Destroy(&json);
        return XFALSE;
    }

    xjson_obj_t *pRoot = json.pRootObj;
    directgate_enroll_t *pEnroll = &pCfg->enroll;

    char sAccessToken[XSTR_MID];
    char sRefreshToken[XSTR_MIN];
    char sRelayUrl[XPATH_MAX];
    char sRoutingKey[XSTR_MID];
    char sDeviceId[XSTR_MID];
    char sEnrollExpAt[XSTR_TINY];

    uint64_t nAccessTokenExp = 0;
    uint64_t nRefreshTokenExp = 0;
    xbool_t bRefreshRotated = XFALSE;
    xbool_t bHaveRefreshToken = XFALSE;
    xbool_t bHaveRefreshExp = XFALSE;

    sAccessToken[0] = XSTR_NUL;
    sRefreshToken[0] = XSTR_NUL;
    sRoutingKey[0] = XSTR_NUL;
    sRelayUrl[0] = XSTR_NUL;
    sDeviceId[0] = XSTR_NUL;
    sEnrollExpAt[0] = XSTR_NUL;

    const char *pAccess = XJSON_GetString(XJSON_GetObject(pRoot, "accessToken"));
    if (!xstrused(pAccess))
    {
        xloge("Enrollment API response is missing accessToken: dev(%s), api(%s)",
            DirectGate_Enroll_GetDeviceId(pCfg), DirectGate_Enroll_GetApiUrl(pCfg));

        XJSON_Destroy(&json);
        return XFALSE;
    }

    const char *pRefresh = XJSON_GetString(XJSON_GetObject(pRoot, "refreshToken"));
    if (xstrused(pRefresh))
    {
        xstrncpy(sRefreshToken, sizeof(sRefreshToken), pRefresh);
        bHaveRefreshToken = XTRUE;
    }

    xjson_obj_t *pRotated = XJSON_GetObject(pRoot, "refreshTokenRotated");
    if (pRotated != NULL) bRefreshRotated = XJSON_GetBool(pRotated);

    if (bRequireRefreshToken && !bHaveRefreshToken)
    {
        xloge("Enrollment API response is missing refreshToken: dev(%s), api(%s)",
            DirectGate_Enroll_GetDeviceId(pCfg), DirectGate_Enroll_GetApiUrl(pCfg));

        XJSON_Destroy(&json);
        return XFALSE;
    }

    uint32_t nExpiresIn = XJSON_GetU32(XJSON_GetObject(pRoot, "accessTokenExpiresIn"));
    if (nExpiresIn > 0) nAccessTokenExp = (uint64_t)time(NULL) + (uint64_t)nExpiresIn;

    if (!nAccessTokenExp)
    {
        xtime_t expTime;
        const char *pAccessExpAt = XJSON_GetString(XJSON_GetObject(pRoot, "accessTokenExpiresAt"));
        if (XTime_FromISO(&expTime, pAccessExpAt) > 0) nAccessTokenExp = XTime_ToEpochUTC(&expTime);
    }

    const char *pEnrollExpAt = XJSON_GetString(XJSON_GetObject(pRoot, "enrollmentExpiresAt"));
    if (xstrused(pEnrollExpAt)) xstrncpy(sEnrollExpAt, sizeof(sEnrollExpAt), pEnrollExpAt);

    if (!xstrused(sEnrollExpAt))
    {
        xloge("Enrollment API response is missing enrollmentExpiresAt: dev(%s), api(%s)",
            DirectGate_Enroll_GetDeviceId(pCfg), DirectGate_Enroll_GetApiUrl(pCfg));

        XJSON_Destroy(&json);
        return XFALSE;
    }

    bHaveRefreshExp = DirectGate_Enroll_ParseExpiry(pRoot, "refreshTokenExpiresAt", &nRefreshTokenExp);
    const char *pRelayUrl = XJSON_GetString(XJSON_GetObject(pRoot, "relayUrl"));
    const char *pSigUrl = XJSON_GetString(XJSON_GetObject(pRoot, "signalingUrl"));
    const char *pRoutingKey = XJSON_GetString(XJSON_GetObject(pRoot, "routingKey"));
    const char *pDeviceId = XJSON_GetString(XJSON_GetObject(pRoot, "deviceId"));

    if (!xstrused(pRoutingKey))
    {
        xloge("Enrollment API response is missing routingKey: dev(%s), api(%s)",
            DirectGate_Enroll_GetDeviceId(pCfg), DirectGate_Enroll_GetApiUrl(pCfg));

        XJSON_Destroy(&json);
        return XFALSE;
    }

    if (xstrused(pRelayUrl)) xstrncpy(sRelayUrl, sizeof(sRelayUrl), pRelayUrl);
    else if (xstrused(pSigUrl)) xstrncpy(sRelayUrl, sizeof(sRelayUrl), pSigUrl);

    if (!xstrused(sRelayUrl))
    {
        xloge("Enrollment API response is missing relayUrl: dev(%s), api(%s)",
            DirectGate_Enroll_GetDeviceId(pCfg), DirectGate_Enroll_GetApiUrl(pCfg));

        XJSON_Destroy(&json);
        return XFALSE;
    }

    if (!nAccessTokenExp || ((bRequireRefreshToken || bRefreshRotated) && !nRefreshTokenExp))
    {
        xloge("Enrollment API response is missing token expiration data: dev(%s), api(%s)",
            DirectGate_Enroll_GetDeviceId(pCfg), DirectGate_Enroll_GetApiUrl(pCfg));

        XJSON_Destroy(&json);
        return XFALSE;
    }
    else if (!bRequireRefreshToken && !bRefreshRotated && !bHaveRefreshToken && !xstrused(pEnroll->sRefreshToken))
    {
        xloge("Refresh response omitted refresh token but agent has no stored token: dev(%s), api(%s)",
            DirectGate_Enroll_GetDeviceId(pCfg), DirectGate_Enroll_GetApiUrl(pCfg));

        XJSON_Destroy(&json);
        return XFALSE;
    }

    xstrncpy(sAccessToken, sizeof(sAccessToken), pAccess);
    xstrncpy(sRoutingKey, sizeof(sRoutingKey), pRoutingKey);
    if (xstrused(pDeviceId)) xstrncpy(sDeviceId, sizeof(sDeviceId), pDeviceId);
    if (xstrused(sDeviceId)) xstrncpy(pCfg->sDeviceId, sizeof(pCfg->sDeviceId), sDeviceId);

    xstrncpy(pEnroll->sAccessToken, sizeof(pEnroll->sAccessToken), sAccessToken);
    xstrncpy(pCfg->sRelayUrl, sizeof(pCfg->sRelayUrl), sRelayUrl);
    xstrncpy(pCfg->sRoutingKey, sizeof(pCfg->sRoutingKey), sRoutingKey);
    xstrncpy(pEnroll->sEnrollExpiresAt, sizeof(pEnroll->sEnrollExpiresAt), sEnrollExpAt);
    DirectGate_Enroll_LoadIceServers(pCfg, pRoot);

    pEnroll->nAccessTokenExp = nAccessTokenExp;
    pEnroll->bEnrolled = XTRUE;

    if (bRequireRefreshToken || bRefreshRotated)
    {
        xstrncpy(pEnroll->sRefreshToken, sizeof(pEnroll->sRefreshToken), sRefreshToken);
        pEnroll->nRefreshTokenExp = nRefreshTokenExp;
    }
    else
    {
        if (bHaveRefreshToken)
        {
            xlogw("Ignoring unexpected refresh token when refreshTokenRotated=false: dev(%s), api(%s)",
                DirectGate_Enroll_GetDeviceId(pCfg), DirectGate_Enroll_GetApiUrl(pCfg));
        }

        if (bHaveRefreshExp)
        {
            xlogw("Ignoring unexpected refreshTokenExpiresAt when refreshTokenRotated=false: dev(%s), api(%s)",
                DirectGate_Enroll_GetDeviceId(pCfg), DirectGate_Enroll_GetApiUrl(pCfg));
        }
    }

    XJSON_Destroy(&json);
    return XTRUE;
}

xbool_t DirectGate_Enroll_IsEnrolled(const directgate_cfg_t *pCfg)
{
    XCHECK_NL((pCfg != NULL), XFALSE);
    XCHECK_NL((xstrused(pCfg->sRoutingKey)), XFALSE);
    XCHECK_NL((xstrused(pCfg->enroll.sRefreshToken)), XFALSE);
    return pCfg->enroll.bEnrolled;
}

xbool_t DirectGate_Enroll_ApplyPairResponse(directgate_cfg_t *pCfg, const uint8_t *pBody, size_t nBodyLen)
{
    xlogd("Applying pair response: dev(%s), api(%s), bytes(%zu)",
        DirectGate_Enroll_GetDeviceId(pCfg), DirectGate_Enroll_GetApiUrl(pCfg), nBodyLen);

    return DirectGate_Enroll_ApplyTokenResponse(pCfg, pBody, nBodyLen, XTRUE);
}

xbool_t DirectGate_Enroll_ApplyRefreshResponse(directgate_cfg_t *pCfg, const uint8_t *pBody, size_t nBodyLen)
{
    xlogd("Applying refresh response: dev(%s), api(%s), bytes(%zu)",
        DirectGate_Enroll_GetDeviceId(pCfg), DirectGate_Enroll_GetApiUrl(pCfg), nBodyLen);

    return DirectGate_Enroll_ApplyTokenResponse(pCfg, pBody, nBodyLen, XFALSE);
}

directgate_enroll_status_t DirectGate_Enroll_ClassifyRefreshFailure(const directgate_cfg_t *pCfg, uint16_t nStatusCode,
                                                            const uint8_t *pBody, size_t nBodyLen,
                                                            char *pReason, size_t nReasonSize)
{
    DirectGate_Enroll_SetReason(pReason, nReasonSize, NULL);
    XCHECK((pCfg != NULL), DIRECTGATE_ENROLL_REFRESH_TRANSIENT);
    XCHECK_NL((pBody != NULL), DIRECTGATE_ENROLL_REFRESH_TRANSIENT);
    XCHECK_NL((nBodyLen > 0), DIRECTGATE_ENROLL_REFRESH_TRANSIENT);

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, (const char*)pBody, nBodyLen))
    {
        xloge("Failed to parse refresh response JSON: dev(%s), api(%s), bytes(%zu)",
            DirectGate_Enroll_GetDeviceId(pCfg), DirectGate_Enroll_GetApiUrl(pCfg), nBodyLen);

        XJSON_Destroy(&json);
        return DIRECTGATE_ENROLL_REFRESH_TRANSIENT;
    }

    xjson_obj_t *pRoot = json.pRootObj;
    const char *pCode = XJSON_GetString(XJSON_GetObject(pRoot, "code"));
    const char *pMessage = XJSON_GetString(XJSON_GetObject(pRoot, "message"));

    if (xstrcmp(pCode, "DEVICE_ENROLLMENT_EXPIRED"))
    {
        DirectGate_Enroll_SetReason(pReason, nReasonSize, "device-enrollment-expired");
        xlogw("Enrollment expired during refresh: dev(%s), api(%s), code(%u), message(%s)",
            DirectGate_Enroll_GetDeviceId(pCfg), DirectGate_Enroll_GetApiUrl(pCfg), nStatusCode,
            xstrused(pMessage) ? pMessage : "N/A");
        XJSON_Destroy(&json);

        return DIRECTGATE_ENROLL_REFRESH_TERMINAL;
    }

    if (xstrcmp(pCode, "DEVICE_ENROLLMENT_REVOKED"))
    {
        DirectGate_Enroll_SetReason(pReason, nReasonSize, "device-revoked");
        xlogw("Enrollment revoked during refresh: dev(%s), api(%s), code(%u), message(%s)",
            DirectGate_Enroll_GetDeviceId(pCfg), DirectGate_Enroll_GetApiUrl(pCfg), nStatusCode,
            xstrused(pMessage) ? pMessage : "N/A");
        XJSON_Destroy(&json);

        return DIRECTGATE_ENROLL_REFRESH_TERMINAL;
    }

    if (xstrcmp(pCode, "REFRESH_TOKEN_REUSE_DETECTED"))
    {
        DirectGate_Enroll_SetReason(pReason, nReasonSize, "refresh-token-reuse");
        xlogw("Refresh token reuse detected: dev(%s), api(%s), code(%u), message(%s)",
            DirectGate_Enroll_GetDeviceId(pCfg), DirectGate_Enroll_GetApiUrl(pCfg), nStatusCode,
            xstrused(pMessage) ? pMessage : "N/A");
        XJSON_Destroy(&json);

        return DIRECTGATE_ENROLL_REFRESH_TERMINAL;
    }

    if (xstrcmp(pCode, "INVALID_REFRESH_TOKEN"))
    {
        DirectGate_Enroll_SetReason(pReason, nReasonSize, "invalid-refresh-token");
        xlogw("Refresh token invalidated: dev(%s), api(%s), code(%u), message(%s)",
            DirectGate_Enroll_GetDeviceId(pCfg), DirectGate_Enroll_GetApiUrl(pCfg), nStatusCode,
            xstrused(pMessage) ? pMessage : "N/A");
        XJSON_Destroy(&json);

        return DIRECTGATE_ENROLL_REFRESH_TERMINAL;
    }

    XJSON_Destroy(&json);
    return DIRECTGATE_ENROLL_REFRESH_TRANSIENT;
}

xbool_t DirectGate_Enroll_Pair(directgate_cfg_t *pCfg, const char *pPairingToken)
{
    XCHECK((pCfg != NULL), XFALSE);
    XCHECK((xstrused(pPairingToken)), XFALSE);
    XCHECK((xstrused(pCfg->sDeviceId)), XFALSE);
    XCHECK((xstrused(pCfg->enroll.sApiUrl)), XFALSE);
    XCHECK((DirectGate_Enroll_ValidateAPIEndpoint(pCfg)), XFALSE);

    char sUrl[XPATH_MAX + 64];
    snprintf(sUrl, sizeof(sUrl), "%s/api/v1/devices/pair", pCfg->enroll.sApiUrl);

    const directgate_enroll_field_t fields[] = {
        { "deviceId", pCfg->sDeviceId },
        { "pairingToken", pPairingToken },
        { "agentVersion", DirectGate_GetVersionShort() },
        { "agentPub", pCfg->keyauth.sIdentityPubB64 }
    };

    size_t nReqLen = 0;
    char *pReqBody = DirectGate_Enroll_BuildBody(fields, XARR_SIZE(fields), &nReqLen);
    XCHECK((pReqBody != NULL && nReqLen > 0), xthrowr(XFALSE, "Failed to build the pair request body"));

    xhttp_t handle;
    directgate_enroll_trace_t trace;

    /* Pairing runs from the interactive CLI, after the operator has already
     * typed the pairing token and set the auth password. A transport blip must
     * not throw that work away, and this path is not on the event loop. */
    xhttp_status_t status = DirectGate_Enroll_Perform(&handle, &trace, sUrl,
        "/api/v1/devices/pair", (const uint8_t*)pReqBody, nReqLen,
        DIRECTGATE_ENROLL_RETRY_ATTEMPTS);

    /* Carries the pairing token, so it does not linger on the heap after the request. */
    OPENSSL_cleanse(pReqBody, nReqLen);
    free(pReqBody);

    if (status != XHTTP_COMPLETE)
    {
        xloge("Pair request failed: dev(%s), url(%s), peer(%s), status(%s)",
            DirectGate_Enroll_GetDeviceId(pCfg), sUrl,
            xstrused(trace.sPeer) ? trace.sPeer : "N/A", XHTTP_GetStatusStr(status));

        XHTTP_Clear(&handle);
        return XFALSE;
    }

    if (!XHTTP_IsSuccessCode(&handle))
    {
        const uint8_t *pBody = XHTTP_GetBody(&handle);
        size_t nBodySize = XHTTP_GetBodySize(&handle);

        xloge("Pair API returned HTTP error: dev(%s), url(%s), code(%u)",
            DirectGate_Enroll_GetDeviceId(pCfg), sUrl, handle.nStatusCode);

        if (pBody && nBodySize > 0)
            DirectGate_Enroll_LogErrorBody("Pair API error", pBody, nBodySize);

        XHTTP_Clear(&handle);
        return XFALSE;
    }

    const uint8_t *pRespBody = XHTTP_GetBody(&handle);
    size_t nRespSize = XHTTP_GetBodySize(&handle);

    xbool_t bOk = DirectGate_Enroll_ApplyPairResponse(pCfg, pRespBody, nRespSize);
    XHTTP_Clear(&handle);

    if (bOk)
    {
        xlogn("Device paired successfully: dev(%s), relay(%s)",
            DirectGate_Enroll_GetDeviceId(pCfg), DirectGate_Enroll_GetRelayUrl(pCfg));

        if (!DirectGate_SaveConfig(pCfg))
        {
            xloge("Failed to save paired device config: dev(%s), cfg(%s)",
                DirectGate_Enroll_GetDeviceId(pCfg), pCfg->sCfgPath);

            return XFALSE;
        }
    }

    return bOk;
}

xbool_t DirectGate_Enroll_RotateAgentKey(directgate_cfg_t *pCfg)
{
    XCHECK((pCfg != NULL), XFALSE);
    XCHECK((xstrused(pCfg->sDeviceId)), XFALSE);
    XCHECK((xstrused(pCfg->enroll.sApiUrl)), XFALSE);
    XCHECK((xstrused(pCfg->enroll.sRefreshToken)), XFALSE);
    XCHECK((xstrused(pCfg->keyauth.sIdentityPubB64)), XFALSE);
    XCHECK((DirectGate_Enroll_ValidateAPIEndpoint(pCfg)), XFALSE);

    char sUrl[XPATH_MAX + 64];
    xstrncpyf(sUrl, sizeof(sUrl), "%s/api/v1/devices/rotate-agent-key", pCfg->enroll.sApiUrl);

    const directgate_enroll_field_t fields[] = {
        { "refreshToken", pCfg->enroll.sRefreshToken },
        { "agentPub", pCfg->keyauth.sIdentityPubB64 }
    };

    size_t nReqLen = 0;
    char *pReqBody = DirectGate_Enroll_BuildBody(fields, XARR_SIZE(fields), &nReqLen);
    XCHECK((pReqBody != NULL && nReqLen > 0), xthrowr(XFALSE, "Failed to build the key rotation request body"));

    xhttp_t handle;
    directgate_enroll_trace_t trace;

    /* Also CLI-driven, so the same in-line retry applies. */
    xhttp_status_t status = DirectGate_Enroll_Perform(&handle, &trace, sUrl,
        "/api/v1/devices/rotate-agent-key", (const uint8_t*)pReqBody, nReqLen,
        DIRECTGATE_ENROLL_RETRY_ATTEMPTS);

    OPENSSL_cleanse(pReqBody, nReqLen);
    free(pReqBody);

    if (status != XHTTP_COMPLETE)
    {
        xloge("Agent key rotation request failed: dev(%s), url(%s), peer(%s), status(%s)",
            DirectGate_Enroll_GetDeviceId(pCfg), sUrl,
            xstrused(trace.sPeer) ? trace.sPeer : "N/A", XHTTP_GetStatusStr(status));

        XHTTP_Clear(&handle);
        return XFALSE;
    }

    if (!XHTTP_IsSuccessCode(&handle))
    {
        const uint8_t *pBody = XHTTP_GetBody(&handle);
        size_t nBodySize = XHTTP_GetBodySize(&handle);

        xloge("Agent key rotation API returned HTTP error: dev(%s), url(%s), code(%u)",
            DirectGate_Enroll_GetDeviceId(pCfg), sUrl, handle.nStatusCode);

        if (pBody && nBodySize > 0)
            DirectGate_Enroll_LogErrorBody("Agent key rotation error", pBody, nBodySize);

        XHTTP_Clear(&handle);
        return XFALSE;
    }

    XHTTP_Clear(&handle);

    xlogn("Agent public key rotated: dev(%s), api(%s)",
        DirectGate_Enroll_GetDeviceId(pCfg), DirectGate_Enroll_GetApiUrl(pCfg));

    return XTRUE;
}

xbool_t DirectGate_Enroll_AccessTokenIsUsable(const directgate_cfg_t *pCfg)
{
    XCHECK((pCfg != NULL), XFALSE);
    const directgate_enroll_t *pEnroll = &pCfg->enroll;

    XCHECK_NL((pEnroll->bEnrolled), XFALSE);
    XCHECK_NL((xstrused(pEnroll->sAccessToken)), XFALSE);
    XCHECK_NL((pEnroll->nAccessTokenExp > 0), XFALSE);

    time_t tNow = time(NULL);
    XCHECK((tNow != (time_t)-1), XFALSE);

    return ((uint64_t)tNow < pEnroll->nAccessTokenExp);
}

directgate_enroll_status_t DirectGate_Enroll_Refresh(directgate_cfg_t *pCfg, char *pReason, size_t nReasonSize)
{
    XCHECK((pCfg != NULL), DIRECTGATE_ENROLL_REFRESH_TRANSIENT);
    DirectGate_Enroll_SetReason(pReason, nReasonSize, NULL);

    directgate_enroll_t *pEnroll = &pCfg->enroll;
    XCHECK((pEnroll->bEnrolled), DIRECTGATE_ENROLL_REFRESH_TERMINAL);

    XCHECK((xstrused(pCfg->sDeviceId)), DIRECTGATE_ENROLL_REFRESH_TERMINAL);
    XCHECK((xstrused(pEnroll->sApiUrl)), DIRECTGATE_ENROLL_REFRESH_TRANSIENT);
    XCHECK((xstrused(pEnroll->sRefreshToken)), DIRECTGATE_ENROLL_REFRESH_TERMINAL);
    XCHECK((DirectGate_Enroll_ValidateAPIEndpoint(pCfg)), DIRECTGATE_ENROLL_REFRESH_TRANSIENT);

    char sUrl[XPATH_MAX + 64];
    xstrncpyf(sUrl, sizeof(sUrl), "%s/api/v1/devices/refresh", pEnroll->sApiUrl);

    const directgate_enroll_field_t fields[] = {
        { "refreshToken", pEnroll->sRefreshToken },
        { "agentVersion", DirectGate_GetVersionShort() }
    };

    size_t nReqLen = 0;
    char *pReqBody = DirectGate_Enroll_BuildBody(fields, XARR_SIZE(fields), &nReqLen);
    if (pReqBody == NULL || nReqLen == 0)
    {
        free(pReqBody);
        xloge("Failed to build the token refresh request body: dev(%s)", DirectGate_Enroll_GetDeviceId(pCfg));
        return DIRECTGATE_ENROLL_REFRESH_TRANSIENT;
    }

    xhttp_t handle;
    directgate_enroll_trace_t trace;

    xhttp_status_t status = DirectGate_Enroll_Perform(&handle, &trace, sUrl,
        "/api/v1/devices/refresh", (const uint8_t*)pReqBody, nReqLen,
        DIRECTGATE_ENROLL_ONESHOT);

    /* Carries the refresh token. */
    OPENSSL_cleanse(pReqBody, nReqLen);
    free(pReqBody);

    if (status != XHTTP_COMPLETE)
    {
        xloge("Token refresh request failed: dev(%s), url(%s), peer(%s), status(%s)",
            DirectGate_Enroll_GetDeviceId(pCfg), sUrl,
            xstrused(trace.sPeer) ? trace.sPeer : "N/A", XHTTP_GetStatusStr(status));

        XHTTP_Clear(&handle);
        return DIRECTGATE_ENROLL_REFRESH_TRANSIENT;
    }

    if (!XHTTP_IsSuccessCode(&handle))
    {
        const uint8_t *pBody = XHTTP_GetBody(&handle);
        size_t nBodySize = XHTTP_GetBodySize(&handle);

        xloge("Token refresh API returned HTTP error: dev(%s), url(%s), code(%u)",
            DirectGate_Enroll_GetDeviceId(pCfg), sUrl, handle.nStatusCode);

        directgate_enroll_status_t eStatus = DirectGate_Enroll_ClassifyRefreshFailure(pCfg,
            handle.nStatusCode, (const uint8_t*)pBody, nBodySize, pReason, nReasonSize);

        if (eStatus == DIRECTGATE_ENROLL_REFRESH_TRANSIENT && pBody != NULL && nBodySize > 0)
            DirectGate_Enroll_LogErrorBody("Token refresh error", pBody, nBodySize);

        XHTTP_Clear(&handle);
        return eStatus;
    }

    const uint8_t *pRespBody = XHTTP_GetBody(&handle);
    size_t nRespSize = XHTTP_GetBodySize(&handle);

    xbool_t bOk = DirectGate_Enroll_ApplyRefreshResponse(pCfg, pRespBody, nRespSize);
    XHTTP_Clear(&handle);

    if (bOk)
    {
        xlogi("Tokens refreshed successfully: dev(%s), relay(%s)",
            DirectGate_Enroll_GetDeviceId(pCfg), DirectGate_Enroll_GetRelayUrl(pCfg));

        DirectGate_SaveConfig(pCfg);
        return DIRECTGATE_ENROLL_REFRESH_OK;
    }

    return DIRECTGATE_ENROLL_REFRESH_TRANSIENT;
}

xbool_t DirectGate_Enroll_NeedsRefresh(const directgate_cfg_t *pCfg)
{
    XCHECK((pCfg != NULL), XFALSE);
    const directgate_enroll_t *pEnroll = &pCfg->enroll;

    XCHECK_NL((pEnroll->bEnrolled), XFALSE);
    XCHECK_NL((pEnroll->nAccessTokenExp > 0), XFALSE);

    time_t tNow = time(NULL);
    XCHECK((tNow != (time_t)-1), XFALSE);

    uint64_t nNow = (uint64_t)tNow;
    if (nNow >= pEnroll->nAccessTokenExp) return XTRUE;

    uint64_t nRemaining = pEnroll->nAccessTokenExp - nNow;
    return (nRemaining <= (uint64_t)pEnroll->nRefreshSkewSec);
}
