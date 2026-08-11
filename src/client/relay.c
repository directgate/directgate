/*!
 * @file directgate-agent/src/client/relay.c
 * @brief Relay connection envelope fetch via API.
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
#include "webapi.h"
#include "relay.h"

/*
 * One-shot relay envelope fetch via the merged session-connect endpoint.
 *
 * Replaces the legacy two-step (POST /sessions then POST /relay/connect)
 * dance with a single POST /api/v1/sessions/connect call. The API returns
 * the session id, session/device envelope, and the relay connection
 * envelope (relayUrl, browserJwt, routingKey, iceServers, exp) atomically.
 *
 * The browserJwt and routingKey it returns are what let the client open the
 * relay socket at all: the routing key becomes the "?rk=" query parameter
 * on the WebSocket handshake, exactly as the workspace UI does it.
 */
xbool_t DirectGate_Relay_FetchEnvelope(directgate_cfg_t *pCfg)
{
    XCHECK((pCfg != NULL), XFALSE);
    XCHECK((xstrused(pCfg->sApiUrl)), XFALSE);
    XCHECK((xstrused(pCfg->sApiToken)), XFALSE);
    XCHECK((xstrused(pCfg->sDeviceId)), XFALSE);

    char sBody[XSTR_MID];
    xstrncpyf(sBody, sizeof(sBody), "{\"deviceId\": \"%s\"}", pCfg->sDeviceId);

    directgate_webapi_res_t res;
    if (!DirectGate_WebApi_Request(&res, XHTTP_POST, pCfg->sApiUrl, "/api/v1/sessions/connect", pCfg->sApiToken, NULL, sBody))
    {
        xloge("Session connect failed: url(%s), reason(%s)", pCfg->sApiUrl, res.sError);
        DirectGate_WebApi_Clear(&res);
        return XFALSE;
    }

    const char *pSessionId = XJSON_GetString(XJSON_GetObject(res.pRoot, "sessionId"));
    if (!xstrused(pSessionId))
    {
        xloge("Session connect response is missing sessionId");
        DirectGate_WebApi_Clear(&res);
        return XFALSE;
    }

    xjson_obj_t *pRelay = XJSON_GetObject(res.pRoot, "relay");
    if (pRelay == NULL)
    {
        xloge("Session connect response is missing relay envelope");
        DirectGate_WebApi_Clear(&res);
        return XFALSE;
    }

    const char *pRelayUrl = XJSON_GetString(XJSON_GetObject(pRelay, "relayUrl"));
    const char *pBrowserJwt = XJSON_GetString(XJSON_GetObject(pRelay, "browserJwt"));
    const char *pRoutingKey = XJSON_GetString(XJSON_GetObject(pRelay, "routingKey"));

    if (!xstrused(pBrowserJwt))
    {
        xloge("Session connect response is missing relay.browserJwt");
        DirectGate_WebApi_Clear(&res);
        return XFALSE;
    }

    if (!xstrused(pRoutingKey))
    {
        xloge("Session connect response is missing relay.routingKey");
        DirectGate_WebApi_Clear(&res);
        return XFALSE;
    }

    xstrncpy(pCfg->sAccessToken, sizeof(pCfg->sAccessToken), pBrowserJwt);
    xstrncpy(pCfg->sRoutingKey, sizeof(pCfg->sRoutingKey), pRoutingKey);
    if (xstrused(pRelayUrl)) xstrncpy(pCfg->sSignalingUrl, sizeof(pCfg->sSignalingUrl), pRelayUrl);

    /* Load ICE servers from relay envelope if present */
    xjson_obj_t *pIce = XJSON_GetObject(pRelay, "iceServers");
    if (pIce != NULL && pIce->nType == XJSON_TYPE_ARRAY)
    {
        size_t nItems = XJSON_GetArrayLength(pIce);
        uint8_t nCount = 0;

        if (nItems > DIRECTGATE_MAX_ICE_SERVERS)
            nItems = DIRECTGATE_MAX_ICE_SERVERS;

        for (size_t i = 0; i < nItems; i++)
        {
            xjson_obj_t *pItem = XJSON_GetArrayItem(pIce, i);
            const char *pIceServer = XJSON_GetString(pItem);
            if (!xstrused(pIceServer)) continue;

            xstrncpy(pCfg->sIceServers[nCount++], DIRECTGATE_ICE_URL_SIZE, pIceServer);
        }

        if (nCount > 0) pCfg->nIceSrvCount = nCount;
    }

    xlogi("Session connect: sessionId(%s), relayUrl(%s), routingKey(%s)",
        pSessionId, pCfg->sSignalingUrl, pCfg->sRoutingKey);

    DirectGate_WebApi_Clear(&res);
    return XTRUE;
}
