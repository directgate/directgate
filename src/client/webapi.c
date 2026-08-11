/*!
 * @file directgate-agent/src/client/webapi.c
 * @brief Shared JSON-over-HTTPS helper for the client's control-plane calls.
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
#include "version.h"
#include "common.h"
#include "webapi.h"

#define DIRECTGATE_WEBAPI_TIMEOUT   20

static const char g_sUnreserved[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";

size_t DirectGate_WebApi_UrlEncode(char *pOut, size_t nSize, const char *pInput)
{
    XCHECK((pOut != NULL && nSize > 0), XSTDNON);
    pOut[0] = XSTR_NUL;
    XCHECK_NL((pInput != NULL), XSTDNON);

    static const char sHex[] = "0123456789ABCDEF";
    size_t nPosit = 0;

    for (const unsigned char *pIt = (const unsigned char*)pInput; *pIt != '\0'; pIt++)
    {
        xbool_t bUnreserved = strchr(g_sUnreserved, (int)*pIt) != NULL ? XTRUE : XFALSE;
        size_t nNeeded = bUnreserved ? 2 : 4;

        /* Truncating a URL silently is worse than failing: leave nothing
         * behind so a caller that ignores the return value cannot send a
         * half-encoded redirect or challenge. */
        if (nPosit + nNeeded > nSize)
        {
            pOut[0] = XSTR_NUL;
            return XSTDNON;
        }

        if (bUnreserved)
        {
            pOut[nPosit++] = (char)*pIt;
            continue;
        }

        pOut[nPosit++] = '%';
        pOut[nPosit++] = sHex[(*pIt >> 4) & 0x0F];
        pOut[nPosit++] = sHex[*pIt & 0x0F];
    }

    pOut[nPosit] = XSTR_NUL;
    return nPosit;
}

void DirectGate_WebApi_Clear(directgate_webapi_res_t *pRes)
{
    XCHECK_VOID_NL((pRes != NULL));

    if (pRes->bParsed)
    {
        XJSON_Destroy(&pRes->json);
        pRes->bParsed = XFALSE;
    }

    pRes->pRoot = NULL;
}

/* Lifts the first human-usable message out of an API error body. Nest's
 * exception filter uses "message", Supabase GoTrue uses "error_description"
 * or "msg"; anything else falls back to the raw status line. */
static void DirectGate_WebApi_ReadError(directgate_webapi_res_t *pRes)
{
    static const char *pFields[] = { "message", "error_description", "msg", "error", NULL };

    for (int i = 0; pFields[i] != NULL; i++)
    {
        const char *pText = XJSON_GetString(XJSON_GetObject(pRes->pRoot, pFields[i]));
        if (!xstrused(pText)) continue;

        xstrncpy(pRes->sError, sizeof(pRes->sError), pText);
        return;
    }

    xstrncpyf(pRes->sError, sizeof(pRes->sError), "endpoint returned HTTP %u", pRes->nStatusCode);
}

xbool_t DirectGate_WebApi_Request(directgate_webapi_res_t *pRes,
                                  xhttp_method_t eMethod,
                                  const char *pBaseUrl,
                                  const char *pPath,
                                  const char *pBearer,
                                  const char *pApiKey,
                                  const char *pBody)
{
    XCHECK((pRes != NULL), XFALSE);
    memset(pRes, 0, sizeof(*pRes));
    xstrncpy(pRes->sError, sizeof(pRes->sError), "request was not attempted");

    XCHECK((xstrused(pBaseUrl) && xstrused(pPath)), XFALSE);

    if (!DirectGate_IsAPIEndpointAllowed(pBaseUrl))
    {
        xstrncpyf(pRes->sError, sizeof(pRes->sError), "invalid or unencrypted endpoint: %s", pBaseUrl);
        return XFALSE;
    }

    xlink_t link;
    if (XLink_Parse(&link, pBaseUrl) < 0)
    {
        xstrncpyf(pRes->sError, sizeof(pRes->sError), "malformed endpoint: %s", pBaseUrl);
        return XFALSE;
    }

    char sUrl[XPATH_MAX];
    xstrncpyf(sUrl, sizeof(sUrl), "%s%s", pBaseUrl, pPath);

    xhttp_t handle;
    if (XHTTP_InitRequest(&handle, eMethod, pPath, NULL) < 0)
    {
        xstrncpy(pRes->sError, sizeof(pRes->sError), "failed to initialize request");
        return XFALSE;
    }

    handle.nTimeout = DIRECTGATE_WEBAPI_TIMEOUT;

    /*
        XHTTP_EasyPerform() only uses the link for the connection, it does
        not synthesize request headers, so Host has to be set by hand or
        HTTP/1.1 servers and TLS edge routers reject the request outright.
        XLink_Parse() appends the default port to sHost; carrying that into
        the header makes the value differ from the certificate name that
        edge routers match on, so the port is only kept when it is real.
    */
    xbool_t bDefaultPort = (xstrcmp(link.sProtocol, "https") && link.nPort == 443) ||
                           (xstrcmp(link.sProtocol, "http") && link.nPort == 80);

    if (bDefaultPort) XHTTP_AddHeader(&handle, "Host", "%s", link.sAddr);
    else XHTTP_AddHeader(&handle, "Host", "%s:%d", link.sAddr, link.nPort);

    XHTTP_AddHeader(&handle, "User-Agent", "directgate-client/%s", DirectGate_GetVersionShort());
    XHTTP_AddHeader(&handle, "Accept", "application/json");

    if (xstrused(pBody)) XHTTP_AddHeader(&handle, "Content-Type", "application/json");
    if (xstrused(pApiKey)) XHTTP_AddHeader(&handle, "apikey", "%s", pApiKey);

    /* Asymmetrically signed access tokens run past a kilobyte; libxutils
     * keeps oversized header values intact, and client_webapi_smoke guards
     * that so a submodule bump cannot quietly clip credentials again. */
    if (xstrused(pBearer)) XHTTP_AddHeader(&handle, "Authorization", "Bearer %s", pBearer);

    const uint8_t *pPayload = xstrused(pBody) ? (const uint8_t*)pBody : NULL;
    size_t nPayload = pPayload != NULL ? strlen(pBody) : XSTDNON;

    xhttp_status_t status = XHTTP_EasyPerform(&handle, sUrl, pPayload, nPayload);
    if (status != XHTTP_COMPLETE)
    {
        /* Name the host: a transport failure is almost always DNS, a proxy or a
         * firewall, and none of those are diagnosable from the status string alone. */
        xstrncpyf(pRes->sError, sizeof(pRes->sError), "%s (host %s, port %d)",
            XHTTP_GetStatusStr(status), link.sAddr, link.nPort);

        XHTTP_Clear(&handle);
        return XFALSE;
    }

    pRes->nStatusCode = handle.nStatusCode;

    const uint8_t *pRespBody = XHTTP_GetBody(&handle);
    size_t nRespSize = XHTTP_GetBodySize(&handle);

    if (pRespBody != NULL && nRespSize > 0 &&
        XJSON_Parse(&pRes->json, NULL, (const char*)pRespBody, nRespSize))
    {
        pRes->bParsed = XTRUE;
        pRes->pRoot = pRes->json.pRootObj;
    }
    else
    {
        /* XJSON_Parse() populates the context even on failure */
        if (pRespBody != NULL && nRespSize > 0) XJSON_Destroy(&pRes->json);
    }

    if (!XHTTP_IsSuccessCode(&handle))
    {
        DirectGate_WebApi_ReadError(pRes);
        XHTTP_Clear(&handle);
        return XFALSE;
    }

    if (!pRes->bParsed)
    {
        xstrncpy(pRes->sError, sizeof(pRes->sError), "response body is not valid JSON");
        XHTTP_Clear(&handle);
        return XFALSE;
    }

    pRes->sError[0] = XSTR_NUL;
    XHTTP_Clear(&handle);
    return XTRUE;
}
