/*!
 * @file directgate-agent/src/client/webapi.h
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

#ifndef __DIRECTGATE_CLIENT_WEBAPI_H__
#define __DIRECTGATE_CLIENT_WEBAPI_H__

#include "includes.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct directgate_webapi_res_ {
    xjson_t json;               /* Parsed response body, valid while bParsed */
    xjson_obj_t *pRoot;         /* Shortcut to json.pRootObj, NULL if unparsed */
    uint16_t nStatusCode;       /* HTTP status code, 0 when the call never landed */
    xbool_t bParsed;            /* Response body parsed as JSON */
    char sError[XSTR_TINY];     /* Human readable failure reason */
} directgate_webapi_res_t;

/*
 * One-shot JSON request against a control-plane endpoint.
 *
 * pBaseUrl is an origin ("https://api.directgate.io"), pPath the absolute
 * path including any query string. pBearer and pApiKey are optional and add
 * an "Authorization: Bearer" and a Supabase "apikey" header respectively.
 * pBody is sent verbatim as application/json when non-empty.
 *
 * Returns XTRUE only for a 2xx response carrying a parseable JSON body; the
 * caller owns the result either way and must always call _Clear().
 */
xbool_t DirectGate_WebApi_Request(directgate_webapi_res_t *pRes,
                                  xhttp_method_t eMethod,
                                  const char *pBaseUrl,
                                  const char *pPath,
                                  const char *pBearer,
                                  const char *pApiKey,
                                  const char *pBody);

void DirectGate_WebApi_Clear(directgate_webapi_res_t *pRes);

/*
 * Renders an API error body into one human-readable line. Nest reports
 * validation failures as an array under "message" and leaves "error" as the
 * bare status text, so reading strings only would turn a precise reason into
 * "Bad Request". Exposed because it is the CLI's only window into a refusal.
 */
size_t DirectGate_WebApi_FormatError(char *pOut, size_t nSize, xjson_obj_t *pRoot, uint16_t nStatusCode);

/* Percent-encodes everything outside the RFC 3986 unreserved set. Returns
 * the written length, or 0 when the output buffer is too small. */
size_t DirectGate_WebApi_UrlEncode(char *pOut, size_t nSize, const char *pInput);

#ifdef __cplusplus
}
#endif

#endif
