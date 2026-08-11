/*!
 * @file directgate-agent/src/client/login.c
 * @brief Browser-based account login (Supabase OAuth 2.0 + PKCE).
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
#include "login.h"

#ifdef _WIN32
#include <shellapi.h>
#include <conio.h>
#else
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define DIRECTGATE_LOGIN_PROVIDER   "google"
#define DIRECTGATE_LOGIN_REQ_MAX    8192
#define DIRECTGATE_LOGIN_POLL_MS    200

/*
 * The loopback listener is an OAuth redirect target, not a web server: it
 * answers exactly one authorization code and shuts down. The CORS headers
 * exist only so the hosted /cli-auth bounce page can hand the code over
 * without the user copy-pasting it; "Access-Control-Allow-Private-Network"
 * is what lets a public-origin page reach a loopback address at all under
 * Chrome's private network access rules.
 */
static const char g_sCorsHeaders[] =
    "Access-Control-Allow-Origin: *\r\n"
    "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
    "Access-Control-Allow-Headers: content-type\r\n"
    "Access-Control-Allow-Private-Network: true\r\n";

static const char g_sSuccessPage[] =
    "<!doctype html><html><head><meta charset=\"utf-8\">"
    "<title>DirectGate</title><style>"
    "body{background:#0b0d10;color:#e6e8eb;font:16px/1.6 system-ui,sans-serif;"
    "display:flex;align-items:center;justify-content:center;height:100vh;margin:0}"
    "div{text-align:center}h1{font-size:20px;margin:0 0 8px}"
    "p{margin:0;color:#8b939c}</style></head><body><div>"
    "<h1>You are signed in</h1><p>Return to your terminal to continue.</p>"
    "</div></body></html>";

void DirectGate_Account_Init(directgate_account_t *pAccount)
{
    XCHECK_VOID_NL((pAccount != NULL));
    memset(pAccount, 0, sizeof(*pAccount));
}

void DirectGate_Account_Cleanse(directgate_account_t *pAccount)
{
    XCHECK_VOID_NL((pAccount != NULL));
    OPENSSL_cleanse(pAccount->sAccessToken, sizeof(pAccount->sAccessToken));
    OPENSSL_cleanse(pAccount->sRefreshToken, sizeof(pAccount->sRefreshToken));
    pAccount->sAccessToken[0] = XSTR_NUL;
    pAccount->sRefreshToken[0] = XSTR_NUL;
}

xbool_t DirectGate_Account_Load(directgate_account_t *pAccount, const char *pPath)
{
    XCHECK((pAccount != NULL), XFALSE);
    DirectGate_Account_Init(pAccount);

    XCHECK_NL((xstrused(pPath)), XFALSE);
    XCHECK_NL((XPath_Exists(pPath)), XFALSE);

    xbyte_buffer_t buffer;
    if (XPath_LoadBuffer(pPath, &buffer) <= 0)
    {
        xlogw("Failed to read account file: %s (%s)", pPath, XSTRERR);
        return XFALSE;
    }

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, (const char*)buffer.pData, buffer.nUsed))
    {
        xlogw("Account file is not valid JSON, ignoring it: %s", pPath);
        XByteBuffer_Clear(&buffer);
        XJSON_Destroy(&json);
        return XFALSE;
    }

    xjson_obj_t *pRoot = json.pRootObj;
    const char *pAccess = XJSON_GetString(XJSON_GetObject(pRoot, "accessToken"));
    const char *pRefresh = XJSON_GetString(XJSON_GetObject(pRoot, "refreshToken"));
    const char *pEmail = XJSON_GetString(XJSON_GetObject(pRoot, "email"));
    const char *pUserId = XJSON_GetString(XJSON_GetObject(pRoot, "userId"));

    if (xstrused(pAccess)) xstrncpy(pAccount->sAccessToken, sizeof(pAccount->sAccessToken), pAccess);
    if (xstrused(pRefresh)) xstrncpy(pAccount->sRefreshToken, sizeof(pAccount->sRefreshToken), pRefresh);
    if (xstrused(pEmail)) xstrncpy(pAccount->sEmail, sizeof(pAccount->sEmail), pEmail);
    if (xstrused(pUserId)) xstrncpy(pAccount->sUserId, sizeof(pAccount->sUserId), pUserId);

    xjson_obj_t *pExpires = XJSON_GetObject(pRoot, "expiresAt");
    if (pExpires != NULL) pAccount->nExpiresAt = XJSON_GetU64(pExpires);

    XByteBuffer_Clear(&buffer);
    XJSON_Destroy(&json);

    return xstrused(pAccount->sAccessToken) || xstrused(pAccount->sRefreshToken);
}

xbool_t DirectGate_Account_Save(const directgate_account_t *pAccount, const char *pPath)
{
    XCHECK((pAccount != NULL), XFALSE);
    XCHECK((xstrused(pPath)), XFALSE);

    if (!DirectGate_EnsurePrivateFileParent(pPath))
    {
        xloge("Failed to create private account directory: path(%s), errno(%d)", pPath, errno);
        return XFALSE;
    }

    xjson_obj_t *pRoot = XJSON_NewObject(NULL, NULL, 4);
    XCHECK((pRoot != NULL), xthrowr(XFALSE, "Failed to create JSON object for account"));

    if (xstrused(pAccount->sAccessToken)) XJSON_AddString(pRoot, "accessToken", pAccount->sAccessToken);
    if (xstrused(pAccount->sRefreshToken)) XJSON_AddString(pRoot, "refreshToken", pAccount->sRefreshToken);
    if (xstrused(pAccount->sEmail)) XJSON_AddString(pRoot, "email", pAccount->sEmail);
    if (xstrused(pAccount->sUserId)) XJSON_AddString(pRoot, "userId", pAccount->sUserId);
    if (pAccount->nExpiresAt) XJSON_AddU64(pRoot, "expiresAt", pAccount->nExpiresAt);

    size_t nLength = 0;
    char *pDump = XJSON_DumpObj(pRoot, 2, &nLength);
    XJSON_FreeObject(pRoot);

    if (pDump == NULL || !nLength)
    {
        free(pDump);
        return XFALSE;
    }

    xbool_t bOk = DirectGate_WritePrivateFile(pPath, (uint8_t*)pDump, nLength);

    OPENSSL_cleanse(pDump, nLength);
    free(pDump);
    return bOk;
}

xbool_t DirectGate_Account_Forget(const char *pPath)
{
    XCHECK((xstrused(pPath)), XFALSE);
    if (!XPath_Exists(pPath)) return XTRUE;
    return remove(pPath) == 0 ? XTRUE : XFALSE;
}

xbool_t DirectGate_Account_IsExpired(const directgate_account_t *pAccount, uint32_t nSkewSec)
{
    XCHECK((pAccount != NULL), XTRUE);
    if (!xstrused(pAccount->sAccessToken)) return XTRUE;

    /* An unknown expiry is treated as live: the API rejects a stale token with 401
     * and the caller refreshes then, which is cheaper than refreshing on every run. */
    if (!pAccount->nExpiresAt) return XFALSE;

    uint64_t nNow = (uint64_t)time(NULL);
    return (nNow + nSkewSec) >= pAccount->nExpiresAt ? XTRUE : XFALSE;
}

xbool_t DirectGate_Login_NewVerifier(char *pOut, size_t nSize)
{
    XCHECK((pOut != NULL && nSize > 0), XFALSE);
    pOut[0] = XSTR_NUL;

    uint8_t sEntropy[DIRECTGATE_PKCE_ENTROPY];
    XCHECK((RAND_bytes(sEntropy, (int)sizeof(sEntropy)) == 1),
        xthrowr(XFALSE, "Failed to generate PKCE verifier entropy"));

    size_t nLength = sizeof(sEntropy);
    char *pEncoded = XBase64_UrlEncrypt(sEntropy, &nLength);
    OPENSSL_cleanse(sEntropy, sizeof(sEntropy));

    XCHECK((pEncoded != NULL), XFALSE);

    xbool_t bOk = nLength < nSize;
    if (bOk) xstrncpy(pOut, nSize, pEncoded);

    OPENSSL_cleanse(pEncoded, nLength);
    free(pEncoded);
    return bOk;
}

xbool_t DirectGate_Login_Challenge(const char *pVerifier, char *pOut, size_t nSize)
{
    XCHECK((pOut != NULL && nSize > 0), XFALSE);
    pOut[0] = XSTR_NUL;
    XCHECK((xstrused(pVerifier)), XFALSE);

    uint8_t sDigest[XSHA256_DIGEST_SIZE];
    XCHECK((XSHA256_Compute(sDigest, sizeof(sDigest), (const uint8_t*)pVerifier, strlen(pVerifier)) == XSTDOK), XFALSE);

    size_t nLength = sizeof(sDigest);
    char *pEncoded = XBase64_UrlEncrypt(sDigest, &nLength);
    XCHECK((pEncoded != NULL), XFALSE);

    xbool_t bOk = nLength < nSize;
    if (bOk) xstrncpy(pOut, nSize, pEncoded);

    free(pEncoded);
    return bOk;
}


size_t DirectGate_Login_StartUrl(char *pOut, size_t nSize,
                                 const directgate_login_ctx_t *pCtx,
                                 uint16_t nPort,
                                 xbool_t bPaste,
                                 const char *pChallenge)
{
    XCHECK((pOut != NULL && nSize > 0), XSTDNON);
    pOut[0] = XSTR_NUL;

    XCHECK((pCtx != NULL), XSTDNON);
    XCHECK_NL((xstrused(pCtx->pWebUrl)), XSTDNON);
    XCHECK((xstrused(pChallenge) && nPort), XSTDNON);

    /* Only the port and the mode travel through the URL. The page rebuilds
     * redirect_to itself, so this can never be turned into an open redirect
     * that walks off with the authorization code. */
    size_t nLength = xstrncpyf(pOut, nSize,
        "%s/cli-auth/start?port=%u&mode=%s&challenge=%s",
        pCtx->pWebUrl, (unsigned)nPort, bPaste ? "paste" : "loopback", pChallenge);

    if (xstrused(pCtx->pProvider) && strcmp(pCtx->pProvider, DIRECTGATE_LOGIN_PROVIDER))
        nLength = xstrncat(pOut, nSize, "&provider=%s", pCtx->pProvider);

    return nLength;
}

/* Reads one query parameter out of a raw (still percent-encoded)
 * query string and decodes it in place into pOut. */
static xbool_t DirectGate_Login_QueryValue(const char *pQuery, const char *pKey,
                                           char *pOut, size_t nSize)
{
    XCHECK_NL((pQuery != NULL && pKey != NULL && pOut != NULL && nSize > 0), XFALSE);
    pOut[0] = XSTR_NUL;

    size_t nKeyLen = strlen(pKey);
    const char *pIt = pQuery;

    while (pIt != NULL && *pIt != '\0')
    {
        const char *pAmp = strchr(pIt, '&');
        size_t nPairLen = pAmp != NULL ? (size_t)(pAmp - pIt) : strlen(pIt);

        if (nPairLen > nKeyLen && pIt[nKeyLen] == '=' && !strncmp(pIt, pKey, nKeyLen))
        {
            const char *pValue = pIt + nKeyLen + 1;
            size_t nValueLen = nPairLen - nKeyLen - 1;
            size_t nPosit = 0;

            for (size_t i = 0; i < nValueLen && nPosit + 1 < nSize; i++)
            {
                if (pValue[i] == '%' && i + 2 < nValueLen)
                {
                    char sHex[3] = { pValue[i + 1], pValue[i + 2], '\0' };
                    char *pEnd = NULL;
                    long nByte = strtol(sHex, &pEnd, 16);

                    if (pEnd != NULL && *pEnd == '\0')
                    {
                        pOut[nPosit++] = (char)nByte;
                        i += 2;
                        continue;
                    }
                }

                pOut[nPosit++] = pValue[i] == '+' ? ' ' : pValue[i];
            }

            pOut[nPosit] = XSTR_NUL;
            return nPosit > 0 ? XTRUE : XFALSE;
        }

        pIt = pAmp != NULL ? pAmp + 1 : NULL;
    }

    return XFALSE;
}

xbool_t DirectGate_Login_ParseRequest(const char *pRequest,
                                      char *pCode, size_t nCodeSize,
                                      char *pError, size_t nErrSize)
{
    XCHECK((pCode != NULL && nCodeSize > 0), XFALSE);
    pCode[0] = XSTR_NUL;
    if (pError != NULL && nErrSize > 0) pError[0] = XSTR_NUL;

    XCHECK((xstrused(pRequest)), XFALSE);

    /* Request line: "<METHOD> <target> HTTP/1.1". The target carries the
     * code on the OAuth redirect; the bounce page posts JSON instead. */
    const char *pTarget = strchr(pRequest, ' ');
    if (pTarget == NULL) return XFALSE;
    pTarget++;

    const char *pTargetEnd = strpbrk(pTarget, " \r\n");
    if (pTargetEnd == NULL) return XFALSE;

    const char *pQuery = memchr(pTarget, '?', (size_t)(pTargetEnd - pTarget));
    if (pQuery != NULL)
    {
        char sQuery[XSTR_MID];
        size_t nQueryLen = (size_t)(pTargetEnd - pQuery) - 1;
        if (nQueryLen >= sizeof(sQuery)) nQueryLen = sizeof(sQuery) - 1;

        memcpy(sQuery, pQuery + 1, nQueryLen);
        sQuery[nQueryLen] = XSTR_NUL;

        if (DirectGate_Login_QueryValue(sQuery, "code", pCode, nCodeSize)) return XTRUE;

        char sReason[XSTR_TINY];
        if (pError != NULL && nErrSize > 0 &&
            (DirectGate_Login_QueryValue(sQuery, "error_description", sReason, sizeof(sReason)) ||
             DirectGate_Login_QueryValue(sQuery, "error", sReason, sizeof(sReason))))
            xstrncpy(pError, nErrSize, sReason);
    }

    const char *pBody = strstr(pRequest, "\r\n\r\n");
    if (pBody == NULL) pBody = strstr(pRequest, "\n\n");
    if (pBody == NULL) return XFALSE;

    pBody += (*pBody == '\r') ? 4 : 2;
    if (*pBody == '\0') return XFALSE;

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, pBody, strlen(pBody)))
    {
        XJSON_Destroy(&json);
        return XFALSE;
    }

    const char *pValue = XJSON_GetString(XJSON_GetObject(json.pRootObj, "code"));
    xbool_t bFound = xstrused(pValue) ? XTRUE : XFALSE;
    if (bFound) xstrncpy(pCode, nCodeSize, pValue);

    if (!bFound && pError != NULL && nErrSize > 0)
    {
        const char *pReason = XJSON_GetString(XJSON_GetObject(json.pRootObj, "error"));
        if (xstrused(pReason)) xstrncpy(pError, nErrSize, pReason);
    }

    XJSON_Destroy(&json);
    return bFound;
}

xbool_t DirectGate_Login_ApplyToken(directgate_account_t *pAccount, xjson_obj_t *pRoot)
{
    XCHECK((pAccount != NULL), XFALSE);
    XCHECK((pRoot != NULL), XFALSE);

    const char *pAccess = XJSON_GetString(XJSON_GetObject(pRoot, "accessToken"));
    XCHECK((xstrused(pAccess)), xthrowr(XFALSE, "Token response is missing access_token"));

    if (strlen(pAccess) >= sizeof(pAccount->sAccessToken))
        return xthrowr(XFALSE, "Access token is larger than the client buffer");

    xstrncpy(pAccount->sAccessToken, sizeof(pAccount->sAccessToken), pAccess);

    const char *pRefresh = XJSON_GetString(XJSON_GetObject(pRoot, "refreshToken"));
    if (xstrused(pRefresh)) xstrncpy(pAccount->sRefreshToken, sizeof(pAccount->sRefreshToken), pRefresh);

    /* The API normalises the provider's payload, including turning a relative
     * expiry into an absolute one, so there is a single shape to parse here. */
    xjson_obj_t *pExpiresAt = XJSON_GetObject(pRoot, "expiresAt");
    pAccount->nExpiresAt = pExpiresAt != NULL ? XJSON_GetU64(pExpiresAt) : 0;

    const char *pEmail = XJSON_GetString(XJSON_GetObject(pRoot, "email"));
    const char *pUserId = XJSON_GetString(XJSON_GetObject(pRoot, "userId"));

    if (xstrused(pEmail)) xstrncpy(pAccount->sEmail, sizeof(pAccount->sEmail), pEmail);
    if (xstrused(pUserId)) xstrncpy(pAccount->sUserId, sizeof(pAccount->sUserId), pUserId);

    return XTRUE;
}

static xbool_t DirectGate_Login_Exchange(directgate_account_t *pAccount,
                                         const directgate_login_ctx_t *pCtx,
                                         const char *pPath,
                                         const char *pBody)
{
    directgate_webapi_res_t res;
    xbool_t bOk = DirectGate_WebApi_Request(&res, XHTTP_POST, pCtx->pApiUrl, pPath, NULL, NULL, pBody);

    if (!bOk)
    {
        xloge("Token request failed: path(%s), reason(%s)", pPath, res.sError);
        DirectGate_WebApi_Clear(&res);
        return XFALSE;
    }

    bOk = DirectGate_Login_ApplyToken(pAccount, res.pRoot);
    DirectGate_WebApi_Clear(&res);
    return bOk;
}

xbool_t DirectGate_Login_Refresh(directgate_account_t *pAccount, const directgate_login_ctx_t *pCtx)
{
    XCHECK((pAccount != NULL && pCtx != NULL), XFALSE);
    XCHECK_NL((xstrused(pAccount->sRefreshToken)), XFALSE);
    XCHECK((xstrused(pCtx->pApiUrl)), XFALSE);

    char sBody[XSTR_MID + XSTR_TINY];
    xstrncpyf(sBody, sizeof(sBody), "{\"refreshToken\":\"%s\"}", pAccount->sRefreshToken);

    xbool_t bOk = DirectGate_Login_Exchange(pAccount, pCtx, "/api/v1/auth/cli/refresh", sBody);
    if (bOk) xlogi("Refreshed account session: user(%s)", pAccount->sEmail);

    OPENSSL_cleanse(sBody, sizeof(sBody));
    return bOk;
}

static xbool_t DirectGate_Login_Redeem(directgate_account_t *pAccount,
                                       const directgate_login_ctx_t *pCtx,
                                       const char *pCode,
                                       const char *pVerifier)
{
    char sBody[XSTR_MID + XSTR_TINY];
    xstrncpyf(sBody, sizeof(sBody), "{\"code\":\"%s\",\"codeVerifier\":\"%s\"}", pCode, pVerifier);

    xbool_t bOk = DirectGate_Login_Exchange(pAccount, pCtx, "/api/v1/auth/cli/token", sBody);

    OPENSSL_cleanse(sBody, sizeof(sBody));
    return bOk;
}

static XSOCKET DirectGate_Login_Listen(xsock_t *pSock, uint16_t *pPort)
{
    XCHECK((pSock != NULL && pPort != NULL), XSOCK_INVALID);

    for (uint16_t i = 0; i < DIRECTGATE_LOGIN_PORT_COUNT; i++)
    {
        uint16_t nPort = (uint16_t)(DIRECTGATE_LOGIN_PORT_FIRST + i);
        if (XSock_Create(pSock, XSOCK_TCP_SERVER, "127.0.0.1", nPort) != XSOCK_INVALID)
        {
            *pPort = nPort;
            return pSock->nFD;
        }

        XSock_Close(pSock);
    }

    xloge("Failed to bind a loopback redirect port in range %d-%d",
        DIRECTGATE_LOGIN_PORT_FIRST,
        DIRECTGATE_LOGIN_PORT_FIRST + DIRECTGATE_LOGIN_PORT_COUNT - 1);

    return XSOCK_INVALID;
}

static void DirectGate_Login_Respond(xsock_t *pPeer, const char *pMethod)
{
    char sResponse[sizeof(g_sSuccessPage) + XSTR_MIN];
    size_t nLength = 0;

    if (!strcmp(pMethod, "OPTIONS"))
    {
        nLength = xstrncpyf(sResponse, sizeof(sResponse),
            "HTTP/1.1 204 No Content\r\n%sContent-Length: 0\r\n"
            "Connection: close\r\n\r\n", g_sCorsHeaders);
    }
    else if (!strcmp(pMethod, "POST"))
    {
        static const char sBody[] = "{\"ok\":true}";

        nLength = xstrncpyf(sResponse, sizeof(sResponse),
            "HTTP/1.1 200 OK\r\n%sContent-Type: application/json\r\n"
            "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
            g_sCorsHeaders, sizeof(sBody) - 1, sBody);
    }
    else
    {
        nLength = xstrncpyf(sResponse, sizeof(sResponse),
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
            "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
            sizeof(g_sSuccessPage) - 1, g_sSuccessPage);
    }

    if (nLength > 0) XSock_Write(pPeer, sResponse, nLength);
}

/* Case-insensitive Content-Length lookup over the header block. strcasestr()
 * is a GNU extension and mingw does not have it, so the scan is done here. */
static size_t DirectGate_Login_ContentLength(const char *pRequest, const char *pBody)
{
    static const char sName[] = "content-length:";
    size_t nNameLen = sizeof(sName) - 1;

    for (const char *pIt = pRequest; pIt + nNameLen < pBody; pIt++)
    {
        if (pIt != pRequest && pIt[-1] != '\n') continue;
        if (!xstrncasecmp(pIt, sName, nNameLen)) continue;
        return (size_t)strtoul(pIt + nNameLen, NULL, 10);
    }

    return 0;
}

/* Serves a single connection. Returns XTRUE once a code has been captured,
 * XFALSE for anything the browser sends before that (CORS preflight, the
 * favicon probe, a provider error). */
static xbool_t DirectGate_Login_ServeOnce(xsock_t *pListener,
                                          char *pCode, size_t nCodeSize,
                                          char *pError, size_t nErrSize)
{
    xsock_t peer;
    if (XSock_Accept(pListener, &peer) == XSOCK_INVALID) return XFALSE;

    XSock_TimeOutR(&peer, 5, 0);

    char sRequest[DIRECTGATE_LOGIN_REQ_MAX];
    size_t nReceived = 0;

    while (nReceived + 1 < sizeof(sRequest))
    {
        int nRead = XSock_Read(&peer, sRequest + nReceived, sizeof(sRequest) - nReceived - 1);
        if (nRead <= 0) break;

        nReceived += (size_t)nRead;
        sRequest[nReceived] = XSTR_NUL;

        const char *pBody = strstr(sRequest, "\r\n\r\n");
        if (pBody == NULL) continue;
        pBody += 4;

        /*
            Headers are in. Waiting for the peer to close instead of
            honouring Content-Length would stall every keep-alive POST
            until the read timeout, which is far longer than the bounce
            page waits before giving up and falling back to manual paste.
        */
        size_t nExpect = DirectGate_Login_ContentLength(sRequest, pBody);
        if (nReceived - (size_t)(pBody - sRequest) >= nExpect) break;
    }

    if (!nReceived)
    {
        XSock_Close(&peer);
        return XFALSE;
    }

    sRequest[nReceived] = XSTR_NUL;
    char sMethod[16] = { 0 };

    for (size_t i = 0; i < sizeof(sMethod) - 1 && sRequest[i] != ' ' && sRequest[i] != '\0'; i++)
        sMethod[i] = sRequest[i];

    DirectGate_Login_Respond(&peer, sMethod);
    XSock_Close(&peer);

    if (!strcmp(sMethod, "OPTIONS")) return XFALSE;
    return DirectGate_Login_ParseRequest(sRequest, pCode, nCodeSize, pError, nErrSize);
}

#ifdef _WIN32
static xbool_t DirectGate_Login_StdinReady(void)
{
    return _kbhit() ? XTRUE : XFALSE;
}
#else
static xbool_t DirectGate_Login_StdinReady(void)
{
    struct pollfd fd;
    fd.fd = STDIN_FILENO;
    fd.events = POLLIN;
    fd.revents = 0;

    return poll(&fd, 1, 0) > 0 && (fd.revents & POLLIN) ? XTRUE : XFALSE;
}
#endif

static xbool_t DirectGate_Login_ReadPaste(char *pCode, size_t nCodeSize)
{
    char sLine[XSTR_MID];
    if (fgets(sLine, sizeof(sLine), stdin) == NULL) return XFALSE;

    size_t nLength = strlen(sLine);
    DirectGate_RemoveNewLine(sLine, &nLength);

    const char *pTrimmed = DirectGate_JumpWiteSpace(sLine);
    if (!xstrused(pTrimmed)) return XFALSE;

    xstrncpy(pCode, nCodeSize, pTrimmed);
    DirectGate_TrimStringRight(pCode);
    return xstrused(pCode) ? XTRUE : XFALSE;
}

static xbool_t DirectGate_Login_Await(xsock_t *pListener, xbool_t bAllowPaste, char *pCode, size_t nCodeSize)
{
    XCHECK((pListener != NULL && pCode != NULL), XFALSE);
    pCode[0] = XSTR_NUL;

    char sError[XSTR_TINY] = { 0 };
    time_t nDeadline = time(NULL) + DIRECTGATE_LOGIN_TIMEOUT_SEC;

    while (time(NULL) < nDeadline)
    {
        if (bAllowPaste && DirectGate_Login_StdinReady())
        {
            if (DirectGate_Login_ReadPaste(pCode, nCodeSize)) return XTRUE;

            /* Closed stdin stays readable forever; stop asking after EOF
             * and let the loopback handoff finish the flow instead. */
            if (feof(stdin)) bAllowPaste = XFALSE;
        }

#ifdef _WIN32
        WSAPOLLFD fd;
        fd.fd = pListener->nFD;
        fd.events = POLLRDNORM;
        fd.revents = 0;

        int nReady = WSAPoll(&fd, 1, DIRECTGATE_LOGIN_POLL_MS);
#else
        struct pollfd fd;
        fd.fd = pListener->nFD;
        fd.events = POLLIN;
        fd.revents = 0;

        int nReady = poll(&fd, 1, DIRECTGATE_LOGIN_POLL_MS);
#endif
        if (nReady < 0)
        {
            /* Only the termination signals are hooked while signing in, so
             * an interrupted poll means the user pressed Ctrl-C. */
            if (errno == EINTR) return xthrowr(XFALSE, "Sign-in cancelled");

            xloge("Failed to poll the loopback redirect listener: errno(%d)", errno);
            return XFALSE;
        }

        if (!nReady) continue;

        if (DirectGate_Login_ServeOnce(pListener, pCode, nCodeSize, sError, sizeof(sError)))
            return XTRUE;

        if (xstrused(sError))
        {
            xloge("Sign-in was rejected by the provider: %s", sError);
            return XFALSE;
        }
    }

    xloge("Timed out waiting for the browser sign-in to complete");
    return XFALSE;
}

static xbool_t DirectGate_Login_HasDisplay(void)
{
#if defined(_WIN32) || defined(__APPLE__)
    return XTRUE;
#else
    return (xstrused(getenv("DISPLAY")) || xstrused(getenv("WAYLAND_DISPLAY"))) ? XTRUE : XFALSE;
#endif
}

static xbool_t DirectGate_Login_OpenBrowser(const char *pUrl)
{
    XCHECK_NL((xstrused(pUrl)), XFALSE);

#ifdef _WIN32
    HINSTANCE hResult = ShellExecuteA(NULL, "open", pUrl, NULL, NULL, SW_SHOWNORMAL);
    return ((INT_PTR)hResult > 32) ? XTRUE : XFALSE;
#else
#ifdef __APPLE__
    static const char *pOpeners[] = { "open", NULL };
#else
    static const char *pOpeners[] = { "xdg-open", "gio", "sensible-browser", NULL };
#endif

    /*
        Double fork so the opener is reparented to init and never becomes a
        zombie we have to reap. execvp() is used rather than a shell so the
        URL can never be re-parsed as a command.
    */
    pid_t nPid = fork();
    if (nPid < 0) return XFALSE;

    if (!nPid)
    {
        if (fork() > 0) _exit(0);

        int nNull = open("/dev/null", O_RDWR);
        if (nNull >= 0)
        {
            dup2(nNull, STDOUT_FILENO);
            dup2(nNull, STDERR_FILENO);
            if (nNull > STDERR_FILENO) close(nNull);
        }

        for (int i = 0; pOpeners[i] != NULL; i++)
        {
            if (!strcmp(pOpeners[i], "gio")) execlp(pOpeners[i], pOpeners[i], "open", pUrl, (char*)NULL);
            else execlp(pOpeners[i], pOpeners[i], pUrl, (char*)NULL);
        }

        _exit(127);
    }

    int nStatus = 0;
    waitpid(nPid, &nStatus, 0);

    /* The intermediate child always exits 0; a failure to actually launch a
     * browser only surfaces as the user never completing the flow, which the
     * paste fallback already covers. */
    return XTRUE;
#endif
}

xbool_t DirectGate_Login_Interactive(directgate_account_t *pAccount,
                                     const directgate_login_ctx_t *pCtx)
{
    XCHECK((pAccount != NULL && pCtx != NULL), XFALSE);
    XCHECK((xstrused(pCtx->pApiUrl)), xthrowr(XFALSE, "API URL is not configured"));
    XCHECK((xstrused(pCtx->pWebUrl)), xthrowr(XFALSE, "Web URL is not configured"));

    char sVerifier[DIRECTGATE_PKCE_VERIFIER_SIZE];
    char sChallenge[DIRECTGATE_PKCE_CHALLENGE_SIZE];

    if (!DirectGate_Login_NewVerifier(sVerifier, sizeof(sVerifier)) ||
        !DirectGate_Login_Challenge(sVerifier, sChallenge, sizeof(sChallenge)))
    {
        xloge("Failed to derive the PKCE challenge");
        return XFALSE;
    }

    xsock_t listener;
    uint16_t nPort = 0;

    if (DirectGate_Login_Listen(&listener, &nPort) == XSOCK_INVALID)
    {
        OPENSSL_cleanse(sVerifier, sizeof(sVerifier));
        return XFALSE;
    }

    /*
        With a local browser the provider redirects straight back to the
        loopback listener. Headless (no display, or -B) there is nothing to
        redirect to, so the hosted bounce page becomes the redirect target:
        it hands the code to the listener when it can reach it and always
        shows it for pasting, which is what makes the flow work over SSH.
    */
    xbool_t bUseBrowser = !pCtx->bNoBrowser && DirectGate_Login_HasDisplay();

    /*
        The printed link is always our own entry point: the CLI holds no
        provider configuration, so /cli-auth/start is what knows where to
        forward the browser.
    */
    char sAuthUrl[XPATH_MAX];
    size_t nUrlLength = DirectGate_Login_StartUrl(sAuthUrl, sizeof(sAuthUrl), pCtx, nPort, !bUseBrowser, sChallenge);
    if (!nUrlLength)
    {
        xloge("Failed to build the sign-in URL");
        XSock_Close(&listener);
        OPENSSL_cleanse(sVerifier, sizeof(sVerifier));
        return XFALSE;
    }

    printf("\n  Sign in to DirectGate by opening this URL:\n\n    %s\n\n", sAuthUrl);

    if (bUseBrowser)
    {
        printf("  Opening your browser...\n");
        DirectGate_Login_OpenBrowser(sAuthUrl);
    }
    else
    {
        printf("  Then paste the code shown by the page and press Enter.\n");
    }

    printf("  Waiting for sign-in (Ctrl-C to cancel)...\n");
    fflush(stdout);

    char sCode[XSTR_MID];
    xbool_t bGotCode = DirectGate_Login_Await(&listener, !bUseBrowser, sCode, sizeof(sCode));
    XSock_Close(&listener);

    if (!bGotCode)
    {
        OPENSSL_cleanse(sVerifier, sizeof(sVerifier));
        return XFALSE;
    }

    xbool_t bOk = DirectGate_Login_Redeem(pAccount, pCtx, sCode, sVerifier);
    OPENSSL_cleanse(sCode, sizeof(sCode));
    OPENSSL_cleanse(sVerifier, sizeof(sVerifier));

    if (!bOk)
    {
        xloge("Failed to exchange the authorization code for a session");
        return XFALSE;
    }

    printf("  Signed in as %s\n\n", xstrused(pAccount->sEmail) ? pAccount->sEmail : "your account");
    return XTRUE;
}

xbool_t DirectGate_Login_Ensure(directgate_account_t *pAccount,
                                const directgate_login_ctx_t *pCtx,
                                const char *pPath,
                                xbool_t bInteractive)
{
    XCHECK((pAccount != NULL), XFALSE);
    XCHECK((pCtx != NULL), XFALSE);

    xbool_t bLoaded = DirectGate_Account_Load(pAccount, pPath);
    if (bLoaded && !DirectGate_Account_IsExpired(pAccount, DIRECTGATE_LOGIN_EXPIRY_SKEW))
        return XTRUE;

    if (bLoaded && xstrused(pAccount->sRefreshToken) && DirectGate_Login_Refresh(pAccount, pCtx))
    {
        if (!DirectGate_Account_Save(pAccount, pPath))
            xlogw("Signed in but failed to persist the session: %s", pPath);

        return XTRUE;
    }

    if (!bInteractive)
    {
        xloge("Not signed in. Run 'dgcli login' from an interactive terminal.");
        return XFALSE;
    }

    if (bLoaded) xlogn("Stored session is no longer valid, signing in again");
    if (!DirectGate_Login_Interactive(pAccount, pCtx)) return XFALSE;

    if (!DirectGate_Account_Save(pAccount, pPath))
        xlogw("Signed in but failed to persist the session: %s", pPath);

    return XTRUE;
}
