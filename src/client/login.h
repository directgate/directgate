/*!
 * @file directgate-agent/src/client/login.h
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

#ifndef __DIRECTGATE_CLIENT_LOGIN_H__
#define __DIRECTGATE_CLIENT_LOGIN_H__

#include "includes.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PKCE verifier is 32 random bytes as unpadded base64url (43 chars) */
#define DIRECTGATE_PKCE_ENTROPY         32
#define DIRECTGATE_PKCE_VERIFIER_SIZE   64
#define DIRECTGATE_PKCE_CHALLENGE_SIZE  64

/* Loopback redirect ports probed in order. Keeping the range small and
 * fixed lets the set be allow-listed in the Supabase redirect config. */
#define DIRECTGATE_LOGIN_PORT_FIRST     40777
#define DIRECTGATE_LOGIN_PORT_COUNT     8

#define DIRECTGATE_LOGIN_TIMEOUT_SEC    300
#define DIRECTGATE_LOGIN_EXPIRY_SKEW    60

typedef struct directgate_account_ {
    char sAccessToken[XSTR_MID];
    char sRefreshToken[XSTR_MID];
    char sEmail[XSTR_TINY];
    char sUserId[XSTR_TINY];
    uint64_t nExpiresAt;            /* Unix seconds, 0 when unknown */
} directgate_account_t;

typedef struct directgate_login_ctx_ {
    /*
        The CLI talks to exactly two hosts and holds no identity-provider
        configuration: the API exchanges tokens on its behalf, and the web app
        forwards the browser to the provider.
    */
    const char *pApiUrl;            /* https://api.directgate.io */
    const char *pWebUrl;            /* https://directgate.io, hosts /cli-auth */
    const char *pProvider;          /* OAuth provider, defaults to "google" */
    xbool_t bNoBrowser;             /* Force the paste-the-code flow */
} directgate_login_ctx_t;

void DirectGate_Account_Init(directgate_account_t *pAccount);
void DirectGate_Account_Cleanse(directgate_account_t *pAccount);

xbool_t DirectGate_Account_Load(directgate_account_t *pAccount, const char *pPath);
xbool_t DirectGate_Account_Save(const directgate_account_t *pAccount, const char *pPath);
xbool_t DirectGate_Account_Forget(const char *pPath);
xbool_t DirectGate_Account_IsExpired(const directgate_account_t *pAccount, uint32_t nSkewSec);

/*
 * Returns a usable access token in pAccount, running as little of the flow
 * as possible: a live token is used as-is, an expired one is refreshed, and
 * only a missing or unrefreshable session opens the browser. Persists to
 * pPath whenever the tokens change. With bInteractive false it fails instead
 * of prompting, which is what non-TTY invocations want.
 */
xbool_t DirectGate_Login_Ensure(directgate_account_t *pAccount,
                                const directgate_login_ctx_t *pCtx,
                                const char *pPath,
                                xbool_t bInteractive);

xbool_t DirectGate_Login_Interactive(directgate_account_t *pAccount,
                                     const directgate_login_ctx_t *pCtx);

xbool_t DirectGate_Login_Refresh(directgate_account_t *pAccount,
                                 const directgate_login_ctx_t *pCtx);

xbool_t DirectGate_Login_NewVerifier(char *pOut, size_t nSize);
xbool_t DirectGate_Login_Challenge(const char *pVerifier, char *pOut, size_t nSize);


/*
 * The URL actually shown to the user: our own /cli-auth/start, which rebuilds
 * the redirect target and forwards to the provider. The CLI has to print its
 * sign-in URL rather than navigate to it like the web app does, so the raw
 * auth-provider host would otherwise be what people are asked to trust.
 */
size_t DirectGate_Login_StartUrl(char *pOut, size_t nSize,
                                 const directgate_login_ctx_t *pCtx,
                                 uint16_t nPort,
                                 xbool_t bPaste,
                                 const char *pChallenge);

/* Pulls the authorization code out of a loopback HTTP request (either the
 * OAuth redirect "GET /callback?code=..." or the bounce page's JSON POST).
 * Populates pError instead when the provider reported a failure. */
xbool_t DirectGate_Login_ParseRequest(const char *pRequest,
                                      char *pCode, size_t nCodeSize,
                                      char *pError, size_t nErrSize);

/* Applies a GoTrue token response (access_token / refresh_token / user) */
xbool_t DirectGate_Login_ApplyToken(directgate_account_t *pAccount, xjson_obj_t *pRoot);

#ifdef __cplusplus
}
#endif

#endif
