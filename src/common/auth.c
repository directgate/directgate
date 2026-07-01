/*!
 * @file directgate-agent/src/common/auth.c
 * @brief SRP authentication config helpers for directgate.
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
#include "auth.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

static int DirectGate_Auth_HexNibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static xbool_t DirectGate_Auth_BytesToHex(const uint8_t *pData, size_t nLen,
                                      char *pHex, size_t nHexSize)
{
    XCHECK((pData != NULL), XFALSE);
    XCHECK((pHex != NULL), XFALSE);
    if (nHexSize < (nLen * 2 + 1)) return XFALSE;

    for (size_t i = 0; i < nLen; i++)
        sprintf(&pHex[i * 2], "%02x", pData[i]);

    pHex[nLen * 2] = '\0';
    return XTRUE;
}

xbool_t DirectGate_AuthSaltHexToBytes(const char *pSaltHex, uint8_t *pSalt, size_t nSaltSize)
{
    XCHECK((xstrused(pSaltHex)), XFALSE);
    XCHECK((pSalt != NULL), XFALSE);
    XCHECK((nSaltSize >= DIRECTGATE_SRP_SALT_SIZE), XFALSE);

    if (strlen(pSaltHex) != DIRECTGATE_AUTH_SALT_HEX_SIZE - 1)
        return XFALSE;

    for (size_t i = 0; i < DIRECTGATE_SRP_SALT_SIZE; i++)
    {
        int hi = DirectGate_Auth_HexNibble(pSaltHex[i * 2]);
        int lo = DirectGate_Auth_HexNibble(pSaltHex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return XFALSE;
        pSalt[i] = (uint8_t)((hi << 4) | lo);
    }

    return XTRUE;
}

void DirectGate_AuthInit(directgate_auth_t *pAuth)
{
    XCHECK_VOID_NL((pAuth != NULL));
    memset(pAuth, 0, sizeof(*pAuth));
}

xbool_t DirectGate_AuthIsConfigured(const directgate_auth_t *pAuth)
{
    XCHECK_NL((pAuth != NULL), XFALSE);
    XCHECK_NL((xstrused(pAuth->sSaltHex)), XFALSE);
    XCHECK_NL((xstrused(pAuth->sVerifierHex)), XFALSE);

    uint8_t salt[DIRECTGATE_SRP_SALT_SIZE];
    xbool_t bOk = DirectGate_AuthSaltHexToBytes(pAuth->sSaltHex, salt, sizeof(salt));
    OPENSSL_cleanse(salt, sizeof(salt));

    return bOk;
}

xbool_t DirectGate_AuthLoad(directgate_auth_t *pAuth, xjson_obj_t *pRoot)
{
    XCHECK((pAuth != NULL), XFALSE);
    XCHECK((pRoot != NULL), XFALSE);

    xjson_obj_t *pAuthObj = XJSON_GetObject(pRoot, "auth");
    if (pAuthObj == NULL || pAuthObj->nType != XJSON_TYPE_OBJECT) return XTRUE;

    xjson_obj_t *pSrpObj = XJSON_GetObject(pAuthObj, "srp");
    if (pSrpObj != NULL && pSrpObj->nType == XJSON_TYPE_OBJECT)
        pAuthObj = pSrpObj;

    const char *pSaltHex = XJSON_GetString(XJSON_GetObject(pAuthObj, "salt"));
    if (xstrused(pSaltHex)) xstrncpy(pAuth->sSaltHex, sizeof(pAuth->sSaltHex), pSaltHex);

    const char *pVerifierHex = XJSON_GetString(XJSON_GetObject(pAuthObj, "verifier"));
    if (xstrused(pVerifierHex)) xstrncpy(pAuth->sVerifierHex, sizeof(pAuth->sVerifierHex), pVerifierHex);

    pAuth->nSuite = XJSON_GetU32(XJSON_GetObject(pAuthObj, "suite"));
    if (xstrused(pAuth->sVerifierHex) && pAuth->nSuite < DIRECTGATE_SRP_SUITE)
        pAuth->nSuite = DIRECTGATE_SRP_SUITE;

    return XTRUE;
}

xbool_t DirectGate_AuthGenerateRecord(directgate_auth_t *pAuth, const char *pPassword)
{
    XCHECK((pAuth != NULL), XFALSE);
    XCHECK((xstrused(pPassword)), XFALSE);

    xbool_t bOk = XTRUE;
    uint8_t salt[DIRECTGATE_SRP_SALT_SIZE];
    if (RAND_bytes(salt, sizeof(salt)) != 1) return XFALSE;

    if (!DirectGate_Auth_BytesToHex(salt, sizeof(salt), pAuth->sSaltHex, sizeof(pAuth->sSaltHex)) ||
        !DirectGate_SRP_CreateVerifier(pPassword, salt, sizeof(salt),
        pAuth->sVerifierHex, sizeof(pAuth->sVerifierHex)))
    {
        pAuth->sSaltHex[0] = XSTR_NUL;
        pAuth->sVerifierHex[0] = XSTR_NUL;
        pAuth->nSuite = XSTDNON;
        bOk = XFALSE;
    }
    else pAuth->nSuite = DIRECTGATE_SRP_SUITE;

    OPENSSL_cleanse(salt, sizeof(salt));
    return bOk;
}
