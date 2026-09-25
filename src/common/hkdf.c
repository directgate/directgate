/*!
 * @file directgate-agent/src/common/hkdf.c
 * @brief HKDF-SHA256 key derivation (RFC 5869).
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
#include "hkdf.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

xbool_t DirectGate_HKDF_Extract(const uint8_t *pSalt, size_t nSaltLen,
                                const uint8_t *pIKM, size_t nIKMLen,
                                uint8_t *pPRK)
{
    XCHECK((pIKM != NULL), XFALSE);
    XCHECK((nIKMLen > 0), XFALSE);
    XCHECK((pPRK != NULL), XFALSE);

    static const uint8_t sZeroSalt[XHKDF_SHA256_LEN] = {0};
    const uint8_t *pUseSalt = pSalt;
    size_t nUseSaltLen = nSaltLen;

    if (pUseSalt == NULL || nUseSaltLen == 0)
    {
        pUseSalt = sZeroSalt;
        nUseSaltLen = sizeof(sZeroSalt);
    }

    XCHECK((nUseSaltLen <= INT_MAX), XFALSE);
    unsigned int nOutLen = 0;

    uint8_t *pOut = HMAC(EVP_sha256(), pUseSalt, (int)nUseSaltLen,
                         pIKM, nIKMLen, pPRK, &nOutLen);

    return (pOut != NULL && nOutLen == XHKDF_SHA256_LEN) ? XTRUE : XFALSE;
}

xbool_t DirectGate_HKDF_Expand(const uint8_t *pPRK, size_t nPRKLen,
                                const char *pInfo, uint8_t *pOKM,
                                size_t nOKMLen)
{
    XCHECK((pPRK != NULL), XFALSE);
    XCHECK((nPRKLen > 0), XFALSE);
    XCHECK((nPRKLen <= INT_MAX), XFALSE);
    XCHECK((pOKM != NULL), XFALSE);
    XCHECK((nOKMLen > 0), XFALSE);

    if (nOKMLen > (size_t)(255 * XHKDF_SHA256_LEN)) return XFALSE;
    const uint8_t *pInfoBytes = (const uint8_t*)"";
    size_t nInfoLen = 0;

    if (xstrused(pInfo))
    {
        pInfoBytes = (const uint8_t*)pInfo;
        nInfoLen = strlen(pInfo);
    }

    uint8_t t[XHKDF_SHA256_LEN];
    size_t nTLen = 0;
    size_t nWritten = 0;

    const size_t nBlocks = (nOKMLen + XHKDF_SHA256_LEN - 1) / XHKDF_SHA256_LEN;

    for (size_t i = 1; i <= nBlocks; i++)
    {
        unsigned int nOutLen = 0;
        HMAC_CTX *pCtx = HMAC_CTX_new();
        if (pCtx == NULL)
        {
            OPENSSL_cleanse(t, sizeof(t));
            return XFALSE;
        }

        int nOk = HMAC_Init_ex(pCtx, pPRK, (int)nPRKLen, EVP_sha256(), NULL);
        if (nOk == 1 && nTLen > 0) nOk = HMAC_Update(pCtx, t, nTLen);
        if (nOk == 1 && nInfoLen > 0) nOk = HMAC_Update(pCtx, pInfoBytes, nInfoLen);

        const uint8_t c = (uint8_t)i;
        if (nOk == 1) nOk = HMAC_Update(pCtx, &c, 1);
        if (nOk == 1) nOk = HMAC_Final(pCtx, t, &nOutLen);
        HMAC_CTX_free(pCtx);

        if (nOk != 1 || nOutLen != XHKDF_SHA256_LEN)
        {
            OPENSSL_cleanse(t, sizeof(t));
            return XFALSE;
        }

        nTLen = (size_t)nOutLen;
        size_t nCopy = nOKMLen - nWritten;
        if (nCopy > XHKDF_SHA256_LEN) nCopy = XHKDF_SHA256_LEN;

        memcpy(pOKM + nWritten, t, nCopy);
        nWritten += nCopy;
    }

    OPENSSL_cleanse(t, sizeof(t));
    return XTRUE;
}

xbool_t DirectGate_HKDF_SHA256(const uint8_t *pSalt, size_t nSaltLen,
                                const uint8_t *pIKM, size_t nIKMLen,
                                const char *pInfo, uint8_t *pOKM,
                                size_t nOKMLen)
{
    uint8_t prk[XHKDF_SHA256_LEN];

    if (!DirectGate_HKDF_Extract(pSalt, nSaltLen, pIKM, nIKMLen, prk))
    {
        OPENSSL_cleanse(prk, sizeof(prk));
        return XFALSE;
    }

    xbool_t bOk = DirectGate_HKDF_Expand(prk, sizeof(prk), pInfo, pOKM, nOKMLen);
    OPENSSL_cleanse(prk, sizeof(prk));

    return bOk;
}
