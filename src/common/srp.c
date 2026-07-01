/*!
 * @file directgate-agent/src/common/srp.c
 * @brief SRP-6a server-side implementation helpers.
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
#include "srp.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/srp.h>

#define DIRECTGATE_SRP_SCRYPT_N 16384u
#define DIRECTGATE_SRP_SCRYPT_R 8u
#define DIRECTGATE_SRP_SCRYPT_P 1u

static int DirectGate_SRP_HexNibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

const char *DirectGate_SRP_StateName(directgate_srp_state_t eState)
{
    switch (eState)
    {
        case DIRECTGATE_SRP_STATE_IDLE: return "IDLE";
        case DIRECTGATE_SRP_STATE_CHALLENGE_SENT: return "CHALLENGE_SENT";
        case DIRECTGATE_SRP_STATE_AUTHENTICATED: return "AUTHENTICATED";
        case DIRECTGATE_SRP_STATE_FAILED: return "FAILED";
        default: return "UNKNOWN";
    }
}

xbool_t DirectGate_SRP_HexToBytes(const char *pHex, uint8_t *pOut,
                                  size_t nOutSize, size_t *pOutLen)
{
    XCHECK((pHex != NULL), XFALSE);
    XCHECK((pOut != NULL), XFALSE);

    size_t nHexLen = strnlen(pHex, nOutSize * 2 + 1);
    if (!nHexLen || (nHexLen & 1U)) return XFALSE;

    size_t nLen = nHexLen / 2;
    if (nLen > nOutSize) return XFALSE;

    for (size_t i = 0; i < nLen; i++)
    {
        int hi = DirectGate_SRP_HexNibble(pHex[i * 2]);
        int lo = DirectGate_SRP_HexNibble(pHex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return XFALSE;
        pOut[i] = (uint8_t)((hi << 4) | lo);
    }

    if (pOutLen != NULL) *pOutLen = nLen;
    return XTRUE;
}

static xbool_t DirectGate_SRP_BytesToHex(const uint8_t *pData, size_t nLen,
                                         char *pHex, size_t nHexSize)
{
    XCHECK((pData != NULL), XFALSE);
    XCHECK((pHex != NULL), XFALSE);

    size_t nRequiredSize = nLen * 2 + 1;
    if (nHexSize < nRequiredSize) return XFALSE;

    for (size_t i = 0; i < nLen; i++)
        sprintf(&pHex[i * 2], "%02x", pData[i]);

    pHex[nLen * 2] = '\0';
    return XTRUE;
}

static size_t DirectGate_SRP_GroupBytes(const directgate_srp_t *pSRP)
{
    XCHECK_NL((pSRP != NULL), 0);
    XCHECK_NL((pSRP->N != NULL), 0);
    return (size_t)BN_num_bytes(pSRP->N);
}

static xbool_t DirectGate_SRP_BNToPadded(const directgate_srp_t *pSRP, const BIGNUM *pBN,
                                         uint8_t *pOut, size_t nOut)
{
    XCHECK((pSRP != NULL), XFALSE);
    XCHECK((pBN != NULL), XFALSE);
    XCHECK((pOut != NULL), XFALSE);

    size_t nBytes = DirectGate_SRP_GroupBytes(pSRP);
    if (nOut < nBytes) return XFALSE;

    return BN_bn2binpad(pBN, pOut, (int)nBytes) == (int)nBytes ? XTRUE : XFALSE;
}

static xbool_t DirectGate_SRP_ComputeKParam(directgate_srp_t *pSRP)
{
    XCHECK((pSRP != NULL), XFALSE);
    XCHECK((pSRP->N != NULL), XFALSE);
    XCHECK((pSRP->g != NULL), XFALSE);

    size_t nBytes = DirectGate_SRP_GroupBytes(pSRP);
    XCHECK((nBytes > 0), XFALSE);

    uint8_t *pBuf = (uint8_t*)malloc(nBytes * 2);
    XCHECK(pBuf, XFALSE);

    if (!DirectGate_SRP_BNToPadded(pSRP, pSRP->N, pBuf, nBytes * 2))
    {
        OPENSSL_cleanse(pBuf, nBytes * 2);
        free(pBuf);
        return XFALSE;
    }

    if (!DirectGate_SRP_BNToPadded(pSRP, pSRP->g, pBuf + nBytes, nBytes * 2 - nBytes))
    {
        OPENSSL_cleanse(pBuf, nBytes * 2);
        free(pBuf);
        return XFALSE;
    }

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(pBuf, nBytes * 2, hash);

    BN_free(pSRP->k);
    pSRP->k = BN_bin2bn(hash, sizeof(hash), NULL);
    xbool_t bOk = (pSRP->k != NULL);

    OPENSSL_cleanse(hash, sizeof(hash));
    OPENSSL_cleanse(pBuf, nBytes * 2);
    free(pBuf);

    return bOk;
}

static xbool_t DirectGate_SRP_ComputeU(const directgate_srp_t *pSRP, const BIGNUM *pA,
                                       const BIGNUM *pB, BIGNUM **ppU)
{
    XCHECK((pSRP != NULL), XFALSE);
    XCHECK((pA != NULL), XFALSE);
    XCHECK((pB != NULL), XFALSE);
    XCHECK((ppU != NULL), XFALSE);

    size_t nBytes = DirectGate_SRP_GroupBytes(pSRP);
    uint8_t *pBuf = (uint8_t*)malloc(nBytes * 2);
    XCHECK(pBuf, XFALSE);

    if (!DirectGate_SRP_BNToPadded(pSRP, pA, pBuf, nBytes * 2))
    {
        OPENSSL_cleanse(pBuf, nBytes * 2);
        free(pBuf);
        return XFALSE;
    }

    if (!DirectGate_SRP_BNToPadded(pSRP, pB, pBuf + nBytes, nBytes * 2 - nBytes))
    {
        OPENSSL_cleanse(pBuf, nBytes * 2);
        free(pBuf);
        return XFALSE;
    }

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(pBuf, nBytes * 2, hash);

    *ppU = BN_bin2bn(hash, sizeof(hash), NULL);
    xbool_t bOk = (*ppU != NULL);

    OPENSSL_cleanse(hash, sizeof(hash));
    OPENSSL_cleanse(pBuf, nBytes * 2);
    free(pBuf);

    return bOk;
}

static xbool_t DirectGate_SRP_ComputeM1(const directgate_srp_t *pSRP,
                                        const uint8_t *pAPad,
                                        const uint8_t *pBPad,
                                        uint8_t *pOut)
{
    XCHECK((pSRP != NULL), XFALSE);
    XCHECK((pAPad != NULL), XFALSE);
    XCHECK((pBPad != NULL), XFALSE);
    XCHECK((pOut != NULL), XFALSE);

    size_t nBytes = DirectGate_SRP_GroupBytes(pSRP);
    uint8_t nPad[512];
    uint8_t gPad[512];

    if (nBytes == 0 || nBytes > sizeof(nPad)) return XFALSE;
    if (!DirectGate_SRP_BNToPadded(pSRP, pSRP->N, nPad, sizeof(nPad))) return XFALSE;
    if (!DirectGate_SRP_BNToPadded(pSRP, pSRP->g, gPad, sizeof(gPad))) return XFALSE;

    uint8_t hN[SHA256_DIGEST_LENGTH];
    uint8_t hG[SHA256_DIGEST_LENGTH];
    uint8_t hI[SHA256_DIGEST_LENGTH];
    uint8_t hXor[SHA256_DIGEST_LENGTH];

    SHA256(nPad, nBytes, hN);
    SHA256(gPad, nBytes, hG);
    SHA256((const uint8_t*)pSRP->sDeviceId, strlen(pSRP->sDeviceId), hI);

    for (size_t i = 0; i < sizeof(hXor); i++)
        hXor[i] = hN[i] ^ hG[i];

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, hXor, sizeof(hXor));
    SHA256_Update(&ctx, hI, sizeof(hI));
    SHA256_Update(&ctx, pSRP->salt, sizeof(pSRP->salt));
    SHA256_Update(&ctx, pAPad, nBytes);
    SHA256_Update(&ctx, pBPad, nBytes);
    SHA256_Update(&ctx, pSRP->nonce, sizeof(pSRP->nonce));
    SHA256_Update(&ctx, pSRP->clientNonce, sizeof(pSRP->clientNonce));
    SHA256_Update(&ctx, pSRP->K, sizeof(pSRP->K));
    SHA256_Final(pOut, &ctx);

    OPENSSL_cleanse(&ctx, sizeof(ctx));
    OPENSSL_cleanse(hN, sizeof(hN));
    OPENSSL_cleanse(hG, sizeof(hG));
    OPENSSL_cleanse(hI, sizeof(hI));
    OPENSSL_cleanse(hXor, sizeof(hXor));

    return XTRUE;
}

static xbool_t DirectGate_SRP_ComputeM2(const directgate_srp_t *pSRP,
                                        const uint8_t *pAPad,
                                        const uint8_t *pM1,
                                        uint8_t *pOut)
{
    XCHECK((pSRP != NULL), XFALSE);
    XCHECK((pAPad != NULL), XFALSE);
    XCHECK((pM1 != NULL), XFALSE);
    XCHECK((pOut != NULL), XFALSE);

    size_t nBytes = DirectGate_SRP_GroupBytes(pSRP);
    XCHECK((nBytes > 0), XFALSE);

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, pAPad, nBytes);
    SHA256_Update(&ctx, pM1, SHA256_DIGEST_LENGTH);
    SHA256_Update(&ctx, pSRP->K, sizeof(pSRP->K));
    SHA256_Final(pOut, &ctx);

    OPENSSL_cleanse(&ctx, sizeof(ctx));
    return XTRUE;
}

static xbool_t DirectGate_SRP_DeriveKFromS(const directgate_srp_t *pSRP, const BIGNUM *pS, uint8_t *pK)
{
    XCHECK((pSRP != NULL), XFALSE);
    XCHECK((pS != NULL), XFALSE);
    XCHECK((pK != NULL), XFALSE);

    size_t nBytes = DirectGate_SRP_GroupBytes(pSRP);
    uint8_t sPad[512];

    if (nBytes == 0 || nBytes > sizeof(sPad)) return XFALSE;

    if (!DirectGate_SRP_BNToPadded(pSRP, pS, sPad, sizeof(sPad))) return XFALSE;

    SHA256(sPad, nBytes, pK);
    OPENSSL_cleanse(sPad, sizeof(sPad));

    return XTRUE;
}

xbool_t DirectGate_SRP_Init(directgate_srp_t *pSRP)
{
    XCHECK((pSRP != NULL), XFALSE);
    memset(pSRP, 0, sizeof(*pSRP));
    pSRP->eState = DIRECTGATE_SRP_STATE_IDLE;

    const SRP_gN *pGroup = SRP_get_default_gN("2048");
    XCHECK((pGroup != NULL), XFALSE);

    pSRP->N = BN_dup(pGroup->N);
    pSRP->g = BN_dup(pGroup->g);

    XCHECK_CALL((pSRP->N != NULL), DirectGate_SRP_Destroy, pSRP, XFALSE);
    XCHECK_CALL((pSRP->g != NULL), DirectGate_SRP_Destroy, pSRP, XFALSE);

    XCHECK_CALL((DirectGate_SRP_ComputeKParam(pSRP) == XTRUE),
        DirectGate_SRP_Destroy, pSRP, xthrowr(XFALSE, "SRP initialization failed"));

    return XTRUE;
}

void DirectGate_SRP_Destroy(directgate_srp_t *pSRP)
{
    XCHECK_VOID_NL((pSRP != NULL));

    BN_free(pSRP->N);
    BN_free(pSRP->g);
    BN_free(pSRP->k);

    BN_free(pSRP->v);
    BN_free(pSRP->b);
    BN_free(pSRP->B);
    BN_free(pSRP->A);

    OPENSSL_cleanse(pSRP->salt, sizeof(pSRP->salt));
    OPENSSL_cleanse(pSRP->nonce, sizeof(pSRP->nonce));
    OPENSSL_cleanse(pSRP->clientNonce, sizeof(pSRP->clientNonce));
    OPENSSL_cleanse(pSRP->K, sizeof(pSRP->K));
    OPENSSL_cleanse(pSRP->sDeviceId, sizeof(pSRP->sDeviceId));

    memset(pSRP, 0, sizeof(*pSRP));
    pSRP->eState = DIRECTGATE_SRP_STATE_IDLE;
}

xbool_t DirectGate_SRP_LoadVerifier(directgate_srp_t *pSRP,
                                    const uint8_t *pSalt,
                                    const size_t nSaltLen,
                                    const char *pVerifierHex)
{
    XCHECK((pSRP != NULL), XFALSE);
    XCHECK((pSRP->N != NULL), XFALSE);
    XCHECK((pSRP->g != NULL), XFALSE);
    XCHECK((pSRP->k != NULL), XFALSE);
    XCHECK((pSalt != NULL), XFALSE);
    XCHECK((nSaltLen == DIRECTGATE_SRP_SALT_SIZE), XFALSE);
    XCHECK((xstrused(pVerifierHex)), XFALSE);

    BIGNUM *pV = NULL;
    if (BN_hex2bn(&pV, pVerifierHex) <= 0 || pV == NULL) return XFALSE;

    if (BN_is_zero(pV) || BN_is_negative(pV) || BN_cmp(pV, pSRP->N) >= 0)
    {
        BN_free(pV);
        return XFALSE;
    }

    BN_free(pSRP->v);
    pSRP->v = pV;

    memcpy(pSRP->salt, pSalt, DIRECTGATE_SRP_SALT_SIZE);
    return XTRUE;
}

xbool_t DirectGate_SRP_SetClientPublic(directgate_srp_t *pSRP, const char *pAHex)
{
    XCHECK((pSRP != NULL), XFALSE);
    XCHECK((pSRP->N != NULL), XFALSE);
    XCHECK((xstrused(pAHex)), XFALSE);

    BIGNUM *pA = NULL;
    XCHECK((BN_hex2bn(&pA, pAHex) > 0), XFALSE);
    XCHECK((pA != NULL), XFALSE);

    BN_CTX *pBN = BN_CTX_new();
    BIGNUM *pRem = BN_new();

    XCHECK_CALL((pBN != NULL), BN_free, pA, XFALSE);
    XCHECK_CALL((pRem != NULL), BN_free, pA, XFALSE);

    if (BN_mod(pRem, pA, pSRP->N, pBN) != 1 ||
        BN_is_zero(pRem) || BN_is_negative(pRem))
    {
        BN_free(pA);
        BN_free(pRem);
        BN_CTX_free(pBN);
        return XFALSE;
    }

    BN_free(pSRP->A);
    pSRP->A = pA;
    pA = NULL;

    BN_free(pSRP->b);
    BN_free(pSRP->B);
    pSRP->b = NULL;
    pSRP->B = NULL;

    OPENSSL_cleanse(pSRP->K, sizeof(pSRP->K));
    pSRP->bAuthenticated = XFALSE;

    BN_free(pA);
    BN_free(pRem);
    BN_CTX_free(pBN);

    return XTRUE;
}

xbool_t DirectGate_SRP_GenerateChallenge(directgate_srp_t *pSRP,
                                         char *pBHex, size_t nBSize,
                                         char *pNonceHex, size_t nNonceSize)
{
    XCHECK((pSRP != NULL), XFALSE);
    XCHECK((pSRP->N != NULL), XFALSE);
    XCHECK((pSRP->g != NULL), XFALSE);
    XCHECK((pSRP->k != NULL), XFALSE);
    XCHECK((pSRP->v != NULL), XFALSE);
    XCHECK((pSRP->A != NULL), XFALSE);
    XCHECK((pBHex != NULL), XFALSE);
    XCHECK((pNonceHex != NULL), XFALSE);

    uint8_t bRaw[32];
    if (RAND_bytes(bRaw, sizeof(bRaw)) != 1) return XFALSE;

    BN_CTX *pBN = BN_CTX_new();
    BIGNUM *pB = NULL;
    BIGNUM *pGExpB = NULL;
    BIGNUM *pKV = NULL;
    BIGNUM *pBigB = BN_bin2bn(bRaw, sizeof(bRaw), NULL);
    xbool_t bOk = XFALSE;

    do
    {
        if (pBN == NULL || pBigB == NULL) break;

        pB = BN_new();
        pGExpB = BN_new();
        pKV = BN_new();

        if (pB == NULL || pGExpB == NULL || pKV == NULL) break;
        if (BN_mod_exp(pGExpB, pSRP->g, pBigB, pSRP->N, pBN) != 1) break;
        if (BN_mod_mul(pKV, pSRP->k, pSRP->v, pSRP->N, pBN) != 1) break;
        if (BN_mod_add(pB, pKV, pGExpB, pSRP->N, pBN) != 1) break;
        if (RAND_bytes(pSRP->nonce, sizeof(pSRP->nonce)) != 1) break;

        char *pBStr = BN_bn2hex(pB);
        if (pBStr == NULL) break;

        if (strlen(pBStr) + 1 > nBSize)
        {
            OPENSSL_free(pBStr);
            break;
        }

        xstrncpy(pBHex, nBSize, pBStr);
        OPENSSL_free(pBStr);

        if (!DirectGate_SRP_BytesToHex(pSRP->nonce, sizeof(pSRP->nonce), pNonceHex, nNonceSize))
            break;

        BN_free(pSRP->b);
        BN_free(pSRP->B);
        pSRP->b = pBigB;
        pSRP->B = pB;
        pBigB = NULL;
        pB = NULL;

        pSRP->bAuthenticated = XFALSE;
        bOk = XTRUE;
    }
    while (0);

    OPENSSL_cleanse(bRaw, sizeof(bRaw));
    BN_free(pBigB);
    BN_free(pB);
    BN_free(pGExpB);
    BN_free(pKV);
    BN_CTX_free(pBN);

    return bOk;
}

xbool_t DirectGate_SRP_VerifyClientProof(directgate_srp_t *pSRP,
                                         const char *pM1Hex,
                                         char *pM2Hex, size_t nM2Size)
{
    XCHECK((pSRP != NULL), XFALSE);
    XCHECK((pSRP->N != NULL), XFALSE);
    XCHECK((pSRP->A != NULL), XFALSE);
    XCHECK((pSRP->B != NULL), XFALSE);
    XCHECK((pSRP->b != NULL), XFALSE);
    XCHECK((pSRP->v != NULL), XFALSE);
    XCHECK((xstrused(pM1Hex)), XFALSE);
    XCHECK((pM2Hex != NULL), XFALSE);

    uint8_t m1[SHA256_DIGEST_LENGTH];
    size_t nM1Len = 0;

    if (!DirectGate_SRP_HexToBytes(pM1Hex, m1, sizeof(m1), &nM1Len) ||
        nM1Len != sizeof(m1)) return XFALSE;

    BN_CTX *pBN = BN_CTX_new();
    BIGNUM *pU = NULL;
    BIGNUM *pVU = NULL;
    BIGNUM *pAVU = NULL;
    BIGNUM *pS = NULL;
    xbool_t bOk = XFALSE;

    size_t nBytes = DirectGate_SRP_GroupBytes(pSRP);
    uint8_t aPad[512];
    uint8_t bPad[512];
    uint8_t expectedM1[SHA256_DIGEST_LENGTH];
    uint8_t m2[SHA256_DIGEST_LENGTH];

    do
    {
        if (nBytes == 0 || nBytes > sizeof(aPad)) break;
        if (pBN == NULL) break;

        pVU = BN_new();
        pAVU = BN_new();
        pS = BN_new();

        if (pVU == NULL || pAVU == NULL || pS == NULL) break;
        if (!DirectGate_SRP_ComputeU(pSRP, pSRP->A, pSRP->B, &pU)) break;

        if (BN_mod_exp(pVU, pSRP->v, pU, pSRP->N, pBN) != 1) break;
        if (BN_mod_mul(pAVU, pSRP->A, pVU, pSRP->N, pBN) != 1) break;
        if (BN_mod_exp(pS, pAVU, pSRP->b, pSRP->N, pBN) != 1) break;

        if (!DirectGate_SRP_DeriveKFromS(pSRP, pS, pSRP->K)) break;
        if (!DirectGate_SRP_BNToPadded(pSRP, pSRP->A, aPad, sizeof(aPad))) break;
        if (!DirectGate_SRP_BNToPadded(pSRP, pSRP->B, bPad, sizeof(bPad))) break;
        if (!DirectGate_SRP_ComputeM1(pSRP, aPad, bPad, expectedM1)) break;

        if (CRYPTO_memcmp(expectedM1, m1, sizeof(m1)) != 0) break;
        if (!DirectGate_SRP_ComputeM2(pSRP, aPad, m1, m2)) break;
        if (!DirectGate_SRP_BytesToHex(m2, sizeof(m2), pM2Hex, nM2Size)) break;

        pSRP->bAuthenticated = XTRUE;
        bOk = XTRUE;
    }
    while (0);

    if (!bOk)
    {
        OPENSSL_cleanse(pSRP->K, sizeof(pSRP->K));
        pSRP->bAuthenticated = XFALSE;
    }

    OPENSSL_cleanse(m1, sizeof(m1));
    OPENSSL_cleanse(expectedM1, sizeof(expectedM1));
    OPENSSL_cleanse(m2, sizeof(m2));
    OPENSSL_cleanse(aPad, sizeof(aPad));
    OPENSSL_cleanse(bPad, sizeof(bPad));

    BN_free(pU);
    BN_free(pVU);
    BN_free(pAVU);
    BN_free(pS);
    BN_CTX_free(pBN);

    return bOk;
}

xbool_t DirectGate_SRP_CreateVerifier(const char *pPassword,
                                      const uint8_t *pSalt, size_t nSaltLen,
                                      char *pVerifierHex, size_t nSize)
{
    XCHECK((xstrused(pPassword)), XFALSE);
    XCHECK((pSalt != NULL), XFALSE);
    XCHECK((nSaltLen == DIRECTGATE_SRP_SALT_SIZE), XFALSE);
    XCHECK((pVerifierHex != NULL), XFALSE);

    const SRP_gN *pGroup = SRP_get_default_gN("2048");
    if (pGroup == NULL) return XFALSE;

    uint8_t xRaw[32];
    if (EVP_PBE_scrypt(pPassword, strlen(pPassword),
                       pSalt, nSaltLen,
                       DIRECTGATE_SRP_SCRYPT_N,
                       DIRECTGATE_SRP_SCRYPT_R,
                       DIRECTGATE_SRP_SCRYPT_P,
                       0, xRaw, sizeof(xRaw)) != 1)
    {
        xloge("Failed to derive SRP verifier key with scrypt");
        return XFALSE;
    }

    BN_CTX *pBN = BN_CTX_new();
    BIGNUM *pX = BN_bin2bn(xRaw, sizeof(xRaw), NULL);
    BIGNUM *pV = BN_new();
    xbool_t bOk = XFALSE;

    do
    {
        if (pBN == NULL || pX == NULL || pV == NULL) break;
        if (BN_mod_exp(pV, pGroup->g, pX, pGroup->N, pBN) != 1) break;

        char *pHex = BN_bn2hex(pV);
        if (pHex == NULL) break;

        if (strlen(pHex) + 1 <= nSize)
        {
            xstrncpy(pVerifierHex, nSize, pHex);
            bOk = XTRUE;
        }

        OPENSSL_free(pHex);
    }
    while (0);

    OPENSSL_cleanse(xRaw, sizeof(xRaw));
    BN_free(pX);
    BN_free(pV);
    BN_CTX_free(pBN);

    return bOk;
}

/* ===== Client-side SRP-6a ===== */

static size_t DirectGate_SRP_ClientGroupBytes(const directgate_srp_client_t *pClient)
{
    XCHECK_NL((pClient != NULL), 0);
    XCHECK_NL((pClient->N != NULL), 0);
    return (size_t)BN_num_bytes(pClient->N);
}

static xbool_t DirectGate_SRP_ClientBNToPadded(const directgate_srp_client_t *pClient,
                                            const BIGNUM *pBN,
                                            uint8_t *pOut, size_t nOut)
{
    XCHECK((pClient != NULL), XFALSE);
    XCHECK((pBN != NULL), XFALSE);

    size_t nBytes = DirectGate_SRP_ClientGroupBytes(pClient);
    if (nOut < nBytes) return XFALSE;

    int nBinPad = BN_bn2binpad(pBN, pOut, (int)nBytes);
    return nBinPad == (int)nBytes ? XTRUE : XFALSE;
}

xbool_t DirectGate_SRP_ClientInit(directgate_srp_client_t *pClient)
{
    XCHECK((pClient != NULL), XFALSE);
    memset(pClient, 0, sizeof(*pClient));

    const SRP_gN *pGroup = SRP_get_default_gN("2048");
    XCHECK((pGroup != NULL), XFALSE);

    pClient->N = BN_dup(pGroup->N);
    pClient->g = BN_dup(pGroup->g);

    if (pClient->N == NULL || pClient->g == NULL)
    {
        DirectGate_SRP_ClientCleanse(pClient);
        return XFALSE;
    }

    /* Compute k = SHA256(PAD(N) || PAD(g)) */
    size_t nBytes = (size_t)BN_num_bytes(pClient->N);
    uint8_t *pBuf = (uint8_t*)malloc(nBytes * 2);

    XCHECK_CALL((pBuf != NULL),
        DirectGate_SRP_ClientCleanse, pClient,
        xthrowr(XFALSE, "Failed to allocate memory for SRP k parameter"));

    if (BN_bn2binpad(pClient->N, pBuf, (int)nBytes) != (int)nBytes ||
        BN_bn2binpad(pClient->g, pBuf + nBytes, (int)nBytes) != (int)nBytes)
    {
        OPENSSL_cleanse(pBuf, nBytes * 2);
        DirectGate_SRP_ClientCleanse(pClient);
        free(pBuf);
        return XFALSE;
    }

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(pBuf, nBytes * 2, hash);
    pClient->k = BN_bin2bn(hash, sizeof(hash), NULL);

    OPENSSL_cleanse(hash, sizeof(hash));
    OPENSSL_cleanse(pBuf, nBytes * 2);
    free(pBuf);

    XCHECK_CALL((pClient->k != NULL),
        DirectGate_SRP_ClientCleanse, pClient,
        xthrowr(XFALSE, "Failed to compute SRP k parameter"));

    return XTRUE;
}

void DirectGate_SRP_ClientCleanse(directgate_srp_client_t *pClient)
{
    XCHECK_VOID_NL((pClient != NULL));

    BN_free(pClient->N);
    BN_free(pClient->g);
    BN_free(pClient->k);
    BN_free(pClient->a);
    BN_free(pClient->A);

    OPENSSL_cleanse(pClient->K, sizeof(pClient->K));
    OPENSSL_cleanse(pClient->M1, sizeof(pClient->M1));
    OPENSSL_cleanse(pClient->nonce, sizeof(pClient->nonce));
    OPENSSL_cleanse(pClient->agentNonce, sizeof(pClient->agentNonce));
    OPENSSL_cleanse(pClient->sDeviceId, sizeof(pClient->sDeviceId));

    memset(pClient, 0, sizeof(*pClient));
}

xbool_t DirectGate_SRP_ClientGenerateA(directgate_srp_client_t *pClient,
                                       char *pAHex, size_t nASize,
                                       char *pNonceHex, size_t nNonceSize)
{
    XCHECK((pClient != NULL), XFALSE);
    XCHECK((pClient->N != NULL), XFALSE);
    XCHECK((pClient->g != NULL), XFALSE);
    XCHECK((pAHex != NULL), XFALSE);
    XCHECK((pNonceHex != NULL), XFALSE);

    uint8_t aRaw[32];
    if (RAND_bytes(aRaw, sizeof(aRaw)) != 1) return XFALSE;

    BN_free(pClient->a);
    BN_free(pClient->A);

    pClient->a = BN_bin2bn(aRaw, sizeof(aRaw), NULL);
    OPENSSL_cleanse(aRaw, sizeof(aRaw));
    if (pClient->a == NULL) return XFALSE;

    BN_CTX *pBN = BN_CTX_new();
    pClient->A = BN_new();

    if (pBN == NULL || pClient->A == NULL ||
        BN_mod_exp(pClient->A, pClient->g, pClient->a, pClient->N, pBN) != 1)
    {
        BN_CTX_free(pBN);
        return XFALSE;
    }

    BN_CTX_free(pBN);

    char *pStr = BN_bn2hex(pClient->A);
    if (pStr == NULL) return XFALSE;

    if (strlen(pStr) + 1 > nASize)
    {
        OPENSSL_free(pStr);
        return XFALSE;
    }

    xstrncpy(pAHex, nASize, pStr);
    OPENSSL_free(pStr);

    if (RAND_bytes(pClient->nonce, sizeof(pClient->nonce)) != 1) return XFALSE;
    if (!DirectGate_SRP_BytesToHex(pClient->nonce, sizeof(pClient->nonce), pNonceHex, nNonceSize)) return XFALSE;

    return XTRUE;
}

xbool_t DirectGate_SRP_ClientComputeKey(directgate_srp_client_t *pClient,
                                        const char *pDeviceId,
                                        const char *pPassword,
                                        const char *pSaltHex,
                                        const char *pBHex,
                                        uint32_t nSuite,
                                        char *pM1Hex,
                                        size_t nM1Size)
{
    XCHECK((pClient != NULL), XFALSE);
    XCHECK((pClient->N != NULL), XFALSE);
    XCHECK((pClient->a != NULL), XFALSE);
    XCHECK((pClient->A != NULL), XFALSE);
    XCHECK((xstrused(pDeviceId)), XFALSE);
    XCHECK((xstrused(pPassword)), XFALSE);
    XCHECK((xstrused(pSaltHex)), XFALSE);
    XCHECK((xstrused(pBHex)), XFALSE);
    XCHECK((pM1Hex != NULL), XFALSE);

    xstrncpy(pClient->sDeviceId, sizeof(pClient->sDeviceId), pDeviceId);

    /* Parse B */
    BIGNUM *pB = NULL;
    BN_CTX *pBN = BN_CTX_new();
    BIGNUM *pU = NULL;
    BIGNUM *pX = NULL;
    BIGNUM *pGX = NULL;
    BIGNUM *pKGX = NULL;
    BIGNUM *pBase = NULL;
    BIGNUM *pExp = NULL;
    BIGNUM *pUX = NULL;
    BIGNUM *pS = NULL;
    xbool_t bOk = XFALSE;

    size_t nBytes = DirectGate_SRP_ClientGroupBytes(pClient);
    uint8_t aPad[512], bPad[512];

    do
    {
        if (nBytes == 0 || nBytes > sizeof(aPad)) break;
        if (BN_hex2bn(&pB, pBHex) <= 0 || pB == NULL) break;
        if (pBN == NULL) break;

        /* Validate B mod N != 0 */
        BIGNUM *pRem = BN_new();
        if (pRem == NULL) break;

        if (BN_mod(pRem, pB, pClient->N, pBN) != 1 || BN_is_zero(pRem))
        {
            BN_free(pRem);
            break;
        }

        BN_free(pRem);

        /* u = SHA256(PAD(A) || PAD(B)) */
        if (!DirectGate_SRP_ClientBNToPadded(pClient, pClient->A, aPad, sizeof(aPad))) break;
        if (!DirectGate_SRP_ClientBNToPadded(pClient, pB, bPad, sizeof(bPad))) break;

        uint8_t uHash[SHA256_DIGEST_LENGTH];
        uint8_t *pCombined = (uint8_t*)malloc(nBytes * 2);
        if (pCombined == NULL) break;
        memcpy(pCombined, aPad, nBytes);
        memcpy(pCombined + nBytes, bPad, nBytes);
        SHA256(pCombined, nBytes * 2, uHash);
        OPENSSL_cleanse(pCombined, nBytes * 2);
        free(pCombined);

        pU = BN_bin2bn(uHash, sizeof(uHash), NULL);
        OPENSSL_cleanse(uHash, sizeof(uHash));
        if (pU == NULL || BN_is_zero(pU)) break;

        uint8_t salt[DIRECTGATE_SRP_SALT_SIZE];
        size_t nSaltLen = 0;

        if (!DirectGate_SRP_HexToBytes(pSaltHex, salt, sizeof(salt), &nSaltLen) ||
            nSaltLen != DIRECTGATE_SRP_SALT_SIZE) break;

        if (nSuite != DIRECTGATE_SRP_SUITE)
        {
            xloge("SRP: unsupported suite %u (version required)", nSuite);
            OPENSSL_cleanse(salt, sizeof(salt));
            break;
        }

        uint8_t xRaw[32];
        if (EVP_PBE_scrypt(pPassword, strlen(pPassword), salt, nSaltLen,
                           DIRECTGATE_SRP_SCRYPT_N, DIRECTGATE_SRP_SCRYPT_R,
                           DIRECTGATE_SRP_SCRYPT_P, 0, xRaw, sizeof(xRaw)) != 1)
        {
            OPENSSL_cleanse(salt, sizeof(salt));
            break;
        }

        pX = BN_bin2bn(xRaw, sizeof(xRaw), NULL);
        OPENSSL_cleanse(xRaw, sizeof(xRaw));
        if (pX == NULL) break;

        /* S = (B - k*g^x)^(a + u*x) mod N */
        pGX = BN_new();
        pKGX = BN_new();
        pBase = BN_new();
        pExp = BN_new();
        pUX = BN_new();
        pS = BN_new();

        if (!pGX || !pKGX || !pBase || !pExp || !pUX || !pS) break;
        if (BN_mod_exp(pGX, pClient->g, pX, pClient->N, pBN) != 1) break;
        if (BN_mod_mul(pKGX, pClient->k, pGX, pClient->N, pBN) != 1) break;
        if (BN_mod_sub(pBase, pB, pKGX, pClient->N, pBN) != 1) break;
        if (BN_mul(pUX, pU, pX, pBN) != 1) break;
        if (BN_add(pExp, pClient->a, pUX) != 1) break;
        if (BN_mod_exp(pS, pBase, pExp, pClient->N, pBN) != 1) break;

        /* K = SHA256(PAD(S)) */
        uint8_t sPad[512];
        if (!DirectGate_SRP_ClientBNToPadded(pClient, pS, sPad, sizeof(sPad))) break;
        SHA256(sPad, nBytes, pClient->K);
        OPENSSL_cleanse(sPad, sizeof(sPad));

        /* M1 = SHA256(H(N)^H(g) || H(I) || salt || PAD(A) || PAD(B) || K) */
        uint8_t nPad2[512], gPad2[512];
        if (!DirectGate_SRP_ClientBNToPadded(pClient, pClient->N, nPad2, sizeof(nPad2))) break;
        if (!DirectGate_SRP_ClientBNToPadded(pClient, pClient->g, gPad2, sizeof(gPad2))) break;

        uint8_t hN[SHA256_DIGEST_LENGTH], hG[SHA256_DIGEST_LENGTH];
        uint8_t hI[SHA256_DIGEST_LENGTH], hXor[SHA256_DIGEST_LENGTH];
        SHA256(nPad2, nBytes, hN);
        SHA256(gPad2, nBytes, hG);
        SHA256((const uint8_t*)pDeviceId, strlen(pDeviceId), hI);
        for (size_t i = 0; i < sizeof(hXor); i++) hXor[i] = hN[i] ^ hG[i];

        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, hXor, sizeof(hXor));
        SHA256_Update(&ctx, hI, sizeof(hI));
        SHA256_Update(&ctx, salt, DIRECTGATE_SRP_SALT_SIZE);
        SHA256_Update(&ctx, aPad, nBytes);
        SHA256_Update(&ctx, bPad, nBytes);
        SHA256_Update(&ctx, pClient->agentNonce, sizeof(pClient->agentNonce));
        SHA256_Update(&ctx, pClient->nonce, sizeof(pClient->nonce));
        SHA256_Update(&ctx, pClient->K, sizeof(pClient->K));
        SHA256_Final(pClient->M1, &ctx);

        OPENSSL_cleanse(&ctx, sizeof(ctx));
        OPENSSL_cleanse(salt, sizeof(salt));

        if (!DirectGate_SRP_BytesToHex(pClient->M1, sizeof(pClient->M1), pM1Hex, nM1Size))
            break;

        bOk = XTRUE;
    }
    while (0);

    OPENSSL_cleanse(aPad, sizeof(aPad));
    OPENSSL_cleanse(bPad, sizeof(bPad));

    BN_free(pB);
    BN_free(pU);
    BN_free(pX);
    BN_free(pGX);
    BN_free(pKGX);
    BN_free(pBase);
    BN_free(pExp);
    BN_free(pUX);
    BN_free(pS);
    BN_CTX_free(pBN);

    return bOk;
}

xbool_t DirectGate_SRP_ClientVerifyM2(const directgate_srp_client_t *pClient,
                                      const char *pBHex,
                                      const char *pM2Hex)
{
    (void)pBHex;
    XCHECK((pClient != NULL), XFALSE);
    XCHECK((pClient->A != NULL), XFALSE);
    XCHECK((xstrused(pM2Hex)), XFALSE);

    uint8_t m2[SHA256_DIGEST_LENGTH];
    size_t nM2Len = 0;
    if (!DirectGate_SRP_HexToBytes(pM2Hex, m2, sizeof(m2), &nM2Len) || nM2Len != sizeof(m2))
        return XFALSE;

    /* M2 = SHA256(PAD(A) || M1 || K) */
    size_t nBytes = DirectGate_SRP_ClientGroupBytes(pClient);
    uint8_t aPad[512];

    if (nBytes == 0 || nBytes > sizeof(aPad)) return XFALSE;
    if (!DirectGate_SRP_ClientBNToPadded(pClient, pClient->A, aPad, sizeof(aPad))) return XFALSE;

    SHA256_CTX ctx;
    uint8_t expected[SHA256_DIGEST_LENGTH];

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, aPad, nBytes);
    SHA256_Update(&ctx, pClient->M1, sizeof(pClient->M1));
    SHA256_Update(&ctx, pClient->K, sizeof(pClient->K));
    SHA256_Final(expected, &ctx);

    OPENSSL_cleanse(&ctx, sizeof(ctx));
    OPENSSL_cleanse(aPad, sizeof(aPad));

    xbool_t bOk = (CRYPTO_memcmp(expected, m2, sizeof(m2)) == 0) ? XTRUE : XFALSE;
    OPENSSL_cleanse(expected, sizeof(expected));
    OPENSSL_cleanse(m2, sizeof(m2));

    return bOk;
}
