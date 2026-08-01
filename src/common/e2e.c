/*!
 * @file directgate-agent/src/common/e2e.c
 * @brief End-to-end encryption for terminal data between agent and client.
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

#include "e2e.h"
#include "hkdf.h"
#include "siv.h"
#include "srp.h"

void DirectGate_E2E_Init(directgate_e2e_t *pE2E)
{
    XCHECK_VOID((pE2E != NULL));
    memset(pE2E, 0, sizeof(*pE2E));
    pE2E->bInitialized = XFALSE;
}

void DirectGate_E2E_ResetCCWindow(directgate_ccwin_t *pWindow)
{
    XCHECK_VOID_NL((pWindow != NULL));
    pWindow->nHighest = 0;
    pWindow->nBitmap = 0;
}

xbool_t DirectGate_E2E_AcceptCC(directgate_ccwin_t *pWindow, uint32_t nCC)
{
    XCHECK_NL((pWindow != NULL), XFALSE);
    XCHECK_NL((nCC > 0), XFALSE);

    if (pWindow->nHighest == 0)
    {
        pWindow->nHighest = nCC;
        pWindow->nBitmap = 1ULL;
        return XTRUE;
    }

    if (nCC > pWindow->nHighest)
    {
        uint32_t nShift = nCC - pWindow->nHighest;
        pWindow->nBitmap = (nShift >= XE2E_CC_WINDOW_SIZE) ?
            1ULL : ((pWindow->nBitmap << nShift) | 1ULL);

        pWindow->nHighest = nCC;
        return XTRUE;
    }

    uint32_t nBehind = pWindow->nHighest - nCC;
    if (nBehind >= XE2E_CC_WINDOW_SIZE) return XFALSE;

    uint64_t nMask = 1ULL << nBehind;
    if (pWindow->nBitmap & nMask) return XFALSE;

    pWindow->nBitmap |= nMask;
    return XTRUE;
}

void DirectGate_E2E_Clear(directgate_e2e_t *pE2E)
{
    XCHECK_VOID((pE2E != NULL));
    OPENSSL_cleanse(pE2E->txCmacKey, sizeof(pE2E->txCmacKey));
    OPENSSL_cleanse(pE2E->txCtrKey, sizeof(pE2E->txCtrKey));
    OPENSSL_cleanse(pE2E->rxCmacKey, sizeof(pE2E->rxCmacKey));
    OPENSSL_cleanse(pE2E->rxCtrKey, sizeof(pE2E->rxCtrKey));
    DirectGate_E2E_Init(pE2E);
}

/* Split 128 bytes of HKDF output into two directional key pairs and assign
   them to TX/RX according to the local role. Layout:
     okm[  0.. 31] agent->client cmac    okm[ 32.. 63] agent->client ctr
     okm[ 64.. 95] client->agent cmac    okm[ 96..127] client->agent ctr
   The agent sends on the agent->client pair and receives on client->agent; the
   client mirrors it. Because TX != RX on each side, a packet looped back to
   its origin cannot be decrypted there. */
static void DirectGate_E2E_AssignKeys(directgate_e2e_t *pE2E, const uint8_t *pOKM, xbool_t bIsAgent)
{
    const uint8_t *pH2cCmac = pOKM;
    const uint8_t *pH2cCtr  = pOKM + XE2E_KEY_SIZE;
    const uint8_t *pC2hCmac = pOKM + (XE2E_KEY_SIZE * 2);
    const uint8_t *pC2hCtr  = pOKM + (XE2E_KEY_SIZE * 3);

    const uint8_t *pTxCmac = bIsAgent ? pH2cCmac : pC2hCmac;
    const uint8_t *pTxCtr  = bIsAgent ? pH2cCtr  : pC2hCtr;
    const uint8_t *pRxCmac = bIsAgent ? pC2hCmac : pH2cCmac;
    const uint8_t *pRxCtr  = bIsAgent ? pC2hCtr  : pH2cCtr;

    memcpy(pE2E->txCmacKey, pTxCmac, XE2E_KEY_SIZE);
    memcpy(pE2E->txCtrKey,  pTxCtr,  XE2E_KEY_SIZE);
    memcpy(pE2E->rxCmacKey, pRxCmac, XE2E_KEY_SIZE);
    memcpy(pE2E->rxCtrKey,  pRxCtr,  XE2E_KEY_SIZE);
}

xbool_t DirectGate_E2E_DeriveFromSRP(directgate_e2e_t *pE2E, const uint8_t *pSessionKey, size_t nSessionKeyLen,
                                    const uint8_t *pagentNonce, const uint8_t *pClientNonce, size_t nNonceSize,
                                    const char *pDeviceId, xbool_t bIsAgent)
{
    XCHECK((pE2E != NULL), XFALSE);
    XCHECK((pSessionKey != NULL), XFALSE);
    XCHECK((nSessionKeyLen > 0), XFALSE);
    XCHECK((pagentNonce != NULL), XFALSE);
    XCHECK((pClientNonce != NULL), XFALSE);
    XCHECK((nNonceSize > 0), XFALSE);
    XCHECK(xstrused(pDeviceId), XFALSE);

    /* Salt = agentNonce || clientNonce */
    uint8_t salt[DIRECTGATE_SRP_NONCE_SIZE * 2];
    XCHECK((nNonceSize * 2 <= sizeof(salt)), XFALSE);
    memcpy(salt, pagentNonce, nNonceSize);
    memcpy(salt + nNonceSize, pClientNonce, nNonceSize);

    /* 128 bytes of OKM: one cmac/ctr pair per direction. */
    uint8_t okm[XE2E_KEY_SIZE * 4];
    char sInfo[XE2E_MAX_HOSTID_LENGTH * 2];
    xstrncpyf(sInfo, sizeof(sInfo), "directgate:e2e:%s", pDeviceId);

    XCHECK((DirectGate_HKDF_SHA256(salt, nNonceSize * 2,
            pSessionKey, nSessionKeyLen, sInfo,
            okm, sizeof(okm)) == XTRUE), XFALSE);

    DirectGate_E2E_AssignKeys(pE2E, okm, bIsAgent);
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(okm, sizeof(okm));

    pE2E->bInitialized = XTRUE;
    return XTRUE;
}

xbool_t DirectGate_E2E_DeriveFromKey(directgate_e2e_t *pE2E, const uint8_t *pSharedSecret, size_t nSharedLen,
                                    const uint8_t *pagentNonce, const uint8_t *pClientNonce, size_t nNonceSize,
                                    const char *pDeviceId, xbool_t bIsAgent)
{
    XCHECK((pE2E != NULL), XFALSE);
    XCHECK((pSharedSecret != NULL), XFALSE);
    XCHECK((nSharedLen > 0), XFALSE);
    XCHECK((pagentNonce != NULL), XFALSE);
    XCHECK((pClientNonce != NULL), XFALSE);
    XCHECK((nNonceSize > 0), XFALSE);
    XCHECK(xstrused(pDeviceId), XFALSE);

    /* Salt layout matches SRP path: agentNonce || clientNonce. */
    uint8_t salt[DIRECTGATE_SRP_NONCE_SIZE * 2];
    XCHECK((nNonceSize * 2 <= sizeof(salt)), XFALSE);
    memcpy(salt, pagentNonce, nNonceSize);
    memcpy(salt + nNonceSize, pClientNonce, nNonceSize);

    /* Domain-separated info string vs the SRP variant. Keeping the nonce
       salt layout identical preserves the mutual-freshness guarantee and
       aligns the KDF with the directional cmac/ctr split. */
    uint8_t okm[XE2E_KEY_SIZE * 4];
    char sInfo[XE2E_MAX_HOSTID_LENGTH * 2];
    xstrncpyf(sInfo, sizeof(sInfo), "directgate:e2e:key:%s", pDeviceId);

    XCHECK((DirectGate_HKDF_SHA256(salt, nNonceSize * 2,
            pSharedSecret, nSharedLen, sInfo,
            okm, sizeof(okm)) == XTRUE), XFALSE);

    DirectGate_E2E_AssignKeys(pE2E, okm, bIsAgent);
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(okm, sizeof(okm));

    pE2E->bInitialized = XTRUE;
    return XTRUE;
}

xbool_t DirectGate_E2E_IsInitialized(const directgate_e2e_t *pE2E)
{
    XCHECK((pE2E != NULL), XFALSE);
    return pE2E->bInitialized;
}

uint8_t* DirectGate_E2E_Encrypt(const directgate_e2e_t *pE2E, const uint8_t *pData, size_t nLength, size_t *pOutLen)
{
    XCHECK((pE2E != NULL && pE2E->bInitialized), NULL);
    XCHECK((pData != NULL && nLength > 0), NULL);
    XCHECK((pOutLen != NULL), NULL);

    uint8_t *pEncrypted = DirectGate_SIV_Encrypt(pE2E->txCmacKey, pE2E->txCtrKey,
        XE2E_AES_SIZE, pData, nLength, pOutLen);
    XCHECK((pEncrypted != NULL), xthrowp(NULL, "E2E: AES-SIV encryption failed"));

    return pEncrypted;
}

uint8_t* DirectGate_E2E_Decrypt(const directgate_e2e_t *pE2E, const uint8_t *pData, size_t nLength, size_t *pOutLen)
{
    XCHECK((pE2E != NULL), NULL);
    XCHECK((pData != NULL), NULL);
    XCHECK((pOutLen != NULL), NULL);
    XCHECK((pE2E->bInitialized), NULL);

    /* Need at least nonce (16) + SIV tag (16) before any ciphertext. */
    XCHECK_NL((nLength > (size_t)XE2E_IV_SIZE * 2),
        xthrowp(NULL, "E2E: Message too short for decryption"));

    uint8_t *pDecrypted = DirectGate_SIV_Decrypt(pE2E->rxCmacKey, pE2E->rxCtrKey,
        XE2E_AES_SIZE, pData, nLength, pOutLen);
    XCHECK((pDecrypted != NULL), xthrowp(NULL, "E2E: AES-SIV decryption failed"));

    return pDecrypted;
}
