/*!
 * @file directgate-agent/src/common/keyauth.c
 * @brief Public-key authentication for directgate.
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
#include "keyauth.h"

#define DIRECTGATE_KEYAUTH_DOMAIN       "directgate-key-auth-v1"
#define DIRECTGATE_KEYAUTH_DOMAIN_LEN   (sizeof(DIRECTGATE_KEYAUTH_DOMAIN) - 1)

void DirectGate_KeyAuth_Init(directgate_keyauth_t *pAuth)
{
    XCHECK_VOID_NL((pAuth != NULL));
    memset(pAuth, 0, sizeof(*pAuth));
    pAuth->eState = DIRECTGATE_KEYAUTH_STATE_IDLE;
}

void DirectGate_KeyAuth_Cleanse(directgate_keyauth_t *pAuth)
{
    XCHECK_VOID_NL((pAuth != NULL));
    OPENSSL_cleanse(pAuth->localEphPriv, sizeof(pAuth->localEphPriv));
    OPENSSL_cleanse(pAuth->sharedSecret, sizeof(pAuth->sharedSecret));
    memset(pAuth, 0, sizeof(*pAuth));
}

const char *DirectGate_KeyAuth_StateName(directgate_keyauth_state_t eState)
{
    switch (eState)
    {
        case DIRECTGATE_KEYAUTH_STATE_IDLE: return "IDLE";
        case DIRECTGATE_KEYAUTH_STATE_HELLO_RECEIVED: return "HELLO_RECEIVED";
        case DIRECTGATE_KEYAUTH_STATE_CHALLENGE_SENT: return "CHALLENGE_SENT";
        case DIRECTGATE_KEYAUTH_STATE_AUTHENTICATED: return "AUTHENTICATED";
        case DIRECTGATE_KEYAUTH_STATE_FAILED: return "FAILED";
        default: return "UNKNOWN";
    }
}

static int DirectGate_KeyAuth_HexNibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

xbool_t DirectGate_KeyAuth_HexToBytes(const char *pHex, uint8_t *pOut,
                                      size_t nOutSize, size_t *pOutLen)
{
    XCHECK_NL((pHex != NULL), XFALSE);
    XCHECK_NL((pOut != NULL), XFALSE);

    size_t nHexLen = strnlen(pHex, nOutSize * 2 + 1);
    if (!nHexLen || (nHexLen & 1U)) return XFALSE;

    size_t nLen = nHexLen / 2;
    if (nLen > nOutSize) return XFALSE;

    for (size_t i = 0; i < nLen; i++)
    {
        int hi = DirectGate_KeyAuth_HexNibble(pHex[i * 2]);
        int lo = DirectGate_KeyAuth_HexNibble(pHex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return XFALSE;
        pOut[i] = (uint8_t)((hi << 4) | lo);
    }

    if (pOutLen != NULL) *pOutLen = nLen;
    return XTRUE;
}

xbool_t DirectGate_KeyAuth_BytesToHex(const uint8_t *pData, size_t nLen,
                                      char *pHex, size_t nHexSize)
{
    XCHECK_NL((pData != NULL), XFALSE);
    XCHECK_NL((pHex != NULL), XFALSE);
    if (nHexSize < nLen * 2 + 1) return XFALSE;

    for (size_t i = 0; i < nLen; i++)
        sprintf(&pHex[i * 2], "%02x", pData[i]);

    pHex[nLen * 2] = '\0';
    return XTRUE;
}

xbool_t DirectGate_KeyAuth_Base64Encode(const uint8_t *pData, size_t nLen,
                                        char *pOut, size_t nOutSize)
{
    XCHECK_NL((pData != NULL && pOut != NULL), XFALSE);

    size_t nInLen = nLen;
    char *pEncoded = XBase64_Encrypt(pData, &nInLen);
    if (pEncoded == NULL) return XFALSE;

    size_t nEncLen = strlen(pEncoded);
    if (nEncLen + 1 > nOutSize)
    {
        free(pEncoded);
        return XFALSE;
    }

    memcpy(pOut, pEncoded, nEncLen + 1);
    free(pEncoded);
    return XTRUE;
}

xbool_t DirectGate_KeyAuth_Base64Decode(const char *pB64,
                                        uint8_t *pOut, size_t nOutSize,
                                        size_t *pOutLen)
{
    XCHECK_NL((pB64 != NULL && pOut != NULL), XFALSE);

    size_t nInLen = strlen(pB64);
    if (!nInLen) return XFALSE;

    size_t nDecLen = nInLen;
    char *pDecoded = XBase64_Decrypt((const uint8_t*)pB64, &nDecLen);
    if (pDecoded == NULL) return XFALSE;

    if (nDecLen > nOutSize)
    {
        OPENSSL_cleanse(pDecoded, nDecLen);
        free(pDecoded);
        return XFALSE;
    }

    memcpy(pOut, pDecoded, nDecLen);
    OPENSSL_cleanse(pDecoded, nDecLen);
    free(pDecoded);
    if (pOutLen != NULL) *pOutLen = nDecLen;
    return XTRUE;
}

xbool_t DirectGate_KeyAuth_Ed25519DerivePub(const uint8_t *pSeed, uint8_t *pPubOut)
{
    XCHECK_NL((pSeed != NULL && pPubOut != NULL), XFALSE);

    EVP_PKEY *pKey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, pSeed,
                                                  DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE);
    if (pKey == NULL) return XFALSE;

    size_t nPubLen = DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE;
    xbool_t bOk = (EVP_PKEY_get_raw_public_key(pKey, pPubOut, &nPubLen) == 1 &&
                   nPubLen == DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE) ? XTRUE : XFALSE;

    EVP_PKEY_free(pKey);
    return bOk;
}

xbool_t DirectGate_KeyAuth_Ed25519Generate(uint8_t *pPubOut, uint8_t *pSeedOut)
{
    XCHECK_NL((pPubOut != NULL && pSeedOut != NULL), XFALSE);

    EVP_PKEY_CTX *pCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (pCtx == NULL) return XFALSE;

    xbool_t bOk = XFALSE;
    EVP_PKEY *pKey = NULL;

    if (EVP_PKEY_keygen_init(pCtx) == 1 &&
        EVP_PKEY_keygen(pCtx, &pKey) == 1 && pKey != NULL)
    {
        size_t nSeedLen = DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE;
        size_t nPubLen = DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE;

        if (EVP_PKEY_get_raw_private_key(pKey, pSeedOut, &nSeedLen) == 1 &&
            nSeedLen == DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE &&
            EVP_PKEY_get_raw_public_key(pKey, pPubOut, &nPubLen) == 1 &&
            nPubLen == DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE)
        {
            bOk = XTRUE;
        }
    }

    if (pKey != NULL) EVP_PKEY_free(pKey);
    EVP_PKEY_CTX_free(pCtx);
    return bOk;
}

xbool_t DirectGate_KeyAuth_Ed25519Sign(const uint8_t *pSeed,
                                       const uint8_t *pMsg, size_t nMsgLen,
                                       uint8_t *pSigOut)
{
    XCHECK_NL((pSeed != NULL && pMsg != NULL && pSigOut != NULL), XFALSE);

    EVP_PKEY *pKey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, pSeed,
                                                  DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE);
    if (pKey == NULL) return XFALSE;

    EVP_MD_CTX *pMdCtx = EVP_MD_CTX_new();
    xbool_t bOk = XFALSE;

    if (pMdCtx != NULL &&
        EVP_DigestSignInit(pMdCtx, NULL, NULL, NULL, pKey) == 1)
    {
        size_t nSigLen = DIRECTGATE_KEYAUTH_ED25519_SIG_SIZE;
        if (EVP_DigestSign(pMdCtx, pSigOut, &nSigLen, pMsg, nMsgLen) == 1 &&
            nSigLen == DIRECTGATE_KEYAUTH_ED25519_SIG_SIZE)
        {
            bOk = XTRUE;
        }
    }

    if (pMdCtx != NULL) EVP_MD_CTX_free(pMdCtx);
    EVP_PKEY_free(pKey);
    return bOk;
}

xbool_t DirectGate_KeyAuth_Ed25519Verify(const uint8_t *pPub,
                                         const uint8_t *pMsg, size_t nMsgLen,
                                         const uint8_t *pSig)
{
    XCHECK_NL((pPub != NULL && pMsg != NULL && pSig != NULL), XFALSE);

    EVP_PKEY *pKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pPub,
                                                 DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE);
    if (pKey == NULL) return XFALSE;

    EVP_MD_CTX *pMdCtx = EVP_MD_CTX_new();
    xbool_t bOk = XFALSE;

    if (pMdCtx != NULL &&
        EVP_DigestVerifyInit(pMdCtx, NULL, NULL, NULL, pKey) == 1)
    {
        if (EVP_DigestVerify(pMdCtx, pSig, DIRECTGATE_KEYAUTH_ED25519_SIG_SIZE,
                             pMsg, nMsgLen) == 1)
        {
            bOk = XTRUE;
        }
    }

    if (pMdCtx != NULL) EVP_MD_CTX_free(pMdCtx);
    EVP_PKEY_free(pKey);
    return bOk;
}

xbool_t DirectGate_KeyAuth_X25519Generate(uint8_t *pPubOut, uint8_t *pPrivOut)
{
    XCHECK_NL((pPubOut != NULL && pPrivOut != NULL), XFALSE);

    EVP_PKEY_CTX *pCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (pCtx == NULL) return XFALSE;

    xbool_t bOk = XFALSE;
    EVP_PKEY *pKey = NULL;

    if (EVP_PKEY_keygen_init(pCtx) == 1 &&
        EVP_PKEY_keygen(pCtx, &pKey) == 1 && pKey != NULL)
    {
        size_t nPrivLen = DIRECTGATE_KEYAUTH_X25519_PRIV_SIZE;
        size_t nPubLen = DIRECTGATE_KEYAUTH_X25519_PUB_SIZE;

        if (EVP_PKEY_get_raw_private_key(pKey, pPrivOut, &nPrivLen) == 1 &&
            nPrivLen == DIRECTGATE_KEYAUTH_X25519_PRIV_SIZE &&
            EVP_PKEY_get_raw_public_key(pKey, pPubOut, &nPubLen) == 1 &&
            nPubLen == DIRECTGATE_KEYAUTH_X25519_PUB_SIZE)
        {
            bOk = XTRUE;
        }
    }

    if (pKey != NULL) EVP_PKEY_free(pKey);
    EVP_PKEY_CTX_free(pCtx);
    return bOk;
}

xbool_t DirectGate_KeyAuth_X25519Derive(const uint8_t *pLocalPriv,
                                        const uint8_t *pRemotePub,
                                        uint8_t *pSharedOut)
{
    XCHECK_NL((pLocalPriv != NULL && pRemotePub != NULL && pSharedOut != NULL), XFALSE);

    EVP_PKEY *pLocal = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, pLocalPriv,
                                                    DIRECTGATE_KEYAUTH_X25519_PRIV_SIZE);
    if (pLocal == NULL) return XFALSE;

    EVP_PKEY *pPeer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pRemotePub,
                                                  DIRECTGATE_KEYAUTH_X25519_PUB_SIZE);
    if (pPeer == NULL)
    {
        EVP_PKEY_free(pLocal);
        return XFALSE;
    }

    EVP_PKEY_CTX *pCtx = EVP_PKEY_CTX_new(pLocal, NULL);
    xbool_t bOk = XFALSE;

    if (pCtx != NULL &&
        EVP_PKEY_derive_init(pCtx) == 1 &&
        EVP_PKEY_derive_set_peer(pCtx, pPeer) == 1)
    {
        size_t nSharedLen = DIRECTGATE_KEYAUTH_X25519_SHARED_SIZE;
        if (EVP_PKEY_derive(pCtx, pSharedOut, &nSharedLen) == 1 &&
            nSharedLen == DIRECTGATE_KEYAUTH_X25519_SHARED_SIZE)
        {
            bOk = XTRUE;
        }
    }

    if (pCtx != NULL) EVP_PKEY_CTX_free(pCtx);
    EVP_PKEY_free(pPeer);
    EVP_PKEY_free(pLocal);
    return bOk;
}

xbool_t DirectGate_KeyAuth_BuildTranscript(xbyte_buffer_t *pOut, char cTag,
                                           const char *pDeviceId,
                                           const uint8_t *pClientPubKey,
                                           const uint8_t *pAgentPubKey,
                                           const uint8_t *pChallenge,
                                           const uint8_t *pClientNonce,
                                           const uint8_t *pagentNonce,
                                           const uint8_t *pClientEphPub,
                                           const uint8_t *pAgentEphPub)
{
    XCHECK_NL((pOut != NULL), XFALSE);
    XCHECK_NL((cTag == 'h' || cTag == 'c'), XFALSE);
    XCHECK_NL((xstrused(pDeviceId)), XFALSE);
    XCHECK_NL((pClientPubKey != NULL && pAgentPubKey != NULL), XFALSE);
    XCHECK_NL((pChallenge != NULL), XFALSE);
    XCHECK_NL((pClientNonce != NULL && pagentNonce != NULL), XFALSE);
    XCHECK_NL((pClientEphPub != NULL && pAgentEphPub != NULL), XFALSE);

    size_t nDeviceIdLen = strlen(pDeviceId);
    if (nDeviceIdLen == 0 || nDeviceIdLen > UINT16_MAX) return XFALSE;

    uint8_t cTagByte = (uint8_t)cTag;
    uint8_t nDevLenBE[2] = {
        (uint8_t)((nDeviceIdLen >> 8) & 0xFF),
        (uint8_t)(nDeviceIdLen & 0xFF)
    };

    XByteBuffer_Reset(pOut);
    if (XByteBuffer_Add(pOut, (const uint8_t*)DIRECTGATE_KEYAUTH_DOMAIN, DIRECTGATE_KEYAUTH_DOMAIN_LEN) <= 0) return XFALSE;
    if (XByteBuffer_Add(pOut, &cTagByte, 1) <= 0) return XFALSE;
    if (XByteBuffer_Add(pOut, nDevLenBE, 2) <= 0) return XFALSE;
    if (XByteBuffer_Add(pOut, (const uint8_t*)pDeviceId, nDeviceIdLen) <= 0) return XFALSE;
    if (XByteBuffer_Add(pOut, pClientPubKey, DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE) <= 0) return XFALSE;
    if (XByteBuffer_Add(pOut, pAgentPubKey, DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE) <= 0) return XFALSE;
    if (XByteBuffer_Add(pOut, pChallenge, DIRECTGATE_KEYAUTH_CHALLENGE_SIZE) <= 0) return XFALSE;
    if (XByteBuffer_Add(pOut, pClientNonce, DIRECTGATE_KEYAUTH_NONCE_SIZE) <= 0) return XFALSE;
    if (XByteBuffer_Add(pOut, pagentNonce, DIRECTGATE_KEYAUTH_NONCE_SIZE) <= 0) return XFALSE;
    if (XByteBuffer_Add(pOut, pClientEphPub, DIRECTGATE_KEYAUTH_X25519_PUB_SIZE) <= 0) return XFALSE;
    if (XByteBuffer_Add(pOut, pAgentEphPub, DIRECTGATE_KEYAUTH_X25519_PUB_SIZE) <= 0) return XFALSE;

    return XTRUE;
}

xbool_t DirectGate_KeyAuth_IsClientAuthorized(const uint8_t *pClientPubKey,
                                              const char **pAuthorizedKeys,
                                              size_t nCount)
{
    XCHECK_NL((pClientPubKey != NULL), XFALSE);
    if (pAuthorizedKeys == NULL || nCount == 0) return XFALSE;

    xbool_t bFound = XFALSE;
    for (size_t i = 0; i < nCount; i++)
    {
        const char *pB64 = pAuthorizedKeys[i];
        if (!xstrused(pB64)) continue;

        uint8_t decoded[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
        size_t nDecLen = 0;

        if (!DirectGate_KeyAuth_Base64Decode(pB64, decoded, sizeof(decoded), &nDecLen) ||
            nDecLen != DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE)
        {
            OPENSSL_cleanse(decoded, sizeof(decoded));
            continue;
        }

        if (CRYPTO_memcmp(decoded, pClientPubKey, DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE) == 0)
            bFound = XTRUE;

        OPENSSL_cleanse(decoded, sizeof(decoded));
        /* Do not short-circuit - scan all entries in roughly constant time. */
    }

    return bFound;
}

xbool_t DirectGate_KeyAuth_AgentProcessHello(directgate_keyauth_t *pAuth,
                                             const char *pDeviceId,
                                             const char *pClientPubKeyB64,
                                             const char *pClientEphPubB64,
                                             const char *pClientNonceHex)
{
    XCHECK_NL((pAuth != NULL), XFALSE);
    XCHECK_NL((xstrused(pDeviceId)), XFALSE);
    XCHECK_NL((xstrused(pClientPubKeyB64)), XFALSE);
    XCHECK_NL((xstrused(pClientEphPubB64)), XFALSE);
    XCHECK_NL((xstrused(pClientNonceHex)), XFALSE);

    size_t nPubLen = 0;
    if (!DirectGate_KeyAuth_Base64Decode(pClientPubKeyB64,
        pAuth->clientPubKey, sizeof(pAuth->clientPubKey), &nPubLen) ||
        nPubLen != DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE) return XFALSE;

    size_t nEphLen = 0;
    if (!DirectGate_KeyAuth_Base64Decode(pClientEphPubB64,
        pAuth->peerEphPub, sizeof(pAuth->peerEphPub), &nEphLen) ||
        nEphLen != DIRECTGATE_KEYAUTH_X25519_PUB_SIZE) return XFALSE;

    size_t nNonceLen = 0;
    if (!DirectGate_KeyAuth_HexToBytes(pClientNonceHex,
        pAuth->peerNonce, sizeof(pAuth->peerNonce), &nNonceLen) ||
        nNonceLen != DIRECTGATE_KEYAUTH_NONCE_SIZE) return XFALSE;

    xstrncpy(pAuth->sDeviceId, sizeof(pAuth->sDeviceId), pDeviceId);
    pAuth->bIsAgent = XTRUE;
    pAuth->eState = DIRECTGATE_KEYAUTH_STATE_HELLO_RECEIVED;
    return XTRUE;
}

xbool_t DirectGate_KeyAuth_AgentBuildChallenge(directgate_keyauth_t *pAuth,
                                               const uint8_t *pagentIdentitySeed,
                                               const uint8_t *pagentIdentityPub,
                                               char *pAgentPubKeyB64Out, size_t nagentPubKeyB64Size,
                                               char *pAgentEphPubB64Out, size_t nagentEphPubB64Size,
                                               char *pagentNonceHexOut, size_t nagentNonceHexSize,
                                               char *pChallengeHexOut, size_t nChallengeHexSize,
                                               char *pAgentSigB64Out, size_t nagentSigB64Size)
{
    XCHECK_NL((pAuth != NULL), XFALSE);
    XCHECK_NL((pagentIdentitySeed != NULL && pagentIdentityPub != NULL), XFALSE);
    XCHECK_NL((pAuth->eState == DIRECTGATE_KEYAUTH_STATE_HELLO_RECEIVED), XFALSE);

    /* 1. Record agent public identity. */
    memcpy(pAuth->agentPubKey, pagentIdentityPub, DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE);

    /* 2. Generate agent ephemeral X25519 keypair. */
    if (!DirectGate_KeyAuth_X25519Generate(pAuth->localEphPub, pAuth->localEphPriv))
        return XFALSE;

    /* 3. Generate agent nonce + challenge. */
    if (RAND_bytes(pAuth->localNonce, sizeof(pAuth->localNonce)) != 1) return XFALSE;
    if (RAND_bytes(pAuth->challenge, sizeof(pAuth->challenge)) != 1) return XFALSE;

    /* 4. Build transcript and sign with agent identity. */
    xbyte_buffer_t transcript;
    XByteBuffer_Init(&transcript, 0, 0);

    if (!DirectGate_KeyAuth_BuildTranscript(&transcript, 'h',
            pAuth->sDeviceId, pAuth->clientPubKey, pAuth->agentPubKey,
            pAuth->challenge, pAuth->peerNonce /* clientNonce */,
            pAuth->localNonce /* agentNonce */,
            pAuth->peerEphPub /* clientEphPub */,
            pAuth->localEphPub /* agentEphPub */))
    {
        XByteBuffer_Clear(&transcript);
        return XFALSE;
    }

    uint8_t sig[DIRECTGATE_KEYAUTH_ED25519_SIG_SIZE];
    xbool_t bSigned = DirectGate_KeyAuth_Ed25519Sign(pagentIdentitySeed,
            transcript.pData, transcript.nUsed, sig);
    XByteBuffer_Clear(&transcript);
    if (!bSigned) return XFALSE;

    /* 5. Serialize outputs. */
    if (!DirectGate_KeyAuth_Base64Encode(pAuth->agentPubKey, DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE,
                                         pAgentPubKeyB64Out, nagentPubKeyB64Size)) return XFALSE;

    if (!DirectGate_KeyAuth_Base64Encode(pAuth->localEphPub, DIRECTGATE_KEYAUTH_X25519_PUB_SIZE,
                                         pAgentEphPubB64Out, nagentEphPubB64Size)) return XFALSE;

    if (!DirectGate_KeyAuth_BytesToHex(pAuth->localNonce, DIRECTGATE_KEYAUTH_NONCE_SIZE,
                                       pagentNonceHexOut, nagentNonceHexSize)) return XFALSE;

    if (!DirectGate_KeyAuth_BytesToHex(pAuth->challenge, DIRECTGATE_KEYAUTH_CHALLENGE_SIZE,
                                       pChallengeHexOut, nChallengeHexSize)) return XFALSE;

    if (!DirectGate_KeyAuth_Base64Encode(sig, DIRECTGATE_KEYAUTH_ED25519_SIG_SIZE,
                                         pAgentSigB64Out, nagentSigB64Size)) return XFALSE;

    pAuth->eState = DIRECTGATE_KEYAUTH_STATE_CHALLENGE_SENT;
    return XTRUE;
}

xbool_t DirectGate_KeyAuth_AgentVerifyProof(directgate_keyauth_t *pAuth,
                                        const char *pClientSigB64)
{
    XCHECK_NL((pAuth != NULL), XFALSE);
    XCHECK_NL((xstrused(pClientSigB64)), XFALSE);
    XCHECK_NL((pAuth->eState == DIRECTGATE_KEYAUTH_STATE_CHALLENGE_SENT), XFALSE);

    uint8_t sig[DIRECTGATE_KEYAUTH_ED25519_SIG_SIZE];
    size_t nSigLen = 0;
    if (!DirectGate_KeyAuth_Base64Decode(pClientSigB64, sig, sizeof(sig), &nSigLen) ||
        nSigLen != DIRECTGATE_KEYAUTH_ED25519_SIG_SIZE)
    {
        pAuth->eState = DIRECTGATE_KEYAUTH_STATE_FAILED;
        return XFALSE;
    }

    xbyte_buffer_t transcript;
    XByteBuffer_Init(&transcript, 0, 0);

    if (!DirectGate_KeyAuth_BuildTranscript(&transcript, 'c',
        pAuth->sDeviceId, pAuth->clientPubKey, pAuth->agentPubKey,
        pAuth->challenge, pAuth->peerNonce, pAuth->localNonce,
        pAuth->peerEphPub, pAuth->localEphPub))
    {
        XByteBuffer_Clear(&transcript);
        pAuth->eState = DIRECTGATE_KEYAUTH_STATE_FAILED;
        return XFALSE;
    }

    xbool_t bOk = DirectGate_KeyAuth_Ed25519Verify(pAuth->clientPubKey,
        transcript.pData, transcript.nUsed, sig);
    XByteBuffer_Clear(&transcript);

    if (!bOk)
    {
        pAuth->eState = DIRECTGATE_KEYAUTH_STATE_FAILED;
        return XFALSE;
    }

    pAuth->eState = DIRECTGATE_KEYAUTH_STATE_AUTHENTICATED;
    return XTRUE;
}

xbool_t DirectGate_KeyAuth_DeriveShared(directgate_keyauth_t *pAuth)
{
    XCHECK_NL((pAuth != NULL), XFALSE);
    XCHECK_NL((pAuth->eState == DIRECTGATE_KEYAUTH_STATE_AUTHENTICATED), XFALSE);

    if (!DirectGate_KeyAuth_X25519Derive(pAuth->localEphPriv, pAuth->peerEphPub,
                                      pAuth->sharedSecret))
    {
        OPENSSL_cleanse(pAuth->sharedSecret, sizeof(pAuth->sharedSecret));
        return XFALSE;
    }

    /* Ephemeral private key has served its purpose; wipe it. */
    OPENSSL_cleanse(pAuth->localEphPriv, sizeof(pAuth->localEphPriv));
    pAuth->bHaveSharedSecret = XTRUE;
    return XTRUE;
}

void DirectGate_KeyAuth_KeyCleanse(directgate_client_key_t *pKey)
{
    XCHECK_VOID_NL((pKey != NULL));
    OPENSSL_cleanse(pKey, sizeof(*pKey));
}

xbool_t DirectGate_KeyAuth_KeyGenerate(directgate_client_key_t *pKey)
{
    XCHECK_NL((pKey != NULL), XFALSE);
    memset(pKey, 0, sizeof(*pKey));

    if (!DirectGate_KeyAuth_Ed25519Generate(pKey->clientPub, pKey->clientSeed))
    {
        DirectGate_KeyAuth_KeyCleanse(pKey);
        return XFALSE;
    }

    return XTRUE;
}

static xbool_t DirectGate_KeyAuth_DecodeFixed(const char *pB64, uint8_t *pOut,
                                              size_t nExpected, const char *pLabel,
                                              const char *pPath)
{
    size_t nLength = 0;

    if (!DirectGate_KeyAuth_Base64Decode(pB64, pOut, nExpected, &nLength) || nLength != nExpected)
    {
        xloge("Client key file has an invalid %s: path(%s)", pLabel, pPath);
        return XFALSE;
    }

    return XTRUE;
}

xbool_t DirectGate_KeyAuth_KeyLoad(directgate_client_key_t *pKey, const char *pPath)
{
    XCHECK_NL((pKey != NULL), XFALSE);
    memset(pKey, 0, sizeof(*pKey));
    XCHECK_NL((xstrused(pPath)), XFALSE);

    xbyte_buffer_t buffer;
    if (XPath_LoadBuffer(pPath, &buffer) <= 0)
    {
        xloge("Failed to load client key file: path(%s), errno(%d)", pPath, errno);
        return XFALSE;
    }

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, (const char*)buffer.pData, buffer.nUsed))
    {
        char sError[XSTR_TINY];
        XJSON_GetErrorStr(&json, sError, sizeof(sError));
        xloge("Failed to parse client key file: path(%s), error(%s)", pPath, sError);

        OPENSSL_cleanse(buffer.pData, buffer.nUsed);
        XByteBuffer_Clear(&buffer);
        XJSON_Destroy(&json);
        return XFALSE;
    }

    xjson_obj_t *pRoot = json.pRootObj;
    const char *pType = XJSON_GetString(XJSON_GetObject(pRoot, "type"));
    const char *pClientPub = XJSON_GetString(XJSON_GetObject(pRoot, "clientPub"));
    const char *pClientSeed = XJSON_GetString(XJSON_GetObject(pRoot, "clientSeed"));

    xbool_t bOk = XFALSE;

    if (!xstrused(pType) || !xstrcmp(pType, DIRECTGATE_CLIENT_KEY_FILE_TYPE))
    {
        xloge("Unsupported client key file type: path(%s), type(%s)",
            pPath, xstrused(pType) ? pType : "(null)");
    }
    else if (!xstrused(pClientPub) || !xstrused(pClientSeed))
    {
        xloge("Client key file is missing clientPub/clientSeed: path(%s)", pPath);
    }
    else if (DirectGate_KeyAuth_DecodeFixed(pClientPub, pKey->clientPub, sizeof(pKey->clientPub), "clientPub", pPath) &&
             DirectGate_KeyAuth_DecodeFixed(pClientSeed, pKey->clientSeed, sizeof(pKey->clientSeed), "clientSeed", pPath))
    {
        /* A seed that does not produce the recorded public key means the file
         * was edited or corrupted; using it would fail authentication with a
         * far less obvious error at the other end of the handshake. */
        uint8_t derived[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];

        if (!DirectGate_KeyAuth_Ed25519DerivePub(pKey->clientSeed, derived))
            xloge("Failed to derive the public key from the client seed: path(%s)", pPath);
        else if (CRYPTO_memcmp(derived, pKey->clientPub, sizeof(derived)) != 0)
            xloge("Client key file seed does not match its public key: path(%s)", pPath);
        else bOk = XTRUE;

        OPENSSL_cleanse(derived, sizeof(derived));
    }

    if (!bOk) DirectGate_KeyAuth_KeyCleanse(pKey);

    OPENSSL_cleanse(buffer.pData, buffer.nUsed);
    XByteBuffer_Clear(&buffer);
    XJSON_Destroy(&json);
    return bOk;
}

xbool_t DirectGate_KeyAuth_KeySave(const directgate_client_key_t *pKey, const char *pPath)
{
    XCHECK_NL((pKey != NULL), XFALSE);
    XCHECK_NL((xstrused(pPath)), XFALSE);

    if (!DirectGate_EnsurePrivateFileParent(pPath))
    {
        xloge("Failed to create private client key directory: path(%s), errno(%d)", pPath, errno);
        return XFALSE;
    }

    char sPubB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sSeedB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];

    if (!DirectGate_KeyAuth_Base64Encode(pKey->clientPub, sizeof(pKey->clientPub), sPubB64, sizeof(sPubB64)) ||
        !DirectGate_KeyAuth_Base64Encode(pKey->clientSeed, sizeof(pKey->clientSeed), sSeedB64, sizeof(sSeedB64)))
    {
        OPENSSL_cleanse(sSeedB64, sizeof(sSeedB64));
        xloge("Failed to encode the client keypair: path(%s)", pPath);
        return XFALSE;
    }

    xjson_obj_t *pRoot = XJSON_NewObject(NULL, NULL, XFALSE);
    if (pRoot == NULL)
    {
        OPENSSL_cleanse(sSeedB64, sizeof(sSeedB64));
        xloge("Failed to allocate the client key JSON: path(%s)", pPath);
        return XFALSE;
    }

    XJSON_AddString(pRoot, "type", DIRECTGATE_CLIENT_KEY_FILE_TYPE);
    XJSON_AddString(pRoot, "clientPub", sPubB64);
    XJSON_AddString(pRoot, "clientSeed", sSeedB64);

    size_t nLength = 0;
    char *pDump = XJSON_DumpObj(pRoot, 2, &nLength);

    XJSON_FreeObject(pRoot);
    OPENSSL_cleanse(sSeedB64, sizeof(sSeedB64));

    if (pDump == NULL || !nLength)
    {
        free(pDump);
        xloge("Failed to serialize the client key JSON: path(%s)", pPath);
        return XFALSE;
    }

    xbool_t bWrote = DirectGate_WritePrivateFile(pPath, (uint8_t*)pDump, nLength);

    OPENSSL_cleanse(pDump, nLength);
    free(pDump);

    if (!bWrote) xloge("Failed to write the client key file: path(%s), errno(%d)", pPath, errno);
    return bWrote;
}

xbool_t DirectGate_KeyAuth_ClientInit(directgate_keyauth_t *pAuth,
                                      const char *pDeviceId,
                                      const directgate_client_key_t *pKey,
                                      const char *pExpectedAgentPubB64)
{
    XCHECK_NL((pAuth != NULL && pKey != NULL), XFALSE);
    XCHECK_NL((xstrused(pDeviceId)), XFALSE);
    XCHECK_NL((xstrused(pExpectedAgentPubB64)), XFALSE);

    DirectGate_KeyAuth_Init(pAuth);

    /* The pinned host identity. Anything else on the wire is rejected. */
    size_t nPubLen = 0;
    if (!DirectGate_KeyAuth_Base64Decode(pExpectedAgentPubB64,
        pAuth->agentPubKey, sizeof(pAuth->agentPubKey), &nPubLen) ||
        nPubLen != DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE) return XFALSE;

    memcpy(pAuth->clientPubKey, pKey->clientPub, sizeof(pAuth->clientPubKey));
    xstrncpy(pAuth->sDeviceId, sizeof(pAuth->sDeviceId), pDeviceId);

    pAuth->bIsAgent = XFALSE;
    pAuth->eState = DIRECTGATE_KEYAUTH_STATE_IDLE;
    return XTRUE;
}

xbool_t DirectGate_KeyAuth_ClientBuildHello(directgate_keyauth_t *pAuth,
                                            char *pClientPubB64Out, size_t nClientPubB64Size,
                                            char *pClientEphB64Out, size_t nClientEphB64Size,
                                            char *pClientNonceHexOut, size_t nClientNonceHexSize)
{
    XCHECK_NL((pAuth != NULL), XFALSE);
    XCHECK_NL((pClientPubB64Out != NULL && pClientEphB64Out != NULL), XFALSE);
    XCHECK_NL((pClientNonceHexOut != NULL), XFALSE);
    XCHECK_NL((pAuth->eState == DIRECTGATE_KEYAUTH_STATE_IDLE), XFALSE);

    if (!DirectGate_KeyAuth_X25519Generate(pAuth->localEphPub, pAuth->localEphPriv)) return XFALSE;
    if (RAND_bytes(pAuth->localNonce, sizeof(pAuth->localNonce)) != 1) return XFALSE;

    if (!DirectGate_KeyAuth_Base64Encode(pAuth->clientPubKey, sizeof(pAuth->clientPubKey), pClientPubB64Out, nClientPubB64Size) ||
        !DirectGate_KeyAuth_Base64Encode(pAuth->localEphPub, sizeof(pAuth->localEphPub), pClientEphB64Out, nClientEphB64Size) ||
        !DirectGate_KeyAuth_BytesToHex(pAuth->localNonce, sizeof(pAuth->localNonce), pClientNonceHexOut, nClientNonceHexSize))
            return XFALSE;

    pAuth->eState = DIRECTGATE_KEYAUTH_STATE_HELLO_RECEIVED;
    return XTRUE;
}

xbool_t DirectGate_KeyAuth_ClientProcessChallenge(directgate_keyauth_t *pAuth,
                                                  const directgate_client_key_t *pKey,
                                                  const char *pAgentPubKeyB64,
                                                  const char *pAgentEphPubB64,
                                                  const char *pAgentNonceHex,
                                                  const char *pChallengeHex,
                                                  const char *pAgentSigB64,
                                                  char *pClientSigB64Out, size_t nClientSigB64Size)
{
    XCHECK_NL((pAuth != NULL && pKey != NULL && pClientSigB64Out != NULL), XFALSE);
    XCHECK_NL((pAuth->eState == DIRECTGATE_KEYAUTH_STATE_HELLO_RECEIVED), XFALSE);

    if (!xstrused(pAgentPubKeyB64) || !xstrused(pAgentEphPubB64) ||
        !xstrused(pAgentNonceHex) || !xstrused(pChallengeHex) || !xstrused(pAgentSigB64))
    {
        xloge("KeyAuth: Incomplete key challenge");
        pAuth->eState = DIRECTGATE_KEYAUTH_STATE_FAILED;
        return XFALSE;
    }

    uint8_t agentPub[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    size_t nLength = 0;

    if (!DirectGate_KeyAuth_Base64Decode(pAgentPubKeyB64, agentPub, sizeof(agentPub), &nLength) || nLength != sizeof(agentPub))
    {
        xloge("KeyAuth: Invalid agent public key in challenge");
        pAuth->eState = DIRECTGATE_KEYAUTH_STATE_FAILED;
        return XFALSE;
    }

    /*
        Pin the host identity: the backend published this device's agentPub
        over TLS, so a host presenting anything else is not the device we
        asked for, however well formed the rest of the challenge is.
    */
    if (CRYPTO_memcmp(agentPub, pAuth->agentPubKey, sizeof(agentPub)) != 0)
    {
        xloge("KeyAuth: Host identity mismatch, refusing to authenticate");
        pAuth->eState = DIRECTGATE_KEYAUTH_STATE_FAILED;
        return XFALSE;
    }

    if (!DirectGate_KeyAuth_Base64Decode(pAgentEphPubB64, pAuth->peerEphPub, sizeof(pAuth->peerEphPub), &nLength) ||
        nLength != DIRECTGATE_KEYAUTH_X25519_PUB_SIZE ||
        !DirectGate_KeyAuth_HexToBytes(pAgentNonceHex, pAuth->peerNonce, sizeof(pAuth->peerNonce), &nLength) ||
        nLength != DIRECTGATE_KEYAUTH_NONCE_SIZE ||
        !DirectGate_KeyAuth_HexToBytes(pChallengeHex, pAuth->challenge, sizeof(pAuth->challenge), &nLength) ||
        nLength != DIRECTGATE_KEYAUTH_CHALLENGE_SIZE)
    {
        xloge("KeyAuth: Malformed key challenge fields");
        pAuth->eState = DIRECTGATE_KEYAUTH_STATE_FAILED;
        return XFALSE;
    }

    uint8_t agentSig[DIRECTGATE_KEYAUTH_ED25519_SIG_SIZE];
    if (!DirectGate_KeyAuth_Base64Decode(pAgentSigB64, agentSig, sizeof(agentSig), &nLength) || nLength != sizeof(agentSig))
    {
        xloge("KeyAuth: Invalid agent signature in challenge");
        pAuth->eState = DIRECTGATE_KEYAUTH_STATE_FAILED;
        return XFALSE;
    }

    xbyte_buffer_t transcript;
    XByteBuffer_Init(&transcript, 0, 0);

    if (!DirectGate_KeyAuth_BuildTranscript(&transcript, 'h',
            pAuth->sDeviceId, pAuth->clientPubKey, pAuth->agentPubKey,
            pAuth->challenge, pAuth->localNonce /* clientNonce */,
            pAuth->peerNonce /* agentNonce */,
            pAuth->localEphPub /* clientEphPub */,
            pAuth->peerEphPub /* agentEphPub */))
    {
        XByteBuffer_Clear(&transcript);
        pAuth->eState = DIRECTGATE_KEYAUTH_STATE_FAILED;
        return XFALSE;
    }

    xbool_t bVerified = DirectGate_KeyAuth_Ed25519Verify(pAuth->agentPubKey, transcript.pData, transcript.nUsed, agentSig);
    XByteBuffer_Clear(&transcript);

    if (!bVerified)
    {
        xloge("KeyAuth: Host signature verification failed");
        pAuth->eState = DIRECTGATE_KEYAUTH_STATE_FAILED;
        return XFALSE;
    }

    XByteBuffer_Init(&transcript, 0, 0);

    if (!DirectGate_KeyAuth_BuildTranscript(&transcript, 'c',
            pAuth->sDeviceId, pAuth->clientPubKey, pAuth->agentPubKey,
            pAuth->challenge, pAuth->localNonce, pAuth->peerNonce,
            pAuth->localEphPub, pAuth->peerEphPub))
    {
        XByteBuffer_Clear(&transcript);
        pAuth->eState = DIRECTGATE_KEYAUTH_STATE_FAILED;
        return XFALSE;
    }

    uint8_t clientSig[DIRECTGATE_KEYAUTH_ED25519_SIG_SIZE];
    xbool_t bSigned = DirectGate_KeyAuth_Ed25519Sign(pKey->clientSeed, transcript.pData, transcript.nUsed, clientSig);
    XByteBuffer_Clear(&transcript);

    if (!bSigned || !DirectGate_KeyAuth_Base64Encode(clientSig, sizeof(clientSig), pClientSigB64Out, nClientSigB64Size))
    {
        OPENSSL_cleanse(clientSig, sizeof(clientSig));
        xloge("KeyAuth: Failed to sign the client transcript");
        pAuth->eState = DIRECTGATE_KEYAUTH_STATE_FAILED;
        return XFALSE;
    }

    OPENSSL_cleanse(clientSig, sizeof(clientSig));
    pAuth->eState = DIRECTGATE_KEYAUTH_STATE_CHALLENGE_SENT;
    return XTRUE;
}

/*!
 * The client learns the handshake succeeded from the host's auth result
 * rather than by verifying a proof of its own, so the transition to
 * authenticated is explicit before the shared secret may be derived.
 */
xbool_t DirectGate_KeyAuth_ClientAccept(directgate_keyauth_t *pAuth)
{
    XCHECK_NL((pAuth != NULL), XFALSE);
    XCHECK_NL((pAuth->eState == DIRECTGATE_KEYAUTH_STATE_CHALLENGE_SENT), XFALSE);

    pAuth->eState = DIRECTGATE_KEYAUTH_STATE_AUTHENTICATED;
    return XTRUE;
}
