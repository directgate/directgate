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
