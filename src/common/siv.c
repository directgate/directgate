/*!
 * @file directgate-agent/src/common/siv.c
 * @brief AES-SIV backend abstraction (OpenSSL when available, libxutils otherwise).
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

#include "siv.h"
#include <limits.h>

/* SIV synthetic tag is one AES block, prepended to the ciphertext. */
#define XSIV_TAG_SIZE   XAES_BLOCK_SIZE
/* Per-message random nonce (one AES block) prepended to the whole output. It is
   the S2V associated-data string that makes the scheme non-deterministic. */
#define XSIV_NONCE_SIZE XAES_BLOCK_SIZE
/* Largest per-half key we accept (AES-256 -> 32-byte MAC + 32-byte CTR). */
#define XSIV_MAX_HALF   XAES_KEY_LENGTH

/* The EVP AES-SIV cipher, EVP_*Init_ex2 and EVP_CIPHER_fetch all arrived in
   OpenSSL 3.0. LibreSSL may advertise a 3.x version number without shipping
   any of them, so exclude it explicitly; the libxutils backend covers it.

   On modern platforms, DirectGate uses OpenSSL's native AES-SIV implementation
   by default. The libxutils AES-SIV backend exists primarily as a compatibility
   fallback for legacy systems where the required OpenSSL functionality is not
   available.

   To reduce the risk of implementation drift, the libxutils AES-SIV code is
   continuously validated in CI against OpenSSL test vectors and behavior.
   Nevertheless, preference is always given to OpenSSL's widely deployed,
   extensively reviewed, and independently audited implementation whenever it
   is available on the target system. See tests/crypto_siv_openssl_smoke.c
 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
#define XSIV_HAVE_OPENSSL 1
#endif

/* ------------------------------------------------------------------------- */
/* libxutils (portable) backend                                              */
/* ------------------------------------------------------------------------- */

/* Writes `siv_tag || ciphertext` (XSIV_TAG_SIZE + nLength bytes) into pDst. The
   nonce is the S2V associated-data string; pDst must be caller-allocated. */
static xbool_t DirectGate_SIV_XUtilsEncrypt(const uint8_t *pCmacKey, const uint8_t *pCtrKey, size_t nKeyBits,
                                            const uint8_t *pNonce, const uint8_t *pData, size_t nLength, uint8_t *pDst)
{
    xaes_key_t key;
    XAES_InitSIVKey(&key, pCmacKey, pCtrKey, nKeyBits);

    xaes_t ctx;
    XCHECK((XAES_Init(&ctx, &key, XAES_MODE_SIV_NONCE) >= 0), XFALSE);
    XAES_SetSIVNonce(&ctx, pNonce, XSIV_NONCE_SIZE);

    size_t nEncLen = nLength;
    uint8_t *pEncrypted = XAES_Encrypt(&ctx, pData, &nEncLen);
    OPENSSL_cleanse(&key, sizeof(key));
    OPENSSL_cleanse(&ctx, sizeof(ctx));
    XCHECK_NL((pEncrypted != NULL), XFALSE);

    memcpy(pDst, pEncrypted, nEncLen);
    free(pEncrypted);
    return XTRUE;
}

static uint8_t* DirectGate_SIV_XUtilsDecrypt(const uint8_t *pCmacKey, const uint8_t *pCtrKey, size_t nKeyBits,
                                             const uint8_t *pNonce, const uint8_t *pData, size_t nLength, size_t *pOutLen)
{
    xaes_key_t key;
    XAES_InitSIVKey(&key, pCmacKey, pCtrKey, nKeyBits);

    xaes_t ctx;
    XCHECK((XAES_Init(&ctx, &key, XAES_MODE_SIV_NONCE) >= 0), NULL);
    XAES_SetSIVNonce(&ctx, pNonce, XSIV_NONCE_SIZE);

    size_t nDecLen = nLength;
    uint8_t *pDecrypted = XAES_Decrypt(&ctx, pData, &nDecLen);
    OPENSSL_cleanse(&key, sizeof(key));
    OPENSSL_cleanse(&ctx, sizeof(ctx));
    XCHECK_NL((pDecrypted != NULL), NULL);

    *pOutLen = nDecLen;
    return pDecrypted;
}

/* ------------------------------------------------------------------------- */
/* OpenSSL EVP backend                                                       */
/* ------------------------------------------------------------------------- */

#ifdef XSIV_HAVE_OPENSSL
/* OpenSSL takes the SIV key as a single MAC||CTR buffer. */
static xbool_t DirectGate_SIV_JoinKey(uint8_t *pFullKey, size_t nFullSize, const uint8_t *pCmacKey,
                                      const uint8_t *pCtrKey, size_t nKeyBits, size_t *pHalfLen)
{
    size_t nHalf = nKeyBits / 8;
    XCHECK((nHalf > 0 && nHalf <= XSIV_MAX_HALF && nHalf * 2 <= nFullSize), XFALSE);
    memcpy(pFullKey, pCmacKey, nHalf);
    memcpy(pFullKey + nHalf, pCtrKey, nHalf);
    *pHalfLen = nHalf;
    return XTRUE;
}

/* OpenSSL >= 3.0 normally ships AES-SIV in the default provider. Publish the
   cached probe through OpenSSL's once primitive: unsynchronized reads/writes
   of the cached integer are a data race even if both probes agree.

   The fetched ciphers are kept for the life of the process. A fetch is a
   provider lookup under a lock; doing one for every encrypt and every decrypt
   was most of the cost of a small message - a keystroke, a pointer move -
   and serialized every thread that encrypts. A fetched EVP_CIPHER is
   immutable and reference counted, so sharing it between threads is safe. */
static CRYPTO_ONCE sOpenSSLOnce = CRYPTO_ONCE_STATIC_INIT;
static EVP_CIPHER *sOpenSSLCiphers[3] = { NULL, NULL, NULL };
static int sOpenSSLReady = 0;

static void DirectGate_SIV_ProbeOpenSSL(void)
{
    sOpenSSLCiphers[0] = EVP_CIPHER_fetch(NULL, "AES-128-SIV", NULL);
    sOpenSSLCiphers[1] = EVP_CIPHER_fetch(NULL, "AES-192-SIV", NULL);
    sOpenSSLCiphers[2] = EVP_CIPHER_fetch(NULL, "AES-256-SIV", NULL);
    sOpenSSLReady = (sOpenSSLCiphers[2] != NULL);
}

static EVP_CIPHER* DirectGate_SIV_Cipher(size_t nKeyBits)
{
    switch (nKeyBits)
    {
        case 128: return sOpenSSLCiphers[0];
        case 192: return sOpenSSLCiphers[1];
        case 256: return sOpenSSLCiphers[2];
        default:  return NULL;
    }
}

static xbool_t DirectGate_SIV_OpenSSLReady(void)
{
    return CRYPTO_THREAD_run_once(&sOpenSSLOnce, DirectGate_SIV_ProbeOpenSSL) &&
        sOpenSSLReady ? XTRUE : XFALSE;
}

/* Writes `siv_tag || ciphertext` (XSIV_TAG_SIZE + nLength bytes) into pDst. The
   nonce is fed as the single associated-data string so OpenSSL's S2V matches the
   libxutils and web backends byte-for-byte. pDst must be caller-allocated. */
static xbool_t DirectGate_SIV_OpenSSLEncrypt(const uint8_t *pCmacKey, const uint8_t *pCtrKey, size_t nKeyBits,
                                             const uint8_t *pNonce, const uint8_t *pData, size_t nLength, uint8_t *pDst)
{
    EVP_CIPHER *pCipher = DirectGate_SIV_Cipher(nKeyBits);
    XCHECK((pCipher != NULL && nLength <= INT_MAX), XFALSE);

    uint8_t fullKey[XSIV_MAX_HALF * 2];
    size_t nHalf = 0;
    XCHECK(DirectGate_SIV_JoinKey(fullKey, sizeof(fullKey), pCmacKey, pCtrKey, nKeyBits, &nHalf), XFALSE);

    EVP_CIPHER_CTX *pCtx = EVP_CIPHER_CTX_new();
    int nWritten = 0, nFinal = 0, nAad = 0;
    xbool_t bOk = XFALSE;

    if (pCipher != NULL && pCtx != NULL &&
        EVP_EncryptInit_ex2(pCtx, pCipher, fullKey, NULL, NULL) == 1 &&
        EVP_EncryptUpdate(pCtx, NULL, &nAad, pNonce, XSIV_NONCE_SIZE) == 1 &&
        EVP_EncryptUpdate(pCtx, pDst + XSIV_TAG_SIZE, &nWritten, pData, (int)nLength) == 1 &&
        EVP_EncryptFinal_ex(pCtx, pDst + XSIV_TAG_SIZE + nWritten, &nFinal) == 1 &&
        (size_t)(nWritten + nFinal) == nLength &&
        EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_AEAD_GET_TAG, XSIV_TAG_SIZE, pDst) == 1)
    {
        bOk = XTRUE;
    }

    EVP_CIPHER_CTX_free(pCtx);
    OPENSSL_cleanse(fullKey, sizeof(fullKey));
    return bOk;
}

/* pData is `siv_tag || ciphertext` (nLength bytes); pNonce is the associated
   data. Returns malloc'd plaintext, or NULL on tag mismatch. */
static uint8_t* DirectGate_SIV_OpenSSLDecrypt(const uint8_t *pCmacKey, const uint8_t *pCtrKey, size_t nKeyBits,
                                              const uint8_t *pNonce, const uint8_t *pData, size_t nLength, size_t *pOutLen)
{
    EVP_CIPHER *pCipher = DirectGate_SIV_Cipher(nKeyBits);
    XCHECK((pCipher != NULL && nLength > XSIV_TAG_SIZE && nLength - XSIV_TAG_SIZE <= INT_MAX), NULL);

    uint8_t fullKey[XSIV_MAX_HALF * 2];
    size_t nHalf = 0;
    XCHECK(DirectGate_SIV_JoinKey(fullKey, sizeof(fullKey), pCmacKey, pCtrKey, nKeyBits, &nHalf), NULL);

    size_t nCipherLen = nLength - XSIV_TAG_SIZE;
    EVP_CIPHER_CTX *pCtx = EVP_CIPHER_CTX_new();
    uint8_t *pOut = malloc(nCipherLen);
    int nWritten = 0, nFinal = 0, nAad = 0;

    if (pCipher == NULL || pCtx == NULL || pOut == NULL ||
        EVP_DecryptInit_ex2(pCtx, pCipher, fullKey, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_AEAD_SET_TAG, XSIV_TAG_SIZE, (void*)pData) != 1 ||
        EVP_DecryptUpdate(pCtx, NULL, &nAad, pNonce, XSIV_NONCE_SIZE) != 1 ||
        EVP_DecryptUpdate(pCtx, pOut, &nWritten, pData + XSIV_TAG_SIZE, (int)nCipherLen) != 1 ||
        EVP_DecryptFinal_ex(pCtx, pOut + nWritten, &nFinal) != 1 ||
        (size_t)(nWritten + nFinal) != nCipherLen)
    {
        free(pOut);
        pOut = NULL;
    }
    else *pOutLen = nCipherLen;

    EVP_CIPHER_CTX_free(pCtx);
    OPENSSL_cleanse(fullKey, sizeof(fullKey));
    return pOut;
}
#endif /* XSIV_HAVE_OPENSSL */

/* ------------------------------------------------------------------------- */
/* Public dispatch                                                           */
/* ------------------------------------------------------------------------- */

uint8_t* DirectGate_SIV_Encrypt(const uint8_t *pCmacKey, const uint8_t *pCtrKey, size_t nKeyBits,
                                const uint8_t *pData, size_t nLength, size_t *pOutLen)
{
    if (pOutLen != NULL) *pOutLen = 0;
    XCHECK((nKeyBits == 128 || nKeyBits == 192 || nKeyBits == 256), NULL);
    XCHECK((pCmacKey != NULL && pCtrKey != NULL), NULL);
    XCHECK((pData != NULL && nLength > 0), NULL);
    XCHECK((pOutLen != NULL), NULL);
    XCHECK((nLength <= SIZE_MAX - XSIV_NONCE_SIZE - XSIV_TAG_SIZE), NULL);

    /* Output layout: nonce || siv_tag || ciphertext. The backend writes the
       siv_tag||ciphertext directly after the nonce, so the hot OpenSSL path
       allocates and copies exactly once. */
    size_t nTotal = XSIV_NONCE_SIZE + XSIV_TAG_SIZE + nLength;
    uint8_t *pOut = malloc(nTotal);
    XCHECK((pOut != NULL), NULL);

    /*
     * Fresh random nonce is generated for every message as a defense-in-depth
     * measure. The AES-SIV mode itself is chosen because it is misuse-resistant.
     * Accidental nonce reuse does not break confidentiality in the catastrophic
     * way it would for conventional AEAD modes such as GCM or ChaCha20-Poly1305.
     *
     * In addition, every encrypted packet carries a strictly monotonically
     * increasing counter (CC) which is authenticated and incorporated into
     * the SIV computation. As a result, even if a nonce were ever repeated,
     * distinct packets would still produce distinct ciphertexts due to the
     * changing authenticated packet metadata.
     *
     * The random nonce therefore serves as an additional independent layer
     * against ciphertext repetition and protocol implementation mistakes,
     * rather than being the sole mechanism relied upon for security.
     */
    XCHECK_FREE((RAND_bytes(pOut, XSIV_NONCE_SIZE) == 1), pOut, NULL);

    xbool_t bOk;
#ifdef XSIV_HAVE_OPENSSL
    if (DirectGate_SIV_OpenSSLReady())
    {
        bOk = DirectGate_SIV_OpenSSLEncrypt(pCmacKey, pCtrKey, nKeyBits, pOut, pData, nLength, pOut + XSIV_NONCE_SIZE);
        XCHECK_FREE(bOk, pOut, NULL);

        *pOutLen = nTotal;
        return pOut;
    }
#endif

    bOk = DirectGate_SIV_XUtilsEncrypt(pCmacKey, pCtrKey, nKeyBits, pOut, pData, nLength, pOut + XSIV_NONCE_SIZE);
    XCHECK_FREE(bOk, pOut, NULL);

    *pOutLen = nTotal;
    return pOut;
}

uint8_t* DirectGate_SIV_Decrypt(const uint8_t *pCmacKey, const uint8_t *pCtrKey, size_t nKeyBits,
                                const uint8_t *pData, size_t nLength, size_t *pOutLen)
{
    if (pOutLen != NULL) *pOutLen = 0;
    XCHECK((nKeyBits == 128 || nKeyBits == 192 || nKeyBits == 256), NULL);
    XCHECK((pCmacKey != NULL && pCtrKey != NULL), NULL);

    /* Need nonce + tag + at least one ciphertext byte. */
    XCHECK((pData != NULL && nLength > XSIV_NONCE_SIZE + XSIV_TAG_SIZE), NULL);
    XCHECK((pOutLen != NULL), NULL);

    const uint8_t *pNonce = pData;
    const uint8_t *pBody  = pData + XSIV_NONCE_SIZE; /* siv_tag || ciphertext */
    size_t nBodyLen = nLength - XSIV_NONCE_SIZE;

#ifdef XSIV_HAVE_OPENSSL
    if (DirectGate_SIV_OpenSSLReady())
        return DirectGate_SIV_OpenSSLDecrypt(pCmacKey, pCtrKey, nKeyBits, pNonce, pBody, nBodyLen, pOutLen);
#endif

    return DirectGate_SIV_XUtilsDecrypt(pCmacKey, pCtrKey, nKeyBits, pNonce, pBody, nBodyLen, pOutLen);
}
