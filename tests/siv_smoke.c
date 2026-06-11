/* AES-SIV (RFC 5297) wrapper behavior tests.
 *
 * Byte-exact S2V/CTR correctness is verified differentially against
 * OpenSSL in crypto_siv_openssl_smoke; this test locks the wrapper
 * contract: wire layout, roundtrips across payload size classes, strict
 * tamper rejection in every region of the message, key separation and
 * malformed-length rejection. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "src/common/siv.h"
#include "src/common/e2e.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "siv_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#define SIV_KEY_BITS   256
#define SIV_KEY_SIZE   32
#define SIV_OVERHEAD   32 /* nonce(16) || siv(16) */

static int roundtrip(const uint8_t *pCmacKey, const uint8_t *pCtrKey,
                     size_t nLen, const char *pLabel)
{
    uint8_t *pPlain = (uint8_t*)malloc(nLen ? nLen : 1);
    CHECK(pPlain != NULL, "alloc plain");

    for (size_t i = 0; i < nLen; i++)
        pPlain[i] = (uint8_t)(i * 7 + 3);

    size_t nEncLen = 0;
    uint8_t *pEnc = DirectGate_SIV_Encrypt(pCmacKey, pCtrKey, SIV_KEY_BITS,
        pPlain, nLen, &nEncLen);

    if (pEnc == NULL || nEncLen != nLen + SIV_OVERHEAD) {
        fprintf(stderr, "siv_smoke: %s encrypt failed: len(%zu)\n", pLabel, nLen);
        free(pPlain);
        return 1;
    }

    size_t nDecLen = 0;
    uint8_t *pDec = DirectGate_SIV_Decrypt(pCmacKey, pCtrKey, SIV_KEY_BITS,
        pEnc, nEncLen, &nDecLen);

    if (pDec == NULL || nDecLen != nLen ||
        (nLen && memcmp(pDec, pPlain, nLen) != 0)) {
        fprintf(stderr, "siv_smoke: %s decrypt mismatch: len(%zu)\n", pLabel, nLen);
        free(pPlain);
        free(pEnc);
        free(pDec);
        return 1;
    }

    free(pPlain);
    free(pEnc);
    free(pDec);
    return 0;
}

int main(void)
{
    uint8_t cmacKey[SIV_KEY_SIZE];
    uint8_t ctrKey[SIV_KEY_SIZE];
    uint8_t otherKey[SIV_KEY_SIZE];

    for (size_t i = 0; i < sizeof(cmacKey); i++) {
        cmacKey[i] = (uint8_t)(0x10 + i);
        ctrKey[i] = (uint8_t)(0x60 + i);
        otherKey[i] = (uint8_t)(0xb0 + i);
    }

    /* Size classes around the AES block boundary plus a bulk payload:
       1 byte, block-1, block, block+1, two blocks, 4 KB (PTY chunk size) */
    const size_t sizes[] = { 1, 15, 16, 17, 32, 4096 };
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
        CHECK(roundtrip(cmacKey, ctrKey, sizes[i], "size-class") == 0,
            "size-class roundtrip");

    /* Fresh random nonce every call: same plaintext, different wire bytes */
    const uint8_t plain[] = "deterministic-check";
    size_t nLenA = 0, nLenB = 0;
    uint8_t *pEncA = DirectGate_SIV_Encrypt(cmacKey, ctrKey, SIV_KEY_BITS,
        plain, sizeof(plain), &nLenA);
    uint8_t *pEncB = DirectGate_SIV_Encrypt(cmacKey, ctrKey, SIV_KEY_BITS,
        plain, sizeof(plain), &nLenB);
    CHECK(pEncA != NULL && pEncB != NULL && nLenA == nLenB, "nonce encrypt");
    CHECK(memcmp(pEncA, pEncB, nLenA) != 0, "fresh nonce per encryption");
    free(pEncB);

    /* Authenticated everywhere: flipping one bit in the nonce, the SIV tag
       or the ciphertext body must each be rejected */
    const size_t nFlipOffsets[] = { 0, 16, SIV_OVERHEAD };
    for (size_t i = 0; i < sizeof(nFlipOffsets) / sizeof(nFlipOffsets[0]); i++)
    {
        size_t nDecLen = 0;
        pEncA[nFlipOffsets[i]] ^= 0x01;
        uint8_t *pDec = DirectGate_SIV_Decrypt(cmacKey, ctrKey, SIV_KEY_BITS,
            pEncA, nLenA, &nDecLen);
        pEncA[nFlipOffsets[i]] ^= 0x01;
        CHECK(pDec == NULL, "tampered message must not decrypt");
    }

    /* Truncation below the nonce+tag envelope must be rejected, not read OOB */
    size_t nDecLen = 0;
    CHECK(DirectGate_SIV_Decrypt(cmacKey, ctrKey, SIV_KEY_BITS,
        pEncA, SIV_OVERHEAD - 1, &nDecLen) == NULL, "truncated envelope");
    CHECK(DirectGate_SIV_Decrypt(cmacKey, ctrKey, SIV_KEY_BITS,
        pEncA, 0, &nDecLen) == NULL, "empty envelope");

    /* Key separation: either half of the key material being wrong fails */
    CHECK(DirectGate_SIV_Decrypt(otherKey, ctrKey, SIV_KEY_BITS,
        pEncA, nLenA, &nDecLen) == NULL, "wrong cmac key");
    CHECK(DirectGate_SIV_Decrypt(cmacKey, otherKey, SIV_KEY_BITS,
        pEncA, nLenA, &nDecLen) == NULL, "wrong ctr key");

    free(pEncA);

    puts("siv_smoke: OK");
    return 0;
}
