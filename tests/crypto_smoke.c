#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "src/common/e2e.h"
#include "src/common/hkdf.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "crypto_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static void fill_range(uint8_t *pData, size_t nLen, uint8_t nStart)
{
    for (size_t i = 0; i < nLen; i++)
        pData[i] = (uint8_t)(nStart + i);
}

int main(void)
{
    const uint8_t ikm[22] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    const uint8_t salt[13] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
    };
    const char info[] = {
        (char)0xf0, (char)0xf1, (char)0xf2, (char)0xf3, (char)0xf4,
        (char)0xf5, (char)0xf6, (char)0xf7, (char)0xf8, (char)0xf9, '\0'
    };
    const uint8_t expectedPrk[XHKDF_SHA256_LEN] = {
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
        0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
        0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
        0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
    };
    const uint8_t expectedOkm[42] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65
    };

    uint8_t prk[XHKDF_SHA256_LEN];
    uint8_t okm[sizeof(expectedOkm)];
    CHECK(DirectGate_HKDF_Extract(salt, sizeof(salt), ikm, sizeof(ikm), prk),
        "HKDF extract");
    CHECK(memcmp(prk, expectedPrk, sizeof(prk)) == 0,
        "HKDF RFC5869 PRK");
    CHECK(DirectGate_HKDF_Expand(prk, sizeof(prk), info, okm, sizeof(okm)),
        "HKDF expand");
    CHECK(memcmp(okm, expectedOkm, sizeof(okm)) == 0,
        "HKDF RFC5869 OKM");
    CHECK(!DirectGate_HKDF_Expand(prk, sizeof(prk), "too-long", okm,
        (size_t)255 * XHKDF_SHA256_LEN + 1), "HKDF max output guard");
    CHECK(!DirectGate_HKDF_Extract(NULL, 0, NULL, 0, prk), "HKDF extract NULL IKM");
    CHECK(!DirectGate_HKDF_Extract(NULL, 0, ikm, 0, prk), "HKDF extract empty IKM");
    CHECK(!DirectGate_HKDF_Extract(NULL, 0, ikm, sizeof(ikm), NULL),
        "HKDF extract NULL output");
    uint8_t noSaltPrk[XHKDF_SHA256_LEN];
    uint8_t noInfoOkm[XHKDF_SHA256_LEN];
    CHECK(DirectGate_HKDF_Extract(NULL, 0, ikm, sizeof(ikm), noSaltPrk),
        "HKDF zero salt");
    CHECK(DirectGate_HKDF_Expand(noSaltPrk, sizeof(noSaltPrk), NULL,
        noInfoOkm, sizeof(noInfoOkm)), "HKDF no info");
    CHECK(!DirectGate_HKDF_Expand(NULL, sizeof(prk), NULL, okm, sizeof(okm)),
        "HKDF expand NULL PRK");
    CHECK(!DirectGate_HKDF_Expand(prk, 0, NULL, okm, sizeof(okm)),
        "HKDF expand empty PRK");
    CHECK(!DirectGate_HKDF_Expand(prk, sizeof(prk), NULL, NULL, sizeof(okm)),
        "HKDF expand NULL output");
    CHECK(!DirectGate_HKDF_Expand(prk, sizeof(prk), NULL, okm, 0),
        "HKDF expand empty output");

    uint8_t secret[32];
    uint8_t agentNonce[32];
    uint8_t clientNonce[32];
    fill_range(secret, sizeof(secret), 0x40);
    fill_range(agentNonce, sizeof(agentNonce), 0x80);
    fill_range(clientNonce, sizeof(clientNonce), 0xc0);

    directgate_e2e_t keyE2E;
    directgate_e2e_t keyE2E2;
    directgate_e2e_t srpE2E;
    DirectGate_E2E_Init(&keyE2E);
    DirectGate_E2E_Init(&keyE2E2);
    DirectGate_E2E_Init(&srpE2E);

    CHECK(!DirectGate_E2E_IsInitialized(NULL), "NULL E2E is uninitialized");
    CHECK(!DirectGate_E2E_IsInitialized(&keyE2E), "E2E starts uninitialized");
    CHECK(!DirectGate_E2E_DeriveFromKey(NULL, secret, sizeof(secret),
        agentNonce, clientNonce, sizeof(agentNonce), "dev-crypto", 1),
        "derive rejects NULL context");
    CHECK(!DirectGate_E2E_DeriveFromKey(&keyE2E, NULL, sizeof(secret),
        agentNonce, clientNonce, sizeof(agentNonce), "dev-crypto", 1),
        "derive rejects NULL secret");
    CHECK(!DirectGate_E2E_DeriveFromKey(&keyE2E, secret, sizeof(secret),
        agentNonce, clientNonce, sizeof(agentNonce), "", 1),
        "derive rejects empty device");
    CHECK(!DirectGate_E2E_DeriveFromKey(&keyE2E, secret, sizeof(secret),
        agentNonce, clientNonce, sizeof(agentNonce) + 1, "dev-crypto", 1),
        "derive rejects oversized nonce");
    /* keyE2E is the agent side, keyE2E2 the client side of the same channel. */
    CHECK(DirectGate_E2E_DeriveFromKey(&keyE2E, secret, sizeof(secret),
        agentNonce, clientNonce, sizeof(agentNonce), "dev-crypto", 1),
        "derive key-auth E2E (agent)");
    CHECK(DirectGate_E2E_DeriveFromKey(&keyE2E2, secret, sizeof(secret),
        agentNonce, clientNonce, sizeof(agentNonce), "dev-crypto", 0),
        "derive key-auth E2E (client)");
    CHECK(DirectGate_E2E_DeriveFromSRP(&srpE2E, secret, sizeof(secret),
        agentNonce, clientNonce, sizeof(agentNonce), "dev-crypto", 1),
        "derive SRP E2E");
    CHECK(DirectGate_E2E_IsInitialized(&keyE2E), "E2E initialized");

    /* The agent's TX channel is the client's RX channel and vice versa. */
    CHECK(memcmp(keyE2E.txCmacKey, keyE2E2.rxCmacKey, XE2E_KEY_SIZE) == 0 &&
          memcmp(keyE2E.txCtrKey,  keyE2E2.rxCtrKey,  XE2E_KEY_SIZE) == 0,
        "agent TX channel matches client RX channel");
    CHECK(memcmp(keyE2E.rxCmacKey, keyE2E2.txCmacKey, XE2E_KEY_SIZE) == 0 &&
          memcmp(keyE2E.rxCtrKey,  keyE2E2.txCtrKey,  XE2E_KEY_SIZE) == 0,
        "client TX channel matches agent RX channel");

    /* Direction binding: each side's TX keys differ from its RX keys, so a
       reflected packet cannot be decrypted by its own sender. */
    CHECK(memcmp(keyE2E.txCmacKey, keyE2E.rxCmacKey, XE2E_KEY_SIZE) != 0 ||
          memcmp(keyE2E.txCtrKey,  keyE2E.rxCtrKey,  XE2E_KEY_SIZE) != 0,
        "TX and RX channels are distinct");

    CHECK(memcmp(keyE2E.txCmacKey, srpE2E.txCmacKey, XE2E_KEY_SIZE) != 0 ||
          memcmp(keyE2E.txCtrKey,  srpE2E.txCtrKey,  XE2E_KEY_SIZE) != 0,
        "SRP and key-auth E2E domains differ");

    const uint8_t plaintext[] = "directgate encrypted payload";
    size_t nEncLen = 0;
    CHECK(DirectGate_E2E_Encrypt(NULL, plaintext, sizeof(plaintext), &nEncLen) == NULL,
        "encrypt rejects NULL context");
    CHECK(DirectGate_E2E_Encrypt(&keyE2E, NULL, sizeof(plaintext), &nEncLen) == NULL,
        "encrypt rejects NULL data");
    CHECK(DirectGate_E2E_Encrypt(&keyE2E, plaintext, 0, &nEncLen) == NULL,
        "encrypt rejects empty data");
    CHECK(DirectGate_E2E_Encrypt(&keyE2E, plaintext, sizeof(plaintext), NULL) == NULL,
        "encrypt rejects NULL output length");
    CHECK(DirectGate_E2E_Decrypt(&keyE2E2, plaintext, sizeof(plaintext), &nEncLen) == NULL,
        "decrypt rejects short packet");
    uint8_t *pEncrypted = DirectGate_E2E_Encrypt(&keyE2E, plaintext,
        sizeof(plaintext), &nEncLen);
    /* Wire layout is nonce(16) || siv_tag(16) || ciphertext, i.e. 32 bytes of
       overhead. The byte-exact S2V/CTR vectors are checked against OpenSSL with
       fixed nonces in crypto_siv_openssl_smoke; here the nonce is random. */
    CHECK(pEncrypted != NULL &&
          nEncLen == (size_t)XE2E_IV_SIZE * 2 + sizeof(plaintext),
        "E2E encrypt length");

    /* Non-determinism: encrypting the same plaintext again must yield different
       bytes (fresh random nonce → fresh synthetic IV → fresh ciphertext). */
    size_t nEncLen2 = 0;
    uint8_t *pEncrypted2 = DirectGate_E2E_Encrypt(&keyE2E, plaintext,
        sizeof(plaintext), &nEncLen2);
    CHECK(pEncrypted2 != NULL && nEncLen2 == nEncLen, "E2E encrypt (second)");
    CHECK(memcmp(pEncrypted, pEncrypted2, nEncLen) != 0,
        "AES-SIV must be non-deterministic across encryptions");
    free(pEncrypted2);

    size_t nDecLen = 0;
    uint8_t *pDecrypted = DirectGate_E2E_Decrypt(&keyE2E2, pEncrypted,
        nEncLen, &nDecLen);
    CHECK(pDecrypted != NULL, "E2E decrypt");
    CHECK(nDecLen == sizeof(plaintext), "E2E decrypted length");
    CHECK(memcmp(pDecrypted, plaintext, sizeof(plaintext)) == 0,
        "E2E decrypted bytes");
    free(pDecrypted);

    /* Reflection guard: the agent must not be able to decrypt a packet it
       itself encrypted (the relay-reflection / cross-direction replay case). */
    CHECK(DirectGate_E2E_Decrypt(&keyE2E, pEncrypted, nEncLen, &nDecLen) == NULL,
        "reflected packet must not decrypt at sender");

    pEncrypted[0] ^= 0x01;
    CHECK(DirectGate_E2E_Decrypt(&keyE2E2, pEncrypted, nEncLen, &nDecLen) == NULL,
        "E2E tamper must fail");
    free(pEncrypted);

    DirectGate_E2E_Clear(&keyE2E);
    CHECK(!DirectGate_E2E_IsInitialized(&keyE2E), "E2E clear");
    for (size_t i = 0; i < sizeof(keyE2E.txCmacKey); i++)
        CHECK(keyE2E.txCmacKey[i] == 0, "E2E clear zeroes key material");

    puts("crypto_smoke: OK");
    return 0;
}
