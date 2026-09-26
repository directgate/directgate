/*
 * The agent's two AES-SIV backends must be interchangeable.
 *
 * Every build uses OpenSSL's AES-SIV when the library has it and the portable
 * libxutils one when it does not, so an agent on an old system and a peer on a
 * new one are the two backends talking to each other. crypto_siv_openssl_smoke
 * checks the libxutils primitive against OpenSSL; this checks the agent's own
 * wrappers around both - the key halves, the nonce as associated data, the tag
 * in front of the ciphertext - by requiring identical bytes for the same
 * nonce, each opening what the other sealed, and both refusing a tampered
 * message, at every key size and around every block boundary.
 */

#include <stdio.h>
#include <string.h>

#include "src/common/siv.c"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "siv_backends_smoke: %s (bits %zu, len %zu)\n", msg, nBits, nLen); \
            return 1; \
        } \
    } while (0)

#ifdef XSIV_HAVE_OPENSSL

static int check_pair(size_t nBits, size_t nLen)
{
    uint8_t cmac[32], ctr[32], nonce[XSIV_NONCE_SIZE], plain[1100];
    for (size_t i = 0; i < sizeof(cmac); i++) cmac[i] = (uint8_t)(0x10 + i);
    for (size_t i = 0; i < sizeof(ctr); i++) ctr[i] = (uint8_t)(0xa0 + i);
    for (size_t i = 0; i < sizeof(nonce); i++) nonce[i] = (uint8_t)(0x55 ^ i);
    for (size_t i = 0; i < nLen; i++) plain[i] = (uint8_t)(i * 7 + 3);

    uint8_t sealedX[XSIV_TAG_SIZE + sizeof(plain)], sealedO[XSIV_TAG_SIZE + sizeof(plain)];
    CHECK(DirectGate_SIV_XUtilsEncrypt(cmac, ctr, nBits, nonce, plain, nLen, sealedX), "the portable backend seals");
    CHECK(DirectGate_SIV_OpenSSLEncrypt(cmac, ctr, nBits, nonce, plain, nLen, sealedO), "the OpenSSL backend seals");
    CHECK(memcmp(sealedX, sealedO, XSIV_TAG_SIZE + nLen) == 0, "both backends seal to the same bytes");

    size_t nOut = 0;
    uint8_t *pOpened = DirectGate_SIV_OpenSSLDecrypt(cmac, ctr, nBits, nonce, sealedX, XSIV_TAG_SIZE + nLen, &nOut);
    CHECK(pOpened != NULL && nOut == nLen && memcmp(pOpened, plain, nLen) == 0, "OpenSSL opens what the portable backend sealed");
    free(pOpened);

    nOut = 0;
    pOpened = DirectGate_SIV_XUtilsDecrypt(cmac, ctr, nBits, nonce, sealedO, XSIV_TAG_SIZE + nLen, &nOut);
    CHECK(pOpened != NULL && nOut == nLen && memcmp(pOpened, plain, nLen) == 0, "the portable backend opens what OpenSSL sealed");
    free(pOpened);

    /* A flipped bit anywhere - tag or body - is refused by both. */
    size_t nFlip = (nLen / 2) + XSIV_TAG_SIZE;
    sealedX[nFlip] ^= 0x01;
    CHECK(DirectGate_SIV_XUtilsDecrypt(cmac, ctr, nBits, nonce, sealedX, XSIV_TAG_SIZE + nLen, &nOut) == NULL,
        "the portable backend refuses a tampered body");
    CHECK(DirectGate_SIV_OpenSSLDecrypt(cmac, ctr, nBits, nonce, sealedX, XSIV_TAG_SIZE + nLen, &nOut) == NULL,
        "OpenSSL refuses a tampered body");
    sealedX[nFlip] ^= 0x01;

    /* The nonce is authenticated: the same bytes under another nonce do not open. */
    nonce[0] ^= 0x80;
    CHECK(DirectGate_SIV_XUtilsDecrypt(cmac, ctr, nBits, nonce, sealedX, XSIV_TAG_SIZE + nLen, &nOut) == NULL,
        "the portable backend refuses another nonce");
    CHECK(DirectGate_SIV_OpenSSLDecrypt(cmac, ctr, nBits, nonce, sealedX, XSIV_TAG_SIZE + nLen, &nOut) == NULL,
        "OpenSSL refuses another nonce");
    return 0;
}

/* The public entry points on a system whose OpenSSL has no AES-SIV provider:
   they fall back to the portable backend, which still opens what a peer with
   the provider sealed, and the other way round. */
static int check_fallback(void)
{
    size_t nBits = 256, nLen = 0;
    uint8_t cmac[32], ctr[32];
    memset(cmac, 0x21, sizeof(cmac));
    memset(ctr, 0x42, sizeof(ctr));
    const uint8_t plain[] = "the same message, sealed on a newer system";
    nLen = sizeof(plain);

    CHECK(DirectGate_SIV_Cipher(100) == NULL, "a key size AES-SIV does not have has no cipher");
    uint8_t out[XSIV_TAG_SIZE + sizeof(plain)];
    CHECK(!DirectGate_SIV_OpenSSLEncrypt(cmac, ctr, 100, cmac, plain, nLen, out), "an unknown key size is refused");

    size_t nSealed = 0, nOpened = 0;
    uint8_t *pSealed = DirectGate_SIV_Encrypt(cmac, ctr, nBits, plain, nLen, &nSealed);
    CHECK(pSealed != NULL, "sealed with the OpenSSL backend");

    sOpenSSLReady = 0;
    uint8_t *pOpened = DirectGate_SIV_Decrypt(cmac, ctr, nBits, pSealed, nSealed, &nOpened);
    CHECK(pOpened != NULL && nOpened == nLen && memcmp(pOpened, plain, nLen) == 0,
        "without the provider, the portable backend opens it");
    free(pOpened);
    free(pSealed);

    pSealed = DirectGate_SIV_Encrypt(cmac, ctr, nBits, plain, nLen, &nSealed);
    CHECK(pSealed != NULL && nSealed == XSIV_NONCE_SIZE + XSIV_TAG_SIZE + nLen,
        "without the provider, the portable backend seals");

    sOpenSSLReady = 1;
    pOpened = DirectGate_SIV_Decrypt(cmac, ctr, nBits, pSealed, nSealed, &nOpened);
    CHECK(pOpened != NULL && nOpened == nLen && memcmp(pOpened, plain, nLen) == 0,
        "the OpenSSL backend opens what the portable one sealed");
    free(pOpened);
    free(pSealed);
    return 0;
}

int main(void)
{
    if (!DirectGate_SIV_OpenSSLReady())
    {
        puts("siv_backends_smoke: this OpenSSL has no AES-SIV provider, nothing to compare against, skipping");
        return 77;
    }

    const size_t bits[] = { 128, 192, 256 };
    const size_t lens[] = { 1, 15, 16, 17, 31, 32, 33, 1000, 1100 };

    for (size_t b = 0; b < sizeof(bits) / sizeof(bits[0]); b++)
        for (size_t l = 0; l < sizeof(lens) / sizeof(lens[0]); l++)
            if (check_pair(bits[b], lens[l])) return 1;

    if (check_fallback()) return 1;

    puts("siv_backends_smoke: OK");
    return 0;
}

#else

int main(void)
{
    puts("siv_backends_smoke: OpenSSL has no AES-SIV here, nothing to compare against, skipping");
    return 77;
}

#endif
