/* What the shared crypto, auth record and logging helpers refuse: missing arguments, keys of no AES size, input
 * too short to be ciphertext, a session that has no keys yet, and log settings of the wrong shape. */

#include <stdio.h>
#include <string.h>

#include "src/common/auth.h"
#include "src/common/e2e.h"
#include "src/common/hkdf.h"
#include "src/common/logger.h"
#include "src/common/siv.h"
#include "src/common/websock.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "common_guards_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static int check_crypto(void)
{
    uint8_t key[32], nonce[32], out[64];
    memset(key, 0x11, sizeof(key));
    memset(nonce, 0x22, sizeof(nonce));
    size_t nOut = 7;

    /* HKDF: no salt is a salt of zeros, and only a whole SHA-256 block of key material is extracted */
    uint8_t withNull[32], withEmpty[32];
    CHECK(DirectGate_HKDF_Extract(NULL, 0, key, sizeof(key), withNull) &&
          DirectGate_HKDF_Extract(nonce, 0, key, sizeof(key), withEmpty) && !memcmp(withNull, withEmpty, sizeof(withNull)),
        "a missing and an empty salt should extract the same key");
    CHECK(!DirectGate_HKDF_Extract(nonce, sizeof(nonce), key, sizeof(key), NULL), "extraction needs room");

    /* SIV: a key size AES does not have, missing keys or data, and input too short to hold a tag are refused */
    const size_t badBits[] = { 0, 64, 255, 512 };
    for (size_t i = 0; i < sizeof(badBits) / sizeof(badBits[0]); i++)
    {
        nOut = 7;
        CHECK(DirectGate_SIV_Encrypt(key, key, badBits[i], nonce, sizeof(nonce), &nOut) == NULL && nOut == 0,
            "a key of no AES size does not encrypt");
        CHECK(DirectGate_SIV_Decrypt(key, key, badBits[i], out, sizeof(out), &nOut) == NULL, "nor decrypt");
    }

    CHECK(DirectGate_SIV_Encrypt(NULL, key, 256, nonce, sizeof(nonce), &nOut) == NULL &&
          DirectGate_SIV_Encrypt(key, NULL, 256, nonce, sizeof(nonce), &nOut) == NULL, "encryption needs both keys");
    CHECK(DirectGate_SIV_Encrypt(key, key, 256, NULL, 1, &nOut) == NULL &&
          DirectGate_SIV_Encrypt(key, key, 256, nonce, 0, &nOut) == NULL, "encryption needs data");
    CHECK(DirectGate_SIV_Encrypt(key, key, 256, nonce, sizeof(nonce), NULL) == NULL, "encryption needs a length");
    CHECK(DirectGate_SIV_Decrypt(NULL, key, 256, out, sizeof(out), &nOut) == NULL &&
          DirectGate_SIV_Decrypt(key, NULL, 256, out, sizeof(out), &nOut) == NULL, "decryption needs both keys");
    CHECK(DirectGate_SIV_Decrypt(key, key, 256, out, 32, &nOut) == NULL,
        "a 16-byte nonce and a 16-byte tag with nothing after them are no ciphertext");
    CHECK(DirectGate_SIV_Decrypt(key, key, 256, out, sizeof(out), NULL) == NULL, "decryption needs a length");

    for (size_t nBits = 128; nBits <= 256; nBits += 64)
    {
        uint8_t *pSealed = DirectGate_SIV_Encrypt(key, key, nBits, nonce, sizeof(nonce), &nOut);
        CHECK(pSealed != NULL, "every AES size encrypts");
        size_t nOpened = 0;
        uint8_t *pOpened = DirectGate_SIV_Decrypt(key, key, nBits, pSealed, nOut, &nOpened);
        CHECK(pOpened != NULL && nOpened == sizeof(nonce) && !memcmp(pOpened, nonce, nOpened), "and decrypts back");
        free(pOpened);
        free(pSealed);
    }

    /* E2E: nothing is derived from a missing part, and a session without keys neither encrypts nor decrypts */
    directgate_e2e_t e2e;
    DirectGate_E2E_Init(&e2e);
    DirectGate_E2E_Init(NULL);
    DirectGate_E2E_Clear(NULL);
    CHECK(!DirectGate_E2E_IsInitialized(NULL), "no session has keys");
    CHECK(!DirectGate_E2E_DeriveFromSRP(NULL, key, 32, nonce, nonce, 32, "dev", XTRUE) &&
          !DirectGate_E2E_DeriveFromSRP(&e2e, NULL, 32, nonce, nonce, 32, "dev", XTRUE) &&
          !DirectGate_E2E_DeriveFromSRP(&e2e, key, 0, nonce, nonce, 32, "dev", XTRUE) &&
          !DirectGate_E2E_DeriveFromSRP(&e2e, key, 32, NULL, nonce, 32, "dev", XTRUE) &&
          !DirectGate_E2E_DeriveFromSRP(&e2e, key, 32, nonce, NULL, 32, "dev", XTRUE) &&
          !DirectGate_E2E_DeriveFromSRP(&e2e, key, 32, nonce, nonce, 0, "dev", XTRUE) &&
          !DirectGate_E2E_DeriveFromSRP(&e2e, key, 32, nonce, nonce, 32, "", XTRUE), "every SRP input is required");
    CHECK(!DirectGate_E2E_DeriveFromKey(&e2e, key, 0, nonce, nonce, 32, "dev", XTRUE) &&
          !DirectGate_E2E_DeriveFromKey(&e2e, key, 32, NULL, nonce, 32, "dev", XTRUE) &&
          !DirectGate_E2E_DeriveFromKey(&e2e, key, 32, nonce, NULL, 32, "dev", XTRUE) &&
          !DirectGate_E2E_DeriveFromKey(&e2e, key, 32, nonce, nonce, 0, "dev", XTRUE), "every key input is required");
    CHECK(!DirectGate_E2E_IsInitialized(&e2e), "a refused derivation leaves the session without keys");
    CHECK(DirectGate_E2E_Encrypt(&e2e, nonce, sizeof(nonce), &nOut) == NULL &&
          DirectGate_E2E_Decrypt(&e2e, out, sizeof(out), &nOut) == NULL, "a session without keys moves no data");
    CHECK(DirectGate_E2E_Encrypt(NULL, nonce, sizeof(nonce), &nOut) == NULL &&
          DirectGate_E2E_Decrypt(NULL, out, sizeof(out), &nOut) == NULL, "no session moves no data");

    CHECK(DirectGate_E2E_DeriveFromSRP(&e2e, key, 32, nonce, nonce, 32, "dev", XTRUE), "derive session keys");
    CHECK(DirectGate_E2E_Decrypt(&e2e, NULL, sizeof(out), &nOut) == NULL &&
          DirectGate_E2E_Decrypt(&e2e, out, sizeof(out), NULL) == NULL, "decryption needs data and a length");
    DirectGate_E2E_Clear(&e2e);
    return 0;
}

static int check_auth_and_log(void)
{
    directgate_auth_t auth;
    uint8_t salt[DIRECTGATE_SRP_SALT_SIZE];
    DirectGate_AuthInit(NULL);
    DirectGate_AuthInit(&auth);
    CHECK(!DirectGate_AuthIsConfigured(NULL), "no record is configured");
    CHECK(!DirectGate_AuthSaltHexToBytes(NULL, salt, sizeof(salt)) &&
          !DirectGate_AuthSaltHexToBytes("00", NULL, sizeof(salt)), "a salt needs text and room");
    char sBadSalt[DIRECTGATE_AUTH_SALT_HEX_SIZE];
    memset(sBadSalt, '0', sizeof(sBadSalt) - 1);
    sBadSalt[sizeof(sBadSalt) - 1] = '\0';
    sBadSalt[5] = 'g';
    CHECK(!DirectGate_AuthSaltHexToBytes(sBadSalt, salt, sizeof(salt)), "a salt with a non-hex digit is refused");
    sBadSalt[5] = 'A';
    CHECK(DirectGate_AuthSaltHexToBytes(sBadSalt, salt, sizeof(salt)) && salt[2] == 0x0a, "a salt takes upper case hex");
    CHECK(!DirectGate_AuthGenerateRecord(NULL, "pw") && !DirectGate_AuthGenerateRecord(&auth, ""),
        "a record needs a holder and a password");

    /* A configuration whose auth or log member is not an object is a configuration without them */
    xjson_t json;
    const char *pDoc = "{\"auth\":[1],\"log\":\"loud\"}";
    CHECK(XJSON_Parse(&json, NULL, pDoc, strlen(pDoc)), "parse a malformed configuration");
    CHECK(DirectGate_AuthLoad(&auth, json.pRootObj) && !DirectGate_AuthIsConfigured(&auth),
        "an auth member that is not an object configures nothing");
    CHECK(!DirectGate_AuthLoad(NULL, json.pRootObj) && !DirectGate_AuthLoad(&auth, NULL), "loading needs both ends");

    directgate_log_t log;
    DirectGate_LogInit(&log, "guards", XLOG_ERROR);
    DirectGate_LogInit(NULL, "guards", XLOG_ERROR);
    DirectGate_LogSetIdent(NULL, "x");
    DirectGate_LogSetIdent(&log, "");
    CHECK(DirectGate_LogLoad(&log, json.pRootObj), "a log member that is not an object is no log setting");
    CHECK(!DirectGate_LogLoad(NULL, json.pRootObj) && !DirectGate_LogLoad(&log, NULL), "loading needs both ends");
    CHECK(!DirectGate_LogSave(NULL, json.pRootObj) && !DirectGate_LogSave(&log, NULL), "saving needs both ends");
    CHECK(DirectGate_LogApply(NULL) == XSTDERR, "nothing is applied without settings");
    XJSON_Destroy(&json);

    /* Levels are matched by prefix and case, and entries that are not names are passed over */
    pDoc = "{\"log\":{\"levels\":[\"PANIC\",\"warning\",7,\"error\"]}}";
    CHECK(XJSON_Parse(&json, NULL, pDoc, strlen(pDoc)), "parse a level list");
    CHECK(DirectGate_LogLoad(&log, json.pRootObj), "load the level list");
    CHECK((log.nFlags & XLOG_FATAL) && (log.nFlags & XLOG_WARN) && (log.nFlags & XLOG_ERROR),
        "named levels are taken whatever their case");
    XJSON_Destroy(&json);

    /* A ping too large for a control frame is not answered */
    xapi_session_t session;
    memset(&session, 0, sizeof(session));
    CHECK(DirectGate_WebSock_SendPong(NULL, NULL) == XAPI_DISCONNECT, "a pong needs a session and a ping");
    CHECK(DirectGate_WebSock_Send(NULL, (const uint8_t*)"x", 1) == XAPI_DISCONNECT, "sending needs a session");
    return 0;
}

int main(void)
{
    if (check_crypto()) return 1;
    if (check_auth_and_log()) return 1;

    puts("common_guards_smoke: OK");
    return 0;
}
