#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "src/common/auth.h"
#include "src/common/srp.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "srp_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static void bytes_to_hex(const uint8_t *pData, size_t nLen,
                         char *pOut, size_t nOutSize)
{
    static const char *pHex = "0123456789abcdef";
    if (nOutSize < nLen * 2 + 1)
    {
        if (nOutSize) pOut[0] = '\0';
        return;
    }

    for (size_t i = 0; i < nLen; i++)
    {
        pOut[i * 2] = pHex[(pData[i] >> 4) & 0x0f];
        pOut[i * 2 + 1] = pHex[pData[i] & 0x0f];
    }

    pOut[nLen * 2] = '\0';
}

/* Refusals of both sides, and the argument guards of every entry point */
static int srp_refusals(const uint8_t *pSalt, const char *pSaltHex, const char *pVerifierHex)
{
    const char *pDeviceId = "srp-guard-device";
    const char *pPassword = "srp guard password";
    char sHex[1024], sNonce[DIRECTGATE_SRP_NONCE_SIZE * 2 + 1], sM2[DIRECTGATE_SRP_KEY_SIZE * 2 + 1];
    uint8_t bytes[4];
    size_t nLen = 0;

    CHECK(!DirectGate_SRP_HexToBytes(NULL, bytes, sizeof(bytes), &nLen), "hex parser needs input");
    CHECK(!DirectGate_SRP_HexToBytes("00", NULL, sizeof(bytes), &nLen), "hex parser needs output");
    CHECK(!DirectGate_SRP_HexToBytes("0g", bytes, sizeof(bytes), &nLen), "hex parser rejects a non-hex digit");
    CHECK(!DirectGate_SRP_HexToBytes("g0", bytes, sizeof(bytes), &nLen), "hex parser rejects a leading non-hex digit");
    CHECK(!DirectGate_SRP_HexToBytes("0011223344", bytes, sizeof(bytes), &nLen), "hex parser rejects an overflow");
    CHECK(!DirectGate_SRP_HexToBytes("", bytes, sizeof(bytes), &nLen), "hex parser rejects empty input");

    CHECK(!strcmp(DirectGate_SRP_StateName(DIRECTGATE_SRP_STATE_IDLE), "IDLE") &&
          !strcmp(DirectGate_SRP_StateName(DIRECTGATE_SRP_STATE_CHALLENGE_SENT), "CHALLENGE_SENT") &&
          !strcmp(DirectGate_SRP_StateName(DIRECTGATE_SRP_STATE_AUTHENTICATED), "AUTHENTICATED") &&
          !strcmp(DirectGate_SRP_StateName(DIRECTGATE_SRP_STATE_FAILED), "FAILED") &&
          !strcmp(DirectGate_SRP_StateName((directgate_srp_state_t)99), "UNKNOWN"), "every state has a name");

    directgate_srp_t empty;
    memset(&empty, 0, sizeof(empty));
    CHECK(!DirectGate_SRP_Init(NULL), "server init needs a context");
    DirectGate_SRP_Destroy(NULL);
    CHECK(!DirectGate_SRP_SetClientPublic(NULL, "02") && !DirectGate_SRP_SetClientPublic(&empty, "02"),
        "A needs an initialized server");
    CHECK(!DirectGate_SRP_LoadVerifier(NULL, pSalt, DIRECTGATE_SRP_SALT_SIZE, pVerifierHex) &&
          !DirectGate_SRP_LoadVerifier(&empty, pSalt, DIRECTGATE_SRP_SALT_SIZE, pVerifierHex),
          "a verifier needs an initialized server");
    CHECK(!DirectGate_SRP_GenerateChallenge(NULL, sHex, sizeof(sHex), sNonce, sizeof(sNonce)) &&
          !DirectGate_SRP_GenerateChallenge(&empty, sHex, sizeof(sHex), sNonce, sizeof(sNonce)),
          "a challenge needs an initialized server");
    CHECK(!DirectGate_SRP_VerifyClientProof(NULL, "00", sM2, sizeof(sM2)) &&
          !DirectGate_SRP_VerifyClientProof(&empty, "00", sM2, sizeof(sM2)), "a proof needs an initialized server");

    directgate_srp_t server;
    CHECK(DirectGate_SRP_Init(&server), "guard server init");
    xstrncpy(server.sDeviceId, sizeof(server.sDeviceId), pDeviceId);
    char *pNHex = BN_bn2hex(server.N);
    CHECK(pNHex != NULL, "N prints as hex");

    CHECK(!DirectGate_SRP_LoadVerifier(&server, NULL, DIRECTGATE_SRP_SALT_SIZE, pVerifierHex), "a verifier needs a salt");
    CHECK(!DirectGate_SRP_LoadVerifier(&server, pSalt, DIRECTGATE_SRP_SALT_SIZE - 1, pVerifierHex),
        "a verifier needs a whole salt");
    CHECK(!DirectGate_SRP_LoadVerifier(&server, pSalt, DIRECTGATE_SRP_SALT_SIZE, ""), "a verifier needs a value");
    CHECK(!DirectGate_SRP_LoadVerifier(&server, pSalt, DIRECTGATE_SRP_SALT_SIZE, "zz"), "a verifier must be hex");
    CHECK(!DirectGate_SRP_LoadVerifier(&server, pSalt, DIRECTGATE_SRP_SALT_SIZE, "-01"), "a verifier must be positive");
    CHECK(!DirectGate_SRP_LoadVerifier(&server, pSalt, DIRECTGATE_SRP_SALT_SIZE, pNHex), "a verifier must be below N");
    CHECK(DirectGate_SRP_LoadVerifier(&server, pSalt, DIRECTGATE_SRP_SALT_SIZE, pVerifierHex), "the real verifier loads");

    CHECK(!DirectGate_SRP_GenerateChallenge(&server, sHex, sizeof(sHex), sNonce, sizeof(sNonce)),
        "no challenge goes out before A arrives");

    /* A public value that is a multiple of N would make the session key known to anyone */
    char sTwoN[1100];
    snprintf(sTwoN, sizeof(sTwoN), "%s0", pNHex);
    CHECK(!DirectGate_SRP_SetClientPublic(&server, "") && !DirectGate_SRP_SetClientPublic(&server, "zz"),
        "A must be hex");
    CHECK(!DirectGate_SRP_SetClientPublic(&server, pNHex), "A equal to N is rejected");
    CHECK(!DirectGate_SRP_SetClientPublic(&server, "-02"), "a negative A is rejected");

    directgate_srp_client_t client;
    char sAHex[1024], sClientNonce[DIRECTGATE_SRP_NONCE_SIZE * 2 + 1], sM1[DIRECTGATE_SRP_KEY_SIZE * 2 + 1];
    CHECK(!DirectGate_SRP_ClientInit(NULL), "client init needs a context");
    DirectGate_SRP_ClientCleanse(NULL);
    CHECK(DirectGate_SRP_ClientInit(&client), "guard client init");
    CHECK(!DirectGate_SRP_ClientGenerateA(NULL, sAHex, sizeof(sAHex), sClientNonce, sizeof(sClientNonce)),
        "A needs a client");
    CHECK(!DirectGate_SRP_ClientGenerateA(&client, sAHex, 4, sClientNonce, sizeof(sClientNonce)),
        "A needs room for its hex");
    CHECK(!DirectGate_SRP_ClientGenerateA(&client, sAHex, sizeof(sAHex), sClientNonce, 4), "A needs room for the nonce");
    CHECK(DirectGate_SRP_ClientGenerateA(&client, sAHex, sizeof(sAHex), sClientNonce, sizeof(sClientNonce)),
        "the client makes A");

    CHECK(DirectGate_SRP_SetClientPublic(&server, sAHex), "the server takes the client's A");
    CHECK(!DirectGate_SRP_GenerateChallenge(&server, sHex, 4, sNonce, sizeof(sNonce)), "B needs room for its hex");
    CHECK(DirectGate_SRP_SetClientPublic(&server, sAHex), "the server takes A again after a refused challenge");
    CHECK(DirectGate_SRP_GenerateChallenge(&server, sHex, sizeof(sHex), sNonce, sizeof(sNonce)), "the server makes B");

    /* A B that is a multiple of N, a foreign suite or a short salt is refused by the client */
    CHECK(!DirectGate_SRP_ClientComputeKey(&client, pDeviceId, pPassword, pSaltHex, pNHex, DIRECTGATE_SRP_SUITE,
        sM1, sizeof(sM1)), "the client rejects B equal to N");
    CHECK(!DirectGate_SRP_ClientComputeKey(&client, pDeviceId, pPassword, pSaltHex, sTwoN, DIRECTGATE_SRP_SUITE,
        sM1, sizeof(sM1)), "the client rejects B equal to a multiple of N");
    CHECK(!DirectGate_SRP_ClientComputeKey(&client, pDeviceId, pPassword, pSaltHex, sHex, DIRECTGATE_SRP_SUITE + 1,
        sM1, sizeof(sM1)), "the client rejects an unsupported suite");
    CHECK(!DirectGate_SRP_ClientComputeKey(&client, pDeviceId, pPassword, "0011", sHex, DIRECTGATE_SRP_SUITE,
        sM1, sizeof(sM1)), "the client rejects a short salt");
    CHECK(!DirectGate_SRP_ClientComputeKey(&client, pDeviceId, pPassword, pSaltHex, "zz", DIRECTGATE_SRP_SUITE,
        sM1, sizeof(sM1)), "the client rejects a B that is not hex");
    CHECK(!DirectGate_SRP_ClientComputeKey(&client, "", pPassword, pSaltHex, sHex, DIRECTGATE_SRP_SUITE, sM1, sizeof(sM1)),
        "the client needs a device id");
    CHECK(!DirectGate_SRP_ClientComputeKey(&client, pDeviceId, pPassword, pSaltHex, sHex, DIRECTGATE_SRP_SUITE, NULL, 0),
        "the client needs room for M1");

    /* A proof that is not a whole hash is refused before any work */
    CHECK(!DirectGate_SRP_VerifyClientProof(&server, "", sM2, sizeof(sM2)), "a proof must be present");
    CHECK(!DirectGate_SRP_VerifyClientProof(&server, "abc", sM2, sizeof(sM2)), "a proof must be whole hex");
    CHECK(!DirectGate_SRP_VerifyClientProof(&server, "0011", sM2, sizeof(sM2)), "a proof must be a whole hash");
    CHECK(!DirectGate_SRP_VerifyClientProof(&server, "0011", NULL, 0), "a proof needs room for M2");
    CHECK(!DirectGate_SRP_ClientVerifyM2(&client, sHex, "0011"), "the client rejects a short M2");
    CHECK(!DirectGate_SRP_ClientVerifyM2(NULL, sHex, "0011"), "M2 needs a client");

    CHECK(!DirectGate_SRP_CreateVerifier(NULL, pSalt, DIRECTGATE_SRP_SALT_SIZE, sHex, sizeof(sHex)),
        "a verifier needs a password");
    CHECK(!DirectGate_SRP_CreateVerifier(pPassword, NULL, DIRECTGATE_SRP_SALT_SIZE, sHex, sizeof(sHex)),
        "a verifier needs a salt");
    CHECK(!DirectGate_SRP_CreateVerifier(pPassword, pSalt, DIRECTGATE_SRP_SALT_SIZE, sHex, 4), "a verifier needs room");

    OPENSSL_free(pNHex);
    DirectGate_SRP_ClientCleanse(&client);
    DirectGate_SRP_Destroy(&server);
    return 0;
}

int main(void)
{
    uint8_t tiny;
    size_t decoded;
    CHECK(!DirectGate_SRP_HexToBytes("00", &tiny, SIZE_MAX, &decoded), "overflowing hex bound rejected");
    uint8_t salt[DIRECTGATE_SRP_SALT_SIZE];
    for (size_t i = 0; i < sizeof(salt); i++) salt[i] = (uint8_t)i;

    char saltHex[DIRECTGATE_SRP_SALT_SIZE * 2 + 1];
    bytes_to_hex(salt, sizeof(salt), saltHex, sizeof(saltHex));

    uint8_t parsedSalt[DIRECTGATE_SRP_SALT_SIZE];
    CHECK(DirectGate_AuthSaltHexToBytes(saltHex, parsedSalt, sizeof(parsedSalt)),
        "auth salt hex parses");
    CHECK(memcmp(parsedSalt, salt, sizeof(salt)) == 0,
        "auth salt bytes match");
    CHECK(!DirectGate_AuthSaltHexToBytes("00", parsedSalt, sizeof(parsedSalt)),
        "short auth salt rejected");
    CHECK(!DirectGate_AuthSaltHexToBytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1x",
        parsedSalt, sizeof(parsedSalt)), "invalid auth salt hex rejected");

    char verifierHex[1024];
    const char *pPassword = "correct horse battery staple";
    const char *pDeviceId = "dev-srp";
    CHECK(DirectGate_SRP_CreateVerifier(pPassword, salt, sizeof(salt),
        verifierHex, sizeof(verifierHex)), "create scrypt verifier");
    CHECK(strlen(verifierHex) > 0, "verifier is non-empty");

    directgate_srp_client_t client;
    directgate_srp_t server;
    CHECK(DirectGate_SRP_ClientInit(&client), "client init");
    CHECK(DirectGate_SRP_Init(&server), "server init");
    xstrncpy(server.sDeviceId, sizeof(server.sDeviceId), pDeviceId);

    CHECK(!DirectGate_SRP_LoadVerifier(&server, salt, sizeof(salt), "0"),
        "zero verifier rejected");
    CHECK(DirectGate_SRP_LoadVerifier(&server, salt, sizeof(salt), verifierHex),
        "server load verifier");
    CHECK(!DirectGate_SRP_SetClientPublic(&server, "0"),
        "zero client public rejected");

    char aHex[1024];
    char clientNonceHex[DIRECTGATE_SRP_NONCE_SIZE * 2 + 1];
    CHECK(DirectGate_SRP_ClientGenerateA(&client, aHex, sizeof(aHex),
        clientNonceHex, sizeof(clientNonceHex)), "client generate A");
    CHECK(strlen(aHex) > 0, "A is non-empty");
    CHECK(strlen(clientNonceHex) == DIRECTGATE_SRP_NONCE_SIZE * 2,
        "client nonce hex length");

    CHECK(DirectGate_SRP_SetClientPublic(&server, aHex),
        "server accepts client public");

    char bHex[1024];
    char agentNonceHex[DIRECTGATE_SRP_NONCE_SIZE * 2 + 1];
    CHECK(DirectGate_SRP_GenerateChallenge(&server, bHex, sizeof(bHex),
        agentNonceHex, sizeof(agentNonceHex)), "server challenge");
    CHECK(strlen(bHex) > 0, "B is non-empty");
    CHECK(strlen(agentNonceHex) == DIRECTGATE_SRP_NONCE_SIZE * 2,
        "agent nonce hex length");

    /* Plumb the exchanged nonces into both sides exactly as the live protocol
       does: the agent stores the client nonce from auth/hello, the client
       stores the agent nonce from auth/challenge. Suite 2 folds both into M1. */
    uint8_t clientNonce[DIRECTGATE_SRP_NONCE_SIZE];
    uint8_t agentNonce[DIRECTGATE_SRP_NONCE_SIZE];
    size_t nNonceBytes = 0;
    CHECK(DirectGate_SRP_HexToBytes(clientNonceHex, clientNonce,
        sizeof(clientNonce), &nNonceBytes) && nNonceBytes == sizeof(clientNonce),
        "parse client nonce");
    CHECK(DirectGate_SRP_HexToBytes(agentNonceHex, agentNonce,
        sizeof(agentNonce), &nNonceBytes) && nNonceBytes == sizeof(agentNonce),
        "parse agent nonce");
    memcpy(server.clientNonce, clientNonce, sizeof(clientNonce));
    memcpy(client.agentNonce, agentNonce, sizeof(agentNonce));

    char m1Hex[DIRECTGATE_SRP_KEY_SIZE * 2 + 1];
    char m2Hex[DIRECTGATE_SRP_KEY_SIZE * 2 + 1];
    CHECK(DirectGate_SRP_ClientComputeKey(&client, pDeviceId, pPassword,
        saltHex, bHex, DIRECTGATE_SRP_SUITE, m1Hex, sizeof(m1Hex)),
        "client compute key");
    CHECK(strlen(m1Hex) == DIRECTGATE_SRP_KEY_SIZE * 2, "M1 hex length");
    CHECK(DirectGate_SRP_VerifyClientProof(&server, m1Hex, m2Hex, sizeof(m2Hex)),
        "server verifies M1");
    CHECK(server.bAuthenticated, "server authenticated flag");
    CHECK(memcmp(server.K, client.K, sizeof(server.K)) == 0,
        "server/client SRP session key match");
    CHECK(DirectGate_SRP_ClientVerifyM2(&client, bHex, m2Hex),
        "client verifies M2");

    directgate_srp_t tamperServer;
    CHECK(DirectGate_SRP_Init(&tamperServer), "tamper server init");
    xstrncpy(tamperServer.sDeviceId, sizeof(tamperServer.sDeviceId), pDeviceId);
    CHECK(DirectGate_SRP_LoadVerifier(&tamperServer, salt, sizeof(salt), verifierHex),
        "tamper server load verifier");
    CHECK(DirectGate_SRP_SetClientPublic(&tamperServer, aHex),
        "tamper server accepts A");

    char tamperBHex[1024];
    char tamperNonceHex[DIRECTGATE_SRP_NONCE_SIZE * 2 + 1];
    char tamperM1Hex[DIRECTGATE_SRP_KEY_SIZE * 2 + 1];
    char tamperM2Hex[DIRECTGATE_SRP_KEY_SIZE * 2 + 1];
    CHECK(DirectGate_SRP_GenerateChallenge(&tamperServer, tamperBHex,
        sizeof(tamperBHex), tamperNonceHex, sizeof(tamperNonceHex)),
        "tamper server challenge");
    memcpy(tamperServer.clientNonce, clientNonce, sizeof(clientNonce));
    CHECK(DirectGate_SRP_HexToBytes(tamperNonceHex, client.agentNonce,
        sizeof(client.agentNonce), &nNonceBytes) &&
        nNonceBytes == sizeof(client.agentNonce), "parse tamper agent nonce");
    CHECK(DirectGate_SRP_ClientComputeKey(&client, pDeviceId, pPassword,
        saltHex, tamperBHex, DIRECTGATE_SRP_SUITE, tamperM1Hex, sizeof(tamperM1Hex)),
        "tamper client compute key");
    tamperM1Hex[0] = tamperM1Hex[0] == '0' ? '1' : '0';
    CHECK(!DirectGate_SRP_VerifyClientProof(&tamperServer, tamperM1Hex,
        tamperM2Hex, sizeof(tamperM2Hex)), "tampered M1 rejected");
    CHECK(!tamperServer.bAuthenticated, "tamper server remains unauthenticated");

    /* Nonce binding (M-2 fix): if the agent nonce the client folds into M1 does
       not match the one the agent used (a relay altered it in transit), the
       proof must be rejected at auth rather than silently deriving mismatched
       E2E keys. Only the agent nonce is corrupted here, so the failure isolates
       the nonce-binding property. */
    directgate_srp_t nonceServer;
    CHECK(DirectGate_SRP_Init(&nonceServer), "nonce server init");
    xstrncpy(nonceServer.sDeviceId, sizeof(nonceServer.sDeviceId), pDeviceId);
    CHECK(DirectGate_SRP_LoadVerifier(&nonceServer, salt, sizeof(salt), verifierHex),
        "nonce server load verifier");
    CHECK(DirectGate_SRP_SetClientPublic(&nonceServer, aHex),
        "nonce server accepts A");

    char nonceBHex[1024];
    char nonceNonceHex[DIRECTGATE_SRP_NONCE_SIZE * 2 + 1];
    char nonceM1Hex[DIRECTGATE_SRP_KEY_SIZE * 2 + 1];
    char nonceM2Hex[DIRECTGATE_SRP_KEY_SIZE * 2 + 1];
    CHECK(DirectGate_SRP_GenerateChallenge(&nonceServer, nonceBHex,
        sizeof(nonceBHex), nonceNonceHex, sizeof(nonceNonceHex)),
        "nonce server challenge");
    memcpy(nonceServer.clientNonce, clientNonce, sizeof(clientNonce));
    memcpy(client.agentNonce, nonceServer.nonce, sizeof(client.agentNonce));
    client.agentNonce[0] ^= 0xff; /* relay flips a byte of the agent nonce */
    CHECK(DirectGate_SRP_ClientComputeKey(&client, pDeviceId, pPassword,
        saltHex, nonceBHex, DIRECTGATE_SRP_SUITE, nonceM1Hex, sizeof(nonceM1Hex)),
        "nonce client compute key");
    CHECK(!DirectGate_SRP_VerifyClientProof(&nonceServer, nonceM1Hex,
        nonceM2Hex, sizeof(nonceM2Hex)), "tampered agent nonce rejected");
    CHECK(!nonceServer.bAuthenticated, "nonce server remains unauthenticated");
    DirectGate_SRP_Destroy(&nonceServer);

    size_t nOutLen = 0;
    CHECK(DirectGate_SRP_HexToBytes("0a0B", parsedSalt, sizeof(parsedSalt), &nOutLen),
        "generic hex parser accepts mixed case");
    CHECK(nOutLen == 2 && parsedSalt[0] == 0x0a && parsedSalt[1] == 0x0b,
        "generic hex parser bytes");
    CHECK(!DirectGate_SRP_HexToBytes("abc", parsedSalt, sizeof(parsedSalt), NULL),
        "generic hex parser rejects odd length");

    DirectGate_SRP_Destroy(&tamperServer);
    DirectGate_SRP_Destroy(&server);
    DirectGate_SRP_ClientCleanse(&client);
    CHECK(srp_refusals(salt, saltHex, verifierHex) == 0, "every refusal and guard holds");

    puts("srp_smoke: OK");
    return 0;
}
