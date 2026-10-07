/* What the SRP-6a code refuses: every step of the exchange, on both sides, with each value it depends on missing in
 * turn - the group, the multiplier, the verifier, either public value, either secret - and with no place for its
 * result. A step that went ahead without one of them would compute on a NULL BIGNUM. Includes srp.c for the
 * internal steps. */

#include <stdio.h>
#include "src/common/srp.c"

#define CHECK(c, msg) do { if (!(c)) { fprintf(stderr, "srp_guards_smoke: %s (line %d)\n", msg, __LINE__); return 1; } } while (0)

/* The call refuses with the field gone, and the field is put back */
#define WITHOUT(pObj, field, call, msg) \
    do { \
        BIGNUM *pSaved = (pObj)->field; \
        (pObj)->field = NULL; \
        xbool_t bRefused = !(call); \
        (pObj)->field = pSaved; \
        CHECK(bRefused, msg); \
    } while (0)

#define DEVICE_ID   "11111111-2222-3333-4444-555555555555"
#define PASSWORD    "correct horse battery staple"

static int check_server(void)
{
    uint8_t salt[DIRECTGATE_SRP_SALT_SIZE], buf[512];
    for (size_t i = 0; i < sizeof(salt); i++) salt[i] = (uint8_t)i;
    char sVerifier[1024], sA[1024], sB[1024], sNonce[128], sM2[128], sHex[16];
    size_t nLen = 0;

    CHECK(DirectGate_SRP_HexToBytes("0a0b", buf, sizeof(buf), NULL), "hex decodes without anyone asking how much");
    CHECK(!DirectGate_SRP_BytesToHex(NULL, 1, sHex, sizeof(sHex)) && !DirectGate_SRP_BytesToHex(buf, 1, NULL, sizeof(sHex)),
        "hex needs bytes and room");

    CHECK(!DirectGate_SRP_CreateVerifier("", salt, sizeof(salt), sVerifier, sizeof(sVerifier)) &&
          !DirectGate_SRP_CreateVerifier(PASSWORD, NULL, sizeof(salt), sVerifier, sizeof(sVerifier)) &&
          !DirectGate_SRP_CreateVerifier(PASSWORD, salt, 3, sVerifier, sizeof(sVerifier)) &&
          !DirectGate_SRP_CreateVerifier(PASSWORD, salt, sizeof(salt), NULL, sizeof(sVerifier)),
        "a verifier needs a password, a full salt and room");
    CHECK(DirectGate_SRP_CreateVerifier(PASSWORD, salt, sizeof(salt), sVerifier, sizeof(sVerifier)), "make a verifier");

    directgate_srp_t srp, empty;
    memset(&empty, 0, sizeof(empty));
    CHECK(DirectGate_SRP_Init(&srp), "start the agent's side");

    CHECK(DirectGate_SRP_GroupBytes(NULL) == 0 && DirectGate_SRP_GroupBytes(&empty) == 0, "no group has no size");
    CHECK(!DirectGate_SRP_BNToPadded(NULL, srp.N, buf, sizeof(buf)) && !DirectGate_SRP_BNToPadded(&srp, NULL, buf, sizeof(buf)) &&
          !DirectGate_SRP_BNToPadded(&srp, srp.N, NULL, sizeof(buf)), "padding needs a group, a number and room");
    CHECK(!DirectGate_SRP_ComputeKParam(NULL), "no multiplier for nothing");
    WITHOUT(&srp, N, DirectGate_SRP_ComputeKParam(&srp), "nor without the prime");
    WITHOUT(&srp, g, DirectGate_SRP_ComputeKParam(&srp), "nor without the generator");

    BIGNUM *pU = NULL;
    CHECK(!DirectGate_SRP_ComputeU(NULL, srp.N, srp.N, &pU) && !DirectGate_SRP_ComputeU(&srp, NULL, srp.N, &pU) &&
          !DirectGate_SRP_ComputeU(&srp, srp.N, NULL, &pU) && !DirectGate_SRP_ComputeU(&srp, srp.N, srp.N, NULL),
        "the scrambler needs both public values and a place for itself");
    CHECK(!DirectGate_SRP_ComputeM1(NULL, buf, buf, buf) && !DirectGate_SRP_ComputeM1(&srp, NULL, buf, buf) &&
          !DirectGate_SRP_ComputeM1(&srp, buf, NULL, buf) && !DirectGate_SRP_ComputeM1(&srp, buf, buf, NULL),
        "the client proof needs its inputs");
    CHECK(!DirectGate_SRP_ComputeM2(NULL, buf, buf, buf) && !DirectGate_SRP_ComputeM2(&srp, NULL, buf, buf) &&
          !DirectGate_SRP_ComputeM2(&srp, buf, NULL, buf) && !DirectGate_SRP_ComputeM2(&srp, buf, buf, NULL) &&
          !DirectGate_SRP_ComputeM2(&empty, buf, buf, buf), "and so does the agent's");
    CHECK(!DirectGate_SRP_DeriveKFromS(NULL, srp.N, buf) && !DirectGate_SRP_DeriveKFromS(&srp, NULL, buf) &&
          !DirectGate_SRP_DeriveKFromS(&srp, srp.N, NULL), "the session key needs a secret and room");

    WITHOUT(&srp, g, DirectGate_SRP_LoadVerifier(&srp, salt, sizeof(salt), sVerifier), "a verifier needs the generator");
    WITHOUT(&srp, k, DirectGate_SRP_LoadVerifier(&srp, salt, sizeof(salt), sVerifier), "and the multiplier");
    CHECK(!DirectGate_SRP_LoadVerifier(&srp, salt, sizeof(salt), "zz"), "and digits");
    CHECK(DirectGate_SRP_LoadVerifier(&srp, salt, sizeof(salt), sVerifier), "load the verifier");

    CHECK(!DirectGate_SRP_SetClientPublic(&srp, "zz"), "a public value needs digits");

    directgate_srp_client_t client;
    CHECK(DirectGate_SRP_ClientInit(&client) && DirectGate_SRP_ClientGenerateA(&client, sA, sizeof(sA), sNonce, sizeof(sNonce)),
        "a client offers its public value");
    CHECK(DirectGate_SRP_SetClientPublic(&srp, sA), "which the agent takes");

    WITHOUT(&srp, g, DirectGate_SRP_GenerateChallenge(&srp, sB, sizeof(sB), sNonce, sizeof(sNonce)),
        "a challenge needs the generator");
    WITHOUT(&srp, k, DirectGate_SRP_GenerateChallenge(&srp, sB, sizeof(sB), sNonce, sizeof(sNonce)), "and the multiplier");
    WITHOUT(&srp, v, DirectGate_SRP_GenerateChallenge(&srp, sB, sizeof(sB), sNonce, sizeof(sNonce)), "and the verifier");
    CHECK(!DirectGate_SRP_GenerateChallenge(&srp, NULL, sizeof(sB), sNonce, sizeof(sNonce)) &&
          !DirectGate_SRP_GenerateChallenge(&srp, sB, sizeof(sB), NULL, sizeof(sNonce)), "and room for both halves");
    CHECK(DirectGate_SRP_GenerateChallenge(&srp, sB, sizeof(sB), sNonce, sizeof(sNonce)), "challenge the client");

    WITHOUT(&srp, B, DirectGate_SRP_VerifyClientProof(&srp, "00", sM2, sizeof(sM2)), "a proof is checked against B");
    WITHOUT(&srp, b, DirectGate_SRP_VerifyClientProof(&srp, "00", sM2, sizeof(sM2)), "and b");
    WITHOUT(&srp, v, DirectGate_SRP_VerifyClientProof(&srp, "00", sM2, sizeof(sM2)), "and the verifier");

    (void)nLen;
    DirectGate_SRP_ClientCleanse(&client);
    DirectGate_SRP_Destroy(&srp);
    return 0;
}

static int check_client(void)
{
    char sA[1024], sNonce[128], sM1[128];
    uint8_t buf[512];
    directgate_srp_client_t client, empty;
    memset(&empty, 0, sizeof(empty));

    CHECK(DirectGate_SRP_ClientInit(&client), "start the client's side");
    CHECK(DirectGate_SRP_ClientGroupBytes(NULL) == 0 && DirectGate_SRP_ClientGroupBytes(&empty) == 0, "no group, no size");
    CHECK(!DirectGate_SRP_ClientBNToPadded(NULL, client.N, buf, sizeof(buf)) &&
          !DirectGate_SRP_ClientBNToPadded(&client, NULL, buf, sizeof(buf)), "padding needs a group and a number");

    WITHOUT(&client, N, DirectGate_SRP_ClientGenerateA(&client, sA, sizeof(sA), sNonce, sizeof(sNonce)), "A needs the prime");
    WITHOUT(&client, g, DirectGate_SRP_ClientGenerateA(&client, sA, sizeof(sA), sNonce, sizeof(sNonce)), "and the generator");
    CHECK(!DirectGate_SRP_ClientGenerateA(&client, NULL, sizeof(sA), sNonce, sizeof(sNonce)) &&
          !DirectGate_SRP_ClientGenerateA(&client, sA, sizeof(sA), NULL, sizeof(sNonce)), "and room for A and its nonce");
    CHECK(DirectGate_SRP_ClientGenerateA(&client, sA, sizeof(sA), sNonce, sizeof(sNonce)), "make A");

    const char *pSalt = "000102030405060708090a0b0c0d0e0f";
    CHECK(!DirectGate_SRP_ClientComputeKey(NULL, DEVICE_ID, PASSWORD, pSalt, "02", DIRECTGATE_SRP_SUITE, sM1, sizeof(sM1)),
        "no key for no client");
    WITHOUT(&client, N, DirectGate_SRP_ClientComputeKey(&client, DEVICE_ID, PASSWORD, pSalt, "02", DIRECTGATE_SRP_SUITE,
        sM1, sizeof(sM1)), "a key needs the prime");
    WITHOUT(&client, a, DirectGate_SRP_ClientComputeKey(&client, DEVICE_ID, PASSWORD, pSalt, "02", DIRECTGATE_SRP_SUITE,
        sM1, sizeof(sM1)), "and the client's secret");
    WITHOUT(&client, A, DirectGate_SRP_ClientComputeKey(&client, DEVICE_ID, PASSWORD, pSalt, "02", DIRECTGATE_SRP_SUITE,
        sM1, sizeof(sM1)), "and its public value");
    CHECK(!DirectGate_SRP_ClientComputeKey(&client, DEVICE_ID, "", pSalt, "02", DIRECTGATE_SRP_SUITE, sM1, sizeof(sM1)) &&
          !DirectGate_SRP_ClientComputeKey(&client, DEVICE_ID, PASSWORD, "", "02", DIRECTGATE_SRP_SUITE, sM1, sizeof(sM1)) &&
          !DirectGate_SRP_ClientComputeKey(&client, DEVICE_ID, PASSWORD, pSalt, "", DIRECTGATE_SRP_SUITE, sM1, sizeof(sM1)),
        "and a password, a salt and B");
    CHECK(!DirectGate_SRP_ClientComputeKey(&client, DEVICE_ID, PASSWORD, pSalt, "zz", DIRECTGATE_SRP_SUITE, sM1, sizeof(sM1)),
        "a B that is not a number is refused");

    WITHOUT(&client, A, DirectGate_SRP_ClientVerifyM2(&client, "02", "00"), "the agent's proof is checked against A");
    CHECK(!DirectGate_SRP_ClientVerifyM2(&client, "02", ""), "and needs a proof");

    DirectGate_SRP_ClientCleanse(&client);
    return 0;
}

int main(void)
{
    if (check_server() || check_client()) return 1;
    puts("srp_guards_smoke: OK");
    return 0;
}
