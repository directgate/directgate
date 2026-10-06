/* Every OpenSSL allocation failure on the paths that authenticate a session and encrypt its traffic.
 * alloc_fail_smoke wraps the allocator at link time, which cannot reach libcrypto: it is a shared library with an
 * allocator of its own. OpenSSL takes a replacement through CRYPTO_set_mem_functions(), as long as nothing was
 * allocated before, so it is installed first thing in main().
 *
 * Each scenario runs once to count its allocations, then once per allocation with exactly that one failing.
 * After every run:
 *   - the scenario reported failure, or what it reported as success is complete and correct,
 *   - everything OpenSSL allocated while it ran was released again. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>

#include "src/common/e2e.h"
#include "src/common/keyauth.h"
#include "src/common/srp.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "openssl_alloc_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

/* What a scenario reports: it finished, it failed and said so, or it reported something that is not true */
#define SCN_DONE        0
#define SCN_FAILED      1
#define SCN_WRONG       -1

static long g_nCount;
static long g_nFailAt = -1;
static long g_nLive;
static int g_bArmed;
static int g_bShielded;     /* Allocations still counted as live, but never failed */
static int g_bSivFreesTwice;

static int fail_now(void)
{
    return g_bArmed && !g_bShielded && ++g_nCount == g_nFailAt;
}

static void *ossl_malloc(size_t nSize, const char *pFile, int nLine)
{
    (void)pFile;
    (void)nLine;
    if (fail_now()) return NULL;

    void *p = malloc(nSize);
    if (p != NULL && g_bArmed) g_nLive++;
    return p;
}

static void *ossl_realloc(void *pPtr, size_t nSize, const char *pFile, int nLine)
{
    (void)pFile;
    (void)nLine;
    if (fail_now()) return NULL;

    void *p = realloc(pPtr, nSize);
    if (!g_bArmed) return p;

    if (p != NULL && pPtr == NULL) g_nLive++;
    else if (p == NULL && nSize == 0 && pPtr != NULL) g_nLive--;
    return p;
}

static void ossl_free(void *pPtr, const char *pFile, int nLine)
{
    (void)pFile;
    (void)nLine;
    if (pPtr != NULL && g_bArmed) g_nLive--;
    free(pPtr);
}

static void arm(long nFailAt)
{
    g_nCount = 0;
    g_nLive = 0;
    g_nFailAt = nFailAt;
    g_bArmed = 1;
}

static void disarm(void)
{
    g_bArmed = 0;
    g_nFailAt = -1;
}

/* ---------------- fixtures, built before anything is armed ---------------- */

#define DEVICE_ID       "11111111-2222-3333-4444-555555555555"
#define PASSWORD        "correct horse battery staple"

static uint8_t g_salt[DIRECTGATE_SRP_SALT_SIZE];
static char g_sSaltHex[sizeof(g_salt) * 2 + 1];
static char g_sVerifierHex[1024];
static char g_sAHex[1024];
static directgate_client_key_t g_clientKey;
static uint8_t g_agentPub[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
static uint8_t g_agentSeed[DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE];
static char g_sAgentPubB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
static BIGNUM *g_pRefK;     /* The group's k = H(N | g), which every initialized side must hold */

/* ---------------- scenarios ---------------- */

/* The agent's side of an SRP exchange up to its challenge, torn down as the agent always does */
static int scn_srp_server(void)
{
    directgate_srp_t server;
    char sB[1024], sNonce[DIRECTGATE_SRP_NONCE_SIZE * 2 + 1];

    xbool_t bOk = DirectGate_SRP_Init(&server);
    int nResult = (bOk && BN_cmp(server.k, g_pRefK) != 0) ? SCN_WRONG : SCN_FAILED;
    if (bOk) bOk = DirectGate_SRP_LoadVerifier(&server, g_salt, sizeof(g_salt), g_sVerifierHex);
    if (bOk) bOk = DirectGate_SRP_SetClientPublic(&server, g_sAHex);
    if (bOk) bOk = DirectGate_SRP_GenerateChallenge(&server, sB, sizeof(sB), sNonce, sizeof(sNonce));

    DirectGate_SRP_Destroy(&server);
    if (nResult == SCN_WRONG) return nResult;
    return bOk ? SCN_DONE : SCN_FAILED;
}

/* The whole password handshake: what both sides report as authenticated shares one session key */
static int scn_srp_exchange(void)
{
    directgate_srp_t server;
    directgate_srp_client_t client;
    char sA[1024], sB[1024], sClientNonce[DIRECTGATE_SRP_NONCE_SIZE * 2 + 1];
    char sAgentNonce[DIRECTGATE_SRP_NONCE_SIZE * 2 + 1];
    char sM1[DIRECTGATE_SRP_KEY_SIZE * 2 + 1], sM2[DIRECTGATE_SRP_KEY_SIZE * 2 + 1];
    size_t nBytes = 0;

    xbool_t bClient = DirectGate_SRP_ClientInit(&client);
    xbool_t bServer = DirectGate_SRP_Init(&server);
    if (bServer) xstrncpy(server.sDeviceId, sizeof(server.sDeviceId), DEVICE_ID);

    xbool_t bDone = bClient && bServer &&
        DirectGate_SRP_LoadVerifier(&server, g_salt, sizeof(g_salt), g_sVerifierHex) &&
        DirectGate_SRP_ClientGenerateA(&client, sA, sizeof(sA), sClientNonce, sizeof(sClientNonce)) &&
        DirectGate_SRP_SetClientPublic(&server, sA) &&
        DirectGate_SRP_GenerateChallenge(&server, sB, sizeof(sB), sAgentNonce, sizeof(sAgentNonce)) &&
        DirectGate_SRP_HexToBytes(sClientNonce, server.clientNonce, sizeof(server.clientNonce), &nBytes) &&
        DirectGate_SRP_HexToBytes(sAgentNonce, client.agentNonce, sizeof(client.agentNonce), &nBytes) &&
        DirectGate_SRP_ClientComputeKey(&client, DEVICE_ID, PASSWORD, g_sSaltHex, sB, DIRECTGATE_SRP_SUITE,
            sM1, sizeof(sM1)) &&
        DirectGate_SRP_VerifyClientProof(&server, sM1, sM2, sizeof(sM2));

    int nResult = bDone ? SCN_DONE : SCN_FAILED;
    if ((bClient && BN_cmp(client.k, g_pRefK) != 0) || (bServer && BN_cmp(server.k, g_pRefK) != 0)) nResult = SCN_WRONG;
    else if (bDone && (!server.bAuthenticated || memcmp(server.K, client.K, sizeof(server.K)) ||
        !DirectGate_SRP_ClientVerifyM2(&client, sB, sM2))) nResult = SCN_WRONG;
    else if (!bDone && server.bAuthenticated) nResult = SCN_WRONG;

    DirectGate_SRP_ClientCleanse(&client);
    DirectGate_SRP_Destroy(&server);
    return nResult;
}

/* The key handshake both ways: whatever both sides report as authenticated ends in the same shared secret */
static int scn_keyauth(void)
{
    directgate_keyauth_t client, agent;
    DirectGate_KeyAuth_Init(&client);
    DirectGate_KeyAuth_Init(&agent);

    char sClientPub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE], sClientEph[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sClientNonce[DIRECTGATE_KEYAUTH_NONCE_SIZE * 2 + 1], sClientSig[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];
    char sAgentPub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE], sAgentEph[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sAgentNonce[DIRECTGATE_KEYAUTH_NONCE_SIZE * 2 + 1], sChallenge[DIRECTGATE_KEYAUTH_CHALLENGE_SIZE * 2 + 1];
    char sAgentSig[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];

    xbool_t bProof = DirectGate_KeyAuth_ClientInit(&client, DEVICE_ID, &g_clientKey, g_sAgentPubB64) &&
        DirectGate_KeyAuth_ClientBuildHello(&client, sClientPub, sizeof(sClientPub), sClientEph, sizeof(sClientEph),
            sClientNonce, sizeof(sClientNonce)) &&
        DirectGate_KeyAuth_AgentProcessHello(&agent, DEVICE_ID, sClientPub, sClientEph, sClientNonce) &&
        DirectGate_KeyAuth_AgentBuildChallenge(&agent, g_agentSeed, g_agentPub, sAgentPub, sizeof(sAgentPub),
            sAgentEph, sizeof(sAgentEph), sAgentNonce, sizeof(sAgentNonce), sChallenge, sizeof(sChallenge),
            sAgentSig, sizeof(sAgentSig)) &&
        DirectGate_KeyAuth_ClientProcessChallenge(&client, &g_clientKey, sAgentPub, sAgentEph, sAgentNonce,
            sChallenge, sAgentSig, sClientSig, sizeof(sClientSig)) &&
        DirectGate_KeyAuth_AgentVerifyProof(&agent, sClientSig);

    /* The agent closes the session when the shared secret cannot be derived after a good proof */
    xbool_t bAgent = bProof && DirectGate_KeyAuth_DeriveShared(&agent);
    xbool_t bClient = bAgent && DirectGate_KeyAuth_ClientAccept(&client) && DirectGate_KeyAuth_DeriveShared(&client);
    int nResult = bClient ? SCN_DONE : SCN_FAILED;
    if (bClient && memcmp(client.sharedSecret, agent.sharedSecret, sizeof(agent.sharedSecret))) nResult = SCN_WRONG;
    if (!bProof && agent.eState == DIRECTGATE_KEYAUTH_STATE_AUTHENTICATED) nResult = SCN_WRONG;
    if ((!bAgent && agent.bHaveSharedSecret) || (!bClient && client.bHaveSharedSecret)) nResult = SCN_WRONG;

    DirectGate_KeyAuth_Cleanse(&client);
    DirectGate_KeyAuth_Cleanse(&agent);
    return nResult;
}

/* Session keys from both sides, and a message each way: what decrypts is what was sent */
static int scn_e2e(void)
{
    uint8_t sessionKey[32], agentNonce[32], clientNonce[32];
    for (size_t i = 0; i < sizeof(sessionKey); i++)
    {
        sessionKey[i] = (uint8_t)(i * 3 + 1);
        agentNonce[i] = (uint8_t)(i * 5 + 2);
        clientNonce[i] = (uint8_t)(i * 7 + 3);
    }

    directgate_e2e_t agent, client;
    DirectGate_E2E_Init(&agent);
    DirectGate_E2E_Init(&client);

    const uint8_t message[] = "a message the relay must not read";
    uint8_t *pSealed = NULL, *pOpened = NULL;
    size_t nSealed = 0, nOpened = 0;
    int nResult = SCN_FAILED;

    xbool_t bKeys = DirectGate_E2E_DeriveFromSRP(&agent, sessionKey, sizeof(sessionKey), agentNonce, clientNonce,
            sizeof(agentNonce), DEVICE_ID, XTRUE) &&
        DirectGate_E2E_DeriveFromKey(&client, sessionKey, sizeof(sessionKey), agentNonce, clientNonce,
            sizeof(agentNonce), DEVICE_ID, XFALSE) &&
        DirectGate_E2E_DeriveFromSRP(&client, sessionKey, sizeof(sessionKey), agentNonce, clientNonce,
            sizeof(agentNonce), DEVICE_ID, XFALSE);

    g_bShielded = g_bSivFreesTwice;
    if (bKeys && (pSealed = DirectGate_E2E_Encrypt(&agent, message, sizeof(message), &nSealed)) != NULL &&
        (pOpened = DirectGate_E2E_Decrypt(&client, pSealed, nSealed, &nOpened)) != NULL)
    {
        nResult = (nOpened == sizeof(message) && !memcmp(pOpened, message, nOpened)) ? SCN_DONE : SCN_WRONG;
    }
    g_bShielded = 0;

    free(pSealed);
    free(pOpened);
    DirectGate_E2E_Clear(&agent);
    DirectGate_E2E_Clear(&client);
    return nResult;
}

/* Up to 3.0.17, 3.2.5, 3.3.4, 3.4.2 and 3.5.3, and in all of 3.1, an allocation failing part way through an AES-SIV
   key setup makes OpenSSL free what the setup allocated so far once more when the cipher context is freed
   (ossl_siv128_init, crypto/modes/siv128.c). With those, the E2E round trip keeps its cipher calls out of the sweep. */
static int siv_setup_frees_twice(void)
{
    if (OPENSSL_version_major() != 3) return 0;
    unsigned int nPatch = OPENSSL_version_patch();

    switch (OPENSSL_version_minor())
    {
        case 0: return nPatch < 18;
        case 1: return 1;
        case 2: return nPatch < 6;
        case 3: return nPatch < 5;
        case 4: return nPatch < 3;
        case 5: return nPatch < 4;
        default: return 0;
    }
}

/* Under valgrind every scrypt costs seconds, so the scenarios that run it fail every few allocations there instead
   of every one; the plain lanes still fail each of them */
static long sweep_stride(long nStride)
{
    const char *pPreload = getenv("LD_PRELOAD");
    return (pPreload != NULL && strstr(pPreload, "vgpreload") != NULL) ? nStride : 1;
}

static int sweep(const char *pName, int (*scenario)(void), long nStride)
{
    arm(-1);
    int nFirst = scenario();
    ERR_clear_error();
    long nAllocs = g_nCount, nLive = g_nLive;
    disarm();

    if (nFirst != SCN_DONE || nLive != 0 || nAllocs <= 0)
    {
        fprintf(stderr, "openssl_alloc_smoke: %s did not run cleanly without injected failures\n", pName);
        return 1;
    }

    for (long i = 1; i <= nAllocs; i += nStride)
    {
        arm(i);
        int nResult = scenario();
        ERR_clear_error();
        nLive = g_nLive;
        disarm();

        if (nResult == SCN_WRONG || nLive != 0)
        {
            fprintf(stderr, "openssl_alloc_smoke: %s %s when allocation %ld of %ld failed\n", pName,
                nResult == SCN_WRONG ? "reported a wrong success" : "leaked", i, nAllocs);
            return 1;
        }
    }

    return 0;
}

int main(void)
{
    CHECK(CRYPTO_set_mem_functions(ossl_malloc, ossl_realloc, ossl_free) == 1,
        "OpenSSL takes the injecting allocator before anything is allocated");

    g_bSivFreesTwice = siv_setup_frees_twice();
    if (g_bSivFreesTwice)
        printf("openssl_alloc_smoke: OpenSSL %s frees a failed AES-SIV key setup twice, the cipher calls are not swept\n",
            OpenSSL_version(OPENSSL_VERSION_STRING));

    for (size_t i = 0; i < sizeof(g_salt); i++) g_salt[i] = (uint8_t)(i * 7 + 1);
    for (size_t i = 0; i < sizeof(g_salt); i++) snprintf(&g_sSaltHex[i * 2], 3, "%02x", g_salt[i]);
    CHECK(DirectGate_SRP_CreateVerifier(PASSWORD, g_salt, sizeof(g_salt), g_sVerifierHex, sizeof(g_sVerifierHex)),
        "build the verifier fixture");

    directgate_srp_t reference;
    CHECK(DirectGate_SRP_Init(&reference) && (g_pRefK = BN_dup(reference.k)) != NULL, "compute the group's k");
    DirectGate_SRP_Destroy(&reference);

    directgate_srp_client_t client;
    char sNonce[DIRECTGATE_SRP_NONCE_SIZE * 2 + 1];
    CHECK(DirectGate_SRP_ClientInit(&client), "build the client fixture");
    CHECK(DirectGate_SRP_ClientGenerateA(&client, g_sAHex, sizeof(g_sAHex), sNonce, sizeof(sNonce)), "build A");
    DirectGate_SRP_ClientCleanse(&client);

    CHECK(DirectGate_KeyAuth_KeyGenerate(&g_clientKey), "generate the client key");
    CHECK(DirectGate_KeyAuth_Ed25519Generate(g_agentPub, g_agentSeed), "generate the agent identity");
    CHECK(DirectGate_KeyAuth_Base64Encode(g_agentPub, sizeof(g_agentPub), g_sAgentPubB64, sizeof(g_sAgentPubB64)),
        "encode the agent identity");

    /* Warm OpenSSL's lazily built global state, the error queue included, before anything is counted */
    CHECK(scn_srp_exchange() == SCN_DONE && scn_keyauth() == SCN_DONE && scn_e2e() == SCN_DONE, "warm every path");
    ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
    ERR_clear_error();

    CHECK(sweep("the SRP server round", scn_srp_server, 1) == 0, "the SRP server round survives every failure");
    CHECK(sweep("the SRP exchange", scn_srp_exchange, sweep_stride(8)) == 0, "the SRP exchange survives every failure");
    CHECK(sweep("the key handshake", scn_keyauth, 1) == 0, "the key handshake survives every failure");
    CHECK(sweep("the E2E round trip", scn_e2e, 1) == 0, "the E2E round trip survives every failure");

    DirectGate_KeyAuth_KeyCleanse(&g_clientKey);
    BN_free(g_pRefK);
    puts("openssl_alloc_smoke: OK");
    return 0;
}
