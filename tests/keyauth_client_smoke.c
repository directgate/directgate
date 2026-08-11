#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "src/common/includes.h"
#include "src/common/keyauth.h"
#include "src/common/e2e.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "keyauth_client_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static int write_text(const char *pPath, const char *pText)
{
    FILE *pFile = fopen(pPath, "wb");
    if (pFile == NULL) return 0;
    size_t nLen = strlen(pText);
    int nOk = fwrite(pText, 1, nLen, pFile) == nLen;
    return fclose(pFile) == 0 && nOk;
}

static int test_key_file(const char *pRoot)
{
    char sPath[XPATH_MAX];
    char sNested[XPATH_MAX];
    snprintf(sPath, sizeof(sPath), "%s/key.json", pRoot);
    snprintf(sNested, sizeof(sNested), "%s/auth/key.json", pRoot);

    directgate_client_key_t key;
    CHECK(DirectGate_KeyAuth_KeyGenerate(&key), "generate client key");

    directgate_client_key_t second;
    CHECK(DirectGate_KeyAuth_KeyGenerate(&second), "generate a second key");
    CHECK(memcmp(key.clientPub, second.clientPub, sizeof(key.clientPub)) != 0,
        "generated keys must differ");

    /* The seed has to be the one that produces the recorded public key */
    uint8_t derived[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    CHECK(DirectGate_KeyAuth_Ed25519DerivePub(key.clientSeed, derived), "derive public key");
    CHECK(memcmp(derived, key.clientPub, sizeof(derived)) == 0, "seed matches public key");

    /* Saving must create the whole directory chain, not just the file */
    CHECK(DirectGate_KeyAuth_KeySave(&key, sNested), "save into a missing directory");

    char sDir[XPATH_MAX];
    snprintf(sDir, sizeof(sDir), "%s/auth", pRoot);

    struct stat info;
    CHECK(stat(sNested, &info) == 0, "stat key file");
#ifndef _WIN32
    CHECK((info.st_mode & 0077) == 0, "key file must not be group or world readable");
    CHECK(stat(sDir, &info) == 0, "stat key directory");
    CHECK((info.st_mode & 0077) == 0, "key directory must not be group or world readable");
#endif

    directgate_client_key_t loaded;
    CHECK(DirectGate_KeyAuth_KeyLoad(&loaded, sNested), "load key file");
    CHECK(memcmp(loaded.clientPub, key.clientPub, sizeof(key.clientPub)) == 0,
        "round trip public key");
    CHECK(memcmp(loaded.clientSeed, key.clientSeed, sizeof(key.clientSeed)) == 0,
        "round trip seed");

    CHECK(!DirectGate_KeyAuth_KeyLoad(&loaded, sPath), "load a missing key file");
    CHECK(!DirectGate_KeyAuth_KeyLoad(&loaded, NULL), "load a NULL path");
    CHECK(!DirectGate_KeyAuth_KeyLoad(NULL, sNested), "load into NULL");

    CHECK(write_text(sPath, "{ not json"), "write malformed key file");
    CHECK(!DirectGate_KeyAuth_KeyLoad(&loaded, sPath), "reject malformed JSON");

    CHECK(write_text(sPath, "{\"type\":\"directgate-client-key-v1\","
        "\"clientPub\":\"AA==\",\"clientSeed\":\"AA==\"}"), "write wrong version");
    CHECK(!DirectGate_KeyAuth_KeyLoad(&loaded, sPath), "reject an unknown file type");

    CHECK(write_text(sPath, "{\"type\":\"directgate-client-key-v2\","
        "\"clientPub\":\"AAAA\"}"), "write truncated key file");
    CHECK(!DirectGate_KeyAuth_KeyLoad(&loaded, sPath), "reject a missing clientSeed");

    CHECK(write_text(sPath, "{\"type\":\"directgate-client-key-v2\","
        "\"clientPub\":\"AAAA\",\"clientSeed\":\"AAAA\"}"), "write short keys");
    CHECK(!DirectGate_KeyAuth_KeyLoad(&loaded, sPath), "reject wrong key lengths");

    /* A seed that does not match its public key is a corrupted or tampered
     * file; catching it here beats an opaque handshake failure later. */
    char sMismatch[XSTR_MID];
    char sPubB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sSeedB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];

    CHECK(DirectGate_KeyAuth_Base64Encode(second.clientPub, sizeof(second.clientPub),
        sPubB64, sizeof(sPubB64)), "encode mismatched public key");
    CHECK(DirectGate_KeyAuth_Base64Encode(key.clientSeed, sizeof(key.clientSeed),
        sSeedB64, sizeof(sSeedB64)), "encode mismatched seed");

    snprintf(sMismatch, sizeof(sMismatch), "{\"type\":\"directgate-client-key-v2\","
        "\"clientPub\":\"%s\",\"clientSeed\":\"%s\"}", sPubB64, sSeedB64);
    CHECK(write_text(sPath, sMismatch), "write mismatched key file");
    CHECK(!DirectGate_KeyAuth_KeyLoad(&loaded, sPath), "reject a seed that is not the public key's");

    DirectGate_KeyAuth_KeyCleanse(&loaded);
    CHECK(unlink(sPath) == 0, "unlink key file");
    CHECK(unlink(sNested) == 0, "unlink nested key file");
    CHECK(rmdir(sDir) == 0, "rmdir key directory");

    DirectGate_KeyAuth_KeyCleanse(&key);
    DirectGate_KeyAuth_KeyCleanse(&second);
    return 0;
}

/*
 * Drives the client state machine against the real agent one, which is what
 * the browser talks to. Anything that diverges in the transcript, the field
 * encodings or the nonce roles shows up here as a failed handshake.
 */
static int test_handshake(void)
{
    const char *pDeviceId = "11111111-2222-3333-4444-555555555555";

    directgate_client_key_t key;
    CHECK(DirectGate_KeyAuth_KeyGenerate(&key), "generate client key");

    uint8_t agentPub[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    uint8_t agentSeed[DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE];
    CHECK(DirectGate_KeyAuth_Ed25519Generate(agentPub, agentSeed), "generate agent identity");

    char sAgentPubB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    CHECK(DirectGate_KeyAuth_Base64Encode(agentPub, sizeof(agentPub),
        sAgentPubB64, sizeof(sAgentPubB64)), "encode agent identity");

    directgate_keyauth_t client;
    CHECK(DirectGate_KeyAuth_ClientInit(&client, pDeviceId, &key, sAgentPubB64),
        "init client state");

    char sClientPubB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sClientEphB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sClientNonceHex[(DIRECTGATE_KEYAUTH_NONCE_SIZE * 2) + 1];

    CHECK(DirectGate_KeyAuth_ClientBuildHello(&client,
        sClientPubB64, sizeof(sClientPubB64),
        sClientEphB64, sizeof(sClientEphB64),
        sClientNonceHex, sizeof(sClientNonceHex)), "build client hello");

    directgate_keyauth_t agent;
    DirectGate_KeyAuth_Init(&agent);
    CHECK(DirectGate_KeyAuth_AgentProcessHello(&agent, pDeviceId,
        sClientPubB64, sClientEphB64, sClientNonceHex), "agent processes hello");

    char sChalAgentPub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sChalAgentEph[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sChalNonce[(DIRECTGATE_KEYAUTH_NONCE_SIZE * 2) + 1];
    char sChalChallenge[(DIRECTGATE_KEYAUTH_CHALLENGE_SIZE * 2) + 1];
    char sChalSig[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];

    CHECK(DirectGate_KeyAuth_AgentBuildChallenge(&agent, agentSeed, agentPub,
        sChalAgentPub, sizeof(sChalAgentPub), sChalAgentEph, sizeof(sChalAgentEph),
        sChalNonce, sizeof(sChalNonce), sChalChallenge, sizeof(sChalChallenge),
        sChalSig, sizeof(sChalSig)), "agent builds challenge");

    char sClientSig[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];
    CHECK(DirectGate_KeyAuth_ClientProcessChallenge(&client, &key,
        sChalAgentPub, sChalAgentEph, sChalNonce, sChalChallenge, sChalSig,
        sClientSig, sizeof(sClientSig)), "client processes challenge");

    CHECK(DirectGate_KeyAuth_AgentVerifyProof(&agent, sClientSig), "agent verifies proof");
    CHECK(DirectGate_KeyAuth_DeriveShared(&agent), "agent derives shared secret");

    CHECK(DirectGate_KeyAuth_ClientAccept(&client), "client accepts result");
    CHECK(DirectGate_KeyAuth_DeriveShared(&client), "client derives shared secret");

    CHECK(memcmp(client.sharedSecret, agent.sharedSecret,
        sizeof(client.sharedSecret)) == 0, "both sides agree on the shared secret");

    /* The directional E2E keys must line up: what the agent encrypts, the
     * client decrypts. bIsAgent is what selects TX vs RX. */
    directgate_e2e_t clientE2E;
    directgate_e2e_t agentE2E;
    DirectGate_E2E_Init(&clientE2E);
    DirectGate_E2E_Init(&agentE2E);

    CHECK(DirectGate_E2E_DeriveFromKey(&clientE2E, client.sharedSecret,
        sizeof(client.sharedSecret), client.peerNonce, client.localNonce,
        DIRECTGATE_KEYAUTH_NONCE_SIZE, pDeviceId, XFALSE), "client derives E2E keys");

    CHECK(DirectGate_E2E_DeriveFromKey(&agentE2E, agent.sharedSecret,
        sizeof(agent.sharedSecret), agent.localNonce, agent.peerNonce,
        DIRECTGATE_KEYAUTH_NONCE_SIZE, pDeviceId, XTRUE), "agent derives E2E keys");

    const char *pPlain = "directgate key auth round trip";
    size_t nCipherLen = 0;
    uint8_t *pCipher = DirectGate_E2E_Encrypt(&agentE2E, (const uint8_t*)pPlain,
        strlen(pPlain), &nCipherLen);
    CHECK(pCipher != NULL && nCipherLen > 0, "agent encrypts");

    size_t nPlainLen = 0;
    uint8_t *pDecrypted = DirectGate_E2E_Decrypt(&clientE2E, pCipher, nCipherLen, &nPlainLen);
    CHECK(pDecrypted != NULL, "client decrypts what the agent encrypted");
    CHECK(nPlainLen == strlen(pPlain) && memcmp(pDecrypted, pPlain, nPlainLen) == 0,
        "round trip plaintext");

    free(pCipher);
    free(pDecrypted);

    DirectGate_E2E_Clear(&clientE2E);
    DirectGate_E2E_Clear(&agentE2E);
    DirectGate_KeyAuth_Cleanse(&client);
    DirectGate_KeyAuth_Cleanse(&agent);
    DirectGate_KeyAuth_KeyCleanse(&key);
    OPENSSL_cleanse(agentSeed, sizeof(agentSeed));
    return 0;
}

/*
 * The pin is the whole point of key auth: a host that answers with a
 * different identity than the one the backend published must be refused even
 * when every field is internally consistent and correctly signed.
 */
static int test_host_pinning(void)
{
    const char *pDeviceId = "device-under-test";

    directgate_client_key_t key;
    CHECK(DirectGate_KeyAuth_KeyGenerate(&key), "generate client key");

    uint8_t expectedPub[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    uint8_t expectedSeed[DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE];
    uint8_t roguePub[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    uint8_t rogueSeed[DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE];

    CHECK(DirectGate_KeyAuth_Ed25519Generate(expectedPub, expectedSeed), "generate expected host");
    CHECK(DirectGate_KeyAuth_Ed25519Generate(roguePub, rogueSeed), "generate rogue host");

    char sExpectedB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    CHECK(DirectGate_KeyAuth_Base64Encode(expectedPub, sizeof(expectedPub),
        sExpectedB64, sizeof(sExpectedB64)), "encode expected host");

    directgate_keyauth_t client;
    CHECK(DirectGate_KeyAuth_ClientInit(&client, pDeviceId, &key, sExpectedB64),
        "init client state");

    char sClientPubB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sClientEphB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sClientNonceHex[(DIRECTGATE_KEYAUTH_NONCE_SIZE * 2) + 1];

    CHECK(DirectGate_KeyAuth_ClientBuildHello(&client,
        sClientPubB64, sizeof(sClientPubB64),
        sClientEphB64, sizeof(sClientEphB64),
        sClientNonceHex, sizeof(sClientNonceHex)), "build client hello");

    /* A rogue host runs the real agent flow with its own identity */
    directgate_keyauth_t rogue;
    DirectGate_KeyAuth_Init(&rogue);
    CHECK(DirectGate_KeyAuth_AgentProcessHello(&rogue, pDeviceId,
        sClientPubB64, sClientEphB64, sClientNonceHex), "rogue processes hello");

    char sChalAgentPub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sChalAgentEph[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sChalNonce[(DIRECTGATE_KEYAUTH_NONCE_SIZE * 2) + 1];
    char sChalChallenge[(DIRECTGATE_KEYAUTH_CHALLENGE_SIZE * 2) + 1];
    char sChalSig[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];

    CHECK(DirectGate_KeyAuth_AgentBuildChallenge(&rogue, rogueSeed, roguePub,
        sChalAgentPub, sizeof(sChalAgentPub), sChalAgentEph, sizeof(sChalAgentEph),
        sChalNonce, sizeof(sChalNonce), sChalChallenge, sizeof(sChalChallenge),
        sChalSig, sizeof(sChalSig)), "rogue builds a well formed challenge");

    char sClientSig[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];
    CHECK(!DirectGate_KeyAuth_ClientProcessChallenge(&client, &key,
        sChalAgentPub, sChalAgentEph, sChalNonce, sChalChallenge, sChalSig,
        sClientSig, sizeof(sClientSig)), "client rejects a host identity mismatch");
    CHECK(client.eState == DIRECTGATE_KEYAUTH_STATE_FAILED, "state moves to failed");

    /* Claiming the right identity without holding its private key must fail
     * on the signature instead. */
    directgate_keyauth_t liar;
    DirectGate_KeyAuth_Init(&liar);
    CHECK(DirectGate_KeyAuth_ClientInit(&client, pDeviceId, &key, sExpectedB64), "re-init client");
    CHECK(DirectGate_KeyAuth_ClientBuildHello(&client,
        sClientPubB64, sizeof(sClientPubB64),
        sClientEphB64, sizeof(sClientEphB64),
        sClientNonceHex, sizeof(sClientNonceHex)), "rebuild client hello");
    CHECK(DirectGate_KeyAuth_AgentProcessHello(&liar, pDeviceId,
        sClientPubB64, sClientEphB64, sClientNonceHex), "liar processes hello");
    CHECK(DirectGate_KeyAuth_AgentBuildChallenge(&liar, rogueSeed, expectedPub,
        sChalAgentPub, sizeof(sChalAgentPub), sChalAgentEph, sizeof(sChalAgentEph),
        sChalNonce, sizeof(sChalNonce), sChalChallenge, sizeof(sChalChallenge),
        sChalSig, sizeof(sChalSig)), "liar signs with the wrong key");

    CHECK(!DirectGate_KeyAuth_ClientProcessChallenge(&client, &key,
        sChalAgentPub, sChalAgentEph, sChalNonce, sChalChallenge, sChalSig,
        sClientSig, sizeof(sClientSig)), "client rejects a bad host signature");

    /* Incomplete challenges must not be treated as anything but a failure */
    CHECK(DirectGate_KeyAuth_ClientInit(&client, pDeviceId, &key, sExpectedB64), "re-init client");
    CHECK(DirectGate_KeyAuth_ClientBuildHello(&client,
        sClientPubB64, sizeof(sClientPubB64),
        sClientEphB64, sizeof(sClientEphB64),
        sClientNonceHex, sizeof(sClientNonceHex)), "rebuild client hello");
    CHECK(!DirectGate_KeyAuth_ClientProcessChallenge(&client, &key,
        sChalAgentPub, sChalAgentEph, NULL, sChalChallenge, sChalSig,
        sClientSig, sizeof(sClientSig)), "client rejects an incomplete challenge");

    DirectGate_KeyAuth_Cleanse(&client);
    DirectGate_KeyAuth_Cleanse(&rogue);
    DirectGate_KeyAuth_Cleanse(&liar);
    DirectGate_KeyAuth_KeyCleanse(&key);
    OPENSSL_cleanse(expectedSeed, sizeof(expectedSeed));
    OPENSSL_cleanse(rogueSeed, sizeof(rogueSeed));
    return 0;
}

int main(void)
{
    xlog_setfl(XLOG_NONE);

    char sRoot[] = "/tmp/directgate_keyauth_client.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "mkdtemp");

    int nStatus = test_key_file(sRoot);
    if (nStatus) return nStatus;

    CHECK(rmdir(sRoot) == 0, "rmdir root");

    nStatus = test_handshake();
    if (nStatus) return nStatus;

    nStatus = test_host_pinning();
    if (nStatus) return nStatus;

    puts("keyauth_client_smoke: OK");
    return 0;
}
