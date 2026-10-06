#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "src/common/keyauth.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "keyauth_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static void hex_encode(const uint8_t *pBytes, size_t nLen,
                       char *pOut, size_t nOutSize)
{
    static const char *pHex = "0123456789abcdef";
    if (nOutSize < nLen * 2 + 1) {
        pOut[0] = '\0';
        return;
    }
    for (size_t i = 0; i < nLen; i++) {
        pOut[i * 2] = pHex[(pBytes[i] >> 4) & 0x0f];
        pOut[i * 2 + 1] = pHex[pBytes[i] & 0x0f];
    }
    pOut[nLen * 2] = '\0';
}

static int write_text(const char *pPath, const char *pText)
{
    FILE *pFile = fopen(pPath, "w");
    if (pFile == NULL) return 0;
    fputs(pText, pFile);
    fclose(pFile);
    return 1;
}

/* What each side refuses, and the argument guards of every entry point */
static int keyauth_refusals(void)
{
    const char *pDeviceId = "keyauth-guard-device";
    uint8_t seed[DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE], pub[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    uint8_t sig[DIRECTGATE_KEYAUTH_ED25519_SIG_SIZE], zeros[DIRECTGATE_KEYAUTH_X25519_PUB_SIZE];
    uint8_t ephPub[DIRECTGATE_KEYAUTH_X25519_PUB_SIZE], ephPriv[DIRECTGATE_KEYAUTH_X25519_PRIV_SIZE];
    uint8_t shared[DIRECTGATE_KEYAUTH_X25519_SHARED_SIZE], bytes[4];
    char sHex[16], sB64[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];
    size_t nLen = 0;
    memset(zeros, 0, sizeof(zeros));

    CHECK(!strcmp(DirectGate_KeyAuth_StateName(DIRECTGATE_KEYAUTH_STATE_IDLE), "IDLE") &&
          !strcmp(DirectGate_KeyAuth_StateName(DIRECTGATE_KEYAUTH_STATE_HELLO_RECEIVED), "HELLO_RECEIVED") &&
          !strcmp(DirectGate_KeyAuth_StateName(DIRECTGATE_KEYAUTH_STATE_FAILED), "FAILED"), "every state has a name");
    DirectGate_KeyAuth_Init(NULL);
    DirectGate_KeyAuth_Cleanse(NULL);
    DirectGate_KeyAuth_KeyCleanse(NULL);

    CHECK(!DirectGate_KeyAuth_HexToBytes(NULL, bytes, sizeof(bytes), &nLen) &&
          !DirectGate_KeyAuth_HexToBytes("00", NULL, sizeof(bytes), &nLen), "hex decoding needs input and output");
    CHECK(!DirectGate_KeyAuth_HexToBytes("0x", bytes, sizeof(bytes), &nLen) &&
          !DirectGate_KeyAuth_HexToBytes("x0", bytes, sizeof(bytes), &nLen), "hex decoding refuses a non-hex digit");
    CHECK(!DirectGate_KeyAuth_HexToBytes("0011223344", bytes, sizeof(bytes), &nLen), "hex decoding refuses an overflow");
    CHECK(DirectGate_KeyAuth_HexToBytes("0aFf", bytes, sizeof(bytes), NULL) && bytes[1] == 0xff,
        "hex decoding takes either case");
    CHECK(!DirectGate_KeyAuth_BytesToHex(NULL, 1, sHex, sizeof(sHex)) && !DirectGate_KeyAuth_BytesToHex(bytes, 1, NULL, 3) &&
          !DirectGate_KeyAuth_BytesToHex(bytes, 1, sHex, 0), "hex encoding needs input and room");
    CHECK(!DirectGate_KeyAuth_Base64Encode(NULL, 1, sB64, sizeof(sB64)) && !DirectGate_KeyAuth_Base64Encode(bytes, 1, NULL, 8),
        "base64 encoding needs input and output");
    CHECK(!DirectGate_KeyAuth_Base64Decode(NULL, bytes, sizeof(bytes), &nLen) &&
          !DirectGate_KeyAuth_Base64Decode("AAAA", NULL, sizeof(bytes), &nLen), "base64 decoding needs input and output");
    CHECK(DirectGate_KeyAuth_Base64Decode("AAA=", bytes, sizeof(bytes), NULL), "base64 decoding needs no length");

    CHECK(!DirectGate_KeyAuth_Ed25519Generate(pub, NULL), "a key pair needs room for the seed");
    CHECK(DirectGate_KeyAuth_Ed25519Generate(pub, seed), "generate a signing key");
    memset(bytes, 0x5a, sizeof(bytes));
    CHECK(!DirectGate_KeyAuth_Ed25519DerivePub(NULL, pub) && !DirectGate_KeyAuth_Ed25519DerivePub(seed, NULL),
        "deriving a public key needs a seed and room");
    CHECK(!DirectGate_KeyAuth_Ed25519Sign(NULL, bytes, 1, sig) && !DirectGate_KeyAuth_Ed25519Sign(seed, NULL, 1, sig) &&
          !DirectGate_KeyAuth_Ed25519Sign(seed, bytes, 1, NULL), "signing needs a seed, a message and room");
    CHECK(DirectGate_KeyAuth_Ed25519Sign(seed, bytes, sizeof(bytes), sig), "sign a message");
    CHECK(!DirectGate_KeyAuth_Ed25519Verify(NULL, bytes, sizeof(bytes), sig) &&
          !DirectGate_KeyAuth_Ed25519Verify(pub, NULL, sizeof(bytes), sig) &&
          !DirectGate_KeyAuth_Ed25519Verify(pub, bytes, sizeof(bytes), NULL), "verifying needs a key, a message and a signature");
    CHECK(!DirectGate_KeyAuth_Ed25519Verify(zeros, bytes, sizeof(bytes), sig), "a signature does not verify under another key");

    /* An all-zero ephemeral key is a low-order point: it must never yield a shared secret */
    CHECK(!DirectGate_KeyAuth_X25519Generate(NULL, ephPriv) && !DirectGate_KeyAuth_X25519Generate(ephPub, NULL),
        "an exchange key pair needs room");
    CHECK(DirectGate_KeyAuth_X25519Generate(ephPub, ephPriv), "generate an exchange key");
    CHECK(!DirectGate_KeyAuth_X25519Derive(NULL, ephPub, shared) && !DirectGate_KeyAuth_X25519Derive(ephPriv, NULL, shared) &&
          !DirectGate_KeyAuth_X25519Derive(ephPriv, ephPub, NULL), "deriving needs both keys and room");
    CHECK(!DirectGate_KeyAuth_X25519Derive(ephPriv, zeros, shared), "a zero peer key yields no shared secret");

    /* Every transcript field is required, and the device id must fit its 16-bit length */
    xbyte_buffer_t transcript;
    XByteBuffer_Init(&transcript, XSTDNON, XFALSE);
    uint8_t challenge[DIRECTGATE_KEYAUTH_CHALLENGE_SIZE] = {0}, nonce[DIRECTGATE_KEYAUTH_NONCE_SIZE] = {0};
    CHECK(!DirectGate_KeyAuth_BuildTranscript(&transcript, 'c', "", pub, pub, challenge, nonce, nonce, ephPub, ephPub),
        "a transcript needs a device id");
    CHECK(!DirectGate_KeyAuth_BuildTranscript(&transcript, 'c', pDeviceId, NULL, pub, challenge, nonce, nonce, ephPub, ephPub),
        "a transcript needs the client key");
    CHECK(!DirectGate_KeyAuth_BuildTranscript(&transcript, 'c', pDeviceId, pub, pub, NULL, nonce, nonce, ephPub, ephPub),
        "a transcript needs the challenge");
    CHECK(!DirectGate_KeyAuth_BuildTranscript(&transcript, 'c', pDeviceId, pub, pub, challenge, NULL, nonce, ephPub, ephPub),
        "a transcript needs both nonces");
    CHECK(!DirectGate_KeyAuth_BuildTranscript(&transcript, 'c', pDeviceId, pub, pub, challenge, nonce, nonce, NULL, ephPub),
        "a transcript needs both exchange keys");
    char *pLongId = (char*)malloc(UINT16_MAX + 2);
    CHECK(pLongId != NULL, "allocate a long device id");
    memset(pLongId, 'd', UINT16_MAX + 1);
    pLongId[UINT16_MAX + 1] = '\0';
    xbool_t bLong = DirectGate_KeyAuth_BuildTranscript(&transcript, 'c', pLongId, pub, pub, challenge, nonce, nonce,
        ephPub, ephPub);
    free(pLongId);
    XByteBuffer_Clear(&transcript);
    CHECK(!bLong, "a device id longer than its length field is refused");

    /* Authorization only ever matches a whole, well formed key */
    char sPubB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE], sShortB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    CHECK(DirectGate_KeyAuth_Base64Encode(pub, sizeof(pub), sPubB64, sizeof(sPubB64)), "encode the key");
    CHECK(DirectGate_KeyAuth_Base64Encode(pub, 16, sShortB64, sizeof(sShortB64)), "encode half a key");
    const char *pKeys[] = { "", "%%%", sShortB64, sPubB64 };
    CHECK(!DirectGate_KeyAuth_IsClientAuthorized(pub, NULL, 1) && !DirectGate_KeyAuth_IsClientAuthorized(pub, pKeys, 0),
        "an empty list authorizes nobody");
    CHECK(!DirectGate_KeyAuth_IsClientAuthorized(pub, pKeys, 3), "empty, broken and short entries authorize nobody");
    CHECK(DirectGate_KeyAuth_IsClientAuthorized(pub, pKeys, 4), "the matching entry authorizes its key");

    /* The agent takes a hello of whole fields only, and runs its steps in order */
    directgate_keyauth_t agent;
    char sEphB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE], sNonceHex[DIRECTGATE_KEYAUTH_NONCE_SIZE * 2 + 1];
    CHECK(DirectGate_KeyAuth_Base64Encode(ephPub, sizeof(ephPub), sEphB64, sizeof(sEphB64)), "encode the exchange key");
    CHECK(DirectGate_KeyAuth_BytesToHex(nonce, sizeof(nonce), sNonceHex, sizeof(sNonceHex)), "encode the nonce");
    DirectGate_KeyAuth_Init(&agent);
    CHECK(!DirectGate_KeyAuth_AgentProcessHello(NULL, pDeviceId, sPubB64, sEphB64, sNonceHex) &&
          !DirectGate_KeyAuth_AgentProcessHello(&agent, "", sPubB64, sEphB64, sNonceHex) &&
          !DirectGate_KeyAuth_AgentProcessHello(&agent, pDeviceId, "", sEphB64, sNonceHex) &&
          !DirectGate_KeyAuth_AgentProcessHello(&agent, pDeviceId, sPubB64, "", sNonceHex) &&
          !DirectGate_KeyAuth_AgentProcessHello(&agent, pDeviceId, sPubB64, sEphB64, ""), "a hello needs every field");
    CHECK(!DirectGate_KeyAuth_AgentProcessHello(&agent, pDeviceId, sShortB64, sEphB64, sNonceHex),
        "a hello with half a client key is refused");
    CHECK(!DirectGate_KeyAuth_AgentProcessHello(&agent, pDeviceId, sPubB64, sShortB64, sNonceHex),
        "a hello with half an exchange key is refused");
    CHECK(!DirectGate_KeyAuth_AgentProcessHello(&agent, pDeviceId, sPubB64, sEphB64, "0011"),
        "a hello with a short nonce is refused");

    char sAgentPub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE], sAgentEph[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sAgentNonce[DIRECTGATE_KEYAUTH_NONCE_SIZE * 2 + 1], sChallenge[DIRECTGATE_KEYAUTH_CHALLENGE_SIZE * 2 + 1];
    char sAgentSig[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];
    CHECK(!DirectGate_KeyAuth_AgentBuildChallenge(&agent, seed, pub, sAgentPub, sizeof(sAgentPub), sAgentEph,
        sizeof(sAgentEph), sAgentNonce, sizeof(sAgentNonce), sChallenge, sizeof(sChallenge), sAgentSig, sizeof(sAgentSig)),
        "no challenge goes out before a hello");
    CHECK(!DirectGate_KeyAuth_AgentVerifyProof(&agent, sShortB64), "no proof is checked before a challenge");
    CHECK(!DirectGate_KeyAuth_DeriveShared(&agent) && !DirectGate_KeyAuth_DeriveShared(NULL),
        "no secret is derived before authentication");

    CHECK(DirectGate_KeyAuth_AgentProcessHello(&agent, pDeviceId, sPubB64, sEphB64, sNonceHex), "a whole hello is taken");
    CHECK(!DirectGate_KeyAuth_AgentBuildChallenge(&agent, NULL, pub, sAgentPub, sizeof(sAgentPub), sAgentEph,
        sizeof(sAgentEph), sAgentNonce, sizeof(sAgentNonce), sChallenge, sizeof(sChallenge), sAgentSig, sizeof(sAgentSig)),
        "a challenge needs the agent identity");
    CHECK(!DirectGate_KeyAuth_AgentBuildChallenge(&agent, seed, pub, sAgentPub, sizeof(sAgentPub), sAgentEph,
        sizeof(sAgentEph), sAgentNonce, 8, sChallenge, sizeof(sChallenge), sAgentSig, sizeof(sAgentSig)),
        "a challenge needs room for its nonce");
    DirectGate_KeyAuth_Init(&agent);
    CHECK(DirectGate_KeyAuth_AgentProcessHello(&agent, pDeviceId, sPubB64, sEphB64, sNonceHex), "take the hello again");
    CHECK(!DirectGate_KeyAuth_AgentBuildChallenge(&agent, seed, pub, sAgentPub, sizeof(sAgentPub), sAgentEph,
        sizeof(sAgentEph), sAgentNonce, sizeof(sAgentNonce), sChallenge, 8, sAgentSig, sizeof(sAgentSig)),
        "a challenge needs room for itself");
    DirectGate_KeyAuth_Init(&agent);
    CHECK(DirectGate_KeyAuth_AgentProcessHello(&agent, pDeviceId, sPubB64, sEphB64, sNonceHex), "take the hello once more");
    CHECK(DirectGate_KeyAuth_AgentBuildChallenge(&agent, seed, pub, sAgentPub, sizeof(sAgentPub), sAgentEph,
        sizeof(sAgentEph), sAgentNonce, sizeof(sAgentNonce), sChallenge, sizeof(sChallenge), sAgentSig, sizeof(sAgentSig)),
        "a challenge goes out after the hello");
    CHECK(!DirectGate_KeyAuth_AgentVerifyProof(&agent, "") && !DirectGate_KeyAuth_AgentVerifyProof(NULL, sAgentSig),
        "a proof needs a signature");
    CHECK(!DirectGate_KeyAuth_AgentVerifyProof(&agent, sShortB64), "a proof shorter than a signature is refused");
    DirectGate_KeyAuth_Cleanse(&agent);

    /* The client is pinned to the agent key the API published, and checks every field of the challenge */
    directgate_client_key_t key;
    directgate_keyauth_t client;
    char sClientPub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE], sClientEph[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sClientNonce[DIRECTGATE_KEYAUTH_NONCE_SIZE * 2 + 1], sClientSig[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];
    CHECK(!DirectGate_KeyAuth_KeyGenerate(NULL), "a client key needs a holder");
    CHECK(DirectGate_KeyAuth_KeyGenerate(&key), "generate a client key");
    CHECK(!DirectGate_KeyAuth_ClientInit(NULL, pDeviceId, &key, sAgentPub) &&
          !DirectGate_KeyAuth_ClientInit(&client, "", &key, sAgentPub) &&
          !DirectGate_KeyAuth_ClientInit(&client, pDeviceId, &key, ""), "a client needs a device and a pinned agent key");
    CHECK(!DirectGate_KeyAuth_ClientInit(&client, pDeviceId, &key, sShortB64), "a client refuses half a pinned key");

    for (int nCase = 0; nCase < 6; nCase++)
    {
        CHECK(DirectGate_KeyAuth_ClientInit(&client, pDeviceId, &key, sAgentPub), "a client pins the agent key");
        CHECK(DirectGate_KeyAuth_ClientBuildHello(&client, sClientPub, sizeof(sClientPub), sClientEph, sizeof(sClientEph),
            sClientNonce, sizeof(sClientNonce)), "a client says hello");
        CHECK(!DirectGate_KeyAuth_ClientBuildHello(&client, sClientPub, sizeof(sClientPub), sClientEph, sizeof(sClientEph),
            sClientNonce, sizeof(sClientNonce)), "a client says hello once");

        const char *pPub = nCase == 1 ? sPubB64 : (nCase == 2 ? sShortB64 : sAgentPub);
        const char *pEph = nCase == 3 ? sShortB64 : sAgentEph;
        const char *pNonce = nCase == 4 ? "0011" : sAgentNonce;
        const char *pSig = nCase == 5 ? sShortB64 : sAgentSig;
        if (nCase == 0)
        {
            CHECK(!DirectGate_KeyAuth_ClientProcessChallenge(&client, &key, pPub, pEph, pNonce, sChallenge, "",
                sClientSig, sizeof(sClientSig)), "an incomplete challenge is refused");
        }
        else
        {
            CHECK(!DirectGate_KeyAuth_ClientProcessChallenge(&client, &key, pPub, pEph, pNonce, sChallenge, pSig,
                sClientSig, sizeof(sClientSig)), "a challenge from another host, or with a broken field, is refused");
        }

        CHECK(client.eState == DIRECTGATE_KEYAUTH_STATE_FAILED, "a refused challenge fails the client");
        CHECK(!DirectGate_KeyAuth_ClientAccept(&client), "a failed client accepts nothing");
        DirectGate_KeyAuth_Cleanse(&client);
    }

    CHECK(!DirectGate_KeyAuth_ClientAccept(NULL), "acceptance needs a client");

    /* A key file of another type, without its fields, or whose seed is not its key's is refused */
    char sRoot[] = "/tmp/directgate_keyauth_smoke.XXXXXX", sPath[96], sBlocked[128], sText[512];
    CHECK(mkdtemp(sRoot) != NULL, "create a key directory");
    snprintf(sPath, sizeof(sPath), "%s/client.key", sRoot);
    char sSeedB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE], sOtherPub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    CHECK(DirectGate_KeyAuth_Base64Encode(key.clientSeed, sizeof(key.clientSeed), sSeedB64, sizeof(sSeedB64)) &&
          DirectGate_KeyAuth_Base64Encode(key.clientPub, sizeof(key.clientPub), sClientPub, sizeof(sClientPub)) &&
          DirectGate_KeyAuth_Base64Encode(pub, sizeof(pub), sOtherPub, sizeof(sOtherPub)), "encode the key fields");

    const char *pFiles[] = {
        "{\"type\":\"directgate-client-key-v1\",\"clientPub\":\"%s\",\"clientSeed\":\"%s\"}",
        "{\"clientPub\":\"%s\",\"clientSeed\":\"%s\"}",
        "{\"type\":\"directgate-client-key-v2\",\"clientPub\":\"%s\"}",
        "{\"type\":\"directgate-client-key-v2\",\"clientPub\":\"%s\",\"clientSeed\":\"AAAA\"}",
        "not json at all"
    };

    directgate_client_key_t loaded;
    CHECK(!DirectGate_KeyAuth_KeyLoad(NULL, sPath) && !DirectGate_KeyAuth_KeyLoad(&loaded, ""), "a key load needs a path");
    CHECK(!DirectGate_KeyAuth_KeyLoad(&loaded, sPath), "a missing key file does not load");
    for (size_t i = 0; i < sizeof(pFiles) / sizeof(pFiles[0]); i++)
    {
        snprintf(sText, sizeof(sText), pFiles[i], sClientPub, sSeedB64);
        CHECK(write_text(sPath, sText), "write a key file");
        CHECK(!DirectGate_KeyAuth_KeyLoad(&loaded, sPath), "a key file of another kind or without its fields is refused");
    }

    snprintf(sText, sizeof(sText), "{\"type\":\"%s\",\"clientPub\":\"%s\",\"clientSeed\":\"%s\"}",
        DIRECTGATE_CLIENT_KEY_FILE_TYPE, sOtherPub, sSeedB64);
    CHECK(write_text(sPath, sText) && !DirectGate_KeyAuth_KeyLoad(&loaded, sPath), "a seed of another key is refused");

    snprintf(sBlocked, sizeof(sBlocked), "%s/client.key", sPath);
    CHECK(!DirectGate_KeyAuth_KeySave(NULL, sPath) && !DirectGate_KeyAuth_KeySave(&key, ""), "a key save needs a key and path");
    CHECK(!DirectGate_KeyAuth_KeySave(&key, sBlocked), "a key is not saved under a file");
    CHECK(DirectGate_KeyAuth_KeySave(&key, sPath) && DirectGate_KeyAuth_KeyLoad(&loaded, sPath) &&
          !memcmp(&loaded, &key, sizeof(key)), "a saved key loads back");

    unlink(sPath);
    rmdir(sRoot);
    DirectGate_KeyAuth_KeyCleanse(&loaded);
    DirectGate_KeyAuth_KeyCleanse(&key);
    return 0;
}

int main(void)
{
    CHECK(strcmp(DirectGate_KeyAuth_StateName(DIRECTGATE_KEYAUTH_STATE_IDLE), "IDLE") == 0,
        "idle state name");
    CHECK(strcmp(DirectGate_KeyAuth_StateName(DIRECTGATE_KEYAUTH_STATE_AUTHENTICATED),
        "AUTHENTICATED") == 0, "authenticated state name");
    CHECK(strcmp(DirectGate_KeyAuth_StateName((directgate_keyauth_state_t)99), "UNKNOWN") == 0,
        "unknown state name");

    uint8_t hexBytes[4];
    size_t nHexLen = 0;
    CHECK(DirectGate_KeyAuth_HexToBytes("00aF10ff", hexBytes, sizeof(hexBytes), &nHexLen),
        "mixed-case hex decode");
    CHECK(nHexLen == sizeof(hexBytes) && hexBytes[0] == 0 && hexBytes[1] == 0xaf &&
          hexBytes[2] == 0x10 && hexBytes[3] == 0xff, "hex decoded bytes");
    char hexOut[9];
    CHECK(DirectGate_KeyAuth_BytesToHex(hexBytes, sizeof(hexBytes), hexOut, sizeof(hexOut)) &&
          strcmp(hexOut, "00af10ff") == 0, "hex encode");
    CHECK(!DirectGate_KeyAuth_HexToBytes("", hexBytes, sizeof(hexBytes), &nHexLen),
        "reject empty hex");
    CHECK(!DirectGate_KeyAuth_HexToBytes("abc", hexBytes, sizeof(hexBytes), &nHexLen),
        "reject odd hex");
    CHECK(!DirectGate_KeyAuth_HexToBytes("zz", hexBytes, sizeof(hexBytes), &nHexLen),
        "reject non-hex");
    CHECK(!DirectGate_KeyAuth_HexToBytes("0011", hexBytes, 1, &nHexLen),
        "reject oversized hex");
    CHECK(!DirectGate_KeyAuth_BytesToHex(hexBytes, sizeof(hexBytes), hexOut, 8),
        "reject small hex output");

    uint8_t trailingZero[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    uint8_t trailingZeroDecoded[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    char trailingZeroB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    size_t nTrailingZeroLen = 0;
    for (size_t i = 0; i < sizeof(trailingZero); i++) trailingZero[i] = (uint8_t)(i + 1);
    trailingZero[sizeof(trailingZero) - 1] = 0;

    CHECK(DirectGate_KeyAuth_Base64Encode(trailingZero, sizeof(trailingZero),
        trailingZeroB64, sizeof(trailingZeroB64)), "encode trailing-zero bytes");
    CHECK(DirectGate_KeyAuth_Base64Decode(trailingZeroB64, trailingZeroDecoded,
        sizeof(trailingZeroDecoded), &nTrailingZeroLen), "decode trailing-zero bytes");
    CHECK(nTrailingZeroLen == sizeof(trailingZero), "trailing-zero decode length");
    CHECK(memcmp(trailingZeroDecoded, trailingZero, sizeof(trailingZero)) == 0,
        "trailing-zero decode bytes");

    uint8_t trailingZeroSig[DIRECTGATE_KEYAUTH_ED25519_SIG_SIZE];
    uint8_t trailingZeroSigDecoded[DIRECTGATE_KEYAUTH_ED25519_SIG_SIZE];
    char trailingZeroSigB64[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];
    size_t nTrailingZeroSigLen = 0;
    for (size_t i = 0; i < sizeof(trailingZeroSig); i++) trailingZeroSig[i] = (uint8_t)(0xa0 + i);
    trailingZeroSig[sizeof(trailingZeroSig) - 1] = 0;

    CHECK(DirectGate_KeyAuth_Base64Encode(trailingZeroSig, sizeof(trailingZeroSig),
        trailingZeroSigB64, sizeof(trailingZeroSigB64)), "encode trailing-zero sig");
    CHECK(DirectGate_KeyAuth_Base64Decode(trailingZeroSigB64, trailingZeroSigDecoded,
        sizeof(trailingZeroSigDecoded), &nTrailingZeroSigLen), "decode trailing-zero sig");
    CHECK(nTrailingZeroSigLen == sizeof(trailingZeroSig), "trailing-zero sig decode length");
    CHECK(memcmp(trailingZeroSigDecoded, trailingZeroSig, sizeof(trailingZeroSig)) == 0,
        "trailing-zero sig decode bytes");
    CHECK(!DirectGate_KeyAuth_Base64Encode(trailingZero, sizeof(trailingZero),
        trailingZeroB64, 4), "reject small base64 output");
    CHECK(!DirectGate_KeyAuth_Base64Decode("", trailingZeroDecoded,
        sizeof(trailingZeroDecoded), &nTrailingZeroLen), "reject empty base64");
    CHECK(!DirectGate_KeyAuth_Base64Decode("!!!!", trailingZeroDecoded,
        sizeof(trailingZeroDecoded), &nTrailingZeroLen), "reject invalid base64");
    CHECK(!DirectGate_KeyAuth_Base64Decode(trailingZeroB64, trailingZeroDecoded,
        sizeof(trailingZeroDecoded) - 1, &nTrailingZeroLen), "reject small decoded output");

    /* --- Agent identity (Ed25519 long-term) --- */
    uint8_t agentIdentityPub[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    uint8_t agentIdentitySeed[DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE];
    CHECK(DirectGate_KeyAuth_Ed25519Generate(agentIdentityPub, agentIdentitySeed),
        "agent identity keygen");
    uint8_t derivedAgentPub[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    CHECK(DirectGate_KeyAuth_Ed25519DerivePub(agentIdentitySeed, derivedAgentPub),
        "derive agent public key");
    CHECK(memcmp(derivedAgentPub, agentIdentityPub, sizeof(derivedAgentPub)) == 0,
        "derived agent public key matches");
    CHECK(!DirectGate_KeyAuth_Ed25519Generate(NULL, agentIdentitySeed),
        "keygen rejects NULL output");

    /* --- Client identity (Ed25519 long-term) --- */
    uint8_t clientPub[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    uint8_t clientSeed[DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE];
    CHECK(DirectGate_KeyAuth_Ed25519Generate(clientPub, clientSeed),
        "client identity keygen");
    const uint8_t sMessage[] = "keyauth primitive message";
    uint8_t primitiveSig[DIRECTGATE_KEYAUTH_ED25519_SIG_SIZE];
    CHECK(DirectGate_KeyAuth_Ed25519Sign(clientSeed, sMessage, sizeof(sMessage), primitiveSig),
        "primitive sign");
    CHECK(DirectGate_KeyAuth_Ed25519Verify(clientPub, sMessage, sizeof(sMessage), primitiveSig),
        "primitive verify");
    primitiveSig[0] ^= 1;
    CHECK(!DirectGate_KeyAuth_Ed25519Verify(clientPub, sMessage, sizeof(sMessage), primitiveSig),
        "primitive signature tamper");
    primitiveSig[0] ^= 1;
    CHECK(!DirectGate_KeyAuth_Ed25519Sign(NULL, sMessage, sizeof(sMessage), primitiveSig),
        "sign rejects NULL seed");

    /* --- Client session: ephemeral X25519 + nonce --- */
    uint8_t clientEphPub[DIRECTGATE_KEYAUTH_X25519_PUB_SIZE];
    uint8_t clientEphPriv[DIRECTGATE_KEYAUTH_X25519_PRIV_SIZE];
    CHECK(DirectGate_KeyAuth_X25519Generate(clientEphPub, clientEphPriv),
        "client x25519 keygen");
    uint8_t peerEphPub[DIRECTGATE_KEYAUTH_X25519_PUB_SIZE];
    uint8_t peerEphPriv[DIRECTGATE_KEYAUTH_X25519_PRIV_SIZE];
    uint8_t clientPrimitiveShared[DIRECTGATE_KEYAUTH_X25519_SHARED_SIZE];
    uint8_t peerPrimitiveShared[DIRECTGATE_KEYAUTH_X25519_SHARED_SIZE];
    CHECK(DirectGate_KeyAuth_X25519Generate(peerEphPub, peerEphPriv), "peer x25519 keygen");
    CHECK(DirectGate_KeyAuth_X25519Derive(clientEphPriv, peerEphPub, clientPrimitiveShared) &&
          DirectGate_KeyAuth_X25519Derive(peerEphPriv, clientEphPub, peerPrimitiveShared),
        "x25519 two-way derive");
    CHECK(memcmp(clientPrimitiveShared, peerPrimitiveShared,
        sizeof(clientPrimitiveShared)) == 0, "x25519 shared secret symmetry");
    CHECK(!DirectGate_KeyAuth_X25519Derive(NULL, peerEphPub, clientPrimitiveShared),
        "x25519 rejects NULL private key");

    uint8_t clientNonce[DIRECTGATE_KEYAUTH_NONCE_SIZE];
    for (size_t i = 0; i < sizeof(clientNonce); i++) clientNonce[i] = (uint8_t)(0x10 + i);

    char clientPubB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char clientEphB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char clientNonceHex[DIRECTGATE_KEYAUTH_NONCE_SIZE * 2 + 1];
    CHECK(DirectGate_KeyAuth_Base64Encode(clientPub, sizeof(clientPub),
        clientPubB64, sizeof(clientPubB64)), "encode clientPub");
    CHECK(DirectGate_KeyAuth_Base64Encode(clientEphPub, sizeof(clientEphPub),
        clientEphB64, sizeof(clientEphB64)), "encode clientEph");
    hex_encode(clientNonce, sizeof(clientNonce), clientNonceHex, sizeof(clientNonceHex));
    const char *authorized[] = { "invalid-base64", clientPubB64, trailingZeroB64 };
    CHECK(DirectGate_KeyAuth_IsClientAuthorized(clientPub, authorized, 3),
        "authorized key lookup");
    CHECK(!DirectGate_KeyAuth_IsClientAuthorized(agentIdentityPub, authorized, 2),
        "unauthorized key lookup");
    CHECK(!DirectGate_KeyAuth_IsClientAuthorized(NULL, authorized, 3),
        "authorized lookup rejects NULL key");

    /* --- Agent state machine: hello --> challenge --- */
    directgate_keyauth_t agentAuth;
    DirectGate_KeyAuth_Init(&agentAuth);
    agentAuth.bIsAgent = XTRUE;

    const char *pDeviceId = "dev-smoke";
    CHECK(DirectGate_KeyAuth_AgentProcessHello(&agentAuth, pDeviceId,
        clientPubB64, clientEphB64, clientNonceHex), "agent process hello");

    char agentPubB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char agentEphB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char agentNonceHex[DIRECTGATE_KEYAUTH_NONCE_SIZE * 2 + 1];
    char challengeHex[DIRECTGATE_KEYAUTH_CHALLENGE_SIZE * 2 + 1];
    char agentSigB64[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];

    CHECK(DirectGate_KeyAuth_AgentBuildChallenge(&agentAuth, agentIdentitySeed, agentIdentityPub,
        agentPubB64, sizeof(agentPubB64),
        agentEphB64, sizeof(agentEphB64),
        agentNonceHex, sizeof(agentNonceHex),
        challengeHex, sizeof(challengeHex),
        agentSigB64, sizeof(agentSigB64)),
        "agent build challenge");

    /* --- Verify agent signature on the client side of the wire --- */
    uint8_t agentEph[DIRECTGATE_KEYAUTH_X25519_PUB_SIZE];
    size_t nAgentEphLen = 0;
    CHECK(DirectGate_KeyAuth_Base64Decode(agentEphB64, agentEph, sizeof(agentEph), &nAgentEphLen),
        "decode agentEph");
    CHECK(nAgentEphLen == sizeof(agentEph), "agentEph length");

    uint8_t agentNonce[DIRECTGATE_KEYAUTH_NONCE_SIZE];
    size_t nAgentNonceLen = 0;
    CHECK(DirectGate_KeyAuth_HexToBytes(agentNonceHex, agentNonce, sizeof(agentNonce), &nAgentNonceLen),
        "decode agent nonce");
    CHECK(nAgentNonceLen == sizeof(agentNonce), "agent nonce length");

    uint8_t challenge[DIRECTGATE_KEYAUTH_CHALLENGE_SIZE];
    size_t nChallengeLen = 0;
    CHECK(DirectGate_KeyAuth_HexToBytes(challengeHex, challenge, sizeof(challenge), &nChallengeLen),
        "decode challenge");
    CHECK(nChallengeLen == sizeof(challenge), "challenge length");

    uint8_t agentSig[DIRECTGATE_KEYAUTH_ED25519_SIG_SIZE];
    size_t nAgentSigLen = 0;
    CHECK(DirectGate_KeyAuth_Base64Decode(agentSigB64, agentSig, sizeof(agentSig), &nAgentSigLen),
        "decode agentSig");
    CHECK(nAgentSigLen == sizeof(agentSig), "agentSig length");

    xbyte_buffer_t agentTranscript;
    XByteBuffer_Init(&agentTranscript, XSTDNON, XFALSE);
    CHECK(!DirectGate_KeyAuth_BuildTranscript(&agentTranscript, 'x', pDeviceId,
        clientPub, agentIdentityPub, challenge, clientNonce, agentNonce,
        clientEphPub, agentEph), "reject invalid transcript tag");
    CHECK(!DirectGate_KeyAuth_BuildTranscript(NULL, 'h', pDeviceId,
        clientPub, agentIdentityPub, challenge, clientNonce, agentNonce,
        clientEphPub, agentEph), "reject NULL transcript output");
    CHECK(DirectGate_KeyAuth_BuildTranscript(&agentTranscript, 'h', pDeviceId,
        clientPub, agentIdentityPub, challenge, clientNonce, agentNonce,
        clientEphPub, agentEph), "build agent transcript");
    CHECK(DirectGate_KeyAuth_Ed25519Verify(agentIdentityPub,
        agentTranscript.pData, agentTranscript.nUsed, agentSig),
        "verify agent signature");
    XByteBuffer_Clear(&agentTranscript);

    /* --- Client side: sign its own transcript --- */
    xbyte_buffer_t clientTranscript;
    XByteBuffer_Init(&clientTranscript, XSTDNON, XFALSE);
    CHECK(DirectGate_KeyAuth_BuildTranscript(&clientTranscript, 'c', pDeviceId,
        clientPub, agentIdentityPub, challenge, clientNonce, agentNonce,
        clientEphPub, agentEph), "build client transcript");

    uint8_t clientSig[DIRECTGATE_KEYAUTH_ED25519_SIG_SIZE];
    CHECK(DirectGate_KeyAuth_Ed25519Sign(clientSeed,
        clientTranscript.pData, clientTranscript.nUsed, clientSig),
        "client sign transcript");
    XByteBuffer_Clear(&clientTranscript);

    char clientSigB64[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];
    CHECK(DirectGate_KeyAuth_Base64Encode(clientSig, sizeof(clientSig),
        clientSigB64, sizeof(clientSigB64)), "encode clientSig");

    /* --- Agent verifies proof and derives shared secret --- */
    CHECK(DirectGate_KeyAuth_AgentVerifyProof(&agentAuth, clientSigB64),
        "agent verify proof");
    CHECK(DirectGate_KeyAuth_DeriveShared(&agentAuth), "agent derive shared");
    CHECK(agentAuth.bHaveSharedSecret, "agent shared set");

    /* --- Client derives shared secret independently and compares --- */
    uint8_t clientShared[DIRECTGATE_KEYAUTH_X25519_SHARED_SIZE];
    CHECK(DirectGate_KeyAuth_X25519Derive(clientEphPriv, agentEph, clientShared),
        "client derive shared");
    CHECK(memcmp(clientShared, agentAuth.sharedSecret, sizeof(clientShared)) == 0,
        "shared secrets match");

    /* --- Tampering detection: fresh handshake with a bit-flipped client sig --- */
    directgate_keyauth_t tamperAuth;
    DirectGate_KeyAuth_Init(&tamperAuth);
    tamperAuth.bIsAgent = XTRUE;
    CHECK(DirectGate_KeyAuth_AgentProcessHello(&tamperAuth, pDeviceId,
        clientPubB64, clientEphB64, clientNonceHex), "tamper agent process hello");

    char agentPubB64_2[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char agentEphB64_2[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char agentNonceHex_2[DIRECTGATE_KEYAUTH_NONCE_SIZE * 2 + 1];
    char challengeHex_2[DIRECTGATE_KEYAUTH_CHALLENGE_SIZE * 2 + 1];
    char agentSigB64_2[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];
    CHECK(DirectGate_KeyAuth_AgentBuildChallenge(&tamperAuth, agentIdentitySeed, agentIdentityPub,
        agentPubB64_2, sizeof(agentPubB64_2),
        agentEphB64_2, sizeof(agentEphB64_2),
        agentNonceHex_2, sizeof(agentNonceHex_2),
        challengeHex_2, sizeof(challengeHex_2),
        agentSigB64_2, sizeof(agentSigB64_2)),
        "tamper build challenge");

    uint8_t agentEph_2[DIRECTGATE_KEYAUTH_X25519_PUB_SIZE];
    size_t nLen2 = 0;
    CHECK(DirectGate_KeyAuth_Base64Decode(agentEphB64_2, agentEph_2, sizeof(agentEph_2), &nLen2),
        "decode agentEph (tamper)");
    uint8_t agentNonce_2[DIRECTGATE_KEYAUTH_NONCE_SIZE];
    CHECK(DirectGate_KeyAuth_HexToBytes(agentNonceHex_2, agentNonce_2, sizeof(agentNonce_2), &nLen2),
        "decode agent nonce (tamper)");
    uint8_t challenge_2[DIRECTGATE_KEYAUTH_CHALLENGE_SIZE];
    CHECK(DirectGate_KeyAuth_HexToBytes(challengeHex_2, challenge_2, sizeof(challenge_2), &nLen2),
        "decode challenge (tamper)");

    xbyte_buffer_t tamperTranscript;
    XByteBuffer_Init(&tamperTranscript, XSTDNON, XFALSE);
    CHECK(DirectGate_KeyAuth_BuildTranscript(&tamperTranscript, 'c', pDeviceId,
        clientPub, agentIdentityPub, challenge_2, clientNonce, agentNonce_2,
        clientEphPub, agentEph_2), "build tamper client transcript");
    uint8_t tamperSig[DIRECTGATE_KEYAUTH_ED25519_SIG_SIZE];
    CHECK(DirectGate_KeyAuth_Ed25519Sign(clientSeed,
        tamperTranscript.pData, tamperTranscript.nUsed, tamperSig),
        "sign tamper client transcript");
    XByteBuffer_Clear(&tamperTranscript);

    tamperSig[0] ^= 0x01;
    char tamperSigB64[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];
    CHECK(DirectGate_KeyAuth_Base64Encode(tamperSig, sizeof(tamperSig),
        tamperSigB64, sizeof(tamperSigB64)), "encode tamper sig");

    CHECK(!DirectGate_KeyAuth_AgentVerifyProof(&tamperAuth, tamperSigB64),
        "tampered clientSig must fail");

    DirectGate_KeyAuth_Cleanse(&agentAuth);
    DirectGate_KeyAuth_Cleanse(&tamperAuth);

    uint8_t tiny = 0;
    char tinyHex[3];
    size_t decoded = 0;
    CHECK(!DirectGate_KeyAuth_HexToBytes("00", &tiny, SIZE_MAX, &decoded), "overflowing hex bound rejected");
    CHECK(!DirectGate_KeyAuth_BytesToHex(&tiny, SIZE_MAX / 2 + 1, tinyHex, sizeof(tinyHex)),
        "overflowing hex output length rejected before reading");
    CHECK(keyauth_refusals() == 0, "every refusal and guard holds");
    printf("keyauth_smoke: OK\n");
    return 0;
}
