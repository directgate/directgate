#include <stdio.h>
#include <string.h>

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

    printf("keyauth_smoke: OK\n");
    return 0;
}
