/*!
 * @file directgate-agent/src/common/keyauth.h
 * @brief Public-key authentication for directgate (Ed25519 identity + X25519 ephemeral ECDH).
 *
 *  Copyright (c) 2025-2026 DirectGate. All rights reserved.
 *  Author: Sandro Kalatozishvili (sandro@directgate.io)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef __DIRECTGATE_KEYAUTH_H__
#define __DIRECTGATE_KEYAUTH_H__

#include "includes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DIRECTGATE_KEYAUTH_DEVICE_ID_SIZE       256
#define DIRECTGATE_KEYAUTH_CHALLENGE_SIZE       32
#define DIRECTGATE_KEYAUTH_NONCE_SIZE           32

#define DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE     32
#define DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE    32
#define DIRECTGATE_KEYAUTH_ED25519_SIG_SIZE     64

#define DIRECTGATE_KEYAUTH_X25519_PUB_SIZE      32
#define DIRECTGATE_KEYAUTH_X25519_PRIV_SIZE     32
#define DIRECTGATE_KEYAUTH_X25519_SHARED_SIZE   32

/* Base64 (no padding stripped): 32 bytes -> 44 chars, 64 bytes -> 88 chars. */
#define DIRECTGATE_KEYAUTH_PUB_B64_SIZE         48
#define DIRECTGATE_KEYAUTH_SIG_B64_SIZE         96

typedef enum {
    DIRECTGATE_KEYAUTH_STATE_IDLE = 0,
    DIRECTGATE_KEYAUTH_STATE_HELLO_RECEIVED,
    DIRECTGATE_KEYAUTH_STATE_CHALLENGE_SENT,
    DIRECTGATE_KEYAUTH_STATE_AUTHENTICATED,
    DIRECTGATE_KEYAUTH_STATE_FAILED
} directgate_keyauth_state_t;

/*!
 * Per-session key-auth state. Mirrors directgate_srp_t in shape so that the
 * session can carry either while handshakes progress. All long-term private
 * keys live outside this struct (agent identity private key is passed in on
 * challenge generation and is not retained here).
 */
typedef struct directgate_keyauth_ {
    directgate_keyauth_state_t eState;

    /* Long-term identities (public halves only). */
    uint8_t clientPubKey[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    uint8_t agentPubKey[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];

    /* Per-session ephemeral X25519 keypair on this side + peer public half. */
    uint8_t localEphPriv[DIRECTGATE_KEYAUTH_X25519_PRIV_SIZE];
    uint8_t localEphPub[DIRECTGATE_KEYAUTH_X25519_PUB_SIZE];
    uint8_t peerEphPub[DIRECTGATE_KEYAUTH_X25519_PUB_SIZE];

    /* Per-session nonces + challenge. */
    uint8_t localNonce[DIRECTGATE_KEYAUTH_NONCE_SIZE];
    uint8_t peerNonce[DIRECTGATE_KEYAUTH_NONCE_SIZE];
    uint8_t challenge[DIRECTGATE_KEYAUTH_CHALLENGE_SIZE];

    /* Shared secret from X25519(localEphPriv, peerEphPub). */
    uint8_t sharedSecret[DIRECTGATE_KEYAUTH_X25519_SHARED_SIZE];

    char sDeviceId[DIRECTGATE_KEYAUTH_DEVICE_ID_SIZE];
    xbool_t bHaveSharedSecret;
    xbool_t bIsAgent;
} directgate_keyauth_t;

/* ---- Client key file (directgate-client-key-v2) ----
 *
 * An identity, not a device binding: one (clientPub, clientSeed) pair that can
 * be authorized on many hosts. The authoritative agentPub for a device comes
 * from the backend device list over TLS, never from this file. Mirrored by
 * front/src/lib/keyauth/parse.ts - the same file must load in both.
 */

#define DIRECTGATE_CLIENT_KEY_FILE_TYPE "directgate-client-key-v2"

typedef struct directgate_client_key_ {
    uint8_t clientPub[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    uint8_t clientSeed[DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE];
} directgate_client_key_t;

void DirectGate_KeyAuth_Init(directgate_keyauth_t *pAuth);
void DirectGate_KeyAuth_Cleanse(directgate_keyauth_t *pAuth);
const char *DirectGate_KeyAuth_StateName(directgate_keyauth_state_t eState);

/*! Generate an Ed25519 keypair. pPubOut must be 32 bytes, pSeedOut 32 bytes. */
xbool_t DirectGate_KeyAuth_Ed25519Generate(uint8_t *pPubOut, uint8_t *pSeedOut);

/*! Derive Ed25519 public key from 32-byte seed. */
xbool_t DirectGate_KeyAuth_Ed25519DerivePub(const uint8_t *pSeed, uint8_t *pPubOut);

/*! Ed25519 pure signature (RFC 8032). pSig must be 64 bytes. */
xbool_t DirectGate_KeyAuth_Ed25519Sign(const uint8_t *pSeed,
                                       const uint8_t *pMsg, size_t nMsgLen,
                                       uint8_t *pSigOut);

xbool_t DirectGate_KeyAuth_Ed25519Verify(const uint8_t *pPub,
                                         const uint8_t *pMsg, size_t nMsgLen,
                                         const uint8_t *pSig);

/*! Generate an X25519 ephemeral keypair. Both buffers are 32 bytes. */
xbool_t DirectGate_KeyAuth_X25519Generate(uint8_t *pPubOut, uint8_t *pPrivOut);

/*! X25519 scalar multiplication. pShared must be 32 bytes. */
xbool_t DirectGate_KeyAuth_X25519Derive(const uint8_t *pLocalPriv,
                                        const uint8_t *pRemotePub,
                                        uint8_t *pSharedOut);

/* ---- Transcript ----
 *
 * Canonical bytes signed by each side. Fixed binary framing with a u16 BE
 * length prefix for deviceId. Tag is 'h' (agent) or 'c' (client) for strict
 * domain separation between the two signatures.
 *
 * Layout:
 *     "directgate-key-auth-v1" (22 bytes, no NUL)
 *   || tag (1 byte, 'h' or 'c')
 *   || u16_be(deviceIdLen) (2 bytes)
 *   || deviceId (deviceIdLen bytes)
 *   || clientPubKey (32) || agentPubKey (32)
 *   || challenge (32)
 *   || clientNonce (32) || agentNonce (32)
 *   || clientEphPub (32) || agentEphPub (32)
 */
xbool_t DirectGate_KeyAuth_BuildTranscript(xbyte_buffer_t *pOut, char cTag,
                                           const char *pDeviceId,
                                           const uint8_t *pClientPubKey,
                                           const uint8_t *pAgentPubKey,
                                           const uint8_t *pChallenge,
                                           const uint8_t *pClientNonce,
                                           const uint8_t *pagentNonce,
                                           const uint8_t *pClientEphPub,
                                           const uint8_t *pAgentEphPub);

xbool_t DirectGate_KeyAuth_Base64Encode(const uint8_t *pData, size_t nLen,
                                        char *pOut, size_t nOutSize);

xbool_t DirectGate_KeyAuth_Base64Decode(const char *pB64,
                                        uint8_t *pOut, size_t nOutSize,
                                        size_t *pOutLen);

/*!
 * Returns XTRUE if pClientPubKeyB64 matches any entry in pAuthorizedKeys
 * (constant-time per-entry compare, case-sensitive exact match on the decoded
 * bytes).
 */
xbool_t DirectGate_KeyAuth_IsClientAuthorized(const uint8_t *pClientPubKey,
                                              const char **pAuthorizedKeys,
                                              size_t nCount);

/* ---- Agent-side session state machine ----
 *
 * Usage:
 *   1. DirectGate_KeyAuth_Init(&ka);
 *   2. On auth/hello: DirectGate_KeyAuth_AgentProcessHello(...)
 *   3. Then DirectGate_KeyAuth_AgentBuildChallenge(...) -> send {method, agentPub, agentEph, agentNonce, challenge, agentSig}
 *   4. On auth/proof: DirectGate_KeyAuth_AgentVerifyProof(...) -> success => DirectGate_KeyAuth_DeriveShared(...)
 */

xbool_t DirectGate_KeyAuth_AgentProcessHello(directgate_keyauth_t *pAuth,
                                             const char *pDeviceId,
                                             const char *pClientPubKeyB64,
                                             const char *pClientEphPubB64,
                                             const char *pClientNonceHex);

xbool_t DirectGate_KeyAuth_AgentBuildChallenge(directgate_keyauth_t *pAuth,
                                               const uint8_t *pagentIdentitySeed,
                                               const uint8_t *pagentIdentityPub,
                                               char *pAgentPubKeyB64Out, size_t nagentPubKeyB64Size,
                                               char *pAgentEphPubB64Out, size_t nagentEphPubB64Size,
                                               char *pagentNonceHexOut, size_t nagentNonceHexSize,
                                               char *pChallengeHexOut, size_t nChallengeHexSize,
                                               char *pAgentSigB64Out, size_t nagentSigB64Size);

xbool_t DirectGate_KeyAuth_AgentVerifyProof(directgate_keyauth_t *pAuth,
                                        const char *pClientSigB64);

/*!
 * Compute shared secret once both ephemeral public halves are in place.
 * Must be called after successful agent-side proof verification, before
 * deriving E2E keys. Writes to pAuth->sharedSecret and sets bHaveSharedSecret.
 */
xbool_t DirectGate_KeyAuth_DeriveShared(directgate_keyauth_t *pAuth);

/*! Hex helpers (shared with srp.c's style - thin wrappers). */
xbool_t DirectGate_KeyAuth_HexToBytes(const char *pHex, uint8_t *pOut,
                                      size_t nOutSize, size_t *pOutLen);

xbool_t DirectGate_KeyAuth_BytesToHex(const uint8_t *pData, size_t nLen,
                                      char *pHex, size_t nHexSize);

void DirectGate_KeyAuth_KeyCleanse(directgate_client_key_t *pKey);
xbool_t DirectGate_KeyAuth_KeyGenerate(directgate_client_key_t *pKey);

/* Reads and validates the file, including the fixed key lengths */
xbool_t DirectGate_KeyAuth_KeyLoad(directgate_client_key_t *pKey, const char *pPath);

/* Writes 0600 through a 0700 parent, like every other secret we persist */
xbool_t DirectGate_KeyAuth_KeySave(const directgate_client_key_t *pKey, const char *pPath);

/* ---- Client-side session state machine ----
 *
 * Counterpart of the agent side above, and of the browser's
 * front/src/lib/keyauth/session.ts:
 *   1. DirectGate_KeyAuth_ClientInit(...) with the agentPub the backend
 *      published for this device - that value is what the host is pinned to.
 *   2. DirectGate_KeyAuth_ClientBuildHello(...) -> send {method:"key",
 *      deviceId, clientPubKey, clientEph, nonce}
 *   3. On auth/challenge: DirectGate_KeyAuth_ClientProcessChallenge(...)
 *      -> send {method:"key", clientSig}
 *   4. On auth/result ok: DirectGate_KeyAuth_DeriveShared(...)
 */

xbool_t DirectGate_KeyAuth_ClientInit(directgate_keyauth_t *pAuth,
                                      const char *pDeviceId,
                                      const directgate_client_key_t *pKey,
                                      const char *pExpectedAgentPubB64);

xbool_t DirectGate_KeyAuth_ClientBuildHello(directgate_keyauth_t *pAuth,
                                            char *pClientPubB64Out, size_t nClientPubB64Size,
                                            char *pClientEphB64Out, size_t nClientEphB64Size,
                                            char *pClientNonceHexOut, size_t nClientNonceHexSize);

/*!
 * Verifies that the host presented the pinned identity and signed the
 * transcript with it, then signs the client half. The long-term seed is
 * passed in rather than retained, matching the agent-side convention.
 */
xbool_t DirectGate_KeyAuth_ClientProcessChallenge(directgate_keyauth_t *pAuth,
                                                  const directgate_client_key_t *pKey,
                                                  const char *pAgentPubKeyB64,
                                                  const char *pAgentEphPubB64,
                                                  const char *pAgentNonceHex,
                                                  const char *pChallengeHex,
                                                  const char *pAgentSigB64,
                                                  char *pClientSigB64Out,
                                                  size_t nClientSigB64Size);

xbool_t DirectGate_KeyAuth_ClientAccept(directgate_keyauth_t *pAuth);

#ifdef __cplusplus
}
#endif

#endif /* __DIRECTGATE_KEYAUTH_H__ */
