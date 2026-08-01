/*!
 * @file directgate-agent/src/common/e2e.h
 * @brief End-to-end encryption for terminal data between agent and client.
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

#ifndef __DIRECTGATE_E2E_H__
#define __DIRECTGATE_E2E_H__

#include "includes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define XE2E_MAX_SECRET_LENGTH      128
#define XE2E_MAX_HOSTID_LENGTH      128

#define XE2E_AES_SIZE               256
#define XE2E_KEY_SIZE               32
#define XE2E_IV_SIZE                16
#define XE2E_CHALLENGE_SIZE         32

/* Sliding replay window for one counter scope.
 *
 * A strictly increasing "must be greater than the last one" check only holds
 * when every packet of a scope travels the same wire. It does not: a session
 * migrates between the relay WebSocket, the reliable data channel and (after
 * a P2P upgrade) a second peer connection, and the unordered input channel
 * reorders by design. A packet that was merely overtaken is not a replay, so
 * rejecting it drops live user input and logs a bogus counter violation.
 *
 * The window keeps the highest accepted counter plus a bitmap of the previous
 * XE2E_CC_WINDOW_SIZE counters, exactly like the IPsec/DTLS anti-replay
 * window: anything newer advances it, anything inside it is accepted once,
 * anything older or already seen is still refused. */
#define XE2E_CC_WINDOW_SIZE 64

typedef struct directgate_ccwin_ {
    uint32_t nHighest; /* Highest counter accepted so far (0 = nothing yet) */
    uint64_t nBitmap;  /* Bit i marks counter (nHighest - i) as already seen */
} directgate_ccwin_t;

typedef struct directgate_e2e_ {
    /* Direction-bound keys: a session encrypts with its TX pair and decrypts
       with its RX pair. The two pairs are distinct, so a packet reflected
       back to its sender fails the SIV tag (no cross-direction replay). */
    uint8_t txCmacKey[XE2E_KEY_SIZE];
    uint8_t txCtrKey[XE2E_KEY_SIZE];
    uint8_t rxCmacKey[XE2E_KEY_SIZE];
    uint8_t rxCtrKey[XE2E_KEY_SIZE];
    uint32_t nTxPacketId;
    uint32_t nTxSessionPacketId;
    uint32_t nTxInputPacketId;
    uint32_t nTxSessionEpoch;
    uint32_t nTxSignalPacketId;
    uint32_t nRxSessionEpoch;
    directgate_ccwin_t rxWindow;        /* Legacy unscoped counter */
    directgate_ccwin_t rxSessionWindow;
    directgate_ccwin_t rxInputWindow;
    directgate_ccwin_t rxSignalWindow;
    xbool_t bInitialized;
} directgate_e2e_t;

/*!
 * @brief Validate @p nCC against the replay window and record it.
 * @return XTRUE when the counter is fresh (window advanced or gap filled),
 *         XFALSE when it is a duplicate or older than the window.
 */
xbool_t DirectGate_E2E_AcceptCC(directgate_ccwin_t *pWindow, uint32_t nCC);
void DirectGate_E2E_ResetCCWindow(directgate_ccwin_t *pWindow);

void DirectGate_E2E_Init(directgate_e2e_t *pE2E);
void DirectGate_E2E_Clear(directgate_e2e_t *pE2E);
xbool_t DirectGate_E2E_IsInitialized(const directgate_e2e_t *pE2E);

/*!
 * @brief Derive E2E keys from the SRP session key, the agent and client nonces,
 *        and the device ID. Uses a distinct HKDF info ("directgate:e2e:{deviceId}").
 *        @p bIsAgent selects which directional key pair becomes TX vs RX, so the
 *        two endpoints encrypt under different keys (reflection-resistant).
 */
xbool_t DirectGate_E2E_DeriveFromSRP(directgate_e2e_t *pE2E, const uint8_t *pSessionKey, size_t nSessionKeyLen,
                                    const uint8_t *pagentNonce, const uint8_t *pClientNonce, size_t nNonceSize,
                                    const char *pDeviceId, xbool_t bIsAgent);

/*!
 * @brief Derive E2E keys from an X25519 shared secret produced by the
 *        public-key authentication handshake. Uses a distinct HKDF info
 *        ("directgate:e2e:key:{deviceId}") for domain separation from SRP.
 *        @p bIsAgent selects which directional key pair becomes TX vs RX.
 */
xbool_t DirectGate_E2E_DeriveFromKey(directgate_e2e_t *pE2E, const uint8_t *pSharedSecret, size_t nSharedLen,
                                    const uint8_t *pagentNonce, const uint8_t *pClientNonce, size_t nNonceSize,
                                    const char *pDeviceId, xbool_t bIsAgent);

uint8_t* DirectGate_E2E_Encrypt(const directgate_e2e_t *pE2E, const uint8_t *pData, size_t nLength, size_t *pOutLen);
uint8_t* DirectGate_E2E_Decrypt(const directgate_e2e_t *pE2E, const uint8_t *pData, size_t nLength, size_t *pOutLen);

#ifdef __cplusplus
}
#endif

#endif
