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

typedef struct directgate_e2e_ {
    /* Direction-bound keys: a session encrypts with its TX pair and decrypts
       with its RX pair. The two pairs are distinct, so a packet reflected
       back to its sender fails the SIV tag (no cross-direction replay). */
    uint8_t txCmacKey[XE2E_KEY_SIZE];
    uint8_t txCtrKey[XE2E_KEY_SIZE];
    uint8_t rxCmacKey[XE2E_KEY_SIZE];
    uint8_t rxCtrKey[XE2E_KEY_SIZE];
    uint32_t nTxPacketId;
    uint32_t nRxPacketId;
    uint32_t nTxSessionPacketId;
    uint32_t nRxSessionPacketId;
    uint32_t nTxSessionEpoch;
    uint32_t nRxSessionEpoch;
    uint32_t nTxSignalPacketId;
    uint32_t nRxSignalPacketId;
    xbool_t bInitialized;
} directgate_e2e_t;

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
