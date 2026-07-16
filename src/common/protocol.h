/*!
 * @file directgate-agent/src/common/protocol.h
 * @brief JSON protocol helpers for directgate transport.
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

#ifndef __DIRECTGATE_PROTOCOL_H__
#define __DIRECTGATE_PROTOCOL_H__

#include "includes.h"
#include "e2e.h"
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DIRECTGATE_PROTO_PREAMBLE_SIZE 4
#define DIRECTGATE_PROTOCOL_VERSION    1

typedef enum {
    DIRECTGATE_PKG_NONE = (int)0,
    DIRECTGATE_PKG_CMD,
    DIRECTGATE_PKG_AUTH,
    DIRECTGATE_PKG_ROLE,
    DIRECTGATE_PKG_ERROR,
    DIRECTGATE_PKG_STATUS,
    DIRECTGATE_PKG_DATA,
    DIRECTGATE_PKG_FILE,
    DIRECTGATE_PKG_ENCRYPTED,
    DIRECTGATE_PKG_KEEPALIVE,
    DIRECTGATE_PKG_MANAGER,
    DIRECTGATE_PKG_RESIZE,
    DIRECTGATE_PKG_VERIFY,
    DIRECTGATE_PKG_WEBRTC,
    DIRECTGATE_PKG_ADMIN
} directgate_pkg_type_t;

typedef struct directgate_pkg_header_ {
    directgate_pkg_type_t eType;
    const char *pType;
    uint32_t nProtoVersion;
    uint32_t nSessionId;
    uint32_t nPacketId;
} directgate_pkg_header_t;

typedef struct directgate_pkg_auth_ {
    const char *pAction;
    const char *pMethod;       /* "srp" (default) or "key" */
    const char *pDeviceId;
    /* SRP-specific */
    const char *pA;
    const char *pB;
    const char *pM1;
    const char *pM2;
    const char *pSalt;
    uint32_t nSuite;
    /* Shared */
    const char *pNonce;
    const char *pStatus;
    const char *pReason;
    /* Key-auth specific (base64 for binary, hex for 32-byte scalars). */
    const char *pClientPub;    /* Ed25519 client identity pubkey, base64 */
    const char *pAgentPub;     /* Ed25519 agent identity pubkey, base64 */
    const char *pClientEph;    /* X25519 client ephemeral pubkey, base64 */
    const char *pAgentEph;     /* X25519 agent ephemeral pubkey, base64 */
    const char *pChallenge;    /* 32-byte challenge, hex */
    const char *pAgentSig;     /* Ed25519 signature from agent, base64 */
    const char *pClientSig;    /* Ed25519 signature from client, base64 */
} directgate_pkg_auth_t;

typedef struct directgate_pkg_verify_ {
    const char *pAction;
    const char *pAccessToken;
    const char *pRequestId;
    const char *pStatus;
    const char *pReason;
    uint64_t nExp;
} directgate_pkg_verify_t;

typedef struct directgate_pkg_data_ {
    const char *pPayloadType;
    const uint8_t *pPayload;
    size_t nPayloadLength;
    xbool_t bEncrypted;
} directgate_pkg_data_t;

typedef struct directgate_pkg_transfer_ {
    const char *pTransferId;
    const char *pFileName;
    uint64_t nFileSize;
    uint32_t nChunks;
    uint32_t nChunkSize;
    uint32_t nChunkIndex;
    const char *pSha256;
} directgate_pkg_transfer_t;

typedef struct directgate_pkg_file_ {
    directgate_pkg_transfer_t transfer;
    directgate_pkg_data_t data;
    const char *pAction;
} directgate_pkg_file_t;

typedef struct directgate_pkg_size_ {
    uint32_t nRows;
    uint32_t nCols;
    uint32_t nWidth;
    uint32_t nHeight;
} directgate_pkg_size_t;

typedef struct directgate_pkg_role_ {
    const char *pRole;
    const char *pDeviceId;
    const char *pAccessToken;
} directgate_pkg_role_t;

typedef struct directgate_pkg_manager_ {
    const char *pAction;
    const char *pPath;
    const char *pFileName;
    const char *pText;
    const char *pTargetPath;
    const char *pPermissions;
    const char *pTypes;
    const char *pMinSize;
    const char *pMaxSize;
    const char *pFileSize;
    const char *pLinkCount;
    xbool_t bForce;
    xbool_t bCancel;
    xbool_t bRecursive;
    xbool_t bInsensitive;
    xbool_t bSearchLines;
    xbool_t bMatchOnly;
} directgate_pkg_manager_t;

typedef struct directgate_pkg_status_ {
    const char *pStatus;
} directgate_pkg_status_t;

typedef struct directgate_pkg_error_ {
    const char *pReason;
} directgate_pkg_error_t;

typedef struct directgate_pkg_keepalive_ {
    const char *pAction;
} directgate_pkg_keepalive_t;

typedef struct directgate_pkg_webrtc_ {
    const char *pAction;
} directgate_pkg_webrtc_t;

typedef struct directgate_pkg_cmd_ {
    const char *pAction;
    const char *pMode;
} directgate_pkg_cmd_t;

typedef struct directgate_pkg_admin_ {
    const char *pAction;
    const char *pClientPub;
    const char *pStatus;
    const char *pReason;
} directgate_pkg_admin_t;

typedef struct directgate_pkg_ {
    directgate_pkg_header_t header;
    xjson_t jsonHeader;
    void *pPackage;
} directgate_pkg_t;

void DirectGate_Package_Clear(directgate_pkg_t *pPkg);
xbool_t DirectGate_Package_Parse(directgate_pkg_t *pPkg, const uint8_t *pData, size_t nSize);

xbool_t DirectGate_Proto_Build(xbyte_buffer_t *pOut, xjson_obj_t *pHeader,
                               const uint8_t *pPayload, size_t nPayload,
                               xbool_t bEncrypted);

xjson_obj_t* DirectGate_Proto_NewHeader(const char *pType, uint32_t nSessionId);
xjson_obj_t* DirectGate_Proto_BuildData(uint32_t nSessionId);
xjson_obj_t* DirectGate_Proto_BuildRole(const char *pRole, const char *pDeviceId);
xjson_obj_t* DirectGate_Proto_BuildError(const char *pReason, uint32_t nSessionId);
xjson_obj_t* DirectGate_Proto_BuildStatus(const char *pStatus, uint32_t nSessionId);
xjson_obj_t* DirectGate_Proto_BuildKeepalive(const char *pAction, uint32_t nSessionId);

xjson_obj_t* DirectGate_Proto_BuildVerify(const char *pAction, const char *pAccessToken,
                                          const char *pRequestId, uint64_t nExp,
                                          const char *pStatus, const char *pReason);

xjson_obj_t* DirectGate_Proto_BuildAuthHello(const char *pDeviceId, const char *pA,
                                             const char *pNonce, uint32_t nSessionId);

xjson_obj_t* DirectGate_Proto_BuildAuthProof(const char *pM1, uint32_t nSessionId);

xjson_obj_t* DirectGate_Proto_BuildAuthChallenge(const char *pSalt, const char *pB,
                                                 const char *pNonce, uint32_t nSuite,
                                                 uint32_t nSessionId);

xjson_obj_t* DirectGate_Proto_BuildAuthResult(const char *pStatus, const char *pM2,
                                              const char *pReason, uint32_t nSessionId);

/* ---- Public-key auth variants (method="key") ----
 *
 * The agent stays cryptographically excluded from the relay path: every
 * key-auth field is either the peer's public-half bytes or a signature, so
 * a compromised relay cannot learn anything that lets it impersonate either
 * endpoint or decrypt the resulting session. */

xjson_obj_t* DirectGate_Proto_BuildAuthKeyHello(const char *pDeviceId,
                                                const char *pClientPubKeyB64,
                                                const char *pClientEphB64,
                                                const char *pNonceHex,
                                                uint32_t nSessionId);

xjson_obj_t* DirectGate_Proto_BuildAuthKeyChallenge(const char *pAgentPubKeyB64,
                                                    const char *pAgentEphB64,
                                                    const char *pNonceHex,
                                                    const char *pChallengeHex,
                                                    const char *pAgentSigB64,
                                                    uint32_t nSessionId);

xjson_obj_t* DirectGate_Proto_BuildAuthKeyProof(const char *pClientSigB64,
                                                uint32_t nSessionId);

xjson_obj_t* DirectGate_Proto_BuildCmd(const char *pAction, const char *pStatus,
                                       const char *pReason, const char *pMode,
                                       uint32_t nSessionId);

xjson_obj_t* DirectGate_Proto_BuildResize(uint32_t nRows, uint32_t nCols, uint32_t nXPixel,
                                          uint32_t nYPixel, uint32_t nSessionId);

xjson_obj_t* DirectGate_Proto_BuildManager(const char *pAction, const char *pStatus,
                                           const char *pPath, const char *pReason,
                                           uint32_t nSessionId);

xjson_obj_t* DirectGate_Proto_BuildAdmin(const char *pAction, const char *pClientPub,
                                         const char *pStatus, const char *pReason,
                                         uint32_t nSessionId);

xjson_obj_t* DirectGate_Proto_BuildFileStart(const char *pTransferId, const char *pName,
                                             uint64_t nSize, uint32_t nChunks,
                                             uint32_t nChunkSize);

xjson_obj_t* DirectGate_Proto_BuildFileChunk(const char *pTransferId, uint32_t nIndex);
xjson_obj_t* DirectGate_Proto_BuildFileEnd(const char *pTransferId, const char *pSha256);
xjson_obj_t* DirectGate_Proto_BuildFileAck(const char *pTransferId, uint32_t nIndex);
xjson_obj_t* DirectGate_Proto_BuildFileCancel(const char *pTransferId, const char *pReason);

xbool_t DirectGate_Proto_EncryptPackage(xbyte_buffer_t *pPkg, directgate_e2e_t *pE2E, uint32_t nSessionId);
xbool_t DirectGate_Proto_DecryptPackage(xbyte_buffer_t *pOut, const directgate_pkg_t *pPkg, directgate_e2e_t *pE2E);
xbool_t DirectGate_Proto_AddCC(xjson_obj_t *pHeader, directgate_e2e_t *pE2E,
                              uint32_t nSessionEpoch);
xbool_t DirectGate_Proto_CheckCC(xbyte_buffer_t *pOut, directgate_e2e_t *pE2E);
xbool_t DirectGate_Proto_BindInnerSessionId(uint32_t nOuterSessionId, directgate_pkg_t *pInnerPkg);

#ifdef __cplusplus
}
#endif

#endif
