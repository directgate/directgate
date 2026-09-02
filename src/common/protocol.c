/*!
 * @file directgate-agent/src/common/protocol.c
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

#include "includes.h"
#include "protocol.h"
#include "version.h"

static uint32_t DirectGate_Proto_ReadU32LE(const uint8_t *pData)
{
    return (uint32_t)pData[0] |
           ((uint32_t)pData[1] << 8) |
           ((uint32_t)pData[2] << 16) |
           ((uint32_t)pData[3] << 24);
}

static void DirectGate_Proto_WriteU32LE(uint8_t *pData, uint32_t nValue)
{
    pData[0] = (uint8_t)(nValue & 0xff);
    pData[1] = (uint8_t)((nValue >> 8) & 0xff);
    pData[2] = (uint8_t)((nValue >> 16) & 0xff);
    pData[3] = (uint8_t)((nValue >> 24) & 0xff);
}

void DirectGate_Package_Clear(directgate_pkg_t *pPkg)
{
    XCHECK_VOID_NL((pPkg != NULL));
    free(pPkg->pPackage);
    XJSON_Destroy(&pPkg->jsonHeader);
    memset(pPkg, 0, sizeof(*pPkg));
}

xjson_obj_t* DirectGate_Proto_NewHeader(const char *pType, uint32_t nSessionId)
{
    xjson_obj_t *pHeader = XJSON_NewObject(NULL, NULL, XTRUE);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    XJSON_AddStrIfUsed(pHeader, "type", pType);
    XJSON_AddU32(pHeader, "version", DIRECTGATE_PROTOCOL_VERSION);
    XJSON_AddU32(pHeader, "sessionId", nSessionId);

    return pHeader;
}

xbool_t DirectGate_Proto_Build(xbyte_buffer_t *pOut, xjson_obj_t *pHeader,
                               const uint8_t *pPayload, size_t nPayload,
                               xbool_t bEncrypted)
{
    XCHECK((pOut != NULL), XFALSE);
    XCHECK((pHeader != NULL), XFALSE);

    if (nPayload) XJSON_AddU32(pHeader, "payloadSize", (uint32_t)nPayload);
    if (bEncrypted) XJSON_AddBool(pHeader, "encrypted", XTRUE);

    xjson_writer_t writer;
    XJSON_InitWriter(&writer, NULL, NULL, 128);
    XByteBuffer_Reset(pOut);

    if (!XJSON_WriteObject(pHeader, &writer))
    {
        const char *pType = XJSON_GetString(XJSON_GetObject(pHeader, "type"));
        uint32_t nSessionId = XJSON_GetU32(XJSON_GetObject(pHeader, "sessionId"));

        xloge("Failed to serialize protocol header: type(%s), sid(%u)",
            xstrused(pType) ? pType : "N/A", nSessionId);

        XJSON_DestroyWriter(&writer);
        return XFALSE;
    }

    uint32_t nHdrLen = (uint32_t)writer.nLength;
    uint8_t sPreamble[DIRECTGATE_PROTO_PREAMBLE_SIZE];
    DirectGate_Proto_WriteU32LE(sPreamble, nHdrLen);

    if (!XByteBuffer_Add(pOut, sPreamble, sizeof(sPreamble)) ||
        !XByteBuffer_Add(pOut, (uint8_t*)writer.pData, writer.nLength) ||
        (pPayload != NULL && nPayload && !XByteBuffer_Add(pOut, pPayload, nPayload)))
    {
        const char *pType = XJSON_GetString(XJSON_GetObject(pHeader, "type"));
        uint32_t nSessionId = XJSON_GetU32(XJSON_GetObject(pHeader, "sessionId"));

        xloge("Failed to assemble protocol packet: type(%s), sid(%u), hdr(%zu), payload(%zu)",
            xstrused(pType) ? pType : "N/A", nSessionId, writer.nLength, nPayload);

        XJSON_DestroyWriter(&writer);
        return XFALSE;
    }

    XJSON_DestroyWriter(&writer);
    return XTRUE;
}

static directgate_pkg_type_t DirectGate_Proto_TypeFromStr(const char *pType)
{
    if (!xstrused(pType)) return DIRECTGATE_PKG_NONE;
    if (xstrcmp(pType, "auth")) return DIRECTGATE_PKG_AUTH;
    if (xstrcmp(pType, "cmd")) return DIRECTGATE_PKG_CMD;
    if (xstrcmp(pType, "data")) return DIRECTGATE_PKG_DATA;
    if (xstrcmp(pType, "encrypted")) return DIRECTGATE_PKG_ENCRYPTED;
    if (xstrcmp(pType, "error")) return DIRECTGATE_PKG_ERROR;
    if (xstrcmp(pType, "file")) return DIRECTGATE_PKG_FILE;
    if (xstrcmp(pType, "keepalive")) return DIRECTGATE_PKG_KEEPALIVE;
    if (xstrcmp(pType, "manager")) return DIRECTGATE_PKG_MANAGER;
    if (xstrcmp(pType, "resize")) return DIRECTGATE_PKG_RESIZE;
    if (xstrcmp(pType, "role")) return DIRECTGATE_PKG_ROLE;
    if (xstrcmp(pType, "status")) return DIRECTGATE_PKG_STATUS;
    if (xstrcmp(pType, "verify")) return DIRECTGATE_PKG_VERIFY;
    if (xstrcmp(pType, "webrtc")) return DIRECTGATE_PKG_WEBRTC;
    if (xstrcmp(pType, "admin")) return DIRECTGATE_PKG_ADMIN;
    return DIRECTGATE_PKG_NONE;
}

static size_t DirectGate_Proto_PackageSize(directgate_pkg_type_t eType)
{
    switch (eType)
    {
        case DIRECTGATE_PKG_AUTH: return sizeof(directgate_pkg_auth_t);
        case DIRECTGATE_PKG_CMD: return sizeof(directgate_pkg_cmd_t);
        case DIRECTGATE_PKG_ENCRYPTED: return sizeof(directgate_pkg_data_t);
        case DIRECTGATE_PKG_DATA: return sizeof(directgate_pkg_data_t);
        case DIRECTGATE_PKG_ERROR: return sizeof(directgate_pkg_error_t);
        case DIRECTGATE_PKG_FILE: return sizeof(directgate_pkg_file_t);
        case DIRECTGATE_PKG_KEEPALIVE: return sizeof(directgate_pkg_keepalive_t);
        case DIRECTGATE_PKG_MANAGER: return sizeof(directgate_pkg_manager_t);
        case DIRECTGATE_PKG_RESIZE: return sizeof(directgate_pkg_size_t);
        case DIRECTGATE_PKG_ROLE: return sizeof(directgate_pkg_role_t);
        case DIRECTGATE_PKG_STATUS: return sizeof(directgate_pkg_status_t);
        case DIRECTGATE_PKG_VERIFY: return sizeof(directgate_pkg_verify_t);
        case DIRECTGATE_PKG_WEBRTC: return sizeof(directgate_pkg_webrtc_t);
        case DIRECTGATE_PKG_ADMIN: return sizeof(directgate_pkg_admin_t);
        default: return 0;
    }
}

static xbool_t DirectGate_Package_ParsePayload(directgate_pkg_data_t *pData, xjson_obj_t *pHdr,
                                               const uint8_t *pRawData, size_t nRawSize,
                                               uint32_t nHdrLen)
{
    uint32_t nPayload = XJSON_GetU32(XJSON_GetObject(pHdr, "payloadSize"));
    pData->pPayloadType = XJSON_GetString(XJSON_GetObject(pHdr, "payloadType"));
    pData->bEncrypted = XJSON_GetBool(XJSON_GetObject(pHdr, "encrypted"));

    size_t nOffset = DIRECTGATE_PROTO_PREAMBLE_SIZE + (size_t)nHdrLen;
    if (nPayload)
    {
        /* Same rule as the header bound: the remaining-bytes comparison is a
           subtraction, so a payloadSize near UINT32_MAX cannot wrap the sum and
           hand the caller a pointer with a 4 GB length attached. nOffset is
           re-tested rather than assumed, so this stays correct even if a future
           caller reaches it without Package_Parse having validated nHdrLen. */
        if (nOffset > nRawSize || nPayload > nRawSize - nOffset)
        {
            xlogw("Protocol packet payload is truncated: payload(%u), hdr(%u), packetBytes(%zu)",
                nPayload, nHdrLen, nRawSize);

            return XFALSE;
        }

        pData->pPayload = pRawData + nOffset;
        pData->nPayloadLength = nPayload;
    }

    return XTRUE;
}

static void DirectGate_Package_ParseAuthPkg(directgate_pkg_auth_t *pPkg, xjson_obj_t *pHdr)
{
    pPkg->pAction = XJSON_GetString(XJSON_GetObject(pHdr, "action"));
    pPkg->pMethod = XJSON_GetString(XJSON_GetObject(pHdr, "method"));
    pPkg->pDeviceId = XJSON_GetString(XJSON_GetObject(pHdr, "deviceId"));
    pPkg->pA = XJSON_GetString(XJSON_GetObject(pHdr, "A"));
    pPkg->pB = XJSON_GetString(XJSON_GetObject(pHdr, "B"));
    pPkg->pM1 = XJSON_GetString(XJSON_GetObject(pHdr, "M1"));
    pPkg->pM2 = XJSON_GetString(XJSON_GetObject(pHdr, "M2"));
    pPkg->pSalt = XJSON_GetString(XJSON_GetObject(pHdr, "salt"));
    pPkg->nSuite = XJSON_GetU32(XJSON_GetObject(pHdr, "suite"));
    pPkg->pNonce = XJSON_GetString(XJSON_GetObject(pHdr, "nonce"));
    pPkg->pStatus = XJSON_GetString(XJSON_GetObject(pHdr, "status"));
    pPkg->pReason = XJSON_GetString(XJSON_GetObject(pHdr, "reason"));
    pPkg->pClientPub = XJSON_GetString(XJSON_GetObject(pHdr, "clientPubKey"));
    pPkg->pAgentPub = XJSON_GetString(XJSON_GetObject(pHdr, "agentPubKey"));
    pPkg->pClientEph = XJSON_GetString(XJSON_GetObject(pHdr, "clientEph"));
    pPkg->pAgentEph = XJSON_GetString(XJSON_GetObject(pHdr, "agentEph"));
    pPkg->pChallenge = XJSON_GetString(XJSON_GetObject(pHdr, "challenge"));
    pPkg->pAgentSig = XJSON_GetString(XJSON_GetObject(pHdr, "agentSig"));
    pPkg->pClientSig = XJSON_GetString(XJSON_GetObject(pHdr, "clientSig"));
    pPkg->pDesktopShareId = XJSON_GetString(XJSON_GetObject(pHdr, "desktopShareId"));

    /* Missing means false: agents that predate pre-logon never enter it. */
    xjson_obj_t *pPreLogon = XJSON_GetObject(pHdr, "preLogon");
    pPkg->bPreLogon = (pPreLogon != NULL && XJSON_GetBool(pPreLogon)) ? XTRUE : XFALSE;
}

static void DirectGate_Package_ParseCmdPkg(directgate_pkg_cmd_t *pPkg, xjson_obj_t *pHdr)
{
    pPkg->pAction = XJSON_GetString(XJSON_GetObject(pHdr, "action"));
    pPkg->pMode = XJSON_GetString(XJSON_GetObject(pHdr, "mode"));
}

static void DirectGate_Package_ParseStatusPkg(directgate_pkg_status_t *pPkg, xjson_obj_t *pHdr)
{
    pPkg->pStatus = XJSON_GetString(XJSON_GetObject(pHdr, "status"));
}

static void DirectGate_Package_ParseErrorPkg(directgate_pkg_error_t *pPkg, xjson_obj_t *pHdr)
{
    pPkg->pReason = XJSON_GetString(XJSON_GetObject(pHdr, "reason"));
}

static void DirectGate_Package_ParseKeepalivePkg(directgate_pkg_keepalive_t *pPkg, xjson_obj_t *pHdr)
{
    pPkg->pAction = XJSON_GetString(XJSON_GetObject(pHdr, "action"));
}

static void DirectGate_Package_ParseWebrtcPkg(directgate_pkg_webrtc_t *pPkg, xjson_obj_t *pHdr)
{
    pPkg->pAction = XJSON_GetString(XJSON_GetObject(pHdr, "action"));
}

static void DirectGate_Package_ParseAdminPkg(directgate_pkg_admin_t *pPkg, xjson_obj_t *pHdr)
{
    pPkg->pAction = XJSON_GetString(XJSON_GetObject(pHdr, "action"));
    pPkg->pClientPub = XJSON_GetString(XJSON_GetObject(pHdr, "clientPub"));
    pPkg->nTtlSeconds = XJSON_GetU32(XJSON_GetObject(pHdr, "ttlSeconds"));
    pPkg->pStatus = XJSON_GetString(XJSON_GetObject(pHdr, "status"));
    pPkg->pReason = XJSON_GetString(XJSON_GetObject(pHdr, "reason"));
    pPkg->pShareId = XJSON_GetString(XJSON_GetObject(pHdr, "shareId"));
    pPkg->pVerifier = XJSON_GetString(XJSON_GetObject(pHdr, "verifier"));
    pPkg->pSalt = XJSON_GetString(XJSON_GetObject(pHdr, "salt"));
}

static void DirectGate_Package_ParseManagerPkg(directgate_pkg_manager_t *pPkg, xjson_obj_t *pHdr)
{
    pPkg->pAction = XJSON_GetString(XJSON_GetObject(pHdr, "action"));
    pPkg->pPath = XJSON_GetString(XJSON_GetObject(pHdr, "path"));
    pPkg->pFileName = XJSON_GetString(XJSON_GetObject(pHdr, "fileName"));
    pPkg->pText = XJSON_GetString(XJSON_GetObject(pHdr, "text"));
    pPkg->pTargetPath = XJSON_GetString(XJSON_GetObject(pHdr, "targetPath"));
    pPkg->pPermissions = XJSON_GetString(XJSON_GetObject(pHdr, "permissions"));
    pPkg->pTypes = XJSON_GetString(XJSON_GetObject(pHdr, "types"));
    pPkg->pMinSize = XJSON_GetString(XJSON_GetObject(pHdr, "minSize"));
    pPkg->pMaxSize = XJSON_GetString(XJSON_GetObject(pHdr, "maxSize"));
    pPkg->pFileSize = XJSON_GetString(XJSON_GetObject(pHdr, "fileSize"));
    pPkg->pLinkCount = XJSON_GetString(XJSON_GetObject(pHdr, "linkCount"));
    pPkg->bForce = XJSON_GetBool(XJSON_GetObject(pHdr, "force"));
    pPkg->bCancel = XJSON_GetBool(XJSON_GetObject(pHdr, "cancel"));
    pPkg->bRecursive = XJSON_GetBool(XJSON_GetObject(pHdr, "recursive"));
    pPkg->bInsensitive = XJSON_GetBool(XJSON_GetObject(pHdr, "insensitive"));
    pPkg->bSearchLines = XJSON_GetBool(XJSON_GetObject(pHdr, "searchLines"));
    pPkg->bMatchOnly = XJSON_GetBool(XJSON_GetObject(pHdr, "matchOnly"));
}

static void DirectGate_Package_ParseResizePkg(directgate_pkg_size_t *pPkg, xjson_obj_t *pHdr)
{
    pPkg->nRows = XJSON_GetU32(XJSON_GetObject(pHdr, "rows"));
    pPkg->nCols = XJSON_GetU32(XJSON_GetObject(pHdr, "cols"));
    pPkg->nWidth = XJSON_GetU32(XJSON_GetObject(pHdr, "width"));
    pPkg->nHeight = XJSON_GetU32(XJSON_GetObject(pHdr, "height"));
    if (!pPkg->nWidth) pPkg->nWidth = XJSON_GetU32(XJSON_GetObject(pHdr, "xpixel"));
    if (!pPkg->nHeight) pPkg->nHeight = XJSON_GetU32(XJSON_GetObject(pHdr, "ypixel"));
}

static void DirectGate_Package_ParseRolePkg(directgate_pkg_role_t *pPkg, xjson_obj_t *pHdr)
{
    pPkg->pRole = XJSON_GetString(XJSON_GetObject(pHdr, "role"));
    pPkg->pDeviceId = XJSON_GetString(XJSON_GetObject(pHdr, "deviceId"));
    pPkg->pAccessToken = XJSON_GetString(XJSON_GetObject(pHdr, "accessToken"));
}

static void DirectGate_Package_ParseVerifyPkg(directgate_pkg_verify_t *pPkg, xjson_obj_t *pHdr)
{
    pPkg->pAction = XJSON_GetString(XJSON_GetObject(pHdr, "action"));
    pPkg->pAccessToken = XJSON_GetString(XJSON_GetObject(pHdr, "accessToken"));
    pPkg->pRequestId = XJSON_GetString(XJSON_GetObject(pHdr, "requestId"));
    pPkg->pStatus = XJSON_GetString(XJSON_GetObject(pHdr, "status"));
    pPkg->pReason = XJSON_GetString(XJSON_GetObject(pHdr, "reason"));

    xjson_obj_t *pExpObj = XJSON_GetObject(pHdr, "exp");
    if (pExpObj != NULL)
    {
        const char *pExpStr = XJSON_GetString(pExpObj);
        if (pExpStr != NULL) pPkg->nExp = (uint64_t)strtoull(pExpStr, NULL, 10);
        else pPkg->nExp = (uint64_t)XJSON_GetU32(pExpObj);
    }
}

static xbool_t DirectGate_Package_ParseFilePkg(directgate_pkg_t *pPkg, xjson_obj_t *pHdr, const uint8_t *pData, size_t nSize, uint32_t nHdrLen)
{
    directgate_pkg_file_t *pFile = (directgate_pkg_file_t*)pPkg->pPackage;

    pFile->pAction = XJSON_GetString(XJSON_GetObject(pHdr, "action"));
    pFile->transfer.pTransferId = XJSON_GetString(XJSON_GetObject(pHdr, "transferId"));
    pFile->transfer.pFileName = XJSON_GetString(XJSON_GetObject(pHdr, "name"));
    pFile->transfer.nChunkSize = XJSON_GetU32(XJSON_GetObject(pHdr, "chunkSize"));
    pFile->transfer.nChunkIndex = XJSON_GetU32(XJSON_GetObject(pHdr, "index"));
    pFile->transfer.nChunks = XJSON_GetU32(XJSON_GetObject(pHdr, "chunks"));
    pFile->transfer.pSha256 = XJSON_GetString(XJSON_GetObject(pHdr, "sha256"));

    const char *pSizeStr = XJSON_GetString(XJSON_GetObject(pHdr, "size"));
    pFile->transfer.nFileSize = pSizeStr ? (uint64_t)strtoull(pSizeStr, NULL, 10) : XSTDNON;

    if (!DirectGate_Package_ParsePayload(&pFile->data, pHdr, pData, nSize, nHdrLen))
    {
        free(pPkg->pPackage);
        pPkg->pPackage = NULL;
        return XFALSE;
    }

    return XTRUE;
}

static xbool_t DirectGate_Package_ParseDataPkg(directgate_pkg_t *pPkg, xjson_obj_t *pHdr, const uint8_t *pData, size_t nSize, uint32_t nHdrLen)
{
    directgate_pkg_data_t *pDataPkg = (directgate_pkg_data_t*)pPkg->pPackage;

    if (!DirectGate_Package_ParsePayload(pDataPkg, pHdr, pData, nSize, nHdrLen))
    {
        free(pPkg->pPackage);
        pPkg->pPackage = NULL;
        return XFALSE;
    }

    return XTRUE;
}

static xbool_t DirectGate_Package_ParsePackage(directgate_pkg_t *pPkg, const uint8_t *pData, size_t nSize, uint32_t nHdrLen)
{
    directgate_pkg_type_t eType = pPkg->header.eType;
    xjson_obj_t *pHdr = pPkg->jsonHeader.pRootObj;

    size_t nPkgSize = DirectGate_Proto_PackageSize(eType);
    XCHECK((nPkgSize > 0), xthrowr(XFALSE, "Unsupported package type: %d", (int)eType));

    pPkg->pPackage = calloc(1, nPkgSize);
    if (pPkg->pPackage == NULL)
    {
        const char *pType = (pPkg != NULL && xstrused(pPkg->header.pType)) ? pPkg->header.pType : "N/A";
        xloge("Failed to allocate protocol package: type(%s), sid(%u), ver(%u), cc(%u), pkgBytes(%zu)",
            pType, pPkg != NULL ? pPkg->header.nSessionId : 0,
            pPkg != NULL ? pPkg->header.nProtoVersion : 0,
            pPkg != NULL ? pPkg->header.nPacketId : 0, nPkgSize);

        return XFALSE;
    }

    switch (eType)
    {
        case DIRECTGATE_PKG_ENCRYPTED:
            if (!DirectGate_Package_ParseDataPkg(pPkg, pHdr, pData, nSize, nHdrLen)) return XFALSE;
            break;
        case DIRECTGATE_PKG_DATA:
            if (!DirectGate_Package_ParseDataPkg(pPkg, pHdr, pData, nSize, nHdrLen)) return XFALSE;
            break;
        case DIRECTGATE_PKG_FILE:
            if (!DirectGate_Package_ParseFilePkg(pPkg, pHdr, pData, nSize, nHdrLen)) return XFALSE;
            break;
        case DIRECTGATE_PKG_AUTH:
            DirectGate_Package_ParseAuthPkg((directgate_pkg_auth_t*)pPkg->pPackage, pHdr);
            break;
        case DIRECTGATE_PKG_CMD:
            DirectGate_Package_ParseCmdPkg((directgate_pkg_cmd_t*)pPkg->pPackage, pHdr);
            break;
        case DIRECTGATE_PKG_ERROR:
            DirectGate_Package_ParseErrorPkg((directgate_pkg_error_t*)pPkg->pPackage, pHdr);
            break;
        case DIRECTGATE_PKG_KEEPALIVE:
            DirectGate_Package_ParseKeepalivePkg((directgate_pkg_keepalive_t*)pPkg->pPackage, pHdr);
            break;
        case DIRECTGATE_PKG_MANAGER:
            DirectGate_Package_ParseManagerPkg((directgate_pkg_manager_t*)pPkg->pPackage, pHdr);
            break;
        case DIRECTGATE_PKG_RESIZE:
            DirectGate_Package_ParseResizePkg((directgate_pkg_size_t*)pPkg->pPackage, pHdr);
            break;
        case DIRECTGATE_PKG_ROLE:
            DirectGate_Package_ParseRolePkg((directgate_pkg_role_t*)pPkg->pPackage, pHdr);
            break;
        case DIRECTGATE_PKG_STATUS:
            DirectGate_Package_ParseStatusPkg((directgate_pkg_status_t*)pPkg->pPackage, pHdr);
            break;
        case DIRECTGATE_PKG_VERIFY:
            DirectGate_Package_ParseVerifyPkg((directgate_pkg_verify_t*)pPkg->pPackage, pHdr);
            break;
        case DIRECTGATE_PKG_WEBRTC:
            DirectGate_Package_ParseWebrtcPkg((directgate_pkg_webrtc_t*)pPkg->pPackage, pHdr);
            break;
        case DIRECTGATE_PKG_ADMIN:
            DirectGate_Package_ParseAdminPkg((directgate_pkg_admin_t*)pPkg->pPackage, pHdr);
            break;
        default:
            break;
    }

    return XTRUE;
}

xbool_t DirectGate_Package_Parse(directgate_pkg_t *pPkg, const uint8_t *pData, size_t nSize)
{
    XCHECK((pPkg != NULL), XFALSE);
    XCHECK((pData != NULL), XFALSE);
    XCHECK_NL((nSize >= DIRECTGATE_PROTO_PREAMBLE_SIZE), XFALSE);

    uint32_t nHdrLen = DirectGate_Proto_ReadU32LE(pData);

    /* Bound the attacker-supplied length by SUBTRACTING from what is actually
       here, never by adding to it. The check above guarantees nSize is at least
       the preamble, so the subtraction cannot underflow - while the addition it
       replaces wraps wherever size_t is 32 bits (ARMHF is a shipped target):
       nHdrLen of 0xFFFFFFFF made (PREAMBLE + nHdrLen) evaluate to 3, so a
       four-byte packet passed and the header parser was handed a 4 GB length
       over a four-byte buffer. */
    if (!nHdrLen || nHdrLen > nSize - DIRECTGATE_PROTO_PREAMBLE_SIZE)
    {
        xlogw("Protocol packet header is incomplete: hdr(%u), packetBytes(%zu)", nHdrLen, nSize);
        return XFALSE;
    }

    const char *pHdrStr = (const char*)(pData + DIRECTGATE_PROTO_PREAMBLE_SIZE);
    memset(pPkg, 0, sizeof(*pPkg));

    if (!XJSON_Parse(&pPkg->jsonHeader, NULL, pHdrStr, nHdrLen))
    {
        char sError[256];
        XJSON_GetErrorStr(&pPkg->jsonHeader, sError, sizeof(sError));
        xloge("Failed to parse protocol header JSON: hdr(%u), packetBytes(%zu), error(%s)", nHdrLen, nSize, sError);

        XJSON_Destroy(&pPkg->jsonHeader);
        return XFALSE;
    }

    xjson_obj_t *pHdrObj = pPkg->jsonHeader.pRootObj;
    if (pHdrObj == NULL || pHdrObj->nType != XJSON_TYPE_OBJECT)
    {
        xloge("Invalid protocol header JSON root, expected object");
        DirectGate_Package_Clear(pPkg);
        return XFALSE;
    }

    /* Parse common header fields */
    pPkg->header.nProtoVersion = XJSON_GetU32(XJSON_GetObject(pHdrObj, "version"));
    pPkg->header.nSessionId = XJSON_GetU32(XJSON_GetObject(pHdrObj, "sessionId"));
    pPkg->header.nPacketId = XJSON_GetU32(XJSON_GetObject(pHdrObj, "cc"));
    pPkg->header.pType = XJSON_GetString(XJSON_GetObject(pHdrObj, "type"));
    pPkg->header.eType = DirectGate_Proto_TypeFromStr(pPkg->header.pType);

    /* Parse type-specific package */
    if (!DirectGate_Package_ParsePackage(pPkg, pData, nSize, nHdrLen))
    {
        DirectGate_Package_Clear(pPkg);
        return XFALSE;
    }

    return XTRUE;
}

xbool_t DirectGate_Proto_IsClientPreAuthType(const char *pType)
{
    XCHECK_NL((xstrused(pType)), XFALSE);
    directgate_pkg_type_t eType = DirectGate_Proto_TypeFromStr(pType);
    return (eType == DIRECTGATE_PKG_ROLE || eType == DIRECTGATE_PKG_AUTH);
}

xjson_obj_t* DirectGate_Proto_BuildRole(const char *pRole, const char *pDeviceId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("role", XSTDNON);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    XJSON_AddStrIfUsed(pHeader, "deviceId", pDeviceId);
    XJSON_AddStrIfUsed(pHeader, "role", pRole);

    return pHeader;
}

xjson_obj_t* DirectGate_Proto_BuildCmd(const char *pAction, const char *pStatus,
                                       const char *pReason, const char *pMode,
                                       uint32_t nSessionId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("cmd", nSessionId);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    XJSON_AddStrIfUsed(pHeader, "action", pAction);
    XJSON_AddStrIfUsed(pHeader, "status", pStatus);
    XJSON_AddStrIfUsed(pHeader, "reason", pReason);
    XJSON_AddStrIfUsed(pHeader, "mode", pMode);

    return pHeader;
}

xjson_obj_t* DirectGate_Proto_BuildError(const char *pReason, uint32_t nSessionId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("error", nSessionId);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    XJSON_AddStrIfUsed(pHeader, "reason", pReason);
    return pHeader;
}

xjson_obj_t* DirectGate_Proto_BuildStatus(const char *pStatus, uint32_t nSessionId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("status", nSessionId);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    XJSON_AddStrIfUsed(pHeader, "status", pStatus);
    return pHeader;
}

xjson_obj_t* DirectGate_Proto_BuildData(uint32_t nSessionId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("data", nSessionId);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));
    return pHeader;
}

xjson_obj_t* DirectGate_Proto_BuildResize(uint32_t nRows, uint32_t nCols,
                                          uint32_t nXPixel, uint32_t nYPixel,
                                          uint32_t nSessionId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("resize", nSessionId);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    XJSON_AddU32(pHeader, "rows", nRows);
    XJSON_AddU32(pHeader, "cols", nCols);
    XJSON_AddU32(pHeader, "xpixel", nXPixel);
    XJSON_AddU32(pHeader, "ypixel", nYPixel);

    return pHeader;
}

xjson_obj_t* DirectGate_Proto_BuildAuthHello(const char *pDeviceId, const char *pA,
                                             const char *pNonce, uint32_t nSessionId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("auth", nSessionId);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    XJSON_AddString(pHeader, "action", "hello");
    XJSON_AddStrIfUsed(pHeader, "deviceId", pDeviceId);
    XJSON_AddStrIfUsed(pHeader, "nonce", pNonce);
    XJSON_AddStrIfUsed(pHeader, "A", pA);

    return pHeader;
}

xjson_obj_t* DirectGate_Proto_BuildAuthProof(const char *pM1, uint32_t nSessionId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("auth", nSessionId);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    XJSON_AddString(pHeader, "action", "proof");
    XJSON_AddStrIfUsed(pHeader, "M1", pM1);

    return pHeader;
}

xjson_obj_t* DirectGate_Proto_BuildAuthChallenge(const char *pSalt, const char *pB,
                                                 const char *pNonce, uint32_t nSuite,
                                                 uint32_t nSessionId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("auth", nSessionId);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    if (nSuite) XJSON_AddU32(pHeader, "suite", nSuite);
    XJSON_AddString(pHeader, "action", "challenge");
    XJSON_AddStrIfUsed(pHeader, "salt", pSalt);
    XJSON_AddStrIfUsed(pHeader, "nonce", pNonce);
    XJSON_AddStrIfUsed(pHeader, "B", pB);

    return pHeader;
}

xjson_obj_t* DirectGate_Proto_BuildAuthResult(const char *pStatus, const char *pM2,
                                              const char *pReason, uint32_t nSessionId,
                                              xbool_t bPreLogon)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("auth", nSessionId);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    XJSON_AddString(pHeader, "action", "result");
    XJSON_AddStrIfUsed(pHeader, "status", pStatus);
    XJSON_AddStrIfUsed(pHeader, "reason", pReason);
    XJSON_AddStrIfUsed(pHeader, "M2", pM2);
    if (bPreLogon) XJSON_AddBool(pHeader, "preLogon", XTRUE);

    return pHeader;
}

xjson_obj_t* DirectGate_Proto_BuildAuthKeyHello(const char *pDeviceId,
                                                const char *pClientPubKeyB64,
                                                const char *pClientEphB64,
                                                const char *pNonceHex,
                                                uint32_t nSessionId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("auth", nSessionId);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    XJSON_AddString(pHeader, "action", "hello");
    XJSON_AddString(pHeader, "method", "key");
    XJSON_AddStrIfUsed(pHeader, "deviceId", pDeviceId);
    XJSON_AddStrIfUsed(pHeader, "clientPubKey", pClientPubKeyB64);
    XJSON_AddStrIfUsed(pHeader, "clientEph", pClientEphB64);
    XJSON_AddStrIfUsed(pHeader, "nonce", pNonceHex);

    return pHeader;
}

xjson_obj_t* DirectGate_Proto_BuildAuthKeyChallenge(const char *pAgentPubKeyB64,
                                                    const char *pAgentEphB64,
                                                    const char *pNonceHex,
                                                    const char *pChallengeHex,
                                                    const char *pAgentSigB64,
                                                    uint32_t nSessionId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("auth", nSessionId);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    XJSON_AddString(pHeader, "action", "challenge");
    XJSON_AddString(pHeader, "method", "key");
    XJSON_AddStrIfUsed(pHeader, "agentPubKey", pAgentPubKeyB64);
    XJSON_AddStrIfUsed(pHeader, "agentEph", pAgentEphB64);
    XJSON_AddStrIfUsed(pHeader, "nonce", pNonceHex);
    XJSON_AddStrIfUsed(pHeader, "challenge", pChallengeHex);
    XJSON_AddStrIfUsed(pHeader, "agentSig", pAgentSigB64);

    return pHeader;
}

xjson_obj_t* DirectGate_Proto_BuildAuthKeyProof(const char *pClientSigB64,
                                                uint32_t nSessionId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("auth", nSessionId);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    XJSON_AddString(pHeader, "action", "proof");
    XJSON_AddString(pHeader, "method", "key");
    XJSON_AddStrIfUsed(pHeader, "clientSig", pClientSigB64);

    return pHeader;
}

xjson_obj_t* DirectGate_Proto_BuildManager(const char *pAction, const char *pStatus,
                                           const char *pPath, const char *pReason,
                                           uint32_t nSessionId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("manager", nSessionId);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    XJSON_AddStrIfUsed(pHeader, "action", pAction);
    XJSON_AddStrIfUsed(pHeader, "status", pStatus);
    XJSON_AddStrIfUsed(pHeader, "reason", pReason);
    XJSON_AddStrIfUsed(pHeader, "path", pPath);

    return pHeader;
}

xjson_obj_t* DirectGate_Proto_BuildAdmin(const char *pAction, const char *pClientPub,
                                         const char *pStatus, const char *pReason,
                                         uint32_t nSessionId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("admin", nSessionId);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    XJSON_AddStrIfUsed(pHeader, "action", pAction);
    XJSON_AddStrIfUsed(pHeader, "clientPub", pClientPub);
    XJSON_AddStrIfUsed(pHeader, "status", pStatus);
    XJSON_AddStrIfUsed(pHeader, "reason", pReason);

    return pHeader;
}

xjson_obj_t* DirectGate_Proto_BuildFileStart(const char *pTransferId, const char *pName,
                                             uint64_t nSize, uint32_t nChunks, uint32_t nChunkSize)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("file", XSTDNON);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    XJSON_AddString(pHeader, "action", "start");
    XJSON_AddStrIfUsed(pHeader, "transferId", pTransferId);
    XJSON_AddStrIfUsed(pHeader, "name", pName);

    char sSize[32];
    snprintf(sSize, sizeof(sSize), "%" PRIu64, nSize);
    XJSON_AddString(pHeader, "size", sSize);

    XJSON_AddU32(pHeader, "chunks", nChunks);
    XJSON_AddU32(pHeader, "chunkSize", nChunkSize);

    return pHeader;
}

xjson_obj_t* DirectGate_Proto_BuildFileChunk(const char *pTransferId, uint32_t nIndex)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("file", XSTDNON);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    XJSON_AddString(pHeader, "action", "chunk");
    XJSON_AddStrIfUsed(pHeader, "transferId", pTransferId);
    XJSON_AddU32(pHeader, "index", nIndex);

    return pHeader;
}

xjson_obj_t* DirectGate_Proto_BuildFileEnd(const char *pTransferId, const char *pSha256)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("file", XSTDNON);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    XJSON_AddString(pHeader, "action", "end");
    XJSON_AddStrIfUsed(pHeader, "transferId", pTransferId);
    XJSON_AddStrIfUsed(pHeader, "sha256", pSha256);

    return pHeader;
}

xjson_obj_t* DirectGate_Proto_BuildFileAck(const char *pTransferId, uint32_t nIndex)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("file", XSTDNON);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    XJSON_AddString(pHeader, "action", "ack");
    XJSON_AddStrIfUsed(pHeader, "transferId", pTransferId);
    XJSON_AddU32(pHeader, "index", nIndex);

    return pHeader;
}

xjson_obj_t* DirectGate_Proto_BuildFileCancel(const char *pTransferId, const char *pReason)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("file", XSTDNON);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    XJSON_AddString(pHeader, "action", "cancel");
    XJSON_AddStrIfUsed(pHeader, "transferId", pTransferId);
    XJSON_AddStrIfUsed(pHeader, "reason", pReason);

    return pHeader;
}

xjson_obj_t* DirectGate_Proto_BuildKeepalive(const char *pAction, uint32_t nSessionId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("keepalive", nSessionId);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    XJSON_AddStrIfUsed(pHeader, "action", pAction);
    return pHeader;
}

xjson_obj_t* DirectGate_Proto_BuildVerify(const char *pAction, const char *pAccessToken,
                                          const char *pRequestId, uint64_t nExp,
                                          const char *pStatus, const char *pReason)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("verify", XSTDNON);
    XCHECK(pHeader, xthrowp(NULL, "Failed to create json header"));

    XJSON_AddStrIfUsed(pHeader, "action", pAction);
    XJSON_AddStrIfUsed(pHeader, "accessToken", pAccessToken);
    XJSON_AddStrIfUsed(pHeader, "requestId", pRequestId);
    XJSON_AddStrIfUsed(pHeader, "status", pStatus);
    XJSON_AddStrIfUsed(pHeader, "reason", pReason);

    if (nExp > 0)
    {
        char sExp[32];
        snprintf(sExp, sizeof(sExp), "%" PRIu64, nExp);
        XJSON_AddString(pHeader, "exp", sExp);
    }

    return pHeader;
}

static xbool_t DirectGate_Proto_IsSignalScope(const char *pScope)
{
    return xstrused(pScope) && xstrcmp(pScope, "signal") ? XTRUE : XFALSE;
}

xbool_t DirectGate_Proto_AddCC(xjson_obj_t *pHeader, directgate_e2e_t *pE2E,
                               uint32_t nSessionEpoch)
{
    XCHECK((pHeader != NULL), XFALSE);
    XCHECK((pE2E != NULL), XFALSE);

    const char *pType = XJSON_GetString(XJSON_GetObject(pHeader, "type"));
    xbool_t bSignal = xstrused(pType) && xstrcmp(pType, "webrtc");
    uint32_t *pScopedCounter;

    if (bSignal)
    {
        pScopedCounter = &pE2E->nTxSignalPacketId;
    }
    else
    {
        if (pE2E->nTxSessionEpoch != nSessionEpoch)
        {
            pE2E->nTxSessionEpoch = nSessionEpoch;
            pE2E->nTxSessionPacketId = 0;
        }

        pScopedCounter = &pE2E->nTxSessionPacketId;
        XJSON_AddU32(pHeader, "ce", nSessionEpoch);
    }

    XJSON_AddString(pHeader, "ccScope", bSignal ? "signal" : "session");
    XJSON_AddU32(pHeader, "sc", ++(*pScopedCounter));
    XJSON_AddU32(pHeader, "cc", ++pE2E->nTxPacketId);
    return XTRUE;
}

xbool_t DirectGate_Proto_CheckCC(xbyte_buffer_t *pOut, directgate_e2e_t *pE2E)
{
    XCHECK((pE2E != NULL), XFALSE);
    XCHECK((pOut != NULL), XFALSE);
    XCHECK_NL((pOut->nUsed >= DIRECTGATE_PROTO_PREAMBLE_SIZE), XFALSE);

    uint32_t nHdrLen = DirectGate_Proto_ReadU32LE(pOut->pData);

    /* Decrypted, so the length is authenticated but a peer that has completed
       the handshake is still not trusted to be well behaved, and the wrap this
       avoids is the same one Package_Parse guards. */
    if (nHdrLen > 0 && nHdrLen <= pOut->nUsed - DIRECTGATE_PROTO_PREAMBLE_SIZE)
    {
        const char *pJsonData = (const char*)(pOut->pData + DIRECTGATE_PROTO_PREAMBLE_SIZE);
        xjson_t json;

        if (XJSON_Parse(&json, NULL, pJsonData, nHdrLen))
        {
            uint32_t nCC = XJSON_GetU32(XJSON_GetObject(json.pRootObj, "cc"));
            XCHECK_CALL((nCC > 0), XJSON_Destroy, &json,
                xthrowr(XFALSE, "Missing CC in the packet header"));

            xjson_obj_t *pScopeObj = XJSON_GetObject(json.pRootObj, "ccScope");
            const char *pScope = pScopeObj != NULL ? XJSON_GetString(pScopeObj) : NULL;
            xbool_t bSignal = DirectGate_Proto_IsSignalScope(pScope);
            xbool_t bInput = xstrused(pScope) && xstrcmp(pScope, "input");

            XCHECK_CALL((!xstrused(pScope) || bSignal || bInput || xstrcmp(pScope, "session")),
                XJSON_Destroy, &json, xthrowr(XFALSE, "Unknown CC scope: %s", pScope));

            if (xstrused(pScope))
            {
                uint32_t nScopedCC = XJSON_GetU32(XJSON_GetObject(json.pRootObj, "sc"));
                XCHECK_CALL((nScopedCC > 0), XJSON_Destroy, &json,
                    xthrowr(XFALSE, "Missing scoped CC for scope(%s)", pScope));

                directgate_ccwin_t *pWindow;
                if (bSignal)
                {
                    pWindow = &pE2E->rxSignalWindow;
                }
                else
                {
                    uint32_t nEpoch = XJSON_GetU32(XJSON_GetObject(json.pRootObj, "ce"));
                    XCHECK_CALL((nEpoch >= pE2E->nRxSessionEpoch), XJSON_Destroy, &json,
                        xthrowr(XFALSE, "Stale session CC epoch(%u) < active(%u)",
                            nEpoch, pE2E->nRxSessionEpoch));
                    if (nEpoch > pE2E->nRxSessionEpoch)
                    {
                        pE2E->nRxSessionEpoch = nEpoch;
                        DirectGate_E2E_ResetCCWindow(&pE2E->rxSessionWindow);
                        DirectGate_E2E_ResetCCWindow(&pE2E->rxInputWindow);
                    }

                    pWindow = bInput ?
                        &pE2E->rxInputWindow :
                        &pE2E->rxSessionWindow;
                }

                if (!DirectGate_E2E_AcceptCC(pWindow, nScopedCC))
                {
                    xlogw("Dropping replayed or stale packet: sc(%u), window(%u), scope(%s)",
                        nScopedCC, pWindow->nHighest, bSignal ? "signal" : (bInput ? "input" : "session"));

                    XJSON_Destroy(&json);
                    return XFALSE;
                }

                DirectGate_E2E_AcceptCC(&pE2E->rxWindow, nCC);
            }
            else if (!DirectGate_E2E_AcceptCC(&pE2E->rxWindow, nCC))
            {
                xlogw("Dropping replayed or stale packet: cc(%u), window(%u)",
                    nCC, pE2E->rxWindow.nHighest);

                XJSON_Destroy(&json);
                return XFALSE;
            }

            XJSON_Destroy(&json);
            return XTRUE;
        }
    }

    return XFALSE;
}

xbool_t DirectGate_Proto_EncryptPackage(xbyte_buffer_t *pOut, directgate_e2e_t *pE2E, uint32_t nSessionId)
{
    XCHECK((pOut != NULL && pOut->nUsed > 0), XFALSE);
    XCHECK((pE2E != NULL && pE2E->bInitialized), XFALSE);

    size_t nEncLen = 0;
    uint8_t *pEncrypted = DirectGate_E2E_Encrypt(pE2E, pOut->pData, pOut->nUsed, &nEncLen);
    XCHECK((pEncrypted != NULL), xthrowr(XFALSE, "E2E encryption failed"));

    XByteBuffer_Reset(pOut);
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("encrypted", nSessionId);
    XCHECK_FREE(pHeader, pEncrypted, xthrowr(XFALSE, "Failed to create encryption header"));

    xbool_t bOk = DirectGate_Proto_Build(pOut, pHeader, pEncrypted, nEncLen, XFALSE);
    XJSON_FreeObject(pHeader);
    free(pEncrypted);

    return bOk;
}

xbool_t DirectGate_Proto_DecryptPackage(xbyte_buffer_t *pOut, const directgate_pkg_t *pPkg, directgate_e2e_t *pE2E)
{
    XCHECK((pOut != NULL), XFALSE);
    XCHECK((pPkg != NULL), XFALSE);
    XCHECK((pE2E != NULL), XFALSE);
    XCHECK((pE2E->bInitialized), XFALSE);
    XCHECK((pPkg->pPackage != NULL), XFALSE);

    const directgate_pkg_data_t *pData = (const directgate_pkg_data_t*)pPkg->pPackage;
    XCHECK((pData->pPayload != NULL), XFALSE);
    XCHECK((pData->nPayloadLength > 0), XFALSE);

    size_t nDecLen = 0;
    uint8_t *pDecrypted;

    pDecrypted = DirectGate_E2E_Decrypt(pE2E, pData->pPayload, pData->nPayloadLength, &nDecLen);
    XCHECK((pDecrypted != NULL), xthrowr(XFALSE, "E2E decryption failed"));

    XByteBuffer_Reset(pOut);
    xbool_t bOk = XByteBuffer_Add(pOut, pDecrypted, nDecLen) > 0;

    free(pDecrypted);
    XCHECK(bOk, XFALSE);

    if (!DirectGate_Proto_CheckCC(pOut, pE2E))
    {
        XByteBuffer_Reset(pOut);
        return XFALSE;
    }

    return XTRUE;
}

xbool_t DirectGate_Proto_BindInnerSessionId(uint32_t nOuterSessionId, directgate_pkg_t *pInnerPkg)
{
    XCHECK((nOuterSessionId > 0), XFALSE);
    XCHECK((pInnerPkg != NULL), XFALSE);

    if (pInnerPkg->header.nSessionId == 0)
    {
        pInnerPkg->header.nSessionId = nOuterSessionId;
        return XTRUE;
    }

    return (pInnerPkg->header.nSessionId == nOuterSessionId);
}
