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

/* {"sessionId":4294967295,"payloadSize":4294967295,"type":"encrypted","version":4294967295} fits with room to spare */
#define DIRECTGATE_PROTO_ENC_HEADER_MAX 128

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

    /* Builders add their fields without checking each one: a header that lost one for want of memory has to
       fail to build, not go out without its type, status or counter while the sender thinks it was sent */
    XJSON_SetStrict(pHeader, XTRUE);
    XJSON_AddStrIfUsed(pHeader, "type", pType);
    XJSON_AddU32(pHeader, "version", DIRECTGATE_PROTOCOL_VERSION);
    XJSON_AddU32(pHeader, "sessionId", nSessionId);

    return pHeader;
}

/* Preamble, header, payload. XByteBuffer_Add returns a negative status when it cannot grow the buffer:
   taken as success, a packet that ran out of memory went out empty or without its payload. */
static xbool_t DirectGate_Proto_Assemble(xbyte_buffer_t *pOut, const char *pHeader, size_t nHdrLen,
                                         const uint8_t *pPayload, size_t nPayload)
{
    uint8_t sPreamble[DIRECTGATE_PROTO_PREAMBLE_SIZE];
    DirectGate_Proto_WriteU32LE(sPreamble, (uint32_t)nHdrLen);

    return (XByteBuffer_Add(pOut, sPreamble, sizeof(sPreamble)) > 0 &&
            XByteBuffer_Add(pOut, (const uint8_t*)pHeader, nHdrLen) > 0 &&
            (pPayload == NULL || !nPayload || XByteBuffer_Add(pOut, pPayload, nPayload) > 0)) ? XTRUE : XFALSE;
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

    if (!DirectGate_Proto_Assemble(pOut, writer.pData, writer.nLength, pPayload, nPayload))
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
        if (pExpObj->nType == XJSON_TYPE_STRING) pPkg->nExp = (uint64_t)strtoull(XJSON_GetString(pExpObj), NULL, 10);
        else pPkg->nExp = XJSON_GetU64(pExpObj);
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

/* The value XJSON_GetU32 reads from the same member once parsed: an integer that fits, otherwise zero */
static uint32_t DirectGate_Proto_FieldU32(const xjson_field_t *pField)
{
    if (pField->nType != XJSON_TYPE_NUMBER || !pField->nLength || pField->pValue[0] == '-') return 0;
    uint64_t nValue = 0;

    for (size_t i = 0; i < pField->nLength; i++)
    {
        nValue = nValue * 10 + (uint64_t)(pField->pValue[i] - '0');
        if (nValue > UINT32_MAX) return 0;
    }

    return (uint32_t)nValue;
}

static xbool_t DirectGate_Proto_FieldIs(const xjson_field_t *pField, const char *pText)
{
    size_t nLength = strlen(pText);
    return pField->nType == XJSON_TYPE_STRING &&
           pField->nLength == nLength &&
           !memcmp(pField->pValue, pText, nLength);
}

/* Every message a relay forwards between a browser and its agent came through DirectGate_Package_Parse,
   and building the header's tree took the most of the relay's time for a small message. The checks are
   the ones it makes: the header bound, a known type and, for an encrypted packet, a payload that fits. */
xbool_t DirectGate_Package_ParseRoute(directgate_pkg_t *pPkg, const uint8_t *pData, size_t nSize)
{
    XCHECK_NL((pPkg != NULL && pData != NULL), XFALSE);
    XCHECK_NL((nSize >= DIRECTGATE_PROTO_PREAMBLE_SIZE), XFALSE);

    uint32_t nHdrLen = DirectGate_Proto_ReadU32LE(pData);
    XCHECK_NL((nHdrLen && nHdrLen <= nSize - DIRECTGATE_PROTO_PREAMBLE_SIZE), XFALSE);

    xjson_field_t fields[] = {
        { "type", NULL, 0, 0 },
        { "sessionId", NULL, 0, 0 },
        { "version", NULL, 0, 0 },
        { "cc", NULL, 0, 0 },
        { "payloadSize", NULL, 0, 0 }
    };

    const char *pHdrStr = (const char*)(pData + DIRECTGATE_PROTO_PREAMBLE_SIZE);
    XCHECK_NL(XJSON_ScanFlat(pHdrStr, nHdrLen, fields, sizeof(fields) / sizeof(fields[0])), XFALSE);

    static const struct {
        const char *pName;
        directgate_pkg_type_t eType;
    } routed[] = {
        { "encrypted", DIRECTGATE_PKG_ENCRYPTED },
        { "webrtc", DIRECTGATE_PKG_WEBRTC },
        { "resize", DIRECTGATE_PKG_RESIZE },
        { "status", DIRECTGATE_PKG_STATUS }
    };

    directgate_pkg_type_t eType = DIRECTGATE_PKG_NONE;
    const char *pType = NULL;

    for (size_t i = 0; i < sizeof(routed) / sizeof(routed[0]) && pType == NULL; i++)
    {
        if (!DirectGate_Proto_FieldIs(&fields[0], routed[i].pName)) continue;
        eType = routed[i].eType;
        pType = routed[i].pName;
    }

    XCHECK_NL((pType != NULL), XFALSE);

    /* The rest of the packet has to hold the payload the header announces, as DirectGate_Package_ParsePayload checks */
    uint32_t nPayload = DirectGate_Proto_FieldU32(&fields[4]);
    size_t nOffset = DIRECTGATE_PROTO_PREAMBLE_SIZE + (size_t)nHdrLen;
    if (eType == DIRECTGATE_PKG_ENCRYPTED && nPayload && nPayload > nSize - nOffset) return XFALSE;

    memset(pPkg, 0, sizeof(*pPkg));
    pPkg->header.eType = eType;
    pPkg->header.pType = pType;
    pPkg->header.nSessionId = DirectGate_Proto_FieldU32(&fields[1]);
    pPkg->header.nProtoVersion = DirectGate_Proto_FieldU32(&fields[2]);
    pPkg->header.nPacketId = DirectGate_Proto_FieldU32(&fields[3]);

    return XTRUE;
}

xbool_t DirectGate_Proto_IsClientPreAuthType(const char *pType)
{
    XCHECK_NL((xstrused(pType)), XFALSE);
    directgate_pkg_type_t eType = DirectGate_Proto_TypeFromStr(pType);
    return (eType == DIRECTGATE_PKG_ROLE || eType == DIRECTGATE_PKG_AUTH);
}

xbool_t DirectGate_Proto_ClientAcceptsPlain(directgate_pkg_type_t eType, xbool_t bAuthenticated)
{
    if (eType == DIRECTGATE_PKG_ERROR || eType == DIRECTGATE_PKG_STATUS) return XTRUE;
    if (bAuthenticated) return XFALSE;

    return (eType == DIRECTGATE_PKG_AUTH ||
            eType == DIRECTGATE_PKG_CMD ||
            eType == DIRECTGATE_PKG_KEEPALIVE);
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

/* What CheckCC reads from an inner header. A scope that is absent or not a string is no scope at all,
   as the empty string XJSON_GetString gives for it always was. */
typedef struct {
    const char *pScope;
    size_t nScopeLen;
    uint32_t nScopedCC;
    uint32_t nEpoch;
    uint32_t nCC;
} directgate_cc_header_t;

static xbool_t DirectGate_Proto_ScopeIs(const directgate_cc_header_t *pHdr, const char *pName)
{
    size_t nLength = strlen(pName);
    return pHdr->nScopeLen == nLength && !memcmp(pHdr->pScope, pName, nLength);
}

static xbool_t DirectGate_Proto_AcceptHeaderCC(directgate_e2e_t *pE2E, const directgate_cc_header_t *pHdr)
{
    XCHECK((pHdr->nCC > 0), xthrowr(XFALSE, "Missing CC in the packet header"));
    int nScopeLen = (int)XSTD_MIN(pHdr->nScopeLen, (size_t)INT_MAX);
    xbool_t bScoped = pHdr->nScopeLen > 0;
    xbool_t bSignal = DirectGate_Proto_ScopeIs(pHdr, "signal");
    xbool_t bInput = DirectGate_Proto_ScopeIs(pHdr, "input");

    XCHECK((!bScoped || bSignal || bInput || DirectGate_Proto_ScopeIs(pHdr, "session")),
        xthrowr(XFALSE, "Unknown CC scope: %.*s", nScopeLen, pHdr->pScope));

    if (!bScoped)
    {
        if (DirectGate_E2E_AcceptCC(&pE2E->rxWindow, pHdr->nCC)) return XTRUE;
        xlogw("Dropping replayed or stale packet: cc(%u), window(%u)", pHdr->nCC, pE2E->rxWindow.nHighest);
        return XFALSE;
    }

    XCHECK((pHdr->nScopedCC > 0), xthrowr(XFALSE, "Missing scoped CC for scope(%.*s)", nScopeLen, pHdr->pScope));
    directgate_ccwin_t *pWindow;

    if (bSignal)
    {
        pWindow = &pE2E->rxSignalWindow;
    }
    else
    {
        XCHECK((pHdr->nEpoch >= pE2E->nRxSessionEpoch), xthrowr(XFALSE,
            "Stale session CC epoch(%u) < active(%u)", pHdr->nEpoch, pE2E->nRxSessionEpoch));

        if (pHdr->nEpoch > pE2E->nRxSessionEpoch)
        {
            pE2E->nRxSessionEpoch = pHdr->nEpoch;
            DirectGate_E2E_ResetCCWindow(&pE2E->rxSessionWindow);
            DirectGate_E2E_ResetCCWindow(&pE2E->rxInputWindow);
        }

        pWindow = bInput ?
            &pE2E->rxInputWindow :
            &pE2E->rxSessionWindow;
    }

    if (!DirectGate_E2E_AcceptCC(pWindow, pHdr->nScopedCC))
    {
        xlogw("Dropping replayed or stale packet: sc(%u), window(%u), scope(%s)",
            pHdr->nScopedCC, pWindow->nHighest, bSignal ? "signal" : (bInput ? "input" : "session"));
        return XFALSE;
    }

    DirectGate_E2E_AcceptCC(&pE2E->rxWindow, pHdr->nCC);
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
    if (!nHdrLen || nHdrLen > pOut->nUsed - DIRECTGATE_PROTO_PREAMBLE_SIZE) return XFALSE;
    const char *pJsonData = (const char*)(pOut->pData + DIRECTGATE_PROTO_PREAMBLE_SIZE);
    directgate_cc_header_t hdr = { NULL, 0, 0, 0, 0 };

    /* Every inner header is a flat object, read in place. XJSON_ScanFlat takes nothing XJSON_Parse would not
       and reports the same members, so anything it refuses is read from the parsed tree as it always was. */
    xjson_field_t fields[] = {
        { "cc", NULL, 0, 0 },
        { "ccScope", NULL, 0, 0 },
        { "sc", NULL, 0, 0 },
        { "ce", NULL, 0, 0 }
    };

    if (XJSON_ScanFlat(pJsonData, nHdrLen, fields, sizeof(fields) / sizeof(fields[0])))
    {
        hdr.nCC = DirectGate_Proto_FieldU32(&fields[0]);
        hdr.nScopedCC = DirectGate_Proto_FieldU32(&fields[2]);
        hdr.nEpoch = DirectGate_Proto_FieldU32(&fields[3]);

        if (fields[1].nType == XJSON_TYPE_STRING)
        {
            hdr.pScope = fields[1].pValue;
            hdr.nScopeLen = fields[1].nLength;
        }

        return DirectGate_Proto_AcceptHeaderCC(pE2E, &hdr);
    }

    xjson_t json;
    XCHECK_NL(XJSON_Parse(&json, NULL, pJsonData, nHdrLen), XFALSE);

    hdr.nCC = XJSON_GetU32(XJSON_GetObject(json.pRootObj, "cc"));
    hdr.nScopedCC = XJSON_GetU32(XJSON_GetObject(json.pRootObj, "sc"));
    hdr.nEpoch = XJSON_GetU32(XJSON_GetObject(json.pRootObj, "ce"));

    xjson_obj_t *pScopeObj = XJSON_GetObject(json.pRootObj, "ccScope");
    hdr.pScope = pScopeObj != NULL ? XJSON_GetString(pScopeObj) : NULL;
    hdr.nScopeLen = hdr.pScope != NULL ? strlen(hdr.pScope) : 0;

    xbool_t bAccepted = DirectGate_Proto_AcceptHeaderCC(pE2E, &hdr);
    XJSON_Destroy(&json);
    return bAccepted;
}

xbool_t DirectGate_Proto_EncryptPackage(xbyte_buffer_t *pOut, directgate_e2e_t *pE2E, uint32_t nSessionId)
{
    XCHECK((pOut != NULL && pOut->nUsed > 0), XFALSE);
    XCHECK((pE2E != NULL && pE2E->bInitialized), XFALSE);

    size_t nEncLen = 0;
    uint8_t *pEncrypted = DirectGate_E2E_Encrypt(pE2E, pOut->pData, pOut->nUsed, &nEncLen);
    XCHECK((pEncrypted != NULL), xthrowr(XFALSE, "E2E encryption failed"));

    /* The header NewHeader("encrypted") and Build give, written out without a tree to build, serialize and
       free for every packet: the members in the order its map holds them, the payload never empty. The text
       is compared with what they give in protocol_smoke, so a change on either side fails there first. */
    char sHeader[DIRECTGATE_PROTO_ENC_HEADER_MAX];
    int nHdrLen = snprintf(sHeader, sizeof(sHeader),
        "{\"sessionId\":%u,\"payloadSize\":%u,\"type\":\"encrypted\",\"version\":%u}",
        nSessionId, (uint32_t)nEncLen, (uint32_t)DIRECTGATE_PROTOCOL_VERSION);

    XByteBuffer_Reset(pOut);
    xbool_t bOk = nHdrLen > 0 && DirectGate_Proto_Assemble(pOut, sHeader, (size_t)nHdrLen, pEncrypted, nEncLen);
    if (!bOk) xloge("Failed to assemble protocol packet: type(encrypted), sid(%u), hdr(%d), payload(%zu)", nSessionId, nHdrLen, nEncLen);

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
