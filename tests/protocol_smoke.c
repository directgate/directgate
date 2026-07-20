#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "src/common/protocol.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "protocol_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static int build_packet(xbyte_buffer_t *pOut, xjson_obj_t *pHeader,
                        const uint8_t *pPayload, size_t nPayload,
                        xbool_t bEncrypted)
{
    int nOk = DirectGate_Proto_Build(pOut, pHeader, pPayload, nPayload, bEncrypted);
    XJSON_FreeObject(pHeader);
    return nOk ? 0 : 1;
}

static xbool_t check_scoped_cc(directgate_e2e_t *pE2E, const char *pScope,
                               uint32_t nEpoch, uint32_t nScopedCC,
                               uint32_t nGlobalCC)
{
    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, XSTDNON, XFALSE);

    xjson_obj_t *pHeader = DirectGate_Proto_BuildData(42);
    if (pHeader == NULL) return XFALSE;
    XJSON_AddString(pHeader, "ccScope", pScope);
    XJSON_AddU32(pHeader, "sc", nScopedCC);
    XJSON_AddU32(pHeader, "cc", nGlobalCC);
    if (strcmp(pScope, "session") == 0) XJSON_AddU32(pHeader, "ce", nEpoch);

    xbool_t bBuilt = DirectGate_Proto_Build(&packet, pHeader, NULL, 0, XFALSE);
    XJSON_FreeObject(pHeader);
    xbool_t bAccepted = bBuilt ? DirectGate_Proto_CheckCC(&packet, pE2E) : XFALSE;
    XByteBuffer_Clear(&packet);
    return bAccepted;
}

int main(void)
{
    directgate_e2e_t ccState;
    DirectGate_E2E_Init(&ccState);
    CHECK(check_scoped_cc(&ccState, "session", 1, 1, 1),
        "first TURN generation packet accepted");
    CHECK(check_scoped_cc(&ccState, "signal", 0, 1, 2),
        "signaling has an independent strict counter");
    CHECK(check_scoped_cc(&ccState, "session", 2, 1, 3),
        "first P2P generation packet accepted after counter restart");
    CHECK(!check_scoped_cc(&ccState, "session", 1, 2, 4),
        "late TURN packet rejected after P2P generation activates");
    CHECK(!check_scoped_cc(&ccState, "session", 2, 1, 5),
        "duplicate packet rejected inside active P2P generation");
    CHECK(check_scoped_cc(&ccState, "session", 2, 2, 6),
        "next P2P generation packet accepted");
    CHECK(!check_scoped_cc(&ccState, "signal", 0, 1, 7),
        "duplicate signaling packet rejected");
    DirectGate_E2E_Clear(&ccState);

    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, XSTDNON, XFALSE);

    const uint8_t payload[] = { 'p', 't', 'y', '\n' };
    xjson_obj_t *pHeader = DirectGate_Proto_BuildData(42);
    CHECK(pHeader != NULL, "build data header");
    XJSON_AddString(pHeader, "payloadType", "raw");
    XJSON_AddU32(pHeader, "cc", 9);
    CHECK(build_packet(&packet, pHeader, payload, sizeof(payload), XTRUE) == 0,
        "build data packet");

    directgate_pkg_t pkg;
    CHECK(DirectGate_Package_Parse(&pkg, packet.pData, packet.nUsed),
        "parse data packet");
    CHECK(pkg.header.eType == DIRECTGATE_PKG_DATA, "data packet type");
    CHECK(pkg.header.nSessionId == 42, "data session id");
    CHECK(pkg.header.nPacketId == 9, "data packet counter");
    directgate_pkg_data_t *pData = (directgate_pkg_data_t*)pkg.pPackage;
    CHECK(pData != NULL, "data package body");
    CHECK(pData->bEncrypted == XTRUE, "data encrypted flag");
    CHECK(pData->pPayloadType != NULL && strcmp(pData->pPayloadType, "raw") == 0,
        "data payload type");
    CHECK(pData->nPayloadLength == sizeof(payload), "data payload length");
    CHECK(memcmp(pData->pPayload, payload, sizeof(payload)) == 0,
        "data payload bytes");
    directgate_pkg_t malformedPkg;
    memset(&malformedPkg, 0, sizeof(malformedPkg));
    CHECK(!DirectGate_Package_Parse(&malformedPkg, packet.pData, packet.nUsed - 1),
        "truncated payload must fail");
    DirectGate_Package_Clear(&pkg);

    XByteBuffer_Reset(&packet);
    pHeader = DirectGate_Proto_BuildResize(24, 80, 640, 480, 7);
    CHECK(pHeader != NULL, "build resize header");
    CHECK(build_packet(&packet, pHeader, NULL, 0, XFALSE) == 0,
        "build resize packet");
    CHECK(DirectGate_Package_Parse(&pkg, packet.pData, packet.nUsed),
        "parse resize packet");
    directgate_pkg_size_t *pSize = (directgate_pkg_size_t*)pkg.pPackage;
    CHECK(pkg.header.eType == DIRECTGATE_PKG_RESIZE, "resize packet type");
    CHECK(pSize != NULL && pSize->nRows == 24 && pSize->nCols == 80,
        "resize rows/cols");
    CHECK(pSize->nWidth == 640 && pSize->nHeight == 480,
        "resize xpixel/ypixel aliases");
    DirectGate_Package_Clear(&pkg);

    XByteBuffer_Reset(&packet);
    pHeader = DirectGate_Proto_BuildAuthKeyChallenge(
        "agent-pub", "agent-eph", "nonce", "challenge", "agent-sig", 77);
    CHECK(pHeader != NULL, "build auth key challenge");
    CHECK(build_packet(&packet, pHeader, NULL, 0, XFALSE) == 0,
        "build auth packet");
    CHECK(DirectGate_Package_Parse(&pkg, packet.pData, packet.nUsed),
        "parse auth packet");
    directgate_pkg_auth_t *pAuth = (directgate_pkg_auth_t*)pkg.pPackage;
    CHECK(pkg.header.eType == DIRECTGATE_PKG_AUTH, "auth packet type");
    CHECK(pAuth != NULL && strcmp(pAuth->pAction, "challenge") == 0,
        "auth action");
    CHECK(strcmp(pAuth->pMethod, "key") == 0, "auth method");
    CHECK(strcmp(pAuth->pAgentPub, "agent-pub") == 0, "auth agent pub");
    CHECK(strcmp(pAuth->pAgentEph, "agent-eph") == 0, "auth agent eph");
    CHECK(strcmp(pAuth->pChallenge, "challenge") == 0, "auth challenge");
    CHECK(strcmp(pAuth->pAgentSig, "agent-sig") == 0, "auth agent sig");
    DirectGate_Package_Clear(&pkg);

    XByteBuffer_Reset(&packet);
    pHeader = DirectGate_Proto_BuildAuthHello("device-1", "client-public", "nonce", 78);
    CHECK(pHeader != NULL, "build temporary share auth hello");
    XJSON_AddString(pHeader, "desktopShareId", "share-1");
    CHECK(build_packet(&packet, pHeader, NULL, 0, XFALSE) == 0,
        "build temporary share auth packet");
    CHECK(DirectGate_Package_Parse(&pkg, packet.pData, packet.nUsed),
        "parse temporary share auth packet");
    pAuth = (directgate_pkg_auth_t*)pkg.pPackage;
    CHECK(pAuth != NULL && pAuth->pDesktopShareId != NULL &&
        strcmp(pAuth->pDesktopShareId, "share-1") == 0,
        "temporary share id");
    DirectGate_Package_Clear(&pkg);

    XByteBuffer_Reset(&packet);
    pHeader = DirectGate_Proto_NewHeader("admin", 79);
    CHECK(pHeader != NULL, "build temporary share admin header");
    XJSON_AddString(pHeader, "action", "desktop-share-provision");
    XJSON_AddString(pHeader, "shareId", "share-1");
    XJSON_AddString(pHeader, "salt", "salt-1");
    XJSON_AddString(pHeader, "verifier", "verifier-1");
    XJSON_AddU32(pHeader, "ttlSeconds", 1800);
    CHECK(build_packet(&packet, pHeader, NULL, 0, XFALSE) == 0,
        "build temporary share admin packet");
    CHECK(DirectGate_Package_Parse(&pkg, packet.pData, packet.nUsed),
        "parse temporary share admin packet");
    directgate_pkg_admin_t *pAdmin = (directgate_pkg_admin_t*)pkg.pPackage;
    CHECK(pAdmin != NULL && strcmp(pAdmin->pShareId, "share-1") == 0,
        "temporary share provision id");
    CHECK(strcmp(pAdmin->pSalt, "salt-1") == 0 &&
        strcmp(pAdmin->pVerifier, "verifier-1") == 0,
        "temporary share SRP verifier fields");
    CHECK(pAdmin->nTtlSeconds == 1800, "temporary share TTL");
    DirectGate_Package_Clear(&pkg);

    XByteBuffer_Reset(&packet);
    pHeader = DirectGate_Proto_BuildManager("search", "ok", "/tmp", NULL, 88);
    CHECK(pHeader != NULL, "build manager header");
    XJSON_AddString(pHeader, "fileName", "*.c");
    XJSON_AddString(pHeader, "text", "needle");
    XJSON_AddBool(pHeader, "recursive", XTRUE);
    XJSON_AddBool(pHeader, "insensitive", XTRUE);
    XJSON_AddBool(pHeader, "matchOnly", XTRUE);
    CHECK(build_packet(&packet, pHeader, NULL, 0, XFALSE) == 0,
        "build manager packet");
    CHECK(DirectGate_Package_Parse(&pkg, packet.pData, packet.nUsed),
        "parse manager packet");
    directgate_pkg_manager_t *pMgr = (directgate_pkg_manager_t*)pkg.pPackage;
    CHECK(pkg.header.eType == DIRECTGATE_PKG_MANAGER, "manager packet type");
    CHECK(pMgr != NULL && strcmp(pMgr->pAction, "search") == 0,
        "manager action");
    CHECK(strcmp(pMgr->pPath, "/tmp") == 0, "manager path");
    CHECK(strcmp(pMgr->pFileName, "*.c") == 0, "manager file name");
    CHECK(strcmp(pMgr->pText, "needle") == 0, "manager text");
    CHECK(pMgr->bRecursive && pMgr->bInsensitive && pMgr->bMatchOnly,
        "manager boolean flags");
    DirectGate_Package_Clear(&pkg);

    XByteBuffer_Reset(&packet);
    pHeader = DirectGate_Proto_BuildFileStart(
        "transfer-1", "big.bin", 4294967301ULL, 3, 1024);
    CHECK(pHeader != NULL, "build file start");
    CHECK(build_packet(&packet, pHeader, NULL, 0, XFALSE) == 0,
        "build file start packet");
    CHECK(DirectGate_Package_Parse(&pkg, packet.pData, packet.nUsed),
        "parse file start packet");
    directgate_pkg_file_t *pFile = (directgate_pkg_file_t*)pkg.pPackage;
    CHECK(pkg.header.eType == DIRECTGATE_PKG_FILE, "file packet type");
    CHECK(pFile != NULL && strcmp(pFile->pAction, "start") == 0,
        "file start action");
    CHECK(strcmp(pFile->transfer.pTransferId, "transfer-1") == 0,
        "file transfer id");
    CHECK(strcmp(pFile->transfer.pFileName, "big.bin") == 0,
        "file name");
    CHECK(pFile->transfer.nFileSize == 4294967301ULL,
        "file uint64 size");
    CHECK(pFile->transfer.nChunks == 3 && pFile->transfer.nChunkSize == 1024,
        "file chunk metadata");
    DirectGate_Package_Clear(&pkg);

    XByteBuffer_Reset(&packet);
    pHeader = DirectGate_Proto_BuildVerify(
        "ack", "access-token", "request-1", 4294967305ULL, "ok", NULL);
    CHECK(pHeader != NULL, "build verify header");
    CHECK(build_packet(&packet, pHeader, NULL, 0, XFALSE) == 0,
        "build verify packet");
    CHECK(DirectGate_Package_Parse(&pkg, packet.pData, packet.nUsed),
        "parse verify packet");
    directgate_pkg_verify_t *pVerify = (directgate_pkg_verify_t*)pkg.pPackage;
    CHECK(pkg.header.eType == DIRECTGATE_PKG_VERIFY, "verify packet type");
    CHECK(pVerify != NULL && strcmp(pVerify->pAction, "ack") == 0,
        "verify action");
    CHECK(strcmp(pVerify->pAccessToken, "access-token") == 0,
        "verify token");
    CHECK(strcmp(pVerify->pRequestId, "request-1") == 0,
        "verify request id");
    CHECK(pVerify->nExp == 4294967305ULL, "verify uint64 exp");
    DirectGate_Package_Clear(&pkg);

    memset(&pkg, 0, sizeof(pkg));
    CHECK(DirectGate_Proto_BindInnerSessionId(42, &pkg),
        "inner session id should inherit outer id");
    CHECK(pkg.header.nSessionId == 42,
        "inner session id should be bound to outer id");
    CHECK(DirectGate_Proto_BindInnerSessionId(42, &pkg),
        "matching inner and outer session ids should pass");
    CHECK(!DirectGate_Proto_BindInnerSessionId(43, &pkg),
        "mismatched inner and outer session ids should fail");
    memset(&pkg, 0, sizeof(pkg));
    CHECK(!DirectGate_Proto_BindInnerSessionId(0, &pkg),
        "encrypted outer session id must be present");

    XByteBuffer_Reset(&packet);
    pHeader = DirectGate_Proto_NewHeader("unknown", 1);
    CHECK(pHeader != NULL, "build unknown header");
    CHECK(build_packet(&packet, pHeader, NULL, 0, XFALSE) == 0,
        "build unknown packet");
    CHECK(!DirectGate_Package_Parse(&pkg, packet.pData, packet.nUsed),
        "unknown packet type must fail");

    XByteBuffer_Clear(&packet);
    puts("protocol_smoke: OK");
    return 0;
}
