/* Build -> serialize -> parse roundtrips for every protocol header
 * builder that protocol_smoke does not already cover, plus a battery of
 * malformed-wire cases. Package_Parse consumes bytes straight from the
 * relay, so it must reject anything inconsistent without crashing. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "src/common/protocol.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "protocol_builders_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#define STREQ(a, b) ((a) != NULL && strcmp((a), (b)) == 0)

/* Serialize the header (consuming it) and parse the wire bytes back */
static int roundtrip(directgate_pkg_t *pPkg, xbyte_buffer_t *pWire,
                     xjson_obj_t *pHeader, const uint8_t *pPayload, size_t nPayload)
{
    CHECK(pHeader != NULL, "builder returned NULL");

    XByteBuffer_Reset(pWire);
    xbool_t bOk = DirectGate_Proto_Build(pWire, pHeader, pPayload, nPayload, XFALSE);
    XJSON_FreeObject(pHeader);
    CHECK(bOk, "serialize package");

    CHECK(DirectGate_Package_Parse(pPkg, pWire->pData, pWire->nUsed),
        "parse package");

    return 0;
}

int main(void)
{
    xbyte_buffer_t wire;
    XByteBuffer_Init(&wire, XSTDNON, XFALSE);

    directgate_pkg_t pkg;
    memset(&pkg, 0, sizeof(pkg));

    /* ---- role ---- */
    CHECK(roundtrip(&pkg, &wire,
        DirectGate_Proto_BuildRole("agent", "dev-42"), NULL, 0) == 0, "role");
    CHECK(pkg.header.eType == DIRECTGATE_PKG_ROLE, "role type");
    {
        directgate_pkg_role_t *pRole = (directgate_pkg_role_t*)pkg.pPackage;
        CHECK(pRole != NULL && STREQ(pRole->pRole, "agent"), "role value");
        CHECK(STREQ(pRole->pDeviceId, "dev-42"), "role device id");
    }
    DirectGate_Package_Clear(&pkg);

    /* ---- error ---- */
    CHECK(roundtrip(&pkg, &wire,
        DirectGate_Proto_BuildError("session not found", 3), NULL, 0) == 0, "error");
    CHECK(pkg.header.eType == DIRECTGATE_PKG_ERROR, "error type");
    CHECK(pkg.header.nSessionId == 3, "error session id");
    {
        directgate_pkg_error_t *pErr = (directgate_pkg_error_t*)pkg.pPackage;
        CHECK(pErr != NULL && STREQ(pErr->pReason, "session not found"), "error reason");
    }
    DirectGate_Package_Clear(&pkg);

    /* ---- status ---- */
    CHECK(roundtrip(&pkg, &wire,
        DirectGate_Proto_BuildStatus("ready", 4), NULL, 0) == 0, "status");
    CHECK(pkg.header.eType == DIRECTGATE_PKG_STATUS, "status type");
    {
        directgate_pkg_status_t *pStatus = (directgate_pkg_status_t*)pkg.pPackage;
        CHECK(pStatus != NULL && STREQ(pStatus->pStatus, "ready"), "status value");
    }
    DirectGate_Package_Clear(&pkg);

    /* ---- keepalive ---- */
    CHECK(roundtrip(&pkg, &wire,
        DirectGate_Proto_BuildKeepalive("ping", 0), NULL, 0) == 0, "keepalive");
    CHECK(pkg.header.eType == DIRECTGATE_PKG_KEEPALIVE, "keepalive type");
    {
        directgate_pkg_keepalive_t *pKA = (directgate_pkg_keepalive_t*)pkg.pPackage;
        CHECK(pKA != NULL && STREQ(pKA->pAction, "ping"), "keepalive action");
    }
    DirectGate_Package_Clear(&pkg);

    /* ---- cmd ---- */
    CHECK(roundtrip(&pkg, &wire,
        DirectGate_Proto_BuildCmd("start", "ok", NULL, "terminal", 9), NULL, 0) == 0, "cmd");
    CHECK(pkg.header.eType == DIRECTGATE_PKG_CMD, "cmd type");
    {
        directgate_pkg_cmd_t *pCmd = (directgate_pkg_cmd_t*)pkg.pPackage;
        CHECK(pCmd != NULL && STREQ(pCmd->pAction, "start"), "cmd action");
        CHECK(STREQ(pCmd->pMode, "terminal"), "cmd mode");
    }
    DirectGate_Package_Clear(&pkg);

    /* ---- SRP auth handshake headers ---- */
    CHECK(roundtrip(&pkg, &wire,
        DirectGate_Proto_BuildAuthHello("dev-42", "0aff", "n0nce", 5), NULL, 0) == 0,
        "auth hello");
    CHECK(pkg.header.eType == DIRECTGATE_PKG_AUTH, "auth hello type");
    {
        directgate_pkg_auth_t *pAuth = (directgate_pkg_auth_t*)pkg.pPackage;
        CHECK(pAuth != NULL && STREQ(pAuth->pAction, "hello"), "auth hello action");
        CHECK(STREQ(pAuth->pDeviceId, "dev-42"), "auth hello device");
        CHECK(STREQ(pAuth->pA, "0aff"), "auth hello A");
        CHECK(STREQ(pAuth->pNonce, "n0nce"), "auth hello nonce");
    }
    DirectGate_Package_Clear(&pkg);

    CHECK(roundtrip(&pkg, &wire,
        DirectGate_Proto_BuildAuthChallenge("5a17", "0bff", "n0nce2", 2048, 5),
        NULL, 0) == 0, "auth challenge");
    {
        directgate_pkg_auth_t *pAuth = (directgate_pkg_auth_t*)pkg.pPackage;
        CHECK(pAuth != NULL && STREQ(pAuth->pSalt, "5a17"), "challenge salt");
        CHECK(STREQ(pAuth->pB, "0bff"), "challenge B");
        CHECK(pAuth->nSuite == 2048, "challenge suite");
    }
    DirectGate_Package_Clear(&pkg);

    CHECK(roundtrip(&pkg, &wire,
        DirectGate_Proto_BuildAuthProof("m1-proof", 5), NULL, 0) == 0, "auth proof");
    {
        directgate_pkg_auth_t *pAuth = (directgate_pkg_auth_t*)pkg.pPackage;
        CHECK(pAuth != NULL && STREQ(pAuth->pM1, "m1-proof"), "proof M1");
    }
    DirectGate_Package_Clear(&pkg);

    CHECK(roundtrip(&pkg, &wire,
        DirectGate_Proto_BuildAuthResult("ok", "m2-proof", NULL, 5), NULL, 0) == 0,
        "auth result");
    {
        directgate_pkg_auth_t *pAuth = (directgate_pkg_auth_t*)pkg.pPackage;
        CHECK(pAuth != NULL && STREQ(pAuth->pStatus, "ok"), "result status");
        CHECK(STREQ(pAuth->pM2, "m2-proof"), "result M2");
    }
    DirectGate_Package_Clear(&pkg);

    /* ---- key auth headers ---- */
    CHECK(roundtrip(&pkg, &wire,
        DirectGate_Proto_BuildAuthKeyHello("dev-42", "cpubB64", "cephB64", "ab12", 6),
        NULL, 0) == 0, "key hello");
    {
        directgate_pkg_auth_t *pAuth = (directgate_pkg_auth_t*)pkg.pPackage;
        CHECK(pAuth != NULL && STREQ(pAuth->pMethod, "key"), "key hello method");
        CHECK(STREQ(pAuth->pClientPub, "cpubB64"), "key hello client pub");
        CHECK(STREQ(pAuth->pClientEph, "cephB64"), "key hello client eph");
    }
    DirectGate_Package_Clear(&pkg);

    CHECK(roundtrip(&pkg, &wire,
        DirectGate_Proto_BuildAuthKeyProof("sigB64", 6), NULL, 0) == 0, "key proof");
    {
        directgate_pkg_auth_t *pAuth = (directgate_pkg_auth_t*)pkg.pPackage;
        CHECK(pAuth != NULL && STREQ(pAuth->pClientSig, "sigB64"), "key proof sig");
    }
    DirectGate_Package_Clear(&pkg);

    /* ---- admin ---- */
    CHECK(roundtrip(&pkg, &wire,
        DirectGate_Proto_BuildAdmin("addkey", "cpubB64", "ok", NULL, 8), NULL, 0) == 0,
        "admin");
    CHECK(pkg.header.eType == DIRECTGATE_PKG_ADMIN, "admin type");
    {
        directgate_pkg_admin_t *pAdmin = (directgate_pkg_admin_t*)pkg.pPackage;
        CHECK(pAdmin != NULL && STREQ(pAdmin->pAction, "addkey"), "admin action");
        CHECK(STREQ(pAdmin->pClientPub, "cpubB64"), "admin client pub");
        CHECK(STREQ(pAdmin->pStatus, "ok"), "admin status");
    }
    DirectGate_Package_Clear(&pkg);

    /* ---- file ack / cancel ---- */
    CHECK(roundtrip(&pkg, &wire,
        DirectGate_Proto_BuildFileAck("tid-1", 12), NULL, 0) == 0, "file ack");
    CHECK(pkg.header.eType == DIRECTGATE_PKG_FILE, "file ack type");
    {
        directgate_pkg_file_t *pFile = (directgate_pkg_file_t*)pkg.pPackage;
        CHECK(pFile != NULL && STREQ(pFile->transfer.pTransferId, "tid-1"), "ack tid");
        CHECK(pFile->transfer.nChunkIndex == 12, "ack chunk index");
    }
    DirectGate_Package_Clear(&pkg);

    CHECK(roundtrip(&pkg, &wire,
        DirectGate_Proto_BuildFileCancel("tid-1", "user abort"), NULL, 0) == 0,
        "file cancel");
    DirectGate_Package_Clear(&pkg);

    /* ---- manager package with the full criteria set ---- */
    {
        xjson_obj_t *pHeader = DirectGate_Proto_BuildManager("search", NULL, "/tmp", NULL, 2);
        CHECK(pHeader != NULL, "manager header");
        XJSON_AddString(pHeader, "fileName", "*.log");
        XJSON_AddString(pHeader, "text", "error");
        XJSON_AddBool(pHeader, "recursive", XTRUE);
        XJSON_AddBool(pHeader, "insensitive", XTRUE);

        CHECK(roundtrip(&pkg, &wire, pHeader, NULL, 0) == 0, "manager");
        CHECK(pkg.header.eType == DIRECTGATE_PKG_MANAGER, "manager type");

        directgate_pkg_manager_t *pMgr = (directgate_pkg_manager_t*)pkg.pPackage;
        CHECK(pMgr != NULL && STREQ(pMgr->pAction, "search"), "manager action");
        CHECK(STREQ(pMgr->pPath, "/tmp"), "manager path");
        CHECK(STREQ(pMgr->pFileName, "*.log"), "manager file name");
        CHECK(STREQ(pMgr->pText, "error"), "manager text");
        CHECK(pMgr->bRecursive == XTRUE, "manager recursive");
        CHECK(pMgr->bInsensitive == XTRUE, "manager insensitive");
        DirectGate_Package_Clear(&pkg);
    }

    /* ---- malformed wire: must be rejected, never crash ---- */

    /* Keep one valid packet around to mutate */
    xjson_obj_t *pHeader = DirectGate_Proto_BuildStatus("ready", 1);
    CHECK(pHeader != NULL, "mutation base header");
    XByteBuffer_Reset(&wire);
    CHECK(DirectGate_Proto_Build(&wire, pHeader, (const uint8_t*)"x", 1, XFALSE),
        "mutation base build");
    XJSON_FreeObject(pHeader);

    /* Truncations at every interesting boundary */
    CHECK(!DirectGate_Package_Parse(&pkg, wire.pData, 0), "empty wire");
    CHECK(!DirectGate_Package_Parse(&pkg, wire.pData, 1), "one byte wire");
    CHECK(!DirectGate_Package_Parse(&pkg, wire.pData, DIRECTGATE_PROTO_PREAMBLE_SIZE - 1),
        "truncated preamble");
    CHECK(!DirectGate_Package_Parse(&pkg, wire.pData, DIRECTGATE_PROTO_PREAMBLE_SIZE),
        "preamble only");
    CHECK(!DirectGate_Package_Parse(&pkg, wire.pData, DIRECTGATE_PROTO_PREAMBLE_SIZE + 5),
        "truncated header");

    /* Header length claiming more bytes than the buffer holds */
    {
        uint8_t sOversize[16];
        memset(sOversize, 0, sizeof(sOversize));
        sOversize[0] = 0xff;
        sOversize[1] = 0xff;
        sOversize[2] = 0xff;
        sOversize[3] = 0x7f;
        CHECK(!DirectGate_Package_Parse(&pkg, sOversize, sizeof(sOversize)),
            "oversized header length");
    }

    /* Valid length prefix but garbage instead of a JSON header */
    {
        uint8_t sGarbage[12];
        memset(sGarbage, 0, sizeof(sGarbage));
        sGarbage[0] = 8; /* nHdrLen = 8 */
        memcpy(&sGarbage[4], "notjson!", 8);
        CHECK(!DirectGate_Package_Parse(&pkg, sGarbage, sizeof(sGarbage)),
            "non-JSON header");
    }

    /* Valid JSON header with an unknown type string */
    {
        const char *pJson = "{\"type\":\"no-such-type\",\"version\":1,\"sessionId\":1}";
        size_t nJsonLen = strlen(pJson);

        xbyte_buffer_t bad;
        XByteBuffer_Init(&bad, XSTDNON, XFALSE);
        uint8_t sPre[4] = { (uint8_t)nJsonLen, 0, 0, 0 };
        CHECK(XByteBuffer_Add(&bad, sPre, 4) > 0, "unknown-type preamble");
        CHECK(XByteBuffer_Add(&bad, (const uint8_t*)pJson, nJsonLen) > 0,
            "unknown-type header");
        CHECK(!DirectGate_Package_Parse(&pkg, bad.pData, bad.nUsed),
            "unknown package type rejected");
        XByteBuffer_Clear(&bad);
    }

    /* Zero-length header */
    {
        uint8_t sZero[8];
        memset(sZero, 0, sizeof(sZero));
        CHECK(!DirectGate_Package_Parse(&pkg, sZero, sizeof(sZero)),
            "zero header length");
    }

    XByteBuffer_Clear(&wire);

    puts("protocol_builders_smoke: OK");
    return 0;
}
