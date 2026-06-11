/* End-to-end encrypted package pipeline: the exact path every terminal
 * byte and file chunk takes between agent and client.
 *
 *   inner package (+cc) -> Proto_Build -> Proto_EncryptPackage -> wire
 *   wire -> Package_Parse -> Proto_DecryptPackage (cc check) -> inner
 *
 * Locks the replay protection (strictly increasing per-direction packet
 * counter), tamper rejection, the missing-counter policy and the inner
 * session-id binding rules. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "src/common/protocol.h"
#include "src/common/e2e.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "proto_crypt_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#define SESSION_ID 7U

static void fill_range(uint8_t *pData, size_t nLen, uint8_t nStart)
{
    for (size_t i = 0; i < nLen; i++)
        pData[i] = (uint8_t)(nStart + i);
}

/* Build inner data package and encrypt it the way term.c does */
static int build_encrypted(xbyte_buffer_t *pWire, directgate_e2e_t *pTx,
                           const uint8_t *pPayload, size_t nPayload,
                           xbool_t bAddCC)
{
    xjson_obj_t *pHeader = DirectGate_Proto_BuildData(SESSION_ID);
    CHECK(pHeader != NULL, "build inner header");

    if (bAddCC)
        XJSON_AddU32(pHeader, "cc", ++pTx->nTxPacketId);

    XByteBuffer_Reset(pWire);
    xbool_t bOk = DirectGate_Proto_Build(pWire, pHeader, pPayload, nPayload, XFALSE);
    XJSON_FreeObject(pHeader);
    CHECK(bOk, "build inner package");

    CHECK(DirectGate_Proto_EncryptPackage(pWire, pTx, SESSION_ID),
        "encrypt package");

    return 0;
}

/* Parse + decrypt one wire buffer; returns 0 and the inner plaintext */
static int decrypt_wire(const xbyte_buffer_t *pWire, directgate_e2e_t *pRx,
                        xbyte_buffer_t *pInner, xbool_t bExpectOk)
{
    directgate_pkg_t pkg;
    CHECK(DirectGate_Package_Parse(&pkg, pWire->pData, pWire->nUsed),
        "parse outer package");
    CHECK(pkg.header.eType == DIRECTGATE_PKG_ENCRYPTED, "outer type encrypted");
    CHECK(pkg.header.nSessionId == SESSION_ID, "outer session id");

    xbool_t bOk = DirectGate_Proto_DecryptPackage(pInner, &pkg, pRx);
    DirectGate_Package_Clear(&pkg);

    if (bExpectOk) CHECK(bOk, "decrypt package");
    else CHECK(!bOk, "decrypt must be rejected");

    return 0;
}

int main(void)
{
    uint8_t secret[32], agentNonce[32], clientNonce[32];
    fill_range(secret, sizeof(secret), 0x11);
    fill_range(agentNonce, sizeof(agentNonce), 0x55);
    fill_range(clientNonce, sizeof(clientNonce), 0x99);

    directgate_e2e_t agentE2E, clientE2E;
    DirectGate_E2E_Init(&agentE2E);
    DirectGate_E2E_Init(&clientE2E);

    CHECK(DirectGate_E2E_DeriveFromKey(&agentE2E, secret, sizeof(secret),
        agentNonce, clientNonce, sizeof(agentNonce), "proto-dev", 1),
        "derive agent E2E");
    CHECK(DirectGate_E2E_DeriveFromKey(&clientE2E, secret, sizeof(secret),
        agentNonce, clientNonce, sizeof(agentNonce), "proto-dev", 0),
        "derive client E2E");

    const uint8_t payload[] = "ls -la /home\r\n";

    xbyte_buffer_t wire, replayCopy, inner;
    XByteBuffer_Init(&wire, XSTDNON, XFALSE);
    XByteBuffer_Init(&replayCopy, XSTDNON, XFALSE);
    XByteBuffer_Init(&inner, XSTDNON, XFALSE);

    /* ---- happy path roundtrip ---- */
    CHECK(build_encrypted(&wire, &agentE2E, payload, sizeof(payload), XTRUE) == 0,
        "build encrypted packet");
    CHECK(XByteBuffer_Add(&replayCopy, wire.pData, wire.nUsed) > 0, "save replay copy");

    CHECK(decrypt_wire(&wire, &clientE2E, &inner, XTRUE) == 0, "roundtrip decrypt");

    directgate_pkg_t innerPkg;
    CHECK(DirectGate_Package_Parse(&innerPkg, inner.pData, inner.nUsed),
        "parse inner package");
    CHECK(innerPkg.header.eType == DIRECTGATE_PKG_DATA, "inner type data");
    CHECK(innerPkg.header.nSessionId == SESSION_ID, "inner session id");
    CHECK(innerPkg.header.nPacketId == 1, "inner packet counter");

    directgate_pkg_data_t *pData = (directgate_pkg_data_t*)innerPkg.pPackage;
    CHECK(pData != NULL && pData->nPayloadLength == sizeof(payload),
        "inner payload length");
    CHECK(memcmp(pData->pPayload, payload, sizeof(payload)) == 0,
        "inner payload bytes");

    /* BindInnerSessionId: equal ids bind, conflicting ids are rejected */
    CHECK(DirectGate_Proto_BindInnerSessionId(SESSION_ID, &innerPkg),
        "matching inner session id binds");
    CHECK(!DirectGate_Proto_BindInnerSessionId(SESSION_ID + 1, &innerPkg),
        "conflicting inner session id is rejected");

    innerPkg.header.nSessionId = 0;
    CHECK(DirectGate_Proto_BindInnerSessionId(SESSION_ID, &innerPkg) &&
          innerPkg.header.nSessionId == SESSION_ID,
        "zero inner session id inherits the outer one");

    DirectGate_Package_Clear(&innerPkg);

    /* ---- replay: the exact same wire bytes must be rejected (cc <= last) ---- */
    CHECK(decrypt_wire(&replayCopy, &clientE2E, &inner, XFALSE) == 0,
        "replayed packet rejected");

    /* ---- the next counter value goes through again ---- */
    CHECK(build_encrypted(&wire, &agentE2E, payload, sizeof(payload), XTRUE) == 0,
        "build second packet");
    CHECK(decrypt_wire(&wire, &clientE2E, &inner, XTRUE) == 0,
        "second packet accepted");

    /* ---- tamper: flip one ciphertext byte in the outer payload ---- */
    CHECK(build_encrypted(&wire, &agentE2E, payload, sizeof(payload), XTRUE) == 0,
        "build tamper packet");
    wire.pData[wire.nUsed - 1] ^= 0x01;
    CHECK(decrypt_wire(&wire, &clientE2E, &inner, XFALSE) == 0,
        "tampered packet rejected");

    /* ---- missing cc: encrypted packet without a counter is rejected ---- */
    CHECK(build_encrypted(&wire, &agentE2E, payload, sizeof(payload), XFALSE) == 0,
        "build counterless packet");
    CHECK(decrypt_wire(&wire, &clientE2E, &inner, XFALSE) == 0,
        "counterless packet rejected");

    /* ---- cross-direction: agent must not accept its own packets ---- */
    CHECK(build_encrypted(&wire, &agentE2E, payload, sizeof(payload), XTRUE) == 0,
        "build reflection packet");
    CHECK(decrypt_wire(&wire, &agentE2E, &inner, XFALSE) == 0,
        "reflected packet rejected at sender");

    /* ---- uninitialized E2E refuses to encrypt ---- */
    directgate_e2e_t coldE2E;
    DirectGate_E2E_Init(&coldE2E);
    XByteBuffer_Reset(&wire);
    CHECK(XByteBuffer_Add(&wire, payload, sizeof(payload)) > 0, "raw buffer");
    CHECK(!DirectGate_Proto_EncryptPackage(&wire, &coldE2E, SESSION_ID),
        "uninitialized E2E must refuse");

    XByteBuffer_Clear(&wire);
    XByteBuffer_Clear(&replayCopy);
    XByteBuffer_Clear(&inner);
    DirectGate_E2E_Clear(&agentE2E);
    DirectGate_E2E_Clear(&clientE2E);

    puts("proto_crypt_smoke: OK");
    return 0;
}
