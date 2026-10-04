#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "src/common/protocol.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "protocol_route_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

/* DirectGate_Package_ParseRoute against DirectGate_Package_Parse on the same bytes. A packet the routing parse takes
   must parse in full to the same header, with nothing in it that the routing parse leaves out; *pRouted says which. */
static int route_agrees(const uint8_t *pData, size_t nSize, int *pRouted)
{
    directgate_pkg_t route;
    directgate_pkg_t full;

    xbool_t bRouted = DirectGate_Package_ParseRoute(&route, pData, nSize);
    xbool_t bParsed = DirectGate_Package_Parse(&full, pData, nSize);
    int nAgrees = 1;

    *pRouted = bRouted ? 1 : 0;
    if (bRouted)
    {
        if (!bParsed || route.pPackage != NULL || route.jsonHeader.pRootObj != NULL || route.header.eType != full.header.eType ||
            route.header.nSessionId != full.header.nSessionId || route.header.nProtoVersion != full.header.nProtoVersion ||
            route.header.nPacketId != full.header.nPacketId || strcmp(route.header.pType, full.header.pType)) nAgrees = 0;

        if (route.header.eType != DIRECTGATE_PKG_ENCRYPTED && route.header.eType != DIRECTGATE_PKG_WEBRTC &&
            route.header.eType != DIRECTGATE_PKG_RESIZE && route.header.eType != DIRECTGATE_PKG_STATUS) nAgrees = 0;

        DirectGate_Package_Clear(&route);
    }

    if (bParsed) DirectGate_Package_Clear(&full);
    return nAgrees;
}

static size_t raw_packet(uint8_t *pOut, size_t nSize, const char *pHeader, const char *pBody)
{
    size_t nHeader = strlen(pHeader);
    size_t nBody = pBody != NULL ? strlen(pBody) : 0;
    if (4 + nHeader + nBody > nSize) return 0;

    for (int i = 0; i < 4; i++) pOut[i] = (uint8_t)(nHeader >> (8 * i));
    memcpy(pOut + 4, pHeader, nHeader);
    if (nBody) memcpy(pOut + 4 + nHeader, pBody, nBody);
    return 4 + nHeader + nBody;
}

int main(void)
{
    uint8_t packet[512];
    int nRouted = 0;

    /* What the agent and the browser actually send is taken, and read as the full parse reads it */
    xbyte_buffer_t built;
    XByteBuffer_Init(&built, XSTDNON, XFALSE);

    const uint8_t sCipher[48] = { 1, 2, 3 };
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("encrypted", 77);
    CHECK(pHeader != NULL && DirectGate_Proto_Build(&built, pHeader, sCipher, sizeof(sCipher), XFALSE),
        "an encrypted packet is built the way the agent builds it");
    XJSON_FreeObject(pHeader);

    directgate_pkg_t pkg;
    CHECK(DirectGate_Package_ParseRoute(&pkg, built.pData, built.nUsed), "the agent's encrypted packet is routed");
    CHECK(pkg.header.eType == DIRECTGATE_PKG_ENCRYPTED && pkg.header.nSessionId == 77 &&
        pkg.header.nProtoVersion == DIRECTGATE_PROTOCOL_VERSION && !strcmp(pkg.header.pType, "encrypted"),
        "its type, session and version are read from the header");
    CHECK(pkg.pPackage == NULL, "nothing past the header is built");
    DirectGate_Package_Clear(&pkg);
    CHECK(route_agrees(built.pData, built.nUsed, &nRouted) && nRouted, "the full parse reads the same header");

    size_t nLength = raw_packet(packet, sizeof(packet), "{\"type\":\"encrypted\",\"sessionId\":9,\"payloadSize\":5}", "hello");
    CHECK(route_agrees(packet, nLength, &nRouted) && nRouted, "the browser's encrypted envelope is routed");

    const char *pRouted[] = { "{\"type\":\"webrtc\",\"action\":\"offer\",\"sessionId\":3,\"sdp\":\"v=0\\r\\n\",\"cc\":12}",
        "{\"type\":\"resize\",\"sessionId\":3,\"cols\":80,\"rows\":24}",
        "{\"type\":\"status\",\"status\":\"closed\",\"sessionId\":3}",
        " {\"version\" : 1 , \"type\" : \"encrypted\" , \"sessionId\" : 4294967295 }\n" };

    for (size_t i = 0; i < sizeof(pRouted) / sizeof(*pRouted); i++)
    {
        nLength = raw_packet(packet, sizeof(packet), pRouted[i], NULL);
        CHECK(route_agrees(packet, nLength, &nRouted) && nRouted, "each forwarded type is routed by its header");
    }

    /* Everything that needs its own fields read, or would fail, goes to the full parse */
    const char *pDeclined[] = { "{\"type\":\"auth\",\"action\":\"hello\",\"sessionId\":3}",
        "{\"type\":\"cmd\",\"action\":\"start\"}",
        "{\"type\":\"role\",\"role\":\"agent\"}", "{\"type\":\"verify\",\"action\":\"update\"}", "{\"type\":\"data\"}",
        "{\"type\":\"file\",\"action\":\"start\"}", "{\"type\":\"teleport\"}", "{\"sessionId\":3}", "{\"type\":5}",
        "{\"type\":\"encr\\u0079pted\"}", "{\"type\":\"encrypted\",\"meta\":{}}", "{\"type\":\"encrypted\",\"a\":[]}",
        "{\"type\":\"encrypted\",\"type\":\"encrypted\"}", "{\"type\":\"encrypted\"} x", "{\"type\":\"encrypted\",}",
        "[\"encrypted\"]", "{\"type\":\"encrypted\",\"payloadSize\":1}" };

    for (size_t i = 0; i < sizeof(pDeclined) / sizeof(*pDeclined); i++)
    {
        nLength = raw_packet(packet, sizeof(packet), pDeclined[i], NULL);
        CHECK(route_agrees(packet, nLength, &nRouted) && !nRouted, "a packet that needs more is left to the full parse");
    }

    /* The payload bound: an encrypted packet that announces more than it carries is not routed, nor parsed */
    nLength = raw_packet(packet, sizeof(packet), "{\"type\":\"encrypted\",\"sessionId\":1,\"payloadSize\":6}", "hello");
    CHECK(route_agrees(packet, nLength, &nRouted) && !nRouted, "a truncated payload is refused");
    nLength = raw_packet(packet, sizeof(packet), "{\"type\":\"encrypted\",\"sessionId\":1,\"payloadSize\":4294967296}", "hello");
    CHECK(route_agrees(packet, nLength, &nRouted) && nRouted, "a size that does not fit 32 bits reads as none, as in full");
    nLength = raw_packet(packet, sizeof(packet), "{\"type\":\"webrtc\",\"sessionId\":1,\"payloadSize\":4096}", NULL);
    CHECK(route_agrees(packet, nLength, &nRouted) && nRouted, "only an encrypted packet has its payload bounded");

    /* Numbers are read the way XJSON_GetU32 reads them */
    const char *pNumbers[] = { "-1", "-0", "1.0", "1e2", "\"7\"", "4294967295", "4294967296", "4294967297", "99999999999",
        "18446744073709551617", "184467440737095516170", "null", "true", "0" };
    for (size_t i = 0; i < sizeof(pNumbers) / sizeof(*pNumbers); i++)
    {
        char sHeader[128];
        snprintf(sHeader, sizeof(sHeader), "{\"type\":\"webrtc\",\"sessionId\":%s,\"cc\":%s}", pNumbers[i], pNumbers[i]);
        nLength = raw_packet(packet, sizeof(packet), sHeader, NULL);
        CHECK(route_agrees(packet, nLength, &nRouted) && nRouted, "every number form agrees with the full parse");
    }

    /* The header length in the preamble is checked before anything is read */
    CHECK(!DirectGate_Package_ParseRoute(&pkg, built.pData, 3), "a packet shorter than its preamble is refused");
    memcpy(packet, built.pData, built.nUsed);
    packet[0] = packet[1] = packet[2] = packet[3] = 0xff;
    CHECK(route_agrees(packet, built.nUsed, &nRouted) && !nRouted, "a header longer than the packet is refused");
    packet[0] = packet[1] = packet[2] = packet[3] = 0;
    CHECK(route_agrees(packet, built.nUsed, &nRouted) && !nRouted, "an empty header is refused");
    CHECK(!DirectGate_Package_ParseRoute(NULL, built.pData, built.nUsed) &&
        !DirectGate_Package_ParseRoute(&pkg, NULL, built.nUsed), "missing arguments are refused");

    /* Every cut of a real packet, then seeded mutations of it: the two parses agree on all of them */
    for (size_t i = 0; i < built.nUsed; i++)
        CHECK(route_agrees(built.pData, i, &nRouted), "the two parses agree on every cut of a packet");

    const char sAlphabet[] = "{}[]:,\"\\ 0123456789-.eE\x01tyencrypdsoIwbz";
    uint32_t nState = 0x9E3779B9;
    int nTaken = 0;

    for (int nRound = 0; nRound < 20000; nRound++)
    {
        size_t nUsed = built.nUsed;
        memcpy(packet, built.pData, nUsed);

        for (int nEdit = 0; nEdit < 1 + nRound % 3; nEdit++)
        {
            nState = nState * 1664525u + 1013904223u;
            size_t nAt = 4 + (nState >> 8) % (nUsed - 4);
            packet[nAt] = (uint8_t)sAlphabet[(nState >> 20) % (sizeof(sAlphabet) - 1)];
        }

        if (!route_agrees(packet, nUsed, &nRouted))
        {
            fprintf(stderr, "protocol_route_smoke: the parses disagree on: %.*s\n", (int)(nUsed - 4), packet + 4);
            return 1;
        }

        nTaken += nRouted;
    }

    CHECK(nTaken > 500, "enough mutations stayed routable for the comparison to mean something");
    XByteBuffer_Clear(&built);

    puts("protocol_route_smoke: OK");
    return 0;
}
