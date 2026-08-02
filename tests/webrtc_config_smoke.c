#include <stdio.h>
#include <string.h>

#include "src/common/webrtc.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "webrtc_config_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

int main(void)
{
    directgate_ice_server_t invalidServers[DIRECTGATE_MAX_ICE_SERVERS];
    uint8_t nInvalidCount = 99;
    CHECK(!DirectGate_WebRTC_LoadIceServers(NULL, &nInvalidCount, NULL),
        "load ICE rejects NULL servers");
    CHECK(!DirectGate_WebRTC_LoadIceServers(invalidServers, NULL, NULL),
        "load ICE rejects NULL count");

    const char *pCustomJson =
        "{"
            "\"iceServers\":["
                "\"turn:one.example.test\","
                "\"stun:two.example.test\","
                "\"turn:three.example.test\","
                "\"stun:four.example.test\","
                "\"turn:five.example.test\","
                "\"stun:six.example.test\","
                "\"turn:seven.example.test\","
                "\"stun:eight.example.test\","
                "\"turn:nine.example.test\""
            "]"
        "}";

    xjson_t json;
    CHECK(XJSON_Parse(&json, NULL, pCustomJson, strlen(pCustomJson)),
        "parse custom ICE JSON");

    directgate_ice_server_t servers[DIRECTGATE_MAX_ICE_SERVERS];
    uint8_t nCount = 0;
    CHECK(DirectGate_WebRTC_LoadIceServers(servers, &nCount, json.pRootObj),
        "load custom ICE servers");
    CHECK(nCount == DIRECTGATE_MAX_ICE_SERVERS, "custom ICE server cap");
    CHECK(strcmp(servers[0], "turn:one.example.test") == 0,
        "custom ICE first entry");
    CHECK(strcmp(servers[DIRECTGATE_MAX_ICE_SERVERS - 1], "stun:eight.example.test") == 0,
        "custom ICE eighth entry");
    XJSON_Destroy(&json);

    const char *pDefaultJson = "{}";
    CHECK(XJSON_Parse(&json, NULL, pDefaultJson, strlen(pDefaultJson)),
        "parse default ICE JSON");
    memset(servers, 0, sizeof(servers));
    nCount = 0;
    CHECK(DirectGate_WebRTC_LoadIceServers(servers, &nCount, json.pRootObj),
        "load default ICE servers");
    CHECK(nCount == 2, "default ICE server count");
    CHECK(strcmp(servers[0], "stun:stun.cloudflare.com:3478") == 0,
        "default ICE first entry");
    CHECK(strcmp(servers[1], "stun:stun.l.google.com:19302") == 0,
        "default ICE second entry");
    XJSON_Destroy(&json);

    directgate_webrtc_t rtc;
    DirectGate_WebRTC_Init(&rtc);

    directgate_ice_server_t configured[3];
    memset(configured, 0, sizeof(configured));
    xstrncpy(configured[0], sizeof(configured[0]), "turn:configured.example.test");
    configured[1][0] = '\0';
    xstrncpy(configured[2], sizeof(configured[2]), "stun:configured.example.test");
    DirectGate_WebRTC_SetIceServers(&rtc, configured, 3);

    CHECK(rtc.nIceSrvCount == 2, "set ICE skips empty entries");
    CHECK(strcmp(rtc.sIceServers[0], "turn:configured.example.test") == 0,
        "set ICE first entry");
    CHECK(strcmp(rtc.sIceServers[1], "stun:configured.example.test") == 0,
        "set ICE second entry");

    directgate_ice_server_t tcpConfigured[2];
    memset(tcpConfigured, 0, sizeof(tcpConfigured));
    xstrncpy(tcpConfigured[0], sizeof(tcpConfigured[0]),
        "turn:relay.example.test:3478?transport=tcp");
    xstrncpy(tcpConfigured[1], sizeof(tcpConfigured[1]),
        "turn:relay.example.test:3478?transport=udp");
    DirectGate_WebRTC_SetIceServers(&rtc, tcpConfigured, 2);
    CHECK(rtc.nIceSrvCount == 1 &&
          strcmp(rtc.sIceServers[0], tcpConfigured[1]) == 0,
        "TCP ICE filtered by default");
    rtc.bAllowTCP = XTRUE;
    DirectGate_WebRTC_SetIceServers(&rtc, tcpConfigured, 2);
    CHECK(rtc.nIceSrvCount == 2, "TCP ICE allowed when configured");
    DirectGate_WebRTC_Clear(&rtc);

    // BYO-shape URLs: longer creds, turns:, ?transport=tcp, plus stun colocation.
    const char *pByoJson =
        "{"
            "\"iceServers\":["
                "\"stun:stun.cloudflare.com:3478\","
                "\"stun:stun.l.google.com:19302\","
                "\"turn:alice:supers3cret-credential-that-is-fairly-long@relay.example.com:3478?transport=udp\","
                "\"turns:alice:supers3cret-credential-that-is-fairly-long@relay.example.com:5349?transport=tcp\""
            "]"
        "}";
    CHECK(XJSON_Parse(&json, NULL, pByoJson, strlen(pByoJson)),
        "parse BYO ICE JSON");
    memset(servers, 0, sizeof(servers));
    nCount = 0;
    CHECK(DirectGate_WebRTC_LoadIceServers(servers, &nCount, json.pRootObj),
        "load BYO ICE servers");
    CHECK(nCount == 4, "BYO ICE server count");
    CHECK(strcmp(servers[0], "stun:stun.cloudflare.com:3478") == 0,
        "BYO first stun");
    CHECK(strcmp(servers[2], "turn:alice:supers3cret-credential-that-is-fairly-long@relay.example.com:3478?transport=udp") == 0,
        "BYO turn url");
    CHECK(strcmp(servers[3], "turns:alice:supers3cret-credential-that-is-fairly-long@relay.example.com:5349?transport=tcp") == 0,
        "BYO turns url");
    XJSON_Destroy(&json);

    /* Remote ICE candidate transport detection. ICE-TCP is disabled on our
     * peer connections, so TCP candidates can never form a pair and must not
     * be allowed to occupy slots in libjuice's fixed remote description. */
    CHECK(!DirectGate_WebRTC_IsTcpCandidate(
        "candidate:1 1 udp 2122260223 192.168.1.10 54321 typ host"),
        "plain UDP host candidate treated as TCP");
    CHECK(!DirectGate_WebRTC_IsTcpCandidate(
        "a=candidate:2 1 UDP 1686052607 203.0.113.7 41234 typ srflx raddr 192.168.1.10 rport 54321"),
        "uppercase UDP with a= prefix treated as TCP");
    CHECK(DirectGate_WebRTC_IsTcpCandidate(
        "candidate:3 1 tcp 1518280447 192.168.1.10 9 typ host tcptype active"),
        "TCP host candidate not detected");
    CHECK(DirectGate_WebRTC_IsTcpCandidate(
        "a=candidate:4 1 TCP 847249919 203.0.113.9 3478 typ relay raddr 0.0.0.0 rport 0 tcptype passive"),
        "TURN/TCP relay candidate not detected");
    /* Anything unreadable is forwarded rather than dropped: libjuice is the
     * authority on candidate syntax and refuses a malformed line before it can
     * occupy a slot, whereas dropping one here could cost a working route. */
    CHECK(!DirectGate_WebRTC_IsTcpCandidate("candidate:5 1"),
        "truncated candidate must be forwarded, not dropped");
    CHECK(!DirectGate_WebRTC_IsTcpCandidate(""),
        "empty candidate must be forwarded, not dropped");

    puts("webrtc_config_smoke: OK");
    return 0;
}
