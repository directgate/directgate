#include <stdio.h>
#include <string.h>
#include "src/common/webrtc.h"

typedef struct peer_ {
    directgate_webrtc_t rtc;
    struct peer_ *remote;
    int errors;
    int received;
} peer_t;

static void signal_peer(const char *data, size_t len, void *ctx)
{
    peer_t *peer = ctx;
    xjson_t json;
    if (!XJSON_Parse(&json, NULL, data, len)) { peer->errors++; return; }
    xjson_obj_t *root = json.pRootObj;
    const char *action = XJSON_GetString(XJSON_GetObject(root, "action"));
    const char *sdp = XJSON_GetString(XJSON_GetObject(root, "sdp"));
    int result = 0;
    if (xstrcmp(action, "offer"))
        result = DirectGate_WebRTC_HandleOffer(&peer->remote->rtc, sdp, 0, XFALSE);
    else if (xstrcmp(action, "answer"))
        result = DirectGate_WebRTC_HandleAnswer(&peer->remote->rtc, sdp);
    else if (xstrcmp(action, "ice"))
        result = DirectGate_WebRTC_HandleIceCandidate(&peer->remote->rtc,
            XJSON_GetString(XJSON_GetObject(root, "candidate")),
            XJSON_GetString(XJSON_GetObject(root, "sdpMid")), 0);
    if (result < 0) peer->errors++;
    XJSON_Destroy(&json);
}

static void receive(const uint8_t *data, size_t len, void *ctx)
{
    peer_t *peer = ctx;
    if (len != 4 || memcmp(data, "ping", 4)) peer->errors++;
    peer->received++;
}

int main(void)
{
    peer_t a = {0}, b = {0};
    DirectGate_WebRTC_Init(&a.rtc);
    DirectGate_WebRTC_Init(&b.rtc);
    a.remote = &b;
    b.remote = &a;
    a.rtc.signalCb = b.rtc.signalCb = signal_peer;
    a.rtc.dataCb = b.rtc.dataCb = receive;
    a.rtc.pSignalCtx = a.rtc.pDataCtx = &a;
    b.rtc.pSignalCtx = b.rtc.pDataCtx = &b;
    /* Host candidates only: no signaling server, STUN or TURN is needed. */
    int ok = DirectGate_WebRTC_CreateOffer(&a.rtc) == XSTDOK;
    for (int i = 0; ok && i < 1000; i++)
    {
        DirectGate_WebRTC_ProcessQueue(&a.rtc);
        DirectGate_WebRTC_ProcessQueue(&b.rtc);
        if (DirectGate_WebRTC_IsConnected(&a.rtc) && DirectGate_WebRTC_IsConnected(&b.rtc)) break;
        xusleep(10000);
    }
    ok = ok && DirectGate_WebRTC_IsConnected(&a.rtc) && DirectGate_WebRTC_IsConnected(&b.rtc);
    if (ok) ok = DirectGate_WebRTC_Send(&a.rtc, (const uint8_t *)"ping", 4) == XSTDOK &&
                 DirectGate_WebRTC_Send(&b.rtc, (const uint8_t *)"ping", 4) == XSTDOK;
    for (int i = 0; ok && i < 200 && (!a.received || !b.received); i++)
    {
        DirectGate_WebRTC_ProcessQueue(&a.rtc);
        DirectGate_WebRTC_ProcessQueue(&b.rtc);
        xusleep(10000);
    }
    ok = ok && a.received == 1 && b.received == 1 && !a.errors && !b.errors;
    DirectGate_WebRTC_Clear(&a.rtc);
    DirectGate_WebRTC_Clear(&b.rtc);
    DirectGate_WebRTC_Cleanup();
    if (!ok) { fprintf(stderr, "webrtc_peer_smoke: negotiation or bidirectional delivery failed\n"); return 1; }
    puts("webrtc_peer_smoke: OK");
    return 0;
}
