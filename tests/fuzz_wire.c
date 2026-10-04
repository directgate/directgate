/* libFuzzer entry point. All inputs are memory-only; no connection, process,
 * file transfer or platform capture is started. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "src/common/protocol.h"
#include "src/common/webrtc.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    xlog_init(NULL, 0, 0);
    return 0;
}

/* The routing parse against the full one: a packet it takes has to parse in full to the same header */
static void check_route(const uint8_t *data, size_t size)
{
    directgate_pkg_t route = {0};
    directgate_pkg_t full = {0};
    xbool_t parsed = DirectGate_Package_Parse(&full, data, size);

    if (DirectGate_Package_ParseRoute(&route, data, size) &&
        (!parsed || route.pPackage != NULL || route.header.eType != full.header.eType ||
         route.header.nSessionId != full.header.nSessionId || route.header.nPacketId != full.header.nPacketId ||
         route.header.nProtoVersion != full.header.nProtoVersion || strcmp(route.header.pType, full.header.pType))) abort();

    DirectGate_Package_Clear(&route);
    DirectGate_Package_Clear(&full);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!size) return 0;
    unsigned mode = *data++ % 6;
    size--;
    if (mode == 0)
    {
        xjson_t json = {0};
        if (XJSON_Parse(&json, NULL, (const char*)data, size))
        {
            size_t len;
            char *dump = XJSON_DumpObj(json.pRootObj, 0, &len);
            free(dump);
        }
        XJSON_Destroy(&json);
    }
    else if (mode == 1 || mode == 2)
    {
        if (mode == 1) check_route(data, size);
        else
        {
            uint8_t *packet = malloc(size + 4);
            if (!packet) return 0;
            uint32_t len = (uint32_t)size;
            for (int i = 0; i < 4; i++) packet[i] = (uint8_t)(len >> (8 * i));
            memcpy(packet + 4, data, size);
            check_route(packet, size + 4);
            free(packet);
        }
    }
    else if (mode == 3)
    {
        uint8_t *copy = malloc(size + 1);
        if (!copy) return 0;
        memcpy(copy, data, size);
        xws_frame_t frame = {0};
        (void)XWebFrame_ParseData(&frame, copy, size);
        XWebFrame_Clear(&frame);
        free(copy);
    }
    else if (mode == 4)
    {
        xbool_t keyframe;
        int lost;
        DirectGate_WebRTC_ParseRtcp(data, size, 42, &keyframe, &lost);
    }
    else
    {
        char *sdp = malloc(size + 1);
        if (!sdp) return 0;
        memcpy(sdp, data, size); sdp[size] = 0;
        uint8_t pt; char mid[64];
        (void)DirectGate_WebRTC_ParseRemoteOpus(sdp, &pt, mid, sizeof(mid));
        free(sdp);
    }
    return 0;
}
