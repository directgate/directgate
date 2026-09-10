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
        directgate_pkg_t pkg = {0};
        if (mode == 1) (void)DirectGate_Package_Parse(&pkg, data, size);
        else
        {
            uint8_t *packet = malloc(size + 4);
            if (!packet) return 0;
            uint32_t len = (uint32_t)size;
            for (int i = 0; i < 4; i++) packet[i] = (uint8_t)(len >> (8 * i));
            memcpy(packet + 4, data, size);
            (void)DirectGate_Package_Parse(&pkg, packet, size + 4);
            DirectGate_Package_Clear(&pkg);
            free(packet);
            return 0;
        }
        DirectGate_Package_Clear(&pkg);
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
