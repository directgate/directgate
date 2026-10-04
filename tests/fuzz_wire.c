/* libFuzzer entry point. All inputs are memory-only; no connection, process,
 * file transfer or platform capture is started. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "src/common/e2e.h"
#include "src/common/protocol.h"
#include "src/common/webrtc.h"

/* Messages are formatted and dropped: a log argument that points into freed memory is caught by ASan
   only when the message is actually written. */
static int discard_log(const char *pLog, size_t nLength, xlog_flag_t eFlag, void *pCtx)
{
    (void)pLog; (void)nLength; (void)eFlag; (void)pCtx;
    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    xlog_init(NULL, XLOG_ALL, 0);
    xlog_screen(XFALSE);
    xlog_callback(discard_log, NULL);
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

static xbool_t check_cc_once(const uint8_t *header, size_t size, const char *pad, size_t padLen, directgate_e2e_t *e2e)
{
    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, size + padLen + 5, XFALSE);
    uint32_t len = (uint32_t)(size + padLen);
    uint8_t preamble[4] = { (uint8_t)len, (uint8_t)(len >> 8), (uint8_t)(len >> 16), (uint8_t)(len >> 24) };

    /* The pad goes right behind the opening brace */
    size_t brace = 0;
    while (padLen && header[brace] != '{') brace++;

    XByteBuffer_Add(&packet, preamble, sizeof(preamble));
    XByteBuffer_Add(&packet, header, padLen ? brace + 1 : size);
    if (padLen)
    {
        XByteBuffer_Add(&packet, (const uint8_t*)pad, padLen);
        XByteBuffer_Add(&packet, header + brace + 1, size - brace - 1);
    }

    xbool_t accepted = DirectGate_Proto_CheckCC(&packet, e2e);
    XByteBuffer_Clear(&packet);
    return accepted;
}

/* CheckCC reads a flat header in place and parses anything else. With a nested member in front, which only
   the parser takes, a flat header has to get the same verdict twice over (the second time as a replay) and
   leave the windows exactly as the scan did. */
static void check_cc(const uint8_t *header, size_t size)
{
    directgate_e2e_t scanned, parsed;
    DirectGate_E2E_Init(&scanned);
    DirectGate_E2E_Init(&parsed);

    xjson_field_t field[1] = { { "~pad~", NULL, 0, 0 } };
    xbool_t flat = size && XJSON_ScanFlat((const char*)header, size, field, 1) && field[0].nType == XJSON_TYPE_INVALID;

    /* An empty object takes the member without a comma after it */
    const char *pad = "\"~pad~\":{},";
    if (flat)
    {
        size_t i = 0;
        while (header[i] != '{') i++;
        for (i++; header[i] == ' ' || header[i] == '\t' || header[i] == '\r' || header[i] == '\n'; i++);
        if (header[i] == '}') pad = "\"~pad~\":{}";
    }

    for (int round = 0; round < 2; round++)
    {
        xbool_t a = check_cc_once(header, size, NULL, 0, &scanned);
        xbool_t b = flat ? check_cc_once(header, size, pad, strlen(pad), &parsed) : check_cc_once(header, size, NULL, 0, &parsed);
        if (a != b || memcmp(&scanned, &parsed, sizeof(scanned))) abort();
    }
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
            check_cc(data, size);
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
