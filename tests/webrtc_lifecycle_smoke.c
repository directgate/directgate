#include <stdio.h>
#include <stdlib.h>
#include "src/common/webrtc.h"

static int calls;
static void destroy_from_callback(const uint8_t *data, size_t len, void *ctx)
{
    (void)data;
    (void)len;
    directgate_webrtc_t *rtc = ctx;
    calls++;
    DirectGate_WebRTC_Clear(rtc);
    free(rtc);
}

int main(void)
{
    directgate_webrtc_t *rtc = malloc(sizeof(*rtc));
    if (!rtc) return 1;
    DirectGate_WebRTC_Init(rtc);
    rtc->dataCb = destroy_from_callback;
    rtc->pDataCtx = rtc;
    for (int i = 0; i < 3; i++)
    {
        directgate_webrtc_event_t *event = calloc(1, sizeof(*event));
        if (!event) return 1;
        event->eType = DIRECTGATE_WEBRTC_DATA;
        event->nSourceID = -1;
        event->pNext = rtc->pQueueHead;
        rtc->pQueueHead = event;
    }
    DirectGate_WebRTC_ProcessQueue(rtc);
    if (calls != 1) return 1;
    puts("webrtc_lifecycle_smoke: OK");
    return 0;
}
