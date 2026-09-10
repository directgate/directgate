/* Exercise concurrent library callbacks without starting upstream transports. */
#include <stdio.h>
#include "src/common/webrtc.c"
#define PRODUCERS 4
#define MESSAGES 500
typedef struct { directgate_webrtc_t *rtc; unsigned id; xvolatile_t done; } producer_t;
static unsigned next[PRODUCERS], received;
static int failed;
static void receive(const uint8_t *data, size_t size, void *ctx)
{
    (void)ctx;
    unsigned message[2];
    if (size != sizeof(message)) { failed = 1; return; }
    memcpy(message, data, size);
    if (message[0] >= PRODUCERS || message[1] != next[message[0]]++) failed = 1;
    received++;
}
static void* produce(void *arg)
{
    producer_t *producer = arg;
    for (unsigned i = 0; i < MESSAGES; i++)
    {
        unsigned message[] = {producer->id, i};
        DirectGate_WebRTC_QueueDataChannelMessage(1000000, (const char*)message,
                                                  sizeof(message), producer->rtc);
        if (i % 20 == 0) xusleep(100);
    }
    XSYNC_ATOMIC_SET(&producer->done, 1);
    return NULL;
}
int main(void)
{
    directgate_webrtc_t rtc;
    DirectGate_WebRTC_Init(&rtc);
    rtc.nDataChannelID = 1000000;
    rtc.dataCb = receive;
    /* A wheel event must reach the application on this pipe wakeup, without
     * being queued again until another main-loop/capture iteration. */
    rtc.nInputDataChannelID = 1000001;
    unsigned input[] = {0, 0};
    DirectGate_WebRTC_QueueDataChannelMessage(rtc.nInputDataChannelID,
        (const char*)input, sizeof(input), &rtc);
    if (received) return 1; /* Library callbacks must not dispatch off-thread. */
    DirectGate_WebRTC_ProcessQueue(&rtc);
    if (failed || received != 1)
    {
        rtc.nInputDataChannelID = rtc.nDataChannelID = -1;
        DirectGate_WebRTC_Clear(&rtc);
        fprintf(stderr, "webrtc_queue_smoke: input was delayed past the first queue dispatch\n");
        return 1;
    }
    DirectGate_WebRTC_QueueDataChannelMessage(1000002, (const char*)input, sizeof(input), &rtc);
    DirectGate_WebRTC_ProcessQueue(&rtc);
    if (received != 1) return 1; /* Stale channels are still filtered on main. */
    rtc.nInputDataChannelID = -1;
    next[0] = received = 0;
    producer_t producers[PRODUCERS] = {0};
    xthread_t threads[PRODUCERS];
    for (unsigned i = 0; i < PRODUCERS; i++)
    {
        producers[i].rtc = &rtc;
        producers[i].id = i;
        if (XThread_Create(&threads[i], produce, &producers[i], 0) != XSTDOK) return 1;
    }
    unsigned done;
    do
    {
        DirectGate_WebRTC_ProcessQueue(&rtc);
        done = 0;
        for (unsigned i = 0; i < PRODUCERS; i++) done += XSYNC_ATOMIC_GET(&producers[i].done);
        xusleep(100);
    } while (done < PRODUCERS);
    for (unsigned i = 0; i < PRODUCERS; i++) XThread_Join(&threads[i]);
    DirectGate_WebRTC_ProcessQueue(&rtc);
    rtc.nDataChannelID = -1;
    DirectGate_WebRTC_Clear(&rtc);
    if (failed || received != PRODUCERS * MESSAGES)
    { fprintf(stderr, "webrtc_queue_smoke: lost, reordered or corrupted messages (%u)\n", received); return 1; }
    puts("webrtc_queue_smoke: OK");
    return 0;
}
