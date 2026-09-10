/* Entropy failure must fail closed and free the partially constructed frame. */
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
static int fail_entropy;
static int test_random(unsigned char *data, int len)
{
    if (fail_entropy) return 0;
    memset(data, 0, len); /* All-zero keys are valid too. */
    return 1;
}
#define RAND_bytes test_random
#define _XUTILS_USE_SSL
#include "libxutils/src/net/ws.c"
#undef RAND_bytes
int main(void)
{
    xws_frame_t frame;
    fail_entropy = 1;
    if (XWebFrame_Create(&frame, (const uint8_t*)"abc", 3, XWS_BINARY, XTRUE, XTRUE) != XWS_ERR_RANDOM ||
        frame.buffer.pData || frame.buffer.nUsed) return 1;
    if (XWebFrame_New((const uint8_t*)"abc", 3, XWS_BINARY, XTRUE, XTRUE)) return 1;
    fail_entropy = 0;
    if (XWebFrame_Create(&frame, (const uint8_t*)"abc", 3, XWS_BINARY, XTRUE, XTRUE) != XWS_ERR_NONE ||
        !frame.bMask || frame.nMaskKey || memcmp(frame.buffer.pData + frame.nHeaderSize, "abc", 3)) return 1;
    XWebFrame_Clear(&frame);
    puts("websock_entropy_smoke: OK");
    return 0;
}
