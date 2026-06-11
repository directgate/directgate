/* libxutils string helpers and byte buffers: the building blocks under
 * every config path, log line and protocol packet. Locks the bounded-copy
 * guarantees (truncation, NUL termination) and buffer growth/advance
 * semantics that the PTY TX queue depends on. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libxutils/src/data/str.h"
#include "libxutils/src/data/buf.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "str_buf_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

int main(void)
{
    /* ---- bounded copies always NUL-terminate and never overflow ---- */
    char sSmall[8];
    memset(sSmall, 0x7f, sizeof(sSmall));

    size_t nLen = xstrncpy(sSmall, sizeof(sSmall), "0123456789abcdef");
    CHECK(nLen < sizeof(sSmall), "xstrncpy truncates");
    CHECK(sSmall[sizeof(sSmall) - 1] == '\0' || strlen(sSmall) < sizeof(sSmall),
        "xstrncpy terminates");
    CHECK(strncmp(sSmall, "0123456", 7) == 0, "xstrncpy content");

    CHECK(xstrncpy(sSmall, sizeof(sSmall), "") == 0, "xstrncpy empty");
    CHECK(sSmall[0] == '\0', "xstrncpy empty terminates");

    nLen = xstrncpyf(sSmall, sizeof(sSmall), "%s-%d", "abc", 42);
    CHECK(nLen == 6 && strcmp(sSmall, "abc-42") == 0, "xstrncpyf format");

    nLen = xstrncpyf(sSmall, sizeof(sSmall), "%s", "0123456789");
    CHECK(strlen(sSmall) < sizeof(sSmall), "xstrncpyf truncates");

    /* Length-limited copy from a non-terminated source */
    char sFrom[4] = { 'w', 'i', 'r', 'e' };
    char sTo[16];
    nLen = xstrncpys(sTo, sizeof(sTo), sFrom, sizeof(sFrom));
    CHECK(nLen == 4 && strcmp(sTo, "wire") == 0, "xstrncpys bounded source");

    /* ---- comparison helpers: TRUE means equal ---- */
    CHECK(xstrcmp("abc", "abc") == XTRUE, "xstrcmp equal");
    CHECK(xstrcmp("abc", "abd") == XFALSE, "xstrcmp differs");
    CHECK(xstrncmp("abcdef", "abc", 3) == XTRUE, "xstrncmp prefix");
    CHECK(xstrused("x") == XTRUE, "xstrused non-empty");
    CHECK(xstrused("") == XFALSE, "xstrused empty");
    CHECK(xstrused(NULL) == XFALSE, "xstrused NULL");

    /* ---- substring search ---- */
    CHECK(xstrsrc("wss://relay.example/ws?x=1", "?") == 22, "xstrsrc offset");
    CHECK(xstrsrc("plain", "?") < 0, "xstrsrc missing");

    /* ---- tokenizer ---- */
    char sTok[32];
    xstrncpy(sTok, sizeof(sTok), "host:443:extra");
    char *pSave = NULL;
    char *pTok = xstrtok(sTok, ":", &pSave);
    CHECK(pTok != NULL && strcmp(pTok, "host") == 0, "first token");
    pTok = xstrtok(NULL, ":", &pSave);
    CHECK(pTok != NULL && strcmp(pTok, "443") == 0, "second token");
    pTok = xstrtok(NULL, ":", &pSave);
    CHECK(pTok != NULL && strcmp(pTok, "extra") == 0, "third token");
    CHECK(xstrtok(NULL, ":", &pSave) == NULL, "tokens exhausted");

    /* ---- byte buffers ---- */
    xbyte_buffer_t buf;
    CHECK(XByteBuffer_Init(&buf, XSTDNON, XFALSE) >= 0, "buffer init");
    CHECK(buf.nUsed == 0, "fresh buffer empty");

    CHECK(XByteBuffer_Add(&buf, (const uint8_t*)"hello", 5) > 0, "buffer add");
    CHECK(buf.nUsed == 5, "buffer used");
    CHECK(XByteBuffer_AddByte(&buf, '!') > 0, "buffer add byte");
    CHECK(buf.nUsed == 6 && memcmp(buf.pData, "hello!", 6) == 0, "buffer content");

    /* Advance models partial PTY writes: drops consumed bytes from the head */
    CHECK(XByteBuffer_Advance(&buf, 2) > 0, "buffer advance");
    CHECK(buf.nUsed == 4 && memcmp(buf.pData, "llo!", 4) == 0, "advance content");

    /* Advancing everything empties without invalidating the buffer */
    XByteBuffer_Advance(&buf, buf.nUsed);
    CHECK(buf.nUsed == 0, "advance to empty");
    CHECK(XByteBuffer_Add(&buf, (const uint8_t*)"again", 5) > 0, "reuse after drain");
    CHECK(buf.nUsed == 5, "reused size");

    /* Reset keeps the allocation, Clear releases it */
    XByteBuffer_Reset(&buf);
    CHECK(buf.nUsed == 0, "reset empties");
    CHECK(XByteBuffer_Add(&buf, (const uint8_t*)"x", 1) > 0, "add after reset");
    XByteBuffer_Clear(&buf);
    CHECK(buf.pData == NULL && buf.nUsed == 0, "clear releases");

    /* Growth: stream 256 KB through in odd-sized chunks, verify content */
    CHECK(XByteBuffer_Init(&buf, XSTDNON, XFALSE) >= 0, "growth buffer init");

    uint8_t sChunk[331];
    size_t nTotal = 0;
    while (nTotal < 256 * 1024)
    {
        for (size_t i = 0; i < sizeof(sChunk); i++)
            sChunk[i] = (uint8_t)((nTotal + i) % 251);

        CHECK(XByteBuffer_Add(&buf, sChunk, sizeof(sChunk)) > 0, "growth add");
        nTotal += sizeof(sChunk);
    }

    CHECK(buf.nUsed == nTotal, "growth size");
    for (size_t i = 0; i < nTotal; i += 7919)
        CHECK(buf.pData[i] == (uint8_t)(i % 251), "growth content spot check");

    XByteBuffer_Clear(&buf);

    /* Binary safety: NUL and 0x1A bytes (the CRLF/EOF hazards) survive */
    CHECK(XByteBuffer_Init(&buf, XSTDNON, XFALSE) >= 0, "binary buffer init");
    const uint8_t binary[] = { 0x00, 0x1a, 0x0d, 0x0a, 0xff, 0x00 };
    CHECK(XByteBuffer_Add(&buf, binary, sizeof(binary)) > 0, "binary add");
    CHECK(buf.nUsed == sizeof(binary) && memcmp(buf.pData, binary, sizeof(binary)) == 0,
        "binary bytes intact");
    XByteBuffer_Clear(&buf);

    puts("str_buf_smoke: OK");
    return 0;
}
