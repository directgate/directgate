/*
 * dgcli's MCP server, without a network: the JSON it writes and the requests it refuses.
 *
 * Remote programs print whatever bytes they like and file names are not always text, but every response line has to
 * be JSON a client can parse: the string encoder is checked against malformed and hostile UTF-8 by value. The
 * protocol handling is driven line by line through DirectGate_Mcp_HandleLine; nothing here reaches a tool call
 * that would run dgcli, which client_e2e_smoke covers against a host.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "src/client/mcp.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "client_mcp_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static int encodes_to(const char *pInput, size_t nInput, const char *pExpected)
{
    xbyte_buffer_t out;
    XByteBuffer_Init(&out, XSTDNON, XFALSE);

    int nOk = DirectGate_Mcp_AppendString(&out, (const uint8_t*)pInput, nInput) == XSTDOK &&
        out.nUsed == strlen(pExpected) && memcmp(out.pData, pExpected, out.nUsed) == 0;

    if (!nOk) fprintf(stderr, "client_mcp_smoke: got [%.*s] want [%s]\n", (int)out.nUsed, (const char*)out.pData, pExpected);
    XByteBuffer_Clear(&out);
    return nOk;
}

/* The response to one request line, as a string; empty when there is none. */
static const char* answer(const char *pLine, xbyte_buffer_t *pOut)
{
    XByteBuffer_Clear(pOut);
    XByteBuffer_Init(pOut, XSTDNON, XFALSE);

    char *aGlobals[] = { NULL };
    DirectGate_Mcp_HandleLine("/nonexistent/dgcli", aGlobals, 0, pLine, strlen(pLine), pOut);
    XByteBuffer_AddByte(pOut, '\0');
    pOut->nUsed--;
    return (const char*)pOut->pData;
}

int main(void)
{
    /* ---- strings ---- */

    CHECK(encodes_to("plain", 5, "\"plain\""), "plain text is quoted as it is");
    CHECK(encodes_to("a\"b\\c", 5, "\"a\\\"b\\\\c\""), "quotes and backslashes are escaped");
    CHECK(encodes_to("\n\r\t", 3, "\"\\n\\r\\t\""), "line breaks and tabs use their short escapes");
    CHECK(encodes_to("\x1b[31m\x07", 6, "\"\\u001b[31m\\u0007\""), "other control characters use \\u escapes");
    CHECK(encodes_to("a\0b", 3, "\"a\\u0000b\""), "a NUL byte is escaped, not a terminator");
    CHECK(encodes_to("\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80", 9, "\"\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80\""),
        "valid two, three and four byte sequences pass through");
    CHECK(encodes_to("a\xff" "b", 3, "\"a\xef\xbf\xbd" "b\""), "a byte that starts nothing becomes U+FFFD");
    CHECK(encodes_to("\xc3", 1, "\"\xef\xbf\xbd\""), "a sequence cut short at the end becomes U+FFFD");
    CHECK(encodes_to("\xc3(", 2, "\"\xef\xbf\xbd(\""), "a lead byte without its continuation becomes U+FFFD");
    CHECK(encodes_to("\xc0\xaf", 2, "\"\xef\xbf\xbd\xef\xbf\xbd\""), "an overlong encoding is refused byte by byte");
    CHECK(encodes_to("\xed\xa0\x80", 3, "\"\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\""), "an encoded surrogate is refused");
    CHECK(encodes_to("\xf4\x90\x80\x80", 4, "\"\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\""),
        "a code point past U+10FFFF is refused");
    CHECK(encodes_to("", 0, "\"\""), "an empty string is two quotes");

    CHECK(DirectGate_Mcp_IsText((const uint8_t*)"text \xc3\xa9\n", 8), "UTF-8 text is text");
    CHECK(!DirectGate_Mcp_IsText((const uint8_t*)"a\0b", 3), "a NUL byte makes it binary");
    CHECK(!DirectGate_Mcp_IsText((const uint8_t*)"a\xff", 2), "invalid UTF-8 makes it binary");
    CHECK(DirectGate_Mcp_IsText((const uint8_t*)"", 0), "nothing at all is empty text");

    /* ---- the protocol ---- */

    xbyte_buffer_t out;
    XByteBuffer_Init(&out, XSTDNON, XFALSE);

    const char *pReply = answer("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"initialize\","
        "\"params\":{\"protocolVersion\":\"2025-03-26\"}}", &out);
    CHECK(strncmp(pReply, "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"protocolVersion\":\"2025-03-26\"", 64) == 0,
        "a protocol version this server speaks is the one agreed on");
    CHECK(pReply[out.nUsed - 1] == '\n' && strchr(pReply, '\n') == pReply + out.nUsed - 1, "a response is exactly one line");

    pReply = answer("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"1999-01-01\"}}",
        &out);
    CHECK(strstr(pReply, "\"protocolVersion\":\"2025-06-18\"") != NULL, "an unknown version is answered with the server's own");

    pReply = answer("{\"jsonrpc\":\"2.0\",\"id\":\"req-\\\"x\\\"\",\"method\":\"ping\"}", &out);
    CHECK(strcmp(pReply, "{\"jsonrpc\":\"2.0\",\"id\":\"req-\\\"x\\\"\",\"result\":{}}\n") == 0,
        "a string id comes back as it was sent");

    pReply = answer("{\"jsonrpc\":\"2.0\",\"id\":-12,\"method\":\"ping\"}", &out);
    CHECK(strcmp(pReply, "{\"jsonrpc\":\"2.0\",\"id\":-12,\"result\":{}}\n") == 0, "a number id comes back in its own digits");

    pReply = answer("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}", &out);
    CHECK(out.nUsed == 0, "a notification is never answered");
    pReply = answer("{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"exec\"}}", &out);
    CHECK(out.nUsed == 0, "a request without an id is a notification even when it names a tool");
    pReply = answer("   ", &out);
    CHECK(out.nUsed == 0, "a blank line is not a request");

    pReply = answer("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}", &out);
    CHECK(out.nUsed == 0, "a response from the client is not answered");

    pReply = answer("{oops", &out);
    CHECK(strcmp(pReply, "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,\"message\":\"parse error\"}}\n") == 0,
        "a line that is not JSON gets a parse error with a null id");

    pReply = answer("[1,2]", &out);
    CHECK(strstr(pReply, "\"code\":-32600") != NULL, "a batch or any non-object is an invalid request");

    pReply = answer("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"resources/list\"}", &out);
    CHECK(strstr(pReply, "\"code\":-32601") != NULL, "an unsupported method is not found");

    pReply = answer("{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\","
        "\"params\":{\"name\":\"format_disk\",\"arguments\":{}}}", &out);
    CHECK(strstr(pReply, "\"code\":-32602") != NULL, "an unknown tool is a protocol error");

    pReply = answer("{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\"}", &out);
    CHECK(strstr(pReply, "\"code\":-32602") != NULL, "a tool call without params is a protocol error");

    /* Arguments a tool cannot use come back as a tool error the model can read and correct, without running dgcli */
    pReply = answer("{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\","
        "\"params\":{\"name\":\"exec\",\"arguments\":{\"device\":\"box\"}}}", &out);
    CHECK(strstr(pReply, "\"isError\":true") != NULL && strstr(pReply, "device and command are required") != NULL,
        "exec without a command is a tool error");

    pReply = answer("{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"exec\","
        "\"arguments\":{\"device\":\"-c\",\"command\":\"id\"}}}", &out);
    CHECK(strstr(pReply, "\"isError\":true") != NULL, "a device that would read as an option is refused");

    pReply = answer("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"exec\","
        "\"arguments\":{\"device\":\"box\",\"command\":\"id\",\"timeout_seconds\":0}}}", &out);
    CHECK(strstr(pReply, "timeout_seconds must be") != NULL, "a zero timeout is refused");

    pReply = answer("{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/call\",\"params\":{\"name\":\"exec\","
        "\"arguments\":{\"device\":\"box\",\"command\":\"id\",\"timeout_seconds\":\"60\"}}}", &out);
    CHECK(strstr(pReply, "timeout_seconds must be") != NULL, "a timeout given as a string is refused");

    pReply = answer("{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"upload\","
        "\"arguments\":{\"device\":\"box\",\"local_path\":\"-\",\"remote_path\":\"/tmp/x\"}}}", &out);
    CHECK(strstr(pReply, "\"isError\":true") != NULL && strstr(pReply, "local_path cannot be -") != NULL,
        "a local path of - (the server's own stdin) is refused");

    pReply = answer("{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"tools/call\",\"params\":{\"name\":\"write_file\","
        "\"arguments\":{\"device\":\"box\",\"path\":\"/tmp/x\"}}}", &out);
    CHECK(strstr(pReply, "path and content are required") != NULL, "write_file without content is a tool error");

    pReply = answer("{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"tools/call\",\"params\":{\"name\":\"move\","
        "\"arguments\":{\"device\":\"box\",\"from\":\"/a\"}}}", &out);
    CHECK(strstr(pReply, "from and to are required") != NULL, "move without a target is a tool error");

    /* A dgcli that cannot be run is reported, not crashed on */
    pReply = answer("{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"tools/call\",\"params\":{\"name\":\"make_directory\","
        "\"arguments\":{\"device\":\"box\",\"path\":\"/tmp/new\"}}}", &out);
    CHECK(strstr(pReply, "\"id\":12") != NULL && strstr(pReply, "\"isError\":true") != NULL,
        "a tool whose dgcli binary is missing fails as a tool error");

    XByteBuffer_Clear(&out);
    puts("client_mcp_smoke: OK");
    return 0;
}
