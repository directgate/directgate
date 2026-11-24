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

#ifndef _WIN32
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

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

#ifndef _WIN32
    /* ---- local files: off without --root, and inside it only, links and .. resolved first ---- */
    {
        char sTop[] = "/tmp/directgate_mcp_root.XXXXXX", sReal[PATH_MAX];
        CHECK(mkdtemp(sTop) != NULL && realpath(sTop, sReal) != NULL, "a scratch directory");

        /* Each a little longer than what it is made from, so no name can be cut short */
        char sRoot[PATH_MAX + 16], sSibling[PATH_MAX + 16], sOutside[PATH_MAX + 16];
        char sSub[PATH_MAX + 32], sIn[PATH_MAX + 32], sSiblingFile[PATH_MAX + 32], sLinkOut[PATH_MAX + 32];
        char sLinkUp[PATH_MAX + 32], sDangling[PATH_MAX + 32], sGot[PATH_MAX + 64], sWant[PATH_MAX + 64];
        snprintf(sRoot, sizeof(sRoot), "%s/root", sReal);
        snprintf(sSub, sizeof(sSub), "%s/sub", sRoot);
        snprintf(sIn, sizeof(sIn), "%s/in.txt", sRoot);
        snprintf(sOutside, sizeof(sOutside), "%s/outside.txt", sReal);
        snprintf(sSibling, sizeof(sSibling), "%s/root2", sReal);
        snprintf(sSiblingFile, sizeof(sSiblingFile), "%s/file.txt", sSibling);
        snprintf(sLinkOut, sizeof(sLinkOut), "%s/link-out", sRoot);
        snprintf(sLinkUp, sizeof(sLinkUp), "%s/up", sRoot);
        snprintf(sDangling, sizeof(sDangling), "%s/dangling", sRoot);

        FILE *pIn = NULL, *pOutside = NULL, *pSibling = NULL;
        CHECK(mkdir(sRoot, 0700) == 0 && mkdir(sSub, 0700) == 0 && mkdir(sSibling, 0700) == 0, "the root and its neighbours");
        CHECK((pIn = fopen(sIn, "w")) != NULL && (pOutside = fopen(sOutside, "w")) != NULL &&
              (pSibling = fopen(sSiblingFile, "w")) != NULL, "files inside and outside");
        fclose(pIn); fclose(pOutside); fclose(pSibling);
        CHECK(symlink(sOutside, sLinkOut) == 0 && symlink(sReal, sLinkUp) == 0 &&
              symlink("/nonexistent/directgate", sDangling) == 0, "links out of the root");

        /* How the server starts: no local path at all, whatever it names */
        const char *pWhy = DirectGate_Mcp_ResolveLocal(sIn, XFALSE, sGot, sizeof(sGot));
        CHECK(pWhy != NULL && strstr(pWhy, "--root <dir>") != NULL, "without a root no local path is taken");
        pReply = answer("{\"jsonrpc\":\"2.0\",\"id\":13,\"method\":\"tools/call\",\"params\":{\"name\":\"download\","
            "\"arguments\":{\"device\":\"box\",\"remote_path\":\"/etc/hosts\",\"local_path\":\"hosts\"}}}", &out);
        CHECK(strstr(pReply, "\"isError\":true") != NULL && strstr(pReply, "local files are off") != NULL,
            "and a transfer says how to turn local files on");

        CHECK(DirectGate_Mcp_SetRoot(sIn) == XSTDERR && DirectGate_Mcp_ResolveLocal(sIn, XFALSE, sGot, sizeof(sGot)) != NULL,
            "a root that is a file is refused, and leaves local files off");
        CHECK(DirectGate_Mcp_SetRoot("/nonexistent/directgate") == XSTDERR &&
              DirectGate_Mcp_ResolveLocal(sIn, XFALSE, sGot, sizeof(sGot)) != NULL, "so is one that does not exist");
        CHECK(DirectGate_Mcp_SetRoot(sRoot) == XSTDOK, "a directory is a root");

        /* What an upload reads: something that exists, inside, wherever its links lead */
#define RESOLVES(path, write, want) (DirectGate_Mcp_ResolveLocal(path, write, sGot, sizeof(sGot)) == NULL && !strcmp(sGot, want))
#define REFUSED(path, write, why) ((pWhy = DirectGate_Mcp_ResolveLocal(path, write, sGot, sizeof(sGot))) != NULL && \
                                   strstr(pWhy, why) != NULL)
        CHECK(RESOLVES("in.txt", XFALSE, sIn), "a relative path is the root's");
        CHECK(RESOLVES(sIn, XFALSE, sIn), "an absolute one inside is itself");
        CHECK(RESOLVES("sub/../in.txt", XFALSE, sIn), "a .. that stays inside resolves");
        CHECK(REFUSED("../outside.txt", XFALSE, "outside"), "a .. out of the root is refused");
        CHECK(REFUSED(sOutside, XFALSE, "outside"), "so is an absolute path elsewhere");
        CHECK(REFUSED("link-out", XFALSE, "outside"), "and a link in the root that points out of it");
        CHECK(REFUSED("up/outside.txt", XFALSE, "outside"), "and a link to a directory above it");
        CHECK(REFUSED(sSiblingFile, XFALSE, "outside"), "a directory whose name the root's begins is not the root");
        CHECK(REFUSED("missing.txt", XFALSE, "does not exist") && REFUSED("dangling", XFALSE, "does not exist"),
            "an upload of nothing is refused");

        /* Where a download writes: a new name in a directory inside, or an existing directory inside */
        snprintf(sWant, sizeof(sWant), "%s/new.txt", sRoot);
        CHECK(RESOLVES("new.txt", XTRUE, sWant), "a new file in the root");
        snprintf(sWant, sizeof(sWant), "%s/new.txt", sSub);
        CHECK(RESOLVES("sub/new.txt", XTRUE, sWant), "a new file in a directory inside it");
        CHECK(RESOLVES("sub", XTRUE, sSub) && RESOLVES("sub/..", XTRUE, sRoot), "a directory inside: it keeps the remote name");
        CHECK(RESOLVES("dangling", XTRUE, sDangling), "a dangling link is a name in the root: a download replaces the link");
        CHECK(REFUSED("nodir/new.txt", XTRUE, "does not exist") && REFUSED("nodir/", XTRUE, "does not exist"),
            "a directory that is not there is refused");
        CHECK(REFUSED("../new.txt", XTRUE, "outside") && REFUSED("..", XTRUE, "outside"), "a .. above the root is refused");
        CHECK(REFUSED("up/new.txt", XTRUE, "outside"), "and a new file behind a link to above it");
        CHECK(REFUSED("link-out", XTRUE, "outside"), "an existing link out is never written through");
        CHECK(RESOLVES("sub/.", XTRUE, sSub), "a directory named by way of . is that directory");

        /* The tool call refuses before anything runs, and says why */
        pReply = answer("{\"jsonrpc\":\"2.0\",\"id\":14,\"method\":\"tools/call\",\"params\":{\"name\":\"upload\","
            "\"arguments\":{\"device\":\"box\",\"local_path\":\"../outside.txt\",\"remote_path\":\"/tmp/x\"}}}", &out);
        CHECK(strstr(pReply, "\"isError\":true") != NULL && strstr(pReply, "outside the directory") != NULL,
            "an upload from outside the root is a tool error");

        /* A root at the top of the file system is the user's word that every path goes */
        CHECK(DirectGate_Mcp_SetRoot("/") == XSTDOK && RESOLVES(sOutside, XFALSE, sOutside), "a root of / takes every path");
#undef RESOLVES
#undef REFUSED

        CHECK(DirectGate_Mcp_SetRoot(NULL) == XSTDOK && DirectGate_Mcp_ResolveLocal(sIn, XFALSE, sGot, sizeof(sGot)) != NULL,
            "and no root turns local files off again");

        unlink(sLinkOut); unlink(sLinkUp); unlink(sDangling); unlink(sIn); unlink(sOutside); unlink(sSiblingFile);
        rmdir(sSub); rmdir(sRoot); rmdir(sSibling); rmdir(sTop);
    }
#endif

    XByteBuffer_Clear(&out);
    puts("client_mcp_smoke: OK");
    return 0;
}
