/*!
 * @file directgate-agent/src/client/mcp.c
 * @brief "dgcli mcp": the remote operations as an MCP server on stdio.
 *
 *  Copyright (c) 2025-2026 DirectGate. All rights reserved.
 *  Author: Sandro Kalatozishvili (sandro@directgate.io)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "mcp.h"
#include "remote.h"
#include "version.h"

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

/* Windows has no signals: XExec_Kill ends the child's job whatever it is asked for */
#ifndef SIGKILL
#define SIGKILL 9
#endif

#ifdef _WIN32
#include <io.h>
#define DIRECTGATE_MCP_READ(fd, buf, len) _read(fd, buf, (unsigned int)(len))
#define DIRECTGATE_MCP_WRITE(fd, buf, len) _write(fd, buf, (unsigned int)(len))
#else
#define DIRECTGATE_MCP_READ(fd, buf, len) read(fd, buf, len)
#define DIRECTGATE_MCP_WRITE(fd, buf, len) write(fd, buf, len)
#endif

/* A child's streams: sockets of a pair on Windows (see exec.h), pipes elsewhere */
#ifdef _WIN32
typedef WSAPOLLFD directgate_mcp_pollfd_t;
#define DIRECTGATE_MCP_POLL(fds, count, ms) WSAPoll(fds, (ULONG)(count), ms)
#define DIRECTGATE_MCP_SOCK_READ(fd, buf, len) recv(fd, (char*)(buf), (int)(len), 0)
#define DIRECTGATE_MCP_SOCK_WRITE(fd, buf, len) send(fd, (const char*)(buf), (int)(len), 0)
#else
typedef struct pollfd directgate_mcp_pollfd_t;
#define DIRECTGATE_MCP_POLL(fds, count, ms) poll(fds, (nfds_t)(count), ms)
#define DIRECTGATE_MCP_SOCK_READ(fd, buf, len) (int)read(fd, buf, len)
#define DIRECTGATE_MCP_SOCK_WRITE(fd, buf, len) (int)write(fd, buf, len)
#endif

#define DIRECTGATE_MCP_DEFAULT_VERSION  "2025-06-18"
#define DIRECTGATE_MCP_LINE_MAX         (16U * 1024U * 1024U)   /* One request, write_file content included */
#define DIRECTGATE_MCP_OUTPUT_MAX       (128U * 1024U)          /* Of each stream, handed back to the model */
#define DIRECTGATE_MCP_READ_MAX         (256U * 1024U)          /* read_file: larger files are downloaded */
#define DIRECTGATE_MCP_EXEC_TIMEOUT     600U                    /* Seconds, when a call names none */
#define DIRECTGATE_MCP_TIMEOUT_MAX      86400U
#define DIRECTGATE_MCP_FILE_TIMEOUT     3600U
#define DIRECTGATE_MCP_CONNECT_GRACE    60U                     /* Signing in and connecting, on top of the work */
#define DIRECTGATE_MCP_GLOBALS_MAX      16
#define DIRECTGATE_MCP_SESSIONS_MAX     8                       /* Connections kept open at once, the oldest goes */
#define DIRECTGATE_MCP_SESSION_GRACE    10U                     /* Seconds an open session gets on top of the work */
#define DIRECTGATE_MCP_LOG_MAX          4096U                   /* Of a session's own stderr, the tail is kept */

#define DIRECTGATE_MCP_ERR_PARSE        -32700
#define DIRECTGATE_MCP_ERR_REQUEST      -32600
#define DIRECTGATE_MCP_ERR_METHOD       -32601
#define DIRECTGATE_MCP_ERR_PARAMS       -32602

static const char *g_pMcpVersions[] = { "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05" };

static const char *g_pMcpInstructions =
    "DirectGate reaches the user's own devices end to end encrypted, the way ssh would. Call list_devices first and "
    "pass a device's name or id as `device`. exec runs a non-interactive shell command (sh -c, or cmd /c on Windows) "
    "as the device's shell user and returns its exit code, stdout and stderr; it has no terminal, so programs that "
    "wait for keyboard input block until the timeout - give them `stdin` instead. Remote paths are absolute. upload "
    "and download reach this machine's files only inside the directory the user started this server with (--root): a "
    "relative local path is taken from there, and nothing outside it, links included. Each call connects on its own "
    "unless you pass "
    "keep_open: true - do that whenever more calls on the same device are likely, so they reuse the connection, and "
    "call disconnect once you are done with the device.";

/* What every device tool takes: whether its connection stays open for the calls that follow */
#define DIRECTGATE_MCP_KEEP_OPEN \
    "\"keep_open\":{\"type\":\"boolean\",\"default\":false,\"description\":\"Keep the connection to this device " \
    "open for the next calls, so they skip signalling and authentication; pass it while more work on this device " \
    "is likely, and call disconnect when done\"},"

/* The tool list, as tools/list returns it. Kept as JSON so the schemas read the way a client sees them. */
static const char *g_pMcpTools =
    "{\"tools\":["
    "{\"name\":\"list_devices\",\"title\":\"List devices\","
    "\"description\":\"Lists the DirectGate devices on the signed-in account: id, name, whether each is online and "
    "whether it can be connected. Use a device's name or id as `device` in the other tools.\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false},"
    "\"annotations\":{\"readOnlyHint\":true,\"openWorldHint\":true}},"

    "{\"name\":\"exec\",\"title\":\"Run a command\","
    "\"description\":\"Runs a shell command on a device, like `ssh device 'command'`: non-interactive, no terminal, "
    "as the device's configured shell user. Returns the exit code, stdout and stderr (each cut at 128 KB). A command "
    "that waits for input or a terminal blocks until the timeout; pass input as `stdin`.\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{" DIRECTGATE_MCP_KEEP_OPEN
    "\"device\":{\"type\":\"string\",\"description\":\"Device name or id, from list_devices\"},"
    "\"command\":{\"type\":\"string\",\"description\":\"The command line, run by the device's shell\"},"
    "\"cwd\":{\"type\":\"string\",\"description\":\"Absolute directory to run in; the shell user's home by default\"},"
    "\"stdin\":{\"type\":\"string\",\"description\":\"Text given to the command as its standard input\"},"
    "\"timeout_seconds\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":86400,"
    "\"description\":\"Kill the command after this many seconds (600 by default)\"}},"
    "\"required\":[\"device\",\"command\"],\"additionalProperties\":false},"
    "\"annotations\":{\"destructiveHint\":true,\"openWorldHint\":true}},"

    "{\"name\":\"list_directory\",\"title\":\"List a directory\","
    "\"description\":\"Lists a directory on a device: name, type, permissions, owner, size and modification time of "
    "each entry, as JSON.\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{" DIRECTGATE_MCP_KEEP_OPEN
    "\"device\":{\"type\":\"string\"},\"path\":{\"type\":\"string\",\"description\":\"Absolute directory path\"}},"
    "\"required\":[\"device\",\"path\"],\"additionalProperties\":false},"
    "\"annotations\":{\"readOnlyHint\":true,\"openWorldHint\":true}},"

    "{\"name\":\"read_file\",\"title\":\"Read a text file\","
    "\"description\":\"Returns the contents of a UTF-8 text file on a device, up to 256 KB. Use download for larger "
    "or binary files.\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{" DIRECTGATE_MCP_KEEP_OPEN
    "\"device\":{\"type\":\"string\"},\"path\":{\"type\":\"string\",\"description\":\"Absolute file path\"}},"
    "\"required\":[\"device\",\"path\"],\"additionalProperties\":false},"
    "\"annotations\":{\"readOnlyHint\":true,\"openWorldHint\":true}},"

    "{\"name\":\"write_file\",\"title\":\"Write a text file\","
    "\"description\":\"Writes text to a file on a device, verified and put in place only once complete. An existing "
    "file is replaced only with overwrite.\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{" DIRECTGATE_MCP_KEEP_OPEN
    "\"device\":{\"type\":\"string\"},\"path\":{\"type\":\"string\",\"description\":\"Absolute file path\"},"
    "\"content\":{\"type\":\"string\"},\"overwrite\":{\"type\":\"boolean\",\"default\":false}},"
    "\"required\":[\"device\",\"path\",\"content\"],\"additionalProperties\":false},"
    "\"annotations\":{\"destructiveHint\":true,\"openWorldHint\":true}},"

    "{\"name\":\"upload\",\"title\":\"Upload a file\","
    "\"description\":\"Copies a file from this machine to a device: only a file inside the directory this server was "
    "started with (--root), relative paths taken from there. A remote path ending in / keeps the local name.\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{" DIRECTGATE_MCP_KEEP_OPEN
    "\"device\":{\"type\":\"string\"},\"local_path\":{\"type\":\"string\"},"
    "\"remote_path\":{\"type\":\"string\",\"description\":\"Absolute path on the device\"},"
    "\"overwrite\":{\"type\":\"boolean\",\"default\":false}},"
    "\"required\":[\"device\",\"local_path\",\"remote_path\"],\"additionalProperties\":false},"
    "\"annotations\":{\"destructiveHint\":true,\"openWorldHint\":true}},"

    "{\"name\":\"download\",\"title\":\"Download a file\","
    "\"description\":\"Copies a file from a device to this machine, put in place only once verified, and only inside "
    "the directory this server was started with (--root), relative paths taken from there. An existing local file is "
    "replaced only with overwrite. A local path that is a directory keeps the remote name.\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{" DIRECTGATE_MCP_KEEP_OPEN
    "\"device\":{\"type\":\"string\"},\"remote_path\":{\"type\":\"string\",\"description\":\"Absolute path on the device\"},"
    "\"local_path\":{\"type\":\"string\"},\"overwrite\":{\"type\":\"boolean\",\"default\":false}},"
    "\"required\":[\"device\",\"remote_path\",\"local_path\"],\"additionalProperties\":false},"
    "\"annotations\":{\"destructiveHint\":true,\"openWorldHint\":true}},"

    "{\"name\":\"remove\",\"title\":\"Remove a file\","
    "\"description\":\"Removes a file or an empty directory on a device; a directory with its contents only with "
    "recursive.\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{" DIRECTGATE_MCP_KEEP_OPEN
    "\"device\":{\"type\":\"string\"},\"path\":{\"type\":\"string\",\"description\":\"Absolute path\"},"
    "\"recursive\":{\"type\":\"boolean\",\"default\":false}},"
    "\"required\":[\"device\",\"path\"],\"additionalProperties\":false},"
    "\"annotations\":{\"destructiveHint\":true,\"openWorldHint\":true}},"

    "{\"name\":\"make_directory\",\"title\":\"Create a directory\","
    "\"description\":\"Creates a directory on a device.\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{" DIRECTGATE_MCP_KEEP_OPEN
    "\"device\":{\"type\":\"string\"},\"path\":{\"type\":\"string\",\"description\":\"Absolute path\"}},"
    "\"required\":[\"device\",\"path\"],\"additionalProperties\":false},"
    "\"annotations\":{\"openWorldHint\":true}},"

    "{\"name\":\"move\",\"title\":\"Move or rename\","
    "\"description\":\"Moves or renames a file or directory on a device. An existing target is refused, never "
    "replaced.\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{" DIRECTGATE_MCP_KEEP_OPEN
    "\"device\":{\"type\":\"string\"},\"from\":{\"type\":\"string\",\"description\":\"Absolute path\"},"
    "\"to\":{\"type\":\"string\",\"description\":\"Absolute path\"}},"
    "\"required\":[\"device\",\"from\",\"to\"],\"additionalProperties\":false},"
    "\"annotations\":{\"destructiveHint\":true,\"openWorldHint\":true}},"

    "{\"name\":\"disconnect\",\"title\":\"Close a kept connection\","
    "\"description\":\"Closes the connection keep_open left open to a device. A kept connection also closes by "
    "itself after 10 minutes unused, and after 30 minutes in all.\","
    "\"inputSchema\":{\"type\":\"object\",\"properties\":{\"device\":{\"type\":\"string\"}},"
    "\"required\":[\"device\"],\"additionalProperties\":false},"
    "\"annotations\":{\"idempotentHint\":true,\"openWorldHint\":true}}"
    "]}";

/* Length of the valid UTF-8 sequence at pData, or 0 when it is not one: overlong forms, surrogates and code points
   past U+10FFFF included. */
static size_t DirectGate_Mcp_Utf8Length(const uint8_t *pData, size_t nLength)
{
    uint8_t nByte = pData[0];
    if (nByte < 0x80) return 1;

    size_t nSeq = 0;
    uint32_t nCode = 0, nMin = 0;

    if ((nByte & 0xE0) == 0xC0) { nSeq = 2; nMin = 0x80; nCode = nByte & 0x1F; }
    else if ((nByte & 0xF0) == 0xE0) { nSeq = 3; nMin = 0x800; nCode = nByte & 0x0F; }
    else if ((nByte & 0xF8) == 0xF0) { nSeq = 4; nMin = 0x10000; nCode = nByte & 0x07; }
    else return 0;

    if (nLength < nSeq) return 0;

    for (size_t i = 1; i < nSeq; i++)
    {
        if ((pData[i] & 0xC0) != 0x80) return 0;
        nCode = (nCode << 6) | (pData[i] & 0x3F);
    }

    if (nCode < nMin || nCode > 0x10FFFF || (nCode >= 0xD800 && nCode <= 0xDFFF)) return 0;
    return nSeq;
}

xbool_t DirectGate_Mcp_IsText(const uint8_t *pData, size_t nLength)
{
    XCHECK_NL((pData != NULL || !nLength), XFALSE);

    for (size_t i = 0; i < nLength; )
    {
        if (pData[i] == 0) return XFALSE;
        size_t nSeq = DirectGate_Mcp_Utf8Length(pData + i, nLength - i);
        if (!nSeq) return XFALSE;
        i += nSeq;
    }

    return XTRUE;
}

XSTATUS DirectGate_Mcp_AppendString(xbyte_buffer_t *pBuffer, const uint8_t *pData, size_t nLength)
{
    XCHECK_NL((pBuffer != NULL), XSTDINV);
    XCHECK_NL((pData != NULL || !nLength), XSTDINV);
    if (XByteBuffer_AddByte(pBuffer, '"') <= 0) return XSTDERR;

    static const uint8_t sReplacement[3] = { 0xEF, 0xBF, 0xBD };
    size_t nPlain = 0;

    for (size_t i = 0; i < nLength; )
    {
        uint8_t nByte = pData[i];
        const char *pEscape = NULL;
        char sEscape[8];

        if (nByte == '"') pEscape = "\\\"";
        else if (nByte == '\\') pEscape = "\\\\";
        else if (nByte == '\n') pEscape = "\\n";
        else if (nByte == '\r') pEscape = "\\r";
        else if (nByte == '\t') pEscape = "\\t";
        else if (nByte < 0x20)
        {
            snprintf(sEscape, sizeof(sEscape), "\\u%04x", (unsigned)nByte);
            pEscape = sEscape;
        }

        size_t nSeq = pEscape != NULL ? 1 : DirectGate_Mcp_Utf8Length(pData + i, nLength - i);
        if (pEscape == NULL && nSeq > 0)
        {
            nPlain += nSeq;
            i += nSeq;
            continue;
        }

        /* Whatever plain run came before goes out in one piece */
        if (nPlain && XByteBuffer_Add(pBuffer, pData + i - nPlain, nPlain) <= 0) return XSTDERR;
        nPlain = 0;

        if (pEscape != NULL && XByteBuffer_Add(pBuffer, (const uint8_t*)pEscape, strlen(pEscape)) <= 0) return XSTDERR;
        if (pEscape == NULL && XByteBuffer_Add(pBuffer, sReplacement, sizeof(sReplacement)) <= 0) return XSTDERR;
        i++;
    }

    if (nPlain && XByteBuffer_Add(pBuffer, pData + nLength - nPlain, nPlain) <= 0) return XSTDERR;
    return XByteBuffer_AddByte(pBuffer, '"') > 0 ? XSTDOK : XSTDERR;
}

static void DirectGate_Mcp_AddText(xbyte_buffer_t *pBuffer, const char *pText)
{
    XByteBuffer_Add(pBuffer, (const uint8_t*)pText, strlen(pText));
}

static void DirectGate_Mcp_AddQuoted(xbyte_buffer_t *pBuffer, const char *pText)
{
    DirectGate_Mcp_AppendString(pBuffer, (const uint8_t*)pText, strlen(pText));
}

static void DirectGate_Mcp_Respond(xbyte_buffer_t *pOut, const char *pId, const xbyte_buffer_t *pResult)
{
    DirectGate_Mcp_AddText(pOut, "{\"jsonrpc\":\"2.0\",\"id\":");
    DirectGate_Mcp_AddText(pOut, pId);
    DirectGate_Mcp_AddText(pOut, ",\"result\":");
    XByteBuffer_Add(pOut, pResult->pData, pResult->nUsed);
    DirectGate_Mcp_AddText(pOut, "}\n");
}

static void DirectGate_Mcp_Error(xbyte_buffer_t *pOut, const char *pId, int nCode, const char *pMessage)
{
    char sCode[32];
    snprintf(sCode, sizeof(sCode), "%d", nCode);

    DirectGate_Mcp_AddText(pOut, "{\"jsonrpc\":\"2.0\",\"id\":");
    DirectGate_Mcp_AddText(pOut, pId);
    DirectGate_Mcp_AddText(pOut, ",\"error\":{\"code\":");
    DirectGate_Mcp_AddText(pOut, sCode);
    DirectGate_Mcp_AddText(pOut, ",\"message\":");
    DirectGate_Mcp_AddQuoted(pOut, pMessage);
    DirectGate_Mcp_AddText(pOut, "}}\n");
}

/* A tool's answer: one text block for the model, the error flag, and the same facts as an object when there is one. */
static void DirectGate_Mcp_ToolResult(xbyte_buffer_t *pOut, const char *pId, const uint8_t *pText, size_t nText,
                                      xbool_t bError, const xbyte_buffer_t *pStructured)
{
    xbyte_buffer_t result;
    XByteBuffer_Init(&result, XSTDNON, XFALSE);

    DirectGate_Mcp_AddText(&result, "{\"content\":[{\"type\":\"text\",\"text\":");
    DirectGate_Mcp_AppendString(&result, pText, nText);
    DirectGate_Mcp_AddText(&result, "}],\"isError\":");
    DirectGate_Mcp_AddText(&result, bError ? "true" : "false");

    if (pStructured != NULL && pStructured->nUsed)
    {
        DirectGate_Mcp_AddText(&result, ",\"structuredContent\":");
        XByteBuffer_Add(&result, pStructured->pData, pStructured->nUsed);
    }

    DirectGate_Mcp_AddText(&result, "}");
    DirectGate_Mcp_Respond(pOut, pId, &result);
    XByteBuffer_Clear(&result);
}

static void DirectGate_Mcp_ToolError(xbyte_buffer_t *pOut, const char *pId, const char *pMessage)
{
    DirectGate_Mcp_ToolResult(pOut, pId, (const uint8_t*)pMessage, strlen(pMessage), XTRUE, NULL);
}

/* A string argument that is present and not empty; NULL otherwise. */
static const char* DirectGate_Mcp_Arg(xjson_obj_t *pArgs, const char *pName)
{
    xjson_obj_t *pObj = XJSON_GetObject(pArgs, pName);
    if (pObj == NULL || pObj->nType != XJSON_TYPE_STRING) return NULL;

    const char *pValue = XJSON_GetString(pObj);
    return xstrused(pValue) ? pValue : NULL;
}

static xbool_t DirectGate_Mcp_Flag(xjson_obj_t *pArgs, const char *pName)
{
    xjson_obj_t *pObj = XJSON_GetObject(pArgs, pName);
    return (pObj != NULL && pObj->nType == XJSON_TYPE_BOOLEAN && XJSON_GetBool(pObj)) ? XTRUE : XFALSE;
}

/*
    Connections kept open for the calls that ask for it (keep_open): one "dgcli session <device>" each, holding one
    authenticated session and its data channel, so that signalling and authentication happen once for many calls.
    Each call's words go to it as a request line and come back as an answer, as a one-shot child's would. A session
    ends itself after ten minutes idle or thirty alive; a dead one is noticed at its next call and opened again.
*/
typedef struct directgate_mcp_session_ {
    char sDevice[XSTR_MID];
    xexec_t exec;
    xbyte_buffer_t in;              /* What it wrote, not taken yet */
    xbyte_buffer_t log;             /* The tail of its own stderr, for when it fails */
    uint64_t nUsedMs;
    xbool_t bOpen;
} directgate_mcp_session_t;

static directgate_mcp_session_t g_mcpSessions[DIRECTGATE_MCP_SESSIONS_MAX];

/* The call being served: which device it is for, and whether its connection is to stay open after it */
static const char *g_pCallDevice;
static xbool_t g_bCallKeepOpen;

static xbool_t DirectGate_Mcp_WriteFd(XSOCKET nFd, const uint8_t *pData, size_t nLength)
{
    while (nLength > 0)
    {
        int nChunk = nLength > (size_t)INT_MAX ? INT_MAX : (int)nLength;
        int nWritten = DIRECTGATE_MCP_SOCK_WRITE(nFd, pData, nChunk);

        if (nWritten < 0 && errno == EINTR) continue;
        if (nWritten <= 0) return XFALSE;

        pData += nWritten;
        nLength -= (size_t)nWritten;
    }

    return XTRUE;
}

static void DirectGate_Mcp_CloseSession(directgate_mcp_session_t *pSession)
{
    if (!pSession->bOpen) return;

    /* Its stdin ending is its end; one that does not go in time is stopped */
    XExec_CloseStdIn(&pSession->exec);
    if (XExec_Wait(&pSession->exec, 2000) != XSTDOK)
    {
        XExec_Kill(&pSession->exec, SIGKILL);
        XExec_Wait(&pSession->exec, XEXEC_WAIT_FOREVER);
    }

    XExec_Close(&pSession->exec);
    XByteBuffer_Clear(&pSession->in);
    XByteBuffer_Clear(&pSession->log);
    memset(pSession, 0, sizeof(*pSession));
}

static void DirectGate_Mcp_CloseSessions(void)
{
    for (size_t i = 0; i < DIRECTGATE_MCP_SESSIONS_MAX; i++) DirectGate_Mcp_CloseSession(&g_mcpSessions[i]);
}

/* The open session for a device, if it is still alive */
static directgate_mcp_session_t* DirectGate_Mcp_FindSession(const char *pDevice)
{
    for (size_t i = 0; i < DIRECTGATE_MCP_SESSIONS_MAX; i++)
    {
        directgate_mcp_session_t *pSession = &g_mcpSessions[i];
        if (!pSession->bOpen || strcmp(pSession->sDevice, pDevice)) continue;
        if (XExec_Wait(&pSession->exec, 0) == XSTDNON) return pSession;

        DirectGate_Mcp_CloseSession(pSession);
        return NULL;
    }

    return NULL;
}

/* Reads what the session writes into in and the tail of its stderr into log, until nWant bytes are in or the time
   runs out. XFALSE when it ended or the time ran out first. */
static xbool_t DirectGate_Mcp_SessionFill(directgate_mcp_session_t *pSession, size_t nWant, uint64_t nDeadlineMs)
{
    while (pSession->in.nUsed < nWant)
    {
        uint64_t nNowMs = XTime_GetMonoMs();
        if (nNowMs >= nDeadlineMs) return XFALSE;

        directgate_mcp_pollfd_t fds[2];
        int nCount = 0;
        fds[nCount].fd = pSession->exec.nStdOut;
        fds[nCount].events = POLLIN;
        fds[nCount++].revents = 0;

        if (pSession->exec.nStdErr != XSOCK_INVALID)
        {
            fds[nCount].fd = pSession->exec.nStdErr;
            fds[nCount].events = POLLIN;
            fds[nCount++].revents = 0;
        }

        uint64_t nLeftMs = nDeadlineMs - nNowMs;
        if (DIRECTGATE_MCP_POLL(fds, nCount, nLeftMs > 1000 ? 1000 : (int)nLeftMs) <= 0) continue;

        uint8_t sBuffer[XFILE_CHUNK_SIZE];
        if (nCount > 1 && fds[1].revents)
        {
            int nRead = DIRECTGATE_MCP_SOCK_READ(pSession->exec.nStdErr, sBuffer, sizeof(sBuffer));
            if (nRead > 0)
            {
                XByteBuffer_Add(&pSession->log, sBuffer, (size_t)nRead);
                if (pSession->log.nUsed > DIRECTGATE_MCP_LOG_MAX)
                    XByteBuffer_Advance(&pSession->log, pSession->log.nUsed - DIRECTGATE_MCP_LOG_MAX);
            }
            else if (nRead == 0)
            {
                xclosesock(pSession->exec.nStdErr);
                pSession->exec.nStdErr = XSOCK_INVALID;
            }
        }

        if (fds[0].revents)
        {
            int nRead = DIRECTGATE_MCP_SOCK_READ(pSession->exec.nStdOut, sBuffer, sizeof(sBuffer));
            if (nRead <= 0 || XByteBuffer_Add(&pSession->in, sBuffer, (size_t)nRead) <= 0) return XFALSE;
        }
    }

    return XTRUE;
}

/* The line it wrote next, without its newline: the ready line, or an answer's header */
static xbool_t DirectGate_Mcp_SessionLine(directgate_mcp_session_t *pSession, size_t *pLength, uint64_t nDeadlineMs)
{
    for (;;)
    {
        const uint8_t *pNewline = pSession->in.nUsed ?
            (const uint8_t*)memchr(pSession->in.pData, '\n', pSession->in.nUsed) : NULL;
        if (pNewline != NULL)
        {
            *pLength = (size_t)(pNewline - pSession->in.pData);
            return XTRUE;
        }

        if (pSession->in.nUsed > XSTR_MID) return XFALSE;
        if (!DirectGate_Mcp_SessionFill(pSession, pSession->in.nUsed + 1, nDeadlineMs)) return XFALSE;
    }
}

/* A new session for the device, once it is open (its ready line). NULL when it could not open: nothing ran then, and
   the call runs on a connection of its own instead, *pTried saying why the session is not there. */
static directgate_mcp_session_t* DirectGate_Mcp_OpenSession(const char *pSelf, char *const *ppGlobals, int nGlobals,
                                                           const char *pDevice)
{
    directgate_mcp_session_t *pSession = NULL;
    for (size_t i = 0; i < DIRECTGATE_MCP_SESSIONS_MAX && pSession == NULL; i++)
        if (!g_mcpSessions[i].bOpen) pSession = &g_mcpSessions[i];

    /* All in use: the one used longest ago makes room */
    if (pSession == NULL)
    {
        pSession = &g_mcpSessions[0];
        for (size_t i = 1; i < DIRECTGATE_MCP_SESSIONS_MAX; i++)
            if (g_mcpSessions[i].nUsedMs < pSession->nUsedMs) pSession = &g_mcpSessions[i];
        DirectGate_Mcp_CloseSession(pSession);
    }

    char *pArgv[DIRECTGATE_MCP_GLOBALS_MAX + 4];
    size_t nArgs = 0;
    pArgv[nArgs++] = (char*)pSelf;
    pArgv[nArgs++] = (char*)"session";
    for (int i = 0; i < nGlobals; i++) pArgv[nArgs++] = ppGlobals[i];
    pArgv[nArgs++] = (char*)pDevice;
    pArgv[nArgs] = NULL;

    xexec_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.pPath = pSelf;
    opts.ppArgv = pArgv;
    opts.nFlags = XEXEC_STDIN | XEXEC_STDOUT | XEXEC_STDERR | XEXEC_GROUP | XEXEC_DIE_WITH_PARENT;

    memset(pSession, 0, sizeof(*pSession));
    XByteBuffer_Init(&pSession->in, XSTDNON, XFALSE);
    XByteBuffer_Init(&pSession->log, XSTDNON, XFALSE);
    if (XExec_Spawn(&pSession->exec, &opts) != XSTDOK) return NULL;

    xstrncpy(pSession->sDevice, sizeof(pSession->sDevice), pDevice);
    pSession->nUsedMs = XTime_GetMonoMs();
    pSession->bOpen = XTRUE;

    size_t nLine = 0;
    uint64_t nDeadlineMs = XTime_GetMonoMs() + DIRECTGATE_MCP_CONNECT_GRACE * 1000ULL;
    if (DirectGate_Mcp_SessionLine(pSession, &nLine, nDeadlineMs) && nLine == 14 &&
        !memcmp(pSession->in.pData, "{\"ready\":true}", 14))
    {
        XByteBuffer_Advance(&pSession->in, nLine + 1);
        return pSession;
    }

    if (pSession->log.nUsed) xlogn("A session for %s did not open: %.*s", pDevice, (int)pSession->log.nUsed, pSession->log.pData);
    DirectGate_Mcp_CloseSession(pSession);
    return NULL;
}

/* One call on an open session: its words as a request line, and the answer taken apart as a one-shot child's result.
   XSTDNON when the request never reached it, so nothing ran. When it ends or stops answering mid-call, the operation
   may or may not have run: the result says so, and the session is closed. */
static XSTATUS DirectGate_Mcp_SessionCall(directgate_mcp_session_t *pSession, const char *pVerb, const char *const *ppArgs,
                                          const uint8_t *pInput, size_t nInput, size_t nMax, uint32_t nTimeoutSec,
                                          xexec_result_t *pResult)
{
    xbyte_buffer_t request;
    XByteBuffer_Init(&request, XSTDNON, XFALSE);
    DirectGate_Mcp_AddText(&request, "{\"argv\":[");
    DirectGate_Mcp_AppendString(&request, (const uint8_t*)pVerb, strlen(pVerb));

    for (size_t i = 0; ppArgs[i] != NULL; i++)
    {
        DirectGate_Mcp_AddText(&request, ",");
        DirectGate_Mcp_AppendString(&request, (const uint8_t*)ppArgs[i], strlen(ppArgs[i]));
    }

    DirectGate_Mcp_AddText(&request, "]");
    if (pInput != NULL)
    {
        DirectGate_Mcp_AddText(&request, ",\"stdin\":");
        DirectGate_Mcp_AppendString(&request, pInput, nInput);
    }

    char sMax[48];
    snprintf(sMax, sizeof(sMax), ",\"max\":%zu}\n", nMax ? nMax : (size_t)DIRECTGATE_REMOTE_CAPTURE_MAX);
    DirectGate_Mcp_AddText(&request, sMax);

    pSession->nUsedMs = XTime_GetMonoMs();
    xbool_t bSent = DirectGate_Mcp_WriteFd(pSession->exec.nStdIn, request.pData, request.nUsed);
    XByteBuffer_Clear(&request);

    /* Gone before the request reached it - it ended itself between calls: nothing ran, and the call goes elsewhere */
    if (!bSent)
    {
        DirectGate_Mcp_CloseSession(pSession);
        return XSTDNON;
    }

    uint64_t nDeadlineMs = XTime_GetMonoMs() + (uint64_t)(nTimeoutSec + DIRECTGATE_MCP_SESSION_GRACE) * 1000ULL;
    size_t nLine = 0;
    xjson_t json;
    XSTATUS nStatus = XSTDERR;

    if (DirectGate_Mcp_SessionLine(pSession, &nLine, nDeadlineMs) &&
        XJSON_Parse(&json, NULL, (const char*)pSession->in.pData, nLine))
    {
        int nCode = XJSON_GetInt(XJSON_GetObject(json.pRootObj, "exitCode"));
        size_t nOut = (size_t)XJSON_GetU64(XJSON_GetObject(json.pRootObj, "stdout"));
        size_t nErr = (size_t)XJSON_GetU64(XJSON_GetObject(json.pRootObj, "stderr"));
        xbool_t bTruncated = XJSON_GetBool(XJSON_GetObject(json.pRootObj, "truncated")) ? XTRUE : XFALSE;
        XJSON_Destroy(&json);

        size_t nTotal = nLine + 1 + nOut + nErr;
        if (nOut <= DIRECTGATE_REMOTE_CAPTURE_MAX && nErr <= DIRECTGATE_REMOTE_CAPTURE_MAX &&
            DirectGate_Mcp_SessionFill(pSession, nTotal, nDeadlineMs))
        {
            const uint8_t *pBody = pSession->in.pData + nLine + 1;
            if (nOut) XByteBuffer_Add(&pResult->output, pBody, nOut);
            if (nErr) XByteBuffer_Add(&pResult->errors, pBody + nOut, nErr);
            XByteBuffer_Advance(&pSession->in, nTotal);

            pResult->nExitCode = nCode;
            pResult->bTruncated = bTruncated;
            nStatus = XSTDOK;
        }
    }

    pSession->nUsedMs = XTime_GetMonoMs();
    if (nStatus == XSTDOK) return XSTDOK;

    /* What the session was doing when it went cannot be known: the call says so, and the next one starts afresh */
    static const char sLost[] = "the connection to the device was lost during the call; the operation may or may not have run";
    XByteBuffer_Add(&pResult->errors, (const uint8_t*)sLost, sizeof(sLost) - 1);
    pResult->nExitCode = DIRECTGATE_REMOTE_EXIT_FAILED;
    DirectGate_Mcp_CloseSession(pSession);
    return XSTDOK;
}

/* Runs "dgcli <verb> <globals...> <args...>" to completion. XSTDOK when it ran, whatever it exited with. */
static XSTATUS DirectGate_Mcp_RunChild(const char *pSelf, char *const *ppGlobals, int nGlobals, const char *pVerb,
                                       const char *const *ppArgs, const uint8_t *pInput, size_t nInput, size_t nMax,
                                       uint32_t nTimeoutSec, xexec_result_t *pResult)
{
    char *pArgv[64];
    size_t nArgs = 0;

    pArgv[nArgs++] = (char*)pSelf;
    pArgv[nArgs++] = (char*)pVerb;
    for (int i = 0; i < nGlobals && nArgs + 1 < XARR_SIZE(pArgv); i++) pArgv[nArgs++] = ppGlobals[i];
    for (size_t i = 0; ppArgs[i] != NULL && nArgs + 1 < XARR_SIZE(pArgv); i++) pArgv[nArgs++] = (char*)ppArgs[i];
    pArgv[nArgs] = NULL;

    /* A call for a device with an open session, or one asked to stay open, goes to that session */
    XExec_ResultInit(pResult);
    for (int nTry = 0; g_pCallDevice != NULL && nTry < 2; nTry++)
    {
        directgate_mcp_session_t *pSession = DirectGate_Mcp_FindSession(g_pCallDevice);
        if (pSession == NULL && g_bCallKeepOpen) pSession = DirectGate_Mcp_OpenSession(pSelf, ppGlobals, nGlobals, g_pCallDevice);
        if (pSession == NULL) break;

        XSTATUS nStatus = DirectGate_Mcp_SessionCall(pSession, pVerb, ppArgs, pInput, nInput, nMax, nTimeoutSec, pResult);
        if (nStatus != XSTDNON) return nStatus;
    }

    xexec_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.pPath = pSelf;
    opts.ppArgv = pArgv;

    return XExec_Run(&opts, pInput, nInput, nMax, (int)((nTimeoutSec + DIRECTGATE_MCP_CONNECT_GRACE) * 1000U), pResult);
}

/* What a failed child said, or how it ended when it said nothing. */
static void DirectGate_Mcp_ChildFailure(xbyte_buffer_t *pOut, const char *pId, const xexec_result_t *pResult)
{
    if (pResult->errors.nUsed)
    {
        DirectGate_Mcp_ToolResult(pOut, pId, pResult->errors.pData, pResult->errors.nUsed, XTRUE, NULL);
        return;
    }

    char sMessage[XSTR_MIN];
    if (pResult->bTimedOut) xstrncpy(sMessage, sizeof(sMessage), "the operation did not finish in time");
    else xstrncpyf(sMessage, sizeof(sMessage), "dgcli exited with code %d", pResult->nExitCode);

    DirectGate_Mcp_ToolError(pOut, pId, sMessage);
}

/* Something a child would take for an option instead of an operand */
static xbool_t DirectGate_Mcp_IsOperand(const char *pValue)
{
    return (xstrused(pValue) && pValue[0] != '-') ? XTRUE : XFALSE;
}

/* A device the child can be told about in <device>:<path>: a colon in the name would move where the path starts */
static xbool_t DirectGate_Mcp_IsDevice(const char *pDevice)
{
    return (DirectGate_Mcp_IsOperand(pDevice) && strchr(pDevice, ':') == NULL) ? XTRUE : XFALSE;
}

static xbool_t DirectGate_Mcp_Spec(char *pOut, size_t nSize, const char *pDevice, const char *pPath)
{
    int nLength = snprintf(pOut, nSize, "%s:%s", pDevice, pPath);
    return (nLength > 0 && (size_t)nLength < nSize) ? XTRUE : XFALSE;
}

#ifdef _WIN32
#define DIRECTGATE_MCP_IS_SEP(c) ((c) == '/' || (c) == '\\')
#else
#define DIRECTGATE_MCP_IS_SEP(c) ((c) == '/')
#endif

/* The one directory upload and download may touch on this machine (--root), resolved once. Empty: none at all. */
static char g_sMcpRoot[XPATH_MAX];

/* The absolute path of something that exists, every link followed. On Windows it is normalised only: a link inside
   the root is the user's own, and no tool here can make one. */
static xbool_t DirectGate_Mcp_RealPath(const char *pPath, char *pOut, size_t nSize, xbool_t *pDirectory)
{
#ifdef _WIN32
    if (_fullpath(pOut, pPath, nSize) == NULL) return XFALSE;

    DWORD nAttributes = GetFileAttributesA(pOut);
    if (nAttributes == INVALID_FILE_ATTRIBUTES) return XFALSE;

    *pDirectory = (nAttributes & FILE_ATTRIBUTE_DIRECTORY) ? XTRUE : XFALSE;
    return XTRUE;
#else
    char *pReal = realpath(pPath, NULL);
    if (pReal == NULL) return XFALSE;

    struct stat st;
    xbool_t bOk = (strlen(pReal) < nSize && stat(pReal, &st) == 0) ? XTRUE : XFALSE;

    if (bOk)
    {
        xstrncpy(pOut, nSize, pReal);
        *pDirectory = S_ISDIR(st.st_mode) ? XTRUE : XFALSE;
    }

    free(pReal);
    return bOk;
#endif
}

/* The root itself or below it: the prefix has to end at a separator, so /data2 is not inside /data */
static xbool_t DirectGate_Mcp_IsInsideRoot(const char *pPath)
{
    size_t nRoot = strlen(g_sMcpRoot);
    XCHECK_NL((nRoot > 0), XFALSE);

#ifdef _WIN32
    if (_strnicmp(pPath, g_sMcpRoot, nRoot) != 0) return XFALSE;
#else
    if (strncmp(pPath, g_sMcpRoot, nRoot) != 0) return XFALSE;
#endif

    /* A root ending in a separator is the top of a file system, and the prefix already ends at one */
    return (DIRECTGATE_MCP_IS_SEP(g_sMcpRoot[nRoot - 1]) || pPath[nRoot] == XSTR_NUL ||
            DIRECTGATE_MCP_IS_SEP(pPath[nRoot])) ? XTRUE : XFALSE;
}

XSTATUS DirectGate_Mcp_SetRoot(const char *pRoot)
{
    g_sMcpRoot[0] = XSTR_NUL;
    XCHECK_NL((xstrused(pRoot)), XSTDOK);

    xbool_t bDirectory = XFALSE;
    if (DirectGate_Mcp_RealPath(pRoot, g_sMcpRoot, sizeof(g_sMcpRoot), &bDirectory) && bDirectory) return XSTDOK;

    g_sMcpRoot[0] = XSTR_NUL;
    return XSTDERR;
}

const char* DirectGate_Mcp_ResolveLocal(const char *pLocal, xbool_t bWrite, char *pOut, size_t nSize)
{
    if (!g_sMcpRoot[0]) return "local files are off: start dgcli mcp with --root <dir> to allow transfers in that directory";
    if (!xstrused(pLocal)) return "local_path is required";

    xbool_t bAbsolute = DIRECTGATE_MCP_IS_SEP(pLocal[0]) ||
        (isalpha((unsigned char)pLocal[0]) && pLocal[1] == ':' && DIRECTGATE_MCP_IS_SEP(pLocal[2]));

    /* A relative path is the root's: the model names files there, not in whatever directory dgcli was started in */
    char sPath[XPATH_MAX];
    const char *pSep = DIRECTGATE_MCP_IS_SEP(g_sMcpRoot[strlen(g_sMcpRoot) - 1]) ? "" : "/";
    int nLength = bAbsolute ? snprintf(sPath, sizeof(sPath), "%s", pLocal) :
        snprintf(sPath, sizeof(sPath), "%s%s%s", g_sMcpRoot, pSep, pLocal);
    if (nLength <= 0 || (size_t)nLength >= sizeof(sPath)) return "local_path is too long";

    /* What exists is judged by where it really is: a link out of the root, or a way out through .., is outside */
    xbool_t bDirectory = XFALSE;
    if (DirectGate_Mcp_RealPath(sPath, pOut, nSize, &bDirectory))
        return DirectGate_Mcp_IsInsideRoot(pOut) ? NULL : "local_path is outside the directory dgcli mcp was given";

    if (!bWrite) return "local_path does not exist";
    if (DIRECTGATE_MCP_IS_SEP(sPath[nLength - 1])) return "local_path names a directory that does not exist";

    /* A download's new file: the directory it goes in exists, inside the root, and what follows is a name */
    size_t nSep = (size_t)nLength;
    while (nSep > 0 && !DIRECTGATE_MCP_IS_SEP(sPath[nSep - 1])) nSep--;

    char sName[XPATH_MAX];
    xstrncpy(sName, sizeof(sName), sPath + nSep);
    if (!nSep || !strcmp(sName, ".") || !strcmp(sName, "..")) return "local_path does not name a file";

    /* The directory keeps its separator: "/" and "C:\" stay the tops they are, never "" or a drive's current one */
    char sParent[XPATH_MAX];
    sPath[nSep] = XSTR_NUL;

    if (!DirectGate_Mcp_RealPath(sPath, sParent, sizeof(sParent), &bDirectory) || !bDirectory)
        return "the directory local_path is in does not exist";

    if (!DirectGate_Mcp_IsInsideRoot(sParent)) return "local_path is outside the directory dgcli mcp was given";

    pSep = DIRECTGATE_MCP_IS_SEP(sParent[strlen(sParent) - 1]) ? "" : "/";
    nLength = snprintf(pOut, nSize, "%s%s%s", sParent, pSep, sName);
    return (nLength > 0 && (size_t)nLength < nSize) ? NULL : "local_path is too long";
}

static void DirectGate_Mcp_Exec(const char *pSelf, char *const *ppGlobals, int nGlobals, xjson_obj_t *pArgs,
                                const char *pId, xbyte_buffer_t *pOut)
{
    const char *pDevice = DirectGate_Mcp_Arg(pArgs, "device");
    const char *pCommand = DirectGate_Mcp_Arg(pArgs, "command");
    const char *pCwd = DirectGate_Mcp_Arg(pArgs, "cwd");
    const char *pStdin = DirectGate_Mcp_Arg(pArgs, "stdin");

    if (!DirectGate_Mcp_IsOperand(pDevice) || pCommand == NULL)
    {
        DirectGate_Mcp_ToolError(pOut, pId, "device and command are required");
        return;
    }

    uint32_t nTimeout = DIRECTGATE_MCP_EXEC_TIMEOUT;
    xjson_obj_t *pTimeout = XJSON_GetObject(pArgs, "timeout_seconds");
    if (pTimeout != NULL)
    {
        nTimeout = XJSON_GetU32(pTimeout);
        if (pTimeout->nType != XJSON_TYPE_NUMBER || nTimeout < 1 || nTimeout > DIRECTGATE_MCP_TIMEOUT_MAX)
        {
            DirectGate_Mcp_ToolError(pOut, pId, "timeout_seconds must be a whole number from 1 to 86400");
            return;
        }
    }

    char sTimeout[16];
    snprintf(sTimeout, sizeof(sTimeout), "%u", nTimeout);

    /* The device sends no more of each stream than is kept, so a command that prints without end does not fill the
       link for nothing. One byte over: output cut there arrives longer than what is kept, and is reported cut. */
    char sOutputMax[16];
    snprintf(sOutputMax, sizeof(sOutputMax), "%u", DIRECTGATE_MCP_OUTPUT_MAX + 1U);

    /* The command follows "--": whatever it looks like, it is the command */
    const char *pWithCwd[] = { "-t", sTimeout, "-o", sOutputMax, "-C", pCwd, pDevice, "--", pCommand, NULL };
    const char *pNoCwd[] = { "-t", sTimeout, "-o", sOutputMax, pDevice, "--", pCommand, NULL };

    xexec_result_t result;
    XSTATUS nStatus = DirectGate_Mcp_RunChild(pSelf, ppGlobals, nGlobals, "exec", pCwd != NULL ? pWithCwd : pNoCwd,
        (const uint8_t*)pStdin, pStdin != NULL ? strlen(pStdin) : 0, DIRECTGATE_MCP_OUTPUT_MAX, nTimeout, &result);

    if (nStatus != XSTDOK)
    {
        DirectGate_Mcp_ToolError(pOut, pId, "cannot run dgcli");
        XExec_ResultClear(&result);
        return;
    }

    /* For the model, the facts in reading order; for the client, the same as an object */
    char sHead[XSTR_MIN];
    xstrncpyf(sHead, sizeof(sHead), "exit code: %d%s", result.nExitCode,
        result.bTimedOut ? " (the call itself timed out and dgcli was stopped)" : "");

    xbyte_buffer_t text, data;
    XByteBuffer_Init(&text, XSTDNON, XFALSE);
    XByteBuffer_Init(&data, XSTDNON, XFALSE);

    DirectGate_Mcp_AddText(&text, sHead);
    if (result.output.nUsed)
    {
        DirectGate_Mcp_AddText(&text, "\n\n[stdout]\n");
        XByteBuffer_Add(&text, result.output.pData, result.output.nUsed);
    }

    if (result.errors.nUsed)
    {
        DirectGate_Mcp_AddText(&text, "\n\n[stderr]\n");
        XByteBuffer_Add(&text, result.errors.pData, result.errors.nUsed);
    }

    if (result.bTruncated) DirectGate_Mcp_AddText(&text, "\n\n[output cut at 128 KB per stream]");

    char sCode[32];
    snprintf(sCode, sizeof(sCode), "%d", result.nExitCode);
    DirectGate_Mcp_AddText(&data, "{\"exitCode\":");
    DirectGate_Mcp_AddText(&data, sCode);
    DirectGate_Mcp_AddText(&data, ",\"stdout\":");
    DirectGate_Mcp_AppendString(&data, result.output.pData, result.output.nUsed);
    DirectGate_Mcp_AddText(&data, ",\"stderr\":");
    DirectGate_Mcp_AppendString(&data, result.errors.pData, result.errors.nUsed);
    DirectGate_Mcp_AddText(&data, result.bTruncated ? ",\"truncated\":true}" : ",\"truncated\":false}");

    DirectGate_Mcp_ToolResult(pOut, pId, text.pData, text.nUsed, result.nExitCode != 0 ? XTRUE : XFALSE, &data);

    XByteBuffer_Clear(&text);
    XByteBuffer_Clear(&data);
    XExec_ResultClear(&result);
}

/* A child whose stdout is a JSON document of its own: handed back as text and as structured content. */
static void DirectGate_Mcp_JsonCall(const char *pSelf, char *const *ppGlobals, int nGlobals, const char *pVerb,
                                    const char *const *ppArgs, const char *pId, xbyte_buffer_t *pOut)
{
    xexec_result_t result;
    if (DirectGate_Mcp_RunChild(pSelf, ppGlobals, nGlobals, pVerb, ppArgs, NULL, 0, 0,
        DIRECTGATE_MCP_EXEC_TIMEOUT, &result) != XSTDOK)
    {
        DirectGate_Mcp_ToolError(pOut, pId, "cannot run dgcli");
        XExec_ResultClear(&result);
        return;
    }

    if (result.nExitCode != 0 || !result.output.nUsed)
    {
        DirectGate_Mcp_ChildFailure(pOut, pId, &result);
        XExec_ResultClear(&result);
        return;
    }

    /* One line of JSON, without the newline it ends with */
    while (result.output.nUsed && (result.output.pData[result.output.nUsed - 1] == '\n' ||
           result.output.pData[result.output.nUsed - 1] == '\r')) result.output.nUsed--;

    xjson_t json;
    xbool_t bValid = XJSON_Parse(&json, NULL, (const char*)result.output.pData, result.output.nUsed) ? XTRUE : XFALSE;
    if (bValid) XJSON_Destroy(&json);

    DirectGate_Mcp_ToolResult(pOut, pId, result.output.pData, result.output.nUsed, XFALSE, bValid ? &result.output : NULL);
    XExec_ResultClear(&result);
}

static void DirectGate_Mcp_ReadFile(const char *pSelf, char *const *ppGlobals, int nGlobals, xjson_obj_t *pArgs,
                                    const char *pId, xbyte_buffer_t *pOut)
{
    const char *pDevice = DirectGate_Mcp_Arg(pArgs, "device");
    const char *pPath = DirectGate_Mcp_Arg(pArgs, "path");
    char sSpec[XPATH_MAX + XSTR_MID];

    if (!DirectGate_Mcp_IsDevice(pDevice) || pPath == NULL || !DirectGate_Mcp_Spec(sSpec, sizeof(sSpec), pDevice, pPath))
    {
        DirectGate_Mcp_ToolError(pOut, pId, "device and path are required, and a device name cannot contain ':'");
        return;
    }

    const char *pChildArgs[] = { sSpec, "-", NULL };
    xexec_result_t result;

    if (DirectGate_Mcp_RunChild(pSelf, ppGlobals, nGlobals, "cp", pChildArgs, NULL, 0, DIRECTGATE_MCP_READ_MAX,
        DIRECTGATE_MCP_FILE_TIMEOUT, &result) != XSTDOK)
    {
        DirectGate_Mcp_ToolError(pOut, pId, "cannot run dgcli");
        XExec_ResultClear(&result);
        return;
    }

    if (result.nExitCode != 0) DirectGate_Mcp_ChildFailure(pOut, pId, &result);
    else if (result.bTruncated) DirectGate_Mcp_ToolError(pOut, pId, "the file is larger than 256 KB; use download instead");
    else if (!DirectGate_Mcp_IsText(result.output.pData, result.output.nUsed))
        DirectGate_Mcp_ToolError(pOut, pId, "the file is not UTF-8 text; use download instead");
    else DirectGate_Mcp_ToolResult(pOut, pId, result.output.pData, result.output.nUsed, XFALSE, NULL);

    XExec_ResultClear(&result);
}

/* An operation whose outcome is all there is to say: pDone on success, the child's own words otherwise. */
static void DirectGate_Mcp_SimpleCall(const char *pSelf, char *const *ppGlobals, int nGlobals, const char *pVerb,
                                      const char *const *ppArgs, const uint8_t *pInput, size_t nInput,
                                      const char *pDone, const char *pId, xbyte_buffer_t *pOut)
{
    xexec_result_t result;
    if (DirectGate_Mcp_RunChild(pSelf, ppGlobals, nGlobals, pVerb, ppArgs, pInput, nInput, DIRECTGATE_MCP_OUTPUT_MAX,
        DIRECTGATE_MCP_FILE_TIMEOUT, &result) != XSTDOK)
    {
        DirectGate_Mcp_ToolError(pOut, pId, "cannot run dgcli");
        XExec_ResultClear(&result);
        return;
    }

    if (result.nExitCode == 0) DirectGate_Mcp_ToolResult(pOut, pId, (const uint8_t*)pDone, strlen(pDone), XFALSE, NULL);
    else DirectGate_Mcp_ChildFailure(pOut, pId, &result);

    XExec_ResultClear(&result);
}

static void DirectGate_Mcp_CallTool(const char *pSelf, char *const *ppGlobals, int nGlobals, xjson_obj_t *pParams,
                                    const char *pId, xbyte_buffer_t *pOut);

/* A call runs on its device's open session when there is one, or opens one with keep_open;
   without keep_open the session goes once the call is done, as a one-shot call's connection does. */
static void DirectGate_Mcp_CallToolOn(const char *pSelf, char *const *ppGlobals, int nGlobals,
                                      xjson_obj_t *pParams, const char *pId, xbyte_buffer_t *pOut)
{
    const char *pName = XJSON_GetString(XJSON_GetObject(pParams, "name"));
    xjson_obj_t *pArgs = XJSON_GetObject(pParams, "arguments");
    if (pArgs != NULL && pArgs->nType != XJSON_TYPE_OBJECT) pArgs = NULL;
    const char *pDevice = DirectGate_Mcp_Arg(pArgs, "device");

    if (xstrcmp(pName, "disconnect"))
    {
        directgate_mcp_session_t *pSession = DirectGate_Mcp_IsOperand(pDevice) ? DirectGate_Mcp_FindSession(pDevice) : NULL;
        if (!DirectGate_Mcp_IsOperand(pDevice)) DirectGate_Mcp_ToolError(pOut, pId, "device is required");
        else if (pSession == NULL) DirectGate_Mcp_ToolResult(pOut, pId, (const uint8_t*)"no open connection", 18, XFALSE, NULL);
        else
        {
            DirectGate_Mcp_CloseSession(pSession);
            DirectGate_Mcp_ToolResult(pOut, pId, (const uint8_t*)"disconnected", 12, XFALSE, NULL);
        }

        return;
    }

    g_pCallDevice = DirectGate_Mcp_IsDevice(pDevice) ? pDevice : NULL;
    g_bCallKeepOpen = DirectGate_Mcp_Flag(pArgs, "keep_open");
    DirectGate_Mcp_CallTool(pSelf, ppGlobals, nGlobals, pParams, pId, pOut);

    directgate_mcp_session_t *pSession = g_pCallDevice != NULL ? DirectGate_Mcp_FindSession(g_pCallDevice) : NULL;
    if (pSession != NULL && !g_bCallKeepOpen) DirectGate_Mcp_CloseSession(pSession);

    g_pCallDevice = NULL;
    g_bCallKeepOpen = XFALSE;
}

static void DirectGate_Mcp_CallTool(const char *pSelf, char *const *ppGlobals, int nGlobals, xjson_obj_t *pParams,
                                    const char *pId, xbyte_buffer_t *pOut)
{
    const char *pName = XJSON_GetString(XJSON_GetObject(pParams, "name"));
    xjson_obj_t *pArgs = XJSON_GetObject(pParams, "arguments");
    if (pArgs != NULL && pArgs->nType != XJSON_TYPE_OBJECT) pArgs = NULL;

    const char *pDevice = DirectGate_Mcp_Arg(pArgs, "device");
    const char *pPath = DirectGate_Mcp_Arg(pArgs, "path");
    xbool_t bForce = DirectGate_Mcp_Flag(pArgs, "overwrite");
    char sDone[XPATH_MAX + 64];

    if (xstrcmp(pName, "list_devices"))
    {
        const char *pChildArgs[] = { "-j", NULL };
        DirectGate_Mcp_JsonCall(pSelf, ppGlobals, nGlobals, "devices", pChildArgs, pId, pOut);
        return;
    }

    if (xstrcmp(pName, "exec"))
    {
        DirectGate_Mcp_Exec(pSelf, ppGlobals, nGlobals, pArgs, pId, pOut);
        return;
    }

    if (xstrcmp(pName, "read_file"))
    {
        DirectGate_Mcp_ReadFile(pSelf, ppGlobals, nGlobals, pArgs, pId, pOut);
        return;
    }

    const char *pKnown[] = { "list_directory", "write_file", "upload", "download", "remove", "make_directory", "move" };
    size_t nKnown = 0;
    while (nKnown < XARR_SIZE(pKnown) && !xstrcmp(pName, pKnown[nKnown])) nKnown++;

    if (nKnown == XARR_SIZE(pKnown))
    {
        DirectGate_Mcp_Error(pOut, pId, DIRECTGATE_MCP_ERR_PARAMS, "unknown tool");
        return;
    }

    if (!DirectGate_Mcp_IsDevice(pDevice))
    {
        DirectGate_Mcp_ToolError(pOut, pId, "device is required, and a device name cannot contain ':' (use its id)");
        return;
    }

    char sSpec[XPATH_MAX + XSTR_MID];
    char sLocal[XPATH_MAX + 4];

    if (xstrcmp(pName, "list_directory") || xstrcmp(pName, "remove") || xstrcmp(pName, "make_directory") ||
        xstrcmp(pName, "write_file"))
    {
        if (pPath == NULL || !DirectGate_Mcp_Spec(sSpec, sizeof(sSpec), pDevice, pPath))
        {
            DirectGate_Mcp_ToolError(pOut, pId, "path is required");
            return;
        }
    }

    if (xstrcmp(pName, "list_directory"))
    {
        const char *pChildArgs[] = { "-j", sSpec, NULL };
        DirectGate_Mcp_JsonCall(pSelf, ppGlobals, nGlobals, "ls", pChildArgs, pId, pOut);
        return;
    }

    if (xstrcmp(pName, "write_file"))
    {
        xjson_obj_t *pContent = XJSON_GetObject(pArgs, "content");
        if (pContent == NULL || pContent->nType != XJSON_TYPE_STRING)
        {
            DirectGate_Mcp_ToolError(pOut, pId, "path and content are required");
            return;
        }

        /* The content arrives on the child's stdin */
        const char *pText = XJSON_GetString(pContent);
        const char *pForced[] = { "-f", "-", sSpec, NULL };
        const char *pPlain[] = { "-", sSpec, NULL };

        xstrncpyf(sDone, sizeof(sDone), "wrote %zu bytes to %s", strlen(pText), pPath);
        DirectGate_Mcp_SimpleCall(pSelf, ppGlobals, nGlobals, "cp", bForce ? pForced : pPlain,
            (const uint8_t*)pText, strlen(pText), sDone, pId, pOut);
        return;
    }

    if (xstrcmp(pName, "upload") || xstrcmp(pName, "download"))
    {
        const char *pLocalArg = DirectGate_Mcp_Arg(pArgs, "local_path");
        const char *pRemote = DirectGate_Mcp_Arg(pArgs, "remote_path");

        /* "-" would be this process's own stdin or stdout, which belong to the protocol */
        if (pLocalArg == NULL || pRemote == NULL || !strcmp(pLocalArg, "-") ||
            !DirectGate_Mcp_Spec(sSpec, sizeof(sSpec), pDevice, pRemote))
        {
            DirectGate_Mcp_ToolError(pOut, pId, "local_path and remote_path are required, and local_path cannot be -");
            return;
        }

        /* Only inside --root, and the child is handed the resolved, absolute path: no option, no <device>:, no link */
        xbool_t bUpload = xstrcmp(pName, "upload");
        const char *pRefused = DirectGate_Mcp_ResolveLocal(pLocalArg, bUpload ? XFALSE : XTRUE, sLocal, sizeof(sLocal));
        if (pRefused != NULL)
        {
            DirectGate_Mcp_ToolError(pOut, pId, pRefused);
            return;
        }

        const char *pFrom = bUpload ? sLocal : sSpec;
        const char *pTo = bUpload ? sSpec : sLocal;
        const char *pForced[] = { "-f", pFrom, pTo, NULL };
        const char *pPlain[] = { pFrom, pTo, NULL };

        xstrncpyf(sDone, sizeof(sDone), bUpload ? "uploaded %s to %s" : "downloaded %s to %s",
            bUpload ? sLocal : pRemote, bUpload ? pRemote : sLocal);

        DirectGate_Mcp_SimpleCall(pSelf, ppGlobals, nGlobals, "cp", bForce ? pForced : pPlain, NULL, 0, sDone, pId, pOut);
        return;
    }

    if (xstrcmp(pName, "move"))
    {
        const char *pFrom = DirectGate_Mcp_Arg(pArgs, "from");
        const char *pTo = DirectGate_Mcp_Arg(pArgs, "to");
        if (pFrom == NULL || pTo == NULL || !DirectGate_Mcp_Spec(sSpec, sizeof(sSpec), pDevice, pFrom))
        {
            DirectGate_Mcp_ToolError(pOut, pId, "from and to are required");
            return;
        }

        const char *pChildArgs[] = { sSpec, pTo, NULL };
        xstrncpyf(sDone, sizeof(sDone), "moved %s to %s", pFrom, pTo);
        DirectGate_Mcp_SimpleCall(pSelf, ppGlobals, nGlobals, "mv", pChildArgs, NULL, 0, sDone, pId, pOut);
        return;
    }

    /* remove, make_directory */
    xbool_t bRemove = xstrcmp(pName, "remove");
    const char *pRecursive[] = { "-r", sSpec, NULL };
    const char *pPlain[] = { sSpec, NULL };
    const char *const *ppArgs = (bRemove && DirectGate_Mcp_Flag(pArgs, "recursive")) ? pRecursive : pPlain;

    xstrncpyf(sDone, sizeof(sDone), bRemove ? "removed %s" : "created %s", pPath);
    DirectGate_Mcp_SimpleCall(pSelf, ppGlobals, nGlobals, bRemove ? "rm" : "mkdir", ppArgs, NULL, 0, sDone, pId, pOut);
}

static void DirectGate_Mcp_Initialize(xjson_obj_t *pParams, const char *pId, xbyte_buffer_t *pOut)
{
    /* The client's version when this server speaks it, otherwise the one it does, which the client may refuse */
    const char *pWanted = XJSON_GetString(XJSON_GetObject(pParams, "protocolVersion"));
    const char *pVersion = DIRECTGATE_MCP_DEFAULT_VERSION;

    for (size_t i = 0; i < XARR_SIZE(g_pMcpVersions); i++)
        if (xstrcmp(pWanted, g_pMcpVersions[i])) pVersion = g_pMcpVersions[i];

    xbyte_buffer_t result;
    XByteBuffer_Init(&result, XSTDNON, XFALSE);

    DirectGate_Mcp_AddText(&result, "{\"protocolVersion\":");
    DirectGate_Mcp_AddQuoted(&result, pVersion);
    DirectGate_Mcp_AddText(&result, ",\"capabilities\":{\"tools\":{\"listChanged\":false}},"
        "\"serverInfo\":{\"name\":\"dgcli\",\"title\":\"DirectGate\",\"version\":");
    DirectGate_Mcp_AddQuoted(&result, DirectGate_GetVersionShort());
    DirectGate_Mcp_AddText(&result, "},\"instructions\":");
    DirectGate_Mcp_AddQuoted(&result, g_pMcpInstructions);
    DirectGate_Mcp_AddText(&result, "}");

    DirectGate_Mcp_Respond(pOut, pId, &result);
    XByteBuffer_Clear(&result);
}

void DirectGate_Mcp_HandleLine(const char *pSelf, char *const *ppGlobals, int nGlobals,
                               const char *pLine, size_t nLength, xbyte_buffer_t *pOut)
{
    XCHECK_VOID_NL((pLine != NULL && pOut != NULL));
    while (nLength && isspace((unsigned char)pLine[nLength - 1])) nLength--;
    while (nLength && isspace((unsigned char)*pLine)) { pLine++; nLength--; }
    if (!nLength) return;

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, pLine, nLength))
    {
        DirectGate_Mcp_Error(pOut, "null", DIRECTGATE_MCP_ERR_PARSE, "parse error");
        return;
    }

    xjson_obj_t *pRoot = json.pRootObj;
    if (pRoot == NULL || pRoot->nType != XJSON_TYPE_OBJECT)
    {
        DirectGate_Mcp_Error(pOut, "null", DIRECTGATE_MCP_ERR_REQUEST, "a request is a JSON object");
        XJSON_Destroy(&json);
        return;
    }

    /* The id goes back exactly as it came: a string re-quoted, a number in its own digits */
    xjson_obj_t *pIdObj = XJSON_GetObject(pRoot, "id");
    xbyte_buffer_t id;
    XByteBuffer_Init(&id, XSTDNON, XFALSE);

    if (pIdObj != NULL && pIdObj->nType == XJSON_TYPE_STRING)
        DirectGate_Mcp_AddQuoted(&id, XJSON_GetString(pIdObj));
    else if (pIdObj != NULL && pIdObj->nType == XJSON_TYPE_NUMBER && pIdObj->pData != NULL)
        DirectGate_Mcp_AddText(&id, (const char*)pIdObj->pData);
    else
        DirectGate_Mcp_AddText(&id, "null");

    XByteBuffer_AddByte(&id, '\0');
    const char *pId = (const char*)id.pData;

    xbool_t bNotification = pIdObj == NULL ? XTRUE : XFALSE;
    const char *pMethod = XJSON_GetString(XJSON_GetObject(pRoot, "method"));
    xjson_obj_t *pParams = XJSON_GetObject(pRoot, "params");

    if (!xstrused(pMethod))
    {
        /* A response from the client to nothing this server asked, or a request without a method */
        if (!bNotification && XJSON_GetObject(pRoot, "result") == NULL && XJSON_GetObject(pRoot, "error") == NULL)
            DirectGate_Mcp_Error(pOut, pId, DIRECTGATE_MCP_ERR_REQUEST, "a request needs a method");
    }
    else if (bNotification)
    {
        /* notifications/initialized, notifications/cancelled: nothing to answer, nothing running to cancel */
    }
    else if (xstrcmp(pMethod, "initialize"))
    {
        DirectGate_Mcp_Initialize(pParams, pId, pOut);
    }
    else if (xstrcmp(pMethod, "ping"))
    {
        xbyte_buffer_t empty;
        XByteBuffer_Init(&empty, XSTDNON, XFALSE);
        DirectGate_Mcp_AddText(&empty, "{}");
        DirectGate_Mcp_Respond(pOut, pId, &empty);
        XByteBuffer_Clear(&empty);
    }
    else if (xstrcmp(pMethod, "tools/list"))
    {
        xbyte_buffer_t tools;
        XByteBuffer_Init(&tools, XSTDNON, XFALSE);
        DirectGate_Mcp_AddText(&tools, g_pMcpTools);
        DirectGate_Mcp_Respond(pOut, pId, &tools);
        XByteBuffer_Clear(&tools);
    }
    else if (xstrcmp(pMethod, "tools/call"))
    {
        if (pParams == NULL || pParams->nType != XJSON_TYPE_OBJECT)
            DirectGate_Mcp_Error(pOut, pId, DIRECTGATE_MCP_ERR_PARAMS, "tools/call needs params");
        else
            DirectGate_Mcp_CallToolOn(pSelf, ppGlobals, nGlobals, pParams, pId, pOut);
    }
    else
    {
        DirectGate_Mcp_Error(pOut, pId, DIRECTGATE_MCP_ERR_METHOD, "method not found");
    }

    XByteBuffer_Clear(&id);
    XJSON_Destroy(&json);
}

static xbool_t DirectGate_Mcp_SelfPath(char *pOut, size_t nSize, const char *pArgv0)
{
#if defined(__linux__)
    ssize_t nLength = readlink("/proc/self/exe", pOut, nSize - 1);
    if (nLength > 0 && (size_t)nLength < nSize - 1)
    {
        pOut[nLength] = '\0';
        return XTRUE;
    }
#elif defined(__APPLE__)
    uint32_t nLength = (uint32_t)nSize;
    if (_NSGetExecutablePath(pOut, &nLength) == 0) return XTRUE;
#elif defined(_WIN32)
    DWORD nLength = GetModuleFileNameA(NULL, pOut, (DWORD)nSize);
    if (nLength > 0 && nLength < nSize) return XTRUE;
#endif

#ifndef _WIN32
    /* Only a path that names the file: a bare name would be looked up in a PATH this process never searched */
    if (pArgv0 != NULL && strchr(pArgv0, '/') != NULL && realpath(pArgv0, pOut) != NULL) return XTRUE;
#else
    (void)pArgv0;
#endif

    return XFALSE;
}

static xbool_t DirectGate_Mcp_WriteAll(const uint8_t *pData, size_t nLength)
{
    while (nLength > 0)
    {
        int nChunk = nLength > (size_t)INT_MAX ? INT_MAX : (int)nLength;
        int nWritten = (int)DIRECTGATE_MCP_WRITE(1, pData, nChunk);
        if (nWritten < 0 && errno == EINTR) continue;
        if (nWritten <= 0) return XFALSE;

        pData += nWritten;
        nLength -= (size_t)nWritten;
    }

    return XTRUE;
}

int DirectGate_Mcp_Run(int argc, char *argv[])
{
    /* stdout is the protocol: every word of dgcli's own goes to stderr */
    xlog_stderr(XTRUE);

#ifndef _WIN32
    /* A session that ended itself is noticed by a write that fails, never by a signal that ends this process */
    signal(SIGPIPE, SIG_IGN);
#endif

    char sSelf[XPATH_MAX];
    if (!DirectGate_Mcp_SelfPath(sSelf, sizeof(sSelf), argc > 0 ? argv[0] : NULL))
    {
        fprintf(stderr, "dgcli: mcp: cannot find the dgcli binary to run the tools with\n");
        return DIRECTGATE_REMOTE_EXIT_FAILED;
    }

    /* The options every tool call is given: which config, which key, which API and relay */
    char *pGlobals[DIRECTGATE_MCP_GLOBALS_MAX];
    const char *pRoot = NULL;
    int nGlobals = 0;

    for (int i = 2; i < argc; i += 2)
    {
        const char *pOption = argv[i];

        /* This process's own: the tools it runs are handed resolved paths, never the root */
        if (!strcmp(pOption, "--root") && pRoot == NULL && i + 1 < argc)
        {
            pRoot = argv[i + 1];
            continue;
        }

        xbool_t bKnown = (!strcmp(pOption, "-c") || !strcmp(pOption, "-k") ||
                          !strcmp(pOption, "-a") || !strcmp(pOption, "-w")) ? XTRUE : XFALSE;

        if (!bKnown || i + 1 >= argc || nGlobals + 2 > DIRECTGATE_MCP_GLOBALS_MAX)
        {
            fprintf(stderr, "dgcli: mcp: only -c <config>, -k <key>, -a <api url>, -w <relay url> and one --root <dir> "
                "are taken\n");
            return DIRECTGATE_REMOTE_EXIT_FAILED;
        }

        pGlobals[nGlobals++] = argv[i];
        pGlobals[nGlobals++] = argv[i + 1];
    }

    /* Refused at the start rather than at the first transfer: a client that is told nothing would think it holds */
    if (pRoot != NULL && DirectGate_Mcp_SetRoot(pRoot) != XSTDOK)
    {
        fprintf(stderr, "dgcli: mcp: --root %s is not a directory\n", pRoot);
        return DIRECTGATE_REMOTE_EXIT_FAILED;
    }

#ifdef _WIN32
    _setmode(0, _O_BINARY);
    _setmode(1, _O_BINARY);
#endif

    xbyte_buffer_t input, output;
    XByteBuffer_Init(&input, XSTDNON, XFALSE);
    XByteBuffer_Init(&output, XSTDNON, XFALSE);

    uint8_t sChunk[XFILE_CHUNK_SIZE];
    xbool_t bOpen = XTRUE;
    xbool_t bOversized = XFALSE;

    while (bOpen)
    {
        int nRead = (int)DIRECTGATE_MCP_READ(0, sChunk, sizeof(sChunk));
        if (nRead < 0 && errno == EINTR) break;
        if (nRead <= 0) bOpen = XFALSE;
        else if (XByteBuffer_Add(&input, sChunk, (size_t)nRead) <= 0) break;

        /* Every complete line is a message; at the end of input, so is what remains */
        for (;;)
        {
            uint8_t *pNewline = input.nUsed ? (uint8_t*)memchr(input.pData, '\n', input.nUsed) : NULL;
            size_t nLine = pNewline != NULL ? (size_t)(pNewline - input.pData) : input.nUsed;
            if (pNewline == NULL && (bOpen || !input.nUsed)) break;

            if (!bOversized) DirectGate_Mcp_HandleLine(sSelf, pGlobals, nGlobals, (const char*)input.pData, nLine, &output);
            bOversized = XFALSE;
            XByteBuffer_Advance(&input, pNewline != NULL ? nLine + 1 : nLine);

            if (output.nUsed && !DirectGate_Mcp_WriteAll(output.pData, output.nUsed)) bOpen = XFALSE;
            XByteBuffer_Clear(&output);
            XByteBuffer_Init(&output, XSTDNON, XFALSE);
        }

        /* A line that never ends is answered once and its bytes dropped as they come */
        if (input.nUsed > DIRECTGATE_MCP_LINE_MAX)
        {
            DirectGate_Mcp_Error(&output, "null", DIRECTGATE_MCP_ERR_REQUEST, "request too large");
            DirectGate_Mcp_WriteAll(output.pData, output.nUsed);
            XByteBuffer_Clear(&output);
            XByteBuffer_Init(&output, XSTDNON, XFALSE);
            XByteBuffer_Clear(&input);
            XByteBuffer_Init(&input, XSTDNON, XFALSE);
            bOversized = XTRUE;
        }
    }

    DirectGate_Mcp_CloseSessions();
    XByteBuffer_Clear(&input);
    XByteBuffer_Clear(&output);
    return 0;
}
