/*!
 * @file directgate-agent/src/client/mcp.h
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

#ifndef __DIRECTGATE_CLIENT_MCP_H__
#define __DIRECTGATE_CLIENT_MCP_H__

#include "includes.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
    A Model Context Protocol server over stdio: newline-delimited JSON-RPC 2.0
    on stdin and stdout, nothing else on stdout, diagnostics on stderr. Its
    tools are dgcli's remote operations - list_devices, exec, list_directory,
    read_file, write_file, upload, download, remove, make_directory, move -
    and each call runs this same binary as a child ("dgcli exec ...", "dgcli
    get ..."), so a call gets a connection, an authentication and end-to-end
    keys of its own and nothing carries over between calls.

    It runs where the AI client runs, never on a server: the E2E keys and the
    client key stay on the machine that holds them. argv[2..] are the options
    every call is given (-c, -k, -a, -w), and --root <dir>, the one local
    directory upload and download may use. Returns the process exit code.
*/
int DirectGate_Mcp_Run(int argc, char *argv[]);

/* Appends pData as a JSON string literal, quotes included: control characters escaped and every byte sequence that
   is not valid UTF-8 replaced by U+FFFD, so whatever a remote program printed is a string a client can parse. */
XSTATUS DirectGate_Mcp_AppendString(xbyte_buffer_t *pBuffer, const uint8_t *pData, size_t nLength);

/* XTRUE when pData is valid UTF-8 without NUL bytes: text a model can be handed as it is. */
xbool_t DirectGate_Mcp_IsText(const uint8_t *pData, size_t nLength);

/* The directory upload and download may touch on this machine (--root), resolved here once with every link followed.
   NULL or empty turns local files off, which is how the server starts: a model steered by what a device printed can
   ask for any path, so it gets none until the user names one. XSTDERR, and local files off, when pRoot is no
   directory. */
XSTATUS DirectGate_Mcp_SetRoot(const char *pRoot);

/* Where an upload reads (bWrite XFALSE) or a download writes, in pOut as an absolute path: a relative pLocal is the
   root's, and the path, links followed, has to be inside the root. A download's file need not exist yet, but the
   directory it goes in must, inside the root. NULL when it holds, otherwise why not, for the model to read. */
const char* DirectGate_Mcp_ResolveLocal(const char *pLocal, xbool_t bWrite, char *pOut, size_t nSize);

/* Handles one request line and appends the response line (newline included) to pOut, or nothing for a
   notification. Exposed for tests; DirectGate_Mcp_Run feeds it stdin. pSelf is the dgcli binary tool calls run. */
void DirectGate_Mcp_HandleLine(const char *pSelf, char *const *ppGlobals, int nGlobals,
                               const char *pLine, size_t nLength, xbyte_buffer_t *pOut);

#ifdef __cplusplus
}
#endif

#endif /* __DIRECTGATE_CLIENT_MCP_H__ */
