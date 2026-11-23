/*!
 * @file directgate-agent/src/client/remote.h
 * @brief Non-interactive remote operations: commands and file management.
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

#ifndef __DIRECTGATE_CLIENT_REMOTE_H__
#define __DIRECTGATE_CLIENT_REMOTE_H__

#include "includes.h"
#include "protocol.h"
#include "transfer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* What dgcli exits with when it - not the remote command - failed: the connection, the sign-in, a refusal. 255 is
   what ssh uses for the same, so a script can tell the two apart; a file operation that fails exits with 1. */
#define DIRECTGATE_REMOTE_EXIT_FAILED   255
#define DIRECTGATE_REMOTE_EXIT_ERROR    1

#define DIRECTGATE_REMOTE_COMMAND_MAX   (64U * 1024U)
#define DIRECTGATE_REMOTE_TIMEOUT_MAX   4294967U    /* seconds, so that the milliseconds still fit 32 bits */

/* Upload chunks are sent while the link - the data channel, or the relay - has less than this queued, and again as
   it drains */
#define DIRECTGATE_REMOTE_TX_WINDOW     (1024U * 1024U)

/* How long an operation waits for its WebRTC data channel before it tells the agent WebRTC is impossible and takes
   the relay. Shorter than the agent's own wait (DIRECTGATE_BULK_CHANNEL_WAIT_MS): the client, which made the offer,
   decides. The relay carries an operation's data only when WebRTC cannot be established at all. */
#define DIRECTGATE_REMOTE_CHANNEL_WAIT_MS   10000U

typedef enum directgate_remote_op_ {
    DIRECTGATE_REMOTE_NONE = 0,
    DIRECTGATE_REMOTE_EXEC,                 /* exec <device> <command...>, as ssh does */
    DIRECTGATE_REMOTE_LIST,                 /* ls <device>:<path> (plain "ls" lists the devices) */
    DIRECTGATE_REMOTE_COPY,                 /* cp <from> <to>, as scp does: parsed into GET or PUT */
    DIRECTGATE_REMOTE_GET,                  /* cp <device>:<path> <local|-> */
    DIRECTGATE_REMOTE_PUT,                  /* cp <local|-> <device>:<path> */
    DIRECTGATE_REMOTE_REMOVE,               /* rm [-r] <device>:<path> */
    DIRECTGATE_REMOTE_MKDIR,                /* mkdir <device>:<path> */
    DIRECTGATE_REMOTE_MOVE,                 /* mv <device>:<path> <path> */
    DIRECTGATE_REMOTE_SESSION               /* session <device>: the others, one after another on one connection */
} directgate_remote_op_t;

/* A session's operation keeps at most this much of each output stream unless its request asks for less */
#define DIRECTGATE_REMOTE_CAPTURE_MAX   (16U * 1024U * 1024U)

/* A session request line: the operation's words, its stdin, and room for both */
#define DIRECTGATE_REMOTE_REQUEST_MAX   (32U * 1024U * 1024U)
#define DIRECTGATE_REMOTE_REQUEST_WORDS 64

/* A session ends after this long with nothing to do, and once it has lived this long - at the end of an operation,
   never in its middle: what the account may reach is checked again when the client connects anew */
#define DIRECTGATE_REMOTE_IDLE_MS       (10U * 60U * 1000U)
#define DIRECTGATE_REMOTE_LIFETIME_MS   (30U * 60U * 1000U)

/* What the command line asked for. Filled by DirectGate_Remote_ParseArgs, released by DirectGate_Remote_ReqClear. */
typedef struct directgate_remote_req_ {
    directgate_remote_op_t eOp;
    char *pCommand;                         /* exec: the words after the device, joined by spaces; owned */
    char sCwd[XPATH_MAX];                   /* exec -C: directory to run in */
    char sPath[XPATH_MAX];                  /* The remote path: listed, fetched, written, removed, created, moved */
    char sTarget[XPATH_MAX];                /* mv: where it goes */
    char sLocal[XPATH_MAX];                 /* cp: the local side, "-" for stdout / stdin */
    uint32_t nTimeoutMs;                    /* exec -t, 0 for none */
    uint32_t nOutputMax;                    /* exec -o, with bOutputMax: bytes of each output stream to keep */
    xbool_t bOutputMax;
    xbool_t bStdin;                         /* exec: local stdin is forwarded (it is not a terminal) */
    xbool_t bForce;                         /* cp -f: replace what is at the destination, either side */
    xbool_t bRecursive;                     /* rm -r: a directory with everything in it */
    xbool_t bJson;                          /* ls -j: the listing as JSON */
} directgate_remote_req_t;

/* Sends one protocol message on the session: the caller adds the counter, encrypts and routes it. */
typedef directgate_file_send_fn directgate_remote_send_fn;

typedef struct directgate_remote_ {
    const directgate_remote_req_t *pReq;
    directgate_remote_send_fn sendFn;
    void *pSendCtx;
    uint32_t nSessionId;

    directgate_transfer_t transfer;
    char sFinalPath[XPATH_MAX];             /* get: where the verified download goes */
    char sTempPath[XPATH_MAX];              /* get: written here first, renamed into place once verified */
    char sSpoolPath[XPATH_MAX];             /* put -: stdin collected here before the upload */

    int nOutFd;                             /* Where remote output and listings go, stdout normally */
    int nErrFd;                             /* Where errors and remote stderr go, stderr normally */

    /* A session's operation: what would go to stdout and stderr is kept here instead, at most nCaptureMax of each,
       and its stdin comes from the request (pStdinData) rather than from the process's own stdin */
    xbyte_buffer_t *pOutCapture;
    xbyte_buffer_t *pErrCapture;
    size_t nCaptureMax;
    const uint8_t *pStdinData;
    size_t nStdinData;
    xbool_t bTruncated;                     /* Output was cut: by -o, by the agent's outputMax, or by nCaptureMax */
    uint64_t nOutWritten;                   /* exec: bytes of each remote stream written, against -o */
    uint64_t nErrWritten;

    int nExitCode;
    xbool_t bStarted;                       /* The operation was sent */
    xbool_t bRunning;                       /* exec: the host confirmed the command started */
    const char *pPendingSignal;             /* exec: an interrupt that came before the start was confirmed */
    xbool_t bTransferDone;
    xbool_t bOpenDone;
    xbool_t bEofSent;
    xbool_t bDone;
} directgate_remote_t;

/* "exec", "cp", "rm", "mkdir", "mv": XTRUE and the operation, or XFALSE when pArg is none of them ("ls" is the
   device list until it is given a <device>:<path>, which the caller decides). pOp may be NULL to only ask. */
xbool_t DirectGate_Remote_ParseOp(const char *pArg, directgate_remote_op_t *pOp);
const char* DirectGate_Remote_OpName(directgate_remote_op_t eOp);

/* Takes the operation's own arguments, argv[nFirst] onwards. exec has had its device consumed already (pDevice);
   a file operation names it in its <device>:<path> and it is written to pDevice. XSTDOK, or XSTDERR after saying
   on stderr what was wrong. Remote paths must be absolute: a relative one would be resolved against whatever
   directory the agent process happens to run in. */
/* exec -o: a whole number of bytes, optionally K, M or G (1024-based), that fits 32 bits. XSTDERR otherwise. */
XSTATUS DirectGate_Remote_ParseSize(const char *pArg, uint32_t *pBytes);

/* Options are checked against the operation as typed: COPY, before it is resolved into GET or PUT */
XSTATUS DirectGate_Remote_CheckOptions(const directgate_remote_req_t *pReq, directgate_remote_op_t eOp);
XSTATUS DirectGate_Remote_ParseArgs(directgate_remote_req_t *pReq, directgate_remote_op_t eOp, int argc, char *argv[],
                                    int nFirst, char *pDevice, size_t nDeviceSize);
void DirectGate_Remote_ReqClear(directgate_remote_req_t *pReq);

/* Everything a request needs locally before a connection is worth opening: put checks its source, and put -
   collects stdin into a private temporary file. XSTDOK, or XSTDERR after saying why. */
XSTATUS DirectGate_Remote_Prepare(directgate_remote_t *pRemote);

void DirectGate_Remote_Init(directgate_remote_t *pRemote, const directgate_remote_req_t *pReq,
                            directgate_remote_send_fn sendFn, void *pSendCtx);

/* Removes what an unfinished operation left behind (a partial download, a stdin spool). */
void DirectGate_Remote_Clear(directgate_remote_t *pRemote);

/* Once authenticated, opens the session mode the operation needs (exec or file-manager). Before anything else: the
   agent sets up WebRTC for a session only once its mode is active, so the data channel is offered after this.
   bExecCapable is what the host's auth result said: a command is never sent to a host that did not offer it.
   XSTDOK, or XSTDERR when the operation ended here (bDone is set and the exit code says how). */
XSTATUS DirectGate_Remote_OpenMode(directgate_remote_t *pRemote, uint32_t nSessionId, xbool_t bExecCapable,
                                   xbool_t bRemoteCapable);

/* Sends the operation itself, on the route already decided */
XSTATUS DirectGate_Remote_Start(directgate_remote_t *pRemote);

/* A message from the host on this session. XAPI_CONTINUE, or XAPI_DISCONNECT once the operation is over. */
int DirectGate_Remote_HandleMessage(directgate_remote_t *pRemote, const directgate_pkg_t *pMsg);

/* The session ended under the operation: nothing more will arrive. */
void DirectGate_Remote_HandleClosed(directgate_remote_t *pRemote);

/* Ends the operation as failed for a reason of the client's own, said on stderr */
void DirectGate_Remote_Abort(directgate_remote_t *pRemote, const char *pReason);

/* A session request: one line of JSON, {"argv": [words], "stdin": "...", "max": n}. The words are those a one-shot
   dgcli takes after its own name - an operation, its options, its device and operands - and the device has to be
   the session's own. "stdin" feeds a command (or "cp - <device>:<path>"); "max" caps what is kept of each output
   stream. XSTDOK and the request, or XSTDERR with why in pError. */
XSTATUS DirectGate_Remote_ParseRequest(directgate_remote_req_t *pReq, const char *pLine, size_t nLength,
                                       const char *pDevice, xbyte_buffer_t *pStdin, size_t *pMax,
                                       char *pError, size_t nErrorSize);

/* A session's first line, once it is open: {"ready":true}. One that ends before writing it ran nothing. */
XSTATUS DirectGate_Remote_WriteReady(int nFd);

/* A session's answer: a line of JSON - exit code, how many bytes of stdout and of stderr follow, whether output was
   cut - then those bytes, stdout first. XSTDOK when all of it was written. */
XSTATUS DirectGate_Remote_WriteResponse(int nFd, int nExitCode, const xbyte_buffer_t *pOut, const xbyte_buffer_t *pErr,
                                        xbool_t bTruncated);

/* exec with stdin: bytes for the command, then its end of file. */
XSTATUS DirectGate_Remote_SendInput(directgate_remote_t *pRemote, const uint8_t *pData, size_t nLength);
XSTATUS DirectGate_Remote_SendEof(directgate_remote_t *pRemote);

/* Ctrl-C or SIGTERM: a running command gets the signal (INT or TERM) - its exit is still waited for; anything
   else is abandoned at once. XAPI_DISCONNECT when there is nothing left to wait for. */
int DirectGate_Remote_Interrupt(directgate_remote_t *pRemote, xbool_t bTerminate);

/* Moves an upload on while the link has room: nQueued is what the relay socket holds unsent. */
void DirectGate_Remote_Pump(directgate_remote_t *pRemote, size_t nQueued);

xbool_t DirectGate_Remote_IsDone(const directgate_remote_t *pRemote);
int DirectGate_Remote_ExitCode(const directgate_remote_t *pRemote);

#ifdef __cplusplus
}
#endif

#endif /* __DIRECTGATE_CLIENT_REMOTE_H__ */
