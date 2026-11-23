/*!
 * @file directgate-agent/src/agent/command.h
 * @brief Non-interactive command execution for "exec" sessions.
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

#ifndef __DIRECTGATE_COMMAND_H__
#define __DIRECTGATE_COMMAND_H__

#include "includes.h"
#include "protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

struct directgate_session_;

/* The command line a client may send, and the input it may have queued for a program that is not reading it */
#define DIRECTGATE_COMMAND_MAX_BYTES        (64U * 1024U)
#define DIRECTGATE_COMMAND_INPUT_MAX        (8U * 1024U * 1024U)

/* After the program exits, how long output still held open by something it started is read before the exit is
   reported, and how long the session then waits for its client to leave before closing it itself */
#define DIRECTGATE_COMMAND_GRACE_MS         500U
#define DIRECTGATE_COMMAND_LINGER_MS        5000U

/* How long the event loop may sleep for a command (DirectGate_CMD_GetWaitMs). Paused output is resumed within
   the shortest; an exit the system cannot announce is polled for from the shortest, backing off towards the
   longest as the wait goes on - an eighth of the time waited so far, so an exit is reported at most that much
   late, and never later than the longest. */
#define DIRECTGATE_COMMAND_WAIT_NONE        UINT32_MAX
#define DIRECTGATE_COMMAND_POLL_MIN_MS      5U
#define DIRECTGATE_COMMAND_POLL_MAX_MS      100U
#define DIRECTGATE_COMMAND_POLL_BACKOFF     8U

typedef enum directgate_command_state_ {
    DIRECTGATE_COMMAND_IDLE = 0,            /* Mode active, nothing started yet */
    DIRECTGATE_COMMAND_RUNNING,             /* Started; the exit has not been reported */
    DIRECTGATE_COMMAND_DONE                 /* Exit reported, waiting for the client to leave */
} directgate_command_state_t;

/*
    One command per session: an "exec" session starts a single program,
    streams its output, reports its exit and ends. The program runs as the
    account a terminal on this session would get (DirectGate_Term_ResolveShell),
    in a process group of its own so a signal, a timeout and a session that
    goes away all reach everything it started.

    Each piped stream is an event-loop endpoint, and so is the exit where the
    system can announce one (XEXEC_EXIT_FD): a program that has closed its
    output costs the loop nothing until it ends. Without one the exit is
    polled for (DirectGate_CMD_GetWaitMs). Those descriptors belong to the
    event loop once registered, which closes them, so they are moved out of
    the xexec_t at registration and only their numbers kept here, to route
    events by.

    A client that asked for at most nOutputMax bytes of each stream gets that
    much; the rest is read and dropped here, so the program runs exactly as
    it would with all of it read - never blocked, never cut off - and the
    link carries only what the client will use.
*/
typedef struct directgate_command_ {
    xexec_t exec;
    xbyte_buffer_t input;                   /* Queued for the program, not yet taken */

    xapi_session_t *pOutSession;
    xapi_session_t *pErrSession;
    xapi_session_t *pInSession;
    xapi_session_t *pExitSession;
    XSOCKET nOutFd;
    XSOCKET nErrFd;
    XSOCKET nInFd;
    XSOCKET nExitFd;

    directgate_command_state_t eState;
    uint64_t nStartMs;
    uint64_t nExitMs;                       /* When the exit was seen, for the output grace */
    uint64_t nDoneMs;                       /* When the exit was reported, for the linger */
    uint64_t nPollMs;                       /* When polling for the exit began, for the backoff; 0 not polling */
    uint64_t nOutSent;                      /* Bytes of each stream sent, against nOutputMax */
    uint64_t nErrSent;
    uint32_t nOutputMax;                    /* With bLimitOutput: bytes of each stream to send */
    uint32_t nTimeoutMs;                    /* 0: as long as it takes */

    xbool_t bInputEof;                      /* The client is done: stdin closes once the queue drains */
    xbool_t bReadPaused;                    /* Output not read while the transport is backed up */
    xbool_t bPaced;                         /* ... or while the relay's limit holds it: when is known, nothing to poll */
    xbool_t bLimitOutput;
    xbool_t bTruncated;                     /* Output past nOutputMax was dropped */
    xbool_t bTimedOut;
} directgate_command_t;

void DirectGate_CMD_Init(directgate_command_t *pCmd);

/* Stops whatever still runs - a hangup to its group, then SIGKILL, collected off the event loop - and releases
   the endpoints and the queued input. Called when the session goes away, at any point in its life. */
void DirectGate_CMD_Clear(directgate_command_t *pCmd);

xbool_t DirectGate_CMD_IsRunning(const directgate_command_t *pCmd);

/* How long the event loop may sleep before this command needs a pass that no event would bring: a paused stream
   to resume, an exit the system cannot announce, the end of the exit grace, a timeout. DIRECTGATE_COMMAND_WAIT_NONE
   when only events matter. */
uint32_t DirectGate_CMD_GetWaitMs(const directgate_command_t *pCmd, uint64_t nNowMs);

/* An "exec" message on an authenticated session in exec mode. Always XAPI_CONTINUE - the relay connection is never
   at stake - but a refusal that ends the session closes it here, so the caller must not touch it afterwards. */
int DirectGate_CMD_HandleMessage(struct directgate_session_ *pSession, const directgate_pkg_exec_t *pExec);

/* Event-loop routing: whether nFd is one of this command's endpoints, and what to do with its events */
xbool_t DirectGate_CMD_OwnsFd(const directgate_command_t *pCmd, XSOCKET nFd);
void DirectGate_CMD_OnRegistered(directgate_command_t *pCmd, xapi_session_t *pApiSession);
int DirectGate_CMD_OnRead(struct directgate_session_ *pSession, XSOCKET nFd);
int DirectGate_CMD_OnWrite(struct directgate_session_ *pSession, XSOCKET nFd);
void DirectGate_CMD_OnClosed(directgate_command_t *pCmd, XSOCKET nFd);

/* The event loop is about to close a stream whose writers are all gone - reported as a hangup on its own while
   reading is paused, so the data still in it would go with the descriptor. Bounded by what the pipe holds, it is
   read and sent now, past the backpressure that paused it. */
void DirectGate_CMD_OnHangup(struct directgate_session_ *pSession, XSOCKET nFd);

/* Once per event-loop pass: collects the exit, enforces the timeout, resumes paused output, reports the exit
   and closes a session whose client did not leave. XAPI_DISCONNECT when the session was closed here. The exit is
   collected on every pass whether or not its endpoint has fired: the endpoint only decides how soon a pass comes. */
int DirectGate_CMD_Check(struct directgate_session_ *pSession, uint64_t nNowMs);

#ifdef __cplusplus
}
#endif

#endif /* __DIRECTGATE_COMMAND_H__ */
