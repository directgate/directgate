/*!
 * @file directgate-agent/src/agent/command.c
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

#include "command.h"
#include "session.h"
#include "webrtc.h"
#include "term.h"

#ifndef SIGHUP
#define SIGHUP  1
#endif

#ifndef SIGKILL
#define SIGKILL 9
#endif

/* Output read per event and per pass, and how far the transport may fall behind before the program's output is
   no longer read: the program then blocks on a full pipe, the flow control a local pipeline has. */
#define DIRECTGATE_COMMAND_READ_SIZE        (16U * 1024U)
#define DIRECTGATE_COMMAND_READ_BUDGET      16
#define DIRECTGATE_COMMAND_DRAIN_ROUNDS     64
#define DIRECTGATE_COMMAND_TX_HIGH_WATER    (4U * 1024U * 1024U)
#define DIRECTGATE_COMMAND_TX_LOW_WATER     (1U * 1024U * 1024U)

static int DirectGate_CMD_GetWsFd(const directgate_session_t *pSession)
{
    return (pSession != NULL && pSession->pWsSession != NULL) ? (int)pSession->pWsSession->sock.nFD : XSTDERR;
}

void DirectGate_CMD_Init(directgate_command_t *pCmd)
{
    XCHECK_VOID_NL((pCmd != NULL));
    memset(pCmd, 0, sizeof(*pCmd));

    XExec_Init(&pCmd->exec);
    XByteBuffer_Init(&pCmd->input, XSTDNON, XFALSE);

    pCmd->nOutFd = XSOCK_INVALID;
    pCmd->nErrFd = XSOCK_INVALID;
    pCmd->nInFd = XSOCK_INVALID;
    pCmd->nExitFd = XSOCK_INVALID;
    pCmd->eState = DIRECTGATE_COMMAND_IDLE;
}

xbool_t DirectGate_CMD_IsRunning(const directgate_command_t *pCmd)
{
    XCHECK_NL((pCmd != NULL), XFALSE);
    return pCmd->eState == DIRECTGATE_COMMAND_RUNNING ? XTRUE : XFALSE;
}

/* Nothing will announce the exit: no exit endpoint, and no output stream whose end of file would bring a pass */
static xbool_t DirectGate_CMD_NeedsPoll(const directgate_command_t *pCmd)
{
    return (!pCmd->exec.bExited && pCmd->nExitFd == XSOCK_INVALID &&
            pCmd->nOutFd == XSOCK_INVALID && pCmd->nErrFd == XSOCK_INVALID) ? XTRUE : XFALSE;
}

/* At least a millisecond: a pass that is already due comes at once, and a state that has not moved on yet cannot
   turn the loop into a spin */
static uint32_t DirectGate_CMD_Until(uint64_t nDueMs, uint64_t nNowMs)
{
    if (nDueMs <= nNowMs) return 1;
    uint64_t nLeft = nDueMs - nNowMs;
    return nLeft < DIRECTGATE_COMMAND_WAIT_NONE ? (uint32_t)nLeft : DIRECTGATE_COMMAND_WAIT_NONE - 1;
}

uint32_t DirectGate_CMD_GetWaitMs(const directgate_command_t *pCmd, uint64_t nNowMs)
{
    XCHECK_NL((pCmd != NULL), DIRECTGATE_COMMAND_WAIT_NONE);
    XCHECK_NL((pCmd->eState == DIRECTGATE_COMMAND_RUNNING), DIRECTGATE_COMMAND_WAIT_NONE);

    /* The transport drains without telling anyone: paused output is looked at again soon. Output held below the relay's
       limit only is due at a time the session knows (DirectGate_Session_GetBulkWaitMs). */
    if (pCmd->bReadPaused) return pCmd->bPaced ? DIRECTGATE_COMMAND_WAIT_NONE : DIRECTGATE_COMMAND_POLL_MIN_MS;

    /* Output that ends is an event; the end of the grace is not */
    if (pCmd->exec.bExited) return DirectGate_CMD_Until(pCmd->nExitMs + DIRECTGATE_COMMAND_GRACE_MS, nNowMs);

    uint32_t nWaitMs = DIRECTGATE_COMMAND_WAIT_NONE;
    if (pCmd->nTimeoutMs && !pCmd->bTimedOut) nWaitMs = DirectGate_CMD_Until(pCmd->nStartMs + pCmd->nTimeoutMs, nNowMs);

    if (DirectGate_CMD_NeedsPoll(pCmd))
    {
        uint64_t nWaited = (pCmd->nPollMs && nNowMs > pCmd->nPollMs) ? nNowMs - pCmd->nPollMs : 0;
        uint64_t nPollMs = nWaited / DIRECTGATE_COMMAND_POLL_BACKOFF;

        if (nPollMs < DIRECTGATE_COMMAND_POLL_MIN_MS) nPollMs = DIRECTGATE_COMMAND_POLL_MIN_MS;
        if (nPollMs > DIRECTGATE_COMMAND_POLL_MAX_MS) nPollMs = DIRECTGATE_COMMAND_POLL_MAX_MS;
        if (nPollMs < nWaitMs) nWaitMs = (uint32_t)nPollMs;
    }

    return nWaitMs;
}

xbool_t DirectGate_CMD_OwnsFd(const directgate_command_t *pCmd, XSOCKET nFd)
{
    XCHECK_NL((pCmd != NULL), XFALSE);
    XCHECK_NL((nFd != XSOCK_INVALID), XFALSE);
    return (nFd == pCmd->nOutFd || nFd == pCmd->nErrFd || nFd == pCmd->nInFd || nFd == pCmd->nExitFd) ? XTRUE : XFALSE;
}

/* A remote session runs one command after another: one reported, it is ready for the next. Its endpoints are gone
   already - dropping one runs its closed callback at once - and its program has been collected. */
static void DirectGate_CMD_Ready(directgate_command_t *pCmd)
{
    XExec_Close(&pCmd->exec);
    XByteBuffer_Clear(&pCmd->input);
    DirectGate_CMD_Init(pCmd);
}

/* The endpoint closes its descriptor, and its closed callback (DirectGate_CMD_OnClosed) clears the route. */
static void DirectGate_CMD_DropEndpoint(xapi_session_t **ppSession)
{
    if (*ppSession == NULL) return;
    xapi_session_t *pApiSession = *ppSession;
    *ppSession = NULL;
    XAPI_Disconnect(pApiSession);
}

void DirectGate_CMD_Clear(directgate_command_t *pCmd)
{
    XCHECK_VOID_NL((pCmd != NULL));

    if (pCmd->exec.nPid > 0 && !pCmd->exec.bExited)
    {
        xlogd("Stopping command that is still running: pid(%d)", (int)pCmd->exec.nPid);

#ifdef _WIN32
        XExec_Kill(&pCmd->exec, SIGKILL);
#else
        /* The terminal's own shutdown: hangup to the group, then SIGKILL, collected off the event loop. The first
           hangup goes through XExec_Kill, which still reaches a child that has not set up its group yet. */
        XExec_Kill(&pCmd->exec, SIGHUP);
        DirectGate_Term_HangupProcess((pid_t)pCmd->exec.nPid);
        pCmd->exec.nPid = XSTDERR;
#endif
    }

    DirectGate_CMD_DropEndpoint(&pCmd->pOutSession);
    DirectGate_CMD_DropEndpoint(&pCmd->pErrSession);
    DirectGate_CMD_DropEndpoint(&pCmd->pInSession);
    DirectGate_CMD_DropEndpoint(&pCmd->pExitSession);

    /* Whatever was never handed to the event loop */
    XExec_Close(&pCmd->exec);
    XByteBuffer_Clear(&pCmd->input);

    pCmd->nOutFd = XSOCK_INVALID;
    pCmd->nErrFd = XSOCK_INVALID;
    pCmd->nInFd = XSOCK_INVALID;
    pCmd->nExitFd = XSOCK_INVALID;
    pCmd->bReadPaused = XFALSE;
    pCmd->bPaced = XFALSE;
}

static int DirectGate_CMD_SignalFromName(const char *pName)
{
    XCHECK_NL((xstrused(pName)), XSTDNON);
    if (xstrcmp(pName, "INT")) return SIGINT;
    if (xstrcmp(pName, "TERM")) return SIGTERM;
    if (xstrcmp(pName, "KILL")) return SIGKILL;
    if (xstrcmp(pName, "HUP")) return SIGHUP;
    return XSTDNON;
}

static const char* DirectGate_CMD_SignalName(int nSignal)
{
    if (nSignal == SIGINT) return "INT";
    if (nSignal == SIGTERM) return "TERM";
    if (nSignal == SIGKILL) return "KILL";
    if (nSignal == SIGHUP) return "HUP";
#ifndef _WIN32
    if (nSignal == SIGQUIT) return "QUIT";
    if (nSignal == SIGPIPE) return "PIPE";
    if (nSignal == SIGSEGV) return "SEGV";
    if (nSignal == SIGABRT) return "ABRT";
#endif
    return NULL;
}

/* What a running command sends - its start, its output, its exit - is bulk data on the one route its start took
   (see DirectGate_Session_GetBulkRoute), so nothing of it is overtaken by a later message on another transport */
static int DirectGate_CMD_Send(directgate_session_t *pSession, xjson_obj_t *pHeader, const uint8_t *pData, size_t nLength)
{
    directgate_bulk_route_t eRoute = DirectGate_Session_GetBulkRoute(pSession, XTime_GetMonoMs());
    if (eRoute == DIRECTGATE_BULK_WAIT) return XSTDERR;

    /* A channel lost midway is the end of the command (DirectGate_CMD_Check), never a move to the relay */
    if (pSession->eBulkPin == DIRECTGATE_BULK_CHANNEL && eRoute != DIRECTGATE_BULK_CHANNEL) return XSTDERR;

    return DirectGate_Session_SendBulk(pSession, eRoute, pHeader, pData, nLength);
}

static int DirectGate_CMD_SendStarted(directgate_session_t *pSession, const char *pStatus, const char *pReason)
{
    xjson_obj_t *pHeader = DirectGate_Proto_BuildExec("started", pStatus, pReason, pSession->nSessionId);
    XCHECK((pHeader != NULL), xthrowr(XSTDERR, "Proto: Failed to build exec started header"));

    /* A refusal is not bulk data: nothing of the command follows it */
    xbool_t bStarted = xstrcmp(pStatus, "ok");
    if (bStarted) XJSON_AddInt(pHeader, "pid", (int)pSession->command.exec.nPid);

    int nStatus = bStarted ? DirectGate_CMD_Send(pSession, pHeader, NULL, XSTDNON) :
        DirectGate_Session_Send(pSession, pHeader, NULL, XSTDNON);

    XJSON_FreeObject(pHeader);
    return nStatus;
}

/* Refuses a request without ending anything: the session stays as it was. */
static int DirectGate_CMD_Refuse(directgate_session_t *pSession, const char *pReason)
{
    xlogw("Command request refused: sid(%u), wsfd(%d), reason(%s)",
        pSession->nSessionId, DirectGate_CMD_GetWsFd(pSession), pReason);

    if (DirectGate_CMD_SendStarted(pSession, "failed", pReason) < 0)
        return DirectGate_Session_Close(pSession, "command answer failed");

    return XAPI_CONTINUE;
}

static xbool_t DirectGate_CMD_IsBacklogged(const directgate_session_t *pSession, size_t nLimit)
{
    /* The transport the output takes: pinned to the relay, it is the relay's queue that counts */
    if (pSession->eBulkPin != DIRECTGATE_BULK_RELAY && DirectGate_WebRTC_IsConnected(&pSession->webrtc))
    {
        int nBuffered = DirectGate_WebRTC_GetBufferedAmount(&pSession->webrtc);
        return (nBuffered > 0 && (size_t)nBuffered > nLimit) ? XTRUE : XFALSE;
    }

    return (pSession->pWsSession != NULL && pSession->pWsSession->txBuffer.nUsed > nLimit) ? XTRUE : XFALSE;
}

/* Output on the relay keeps below the relay's limit: the session's bucket says when the next may go */
static xbool_t DirectGate_CMD_IsPaced(const directgate_session_t *pSession)
{
    XCHECK_NL((pSession->eBulkPin == DIRECTGATE_BULK_RELAY), XFALSE);
    XCHECK_NL((pSession->pMgr != NULL && pSession->pMgr->nRelayRateBytes), XFALSE);
    return DirectGate_Session_GetRelayWaitMs(pSession, XTime_GetMonoMs()) ? XTRUE : XFALSE;
}

/* A directory the client names is resolved by nobody but the system: relative, it would mean wherever the agent
   process happens to run. */
static xbool_t DirectGate_CMD_IsAbsolute(const char *pPath)
{
#ifdef _WIN32
    if (pPath[0] == '\\' && pPath[1] == '\\') return XTRUE;
    return (isalpha((unsigned char)pPath[0]) && pPath[1] == ':' && (pPath[2] == '\\' || pPath[2] == '/')) ? XTRUE : XFALSE;
#else
    return pPath[0] == '/' ? XTRUE : XFALSE;
#endif
}

#ifndef _WIN32
/* No terminal behind the program's streams: TERM says so, where the PTY's environment names xterm. */
static void DirectGate_CMD_SetDumbTerm(char **ppEnv)
{
    for (size_t i = 0; ppEnv != NULL && ppEnv[i] != NULL; i++)
    {
        if (strncmp(ppEnv[i], "TERM=", 5)) continue;

        char *pDumb = strdup("TERM=dumb");
        if (pDumb == NULL) return;

        free(ppEnv[i]);
        ppEnv[i] = pDumb;
        return;
    }
}

static XSTATUS DirectGate_CMD_Spawn(directgate_session_t *pSession, const directgate_pkg_exec_t *pExec)
{
    directgate_command_t *pCmd = &pSession->command;

    directgate_term_spawn_t spawn;
    if (DirectGate_Term_ResolveShell(&pSession->term, &spawn) < 0) return XSTDERR;
    DirectGate_CMD_SetDumbTerm(spawn.ppEnv);

    char *aArgv[] = { spawn.sArg0, (char*)"-c", (char*)pExec->pCommand, NULL };

    /* A directory the client named is never swapped for another: a command meant for one directory must not
       run in a different one. Only the default, the account's home, falls back to / the way login does. */
    xexec_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.pPath = spawn.sShell;
    opts.ppArgv = aArgv;
    opts.ppEnv = spawn.ppEnv;
    opts.pWorkDir = xstrused(pExec->pCwd) ? pExec->pCwd : spawn.sWorkDir;
    opts.pWorkDirFallback = xstrused(pExec->pCwd) ? NULL : "/";
    opts.nFlags = XEXEC_STDOUT | XEXEC_STDERR | XEXEC_GROUP | XEXEC_NONBLOCK | XEXEC_DIE_WITH_PARENT | XEXEC_EXIT_FD;
    if (pExec->bStdin) opts.nFlags |= XEXEC_STDIN;

    opts.bSetIdentity = spawn.bSwitchUser;
    opts.nUid = spawn.nUid;
    opts.nGid = spawn.nGid;
    opts.pGroups = spawn.pGroups;
    opts.nGroups = spawn.nGroups > 0 ? (size_t)spawn.nGroups : 0;

    XSTATUS nStatus = XExec_Spawn(&pCmd->exec, &opts);
    int nError = errno;

    DirectGate_Term_FreeSpawn(&spawn);
    errno = nError;
    return nStatus;
}
#else
static XSTATUS DirectGate_CMD_Spawn(directgate_session_t *pSession, const directgate_pkg_exec_t *pExec)
{
    directgate_command_t *pCmd = &pSession->command;
    XCHECK_NL((DirectGate_Term_ValidateShellUser(&pSession->term) == XSTDOK), XSTDERR);

    /* /s: cmd.exe takes everything between the first and the last quote as the command, as typed */
    const char *pComSpec = getenv("COMSPEC");
    size_t nLen = strlen(pExec->pCommand) + (xstrused(pComSpec) ? strlen(pComSpec) : 7) + 32;

    char *pCmdLine = (char*)malloc(nLen);
    XCHECK_NL((pCmdLine != NULL), XSTDERR);

    xstrncpyf(pCmdLine, nLen, "\"%s\" /d /s /c \"%s\"", xstrused(pComSpec) ? pComSpec : "cmd.exe", pExec->pCommand);
    const char *pHome = xstrused(pSession->term.sShellHome) ? pSession->term.sShellHome : NULL;

    xexec_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.pPath = xstrused(pComSpec) ? pComSpec : NULL;
    opts.pCmdLine = pCmdLine;
    opts.pWorkDir = xstrused(pExec->pCwd) ? pExec->pCwd : pHome;
    opts.pWorkDirFallback = xstrused(pExec->pCwd) ? NULL : getenv("USERPROFILE");
    opts.nFlags = XEXEC_STDOUT | XEXEC_STDERR | XEXEC_GROUP | XEXEC_NONBLOCK | XEXEC_DIE_WITH_PARENT | XEXEC_EXIT_FD;
    if (pExec->bStdin) opts.nFlags |= XEXEC_STDIN;

    XSTATUS nStatus = XExec_Spawn(&pCmd->exec, &opts);
    free(pCmdLine);
    return nStatus;
}
#endif

/* Hands one of the program's streams to the event loop, which owns the descriptor from here on whether the
   registration succeeds or not: a failed registration has closed it already. */
static XSTATUS DirectGate_CMD_AddEndpoint(directgate_session_t *pSession, XSOCKET *pExecFd, XSOCKET *pRouteFd)
{
    XSOCKET nFd = *pExecFd;
    if (nFd == XSOCK_INVALID) return XSTDNON;

    *pExecFd = XSOCK_INVALID;
    *pRouteFd = nFd;

    xapi_endpoint_t endpt;
    XAPI_InitEndpoint(&endpt);

    endpt.eType = XAPI_EVENT;
    endpt.eRole = XAPI_CUSTOM;
    endpt.nEvents = XPOLLIN;
    endpt.bUnix = XTRUE;
    endpt.nFD = nFd;
    endpt.pSessionData = pSession;

    if (XAPI_AddEndpoint(pSession->pWsSession->pApi, &endpt) < 0)
    {
        *pRouteFd = XSOCK_INVALID;
        return XSTDERR;
    }

    return XSTDOK;
}

static int DirectGate_CMD_Start(directgate_session_t *pSession, const directgate_pkg_exec_t *pExec)
{
    directgate_command_t *pCmd = &pSession->command;

    /* An exec session runs one command; a remote session one after another, never two at once */
    xbool_t bRemote = pSession->eActiveMode == DIRECTGATE_SESSION_MODE_REMOTE ? XTRUE : XFALSE;

    const char *pRefusal = NULL;
    if (bRemote && pCmd->eState == DIRECTGATE_COMMAND_RUNNING) pRefusal = "a command is already running";
    else if (pCmd->eState != DIRECTGATE_COMMAND_IDLE) pRefusal = "a command has already run on this session";
    else if (!xstrused(pExec->pCommand)) pRefusal = "command is required";
    else if (strlen(pExec->pCommand) > DIRECTGATE_COMMAND_MAX_BYTES) pRefusal = "command is too long";
    else if (pExec->pCwd != NULL && strlen(pExec->pCwd) >= XPATH_MAX) pRefusal = "working directory is too long";
    else if (xstrused(pExec->pCwd) && !DirectGate_CMD_IsAbsolute(pExec->pCwd)) pRefusal = "working directory must be an absolute path";
    else if (pExec->bBadOutputMax) pRefusal = "outputMax must be a whole number of bytes";
    if (pRefusal != NULL) return DirectGate_CMD_Refuse(pSession, pRefusal);

    if (pSession->pWsSession == NULL || pSession->pWsSession->pApi == NULL)
        return DirectGate_CMD_Refuse(pSession, "no event loop for the command");

    uint64_t nNowMs = XTime_GetMonoMs();

    /* Output is bulk data: a client starts its command once the data channel is open, or once it has found WebRTC
       impossible (webrtc/unavailable) - never while a channel may still come, which the relay would carry instead */
    if (DirectGate_Session_GetBulkRoute(pSession, nNowMs) == DIRECTGATE_BULK_WAIT)
        return DirectGate_CMD_Refuse(pSession, "the data channel is not ready");

    if (DirectGate_CMD_Spawn(pSession, pExec) != XSTDOK)
    {
        char sReason[XSTR_MIN];
        xstrncpyf(sReason, sizeof(sReason), "cannot start the command: %s", strerror(errno));

        xloge("Failed to start command: sid(%u), wsfd(%d), errno(%d)",
            pSession->nSessionId, DirectGate_CMD_GetWsFd(pSession), errno);

        /* Nothing ran: the client is told, and the session ends once it leaves - a remote session is ready again */
        if (bRemote) DirectGate_CMD_Ready(pCmd);
        else
        {
            pCmd->eState = DIRECTGATE_COMMAND_DONE;
            pCmd->nDoneMs = nNowMs;
        }

        if (DirectGate_CMD_SendStarted(pSession, "failed", sReason) < 0)
            return DirectGate_Session_Close(pSession, "command answer failed");

        return XAPI_CONTINUE;
    }

    pCmd->eState = DIRECTGATE_COMMAND_RUNNING;
    pCmd->nTimeoutMs = pExec->nTimeoutMs;
    pCmd->bLimitOutput = pExec->bHasOutputMax;
    pCmd->nOutputMax = pExec->nOutputMax;
    pCmd->nStartMs = nNowMs;

    char sOutputMax[XSTR_TINY];
    if (pCmd->bLimitOutput) xstrncpyf(sOutputMax, sizeof(sOutputMax), "%u", pCmd->nOutputMax);
    else xstrncpy(sOutputMax, sizeof(sOutputMax), "none");

    /* Never the command line itself: it can carry a password as easily as a path */
    xlogi("Command started: sid(%u), wsfd(%d), pid(%d), bytes(%zu), stdin(%s), timeoutMs(%u), outputMax(%s), exitEvent(%s)",
        pSession->nSessionId, DirectGate_CMD_GetWsFd(pSession), (int)pCmd->exec.nPid, strlen(pExec->pCommand),
        pExec->bStdin ? "yes" : "no", pExec->nTimeoutMs, sOutputMax, pCmd->exec.nExitFd != XSOCK_INVALID ? "yes" : "no");

    if (DirectGate_CMD_AddEndpoint(pSession, &pCmd->exec.nStdOut, &pCmd->nOutFd) < 0 ||
        DirectGate_CMD_AddEndpoint(pSession, &pCmd->exec.nStdErr, &pCmd->nErrFd) < 0 ||
        DirectGate_CMD_AddEndpoint(pSession, &pCmd->exec.nStdIn, &pCmd->nInFd) < 0)
    {
        xloge("Failed to register command endpoints: sid(%u), wsfd(%d), pid(%d)",
            pSession->nSessionId, DirectGate_CMD_GetWsFd(pSession), (int)pCmd->exec.nPid);

        return DirectGate_Session_Close(pSession, "command endpoint registration failed");
    }

    /* Only a shortcut: without it the exit is polled for, as where the system has no way to announce one */
    if (DirectGate_CMD_AddEndpoint(pSession, &pCmd->exec.nExitFd, &pCmd->nExitFd) < 0)
    {
        xlogw("Failed to register command exit endpoint, polling for the exit: sid(%u), wsfd(%d), pid(%d)",
            pSession->nSessionId, DirectGate_CMD_GetWsFd(pSession), (int)pCmd->exec.nPid);
    }

    if (DirectGate_CMD_SendStarted(pSession, "ok", NULL) < 0)
        return DirectGate_Session_Close(pSession, "command answer failed");

    return XAPI_CONTINUE;
}

static int DirectGate_CMD_WriteSome(XSOCKET nFd, const uint8_t *pData, size_t nSize)
{
#ifdef _WIN32
    int nSent = send(nFd, (const char*)pData, (int)nSize, 0);
    if (nSent > 0) return nSent;
    int nError = WSAGetLastError();
    return (nSent < 0 && (nError == WSAEWOULDBLOCK || nError == WSAEINTR)) ? XSTDNON : XSTDERR;
#else
    ssize_t nSent = write(nFd, pData, nSize);
    if (nSent > 0) return (int)nSent;
    return (nSent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) ? XSTDNON : XSTDERR;
#endif
}

/* XSTDOK when the queue is empty, XSTDNON when the program has not taken all of it yet, XSTDERR when it no
   longer reads its input at all. */
static XSTATUS DirectGate_CMD_Flush(directgate_command_t *pCmd)
{
    while (pCmd->input.nUsed)
    {
        int nSent = DirectGate_CMD_WriteSome(pCmd->nInFd, pCmd->input.pData, pCmd->input.nUsed);
        if (nSent == XSTDNON) return XSTDNON;
        if (nSent < 0) return XSTDERR;
        XByteBuffer_Advance(&pCmd->input, (size_t)nSent);
    }

    return XSTDOK;
}

static int DirectGate_CMD_Input(directgate_session_t *pSession, const directgate_pkg_exec_t *pExec)
{
    directgate_command_t *pCmd = &pSession->command;
    const uint8_t *pData = pExec->data.pPayload;
    size_t nLength = pExec->data.nPayloadLength;

    /* The program closed its input, or was started without one: what still arrives has nowhere to go */
    if (pCmd->eState != DIRECTGATE_COMMAND_RUNNING || pCmd->pInSession == NULL || pCmd->bInputEof) return XAPI_CONTINUE;
    if (pData == NULL || !nLength) return XAPI_CONTINUE;

    if (pCmd->input.nUsed + nLength > DIRECTGATE_COMMAND_INPUT_MAX)
    {
        xlogw("Command input queue overflow: sid(%u), wsfd(%d), queued(%zu), bytes(%zu)",
            pSession->nSessionId, DirectGate_CMD_GetWsFd(pSession), pCmd->input.nUsed, nLength);

        return DirectGate_Session_Close(pSession, "command input overflow");
    }

    if (XByteBuffer_Add(&pCmd->input, pData, nLength) <= 0)
        return DirectGate_Session_Close(pSession, "command input allocation failed");

    XSTATUS nStatus = DirectGate_CMD_Flush(pCmd);
    if (nStatus == XSTDERR)
    {
        XByteBuffer_Clear(&pCmd->input);
        DirectGate_CMD_DropEndpoint(&pCmd->pInSession);
    }
    else if (nStatus == XSTDNON)
    {
        XAPI_EnableEvent(pCmd->pInSession, XPOLLOUT);
    }

    return XAPI_CONTINUE;
}

static int DirectGate_CMD_Eof(directgate_session_t *pSession)
{
    directgate_command_t *pCmd = &pSession->command;
    pCmd->bInputEof = XTRUE;

    /* Closed now when nothing is queued, otherwise once the program has taken the rest (OnWrite) */
    if (!pCmd->input.nUsed) DirectGate_CMD_DropEndpoint(&pCmd->pInSession);
    return XAPI_CONTINUE;
}

static int DirectGate_CMD_Signal(directgate_session_t *pSession, const directgate_pkg_exec_t *pExec)
{
    directgate_command_t *pCmd = &pSession->command;
    int nSignal = DirectGate_CMD_SignalFromName(pExec->pSignal);

    if (!nSignal)
    {
        DirectGate_Session_SendErrorMsg(pSession, "unknown signal");
        return XAPI_CONTINUE;
    }

    if (pCmd->eState != DIRECTGATE_COMMAND_RUNNING || pCmd->exec.bExited) return XAPI_CONTINUE;

    xlogi("Signalling command: sid(%u), wsfd(%d), pid(%d), signal(%s)",
        pSession->nSessionId, DirectGate_CMD_GetWsFd(pSession), (int)pCmd->exec.nPid, pExec->pSignal);

    XExec_Kill(&pCmd->exec, nSignal);
    return XAPI_CONTINUE;
}

int DirectGate_CMD_HandleMessage(directgate_session_t *pSession, const directgate_pkg_exec_t *pExec)
{
    XCHECK((pSession != NULL), XAPI_CONTINUE);
    XCHECK((pExec != NULL), XAPI_CONTINUE);

    /* Refused here may mean the session is already gone: nothing below may touch it then */
    if (DirectGate_Session_EnsureMode(pSession, DIRECTGATE_SESSION_MODE_EXEC, "exec mode is not active") != XSTDOK)
        return XAPI_CONTINUE;

    const char *pAction = pExec->pAction;
    if (xstrcmp(pAction, "start")) return DirectGate_CMD_Start(pSession, pExec);
    if (xstrcmp(pAction, "input")) return DirectGate_CMD_Input(pSession, pExec);
    if (xstrcmp(pAction, "eof")) return DirectGate_CMD_Eof(pSession);
    if (xstrcmp(pAction, "signal")) return DirectGate_CMD_Signal(pSession, pExec);

    xlogw("Unknown exec action: sid(%u), wsfd(%d), action(%s)",
        pSession->nSessionId, DirectGate_CMD_GetWsFd(pSession), xstrused(pAction) ? pAction : "N/A");

    DirectGate_Session_SendErrorMsg(pSession, "unknown exec action");
    return XAPI_CONTINUE;
}

void DirectGate_CMD_OnRegistered(directgate_command_t *pCmd, xapi_session_t *pApiSession)
{
    XCHECK_VOID_NL((pCmd != NULL && pApiSession != NULL));
    XSOCKET nFd = pApiSession->sock.nFD;

    if (nFd == pCmd->nOutFd) pCmd->pOutSession = pApiSession;
    else if (nFd == pCmd->nErrFd) pCmd->pErrSession = pApiSession;
    else if (nFd == pCmd->nInFd) pCmd->pInSession = pApiSession;
    else if (nFd == pCmd->nExitFd) pCmd->pExitSession = pApiSession;
}

void DirectGate_CMD_OnClosed(directgate_command_t *pCmd, XSOCKET nFd)
{
    XCHECK_VOID_NL((pCmd != NULL));

    if (nFd == pCmd->nOutFd)
    {
        pCmd->nOutFd = XSOCK_INVALID;
        pCmd->pOutSession = NULL;
    }
    else if (nFd == pCmd->nErrFd)
    {
        pCmd->nErrFd = XSOCK_INVALID;
        pCmd->pErrSession = NULL;
    }
    else if (nFd == pCmd->nInFd)
    {
        pCmd->nInFd = XSOCK_INVALID;
        pCmd->pInSession = NULL;
        XByteBuffer_Clear(&pCmd->input);
    }
    else if (nFd == pCmd->nExitFd)
    {
        pCmd->nExitFd = XSOCK_INVALID;
        pCmd->pExitSession = NULL;
    }
}

static int DirectGate_CMD_SendOutput(directgate_session_t *pSession, const char *pStream, const uint8_t *pData, size_t nLength)
{
    xjson_obj_t *pHeader = DirectGate_Proto_BuildExec("output", NULL, NULL, pSession->nSessionId);
    XCHECK((pHeader != NULL), xthrowr(XSTDERR, "Proto: Failed to build exec output header"));

    XJSON_AddString(pHeader, "stream", pStream);
    int nStatus = DirectGate_CMD_Send(pSession, pHeader, pData, nLength);

    XJSON_FreeObject(pHeader);
    return nStatus;
}

static xbool_t DirectGate_CMD_IsCapped(const directgate_command_t *pCmd, xbool_t bStdErr)
{
    uint64_t nSent = bStdErr ? pCmd->nErrSent : pCmd->nOutSent;
    return (pCmd->bLimitOutput && nSent >= pCmd->nOutputMax) ? XTRUE : XFALSE;
}

/* What a stream wrote, as far as the client's limit goes; the rest is dropped. XSTDERR only when a send failed. */
static XSTATUS DirectGate_CMD_Deliver(directgate_session_t *pSession, xbool_t bStdErr, const uint8_t *pData, size_t nLength)
{
    directgate_command_t *pCmd = &pSession->command;
    uint64_t *pSent = bStdErr ? &pCmd->nErrSent : &pCmd->nOutSent;

    if (pCmd->bLimitOutput)
    {
        uint64_t nLeft = *pSent < pCmd->nOutputMax ? pCmd->nOutputMax - *pSent : 0;
        if (nLength > nLeft)
        {
            nLength = (size_t)nLeft;
            pCmd->bTruncated = XTRUE;
        }
    }

    if (!nLength) return XSTDOK;
    if (DirectGate_CMD_SendOutput(pSession, bStdErr ? "stderr" : "stdout", pData, nLength) < 0) return XSTDERR;

    *pSent += nLength;
    return XSTDOK;
}

int DirectGate_CMD_OnRead(directgate_session_t *pSession, XSOCKET nFd)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_command_t *pCmd = &pSession->command;

    /* Readiness on the input end only ever means the program closed its side */
    if (nFd == pCmd->nInFd) return XAPI_DISCONNECT;

    /* The program has exited. The endpoint has done its work: the exit is collected by this pass's check, and a
       descriptor that stays readable for good cannot stay on the loop. */
    if (nFd == pCmd->nExitFd) return XAPI_DISCONNECT;

    xbool_t bStdErr = nFd == pCmd->nErrFd ? XTRUE : XFALSE;
    xapi_session_t *pEvent = bStdErr ? pCmd->pErrSession : pCmd->pOutSession;
    const char *pStream = bStdErr ? "stderr" : "stdout";

    for (int nRound = 0; nRound < DIRECTGATE_COMMAND_READ_BUDGET; nRound++)
    {
        /* A stream past its limit sends nothing, so nothing on the transport holds it back */
        if (!DirectGate_CMD_IsCapped(pCmd, bStdErr))
        {
            if (DirectGate_CMD_IsBacklogged(pSession, DIRECTGATE_COMMAND_TX_HIGH_WATER) || DirectGate_CMD_IsPaced(pSession))
            {
                /* Which of the two holds it is settled by the check after this pass (DirectGate_CMD_Check) */
                if (pEvent != NULL && XAPI_DisableEvent(pEvent, XPOLLIN) >= 0) pCmd->bReadPaused = XTRUE;
                break;
            }
        }

        uint8_t sBuffer[DIRECTGATE_COMMAND_READ_SIZE];
#ifdef _WIN32
        int nRead = recv(nFd, (char*)sBuffer, (int)sizeof(sBuffer), 0);
        int nError = nRead < 0 ? WSAGetLastError() : 0;
        if (nRead < 0 && nError == WSAEINTR) continue;
        if (nRead < 0 && nError == WSAEWOULDBLOCK) break;
#else
        ssize_t nRead = read(nFd, sBuffer, sizeof(sBuffer));
        int nError = nRead < 0 ? errno : 0;
        if (nRead < 0 && nError == EINTR) continue;
        if (nRead < 0 && (nError == EAGAIN || nError == EWOULDBLOCK)) break;
#endif

        if (nRead == 0) return XAPI_DISCONNECT;

        if (nRead < 0)
        {
            xlogw("Failed to read command output: sid(%u), wsfd(%d), stream(%s), errno(%d)",
                pSession->nSessionId, DirectGate_CMD_GetWsFd(pSession), pStream, nError);

            return XAPI_DISCONNECT;
        }

        if (DirectGate_CMD_Deliver(pSession, bStdErr, sBuffer, (size_t)nRead) < 0)
            return XAPI_DISCONNECT;
    }

    return XAPI_CONTINUE;
}

/* Reads out what a stream holds now and sends it, never waiting for more: the descriptor does not block,
   and the bound only stops a stream that something the program started keeps writing to */
static void DirectGate_CMD_Drain(directgate_session_t *pSession, XSOCKET nFd, xbool_t bStdErr)
{
    uint8_t sBuffer[DIRECTGATE_COMMAND_READ_SIZE];

    /* A pipe holds at most 1 MB unless its owner enlarged it */
    for (int nRound = 0; nRound < DIRECTGATE_COMMAND_DRAIN_ROUNDS; nRound++)
    {
#ifdef _WIN32
        int nRead = recv(nFd, (char*)sBuffer, (int)sizeof(sBuffer), 0);
        if (nRead < 0 && WSAGetLastError() == WSAEINTR) continue;
#else
        ssize_t nRead = read(nFd, sBuffer, sizeof(sBuffer));
        if (nRead < 0 && errno == EINTR) continue;
#endif
        if (nRead <= 0) return;
        if (DirectGate_CMD_Deliver(pSession, bStdErr, sBuffer, (size_t)nRead) < 0) return;
    }
}

void DirectGate_CMD_OnHangup(directgate_session_t *pSession, XSOCKET nFd)
{
    XCHECK_VOID_NL((pSession != NULL));
    directgate_command_t *pCmd = &pSession->command;
    if (nFd != pCmd->nOutFd && nFd != pCmd->nErrFd) return;
    DirectGate_CMD_Drain(pSession, nFd, nFd == pCmd->nErrFd ? XTRUE : XFALSE);
}

int DirectGate_CMD_OnWrite(directgate_session_t *pSession, XSOCKET nFd)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_command_t *pCmd = &pSession->command;
    if (nFd != pCmd->nInFd) return XAPI_CONTINUE;

    XSTATUS nStatus = DirectGate_CMD_Flush(pCmd);
    if (nStatus == XSTDERR) return XAPI_DISCONNECT;
    if (nStatus == XSTDNON) return XAPI_CONTINUE;

    /* Everything delivered: either the client is done and the program reads end of file, or wait for more */
    if (pCmd->bInputEof) return XAPI_DISCONNECT;
    if (pCmd->pInSession != NULL) XAPI_DisableEvent(pCmd->pInSession, XPOLLOUT);
    return XAPI_CONTINUE;
}

static int DirectGate_CMD_Finish(directgate_session_t *pSession, uint64_t nNowMs)
{
    directgate_command_t *pCmd = &pSession->command;
    xexec_t *pExec = &pCmd->exec;

    /* What the program wrote before it exited goes out ahead of its exit, however late the loop came to read it - a
       busy pass, a pipe the program enlarged past one pass's read. Output something it started still holds open is
       not read any further than what is there now. */
    if (pCmd->nOutFd != XSOCK_INVALID) DirectGate_CMD_Drain(pSession, pCmd->nOutFd, XFALSE);
    if (pCmd->nErrFd != XSOCK_INVALID) DirectGate_CMD_Drain(pSession, pCmd->nErrFd, XTRUE);

    DirectGate_CMD_DropEndpoint(&pCmd->pOutSession);
    DirectGate_CMD_DropEndpoint(&pCmd->pErrSession);
    DirectGate_CMD_DropEndpoint(&pCmd->pInSession);
    DirectGate_CMD_DropEndpoint(&pCmd->pExitSession);
    XByteBuffer_Clear(&pCmd->input);

    pCmd->eState = DIRECTGATE_COMMAND_DONE;
    pCmd->bReadPaused = XFALSE;
    pCmd->bPaced = XFALSE;
    pCmd->nDoneMs = nNowMs;

    const char *pSignal = pExec->nSignal ? DirectGate_CMD_SignalName(pExec->nSignal) : NULL;

    xlogi("Command finished: sid(%u), wsfd(%d), pid(%d), code(%d), signal(%d), timeout(%s), truncated(%s), "
        "stdout(%llu), stderr(%llu), ms(%llu)", pSession->nSessionId, DirectGate_CMD_GetWsFd(pSession), (int)pExec->nPid,
        pExec->nExitCode, pExec->nSignal, pCmd->bTimedOut ? "yes" : "no", pCmd->bTruncated ? "yes" : "no",
        (unsigned long long)pCmd->nOutSent, (unsigned long long)pCmd->nErrSent,
        (unsigned long long)(nNowMs - pCmd->nStartMs));

    xjson_obj_t *pHeader = DirectGate_Proto_BuildExec("exit", "ok", NULL, pSession->nSessionId);
    if (pHeader == NULL)
    {
        DirectGate_Session_Close(pSession, "command exit header failed");
        return XAPI_DISCONNECT;
    }

    XJSON_AddInt(pHeader, "exitCode", pExec->nExitCode);
    if (xstrused(pSignal)) XJSON_AddString(pHeader, "signal", pSignal);
    if (pCmd->bTimedOut) XJSON_AddBool(pHeader, "timedOut", XTRUE);
    if (pCmd->bTruncated) XJSON_AddBool(pHeader, "truncated", XTRUE);

    int nStatus = DirectGate_CMD_Send(pSession, pHeader, NULL, XSTDNON);
    XJSON_FreeObject(pHeader);

    if (nStatus < 0)
    {
        DirectGate_Session_Close(pSession, "command exit send failed");
        return XAPI_DISCONNECT;
    }

    /* A remote session stays for its next command */
    if (pSession->eActiveMode == DIRECTGATE_SESSION_MODE_REMOTE) DirectGate_CMD_Ready(pCmd);
    return XAPI_CONTINUE;
}

int DirectGate_CMD_Check(directgate_session_t *pSession, uint64_t nNowMs)
{
    XCHECK_NL((pSession != NULL), XAPI_CONTINUE);
    directgate_command_t *pCmd = &pSession->command;

    /* The client closes the session once it has the exit; the relay tells us, and the session goes. A client
       that stays is not kept: the exit has already been reported over the same transport as the output. */
    if (pCmd->eState == DIRECTGATE_COMMAND_DONE)
    {
        if (nNowMs - pCmd->nDoneMs < DIRECTGATE_COMMAND_LINGER_MS) return XAPI_CONTINUE;
        DirectGate_Session_Close(pSession, "command finished");
        return XAPI_DISCONNECT;
    }

    if (pCmd->eState != DIRECTGATE_COMMAND_RUNNING) return XAPI_CONTINUE;

    /* The output went over a data channel that is gone: what was in it cannot be known to have arrived, so the command
       ends here rather than carry on with a gap its client would never see */
    if (pSession->eBulkPin == DIRECTGATE_BULK_CHANNEL && !DirectGate_WebRTC_IsConnected(&pSession->webrtc))
    {
        xlogw("Data channel lost while a command ran: sid(%u), wsfd(%d), pid(%d)",
            pSession->nSessionId, DirectGate_CMD_GetWsFd(pSession), (int)pCmd->exec.nPid);

        DirectGate_Session_Close(pSession, "data channel lost during the command");
        return XAPI_DISCONNECT;
    }

    xexec_t *pExec = &pCmd->exec;

    /* Held by the transport, the limit, or both: read again once neither holds it, polled meanwhile only while the
       transport does */
    xbool_t bBacklogged = pCmd->bReadPaused ? DirectGate_CMD_IsBacklogged(pSession, DIRECTGATE_COMMAND_TX_LOW_WATER) : XFALSE;
    if (pCmd->bReadPaused) pCmd->bPaced = bBacklogged ? XFALSE : XTRUE;

    if (pCmd->bReadPaused && !bBacklogged && !DirectGate_CMD_IsPaced(pSession))
    {
        pCmd->bReadPaused = XFALSE;
        pCmd->bPaced = XFALSE;
        if (pCmd->pOutSession != NULL) XAPI_EnableEvent(pCmd->pOutSession, XPOLLIN);
        if (pCmd->pErrSession != NULL) XAPI_EnableEvent(pCmd->pErrSession, XPOLLIN);

        /* The exit grace counts from when the output can be read again, not from an exit that came while paused */
        if (pExec->bExited) pCmd->nExitMs = nNowMs;
    }

    if (!pExec->bExited)
    {
        XSTATUS nWait = XExec_Wait(pExec, 0);

        if (nWait == XSTDOK)
        {
            pCmd->nExitMs = nNowMs;
        }
        else if (nWait == XSTDERR)
        {
            /* Collected by someone else, or no longer ours to wait for: reported as an unknown exit rather
               than waited for forever */
            xlogw("Command exit could not be collected: sid(%u), pid(%d), errno(%d)",
                pSession->nSessionId, (int)pExec->nPid, errno);

            pExec->bExited = XTRUE;
            pExec->nExitCode = XSTDERR;
            pCmd->nExitMs = nNowMs;
        }
        else if (pCmd->nTimeoutMs && !pCmd->bTimedOut && nNowMs - pCmd->nStartMs >= pCmd->nTimeoutMs)
        {
            xlogw("Command timed out, killing its process group: sid(%u), pid(%d), timeoutMs(%u)",
                pSession->nSessionId, (int)pExec->nPid, pCmd->nTimeoutMs);

            pCmd->bTimedOut = XTRUE;
            XExec_Kill(pExec, SIGKILL);
        }
    }

    /* The backoff counts from the pass that found nothing left to announce the exit. Nothing comes back - a stream or
       the exit endpoint, once gone, stays gone - so it is set once. */
    if (!pCmd->nPollMs && DirectGate_CMD_NeedsPoll(pCmd)) pCmd->nPollMs = nNowMs;

    if (!pExec->bExited) return XAPI_CONTINUE;

    /* Everything the program wrote is out before its exit: both streams at end of file, or - when something it
       started holds them open - a short grace. Output paused behind the transport is waited for, not dropped. */
    xbool_t bDrained = (pCmd->nOutFd == XSOCK_INVALID && pCmd->nErrFd == XSOCK_INVALID) ? XTRUE : XFALSE;
    if (!bDrained && (pCmd->bReadPaused || nNowMs - pCmd->nExitMs < DIRECTGATE_COMMAND_GRACE_MS)) return XAPI_CONTINUE;

    return DirectGate_CMD_Finish(pSession, nNowMs);
}
