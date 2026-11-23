/*!
 * @file directgate-agent/src/agent/directgate_term.h
 * @brief Agent PTY session interface.
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

#ifndef __DIRECTGATE_TERM_H__
#define __DIRECTGATE_TERM_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _WIN32
#include <sys/ioctl.h>
#endif

#include "includes.h"
#include "webrtc.h"
#include "e2e.h"

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#define _XOS_UNIX_LIKE
#endif

typedef struct directgate_term_ {
    directgate_webrtc_t *pWebRTC;
    xapi_session_t *pPTYSession;
    xapi_session_t *pWsSession;
    directgate_e2e_t *pE2E;
    xapi_t *pApi;

    xbyte_buffer_t txBuffer;
    struct winsize winSize;

    xbool_t bHaveWinSize;
    xbool_t bEncrypt;
    xbool_t bRunning;

    /* Shell output is not read while the transport it goes out on is this far
     * behind (see DirectGate_Term_ResumeRead). A shell printing faster than
     * the link drains - `cat` of a large file, `yes` - otherwise grew the
     * send queue without bound and starved every other session of the loop. */
    xbool_t bReadPaused;

    /*
    * sShellHome defines the initial working directory for the PTY session after launch.
    * It is not a filesystem restriction or security boundary like a DOCUMENT_ROOT.
    *
    * sShellUser defines the user account under which the PTY session or file manager
    * runs. Filesystem and resource access are determined by the operating system
    * through standard permission checks for that user.
    *
    * Process-level privileges are also affected by the User setting in the systemd
    * service that runs DirectGate. By default, this is the same user that was specified
    * during installation, and the installer normally keeps both configurations
    * aligned. However, either setting may be changed independently at any time.
    * Check the User value in /etc/systemd/system/directgate-agent.service to see which
    * account is currently used to run DirectGate.
    *
    * In addition, DirectGate drops privileges to the user specified by sShellUser
    * immediately after startup and before performing any PTY or filesystem
    * operations. This is mandatory field and must be set to a valid user account.
    */
    char sShellHome[XPATH_MAX];
    char sShellUser[XSTR_MID];

    uint32_t nSessionId;

    /*
    * POSIX: nMasterFd is the PTY master returned by openpty().
    *
    * Windows: the shell runs attached to a ConPTY pseudo console. ConPTY
    * exposes plain pipe HANDLEs, which WSAPoll (the Windows event engine
    * in libxutils) cannot poll, so two pump threads bridge the ConPTY
    * pipes to a private socket pair from XSock_CreatePair(). nMasterFd is
    * the event-loop side of that bridge and behaves like the PTY master:
    * readable when the shell produces output, writable for input, EOF
    * when the shell exits.
    */
    int nMasterFd;
    pid_t nPid;

#ifdef _WIN32
    HPCON hPC;               /* Pseudo console */
    HANDLE hProcess;         /* Shell process */
    HANDLE hConInWrite;      /* Agent -> ConPTY input pipe */
    HANDLE hConOutRead;      /* ConPTY output pipe -> agent */
    HANDLE hOutPump;         /* ConPTY output -> bridge socket thread */
    HANDLE hInPump;          /* Bridge socket -> ConPTY input thread */
    XSOCKET nBridgeSock;     /* Pump-side end of the bridge pair */
#endif
} directgate_term_t;

void DirectGate_Term_Init(directgate_term_t *pTerm);
void DirectGate_Term_Clear(directgate_term_t *pTerm);

XSTATUS DirectGate_Term_StartNoEndpoint(directgate_term_t *pTerm, xapi_t *pApi, xapi_session_t *pWsSession);

xbool_t DirectGate_Term_IsRunning(const directgate_term_t *pTerm);
void DirectGate_Term_RequestStop(directgate_term_t *pTerm);
void DirectGate_Term_Shutdown(directgate_term_t *pTerm, xbool_t bCloseFd);

void DirectGate_Term_AttachEvent(directgate_term_t *pTerm, xapi_session_t *pPTYSession);
void DirectGate_Term_DetachEvent(directgate_term_t *pTerm);

int DirectGate_Term_OnRead(directgate_term_t *pTerm);
int DirectGate_Term_OnWrite(directgate_term_t *pTerm);

/* Queues input for the shell. Fails once the shell has left DIRECTGATE_TERM_TX_MAX
 * bytes unread, which ends the session rather than letting a stalled program grow
 * the agent's memory without bound. */
XSTATUS DirectGate_Term_Write(directgate_term_t *pTerm, const uint8_t *pData, size_t nLength);

/* Re-arms reading shell output once the transport has drained. Called on every
 * event loop pass; a no-op unless reading was paused. */
void DirectGate_Term_ResumeRead(directgate_term_t *pTerm);
xbool_t DirectGate_Term_IsReadPaused(const directgate_term_t *pTerm);

/* Reaps shells that were hung up but had not exited yet, killing any that
 * outstay the grace period. Never blocks: a shell stuck in the kernel (a dead
 * NFS mount) is retried on the next call instead of freezing the agent. Called
 * on every event loop pass. Returns how many are still outstanding. */
size_t DirectGate_Term_ReapPending(void);
XSTATUS DirectGate_Term_UpdateWinSize(directgate_term_t *pTerm, const struct winsize *pSize);
XSTATUS DirectGate_Term_GetCwd(const directgate_term_t *pTerm, char *pBuf, size_t nBufSize);

#ifndef _WIN32
/* Everything the child needs, worked out in the parent. The agent is threaded
 * (libdatachannel, search, capture, audio), and after fork() the child holds
 * a copy of every lock exactly as it was: a name-service lookup, a malloc or
 * a log line there can wait forever on a lock whose owner does not exist in
 * the child. So the child only makes system calls on what is prepared here. */
typedef struct directgate_term_spawn_ {
    uid_t nUid;
    gid_t nGid;
    gid_t *pGroups;
    int nGroups;
    xbool_t bSwitchUser;
    char sWorkDir[XPATH_MAX];
    char sShell[XPATH_MAX];
    char sArg0[XPATH_MAX];
    char **ppEnv;
} directgate_term_spawn_t;

/* The account a shell runs as - shell.user, its groups, shell.home or its home, its login shell and an
 * environment naming it - for the PTY and for a non-interactive command alike, so the two can never run as
 * different users. A configured user that does not resolve fails closed. Release with FreeSpawn. */
XSTATUS DirectGate_Term_ResolveShell(const directgate_term_t *pTerm, directgate_term_spawn_t *pSpawn);
void DirectGate_Term_FreeSpawn(directgate_term_spawn_t *pSpawn);

/* Ends a child that leads its own process group the way a closed terminal does: SIGHUP to the group, then
 * SIGKILL to whatever outstays the grace period, collected by DirectGate_Term_ReapPending off the event loop. */
void DirectGate_Term_HangupProcess(pid_t nPid);
#else
/* Refuses a shell.user that is not the account running the agent: there is no user switching on Windows. */
XSTATUS DirectGate_Term_ValidateShellUser(const directgate_term_t *pTerm);
#endif

#ifdef __cplusplus
}
#endif

#endif
