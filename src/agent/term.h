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

XSTATUS DirectGate_Term_Start(directgate_term_t *pTerm, xapi_t *pApi, xapi_session_t *pWsSession);
XSTATUS DirectGate_Term_StartNoEndpoint(directgate_term_t *pTerm, xapi_t *pApi, xapi_session_t *pWsSession);

xbool_t DirectGate_Term_IsRunning(const directgate_term_t *pTerm);
void DirectGate_Term_RequestStop(directgate_term_t *pTerm);
void DirectGate_Term_Shutdown(directgate_term_t *pTerm, xbool_t bCloseFd);

void DirectGate_Term_AttachEvent(directgate_term_t *pTerm, xapi_session_t *pPTYSession);
void DirectGate_Term_DetachEvent(directgate_term_t *pTerm);

int DirectGate_Term_OnRead(directgate_term_t *pTerm);
int DirectGate_Term_OnWrite(directgate_term_t *pTerm);

XSTATUS DirectGate_Term_Write(directgate_term_t *pTerm, const uint8_t *pData, size_t nLength);
XSTATUS DirectGate_Term_UpdateWinSize(directgate_term_t *pTerm, const struct winsize *pSize);
XSTATUS DirectGate_Term_GetCwd(const directgate_term_t *pTerm, char *pBuf, size_t nBufSize);

#ifdef __cplusplus
}
#endif

#endif
