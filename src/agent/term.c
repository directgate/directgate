/*!
 * @file directgate-agent/src/agent/directgate_term.c
 * @brief Agent PTY spawn and I/O bridge implementation.
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

#define _GNU_SOURCE
#include "includes.h"
#include "protocol.h"
#include "websock.h"
#include "common.h"
#include "term.h"

#ifndef _WIN32
#ifdef _XOS_UNIX_LIKE
#include <util.h>
#else
#include <pty.h>
#endif
#endif

#ifdef _WIN32
#include <winternl.h>   /* NtQueryInformationProcess for the shell cwd */
#endif

#ifdef __APPLE__
#include <libproc.h>
#endif

#define DIRECTGATE_TERM_BUF_SIZE 4096

static int DirectGate_Term_GetWsFd(const directgate_term_t *pTerm)
{
    XCHECK_NL((pTerm != NULL), (int)XSOCK_INVALID);
    XCHECK_NL((pTerm->pWsSession != NULL), (int)XSOCK_INVALID);
    return (int)pTerm->pWsSession->sock.nFD;
}

#ifdef _WIN32
static XSTATUS DirectGate_Term_SetNonBlock(int nFd, xbool_t bNonblock)
{
    u_long nMode = bNonblock ? 1 : 0;
    int nStatus = ioctlsocket((XSOCKET)nFd, FIONBIO, &nMode);
    XCHECK((nStatus == 0), xthrow("Failed to set bridge socket mode: error(%d)", WSAGetLastError()));
    return XSTDOK;
}
#else
static XSTATUS DirectGate_Term_SetNonBlock(int nFd, xbool_t bNonblock)
{
    int nFlags = fcntl(nFd, F_GETFL, 0);
    XCHECK((nFlags >= 0), xthrow("Failed to get PTY fd flags: errno(%d)", errno));

    if (bNonblock) nFlags |= O_NONBLOCK;
    else nFlags &= ~O_NONBLOCK;

    int nStatus = fcntl(nFd, F_SETFL, nFlags);
    XCHECK((nStatus >= 0), xthrow("Failed to set PTY fd flags: errno(%d)", errno));

    return XSTDOK;
}
#endif

#ifndef _WIN32
static XSTATUS DirectGate_Term_ApplyShell(const directgate_term_t *pTerm)
{
    const char *pHome = NULL;

    if (pTerm != NULL && xstrused(pTerm->sShellUser))
    {
        errno = 0;
        struct passwd *pUser = getpwnam(pTerm->sShellUser);

        if (pUser == NULL)
        {
            xloge("Configured PTY user not found: user(%s), errno(%d)",
                pTerm->sShellUser, errno);

            return XSTDERR;
        }

        xbool_t bAlreadyTargetUser = (getuid() == pUser->pw_uid && geteuid() == pUser->pw_uid);
        if (!bAlreadyTargetUser && initgroups(pUser->pw_name, pUser->pw_gid) != 0)
        {
            xloge("Failed to initialize PTY supplementary groups: user(%s), gid(%u), errno(%d)",
                pUser->pw_name, (unsigned)pUser->pw_gid, errno);

            return XSTDERR;
        }

        if (!bAlreadyTargetUser && setgid(pUser->pw_gid) != 0)
        {
            xloge("Failed to switch PTY group: user(%s), gid(%u), errno(%d)",
                pUser->pw_name, (unsigned)pUser->pw_gid, errno);

            return XSTDERR;
        }

        if (!bAlreadyTargetUser && setuid(pUser->pw_uid) != 0)
        {
            xloge("Failed to switch PTY user: user(%s), uid(%u), errno(%d)",
                pUser->pw_name, (unsigned)pUser->pw_uid, errno);

            return XSTDERR;
        }

        if (!xstrused(pTerm->sShellHome) &&
            xstrused(pUser->pw_dir))
            pHome = pUser->pw_dir;
    }

    if (pTerm != NULL &&
        xstrused(pTerm->sShellHome))
        pHome = pTerm->sShellHome;

    if (!xstrused(pHome))
    {
        xlogd("PTY shell home is not set, using root");
        pHome = "/";
    }

    if (chdir(pHome) != 0)
    {
        xlogw("Failed to change PTY working directory: home(%s), errno(%d)", pHome, errno);
        if (chdir("/") != 0) xlogw("Failed to change PTY working directory to root: errno(%d)", errno);
    }

    return XSTDOK;
}

static void DirectGate_SetCloseExec(int fd)
{
    int fl = fcntl(fd, F_GETFD);
    if (fl >= 0) (void)fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
}

static int DirectGate_WaitNoHang(pid_t pid, int *pStatus)
{
    for (;;)
    {
        pid_t r = waitpid(pid, pStatus, WNOHANG);
        if (r > 0) return 1; /* reaped */
        if (r == 0) return 0; /* still running */
        if (errno == EINTR) continue; /* retry */
        return XSTDERR; /* error (ECHILD, etc) */
    }
}

static void DirectGate_WaitBlocking(pid_t pid, int *pStatus)
{
    for (;;)
    {
        pid_t r = waitpid(pid, pStatus, 0);
        if (r > 0) return;
        if (r < 0 && errno == EINTR) continue;
        return; /* ECHILD or other error */
    }
}

static void DirectGate_SleepMs(long ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000L * 1000L;
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR){}
}

static const char* DirectGate_Term_GetShellPath(void)
{
    const char *pShell = getenv("SHELL");
    if (pShell != NULL && access(pShell, X_OK) == 0)
        return pShell;

#ifdef __APPLE__
    if (access("/bin/zsh", X_OK) == 0)
        return "/bin/zsh";
#endif

    if (access("/bin/bash", X_OK) == 0)
        return "/bin/bash";

    if (access("/usr/bin/bash", X_OK) == 0)
        return "/usr/bin/bash";

    if (access("/bin/sh", X_OK) == 0)
        return "/bin/sh";

    if (access("/usr/bin/sh", X_OK) == 0)
        return "/usr/bin/sh";

    return "/bin/sh";
}

static const char* DirectGate_Term_GetArg0(const char *pShell)
{
    XCHECK_NL((pShell != NULL), "sh");
    const char *pBase = strrchr(pShell, '/');
    XCHECK_NL((pBase != NULL), pShell);
    return (*(pBase + 1) != '\0') ? (pBase + 1) : pShell;
}

static XSTATUS DirectGate_Term_Spawn(directgate_term_t *pTerm)
{
    XCHECK((pTerm != NULL), XSTDINV);

    int nMasterFd = -1;
    int nSlaveFd = -1;

    if (openpty(&nMasterFd, &nSlaveFd, NULL, NULL, NULL) != 0)
    {
        xloge("Failed to open PTY session: sid(%u), wsfd(%d), errno(%d)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), errno);

        return XSTDERR;
    }

    DirectGate_SetCloseExec(nMasterFd);
    DirectGate_SetCloseExec(nSlaveFd);

    pid_t nPid = fork();
    if (nPid < 0)
    {
        xloge("Failed to fork PTY process: sid(%u), wsfd(%d), errno(%d)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), errno);

        close(nMasterFd);
        close(nSlaveFd);
        return XSTDERR;
    }

    if (nPid == 0)
    {
        close(nMasterFd);

        /* detache from parent */
        if (setsid() < 0) _exit(127);

        if (ioctl(nSlaveFd, TIOCSCTTY, 0) != 0 ||
            dup2(nSlaveFd, STDIN_FILENO) < 0 ||
            dup2(nSlaveFd, STDOUT_FILENO) < 0 ||
            dup2(nSlaveFd, STDERR_FILENO) < 0)
        {
            _exit(127);
        }

        if (nSlaveFd > STDERR_FILENO) close(nSlaveFd);

        if (DirectGate_Term_ApplyShell(pTerm) < 0)
            _exit(127);

        setenv("TERM", "xterm-256color", 1);

        const char *pShell = DirectGate_Term_GetShellPath();
        const char *pArg0 = DirectGate_Term_GetArg0(pShell);

        execl(pShell, pArg0, "-i", NULL);
        _exit(127);
    }

    close(nSlaveFd);

    if (DirectGate_Term_SetNonBlock(nMasterFd, XTRUE) < 0)
    {
        xloge("Failed to set PTY non-blocking mode: sid(%u), wsfd(%d), ptfd(%d), errno(%d)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), nMasterFd, errno);

        /* close PTY master fd */
        close(nMasterFd);

        /* terminal-like shutdown: HUP then KILL */
        (void)kill(-nPid, SIGHUP);
        (void)kill(-nPid, SIGKILL);
        DirectGate_WaitBlocking(nPid, NULL);

        return XSTDERR;
    }

    pTerm->nPid = nPid;
    pTerm->nMasterFd = nMasterFd;
    pTerm->bRunning = XTRUE;

    return XSTDOK;
}
#endif /* !_WIN32 */

#ifdef _WIN32
/*
    ConPTY terminal backend.

    The shell is attached to a pseudo console (CreatePseudoConsole). Two
    pump threads bridge the ConPTY pipes to a private socket pair so the
    WSAPoll-based event loop can treat the terminal like any other socket:

        shell -> ConPTY out pipe -> OutPump -> bridge -> event loop
        event loop -> bridge -> InPump -> ConPTY in pipe -> shell

    The pumps run blocking I/O and exit on their own when either side
    goes away: closing the pseudo console breaks the pipes, shutting
    down the bridge socket breaks the socket calls.
*/

static void DirectGate_Term_KillChild(directgate_term_t *pTerm);

static DWORD WINAPI DirectGate_Term_OutPump(LPVOID pArg)
{
    directgate_term_t *pTerm = (directgate_term_t*)pArg;
    uint8_t sBuffer[DIRECTGATE_TERM_BUF_SIZE];
    DWORD nRead = 0;

    while (ReadFile(pTerm->hConOutRead, sBuffer, sizeof(sBuffer), &nRead, NULL) && nRead > 0)
    {
        size_t nSent = 0;
        while (nSent < (size_t)nRead)
        {
            int nRet = send(pTerm->nBridgeSock, (const char*)sBuffer + nSent, (int)(nRead - nSent), 0);
            if (nRet <= 0) return 0;
            nSent += (size_t)nRet;
        }
    }

    /* Shell side is gone: signal EOF to the event loop (recv returns 0) */
    shutdown(pTerm->nBridgeSock, SD_SEND);
    return 0;
}

static DWORD WINAPI DirectGate_Term_InPump(LPVOID pArg)
{
    directgate_term_t *pTerm = (directgate_term_t*)pArg;
    char sBuffer[DIRECTGATE_TERM_BUF_SIZE];

    for (;;)
    {
        int nRecv = recv(pTerm->nBridgeSock, sBuffer, sizeof(sBuffer), 0);
        if (nRecv <= 0) return 0;

        size_t nWritten = 0;
        while (nWritten < (size_t)nRecv)
        {
            DWORD nDone = 0;
            if (!WriteFile(pTerm->hConInWrite, sBuffer + nWritten, (DWORD)(nRecv - nWritten), &nDone, NULL))
                return 0;

            nWritten += (size_t)nDone;
        }
    }
}

static XSTATUS DirectGate_Term_ValidateShellUser(const directgate_term_t *pTerm)
{
    XCHECK_NL((pTerm != NULL), XSTDOK);
    XCHECK_NL(xstrused(pTerm->sShellUser), XSTDOK);

    /*
        Switching the session to another account needs CreateProcessAsUser
        with token privileges the agent intentionally does not hold. The
        POSIX builds refuse silent fallbacks, so the Windows build refuses
        a shell.user that is not the account already running the agent.
        Account names are case-insensitive on Windows.
    */
    char sCurrentUser[XSTR_MID] = {0};
    DirectGate_GetUserName(sCurrentUser, sizeof(sCurrentUser));

    if (!xstrused(sCurrentUser) || _stricmp(sCurrentUser, pTerm->sShellUser) != 0)
    {
        xloge("Configured shell.user does not match the agent account; "
              "user switching is not supported on Windows: shell.user(%s), agent(%s)",
            pTerm->sShellUser, sCurrentUser);

        return XSTDERR;
    }

    return XSTDOK;
}

static size_t DirectGate_Term_GetShellCmd(char *pCmd, size_t nSize)
{
    /* PowerShell is the expected interactive shell on modern Windows */
    char sPath[XPATH_MAX];
    DWORD nLen = SearchPathA(NULL, "powershell.exe", NULL, (DWORD)sizeof(sPath), sPath, NULL);
    if (nLen > 0 && nLen < sizeof(sPath)) return xstrncpy(pCmd, nSize, sPath);

    const char *pComSpec = getenv("COMSPEC");
    if (xstrused(pComSpec)) return xstrncpy(pCmd, nSize, pComSpec);

    return xstrncpy(pCmd, nSize, "cmd.exe");
}

static void DirectGate_Term_CloseWinHandles(directgate_term_t *pTerm)
{
    if (pTerm->hConInWrite != NULL)
    {
        CloseHandle(pTerm->hConInWrite);
        pTerm->hConInWrite = NULL;
    }

    if (pTerm->hConOutRead != NULL)
    {
        CloseHandle(pTerm->hConOutRead);
        pTerm->hConOutRead = NULL;
    }

    if (pTerm->nBridgeSock != XSOCK_INVALID)
    {
        xclosesock(pTerm->nBridgeSock);
        pTerm->nBridgeSock = XSOCK_INVALID;
    }
}

static XSTATUS DirectGate_Term_Spawn(directgate_term_t *pTerm)
{
    XCHECK((pTerm != NULL), XSTDINV);
    XCHECK((DirectGate_Term_ValidateShellUser(pTerm) == XSTDOK), XSTDERR);

    HANDLE hConPtyIn = NULL;   /* ConPTY reads shell input here */
    HANDLE hConPtyOut = NULL;  /* ConPTY writes shell output here */

    SECURITY_ATTRIBUTES pipeAttrs;
    memset(&pipeAttrs, 0, sizeof(pipeAttrs));
    pipeAttrs.nLength = sizeof(pipeAttrs);
    pipeAttrs.bInheritHandle = FALSE;

    if (!CreatePipe(&hConPtyIn, &pTerm->hConInWrite, &pipeAttrs, 0) ||
        !CreatePipe(&pTerm->hConOutRead, &hConPtyOut, &pipeAttrs, 0))
    {
        xloge("Failed to create ConPTY pipes: sid(%u), wsfd(%d), error(%lu)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), GetLastError());

        if (hConPtyIn != NULL) CloseHandle(hConPtyIn);
        DirectGate_Term_CloseWinHandles(pTerm);
        return XSTDERR;
    }

    COORD size;
    size.X = (SHORT)(pTerm->bHaveWinSize && pTerm->winSize.ws_col ? pTerm->winSize.ws_col : 80);
    size.Y = (SHORT)(pTerm->bHaveWinSize && pTerm->winSize.ws_row ? pTerm->winSize.ws_row : 24);

    HRESULT hResult = CreatePseudoConsole(size, hConPtyIn, hConPtyOut, 0, &pTerm->hPC);

    /* ConPTY duplicated its pipe ends, ours are no longer needed */
    CloseHandle(hConPtyIn);
    CloseHandle(hConPtyOut);

    if (FAILED(hResult))
    {
        xloge("Failed to create pseudo console: sid(%u), wsfd(%d), hresult(0x%lx)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), (unsigned long)hResult);

        DirectGate_Term_CloseWinHandles(pTerm);
        return XSTDERR;
    }

    /* Attach the shell to the pseudo console via the process attribute list */
    SIZE_T nAttrListSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &nAttrListSize);

    STARTUPINFOEXA startInfo;
    memset(&startInfo, 0, sizeof(startInfo));
    startInfo.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    startInfo.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(nAttrListSize);

    if (startInfo.lpAttributeList == NULL ||
        !InitializeProcThreadAttributeList(startInfo.lpAttributeList, 1, 0, &nAttrListSize) ||
        !UpdateProcThreadAttribute(startInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
            pTerm->hPC, sizeof(HPCON), NULL, NULL))
    {
        xloge("Failed to prepare ConPTY process attributes: sid(%u), wsfd(%d), error(%lu)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), GetLastError());

        free(startInfo.lpAttributeList);
        ClosePseudoConsole(pTerm->hPC);
        pTerm->hPC = NULL;
        DirectGate_Term_CloseWinHandles(pTerm);
        return XSTDERR;
    }

    char sShellCmd[XPATH_MAX];
    DirectGate_Term_GetShellCmd(sShellCmd, sizeof(sShellCmd));

    const char *pHome = xstrused(pTerm->sShellHome) ? pTerm->sShellHome : NULL;
    if (pHome != NULL && GetFileAttributesA(pHome) == INVALID_FILE_ATTRIBUTES)
    {
        xlogw("PTY working directory does not exist, using default: home(%s)", pHome);
        pHome = NULL;
    }

    PROCESS_INFORMATION procInfo;
    memset(&procInfo, 0, sizeof(procInfo));

    BOOL bCreated = CreateProcessA(NULL, sShellCmd, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
        NULL, pHome, &startInfo.StartupInfo, &procInfo);

    DeleteProcThreadAttributeList(startInfo.lpAttributeList);
    free(startInfo.lpAttributeList);

    if (!bCreated)
    {
        xloge("Failed to spawn PTY shell: sid(%u), wsfd(%d), shell(%s), error(%lu)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), sShellCmd, GetLastError());

        ClosePseudoConsole(pTerm->hPC);
        pTerm->hPC = NULL;
        DirectGate_Term_CloseWinHandles(pTerm);
        return XSTDERR;
    }

    CloseHandle(procInfo.hThread);
    pTerm->hProcess = procInfo.hProcess;
    pTerm->nPid = (pid_t)procInfo.dwProcessId;

    /* Bridge the ConPTY pipes to the event loop through a socket pair */
    XSOCKET aBridge[2] = { XSOCK_INVALID, XSOCK_INVALID };
    if (XSock_CreatePair(aBridge) != XSTDOK)
    {
        xloge("Failed to create PTY bridge socket pair: sid(%u), wsfd(%d), error(%d)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), WSAGetLastError());

        DirectGate_Term_KillChild(pTerm);
        ClosePseudoConsole(pTerm->hPC);
        pTerm->hPC = NULL;
        DirectGate_Term_CloseWinHandles(pTerm);
        return XSTDERR;
    }

    pTerm->nMasterFd = (int)aBridge[0];
    pTerm->nBridgeSock = aBridge[1];

    if (DirectGate_Term_SetNonBlock(pTerm->nMasterFd, XTRUE) < 0)
    {
        xloge("Failed to set PTY bridge non-blocking mode: sid(%u), wsfd(%d), ptfd(%d)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), pTerm->nMasterFd);

        xclosesock((XSOCKET)pTerm->nMasterFd);
        pTerm->nMasterFd = (int)XSOCK_INVALID;

        DirectGate_Term_KillChild(pTerm);
        ClosePseudoConsole(pTerm->hPC);
        pTerm->hPC = NULL;
        DirectGate_Term_CloseWinHandles(pTerm);
        return XSTDERR;
    }

    pTerm->hOutPump = CreateThread(NULL, 0, DirectGate_Term_OutPump, pTerm, 0, NULL);
    pTerm->hInPump = CreateThread(NULL, 0, DirectGate_Term_InPump, pTerm, 0, NULL);

    if (pTerm->hOutPump == NULL || pTerm->hInPump == NULL)
    {
        xloge("Failed to start PTY pump threads: sid(%u), wsfd(%d), error(%lu)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), GetLastError());

        DirectGate_Term_KillChild(pTerm);
        ClosePseudoConsole(pTerm->hPC);
        pTerm->hPC = NULL;

        /* Unblock and reap whichever pump did start */
        shutdown(pTerm->nBridgeSock, SD_BOTH);

        if (pTerm->hOutPump != NULL)
        {
            WaitForSingleObject(pTerm->hOutPump, 2000);
            CloseHandle(pTerm->hOutPump);
            pTerm->hOutPump = NULL;
        }

        if (pTerm->hInPump != NULL)
        {
            WaitForSingleObject(pTerm->hInPump, 2000);
            CloseHandle(pTerm->hInPump);
            pTerm->hInPump = NULL;
        }

        DirectGate_Term_CloseWinHandles(pTerm);
        xclosesock((XSOCKET)pTerm->nMasterFd);
        pTerm->nMasterFd = (int)XSOCK_INVALID;
        return XSTDERR;
    }

    pTerm->bRunning = XTRUE;
    return XSTDOK;
}

static void DirectGate_Term_KillChild(directgate_term_t *pTerm)
{
    XCHECK_VOID((pTerm != NULL));
    XCHECK_VOID((pTerm->hProcess != NULL));

    /*
        Mirror of the POSIX HUP-then-KILL shutdown: closing the pseudo
        console asks the attached shell to leave, TerminateProcess is the
        SIGKILL fallback when it does not exit within the grace period.
    */
    if (pTerm->hPC != NULL)
    {
        ClosePseudoConsole(pTerm->hPC);
        pTerm->hPC = NULL;
    }

    if (WaitForSingleObject(pTerm->hProcess, 500) == WAIT_TIMEOUT)
    {
        TerminateProcess(pTerm->hProcess, 127);
        WaitForSingleObject(pTerm->hProcess, 2000);
    }

    CloseHandle(pTerm->hProcess);
    pTerm->hProcess = NULL;
    pTerm->nPid = -1;

    /* Unblock the pumps and reap them before the handles go away */
    if (pTerm->nBridgeSock != XSOCK_INVALID)
        shutdown(pTerm->nBridgeSock, SD_BOTH);

    if (pTerm->hOutPump != NULL)
    {
        WaitForSingleObject(pTerm->hOutPump, 2000);
        CloseHandle(pTerm->hOutPump);
        pTerm->hOutPump = NULL;
    }

    if (pTerm->hInPump != NULL)
    {
        WaitForSingleObject(pTerm->hInPump, 2000);
        CloseHandle(pTerm->hInPump);
        pTerm->hInPump = NULL;
    }

    DirectGate_Term_CloseWinHandles(pTerm);
}
#else
static void DirectGate_Term_KillChild(directgate_term_t *pTerm)
{
    XCHECK_VOID((pTerm != NULL));
    XCHECK_VOID((pTerm->nPid > 0));

    const pid_t pid = pTerm->nPid;
    int status = 0;

    /* If already dead, reap and exit */
    int rr = DirectGate_WaitNoHang(pid, &status);
    if (rr == 1 || rr < 0)
    {
        pTerm->nPid = -1;
        return;
    }

    /* Hangup whole group */
    pid_t pgid = pid;
    (void)kill(-pgid, SIGHUP);

    /* Wait up to 500ms */
    const long hupTimeoutMs = 500;
    const long stepMs = 20;
    long waited = 0;

    while (waited < hupTimeoutMs)
    {
        rr = DirectGate_WaitNoHang(pid, &status);
        if (rr == 1 || rr < 0)
        {
            pTerm->nPid = -1;
            return;
        }

        DirectGate_SleepMs(stepMs);
        waited += stepMs;
    }

    /* Force kill whole group */
    (void)kill(-pgid, SIGKILL);

    DirectGate_WaitBlocking(pid, &status);
    pTerm->nPid = -1;
}
#endif /* _WIN32 */

static XSTATUS DirectGate_Term_SendWs(directgate_term_t *pTerm, const uint8_t *pData, size_t nLength)
{
    XCHECK(nLength, XSTDOK);
    XCHECK((pTerm != NULL), XSTDINV);
    XCHECK((pData != NULL), XSTDINV);
    XCHECK((pTerm->pWsSession != NULL), XSTDERR);

    if (pTerm->pWsSession->eType == XAPI_WS &&
        !pTerm->pWsSession->bHandshakeDone)
        return XSTDOK;

    xjson_obj_t *pHeader = DirectGate_Proto_BuildData(pTerm->nSessionId);
    XCHECK_NL((pHeader != NULL), xthrow("Failed to create PTY data header"));

    /* Add packet counter for encrypted sessions */
    if (pTerm->bEncrypt && DirectGate_E2E_IsInitialized(pTerm->pE2E))
        XJSON_AddU32(pHeader, "cc", ++pTerm->pE2E->nTxPacketId);

    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, XSTDNON, XSTDNON);

    if (!DirectGate_Proto_Build(&packet, pHeader, pData, nLength, XFALSE))
    {
        XJSON_FreeObject(pHeader);
        XByteBuffer_Clear(&packet);
        return XSTDERR;
    }

    XJSON_FreeObject(pHeader);

    if (pTerm->bEncrypt && DirectGate_E2E_IsInitialized(pTerm->pE2E))
    {
        if (!DirectGate_Proto_EncryptPackage(&packet, pTerm->pE2E, pTerm->nSessionId))
        {
            xloge("Failed to encrypt PTY data message: sid(%u), wsfd(%d), ptfd(%d)",
                pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), pTerm->nMasterFd);

            XByteBuffer_Clear(&packet);
            return XSTDERR;
        }
    }

    /* If WebRTC data channel is connected, send via P2P */
    if (pTerm->pWebRTC != NULL && DirectGate_WebRTC_IsConnected(pTerm->pWebRTC))
    {
        int nRet = DirectGate_WebRTC_Send(pTerm->pWebRTC, packet.pData, packet.nUsed);
        if (nRet >= 0)
        {
            XByteBuffer_Clear(&packet);
            return XSTDOK;
        }

        xlogw("WebRTC PTY send failed, falling back to relay: sid(%u), wsfd(%d), ptfd(%d)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), pTerm->nMasterFd);

        pTerm->pWebRTC->bConnected = XFALSE;
    }

    /* Fallback: send via WebSocket relay */
    int nStatus = DirectGate_WebSock_Send(pTerm->pWsSession, packet.pData, packet.nUsed);
    XByteBuffer_Clear(&packet);
    return nStatus;
}

static XSTATUS DirectGate_Term_Flush(directgate_term_t *pTerm)
{
    XCHECK((pTerm != NULL), XSTDINV);
    XCHECK_NL((pTerm->txBuffer.nUsed > 0), XSTDOK);

    while (pTerm->txBuffer.nUsed)
    {
#ifdef _WIN32
        int nWritten = send((XSOCKET)pTerm->nMasterFd,
            (const char*)pTerm->txBuffer.pData, (int)pTerm->txBuffer.nUsed, 0);

        if (nWritten > 0)
        {
            XByteBuffer_Advance(&pTerm->txBuffer, (size_t)nWritten);
            continue;
        }

        int nError = WSAGetLastError();
        if (nWritten < 0 && nError == WSAEINTR) continue;
        if (nWritten < 0 && nError == WSAEWOULDBLOCK) return XSTDOK;

        xloge("Failed to write PTY buffer: sid(%u), wsfd(%d), ptfd(%d), error(%d)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), pTerm->nMasterFd, nError);
#else
        ssize_t nWritten = write(pTerm->nMasterFd, pTerm->txBuffer.pData, pTerm->txBuffer.nUsed);
        if (nWritten > 0)
        {
            XByteBuffer_Advance(&pTerm->txBuffer, (size_t)nWritten);
            continue;
        }

        if (nWritten < 0 && errno == EINTR) continue;
        if (nWritten < 0 && (errno == EAGAIN ||
            errno == EWOULDBLOCK)) return XSTDOK;

        xloge("Failed to write PTY buffer: sid(%u), wsfd(%d), ptfd(%d), errno(%d)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), pTerm->nMasterFd, errno);
#endif

        return XSTDERR;
    }

    return XSTDOK;
}

void DirectGate_Term_Init(directgate_term_t *pTerm)
{
    XCHECK_VOID_NL(pTerm);
    memset(pTerm, 0, sizeof(*pTerm));

    XByteBuffer_Init(&pTerm->txBuffer, XSTDNON, XFALSE);
    pTerm->nMasterFd = (int)XSOCK_INVALID;
    pTerm->bHaveWinSize = XFALSE;
    pTerm->bRunning = XFALSE;
    pTerm->bEncrypt = XFALSE;
    pTerm->pPTYSession = NULL;
    pTerm->pWsSession = NULL;
    pTerm->pApi = NULL;
    pTerm->pE2E = NULL;
    pTerm->nPid = -1;
    pTerm->nSessionId = 0;

#ifdef _WIN32
    pTerm->hPC = NULL;
    pTerm->hProcess = NULL;
    pTerm->hConInWrite = NULL;
    pTerm->hConOutRead = NULL;
    pTerm->hOutPump = NULL;
    pTerm->hInPump = NULL;
    pTerm->nBridgeSock = XSOCK_INVALID;
#endif
}

void DirectGate_Term_Clear(directgate_term_t *pTerm)
{
    XCHECK_VOID_NL(pTerm);
    XByteBuffer_Clear(&pTerm->txBuffer);
    pTerm->nMasterFd = (int)XSOCK_INVALID;
    pTerm->bHaveWinSize = XFALSE;
    pTerm->bRunning = XFALSE;
    pTerm->pPTYSession = NULL;
    pTerm->pWsSession = NULL;
    pTerm->pApi = NULL;
    pTerm->nPid = -1;

#ifdef _WIN32
    pTerm->hPC = NULL;
    pTerm->hProcess = NULL;
    pTerm->hConInWrite = NULL;
    pTerm->hConOutRead = NULL;
    pTerm->hOutPump = NULL;
    pTerm->hInPump = NULL;
    pTerm->nBridgeSock = XSOCK_INVALID;
#endif
}

xbool_t DirectGate_Term_IsRunning(const directgate_term_t *pTerm)
{
    XCHECK_NL((pTerm != NULL), XFALSE);
    return pTerm->bRunning;
}

XSTATUS DirectGate_Term_StartNoEndpoint(directgate_term_t *pTerm, xapi_t *pApi, xapi_session_t *pWsSession)
{
    XCHECK((pApi != NULL), XSTDINV);
    XCHECK((pTerm != NULL), XSTDINV);
    XCHECK((pWsSession != NULL), XSTDINV);
    XCHECK_NL((!pTerm->bRunning), XSTDOK);

    DirectGate_Term_Clear(pTerm);
    XByteBuffer_Init(&pTerm->txBuffer, XSTDNON, XFALSE);

    XCHECK((DirectGate_Term_Spawn(pTerm) >= 0),
        xthrow("Failed to spawn PTY process"));

    pTerm->pApi = pApi;
    pTerm->pWsSession = pWsSession;

    if (pTerm->bHaveWinSize)
        DirectGate_Term_UpdateWinSize(pTerm, &pTerm->winSize);

    return XSTDOK;
}

XSTATUS DirectGate_Term_Start(directgate_term_t *pTerm, xapi_t *pApi, xapi_session_t *pWsSession)
{
    XSTATUS nStatus = DirectGate_Term_StartNoEndpoint(pTerm, pApi, pWsSession);
    XCHECK_NL((nStatus >= 0), nStatus);

    xapi_endpoint_t endpt;
    XAPI_InitEndpoint(&endpt);

    endpt.eType = XAPI_EVENT;
    endpt.eRole = XAPI_CUSTOM;
    endpt.nFD = pTerm->nMasterFd;
    endpt.nEvents = XPOLLIN;
    endpt.bUnix = XTRUE;
    endpt.pSessionData = pTerm;

    if (XAPI_AddEndpoint(pApi, &endpt) < 0)
    {
        xloge("Failed to register PTY endpoint: sid(%u), wsfd(%d), ptfd(%d)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), pTerm->nMasterFd);

        DirectGate_Term_Shutdown(pTerm, XTRUE);
        return XSTDERR;
    }

    return XSTDOK;
}

void DirectGate_Term_RequestStop(directgate_term_t *pTerm)
{
    XCHECK_VOID((pTerm != NULL));
    XCHECK_VOID_NL(pTerm->bRunning);

    if (pTerm->pPTYSession != NULL)
        XAPI_Disconnect(pTerm->pPTYSession);
    else DirectGate_Term_Shutdown(pTerm, XTRUE);
}

void DirectGate_Term_Shutdown(directgate_term_t *pTerm, xbool_t bCloseFd)
{
    XCHECK_VOID((pTerm != NULL));
    XCHECK_VOID_NL(pTerm->bRunning);

    xlogd("Terminating PTY process: sid(%u), wsfd(%d), ptfd(%d), pid(%d)",
        pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), pTerm->nMasterFd, (int)pTerm->nPid);

    DirectGate_Term_KillChild(pTerm);

    xlogd("PTY process reaped: sid(%u), wsfd(%d), ptfd(%d)",
        pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), pTerm->nMasterFd);

    if (bCloseFd && pTerm->nMasterFd != (int)XSOCK_INVALID)
    {
        /* xclosesock: close() on POSIX, closesocket() for the Windows bridge */
        xclosesock((XSOCKET)pTerm->nMasterFd);
        pTerm->nMasterFd = (int)XSOCK_INVALID;
    }
    else
    {
        xlogt("Keeping PTY master fd open for async cleanup: sid(%u), wsfd(%d), ptfd(%d)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), pTerm->nMasterFd);

        pTerm->nMasterFd = (int)XSOCK_INVALID;
    }

    XByteBuffer_Clear(&pTerm->txBuffer);
    pTerm->pPTYSession = NULL;
    pTerm->bRunning = XFALSE;
    pTerm->bEncrypt = XFALSE;
}

void DirectGate_Term_AttachEvent(directgate_term_t *pTerm, xapi_session_t *pPTYSession)
{
    XCHECK_VOID((pTerm != NULL));
    XCHECK_VOID((pPTYSession != NULL));
    pTerm->pPTYSession = pPTYSession;

    if (pTerm->txBuffer.nUsed)
        XAPI_EnableEvent(pPTYSession, XPOLLOUT);
}

void DirectGate_Term_DetachEvent(directgate_term_t *pTerm)
{
    XCHECK_VOID((pTerm != NULL));
    pTerm->pPTYSession = NULL;
}

int DirectGate_Term_OnRead(directgate_term_t *pTerm)
{
    XCHECK((pTerm != NULL), XAPI_DISCONNECT);
    XCHECK(pTerm->bRunning, XAPI_DISCONNECT);

    for (;;)
    {
        uint8_t sBuffer[DIRECTGATE_TERM_BUF_SIZE];

#ifdef _WIN32
        int nRead = recv((XSOCKET)pTerm->nMasterFd, (char*)sBuffer, (int)sizeof(sBuffer), 0);

        if (nRead > 0)
        {
            if (DirectGate_Term_SendWs(pTerm, sBuffer, (size_t)nRead) < 0)
                return XAPI_DISCONNECT;

            continue;
        }

        /* recv() == 0: out pump signaled EOF, the shell has exited */
        if (nRead == 0) return XAPI_DISCONNECT;

        int nError = WSAGetLastError();
        if (nError == WSAEINTR) continue;
        if (nError == WSAEWOULDBLOCK) break;

        xloge("Failed to read PTY output: sid(%u), wsfd(%d), ptfd(%d), error(%d)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), pTerm->nMasterFd, nError);

        return XAPI_DISCONNECT;
#else
        ssize_t nRead = read(pTerm->nMasterFd, sBuffer, sizeof(sBuffer));

        if (nRead > 0)
        {
            if (DirectGate_Term_SendWs(pTerm, sBuffer, (size_t)nRead) < 0)
                return XAPI_DISCONNECT;

            continue;
        }

        if (nRead == 0) return XAPI_DISCONNECT;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        if (errno == EIO) return XAPI_DISCONNECT;

        xloge("Failed to read PTY output: sid(%u), wsfd(%d), ptfd(%d), errno(%d)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), pTerm->nMasterFd, errno);

        return XAPI_DISCONNECT;
#endif
    }

    return XAPI_CONTINUE;
}

int DirectGate_Term_OnWrite(directgate_term_t *pTerm)
{
    XCHECK((pTerm != NULL), XAPI_DISCONNECT);
    XCHECK(pTerm->bRunning, XAPI_DISCONNECT);

    XCHECK((DirectGate_Term_Flush(pTerm) >= 0),
        xthrowr(XAPI_DISCONNECT, "Failed to flush PTY output"));

    if (!pTerm->txBuffer.nUsed && pTerm->pPTYSession != NULL)
        XAPI_DisableEvent(pTerm->pPTYSession, XPOLLOUT);

    return XAPI_CONTINUE;
}

XSTATUS DirectGate_Term_Write(directgate_term_t *pTerm, const uint8_t *pData, size_t nLength)
{
    XCHECK((pTerm != NULL), XSTDINV);
    XCHECK(pTerm->bRunning, XSTDERR);

    XCHECK_NL((pData != NULL), XSTDOK);
    XCHECK_NL((nLength > 0), XSTDOK);

    XCHECK((XByteBuffer_Add(&pTerm->txBuffer, pData, nLength) > 0),
        xthrow("Failed to append data to PTY buffer"));

    XCHECK((DirectGate_Term_Flush(pTerm) >= 0),
        xthrow("Failed to flush PTY output"));

    if (pTerm->txBuffer.nUsed && pTerm->pPTYSession != NULL)
        XAPI_EnableEvent(pTerm->pPTYSession, XPOLLOUT);

    return XSTDOK;
}

XSTATUS DirectGate_Term_UpdateWinSize(directgate_term_t *pTerm, const struct winsize *pSize)
{
    XCHECK((pTerm != NULL), XSTDINV);
    XCHECK((pSize != NULL), XSTDINV);

    XCHECK_NL(pTerm->bRunning, XSTDOK);
    XCHECK_NL((pTerm->nMasterFd >= 0) , XSTDOK);

    pTerm->winSize = *pSize;
    pTerm->bHaveWinSize = XTRUE;

#ifdef _WIN32
    XCHECK_NL((pTerm->hPC != NULL), XSTDOK);

    COORD size;
    size.X = (SHORT)pSize->ws_col;
    size.Y = (SHORT)pSize->ws_row;

    HRESULT hResult = ResizePseudoConsole(pTerm->hPC, size);
    if (FAILED(hResult))
    {
        xloge("Failed to update PTY window size: sid(%u), wsfd(%d), ptfd(%d), rows(%u), cols(%u), hresult(0x%lx)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), pTerm->nMasterFd,
            (unsigned)pSize->ws_row, (unsigned)pSize->ws_col, (unsigned long)hResult);

        return XSTDERR;
    }
#else
    if (ioctl(pTerm->nMasterFd, TIOCSWINSZ, pSize) != 0)
    {
        xloge("Failed to update PTY window size: sid(%u), wsfd(%d), ptfd(%d), rows(%u), cols(%u), errno(%d)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), pTerm->nMasterFd,
            (unsigned)pSize->ws_row, (unsigned)pSize->ws_col, errno);

        return XSTDERR;
    }
#endif

    return XSTDOK;
}

XSTATUS DirectGate_Term_GetCwd(const directgate_term_t *pTerm, char *pBuf, size_t nBufSize)
{
    XCHECK((pTerm != NULL), XSTDINV);
    XCHECK((pBuf != NULL), XSTDINV);
    XCHECK((nBufSize > 0), XSTDINV);
    XCHECK((pTerm->nPid > 0), XSTDERR);

#ifdef __APPLE__
    struct proc_vnodepathinfo vpi;
    int nRet = proc_pidinfo((int)pTerm->nPid, PROC_PIDVNODEPATHINFO, 0, &vpi, sizeof(vpi));
    if (nRet <= 0)
    {
        pBuf[0] = '\0';
        return XSTDERR;
    }

    xstrncpy(pBuf, nBufSize, vpi.pvi_cdir.vip_path);
#elif defined(_WIN32)
    /*
        The working directory of the shell lives in the CurrentDirectory
        field of its RTL_USER_PROCESS_PARAMETERS. winternl.h hides that
        field behind Reserved2, but the layout is stable on 64-bit
        Windows: CURDIR sits at offset 0x38. Tracks cmd.exe faithfully;
        PowerShell keeps Set-Location in managed state without chdir, so
        the value reflects only its startup directory there.
    */
    pBuf[0] = '\0';
    XCHECK((pTerm->hProcess != NULL), XSTDERR);

    PROCESS_BASIC_INFORMATION basicInfo;
    memset(&basicInfo, 0, sizeof(basicInfo));
    ULONG nInfoLen = 0;

    NTSTATUS nStatus = NtQueryInformationProcess(pTerm->hProcess,
        ProcessBasicInformation, &basicInfo, sizeof(basicInfo), &nInfoLen);

    if (nStatus != 0 || basicInfo.PebBaseAddress == NULL) return XSTDERR;

    PEB peb;
    SIZE_T nMemRead = 0;
    if (!ReadProcessMemory(pTerm->hProcess, basicInfo.PebBaseAddress,
        &peb, sizeof(peb), &nMemRead) || nMemRead != sizeof(peb)) return XSTDERR;

    UNICODE_STRING dosPath;
    const size_t nCurDirOffset = 0x38; /* CURDIR.DosPath inside process parameters */

    if (!ReadProcessMemory(pTerm->hProcess,
        (uint8_t*)peb.ProcessParameters + nCurDirOffset,
        &dosPath, sizeof(dosPath), &nMemRead) || nMemRead != sizeof(dosPath)) return XSTDERR;

    if (dosPath.Buffer == NULL || dosPath.Length == 0 ||
        dosPath.Length > (XPATH_MAX * sizeof(WCHAR))) return XSTDERR;

    WCHAR wsCwd[XPATH_MAX];
    size_t nChars = dosPath.Length / sizeof(WCHAR);

    if (!ReadProcessMemory(pTerm->hProcess, dosPath.Buffer,
        wsCwd, dosPath.Length, &nMemRead) || nMemRead != dosPath.Length) return XSTDERR;

    /* NT keeps a trailing backslash; drop it except for drive roots */
    if (nChars > 3 && wsCwd[nChars - 1] == L'\\') nChars--;

    int nConverted = WideCharToMultiByte(CP_UTF8, 0, wsCwd, (int)nChars,
        pBuf, (int)nBufSize - 1, NULL, NULL);

    if (nConverted <= 0)
    {
        pBuf[0] = '\0';
        return XSTDERR;
    }

    pBuf[nConverted] = '\0';
#else
    char sProcPath[64];
    snprintf(sProcPath, sizeof(sProcPath), "/proc/%d/cwd", (int)pTerm->nPid);

    ssize_t nLen = readlink(sProcPath, pBuf, nBufSize - 1);
    if (nLen < 0)
    {
        pBuf[0] = '\0';
        return XSTDERR;
    }

    pBuf[nLen] = '\0';
#endif

    return XSTDOK;
}
