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

#ifdef __APPLE__
#include <libproc.h>
#endif

#define DIRECTGATE_TERM_BUF_SIZE 4096

/* Reads of shell output per event: bounds how long one busy shell can hold the
 * loop before every other session, and its own queued output, get a turn. */
#define DIRECTGATE_TERM_READ_BUDGET   16

/* Transport backlog at which shell output stops being read, and the level it
 * has to drain back to before reading resumes. The relay socket is shared, so
 * the high mark sits well above what a file transfer keeps queued on it
 * (DIRECTGATE_TRANSFER_WS_BUFFER_MAX): a transfer must not freeze a terminal,
 * only a link that is genuinely not keeping up. */
#define DIRECTGATE_TERM_TX_HIGH_WATER (4U * 1024U * 1024U)
#define DIRECTGATE_TERM_TX_LOW_WATER  (1U * 1024U * 1024U)

/* Input the shell has not read yet. A program that stops reading stdin while
 * the viewer keeps pasting is the only way to reach it. */
#define DIRECTGATE_TERM_TX_MAX        (8U * 1024U * 1024U)

static int DirectGate_Term_GetWsFd(const directgate_term_t *pTerm)
{
    XCHECK_NL((pTerm != NULL), (int)XSOCK_INVALID);
    XCHECK_NL((pTerm->pWsSession != NULL), (int)XSOCK_INVALID);
    return (int)pTerm->pWsSession->sock.nFD;
}

static void DirectGate_Term_KillChild(directgate_term_t *pTerm);

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
extern char **environ;

/* Grace a hung-up shell gets before SIGKILL, and how many can wait at once. */
#define DIRECTGATE_TERM_HUP_GRACE_MS  500U
#define DIRECTGATE_TERM_REAP_SLOTS    64U

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

static void DirectGate_Term_FreeSpawn(directgate_term_spawn_t *pSpawn)
{
    XCHECK_VOID_NL((pSpawn != NULL));

    if (pSpawn->ppEnv != NULL)
    {
        for (size_t i = 0; pSpawn->ppEnv[i] != NULL; i++) free(pSpawn->ppEnv[i]);
        free(pSpawn->ppEnv);
    }

    free(pSpawn->pGroups);
    memset(pSpawn, 0, sizeof(*pSpawn));
}

/* getpwnam_r/getpwuid_r into a buffer that grows until the record fits: a long
 * GECOS field or an LDAP account can exceed any fixed size. */
static struct passwd* DirectGate_Term_LookupUser(const char *pName, struct passwd *pPwd, char **ppBuf)
{
    size_t nSize = 16384;
    *ppBuf = NULL;

    for (int nTry = 0; nTry < 8; nTry++, nSize *= 2)
    {
        char *pBuf = (char*)realloc(*ppBuf, nSize);
        if (pBuf == NULL) break;
        *ppBuf = pBuf;

        struct passwd *pResult = NULL;
        int nError = xstrused(pName) ?
            getpwnam_r(pName, pPwd, pBuf, nSize, &pResult) :
            getpwuid_r(getuid(), pPwd, pBuf, nSize, &pResult);

        if (nError == ERANGE) continue;
        if (nError != 0) errno = nError;
        return pResult;
    }

    return NULL;
}

static xbool_t DirectGate_Term_IsLoginShell(const char *pShell)
{
    if (!xstrused(pShell) || access(pShell, X_OK) != 0) return XFALSE;

    const char *pBase = strrchr(pShell, '/');
    pBase = pBase != NULL ? pBase + 1 : pShell;

    /* Accounts that must not get a shell carry one of these on purpose. */
    return (strcmp(pBase, "nologin") && strcmp(pBase, "false")) ? XTRUE : XFALSE;
}

static const char* DirectGate_Term_GetShellPath(const char *pUserShell)
{
    /* The account's own login shell first, as login and sshd do. The agent's
       $SHELL is only its own: after a privilege drop from root it names
       root's shell, not the one the account chose. */
    if (DirectGate_Term_IsLoginShell(pUserShell)) return pUserShell;

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

static xbool_t DirectGate_Term_EnvIsOverridden(const char *pEntry)
{
    static const char *pNames[] = { "HOME=", "USER=", "LOGNAME=", "SHELL=", "TERM=" };

    for (size_t i = 0; i < XARR_SIZE(pNames); i++)
        if (!strncmp(pEntry, pNames[i], strlen(pNames[i]))) return XTRUE;

    return XFALSE;
}

/* The agent's environment with the identity variables replaced by the target
 * account's. Inherited unchanged they described the process that started the
 * agent - HOME=/root after a privilege drop - so the user's shell read root's
 * startup files, failed to write its history and took `cd` to /root. */
static char** DirectGate_Term_BuildEnv(const char *pUser, const char *pHome, const char *pShell)
{
    size_t nInherited = 0;
    while (environ != NULL && environ[nInherited] != NULL) nInherited++;

    char **ppEnv = (char**)calloc(nInherited + 6, sizeof(char*));
    XCHECK_NL((ppEnv != NULL), NULL);
    size_t nCount = 0;

    for (size_t i = 0; i < nInherited; i++)
    {
        if (DirectGate_Term_EnvIsOverridden(environ[i])) continue;
        if ((ppEnv[nCount] = strdup(environ[i])) == NULL) break;
        nCount++;
    }

    const char *pNames[] = { "HOME", "USER", "LOGNAME", "SHELL", "TERM" };
    const char *pValues[] = { pHome, pUser, pUser, pShell, "xterm-256color" };

    for (size_t i = 0; i < XARR_SIZE(pNames); i++)
    {
        if (!xstrused(pValues[i])) continue;

        size_t nLen = strlen(pNames[i]) + strlen(pValues[i]) + 2;
        char *pEntry = (char*)malloc(nLen);
        if (pEntry == NULL) break;

        snprintf(pEntry, nLen, "%s=%s", pNames[i], pValues[i]);
        ppEnv[nCount++] = pEntry;
    }

    ppEnv[nCount] = NULL;
    return ppEnv;
}

static XSTATUS DirectGate_Term_ResolveShell(const directgate_term_t *pTerm, directgate_term_spawn_t *pSpawn)
{
    XCHECK((pTerm != NULL && pSpawn != NULL), XSTDINV);
    memset(pSpawn, 0, sizeof(*pSpawn));

    pSpawn->nUid = getuid();
    pSpawn->nGid = getgid();

    struct passwd pwd;
    char *pPwBuf = NULL;
    struct passwd *pUser = DirectGate_Term_LookupUser(pTerm->sShellUser, &pwd, &pPwBuf);

    /* A configured user that does not resolve fails closed, never falling
       back to the agent's own account. */
    if (xstrused(pTerm->sShellUser) && pUser == NULL)
    {
        xloge("Configured PTY user not found: user(%s), errno(%d)", pTerm->sShellUser, errno);
        free(pPwBuf);
        return XSTDERR;
    }

    const char *pName = pUser != NULL ? pUser->pw_name : NULL;
    const char *pUserHome = pUser != NULL ? pUser->pw_dir : NULL;

    if (pUser != NULL && !(getuid() == pUser->pw_uid && geteuid() == pUser->pw_uid))
    {
        int nGroups = 64;

        for (int nTry = 0; nTry < 8; nTry++)
        {
            gid_t *pGroups = (gid_t*)realloc(pSpawn->pGroups, (size_t)nGroups * sizeof(gid_t));
            if (pGroups == NULL) break;
            pSpawn->pGroups = pGroups;

            int nFound = nGroups;
#ifdef __APPLE__
            if (getgrouplist(pUser->pw_name, (int)pUser->pw_gid, (int*)pGroups, &nFound) >= 0)
#else
            if (getgrouplist(pUser->pw_name, pUser->pw_gid, pGroups, &nFound) >= 0)
#endif
            {
                pSpawn->nGroups = nFound;
                break;
            }

            nGroups = nFound > nGroups ? nFound : nGroups * 2;
        }

        if (pSpawn->nGroups <= 0)
        {
            xloge("Failed to resolve PTY supplementary groups: user(%s), gid(%u)",
                pUser->pw_name, (unsigned)pUser->pw_gid);

            free(pPwBuf);
            DirectGate_Term_FreeSpawn(pSpawn);
            return XSTDERR;
        }

        pSpawn->bSwitchUser = XTRUE;
        pSpawn->nUid = pUser->pw_uid;
        pSpawn->nGid = pUser->pw_gid;
    }

    const char *pWorkDir = xstrused(pTerm->sShellHome) ? pTerm->sShellHome : pUserHome;
    if (!xstrused(pWorkDir))
    {
        xlogd("PTY shell home is not set, using root");
        pWorkDir = "/";
    }

    xstrncpy(pSpawn->sWorkDir, sizeof(pSpawn->sWorkDir), pWorkDir);
    xstrncpy(pSpawn->sShell, sizeof(pSpawn->sShell),
        DirectGate_Term_GetShellPath(pUser != NULL ? pUser->pw_shell : NULL));
    xstrncpy(pSpawn->sArg0, sizeof(pSpawn->sArg0), DirectGate_Term_GetArg0(pSpawn->sShell));

    pSpawn->ppEnv = DirectGate_Term_BuildEnv(pName, xstrused(pUserHome) ? pUserHome : pSpawn->sWorkDir, pSpawn->sShell);
    free(pPwBuf);

    if (pSpawn->ppEnv == NULL)
    {
        xloge("Failed to prepare the PTY environment: user(%s)", xstrused(pName) ? pName : "N/A");
        DirectGate_Term_FreeSpawn(pSpawn);
        return XSTDERR;
    }

    return XSTDOK;
}

/* Child side of the spawn: system calls only (see directgate_term_spawn_t).
   The message goes to the new terminal, where the user who opened it sees why
   it closed straight away. */
static void DirectGate_Term_ChildFail(const char *pMessage)
{
    ssize_t nWritten = write(STDERR_FILENO, pMessage, strlen(pMessage));
    (void)nWritten;
    _exit(127);
}

static void DirectGate_Term_ExecChild(const directgate_term_spawn_t *pSpawn, int nSlaveFd)
{
    /* detach from parent */
    if (setsid() < 0) _exit(127);

    if (ioctl(nSlaveFd, TIOCSCTTY, 0) != 0 ||
        dup2(nSlaveFd, STDIN_FILENO) < 0 ||
        dup2(nSlaveFd, STDOUT_FILENO) < 0 ||
        dup2(nSlaveFd, STDERR_FILENO) < 0)
    {
        _exit(127);
    }

    if (nSlaveFd > STDERR_FILENO) close(nSlaveFd);

    /* Order matters: supplementary groups, then gid, then uid. */
    if (pSpawn->bSwitchUser &&
        (setgroups((size_t)pSpawn->nGroups, pSpawn->pGroups) != 0 ||
         setgid(pSpawn->nGid) != 0 || setuid(pSpawn->nUid) != 0))
    {
        DirectGate_Term_ChildFail("directgate: cannot switch to the configured shell user\r\n");
    }

    if (chdir(pSpawn->sWorkDir) != 0 && chdir("/") != 0)
        DirectGate_Term_ChildFail("directgate: no usable working directory\r\n");

    char *pArgv[] = { (char*)pSpawn->sArg0, (char*)"-i", NULL };
    execve(pSpawn->sShell, pArgv, pSpawn->ppEnv);
    DirectGate_Term_ChildFail("directgate: cannot start the shell\r\n");
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

static XSTATUS DirectGate_Term_Spawn(directgate_term_t *pTerm)
{
    XCHECK((pTerm != NULL), XSTDINV);

    directgate_term_spawn_t spawn;
    if (DirectGate_Term_ResolveShell(pTerm, &spawn) < 0) return XSTDERR;

    int nMasterFd = -1;
    int nSlaveFd = -1;

    if (openpty(&nMasterFd, &nSlaveFd, NULL, NULL, NULL) != 0)
    {
        xloge("Failed to open PTY session: sid(%u), wsfd(%d), errno(%d)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), errno);

        DirectGate_Term_FreeSpawn(&spawn);
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
        DirectGate_Term_FreeSpawn(&spawn);
        return XSTDERR;
    }

    if (nPid == 0)
    {
        close(nMasterFd);
        DirectGate_Term_ExecChild(&spawn, nSlaveFd);
        _exit(127);
    }

    close(nSlaveFd);
    DirectGate_Term_FreeSpawn(&spawn);

    if (DirectGate_Term_SetNonBlock(nMasterFd, XTRUE) < 0)
    {
        xloge("Failed to set PTY non-blocking mode: sid(%u), wsfd(%d), ptfd(%d), errno(%d)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), nMasterFd, errno);

        /* close PTY master fd */
        close(nMasterFd);

        /* terminal-like shutdown: HUP then KILL, reaped off the event loop */
        pTerm->nPid = nPid;
        (void)kill(-nPid, SIGKILL);
        DirectGate_Term_KillChild(pTerm);
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

/*
    What a pump works on, copied out of the terminal so the thread never reads
    the terminal itself: that lives inside the session, which is freed on the
    event loop. The pump frees this on its way out. One that outlives its join
    (it should not - closing the console and the bridge ends both) keeps its
    handle and socket, which DirectGate_Term_JoinPumps then leaves open rather
    than closing values a live thread is still using.
*/
typedef struct directgate_term_pump_ {
    HANDLE hPipe;           /* ConPTY output read end, or input write end */
    XSOCKET nBridgeSock;
} directgate_term_pump_t;

static DWORD WINAPI DirectGate_Term_OutPump(LPVOID pArg)
{
    directgate_term_pump_t pump = *(directgate_term_pump_t*)pArg;
    uint8_t sBuffer[DIRECTGATE_TERM_BUF_SIZE];
    DWORD nRead = 0;
    free(pArg);

    while (ReadFile(pump.hPipe, sBuffer, sizeof(sBuffer), &nRead, NULL) && nRead > 0)
    {
        size_t nSent = 0;
        while (nSent < (size_t)nRead)
        {
            int nRet = send(pump.nBridgeSock, (const char*)sBuffer + nSent, (int)(nRead - nSent), 0);
            if (nRet <= 0) return 0;
            nSent += (size_t)nRet;
        }
    }

    /* Shell side is gone: signal EOF to the event loop (recv returns 0) */
    shutdown(pump.nBridgeSock, SD_SEND);
    return 0;
}

static DWORD WINAPI DirectGate_Term_InPump(LPVOID pArg)
{
    directgate_term_pump_t pump = *(directgate_term_pump_t*)pArg;
    char sBuffer[DIRECTGATE_TERM_BUF_SIZE];
    free(pArg);

    for (;;)
    {
        int nRecv = recv(pump.nBridgeSock, sBuffer, sizeof(sBuffer), 0);
        if (nRecv <= 0) return 0;

        size_t nWritten = 0;
        while (nWritten < (size_t)nRecv)
        {
            DWORD nDone = 0;
            if (!WriteFile(pump.hPipe, sBuffer + nWritten, (DWORD)(nRecv - nWritten), &nDone, NULL))
                return 0;

            nWritten += (size_t)nDone;
        }
    }
}

static HANDLE DirectGate_Term_StartPump(LPTHREAD_START_ROUTINE fnPump, HANDLE hPipe, XSOCKET nBridgeSock)
{
    directgate_term_pump_t *pPump = (directgate_term_pump_t*)malloc(sizeof(*pPump));
    if (pPump == NULL) return NULL;

    pPump->hPipe = hPipe;
    pPump->nBridgeSock = nBridgeSock;

    HANDLE hThread = CreateThread(NULL, 0, fnPump, pPump, 0, NULL);
    if (hThread == NULL) free(pPump);

    return hThread;
}

/* Bridge shut down first, so both pumps are on their way out. A pump that still has not left keeps what it uses:
   its pipe end and the bridge socket are dropped from the terminal without being closed. */
static void DirectGate_Term_JoinPumps(directgate_term_t *pTerm)
{
    xbool_t bOutStuck = XFALSE;
    xbool_t bInStuck = XFALSE;

    if (pTerm->nBridgeSock != XSOCK_INVALID)
        shutdown(pTerm->nBridgeSock, SD_BOTH);

    if (pTerm->hOutPump != NULL)
    {
        bOutStuck = (WaitForSingleObject(pTerm->hOutPump, 2000) != WAIT_OBJECT_0) ? XTRUE : XFALSE;
        CloseHandle(pTerm->hOutPump);
        pTerm->hOutPump = NULL;
    }

    if (pTerm->hInPump != NULL)
    {
        bInStuck = (WaitForSingleObject(pTerm->hInPump, 2000) != WAIT_OBJECT_0) ? XTRUE : XFALSE;
        CloseHandle(pTerm->hInPump);
        pTerm->hInPump = NULL;
    }

    if (!bOutStuck && !bInStuck) return;

    xlogw("PTY pump did not exit, leaving its handles open: sid(%u), out(%s), in(%s)",
        pTerm->nSessionId, bOutStuck ? "stuck" : "done", bInStuck ? "stuck" : "done");

    if (bOutStuck) pTerm->hConOutRead = NULL;
    if (bInStuck) pTerm->hConInWrite = NULL;
    pTerm->nBridgeSock = XSOCK_INVALID;
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

    pTerm->hOutPump = DirectGate_Term_StartPump(DirectGate_Term_OutPump, pTerm->hConOutRead, pTerm->nBridgeSock);
    pTerm->hInPump = DirectGate_Term_StartPump(DirectGate_Term_InPump, pTerm->hConInWrite, pTerm->nBridgeSock);

    if (pTerm->hOutPump == NULL || pTerm->hInPump == NULL)
    {
        xloge("Failed to start PTY pump threads: sid(%u), wsfd(%d), error(%lu)",
            pTerm->nSessionId, DirectGate_Term_GetWsFd(pTerm), GetLastError());

        DirectGate_Term_KillChild(pTerm);
        ClosePseudoConsole(pTerm->hPC);
        pTerm->hPC = NULL;

        /* Unblock and reap whichever pump did start */
        DirectGate_Term_JoinPumps(pTerm);
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
    DirectGate_Term_JoinPumps(pTerm);
    DirectGate_Term_CloseWinHandles(pTerm);
}

size_t DirectGate_Term_ReapPending(void)
{
    /* KillChild still waits for the process in-line on Windows. */
    return 0;
}
#else
/* Shells that were hung up and have not exited yet. The event loop polls them
   (DirectGate_Term_ReapPending) instead of waiting: the old in-line wait held
   the loop for up to half a second on every terminal close, and its final
   blocking waitpid never returned for a shell stuck in uninterruptible sleep -
   a dead NFS mount froze the whole agent. Main thread only. */
typedef struct directgate_term_reap_ {
    pid_t nPid;
    uint64_t nKillAtMs;
    xbool_t bKilled;
} directgate_term_reap_t;

static directgate_term_reap_t g_termReap[DIRECTGATE_TERM_REAP_SLOTS];

static void DirectGate_Term_DeferReap(pid_t nPid)
{
    for (size_t i = 0; i < DIRECTGATE_TERM_REAP_SLOTS; i++)
    {
        if (g_termReap[i].nPid > 0) continue;

        g_termReap[i].nPid = nPid;
        g_termReap[i].nKillAtMs = XTime_GetMonoMs() + DIRECTGATE_TERM_HUP_GRACE_MS;
        g_termReap[i].bKilled = XFALSE;
        return;
    }

    /* Every slot taken: skip the grace rather than lose track of the child. */
    (void)kill(-nPid, SIGKILL);
    if (DirectGate_WaitNoHang(nPid, NULL) == 0)
        xlogw("PTY process could not be reaped yet, reap queue is full: pid(%d)", (int)nPid);
}

size_t DirectGate_Term_ReapPending(void)
{
    uint64_t nNowMs = XTime_GetMonoMs();
    size_t nPending = 0;

    for (size_t i = 0; i < DIRECTGATE_TERM_REAP_SLOTS; i++)
    {
        directgate_term_reap_t *pReap = &g_termReap[i];
        if (pReap->nPid <= 0) continue;

        if (DirectGate_WaitNoHang(pReap->nPid, NULL) != 0)
        {
            memset(pReap, 0, sizeof(*pReap));
            continue;
        }

        if (!pReap->bKilled && nNowMs >= pReap->nKillAtMs)
        {
            xlogd("PTY process ignored hangup, killing its process group: pid(%d)", (int)pReap->nPid);
            (void)kill(-pReap->nPid, SIGKILL);
            pReap->bKilled = XTRUE;
        }

        nPending++;
    }

    return nPending;
}

static void DirectGate_Term_KillChild(directgate_term_t *pTerm)
{
    XCHECK_VOID((pTerm != NULL));
    XCHECK_VOID((pTerm->nPid > 0));

    const pid_t pid = pTerm->nPid;
    pTerm->nPid = -1;

    /* If already dead, reap and exit */
    if (DirectGate_WaitNoHang(pid, NULL) != 0) return;

    /* Hangup whole group; the rest happens on the event loop. */
    (void)kill(-pid, SIGHUP);
    if (DirectGate_WaitNoHang(pid, NULL) != 0) return;

    DirectGate_Term_DeferReap(pid);
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
        DirectGate_Proto_AddCC(pHeader, pTerm->pE2E,
            pTerm->pWebRTC != NULL ? pTerm->pWebRTC->nSignalGeneration : 0);

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

        DirectGate_WebRTC_NoteSendFailure(pTerm->pWebRTC);
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

        /* A failed registration closes the descriptor itself; only the shell is left to reap. */
        DirectGate_Term_Shutdown(pTerm, XFALSE);
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
    pTerm->bReadPaused = XFALSE;
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

static xbool_t DirectGate_Term_IsBacklogged(const directgate_term_t *pTerm, size_t nLimit)
{
    XCHECK_NL((pTerm != NULL), XFALSE);

    if (pTerm->pWebRTC != NULL && DirectGate_WebRTC_IsConnected(pTerm->pWebRTC))
    {
        int nBuffered = DirectGate_WebRTC_GetBufferedAmount(pTerm->pWebRTC);
        return (nBuffered > 0 && (size_t)nBuffered > nLimit) ? XTRUE : XFALSE;
    }

    return (pTerm->pWsSession != NULL && pTerm->pWsSession->txBuffer.nUsed > nLimit) ? XTRUE : XFALSE;
}

xbool_t DirectGate_Term_IsReadPaused(const directgate_term_t *pTerm)
{
    XCHECK_NL((pTerm != NULL), XFALSE);
    return pTerm->bRunning && pTerm->bReadPaused;
}

void DirectGate_Term_ResumeRead(directgate_term_t *pTerm)
{
    XCHECK_VOID_NL((pTerm != NULL));
    XCHECK_VOID_NL((pTerm->bReadPaused));

    if (!pTerm->bRunning || pTerm->pPTYSession == NULL)
    {
        pTerm->bReadPaused = XFALSE;
        return;
    }

    if (DirectGate_Term_IsBacklogged(pTerm, DIRECTGATE_TERM_TX_LOW_WATER)) return;

    pTerm->bReadPaused = XFALSE;
    XAPI_EnableEvent(pTerm->pPTYSession, XPOLLIN);
}

int DirectGate_Term_OnRead(directgate_term_t *pTerm)
{
    XCHECK((pTerm != NULL), XAPI_DISCONNECT);
    XCHECK(pTerm->bRunning, XAPI_DISCONNECT);

    for (int nRound = 0; nRound < DIRECTGATE_TERM_READ_BUDGET; nRound++)
    {
        /* Stop reading while the link is this far behind: the shell then blocks on
           a full PTY, which is exactly the flow control a local terminal has. The
           level-triggered event is switched off until ResumeRead sees it drain. */
        if (pTerm->pPTYSession != NULL && DirectGate_Term_IsBacklogged(pTerm, DIRECTGATE_TERM_TX_HIGH_WATER))
        {
            if (XAPI_DisableEvent(pTerm->pPTYSession, XPOLLIN) >= 0) pTerm->bReadPaused = XTRUE;
            break;
        }

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

    if (pTerm->txBuffer.nUsed > DIRECTGATE_TERM_TX_MAX || nLength > DIRECTGATE_TERM_TX_MAX - pTerm->txBuffer.nUsed)
    {
        xloge("PTY input backlog limit reached, the shell is not reading: sid(%u), ptfd(%d), bytes(%zu)",
            pTerm->nSessionId, pTerm->nMasterFd, pTerm->txBuffer.nUsed);

        return XSTDERR;
    }

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

    pTerm->winSize = *pSize;
    pTerm->bHaveWinSize = XTRUE;

    XCHECK_NL(pTerm->bRunning, XSTDOK);
    XCHECK_NL((pTerm->nMasterFd >= 0) , XSTDOK);

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
        Windows exposes no stable public API for reading another process'
        current directory. Avoid cross-process memory inspection here: this is
        only a UI convenience feature, and failing closed is safer for AV/EDR
        trust than carrying process-inspection imports.
    */
    pBuf[0] = '\0';
    return XSTDERR;
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
