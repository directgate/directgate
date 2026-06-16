/*!
 * @file directgate-agent/src/agent/c
 * @brief SYSTEM launcher for the Windows privilege-separation model.
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
 */

#ifdef _WIN32
#include "includes.h"
#include "config.h"
#include "launcher.h"

#include <windows.h>   /* HANDLE, DWORD, etc. */
#include <wtsapi32.h>  /* WTSEnumerateSessionsA / WTSQueryUserToken */
#include <userenv.h>   /* CreateEnvironmentBlock / DestroyEnvironmentBlock */

#define DIRECTGATE_WIN_LAUNCHER_POLL_MS    2000  /* supervisor tick */
#define DIRECTGATE_WIN_LAUNCHER_RESPAWN_MS 2000  /* min gap between spawn attempts */

/*
    Windows Service Control Manager integration: the systemd/launchd
    counterpart on Windows. The SCM kills any service process that does
    not register a control handler, so the agent cannot simply run its
    console main under the SCM. Installed as:

      sc.exe create directgate-agent binPath= "C:\path\directgate.exe --win-service" \
             start= auto obj= ".\<user>" password= <password>

    A STOP/SHUTDOWN control sets the same g_bFinish flag as SIGTERM, so
    the shutdown path is byte-for-byte the console one.
*/
#define DIRECTGATE_WIN_SERVICE_NAME "directgate-agent"
#define DIRECTGATE_WIN_SERVICE_FLAG "--win-service"
#define DIRECTGATE_WIN_LAUNCHER_FLAG "--win-launcher"

static SERVICE_STATUS_HANDLE g_hSvcStatusHandle = NULL;
static char **g_pSvcArgv = NULL;
static int g_nSvcArgc = 0;

/* When the service runs the privilege-separation launcher instead of the agent
   directly: the launcher supervises an agent spawned as shell.user. */
static xbool_t g_bSvcLauncher = XFALSE;
static const char *g_pSvcCfgPath = NULL;
static volatile LONG g_nLauncherStop = 0;
extern xbool_t g_bFinish;

/* Real agent entrypoint from directgate.c */
int DirectGate_RunAgent(int argc, char* argv[]);

/* Resolve an account name (accepts "user", "DOMAIN\user" or ".\user") 
   to a SID copied into pSidBuf (SECURITY_MAX_SID_SIZE bytes). */
static XSTATUS DirectGate_WinLauncher_LookupSid(const char *pShellUser, PSID pSidBuf)
{
    const char *pName = pShellUser;
    if (pName[0] == '.' && pName[1] == '\\') pName += 2;

    char sDomain[XSTR_TINY];
    DWORD nDomLen = (DWORD)sizeof(sDomain);
    DWORD nSidLen = SECURITY_MAX_SID_SIZE;
    SID_NAME_USE eUse;

    if (!LookupAccountNameA(NULL, pName, pSidBuf, &nSidLen, sDomain, &nDomLen, &eUse))
    {
        xloge("token: failed to resolve shell.user account: user(%s), error(%lu)",
            pShellUser, GetLastError());
        return XSTDERR;
    }

    return XSTDOK;
}

/* True when the user SID of hToken equals pWantSid. */
static xbool_t DirectGate_WinLauncher_TokenMatchesUser(HANDLE hToken, PSID pWantSid)
{
    uint8_t sUserBuf[XSTR_TINY];
    DWORD nLen = 0;

    if (!GetTokenInformation(hToken, TokenUser, sUserBuf, (DWORD)sizeof(sUserBuf), &nLen))
        return XFALSE;

    return EqualSid(((TOKEN_USER*)sUserBuf)->User.Sid, pWantSid) ? XTRUE : XFALSE;
}

static XSTATUS DirectGate_WinLauncher_AcquireTokenForUser(const char *pShellUser, HANDLE *phToken)
{
    XCHECK((xstrused(pShellUser) && phToken != NULL), XSTDINV);
    *phToken = NULL;

    uint8_t sWantSid[SECURITY_MAX_SID_SIZE];
    if (DirectGate_WinLauncher_LookupSid(pShellUser, sWantSid) != XSTDOK) return XSTDERR;

    PWTS_SESSION_INFOA pSessions = NULL;
    XSTATUS nStatus = XSTDERR;
    DWORD nCount = 0;

    if (!WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessions, &nCount))
    {
        xloge("token: failed to enumerate logon sessions: error(%lu)", GetLastError());
        return XSTDERR;
    }

    for (DWORD i = 0; i < nCount; i++)
    {
        /* Active = at the console/RDP; Disconnected = still logged on (RDP
           detached). Both carry a usable user token; other states do not. */
        if (pSessions[i].State != WTSActive && pSessions[i].State != WTSDisconnected) continue;

        HANDLE hToken = NULL;
        if (!WTSQueryUserToken(pSessions[i].SessionId, &hToken)) continue;

        if (DirectGate_WinLauncher_TokenMatchesUser(hToken, sWantSid))
        {
            *phToken = hToken;
            nStatus = XSTDOK;
            break;
        }

        CloseHandle(hToken);
    }

    WTSFreeMemory(pSessions);

    if (nStatus != XSTDOK)
        xlogw("token: shell.user is not logged on, cannot start session: user(%s)", pShellUser);

    return nStatus;
}

static BOOL WINAPI DirectGate_WinLauncher_CtrlHandler(DWORD nType)
{
    switch (nType)
    {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            InterlockedExchange(&g_nLauncherStop, 1);
            return TRUE;
        default:
            return FALSE;
    }
}

static xbool_t DirectGate_WinLauncher_Stopping(void)
{
    return InterlockedCompareExchange(&g_nLauncherStop, 0, 0) ? XTRUE : XFALSE;
}

static void DirectGate_WinLauncher_Stop(void)
{
    InterlockedExchange(&g_nLauncherStop, 1);
}

/*
 * Spawn the agent itself (same executable, no launcher flag) inside shell.user's
 * session via their logon token, so the agent and everything it does runs AS
 * shell.user. The identity comes only from the token the launcher minted for the
 * configured shell.user.
 */
static XSTATUS DirectGate_WinLauncher_SpawnAgent(HANDLE hToken, const char *pCfgPath, HANDLE *phProcess)
{
    *phProcess = NULL;
    char sSelf[XPATH_MAX];

    DWORD nSelfLen = GetModuleFileNameA(NULL, sSelf, (DWORD)sizeof(sSelf));
    if (nSelfLen == 0 || nSelfLen >= sizeof(sSelf))
    {
        xloge("launcher: failed to resolve own executable path: error(%lu)", GetLastError());
        return XSTDERR;
    }

    char sCmd[XPATH_MAX + 256];
    xstrncpyf(sCmd, sizeof(sCmd), "\"%s\" -c \"%s\"", sSelf, pCfgPath);

    /* Run with the user's environment so HOME/USERPROFILE/APPDATA
       resolve to shell.user, not the launcher's SYSTEM profile. */
    LPVOID pEnv = NULL;
    CreateEnvironmentBlock(&pEnv, hToken, FALSE);

    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.lpDesktop = (LPSTR)"winsta0\\default";

    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));

    BOOL bOk = CreateProcessAsUserA(hToken, NULL, sCmd, NULL, NULL, FALSE,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, pEnv, NULL, &si, &pi);

    if (pEnv != NULL)
        DestroyEnvironmentBlock(pEnv);

    if (!bOk)
    {
        xloge("launcher: failed to spawn agent as shell.user: error(%lu)", GetLastError());
        return XSTDERR;
    }

    CloseHandle(pi.hThread);
    *phProcess = pi.hProcess;

    xlogn("launcher: started agent in shell.user session: pid(%lu)", pi.dwProcessId);
    return XSTDOK;
}

static XSTATUS DirectGate_WinLauncher_Run(const char *pCfgPath)
{
    xlog_defaults();
    xlog_coloring(XFALSE);
    xlog_timing(XLOG_DATE);
    xlog_indent(XTRUE);

    if (!xstrused(pCfgPath))
    {
        xloge("launcher: no config path provided; pass -c <agent.json>");
        return XSTDERR;
    }

    /* Read the trusted identity once. Every agent process is spawned as this
       account; it is never derived from anything but config. */
    directgate_cfg_t cfg;
    DirectGate_InitConfig(&cfg);

    if (!DirectGate_LoadConfig(&cfg, pCfgPath))
    {
        xloge("launcher: failed to load agent config: path(%s)", pCfgPath);
        return XSTDERR;
    }

    if (!xstrused(cfg.sShellUser))
    {
        xloge("launcher: shell.user is not configured, refusing to start: cfg(%s)", pCfgPath);
        return XSTDERR;
    }

    char sShellUser[XSTR_MID];
    xstrncpy(sShellUser, sizeof(sShellUser), cfg.sShellUser);

    SetConsoleCtrlHandler(DirectGate_WinLauncher_CtrlHandler, TRUE);
    xlogn("launcher: supervising agent for shell.user(%s)", sShellUser);

    HANDLE hAgent = NULL;
    uint64_t nLastSpawnMs = 0;
    xbool_t bWaitingForLogon = XFALSE;

    while (!DirectGate_WinLauncher_Stopping())
    {
        if (hAgent == NULL)
        {
            uint64_t nNow = XTime_GetMs();
            if (nNow - nLastSpawnMs < DIRECTGATE_WIN_LAUNCHER_RESPAWN_MS)
            {
                Sleep(DIRECTGATE_WIN_LAUNCHER_POLL_MS);
                continue;
            }

            HANDLE hToken = NULL;
            if (DirectGate_WinLauncher_AcquireTokenForUser(sShellUser, &hToken) != XSTDOK)
            {
                /* shell.user not logged on: passwordless model waits for a logon. */
                if (!bWaitingForLogon)
                {
                    xlogn("launcher: shell.user not logged on; waiting for logon: user(%s)", sShellUser);
                    bWaitingForLogon = XTRUE;
                }

                Sleep(DIRECTGATE_WIN_LAUNCHER_POLL_MS);
                continue;
            }

            bWaitingForLogon = XFALSE;
            nLastSpawnMs = nNow;

            if (DirectGate_WinLauncher_SpawnAgent(hToken, pCfgPath, &hAgent) != XSTDOK)
                hAgent = NULL;

            CloseHandle(hToken);
            if (hAgent == NULL)
            {
                Sleep(DIRECTGATE_WIN_LAUNCHER_POLL_MS);
                continue;
            }
        }

        /* Agent running: wake on its exit, on stop (POLL_MS cap), then respawn
           on the next shell.user logon. */
        DWORD nWait = WaitForSingleObject(hAgent, DIRECTGATE_WIN_LAUNCHER_POLL_MS);
        if (nWait == WAIT_OBJECT_0)
        {
            CloseHandle(hAgent);
            hAgent = NULL;
            xlogn("launcher: agent exited; will restart when shell.user is logged on");
        }
    }

    if (hAgent != NULL)
    {
        /* TODO: graceful stop (console ctrl / signal) instead of kill;
           sessions already tolerate an abrupt agent exit like a logoff. */
        TerminateProcess(hAgent, 0);
        WaitForSingleObject(hAgent, 5000);
        CloseHandle(hAgent);
    }

    xlogn("launcher: stopped");
    return XSTDOK;
}

static void DirectGate_WinLauncher_SvcReportState(DWORD nState, DWORD nExitCode)
{
    if (g_hSvcStatusHandle == NULL) return;

    SERVICE_STATUS status;
    memset(&status, 0, sizeof(status));

    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = nState;
    status.dwWin32ExitCode = nExitCode;
    status.dwControlsAccepted = (nState == SERVICE_RUNNING) ?
        (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;

    SetServiceStatus(g_hSvcStatusHandle, &status);
}

static void WINAPI DirectGate_WinLauncher_SvcCtrlHandler(DWORD nControl)
{
    switch (nControl)
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            DirectGate_WinLauncher_SvcReportState(SERVICE_STOP_PENDING, NO_ERROR);
            g_bFinish = XTRUE;
            /* Harmless when running the agent directly but breaks the
               launcher's supervise loop when running in launcher mode. */
            DirectGate_WinLauncher_Stop();
            break;
        default:
            break;
    }
}

static void WINAPI DirectGate_WinLauncher_SvcMain(DWORD nArgc, LPSTR *pArgv)
{
    /* SCM start parameters are ignored: the agent arguments come from
       the binPath command line captured before the dispatcher started */
    (void)nArgc;
    (void)pArgv;
    int nStatus;

    g_hSvcStatusHandle = RegisterServiceCtrlHandlerA(
        DIRECTGATE_WIN_SERVICE_NAME,
        DirectGate_WinLauncher_SvcCtrlHandler
    );

    if (g_hSvcStatusHandle == NULL) return;

    DirectGate_WinLauncher_SvcReportState(SERVICE_RUNNING, NO_ERROR);
    if (!g_bSvcLauncher) nStatus = DirectGate_RunAgent(g_nSvcArgc, g_pSvcArgv);
    else nStatus = (DirectGate_WinLauncher_Run(g_pSvcCfgPath) == XSTDOK) ? XSTDNON : XSTDERR;
    DirectGate_WinLauncher_SvcReportState(SERVICE_STOPPED, nStatus < 0 ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR);
}

XSTATUS DirectGate_WinLauncher_Main(int argc, char* argv[])
{
    static char *pFilteredArgv[64];
    xbool_t bWinLauncher = XFALSE;
    xbool_t bWinService = XFALSE;
    const char *pWinCfg = NULL;
    int i, nFiltered = XSTDNON;

    for (i = 0; i < argc && nFiltered < (int)XARR_SIZE(pFilteredArgv) - 1; i++)
    {
        if (strcmp(argv[i], DIRECTGATE_WIN_LAUNCHER_FLAG) == 0) { bWinLauncher = XTRUE; continue; }
        if (strcmp(argv[i], DIRECTGATE_WIN_SERVICE_FLAG) == 0) { bWinService = XTRUE; continue; }
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) pWinCfg = argv[i + 1];
        pFilteredArgv[nFiltered++] = argv[i];
    }

    pFilteredArgv[nFiltered] = NULL;

    if (bWinService)
    {
        g_pSvcCfgPath = pWinCfg;
        g_bSvcLauncher = bWinLauncher;
        g_pSvcArgv = pFilteredArgv;
        g_nSvcArgc = nFiltered;

        SERVICE_TABLE_ENTRYA svcTable[] = {
            { (LPSTR)DIRECTGATE_WIN_SERVICE_NAME, DirectGate_WinLauncher_SvcMain },
            { NULL, NULL }
        };

        /* Blocks until the service is stopped */
        if (!StartServiceCtrlDispatcherA(svcTable))
        {
            fprintf(stderr, "Failed to connect to the service control manager (error %lu): %s "
                "is only valid when started as a Windows service\n",
                GetLastError(), DIRECTGATE_WIN_SERVICE_FLAG);

            return XSTDERR;
        }

        return XSTDNON;
    }

    /* Console launcher (no service): useful for manual testing under an account holding SeTcbPrivilege */
    if (bWinLauncher) return (DirectGate_WinLauncher_Run(pWinCfg) == XSTDOK) ? XSTDNON : XSTDOK;

    return DirectGate_RunAgent(nFiltered, pFilteredArgv);
}
#endif /* _WIN32 */
