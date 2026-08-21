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
#include "session.h"
#include "elevated.h"

#include <windows.h>   /* HANDLE, DWORD, etc. */
#include <wtsapi32.h>  /* WTSEnumerateSessionsA / WTSQueryUserToken */
#include <userenv.h>   /* CreateEnvironmentBlock / DestroyEnvironmentBlock */

#define DIRECTGATE_WIN_LAUNCHER_POLL_MS    2000  /* supervisor tick */
#define DIRECTGATE_WIN_LAUNCHER_RESPAWN_MS 2000  /* min gap between spawn attempts */

/* How long shell.user must stay absent before a running agent started for them
   is torn down. Long enough that one failed session enumeration cannot cost a
   healthy agent the session it is serving, short enough that signing out gets
   the logon screen back on the air while the operator is still watching. */
#define DIRECTGATE_WIN_LAUNCHER_LOGOFF_MS  6000

/* Page-aligned so the pixel slot that follows starts on a page boundary. */
#define DIRECTGATE_WIN_ELEV_HEADER_BYTES   4096U

/* Sanity bound on the capture rectangle an agent may ask a section for; the
   per-axis caps in elevated.h already keep the slot itself in check. */
#define DIRECTGATE_WIN_ELEV_MAX_EDGE       16384U

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

/* Launcher -> agent: "you are the pre-logon stand-in". Never passed by hand;
   the agent additionally refuses it unless it really is running as SYSTEM. */
#define DIRECTGATE_WIN_PRELOGON_FLAG "--win-prelogon"

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

/* Windows Game Mode and the modern power manager favour the foreground game.
 * The desktop capture -> encode -> send pipeline is exactly the kind of
 * background work that otherwise loses scheduling time, so raise the process
 * base priority and explicitly opt out of execution-speed power throttling.
 *
 * HIGH_PRIORITY_CLASS (not REALTIME) is deliberate: realtime outranks kernel
 * input, paging and disk threads and can freeze the machine. High is the
 * strongest non-realtime class. Worker threads use ABOVE_NORMAL within this
 * class instead of MMCSS, whose CPU quota can demote sustained encode work. */
void DirectGate_WinLauncher_BoostPriority(void)
{
    HANDLE hProcess = GetCurrentProcess();

    if (SetPriorityClass(hProcess, HIGH_PRIORITY_CLASS))
        xlogi("Agent process priority raised to HIGH_PRIORITY_CLASS");
    else
    {
        DWORD nHighError = GetLastError();
        if (SetPriorityClass(hProcess, ABOVE_NORMAL_PRIORITY_CLASS))
            xlogw("HIGH_PRIORITY_CLASS unavailable; using ABOVE_NORMAL_PRIORITY_CLASS: err(%lu)",
                (unsigned long)nHighError);
        else
            xlogw("Failed to raise agent process priority class: high_err(%lu), fallback_err(%lu)",
                (unsigned long)nHighError, (unsigned long)GetLastError());
    }

    /* SetProcessInformation(ProcessPowerThrottling, ...) is Windows 10 1709+.
     * Resolve it at runtime and describe the state struct locally so the build
     * stays independent of the SDK version and still loads on older Windows
     * (where Game Mode background throttling does not exist). ControlMask =
     * EXECUTION_SPEED with StateMask = 0 means "I manage throttling and I want
     * it off": the process runs at full speed / HighQoS. */
    typedef struct {
        ULONG Version;
        ULONG ControlMask;
        ULONG StateMask;
    } directgate_power_throttling_t;

    enum {
        DIRECTGATE_POWER_THROTTLING_VERSION_1       = 1,
        DIRECTGATE_POWER_THROTTLING_EXECUTION_SPEED = 0x1,
        DIRECTGATE_PROCESS_POWER_THROTTLING         = 4 /* ProcessPowerThrottling */
    };

    typedef BOOL (WINAPI *directgate_set_process_info_fn)(HANDLE, int, LPVOID, DWORD);
    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    directgate_set_process_info_fn pSetProcessInformation = (hKernel != NULL)
        ? (directgate_set_process_info_fn)(void*)GetProcAddress(hKernel, "SetProcessInformation")
        : NULL;

    if (pSetProcessInformation == NULL) return;

    directgate_power_throttling_t state;
    memset(&state, 0, sizeof(state));
    state.Version = DIRECTGATE_POWER_THROTTLING_VERSION_1;
    state.ControlMask = DIRECTGATE_POWER_THROTTLING_EXECUTION_SPEED;
    state.StateMask = 0;

    if (pSetProcessInformation(hProcess, DIRECTGATE_PROCESS_POWER_THROTTLING, &state, (DWORD)sizeof(state)))
        xlogi("Agent execution-speed power throttling disabled");
    else
        xlogw("Failed to disable agent power throttling: err(%lu)", (unsigned long)GetLastError());
}

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

/* bQuiet suppresses the "not logged on" warning: the supervisor also uses this
   as a plain predicate while a pre-logon agent is running, and that must not
   turn a normal state of affairs into a log line every couple of seconds. */
static XSTATUS DirectGate_WinLauncher_AcquireTokenForUser(const char *pShellUser, HANDLE *phToken, xbool_t bQuiet)
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

    if (nStatus != XSTDOK && !bQuiet)
        xlogw("token: shell.user is not logged on, cannot start session: user(%s)", pShellUser);

    return nStatus;
}

/* Whether shell.user has a logon session anywhere - console or RDP. */
static xbool_t DirectGate_WinLauncher_UserIsLoggedOn(const char *pShellUser)
{
    HANDLE hToken = NULL;
    if (DirectGate_WinLauncher_AcquireTokenForUser(pShellUser, &hToken, XTRUE) != XSTDOK)
        return XFALSE;

    CloseHandle(hToken);
    return XTRUE;
}

/*
    Pre-logon reachability (see desktop.preLogon in config.h).

    A machine that reboots unattended has nobody logged on, so there is no
    shell.user token to be had and the model above simply waits - which is
    exactly the state an operator cannot recover from remotely, because
    recovering means logging on and logging on means being at the keyboard.

    The way out is the one identity that exists before any user does: the
    launcher's own. A copy of its LocalSystem token retargeted at the console
    session runs an agent that can see and drive the logon screen, and nothing
    else - DirectGate_Session_SetPreLogon refuses every session mode but
    "desktop", so the pre-logon window never yields a SYSTEM shell.

    It is strictly a stand-in. The supervisor retires it the instant anyone
    logs on: shell.user gets the normal unprivileged agent, and any other
    account gets none, because a SYSTEM agent left running in a session that
    now belongs to someone else would be streaming their desktop.
*/

static xbool_t g_bPreLogon = XTRUE;

/* Whether the agent currently supervised is the pre-logon stand-in. Read by
   SpawnHelper, which has to answer the lock-screen question differently for
   it, so it cannot live as a local in the supervision loop. */
static xbool_t g_bAgentPreLogon = XFALSE;

/* True when nSessionId has an interactive user. Anything other than a clean
   "no token" answer counts as occupied: guessing wrong in that direction only
   withholds a pre-logon agent, while guessing wrong the other way would put a
   SYSTEM capture into a session we could not account for. */
static xbool_t DirectGate_WinLauncher_SessionHasUser(DWORD nSessionId)
{
    HANDLE hToken = NULL;

    if (WTSQueryUserToken(nSessionId, &hToken))
    {
        CloseHandle(hToken);
        return XTRUE;
    }

    DWORD nError = GetLastError();
    if (nError == ERROR_NO_TOKEN) return XFALSE;

    xlogw("token: could not tell whether session %lu is occupied, assuming it is: error(%lu)",
        (unsigned long)nSessionId, nError);

    return XTRUE;
}

/* A primary LocalSystem token aimed at nSessionId. Setting TokenSessionId
   needs SeTcbPrivilege, which is why only the launcher can do this. */
static HANDLE DirectGate_WinLauncher_SystemTokenForSession(DWORD nSessionId, const char *pWhat)
{
    HANDLE hSelfToken = NULL, hToken = NULL;

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hSelfToken) ||
        !DuplicateTokenEx(hSelfToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hToken))
    {
        xloge("launcher: failed to duplicate the system token for the %s: error(%lu)",
            pWhat, GetLastError());

        if (hSelfToken != NULL) CloseHandle(hSelfToken);
        return NULL;
    }

    CloseHandle(hSelfToken);

    if (!SetTokenInformation(hToken, TokenSessionId, &nSessionId, (DWORD)sizeof(nSessionId)))
    {
        xloge("launcher: failed to move the %s token into session %lu: error(%lu)",
            pWhat, (unsigned long)nSessionId, GetLastError());

        CloseHandle(hToken);
        return NULL;
    }

    return hToken;
}

/* The token a pre-logon agent should run under, or NULL when this is not a
   moment for one. On success *pnSessionId is the console session it belongs
   to, which the supervisor watches for the logon that ends its life. */
static HANDLE DirectGate_WinLauncher_AcquirePreLogonToken(DWORD *pnSessionId)
{
    *pnSessionId = 0;
    if (!g_bPreLogon) return NULL;

    /* 0 is the services session (no desktop of its own) and 0xFFFFFFFF means
       there is no console session at all; both also show up transiently while
       one session is handing the console to another. */
    DWORD nSession = WTSGetActiveConsoleSessionId();
    if (nSession == 0 || nSession == 0xFFFFFFFF) return NULL;

    if (DirectGate_WinLauncher_SessionHasUser(nSession)) return NULL;

    HANDLE hToken = DirectGate_WinLauncher_SystemTokenForSession(nSession, "pre-logon agent");
    if (hToken == NULL) return NULL;

    *pnSessionId = nSession;
    return hToken;
}

/*
    Elevated-UI bridge, launcher half (see desktop/elevated.h for the model).

    The launcher is the only process here that can do three things: mint kernel
    objects nobody else can name, put a SYSTEM process into the interactive
    session, and generate the secure attention sequence. It does all three on
    request from the one agent it supervises, and nothing else - the request
    channel is an anonymous pipe inherited by that agent at spawn, so there is
    no endpoint another process could ever reach.
*/

typedef struct directgate_win_elev_ctx_ {
    HANDLE hAgent;
    DWORD nAgentPid;
} directgate_win_elev_ctx_t;

static HANDLE g_hElevRequest = NULL;   /* read end:  agent -> launcher */
static HANDLE g_hElevReply = NULL;     /* write end: launcher -> agent */
static HANDLE g_hElevThread = NULL;
static HANDLE g_hElevHelper = NULL;
static xbool_t g_bElevEnabled = XTRUE;
static xbool_t g_bElevLockScreen = XTRUE;
static char g_sElevCfgPath[XPATH_MAX] = { 0 };

/* Builds a single-entry PROC_THREAD_ATTRIBUTE_HANDLE_LIST so a child inherits exactly the
   handles named here and nothing else that happens to be inheritable in this process. */
static LPPROC_THREAD_ATTRIBUTE_LIST DirectGate_WinLauncher_HandleList(HANDLE *pHandles, DWORD nCount)
{
    SIZE_T nSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &nSize);
    if (nSize == 0) return NULL;

    LPPROC_THREAD_ATTRIBUTE_LIST pList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(nSize);
    if (pList == NULL) return NULL;

    if (!InitializeProcThreadAttributeList(pList, 1, 0, &nSize))
    {
        free(pList);
        return NULL;
    }

    if (!UpdateProcThreadAttribute(pList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        pHandles, (SIZE_T)nCount * sizeof(HANDLE), NULL, NULL))
    {
        DeleteProcThreadAttributeList(pList);
        free(pList);
        return NULL;
    }

    return pList;
}

static void DirectGate_WinLauncher_FreeHandleList(LPPROC_THREAD_ATTRIBUTE_LIST pList)
{
    if (pList == NULL) return;
    DeleteProcThreadAttributeList(pList);
    free(pList);
}

static void DirectGate_WinLauncher_CloseHandle(HANDLE *phHandle)
{
    if (phHandle == NULL || *phHandle == NULL) return;
    CloseHandle(*phHandle);
    *phHandle = NULL;
}

static void DirectGate_WinLauncher_StopHelper(void)
{
    if (g_hElevHelper == NULL) return;

    /* The agent closes its write end of the command pipe before releasing, so
       by the time this runs the helper is normally already on its way out.
       The short wait is only there to reap it cleanly; anything longer would
       just stall the control thread on a helper that is being replaced. */
    if (WaitForSingleObject(g_hElevHelper, 1500) != WAIT_OBJECT_0)
    {
        xlogw("launcher: elevated helper did not exit, terminating it");
        TerminateProcess(g_hElevHelper, 0);
        WaitForSingleObject(g_hElevHelper, 2000);
    }

    CloseHandle(g_hElevHelper);
    g_hElevHelper = NULL;
}

/* Spawns the in-session SYSTEM helper and hands the agent its end of every
   channel. On success pReady carries handle values already valid inside the
   agent's own handle table. */
static XSTATUS DirectGate_WinLauncher_SpawnHelper(HANDLE hAgent, DWORD nAgentPid,
                                                  uint32_t nCaptureWidth, uint32_t nCaptureHeight,
                                                  directgate_elev_helper_ready_t *pReady)
{
    memset(pReady, 0, sizeof(*pReady));
    pReady->nStatus = XSTDERR;

    if (nCaptureWidth == 0 || nCaptureHeight == 0 ||
        nCaptureWidth > DIRECTGATE_WIN_ELEV_MAX_EDGE ||
        nCaptureHeight > DIRECTGATE_WIN_ELEV_MAX_EDGE)
    {
        xloge("launcher: refusing an implausible helper capture rectangle: %ux%u",
            nCaptureWidth, nCaptureHeight);
        return XSTDERR;
    }

    DWORD nSessionId = 0;
    if (!ProcessIdToSessionId(nAgentPid, &nSessionId))
    {
        xloge("launcher: failed to resolve the agent session: pid(%lu), error(%lu)",
            (unsigned long)nAgentPid, GetLastError());
        return XSTDERR;
    }

    uint32_t nSlotWidth = (nCaptureWidth < DIRECTGATE_ELEV_MAX_WIDTH) ? nCaptureWidth : DIRECTGATE_ELEV_MAX_WIDTH;
    uint32_t nSlotHeight = (nCaptureHeight < DIRECTGATE_ELEV_MAX_HEIGHT) ? nCaptureHeight : DIRECTGATE_ELEV_MAX_HEIGHT;
    uint64_t nSlotBytes = (uint64_t)nSlotWidth * nSlotHeight * 4ULL;
    uint64_t nTotalBytes = DIRECTGATE_WIN_ELEV_HEADER_BYTES + nSlotBytes;

    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;   /* default DACL: SYSTEM + Administrators only */

    HANDLE hCmdRead = NULL, hCmdWrite = NULL, hSection = NULL;
    HANDLE hReady = NULL, hTaken = NULL, hAgentInherit = NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST pAttrs = NULL;
    HANDLE hToken = NULL;
    XSTATUS nStatus = XSTDERR;

    /* Single-pass block: every failure below breaks out to the one teardown
       after it, so no step has to know what the previous ones allocated. */
    do
    {
        if (!CreatePipe(&hCmdRead, &hCmdWrite, &sa, 64U * 1024U))
        {
            xloge("launcher: failed to create the helper command pipe: error(%lu)", GetLastError());
            break;
        }

        hSection = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE,
            (DWORD)(nTotalBytes >> 32), (DWORD)(nTotalBytes & 0xFFFFFFFFULL), NULL);

        if (hSection == NULL)
        {
            xloge("launcher: failed to create the %llu byte frame section: error(%lu)",
                (unsigned long long)nTotalBytes, GetLastError());
            break;
        }

        directgate_elev_shm_t *pShm = (directgate_elev_shm_t*)MapViewOfFile(hSection,
            FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, (SIZE_T)nTotalBytes);

        if (pShm == NULL)
        {
            xloge("launcher: failed to map the frame section: error(%lu)", GetLastError());
            break;
        }

        memset(pShm, 0, sizeof(*pShm));
        pShm->nMagic = DIRECTGATE_ELEV_SHM_MAGIC;
        pShm->nHeaderBytes = DIRECTGATE_WIN_ELEV_HEADER_BYTES;
        pShm->nSlotBytes = (uint32_t)nSlotBytes;
        pShm->nMaxWidth = nSlotWidth;
        pShm->nMaxHeight = nSlotHeight;
        UnmapViewOfFile(pShm);

        hReady = CreateEventW(&sa, FALSE, FALSE, NULL);
        hTaken = CreateEventW(&sa, FALSE, FALSE, NULL);

        if (hReady == NULL || hTaken == NULL)
        {
            xloge("launcher: failed to create the frame hand-off events: error(%lu)", GetLastError());
            break;
        }

        /* SYNCHRONIZE only: the helper waits on the agent to know when to exit
           and must not be able to do anything else to it. */
        if (!DuplicateHandle(GetCurrentProcess(), hAgent, GetCurrentProcess(),
            &hAgentInherit, SYNCHRONIZE, TRUE, 0))
        {
            xloge("launcher: failed to duplicate the agent handle for the helper: error(%lu)", GetLastError());
            break;
        }

        char sSelf[XPATH_MAX];
        DWORD nSelfLen = GetModuleFileNameA(NULL, sSelf, (DWORD)sizeof(sSelf));
        if (nSelfLen == 0 || nSelfLen >= sizeof(sSelf))
        {
            xloge("launcher: failed to resolve own executable path: error(%lu)", GetLastError());
            break;
        }

        /* Inherited handles keep their numeric value in the child, so passing them
           on the command line is enough; the values mean nothing anywhere else. */
        char sCmd[XPATH_MAX * 2 + 512];
        xstrncpyf(sCmd, sizeof(sCmd),
            "\"%s\" %s --cmd %llu --shm %llu --shm-bytes %llu --ready %llu --taken %llu "
            "--agent %llu --agent-pid %lu --allow-lock %d -c \"%s\"",
            sSelf, DIRECTGATE_ELEV_HELPER_FLAG,
            (unsigned long long)(uintptr_t)hCmdRead,
            (unsigned long long)(uintptr_t)hSection,
            (unsigned long long)nTotalBytes,
            (unsigned long long)(uintptr_t)hReady,
            (unsigned long long)(uintptr_t)hTaken,
            (unsigned long long)(uintptr_t)hAgentInherit,
            (unsigned long)nAgentPid,
            (g_bAgentPreLogon || g_bElevLockScreen) ? 1 : 0,
            g_sElevCfgPath);

        HANDLE sHandles[5] = { hCmdRead, hSection, hReady, hTaken, hAgentInherit };
        pAttrs = DirectGate_WinLauncher_HandleList(sHandles, 5);
        if (pAttrs == NULL)
        {
            xloge("launcher: failed to build the helper handle list: error(%lu)", GetLastError());
            break;
        }

        /* A copy of this process's own LocalSystem token, retargeted at the
           interactive session - the same mint the pre-logon agent uses. */
        hToken = DirectGate_WinLauncher_SystemTokenForSession(nSessionId, "helper");
        if (hToken == NULL) break;

        STARTUPINFOEXA si;
        memset(&si, 0, sizeof(si));
        si.StartupInfo.cb = sizeof(si);
        si.StartupInfo.lpDesktop = (LPSTR)"winsta0\\default";
        si.lpAttributeList = pAttrs;

        PROCESS_INFORMATION pi;
        memset(&pi, 0, sizeof(pi));

        if (!CreateProcessAsUserA(hToken, NULL, sCmd, NULL, NULL, TRUE,
            CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi))
        {
            xloge("launcher: failed to start the elevated desktop helper: error(%lu)", GetLastError());
            break;
        }

        CloseHandle(pi.hThread);
        g_hElevHelper = pi.hProcess;

        /* Hand the agent its ends. DUPLICATE_SAME_ACCESS from these full-access
           handles is what grants the agent use of objects whose DACL would
           otherwise keep it out - the handle, not the DACL, is the grant. */
        HANDLE hAgentCmd = NULL, hAgentSection = NULL, hAgentReady = NULL, hAgentTaken = NULL;

        if (!DuplicateHandle(GetCurrentProcess(), hCmdWrite, hAgent, &hAgentCmd, 0, FALSE, DUPLICATE_SAME_ACCESS) ||
            !DuplicateHandle(GetCurrentProcess(), hSection, hAgent, &hAgentSection, 0, FALSE, DUPLICATE_SAME_ACCESS) ||
            !DuplicateHandle(GetCurrentProcess(), hReady, hAgent, &hAgentReady, 0, FALSE, DUPLICATE_SAME_ACCESS) ||
            !DuplicateHandle(GetCurrentProcess(), hTaken, hAgent, &hAgentTaken, 0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            xloge("launcher: failed to hand the helper channels to the agent: error(%lu)", GetLastError());

            /* Nothing else holds a write end, so dropping ours is what tells
               the helper to leave; without it StopHelper would sit out its wait. */
            DirectGate_WinLauncher_CloseHandle(&hCmdWrite);
            DirectGate_WinLauncher_StopHelper();
            break;
        }

        pReady->nStatus = XSTDOK;
        pReady->nSectionBytes = (uint32_t)nTotalBytes;
        pReady->hCommand = (uint64_t)(uintptr_t)hAgentCmd;
        pReady->hSection = (uint64_t)(uintptr_t)hAgentSection;
        pReady->hFrameReady = (uint64_t)(uintptr_t)hAgentReady;
        pReady->hFrameTaken = (uint64_t)(uintptr_t)hAgentTaken;
        nStatus = XSTDOK;

        xlogn("launcher: elevated desktop helper started: pid(%lu), session(%lu), slot(%ux%u)",
            (unsigned long)pi.dwProcessId, (unsigned long)nSessionId, nSlotWidth, nSlotHeight);
    } while (0);

    DirectGate_WinLauncher_FreeHandleList(pAttrs);
    DirectGate_WinLauncher_CloseHandle(&hToken);
    DirectGate_WinLauncher_CloseHandle(&hAgentInherit);
    DirectGate_WinLauncher_CloseHandle(&hCmdRead);
    DirectGate_WinLauncher_CloseHandle(&hCmdWrite);
    DirectGate_WinLauncher_CloseHandle(&hSection);
    DirectGate_WinLauncher_CloseHandle(&hReady);
    DirectGate_WinLauncher_CloseHandle(&hTaken);

    return nStatus;
}

/* Ctrl+Alt+Del. SendSAS only obeys a process running as LocalSystem under the
   SCM, so the in-session helper cannot do this and the launcher must. */
static void DirectGate_WinLauncher_SendSAS(void)
{
    typedef VOID (WINAPI *directgate_send_sas_fn)(BOOL);
    static directgate_send_sas_fn pSendSAS = NULL;
    static xbool_t bResolved = XFALSE;

    if (!bResolved)
    {
        HMODULE hSas = LoadLibraryW(L"sas.dll");
        if (hSas != NULL) pSendSAS = (directgate_send_sas_fn)(void*)GetProcAddress(hSas, "SendSAS");
        bResolved = XTRUE;
    }

    if (pSendSAS == NULL)
    {
        xlogw("launcher: SendSAS is unavailable; Ctrl+Alt+Del cannot be injected");
        return;
    }

    pSendSAS(FALSE);
    xlogn("launcher: injected the secure attention sequence");
}

/* Serves one agent for as long as it lives. Ends when the agent closes its
   write end (exit or shutdown), which is also the only way the loop stops. */
static DWORD WINAPI DirectGate_WinLauncher_ElevThread(LPVOID pArg)
{
    directgate_win_elev_ctx_t ctx = *(directgate_win_elev_ctx_t*)pArg;
    free(pArg);

    uint8_t sPayload[DIRECTGATE_ELEV_MAX_PAYLOAD];
    uint16_t nType = 0, nLength = 0;

    while (DirectGate_Elevated_RecvRecord(g_hElevRequest, &nType, sPayload, &nLength))
    {
        if (!g_bElevEnabled)
        {
            xlogw("launcher: ignoring an elevated-UI request while the feature is disabled");
            if (nType == DIRECTGATE_ELEV_MSG_HELPER_REQUEST)
            {
                directgate_elev_helper_ready_t ready;
                memset(&ready, 0, sizeof(ready));
                ready.nStatus = XSTDERR;

                (void)DirectGate_Elevated_SendRecord(g_hElevReply, DIRECTGATE_ELEV_MSG_HELPER_READY,
                    &ready, (uint16_t)sizeof(ready));
            }

            continue;
        }

        switch (nType)
        {
            case DIRECTGATE_ELEV_MSG_HELPER_REQUEST:
            {
                directgate_elev_helper_ready_t ready;
                memset(&ready, 0, sizeof(ready));
                ready.nStatus = XSTDERR;

                if (nLength == (uint16_t)sizeof(directgate_elev_helper_req_t))
                {
                    directgate_elev_helper_req_t request;
                    memcpy(&request, sPayload, sizeof(request));

                    DirectGate_WinLauncher_StopHelper();
                    (void)DirectGate_WinLauncher_SpawnHelper(ctx.hAgent, ctx.nAgentPid, request.nCaptureWidth, request.nCaptureHeight, &ready);
                }

                if (!DirectGate_Elevated_SendRecord(g_hElevReply, DIRECTGATE_ELEV_MSG_HELPER_READY, &ready, (uint16_t)sizeof(ready)))
                {
                    xlogw("launcher: failed to answer a helper request; agent channel is gone");
                    DirectGate_WinLauncher_StopHelper();
                    return 0;
                }

                break;
            }

            case DIRECTGATE_ELEV_MSG_HELPER_RELEASE:
                DirectGate_WinLauncher_StopHelper();
                break;

            case DIRECTGATE_ELEV_MSG_SAS_REQUEST:
                DirectGate_WinLauncher_SendSAS();
                break;

            default:
                xlogd("launcher: ignoring unknown control record: type(%u), length(%u)", nType, nLength);
                break;
        }
    }

    DirectGate_WinLauncher_StopHelper();
    return 0;
}

/* Called only once the agent process is gone. That is what unblocks the
   servicing thread: the agent held the sole write end of the request pipe, so
   its exit turns the thread's blocking read into a clean end-of-file. Joining
   before closing matters - closing a handle a thread is parked in ReadFile on
   is not something Windows defines. */
static void DirectGate_WinLauncher_StopElevChannel(void)
{
    if (g_hElevThread != NULL)
    {
        if (WaitForSingleObject(g_hElevThread, 5000) != WAIT_OBJECT_0)
        {
            xlogw("launcher: control channel thread did not stop; leaking its handles");
        }
        else
        {
            DirectGate_WinLauncher_CloseHandle(&g_hElevRequest);
            DirectGate_WinLauncher_CloseHandle(&g_hElevReply);
        }

        CloseHandle(g_hElevThread);
        g_hElevThread = NULL;
    }
    else
    {
        DirectGate_WinLauncher_CloseHandle(&g_hElevRequest);
        DirectGate_WinLauncher_CloseHandle(&g_hElevReply);
    }

    DirectGate_WinLauncher_StopHelper();
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
static XSTATUS DirectGate_WinLauncher_SpawnAgent(HANDLE hToken, const char *pCfgPath, xbool_t bPreLogon, HANDLE *phProcess)
{
    *phProcess = NULL;
    char sSelf[XPATH_MAX];

    DWORD nSelfLen = GetModuleFileNameA(NULL, sSelf, (DWORD)sizeof(sSelf));
    if (nSelfLen == 0 || nSelfLen >= sizeof(sSelf))
    {
        xloge("launcher: failed to resolve own executable path: error(%lu)", GetLastError());
        return XSTDERR;
    }

    /* Control channel for the elevated-UI bridge: two anonymous pipes the
       agent inherits at spawn. Nothing about them is named, so the only
       process that can ever reach the launcher through them is this child. */
    HANDLE hReqRead = NULL, hReqWrite = NULL, hRspRead = NULL, hRspWrite = NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST pAttrs = NULL;

    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    if (g_bElevEnabled)
    {
        if (!CreatePipe(&hReqRead, &hReqWrite, &sa, 0) ||
            !CreatePipe(&hRspRead, &hRspWrite, &sa, 0))
        {
            xlogw("launcher: failed to create the agent control channel, elevated UI "
                  "will be unavailable: error(%lu)", GetLastError());

            DirectGate_WinLauncher_CloseHandle(&hReqRead);
            DirectGate_WinLauncher_CloseHandle(&hReqWrite);
            DirectGate_WinLauncher_CloseHandle(&hRspRead);
            DirectGate_WinLauncher_CloseHandle(&hRspWrite);
        }
        else
        {
            HANDLE sHandles[2] = { hReqWrite, hRspRead };
            pAttrs = DirectGate_WinLauncher_HandleList(sHandles, 2);
        }
    }

    char sCmd[XPATH_MAX * 2 + 256];

    /* The child cannot work out for itself that it is the pre-logon stand-in:
       being SYSTEM is a symptom of it, not proof of it. The launcher decided,
       so the launcher says so. */
    const char *pPreLogonArg = bPreLogon ? " " DIRECTGATE_WIN_PRELOGON_FLAG : "";

    if (pAttrs != NULL)
    {
        xstrncpyf(sCmd, sizeof(sCmd), "\"%s\" -c \"%s\" --win-ctl-write %llu --win-ctl-read %llu%s",
            sSelf, pCfgPath, (unsigned long long)(uintptr_t)hReqWrite,
            (unsigned long long)(uintptr_t)hRspRead, pPreLogonArg);
    }
    else xstrncpyf(sCmd, sizeof(sCmd), "\"%s\" -c \"%s\"%s", sSelf, pCfgPath, pPreLogonArg);

    /* Run with the user's environment so HOME/USERPROFILE/APPDATA
       resolve to shell.user, not the launcher's SYSTEM profile. In pre-logon
       mode there is no user, and this resolves to the SYSTEM profile - which
       is correct, because that is whose process it is. */
    LPVOID pEnv = NULL;
    CreateEnvironmentBlock(&pEnv, hToken, FALSE);

    STARTUPINFOEXA si;
    memset(&si, 0, sizeof(si));
    si.StartupInfo.cb = (pAttrs != NULL) ? (DWORD)sizeof(si) : (DWORD)sizeof(si.StartupInfo);
    si.StartupInfo.lpDesktop = (LPSTR)"winsta0\\default";
    si.lpAttributeList = pAttrs;

    DWORD nFlags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
    if (pAttrs != NULL) nFlags |= EXTENDED_STARTUPINFO_PRESENT;

    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));

    BOOL bOk = CreateProcessAsUserA(hToken, NULL, sCmd, NULL, NULL,
        (pAttrs != NULL) ? TRUE : FALSE, nFlags, pEnv, NULL, &si.StartupInfo, &pi);

    if (pEnv != NULL) DestroyEnvironmentBlock(pEnv);
    DirectGate_WinLauncher_FreeHandleList(pAttrs);

    /* The child owns its ends now; keeping copies here would hide its exit
       from the servicing thread's blocking read. */
    DirectGate_WinLauncher_CloseHandle(&hReqWrite);
    DirectGate_WinLauncher_CloseHandle(&hRspRead);

    if (!bOk)
    {
        xloge("launcher: failed to spawn agent as shell.user: error(%lu)", GetLastError());
        DirectGate_WinLauncher_CloseHandle(&hReqRead);
        DirectGate_WinLauncher_CloseHandle(&hRspWrite);
        return XSTDERR;
    }

    CloseHandle(pi.hThread);
    *phProcess = pi.hProcess;

    if (hReqRead != NULL && hRspWrite != NULL)
    {
        directgate_win_elev_ctx_t *pCtx = (directgate_win_elev_ctx_t*)calloc(1, sizeof(*pCtx));
        g_hElevRequest = hReqRead;
        g_hElevReply = hRspWrite;

        if (pCtx != NULL)
        {
            pCtx->hAgent = pi.hProcess;
            pCtx->nAgentPid = pi.dwProcessId;
            g_hElevThread = CreateThread(NULL, 0, DirectGate_WinLauncher_ElevThread, pCtx, 0, NULL);
        }

        if (g_hElevThread == NULL)
        {
            xlogw("launcher: failed to start the control channel thread: error(%lu)", GetLastError());
            free(pCtx);
            DirectGate_WinLauncher_CloseHandle(&g_hElevRequest);
            DirectGate_WinLauncher_CloseHandle(&g_hElevReply);
        }
    }

    if (bPreLogon) xlogn("launcher: started pre-logon agent as SYSTEM, desktop sessions only: pid(%lu)", pi.dwProcessId);
    else xlogn("launcher: started agent in shell.user session: pid(%lu)", pi.dwProcessId);

    return XSTDOK;
}

/* Kill the supervised agent and tear the elevated-UI bridge down with it: no
   agent means no reason for a SYSTEM process to still be injecting input. */
static void DirectGate_WinLauncher_StopAgent(HANDLE *phAgent)
{
    if (phAgent == NULL || *phAgent == NULL) return;

    /* TODO: graceful stop (console ctrl / signal) instead of kill;
       sessions already tolerate an abrupt agent exit like a logoff. */
    TerminateProcess(*phAgent, 0);
    WaitForSingleObject(*phAgent, 5000);

    /* After the agent is gone, so the servicing thread's read has ended. */
    DirectGate_WinLauncher_StopElevChannel();
    CloseHandle(*phAgent);
    *phAgent = NULL;
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

    SetConsoleCtrlHandler(DirectGate_WinLauncher_CtrlHandler, TRUE);
    xstrncpy(g_sElevCfgPath, sizeof(g_sElevCfgPath), pCfgPath);

    /*
       Wait for a usable configuration rather than exiting without one.

       The installer starts this service, and on a fresh machine that happens
       before anything has been paired - there is no agent.json yet, and no
       shell.user in it when there is. Exiting there would make the MSI's
       StartServices look like a failed start, and would mean pairing had to be
       followed by a manual service start or a reboot. Waiting costs a 2 s poll
       loop and makes pairing alone enough to bring the agent up.

       The identity is still read once and pinned: the loop ends the moment a
       valid shell.user appears and nothing re-reads it afterwards, so an agent
       can never be spawned under an account the launcher did not commit to at
       start-up.
    */
    directgate_cfg_t cfg;
    char sShellUser[XSTR_MID] = { 0 };
    xbool_t bWaitingForConfig = XFALSE;

    /* Logging before anything else, from whatever can be read right now - on an
       unpaired machine that is the built-in default. Without it every launcher
       and helper diagnostic is lost, because the SCM gives a service no
       console. A separate ident keeps the file apart from the agent's own. */
    DirectGate_InitConfig(&cfg);
    if (XPath_Exists(pCfgPath)) (void)DirectGate_LoadConfig(&cfg, pCfgPath);
    xstrncpy(cfg.log.sIdent, sizeof(cfg.log.sIdent), "directgate-launcher");
    DirectGate_LogApply(&cfg.log);

    while (!DirectGate_WinLauncher_Stopping())
    {
        DirectGate_InitConfig(&cfg);

        /* DirectGate_InitConfig seeds shell.user with the account the process
           is running under, which for a LocalSystem service is SYSTEM. Clearing
           it is what makes "the identity comes only from the file" true rather
           than merely intended - and it is also what lets the wait below tell
           an unpaired config apart from a paired one. */
        cfg.sShellUser[0] = '\0';

        /* Existence first: a machine that is installed but not yet paired must
           not log a failed load on every poll for as long as it stays that way. */
        if (XPath_Exists(pCfgPath) && DirectGate_LoadConfig(&cfg, pCfgPath) &&
            xstrused(cfg.sShellUser))
        {
            xstrncpy(sShellUser, sizeof(sShellUser), cfg.sShellUser);

            /* Elevated-UI policy is read here, not taken from the agent: the
               launcher is the process that would act on it, so it must own
               the decision. */
            g_bElevEnabled = cfg.desktop.bElevatedInput;
            g_bElevLockScreen = cfg.desktop.bLockScreen;
            g_bPreLogon = cfg.desktop.bPreLogon;

            /* Pre-logon capture lands on the Winlogon desktop, which only the
               elevated helper can reach. Without it the operator would get a
               connected session showing nothing, so say why instead. */
            if (g_bPreLogon && !g_bElevEnabled)
            {
                xlogw("launcher: desktop.preLogon needs desktop.elevatedInput, disabling it: "
                      "the logon screen is only reachable through the elevated helper");

                g_bPreLogon = XFALSE;
            }

            xstrncpy(cfg.log.sIdent, sizeof(cfg.log.sIdent), "directgate-launcher");
            DirectGate_LogApply(&cfg.log);
            break;
        }

        if (!bWaitingForConfig)
        {
            bWaitingForConfig = XTRUE;
            xlogn("launcher: no paired configuration with shell.user yet, waiting for one: cfg(%s)", pCfgPath);
        }

        Sleep(DIRECTGATE_WIN_LAUNCHER_POLL_MS);
    }

    if (!xstrused(sShellUser))
    {
        xlogn("launcher: stopped before a configuration became available");
        return XSTDOK;
    }

    xlogn("launcher: supervising agent for shell.user(%s), elevatedInput(%s), lockScreen(%s), preLogon(%s)",
        sShellUser, g_bElevEnabled ? "on" : "off", g_bElevLockScreen ? "on" : "off", g_bPreLogon ? "on" : "off");

    HANDLE hAgent = NULL;
    uint64_t nLastSpawnMs = 0;
    xbool_t bWaitingForLogon = XFALSE;
    xbool_t bAgentPreLogon = XFALSE;
    DWORD nAgentSession = 0;

    /* When shell.user was first seen to be gone while their agent was still
       running; 0 whenever they are present. See the retire check below. */
    uint64_t nUserGoneSinceMs = 0;

    while (!DirectGate_WinLauncher_Stopping())
    {
        /*
            Whichever agent is running, it stays legitimate only while the
            state it was started for still holds: a normal agent needs
            shell.user logged on, a pre-logon agent needs the console still
            empty. Neither can report losing that itself - a Windows session
            can be destroyed out from under a process that keeps running, and
            an agent in that position holds its relay connection open and looks
            perfectly healthy while every session it could serve is already
            impossible. Only the supervisor can see it, so it checks both.

            Checked before the spawn block, so the logon or logoff that ends
            one agent can start its replacement on the very same tick.
        */
        if (hAgent != NULL)
        {
            xbool_t bUserLoggedOn = DirectGate_WinLauncher_UserIsLoggedOn(sShellUser);
            const char *pWhy = NULL;

            if (bAgentPreLogon)
            {
                /* shell.user is checked separately from the console: an RDP
                   logon gives them a session of their own and leaves the
                   console sitting at the logon screen, so watching the console
                   alone would keep a SYSTEM agent running when the real one
                   could have taken over. */
                DWORD nConsole = WTSGetActiveConsoleSessionId();

                if (bUserLoggedOn) pWhy = "shell.user logged on";
                else if (nConsole != nAgentSession) pWhy = "the console moved to another session";
                else if (DirectGate_WinLauncher_SessionHasUser(nAgentSession)) pWhy = "someone logged on at the console";

                nUserGoneSinceMs = 0;
            }
            else if (!bUserLoggedOn)
            {
                /* Signing out is the case this exists for: the agent's session
                   is gone, so it can serve nothing, and without this the
                   launcher would wait forever on a process that will never
                   exit and never work again - the device online and useless,
                   recoverable only by walking to it. Confirmed over a window
                   rather than acted on at once, because the price of a single
                   spurious reading is a live session killed under a user who
                   is still sitting in front of it. */
                uint64_t nNow = XTime_GetMs();

                if (nUserGoneSinceMs == 0) nUserGoneSinceMs = nNow;
                else if (nNow - nUserGoneSinceMs >= DIRECTGATE_WIN_LAUNCHER_LOGOFF_MS) pWhy = "shell.user signed out";
            }
            else nUserGoneSinceMs = 0;

            if (pWhy != NULL)
            {
                /* Only the pre-logon agent has a session the launcher chose
                   and tracked; the normal one lives in whatever session
                   shell.user logged into, which is not ours to name. */
                if (bAgentPreLogon)
                {
                    xlogn("launcher: retiring the pre-logon agent in session %lu: %s",
                        (unsigned long)nAgentSession, pWhy);
                }
                else xlogn("launcher: retiring the shell.user agent: %s", pWhy);

                DirectGate_WinLauncher_StopAgent(&hAgent);
                bAgentPreLogon = XFALSE;
                g_bAgentPreLogon = XFALSE;
                nUserGoneSinceMs = 0;
            }
        }

        if (hAgent == NULL)
        {
            uint64_t nNow = XTime_GetMs();
            if (nNow - nLastSpawnMs < DIRECTGATE_WIN_LAUNCHER_RESPAWN_MS)
            {
                Sleep(DIRECTGATE_WIN_LAUNCHER_POLL_MS);
                continue;
            }

            HANDLE hToken = NULL;
            xbool_t bPreLogon = XFALSE;
            DWORD nSession = 0;

            if (DirectGate_WinLauncher_AcquireTokenForUser(sShellUser, &hToken, XFALSE) == XSTDOK)
            {
                bWaitingForLogon = XFALSE;
            }
            else
            {
                /* shell.user not logged on. Either nobody is - and the machine
                   can still be reached on the logon screen - or somebody else
                   is, and the passwordless model has nothing to offer but the
                   wait it always did. */
                hToken = DirectGate_WinLauncher_AcquirePreLogonToken(&nSession);

                if (hToken == NULL)
                {
                    if (!bWaitingForLogon)
                    {
                        xlogn("launcher: shell.user not logged on; waiting for logon: user(%s)", sShellUser);
                        bWaitingForLogon = XTRUE;
                    }

                    Sleep(DIRECTGATE_WIN_LAUNCHER_POLL_MS);
                    continue;
                }

                bWaitingForLogon = XFALSE;
                bPreLogon = XTRUE;
            }

            nLastSpawnMs = nNow;
            g_bAgentPreLogon = bPreLogon;

            if (DirectGate_WinLauncher_SpawnAgent(hToken, pCfgPath, bPreLogon, &hAgent) != XSTDOK)
                hAgent = NULL;

            CloseHandle(hToken);

            bAgentPreLogon = (hAgent != NULL) ? bPreLogon : XFALSE;
            g_bAgentPreLogon = bAgentPreLogon;
            nAgentSession = nSession;
            nUserGoneSinceMs = 0;

            if (hAgent == NULL)
            {
                Sleep(DIRECTGATE_WIN_LAUNCHER_POLL_MS);
                continue;
            }
        }

        /* Agent running: wake on its exit, on stop (POLL_MS cap), then respawn
           on the next shell.user logon - or straight away on the logon screen. */
        DWORD nWait = WaitForSingleObject(hAgent, DIRECTGATE_WIN_LAUNCHER_POLL_MS);
        if (nWait == WAIT_OBJECT_0)
        {
            /* Tear the bridge down before the handle goes: no agent means no
               reason for a SYSTEM process to be injecting input. */
            DirectGate_WinLauncher_StopElevChannel();
            CloseHandle(hAgent);
            hAgent = NULL;
            bAgentPreLogon = XFALSE;
            g_bAgentPreLogon = XFALSE;
            nUserGoneSinceMs = 0;

            xlogn("launcher: agent exited; will restart when a session is available");
        }
    }

    DirectGate_WinLauncher_StopAgent(&hAgent);

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
    HANDLE hCtlRead = NULL, hCtlWrite = NULL;
    int i, nFiltered = XSTDNON;

    /* The in-session SYSTEM desktop helper shares this executable but none of
       the agent: it reads only the log section of the config, never opens a
       socket and never parses a protocol message. Dispatch before anything
       else so none of the agent's start-up runs in a SYSTEM process. */
    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], DIRECTGATE_ELEV_HELPER_FLAG) == 0)
            return DirectGate_Elevated_HelperMain(argc, argv);
    }

    for (i = 0; i < argc && nFiltered < (int)XARR_SIZE(pFilteredArgv) - 1; i++)
    {
        if (strcmp(argv[i], DIRECTGATE_WIN_LAUNCHER_FLAG) == 0) { bWinLauncher = XTRUE; continue; }
        if (strcmp(argv[i], DIRECTGATE_WIN_SERVICE_FLAG) == 0) { bWinService = XTRUE; continue; }

        /* Set before any of the agent's start-up runs, so no code path can
           observe an agent that is briefly unrestricted. Stripped like the
           control handles, for the same reason: the agent's own option parser
           has no business knowing about the launcher's private arguments. */
        if (strcmp(argv[i], DIRECTGATE_WIN_PRELOGON_FLAG) == 0)
        {
            DirectGate_Session_SetPreLogon(XTRUE);
            continue;
        }

        /* Control-channel handles the launcher inherited into this process.
           Stripped here so no other option parser has to know about them. */
        if (strcmp(argv[i], "--win-ctl-read") == 0 && i + 1 < argc)
        {
            hCtlRead = (HANDLE)(uintptr_t)strtoull(argv[++i], NULL, 0);
            continue;
        }

        if (strcmp(argv[i], "--win-ctl-write") == 0 && i + 1 < argc)
        {
            hCtlWrite = (HANDLE)(uintptr_t)strtoull(argv[++i], NULL, 0);
            continue;
        }

        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) pWinCfg = argv[i + 1];
        pFilteredArgv[nFiltered++] = argv[i];
    }

    pFilteredArgv[nFiltered] = NULL;

    /* Called even when there are no handles: this is also what initialises the
       bridge's own state and records why it is unavailable. */
    DirectGate_Elevated_SetControlChannel(hCtlRead, hCtlWrite);

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
