/*!
 * @file directgate-agent/src/agent/desktop/elevated.c
 * @brief Windows elevated-UI bridge: agent-side client and SYSTEM helper.
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

#if defined(_WIN32)

#define COBJMACROS

#include "elevated.h"
#include "config.h"
#include "logger.h"
#include "yuv.h"

#include <d3d11.h>
#include <dxgi1_2.h>
#include <wtsapi32.h>

/* Both halves live here so the record layouts have exactly one definition and
 * cannot drift between the process that writes them and the one that reads
 * them. The agent-side half runs inside the normal agent; DIRECTGATE_ELEV_HELPER_FLAG
 * selects the helper half, which touches none of the agent's state. */

static uint64_t DirectGate_Elev_MonotonicUs(void)
{
    LARGE_INTEGER counter, frequency;
    if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0) return 0;
    if (!QueryPerformanceCounter(&counter)) return 0;
    return (uint64_t)counter.QuadPart * 1000000ULL / (uint64_t)frequency.QuadPart;
}

static xbool_t DirectGate_Elev_WriteAll(HANDLE hPipe, const void *pData, DWORD nBytes)
{
    const uint8_t *pByte = (const uint8_t*)pData;

    while (nBytes > 0)
    {
        DWORD nWrote = 0;
        if (!WriteFile(hPipe, pByte, nBytes, &nWrote, NULL) || nWrote == 0) return XFALSE;
        pByte += nWrote;
        nBytes -= nWrote;
    }

    return XTRUE;
}

static xbool_t DirectGate_Elev_ReadAll(HANDLE hPipe, void *pData, DWORD nBytes)
{
    uint8_t *pByte = (uint8_t*)pData;

    while (nBytes > 0)
    {
        DWORD nRead = 0;
        if (!ReadFile(hPipe, pByte, nBytes, &nRead, NULL) || nRead == 0) return XFALSE;
        pByte += nRead;
        nBytes -= nRead;
    }

    return XTRUE;
}

/* One record per write call: anonymous pipe writes below the pipe buffer are
 * atomic, so a single writer never interleaves a header with someone else's
 * payload. Callers with several writer threads still take a lock, because
 * atomicity does not order two concurrent records. */
xbool_t DirectGate_Elevated_SendRecord(HANDLE hPipe, uint16_t nType,
                                       const void *pPayload, uint16_t nLength)
{
    uint8_t sFrame[sizeof(directgate_elev_hdr_t) + DIRECTGATE_ELEV_MAX_PAYLOAD];
    XCHECK_NL((hPipe != NULL && hPipe != INVALID_HANDLE_VALUE), XFALSE);
    XCHECK_NL((nLength <= DIRECTGATE_ELEV_MAX_PAYLOAD), XFALSE);

    directgate_elev_hdr_t *pHeader = (directgate_elev_hdr_t*)sFrame;
    pHeader->nMagic = DIRECTGATE_ELEV_MAGIC;
    pHeader->nType = nType;
    pHeader->nLength = nLength;

    if (nLength > 0 && pPayload != NULL)
        memcpy(sFrame + sizeof(*pHeader), pPayload, nLength);

    return DirectGate_Elev_WriteAll(hPipe, sFrame, (DWORD)(sizeof(*pHeader) + nLength));
}

/* Blocks until a whole record arrives. A bad magic or an unexpected length is
 * treated as a broken channel rather than something to resynchronise from:
 * there is no framing recovery to attempt on a private, single-writer pipe,
 * and guessing would be the one place a parser could go wrong. */
xbool_t DirectGate_Elevated_RecvRecord(HANDLE hPipe, uint16_t *pType,
                                       void *pPayload, uint16_t *pLength)
{
    directgate_elev_hdr_t header;
    if (!DirectGate_Elev_ReadAll(hPipe, &header, (DWORD)sizeof(header))) return XFALSE;
    if (header.nMagic != DIRECTGATE_ELEV_MAGIC) return XFALSE;
    if (header.nLength > DIRECTGATE_ELEV_MAX_PAYLOAD) return XFALSE;
    if (header.nLength > 0 && !DirectGate_Elev_ReadAll(hPipe, pPayload, (DWORD)header.nLength)) return XFALSE;

    *pType = header.nType;
    *pLength = header.nLength;

    return XTRUE;
}

/* Bounded receive for the launcher reply. The plain blocking read is fine on
 * the helper's dedicated command thread, but the agent asks for a helper from
 * its main loop: a launcher that never answers must not wedge every session.
 * Anonymous pipes have no read timeout, so poll for the header and then let
 * the normal read collect the rest - the whole record arrives in one write. */
static xbool_t DirectGate_Elev_RecvTimed(HANDLE hPipe, uint16_t *pType, void *pPayload,
                                         uint16_t *pLength, uint32_t nTimeoutMs)
{
    uint64_t nDeadlineMs = XTime_GetMs() + nTimeoutMs;

    for (;;)
    {
        DWORD nAvailable = 0;
        if (!PeekNamedPipe(hPipe, NULL, 0, NULL, &nAvailable, NULL)) return XFALSE;
        if (nAvailable >= sizeof(directgate_elev_hdr_t)) break;
        if (XTime_GetMs() >= nDeadlineMs) return XFALSE;
        Sleep(5);
    }

    return DirectGate_Elevated_RecvRecord(hPipe, pType, pPayload, pLength);
}

/* Integrity level of a process, as the RID of its token's integrity SID
   (SECURITY_MANDATORY_MEDIUM_RID and friends). Zero when it cannot be read. */
static DWORD DirectGate_Elev_ProcessIntegrity(DWORD nPid)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, nPid);
    if (hProcess == NULL) return 0;

    HANDLE hToken = NULL;
    DWORD nLevel = 0;

    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        DWORD nSize = 0;
        GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &nSize);

        if (nSize > 0)
        {
            TOKEN_MANDATORY_LABEL *pLabel = (TOKEN_MANDATORY_LABEL*)malloc(nSize);
            if (pLabel != NULL)
            {
                if (GetTokenInformation(hToken, TokenIntegrityLevel, pLabel, nSize, &nSize))
                {
                    UCHAR *pCount = GetSidSubAuthorityCount(pLabel->Label.Sid);
                    if (pCount != NULL && *pCount > 0)
                        nLevel = *GetSidSubAuthority(pLabel->Label.Sid, (DWORD)(*pCount - 1));
                }

                free(pLabel);
            }
        }

        CloseHandle(hToken);
    }

    CloseHandle(hProcess);
    return nLevel;
}

/* Name of the desktop currently receiving input. Empty when the caller is not
 * allowed to open it, which for a medium-integrity process is itself the
 * secure-desktop signal. */
static xbool_t DirectGate_Elev_InputDesktopName(char *pName, size_t nSize, xbool_t *pDenied)
{
    if (pDenied != NULL) *pDenied = XFALSE;
    if (nSize > 0) pName[0] = '\0';

    HDESK hDesktop = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
    if (hDesktop == NULL)
    {
        if (pDenied != NULL) *pDenied = (GetLastError() == ERROR_ACCESS_DENIED) ? XTRUE : XFALSE;
        return XFALSE;
    }

    DWORD nLength = 0;
    xbool_t bOk = GetUserObjectInformationA(hDesktop, UOI_NAME, pName, (DWORD)nSize, &nLength) ? XTRUE : XFALSE;

    CloseDesktop(hDesktop);
    return (bOk && pName[0] != '\0') ? XTRUE : XFALSE;
}

typedef struct directgate_elev_agent_ {
    /* Control channel to the launcher, inherited at spawn. */
    HANDLE hCtlRead;
    HANDLE hCtlWrite;
    CRITICAL_SECTION ctlLock;

    /* Channel to the helper, minted by the launcher on demand. */
    HANDLE hCommand;
    HANDLE hSection;
    HANDLE hFrameReady;
    HANDLE hFrameTaken;
    CRITICAL_SECTION cmdLock;
    directgate_elev_shm_t *pShm;
    uint32_t nSectionBytes;

    LONG nAttachCount;
    xbool_t bReady;
    xbool_t bInitialized;
    xbool_t bEnabled;      /* desktop.elevatedInput; lockScreen is the helper's */
    volatile LONG bCapturing;
    char sReason[DIRECTGATE_ELEV_REASON_LEN];
} directgate_elev_agent_t;

static directgate_elev_agent_t g_elev = { 0 };

static void DirectGate_Elev_SetReason(const char *pReason)
{
    xstrncpy(g_elev.sReason, sizeof(g_elev.sReason), pReason);
}

void DirectGate_Elevated_SetControlChannel(HANDLE hRead, HANDLE hWrite)
{
    if (!g_elev.bInitialized)
    {
        InitializeCriticalSection(&g_elev.ctlLock);
        InitializeCriticalSection(&g_elev.cmdLock);
        g_elev.bInitialized = XTRUE;
        g_elev.bEnabled = XTRUE;
    }

    g_elev.hCtlRead = hRead;
    g_elev.hCtlWrite = hWrite;

    if (hRead == NULL || hWrite == NULL)
    {
        DirectGate_Elev_SetReason("The agent was not started by the DirectGate service, "
            "so UAC prompts and elevated windows cannot be controlled remotely.");
    }
}

/* bLockScreen is accepted but not stored: the agent could only ever advise on
 * it, and a policy that decides what a SYSTEM process may drive has no business
 * living in the process the policy is protecting against. The launcher reads
 * the same config and passes it to the helper, which enforces it. */
void DirectGate_Elevated_SetEnabled(xbool_t bElevatedInput, xbool_t bLockScreen)
{
    (void)bLockScreen;
    if (!g_elev.bInitialized) DirectGate_Elevated_SetControlChannel(NULL, NULL);

    g_elev.bEnabled = bElevatedInput;

    if (!bElevatedInput)
    {
        DirectGate_Elev_SetReason("Elevated input is disabled in the agent configuration "
            "(desktop.elevatedInput), so UAC prompts and elevated windows stay read-only.");
    }
}

xbool_t DirectGate_Elevated_Supported(void)
{
    return (g_elev.bInitialized && g_elev.bEnabled &&
            g_elev.hCtlWrite != NULL && g_elev.hCtlRead != NULL) ? XTRUE : XFALSE;
}

xbool_t DirectGate_Elevated_Ready(void)
{
    return (g_elev.bReady && g_elev.hCommand != NULL) ? XTRUE : XFALSE;
}

const char* DirectGate_Elevated_Reason(void)
{
    return xstrused(g_elev.sReason) ? g_elev.sReason : NULL;
}

xbool_t DirectGate_Elevated_SecureDesktopActive(void)
{
    char sName[64] = { 0 };
    xbool_t bDenied = XFALSE;

    if (!DirectGate_Elev_InputDesktopName(sName, sizeof(sName), &bDenied))
        return bDenied;

    return xstrcmp(sName, "Default") ? XFALSE : XTRUE;
}

/*
 * The two refusals are not alike, and this is the one that has to be seen
 * coming. The secure desktop reports itself: SendInput returns zero because
 * the calling thread's desktop is not the one receiving input. UIPI does not -
 * MSDN says outright that SendInput "fails when it is blocked by UIPI" and
 * that "neither GetLastError nor the return value will indicate the failure",
 * so a higher-integrity foreground window is silently swallowed and there is
 * nothing after the call to notice. It has to be decided beforehand.
 *
 * GetForegroundWindow is cheap enough to run per event; the token lookup
 * behind it is not, so the verdict is cached against the window it was taken
 * for and only recomputed when focus actually moves. During a game that is one
 * fast user32 call per input event and nothing else.
 */
xbool_t DirectGate_Elevated_ForegroundOutranksAgent(void)
{
    static HWND hCachedWindow = NULL;
    static xbool_t bCachedVerdict = XFALSE;
    static DWORD nAgentIntegrity = 0;

    HWND hForeground = GetForegroundWindow();
    if (hForeground == NULL) return XFALSE;
    if (hForeground == hCachedWindow) return bCachedVerdict;

    if (nAgentIntegrity == 0)
    {
        nAgentIntegrity = DirectGate_Elev_ProcessIntegrity(GetCurrentProcessId());
        if (nAgentIntegrity == 0) nAgentIntegrity = SECURITY_MANDATORY_MEDIUM_RID;
    }

    DWORD nPid = 0;
    GetWindowThreadProcessId(hForeground, &nPid);

    xbool_t bOutranks = XFALSE;
    if (nPid != 0 && nPid != GetCurrentProcessId())
    {
        DWORD nIntegrity = DirectGate_Elev_ProcessIntegrity(nPid);

        /* A refused query counts as outranking. PROCESS_QUERY_LIMITED_INFORMATION
         * exists so a process can look at one above it, and within our own
         * session everything at or below our level answers, so being turned
         * away is itself the answer. */
        bOutranks = (nIntegrity == 0 || nIntegrity > nAgentIntegrity) ? XTRUE : XFALSE;
    }

    hCachedWindow = hForeground;
    bCachedVerdict = bOutranks;
    return bOutranks;
}

static void DirectGate_Elev_CloseHelper(void)
{
    if (g_elev.pShm != NULL)
    {
        UnmapViewOfFile(g_elev.pShm);
        g_elev.pShm = NULL;
    }

    if (g_elev.hSection != NULL) { CloseHandle(g_elev.hSection); g_elev.hSection = NULL; }
    if (g_elev.hFrameReady != NULL) { CloseHandle(g_elev.hFrameReady); g_elev.hFrameReady = NULL; }
    if (g_elev.hFrameTaken != NULL) { CloseHandle(g_elev.hFrameTaken); g_elev.hFrameTaken = NULL; }
    if (g_elev.hCommand != NULL) { CloseHandle(g_elev.hCommand); g_elev.hCommand = NULL; }

    g_elev.nSectionBytes = 0;
    g_elev.bReady = XFALSE;
    InterlockedExchange(&g_elev.bCapturing, 0);
}

/* Asks the launcher for a helper and adopts the handles it duplicated in. The
 * reply is read synchronously: the control channel has exactly one requester
 * (this call, under ctlLock) and one responder, so there is nothing to interleave with. */
static int DirectGate_Elev_RequestHelper(uint32_t nCaptureWidth, uint32_t nCaptureHeight)
{
    directgate_elev_helper_req_t request;
    request.nCaptureWidth = nCaptureWidth;
    request.nCaptureHeight = nCaptureHeight;

    if (!DirectGate_Elevated_SendRecord(g_elev.hCtlWrite, DIRECTGATE_ELEV_MSG_HELPER_REQUEST,
        &request, (uint16_t)sizeof(request)))
    {
        DirectGate_Elev_SetReason("Lost the control channel to the DirectGate service.");
        return XSTDERR;
    }

    uint8_t sPayload[DIRECTGATE_ELEV_MAX_PAYLOAD];
    uint16_t nType = 0, nLength = 0;

    if (!DirectGate_Elev_RecvTimed(g_elev.hCtlRead, &nType, sPayload, &nLength, DIRECTGATE_ELEV_ATTACH_WAIT_MS) ||
        nType != DIRECTGATE_ELEV_MSG_HELPER_READY || nLength != (uint16_t)sizeof(directgate_elev_helper_ready_t))
    {
        DirectGate_Elev_SetReason("The DirectGate service did not answer the desktop helper request.");
        return XSTDERR;
    }

    directgate_elev_helper_ready_t ready;
    memcpy(&ready, sPayload, sizeof(ready));

    if (ready.nStatus != XSTDOK)
    {
        DirectGate_Elev_SetReason("The DirectGate service could not start the elevated desktop helper.");
        return XSTDERR;
    }

    g_elev.hCommand = (HANDLE)(uintptr_t)ready.hCommand;
    g_elev.hSection = (HANDLE)(uintptr_t)ready.hSection;
    g_elev.hFrameReady = (HANDLE)(uintptr_t)ready.hFrameReady;
    g_elev.hFrameTaken = (HANDLE)(uintptr_t)ready.hFrameTaken;
    g_elev.nSectionBytes = ready.nSectionBytes;

    g_elev.pShm = (directgate_elev_shm_t*)MapViewOfFile(g_elev.hSection, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, g_elev.nSectionBytes);
    if (g_elev.pShm == NULL || g_elev.pShm->nMagic != DIRECTGATE_ELEV_SHM_MAGIC)
    {
        DirectGate_Elev_SetReason("Failed to map the elevated desktop frame section.");
        DirectGate_Elev_CloseHelper();
        return XSTDERR;
    }

    g_elev.bReady = XTRUE;
    g_elev.sReason[0] = '\0';
    return XSTDOK;
}

/*
 * The frame slot is sized from the whole virtual desktop, not from the monitor
 * the session happens to have selected. Every encode size the pipeline can
 * ever ask for is bounded by it, so the section is allocated once and no
 * monitor switch or preset change can outgrow it - which in turn means Attach
 * never has to tear down a live helper. That matters: a rebuild happens while
 * the previous pipeline's capture thread may still be parked on the hand-off
 * event, and closing it underneath that thread would be a use-after-close.
 */
int DirectGate_Elevated_Attach(void)
{
    /* Both early returns below used to be silent, which made the one failure
       that matters invisible: with no helper the capture path never probes for
       the secure desktop at all (see bElevAttached in desktop_win.c), so a
       session on the logon screen produces no frames, reports no error, and
       leaves the viewer sitting on "choose a display" with nothing in the log
       to say why. */
    if (!DirectGate_Elevated_Supported())
    {
        xlogw("Elevated desktop helper unavailable: %s", DirectGate_Elevated_Reason());
        return XSTDNON;
    }

    EnterCriticalSection(&g_elev.ctlLock);

    if (g_elev.bReady)
    {
        g_elev.nAttachCount++;
        LeaveCriticalSection(&g_elev.ctlLock);
        return XSTDOK;
    }

    /* A previous helper may have died with its handles still open (the command
       path only clears bReady, it never closes). This is where they go. */
    DirectGate_Elev_CloseHelper();

    int nVirtualWidth = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int nVirtualHeight = GetSystemMetrics(SM_CYVIRTUALSCREEN);

    if (nVirtualWidth <= 0 || nVirtualHeight <= 0)
    {
        LeaveCriticalSection(&g_elev.ctlLock);

        /* Zero here means this process cannot see a desktop at all - which a
           SYSTEM process can hit in a session whose window station it never
           reached. Worth naming: it looks nothing like a helper problem from
           the outside, and every symptom downstream is identical to one. */
        xlogw("Elevated desktop helper unavailable: this process reports no virtual "
              "screen (%dx%d), so it has no desktop to capture", nVirtualWidth, nVirtualHeight);

        return XSTDNON;
    }

    int nStatus = DirectGate_Elev_RequestHelper((uint32_t)nVirtualWidth, (uint32_t)nVirtualHeight);
    if (nStatus == XSTDOK) g_elev.nAttachCount++;

    LeaveCriticalSection(&g_elev.ctlLock);

    if (nStatus == XSTDOK)
    {
        xlogi("Elevated desktop helper attached: desktop(%dx%d), section(%u bytes)",
            nVirtualWidth, nVirtualHeight, g_elev.nSectionBytes);
    }
    else xlogw("Elevated desktop helper unavailable: %s", DirectGate_Elevated_Reason());

    return nStatus;
}

void DirectGate_Elevated_Detach(void)
{
    if (!g_elev.bInitialized) return;
    EnterCriticalSection(&g_elev.ctlLock);

    if (g_elev.nAttachCount > 0) g_elev.nAttachCount--;
    if (g_elev.nAttachCount == 0 && g_elev.hCommand != NULL)
    {
        EnterCriticalSection(&g_elev.cmdLock);

        /* Closing the command pipe is what actually ends the helper; the
           release below only lets the launcher reap it without waiting. */
        (void)DirectGate_Elevated_SendRecord(g_elev.hCommand, DIRECTGATE_ELEV_MSG_CAPTURE_STOP, NULL, 0);
        DirectGate_Elev_CloseHelper();
        LeaveCriticalSection(&g_elev.cmdLock);

        (void)DirectGate_Elevated_SendRecord(g_elev.hCtlWrite, DIRECTGATE_ELEV_MSG_HELPER_RELEASE, NULL, 0);
        xlogi("Elevated desktop helper released");
    }

    LeaveCriticalSection(&g_elev.ctlLock);
}

/* Every command out of the agent funnels through here so the pipe has a single
 * serialised writer.
 *
 * A broken pipe only clears bReady; the handles themselves are closed by
 * Attach/Detach, which run on the main loop with the capture thread stopped.
 * Closing them here would be closing a handle the capture thread may be
 * blocked on inside WaitForSingleObject. */
static xbool_t DirectGate_Elev_Command(uint16_t nType, const void *pPayload, uint16_t nLength)
{
    if (!DirectGate_Elevated_Ready()) return XFALSE;
    EnterCriticalSection(&g_elev.cmdLock);

    xbool_t bOk = XFALSE;
    if (g_elev.hCommand != NULL && g_elev.bReady)
    {
        bOk = DirectGate_Elevated_SendRecord(g_elev.hCommand, nType, pPayload, nLength);
        if (!bOk)
        {
            xlogw("Elevated desktop helper channel broke, falling back to direct input");
            DirectGate_Elev_SetReason("The elevated desktop helper stopped responding.");
            g_elev.bReady = XFALSE;
            InterlockedExchange(&g_elev.bCapturing, 0);

            /* Wake a capture thread parked on the hand-off so it notices the
               bridge is gone this frame instead of after the timeout. */
            if (g_elev.hFrameReady != NULL) SetEvent(g_elev.hFrameReady);
        }
    }

    LeaveCriticalSection(&g_elev.cmdLock);
    return bOk;
}

xbool_t DirectGate_Elevated_SendInput(const INPUT *pInput)
{
    XCHECK_NL((pInput != NULL), XFALSE);

    directgate_elev_input_t record;
    memset(&record, 0, sizeof(record));

    if (pInput->type == INPUT_MOUSE)
    {
        record.nKind = DIRECTGATE_ELEV_INPUT_MOUSE;
        record.nFlags = (uint32_t)pInput->mi.dwFlags;
        record.nData = (uint32_t)pInput->mi.mouseData;
        record.nX = (int32_t)pInput->mi.dx;
        record.nY = (int32_t)pInput->mi.dy;
    }
    else if (pInput->type == INPUT_KEYBOARD)
    {
        record.nKind = DIRECTGATE_ELEV_INPUT_KEY;
        record.nFlags = (uint32_t)pInput->ki.dwFlags;
        record.nData = (uint32_t)pInput->ki.wVk;
        record.nScan = (uint32_t)pInput->ki.wScan;
    }
    else return XFALSE;

    return DirectGate_Elev_Command(DIRECTGATE_ELEV_MSG_INPUT, &record, (uint16_t)sizeof(record));
}

xbool_t DirectGate_Elevated_SetCursorPos(int nX, int nY)
{
    directgate_elev_cursor_t cursor;
    cursor.nX = (int32_t)nX;
    cursor.nY = (int32_t)nY;

    return DirectGate_Elev_Command(DIRECTGATE_ELEV_MSG_CURSOR, &cursor, (uint16_t)sizeof(cursor));
}

xbool_t DirectGate_Elevated_GetCursorPos(int *pX, int *pY)
{
    XCHECK_NL((pX != NULL && pY != NULL), XFALSE);
    if (!DirectGate_Elevated_Ready() || g_elev.pShm == NULL) return XFALSE;

    *pX = (int)InterlockedCompareExchange(&g_elev.pShm->nCursorX, 0, 0);
    *pY = (int)InterlockedCompareExchange(&g_elev.pShm->nCursorY, 0, 0);
    return XTRUE;
}

xbool_t DirectGate_Elevated_SendSAS(void)
{
    if (!DirectGate_Elevated_Supported()) return XFALSE;

    /* SAS is generated by the service itself: SendSAS only obeys a process
       running as LocalSystem under the SCM, which the in-session helper is
       not. Fire and forget - there is no reply to wait for. */
    EnterCriticalSection(&g_elev.ctlLock);
    xbool_t bOk = DirectGate_Elevated_SendRecord(g_elev.hCtlWrite, DIRECTGATE_ELEV_MSG_SAS_REQUEST, NULL, 0);
    LeaveCriticalSection(&g_elev.ctlLock);

    return bOk;
}

int DirectGate_Elevated_StartCapture(int32_t nX, int32_t nY,
                                     uint32_t nCaptureWidth, uint32_t nCaptureHeight,
                                     uint32_t nEncodeWidth, uint32_t nEncodeHeight,
                                     uint32_t nFps)
{
    if (!DirectGate_Elevated_Ready()) return XSTDNON;
    if (InterlockedCompareExchange(&g_elev.bCapturing, 0, 0)) return XSTDOK;

    directgate_elev_capture_t capture;
    capture.nX = nX;
    capture.nY = nY;
    capture.nWidth = nCaptureWidth;
    capture.nHeight = nCaptureHeight;
    capture.nEncodeWidth = nEncodeWidth;
    capture.nEncodeHeight = nEncodeHeight;
    capture.nFps = nFps ? nFps : 15U;

    if (!DirectGate_Elev_Command(DIRECTGATE_ELEV_MSG_CAPTURE_START, &capture, (uint16_t)sizeof(capture)))
        return XSTDERR;

    InterlockedExchange(&g_elev.bCapturing, 1);
    xlogi("Secure desktop is up, capture handed to the elevated helper: encode(%ux%u)",
        nEncodeWidth, nEncodeHeight);

    return XSTDOK;
}

void DirectGate_Elevated_StopCapture(void)
{
    if (!InterlockedExchange(&g_elev.bCapturing, 0)) return;
    (void)DirectGate_Elev_Command(DIRECTGATE_ELEV_MSG_CAPTURE_STOP, NULL, 0);
    xlogi("Secure desktop dismissed, capture returned to the agent pipeline");
}

int DirectGate_Elevated_ReadFrame(uint8_t *pDstBGRA, uint32_t nWidth, uint32_t nHeight,
                                  uint32_t nTimeoutMs, uint64_t *pCapturedUs)
{
    XCHECK_NL((pDstBGRA != NULL && nWidth > 0 && nHeight > 0), XSTDERR);
    if (!DirectGate_Elevated_Ready() || g_elev.pShm == NULL) return XSTDERR;

    DWORD nWait = WaitForSingleObject(g_elev.hFrameReady, nTimeoutMs);
    if (nWait == WAIT_TIMEOUT) return XSTDNON;
    if (nWait != WAIT_OBJECT_0) return XSTDERR;

    /* The wake may have come from a broken command channel rather than the
       helper, in which case the slot holds nothing worth reading. */
    if (!DirectGate_Elevated_Ready()) return XSTDERR;

    directgate_elev_shm_t *pShm = g_elev.pShm;
    const uint8_t *pSlot = (const uint8_t*)pShm + pShm->nHeaderBytes;
    uint32_t nSrcWidth = pShm->nWidth;
    uint32_t nSrcHeight = pShm->nHeight;
    uint32_t nSrcStride = pShm->nStride;
    int nStatus = XSTDOK;

    if (nSrcWidth == 0 || nSrcHeight == 0 || (size_t)nSrcStride * nSrcHeight > pShm->nSlotBytes)
    {
        nStatus = XSTDNON;
    }
    else if (nSrcWidth == nWidth && nSrcHeight == nHeight && nSrcStride == nWidth * 4U)
    {
        memcpy(pDstBGRA, pSlot, (size_t)nWidth * nHeight * 4U);
    }
    else
    {
        /* The helper caps its slot at DIRECTGATE_ELEV_MAX_*, so a capture
           rectangle beyond that arrives smaller and is scaled the rest of the
           way here. Only ever hit by very wide multi-monitor rectangles. */
        DirectGate_YUV_ScaleBGRA(pDstBGRA, nWidth, nHeight, pSlot, nSrcWidth, nSrcHeight, nSrcStride);
    }

    if (pCapturedUs != NULL) *pCapturedUs = pShm->nCapturedUs;

    /* Release the slot before doing anything else with the frame: the helper
       is parked on this event and the picture it is waiting to draw is the one
       the operator is looking at. */
    SetEvent(g_elev.hFrameTaken);
    return nStatus;
}

typedef struct directgate_elev_helper_ {
    HANDLE hCommand;        /* agent -> helper */
    HANDLE hSection;
    HANDLE hFrameReady;
    HANDLE hFrameTaken;
    HANDLE hAgent;          /* agent process, waited on for lifetime */
    directgate_elev_shm_t *pShm;
    uint32_t nSectionBytes;
    DWORD nAgentPid;
    DWORD nAgentIntegrity;
    xbool_t bAllowLockScreen;

    HANDLE hCaptureThread;
    volatile LONG bCaptureRun;
    directgate_elev_capture_t capture;
} directgate_elev_helper_t;

static directgate_elev_helper_t g_helper = { 0 };

/* True while the interactive session is showing the lock screen. Treated as
   unlocked when the query fails: a UAC prompt must never be blocked because
   the lock state could not be read. */
static xbool_t DirectGate_Elev_SessionLocked(void)
{
    WTSINFOEXW *pInfo = NULL;
    DWORD nBytes = 0;
    xbool_t bLocked = XFALSE;

    if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION,
        WTSSessionInfoEx, (LPWSTR*)&pInfo, &nBytes)) return XFALSE;

    if (pInfo != NULL && nBytes >= sizeof(WTSINFOEXW) && pInfo->Level == 1)
        bLocked = (pInfo->Data.WTSInfoExLevel1.SessionFlags == WTS_SESSIONSTATE_LOCK) ? XTRUE : XFALSE;

    if (pInfo != NULL) WTSFreeMemory(pInfo);
    return bLocked;
}

/* SetThreadDesktop binds the calling thread only, so each thread that injects
   or captures keeps its own attachment. A single shared handle would silently
   leave whichever thread got there second on the wrong desktop. */
typedef struct directgate_elev_deskref_ {
    HDESK hDesktop;
    char sName[64];
} directgate_elev_deskref_t;

/* Only ever called as the owning thread is finishing: a desktop handle has to
   stay open while it is the thread's desktop, and the thread is about to stop
   having one. */
static void DirectGate_Elev_ReleaseDesktop(directgate_elev_deskref_t *pRef)
{
    if (pRef->hDesktop == NULL) return;

    CloseDesktop(pRef->hDesktop);
    pRef->hDesktop = NULL;
    pRef->sName[0] = '\0';
}

/* Attaches the calling thread to whatever desktop currently receives input.
   Returns XSTDOK when the desktop changed (callers rebuild their capture
   objects), XSTDNON when it did not and XSTDERR when it could not be opened. */
static int DirectGate_Elev_AttachDesktop(directgate_elev_deskref_t *pRef)
{
    HDESK hDesktop = OpenInputDesktop(0, FALSE, GENERIC_ALL);
    if (hDesktop == NULL) return XSTDERR;

    char sName[64] = { 0 };
    DWORD nLength = 0;
    if (!GetUserObjectInformationA(hDesktop, UOI_NAME, sName, (DWORD)sizeof(sName), &nLength))
        sName[0] = '\0';

    if (pRef->hDesktop != NULL && xstrcmp(sName, pRef->sName))
    {
        CloseDesktop(hDesktop);
        return XSTDNON;
    }

    if (!SetThreadDesktop(hDesktop))
    {
        CloseDesktop(hDesktop);
        return XSTDERR;
    }

    if (pRef->hDesktop != NULL) CloseDesktop(pRef->hDesktop);
    pRef->hDesktop = hDesktop;
    xstrncpy(pRef->sName, sizeof(pRef->sName), sName);

    if (g_helper.pShm != NULL)
    {
        InterlockedExchange(&g_helper.pShm->nInputDesktop,
            xstrcmp(sName, "Default") ? DIRECTGATE_ELEV_DESKTOP_DEFAULT :
                                        DIRECTGATE_ELEV_DESKTOP_SECURE);
    }

    xlogi("helper: attached to input desktop: name(%s)", xstrused(sName) ? sName : "?");
    return XSTDOK;
}

/*
 * The whole point of the privilege boundary: a SYSTEM process injecting input
 * on behalf of a medium-integrity agent must only do what the agent could not
 * do for itself. Injection is therefore allowed only when
 *
 *   - the input desktop is not Default (a UAC prompt, the lock screen or the
 *     security screen), or
 *   - the foreground window belongs to a process of higher integrity than the
 *     agent (Task Manager, an elevated application).
 *
 * On the plain desktop with an ordinary foreground window the event is
 * dropped, so a compromised agent gains nothing here that it did not already
 * have as shell.user.
 */
static xbool_t DirectGate_Elev_InjectionAllowed(const char *pDesktop)
{
    if (!xstrcmp(pDesktop, "Default"))
    {
        if (!g_helper.bAllowLockScreen && DirectGate_Elev_SessionLocked()) return XFALSE;
        return XTRUE;
    }

    HWND hForeground = GetForegroundWindow();
    if (hForeground == NULL) return XFALSE;

    DWORD nPid = 0;
    GetWindowThreadProcessId(hForeground, &nPid);
    if (nPid == 0 || nPid == g_helper.nAgentPid) return XFALSE;

    DWORD nIntegrity = DirectGate_Elev_ProcessIntegrity(nPid);
    return (nIntegrity > g_helper.nAgentIntegrity) ? XTRUE : XFALSE;
}

static void DirectGate_Elev_Inject(directgate_elev_deskref_t *pRef,
                                   const directgate_elev_input_t *pInput)
{
    /* Follow the input desktop first: SendInput is delivered to the desktop
       the calling thread is attached to, and a UAC prompt can appear between
       two events of the same drag. */
    (void)DirectGate_Elev_AttachDesktop(pRef);
    if (!DirectGate_Elev_InjectionAllowed(pRef->sName)) return;

    INPUT input;
    memset(&input, 0, sizeof(input));

    if (pInput->nKind == DIRECTGATE_ELEV_INPUT_MOUSE)
    {
        input.type = INPUT_MOUSE;
        input.mi.dx = (LONG)pInput->nX;
        input.mi.dy = (LONG)pInput->nY;
        input.mi.mouseData = (DWORD)pInput->nData;
        input.mi.dwFlags = (DWORD)pInput->nFlags;
    }
    else if (pInput->nKind == DIRECTGATE_ELEV_INPUT_KEY)
    {
        input.type = INPUT_KEYBOARD;
        input.ki.wVk = (WORD)pInput->nData;
        input.ki.wScan = (WORD)pInput->nScan;
        input.ki.dwFlags = (DWORD)pInput->nFlags;
    }
    else return;

    if (SendInput(1, &input, sizeof(input)) == 0)
        xlogd("helper: SendInput refused: kind(%u), err(%lu)", pInput->nKind, (unsigned long)GetLastError());
}

typedef struct directgate_elev_capsrc_ {
    ID3D11Device *pDevice;
    ID3D11DeviceContext *pContext;
    IDXGIOutput1 *pOutput;
    IDXGIOutputDuplication *pDuplication;
    ID3D11Texture2D *pStaging;

    HDC hScreenDC;
    HDC hMemDC;
    HBITMAP hDib;
    HGDIOBJ hOldBitmap;
    uint8_t *pDibBits;
    xbool_t bUseGdi;
} directgate_elev_capsrc_t;

static void DirectGate_Elev_CapReleaseDxgi(directgate_elev_capsrc_t *pSrc)
{
    if (pSrc->pStaging != NULL) { ID3D11Texture2D_Release(pSrc->pStaging); pSrc->pStaging = NULL; }
    if (pSrc->pDuplication != NULL) { IDXGIOutputDuplication_Release(pSrc->pDuplication); pSrc->pDuplication = NULL; }
    if (pSrc->pOutput != NULL) { IDXGIOutput1_Release(pSrc->pOutput); pSrc->pOutput = NULL; }
    if (pSrc->pContext != NULL) { ID3D11DeviceContext_Release(pSrc->pContext); pSrc->pContext = NULL; }
    if (pSrc->pDevice != NULL) { ID3D11Device_Release(pSrc->pDevice); pSrc->pDevice = NULL; }
}

static void DirectGate_Elev_CapReleaseGdi(directgate_elev_capsrc_t *pSrc)
{
    if (pSrc->hMemDC != NULL)
    {
        if (pSrc->hOldBitmap != NULL) SelectObject(pSrc->hMemDC, pSrc->hOldBitmap);
        DeleteDC(pSrc->hMemDC);
        pSrc->hMemDC = NULL;
        pSrc->hOldBitmap = NULL;
    }

    if (pSrc->hDib != NULL) { DeleteObject(pSrc->hDib); pSrc->hDib = NULL; pSrc->pDibBits = NULL; }
    if (pSrc->hScreenDC != NULL) { ReleaseDC(NULL, pSrc->hScreenDC); pSrc->hScreenDC = NULL; }
}

static void DirectGate_Elev_CapRelease(directgate_elev_capsrc_t *pSrc)
{
    DirectGate_Elev_CapReleaseDxgi(pSrc);
    DirectGate_Elev_CapReleaseGdi(pSrc);
    pSrc->bUseGdi = XFALSE;
}

/* Deliberately a second, self-contained copy of the duplication setup in
 * desktop_win.c rather than a shared abstraction: that file is the latency
 * hot path of the whole product and is not worth refactoring behind an
 * indirection for a fallback that only runs while a modal dialog is on
 * screen. This copy is also allowed to be simpler - no pacing, no mailbox. */
static xbool_t DirectGate_Elev_CapInitDxgi(directgate_elev_capsrc_t *pSrc,
                                           const directgate_elev_capture_t *pCapture)
{
    IDXGIFactory1 *pFactory = NULL;
    IDXGIAdapter *pAdapter = NULL;
    IDXGIOutput *pOutput = NULL;
    IDXGIAdapter *pFoundAdapter = NULL;
    IDXGIOutput1 *pFoundOutput = NULL;

    if (FAILED(CreateDXGIFactory1(&IID_IDXGIFactory1, (void**)&pFactory)) || pFactory == NULL) return XFALSE;

    for (UINT a = 0; pFoundOutput == NULL && IDXGIFactory1_EnumAdapters(pFactory, a, &pAdapter) == S_OK; a++)
    {
        for (UINT o = 0; IDXGIAdapter_EnumOutputs(pAdapter, o, &pOutput) == S_OK; o++)
        {
            DXGI_OUTPUT_DESC desc;
            memset(&desc, 0, sizeof(desc));

            if (SUCCEEDED(IDXGIOutput_GetDesc(pOutput, &desc)) &&
                desc.AttachedToDesktop &&
                desc.DesktopCoordinates.left == pCapture->nX &&
                desc.DesktopCoordinates.top == pCapture->nY &&
                (uint32_t)(desc.DesktopCoordinates.right - desc.DesktopCoordinates.left) == pCapture->nWidth &&
                (uint32_t)(desc.DesktopCoordinates.bottom - desc.DesktopCoordinates.top) == pCapture->nHeight &&
                SUCCEEDED(IDXGIOutput_QueryInterface(pOutput, &IID_IDXGIOutput1, (void**)&pFoundOutput)))
            {
                pFoundAdapter = pAdapter;
                IDXGIAdapter_AddRef(pFoundAdapter);
                IDXGIOutput_Release(pOutput);
                break;
            }

            IDXGIOutput_Release(pOutput);
        }

        IDXGIAdapter_Release(pAdapter);
    }

    IDXGIFactory1_Release(pFactory);
    if (pFoundOutput == NULL) return XFALSE;

    HRESULT hr = D3D11CreateDevice(pFoundAdapter, D3D_DRIVER_TYPE_UNKNOWN, NULL, 0,
        NULL, 0, D3D11_SDK_VERSION, &pSrc->pDevice, NULL, &pSrc->pContext);
    IDXGIAdapter_Release(pFoundAdapter);

    if (FAILED(hr) || pSrc->pDevice == NULL)
    {
        IDXGIOutput1_Release(pFoundOutput);
        pSrc->pDevice = NULL;
        pSrc->pContext = NULL;
        return XFALSE;
    }

    pSrc->pOutput = pFoundOutput;
    if (FAILED(IDXGIOutput1_DuplicateOutput(pSrc->pOutput, (IUnknown*)pSrc->pDevice, &pSrc->pDuplication)) || pSrc->pDuplication == NULL)
    {
        pSrc->pDuplication = NULL;
        DirectGate_Elev_CapReleaseDxgi(pSrc);
        return XFALSE;
    }

    return XTRUE;
}

static xbool_t DirectGate_Elev_CapInitGdi(directgate_elev_capsrc_t *pSrc,
                                          const directgate_elev_capture_t *pCapture)
{
    pSrc->hScreenDC = GetDC(NULL);
    if (pSrc->hScreenDC == NULL) return XFALSE;

    pSrc->hMemDC = CreateCompatibleDC(pSrc->hScreenDC);
    if (pSrc->hMemDC == NULL)
    {
        DirectGate_Elev_CapReleaseGdi(pSrc);
        return XFALSE;
    }

    BITMAPINFO info;
    memset(&info, 0, sizeof(info));
    info.bmiHeader.biSize = sizeof(info.bmiHeader);
    info.bmiHeader.biWidth = (LONG)pCapture->nWidth;
    info.bmiHeader.biHeight = -(LONG)pCapture->nHeight; /* top-down rows */
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;

    void *pBits = NULL;
    pSrc->hDib = CreateDIBSection(pSrc->hScreenDC, &info, DIB_RGB_COLORS, &pBits, NULL, 0);
    if (pSrc->hDib == NULL || pBits == NULL)
    {
        DirectGate_Elev_CapReleaseGdi(pSrc);
        return XFALSE;
    }

    pSrc->pDibBits = (uint8_t*)pBits;
    pSrc->hOldBitmap = SelectObject(pSrc->hMemDC, pSrc->hDib);
    return XTRUE;
}

/* DXGI first, GDI as the fallback. On the Winlogon desktop GDI is a weak
 * substitute (LogonUI is composited and can come back black), so a failed
 * duplication there is worth a log line. */
static xbool_t DirectGate_Elev_CapInit(directgate_elev_capsrc_t *pSrc,
                                       const directgate_elev_capture_t *pCapture,
                                       const char *pDesktop)
{
    DirectGate_Elev_CapRelease(pSrc);

    if (DirectGate_Elev_CapInitDxgi(pSrc, pCapture)) return XTRUE;

    xlogw("helper: duplication unavailable on desktop(%s), falling back to GDI", xstrused(pDesktop) ? pDesktop : "?");

    pSrc->bUseGdi = XTRUE;
    return DirectGate_Elev_CapInitGdi(pSrc, pCapture);
}

/* Fills pDst (nDstW x nDstH BGRA) from the current desktop. XSTDOK on a new
 * frame, XSTDNON when nothing was ready, XSTDERR when the source died. */
static int DirectGate_Elev_CapAcquire(directgate_elev_capsrc_t *pSrc,
                                      const directgate_elev_capture_t *pCapture,
                                      uint8_t *pDst, uint32_t nDstW, uint32_t nDstH,
                                      uint32_t nTimeoutMs)
{
    if (pSrc->bUseGdi)
    {
        if (!BitBlt(pSrc->hMemDC, 0, 0, (int)pCapture->nWidth, (int)pCapture->nHeight,
            pSrc->hScreenDC, pCapture->nX, pCapture->nY, SRCCOPY)) return XSTDERR;

        GdiFlush();
        DirectGate_YUV_ScaleBGRA(pDst, nDstW, nDstH, pSrc->pDibBits,
            pCapture->nWidth, pCapture->nHeight, (size_t)pCapture->nWidth * 4U);

        return XSTDOK;
    }

    DXGI_OUTDUPL_FRAME_INFO frameInfo;
    IDXGIResource *pResource = NULL;
    memset(&frameInfo, 0, sizeof(frameInfo));

    HRESULT hr = IDXGIOutputDuplication_AcquireNextFrame(pSrc->pDuplication, nTimeoutMs, &frameInfo, &pResource);
    if (hr == DXGI_ERROR_WAIT_TIMEOUT) return XSTDNON;
    if (FAILED(hr) || pResource == NULL) return XSTDERR;

    ID3D11Texture2D *pTexture = NULL;
    hr = IDXGIResource_QueryInterface(pResource, &IID_ID3D11Texture2D, (void**)&pTexture);
    IDXGIResource_Release(pResource);

    if (FAILED(hr) || pTexture == NULL)
    {
        IDXGIOutputDuplication_ReleaseFrame(pSrc->pDuplication);
        return XSTDERR;
    }

    D3D11_TEXTURE2D_DESC desc;
    ID3D11Texture2D_GetDesc(pTexture, &desc);

    if (pSrc->pStaging != NULL)
    {
        D3D11_TEXTURE2D_DESC staging;
        ID3D11Texture2D_GetDesc(pSrc->pStaging, &staging);

        if (staging.Width != desc.Width || staging.Height != desc.Height ||
            staging.Format != desc.Format)
        {
            ID3D11Texture2D_Release(pSrc->pStaging);
            pSrc->pStaging = NULL;
        }
    }

    if (pSrc->pStaging == NULL)
    {
        D3D11_TEXTURE2D_DESC staging = desc;
        staging.Usage = D3D11_USAGE_STAGING;
        staging.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        staging.BindFlags = 0;
        staging.MiscFlags = 0;
        staging.MipLevels = 1;
        staging.ArraySize = 1;

        if (FAILED(ID3D11Device_CreateTexture2D(pSrc->pDevice, &staging, NULL, &pSrc->pStaging)))
        {
            pSrc->pStaging = NULL;
            ID3D11Texture2D_Release(pTexture);
            IDXGIOutputDuplication_ReleaseFrame(pSrc->pDuplication);
            return XSTDERR;
        }
    }

    ID3D11DeviceContext_CopyResource(pSrc->pContext, (ID3D11Resource*)pSrc->pStaging, (ID3D11Resource*)pTexture);
    ID3D11Texture2D_Release(pTexture);
    IDXGIOutputDuplication_ReleaseFrame(pSrc->pDuplication);

    D3D11_MAPPED_SUBRESOURCE mapped;
    memset(&mapped, 0, sizeof(mapped));

    if (FAILED(ID3D11DeviceContext_Map(pSrc->pContext, (ID3D11Resource*)pSrc->pStaging,
        0, D3D11_MAP_READ, 0, &mapped)) || mapped.pData == NULL) return XSTDERR;

    DirectGate_YUV_ScaleBGRA(pDst, nDstW, nDstH, (const uint8_t*)mapped.pData,
        desc.Width, desc.Height, mapped.RowPitch);

    ID3D11DeviceContext_Unmap(pSrc->pContext, (ID3D11Resource*)pSrc->pStaging, 0);
    return XSTDOK;
}

static DWORD WINAPI DirectGate_Elev_CaptureThread(LPVOID pArg)
{
    directgate_elev_capture_t capture = *(const directgate_elev_capture_t*)pArg;
    directgate_elev_shm_t *pShm = g_helper.pShm;
    HRESULT hrCom = CoInitializeEx(NULL, COINIT_MULTITHREADED);

    /* Clamp to what the slot can hold; the agent scales the remainder. */
    uint32_t nDstW = capture.nEncodeWidth;
    uint32_t nDstH = capture.nEncodeHeight;
    if (nDstW > pShm->nMaxWidth) nDstW = pShm->nMaxWidth;
    if (nDstH > pShm->nMaxHeight) nDstH = pShm->nMaxHeight;
    nDstW &= ~1U;
    nDstH &= ~1U;

    size_t nFrameBytes = (size_t)nDstW * nDstH * 4U;
    uint8_t *pFrame = (uint8_t*)malloc(nFrameBytes);
    uint8_t *pPrev = (uint8_t*)malloc(nFrameBytes);
    directgate_elev_capsrc_t source;
    directgate_elev_deskref_t desktop;
    memset(&source, 0, sizeof(source));
    memset(&desktop, 0, sizeof(desktop));

    xbool_t bHavePrev = XFALSE;
    xbool_t bSourceReady = XFALSE;
    uint32_t nFps = capture.nFps ? capture.nFps : 15U;
    DWORD nIntervalMs = 1000U / nFps;
    if (nIntervalMs == 0) nIntervalMs = 1;

    if (pFrame == NULL || pPrev == NULL)
    {
        xloge("helper: failed to allocate %zu byte capture buffers", nFrameBytes);
        InterlockedExchange(&pShm->nCaptureFailed, 1);
    }

    while (pFrame != NULL && pPrev != NULL && InterlockedCompareExchange(&g_helper.bCaptureRun, 0, 0))
    {
        InterlockedExchange(&pShm->nHeartbeatMs, (LONG)GetTickCount());

        /* A desktop switch invalidates both the duplication and the screen DC,
           so rebuild the source whenever the thread moves. */
        int nAttached = DirectGate_Elev_AttachDesktop(&desktop);
        if (nAttached == XSTDERR)
        {
            InterlockedExchange(&pShm->nCaptureFailed, 1);
            Sleep(nIntervalMs);
            continue;
        }

        /* The lock-screen policy has to cover the picture as well as the
           input: with it off the operator gets what they got before the
           bridge existed - the frozen desktop, not the logon UI. Deliberately
           narrower than the injection gate, which also has an opinion about
           foreground windows that says nothing about what may be captured. */
        if (!g_helper.bAllowLockScreen && !xstrcmp(desktop.sName, "Default") && DirectGate_Elev_SessionLocked())
        {
            if (bSourceReady)
            {
                DirectGate_Elev_CapRelease(&source);
                bSourceReady = XFALSE;
                bHavePrev = XFALSE;
            }

            Sleep(nIntervalMs);
            continue;
        }

        if (nAttached == XSTDOK || !bSourceReady)
        {
            bSourceReady = DirectGate_Elev_CapInit(&source, &capture, desktop.sName);
            bHavePrev = XFALSE;

            if (!bSourceReady)
            {
                InterlockedExchange(&pShm->nCaptureFailed, 1);
                Sleep(nIntervalMs);
                continue;
            }

            InterlockedExchange(&pShm->nCaptureFailed, 0);
        }

        POINT cursor;
        if (GetCursorPos(&cursor))
        {
            InterlockedExchange(&pShm->nCursorX, (LONG)cursor.x);
            InterlockedExchange(&pShm->nCursorY, (LONG)cursor.y);
        }

        int nCapture = DirectGate_Elev_CapAcquire(&source, &capture, pFrame, nDstW, nDstH, nIntervalMs);
        if (nCapture == XSTDERR)
        {
            bSourceReady = XFALSE;
            Sleep(nIntervalMs);
            continue;
        }

        if (nCapture == XSTDNON)
        {
            if (source.bUseGdi) Sleep(nIntervalMs);
            continue;
        }

        /* Only publish real changes: a consent dialog is a still picture and
           the agent's encoder must not be fed the same frame at 15 fps. */
        if (bHavePrev && memcmp(pFrame, pPrev, nFrameBytes) == 0)
        {
            if (source.bUseGdi) Sleep(nIntervalMs);
            continue;
        }

        uint8_t *pSlot = (uint8_t*)pShm + pShm->nHeaderBytes;
        memcpy(pSlot, pFrame, nFrameBytes);
        pShm->nWidth = nDstW;
        pShm->nHeight = nDstH;
        pShm->nStride = nDstW * 4U;
        pShm->nCapturedUs = DirectGate_Elev_MonotonicUs();

        memcpy(pPrev, pFrame, nFrameBytes);
        bHavePrev = XTRUE;

        SetEvent(g_helper.hFrameReady);

        /* Single slot: wait for the agent to take it before drawing again. The
           timeout keeps a stalled agent from wedging the helper. */
        WaitForSingleObject(g_helper.hFrameTaken, 1000);

        /* Duplication paces itself inside AcquireNextFrame; BitBlt does not,
           and would otherwise run as fast as the agent can drain. */
        if (source.bUseGdi) Sleep(nIntervalMs);
    }

    DirectGate_Elev_CapRelease(&source);
    DirectGate_Elev_ReleaseDesktop(&desktop);
    free(pFrame);
    free(pPrev);

    if (SUCCEEDED(hrCom)) CoUninitialize();
    return 0;
}

static void DirectGate_Elev_StopCaptureThread(void)
{
    if (g_helper.hCaptureThread == NULL) return;

    InterlockedExchange(&g_helper.bCaptureRun, 0);
    SetEvent(g_helper.hFrameTaken);

    if (WaitForSingleObject(g_helper.hCaptureThread, 5000) != WAIT_OBJECT_0)
        xlogw("helper: capture thread did not stop in time");

    CloseHandle(g_helper.hCaptureThread);
    g_helper.hCaptureThread = NULL;
}

static void DirectGate_Elev_StartCaptureThread(const directgate_elev_capture_t *pCapture)
{
    DirectGate_Elev_StopCaptureThread();

    g_helper.capture = *pCapture;
    InterlockedExchange(&g_helper.bCaptureRun, 1);
    InterlockedExchange(&g_helper.pShm->nCaptureFailed, 0);

    g_helper.hCaptureThread = CreateThread(NULL, 0, DirectGate_Elev_CaptureThread, &g_helper.capture, 0, NULL);
    if (g_helper.hCaptureThread == NULL)
    {
        InterlockedExchange(&g_helper.bCaptureRun, 0);
        InterlockedExchange(&g_helper.pShm->nCaptureFailed, 1);
        xloge("helper: failed to start the capture thread: err(%lu)", (unsigned long)GetLastError());
        return;
    }

    xlogi("helper: capture started: rect(%d,%d %ux%u), encode(%ux%u), fps(%u)",
        pCapture->nX, pCapture->nY, pCapture->nWidth, pCapture->nHeight,
        pCapture->nEncodeWidth, pCapture->nEncodeHeight, pCapture->nFps);
}

/* Watches the agent process so a killed or crashed agent can never leave a
   SYSTEM injector running. */
static DWORD WINAPI DirectGate_Elev_AgentWatchThread(LPVOID pArg)
{
    (void)pArg;
    if (g_helper.hAgent != NULL) WaitForSingleObject(g_helper.hAgent, INFINITE);

    xlogn("helper: agent process is gone, exiting");
    ExitProcess(0);
    return 0;
}

static HANDLE DirectGate_Elev_ArgHandle(int argc, char *argv[], const char *pName)
{
    for (int i = 1; i + 1 < argc; i++)
    {
        if (!xstrcmp(argv[i], pName)) continue;
        return (HANDLE)(uintptr_t)strtoull(argv[i + 1], NULL, 0);
    }

    return NULL;
}

static uint64_t DirectGate_Elev_ArgNumber(int argc, char *argv[], const char *pName, uint64_t nDefault)
{
    for (int i = 1; i + 1 < argc; i++)
    {
        if (!xstrcmp(argv[i], pName)) continue;
        return strtoull(argv[i + 1], NULL, 0);
    }

    return nDefault;
}

XSTATUS DirectGate_Elevated_HelperMain(int argc, char *argv[])
{
    directgate_log_t log;
    DirectGate_LogInit(&log, "directgate-helper", XLOG_ERROR | XLOG_WARN | XLOG_NOTE | XLOG_INFO);

    /*
     * Verbosity arrives as a number from the launcher, and nothing else does.
     * This process is SYSTEM and agent.json belongs to shell.user, so reading
     * that file here would mean a SYSTEM process running the same JSON parser
     * the protocol uses over data an unprivileged account controls - and, far
     * worse, taking log.path and log.ident from it, which is a SYSTEM file
     * write at a path of that account's choosing. The helper keeps its own
     * name and its own directory; the only thing the config is allowed to
     * decide is how much gets written.
     */
    uint64_t nFlags = DirectGate_Elev_ArgNumber(argc, argv, "--log-flags", (uint64_t)log.nFlags);
    if (nFlags <= UINT16_MAX) log.nFlags = (uint16_t)nFlags;

    /* log.toFile travels with it, so turning file logging off in the config
       still silences the helper the way it always did. */
    log.bToFile = DirectGate_Elev_ArgNumber(argc, argv, "--log-file", 1) ? XTRUE : XFALSE;

    xlog_defaults();
    xlog_indent(XTRUE);
    xlog_coloring(XFALSE);
    xlog_timing(XLOG_DATE);
    DirectGate_LogApply(&log);

    g_helper.hCommand = DirectGate_Elev_ArgHandle(argc, argv, "--cmd");
    g_helper.hSection = DirectGate_Elev_ArgHandle(argc, argv, "--shm");
    g_helper.hFrameReady = DirectGate_Elev_ArgHandle(argc, argv, "--ready");
    g_helper.hFrameTaken = DirectGate_Elev_ArgHandle(argc, argv, "--taken");
    g_helper.hAgent = DirectGate_Elev_ArgHandle(argc, argv, "--agent");
    g_helper.nSectionBytes = (uint32_t)DirectGate_Elev_ArgNumber(argc, argv, "--shm-bytes", 0);
    g_helper.nAgentPid = (DWORD)DirectGate_Elev_ArgNumber(argc, argv, "--agent-pid", 0);
    g_helper.bAllowLockScreen = DirectGate_Elev_ArgNumber(argc, argv, "--allow-lock", 1) ? XTRUE : XFALSE;

    if (g_helper.hCommand == NULL || g_helper.hSection == NULL ||
        g_helper.hFrameReady == NULL || g_helper.hFrameTaken == NULL ||
        g_helper.nSectionBytes < sizeof(directgate_elev_shm_t) || g_helper.nAgentPid == 0)
    {
        xloge("helper: missing or invalid channel handles; this process is started by the "
              "DirectGate service and cannot be run by hand");
        return XSTDERR;
    }

    g_helper.pShm = (directgate_elev_shm_t*)MapViewOfFile(g_helper.hSection,
        FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, g_helper.nSectionBytes);

    if (g_helper.pShm == NULL || g_helper.pShm->nMagic != DIRECTGATE_ELEV_SHM_MAGIC)
    {
        xloge("helper: failed to map the frame section: err(%lu)", (unsigned long)GetLastError());
        return XSTDERR;
    }

    /* The integrity floor for the injection gate. If the agent's own level
       cannot be read, fall back to Medium so the gate stays closed for
       ordinary windows rather than open. */
    g_helper.nAgentIntegrity = DirectGate_Elev_ProcessIntegrity(g_helper.nAgentPid);
    if (g_helper.nAgentIntegrity == 0) g_helper.nAgentIntegrity = SECURITY_MANDATORY_MEDIUM_RID;

    SetProcessShutdownParameters(0x100, 0);
    HANDLE hWatch = CreateThread(NULL, 0, DirectGate_Elev_AgentWatchThread, NULL, 0, NULL);
    if (hWatch != NULL) CloseHandle(hWatch);

    /* Per-monitor DPI awareness must match the agent's, or injected absolute
       coordinates land on the wrong pixel on a scaled display. */
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    /* This thread's own attachment; the capture thread keeps a separate one. */
    directgate_elev_deskref_t desktop;
    memset(&desktop, 0, sizeof(desktop));
    (void)DirectGate_Elev_AttachDesktop(&desktop);

    xlogn("helper: started: agentPid(%lu), agentIntegrity(0x%lx), lockScreen(%s)",
        (unsigned long)g_helper.nAgentPid, (unsigned long)g_helper.nAgentIntegrity,
        g_helper.bAllowLockScreen ? "allowed" : "blocked");

    uint8_t sPayload[DIRECTGATE_ELEV_MAX_PAYLOAD];
    uint16_t nType = 0, nLength = 0;

    while (DirectGate_Elevated_RecvRecord(g_helper.hCommand, &nType, sPayload, &nLength))
    {
        switch (nType)
        {
            case DIRECTGATE_ELEV_MSG_INPUT:
                if (nLength == (uint16_t)sizeof(directgate_elev_input_t))
                {
                    directgate_elev_input_t input;
                    memcpy(&input, sPayload, sizeof(input));
                    DirectGate_Elev_Inject(&desktop, &input);
                }
                break;

            case DIRECTGATE_ELEV_MSG_CURSOR:
                if (nLength == (uint16_t)sizeof(directgate_elev_cursor_t))
                {
                    directgate_elev_cursor_t cursor;
                    memcpy(&cursor, sPayload, sizeof(cursor));

                    (void)DirectGate_Elev_AttachDesktop(&desktop);
                    if (DirectGate_Elev_InjectionAllowed(desktop.sName))
                        SetCursorPos(cursor.nX, cursor.nY);
                }
                break;

            case DIRECTGATE_ELEV_MSG_CAPTURE_START:
                if (nLength == (uint16_t)sizeof(directgate_elev_capture_t))
                {
                    directgate_elev_capture_t capture;
                    memcpy(&capture, sPayload, sizeof(capture));

                    if (capture.nWidth > 0 && capture.nHeight > 0 &&
                        capture.nEncodeWidth > 0 && capture.nEncodeHeight > 0)
                        DirectGate_Elev_StartCaptureThread(&capture);
                }
                break;

            case DIRECTGATE_ELEV_MSG_CAPTURE_STOP:
                DirectGate_Elev_StopCaptureThread();
                break;

            default:
                xlogd("helper: ignoring unknown record: type(%u), length(%u)", nType, nLength);
                break;
        }
    }

    xlogn("helper: command channel closed, shutting down");
    DirectGate_Elev_StopCaptureThread();
    DirectGate_Elev_ReleaseDesktop(&desktop);
    UnmapViewOfFile(g_helper.pShm);
    XLog_Destroy();

    return XSTDNON;
}

#endif /* _WIN32 */
