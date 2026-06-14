/*!
 * @file directgate-agent/src/agent/winpriv/token.c
 * @brief shell.user logon-token acquisition for the launcher (privilege sep).
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
#include "token.h"

#include <wtsapi32.h>

/* Resolve an account name (accepts "user", "DOMAIN\user" or ".\user") to a SID
   copied into pSidBuf (SECURITY_MAX_SID_SIZE bytes). */
static XSTATUS DirectGate_WinToken_LookupSid(const char *pShellUser, PSID pSidBuf)
{
    const char *pName = pShellUser;

    /* ".\user" means a local account; LookupAccountName wants the bare name. */
    if (pName[0] == '.' && pName[1] == '\\') pName += 2;

    DWORD nSidLen = SECURITY_MAX_SID_SIZE;
    char sDomain[256];
    DWORD nDomLen = (DWORD)sizeof(sDomain);
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
static xbool_t DirectGate_WinToken_MatchesUser(HANDLE hToken, PSID pWantSid)
{
    uint8_t sUserBuf[256];
    DWORD nLen = 0;

    if (!GetTokenInformation(hToken, TokenUser, sUserBuf, (DWORD)sizeof(sUserBuf), &nLen))
        return XFALSE;

    return EqualSid(((TOKEN_USER*)sUserBuf)->User.Sid, pWantSid) ? XTRUE : XFALSE;
}

XSTATUS DirectGate_WinToken_AcquireForUser(const char *pShellUser, HANDLE *phToken)
{
    XCHECK((xstrused(pShellUser) && phToken != NULL), XSTDINV);
    *phToken = NULL;

    uint8_t sWantSid[SECURITY_MAX_SID_SIZE];
    if (DirectGate_WinToken_LookupSid(pShellUser, sWantSid) != XSTDOK)
        return XSTDERR;

    PWTS_SESSION_INFOA pSessions = NULL;
    DWORD nCount = 0;

    if (!WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessions, &nCount))
    {
        xloge("token: failed to enumerate logon sessions: error(%lu)", GetLastError());
        return XSTDERR;
    }

    XSTATUS nStatus = XSTDERR;

    for (DWORD i = 0; i < nCount; i++)
    {
        /* Active = at the console/RDP; Disconnected = still logged on (RDP
           detached). Both carry a usable user token; other states do not. */
        if (pSessions[i].State != WTSActive && pSessions[i].State != WTSDisconnected)
            continue;

        HANDLE hToken = NULL;
        if (!WTSQueryUserToken(pSessions[i].SessionId, &hToken))
            continue;

        if (DirectGate_WinToken_MatchesUser(hToken, sWantSid))
        {
            /* WTSQueryUserToken already returns a primary token suitable for
               CreateProcessAsUser - hand it straight back. */
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

#endif /* _WIN32 */
