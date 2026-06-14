/*!
 * @file directgate-agent/src/agent/winpriv/token.h
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

#ifndef __DIRECTGATE_WINPRIV_TOKEN_H__
#define __DIRECTGATE_WINPRIV_TOKEN_H__

#ifdef _WIN32

#include "xstd.h"
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Find an interactive logon session whose user account matches pShellUser and
 * return its primary token (suitable for CreateProcessAsUser). The caller owns
 * *phToken and must CloseHandle it.
 *
 * Passwordless by design: this uses WTSQueryUserToken, which only succeeds for a
 * user who is currently logged on (console or RDP, active or disconnected).
 * Returns XSTDERR when pShellUser is not logged on - that is the expected
 * "no headless" outcome, not a hard error.
 *
 * Only the launcher (LocalSystem, holding SeTcbPrivilege) can call this; it is
 * the single place a token is minted, and it is always minted for the configured
 * shell.user - never for an identity supplied by a request.
 */
XSTATUS DirectGate_WinToken_AcquireForUser(const char *pShellUser, HANDLE *phToken);

#ifdef __cplusplus
}
#endif

#endif /* _WIN32 */
#endif /* __DIRECTGATE_WINPRIV_TOKEN_H__ */
