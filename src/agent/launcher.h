/*!
 * @file directgate-agent/src/agent/launcher.h
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

/*
 * Windows privilege-separation model (see agent/docs/windows.md).
 *
 * A tiny LocalSystem launcher acquires shell.user's interactive logon token
 * (passwordless, via WTSQueryUserToken) and spawns the WHOLE agent inside that
 * user's session. The agent then runs exactly as on POSIX after setuid: the
 * untrusted protocol parser, the PTY and the file manager all run as shell.user,
 * never as SYSTEM. The launcher itself does no untrusted parsing, so the only
 * SYSTEM-level code is this small, auditable supervisor.
 *
 * Passwordless has one consequence: a logon token only exists while shell.user
 * is logged on (console/RDP). The launcher (re)starts the agent when shell.user
 * is present and simply waits when they are not - there is no headless mode.
 */

#ifndef __DIRECTGATE_WIN_LAUNCHER_H__
#define __DIRECTGATE_WIN_LAUNCHER_H__
#ifdef _WIN32

#include "xstd.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Selects the launcher role; the agent is the same executable without it. */
#define DIRECTGATE_WIN_LAUNCHER_FLAG "--win-launcher"

/*
 * Run the launcher: read shell.user from the agent config at pCfgPath, then
 * supervise one agent process - spawn it as shell.user whenever that account is
 * logged on, and respawn it on the next logon after it exits. Blocks until
 * interrupted. Returns XSTDERR if shell.user is not configured.
 */
XSTATUS DirectGate_WinLauncher_Run(const char *pCfgPath);

/* Ask a running launcher loop to stop (called from the service control handler
   when --win-launcher runs under the SCM). Safe to call from another thread. */
void DirectGate_WinLauncher_Stop(void);

#ifdef __cplusplus
}
#endif

#endif /* _WIN32 */
#endif /* __DIRECTGATE_WIN_LAUNCHER_H__ */
