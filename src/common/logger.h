/*!
 * @file directgate-agent/src/common/logger.h
 * @brief DirectGate log config parsing and apply helpers.
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

#ifndef __DIRECTGATE_LOGGER_H__
#define __DIRECTGATE_LOGGER_H__

#include "includes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DIRECTGATE_LOG_DIR_MODE 0755

typedef struct directgate_log_ {
    char sIdent[XLOG_NAME_MAX];
    char sPath[XPATH_MAX];
    uint8_t nRTCLevel;
    xbool_t bLogRTC;
    xbool_t bToScreen;
    xbool_t bToFile;
    xbool_t bFlush;
    uint16_t nFlags;
    /* Provenance of sPath / sIdent: XTRUE when they came out of agent.json
       rather than from a command-line switch or the built-in default. A
       privileged process refuses the former and honours the latter, so the
       two cannot be told apart after the fact - see
       DirectGate_LogRestrictConfigPaths(). */
    xbool_t bPathFromConfig;
    xbool_t bIdentFromConfig;
} directgate_log_t;

void DirectGate_LogInit(directgate_log_t *pLog, const char *pDefaultIdent, uint16_t nDefaultFlags);
XSTATUS DirectGate_LogApply(const directgate_log_t *pLog);

/* Writes the platform's own log directory (/var/log/directgate, or
   %ProgramData%\directgate on Windows) into @p pPath. */
void DirectGate_LogGetDefaultPath(char *pPath, size_t nSize);

/*
 * Stops DirectGate_LogApply from honouring a log directory or log file name
 * that came out of agent.json, falling back to the platform's own directory
 * and to the ident the process set for itself.
 *
 * agent.json is owned and rewritten by shell.user - it has to be, because the
 * agent persists refreshed enrolment tokens into it - so every process that
 * runs with more privilege than that account must treat log.path and
 * log.ident as untrusted input. Honouring them would let the unprivileged
 * account pick where a SYSTEM or root process creates directories and opens
 * files, which is a privilege-escalation primitive rather than a logging
 * preference. It applies to the Windows LocalSystem launcher, the SYSTEM
 * desktop helper, the pre-logon SYSTEM agent, and a POSIX agent that has not
 * dropped privileges yet.
 *
 * Verbosity, the screen/file sinks and flush behaviour stay configurable:
 * those decide how much is written, never where.
 */
void DirectGate_LogRestrictConfigPaths(void);

/* Lifts the restriction. Called by the POSIX agent once it has verifiably
   dropped to shell.user, because from then on it holds exactly the privilege
   of the account that owns the file it is reading the path from. */
void DirectGate_LogAllowConfigPaths(void);

/* The directory the last DirectGate_LogApply() actually settled on, which is
   not always pLog->sPath - a restricted process is redirected to the platform
   default. Empty until the first apply. Callers that need to act on the log
   directory (the privilege drop hands it to shell.user) must use this rather
   than the configured path, so they can never act on one that was refused. */
const char* DirectGate_LogGetActivePath(void);

/* Replaces the log identity with one the process picked for itself and drops
   the config provenance with it, so a restricted process still honours it.
   Assigning sIdent directly would leave bIdentFromConfig set from an earlier
   DirectGate_LogLoad() and get the new name refused along with the old one. */
void DirectGate_LogSetIdent(directgate_log_t *pLog, const char *pIdent);

xbool_t DirectGate_LogLoad(directgate_log_t *pLog, xjson_obj_t *pRoot);
xbool_t DirectGate_LogSave(const directgate_log_t *pLog, xjson_obj_t *pRoot);

int DirectGate_LogGetRTCLevel(const directgate_log_t *pLog);

#ifdef __cplusplus
}
#endif

#endif

