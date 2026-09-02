/*!
 * @file directgate-agent/src/common/logger.c
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

#include "includes.h"
#include "webrtc.h"
#include "logger.h"

#ifdef _WIN32
#define DIRECTGATE_LOG_PATH_DEFAULT "C:/ProgramData/directgate"
#else
#define DIRECTGATE_LOG_PATH_DEFAULT "/var/log/directgate"
#endif

static uint16_t DirectGate_LogFlagFromLevel(const char *pLevel)
{
    if (!xstrused(pLevel)) return XSTDNON;

    if (xstrncasecmp(pLevel, "panic", 5) ||
        xstrncasecmp(pLevel, "fatal", 5))
        return XLOG_FATAL;
    if (xstrncasecmp(pLevel, "error", 5))
        return XLOG_ERROR;
    if (xstrncasecmp(pLevel, "warn", 4) ||
        xstrncasecmp(pLevel, "warning", 7))
        return XLOG_WARN;
    if (xstrncasecmp(pLevel, "note", 4))
        return XLOG_NOTE;
    if (xstrncasecmp(pLevel, "info", 4))
        return XLOG_INFO;
    if (xstrncasecmp(pLevel, "debug", 5))
        return XLOG_DEBUG;
    if (xstrncasecmp(pLevel, "trace", 5))
        return XLOG_TRACE;
    if (xstrncasecmp(pLevel, "all", 3))
        return XLOG_ALL;

    return XSTDNON;
}

static uint16_t DirectGate_LogParseLevels(xjson_obj_t *pLevels)
{
    XCHECK((pLevels != NULL), XSTDNON);
    XCHECK((pLevels->nType == XJSON_TYPE_ARRAY), XSTDNON);

    uint16_t nFlags = 0;
    size_t nCount = XJSON_GetArrayLength(pLevels);

    for (size_t i = 0; i < nCount; ++i)
    {
        xjson_obj_t *pItem = XJSON_GetArrayItem(pLevels, i);
        if (pItem == NULL || pItem->nType != XJSON_TYPE_STRING) continue;

        const char *pLevel = XJSON_GetString(pItem);
        uint16_t nFlag = DirectGate_LogFlagFromLevel(pLevel);
        if (!nFlag) continue;

        if (nFlag == XLOG_ALL)
        {
            nFlags = XLOG_ALL;
            break;
        }

        nFlags |= nFlag;
    }

    if (nFlags) nFlags |= XLOG_NONE;
    return nFlags;
}

static void DirectGate_LogAddLevel(xjson_obj_t *pLevels, const char *pLevel)
{
    XCHECK_VOID_NL((xstrused(pLevel)));
    XCHECK_VOID((pLevels != NULL));
    XCHECK_VOID((pLevels->nType == XJSON_TYPE_ARRAY));

    xjson_obj_t *pItem = XJSON_NewString(pLevels->pPool, NULL, pLevel);
    XCHECK_VOID((pItem != NULL));

    if (XJSON_AddObject(pLevels, pItem) != XJSON_ERR_NONE)
        XJSON_FreeObject(pItem);
}

static void DirectGate_LogAddLevelsJson(xjson_obj_t *pLog, uint16_t nFlags)
{
    XCHECK_VOID_NL(nFlags);
    XCHECK_VOID((pLog != NULL));
    XCHECK_VOID((pLog->nType == XJSON_TYPE_OBJECT));

    xjson_obj_t *pLevels = XJSON_GetOrCreateArray(pLog, "levels", 1);
    XCHECK_VOID((pLevels != NULL));

    if (XLOG_FLAGS_CHECK(nFlags, XLOG_FATAL)) DirectGate_LogAddLevel(pLevels, "panic");
    if (XLOG_FLAGS_CHECK(nFlags, XLOG_ERROR)) DirectGate_LogAddLevel(pLevels, "error");
    if (XLOG_FLAGS_CHECK(nFlags, XLOG_WARN)) DirectGate_LogAddLevel(pLevels, "warn");
    if (XLOG_FLAGS_CHECK(nFlags, XLOG_NOTE)) DirectGate_LogAddLevel(pLevels, "note");
    if (XLOG_FLAGS_CHECK(nFlags, XLOG_INFO)) DirectGate_LogAddLevel(pLevels, "info");
    if (XLOG_FLAGS_CHECK(nFlags, XLOG_DEBUG)) DirectGate_LogAddLevel(pLevels, "debug");
    if (XLOG_FLAGS_CHECK(nFlags, XLOG_TRACE)) DirectGate_LogAddLevel(pLevels, "trace");
}

int DirectGate_LogGetRTCLevel(const directgate_log_t *pLog)
{
    if (!pLog->bLogRTC) return RTC_LOG_ERROR;
    uint16_t nLogFlags = pLog->nFlags;

    if (nLogFlags & XLOG_TRACE) return RTC_LOG_VERBOSE;
    if (nLogFlags & XLOG_DEBUG) return RTC_LOG_DEBUG;
    if (nLogFlags & XLOG_INFO) return RTC_LOG_INFO;
    if (nLogFlags & XLOG_NOTE) return RTC_LOG_WARNING;
    if (nLogFlags & XLOG_WARN) return RTC_LOG_WARNING;
    if (nLogFlags & XLOG_ERROR) return RTC_LOG_ERROR;
    if (nLogFlags & XLOG_FATAL) return RTC_LOG_FATAL;
    return RTC_LOG_NONE;
}

/* When set, a log directory or file name that came out of agent.json is
   ignored in favour of the platform default. See the header for why. */
static xbool_t g_bRestrictConfigPaths = XFALSE;

void DirectGate_LogRestrictConfigPaths(void)
{
    g_bRestrictConfigPaths = XTRUE;
}

void DirectGate_LogAllowConfigPaths(void)
{
    g_bRestrictConfigPaths = XFALSE;
}

/* Set by DirectGate_LogApply() once it knows which directory it settled on. */
static char g_sActiveLogPath[XPATH_MAX] = { 0 };

const char* DirectGate_LogGetActivePath(void)
{
    return g_sActiveLogPath;
}

void DirectGate_LogSetIdent(directgate_log_t *pLog, const char *pIdent)
{
    XCHECK_VOID_NL((pLog != NULL));
    XCHECK_VOID_NL((xstrused(pIdent)));

    xstrncpy(pLog->sIdent, sizeof(pLog->sIdent), pIdent);
    pLog->bIdentFromConfig = XFALSE;
}

/* Writes the platform's default log directory into @p pPath. */
void DirectGate_LogGetDefaultPath(char *pPath, size_t nSize)
{
#ifdef _WIN32
    /* The literal above names the C: drive, but Windows is not always
     * installed there and ProgramData moves with it. The environment variable
     * is what the system itself uses to find that directory, so it wins when
     * it is set and the literal stays as the fallback. */
    const char *pProgramData = getenv("ProgramData");

    if (xstrused(pProgramData)) xstrncpyf(pPath, nSize, "%s/directgate", pProgramData);
    else xstrncpy(pPath, nSize, DIRECTGATE_LOG_PATH_DEFAULT);

    /* Windows hands that variable back with backslashes, and the directory
     * walker that creates the path splits on forward slashes only. */
    for (size_t i = 0; pPath[i] != XSTR_NUL; i++)
        if (pPath[i] == '\\') pPath[i] = '/';
#else
    xstrncpy(pPath, nSize, DIRECTGATE_LOG_PATH_DEFAULT);
#endif
}

void DirectGate_LogInit(directgate_log_t *pLog, const char *pDefaultIdent, uint16_t nDefaultFlags)
{
    XCHECK_VOID_NL((pLog != NULL));
    memset(pLog, 0, sizeof(*pLog));

    pLog->bToScreen = XFALSE;
    pLog->bToFile = XTRUE;
    pLog->bFlush = XTRUE;
    pLog->bLogRTC = XFALSE;
    pLog->nFlags = nDefaultFlags;

    if (xstrused(pDefaultIdent))
        xstrncpy(pLog->sIdent, sizeof(pLog->sIdent), pDefaultIdent);

    DirectGate_LogGetDefaultPath(pLog->sPath, sizeof(pLog->sPath));
}

XSTATUS DirectGate_LogApply(const directgate_log_t *pLog)
{
    XCHECK((pLog != NULL), XSTDERR);
    xlog_screen(pLog->bToScreen);
    xlog_file(pLog->bToFile);
    xlog_setfl(pLog->nFlags);
    xlog_flush(pLog->bFlush);

    /* A privileged process keeps the name it chose for itself: a config-
       supplied ident would otherwise let the unprivileged account pick the
       file name a SYSTEM process opens. */
    xbool_t bRefuseConfig = g_bRestrictConfigPaths;
    if (xstrused(pLog->sIdent) && !(bRefuseConfig && pLog->bIdentFromConfig))
        xlog_name(pLog->sIdent);

    char sDefault[XPATH_MAX];
    const char *pWanted = pLog->sPath;
    xbool_t bRefused = (bRefuseConfig && pLog->bPathFromConfig) ? XTRUE : XFALSE;

    if (bRefused)
    {
        DirectGate_LogGetDefaultPath(sDefault, sizeof(sDefault));
        pWanted = sDefault;
    }

    if (xstrused(pWanted))
    {
        char sPath[XPATH_MAX];
        xlog_file(XFALSE);

        size_t nLen = xstrncpy(sPath, sizeof(sPath), pWanted);

#ifdef _WIN32
        /* A path written into the config the way Windows writes paths is
         * still a valid path; normalising the separators here is what lets
         * the directory walk below see its components. */
        for (size_t i = 0; i < nLen; i++) if (sPath[i] == '\\') sPath[i] = '/';
#endif

        while (nLen > 1 && (sPath[nLen - 1] == '/')) sPath[--nLen] = XSTR_NUL;

        XCHECK((XDir_Create(sPath, DIRECTGATE_LOG_DIR_MODE) > 0),
            xthrowe("Failed to create log directory: %s", sPath));

        xlog_file(pLog->bToFile);
        xlog_path(sPath);

        xstrncpy(g_sActiveLogPath, sizeof(g_sActiveLogPath), sPath);
    }

    /* Only once the destination is in place. Until xlog_path() runs the file
       sink is still libxutils' default of ".", so a line written before it
       lands in the process working directory - which for a service is a system
       directory it has no business creating files in, and which is exactly the
       kind of write this restriction exists to prevent. */
    if (bRefused)
    {
        xlogw("Ignoring the configured log directory: this process is more "
              "privileged than the account that owns the config, so it logs "
              "to its own directory instead: wanted(%s), using(%s)",
              pLog->sPath, pWanted);
    }

    return XSTDOK;
}

xbool_t DirectGate_LogLoad(directgate_log_t *pLog, xjson_obj_t *pRoot)
{
    XCHECK_NL((pLog != NULL), XFALSE);
    XCHECK_NL((pRoot != NULL), XFALSE);

    xjson_obj_t *pLogObj = XJSON_GetObject(pRoot, "log");
    if (pLogObj == NULL || pLogObj->nType != XJSON_TYPE_OBJECT) return XTRUE;

    xjson_obj_t *pToScreen = XJSON_GetObject(pLogObj, "toScreen");
    if (pToScreen != NULL) pLog->bToScreen = XJSON_GetBool(pToScreen);

    xjson_obj_t *pToFile = XJSON_GetObject(pLogObj, "toFile");
    if (pToFile != NULL) pLog->bToFile = XJSON_GetBool(pToFile);

    xjson_obj_t *pLogRTC = XJSON_GetObject(pLogObj, "logRTC");
    if (pLogRTC != NULL) pLog->bLogRTC = XJSON_GetBool(pLogRTC);

    xjson_obj_t *pFlush = XJSON_GetObject(pLogObj, "flush");
    if (pFlush != NULL) pLog->bFlush = XJSON_GetBool(pFlush);

    /* Provenance marks a genuine override, not an echo. DirectGate_LogSave()
       writes both fields back every time the config is persisted, so an
       ordinary agent.json already contains the platform default path and the
       process's own ident - and a privileged process must not then announce
       that it is refusing a value in order to substitute the same one, nor
       lose the name it was initialised with. Only a value that actually
       differs from what this process already holds is the config choosing. */
    const char *pPath = XJSON_GetString(XJSON_GetObject(pLogObj, "path"));
    if (xstrused(pPath))
    {
        if (!xstrcmp(pLog->sPath, pPath)) pLog->bPathFromConfig = XTRUE;
        xstrncpy(pLog->sPath, sizeof(pLog->sPath), pPath);
    }

    if (pToFile == NULL && xstrused(pPath)) pLog->bToFile = XTRUE;

    const char *pIdent = XJSON_GetString(XJSON_GetObject(pLogObj, "ident"));
    if (xstrused(pIdent))
    {
        if (!xstrcmp(pLog->sIdent, pIdent)) pLog->bIdentFromConfig = XTRUE;
        xstrncpy(pLog->sIdent, sizeof(pLog->sIdent), pIdent);
    }

    xjson_obj_t *pLevels = XJSON_GetObject(pLogObj, "levels");
    if (pLevels != NULL && pLevels->nType == XJSON_TYPE_ARRAY)
    {
        uint16_t nFlags = DirectGate_LogParseLevels(pLevels);
        if (nFlags) pLog->nFlags = nFlags;
    }

    pLog->nRTCLevel = DirectGate_LogGetRTCLevel(pLog);
    return XTRUE;
}

xbool_t DirectGate_LogSave(const directgate_log_t *pLog, xjson_obj_t *pRoot)
{
    XCHECK_NL((pLog != NULL), XFALSE);
    XCHECK_NL((pRoot != NULL), XFALSE);

    xjson_obj_t *pLogObj = XJSON_GetOrCreateObject(pRoot, "log", 1);
    if (pLogObj == NULL) return XFALSE;

    XJSON_AddBool(pLogObj, "logRTC", pLog->bLogRTC);
    XJSON_AddBool(pLogObj, "toScreen", pLog->bToScreen);
    XJSON_AddBool(pLogObj, "toFile", pLog->bToFile);
    XJSON_AddBool(pLogObj, "flush", pLog->bFlush);

    if (xstrused(pLog->sPath)) XJSON_AddString(pLogObj, "path", pLog->sPath);
    if (xstrused(pLog->sIdent)) XJSON_AddString(pLogObj, "ident", pLog->sIdent);

    DirectGate_LogAddLevelsJson(pLogObj, pLog->nFlags);
    return XTRUE;
}
