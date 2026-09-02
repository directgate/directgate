/* Regression test for the privileged-path restriction in logger.c.
 *
 * agent.json is owned and rewritten by shell.user, so a process that outranks
 * that account (the Windows LocalSystem launcher, the SYSTEM desktop helper,
 * the pre-logon SYSTEM agent, or a POSIX agent that has not dropped privileges
 * yet) must not create directories or open log files where that file points.
 * These cases pin the behaviour that stops it. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "src/common/logger.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "log_privpath_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

/* A path under the build directory that the test owns and can prove is
 * absent before each case. */
static void temp_path(char *pOut, size_t nSize, const char *pLeaf)
{
    snprintf(pOut, nSize, "dg-privpath-%s-%u", pLeaf, (unsigned)getpid());
}

static void wipe(const char *pPath)
{
    XPath_Remove(pPath);
}

static int load_from_json(directgate_log_t *pLog, const char *pJson)
{
    xjson_t json;
    if (!XJSON_Parse(&json, NULL, pJson, strlen(pJson))) return 0;
    xbool_t bOk = DirectGate_LogLoad(pLog, json.pRootObj);
    XJSON_Destroy(&json);
    return bOk ? 1 : 0;
}

int main(void)
{
    char sConfigDir[XPATH_MAX];
    char sArgvDir[XPATH_MAX];

    temp_path(sConfigDir, sizeof(sConfigDir), "cfg");
    temp_path(sArgvDir, sizeof(sArgvDir), "argv");

    wipe(sConfigDir);
    wipe(sArgvDir);

    /* ---- provenance is recorded when the path comes from the config ---- */
    directgate_log_t log;
    DirectGate_LogInit(&log, "dg-test", XLOG_ERROR);
    CHECK(!log.bPathFromConfig, "the built-in default path is not config-sourced");
    CHECK(!log.bIdentFromConfig, "the built-in default ident is not config-sourced");

    char sJson[XPATH_MAX + 128];
    snprintf(sJson, sizeof(sJson),
        "{\"log\":{\"toFile\":true,\"path\":\"%s\",\"ident\":\"pwned\"}}", sConfigDir);

    CHECK(load_from_json(&log, sJson), "log config parses");
    CHECK(log.bPathFromConfig, "a path out of agent.json is marked config-sourced");
    CHECK(log.bIdentFromConfig, "an ident out of agent.json is marked config-sourced");
    CHECK(strcmp(log.sPath, sConfigDir) == 0, "config path loaded");

    /* ---- restricted: the config's directory must NOT be created ---- */
    DirectGate_LogRestrictConfigPaths();
    DirectGate_LogApply(&log);
    CHECK(!XPath_Exists(sConfigDir),
        "a privileged process must not create the log directory agent.json names");

    /* The privilege drop hands the active log directory to shell.user with a
     * chown, so the accessor must never report the refused path back. */
    CHECK(strcmp(DirectGate_LogGetActivePath(), sConfigDir) != 0,
        "the refused path must not be reported as the active one");
    CHECK(xstrused(DirectGate_LogGetActivePath()),
        "a restricted apply still reports the directory it fell back to");

    /* ---- restricted: an ident the process picked for itself survives, the
            way the launcher renames its own log. Assigning sIdent directly
            would leave the config provenance behind and get it refused. ---- */
    directgate_log_t named;
    DirectGate_LogInit(&named, "dg-test", XLOG_ERROR);
    CHECK(load_from_json(&named, sJson), "log config parses again");
    CHECK(named.bIdentFromConfig, "ident starts out config-sourced");

    DirectGate_LogSetIdent(&named, "dg-privileged");
    CHECK(!named.bIdentFromConfig, "a self-chosen ident drops the provenance");
    CHECK(strcmp(named.sIdent, "dg-privileged") == 0, "self-chosen ident stored");

    /* ---- restricted: a path the operator passed on argv is still honoured,
            because argv comes from whoever started the process ---- */
    directgate_log_t argvLog;
    DirectGate_LogInit(&argvLog, "dg-test", XLOG_ERROR);
    xstrncpy(argvLog.sPath, sizeof(argvLog.sPath), sArgvDir);
    argvLog.bPathFromConfig = XFALSE;
    argvLog.bToFile = XTRUE;

    DirectGate_LogApply(&argvLog);
    CHECK(XPath_Exists(sArgvDir), "an argv-supplied log directory stays honoured");
    CHECK(strcmp(DirectGate_LogGetActivePath(), sArgvDir) == 0,
        "the honoured path is reported as the active one");
    wipe(sArgvDir);

    /* ---- unrestricted: the same config is honoured once the process holds
            no more privilege than the account that owns it ---- */
    DirectGate_LogAllowConfigPaths();
    DirectGate_LogApply(&log);
    CHECK(XPath_Exists(sConfigDir),
        "an unprivileged process still honours the configured log directory");
    CHECK(strcmp(DirectGate_LogGetActivePath(), sConfigDir) == 0,
        "an unrestricted apply reports the configured directory as active");
    wipe(sConfigDir);

    /* Leave the global in its default state for anything that follows. */
    DirectGate_LogAllowConfigPaths();

    printf("log_privpath_smoke: OK\n");
    return 0;
}
