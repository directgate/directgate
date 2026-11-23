#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "src/client/config.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "client_config_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static int write_text(const char *pPath, const char *pText)
{
    FILE *pFile = fopen(pPath, "wb");
    if (pFile == NULL) return 0;
    size_t nLen = strlen(pText);
    int nOk = fwrite(pText, 1, nLen, pFile) == nLen;
    return fclose(pFile) == 0 && nOk;
}

/* ---- remote operations: what each command line parses into, or that it is refused ---- */

#define RC_F 1  /* -f */
#define RC_R 2  /* -r */
#define RC_J 4  /* -j */

typedef struct {
    const char *pWords[10];     /* the verb, then whatever follows "-c <config>" */
    XSTATUS nStatus;            /* what DirectGate_ParseArgs returns */
    directgate_remote_op_t eOp; /* NONE: the device list */
    const char *pDevice;
    const char *pPath;
    const char *pOther;         /* cp: the local side, mv: the target, exec: the command */
    int nFlags;
    uint32_t nTimeoutMs;
    const char *pCwd;
    const char *pWhat;
} remote_case_t;

/* glibc reads the ordering ('+' stops at the first operand) only when getopt starts over: each case starts
   over the way a fresh dgcli process does */
static void getopt_restart(void)
{
    char *pArgv[] = { (char*)"dgcli", NULL };
    optind = 0;
    (void)getopt(1, pArgv, "+");
}

static int remote_case(const char *pConfig, const remote_case_t *pCase)
{
    char *pArgv[16];
    int nArgc = 0;
    pArgv[nArgc++] = (char*)"dgcli";
    pArgv[nArgc++] = (char*)pCase->pWords[0];
    pArgv[nArgc++] = (char*)"-c";
    pArgv[nArgc++] = (char*)pConfig;
    for (int i = 1; pCase->pWords[i] != NULL && nArgc + 1 < 16; i++) pArgv[nArgc++] = (char*)pCase->pWords[i];
    pArgv[nArgc] = NULL;

    directgate_cfg_t cfg;
    getopt_restart();
    XSTATUS nStatus = DirectGate_ParseArgs(&cfg, nArgc, pArgv);
    const directgate_remote_req_t *pReq = &cfg.remote;
    int bPass = nStatus == pCase->nStatus;

    if (bPass && nStatus == XSTDOK && pCase->eOp == DIRECTGATE_REMOTE_NONE)
        bPass = cfg.eCommand == DIRECTGATE_CMD_DEVICES && cfg.bJson == ((pCase->nFlags & RC_J) ? XTRUE : XFALSE);
    else if (bPass && nStatus == XSTDOK)
    {
        const char *pOther = pReq->eOp == DIRECTGATE_REMOTE_EXEC ? pReq->pCommand :
            pReq->eOp == DIRECTGATE_REMOTE_MOVE ? pReq->sTarget : pReq->sLocal;

        bPass = cfg.eCommand == DIRECTGATE_CMD_REMOTE && pReq->eOp == pCase->eOp &&
            strcmp(cfg.sDeviceQuery, pCase->pDevice) == 0 &&
            strcmp(pReq->sPath, pCase->pPath != NULL ? pCase->pPath : "") == 0 &&
            strcmp(pOther != NULL ? pOther : "", pCase->pOther != NULL ? pCase->pOther : "") == 0 &&
            pReq->bForce == ((pCase->nFlags & RC_F) ? XTRUE : XFALSE) &&
            pReq->bRecursive == ((pCase->nFlags & RC_R) ? XTRUE : XFALSE) &&
            pReq->bJson == ((pCase->nFlags & RC_J) ? XTRUE : XFALSE) &&
            pReq->nTimeoutMs == pCase->nTimeoutMs &&
            strcmp(pReq->sCwd, pCase->pCwd != NULL ? pCase->pCwd : "") == 0 &&
            !pReq->bOutputMax && !pReq->nOutputMax;
    }

    if (!bPass) fprintf(stderr, "client_config_smoke: %s (status %d)\n", pCase->pWhat, (int)nStatus);
    DirectGate_Remote_ReqClear(&cfg.remote);
    return bPass;
}

static int remote_cases(const char *pConfig)
{
    static char sLongSpec[XSTR_MID + 16];
    memset(sLongSpec, 'b', XSTR_MID);
    memcpy(sLongSpec + XSTR_MID, ":/x", 4);

    const remote_case_t cases[] = {
        { { "ls", "box:/srv" }, XSTDOK, DIRECTGATE_REMOTE_LIST, "box", "/srv", NULL, 0, 0, NULL, "ls <device>:<path>" },
        { { "ls", "-j", "box:/srv" }, XSTDOK, DIRECTGATE_REMOTE_LIST, "box", "/srv", NULL, RC_J, 0, NULL, "ls -j" },
        { { "ls" }, XSTDOK, DIRECTGATE_REMOTE_NONE, NULL, NULL, NULL, 0, 0, NULL, "ls alone is the device list" },
        { { "ls", "-j" }, XSTDOK, DIRECTGATE_REMOTE_NONE, NULL, NULL, NULL, RC_J, 0, NULL, "ls -j is the device list" },
        { { "cp", "box:/a/b.txt", "." }, XSTDOK, DIRECTGATE_REMOTE_GET, "box", "/a/b.txt", ".", 0, 0, NULL, "cp down" },
        { { "cp", "box:/a/b.txt", "-" }, XSTDOK, DIRECTGATE_REMOTE_GET, "box", "/a/b.txt", "-", 0, 0, NULL, "cp to -" },
        { { "cp", "./x", "box:/tmp/" }, XSTDOK, DIRECTGATE_REMOTE_PUT, "box", "/tmp/", "./x", 0, 0, NULL, "cp up" },
        { { "cp", "-f", "-", "box:/tmp/x" }, XSTDOK, DIRECTGATE_REMOTE_PUT, "box", "/tmp/x", "-", RC_F, 0, NULL, "cp -f -" },
        { { "cp", "-f", "box:/x", "y" }, XSTDOK, DIRECTGATE_REMOTE_GET, "box", "/x", "y", RC_F, 0, NULL, "cp -f down" },
        { { "cp", "C:/x", "box:/tmp/" }, XSTDOK, DIRECTGATE_REMOTE_PUT, "box", "/tmp/", "C:/x", 0, 0, NULL,
            "a single letter before the colon is a local drive" },
        { { "cp", "./a:b", "box:/tmp/" }, XSTDOK, DIRECTGATE_REMOTE_PUT, "box", "/tmp/", "./a:b", 0, 0, NULL,
            "a separator before the colon makes it local" },
        { { "cp", "Test Box:/srv/x", "." }, XSTDOK, DIRECTGATE_REMOTE_GET, "Test Box", "/srv/x", ".", 0, 0, NULL,
            "a device name with a space" },
        { { "cp", "box:C:\\x", "." }, XSTDOK, DIRECTGATE_REMOTE_GET, "box", "C:\\x", ".", 0, 0, NULL,
            "an absolute Windows path on the device" },
        { { "rm", "box:/x" }, XSTDOK, DIRECTGATE_REMOTE_REMOVE, "box", "/x", NULL, 0, 0, NULL, "rm" },
        { { "rm", "-r", "box:/x" }, XSTDOK, DIRECTGATE_REMOTE_REMOVE, "box", "/x", NULL, RC_R, 0, NULL, "rm -r" },
        { { "mkdir", "box:/x" }, XSTDOK, DIRECTGATE_REMOTE_MKDIR, "box", "/x", NULL, 0, 0, NULL, "mkdir" },
        { { "mv", "box:/a", "/b" }, XSTDOK, DIRECTGATE_REMOTE_MOVE, "box", "/a", "/b", 0, 0, NULL, "mv to a path" },
        { { "mv", "box:/a", "box:/b" }, XSTDOK, DIRECTGATE_REMOTE_MOVE, "box", "/a", "/b", 0, 0, NULL, "mv to a spec" },
        { { "exec", "box", "ls", "-la" }, XSTDOK, DIRECTGATE_REMOTE_EXEC, "box", NULL, "ls -la", 0, 0, NULL,
            "exec: what follows the device is the command" },
        { { "exec", "box", "--", "ls" }, XSTDOK, DIRECTGATE_REMOTE_EXEC, "box", NULL, "ls", 0, 0, NULL, "exec --" },
        { { "exec", "-d", "box", "ls" }, XSTDOK, DIRECTGATE_REMOTE_EXEC, "box", NULL, "ls", 0, 0, NULL, "exec -d" },
        { { "exec", "-t", "5", "-C", "/srv", "box", "make", "test" }, XSTDOK, DIRECTGATE_REMOTE_EXEC, "box", NULL,
            "make test", 0, 5000, "/srv", "exec -t -C" },
        { { "exec", "box", "gcc", "-c", "x.c" }, XSTDOK, DIRECTGATE_REMOTE_EXEC, "box", NULL, "gcc -c x.c", 0, 0, NULL,
            "a -c after the device is the command's" },
        { { "exec", "box", "head", "-o", "x" }, XSTDOK, DIRECTGATE_REMOTE_EXEC, "box", NULL, "head -o x", 0, 0, NULL,
            "a -o after the device is the command's, and sets no limit" },
        { { "session", "box" }, XSTDOK, DIRECTGATE_REMOTE_SESSION, "box", NULL, NULL, 0, 0, NULL, "session <device>" },
        { { "session", "-t", "60", "box" }, XSTDOK, DIRECTGATE_REMOTE_SESSION, "box", NULL, NULL, 0, 60000, NULL,
            "session -t sets how long it may stay idle" },
        { { "session", "-d", "box" }, XSTDOK, DIRECTGATE_REMOTE_SESSION, "box", NULL, NULL, 0, 0, NULL, "session -d" },

        { { "cp", "a", "b" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "cp with no remote side" },
        { { "cp", "box:/a", "box:/b" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "cp with two remote sides" },
        { { "cp", "box:rel", "." }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "a relative remote path" },
        { { "cp", "box:", "." }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "a device with no path" },
        { { "cp", "box:/a" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "cp with one argument" },
        { { "cp", "box:/a", ".", "x" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "cp with three arguments" },
        { { "cp", sLongSpec, "." }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "a device name too long" },
        { { "cp", "-r", "box:/a", "." }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "cp -r is refused, not ignored" },
        { { "cp", "-j", "box:/a", "." }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "cp -j is refused" },
        { { "cp", "-t", "5", "box:/a", "." }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "cp -t is refused" },
        { { "rm", "-f", "box:/x" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "rm -f is refused" },
        { { "rm", "/x" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "rm without the device" },
        { { "rm", "box:/x", "box:/y" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "rm with two paths" },
        { { "rm", "-d", "box", "box:/x" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "-d with a file operation" },
        { { "mkdir", "-r", "box:/x" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "mkdir -r is refused" },
        { { "mv", "box:/a", "other:/b" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "mv across devices" },
        { { "mv", "box:/a", "b" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "mv to a relative target" },
        { { "mv", "-f", "box:/a", "/b" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "mv -f is refused" },
        { { "ls", "-r", "box:/x" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "ls -r is refused" },
        { { "ls", "-f" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "the device list refuses -f" },
        { { "ls", "-C", "/x" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "the device list refuses -C" },
        { { "ls", "-n", "x" }, XSTDERR, 0, NULL, NULL, NULL, 0, 0, NULL, "ls takes no -n" },
        { { "ls", "box:/x", "-j" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "options come before the operands" },
        { { "exec", "box" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "exec without a command" },
        { { "exec" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "exec without a device" },
        { { "exec", "box", "--" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "exec with only --" },
        { { "exec", "-C", "rel", "box", "ls" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "exec -C relative" },
        { { "exec", "-f", "box", "ls" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "exec -f is refused" },
        { { "exec", "-j", "box", "ls" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "exec -j is refused" },
        { { "exec", "-r", "box", "ls" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "exec -r is refused" },
        { { "exec", "-n", "name", "box", "ls" }, XSTDERR, 0, NULL, NULL, NULL, 0, 0, NULL, "exec takes no -n" },
        { { "exec", "-p", "list", "box", "ls" }, XSTDERR, 0, NULL, NULL, NULL, 0, 0, NULL, "exec takes no -p" },
        { { "exec", "-t", "x", "box", "ls" }, XSTDERR, 0, NULL, NULL, NULL, 0, 0, NULL, "exec -t not a number" },
        { { "exec", "-t", "4294968", "box", "ls" }, XSTDERR, 0, NULL, NULL, NULL, 0, 0, NULL, "exec -t too large" },
        { { "exec", "-o", "x", "box", "ls" }, XSTDERR, 0, NULL, NULL, NULL, 0, 0, NULL, "exec -o not a number" },
        { { "session" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "session without a device" },
        { { "session", "box", "ls" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "session takes nothing after the device" },
        { { "session", "-t", "601", "box" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "session -t past ten minutes" },
        { { "session", "-C", "/x", "box" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "session -C is refused" },
        { { "session", "-o", "1", "box" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "session -o is refused" },
        { { "session", "-f", "box" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "session -f is refused" },
        { { "cp", "-o", "1", "box:/a", "." }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "cp -o is refused" },
        { { "exec", "-o", "", "box", "ls" }, XSTDERR, 0, NULL, NULL, NULL, 0, 0, NULL, "exec -o empty" },
        { { "exec", "-o", "-1", "box", "ls" }, XSTDERR, 0, NULL, NULL, NULL, 0, 0, NULL, "exec -o negative" },
        { { "exec", "-o", "+5", "box", "ls" }, XSTDERR, 0, NULL, NULL, NULL, 0, 0, NULL, "exec -o with a sign" },
        { { "exec", "-o", " 5", "box", "ls" }, XSTDERR, 0, NULL, NULL, NULL, 0, 0, NULL, "exec -o with a space" },
        { { "exec", "-o", "1.5K", "box", "ls" }, XSTDERR, 0, NULL, NULL, NULL, 0, 0, NULL, "exec -o not whole" },
        { { "exec", "-o", "5KB", "box", "ls" }, XSTDERR, 0, NULL, NULL, NULL, 0, 0, NULL, "exec -o with more after K" },
        { { "exec", "-o", "5T", "box", "ls" }, XSTDERR, 0, NULL, NULL, NULL, 0, 0, NULL, "exec -o with an unknown suffix" },
        { { "exec", "-o", "4294967296", "box", "ls" }, XSTDERR, 0, NULL, NULL, NULL, 0, 0, NULL, "exec -o past 32 bits" },
        { { "exec", "-o", "4G", "box", "ls" }, XSTDERR, 0, NULL, NULL, NULL, 0, 0, NULL, "exec -o 4G is past 32 bits" },
        { { "exec", "-o", "99999999999999999999", "box", "ls" }, XSTDERR, 0, NULL, NULL, NULL, 0, 0, NULL,
            "exec -o past 64 bits" },
        { { "cp", "-o", "1K", "box:/a", "." }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "cp -o is refused" },
        { { "ls", "-o", "1K", "box:/x" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "ls -o is refused" },
        { { "ls", "-o", "1K" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "the device list refuses -o" },
        { { "rm", "-o", "0", "box:/x" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL, "rm -o 0 is refused, not taken as unset" },
        { { "ls", "-c", "/nonexistent", "box:/x" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL,
            "a second -c is refused, not ignored" },
        { { "ls", "-fc", "/nonexistent" }, XSTDEXC, 0, NULL, NULL, NULL, 0, 0, NULL,
            "a -c the config scan cannot see is refused, not ignored" },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        if (!remote_case(pConfig, &cases[i])) return 0;

    return 1;
}

/* exec -o <value>: what it parses into */
static int output_cases(const char *pConfig)
{
    const struct { const char *pValue; uint32_t nBytes; const char *pWhat; } cases[] = {
        { "131073", 131073, "exec -o in bytes" },
        { "0", 0, "exec -o 0 keeps no output, which is not the same as no limit" },
        { "64K", 65536, "exec -o with K" },
        { "2m", 2097152, "exec -o with m" },
        { "3G", 3221225472U, "exec -o with G" },
        { "1M", 1048576, "exec -o with M" },
        { "1g", 1073741824, "exec -o with g" },
        { "4294967295", 4294967295U, "exec -o at the largest" },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        char *pArgv[] = { (char*)"dgcli", (char*)"exec", (char*)"-c", (char*)pConfig, (char*)"-o", (char*)cases[i].pValue,
                          (char*)"box", (char*)"ls", NULL };

        directgate_cfg_t cfg;
        getopt_restart();
        XSTATUS nStatus = DirectGate_ParseArgs(&cfg, 8, pArgv);
        int bPass = nStatus == XSTDOK && cfg.remote.eOp == DIRECTGATE_REMOTE_EXEC && cfg.remote.bOutputMax &&
            cfg.remote.nOutputMax == cases[i].nBytes && xstrcmp(cfg.remote.pCommand, "ls");

        if (!bPass) fprintf(stderr, "client_config_smoke: %s (status %d)\n", cases[i].pWhat, (int)nStatus);
        DirectGate_Remote_ReqClear(&cfg.remote);
        if (!bPass) return 0;
    }

    /* Joined to its option, as getopt allows */
    char *pJoined[] = { (char*)"dgcli", (char*)"exec", (char*)"-c", (char*)pConfig, (char*)"-o1k", (char*)"box", (char*)"ls",
                        NULL };
    directgate_cfg_t cfg;
    getopt_restart();
    XSTATUS nStatus = DirectGate_ParseArgs(&cfg, 7, pJoined);
    int bPass = nStatus == XSTDOK && cfg.remote.bOutputMax && cfg.remote.nOutputMax == 1024;
    DirectGate_Remote_ReqClear(&cfg.remote);
    if (!bPass)
    {
        fprintf(stderr, "client_config_smoke: exec -o joined to its value (status %d)\n", (int)nStatus);
        return 0;
    }

    /* The config scan steps over -o's value: a -c after it is the config, not an operand's */
    char *pBefore[] = { (char*)"dgcli", (char*)"exec", (char*)"-o", (char*)"1K", (char*)"-c", (char*)pConfig, (char*)"box",
                        (char*)"ls", NULL };
    getopt_restart();
    nStatus = DirectGate_ParseArgs(&cfg, 8, pBefore);
    bPass = nStatus == XSTDOK && cfg.remote.bOutputMax && cfg.remote.nOutputMax == 1024 && xstrcmp(cfg.sCfgPath, pConfig);
    DirectGate_Remote_ReqClear(&cfg.remote);
    if (!bPass) fprintf(stderr, "client_config_smoke: a -c after exec -o's value is the config (status %d)\n", (int)nStatus);
    return bPass;
}

/* ---- a session's requests: one JSON line each, the words of a one-shot operation on the session's device ---- */

typedef struct {
    const char *pLine;
    XSTATUS nStatus;
    directgate_remote_op_t eOp;
    const char *pPath;          /* exec: the command */
    const char *pStdin;
    size_t nMax;
    const char *pError;         /* what the refusal says */
} request_case_t;

static int request_cases(void)
{
    const request_case_t cases[] = {
        { "{\"argv\":[\"exec\",\"-t\",\"5\",\"-o\",\"100\",\"box\",\"echo\",\"hi\"]}", XSTDOK,
            DIRECTGATE_REMOTE_EXEC, "echo hi", "", DIRECTGATE_REMOTE_CAPTURE_MAX, NULL },
        { "{\"argv\":[\"exec\",\"box\",\"--\",\"ls\",\"-la\"]}", XSTDOK, DIRECTGATE_REMOTE_EXEC, "ls -la", "",
            DIRECTGATE_REMOTE_CAPTURE_MAX, NULL },
        { "{\"argv\":[\"exec\",\"--\",\"box\",\"ls\"]}", XSTDOK, DIRECTGATE_REMOTE_EXEC, "ls", "",
            DIRECTGATE_REMOTE_CAPTURE_MAX, NULL },
        { "{\"argv\":[\"exec\",\"box\",\"cat\"],\"stdin\":\"hello\\n\",\"max\":131073}", XSTDOK,
            DIRECTGATE_REMOTE_EXEC, "cat", "hello\n", 131073, NULL },
        { "{\"argv\":[\"ls\",\"-j\",\"box:/etc\"]}", XSTDOK, DIRECTGATE_REMOTE_LIST, "/etc", "",
            DIRECTGATE_REMOTE_CAPTURE_MAX, NULL },
        { "{\"argv\":[\"cp\",\"box:/a.txt\",\"-\"]}", XSTDOK, DIRECTGATE_REMOTE_GET, "/a.txt", "",
            DIRECTGATE_REMOTE_CAPTURE_MAX, NULL },
        { "{\"argv\":[\"cp\",\"-f\",\"-\",\"box:/tmp/x\"],\"stdin\":\"data\"}", XSTDOK, DIRECTGATE_REMOTE_PUT,
            "/tmp/x", "data", DIRECTGATE_REMOTE_CAPTURE_MAX, NULL },
        { "{\"argv\":[\"rm\",\"-r\",\"box:/tmp/d\"]}", XSTDOK, DIRECTGATE_REMOTE_REMOVE, "/tmp/d", "",
            DIRECTGATE_REMOTE_CAPTURE_MAX, NULL },
        { "{\"argv\":[\"mv\",\"box:/a\",\"/b\"]}", XSTDOK, DIRECTGATE_REMOTE_MOVE, "/a", "", DIRECTGATE_REMOTE_CAPTURE_MAX,
            NULL },

        { "not json", XSTDERR, 0, NULL, NULL, 0, "a request is one line of JSON" },
        { "{}", XSTDERR, 0, NULL, NULL, 0, "argv is a list" },
        { "{\"argv\":\"exec box ls\"}", XSTDERR, 0, NULL, NULL, 0, "argv is a list" },
        { "{\"argv\":[]}", XSTDERR, 0, NULL, NULL, 0, "argv is a list" },
        { "{\"argv\":[\"exec\",\"box\",1]}", XSTDERR, 0, NULL, NULL, 0, "every word of argv is a string" },
        { "{\"argv\":[\"login\"]}", XSTDERR, 0, NULL, NULL, 0, "the first word is the operation" },
        { "{\"argv\":[\"session\",\"box\"]}", XSTDERR, 0, NULL, NULL, 0, "the first word is the operation" },
        { "{\"argv\":[\"exec\",\"-x\",\"box\",\"ls\"]}", XSTDERR, 0, NULL, NULL, 0, "not an option" },
        { "{\"argv\":[\"exec\",\"-t\"]}", XSTDERR, 0, NULL, NULL, 0, "not an option" },
        { "{\"argv\":[\"exec\",\"-t\",\"soon\",\"box\",\"ls\"]}", XSTDERR, 0, NULL, NULL, 0, "-t takes whole seconds" },
        { "{\"argv\":[\"exec\",\"-t\",\"4294968\",\"box\",\"ls\"]}", XSTDERR, 0, NULL, NULL, 0,
            "-t takes whole seconds" },
        { "{\"argv\":[\"exec\",\"-o\",\"lots\",\"box\",\"ls\"]}", XSTDERR, 0, NULL, NULL, 0, "-o takes a number" },
        { "{\"argv\":[\"exec\",\"-f\",\"box\",\"ls\"]}", XSTDERR, 0, NULL, NULL, 0, "-f belongs to cp" },
        { "{\"argv\":[\"exec\"]}", XSTDERR, 0, NULL, NULL, 0, "a device is required" },
        { "{\"argv\":[\"exec\",\"other\",\"ls\"]}", XSTDERR, 0, NULL, NULL, 0, "a session reaches its own device only" },
        { "{\"argv\":[\"ls\",\"other:/etc\"]}", XSTDERR, 0, NULL, NULL, 0, "a session reaches its own device only" },
        { "{\"argv\":[\"ls\",\"box:etc\"]}", XSTDERR, 0, NULL, NULL, 0, "remote paths must be absolute" },
        { "{\"argv\":[\"ls\",\"box:/etc\"],\"stdin\":\"x\"}", XSTDERR, 0, NULL, NULL, 0, "stdin is a string, for exec" },
        { "{\"argv\":[\"exec\",\"box\",\"cat\"],\"stdin\":5}", XSTDERR, 0, NULL, NULL, 0, "stdin is a string" },
        { "{\"argv\":[\"exec\",\"box\",\"ls\"],\"max\":0}", XSTDERR, 0, NULL, NULL, 0, "max is a number of bytes" },
        { "{\"argv\":[\"exec\",\"box\",\"ls\"],\"max\":16777217}", XSTDERR, 0, NULL, NULL, 0, "max is a number of bytes" },
        { "{\"argv\":[\"exec\",\"box\",\"ls\"],\"max\":\"1\"}", XSTDERR, 0, NULL, NULL, 0, "max is a number of bytes" },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        const request_case_t *pCase = &cases[i];
        directgate_remote_req_t req;
        memset(&req, 0, sizeof(req));

        xbyte_buffer_t stdinData;
        XByteBuffer_Init(&stdinData, XSTDNON, XFALSE);
        char sError[XSTR_MID];
        size_t nMax = 0;

        XSTATUS nStatus = DirectGate_Remote_ParseRequest(&req, pCase->pLine, strlen(pCase->pLine), "box", &stdinData, &nMax,
            sError, sizeof(sError));

        int bPass = nStatus == pCase->nStatus;
        if (bPass && nStatus == XSTDOK)
        {
            const char *pGot = req.eOp == DIRECTGATE_REMOTE_EXEC ? req.pCommand : req.sPath;
            size_t nStdin = strlen(pCase->pStdin);
            bPass = req.eOp == pCase->eOp && pGot != NULL && strcmp(pGot, pCase->pPath) == 0 && nMax == pCase->nMax &&
                stdinData.nUsed == nStdin && (!nStdin || memcmp(stdinData.pData, pCase->pStdin, nStdin) == 0) &&
                req.bStdin == (req.eOp == DIRECTGATE_REMOTE_EXEC && nStdin ? XTRUE : XFALSE);
        }
        else if (bPass)
        {
            bPass = strstr(sError, pCase->pError) != NULL && req.pCommand == NULL && req.eOp == DIRECTGATE_REMOTE_NONE;
        }

        if (!bPass) fprintf(stderr, "client_config_smoke: request %zu: %s (status %d, said %s)\n", i, pCase->pLine,
            (int)nStatus, sError);

        XByteBuffer_Clear(&stdinData);
        DirectGate_Remote_ReqClear(&req);
        if (!bPass) return 0;
    }

    /* More words than a request may have */
    char sMany[2048];
    size_t nUsed = (size_t)snprintf(sMany, sizeof(sMany), "{\"argv\":[\"exec\",\"box\"");
    for (int i = 0; i < DIRECTGATE_REMOTE_REQUEST_WORDS; i++)
        nUsed += (size_t)snprintf(sMany + nUsed, sizeof(sMany) - nUsed, ",\"w\"");
    snprintf(sMany + nUsed, sizeof(sMany) - nUsed, "]}");

    directgate_remote_req_t req;
    memset(&req, 0, sizeof(req));
    xbyte_buffer_t stdinData;
    XByteBuffer_Init(&stdinData, XSTDNON, XFALSE);
    char sError[XSTR_MID];
    size_t nMax = 0;
    XSTATUS nStatus = DirectGate_Remote_ParseRequest(&req, sMany, strlen(sMany), "box", &stdinData, &nMax, sError,
        sizeof(sError));
    XByteBuffer_Clear(&stdinData);
    DirectGate_Remote_ReqClear(&req);
    if (nStatus != XSTDERR || strstr(sError, "up to 64 words") == NULL)
    {
        fprintf(stderr, "client_config_smoke: a request of too many words is refused\n");
        return 0;
    }

    return DirectGate_Remote_ParseRequest(NULL, "{}", 2, "box", &stdinData, &nMax, sError, sizeof(sError)) == XSTDINV;
}

/* The answer: a JSON line, then stdout's bytes, then stderr's */
static int response_cases(void)
{
    char sPath[] = "/tmp/directgate_response.XXXXXX";
    int nFd = mkstemp(sPath);
    if (nFd < 0) return 0;
    unlink(sPath);

    xbyte_buffer_t out, err;
    XByteBuffer_Init(&out, XSTDNON, XFALSE);
    XByteBuffer_Init(&err, XSTDNON, XFALSE);
    XByteBuffer_Add(&out, (const uint8_t*)"a\0b", 3);
    XByteBuffer_Add(&err, (const uint8_t*)"warn\n", 5);

    int bOk = DirectGate_Remote_WriteResponse(nFd, 7, &out, &err, XTRUE) == XSTDOK &&
              DirectGate_Remote_WriteResponse(nFd, 0, NULL, NULL, XFALSE) == XSTDOK;

    char sGot[256] = {0};
    ssize_t nGot = bOk ? pread(nFd, sGot, sizeof(sGot) - 1, 0) : -1;
    const char *pFirst = "{\"exitCode\":7,\"stdout\":3,\"stderr\":5,\"truncated\":true}\n";
    const char *pSecond = "{\"exitCode\":0,\"stdout\":0,\"stderr\":0,\"truncated\":false}\n";
    size_t nFirst = strlen(pFirst), nSecond = strlen(pSecond);

    char sWant[256];
    memcpy(sWant, pFirst, nFirst);
    memcpy(sWant + nFirst, "a\0bwarn\n", 8);
    memcpy(sWant + nFirst + 8, pSecond, nSecond);
    size_t nWant = nFirst + 8 + nSecond;
    bOk = bOk && nGot == (ssize_t)nWant && memcmp(sGot, sWant, nWant) == 0;

    bOk = bOk && DirectGate_Remote_WriteResponse(-1, 0, NULL, NULL, XFALSE) == XSTDERR;
    close(nFd);
    XByteBuffer_Clear(&out);
    XByteBuffer_Clear(&err);
    return bOk;
}

int main(void)
{
    DirectGate_InitConfig(NULL);

    directgate_cfg_t cfg;
    DirectGate_InitConfig(&cfg);
    CHECK(cfg.nVerbose == XSTDNON, "default verbose");
    CHECK(cfg.bSaveDevice == XFALSE && cfg.bForce == XFALSE && cfg.bInit == XFALSE,
        "default flags");
    CHECK(cfg.log.bToScreen == XTRUE, "client logs to screen by default");
    CHECK(xstrused(cfg.sCfgPath) && xstrused(cfg.sDeviceList), "default paths");
    /* The leading verb selects the command; everything else is a device name,
       so a verb that is not one must not swallow the argument. */
    directgate_cmd_t eCommand = (directgate_cmd_t)0xFF;
    CHECK(DirectGate_ParseCommand("login", &eCommand) && eCommand == DIRECTGATE_CMD_LOGIN,
        "login selects the login command");
    CHECK(DirectGate_ParseCommand("logout", &eCommand) && eCommand == DIRECTGATE_CMD_LOGOUT,
        "logout selects the logout command");
    CHECK(DirectGate_ParseCommand("devices", &eCommand) && eCommand == DIRECTGATE_CMD_DEVICES,
        "devices selects the device list command");
    CHECK(DirectGate_ParseCommand("ls", &eCommand) && eCommand == DIRECTGATE_CMD_DEVICES,
        "ls is an alias for the device list command");
    CHECK(DirectGate_ParseCommand("whoami", &eCommand) && eCommand == DIRECTGATE_CMD_WHOAMI,
        "whoami selects the identity command");

    eCommand = DIRECTGATE_CMD_WHOAMI;
    CHECK(!DirectGate_ParseCommand("Login", &eCommand),
        "a differently-cased verb is a device name, not a command");
    CHECK(!DirectGate_ParseCommand("laptop", &eCommand),
        "a device name is not a command");
    CHECK(!DirectGate_ParseCommand("", &eCommand), "an empty argument is not a command");
    CHECK(!DirectGate_ParseCommand(NULL, &eCommand), "a missing argument is not a command");
    CHECK(!DirectGate_ParseCommand("login", NULL), "a missing output is refused");
    CHECK(eCommand == DIRECTGATE_CMD_WHOAMI,
        "an argument that is not a command leaves the selected one alone");

    /* The environment overrides the config file but not the command line, and
       an empty variable is not an override. */
    directgate_cfg_t envCfg;
    DirectGate_InitConfig(&envCfg);
    xstrncpy(envCfg.sApiUrl, sizeof(envCfg.sApiUrl), "https://from-config.example.test");
    xstrncpy(envCfg.sWebUrl, sizeof(envCfg.sWebUrl), "https://web-from-config.example.test");

    unsetenv("DIRECTGATE_API_URL");
    unsetenv("DIRECTGATE_WEB_URL");
    DirectGate_ApplyEnvConfig(&envCfg);
    CHECK(strcmp(envCfg.sApiUrl, "https://from-config.example.test") == 0,
        "an unset variable leaves the configured API URL alone");

    setenv("DIRECTGATE_API_URL", "", 1);
    DirectGate_ApplyEnvConfig(&envCfg);
    CHECK(strcmp(envCfg.sApiUrl, "https://from-config.example.test") == 0,
        "an empty variable is not an override");

    setenv("DIRECTGATE_API_URL", "https://from-env.example.test", 1);
    setenv("DIRECTGATE_WEB_URL", "https://web-from-env.example.test", 1);
    DirectGate_ApplyEnvConfig(&envCfg);
    CHECK(strcmp(envCfg.sApiUrl, "https://from-env.example.test") == 0,
        "the environment overrides the configured API URL");
    CHECK(strcmp(envCfg.sWebUrl, "https://web-from-env.example.test") == 0,
        "the environment overrides the configured web URL");

    unsetenv("DIRECTGATE_API_URL");
    unsetenv("DIRECTGATE_WEB_URL");
    DirectGate_ApplyEnvConfig(NULL);

    CHECK(!DirectGate_LoadConfig(NULL, "unused"), "load NULL config");
    CHECK(!DirectGate_LoadConfig(&cfg, NULL), "load NULL path");
    CHECK(!DirectGate_LoadConfig(&cfg, ""), "load empty path");

    char sRoot[] = "/tmp/directgate_client_cfg.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "mkdtemp");
    char sValid[XPATH_MAX];
    char sMalformed[XPATH_MAX];
    char sMissing[XPATH_MAX];
    char sDevices[XPATH_MAX];
    snprintf(sValid, sizeof(sValid), "%s/valid.json", sRoot);
    snprintf(sMalformed, sizeof(sMalformed), "%s/malformed.json", sRoot);
    snprintf(sMissing, sizeof(sMissing), "%s/missing.json", sRoot);
    snprintf(sDevices, sizeof(sDevices), "%s/devices", sRoot);

    const char *pValid =
        "{"
        "\"deviceList\":\"/tmp/devices\","
        "\"signalingUrl\":\"wss://relay.example.test/ws\","
        "\"routingKey\":\"route\","
        "\"accessToken\":\"access\","
        "\"apiUrl\":\"https://api.example.test\","
        "\"apiToken\":\"api-token\","
        "\"iceServers\":[\"turn:one.example.test\",\"stun:two.example.test\"],"
        "\"log\":{\"toScreen\":false,\"toFile\":false,\"flush\":false,"
                  "\"logRTC\":true,\"path\":\"/tmp/logs\",\"ident\":\"client-test\","
                  "\"levels\":[\"error\",\"debug\"]},"
        "\"auth\":{\"srp\":{\"salt\":\"00112233445566778899aabbccddeeff\","
                          "\"verifier\":\"abc123\",\"suite\":7}}"
        "}";
    CHECK(write_text(sValid, pValid), "write valid config");
    CHECK(DirectGate_LoadConfig(&cfg, sValid), "load valid config");
    CHECK(strcmp(cfg.sDeviceList, "/tmp/devices") == 0, "device list");
    CHECK(strcmp(cfg.sSignalingUrl, "wss://relay.example.test/ws") == 0,
        "signaling URL");
    CHECK(strcmp(cfg.sRoutingKey, "route") == 0 &&
          strcmp(cfg.sAccessToken, "access") == 0, "relay credentials");
    CHECK(strcmp(cfg.sApiUrl, "https://api.example.test") == 0 &&
          strcmp(cfg.sApiToken, "api-token") == 0, "API credentials");
    CHECK(cfg.nIceSrvCount == 2 &&
          strcmp(cfg.sIceServers[0], "turn:one.example.test") == 0,
        "ICE servers");
    CHECK(cfg.log.bToScreen == XFALSE && cfg.log.bToFile == XFALSE &&
          cfg.log.bFlush == XFALSE && cfg.log.bLogRTC == XTRUE, "log booleans");
    CHECK(strcmp(cfg.log.sPath, "/tmp/logs") == 0 &&
          strcmp(cfg.log.sIdent, "client-test") == 0, "log strings");
    CHECK((cfg.log.nFlags & XLOG_ERROR) && (cfg.log.nFlags & XLOG_DEBUG),
        "log levels");
    CHECK(strcmp(cfg.auth.sSaltHex, "00112233445566778899aabbccddeeff") == 0 &&
          strcmp(cfg.auth.sVerifierHex, "abc123") == 0 && cfg.auth.nSuite == 7,
        "auth fields");

    CHECK(write_text(sMalformed, "{\"signalingUrl\":}"), "write malformed config");
    CHECK(!DirectGate_LoadConfig(&cfg, sMalformed), "reject malformed config");
    CHECK(!DirectGate_LoadConfig(&cfg, sMissing), "reject missing config");

    CHECK(write_text(sMalformed, "{}"), "write empty config");
    CHECK(DirectGate_LoadConfig(&cfg, sMalformed), "load empty config");
    CHECK(strcmp(cfg.sSignalingUrl, "wss://relay.example.test/ws") == 0,
        "missing fields preserve current values");

    char *saveArgs[] = {
        (char*)"directgate",
        (char*)"-w", (char*)"wss://cli.example.test/ws",
        (char*)"-d", (char*)"cli-device-id",
        (char*)"-n", (char*)"cli-device",
        (char*)"-p", sDevices,
        (char*)"-l", sRoot,
        (char*)"-v", (char*)"5",
        (char*)"-s",
        (char*)"-f"
    };
    CHECK(DirectGate_ParseArgs(&cfg, (int)(sizeof(saveArgs) / sizeof(saveArgs[0])),
        saveArgs) == XSTDNON, "parse save-device CLI path");
    CHECK(cfg.bSaveDevice == XTRUE && cfg.bForce == XTRUE && cfg.nVerbose == 5,
        "CLI flags");
    CHECK(strcmp(cfg.sSignalingUrl, "wss://cli.example.test/ws") == 0 &&
          strcmp(cfg.sDeviceId, "cli-device-id") == 0 &&
          strcmp(cfg.sDeviceName, "cli-device") == 0, "CLI values");

    FILE *pDevices = fopen(sDevices, "rb");
    CHECK(pDevices != NULL, "CLI device list created");
    char sLine[128];
    CHECK(fgets(sLine, sizeof(sLine), pDevices) != NULL &&
          strstr(sLine, "cli-device") != NULL &&
          strstr(sLine, "cli-device-id") != NULL, "CLI device list content");
    CHECK(fclose(pDevices) == 0, "close CLI device list");

    /* -n connects to the device the list names, and a name the list does not
       hold is matched against the account's devices like any other name. */
    char *byNameArgs[] = { (char*)"directgate", (char*)"-p", sDevices, (char*)"-n", (char*)"cli-device" };
    CHECK(DirectGate_ParseArgs(&cfg, 5, byNameArgs) == XSTDOK, "parse a connection by saved name");
    CHECK(strcmp(cfg.sDeviceQuery, "cli-device-id") == 0, "a saved name connects to the id the list holds for it");

    char *unlistedArgs[] = { (char*)"directgate", (char*)"-p", sDevices, (char*)"-n", (char*)"Test Box" };
    CHECK(DirectGate_ParseArgs(&cfg, 5, unlistedArgs) == XSTDOK, "parse a connection by an unlisted name");
    CHECK(strcmp(cfg.sDeviceQuery, "Test Box") == 0, "an unlisted name is looked for among the account's devices");

    char *positionalArgs[] = { (char*)"directgate", (char*)"-p", sDevices, (char*)"-n", (char*)"cli-device", (char*)"other" };
    CHECK(DirectGate_ParseArgs(&cfg, 6, positionalArgs) == XSTDOK, "parse a named device and a positional one");
    CHECK(strcmp(cfg.sDeviceQuery, "other") == 0, "a device given after the options wins over -n");

    char *helpArgs[] = { (char*)"directgate", (char*)"-h" };
    CHECK(DirectGate_ParseArgs(&cfg, 2, helpArgs) == XSTDERR, "CLI help status");

    /* A config that does not load is a failure the caller exits on, not a
       finished command: it used to come back as XSTDNON and dgcli exited 0. */
    char *missingArgs[] = { (char*)"directgate", (char*)"-c", (char*)"/nonexistent/dgcli.json", (char*)"devices" };
    CHECK(DirectGate_ParseArgs(&cfg, 4, missingArgs) == XSTDEXC, "a missing config is reported as a failure");

    /* Only -i may name a config that is not there yet. The letters of an option's value are not
       options: an 'i' in a device name does not excuse a config that is missing. */
    char *valueArgs[] = { (char*)"directgate", (char*)"-c", (char*)"/nonexistent/dgcli.json", (char*)"-ninky" };
    CHECK(DirectGate_ParseArgs(&cfg, 4, valueArgs) == XSTDEXC, "an 'i' inside a value does not pass for -i");
    char *spacedArgs[] = { (char*)"directgate", (char*)"-n", (char*)"-i", (char*)"-c", (char*)"/nonexistent/dgcli.json" };
    CHECK(DirectGate_ParseArgs(&cfg, 5, spacedArgs) == XSTDEXC, "a value that looks like -i does not pass for -i");

    CHECK(write_text(sMalformed, "{\"apiUrl\":"), "write a truncated config");
    char *malformedArgs[] = { (char*)"directgate", (char*)"-c", sMalformed, (char*)"devices" };
    CHECK(DirectGate_ParseArgs(&cfg, 4, malformedArgs) == XSTDEXC, "a malformed config is reported as a failure");

    /* Saving a device into a list that cannot be written fails the same way. */
    char *badSaveArgs[] = {
        (char*)"directgate", (char*)"-d", (char*)"cli-device-id", (char*)"-n", (char*)"cli-device",
        (char*)"-p", (char*)"/proc/directgate-no-such-dir/devices", (char*)"-s"
    };
    CHECK(DirectGate_ParseArgs(&cfg, 8, badSaveArgs) == XSTDEXC, "a device list that cannot be written is a failure");

    CHECK(remote_cases(sValid), "remote operations parse as documented");
    CHECK(output_cases(sValid), "exec -o parses as documented");
    CHECK(request_cases(), "session requests parse as documented");
    CHECK(response_cases(), "session answers are written as documented");

    CHECK(unlink(sValid) == 0, "unlink valid");
    CHECK(unlink(sMalformed) == 0, "unlink malformed");
    CHECK(unlink(sDevices) == 0, "unlink devices");
    CHECK(rmdir(sRoot) == 0, "rmdir root");

    puts("client_config_smoke: OK");
    return 0;
}
