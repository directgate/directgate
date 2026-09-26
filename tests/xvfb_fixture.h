/*
 * A private Xvfb for tests that need a real X server.
 *
 * The binary comes from DIRECTGATE_XVFB or PATH. The server gets a display
 * number that has neither a lock nor a socket, so it can never be the display
 * of whoever runs the tests; it reports readiness through -displayfd and dies
 * with the test process (PR_SET_PDEATHSIG) if the test crashes. Starts are
 * serialized across test processes, so parallel ctest runs never collide.
 */

#ifndef DIRECTGATE_TESTS_XVFB_FIXTURE_H
#define DIRECTGATE_TESTS_XVFB_FIXTURE_H

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef XVFB_SCREEN_W
#define XVFB_SCREEN_W 1280
#define XVFB_SCREEN_H 720
#endif

typedef struct {
    pid_t nPid;
    int nDisplay;
    char sDisplay[16];
} xvfb_t;

static int find_xvfb(char *pOut, size_t nSize)
{
    const char *pEnv = getenv("DIRECTGATE_XVFB");
    if (pEnv != NULL && pEnv[0] != '\0')
    {
        snprintf(pOut, nSize, "%s", pEnv);
        return access(pOut, X_OK) == 0;
    }

    const char *pPath = getenv("PATH");
    if (pPath == NULL) return 0;

    char sPath[4096];
    snprintf(sPath, sizeof(sPath), "%s", pPath);

    for (char *pSave = NULL, *pDir = strtok_r(sPath, ":", &pSave); pDir != NULL; pDir = strtok_r(NULL, ":", &pSave))
    {
        snprintf(pOut, nSize, "%s/Xvfb", pDir);
        if (access(pOut, X_OK) == 0) return 1;
    }

    return 0;
}

/* A display number with neither a lock nor a socket: nobody else's server. */
static int free_display(int nFrom)
{
    for (int n = nFrom; n < nFrom + 100; n++)
    {
        char sLock[64], sSocket[64];
        snprintf(sLock, sizeof(sLock), "/tmp/.X%d-lock", n);
        snprintf(sSocket, sizeof(sSocket), "/tmp/.X11-unix/X%d", n);
        if (access(sLock, F_OK) != 0 && access(sSocket, F_OK) != 0) return n;
    }

    return -1;
}

/* nDepth is the screen depth; pWithout names an extension to leave out (MIT-SHM, RANDR), the
   way some remote and nested X servers come. */
static int xvfb_start_locked(xvfb_t *pX, const char *pBinary, int nDepth, const char *pWithout);

static int xvfb_start(xvfb_t *pX, const char *pBinary, int nDepth, const char *pWithout)
{
    memset(pX, 0, sizeof(*pX));

    /* Test processes running side by side must not pick the same free number: the server that loses the race
       removes the winner's socket on its way out. So the pick and the start are one step, under a lock every
       test takes. Close-on-exec keeps the server from holding it; exiting drops it, so none is left stale. */
    int nLock = open("/tmp/.directgate-xvfb.lock", O_RDWR | O_CREAT | O_CLOEXEC, 0666);
    if (nLock >= 0) (void)flock(nLock, LOCK_EX);

    int nStarted = xvfb_start_locked(pX, pBinary, nDepth, pWithout);

    if (nLock >= 0) close(nLock);
    return nStarted;
}

static int xvfb_start_locked(xvfb_t *pX, const char *pBinary, int nDepth, const char *pWithout)
{
    for (int nFrom = 90; nFrom < 400; nFrom++)
    {
        int nDisplay = free_display(nFrom);
        if (nDisplay < 0) return 0;
        nFrom = nDisplay;

        int pipeFds[2];
        if (pipe(pipeFds) != 0) return 0;

        pid_t nPid = fork();
        if (nPid < 0) return 0;

        if (nPid == 0)
        {
            /* The server must not outlive a test that crashed. */
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            close(pipeFds[0]);

            int nNull = open("/dev/null", O_RDWR);
            if (nNull >= 0)
            {
                dup2(nNull, STDIN_FILENO);
                dup2(nNull, STDOUT_FILENO);
                dup2(nNull, STDERR_FILENO);
            }

            /* DIRECTGATE_XVFB_LOG names a directory to keep each server's own log in, for a run that went wrong. */
            const char *pLogDir = getenv("DIRECTGATE_XVFB_LOG");
            if (pLogDir != NULL && pLogDir[0] != '\0')
            {
                char sLog[512];
                snprintf(sLog, sizeof(sLog), "%s/xvfb-%d-%d.log", pLogDir, nDisplay, (int)getpid());
                int nLog = open(sLog, O_WRONLY | O_CREAT | O_TRUNC, 0600);
                if (nLog >= 0) dup2(nLog, STDERR_FILENO);
            }

            char sDisplay[16], sFd[16], sScreen[32];
            snprintf(sDisplay, sizeof(sDisplay), ":%d", nDisplay);
            snprintf(sFd, sizeof(sFd), "%d", pipeFds[1]);
            snprintf(sScreen, sizeof(sScreen), "%dx%dx%d", XVFB_SCREEN_W, XVFB_SCREEN_H, nDepth);
            if (pWithout != NULL)
                execl(pBinary, "Xvfb", sDisplay, "-displayfd", sFd, "-screen", "0", sScreen,
                    "-nolisten", "tcp", "-noreset", "-extension", pWithout, (char*)NULL);
            else
                execl(pBinary, "Xvfb", sDisplay, "-displayfd", sFd, "-screen", "0", sScreen,
                    "-nolisten", "tcp", "-noreset", (char*)NULL);
            _exit(127);
        }

        close(pipeFds[1]);

        /* The server writes its display number once it is accepting clients. */
        char sReady[16] = { 0 };
        struct pollfd pfd = { pipeFds[0], POLLIN, 0 };
        ssize_t nRead = poll(&pfd, 1, 15000) > 0 ? read(pipeFds[0], sReady, sizeof(sReady) - 1) : -1;
        close(pipeFds[0]);

        if (nRead > 0 && atoi(sReady) == nDisplay)
        {
            pX->nPid = nPid;
            pX->nDisplay = nDisplay;
            snprintf(pX->sDisplay, sizeof(pX->sDisplay), ":%d", nDisplay);
            return 1;
        }

        /* Lost a race for that number, or the server would not start: try the next. */
        kill(nPid, SIGKILL);
        waitpid(nPid, NULL, 0);
    }

    return 0;
}

static void xvfb_stop(xvfb_t *pX)
{
    if (pX->nPid <= 0) return;
    kill(pX->nPid, SIGTERM);
    waitpid(pX->nPid, NULL, 0);
    pX->nPid = 0;
}

#endif /* DIRECTGATE_TESTS_XVFB_FIXTURE_H */
