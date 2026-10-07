/*!
 * @file directgate-agent/tests/term_io_smoke.c
 * @brief PTY lifecycle and I/O against a real shell.
 *
 * The terminal is the oldest surface in the agent and the one whose failures
 * are quietest: a write that goes nowhere, a window size that never reaches
 * the shell, an fd or a child left behind when a session ends. Every case here
 * runs a real PTY with a real child, because none of those show up against a
 * mocked one.
 *
 * The child is /bin/sh through the ordinary spawn path, and every test reaps
 * it before returning so a failure cannot leave a shell on the runner.
 */

#include "src/agent/term.c"

#include <pwd.h>
#include <pty.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "term_io_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

/* The session registers the PTY with the event loop; these tests drive the
 * terminal directly, so the api and websocket sides are inert stand-ins. */
static xapi_t g_api;
static xapi_session_t g_ws;

static void setup_stubs(void)
{
    memset(&g_api, 0, sizeof(g_api));
    memset(&g_ws, 0, sizeof(g_ws));

    g_ws.eType = XAPI_EVENT;
    g_ws.eRole = XAPI_CUSTOM;
    g_ws.sock.nFD = XSOCK_INVALID;
}

static const char* current_user(void)
{
    struct passwd *pSelf = getpwuid(getuid());
    return (pSelf != NULL && xstrused(pSelf->pw_name)) ? pSelf->pw_name : NULL;
}

/* Reads the PTY master until it sees pNeedle or runs out of patience. The
 * shell echoes and prompts on its own schedule, so this cannot be one read. */
static xbool_t wait_for_output(directgate_term_t *pTerm, const char *pNeedle, int nTries)
{
    char sSeen[4096];
    size_t nSeen = 0;

    memset(sSeen, 0, sizeof(sSeen));

    for (int i = 0; i < nTries; i++)
    {
        char sChunk[512];
        ssize_t nRead = read(pTerm->nMasterFd, sChunk, sizeof(sChunk) - 1);

        if (nRead > 0)
        {
            sChunk[nRead] = '\0';
            size_t nRoom = sizeof(sSeen) - nSeen - 1;
            size_t nCopy = (size_t)nRead < nRoom ? (size_t)nRead : nRoom;

            memcpy(sSeen + nSeen, sChunk, nCopy);
            nSeen += nCopy;
            sSeen[nSeen] = '\0';

            if (strstr(sSeen, pNeedle) != NULL) return XTRUE;
            continue;
        }

        if (nRead < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            usleep(20000);
            continue;
        }

        break;
    }

    return XFALSE;
}

/* The child chdirs to the shell home after fork returns in the parent, so the
 * directory it starts in only becomes visible once it gets there. */
static xbool_t wait_for_cwd(directgate_term_t *pTerm, const char *pExpect, int nTries)
{
    char sCwd[XPATH_MAX];

    for (int i = 0; i < nTries; i++)
    {
        if (DirectGate_Term_GetCwd(pTerm, sCwd, sizeof(sCwd)) == XSTDOK &&
            strcmp(sCwd, pExpect) == 0) return XTRUE;

        usleep(20000);
    }

    return XFALSE;
}

static int test_guards(void)
{
    directgate_term_t term;
    DirectGate_Term_Init(&term);

    CHECK(!DirectGate_Term_IsRunning(&term), "a terminal starts out not running");
    CHECK(!DirectGate_Term_IsRunning(NULL), "a missing terminal is not running");
    CHECK(term.nMasterFd == (int)XSOCK_INVALID, "a terminal starts with no PTY master");
    CHECK(term.nPid == -1, "a terminal starts with no child");

    CHECK(DirectGate_Term_Write(NULL, (const uint8_t*)"x", 1) == XSTDINV,
        "writing to a missing terminal is refused");
    CHECK(DirectGate_Term_Write(&term, (const uint8_t*)"x", 1) == XSTDERR,
        "writing to a terminal that is not running is refused");
    CHECK(term.txBuffer.nUsed == 0,
        "a refused write leaves nothing buffered for a later flush");

    CHECK(DirectGate_Term_UpdateWinSize(NULL, NULL) == XSTDINV,
        "resizing a missing terminal is refused");
    CHECK(DirectGate_Term_UpdateWinSize(&term, NULL) == XSTDINV,
        "resizing without a size is refused");

    CHECK(DirectGate_Term_GetCwd(NULL, NULL, 0) == XSTDINV,
        "reading the directory of a missing terminal is refused");

    char sCwd[XPATH_MAX];
    CHECK(DirectGate_Term_GetCwd(&term, NULL, sizeof(sCwd)) == XSTDINV,
        "reading the directory without a buffer is refused");
    CHECK(DirectGate_Term_GetCwd(&term, sCwd, 0) == XSTDINV,
        "reading the directory into a zero-sized buffer is refused");
    CHECK(DirectGate_Term_GetCwd(&term, sCwd, sizeof(sCwd)) == XSTDERR,
        "a terminal with no child has no working directory");

    /* These are reached from the event loop, which can fire during teardown. */
    CHECK(DirectGate_Term_OnRead(NULL) == XAPI_DISCONNECT,
        "a read event for a missing terminal drops the connection");
    CHECK(DirectGate_Term_OnRead(&term) == XAPI_DISCONNECT,
        "a read event for a stopped terminal drops the connection");
    CHECK(DirectGate_Term_OnWrite(NULL) == XAPI_DISCONNECT,
        "a write event for a missing terminal drops the connection");

    DirectGate_Term_DetachEvent(&term);
    DirectGate_Term_DetachEvent(NULL);
    DirectGate_Term_AttachEvent(&term, NULL);
    DirectGate_Term_RequestStop(&term);
    DirectGate_Term_RequestStop(NULL);
    DirectGate_Term_Shutdown(&term, XTRUE);
    DirectGate_Term_Shutdown(NULL, XTRUE);
    DirectGate_Term_Clear(&term);

    CHECK(!DirectGate_Term_IsRunning(&term),
        "tearing down a terminal that never ran leaves it stopped");

    return 0;
}

static int test_shell_path(void)
{
    /* The shell the child execs. An unusable SHELL must not be taken at its
     * word, or every terminal session dies at exec. */
    setenv("SHELL", "/nonexistent/shell", 1);
    const char *pShell = DirectGate_Term_GetShellPath(NULL);
    CHECK(access(pShell, X_OK) == 0, "an unusable SHELL falls back to a shell that exists");

    setenv("SHELL", "/bin/sh", 1);
    CHECK(strcmp(DirectGate_Term_GetShellPath(NULL), "/bin/sh") == 0,
        "a usable SHELL is used as given when the account names no shell");

    unsetenv("SHELL");
    pShell = DirectGate_Term_GetShellPath(NULL);
    CHECK(access(pShell, X_OK) == 0, "with no SHELL set a usable shell is still found");

    /* The account's login shell wins over the agent's own $SHELL, which after a
     * privilege drop from root names root's shell. One that refuses logins or
     * does not exist is never picked. */
    setenv("SHELL", "/nonexistent/shell", 1);
    CHECK(strcmp(DirectGate_Term_GetShellPath("/bin/sh"), "/bin/sh") == 0,
        "the account's own login shell is preferred");

    setenv("SHELL", "/bin/sh", 1);
    CHECK(strcmp(DirectGate_Term_GetShellPath("/usr/sbin/nologin"), "/bin/sh") == 0,
        "an account shell that refuses logins is not used");
    CHECK(strcmp(DirectGate_Term_GetShellPath("/bin/false"), "/bin/sh") == 0,
        "an account shell of false is not used");
    CHECK(strcmp(DirectGate_Term_GetShellPath("/nonexistent/zsh"), "/bin/sh") == 0,
        "an account shell that does not exist is not used");

    CHECK(strcmp(DirectGate_Term_GetArg0("/bin/bash"), "bash") == 0,
        "argv[0] is the shell's basename, so it starts as a login-style shell");
    CHECK(strcmp(DirectGate_Term_GetArg0("sh"), "sh") == 0,
        "a bare shell name is its own argv[0]");
    CHECK(strcmp(DirectGate_Term_GetArg0("/bin/"), "/bin/") == 0,
        "a path ending in a slash falls back to the path itself rather than an empty argv[0]");
    CHECK(strcmp(DirectGate_Term_GetArg0(NULL), "sh") == 0,
        "a missing shell path still produces a usable argv[0]");

    setenv("SHELL", "/bin/sh", 1);
    return 0;
}

static int test_running_terminal(void)
{
    const char *pUser = current_user();
    if (pUser == NULL) return 0;

    directgate_term_t term;
    DirectGate_Term_Init(&term);

    term.nSessionId = 3;
    xstrncpy(term.sShellUser, sizeof(term.sShellUser), pUser);
    xstrncpy(term.sShellHome, sizeof(term.sShellHome), "/tmp");

    CHECK(DirectGate_Term_StartNoEndpoint(&term, NULL, &g_ws) == XSTDINV,
        "starting a terminal without an event loop is refused");
    CHECK(DirectGate_Term_StartNoEndpoint(&term, &g_api, NULL) == XSTDINV,
        "starting a terminal without a transport is refused");
    CHECK(!DirectGate_Term_IsRunning(&term), "a refused start leaves the terminal stopped");

    CHECK(DirectGate_Term_StartNoEndpoint(&term, &g_api, &g_ws) == XSTDOK,
        "a terminal starts a shell");
    CHECK(DirectGate_Term_IsRunning(&term), "a started terminal reports itself running");
    CHECK(term.nMasterFd >= 0, "a started terminal holds a PTY master");
    CHECK(term.nPid > 0, "a started terminal holds its child");

    /* The master has to be non-blocking or the event loop stalls on it. */
    int nFlags = fcntl(term.nMasterFd, F_GETFL);
    CHECK(nFlags >= 0 && (nFlags & O_NONBLOCK),
        "the PTY master is non-blocking so the event loop never stalls on it");

    int nFdFlags = fcntl(term.nMasterFd, F_GETFD);
    CHECK(nFdFlags >= 0 && (nFdFlags & FD_CLOEXEC),
        "the PTY master is close-on-exec so it cannot leak into a spawned process");

    CHECK(DirectGate_Term_StartNoEndpoint(&term, &g_api, &g_ws) == XSTDOK,
        "starting an already running terminal is a no-op");
    CHECK(term.nPid > 0, "a no-op start does not replace the running child");

    /* The child's working directory is what the file manager follows. */
    char sCwd[XPATH_MAX];
    CHECK(DirectGate_Term_GetCwd(&term, sCwd, sizeof(sCwd)) == XSTDOK,
        "a running terminal reports its child's working directory");
    CHECK(sCwd[0] == '/', "the reported working directory is an absolute path");
    CHECK(wait_for_cwd(&term, "/tmp", 200),
        "the child settles in the configured shell home");

    struct winsize size;
    memset(&size, 0, sizeof(size));
    size.ws_row = 40;
    size.ws_col = 100;

    CHECK(DirectGate_Term_UpdateWinSize(&term, &size) == XSTDOK,
        "a running terminal accepts a window size");
    CHECK(term.bHaveWinSize, "the window size is recorded");

    struct winsize applied;
    memset(&applied, 0, sizeof(applied));
    CHECK(ioctl(term.nMasterFd, TIOCGWINSZ, &applied) == 0,
        "read the window size back from the PTY");
    CHECK(applied.ws_row == 40 && applied.ws_col == 100,
        "the window size reaches the PTY the shell is on");

    /* A write has to arrive at the shell, not just land in the buffer. */
    const char sCmd[] = "echo directgate-term-marker\n";
    CHECK(DirectGate_Term_Write(&term, (const uint8_t*)sCmd, sizeof(sCmd) - 1) == XSTDOK,
        "a running terminal accepts a write");
    CHECK(term.txBuffer.nUsed == 0,
        "a write that the PTY took leaves nothing buffered");
    CHECK(wait_for_output(&term, "directgate-term-marker", 200),
        "what was written reaches the shell and its output comes back");

    CHECK(DirectGate_Term_Write(&term, NULL, 4) == XSTDOK,
        "a write with no data is a no-op rather than an error");
    CHECK(DirectGate_Term_Write(&term, (const uint8_t*)"x", 0) == XSTDOK,
        "a zero-length write is a no-op rather than an error");

    pid_t nChild = term.nPid;
    DirectGate_Term_Shutdown(&term, XTRUE);

    CHECK(!DirectGate_Term_IsRunning(&term), "a shut down terminal reports itself stopped");
    CHECK(term.nMasterFd == (int)XSOCK_INVALID, "shutdown closes the PTY master");
    CHECK(term.txBuffer.nUsed == 0, "shutdown drops anything still buffered");

    /* A child that outlived its session would hold the PTY and the user's
     * login open for as long as the agent runs. The reap happens on the event
     * loop now, so drive it the way the loop would, for at most two seconds. */
    for (int nPass = 0; nPass < 200 && DirectGate_Term_ReapPending() > 0; nPass++) usleep(10000);
    CHECK(DirectGate_Term_ReapPending() == 0, "the event loop reaps every hung-up shell");
    CHECK(kill(nChild, 0) != 0 && errno == ESRCH,
        "shutdown reaps the shell rather than leaving it behind");

    DirectGate_Term_Clear(&term);
    return 0;
}

/* A shell that exits is followed by a new one on the same session. The size
 * the viewer already established has to survive that, or the replacement shell
 * comes up at the PTY default and every full-screen program draws wrong. */
static int test_restart_keeps_window_size(void)
{
    const char *pUser = current_user();
    if (pUser == NULL) return 0;

    directgate_term_t term;
    DirectGate_Term_Init(&term);

    term.nSessionId = 4;
    xstrncpy(term.sShellUser, sizeof(term.sShellUser), pUser);
    xstrncpy(term.sShellHome, sizeof(term.sShellHome), "/tmp");

    CHECK(DirectGate_Term_StartNoEndpoint(&term, &g_api, &g_ws) == XSTDOK,
        "start the first shell");

    struct winsize size;
    memset(&size, 0, sizeof(size));
    size.ws_row = 55;
    size.ws_col = 120;
    CHECK(DirectGate_Term_UpdateWinSize(&term, &size) == XSTDOK,
        "the viewer sets a window size on the first shell");

    DirectGate_Term_Shutdown(&term, XTRUE);
    CHECK(term.bHaveWinSize,
        "shutting a shell down does not forget the size the viewer established");

    CHECK(DirectGate_Term_StartNoEndpoint(&term, &g_api, &g_ws) == XSTDOK,
        "start a replacement shell on the same terminal");

    struct winsize applied;
    memset(&applied, 0, sizeof(applied));
    CHECK(ioctl(term.nMasterFd, TIOCGWINSZ, &applied) == 0,
        "read the replacement shell's window size");
    CHECK(applied.ws_row == 55 && applied.ws_col == 120,
        "the replacement shell comes up at the size the viewer already set");

    DirectGate_Term_Shutdown(&term, XTRUE);
    DirectGate_Term_Clear(&term);
    return 0;
}

/* A size that arrives before the shell is up is the size it must start at. */
static int test_size_before_start(void)
{
    const char *pUser = current_user();
    if (pUser == NULL) return 0;

    directgate_term_t term;
    DirectGate_Term_Init(&term);

    term.nSessionId = 5;
    xstrncpy(term.sShellUser, sizeof(term.sShellUser), pUser);
    xstrncpy(term.sShellHome, sizeof(term.sShellHome), "/tmp");

    struct winsize size;
    memset(&size, 0, sizeof(size));
    size.ws_row = 31;
    size.ws_col = 111;

    CHECK(DirectGate_Term_UpdateWinSize(&term, &size) == XSTDOK,
        "a window size for a terminal that has not started yet is accepted");
    CHECK(term.bHaveWinSize, "a window size that arrives early is remembered");

    CHECK(DirectGate_Term_StartNoEndpoint(&term, &g_api, &g_ws) == XSTDOK,
        "start the shell after the size was set");

    struct winsize applied;
    memset(&applied, 0, sizeof(applied));
    CHECK(ioctl(term.nMasterFd, TIOCGWINSZ, &applied) == 0,
        "read the shell's window size");
    CHECK(applied.ws_row == 31 && applied.ws_col == 111,
        "the shell comes up at the size that arrived before it started");

    DirectGate_Term_Shutdown(&term, XTRUE);
    DirectGate_Term_Clear(&term);
    return 0;
}

/* A shell that ignores the hangup is given the grace period and then killed
   with its whole process group, never left holding the PTY. */
static int test_hangup_ignored(void)
{
    const char *pUser = current_user();
    if (pUser == NULL) return 0;

    directgate_term_t term;
    DirectGate_Term_Init(&term);
    term.nSessionId = 6;
    xstrncpy(term.sShellUser, sizeof(term.sShellUser), pUser);
    xstrncpy(term.sShellHome, sizeof(term.sShellHome), "/tmp");

    CHECK(DirectGate_Term_StartNoEndpoint(&term, &g_api, &g_ws) == XSTDOK, "start a shell to ignore the hangup");
    /* sleep inherits the ignored SIGHUP and never reads the terminal, so closing it does not end it either. */
    const char sTrap[] = "trap '' HUP; echo hup-$((40+2)); exec sleep 30\n";
    CHECK(DirectGate_Term_Write(&term, (const uint8_t*)sTrap, sizeof(sTrap) - 1) == XSTDOK, "tell it to ignore SIGHUP");
    CHECK(wait_for_output(&term, "hup-42", 200), "the shell ignores SIGHUP from here on");

    pid_t nChild = term.nPid;
    uint64_t nStart = XTime_GetMonoMs();
    DirectGate_Term_Shutdown(&term, XTRUE);

    for (int nPass = 0; nPass < 300 && DirectGate_Term_ReapPending() > 0; nPass++) usleep(10000);
    CHECK(DirectGate_Term_ReapPending() == 0 && kill(nChild, 0) != 0 && errno == ESRCH,
        "a shell that ignored the hangup is killed and reaped");
    CHECK(XTime_GetMonoMs() - nStart >= DIRECTGATE_TERM_HUP_GRACE_MS, "but only once its grace period is over");

    DirectGate_Term_Clear(&term);
    return 0;
}

/* With every reap slot taken, a shell is killed at once rather than forgotten. */
static int test_reap_queue_full(void)
{
    pid_t nChild = fork();
    CHECK(nChild >= 0, "fork a stand-in shell");
    if (nChild == 0)
    {
        setpgid(0, 0);
        pause();
        _exit(0);
    }

    setpgid(nChild, nChild);
    directgate_term_reap_t saved[DIRECTGATE_TERM_REAP_SLOTS];
    memcpy(saved, g_termReap, sizeof(saved));

    /* Slots held by a pid that is not ours: waitpid() on it fails, but not before this call. */
    for (size_t i = 0; i < DIRECTGATE_TERM_REAP_SLOTS; i++)
    {
        g_termReap[i].nPid = 1;
        g_termReap[i].nKillAtMs = UINT64_MAX;
    }

    DirectGate_Term_DeferReap(nChild);
    memcpy(g_termReap, saved, sizeof(saved));

    int nStatus = 0;
    CHECK(waitpid(nChild, &nStatus, 0) == nChild || errno == ECHILD, "the stand-in shell is gone");
    CHECK(kill(nChild, 0) != 0, "a full reap queue kills the shell rather than losing it");
    return 0;
}

/* A terminal whose PTY went bad under it: every call fails cleanly. */
static int test_broken_pty(void)
{
    directgate_term_t term;
    DirectGate_Term_Init(&term);
    term.nSessionId = 7;
    term.bRunning = XTRUE;

    /* The read end of a pipe: not a terminal to size, not a file to write. */
    int fds[2];
    CHECK(pipe(fds) == 0, "create a pipe to stand in for the PTY");
    term.nMasterFd = fds[0];

    struct winsize size;
    memset(&size, 0, sizeof(size));
    size.ws_row = 24;
    size.ws_col = 80;
    CHECK(DirectGate_Term_UpdateWinSize(&term, &size) == XSTDERR, "a window size a non-terminal cannot take fails");
    CHECK(DirectGate_Term_Write(&term, (const uint8_t*)"x", 1) == XSTDERR, "a write the PTY refuses fails");
    XByteBuffer_Clear(&term.txBuffer);

    /* A master whose slave is gone reads EIO: the shell has exited. */
    int nMaster = -1, nSlave = -1;
    CHECK(openpty(&nMaster, &nSlave, NULL, NULL, NULL) == 0, "open a PTY pair");
    close(nSlave);
    term.nMasterFd = nMaster;
    CHECK(DirectGate_Term_OnRead(&term) == XAPI_DISCONNECT, "a PTY whose shell has gone ends the session");

    /* Any other read error ends it too. */
    term.nMasterFd = fds[1];
    CHECK(DirectGate_Term_OnRead(&term) == XAPI_DISCONNECT, "a PTY that cannot be read ends the session");

    /* A child that is gone has no working directory. */
    pid_t nGone = fork();
    CHECK(nGone >= 0, "fork a child that exits");
    if (nGone == 0) _exit(0);
    CHECK(waitpid(nGone, NULL, 0) == nGone, "reap it");
    term.nPid = nGone;
    char sCwd[XPATH_MAX];
    CHECK(DirectGate_Term_GetCwd(&term, sCwd, sizeof(sCwd)) == XSTDERR && sCwd[0] == '\0', "a gone child has no cwd");

    /* Paused reading on a terminal that stopped is simply unpaused. */
    term.bRunning = XFALSE;
    term.bReadPaused = XTRUE;
    DirectGate_Term_ResumeRead(&term);
    CHECK(!term.bReadPaused, "a stopped terminal is not left paused");

    close(fds[0]);
    close(fds[1]);
    close(nMaster);
    term.nMasterFd = (int)XSOCK_INVALID;
    term.nPid = 0;
    DirectGate_Term_Clear(&term);
    return 0;
}

/* Reaps what a test shut down, the way the event loop would, for at most two seconds. */
static xbool_t reap_shell(pid_t nChild)
{
    for (int nPass = 0; nPass < 200 && DirectGate_Term_ReapPending() > 0; nPass++) usleep(10000);
    return DirectGate_Term_ReapPending() == 0 && kill(nChild, 0) != 0 && errno == ESRCH;
}

/* A configured shell user the agent cannot become: the shell does not start as
 * the agent's own account instead, and the terminal says why it closed. */
static int test_switch_user_refused(void)
{
    struct passwd *pRoot = getpwuid(0);
    if (geteuid() == 0 || pRoot == NULL || !xstrused(pRoot->pw_name)) return 0;

    directgate_term_t term;
    DirectGate_Term_Init(&term);
    term.nSessionId = 9;
    xstrncpy(term.sShellUser, sizeof(term.sShellUser), pRoot->pw_name);
    xstrncpy(term.sShellHome, sizeof(term.sShellHome), "/");

    CHECK(DirectGate_Term_StartNoEndpoint(&term, &g_api, &g_ws) == XSTDOK, "a terminal for another account forks its child");
    CHECK(wait_for_output(&term, "cannot switch to the configured shell user", 200),
        "a child that cannot become the shell user says so and runs no shell");

    pid_t nChild = term.nPid;
    DirectGate_Term_Shutdown(&term, XTRUE);
    CHECK(reap_shell(nChild), "the refused child is reaped");
    DirectGate_Term_Clear(&term);
    return 0;
}

/* A spawn with no descriptor or no process to spare fails before anything is
 * left running. Limits only bind a process that is not root, and they cannot be
 * undone, so the checks run in a child. */
static int spawn_limited(int nResource, rlim_t nLimit)
{
    struct rlimit saved, limit;
    if (getrlimit(nResource, &saved) != 0) return 2;
    limit = saved;
    limit.rlim_cur = nLimit;
    if (setrlimit(nResource, &limit) != 0) return 2;

    directgate_term_t term;
    DirectGate_Term_Init(&term);
    XSTATUS nStatus = DirectGate_Term_StartNoEndpoint(&term, &g_api, &g_ws);
    xbool_t bRefused = nStatus == XSTDERR && !DirectGate_Term_IsRunning(&term) && term.nPid <= 0;
    DirectGate_Term_Clear(&term);

    /* The soft limit goes back so the child can still write what it has to on exit */
    (void)setrlimit(nResource, &saved);
    return bRefused ? 0 : 1;
}

/* A stop asked for before the event loop took the terminal on is a shutdown on the spot */
static int test_stop_without_event(void)
{
    const char *pUser = current_user();
    if (pUser == NULL) return 0;

    directgate_term_t term;
    DirectGate_Term_Init(&term);
    term.nSessionId = 10;
    xstrncpy(term.sShellUser, sizeof(term.sShellUser), pUser);

    CHECK(DirectGate_Term_StartNoEndpoint(&term, &g_api, &g_ws) == XSTDOK, "start a shell with no event registered");
    pid_t nChild = term.nPid;
    DirectGate_Term_RequestStop(&term);
    CHECK(!DirectGate_Term_IsRunning(&term) && term.nMasterFd == (int)XSOCK_INVALID, "a stop shuts it down at once");
    CHECK(reap_shell(nChild), "and its shell is reaped");

    DirectGate_Term_RequestStop(&term);
    DirectGate_Term_Clear(&term);
    return 0;
}

static int test_spawn_refused(void)
{
    if (geteuid() == 0) return 0;

    /* The lowest free descriptor is where the PTY would go; a limit at it leaves none. */
    int nLowest = dup(STDERR_FILENO);
    CHECK(nLowest >= 0, "find the lowest free descriptor");
    close(nLowest);

    const int resources[] = { RLIMIT_NOFILE, RLIMIT_NPROC };
    const rlim_t limits[] = { (rlim_t)nLowest, 0 };
    for (int i = 0; i < 2; i++)
    {
        /* exit(), not _exit(): a coverage build writes the child's counts at exit */
        fflush(NULL);
        pid_t nChild = fork();
        CHECK(nChild >= 0, "fork a child to limit");
        if (nChild == 0) exit(spawn_limited(resources[i], limits[i]));

        int nStatus = 0;
        CHECK(waitpid(nChild, &nStatus, 0) == nChild && WIFEXITED(nStatus), "the limited child finishes");
        CHECK(WEXITSTATUS(nStatus) != 1, i == 0 ? "a spawn without a descriptor to spare fails" :
            "a spawn without a process to spare fails");
    }

    /* A descriptor the event loop no longer owns goes back to blocking. */
    int fds[2];
    CHECK(pipe(fds) == 0, "create a pipe to switch modes on");
    CHECK(DirectGate_Term_SetNonBlock(fds[0], XTRUE) == XSTDOK && DirectGate_Term_SetNonBlock(fds[0], XFALSE) == XSTDOK &&
          !(fcntl(fds[0], F_GETFL) & O_NONBLOCK), "a descriptor is put back in blocking mode");
    close(fds[0]);
    close(fds[1]);
    CHECK(DirectGate_Term_SetNonBlock(fds[0], XTRUE) == XSTDERR, "a closed descriptor has no mode");
    return 0;
}

int main(void)
{
    setup_stubs();

    if (test_guards()) return 1;
    if (test_shell_path()) return 1;
    if (test_running_terminal()) return 1;
    if (test_restart_keeps_window_size()) return 1;
    if (test_size_before_start()) return 1;
    if (test_hangup_ignored()) return 1;
    if (test_reap_queue_full()) return 1;
    if (test_broken_pty()) return 1;
    if (test_switch_user_refused()) return 1;
    if (test_stop_without_event()) return 1;
    if (test_spawn_refused()) return 1;

    puts("term_io_smoke: OK");
    return 0;
}
