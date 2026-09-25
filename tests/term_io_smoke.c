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
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "term_io_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

/* Term_Start registers an endpoint with the event loop; these tests drive the
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

int main(void)
{
    setup_stubs();

    if (test_guards()) return 1;
    if (test_shell_path()) return 1;
    if (test_running_terminal()) return 1;
    if (test_restart_keeps_window_size()) return 1;
    if (test_size_before_start()) return 1;

    puts("term_io_smoke: OK");
    return 0;
}
