/*
 * dgcli's terminal I/O and inbound message gate, compiled straight from client.c (its main renamed away) so the
 * static handlers can be driven without a relay.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define main dgcli_main
#include "src/client/client.c"
#undef main

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "client_io_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#define WRITE_ALL_BYTES (1024 * 1024)

static int feed(directgate_ctx_t *pCli, xjson_obj_t *pHeader, const char *pPayload)
{
    if (pHeader == NULL) return -100;

    size_t nPayload = pPayload != NULL ? strlen(pPayload) : 0;
    xbyte_buffer_t wire;
    XByteBuffer_Init(&wire, XSTDNON, XFALSE);

    int nStatus = -100;
    if (DirectGate_Proto_Build(&wire, pHeader, (const uint8_t*)pPayload, nPayload, XFALSE))
        nStatus = DirectGate_Client_HandleMessage(pCli, wire.pData, wire.nUsed, "test");

    XByteBuffer_Clear(&wire);
    XJSON_FreeObject(pHeader);
    return nStatus;
}

static xbool_t pipe_is_empty(int nFd)
{
    char sByte;
    return read(nFd, &sByte, 1) < 0 && errno == EAGAIN;
}

/*
 * Before auth the relay is the only party on the line. It used to be able to write to the terminal, drop a file
 * into the working directory and tell -a the key was authorized; after auth a zero session id, or an auth message,
 * still went through in the clear.
 */
static int check_plain_gate(void)
{
    char sDir[] = "/tmp/dgcli-io-XXXXXX";
    CHECK(mkdtemp(sDir) != NULL, "temp dir");

    char sCwd[4096];
    CHECK(getcwd(sCwd, sizeof(sCwd)) != NULL, "getcwd");
    CHECK(chdir(sDir) == 0, "chdir to temp dir");

    int out[2];
    CHECK(pipe(out) == 0, "stdout pipe");
    CHECK(fcntl(out[0], F_SETFL, O_NONBLOCK) == 0, "stdout pipe non-blocking");

    fflush(stdout);
    int nSavedOut = dup(STDOUT_FILENO);
    CHECK(nSavedOut >= 0 && dup2(out[1], STDOUT_FILENO) >= 0, "redirect stdout");

    directgate_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    xstrncpy(cfg.sDeviceId, sizeof(cfg.sDeviceId), "dev-42");

    directgate_ctx_t cli;
    DirectGate_Client_Init(&cli);
    cli.pCfg = &cfg;
    cli.nSessionId = 5;
    cli.bAddKeyMode = XTRUE;

    int nFailed = 0;
    do
    {
        /* The relay's own traffic before auth still works */
        if (feed(&cli, DirectGate_Proto_BuildStatus("ready", 5), NULL) != XAPI_CONTINUE) { nFailed = 1; break; }
        if (feed(&cli, DirectGate_Proto_BuildError("busy", 0), NULL) != XAPI_CONTINUE) { nFailed = 2; break; }
        if (feed(&cli, DirectGate_Proto_BuildKeepalive("ping", 5), NULL) != XAPI_CONTINUE) { nFailed = 3; break; }

        if (feed(&cli, DirectGate_Proto_BuildData(5), "\x1b]52;c;cGF5bG9hZA==\x07") != XAPI_DISCONNECT) { nFailed = 4; break; }
        if (!pipe_is_empty(out[0])) { nFailed = 5; break; }

        if (feed(&cli, DirectGate_Proto_BuildFileStart("t1", "planted.txt", 4, 1, 4), NULL) != XAPI_DISCONNECT)
        {
            nFailed = 6;
            break;
        }

        struct stat st;
        if (stat("planted.txt", &st) == 0 || errno != ENOENT) { nFailed = 7; break; }

        if (feed(&cli, DirectGate_Proto_BuildAdmin("add-key-result", NULL, "ok", NULL, 5), NULL) != XAPI_DISCONNECT ||
            cli.bAddKeyDone)
        {
            nFailed = 8;
            break;
        }

        /* After auth only the relay's error and status notices may arrive in the clear */
        cli.bAuthDone = XTRUE;
        cli.bUseKeyAuth = XTRUE;

        if (feed(&cli, DirectGate_Proto_BuildData(0), "sid zero") != XAPI_DISCONNECT) { nFailed = 9; break; }
        if (feed(&cli, DirectGate_Proto_BuildData(5), "sid five") != XAPI_DISCONNECT) { nFailed = 10; break; }
        if (!pipe_is_empty(out[0])) { nFailed = 11; break; }

        if (feed(&cli, DirectGate_Proto_BuildAuthResult("failed", NULL, "denied", 5, XFALSE), NULL) != XAPI_DISCONNECT ||
            cli.bKeyAuthFailed)
        {
            nFailed = 12;
            break;
        }

        if (feed(&cli, DirectGate_Proto_BuildStatus("ready", 5), NULL) != XAPI_CONTINUE) { nFailed = 13; break; }
    }
    while (0);

    fflush(stdout);
    dup2(nSavedOut, STDOUT_FILENO);
    close(nSavedOut);
    close(out[0]);
    close(out[1]);

    DirectGate_Transfer_Destroy(&cli.transfer);
    DirectGate_WebRTC_Clear(&cli.webrtc);
    DirectGate_SRP_ClientCleanse(&cli.srp);
    g_bFinish = XFALSE;

    CHECK(chdir(sCwd) == 0, "restore cwd");
    rmdir(sDir);

    if (nFailed) fprintf(stderr, "client_io_smoke: plain gate step %d\n", nFailed);
    return nFailed ? 1 : 0;
}

typedef struct {
    int nFd;
    size_t nRead;
    xbool_t bIntact;
} drain_ctx_t;

static void* drain_pipe(void *pArg)
{
    drain_ctx_t *pCtx = (drain_ctx_t*)pArg;
    uint8_t sBuffer[8192];

    /* Let the writer fill the pipe and hit EAGAIN before anything drains */
    usleep(50000);

    for (;;)
    {
        ssize_t nRead = read(pCtx->nFd, sBuffer, sizeof(sBuffer));
        if (nRead <= 0) break;

        for (ssize_t i = 0; i < nRead; i++)
            if (sBuffer[i] != (uint8_t)((pCtx->nRead + (size_t)i) % 251)) pCtx->bIntact = XFALSE;

        pCtx->nRead += (size_t)nRead;
        usleep(200);
    }

    return NULL;
}

/*
 * Raw mode puts stdin in O_NONBLOCK, and a terminal's stdin and stdout share one open file description, so stdout
 * turns non-blocking with it. A write that filled the terminal used to return short and the caller took it as done:
 * the rest of the remote output was simply dropped.
 */
static int check_write_all_waits(void)
{
    int fds[2];
    CHECK(pipe(fds) == 0, "write pipe");
    CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0, "write end non-blocking");

    uint8_t *pData = (uint8_t*)malloc(WRITE_ALL_BYTES);
    CHECK(pData != NULL, "write buffer");
    for (size_t i = 0; i < WRITE_ALL_BYTES; i++) pData[i] = (uint8_t)(i % 251);

    drain_ctx_t ctx = { fds[0], 0, XTRUE };
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, drain_pipe, &ctx) == 0, "drain thread");

    ssize_t nWritten = DirectGate_Client_WriteAll(fds[1], pData, WRITE_ALL_BYTES);
    close(fds[1]);
    pthread_join(thread, NULL);
    close(fds[0]);
    free(pData);

    CHECK(nWritten == WRITE_ALL_BYTES, "a full pipe must be waited on, not truncated");
    CHECK(ctx.nRead == WRITE_ALL_BYTES, "every byte must reach the reader");
    CHECK(ctx.bIntact, "bytes must arrive in order and unchanged");
    return 0;
}

/*
 * When stdin is not a tty raw mode is never entered and stdin stays blocking. The handler used to read until
 * EAGAIN, so its second read parked the whole event loop until more input came. alarm() turns a hang into a kill.
 */
static int check_stdin_single_read(void)
{
    int fds[2];
    CHECK(pipe(fds) == 0, "stdin pipe");

    int nSavedIn = dup(STDIN_FILENO);
    CHECK(nSavedIn >= 0 && dup2(fds[0], STDIN_FILENO) >= 0, "redirect stdin");

    directgate_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    directgate_ctx_t cli;
    DirectGate_Client_Init(&cli);
    cli.pCfg = &cfg;

    xapi_session_t ws, input;
    memset(&ws, 0, sizeof(ws));
    memset(&input, 0, sizeof(input));
    ws.bHandshakeDone = XFALSE;
    input.pSessionData = &cli;
    cli.pWsSession = &ws;

    int nFailed = 0;
    alarm(10);

    do
    {
        if (write(fds[1], "typed", 5) != 5) { nFailed = 1; break; }
        if (DirectGate_Client_HandleStdin(&input) != XAPI_CONTINUE) { nFailed = 2; break; }
        if (g_bFinish) { nFailed = 3; break; }

        close(fds[1]);
        fds[1] = -1;

        if (DirectGate_Client_HandleStdin(&input) != XAPI_CONTINUE || !g_bFinish) { nFailed = 4; break; }
    }
    while (0);

    alarm(0);
    g_bFinish = XFALSE;

    dup2(nSavedIn, STDIN_FILENO);
    close(nSavedIn);
    close(fds[0]);
    if (fds[1] >= 0) close(fds[1]);

    DirectGate_Transfer_Destroy(&cli.transfer);
    DirectGate_WebRTC_Clear(&cli.webrtc);
    DirectGate_SRP_ClientCleanse(&cli.srp);

    if (nFailed) fprintf(stderr, "client_io_smoke: stdin step %d\n", nFailed);
    return nFailed ? 1 : 0;
}

int main(void)
{
    xlog_defaults();
    xlog_screen(XFALSE);

    /* The drain thread closes its end last; a racing write must fail, not kill the test */
    signal(SIGPIPE, SIG_IGN);

    if (check_plain_gate()) return 1;
    if (check_write_all_waits()) return 1;
    if (check_stdin_single_read()) return 1;

    DirectGate_WebRTC_Cleanup();
    XLog_Destroy();
    printf("client_io_smoke: ok\n");
    return 0;
}
