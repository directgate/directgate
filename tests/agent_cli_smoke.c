/*
 * The agent's own command line, end to end: pairing a device (-e), setting its
 * password (-s) and rotating its identity (-r), each run the way an operator
 * runs it - the real binary on a pseudo terminal, answering its prompts -
 * against an enrollment API played by this test over real TLS.
 *
 * Each is judged by what reaches the API, what the config file holds after,
 * and how the process exits: a pairing writes the tokens, the relay, a fresh
 * identity and the password verifier, and never the pairing token or the
 * password; a mistyped confirmation, a refused pairing token, a refused
 * rotation and a rotation with nothing to rotate against all fail loudly and
 * leave the config as it was.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>

#include "src/common/common.h"
#include "src/common/keyauth.h"

#include "tls_fixture.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "agent_cli_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#define CLI_DEVICE_ID     "dev-agent-cli"
#define CLI_PAIRING_TOKEN "pairing-token-7f3a"
#define CLI_PASSWORD      "agent cli password"
#define CLI_ROUTING_KEY   "rk-agent-cli-0001"
#define CLI_RELAY_URL     "wss://relay.example.test/websock"

typedef struct {
    xapi_t api;
    uint16_t nApiPort;

    /* How the API answers. */
    xatomic_t nPairCode;
    xatomic_t nRotateCode;

    /* What reached it. */
    xatomic_t bStop;
    xatomic_t nPairs;
    xatomic_t nRotations;
    xatomic_t bPairBodyOk;
    xatomic_t bRotateBodyOk;
    char sPairPub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sRotatePub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
} cli_api_t;

static cli_api_t g_api;

static uint16_t reserve_port(void)
{
    int nFd = socket(AF_INET, SOCK_STREAM, 0);
    if (nFd < 0) return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    socklen_t nLen = sizeof(addr);
    uint16_t nPort = 0;

    if (bind(nFd, (struct sockaddr*)&addr, sizeof(addr)) == 0 &&
        getsockname(nFd, (struct sockaddr*)&addr, &nLen) == 0)
        nPort = ntohs(addr.sin_port);

    close(nFd);
    return nPort;
}

/* ---- the API ------------------------------------------------------------------ */

static int api_respond(xapi_session_t *pSession, uint16_t nCode, const char *pBody)
{
    xhttp_t handle;
    if (XHTTP_InitResponse(&handle, nCode, NULL) <= 0) return XAPI_DISCONNECT;

    if (XHTTP_AddHeader(&handle, "Content-Type", "application/json") < 0 ||
        XHTTP_Assemble(&handle, (const uint8_t*)pBody, strlen(pBody)) == NULL)
    {
        XHTTP_Clear(&handle);
        return XAPI_DISCONNECT;
    }

    XByteBuffer_AddBuff(&pSession->txBuffer, &handle.rawData);
    XHTTP_Clear(&handle);
    return XAPI_EnableEvent(pSession, XPOLLOUT);
}

/* The agent's public key, as a 32-byte key in base64, or no key at all. */
static int body_pub(xjson_obj_t *pRoot, char *pOut, size_t nSize)
{
    const char *pPub = XJSON_GetString(XJSON_GetObject(pRoot, "agentPub"));
    uint8_t raw[64];
    size_t nRaw = 0;

    if (pPub == NULL || !DirectGate_KeyAuth_Base64Decode(pPub, raw, sizeof(raw), &nRaw) ||
        nRaw != DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE) return 0;

    xstrncpy(pOut, nSize, pPub);
    return 1;
}

static int api_request(xapi_session_t *pSession)
{
    xhttp_t *pHandle = (xhttp_t*)pSession->pPacket;
    if (pHandle == NULL) return XAPI_DISCONNECT;

    const char *pBody = (const char*)XHTTP_GetBody(pHandle);
    size_t nBody = XHTTP_GetBodySize(pHandle);

    xjson_t json;
    if (pBody == NULL || !nBody || !XJSON_Parse(&json, NULL, pBody, nBody))
        return api_respond(pSession, 400, "{\"message\":\"no body\"}");

    xjson_obj_t *pRoot = json.pRootObj;
    int nStatus = XAPI_DISCONNECT;

    if (strcmp(pHandle->sUri, "/api/v1/devices/pair") == 0)
    {
        XSYNC_ATOMIC_ADD(&g_api.nPairs, 1);
        const char *pDevice = XJSON_GetString(XJSON_GetObject(pRoot, "deviceId"));
        const char *pToken = XJSON_GetString(XJSON_GetObject(pRoot, "pairingToken"));
        const char *pVersion = XJSON_GetString(XJSON_GetObject(pRoot, "agentVersion"));

        if (pDevice != NULL && strcmp(pDevice, CLI_DEVICE_ID) == 0 && pToken != NULL &&
            strcmp(pToken, CLI_PAIRING_TOKEN) == 0 && pVersion != NULL && pVersion[0] &&
            body_pub(pRoot, g_api.sPairPub, sizeof(g_api.sPairPub)))
            XSYNC_ATOMIC_SET(&g_api.bPairBodyOk, 1);

        int nCode = (int)XSYNC_ATOMIC_GET(&g_api.nPairCode);
        char sReply[1024];

        if (nCode == 200)
            snprintf(sReply, sizeof(sReply),
                "{\"accessToken\":\"access-pair\",\"refreshToken\":\"refresh-pair\",\"accessTokenExpiresIn\":3600,"
                "\"enrollmentExpiresAt\":\"2099-01-01T00:00:00Z\",\"refreshTokenExpiresAt\":\"2099-01-01T00:00:00Z\","
                "\"relayUrl\":\"%s\",\"routingKey\":\"%s\","
                "\"deviceId\":\"%s\"}", CLI_RELAY_URL, CLI_ROUTING_KEY, CLI_DEVICE_ID);
        else
            snprintf(sReply, sizeof(sReply), "{\"code\":\"PAIRING_TOKEN_INVALID\",\"message\":\"that pairing token was used\"}");

        nStatus = api_respond(pSession, (uint16_t)nCode, sReply);
    }
    else if (strcmp(pHandle->sUri, "/api/v1/devices/rotate-agent-key") == 0)
    {
        XSYNC_ATOMIC_ADD(&g_api.nRotations, 1);
        const char *pRefresh = XJSON_GetString(XJSON_GetObject(pRoot, "refreshToken"));

        if (pRefresh != NULL && strcmp(pRefresh, "refresh-pair") == 0 &&
            body_pub(pRoot, g_api.sRotatePub, sizeof(g_api.sRotatePub)))
            XSYNC_ATOMIC_SET(&g_api.bRotateBodyOk, 1);

        int nCode = (int)XSYNC_ATOMIC_GET(&g_api.nRotateCode);
        nStatus = api_respond(pSession, (uint16_t)nCode, nCode == 200 ? "{\"ok\":true}" :
            "{\"code\":\"FORBIDDEN\",\"message\":\"rotation refused\"}");
    }
    else
    {
        nStatus = api_respond(pSession, 404, "{\"message\":\"not found\"}");
    }

    XJSON_Destroy(&json);
    return nStatus;
}

static int service_callback(xapi_ctx_t *pCtx, xapi_session_t *pSession)
{
    switch (pCtx->eCbType)
    {
        case XAPI_CB_ACCEPTED:
            return XAPI_SetEvents(pSession, XPOLLIN);
        case XAPI_CB_READ:
            return api_request(pSession);
        case XAPI_CB_COMPLETE:
            return XAPI_DISCONNECT;
        default:
            break;
    }

    return XAPI_CONTINUE;
}

static void* server_thread(void *pArg)
{
    (void)pArg;
    while (!XSYNC_ATOMIC_GET(&g_api.bStop)) XAPI_Service(&g_api.api, 20);
    return NULL;
}

/* ---- the operator's terminal ---------------------------------------------------- */

typedef struct {
    const char *pCert;
    int nMaster;
    pid_t nPid;
    char sScreen[32768];
    size_t nScreen;
} tty_t;

static void tty_pump(tty_t *pTty, int nWaitMs)
{
    struct pollfd pfd = { pTty->nMaster, POLLIN, 0 };
    if (pTty->nMaster < 0 || poll(&pfd, 1, nWaitMs) <= 0 || !(pfd.revents & (POLLIN | POLLHUP))) return;

    size_t nRoom = sizeof(pTty->sScreen) - 1 - pTty->nScreen;
    if (nRoom == 0) return;

    ssize_t nRead = read(pTty->nMaster, pTty->sScreen + pTty->nScreen, nRoom);
    if (nRead > 0) pTty->nScreen += (size_t)nRead;
    pTty->sScreen[pTty->nScreen] = '\0';
}

static int tty_expect(tty_t *pTty, const char *pNeedle, uint32_t nTimeoutMs)
{
    for (uint32_t nWaited = 0; nWaited < nTimeoutMs; nWaited += 20)
    {
        if (strstr(pTty->sScreen, pNeedle) != NULL) return 1;
        tty_pump(pTty, 20);
    }

    return strstr(pTty->sScreen, pNeedle) != NULL;
}

/* Waits for a prompt and answers it. */
static int tty_answer(tty_t *pTty, const char *pPrompt, const char *pAnswer)
{
    if (!tty_expect(pTty, pPrompt, 20000)) return 0;

    /* Forget the prompt, so the next one with the same words is a new one. */
    pTty->nScreen = 0;
    pTty->sScreen[0] = '\0';

    char sLine[256];
    snprintf(sLine, sizeof(sLine), "%s\n", pAnswer);
    size_t nLen = strlen(sLine);
    return write(pTty->nMaster, sLine, nLen) == (ssize_t)nLen;
}

static int tty_start(tty_t *pTty, const char *const *pArgs)
{
    pTty->nScreen = 0;
    pTty->sScreen[0] = '\0';
    pTty->nPid = forkpty(&pTty->nMaster, NULL, NULL, NULL);
    if (pTty->nPid < 0) return 0;

    if (pTty->nPid == 0)
    {
        setenv("SSL_CERT_FILE", pTty->pCert, 1);
        unsetenv("SSL_CERT_DIR");
        unsetenv("DISPLAY");
        unsetenv("WAYLAND_DISPLAY");

        char *pArgv[16];
        size_t n = 0;
        pArgv[n++] = (char*)DIRECTGATE_AGENT_BIN;
        for (size_t i = 0; pArgs[i] != NULL && n + 1 < sizeof(pArgv) / sizeof(pArgv[0]); i++) pArgv[n++] = (char*)pArgs[i];
        pArgv[n] = NULL;

        execv(DIRECTGATE_AGENT_BIN, pArgv);
        _exit(127);
    }

    return 1;
}

/* The exit code, or -1 when it did not exit in time. */
static int tty_finish(tty_t *pTty, uint32_t nTimeoutMs)
{
    int nStatus = 0;
    pid_t nDone = 0;

    for (uint32_t nWaited = 0; nWaited < nTimeoutMs && (nDone = waitpid(pTty->nPid, &nStatus, WNOHANG)) == 0; nWaited += 20)
        tty_pump(pTty, 20);

    for (int i = 0; i < 10; i++) tty_pump(pTty, 5);

    if (nDone != pTty->nPid)
    {
        kill(pTty->nPid, SIGKILL);
        waitpid(pTty->nPid, NULL, 0);
        nStatus = -1;
    }

    pTty->nPid = 0;
    close(pTty->nMaster);
    pTty->nMaster = -1;

    if (nStatus < 0 || !WIFEXITED(nStatus)) return -1;
    return WEXITSTATUS(nStatus);
}

/* ---- the config file ----------------------------------------------------------- */

static int load_text(const char *pPath, char *pOut, size_t nSize)
{
    xbyte_buffer_t buf;
    if (XPath_LoadBuffer(pPath, &buf) <= 0) return 0;

    xstrncpy(pOut, nSize, (const char*)buf.pData);
    XByteBuffer_Clear(&buf);
    return 1;
}

/* A string field anywhere in the config, by name. */
static int config_field(const char *pText, const char *pName, char *pOut, size_t nSize)
{
    char sKey[64];
    snprintf(sKey, sizeof(sKey), "\"%s\"", pName);

    const char *pAt = strstr(pText, sKey);
    if (pAt == NULL) return 0;

    pAt = strchr(pAt + strlen(sKey), '"');
    if (pAt == NULL) return 0;

    const char *pEnd = strchr(++pAt, '"');
    if (pEnd == NULL || (size_t)(pEnd - pAt) >= nSize) return 0;

    memcpy(pOut, pAt, (size_t)(pEnd - pAt));
    pOut[pEnd - pAt] = '\0';
    return 1;
}

/* The agent's identity key: "pub" inside auth.key.agentIdentity. */
static int identity_pub(const char *pText, char *pOut, size_t nSize)
{
    const char *pIdentity = strstr(pText, "\"agentIdentity\"");
    return pIdentity != NULL && config_field(pIdentity, "pub", pOut, nSize);
}

/* A config that knows only where the API is - never the built-in production
   default - and, when given, the device id. */
static int seed_config(const char *pPath, const char *pDeviceId)
{
    FILE *pFile = fopen(pPath, "w");
    if (pFile == NULL) return 0;

    fprintf(pFile, "{%s%s%s\"enrollment\":{\"apiUrl\":\"https://127.0.0.1:%u\"}}\n",
        pDeviceId != NULL ? "\"deviceId\":\"" : "", pDeviceId != NULL ? pDeviceId : "",
        pDeviceId != NULL ? "\"," : "", (unsigned)g_api.nApiPort);

    fclose(pFile);
    return chmod(pPath, 0600) == 0;
}

/* ---- scenarios -------------------------------------------------------------------- */

static int scenario_pair(tty_t *pTty, const char *pRoot, char *pCfg, size_t nCfgSize)
{
    char sText[16384], sValue[2048];

    /* A typo in the confirmation stops the pairing before the API is asked. */
    snprintf(pCfg, nCfgSize, "%s/mistyped.json", pRoot);
    CHECK(seed_config(pCfg, NULL), "seed a config that points at the test API");
    XSYNC_ATOMIC_SET(&g_api.nPairCode, 200);
    const char *mistyped[] = { "-c", pCfg, "-e", "-d", CLI_DEVICE_ID, "-t", CLI_PAIRING_TOKEN, NULL };
    CHECK(tty_start(pTty, mistyped), "start a pairing");
    CHECK(tty_answer(pTty, "Set new auth password", CLI_PASSWORD), "the pairing asks for a password");
    CHECK(tty_answer(pTty, "Repeat password", "a different password"), "the pairing asks to confirm it");
    CHECK(tty_finish(pTty, 20000) != 0, "a mistyped confirmation fails the pairing");
    CHECK(XSYNC_ATOMIC_GET(&g_api.nPairs) == 0, "a mistyped confirmation never reaches the API");
    CHECK(load_text(pCfg, sText, sizeof(sText)) && strstr(sText, "enrolled") == NULL && strstr(sText, "verifier") == NULL,
        "a mistyped confirmation leaves the config untouched");

    /* A pairing token the API refuses: the operator is told, nothing is enrolled. */
    snprintf(pCfg, nCfgSize, "%s/refused.json", pRoot);
    CHECK(seed_config(pCfg, NULL), "seed a config for the refused pairing");
    XSYNC_ATOMIC_SET(&g_api.nPairCode, 401);
    const char *refused[] = { "-c", pCfg, "-e", "-d", CLI_DEVICE_ID, "-t", CLI_PAIRING_TOKEN, NULL };
    CHECK(tty_start(pTty, refused), "start a pairing with a spent token");
    CHECK(tty_answer(pTty, "Set new auth password", CLI_PASSWORD), "the password is asked for");
    CHECK(tty_answer(pTty, "Repeat password", CLI_PASSWORD), "the password is confirmed");
    CHECK(tty_finish(pTty, 30000) != 0, "a refused pairing token fails the pairing");
    CHECK(XSYNC_ATOMIC_GET(&g_api.nPairs) == 1, "the refused pairing reached the API once");
    CHECK(strstr(pTty->sScreen, "enrollment failed") != NULL || strstr(pTty->sScreen, "Pair API") != NULL,
        "a refused pairing is reported");
    /* The password is set before the API is asked, so a retry does not ask for it again. */
    CHECK(load_text(pCfg, sText, sizeof(sText)) && strstr(sText, "refresh-pair") == NULL &&
        strstr(sText, "\"enrolled\": false") != NULL, "a refused pairing stores no tokens and enrolls nothing");
    CHECK(strstr(sText, "\"verifier\"") != NULL, "the password chosen before the refusal is kept for the retry");

    /* Everything asked for on the terminal, the pairing token without echo. */
    snprintf(pCfg, nCfgSize, "%s/agent.json", pRoot);
    CHECK(seed_config(pCfg, NULL), "seed a config for the interactive pairing");
    XSYNC_ATOMIC_SET(&g_api.nPairCode, 200);
    XSYNC_ATOMIC_SET(&g_api.nPairs, 0);
    const char *pair[] = { "-c", pCfg, "-e", NULL };
    CHECK(tty_start(pTty, pair), "start an interactive pairing");
    CHECK(tty_answer(pTty, "Device ID", CLI_DEVICE_ID), "the device id is asked for");
    CHECK(tty_answer(pTty, "Pairing token", CLI_PAIRING_TOKEN), "the pairing token is asked for");
    CHECK(tty_answer(pTty, "Set new auth password", CLI_PASSWORD), "the password is asked for");
    CHECK(tty_answer(pTty, "Repeat password", CLI_PASSWORD), "the password is confirmed");
    CHECK(tty_finish(pTty, 30000) == 0, "an accepted pairing succeeds");
    CHECK(XSYNC_ATOMIC_GET(&g_api.bPairBodyOk), "the API receives the device, the pairing token and a fresh agent key");
    CHECK(strstr(pTty->sScreen, "restart") != NULL, "the operator is told a running agent needs a restart");
    CHECK(strstr(pTty->sScreen, CLI_PAIRING_TOKEN) == NULL, "the pairing token is not echoed");

    struct stat st;
    CHECK(stat(pCfg, &st) == 0 && (st.st_mode & 0077) == 0, "the paired config is private to its owner");
    CHECK(load_text(pCfg, sText, sizeof(sText)), "the paired config loads");
    CHECK(strstr(sText, "\"enrolled\": true") != NULL, "the config says the device is enrolled");
    CHECK(config_field(sText, "relayUrl", sValue, sizeof(sValue)) && strcmp(sValue, CLI_RELAY_URL) == 0,
        "the relay the API named is stored");
    CHECK(config_field(sText, "routingKey", sValue, sizeof(sValue)) && strcmp(sValue, CLI_ROUTING_KEY) == 0,
        "the routing key the API named is stored");
    CHECK(config_field(sText, "refreshToken", sValue, sizeof(sValue)) && strcmp(sValue, "refresh-pair") == 0,
        "the refresh token is stored");
    CHECK(config_field(sText, "verifier", sValue, sizeof(sValue)) && strlen(sValue) > 64, "a password verifier is stored");
    CHECK(identity_pub(sText, sValue, sizeof(sValue)) && strcmp(sValue, g_api.sPairPub) == 0,
        "the identity the API was given is the one stored");
    CHECK(strstr(sText, CLI_PAIRING_TOKEN) == NULL, "the pairing token is not stored");
    CHECK(strstr(sText, CLI_PASSWORD) == NULL, "the password is not stored, only its verifier");
    return 0;
}

static int scenario_password(tty_t *pTty, const char *pCfg)
{
    char sBefore[16384], sAfter[16384], sOld[2048], sNew[2048], sToken[256];
    CHECK(load_text(pCfg, sBefore, sizeof(sBefore)) && config_field(sBefore, "verifier", sOld, sizeof(sOld)),
        "read the current verifier");

    /* A mistyped confirmation changes nothing. */
    const char *mistyped[] = { "-c", pCfg, "-s", NULL };
    CHECK(tty_start(pTty, mistyped), "start a password change");
    CHECK(tty_answer(pTty, "Set new auth password", "new password"), "the new password is asked for");
    CHECK(tty_answer(pTty, "Repeat password", "new passwort"), "the new password is confirmed wrongly");
    CHECK(tty_finish(pTty, 20000) != 0, "a mistyped confirmation fails the change");
    CHECK(load_text(pCfg, sAfter, sizeof(sAfter)) && config_field(sAfter, "verifier", sNew, sizeof(sNew)) &&
        strcmp(sNew, sOld) == 0, "a mistyped confirmation leaves the old password in force");

    /* A confirmed one replaces the verifier and nothing else. */
    const char *change[] = { "-c", pCfg, "-s", NULL };
    CHECK(tty_start(pTty, change), "start a second password change");
    CHECK(tty_answer(pTty, "Set new auth password", "new password"), "the new password is asked for again");
    CHECK(tty_answer(pTty, "Repeat password", "new password"), "the new password is confirmed");
    CHECK(tty_finish(pTty, 20000) == 0, "a confirmed password change succeeds");
    CHECK(load_text(pCfg, sAfter, sizeof(sAfter)) && config_field(sAfter, "verifier", sNew, sizeof(sNew)) &&
        strcmp(sNew, sOld) != 0, "the new password has a new verifier");
    CHECK(config_field(sAfter, "refreshToken", sToken, sizeof(sToken)) && strcmp(sToken, "refresh-pair") == 0,
        "changing the password keeps the enrollment");
    CHECK(strstr(sAfter, "new password") == NULL, "the new password is not stored, only its verifier");
    return 0;
}

static int scenario_rotate(tty_t *pTty, const char *pRoot, const char *pCfg)
{
    char sText[16384], sOld[256], sNew[256];
    CHECK(load_text(pCfg, sText, sizeof(sText)) && identity_pub(sText, sOld, sizeof(sOld)),
        "read the current identity");

    /* The API refuses: the old identity stays, since it is still the one on record. */
    XSYNC_ATOMIC_SET(&g_api.nRotateCode, 403);
    const char *refused[] = { "-c", pCfg, "-r", NULL };
    CHECK(tty_start(pTty, refused), "start a rotation the API refuses");
    CHECK(tty_finish(pTty, 30000) != 0, "a refused rotation fails");
    CHECK(XSYNC_ATOMIC_GET(&g_api.nRotations) == 1 && XSYNC_ATOMIC_GET(&g_api.bRotateBodyOk),
        "the rotation asked the API with the refresh token and a new key");
    CHECK(strcmp(g_api.sRotatePub, sOld) != 0, "the key offered is a new one");
    CHECK(load_text(pCfg, sText, sizeof(sText)) && identity_pub(sText, sNew, sizeof(sNew)) &&
        strcmp(sNew, sOld) == 0, "a refused rotation keeps the identity on record");

    /* Accepted: the new identity is the one offered, and it is stored. */
    XSYNC_ATOMIC_SET(&g_api.nRotateCode, 200);
    const char *rotate[] = { "-c", pCfg, "-r", NULL };
    CHECK(tty_start(pTty, rotate), "start a rotation");
    CHECK(tty_finish(pTty, 30000) == 0, "an accepted rotation succeeds");
    CHECK(load_text(pCfg, sText, sizeof(sText)) && identity_pub(sText, sNew, sizeof(sNew)) &&
        strcmp(sNew, sOld) != 0 && strcmp(sNew, g_api.sRotatePub) == 0, "the rotated identity is the one the API accepted");

    /* Without an enrollment there is nothing to rotate against, and the API is not asked. */
    char sBare[512];
    snprintf(sBare, sizeof(sBare), "%s/bare.json", pRoot);
    FILE *pFile = fopen(sBare, "w");
    CHECK(pFile != NULL, "write a config with no enrollment");
    fprintf(pFile, "{\"deviceId\":\"%s\",\"relayUrl\":\"%s\",\"enrollment\":{\"apiUrl\":\"https://127.0.0.1:%u\"}}\n",
        CLI_DEVICE_ID, CLI_RELAY_URL, (unsigned)g_api.nApiPort);
    fclose(pFile);
    chmod(sBare, 0600);

    int nRotations = (int)XSYNC_ATOMIC_GET(&g_api.nRotations);
    const char *bare[] = { "-c", sBare, "-r", NULL };
    CHECK(tty_start(pTty, bare), "start a rotation with no enrollment");
    CHECK(tty_finish(pTty, 20000) != 0, "a rotation with no enrollment fails");
    CHECK((int)XSYNC_ATOMIC_GET(&g_api.nRotations) == nRotations, "a rotation with no enrollment does not ask the API");
    CHECK(strstr(pTty->sScreen, "refresh token") != NULL, "a rotation with no enrollment says what is missing");
    return 0;
}

/* Waits for a prompt and answers it with end-of-file, as a closed terminal does. */
static int tty_eof(tty_t *pTty, const char *pPrompt)
{
    if (!tty_expect(pTty, pPrompt, 20000)) return 0;
    pTty->nScreen = 0;
    pTty->sScreen[0] = '\0';
    return write(pTty->nMaster, "\x04", 1) == 1;
}

static int write_config(const char *pPath, const char *pBody)
{
    FILE *pFile = fopen(pPath, "w");
    if (pFile == NULL) return 0;
    fputs(pBody, pFile);
    fclose(pFile);
    return chmod(pPath, 0600) == 0;
}

/* A config set up from nothing with -i, and every prompt a start or a pairing
   falls back to answered with end-of-file: each is a failure, never a start
   without what it asked for. */
static int scenario_setup(tty_t *pTty, const char *pRoot)
{
    struct passwd *pSelf = getpwuid(getuid());
    CHECK(pSelf != NULL, "resolve the current account");

    char sDir[512], sCfg[600], sLogs[600], sText[16384], sField[256];
    snprintf(sDir, sizeof(sDir), "%s/init", pRoot);
    snprintf(sCfg, sizeof(sCfg), "%s/agent.json", sDir);
    snprintf(sLogs, sizeof(sLogs), "%s/logs", pRoot);
    CHECK(mkdir(sDir, 0700) == 0, "create the setup directory");

    const char *init[] = { "-c", sCfg, "-i", NULL };
    CHECK(tty_start(pTty, init), "start an interactive setup");
    CHECK(tty_answer(pTty, "Relay URL", CLI_RELAY_URL), "the relay is asked for");
    CHECK(tty_answer(pTty, "Device ID", "dev-init"), "the device id is asked for");
    CHECK(tty_answer(pTty, "Set new auth password", CLI_PASSWORD), "the password is asked for");
    CHECK(tty_answer(pTty, "Repeat password", CLI_PASSWORD), "the password is confirmed");
    CHECK(tty_answer(pTty, "KA Interval", "25"), "the keepalive interval is asked for");
    CHECK(tty_answer(pTty, "Log to screen", "n"), "screen logging is asked for");
    CHECK(tty_answer(pTty, "Log to file", "y"), "file logging is asked for");
    CHECK(tty_answer(pTty, "Log path", sLogs), "the log path is asked for");
    CHECK(tty_answer(pTty, "Shell user", pSelf->pw_name), "the shell user is asked for");
    CHECK(tty_answer(pTty, "Shell home", pRoot), "the shell home is asked for");
    CHECK(tty_finish(pTty, 20000) == 0, "a completed setup writes the config");
    CHECK(load_text(sCfg, sText, sizeof(sText)) && config_field(sText, "deviceId", sField, sizeof(sField)) &&
        strcmp(sField, "dev-init") == 0, "the config holds what was answered");

    /* A setup that cannot write its config fails at the end, having asked everything. */
    if (geteuid() != 0)
    {
        char sLocked[600], sLockedCfg[700];
        snprintf(sLocked, sizeof(sLocked), "%s/locked", pRoot);
        snprintf(sLockedCfg, sizeof(sLockedCfg), "%s/agent.json", sLocked);
        CHECK(mkdir(sLocked, 0500) == 0, "create a directory the setup cannot write");

        const char *locked[] = { "-c", sLockedCfg, "-i", NULL };
        CHECK(tty_start(pTty, locked), "start a setup that cannot save");
        CHECK(tty_answer(pTty, "Relay URL", CLI_RELAY_URL) && tty_answer(pTty, "Device ID", "dev-locked") &&
            tty_answer(pTty, "Set new auth password", CLI_PASSWORD) && tty_answer(pTty, "Repeat password", CLI_PASSWORD) &&
            tty_answer(pTty, "KA Interval", "") && tty_answer(pTty, "Log to screen", "") &&
            tty_answer(pTty, "Log to file", "n") && tty_answer(pTty, "Shell user", "") && tty_answer(pTty, "Shell home", ""),
            "answer every setup question");
        CHECK(tty_finish(pTty, 20000) != 0 && strstr(pTty->sScreen, "Failed to create initial agent config") != NULL,
            "a config that cannot be written fails the setup");
        chmod(sLocked, 0700);
    }

    /* A start that has to ask for what the config lacks, and gets nothing. */
    char sBody[512], sGap[600];
    snprintf(sGap, sizeof(sGap), "%s/gap.json", pRoot);
    struct { const char *pBody; const char *pPrompt; const char *pSaid; } gaps[] = {
        { "{\"deviceId\":\"dev-gap\"}", "Relay URL", "Relay URL is not configured" },
        { "{\"relayUrl\":\"" CLI_RELAY_URL "\"}", "Device ID", "Device id is not configured" },
        { "{\"relayUrl\":\"" CLI_RELAY_URL "\",\"deviceId\":\"dev-gap\"}", "Set new auth password",
          "Failed to prepare SRP auth" }
    };

    for (size_t i = 0; i < sizeof(gaps) / sizeof(gaps[0]); i++)
    {
        snprintf(sBody, sizeof(sBody), "%s\n", gaps[i].pBody);
        CHECK(write_config(sGap, sBody), "write a config with a gap");
        const char *start[] = { "-c", sGap, NULL };
        CHECK(tty_start(pTty, start), "start with a gap in the config");
        CHECK(tty_eof(pTty, gaps[i].pPrompt), "the gap is asked for");
        CHECK(tty_finish(pTty, 20000) != 0, "no answer is a failed start");
        CHECK(strstr(pTty->sScreen, gaps[i].pSaid) != NULL, "and says what is missing");
    }

    /* A password whose confirmation never comes. */
    const char *start[] = { "-c", sGap, NULL };
    CHECK(tty_start(pTty, start), "start again to set a password");
    CHECK(tty_answer(pTty, "Set new auth password", CLI_PASSWORD), "the password is given");
    CHECK(tty_eof(pTty, "Repeat password"), "the confirmation is not");
    CHECK(tty_finish(pTty, 20000) != 0, "an unconfirmed password is a failed start");

    /* A pairing that gets no device id, and one that gets no token. */
    snprintf(sBody, sizeof(sBody), "{\"enrollment\":{\"apiUrl\":\"https://127.0.0.1:%u\"}}\n", (unsigned)g_api.nApiPort);
    CHECK(write_config(sGap, sBody), "write a config with nothing but the API");
    const char *pair[] = { "-c", sGap, "-e", NULL };
    CHECK(tty_start(pTty, pair), "start a pairing without a device id");
    CHECK(tty_eof(pTty, "Device ID"), "the device id is asked for");
    CHECK(tty_finish(pTty, 20000) != 0 && strstr(pTty->sScreen, "Enrollment requires device id") != NULL,
        "a pairing without a device id fails");

    CHECK(tty_start(pTty, pair), "start a pairing without a token");
    CHECK(tty_answer(pTty, "Device ID", CLI_DEVICE_ID), "the device id is given");
    CHECK(tty_eof(pTty, "Pairing token"), "the token is not");
    CHECK(tty_finish(pTty, 20000) != 0 && strstr(pTty->sScreen, "Failed to read pairing token") != NULL,
        "a pairing without a token fails");

    /* A rotation with no device to rotate for. */
    const char *rotate[] = { "-c", sGap, "-r", NULL };
    CHECK(tty_start(pTty, rotate), "start a rotation without a device id");
    CHECK(tty_finish(pTty, 20000) != 0 && strstr(pTty->sScreen, "requires device id") != NULL,
        "a rotation without a device id fails");
    return 0;
}

int main(void)
{
    memset(&g_api, 0, sizeof(g_api));
    signal(SIGPIPE, SIG_IGN);

    if (access(DIRECTGATE_AGENT_BIN, X_OK) != 0)
    {
        printf("agent_cli_smoke: agent binary not built, skipping\n");
        return 77;
    }

    tls_fixture_t tls;
    CHECK(tls_fixture_begin(&tls), "create a TLS identity for the API");

    char sRoot[] = "/tmp/directgate_agent_cli.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "create a working directory");

    g_api.nApiPort = reserve_port();
    CHECK(g_api.nApiPort != 0, "reserve a local port");

    XAPI_Init(&g_api.api, service_callback, &g_api);
    xapi_endpoint_t endpt;
    XAPI_InitEndpoint(&endpt);
    endpt.eType = XAPI_HTTP;
    endpt.eRole = XAPI_SERVER;
    endpt.pAddr = "127.0.0.1";
    endpt.nPort = g_api.nApiPort;
    endpt.bTLS = XTRUE;
    endpt.bForce = XTRUE;
    endpt.certs.pCertPath = tls.sCert;
    endpt.certs.pKeyPath = tls.sKey;
    CHECK(XAPI_AddEndpoint(&g_api.api, &endpt) >= 0, "start the API");

    xthread_t thread;
    CHECK(XThread_Create(&thread, server_thread, NULL, XFALSE) == XSTDOK, "start the server thread");

    tty_t tty;
    memset(&tty, 0, sizeof(tty));
    tty.nMaster = -1;
    tty.pCert = tls.sCert;

    char sCfg[512];
    int nResult = scenario_pair(&tty, sRoot, sCfg, sizeof(sCfg));
    if (!nResult) nResult = scenario_password(&tty, sCfg);
    if (!nResult) nResult = scenario_rotate(&tty, sRoot, sCfg);
    if (!nResult) nResult = scenario_setup(&tty, sRoot);

    if (nResult != 0) fprintf(stderr, "---- agent terminal ----\n%s\n------------------------\n", tty.sScreen);

    if (tty.nPid > 0)
    {
        kill(tty.nPid, SIGKILL);
        waitpid(tty.nPid, NULL, 0);
    }

    if (tty.nMaster >= 0) close(tty.nMaster);

    XSYNC_ATOMIC_SET(&g_api.bStop, 1);
    XThread_Join(&thread);
    XAPI_Destroy(&g_api.api);

    char sCmd[512];
    snprintf(sCmd, sizeof(sCmd), "rm -rf '%s'", sRoot);
    if (system(sCmd) != 0) fprintf(stderr, "agent_cli_smoke: could not remove %s\n", sRoot);
    tls_fixture_end(&tls);

    if (nResult != 0) return 1;
    puts("agent_cli_smoke: OK");
    return 0;
}
