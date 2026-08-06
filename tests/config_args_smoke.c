/*
 * Argument parsing, config persistence and authorized-key bookkeeping.
 *
 * DirectGate_ParseArgs is the agent's whole entry contract: it decides which
 * config file is read, which one-shot mode the process runs in, and what the
 * log level becomes. It also drives getopt, whose state is global and easy to
 * leave dirty between calls, so every case here re-parses from scratch.
 *
 * These run under ASan/LSan and Valgrind in CI, so the point is as much that
 * the paths allocate nothing they fail to release as that they answer right.
 */

/* posix_openpt/grantpt/ptsname are XOPEN, not in the default ISO C view the
   project compiles tests with. */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "src/agent/config.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "config_args_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static int write_file(const char *pPath, const char *pData)
{
    FILE *pFile = fopen(pPath, "wb");
    if (pFile == NULL) return 0;

    size_t nLen = strlen(pData);
    int nOk = fwrite(pData, 1, nLen, pFile) == nLen;
    fclose(pFile);
    return nOk;
}

/* getopt keeps global cursor state; a helper that always parses a fresh argv
   keeps one case from inheriting the previous one's position. */
static xbool_t parse(directgate_cfg_t *pCfg, int argc, char *argv[])
{
    return DirectGate_ParseArgs(pCfg, argc, argv);
}

int main(void)
{
    char sRoot[] = "/tmp/directgate_config_args_smoke.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "mkdtemp root");
    CHECK(setenv("HOME", sRoot, 1) == 0, "set HOME");

    char sCfgDir[512];
    snprintf(sCfgDir, sizeof(sCfgDir), "%s/.config", sRoot);
    CHECK(mkdir(sCfgDir, 0700) == 0, "mkdir .config");
    snprintf(sCfgDir, sizeof(sCfgDir), "%s/.config/directgate", sRoot);
    CHECK(mkdir(sCfgDir, 0700) == 0, "mkdir .config/directgate");

    char sCfgPath[512];
    char sMissingPath[512];
    char sLogDir[512];
    snprintf(sCfgPath, sizeof(sCfgPath), "%s/agent.json", sRoot);
    snprintf(sMissingPath, sizeof(sMissingPath), "%s/absent.json", sRoot);
    snprintf(sLogDir, sizeof(sLogDir), "%s/logs", sRoot);

    const char *pSalt =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    char sJson[2048];
    int nJson = snprintf(sJson, sizeof(sJson),
        "{\"deviceId\":\"dev-from-file\","
        "\"relayUrl\":\"wss://relay.example/websock\","
        "\"routingKey\":\"rk-from-file\","
        "\"kaInterval\":31,"
        "\"allowTCP\":true,"
        "\"auth\":{\"method\":\"srp\",\"salt\":\"%s\",\"verifier\":\"abcdef\"},"
        "\"desktop\":{\"elevatedInput\":false,\"lockScreen\":false},"
        "\"enroll\":{\"enrolled\":true,"
        "\"apiUrl\":\"https://api.example\","
        "\"accessToken\":\"access-from-file\","
        "\"refreshToken\":\"refresh-from-file\"},"
        "\"iceServers\":[\"stun:one.example:3478\",\"stun:two.example:3478\"]}",
        pSalt);
    CHECK(nJson > 0 && (size_t)nJson < sizeof(sJson), "compose config json");
    CHECK(write_file(sCfgPath, sJson), "write config json");

    /* -c selects the file, and values in it survive into the parsed config. */
    {
        directgate_cfg_t cfg;
        char *argv[] = { (char*)"directgate", (char*)"-c", sCfgPath, NULL };
        CHECK(parse(&cfg, 3, argv), "parse with explicit config");
        CHECK(strcmp(cfg.sCfgPath, sCfgPath) == 0, "explicit config path is kept");
        CHECK(strcmp(cfg.sDeviceId, "dev-from-file") == 0, "device id from file");
        CHECK(strcmp(cfg.sRoutingKey, "rk-from-file") == 0, "routing key from file");
        CHECK(cfg.nKAInterval == 31, "keepalive interval from file");
        CHECK(cfg.bAllowTCP, "allowTCP from file");
        CHECK(cfg.nIceSrvCount == 2, "ice servers from file");
        CHECK(!cfg.desktop.bElevatedInput, "elevatedInput disabled from file");
        CHECK(!cfg.desktop.bLockScreen, "lockScreen disabled from file");
    }

    /* Command line beats the file for every value both can carry. */
    {
        directgate_cfg_t cfg;
        char *argv[] = {
            (char*)"directgate", (char*)"-c", sCfgPath,
            (char*)"-d", (char*)"dev-from-argv",
            (char*)"-u", (char*)"wss://argv.example/websock",
            (char*)"-t", (char*)"pair-token",
            (char*)"-l", sLogDir,
            (char*)"-v", (char*)"5",
            (char*)"-w",
            NULL
        };
        CHECK(parse(&cfg, 14, argv), "parse with overrides");
        CHECK(strcmp(cfg.sDeviceId, "dev-from-argv") == 0, "argv overrides device id");
        CHECK(strcmp(cfg.sRelayUrl, "wss://argv.example/websock") == 0,
            "argv overrides relay url");
        CHECK(strcmp(cfg.sPairingToken, "pair-token") == 0, "argv sets pairing token");
        CHECK(strcmp(cfg.log.sPath, sLogDir) == 0, "argv sets log path");
        CHECK(cfg.nVerbose == 5, "argv sets verbosity");
        CHECK(cfg.bWebRTCVerbose, "argv sets webrtc verbosity");
        /* -v 5 is the most verbose tier and must light up every level. */
        CHECK((cfg.log.nFlags & XLOG_TRACE) != 0, "verbosity 5 enables trace");
        CHECK((cfg.log.nFlags & XLOG_DEBUG) != 0, "verbosity 5 enables debug");
        CHECK(cfg.log.bLogRTC, "webrtc logging follows -w");
    }

    /* Each one-shot mode is its own flag, and none of them implies another. */
    {
        struct {
            const char *pFlag;
            size_t nOffset;
        } modes[] = {
            { "-e", offsetof(directgate_cfg_t, bEnroll) },
            { "-s", offsetof(directgate_cfg_t, bSetSRP) },
            { "-r", offsetof(directgate_cfg_t, bRotateAgentKey) },
        };

        for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++)
        {
            directgate_cfg_t cfg;
            char *argv[] = {
                (char*)"directgate", (char*)"-c", sCfgPath,
                (char*)modes[i].pFlag, NULL
            };
            CHECK(parse(&cfg, 4, argv), "parse one-shot mode");
            CHECK(*(xbool_t*)((char*)&cfg + modes[i].nOffset), "one-shot flag is set");
        }
    }

    /* -g and -a carry a path and put the process in a key-file mode. */
    {
        directgate_cfg_t cfg;
        char sKeyPath[512];
        snprintf(sKeyPath, sizeof(sKeyPath), "%s/client-key.json", sRoot);

        char *argv[] = {
            (char*)"directgate", (char*)"-c", sCfgPath,
            (char*)"-g", sKeyPath, NULL
        };
        CHECK(parse(&cfg, 5, argv), "parse genkey");
        CHECK(cfg.bGenKey, "genkey flag is set");
        CHECK(strcmp(cfg.sGenKeyPath, sKeyPath) == 0, "genkey path is kept");

        directgate_cfg_t enrollCfg;
        char *enrollArgv[] = {
            (char*)"directgate", (char*)"-c", sCfgPath,
            (char*)"-a", sKeyPath, NULL
        };
        CHECK(parse(&enrollCfg, 5, enrollArgv), "parse enroll-key");
        CHECK(enrollCfg.bEnrollKey, "enroll-key flag is set");
        CHECK(strcmp(enrollCfg.sEnrollKeyPath, sKeyPath) == 0, "enroll-key path is kept");
    }

    /* -h prints usage and refuses to run; so does an unknown option. */
    {
        directgate_cfg_t cfg;
        char *argv[] = { (char*)"directgate", (char*)"-h", NULL };
        CHECK(!parse(&cfg, 2, argv), "help does not start the agent");
        CHECK(cfg.bHelp, "help flag is set");

        directgate_cfg_t badCfg;
        char *badArgv[] = { (char*)"directgate", (char*)"-Z", NULL };
        CHECK(!parse(&badCfg, 2, badArgv), "unknown option does not start the agent");
        CHECK(badCfg.bHelp, "unknown option falls through to usage");
    }

    /* A -c naming a file that is not there is fatal for a normal start, but
       the modes that create a config are allowed to run without one. */
    {
        directgate_cfg_t cfg;
        char *argv[] = { (char*)"directgate", (char*)"-c", sMissingPath, NULL };
        CHECK(!parse(&cfg, 3, argv), "missing explicit config is fatal");

        directgate_cfg_t enrollCfg;
        char *enrollArgv[] = {
            (char*)"directgate", (char*)"-c", sMissingPath, (char*)"-e", NULL
        };
        CHECK(parse(&enrollCfg, 4, enrollArgv), "enroll may create the config");
    }

    /* -c with no value is rejected rather than silently reading a default. */
    {
        directgate_cfg_t cfg;
        char *argv[] = { (char*)"directgate", (char*)"-c", NULL };
        CHECK(!parse(&cfg, 2, argv), "dangling -c is rejected");
    }

    /* Saving then loading must round-trip every field the agent persists. */
    {
        directgate_cfg_t cfg;
        char *argv[] = { (char*)"directgate", (char*)"-c", sCfgPath, NULL };
        CHECK(parse(&cfg, 3, argv), "parse before save");

        xstrncpy(cfg.sDeviceId, sizeof(cfg.sDeviceId), "dev-roundtrip");
        xstrncpy(cfg.sRoutingKey, sizeof(cfg.sRoutingKey), "rk-roundtrip");
        xstrncpy(cfg.enroll.sApiUrl, sizeof(cfg.enroll.sApiUrl),
            "https://api.directgate.io");
        xstrncpy(cfg.enroll.sAccessToken, sizeof(cfg.enroll.sAccessToken), "access-tok");
        xstrncpy(cfg.enroll.sRefreshToken, sizeof(cfg.enroll.sRefreshToken), "refresh-tok");
        cfg.enroll.bEnrolled = XTRUE;
        cfg.enroll.nAccessTokenExp = 1785772641ULL;
        cfg.nKAInterval = 44;
        cfg.desktop.bElevatedInput = XTRUE;
        cfg.desktop.bLockScreen = XFALSE;

        CHECK(DirectGate_SaveConfig(&cfg), "save config");

        directgate_cfg_t loaded;
        DirectGate_InitConfig(&loaded);
        CHECK(DirectGate_LoadConfig(&loaded, sCfgPath), "reload saved config");
        CHECK(strcmp(loaded.sDeviceId, "dev-roundtrip") == 0, "device id round-trips");
        CHECK(strcmp(loaded.sRoutingKey, "rk-roundtrip") == 0, "routing key round-trips");
        CHECK(strcmp(loaded.enroll.sApiUrl, "https://api.directgate.io") == 0,
            "api url round-trips");
        CHECK(strcmp(loaded.enroll.sAccessToken, "access-tok") == 0,
            "access token round-trips");
        CHECK(strcmp(loaded.enroll.sRefreshToken, "refresh-tok") == 0,
            "refresh token round-trips");
        CHECK(loaded.enroll.bEnrolled, "enrolled flag round-trips");
        CHECK(loaded.enroll.nAccessTokenExp == 1785772641ULL, "token expiry round-trips");
        CHECK(loaded.nKAInterval == 44, "keepalive interval round-trips");
        CHECK(loaded.desktop.bElevatedInput, "elevatedInput round-trips");
        CHECK(!loaded.desktop.bLockScreen, "lockScreen round-trips");
        CHECK(loaded.nIceSrvCount == 2, "ice servers round-trip");
    }

    /* Authorized keys: added once, recognised on repeat, capped, and every
       string that is not a 32-byte Ed25519 public key is refused. */
    {
        directgate_cfg_t cfg;
        DirectGate_InitConfig(&cfg);

        /* 32 zero bytes, standard base64 - the shape a genkey file carries. */
        const char *pKeyA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        const char *pKeyB = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        CHECK(DirectGate_AddAuthorizedKey(&cfg, pKeyA) == DIRECTGATE_ADD_KEY_ADDED,
            "first key is added");
        CHECK(cfg.keyauth.nAuthorizedKeyCount == 1, "key count advances");
        CHECK(DirectGate_AddAuthorizedKey(&cfg, pKeyA) == DIRECTGATE_ADD_KEY_ALREADY,
            "the same key is not added twice");
        CHECK(cfg.keyauth.nAuthorizedKeyCount == 1, "duplicate does not grow the list");
        CHECK(DirectGate_AddAuthorizedKey(&cfg, pKeyB) == DIRECTGATE_ADD_KEY_ADDED,
            "a different key is added");

        CHECK(DirectGate_AddAuthorizedKey(&cfg, "") == DIRECTGATE_ADD_KEY_INVALID,
            "empty key is refused");
        CHECK(DirectGate_AddAuthorizedKey(&cfg, "not-base64!!") == DIRECTGATE_ADD_KEY_INVALID,
            "non-base64 key is refused");
        /* Decodes cleanly but is the wrong length for Ed25519. */
        CHECK(DirectGate_AddAuthorizedKey(&cfg, "AAAA") == DIRECTGATE_ADD_KEY_INVALID,
            "short key is refused");
        CHECK(DirectGate_AddAuthorizedKey(&cfg, NULL) == DIRECTGATE_ADD_KEY_INVALID,
            "null key is refused");

        /* Fill to the cap, then confirm the cap is reported rather than
           overrunning the fixed-size array. */
        char sKey[64];
        while (cfg.keyauth.nAuthorizedKeyCount < DIRECTGATE_MAX_AUTHORIZED_KEYS)
        {
            uint8_t nIndex = cfg.keyauth.nAuthorizedKeyCount;
            snprintf(sKey, sizeof(sKey),
                "A%c%s", (char)('A' + nIndex),
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
            CHECK(DirectGate_AddAuthorizedKey(&cfg, sKey) == DIRECTGATE_ADD_KEY_ADDED,
                "filler key is added");
        }

        CHECK(cfg.keyauth.nAuthorizedKeyCount == DIRECTGATE_MAX_AUTHORIZED_KEYS,
            "list reaches the documented cap");
        CHECK(DirectGate_AddAuthorizedKey(&cfg,
                "Az" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") ==
            DIRECTGATE_ADD_KEY_FULL, "a full list is reported, not overrun");
    }

    /* -i walks the interactive setup and writes a config from the answers.
       It has to be driven through a pseudo-terminal rather than a file:
       the password prompt turns echo off with tcsetattr, which fails with
       ENOTTY on anything that is not a terminal and would make the run bail
       out before reading a byte. This is the only caller of the prompt
       helpers in common.c, so it is what covers them. */
    {
        int nMaster = posix_openpt(O_RDWR | O_NOCTTY);
        if (nMaster < 0 || grantpt(nMaster) != 0 || unlockpt(nMaster) != 0)
        {
            /* No /dev/ptmx in this sandbox: skip the interactive leg rather
               than fail a test that is not about pty availability. */
            if (nMaster >= 0) close(nMaster);
            puts("config_args_smoke: no pty available, skipping interactive init");
        }
        else
        {
            const char *pSlaveName = ptsname(nMaster);
            CHECK(pSlaveName != NULL, "resolve pty slave name");

            int nSlave = open(pSlaveName, O_RDWR | O_NOCTTY);
            CHECK(nSlave >= 0, "open pty slave");

            /* Relay URL, device id, password twice, keepalive interval,
               log-to-screen, log-to-file, shell user, shell home. Empty
               lines accept whatever default the prompt offers. */
            static const char sAnswers[] =
                "wss://init.example/websock\n"
                "dev-init\n"
                "init-password\n"
                "init-password\n"
                "27\n"
                "y\n"
                "n\n"
                "\n"
                "\n";

            size_t nAnswers = sizeof(sAnswers) - 1;
            ssize_t nWritten = write(nMaster, sAnswers, nAnswers);
            CHECK(nWritten == (ssize_t)nAnswers, "queue the prompt answers");

            int nSavedStdin = dup(STDIN_FILENO);
            CHECK(nSavedStdin >= 0, "save the real stdin");
            CHECK(dup2(nSlave, STDIN_FILENO) >= 0, "point stdin at the pty");
            clearerr(stdin);

            char sInitCfgPath[512];
            snprintf(sInitCfgPath, sizeof(sInitCfgPath), "%s/init-agent.json", sRoot);

            directgate_cfg_t initCfg;
            char *initArgv[] = {
                (char*)"directgate", (char*)"-c", sInitCfgPath, (char*)"-i", NULL
            };
            xbool_t bInitOk = parse(&initCfg, 4, initArgv);

            CHECK(dup2(nSavedStdin, STDIN_FILENO) >= 0, "restore stdin");
            close(nSavedStdin);
            close(nSlave);
            close(nMaster);
            clearerr(stdin);

            CHECK(bInitOk, "interactive init completes");
            CHECK(initCfg.bInit, "init flag is set");
            CHECK(strcmp(initCfg.sRelayUrl, "wss://init.example/websock") == 0,
                "relay url comes from the prompt");
            CHECK(strcmp(initCfg.sDeviceId, "dev-init") == 0,
                "device id comes from the prompt");
            CHECK(initCfg.nKAInterval == 27, "keepalive interval comes from the prompt");
            CHECK(initCfg.log.bToScreen, "log-to-screen answer is applied");
            CHECK(!initCfg.log.bToFile, "log-to-file answer is applied");

            /* The password must have been turned into an SRP verifier, never
               stored as given. */
            CHECK(xstrused(initCfg.auth.sSaltHex), "init derived an SRP salt");
            CHECK(xstrused(initCfg.auth.sVerifierHex), "init derived an SRP verifier");
            CHECK(strstr(initCfg.auth.sVerifierHex, "init-password") == NULL,
                "the password is not stored verbatim");

            directgate_cfg_t reloaded;
            DirectGate_InitConfig(&reloaded);
            CHECK(DirectGate_LoadConfig(&reloaded, sInitCfgPath),
                "init wrote a config that loads back");
            CHECK(strcmp(reloaded.sDeviceId, "dev-init") == 0,
                "written config carries the device id");
            CHECK(strcmp(reloaded.auth.sVerifierHex, initCfg.auth.sVerifierHex) == 0,
                "written config carries the derived verifier");
        }
    }

    /* Usage output must not depend on a configured agent. */
    DirectGate_DisplayUsage("directgate");

    puts("config_args_smoke: OK");
    return 0;
}
