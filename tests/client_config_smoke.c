#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

    char *helpArgs[] = { (char*)"directgate", (char*)"-h" };
    CHECK(DirectGate_ParseArgs(&cfg, 2, helpArgs) == XSTDERR, "CLI help status");

    CHECK(unlink(sValid) == 0, "unlink valid");
    CHECK(unlink(sMalformed) == 0, "unlink malformed");
    CHECK(unlink(sDevices) == 0, "unlink devices");
    CHECK(rmdir(sRoot) == 0, "rmdir root");

    puts("client_config_smoke: OK");
    return 0;
}
