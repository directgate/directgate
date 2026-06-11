#include <stdio.h>
#include <string.h>

#include "src/client/relay.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "client_relay_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

int main(void)
{
    CHECK(!DirectGate_Relay_FetchEnvelope(NULL), "reject NULL config");

    directgate_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    CHECK(!DirectGate_Relay_FetchEnvelope(&cfg), "reject missing API URL");

    xstrncpy(cfg.sApiUrl, sizeof(cfg.sApiUrl), "https://api.example.test");
    CHECK(!DirectGate_Relay_FetchEnvelope(&cfg), "reject missing API token");

    xstrncpy(cfg.sApiToken, sizeof(cfg.sApiToken), "token");
    CHECK(!DirectGate_Relay_FetchEnvelope(&cfg), "reject missing device ID");

    xstrncpy(cfg.sDeviceId, sizeof(cfg.sDeviceId), "device-id");
    xstrncpy(cfg.sApiUrl, sizeof(cfg.sApiUrl), "wss://api.example.test");
    CHECK(!DirectGate_Relay_FetchEnvelope(&cfg), "reject non-HTTP API scheme");
    CHECK(cfg.sAccessToken[0] == '\0' && cfg.sRoutingKey[0] == '\0' &&
          cfg.sSignalingUrl[0] == '\0', "failed fetch preserves relay envelope");

    xstrncpy(cfg.sApiUrl, sizeof(cfg.sApiUrl), "https://");
    CHECK(!DirectGate_Relay_FetchEnvelope(&cfg), "reject API URL without host");

    puts("client_relay_smoke: OK");
    return 0;
}
