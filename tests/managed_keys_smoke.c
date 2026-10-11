#include <stdio.h>
#include <string.h>

#include "src/agent/managed_keys.h"
#include "src/common/keyauth.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "managed_keys_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

int main(void)
{
    const char *pKey = "G8tzS4EVKlvTqIPkKxTV/jJMHCvQkQCnYJO1B4EFRzE=";
    const char *pFirst =
        "{\"publicKeys\":[\"G8tzS4EVKlvTqIPkKxTV/jJMHCvQkQCnYJO1B4EFRzE=\"],"
        "\"policyId\":\"11111111-1111-1111-1111-111111111111\","
        "\"expiresAt\":\"2999-01-01T00:00:00.000Z\"}";
    const char *pReplacement =
        "{\"publicKeys\":[\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"],"
        "\"policyId\":\"11111111-1111-1111-1111-111111111111\","
        "\"expiresAt\":\"2999-01-01T00:00:00.000Z\"}";
    const char *pEmpty =
        "{\"publicKeys\":[],\"policyId\":\"11111111-1111-1111-1111-111111111111\","
        "\"expiresAt\":\"2999-01-01T00:00:00.000Z\"}";

    directgate_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    xstrncpy(cfg.enroll.sOrganizationId, sizeof(cfg.enroll.sOrganizationId),
        "11111111-1111-1111-1111-111111111111");

    directgate_managed_keys_t keys;
    DirectGate_ManagedKeys_Init(&keys, &cfg);
    CHECK(DirectGate_ManagedKeys_ApplyResponse(&keys, (const uint8_t*)pFirst, strlen(pFirst)),
        "first lease applies");
    CHECK(keys.nKeyCount == 1, "first lease replaces the set");

    uint8_t raw[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    size_t nRaw = 0;
    CHECK(DirectGate_KeyAuth_Base64Decode(pKey, raw, sizeof(raw), &nRaw), "fixture key decodes");
    CHECK(DirectGate_ManagedKeys_IsAuthorized(&keys, raw), "leased key authorizes");

    CHECK(DirectGate_ManagedKeys_ApplyResponse(&keys, (const uint8_t*)pReplacement, strlen(pReplacement)),
        "replacement lease applies");
    CHECK(!DirectGate_ManagedKeys_IsAuthorized(&keys, raw), "replacement removes the previous key");
    uint8_t replacement[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    size_t nReplacement = 0;
    CHECK(DirectGate_KeyAuth_Base64Decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", replacement,
        sizeof(replacement), &nReplacement), "replacement fixture key decodes");
    CHECK(DirectGate_ManagedKeys_IsAuthorized(&keys, replacement), "replacement key authorizes");

    DirectGate_ManagedKeys_ApplyFailure(&keys, keys.nExpiresAt - 1);
    CHECK(keys.nKeyCount == 1, "transient failure keeps an unexpired lease");
    DirectGate_ManagedKeys_ApplyFailure(&keys, keys.nExpiresAt);
    CHECK(keys.nKeyCount == 0, "expired lease clears");

    CHECK(DirectGate_ManagedKeys_ApplyResponse(&keys, (const uint8_t*)pFirst, strlen(pFirst)),
        "new lease applies after expiry");
    CHECK(DirectGate_ManagedKeys_ApplyResponse(&keys, (const uint8_t*)pEmpty, strlen(pEmpty)),
        "empty lease applies");
    CHECK(keys.nKeyCount == 0, "successful empty lease clears immediately");

    DirectGate_ManagedKeys_Stop(&keys);
    puts("managed_keys_smoke: ok");
    return 0;
}
