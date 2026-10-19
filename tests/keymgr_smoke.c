/*
 * The organization key lease: what the agent takes from the API, how long it trusts it, and when it lets go.
 *
 * A managed key opens a shell on the device for as long as the lease names it, so every way the lease could
 * outlive its word is asserted here by value: a far-future expiresAt, a host clock that is off, a refusal from
 * the API, a gateway answering in its place, a response for another organization, the enrollment ending. The
 * worker runs against a real HTTPS endpoint in this process, the way the agent reaches the API, and a second
 * endpoint that never answers shows a request stuck on the network cannot hold the agent's shutdown.
 */

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "src/agent/keymgr.h"
#include "src/common/common.h"
#include "src/common/keyauth.h"
#include "fake_https.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "keymgr_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#define ORG_ID      "11111111-1111-1111-1111-111111111111"
#define OTHER_ORG   "22222222-2222-2222-2222-222222222222"
#define KEY_A       "G8tzS4EVKlvTqIPkKxTV/jJMHCvQkQCnYJO1B4EFRzE="
#define KEY_B       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
#define PUMP_MS     10000U

static int decode(const char *pB64, uint8_t *pOut)
{
    size_t nDecoded = 0;
    return DirectGate_KeyAuth_Base64Decode(pB64, pOut, DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE, &nDecoded) &&
        nDecoded == DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE;
}

static int parse(const char *pJson, directgate_keymgr_lease_t *pLease)
{
    return DirectGate_KeyManager_ParseLease((const uint8_t*)pJson, strlen(pJson), (uint64_t)time(NULL), pLease);
}

static int install(directgate_keymgr_t *pKeyMgr, const char *pJson, uint64_t nNowMs)
{
    directgate_keymgr_lease_t lease;
    if (!parse(pJson, &lease)) return 0;

    int nInstalled = DirectGate_KeyManager_Install(pKeyMgr, &lease, nNowMs);
    DirectGate_KeyManager_FreeLease(&lease);
    return nInstalled;
}

static void init_cfg(directgate_cfg_t *pCfg, const char *pOrganizationId)
{
    memset(pCfg, 0, sizeof(*pCfg));
    xstrncpy(pCfg->enroll.sOrganizationId, sizeof(pCfg->enroll.sOrganizationId), pOrganizationId);
}

static int test_parse(void)
{
    directgate_keymgr_lease_t lease;
    uint8_t keyA[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    uint8_t keyB[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    CHECK(decode(KEY_A, keyA) && decode(KEY_B, keyB), "the fixture keys decode");

    CHECK(parse("{\"publicKeys\":[\"" KEY_A "\",\"" KEY_B "\"],\"policyId\":\"" ORG_ID "\","
        "\"expiresAt\":\"2999-01-01T00:00:00.000Z\",\"expiresIn\":120}", &lease), "a lease with expiresIn parses");
    CHECK(lease.nKeyCount == 2 && lease.nRejected == 0, "both keys are taken");
    CHECK(!memcmp(lease.pKeys[0], keyA, sizeof(keyA)) && !memcmp(lease.pKeys[1], keyB, sizeof(keyB)),
        "the keys are held decoded, in the order the API sent them");
    CHECK(lease.nTtlMs == 120000U, "expiresIn is the lifetime, whatever expiresAt says");
    CHECK(!strcmp(lease.sPolicyId, ORG_ID) && !strcmp(lease.sExpiresAt, "2999-01-01T00:00:00.000Z"),
        "the policy and the expiry the API named are kept for the acknowledgement");
    DirectGate_KeyManager_FreeLease(&lease);

    /* The first version of this trusted expiresAt as is: a lease dated 2999 authorized its keys for ever. */
    CHECK(parse("{\"publicKeys\":[\"" KEY_A "\"],\"policyId\":\"" ORG_ID "\","
        "\"expiresAt\":\"2999-01-01T00:00:00.000Z\"}", &lease), "a lease with only expiresAt parses");
    CHECK(lease.nTtlMs == DIRECTGATE_KEYMGR_LEASE_MAX_MS, "a far-future expiresAt is cut to the lease maximum");
    DirectGate_KeyManager_FreeLease(&lease);

    CHECK(parse("{\"publicKeys\":[],\"policyId\":\"" ORG_ID "\",\"expiresIn\":3600}", &lease) &&
        lease.nTtlMs == DIRECTGATE_KEYMGR_LEASE_MAX_MS && lease.nKeyCount == 0,
        "a long expiresIn is cut to the lease maximum, and an empty lease is still a lease");
    DirectGate_KeyManager_FreeLease(&lease);

    CHECK(parse("{\"publicKeys\":[\"" KEY_A "\"],\"policyId\":\"" ORG_ID "\","
        "\"expiresAt\":\"2000-01-01T00:00:00.000Z\"}", &lease) && lease.nTtlMs == 0,
        "an expiresAt already past gives a lease with no lifetime");
    DirectGate_KeyManager_FreeLease(&lease);

    /* Every entry that is not exactly one Ed25519 public key is skipped and counted, the rest still applies. */
    CHECK(parse("{\"publicKeys\":[\"" KEY_A "\",7,\"\",null,\"AAAA\","
        "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\","
        "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\","
        "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\","
        "\"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!=\"],"
        "\"policyId\":\"" ORG_ID "\",\"expiresIn\":60}", &lease), "a lease with malformed entries parses");
    CHECK(lease.nKeyCount == 1 && !memcmp(lease.pKeys[0], keyA, sizeof(keyA)), "only the well formed key is taken");
    CHECK(lease.nRejected == 8, "a number, an empty string, null, short, 31-byte, 33-byte, 64-byte and non-base64 "
        "entries are all skipped and counted");
    DirectGate_KeyManager_FreeLease(&lease);

    static const char *pRefused[] = {
        "not json",
        "[\"" KEY_A "\"]",
        "{\"policyId\":\"" ORG_ID "\",\"expiresIn\":60}",
        "{\"publicKeys\":{},\"policyId\":\"" ORG_ID "\",\"expiresIn\":60}",
        "{\"publicKeys\":[],\"expiresIn\":60}",
        "{\"publicKeys\":[],\"policyId\":7,\"expiresIn\":60}",
        "{\"publicKeys\":[],\"policyId\":\"" ORG_ID "\"}",
        "{\"publicKeys\":[],\"policyId\":\"" ORG_ID "\",\"expiresAt\":\"tomorrow\"}",
        "{\"publicKeys\":[],\"policyId\":\"" ORG_ID "\",\"expiresIn\":-5}"
    };

    for (size_t i = 0; i < sizeof(pRefused) / sizeof(pRefused[0]); i++)
    {
        CHECK(!parse(pRefused[i], &lease), "a body that is not a complete lease is refused");
        CHECK(lease.pKeys == NULL && lease.nKeyCount == 0, "a refused body leaves nothing allocated");
    }

    char sLongPolicy[XSTR_TINY + 64];
    char sJson[XSTR_TINY + 256];
    memset(sLongPolicy, 'p', sizeof(sLongPolicy) - 1);
    sLongPolicy[sizeof(sLongPolicy) - 1] = '\0';
    snprintf(sJson, sizeof(sJson), "{\"publicKeys\":[],\"policyId\":\"%s\",\"expiresIn\":60}", sLongPolicy);
    CHECK(!parse(sJson, &lease), "a policy id that does not fit is refused, not cut short into another one");
    CHECK(!DirectGate_KeyManager_ParseLease(NULL, 5, 0, &lease) &&
        !DirectGate_KeyManager_ParseLease((const uint8_t*)"{}", 0, 0, &lease), "no body is no lease");

    /* The API caps the set at 2,000 too; one more is skipped rather than overrunning the table. */
    size_t nBig = (DIRECTGATE_KEYMGR_MAX + 1U) * 48U + 256U;
    char *pBig = (char*)malloc(nBig);
    CHECK(pBig != NULL, "allocate an oversized lease");
    size_t nUsed = (size_t)snprintf(pBig, nBig, "{\"publicKeys\":[");
    for (uint32_t i = 0; i <= DIRECTGATE_KEYMGR_MAX; i++)
        nUsed += (size_t)snprintf(pBig + nUsed, nBig - nUsed, "%s\"" KEY_A "\"", i ? "," : "");
    snprintf(pBig + nUsed, nBig - nUsed, "],\"policyId\":\"" ORG_ID "\",\"expiresIn\":60}");

    int nParsed = parse(pBig, &lease);
    free(pBig);
    CHECK(nParsed, "an oversized lease parses");
    CHECK(lease.nKeyCount == DIRECTGATE_KEYMGR_MAX && lease.nRejected == 1, "keys past the maximum are skipped and counted");
    DirectGate_KeyManager_FreeLease(&lease);

    return 0;
}

static int test_install(void)
{
    uint8_t keyA[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    uint8_t keyB[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    CHECK(decode(KEY_A, keyA) && decode(KEY_B, keyB), "the fixture keys decode");

    const char *pLeaseA = "{\"publicKeys\":[\"" KEY_A "\"],\"policyId\":\"" ORG_ID "\",\"expiresIn\":300}";
    const char *pLeaseB = "{\"publicKeys\":[\"" KEY_B "\"],\"policyId\":\"" ORG_ID "\",\"expiresIn\":300}";
    const char *pEmpty = "{\"publicKeys\":[],\"policyId\":\"" ORG_ID "\",\"expiresIn\":300}";

    directgate_keymgr_t keyMgr;
    DirectGate_KeyManager_Init(&keyMgr);
    CHECK(!install(&keyMgr, pLeaseA, 1000), "no lease is installed before the agent knows its organization");

    directgate_cfg_t cfg;
    init_cfg(&cfg, ORG_ID);
    DirectGate_KeyManager_Sync(&keyMgr, &cfg, 1000);
    CHECK(!strcmp(keyMgr.sOrganizationId, ORG_ID), "the lease follows the enrollment's organization");
    CHECK(keyMgr.pWorker == NULL, "without AllowWorker() no thread is started, whatever the enrollment says");

    CHECK(!install(&keyMgr, "{\"publicKeys\":[\"" KEY_A "\"],\"policyId\":\"" OTHER_ORG "\",\"expiresIn\":300}", 1000),
        "a lease for another organization is not installed");
    CHECK(keyMgr.nDeadlineMs == 0 && keyMgr.nKeyCount == 0, "a refused lease leaves nothing behind");

    CHECK(install(&keyMgr, pLeaseA, 1000), "a lease for this organization is installed");
    CHECK(keyMgr.nDeadlineMs == 1000 + 300000, "the deadline is the response time plus the lease lifetime");
    CHECK(DirectGate_KeyManager_IsAuthorized(&keyMgr, ORG_ID, keyA, 1000), "a leased key is authorized");
    CHECK(!DirectGate_KeyManager_IsAuthorized(&keyMgr, ORG_ID, keyB, 1000), "a key outside the lease is not");
    CHECK(!DirectGate_KeyManager_IsAuthorized(&keyMgr, OTHER_ORG, keyA, 1000), "the lease is only good for its organization");
    CHECK(!DirectGate_KeyManager_IsAuthorized(&keyMgr, "", keyA, 1000) &&
        !DirectGate_KeyManager_IsAuthorized(&keyMgr, NULL, keyA, 1000), "a device outside any organization takes no lease");
    CHECK(DirectGate_KeyManager_IsAuthorized(&keyMgr, ORG_ID, keyA, 1000 + 299999) &&
        !DirectGate_KeyManager_IsAuthorized(&keyMgr, ORG_ID, keyA, 1000 + 300000), "the deadline itself is already expired");
    CHECK(!DirectGate_KeyManager_IsAuthorized(NULL, ORG_ID, keyA, 1000) &&
        !DirectGate_KeyManager_IsAuthorized(&keyMgr, ORG_ID, NULL, 1000), "missing arguments authorize nothing");

    uint32_t nGenA = keyMgr.nGeneration;
    uint32_t nSessionGen = nGenA;
    CHECK(DirectGate_KeyManager_Recheck(&keyMgr, keyA, &nSessionGen, 2000), "a session on a leased key passes its check");

    /* A renewal of the same set moves only the deadline, so sessions are not rescanned every minute. */
    CHECK(install(&keyMgr, pLeaseA, 60000), "the same lease is renewed");
    CHECK(keyMgr.nGeneration == nGenA && keyMgr.nDeadlineMs == 60000 + 300000,
        "a renewal keeps the generation and moves the deadline");

    CHECK(install(&keyMgr, pLeaseB, 61000), "a different lease replaces the set");
    CHECK(keyMgr.nGeneration != nGenA, "a changed set moves the generation");
    CHECK(!DirectGate_KeyManager_IsAuthorized(&keyMgr, ORG_ID, keyA, 61000), "a key the new lease dropped is refused");
    CHECK(!DirectGate_KeyManager_Recheck(&keyMgr, keyA, &nSessionGen, 61000), "a session on a dropped key fails its check");
    nSessionGen = nGenA;
    CHECK(DirectGate_KeyManager_Recheck(&keyMgr, keyB, &nSessionGen, 61000) && nSessionGen == keyMgr.nGeneration,
        "a session on a kept key passes and remembers the generation it was found in");
    CHECK(!DirectGate_KeyManager_Recheck(&keyMgr, keyB, &nSessionGen, keyMgr.nDeadlineMs),
        "a current generation does not outlive the deadline");

    CHECK(install(&keyMgr, pEmpty, 62000), "an empty lease is installed");
    CHECK(keyMgr.nKeyCount == 0 && keyMgr.nDeadlineMs > 0, "an empty lease is a lease that authorizes nobody");
    CHECK(!DirectGate_KeyManager_IsAuthorized(&keyMgr, ORG_ID, keyB, 62000), "an empty lease authorizes nobody");

    CHECK(install(&keyMgr, pLeaseA, 63000), "reinstall a key");
    CHECK(!install(&keyMgr, "{\"publicKeys\":[\"" KEY_A "\"],\"policyId\":\"" ORG_ID "\","
        "\"expiresAt\":\"2000-01-01T00:00:00.000Z\"}", 64000), "a lease that arrives expired is not installed");
    CHECK(keyMgr.nDeadlineMs == 0 && !DirectGate_KeyManager_IsAuthorized(&keyMgr, ORG_ID, keyA, 64000),
        "and it drops the lease that was there, rather than keeping it");

    /* The event loop expires the lease on the monotonic clock. */
    CHECK(install(&keyMgr, pLeaseA, 70000), "reinstall the lease");
    uint32_t nGenBefore = keyMgr.nGeneration;
    DirectGate_KeyManager_Sync(&keyMgr, &cfg, 70000 + 299999);
    CHECK(keyMgr.nDeadlineMs > 0, "a lease is kept until its deadline");
    DirectGate_KeyManager_Sync(&keyMgr, &cfg, 70000 + 300000);
    CHECK(keyMgr.nDeadlineMs == 0 && keyMgr.nKeyCount == 0 && keyMgr.nGeneration != nGenBefore,
        "at the deadline the lease is dropped and sessions are told");

    /* Leaving the organization, or being revoked out of it, drops the lease at once. */
    CHECK(install(&keyMgr, pLeaseA, 80000), "reinstall the lease");
    xstrncpy(cfg.enroll.sOrganizationId, sizeof(cfg.enroll.sOrganizationId), OTHER_ORG);
    DirectGate_KeyManager_Sync(&keyMgr, &cfg, 80000);
    CHECK(keyMgr.nDeadlineMs == 0 && !DirectGate_KeyManager_IsAuthorized(&keyMgr, OTHER_ORG, keyA, 80000),
        "moving to another organization drops the previous one's lease");

    xstrncpy(cfg.enroll.sOrganizationId, sizeof(cfg.enroll.sOrganizationId), ORG_ID);
    DirectGate_KeyManager_Sync(&keyMgr, &cfg, 80000);
    CHECK(install(&keyMgr, pLeaseA, 80000), "reinstall the lease");
    cfg.enroll.sOrganizationId[0] = '\0';
    DirectGate_KeyManager_Sync(&keyMgr, &cfg, 80000);
    CHECK(keyMgr.nDeadlineMs == 0 && keyMgr.sOrganizationId[0] == '\0', "a cleared enrollment drops the lease");

    DirectGate_KeyManager_Destroy(&keyMgr);
    DirectGate_KeyManager_Destroy(&keyMgr);
    DirectGate_KeyManager_Sync(NULL, &cfg, 0);
    DirectGate_KeyManager_Sync(&keyMgr, NULL, 0);
    DirectGate_KeyManager_Destroy(NULL);
    CHECK(!DirectGate_KeyManager_Install(NULL, NULL, 0) && !DirectGate_KeyManager_Recheck(&keyMgr, keyA, NULL, 0),
        "missing arguments install and pass nothing");
    return 0;
}

static int test_classify(void)
{
    char sReason[XSTR_TINY];

    CHECK(DirectGate_KeyManager_Classify(200, NULL, 0, sReason, sizeof(sReason)) == DIRECTGATE_KEYMGR_POLL_LEASE,
        "a 2xx carries a lease");

    static const char *pDenied[] = {
        "DEVICE_ENROLLMENT_EXPIRED", "DEVICE_ENROLLMENT_REVOKED", "DEVICE_NOT_ORGANIZATION_MANAGED",
        "INVALID_REFRESH_TOKEN", "REFRESH_TOKEN_REUSE_DETECTED"
    };

    for (size_t i = 0; i < sizeof(pDenied) / sizeof(pDenied[0]); i++)
    {
        char sBody[128];
        snprintf(sBody, sizeof(sBody), "{\"message\":\"no\",\"code\":\"%s\"}", pDenied[i]);
        CHECK(DirectGate_KeyManager_Classify(403, (const uint8_t*)sBody, strlen(sBody), sReason, sizeof(sReason)) ==
            DIRECTGATE_KEYMGR_POLL_DENIED && !strcmp(sReason, pDenied[i]), "an API device code is a refusal, named by it");
    }

    /* A CDN or WAF edge answers 403 too; dropping every managed session on that would hand the path a kill switch. */
    const char *pWaf = "<html><body>Access denied</body></html>";
    const char *pNoCode = "{\"message\":\"Forbidden\"}";
    const char *pOther = "{\"code\":\"SOMETHING_ELSE\"}";
    const char *pRevoked = "{\"code\":\"DEVICE_ENROLLMENT_REVOKED\"}";

    CHECK(DirectGate_KeyManager_Classify(403, (const uint8_t*)pWaf, strlen(pWaf), sReason, sizeof(sReason)) ==
        DIRECTGATE_KEYMGR_POLL_TRANSIENT && !strcmp(sReason, "http-403"), "a 403 that is not the API's is transient");
    CHECK(DirectGate_KeyManager_Classify(403, (const uint8_t*)pNoCode, strlen(pNoCode), sReason, sizeof(sReason)) ==
        DIRECTGATE_KEYMGR_POLL_TRANSIENT, "a 4xx without a code is transient");
    CHECK(DirectGate_KeyManager_Classify(400, (const uint8_t*)pOther, strlen(pOther), sReason, sizeof(sReason)) ==
        DIRECTGATE_KEYMGR_POLL_TRANSIENT, "a code that is not about the device is transient");
    CHECK(DirectGate_KeyManager_Classify(403, NULL, 0, sReason, sizeof(sReason)) == DIRECTGATE_KEYMGR_POLL_TRANSIENT,
        "a 4xx with no body is transient");
    CHECK(DirectGate_KeyManager_Classify(503, (const uint8_t*)pRevoked, strlen(pRevoked), sReason, sizeof(sReason)) ==
        DIRECTGATE_KEYMGR_POLL_TRANSIENT, "a 5xx is transient whatever it says");
    CHECK(DirectGate_KeyManager_Classify(302, NULL, 0, NULL, 0) == DIRECTGATE_KEYMGR_POLL_TRANSIENT,
        "a redirect is not followed and not a lease");
    return 0;
}

static int has_keys(const directgate_keymgr_t *pKeyMgr, uint16_t nCount)
{
    return pKeyMgr->nDeadlineMs > 0 && pKeyMgr->nKeyCount == nCount;
}

/* Runs the event loop's half until the last result is eResult and the key count is nCount (or any, for -1). */
static int pump(directgate_keymgr_t *pKeyMgr, const directgate_cfg_t *pCfg, directgate_keymgr_poll_t eResult, int nCount)
{
    uint64_t nEndMs = XTime_GetMonoMs() + PUMP_MS;

    while (XTime_GetMonoMs() < nEndMs)
    {
        DirectGate_KeyManager_Sync(pKeyMgr, pCfg, XTime_GetMonoMs());
        if (pKeyMgr->eLastPoll == eResult && (nCount < 0 || pKeyMgr->nKeyCount == (uint16_t)nCount)) return 1;
        xusleep(10000);
    }

    return 0;
}

/* Hands the worker a new refresh token, which is what makes it poll at once rather than at its next interval. */
static void rotate(directgate_cfg_t *pCfg, directgate_keymgr_t *pKeyMgr, const char *pToken)
{
    xstrncpy(pCfg->enroll.sRefreshToken, sizeof(pCfg->enroll.sRefreshToken), pToken);
    pKeyMgr->eLastPoll = DIRECTGATE_KEYMGR_POLL_NONE;
}

static int test_worker(fake_https_t *pApi)
{
    uint8_t keyA[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    CHECK(decode(KEY_A, keyA), "the fixture key decodes");

    directgate_cfg_t cfg;
    init_cfg(&cfg, ORG_ID);
    cfg.enroll.bEnrolled = XTRUE;
    xstrncpy(cfg.enroll.sApiUrl, sizeof(cfg.enroll.sApiUrl), pApi->sUrl);
    xstrncpy(cfg.enroll.sRefreshToken, sizeof(cfg.enroll.sRefreshToken), "refresh-managed");

    const char *pLeaseA = "{\"publicKeys\":[\"" KEY_A "\"],\"policyId\":\"" ORG_ID "\","
        "\"expiresAt\":\"2099-01-01T00:00:00.000Z\",\"expiresIn\":300}";
    const char *pLeaseAB = "{\"publicKeys\":[\"" KEY_A "\",\"" KEY_B "\"],\"policyId\":\"" ORG_ID "\","
        "\"expiresAt\":\"2099-01-01T00:00:00.000Z\",\"expiresIn\":300}";
    fake_https_reply(pApi, 200, "application/json", pLeaseA);

    directgate_keymgr_t keyMgr;
    DirectGate_KeyManager_Init(&keyMgr);
    DirectGate_KeyManager_AllowWorker(&keyMgr);

    CHECK(pump(&keyMgr, &cfg, DIRECTGATE_KEYMGR_POLL_LEASE, 1), "the worker fetches the lease and the event loop installs it");
    CHECK(keyMgr.pWorker != NULL && has_keys(&keyMgr, 1), "an organization enrollment starts the worker");
    CHECK(DirectGate_KeyManager_IsAuthorized(&keyMgr, ORG_ID, keyA, XTime_GetMonoMs()), "the fetched key is authorized");

    fake_https_t request;
    int nRequests = fake_https_last(pApi, &request);
    CHECK(nRequests >= 1 && !strcmp(request.sUri, "/api/v1/devices/managed-keys"), "the lease comes from the managed-keys route");
    CHECK(strstr(request.sBody, "\"refreshToken\":\"refresh-managed\"") != NULL,
        "the device proves itself with its refresh token");
    CHECK(strstr(request.sBody, "appliedPolicyId") == NULL, "nothing is acknowledged before anything was applied");
    CHECK(strstr(pApi->sUrl, request.sHost) != NULL && request.sHost[0] != '\0', "the request names its host, as edges require");

    /* A rotation is taken at once, and the acknowledgement survives it: it is still the same enrollment. */
    fake_https_reply(pApi, 200, "application/json", pLeaseAB);
    rotate(&cfg, &keyMgr, "refresh-rotated");
    CHECK(pump(&keyMgr, &cfg, DIRECTGATE_KEYMGR_POLL_LEASE, 2), "a rotated refresh token is used at once, not a minute later");
    CHECK(fake_https_last(pApi, &request) > nRequests, "the rotation made a new request");
    CHECK(strstr(request.sBody, "\"refreshToken\":\"refresh-rotated\"") != NULL, "the new request carries the rotated token");
    CHECK(strstr(request.sBody, "\"appliedPolicyId\":\"" ORG_ID "\"") != NULL &&
        strstr(request.sBody, "\"appliedExpiresAt\":\"2099-01-01T00:00:00.000Z\"") != NULL,
        "the device acknowledges the lease it enforces");

    /* A refusal by code drops the lease at once, before its deadline. */
    fake_https_reply(pApi, 403, "application/json", "{\"message\":\"revoked\",\"code\":\"DEVICE_ENROLLMENT_REVOKED\"}");
    rotate(&cfg, &keyMgr, "refresh-3");
    CHECK(pump(&keyMgr, &cfg, DIRECTGATE_KEYMGR_POLL_DENIED, 0), "a revoked device gets a refusal");
    CHECK(keyMgr.nDeadlineMs == 0 && !DirectGate_KeyManager_IsAuthorized(&keyMgr, ORG_ID, keyA, XTime_GetMonoMs()),
        "a refusal by the API drops the lease without waiting for it to expire");

    fake_https_reply(pApi, 200, "application/json", pLeaseA);
    rotate(&cfg, &keyMgr, "refresh-4");
    CHECK(pump(&keyMgr, &cfg, DIRECTGATE_KEYMGR_POLL_LEASE, 1), "a new lease after a refusal is installed");

    /* What is not the API's word about the device keeps the lease to its deadline, and no further. */
    fake_https_reply(pApi, 403, "text/html", "<html>blocked by the edge</html>");
    rotate(&cfg, &keyMgr, "refresh-5");
    CHECK(pump(&keyMgr, &cfg, DIRECTGATE_KEYMGR_POLL_TRANSIENT, 1), "a gateway's 403 is a transient failure");
    CHECK(has_keys(&keyMgr, 1) && keyMgr.nDeadlineMs > XTime_GetMonoMs(), "a transient failure keeps the current lease");

    fake_https_reply(pApi, 200, "application/json", "{\"publicKeys\":\"not a list\"}");
    rotate(&cfg, &keyMgr, "refresh-6");
    CHECK(pump(&keyMgr, &cfg, DIRECTGATE_KEYMGR_POLL_TRANSIENT, 1), "an unreadable lease is a transient failure");

    fake_https_reply(pApi, 200, "application/json",
        "{\"publicKeys\":[\"" KEY_B "\"],\"policyId\":\"" OTHER_ORG "\",\"expiresIn\":300}");
    rotate(&cfg, &keyMgr, "refresh-7");
    CHECK(pump(&keyMgr, &cfg, DIRECTGATE_KEYMGR_POLL_LEASE, 1), "a lease for another organization arrives");
    CHECK(DirectGate_KeyManager_IsAuthorized(&keyMgr, ORG_ID, keyA, XTime_GetMonoMs()),
        "a lease for another organization is ignored, the current one stands to its deadline");

    /* Leaving the organization drops the lease and stops the polling. */
    cfg.enroll.sOrganizationId[0] = '\0';
    DirectGate_KeyManager_Sync(&keyMgr, &cfg, XTime_GetMonoMs());
    CHECK(keyMgr.nDeadlineMs == 0, "a device that left its organization drops the lease");
    xusleep(300000);
    nRequests = fake_https_last(pApi, NULL);
    for (int i = 0; i < 60; i++)
    {
        DirectGate_KeyManager_Sync(&keyMgr, &cfg, XTime_GetMonoMs());
        xusleep(10000);
    }
    CHECK(fake_https_last(pApi, NULL) == nRequests, "a device outside any organization asks the API nothing");

    /* The lease decides who gets a shell, so it follows the transport rule pairing follows. */
    if (!DirectGate_IsAPIEndpointAllowed("http://127.0.0.1:1"))
    {
        xstrncpy(cfg.enroll.sOrganizationId, sizeof(cfg.enroll.sOrganizationId), ORG_ID);
        xstrncpy(cfg.enroll.sApiUrl, sizeof(cfg.enroll.sApiUrl), "http://127.0.0.1:1");
        CHECK(pump(&keyMgr, &cfg, DIRECTGATE_KEYMGR_POLL_DENIED, 0), "an unencrypted API endpoint is refused");
        CHECK(fake_https_last(pApi, NULL) == nRequests && keyMgr.nDeadlineMs == 0, "and nothing is fetched over it");
    }

    uint64_t nStartMs = XTime_GetMonoMs();
    DirectGate_KeyManager_Destroy(&keyMgr);
    CHECK(XTime_GetMonoMs() - nStartMs < 1000U, "an idle worker stops promptly");
    CHECK(keyMgr.pWorker == NULL && keyMgr.nDeadlineMs == 0 && keyMgr.pKeys == NULL,
        "destroying drops the worker and the lease");
    return 0;
}

/* A request that never gets an answer: the API's TCP port accepts and then says nothing, so the worker sits in
   the TLS handshake. Shutdown waits a bounded time and moves on; the worker frees its own state once released. */
static int test_stuck_worker(void)
{
    int nListen = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(nListen >= 0, "open a listening socket");

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t nLen = sizeof(addr);
    CHECK(bind(nListen, (struct sockaddr*)&addr, sizeof(addr)) == 0 && listen(nListen, 4) == 0 &&
        getsockname(nListen, (struct sockaddr*)&addr, &nLen) == 0, "listen on a loopback port");

    directgate_cfg_t cfg;
    init_cfg(&cfg, ORG_ID);
    cfg.enroll.bEnrolled = XTRUE;
    snprintf(cfg.enroll.sApiUrl, sizeof(cfg.enroll.sApiUrl), "https://127.0.0.1:%u", (unsigned)ntohs(addr.sin_port));
    xstrncpy(cfg.enroll.sRefreshToken, sizeof(cfg.enroll.sRefreshToken), "refresh-stuck");

    directgate_keymgr_t keyMgr;
    DirectGate_KeyManager_Init(&keyMgr);
    DirectGate_KeyManager_AllowWorker(&keyMgr);
    DirectGate_KeyManager_Sync(&keyMgr, &cfg, XTime_GetMonoMs());
    CHECK(keyMgr.pWorker != NULL, "the worker starts");

    struct pollfd pfd = { nListen, POLLIN, 0 };
    CHECK(poll(&pfd, 1, 10000) == 1, "the worker connects");
    int nPeer = accept(nListen, NULL, NULL);
    CHECK(nPeer >= 0, "accept the worker's connection");

    pfd.fd = nPeer;
    CHECK(poll(&pfd, 1, 10000) == 1, "the worker starts its TLS handshake and waits for an answer");

    uint64_t nStartMs = XTime_GetMonoMs();
    DirectGate_KeyManager_Destroy(&keyMgr);
    uint64_t nTookMs = XTime_GetMonoMs() - nStartMs;
    CHECK(keyMgr.pWorker == NULL, "the owner lets go of a stuck worker");
    CHECK(nTookMs >= 2000U - 100U, "the worker was still inside the request, so the bounded wait ran out");
    CHECK(nTookMs < 2000U + 1500U, "a request stuck on the network holds shutdown only for the bounded wait");

    /* Release the handshake and wait for the worker to close its end: it frees its state right after. */
    shutdown(nPeer, SHUT_WR);
    char sDrain[4096];
    uint64_t nEndMs = XTime_GetMonoMs() + 10000U;
    int nEof = 0;

    while (!nEof && XTime_GetMonoMs() < nEndMs)
    {
        if (poll(&pfd, 1, 100) != 1) continue;
        ssize_t nRead = read(nPeer, sDrain, sizeof(sDrain));
        if (nRead <= 0) nEof = 1;
    }

    close(nPeer);
    close(nListen);
    CHECK(nEof, "the released worker closes its connection");
    xusleep(500000);
    return 0;
}

int main(void)
{
    if (test_parse()) return 1;
    if (test_install()) return 1;
    if (test_classify()) return 1;
    if (test_stuck_worker()) return 1;

    fake_https_t api;
    if (!fake_https_begin(&api))
    {
        fake_https_end(&api);
        fprintf(stderr, "keymgr_smoke: no TLS endpoint could be started, skipping the worker test\n");
        return 77;
    }

    int nStatus = test_worker(&api);
    fake_https_end(&api);
    if (nStatus) return nStatus;

    puts("keymgr_smoke: OK");
    return 0;
}
