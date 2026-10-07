/* What enrollment refuses before it reaches the API: pairing, refresh and key rotation with each piece of the
 * configuration they need missing in turn, token checks on an agent that is not enrolled, request building with no
 * handle or no address, token responses with nothing in them, and the trace and body helpers with nothing to work
 * on. Includes enroll.c for the internal helpers. */

#include <stdio.h>
#include "src/agent/enroll.c"

#define CHECK(c, msg) \
    do { if (!(c)) { fprintf(stderr, "enroll_guards_smoke: %s (line %d)\n", msg, __LINE__); return 1; } } while (0)

static void enrolled(directgate_cfg_t *pCfg)
{
    DirectGate_InitConfig(pCfg);
    xstrncpy(pCfg->sDeviceId, sizeof(pCfg->sDeviceId), "device");
    xstrncpy(pCfg->enroll.sApiUrl, sizeof(pCfg->enroll.sApiUrl), "https://api.example.test");
    xstrncpy(pCfg->enroll.sRefreshToken, sizeof(pCfg->enroll.sRefreshToken), "refresh");
    xstrncpy(pCfg->enroll.sAccessToken, sizeof(pCfg->enroll.sAccessToken), "access");
    xstrncpy(pCfg->keyauth.sIdentityPubB64, sizeof(pCfg->keyauth.sIdentityPubB64), "AGENTPUB");
    pCfg->enroll.bEnrolled = XTRUE;
    pCfg->enroll.nAccessTokenExp = 1;
}

static int check_helpers(void)
{
    CHECK(DirectGate_Enroll_GetDeviceId(NULL) == NULL && DirectGate_Enroll_GetApiUrl(NULL) == NULL &&
          DirectGate_Enroll_GetRelayUrl(NULL) == NULL && !DirectGate_Enroll_ValidateAPIEndpoint(NULL),
        "no configuration has nothing to read");

    /* The trace keeps the address a name resolved to, and nothing else */
    directgate_enroll_trace_t trace;
    memset(&trace, 0, sizeof(trace));
    xhttp_t http;
    memset(&http, 0, sizeof(http));
    xhttp_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    CHECK(DirectGate_Enroll_TraceCb(NULL, &ctx) == XSTDOK && DirectGate_Enroll_TraceCb(&http, NULL) == XSTDOK &&
          DirectGate_Enroll_TraceCb(&http, &ctx) == XSTDOK, "a trace without a record is let go");
    http.pUserCtx = &trace;
    ctx.eStatus = XHTTP_CONNECTED;
    CHECK(DirectGate_Enroll_TraceCb(&http, &ctx) == XSTDOK && trace.sPeer[0] == '\0', "only a resolution is kept");
    ctx.eStatus = XHTTP_RESOLVED;
    CHECK(DirectGate_Enroll_TraceCb(&http, &ctx) == XSTDOK && trace.sPeer[0] == '\0', "and one that says where");
    ctx.pData = (void*)"192.0.2.1";
    CHECK(DirectGate_Enroll_TraceCb(&http, &ctx) == XSTDOK && strcmp(trace.sPeer, "192.0.2.1") == 0, "is kept");

    CHECK(!DirectGate_Enroll_BuildRequest(NULL, "https://api.example.test", "/x"), "a request needs a handle");
    CHECK(DirectGate_Enroll_Perform(NULL, &trace, "https://api.example.test", "/x", NULL, 0, 1) == XHTTP_EINIT &&
          DirectGate_Enroll_Perform(&http, NULL, "https://api.example.test", "/x", NULL, 0, 1) == XHTTP_EINIT,
        "and a trace");
    CHECK(DirectGate_Enroll_Perform(&http, &trace, "", "/x", NULL, 0, 1) == XHTTP_ELINK &&
          DirectGate_Enroll_Perform(&http, &trace, "https://api.example.test", "", NULL, 0, 1) == XHTTP_ELINK,
        "and somewhere to send it");

    /* A reason buffer the caller says has no room is not written at all, not even its terminator */
    char sReason[16] = "kept";
    DirectGate_Enroll_SetReason(NULL, sizeof(sReason), "x");
    DirectGate_Enroll_SetReason(sReason, 0, "x");
    CHECK(strcmp(sReason, "kept") == 0, "a reason needs room");
    directgate_cfg_t cfg;
    DirectGate_InitConfig(&cfg);
    CHECK(DirectGate_Enroll_ClassifyRefreshFailure(&cfg, 500, NULL, 0, sReason, 0) == DIRECTGATE_ENROLL_REFRESH_TRANSIENT &&
          strcmp(sReason, "kept") == 0, "nor by a refresh failure that has no room for why");
    DirectGate_Enroll_LogErrorBody("", (const uint8_t*)"x", 1);
    DirectGate_Enroll_LogErrorBody("label", NULL, 1);
    DirectGate_Enroll_LogErrorBody("label", (const uint8_t*)"x", 0);

    directgate_enroll_field_t field = { "k", "v" };
    size_t nLen = 0;
    CHECK(DirectGate_Enroll_BuildBody(NULL, 1, &nLen) == NULL && DirectGate_Enroll_BuildBody(&field, 0, &nLen) == NULL &&
          DirectGate_Enroll_BuildBody(&field, 1, NULL) == NULL, "a body needs fields and a length");
    return 0;
}

static int check_responses(void)
{
    directgate_cfg_t cfg;
    enrolled(&cfg);

    xjson_t json;
    const char *pDoc = "{\"expiresAt\":\"not a date\",\"iceServers\":\"stun:not-a-list\"}";
    CHECK(XJSON_Parse(&json, NULL, pDoc, strlen(pDoc)), "parse a response");
    uint64_t nExpiry = 7;
    CHECK(!DirectGate_Enroll_ParseExpiry(NULL, "expiresAt", &nExpiry) &&
          !DirectGate_Enroll_ParseExpiry(json.pRootObj, "expiresAt", NULL), "an expiry needs a response and a place");
    CHECK(!DirectGate_Enroll_ParseExpiry(json.pRootObj, "expiresAt", &nExpiry), "and a date");

    uint8_t nIce = cfg.nIceSrvCount;
    DirectGate_Enroll_LoadIceServers(NULL, json.pRootObj);
    DirectGate_Enroll_LoadIceServers(&cfg, NULL);
    DirectGate_Enroll_LoadIceServers(&cfg, json.pRootObj);
    CHECK(cfg.nIceSrvCount == nIce, "ICE servers that are not a list change nothing");
    XJSON_Destroy(&json);

    const uint8_t body[] = "{}";
    CHECK(!DirectGate_Enroll_ApplyTokenResponse(NULL, body, sizeof(body), XTRUE) &&
          !DirectGate_Enroll_ApplyTokenResponse(&cfg, NULL, sizeof(body), XTRUE) &&
          !DirectGate_Enroll_ApplyTokenResponse(&cfg, body, 0, XTRUE), "a token response needs a body");

    char sReason[64];
    CHECK(DirectGate_Enroll_ClassifyRefreshFailure(NULL, 401, body, sizeof(body), sReason, sizeof(sReason)) ==
          DIRECTGATE_ENROLL_REFRESH_TRANSIENT, "a failure for no configuration is transient");
    CHECK(DirectGate_Enroll_ClassifyRefreshFailure(&cfg, 401, NULL, 1, sReason, sizeof(sReason)) ==
          DIRECTGATE_ENROLL_REFRESH_TRANSIENT &&
          DirectGate_Enroll_ClassifyRefreshFailure(&cfg, 401, body, 0, sReason, sizeof(sReason)) ==
          DIRECTGATE_ENROLL_REFRESH_TRANSIENT, "and so is one with no body to read");
    return 0;
}

static int check_requests(void)
{
    directgate_cfg_t cfg;
    char sReason[64];

    CHECK(!DirectGate_Enroll_Pair(NULL, "token"), "no configuration, no pairing");
    enrolled(&cfg);
    CHECK(!DirectGate_Enroll_Pair(&cfg, ""), "nor without a pairing token");
    cfg.sDeviceId[0] = '\0';
    CHECK(!DirectGate_Enroll_Pair(&cfg, "token"), "nor without a device");
    enrolled(&cfg);
    cfg.enroll.sApiUrl[0] = '\0';
    CHECK(!DirectGate_Enroll_Pair(&cfg, "token"), "nor without an API");

    /* A key rotation needs each of device, API, refresh token and the new key */
    CHECK(!DirectGate_Enroll_RotateAgentKey(NULL), "no configuration, no rotation");
    for (int i = 0; i < 4; i++)
    {
        enrolled(&cfg);
        if (i == 0) cfg.sDeviceId[0] = '\0';
        if (i == 1) cfg.enroll.sApiUrl[0] = '\0';
        if (i == 2) cfg.enroll.sRefreshToken[0] = '\0';
        if (i == 3) cfg.keyauth.sIdentityPubB64[0] = '\0';
        CHECK(!DirectGate_Enroll_RotateAgentKey(&cfg), "a rotation missing anything is not sent");
    }

    /* A refresh is terminal when it can never work, transient when it only cannot now */
    CHECK(DirectGate_Enroll_Refresh(NULL, sReason, sizeof(sReason)) == DIRECTGATE_ENROLL_REFRESH_TRANSIENT,
        "no configuration is a transient failure");
    enrolled(&cfg);
    cfg.enroll.bEnrolled = XFALSE;
    CHECK(DirectGate_Enroll_Refresh(&cfg, sReason, sizeof(sReason)) == DIRECTGATE_ENROLL_REFRESH_TERMINAL, "unenrolled is final");
    enrolled(&cfg);
    cfg.sDeviceId[0] = '\0';
    CHECK(DirectGate_Enroll_Refresh(&cfg, sReason, sizeof(sReason)) == DIRECTGATE_ENROLL_REFRESH_TERMINAL, "so is no device");
    enrolled(&cfg);
    cfg.enroll.sApiUrl[0] = '\0';
    CHECK(DirectGate_Enroll_Refresh(&cfg, sReason, sizeof(sReason)) == DIRECTGATE_ENROLL_REFRESH_TRANSIENT, "no API is not");
    enrolled(&cfg);
    cfg.enroll.sRefreshToken[0] = '\0';
    CHECK(DirectGate_Enroll_Refresh(&cfg, sReason, sizeof(sReason)) == DIRECTGATE_ENROLL_REFRESH_TERMINAL,
        "and no refresh token is final");

    /* What an agent that is not enrolled, or has no token, says about its token */
    CHECK(!DirectGate_Enroll_IsEnrolled(NULL) && !DirectGate_Enroll_AccessTokenIsUsable(NULL) &&
          !DirectGate_Enroll_NeedsRefresh(NULL), "no configuration has no token");
    enrolled(&cfg);
    cfg.enroll.sRefreshToken[0] = '\0';
    CHECK(!DirectGate_Enroll_IsEnrolled(&cfg), "without a refresh token it is not enrolled");
    enrolled(&cfg);
    cfg.enroll.bEnrolled = XFALSE;
    CHECK(!DirectGate_Enroll_AccessTokenIsUsable(&cfg) && !DirectGate_Enroll_NeedsRefresh(&cfg), "nor is an unenrolled one");
    enrolled(&cfg);
    cfg.enroll.sAccessToken[0] = '\0';
    CHECK(!DirectGate_Enroll_AccessTokenIsUsable(&cfg), "an access token that is not there is no use");
    enrolled(&cfg);
    cfg.enroll.nAccessTokenExp = 0;
    CHECK(!DirectGate_Enroll_AccessTokenIsUsable(&cfg) && !DirectGate_Enroll_NeedsRefresh(&cfg),
        "and one without an expiry is not refreshed on a clock");
    return 0;
}

int main(void)
{
    if (check_helpers() || check_responses() || check_requests()) return 1;
    puts("enroll_guards_smoke: OK");
    return 0;
}
