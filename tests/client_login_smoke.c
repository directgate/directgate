#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "src/common/includes.h"
#include "src/client/login.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "client_login_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

/* RFC 7636 appendix B: the one published PKCE S256 test vector. Getting this
 * wrong is invisible until the provider rejects every token exchange. */
static const char *g_pRfcVerifier =
    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
static const char *g_pRfcChallenge =
    "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

static int test_pkce(void)
{
    char sChallenge[DIRECTGATE_PKCE_CHALLENGE_SIZE];
    CHECK(DirectGate_Login_Challenge(g_pRfcVerifier, sChallenge, sizeof(sChallenge)),
        "derive RFC 7636 challenge");
    CHECK(strcmp(sChallenge, g_pRfcChallenge) == 0, "RFC 7636 S256 vector");

    CHECK(!DirectGate_Login_Challenge(NULL, sChallenge, sizeof(sChallenge)),
        "reject NULL verifier");
    CHECK(!DirectGate_Login_Challenge(g_pRfcVerifier, sChallenge, 4),
        "reject undersized challenge buffer");

    char sFirst[DIRECTGATE_PKCE_VERIFIER_SIZE];
    char sSecond[DIRECTGATE_PKCE_VERIFIER_SIZE];
    CHECK(DirectGate_Login_NewVerifier(sFirst, sizeof(sFirst)), "generate verifier");
    CHECK(DirectGate_Login_NewVerifier(sSecond, sizeof(sSecond)), "generate second verifier");

    /* 32 bytes of entropy as unpadded base64url */
    CHECK(strlen(sFirst) == 43, "verifier length");
    CHECK(strcmp(sFirst, sSecond) != 0, "verifiers are not reused");
    CHECK(strchr(sFirst, '=') == NULL && strchr(sFirst, '+') == NULL &&
          strchr(sFirst, '/') == NULL, "verifier is url safe and unpadded");
    CHECK(!DirectGate_Login_NewVerifier(sFirst, 8), "reject undersized verifier buffer");

    return 0;
}


static int test_start_url(void)
{
    directgate_login_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.pApiUrl = "https://api.directgate.io";
    ctx.pWebUrl = "https://directgate.io";

    char sUrl[XPATH_MAX];
    CHECK(DirectGate_Login_StartUrl(sUrl, sizeof(sUrl), &ctx, 40777, XFALSE, "chal") > 0,
        "build start URL");

    /* The printed link has to be ours, and the binary must not carry the
     * identity provider's host at all any more. */
    CHECK(strstr(sUrl, "https://directgate.io/cli-auth/start?") == sUrl, "start endpoint");
    CHECK(strstr(sUrl, "port=40777") != NULL, "loopback port");
    CHECK(strstr(sUrl, "mode=loopback") != NULL, "loopback mode");
    CHECK(strstr(sUrl, "challenge=chal") != NULL, "challenge parameter");
    CHECK(strstr(sUrl, "supabase") == NULL, "start URL never leaks the provider host");

    /* redirect_to is rebuilt by the page, so it must never be a parameter */
    CHECK(strstr(sUrl, "redirect_to") == NULL, "no caller supplied redirect");

    CHECK(DirectGate_Login_StartUrl(sUrl, sizeof(sUrl), &ctx, 40780, XTRUE, "chal") > 0,
        "build paste-mode start URL");
    CHECK(strstr(sUrl, "mode=paste") != NULL, "paste mode");
    CHECK(strstr(sUrl, "port=40780") != NULL, "paste mode keeps the port");

    ctx.pProvider = "google";
    CHECK(DirectGate_Login_StartUrl(sUrl, sizeof(sUrl), &ctx, 40777, XFALSE, "chal") > 0,
        "build with default provider");
    CHECK(strstr(sUrl, "provider=") == NULL, "default provider stays implicit");

    ctx.pProvider = "github";
    CHECK(DirectGate_Login_StartUrl(sUrl, sizeof(sUrl), &ctx, 40777, XFALSE, "chal") > 0,
        "build with explicit provider");
    CHECK(strstr(sUrl, "provider=github") != NULL, "explicit provider is carried");

    /* Without a web URL the caller has to fall back to the provider URL */
    ctx.pWebUrl = NULL;
    CHECK(!DirectGate_Login_StartUrl(sUrl, sizeof(sUrl), &ctx, 40777, XFALSE, "chal"),
        "reject missing web URL");

    ctx.pWebUrl = "https://directgate.io";
    CHECK(!DirectGate_Login_StartUrl(sUrl, sizeof(sUrl), &ctx, 0, XFALSE, "chal"),
        "reject zero port");
    CHECK(!DirectGate_Login_StartUrl(sUrl, sizeof(sUrl), &ctx, 40777, XFALSE, NULL),
        "reject missing challenge");
    CHECK(!DirectGate_Login_StartUrl(sUrl, sizeof(sUrl), NULL, 40777, XFALSE, "chal"),
        "reject NULL context");

    return 0;
}

static int test_parse_request(void)
{
    char sCode[256];
    char sError[128];

    CHECK(DirectGate_Login_ParseRequest(
        "GET /callback?code=abc123 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        sCode, sizeof(sCode), sError, sizeof(sError)), "parse GET redirect");
    CHECK(strcmp(sCode, "abc123") == 0, "GET code value");

    CHECK(DirectGate_Login_ParseRequest(
        "GET /callback?state=x&code=pkce%2Fcode%3D1&extra=y HTTP/1.1\r\n\r\n",
        sCode, sizeof(sCode), sError, sizeof(sError)), "parse encoded code");
    CHECK(strcmp(sCode, "pkce/code=1") == 0, "percent decoded code");

    /* The bounce page hands the code over as a JSON body instead */
    CHECK(DirectGate_Login_ParseRequest(
        "POST /callback HTTP/1.1\r\nContent-Type: text/plain\r\n"
        "Content-Length: 20\r\n\r\n{\"code\":\"posted-1\"}",
        sCode, sizeof(sCode), sError, sizeof(sError)), "parse POST handoff");
    CHECK(strcmp(sCode, "posted-1") == 0, "POST code value");

    CHECK(!DirectGate_Login_ParseRequest(
        "GET /callback?error=access_denied&error_description=User+declined HTTP/1.1\r\n\r\n",
        sCode, sizeof(sCode), sError, sizeof(sError)), "reject provider error");
    CHECK(strcmp(sError, "User declined") == 0, "provider error reason");

    CHECK(!DirectGate_Login_ParseRequest("GET /favicon.ico HTTP/1.1\r\n\r\n",
        sCode, sizeof(sCode), sError, sizeof(sError)), "ignore unrelated request");
    CHECK(sCode[0] == '\0', "unrelated request leaves no code");

    CHECK(!DirectGate_Login_ParseRequest(NULL, sCode, sizeof(sCode), sError, sizeof(sError)),
        "reject NULL request");
    CHECK(!DirectGate_Login_ParseRequest("garbage", sCode, sizeof(sCode), sError, sizeof(sError)),
        "reject malformed request");

    return 0;
}

static int test_apply_token(void)
{
    directgate_account_t account;
    DirectGate_Account_Init(&account);

    /* The API normalises the provider payload, so this is the only shape the
     * CLI ever parses - no GoTrue snake_case, no relative expiry. */
    const char *pBody =
        "{\"accessToken\":\"jwt-value\",\"refreshToken\":\"refresh-value\","
        "\"expiresAt\":2000000000,\"email\":\"kala@example.test\","
        "\"userId\":\"user-1\"}";

    xjson_t json;
    CHECK(XJSON_Parse(&json, NULL, pBody, strlen(pBody)), "parse session body");
    CHECK(DirectGate_Login_ApplyToken(&account, json.pRootObj), "apply session body");
    XJSON_Destroy(&json);

    CHECK(strcmp(account.sAccessToken, "jwt-value") == 0, "access token");
    CHECK(strcmp(account.sRefreshToken, "refresh-value") == 0, "refresh token");
    CHECK(strcmp(account.sEmail, "kala@example.test") == 0, "account email");
    CHECK(strcmp(account.sUserId, "user-1") == 0, "account user id");
    CHECK(account.nExpiresAt == 2000000000ULL, "absolute expiry");

    /* A session without an expiry is usable; the API decides, not the clock */
    const char *pMinimal =
        "{\"accessToken\":\"jwt-2\",\"refreshToken\":\"r2\"}";

    DirectGate_Account_Init(&account);
    CHECK(XJSON_Parse(&json, NULL, pMinimal, strlen(pMinimal)), "parse minimal body");
    CHECK(DirectGate_Login_ApplyToken(&account, json.pRootObj), "apply minimal body");
    XJSON_Destroy(&json);

    CHECK(account.nExpiresAt == 0, "missing expiry stays unknown");
    CHECK(!DirectGate_Account_IsExpired(&account, 60), "unknown expiry is live");

    /* The provider's own field names must no longer be accepted, or a
     * regression in the API contract would pass silently here. */
    const char *pLegacy =
        "{\"access_token\":\"jwt-3\",\"refresh_token\":\"r3\"}";

    DirectGate_Account_Init(&account);
    CHECK(XJSON_Parse(&json, NULL, pLegacy, strlen(pLegacy)), "parse legacy body");
    CHECK(!DirectGate_Login_ApplyToken(&account, json.pRootObj),
        "reject the raw provider payload shape");
    XJSON_Destroy(&json);

    const char *pBroken = "{\"refreshToken\":\"r\"}";
    DirectGate_Account_Init(&account);
    CHECK(XJSON_Parse(&json, NULL, pBroken, strlen(pBroken)), "parse broken body");
    CHECK(!DirectGate_Login_ApplyToken(&account, json.pRootObj),
        "reject a session without an access token");
    XJSON_Destroy(&json);

    CHECK(!DirectGate_Login_ApplyToken(NULL, NULL), "reject NULL arguments");
    return 0;
}

static int test_account_store(const char *pRoot)
{
    char sPath[XPATH_MAX];
    snprintf(sPath, sizeof(sPath), "%s/auth.json", pRoot);

    directgate_account_t account;
    DirectGate_Account_Init(&account);
    CHECK(!DirectGate_Account_Load(&account, sPath), "load missing account");
    CHECK(DirectGate_Account_Forget(sPath), "forget missing account is a no-op");

    xstrncpy(account.sAccessToken, sizeof(account.sAccessToken), "access-1");
    xstrncpy(account.sRefreshToken, sizeof(account.sRefreshToken), "refresh-1");
    xstrncpy(account.sEmail, sizeof(account.sEmail), "kala@example.test");
    xstrncpy(account.sUserId, sizeof(account.sUserId), "user-1");
    account.nExpiresAt = 2000000000ULL;

    CHECK(DirectGate_Account_Save(&account, sPath), "save account");

    directgate_account_t loaded;
    CHECK(DirectGate_Account_Load(&loaded, sPath), "load account");
    CHECK(strcmp(loaded.sAccessToken, "access-1") == 0, "round trip access token");
    CHECK(strcmp(loaded.sRefreshToken, "refresh-1") == 0, "round trip refresh token");
    CHECK(strcmp(loaded.sEmail, "kala@example.test") == 0, "round trip email");
    CHECK(loaded.nExpiresAt == 2000000000ULL, "round trip expiry");

    /* Credentials must never be world readable */
    struct stat info;
    CHECK(stat(sPath, &info) == 0, "stat account file");
#ifndef _WIN32
    CHECK((info.st_mode & 0077) == 0, "account file is private");
#endif

    CHECK(!DirectGate_Account_IsExpired(&loaded, 60), "future expiry is live");
    loaded.nExpiresAt = 1000;
    CHECK(DirectGate_Account_IsExpired(&loaded, 60), "past expiry is stale");

    /* An unknown expiry is optimistic: the API decides, not the clock */
    loaded.nExpiresAt = 0;
    CHECK(!DirectGate_Account_IsExpired(&loaded, 60), "unknown expiry is live");
    loaded.sAccessToken[0] = '\0';
    CHECK(DirectGate_Account_IsExpired(&loaded, 60), "missing token is expired");
    CHECK(DirectGate_Account_IsExpired(NULL, 60), "NULL account is expired");

    DirectGate_Account_Cleanse(&account);
    CHECK(account.sAccessToken[0] == '\0' && account.sRefreshToken[0] == '\0',
        "cleanse clears the tokens");
    CHECK(strcmp(account.sEmail, "kala@example.test") == 0,
        "cleanse keeps the non-secret identity");

    CHECK(DirectGate_Account_Forget(sPath), "forget account");
    CHECK(!XPath_Exists(sPath), "account file removed");

    return 0;
}

int main(void)
{
    xlog_setfl(XLOG_NONE);

    int nStatus = test_pkce();
    if (nStatus) return nStatus;

    nStatus = test_start_url();
    if (nStatus) return nStatus;

    nStatus = test_parse_request();
    if (nStatus) return nStatus;

    nStatus = test_apply_token();
    if (nStatus) return nStatus;

    char sRoot[] = "/tmp/directgate_client_login.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "mkdtemp");

    nStatus = test_account_store(sRoot);
    if (nStatus) return nStatus;

    CHECK(rmdir(sRoot) == 0, "rmdir root");

    puts("client_login_smoke: OK");
    return 0;
}
