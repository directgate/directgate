/* What dgcli's sign-in refuses: account files and tokens with no account or no path, PKCE values with no room,
 * callback requests that are cut short, carry another flow's state, post from an unexpected origin or carry a code
 * no authorization code looks like, and every sign-in entry point without what it needs. Includes login.c for the
 * request parsers. */

#include <stdio.h>
#include <unistd.h>

#include "src/client/login.c"

#define CHECK(c, msg) \
    do { if (!(c)) { fprintf(stderr, "client_login_guards_smoke: %s (line %d)\n", msg, __LINE__); return 1; } } while (0)

static int check_account(void)
{
    directgate_account_t account;
    DirectGate_Account_Init(NULL);
    DirectGate_Account_Cleanse(NULL);
    DirectGate_Account_Init(&account);

    CHECK(!DirectGate_Account_Load(NULL, "/tmp/x") && !DirectGate_Account_Load(&account, ""), "nothing loads from nowhere");
    CHECK(!DirectGate_Account_Save(NULL, "/tmp/x") && !DirectGate_Account_Save(&account, ""), "nor saves");
    CHECK(!DirectGate_Account_Forget(""), "nor is forgotten");

    /* An account file that does not say when its token expires has no expiry */
    char sPath[] = "/tmp/directgate_login_guards.XXXXXX";
    int nFd = mkstemp(sPath);
    CHECK(nFd >= 0, "make an account file");
    const char *pDoc = "{\"accessToken\":\"a\",\"refreshToken\":\"r\"}";
    CHECK(write(nFd, pDoc, strlen(pDoc)) == (ssize_t)strlen(pDoc), "write it");
    close(nFd);
    CHECK(DirectGate_Account_Load(&account, sPath) && account.nExpiresAt == 0, "an account without an expiry has none");
    unlink(sPath);

    char sOut[128];
    CHECK(!DirectGate_Login_NewVerifier(NULL, sizeof(sOut)) && !DirectGate_Login_NewVerifier(sOut, 0), "a verifier needs room");
    CHECK(!DirectGate_Login_Challenge("verifier", NULL, sizeof(sOut)) && !DirectGate_Login_Challenge("verifier", sOut, 0),
        "and so does its challenge");

    directgate_login_ctx_t ctx = { "https://api.example.test", "https://web.example.test", NULL, XFALSE };
    CHECK(DirectGate_Login_StartUrl(NULL, sizeof(sOut), &ctx, 1234, XFALSE, "c", "s") == 0 &&
          DirectGate_Login_StartUrl(sOut, 0, &ctx, 1234, XFALSE, "c", "s") == 0, "and the start address");

    CHECK(!DirectGate_Login_ApplyToken(&account, NULL), "a token response needs a body");
    DirectGate_Account_Cleanse(&account);
    return 0;
}

static int check_parsers(void)
{
    char sOut[64];
    CHECK(!DirectGate_Login_QueryValue(NULL, "k", sOut, sizeof(sOut)) &&
          !DirectGate_Login_QueryValue("k=v", NULL, sOut, sizeof(sOut)) &&
          !DirectGate_Login_QueryValue("k=v", "k", NULL, sizeof(sOut)) && !DirectGate_Login_QueryValue("k=v", "k", sOut, 0),
        "a query value needs a query, a key and room");
    CHECK(!DirectGate_Login_QueryValue("other=1&k=", "k", sOut, sizeof(sOut)), "an empty value is no value");
    CHECK(DirectGate_Login_QueryValue("k=%zz+x", "k", sOut, sizeof(sOut)) && strcmp(sOut, "%zz x") == 0,
        "an escape that is not hex is kept as it is");

    CHECK(!DirectGate_Login_Header("", "Host:", sOut, sizeof(sOut)) &&
          !DirectGate_Login_Header("Host: x", "", sOut, sizeof(sOut)) &&
          !DirectGate_Login_Header("Host: x", "Host:", NULL, sizeof(sOut)) &&
          !DirectGate_Login_Header("Host: x", "Host:", sOut, 0),
        "a header needs a request, a name and room");
    CHECK(!DirectGate_Login_CodeIsPlain(""), "no code is no plain code");

    directgate_login_guard_t guard = { "state-1", NULL };
    directgate_login_guard_t noState = { "", NULL };
    CHECK(DirectGate_Login_StateOk(NULL, "x") && DirectGate_Login_StateOk(&noState, "x") && DirectGate_Login_StateOk(&guard, ""),
        "a flow without a state, or a callback without one, is let through");
    CHECK(!DirectGate_Login_StateOk(&guard, "state-2"), "another flow's state is not");
    return 0;
}

static int check_requests(void)
{
    char sCode[64], sError[64];
    directgate_login_guard_t guard = { "state-1", "https://web.example.test" };

    CHECK(!DirectGate_Login_ParseRequest("GET /?code=a HTTP/1.1\r\n\r\n", NULL, NULL, 8, NULL, 0) &&
          !DirectGate_Login_ParseRequest("GET /?code=a HTTP/1.1\r\n\r\n", NULL, sCode, 0, NULL, 0), "a code needs room");
    CHECK(DirectGate_Login_ParseRequest("GET /?code=abc HTTP/1.1\r\n\r\n", NULL, sCode, sizeof(sCode), NULL, 0) &&
          strcmp(sCode, "abc") == 0, "without a place for an error the code still comes through");
    CHECK(!DirectGate_Login_ParseRequest("GET", NULL, sCode, sizeof(sCode), sError, sizeof(sError)) &&
          !DirectGate_Login_ParseRequest("GET /callback", NULL, sCode, sizeof(sCode), sError, sizeof(sError)),
        "a request line cut short has no code");
    CHECK(!DirectGate_Login_ParseRequest("GET /?code=abc&state=other HTTP/1.1\r\n\r\n", &guard, sCode, sizeof(sCode),
          sError, sizeof(sError)) && sCode[0] == '\0', "a code from another flow is dropped");
    CHECK(!DirectGate_Login_ParseRequest("GET /?code=a%22b HTTP/1.1\r\n\r\n", NULL, sCode, sizeof(sCode), sError, sizeof(sError)),
        "and so is one with a quote in it");

    CHECK(!DirectGate_Login_ParseRequest("POST /cb HTTP/1.1\r\nHost: x", NULL, sCode, sizeof(sCode), sError, sizeof(sError)),
        "a post without a body has no code");
    CHECK(!DirectGate_Login_ParseRequest("POST /cb HTTP/1.1\r\n\r\n", NULL, sCode, sizeof(sCode), sError, sizeof(sError)),
        "nor one with an empty body");
    CHECK(!DirectGate_Login_ParseRequest("POST /cb HTTP/1.1\r\nOrigin: https://evil.test\r\n\r\n{\"code\":\"a\"}", &guard,
          sCode, sizeof(sCode), sError, sizeof(sError)), "a post from another origin is refused");
    CHECK(!DirectGate_Login_ParseRequest("POST /cb HTTP/1.1\r\n\r\n{\"code\":\"a\"}", &guard, sCode, sizeof(sCode),
          sError, sizeof(sError)), "and so is one that does not say where it is from");
    CHECK(!DirectGate_Login_ParseRequest("POST / HTTP/1.1\nOrigin: https://web.example.test\n\n{\"code\":\"a\",\"state\":\"x\"}",
          &guard, sCode, sizeof(sCode), sError, sizeof(sError)), "a posted code from another flow is refused");
    CHECK(!DirectGate_Login_ParseRequest("POST /cb HTTP/1.1\r\n\r\n{\"code\":\"a\\u0001\"}", NULL, sCode, sizeof(sCode),
          sError, sizeof(sError)), "a posted code is checked like any other");
    CHECK(!DirectGate_Login_ParseRequest("POST /cb HTTP/1.1\r\n\r\n{\"error\":\"denied\"}", NULL, sCode, sizeof(sCode),
          sError, sizeof(sError)) && strcmp(sError, "denied") == 0, "a posted refusal says why");
    CHECK(!DirectGate_Login_ParseRequest("POST /cb HTTP/1.1\r\n\r\n{\"error\":\"denied\"}", NULL, sCode, sizeof(sCode), NULL, 0),
        "even when nobody asks why");
    CHECK(!DirectGate_Login_ParseRequest("POST /cb HTTP/1.1\r\n\r\n{nope", NULL, sCode, sizeof(sCode), sError, sizeof(sError)),
        "a body that is not JSON has no code");
    return 0;
}

static int check_flows(void)
{
    directgate_account_t account;
    DirectGate_Account_Init(&account);
    directgate_login_ctx_t ctx = { "", "", NULL, XTRUE };
    char sCode[64];

    CHECK(!DirectGate_Login_Refresh(NULL, &ctx) && !DirectGate_Login_Refresh(&account, NULL), "a refresh needs an account");
    CHECK(!DirectGate_Login_Refresh(&account, &ctx), "and a refresh token");
    xstrncpy(account.sRefreshToken, sizeof(account.sRefreshToken), "refresh");
    CHECK(!DirectGate_Login_Refresh(&account, &ctx), "and an API");

    xsock_t sock;
    uint16_t nPort = 0;
    CHECK(DirectGate_Login_Listen(NULL, &nPort) == XSOCK_INVALID && DirectGate_Login_Listen(&sock, NULL) == XSOCK_INVALID,
        "a listener needs a socket and a port");
    CHECK(!DirectGate_Login_Await(NULL, NULL, XFALSE, sCode, sizeof(sCode)) &&
          !DirectGate_Login_Await(&sock, NULL, XFALSE, NULL, sizeof(sCode)), "waiting needs a listener and room");
    CHECK(!DirectGate_Login_OpenBrowser(""), "no address opens no browser");

    CHECK(!DirectGate_Login_Interactive(NULL, &ctx) &&
          !DirectGate_Login_Interactive(&account, NULL), "a sign-in needs an account");
    CHECK(!DirectGate_Login_Interactive(&account, &ctx), "and an API");
    ctx.pApiUrl = "https://api.example.test";
    CHECK(!DirectGate_Login_Interactive(&account, &ctx), "and a web app");
    CHECK(!DirectGate_Login_Ensure(NULL, &ctx, "/tmp/x", XFALSE) && !DirectGate_Login_Ensure(&account, NULL, "/tmp/x", XFALSE),
        "and so does making sure of one");

    DirectGate_Account_Cleanse(&account);
    return 0;
}

int main(void)
{
    if (check_account() || check_parsers() || check_requests() || check_flows()) return 1;
    puts("client_login_guards_smoke: OK");
    return 0;
}
