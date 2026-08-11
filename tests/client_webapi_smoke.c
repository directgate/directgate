#include <stdio.h>
#include <string.h>

#include "src/common/includes.h"
#include "src/client/webapi.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "client_webapi_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static int test_url_encode(void)
{
    char sOut[128];

    /* The RFC 3986 unreserved set has to survive untouched, or the PKCE
     * challenge and verifier stop matching what the provider hashed. */
    const char *pUnreserved =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";

    CHECK(DirectGate_WebApi_UrlEncode(sOut, sizeof(sOut), pUnreserved) == strlen(pUnreserved),
        "unreserved length");
    CHECK(strcmp(sOut, pUnreserved) == 0, "unreserved characters pass through");

    CHECK(DirectGate_WebApi_UrlEncode(sOut, sizeof(sOut), "http://127.0.0.1:40777/callback") > 0,
        "encode redirect");
    CHECK(strcmp(sOut, "http%3A%2F%2F127.0.0.1%3A40777%2Fcallback") == 0,
        "redirect encoding");

    CHECK(DirectGate_WebApi_UrlEncode(sOut, sizeof(sOut), "a b&c=d") > 0, "encode separators");
    CHECK(strcmp(sOut, "a%20b%26c%3Dd") == 0, "separators are escaped");

    /* High bytes must be escaped per byte, never truncated */
    CHECK(DirectGate_WebApi_UrlEncode(sOut, sizeof(sOut), "\xC3\xA9") > 0, "encode utf-8");
    CHECK(strcmp(sOut, "%C3%A9") == 0, "utf-8 is escaped bytewise");

    CHECK(DirectGate_WebApi_UrlEncode(sOut, sizeof(sOut), "") == 0, "empty input");
    CHECK(sOut[0] == '\0', "empty output is terminated");

    /* A too-small buffer must fail loudly rather than emit a partial URL */
    CHECK(DirectGate_WebApi_UrlEncode(sOut, 4, "a b c") == 0, "reject overflow");
    CHECK(sOut[0] == '\0', "overflow leaves an empty string");
    CHECK(DirectGate_WebApi_UrlEncode(NULL, sizeof(sOut), "x") == 0, "reject NULL output");
    CHECK(DirectGate_WebApi_UrlEncode(sOut, 0, "x") == 0, "reject zero size");
    CHECK(DirectGate_WebApi_UrlEncode(sOut, sizeof(sOut), NULL) == 0, "reject NULL input");

    return 0;
}

static int test_request_guards(void)
{
    directgate_webapi_res_t res;

    CHECK(!DirectGate_WebApi_Request(&res, XHTTP_GET, NULL, "/x", NULL, NULL, NULL),
        "reject missing base URL");
    DirectGate_WebApi_Clear(&res);

    CHECK(!DirectGate_WebApi_Request(&res, XHTTP_GET, "https://api.example.test", NULL,
        NULL, NULL, NULL), "reject missing path");
    DirectGate_WebApi_Clear(&res);

    /* Release builds refuse plaintext endpoints outright */
    CHECK(!DirectGate_WebApi_Request(&res, XHTTP_GET, "wss://api.example.test", "/x",
        NULL, NULL, NULL), "reject non-HTTP scheme");
    CHECK(xstrused(res.sError), "rejection carries a reason");
    DirectGate_WebApi_Clear(&res);

    CHECK(!DirectGate_WebApi_Request(&res, XHTTP_GET, "https://", "/x", NULL, NULL, NULL),
        "reject URL without host");
    DirectGate_WebApi_Clear(&res);

    CHECK(!DirectGate_WebApi_Request(NULL, XHTTP_GET, "https://api.example.test", "/x",
        NULL, NULL, NULL), "reject NULL result");

    /* Clearing an untouched or already cleared result must stay safe */
    memset(&res, 0, sizeof(res));
    DirectGate_WebApi_Clear(&res);
    DirectGate_WebApi_Clear(&res);
    DirectGate_WebApi_Clear(NULL);

    return 0;
}

/*
 * Guards the bearer token against libxutils' header path.
 *
 * XHTTP_AddHeader() formats through a fixed stack buffer (XHTTP_OPTION_MAX)
 * and vsnprintf truncates rather than failing. A Supabase access token signed
 * with an asymmetric key is ~1.4 KB, so a regression here does not fail
 * loudly - it puts a clipped credential on the wire and the API answers with
 * a misleading "Invalid or expired bearer token".
 */
static int test_long_header(void)
{
    char sToken[2048];
    memset(sToken, 'a', sizeof(sToken) - 1);
    sToken[sizeof(sToken) - 1] = '\0';

    xhttp_t handle;
    CHECK(XHTTP_InitRequest(&handle, XHTTP_GET, "/api/v1/devices", NULL) > 0,
        "init request");
    CHECK(XHTTP_AddHeader(&handle, "Authorization", "Bearer %s", sToken) > 0,
        "add long authorization header");

    xbyte_buffer_t *pBuffer = XHTTP_Assemble(&handle, NULL, 0);
    CHECK(pBuffer != NULL && pBuffer->pData != NULL, "assemble request");

    const char *pNeedle = "\r\nAuthorization: Bearer ";
    const char *pAt = strstr((const char*)pBuffer->pData, pNeedle);
    CHECK(pAt != NULL, "authorization header is present");

    pAt += strlen(pNeedle);
    const char *pEnd = strstr(pAt, "\r\n");
    CHECK(pEnd != NULL, "authorization header is terminated");

    CHECK((size_t)(pEnd - pAt) == strlen(sToken),
        "oversized bearer token survives the header path intact");

    XHTTP_Clear(&handle);
    return 0;
}

/*
 * Nest reports validation failures as an array of reasons under "message" and
 * leaves "error" as the bare status text, so a reader that only understands
 * strings turns a precise "code is required" into "Bad Request". That is the
 * CLI's only window into why a request was refused, and it cost a real
 * debugging session once already.
 */
static int test_error_reporting(void)
{
    char sError[XSTR_TINY];
    xjson_t json;

    const char *pNestValidation =
        "{\"message\":[\"code is required\",\"codeVerifier must be a string\"],"
        "\"error\":\"Bad Request\",\"statusCode\":400}";

    CHECK(XJSON_Parse(&json, NULL, pNestValidation, strlen(pNestValidation)),
        "parse a Nest validation body");
    CHECK(DirectGate_WebApi_FormatError(sError, sizeof(sError), json.pRootObj, 400) > 0,
        "format a validation body");
    CHECK(strcmp(sError, "code is required, codeVerifier must be a string") == 0,
        "every validation reason is reported, not the bare status text");
    XJSON_Destroy(&json);

    /* Nest's single-string form */
    const char *pSingle = "{\"message\":\"Session not found\",\"statusCode\":404}";
    CHECK(XJSON_Parse(&json, NULL, pSingle, strlen(pSingle)), "parse a single message");
    CHECK(DirectGate_WebApi_FormatError(sError, sizeof(sError), json.pRootObj, 404) > 0,
        "format a single message");
    CHECK(strcmp(sError, "Session not found") == 0, "single message is used as is");
    XJSON_Destroy(&json);

    /* GoTrue's wording */
    const char *pGoTrue = "{\"error\":\"invalid_grant\",\"error_description\":\"code expired\"}";
    CHECK(XJSON_Parse(&json, NULL, pGoTrue, strlen(pGoTrue)), "parse a provider body");
    CHECK(DirectGate_WebApi_FormatError(sError, sizeof(sError), json.pRootObj, 400) > 0,
        "format a provider body");
    CHECK(strcmp(sError, "code expired") == 0, "the description beats the error code");
    XJSON_Destroy(&json);

    /* An empty array must not swallow the fallback fields */
    const char *pEmptyArray = "{\"message\":[],\"error\":\"Bad Request\"}";
    CHECK(XJSON_Parse(&json, NULL, pEmptyArray, strlen(pEmptyArray)), "parse an empty array");
    CHECK(DirectGate_WebApi_FormatError(sError, sizeof(sError), json.pRootObj, 400) > 0,
        "format an empty array");
    CHECK(strcmp(sError, "Bad Request") == 0, "an empty array falls through");
    XJSON_Destroy(&json);

    /* Bodies with nothing usable still say something actionable */
    const char *pOpaque = "{\"statusCode\":503}";
    CHECK(XJSON_Parse(&json, NULL, pOpaque, strlen(pOpaque)), "parse an opaque body");
    CHECK(DirectGate_WebApi_FormatError(sError, sizeof(sError), json.pRootObj, 503) > 0,
        "format an opaque body");
    CHECK(strstr(sError, "503") != NULL, "the status code is reported");
    XJSON_Destroy(&json);

    CHECK(DirectGate_WebApi_FormatError(sError, sizeof(sError), NULL, 500) > 0,
        "format without a body");
    CHECK(strstr(sError, "500") != NULL, "a missing body still reports the status");
    CHECK(DirectGate_WebApi_FormatError(NULL, sizeof(sError), NULL, 500) == 0,
        "reject NULL output");

    return 0;
}

int main(void)
{
    xlog_setfl(XLOG_NONE);

    int nErrStatus = test_error_reporting();
    if (nErrStatus) return nErrStatus;

    int nStatus = test_long_header();
    if (nStatus) return nStatus;

    nStatus = test_url_encode();
    if (nStatus) return nStatus;

    nStatus = test_request_guards();
    if (nStatus) return nStatus;

    puts("client_webapi_smoke: OK");
    return 0;
}
