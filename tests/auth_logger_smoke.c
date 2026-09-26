/* SRP auth record management (auth.c), logger configuration (logger.c)
 * and version strings (version.c). */

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "src/common/auth.h"
#include "src/common/logger.h"
#include "src/common/webrtc.h"
#include "src/common/version.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "auth_logger_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static int parse_json(xjson_t *pJson, const char *pData)
{
    return XJSON_Parse(pJson, NULL, pData, strlen(pData));
}

int main(void)
{
    /* ---- auth records ---- */
    directgate_auth_t auth;
    DirectGate_AuthInit(&auth);
    CHECK(!DirectGate_AuthIsConfigured(&auth), "fresh auth is unconfigured");

    CHECK(DirectGate_AuthGenerateRecord(&auth, "correct horse battery"),
        "generate auth record");
    CHECK(DirectGate_AuthIsConfigured(&auth), "generated auth is configured");
    CHECK(strlen(auth.sSaltHex) > 0, "salt present");
    CHECK(strlen(auth.sVerifierHex) > 0, "verifier present");
    CHECK(auth.nSuite > 0, "suite set");

    /* Hex fields must decode as hex */
    uint8_t salt[64];
    CHECK(DirectGate_AuthSaltHexToBytes(auth.sSaltHex, salt, strlen(auth.sSaltHex) / 2),
        "salt hex decodes");

    /* Salt is random: a second record must differ in both salt and verifier */
    directgate_auth_t auth2;
    DirectGate_AuthInit(&auth2);
    CHECK(DirectGate_AuthGenerateRecord(&auth2, "correct horse battery"),
        "generate second record");
    CHECK(strcmp(auth.sSaltHex, auth2.sSaltHex) != 0, "fresh salt per record");
    CHECK(strcmp(auth.sVerifierHex, auth2.sVerifierHex) != 0,
        "verifier depends on the salt");

    /* Invalid hex and bad sizes must be rejected */
    CHECK(!DirectGate_AuthSaltHexToBytes("zz", salt, 1), "non-hex salt rejected");
    CHECK(!DirectGate_AuthSaltHexToBytes("", salt, sizeof(salt)), "empty salt rejected");
    CHECK(!DirectGate_AuthSaltHexToBytes("0a", salt, 0), "zero-size salt rejected");
    {
        /* Full length: upper-case hex is the same salt, and one stray character spoils it. */
        char sUpper[DIRECTGATE_AUTH_SALT_HEX_SIZE];
        uint8_t lower[DIRECTGATE_SRP_SALT_SIZE], upper[DIRECTGATE_SRP_SALT_SIZE];
        for (size_t i = 0; auth.sSaltHex[i] != '\0'; i++) sUpper[i] = (char)toupper((unsigned char)auth.sSaltHex[i]);
        sUpper[DIRECTGATE_AUTH_SALT_HEX_SIZE - 1] = '\0';
        CHECK(DirectGate_AuthSaltHexToBytes(auth.sSaltHex, lower, sizeof(lower)), "lower-case salt decodes");
        CHECK(DirectGate_AuthSaltHexToBytes(sUpper, upper, sizeof(upper)), "upper-case salt decodes");
        CHECK(memcmp(lower, upper, sizeof(lower)) == 0, "the case of the hex does not change the salt");
        sUpper[DIRECTGATE_AUTH_SALT_HEX_SIZE - 2] = 'g';
        CHECK(!DirectGate_AuthSaltHexToBytes(sUpper, upper, sizeof(upper)), "a salt with a non-hex character is refused");
    }

    /* AuthLoad from a config document */
    {
        xjson_t json;
        char sDoc[sizeof(auth.sSaltHex) + sizeof(auth.sVerifierHex) + 128];
        int nDocLen = snprintf(sDoc, sizeof(sDoc),
            "{\"auth\":{\"salt\":\"%s\",\"verifier\":\"%s\",\"suite\":%u}}",
            auth.sSaltHex, auth.sVerifierHex, auth.nSuite);
        CHECK(nDocLen > 0 && (size_t)nDocLen < sizeof(sDoc), "format auth json");

        CHECK(parse_json(&json, sDoc), "parse auth json");

        directgate_auth_t loaded;
        DirectGate_AuthInit(&loaded);
        CHECK(DirectGate_AuthLoad(&loaded, json.pRootObj), "auth load");
        XJSON_Destroy(&json);

        CHECK(DirectGate_AuthIsConfigured(&loaded), "loaded auth configured");
        CHECK(strcmp(loaded.sSaltHex, auth.sSaltHex) == 0, "loaded salt");
        CHECK(strcmp(loaded.sVerifierHex, auth.sVerifierHex) == 0, "loaded verifier");
        CHECK(loaded.nSuite == auth.nSuite, "loaded suite");
    }

    /* Document without an auth object leaves the struct unconfigured */
    {
        xjson_t json;
        CHECK(parse_json(&json, "{\"other\":1}"), "parse empty json");

        directgate_auth_t empty;
        DirectGate_AuthInit(&empty);
        DirectGate_AuthLoad(&empty, json.pRootObj);
        XJSON_Destroy(&json);

        CHECK(!DirectGate_AuthIsConfigured(&empty), "no auth object stays unconfigured");
    }

    /* ---- logger configuration ---- */
    directgate_log_t logCfg;
    DirectGate_LogInit(&logCfg, "test-ident", XLOG_NONE | XLOG_ERROR | XLOG_WARN);
    CHECK(strcmp(logCfg.sIdent, "test-ident") == 0, "log ident default");
    CHECK(logCfg.nFlags == (XLOG_NONE | XLOG_ERROR | XLOG_WARN), "log flags default");

    {
        xjson_t json;
        CHECK(parse_json(&json,
            "{\"log\":{\"toScreen\":true,\"toFile\":true,\"flush\":true,"
            "\"path\":\"/tmp/dg-test-logs\",\"ident\":\"agent-x\","
            "\"logRTC\":true}}"), "parse log json");

        CHECK(DirectGate_LogLoad(&logCfg, json.pRootObj), "log load");
        XJSON_Destroy(&json);

        CHECK(logCfg.bToScreen == XTRUE, "log toScreen");
        CHECK(logCfg.bToFile == XTRUE, "log toFile");
        CHECK(logCfg.bFlush == XTRUE, "log flush");
        CHECK(logCfg.bLogRTC == XTRUE, "log rtc flag");
        CHECK(strcmp(logCfg.sPath, "/tmp/dg-test-logs") == 0, "log path");
        CHECK(strcmp(logCfg.sIdent, "agent-x") == 0, "log ident");
    }

    /* path without toFile implies file logging */
    {
        xjson_t json;
        CHECK(parse_json(&json, "{\"log\":{\"path\":\"/tmp/dg-implied\"}}"),
            "parse implied json");

        directgate_log_t implied;
        DirectGate_LogInit(&implied, "x", 0);
        CHECK(DirectGate_LogLoad(&implied, json.pRootObj), "implied load");
        XJSON_Destroy(&json);
        CHECK(implied.bToFile == XTRUE, "path implies toFile");
    }

    /* Save -> Load roundtrip */
    {
        xjson_obj_t *pRoot = XJSON_NewObject(NULL, NULL, XFALSE);
        CHECK(pRoot != NULL, "save root");
        CHECK(DirectGate_LogSave(&logCfg, pRoot), "log save");

        directgate_log_t reloaded;
        DirectGate_LogInit(&reloaded, "other", 0);
        CHECK(DirectGate_LogLoad(&reloaded, pRoot), "log reload");
        XJSON_FreeObject(pRoot);

        CHECK(reloaded.bToFile == logCfg.bToFile, "roundtrip toFile");
        CHECK(reloaded.bToScreen == logCfg.bToScreen, "roundtrip toScreen");
        CHECK(strcmp(reloaded.sPath, logCfg.sPath) == 0, "roundtrip path");
        CHECK(strcmp(reloaded.sIdent, logCfg.sIdent) == 0, "roundtrip ident");
        CHECK(reloaded.nFlags == logCfg.nFlags, "roundtrip flags");
    }

    /* Level names in any case, unknown ones and non-strings skipped; "all" ends the list. */
    {
        static const struct { const char *pDoc; uint16_t nFlags; int nRTC; } levels[] = {
            { "[\"Note\",\"INFO\",5,\"nonsense\",\"trace\"]", XLOG_NOTE | XLOG_INFO | XLOG_TRACE | XLOG_NONE, RTC_LOG_VERBOSE },
            { "[\"warning\",\"all\",\"error\"]", XLOG_ALL, RTC_LOG_VERBOSE },
            { "[\"debug\"]", XLOG_DEBUG | XLOG_NONE, RTC_LOG_DEBUG },
            { "[\"info\"]", XLOG_INFO | XLOG_NONE, RTC_LOG_INFO },
            { "[\"note\"]", XLOG_NOTE | XLOG_NONE, RTC_LOG_WARNING },
            { "[\"warn\"]", XLOG_WARN | XLOG_NONE, RTC_LOG_WARNING },
            { "[\"error\"]", XLOG_ERROR | XLOG_NONE, RTC_LOG_ERROR },
            { "[\"panic\"]", XLOG_FATAL | XLOG_NONE, RTC_LOG_FATAL }
        };

        for (size_t i = 0; i < sizeof(levels) / sizeof(levels[0]); i++)
        {
            char sDoc[256];
            snprintf(sDoc, sizeof(sDoc), "{\"log\":{\"logRTC\":true,\"levels\":%s}}", levels[i].pDoc);

            xjson_t json;
            CHECK(parse_json(&json, sDoc), "parse levels json");

            directgate_log_t levelled;
            DirectGate_LogInit(&levelled, "x", XLOG_DEFAULT);
            CHECK(DirectGate_LogLoad(&levelled, json.pRootObj), "levels load");
            XJSON_Destroy(&json);
            CHECK(levelled.nFlags == levels[i].nFlags, "level names map to their flags");
            CHECK(levelled.nRTCLevel == levels[i].nRTC, "the flags map to the WebRTC log level");
        }

        /* Nothing it knows: the flags already in place stay. */
        xjson_t json;
        CHECK(parse_json(&json, "{\"log\":{\"levels\":[\"loud\",\"\"]}}"), "parse unknown levels json");
        directgate_log_t unknown;
        DirectGate_LogInit(&unknown, "x", XLOG_ERROR);
        CHECK(DirectGate_LogLoad(&unknown, json.pRootObj) && unknown.nFlags == XLOG_ERROR, "unknown level names change nothing");
        XJSON_Destroy(&json);

        unknown.bLogRTC = XTRUE;
        unknown.nFlags = 0;
        CHECK(DirectGate_LogGetRTCLevel(&unknown) == RTC_LOG_NONE, "no levels at all is no WebRTC logging");
    }

    /* RTC level mapping respects the master switch */
    logCfg.bLogRTC = XFALSE;
    int nMuted = DirectGate_LogGetRTCLevel(&logCfg);
    logCfg.bLogRTC = XTRUE;
    int nActive = DirectGate_LogGetRTCLevel(&logCfg);
    CHECK(nActive >= nMuted, "rtc level not below muted level");

    /* ---- version strings ---- */
    const char *pShort = DirectGate_GetVersionShort();
    const char *pLong = DirectGate_GetVersionLong();
    CHECK(pShort != NULL && strlen(pShort) >= 5, "short version present");
    CHECK(pLong != NULL && strlen(pLong) > strlen(pShort), "long version present");
    CHECK(strchr(pShort, '.') != NULL, "short version is dotted");
    CHECK(strstr(pLong, "build") != NULL, "long version mentions build");

    puts("auth_logger_smoke: OK");
    return 0;
}
