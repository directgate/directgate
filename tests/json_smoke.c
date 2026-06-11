/* libxutils JSON engine: every protocol header crosses this parser with
 * relay-supplied bytes, so it must roundtrip cleanly and reject garbage
 * without crashing or leaking. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libxutils/src/data/json.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "json_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static int parse_ok(const char *pData)
{
    xjson_t json;
    if (!XJSON_Parse(&json, NULL, pData, strlen(pData))) return 0;
    XJSON_Destroy(&json);
    return 1;
}

int main(void)
{
    /* ---- representative protocol document ---- */
    const char *pDoc =
        "{\"type\":\"manager\",\"version\":1,\"sessionId\":42,"
        "\"force\":true,\"cancel\":false,\"ratio\":0.5,"
        "\"path\":\"/home/user/file with spaces\","
        "\"entries\":[{\"name\":\"a\",\"size\":123},{\"name\":\"b\",\"size\":0}],"
        "\"nothing\":null,"
        "\"big\":4294967295}";

    xjson_t json;
    CHECK(XJSON_Parse(&json, NULL, pDoc, strlen(pDoc)), "parse document");

    xjson_obj_t *pRoot = json.pRootObj;
    CHECK(pRoot != NULL, "root object");

    const char *pType = XJSON_GetString(XJSON_GetObject(pRoot, "type"));
    CHECK(pType != NULL && strcmp(pType, "manager") == 0, "string field");
    CHECK(XJSON_GetU32(XJSON_GetObject(pRoot, "sessionId")) == 42, "u32 field");
    CHECK(XJSON_GetInt(XJSON_GetObject(pRoot, "version")) == 1, "int field");
    CHECK(XJSON_GetBool(XJSON_GetObject(pRoot, "force")) == 1, "true field");
    CHECK(XJSON_GetBool(XJSON_GetObject(pRoot, "cancel")) == 0, "false field");
    CHECK(XJSON_GetU32(XJSON_GetObject(pRoot, "big")) == 4294967295U, "u32 max");
    CHECK(XJSON_GetObject(pRoot, "no-such-key") == NULL, "missing key is NULL");

    const char *pPath = XJSON_GetString(XJSON_GetObject(pRoot, "path"));
    CHECK(pPath != NULL && strcmp(pPath, "/home/user/file with spaces") == 0,
        "string with spaces");

    xjson_obj_t *pEntries = XJSON_GetObject(pRoot, "entries");
    CHECK(pEntries != NULL && pEntries->nType == XJSON_TYPE_ARRAY, "array field");
    CHECK(XJSON_GetArrayLength(pEntries) == 2, "array length");

    xjson_obj_t *pFirst = XJSON_GetArrayItem(pEntries, 0);
    CHECK(pFirst != NULL, "array item");
    const char *pName = XJSON_GetString(XJSON_GetObject(pFirst, "name"));
    CHECK(pName != NULL && strcmp(pName, "a") == 0, "nested string");
    CHECK(XJSON_GetArrayItem(pEntries, 5) == NULL, "out-of-range item is NULL");

    /* ---- dump -> reparse roundtrip ---- */
    size_t nDumpLen = 0;
    char *pDump = XJSON_DumpObj(pRoot, 0, &nDumpLen);
    CHECK(pDump != NULL && nDumpLen > 0, "dump document");
    XJSON_Destroy(&json);

    xjson_t reparsed;
    CHECK(XJSON_Parse(&reparsed, NULL, pDump, nDumpLen), "reparse dump");
    free(pDump);

    CHECK(XJSON_GetU32(XJSON_GetObject(reparsed.pRootObj, "sessionId")) == 42,
        "roundtrip u32");
    xjson_obj_t *pReEntries = XJSON_GetObject(reparsed.pRootObj, "entries");
    CHECK(pReEntries != NULL && XJSON_GetArrayLength(pReEntries) == 2,
        "roundtrip array");
    XJSON_Destroy(&reparsed);

    /* ---- programmatic build -> dump -> parse ---- */
    xjson_obj_t *pBuilt = XJSON_NewObject(NULL, NULL, XFALSE);
    CHECK(pBuilt != NULL, "new object");
    CHECK(XJSON_AddString(pBuilt, "k", "v") == XJSON_ERR_NONE, "add string");
    CHECK(XJSON_AddU32(pBuilt, "n", 7) == XJSON_ERR_NONE, "add u32");
    CHECK(XJSON_AddBool(pBuilt, "b", 1) == XJSON_ERR_NONE, "add bool");

    pDump = XJSON_DumpObj(pBuilt, 0, &nDumpLen);
    CHECK(pDump != NULL, "dump built");
    XJSON_FreeObject(pBuilt);

    CHECK(XJSON_Parse(&reparsed, NULL, pDump, nDumpLen), "parse built");
    free(pDump);
    CHECK(XJSON_GetU32(XJSON_GetObject(reparsed.pRootObj, "n")) == 7, "built u32");
    XJSON_Destroy(&reparsed);

    /* ---- malformed input must be rejected ---- */
    CHECK(!parse_ok(""), "empty input");
    CHECK(!parse_ok("{"), "unterminated object");
    CHECK(!parse_ok("{\"a\":}"), "missing value");
    CHECK(!parse_ok("{\"a\":1,}"), "trailing comma");
    CHECK(!parse_ok("{,\"a\":1}"), "leading comma");
    CHECK(!parse_ok("{\"a\":1,,\"b\":2}"), "double comma");
    CHECK(!parse_ok("[1,2,]"), "array trailing comma");
    CHECK(!parse_ok("{\"a\" 1}"), "missing colon");
    CHECK(!parse_ok("nonsense"), "bare garbage");
    CHECK(!parse_ok("{\"a\":\"unterminated}"), "unterminated string");
    CHECK(!parse_ok("[1,2"), "unterminated array");

    /* Truncations of a valid document at every byte must never crash */
    for (size_t i = 1; i + 1 < strlen(pDoc); i++)
    {
        xjson_t cut;
        if (XJSON_Parse(&cut, NULL, pDoc, i))
            XJSON_Destroy(&cut);
    }

    /* Moderately deep nesting parses and frees cleanly */
    {
        char sDeep[512];
        size_t nPos = 0;
        const int nDepth = 60;
        for (int i = 0; i < nDepth; i++) sDeep[nPos++] = '[';
        sDeep[nPos++] = '1';
        for (int i = 0; i < nDepth; i++) sDeep[nPos++] = ']';
        sDeep[nPos] = '\0';

        xjson_t deep;
        if (XJSON_Parse(&deep, NULL, sDeep, nPos))
            XJSON_Destroy(&deep);
    }

    puts("json_smoke: OK");
    return 0;
}
