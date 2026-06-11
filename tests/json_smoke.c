/* libxutils JSON engine: every protocol header crosses this parser with
 * relay-supplied bytes, so it must roundtrip cleanly and reject garbage
 * without crashing or leaking. */

#include <stdint.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libxutils/src/data/json.h"
#include "libxutils/src/sys/log.h"

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
    if (json.nError != XJSON_ERR_NONE)
    {
        XJSON_Destroy(&json);
        return 0;
    }
    XJSON_Destroy(&json);
    return 1;
}

static int parse_bytes_ok(const char *pData, size_t nSize)
{
    xjson_t json;
    if (!XJSON_Parse(&json, NULL, pData, nSize)) return 0;
    int nStatus = json.nError == XJSON_ERR_NONE && json.pRootObj != NULL;
    XJSON_Destroy(&json);
    return nStatus;
}

static int parse_bytes_rejected(const char *pData, size_t nSize)
{
    xjson_t json;
    if (XJSON_Parse(&json, NULL, pData, nSize))
    {
        XJSON_Destroy(&json);
        return 0;
    }

    char sError[128];
    int nStatus = json.nError != XJSON_ERR_NONE &&
        json.pRootObj == NULL &&
        XJSON_GetErrorStr(&json, sError, sizeof(sError)) > 0 &&
        sError[0] != '\0';
    XJSON_Destroy(&json);
    return nStatus;
}

static int count_log(const char *pLog, size_t nLength, xlog_flag_t eFlag, void *pContext)
{
    (void)pLog;
    (void)nLength;
    (void)eFlag;
    int *pCount = (int*)pContext;
    (*pCount)++;
    return XSTDNON;
}

typedef struct json_case_ {
    const char *pData;
    size_t nSize;
} json_case_t;

#define JSON_CASE(text) { (text), sizeof(text) - 1 }

static int test_parse_matrix(void)
{
    static const json_case_t valid[] = {
        JSON_CASE("{}"),
        JSON_CASE("[]"),
        JSON_CASE(" \t\r\n{}\n\r\t "),
        JSON_CASE("{\"\":1}"),
        JSON_CASE("{\"empty\":\"\",\"object\":{},\"array\":[]}"),
        JSON_CASE("[null,true,false,\"\",0,-0,1,-1,1.0,-0.5,1e2,1E+2,1e-2]"),
        JSON_CASE("{\"escapes\":\"\\\"\\\\\\/\\b\\f\\n\\r\\t\"}"),
        JSON_CASE("{\"unicode\":\"\\u0000\\u00ff\\uD800\\uDC00\\uFFFF\"}"),
        JSON_CASE("{\"nested\":[{},[],{\"a\":[1,{\"b\":false}]}]}"),
        JSON_CASE("{\"n\":1234567890123456789012345678901234567890}"),
        JSON_CASE("{\"n\":1.234567890123456789e+123}"),
        JSON_CASE("{\n\"a\"\t:\r1,\n\"b\"\t:\r[\ntrue,\rfalse,\tnull\n]\n}"),
        { "{\"utf8\":\"\xE1\x83\xA5\xE1\x83\x90\xE1\x83\xA0\xE1\x83\x97\xE1\x83\xA3\xE1\x83\x9A\xE1\x83\x98\"}",
          sizeof("{\"utf8\":\"\xE1\x83\xA5\xE1\x83\x90\xE1\x83\xA0\xE1\x83\x97\xE1\x83\xA3\xE1\x83\x9A\xE1\x83\x98\"}") - 1 }
    };

    static const json_case_t invalid[] = {
        JSON_CASE(""),
        JSON_CASE(" \t\r\n"),
        JSON_CASE("null"),
        JSON_CASE("true"),
        JSON_CASE("0"),
        JSON_CASE("\"root\""),
        JSON_CASE("{"),
        JSON_CASE("["),
        JSON_CASE("}"),
        JSON_CASE("]"),
        JSON_CASE("{]"),
        JSON_CASE("[}"),
        JSON_CASE("{\"a\"}"),
        JSON_CASE("{\"a\":}"),
        JSON_CASE("{:\"a\"}"),
        JSON_CASE("{,\"a\":1}"),
        JSON_CASE("{\"a\":1,}"),
        JSON_CASE("{\"a\":1,,\"b\":2}"),
        JSON_CASE("{\"a\":1 \"b\":2}"),
        JSON_CASE("{\"a\":1,\"a\":2}"),
        JSON_CASE("[,]"),
        JSON_CASE("[1,]"),
        JSON_CASE("[1,,2]"),
        JSON_CASE("[1 2]"),
        JSON_CASE("[1,2"),
        JSON_CASE("{\"a\":01}"),
        JSON_CASE("{\"a\":-01}"),
        JSON_CASE("{\"a\":+1}"),
        JSON_CASE("{\"a\":.1}"),
        JSON_CASE("{\"a\":1.}"),
        JSON_CASE("{\"a\":1e}"),
        JSON_CASE("{\"a\":1e+}"),
        JSON_CASE("{\"a\":1e-}"),
        JSON_CASE("{\"a\":--1}"),
        JSON_CASE("{\"a\":1..2}"),
        JSON_CASE("{\"a\":NaN}"),
        JSON_CASE("{\"a\":Infinity}"),
        JSON_CASE("{\"a\":TRUE}"),
        JSON_CASE("{\"a\":False}"),
        JSON_CASE("{\"a\":nul}"),
        JSON_CASE("{\"a\":nullx}"),
        JSON_CASE("{\"a\":truefalse}"),
        JSON_CASE("{\"a\":\"unterminated}"),
        JSON_CASE("{\"a\":\"bad\\"),
        JSON_CASE("{\"a\":\"bad\\q\"}"),
        JSON_CASE("{\"a\":\"bad\\u\"}"),
        JSON_CASE("{\"a\":\"bad\\u0\"}"),
        JSON_CASE("{\"a\":\"bad\\u00\"}"),
        JSON_CASE("{\"a\":\"bad\\u000\"}"),
        JSON_CASE("{\"a\":\"bad\\u00xz\"}"),
        JSON_CASE("{\"a\":\"raw\nnewline\"}"),
        JSON_CASE("{\"a\":\"raw\ttab\"}"),
        JSON_CASE("{\"a\":\"\x01\"}"),
        JSON_CASE("{}{}"),
        JSON_CASE("{} []"),
        JSON_CASE("{} trailing"),
        JSON_CASE("{}\v"),
        JSON_CASE("{}\f")
    };

    int nLogCount = 0;
    int nValidStatus = 1;
    xlog_init("json-matrix", XLOG_ALL, XFALSE);
    xlog_screen(XFALSE);
    xlog_callback(count_log, &nLogCount);
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); i++)
    {
        if (!parse_bytes_ok(valid[i].pData, valid[i].nSize))
        {
            nValidStatus = 0;
            break;
        }
    }
    xlog_destroy();
    if (!nValidStatus || nLogCount != 0) return 0;

    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++)
        if (!parse_bytes_rejected(invalid[i].pData, invalid[i].nSize)) return 0;

    return 1;
}

static int test_parse_boundaries(void)
{
    static const char sNulAfterRoot[] = { '{', '}', '\0' };
    static const char sNulThenData[] = { '{', '}', '\0', '{', '}' };
    static const char sBounded[] = { '{', '}', 'g', 'a', 'r', 'b', 'a', 'g', 'e' };

    if (!parse_bytes_rejected(NULL, 0) ||
        !parse_bytes_rejected(NULL, 1) ||
        !parse_bytes_rejected(sNulAfterRoot, sizeof(sNulAfterRoot)) ||
        !parse_bytes_rejected(sNulThenData, sizeof(sNulThenData)) ||
        !parse_bytes_ok(sBounded, 2))
        return 0;

    const char *pDoc = "{\"a\":[1,true,null,{\"b\":\"value\"}],\"c\":-1.25e+3}";
    size_t nLength = strlen(pDoc);
    for (size_t i = 0; i < nLength; i++)
        if (!parse_bytes_rejected(pDoc, i)) return 0;

    return parse_bytes_ok(pDoc, nLength);
}

static int test_builders_and_writers(void)
{
    xjson_obj_t *pRoot = XJSON_NewObject(NULL, NULL, XTRUE);
    if (pRoot == NULL) return 0;

    int nStatus =
        XJSON_AddU16(pRoot, "u16", UINT16_MAX) == XJSON_ERR_NONE &&
        XJSON_AddU32(pRoot, "u32", UINT32_MAX) == XJSON_ERR_NONE &&
        XJSON_AddU64(pRoot, "u64", UINT64_MAX) == XJSON_ERR_NONE &&
        XJSON_AddInt(pRoot, "minInt", INT32_MIN) == XJSON_ERR_NONE &&
        XJSON_AddFloat(pRoot, "float", -123.5) == XJSON_ERR_NONE &&
        XJSON_AddBool(pRoot, "true", XTRUE) == XJSON_ERR_NONE &&
        XJSON_AddBool(pRoot, "false", XFALSE) == XJSON_ERR_NONE &&
        XJSON_AddString(pRoot, "", "emptyName") == XJSON_ERR_NONE &&
        XJSON_AddString(pRoot, "empty", "") == XJSON_ERR_NONE &&
        XJSON_AddString(pRoot, "nullFromString", NULL) == XJSON_ERR_NONE &&
        XJSON_AddNull(pRoot, "null") == XJSON_ERR_NONE &&
        XJSON_AddStrIfUsed(pRoot, "unused", "") == XJSON_ERR_NONE &&
        XJSON_GetObject(pRoot, "unused") == NULL;
    if (!nStatus)
    {
        XJSON_FreeObject(pRoot);
        return 0;
    }

    if (XJSON_AddInt(pRoot, "minInt", 77) != XJSON_ERR_NONE ||
        XJSON_GetInt(XJSON_GetObject(pRoot, "minInt")) != 77)
    {
        XJSON_FreeObject(pRoot);
        return 0;
    }

    xjson_obj_t *pUpdated = XJSON_GetObject(pRoot, "minInt");
    xjson_obj_t *pUnnamedObjectChild = XJSON_NewInt(NULL, NULL, 1);
    if (pUpdated == NULL ||
        XJSON_AddObject(pRoot, pUpdated) != XJSON_ERR_NONE ||
        XJSON_GetInt(XJSON_GetObject(pRoot, "minInt")) != 77 ||
        pUnnamedObjectChild == NULL ||
        XJSON_AddObject(pRoot, pUnnamedObjectChild) != XJSON_ERR_INVALID ||
        XJSON_GetOrCreateObject(pRoot, "minInt", XFALSE) != NULL ||
        XJSON_GetOrCreateArray(pRoot, "minInt", XFALSE) != NULL)
    {
        XJSON_FreeObject(pUnnamedObjectChild);
        XJSON_FreeObject(pRoot);
        return 0;
    }
    XJSON_FreeObject(pUnnamedObjectChild);

    xjson_obj_t *pNested = XJSON_GetOrCreateObject(pRoot, "nested", XFALSE);
    xjson_obj_t *pArray = XJSON_GetOrCreateArray(pRoot, "array", XFALSE);
    if (pNested == NULL || pArray == NULL ||
        XJSON_AddString(pNested, "value", "nested") != XJSON_ERR_NONE)
    {
        XJSON_FreeObject(pRoot);
        return 0;
    }

    xjson_obj_t *pNamedArrayChild = XJSON_NewInt(NULL, "named", 1);
    if (pNamedArrayChild == NULL ||
        XJSON_AddObject(pArray, pNamedArrayChild) != XJSON_ERR_INVALID)
    {
        XJSON_FreeObject(pNamedArrayChild);
        XJSON_FreeObject(pRoot);
        return 0;
    }
    XJSON_FreeObject(pNamedArrayChild);

    for (int i = 0; i < 5; i++)
    {
        xjson_obj_t *pItem = XJSON_NewInt(NULL, NULL, i);
        if (pItem == NULL || XJSON_AddObject(pArray, pItem) != XJSON_ERR_NONE)
        {
            XJSON_FreeObject(pItem);
            XJSON_FreeObject(pRoot);
            return 0;
        }
    }

    if (XJSON_RemoveArrayItem(pArray, 0) != XARRAY_SUCCESS ||
        XJSON_RemoveArrayItem(pArray, 2) != XARRAY_SUCCESS ||
        XJSON_RemoveArrayItem(pArray, 2) != XARRAY_SUCCESS ||
        XJSON_GetArrayLength(pArray) != 2 ||
        XJSON_GetInt(XJSON_GetArrayItem(pArray, 0)) != 1 ||
        XJSON_GetInt(XJSON_GetArrayItem(pArray, 1)) != 2)
    {
        XJSON_FreeObject(pRoot);
        return 0;
    }

    xarray_t *pObjects = XJSON_GetObjects(pRoot);
    if (pObjects == NULL || XArray_Used(pObjects) != 13)
    {
        XArray_Destroy(pObjects);
        XJSON_FreeObject(pRoot);
        return 0;
    }
    XArray_Destroy(pObjects);

    size_t nCompactLen = 0;
    size_t nPrettyLen = 0;
    char *pCompact = XJSON_DumpObj(pRoot, 0, &nCompactLen);
    char *pPretty = XJSON_DumpObj(pRoot, 2, &nPrettyLen);
    if (pCompact == NULL || pPretty == NULL ||
        nCompactLen != strlen(pCompact) ||
        nPrettyLen != strlen(pPretty) ||
        strchr(pCompact, '\n') != NULL ||
        strchr(pPretty, '\n') == NULL ||
        !parse_bytes_ok(pCompact, nCompactLen) ||
        !parse_bytes_ok(pPretty, nPrettyLen))
    {
        free(pCompact);
        free(pPretty);
        XJSON_FreeObject(pRoot);
        return 0;
    }

    xjson_t wrapper;
    XJSON_Init(&wrapper);
    wrapper.pRootObj = pRoot;

    char sOutput[4096];
    char sTiny[4] = "xxx";
    if (!XJSON_Write(&wrapper, sOutput, sizeof(sOutput)) ||
        !parse_ok(sOutput) ||
        XJSON_Write(&wrapper, sTiny, sizeof(sTiny)))
    {
        free(pCompact);
        free(pPretty);
        XJSON_FreeObject(pRoot);
        return 0;
    }

    xjson_writer_t dynamicWriter;
    xjson_writer_t fixedWriter;
    char sFixed[4096];
    if (!XJSON_InitWriter(&dynamicWriter, NULL, NULL, 1) ||
        !XJSON_WriteObject(pRoot, &dynamicWriter) ||
        !parse_bytes_ok(dynamicWriter.pData, dynamicWriter.nLength) ||
        !XJSON_InitWriter(&fixedWriter, NULL, sFixed, sizeof(sFixed)) ||
        !XJSON_WriteObject(pRoot, &fixedWriter) ||
        !parse_bytes_ok(fixedWriter.pData, fixedWriter.nLength))
    {
        XJSON_DestroyWriter(&dynamicWriter);
        free(pCompact);
        free(pPretty);
        XJSON_FreeObject(pRoot);
        return 0;
    }
    XJSON_DestroyWriter(&dynamicWriter);

    xjson_format_t format;
    XJSON_FormatInit(&format);
    size_t nFormatLen = 0;
    char *pFormatted = XJSON_FormatObj(pRoot, 2, &format, &nFormatLen);
    if (pFormatted == NULL || nFormatLen != strlen(pFormatted))
    {
        free(pFormatted);
        free(pCompact);
        free(pPretty);
        XJSON_FreeObject(pRoot);
        return 0;
    }

    free(pFormatted);
    free(pCompact);
    free(pPretty);
    XJSON_FreeObject(pRoot);

    xjson_obj_t *pFromStr = XJSON_FromStr(NULL, "{\"ok\":true,\"a\":[1,2,3]}");
    if (pFromStr == NULL) return 0;
    nStatus = XJSON_GetBool(XJSON_GetObject(pFromStr, "ok")) &&
        XJSON_GetArrayLength(XJSON_GetObject(pFromStr, "a")) == 3;
    XJSON_FreeObject(pFromStr);
    return nStatus;
}

static int test_generated_string_edges(void)
{
    xjson_obj_t *pRoot = XJSON_NewObject(NULL, NULL, XFALSE);
    if (pRoot == NULL) return 0;

    int nStatus =
        XJSON_AddString(pRoot, "quote\"key", "quote\"value") == XJSON_ERR_NONE &&
        XJSON_AddString(pRoot, "backslash", "C:\\path\\file") == XJSON_ERR_NONE &&
        XJSON_AddString(pRoot, "validEscapes", "\\\"\\\\\\/\\b\\f\\n\\r\\t\\u0041") == XJSON_ERR_NONE &&
        XJSON_AddString(pRoot, "controls", "line\nrow\rtab\tback\bform\f") == XJSON_ERR_NONE &&
        XJSON_AddString(pRoot, "control\nkey", "\x01") == XJSON_ERR_NONE &&
        XJSON_AddString(pRoot, "utf8", "\xE1\x83\xA5\xE1\x83\x90\xE1\x83\xA0\xE1\x83\x97\xE1\x83\xA3\xE1\x83\x9A\xE1\x83\x98") == XJSON_ERR_NONE &&
        XJSON_AddFloat(pRoot, "nan", NAN) == XJSON_ERR_INVALID &&
        XJSON_AddFloat(pRoot, "positiveInf", INFINITY) == XJSON_ERR_INVALID &&
        XJSON_AddFloat(pRoot, "negativeInf", -INFINITY) == XJSON_ERR_INVALID;
    if (!nStatus)
    {
        XJSON_FreeObject(pRoot);
        return 0;
    }

    size_t nLength = 0;
    char *pDump = XJSON_DumpObj(pRoot, 0, &nLength);
    nStatus = pDump != NULL &&
        nLength == strlen(pDump) &&
        strstr(pDump, "\\\"") != NULL &&
        strstr(pDump, "\\\\path") != NULL &&
        strstr(pDump, "\\u0001") != NULL &&
        strstr(pDump, "\\n") != NULL &&
        strstr(pDump, "\\r") != NULL &&
        strstr(pDump, "\\t") != NULL &&
        parse_bytes_ok(pDump, nLength);

    free(pDump);
    XJSON_FreeObject(pRoot);
    return nStatus;
}

static int test_byte_boundaries(void)
{
    for (int nByte = 0; nByte <= UINT8_MAX; nByte++)
    {
        char sTrailing[] = { '{', '}', (char)nByte };
        int nWhitespace = nByte == ' ' || nByte == '\n' ||
            nByte == '\r' || nByte == '\t';
        if (parse_bytes_ok(sTrailing, sizeof(sTrailing)) != nWhitespace)
            return 0;
    }

    for (int nByte = 0; nByte <= 0x7f; nByte++)
    {
        char sString[] = { '{', '"', 'a', '"', ':', '"', (char)nByte, '"', '}' };
        int nValid = nByte >= 0x20 && nByte != '"' && nByte != '\\';
        if (parse_bytes_ok(sString, sizeof(sString)) != nValid)
            return 0;
    }

    return 1;
}

static int test_error_states(void)
{
    static const struct {
        const char *pData;
        size_t nSize;
        xjson_error_t nError;
        size_t nOffset;
    } cases[] = {
        { "{", 1, XJSON_ERR_BOUNDS, 1 },
        { "[", 1, XJSON_ERR_BOUNDS, 1 },
        { "{\"a\":\"unterminated", sizeof("{\"a\":\"unterminated") - 1, XJSON_ERR_BOUNDS, sizeof("{\"a\":\"unterminated") - 1 },
        { "{\"a\":-", sizeof("{\"a\":-") - 1, XJSON_ERR_BOUNDS, sizeof("{\"a\":-") - 1 },
        { "{}x", 3, XJSON_ERR_UNEXPECTED, 2 },
        { "{\"a\":1,\"a\":2}", sizeof("{\"a\":1,\"a\":2}") - 1, XJSON_ERR_EXITS, 12 }
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        xjson_t json;
        if (XJSON_Parse(&json, NULL, cases[i].pData, cases[i].nSize))
        {
            XJSON_Destroy(&json);
            return 0;
        }

        char sError[128];
        int nStatus = json.nError == cases[i].nError &&
            json.nOffset == cases[i].nOffset &&
            json.pRootObj == NULL &&
            XJSON_GetErrorStr(&json, sError, sizeof(sError)) > 0;
        if (!nStatus)
            fprintf(stderr, "json_smoke: error case %zu got error(%d) offset(%zu), expected error(%d) offset(%zu)\n",
                i, json.nError, json.nOffset, cases[i].nError, cases[i].nOffset);
        XJSON_Destroy(&json);
        if (!nStatus) return 0;
    }

    return 1;
}

static int test_pool_and_stress(void)
{
    xpool_t pool;
    if (XPool_Init(&pool, 64) != XSTDOK) return 0;

    const char *pDoc = "{\"pool\":[1,2,3],\"nested\":{\"ok\":true}}";
    xjson_t pooled;
    if (!XJSON_Parse(&pooled, &pool, pDoc, strlen(pDoc)))
    {
        XPool_Destroy(&pool);
        return 0;
    }

    size_t nDumpLen = 0;
    char *pDump = XJSON_Dump(&pooled, 2, &nDumpLen);
    int nStatus = pDump != NULL && parse_bytes_ok(pDump, nDumpLen);
    XJSON_Destroy(&pooled);
    XPool_Destroy(&pool);
    if (!nStatus) return 0;

    const size_t nItems = 2000;
    size_t nCapacity = nItems * 12 + 2;
    char *pArray = (char*)malloc(nCapacity);
    if (pArray == NULL) return 0;

    size_t nOffset = 0;
    pArray[nOffset++] = '[';
    for (size_t i = 0; i < nItems; i++)
    {
        int nWritten = snprintf(&pArray[nOffset], nCapacity - nOffset,
            "%s%zu", i ? "," : "", i);
        if (nWritten < 0 || (size_t)nWritten >= nCapacity - nOffset)
        {
            free(pArray);
            return 0;
        }
        nOffset += (size_t)nWritten;
    }
    pArray[nOffset++] = ']';

    xjson_t large;
    nStatus = XJSON_Parse(&large, NULL, pArray, nOffset) &&
        XJSON_GetArrayLength(large.pRootObj) == nItems;
    if (nStatus) XJSON_Destroy(&large);
    free(pArray);
    if (!nStatus) return 0;

    const size_t nPairs = 1000;
    nCapacity = nPairs * 24 + 2;
    char *pObject = (char*)malloc(nCapacity);
    if (pObject == NULL) return 0;

    nOffset = 0;
    pObject[nOffset++] = '{';
    for (size_t i = 0; i < nPairs; i++)
    {
        int nWritten = snprintf(&pObject[nOffset], nCapacity - nOffset,
            "%s\"k%zu\":%zu", i ? "," : "", i, i);
        if (nWritten < 0 || (size_t)nWritten >= nCapacity - nOffset)
        {
            free(pObject);
            return 0;
        }
        nOffset += (size_t)nWritten;
    }
    pObject[nOffset++] = '}';

    nStatus = XJSON_Parse(&large, NULL, pObject, nOffset) &&
        XJSON_GetU32(XJSON_GetObject(large.pRootObj, "k999")) == 999;
    if (nStatus) XJSON_Destroy(&large);
    free(pObject);
    if (!nStatus) return 0;

    char sDeep[2048];
    nOffset = 0;
    const size_t nDepth = 128;
    for (size_t i = 0; i < nDepth; i++) sDeep[nOffset++] = '[';
    sDeep[nOffset++] = '0';
    for (size_t i = 0; i < nDepth; i++) sDeep[nOffset++] = ']';
    return parse_bytes_ok(sDeep, nOffset);
}

static int test_root_array_and_api_boundaries(void)
{
    xjson_obj_t *pRoot = XJSON_NewArray(NULL, NULL, XFALSE);
    if (pRoot == NULL) return 0;

    xjson_obj_t *pNestedObject = XJSON_NewObject(NULL, NULL, XFALSE);
    xjson_obj_t *pNestedArray = XJSON_NewArray(NULL, NULL, XFALSE);
    if (pNestedObject == NULL || pNestedArray == NULL ||
        XJSON_AddString(pNestedObject, "key", "value") != XJSON_ERR_NONE ||
        XJSON_AddObject(pNestedArray, XJSON_NewBool(NULL, NULL, XTRUE)) != XJSON_ERR_NONE ||
        XJSON_AddObject(pRoot, XJSON_NewNull(NULL, NULL)) != XJSON_ERR_NONE ||
        XJSON_AddObject(pRoot, XJSON_NewString(NULL, NULL, "text")) != XJSON_ERR_NONE ||
        XJSON_AddObject(pRoot, XJSON_NewInt(NULL, NULL, -7)) != XJSON_ERR_NONE ||
        XJSON_AddObject(pRoot, XJSON_NewFloat(NULL, NULL, 2.5)) != XJSON_ERR_NONE ||
        XJSON_AddObject(pRoot, pNestedObject) != XJSON_ERR_NONE ||
        XJSON_AddObject(pRoot, pNestedArray) != XJSON_ERR_NONE)
    {
        XJSON_FreeObject(pNestedObject);
        XJSON_FreeObject(pNestedArray);
        XJSON_FreeObject(pRoot);
        return 0;
    }

    size_t nLength = 0;
    char *pDump = XJSON_DumpObj(pRoot, 0, &nLength);
    if (pDump == NULL || !parse_bytes_ok(pDump, nLength))
    {
        free(pDump);
        XJSON_FreeObject(pRoot);
        return 0;
    }

    xjson_t wrapper;
    XJSON_Init(&wrapper);
    wrapper.pRootObj = pRoot;

    char *pExact = (char*)malloc(nLength + 1);
    char *pShort = (char*)malloc(nLength);
    if (pExact == NULL || pShort == NULL ||
        !XJSON_Write(&wrapper, pExact, nLength + 1) ||
        XJSON_Write(&wrapper, pShort, nLength) ||
        strcmp(pExact, pDump) != 0)
    {
        free(pExact);
        free(pShort);
        free(pDump);
        XJSON_FreeObject(pRoot);
        return 0;
    }

    size_t nWrapperDumpLen = 0;
    size_t nWrapperFormatLen = 0;
    char *pWrapperDump = XJSON_Dump(&wrapper, 0, &nWrapperDumpLen);
    char *pWrapperFormat = XJSON_Format(&wrapper, 2, NULL, &nWrapperFormatLen);
    xjson_writer_t invalidWriter;
    char sZeroSize[1] = { '\0' };
    char sError[8];
    int nStatus =
        pWrapperDump != NULL && nWrapperDumpLen == strlen(pWrapperDump) &&
        pWrapperFormat != NULL && nWrapperFormatLen == strlen(pWrapperFormat) &&
        XJSON_Write(NULL, pExact, nLength + 1) == XJSON_FAILURE &&
        XJSON_Write(&wrapper, NULL, nLength + 1) == XJSON_FAILURE &&
        XJSON_Write(&wrapper, pExact, 0) == XJSON_FAILURE &&
        XJSON_DumpObj(NULL, 0, NULL) == NULL &&
        XJSON_FormatObj(NULL, 0, NULL, NULL) == NULL &&
        XJSON_GetErrorStr(NULL, sError, sizeof(sError)) == 0 &&
        XJSON_GetErrorStr(&wrapper, NULL, sizeof(sError)) == 0 &&
        XJSON_GetErrorStr(&wrapper, sError, 0) == 0 &&
        XJSON_InitWriter(NULL, NULL, NULL, 1) == XJSON_FAILURE &&
        XJSON_InitWriter(&invalidWriter, NULL, sZeroSize, 0) == XJSON_FAILURE &&
        XJSON_AddObject(NULL, NULL) == XJSON_ERR_INVALID &&
        XJSON_AddU16(NULL, "x", 1) == XJSON_ERR_INVALID &&
        XJSON_AddU32(NULL, "x", 1) == XJSON_ERR_INVALID &&
        XJSON_AddU64(NULL, "x", 1) == XJSON_ERR_INVALID &&
        XJSON_AddInt(NULL, "x", 1) == XJSON_ERR_INVALID &&
        XJSON_AddFloat(NULL, "x", 1.0) == XJSON_ERR_INVALID &&
        XJSON_AddString(NULL, "x", "x") == XJSON_ERR_INVALID &&
        XJSON_AddStrIfUsed(NULL, "x", "x") == XJSON_ERR_INVALID &&
        XJSON_AddBool(NULL, "x", XTRUE) == XJSON_ERR_INVALID &&
        XJSON_AddNull(NULL, "x") == XJSON_ERR_INVALID &&
        XJSON_NewFloat(NULL, "nan", NAN) == NULL &&
        XJSON_NewFloat(NULL, "inf", INFINITY) == NULL &&
        XJSON_GetOrCreateObject(NULL, "x", XFALSE) == NULL &&
        XJSON_GetOrCreateArray(NULL, "x", XFALSE) == NULL &&
        XJSON_GetObject(NULL, "x") == NULL &&
        XJSON_GetArrayItem(NULL, 0) == NULL &&
        XJSON_GetArrayLength(NULL) == 0 &&
        XJSON_GetObjects(NULL) == NULL &&
        XJSON_GetInt(NULL) == 0 &&
        XJSON_GetU16(NULL) == 0 &&
        XJSON_GetU32(NULL) == 0 &&
        XJSON_GetU64(NULL) == 0 &&
        XJSON_GetFloat(NULL) == 0.0 &&
        XJSON_GetBool(NULL) == 0 &&
        strcmp(XJSON_GetString(NULL), "") == 0 &&
        XJSON_GetInt(XJSON_GetArrayItem(pRoot, 1)) == 0 &&
        XJSON_GetString(XJSON_GetArrayItem(pRoot, 2))[0] == '\0';

    free(pWrapperDump);
    free(pWrapperFormat);
    free(pExact);
    free(pShort);
    free(pDump);
    XJSON_FreeObject(pRoot);
    XJSON_Init(NULL);
    XJSON_FormatInit(NULL);
    XJSON_Destroy(NULL);
    XJSON_FreeObject(NULL);
    return nStatus;
}

int main(void)
{
    /* EOF after a valid root is normal parser control flow, not an assertion. */
    {
        int nLogCount = 0;
        xjson_t exact;
        xjson_t spaced;

        xlog_init("json-smoke", XLOG_ALL, XFALSE);
        xlog_screen(XFALSE);
        xlog_callback(count_log, &nLogCount);

        int nExactOk = XJSON_Parse(&exact, NULL, "{}", 2);
        int nSpacedOk = XJSON_Parse(&spaced, NULL, "{} \r\n\t", 6);
        if (nExactOk) XJSON_Destroy(&exact);
        if (nSpacedOk) XJSON_Destroy(&spaced);
        xlog_destroy();

        CHECK(nExactOk && nSpacedOk, "valid root EOF parsing");
        CHECK(nLogCount == 0, "valid root EOF must not emit assertion logs");
    }

    CHECK(test_parse_matrix(), "valid/invalid parse matrix");
    CHECK(test_parse_boundaries(), "parse boundaries and truncations");
    CHECK(test_byte_boundaries(), "byte boundaries");
    CHECK(test_error_states(), "error states");

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
    CHECK(json.nError == XJSON_ERR_NONE, "valid exact-length parse has no error");

    xjson_obj_t *pRoot = json.pRootObj;
    CHECK(pRoot != NULL, "root object");

    const char *pType = XJSON_GetString(XJSON_GetObject(pRoot, "type"));
    CHECK(pType != NULL && strcmp(pType, "manager") == 0, "string field");
    CHECK(XJSON_GetU32(XJSON_GetObject(pRoot, "sessionId")) == 42, "u32 field");
    CHECK(XJSON_GetInt(XJSON_GetObject(pRoot, "version")) == 1, "int field");
    CHECK(XJSON_GetBool(XJSON_GetObject(pRoot, "force")) == 1, "true field");
    CHECK(XJSON_GetBool(XJSON_GetObject(pRoot, "cancel")) == 0, "false field");
    CHECK(XJSON_GetFloat(XJSON_GetObject(pRoot, "ratio")) == 0.5, "float field");
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
    CHECK(XJSON_AddNull(pBuilt, "nil") == XJSON_ERR_NONE, "add null");
    CHECK(XJSON_AddFloat(pBuilt, "f", 1.25) == XJSON_ERR_NONE, "add float");
    CHECK(XJSON_AddString(pBuilt, "k", "replacement") == XJSON_ERR_EXITS,
        "duplicate rejected when updates disabled");

    xjson_obj_t *pArray = XJSON_GetOrCreateArray(pBuilt, "items", XFALSE);
    CHECK(pArray != NULL, "create array");
    CHECK(XJSON_AddObject(pArray, XJSON_NewInt(pArray->pPool, NULL, -7)) == XJSON_ERR_NONE,
        "add array item");
    CHECK(XJSON_GetArrayLength(pArray) == 1 &&
          XJSON_GetInt(XJSON_GetArrayItem(pArray, 0)) == -7, "array item value");
    CHECK(XJSON_RemoveArrayItem(pArray, 0) == XARRAY_SUCCESS &&
          XJSON_GetArrayLength(pArray) == 0, "remove array item");

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
    CHECK(!parse_ok("{} trailing"), "trailing garbage");
    CHECK(!parse_ok("{\"a\":01}"), "leading-zero number");
    CHECK(!parse_ok("{\"a\":1.}"), "missing fractional digits");
    CHECK(!parse_ok("{\"a\":.1}"), "missing integer digits");
    CHECK(!parse_ok("{\"a\":1e}"), "missing exponent digits");
    CHECK(!parse_ok("{\"a\":true false}"), "adjacent values");
    CHECK(!parse_ok("{\"a\":\"bad\nstring\"}"), "raw newline in string");
    CHECK(!parse_ok("{\"a\":\"bad\\qescape\"}"), "invalid string escape");
    CHECK(!parse_ok("{\"a\":\"bad\\u12xz\"}"), "invalid unicode escape");
    CHECK(parse_ok("{\"a\":-1.25e+3,\"b\":0,\"c\":1E-2}"),
        "valid JSON number grammar");
    CHECK(parse_ok("{\"a\":\"quote: \\\" slash: \\\\ unicode: \\u0041\"}"),
        "valid JSON string escapes");
    CHECK(parse_ok("{\r\n\t\"a\" : 1\r\n}"), "valid JSON whitespace");
    CHECK(parse_ok("{} \r\n\t"), "valid trailing whitespace has no error");

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

    CHECK(test_builders_and_writers(), "builders and writers");
    CHECK(test_generated_string_edges(), "generated string edge cases");
    CHECK(test_pool_and_stress(), "pool and stress cases");
    CHECK(test_root_array_and_api_boundaries(), "root array and API boundaries");

    puts("json_smoke: OK");
    return 0;
}
