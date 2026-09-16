/* Search criteria parsing: the numeric filters a browser sends with a
 * file-manager search request.
 *
 * Every one of these values arrives as a string over the wire and ends up in
 * an xsearch_t field whose "unset" marker is a value the string could also
 * produce - 0 for the size bounds, -1 for the exact size and the link count.
 * A parser that wraps or truncates therefore does not return a wrong bound, it
 * returns *no* bound, and the search silently answers a question nobody asked.
 * These cases pin the refusals that keep that from happening.
 *
 * Compiles search.c directly: the parsers are static, and their boundaries are
 * what needs asserting by value rather than through a running search. */

#include <stdio.h>
#include <string.h>

#include "src/agent/search.c"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "search_criteria_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

/* search.c reports through the session and renders entries through the file
 * manager; nothing here runs a search, so the boundary is stubbed. */
xjson_obj_t* DirectGate_Files_CreateEntryJson(const char *pName, const char *pDirPath, const xstat_t *pStat)
{
    (void)pName; (void)pDirPath; (void)pStat;
    return NULL;
}

int DirectGate_Session_SendManagerResp(directgate_session_t *pSession,
                                       const char *pAction, const char *pStatus,
                                       const char *pReason, const char *pPath)
{
    (void)pSession; (void)pAction; (void)pStatus; (void)pReason; (void)pPath;
    return XSTDOK;
}

int DirectGate_Session_SendManagerData(directgate_session_t *pSession, const char *pAction,
                                       const char *pStatus, const char *pPath,
                                       const uint8_t *pPayload, size_t nPayloadLen)
{
    (void)pSession; (void)pAction; (void)pStatus; (void)pPath;
    (void)pPayload; (void)nPayloadLen;
    return XSTDOK;
}

static int test_parse_size(void)
{
    size_t nSize = 12345;

    CHECK(DirectGate_Search_ParseSize(NULL, &nSize) < 0, "a NULL size string is refused");
    CHECK(DirectGate_Search_ParseSize("100", NULL) < 0, "a NULL output pointer is refused");
    CHECK(DirectGate_Search_ParseSize("", &nSize) < 0, "an empty size string is refused");
    CHECK(DirectGate_Search_ParseSize(" 100", &nSize) < 0, "a leading space is refused");
    CHECK(DirectGate_Search_ParseSize("-1", &nSize) < 0, "a negative size is refused");
    CHECK(DirectGate_Search_ParseSize("+1", &nSize) < 0, "a signed size is refused");
    CHECK(DirectGate_Search_ParseSize("abc", &nSize) < 0, "a non-numeric size is refused");
    CHECK(DirectGate_Search_ParseSize("100t", &nSize) < 0, "an unknown size suffix is refused");
    CHECK(DirectGate_Search_ParseSize("100kk", &nSize) < 0, "a doubled size suffix is refused");
    CHECK(DirectGate_Search_ParseSize("1 0", &nSize) < 0, "an embedded space is refused");
    CHECK(nSize == 12345, "a refused size must not touch the output");

    CHECK(DirectGate_Search_ParseSize("0", &nSize) == XSTDOK && nSize == 0,
        "zero parses as zero");
    CHECK(DirectGate_Search_ParseSize("1024", &nSize) == XSTDOK && nSize == 1024,
        "a plain byte count parses unscaled");
    CHECK(DirectGate_Search_ParseSize("1k", &nSize) == XSTDOK && nSize == 1024,
        "the k suffix scales by 1024");
    CHECK(DirectGate_Search_ParseSize("2M", &nSize) == XSTDOK && nSize == 2ULL * 1024 * 1024,
        "the m suffix is case insensitive");
    CHECK(DirectGate_Search_ParseSize("3g", &nSize) == XSTDOK && nSize == 3ULL * 1024 * 1024 * 1024,
        "the g suffix scales by a gigabyte");
    CHECK(DirectGate_Search_ParseSize("5k ", &nSize) == XSTDOK && nSize == 5120,
        "trailing space after a suffix is tolerated");

    /* The wrap this refuses used to land exactly on zero, which the search
       reads as "no bound", so an impossible filter matched every file. */
    CHECK(DirectGate_Search_ParseSize("17179869184g", &nSize) < 0,
        "a size whose suffix would wrap to zero is refused, not wrapped");
    CHECK(DirectGate_Search_ParseSize("18446744073709551615k", &nSize) < 0,
        "a size whose suffix would overflow is refused");
    CHECK(DirectGate_Search_ParseSize("18446744073709551616", &nSize) < 0,
        "a size beyond the parser's range is refused rather than saturated");
    CHECK(DirectGate_Search_ParseSize("99999999999999999999999", &nSize) < 0,
        "a wildly oversized value is refused");
    CHECK(nSize == 5120, "a refused oversized size must not touch the output");

    /* The largest value that still fits every supported build. */
    char sMax[64];
    snprintf(sMax, sizeof(sMax), "%llu", (unsigned long long)SIZE_MAX);
    CHECK(DirectGate_Search_ParseSize(sMax, &nSize) == XSTDOK && nSize == SIZE_MAX,
        "the largest representable size is accepted exactly");

    return 0;
}

static int test_parse_count(void)
{
    int nCount = 7;

    CHECK(DirectGate_Search_ParseCount(NULL, &nCount) < 0, "a NULL count string is refused");
    CHECK(DirectGate_Search_ParseCount("2", NULL) < 0, "a NULL count output is refused");
    CHECK(DirectGate_Search_ParseCount("", &nCount) < 0, "an empty count is refused");
    CHECK(DirectGate_Search_ParseCount("2x", &nCount) < 0, "a count with trailing junk is refused");
    CHECK(DirectGate_Search_ParseCount("x", &nCount) < 0, "a non-numeric count is refused");
    CHECK(nCount == 7, "a refused count must not touch the output");

    CHECK(DirectGate_Search_ParseCount("3", &nCount) == XSTDOK && nCount == 3,
        "a plain link count parses");
    CHECK(DirectGate_Search_ParseCount("2147483647", &nCount) == XSTDOK && nCount == INT_MAX,
        "the largest link count is accepted exactly");

    /* Truncation used to turn these negative, and a negative link count is the
       "no link-count filter" marker - so the filter vanished instead. */
    CHECK(DirectGate_Search_ParseCount("2147483648", &nCount) < 0,
        "a link count one past the int range is refused, not truncated");
    CHECK(DirectGate_Search_ParseCount("99999999999999999999", &nCount) < 0,
        "a link count beyond the parser's range is refused");
    CHECK(nCount == INT_MAX, "a refused oversized count must not touch the output");

    return 0;
}

static int test_parse_types_and_permissions(void)
{
    CHECK(DirectGate_Search_ParseFileTypes(NULL) < 0, "a NULL type list is refused");
    CHECK(DirectGate_Search_ParseFileTypes("") < 0, "an empty type list is refused");
    CHECK(DirectGate_Search_ParseFileTypes("z") < 0, "an unknown file type is refused");
    CHECK(DirectGate_Search_ParseFileTypes("fz") < 0, "one bad letter refuses the whole list");

    CHECK(DirectGate_Search_ParseFileTypes("f") == XF_REGULAR, "f selects regular files");
    CHECK(DirectGate_Search_ParseFileTypes("D") == XF_DIRECTORY, "the type letters are case insensitive");
    CHECK(DirectGate_Search_ParseFileTypes("f,d") == (XF_REGULAR | XF_DIRECTORY),
        "separators combine types rather than ending the list");
    CHECK(DirectGate_Search_ParseFileTypes("f d;l") == (XF_REGULAR | XF_DIRECTORY | XF_SYMLINK),
        "spaces and semicolons are separators too");

    CHECK(DirectGate_Search_ParsePermissions(NULL) < 0, "NULL permissions are refused");
    CHECK(DirectGate_Search_ParsePermissions("") < 0, "empty permissions are refused");
    CHECK(DirectGate_Search_ParsePermissions("not-a-mode") < 0, "an unparsable mode is refused");

    /* The criterion libxutils compares against is the chmod digits read as a
       decimal int, so the round trip has to land on exactly that. */
    CHECK(DirectGate_Search_ParsePermissions("rw-r--r--") == 644,
        "a symbolic mode becomes the digits the search compares");
    CHECK(DirectGate_Search_ParsePermissions("rwxr-xr-x") == 755,
        "an executable mode becomes its chmod digits");
    CHECK(DirectGate_Search_ParsePermissions("r--------") == 400,
        "a mode with only the owner read bit becomes 400");
    CHECK(DirectGate_Search_ParsePermissions("rwxrwxrwx") == 777,
        "a fully open mode becomes 777");
    CHECK(DirectGate_Search_ParsePermissions("rw-r--r-") < 0,
        "a mode one character short is refused");
    CHECK(DirectGate_Search_ParsePermissions("rw-r--r--x") < 0,
        "a mode one character too long is refused");
    CHECK(DirectGate_Search_ParsePermissions("xw-r--r--") < 0,
        "a mode letter in the wrong column is refused");

    /* An all-clear mode parses, but the criterion cannot tell 000 apart from
       "no permission filter" - the search reads both as unset. Pinned here so
       the ambiguity is a known property rather than a surprise. */
    CHECK(DirectGate_Search_ParsePermissions("---------") == 0,
        "an all-clear mode parses as zero, which the search reads as unset");

    return 0;
}

/* The criteria only matter once they reach the xsearch_t the worker runs, and
 * that is where the exact-size filter is narrowed to an int. */
static int test_apply_criteria(void)
{
    directgate_search_t search;
    xsearch_t ctx;

    memset(&search, 0, sizeof(search));

    XSearch_Init(&ctx, "*");
    xstrncpy(search.sMaxSize, sizeof(search.sMaxSize), "1m");
    CHECK(DirectGate_Search_ApplyCriteria(&search, &ctx) == XSTDOK,
        "a valid maximum size is applied");
    CHECK(ctx.nMaxSize == 1024 * 1024, "the maximum size reaches the search context");
    XSearch_Destroy(&ctx);

    XSearch_Init(&ctx, "*");
    xstrncpy(search.sMaxSize, sizeof(search.sMaxSize), "17179869184g");
    CHECK(DirectGate_Search_ApplyCriteria(&search, &ctx) == XSTDERR,
        "an overflowing maximum size fails the whole request");
    CHECK(ctx.nMaxSize == 0, "a refused maximum size leaves the search unbounded rather than mis-bounded");
    XSearch_Destroy(&ctx);

    memset(&search, 0, sizeof(search));
    XSearch_Init(&ctx, "*");
    xstrncpy(search.sFileSize, sizeof(search.sFileSize), "4294967295");
    CHECK(DirectGate_Search_ApplyCriteria(&search, &ctx) == XSTDERR,
        "an exact size that does not fit the int criterion is refused");
    CHECK(ctx.nFileSize == -1, "the refused exact size must not land on the unset marker");
    XSearch_Destroy(&ctx);

    XSearch_Init(&ctx, "*");
    xstrncpy(search.sFileSize, sizeof(search.sFileSize), "2147483647");
    CHECK(DirectGate_Search_ApplyCriteria(&search, &ctx) == XSTDOK,
        "the largest exact size the criterion can hold is accepted");
    CHECK(ctx.nFileSize == INT_MAX, "the exact size reaches the search context");
    XSearch_Destroy(&ctx);

    memset(&search, 0, sizeof(search));
    XSearch_Init(&ctx, "*");
    xstrncpy(search.sLinkCount, sizeof(search.sLinkCount), "2147483648");
    CHECK(DirectGate_Search_ApplyCriteria(&search, &ctx) == XSTDERR,
        "an out-of-range link count fails the whole request");
    CHECK(ctx.nLinkCount == -1, "the refused link count must not land on the unset marker");
    XSearch_Destroy(&ctx);

    return 0;
}

int main(void)
{
    if (test_parse_size()) return 1;
    if (test_parse_count()) return 1;
    if (test_parse_types_and_permissions()) return 1;
    if (test_apply_criteria()) return 1;

    puts("search_criteria_smoke: OK");
    return 0;
}
