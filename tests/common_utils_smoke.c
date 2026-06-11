#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "src/common/common.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "common_utils_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static int read_file(const char *pPath, char *pOut, size_t nOutSize)
{
    FILE *pFile = fopen(pPath, "rb");
    if (pFile == NULL) return 0;

    size_t nRead = fread(pOut, 1, nOutSize - 1, pFile);
    int nOk = !ferror(pFile) && feof(pFile);
    pOut[nRead] = '\0';
    fclose(pFile);
    return nOk;
}

static int has_entry_prefix(const char *pDirPath, const char *pPrefix)
{
    DIR *pDir = opendir(pDirPath);
    if (pDir == NULL) return 0;

    size_t nPrefixLen = strlen(pPrefix);
    int nFound = 0;
    struct dirent *pEntry = NULL;
    while ((pEntry = readdir(pDir)) != NULL)
    {
        if (strncmp(pEntry->d_name, pPrefix, nPrefixLen) == 0)
        {
            nFound = 1;
            break;
        }
    }

    closedir(pDir);
    return nFound;
}

int main(void)
{
    char sValue[32];
    CHECK(DirectGate_GetQueryValue(NULL, "rk", sValue, sizeof(sValue)) == 0,
        "NULL URI");
    CHECK(DirectGate_GetQueryValue("/websock?rk=abc", NULL, sValue, sizeof(sValue)) == 0,
        "NULL query key");
    CHECK(DirectGate_GetQueryValue("/websock?rk=abc", "rk", sValue, 0) == 0,
        "zero output size");
    CHECK(DirectGate_GetQueryValue("/websock?rk=abc&token=xyz", "rk",
        sValue, sizeof(sValue)) == 3, "query value length");
    CHECK(strcmp(sValue, "abc") == 0, "query value content");
    CHECK(DirectGate_GetQueryValue("/websock?token2=no&token=yes", "token",
        sValue, sizeof(sValue)) == 3, "query key must not match prefixes");
    CHECK(strcmp(sValue, "yes") == 0, "query prefix-safe content");
    CHECK(DirectGate_GetQueryValue("/websock", "rk", sValue, sizeof(sValue)) == 0,
        "missing query must return zero");
    CHECK(sValue[0] == '\0', "missing query must clear output");
    CHECK(DirectGate_GetQueryValue("/websock?&&rk=abc&&rk=last", "rk",
        sValue, sizeof(sValue)) == 3 && strcmp(sValue, "abc") == 0,
        "query skips repeated separators and uses first match");
    char sTiny[3];
    CHECK(DirectGate_GetQueryValue("/websock?rk=abcdef", "rk",
        sTiny, sizeof(sTiny)) == 2 && strcmp(sTiny, "ab") == 0,
        "query output truncation");
    CHECK(DirectGate_GetQueryValue("/websock?rk=&x=y", "rk",
        sValue, sizeof(sValue)) == 0 && sValue[0] == '\0',
        "empty query value");

    char sLine1[] = "hello\r\n";
    size_t nLine1 = strlen(sLine1);
    CHECK(DirectGate_RemoveNewLine(sLine1, &nLine1) == 5, "CRLF length");
    CHECK(nLine1 == 5 && strcmp(sLine1, "hello") == 0, "CRLF removal");

    char sLine2[] = "hello\n";
    size_t nLine2 = strlen(sLine2);
    CHECK(DirectGate_RemoveNewLine(sLine2, &nLine2) == 5, "LF length");
    CHECK(nLine2 == 5 && strcmp(sLine2, "hello") == 0, "LF removal");
    char sLine3[] = "hello\r";
    size_t nLine3 = strlen(sLine3);
    CHECK(DirectGate_RemoveNewLine(sLine3, &nLine3) == 5 &&
          strcmp(sLine3, "hello") == 0, "CR removal");
    char sLine4[] = "hello";
    size_t nLine4 = strlen(sLine4);
    CHECK(DirectGate_RemoveNewLine(sLine4, &nLine4) == 5 &&
          strcmp(sLine4, "hello") == 0, "no newline unchanged");
    CHECK(DirectGate_RemoveNewLine(NULL, &nLine4) == -1, "NULL newline input");

    const uint8_t sBytes[] = { 'a', '\r', '\n', 'b' };
    size_t nOffset = 99;
    CHECK(DirectGate_FindCRLF(sBytes, sizeof(sBytes), &nOffset), "CRLF find");
    CHECK(nOffset == 1, "CRLF offset");
    CHECK(!DirectGate_FindCRLF((const uint8_t*)"abc\r", 4, NULL),
        "partial CRLF must not match");
    CHECK(DirectGate_FindCRLF((const uint8_t*)"\r\n", 2, &nOffset) && nOffset == 0,
        "CRLF at beginning");
    CHECK(!DirectGate_FindCRLF(NULL, 0, &nOffset), "NULL CRLF input");

    int64_t nValue = 0;
    CHECK(DirectGate_ParseI64((const uint8_t*)"-42", 3, &nValue),
        "parse negative int64");
    CHECK(nValue == -42, "negative int64 value");
    CHECK(!DirectGate_ParseI64((const uint8_t*)"42x", 3, &nValue),
        "invalid int64 must fail");
    CHECK(DirectGate_ParseI64((const uint8_t*)"9223372036854775807", 19, &nValue) &&
          nValue == INT64_MAX, "parse int64 max");
    CHECK(DirectGate_ParseI64((const uint8_t*)"-9223372036854775808", 20, &nValue) &&
          nValue == INT64_MIN, "parse int64 min");
    CHECK(!DirectGate_ParseI64((const uint8_t*)"9223372036854775808", 19, &nValue),
        "reject positive int64 overflow");
    CHECK(!DirectGate_ParseI64((const uint8_t*)"-9223372036854775809", 20, &nValue),
        "reject negative int64 overflow");
    CHECK(!DirectGate_ParseI64((const uint8_t*)"+", 1, &nValue),
        "reject sign without digits");
    CHECK(!DirectGate_ParseI64((const uint8_t*)"", 0, &nValue), "reject empty int64");

    CHECK(DirectGate_IsAPIEndpointAllowed("https://api.example.test"),
        "HTTPS API endpoint should be allowed");
#ifdef DIRECTGATE_DEBUG
    CHECK(DirectGate_IsAPIEndpointAllowed("http://127.0.0.1:5000"),
        "HTTP API endpoint should be allowed in debug mode");
#else
    CHECK(!DirectGate_IsAPIEndpointAllowed("http://127.0.0.1:5000"),
        "HTTP API endpoint must be rejected in production mode");
#endif
    CHECK(!DirectGate_IsAPIEndpointAllowed("wss://api.example.test"),
        "non-HTTP API endpoint must be rejected");
    CHECK(!DirectGate_IsAPIEndpointAllowed("https://"),
        "API endpoint without host must be rejected");

    char sTrim[] = "abc \t\r\n";
    DirectGate_TrimStringRight(sTrim);
    CHECK(strcmp(sTrim, "abc") == 0, "right trim");
    char sAllSpace[] = " \t\r\n";
    DirectGate_TrimStringRight(sAllSpace);
    CHECK(sAllSpace[0] == '\0', "right trim all whitespace");
    CHECK(*DirectGate_JumpWiteSpace(" \tvalue") == 'v', "jump whitespace");
    CHECK(*DirectGate_JumpWiteSpace(" \t") == '\0', "jump all whitespace");
    CHECK(*DirectGate_SkipToken("value rest") == ' ', "skip token");
    CHECK(*DirectGate_SkipToken("") == '\0', "skip empty token");
    CHECK(DirectGate_JumpWiteSpace(NULL) == NULL && DirectGate_SkipToken(NULL) == NULL,
        "token helpers reject NULL");

    char sRoot[] = "/tmp/directgate_common_private.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "mkdtemp private root");

    char sPrivateDir[XPATH_MAX];
    char sPrivateFile[XPATH_MAX];
    snprintf(sPrivateDir, sizeof(sPrivateDir), "%s/private", sRoot);
    snprintf(sPrivateFile, sizeof(sPrivateFile), "%s/private/config.json", sRoot);

    const uint8_t sSecret[] = "secret";
    CHECK(!DirectGate_WritePrivateFile(NULL, sSecret, sizeof(sSecret) - 1),
        "private writer rejects NULL path");
    CHECK(!DirectGate_WritePrivateFile(sPrivateFile, NULL, sizeof(sSecret) - 1),
        "private writer rejects NULL data");
    CHECK(!DirectGate_WritePrivateFile(sPrivateFile, sSecret, 0),
        "private writer rejects empty data");
    CHECK(DirectGate_WritePrivateFile(sPrivateFile, sSecret, sizeof(sSecret) - 1),
        "write private file");

    struct stat st;
    CHECK(stat(sPrivateDir, &st) == 0, "stat private dir");
    CHECK((st.st_mode & 0777) == 0700, "private dir mode");
    CHECK(stat(sPrivateFile, &st) == 0, "stat private file");
    CHECK((st.st_mode & 0777) == 0600, "private file mode");

    ino_t nOriginalInode = st.st_ino;
    const uint8_t sUpdatedSecret[] = "updated-secret";
    CHECK(DirectGate_WritePrivateFile(sPrivateFile, sUpdatedSecret, sizeof(sUpdatedSecret) - 1),
        "atomically replace private file");
    CHECK(stat(sPrivateFile, &st) == 0, "stat replaced private file");
    CHECK(st.st_ino != nOriginalInode,
        "private file replacement must rename a new inode");
    CHECK((st.st_mode & 0777) == 0600, "replaced private file mode");

    char sSavedSecret[64];
    CHECK(read_file(sPrivateFile, sSavedSecret, sizeof(sSavedSecret)),
        "read replaced private file");
    CHECK(strcmp(sSavedSecret, (const char*)sUpdatedSecret) == 0,
        "replaced private file content");
    CHECK(!has_entry_prefix(sPrivateDir, "config.json.tmp."),
        "atomic private file write must not leave temp files");

    char sLinkTarget[XPATH_MAX];
    char sLinkPath[XPATH_MAX];
    snprintf(sLinkTarget, sizeof(sLinkTarget), "%s/private/link-target.json", sRoot);
    snprintf(sLinkPath, sizeof(sLinkPath), "%s/private/config-link.json", sRoot);
    CHECK(DirectGate_WritePrivateFile(sLinkTarget, sSecret, sizeof(sSecret) - 1),
        "write private symlink target");
    CHECK(symlink(sLinkTarget, sLinkPath) == 0, "create private file symlink");
    CHECK(!DirectGate_WritePrivateFile(sLinkPath, sUpdatedSecret, sizeof(sUpdatedSecret) - 1),
        "private file writer must reject symlink target");
    CHECK(read_file(sLinkTarget, sSavedSecret, sizeof(sSavedSecret)),
        "read private symlink target");
    CHECK(strcmp(sSavedSecret, (const char*)sSecret) == 0,
        "rejected symlink write must preserve target content");
    CHECK(!has_entry_prefix(sPrivateDir, "config-link.json.tmp."),
        "rejected symlink write must not leave temp files");
    CHECK(unlink(sLinkPath) == 0, "cleanup private file symlink");
    CHECK(unlink(sLinkTarget) == 0, "cleanup private symlink target");

    CHECK(unlink(sPrivateFile) == 0, "cleanup private file");
    CHECK(rmdir(sPrivateDir) == 0, "cleanup private dir");

    char sCwd[XPATH_MAX];
    CHECK(getcwd(sCwd, sizeof(sCwd)) != NULL, "getcwd before relative private file");
    CHECK(chdir(sRoot) == 0, "chdir relative private file root");
    CHECK(DirectGate_WritePrivateFile("relative-private.json", sSecret, sizeof(sSecret) - 1),
        "write private file without parent directory");
    CHECK(stat("relative-private.json", &st) == 0, "stat relative private file");
    CHECK((st.st_mode & 0777) == 0600, "relative private file mode");
    CHECK(unlink("relative-private.json") == 0, "cleanup relative private file");
    CHECK(DirectGate_WritePrivateFile("./relative-dot-private.json", sSecret, sizeof(sSecret) - 1),
        "write private file in current directory");
    CHECK(stat("./relative-dot-private.json", &st) == 0, "stat current directory private file");
    CHECK((st.st_mode & 0777) == 0600, "current directory private file mode");
    CHECK(unlink("./relative-dot-private.json") == 0, "cleanup current directory private file");
    CHECK(chdir(sCwd) == 0, "restore cwd after relative private file");

    char sExistingDir[XPATH_MAX];
    char sExistingFile[XPATH_MAX];
    snprintf(sExistingDir, sizeof(sExistingDir), "%s/existing", sRoot);
    snprintf(sExistingFile, sizeof(sExistingFile), "%s/existing/config.json", sRoot);
    CHECK(mkdir(sExistingDir, 0755) == 0, "mkdir existing shared dir");
    CHECK(chmod(sExistingDir, 0755) == 0, "chmod existing shared dir");
    CHECK(DirectGate_WritePrivateFile(sExistingFile, sSecret, sizeof(sSecret) - 1),
        "write private file in existing directory");
    CHECK(stat(sExistingDir, &st) == 0, "stat existing shared dir");
    CHECK((st.st_mode & 0777) == 0755,
        "private file writer must not chmod existing directories");
    CHECK(stat(sExistingFile, &st) == 0, "stat private file in existing directory");
    CHECK((st.st_mode & 0777) == 0600,
        "private file in existing directory mode");
    CHECK(unlink(sExistingFile) == 0, "cleanup private file in existing directory");
    CHECK(rmdir(sExistingDir) == 0, "cleanup existing shared dir");
    CHECK(rmdir(sRoot) == 0, "cleanup private root");

    xtime_t parsedTime;
    CHECK(XTime_FromISO(&parsedTime, "2024-02-29T12:34:56Z") == 6,
        "valid ISO leap-day timestamp should parse");
    CHECK(parsedTime.nYear == 2024 && parsedTime.nMonth == 2 && parsedTime.nDay == 29,
        "parsed ISO timestamp fields");
    CHECK(XTime_FromISO(&parsedTime, "2023-02-29T12:34:56Z") == 0,
        "invalid ISO leap-day timestamp should fail");
    CHECK(XTime_GetMonthDays(2024, 2) == 29 && XTime_GetMonthDays(2023, 2) == 28,
        "February day count");

    puts("common_utils_smoke: OK");
    return 0;
}
