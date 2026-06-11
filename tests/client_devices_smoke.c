#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "src/common/includes.h"
#include "src/client/devices.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "client_devices_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static void clear_pair(xmap_pair_t *pPair)
{
    free(pPair->pKey);
    free(pPair->pData);
    pPair->pKey = NULL;
    pPair->pData = NULL;
}

static int init_map(xmap_t *pMap)
{
    if (XMap_Init(pMap, NULL, 2) != XMAP_OK) return 0;
    pMap->clearCb = clear_pair;
    return 1;
}

static int write_text(const char *pPath, const char *pText)
{
    FILE *pFile = fopen(pPath, "wb");
    if (pFile == NULL) return 0;
    size_t nLen = strlen(pText);
    int nOk = fwrite(pText, 1, nLen, pFile) == nLen;
    return fclose(pFile) == 0 && nOk;
}

int main(void)
{
    xmap_t map;
    CHECK(init_map(&map), "init map");

    CHECK(!DirectGate_Devices_Add(NULL, "one", "id-1", XFALSE), "add NULL map");
    CHECK(!DirectGate_Devices_Add(&map, NULL, "id-1", XFALSE), "add NULL name");
    CHECK(!DirectGate_Devices_Add(&map, "", "id-1", XFALSE), "add empty name");
    CHECK(!DirectGate_Devices_Add(&map, "one", "", XFALSE), "add empty id");
    CHECK(DirectGate_Devices_Add(&map, "one", "id-1", XFALSE), "add first");
    CHECK(map.nCount == 1, "first count");
    CHECK(!DirectGate_Devices_Add(&map, "one", "id-2", XFALSE),
        "duplicate without force");

    char sId[64];
    memset(sId, 0x7f, sizeof(sId));
    CHECK(DirectGate_Devices_Search(&map, "one", sId, sizeof(sId)), "search first");
    CHECK(strcmp(sId, "id-1") == 0, "search first value");
    CHECK(!DirectGate_Devices_Search(&map, "missing", sId, sizeof(sId)),
        "search missing");

    CHECK(DirectGate_Devices_Add(&map, "one", "id-2", XTRUE), "force overwrite");
    CHECK(map.nCount == 1, "overwrite count");
    CHECK(DirectGate_Devices_Search(&map, "one", sId, sizeof(sId)), "search overwrite");
    CHECK(strcmp(sId, "id-2") == 0, "overwrite value");

    CHECK(DirectGate_Devices_Add(&map, "two", "a-long-device-id", XFALSE), "add second");
    char sTiny[5];
    CHECK(DirectGate_Devices_Search(&map, "two", sTiny, sizeof(sTiny)),
        "search truncation");
    CHECK(strcmp(sTiny, "a-lo") == 0, "search truncates and terminates");

    CHECK(!DirectGate_Devices_Write(NULL, "/tmp/unused"), "write NULL map");
    CHECK(!DirectGate_Devices_Write(&map, ""), "write empty path");

    char sRoot[] = "/tmp/directgate_devices.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "mkdtemp");
    char sInput[XPATH_MAX];
    char sOutput[XPATH_MAX];
    char sMissing[XPATH_MAX];
    snprintf(sInput, sizeof(sInput), "%s/input", sRoot);
    snprintf(sOutput, sizeof(sOutput), "%s/output", sRoot);
    snprintf(sMissing, sizeof(sMissing), "%s/missing", sRoot);

    CHECK(!DirectGate_Devices_Load(&map, sMissing), "load missing file");
    CHECK(DirectGate_Devices_Write(&map, sOutput), "write populated map");

    xmap_t roundtrip;
    CHECK(init_map(&roundtrip), "init roundtrip map");
    CHECK(DirectGate_Devices_Load(&roundtrip, sOutput), "load written map");
    CHECK(roundtrip.nCount == 2, "roundtrip count");
    CHECK(DirectGate_Devices_Search(&roundtrip, "one", sId, sizeof(sId)) &&
          strcmp(sId, "id-2") == 0, "roundtrip overwritten value");

    CHECK(write_text(sInput,
        "\n"
        "   alpha    id-a   ignored-column\n"
        "malformed-only-name\n"
        "\tbeta\tid-b\n"
        "alpha id-new\n"
        "      \n"), "write parser fixture");

    xmap_t parsed;
    CHECK(init_map(&parsed), "init parsed map");
    CHECK(DirectGate_Devices_Load(&parsed, sInput), "load parser fixture");
    CHECK(parsed.nCount == 2, "parser skips malformed and overwrites duplicate");
    CHECK(DirectGate_Devices_Search(&parsed, "alpha", sId, sizeof(sId)) &&
          strcmp(sId, "id-new") == 0, "duplicate load uses last value");
    CHECK(DirectGate_Devices_Search(&parsed, "beta", sId, sizeof(sId)) &&
          strcmp(sId, "id-b") == 0, "tab-separated load");

    xmap_t empty;
    CHECK(init_map(&empty), "init empty map");
    CHECK(!DirectGate_Devices_Write(&empty, sOutput), "write empty map");
    CHECK(write_text(sInput, "\n invalid\n"), "write invalid fixture");
    CHECK(!DirectGate_Devices_Load(&empty, sInput), "load no valid devices");

    XMap_Destroy(&empty);
    XMap_Destroy(&parsed);
    XMap_Destroy(&roundtrip);
    XMap_Destroy(&map);
    CHECK(unlink(sInput) == 0, "unlink input");
    CHECK(unlink(sOutput) == 0, "unlink output");
    CHECK(rmdir(sRoot) == 0, "rmdir root");

    puts("client_devices_smoke: OK");
    return 0;
}
