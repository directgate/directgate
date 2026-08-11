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

/*
 * The connectability rules here have to stay in step with
 * front/src/lib/devices/device-domain.ts, so the fixture covers one device
 * per rule rather than only the happy path.
 */
static const char *g_pDeviceListBody =
    "{\"devices\":["
      "{\"id\":\"id-online\",\"name\":\"workstation\",\"status\":\"PAIRED\","
       "\"enrollmentStatus\":\"ACTIVE\",\"requiresPairing\":false,"
       "\"isOnline\":true,\"isOwner\":true,\"revokedAt\":null},"
      "{\"id\":\"id-offline\",\"name\":\"laptop\",\"status\":\"PAIRED\","
       "\"enrollmentStatus\":\"EXTENDED\",\"requiresPairing\":false,"
       "\"isOnline\":false,\"isOwner\":true,\"revokedAt\":null},"
      "{\"id\":\"id-shared\",\"name\":\"buildbox\",\"status\":\"PAIRED\","
       "\"enrollmentStatus\":\"ACTIVE\",\"requiresPairing\":false,"
       "\"isOnline\":true,\"isOwner\":false,\"shareStatus\":\"ACCEPTED\","
       "\"ownerEmail\":\"owner@example.test\",\"revokedAt\":null},"
      "{\"id\":\"id-pending\",\"name\":\"invited\",\"status\":\"PAIRED\","
       "\"enrollmentStatus\":\"ACTIVE\",\"requiresPairing\":false,"
       "\"isOnline\":true,\"isOwner\":false,\"shareStatus\":\"PENDING\","
       "\"revokedAt\":null},"
      "{\"id\":\"id-expired\",\"name\":\"stale\",\"status\":\"PAIRED\","
       "\"enrollmentStatus\":\"EXPIRED\",\"requiresPairing\":false,"
       "\"isOnline\":false,\"isOwner\":true,\"revokedAt\":null},"
      "{\"id\":\"id-unpaired\",\"name\":\"fresh\",\"status\":\"CREATED\","
       "\"enrollmentStatus\":null,\"requiresPairing\":true,"
       "\"isOnline\":false,\"isOwner\":true,\"revokedAt\":null},"
      "{\"id\":\"id-repair\",\"name\":\"needy\",\"status\":\"PAIRED\","
       "\"enrollmentStatus\":\"ACTIVE\",\"requiresPairing\":true,"
       "\"isOnline\":true,\"isOwner\":true,\"revokedAt\":null},"
      "{\"id\":\"id-revoked\",\"name\":\"gone\",\"status\":\"REVOKED\","
       "\"enrollmentStatus\":\"REVOKED\",\"requiresPairing\":false,"
       "\"isOnline\":false,\"isOwner\":true,"
       "\"revokedAt\":\"2026-01-01T00:00:00.000Z\"}"
    "]}";

static int test_account_list(void)
{
    directgate_device_list_t list;
    xjson_t json;

    CHECK(XJSON_Parse(&json, NULL, g_pDeviceListBody, strlen(g_pDeviceListBody)),
        "parse device list body");
    CHECK(DirectGate_Devices_ParseList(&list, json.pRootObj), "map device list");
    XJSON_Destroy(&json);

    /* The revoked device is dropped entirely, like the workspace does */
    CHECK(list.nCount == 7, "revoked devices are hidden");

    CHECK(strcmp(list.devices[0].sId, "id-online") == 0, "first device id");
    CHECK(strcmp(list.devices[0].sName, "workstation") == 0, "first device name");
    CHECK(list.devices[0].bConnectable && list.devices[0].bOnline &&
          list.devices[0].bOwned, "paired active device is connectable");

    CHECK(list.devices[1].bConnectable && !list.devices[1].bOnline,
        "offline device is still connectable");

    CHECK(list.devices[2].bConnectable && !list.devices[2].bOwned &&
          strcmp(list.devices[2].sOwner, "owner@example.test") == 0,
        "accepted share is connectable and keeps its owner");

    CHECK(!list.devices[3].bConnectable &&
          strcmp(list.devices[3].sReason, "invite pending") == 0,
        "pending share is not connectable");
    CHECK(!list.devices[4].bConnectable &&
          strcmp(list.devices[4].sReason, "enrollment expired") == 0,
        "expired enrollment is not connectable");
    CHECK(!list.devices[5].bConnectable &&
          strcmp(list.devices[5].sReason, "not paired") == 0,
        "unpaired device is not connectable");
    CHECK(!list.devices[6].bConnectable &&
          strcmp(list.devices[6].sReason, "needs re-pairing") == 0,
        "device awaiting re-pairing is not connectable");

    CHECK(DirectGate_Devices_Find(&list, "id-offline") == 1, "find by id");
    CHECK(DirectGate_Devices_Find(&list, "laptop") == 1, "find by exact name");
    CHECK(DirectGate_Devices_Find(&list, "BUILD") == 2, "find by case insensitive prefix");
    CHECK(DirectGate_Devices_Find(&list, "nope") == DIRECTGATE_DEVICE_NO_PICK,
        "unknown query finds nothing");
    CHECK(DirectGate_Devices_Find(&list, "") == DIRECTGATE_DEVICE_NO_PICK,
        "empty query finds nothing");
    CHECK(DirectGate_Devices_Find(NULL, "laptop") == DIRECTGATE_DEVICE_NO_PICK,
        "NULL list finds nothing");

    /* An ambiguous prefix must refuse rather than pick arbitrarily */
    const char *pAmbiguous =
        "{\"devices\":["
          "{\"id\":\"id-1\",\"name\":\"web-one\",\"status\":\"PAIRED\","
           "\"enrollmentStatus\":\"ACTIVE\",\"requiresPairing\":false},"
          "{\"id\":\"id-2\",\"name\":\"web-two\",\"status\":\"PAIRED\","
           "\"enrollmentStatus\":\"ACTIVE\",\"requiresPairing\":false}"
        "]}";

    CHECK(XJSON_Parse(&json, NULL, pAmbiguous, strlen(pAmbiguous)), "parse ambiguous body");
    CHECK(DirectGate_Devices_ParseList(&list, json.pRootObj), "map ambiguous list");
    XJSON_Destroy(&json);

    CHECK(DirectGate_Devices_Find(&list, "web") == DIRECTGATE_DEVICE_NO_PICK,
        "ambiguous prefix is refused");
    CHECK(DirectGate_Devices_Find(&list, "web-two") == 1, "exact name beats prefix");

    const char *pEmpty = "{\"devices\":[]}";
    CHECK(XJSON_Parse(&json, NULL, pEmpty, strlen(pEmpty)), "parse empty body");
    CHECK(DirectGate_Devices_ParseList(&list, json.pRootObj), "map empty list");
    XJSON_Destroy(&json);
    CHECK(list.nCount == 0, "empty list has no devices");

    const char *pJunk = "{\"nope\":1}";
    CHECK(XJSON_Parse(&json, NULL, pJunk, strlen(pJunk)), "parse junk body");
    CHECK(!DirectGate_Devices_ParseList(&list, json.pRootObj), "reject body without devices");
    XJSON_Destroy(&json);

    CHECK(!DirectGate_Devices_ParseList(&list, NULL), "reject NULL root");
    CHECK(!DirectGate_Devices_ParseList(NULL, NULL), "reject NULL list");

    CHECK(!DirectGate_Devices_Fetch(&list, NULL, "token", NULL, 0),
        "reject fetch without API URL");
    CHECK(!DirectGate_Devices_Fetch(&list, "https://api.example.test", NULL, NULL, 0),
        "reject fetch without token");

    return 0;
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

    int nStatus = test_account_list();
    if (nStatus) return nStatus;

    puts("client_devices_smoke: OK");
    return 0;
}
