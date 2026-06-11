#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libxutils/src/data/array.h"
#include "libxutils/src/data/map.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "collections_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static int count_it(xmap_pair_t *pPair, void *pContext)
{
    int *pCount = (int*)pContext;
    if (pPair == NULL || pPair->pKey == NULL) return XMAP_OINV;
    (*pCount)++;
    return XMAP_OK;
}

static int stop_it(xmap_pair_t *pPair, void *pContext)
{
    (void)pPair;
    (void)pContext;
    return XMAP_STOP;
}

static int test_map(void)
{
    xmap_t map;
    CHECK(XMap_Init(NULL, NULL, 1) == XMAP_OINV, "map rejects NULL init");
    CHECK(XMap_Init(&map, NULL, 0) == XMAP_OK, "map lazy init");
    CHECK(XMap_UsedSize(&map) == 0, "map starts empty");
    CHECK(XMap_Iterate(&map, count_it, NULL) == XMAP_EINIT,
        "unallocated map iteration");
    CHECK(XMap_Put(NULL, "x", "y") == XMAP_OINV, "map rejects NULL put");
    CHECK(XMap_Put(&map, NULL, "y") == XMAP_OINV, "map rejects NULL key");

    char keys[128][16];
    int values[128];
    for (int i = 0; i < 128; i++)
    {
        snprintf(keys[i], sizeof(keys[i]), "key-%03d", i);
        values[i] = i * 3;
        CHECK(XMap_Put(&map, keys[i], &values[i]) == XMAP_OK, "map bulk put");
    }
    CHECK(map.nCount == 128 && map.nTableSize >= 128, "map grows");
    for (int i = 0; i < 128; i++)
        CHECK(XMap_Get(&map, keys[i]) == &values[i], "map bulk get");

    int replacement = 999;
    CHECK(XMap_Put(&map, keys[5], &replacement) == XMAP_OK, "map update");
    CHECK(XMap_Get(&map, keys[5]) == &replacement && map.nCount == 128,
        "map update retains count");

    map.bAllowUpdate = XFALSE;
    CHECK(XMap_Put(&map, keys[5], &values[5]) == XMAP_EEXIST,
        "map update disabled");
    CHECK(XMap_Get(&map, keys[5]) == &replacement, "failed update preserves value");
    map.bAllowUpdate = XTRUE;

    for (int i = 0; i < 48; i++)
        CHECK(XMap_Remove(&map, keys[i]) == XMAP_OK, "map remove");
    CHECK(XMap_Remove(&map, "missing") == XMAP_MISSING, "map remove missing");
    CHECK(map.nCount == 80 && XMap_Get(&map, keys[0]) == NULL, "map removal state");

    for (int i = 0; i < 48; i++)
        CHECK(XMap_Put(&map, keys[i], &values[i]) == XMAP_OK, "map tombstone reuse");
    CHECK(map.nCount == 128, "map count after tombstone reuse");

    int nCount = 0;
    CHECK(XMap_Iterate(&map, count_it, &nCount) == XMAP_OK && nCount == 128,
        "map iteration");
    CHECK(XMap_Iterate(&map, stop_it, NULL) == XMAP_STOP, "map iteration stop");

    XMap_Reset(&map);
    CHECK(map.nCount == 0 && XMap_Iterate(&map, count_it, &nCount) == XMAP_EMPTY,
        "map reset");
    XMap_Destroy(&map);
    CHECK(map.pPairs == NULL && map.nTableSize == 0, "map destroy");
    return 0;
}

static int test_array(void)
{
    xarray_t arr;
    CHECK(XArray_Init(&arr, NULL, 0, 0) == NULL, "array lazy init");
    CHECK(XArray_Used(NULL) == 0 && XArray_Size(NULL) == 0, "array NULL sizes");
    CHECK(XArray_AddData(NULL, NULL, 0) == XARRAY_FAILURE, "array rejects NULL add");

    int values[] = { 50, 10, 40, 20, 30 };
    uint32_t keys[] = { 5, 1, 4, 2, 3 };
    for (size_t i = 0; i < 5; i++)
        CHECK(XArray_AddDataKey(&arr, &values[i], sizeof(values[i]), keys[i]) == (int)i,
            "array keyed add");
    CHECK(arr.nUsed == 5 && arr.nSize >= 5, "array lazy growth");
    CHECK(*(int*)XArray_GetData(&arr, 0) == 50, "array copied data");
    values[0] = -1;
    CHECK(*(int*)XArray_GetData(&arr, 0) == 50, "array owns copy");
    CHECK(XArray_GetData(&arr, 100) == NULL && XArray_GetSize(&arr, 100) == 0,
        "array out of range");

    XArray_SortBy(&arr, XARRAY_SORTBY_KEY);
    for (size_t i = 0; i < 5; i++)
        CHECK(XArray_GetKey(&arr, i) == i + 1, "array key sort");
    CHECK(XArray_LinearSearch(&arr, 4) == 3, "array linear search");
    CHECK(XArray_SentinelSearch(&arr, 4) == 3, "array sentinel search");
    CHECK(XArray_DoubleSearch(&arr, 4) == 3, "array double search");
    CHECK(XArray_BinarySearch(&arr, 4) == 3, "array binary search");
    CHECK(XArray_BinarySearch(&arr, 99) == XARRAY_FAILURE, "array search missing");

    xarray_data_t *pRemoved = XArray_Remove(&arr, 1);
    CHECK(pRemoved != NULL && pRemoved->nKey == 2 && arr.nUsed == 4,
        "array remove");
    XArray_FreeData(pRemoved);

    int inserted = 77;
    CHECK(XArray_InsertData(&arr, 1, &inserted, sizeof(inserted)) != NULL,
        "array insert");
    CHECK(*(int*)XArray_GetData(&arr, 1) == inserted && arr.nUsed == 5,
        "array insert position");

    int replacement = 88;
    xarray_data_t *pOld = XArray_SetData(&arr, 0, &replacement, sizeof(replacement));
    CHECK(pOld != NULL && *(int*)XArray_GetData(&arr, 0) == replacement,
        "array set");
    XArray_FreeData(pOld);

    XArray_Swap(&arr, 0, arr.nUsed - 1);
    CHECK(*(int*)XArray_GetData(&arr, arr.nUsed - 1) == replacement,
        "array swap");
    XArray_Delete(&arr, arr.nUsed - 1);
    CHECK(arr.nUsed == 4, "array delete");
    XArray_Clear(&arr);
    CHECK(arr.nUsed == 0, "array clear");
    XArray_Destroy(&arr);
    CHECK(arr.pData == NULL && arr.nSize == 0, "array destroy");

    xarray_t fixed;
    CHECK(XArray_Init(&fixed, NULL, 1, 1) != NULL, "fixed array init");
    CHECK(XArray_AddData(&fixed, &replacement, sizeof(replacement)) == 0,
        "fixed array first add");
    CHECK(XArray_AddData(&fixed, &replacement, sizeof(replacement)) == XARRAY_FAILURE,
        "fixed array rejects overflow");
    XArray_Destroy(&fixed);
    return 0;
}

int main(void)
{
    CHECK(test_map() == 0, "map cases");
    CHECK(test_array() == 0, "array cases");
    puts("collections_smoke: OK");
    return 0;
}
