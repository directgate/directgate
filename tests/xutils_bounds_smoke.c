#include <stdio.h>
#include "libxutils/src/data/buf.h"
#include "libxutils/src/data/str.h"
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "xutils_bounds_smoke:%d: %s\n", __LINE__, #c); return 1; } } while (0)
int main(void)
{
    xbyte_buffer_t bytes;
    XByteBuffer_Init(&bytes, 0, 1);
    CHECK(XByteBuffer_Add(&bytes, (const uint8_t*)"abc", 3) == 3);
    CHECK(XByteBuffer_Add(&bytes, (const uint8_t*)"x", SIZE_MAX) < 0);
    CHECK(bytes.nUsed == 3 && !memcmp(bytes.pData, "abc", 3));
    XByteBuffer_Reset(&bytes);
    CHECK(XByteBuffer_Add(&bytes, (const uint8_t*)"abc", 3) == 3);
    CHECK(XByteBuffer_Remove(&bytes, 1, SIZE_MAX) == 2);
    CHECK(bytes.nUsed == 1 && !strcmp((char*)bytes.pData, "a"));
    CHECK(XByteBuffer_Resize(&bytes, 2) == 2); /* Force self-append to reallocate. */
    CHECK(XByteBuffer_AddBuff(&bytes, &bytes) > 0 && !strcmp((char*)bytes.pData, "aa"));
    CHECK(XByteBuffer_Insert(&bytes, 1, bytes.pData, bytes.nUsed) > 0 &&
        bytes.nUsed == 4 && !strcmp((char*)bytes.pData, "aaaa"));
    XByteBuffer_Clear(&bytes);
    CHECK(XByteBuffer_Delete(&bytes, 0, SIZE_MAX) >= 0);
    XByteBuffer_Clear(&bytes);
    uint8_t borrowed[3] = {'a', 'b', 'c'};
    XByteBuffer_SetData(&bytes, borrowed, 3);
    CHECK(XByteBuffer_Terminate(&bytes, 3) < 0);
    CHECK(!memcmp(borrowed, "abc", 3));
    XByteBuffer_Clear(&bytes);
    CHECK(!XByteData_Dup((const uint8_t*)"x", SIZE_MAX));

    xdata_buffer_t data;
    int a = 1, b = 2;
    CHECK(XDataBuffer_Init(&data, 1, 0) > 0);
    CHECK(XDataBuffer_Add(&data, &a) == 0 && XDataBuffer_Get(&data, 0) == &a);
    CHECK(XDataBuffer_Add(&data, &b) == 1);
    CHECK(XDataBuffer_Set(&data, UINT_MAX, &a) == NULL && data.nUsed == 2);
    CHECK(XDataBuffer_Pop(&data, 0) == &a && XDataBuffer_Get(&data, 0) == &b);
    XDataBuffer_Destroy(&data);
    CHECK(XDataBuffer_Init(&data, SIZE_MAX, 0) < 0);
    XDataBuffer_Destroy(&data);

    xring_buffer_t ring;
    CHECK(XRingBuffer_Init(&ring, 2) == 2);
    for (int cycle = 0; cycle < 3; cycle++)
    {
        uint8_t *view, out[8] = {0}; size_t len;
        CHECK(!XRingBuffer_GetData(&ring, &view, &len));
        CHECK(XRingBuffer_AddData(&ring, (const uint8_t*)"abc", 3) == 3);
        CHECK(XRingBuffer_AddData(&ring, (const uint8_t*)"z", 1) == 1);
        CHECK(ring.nUsed == 2 && XRingBuffer_GetData(&ring, &view, &len) == 1);
        CHECK(len == 3 && !memcmp(view, "abc", 3));
        CHECK(!XRingBuffer_AddData(&ring, (const uint8_t*)"x", 1));
        CHECK(XRingBuffer_Pop(&ring, out, sizeof(out)) == 3 && !memcmp(out, "abc", 3));
        CHECK(XRingBuffer_Pop(&ring, out, sizeof(out)) == 1 && out[0] == 'z');
        CHECK(!ring.nUsed && !XRingBuffer_Pop(&ring, out, sizeof(out)));
        XRingBuffer_Reset(&ring);
    }
    CHECK(XRingBuffer_AddData(&ring, (const uint8_t*)"a", 1) == 1);
    CHECK(XRingBuffer_AddData(&ring, (const uint8_t*)"b", 1) == 1);
    CHECK(XRingBuffer_AddDataAdv(&ring, (const uint8_t*)"c", 1) == 1);
    uint8_t out;
    CHECK(XRingBuffer_Pop(&ring, &out, 1) == 1 && out == 'b');
    CHECK(XRingBuffer_Pop(&ring, &out, 1) == 1 && out == 'c');
    XRingBuffer_Destroy(&ring);
    CHECK(!XRingBuffer_Init(&ring, SIZE_MAX));
    XRingBuffer_Destroy(&ring);

    xarray_t *split = XString_Split("abc", "");
    if (split) XArray_Destroy(split);
    split = XString_Split("a,b,c", ",");
    CHECK(split && split->nUsed == 3);
    XArray_Destroy(split);
    puts("xutils_bounds_smoke: OK");
    return 0;
}
