/* Smoke test for the desktop BGRA->I420 converter and bilinear scaler
 * (src/agent/yuv.c): BT.709 limited-range reference colours,
 * chroma subsampling of uniform blocks, and scaler identity/downscale
 * behavior. Pure CPU code, no X11 or encoder dependencies. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "src/agent/yuv.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "yuv_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static int near_value(int nGot, int nWant, int nTolerance)
{
    int nDiff = nGot - nWant;
    if (nDiff < 0) nDiff = -nDiff;
    return nDiff <= nTolerance;
}

/* Fills a WxH BGRA buffer with a single colour. */
static void fill_bgra(uint8_t *pBuf, uint32_t nWidth, uint32_t nHeight,
                      uint8_t nB, uint8_t nG, uint8_t nR)
{
    for (uint32_t i = 0; i < nWidth * nHeight; i++)
    {
        pBuf[i * 4U + 0U] = nB;
        pBuf[i * 4U + 1U] = nG;
        pBuf[i * 4U + 2U] = nR;
        pBuf[i * 4U + 3U] = 255U;
    }
}

/* Converts a uniform colour and checks Y/U/V against BT.709 limited-range
 * reference values (2-step tolerance for fixed-point rounding). */
static int check_solid(uint8_t nB, uint8_t nG, uint8_t nR,
                       int nWantY, int nWantU, int nWantV, const char *pLabel)
{
    enum { W = 16, H = 16 };
    uint8_t bgra[W * H * 4];
    uint8_t yuv[W * H * 3 / 2];

    fill_bgra(bgra, W, H, nB, nG, nR);
    DirectGate_YUV_BGRAToI420(yuv, yuv + W * H, yuv + W * H + (W / 2) * (H / 2),
        bgra, W, H);

    if (!near_value(yuv[0], nWantY, 2) ||
        !near_value(yuv[W * H], nWantU, 2) ||
        !near_value(yuv[W * H + (W / 2) * (H / 2)], nWantV, 2))
    {
        fprintf(stderr, "yuv_smoke: %s mismatch: got Y(%d) U(%d) V(%d), want Y(%d) U(%d) V(%d)\n",
            pLabel, yuv[0], yuv[W * H], yuv[W * H + (W / 2) * (H / 2)],
            nWantY, nWantU, nWantV);
        return 1;
    }

    /* Uniform input must produce uniform planes. */
    for (int i = 1; i < W * H; i++)
        CHECK(yuv[i] == yuv[0], "Y plane is not uniform for solid colour");
    for (int i = 1; i < (W / 2) * (H / 2); i++)
    {
        CHECK(yuv[W * H + i] == yuv[W * H], "U plane is not uniform for solid colour");
        CHECK(yuv[W * H + (W / 2) * (H / 2) + i] == yuv[W * H + (W / 2) * (H / 2)],
            "V plane is not uniform for solid colour");
    }

    return 0;
}

static int check_scaler(void)
{
    enum { SW = 8, SH = 8, DW = 4, DH = 4 };
    uint8_t src[SW * SH * 4];
    uint8_t dst[DW * DH * 4];

    /* Identity: same size in/out must be a byte-exact copy plus alpha. */
    fill_bgra(src, SW, SH, 10, 20, 30);
    uint8_t same[SW * SH * 4];
    DirectGate_YUV_ScaleBGRA(same, SW, SH, src, SW, SH, SW * 4);
    CHECK(memcmp(same, src, sizeof(src)) == 0, "identity scale is not a copy");

    /* Uniform colour must survive any scale ratio exactly. */
    DirectGate_YUV_ScaleBGRA(dst, DW, DH, src, SW, SH, SW * 4);
    for (int i = 0; i < DW * DH; i++)
    {
        CHECK(dst[i * 4 + 0] == 10, "scaled B channel mismatch");
        CHECK(dst[i * 4 + 1] == 20, "scaled G channel mismatch");
        CHECK(dst[i * 4 + 2] == 30, "scaled R channel mismatch");
        CHECK(dst[i * 4 + 3] == 255, "scaled alpha is not opaque");
    }

    /* Left/right halves in different colours must stay ordered after the
     * downscale (no mirroring / index off-by-one). */
    for (uint32_t y = 0; y < SH; y++)
    {
        for (uint32_t x = 0; x < SW; x++)
        {
            uint8_t *p = src + (y * SW + x) * 4U;
            uint8_t nValue = (x < SW / 2) ? 0U : 200U;
            p[0] = p[1] = p[2] = nValue;
            p[3] = 255U;
        }
    }

    DirectGate_YUV_ScaleBGRA(dst, DW, DH, src, SW, SH, SW * 4);
    CHECK(dst[0] < 60, "left edge should stay dark after downscale");
    CHECK(dst[(DW - 1) * 4] > 140, "right edge should stay bright after downscale");

    /* Row padding: a stride larger than width*4 must be skipped. */
    enum { PW = 4, PH = 2, PSTRIDE = PW * 4 + 8 };
    uint8_t padded[PSTRIDE * PH];
    memset(padded, 0xAB, sizeof(padded)); /* poison the padding bytes */
    for (uint32_t y = 0; y < PH; y++)
    {
        for (uint32_t x = 0; x < PW; x++)
        {
            uint8_t *p = padded + y * PSTRIDE + x * 4U;
            p[0] = 40; p[1] = 50; p[2] = 60; p[3] = 255;
        }
    }

    uint8_t out[PW * PH * 4];
    DirectGate_YUV_ScaleBGRA(out, PW, PH, padded, PW, PH, PSTRIDE);
    for (int i = 0; i < PW * PH; i++)
    {
        CHECK(out[i * 4 + 0] == 40 && out[i * 4 + 1] == 50 && out[i * 4 + 2] == 60,
            "stride padding leaked into scaled output");
    }

    return 0;
}

int main(void)
{
    /* BT.709 limited-range references:
     * black -> (16, 128, 128), white -> (235, 128, 128),
     * red   -> (63, 102, 240), green -> (173, 42, 26), blue -> (32, 240, 118). */
    if (check_solid(0, 0, 0, 16, 128, 128, "black")) return 1;
    if (check_solid(255, 255, 255, 235, 128, 128, "white")) return 1;
    if (check_solid(0, 0, 255, 63, 102, 240, "red")) return 1;
    if (check_solid(0, 255, 0, 173, 42, 26, "green")) return 1;
    if (check_solid(255, 0, 0, 32, 240, 118, "blue")) return 1;

    if (check_scaler()) return 1;

    printf("yuv_smoke: OK\n");
    return 0;
}
