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

/* NV12 must produce exactly the I420 planes with Cb/Cr interleaved -
 * both converters share the same BT.709 core. */
static int check_nv12(void)
{
    enum { W = 16, H = 16 };
    uint8_t bgra[W * H * 4];
    uint8_t i420[W * H * 3 / 2];
    uint8_t nv12[W * H * 3 / 2];

    fill_bgra(bgra, W, H, 20, 40, 200);
    DirectGate_YUV_BGRAToI420(i420, i420 + W * H, i420 + W * H + (W / 2) * (H / 2),
        bgra, W, H);
    DirectGate_YUV_BGRAToNV12(nv12, nv12 + W * H, bgra, W, H);

    CHECK(memcmp(nv12, i420, W * H) == 0, "NV12 Y plane differs from I420");

    const uint8_t *pU = i420 + W * H;
    const uint8_t *pV = pU + (W / 2) * (H / 2);
    const uint8_t *pUV = nv12 + W * H;
    for (int i = 0; i < (W / 2) * (H / 2); i++)
    {
        CHECK(pUV[i * 2 + 0] == pU[i], "NV12 Cb sample differs from I420 U plane");
        CHECK(pUV[i * 2 + 1] == pV[i], "NV12 Cr sample differs from I420 V plane");
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

/* Exact halving (4K -> 1080p) takes a shortcut: each output pixel is the mean
 * of its 2x2 source block. Checked on uneven content, on a width that is not a
 * multiple of anything convenient, and on a padded stride, against the block
 * means computed here - and against a non-half ratio still going the long way. */
static int check_half_scaler(void)
{
    enum { SW = 10, SH = 6, DW = 5, DH = 3, STRIDE = SW * 4 + 12 };
    uint8_t src[STRIDE * SH];
    uint8_t dst[DW * DH * 4];

    memset(src, 0xEE, sizeof(src));
    for (uint32_t y = 0; y < SH; y++)
    {
        for (uint32_t x = 0; x < SW; x++)
        {
            uint8_t *p = src + y * STRIDE + x * 4U;
            p[0] = (uint8_t)(x * 23U + y * 7U);
            p[1] = (uint8_t)(x * 5U + y * 41U);
            p[2] = (uint8_t)(x * y * 13U + 3U);
            p[3] = 0U;
        }
    }

    DirectGate_YUV_ScaleBGRA(dst, DW, DH, src, SW, SH, STRIDE);

    for (uint32_t y = 0; y < DH; y++)
    {
        for (uint32_t x = 0; x < DW; x++)
        {
            const uint8_t *p00 = src + (y * 2U) * STRIDE + (x * 2U) * 4U;
            const uint8_t *p01 = p00 + 4U;
            const uint8_t *p10 = p00 + STRIDE;
            const uint8_t *p11 = p10 + 4U;
            const uint8_t *pOut = dst + (y * DW + x) * 4U;

            for (int c = 0; c < 3; c++)
            {
                uint32_t nMean = (uint32_t)(p00[c] + p01[c] + p10[c] + p11[c] + 2U) >> 2;
                CHECK(pOut[c] == nMean, "a halved pixel is the mean of its 2x2 source block");
            }

            CHECK(pOut[3] == 255U, "a halved pixel is opaque");
        }
    }

    /* 10x6 -> 4x3 is not a halving on one axis and must not take the shortcut:
       a shortcut applied there would read past the source rows it was given. */
    uint8_t other[4 * 3 * 4];
    DirectGate_YUV_ScaleBGRA(other, 4, 3, src, SW, SH, STRIDE);
    CHECK(other[3] == 255U, "a non-halving scale still produces opaque output");

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

    if (check_nv12()) return 1;
    if (check_scaler()) return 1;
    if (check_half_scaler()) return 1;

    printf("yuv_smoke: OK\n");
    return 0;
}
