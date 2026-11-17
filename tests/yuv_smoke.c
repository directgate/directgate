/* Smoke test for the desktop BGRA->I420 converter and bilinear scaler
 * (src/agent/yuv.c): BT.709 limited-range reference colours,
 * chroma subsampling of uniform blocks, and scaler identity/downscale
 * behavior. Pure CPU code, no X11 or encoder dependencies.
 *
 * yuv.c has vector kernels on x86-64 and 64-bit ARM; every one of them must
 * reproduce the original scalar loops byte for byte, which the reference
 * comparison at the end checks. yuv_scalar_smoke runs this same file against
 * a DIRECTGATE_YUV_SCALAR build, the loops other targets keep. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "src/agent/yuv.h"

#ifndef YUV_SMOKE_NAME
#define YUV_SMOKE_NAME "yuv_smoke"
#endif

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, YUV_SMOKE_NAME ": %s\n", msg); \
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
        fprintf(stderr, YUV_SMOKE_NAME ": %s mismatch: got Y(%d) U(%d) V(%d), want Y(%d) U(%d) V(%d)\n",
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

/* The scaler and the converter exactly as they were before yuv.c gained its
 * vector kernels. Kept verbatim: whatever form a build of yuv.c takes, its
 * output must be these loops' output, byte for byte. */
typedef struct ref_tap_ {
    uint32_t nLow;
    uint32_t nHigh;
    uint32_t nFrac;
} ref_tap_t;

static void ref_fill_tap(ref_tap_t *pTap, uint32_t nDstPos, uint32_t nDstSize, uint32_t nSrcSize)
{
    uint64_t nPos = ((uint64_t)nDstPos * 2U + 1U) * nSrcSize * 128U / nDstSize;
    nPos = (nPos >= 128U) ? nPos - 128U : 0U;

    pTap->nLow = (uint32_t)(nPos >> 8);
    if (pTap->nLow >= nSrcSize) pTap->nLow = nSrcSize - 1U;

    pTap->nHigh = (pTap->nLow + 1U < nSrcSize) ? pTap->nLow + 1U : pTap->nLow;
    pTap->nFrac = (uint32_t)(nPos & 0xFFU);
}

static void ref_scale_bgra(uint8_t *pDst, uint32_t nDstWidth, uint32_t nDstHeight,
                           const uint8_t *pSrc, uint32_t nSrcWidth, uint32_t nSrcHeight, size_t nSrcStride)
{
    if (nDstWidth == nSrcWidth && nDstHeight == nSrcHeight && nSrcStride == (size_t)nSrcWidth * 4U)
    {
        memcpy(pDst, pSrc, (size_t)nDstWidth * nDstHeight * 4U);
        return;
    }

    if ((uint64_t)nDstWidth * 2U == nSrcWidth && (uint64_t)nDstHeight * 2U == nSrcHeight && nSrcStride >= (size_t)nSrcWidth * 4U)
    {
        for (uint32_t y = 0; y < nDstHeight; y++)
        {
            const uint8_t *pRow0 = pSrc + (size_t)y * 2U * nSrcStride;
            const uint8_t *pRow1 = pRow0 + nSrcStride;
            uint8_t *pOut = pDst + (size_t)y * nDstWidth * 4U;

            for (uint32_t x = 0; x < nDstWidth; x++)
            {
                const uint8_t *pTop = pRow0 + (size_t)x * 8U;
                const uint8_t *pBottom = pRow1 + (size_t)x * 8U;

                pOut[0] = (uint8_t)((pTop[0] + pTop[4] + pBottom[0] + pBottom[4] + 2U) >> 2);
                pOut[1] = (uint8_t)((pTop[1] + pTop[5] + pBottom[1] + pBottom[5] + 2U) >> 2);
                pOut[2] = (uint8_t)((pTop[2] + pTop[6] + pBottom[2] + pBottom[6] + 2U) >> 2);
                pOut[3] = 255U;
                pOut += 4;
            }
        }

        return;
    }

    ref_tap_t *pCols = (ref_tap_t*)malloc((size_t)nDstWidth * sizeof(ref_tap_t));
    if (pCols == NULL) return;

    for (uint32_t x = 0; x < nDstWidth; x++) ref_fill_tap(&pCols[x], x, nDstWidth, nSrcWidth);

    for (uint32_t y = 0; y < nDstHeight; y++)
    {
        ref_tap_t row;
        ref_fill_tap(&row, y, nDstHeight, nSrcHeight);

        const uint8_t *pRow0 = pSrc + (size_t)row.nLow * nSrcStride;
        const uint8_t *pRow1 = pSrc + (size_t)row.nHigh * nSrcStride;
        uint8_t *pOut = pDst + (size_t)y * nDstWidth * 4U;

        for (uint32_t x = 0; x < nDstWidth; x++)
        {
            const ref_tap_t *pCol = &pCols[x];
            const uint8_t *p00 = pRow0 + (size_t)pCol->nLow * 4U;
            const uint8_t *p01 = pRow0 + (size_t)pCol->nHigh * 4U;
            const uint8_t *p10 = pRow1 + (size_t)pCol->nLow * 4U;
            const uint8_t *p11 = pRow1 + (size_t)pCol->nHigh * 4U;

            for (int c = 0; c < 3; c++)
            {
                uint32_t nTop = (p00[c] * (256U - pCol->nFrac) + p01[c] * pCol->nFrac) >> 8;
                uint32_t nBottom = (p10[c] * (256U - pCol->nFrac) + p11[c] * pCol->nFrac) >> 8;
                pOut[c] = (uint8_t)((nTop * (256U - row.nFrac) + nBottom * row.nFrac) >> 8);
            }

            pOut[3] = 255U;
            pOut += 4;
        }
    }

    free(pCols);
}

static uint8_t ref_clamp(int32_t nValue)
{
    if (nValue < 0) return 0;
    if (nValue > 255) return 255;
    return (uint8_t)nValue;
}

static void ref_bgra_to_ycbcr(uint8_t *pY, uint8_t *pU, uint8_t *pV, size_t nChromaStep, size_t nChromaRowStride,
                              const uint8_t *pBGRA, uint32_t nWidth, uint32_t nHeight)
{
    size_t nRowBytes = (size_t)nWidth * 4U;

    for (uint32_t y = 0; y < nHeight; y += 2U)
    {
        const uint8_t *pRow0 = pBGRA + (size_t)y * nRowBytes;
        const uint8_t *pRow1 = pRow0 + nRowBytes;
        uint8_t *pY0 = pY + (size_t)y * nWidth;
        uint8_t *pY1 = pY0 + nWidth;
        uint8_t *pURow = pU + (size_t)(y / 2U) * nChromaRowStride;
        uint8_t *pVRow = pV + (size_t)(y / 2U) * nChromaRowStride;

        for (uint32_t x = 0; x < nWidth; x += 2U)
        {
            const uint8_t *p00 = pRow0 + (size_t)x * 4U;
            const uint8_t *p01 = p00 + 4U;
            const uint8_t *p10 = pRow1 + (size_t)x * 4U;
            const uint8_t *p11 = p10 + 4U;

            pY0[x]      = (uint8_t)(16U + ((47U * p00[2] + 157U * p00[1] + 16U * p00[0] + 128U) >> 8));
            pY0[x + 1U] = (uint8_t)(16U + ((47U * p01[2] + 157U * p01[1] + 16U * p01[0] + 128U) >> 8));
            pY1[x]      = (uint8_t)(16U + ((47U * p10[2] + 157U * p10[1] + 16U * p10[0] + 128U) >> 8));
            pY1[x + 1U] = (uint8_t)(16U + ((47U * p11[2] + 157U * p11[1] + 16U * p11[0] + 128U) >> 8));

            uint32_t nB = (uint32_t)(p00[0] + p01[0] + p10[0] + p11[0] + 2U) >> 2;
            uint32_t nG = (uint32_t)(p00[1] + p01[1] + p10[1] + p11[1] + 2U) >> 2;
            uint32_t nR = (uint32_t)(p00[2] + p01[2] + p10[2] + p11[2] + 2U) >> 2;

            int32_t nCb = 128 + ((-26 * (int32_t)nR - 87 * (int32_t)nG + 112 * (int32_t)nB + 128) >> 8);
            int32_t nCr = 128 + ((112 * (int32_t)nR - 102 * (int32_t)nG - 10 * (int32_t)nB + 128) >> 8);

            pURow[(x / 2U) * nChromaStep] = ref_clamp(nCb);
            pVRow[(x / 2U) * nChromaStep] = ref_clamp(nCr);
        }
    }
}

static uint32_t g_nRandom = 0x9E3779B9U;

/* Picture content for the comparison. Saturated and bright content is the
 * part that matters: it is what drives a 16-bit lane to its largest sums. */
static void fill_content(uint8_t *pBuf, size_t nBytes, int nMode)
{
    for (size_t i = 0; i < nBytes; i++)
    {
        g_nRandom ^= g_nRandom << 13;
        g_nRandom ^= g_nRandom >> 17;
        g_nRandom ^= g_nRandom << 5;

        if (nMode == 0) pBuf[i] = (uint8_t)g_nRandom;
        else if (nMode == 1) pBuf[i] = (g_nRandom & 1U) ? 255U : 0U;
        else if (nMode == 2) pBuf[i] = (uint8_t)((i / 4U) * 7U + (i & 3U) * 50U);
        else pBuf[i] = (g_nRandom % 3U == 0U) ? 255U : (g_nRandom % 3U == 1U) ? (uint8_t)(g_nRandom >> 8) : 254U;
    }
}

/* One scale against the reference, on a padded source (the padding holds
 * content too, so a read past a row's end changes the output) and into
 * destinations with a guard tail (so a write past the end shows). */
static int compare_scale(uint32_t nDstWidth, uint32_t nDstHeight, uint32_t nSrcWidth, uint32_t nSrcHeight, size_t nPad, int nMode)
{
    size_t nStride = (size_t)nSrcWidth * 4U + nPad;
    size_t nDstBytes = (size_t)nDstWidth * nDstHeight * 4U + 16U;
    uint8_t *pSrc = (uint8_t*)malloc(nStride * nSrcHeight);
    uint8_t *pGot = (uint8_t*)malloc(nDstBytes);
    uint8_t *pWant = (uint8_t*)malloc(nDstBytes);
    int nResult = 1;

    if (pSrc != NULL && pGot != NULL && pWant != NULL)
    {
        fill_content(pSrc, nStride * nSrcHeight, nMode);
        memset(pGot, 0x5A, nDstBytes);
        memset(pWant, 0x5A, nDstBytes);

        DirectGate_YUV_ScaleBGRA(pGot, nDstWidth, nDstHeight, pSrc, nSrcWidth, nSrcHeight, nStride);
        ref_scale_bgra(pWant, nDstWidth, nDstHeight, pSrc, nSrcWidth, nSrcHeight, nStride);
        nResult = (memcmp(pGot, pWant, nDstBytes) == 0) ? 0 : 1;
    }

    if (nResult)
    {
        fprintf(stderr, YUV_SMOKE_NAME ": scale %ux%u -> %ux%u (pad %zu, content %d) differs from the reference\n",
            nSrcWidth, nSrcHeight, nDstWidth, nDstHeight, nPad, nMode);
    }

    free(pSrc);
    free(pGot);
    free(pWant);
    return nResult;
}

/* One conversion to both layouts against the reference, with guard tails. */
static int compare_convert(uint32_t nWidth, uint32_t nHeight, int nMode)
{
    size_t nLuma = (size_t)nWidth * nHeight;
    size_t nChroma = (size_t)(nWidth / 2U) * (nHeight / 2U);
    size_t nTotal = nLuma + nChroma * 2U + 16U;
    uint8_t *pSrc = (uint8_t*)malloc(nLuma * 4U);
    uint8_t *pGot = (uint8_t*)malloc(nTotal);
    uint8_t *pWant = (uint8_t*)malloc(nTotal);
    int nResult = 1;

    if (pSrc != NULL && pGot != NULL && pWant != NULL)
    {
        fill_content(pSrc, nLuma * 4U, nMode);

        memset(pGot, 0xC3, nTotal);
        memset(pWant, 0xC3, nTotal);
        DirectGate_YUV_BGRAToI420(pGot, pGot + nLuma, pGot + nLuma + nChroma, pSrc, nWidth, nHeight);
        ref_bgra_to_ycbcr(pWant, pWant + nLuma, pWant + nLuma + nChroma, 1U, nWidth / 2U, pSrc, nWidth, nHeight);
        nResult = (memcmp(pGot, pWant, nTotal) == 0) ? 0 : 1;

        memset(pGot, 0xC3, nTotal);
        memset(pWant, 0xC3, nTotal);
        DirectGate_YUV_BGRAToNV12(pGot, pGot + nLuma, pSrc, nWidth, nHeight);
        ref_bgra_to_ycbcr(pWant, pWant + nLuma, pWant + nLuma + 1U, 2U, nWidth, pSrc, nWidth, nHeight);
        if (memcmp(pGot, pWant, nTotal) != 0) nResult = 1;
    }

    if (nResult)
    {
        fprintf(stderr, YUV_SMOKE_NAME ": convert %ux%u (content %d) differs from the reference\n", nWidth, nHeight, nMode);
    }

    free(pSrc);
    free(pGot);
    free(pWant);
    return nResult;
}

/* Small sizes cover every vector-width remainder and both edge clamps of the
 * taps; the real sizes cover desktop geometry, including widths a vector
 * kernel does not divide and a fit-to-window ratio. */
static int check_matches_reference(void)
{
    static const size_t pads[] = { 0U, 4U, 7U, 12U };

    for (uint32_t nSrcWidth = 1; nSrcWidth <= 10; nSrcWidth++)
        for (uint32_t nSrcHeight = 1; nSrcHeight <= 10; nSrcHeight++)
            for (uint32_t nDstWidth = 1; nDstWidth <= 12; nDstWidth++)
                for (uint32_t nDstHeight = 1; nDstHeight <= 12; nDstHeight++)
                {
                    uint32_t nPick = nSrcWidth + nSrcHeight + nDstWidth + nDstHeight;
                    if (compare_scale(nDstWidth, nDstHeight, nSrcWidth, nSrcHeight, pads[nPick % 4U], (int)(nPick % 3U)))
                        return 1;
                }

    for (uint32_t nDstWidth = 1; nDstWidth <= 40; nDstWidth++)
        for (uint32_t nDstHeight = 1; nDstHeight <= 3; nDstHeight++)
            for (int nMode = 0; nMode < 4; nMode++)
                if (compare_scale(nDstWidth, nDstHeight, nDstWidth * 2U, nDstHeight * 2U, pads[nMode], nMode)) return 1;

    static const uint32_t scales[][4] = {
        { 1280, 720, 1920, 1080 }, { 1700, 956, 1920, 1080 }, { 1920, 1080, 2560, 1440 }, { 1366, 768, 1920, 1080 },
        { 1919, 1079, 1920, 1080 }, { 1921, 1081, 1920, 1080 }, { 960, 540, 1920, 1080 }, { 3, 1081, 1920, 1080 }
    };

    for (size_t i = 0; i < sizeof(scales) / sizeof(scales[0]); i++)
    {
        if (compare_scale(scales[i][0], scales[i][1], scales[i][2], scales[i][3], (i & 1U) ? 260U : 0U, (int)(i % 4U))) return 1;
    }

    for (uint32_t nWidth = 2; nWidth <= 48; nWidth += 2U)
        for (uint32_t nHeight = 2; nHeight <= 6; nHeight += 2U)
            for (int nMode = 0; nMode < 4; nMode++)
                if (compare_convert(nWidth, nHeight, nMode)) return 1;

    static const uint32_t converts[][2] = { { 1920, 1080 }, { 1366, 768 }, { 1918, 1078 }, { 1700, 956 } };
    for (size_t i = 0; i < sizeof(converts) / sizeof(converts[0]); i++)
        for (int nMode = 0; nMode < 4; nMode++)
            if (compare_convert(converts[i][0], converts[i][1], nMode)) return 1;

    return 0;
}

/* Arguments the scaler and the converters refuse leave every output byte as it was. */
static int check_refusals(void)
{
    enum { W = 8, H = 8 };
    uint8_t src[W * H * 4];
    uint8_t dst[W * H * 4];
    uint8_t planes[W * H * 2];

    fill_bgra(src, W, H, 10, 20, 30);
    memset(dst, 0x77, sizeof(dst));

    DirectGate_YUV_ScaleBGRA(NULL, 4, 4, src, W, H, W * 4);
    DirectGate_YUV_ScaleBGRA(dst, 4, 4, NULL, W, H, W * 4);
    DirectGate_YUV_ScaleBGRA(dst, 0, 4, src, W, H, W * 4);
    DirectGate_YUV_ScaleBGRA(dst, 4, 0, src, W, H, W * 4);
    DirectGate_YUV_ScaleBGRA(dst, 4, 4, src, 0, H, W * 4);
    DirectGate_YUV_ScaleBGRA(dst, 4, 4, src, W, 0, W * 4);
    for (size_t i = 0; i < sizeof(dst); i++) CHECK(dst[i] == 0x77, "a refused scale writes nothing");

    uint8_t *pY = planes;
    uint8_t *pU = planes + W * H;
    uint8_t *pV = pU + (W / 2) * (H / 2);
    memset(planes, 0x77, sizeof(planes));

    DirectGate_YUV_BGRAToI420(NULL, pU, pV, src, W, H);
    DirectGate_YUV_BGRAToI420(pY, NULL, pV, src, W, H);
    DirectGate_YUV_BGRAToI420(pY, pU, NULL, src, W, H);
    DirectGate_YUV_BGRAToI420(pY, pU, pV, NULL, W, H);
    DirectGate_YUV_BGRAToI420(pY, pU, pV, src, 1, H);
    DirectGate_YUV_BGRAToI420(pY, pU, pV, src, W, 1);
    DirectGate_YUV_BGRAToI420(pY, pU, pV, src, W - 1, H);
    DirectGate_YUV_BGRAToI420(pY, pU, pV, src, W, H - 1);
    DirectGate_YUV_BGRAToNV12(pY, NULL, src, W, H);
    DirectGate_YUV_BGRAToNV12(NULL, pU, src, W, H);
    DirectGate_YUV_BGRAToNV12(pY, pU, src, W - 1, H);
    for (size_t i = 0; i < sizeof(planes); i++) CHECK(planes[i] == 0x77, "a refused conversion writes nothing");

    return 0;
}

/* A stride shorter than a row is no exact halving: the shortcut reads whole rows, so the long way is taken, as it
   always was. */
static int check_short_stride(void)
{
    enum { SW = 12, SH = 6, DW = 6, DH = 3, STRIDE = SW * 4 - 8 };
    uint8_t src[SW * SH * 4];
    uint8_t got[DW * DH * 4];
    uint8_t want[DW * DH * 4];

    fill_content(src, sizeof(src), 0);
    DirectGate_YUV_ScaleBGRA(got, DW, DH, src, SW, SH, STRIDE);
    ref_scale_bgra(want, DW, DH, src, SW, SH, STRIDE);
    CHECK(memcmp(got, want, sizeof(got)) == 0, "a short stride scales as it always did");
    return 0;
}

#ifdef YUV_SMOKE_WRAP_MALLOC
/* The linker routes malloc here (--wrap), so one allocation can be made to fail. */
void *__real_malloc(size_t nSize);
static int g_bFailMalloc;

void *__wrap_malloc(size_t nSize)
{
    if (g_bFailMalloc)
    {
        g_bFailMalloc = 0;
        return NULL;
    }

    return __real_malloc(nSize);
}

/* The bilinear path needs one allocation a frame. Without it there is nothing to scale with, and the frame is left
   as it was rather than half written. */
static int check_scale_without_memory(void)
{
    enum { SW = 16, SH = 16, DW = 10, DH = 10 };
    uint8_t src[SW * SH * 4];
    uint8_t dst[DW * DH * 4];

    fill_content(src, sizeof(src), 0);
    memset(dst, 0x77, sizeof(dst));

    g_bFailMalloc = 1;
    DirectGate_YUV_ScaleBGRA(dst, DW, DH, src, SW, SH, SW * 4);
    CHECK(!g_bFailMalloc, "the bilinear scale asks for its working memory");
    for (size_t i = 0; i < sizeof(dst); i++) CHECK(dst[i] == 0x77, "a scale without its working memory writes nothing");

    DirectGate_YUV_ScaleBGRA(dst, DW, DH, src, SW, SH, SW * 4);
    CHECK(dst[3] == 255U, "the next frame scales again");
    return 0;
}
#endif

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
    if (check_matches_reference()) return 1;
    if (check_refusals()) return 1;
    if (check_short_stride()) return 1;
#ifdef YUV_SMOKE_WRAP_MALLOC
    if (check_scale_without_memory()) return 1;
#endif

    printf(YUV_SMOKE_NAME ": OK\n");
    return 0;
}
