/*!
 * @file directgate-agent/src/agent/yuv.c
 * @brief BGRA scaling and BGRA to I420 conversion for the desktop encoder.
 *
 *  Copyright (c) 2025-2026 DirectGate. All rights reserved.
 *  Author: Sandro Kalatozishvili (sandro@directgate.io)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "yuv.h"

/* Every kernel here also has a vector form, on x86-64 (SSE2, part of its base
 * instruction set) and on 64-bit ARM (NEON, likewise), so no build needs a
 * flag and no host is probed at run time. A vector form computes the scalar
 * integer formula lane for lane - no rounding average, no saturation the
 * scalar code does not also do - so the picture is byte-identical whichever
 * form ran; yuv_smoke holds both against a copy of the original loops. Other
 * targets (armhf, 32-bit x86 without SSE2, ...) and DIRECTGATE_YUV_SCALAR
 * builds keep the scalar loops. NEON is only taken on little-endian, where
 * reinterpreting 32-bit lanes as bytes keeps memory order. */
#if !defined(DIRECTGATE_YUV_SCALAR)
#if defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
#include <emmintrin.h>
#define DIRECTGATE_YUV_SSE2
#elif (defined(__aarch64__) || defined(_M_ARM64)) && (!defined(__BYTE_ORDER__) || __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#include <arm_neon.h>
#define DIRECTGATE_YUV_NEON
#endif
#endif

/* 8.8 fixed point sampling offsets used by the bilinear scaler. */
typedef struct directgate_yuv_tap_ {
    uint32_t nLow;   /* left/top source index */
    uint32_t nHigh;  /* right/bottom source index (clamped) */
    uint32_t nFrac;  /* blend weight of the high tap, 0..255 */
} directgate_yuv_tap_t;

static void DirectGate_YUV_FillTap(directgate_yuv_tap_t *pTap, uint32_t nDstPos,
                               uint32_t nDstSize, uint32_t nSrcSize)
{
    /* Center-aligned mapping: dst pixel centers sample src pixel centers,
     * which keeps text from drifting half a pixel on non-integer ratios. */
    uint64_t nPos = ((uint64_t)nDstPos * 2U + 1U) * nSrcSize * 128U / nDstSize;
    nPos = (nPos >= 128U) ? nPos - 128U : 0U;

    pTap->nLow = (uint32_t)(nPos >> 8);
    if (pTap->nLow >= nSrcSize) pTap->nLow = nSrcSize - 1U;

    pTap->nHigh = (pTap->nLow + 1U < nSrcSize) ? pTap->nLow + 1U : pTap->nLow;
    pTap->nFrac = (uint32_t)(nPos & 0xFFU);
}

#if defined(DIRECTGATE_YUV_SSE2)
/* Four output pixels per pass. Each 16-bit lane holds one channel's sum of
 * four bytes plus the rounding term, at most 1022, so nothing saturates. */
static uint32_t DirectGate_YUV_HalfRowSSE2(uint8_t *pOut, const uint8_t *pRow0, const uint8_t *pRow1, uint32_t nWidth)
{
    const __m128i vZero = _mm_setzero_si128();
    const __m128i vRound = _mm_set1_epi16(2);
    const __m128i vAlpha = _mm_slli_epi32(_mm_set1_epi32(0xFF), 24);
    uint32_t x = 0;

    for (; x + 4U <= nWidth; x += 4U)
    {
        const uint8_t *pTop = pRow0 + (size_t)x * 8U;
        const uint8_t *pBottom = pRow1 + (size_t)x * 8U;
        __m128i vTop0 = _mm_loadu_si128((const __m128i*)pTop);
        __m128i vTop1 = _mm_loadu_si128((const __m128i*)(pTop + 16));
        __m128i vBottom0 = _mm_loadu_si128((const __m128i*)pBottom);
        __m128i vBottom1 = _mm_loadu_si128((const __m128i*)(pBottom + 16));

        /* Column sums: each register is one source pixel pair, both pixels' channels. */
        __m128i vSum0 = _mm_add_epi16(_mm_unpacklo_epi8(vTop0, vZero), _mm_unpacklo_epi8(vBottom0, vZero));
        __m128i vSum1 = _mm_add_epi16(_mm_unpackhi_epi8(vTop0, vZero), _mm_unpackhi_epi8(vBottom0, vZero));
        __m128i vSum2 = _mm_add_epi16(_mm_unpacklo_epi8(vTop1, vZero), _mm_unpacklo_epi8(vBottom1, vZero));
        __m128i vSum3 = _mm_add_epi16(_mm_unpackhi_epi8(vTop1, vZero), _mm_unpackhi_epi8(vBottom1, vZero));

        /* Fold each pair's right pixel onto its left one: the low four lanes are an output pixel. */
        vSum0 = _mm_add_epi16(vSum0, _mm_srli_si128(vSum0, 8));
        vSum1 = _mm_add_epi16(vSum1, _mm_srli_si128(vSum1, 8));
        vSum2 = _mm_add_epi16(vSum2, _mm_srli_si128(vSum2, 8));
        vSum3 = _mm_add_epi16(vSum3, _mm_srli_si128(vSum3, 8));

        __m128i vLo = _mm_srli_epi16(_mm_add_epi16(_mm_unpacklo_epi64(vSum0, vSum1), vRound), 2);
        __m128i vHi = _mm_srli_epi16(_mm_add_epi16(_mm_unpacklo_epi64(vSum2, vSum3), vRound), 2);
        _mm_storeu_si128((__m128i*)(pOut + (size_t)x * 4U), _mm_or_si128(_mm_packus_epi16(vLo, vHi), vAlpha));
    }

    return x;
}
#elif defined(DIRECTGATE_YUV_NEON)
/* Eight output pixels per pass, one channel per register: the pairwise widening
 * adds fold each source pair, and both rows land in the same 16-bit lane. */
static uint32_t DirectGate_YUV_HalfRowNEON(uint8_t *pOut, const uint8_t *pRow0, const uint8_t *pRow1, uint32_t nWidth)
{
    const uint16x8_t vRound = vdupq_n_u16(2);
    uint32_t x = 0;

    for (; x + 8U <= nWidth; x += 8U)
    {
        uint8x16x4_t vTop = vld4q_u8(pRow0 + (size_t)x * 8U);
        uint8x16x4_t vBottom = vld4q_u8(pRow1 + (size_t)x * 8U);
        uint8x8x4_t vOut;

        for (int c = 0; c < 3; c++)
        {
            uint16x8_t vSum = vpadalq_u8(vpaddlq_u8(vTop.val[c]), vBottom.val[c]);
            vOut.val[c] = vmovn_u16(vshrq_n_u16(vaddq_u16(vSum, vRound), 2));
        }

        vOut.val[3] = vdup_n_u8(255U);
        vst4_u8(pOut + (size_t)x * 4U, vOut);
    }

    return x;
}
#endif

/* Exactly half size on both axes: 4K to 1080p, 1440p to 720p, a 2880x1800
 * panel to 1440x900. The bilinear taps land on the same 2x2 block with equal
 * weights there, so every output pixel is simply that block's mean - the
 * general path's result to within one rounding step, at about half its cost
 * on a path that runs for every captured frame. */
static void DirectGate_YUV_ScaleHalfBGRA(uint8_t *pDst,
                                         uint32_t nDstWidth,
                                         uint32_t nDstHeight,
                                         const uint8_t *pSrc,
                                         size_t nSrcStride)
{
    for (uint32_t y = 0; y < nDstHeight; y++)
    {
        const uint8_t *pRow0 = pSrc + (size_t)y * 2U * nSrcStride;
        const uint8_t *pRow1 = pRow0 + nSrcStride;
        uint8_t *pRowOut = pDst + (size_t)y * nDstWidth * 4U;
        uint32_t x = 0;

#if defined(DIRECTGATE_YUV_SSE2)
        x = DirectGate_YUV_HalfRowSSE2(pRowOut, pRow0, pRow1, nDstWidth);
#elif defined(DIRECTGATE_YUV_NEON)
        x = DirectGate_YUV_HalfRowNEON(pRowOut, pRow0, pRow1, nDstWidth);
#endif

        for (; x < nDstWidth; x++)
        {
            const uint8_t *pTop = pRow0 + (size_t)x * 8U;
            const uint8_t *pBottom = pRow1 + (size_t)x * 8U;
            uint8_t *pOut = pRowOut + (size_t)x * 4U;

            pOut[0] = (uint8_t)((pTop[0] + pTop[4] + pBottom[0] + pBottom[4] + 2U) >> 2);
            pOut[1] = (uint8_t)((pTop[1] + pTop[5] + pBottom[1] + pBottom[5] + 2U) >> 2);
            pOut[2] = (uint8_t)((pTop[2] + pTop[6] + pBottom[2] + pBottom[6] + 2U) >> 2);
            pOut[3] = 255U;
        }
    }
}

#if defined(DIRECTGATE_YUV_SSE2) || defined(DIRECTGATE_YUV_NEON)
/* The vector builds split the bilinear blend into its two passes. Each output
 * byte is still (top * (256 - fy) + bottom * fy) >> 8 over the same two
 * horizontally blended bytes, so the result is the scalar loop's exactly, but
 * a source row is blended across once and kept while the output rows that
 * sample it go by, instead of once for every output row: a downscale by less
 * than half, the usual fit-to-window case, reuses nearly every row. */

#if defined(DIRECTGATE_YUV_SSE2)
/* Per output column, the two tap weights paired for _mm_madd_epi16. */
typedef struct directgate_yuv_weight_ {
    int16_t nPairs[8];    /* 256 - f, f, four times */
} directgate_yuv_weight_t;
#else
/* Per output column, the high tap's weight once per byte of a pixel. */
typedef struct directgate_yuv_weight_ {
    uint8_t nFrac[4];
} directgate_yuv_weight_t;
#endif

typedef struct directgate_yuv_rows_ {
    const uint8_t *pSrc;
    size_t nSrcStride;
    const directgate_yuv_tap_t *pCols;
    const directgate_yuv_weight_t *pWeights;
    uint32_t nWidth;
    uint8_t *pRow[2];     /* horizontally blended source rows, nWidth * 4 bytes each */
    uint32_t nSource[2];  /* the source row each one holds, UINT32_MAX for none */
} directgate_yuv_rows_t;

/* One horizontally blended pixel, all four bytes (the first pass). */
static inline void DirectGate_YUV_LerpPixel(uint8_t *pOut, const uint8_t *pRow, const directgate_yuv_tap_t *pTap)
{
    const uint8_t *pA = pRow + (size_t)pTap->nLow * 4U;
    const uint8_t *pB = pRow + (size_t)pTap->nHigh * 4U;

    for (int c = 0; c < 4; c++)
        pOut[c] = (uint8_t)((pA[c] * (256U - pTap->nFrac) + pB[c] * pTap->nFrac) >> 8);
}

/* One vertically blended output pixel (the second pass), alpha forced opaque. */
static inline void DirectGate_YUV_BlendPixel(uint8_t *pOut, const uint8_t *pTop, const uint8_t *pBottom, uint32_t nFrac)
{
    for (int c = 0; c < 3; c++)
        pOut[c] = (uint8_t)((pTop[c] * (256U - nFrac) + pBottom[c] * nFrac) >> 8);

    pOut[3] = 255U;
}

#if defined(DIRECTGATE_YUV_SSE2)
/* Both taps of one pixel, byte interleaved and widened, so one madd gives each
 * channel's a * (256 - f) + b * f in a 32-bit lane (at most 65280, exact). */
static inline __m128i DirectGate_YUV_LerpSSE2(const uint8_t *pRow, const directgate_yuv_tap_t *pTap,
                                              const directgate_yuv_weight_t *pWeight)
{
    int32_t nA = 0, nB = 0;
    memcpy(&nA, pRow + (size_t)pTap->nLow * 4U, sizeof(nA));
    memcpy(&nB, pRow + (size_t)pTap->nHigh * 4U, sizeof(nB));

    __m128i vPairs = _mm_unpacklo_epi8(_mm_cvtsi32_si128(nA), _mm_cvtsi32_si128(nB));
    vPairs = _mm_unpacklo_epi8(vPairs, _mm_setzero_si128());
    return _mm_srli_epi32(_mm_madd_epi16(vPairs, _mm_loadu_si128((const __m128i*)pWeight->nPairs)), 8);
}

static void DirectGate_YUV_LerpRowSSE2(uint8_t *pOut, const uint8_t *pRow, const directgate_yuv_rows_t *pRows)
{
    const directgate_yuv_tap_t *pCols = pRows->pCols;
    const directgate_yuv_weight_t *pWeights = pRows->pWeights;
    uint32_t nWidth = pRows->nWidth;
    uint32_t x = 0;

    for (; x + 4U <= nWidth; x += 4U)
    {
        __m128i vLo = _mm_packs_epi32(DirectGate_YUV_LerpSSE2(pRow, &pCols[x], &pWeights[x]),
            DirectGate_YUV_LerpSSE2(pRow, &pCols[x + 1U], &pWeights[x + 1U]));
        __m128i vHi = _mm_packs_epi32(DirectGate_YUV_LerpSSE2(pRow, &pCols[x + 2U], &pWeights[x + 2U]),
            DirectGate_YUV_LerpSSE2(pRow, &pCols[x + 3U], &pWeights[x + 3U]));
        _mm_storeu_si128((__m128i*)(pOut + (size_t)x * 4U), _mm_packus_epi16(vLo, vHi));
    }

    for (; x < nWidth; x++) DirectGate_YUV_LerpPixel(pOut + (size_t)x * 4U, pRow, &pCols[x]);
}

static void DirectGate_YUV_BlendRowSSE2(uint8_t *pOut, const uint8_t *pTop, const uint8_t *pBottom,
                                        uint32_t nFrac, uint32_t nWidth)
{
    const __m128i vZero = _mm_setzero_si128();
    const __m128i vAlpha = _mm_slli_epi32(_mm_set1_epi32(0xFF), 24);
    const __m128i vTopWeight = _mm_set1_epi16((short)(256U - nFrac));
    const __m128i vBottomWeight = _mm_set1_epi16((short)nFrac);
    size_t nBytes = (size_t)nWidth * 4U;
    size_t i = 0;

    for (; i + 16U <= nBytes; i += 16U)
    {
        __m128i vTop = _mm_loadu_si128((const __m128i*)(pTop + i));
        __m128i vBottom = _mm_loadu_si128((const __m128i*)(pBottom + i));
        __m128i vLo = _mm_add_epi16(_mm_mullo_epi16(_mm_unpacklo_epi8(vTop, vZero), vTopWeight),
            _mm_mullo_epi16(_mm_unpacklo_epi8(vBottom, vZero), vBottomWeight));
        __m128i vHi = _mm_add_epi16(_mm_mullo_epi16(_mm_unpackhi_epi8(vTop, vZero), vTopWeight),
            _mm_mullo_epi16(_mm_unpackhi_epi8(vBottom, vZero), vBottomWeight));

        __m128i vOut = _mm_packus_epi16(_mm_srli_epi16(vLo, 8), _mm_srli_epi16(vHi, 8));
        _mm_storeu_si128((__m128i*)(pOut + i), _mm_or_si128(vOut, vAlpha));
    }

    for (; i < nBytes; i += 4U) DirectGate_YUV_BlendPixel(pOut + i, pTop + i, pBottom + i, nFrac);
}
#else
static inline uint32x2_t DirectGate_YUV_LoadPairNEON(const uint8_t *pRow, uint32_t nFirst, uint32_t nSecond)
{
    uint32_t nA = 0, nB = 0;
    memcpy(&nA, pRow + (size_t)nFirst * 4U, sizeof(nA));
    memcpy(&nB, pRow + (size_t)nSecond * 4U, sizeof(nB));
    return vset_lane_u32(nB, vdup_n_u32(nA), 1);
}

/* Two pixels per pass. 256 - f does not fit a byte, so a * (256 - f) + b * f
 * is formed as (a << 8) - a * f + b * f: wrapping 16-bit arithmetic whose
 * true result, at most 65280, is exact. The shift is a widen and a shift of
 * its own, not vshll_n_u8 by the full lane width, which toolchains have not
 * all accepted. */
static void DirectGate_YUV_LerpRowNEON(uint8_t *pOut, const uint8_t *pRow, const directgate_yuv_rows_t *pRows)
{
    const directgate_yuv_tap_t *pCols = pRows->pCols;
    uint32_t nWidth = pRows->nWidth;
    uint32_t x = 0;

    for (; x + 2U <= nWidth; x += 2U)
    {
        uint8x8_t vLow = vreinterpret_u8_u32(DirectGate_YUV_LoadPairNEON(pRow, pCols[x].nLow, pCols[x + 1U].nLow));
        uint8x8_t vHigh = vreinterpret_u8_u32(DirectGate_YUV_LoadPairNEON(pRow, pCols[x].nHigh, pCols[x + 1U].nHigh));
        uint8x8_t vFrac = vld1_u8(pRows->pWeights[x].nFrac);

        uint16x8_t vSum = vshlq_n_u16(vmovl_u8(vLow), 8);
        vSum = vmlal_u8(vmlsl_u8(vSum, vLow, vFrac), vHigh, vFrac);
        vst1_u8(pOut + (size_t)x * 4U, vshrn_n_u16(vSum, 8));
    }

    for (; x < nWidth; x++) DirectGate_YUV_LerpPixel(pOut + (size_t)x * 4U, pRow, &pCols[x]);
}

static void DirectGate_YUV_BlendRowNEON(uint8_t *pOut, const uint8_t *pTop, const uint8_t *pBottom,
                                        uint32_t nFrac, uint32_t nWidth)
{
    const uint8x16_t vAlpha = vreinterpretq_u8_u32(vdupq_n_u32(0xFF000000U));
    const uint16x8_t vTopWeight = vdupq_n_u16((uint16_t)(256U - nFrac));
    const uint16x8_t vBottomWeight = vdupq_n_u16((uint16_t)nFrac);
    size_t nBytes = (size_t)nWidth * 4U;
    size_t i = 0;

    for (; i + 16U <= nBytes; i += 16U)
    {
        uint8x16_t vTop = vld1q_u8(pTop + i);
        uint8x16_t vBottom = vld1q_u8(pBottom + i);
        uint16x8_t vLo = vmulq_u16(vmovl_u8(vget_low_u8(vTop)), vTopWeight);
        uint16x8_t vHi = vmulq_u16(vmovl_u8(vget_high_u8(vTop)), vTopWeight);

        vLo = vmlaq_u16(vLo, vmovl_u8(vget_low_u8(vBottom)), vBottomWeight);
        vHi = vmlaq_u16(vHi, vmovl_u8(vget_high_u8(vBottom)), vBottomWeight);
        vst1q_u8(pOut + i, vorrq_u8(vcombine_u8(vshrn_n_u16(vLo, 8), vshrn_n_u16(vHi, 8)), vAlpha));
    }

    for (; i < nBytes; i += 4U) DirectGate_YUV_BlendPixel(pOut + i, pTop + i, pBottom + i, nFrac);
}
#endif

/* Source row nRow blended across, from the cache or computed into whichever
 * buffer does not hold nKeep, the other row the current output row needs. A
 * row is only ever computed when neither buffer holds it, so the two never
 * hold the same one. */
static const uint8_t* DirectGate_YUV_BlendedRow(directgate_yuv_rows_t *pRows, uint32_t nRow, uint32_t nKeep)
{
    if (pRows->nSource[0] == nRow) return pRows->pRow[0];
    if (pRows->nSource[1] == nRow) return pRows->pRow[1];

    int nSlot = (pRows->nSource[0] == nKeep) ? 1 : 0;
    const uint8_t *pSrcRow = pRows->pSrc + (size_t)nRow * pRows->nSrcStride;

#if defined(DIRECTGATE_YUV_SSE2)
    DirectGate_YUV_LerpRowSSE2(pRows->pRow[nSlot], pSrcRow, pRows);
#else
    DirectGate_YUV_LerpRowNEON(pRows->pRow[nSlot], pSrcRow, pRows);
#endif

    pRows->nSource[nSlot] = nRow;
    return pRows->pRow[nSlot];
}

static void DirectGate_YUV_ScaleSeparable(uint8_t *pDst, uint32_t nDstWidth, uint32_t nDstHeight, const uint8_t *pSrc,
                                          uint32_t nSrcWidth, uint32_t nSrcHeight, size_t nSrcStride)
{
    size_t nWeightBytes = (size_t)nDstWidth * sizeof(directgate_yuv_weight_t);
    size_t nTapBytes = (size_t)nDstWidth * sizeof(directgate_yuv_tap_t);
    size_t nRowBytes = (size_t)nDstWidth * 4U;

    /* One allocation per frame, as before: weights, taps, both row buffers. */
    uint8_t *pWork = (uint8_t*)malloc(nWeightBytes + nTapBytes + nRowBytes * 2U);
    XCHECK_VOID_NL((pWork != NULL));

    directgate_yuv_weight_t *pWeights = (directgate_yuv_weight_t*)pWork;
    directgate_yuv_tap_t *pCols = (directgate_yuv_tap_t*)(pWork + nWeightBytes);

    for (uint32_t x = 0; x < nDstWidth; x++)
    {
        DirectGate_YUV_FillTap(&pCols[x], x, nDstWidth, nSrcWidth);

        for (int i = 0; i < 4; i++)
        {
#if defined(DIRECTGATE_YUV_SSE2)
            pWeights[x].nPairs[i * 2] = (int16_t)(256U - pCols[x].nFrac);
            pWeights[x].nPairs[i * 2 + 1] = (int16_t)pCols[x].nFrac;
#else
            pWeights[x].nFrac[i] = (uint8_t)pCols[x].nFrac;
#endif
        }
    }

    directgate_yuv_rows_t rows;
    rows.pSrc = pSrc;
    rows.nSrcStride = nSrcStride;
    rows.pCols = pCols;
    rows.pWeights = pWeights;
    rows.nWidth = nDstWidth;
    rows.pRow[0] = pWork + nWeightBytes + nTapBytes;
    rows.pRow[1] = rows.pRow[0] + nRowBytes;
    rows.nSource[0] = UINT32_MAX;
    rows.nSource[1] = UINT32_MAX;

    for (uint32_t y = 0; y < nDstHeight; y++)
    {
        directgate_yuv_tap_t row;
        DirectGate_YUV_FillTap(&row, y, nDstHeight, nSrcHeight);

        const uint8_t *pTop = DirectGate_YUV_BlendedRow(&rows, row.nLow, row.nHigh);
        const uint8_t *pBottom = DirectGate_YUV_BlendedRow(&rows, row.nHigh, row.nLow);
        uint8_t *pOut = pDst + (size_t)y * nRowBytes;

#if defined(DIRECTGATE_YUV_SSE2)
        DirectGate_YUV_BlendRowSSE2(pOut, pTop, pBottom, row.nFrac, nDstWidth);
#else
        DirectGate_YUV_BlendRowNEON(pOut, pTop, pBottom, row.nFrac, nDstWidth);
#endif
    }

    free(pWork);
}
#endif

void DirectGate_YUV_ScaleBGRA(uint8_t *pDst,
                              uint32_t nDstWidth,
                              uint32_t nDstHeight,
                              const uint8_t *pSrc,
                              uint32_t nSrcWidth,
                              uint32_t nSrcHeight,
                              size_t nSrcStride)
{
    XCHECK_VOID_NL((pDst != NULL && pSrc != NULL));
    XCHECK_VOID_NL((nDstWidth > 0 && nDstHeight > 0));
    XCHECK_VOID_NL((nSrcWidth > 0 && nSrcHeight > 0));

    if (nDstWidth == nSrcWidth && nDstHeight == nSrcHeight &&
        nSrcStride == (size_t)nSrcWidth * 4U)
    {
        memcpy(pDst, pSrc, (size_t)nDstWidth * nDstHeight * 4U);
        return;
    }

    if ((uint64_t)nDstWidth * 2U == nSrcWidth && (uint64_t)nDstHeight * 2U == nSrcHeight &&
        nSrcStride >= (size_t)nSrcWidth * 4U)
    {
        DirectGate_YUV_ScaleHalfBGRA(pDst, nDstWidth, nDstHeight, pSrc, nSrcStride);
        return;
    }

#if defined(DIRECTGATE_YUV_SSE2) || defined(DIRECTGATE_YUV_NEON)
    DirectGate_YUV_ScaleSeparable(pDst, nDstWidth, nDstHeight, pSrc, nSrcWidth, nSrcHeight, nSrcStride);
#else
    directgate_yuv_tap_t *pCols = (directgate_yuv_tap_t*)malloc(
        (size_t)nDstWidth * sizeof(directgate_yuv_tap_t));
    XCHECK_VOID_NL((pCols != NULL));

    for (uint32_t x = 0; x < nDstWidth; x++)
        DirectGate_YUV_FillTap(&pCols[x], x, nDstWidth, nSrcWidth);

    for (uint32_t y = 0; y < nDstHeight; y++)
    {
        directgate_yuv_tap_t row;
        DirectGate_YUV_FillTap(&row, y, nDstHeight, nSrcHeight);

        const uint8_t *pRow0 = pSrc + (size_t)row.nLow * nSrcStride;
        const uint8_t *pRow1 = pSrc + (size_t)row.nHigh * nSrcStride;
        uint8_t *pOut = pDst + (size_t)y * nDstWidth * 4U;

        for (uint32_t x = 0; x < nDstWidth; x++)
        {
            const directgate_yuv_tap_t *pCol = &pCols[x];
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
#endif
}

/* BT.709 limited-range RGB -> YCbCr in 8.8 fixed point:
 *   Y = 16  + 0.1826*R + 0.6142*G + 0.0620*B
 *   U = 128 - 0.1006*R - 0.3386*G + 0.4392*B
 *   V = 128 + 0.4392*R - 0.3989*G - 0.0403*B */
static inline uint8_t DirectGate_YUV_LumaBT709(uint32_t nR, uint32_t nG, uint32_t nB)
{
    return (uint8_t)(16U + ((47U * nR + 157U * nG + 16U * nB + 128U) >> 8));
}

static inline uint8_t DirectGate_YUV_Clamp(int32_t nValue)
{
    if (nValue < 0) return 0;
    if (nValue > 255) return 255;
    return (uint8_t)nValue;
}

#if defined(DIRECTGATE_YUV_SSE2)
/* Eight BGRA pixels as one 16-bit lane per pixel and channel. */
static inline void DirectGate_YUV_SplitSSE2(const uint8_t *pPixels, __m128i *pB, __m128i *pG, __m128i *pR)
{
    const __m128i vMask = _mm_set1_epi32(0xFF);
    __m128i vLo = _mm_loadu_si128((const __m128i*)pPixels);
    __m128i vHi = _mm_loadu_si128((const __m128i*)(pPixels + 16));

    *pB = _mm_packs_epi32(_mm_and_si128(vLo, vMask), _mm_and_si128(vHi, vMask));
    *pG = _mm_packs_epi32(_mm_and_si128(_mm_srli_epi32(vLo, 8), vMask), _mm_and_si128(_mm_srli_epi32(vHi, 8), vMask));
    *pR = _mm_packs_epi32(_mm_and_si128(_mm_srli_epi32(vLo, 16), vMask), _mm_and_si128(_mm_srli_epi32(vHi, 16), vMask));
}

/* The luma sum is at most 56228: exact in an unsigned 16-bit lane. */
static inline __m128i DirectGate_YUV_LumaSSE2(__m128i vB, __m128i vG, __m128i vR)
{
    __m128i vSum = _mm_add_epi16(_mm_mullo_epi16(vR, _mm_set1_epi16(47)), _mm_mullo_epi16(vG, _mm_set1_epi16(157)));
    vSum = _mm_add_epi16(vSum, _mm_add_epi16(_mm_mullo_epi16(vB, _mm_set1_epi16(16)), _mm_set1_epi16(128)));
    return _mm_add_epi16(_mm_srli_epi16(vSum, 8), _mm_set1_epi16(16));
}

/* 2x2 means of one channel from both rows' 16-bit lanes, eight samples. */
static inline __m128i DirectGate_YUV_MeanSSE2(__m128i vRow0Lo, __m128i vRow1Lo, __m128i vRow0Hi, __m128i vRow1Hi)
{
    const __m128i vLow16 = _mm_set1_epi32(0xFFFF);
    __m128i vLo = _mm_add_epi16(vRow0Lo, vRow1Lo);
    __m128i vHi = _mm_add_epi16(vRow0Hi, vRow1Hi);

    vLo = _mm_add_epi32(_mm_and_si128(vLo, vLow16), _mm_srli_epi32(vLo, 16));
    vHi = _mm_add_epi32(_mm_and_si128(vHi, vLow16), _mm_srli_epi32(vHi, 16));
    return _mm_srli_epi16(_mm_add_epi16(_mm_packs_epi32(vLo, vHi), _mm_set1_epi16(2)), 2);
}

/* Signed 16-bit lanes hold every partial and final chroma sum (|sum| < 28700),
 * and the arithmetic shift is the scalar code's >> on a negative int. */
static inline __m128i DirectGate_YUV_ChromaSSE2(__m128i vB, __m128i vG, __m128i vR, short nKr, short nKg, short nKb)
{
    __m128i vSum = _mm_add_epi16(_mm_mullo_epi16(vR, _mm_set1_epi16(nKr)), _mm_mullo_epi16(vG, _mm_set1_epi16(nKg)));
    vSum = _mm_add_epi16(vSum, _mm_add_epi16(_mm_mullo_epi16(vB, _mm_set1_epi16(nKb)), _mm_set1_epi16(128)));
    return _mm_add_epi16(_mm_srai_epi16(vSum, 8), _mm_set1_epi16(128));
}

/* Sixteen pixels of two rows: 32 luma samples and 8 chroma pairs. The final
 * pack saturates to 0..255, which is DirectGate_YUV_Clamp. */
static void DirectGate_YUV_Convert16SSE2(const uint8_t *pRow0, const uint8_t *pRow1, uint8_t *pY0,
                                         uint8_t *pY1, uint8_t *pU, uint8_t *pV, xbool_t bInterleaved)
{
    __m128i vB0Lo, vG0Lo, vR0Lo, vB0Hi, vG0Hi, vR0Hi;
    __m128i vB1Lo, vG1Lo, vR1Lo, vB1Hi, vG1Hi, vR1Hi;

    DirectGate_YUV_SplitSSE2(pRow0, &vB0Lo, &vG0Lo, &vR0Lo);
    DirectGate_YUV_SplitSSE2(pRow0 + 32, &vB0Hi, &vG0Hi, &vR0Hi);
    DirectGate_YUV_SplitSSE2(pRow1, &vB1Lo, &vG1Lo, &vR1Lo);
    DirectGate_YUV_SplitSSE2(pRow1 + 32, &vB1Hi, &vG1Hi, &vR1Hi);

    _mm_storeu_si128((__m128i*)pY0, _mm_packus_epi16(DirectGate_YUV_LumaSSE2(vB0Lo, vG0Lo, vR0Lo),
        DirectGate_YUV_LumaSSE2(vB0Hi, vG0Hi, vR0Hi)));
    _mm_storeu_si128((__m128i*)pY1, _mm_packus_epi16(DirectGate_YUV_LumaSSE2(vB1Lo, vG1Lo, vR1Lo),
        DirectGate_YUV_LumaSSE2(vB1Hi, vG1Hi, vR1Hi)));

    __m128i vB = DirectGate_YUV_MeanSSE2(vB0Lo, vB1Lo, vB0Hi, vB1Hi);
    __m128i vG = DirectGate_YUV_MeanSSE2(vG0Lo, vG1Lo, vG0Hi, vG1Hi);
    __m128i vR = DirectGate_YUV_MeanSSE2(vR0Lo, vR1Lo, vR0Hi, vR1Hi);
    __m128i vCb = _mm_packus_epi16(DirectGate_YUV_ChromaSSE2(vB, vG, vR, -26, -87, 112), _mm_setzero_si128());
    __m128i vCr = _mm_packus_epi16(DirectGate_YUV_ChromaSSE2(vB, vG, vR, 112, -102, -10), _mm_setzero_si128());

    if (bInterleaved)
    {
        _mm_storeu_si128((__m128i*)pU, _mm_unpacklo_epi8(vCb, vCr));
        return;
    }

    _mm_storel_epi64((__m128i*)pU, vCb);
    _mm_storel_epi64((__m128i*)pV, vCr);
}
#elif defined(DIRECTGATE_YUV_NEON)
/* The luma sum is at most 56228: exact in an unsigned 16-bit lane. */
static inline uint8x8_t DirectGate_YUV_LumaNEON(uint8x8_t vB, uint8x8_t vG, uint8x8_t vR)
{
    uint16x8_t vSum = vmull_u8(vR, vdup_n_u8(47));
    vSum = vmlal_u8(vSum, vG, vdup_n_u8(157));
    vSum = vmlal_u8(vSum, vB, vdup_n_u8(16));
    return vadd_u8(vshrn_n_u16(vaddq_u16(vSum, vdupq_n_u16(128)), 8), vdup_n_u8(16));
}

/* Signed 16-bit lanes hold every partial and final chroma sum (|sum| < 28700),
 * and the narrowing saturates to 0..255, which is DirectGate_YUV_Clamp. */
static inline uint8x8_t DirectGate_YUV_ChromaNEON(int16x8_t vB, int16x8_t vG, int16x8_t vR, int16_t nKr, int16_t nKg, int16_t nKb)
{
    int16x8_t vSum = vmulq_n_s16(vR, nKr);
    vSum = vmlaq_n_s16(vSum, vG, nKg);
    vSum = vmlaq_n_s16(vSum, vB, nKb);
    vSum = vshrq_n_s16(vaddq_s16(vSum, vdupq_n_s16(128)), 8);
    return vqmovun_s16(vaddq_s16(vSum, vdupq_n_s16(128)));
}

static void DirectGate_YUV_Convert16NEON(const uint8_t *pRow0, const uint8_t *pRow1, uint8_t *pY0,
                                         uint8_t *pY1, uint8_t *pU, uint8_t *pV, xbool_t bInterleaved)
{
    uint8x16x4_t vTop = vld4q_u8(pRow0);
    uint8x16x4_t vBottom = vld4q_u8(pRow1);

    vst1q_u8(pY0, vcombine_u8(
        DirectGate_YUV_LumaNEON(vget_low_u8(vTop.val[0]), vget_low_u8(vTop.val[1]), vget_low_u8(vTop.val[2])),
        DirectGate_YUV_LumaNEON(vget_high_u8(vTop.val[0]), vget_high_u8(vTop.val[1]), vget_high_u8(vTop.val[2]))));
    vst1q_u8(pY1, vcombine_u8(
        DirectGate_YUV_LumaNEON(vget_low_u8(vBottom.val[0]), vget_low_u8(vBottom.val[1]), vget_low_u8(vBottom.val[2])),
        DirectGate_YUV_LumaNEON(vget_high_u8(vBottom.val[0]), vget_high_u8(vBottom.val[1]), vget_high_u8(vBottom.val[2]))));

    /* 2x2 means: pairwise widening adds fold each row's neighbours. */
    int16x8_t vMean[3];
    for (int c = 0; c < 3; c++)
    {
        uint16x8_t vSum = vpadalq_u8(vpaddlq_u8(vTop.val[c]), vBottom.val[c]);
        vMean[c] = vreinterpretq_s16_u16(vshrq_n_u16(vaddq_u16(vSum, vdupq_n_u16(2)), 2));
    }

    uint8x8_t vCb = DirectGate_YUV_ChromaNEON(vMean[0], vMean[1], vMean[2], -26, -87, 112);
    uint8x8_t vCr = DirectGate_YUV_ChromaNEON(vMean[0], vMean[1], vMean[2], 112, -102, -10);

    if (bInterleaved)
    {
        uint8x8x2_t vPairs;
        vPairs.val[0] = vCb;
        vPairs.val[1] = vCr;
        vst2_u8(pU, vPairs);
        return;
    }

    vst1_u8(pU, vCb);
    vst1_u8(pV, vCr);
}
#endif

/* Shared BGRA -> luma + subsampled chroma core. The planar layouts only
 * differ in where the chroma samples land: I420 keeps two planes with one
 * byte per sample (nChromaStep 1), NV12 interleaves Cb,Cr pairs in a single
 * plane (nChromaStep 2, pV = pU + 1). */
static void DirectGate_YUV_BGRAToYCbCr(uint8_t *pY,
                                       uint8_t *pU,
                                       uint8_t *pV,
                                       size_t nChromaStep,
                                       size_t nChromaRowStride,
                                       const uint8_t *pBGRA,
                                       uint32_t nWidth,
                                       uint32_t nHeight)
{
    XCHECK_VOID_NL((pY != NULL && pU != NULL && pV != NULL && pBGRA != NULL));
    XCHECK_VOID_NL((nWidth > 1 && nHeight > 1));
    XCHECK_VOID_NL(((nWidth & 1U) == 0 && (nHeight & 1U) == 0));

    size_t nRowBytes = (size_t)nWidth * 4U;

    for (uint32_t y = 0; y < nHeight; y += 2U)
    {
        const uint8_t *pRow0 = pBGRA + (size_t)y * nRowBytes;
        const uint8_t *pRow1 = pRow0 + nRowBytes;
        uint8_t *pY0 = pY + (size_t)y * nWidth;
        uint8_t *pY1 = pY0 + nWidth;
        uint8_t *pURow = pU + (size_t)(y / 2U) * nChromaRowStride;
        uint8_t *pVRow = pV + (size_t)(y / 2U) * nChromaRowStride;
        uint32_t x = 0;

#if defined(DIRECTGATE_YUV_SSE2) || defined(DIRECTGATE_YUV_NEON)
        /* With nChromaStep 2, pVRow is pURow + 1: the interleaved store writes both. */
        xbool_t bInterleaved = (nChromaStep == 2U) ? XTRUE : XFALSE;

        for (; x + 16U <= nWidth; x += 16U)
        {
            size_t nChroma = (size_t)(x / 2U) * nChromaStep;

#if defined(DIRECTGATE_YUV_SSE2)
            DirectGate_YUV_Convert16SSE2(pRow0 + (size_t)x * 4U, pRow1 + (size_t)x * 4U,
                pY0 + x, pY1 + x, pURow + nChroma, pVRow + nChroma, bInterleaved);
#else
            DirectGate_YUV_Convert16NEON(pRow0 + (size_t)x * 4U, pRow1 + (size_t)x * 4U,
                pY0 + x, pY1 + x, pURow + nChroma, pVRow + nChroma, bInterleaved);
#endif
        }
#endif

        for (; x < nWidth; x += 2U)
        {
            const uint8_t *p00 = pRow0 + (size_t)x * 4U;
            const uint8_t *p01 = p00 + 4U;
            const uint8_t *p10 = pRow1 + (size_t)x * 4U;
            const uint8_t *p11 = p10 + 4U;

            pY0[x]      = DirectGate_YUV_LumaBT709(p00[2], p00[1], p00[0]);
            pY0[x + 1U] = DirectGate_YUV_LumaBT709(p01[2], p01[1], p01[0]);
            pY1[x]      = DirectGate_YUV_LumaBT709(p10[2], p10[1], p10[0]);
            pY1[x + 1U] = DirectGate_YUV_LumaBT709(p11[2], p11[1], p11[0]);

            /* Chroma from the 2x2 average (+2 rounds the /4). */
            uint32_t nB = (uint32_t)(p00[0] + p01[0] + p10[0] + p11[0] + 2U) >> 2;
            uint32_t nG = (uint32_t)(p00[1] + p01[1] + p10[1] + p11[1] + 2U) >> 2;
            uint32_t nR = (uint32_t)(p00[2] + p01[2] + p10[2] + p11[2] + 2U) >> 2;

            int32_t nCb = 128 + ((-26 * (int32_t)nR - 87 * (int32_t)nG + 112 * (int32_t)nB + 128) >> 8);
            int32_t nCr = 128 + ((112 * (int32_t)nR - 102 * (int32_t)nG - 10 * (int32_t)nB + 128) >> 8);

            pURow[(x / 2U) * nChromaStep] = DirectGate_YUV_Clamp(nCb);
            pVRow[(x / 2U) * nChromaStep] = DirectGate_YUV_Clamp(nCr);
        }
    }
}

void DirectGate_YUV_BGRAToI420(uint8_t *pY,
                               uint8_t *pU,
                               uint8_t *pV,
                               const uint8_t *pBGRA,
                               uint32_t nWidth,
                               uint32_t nHeight)
{
    DirectGate_YUV_BGRAToYCbCr(pY, pU, pV, 1U, (size_t)nWidth / 2U,
        pBGRA, nWidth, nHeight);
}

void DirectGate_YUV_BGRAToNV12(uint8_t *pY,
                               uint8_t *pUV,
                               const uint8_t *pBGRA,
                               uint32_t nWidth,
                               uint32_t nHeight)
{
    XCHECK_VOID_NL((pUV != NULL));
    DirectGate_YUV_BGRAToYCbCr(pY, pUV, pUV + 1U, 2U, (size_t)nWidth,
        pBGRA, nWidth, nHeight);
}
