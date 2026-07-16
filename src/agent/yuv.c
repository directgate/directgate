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

        for (uint32_t x = 0; x < nWidth; x += 2U)
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
