/*!
 * @file directgate-agent/src/agent/yuv.h
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

#ifndef __DIRECTGATE_YUV_H__
#define __DIRECTGATE_YUV_H__

#include "includes.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Pixel layout used by every buffer in this module: 4 bytes per pixel in
 * B,G,R,A memory order (the little-endian X11 32-bit ZPixmap layout and the
 * same layout the macOS pipeline feeds to VideoToolbox). */

/* Bilinear downscale/upscale of a BGRA image. Source rows may carry padding
 * (nSrcStride is in bytes); destination rows are tightly packed. The alpha
 * channel of the output is forced to 255. */
void DirectGate_YUV_ScaleBGRA(uint8_t *pDst,
                          uint32_t nDstWidth,
                          uint32_t nDstHeight,
                          const uint8_t *pSrc,
                          uint32_t nSrcWidth,
                          uint32_t nSrcHeight,
                          size_t nSrcStride);

/* Convert a tightly packed BGRA image to planar I420 using BT.709 limited
 * range coefficients (matching the colour metadata the encoder signals in
 * the SPS VUI). Width and height must be even; the caller guarantees this
 * because H.264 requires even encode dimensions anyway. The Y plane is
 * nWidth*nHeight bytes; U and V planes are (nWidth/2)*(nHeight/2) bytes. */
void DirectGate_YUV_BGRAToI420(uint8_t *pY,
                           uint8_t *pU,
                           uint8_t *pV,
                           const uint8_t *pBGRA,
                           uint32_t nWidth,
                           uint32_t nHeight);

/* Same conversion as DirectGate_YUV_BGRAToI420 but with the chroma planes
 * interleaved as Cb,Cr pairs (NV12) - the only input layout every Windows
 * Media Foundation hardware H.264 encoder accepts. The Y plane is
 * nWidth*nHeight bytes; the UV plane is nWidth*(nHeight/2) bytes. */
void DirectGate_YUV_BGRAToNV12(uint8_t *pY,
                           uint8_t *pUV,
                           const uint8_t *pBGRA,
                           uint32_t nWidth,
                           uint32_t nHeight);

#ifdef __cplusplus
}
#endif

#endif
