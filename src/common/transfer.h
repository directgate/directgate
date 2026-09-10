/*!
 * @file directgate-agent/src/common/transfer.h
 * @brief Chunked file transfer over WebSocket or WebRTC data channel.
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

#ifndef __DIRECTGATE_FILETRANSFER_H__
#define __DIRECTGATE_FILETRANSFER_H__

#include "includes.h"
#include "protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Default chunk size: 64 KB (safe for both WebRTC and WebSocket) */
#define XFILE_CHUNK_SIZE    (64 * 1024)
#define XFILE_ID_SIZE       32
#define XFILE_NAME_SIZE     256
#define XFILE_PATH_SIZE     4096

typedef enum {
    XTRANSFER_STATE_IDLE = 0,
    XTRANSFER_STATE_SENDING,
    XTRANSFER_STATE_RECEIVING,
    XTRANSFER_STATE_DONE,
    XTRANSFER_STATE_ERROR,
    XTRANSFER_STATE_CANCELLED
} directgate_transfer_state_t;

/*
 * Callback type used by the file transfer module to send protocol messages.
 * The caller receives a JSON header object and optional binary payload.
 * The callback is responsible for adding cc, building the protocol packet,
 * encrypting, and routing to the appropriate transport.
 * Return XSTDOK (0) on success, negative on failure.
 */
typedef int (*directgate_file_send_fn)(xjson_obj_t *pHeader, const uint8_t *pPayload, size_t nLen, void *pCtx);

typedef struct xfile_transfer_ {
    directgate_transfer_state_t eState;
    char sId[XFILE_ID_SIZE];
    char sName[XFILE_NAME_SIZE];
    char sPath[XFILE_PATH_SIZE];

    FILE *pFile;
    xbool_t bRemoveOnDestroy;           /* owns an uncommitted inbound file */
    uint64_t nSize;                     /* total file size in bytes */
    uint32_t nTotalChunks;              /* total number of chunks */
    uint32_t nCurrentChunk;             /* next chunk index to send / last written */
    uint64_t nBytesXferred;             /* bytes transferred so far */
    size_t nChunkSize;                  /* bytes per chunk */

    xsha256_t sha256Ctx;                 /* running SHA-256 context */
    uint8_t sha256[XSHA256_DIGEST_SIZE]; /* final SHA-256 digest */
} directgate_transfer_t;

void DirectGate_Transfer_Init(directgate_transfer_t *pFT);
void DirectGate_Transfer_Destroy(directgate_transfer_t *pFT);

xbool_t DirectGate_Transfer_IsActive(const directgate_transfer_t *pFT);
xbool_t DirectGate_Transfer_IsDone(const directgate_transfer_t *pFT);

XSTATUS DirectGate_Transfer_Send(directgate_transfer_t *pFT, const char *pPath, directgate_file_send_fn sendFn, void *pCtx);
XSTATUS DirectGate_Transfer_SendNext(directgate_transfer_t *pFT, directgate_file_send_fn sendFn, void *pCtx);

XSTATUS DirectGate_Transfer_HandleStart(directgate_transfer_t *pFT, const directgate_pkg_t *pPkg, const char *pDestDir);
XSTATUS DirectGate_Transfer_HandleStartPath(directgate_transfer_t *pFT, const directgate_pkg_t *pPkg, const char *pPath);
XSTATUS DirectGate_Transfer_HandleEnd(directgate_transfer_t *pFT, const directgate_pkg_t *pPkg, directgate_file_send_fn sendFn, void *pCtx);
XSTATUS DirectGate_Transfer_HandleChunk(directgate_transfer_t *pFT, const directgate_pkg_t *pPkg);
XSTATUS DirectGate_Transfer_HandleCancel(directgate_transfer_t *pFT);

#ifdef __cplusplus
}
#endif

#endif /* __DIRECTGATE_FILETRANSFER_H__ */
