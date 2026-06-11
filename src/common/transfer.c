/*!
 * @file directgate-agent/src/common/filetransfer.c
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

#include "transfer.h"

#define XSHA256_HEX_LENGTH ((XSHA256_DIGEST_SIZE * 2) + 1)

static FILE* DirectGate_Transfer_OpenDestination(const char *pPath)
{
    XCHECK((xstrused(pPath)), NULL);

#ifdef _WIN32
    /* O_NOFOLLOW analog: refuse a destination that is a reparse point so
       the transfer cannot be redirected through a planted link. O_EXCL
       below still rejects any pre-existing regular file. */
    DWORD nAttrs = GetFileAttributesA(pPath);
    if (nAttrs != INVALID_FILE_ATTRIBUTES && (nAttrs & FILE_ATTRIBUTE_REPARSE_POINT))
        return NULL;

    /* _O_NOINHERIT = FD_CLOEXEC analog, _O_BINARY keeps payload bytes exact */
    int nFlags = _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY | _O_NOINHERIT;

    int nFd = -1;
    if (_sopen_s(&nFd, pPath, nFlags, _SH_DENYWR, _S_IREAD | _S_IWRITE) != 0 || nFd < 0)
        return NULL;

    FILE *pFile = _fdopen(nFd, "wb");
    if (pFile == NULL)
    {
        _close(nFd);
        return NULL;
    }

    return pFile;
#else
    int nFlags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
    nFlags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    nFlags |= O_NOFOLLOW;
#endif

    int nFd = open(pPath, nFlags, 0600);
    if (nFd < 0) return NULL;

#ifndef O_CLOEXEC
    int nFdFlags = fcntl(nFd, F_GETFD);
    if (nFdFlags >= 0) (void)fcntl(nFd, F_SETFD, nFdFlags | FD_CLOEXEC);
#endif

    FILE *pFile = fdopen(nFd, "wb");
    if (pFile == NULL)
    {
        close(nFd);
        return NULL;
    }

    return pFile;
#endif
}

static const char* DirectGate_Transfer_StateToString(directgate_transfer_state_t eState)
{
    switch (eState)
    {
        case XTRANSFER_STATE_IDLE: return "idle";
        case XTRANSFER_STATE_SENDING: return "sending";
        case XTRANSFER_STATE_RECEIVING: return "receiving";
        case XTRANSFER_STATE_DONE: return "done";
        case XTRANSFER_STATE_ERROR: return "error";
        case XTRANSFER_STATE_CANCELLED: return "cancelled";
        default: return "unknown";
    }
}

static const char* DirectGate_Transfer_GetId(const directgate_transfer_t *pFT)
{
    XCHECK_NL((pFT != NULL), "N/A");
    return xstrused(pFT->sId) ? pFT->sId : "N/A";
}

static const char* DirectGate_Transfer_GetName(const directgate_transfer_t *pFT)
{
    XCHECK_NL((pFT != NULL), "N/A");
    return xstrused(pFT->sName) ? pFT->sName : "N/A";
}

static const char* DirectGate_Transfer_GetPath(const directgate_transfer_t *pFT)
{
    XCHECK_NL((pFT != NULL), "N/A");
    return xstrused(pFT->sPath) ? pFT->sPath : "N/A";
}

static void DirectGate_Transfer_SHA256ToHex(const uint8_t *pDigest, char *pHex, size_t nSize)
{
    XCHECK_VOID((pDigest != NULL));
    XCHECK_VOID((pHex != NULL));
    XCHECK_VOID((nSize >= XSHA256_HEX_LENGTH));

    for (size_t i = 0; i < XSHA256_DIGEST_SIZE; i++)
        snprintf(pHex + (i * 2), nSize - (i * 2), "%02x", pDigest[i]);
}

static xbool_t DirectGate_Transfer_IsSHA256Hex(const char *pHex)
{
    XCHECK_NL((xstrused(pHex)), XFALSE);
    XCHECK_NL((strlen(pHex) == (XSHA256_DIGEST_SIZE * 2)), XFALSE);

    for (size_t i = 0; i < (XSHA256_DIGEST_SIZE * 2); i++)
    {
        if (!isxdigit((unsigned char)pHex[i])) return XFALSE;
    }

    return XTRUE;
}

static void DirectGate_Transfer_GenerateId(char *pId, size_t nSize)
{
    XCHECK_VOID((pId != NULL));
    XCHECK_VOID((nSize > 0));

    static unsigned int nCounter = 0;
    unsigned int nNow  = (unsigned int)time(NULL);
    unsigned int nRand = (unsigned int)rand();

    snprintf(pId, nSize, "%08x%04x%04x",
        nNow, nRand & 0xffff, (++nCounter) & 0xffff);
}

static int DirectGate_Transfer_SendMsg(xjson_obj_t *pHeader, const uint8_t *pPayload,
                                       size_t nLen, directgate_file_send_fn sendFn, void *pCtx)
{
    XCHECK((pHeader != NULL), XSTDERR);
    XCHECK((sendFn != NULL), XSTDERR);
    return sendFn(pHeader, pPayload, nLen, pCtx);
}

void DirectGate_Transfer_Init(directgate_transfer_t *pFT)
{
    XCHECK_VOID_NL((pFT != NULL));
    memset(pFT, 0, sizeof(*pFT));
    pFT->eState = XTRANSFER_STATE_IDLE;
    pFT->nChunkSize = XFILE_CHUNK_SIZE;
}

void DirectGate_Transfer_Destroy(directgate_transfer_t *pFT)
{
    XCHECK_VOID_NL((pFT != NULL));
    directgate_transfer_state_t eState = pFT->eState;
    char sPath[XFILE_PATH_SIZE];
    xstrncpy(sPath, sizeof(sPath), pFT->sPath);

    if (pFT->pFile != NULL)
    {
        fclose(pFT->pFile);
        pFT->pFile = NULL;
    }

    if (eState == XTRANSFER_STATE_RECEIVING && xstrused(sPath))
    {
        if (remove(sPath) != 0 && errno != ENOENT)
        {
            xlogw("Failed to remove partial inbound transfer file during destroy: id(%s), path(%s), errno(%d)",
                DirectGate_Transfer_GetId(pFT), sPath, errno);
        }
    }

    memset(pFT, 0, sizeof(*pFT));
    pFT->eState = XTRANSFER_STATE_IDLE;
    pFT->nChunkSize = XFILE_CHUNK_SIZE;
}

xbool_t DirectGate_Transfer_IsActive(const directgate_transfer_t *pFT)
{
    XCHECK_NL((pFT != NULL), XFALSE);
    return pFT->eState == XTRANSFER_STATE_SENDING ||
           pFT->eState == XTRANSFER_STATE_RECEIVING;
}

xbool_t DirectGate_Transfer_IsDone(const directgate_transfer_t *pFT)
{
    XCHECK_NL((pFT != NULL), XFALSE);
    return pFT->eState == XTRANSFER_STATE_DONE ||
           pFT->eState == XTRANSFER_STATE_ERROR ||
           pFT->eState == XTRANSFER_STATE_CANCELLED;
}

XSTATUS DirectGate_Transfer_Send(directgate_transfer_t *pFT, const char *pPath,
                                 directgate_file_send_fn sendFn, void *pCtx)
{
    XCHECK((pFT != NULL), XSTDERR);
    XCHECK((pPath != NULL), XSTDERR);
    XCHECK((sendFn != NULL), XSTDERR);

    /* Get file size */
    struct stat st;
    if (stat(pPath, &st) != 0)
    {
        xloge("Failed to stat transfer source: id(%s), path(%s), errno(%d)",
            DirectGate_Transfer_GetId(pFT), pPath, errno);

        pFT->eState = XTRANSFER_STATE_ERROR;
        return XSTDERR;
    }

    if (!S_ISREG(st.st_mode))
    {
        xloge("Transfer source is not a regular file: id(%s), path(%s)",
            DirectGate_Transfer_GetId(pFT), pPath);

        pFT->eState = XTRANSFER_STATE_ERROR;
        return XSTDERR;
    }

    pFT->pFile = fopen(pPath, "rb");
    if (pFT->pFile == NULL)
    {
        xloge("Failed to open transfer source for reading: id(%s), path(%s), errno(%d)",
            DirectGate_Transfer_GetId(pFT), pPath, errno);

        pFT->eState = XTRANSFER_STATE_ERROR;
        return XSTDERR;
    }

    /* Extract just the filename from the path */
    const char *pName = strrchr(pPath, '/');
    pName = pName ? pName + 1 : pPath;

    pFT->nSize = (uint64_t)st.st_size;
    pFT->nChunkSize = XFILE_CHUNK_SIZE;
    pFT->nTotalChunks = (uint32_t)((pFT->nSize + pFT->nChunkSize - 1) / pFT->nChunkSize);

    pFT->nCurrentChunk = 0;
    pFT->nBytesXferred = 0;
    pFT->eState = XTRANSFER_STATE_SENDING;

    XSHA256_Init(&pFT->sha256Ctx);
    DirectGate_Transfer_GenerateId(pFT->sId, sizeof(pFT->sId));
    xstrncpy(pFT->sName, sizeof(pFT->sName), pName);
    xstrncpy(pFT->sPath, sizeof(pFT->sPath), pPath);

    xlogi("Starting outbound file transfer: id(%s), name(%s), path(%s), chunks(%u), bytes(%" PRIu64 ")",
        DirectGate_Transfer_GetId(pFT), DirectGate_Transfer_GetName(pFT), DirectGate_Transfer_GetPath(pFT),
        pFT->nTotalChunks, pFT->nSize);

    /* Send start message */
    xjson_obj_t *pHeader = DirectGate_Proto_BuildFileStart(pFT->sId, pFT->sName,
        pFT->nSize, pFT->nTotalChunks, (uint32_t)pFT->nChunkSize);

    if (pHeader == NULL)
    {
        xloge("Failed to build transfer start header: id(%s), path(%s)",
            DirectGate_Transfer_GetId(pFT), DirectGate_Transfer_GetPath(pFT));

        pFT->eState = XTRANSFER_STATE_ERROR;
        return XSTDERR;
    }

    int nRet = DirectGate_Transfer_SendMsg(pHeader, NULL, 0, sendFn, pCtx);
    XJSON_FreeObject(pHeader);

    if (nRet < 0)
    {
        xloge("Failed to send transfer start message: id(%s), path(%s)",
            DirectGate_Transfer_GetId(pFT), DirectGate_Transfer_GetPath(pFT));

        pFT->eState = XTRANSFER_STATE_ERROR;
        return XSTDERR;
    }

    return XSTDOK;
}

XSTATUS DirectGate_Transfer_SendNext(directgate_transfer_t *pFT, directgate_file_send_fn sendFn, void *pCtx)
{
    XCHECK((pFT != NULL), XSTDERR);
    XCHECK((sendFn != NULL), XSTDERR);
    XCHECK_NL((pFT->eState == XTRANSFER_STATE_SENDING), XSTDNON);

    if (pFT->pFile == NULL)
    {
        pFT->eState = XTRANSFER_STATE_ERROR;
        return XSTDERR;
    }

    if (pFT->nCurrentChunk >= pFT->nTotalChunks)
    {
        /* All chunks sent — send end message */
        char sSha256Hex[XSHA256_HEX_LENGTH];
        XSHA256_Final(&pFT->sha256Ctx, pFT->sha256);
        DirectGate_Transfer_SHA256ToHex(pFT->sha256, sSha256Hex, sizeof(sSha256Hex));

        xjson_obj_t *pHeader = DirectGate_Proto_BuildFileEnd(pFT->sId, sSha256Hex);
        if (pHeader == NULL)
        {
            xloge("Failed to build transfer end header: id(%s), path(%s)",
                DirectGate_Transfer_GetId(pFT), DirectGate_Transfer_GetPath(pFT));

            pFT->eState = XTRANSFER_STATE_ERROR;
            return XSTDERR;
        }

        int nRet = DirectGate_Transfer_SendMsg(pHeader, NULL, 0, sendFn, pCtx);
        XJSON_FreeObject(pHeader);

        fclose(pFT->pFile);
        pFT->pFile = NULL;

        if (nRet < 0)
        {
            xloge("Failed to send transfer end message: id(%s), path(%s)",
                DirectGate_Transfer_GetId(pFT), DirectGate_Transfer_GetPath(pFT));

            pFT->eState = XTRANSFER_STATE_ERROR;
            return XSTDERR;
        }

        xlogi("Completed outbound file transfer: id(%s), path(%s), chunks(%u), bytes(%" PRIu64 "), sha256(%.16s...)",
            DirectGate_Transfer_GetId(pFT), DirectGate_Transfer_GetPath(pFT),
            pFT->nCurrentChunk, pFT->nBytesXferred, sSha256Hex);

        pFT->eState = XTRANSFER_STATE_DONE;
        return XSTDOK;
    }

    /* Read next chunk */
    uint8_t sBuf[XFILE_CHUNK_SIZE];
    size_t nRead = fread(sBuf, 1, pFT->nChunkSize, pFT->pFile);

    if (nRead == 0)
    {
        if (ferror(pFT->pFile))
        {
            xloge("Failed to read transfer chunk: id(%s), path(%s), chunk(%u/%u), errno(%d)",
                DirectGate_Transfer_GetId(pFT), DirectGate_Transfer_GetPath(pFT),
                pFT->nCurrentChunk, pFT->nTotalChunks, errno);

            pFT->eState = XTRANSFER_STATE_ERROR;
            return XSTDERR;
        }

        /* EOF reached before expected — treat as complete */
        pFT->nCurrentChunk = pFT->nTotalChunks;
        return DirectGate_Transfer_SendNext(pFT, sendFn, pCtx);
    }

    /* Update SHA-256 */
    XSHA256_Update(&pFT->sha256Ctx, sBuf, nRead);

    /* Send chunk */
    xjson_obj_t *pHeader = DirectGate_Proto_BuildFileChunk(pFT->sId, pFT->nCurrentChunk);
    if (pHeader == NULL)
    {
        xloge("Failed to build transfer chunk header: id(%s), chunk(%u/%u)",
            DirectGate_Transfer_GetId(pFT), pFT->nCurrentChunk, pFT->nTotalChunks);

        pFT->eState = XTRANSFER_STATE_ERROR;
        return XSTDERR;
    }

    int nRet = DirectGate_Transfer_SendMsg(pHeader, sBuf, nRead, sendFn, pCtx);
    XJSON_FreeObject(pHeader);

    if (nRet < 0)
    {
        xloge("Failed to send transfer chunk: id(%s), path(%s), chunk(%u/%u), bytes(%zu)",
            DirectGate_Transfer_GetId(pFT), DirectGate_Transfer_GetPath(pFT),
            pFT->nCurrentChunk, pFT->nTotalChunks, nRead);

        pFT->eState = XTRANSFER_STATE_ERROR;
        return XSTDERR;
    }

    pFT->nBytesXferred += nRead;
    pFT->nCurrentChunk++;

    xlogd("Sent transfer chunk: id(%s), chunk(%u/%u), bytes(%zu), total(%" PRIu64 "/%" PRIu64 ")",
        DirectGate_Transfer_GetId(pFT), pFT->nCurrentChunk, pFT->nTotalChunks,
        nRead, pFT->nBytesXferred, pFT->nSize);

    return XSTDOK;
}

XSTATUS DirectGate_Transfer_HandleStartPath(directgate_transfer_t *pFT, const directgate_pkg_t *pPkg, const char *pPath)
{
    XCHECK((pFT != NULL), XSTDERR);
    XCHECK((pPkg != NULL), XSTDERR);
    XCHECK((pPkg->pPackage != NULL), XSTDERR);
    XCHECK((xstrused(pPath)), XSTDERR);

    const directgate_pkg_file_t *pFilePkg = (const directgate_pkg_file_t*)pPkg->pPackage;
    const directgate_pkg_transfer_t *pTransfer = &pFilePkg->transfer;

    if (!xstrused(pTransfer->pTransferId) || !xstrused(pTransfer->pFileName))
    {
        xloge("Inbound transfer start is missing transfer id or file name: path(%s)", pPath);
        return XSTDERR;
    }

    if (pTransfer->nChunks == 0 && pTransfer->nFileSize > 0)
    {
        xloge("Inbound transfer start has invalid zero-chunk payload: id(%s), path(%s), bytes(%" PRIu64 ")",
            pTransfer->pTransferId, pPath, pTransfer->nFileSize);

        return XSTDERR;
    }

    /* Close any previous transfer */
    DirectGate_Transfer_Destroy(pFT);
    DirectGate_Transfer_Init(pFT);

    xstrncpy(pFT->sId, sizeof(pFT->sId), pTransfer->pTransferId);
    xstrncpy(pFT->sName, sizeof(pFT->sName), pTransfer->pFileName);
    xstrncpy(pFT->sPath, sizeof(pFT->sPath), pPath);

    pFT->nChunkSize = pTransfer->nChunkSize > 0 ? pTransfer->nChunkSize : XFILE_CHUNK_SIZE;
    pFT->nTotalChunks = pTransfer->nChunks;
    pFT->nCurrentChunk = XSTDNON;
    pFT->nBytesXferred = XSTDNON;
    pFT->nSize = pTransfer->nFileSize;
    XSHA256_Init(&pFT->sha256Ctx);

    pFT->pFile = DirectGate_Transfer_OpenDestination(pFT->sPath);
    if (pFT->pFile == NULL)
    {
        xloge("Failed to open transfer destination for writing: id(%s), path(%s), errno(%d)",
            DirectGate_Transfer_GetId(pFT), DirectGate_Transfer_GetPath(pFT), errno);

        pFT->eState = XTRANSFER_STATE_ERROR;
        return XSTDERR;
    }

    xlogi("Starting inbound file transfer: id(%s), name(%s), path(%s), chunks(%u), bytes(%" PRIu64 ")",
        DirectGate_Transfer_GetId(pFT), DirectGate_Transfer_GetName(pFT), DirectGate_Transfer_GetPath(pFT),
        pFT->nTotalChunks, pFT->nSize);

    pFT->eState = XTRANSFER_STATE_RECEIVING;
    return XSTDOK;
}

XSTATUS DirectGate_Transfer_HandleStart(directgate_transfer_t *pFT, const directgate_pkg_t *pPkg, const char *pDestDir)
{
    XCHECK((pPkg != NULL && pPkg->pPackage != NULL), XSTDERR);

    const directgate_pkg_file_t *pFilePkg = (const directgate_pkg_file_t*)pPkg->pPackage;
    const directgate_pkg_transfer_t *pTransfer = &pFilePkg->transfer;
    XCHECK((xstrused(pTransfer->pFileName)), XSTDERR);
    const char *pDir = xstrused(pDestDir) ? pDestDir : ".";

    char sPath[XFILE_PATH_SIZE];
    snprintf(sPath, sizeof(sPath), "%s/%s", pDir, pTransfer->pFileName);

    return DirectGate_Transfer_HandleStartPath(pFT, pPkg, sPath);
}

XSTATUS DirectGate_Transfer_HandleChunk(directgate_transfer_t *pFT, const directgate_pkg_t *pPkg)
{
    XCHECK((pFT != NULL), XSTDERR);
    XCHECK((pPkg != NULL), XSTDERR);
    XCHECK((pPkg->pPackage != NULL), XSTDERR);
    const directgate_pkg_file_t *pFilePkg = (const directgate_pkg_file_t*)pPkg->pPackage;

    if (pFT->eState != XTRANSFER_STATE_RECEIVING)
    {
        xlogw("Received transfer chunk while state is not receiving: id(%s), state(%s), chunk(%u/%u)",
            DirectGate_Transfer_GetId(pFT), DirectGate_Transfer_StateToString(pFT->eState),
            pFT->nCurrentChunk, pFT->nTotalChunks);

        return XSTDERR;
    }

    if (pFilePkg->data.pPayload == NULL || pFilePkg->data.nPayloadLength == 0)
    {
        xloge("Inbound transfer chunk is missing payload: id(%s), chunk(%u/%u)",
            DirectGate_Transfer_GetId(pFT), pFT->nCurrentChunk, pFT->nTotalChunks);

        return XSTDERR;
    }

    if (pFilePkg->transfer.nChunkIndex != pFT->nCurrentChunk)
    {
        xloge("Inbound transfer chunk index mismatch: id(%s), expected(%u), got(%u)",
            DirectGate_Transfer_GetId(pFT), pFT->nCurrentChunk, pFilePkg->transfer.nChunkIndex);

        pFT->eState = XTRANSFER_STATE_ERROR;
        return XSTDERR;
    }

    size_t nWritten = fwrite(pFilePkg->data.pPayload, 1, pFilePkg->data.nPayloadLength, pFT->pFile);
    if (nWritten != pFilePkg->data.nPayloadLength)
    {
        xloge("Failed to write inbound transfer chunk: id(%s), path(%s), chunk(%u/%u), errno(%d)",
            DirectGate_Transfer_GetId(pFT), DirectGate_Transfer_GetPath(pFT),
            pFT->nCurrentChunk, pFT->nTotalChunks, errno);

        pFT->eState = XTRANSFER_STATE_ERROR;
        return XSTDERR;
    }

    XSHA256_Update(&pFT->sha256Ctx, pFilePkg->data.pPayload, pFilePkg->data.nPayloadLength);
    pFT->nBytesXferred += pFilePkg->data.nPayloadLength;
    pFT->nCurrentChunk++;

    xlogd("Received transfer chunk: id(%s), chunk(%u/%u), bytes(%zu), total(%" PRIu64 "/%" PRIu64 ")",
        DirectGate_Transfer_GetId(pFT), pFT->nCurrentChunk, pFT->nTotalChunks,
        pFilePkg->data.nPayloadLength, pFT->nBytesXferred, pFT->nSize);

    return XSTDOK;
}

XSTATUS DirectGate_Transfer_HandleEnd(directgate_transfer_t *pFT, const directgate_pkg_t *pPkg,
                                      directgate_file_send_fn sendFn, void *pCtx)
{
    XCHECK((pFT != NULL), XSTDERR);
    XCHECK((pPkg != NULL), XSTDERR);
    XCHECK((pPkg->pPackage != NULL), XSTDERR);
    const directgate_pkg_file_t *pFilePkg = (const directgate_pkg_file_t*)pPkg->pPackage;

    if (pFT->eState != XTRANSFER_STATE_RECEIVING)
    {
        xlogw("Received transfer end while state is not receiving: id(%s), state(%s)",
            DirectGate_Transfer_GetId(pFT), DirectGate_Transfer_StateToString(pFT->eState));

        return XSTDERR;
    }

    fclose(pFT->pFile);
    pFT->pFile = NULL;

    /* Verify SHA-256 */
    char sRecvHex[XSHA256_HEX_LENGTH];
    XSHA256_Final(&pFT->sha256Ctx, pFT->sha256);
    DirectGate_Transfer_SHA256ToHex(pFT->sha256, sRecvHex, sizeof(sRecvHex));

    if (!DirectGate_Transfer_IsSHA256Hex(pFilePkg->transfer.pSha256))
    {
        xloge("Inbound transfer end is missing valid SHA-256: id(%s), path(%s)",
            DirectGate_Transfer_GetId(pFT), DirectGate_Transfer_GetPath(pFT));

        pFT->eState = XTRANSFER_STATE_ERROR;
        return XSTDERR;
    }

    if (!xstrncasecmp(pFilePkg->transfer.pSha256, sRecvHex, XSHA256_DIGEST_SIZE * 2))
    {
        xloge("Inbound transfer SHA-256 mismatch: id(%s), path(%s), expected(%.16s...), got(%.16s...)",
            DirectGate_Transfer_GetId(pFT), DirectGate_Transfer_GetPath(pFT),
            pFilePkg->transfer.pSha256, sRecvHex);

        pFT->eState = XTRANSFER_STATE_ERROR;
        return XSTDERR;
    }

    xlogi("Completed inbound file transfer: id(%s), path(%s), chunks(%u), bytes(%" PRIu64 "), sha256(%.16s...)",
        DirectGate_Transfer_GetId(pFT), DirectGate_Transfer_GetPath(pFT),
        pFT->nCurrentChunk, pFT->nBytesXferred, sRecvHex);

    /* Send ack */
    if (sendFn != NULL)
    {
        xjson_obj_t *pHeader = DirectGate_Proto_BuildFileAck(pFT->sId, pFT->nCurrentChunk);
        if (pHeader != NULL)
        {
            DirectGate_Transfer_SendMsg(pHeader, NULL, 0, sendFn, pCtx);
            XJSON_FreeObject(pHeader);
        }
    }

    pFT->eState = XTRANSFER_STATE_DONE;
    return XSTDOK;
}

XSTATUS DirectGate_Transfer_HandleCancel(directgate_transfer_t *pFT)
{
    XCHECK((pFT != NULL), XSTDERR);
    xbool_t bReceiving = (pFT->eState == XTRANSFER_STATE_RECEIVING);

    xlogw("Transfer cancelled by remote peer: id(%s), path(%s), state(%s), direction(%s)",
        DirectGate_Transfer_GetId(pFT), DirectGate_Transfer_GetPath(pFT),
        DirectGate_Transfer_StateToString(pFT->eState),
        bReceiving ? "inbound" : "outbound");

    if (pFT->pFile != NULL)
    {
        fclose(pFT->pFile);
        pFT->pFile = NULL;

        /* Remove incomplete file only for inbound (receiving) transfers;
         * for outbound (sending) transfers sPath is the original source file */
        if (bReceiving && xstrused(pFT->sPath)) remove(pFT->sPath);
    }

    pFT->eState = XTRANSFER_STATE_CANCELLED;
    return XSTDOK;
}
