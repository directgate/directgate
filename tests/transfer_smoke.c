#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/sha.h>

#include "src/common/transfer.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "transfer_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

typedef struct capture_ctx_ {
    uint8_t sData[90000];
    size_t nData;
    int nStart;
    int nChunk;
    int nEnd;
    int nAck;
    int nError;
    char sEndSha[SHA256_DIGEST_LENGTH * 2 + 1];
} capture_ctx_t;

static void sha256_hex(const uint8_t *pData, size_t nLen,
                       char *pOut, size_t nOutSize)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(pData, nLen, digest);

    for (size_t i = 0; i < sizeof(digest) && i * 2 + 2 < nOutSize; i++)
        snprintf(pOut + i * 2, nOutSize - i * 2, "%02x", digest[i]);
}

static int write_file(const char *pPath, const uint8_t *pData, size_t nLen)
{
    FILE *pFile = fopen(pPath, "wb");
    if (pFile == NULL) return 0;

    int nOk = fwrite(pData, 1, nLen, pFile) == nLen;
    fclose(pFile);
    return nOk;
}

static int read_file(const char *pPath, uint8_t *pData, size_t nCap, size_t *pLen)
{
    FILE *pFile = fopen(pPath, "rb");
    if (pFile == NULL) return 0;

    size_t nRead = fread(pData, 1, nCap, pFile);
    int nErr = ferror(pFile);
    fclose(pFile);

    if (nErr) return 0;
    *pLen = nRead;
    return 1;
}

static int capture_send(xjson_obj_t *pHeader, const uint8_t *pPayload,
                        size_t nLen, void *pCtx)
{
    capture_ctx_t *pCapture = (capture_ctx_t*)pCtx;
    const char *pAction = XJSON_GetString(XJSON_GetObject(pHeader, "action"));
    if (!xstrused(pAction))
    {
        pCapture->nError++;
        return XSTDERR;
    }

    if (strcmp(pAction, "start") == 0)
    {
        pCapture->nStart++;
        return XSTDOK;
    }

    if (strcmp(pAction, "chunk") == 0)
    {
        if (pCapture->nData + nLen > sizeof(pCapture->sData))
        {
            pCapture->nError++;
            return XSTDERR;
        }

        memcpy(pCapture->sData + pCapture->nData, pPayload, nLen);
        pCapture->nData += nLen;
        pCapture->nChunk++;
        return XSTDOK;
    }

    if (strcmp(pAction, "end") == 0)
    {
        const char *pSha = XJSON_GetString(XJSON_GetObject(pHeader, "sha256"));
        if (xstrused(pSha))
            xstrncpy(pCapture->sEndSha, sizeof(pCapture->sEndSha), pSha);
        pCapture->nEnd++;
        return XSTDOK;
    }

    if (strcmp(pAction, "ack") == 0)
    {
        pCapture->nAck++;
        return XSTDOK;
    }

    pCapture->nError++;
    return XSTDERR;
}

static int build_file_pkg(xbyte_buffer_t *pWire, directgate_pkg_t *pPkg,
                          xjson_obj_t *pHeader,
                          const uint8_t *pPayload, size_t nPayload)
{
    XByteBuffer_Init(pWire, XSTDNON, XFALSE);

    if (!DirectGate_Proto_Build(pWire, pHeader, pPayload, nPayload, XFALSE))
    {
        XJSON_FreeObject(pHeader);
        XByteBuffer_Clear(pWire);
        return 0;
    }

    XJSON_FreeObject(pHeader);
    return DirectGate_Package_Parse(pPkg, pWire->pData, pWire->nUsed);
}

static void clear_file_pkg(xbyte_buffer_t *pWire, directgate_pkg_t *pPkg)
{
    DirectGate_Package_Clear(pPkg);
    XByteBuffer_Clear(pWire);
}

int main(void)
{
    uint8_t content[70000];
    for (size_t i = 0; i < sizeof(content); i++)
        content[i] = (uint8_t)(i & 0xff);

    char sExpectedSha[SHA256_DIGEST_LENGTH * 2 + 1] = {0};
    sha256_hex(content, sizeof(content), sExpectedSha, sizeof(sExpectedSha));

    char sSrcPath[] = "/tmp/directgate_transfer_src.XXXXXX";
    int nSrcFd = mkstemp(sSrcPath);
    CHECK(nSrcFd >= 0, "mkstemp source");
    close(nSrcFd);
    CHECK(write_file(sSrcPath, content, sizeof(content)), "write source");

    directgate_transfer_t tx;
    capture_ctx_t txCapture;
    memset(&txCapture, 0, sizeof(txCapture));
    DirectGate_Transfer_Init(&tx);
    CHECK(DirectGate_Transfer_Send(&tx, sSrcPath, capture_send, &txCapture) == XSTDOK,
        "start outbound transfer");
    while (DirectGate_Transfer_IsActive(&tx))
        CHECK(DirectGate_Transfer_SendNext(&tx, capture_send, &txCapture) >= 0,
            "send next outbound chunk");
    CHECK(DirectGate_Transfer_IsDone(&tx), "outbound transfer done");
    CHECK(tx.eState == XTRANSFER_STATE_DONE, "outbound transfer state");
    CHECK(txCapture.nStart == 1, "outbound start count");
    CHECK(txCapture.nChunk == 2, "outbound chunk count");
    CHECK(txCapture.nEnd == 1, "outbound end count");
    CHECK(txCapture.nError == 0, "outbound callback errors");
    CHECK(txCapture.nData == sizeof(content), "outbound data length");
    CHECK(memcmp(txCapture.sData, content, sizeof(content)) == 0,
        "outbound data bytes");
    CHECK(strcmp(txCapture.sEndSha, sExpectedSha) == 0,
        "outbound SHA-256");
    DirectGate_Transfer_Destroy(&tx);

    char sDstPath[] = "/tmp/directgate_transfer_dst.XXXXXX";
    int nDstFd = mkstemp(sDstPath);
    CHECK(nDstFd >= 0, "mkstemp destination");
    close(nDstFd);
    CHECK(unlink(sDstPath) == 0, "unlink destination placeholder");

    directgate_transfer_t rx;
    DirectGate_Transfer_Init(&rx);
    xbyte_buffer_t wire;
    directgate_pkg_t pkg;
    xjson_obj_t *pHeader = DirectGate_Proto_BuildFileStart(
        "rx-1", "download.bin", sizeof(content), 2, XFILE_CHUNK_SIZE);
    CHECK(pHeader != NULL, "build inbound start");
    CHECK(build_file_pkg(&wire, &pkg, pHeader, NULL, 0),
        "parse inbound start");
    CHECK(DirectGate_Transfer_HandleStartPath(&rx, &pkg, sDstPath) == XSTDOK,
        "handle inbound start");
    clear_file_pkg(&wire, &pkg);

    pHeader = DirectGate_Proto_BuildFileChunk("rx-1", 0);
    CHECK(pHeader != NULL, "build inbound chunk 0");
    CHECK(build_file_pkg(&wire, &pkg, pHeader, content, XFILE_CHUNK_SIZE),
        "parse inbound chunk 0");
    CHECK(DirectGate_Transfer_HandleChunk(&rx, &pkg) == XSTDOK,
        "handle inbound chunk 0");
    clear_file_pkg(&wire, &pkg);

    pHeader = DirectGate_Proto_BuildFileChunk("rx-1", 1);
    CHECK(pHeader != NULL, "build inbound chunk 1");
    CHECK(build_file_pkg(&wire, &pkg, pHeader, content + XFILE_CHUNK_SIZE,
        sizeof(content) - XFILE_CHUNK_SIZE), "parse inbound chunk 1");
    CHECK(DirectGate_Transfer_HandleChunk(&rx, &pkg) == XSTDOK,
        "handle inbound chunk 1");
    clear_file_pkg(&wire, &pkg);

    capture_ctx_t rxCapture;
    memset(&rxCapture, 0, sizeof(rxCapture));
    pHeader = DirectGate_Proto_BuildFileEnd("rx-1", sExpectedSha);
    CHECK(pHeader != NULL, "build inbound end");
    CHECK(build_file_pkg(&wire, &pkg, pHeader, NULL, 0),
        "parse inbound end");
    CHECK(DirectGate_Transfer_HandleEnd(&rx, &pkg, capture_send, &rxCapture) == XSTDOK,
        "handle inbound end");
    CHECK(rx.eState == XTRANSFER_STATE_DONE, "inbound transfer state");
    CHECK(rxCapture.nAck == 1, "inbound ack count");
    clear_file_pkg(&wire, &pkg);

    uint8_t received[sizeof(content)];
    size_t nReceived = 0;
    CHECK(read_file(sDstPath, received, sizeof(received), &nReceived),
        "read inbound destination");
    CHECK(nReceived == sizeof(content), "inbound destination length");
    CHECK(memcmp(received, content, sizeof(content)) == 0,
        "inbound destination bytes");
    DirectGate_Transfer_Destroy(&rx);

    char sCancelPath[] = "/tmp/directgate_transfer_cancel.XXXXXX";
    int nCancelFd = mkstemp(sCancelPath);
    CHECK(nCancelFd >= 0, "mkstemp cancel path");
    close(nCancelFd);
    unlink(sCancelPath);

    directgate_transfer_t cancelRx;
    DirectGate_Transfer_Init(&cancelRx);
    pHeader = DirectGate_Proto_BuildFileStart("cancel-1", "cancel.bin", 10, 1, 10);
    CHECK(pHeader != NULL, "build cancel start");
    CHECK(build_file_pkg(&wire, &pkg, pHeader, NULL, 0),
        "parse cancel start");
    CHECK(DirectGate_Transfer_HandleStartPath(&cancelRx, &pkg, sCancelPath) == XSTDOK,
        "handle cancel start");
    clear_file_pkg(&wire, &pkg);
    CHECK(DirectGate_Transfer_HandleCancel(&cancelRx) == XSTDOK,
        "handle cancel");
    CHECK(cancelRx.eState == XTRANSFER_STATE_CANCELLED,
        "cancel state");
    CHECK(access(sCancelPath, F_OK) != 0,
        "cancel removes partial inbound file");
    DirectGate_Transfer_Destroy(&cancelRx);

    /* HandleStart joins a peer-supplied name to a directory this side chose,
       so the name must not be able to walk out of it. */
    {
        char sEscapeDir[] = "/tmp/directgate_transfer_escape.XXXXXX";
        CHECK(mkdtemp(sEscapeDir) != NULL, "mkdtemp escape dir");

        char sEscapeTarget[512];
        snprintf(sEscapeTarget, sizeof(sEscapeTarget), "%s/../directgate_escaped.bin", sEscapeDir);
        unlink(sEscapeTarget);

        directgate_transfer_t escapeRx;
        DirectGate_Transfer_Init(&escapeRx);

        pHeader = DirectGate_Proto_BuildFileStart("esc-1",
            "../directgate_escaped.bin", 4, 1, 4);
        CHECK(pHeader != NULL, "build traversing start");
        CHECK(build_file_pkg(&wire, &pkg, pHeader, NULL, 0), "parse traversing start");
        CHECK(DirectGate_Transfer_HandleStart(&escapeRx, &pkg, sEscapeDir) == XSTDOK,
            "a traversing name is reduced to its last component, not refused");
        clear_file_pkg(&wire, &pkg);

        CHECK(access(sEscapeTarget, F_OK) != 0,
            "the transfer did not write outside the destination directory");

        char sInside[512];
        snprintf(sInside, sizeof(sInside), "%s/directgate_escaped.bin", sEscapeDir);
        CHECK(access(sInside, F_OK) == 0, "it wrote inside the destination directory");
        DirectGate_Transfer_Destroy(&escapeRx);

        /* A name that is nothing but a walk has no last component to keep. */
        directgate_transfer_t dotRx;
        DirectGate_Transfer_Init(&dotRx);
        pHeader = DirectGate_Proto_BuildFileStart("esc-2", "..", 4, 1, 4);
        CHECK(pHeader != NULL, "build dotdot start");
        CHECK(build_file_pkg(&wire, &pkg, pHeader, NULL, 0), "parse dotdot start");
        CHECK(DirectGate_Transfer_HandleStart(&dotRx, &pkg, sEscapeDir) == XSTDERR,
            "a bare parent reference is refused");
        clear_file_pkg(&wire, &pkg);
        DirectGate_Transfer_Destroy(&dotRx);

        unlink(sInside);
        rmdir(sEscapeDir);
    }

    char sLinkPath[] = "/tmp/directgate_transfer_link.XXXXXX";
    int nLinkFd = mkstemp(sLinkPath);
    CHECK(nLinkFd >= 0, "mkstemp symlink path");
    close(nLinkFd);
    CHECK(unlink(sLinkPath) == 0, "unlink symlink placeholder");
    CHECK(symlink(sSrcPath, sLinkPath) == 0, "create symlink destination");

    directgate_transfer_t linkRx;
    DirectGate_Transfer_Init(&linkRx);
    pHeader = DirectGate_Proto_BuildFileStart("link-1", "link.bin", 10, 1, 10);
    CHECK(pHeader != NULL, "build symlink start");
    CHECK(build_file_pkg(&wire, &pkg, pHeader, NULL, 0),
        "parse symlink start");
    errno = 0;
    CHECK(DirectGate_Transfer_HandleStartPath(&linkRx, &pkg, sLinkPath) == XSTDERR,
        "exclusive inbound start rejects symlink destination");
    clear_file_pkg(&wire, &pkg);
    DirectGate_Transfer_Destroy(&linkRx);
    CHECK(unlink(sLinkPath) == 0, "cleanup symlink destination");

    unlink(sSrcPath);
    unlink(sDstPath);
    puts("transfer_smoke: OK");
    return 0;
}
