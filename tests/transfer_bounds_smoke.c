#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>

#include "src/common/transfer.h"

#define CHECK(c, msg) do { if (!(c)) { \
    fprintf(stderr, "transfer_bounds_smoke: %s\n", msg); return 1; } } while (0)

static int ends;
static size_t bytes;
static int send_packet(xjson_obj_t *header, const uint8_t *payload, size_t size, void *ctx)
{
    (void)payload;
    (void)ctx;
    bytes += size;
    if (xstrcmp(XJSON_GetString(XJSON_GetObject(header, "action")), "end")) ends++;
    return XSTDOK;
}

int main(void)
{
    char dir[] = "/tmp/directgate-transfer-bounds.XXXXXX";
    CHECK(mkdtemp(dir), "temporary directory");
    char path[512], source[512];
    snprintf(path, sizeof(path), "%s/output", dir);
    snprintf(source, sizeof(source), "%s/source", dir);
    directgate_transfer_t rx, tx;
    DirectGate_Transfer_Init(&rx);
    DirectGate_Transfer_Init(&tx);
    directgate_pkg_file_t file = {0};
    directgate_pkg_t pkg = {0};
    pkg.header.eType = DIRECTGATE_PKG_FILE;
    pkg.pPackage = &file;
    file.transfer.pTransferId = "one";
    file.transfer.pFileName = "output";
    file.transfer.nFileSize = 4;
    file.transfer.nChunkSize = 4;
    file.transfer.nChunks = 1;
    file.transfer.pSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    CHECK(DirectGate_Transfer_HandleStartPath(&rx, &pkg, path) == XSTDOK, "start");
    errno = EAGAIN; /* A drained nonblocking socket commonly leaves this behind. */
    CHECK(DirectGate_Transfer_HandleEnd(&rx, &pkg, send_packet, NULL) < 0,
        "matching hash of empty data cannot finalize a four-byte file");
    CHECK(errno == EINVAL, "incomplete transfer must not report stale socket errno");
    DirectGate_Transfer_Destroy(&rx);
    CHECK(access(path, F_OK) < 0, "destroy removes failed inbound file");

    CHECK(DirectGate_Transfer_HandleStartPath(&rx, &pkg, path) == XSTDOK, "restart");
    file.data.pPayload = (const uint8_t *)"abcde";
    file.data.nPayloadLength = 5;
    CHECK(DirectGate_Transfer_HandleChunk(&rx, &pkg) < 0, "oversized chunk rejected");
    CHECK(rx.nBytesXferred == 0, "oversized chunk never written");
    DirectGate_Transfer_HandleCancel(&rx);
    CHECK(access(path, F_OK) < 0, "cancel removes errored inbound file");

    CHECK(DirectGate_Transfer_HandleStartPath(&rx, &pkg, path) == XSTDOK, "restart ID case");
    file.transfer.pTransferId = "other";
    file.data.nPayloadLength = 4;
    CHECK(DirectGate_Transfer_HandleChunk(&rx, &pkg) < 0 && rx.nBytesXferred == 0,
        "wrong transfer ID cannot write");
    CHECK(DirectGate_Transfer_HandleEnd(&rx, &pkg, NULL, NULL) < 0,
        "wrong transfer ID cannot finish");
    file.transfer.pTransferId = "one";
    CHECK(DirectGate_Transfer_HandleChunk(&rx, &pkg) == XSTDOK, "correct chunk accepted");
    file.transfer.nChunkIndex = 1;
    CHECK(DirectGate_Transfer_HandleChunk(&rx, &pkg) < 0, "extra chunk rejected");
    DirectGate_Transfer_Destroy(&rx);
    CHECK(access(path, F_OK) < 0, "extra chunk failure cleaned");

    file.transfer.nChunks = 2;
    CHECK(DirectGate_Transfer_HandleStartPath(&rx, &pkg, path) < 0,
        "inconsistent chunk count rejected before creating a file");
    file.transfer.nFileSize = UINT64_MAX;
    file.transfer.nChunkSize = 1;
    file.transfer.nChunks = UINT32_MAX;
    CHECK(DirectGate_Transfer_HandleStartPath(&rx, &pkg, path) < 0,
        "unrepresentable chunk count rejected");
    file.transfer.nFileSize = 0;
    file.transfer.nChunks = 0;
    CHECK(DirectGate_Transfer_HandleStartPath(&rx, &pkg, path) == XSTDOK, "empty start");
    CHECK(DirectGate_Transfer_HandleEnd(&rx, &pkg, NULL, NULL) == XSTDOK, "empty end");
    DirectGate_Transfer_HandleCancel(&rx);
    DirectGate_Transfer_Destroy(&rx);
    CHECK(access(path, F_OK) == 0, "completed file survives cancel and destroy");
    unlink(path);

    char longPath[XFILE_PATH_SIZE + 1];
    memset(longPath, 'x', sizeof(longPath) - 1);
    longPath[sizeof(longPath) - 1] = 0;
    CHECK(DirectGate_Transfer_HandleStartPath(&rx, &pkg, longPath) < 0,
        "overlong path rejected without truncation");
    file.transfer.pTransferId = longPath;
    CHECK(DirectGate_Transfer_HandleStartPath(&rx, &pkg, path) < 0,
        "overlong ID rejected without truncation");

    CHECK(mkfifo(source, 0600) == 0, "create FIFO source");
    alarm(3);
    CHECK(DirectGate_Transfer_Send(&tx, source, send_packet, NULL) < 0,
        "FIFO rejected without waiting for a writer");
    alarm(0);
    DirectGate_Transfer_Destroy(&tx);
    unlink(source);

    FILE *f = fopen(source, "wb");
    CHECK(f && fwrite("abcd", 1, 4, f) == 4 && fclose(f) == 0, "write source");
    CHECK(DirectGate_Transfer_Send(&tx, source, send_packet, NULL) == XSTDOK, "send source");
    FILE *original = tx.pFile;
    CHECK(DirectGate_Transfer_Send(&tx, source, send_packet, NULL) < 0 && tx.pFile == original,
        "second send preserves active transfer");
    CHECK(truncate(source, 0) == 0, "truncate source during transfer");
    CHECK(DirectGate_Transfer_SendNext(&tx, send_packet, NULL) < 0,
        "short source fails instead of sending success");
    CHECK(ends == 0, "no successful end for truncated source");
    DirectGate_Transfer_Destroy(&tx);
    CHECK(access(source, F_OK) == 0, "failed send preserves source");

    f = fopen(source, "wb");
    CHECK(f && fwrite("abcd", 1, 4, f) == 4 && fclose(f) == 0, "rewrite source");
    CHECK(DirectGate_Transfer_Send(&tx, source, send_packet, NULL) == XSTDOK, "send before growth");
    f = fopen(source, "ab");
    CHECK(f && fwrite("extra", 1, 5, f) == 5 && fclose(f) == 0, "grow source");
    bytes = 0;
    while (DirectGate_Transfer_IsActive(&tx))
        CHECK(DirectGate_Transfer_SendNext(&tx, send_packet, NULL) == XSTDOK, "send announced bytes");
    CHECK(bytes == 4 && ends == 1, "source growth does not exceed announced size");
    DirectGate_Transfer_Destroy(&tx);
    unlink(source);
    rmdir(dir);
    puts("transfer_bounds_smoke: OK");
    return 0;
}
