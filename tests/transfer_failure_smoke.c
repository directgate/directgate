/*
 * The file transfer engine when something goes wrong.
 *
 * transfer_smoke covers transfers that work. This covers the ones that do not:
 * a peer that cannot take the next message at the start, a chunk or the end;
 * an inbound start that is incomplete, inconsistent or arrives mid-transfer; a
 * chunk with nothing in it; an end with no usable hash; and a destination that
 * fills up, both on a chunk too big to buffer and on the final flush. Every one
 * ends in the error state, and none leaves a partial file behind to be
 * mistaken for a finished one.
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/sha.h>

#include "src/common/transfer.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "transfer_failure_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

/* A peer that takes every message except those with this action. */
typedef struct {
    const char *pFailOn;
    int nSent;
} refusing_peer_t;

static int refusing_send(xjson_obj_t *pHeader, const uint8_t *pPayload, size_t nLen, void *pCtx)
{
    (void)pPayload;
    (void)nLen;
    refusing_peer_t *pPeer = (refusing_peer_t*)pCtx;
    const char *pAction = XJSON_GetString(XJSON_GetObject(pHeader, "action"));

    if (pAction != NULL && pPeer->pFailOn != NULL && strcmp(pAction, pPeer->pFailOn) == 0) return XSTDERR;
    pPeer->nSent++;
    return XSTDOK;
}

static int write_file(const char *pPath, size_t nSize)
{
    FILE *pFile = fopen(pPath, "wb");
    if (pFile == NULL) return 0;

    for (size_t i = 0; i < nSize; i++) fputc((int)('a' + (i % 26)), pFile);
    return fclose(pFile) == 0;
}

/* A file message as it arrives, parsed; the wire bytes back the package. */
static int file_pkg(xbyte_buffer_t *pWire, directgate_pkg_t *pPkg, xjson_obj_t *pHeader, const uint8_t *pPayload, size_t nLen)
{
    XByteBuffer_Init(pWire, XSTDNON, XFALSE);
    if (pHeader == NULL) return 0;

    int nOk = DirectGate_Proto_Build(pWire, pHeader, pPayload, nLen, XFALSE) &&
        DirectGate_Package_Parse(pPkg, pWire->pData, pWire->nUsed);

    XJSON_FreeObject(pHeader);
    return nOk;
}

static void file_pkg_clear(xbyte_buffer_t *pWire, directgate_pkg_t *pPkg)
{
    DirectGate_Package_Clear(pPkg);
    XByteBuffer_Clear(pWire);
}

static int test_outbound_refusals(const char *pRoot)
{
    char sSource[512];
    snprintf(sSource, sizeof(sSource), "%s/source.bin", pRoot);
    CHECK(write_file(sSource, 70000), "write a source spanning two chunks");

    /* Refused at the start: nothing more is sent. */
    directgate_transfer_t ft;
    refusing_peer_t peer = { "start", 0 };
    DirectGate_Transfer_Init(&ft);
    CHECK(DirectGate_Transfer_Send(&ft, sSource, refusing_send, &peer) == XSTDERR, "a refused start fails the send");
    CHECK(!DirectGate_Transfer_IsActive(&ft) && peer.nSent == 0, "a refused start sends nothing after it");
    DirectGate_Transfer_Destroy(&ft);

    /* Refused on a chunk. */
    peer.pFailOn = "chunk";
    peer.nSent = 0;
    DirectGate_Transfer_Init(&ft);
    CHECK(DirectGate_Transfer_Send(&ft, sSource, refusing_send, &peer) == XSTDOK,
        "a transfer whose chunk will be refused starts");
    CHECK(DirectGate_Transfer_SendNext(&ft, refusing_send, &peer) == XSTDERR, "a refused chunk fails the transfer");
    CHECK(!DirectGate_Transfer_IsActive(&ft), "a refused chunk ends the transfer");
    int nSent = peer.nSent;
    CHECK(DirectGate_Transfer_SendNext(&ft, refusing_send, &peer) == XSTDNON && peer.nSent == nSent,
        "a failed transfer has nothing more to send");
    DirectGate_Transfer_Destroy(&ft);

    /* Refused at the end, after every chunk went out. */
    peer.pFailOn = "end";
    peer.nSent = 0;
    DirectGate_Transfer_Init(&ft);
    CHECK(DirectGate_Transfer_Send(&ft, sSource, refusing_send, &peer) == XSTDOK, "a transfer whose end will be refused starts");
    int nStatus = XSTDOK;
    for (int i = 0; i < 8 && nStatus == XSTDOK && DirectGate_Transfer_IsActive(&ft); i++)
        nStatus = DirectGate_Transfer_SendNext(&ft, refusing_send, &peer);
    CHECK(nStatus == XSTDERR && ft.eState == XTRANSFER_STATE_ERROR, "a refused end fails the transfer");
    CHECK(peer.nSent == 3, "the start and both chunks went out before the end was refused");
    DirectGate_Transfer_Destroy(&ft);

    /* A source that shrinks under the transfer is caught, not padded. */
    peer.pFailOn = NULL;
    peer.nSent = 0;
    DirectGate_Transfer_Init(&ft);
    CHECK(DirectGate_Transfer_Send(&ft, sSource, refusing_send, &peer) == XSTDOK, "start a transfer of a file about to shrink");
    CHECK(truncate(sSource, 100) == 0, "shrink the source");
    CHECK(DirectGate_Transfer_SendNext(&ft, refusing_send, &peer) == XSTDERR, "a source that shrank fails the transfer");
    DirectGate_Transfer_Destroy(&ft);

    /* Nothing to send when nothing was started. */
    DirectGate_Transfer_Init(&ft);
    CHECK(DirectGate_Transfer_SendNext(&ft, refusing_send, &peer) == XSTDNON,
        "a transfer that never started has nothing to send");
    CHECK(DirectGate_Transfer_Send(&ft, "/nonexistent/source.bin", refusing_send, &peer) == XSTDERR,
        "a source that does not exist is not sent");
    CHECK(DirectGate_Transfer_Send(&ft, pRoot, refusing_send, &peer) == XSTDERR, "a directory is not sent");
    DirectGate_Transfer_Destroy(&ft);

    unlink(sSource);
    return 0;
}

static int test_inbound_refusals(const char *pRoot)
{
    char sDest[512];
    snprintf(sDest, sizeof(sDest), "%s/dest.bin", pRoot);

    directgate_transfer_t ft;
    xbyte_buffer_t wire;
    directgate_pkg_t pkg;
    DirectGate_Transfer_Init(&ft);

    /* A start without an id, and one whose chunk count does not fit its size. */
    CHECK(file_pkg(&wire, &pkg, DirectGate_Proto_BuildFileStart(NULL, "dest.bin", 10, 1, 4096), NULL, 0),
        "build a start without an id");
    CHECK(DirectGate_Transfer_HandleStartPath(&ft, &pkg, sDest) == XSTDERR, "a start without an id is refused");
    file_pkg_clear(&wire, &pkg);

    CHECK(file_pkg(&wire, &pkg, DirectGate_Proto_BuildFileStart("in-1", "dest.bin", 10000, 1, 4096), NULL, 0),
        "build a start whose chunk count is wrong");
    CHECK(DirectGate_Transfer_HandleStartPath(&ft, &pkg, sDest) == XSTDERR,
        "a start whose chunks cannot hold its size is refused");
    file_pkg_clear(&wire, &pkg);
    CHECK(access(sDest, F_OK) != 0, "a refused start creates no file");

    /* A proper start, then a second one while it runs. */
    CHECK(file_pkg(&wire, &pkg, DirectGate_Proto_BuildFileStart("in-2", "dest.bin", 8, 1, 4096), NULL, 0), "build a start");
    CHECK(DirectGate_Transfer_HandleStartPath(&ft, &pkg, sDest) == XSTDOK, "a proper start is taken");
    CHECK(DirectGate_Transfer_HandleStartPath(&ft, &pkg, sDest) == XSTDERR && errno == EBUSY,
        "a second start while one runs is refused as busy");
    file_pkg_clear(&wire, &pkg);

    /* A chunk that carries nothing, then the real one, then an end without a usable hash. */
    CHECK(file_pkg(&wire, &pkg, DirectGate_Proto_BuildFileChunk("in-2", 0), NULL, 0), "build an empty chunk");
    CHECK(DirectGate_Transfer_HandleChunk(&ft, &pkg) == XSTDERR, "a chunk without a payload is refused");
    file_pkg_clear(&wire, &pkg);

    CHECK(file_pkg(&wire, &pkg, DirectGate_Proto_BuildFileChunk("in-2", 0), (const uint8_t*)"12345678", 8), "build the chunk");
    CHECK(DirectGate_Transfer_HandleChunk(&ft, &pkg) == XSTDOK, "the chunk is written");
    file_pkg_clear(&wire, &pkg);

    CHECK(file_pkg(&wire, &pkg, DirectGate_Proto_BuildFileEnd("in-2", "not-a-hash"), NULL, 0),
        "build an end with no usable hash");
    CHECK(DirectGate_Transfer_HandleEnd(&ft, &pkg, NULL, NULL) == XSTDERR, "an end without a usable hash is refused");
    file_pkg_clear(&wire, &pkg);
    DirectGate_Transfer_Destroy(&ft);
    CHECK(access(sDest, F_OK) != 0, "an upload that could not be verified is removed");

    /* A cancel of an outbound transfer names it as such. */
    char sSource[512];
    snprintf(sSource, sizeof(sSource), "%s/cancel-source.bin", pRoot);
    CHECK(write_file(sSource, 100), "write a source to cancel");
    refusing_peer_t peer = { NULL, 0 };
    DirectGate_Transfer_Init(&ft);
    CHECK(DirectGate_Transfer_Send(&ft, sSource, refusing_send, &peer) == XSTDOK, "start a transfer to cancel");
    CHECK(DirectGate_Transfer_HandleCancel(&ft) == XSTDOK && !DirectGate_Transfer_IsActive(&ft),
        "an outbound cancel stops it");
    CHECK(access(sSource, F_OK) == 0, "cancelling a download leaves the source alone");
    DirectGate_Transfer_Destroy(&ft);
    unlink(sSource);
    return 0;
}

/* A destination that fills up. Run in a child: the size limit applies to the
   whole process, and hitting it raises SIGXFSZ unless that is ignored. Only the
   soft limit is lowered, so the child can lift it again before it exits. */
static int full_disk_child(const char *pRoot)
{
    signal(SIGXFSZ, SIG_IGN);
    struct rlimit limit;
    CHECK(getrlimit(RLIMIT_FSIZE, &limit) == 0, "read the file size limit");
    limit.rlim_cur = 1024;
    CHECK(setrlimit(RLIMIT_FSIZE, &limit) == 0, "cap the file size");

    char sDest[512];
    static uint8_t chunk[8192];
    memset(chunk, 'z', sizeof(chunk));

    /* A chunk too big to buffer is written at once, and fails at once. */
    snprintf(sDest, sizeof(sDest), "%s/full-chunk.bin", pRoot);
    directgate_transfer_t ft;
    xbyte_buffer_t wire;
    directgate_pkg_t pkg;
    DirectGate_Transfer_Init(&ft);
    CHECK(file_pkg(&wire, &pkg, DirectGate_Proto_BuildFileStart("full-1", "x", sizeof(chunk), 1, sizeof(chunk)), NULL, 0),
        "build the start of a big upload");
    CHECK(DirectGate_Transfer_HandleStartPath(&ft, &pkg, sDest) == XSTDOK, "the big upload starts");
    file_pkg_clear(&wire, &pkg);
    CHECK(file_pkg(&wire, &pkg, DirectGate_Proto_BuildFileChunk("full-1", 0), chunk, sizeof(chunk)), "build the big chunk");
    CHECK(DirectGate_Transfer_HandleChunk(&ft, &pkg) == XSTDERR, "a chunk the disk cannot take fails the upload");
    file_pkg_clear(&wire, &pkg);
    DirectGate_Transfer_Destroy(&ft);
    CHECK(access(sDest, F_OK) != 0, "a failed upload leaves no partial file");

    /* Small chunks sit in the buffer until the end flushes them, and that is where it fails. */
    snprintf(sDest, sizeof(sDest), "%s/full-end.bin", pRoot);
    DirectGate_Transfer_Init(&ft);
    CHECK(file_pkg(&wire, &pkg, DirectGate_Proto_BuildFileStart("full-2", "x", 2000, 2, 1000), NULL, 0),
        "build the start of a buffered upload");
    CHECK(DirectGate_Transfer_HandleStartPath(&ft, &pkg, sDest) == XSTDOK, "the buffered upload starts");
    file_pkg_clear(&wire, &pkg);

    for (uint32_t i = 0; i < 2; i++)
    {
        CHECK(file_pkg(&wire, &pkg, DirectGate_Proto_BuildFileChunk("full-2", i), chunk, 1000), "build a buffered chunk");
        CHECK(DirectGate_Transfer_HandleChunk(&ft, &pkg) == XSTDOK, "a buffered chunk is taken");
        file_pkg_clear(&wire, &pkg);
    }

    char sHash[SHA256_DIGEST_LENGTH * 2 + 1];
    uint8_t digest[SHA256_DIGEST_LENGTH], all[2000];
    memset(all, 'z', sizeof(all));
    SHA256(all, sizeof(all), digest);
    for (size_t i = 0; i < sizeof(digest); i++) snprintf(sHash + (i * 2), 3, "%02x", digest[i]);

    CHECK(file_pkg(&wire, &pkg, DirectGate_Proto_BuildFileEnd("full-2", sHash), NULL, 0), "build the end");
    CHECK(DirectGate_Transfer_HandleEnd(&ft, &pkg, NULL, NULL) == XSTDERR,
        "a disk that fills on the final flush fails the upload, not its hash check");
    file_pkg_clear(&wire, &pkg);
    DirectGate_Transfer_Destroy(&ft);
    CHECK(access(sDest, F_OK) != 0, "an upload that could not be flushed leaves no partial file");
    return 0;
}

static int test_full_disk(const char *pRoot)
{
    pid_t nPid = fork();
    CHECK(nPid >= 0, "fork a child for the size limit");
    /* exit, not _exit, and with the cap lifted: the child's coverage and memcheck
       reports are written by its exit handlers, and they are bigger than the cap. */
    if (nPid == 0)
    {
        int nResult = full_disk_child(pRoot);
        struct rlimit limit;
        if (getrlimit(RLIMIT_FSIZE, &limit) == 0)
        {
            limit.rlim_cur = limit.rlim_max;
            setrlimit(RLIMIT_FSIZE, &limit);
        }
        exit(nResult);
    }

    int nStatus = 0;
    CHECK(waitpid(nPid, &nStatus, 0) == nPid, "wait for the size-limited child");
    CHECK(WIFEXITED(nStatus) && WEXITSTATUS(nStatus) == 0, "a full disk is handled as a failed upload");
    return 0;
}

int main(void)
{
    char sRoot[] = "/tmp/directgate_transfer_failure.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "create a working directory");

    int nResult = test_outbound_refusals(sRoot);
    if (!nResult) nResult = test_inbound_refusals(sRoot);
    if (!nResult) nResult = test_full_disk(sRoot);

    char sCmd[512];
    snprintf(sCmd, sizeof(sCmd), "rm -rf '%s'", sRoot);
    if (system(sCmd) != 0) fprintf(stderr, "transfer_failure_smoke: could not remove %s\n", sRoot);

    if (nResult) return 1;
    puts("transfer_failure_smoke: OK");
    return 0;
}
