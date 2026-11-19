/*
 * The SHA-256 a file transfer carries and checks.
 *
 * transfer.c hashes every byte of a transfer with OpenSSL where it can and with libxutils where it cannot; the
 * digest is the contract with the browser either way. Files of every size that matters to a block hash - empty, one
 * byte, either side of the 55/56/64 byte padding edges, either side of a chunk and across several - go from a sender
 * into a receiver here. The sender's file/end has to carry the SHA-256 of exactly the file, the receiver has to keep
 * exactly the file and acknowledge it, and the receiver has to refuse an end of each size whose digest is one bit off.
 *
 * Where the linker can wrap OpenSSL's digest calls, each of them is also failed on purpose. A context or an init
 * that cannot be had leaves the transfer to libxutils and changes nothing on the wire; an update or a final that
 * fails part way fails the transfer, and no digest goes out or is accepted. Every context a transfer takes is given
 * back, whether it finished, failed, was cancelled or was destroyed part way.
 */

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
            fprintf(stderr, "transfer_digest_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#define CHUNK       XFILE_CHUNK_SIZE
#define MAX_FILE    (3U * CHUNK + 17U)
#define HEX_SIZE    (SHA256_DIGEST_LENGTH * 2 + 1)

static uint8_t g_content[MAX_FILE];
static uint8_t g_readBack[MAX_FILE + 1];
static char g_sSource[512];
static char g_sDest[512];

#ifdef DIRECTGATE_TEST_EVP_WRAP
/* Counted from the last reset_evp(); a fail-at of zero fails nothing */
static int g_nCtxLive, g_nNewCalls, g_nInitCalls, g_nUpdateCalls, g_nFinalCalls;
static int g_nFailNewAt, g_nFailInitAt, g_nFailUpdateAt, g_nFailFinalAt;
static int g_nShortFinalAt;     /* the final with this number succeeds, but with a digest shorter than SHA-256's */

EVP_MD_CTX *__real_EVP_MD_CTX_new(void);
void __real_EVP_MD_CTX_free(EVP_MD_CTX *pCtx);
int __real_EVP_DigestInit_ex(EVP_MD_CTX *pCtx, const EVP_MD *pType, ENGINE *pImpl);
int __real_EVP_DigestUpdate(EVP_MD_CTX *pCtx, const void *pData, size_t nCount);
int __real_EVP_DigestFinal_ex(EVP_MD_CTX *pCtx, unsigned char *pMd, unsigned int *pSize);

EVP_MD_CTX *__wrap_EVP_MD_CTX_new(void)
{
    if (++g_nNewCalls == g_nFailNewAt) return NULL;
    EVP_MD_CTX *pCtx = __real_EVP_MD_CTX_new();
    if (pCtx != NULL) g_nCtxLive++;
    return pCtx;
}

void __wrap_EVP_MD_CTX_free(EVP_MD_CTX *pCtx)
{
    if (pCtx != NULL) g_nCtxLive--;
    __real_EVP_MD_CTX_free(pCtx);
}

int __wrap_EVP_DigestInit_ex(EVP_MD_CTX *pCtx, const EVP_MD *pType, ENGINE *pImpl)
{
    if (++g_nInitCalls == g_nFailInitAt) return 0;
    return __real_EVP_DigestInit_ex(pCtx, pType, pImpl);
}

int __wrap_EVP_DigestUpdate(EVP_MD_CTX *pCtx, const void *pData, size_t nCount)
{
    if (++g_nUpdateCalls == g_nFailUpdateAt) return 0;
    return __real_EVP_DigestUpdate(pCtx, pData, nCount);
}

int __wrap_EVP_DigestFinal_ex(EVP_MD_CTX *pCtx, unsigned char *pMd, unsigned int *pSize)
{
    if (++g_nFinalCalls == g_nFailFinalAt)
    {
        /* What a failing final leaves behind is not a digest; make sure nothing takes it for one */
        if (pMd != NULL) memset(pMd, 0xA5, SHA256_DIGEST_LENGTH);
        return 0;
    }

    int nRet = __real_EVP_DigestFinal_ex(pCtx, pMd, pSize);
    if (g_nFinalCalls == g_nShortFinalAt && pSize != NULL) *pSize = 20;
    return nRet;
}

static void reset_evp(void)
{
    g_nNewCalls = g_nInitCalls = g_nUpdateCalls = g_nFinalCalls = 0;
    g_nFailNewAt = g_nFailInitAt = g_nFailUpdateAt = g_nFailFinalAt = g_nShortFinalAt = 0;
}
#endif

/* The receiving end of a transfer, fed what the sender hands its callback as the packets it would have become */
typedef struct {
    directgate_transfer_t *pRx;
    char sEndSha[HEX_SIZE];     /* the digest the sender's file/end carried */
    int nStarts;
    int nChunks;
    int nEnds;
    int nAcks;
    int nRefused;               /* calls the receiver refused */
    int nRefusedErrno;          /* errno of the first refusal */
    xbool_t bFlipEnd;           /* hand the receiver the end with one bit of its digest flipped */
} link_t;

static void to_hex(const uint8_t *pDigest, char *pHex)
{
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) snprintf(pHex + i * 2, 3, "%02x", pDigest[i]);
}

#ifdef DIRECTGATE_TEST_EVP_WRAP
/* A peer that takes every message and passes none of them on */
static int sink_send(xjson_obj_t *pHeader, const uint8_t *pPayload, size_t nLen, void *pCtx)
{
    (void)pHeader;
    (void)pPayload;
    (void)nLen;
    (void)pCtx;
    return XSTDOK;
}
#endif

static int ack_send(xjson_obj_t *pHeader, const uint8_t *pPayload, size_t nLen, void *pCtx)
{
    (void)pPayload;
    (void)nLen;
    const char *pAction = XJSON_GetString(XJSON_GetObject(pHeader, "action"));
    if (pAction != NULL && !strcmp(pAction, "ack")) ((link_t*)pCtx)->nAcks++;
    return XSTDOK;
}

/* One bit of one hex digit: the lowest bit of the digit's value */
static void flip_bit(char *pHex)
{
    const char *pDigits = "0123456789abcdef";
    const char *pAt = strchr(pDigits, pHex[7]);
    if (pAt != NULL) pHex[7] = pDigits[(pAt - pDigits) ^ 1];
}

static int deliver(xjson_obj_t *pHeader, const uint8_t *pPayload, size_t nLen, void *pCtx)
{
    link_t *pLink = (link_t*)pCtx;
    const char *pAction = XJSON_GetString(XJSON_GetObject(pHeader, "action"));
    if (pAction == NULL) return XSTDERR;

    xjson_obj_t *pFlipped = NULL;
    if (!strcmp(pAction, "end"))
    {
        const char *pSha = XJSON_GetString(XJSON_GetObject(pHeader, "sha256"));
        const char *pId = XJSON_GetString(XJSON_GetObject(pHeader, "transferId"));
        xstrncpy(pLink->sEndSha, sizeof(pLink->sEndSha), pSha != NULL ? pSha : "");
        pLink->nEnds++;

        if (pLink->bFlipEnd)
        {
            char sFlipped[HEX_SIZE];
            xstrncpy(sFlipped, sizeof(sFlipped), pLink->sEndSha);
            flip_bit(sFlipped);
            pFlipped = DirectGate_Proto_BuildFileEnd(pId, sFlipped);
            if (pFlipped == NULL) return XSTDERR;
        }
    }

    xbyte_buffer_t wire;
    XByteBuffer_Init(&wire, 0, XFALSE);

    directgate_pkg_t pkg;
    if (!DirectGate_Proto_Build(&wire, pFlipped != NULL ? pFlipped : pHeader, pPayload, nLen, XFALSE) ||
        !DirectGate_Package_Parse(&pkg, wire.pData, wire.nUsed))
    {
        XJSON_FreeObject(pFlipped);
        XByteBuffer_Clear(&wire);
        return XSTDERR;
    }

    int nStatus = XSTDERR;
    errno = 0;

    if (!strcmp(pAction, "start"))
    {
        pLink->nStarts++;
        nStatus = DirectGate_Transfer_HandleStartPath(pLink->pRx, &pkg, g_sDest);
    }
    else if (!strcmp(pAction, "chunk"))
    {
        pLink->nChunks++;
        nStatus = DirectGate_Transfer_HandleChunk(pLink->pRx, &pkg);
    }
    else if (!strcmp(pAction, "end"))
    {
        nStatus = DirectGate_Transfer_HandleEnd(pLink->pRx, &pkg, ack_send, pLink);
    }

    if (nStatus < 0 && !pLink->nRefused++) pLink->nRefusedErrno = errno;

    DirectGate_Package_Clear(&pkg);
    XByteBuffer_Clear(&wire);
    XJSON_FreeObject(pFlipped);
    return nStatus;
}

static int write_source(size_t nSize)
{
    FILE *pFile = fopen(g_sSource, "wb");
    if (pFile == NULL) return 0;

    int nOk = (nSize == 0 || fwrite(g_content, 1, nSize, pFile) == nSize);
    return fclose(pFile) == 0 && nOk;
}

/* Whether the destination holds exactly the first nSize bytes of the content */
static int dest_holds(size_t nSize)
{
    FILE *pFile = fopen(g_sDest, "rb");
    if (pFile == NULL) return 0;

    size_t nRead = fread(g_readBack, 1, sizeof(g_readBack), pFile);
    fclose(pFile);
    return nRead == nSize && (nSize == 0 || !memcmp(g_readBack, g_content, nSize));
}

static int dest_exists(void)
{
    return access(g_sDest, F_OK) == 0;
}

/* Runs the sender until it finishes or fails; the receiver sees each message as it goes */
static void run_transfer(directgate_transfer_t *pTx, link_t *pLink)
{
    if (DirectGate_Transfer_Send(pTx, g_sSource, deliver, pLink) != XSTDOK) return;

    while (DirectGate_Transfer_IsActive(pTx))
        if (DirectGate_Transfer_SendNext(pTx, deliver, pLink) < 0) break;
}

static void expected_hex(size_t nSize, char *pHex)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(g_content, nSize, digest);
    to_hex(digest, pHex);
}

/* A transfer of nSize bytes that has to arrive whole, with the digest of exactly those bytes */
static int transfer_ok(size_t nSize, const char *pWhat)
{
    char sExpected[HEX_SIZE], sMsg[256];
    expected_hex(nSize, sExpected);

    directgate_transfer_t tx, rx;
    DirectGate_Transfer_Init(&tx);
    DirectGate_Transfer_Init(&rx);
    unlink(g_sDest);

    link_t link;
    memset(&link, 0, sizeof(link));
    link.pRx = &rx;

    snprintf(sMsg, sizeof(sMsg), "%s: the source of %zu bytes is written", pWhat, nSize);
    CHECK(write_source(nSize), sMsg);
    run_transfer(&tx, &link);

    size_t nChunks = (nSize + CHUNK - 1U) / CHUNK;
    snprintf(sMsg, sizeof(sMsg), "%s: a file of %zu bytes is sent whole", pWhat, nSize);
    CHECK(tx.eState == XTRANSFER_STATE_DONE && link.nStarts == 1 && (size_t)link.nChunks == nChunks && link.nEnds == 1, sMsg);

    snprintf(sMsg, sizeof(sMsg), "%s: the end of a file of %zu bytes carries the SHA-256 of exactly that file", pWhat, nSize);
    CHECK(!strcmp(link.sEndSha, sExpected), sMsg);

    snprintf(sMsg, sizeof(sMsg), "%s: a file of %zu bytes is received, checked and acknowledged", pWhat, nSize);
    CHECK(rx.eState == XTRANSFER_STATE_DONE && link.nRefused == 0 && link.nAcks == 1, sMsg);

    snprintf(sMsg, sizeof(sMsg), "%s: the receiver keeps exactly the %zu bytes that were sent", pWhat, nSize);
    CHECK(dest_holds(nSize), sMsg);

    DirectGate_Transfer_Destroy(&tx);
    DirectGate_Transfer_Destroy(&rx);

    snprintf(sMsg, sizeof(sMsg), "%s: a finished transfer of %zu bytes stays saved", pWhat, nSize);
    CHECK(dest_holds(nSize), sMsg);

    unlink(g_sDest);
    return 0;
}

/* The same transfer, with the receiver handed a digest one bit off: refused, and nothing is kept */
static int transfer_tampered(size_t nSize)
{
    char sMsg[256];
    directgate_transfer_t tx, rx;
    DirectGate_Transfer_Init(&tx);
    DirectGate_Transfer_Init(&rx);
    unlink(g_sDest);

    link_t link;
    memset(&link, 0, sizeof(link));
    link.pRx = &rx;
    link.bFlipEnd = XTRUE;

    snprintf(sMsg, sizeof(sMsg), "the source of %zu bytes is written for the tampered end", nSize);
    CHECK(write_source(nSize), sMsg);
    run_transfer(&tx, &link);

    snprintf(sMsg, sizeof(sMsg), "an end of a file of %zu bytes whose digest is one bit off is refused", nSize);
    CHECK(link.nEnds == 1 && link.nRefused == 1 && link.nRefusedErrno == EINVAL && link.nAcks == 0 &&
        rx.eState == XTRANSFER_STATE_ERROR, sMsg);

    DirectGate_Transfer_Destroy(&tx);
    DirectGate_Transfer_Destroy(&rx);

    snprintf(sMsg, sizeof(sMsg), "a refused file of %zu bytes is not left behind", nSize);
    CHECK(!dest_exists(), sMsg);
    return 0;
}

#ifdef DIRECTGATE_TEST_EVP_WRAP
/* A three-chunk file and a tail. Of the digest calls a round trip makes, the sender's come first: its init before
   the start goes out, its update for a chunk before the chunk does, its final before the end. */
#define WRAP_SIZE   (3U * CHUNK + 17U)
#define WRAP_CHUNKS 4

static int wrap_fallbacks(void)
{
    /* Untouched, both ends hash with OpenSSL, and each lets go of its context the moment it has its digest */
    reset_evp();
    directgate_transfer_t tx, rx;
    DirectGate_Transfer_Init(&tx);
    DirectGate_Transfer_Init(&rx);
    link_t link;
    memset(&link, 0, sizeof(link));
    link.pRx = &rx;
    CHECK(write_source(WRAP_SIZE), "the source is written for the OpenSSL round trip");
    run_transfer(&tx, &link);
    CHECK(tx.eState == XTRANSFER_STATE_DONE && rx.eState == XTRANSFER_STATE_DONE && dest_holds(WRAP_SIZE),
        "a round trip hashed by OpenSSL arrives whole");
    CHECK(g_nUpdateCalls == 2 * WRAP_CHUNKS, "both ends hash every chunk with OpenSSL");
    CHECK(g_nCtxLive == 0, "both ends give back their OpenSSL context as soon as they have the digest");
    DirectGate_Transfer_Destroy(&tx);
    DirectGate_Transfer_Destroy(&rx);
    unlink(g_sDest);

    /* No context, or one OpenSSL will not set up, at either end or both: libxutils hashes, nothing else changes */
    static const struct { int nNewAt; int nInitAt; int nOpenSSLUpdates; const char *pWhat; } cases[] = {
        { 1, 0, WRAP_CHUNKS, "the sender gets no OpenSSL context" },
        { 2, 0, WRAP_CHUNKS, "the receiver gets no OpenSSL context" },
        { 0, 1, WRAP_CHUNKS, "OpenSSL will not set up the sender's SHA-256" },
        { 0, 2, WRAP_CHUNKS, "OpenSSL will not set up the receiver's SHA-256" }
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        reset_evp();
        g_nFailNewAt = cases[i].nNewAt;
        g_nFailInitAt = cases[i].nInitAt;
        if (transfer_ok(WRAP_SIZE, cases[i].pWhat)) return 1;

        char sMsg[256];
        snprintf(sMsg, sizeof(sMsg), "%s: the other end still hashes with OpenSSL", cases[i].pWhat);
        CHECK(g_nUpdateCalls == cases[i].nOpenSSLUpdates, sMsg);
        snprintf(sMsg, sizeof(sMsg), "%s: no OpenSSL context is kept", cases[i].pWhat);
        CHECK(g_nCtxLive == 0, sMsg);
    }

    /* Neither end gets one */
    reset_evp();
    g_nFailInitAt = 1;
    g_nFailNewAt = 2;
    if (transfer_ok(WRAP_SIZE, "neither end gets OpenSSL's SHA-256")) return 1;
    CHECK(g_nUpdateCalls == 0 && g_nCtxLive == 0, "with neither end on OpenSSL, libxutils hashes both");

    /* Every size again with libxutils at both ends: its digests are the contract as much as OpenSSL's */
    static const size_t sizes[] = { 0, 1, 55, 56, 64, 65, CHUNK - 1U, CHUNK, CHUNK + 1U, 2U * CHUNK + 1U };
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
    {
        reset_evp();
        g_nFailNewAt = 1;
        g_nFailInitAt = 1;
        if (transfer_ok(sizes[i], "libxutils at both ends")) return 1;
        CHECK(g_nCtxLive == 0, "libxutils at both ends keeps no OpenSSL context");
    }

    return 0;
}

/* An update or a final OpenSSL fails: the transfer fails there, no digest is sent or accepted, nothing is kept */
static int wrap_failures(void)
{
    directgate_transfer_t tx, rx;
    link_t link;

    /* The sender's update for its second chunk */
    reset_evp();
    g_nFailUpdateAt = 3;
    DirectGate_Transfer_Init(&tx);
    DirectGate_Transfer_Init(&rx);
    memset(&link, 0, sizeof(link));
    link.pRx = &rx;
    CHECK(write_source(WRAP_SIZE), "the source is written for the failing sender update");
    run_transfer(&tx, &link);
    CHECK(tx.eState == XTRANSFER_STATE_ERROR, "a sender whose hash fails stops in error");
    CHECK(link.nChunks == 1 && link.nEnds == 0, "the chunk the sender could not hash is not sent, nor any end");
    DirectGate_Transfer_Destroy(&tx);
    DirectGate_Transfer_Destroy(&rx);
    CHECK(g_nCtxLive == 0 && !dest_exists(), "the failed send leaves no context and no partial file");

    /* The receiver's update for the second chunk; the session then cancels it, as files.c does */
    reset_evp();
    g_nFailUpdateAt = 4;
    DirectGate_Transfer_Init(&tx);
    DirectGate_Transfer_Init(&rx);
    memset(&link, 0, sizeof(link));
    link.pRx = &rx;
    run_transfer(&tx, &link);
    CHECK(rx.eState == XTRANSFER_STATE_ERROR && link.nRefused == 1 && link.nRefusedErrno == EIO,
        "a chunk the receiver cannot hash is refused with an I/O error");
    CHECK(link.nChunks == 2 && link.nEnds == 0 && tx.eState == XTRANSFER_STATE_ERROR,
        "the sender stops at the chunk the receiver refused");
    CHECK(g_nCtxLive == 2, "both failed ends hold their context until the transfer is let go of");
    CHECK(DirectGate_Transfer_HandleCancel(&rx) == XSTDOK && g_nCtxLive == 1 && !dest_exists(),
        "cancelling the receiver gives its context back at once and removes the partial file");
    DirectGate_Transfer_Destroy(&tx);
    DirectGate_Transfer_Destroy(&rx);
    CHECK(g_nCtxLive == 0, "destroying the failed sender gives its context back");

    /* The sender's final */
    reset_evp();
    g_nFailFinalAt = 1;
    DirectGate_Transfer_Init(&tx);
    DirectGate_Transfer_Init(&rx);
    memset(&link, 0, sizeof(link));
    link.pRx = &rx;
    run_transfer(&tx, &link);
    CHECK(tx.eState == XTRANSFER_STATE_ERROR && link.nChunks == WRAP_CHUNKS && link.nEnds == 0,
        "a sender that cannot finish its digest sends no end");
    CHECK(g_nCtxLive == 1, "the sender gave back its context with the failed final, the receiver still has its");
    DirectGate_Transfer_Destroy(&tx);
    DirectGate_Transfer_Destroy(&rx);
    CHECK(g_nCtxLive == 0 && !dest_exists(), "the transfer without an end leaves no context and no partial file");

    /* The receiver's final */
    reset_evp();
    g_nFailFinalAt = 2;
    DirectGate_Transfer_Init(&tx);
    DirectGate_Transfer_Init(&rx);
    memset(&link, 0, sizeof(link));
    link.pRx = &rx;
    run_transfer(&tx, &link);
    CHECK(link.nEnds == 1 && link.nRefused == 1 && link.nRefusedErrno == EIO && link.nAcks == 0,
        "an end the receiver cannot finish the digest for is refused with an I/O error, unacknowledged");
    CHECK(rx.eState == XTRANSFER_STATE_ERROR && g_nCtxLive == 0, "the receiver gave back its context with the final");
    CHECK(DirectGate_Transfer_HandleCancel(&rx) == XSTDOK && !dest_exists(),
        "the file whose digest could not be finished is not kept");
    DirectGate_Transfer_Destroy(&tx);
    DirectGate_Transfer_Destroy(&rx);

    /* A final that says it worked but hands back fewer bytes than a SHA-256 has is no digest either, at both ends */
    reset_evp();
    g_nShortFinalAt = 1;
    DirectGate_Transfer_Init(&tx);
    DirectGate_Transfer_Init(&rx);
    memset(&link, 0, sizeof(link));
    link.pRx = &rx;
    run_transfer(&tx, &link);
    CHECK(tx.eState == XTRANSFER_STATE_ERROR && link.nEnds == 0, "a sender handed a short digest sends no end");
    DirectGate_Transfer_Destroy(&tx);
    DirectGate_Transfer_Destroy(&rx);

    reset_evp();
    g_nShortFinalAt = 2;
    DirectGate_Transfer_Init(&tx);
    DirectGate_Transfer_Init(&rx);
    memset(&link, 0, sizeof(link));
    link.pRx = &rx;
    run_transfer(&tx, &link);
    CHECK(link.nEnds == 1 && link.nRefused == 1 && link.nRefusedErrno == EIO && rx.eState == XTRANSFER_STATE_ERROR,
        "a receiver handed a short digest refuses the end with an I/O error");
    DirectGate_Transfer_Destroy(&tx);
    DirectGate_Transfer_Destroy(&rx);
    CHECK(g_nCtxLive == 0 && !dest_exists(), "short digests leave no context and no file behind");
    unlink(g_sDest);
    return 0;
}

/* However a transfer ends, its context goes with it */
static int wrap_lifetimes(void)
{
    directgate_transfer_t tx, rx;
    link_t link;

    /* Destroyed part way, both ends */
    reset_evp();
    DirectGate_Transfer_Init(&tx);
    DirectGate_Transfer_Init(&rx);
    memset(&link, 0, sizeof(link));
    link.pRx = &rx;
    CHECK(write_source(WRAP_SIZE), "the source is written for the lifetime checks");
    CHECK(DirectGate_Transfer_Send(&tx, g_sSource, deliver, &link) == XSTDOK, "a send starts");
    CHECK(DirectGate_Transfer_SendNext(&tx, deliver, &link) == XSTDOK, "its first chunk goes out");
    CHECK(g_nCtxLive == 2, "each end holds one context while the transfer runs");
    DirectGate_Transfer_Destroy(&tx);
    CHECK(g_nCtxLive == 1, "destroying the sender part way gives its context back");
    DirectGate_Transfer_Destroy(&rx);
    CHECK(g_nCtxLive == 0 && !dest_exists(), "destroying the receiver part way gives its context back");

    /* A new send over one that failed takes the place of the old context, it does not pile up */
    reset_evp();
    g_nFailUpdateAt = 1;
    DirectGate_Transfer_Init(&tx);
    DirectGate_Transfer_Init(&rx);
    memset(&link, 0, sizeof(link));
    link.pRx = &rx;
    CHECK(DirectGate_Transfer_Send(&tx, g_sSource, deliver, &link) == XSTDOK, "a send starts again");
    CHECK(DirectGate_Transfer_SendNext(&tx, deliver, &link) < 0 && tx.eState == XTRANSFER_STATE_ERROR, "its first update fails");
    DirectGate_Transfer_Destroy(&rx);
    CHECK(g_nCtxLive == 1, "the failed sender still holds its context");
    CHECK(DirectGate_Transfer_Send(&tx, g_sSource, sink_send, NULL) == XSTDOK && g_nCtxLive == 1,
        "the next send on the same transfer replaces the context instead of adding one");
    DirectGate_Transfer_Destroy(&tx);
    CHECK(g_nCtxLive == 0, "the replacing send gives its context back too");
    DirectGate_Transfer_Destroy(&rx);
    unlink(g_sDest);

    /* A receive whose destination cannot be opened takes no context at all */
    reset_evp();
    DirectGate_Transfer_Init(&tx);
    DirectGate_Transfer_Init(&rx);
    memset(&link, 0, sizeof(link));
    link.pRx = &rx;
    char sKeep[sizeof(g_sDest)];
    xstrncpy(sKeep, sizeof(sKeep), g_sDest);
    int nDestLen = snprintf(g_sDest, sizeof(g_sDest), "%s.missing/dest.bin", sKeep);
    CHECK(nDestLen > 0 && (size_t)nDestLen < sizeof(g_sDest), "a destination under a missing directory is named");
    run_transfer(&tx, &link);
    CHECK(link.nStarts == 1 && link.nRefused == 1 && rx.eState == XTRANSFER_STATE_ERROR,
        "a destination that cannot be opened refuses the start");
    CHECK(g_nCtxLive == 1, "the refused receiver takes no context, only the sender it stopped holds one");
    xstrncpy(g_sDest, sizeof(g_sDest), sKeep);
    DirectGate_Transfer_Destroy(&tx);
    DirectGate_Transfer_Destroy(&rx);
    CHECK(g_nCtxLive == 0, "destroying the stopped sender gives its context back");
    return 0;
}
#endif

int main(void)
{
    char sRoot[] = "/tmp/directgate_transfer_digest.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "a scratch directory is created");
    snprintf(g_sSource, sizeof(g_sSource), "%s/source.bin", sRoot);
    snprintf(g_sDest, sizeof(g_sDest), "%s/dest.bin", sRoot);

    /* Deterministic bytes with no period a block or a chunk lines up with */
    uint32_t nState = 0x2545F491U;
    for (size_t i = 0; i < sizeof(g_content); i++)
    {
        nState ^= nState << 13;
        nState ^= nState >> 17;
        nState ^= nState << 5;
        g_content[i] = (uint8_t)(nState >> 24);
    }

    /* The reference itself: OpenSSL's one-shot and libxutils' agree on the content the transfers use */
    uint8_t refA[SHA256_DIGEST_LENGTH], refB[XSHA256_DIGEST_SIZE];
    SHA256(g_content, sizeof(g_content), refA);
    CHECK(XSHA256_Compute(refB, sizeof(refB), g_content, sizeof(g_content)) == XSTDOK && !memcmp(refA, refB, 32),
        "OpenSSL's and libxutils' SHA-256 agree on the reference content");

    static const size_t sizes[] = {
        0, 1, 2, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 4095, 4096,
        CHUNK - 1U, CHUNK, CHUNK + 1U, 2U * CHUNK, 2U * CHUNK + 55U, MAX_FILE
    };

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
    {
#ifdef DIRECTGATE_TEST_EVP_WRAP
        reset_evp();
#endif
        if (transfer_ok(sizes[i], "the default hash")) return 1;
        if (transfer_tampered(sizes[i])) return 1;
    }

#ifdef DIRECTGATE_TEST_EVP_WRAP
    CHECK(g_nCtxLive == 0, "the size sweep gives back every OpenSSL context it took");
    if (wrap_fallbacks() || wrap_failures() || wrap_lifetimes()) return 1;
    CHECK(g_nCtxLive == 0, "every OpenSSL context the transfers took was given back");
#endif

    unlink(g_sSource);
    unlink(g_sDest);
    CHECK(rmdir(sRoot) == 0, "the scratch directory is left empty");

    puts("transfer_digest_smoke: OK");
    return 0;
}
