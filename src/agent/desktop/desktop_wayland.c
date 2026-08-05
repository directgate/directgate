/*!
 * @file directgate-agent/src/agent/desktop/desktop_wayland.c
 * @brief Wayland frame source: portal grant, PipeWire stream, newest frame.
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

#include "wayland.h"

#ifdef DIRECTGATE_DESKTOP_HAS_WAYLAND

#include "yuv.h"

/* A Wayland source deliberately stops at "here is the newest frame in BGRA".
 * Everything after that - scaling to the encode size, I420 conversion, the
 * hardware or software H.264 encoder, the adaptive bitrate controller, the
 * mailbox the main loop drains - is the same code the X11 path uses. Giving
 * Wayland its own copy of that pipeline would have meant two places to fix
 * every future encoder bug, and only one of them ever being tested. */

struct directgate_wl_source_ {
    directgate_wl_portal_t *pPortal;
    directgate_wl_capture_t *pCapture;

    xthread_t setupThread;
    xbool_t bThreadStarted;

    /* Newest frame, published by the PipeWire thread and consumed by the
     * encoder worker. One slot, not a queue: a frame that has been overtaken
     * is of no use to a live stream, and dropping it is what keeps latency
     * from growing when the encoder falls behind the compositor. */
    xsync_mutex_t frameLock;
    uint8_t *pFrame;
    size_t nFrameSize;
    uint32_t nFrameWidth;
    uint32_t nFrameHeight;
    xbool_t bFrameFresh;

    uint32_t nActiveNode;         /* screen the capture is currently bound to */

    /* The setup thread's result, read by the event loop. Published under this
     * lock and never bare: the loop decides what to dereference from eState,
     * and a plain write of it carries no promise that the portal and capture
     * pointers written just before it are visible yet. One mispredicted store
     * order is a NULL portal on a session that says it is ready. */
    xsync_mutex_t stateLock;
    directgate_wl_state_t eState;
    char sError[512];

    char sTokenPath[XPATH_MAX];
};

/* Both halves of publishing a result, so no caller can do half of it. */
static void DirectGate_WL_SourcePublish(directgate_wl_source_t *pSource,
                                        directgate_wl_state_t eState,
                                        const char *pError)
{
    XSync_Lock(&pSource->stateLock);

    if (xstrused(pError)) xstrncpy(pSource->sError, sizeof(pSource->sError), pError);
    pSource->eState = eState;

    XSync_Unlock(&pSource->stateLock);
}

/* The token that lets a reconnect skip the permission prompt. It is a
 * capability, so it is written only for its owner. Losing it costs one
 * prompt; leaking it would let anything on the machine resume a screen cast
 * that was granted to this agent. */
static void DirectGate_WL_TokenSave(const char *pPath, const char *pToken)
{
    if (!xstrused(pPath) || !xstrused(pToken)) return;

    /* The directory is not guaranteed to exist - an agent that was never
     * paired on this account has no ~/.config/directgate - and open() would
     * simply fail, leaving the permission un-remembered for no visible
     * reason. */
    char sDir[XPATH_MAX];
    xstrncpy(sDir, sizeof(sDir), pPath);

    char *pSlash = strrchr(sDir, '/');
    if (pSlash != NULL)
    {
        *pSlash = '\0';
        XDir_Create(sDir, S_IRWXU);
    }

    int nFd = open(pPath, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (nFd < 0)
    {
        xlogw("Failed to remember the desktop sharing permission: path(%s), error(%s)",
            pPath, strerror(errno));

        return;
    }

    size_t nLength = strlen(pToken);
    if (write(nFd, pToken, nLength) != (ssize_t)nLength)
        xlogw("Failed to write the desktop sharing permission token: path(%s)", pPath);

    close(nFd);
}

/* Throws away a remembered grant that turned out to be unusable, so the next
 * attempt asks instead of failing the same way for ever. */
static void DirectGate_WL_TokenForget(const char *pPath)
{
    if (!xstrused(pPath)) return;
    if (unlink(pPath) == 0 || errno == ENOENT) return;
    xlogw("Failed to forget the stale desktop sharing permission: path(%s), error(%s)", pPath, strerror(errno));
}

static xbool_t DirectGate_WL_TokenLoad(const char *pPath, char *pBuf, size_t nSize)
{
    if (!xstrused(pPath)) return XFALSE;

    int nFd = open(pPath, O_RDONLY);
    if (nFd < 0) return XFALSE;

    ssize_t nRead = read(nFd, pBuf, nSize - 1);
    close(nFd);

    if (nRead <= 0) return XFALSE;
    pBuf[nRead] = '\0';

    /* A trailing newline from a hand-edited file would be sent verbatim and
     * silently rejected by the portal. */
    while (nRead > 0 && (pBuf[nRead - 1] == '\n' || pBuf[nRead - 1] == '\r'))
        pBuf[--nRead] = '\0';

    return pBuf[0] != '\0';
}

static void DirectGate_WL_OnFrame(void *pUserCtx, const directgate_wl_frame_t *pFrame)
{
    directgate_wl_source_t *pSource = (directgate_wl_source_t*)pUserCtx;
    size_t nNeeded = (size_t)pFrame->nWidth * pFrame->nHeight * 4U;

    XSync_Lock(&pSource->frameLock);

    if (pSource->nFrameSize < nNeeded)
    {
        uint8_t *pGrown = (uint8_t*)realloc(pSource->pFrame, nNeeded);
        if (pGrown == NULL)
        {
            XSync_Unlock(&pSource->frameLock);
            return;
        }

        pSource->pFrame = pGrown;
        pSource->nFrameSize = nNeeded;
    }

    /* Copied out of the PipeWire buffer rather than referenced: the buffer is
     * recycled the moment this returns, and the encoder runs on another
     * thread entirely. Row by row because the source stride is almost never
     * the packed width. */
    for (uint32_t y = 0; y < pFrame->nHeight; y++)
    {
        memcpy(pSource->pFrame + (size_t)y * pFrame->nWidth * 4U,
               pFrame->pPixels + (size_t)y * pFrame->nStride,
               (size_t)pFrame->nWidth * 4U);
    }

    pSource->nFrameWidth = pFrame->nWidth;
    pSource->nFrameHeight = pFrame->nHeight;
    pSource->bFrameFresh = XTRUE;

    XSync_Unlock(&pSource->frameLock);
}

static void* DirectGate_WL_SetupWorker(void *pCtx)
{
    directgate_wl_source_t *pSource = (directgate_wl_source_t*)pCtx;
    char sError[512] = { 0 };
    char sOldToken[512] = { 0 };
    char sNewToken[512] = { 0 };

    xbool_t bHaveToken = DirectGate_WL_TokenLoad(pSource->sTokenPath, sOldToken, sizeof(sOldToken));

    /* Say where this lives. A stale grant is the one thing that makes the
     * portal skip its dialog, so when the shared screens are not the ones
     * someone expects, this file is the answer - and hunting for it should
     * not be part of the job. */
    xlogi("Wayland sharing permission: file(%s), remembered(%s)",
        xstrused(pSource->sTokenPath) ? pSource->sTokenPath : "none",
        bHaveToken ? "yes - delete this file to be asked again" : "no");

    xbool_t bDeclined = XFALSE;
    pSource->pPortal = DirectGate_WL_PortalOpen(bHaveToken ? sOldToken : NULL,
        sNewToken, sizeof(sNewToken), &bDeclined, sError, sizeof(sError));

    /* A remembered grant that cannot be restored is worse than having none:
     * the portal answers the restore with no stream at all, and because the
     * token stays on disk every later connection fails the same way - closing
     * a laptop lid was enough to lock the agent out of the monitor that was
     * still there. The screens it was granted for are gone, so the grant is
     * dropped and the prompt is put back up for the screens there are now.
     * Not after a refusal, though: answering "no" must not summon another. */
    if (pSource->pPortal == NULL && bHaveToken && !bDeclined)
    {
        xlogw("The remembered desktop sharing permission no longer works, asking again: reason(%s)", sError);
        DirectGate_WL_TokenForget(pSource->sTokenPath);

        sError[0] = '\0';
        sNewToken[0] = '\0';
        pSource->pPortal = DirectGate_WL_PortalOpen(NULL, sNewToken, sizeof(sNewToken), &bDeclined, sError, sizeof(sError));
    }

    if (pSource->pPortal == NULL)
    {
        DirectGate_WL_SourcePublish(pSource, DIRECTGATE_WL_FAILED, sError);
        return NULL;
    }

    /* The portal hands back a fresh token every time it accepts one, and the
     * one just used is spent - so this write is not an optimisation, it is
     * what keeps the next connection from prompting. A grant that came back
     * with no token at all cannot be resumed by anyone, and keeping the old
     * file would only make every future attempt present something the portal
     * has already refused. */
    if (xstrused(sNewToken))
    {
        DirectGate_WL_TokenSave(pSource->sTokenPath, sNewToken);
        xlogi("Wayland sharing permission stored; the next connection should not prompt");
    }
    else if (bHaveToken)
    {
        xlogw("The desktop portal granted sharing without a permission to remember; "
              "the stored one is dropped and the next connection will ask again");

        DirectGate_WL_TokenForget(pSource->sTokenPath);
    }

    int nFd = DirectGate_WL_PortalOpenPipeWire(pSource->pPortal, sError, sizeof(sError));
    if (nFd < 0)
    {
        DirectGate_WL_SourcePublish(pSource, DIRECTGATE_WL_FAILED, sError);
        return NULL;
    }

    pSource->pCapture = DirectGate_WL_CaptureStart(nFd,
        DirectGate_WL_PortalNodeId(pSource->pPortal),
        DirectGate_WL_OnFrame, pSource, sError, sizeof(sError));

    if (pSource->pCapture == NULL)
    {
        DirectGate_WL_SourcePublish(pSource, DIRECTGATE_WL_FAILED, sError);
        return NULL;
    }

    /* Nothing about the stream is usable until a format exists, including its
     * size, so readiness is reported from here and not from the connect. */
    if (DirectGate_WL_CaptureWaitFormat(pSource->pCapture, 4000) != XSTDOK)
    {
        DirectGate_WL_SourcePublish(pSource, DIRECTGATE_WL_FAILED,
            "The desktop stream never agreed on a video format.");

        return NULL;
    }

    pSource->nActiveNode = DirectGate_WL_PortalNodeId(pSource->pPortal);

    /* Last, and under the lock: everything above has to be visible to the
     * loop before it is told it may look. */
    DirectGate_WL_SourcePublish(pSource, DIRECTGATE_WL_READY, NULL);
    return NULL;
}

directgate_wl_source_t* DirectGate_WL_SourceCreate(const char *pTokenPath)
{
    directgate_wl_source_t *pSource = (directgate_wl_source_t*)calloc(1, sizeof(*pSource));
    XCHECK_NL((pSource != NULL), NULL);

    pSource->eState = DIRECTGATE_WL_PENDING;
    if (xstrused(pTokenPath))
        xstrncpy(pSource->sTokenPath, sizeof(pSource->sTokenPath), pTokenPath);

    if (XSync_InitAdv(&pSource->frameLock, XFALSE) < 0)
    {
        free(pSource);
        return NULL;
    }

    if (XSync_InitAdv(&pSource->stateLock, XFALSE) < 0)
    {
        XSync_Destroy(&pSource->frameLock);
        free(pSource);
        return NULL;
    }

    /* Started last: the thread publishes into this struct from its first
     * line, so everything it touches has to exist before it runs. */
    if (XThread_Create(&pSource->setupThread, DirectGate_WL_SetupWorker, pSource, XFALSE) < 0)
    {
        XSync_Destroy(&pSource->stateLock);
        XSync_Destroy(&pSource->frameLock);
        free(pSource);
        return NULL;
    }

    pSource->bThreadStarted = XTRUE;
    return pSource;
}

directgate_wl_state_t DirectGate_WL_SourceState(directgate_wl_source_t *pSource)
{
    XCHECK_NL((pSource != NULL), DIRECTGATE_WL_FAILED);

    XSync_Lock(&pSource->stateLock);
    directgate_wl_state_t eState = pSource->eState;
    XSync_Unlock(&pSource->stateLock);

    return eState;
}

const char* DirectGate_WL_SourceError(directgate_wl_source_t *pSource)
{
    XCHECK_NL((pSource != NULL), "Wayland desktop capture failed.");

    /* Taken and released rather than read bare: the string was written by the
     * setup thread, and the caller only ever asks once the state it published
     * with it says there is something to read. The buffer itself outlives
     * every caller, so handing back a pointer into it is safe. */
    XSync_Lock(&pSource->stateLock);
    xbool_t bHaveError = (pSource->sError[0] != '\0') ? XTRUE : XFALSE;
    XSync_Unlock(&pSource->stateLock);

    return bHaveError ? pSource->sError : "Wayland desktop capture failed.";
}

xbool_t DirectGate_WL_SourceSize(directgate_wl_source_t *pSource, uint32_t *pWidth, uint32_t *pHeight)
{
    XCHECK_NL((pSource != NULL && pSource->pCapture != NULL), XFALSE);
    return DirectGate_WL_CaptureSize(pSource->pCapture, pWidth, pHeight);
}

uint32_t DirectGate_WL_SourceActiveNode(directgate_wl_source_t *pSource)
{
    XCHECK_NL((pSource != NULL), XSTDNON);
    return pSource->nActiveNode;
}

xbool_t DirectGate_WL_SourceHasInput(directgate_wl_source_t *pSource)
{
    XCHECK_NL((pSource != NULL), XFALSE);
    return DirectGate_WL_PortalHasInput(pSource->pPortal);
}

xbool_t DirectGate_WL_SourceLost(directgate_wl_source_t *pSource, char *pErrBuf, size_t nErrSize)
{
    XCHECK_NL((pSource != NULL && pSource->pCapture != NULL), XFALSE);

    /* Only a live source can be lost. While the setup thread is still working
     * the capture belongs to it, and its own result says what happened. */
    if (DirectGate_WL_SourceState(pSource) != DIRECTGATE_WL_READY) return XFALSE;

    return DirectGate_WL_CaptureLost(pSource->pCapture, pErrBuf, nErrSize);
}

uint32_t DirectGate_WL_SourceScreenCount(directgate_wl_source_t *pSource)
{
    XCHECK_NL((pSource != NULL), XSTDNON);
    return DirectGate_WL_PortalStreamCount(pSource->pPortal);
}

const directgate_wl_stream_t* DirectGate_WL_SourceScreen(directgate_wl_source_t *pSource, uint32_t nIndex)
{
    XCHECK_NL((pSource != NULL), NULL);
    return DirectGate_WL_PortalStream(pSource->pPortal, nIndex);
}

int DirectGate_WL_SourceSelect(directgate_wl_source_t *pSource, uint32_t nNodeId)
{
    XCHECK((pSource != NULL && pSource->pPortal != NULL), XSTDERR);
    if (nNodeId == 0 || nNodeId == pSource->nActiveNode) return XSTDOK;

    /* Only the PipeWire stream is rebuilt. The portal grant covers every
     * screen the person allowed, so moving between them is not a permission
     * question and must never put a prompt back on their screen. */
    char sError[256] = { 0 };
    int nFd = DirectGate_WL_PortalOpenPipeWire(pSource->pPortal, sError, sizeof(sError));

    if (nFd < 0)
    {
        xlogw("Failed to reopen PipeWire for another screen: reason(%s)", sError);
        return XSTDERR;
    }

    directgate_wl_capture_t *pCapture = DirectGate_WL_CaptureStart(nFd, nNodeId,
        DirectGate_WL_OnFrame, pSource, sError, sizeof(sError));

    if (pCapture == NULL)
    {
        xlogw("Failed to switch to screen node %u: reason(%s)", nNodeId, sError);
        return XSTDERR;
    }

    if (DirectGate_WL_CaptureWaitFormat(pCapture, 4000) != XSTDOK)
    {
        DirectGate_WL_CaptureStop(pCapture);
        xlogw("Screen node %u never agreed on a video format", nNodeId);
        return XSTDERR;
    }

    /* The old capture goes only once the new one is proven, so a screen that
     * cannot be opened leaves the session on the one that works. */
    directgate_wl_capture_t *pOld = pSource->pCapture;

    XSync_Lock(&pSource->frameLock);
    pSource->pCapture = pCapture;
    pSource->nActiveNode = nNodeId;
    pSource->bFrameFresh = XFALSE;
    XSync_Unlock(&pSource->frameLock);

    if (pOld != NULL) DirectGate_WL_CaptureStop(pOld);

    xlogi("Wayland capture switched screen: node(%u)", nNodeId);
    return XSTDOK;
}

directgate_wl_portal_t* DirectGate_WL_SourcePortal(directgate_wl_source_t *pSource)
{
    XCHECK_NL((pSource != NULL), NULL);    
    return pSource->pPortal;
}

int DirectGate_WL_SourceTakeFrame(directgate_wl_source_t *pSource, uint8_t *pDst,
                                  uint32_t nWidth, uint32_t nHeight)
{
    XCHECK((pSource != NULL && pDst != NULL), XSTDERR);
    XCHECK((nWidth > 0 && nHeight > 0), XSTDERR);

    XSync_Lock(&pSource->frameLock);

    if (!pSource->bFrameFresh || pSource->pFrame == NULL)
    {
        XSync_Unlock(&pSource->frameLock);
        return XSTDNON;
    }

    if (pSource->nFrameWidth == nWidth && pSource->nFrameHeight == nHeight)
    {
        memcpy(pDst, pSource->pFrame, (size_t)nWidth * nHeight * 4U);
    }
    else
    {
        DirectGate_YUV_ScaleBGRA(pDst, nWidth, nHeight, pSource->pFrame,
            pSource->nFrameWidth, pSource->nFrameHeight,
            (size_t)pSource->nFrameWidth * 4U);
    }

    pSource->bFrameFresh = XFALSE;
    XSync_Unlock(&pSource->frameLock);

    return XSTDOK;
}

void DirectGate_WL_SourceDestroy(directgate_wl_source_t *pSource)
{
    XCHECK_VOID_NL((pSource != NULL));

    /* The worker can be sitting in the portal's two-minute grant wait, so it
     * is joined rather than abandoned: it writes into this struct, and there
     * is no safe way to free memory a live thread still owns. */
    if (pSource->bThreadStarted) XThread_Join(&pSource->setupThread);
    if (pSource->pCapture != NULL) DirectGate_WL_CaptureStop(pSource->pCapture);
    if (pSource->pPortal != NULL) DirectGate_WL_PortalClose(pSource->pPortal);

    XSync_Destroy(&pSource->stateLock);
    XSync_Destroy(&pSource->frameLock);
    free(pSource->pFrame);
    free(pSource);
}

#endif /* DIRECTGATE_DESKTOP_HAS_WAYLAND */
