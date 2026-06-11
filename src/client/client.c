/*!
 * @file directgate-agent/src/client/client.c
 * @brief Client-side WS terminal frontend.
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

#include "includes.h"
#include "version.h"
#include "protocol.h"
#include "transfer.h"
#include "config.h"
#include "relay.h"
#include "webrtc.h"
#include "e2e.h"
#include "srp.h"

static xbool_t g_bFinish = XFALSE;

#ifndef _WIN32
static volatile sig_atomic_t g_bWinch = 0;
#endif

#ifdef _WIN32
/* Console fds for the CRT write()/read() compatibility calls */
#ifndef STDIN_FILENO
#define STDIN_FILENO  0
#endif
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif

/*
    WSAPoll (the Windows event engine in libxutils) handles only sockets,
    so console input cannot sit in the event loop directly. A pump thread
    blocks on the console and forwards every chunk into a private socket
    pair; the event loop polls the other end like a regular socket.
    [0]=event loop (non-blocking), [1]=pump thread (blocking).
*/
static XSOCKET g_nStdinBridge[2] = { XSOCK_INVALID, XSOCK_INVALID };

typedef struct directgate_client_io_ {
    DWORD nSavedInMode;
    DWORD nSavedOutMode;
    xbool_t bSavedIn;
    xbool_t bSavedOut;
    xbool_t bRaw;
} directgate_client_io_t;
#else
typedef struct directgate_client_io_ {
    struct termios saved;
    xbool_t bRaw;
} directgate_client_io_t;
#endif

typedef struct directgate_client_ctx_ {
    const directgate_cfg_t *pCfg;
    struct winsize lastSize;

    directgate_webrtc_t webrtc;
    directgate_transfer_t transfer;
    directgate_srp_client_t srp;
    directgate_client_io_t io;
    directgate_e2e_t e2e;

    xapi_session_t *pPipeSession;
    xapi_session_t *pWsSession;
    uint32_t nSessionId;

    xbool_t bRoleSent;
    xbool_t bLogMuted;
    xbool_t bHaveSize;
    xbool_t bAuthDone;
    xbool_t bInputBlocked;
} directgate_ctx_t;

static int DirectGate_Client_SendAuthHello(directgate_ctx_t *pCli);
static int DirectGate_Client_SendResize(directgate_ctx_t *pCli);
static int DirectGate_Client_SendCmdStart(directgate_ctx_t *pCli, const char *pMode);
static void DirectGate_Client_WebRTC_DataCb(const uint8_t *pData, size_t nLen, void *pCtx);
static int DirectGate_Client_HandleMessage(directgate_ctx_t *pCli, const uint8_t *pPayload, size_t nPayload, const char *pTransport);

static void DirectGate_Client_SignalCallback(int sig)
{
#ifndef _WIN32
    if (sig == SIGWINCH)
    {
        g_bWinch = 1;
        return;
    }

    if (sig == SIGPIPE) return;
#endif
    (void)sig;
    g_bFinish = XTRUE;
}

static void DirectGate_Client_CleanseSecret(directgate_cfg_t *pCfg)
{
    XCHECK_VOID_NL((pCfg != NULL));
    OPENSSL_cleanse(pCfg->sSecret, sizeof(pCfg->sSecret));
    pCfg->sSecret[0] = XSTR_NUL;
}

static void DirectGate_Client_CleanseSecretCtx(directgate_ctx_t *pCli)
{
    XCHECK_VOID_NL((pCli != NULL));
    XCHECK_VOID_NL((pCli->pCfg != NULL));
    DirectGate_Client_CleanseSecret((directgate_cfg_t*)pCli->pCfg);
}

static int DirectGate_Client_LogStatus(xapi_ctx_t *pCtx, xapi_session_t *pSession)
{
    int nFD = pSession ? (int)pSession->sock.nFD : XSTDERR;
    const char *pStr = XAPI_GetStatus(pCtx);

    xbool_t nDestroyEvent = pCtx && pCtx->eStatType == XAPI_SELF &&
                            pCtx->nStatus == XAPI_DESTROY ? XTRUE : XFALSE;

    if (nDestroyEvent) xlogn("%s", pStr);
    else xlogn("%s: fd(%d)", pStr, nFD);
    return XAPI_CONTINUE;
}

static int DirectGate_Client_LogError(xapi_ctx_t *pCtx, xapi_session_t *pSession)
{
    int nFD = pSession ? (int)pSession->sock.nFD : XSTDERR;
    const char *pStr = XAPI_GetStatus(pCtx);
    xloge("%s: fd(%d), errno(%d)", pStr, nFD, errno);
    return XAPI_CONTINUE;
}

void DirectGate_Client_Init(directgate_ctx_t *pClient)
{
    memset(pClient, 0, sizeof(directgate_ctx_t));
    pClient->io.bRaw = XFALSE;
    pClient->nSessionId = 0;

    DirectGate_E2E_Init(&pClient->e2e);
    DirectGate_SRP_ClientCleanse(&pClient->srp);

    if (!DirectGate_SRP_ClientInit(&pClient->srp))
        xloge("Failed to initialize SRP client context");

    DirectGate_WebRTC_Init(&pClient->webrtc);
    DirectGate_Transfer_Init(&pClient->transfer);
}

#ifdef _WIN32
static DWORD WINAPI DirectGate_Client_StdinPump(LPVOID pArg)
{
    (void)pArg;
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    char sBuffer[XSTR_BIG];
    DWORD nRead = 0;

    while (ReadFile(hStdin, sBuffer, sizeof(sBuffer), &nRead, NULL) && nRead > 0)
    {
        size_t nSent = 0;
        while (nSent < (size_t)nRead)
        {
            int nRet = send(g_nStdinBridge[1], sBuffer + nSent, (int)(nRead - nSent), 0);
            if (nRet <= 0) return 0;
            nSent += (size_t)nRet;
        }
    }

    /* Console EOF (Ctrl-Z + Enter or closed input): recv reports 0 */
    shutdown(g_nStdinBridge[1], SD_SEND);
    return 0;
}

static XSTATUS DirectGate_Client_EnableRawIO(directgate_client_io_t *pIO)
{
    XCHECK((pIO != NULL), XSTDINV);
    if (pIO->bRaw) return XSTDOK;

    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

    if (!GetConsoleMode(hStdin, &pIO->nSavedInMode))
    {
        xloge("Failed to read console input mode: error(%lu)", GetLastError());
        return XSTDERR;
    }
    pIO->bSavedIn = XTRUE;

    if (!GetConsoleMode(hStdout, &pIO->nSavedOutMode))
    {
        xloge("Failed to read console output mode: error(%lu)", GetLastError());
        return XSTDERR;
    }
    pIO->bSavedOut = XTRUE;

    /*
        Raw mode, SSH-like: no line buffering, no local echo and no local
        Ctrl-C handling - VT input mode turns every key (including arrows
        and Ctrl sequences) into bytes the remote PTY understands.
    */
    if (!SetConsoleMode(hStdin, ENABLE_VIRTUAL_TERMINAL_INPUT))
    {
        xloge("Failed to set console raw input mode: error(%lu)", GetLastError());
        return XSTDERR;
    }

    /* VT output processing renders the remote escape sequences */
    DWORD nOutMode = pIO->nSavedOutMode |
        ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING;

    if (!SetConsoleMode(hStdout, nOutMode))
    {
        SetConsoleMode(hStdin, pIO->nSavedInMode);
        xloge("Failed to set console VT output mode: error(%lu)", GetLastError());
        return XSTDERR;
    }

    /* The remote PTY speaks UTF-8 in both directions */
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);

    pIO->bRaw = XTRUE;
    return XSTDOK;
}

static void DirectGate_Client_RestoreIO(directgate_client_io_t *pIO)
{
    XCHECK_VOID((pIO != NULL));
    XCHECK_VOID_NL(pIO->bRaw);

    if (pIO->bSavedIn) SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), pIO->nSavedInMode);
    if (pIO->bSavedOut) SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), pIO->nSavedOutMode);
    pIO->bRaw = XFALSE;
}
#else
static XSTATUS DirectGate_Client_SetNonBlock(int nFd, xbool_t bNonblock)
{
    int nFlags = fcntl(nFd, F_GETFL, 0);
    XCHECK((nFlags >= 0), xthrow("Failed to get fd flags: errno(%d)", errno));

    if (bNonblock) nFlags |= O_NONBLOCK;
    else nFlags &= ~O_NONBLOCK;

    int nStatus = fcntl(nFd, F_SETFL, nFlags);
    XCHECK((nStatus >= 0), xthrow("Failed to set fd flags: errno(%d)", errno));

    return XSTDOK;
}

static XSTATUS DirectGate_Client_EnableRawIO(directgate_client_io_t *pIO)
{
    XCHECK((pIO != NULL), XSTDINV);
    if (pIO->bRaw) return XSTDOK;

    if (tcgetattr(STDIN_FILENO, &pIO->saved) != 0)
    {
        xloge("Failed to read tty attrs: errno(%d)", errno);
        return XSTDERR;
    }

    struct termios raw = pIO->saved;
    cfmakeraw(&raw);

    /* Do NOT set ISIG: forward Ctrl-C, Ctrl-Z, etc. to remote shell
       (same behavior as SSH). The client exits when the remote closes. */
    /* Keep output post-processing for clean prompt rendering. */
#ifdef OPOST
    raw.c_oflag |= OPOST;
#endif
#ifdef ONLCR
    raw.c_oflag |= ONLCR;
#endif

    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0)
    {
        xloge("Failed to set tty raw mode: errno(%d)", errno);
        return XSTDERR;
    }

    if (DirectGate_Client_SetNonBlock(STDIN_FILENO, XTRUE) < 0)
    {
        xloge("Failed to set stdin non-blocking: errno(%d)", errno);
        return XSTDERR;
    }

    pIO->bRaw = XTRUE;
    return XSTDOK;
}

static void DirectGate_Client_RestoreIO(directgate_client_io_t *pIO)
{
    XCHECK_VOID((pIO != NULL));
    XCHECK_VOID_NL(pIO->bRaw);
    tcsetattr(STDIN_FILENO, TCSANOW, &pIO->saved);
    DirectGate_Client_SetNonBlock(STDIN_FILENO, XFALSE);
    pIO->bRaw = XFALSE;
}
#endif /* _WIN32 */

static ssize_t DirectGate_Client_WriteAll(int nFd, const void *pBuff, size_t nSize)
{
    XCHECK((pBuff != NULL), XSTDERR);
    XCHECK((nSize > 0), XSTDNON);

    const uint8_t *pData = (const uint8_t*)pBuff;
    size_t nLeft = nSize;

    while (nLeft)
    {
        ssize_t nWritten = write(nFd, pData, nLeft);
        if (nWritten > 0)
        {
            pData += (size_t)nWritten;
            nLeft -= (size_t)nWritten;
            continue;
        }

        if (nWritten < 0)
        {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN ||
                errno == EWOULDBLOCK)
                return (ssize_t)(nSize - nLeft);
        }

        return XSTDERR;
    }

    return (ssize_t)nSize;
}

static int DirectGate_Client_SendFrame(xapi_session_t *pSession, const uint8_t *pPayload,
                                       size_t nLength, xws_frame_type_t eType)
{
    xws_frame_t frame;
    xws_status_t status;

    status = XWebFrame_Create(&frame, pPayload, nLength, eType, XTRUE, XTRUE);
    if (status != XWS_ERR_NONE)
    {
        xloge("Failed to create WS frame: %s", XWebSock_GetStatusStr(status));
        return XAPI_DISCONNECT;
    }

    if (XAPI_PutTxBuff(pSession, &frame.buffer) < 0)
    {
        xloge("Failed to put data to tx buffer: errno(%d)", errno);
        XWebFrame_Clear(&frame);
        return XAPI_DISCONNECT;
    }

    XWebFrame_Clear(&frame);
    return XAPI_EnableEvent(pSession, XPOLLOUT);
}

static int DirectGate_Client_SendPong(xapi_session_t *pSession)
{
    xlogd("Sending WS PONG: fd(%d)", (int)pSession->sock.nFD);
    return DirectGate_Client_SendFrame(pSession, NULL, 0, XWS_PONG);
}

static int DirectGate_Client_SendMsg(directgate_ctx_t *pCli, xjson_obj_t *pHeader,
                                     const uint8_t *pPayload, size_t nLen)
{
    XCHECK((pCli != NULL), XAPI_DISCONNECT);
    XCHECK((pHeader != NULL), XAPI_DISCONNECT);

    /* Add packet counter for authenticated sessions */
    if (pCli->bAuthDone && DirectGate_E2E_IsInitialized(&pCli->e2e))
        XJSON_AddU32(pHeader, "cc", ++pCli->e2e.nTxPacketId);

    xbyte_buffer_t msg;
    XByteBuffer_Init(&msg, XSTDNON, XFALSE);

    if (!DirectGate_Proto_Build(&msg, pHeader, pPayload, nLen, XFALSE))
    {
        XByteBuffer_Clear(&msg);
        return XAPI_DISCONNECT;
    }

    if (pCli->bAuthDone && DirectGate_E2E_IsInitialized(&pCli->e2e))
    {
        if (!DirectGate_Proto_EncryptPackage(&msg, &pCli->e2e, pCli->nSessionId))
        {
            xloge("Failed to encrypt message");
            XByteBuffer_Clear(&msg);
            return XAPI_DISCONNECT;
        }
    }

    int nStatus;
    if (DirectGate_WebRTC_IsConnected(&pCli->webrtc))
    {
        nStatus = DirectGate_WebRTC_Send(&pCli->webrtc, msg.pData, msg.nUsed);
        nStatus = (nStatus == XSTDOK) ? XAPI_CONTINUE : XAPI_DISCONNECT;
    }
    else
    {
        XCHECK_CALL((pCli->pWsSession != NULL), XByteBuffer_Clear, &msg, XAPI_DISCONNECT);
        nStatus = DirectGate_Client_SendFrame(pCli->pWsSession, msg.pData, msg.nUsed, XWS_BINARY);
    }

    XByteBuffer_Clear(&msg);
    return nStatus;
}

/* File transfer send callback: header comes from transfer.c, we handle cc/build/encrypt/route */
static int DirectGate_Client_Transfer_SendCb(xjson_obj_t *pHeader, const uint8_t *pPayload,
                                             size_t nLen, void *pCtx)
{
    directgate_ctx_t *pCli = (directgate_ctx_t*)pCtx;
    XCHECK((pCli != NULL), XSTDERR);
    XCHECK((pHeader != NULL), XSTDERR);

    int nStatus = DirectGate_Client_SendMsg(pCli, pHeader, pPayload, nLen);
    return (nStatus >= 0) ? XSTDOK : XSTDERR;
}

/* WebRTC signaling callback: parse enqueued JSON string and relay via unified send */
static void DirectGate_Client_WebRTC_SignalCb(const char *pJson, size_t nLen, void *pCtx)
{
    directgate_ctx_t *pCli = (directgate_ctx_t*)pCtx;
    XCHECK_VOID((pCli != NULL));
    XCHECK_VOID((pJson != NULL));
    XCHECK_VOID((nLen > 0));

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, pJson, nLen))
    {
        xloge("RTC: Failed to parse signaling JSON");
        return;
    }

    DirectGate_Client_SendMsg(pCli, json.pRootObj, NULL, 0);
    XJSON_Destroy(&json);
}

static xbool_t DirectGate_Client_RequiresEncryption(directgate_ctx_t *pCli, const directgate_pkg_t *pPkg)
{
    XCHECK((pCli != NULL), XFALSE);
    XCHECK((pPkg != NULL), XFALSE);
    XCHECK_NL((pCli->bAuthDone), XFALSE);
    XCHECK_NL((pPkg->header.nSessionId != 0), XFALSE);

    return (pPkg->header.eType == DIRECTGATE_PKG_DATA ||
            pPkg->header.eType == DIRECTGATE_PKG_FILE ||
            pPkg->header.eType == DIRECTGATE_PKG_MANAGER ||
            pPkg->header.eType == DIRECTGATE_PKG_RESIZE ||
            pPkg->header.eType == DIRECTGATE_PKG_WEBRTC ||
            pPkg->header.eType == DIRECTGATE_PKG_ADMIN);
}

static int DirectGate_Client_HandleAuthMsg(directgate_ctx_t *pCli, directgate_pkg_t *pMsg)
{
    directgate_pkg_auth_t *pAuth = (directgate_pkg_auth_t*)pMsg->pPackage;
    const directgate_cfg_t *pCfg = pCli != NULL ? pCli->pCfg : NULL;

    if (pCli == NULL || pCfg == NULL || pAuth == NULL)
    {
        xloge("Invalid auth message or client context");
        return XAPI_DISCONNECT;
    }

    if (!xstrused(pCfg->sDeviceId) || !xstrused(pCfg->sSecret))
    {
        xloge("SRP: Auth is not configured");
        return XAPI_DISCONNECT;
    }

    if (xstrused(pAuth->pAction) && xstrcmp(pAuth->pAction, "challenge"))
    {
        if (!xstrused(pAuth->pSalt) || !xstrused(pAuth->pB) || !xstrused(pAuth->pNonce))
        {
            xloge("SRP: Auth challenge missing fields");
            return XAPI_DISCONNECT;
        }

        size_t nNonceLen = 0;
        if (!DirectGate_SRP_HexToBytes(pAuth->pNonce,
            pCli->srp.agentNonce, sizeof(pCli->srp.agentNonce),
            &nNonceLen) || nNonceLen != DIRECTGATE_SRP_NONCE_SIZE)
        {
            xloge("SRP: Invalid agent nonce");
            return XAPI_DISCONNECT;
        }

        char sM1Hex[128];
        if (!DirectGate_SRP_ClientComputeKey(&pCli->srp, pCfg->sDeviceId, pCfg->sSecret,
                pAuth->pSalt, pAuth->pB, pAuth->nSuite, sM1Hex, sizeof(sM1Hex)))
        {
            xloge("SRP: Failed to compute proof");
            return XAPI_DISCONNECT;
        }

        xjson_obj_t *pProof = DirectGate_Proto_BuildAuthProof(sM1Hex, pCli->nSessionId);
        XCHECK((pProof != NULL), XAPI_DISCONNECT);

        int nSendStatus = DirectGate_Client_SendMsg(pCli, pProof, NULL, 0);
        xlogi("SRP: Auth proof sent");

        XJSON_FreeObject(pProof);
        return nSendStatus;
    }

    if (xstrused(pAuth->pAction) && xstrcmp(pAuth->pAction, "result") &&
        xstrused(pAuth->pStatus) && xstrcmp(pAuth->pStatus, "ok"))
    {
        if (!xstrused(pAuth->pM2) || !DirectGate_SRP_ClientVerifyM2(&pCli->srp, NULL, pAuth->pM2))
        {
            xloge("SRP: server proof verification failed");
            DirectGate_Client_CleanseSecretCtx(pCli);
            return XAPI_DISCONNECT;
        }

        if (!DirectGate_E2E_DeriveFromSRP(&pCli->e2e, pCli->srp.K, sizeof(pCli->srp.K),
            pCli->srp.agentNonce, pCli->srp.nonce, DIRECTGATE_SRP_NONCE_SIZE, pCfg->sDeviceId, XFALSE))
        {
            xloge("SRP: Failed to derive E2E keys from session key");
            return XAPI_DISCONNECT;
        }

        xlogn("SRP: Authentication successful, E2E encryption enabled");
        DirectGate_Client_CleanseSecretCtx(pCli);
        pCli->bAuthDone = XTRUE;

        if (DirectGate_Client_SendCmdStart(pCli, "terminal") < 0)
            return XAPI_DISCONNECT;

        DirectGate_Client_SendResize(pCli);

        pCli->webrtc.signalCb = DirectGate_Client_WebRTC_SignalCb;
        pCli->webrtc.pSignalCtx = pCli;
        pCli->webrtc.dataCb = DirectGate_Client_WebRTC_DataCb;
        pCli->webrtc.pDataCtx = pCli;

        if (pCli->pCfg != NULL && pCli->pCfg->nIceSrvCount > 0)
            DirectGate_WebRTC_SetIceServers(&pCli->webrtc, pCli->pCfg->sIceServers, pCli->pCfg->nIceSrvCount);

        if (DirectGate_WebRTC_CreateOffer(&pCli->webrtc) < 0)
            xlogw("RTC: Offer failed, continuing with WebSocket relay");
        else
            xlogn("RTC: P2P offer sent, waiting for answer");

        return XAPI_CONTINUE;
    }

    if (xstrused(pAuth->pStatus) && xstrcmp(pAuth->pStatus, "failed"))
    {
        xloge("Authentication failed: %s", xstrused(pAuth->pReason) ? pAuth->pReason : "unknown");
        DirectGate_Client_CleanseSecretCtx(pCli);
        return XAPI_DISCONNECT;
    }

    if (xstrused(pAuth->pStatus) && xstrcmp(pAuth->pStatus, "error"))
    {
        xloge("Authentication error: %s", xstrused(pAuth->pReason) ? pAuth->pReason : "unknown");
        DirectGate_Client_CleanseSecretCtx(pCli);
        return XAPI_DISCONNECT;
    }

    return XAPI_CONTINUE;
}

static int DirectGate_Client_HandleCmdMsg(directgate_ctx_t *pCli, directgate_pkg_t *pMsg)
{
    directgate_pkg_cmd_t *pCmd = (directgate_pkg_cmd_t*)pMsg->pPackage;

    if (pCli == NULL || pCmd == NULL || !xstrused(pCmd->pAction))
    {
        xloge("Invalid command message or client context");
        return XAPI_DISCONNECT;
    }

    if (xstrcmp(pCmd->pAction, "start") && !pCli->bAuthDone)
    {
        if (pMsg->header.nSessionId) pCli->nSessionId = pMsg->header.nSessionId;
        return DirectGate_Client_SendAuthHello(pCli);
    }

    return XAPI_CONTINUE;
}

static int DirectGate_Client_HandleWebRTCMsg(directgate_ctx_t *pCli, directgate_pkg_t *pMsg)
{
    directgate_pkg_webrtc_t *pRtc = (directgate_pkg_webrtc_t*)pMsg->pPackage;

    if (pCli == NULL || pRtc == NULL || !xstrused(pRtc->pAction))
    {
        xloge("Invalid WebRTC message or client context");
        return XAPI_DISCONNECT;
    }

    if (xstrcmp(pRtc->pAction, "answer"))
    {
        xjson_obj_t *pHdrObj = pMsg->jsonHeader.pRootObj;
        const char *pSdp = NULL;

        if (pHdrObj != NULL)
        {
            xjson_obj_t *pSdpObj = XJSON_GetObject(pHdrObj, "sdp");
            if (pSdpObj != NULL) pSdp = XJSON_GetString(pSdpObj);
        }

        if (xstrused(pSdp))
        {
            xlogn("RTC: Received answer from agent");
            xlogd("RTC: Answer SDP: %s", pSdp);
            DirectGate_WebRTC_HandleAnswer(&pCli->webrtc, pSdp);
        }
        else xloge("RTC: Answer does not contain SDP");
    }
    else if (xstrcmp(pRtc->pAction, "ice"))
    {
        xjson_obj_t *pHdrObj = pMsg->jsonHeader.pRootObj;
        const char *pCandidate = NULL;
        const char *pMid = NULL;

        if (pHdrObj != NULL)
        {
            xjson_obj_t *pCandObj = XJSON_GetObject(pHdrObj, "candidate");
            if (pCandObj != NULL) pCandidate = XJSON_GetString(pCandObj);

            xjson_obj_t *pMidObj = XJSON_GetObject(pHdrObj, "sdpMid");
            if (pMidObj != NULL) pMid = XJSON_GetString(pMidObj);
        }

        if (xstrused(pCandidate))
            DirectGate_WebRTC_HandleIceCandidate(&pCli->webrtc, pCandidate, pMid);
    }

    return XAPI_CONTINUE;
}

static int DirectGate_Client_HandleFileMsg(directgate_ctx_t *pCli, directgate_pkg_t *pMsg,
                                           const char *pTransport)
{
    directgate_pkg_file_t *pFile = (directgate_pkg_file_t*)pMsg->pPackage;

    if (pCli == NULL || pFile == NULL || !xstrused(pFile->pAction))
    {
        xloge("Invalid file message or client context");
        return XAPI_DISCONNECT;
    }

    directgate_transfer_t *pFT = &pCli->transfer;
    directgate_pkg_transfer_t *pTransfer = &pFile->transfer;

    if (xstrcmp(pFile->pAction, "start"))
        DirectGate_Transfer_HandleStart(pFT, pMsg, ".");
    else if (xstrcmp(pFile->pAction, "chunk"))
        DirectGate_Transfer_HandleChunk(pFT, pMsg);
    else if (xstrcmp(pFile->pAction, "cancel"))
        DirectGate_Transfer_HandleCancel(pFT);
    else if (xstrcmp(pFile->pAction, "end"))
        DirectGate_Transfer_HandleEnd(pFT, pMsg, DirectGate_Client_Transfer_SendCb, pCli);
    else if (xstrcmp(pFile->pAction, "ack"))
        xlogi("%s: file transfer ack, chunk(%u)",
            xstrused(pTransport) ? pTransport : "transport", pTransfer->nChunkIndex);

    return XAPI_CONTINUE;
}

static int DirectGate_Client_HandleStatusMsg(directgate_pkg_t *pMsg, const char *pTransport)
{
    directgate_pkg_status_t *pStatus = (directgate_pkg_status_t*)pMsg->pPackage;
    if (pStatus != NULL && xstrused(pStatus->pStatus) && xstrcmp(pStatus->pStatus, "closed"))
    {
        xlogn("%s: Session closed by agent", xstrused(pTransport) ? pTransport : "transport");
        g_bFinish = XTRUE;
        return XAPI_DISCONNECT;
    }

    return XAPI_CONTINUE;
}

static int DirectGate_Client_HandleDataMsg(directgate_ctx_t *pCli, directgate_pkg_t *pMsg)
{
    directgate_pkg_data_t *pData = (directgate_pkg_data_t*)pMsg->pPackage;

    if (pCli != NULL && !pCli->bLogMuted)
    {
        xlog_screen(XFALSE);
        pCli->bLogMuted = XTRUE;
    }

    if (pData != NULL && pData->pPayload && pData->nPayloadLength)
    {
        if (DirectGate_Client_WriteAll(STDOUT_FILENO, pData->pPayload, pData->nPayloadLength) < 0)
            return XAPI_DISCONNECT;
    }

    return XAPI_CONTINUE;
}

static int DirectGate_Client_HandleKeepaliveMsg(directgate_ctx_t *pCli, directgate_pkg_t *pMsg)
{
    directgate_pkg_keepalive_t *pKA = (directgate_pkg_keepalive_t*)pMsg->pPackage;
    if (pCli != NULL && pKA != NULL && xstrused(pKA->pAction) && xstrcmp(pKA->pAction, "ping"))
    {
        xlogd("Received keepalive ping, sending pong");
        xjson_obj_t *pHeader = DirectGate_Proto_BuildKeepalive("pong", pCli->nSessionId);
        if (pHeader != NULL)
        {
            int nStatus = DirectGate_Client_SendMsg(pCli, pHeader, NULL, 0);
            XJSON_FreeObject(pHeader);
            return nStatus;
        }
    }

    return XAPI_CONTINUE;
}

static int DirectGate_Client_DispatchMessage(directgate_ctx_t *pCli, directgate_pkg_t *pMsg, const char *pTransport)
{
    XCHECK((pCli != NULL), XAPI_DISCONNECT);
    XCHECK((pMsg != NULL), XAPI_DISCONNECT);
    XCHECK((pMsg->pPackage != NULL), XAPI_DISCONNECT);

    switch (pMsg->header.eType)
    {
        case DIRECTGATE_PKG_ERROR:
        {
            directgate_pkg_error_t *pError = (directgate_pkg_error_t*)pMsg->pPackage;
            const char *pReason = (pError != NULL && xstrused(pError->pReason)) ? pError->pReason : "unknown";
            xloge("Received server side error message: %s", pReason);
            return XAPI_CONTINUE;
        }
        case DIRECTGATE_PKG_AUTH:
            return DirectGate_Client_HandleAuthMsg(pCli, pMsg);
        case DIRECTGATE_PKG_CMD:
            return DirectGate_Client_HandleCmdMsg(pCli, pMsg);
        case DIRECTGATE_PKG_WEBRTC:
            return DirectGate_Client_HandleWebRTCMsg(pCli, pMsg);
        case DIRECTGATE_PKG_FILE:
            return DirectGate_Client_HandleFileMsg(pCli, pMsg, pTransport);
        case DIRECTGATE_PKG_STATUS:
            return DirectGate_Client_HandleStatusMsg(pMsg, pTransport);
        case DIRECTGATE_PKG_DATA:
            return DirectGate_Client_HandleDataMsg(pCli, pMsg);
        case DIRECTGATE_PKG_KEEPALIVE:
            return DirectGate_Client_HandleKeepaliveMsg(pCli, pMsg);
        default:
            break;
    }

    xlogw("Unknown protocol message type: %s", xstrused(pMsg->header.pType) ? pMsg->header.pType : "N/A");
    return XAPI_CONTINUE;
}

static int DirectGate_Client_HandleEncryptedMsg(directgate_ctx_t *pCli, directgate_pkg_t *pMsg, const char *pTransport)
{
    if (!DirectGate_E2E_IsInitialized(&pCli->e2e))
    {
        xloge("%s: Encrypted message but E2E not initialized",
            xstrused(pTransport) ? pTransport : "transport");

        return XAPI_DISCONNECT;
    }

    xbyte_buffer_t inner;
    XByteBuffer_Init(&inner, XSTDNON, XFALSE);

    if (!DirectGate_Proto_DecryptPackage(&inner, pMsg, &pCli->e2e))
    {
        xloge("%s: Failed to decrypt message", xstrused(pTransport) ? pTransport : "transport");
        XByteBuffer_Clear(&inner);
        return XAPI_DISCONNECT;
    }

    directgate_pkg_t innerMsg;
    if (!DirectGate_Package_Parse(&innerMsg, inner.pData, inner.nUsed))
    {
        xloge("%s: Failed to parse decrypted message", xstrused(pTransport) ? pTransport : "transport");
        XByteBuffer_Clear(&inner);
        return XAPI_DISCONNECT;
    }

    uint32_t nInnerSessionId = innerMsg.header.nSessionId;
    if (!DirectGate_Proto_BindInnerSessionId(pMsg->header.nSessionId, &innerMsg))
    {
        xloge("%s: Encrypted session id mismatch: sid(%u), innerSid(%u)",
            xstrused(pTransport) ? pTransport : "transport",
            pMsg->header.nSessionId, nInnerSessionId);

        DirectGate_Package_Clear(&innerMsg);
        XByteBuffer_Clear(&inner);
        return XAPI_DISCONNECT;
    }

    int nStatus = DirectGate_Client_DispatchMessage(pCli, &innerMsg, pTransport);
    DirectGate_Package_Clear(&innerMsg);
    XByteBuffer_Clear(&inner);
    return nStatus;
}

static int DirectGate_Client_HandleMessage(directgate_ctx_t *pCli, const uint8_t *pPayload, size_t nPayload, const char *pTransport)
{
    XCHECK((pCli != NULL), XAPI_DISCONNECT);
    XCHECK((pPayload != NULL), XAPI_CONTINUE);
    XCHECK((nPayload > 0), XAPI_CONTINUE);

    directgate_pkg_t msg;
    if (!DirectGate_Package_Parse(&msg, pPayload, nPayload))
    {
        xlogw("%s: Invalid protocol message", xstrused(pTransport) ? pTransport : "transport");
        return XAPI_DISCONNECT;
    }

    if (msg.header.eType == DIRECTGATE_PKG_NONE)
    {
        xlogw("%s: Message missing type", xstrused(pTransport) ? pTransport : "transport");
        DirectGate_Package_Clear(&msg);
        return XAPI_DISCONNECT;
    }

    int nStatus = XAPI_CONTINUE;
    if (msg.header.eType == DIRECTGATE_PKG_ENCRYPTED)
    {
        nStatus = DirectGate_Client_HandleEncryptedMsg(pCli, &msg, pTransport);
    }
    else if (DirectGate_Client_RequiresEncryption(pCli, &msg))
    {
        xloge("%s: Protocol violation: unencrypted '%s' after auth",
            xstrused(pTransport) ? pTransport : "transport",
            xstrused(msg.header.pType) ? msg.header.pType : "N/A");

        nStatus = XAPI_DISCONNECT;
    }
    else
    {
        nStatus = DirectGate_Client_DispatchMessage(pCli, &msg, pTransport);
    }

    DirectGate_Package_Clear(&msg);
    return nStatus;
}

/* WebRTC data channel callback: dispatch protocol messages through the same path as WebSocket */
static void DirectGate_Client_WebRTC_DataCb(const uint8_t *pData, size_t nLen, void *pCtx)
{
    directgate_ctx_t *pCli = (directgate_ctx_t*)pCtx;
    XCHECK_VOID((pCli != NULL));
    XCHECK_VOID((pData != NULL));
    XCHECK_VOID((nLen > 0));

    if (DirectGate_Client_HandleMessage(pCli, pData, nLen, "WebRTC") < 0)
        g_bFinish = XTRUE;
}

static int DirectGate_Client_SendRole(directgate_ctx_t *pCli, const char *pRole, const char *pAgentId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_BuildRole(pRole, pAgentId);
    XCHECK((pHeader != NULL), XAPI_DISCONNECT);

    if (pCli->pCfg != NULL && xstrused(pCli->pCfg->sAccessToken))
        XJSON_AddString(pHeader, "accessToken", pCli->pCfg->sAccessToken);

    int nStatus = DirectGate_Client_SendMsg(pCli, pHeader, NULL, 0);
    XJSON_FreeObject(pHeader);
    return nStatus;
}

static int DirectGate_Client_SendAuthHello(directgate_ctx_t *pCli)
{
    XCHECK((pCli != NULL), XAPI_DISCONNECT);
    XCHECK((pCli->pWsSession != NULL), XAPI_DISCONNECT);

    const directgate_cfg_t *pCfg = pCli->pCfg;
    XCHECK((pCfg != NULL), XAPI_DISCONNECT);

    if (!xstrused(pCfg->sDeviceId) || !xstrused(pCfg->sSecret))
    {
        xloge("SRP: Failed to send hello, auth is not configured");
        return XAPI_DISCONNECT;
    }

    char sAHex[1024];
    char sNonceHex[(DIRECTGATE_SRP_NONCE_SIZE * 2) + 1];

    if (!DirectGate_SRP_ClientGenerateA(&pCli->srp, sAHex, sizeof(sAHex), sNonceHex, sizeof(sNonceHex)))
    {
        xloge("SRP: Failed to generate client public value");
        return XAPI_DISCONNECT;
    }

    xjson_obj_t *pHeader = DirectGate_Proto_BuildAuthHello(pCfg->sDeviceId, sAHex, sNonceHex, pCli->nSessionId);
    XCHECK((pHeader != NULL), XAPI_DISCONNECT);

    int nStatus = DirectGate_Client_SendMsg(pCli, pHeader, NULL, 0);
    XJSON_FreeObject(pHeader);

    if (nStatus >= 0) xlogi("SRP: Auth hello sent");
    return nStatus;
}

static int DirectGate_Client_SendData(directgate_ctx_t *pCli, const uint8_t *pPayload, size_t nLength)
{
    XCHECK((pCli != NULL), XAPI_DISCONNECT);
    XCHECK((pCli->pWsSession != NULL), XAPI_DISCONNECT);
    XCHECK((pPayload != NULL || !nLength), XAPI_DISCONNECT);

    if (pCli->bAuthDone && !DirectGate_E2E_IsInitialized(&pCli->e2e))
    {
        xloge("E2E is active but keys are not initialized");
        return XAPI_DISCONNECT;
    }

    xjson_obj_t *pHeader = DirectGate_Proto_BuildData(pCli->nSessionId);
    XCHECK((pHeader != NULL), XAPI_DISCONNECT);

    int nStatus = DirectGate_Client_SendMsg(pCli, pHeader, pPayload, nLength);
    XJSON_FreeObject(pHeader);
    return nStatus;
}

static int DirectGate_Client_SendResize(directgate_ctx_t *pCli)
{
    XCHECK((pCli != NULL), XAPI_DISCONNECT);
    XCHECK((pCli->pWsSession != NULL), XAPI_DISCONNECT);
    if (!pCli->pWsSession->bHandshakeDone) return XAPI_CONTINUE;

    struct winsize size;
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO bufInfo;
    XCHECK(GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &bufInfo),
        xthrowr(XAPI_CONTINUE, "Failed to get terminal size: error(%lu)", GetLastError()));

    memset(&size, 0, sizeof(size));
    size.ws_col = (unsigned short)(bufInfo.srWindow.Right - bufInfo.srWindow.Left + 1);
    size.ws_row = (unsigned short)(bufInfo.srWindow.Bottom - bufInfo.srWindow.Top + 1);
#else
    XCHECK((!ioctl(STDOUT_FILENO, TIOCGWINSZ, &size)),
        xthrowr(XAPI_CONTINUE, "Failed to get terminal size: errno(%d)", errno));
#endif

    XCHECK((size.ws_row > 0 || size.ws_col > 0),
        xthrowr(XAPI_CONTINUE, "Invalid terminal size: (%d), cols(%d)", size.ws_row, size.ws_col));

    if (pCli->bHaveSize &&
        pCli->lastSize.ws_row == size.ws_row &&
        pCli->lastSize.ws_col == size.ws_col &&
        pCli->lastSize.ws_xpixel == size.ws_xpixel &&
        pCli->lastSize.ws_ypixel == size.ws_ypixel)
    {
        return XAPI_CONTINUE;
    }

    xlogd("Terminal resized: rows(%d), cols(%d), xpixel(%d), ypixel(%d)",
        size.ws_row, size.ws_col, size.ws_xpixel, size.ws_ypixel);

    xjson_obj_t *pHeader = DirectGate_Proto_BuildResize(
        size.ws_row, size.ws_col, size.ws_xpixel,
        size.ws_ypixel, pCli->nSessionId);
    XCHECK((pHeader != NULL), XAPI_DISCONNECT);

    int nStatus = DirectGate_Client_SendMsg(pCli, pHeader, NULL, 0);
    XJSON_FreeObject(pHeader);

    if (nStatus >= 0)
    {
        pCli->lastSize = size;
        pCli->bHaveSize = XTRUE;
    }

    return nStatus;
}

static int DirectGate_Client_SendCmdStart(directgate_ctx_t *pCli, const char *pMode)
{
    XCHECK((pCli != NULL), XAPI_DISCONNECT);
    XCHECK((pCli->pWsSession != NULL), XAPI_DISCONNECT);

    xjson_obj_t *pHeader = DirectGate_Proto_BuildCmd("start", NULL, NULL, pMode, pCli->nSessionId);
    XCHECK((pHeader != NULL), XAPI_DISCONNECT);

    int nStatus = DirectGate_Client_SendMsg(pCli, pHeader, NULL, 0);
    XJSON_FreeObject(pHeader);
    return nStatus;
}

static xbool_t DirectGate_Client_ExtractRoutingKey(const char *pToken, char *pRkBuf, size_t nRkSize)
{
    XCHECK((pToken != NULL), XFALSE);
    XCHECK((pRkBuf != NULL), XFALSE);
    pRkBuf[0] = XSTR_NUL;

    xjwt_t jwt;
    if (XJWT_Parse(&jwt, pToken, strlen(pToken), NULL, 0) != XSTDOK)
    {
        XJWT_Destroy(&jwt);
        return XFALSE;
    }

    xjson_obj_t *pPayload = XJWT_GetPayloadObj(&jwt);
    if (pPayload == NULL)
    {
        XJWT_Destroy(&jwt);
        return XFALSE;
    }

    const char *pRk = XJSON_GetString(XJSON_GetObject(pPayload, "rk"));
    if (!xstrused(pRk))
    {
        XJWT_Destroy(&jwt);
        return XFALSE;
    }

    xstrncpy(pRkBuf, nRkSize, pRk);
    XJWT_Destroy(&jwt);
    return XTRUE;
}

static int DirectGate_Client_HandshakeRequest(xapi_ctx_t *pCtx, xapi_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    XCHECK((pCtx != NULL), XAPI_DISCONNECT);
    xhttp_t *pHandle = (xhttp_t*)pSession->pPacket;

    directgate_ctx_t *pCli = (directgate_ctx_t*)pSession->pSessionData;
    if (pCli != NULL && pCli->pCfg != NULL)
    {
        directgate_cfg_t *pCfg = (directgate_cfg_t*)pCli->pCfg;

        /* Extract routing key from JWT if not explicitly configured */
        if (!xstrused(pCfg->sRoutingKey) && xstrused(pCfg->sAccessToken))
        {
            if (DirectGate_Client_ExtractRoutingKey(pCfg->sAccessToken,
                    pCfg->sRoutingKey, sizeof(pCfg->sRoutingKey)))
                xlogi("Extracted routing key from access token: rk(%s)", pCfg->sRoutingKey);
            else
                xlogw("Failed to extract routing key from access token");
        }

        if (xstrused(pCfg->sRoutingKey))
        {
            char sUri[XHTTP_URL_MAX];
            const char *pSep = strchr(pHandle->sUri, '?') != NULL ? "&" : "?";
            xstrncpyf(sUri, sizeof(sUri), "%s%srk=%s", pHandle->sUri, pSep, pCfg->sRoutingKey);
            xstrncpy(pHandle->sUri, sizeof(pHandle->sUri), sUri);

            /* Reassemble the HTTP request with the updated URI */
            const uint8_t *pContent = XHTTP_GetBody(pHandle);
            size_t nLength = XHTTP_GetBodySize(pHandle);
            uint8_t *pBuffer = NULL;

            if (nLength > 0)
            {
                pBuffer = (uint8_t*)malloc(nLength);
                XCHECK((pBuffer != NULL), XAPI_DISCONNECT);
                memcpy(pBuffer, pContent, nLength);
            }

            XByteBuffer_Clear(&pHandle->rawData);
            pHandle->nComplete = XFALSE;

            XCHECK((XHTTP_Assemble(pHandle, pBuffer, nLength) != NULL),
                xthrowr(XAPI_DISCONNECT, "Failed to reassemble handshake request"));

            free(pBuffer);
        }
    }

    xlogn("Sending handhshake request: fd(%d), uri(%s), buff(%zu)",
        (int)pSession->sock.nFD, pHandle->sUri, pHandle->rawData.nUsed);

    char *pHeader = XHTTP_GetHeaderRaw(pHandle);
    if (pHeader != NULL)
    {
        xlogd("Raw request header:\n\n%s", pHeader);
        free(pHeader);
    }

    return XAPI_CONTINUE;
}

static int DirectGate_Client_HandshakeResponse(xapi_ctx_t *pCtx, xapi_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    XCHECK((pCtx != NULL), XAPI_DISCONNECT);

    directgate_ctx_t *pCli = (directgate_ctx_t*)pSession->pSessionData;
    xhttp_t *pHandle = (xhttp_t*)pSession->pPacket;

    xlogn("Received handhshake response: fd(%d), buff(%zu)",
        (int)pSession->sock.nFD, pHandle->rawData.nUsed);

    char *pHeader = XHTTP_GetHeaderRaw(pHandle);
    if (pHeader != NULL)
    {
        xlogd("Raw answer response:\n\n%s", pHeader);
        free(pHeader);
    }

    if (pCli != NULL && !pCli->bRoleSent)
    {
        pCli->bRoleSent = XTRUE;
        const directgate_cfg_t *pCfg = pCli->pCfg;
        XCHECK((pCfg != NULL), XAPI_DISCONNECT);

        const char *pDeviceId = pCli->pCfg ? pCli->pCfg->sDeviceId : NULL;
        if (!xstrused(pDeviceId))
        {
            xloge("Missing device ID");
            return XAPI_DISCONNECT;
        }

        int nStatus = DirectGate_Client_SendRole(pCli, "client", pDeviceId);
        if (nStatus < 0) return nStatus;

        if (!xstrused(pCfg->sDeviceId) || !xstrused(pCfg->sSecret))
        {
            xloge("SRP: Auth is not configured");
            return XAPI_DISCONNECT;
        }

        xlogi("Waiting for start command to begin SRP authentication");
        return nStatus;
    }

    return XAPI_CONTINUE;
}

static int DirectGate_Client_HandleStdin(xapi_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    XCHECK((pSession->pSessionData != NULL), XAPI_DISCONNECT);

    directgate_ctx_t *pCli = (directgate_ctx_t*)pSession->pSessionData;
    XCHECK((pCli->pWsSession != NULL), XAPI_DISCONNECT);

    uint8_t sBuffer[XSTR_BIG];
    for (;;)
    {
#ifdef _WIN32
        int nRead = recv(g_nStdinBridge[0], (char*)sBuffer, (int)sizeof(sBuffer), 0);
#else
        ssize_t nRead = read(STDIN_FILENO, sBuffer, sizeof(sBuffer));
#endif
        if (nRead > 0)
        {
            if (!pCli->pWsSession->bHandshakeDone) continue;

            /* Don't let client input break the session while auth is pending. */
            if (pCli->pCfg != NULL && !pCli->bAuthDone &&
                xstrused(pCli->pCfg->sDeviceId) &&
                xstrused(pCli->pCfg->sSecret))
            {
                if (!pCli->bInputBlocked)
                {
                    xlogi("Waiting for authentication - input is temporarily blocked");
                    pCli->bInputBlocked = XTRUE;
                }

                continue;
            }

            if (DirectGate_Client_SendData(pCli, sBuffer, (size_t)nRead) < 0)
                return XAPI_DISCONNECT;

            continue;
        }

        if (nRead == 0)
        {
            g_bFinish = XTRUE;
            return XAPI_CONTINUE;
        }

#ifdef _WIN32
        int nError = WSAGetLastError();
        if (nError == WSAEINTR) continue;
        if (nError == WSAEWOULDBLOCK) break;
#else
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
#endif

        return XAPI_DISCONNECT;
    }

    return XAPI_CONTINUE;
}

static int DirectGate_Client_HandleFrame(xapi_ctx_t *pCtx, xapi_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    XCHECK((pCtx != NULL), XAPI_DISCONNECT);

    if (pSession->eRole == XAPI_CUSTOM)
    {
        directgate_ctx_t *pCli = (directgate_ctx_t*)pSession->pSessionData;
        if (pCli != NULL && (int)pSession->sock.nFD == DirectGate_WebRTC_GetPipeFd(&pCli->webrtc))
        {
            DirectGate_WebRTC_ProcessQueue(&pCli->webrtc);
            return XAPI_CONTINUE;
        }
        return DirectGate_Client_HandleStdin(pSession);
    }

    xws_frame_t *pFrame = (xws_frame_t*)pSession->pPacket;
    XCHECK((pFrame != NULL), XAPI_DISCONNECT);

    xlogd("Received WS frame: fd(%d), type(%s), fin(%s), hdr(%zu), pl(%zu), buff(%zu)",
        (int)pSession->sock.nFD, XWS_FrameTypeStr(pFrame->eType), pFrame->bFin?"true":"false",
        pFrame->nHeaderSize, pFrame->nPayloadLength, pFrame->buffer.nUsed);

    if (pFrame->eType == XWS_PING)
        return DirectGate_Client_SendPong(pSession);

    if (pFrame->eType == XWS_CLOSE)
        return XAPI_DISCONNECT;

    const uint8_t *pPayload = XWebFrame_GetPayload(pFrame);
    size_t nLength = XWebFrame_GetPayloadLength(pFrame);

    if (pPayload == NULL || !nLength) return XAPI_CONTINUE;
    if (pFrame->eType != XWS_BINARY) return XAPI_CONTINUE;

    directgate_ctx_t *pCli = (directgate_ctx_t*)pSession->pSessionData;
    XCHECK((pCli != NULL), XAPI_DISCONNECT);
    return DirectGate_Client_HandleMessage(pCli, pPayload, nLength, "WebSocket");
}

static int DirectGate_Client_InitSession(xapi_ctx_t *pCtx, xapi_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    XCHECK((pCtx != NULL), XAPI_DISCONNECT);

    directgate_ctx_t *pCli = (directgate_ctx_t*)pSession->pSessionData;
    xlogn("Client connected to server: fd(%d) %s:%u",
        (int)pSession->sock.nFD, pSession->sAddr, pSession->nPort);

    if (pCli != NULL)
    {
        pCli->pWsSession = pSession;
        pCli->bRoleSent = XFALSE;
        pCli->bAuthDone = XFALSE;
        pCli->bInputBlocked = XFALSE;
        pCli->nSessionId = 0;

        DirectGate_E2E_Init(&pCli->e2e);
        DirectGate_SRP_ClientCleanse(&pCli->srp);

        if (!DirectGate_SRP_ClientInit(&pCli->srp))
        {
            xloge("Failed to initialize SRP client context");
            return XAPI_DISCONNECT;
        }

        DirectGate_Client_EnableRawIO(&pCli->io);
    }

    return XAPI_SetEvents(pSession, XPOLLIO);
}

static int DirectGate_Client_DestroySession(xapi_ctx_t *pCtx, xapi_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    XCHECK((pCtx != NULL), XAPI_DISCONNECT);

    if (pSession->eRole == XAPI_CUSTOM)
    {
        directgate_ctx_t *pCli = (directgate_ctx_t*)pSession->pSessionData;
        if (pCli != NULL)
        {
            int nPipeFd = DirectGate_WebRTC_GetPipeFd(&pCli->webrtc);
            if ((int)pSession->sock.nFD == nPipeFd)
            {
                pCli->webrtc.nPipeFds[0] = -1;
                pCli->pPipeSession = NULL;
            }
        }

        return XAPI_NO_ACTION;
    }

    directgate_ctx_t *pCli = (directgate_ctx_t*)pSession->pSessionData;
    xlogn("Connection closed: fd(%d)", (int)pSession->sock.nFD);

    if (pCli != NULL)
    {
        DirectGate_Client_RestoreIO(&pCli->io);
        DirectGate_Client_CleanseSecretCtx(pCli);
        DirectGate_SRP_ClientCleanse(&pCli->srp);

        if (pCli->pPipeSession != NULL)
        {
            xapi_session_t *pPipe = pCli->pPipeSession;
            pCli->pPipeSession = NULL;
            XAPI_Disconnect(pPipe);
        }

        DirectGate_WebRTC_Clear(&pCli->webrtc);
        DirectGate_Transfer_Destroy(&pCli->transfer);
        pCli->pWsSession = NULL;

        if (pCli->bLogMuted)
        {
            xlog_screen(XTRUE);
            pCli->bLogMuted = XFALSE;
        }
    }

    g_bFinish = XTRUE;
    return XAPI_DISCONNECT;
}

static int DirectGate_Client_Interrupt(xapi_ctx_t *pCtx)
{
    directgate_ctx_t *pCli = (directgate_ctx_t*)pCtx->pApi->pUserCtx;

#ifndef _WIN32
    if (g_bWinch && pCli != NULL)
    {
        g_bWinch = 0;
        int nResize = DirectGate_Client_SendResize(pCli);
        if (nResize < 0) return nResize;
    }
#else
    (void)pCli;
#endif

    if (g_bFinish) return XAPI_DISCONNECT;
    return XAPI_CONTINUE;
}

static int DirectGate_Client_Tick(xapi_ctx_t *pCtx)
{
    directgate_ctx_t *pCli = (directgate_ctx_t*)pCtx->pApi->pUserCtx;

    if (pCli != NULL && pCli->transfer.eState == XTRANSFER_STATE_SENDING)
    {
        xlogt("Tick event: advancing active file transfer");
        DirectGate_Transfer_SendNext(&pCli->transfer, DirectGate_Client_Transfer_SendCb, pCli);
    }

#ifdef _WIN32
    /* No SIGWINCH on Windows: poll the console geometry on the loop tick.
       SendResize only transmits when the size actually changed. */
    if (pCli != NULL && pCli->io.bRaw)
    {
        int nResize = DirectGate_Client_SendResize(pCli);
        if (nResize < 0) return nResize;
    }
#endif

    if (g_bFinish) return XAPI_DISCONNECT;
    return XAPI_CONTINUE;
}

static int DirectGate_Client_HandleRegistered(xapi_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    if (pSession->eRole != XAPI_CUSTOM) return XAPI_CONTINUE;

    directgate_ctx_t *pCli = (directgate_ctx_t*)pSession->pSessionData;
    XCHECK_NL((pCli != NULL), XAPI_DISCONNECT);

    int nPipeFd = DirectGate_WebRTC_GetPipeFd(&pCli->webrtc);
    if ((int)pSession->sock.nFD == nPipeFd) pCli->pPipeSession = pSession;

    return XAPI_CONTINUE;
}

static int DirectGate_Client_ServiceCallback(xapi_ctx_t *pCtx, xapi_session_t *pSession)
{
    switch (pCtx->eCbType)
    {
        case XAPI_CB_HANDSHAKE_REQUEST:
            return DirectGate_Client_HandshakeRequest(pCtx, pSession);
        case XAPI_CB_HANDSHAKE_RESPONSE:
            return DirectGate_Client_HandshakeResponse(pCtx, pSession);
        case XAPI_CB_REGISTERED:
            return DirectGate_Client_HandleRegistered(pSession);
        case XAPI_CB_CONNECTED:
            return DirectGate_Client_InitSession(pCtx, pSession);
        case XAPI_CB_CLOSED:
            return DirectGate_Client_DestroySession(pCtx, pSession);
        case XAPI_CB_READ:
            return DirectGate_Client_HandleFrame(pCtx, pSession);
        case XAPI_CB_ERROR:
            return DirectGate_Client_LogError(pCtx, pSession);
        case XAPI_CB_STATUS:
            return DirectGate_Client_LogStatus(pCtx, pSession);
        case XAPI_CB_INTERRUPT:
            return DirectGate_Client_Interrupt(pCtx);
        case XAPI_CB_TICK:
            return DirectGate_Client_Tick(pCtx);
        case XAPI_CB_COMPLETE:
            XCHECK((pSession != NULL), XAPI_DISCONNECT);
            xlogd("TX complete: fd(%d)", (int)pSession->sock.nFD);
            break;
        default:
            break;
    }

    return XAPI_CONTINUE;
}

int main(int argc, char* argv[])
{
    xlog_defaults();
    xlog_coloring(XFALSE);
    xlog_timing(XLOG_TIME);
    xlog_indent(XTRUE);
    xlog_setfl(XLOG_FATAL | XLOG_ERROR | XLOG_WARN);

#ifdef _WIN32
    /* No SIGPIPE/SIGWINCH on Windows: resize is polled on the loop tick */
    int nSignals[2] = { SIGTERM, SIGINT };
    XSig_Register(nSignals, 2, DirectGate_Client_SignalCallback);
#else
    int nSignals[4] = { SIGTERM, SIGINT, SIGPIPE, SIGWINCH };
    XSig_Register(nSignals, 4, DirectGate_Client_SignalCallback);
#endif

    directgate_ctx_t client;
    memset(&client, 0, sizeof(client));
    DirectGate_Client_Init(&client);

    directgate_cfg_t args;
    int nStatus = DirectGate_ParseArgs(&args, argc, argv);
    if (nStatus < 0)
    {
        DirectGate_DisplayUsage(argv[0]);
        XLog_Destroy();
        return XSTDERR;
    }
    else if (!nStatus)
    {
        XLog_Destroy();
        return XSTDERR;
    }

    xlogn("Starting directgate client v%s", DirectGate_GetVersionLong());
    xlogn("libxutils v%s", XUtils_Version());

    client.pCfg = &args;
    client.bAuthDone = XFALSE;

    /* Fetch relay envelope from API when apiUrl and apiToken are configured */
    if (xstrused(args.sApiUrl) && xstrused(args.sApiToken))
    {
        xlogi("Fetching relay connection envelope from API: %s", args.sApiUrl);
        if (!DirectGate_Relay_FetchEnvelope(&args))
        {
            xloge("Failed to fetch relay connection envelope");
            XLog_Destroy();
            return XSTDERR;
        }
    }

    xapi_t api;
    xlink_t link;
    XAPI_Init(&api, DirectGate_Client_ServiceCallback, &client);

    if (!xstrused(args.sSignalingUrl))
    {
        xloge("Signaling URL is required");
        XLog_Destroy();
        return XSTDERR;
    }

    if (XLink_Parse(&link, args.sSignalingUrl) < 0)
    {
        xloge("Failed to parse URL: %s", args.sSignalingUrl);
        XLog_Destroy();
        return XSTDERR;
    }

    xapi_endpoint_t endpt;
    XAPI_InitEndpoint(&endpt);

    endpt.eType = XAPI_WS;
    endpt.eRole = XAPI_CLIENT;
    endpt.pAddr = link.sAddr;
    endpt.nPort = link.nPort;
    endpt.pUri = link.sUri;
    endpt.bTLS = xstrcmp(link.sProtocol, "wss");
    endpt.pSessionData = &client;

    if (XAPI_AddEndpoint(&api, &endpt) < 0)
    {
        XAPI_Destroy(&api);
        XLog_Destroy();
        return XSTDERR;
    }

    xapi_endpoint_t stdinEndpt;
    XAPI_InitEndpoint(&stdinEndpt);

    stdinEndpt.eType = XAPI_EVENT;
    stdinEndpt.eRole = XAPI_CUSTOM;
    stdinEndpt.nEvents = XPOLLIN;
    stdinEndpt.bUnix = XTRUE;
    stdinEndpt.pSessionData = &client;

#ifdef _WIN32
    if (XSock_CreatePair(g_nStdinBridge) != XSTDOK)
    {
        xloge("Failed to create stdin bridge socket pair: error(%d)", WSAGetLastError());
        XAPI_Destroy(&api);
        XLog_Destroy();
        return XSTDERR;
    }

    u_long nNonBlock = 1;
    ioctlsocket(g_nStdinBridge[0], FIONBIO, &nNonBlock);

    HANDLE hStdinPump = CreateThread(NULL, 0, DirectGate_Client_StdinPump, NULL, 0, NULL);
    if (hStdinPump == NULL)
    {
        xloge("Failed to start stdin pump thread: error(%lu)", GetLastError());
        XAPI_Destroy(&api);
        XLog_Destroy();
        return XSTDERR;
    }
    CloseHandle(hStdinPump);

    stdinEndpt.nFD = g_nStdinBridge[0];
#else
    stdinEndpt.nFD = STDIN_FILENO;
#endif

    if (XAPI_AddEndpoint(&api, &stdinEndpt) < 0)
    {
        XAPI_Destroy(&api);
        XLog_Destroy();
        return XSTDERR;
    }

    int nPipeFd = DirectGate_WebRTC_GetPipeFd(&client.webrtc);
    if (nPipeFd >= 0)
    {
        xapi_endpoint_t pipeEndpt;
        XAPI_InitEndpoint(&pipeEndpt);

        pipeEndpt.eType = XAPI_EVENT;
        pipeEndpt.eRole = XAPI_CUSTOM;
        pipeEndpt.nFD = nPipeFd;
        pipeEndpt.nEvents = XPOLLIN;
        pipeEndpt.bUnix = XTRUE;
        pipeEndpt.pSessionData = &client;

        if (XAPI_AddEndpoint(&api, &pipeEndpt) < 0)
            xlogw("Failed to register WebRTC notification pipe");
    }

    xevent_status_t status;
    do status = XAPI_Service(&api, 100);
    while (status == XEVENTS_SUCCESS && !g_bFinish);

    DirectGate_Client_RestoreIO(&client.io);
    DirectGate_Client_CleanseSecret(&args);

    DirectGate_WebRTC_Clear(&client.webrtc);
    DirectGate_WebRTC_Cleanup();

    client.pPipeSession = NULL;
    XAPI_Destroy(&api);
    XLog_Destroy();

    return 0;
}
