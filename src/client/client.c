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
#include "keyauth.h"
#include "common.h"
#include "config.h"
#include "devices.h"
#include "login.h"
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

    /* Public-key auth, attempted before the password when a key is usable */
    directgate_keyauth_t keyauth;
    directgate_client_key_t key;
    char sAgentPub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    xbool_t bUseKeyAuth;
    xbool_t bKeyAuthFailed;

    /* -a: authorize a client key on the device instead of opening a shell */
    char sAddKeyPub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    xbool_t bAddKeyMode;
    xbool_t bAddKeyDone;

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
    DirectGate_KeyAuth_Init(&pClient->keyauth);
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

    /*
        The relay disconnects an unauthenticated client the moment it sends
        anything other than role or auth. Dropping such a message here costs
        nothing - every one of them is a periodic or event-driven update that
        is resent once the session is up - and it keeps a single stray send
        from tearing down the whole connection.
    */
    if (!pCli->bAuthDone)
    {
        const char *pType = XJSON_GetString(XJSON_GetObject(pHeader, "type"));
        if (!DirectGate_Proto_IsClientPreAuthType(pType))
        {
            xlogw("Suppressed pre-authentication message: type(%s)", xstrused(pType) ? pType : "none");
            return XAPI_CONTINUE;
        }
    }

    /* Add packet counter for authenticated sessions */
    if (pCli->bAuthDone && DirectGate_E2E_IsInitialized(&pCli->e2e))
        DirectGate_Proto_AddCC(pHeader, &pCli->e2e,
            pCli->webrtc.nSignalGeneration);

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

/*
 * Hands the client key to the device for authorization. This is the whole
 * point of -a: one admin message on an authenticated, encrypted session, the
 * same thing the workspace UI does when you add a key from the browser.
 */
static int DirectGate_Client_SendAddKey(directgate_ctx_t *pCli)
{
    xjson_obj_t *pHeader = DirectGate_Proto_BuildAdmin("add-key", pCli->sAddKeyPub, NULL, NULL, pCli->nSessionId);
    XCHECK((pHeader != NULL), XAPI_DISCONNECT);

    int nStatus = DirectGate_Client_SendMsg(pCli, pHeader, NULL, 0);
    XJSON_FreeObject(pHeader);

    if (nStatus >= 0) xlogi("Sent the key authorization request");
    return nStatus;
}

/*
 * The device answers add-key with ok, already or error. Any of the three ends
 * the session: -a authorizes a key and stops, it never opens a shell.
 */
static int DirectGate_Client_HandleAdminMsg(directgate_ctx_t *pCli, directgate_pkg_t *pMsg)
{
    directgate_pkg_admin_t *pAdmin = (directgate_pkg_admin_t*)pMsg->pPackage;
    XCHECK((pAdmin != NULL), XAPI_DISCONNECT);

    if (!xstrused(pAdmin->pAction) || !xstrcmp(pAdmin->pAction, "add-key-result"))
    {
        xlogw("Ignoring unexpected admin response: action(%s)", xstrused(pAdmin->pAction) ? pAdmin->pAction : "N/A");
        return XAPI_CONTINUE;
    }

    const char *pStatus = xstrused(pAdmin->pStatus) ? pAdmin->pStatus : "error";

    if (xstrcmp(pStatus, "ok")) printf("\n  Key authorized. You can now connect without the password.\n\n");
    else if (xstrcmp(pStatus, "already")) printf("\n  Key was already authorized on this device.\n\n");
    else
    {
        xloge("Device refused the key: %s", xstrused(pAdmin->pReason) ? pAdmin->pReason : "unknown reason");
        pCli->bAddKeyDone = XFALSE;
        g_bFinish = XTRUE;
        return XAPI_DISCONNECT;
    }

    pCli->bAddKeyDone = XTRUE;
    g_bFinish = XTRUE;
    return XAPI_DISCONNECT;
}

/* Terminal session is up: bring the P2P data channel online.
 * Shared by both authentication methods so they cannot drift apart. */
static void DirectGate_Client_StartWebRTC(directgate_ctx_t *pCli)
{
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
}

/* Completes a successful key handshake: derive the shared secret from the two
 * ephemeral halves and turn it into the directional E2E keys. */
static xbool_t DirectGate_Client_KeyAuthDone(directgate_ctx_t *pCli)
{
    if (!DirectGate_KeyAuth_ClientAccept(&pCli->keyauth) ||
        !DirectGate_KeyAuth_DeriveShared(&pCli->keyauth))
    {
        xloge("KeyAuth: Failed to derive the shared secret");
        return XFALSE;
    }

    xbool_t bDerived = DirectGate_E2E_DeriveFromKey(&pCli->e2e,
        pCli->keyauth.sharedSecret, sizeof(pCli->keyauth.sharedSecret),
        pCli->keyauth.peerNonce /* agentNonce */,
        pCli->keyauth.localNonce /* clientNonce */,
        DIRECTGATE_KEYAUTH_NONCE_SIZE, pCli->pCfg->sDeviceId, XFALSE);

    DirectGate_KeyAuth_Cleanse(&pCli->keyauth);

    if (!bDerived) xloge("KeyAuth: Failed to derive E2E keys");
    return bDerived;
}

static int DirectGate_Client_HandleKeyAuthMsg(directgate_ctx_t *pCli, directgate_pkg_auth_t *pAuth)
{
    if (xstrused(pAuth->pAction) && xstrcmp(pAuth->pAction, "challenge"))
    {
        char sClientSigB64[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];

        if (!DirectGate_KeyAuth_ClientProcessChallenge(&pCli->keyauth, &pCli->key,
                pAuth->pAgentPub, pAuth->pAgentEph, pAuth->pNonce,
                pAuth->pChallenge, pAuth->pAgentSig,
                sClientSigB64, sizeof(sClientSigB64)))
        {
            /*
                A rejected challenge is not a reason to fall back to the
                password: either the host is not the one the backend
                published, or it signed badly. Both mean the peer is not
                provably the device we asked for, so the connection ends.
            */
            xloge("KeyAuth: Refusing the host challenge");
            return XAPI_DISCONNECT;
        }

        xjson_obj_t *pProof = DirectGate_Proto_BuildAuthKeyProof(sClientSigB64, pCli->nSessionId);
        XCHECK((pProof != NULL), XAPI_DISCONNECT);

        int nStatus = DirectGate_Client_SendMsg(pCli, pProof, NULL, 0);
        XJSON_FreeObject(pProof);

        if (nStatus >= 0) xlogi("KeyAuth: Auth proof sent");
        return nStatus;
    }

    if (xstrused(pAuth->pAction) && xstrcmp(pAuth->pAction, "result"))
    {
        if (xstrused(pAuth->pStatus) && xstrcmp(pAuth->pStatus, "ok"))
        {
            if (!DirectGate_Client_KeyAuthDone(pCli)) return XAPI_DISCONNECT;

            xlogn("KeyAuth: Authentication successful, E2E encryption enabled");
            pCli->bAuthDone = XTRUE;

            if (pCli->bAddKeyMode)
                return DirectGate_Client_SendAddKey(pCli);

            if (DirectGate_Client_SendCmdStart(pCli, "terminal") < 0)
                return XAPI_DISCONNECT;

            DirectGate_Client_SendResize(pCli);
            DirectGate_Client_StartWebRTC(pCli);

            return XAPI_CONTINUE;
        }

        /*
            The host is who it claims to be but has not authorized this key.
            That is exactly what the password is for, so the caller reconnects
            and runs SRP instead of failing outright.
        */
        xlogn("KeyAuth: Key was not accepted (%s), falling back to the password",
            xstrused(pAuth->pReason) ? pAuth->pReason : "rejected");

        pCli->bKeyAuthFailed = XTRUE;
        g_bFinish = XTRUE;
        return XAPI_DISCONNECT;
    }

    return XAPI_CONTINUE;
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

    if (pCli->bUseKeyAuth) return DirectGate_Client_HandleKeyAuthMsg(pCli, pAuth);

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

        /* Authorizes a key and stops; it never opens a shell. */
        if (pCli->bAddKeyMode)
            return DirectGate_Client_SendAddKey(pCli);

        if (DirectGate_Client_SendCmdStart(pCli, "terminal") < 0)
            return XAPI_DISCONNECT;

        DirectGate_Client_SendResize(pCli);
        DirectGate_Client_StartWebRTC(pCli);

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
            DirectGate_WebRTC_HandleIceCandidate(&pCli->webrtc, pCandidate, pMid, 0);
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
        case DIRECTGATE_PKG_ADMIN:
            return DirectGate_Client_HandleAdminMsg(pCli, pMsg);
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
        xlogw("%s: Dropped undecryptable message", xstrused(pTransport) ? pTransport : "transport");
        XByteBuffer_Clear(&inner);
        return XAPI_CONTINUE;
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

static int DirectGate_Client_SendKeyHello(directgate_ctx_t *pCli)
{
    const directgate_cfg_t *pCfg = pCli->pCfg;

    if (!DirectGate_KeyAuth_ClientInit(&pCli->keyauth, pCfg->sDeviceId, &pCli->key, pCli->sAgentPub))
    {
        xloge("KeyAuth: Failed to initialize client state");
        return XAPI_DISCONNECT;
    }

    char sClientPubB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sClientEphB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sNonceHex[(DIRECTGATE_KEYAUTH_NONCE_SIZE * 2) + 1];

    if (!DirectGate_KeyAuth_ClientBuildHello(&pCli->keyauth,
            sClientPubB64, sizeof(sClientPubB64),
            sClientEphB64, sizeof(sClientEphB64),
            sNonceHex, sizeof(sNonceHex)))
    {
        xloge("KeyAuth: Failed to build hello");
        return XAPI_DISCONNECT;
    }

    xjson_obj_t *pHeader = DirectGate_Proto_BuildAuthKeyHello(pCfg->sDeviceId, sClientPubB64, sClientEphB64, sNonceHex, pCli->nSessionId);
    XCHECK((pHeader != NULL), XAPI_DISCONNECT);

    int nStatus = DirectGate_Client_SendMsg(pCli, pHeader, NULL, 0);
    XJSON_FreeObject(pHeader);

    if (nStatus >= 0) xlogi("KeyAuth: Auth hello sent");
    return nStatus;
}

static int DirectGate_Client_SendAuthHello(directgate_ctx_t *pCli)
{
    XCHECK((pCli != NULL), XAPI_DISCONNECT);
    XCHECK((pCli->pWsSession != NULL), XAPI_DISCONNECT);

    const directgate_cfg_t *pCfg = pCli->pCfg;
    XCHECK((pCfg != NULL), XAPI_DISCONNECT);

    /* The key is tried first; the password is only reached when there is no
     * usable key, or after the host has turned one down. */
    if (pCli->bUseKeyAuth) return DirectGate_Client_SendKeyHello(pCli);

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

        /* Key auth carries no password, so only the SRP path needs a secret
         * here; both wait for the same start command before saying hello. */
        if (!pCli->bUseKeyAuth && !xstrused(pCfg->sSecret))
        {
            xloge("SRP: Auth is not configured");
            return XAPI_DISCONNECT;
        }

        xlogi("Waiting for start command to begin %s authentication",
            pCli->bUseKeyAuth ? "key" : "SRP");

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

            /* Don't let client input break the session while auth is pending.
             * Keyed on the handshake itself, not on the password, or a key
             * authenticated session would pass keystrokes through early. */
            if (!pCli->bAuthDone)
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
    /*
        No SIGWINCH on Windows: poll the console geometry on the loop tick.
        SendResize only transmits when the size actually changed.

        Raw mode is entered as soon as the socket connects, well before
        authentication, but the relay disconnects a client that sends
        anything other than auth traffic while unauthenticated. Sending
        the very first resize from here therefore killed every Windows
        session one tick after connecting, which is why the gate is on
        bAuthDone and not on bRaw. The post-auth path sends the initial
        resize itself, so nothing is lost by waiting.
    */
    if (pCli != NULL && pCli->bAuthDone && !pCli->bAddKeyMode)
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

static void DirectGate_Client_LoginContext(directgate_login_ctx_t *pCtx, const directgate_cfg_t *pCfg)
{
    memset(pCtx, 0, sizeof(*pCtx));
    pCtx->pApiUrl = pCfg->sApiUrl;
    pCtx->pWebUrl = pCfg->sWebUrl;
    pCtx->bNoBrowser = pCfg->bNoBrowser;
}

/*
 * Generates the client identity used for key authentication. The key file is
 * only half the story: the public half still has to be authorized on each
 * device, so it is printed rather than left for the user to dig out of JSON.
 */
static XSTATUS DirectGate_Client_GenerateKey(const directgate_cfg_t *pCfg)
{
    if (XPath_Exists(pCfg->sKeyPath))
    {
        xbool_t bOverwrite = XFALSE;

        printf("  A client key already exists at %s\n", pCfg->sKeyPath);
        printf("  Overwriting it means re-authorizing the new key on every device.\n");

        if (!DirectGate_PromptBool("  Overwrite it", &bOverwrite) || !bOverwrite)
        {
            printf("  Keeping the existing key.\n");
            return XSTDNON;
        }
    }

    directgate_client_key_t key;
    if (!DirectGate_KeyAuth_KeyGenerate(&key))
    {
        xloge("Failed to generate a client keypair");
        return XSTDERR;
    }

    char sClientPubB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    xbool_t bEncoded = DirectGate_KeyAuth_Base64Encode(key.clientPub,
        sizeof(key.clientPub), sClientPubB64, sizeof(sClientPubB64));

    xbool_t bSaved = bEncoded && DirectGate_KeyAuth_KeySave(&key, pCfg->sKeyPath);
    DirectGate_KeyAuth_KeyCleanse(&key);

    if (!bSaved)
    {
        xloge("Failed to write the client key: %s", pCfg->sKeyPath);
        return XSTDERR;
    }

    printf("\n  Client key written to %s\n\n", pCfg->sKeyPath);
    printf("  Public key:\n    %s\n\n", sClientPubB64);
    printf("  Authorize it on your devices:\n");
    printf("    dgcli -A  %s# interactive device select%s\n", XSTR_FMT_DIM, XSTR_FMT_RESET);
    printf("    dgcli -A -d <deviceId>\n\n");

    return XSTDNON;
}

/*
 * Loads the key that -a will authorize. The key comes from -k when given and
 * from the default path otherwise; having neither is the common first-run
 * case, so it says where the key would live and how to get one rather than
 * just failing.
 */
static xbool_t DirectGate_Client_LoadKeyToAdd(directgate_ctx_t *pCli, const directgate_cfg_t *pCfg)
{
    if (!xstrused(pCfg->sKeyPath) || !XPath_Exists(pCfg->sKeyPath))
    {
        printf("\n  No client key at %s\n\n", pCfg->sKeyPath);
        printf("  Generate one:            dgcli -g\n");
        printf("  Or point at an existing: dgcli -A -k <path to key file>\n\n");
        return XFALSE;
    }

    directgate_client_key_t key;
    if (!DirectGate_KeyAuth_KeyLoad(&key, pCfg->sKeyPath)) return XFALSE;

    if (!DirectGate_KeyAuth_Base64Encode(key.clientPub, sizeof(key.clientPub), pCli->sAddKeyPub, sizeof(pCli->sAddKeyPub)))
    {
        xloge("Failed to encode the client public key: %s", pCfg->sKeyPath);
        DirectGate_KeyAuth_KeyCleanse(&key);
        return XFALSE;
    }

    DirectGate_KeyAuth_KeyCleanse(&key);
    pCli->bAddKeyMode = XTRUE;

    printf("\n  Authorizing key %s\n  from %s\n", pCli->sAddKeyPub, pCfg->sKeyPath);
    return XTRUE;
}

/*
 * Decides whether this connection can try the key first. Both halves have to
 * be present: a usable key file on this side, and an agentPub published by
 * the device on the other, since that is what the host gets pinned to.
 */
static void DirectGate_Client_PrepareKeyAuth(directgate_ctx_t *pCli,
                                             const directgate_cfg_t *pCfg,
                                             const directgate_device_t *pDevice)
{
    pCli->bUseKeyAuth = XFALSE;

    if (!xstrused(pCfg->sKeyPath)) return;

    if (!XPath_Exists(pCfg->sKeyPath))
    {
        /* Only an explicit -k is worth complaining about; the default path
         * simply not existing is the normal password-only setup. */
        if (pCfg->bKeyRequired) xloge("Client key file not found: %s", pCfg->sKeyPath);
        return;
    }

    if (!DirectGate_KeyAuth_KeyLoad(&pCli->key, pCfg->sKeyPath)) return;

    if (!xstrused(pDevice->sAgentPub))
    {
        xlogw("Device '%s' has not published a host key, using the password",
            pDevice->sName);

        DirectGate_KeyAuth_KeyCleanse(&pCli->key);
        return;
    }

    xstrncpy(pCli->sAgentPub, sizeof(pCli->sAgentPub), pDevice->sAgentPub);
    pCli->bUseKeyAuth = XTRUE;

    xlogi("Using client key for authentication: %s", pCfg->sKeyPath);
}

static xbool_t DirectGate_Client_IsInteractive(void)
{
#ifdef _WIN32
    return _isatty(_fileno(stdin)) ? XTRUE : XFALSE;
#else
    return isatty(STDIN_FILENO) ? XTRUE : XFALSE;
#endif
}

/*
 * Fetches the account device list, refreshing the session once if the API
 * turns the token down. Ensure() already refreshes ahead of the expiry, so
 * this only covers a token that went stale between the two calls.
 */
static xbool_t DirectGate_Client_LoadDevices(directgate_device_list_t *pList,
                                             directgate_cfg_t *pCfg,
                                             directgate_account_t *pAccount,
                                             const directgate_login_ctx_t *pLogin)
{
    char sError[XSTR_TINY];

    if (DirectGate_Devices_Fetch(pList, pCfg->sApiUrl, pCfg->sApiToken, sError, sizeof(sError)))
        return XTRUE;

    if (pAccount == NULL || !xstrused(pAccount->sRefreshToken) || !DirectGate_Login_Refresh(pAccount, pLogin))
    {
        xloge("Failed to list devices: %s", sError);
        return XFALSE;
    }

    DirectGate_Account_Save(pAccount, pCfg->sAuthPath);
    xstrncpy(pCfg->sApiToken, sizeof(pCfg->sApiToken), pAccount->sAccessToken);

    if (DirectGate_Devices_Fetch(pList, pCfg->sApiUrl, pCfg->sApiToken, sError, sizeof(sError)))
        return XTRUE;

    xloge("Failed to list devices: %s", sError);
    return XFALSE;
}

/*
 * Turns "which device?" into a concrete device id: an explicit -d / trailing
 * argument is matched against the account list, and with nothing given the
 * arrow-key picker runs. Fills in the config's device id and name, or fails
 * when nothing matched, nothing was picked, or the match cannot be connected.
 */
static const directgate_device_t* DirectGate_Client_ResolveDevice(directgate_cfg_t *pCfg,
                                                                  const directgate_device_list_t *pList,
                                                                  const char *pPurpose)
{
    if (!pList->nCount)
    {
        xloge("No devices on this account yet. Add one from %s first.", pCfg->sWebUrl);
        return NULL;
    }

    int nIndex = DIRECTGATE_DEVICE_NO_PICK;

    if (xstrused(pCfg->sDeviceQuery))
    {
        nIndex = DirectGate_Devices_Find(pList, pCfg->sDeviceQuery);
        if (nIndex == DIRECTGATE_DEVICE_NO_PICK)
        {
            xloge("No device matches '%s'. Known devices:", pCfg->sDeviceQuery);
            DirectGate_Devices_Print(pList);
            return NULL;
        }
    }
    else
    {
        nIndex = DirectGate_Devices_Select(pList, pPurpose);
        if (nIndex < 0)
        {
            xlogn("No device selected");
            return NULL;
        }
    }

    const directgate_device_t *pDevice = &pList->devices[nIndex];
    if (!pDevice->bConnectable)
    {
        xloge("Device '%s' cannot be connected: %s", pDevice->sName,
            xstrused(pDevice->sReason) ? pDevice->sReason : "unavailable");

        return NULL;
    }

    if (!pDevice->bOnline) xlogw("Device '%s' looks offline, connecting anyway", pDevice->sName);

    xstrncpy(pCfg->sDeviceId, sizeof(pCfg->sDeviceId), pDevice->sId);
    xstrncpy(pCfg->sDeviceName, sizeof(pCfg->sDeviceName), pDevice->sName);

    printf("\n  %s %s...\n\n", pCfg->bAddKey ? "Authorizing the key on" : "Connecting to", pDevice->sName);
    return pDevice;
}

/*
 * Everything that has to happen before the relay socket is opened: sign in,
 * choose a device and collect its password. Returns XSTDNON when the command
 * was a standalone one (login / logout / devices / whoami) that is already
 * finished, XSTDERR on failure and XSTDOK when the client should connect.
 */
static XSTATUS DirectGate_Client_Prepare(directgate_ctx_t *pCli, directgate_cfg_t *pCfg, directgate_account_t *pAccount)
{
    directgate_login_ctx_t login;
    DirectGate_Client_LoginContext(&login, pCfg);

    if (pCfg->bGenKey) return DirectGate_Client_GenerateKey(pCfg);

    /*
        Authorizes a key rather than opening a shell. Loading it first
        makes a missing key fail immediately: there is no point signing in
        and picking a device to add a key that is not there.
    */
    if (pCfg->bAddKey && !DirectGate_Client_LoadKeyToAdd(pCli, pCfg)) return XSTDERR;

    if (pCfg->eCommand == DIRECTGATE_CMD_LOGOUT)
    {
        if (!DirectGate_Account_Forget(pCfg->sAuthPath))
        {
            xloge("Failed to remove the stored session: %s", pCfg->sAuthPath);
            return XSTDERR;
        }

        printf("  Signed out.\n");
        return XSTDNON;
    }

    if (pCfg->eCommand == DIRECTGATE_CMD_LOGIN)
    {
        /* An explicit login always re-runs the browser flow, so a stale or
         * wrong-account session can be replaced without logging out first. */
        if (!DirectGate_Login_Interactive(pAccount, &login)) return XSTDERR;

        if (!DirectGate_Account_Save(pAccount, pCfg->sAuthPath))
        {
            xloge("Failed to store the session: %s", pCfg->sAuthPath);
            return XSTDERR;
        }

        return XSTDNON;
    }

    /*
        A configured apiToken is an explicit override for automation: it
        replaces the account session entirely and never opens a browser.
    */
    xbool_t bManualToken = xstrused(pCfg->sApiToken) ? XTRUE : XFALSE;
    if (!bManualToken)
    {
        xbool_t bInteractive = DirectGate_Client_IsInteractive();
        if (!DirectGate_Login_Ensure(pAccount, &login, pCfg->sAuthPath, bInteractive)) return XSTDERR;

        xstrncpy(pCfg->sApiToken, sizeof(pCfg->sApiToken), pAccount->sAccessToken);
    }

    if (pCfg->eCommand == DIRECTGATE_CMD_WHOAMI)
    {
        printf("  %s\n", xstrused(pAccount->sEmail) ? pAccount->sEmail :
            (bManualToken ? "signed in with a configured API token" : "signed in"));

        return XSTDNON;
    }

    directgate_device_list_t devices;
    if (!DirectGate_Client_LoadDevices(&devices, pCfg, bManualToken ? NULL : pAccount, &login))
        return XSTDERR;

    if (pCfg->eCommand == DIRECTGATE_CMD_DEVICES)
    {
        if (!devices.nCount) printf("  No devices on this account yet.\n");
        else DirectGate_Devices_Print(&devices);

        return XSTDNON;
    }

    const directgate_device_t *pDevice = DirectGate_Client_ResolveDevice(pCfg, &devices, pCfg->bAddKey ? "authorize this key on" : "connect to");
    if (pDevice == NULL) return XSTDERR;

    /*
        A key file holds a single identity, so in -a mode the key being added
        is the one that would authenticate - and it is not authorized yet.
        The password is what proves ownership here, the same way ssh-copy-id
        works.
    */
    if (!pCfg->bAddKey) DirectGate_Client_PrepareKeyAuth(pCli, pCfg, pDevice);

    /* An explicit -k means the user asked for that key specifically, so a
     * silent downgrade to the password would be the wrong answer. */
    if (!pCli->bUseKeyAuth && !pCfg->bAddKey && pCfg->bKeyRequired)
    {
        xloge("Client key is unusable and -k was given, refusing to fall back");
        return XSTDERR;
    }

    if (!pCli->bUseKeyAuth && !DirectGate_PromptDeviceSecret(pCfg, pCfg->sDeviceName))
    {
        xloge("A device password is required to authenticate");
        return XSTDERR;
    }

    return XSTDOK;
}

/*
 * One connection attempt: mint a relay envelope, wire up the endpoints and
 * service them until the session ends. Run twice at most - a host that
 * refuses the client key sends us back here to authenticate with the
 * password instead.
 */
static XSTATUS DirectGate_Client_Run(directgate_ctx_t *pClient, directgate_cfg_t *pArgs)
{
    /* Relay URL, browser JWT, routing key and ICE servers in one call */
    if (xstrused(pArgs->sApiUrl) && xstrused(pArgs->sApiToken))
    {
        xlogi("Fetching relay connection envelope from API: %s", pArgs->sApiUrl);
        if (!DirectGate_Relay_FetchEnvelope(pArgs))
        {
            xloge("Failed to fetch relay connection envelope");
            return XSTDERR;
        }
    }

    xapi_t api;
    xlink_t link;
    XAPI_Init(&api, DirectGate_Client_ServiceCallback, pClient);

    if (!xstrused(pArgs->sSignalingUrl))
    {
        xloge("Signaling URL is required");
        return XSTDERR;
    }

    if (XLink_Parse(&link, pArgs->sSignalingUrl) < 0)
    {
        xloge("Failed to parse URL: %s", pArgs->sSignalingUrl);
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
    endpt.pSessionData = pClient;

    if (XAPI_AddEndpoint(&api, &endpt) < 0)
    {
        XAPI_Destroy(&api);
        return XSTDERR;
    }

    xapi_endpoint_t stdinEndpt;
    XAPI_InitEndpoint(&stdinEndpt);

    stdinEndpt.eType = XAPI_EVENT;
    stdinEndpt.eRole = XAPI_CUSTOM;
    stdinEndpt.nEvents = XPOLLIN;
    stdinEndpt.bUnix = XTRUE;
    stdinEndpt.pSessionData = pClient;

    /*
        XAPI owns and closes every endpoint socket it is handed, and an
        attempt that ends tears the whole API down. Handing it the real
        stdin would therefore close fd 0 - which used to be harmless at
        exit, but now leaves the key-auth fallback with no terminal to read
        the password from. Both platforms give it a disposable handle.
    */
#ifdef _WIN32
    if (XSock_CreatePair(g_nStdinBridge) != XSTDOK)
    {
        xloge("Failed to create stdin bridge socket pair: error(%d)", WSAGetLastError());
        XAPI_Destroy(&api);
        return XSTDERR;
    }

    u_long nNonBlock = 1;
    ioctlsocket(g_nStdinBridge[0], FIONBIO, &nNonBlock);

    HANDLE hStdinPump = CreateThread(NULL, 0, DirectGate_Client_StdinPump, NULL, 0, NULL);
    if (hStdinPump == NULL)
    {
        xloge("Failed to start stdin pump thread: error(%lu)", GetLastError());
        XAPI_Destroy(&api);
        return XSTDERR;
    }

    stdinEndpt.nFD = g_nStdinBridge[0];
#else
    int nStdinFd = dup(STDIN_FILENO);
    if (nStdinFd < 0)
    {
        xloge("Failed to duplicate stdin: errno(%d)", errno);
        XAPI_Destroy(&api);
        return XSTDERR;
    }

    stdinEndpt.nFD = nStdinFd;
#endif

    if (XAPI_AddEndpoint(&api, &stdinEndpt) < 0)
    {
        XAPI_Destroy(&api);
        return XSTDERR;
    }

    int nPipeFd = DirectGate_WebRTC_GetPipeFd(&pClient->webrtc);
    if (nPipeFd >= 0)
    {
        xapi_endpoint_t pipeEndpt;
        XAPI_InitEndpoint(&pipeEndpt);

        pipeEndpt.eType = XAPI_EVENT;
        pipeEndpt.eRole = XAPI_CUSTOM;
        pipeEndpt.nFD = nPipeFd;
        pipeEndpt.nEvents = XPOLLIN;
        pipeEndpt.bUnix = XTRUE;
        pipeEndpt.pSessionData = pClient;

        if (XAPI_AddEndpoint(&api, &pipeEndpt) < 0)
            xlogw("Failed to register WebRTC notification pipe");
    }

    xevent_status_t status;
    do status = XAPI_Service(&api, 100);
    while (status == XEVENTS_SUCCESS && !g_bFinish);

    DirectGate_Client_RestoreIO(&pClient->io);

    /*
        Never exit without saying why. Everything the teardown logs is at
        note level, which the default verbosity hides, so a session dropped
        before authentication left the terminal with no output at all -
        indistinguishable from a crash. This one prints unconditionally.
    */
    if (!pClient->bAuthDone && !pClient->bKeyAuthFailed)
    {
        printf("\n  The session ended before authentication completed.\n");
        printf("  Re-run with -v 5 to see the exchange.\n\n");

        xlogn("Session ended unauthenticated: status(%d), relay(%s)",
            (int)status, pArgs->sSignalingUrl);
    }

    pClient->pPipeSession = NULL;
    DirectGate_WebRTC_Clear(&pClient->webrtc);

#ifdef _WIN32
    /*
        The pump thread blocks in ReadFile on the console, so it has to be
        unblocked before the next prompt or it would swallow the password
        the user types for the fallback.
    */
    CancelIoEx(GetStdHandle(STD_INPUT_HANDLE), NULL);
    WaitForSingleObject(hStdinPump, 1000);
    CloseHandle(hStdinPump);
#endif

    XAPI_Destroy(&api);
    return XSTDOK;
}

int main(int argc, char* argv[])
{
    xlog_defaults();
    xlog_coloring(XFALSE);
    xlog_timing(XLOG_TIME);
    xlog_indent(XTRUE);
    xlog_setfl(XLOG_FATAL | XLOG_ERROR | XLOG_WARN);

    /*
        SIGWINCH is deliberately left alone until the PTY session exists.
        The sign-in and device-picker loops below block in poll()/read()
        with no SA_RESTART, so a terminal resize registered this early
        would surface there as an interrupt and cancel the sign-in.
    */
#ifdef _WIN32
    /* No SIGPIPE/SIGWINCH on Windows: resize is polled on the loop tick */
    int nSignals[2] = { SIGTERM, SIGINT };
    XSig_Register(nSignals, 2, DirectGate_Client_SignalCallback);
#else
    int nSignals[3] = { SIGTERM, SIGINT, SIGPIPE };
    XSig_Register(nSignals, 3, DirectGate_Client_SignalCallback);
#endif

    /* Before the first relay or API connection; see common.c. */
    DirectGate_InitTrustStore();

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
        /* -i and -s finish their work inside the parser */
        XLog_Destroy();
        return XSTDNON;
    }

    xlogn("Starting directgate client v%s", DirectGate_GetVersionLong());
    xlogn("libxutils v%s", XUtils_Version());

    client.pCfg = &args;
    client.bAuthDone = XFALSE;

    /*
        Sign in, list the account's devices and pick one. Standalone
        commands (login / logout / devices / whoami) finish here.
    */
    directgate_account_t account;
    DirectGate_Account_Init(&account);

    nStatus = DirectGate_Client_Prepare(&client, &args, &account);
    if (nStatus != XSTDOK)
    {
        DirectGate_Account_Cleanse(&account);
        DirectGate_Client_CleanseSecret(&args);
        XLog_Destroy();

        return nStatus == XSTDNON ? XSTDNON : XSTDERR;
    }

    /* The relay envelope carries its own short-lived JWT from here on */
    DirectGate_Account_Cleanse(&account);

#ifndef _WIN32
    /* Safe to watch for resizes now that the interactive prompts are done */
    int nWinch = SIGWINCH;
    XSig_Register(&nWinch, 1, DirectGate_Client_SignalCallback);
#endif

    int nResult = XSTDNON;

    for (;;)
    {
        if (DirectGate_Client_Run(&client, &args) != XSTDOK)
        {
            nResult = XSTDERR;
            break;
        }

        /* The host accepted the handshake or ended the session: done either
         * way. Only an explicitly refused key sends us round again. */
        if (!client.bKeyAuthFailed)
        {
            if (args.bAddKey && !client.bAddKeyDone) nResult = XSTDERR;
            break;
        }

        client.bKeyAuthFailed = XFALSE;
        client.bUseKeyAuth = XFALSE;
        DirectGate_KeyAuth_KeyCleanse(&client.key);

        if (!DirectGate_PromptDeviceSecret(&args, args.sDeviceName))
        {
            xloge("A device password is required to authenticate");
            nResult = XSTDERR;
            break;
        }

        /* Fresh transport state for the second attempt; the previous one
         * tore its own down when the socket closed. */
        g_bFinish = XFALSE;
        DirectGate_Client_Init(&client);
        client.pCfg = &args;
    }

    DirectGate_Client_RestoreIO(&client.io);
    DirectGate_Client_CleanseSecret(&args);
    DirectGate_KeyAuth_KeyCleanse(&client.key);

    DirectGate_WebRTC_Clear(&client.webrtc);
    DirectGate_WebRTC_Cleanup();

    XLog_Destroy();
    return nResult;
}
