/*!
 * @file directgate-agent/src/client/remote.c
 * @brief Non-interactive remote operations: commands and file management.
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

#include "remote.h"
#include "common.h"

#ifdef _WIN32
#include <io.h>
#define DIRECTGATE_REMOTE_WRITE(fd, buf, len) _write(fd, buf, (unsigned int)(len))
#define DIRECTGATE_REMOTE_READ(fd, buf, len) _read(fd, buf, (unsigned int)(len))
#else
#define DIRECTGATE_REMOTE_WRITE(fd, buf, len) write(fd, buf, len)
#define DIRECTGATE_REMOTE_READ(fd, buf, len) read(fd, buf, len)
#endif

static const struct {
    const char *pName;
    directgate_remote_op_t eOp;
} g_remoteOps[] = {
    { "exec", DIRECTGATE_REMOTE_EXEC },
    { "cp", DIRECTGATE_REMOTE_COPY },
    { "rm", DIRECTGATE_REMOTE_REMOVE },
    { "mkdir", DIRECTGATE_REMOTE_MKDIR },
    { "mv", DIRECTGATE_REMOTE_MOVE },
    { "session", DIRECTGATE_REMOTE_SESSION }
};

xbool_t DirectGate_Remote_ParseOp(const char *pArg, directgate_remote_op_t *pOp)
{
    XCHECK_NL((xstrused(pArg)), XFALSE);

    for (size_t i = 0; i < XARR_SIZE(g_remoteOps); i++)
    {
        if (strcmp(pArg, g_remoteOps[i].pName)) continue;
        if (pOp != NULL) *pOp = g_remoteOps[i].eOp;
        return XTRUE;
    }

    return XFALSE;
}

const char* DirectGate_Remote_OpName(directgate_remote_op_t eOp)
{
    /* Named as typed: "ls" lists a directory, and both directions of a copy are "cp" */
    if (eOp == DIRECTGATE_REMOTE_LIST) return "ls";
    if (eOp == DIRECTGATE_REMOTE_GET || eOp == DIRECTGATE_REMOTE_PUT) return "cp";

    for (size_t i = 0; i < XARR_SIZE(g_remoteOps); i++)
        if (g_remoteOps[i].eOp == eOp) return g_remoteOps[i].pName;

    return "remote";
}

static xbool_t DirectGate_Remote_WriteAll(int nFd, const uint8_t *pData, size_t nLength)
{
    while (nLength > 0)
    {
        int nChunk = nLength > (size_t)INT_MAX ? INT_MAX : (int)nLength;
        int nWritten = (int)DIRECTGATE_REMOTE_WRITE(nFd, pData, nChunk);

        if (nWritten < 0 && errno == EINTR) continue;
        if (nWritten <= 0) return XFALSE;

        pData += nWritten;
        nLength -= (size_t)nWritten;
    }

    return XTRUE;
}

/* Output of the operation: to its stream, or into a session's capture, of which at most nCaptureMax is kept */
static xbool_t DirectGate_Remote_Emit(directgate_remote_t *pRemote, xbool_t bStdErr, const uint8_t *pData, size_t nLength)
{
    xbyte_buffer_t *pCapture = bStdErr ? pRemote->pErrCapture : pRemote->pOutCapture;
    if (pCapture == NULL) return DirectGate_Remote_WriteAll(bStdErr ? pRemote->nErrFd : pRemote->nOutFd, pData, nLength);

    size_t nRoom = pCapture->nUsed < pRemote->nCaptureMax ? pRemote->nCaptureMax - pCapture->nUsed : 0;
    if (nLength > nRoom)
    {
        nLength = nRoom;
        pRemote->bTruncated = XTRUE;
    }

    return (!nLength || XByteBuffer_Add(pCapture, pData, nLength) > 0) ? XTRUE : XFALSE;
}

/* dgcli's own word about the operation, where its stderr goes */
static void DirectGate_Remote_Tell(directgate_remote_t *pRemote, const char *pFmt, ...)
{
    char sMessage[XSTR_MID];
    va_list args;

    va_start(args, pFmt);
    int nLength = vsnprintf(sMessage, sizeof(sMessage), pFmt, args);
    va_end(args);

    if (nLength <= 0) return;
    size_t nUsed = (size_t)nLength < sizeof(sMessage) ? (size_t)nLength : sizeof(sMessage) - 1;
    DirectGate_Remote_Emit(pRemote, XTRUE, (const uint8_t*)sMessage, nUsed);
}

static int DirectGate_Remote_FailCode(const directgate_remote_t *pRemote)
{
    /* A command's own codes are its program's, and a session's are the operations': dgcli failing is 255 for both */
    return (pRemote->pReq != NULL && (pRemote->pReq->eOp == DIRECTGATE_REMOTE_EXEC ||
            pRemote->pReq->eOp == DIRECTGATE_REMOTE_SESSION)) ? DIRECTGATE_REMOTE_EXIT_FAILED : DIRECTGATE_REMOTE_EXIT_ERROR;
}

/* Ends the operation as failed, after saying why on stderr. Always XAPI_DISCONNECT, for the callers' returns.
   A reason is often the host's or the relay's own words, so it reaches the terminal with no control characters. */
static int DirectGate_Remote_Fail(directgate_remote_t *pRemote, const char *pReason)
{
    if (!pRemote->bDone)
    {
        char sSafe[XSTR_MID];
        DirectGate_CopyDisplaySafe(sSafe, sizeof(sSafe), xstrused(pReason) ? pReason : "failed");
        DirectGate_Remote_Tell(pRemote, "dgcli: %s: %s\n", DirectGate_Remote_OpName(pRemote->pReq->eOp), sSafe);
    }

    pRemote->nExitCode = DirectGate_Remote_FailCode(pRemote);
    pRemote->bDone = XTRUE;
    return XAPI_DISCONNECT;
}

static int DirectGate_Remote_Succeed(directgate_remote_t *pRemote, int nExitCode)
{
    pRemote->nExitCode = nExitCode;
    pRemote->bDone = XTRUE;
    return XAPI_DISCONNECT;
}

static xbool_t DirectGate_Remote_IsAbsolute(const char *pPath)
{
    XCHECK_NL((xstrused(pPath)), XFALSE);
    if (pPath[0] == '/' || pPath[0] == '\\') return XTRUE;

    return (isalpha((unsigned char)pPath[0]) && pPath[1] == ':' && (pPath[2] == '/' || pPath[2] == '\\')) ? XTRUE : XFALSE;
}

/* The last component of a path, either separator; empty when the path ends with one. */
static const char* DirectGate_Remote_BaseName(const char *pPath)
{
    const char *pBase = pPath;
    for (const char *pChar = pPath; *pChar; pChar++)
        if (*pChar == '/' || *pChar == '\\') pBase = pChar + 1;

    return pBase;
}

static xbool_t DirectGate_Remote_IsUsableName(const char *pName)
{
    return (xstrused(pName) && strcmp(pName, ".") && strcmp(pName, "..")) ? XTRUE : XFALSE;
}

static xbool_t DirectGate_Remote_EndsWithSeparator(const char *pPath)
{
    size_t nLength = xstrused(pPath) ? strlen(pPath) : 0;
    return (nLength > 0 && (pPath[nLength - 1] == '/' || pPath[nLength - 1] == '\\')) ? XTRUE : XFALSE;
}

/* While a session request is parsed, what is wrong with it goes into its answer, not to the session's own stderr */
static char *g_pUsageSink;
static size_t g_nUsageSink;

static XSTATUS DirectGate_Remote_Usage(const char *pOp, const char *pMessage)
{
    if (g_pUsageSink != NULL) xstrncpyf(g_pUsageSink, g_nUsageSink, "dgcli: %s: %s\n", pOp, pMessage);
    else fprintf(stderr, "dgcli: %s: %s\n", pOp, pMessage);
    return XSTDERR;
}

static XSTATUS DirectGate_Remote_CopyPath(char *pDst, size_t nSize, const char *pSrc, const char *pOp, xbool_t bRemote)
{
    if (!xstrused(pSrc)) return DirectGate_Remote_Usage(pOp, "a path is empty");
    if (strlen(pSrc) >= nSize) return DirectGate_Remote_Usage(pOp, "a path is too long");
    if (bRemote && !DirectGate_Remote_IsAbsolute(pSrc)) return DirectGate_Remote_Usage(pOp, "remote paths must be absolute");

    xstrncpy(pDst, nSize, pSrc);
    return XSTDOK;
}

/*
    "device:/path" names a path on a device, the way scp does; anything else is local. A single letter before the
    colon is a Windows drive ("C:\dir"), and a separator before it makes it a local path ("./a:b"). XSTDOK for a
    remote path (device and path filled in), XSTDNON for a local one, XSTDERR for a device name too long to hold.
*/
static XSTATUS DirectGate_Remote_SplitSpec(const char *pArg, char *pDevice, size_t nDeviceSize, const char **ppPath)
{
    const char *pColon = strchr(pArg, ':');
    if (pColon == NULL || pColon - pArg < 2) return XSTDNON;

    for (const char *pChar = pArg; pChar < pColon; pChar++)
        if (*pChar == '/' || *pChar == '\\') return XSTDNON;

    size_t nLength = (size_t)(pColon - pArg);
    if (nLength >= nDeviceSize) return XSTDERR;

    memcpy(pDevice, pArg, nLength);
    pDevice[nLength] = '\0';
    *ppPath = pColon + 1;
    return XSTDOK;
}

/* A remote path: on the one device the operation is about, and absolute */
static XSTATUS DirectGate_Remote_TakeRemote(const char *pArg, char *pPath, size_t nPathSize,
                                            char *pDevice, size_t nDeviceSize, const char *pOp)
{
    char sDevice[XSTR_MID];
    const char *pRemote = NULL;
    XSTATUS nStatus = DirectGate_Remote_SplitSpec(pArg, sDevice, sizeof(sDevice), &pRemote);

    if (nStatus == XSTDERR) return DirectGate_Remote_Usage(pOp, "the device name is too long");
    if (nStatus != XSTDOK) return DirectGate_Remote_Usage(pOp, "name the remote side as <device>:<path>");
    if (strlen(sDevice) >= nDeviceSize) return DirectGate_Remote_Usage(pOp, "the device name is too long");
    if (xstrused(pDevice) && strcmp(pDevice, sDevice))
        return DirectGate_Remote_Usage(pOp, "both paths must be on the same device");
    if (!xstrused(pRemote)) return DirectGate_Remote_Usage(pOp, "a remote path is required after the device");

    xstrncpy(pDevice, nDeviceSize, sDevice);
    return DirectGate_Remote_CopyPath(pPath, nPathSize, pRemote, pOp, XTRUE);
}

XSTATUS DirectGate_Remote_ParseSize(const char *pArg, uint32_t *pBytes)
{
    XCHECK_NL((pArg != NULL && pBytes != NULL), XSTDINV);

    /* A digit first: strtoull would also take a sign - negating the number - or leading blanks. An overflow comes back
       as ULLONG_MAX, which the range check below refuses with the rest. */
    XCHECK_NL((pArg[0] >= '0' && pArg[0] <= '9'), XSTDERR);
    char *pEnd = NULL;
    unsigned long long nValue = strtoull(pArg, &pEnd, 10);

    uint64_t nScale = 1;
    if (*pEnd == 'K' || *pEnd == 'k') nScale = 1024ULL;
    else if (*pEnd == 'M' || *pEnd == 'm') nScale = 1024ULL * 1024ULL;
    else if (*pEnd == 'G' || *pEnd == 'g') nScale = 1024ULL * 1024ULL * 1024ULL;
    if (nScale > 1) pEnd++;

    XCHECK_NL((*pEnd == XSTR_NUL && nValue <= UINT32_MAX / nScale), XSTDERR);
    *pBytes = (uint32_t)(nValue * nScale);
    return XSTDOK;
}

/* Each option belongs to the operations it means something to; given to any other it is refused, never ignored */
XSTATUS DirectGate_Remote_CheckOptions(const directgate_remote_req_t *pReq, directgate_remote_op_t eOp)
{
    XCHECK_NL((pReq != NULL), XSTDINV);
    const char *pOp = DirectGate_Remote_OpName(eOp);

    if (pReq->bForce && eOp != DIRECTGATE_REMOTE_COPY)
        return DirectGate_Remote_Usage(pOp, "-f belongs to cp (replace the destination)");
    if (pReq->bRecursive && eOp != DIRECTGATE_REMOTE_REMOVE) return DirectGate_Remote_Usage(pOp, "-r belongs to rm");
    if (pReq->bJson && eOp != DIRECTGATE_REMOTE_LIST) return DirectGate_Remote_Usage(pOp, "-j belongs to ls");
    if (pReq->nTimeoutMs && eOp != DIRECTGATE_REMOTE_EXEC && eOp != DIRECTGATE_REMOTE_SESSION)
        return DirectGate_Remote_Usage(pOp, "-t belongs to exec and session");
    if ((xstrused(pReq->sCwd) || pReq->bOutputMax) && eOp != DIRECTGATE_REMOTE_EXEC)
        return DirectGate_Remote_Usage(pOp, "-C and -o belong to exec");

    return XSTDOK;
}

XSTATUS DirectGate_Remote_ParseArgs(directgate_remote_req_t *pReq, directgate_remote_op_t eOp, int argc, char *argv[],
                                    int nFirst, char *pDevice, size_t nDeviceSize)
{
    XCHECK_NL((pReq != NULL && argv != NULL && pDevice != NULL), XSTDINV);

    const char *pOp = DirectGate_Remote_OpName(eOp);
    int nArgs = argc > nFirst ? argc - nFirst : 0;
    char **ppArgs = argv + nFirst;
    pReq->eOp = eOp;

    if (DirectGate_Remote_CheckOptions(pReq, eOp) != XSTDOK) return XSTDERR;

    /* session <device>: its operations come later, one request at a time; -t shortens how long it may stay idle */
    if (eOp == DIRECTGATE_REMOTE_SESSION)
    {
        if (nArgs > 0) return DirectGate_Remote_Usage(pOp, "takes nothing after the device; operations come on stdin");
        if (pReq->nTimeoutMs > DIRECTGATE_REMOTE_IDLE_MS) return DirectGate_Remote_Usage(pOp, "-t is at most 600 seconds");
        return XSTDOK;
    }

    if (eOp == DIRECTGATE_REMOTE_EXEC)
    {
        /* "exec host -- ls -la": the separator belongs to dgcli, not to the command */
        if (nArgs > 0 && !strcmp(ppArgs[0], "--"))
        {
            ppArgs++;
            nArgs--;
        }

        if (nArgs < 1) return DirectGate_Remote_Usage(pOp, "a command is required");

        /* As ssh does: the words are joined by spaces and the remote shell parses the result */
        size_t nLength = 1;
        for (int i = 0; i < nArgs; i++) nLength += strlen(ppArgs[i]) + 1;
        if (nLength > DIRECTGATE_REMOTE_COMMAND_MAX) return DirectGate_Remote_Usage(pOp, "the command is too long");

        free(pReq->pCommand);
        pReq->pCommand = (char*)calloc(1, nLength);
        if (pReq->pCommand == NULL) return DirectGate_Remote_Usage(pOp, "out of memory");

        for (int i = 0; i < nArgs; i++)
        {
            if (i > 0) strcat(pReq->pCommand, " ");
            strcat(pReq->pCommand, ppArgs[i]);
        }

        if (!xstrused(pReq->pCommand)) return DirectGate_Remote_Usage(pOp, "a command is required");
        if (xstrused(pReq->sCwd) && !DirectGate_Remote_IsAbsolute(pReq->sCwd))
            return DirectGate_Remote_Usage(pOp, "remote paths must be absolute");

        return XSTDOK;
    }

    /* Every file operation names its device in the path; a device given on its own as well is one too many */
    if (xstrused(pDevice)) return DirectGate_Remote_Usage(pOp, "name the device in the path, as <device>:<path>");

    switch (eOp)
    {
        case DIRECTGATE_REMOTE_LIST:
        case DIRECTGATE_REMOTE_REMOVE:
        case DIRECTGATE_REMOTE_MKDIR:
            if (nArgs != 1) return DirectGate_Remote_Usage(pOp, "expects one <device>:<path>");
            return DirectGate_Remote_TakeRemote(ppArgs[0], pReq->sPath, sizeof(pReq->sPath), pDevice, nDeviceSize, pOp);
        case DIRECTGATE_REMOTE_COPY:
        {
            if (nArgs != 2)
                return DirectGate_Remote_Usage(pOp, "expects a source and a destination, one of them <device>:<path>");

            char sProbe[XSTR_MID];
            const char *pProbe = NULL;
            xbool_t bFromRemote = DirectGate_Remote_SplitSpec(ppArgs[0], sProbe, sizeof(sProbe), &pProbe) != XSTDNON;
            xbool_t bToRemote = DirectGate_Remote_SplitSpec(ppArgs[1], sProbe, sizeof(sProbe), &pProbe) != XSTDNON;

            if (bFromRemote == bToRemote)
                return DirectGate_Remote_Usage(pOp, "exactly one side is <device>:<path>, the other a local path or -");

            /* Which way the copy goes is which side names the device */
            pReq->eOp = bFromRemote ? DIRECTGATE_REMOTE_GET : DIRECTGATE_REMOTE_PUT;
            const char *pLocal = bFromRemote ? ppArgs[1] : ppArgs[0];
            const char *pRemote = bFromRemote ? ppArgs[0] : ppArgs[1];

            if (DirectGate_Remote_CopyPath(pReq->sLocal, sizeof(pReq->sLocal), pLocal, pOp, XFALSE) != XSTDOK) return XSTDERR;
            return DirectGate_Remote_TakeRemote(pRemote, pReq->sPath, sizeof(pReq->sPath), pDevice, nDeviceSize, pOp);
        }
        case DIRECTGATE_REMOTE_MOVE:
        {
            if (nArgs != 2) return DirectGate_Remote_Usage(pOp, "expects <device>:<path> and where it goes");
            if (DirectGate_Remote_TakeRemote(ppArgs[0], pReq->sPath, sizeof(pReq->sPath), pDevice, nDeviceSize, pOp) != XSTDOK)
                return XSTDERR;

            /* The target is on the same device: "<device>:/new" or just "/new" */
            char sProbe[XSTR_MID];
            const char *pProbe = NULL;
            if (DirectGate_Remote_SplitSpec(ppArgs[1], sProbe, sizeof(sProbe), &pProbe) != XSTDNON)
                return DirectGate_Remote_TakeRemote(ppArgs[1], pReq->sTarget, sizeof(pReq->sTarget), pDevice, nDeviceSize, pOp);

            return DirectGate_Remote_CopyPath(pReq->sTarget, sizeof(pReq->sTarget), ppArgs[1], pOp, XTRUE);
        }
        default:
            break;
    }

    return DirectGate_Remote_Usage(pOp, "unknown operation");
}

/* A session request's options: the command line's, before the operands, each value the next word */
static XSTATUS DirectGate_Remote_RequestOptions(directgate_remote_req_t *pReq, char **ppWords, int nWords, int *pArg)
{
    int nArg = *pArg;

    while (nArg < nWords && ppWords[nArg][0] == '-' && strcmp(ppWords[nArg], "-"))
    {
        const char *pWord = ppWords[nArg++];
        if (!strcmp(pWord, "--")) break;

        if (!strcmp(pWord, "-f")) pReq->bForce = XTRUE;
        else if (!strcmp(pWord, "-r")) pReq->bRecursive = XTRUE;
        else if (!strcmp(pWord, "-j")) pReq->bJson = XTRUE;
        else if (nArg < nWords && !strcmp(pWord, "-t"))
        {
            char *pEnd = NULL;
            const char *pValue = ppWords[nArg++];
            unsigned long nSeconds = strtoul(pValue, &pEnd, 10);
            if (pValue[0] < '0' || pValue[0] > '9' || *pEnd != XSTR_NUL || nSeconds > DIRECTGATE_REMOTE_TIMEOUT_MAX)
                return DirectGate_Remote_Usage("session", "-t takes whole seconds");
            pReq->nTimeoutMs = (uint32_t)nSeconds * 1000U;
        }
        else if (nArg < nWords && !strcmp(pWord, "-C"))
        {
            const char *pValue = ppWords[nArg++];
            if (strlen(pValue) >= sizeof(pReq->sCwd)) return DirectGate_Remote_Usage("session", "-C is too long");
            xstrncpy(pReq->sCwd, sizeof(pReq->sCwd), pValue);
        }
        else if (nArg < nWords && !strcmp(pWord, "-o"))
        {
            if (DirectGate_Remote_ParseSize(ppWords[nArg++], &pReq->nOutputMax) != XSTDOK)
                return DirectGate_Remote_Usage("session", "-o takes a number of bytes");
            pReq->bOutputMax = XTRUE;
        }
        else return DirectGate_Remote_Usage("session", "not an option of an operation, or one without its value");
    }

    *pArg = nArg;
    return XSTDOK;
}

XSTATUS DirectGate_Remote_ParseRequest(directgate_remote_req_t *pReq, const char *pLine, size_t nLength,
                                       const char *pDevice, xbyte_buffer_t *pStdin, size_t *pMax,
                                       char *pError, size_t nErrorSize)
{
    XCHECK_NL((pReq != NULL && pLine != NULL && pDevice != NULL && pStdin != NULL), XSTDINV);
    XCHECK_NL((pMax != NULL && pError != NULL && nErrorSize > 0), XSTDINV);

    DirectGate_Remote_ReqClear(pReq);
    *pMax = DIRECTGATE_REMOTE_CAPTURE_MAX;
    pError[0] = XSTR_NUL;

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, pLine, nLength))
    {
        xstrncpy(pError, nErrorSize, "dgcli: session: a request is one line of JSON\n");
        return XSTDERR;
    }

    g_pUsageSink = pError;
    g_nUsageSink = nErrorSize;
    XSTATUS nStatus = XSTDERR;

    do
    {
        xjson_obj_t *pRoot = json.pRootObj;
        xjson_obj_t *pArgv = XJSON_GetObject(pRoot, "argv");
        size_t nWords = (pArgv != NULL && pArgv->nType == XJSON_TYPE_ARRAY) ? XJSON_GetArrayLength(pArgv) : 0;

        if (!nWords || nWords > DIRECTGATE_REMOTE_REQUEST_WORDS)
        {
            DirectGate_Remote_Usage("session", "argv is a list of up to 64 words");
            break;
        }

        char *pWords[DIRECTGATE_REMOTE_REQUEST_WORDS + 1];
        size_t nWord = 0;

        for (; nWord < nWords; nWord++)
        {
            xjson_obj_t *pWord = XJSON_GetArrayItem(pArgv, nWord);
            if (pWord == NULL || pWord->nType != XJSON_TYPE_STRING) break;
            pWords[nWord] = (char*)XJSON_GetString(pWord);
        }

        pWords[nWord] = NULL;
        if (nWord < nWords)
        {
            DirectGate_Remote_Usage("session", "every word of argv is a string");
            break;
        }

        directgate_remote_op_t eOp = DIRECTGATE_REMOTE_NONE;
        if (!strcmp(pWords[0], "ls")) eOp = DIRECTGATE_REMOTE_LIST;
        else if (!DirectGate_Remote_ParseOp(pWords[0], &eOp) || eOp == DIRECTGATE_REMOTE_SESSION)
        {
            DirectGate_Remote_Usage("session", "the first word is the operation: exec, cp, ls, rm, mkdir or mv");
            break;
        }

        int nArg = 1;
        if (DirectGate_Remote_RequestOptions(pReq, pWords, (int)nWords, &nArg) != XSTDOK) break;

        /* exec names its device first, the file operations in <device>:<path>: either way it is the session's */
        char sDevice[XSTR_MID];
        sDevice[0] = XSTR_NUL;

        if (eOp == DIRECTGATE_REMOTE_EXEC)
        {
            if (nArg >= (int)nWords)
            {
                DirectGate_Remote_Usage("exec", "a device is required");
                break;
            }

            xstrncpy(sDevice, sizeof(sDevice), pWords[nArg++]);
        }

        if (DirectGate_Remote_ParseArgs(pReq, eOp, (int)nWords, pWords, nArg, sDevice, sizeof(sDevice)) != XSTDOK) break;
        if (strcmp(sDevice, pDevice))
        {
            DirectGate_Remote_Usage(DirectGate_Remote_OpName(pReq->eOp), "a session reaches its own device only");
            break;
        }

        xjson_obj_t *pStdinObj = XJSON_GetObject(pRoot, "stdin");
        xbool_t bFromStdin = (pReq->eOp == DIRECTGATE_REMOTE_PUT && !strcmp(pReq->sLocal, "-")) ? XTRUE : XFALSE;

        if (pStdinObj != NULL)
        {
            const char *pText = pStdinObj->nType == XJSON_TYPE_STRING ? XJSON_GetString(pStdinObj) : NULL;
            if (pText == NULL || (pReq->eOp != DIRECTGATE_REMOTE_EXEC && !bFromStdin))
            {
                DirectGate_Remote_Usage(DirectGate_Remote_OpName(pReq->eOp), "stdin is a string, for exec and cp -");
                break;
            }

            size_t nText = strlen(pText);
            if (nText && XByteBuffer_Add(pStdin, (const uint8_t*)pText, nText) <= 0)
            {
                DirectGate_Remote_Usage(DirectGate_Remote_OpName(pReq->eOp), "out of memory");
                break;
            }

            if (pReq->eOp == DIRECTGATE_REMOTE_EXEC) pReq->bStdin = XTRUE;
        }

        xjson_obj_t *pMaxObj = XJSON_GetObject(pRoot, "max");
        if (pMaxObj != NULL)
        {
            uint64_t nMax = pMaxObj->nType == XJSON_TYPE_NUMBER ? XJSON_GetU64(pMaxObj) : 0;
            if (!nMax || nMax > DIRECTGATE_REMOTE_CAPTURE_MAX)
            {
                DirectGate_Remote_Usage("session", "max is a number of bytes, from 1 to 16 MB");
                break;
            }

            *pMax = (size_t)nMax;
        }

        nStatus = XSTDOK;
    }
    while (0);

    g_pUsageSink = NULL;
    g_nUsageSink = 0;
    XJSON_Destroy(&json);

    if (nStatus != XSTDOK) DirectGate_Remote_ReqClear(pReq);
    return nStatus;
}

XSTATUS DirectGate_Remote_WriteReady(int nFd)
{
    static const char sReady[] = "{\"ready\":true}\n";
    return DirectGate_Remote_WriteAll(nFd, (const uint8_t*)sReady, sizeof(sReady) - 1) ? XSTDOK : XSTDERR;
}

XSTATUS DirectGate_Remote_WriteResponse(int nFd, int nExitCode, const xbyte_buffer_t *pOut, const xbyte_buffer_t *pErr,
                                        xbool_t bTruncated)
{
    size_t nOut = pOut != NULL ? pOut->nUsed : 0;
    size_t nErr = pErr != NULL ? pErr->nUsed : 0;

    char sHeader[XSTR_TINY];
    int nHeader = snprintf(sHeader, sizeof(sHeader), "{\"exitCode\":%d,\"stdout\":%zu,\"stderr\":%zu,\"truncated\":%s}\n",
        nExitCode, nOut, nErr, bTruncated ? "true" : "false");

    XCHECK_NL((nHeader > 0 && (size_t)nHeader < sizeof(sHeader)), XSTDERR);
    if (!DirectGate_Remote_WriteAll(nFd, (const uint8_t*)sHeader, (size_t)nHeader)) return XSTDERR;
    if (nOut && !DirectGate_Remote_WriteAll(nFd, pOut->pData, nOut)) return XSTDERR;
    if (nErr && !DirectGate_Remote_WriteAll(nFd, pErr->pData, nErr)) return XSTDERR;
    return XSTDOK;
}

void DirectGate_Remote_ReqClear(directgate_remote_req_t *pReq)
{
    XCHECK_VOID_NL((pReq != NULL));
    free(pReq->pCommand);
    memset(pReq, 0, sizeof(*pReq));
}

void DirectGate_Remote_Init(directgate_remote_t *pRemote, const directgate_remote_req_t *pReq,
                            directgate_remote_send_fn sendFn, void *pSendCtx)
{
    XCHECK_VOID_NL((pRemote != NULL));
    memset(pRemote, 0, sizeof(*pRemote));

    pRemote->pReq = pReq;
    pRemote->sendFn = sendFn;
    pRemote->pSendCtx = pSendCtx;
    pRemote->nOutFd = 1;
    pRemote->nErrFd = 2;

    DirectGate_Transfer_Init(&pRemote->transfer);

    /* Until the operation completes, ending is a failure */
    pRemote->nExitCode = DirectGate_Remote_FailCode(pRemote);
}

static void DirectGate_Remote_RemoveFile(char *pPath, size_t nSize)
{
    if (!xstrused(pPath)) return;
    remove(pPath);
    memset(pPath, 0, nSize);
}

void DirectGate_Remote_Clear(directgate_remote_t *pRemote)
{
    XCHECK_VOID_NL((pRemote != NULL));

    /* An inbound transfer that never verified removes its own partial file */
    DirectGate_Transfer_Destroy(&pRemote->transfer);
    DirectGate_Remote_RemoveFile(pRemote->sTempPath, sizeof(pRemote->sTempPath));
    DirectGate_Remote_RemoveFile(pRemote->sSpoolPath, sizeof(pRemote->sSpoolPath));
}

static void DirectGate_Remote_RandomHex(char *pOut, size_t nSize)
{
    uint8_t sRandom[8];
    if (RAND_bytes(sRandom, sizeof(sRandom)) != 1)
    {
        uint64_t nSeed = XTime_GetMs() ^ ((uint64_t)(uintptr_t)pOut << 16);
        memcpy(sRandom, &nSeed, sizeof(sRandom));
    }

    static const char sHex[] = "0123456789abcdef";
    size_t nPos = 0;

    for (size_t i = 0; i < sizeof(sRandom) && nPos + 2 < nSize; i++)
    {
        pOut[nPos++] = sHex[sRandom[i] >> 4];
        pOut[nPos++] = sHex[sRandom[i] & 0x0f];
    }

    pOut[nPos] = '\0';
}

static void DirectGate_Remote_TempDir(char *pOut, size_t nSize)
{
#ifdef _WIN32
    DWORD nLength = GetTempPathA((DWORD)nSize, pOut);
    if (nLength == 0 || nLength >= nSize) xstrncpy(pOut, nSize, ".\\");
#else
    const char *pTmp = getenv("TMPDIR");
    xstrncpyf(pOut, nSize, "%s/", xstrused(pTmp) ? pTmp : "/tmp");
#endif
}

/* Creates a private file that did not exist, for put - to collect stdin into. */
static int DirectGate_Remote_CreatePrivate(char *pPath, size_t nSize)
{
    char sDir[XPATH_MAX], sRandom[32];
    DirectGate_Remote_TempDir(sDir, sizeof(sDir));

    for (int nTry = 0; nTry < 8; nTry++)
    {
        DirectGate_Remote_RandomHex(sRandom, sizeof(sRandom));
        xstrncpyf(pPath, nSize, "%sdgcli-put-%s", sDir, sRandom);

#ifdef _WIN32
        int nFd = -1;
        if (_sopen_s(&nFd, pPath, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY | _O_NOINHERIT,
            _SH_DENYRW, _S_IREAD | _S_IWRITE) == 0 && nFd >= 0) return nFd;
#else
        int nFd = open(pPath, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (nFd >= 0) return nFd;
#endif
        if (errno != EEXIST) break;
    }

    pPath[0] = '\0';
    return XSTDERR;
}

static XSTATUS DirectGate_Remote_SpoolStdin(directgate_remote_t *pRemote)
{
    int nFd = DirectGate_Remote_CreatePrivate(pRemote->sSpoolPath, sizeof(pRemote->sSpoolPath));
    if (nFd < 0) return XSTDERR;

    /* A session's operation: its stdin came with the request, and the process's own stdin carries the requests */
    if (pRemote->pOutCapture != NULL)
    {
        xbool_t bWritten = (!pRemote->nStdinData || DirectGate_Remote_WriteAll(nFd, pRemote->pStdinData, pRemote->nStdinData));
#ifdef _WIN32
        if (_close(nFd) != 0) bWritten = XFALSE;
#else
        if (close(nFd) != 0) bWritten = XFALSE;
#endif
        return bWritten ? XSTDOK : XSTDERR;
    }

#ifdef _WIN32
    _setmode(0, _O_BINARY);
#endif

    uint8_t sBuffer[XFILE_CHUNK_SIZE];
    xbool_t bOk = XTRUE;

    for (;;)
    {
        int nRead = (int)DIRECTGATE_REMOTE_READ(0, sBuffer, sizeof(sBuffer));
        if (nRead < 0 && errno == EINTR) continue;
        if (nRead < 0) bOk = XFALSE;
        if (nRead <= 0) break;

        if (!DirectGate_Remote_WriteAll(nFd, sBuffer, (size_t)nRead))
        {
            bOk = XFALSE;
            break;
        }
    }

#ifdef _WIN32
    if (_close(nFd) != 0) bOk = XFALSE;
#else
    if (close(nFd) != 0) bOk = XFALSE;
#endif

    return bOk ? XSTDOK : XSTDERR;
}

static xbool_t DirectGate_Remote_IsDirectory(const char *pPath)
{
    struct stat st;
    return (stat(pPath, &st) == 0 && S_ISDIR(st.st_mode)) ? XTRUE : XFALSE;
}

static XSTATUS DirectGate_Remote_PrepareGet(directgate_remote_t *pRemote)
{
    const directgate_remote_req_t *pReq = pRemote->pReq;
    const char *pName = DirectGate_Remote_BaseName(pReq->sPath);
    char sRandom[32];
    DirectGate_Remote_RandomHex(sRandom, sizeof(sRandom));

    if (xstrcmp(pReq->sLocal, "-"))
    {
        /* For stdout: verified in a private file first, never streamed out unverified */
        char sDir[XPATH_MAX];
        DirectGate_Remote_TempDir(sDir, sizeof(sDir));
        xstrncpyf(pRemote->sTempPath, sizeof(pRemote->sTempPath), "%sdgcli-get-%s", sDir, sRandom);
        return XSTDOK;
    }

    if (!xstrused(pReq->sLocal) || DirectGate_Remote_EndsWithSeparator(pReq->sLocal) ||
        DirectGate_Remote_IsDirectory(pReq->sLocal))
    {
        /* The remote file's own name, as the user typed it - never the name the host announces */
        if (!DirectGate_Remote_IsUsableName(pName))
        {
            DirectGate_Remote_Tell(pRemote, "dgcli: cp: %s does not name a file; give a local name\n", pReq->sPath);
            return XSTDERR;
        }

        const char *pDir = xstrused(pReq->sLocal) ? pReq->sLocal : ".";
        const char *pSep = DirectGate_Remote_EndsWithSeparator(pDir) ? "" : "/";
        xstrncpyf(pRemote->sFinalPath, sizeof(pRemote->sFinalPath), "%s%s%s", pDir, pSep, pName);
    }
    else
    {
        xstrncpy(pRemote->sFinalPath, sizeof(pRemote->sFinalPath), pReq->sLocal);
    }

    /* Next to the destination, so the final rename never crosses a file system */
    if ((size_t)xstrncpyf(pRemote->sTempPath, sizeof(pRemote->sTempPath), "%s.dgpart-%s",
        pRemote->sFinalPath, sRandom) + 1 >= sizeof(pRemote->sTempPath))
    {
        DirectGate_Remote_Tell(pRemote, "dgcli: cp: the local path is too long\n");
        return XSTDERR;
    }

    /* Nothing is replaced without -f; checked here so nothing is fetched for nothing, and again at the commit */
    struct stat st;
#ifdef _WIN32
    xbool_t bExists = stat(pRemote->sFinalPath, &st) == 0 ? XTRUE : XFALSE;
#else
    xbool_t bExists = lstat(pRemote->sFinalPath, &st) == 0 ? XTRUE : XFALSE;
#endif

    if (bExists && !pReq->bForce)
    {
        DirectGate_Remote_Tell(pRemote, "dgcli: cp: %s exists; give -f to replace it\n", pRemote->sFinalPath);
        return XSTDERR;
    }

    return XSTDOK;
}

static XSTATUS DirectGate_Remote_PreparePut(directgate_remote_t *pRemote)
{
    const directgate_remote_req_t *pReq = pRemote->pReq;
    xbool_t bStdin = xstrcmp(pReq->sLocal, "-");

    if (DirectGate_Remote_EndsWithSeparator(pReq->sPath))
    {
        const char *pName = DirectGate_Remote_BaseName(pReq->sLocal);
        if (bStdin || !DirectGate_Remote_IsUsableName(pName))
        {
            DirectGate_Remote_Tell(pRemote, "dgcli: cp: give the remote file a name, not only a directory\n");
            return XSTDERR;
        }
    }

    if (bStdin)
    {
        if (DirectGate_Remote_SpoolStdin(pRemote) != XSTDOK)
        {
            DirectGate_Remote_Tell(pRemote, "dgcli: cp: cannot read stdin: %s\n", strerror(errno));
            return XSTDERR;
        }

        return XSTDOK;
    }

    struct stat st;
    if (stat(pReq->sLocal, &st) != 0 || !S_ISREG(st.st_mode))
    {
        DirectGate_Remote_Tell(pRemote, "dgcli: cp: %s is not a readable regular file\n", pReq->sLocal);
        return XSTDERR;
    }

    return XSTDOK;
}

XSTATUS DirectGate_Remote_Prepare(directgate_remote_t *pRemote)
{
    XCHECK_NL((pRemote != NULL && pRemote->pReq != NULL), XSTDINV);
    if (pRemote->pReq->eOp == DIRECTGATE_REMOTE_GET) return DirectGate_Remote_PrepareGet(pRemote);
    if (pRemote->pReq->eOp == DIRECTGATE_REMOTE_PUT) return DirectGate_Remote_PreparePut(pRemote);
    return XSTDOK;
}

static XSTATUS DirectGate_Remote_Send(directgate_remote_t *pRemote, xjson_obj_t *pHeader, const uint8_t *pPayload, size_t nLength)
{
    XCHECK_NL((pHeader != NULL), XSTDERR);
    int nStatus = pRemote->sendFn(pHeader, pPayload, nLength, pRemote->pSendCtx);
    XJSON_FreeObject(pHeader);
    return nStatus < 0 ? XSTDERR : XSTDOK;
}

static XSTATUS DirectGate_Remote_SendSignal(directgate_remote_t *pRemote, const char *pSignal)
{
    xjson_obj_t *pHeader = DirectGate_Proto_BuildExec("signal", NULL, NULL, pRemote->nSessionId);
    if (pHeader != NULL) XJSON_AddString(pHeader, "signal", pSignal);
    return DirectGate_Remote_Send(pRemote, pHeader, NULL, 0);
}

/* The remote path the operation acts on: put into a directory takes the local file's name. */
static void DirectGate_Remote_TargetPath(const directgate_remote_t *pRemote, char *pOut, size_t nSize)
{
    const directgate_remote_req_t *pReq = pRemote->pReq;

    if (pReq->eOp == DIRECTGATE_REMOTE_PUT && DirectGate_Remote_EndsWithSeparator(pReq->sPath))
        xstrncpyf(pOut, nSize, "%s%s", pReq->sPath, DirectGate_Remote_BaseName(pReq->sLocal));
    else
        xstrncpy(pOut, nSize, pReq->sPath);
}

/* The file manager action a file operation asks the host for, by name and not by position in the enum */
static const char* DirectGate_Remote_ManagerAction(directgate_remote_op_t eOp)
{
    switch (eOp)
    {
        case DIRECTGATE_REMOTE_LIST: return "list";
        case DIRECTGATE_REMOTE_GET: return "open";
        case DIRECTGATE_REMOTE_PUT: return "save";
        case DIRECTGATE_REMOTE_REMOVE: return "delete";
        case DIRECTGATE_REMOTE_MKDIR: return "mkdir";
        case DIRECTGATE_REMOTE_MOVE: return "rename";
        default: break;
    }

    return NULL;
}

static xjson_obj_t* DirectGate_Remote_BuildRequest(const directgate_remote_t *pRemote)
{
    const directgate_remote_req_t *pReq = pRemote->pReq;
    uint32_t nSessionId = pRemote->nSessionId;
    char sPath[XPATH_MAX];
    xjson_obj_t *pHeader = NULL;

    if (pReq->eOp == DIRECTGATE_REMOTE_EXEC)
    {
        pHeader = DirectGate_Proto_BuildExec("start", NULL, NULL, nSessionId);
        if (pHeader == NULL) return NULL;

        XJSON_AddString(pHeader, "command", pReq->pCommand);
        XJSON_AddStrIfUsed(pHeader, "cwd", pReq->sCwd);
        if (pReq->nTimeoutMs) XJSON_AddU32(pHeader, "timeoutMs", pReq->nTimeoutMs);
        if (pReq->bOutputMax) XJSON_AddU32(pHeader, "outputMax", pReq->nOutputMax);
        if (pReq->bStdin) XJSON_AddBool(pHeader, "stdin", XTRUE);
        return pHeader;
    }

    const char *pAction = DirectGate_Remote_ManagerAction(pReq->eOp);
    XCHECK_NL((pAction != NULL), NULL);

    DirectGate_Remote_TargetPath(pRemote, sPath, sizeof(sPath));
    pHeader = DirectGate_Proto_BuildManager(pAction, NULL, sPath, NULL, nSessionId);
    if (pHeader == NULL) return NULL;

    /* rename, not move: an existing target is refused instead of being dodged with a "(2)" name */
    if (pReq->eOp == DIRECTGATE_REMOTE_MOVE) XJSON_AddString(pHeader, "targetPath", pReq->sTarget);
    /* "force" is the protocol's word for both: replace on save, recurse on delete */
    if ((pReq->eOp == DIRECTGATE_REMOTE_PUT && pReq->bForce) || (pReq->eOp == DIRECTGATE_REMOTE_REMOVE && pReq->bRecursive))
        XJSON_AddBool(pHeader, "force", XTRUE);

    return pHeader;
}

XSTATUS DirectGate_Remote_OpenMode(directgate_remote_t *pRemote, uint32_t nSessionId, xbool_t bExecCapable,
                                   xbool_t bRemoteCapable)
{
    XCHECK_NL((pRemote != NULL && pRemote->pReq != NULL && pRemote->sendFn != NULL), XSTDINV);
    const directgate_remote_req_t *pReq = pRemote->pReq;
    pRemote->nSessionId = nSessionId;

    if (pReq->eOp == DIRECTGATE_REMOTE_EXEC && !bExecCapable)
    {
        DirectGate_Remote_Fail(pRemote, "the agent on this device cannot run commands; update it to a newer version");
        return XSTDERR;
    }

    if (pReq->eOp == DIRECTGATE_REMOTE_SESSION && !bRemoteCapable)
    {
        DirectGate_Remote_Fail(pRemote, "the agent on this device cannot keep sessions; update it to a newer version");
        return XSTDERR;
    }

    const char *pMode = pReq->eOp == DIRECTGATE_REMOTE_EXEC ? "exec" :
        pReq->eOp == DIRECTGATE_REMOTE_SESSION ? "remote" : "file-manager";
    if (DirectGate_Remote_Send(pRemote, DirectGate_Proto_BuildCmd("start", NULL, NULL, pMode, nSessionId), NULL, 0) != XSTDOK)
    {
        DirectGate_Remote_Fail(pRemote, "cannot send the request");
        return XSTDERR;
    }

    return XSTDOK;
}

XSTATUS DirectGate_Remote_Start(directgate_remote_t *pRemote)
{
    XCHECK_NL((pRemote != NULL && pRemote->pReq != NULL && pRemote->sendFn != NULL), XSTDINV);

    if (DirectGate_Remote_Send(pRemote, DirectGate_Remote_BuildRequest(pRemote), NULL, 0) != XSTDOK)
    {
        DirectGate_Remote_Fail(pRemote, "cannot send the request");
        return XSTDERR;
    }

    pRemote->bStarted = XTRUE;
    return XSTDOK;
}

static const char* DirectGate_Remote_TypeChar(const char *pType)
{
    if (xstrcmp(pType, "directory")) return "d";
    if (xstrcmp(pType, "symlink")) return "l";
    if (xstrcmp(pType, "block")) return "b";
    if (xstrcmp(pType, "char")) return "c";
    if (xstrcmp(pType, "socket")) return "s";
    if (xstrcmp(pType, "pipe")) return "p";
    if (xstrcmp(pType, "file")) return "-";
    return "?";
}

/* One line per entry, ls -l style; the JSON the host sent when -j was given. */
static int DirectGate_Remote_PrintListing(directgate_remote_t *pRemote, const uint8_t *pPayload, size_t nLength)
{
    if (pPayload == NULL || !nLength) return DirectGate_Remote_Fail(pRemote, "the host sent an empty listing");

    if (pRemote->pReq->bJson)
    {
        if (!DirectGate_Remote_Emit(pRemote, XFALSE, pPayload, nLength) ||
            !DirectGate_Remote_Emit(pRemote, XFALSE, (const uint8_t*)"\n", 1))
            return DirectGate_Remote_Fail(pRemote, "cannot write the listing");

        return DirectGate_Remote_Succeed(pRemote, 0);
    }

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, (const char*)pPayload, nLength))
        return DirectGate_Remote_Fail(pRemote, "the host sent a listing that is not JSON");

    xjson_obj_t *pEntries = XJSON_GetObject(json.pRootObj, "entries");
    size_t nCount = pEntries != NULL ? XJSON_GetArrayLength(pEntries) : 0;
    xbool_t bOk = XTRUE;

    for (size_t i = 0; i < nCount && bOk; i++)
    {
        xjson_obj_t *pEntry = XJSON_GetArrayItem(pEntries, i);
        const char *pName = XJSON_GetString(XJSON_GetObject(pEntry, "name"));
        const char *pPerm = XJSON_GetString(XJSON_GetObject(pEntry, "permissions"));
        const char *pOwner = XJSON_GetString(XJSON_GetObject(pEntry, "owner"));
        const char *pGroup = XJSON_GetString(XJSON_GetObject(pEntry, "group"));
        const char *pModified = XJSON_GetString(XJSON_GetObject(pEntry, "modified"));
        const char *pType = XJSON_GetString(XJSON_GetObject(pEntry, "type"));
        uint64_t nSize = XJSON_GetU64(XJSON_GetObject(pEntry, "sizeBytes"));

        /* The permission string already starts with the type letter; a host without one gets it from the type */
        char sLine[XPATH_MAX + 256];
        xstrncpyf(sLine, sizeof(sLine), "%s%s %-8s %-8s %12" PRIu64 " %s %s\n",
            xstrused(pPerm) ? "" : DirectGate_Remote_TypeChar(pType), xstrused(pPerm) ? pPerm : "?????????",
            xstrused(pOwner) ? pOwner : "-", xstrused(pGroup) ? pGroup : "-", nSize,
            xstrused(pModified) ? pModified : "-", xstrused(pName) ? pName : "?");

        bOk = DirectGate_Remote_Emit(pRemote, XFALSE, (const uint8_t*)sLine, strlen(sLine));
    }

    XJSON_Destroy(&json);
    return bOk ? DirectGate_Remote_Succeed(pRemote, 0) : DirectGate_Remote_Fail(pRemote, "cannot write the listing");
}

/* get -: the verified download goes to stdout, then the private copy goes */
static xbool_t DirectGate_Remote_CopyToStdout(directgate_remote_t *pRemote)
{
    FILE *pFile = fopen(pRemote->sTempPath, "rb");
    if (pFile == NULL) return XFALSE;

#ifdef _WIN32
    if (pRemote->pOutCapture == NULL) _setmode(pRemote->nOutFd, _O_BINARY);
#endif

    uint8_t sBuffer[XFILE_CHUNK_SIZE];
    xbool_t bOk = XTRUE;
    size_t nRead = 0;

    while (bOk && (nRead = fread(sBuffer, 1, sizeof(sBuffer), pFile)) > 0)
        bOk = DirectGate_Remote_Emit(pRemote, XFALSE, sBuffer, nRead);

    if (ferror(pFile)) bOk = XFALSE;
    fclose(pFile);
    return bOk;
}

static xbool_t DirectGate_Remote_Commit(directgate_remote_t *pRemote)
{
    if (xstrcmp(pRemote->pReq->sLocal, "-"))
    {
        xbool_t bOk = DirectGate_Remote_CopyToStdout(pRemote);
        DirectGate_Remote_RemoveFile(pRemote->sTempPath, sizeof(pRemote->sTempPath));
        return bOk;
    }

    /* Without -f the destination is never replaced, not even by a file that appeared while the download ran */
#ifdef _WIN32
    DWORD nMove = pRemote->pReq->bForce ? MOVEFILE_REPLACE_EXISTING : 0;
    if (!MoveFileExA(pRemote->sTempPath, pRemote->sFinalPath, nMove))
    {
        DWORD nError = GetLastError();
        errno = (nError == ERROR_ALREADY_EXISTS || nError == ERROR_FILE_EXISTS) ? EEXIST : EACCES;
        return XFALSE;
    }
#else
    if (pRemote->pReq->bForce)
    {
        if (rename(pRemote->sTempPath, pRemote->sFinalPath) != 0) return XFALSE;
    }
    else if (link(pRemote->sTempPath, pRemote->sFinalPath) == 0)
    {
        /* link() refuses a name that exists: the no-clobber is atomic */
        unlink(pRemote->sTempPath);
    }
    else
    {
        if (errno == EEXIST) return XFALSE;

        /* A file system without hard links: the check right before the rename is the closest there is */
        struct stat st;
        if (lstat(pRemote->sFinalPath, &st) == 0)
        {
            errno = EEXIST;
            return XFALSE;
        }

        if (rename(pRemote->sTempPath, pRemote->sFinalPath) != 0) return XFALSE;
    }
#endif

    pRemote->sTempPath[0] = '\0';
    return XTRUE;
}

static int DirectGate_Remote_CancelTransfer(directgate_remote_t *pRemote, const char *pReason)
{
    if (xstrused(pRemote->transfer.sId))
        DirectGate_Remote_Send(pRemote, DirectGate_Proto_BuildFileCancel(pRemote->transfer.sId, pReason), NULL, 0);

    DirectGate_Transfer_Destroy(&pRemote->transfer);
    DirectGate_Transfer_Init(&pRemote->transfer);
    return DirectGate_Remote_Fail(pRemote, pReason);
}

static int DirectGate_Remote_HandleFile(directgate_remote_t *pRemote, const directgate_pkg_t *pMsg)
{
    const directgate_pkg_file_t *pFile = (const directgate_pkg_file_t*)pMsg->pPackage;
    const directgate_remote_req_t *pReq = pRemote->pReq;
    const char *pAction = pFile->pAction;

    if (xstrcmp(pAction, "cancel"))
    {
        const char *pReason = XJSON_GetString(XJSON_GetObject(pMsg->jsonHeader.pRootObj, "reason"));
        DirectGate_Transfer_HandleCancel(&pRemote->transfer);
        return DirectGate_Remote_Fail(pRemote, xstrused(pReason) ? pReason : "the host cancelled the transfer");
    }

    if (pReq->eOp == DIRECTGATE_REMOTE_PUT)
    {
        /* The host acknowledges an upload once it is verified and in place */
        if (xstrcmp(pAction, "ack") && pRemote->transfer.eState == XTRANSFER_STATE_DONE)
            return DirectGate_Remote_Succeed(pRemote, 0);

        return XAPI_CONTINUE;
    }

    if (pReq->eOp != DIRECTGATE_REMOTE_GET) return XAPI_CONTINUE;

    if (xstrcmp(pAction, "start"))
    {
        if (DirectGate_Transfer_HandleStartPath(&pRemote->transfer, pMsg, pRemote->sTempPath) != XSTDOK)
        {
            char sReason[XSTR_MIN];
            xstrncpyf(sReason, sizeof(sReason), "cannot write %s: %s",
                xstrused(pRemote->sFinalPath) ? pRemote->sFinalPath : "the download", strerror(errno));

            return DirectGate_Remote_CancelTransfer(pRemote, sReason);
        }

        return XAPI_CONTINUE;
    }

    if (xstrcmp(pAction, "chunk"))
    {
        if (DirectGate_Transfer_HandleChunk(&pRemote->transfer, pMsg) != XSTDOK)
            return DirectGate_Remote_CancelTransfer(pRemote, "the download could not be written");

        return XAPI_CONTINUE;
    }

    if (xstrcmp(pAction, "end"))
    {
        if (DirectGate_Transfer_HandleEnd(&pRemote->transfer, pMsg, pRemote->sendFn, pRemote->pSendCtx) != XSTDOK)
            return DirectGate_Remote_CancelTransfer(pRemote, "the download failed its integrity check");

        if (!DirectGate_Remote_Commit(pRemote))
        {
            char sReason[XPATH_MAX + 64];
            if (errno == EEXIST) xstrncpyf(sReason, sizeof(sReason), "%s exists; give -f to replace it", pRemote->sFinalPath);
            else xstrncpyf(sReason, sizeof(sReason), "cannot put the download in place: %s", strerror(errno));
            return DirectGate_Remote_Fail(pRemote, sReason);
        }

        pRemote->bTransferDone = XTRUE;
        if (pRemote->bOpenDone) return DirectGate_Remote_Succeed(pRemote, 0);
    }

    return XAPI_CONTINUE;
}

static int DirectGate_Remote_HandleManager(directgate_remote_t *pRemote, const directgate_pkg_t *pMsg)
{
    const directgate_pkg_manager_t *pMgr = (const directgate_pkg_manager_t*)pMsg->pPackage;
    xjson_obj_t *pRoot = pMsg->jsonHeader.pRootObj;
    const char *pStatus = XJSON_GetString(XJSON_GetObject(pRoot, "status"));
    const char *pReason = XJSON_GetString(XJSON_GetObject(pRoot, "reason"));
    const directgate_remote_req_t *pReq = pRemote->pReq;

    if (xstrcmp(pStatus, "failed") || (xstrused(pStatus) && !xstrcmp(pStatus, "ok") && !xstrcmp(pStatus, "exists")))
    {
        char sReason[XSTR_MID];
        xstrncpyf(sReason, sizeof(sReason), "%s: %s", xstrused(pMgr->pPath) ? pMgr->pPath : pReq->sPath,
            xstrused(pReason) ? pReason : "failed");

        if (xstrused(pRemote->transfer.sId)) DirectGate_Transfer_HandleCancel(&pRemote->transfer);
        return DirectGate_Remote_Fail(pRemote, sReason);
    }

    switch (pReq->eOp)
    {
        case DIRECTGATE_REMOTE_LIST:
            if (!xstrcmp(pMgr->pAction, "list")) return XAPI_CONTINUE;
            return DirectGate_Remote_PrintListing(pRemote, pMgr->data.pPayload, pMgr->data.nPayloadLength);
        case DIRECTGATE_REMOTE_PUT:
        {
            if (!xstrcmp(pMgr->pAction, "save")) return XAPI_CONTINUE;
            if (xstrcmp(pStatus, "exists"))
                return DirectGate_Remote_Fail(pRemote, "the remote file exists; give -f to replace it");

            /* The host has reserved the destination: the upload itself goes out as the link drains */
            const char *pSource = xstrused(pRemote->sSpoolPath) ? pRemote->sSpoolPath : pReq->sLocal;
            if (DirectGate_Transfer_Send(&pRemote->transfer, pSource, pRemote->sendFn, pRemote->pSendCtx) != XSTDOK)
            {
                char sReason[XSTR_MIN];
                xstrncpyf(sReason, sizeof(sReason), "cannot read %s: %s", pReq->sLocal, strerror(errno));
                return DirectGate_Remote_Fail(pRemote, sReason);
            }

            return XAPI_CONTINUE;
        }
        case DIRECTGATE_REMOTE_GET:
            if (!xstrcmp(pMgr->pAction, "open")) return XAPI_CONTINUE;
            pRemote->bOpenDone = XTRUE;
            return pRemote->bTransferDone ? DirectGate_Remote_Succeed(pRemote, 0) : XAPI_CONTINUE;
        case DIRECTGATE_REMOTE_REMOVE:
            return xstrcmp(pMgr->pAction, "delete") ? DirectGate_Remote_Succeed(pRemote, 0) : XAPI_CONTINUE;
        case DIRECTGATE_REMOTE_MKDIR:
            return xstrcmp(pMgr->pAction, "mkdir") ? DirectGate_Remote_Succeed(pRemote, 0) : XAPI_CONTINUE;
        case DIRECTGATE_REMOTE_MOVE:
            return xstrcmp(pMgr->pAction, "rename") ? DirectGate_Remote_Succeed(pRemote, 0) : XAPI_CONTINUE;
        default:
            break;
    }

    return XAPI_CONTINUE;
}

/* How much of a remote stream's output -o still lets through. The device is asked for no more, but it is the other
   side of the trust boundary - a compromised one sends what it likes - so the limit holds here as well. */
static size_t DirectGate_Remote_OutputRoom(directgate_remote_t *pRemote, xbool_t bStdErr, size_t nLength)
{
    const directgate_remote_req_t *pReq = pRemote->pReq;
    uint64_t *pWritten = bStdErr ? &pRemote->nErrWritten : &pRemote->nOutWritten;

    if (pReq->bOutputMax)
    {
        uint64_t nLeft = *pWritten < pReq->nOutputMax ? pReq->nOutputMax - *pWritten : 0;
        if (nLength > nLeft)
        {
            nLength = (size_t)nLeft;
            pRemote->bTruncated = XTRUE;
        }
    }

    *pWritten += nLength;
    return nLength;
}

static int DirectGate_Remote_HandleExec(directgate_remote_t *pRemote, const directgate_pkg_t *pMsg)
{
    const directgate_pkg_exec_t *pExec = (const directgate_pkg_exec_t*)pMsg->pPackage;
    const char *pAction = pExec->pAction;

    if (xstrcmp(pAction, "started"))
    {
        if (!xstrcmp(pExec->pStatus, "ok"))
            return DirectGate_Remote_Fail(pRemote, xstrused(pExec->pReason) ? pExec->pReason : "the command did not start");

        pRemote->bRunning = XTRUE;

        /* An interrupt that came while the start was on its way goes now */
        if (pRemote->pPendingSignal != NULL)
        {
            const char *pSignal = pRemote->pPendingSignal;
            pRemote->pPendingSignal = NULL;
            if (DirectGate_Remote_SendSignal(pRemote, pSignal) != XSTDOK)
                return DirectGate_Remote_Fail(pRemote, "the interrupt could not be sent");
        }

        return XAPI_CONTINUE;
    }

    if (xstrcmp(pAction, "output"))
    {
        xbool_t bStdErr = xstrcmp(pExec->pStream, "stderr");
        size_t nLength = DirectGate_Remote_OutputRoom(pRemote, bStdErr, pExec->data.nPayloadLength);
        if (nLength && !DirectGate_Remote_Emit(pRemote, bStdErr, pExec->data.pPayload, nLength))
            return DirectGate_Remote_Fail(pRemote, "cannot write the command's output");

        return XAPI_CONTINUE;
    }

    if (xstrcmp(pAction, "exit"))
    {
        if (pExec->bTruncated) pRemote->bTruncated = XTRUE;
        if (pExec->bTimedOut)
            DirectGate_Remote_Tell(pRemote, "dgcli: exec: the command timed out and was killed\n");

        /* Exit statuses are a byte; an exit the host could not collect is reported as dgcli's own failure */
        int nCode = pExec->bHasExitCode && pExec->nExitCode >= 0 ? (pExec->nExitCode & 0xff) : DIRECTGATE_REMOTE_EXIT_FAILED;
        return DirectGate_Remote_Succeed(pRemote, nCode);
    }

    return XAPI_CONTINUE;
}

int DirectGate_Remote_HandleMessage(directgate_remote_t *pRemote, const directgate_pkg_t *pMsg)
{
    XCHECK_NL((pRemote != NULL && pRemote->pReq != NULL), XAPI_DISCONNECT);
    XCHECK_NL((pMsg != NULL && pMsg->pPackage != NULL), XAPI_CONTINUE);
    if (pRemote->bDone) return XAPI_DISCONNECT;

    switch (pMsg->header.eType)
    {
        case DIRECTGATE_PKG_EXEC:
            if (pRemote->pReq->eOp != DIRECTGATE_REMOTE_EXEC) return XAPI_CONTINUE;
            return DirectGate_Remote_HandleExec(pRemote, pMsg);
        case DIRECTGATE_PKG_MANAGER:
            if (pRemote->pReq->eOp == DIRECTGATE_REMOTE_EXEC) return XAPI_CONTINUE;
            return DirectGate_Remote_HandleManager(pRemote, pMsg);
        case DIRECTGATE_PKG_FILE:
            if (pRemote->pReq->eOp == DIRECTGATE_REMOTE_EXEC) return XAPI_CONTINUE;
            return DirectGate_Remote_HandleFile(pRemote, pMsg);
        case DIRECTGATE_PKG_ERROR:
        {
            const directgate_pkg_error_t *pError = (const directgate_pkg_error_t*)pMsg->pPackage;
            return DirectGate_Remote_Fail(pRemote, xstrused(pError->pReason) ? pError->pReason : "the host refused");
        }
        case DIRECTGATE_PKG_STATUS:
        {
            const directgate_pkg_status_t *pStatus = (const directgate_pkg_status_t*)pMsg->pPackage;
            if (!xstrcmp(pStatus->pStatus, "closed")) return XAPI_CONTINUE;
            DirectGate_Remote_HandleClosed(pRemote);
            return XAPI_DISCONNECT;
        }
        default:
            break;
    }

    return XAPI_CONTINUE;
}

void DirectGate_Remote_Abort(directgate_remote_t *pRemote, const char *pReason)
{
    XCHECK_VOID_NL((pRemote != NULL && pRemote->pReq != NULL));
    DirectGate_Remote_Fail(pRemote, pReason);
}

void DirectGate_Remote_HandleClosed(directgate_remote_t *pRemote)
{
    XCHECK_VOID_NL((pRemote != NULL && pRemote->pReq != NULL));
    if (pRemote->bDone) return;

    DirectGate_Remote_Fail(pRemote, pRemote->pReq->eOp == DIRECTGATE_REMOTE_EXEC ?
        "the session closed before the command finished" : "the session closed before the operation finished");
}

XSTATUS DirectGate_Remote_SendInput(directgate_remote_t *pRemote, const uint8_t *pData, size_t nLength)
{
    XCHECK_NL((pRemote != NULL && pRemote->bStarted && !pRemote->bDone), XSTDERR);
    XCHECK_NL((pData != NULL && nLength > 0), XSTDOK);

    xjson_obj_t *pHeader = DirectGate_Proto_BuildExec("input", NULL, NULL, pRemote->nSessionId);
    return DirectGate_Remote_Send(pRemote, pHeader, pData, nLength);
}

XSTATUS DirectGate_Remote_SendEof(directgate_remote_t *pRemote)
{
    XCHECK_NL((pRemote != NULL && pRemote->bStarted && !pRemote->bDone), XSTDERR);
    if (pRemote->bEofSent) return XSTDOK;

    pRemote->bEofSent = XTRUE;
    return DirectGate_Remote_Send(pRemote, DirectGate_Proto_BuildExec("eof", NULL, NULL, pRemote->nSessionId), NULL, 0);
}

int DirectGate_Remote_Interrupt(directgate_remote_t *pRemote, xbool_t bTerminate)
{
    XCHECK_NL((pRemote != NULL && pRemote->pReq != NULL), XAPI_DISCONNECT);
    if (pRemote->bDone) return XAPI_DISCONNECT;

    if (pRemote->pReq->eOp == DIRECTGATE_REMOTE_EXEC && pRemote->bRunning)
    {
        if (DirectGate_Remote_SendSignal(pRemote, bTerminate ? "TERM" : "INT") == XSTDOK) return XAPI_CONTINUE;
    }

    /* Sent, not confirmed yet: the command may be starting this very moment, so the interrupt waits for its start */
    if (pRemote->pReq->eOp == DIRECTGATE_REMOTE_EXEC && pRemote->bStarted && !pRemote->bRunning)
    {
        pRemote->pPendingSignal = bTerminate ? "TERM" : "INT";
        return XAPI_CONTINUE;
    }

    if (pRemote->transfer.eState == XTRANSFER_STATE_SENDING || pRemote->transfer.eState == XTRANSFER_STATE_RECEIVING)
        return DirectGate_Remote_CancelTransfer(pRemote, "interrupted");

    return DirectGate_Remote_Fail(pRemote, "interrupted");
}

void DirectGate_Remote_Pump(directgate_remote_t *pRemote, size_t nQueued)
{
    XCHECK_VOID_NL((pRemote != NULL && !pRemote->bDone));

    /* Chunks are encrypted as they are sent, so keeping the queue short keeps memory flat for any file size */
    for (int nRound = 0; nRound < 64 && pRemote->transfer.eState == XTRANSFER_STATE_SENDING; nRound++)
    {
        if (nQueued >= DIRECTGATE_REMOTE_TX_WINDOW) return;

        if (DirectGate_Transfer_SendNext(&pRemote->transfer, pRemote->sendFn, pRemote->pSendCtx) < 0)
        {
            DirectGate_Remote_CancelTransfer(pRemote, "the upload could not be read or sent");
            return;
        }

        nQueued += XFILE_CHUNK_SIZE;
    }
}

xbool_t DirectGate_Remote_IsDone(const directgate_remote_t *pRemote)
{
    return (pRemote != NULL && pRemote->bDone) ? XTRUE : XFALSE;
}

int DirectGate_Remote_ExitCode(const directgate_remote_t *pRemote)
{
    XCHECK_NL((pRemote != NULL), DIRECTGATE_REMOTE_EXIT_FAILED);
    return pRemote->nExitCode;
}
