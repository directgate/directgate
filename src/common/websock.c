/*!
 * @file directgate-agent/src/common/websock.c
 * @brief WebSocket wrapper for DirectGate.
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

#include "websock.h"
#include "protocol.h"

int DirectGate_WebSock_Send(xapi_session_t *pSession, const uint8_t *pPkg, size_t nLen)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    XCHECK((pPkg != NULL), XAPI_CONTINUE);
    XCHECK((nLen > 0), XAPI_CONTINUE);

    xbool_t bMask = (pSession->eRole == XAPI_CLIENT) ? XTRUE : XFALSE;
    xws_status_t status;
    xws_frame_t frame;

    status = XWebFrame_Create(&frame, pPkg, nLen, XWS_BINARY, bMask, XTRUE);
    if (status != XWS_ERR_NONE)
    {
        const char *pAddr = (pSession != NULL && xstrused(pSession->sAddr)) ? pSession->sAddr : "N/A";
        xloge("Failed to create WS frame: id(%u), fd(%d), role(%d), addr(%s), port(%u), bytes(%zu), status(%s)",
            pSession != NULL ? (uint32_t)pSession->nID : 0,
            pSession != NULL ? (int)pSession->sock.nFD : -1,
            pSession != NULL ? (int)pSession->eRole : -1,
            pAddr, pSession != NULL ? pSession->nPort : 0,
            nLen, XWebSock_GetStatusStr(status));

        return XAPI_DISCONNECT;
    }

    if (XByteBuffer_AddBuff(&pSession->txBuffer, &frame.buffer) <= 0)
    {
        XWebFrame_Clear(&frame);
        return XAPI_DISCONNECT;
    }

    XWebFrame_Clear(&frame);
    return XAPI_EnableEvent(pSession, XPOLLOUT);
}

int DirectGate_WebSock_SendBuff(xapi_session_t *pSession, const xbyte_buffer_t *pPkg)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    XCHECK((pPkg != NULL), XAPI_CONTINUE);
    return DirectGate_WebSock_Send(pSession, pPkg->pData, pPkg->nUsed);
}
