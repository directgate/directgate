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

int DirectGate_WebSock_SendPong(xapi_session_t *pSession, xws_frame_t *pPing)
{
    XCHECK((pSession != NULL && pPing != NULL), XAPI_DISCONNECT);
    XCHECK((pPing->eType == XWS_PING && pPing->bFin && pPing->nPayloadLength <= 125), XAPI_DISCONNECT);

    xbool_t bMask = pSession->eRole == XAPI_CLIENT ? XTRUE : XFALSE;

    /* RFC 6455 section 5.5.3 requires the ping's application data verbatim. */
    if (XWS_AppendFrame(&pSession->txBuffer, XWebFrame_GetPayload(pPing), XWebFrame_GetPayloadLength(pPing),
        XWS_PONG, bMask, XTRUE) != XWS_ERR_NONE) return XAPI_DISCONNECT;

    return XAPI_EnableEvent(pSession, XPOLLOUT);
}

int DirectGate_WebSock_Send(xapi_session_t *pSession, const uint8_t *pPkg, size_t nLen)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    XCHECK((pPkg != NULL), XAPI_CONTINUE);
    XCHECK((nLen > 0), XAPI_CONTINUE);

    xbool_t bMask = (pSession->eRole == XAPI_CLIENT) ? XTRUE : XFALSE;

    /* The frame is written straight into the tx buffer: building it on its own
       first and then adding it copied every payload twice, with an allocation
       and a free in between, on the path every desktop frame takes. */
    xws_status_t status = XWS_AppendFrame(&pSession->txBuffer, pPkg, nLen, XWS_BINARY, bMask, XTRUE);
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

    return XAPI_EnableEvent(pSession, XPOLLOUT);
}

int DirectGate_WebSock_SendBuff(xapi_session_t *pSession, const xbyte_buffer_t *pPkg)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    XCHECK((pPkg != NULL), XAPI_CONTINUE);
    return DirectGate_WebSock_Send(pSession, pPkg->pData, pPkg->nUsed);
}
