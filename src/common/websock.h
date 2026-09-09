/*!
 * @file directgate-agent/src/common/websock.h
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

#ifndef __DIRECTGATE_WEBSOCK_H__
#define __DIRECTGATE_WEBSOCK_H__

#include "includes.h"

#ifdef __cplusplus
extern "C" {
#endif

int DirectGate_WebSock_Send(xapi_session_t *pSession, const uint8_t *pPkg, size_t nLen);
int DirectGate_WebSock_SendBuff(xapi_session_t *pSession, const xbyte_buffer_t *pPkg);
int DirectGate_WebSock_SendPong(xapi_session_t *pSession, xws_frame_t *pPing);

#ifdef __cplusplus
}
#endif

#endif
