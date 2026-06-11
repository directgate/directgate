/*!
 * @file directgate-agent/src/common/webrtc.h
 * @brief WebRTC peer connection wrapper using libdatachannel.
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

#ifndef __DIRECTGATE_WEBRTC_H__
#define __DIRECTGATE_WEBRTC_H__

#include "includes.h"
#include <pthread.h>
#include <rtc/rtc.h>

#define DIRECTGATE_KA_INTERVAL_SEC  25
#define DIRECTGATE_MAX_ICE_SERVERS  8
#define DIRECTGATE_ICE_URL_SIZE     256

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*directgate_webrtc_signal_cb)(const char *pJson, size_t nLen, void *pUserCtx);
typedef void (*directgate_webrtc_data_cb)(const uint8_t *pData, size_t nLen, void *pUserCtx);
typedef char directgate_ice_server_t[DIRECTGATE_ICE_URL_SIZE];

typedef enum {
    DIRECTGATE_WEBRTC_OPEN = 0,
    DIRECTGATE_WEBRTC_CLOSED,
    DIRECTGATE_WEBRTC_DATA,
    DIRECTGATE_WEBRTC_SIGNAL
} directgate_webrtc_event_type_t;

typedef struct directgate_webrtc_event_ {
    struct directgate_webrtc_event_ *pNext;
    directgate_webrtc_event_type_t eType;
    int nSourceID;
    uint8_t *pData;
    size_t nLength;
} directgate_webrtc_event_t;

typedef struct directgate_pending_ice_ {
    struct directgate_pending_ice_ *pNext;
    char sCandidate[XSTR_SUB];
    char sMid[XSTR_PICO];
} directgate_pending_ice_t;

typedef struct directgate_webrtc_ {
    int nPeerConnectionID;      /* Peer connection ID (-1 if not created) */
    int nDataChannelID;         /* Data channel ID (-1 if not created) */
    xbool_t bConnected;         /* Data channel is open (main thread only) */
    rtcLogLevel logLevel;       /* Log level for libdatachannel */

    /* Callbacks to send signaling messages via relay WebSocket */
    directgate_webrtc_signal_cb signalCb;
    void *pSignalCtx;

    /* Callback when data is received on the data channel */
    directgate_webrtc_data_cb dataCb;
    void *pDataCtx;

    /* Cross-thread event queue (libdatachannel thread -> main loop) */
    directgate_webrtc_event_t *pQueueHead;
    directgate_webrtc_event_t *pQueueTail;
    xsync_mutex_t queueLock;

    /* [0]=read (main loop), [1]=write (callback).
       POSIX: a pipe (XSOCKET == int there). Windows: a private socket
       pair from XSock_CreatePair(), since WSAPoll only polls sockets. */
    XSOCKET nPipeFds[2];

    /* Configurable ICE/TURN servers (from config file) */
    directgate_ice_server_t sIceServers[DIRECTGATE_MAX_ICE_SERVERS];
    uint8_t nIceSrvCount;

    /* Allow TCP ICE candidates */
    xbool_t bAllowTCP;

    /* Buffered remote ICE candidates received before peer connection exists */
    directgate_pending_ice_t *pPendingIce;
} directgate_webrtc_t;

void DirectGate_WebRTC_Init(directgate_webrtc_t *pRTC);
void DirectGate_WebRTC_Destroy(directgate_webrtc_t *pRTC);

void DirectGate_WebRTC_Clear(directgate_webrtc_t *pRTC);
void DirectGate_WebRTC_Cleanup(void);

/* Load ICE/TURN servers from JSON configuration */
xbool_t DirectGate_WebRTC_LoadIceServers(directgate_ice_server_t *pServers, uint8_t *pCount, xjson_obj_t *pRoot);

/* Set ICE/TURN servers for the WebRTC peer connection */
void DirectGate_WebRTC_SetIceServers(directgate_webrtc_t *pRTC, const directgate_ice_server_t *pServers, uint8_t nCount);

/* Create peer connection and data channel, generate SDP offer (client/offerer side) */
XSTATUS DirectGate_WebRTC_CreateOffer(directgate_webrtc_t *pRTC);

/* Handle incoming SDP answer from agent — completes the offer/answer exchange */
XSTATUS DirectGate_WebRTC_HandleAnswer(directgate_webrtc_t *pRTC, const char *pSdp);

/* Handle incoming SDP offer from client — creates peer connection and answer */
XSTATUS DirectGate_WebRTC_HandleOffer(directgate_webrtc_t *pRTC, const char *pSdp);

/* Handle incoming ICE candidate from remote peer */
XSTATUS DirectGate_WebRTC_HandleIceCandidate(directgate_webrtc_t *pRTC, const char *pCandidate, const char *pMid);

/* Send binary data over the data channel. Returns 0 on success, -1 on failure */
XSTATUS DirectGate_WebRTC_Send(directgate_webrtc_t *pRTC, const uint8_t *pData, size_t nLen);

/* Check if the data channel is connected */
xbool_t DirectGate_WebRTC_IsConnected(const directgate_webrtc_t *pRTC);
int DirectGate_WebRTC_GetBufferedAmount(const directgate_webrtc_t *pRTC);

/* Drain queued events and dispatch callbacks on the calling (main) thread */
void DirectGate_WebRTC_ProcessQueue(directgate_webrtc_t *pRTC);

/* Get the pipe read fd for event loop registration (-1 if not available) */
int DirectGate_WebRTC_GetPipeFd(const directgate_webrtc_t *pRTC);

#ifdef __cplusplus
}
#endif

#endif
