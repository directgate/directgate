/*!
 * @file directgate-agent/src/client/config.h
 * @brief Client config and CLI parsing.
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

#ifndef __DIRECTGATE_CLIENT_CONFIG_H__
#define __DIRECTGATE_CLIENT_CONFIG_H__

#include "includes.h"
#include "auth.h"
#include "logger.h"
#include "webrtc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    DIRECTGATE_CMD_CONNECT = 0,     /* Default: pick a device and attach */
    DIRECTGATE_CMD_LOGIN,
    DIRECTGATE_CMD_LOGOUT,
    DIRECTGATE_CMD_DEVICES,
    DIRECTGATE_CMD_WHOAMI
} directgate_cmd_t;

typedef struct directgate_cfg_ {
    directgate_ice_server_t sIceServers[DIRECTGATE_MAX_ICE_SERVERS];
    char sSignalingUrl[XPATH_MAX];
    char sDeviceList[XPATH_MAX];
    char sAccessToken[XSTR_MID];
    char sRoutingKey[XSTR_MID];
    char sApiUrl[XPATH_MAX];
    char sApiToken[XSTR_MID];
    char sWebUrl[XPATH_MAX];
    char sAuthPath[XPATH_MAX];
    char sKeyPath[XPATH_MAX];
    char sDeviceQuery[XSTR_MID];
    char sDeviceName[XSTR_MID];
    char sDeviceId[XSTR_MID];
    char sCfgPath[XPATH_MAX];
    char sSecret[XSTR_MID];
    directgate_auth_t auth;
    directgate_log_t log;
    directgate_cmd_t eCommand;
    uint16_t nVerbose;
    uint8_t nIceSrvCount;
    xbool_t bSaveDevice;
    xbool_t bNoBrowser;
    xbool_t bKeyRequired;
    xbool_t bGenKey;
    xbool_t bAddKey;
    xbool_t bForce;
    xbool_t bInit;
} directgate_cfg_t;

void DirectGate_DisplayUsage(const char *pName);
void DirectGate_InitConfig(directgate_cfg_t *pCfg);

xbool_t DirectGate_LoadConfig(directgate_cfg_t *pCfg, const char *pPath);
XSTATUS DirectGate_ParseArgs(directgate_cfg_t *pCfg, int argc, char *argv[]);

/* Maps a leading "login"/"logout"/"devices"/"whoami" verb onto a command.
 * Returns XFALSE when the token is not a verb, leaving it as a device query. */
xbool_t DirectGate_ParseCommand(const char *pArg, directgate_cmd_t *pCommand);

/* Applies the DIRECTGATE_API_URL / DIRECTGATE_WEB_URL overrides, which sit
 * between the config file and the command line so a dev shell can retarget
 * the CLI without editing JSON. */
void DirectGate_ApplyEnvConfig(directgate_cfg_t *pCfg);

/* Prompts for the device's SRP password, once a device has been chosen.
 * A secret already loaded from the config is kept as-is. */
xbool_t DirectGate_PromptDeviceSecret(directgate_cfg_t *pCfg, const char *pDeviceName);

#ifdef __cplusplus
}
#endif

#endif
