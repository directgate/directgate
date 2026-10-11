/*!
 * @file directgate-agent/src/agent/managed_keys.h
 * @brief Volatile organization-managed client-key leases.
 */

#ifndef __DIRECTGATE_MANAGED_KEYS_H__
#define __DIRECTGATE_MANAGED_KEYS_H__

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DIRECTGATE_MAX_MANAGED_KEYS 2000

typedef struct directgate_managed_keys_ {
    directgate_auth_key_t keys[DIRECTGATE_MAX_MANAGED_KEYS];
    char sApiUrl[XPATH_MAX];
    char sRefreshToken[XSTR_MIN];
    char sOrganizationId[XSTR_MID];
    char sPolicyId[XSTR_MID];
    char sExpiresAt[XSTR_TINY];
    xthread_t thread;
    xsync_mutex_t lock;
    uint64_t nExpiresAt;
    uint16_t nKeyCount;
    xbool_t bStarted;
    xbool_t bStop;
} directgate_managed_keys_t;

void DirectGate_ManagedKeys_Init(directgate_managed_keys_t *pKeys, const directgate_cfg_t *pCfg);
xbool_t DirectGate_ManagedKeys_Start(directgate_managed_keys_t *pKeys);
void DirectGate_ManagedKeys_UpdateEnrollment(directgate_managed_keys_t *pKeys, const directgate_cfg_t *pCfg);
void DirectGate_ManagedKeys_Stop(directgate_managed_keys_t *pKeys);
xbool_t DirectGate_ManagedKeys_ApplyResponse(directgate_managed_keys_t *pKeys,
                                             const uint8_t *pBody, size_t nBodyLen);
void DirectGate_ManagedKeys_ApplyFailure(directgate_managed_keys_t *pKeys, uint64_t nNow);
xbool_t DirectGate_ManagedKeys_IsAuthorized(directgate_managed_keys_t *pKeys,
                                            const uint8_t *pClientPubKey);
xbool_t DirectGate_ManagedKeys_Contains(directgate_managed_keys_t *pKeys, const char *pClientPub);

#ifdef __cplusplus
}
#endif

#endif
