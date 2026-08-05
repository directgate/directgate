/*!
 * @file directgate-agent/src/agent/desktop/wayland_portal.c
 * @brief xdg-desktop-portal session for Wayland screen capture and input.
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

#include <dlfcn.h>
#include <unistd.h>
#include <dbus/dbus.h>

#define DIRECTGATE_PORTAL_BUS     "org.freedesktop.portal.Desktop"
#define DIRECTGATE_PORTAL_PATH    "/org/freedesktop/portal/desktop"
#define DIRECTGATE_PORTAL_SCREEN  "org.freedesktop.portal.ScreenCast"
#define DIRECTGATE_PORTAL_REMOTE  "org.freedesktop.portal.RemoteDesktop"
#define DIRECTGATE_PORTAL_REQUEST "org.freedesktop.portal.Request"

/* The compositor prompt is answered by a human. Everything up to Start is
 * machine-to-machine and must not wait anywhere near this long. */
#define DIRECTGATE_PORTAL_CALL_MS   10000
#define DIRECTGATE_PORTAL_GRANT_MS  120000

/* Portal enumerations, spelled out so the call sites read as intent. */
#define DIRECTGATE_PORTAL_SOURCE_MONITOR  1U
#define DIRECTGATE_PORTAL_CURSOR_HIDDEN   1U
#define DIRECTGATE_PORTAL_CURSOR_EMBEDDED 2U
#define DIRECTGATE_PORTAL_DEVICE_KEYBOARD 1U
#define DIRECTGATE_PORTAL_DEVICE_POINTER  2U
#define DIRECTGATE_PORTAL_PERSIST_SESSION 2U

typedef DBusConnection* (*directgate_dbus_bus_get_fn)(DBusBusType, DBusError*);
typedef void         (*directgate_dbus_error_init_fn)(DBusError*);
typedef void         (*directgate_dbus_error_free_fn)(DBusError*);
typedef dbus_bool_t  (*directgate_dbus_error_is_set_fn)(const DBusError*);
typedef const char*  (*directgate_dbus_bus_unique_fn)(DBusConnection*);
typedef void         (*directgate_dbus_bus_add_match_fn)(DBusConnection*, const char*, DBusError*);
typedef DBusMessage* (*directgate_dbus_msg_new_call_fn)(const char*, const char*, const char*, const char*);
typedef void         (*directgate_dbus_msg_unref_fn)(DBusMessage*);
typedef DBusMessage* (*directgate_dbus_send_block_fn)(DBusConnection*, DBusMessage*, int, DBusError*);
typedef dbus_bool_t  (*directgate_dbus_send_fn)(DBusConnection*, DBusMessage*, dbus_uint32_t*);
typedef void         (*directgate_dbus_flush_fn)(DBusConnection*);
typedef dbus_bool_t  (*directgate_dbus_read_write_fn)(DBusConnection*, int);
typedef DBusMessage* (*directgate_dbus_pop_fn)(DBusConnection*);
typedef dbus_bool_t  (*directgate_dbus_is_signal_fn)(DBusMessage*, const char*, const char*);
typedef const char*  (*directgate_dbus_msg_path_fn)(DBusMessage*);
typedef void         (*directgate_dbus_iter_init_append_fn)(DBusMessage*, DBusMessageIter*);
typedef dbus_bool_t  (*directgate_dbus_iter_append_fn)(DBusMessageIter*, int, const void*);
typedef dbus_bool_t  (*directgate_dbus_iter_open_fn)(DBusMessageIter*, int, const char*, DBusMessageIter*);
typedef dbus_bool_t  (*directgate_dbus_iter_close_fn)(DBusMessageIter*, DBusMessageIter*);
typedef dbus_bool_t  (*directgate_dbus_iter_init_fn)(DBusMessage*, DBusMessageIter*);
typedef int          (*directgate_dbus_iter_argtype_fn)(DBusMessageIter*);
typedef void         (*directgate_dbus_iter_recurse_fn)(DBusMessageIter*, DBusMessageIter*);
typedef void         (*directgate_dbus_iter_get_fn)(DBusMessageIter*, void*);
typedef dbus_bool_t  (*directgate_dbus_iter_next_fn)(DBusMessageIter*);
typedef void         (*directgate_dbus_conn_unref_fn)(DBusConnection*);
typedef void         (*directgate_dbus_conn_close_fn)(DBusConnection*);
typedef dbus_bool_t  (*directgate_dbus_threads_init_fn)(void);
typedef int          (*directgate_dbus_msg_type_fn)(DBusMessage*);
typedef const char*  (*directgate_dbus_msg_errname_fn)(DBusMessage*);
typedef void         (*directgate_dbus_exit_on_disc_fn)(DBusConnection*, dbus_bool_t);

typedef struct directgate_dbus_lib_ {
    void *pHandle;
    directgate_dbus_bus_get_fn busGet;
    directgate_dbus_error_init_fn errorInit;
    directgate_dbus_error_free_fn errorFree;
    directgate_dbus_error_is_set_fn errorIsSet;
    directgate_dbus_bus_unique_fn uniqueName;
    directgate_dbus_bus_add_match_fn addMatch;
    directgate_dbus_msg_new_call_fn newCall;
    directgate_dbus_msg_unref_fn msgUnref;
    directgate_dbus_send_block_fn sendBlock;
    directgate_dbus_send_fn send;
    directgate_dbus_flush_fn flush;
    directgate_dbus_read_write_fn readWrite;
    directgate_dbus_pop_fn pop;
    directgate_dbus_is_signal_fn isSignal;
    directgate_dbus_msg_path_fn msgPath;
    directgate_dbus_iter_init_append_fn iterInitAppend;
    directgate_dbus_iter_append_fn iterAppend;
    directgate_dbus_iter_open_fn iterOpen;
    directgate_dbus_iter_close_fn iterClose;
    directgate_dbus_iter_init_fn iterInit;
    directgate_dbus_iter_argtype_fn iterArgType;
    directgate_dbus_iter_recurse_fn iterRecurse;
    directgate_dbus_iter_get_fn iterGet;
    directgate_dbus_iter_next_fn iterNext;
    directgate_dbus_conn_unref_fn connUnref;
    directgate_dbus_conn_close_fn connClose;
    directgate_dbus_threads_init_fn threadsInit;
    directgate_dbus_msg_type_fn msgType;
    directgate_dbus_msg_errname_fn msgErrorName;
    directgate_dbus_exit_on_disc_fn setExitOnDisconnect;
    xbool_t bLoadAttempted;
    xbool_t bLoaded;
} directgate_dbus_lib_t;

static directgate_dbus_lib_t g_dbus;

static const char *g_pDBusNames[] = { "libdbus-1.so.3", "libdbus-1.so", NULL };

struct directgate_wl_portal_ {
    DBusConnection *pConn;
    char sSessionHandle[256];
    char sSenderId[128];      /* unique name, mangled for request paths */
    directgate_wl_stream_t streams[DIRECTGATE_WL_MAX_STREAMS];
    uint32_t nStreamCount;
    uint32_t nDevices;        /* device types the portal actually granted */
    uint32_t nInputErrors;    /* refused input events already reported */
    xbool_t bKeysymRefused;   /* this portal will not type by character */
    uint32_t nTokenSeq;
    /* Raised when a person answered the prompt with "no", as opposed to the
     * request failing. The caller's flag, not this struct's, because the
     * portal is freed on the way out and the answer has to outlive it. */
    xbool_t *pDeclined;
};

static void DirectGate_WL_PortalSetError(char *pErrBuf, size_t nErrSize, const char *pFmt, ...)
{
    if (pErrBuf == NULL || !nErrSize) return;

    va_list args;
    va_start(args, pFmt);
    vsnprintf(pErrBuf, nErrSize, pFmt, args);
    va_end(args);
}

int DirectGate_WL_DBusLoad(char *pErrBuf, size_t nErrSize)
{
    directgate_dbus_lib_t *pLib = &g_dbus;

    if (pLib->bLoadAttempted)
    {
        if (pLib->bLoaded) return XSTDOK;
        DirectGate_WL_PortalSetError(pErrBuf, nErrSize, "D-Bus is not available on this host.");
        return XSTDERR;
    }

    pLib->bLoadAttempted = XTRUE;

    void *pHandle = NULL;
    for (int i = 0; g_pDBusNames[i] != NULL && pHandle == NULL; i++)
        pHandle = dlopen(g_pDBusNames[i], RTLD_NOW | RTLD_LOCAL);

    if (pHandle == NULL)
    {
        DirectGate_WL_PortalSetError(pErrBuf, nErrSize, "D-Bus is not available on this host.");
        return XSTDERR;
    }

    /* Private, not shared. A shared connection is handed to every caller in
     * the process, and this code pops messages off the incoming queue by
     * hand - on a shared connection that means one portal session can eat
     * another's Response signal, and the loser waits out its whole timeout
     * for an answer that already arrived. */
    pLib->busGet = (directgate_dbus_bus_get_fn)dlsym(pHandle, "dbus_bus_get_private");
    if (pLib->busGet == NULL) pLib->busGet = (directgate_dbus_bus_get_fn)dlsym(pHandle, "dbus_bus_get");
    pLib->connClose = (directgate_dbus_conn_close_fn)dlsym(pHandle, "dbus_connection_close");
    pLib->setExitOnDisconnect = (directgate_dbus_exit_on_disc_fn)dlsym(pHandle, "dbus_connection_set_exit_on_disconnect");
    pLib->errorInit = (directgate_dbus_error_init_fn)dlsym(pHandle, "dbus_error_init");
    pLib->errorFree = (directgate_dbus_error_free_fn)dlsym(pHandle, "dbus_error_free");
    pLib->errorIsSet = (directgate_dbus_error_is_set_fn)dlsym(pHandle, "dbus_error_is_set");
    pLib->uniqueName = (directgate_dbus_bus_unique_fn)dlsym(pHandle, "dbus_bus_get_unique_name");
    pLib->addMatch = (directgate_dbus_bus_add_match_fn)dlsym(pHandle, "dbus_bus_add_match");
    pLib->newCall = (directgate_dbus_msg_new_call_fn)dlsym(pHandle, "dbus_message_new_method_call");
    pLib->msgUnref = (directgate_dbus_msg_unref_fn)dlsym(pHandle, "dbus_message_unref");
    pLib->sendBlock = (directgate_dbus_send_block_fn)dlsym(pHandle, "dbus_connection_send_with_reply_and_block");
    pLib->send = (directgate_dbus_send_fn)dlsym(pHandle, "dbus_connection_send");
    pLib->flush = (directgate_dbus_flush_fn)dlsym(pHandle, "dbus_connection_flush");
    pLib->readWrite = (directgate_dbus_read_write_fn)dlsym(pHandle, "dbus_connection_read_write");
    pLib->pop = (directgate_dbus_pop_fn)dlsym(pHandle, "dbus_connection_pop_message");
    pLib->isSignal = (directgate_dbus_is_signal_fn)dlsym(pHandle, "dbus_message_is_signal");
    pLib->msgPath = (directgate_dbus_msg_path_fn)dlsym(pHandle, "dbus_message_get_path");
    pLib->iterInitAppend = (directgate_dbus_iter_init_append_fn)dlsym(pHandle, "dbus_message_iter_init_append");
    pLib->iterAppend = (directgate_dbus_iter_append_fn)dlsym(pHandle, "dbus_message_iter_append_basic");
    pLib->iterOpen = (directgate_dbus_iter_open_fn)dlsym(pHandle, "dbus_message_iter_open_container");
    pLib->iterClose = (directgate_dbus_iter_close_fn)dlsym(pHandle, "dbus_message_iter_close_container");
    pLib->iterInit = (directgate_dbus_iter_init_fn)dlsym(pHandle, "dbus_message_iter_init");
    pLib->iterArgType = (directgate_dbus_iter_argtype_fn)dlsym(pHandle, "dbus_message_iter_get_arg_type");
    pLib->iterRecurse = (directgate_dbus_iter_recurse_fn)dlsym(pHandle, "dbus_message_iter_recurse");
    pLib->iterGet = (directgate_dbus_iter_get_fn)dlsym(pHandle, "dbus_message_iter_get_basic");
    pLib->iterNext = (directgate_dbus_iter_next_fn)dlsym(pHandle, "dbus_message_iter_next");
    pLib->connUnref = (directgate_dbus_conn_unref_fn)dlsym(pHandle, "dbus_connection_unref");
    pLib->threadsInit = (directgate_dbus_threads_init_fn)dlsym(pHandle, "dbus_threads_init_default");
    pLib->msgType = (directgate_dbus_msg_type_fn)dlsym(pHandle, "dbus_message_get_type");
    pLib->msgErrorName = (directgate_dbus_msg_errname_fn)dlsym(pHandle, "dbus_message_get_error_name");

    if (pLib->busGet == NULL || pLib->newCall == NULL || pLib->sendBlock == NULL ||
        pLib->iterInitAppend == NULL || pLib->iterAppend == NULL || pLib->iterOpen == NULL ||
        pLib->iterClose == NULL || pLib->iterInit == NULL || pLib->iterRecurse == NULL ||
        pLib->iterGet == NULL || pLib->iterNext == NULL || pLib->addMatch == NULL ||
        pLib->readWrite == NULL || pLib->pop == NULL || pLib->isSignal == NULL ||
        pLib->uniqueName == NULL || pLib->msgUnref == NULL || pLib->errorInit == NULL)
    {
        dlclose(pHandle);
        memset(pLib, 0, sizeof(*pLib));
        pLib->bLoadAttempted = XTRUE;

        DirectGate_WL_PortalSetError(pErrBuf, nErrSize,
            "The installed D-Bus library is missing entry points this agent needs.");

        return XSTDERR;
    }

    /* libdbus is not thread-safe until this is called, and it has to be
     * called before any connection exists. This portal is opened on a setup
     * worker and then used from the agent's event loop for every keystroke
     * and mouse move, so without it the input path is undefined behaviour -
     * which shows up as input that simply never arrives. */
    if (pLib->threadsInit != NULL && !pLib->threadsInit())
    {
        dlclose(pHandle);
        memset(pLib, 0, sizeof(*pLib));
        pLib->bLoadAttempted = XTRUE;

        DirectGate_WL_PortalSetError(pErrBuf, nErrSize, "D-Bus thread support could not be initialised.");
        return XSTDERR;
    }

    pLib->pHandle = pHandle;
    pLib->bLoaded = XTRUE;
    return XSTDOK;
}

static void DirectGate_WL_DictString(DBusMessageIter *pDict, const char *pKey, const char *pValue)
{
    DBusMessageIter entry, variant;

    if (!g_dbus.iterOpen(pDict, DBUS_TYPE_DICT_ENTRY, NULL, &entry)) return;
    g_dbus.iterAppend(&entry, DBUS_TYPE_STRING, &pKey);

    if (g_dbus.iterOpen(&entry, DBUS_TYPE_VARIANT, "s", &variant))
    {
        g_dbus.iterAppend(&variant, DBUS_TYPE_STRING, &pValue);
        g_dbus.iterClose(&entry, &variant);
    }

    g_dbus.iterClose(pDict, &entry);
}

static void DirectGate_WL_DictBool(DBusMessageIter *pDict, const char *pKey, xbool_t bValue)
{
    DBusMessageIter entry, variant;
    dbus_bool_t bDbusValue = bValue ? TRUE : FALSE;

    if (!g_dbus.iterOpen(pDict, DBUS_TYPE_DICT_ENTRY, NULL, &entry)) return;
    g_dbus.iterAppend(&entry, DBUS_TYPE_STRING, &pKey);

    if (g_dbus.iterOpen(&entry, DBUS_TYPE_VARIANT, "b", &variant))
    {
        g_dbus.iterAppend(&variant, DBUS_TYPE_BOOLEAN, &bDbusValue);
        g_dbus.iterClose(&entry, &variant);
    }

    g_dbus.iterClose(pDict, &entry);
}

static void DirectGate_WL_DictUint(DBusMessageIter *pDict, const char *pKey, uint32_t nValue)
{
    DBusMessageIter entry, variant;
    dbus_uint32_t nDbusValue = nValue;

    if (!g_dbus.iterOpen(pDict, DBUS_TYPE_DICT_ENTRY, NULL, &entry)) return;
    g_dbus.iterAppend(&entry, DBUS_TYPE_STRING, &pKey);

    if (g_dbus.iterOpen(&entry, DBUS_TYPE_VARIANT, "u", &variant))
    {
        g_dbus.iterAppend(&variant, DBUS_TYPE_UINT32, &nDbusValue);
        g_dbus.iterClose(&entry, &variant);
    }

    g_dbus.iterClose(pDict, &entry);
}

/* Unique per call. The token is not a secret; it only has to be distinct
 * within this connection, because it is what the request object path is
 * derived from. */
static void DirectGate_WL_MakeToken(directgate_wl_portal_t *pPortal, char *pBuf, size_t nSize)
{
    snprintf(pBuf, nSize, "directgate%u_%u", (unsigned)getpid(), ++pPortal->nTokenSeq);
}

/* The portal answers asynchronously on an object path derived from the
 * caller's unique bus name, so the path can be computed before the call is
 * made - which is the only way to subscribe in time. Waiting until the method
 * returns the path is a race the portal can and does win on a warm cache. */
static void DirectGate_WL_RequestPath(const directgate_wl_portal_t *pPortal,
                                      const char *pToken, char *pBuf, size_t nSize)
{
    snprintf(pBuf, nSize, "%s/request/%s/%s", DIRECTGATE_PORTAL_PATH, pPortal->sSenderId, pToken);
}

static void DirectGate_WL_MangleSender(const char *pUnique, char *pBuf, size_t nSize)
{
    size_t j = 0;

    /* ":1.234" becomes "1_234": the leading colon goes, dots become
     * underscores. This is the portal's own rule for the path segment. */
    for (size_t i = 0; pUnique[i] != '\0' && j + 1 < nSize; i++)
    {
        if (pUnique[i] == ':') continue;
        pBuf[j++] = (pUnique[i] == '.') ? '_' : pUnique[i];
    }

    pBuf[j] = '\0';
}

/* Finds @p pKey in an a{sv} and leaves @p pValue on its variant's content. */
static xbool_t DirectGate_WL_DictFind(DBusMessageIter *pDict, const char *pKey, DBusMessageIter *pValue)
{
    DBusMessageIter dict = *pDict;

    while (g_dbus.iterArgType(&dict) == DBUS_TYPE_DICT_ENTRY)
    {
        DBusMessageIter entry, variant;
        const char *pName = NULL;

        g_dbus.iterRecurse(&dict, &entry);
        if (g_dbus.iterArgType(&entry) != DBUS_TYPE_STRING) break;

        g_dbus.iterGet(&entry, &pName);
        g_dbus.iterNext(&entry);

        if (g_dbus.iterArgType(&entry) == DBUS_TYPE_VARIANT && pName != NULL && xstrcmp(pName, pKey))
        {
            g_dbus.iterRecurse(&entry, &variant);
            *pValue = variant;
            return XTRUE;
        }

        if (!g_dbus.iterNext(&dict)) break;
    }

    return XFALSE;
}

/* Waits for the Request.Response signal on @p pPath.
 *
 * Returns XSTDOK when the portal answered success and leaves the results
 * dictionary in @p pResults (valid while @p ppMessage lives, which the caller
 * must unref). Response code 1 is the user cancelling, 2 is the portal
 * ending the request itself; both are refusals, not errors to retry. */
static int DirectGate_WL_WaitResponse(directgate_wl_portal_t *pPortal, const char *pPath,
                                      int nTimeoutMs, DBusMessage **ppMessage,
                                      DBusMessageIter *pResults, char *pErrBuf, size_t nErrSize)
{
    uint64_t nDeadline = XTime_GetMs() + (uint64_t)nTimeoutMs;
    *ppMessage = NULL;

    while (XTime_GetMs() < nDeadline)
    {
        if (!g_dbus.readWrite(pPortal->pConn, 100))
        {
            DirectGate_WL_PortalSetError(pErrBuf, nErrSize, "The D-Bus connection to the portal was lost.");
            return XSTDERR;
        }

        DBusMessage *pMessage = NULL;
        while ((pMessage = g_dbus.pop(pPortal->pConn)) != NULL)
        {
            const char *pMsgPath = g_dbus.msgPath != NULL ? g_dbus.msgPath(pMessage) : NULL;

            if (!g_dbus.isSignal(pMessage, DIRECTGATE_PORTAL_REQUEST, "Response") ||
                pMsgPath == NULL || !xstrcmp(pMsgPath, pPath))
            {
                g_dbus.msgUnref(pMessage);
                continue;
            }

            DBusMessageIter iter;
            dbus_uint32_t nResponse = 2;

            if (!g_dbus.iterInit(pMessage, &iter) ||
                g_dbus.iterArgType(&iter) != DBUS_TYPE_UINT32)
            {
                g_dbus.msgUnref(pMessage);
                DirectGate_WL_PortalSetError(pErrBuf, nErrSize, "The portal sent a malformed response.");
                return XSTDERR;
            }

            g_dbus.iterGet(&iter, &nResponse);
            g_dbus.iterNext(&iter);

            if (nResponse != 0)
            {
                g_dbus.msgUnref(pMessage);

                /* Told apart because a refusal must not be answered with
                 * another prompt, while a request that merely failed may be
                 * worth retrying without a stale grant. */
                if (nResponse == 1 && pPortal->pDeclined != NULL) *pPortal->pDeclined = XTRUE;

                DirectGate_WL_PortalSetError(pErrBuf, nErrSize, nResponse == 1 ?
                    "Screen sharing was declined on the remote computer." :
                    "The desktop portal ended the screen sharing request.");

                return XSTDERR;
            }

            if (g_dbus.iterArgType(&iter) == DBUS_TYPE_ARRAY)
                g_dbus.iterRecurse(&iter, pResults);
            else
                memset(pResults, 0, sizeof(*pResults));

            *ppMessage = pMessage;
            return XSTDOK;
        }
    }

    DirectGate_WL_PortalSetError(pErrBuf, nErrSize,
        "The desktop portal did not answer in time. No one may have been at the remote computer to allow it.");

    return XSTDERR;
}

/* Reads a uint32 property off one of the portal interfaces.
 *
 * The portal rejects a request outright when it carries an option the running
 * version does not know, so the options below are chosen from what it says it
 * supports rather than from what the newest specification allows. Asking is
 * one round trip; guessing wrong costs the whole session. */
static uint32_t DirectGate_WL_PortalPropertyUint(directgate_wl_portal_t *pPortal,
                                                 const char *pInterface,
                                                 const char *pProperty,
                                                 uint32_t nFallback)
{
    DBusMessage *pCall = g_dbus.newCall(DIRECTGATE_PORTAL_BUS, DIRECTGATE_PORTAL_PATH,
        "org.freedesktop.DBus.Properties", "Get");

    if (pCall == NULL) return nFallback;

    DBusMessageIter args;
    g_dbus.iterInitAppend(pCall, &args);
    g_dbus.iterAppend(&args, DBUS_TYPE_STRING, &pInterface);
    g_dbus.iterAppend(&args, DBUS_TYPE_STRING, &pProperty);

    DBusError error;
    g_dbus.errorInit(&error);

    DBusMessage *pReply = g_dbus.sendBlock(pPortal->pConn, pCall, DIRECTGATE_PORTAL_CALL_MS, &error);
    g_dbus.msgUnref(pCall);

    if (pReply == NULL)
    {
        if (g_dbus.errorFree != NULL) g_dbus.errorFree(&error);
        return nFallback;
    }

    DBusMessageIter iter, variant;
    uint32_t nValue = nFallback;

    if (g_dbus.iterInit(pReply, &iter) && g_dbus.iterArgType(&iter) == DBUS_TYPE_VARIANT)
    {
        g_dbus.iterRecurse(&iter, &variant);

        if (g_dbus.iterArgType(&variant) == DBUS_TYPE_UINT32)
        {
            dbus_uint32_t nRead = 0;
            g_dbus.iterGet(&variant, &nRead);
            nValue = (uint32_t)nRead;
        }
    }

    g_dbus.msgUnref(pReply);
    return nValue;
}

/* Options a caller wants added to a portal request, beyond handle_token. */
typedef void (*directgate_wl_options_fn)(DBusMessageIter *pDict, void *pCtx);

/* One portal request from end to end: subscribe, call, wait for the Response.
 *
 * The subscription happens before the call precisely because the answer can
 * arrive before the call returns. @p pSessionHandle, when set, is prepended
 * as the object-path argument every method except CreateSession takes. */
static int DirectGate_WL_PortalRequest(directgate_wl_portal_t *pPortal,
                                       const char *pInterface, const char *pMethod,
                                       const char *pSessionHandle, const char *pParentWindow,
                                       directgate_wl_options_fn fnOptions, void *pOptionsCtx,
                                       int nTimeoutMs, DBusMessage **ppResponse,
                                       DBusMessageIter *pResults, char *pErrBuf, size_t nErrSize)
{
    char sToken[128];
    char sPath[512];
    char sRule[768];
    DBusError error;

    DirectGate_WL_MakeToken(pPortal, sToken, sizeof(sToken));
    DirectGate_WL_RequestPath(pPortal, sToken, sPath, sizeof(sPath));

    snprintf(sRule, sizeof(sRule),
        "type='signal',interface='%s',member='Response',path='%s'",
        DIRECTGATE_PORTAL_REQUEST, sPath);

    g_dbus.errorInit(&error);
    g_dbus.addMatch(pPortal->pConn, sRule, &error);

    if (g_dbus.errorIsSet != NULL && g_dbus.errorIsSet(&error))
    {
        DirectGate_WL_PortalSetError(pErrBuf, nErrSize, "Failed to subscribe to the portal response: %s", error.message);
        g_dbus.errorFree(&error);
        return XSTDERR;
    }

    DBusMessage *pCall = g_dbus.newCall(DIRECTGATE_PORTAL_BUS, DIRECTGATE_PORTAL_PATH, pInterface, pMethod);
    if (pCall == NULL)
    {
        DirectGate_WL_PortalSetError(pErrBuf, nErrSize, "Out of memory building a portal request.");
        return XSTDERR;
    }

    DBusMessageIter args, dict;
    g_dbus.iterInitAppend(pCall, &args);

    if (pSessionHandle != NULL)
        g_dbus.iterAppend(&args, DBUS_TYPE_OBJECT_PATH, &pSessionHandle);

    if (pParentWindow != NULL)
        g_dbus.iterAppend(&args, DBUS_TYPE_STRING, &pParentWindow);

    if (!g_dbus.iterOpen(&args, DBUS_TYPE_ARRAY, "{sv}", &dict))
    {
        g_dbus.msgUnref(pCall);
        DirectGate_WL_PortalSetError(pErrBuf, nErrSize, "Failed to build the portal request options.");
        return XSTDERR;
    }

    const char *pTokenKey = sToken;
    DirectGate_WL_DictString(&dict, "handle_token", pTokenKey);
    if (fnOptions != NULL) fnOptions(&dict, pOptionsCtx);
    g_dbus.iterClose(&args, &dict);

    DBusMessage *pReply = g_dbus.sendBlock(pPortal->pConn, pCall, DIRECTGATE_PORTAL_CALL_MS, &error);
    g_dbus.msgUnref(pCall);

    if (pReply == NULL)
    {
        DirectGate_WL_PortalSetError(pErrBuf, nErrSize, "The desktop portal refused %s: %s",
            pMethod, (g_dbus.errorIsSet != NULL && g_dbus.errorIsSet(&error) && error.message) ?
                error.message : "no reply");

        if (g_dbus.errorFree != NULL) g_dbus.errorFree(&error);
        return XSTDERR;
    }

    /* The path the portal actually created wins over the predicted one. The
     * prediction exists only to subscribe before the answer can arrive; the
     * reply is the authority, and following it is the difference between a
     * prompt whose answer lands and one that is waited out in full and then
     * reported as "the portal did not answer" - with the person who pressed
     * Allow watching nothing happen. */
    DBusMessageIter replyIter;
    if (g_dbus.iterInit(pReply, &replyIter) &&
        g_dbus.iterArgType(&replyIter) == DBUS_TYPE_OBJECT_PATH)
    {
        const char *pActual = NULL;
        g_dbus.iterGet(&replyIter, &pActual);

        if (xstrused(pActual) && !xstrcmp(pActual, sPath))
        {
            xlogw("Portal request path differs from the predicted one, following the portal: "
                  "expected(%s), got(%s)", sPath, pActual);

            snprintf(sRule, sizeof(sRule),
                "type='signal',interface='%s',member='Response',path='%s'",
                DIRECTGATE_PORTAL_REQUEST, pActual);

            g_dbus.errorInit(&error);
            g_dbus.addMatch(pPortal->pConn, sRule, &error);

            if (g_dbus.errorIsSet != NULL && g_dbus.errorIsSet(&error))
            {
                xlogw("Failed to subscribe to the portal's own response path: %s",
                    error.message != NULL ? error.message : "unknown");

                g_dbus.errorFree(&error);
            }
            else xstrncpy(sPath, sizeof(sPath), pActual);
        }
    }

    g_dbus.msgUnref(pReply);

    return DirectGate_WL_WaitResponse(pPortal, sPath, nTimeoutMs, ppResponse, pResults, pErrBuf, nErrSize);
}

/* SelectSources option sets, richest first.
 *
 * Portal implementations disagree about which options a session created
 * through RemoteDesktop may carry, and a rejected option fails the entire
 * request rather than being ignored. Rather than encode one reading of the
 * specification and lose a session when it is wrong, the richest set is tried
 * and the client steps down until one is accepted - and says which. */
typedef enum {
    DIRECTGATE_WL_OPTS_FULL = 0, /* types + persistence + the remembered grant */
    DIRECTGATE_WL_OPTS_FRESH,    /* ... persistence, but asking anew */
    DIRECTGATE_WL_OPTS_MINIMAL,  /* types only: accepted by every version */
    DIRECTGATE_WL_OPTS_COUNT
} directgate_wl_opts_t;

typedef struct directgate_wl_sources_ {
    uint32_t nVersion;      /* ScreenCast interface version */
    uint32_t nCursorModes;  /* AvailableCursorModes bitmask, for the log */
    uint32_t nSourceTypes;  /* AvailableSourceTypes bitmask */
    directgate_wl_opts_t eProfile;
} directgate_wl_sources_t;

static void DirectGate_WL_SessionOptions(DBusMessageIter *pDict, void *pCtx)
{
    directgate_wl_portal_t *pPortal = (directgate_wl_portal_t*)pCtx;
    char sToken[128];

    DirectGate_WL_MakeToken(pPortal, sToken, sizeof(sToken));
    DirectGate_WL_DictString(pDict, "session_handle_token", sToken);
}

static void DirectGate_WL_SourceOptions(DBusMessageIter *pDict, void *pCtx)
{
    directgate_wl_sources_t *pSources = (directgate_wl_sources_t*)pCtx;

    /* Whole monitors only, and only if the portal offers them. */
    uint32_t nTypes = (pSources->nSourceTypes & DIRECTGATE_PORTAL_SOURCE_MONITOR) ?
        DIRECTGATE_PORTAL_SOURCE_MONITOR : pSources->nSourceTypes;

    DirectGate_WL_DictUint(pDict, "types", nTypes ? nTypes : DIRECTGATE_PORTAL_SOURCE_MONITOR);

    /* Let the person choose more than one screen. Without this the portal
     * grants exactly one and the monitor list can only ever hold that one,
     * which on a two-screen machine looks like the other screen does not
     * exist. Worth one retry without it if a portal objects - one screen
     * beats no session. */
    if (pSources->eProfile == DIRECTGATE_WL_OPTS_FULL)
        DirectGate_WL_DictBool(pDict, "multiple", XTRUE);

    /* No cursor_mode is asked for, on purpose. The host cursor has to stay
     * out of the frames - the viewer's own pointer is the cursor, and drawing
     * the host's one as well puts two arrows on screen with only one of them
     * under their hand - and "hidden" is exactly what the portal does when it
     * is not told otherwise. Asking for it anyway would add one more option
     * for a portal to refuse, and a refused option fails the whole request,
     * not just that option. (This used to ask for the cursor to be drawn in,
     * which is not the default and did have to be requested.) */

    /* Persistence is asked for on RemoteDesktop.SelectDevices and nowhere
     * else. This session belongs to RemoteDesktop - the screens are being
     * selected onto it, not the other way round - so the grant that gets
     * remembered is the device grant, and its token is a RemoteDesktop token.
     * Offering that same token here asked ScreenCast to restore something
     * that was never its to give: one more option to be refused, and a
     * refusal fails the entire request. */
}

static const char* DirectGate_WL_OptsName(directgate_wl_opts_t eProfile)
{
    switch (eProfile)
    {
        case DIRECTGATE_WL_OPTS_FULL: return "types+persist+restore";
        case DIRECTGATE_WL_OPTS_FRESH: return "types+persist";
        default: return "types";
    }
}

typedef struct directgate_wl_devices_ {
    const char *pRestoreToken;
    uint32_t nVersion;  /* RemoteDesktop interface version */
    directgate_wl_opts_t eProfile;
} directgate_wl_devices_t;

static void DirectGate_WL_DeviceOptions(DBusMessageIter *pDict, void *pCtx)
{
    directgate_wl_devices_t *pDevices = (directgate_wl_devices_t*)pCtx;

    DirectGate_WL_DictUint(pDict, "types",
        DIRECTGATE_PORTAL_DEVICE_KEYBOARD | DIRECTGATE_PORTAL_DEVICE_POINTER);

    /* For a session that owns input, persistence belongs to RemoteDesktop and
     * not to ScreenCast - it is the device grant being remembered, not just
     * the picture. Version 2 is where the interface gained it.
     *
     * Asking to be remembered and presenting a remembered grant are separate
     * steps here, and only the second is given up when the portal refuses.
     * A token it will not take - expired, spent by another session, granted
     * for screens that are gone - then costs one prompt, after which a new
     * one is stored. Dropping both together is how an agent ends up asking on
     * every connection and never storing anything, which on a machine nobody
     * is sitting at means nobody can get in at all. */
    if (pDevices != NULL && pDevices->nVersion >= 2)
    {
        DirectGate_WL_DictUint(pDict, "persist_mode", DIRECTGATE_PORTAL_PERSIST_SESSION);

        /* Only a UUID is accepted here; a token file that has been truncated
         * or hand-edited would otherwise fail the request rather than simply
         * being ignored. */
        if (pDevices->eProfile == DIRECTGATE_WL_OPTS_FULL &&
            xstrused(pDevices->pRestoreToken) && strlen(pDevices->pRestoreToken) == 36)
            DirectGate_WL_DictString(pDict, "restore_token", pDevices->pRestoreToken);
    }
}

/* Pulls every granted stream out of the a(ua{sv}) the Start response carries.
 *
 * The portal returns one entry per source the person allowed, so this is what
 * decides how many screens the viewer is offered. Sizes are optional; the
 * PipeWire format is authoritative either way. */
static xbool_t DirectGate_WL_ParseStreams(directgate_wl_portal_t *pPortal, DBusMessageIter *pResults)
{
    DBusMessageIter streams;
    if (!DirectGate_WL_DictFind(pResults, "streams", &streams)) return XFALSE;
    if (g_dbus.iterArgType(&streams) != DBUS_TYPE_ARRAY) return XFALSE;

    DBusMessageIter array;
    g_dbus.iterRecurse(&streams, &array);

    pPortal->nStreamCount = 0;

    while (g_dbus.iterArgType(&array) == DBUS_TYPE_STRUCT &&
           pPortal->nStreamCount < DIRECTGATE_WL_MAX_STREAMS)
    {
        DBusMessageIter entry;
        dbus_uint32_t nNodeId = 0;

        g_dbus.iterRecurse(&array, &entry);

        if (g_dbus.iterArgType(&entry) == DBUS_TYPE_UINT32)
        {
            g_dbus.iterGet(&entry, &nNodeId);

            directgate_wl_stream_t *pStream = &pPortal->streams[pPortal->nStreamCount];
            memset(pStream, 0, sizeof(*pStream));
            pStream->nNodeId = (uint32_t)nNodeId;

            if (g_dbus.iterNext(&entry) && g_dbus.iterArgType(&entry) == DBUS_TYPE_ARRAY)
            {
                DBusMessageIter props, value;
                g_dbus.iterRecurse(&entry, &props);

                if (DirectGate_WL_DictFind(&props, "size", &value) &&
                    g_dbus.iterArgType(&value) == DBUS_TYPE_STRUCT)
                {
                    DBusMessageIter dims;
                    dbus_int32_t nWidth = 0, nHeight = 0;

                    g_dbus.iterRecurse(&value, &dims);
                    if (g_dbus.iterArgType(&dims) == DBUS_TYPE_INT32)
                    {
                        g_dbus.iterGet(&dims, &nWidth);
                        if (g_dbus.iterNext(&dims) && g_dbus.iterArgType(&dims) == DBUS_TYPE_INT32)
                            g_dbus.iterGet(&dims, &nHeight);
                    }

                    if (nWidth > 0 && nHeight > 0)
                    {
                        pStream->nWidth = (uint32_t)nWidth;
                        pStream->nHeight = (uint32_t)nHeight;
                    }
                }

                if (DirectGate_WL_DictFind(&props, "position", &value) &&
                    g_dbus.iterArgType(&value) == DBUS_TYPE_STRUCT)
                {
                    DBusMessageIter pos;
                    dbus_int32_t nX = 0, nY = 0;

                    g_dbus.iterRecurse(&value, &pos);
                    if (g_dbus.iterArgType(&pos) == DBUS_TYPE_INT32)
                    {
                        g_dbus.iterGet(&pos, &nX);
                        if (g_dbus.iterNext(&pos) && g_dbus.iterArgType(&pos) == DBUS_TYPE_INT32)
                            g_dbus.iterGet(&pos, &nY);
                    }

                    pStream->nX = (int32_t)nX;
                    pStream->nY = (int32_t)nY;
                }
            }

            pPortal->nStreamCount++;
        }

        if (!g_dbus.iterNext(&array)) break;
    }

    return pPortal->nStreamCount > 0 ? XTRUE : XFALSE;
}

xbool_t DirectGate_WL_PortalHasInput(const directgate_wl_portal_t *pPortal)
{
    if (pPortal == NULL) return XFALSE;
    return (pPortal->nDevices & (DIRECTGATE_PORTAL_DEVICE_KEYBOARD | DIRECTGATE_PORTAL_DEVICE_POINTER)) ? XTRUE : XFALSE;
}

xbool_t DirectGate_WL_PortalKeysymRefused(const directgate_wl_portal_t *pPortal)
{
    return (pPortal != NULL && pPortal->bKeysymRefused) ? XTRUE : XFALSE;
}

uint32_t DirectGate_WL_PortalStreamCount(const directgate_wl_portal_t *pPortal)
{
    return pPortal != NULL ? pPortal->nStreamCount : 0;
}

const directgate_wl_stream_t* DirectGate_WL_PortalStream(const directgate_wl_portal_t *pPortal, uint32_t nIndex)
{
    if (pPortal == NULL || nIndex >= pPortal->nStreamCount) return NULL;
    return &pPortal->streams[nIndex];
}

directgate_wl_portal_t* DirectGate_WL_PortalOpen(const char *pRestoreToken,
                                                 char *pNewToken, size_t nTokenSize,
                                                 xbool_t *pDeclined,
                                                 char *pErrBuf, size_t nErrSize)
{
    if (pDeclined != NULL) *pDeclined = XFALSE;
    if (DirectGate_WL_DBusLoad(pErrBuf, nErrSize) != XSTDOK) return NULL;

    directgate_wl_portal_t *pPortal = (directgate_wl_portal_t*)calloc(1, sizeof(*pPortal));
    if (pPortal == NULL)
    {
        DirectGate_WL_PortalSetError(pErrBuf, nErrSize, "Out of memory opening the desktop portal.");
        return NULL;
    }

    pPortal->pDeclined = pDeclined;

    DBusError error;
    g_dbus.errorInit(&error);

    pPortal->pConn = g_dbus.busGet(DBUS_BUS_SESSION, &error);
    if (pPortal->pConn == NULL)
    {
        DirectGate_WL_PortalSetError(pErrBuf, nErrSize,
            "No session D-Bus is reachable, so the desktop portal cannot be asked for permission: %s",
            (error.message != NULL) ? error.message : "unavailable");

        if (g_dbus.errorFree != NULL) g_dbus.errorFree(&error);
        free(pPortal);
        return NULL;
    }

    /* A private connection defaults to killing the process when the bus goes
     * away. The agent has many other things to do; a lost portal is a lost
     * desktop session, not a lost agent. */
    if (g_dbus.setExitOnDisconnect != NULL)
        g_dbus.setExitOnDisconnect(pPortal->pConn, FALSE);

    const char *pUnique = g_dbus.uniqueName(pPortal->pConn);
    if (!xstrused(pUnique))
    {
        DirectGate_WL_PortalSetError(pErrBuf, nErrSize, "The session D-Bus did not assign this agent a name.");
        DirectGate_WL_PortalClose(pPortal);
        return NULL;
    }

    DirectGate_WL_MangleSender(pUnique, pPortal->sSenderId, sizeof(pPortal->sSenderId));

    /* 1. CreateSession on RemoteDesktop, not ScreenCast: the session has to
     *    own input as well, and only the RemoteDesktop interface can create
     *    one that does. ScreenCast then attaches to this same session, which
     *    is what keeps it to a single prompt. */
    DBusMessage *pResponse = NULL;
    DBusMessageIter results;

    if (DirectGate_WL_PortalRequest(pPortal, DIRECTGATE_PORTAL_REMOTE, "CreateSession",
            NULL, NULL, DirectGate_WL_SessionOptions, pPortal,
            DIRECTGATE_PORTAL_CALL_MS, &pResponse, &results, pErrBuf, nErrSize) != XSTDOK)
    {
        DirectGate_WL_PortalClose(pPortal);
        return NULL;
    }

    DBusMessageIter handle;
    const char *pSessionHandle = NULL;

    if (DirectGate_WL_DictFind(&results, "session_handle", &handle) &&
        g_dbus.iterArgType(&handle) == DBUS_TYPE_STRING)
        g_dbus.iterGet(&handle, &pSessionHandle);

    if (!xstrused(pSessionHandle))
    {
        g_dbus.msgUnref(pResponse);
        DirectGate_WL_PortalSetError(pErrBuf, nErrSize, "The desktop portal did not return a session.");
        DirectGate_WL_PortalClose(pPortal);
        return NULL;
    }

    xstrncpy(pPortal->sSessionHandle, sizeof(pPortal->sSessionHandle), pSessionHandle);
    g_dbus.msgUnref(pResponse);

    /* 2. What the portal admits to supporting, before anything is asked of
     *    it. Every option below is chosen from these numbers. */
    directgate_wl_sources_t sources;
    memset(&sources, 0, sizeof(sources));

    sources.nVersion = DirectGate_WL_PortalPropertyUint(pPortal, DIRECTGATE_PORTAL_SCREEN, "version", 1);
    sources.nCursorModes = DirectGate_WL_PortalPropertyUint(pPortal, DIRECTGATE_PORTAL_SCREEN, "AvailableCursorModes", 0);
    sources.nSourceTypes = DirectGate_WL_PortalPropertyUint(pPortal, DIRECTGATE_PORTAL_SCREEN, "AvailableSourceTypes", DIRECTGATE_PORTAL_SOURCE_MONITOR);

    directgate_wl_devices_t devices;
    memset(&devices, 0, sizeof(devices));

    devices.pRestoreToken = pRestoreToken;
    devices.nVersion = DirectGate_WL_PortalPropertyUint(pPortal, DIRECTGATE_PORTAL_REMOTE, "version", 1);

    xlogi("Desktop portal capabilities: screencast(v%u), cursorModes(0x%X), sourceTypes(0x%X), remotedesktop(v%u)",
        sources.nVersion, sources.nCursorModes, sources.nSourceTypes, devices.nVersion);

    /* 3. What to inject, and whether to remember it. Devices before sources,
     *    which is the order the portal's own reference flow uses for a session
     *    that does both. A compositor without RemoteDesktop support fails here,
     *    and the message says so rather than blaming the capture.
     *
     *    This is also where the remembered grant is presented, so it is where
     *    the step down happens: a token the portal will not take costs one
     *    prompt, never the ability to store a new one. */
    xbool_t bHaveToken = (xstrused(pRestoreToken) && strlen(pRestoreToken) == 36) ? XTRUE : XFALSE;
    int nDevSelected = XSTDERR;

    for (int i = 0; i <= (int)DIRECTGATE_WL_OPTS_FRESH && nDevSelected != XSTDOK; i++)
    {
        devices.eProfile = (directgate_wl_opts_t)i;

        /* With nothing to present, the two sets are the same request twice. */
        if (devices.eProfile == DIRECTGATE_WL_OPTS_FULL && !bHaveToken) continue;

        nDevSelected = DirectGate_WL_PortalRequest(pPortal, DIRECTGATE_PORTAL_REMOTE, "SelectDevices",
            pPortal->sSessionHandle, NULL, DirectGate_WL_DeviceOptions, &devices,
            DIRECTGATE_PORTAL_CALL_MS, &pResponse, &results, pErrBuf, nErrSize);

        if (nDevSelected == XSTDOK)
        {
            xlogi("Desktop portal accepted the input options: options(%s)",
                DirectGate_WL_OptsName(devices.eProfile));

            if (bHaveToken && devices.eProfile != DIRECTGATE_WL_OPTS_FULL)
                xlogw("The remembered desktop sharing permission was not accepted; "
                      "asking once more so a new one can be stored");

            if (devices.nVersion < 2)
                xlogw("This desktop portal cannot remember the permission (remotedesktop v%u); "
                      "every connection has to be allowed on the remote computer", devices.nVersion);

            break;
        }

        xlogw("Desktop portal rejected the input options, retrying with fewer: options(%s), reason(%s)",
            DirectGate_WL_OptsName(devices.eProfile), (pErrBuf != NULL && pErrBuf[0]) ? pErrBuf : "unspecified");
    }

    if (nDevSelected != XSTDOK)
    {
        DirectGate_WL_PortalClose(pPortal);
        return NULL;
    }

    g_dbus.msgUnref(pResponse);
    int nSelected = XSTDERR;

    /* The screens carry no grant of their own on this session, so there is
     * one thing left that a portal might refuse: being offered more than one
     * screen to pick. */
    for (int i = 0; i < DIRECTGATE_WL_OPTS_COUNT && nSelected != XSTDOK; i++)
    {
        sources.eProfile = (directgate_wl_opts_t)i;
        if (sources.eProfile == DIRECTGATE_WL_OPTS_FRESH) continue;

        nSelected = DirectGate_WL_PortalRequest(pPortal, DIRECTGATE_PORTAL_SCREEN, "SelectSources",
            pPortal->sSessionHandle, NULL, DirectGate_WL_SourceOptions, &sources,
            DIRECTGATE_PORTAL_CALL_MS, &pResponse, &results, pErrBuf, nErrSize);

        if (nSelected == XSTDOK)
        {
            xlogi("Desktop portal accepted the capture options: options(%s)",
                sources.eProfile == DIRECTGATE_WL_OPTS_FULL ? "types+multiple" : "types");

            break;
        }

        xlogw("Desktop portal rejected the capture options, retrying with fewer: reason(%s)",
            (pErrBuf != NULL && pErrBuf[0]) ? pErrBuf : "unspecified");
    }

    if (nSelected != XSTDOK)
    {
        DirectGate_WL_PortalClose(pPortal);
        return NULL;
    }

    g_dbus.msgUnref(pResponse);

    /* 4. Start: this is the one a human answers, so it gets the long wait. */
    xlogi("Waiting for desktop sharing to be allowed on the remote computer");

    if (DirectGate_WL_PortalRequest(pPortal, DIRECTGATE_PORTAL_REMOTE, "Start",
            pPortal->sSessionHandle, "", NULL, NULL,
            DIRECTGATE_PORTAL_GRANT_MS, &pResponse, &results, pErrBuf, nErrSize) != XSTDOK)
    {
        DirectGate_WL_PortalClose(pPortal);
        return NULL;
    }

    if (!DirectGate_WL_ParseStreams(pPortal, &results))
    {
        g_dbus.msgUnref(pResponse);
        DirectGate_WL_PortalSetError(pErrBuf, nErrSize, "The desktop portal allowed sharing but returned no stream.");
        DirectGate_WL_PortalClose(pPortal);
        return NULL;
    }

    /* What the compositor granted for input. A screen-cast-only backend
     * answers zero here, and the session must then say that remote control
     * is unavailable rather than silently swallowing every keystroke. */
    DBusMessageIter devicesIter;
    if (DirectGate_WL_DictFind(&results, "devices", &devicesIter) &&
        g_dbus.iterArgType(&devicesIter) == DBUS_TYPE_UINT32)
    {
        dbus_uint32_t nDevices = 0;
        g_dbus.iterGet(&devicesIter, &nDevices);
        pPortal->nDevices = (uint32_t)nDevices;
    }

    /* The token that lets the next session skip the prompt. Persisting it is
     * the caller's business; losing it costs a prompt, not a session. */
    DBusMessageIter token;
    if (pNewToken != NULL && nTokenSize > 0)
    {
        const char *pToken = NULL;
        pNewToken[0] = '\0';

        if (DirectGate_WL_DictFind(&results, "restore_token", &token) &&
            g_dbus.iterArgType(&token) == DBUS_TYPE_STRING)
        {
            g_dbus.iterGet(&token, &pToken);
            if (xstrused(pToken)) xstrncpy(pNewToken, nTokenSize, pToken);
        }
    }

    g_dbus.msgUnref(pResponse);

    for (uint32_t i = 0; i < pPortal->nStreamCount; i++)
    {
        xlogi("Desktop sharing allowed: screen(%u/%u), node(%u), size(%ux%u), at(%d,%d)",
            i + 1U, pPortal->nStreamCount, pPortal->streams[i].nNodeId,
            pPortal->streams[i].nWidth, pPortal->streams[i].nHeight,
            pPortal->streams[i].nX, pPortal->streams[i].nY);
    }

    xlogi("Desktop sharing input granted: keyboard(%s), pointer(%s)",
        (pPortal->nDevices & DIRECTGATE_PORTAL_DEVICE_KEYBOARD) ? "yes" : "no",
        (pPortal->nDevices & DIRECTGATE_PORTAL_DEVICE_POINTER) ? "yes" : "no");

    xlogi("Desktop sharing permission remembered: restore(%s)",
        (pNewToken != NULL && pNewToken[0]) ? "yes" : "no");

    return pPortal;
}

int DirectGate_WL_PortalOpenPipeWire(directgate_wl_portal_t *pPortal, char *pErrBuf, size_t nErrSize)
{
    XCHECK((pPortal != NULL && pPortal->pConn != NULL), -1);

    /* Unlike everything above, this one answers directly: there is no user
     * decision left to make, so no Request object is involved. */
    DBusMessage *pCall = g_dbus.newCall(DIRECTGATE_PORTAL_BUS, DIRECTGATE_PORTAL_PATH,
        DIRECTGATE_PORTAL_SCREEN, "OpenPipeWireRemote");

    if (pCall == NULL)
    {
        DirectGate_WL_PortalSetError(pErrBuf, nErrSize, "Out of memory opening the PipeWire remote.");
        return -1;
    }

    DBusMessageIter args, dict;
    const char *pSession = pPortal->sSessionHandle;

    g_dbus.iterInitAppend(pCall, &args);
    g_dbus.iterAppend(&args, DBUS_TYPE_OBJECT_PATH, &pSession);

    if (g_dbus.iterOpen(&args, DBUS_TYPE_ARRAY, "{sv}", &dict))
        g_dbus.iterClose(&args, &dict);

    DBusError error;
    g_dbus.errorInit(&error);

    DBusMessage *pReply = g_dbus.sendBlock(pPortal->pConn, pCall, DIRECTGATE_PORTAL_CALL_MS, &error);
    g_dbus.msgUnref(pCall);

    if (pReply == NULL)
    {
        DirectGate_WL_PortalSetError(pErrBuf, nErrSize, "The desktop portal would not open the video stream: %s",
            (error.message != NULL) ? error.message : "no reply");

        if (g_dbus.errorFree != NULL) g_dbus.errorFree(&error);
        return -1;
    }

    DBusMessageIter iter;
    int nFd = -1;

    if (g_dbus.iterInit(pReply, &iter) && g_dbus.iterArgType(&iter) == DBUS_TYPE_UNIX_FD)
        g_dbus.iterGet(&iter, &nFd);

    g_dbus.msgUnref(pReply);

    if (nFd < 0)
        DirectGate_WL_PortalSetError(pErrBuf, nErrSize, "The desktop portal returned no video stream descriptor.");

    return nFd;
}

/* Non-blocking sweep of anything the bus sent back, so a refused input event
 * is visible. Rate-limited: a portal that rejects everything would otherwise
 * turn one broken session into a flooded log. */
static void DirectGate_WL_PortalDrainErrors(directgate_wl_portal_t *pPortal, const char *pMethod)
{
    if (g_dbus.readWrite == NULL || g_dbus.pop == NULL) return;

    g_dbus.readWrite(pPortal->pConn, 0);

    DBusMessage *pMessage = NULL;
    while ((pMessage = g_dbus.pop(pPortal->pConn)) != NULL)
    {
        /* An error name is only ever set on an error reply, so it identifies
         * one without depending on the message-type accessor resolving. */
        const char *pName = g_dbus.msgErrorName != NULL ? g_dbus.msgErrorName(pMessage) : NULL;

        if (xstrused(pName))
        {
            /* Which method was refused decides what it costs. Keysyms are the
             * only way to type a character the host keyboard layout does not
             * carry, so a portal that will not take them can still be typed
             * on - just not in another script - and the viewer is better told
             * than left wondering why some keys do nothing. */
            if (xstrcmp(pMethod, "NotifyKeyboardKeysym")) pPortal->bKeysymRefused = XTRUE;

            if (pPortal->nInputErrors < 3)
            {
                pPortal->nInputErrors++;
                xloge("The desktop portal refused an input event: method(%s), error(%s)", pMethod, pName);
            }
        }

        g_dbus.msgUnref(pMessage);
    }
}

/* Fire-and-forget: input is a stream of small messages whose value is that
 * they arrive quickly, and blocking on a round trip for every mouse move
 * would put the whole D-Bus latency in the input path. */
static int DirectGate_WL_PortalNotify(directgate_wl_portal_t *pPortal, const char *pMethod,
                                      void (*fnArgs)(DBusMessageIter*, void*), void *pCtx)
{
    XCHECK((pPortal != NULL && pPortal->pConn != NULL), XSTDERR);

    DBusMessage *pCall = g_dbus.newCall(DIRECTGATE_PORTAL_BUS, DIRECTGATE_PORTAL_PATH,
        DIRECTGATE_PORTAL_REMOTE, pMethod);

    XCHECK((pCall != NULL), XSTDERR);

    DBusMessageIter args, dict;
    const char *pSession = pPortal->sSessionHandle;

    g_dbus.iterInitAppend(pCall, &args);
    g_dbus.iterAppend(&args, DBUS_TYPE_OBJECT_PATH, &pSession);

    if (g_dbus.iterOpen(&args, DBUS_TYPE_ARRAY, "{sv}", &dict))
        g_dbus.iterClose(&args, &dict);

    if (fnArgs != NULL) fnArgs(&args, pCtx);

    dbus_bool_t bSent = (g_dbus.send != NULL) ? g_dbus.send(pPortal->pConn, pCall, NULL) : FALSE;
    g_dbus.msgUnref(pCall);

    if (g_dbus.flush != NULL) g_dbus.flush(pPortal->pConn);

    /* Input is sent without waiting for a reply, so a portal that refuses
     * every event would otherwise do it in complete silence - which is
     * indistinguishable from input that works and does nothing. Errors are
     * collected here without blocking, and the first few are reported. */
    DirectGate_WL_PortalDrainErrors(pPortal, pMethod);

    return bSent ? XSTDOK : XSTDERR;
}

typedef struct directgate_wl_motion_ { dbus_uint32_t nStream; double nX, nY; } directgate_wl_motion_t;
typedef struct directgate_wl_button_ { dbus_int32_t nButton; dbus_uint32_t nState; } directgate_wl_button_t;
typedef struct directgate_wl_axis_ { double nDx, nDy; } directgate_wl_axis_t;
typedef struct directgate_wl_key_ { dbus_int32_t nKeysym; dbus_uint32_t nState; } directgate_wl_key_t;

static void DirectGate_WL_MotionArgs(DBusMessageIter *pArgs, void *pCtx)
{
    directgate_wl_motion_t *pMotion = (directgate_wl_motion_t*)pCtx;
    g_dbus.iterAppend(pArgs, DBUS_TYPE_UINT32, &pMotion->nStream);
    g_dbus.iterAppend(pArgs, DBUS_TYPE_DOUBLE, &pMotion->nX);
    g_dbus.iterAppend(pArgs, DBUS_TYPE_DOUBLE, &pMotion->nY);
}

static void DirectGate_WL_ButtonArgs(DBusMessageIter *pArgs, void *pCtx)
{
    directgate_wl_button_t *pButton = (directgate_wl_button_t*)pCtx;
    g_dbus.iterAppend(pArgs, DBUS_TYPE_INT32, &pButton->nButton);
    g_dbus.iterAppend(pArgs, DBUS_TYPE_UINT32, &pButton->nState);
}

static void DirectGate_WL_AxisArgs(DBusMessageIter *pArgs, void *pCtx)
{
    directgate_wl_axis_t *pAxis = (directgate_wl_axis_t*)pCtx;
    g_dbus.iterAppend(pArgs, DBUS_TYPE_DOUBLE, &pAxis->nDx);
    g_dbus.iterAppend(pArgs, DBUS_TYPE_DOUBLE, &pAxis->nDy);
}

static void DirectGate_WL_KeyArgs(DBusMessageIter *pArgs, void *pCtx)
{
    directgate_wl_key_t *pKey = (directgate_wl_key_t*)pCtx;
    g_dbus.iterAppend(pArgs, DBUS_TYPE_INT32, &pKey->nKeysym);
    g_dbus.iterAppend(pArgs, DBUS_TYPE_UINT32, &pKey->nState);
}

int DirectGate_WL_PortalPointerMotion(directgate_wl_portal_t *pPortal, uint32_t nStream, double nX, double nY)
{
    directgate_wl_motion_t motion = { nStream ? nStream : DirectGate_WL_PortalNodeId(pPortal), nX, nY };
    return DirectGate_WL_PortalNotify(pPortal, "NotifyPointerMotionAbsolute", DirectGate_WL_MotionArgs, &motion);
}

int DirectGate_WL_PortalPointerButton(directgate_wl_portal_t *pPortal, int32_t nButton, xbool_t bPressed)
{
    directgate_wl_button_t button = { (dbus_int32_t)nButton, bPressed ? 1U : 0U };
    return DirectGate_WL_PortalNotify(pPortal, "NotifyPointerButton", DirectGate_WL_ButtonArgs, &button);
}

int DirectGate_WL_PortalPointerAxis(directgate_wl_portal_t *pPortal, double nDx, double nDy)
{
    directgate_wl_axis_t axis = { nDx, nDy };
    return DirectGate_WL_PortalNotify(pPortal, "NotifyPointerAxis", DirectGate_WL_AxisArgs, &axis);
}

int DirectGate_WL_PortalKeysym(directgate_wl_portal_t *pPortal, int32_t nKeysym, xbool_t bPressed)
{
    directgate_wl_key_t key = { (dbus_int32_t)nKeysym, bPressed ? 1U : 0U };
    return DirectGate_WL_PortalNotify(pPortal, "NotifyKeyboardKeysym", DirectGate_WL_KeyArgs, &key);
}

int DirectGate_WL_PortalKeycode(directgate_wl_portal_t *pPortal, int32_t nKeycode, xbool_t bPressed)
{
    /* Same wire shape as the keysym call - an int32 and a state,
     * so the one argument writer serves both. */
    directgate_wl_key_t key = { (dbus_int32_t)nKeycode, bPressed ? 1U : 0U };
    return DirectGate_WL_PortalNotify(pPortal, "NotifyKeyboardKeycode", DirectGate_WL_KeyArgs, &key);
}

int32_t DirectGate_WL_PortalButtonCode(uint32_t nX11Button)
{
    /* evdev codes, which is what the portal takes - not the X11 numbering the
     * browser sends. Wheel buttons are absent on purpose: they are axis
     * motion here, not buttons. */
    switch (nX11Button)
    {
        case 1: return 0x110; /* BTN_LEFT */
        case 2: return 0x112; /* BTN_MIDDLE */
        case 3: return 0x111; /* BTN_RIGHT */
        case 8: return 0x113; /* BTN_SIDE (back) */
        case 9: return 0x114; /* BTN_EXTRA (forward) */
        default: return 0;
    }
}

uint32_t DirectGate_WL_PortalNodeId(const directgate_wl_portal_t *pPortal)
{
    return (pPortal != NULL && pPortal->nStreamCount > 0) ? pPortal->streams[0].nNodeId : 0;
}

void DirectGate_WL_PortalClose(directgate_wl_portal_t *pPortal)
{
    if (pPortal == NULL) return;

    /* Tell the portal the session is over. Without this the compositor keeps
     * the grant - and its "your screen is being shared" indicator - alive
     * until the connection happens to drop, which is both alarming to look at
     * and a permission outliving the thing it was granted for. */
    if (pPortal->pConn != NULL && pPortal->sSessionHandle[0] != '\0')
    {
        DBusMessage *pCall = g_dbus.newCall(DIRECTGATE_PORTAL_BUS, pPortal->sSessionHandle,
            "org.freedesktop.portal.Session", "Close");

        if (pCall != NULL)
        {
            if (g_dbus.send != NULL) g_dbus.send(pPortal->pConn, pCall, NULL);
            if (g_dbus.flush != NULL) g_dbus.flush(pPortal->pConn);
            g_dbus.msgUnref(pCall);
        }
    }

    if (pPortal->pConn != NULL)
    {
        /* Private connections must be closed as well as unreferenced, or the
         * socket and its match rules leak for the life of the process. */
        if (g_dbus.connClose != NULL) g_dbus.connClose(pPortal->pConn);
        if (g_dbus.connUnref != NULL) g_dbus.connUnref(pPortal->pConn);
    }

    free(pPortal);
}

#endif /* DIRECTGATE_DESKTOP_HAS_WAYLAND */
