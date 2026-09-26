/*
 * The Wayland desktop portal client against a portal served on a real bus.
 *
 * wayland_portal_smoke checks what the client serializes with the bus stubbed
 * out. This one starts a private dbus-daemon, plays org.freedesktop.portal.Desktop
 * on it with libdbus, and lets the unmodified client do what it does on a
 * GNOME or KDE host: create a RemoteDesktop session, read the portal's
 * capabilities, select devices and sources, wait for the grant, parse the
 * streams it returns, open the PipeWire remote, forward input and close.
 *
 * The portal can be told to misbehave the ways real ones do: refuse a stale
 * remembered grant or the multi-screen option (the client has to step down),
 * answer from a request path other than the one predicted, decline, fail,
 * never answer (the client has to honour its cancel flag), send a malformed
 * answer, leave out the session or the streams, be too old to remember a
 * grant, refuse input events (and have the refusal pinned on the right one),
 * be KDE (vertical scroll is inverted there), not be running, or lose the bus.
 *
 * The bus is private and has no service directories, so nothing installed on
 * the machine - the real portal included - can be activated onto it.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <dbus/dbus.h>

#include "src/agent/desktop/wayland.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "wayland_portal_bus_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#define PORTAL_BUS     "org.freedesktop.portal.Desktop"
#define PORTAL_PATH    "/org/freedesktop/portal/desktop"
#define PORTAL_SCREEN  "org.freedesktop.portal.ScreenCast"
#define PORTAL_REMOTE  "org.freedesktop.portal.RemoteDesktop"
#define PORTAL_REQUEST "org.freedesktop.portal.Request"
#define PORTAL_SESSION "org.freedesktop.portal.Session"
#define KDE_PORTAL     "org.freedesktop.impl.portal.desktop.kde"
#define KDE_KWIN       "org.kde.KWin"
#define RESTORE_TOKEN  "01234567-89ab-cdef-0123-456789abcdef"
#define NEW_TOKEN      "fedcba98-7654-3210-fedc-ba9876543210"

/* How a request is answered: a Response code, or one of these. */
#define ANSWER_NEVER     -1
#define ANSWER_MALFORMED -2

typedef struct {
    DBusConnection *pConn;
    pthread_t thread;
    volatile int bStop;
    int bRunning;
    pthread_mutex_t lock;

    /* How to behave. */
    int bRejectRestoredGrant;
    int bRejectMultiple;
    int bRejectDevices;       /* every SelectDevices ends with Response 2 */
    int bRejectSources;       /* every SelectSources ends with Response 2 */
    int bDevicesError;        /* SelectDevices is refused as a method call */
    int nStartResponse;       /* 0 grant, 1 decline, 2 fail, or ANSWER_* */
    int bStartOtherPath;
    int bNoSessionHandle;
    int bNoStreams;
    int bNoToken;
    int bNoDevices;
    int bPropsError;
    int nPipeWire;            /* 0 an fd, 1 an error, 2 a reply without one */
    int bRefuseKeysym;
    int bRefuseMotion;

    /* What was asked of it. */
    int nCreate, nSelectDevices, nSelectSources, nStart, nOpenPipeWire, nClose;
    int nDevicesWithToken, nDevicesPersist, nSourcesMultiple;
    int nMotions, nButtons, nAxis, nRelative, nKeysyms, nKeycodes;
    unsigned int nMotionStream;
    double fMotionX, fMotionY, fAxisDx, fAxisDy;
    int nButtonCode, nKeyCode;
    unsigned int nButtonState;
} portal_t;

static portal_t g_portal;

/* ---- building replies ------------------------------------------------------------- */

static void dict_string(DBusMessageIter *pDict, const char *pKey, const char *pValue)
{
    DBusMessageIter entry, variant;
    dbus_message_iter_open_container(pDict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &pKey);
    dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "s", &variant);
    dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &pValue);
    dbus_message_iter_close_container(&entry, &variant);
    dbus_message_iter_close_container(pDict, &entry);
}

static void dict_uint(DBusMessageIter *pDict, const char *pKey, dbus_uint32_t nValue)
{
    DBusMessageIter entry, variant;
    dbus_message_iter_open_container(pDict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &pKey);
    dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "u", &variant);
    dbus_message_iter_append_basic(&variant, DBUS_TYPE_UINT32, &nValue);
    dbus_message_iter_close_container(&entry, &variant);
    dbus_message_iter_close_container(pDict, &entry);
}

static void dict_pair(DBusMessageIter *pDict, const char *pKey, dbus_int32_t nA, dbus_int32_t nB)
{
    DBusMessageIter entry, variant, pair;
    dbus_message_iter_open_container(pDict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &pKey);
    dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "(ii)", &variant);
    dbus_message_iter_open_container(&variant, DBUS_TYPE_STRUCT, NULL, &pair);
    dbus_message_iter_append_basic(&pair, DBUS_TYPE_INT32, &nA);
    dbus_message_iter_append_basic(&pair, DBUS_TYPE_INT32, &nB);
    dbus_message_iter_close_container(&variant, &pair);
    dbus_message_iter_close_container(&entry, &variant);
    dbus_message_iter_close_container(pDict, &entry);
}

/* Two screens side by side: the streams entry of a granted Start. */
static void dict_streams(DBusMessageIter *pDict)
{
    const char *pKey = "streams";
    DBusMessageIter entry, variant, array;
    dbus_message_iter_open_container(pDict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &pKey);
    dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "a(ua{sv})", &variant);
    dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY, "(ua{sv})", &array);

    const dbus_uint32_t nodes[2] = { 42, 43 };
    const dbus_int32_t x[2] = { 0, 1920 };

    for (int i = 0; i < 2; i++)
    {
        DBusMessageIter stream, props;
        dbus_message_iter_open_container(&array, DBUS_TYPE_STRUCT, NULL, &stream);
        dbus_message_iter_append_basic(&stream, DBUS_TYPE_UINT32, &nodes[i]);
        dbus_message_iter_open_container(&stream, DBUS_TYPE_ARRAY, "{sv}", &props);
        dict_pair(&props, "size", 1920, 1080);
        dict_pair(&props, "position", x[i], 0);
        dbus_message_iter_close_container(&stream, &props);
        dbus_message_iter_close_container(&array, &stream);
    }

    dbus_message_iter_close_container(&variant, &array);
    dbus_message_iter_close_container(&entry, &variant);
    dbus_message_iter_close_container(pDict, &entry);
}

/* The sender's unique name with the leading ':' dropped and '.' made '_',
   which is how the portal names its request objects. */
static void mangle(const char *pSender, char *pOut, size_t nSize)
{
    size_t n = 0;
    for (const char *p = pSender + (pSender[0] == ':'); *p != '\0' && n + 1 < nSize; p++)
        pOut[n++] = *p == '.' ? '_' : *p;
    pOut[n] = '\0';
}

/* Finds pKey in an a{sv} and reports its value if it is a string or a boolean. */
static int options_find(DBusMessageIter *pOptions, const char *pKey, const char **ppString, dbus_bool_t *pBool)
{
    DBusMessageIter dict;
    dbus_message_iter_recurse(pOptions, &dict);

    while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY)
    {
        DBusMessageIter entry, variant;
        const char *pName = NULL;
        dbus_message_iter_recurse(&dict, &entry);
        dbus_message_iter_get_basic(&entry, &pName);
        dbus_message_iter_next(&entry);
        dbus_message_iter_recurse(&entry, &variant);

        if (pName != NULL && strcmp(pName, pKey) == 0)
        {
            int nType = dbus_message_iter_get_arg_type(&variant);
            if (nType == DBUS_TYPE_STRING && ppString != NULL) dbus_message_iter_get_basic(&variant, ppString);
            if (nType == DBUS_TYPE_BOOLEAN && pBool != NULL) dbus_message_iter_get_basic(&variant, pBool);
            return 1;
        }

        dbus_message_iter_next(&dict);
    }

    return 0;
}

static void send_reply(DBusMessage *pReply)
{
    dbus_connection_send(g_portal.pConn, pReply, NULL);
    dbus_message_unref(pReply);
}

/* Answers a portal request: the request path, then its Response signal,
   addressed to the caller alone the way xdg-desktop-portal addresses it. */
static void respond(DBusMessage *pCall, const char *pToken, int nResponse, int bOtherPath,
                    void (*fnResults)(DBusMessageIter*, DBusMessage*))
{
    char sSender[128], sPath[512];
    mangle(dbus_message_get_sender(pCall), sSender, sizeof(sSender));
    snprintf(sPath, sizeof(sPath), PORTAL_PATH "/request/%s/%s%s", sSender, pToken != NULL ? pToken : "none",
        bOtherPath ? "_moved" : "");

    DBusMessage *pReply = dbus_message_new_method_return(pCall);
    const char *pPathArg = sPath;
    dbus_message_append_args(pReply, DBUS_TYPE_OBJECT_PATH, &pPathArg, DBUS_TYPE_INVALID);
    send_reply(pReply);

    if (nResponse == ANSWER_NEVER) return;

    DBusMessage *pSignal = dbus_message_new_signal(sPath, PORTAL_REQUEST, "Response");
    dbus_message_set_destination(pSignal, dbus_message_get_sender(pCall));

    DBusMessageIter args, results;
    dbus_message_iter_init_append(pSignal, &args);

    if (nResponse == ANSWER_MALFORMED)
    {
        const char *pNonsense = "granted";
        dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &pNonsense);
    }
    else
    {
        dbus_uint32_t nCode = (dbus_uint32_t)nResponse;
        dbus_message_iter_append_basic(&args, DBUS_TYPE_UINT32, &nCode);
        dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{sv}", &results);
        if (fnResults != NULL && nResponse == 0) fnResults(&results, pCall);
        dbus_message_iter_close_container(&args, &results);
    }

    send_reply(pSignal);
}

static void results_session(DBusMessageIter *pResults, DBusMessage *pCall)
{
    char sSender[128], sSession[512];
    if (g_portal.bNoSessionHandle) return;

    mangle(dbus_message_get_sender(pCall), sSender, sizeof(sSender));
    snprintf(sSession, sizeof(sSession), PORTAL_PATH "/session/%s/test", sSender);
    dict_string(pResults, "session_handle", sSession);
}

static void results_start(DBusMessageIter *pResults, DBusMessage *pCall)
{
    (void)pCall;
    if (!g_portal.bNoStreams) dict_streams(pResults);
    if (!g_portal.bNoDevices) dict_uint(pResults, "devices", 3); /* keyboard and pointer */
    if (!g_portal.bNoToken) dict_string(pResults, "restore_token", NEW_TOKEN);
}

static DBusHandlerResult handle_properties(DBusMessage *pMsg)
{
    const char *pOn = NULL, *pProp = NULL;
    dbus_message_get_args(pMsg, NULL, DBUS_TYPE_STRING, &pOn, DBUS_TYPE_STRING, &pProp, DBUS_TYPE_INVALID);

    if (g_portal.bPropsError)
    {
        send_reply(dbus_message_new_error(pMsg, DBUS_ERROR_UNKNOWN_PROPERTY, "no such property"));
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    dbus_uint32_t nValue = 0;
    if (pProp != NULL && strcmp(pProp, "version") == 0) nValue = (pOn != NULL && strcmp(pOn, PORTAL_SCREEN) == 0) ? 5 : 2;
    else if (pProp != NULL && strcmp(pProp, "AvailableCursorModes") == 0) nValue = 7;
    else if (pProp != NULL && strcmp(pProp, "AvailableSourceTypes") == 0) nValue = 7;

    DBusMessage *pReply = dbus_message_new_method_return(pMsg);
    DBusMessageIter out, variant;
    dbus_message_iter_init_append(pReply, &out);
    dbus_message_iter_open_container(&out, DBUS_TYPE_VARIANT, "u", &variant);
    dbus_message_iter_append_basic(&variant, DBUS_TYPE_UINT32, &nValue);
    dbus_message_iter_close_container(&out, &variant);
    send_reply(pReply);
    return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult handle_pipewire(DBusMessage *pMsg)
{
    pthread_mutex_lock(&g_portal.lock);
    g_portal.nOpenPipeWire++;
    int nMode = g_portal.nPipeWire;
    pthread_mutex_unlock(&g_portal.lock);

    if (nMode == 1)
    {
        send_reply(dbus_message_new_error(pMsg, DBUS_ERROR_ACCESS_DENIED, "session not started"));
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    DBusMessage *pReply = dbus_message_new_method_return(pMsg);
    int pair[2];

    if (nMode == 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0)
    {
        dbus_message_append_args(pReply, DBUS_TYPE_UNIX_FD, &pair[0], DBUS_TYPE_INVALID);
        close(pair[0]);
        close(pair[1]);
    }

    send_reply(pReply);
    return DBUS_HANDLER_RESULT_HANDLED;
}

/* Fire-and-forget input: record the arguments, and refuse what it was told to. */
static DBusHandlerResult handle_input(DBusMessage *pMsg, const char *pMember, DBusMessageIter *pArgs)
{
    int bRefuse = 0;
    if (dbus_message_iter_get_arg_type(pArgs) == DBUS_TYPE_ARRAY) dbus_message_iter_next(pArgs);

    pthread_mutex_lock(&g_portal.lock);

    if (strcmp(pMember, "NotifyPointerMotionAbsolute") == 0)
    {
        g_portal.nMotions++;
        dbus_message_iter_get_basic(pArgs, &g_portal.nMotionStream);
        dbus_message_iter_next(pArgs);
        dbus_message_iter_get_basic(pArgs, &g_portal.fMotionX);
        dbus_message_iter_next(pArgs);
        dbus_message_iter_get_basic(pArgs, &g_portal.fMotionY);
        bRefuse = g_portal.bRefuseMotion;
    }
    else if (strcmp(pMember, "NotifyPointerButton") == 0)
    {
        g_portal.nButtons++;
        dbus_message_iter_get_basic(pArgs, &g_portal.nButtonCode);
        dbus_message_iter_next(pArgs);
        dbus_message_iter_get_basic(pArgs, &g_portal.nButtonState);
    }
    else if (strcmp(pMember, "NotifyPointerAxis") == 0 || strcmp(pMember, "NotifyPointerMotion") == 0)
    {
        if (strcmp(pMember, "NotifyPointerAxis") == 0) g_portal.nAxis++;
        else g_portal.nRelative++;
        dbus_message_iter_get_basic(pArgs, &g_portal.fAxisDx);
        dbus_message_iter_next(pArgs);
        dbus_message_iter_get_basic(pArgs, &g_portal.fAxisDy);
    }
    else if (strcmp(pMember, "NotifyKeyboardKeysym") == 0)
    {
        g_portal.nKeysyms++;
        dbus_message_iter_get_basic(pArgs, &g_portal.nKeyCode);
        bRefuse = g_portal.bRefuseKeysym;
    }
    else if (strcmp(pMember, "NotifyKeyboardKeycode") == 0)
    {
        g_portal.nKeycodes++;
        dbus_message_iter_get_basic(pArgs, &g_portal.nKeyCode);
    }

    pthread_mutex_unlock(&g_portal.lock);

    send_reply(bRefuse ? dbus_message_new_error(pMsg, DBUS_ERROR_FAILED, "not accepted by this portal") :
        dbus_message_new_method_return(pMsg));

    return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult handle_call(DBusConnection *pConn, DBusMessage *pMsg, void *pData)
{
    (void)pConn;
    (void)pData;
    if (dbus_message_get_type(pMsg) != DBUS_MESSAGE_TYPE_METHOD_CALL) return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    const char *pIface = dbus_message_get_interface(pMsg);
    const char *pMember = dbus_message_get_member(pMsg);
    if (pIface == NULL || pMember == NULL) return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    /* The capabilities the client reads before asking for anything. */
    if (strcmp(pIface, DBUS_INTERFACE_PROPERTIES) == 0 && strcmp(pMember, "Get") == 0) return handle_properties(pMsg);

    if (strcmp(pIface, PORTAL_SESSION) == 0 && strcmp(pMember, "Close") == 0)
    {
        pthread_mutex_lock(&g_portal.lock);
        g_portal.nClose++;
        pthread_mutex_unlock(&g_portal.lock);
        send_reply(dbus_message_new_method_return(pMsg));
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    if (strcmp(pIface, PORTAL_REMOTE) != 0 && strcmp(pIface, PORTAL_SCREEN) != 0)
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    if (strcmp(pMember, "OpenPipeWireRemote") == 0) return handle_pipewire(pMsg);

    /* Every method takes the session first, except CreateSession. */
    DBusMessageIter args;
    dbus_message_iter_init(pMsg, &args);
    if (strcmp(pMember, "CreateSession") != 0) dbus_message_iter_next(&args);
    if (strcmp(pMember, "Start") == 0) dbus_message_iter_next(&args); /* parent window */

    if (strncmp(pMember, "Notify", 6) == 0) return handle_input(pMsg, pMember, &args);

    const char *pToken = NULL, *pRestore = NULL;
    dbus_bool_t bMultiple = FALSE;
    int bPersist = 0;

    if (dbus_message_iter_get_arg_type(&args) == DBUS_TYPE_ARRAY)
    {
        options_find(&args, "handle_token", &pToken, NULL);
        options_find(&args, "restore_token", &pRestore, NULL);
        options_find(&args, "multiple", NULL, &bMultiple);
        bPersist = options_find(&args, "persist_mode", NULL, NULL);
    }

    pthread_mutex_lock(&g_portal.lock);
    int nResponse = 0, bOther = 0;
    void (*fnResults)(DBusMessageIter*, DBusMessage*) = NULL;

    if (strcmp(pMember, "CreateSession") == 0)
    {
        g_portal.nCreate++;
        fnResults = results_session;
    }
    else if (strcmp(pMember, "SelectDevices") == 0)
    {
        g_portal.nSelectDevices++;
        if (pRestore != NULL) g_portal.nDevicesWithToken++;
        if (bPersist) g_portal.nDevicesPersist++;
        if (g_portal.bRejectDevices || (g_portal.bRejectRestoredGrant && pRestore != NULL)) nResponse = 2;

        if (g_portal.bDevicesError)
        {
            pthread_mutex_unlock(&g_portal.lock);
            send_reply(dbus_message_new_error(pMsg, DBUS_ERROR_NOT_SUPPORTED, "remote desktop is not supported"));
            return DBUS_HANDLER_RESULT_HANDLED;
        }
    }
    else if (strcmp(pMember, "SelectSources") == 0)
    {
        g_portal.nSelectSources++;
        if (bMultiple) g_portal.nSourcesMultiple++;
        if (g_portal.bRejectSources || (g_portal.bRejectMultiple && bMultiple)) nResponse = 2;
    }
    else if (strcmp(pMember, "Start") == 0)
    {
        g_portal.nStart++;
        nResponse = g_portal.nStartResponse;
        bOther = g_portal.bStartOtherPath;
        fnResults = results_start;
    }
    else
    {
        pthread_mutex_unlock(&g_portal.lock);
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    pthread_mutex_unlock(&g_portal.lock);
    respond(pMsg, pToken, nResponse, bOther, fnResults);
    return DBUS_HANDLER_RESULT_HANDLED;
}

static void* portal_thread(void *pArg)
{
    (void)pArg;
    while (!g_portal.bStop && dbus_connection_read_write_dispatch(g_portal.pConn, 20)) { }
    return NULL;
}

static int portal_start(void)
{
    DBusError error;
    dbus_error_init(&error);

    g_portal.pConn = dbus_bus_get_private(DBUS_BUS_SESSION, &error);
    if (g_portal.pConn == NULL)
    {
        dbus_error_free(&error);
        return 0;
    }

    dbus_connection_set_exit_on_disconnect(g_portal.pConn, FALSE);
    if (dbus_bus_request_name(g_portal.pConn, PORTAL_BUS, DBUS_NAME_FLAG_DO_NOT_QUEUE, &error) !=
        DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER)
    {
        dbus_error_free(&error);
        return 0;
    }

    dbus_connection_add_filter(g_portal.pConn, handle_call, NULL, NULL);
    g_portal.bStop = 0;
    g_portal.bRunning = pthread_create(&g_portal.thread, NULL, portal_thread, NULL) == 0;
    return g_portal.bRunning;
}

static void portal_stop(void)
{
    if (g_portal.bRunning)
    {
        g_portal.bStop = 1;
        pthread_join(g_portal.thread, NULL);
        g_portal.bRunning = 0;
    }

    if (g_portal.pConn != NULL)
    {
        dbus_connection_close(g_portal.pConn);
        dbus_connection_unref(g_portal.pConn);
        g_portal.pConn = NULL;
    }
}

static void portal_reset(void)
{
    pthread_mutex_lock(&g_portal.lock);
    g_portal.bRejectRestoredGrant = g_portal.bRejectMultiple = g_portal.bRejectDevices = g_portal.bRejectSources = 0;
    g_portal.bDevicesError = g_portal.bStartOtherPath = g_portal.bNoSessionHandle = g_portal.bNoStreams = 0;
    g_portal.bNoToken = g_portal.bNoDevices = g_portal.bPropsError = g_portal.nPipeWire = 0;
    g_portal.bRefuseKeysym = g_portal.bRefuseMotion = g_portal.nStartResponse = 0;
    g_portal.nCreate = g_portal.nSelectDevices = g_portal.nSelectSources = g_portal.nStart = 0;
    g_portal.nOpenPipeWire = g_portal.nClose = g_portal.nDevicesWithToken = g_portal.nDevicesPersist = 0;
    g_portal.nSourcesMultiple = g_portal.nMotions = g_portal.nButtons = g_portal.nAxis = g_portal.nRelative = 0;
    g_portal.nKeysyms = g_portal.nKeycodes = 0;
    pthread_mutex_unlock(&g_portal.lock);
}

static int portal_count(const int *pCounter)
{
    pthread_mutex_lock(&g_portal.lock);
    int n = *pCounter;
    pthread_mutex_unlock(&g_portal.lock);
    return n;
}

static int wait_count(const int *pCounter, int nWant)
{
    for (int i = 0; i < 300 && portal_count(pCounter) < nWant; i++) usleep(10000);
    return portal_count(pCounter) >= nWant;
}

/* Other desktop services' names, held on a connection of their own: a
   blocking call on the portal's connection would race its dispatch thread
   for the reply. Nothing is ever asked of these names, only whether they
   are owned. */
static DBusConnection *g_pNames;

static int own_name(const char *pName)
{
    DBusError error;
    dbus_error_init(&error);

    if (g_pNames == NULL)
    {
        g_pNames = dbus_bus_get_private(DBUS_BUS_SESSION, &error);
        if (g_pNames == NULL)
        {
            dbus_error_free(&error);
            return 0;
        }

        dbus_connection_set_exit_on_disconnect(g_pNames, FALSE);
    }

    int nResult = dbus_bus_request_name(g_pNames, pName, DBUS_NAME_FLAG_DO_NOT_QUEUE, &error);
    dbus_error_free(&error);
    return nResult == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER;
}

static void release_names(void)
{
    if (g_pNames == NULL) return;
    dbus_connection_close(g_pNames);
    dbus_connection_unref(g_pNames);
    g_pNames = NULL;
}

/* ---- the bus -------------------------------------------------------------------- */

static pid_t g_nDaemon;
static char g_sBusDir[256];
static char g_sConfig[300];

/* A session bus that owns nothing and can activate nothing. */
static int bus_config(void)
{
    const char *pTmp = getenv("TMPDIR");
    snprintf(g_sBusDir, sizeof(g_sBusDir), "%s/dg-portal-bus-XXXXXX", (pTmp != NULL && pTmp[0]) ? pTmp : "/tmp");
    if (mkdtemp(g_sBusDir) == NULL) return 0;

    snprintf(g_sConfig, sizeof(g_sConfig), "%s/bus.conf", g_sBusDir);
    FILE *pFile = fopen(g_sConfig, "w");
    if (pFile == NULL) return 0;

    fprintf(pFile,
        "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\"\n"
        " \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n"
        "<busconfig>\n"
        "  <type>session</type>\n"
        "  <listen>unix:dir=%s</listen>\n"
        "  <auth>EXTERNAL</auth>\n"
        "  <policy context=\"default\">\n"
        "    <allow send_destination=\"*\" eavesdrop=\"true\"/>\n"
        "    <allow eavesdrop=\"true\"/>\n"
        "    <allow own=\"*\"/>\n"
        "  </policy>\n"
        "</busconfig>\n", g_sBusDir);

    return fclose(pFile) == 0;
}

static int bus_start(void)
{
    int pipefd[2];
    if (!bus_config() || pipe(pipefd) != 0) return 0;

    g_nDaemon = fork();
    if (g_nDaemon == 0)
    {
        /* The daemon goes with the test, however the test ends, and keeps
           nothing of the test's output open after it. */
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        int nNull = open("/dev/null", O_RDWR);
        if (nNull >= 0)
        {
            dup2(nNull, STDOUT_FILENO);
            dup2(nNull, STDERR_FILENO);
        }

        close(pipefd[0]);
        char sConfig[320], sFd[32];
        snprintf(sConfig, sizeof(sConfig), "--config-file=%s", g_sConfig);
        snprintf(sFd, sizeof(sFd), "--print-address=%d", pipefd[1]);
        execlp("dbus-daemon", "dbus-daemon", sConfig, "--nofork", "--nopidfile", sFd, (char*)NULL);
        _exit(127);
    }

    close(pipefd[1]);
    char sAddress[512] = { 0 };
    ssize_t nRead = read(pipefd[0], sAddress, sizeof(sAddress) - 1);
    close(pipefd[0]);

    if (nRead <= 0) return 0;
    char *pNewline = strchr(sAddress, '\n');
    if (pNewline != NULL) *pNewline = '\0';

    setenv("DBUS_SESSION_BUS_ADDRESS", sAddress, 1);
    return 1;
}

static void bus_stop(void)
{
    if (g_nDaemon > 0)
    {
        kill(g_nDaemon, SIGTERM);
        waitpid(g_nDaemon, NULL, 0);
        g_nDaemon = 0;
    }

    if (g_sConfig[0]) unlink(g_sConfig);
    if (g_sBusDir[0]) rmdir(g_sBusDir);
}

/* ---- scenarios ------------------------------------------------------------------ */

static xvolatile_t g_nCancel;

static void* cancel_later(void *pArg)
{
    (void)pArg;
    wait_count(&g_portal.nStart, 1);
    usleep(100000);
    XSYNC_ATOMIC_SET(&g_nCancel, 1);
    return NULL;
}

/* Once the prompt is up, and not before: the loss has to land in the wait. */
static void* kill_bus_later(void *pArg)
{
    (void)pArg;
    wait_count(&g_portal.nStart, 1);
    usleep(100000);
    kill(g_nDaemon, SIGTERM);
    return NULL;
}

static int scenario_granted(void)
{
    char sErr[512], sToken[64];
    xbool_t bDeclined = XTRUE;
    portal_reset();

    directgate_wl_portal_t *pPortal = DirectGate_WL_PortalOpen(NULL, sToken, sizeof(sToken), &bDeclined, NULL,
        sErr, sizeof(sErr));
    if (pPortal == NULL) fprintf(stderr, "wayland_portal_bus_smoke: open failed: %s\n", sErr);
    CHECK(pPortal != NULL, "a portal that grants the request opens a session");
    CHECK(!bDeclined, "a granted session is not reported as declined");

    CHECK(portal_count(&g_portal.nCreate) == 1 && portal_count(&g_portal.nSelectDevices) == 1 &&
        portal_count(&g_portal.nSelectSources) == 1 && portal_count(&g_portal.nStart) == 1,
        "one session asks exactly once for devices, sources and the grant");
    CHECK(portal_count(&g_portal.nDevicesWithToken) == 0, "without a remembered grant none is presented");
    CHECK(portal_count(&g_portal.nDevicesPersist) == 1, "a portal that can remember a grant is asked to");
    CHECK(portal_count(&g_portal.nSourcesMultiple) == 1, "the client offers to share every screen");

    CHECK(DirectGate_WL_PortalStreamCount(pPortal) == 2, "both granted screens are known");
    const directgate_wl_stream_t *pSecond = DirectGate_WL_PortalStream(pPortal, 1);
    CHECK(pSecond != NULL && pSecond->nNodeId == 43 && pSecond->nWidth == 1920 && pSecond->nHeight == 1080 &&
        pSecond->nX == 1920 && pSecond->nY == 0, "each screen's node, size and position are read");
    CHECK(DirectGate_WL_PortalStream(pPortal, 2) == NULL, "there is no third screen");
    CHECK(DirectGate_WL_PortalNodeId(pPortal) == 42, "the first screen's node is the default one");
    CHECK(DirectGate_WL_PortalHasInput(pPortal), "keyboard and pointer were granted");
    CHECK(strcmp(sToken, NEW_TOKEN) == 0, "the new restore token is handed back to be remembered");

    int nFd = DirectGate_WL_PortalOpenPipeWire(pPortal, sErr, sizeof(sErr));
    CHECK(nFd >= 0, "the PipeWire remote is opened through the portal");
    close(nFd);

    /* Input goes out with the session handle and the values it was given. */
    CHECK(DirectGate_WL_PortalPointerMotion(pPortal, 0, 100.5, 200.25) == XSTDOK, "send an absolute motion");
    CHECK(wait_count(&g_portal.nMotions, 1), "the motion reaches the portal");
    CHECK(g_portal.nMotionStream == 42 && g_portal.fMotionX == 100.5 && g_portal.fMotionY == 200.25,
        "an absolute motion without a stream lands on the default screen at the exact position");

    CHECK(DirectGate_WL_PortalPointerMotion(pPortal, 43, 1.0, 2.0) == XSTDOK, "send a motion to the second screen");
    CHECK(wait_count(&g_portal.nMotions, 2), "the second motion reaches the portal");
    CHECK(g_portal.nMotionStream == 43, "a motion addressed to a screen lands on that screen");

    CHECK(DirectGate_WL_PortalPointerButton(pPortal, DirectGate_WL_PortalButtonCode(3), XTRUE) == XSTDOK, "press");
    CHECK(wait_count(&g_portal.nButtons, 1), "the button reaches the portal");
    CHECK(g_portal.nButtonCode == 0x111 && g_portal.nButtonState == 1, "the right button goes out as BTN_RIGHT, pressed");

    CHECK(DirectGate_WL_PortalPointerButton(pPortal, DirectGate_WL_PortalButtonCode(1), XFALSE) == XSTDOK, "release");
    CHECK(wait_count(&g_portal.nButtons, 2), "the release reaches the portal");
    CHECK(g_portal.nButtonCode == 0x110 && g_portal.nButtonState == 0, "the left button goes out as BTN_LEFT, released");

    CHECK(DirectGate_WL_PortalPointerAxis(pPortal, 1.0, 3.0) == XSTDOK, "scroll");
    CHECK(wait_count(&g_portal.nAxis, 1), "the scroll reaches the portal");
    CHECK(g_portal.fAxisDx == 1.0 && g_portal.fAxisDy == 3.0, "outside KDE the scroll direction is passed through");

    CHECK(DirectGate_WL_PortalPointerMotionRelative(pPortal, -4.0, 2.0) == XSTDOK, "relative motion");
    CHECK(wait_count(&g_portal.nRelative, 1), "the relative motion reaches the portal");
    CHECK(g_portal.fAxisDx == -4.0 && g_portal.fAxisDy == 2.0, "a relative motion carries its deltas");

    CHECK(DirectGate_WL_PortalKeycode(pPortal, 30, XTRUE) == XSTDOK, "send a keycode");
    CHECK(wait_count(&g_portal.nKeycodes, 1), "the keycode reaches the portal");
    CHECK(g_portal.nKeyCode == 30, "a keycode goes out as given");
    CHECK(DirectGate_WL_PortalKeysym(pPortal, 0x61, XTRUE) == XSTDOK, "send a keysym");
    CHECK(wait_count(&g_portal.nKeysyms, 1), "the keysym reaches the portal");
    CHECK(g_portal.nKeyCode == 0x61, "a keysym goes out as given");

    /* One more event to collect any refusal of the ones before it: there was none. */
    usleep(50000);
    CHECK(DirectGate_WL_PortalKeycode(pPortal, 30, XFALSE) == XSTDOK, "release the keycode");
    CHECK(!DirectGate_WL_PortalKeysymRefused(pPortal), "an accepted keysym is not reported as refused");

    DirectGate_WL_PortalClose(pPortal);
    CHECK(wait_count(&g_portal.nClose, 1), "closing ends the portal session");
    return 0;
}

static int scenario_step_down(void)
{
    char sErr[512], sToken[64];
    portal_reset();
    g_portal.bRejectRestoredGrant = 1;
    g_portal.bRejectMultiple = 1;
    g_portal.bStartOtherPath = 1;

    /* A remembered grant the portal no longer takes, a portal that shares one
       screen at a time, and a grant answered from a path nobody predicted. */
    directgate_wl_portal_t *pPortal = DirectGate_WL_PortalOpen(RESTORE_TOKEN, sToken, sizeof(sToken), NULL, NULL,
        sErr, sizeof(sErr));
    if (pPortal == NULL) fprintf(stderr, "wayland_portal_bus_smoke: step-down failed: %s\n", sErr);
    CHECK(pPortal != NULL, "the client steps down to options the portal accepts");
    CHECK(portal_count(&g_portal.nDevicesWithToken) == 1 && portal_count(&g_portal.nSelectDevices) == 2,
        "a refused remembered grant is retried once without it");
    CHECK(portal_count(&g_portal.nDevicesPersist) == 2, "stepping down keeps asking for the grant to be remembered");
    CHECK(portal_count(&g_portal.nSelectSources) == 2 && portal_count(&g_portal.nSourcesMultiple) == 1,
        "a refused multi-screen request is retried for a single screen");
    CHECK(strcmp(sToken, NEW_TOKEN) == 0, "the new grant can still be remembered after stepping down");
    DirectGate_WL_PortalClose(pPortal);

    /* A token that is not a UUID is never presented: it would fail the request. */
    portal_reset();
    pPortal = DirectGate_WL_PortalOpen("truncated-token", sToken, sizeof(sToken), NULL, NULL, sErr, sizeof(sErr));
    CHECK(pPortal != NULL, "a malformed remembered token does not stop a session");
    CHECK(portal_count(&g_portal.nDevicesWithToken) == 0 && portal_count(&g_portal.nSelectDevices) == 1,
        "a malformed remembered token is not presented at all");
    DirectGate_WL_PortalClose(pPortal);

    /* An accepted token is presented once, and that is all it costs. */
    portal_reset();
    pPortal = DirectGate_WL_PortalOpen(RESTORE_TOKEN, sToken, sizeof(sToken), NULL, NULL, sErr, sizeof(sErr));
    CHECK(pPortal != NULL, "a remembered grant the portal accepts opens a session");
    CHECK(portal_count(&g_portal.nDevicesWithToken) == 1 && portal_count(&g_portal.nSelectDevices) == 1,
        "an accepted remembered grant is presented exactly once");
    DirectGate_WL_PortalClose(pPortal);
    return 0;
}

/* A refusal comes back on the bus after later input went out. It has to be
   pinned on the call it answers, not on whichever call happens to collect it. */
static int scenario_refusal_attribution(void)
{
    char sErr[512];
    portal_reset();

    directgate_wl_portal_t *pPortal = DirectGate_WL_PortalOpen(NULL, NULL, 0, NULL, NULL, sErr, sizeof(sErr));
    CHECK(pPortal != NULL, "open a session to refuse input on");

    /* A pointer position the compositor would not map, collected by a keysym. */
    g_portal.bRefuseMotion = 1;
    CHECK(DirectGate_WL_PortalPointerMotion(pPortal, 0, 99999.0, 99999.0) == XSTDOK, "send a motion to be refused");
    CHECK(wait_count(&g_portal.nMotions, 1), "the refused motion reached the portal");
    usleep(100000);
    CHECK(DirectGate_WL_PortalKeysym(pPortal, 0x61, XTRUE) == XSTDOK, "send a keysym that collects the refusal");
    CHECK(wait_count(&g_portal.nKeysyms, 1), "the keysym reached the portal");
    usleep(100000);
    CHECK(DirectGate_WL_PortalKeycode(pPortal, 30, XTRUE) == XSTDOK, "send a keycode that collects the rest");
    CHECK(!DirectGate_WL_PortalKeysymRefused(pPortal),
        "a refused pointer motion is not mistaken for a portal that refuses keysyms");

    /* A refused keysym, collected by a keycode. */
    g_portal.bRefuseMotion = 0;
    g_portal.bRefuseKeysym = 1;
    CHECK(DirectGate_WL_PortalKeysym(pPortal, 0x3b1, XTRUE) == XSTDOK, "send a keysym to be refused");
    CHECK(wait_count(&g_portal.nKeysyms, 2), "the refused keysym reached the portal");
    usleep(100000);
    CHECK(DirectGate_WL_PortalKeycode(pPortal, 30, XFALSE) == XSTDOK, "send a keycode that collects the refusal");
    CHECK(DirectGate_WL_PortalKeysymRefused(pPortal), "a refused keysym is noticed whichever call collects it");

    /* Enough refusals to reach the log's limit: they keep being collected, quietly. */
    for (int i = 0; i < 12; i++) DirectGate_WL_PortalKeysym(pPortal, 0x3b1, (i & 1) ? XFALSE : XTRUE);
    CHECK(wait_count(&g_portal.nKeysyms, 14), "every refused keysym reached the portal");
    usleep(100000);
    CHECK(DirectGate_WL_PortalKeycode(pPortal, 30, XFALSE) == XSTDOK, "input still goes out after many refusals");

    DirectGate_WL_PortalClose(pPortal);
    return 0;
}

static int scenario_refusals(void)
{
    char sErr[512];
    xbool_t bDeclined = XFALSE;

    /* Declined by the person at the computer. */
    portal_reset();
    g_portal.nStartResponse = 1;
    CHECK(DirectGate_WL_PortalOpen(NULL, NULL, 0, &bDeclined, NULL, sErr, sizeof(sErr)) == NULL,
        "a declined request opens nothing");
    CHECK(bDeclined, "a decline is reported as a decline, so it is not asked again at once");
    CHECK(strstr(sErr, "declined") != NULL, "the decline is explained");

    /* Ended by the portal itself: a failure, not a refusal. */
    portal_reset();
    g_portal.nStartResponse = 2;
    bDeclined = XFALSE;
    CHECK(DirectGate_WL_PortalOpen(NULL, NULL, 0, &bDeclined, NULL, sErr, sizeof(sErr)) == NULL,
        "a request the portal ends opens nothing");
    CHECK(!bDeclined, "a portal failure is not mistaken for a decline");
    CHECK(strstr(sErr, "ended") != NULL, "the portal's own failure is explained");

    /* A declined request with nobody interested in the difference. */
    portal_reset();
    g_portal.nStartResponse = 1;
    CHECK(DirectGate_WL_PortalOpen(NULL, NULL, 0, NULL, NULL, NULL, 0) == NULL,
        "a decline without a flag or an error buffer still opens nothing");

    /* An answer that is not a portal answer. */
    portal_reset();
    g_portal.nStartResponse = ANSWER_MALFORMED;
    CHECK(DirectGate_WL_PortalOpen(NULL, NULL, 0, NULL, NULL, sErr, sizeof(sErr)) == NULL,
        "a malformed answer opens nothing");
    CHECK(strstr(sErr, "malformed") != NULL, "the malformed answer is explained");

    /* A session that never came into being. */
    portal_reset();
    g_portal.bNoSessionHandle = 1;
    CHECK(DirectGate_WL_PortalOpen(NULL, NULL, 0, NULL, NULL, sErr, sizeof(sErr)) == NULL,
        "a portal that returns no session opens nothing");
    CHECK(strstr(sErr, "did not return a session") != NULL, "the missing session is explained");
    CHECK(portal_count(&g_portal.nSelectDevices) == 0, "nothing is selected on a session that does not exist");

    /* A grant with nothing in it. */
    portal_reset();
    g_portal.bNoStreams = 1;
    CHECK(DirectGate_WL_PortalOpen(NULL, NULL, 0, NULL, NULL, sErr, sizeof(sErr)) == NULL,
        "a grant without a stream opens nothing");
    CHECK(strstr(sErr, "no stream") != NULL, "the empty grant is explained");
    CHECK(wait_count(&g_portal.nClose, 1), "a session that failed after it was created is closed on the portal");

    /* No input at all, even after stepping down. */
    portal_reset();
    g_portal.bRejectDevices = 1;
    CHECK(DirectGate_WL_PortalOpen(RESTORE_TOKEN, NULL, 0, NULL, NULL, sErr, sizeof(sErr)) == NULL,
        "a portal that refuses every input option opens nothing");
    CHECK(portal_count(&g_portal.nSelectDevices) == 2 && portal_count(&g_portal.nSelectSources) == 0,
        "input is tried with and without the grant, and capture is not asked for after both fail");

    portal_reset();
    g_portal.bDevicesError = 1;
    CHECK(DirectGate_WL_PortalOpen(NULL, NULL, 0, NULL, NULL, sErr, sizeof(sErr)) == NULL,
        "a compositor without remote desktop support opens nothing");
    CHECK(strstr(sErr, "SelectDevices") != NULL && strstr(sErr, "not supported") != NULL,
        "the refused method and the portal's reason are both reported");

    /* No capture at all, even for one screen. */
    portal_reset();
    g_portal.bRejectSources = 1;
    CHECK(DirectGate_WL_PortalOpen(NULL, NULL, 0, NULL, NULL, sErr, sizeof(sErr)) == NULL,
        "a portal that refuses every capture option opens nothing");
    CHECK(portal_count(&g_portal.nSelectSources) == 2 && portal_count(&g_portal.nStart) == 0,
        "capture is tried with and without several screens, and nothing is started after both fail");

    /* Nobody answers, and the session that asked is abandoned. */
    portal_reset();
    g_portal.nStartResponse = ANSWER_NEVER;
    XSYNC_ATOMIC_SET(&g_nCancel, 0);
    pthread_t canceller;
    CHECK(pthread_create(&canceller, NULL, cancel_later, NULL) == 0, "start the canceller");
    uint64_t nStart = XTime_GetMonoMs();
    CHECK(DirectGate_WL_PortalOpen(NULL, NULL, 0, NULL, &g_nCancel, sErr, sizeof(sErr)) == NULL,
        "an abandoned request opens nothing");
    pthread_join(canceller, NULL);
    CHECK(XTime_GetMonoMs() - nStart < 5000, "an abandoned request stops waiting promptly");
    CHECK(strstr(sErr, "abandoned") != NULL, "the abandonment is explained");
    return 0;
}

static int scenario_old_portal(void)
{
    char sErr[512], sToken[64];

    /* A portal that answers no property: every capability falls back to the
       oldest version, which cannot remember a grant, so none is presented or
       asked for, and a session still opens. */
    portal_reset();
    g_portal.bPropsError = 1;
    g_portal.bNoToken = 1;
    g_portal.bNoDevices = 1;
    strcpy(sToken, "stale");

    directgate_wl_portal_t *pPortal = DirectGate_WL_PortalOpen(RESTORE_TOKEN, sToken, sizeof(sToken), NULL, NULL,
        sErr, sizeof(sErr));
    CHECK(pPortal != NULL, "a portal that answers no property still opens a session");
    CHECK(portal_count(&g_portal.nDevicesPersist) == 0 && portal_count(&g_portal.nDevicesWithToken) == 0,
        "an old portal is neither asked to remember nor handed a remembered grant");
    CHECK(sToken[0] == '\0', "without a new token the old one is not handed back");
    CHECK(!DirectGate_WL_PortalHasInput(pPortal), "a grant without devices has no input");

    /* The PipeWire remote refused, and answered without a descriptor. */
    g_portal.nPipeWire = 1;
    CHECK(DirectGate_WL_PortalOpenPipeWire(pPortal, sErr, sizeof(sErr)) < 0, "a refused PipeWire remote is no descriptor");
    CHECK(strstr(sErr, "would not open") != NULL && strstr(sErr, "session not started") != NULL,
        "the refusal and the portal's reason are reported");
    g_portal.nPipeWire = 2;
    CHECK(DirectGate_WL_PortalOpenPipeWire(pPortal, sErr, sizeof(sErr)) < 0, "an empty PipeWire answer is no descriptor");
    CHECK(strstr(sErr, "no video stream descriptor") != NULL, "the empty answer is explained");

    DirectGate_WL_PortalClose(pPortal);
    return 0;
}

static int scenario_kde(void)
{
    char sErr[512];

    /* KDE's file-picker portal can run under GNOME: that alone is not KDE. */
    portal_reset();
    CHECK(own_name(KDE_PORTAL), "impersonate the KDE portal backend");
    directgate_wl_portal_t *pPortal = DirectGate_WL_PortalOpen(NULL, NULL, 0, NULL, NULL, sErr, sizeof(sErr));
    CHECK(pPortal != NULL, "a session opens beside a KDE portal backend");
    CHECK(DirectGate_WL_PortalPointerAxis(pPortal, 1.0, 3.0) == XSTDOK, "scroll beside a KDE backend");
    CHECK(wait_count(&g_portal.nAxis, 1), "that scroll reaches the portal");
    CHECK(g_portal.fAxisDy == 3.0, "a KDE backend without KWin is not treated as KDE");
    DirectGate_WL_PortalClose(pPortal);

    /* KDE proper inverts the vertical axis, and the client compensates. */
    portal_reset();
    CHECK(own_name(KDE_KWIN), "impersonate KWin");
    pPortal = DirectGate_WL_PortalOpen(NULL, NULL, 0, NULL, NULL, sErr, sizeof(sErr));
    CHECK(pPortal != NULL, "a KDE session opens");
    CHECK(DirectGate_WL_PortalPointerAxis(pPortal, 1.0, 3.0) == XSTDOK, "scroll under KDE");
    CHECK(wait_count(&g_portal.nAxis, 1), "the KDE scroll reaches the portal");
    CHECK(g_portal.fAxisDx == 1.0 && g_portal.fAxisDy == -3.0, "under KDE only the vertical axis is inverted");
    CHECK(DirectGate_WL_PortalPointerMotionRelative(pPortal, 0.0, 3.0) == XSTDOK, "relative motion under KDE");
    CHECK(wait_count(&g_portal.nRelative, 1), "the KDE relative motion reaches the portal");
    CHECK(g_portal.fAxisDy == 3.0, "relative motion is not inverted, only the scroll axis");
    DirectGate_WL_PortalClose(pPortal);

    release_names();
    return 0;
}

static int scenario_no_portal(void)
{
    char sErr[512];

    /* No portal on the bus, and nothing that could be activated onto it. */
    portal_stop();
    CHECK(DirectGate_WL_PortalOpen(NULL, NULL, 0, NULL, NULL, sErr, sizeof(sErr)) == NULL,
        "without a portal nothing opens");
    CHECK(strstr(sErr, "refused CreateSession") != NULL, "the missing portal is explained");
    return 0;
}

static int scenario_bus_lost(void)
{
    char sErr[512];

    /* The bus goes away while the prompt is on screen. */
    CHECK(portal_start(), "bring the portal back");
    portal_reset();
    g_portal.nStartResponse = ANSWER_NEVER;

    pthread_t killer;
    CHECK(pthread_create(&killer, NULL, kill_bus_later, NULL) == 0, "start the bus killer");
    uint64_t nStart = XTime_GetMonoMs();
    directgate_wl_portal_t *pPortal = DirectGate_WL_PortalOpen(NULL, NULL, 0, NULL, NULL, sErr, sizeof(sErr));
    pthread_join(killer, NULL);
    CHECK(pPortal == NULL, "a session whose bus went away does not open");
    if (strstr(sErr, "lost") == NULL) fprintf(stderr, "wayland_portal_bus_smoke: lost bus reported as: %s\n", sErr);
    CHECK(XTime_GetMonoMs() - nStart < 5000, "a lost bus is noticed without waiting out the prompt");
    CHECK(strstr(sErr, "lost") != NULL, "the lost bus is explained");

    /* With no bus at all the process carries on, and says why nothing opens. */
    waitpid(g_nDaemon, NULL, 0);
    g_nDaemon = 0;
    CHECK(DirectGate_WL_PortalOpen(NULL, NULL, 0, NULL, NULL, sErr, sizeof(sErr)) == NULL,
        "without a session bus nothing opens");
    CHECK(strstr(sErr, "No session D-Bus") != NULL, "the missing bus is explained");
    return 0;
}

static int scenario_no_session(void)
{
    char sErr[64] = "untouched";

    /* Every accessor takes a portal that never opened. */
    CHECK(DirectGate_WL_PortalStreamCount(NULL) == 0, "no portal has no screens");
    CHECK(DirectGate_WL_PortalStream(NULL, 0) == NULL, "no portal has no first screen");
    CHECK(DirectGate_WL_PortalNodeId(NULL) == 0, "no portal has no node");
    CHECK(!DirectGate_WL_PortalHasInput(NULL), "no portal has no input");
    CHECK(!DirectGate_WL_PortalKeysymRefused(NULL), "no portal refused anything");
    CHECK(DirectGate_WL_PortalOpenPipeWire(NULL, sErr, sizeof(sErr)) < 0, "no portal opens no PipeWire remote");
    CHECK(DirectGate_WL_PortalPointerMotion(NULL, 0, 1.0, 1.0) == XSTDERR, "no portal takes no absolute motion");
    CHECK(DirectGate_WL_PortalPointerMotionRelative(NULL, 1.0, 1.0) == XSTDERR, "no portal takes no relative motion");
    CHECK(DirectGate_WL_PortalPointerButton(NULL, 0x110, XTRUE) == XSTDERR, "no portal takes no button");
    CHECK(DirectGate_WL_PortalPointerAxis(NULL, 1.0, 1.0) == XSTDERR, "no portal takes no scroll");
    CHECK(DirectGate_WL_PortalKeysym(NULL, 0x61, XTRUE) == XSTDERR, "no portal takes no keysym");
    CHECK(DirectGate_WL_PortalKeycode(NULL, 30, XTRUE) == XSTDERR, "no portal takes no keycode");
    DirectGate_WL_PortalClose(NULL);

    /* Browser buttons map to evdev codes; wheel buttons are axis motion, not buttons. */
    CHECK(DirectGate_WL_PortalButtonCode(2) == 0x112 && DirectGate_WL_PortalButtonCode(8) == 0x113 &&
        DirectGate_WL_PortalButtonCode(9) == 0x114, "middle, back and forward map to their evdev codes");
    CHECK(DirectGate_WL_PortalButtonCode(4) == 0 && DirectGate_WL_PortalButtonCode(0) == 0,
        "wheel and unknown buttons have no evdev code");
    return 0;
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    memset(&g_portal, 0, sizeof(g_portal));
    pthread_mutex_init(&g_portal.lock, NULL);

    char sErr[256];
    if (DirectGate_WL_DBusLoad(sErr, sizeof(sErr)) != XSTDOK)
    {
        printf("wayland_portal_bus_smoke: libdbus is not loadable (%s), skipping\n", sErr);
        return 77;
    }

    CHECK(DirectGate_WL_DBusLoad(NULL, 0) == XSTDOK, "loading libdbus twice is harmless");

    if (!bus_start())
    {
        bus_stop();
        printf("wayland_portal_bus_smoke: no dbus-daemon, skipping\n");
        return 77;
    }

    int nResult = 1;
    if (portal_start())
    {
        nResult = scenario_no_session();
        if (!nResult) nResult = scenario_granted();
        if (!nResult) nResult = scenario_step_down();
        if (!nResult) nResult = scenario_refusal_attribution();
        if (!nResult) nResult = scenario_refusals();
        if (!nResult) nResult = scenario_old_portal();
        if (!nResult) nResult = scenario_kde();
        if (!nResult) nResult = scenario_no_portal();
        if (!nResult) nResult = scenario_bus_lost();
    }
    else
    {
        fprintf(stderr, "wayland_portal_bus_smoke: could not claim the portal name on the private bus\n");
    }

    portal_stop();
    bus_stop();
    pthread_mutex_destroy(&g_portal.lock);

    if (nResult) return 1;
    puts("wayland_portal_bus_smoke: OK");
    return 0;
}
