/* Test real D-Bus serialization and compositor-specific scroll direction.
 * Bus ownership and message delivery are stubbed; no running desktop or
 * session bus is needed. */
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "src/agent/desktop/wayland_portal.c"

#define CHECK(c, msg) do { if (!(c)) { \
    fprintf(stderr, "wayland_portal_smoke: %s\n", msg); return 1; } } while (0)

static dbus_bool_t g_bKdePortal, g_bKwin;
static xbool_t g_bProbeError;
static unsigned int g_nProbes, g_nSent;
static DBusMessage *g_pSent;

static DBusMessage* Probe(DBusConnection *pConn, DBusMessage *pCall, int nTimeout, DBusError *pError)
{
    (void)pConn;
    g_nProbes++;
    if (!dbus_message_is_method_call(pCall, DBUS_INTERFACE_DBUS, "NameHasOwner") ||
        strcmp(dbus_message_get_destination(pCall), DBUS_SERVICE_DBUS) != 0 || nTimeout != 1000)
        return NULL;

    if (g_bProbeError)
    {
        dbus_set_error_const(pError, DBUS_ERROR_NO_REPLY, "test bus unavailable");
        return NULL;
    }

    const char *pName = NULL;
    if (!dbus_message_get_args(pCall, NULL, DBUS_TYPE_STRING, &pName, DBUS_TYPE_INVALID)) return NULL;
    dbus_bool_t bOwned = FALSE;
    if (strcmp(pName, "org.freedesktop.impl.portal.desktop.kde") == 0) bOwned = g_bKdePortal;
    else if (strcmp(pName, "org.kde.KWin") == 0) bOwned = g_bKwin;

    dbus_message_set_serial(pCall, g_nProbes);
    DBusMessage *pReply = dbus_message_new_method_return(pCall);
    if (pReply != NULL && !dbus_message_append_args(pReply, DBUS_TYPE_BOOLEAN, &bOwned, DBUS_TYPE_INVALID))
    {
        dbus_message_unref(pReply);
        return NULL;
    }
    return pReply;
}

static dbus_bool_t Send(DBusConnection *pConn, DBusMessage *pCall, dbus_uint32_t *pSerial)
{
    (void)pConn; (void)pSerial;
    if (g_pSent != NULL) dbus_message_unref(g_pSent);
    g_pSent = dbus_message_ref(pCall);
    g_nSent++;
    return TRUE;
}

static int CheckAxis(directgate_wl_portal_t *pPortal, double nDx, double nDy, xbool_t bKde)
{
    unsigned int nProbes = g_nProbes, nSent = g_nSent;
    CHECK(DirectGate_WL_PortalPointerAxis(pPortal, nDx, nDy) == XSTDOK, "send axis");
    CHECK(g_nSent == nSent + 1 && g_nProbes == nProbes, "one send, no probing in input path");
    CHECK(dbus_message_is_method_call(g_pSent, DIRECTGATE_PORTAL_REMOTE, "NotifyPointerAxis"), "axis method");
    CHECK(strcmp(dbus_message_get_signature(g_pSent), "oa{sv}dd") == 0, "axis wire signature");

    DBusMessageIter iter;
    const char *pSession = NULL;
    double nWireX = 0.0, nWireY = 0.0;
    dbus_message_iter_init(g_pSent, &iter);
    dbus_message_iter_get_basic(&iter, &pSession);
    CHECK(strcmp(pSession, pPortal->sSessionHandle) == 0, "axis session");
    dbus_message_iter_next(&iter); /* options */
    dbus_message_iter_next(&iter);
    dbus_message_iter_get_basic(&iter, &nWireX);
    dbus_message_iter_next(&iter);
    dbus_message_iter_get_basic(&iter, &nWireY);
    /* KDE requestPointerAxis applies (x, -y), GNOME applies (x, y).
     * After that transformation the compositor must see the requested
     * direction and distance. Check both signs and fractional motion. */
    double nNativeY = bKde ? -nWireY : nWireY;
    CHECK(fabs(nWireX - nDx) < 1e-12 && fabs(nNativeY - nDy) < 1e-12,
        "compositor scroll direction/distance differs from browser");
    return 0;
}

int main(void)
{
    /* Use libdbus's message implementation, with no connection to the bus. */
    g_dbus.newCall = dbus_message_new_method_call;
    g_dbus.msgUnref = dbus_message_unref;
    g_dbus.errorInit = dbus_error_init;
    g_dbus.errorFree = dbus_error_free;
    g_dbus.iterInitAppend = dbus_message_iter_init_append;
    g_dbus.iterAppend = dbus_message_iter_append_basic;
    g_dbus.iterOpen = dbus_message_iter_open_container;
    g_dbus.iterClose = dbus_message_iter_close_container;
    g_dbus.iterInit = dbus_message_iter_init;
    g_dbus.iterArgType = dbus_message_iter_get_arg_type;
    g_dbus.iterGet = dbus_message_iter_get_basic;
    g_dbus.sendBlock = Probe;
    g_dbus.send = Send;

    directgate_wl_portal_t portal = {0};
    int nConnectionToken = 0;
    portal.pConn = (DBusConnection*)&nConnectionToken; /* Only passed to stubs. */
    strcpy(portal.sSessionHandle, "/org/freedesktop/portal/desktop/session/test");

    for (unsigned int nCase = 0; nCase < 4; nCase++)
    {
        g_bKdePortal = (nCase & 1U) != 0;
        g_bKwin = (nCase & 2U) != 0;
        xbool_t bKde = g_bKdePortal && g_bKwin;
        DirectGate_WL_PortalInitScroll(&portal);
        CHECK(CheckAxis(&portal, 0, 10, bKde) == 0, "down scroll");
        CHECK(CheckAxis(&portal, 0, -10, bKde) == 0, "up scroll");
        CHECK(CheckAxis(&portal, 10, 0, bKde) == 0, "right scroll");
        CHECK(CheckAxis(&portal, -0.25, 0.5, bKde) == 0, "fractional diagonal scroll");

        CHECK(DirectGate_WL_PortalPointerMotionRelative(&portal, 1.25, -2.5) == XSTDOK, "relative motion");
        CHECK(dbus_message_is_method_call(g_pSent, DIRECTGATE_PORTAL_REMOTE, "NotifyPointerMotion"), "motion method");
        DBusMessageIter iter;
        double nX, nY;
        dbus_message_iter_init(g_pSent, &iter);
        dbus_message_iter_next(&iter);
        dbus_message_iter_next(&iter);
        dbus_message_iter_get_basic(&iter, &nX);
        dbus_message_iter_next(&iter);
        dbus_message_iter_get_basic(&iter, &nY);
        CHECK(nX == 1.25 && nY == -2.5, "scroll compensation changed pointer motion");
    }

    g_bProbeError = XTRUE;
    DirectGate_WL_PortalInitScroll(&portal);
    CHECK(CheckAxis(&portal, 1, 2, XFALSE) == 0, "probe failure preserves standard direction");
    CHECK(DirectGate_WL_PortalPointerAxis(NULL, 1, 2) == XSTDERR, "null portal guard");
    dbus_message_unref(g_pSent);
    puts("wayland_portal_smoke: OK");
    return 0;
}
