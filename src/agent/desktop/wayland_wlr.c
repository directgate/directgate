/*!
 * @file directgate-agent/src/agent/desktop/wayland_wlr.c
 * @brief wlroots screen capture and virtual input, for compositors whose portal has no RemoteDesktop.
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
#include <math.h>
#include <poll.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/* One round trip to the compositor. A local socket answers in microseconds;
 * a compositor that takes this long is not one a session can be run on, and
 * the wait has to end so the thread that is joined on teardown is not held. */
#define DIRECTGATE_WLR_CALL_MS        2000U

#define DIRECTGATE_WLR_MAX_DIM        16384U
#define DIRECTGATE_WLR_MAX_BYTES      (1024U * 1024U * 1024U)
#define DIRECTGATE_WLR_MAX_KEYMAP     (4U * 1024U * 1024U)
#define DIRECTGATE_WLR_RETRY_MAX_MS   1000U
#define DIRECTGATE_WLR_SCRATCH_MAX    128U
#define DIRECTGATE_WLR_HELD_MAX       32U

/* wl_shm formats: the first two are wl_shm's own codes, the rest DRM fourccs. */
#define DIRECTGATE_WLR_SHM_ARGB8888   0U
#define DIRECTGATE_WLR_SHM_XRGB8888   1U
#define DIRECTGATE_WLR_SHM_ABGR8888   0x34324241U
#define DIRECTGATE_WLR_SHM_XBGR8888   0x34324258U

#define DIRECTGATE_WLR_FRAME_Y_INVERT 1U
#define DIRECTGATE_WLR_SEAT_KEYBOARD  2U
#define DIRECTGATE_WLR_KEYMAP_XKB_V1  1U
#define DIRECTGATE_WLR_MODE_CURRENT   1U
#define DIRECTGATE_WLR_AXIS_VERTICAL  0U
#define DIRECTGATE_WLR_AXIS_HORIZONTAL 1U
#define DIRECTGATE_WLR_AXIS_CONTINUOUS 2U

/* Request and event opcodes, in the order the protocol XML declares them:
 * wayland.xml, wlr-screencopy-unstable-v1, wlr-virtual-pointer-unstable-v1,
 * virtual-keyboard-unstable-v1 and xdg-output-unstable-v1. */
#define DIRECTGATE_WLR_DISPLAY_SYNC           0U
#define DIRECTGATE_WLR_DISPLAY_GET_REGISTRY   1U
#define DIRECTGATE_WLR_REGISTRY_BIND          0U
#define DIRECTGATE_WLR_REGISTRY_GLOBAL        0U
#define DIRECTGATE_WLR_REGISTRY_REMOVE        1U
#define DIRECTGATE_WLR_SHM_CREATE_POOL        0U
#define DIRECTGATE_WLR_POOL_CREATE_BUFFER     0U
#define DIRECTGATE_WLR_POOL_DESTROY           1U
#define DIRECTGATE_WLR_BUFFER_DESTROY         0U
#define DIRECTGATE_WLR_OUTPUT_GEOMETRY        0U
#define DIRECTGATE_WLR_OUTPUT_MODE            1U
#define DIRECTGATE_WLR_OUTPUT_NAME            4U
#define DIRECTGATE_WLR_SEAT_GET_KEYBOARD      1U
#define DIRECTGATE_WLR_SEAT_CAPABILITIES      0U
#define DIRECTGATE_WLR_KEYBOARD_RELEASE       0U
#define DIRECTGATE_WLR_KEYBOARD_KEYMAP        0U
#define DIRECTGATE_WLR_COPY_CAPTURE_OUTPUT    0U
#define DIRECTGATE_WLR_FRAME_COPY             0U
#define DIRECTGATE_WLR_FRAME_DESTROY          1U
#define DIRECTGATE_WLR_FRAME_COPY_DAMAGE      2U
#define DIRECTGATE_WLR_FRAME_BUFFER           0U
#define DIRECTGATE_WLR_FRAME_FLAGS            1U
#define DIRECTGATE_WLR_FRAME_READY            2U
#define DIRECTGATE_WLR_FRAME_FAILED           3U
#define DIRECTGATE_WLR_FRAME_BUFFER_DONE      6U
#define DIRECTGATE_WLR_VPM_CREATE             0U
#define DIRECTGATE_WLR_VPM_CREATE_WITH_OUTPUT 2U
#define DIRECTGATE_WLR_VP_MOTION              0U
#define DIRECTGATE_WLR_VP_MOTION_ABSOLUTE     1U
#define DIRECTGATE_WLR_VP_BUTTON              2U
#define DIRECTGATE_WLR_VP_AXIS                3U
#define DIRECTGATE_WLR_VP_FRAME               4U
#define DIRECTGATE_WLR_VP_AXIS_SOURCE         5U
#define DIRECTGATE_WLR_VP_DESTROY             8U
#define DIRECTGATE_WLR_VKM_CREATE             0U
#define DIRECTGATE_WLR_VK_KEYMAP              0U
#define DIRECTGATE_WLR_VK_KEY                 1U
#define DIRECTGATE_WLR_VK_MODIFIERS           2U
#define DIRECTGATE_WLR_VK_DESTROY             3U
#define DIRECTGATE_WLR_XDGM_GET_OUTPUT        1U
#define DIRECTGATE_WLR_XDG_DESTROY            0U
#define DIRECTGATE_WLR_XDG_LOGICAL_POSITION   0U
#define DIRECTGATE_WLR_XDG_NAME               3U

/* libwayland-client is opened at runtime, so its headers are not needed to
 * build this file and none of its symbols are linked. These three mirror
 * wl_message, wl_interface and wl_argument from wayland-util.h: they are part
 * of libwayland's frozen ABI - every protocol binding compiled into every
 * Wayland client in a distribution depends on their layout - and have not
 * changed since 1.0. The smoke test compares them with the real headers. */
typedef struct directgate_wlr_iface_ directgate_wlr_iface_t;

typedef struct directgate_wlr_msg_ {
    const char *pName;
    const char *pSignature;
    const directgate_wlr_iface_t **ppTypes;
} directgate_wlr_msg_t;

struct directgate_wlr_iface_ {
    const char *pName;
    int nVersion;
    int nMethodCount;
    const directgate_wlr_msg_t *pMethods;
    int nEventCount;
    const directgate_wlr_msg_t *pEvents;
};

typedef union directgate_wlr_arg_ {
    int32_t nInt;       /* i */
    uint32_t nUint;     /* u */
    int32_t nFixed;     /* f, 24.8 */
    const char *pStr;   /* s */
    void *pObject;      /* o */
    uint32_t nNewId;    /* n */
    void *pArray;       /* a */
    int32_t nFd;        /* h */
} directgate_wlr_arg_t;

struct wl_display;
struct wl_proxy;

typedef int (*directgate_wlr_dispatch_fn)(const void*, void*, uint32_t, const directgate_wlr_msg_t*, directgate_wlr_arg_t*);
typedef struct wl_display* (*directgate_wlr_connect_fn)(const char*);
typedef void (*directgate_wlr_display_void_fn)(struct wl_display*);
typedef int (*directgate_wlr_display_int_fn)(struct wl_display*);
typedef struct wl_proxy* (*directgate_wlr_marshal_ctor_fn)(struct wl_proxy*, uint32_t, directgate_wlr_arg_t*,
                                                          const directgate_wlr_iface_t*, uint32_t);
typedef void (*directgate_wlr_marshal_fn)(struct wl_proxy*, uint32_t, directgate_wlr_arg_t*);
typedef int (*directgate_wlr_add_dispatcher_fn)(struct wl_proxy*, directgate_wlr_dispatch_fn, const void*, void*);
typedef void (*directgate_wlr_proxy_void_fn)(struct wl_proxy*);
typedef void* (*directgate_wlr_proxy_data_fn)(struct wl_proxy*);
typedef uint32_t (*directgate_wlr_proxy_version_fn)(struct wl_proxy*);
typedef uint32_t (*directgate_wlr_protocol_error_fn)(struct wl_display*, const directgate_wlr_iface_t**, uint32_t*);

typedef struct directgate_wlr_lib_ {
    void *pHandle;
    directgate_wlr_connect_fn connect;
    directgate_wlr_display_void_fn disconnect;
    directgate_wlr_display_int_fn getFd;
    directgate_wlr_display_int_fn dispatchPending;
    directgate_wlr_display_int_fn flush;
    directgate_wlr_display_int_fn prepareRead;
    directgate_wlr_display_int_fn readEvents;
    directgate_wlr_display_void_fn cancelRead;
    directgate_wlr_display_int_fn getError;
    directgate_wlr_protocol_error_fn protocolError;
    directgate_wlr_marshal_ctor_fn marshalCtor;
    directgate_wlr_marshal_fn marshal;
    directgate_wlr_add_dispatcher_fn addDispatcher;
    directgate_wlr_proxy_void_fn proxyDestroy;
    directgate_wlr_proxy_data_fn proxyData;
    directgate_wlr_proxy_version_fn proxyVersion;
    const directgate_wlr_iface_t *pRegistry;
    const directgate_wlr_iface_t *pCallback;
    const directgate_wlr_iface_t *pOutput;
    const directgate_wlr_iface_t *pShm;
    const directgate_wlr_iface_t *pShmPool;
    const directgate_wlr_iface_t *pBuffer;
    const directgate_wlr_iface_t *pSeat;
    const directgate_wlr_iface_t *pKeyboard;
    xbool_t bLoadAttempted;
    xbool_t bLoaded;
} directgate_wlr_lib_t;

static directgate_wlr_lib_t g_wlr;

/* libxkbcommon, the same way. The virtual keyboard protocol carries a keymap
 * and leaves the modifier state entirely to the client - wlroots takes the
 * keys as they come and never works out that a Shift went down - so the
 * keyboard needs a real xkb state of its own, and nothing short of xkbcommon
 * can compile one. Every wlroots compositor links it, so it is always there. */
struct xkb_context;
struct xkb_keymap;
struct xkb_state;

typedef struct directgate_xkb_names_ {
    const char *pRules;
    const char *pModel;
    const char *pLayout;
    const char *pVariant;
    const char *pOptions;
} directgate_xkb_names_t;

typedef struct xkb_context* (*directgate_xkb_context_new_fn)(int);
typedef void (*directgate_xkb_context_unref_fn)(struct xkb_context*);
typedef struct xkb_keymap* (*directgate_xkb_from_names_fn)(struct xkb_context*, const directgate_xkb_names_t*, int);
typedef struct xkb_keymap* (*directgate_xkb_from_string_fn)(struct xkb_context*, const char*, int, int);
typedef char* (*directgate_xkb_as_string_fn)(struct xkb_keymap*, int);
typedef void (*directgate_xkb_keymap_unref_fn)(struct xkb_keymap*);
typedef uint32_t (*directgate_xkb_keycode_fn)(struct xkb_keymap*);
typedef const char* (*directgate_xkb_key_name_fn)(struct xkb_keymap*, uint32_t);
typedef uint32_t (*directgate_xkb_num_layouts_fn)(struct xkb_keymap*, uint32_t);
typedef uint32_t (*directgate_xkb_num_levels_fn)(struct xkb_keymap*, uint32_t, uint32_t);
typedef int (*directgate_xkb_syms_fn)(struct xkb_keymap*, uint32_t, uint32_t, uint32_t, const uint32_t**);
typedef int (*directgate_xkb_sym_name_fn)(uint32_t, char*, size_t);
typedef struct xkb_state* (*directgate_xkb_state_new_fn)(struct xkb_keymap*);
typedef void (*directgate_xkb_state_unref_fn)(struct xkb_state*);
typedef int (*directgate_xkb_update_key_fn)(struct xkb_state*, uint32_t, int);
typedef uint32_t (*directgate_xkb_serialize_fn)(struct xkb_state*, int);
typedef uint32_t (*directgate_xkb_one_sym_fn)(struct xkb_state*, uint32_t);

typedef struct directgate_xkb_lib_ {
    void *pHandle;
    directgate_xkb_context_new_fn contextNew;
    directgate_xkb_context_unref_fn contextUnref;
    directgate_xkb_from_names_fn keymapFromNames;
    directgate_xkb_from_string_fn keymapFromString;
    directgate_xkb_as_string_fn keymapAsString;
    directgate_xkb_keymap_unref_fn keymapUnref;
    directgate_xkb_keycode_fn minKeycode;
    directgate_xkb_keycode_fn maxKeycode;
    directgate_xkb_key_name_fn keyName;
    directgate_xkb_num_layouts_fn numLayouts;
    directgate_xkb_num_levels_fn numLevels;
    directgate_xkb_syms_fn symsByLevel;
    directgate_xkb_sym_name_fn keysymName;
    directgate_xkb_state_new_fn stateNew;
    directgate_xkb_state_unref_fn stateUnref;
    directgate_xkb_update_key_fn updateKey;
    directgate_xkb_serialize_fn serializeMods;
    directgate_xkb_serialize_fn serializeLayout;
    directgate_xkb_one_sym_fn oneSym;
    xbool_t bLoadAttempted;
    xbool_t bLoaded;
} directgate_xkb_lib_t;

static directgate_xkb_lib_t g_xkb;

#define DIRECTGATE_XKB_TEXT_V1          1
#define DIRECTGATE_XKB_KEY_UP           0
#define DIRECTGATE_XKB_KEY_DOWN         1
#define DIRECTGATE_XKB_MODS_DEPRESSED   (1 << 0)
#define DIRECTGATE_XKB_MODS_LATCHED     (1 << 1)
#define DIRECTGATE_XKB_MODS_LOCKED      (1 << 2)
#define DIRECTGATE_XKB_LAYOUT_EFFECTIVE (1 << 7)

static pthread_mutex_t g_wlrLoadLock = PTHREAD_MUTEX_INITIALIZER;

/* The protocol tables. A types entry names the interface of an object or
 * new_id argument; those that belong to the core protocol live in libwayland
 * and are filled in once it is loaded, which is why these are not const. */
static const directgate_wlr_iface_t *g_wlrNoTypes[8];

static const directgate_wlr_iface_t g_wlrFrameIface;
static const directgate_wlr_iface_t g_wlrPointerIface;
static const directgate_wlr_iface_t g_wlrKeyboardIface;
static const directgate_wlr_iface_t g_wlrXdgOutputIface;

static const directgate_wlr_iface_t *g_wlrCopyTypes[] = { NULL /* wl_buffer */ };
static const directgate_wlr_iface_t *g_wlrCaptureTypes[] = { &g_wlrFrameIface, NULL, NULL /* wl_output */ };
static const directgate_wlr_iface_t *g_wlrRegionTypes[] = { &g_wlrFrameIface, NULL, NULL, NULL, NULL, NULL, NULL };
static const directgate_wlr_iface_t *g_wlrPointerTypes[] = { NULL /* wl_seat */, &g_wlrPointerIface };
static const directgate_wlr_iface_t *g_wlrPointerOutputTypes[] = { NULL /* wl_seat */, NULL /* wl_output */, &g_wlrPointerIface };
static const directgate_wlr_iface_t *g_wlrKeyboardTypes[] = { NULL /* wl_seat */, &g_wlrKeyboardIface };
static const directgate_wlr_iface_t *g_wlrXdgOutputTypes[] = { &g_wlrXdgOutputIface, NULL /* wl_output */ };

static const directgate_wlr_msg_t g_wlrFrameRequests[] = {
    { "copy", "o", g_wlrCopyTypes },
    { "destroy", "", g_wlrNoTypes },
    { "copy_with_damage", "2o", g_wlrCopyTypes },
};

static const directgate_wlr_msg_t g_wlrFrameEvents[] = {
    { "buffer", "uuuu", g_wlrNoTypes },
    { "flags", "u", g_wlrNoTypes },
    { "ready", "uuu", g_wlrNoTypes },
    { "failed", "", g_wlrNoTypes },
    { "damage", "2uuuu", g_wlrNoTypes },
    { "linux_dmabuf", "3uuu", g_wlrNoTypes },
    { "buffer_done", "3", g_wlrNoTypes },
};

static const directgate_wlr_iface_t g_wlrFrameIface = {
    "zwlr_screencopy_frame_v1", 3, 3, g_wlrFrameRequests, 7, g_wlrFrameEvents
};

static const directgate_wlr_msg_t g_wlrCopyManagerRequests[] = {
    { "capture_output", "nio", g_wlrCaptureTypes },
    { "capture_output_region", "nioiiii", g_wlrRegionTypes },
    { "destroy", "", g_wlrNoTypes },
};

static const directgate_wlr_iface_t g_wlrCopyManagerIface = {
    "zwlr_screencopy_manager_v1", 3, 3, g_wlrCopyManagerRequests, 0, NULL
};

static const directgate_wlr_msg_t g_wlrPointerRequests[] = {
    { "motion", "uff", g_wlrNoTypes },
    { "motion_absolute", "uuuuu", g_wlrNoTypes },
    { "button", "uuu", g_wlrNoTypes },
    { "axis", "uuf", g_wlrNoTypes },
    { "frame", "", g_wlrNoTypes },
    { "axis_source", "u", g_wlrNoTypes },
    { "axis_stop", "uu", g_wlrNoTypes },
    { "axis_discrete", "uufi", g_wlrNoTypes },
    { "destroy", "", g_wlrNoTypes },
};

static const directgate_wlr_iface_t g_wlrPointerIface = {
    "zwlr_virtual_pointer_v1", 2, 9, g_wlrPointerRequests, 0, NULL
};

static const directgate_wlr_msg_t g_wlrPointerManagerRequests[] = {
    { "create_virtual_pointer", "?on", g_wlrPointerTypes },
    { "destroy", "", g_wlrNoTypes },
    { "create_virtual_pointer_with_output", "2?o?on", g_wlrPointerOutputTypes },
};

static const directgate_wlr_iface_t g_wlrPointerManagerIface = {
    "zwlr_virtual_pointer_manager_v1", 2, 3, g_wlrPointerManagerRequests, 0, NULL
};

static const directgate_wlr_msg_t g_wlrKeyboardRequests[] = {
    { "keymap", "uhu", g_wlrNoTypes },
    { "key", "uuu", g_wlrNoTypes },
    { "modifiers", "uuuu", g_wlrNoTypes },
    { "destroy", "", g_wlrNoTypes },
};

static const directgate_wlr_iface_t g_wlrKeyboardIface = {
    "zwp_virtual_keyboard_v1", 1, 4, g_wlrKeyboardRequests, 0, NULL
};

static const directgate_wlr_msg_t g_wlrKeyboardManagerRequests[] = {
    { "create_virtual_keyboard", "on", g_wlrKeyboardTypes },
};

static const directgate_wlr_iface_t g_wlrKeyboardManagerIface = {
    "zwp_virtual_keyboard_manager_v1", 1, 1, g_wlrKeyboardManagerRequests, 0, NULL
};

static const directgate_wlr_msg_t g_wlrXdgOutputRequests[] = {
    { "destroy", "", g_wlrNoTypes },
};

static const directgate_wlr_msg_t g_wlrXdgOutputEvents[] = {
    { "logical_position", "ii", g_wlrNoTypes },
    { "logical_size", "ii", g_wlrNoTypes },
    { "done", "", g_wlrNoTypes },
    { "name", "2s", g_wlrNoTypes },
    { "description", "2s", g_wlrNoTypes },
};

static const directgate_wlr_iface_t g_wlrXdgOutputIface = {
    "zxdg_output_v1", 3, 1, g_wlrXdgOutputRequests, 5, g_wlrXdgOutputEvents
};

static const directgate_wlr_msg_t g_wlrXdgManagerRequests[] = {
    { "destroy", "", g_wlrNoTypes },
    { "get_xdg_output", "no", g_wlrXdgOutputTypes },
};

static const directgate_wlr_iface_t g_wlrXdgManagerIface = {
    "zxdg_output_manager_v1", 3, 2, g_wlrXdgManagerRequests, 0, NULL
};

static void DirectGate_WLR_SetError(char *pErrBuf, size_t nErrSize, const char *pFmt, ...)
{
    if (pErrBuf == NULL || !nErrSize) return;

    va_list args;
    va_start(args, pFmt);
    vsnprintf(pErrBuf, nErrSize, pFmt, args);
    va_end(args);
}

static int DirectGate_WLR_Load(char *pErrBuf, size_t nErrSize)
{
    directgate_wlr_lib_t *pLib = &g_wlr;
    pthread_mutex_lock(&g_wlrLoadLock);

    if (pLib->bLoadAttempted)
    {
        xbool_t bLoaded = pLib->bLoaded;
        pthread_mutex_unlock(&g_wlrLoadLock);

        if (!bLoaded) DirectGate_WLR_SetError(pErrBuf, nErrSize, "libwayland-client is not available on this host.");
        return bLoaded ? XSTDOK : XSTDERR;
    }

    pLib->bLoadAttempted = XTRUE;

    void *pHandle = dlopen("libwayland-client.so.0", RTLD_NOW | RTLD_LOCAL);
    if (pHandle == NULL) pHandle = dlopen("libwayland-client.so", RTLD_NOW | RTLD_LOCAL);

    if (pHandle == NULL)
    {
        pthread_mutex_unlock(&g_wlrLoadLock);
        DirectGate_WLR_SetError(pErrBuf, nErrSize, "libwayland-client is not available on this host.");
        return XSTDERR;
    }

    pLib->connect = (directgate_wlr_connect_fn)dlsym(pHandle, "wl_display_connect");
    pLib->disconnect = (directgate_wlr_display_void_fn)dlsym(pHandle, "wl_display_disconnect");
    pLib->getFd = (directgate_wlr_display_int_fn)dlsym(pHandle, "wl_display_get_fd");
    pLib->dispatchPending = (directgate_wlr_display_int_fn)dlsym(pHandle, "wl_display_dispatch_pending");
    pLib->flush = (directgate_wlr_display_int_fn)dlsym(pHandle, "wl_display_flush");
    pLib->prepareRead = (directgate_wlr_display_int_fn)dlsym(pHandle, "wl_display_prepare_read");
    pLib->readEvents = (directgate_wlr_display_int_fn)dlsym(pHandle, "wl_display_read_events");
    pLib->cancelRead = (directgate_wlr_display_void_fn)dlsym(pHandle, "wl_display_cancel_read");
    pLib->getError = (directgate_wlr_display_int_fn)dlsym(pHandle, "wl_display_get_error");
    pLib->protocolError = (directgate_wlr_protocol_error_fn)dlsym(pHandle, "wl_display_get_protocol_error");
    pLib->marshalCtor = (directgate_wlr_marshal_ctor_fn)dlsym(pHandle, "wl_proxy_marshal_array_constructor_versioned");
    pLib->marshal = (directgate_wlr_marshal_fn)dlsym(pHandle, "wl_proxy_marshal_array");
    pLib->addDispatcher = (directgate_wlr_add_dispatcher_fn)dlsym(pHandle, "wl_proxy_add_dispatcher");
    pLib->proxyDestroy = (directgate_wlr_proxy_void_fn)dlsym(pHandle, "wl_proxy_destroy");
    pLib->proxyData = (directgate_wlr_proxy_data_fn)dlsym(pHandle, "wl_proxy_get_user_data");
    pLib->proxyVersion = (directgate_wlr_proxy_version_fn)dlsym(pHandle, "wl_proxy_get_version");
    pLib->pRegistry = (const directgate_wlr_iface_t*)dlsym(pHandle, "wl_registry_interface");
    pLib->pCallback = (const directgate_wlr_iface_t*)dlsym(pHandle, "wl_callback_interface");
    pLib->pOutput = (const directgate_wlr_iface_t*)dlsym(pHandle, "wl_output_interface");
    pLib->pShm = (const directgate_wlr_iface_t*)dlsym(pHandle, "wl_shm_interface");
    pLib->pShmPool = (const directgate_wlr_iface_t*)dlsym(pHandle, "wl_shm_pool_interface");
    pLib->pBuffer = (const directgate_wlr_iface_t*)dlsym(pHandle, "wl_buffer_interface");
    pLib->pSeat = (const directgate_wlr_iface_t*)dlsym(pHandle, "wl_seat_interface");
    pLib->pKeyboard = (const directgate_wlr_iface_t*)dlsym(pHandle, "wl_keyboard_interface");

    if (pLib->connect == NULL || pLib->disconnect == NULL || pLib->getFd == NULL || pLib->dispatchPending == NULL ||
        pLib->flush == NULL || pLib->prepareRead == NULL || pLib->readEvents == NULL || pLib->cancelRead == NULL ||
        pLib->getError == NULL || pLib->marshalCtor == NULL || pLib->marshal == NULL || pLib->addDispatcher == NULL ||
        pLib->proxyDestroy == NULL || pLib->proxyData == NULL || pLib->proxyVersion == NULL ||
        pLib->pRegistry == NULL || pLib->pCallback == NULL || pLib->pOutput == NULL || pLib->pShm == NULL ||
        pLib->pShmPool == NULL || pLib->pBuffer == NULL || pLib->pSeat == NULL || pLib->pKeyboard == NULL)
    {
        dlclose(pHandle);
        memset(pLib, 0, sizeof(*pLib));
        pLib->bLoadAttempted = XTRUE;
        pthread_mutex_unlock(&g_wlrLoadLock);

        DirectGate_WLR_SetError(pErrBuf, nErrSize, "The installed libwayland-client is missing entry points this agent needs.");
        return XSTDERR;
    }

    g_wlrCopyTypes[0] = pLib->pBuffer;
    g_wlrCaptureTypes[2] = pLib->pOutput;
    g_wlrRegionTypes[2] = pLib->pOutput;   /* wl_output */
    g_wlrPointerTypes[0] = pLib->pSeat;
    g_wlrPointerOutputTypes[0] = pLib->pSeat;
    g_wlrPointerOutputTypes[1] = pLib->pOutput;
    g_wlrKeyboardTypes[0] = pLib->pSeat;
    g_wlrXdgOutputTypes[1] = pLib->pOutput;

    pLib->pHandle = pHandle;
    pLib->bLoaded = XTRUE;
    pthread_mutex_unlock(&g_wlrLoadLock);

    return XSTDOK;
}

static int DirectGate_WLR_XkbLoad(char *pErrBuf, size_t nErrSize)
{
    directgate_xkb_lib_t *pLib = &g_xkb;
    pthread_mutex_lock(&g_wlrLoadLock);

    if (pLib->bLoadAttempted)
    {
        xbool_t bLoaded = pLib->bLoaded;
        pthread_mutex_unlock(&g_wlrLoadLock);

        if (!bLoaded) DirectGate_WLR_SetError(pErrBuf, nErrSize, "libxkbcommon is not available on this host.");
        return bLoaded ? XSTDOK : XSTDERR;
    }

    pLib->bLoadAttempted = XTRUE;

    void *pHandle = dlopen("libxkbcommon.so.0", RTLD_NOW | RTLD_LOCAL);
    if (pHandle == NULL) pHandle = dlopen("libxkbcommon.so", RTLD_NOW | RTLD_LOCAL);

    if (pHandle == NULL)
    {
        pthread_mutex_unlock(&g_wlrLoadLock);
        DirectGate_WLR_SetError(pErrBuf, nErrSize, "libxkbcommon is not available on this host.");
        return XSTDERR;
    }

    pLib->contextNew = (directgate_xkb_context_new_fn)dlsym(pHandle, "xkb_context_new");
    pLib->contextUnref = (directgate_xkb_context_unref_fn)dlsym(pHandle, "xkb_context_unref");
    pLib->keymapFromNames = (directgate_xkb_from_names_fn)dlsym(pHandle, "xkb_keymap_new_from_names");
    pLib->keymapFromString = (directgate_xkb_from_string_fn)dlsym(pHandle, "xkb_keymap_new_from_string");
    pLib->keymapAsString = (directgate_xkb_as_string_fn)dlsym(pHandle, "xkb_keymap_get_as_string");
    pLib->keymapUnref = (directgate_xkb_keymap_unref_fn)dlsym(pHandle, "xkb_keymap_unref");
    pLib->minKeycode = (directgate_xkb_keycode_fn)dlsym(pHandle, "xkb_keymap_min_keycode");
    pLib->maxKeycode = (directgate_xkb_keycode_fn)dlsym(pHandle, "xkb_keymap_max_keycode");
    pLib->keyName = (directgate_xkb_key_name_fn)dlsym(pHandle, "xkb_keymap_key_get_name");
    pLib->numLayouts = (directgate_xkb_num_layouts_fn)dlsym(pHandle, "xkb_keymap_num_layouts_for_key");
    pLib->numLevels = (directgate_xkb_num_levels_fn)dlsym(pHandle, "xkb_keymap_num_levels_for_key");
    pLib->symsByLevel = (directgate_xkb_syms_fn)dlsym(pHandle, "xkb_keymap_key_get_syms_by_level");
    pLib->keysymName = (directgate_xkb_sym_name_fn)dlsym(pHandle, "xkb_keysym_get_name");
    pLib->stateNew = (directgate_xkb_state_new_fn)dlsym(pHandle, "xkb_state_new");
    pLib->stateUnref = (directgate_xkb_state_unref_fn)dlsym(pHandle, "xkb_state_unref");
    pLib->updateKey = (directgate_xkb_update_key_fn)dlsym(pHandle, "xkb_state_update_key");
    pLib->serializeMods = (directgate_xkb_serialize_fn)dlsym(pHandle, "xkb_state_serialize_mods");
    pLib->serializeLayout = (directgate_xkb_serialize_fn)dlsym(pHandle, "xkb_state_serialize_layout");
    pLib->oneSym = (directgate_xkb_one_sym_fn)dlsym(pHandle, "xkb_state_key_get_one_sym");

    if (pLib->contextNew == NULL || pLib->contextUnref == NULL || pLib->keymapFromNames == NULL ||
        pLib->keymapFromString == NULL || pLib->keymapAsString == NULL || pLib->keymapUnref == NULL ||
        pLib->minKeycode == NULL || pLib->maxKeycode == NULL || pLib->keyName == NULL || pLib->numLayouts == NULL ||
        pLib->numLevels == NULL || pLib->symsByLevel == NULL || pLib->keysymName == NULL || pLib->stateNew == NULL ||
        pLib->stateUnref == NULL || pLib->updateKey == NULL || pLib->serializeMods == NULL ||
        pLib->serializeLayout == NULL || pLib->oneSym == NULL)
    {
        dlclose(pHandle);
        memset(pLib, 0, sizeof(*pLib));
        pLib->bLoadAttempted = XTRUE;
        pthread_mutex_unlock(&g_wlrLoadLock);

        DirectGate_WLR_SetError(pErrBuf, nErrSize, "The installed libxkbcommon is missing entry points this agent needs.");
        return XSTDERR;
    }

    pLib->pHandle = pHandle;
    pLib->bLoaded = XTRUE;
    pthread_mutex_unlock(&g_wlrLoadLock);

    return XSTDOK;
}

static uint32_t DirectGate_WLR_Now(void)
{
    return (uint32_t)XTime_GetMonoMs();
}

static int32_t DirectGate_WLR_Fixed(double nValue)
{
    /* 24.8 fixed point; anything past its range is no motion anyone meant */
    double nScaled = nValue * 256.0;
    if (nScaled > 2147483000.0) nScaled = 2147483000.0;
    if (nScaled < -2147483000.0) nScaled = -2147483000.0;
    return (int32_t)lrint(nScaled);
}

/* An unnamed file in memory, for the screen buffer and the keymap. Through the
 * raw system call because the libc wrapper needs _GNU_SOURCE and a glibc newer
 * than some of the hosts this is built for; a file in the runtime directory,
 * unlinked at once, where the kernel predates it. */
static int DirectGate_WLR_AnonFile(size_t nSize)
{
    int nFd = -1;

#ifdef __NR_memfd_create
    nFd = (int)syscall(__NR_memfd_create, "directgate-wayland", 1U /* MFD_CLOEXEC */);
#endif

    if (nFd < 0)
    {
        const char *pDir = getenv("XDG_RUNTIME_DIR");
        char sPath[XPATH_MAX];

        snprintf(sPath, sizeof(sPath), "%s/directgate-wayland-XXXXXX", xstrused(pDir) ? pDir : "/tmp");
        nFd = mkstemp(sPath);
        if (nFd < 0) return -1;

        unlink(sPath);
        fcntl(nFd, F_SETFD, FD_CLOEXEC);
    }

    if (ftruncate(nFd, (off_t)nSize) < 0)
    {
        close(nFd);
        return -1;
    }

    return nFd;
}

/* One screen as the compositor describes it. */
typedef struct directgate_wlr_output_ {
    uint32_t nName;                /* wl_output global name - the screen's id */
    struct wl_proxy *pOutput;
    struct wl_proxy *pXdgOutput;
    struct wl_proxy *pPointer;     /* input only: a virtual pointer mapped onto it */
    int32_t nWidth;                /* current mode, in the buffer's pixels */
    int32_t nHeight;
    int32_t nX;                    /* layout position, when xdg-output says */
    int32_t nY;
    int32_t nTransform;
    char sName[64];
    xbool_t bGone;
} directgate_wlr_output_t;

/* One connection to the compositor and the globals bound on it. The capture
 * and the input each have their own, so each is only ever touched by one
 * thread and neither ever waits on the other's traffic. */
typedef struct directgate_wlr_conn_ {
    struct wl_display *pDisplay;
    struct wl_proxy *pRegistry;
    xbool_t bInput;                /* bind what input needs, not what capture does */
    uint32_t nWantOutput;          /* capture: the one screen to bind */

    struct wl_proxy *pShm;
    struct wl_proxy *pScreencopy;
    uint32_t nScreencopyVersion;   /* advertised, also on the input connection */
    struct wl_proxy *pSeat;
    uint32_t nSeatVersion;
    uint32_t nSeatCaps;
    struct wl_proxy *pPointerManager;
    uint32_t nPointerVersion;
    struct wl_proxy *pKeyboardManager;
    struct wl_proxy *pXdgManager;

    directgate_wlr_output_t outputs[DIRECTGATE_WL_MAX_STREAMS];
    uint32_t nOutputs;
    xbool_t bOutputLost;           /* capture: the screen was unplugged */
    char sDisplay[64];
} directgate_wlr_conn_t;

static int DirectGate_WLR_OnOutput(const void *pImpl, void *pTarget, uint32_t nOpcode,
                                   const directgate_wlr_msg_t *pMsg, directgate_wlr_arg_t *pArgs)
{
    (void)pImpl; (void)pMsg;
    directgate_wlr_output_t *pOut = (directgate_wlr_output_t*)g_wlr.proxyData((struct wl_proxy*)pTarget);
    if (pOut == NULL) return 0;

    if (nOpcode == DIRECTGATE_WLR_OUTPUT_GEOMETRY) pOut->nTransform = pArgs[7].nInt;
    else if (nOpcode == DIRECTGATE_WLR_OUTPUT_MODE && (pArgs[0].nUint & DIRECTGATE_WLR_MODE_CURRENT))
    {
        pOut->nWidth = pArgs[1].nInt;
        pOut->nHeight = pArgs[2].nInt;
    }
    else if (nOpcode == DIRECTGATE_WLR_OUTPUT_NAME && pArgs[0].pStr != NULL)
    {
        xstrncpy(pOut->sName, sizeof(pOut->sName), pArgs[0].pStr);
    }

    return 0;
}

static int DirectGate_WLR_OnXdgOutput(const void *pImpl, void *pTarget, uint32_t nOpcode,
                                      const directgate_wlr_msg_t *pMsg, directgate_wlr_arg_t *pArgs)
{
    (void)pImpl; (void)pMsg;
    directgate_wlr_output_t *pOut = (directgate_wlr_output_t*)g_wlr.proxyData((struct wl_proxy*)pTarget);
    if (pOut == NULL) return 0;

    if (nOpcode == DIRECTGATE_WLR_XDG_LOGICAL_POSITION)
    {
        pOut->nX = pArgs[0].nInt;
        pOut->nY = pArgs[1].nInt;
    }
    else if (nOpcode == DIRECTGATE_WLR_XDG_NAME && pArgs[0].pStr != NULL && !pOut->sName[0])
    {
        xstrncpy(pOut->sName, sizeof(pOut->sName), pArgs[0].pStr);
    }

    return 0;
}

static int DirectGate_WLR_OnSeat(const void *pImpl, void *pTarget, uint32_t nOpcode,
                                 const directgate_wlr_msg_t *pMsg, directgate_wlr_arg_t *pArgs)
{
    (void)pImpl; (void)pMsg;
    directgate_wlr_conn_t *pConn = (directgate_wlr_conn_t*)g_wlr.proxyData((struct wl_proxy*)pTarget);
    if (pConn != NULL && nOpcode == DIRECTGATE_WLR_SEAT_CAPABILITIES) pConn->nSeatCaps = pArgs[0].nUint;
    return 0;
}

static struct wl_proxy* DirectGate_WLR_Bind(directgate_wlr_conn_t *pConn, uint32_t nName,
                                            const directgate_wlr_iface_t *pIface, uint32_t nVersion)
{
    directgate_wlr_arg_t args[4];
    memset(args, 0, sizeof(args));

    args[0].nUint = nName;
    args[1].pStr = pIface->pName;
    args[2].nUint = nVersion;

    return g_wlr.marshalCtor(pConn->pRegistry, DIRECTGATE_WLR_REGISTRY_BIND, args, pIface, nVersion);
}

static void DirectGate_WLR_OnGlobal(directgate_wlr_conn_t *pConn, uint32_t nName, const char *pIface, uint32_t nVersion)
{
    if (pIface == NULL) return;

    if (xstrcmp(pIface, "zwlr_screencopy_manager_v1"))
    {
        pConn->nScreencopyVersion = nVersion < 3U ? nVersion : 3U;
        if (!pConn->bInput && pConn->pScreencopy == NULL)
            pConn->pScreencopy = DirectGate_WLR_Bind(pConn, nName, &g_wlrCopyManagerIface, pConn->nScreencopyVersion);
    }
    else if (xstrcmp(pIface, "wl_output"))
    {
        if (pConn->nOutputs >= DIRECTGATE_WL_MAX_STREAMS) return;
        if (!pConn->bInput && nName != pConn->nWantOutput) return;

        directgate_wlr_output_t *pOut = &pConn->outputs[pConn->nOutputs];
        memset(pOut, 0, sizeof(*pOut));

        pOut->nName = nName;
        pOut->pOutput = DirectGate_WLR_Bind(pConn, nName, g_wlr.pOutput, nVersion < 4U ? nVersion : 4U);
        if (pOut->pOutput == NULL) return;

        g_wlr.addDispatcher(pOut->pOutput, DirectGate_WLR_OnOutput, pOut, pOut);
        pConn->nOutputs++;
    }
    else if (!pConn->bInput && xstrcmp(pIface, "wl_shm") && pConn->pShm == NULL)
    {
        pConn->pShm = DirectGate_WLR_Bind(pConn, nName, g_wlr.pShm, 1U);
    }
    else if (pConn->bInput && xstrcmp(pIface, "wl_seat") && pConn->pSeat == NULL)
    {
        pConn->nSeatVersion = nVersion < 5U ? nVersion : 5U;
        pConn->pSeat = DirectGate_WLR_Bind(pConn, nName, g_wlr.pSeat, pConn->nSeatVersion);
        if (pConn->pSeat != NULL) g_wlr.addDispatcher(pConn->pSeat, DirectGate_WLR_OnSeat, pConn, pConn);
    }
    else if (pConn->bInput && xstrcmp(pIface, "zwlr_virtual_pointer_manager_v1") && pConn->pPointerManager == NULL)
    {
        pConn->nPointerVersion = nVersion < 2U ? nVersion : 2U;
        pConn->pPointerManager = DirectGate_WLR_Bind(pConn, nName, &g_wlrPointerManagerIface, pConn->nPointerVersion);
    }
    else if (pConn->bInput && xstrcmp(pIface, "zwp_virtual_keyboard_manager_v1") && pConn->pKeyboardManager == NULL)
    {
        pConn->pKeyboardManager = DirectGate_WLR_Bind(pConn, nName, &g_wlrKeyboardManagerIface, 1U);
    }
    else if (pConn->bInput && xstrcmp(pIface, "zxdg_output_manager_v1") && pConn->pXdgManager == NULL)
    {
        pConn->pXdgManager = DirectGate_WLR_Bind(pConn, nName, &g_wlrXdgManagerIface, nVersion < 3U ? nVersion : 3U);
    }
}

static int DirectGate_WLR_OnRegistry(const void *pImpl, void *pTarget, uint32_t nOpcode,
                                     const directgate_wlr_msg_t *pMsg, directgate_wlr_arg_t *pArgs)
{
    (void)pImpl; (void)pMsg;
    directgate_wlr_conn_t *pConn = (directgate_wlr_conn_t*)g_wlr.proxyData((struct wl_proxy*)pTarget);
    if (pConn == NULL) return 0;

    if (nOpcode == DIRECTGATE_WLR_REGISTRY_GLOBAL)
    {
        DirectGate_WLR_OnGlobal(pConn, pArgs[0].nUint, pArgs[1].pStr, pArgs[2].nUint);
        return 0;
    }

    if (nOpcode != DIRECTGATE_WLR_REGISTRY_REMOVE) return 0;

    for (uint32_t i = 0; i < pConn->nOutputs; i++)
    {
        if (pConn->outputs[i].nName != pArgs[0].nUint) continue;

        pConn->outputs[i].bGone = XTRUE;
        if (!pConn->bInput) pConn->bOutputLost = XTRUE;
    }

    return 0;
}

static int DirectGate_WLR_OnCallback(const void *pImpl, void *pTarget, uint32_t nOpcode,
                                     const directgate_wlr_msg_t *pMsg, directgate_wlr_arg_t *pArgs)
{
    (void)pImpl; (void)nOpcode; (void)pMsg; (void)pArgs;
    xbool_t *pDone = (xbool_t*)g_wlr.proxyData((struct wl_proxy*)pTarget);
    if (pDone != NULL) *pDone = XTRUE;
    return 0;
}

/* Reads whatever the compositor sent, waiting at most @p nTimeoutMs for it
 * (-1 waits for ever, 0 not at all), and dispatches it. @p nWakeFd, when not
 * negative, also ends the wait. The prepare/read pair is libwayland's own
 * contract for reading on a connection without its blocking helpers. */
static int DirectGate_WLR_Pump(directgate_wlr_conn_t *pConn, int nTimeoutMs, int nWakeFd)
{
    struct wl_display *pDisplay = pConn->pDisplay;

    while (g_wlr.prepareRead(pDisplay) != 0)
    {
        if (g_wlr.dispatchPending(pDisplay) < 0)
            return XSTDERR;
    }

    short nEvents = POLLIN;
    if (g_wlr.flush(pDisplay) < 0)
    {
        if (errno != EAGAIN)
        {
            g_wlr.cancelRead(pDisplay);
            return XSTDERR;
        }

        /* Requests are still queued: wake as soon as they can go out too. */
        nEvents |= POLLOUT;
    }

    struct pollfd fds[2];
    fds[0].fd = g_wlr.getFd(pDisplay);
    fds[0].events = nEvents;
    fds[0].revents = 0;
    fds[1].fd = nWakeFd;
    fds[1].events = POLLIN;
    fds[1].revents = 0;

    int nReady = poll(fds, nWakeFd >= 0 ? 2 : 1, nTimeoutMs);
    if (nReady > 0 && (fds[0].revents & (POLLIN | POLLERR | POLLHUP)))
    {
        if (g_wlr.readEvents(pDisplay) < 0) return XSTDERR;
    }
    else
    {
        g_wlr.cancelRead(pDisplay);
        if (nReady < 0 && errno != EINTR) return XSTDERR;
    }

    return g_wlr.dispatchPending(pDisplay) < 0 ? XSTDERR : XSTDOK;
}

/* wl_display_roundtrip(), except that it gives up. The library's own waits
 * for ever, and a compositor that stopped answering would then hold the
 * thread that has to be joined before a session can be torn down. */
static int DirectGate_WLR_Roundtrip(directgate_wlr_conn_t *pConn, uint32_t nTimeoutMs)
{
    directgate_wlr_arg_t args[1];
    memset(args, 0, sizeof(args));

    struct wl_proxy *pDisplay = (struct wl_proxy*)pConn->pDisplay;
    struct wl_proxy *pCallback = g_wlr.marshalCtor(pDisplay, DIRECTGATE_WLR_DISPLAY_SYNC, args, g_wlr.pCallback, g_wlr.proxyVersion(pDisplay));
    if (pCallback == NULL) return XSTDERR;

    xbool_t bDone = XFALSE;
    g_wlr.addDispatcher(pCallback, DirectGate_WLR_OnCallback, &bDone, &bDone);

    uint64_t nDeadline = XTime_GetMonoMs() + nTimeoutMs;
    int nStatus = XSTDOK;

    while (!bDone)
    {
        uint64_t nNow = XTime_GetMonoMs();
        if (nNow >= nDeadline || DirectGate_WLR_Pump(pConn, (int)(nDeadline - nNow), -1) != XSTDOK)
        {
            nStatus = XSTDERR;
            break;
        }
    }

    g_wlr.proxyDestroy(pCallback);
    return nStatus;
}

/* Why the connection failed, in words. A protocol error names the object and
 * code the compositor objected to, which is the whole diagnosis when it was
 * this agent's request that was refused. */
static void DirectGate_WLR_ConnError(directgate_wlr_conn_t *pConn, char *pBuf, size_t nSize)
{
    int nError = (pConn->pDisplay != NULL) ? g_wlr.getError(pConn->pDisplay) : 0;

    if (nError == EPROTO && g_wlr.protocolError != NULL)
    {
        const directgate_wlr_iface_t *pIface = NULL;
        uint32_t nId = 0;
        uint32_t nCode = g_wlr.protocolError(pConn->pDisplay, &pIface, &nId);

        DirectGate_WLR_SetError(pBuf, nSize, "the compositor refused a request: interface(%s), code(%u)",
            (pIface != NULL && pIface->pName != NULL) ? pIface->pName : "unknown", nCode);

        return;
    }

    if (!nError) DirectGate_WLR_SetError(pBuf, nSize, "the compositor did not answer in time");
    else DirectGate_WLR_SetError(pBuf, nSize, "the compositor closed the connection: %s", strerror(nError));
}

/* The compositor's socket. WAYLAND_DISPLAY when the agent has one; the agent
 * usually runs as a service that does not, so otherwise the sockets in the
 * runtime directory are tried in turn - the same probe that decided this is a
 * Wayland session in the first place. */
static int DirectGate_WLR_Connect(directgate_wlr_conn_t *pConn, char *pErrBuf, size_t nErrSize)
{
    const char *pEnv = getenv("WAYLAND_DISPLAY");
    if (xstrused(pEnv))
    {
        pConn->pDisplay = g_wlr.connect(NULL);
        xstrncpy(pConn->sDisplay, sizeof(pConn->sDisplay), pEnv);
    }
    else
    {
        const char *pRuntimeDir = getenv("XDG_RUNTIME_DIR");

        for (int i = 0; i < 4 && pConn->pDisplay == NULL && xstrused(pRuntimeDir); i++)
        {
            char sSocket[XPATH_MAX];
            snprintf(sSocket, sizeof(sSocket), "%s/wayland-%d", pRuntimeDir, i);
            if (access(sSocket, F_OK) != 0) continue;

            snprintf(pConn->sDisplay, sizeof(pConn->sDisplay), "wayland-%d", i);
            pConn->pDisplay = g_wlr.connect(pConn->sDisplay);
        }
    }

    if (pConn->pDisplay == NULL)
    {
        DirectGate_WLR_SetError(pErrBuf, nErrSize, "the Wayland compositor's socket could not be reached: display(%s)",
            pConn->sDisplay[0] ? pConn->sDisplay : "none found");

        return XSTDERR;
    }

    directgate_wlr_arg_t args[1];
    memset(args, 0, sizeof(args));

    struct wl_proxy *pDisplay = (struct wl_proxy*)pConn->pDisplay;
    pConn->pRegistry = g_wlr.marshalCtor(pDisplay, DIRECTGATE_WLR_DISPLAY_GET_REGISTRY, args, g_wlr.pRegistry, g_wlr.proxyVersion(pDisplay));
    if (pConn->pRegistry == NULL)
    {
        DirectGate_WLR_SetError(pErrBuf, nErrSize, "the compositor's registry could not be opened");
        return XSTDERR;
    }

    g_wlr.addDispatcher(pConn->pRegistry, DirectGate_WLR_OnRegistry, pConn, pConn);

    if (DirectGate_WLR_Roundtrip(pConn, DIRECTGATE_WLR_CALL_MS) != XSTDOK)
    {
        DirectGate_WLR_ConnError(pConn, pErrBuf, nErrSize);
        return XSTDERR;
    }

    return XSTDOK;
}

static void DirectGate_WLR_Destroy(struct wl_proxy **ppProxy)
{
    if (*ppProxy == NULL) return;
    g_wlr.proxyDestroy(*ppProxy);
    *ppProxy = NULL;
}

/* A request that carries no arguments. Given an empty array rather than NULL,
 * which libwayland would hand straight to memcpy. */
static void DirectGate_WLR_Request(struct wl_proxy *pProxy, uint32_t nOpcode)
{
    directgate_wlr_arg_t args[1];
    memset(args, 0, sizeof(args));
    g_wlr.marshal(pProxy, nOpcode, args);
}

/* Sends a destructor request and frees the proxy that made it. */
static void DirectGate_WLR_Release(struct wl_proxy **ppProxy, uint32_t nOpcode)
{
    if (*ppProxy == NULL) return;
    DirectGate_WLR_Request(*ppProxy, nOpcode);
    DirectGate_WLR_Destroy(ppProxy);
}

/* Everything is torn down by the disconnect on the compositor's side; the
 * proxies are freed here only so the client side does not leak them. */
static void DirectGate_WLR_Disconnect(directgate_wlr_conn_t *pConn)
{
    if (pConn->pDisplay == NULL) return;

    for (uint32_t i = 0; i < pConn->nOutputs; i++)
    {
        DirectGate_WLR_Destroy(&pConn->outputs[i].pXdgOutput);
        DirectGate_WLR_Destroy(&pConn->outputs[i].pOutput);
    }

    DirectGate_WLR_Destroy(&pConn->pShm);
    DirectGate_WLR_Destroy(&pConn->pScreencopy);
    DirectGate_WLR_Destroy(&pConn->pSeat);
    DirectGate_WLR_Destroy(&pConn->pPointerManager);
    DirectGate_WLR_Destroy(&pConn->pKeyboardManager);
    DirectGate_WLR_Destroy(&pConn->pXdgManager);
    DirectGate_WLR_Destroy(&pConn->pRegistry);

    g_wlr.flush(pConn->pDisplay);
    g_wlr.disconnect(pConn->pDisplay);
    pConn->pDisplay = NULL;
}

struct directgate_wlr_capture_ {
    directgate_wlr_conn_t conn;
    uint32_t nOutput;

    directgate_wl_frame_cb_t fnFrame;
    void *pUserCtx;

    /* The frame in flight and what the compositor said about it */
    struct wl_proxy *pFrame;
    uint32_t nFormat;
    uint32_t nWidth;
    uint32_t nHeight;
    uint32_t nStride;
    uint32_t nFlags;
    xbool_t bCopying;

    /* The buffer it is copied into, kept while the screen keeps its size */
    struct wl_proxy *pBuffer;
    uint8_t *pMap;
    size_t nMapSize;
    uint32_t nBufFormat;
    uint32_t nBufWidth;
    uint32_t nBufHeight;
    uint32_t nBufStride;
    uint8_t *pRow;                 /* one row, for turning a frame the right way up */

    /* An unchanged screen sends nothing at all once the first frame is out,
     * which is what keeps an idle desktop from costing a copy per refresh. */
    xbool_t bCopiedOnce;
    xbool_t bWantFull;
    uint32_t nFailures;
    uint64_t nRetryAtMs;

    xthread_t thread;
    xbool_t bThreadStarted;
    int nWakeFd;
    xvolatile_t nStop;
    xvolatile_t nRefresh;

    /* Published to the other threads */
    xsync_mutex_t lock;
    xbool_t bHaveFormat;
    uint32_t nPubWidth;
    uint32_t nPubHeight;
    xbool_t bLost;
    char sLost[256];
};

static void DirectGate_WLR_CaptureLose(directgate_wlr_capture_t *pCap, const char *pReason)
{
    XSync_Lock(&pCap->lock);

    if (!pCap->bLost)
    {
        pCap->bLost = XTRUE;
        xstrncpy(pCap->sLost, sizeof(pCap->sLost), pReason);
    }

    XSync_Unlock(&pCap->lock);
    XSYNC_ATOMIC_SET(&pCap->nStop, 1);
}

static void DirectGate_WLR_FreeBuffer(directgate_wlr_capture_t *pCap)
{
    DirectGate_WLR_Release(&pCap->pBuffer, DIRECTGATE_WLR_BUFFER_DESTROY);
    if (pCap->pMap != NULL) munmap(pCap->pMap, pCap->nMapSize);

    pCap->pMap = NULL;
    pCap->nMapSize = 0;
}

/* A shared-memory buffer the compositor copies the screen into, sized and
 * formatted exactly as it asked. Rebuilt only when that changes. */
static int DirectGate_WLR_EnsureBuffer(directgate_wlr_capture_t *pCap)
{
    if (pCap->pBuffer != NULL && pCap->nBufFormat == pCap->nFormat && pCap->nBufWidth == pCap->nWidth &&
        pCap->nBufHeight == pCap->nHeight && pCap->nBufStride == pCap->nStride) return XSTDOK;

    DirectGate_WLR_FreeBuffer(pCap);

    size_t nSize = (size_t)pCap->nStride * pCap->nHeight;
    uint8_t *pRow = (uint8_t*)realloc(pCap->pRow, (size_t)pCap->nWidth * 4U);
    if (pRow == NULL) return XSTDERR;
    pCap->pRow = pRow;

    int nFd = DirectGate_WLR_AnonFile(nSize);
    if (nFd < 0) return XSTDERR;

    void *pMap = mmap(NULL, nSize, PROT_READ | PROT_WRITE, MAP_SHARED, nFd, 0);
    if (pMap == MAP_FAILED)
    {
        close(nFd);
        return XSTDERR;
    }

    directgate_wlr_arg_t args[6];
    memset(args, 0, sizeof(args));
    args[1].nFd = nFd;
    args[2].nInt = (int32_t)nSize;

    struct wl_proxy *pPool = g_wlr.marshalCtor(pCap->conn.pShm, DIRECTGATE_WLR_SHM_CREATE_POOL, args, g_wlr.pShmPool, 1U);
    close(nFd);

    if (pPool == NULL)
    {
        munmap(pMap, nSize);
        return XSTDERR;
    }

    memset(args, 0, sizeof(args));
    args[2].nInt = (int32_t)pCap->nWidth;
    args[3].nInt = (int32_t)pCap->nHeight;
    args[4].nInt = (int32_t)pCap->nStride;
    args[5].nUint = pCap->nFormat;

    pCap->pBuffer = g_wlr.marshalCtor(pPool, DIRECTGATE_WLR_POOL_CREATE_BUFFER, args, g_wlr.pBuffer, 1U);
    DirectGate_WLR_Release(&pPool, DIRECTGATE_WLR_POOL_DESTROY);

    if (pCap->pBuffer == NULL)
    {
        munmap(pMap, nSize);
        return XSTDERR;
    }

    pCap->pMap = (uint8_t*)pMap;
    pCap->nMapSize = nSize;
    pCap->nBufFormat = pCap->nFormat;
    pCap->nBufWidth = pCap->nWidth;
    pCap->nBufHeight = pCap->nHeight;
    pCap->nBufStride = pCap->nStride;

    return XSTDOK;
}

static xbool_t DirectGate_WLR_FormatSupported(uint32_t nFormat)
{
    return (nFormat == DIRECTGATE_WLR_SHM_ARGB8888 || nFormat == DIRECTGATE_WLR_SHM_XRGB8888 ||
            nFormat == DIRECTGATE_WLR_SHM_ABGR8888 || nFormat == DIRECTGATE_WLR_SHM_XBGR8888) ? XTRUE : XFALSE;
}

/* The compositor has described the buffer; checks it and asks for the copy. */
static void DirectGate_WLR_StartCopy(directgate_wlr_capture_t *pCap)
{
    if (pCap->pFrame == NULL || pCap->bCopying) return;

    /* Every number here came from the compositor and decides an allocation,
     * so each is bounded before it is multiplied. */
    if (!DirectGate_WLR_FormatSupported(pCap->nFormat) || !pCap->nWidth || !pCap->nHeight ||
        pCap->nWidth > DIRECTGATE_WLR_MAX_DIM || pCap->nHeight > DIRECTGATE_WLR_MAX_DIM ||
        pCap->nStride < pCap->nWidth * 4U || (uint64_t)pCap->nStride * pCap->nHeight > DIRECTGATE_WLR_MAX_BYTES)
    {
        char sReason[256];
        snprintf(sReason, sizeof(sReason), "The compositor offered a screen buffer this agent cannot read: "
            "format(0x%08X), size(%ux%u), stride(%u)", pCap->nFormat, pCap->nWidth, pCap->nHeight, pCap->nStride);

        DirectGate_WLR_CaptureLose(pCap, sReason);
        return;
    }

    if (DirectGate_WLR_EnsureBuffer(pCap) != XSTDOK)
    {
        DirectGate_WLR_CaptureLose(pCap, "Out of memory for the screen buffer.");
        return;
    }

    XSync_Lock(&pCap->lock);
    pCap->bHaveFormat = XTRUE;
    pCap->nPubWidth = pCap->nWidth;
    pCap->nPubHeight = pCap->nHeight;
    XSync_Unlock(&pCap->lock);

    xbool_t bDamage = (pCap->bCopiedOnce && !pCap->bWantFull && pCap->conn.nScreencopyVersion >= 2U) ? XTRUE : XFALSE;

    directgate_wlr_arg_t args[1];
    args[0].pObject = pCap->pBuffer;

    g_wlr.marshal(pCap->pFrame, bDamage ? DIRECTGATE_WLR_FRAME_COPY_DAMAGE : DIRECTGATE_WLR_FRAME_COPY, args);
    pCap->bWantFull = XFALSE;
    pCap->bCopying = XTRUE;
}

/* Turns the copied frame into what every other source produces - BGRA rows,
 * top row first - in place, since the buffer is this thread's until the next
 * copy, and hands it on. */
static void DirectGate_WLR_Deliver(directgate_wlr_capture_t *pCap)
{
    uint32_t nWidth = pCap->nBufWidth;
    uint32_t nHeight = pCap->nBufHeight;
    size_t nStride = pCap->nBufStride;
    size_t nRowBytes = (size_t)nWidth * 4U;

    if (pCap->nBufFormat == DIRECTGATE_WLR_SHM_ABGR8888 || pCap->nBufFormat == DIRECTGATE_WLR_SHM_XBGR8888)
    {
        for (uint32_t y = 0; y < nHeight; y++)
        {
            uint8_t *pPixel = pCap->pMap + (size_t)y * nStride;

            for (uint32_t x = 0; x < nWidth; x++, pPixel += 4)
            {
                uint8_t nRed = pPixel[0];
                pPixel[0] = pPixel[2];
                pPixel[2] = nRed;
            }
        }
    }

    if (pCap->nFlags & DIRECTGATE_WLR_FRAME_Y_INVERT)
    {
        for (uint32_t y = 0; y < nHeight / 2U; y++)
        {
            uint8_t *pTop = pCap->pMap + (size_t)y * nStride;
            uint8_t *pBottom = pCap->pMap + (size_t)(nHeight - 1U - y) * nStride;

            memcpy(pCap->pRow, pTop, nRowBytes);
            memcpy(pTop, pBottom, nRowBytes);
            memcpy(pBottom, pCap->pRow, nRowBytes);
        }
    }

    directgate_wl_frame_t frame;
    memset(&frame, 0, sizeof(frame));

    frame.eKind = DIRECTGATE_WL_FRAME_MAPPED;
    frame.nWidth = nWidth;
    frame.nHeight = nHeight;
    frame.pPixels = pCap->pMap;
    frame.nStride = (uint32_t)nStride;

    if (pCap->fnFrame != NULL) pCap->fnFrame(pCap->pUserCtx, &frame);
}

static void DirectGate_WLR_EndFrame(directgate_wlr_capture_t *pCap)
{
    DirectGate_WLR_Release(&pCap->pFrame, DIRECTGATE_WLR_FRAME_DESTROY);
    pCap->bCopying = XFALSE;
    pCap->nFlags = 0;
}

static int DirectGate_WLR_OnFrame(const void *pImpl, void *pTarget, uint32_t nOpcode,
                                  const directgate_wlr_msg_t *pMsg, directgate_wlr_arg_t *pArgs)
{
    (void)pImpl; (void)pMsg;
    directgate_wlr_capture_t *pCap = (directgate_wlr_capture_t*)g_wlr.proxyData((struct wl_proxy*)pTarget);
    if (pCap == NULL || pTarget != (void*)pCap->pFrame) return 0;

    switch (nOpcode)
    {
        case DIRECTGATE_WLR_FRAME_BUFFER:
            pCap->nFormat = pArgs[0].nUint;
            pCap->nWidth = pArgs[1].nUint;
            pCap->nHeight = pArgs[2].nUint;
            pCap->nStride = pArgs[3].nUint;

            /* Before version 3 nothing else is coming; from it, buffer_done says so */
            if (pCap->conn.nScreencopyVersion < 3U) DirectGate_WLR_StartCopy(pCap);
            break;
        case DIRECTGATE_WLR_FRAME_BUFFER_DONE:
            DirectGate_WLR_StartCopy(pCap);
            break;
        case DIRECTGATE_WLR_FRAME_FLAGS:
            pCap->nFlags = pArgs[0].nUint;
            break;
        case DIRECTGATE_WLR_FRAME_READY:
            if (pCap->nFailures)
                xlogi("Wayland compositor screen copy recovered: output(%u), failures(%u)", pCap->nOutput, pCap->nFailures);

            pCap->nFailures = 0;
            pCap->bCopiedOnce = XTRUE;
            DirectGate_WLR_Deliver(pCap);
            DirectGate_WLR_EndFrame(pCap);
            break;
        case DIRECTGATE_WLR_FRAME_FAILED:
            /* A screen that is switched off or being reconfigured refuses to
             * be copied for a while, then comes back. Not a lost session: the
             * copy is retried, backing off to once a second. */
            if (!pCap->nFailures)
                xlogw("Wayland compositor refused to copy the screen, retrying: output(%u)", pCap->nOutput);

            pCap->nFailures++;
            pCap->bWantFull = XTRUE;
            pCap->nRetryAtMs = XTime_GetMonoMs() + XSTD_MIN(DIRECTGATE_WLR_RETRY_MAX_MS, 50U * pCap->nFailures);
            DirectGate_WLR_EndFrame(pCap);
            break;
        default:
            break;
    }

    return 0;
}

static void DirectGate_WLR_RequestFrame(directgate_wlr_capture_t *pCap)
{
    directgate_wlr_arg_t args[3];
    memset(args, 0, sizeof(args));
    args[1].nInt = 0;   /* the viewer's own pointer is the cursor; the host's stays out */
    args[2].pObject = pCap->conn.outputs[0].pOutput;

    pCap->pFrame = g_wlr.marshalCtor(pCap->conn.pScreencopy, DIRECTGATE_WLR_COPY_CAPTURE_OUTPUT, args,
        &g_wlrFrameIface, g_wlr.proxyVersion(pCap->conn.pScreencopy));

    if (pCap->pFrame == NULL)
    {
        DirectGate_WLR_CaptureLose(pCap, "Out of memory requesting a screen copy.");
        return;
    }

    g_wlr.addDispatcher(pCap->pFrame, DirectGate_WLR_OnFrame, pCap, pCap);
}

static void* DirectGate_WLR_CaptureThread(void *pCtx)
{
    directgate_wlr_capture_t *pCap = (directgate_wlr_capture_t*)pCtx;

    while (!XSYNC_ATOMIC_GET(&pCap->nStop))
    {
        /* A viewer arriving at this screen needs a picture now, not at the
         * next change: a copy still waiting for damage is dropped and asked
         * for again without the wait. */
        if (XSYNC_ATOMIC_GET(&pCap->nRefresh))
        {
            XSYNC_ATOMIC_SET(&pCap->nRefresh, 0);
            pCap->bWantFull = XTRUE;
            if (pCap->bCopying) DirectGate_WLR_EndFrame(pCap);
        }

        uint64_t nNow = XTime_GetMonoMs();
        int nTimeout = -1;

        if (pCap->pFrame == NULL)
        {
            if (nNow >= pCap->nRetryAtMs) DirectGate_WLR_RequestFrame(pCap);
            else nTimeout = (int)(pCap->nRetryAtMs - nNow);
        }

        if (XSYNC_ATOMIC_GET(&pCap->nStop)) break;

        if (DirectGate_WLR_Pump(&pCap->conn, nTimeout, pCap->nWakeFd) != XSTDOK)
        {
            char sReason[192], sLost[256];
            DirectGate_WLR_ConnError(&pCap->conn, sReason, sizeof(sReason));
            snprintf(sLost, sizeof(sLost), "Screen sharing stopped: %s.", sReason);

            DirectGate_WLR_CaptureLose(pCap, sLost);
            break;
        }

        uint64_t nTicks = 0;
        while (read(pCap->nWakeFd, &nTicks, sizeof(nTicks)) > 0) { /* drain */ }

        if (pCap->conn.bOutputLost)
        {
            DirectGate_WLR_CaptureLose(pCap, "The shared screen was disconnected on the remote computer.");
            break;
        }
    }

    return NULL;
}

directgate_wlr_capture_t* DirectGate_WLR_CaptureStart(uint32_t nOutput,
                                                      directgate_wl_frame_cb_t fnFrame,
                                                      void *pUserCtx,
                                                      char *pErrBuf,
                                                      size_t nErrSize)
{
    if (DirectGate_WLR_Load(pErrBuf, nErrSize) != XSTDOK) return NULL;

    directgate_wlr_capture_t *pCap = (directgate_wlr_capture_t*)calloc(1, sizeof(*pCap));
    if (pCap == NULL)
    {
        DirectGate_WLR_SetError(pErrBuf, nErrSize, "Out of memory starting the screen copy.");
        return NULL;
    }

    pCap->nOutput = nOutput;
    pCap->fnFrame = fnFrame;
    pCap->pUserCtx = pUserCtx;
    pCap->conn.nWantOutput = nOutput;
    pCap->nWakeFd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);

    if (pCap->nWakeFd < 0 || XSync_InitAdv(&pCap->lock, XFALSE) < 0)
    {
        if (pCap->nWakeFd >= 0) close(pCap->nWakeFd);
        free(pCap);

        DirectGate_WLR_SetError(pErrBuf, nErrSize, "Failed to prepare the screen copy thread.");
        return NULL;
    }

    char sReason[256] = { 0 };
    xbool_t bOk = XFALSE;

    do
    {
        if (DirectGate_WLR_Connect(&pCap->conn, sReason, sizeof(sReason)) != XSTDOK) break;

        if (pCap->conn.pScreencopy == NULL || pCap->conn.pShm == NULL)
        {
            xstrncpy(sReason, sizeof(sReason), "the compositor offers no screen copy protocol");
            break;
        }

        if (!pCap->conn.nOutputs || pCap->conn.outputs[0].pOutput == NULL)
        {
            snprintf(sReason, sizeof(sReason), "screen %u is not connected", nOutput);
            break;
        }

        /* Handed to the thread from here on; nothing else touches it. */
        if (XThread_Create(&pCap->thread, DirectGate_WLR_CaptureThread, pCap, XFALSE) < 0)
        {
            xstrncpy(sReason, sizeof(sReason), "the screen copy thread could not be started");
            break;
        }

        pCap->bThreadStarted = XTRUE;
        bOk = XTRUE;
    }
    while (0);

    if (!bOk)
    {
        DirectGate_WLR_SetError(pErrBuf, nErrSize, "The screen could not be copied: %s.", sReason);
        DirectGate_WLR_CaptureStop(pCap);
        return NULL;
    }

    return pCap;
}

int DirectGate_WLR_CaptureWaitFormat(directgate_wlr_capture_t *pCapture, uint32_t nTimeoutMs)
{
    XCHECK_NL((pCapture != NULL), XSTDERR);
    uint64_t nDeadline = XTime_GetMonoMs() + nTimeoutMs;

    for (;;)
    {
        XSync_Lock(&pCapture->lock);
        xbool_t bFormat = pCapture->bHaveFormat;
        xbool_t bLost = pCapture->bLost;
        XSync_Unlock(&pCapture->lock);

        if (bFormat) return XSTDOK;
        if (bLost || XTime_GetMonoMs() >= nDeadline) return XSTDERR;

        xusleep(2000);
    }
}

xbool_t DirectGate_WLR_CaptureSize(directgate_wlr_capture_t *pCapture, uint32_t *pWidth, uint32_t *pHeight)
{
    XCHECK_NL((pCapture != NULL), XFALSE);

    XSync_Lock(&pCapture->lock);
    xbool_t bHave = pCapture->bHaveFormat;
    if (bHave && pWidth != NULL) *pWidth = pCapture->nPubWidth;
    if (bHave && pHeight != NULL) *pHeight = pCapture->nPubHeight;
    XSync_Unlock(&pCapture->lock);

    return bHave;
}

xbool_t DirectGate_WLR_CaptureLost(directgate_wlr_capture_t *pCapture, char *pErrBuf, size_t nErrSize)
{
    XCHECK_NL((pCapture != NULL), XFALSE);

    XSync_Lock(&pCapture->lock);
    xbool_t bLost = pCapture->bLost;
    if (bLost && pErrBuf != NULL && nErrSize) xstrncpy(pErrBuf, nErrSize, pCapture->sLost);
    XSync_Unlock(&pCapture->lock);

    return bLost;
}

void DirectGate_WLR_CaptureRefresh(directgate_wlr_capture_t *pCapture)
{
    XCHECK_VOID_NL((pCapture != NULL));
    XSYNC_ATOMIC_SET(&pCapture->nRefresh, 1);

    uint64_t nTick = 1;
    ssize_t nWritten = write(pCapture->nWakeFd, &nTick, sizeof(nTick));
    (void)nWritten;
}

void DirectGate_WLR_CaptureHalt(directgate_wlr_capture_t *pCapture)
{
    XCHECK_VOID_NL((pCapture != NULL));
    if (!pCapture->bThreadStarted) return;

    XSYNC_ATOMIC_SET(&pCapture->nStop, 1);

    uint64_t nTick = 1;
    ssize_t nWritten = write(pCapture->nWakeFd, &nTick, sizeof(nTick));
    (void)nWritten;

    XThread_Join(&pCapture->thread);
    pCapture->bThreadStarted = XFALSE;
}

void DirectGate_WLR_CaptureStop(directgate_wlr_capture_t *pCapture)
{
    XCHECK_VOID_NL((pCapture != NULL));
    DirectGate_WLR_CaptureHalt(pCapture);

    if (pCapture->conn.pDisplay != NULL)
    {
        DirectGate_WLR_Destroy(&pCapture->pFrame);
        DirectGate_WLR_Destroy(&pCapture->pBuffer);
    }

    if (pCapture->pMap != NULL) munmap(pCapture->pMap, pCapture->nMapSize);
    DirectGate_WLR_Disconnect(&pCapture->conn);

    XSync_Destroy(&pCapture->lock);
    if (pCapture->nWakeFd >= 0) close(pCapture->nWakeFd);

    free(pCapture->pRow);
    free(pCapture);
}

/* A key the virtual keyboard's keymap lends to a character the host layout
 * does not have. */
typedef struct directgate_wlr_slot_ {
    uint32_t nKeycode;      /* xkb keycode, evdev + 8 */
    size_t nOffset;         /* where its line starts in the base keymap text */
    size_t nLength;         /* the line it replaces there; 0 when it is added */
    char sKey[32];          /* its key name, without the brackets */
    uint32_t nSym;          /* the keysym it types now, 0 while free */
    char sSym[64];          /* that keysym as the keymap spells it */
    uint64_t nUsed;
} directgate_wlr_slot_t;

typedef struct directgate_wlr_held_ {
    uint32_t nSym;
    uint32_t nEvdev;
} directgate_wlr_held_t;

struct directgate_wlr_input_ {
    directgate_wlr_conn_t conn;
    directgate_wl_stream_t streams[DIRECTGATE_WL_MAX_STREAMS];
    uint32_t nStreams;

    struct wl_proxy *pSharedPointer;   /* manager v1: one pointer for the whole layout */
    struct wl_proxy *pLastPointer;
    struct wl_proxy *pKeyboard;

    struct xkb_context *pContext;
    struct xkb_keymap *pKeymap;        /* the host layout; spare keys never change it */
    struct xkb_state *pState;
    char *pBaseText;                   /* that keymap as text, which the uploads are built from */
    size_t nBaseLength;
    const char *pLayoutSource;

    directgate_wlr_slot_t slots[DIRECTGATE_WLR_SCRATCH_MAX];
    uint32_t nSlots;
    uint64_t nUseClock;
    directgate_wlr_held_t held[DIRECTGATE_WLR_HELD_MAX];
    uint32_t nHeld;

    uint32_t nModsDepressed;
    uint32_t nModsLatched;
    uint32_t nModsLocked;
    uint32_t nGroup;
    xbool_t bModsSent;

    xbool_t bKeysymRefused;
    xbool_t bBroken;
    xbool_t bWarnedLayout;

    /* From /etc/default/keyboard, when the layout comes from there */
    char sModel[64];
    char sLayout[64];
    char sVariant[64];
    char sOptions[128];
};

/* Sends whatever was queued and reads anything the compositor sent back,
 * without waiting. Input is fire-and-forget, so this is where a refusal shows
 * up: a protocol error ends the connection, and saying so once beats every
 * later keystroke vanishing in silence. */
static int DirectGate_WLR_InputFlush(directgate_wlr_input_t *pInput)
{
    if (pInput->bBroken) return XSTDERR;

    if (DirectGate_WLR_Pump(&pInput->conn, 0, -1) == XSTDOK &&
        !g_wlr.getError(pInput->conn.pDisplay)) return XSTDOK;

    char sReason[192];
    DirectGate_WLR_ConnError(&pInput->conn, sReason, sizeof(sReason));
    xloge("Wayland compositor input stopped working: reason(%s)", sReason);

    pInput->bBroken = XTRUE;
    return XSTDERR;
}

static int DirectGate_WLR_OnSeatKeyboard(const void *pImpl, void *pTarget, uint32_t nOpcode,
                                         const directgate_wlr_msg_t *pMsg, directgate_wlr_arg_t *pArgs)
{
    (void)pImpl; (void)pMsg;
    char **ppText = (char**)g_wlr.proxyData((struct wl_proxy*)pTarget);
    if (ppText == NULL || nOpcode != DIRECTGATE_WLR_KEYBOARD_KEYMAP) return 0;

    int nFd = pArgs[1].nFd;
    uint32_t nSize = pArgs[2].nUint;

    if (pArgs[0].nUint == DIRECTGATE_WLR_KEYMAP_XKB_V1 && nSize > 0 && nSize < DIRECTGATE_WLR_MAX_KEYMAP && *ppText == NULL)
    {
        void *pMap = mmap(NULL, nSize, PROT_READ, MAP_PRIVATE, nFd, 0);
        if (pMap != MAP_FAILED)
        {
            char *pText = (char*)malloc((size_t)nSize + 1U);
            if (pText != NULL)
            {
                memcpy(pText, pMap, nSize);
                pText[nSize] = '\0';
                *ppText = pText;
            }

            munmap(pMap, nSize);
        }
    }

    if (nFd >= 0) close(nFd);
    return 0;
}

/* The keymap of the keyboard the person at the machine is using, so a key
 * pressed by position types what it types for them. None on a machine with no
 * keyboard attached, which is not unusual for one reached remotely. */
static char* DirectGate_WLR_SeatKeymap(directgate_wlr_input_t *pInput)
{
    directgate_wlr_conn_t *pConn = &pInput->conn;
    if (pConn->pSeat == NULL || !(pConn->nSeatCaps & DIRECTGATE_WLR_SEAT_KEYBOARD)) return NULL;

    directgate_wlr_arg_t args[1];
    memset(args, 0, sizeof(args));

    struct wl_proxy *pKeyboard = g_wlr.marshalCtor(pConn->pSeat, DIRECTGATE_WLR_SEAT_GET_KEYBOARD, args,
        g_wlr.pKeyboard, pConn->nSeatVersion);

    if (pKeyboard == NULL) return NULL;

    char *pText = NULL;
    g_wlr.addDispatcher(pKeyboard, DirectGate_WLR_OnSeatKeyboard, &pText, &pText);
    DirectGate_WLR_Roundtrip(pConn, DIRECTGATE_WLR_CALL_MS);

    if (pConn->nSeatVersion >= 3U) DirectGate_WLR_Release(&pKeyboard, DIRECTGATE_WLR_KEYBOARD_RELEASE);
    else DirectGate_WLR_Destroy(&pKeyboard);

    return pText;
}

/* Debian's keyboard configuration, which Raspberry Pi OS keeps current from
 * its own settings. Read only when XKB_DEFAULT_LAYOUT is not set, because
 * xkbcommon reads the XKB_DEFAULT_* variables itself. */
static void DirectGate_WLR_SystemLayout(directgate_wlr_input_t *pInput, directgate_xkb_names_t *pNames)
{
    memset(pNames, 0, sizeof(*pNames));
    if (xstrused(getenv("XKB_DEFAULT_LAYOUT"))) return;

    FILE *pFile = fopen("/etc/default/keyboard", "r");
    if (pFile == NULL) return;

    char sLine[256];
    while (fgets(sLine, sizeof(sLine), pFile) != NULL)
    {
        char *pValue = strchr(sLine, '=');
        if (pValue == NULL) continue;
        *pValue++ = '\0';

        size_t nLength = strlen(pValue);
        while (nLength > 0 && (pValue[nLength - 1] == '\n' || pValue[nLength - 1] == '\r' ||
               pValue[nLength - 1] == '"' || pValue[nLength - 1] == '\'')) pValue[--nLength] = '\0';
        while (*pValue == '"' || *pValue == '\'') pValue++;

        if (xstrcmp(sLine, "XKBMODEL")) xstrncpy(pInput->sModel, sizeof(pInput->sModel), pValue);
        else if (xstrcmp(sLine, "XKBLAYOUT")) xstrncpy(pInput->sLayout, sizeof(pInput->sLayout), pValue);
        else if (xstrcmp(sLine, "XKBVARIANT")) xstrncpy(pInput->sVariant, sizeof(pInput->sVariant), pValue);
        else if (xstrcmp(sLine, "XKBOPTIONS")) xstrncpy(pInput->sOptions, sizeof(pInput->sOptions), pValue);
    }

    fclose(pFile);

    if (!pInput->sLayout[0]) return;
    pNames->pModel = pInput->sModel[0] ? pInput->sModel : NULL;
    pNames->pLayout = pInput->sLayout;
    pNames->pVariant = pInput->sVariant[0] ? pInput->sVariant : NULL;
    pNames->pOptions = pInput->sOptions[0] ? pInput->sOptions : NULL;
}

/* Finds @p pNeedle within [pStart, pEnd); no memmem() without _GNU_SOURCE. */
static const char* DirectGate_WLR_Find(const char *pStart, const char *pEnd, const char *pNeedle)
{
    size_t nNeedle = strlen(pNeedle);

    for (const char *p = pStart; p + nNeedle <= pEnd; p++)
    {
        if (*p == *pNeedle && !memcmp(p, pNeedle, nNeedle)) return p;
    }

    return NULL;
}

/* The upload: the base keymap with every spare key that holds a character
 * rewritten to type it. Malloc'd, NUL-terminated, length in @p pLength. */
static char* DirectGate_WLR_BuildKeymap(const directgate_wlr_input_t *pInput, size_t *pLength)
{
    size_t nCapacity = pInput->nBaseLength + (size_t)pInput->nSlots * 128U + 1U;
    char *pText = (char*)malloc(nCapacity);
    if (pText == NULL) return NULL;

    size_t nCursor = 0, nUsed = 0;

    for (uint32_t i = 0; i < pInput->nSlots; i++)
    {
        const directgate_wlr_slot_t *pSlot = &pInput->slots[i];

        memcpy(pText + nUsed, pInput->pBaseText + nCursor, pSlot->nOffset - nCursor);
        nUsed += pSlot->nOffset - nCursor;

        if (pSlot->nSym)
        {
            int nLine = snprintf(pText + nUsed, nCapacity - nUsed, "\tkey <%s> {\t[ %s ] };\n", pSlot->sKey, pSlot->sSym);
            if (nLine > 0) nUsed += (size_t)nLine;
        }
        else if (pSlot->nLength)
        {
            memcpy(pText + nUsed, pInput->pBaseText + pSlot->nOffset, pSlot->nLength);
            nUsed += pSlot->nLength;
        }

        nCursor = pSlot->nOffset + pSlot->nLength;
    }

    memcpy(pText + nUsed, pInput->pBaseText + nCursor, pInput->nBaseLength - nCursor);
    nUsed += pInput->nBaseLength - nCursor;
    pText[nUsed] = '\0';

    *pLength = nUsed;
    return pText;
}

static void DirectGate_WLR_SendModifiers(directgate_wlr_input_t *pInput)
{
    uint32_t nDepressed = g_xkb.serializeMods(pInput->pState, DIRECTGATE_XKB_MODS_DEPRESSED);
    uint32_t nLatched = g_xkb.serializeMods(pInput->pState, DIRECTGATE_XKB_MODS_LATCHED);
    uint32_t nLocked = g_xkb.serializeMods(pInput->pState, DIRECTGATE_XKB_MODS_LOCKED);
    uint32_t nGroup = g_xkb.serializeLayout(pInput->pState, DIRECTGATE_XKB_LAYOUT_EFFECTIVE);

    if (pInput->bModsSent && nDepressed == pInput->nModsDepressed && nLatched == pInput->nModsLatched &&
        nLocked == pInput->nModsLocked && nGroup == pInput->nGroup) return;

    directgate_wlr_arg_t args[4];
    args[0].nUint = nDepressed;
    args[1].nUint = nLatched;
    args[2].nUint = nLocked;
    args[3].nUint = nGroup;

    g_wlr.marshal(pInput->pKeyboard, DIRECTGATE_WLR_VK_MODIFIERS, args);

    pInput->nModsDepressed = nDepressed;
    pInput->nModsLatched = nLatched;
    pInput->nModsLocked = nLocked;
    pInput->nGroup = nGroup;
    pInput->bModsSent = XTRUE;
}

/* Hands the compositor the keyboard's keymap. wlroots builds a fresh state
 * for it, so the modifiers held right now are sent again after it. */
static int DirectGate_WLR_UploadKeymap(directgate_wlr_input_t *pInput)
{
    size_t nLength = 0;
    char *pText = DirectGate_WLR_BuildKeymap(pInput, &nLength);
    if (pText == NULL) return XSTDERR;

    /* The terminating NUL goes too: the compositor maps exactly this many
     * bytes and reads them as a C string. */
    int nFd = DirectGate_WLR_AnonFile(nLength + 1U);
    xbool_t bWritten = XFALSE;

    if (nFd >= 0)
    {
        size_t nDone = 0;
        while (nDone < nLength + 1U)
        {
            ssize_t nWrote = pwrite(nFd, pText + nDone, nLength + 1U - nDone, (off_t)nDone);
            if (nWrote <= 0 && errno != EINTR) break;
            if (nWrote > 0) nDone += (size_t)nWrote;
        }

        bWritten = (nDone == nLength + 1U) ? XTRUE : XFALSE;
    }

    free(pText);

    if (!bWritten)
    {
        if (nFd >= 0) close(nFd);
        return XSTDERR;
    }

    directgate_wlr_arg_t args[3];
    args[0].nUint = DIRECTGATE_WLR_KEYMAP_XKB_V1;
    args[1].nFd = nFd;
    args[2].nUint = (uint32_t)(nLength + 1U);

    /* libwayland duplicates the descriptor as it queues the request */
    g_wlr.marshal(pInput->pKeyboard, DIRECTGATE_WLR_VK_KEYMAP, args);
    close(nFd);

    pInput->bModsSent = XFALSE;
    DirectGate_WLR_SendModifiers(pInput);

    return XSTDOK;
}

/* Whether the keymap text spells @p nSym in a way that compiles back to it.
 * Checked in a keymap of one key before it goes anywhere near the real one: a
 * keymap the compositor cannot compile is answered by ending the connection,
 * and with it every keystroke for the rest of the session. */
static xbool_t DirectGate_WLR_KeysymSpelling(directgate_wlr_input_t *pInput, uint32_t nSym, char *pBuf, size_t nSize)
{
    if (g_xkb.keysymName(nSym, pBuf, nSize) <= 0) return XFALSE;

    for (const char *p = pBuf; *p; p++)
    {
        if (!isalnum((unsigned char)*p) && *p != '_') return XFALSE;
    }

    char sText[512];
    snprintf(sText, sizeof(sText),
        "xkb_keymap {\n"
        "xkb_keycodes \"dg\" { minimum = 8; maximum = 255; <DGK> = 9; };\n"
        "xkb_types \"dg\" { type \"ONE_LEVEL\" { modifiers = none; level_name[Level1] = \"Any\"; }; };\n"
        "xkb_compatibility \"dg\" { };\n"
        "xkb_symbols \"dg\" { key <DGK> { [ %s ] }; };\n"
        "};\n", pBuf);

    struct xkb_keymap *pKeymap = g_xkb.keymapFromString(pInput->pContext, sText, DIRECTGATE_XKB_TEXT_V1, 0);
    if (pKeymap == NULL) return XFALSE;

    const uint32_t *pSyms = NULL;
    int nSyms = g_xkb.symsByLevel(pKeymap, 9U, 0U, 0U, &pSyms);
    xbool_t bOk = (nSyms == 1 && pSyms != NULL && pSyms[0] == nSym) ? XTRUE : XFALSE;

    g_xkb.keymapUnref(pKeymap);
    return bOk;
}

/* Whether the two keymaps type the same on @p nKeycode in every level of
 * every layout - used to prove the spare keys did not move anything else. */
static xbool_t DirectGate_WLR_SameKey(struct xkb_keymap *pA, struct xkb_keymap *pB, uint32_t nKeycode)
{
    uint32_t nLayouts = g_xkb.numLayouts(pA, nKeycode);
    if (nLayouts != g_xkb.numLayouts(pB, nKeycode)) return XFALSE;

    for (uint32_t nLayout = 0; nLayout < nLayouts; nLayout++)
    {
        uint32_t nLevels = g_xkb.numLevels(pA, nKeycode, nLayout);
        if (nLevels != g_xkb.numLevels(pB, nKeycode, nLayout)) return XFALSE;

        for (uint32_t nLevel = 0; nLevel < nLevels; nLevel++)
        {
            const uint32_t *pSymsA = NULL, *pSymsB = NULL;
            int nA = g_xkb.symsByLevel(pA, nKeycode, nLayout, nLevel, &pSymsA);
            int nB = g_xkb.symsByLevel(pB, nKeycode, nLayout, nLevel, &pSymsB);

            if (nA != nB) return XFALSE;
            if (nA > 0 && memcmp(pSymsA, pSymsB, (size_t)nA * sizeof(uint32_t))) return XFALSE;
        }
    }

    return XTRUE;
}

/* evdev codes the browser can never send by position (see input.c's table):
 * media and launcher keys, F13-F24 excepted. In this keyboard's own keymap
 * they are free to carry characters - the physical keyboard keeps a keymap of
 * its own - and a keysym that used to live on one gets a spare key like any
 * other character. */
static xbool_t DirectGate_WLR_SpareCode(uint32_t nEvdev)
{
    return ((nEvdev >= 128U && nEvdev <= 182U) || (nEvdev >= 195U && nEvdev <= 247U)) ? XTRUE : XFALSE;
}

static xbool_t DirectGate_WLR_IsSlot(const directgate_wlr_input_t *pInput, uint32_t nKeycode)
{
    for (uint32_t i = 0; i < pInput->nSlots; i++)
    {
        if (pInput->slots[i].nKeycode == nKeycode) return XTRUE;
    }

    return XFALSE;
}

/* Finds the keys the keymap can lend out, and proves it: the keymap is
 * rebuilt with every one of them holding a character of its own and compiled,
 * every one must then type its character, and every other key must type
 * exactly what it did before. Whatever fails that is not used - typing by
 * character is then refused, which costs other scripts, never the layout. */
static void DirectGate_WLR_ScratchInit(directgate_wlr_input_t *pInput)
{
    const char *pBase = pInput->pBaseText;
    const char *pSection = strstr(pBase, "\nxkb_symbols");
    if (pSection == NULL) return;

    const char *pSectionEnd = strstr(pSection + 1, "\n};");
    if (pSectionEnd == NULL) return;

    size_t nEndLine = (size_t)(pSectionEnd + 1 - pBase);
    uint32_t nMin = g_xkb.minKeycode(pInput->pKeymap);
    uint32_t nMax = g_xkb.maxKeycode(pInput->pKeymap);
    if (nMax > 255U) nMax = 255U;   /* X11 clients under XWayland cannot take more */

    for (uint32_t nKeycode = nMin < 9U ? 9U : nMin; nKeycode <= nMax && pInput->nSlots < DIRECTGATE_WLR_SCRATCH_MAX; nKeycode++)
    {
        const char *pName = g_xkb.keyName(pInput->pKeymap, nKeycode);
        if (pName == NULL || !pName[0] || strlen(pName) >= sizeof(pInput->slots[0].sKey)) continue;

        if (!DirectGate_WLR_SpareCode(nKeycode - 8U)) continue;
        uint32_t nLayouts = g_xkb.numLayouts(pInput->pKeymap, nKeycode);

        char sNeedle[48];
        snprintf(sNeedle, sizeof(sNeedle), "<%s>", pName);

        /* A key a modifier is bound to is left alone. */
        xbool_t bModifier = XFALSE;
        for (const char *p = DirectGate_WLR_Find(pSection, pSectionEnd, "\n\tmodifier_map"); p != NULL && !bModifier;
             p = DirectGate_WLR_Find(p + 1, pSectionEnd, "\n\tmodifier_map"))
        {
            const char *pLineEnd = strchr(p + 1, '\n');
            if (pLineEnd == NULL) pLineEnd = pSectionEnd;
            if (DirectGate_WLR_Find(p, pLineEnd, sNeedle) != NULL) bModifier = XTRUE;
        }

        if (bModifier) continue;

        directgate_wlr_slot_t slot;
        memset(&slot, 0, sizeof(slot));
        slot.nKeycode = nKeycode;
        xstrncpy(slot.sKey, sizeof(slot.sKey), pName);

        snprintf(sNeedle, sizeof(sNeedle), "\n\tkey <%s>", pName);
        const char *pLine = DirectGate_WLR_Find(pSection, pSectionEnd, sNeedle);

        if (pLine != NULL)
        {
            /* Only a definition on one line is replaced. Anything longer carries
             * types or actions of its own and is not worth reasoning about. */
            const char *pLineEnd = strchr(pLine + 1, '\n');
            if (pLineEnd == NULL || pLineEnd < pLine + 4 || memcmp(pLineEnd - 2, "};", 2)) continue;

            slot.nOffset = (size_t)(pLine + 1 - pBase);
            slot.nLength = (size_t)(pLineEnd - pLine);
        }
        else if (!nLayouts)
        {
            slot.nOffset = nEndLine;
            slot.nLength = 0;
        }
        else continue;

        /* Kept in text order: that is the order the upload is built in. */
        uint32_t nAt = pInput->nSlots;
        while (nAt > 0 && pInput->slots[nAt - 1].nOffset > slot.nOffset)
        {
            pInput->slots[nAt] = pInput->slots[nAt - 1];
            nAt--;
        }

        pInput->slots[nAt] = slot;
        pInput->nSlots++;
    }

    if (!pInput->nSlots) return;

    for (uint32_t i = 0; i < pInput->nSlots; i++)
    {
        pInput->slots[i].nSym = 0x0100E000U + i;   /* private use: no layout has these */
        snprintf(pInput->slots[i].sSym, sizeof(pInput->slots[i].sSym), "U%X", 0xE000U + i);
    }

    size_t nLength = 0;
    char *pText = DirectGate_WLR_BuildKeymap(pInput, &nLength);
    struct xkb_keymap *pTrial = pText != NULL ?
        g_xkb.keymapFromString(pInput->pContext, pText, DIRECTGATE_XKB_TEXT_V1, 0) : NULL;

    free(pText);
    xbool_t bProven = (pTrial != NULL) ? XTRUE : XFALSE;

    for (uint32_t nKeycode = nMin; bProven && nKeycode <= g_xkb.maxKeycode(pInput->pKeymap); nKeycode++)
    {
        if (DirectGate_WLR_IsSlot(pInput, nKeycode)) continue;
        if (!DirectGate_WLR_SameKey(pInput->pKeymap, pTrial, nKeycode)) bProven = XFALSE;
    }

    uint32_t nKept = 0;
    for (uint32_t i = 0; bProven && i < pInput->nSlots; i++)
    {
        const uint32_t *pSyms = NULL;
        int nSyms = g_xkb.symsByLevel(pTrial, pInput->slots[i].nKeycode, 0U, 0U, &pSyms);
        if (nSyms != 1 || pSyms == NULL || pSyms[0] != pInput->slots[i].nSym) continue;

        pInput->slots[nKept] = pInput->slots[i];
        pInput->slots[nKept].nSym = 0;
        pInput->slots[nKept].sSym[0] = '\0';
        nKept++;
    }

    if (pTrial != NULL) g_xkb.keymapUnref(pTrial);

    if (!bProven)
    {
        xlogw("Wayland keyboard cannot lend keys to other characters; only the host layout can be typed");
        nKept = 0;
    }

    pInput->nSlots = nKept;
}

static int DirectGate_WLR_KeyboardInit(directgate_wlr_input_t *pInput)
{
    char sReason[256] = { 0 };
    if (DirectGate_WLR_XkbLoad(sReason, sizeof(sReason)) != XSTDOK)
    {
        xlogw("Wayland keyboard input is unavailable: reason(%s)", sReason);
        return XSTDERR;
    }

    pInput->pContext = g_xkb.contextNew(0);
    if (pInput->pContext == NULL) return XSTDERR;

    char *pSeatText = DirectGate_WLR_SeatKeymap(pInput);
    if (pSeatText != NULL)
    {
        pInput->pKeymap = g_xkb.keymapFromString(pInput->pContext, pSeatText, DIRECTGATE_XKB_TEXT_V1, 0);
        pInput->pLayoutSource = "the attached keyboard";
        free(pSeatText);
    }

    if (pInput->pKeymap == NULL)
    {
        directgate_xkb_names_t names;
        DirectGate_WLR_SystemLayout(pInput, &names);

        pInput->pKeymap = g_xkb.keymapFromNames(pInput->pContext, &names, 0);
        pInput->pLayoutSource = names.pLayout != NULL ? "/etc/default/keyboard" : "the system default";
    }

    if (pInput->pKeymap == NULL)
    {
        xlogw("Wayland keyboard input is unavailable: no keyboard layout could be compiled");
        return XSTDERR;
    }

    pInput->pBaseText = g_xkb.keymapAsString(pInput->pKeymap, DIRECTGATE_XKB_TEXT_V1);
    pInput->pState = g_xkb.stateNew(pInput->pKeymap);
    if (pInput->pBaseText == NULL || pInput->pState == NULL) return XSTDERR;

    pInput->nBaseLength = strlen(pInput->pBaseText);
    DirectGate_WLR_ScratchInit(pInput);

    directgate_wlr_arg_t args[2];
    args[0].pObject = pInput->conn.pSeat;
    args[1].nNewId = 0;

    pInput->pKeyboard = g_wlr.marshalCtor(pInput->conn.pKeyboardManager, DIRECTGATE_WLR_VKM_CREATE, args, &g_wlrKeyboardIface, 1U);
    if (pInput->pKeyboard == NULL) return XSTDERR;

    /* A key pressed before there is a keymap is a protocol error. */
    if (DirectGate_WLR_UploadKeymap(pInput) != XSTDOK)
    {
        DirectGate_WLR_Release(&pInput->pKeyboard, DIRECTGATE_WLR_VK_DESTROY);
        return XSTDERR;
    }

    return XSTDOK;
}

directgate_wlr_input_t* DirectGate_WLR_InputOpen(char *pErrBuf, size_t nErrSize)
{
    if (DirectGate_WLR_Load(pErrBuf, nErrSize) != XSTDOK) return NULL;

    directgate_wlr_input_t *pInput = (directgate_wlr_input_t*)calloc(1, sizeof(*pInput));
    if (pInput == NULL)
    {
        DirectGate_WLR_SetError(pErrBuf, nErrSize, "Out of memory opening the compositor.");
        return NULL;
    }

    pInput->conn.bInput = XTRUE;
    char sReason[256] = { 0 };
    xbool_t bOk = XFALSE;

    do
    {
        if (DirectGate_WLR_Connect(&pInput->conn, sReason, sizeof(sReason)) != XSTDOK) break;

        if (!pInput->conn.nScreencopyVersion)
        {
            xstrncpy(sReason, sizeof(sReason), "this compositor offers no screen capture protocol (zwlr_screencopy_manager_v1)");
            break;
        }

        for (uint32_t i = 0; pInput->conn.pXdgManager != NULL && i < pInput->conn.nOutputs; i++)
        {
            directgate_wlr_output_t *pOut = &pInput->conn.outputs[i];
            directgate_wlr_arg_t args[2];
            args[0].nNewId = 0;
            args[1].pObject = pOut->pOutput;

            pOut->pXdgOutput = g_wlr.marshalCtor(pInput->conn.pXdgManager, DIRECTGATE_WLR_XDGM_GET_OUTPUT, args,
                &g_wlrXdgOutputIface, g_wlr.proxyVersion(pInput->conn.pXdgManager));

            if (pOut->pXdgOutput != NULL) g_wlr.addDispatcher(pOut->pXdgOutput, DirectGate_WLR_OnXdgOutput, pOut, pOut);
        }

        /* Screens, their names and positions, and what the seat can do */
        if (DirectGate_WLR_Roundtrip(&pInput->conn, DIRECTGATE_WLR_CALL_MS) != XSTDOK)
        {
            DirectGate_WLR_ConnError(&pInput->conn, sReason, sizeof(sReason));
            break;
        }

        for (uint32_t i = 0; i < pInput->conn.nOutputs; i++)
        {
            const directgate_wlr_output_t *pOut = &pInput->conn.outputs[i];
            if (pOut->nWidth <= 0 || pOut->nHeight <= 0) continue;

            directgate_wl_stream_t *pStream = &pInput->streams[pInput->nStreams++];
            pStream->nNodeId = pOut->nName;
            pStream->nWidth = (uint32_t)pOut->nWidth;
            pStream->nHeight = (uint32_t)pOut->nHeight;
            pStream->nX = pOut->nX;
            pStream->nY = pOut->nY;

            /* The copy is the panel's own buffer, so a rotated screen arrives
             * rotated. Said rather than corrected for now. */
            if (pOut->nTransform != 0)
            {
                xlogw("Wayland screen is rotated; it is shared as the panel scans it out: output(%s), transform(%d)",
                    pOut->sName[0] ? pOut->sName : "unnamed", pOut->nTransform);
            }
        }

        if (!pInput->nStreams)
        {
            xstrncpy(sReason, sizeof(sReason), "the compositor reported no active screen");
            break;
        }

        if (pInput->conn.pKeyboardManager != NULL && pInput->conn.pSeat != NULL)
            DirectGate_WLR_KeyboardInit(pInput);

        /* One more round trip so a request the compositor refused - the
         * keymap above all - fails here and not on the first keystroke. */
        if (DirectGate_WLR_Roundtrip(&pInput->conn, DIRECTGATE_WLR_CALL_MS) != XSTDOK || g_wlr.getError(pInput->conn.pDisplay))
        {
            DirectGate_WLR_ConnError(&pInput->conn, sReason, sizeof(sReason));
            break;
        }

        bOk = XTRUE;
    }
    while (0);

    if (!bOk)
    {
        DirectGate_WLR_SetError(pErrBuf, nErrSize, "%s.", sReason);
        DirectGate_WLR_InputClose(pInput);
        return NULL;
    }

    xlogi("Wayland compositor opened directly: display(%s), screens(%u), pointer(%s), keyboard(%s), "
        "layout(%s), spareKeys(%u)", pInput->conn.sDisplay, pInput->nStreams,
        pInput->conn.pPointerManager != NULL ? "yes" : "no", pInput->pKeyboard != NULL ? "yes" : "no",
        pInput->pLayoutSource != NULL ? pInput->pLayoutSource : "none", pInput->nSlots);

    return pInput;
}

uint32_t DirectGate_WLR_InputScreenCount(const directgate_wlr_input_t *pInput)
{
    return pInput != NULL ? pInput->nStreams : 0;
}

const directgate_wl_stream_t* DirectGate_WLR_InputScreen(const directgate_wlr_input_t *pInput, uint32_t nIndex)
{
    return (pInput != NULL && nIndex < pInput->nStreams) ? &pInput->streams[nIndex] : NULL;
}

xbool_t DirectGate_WLR_InputHasPointer(const directgate_wlr_input_t *pInput)
{
    return (pInput != NULL && pInput->conn.pPointerManager != NULL) ? XTRUE : XFALSE;
}

xbool_t DirectGate_WLR_InputHasKeyboard(const directgate_wlr_input_t *pInput)
{
    return (pInput != NULL && pInput->pKeyboard != NULL) ? XTRUE : XFALSE;
}

static directgate_wlr_output_t* DirectGate_WLR_FindOutput(directgate_wlr_input_t *pInput, uint32_t nOutput)
{
    directgate_wlr_output_t *pFirst = NULL;

    for (uint32_t i = 0; i < pInput->conn.nOutputs; i++)
    {
        directgate_wlr_output_t *pOut = &pInput->conn.outputs[i];
        if (pOut->bGone || pOut->nWidth <= 0 || pOut->nHeight <= 0) continue;

        if (pOut->nName == nOutput) return pOut;
        if (pFirst == NULL) pFirst = pOut;
    }

    return pFirst;
}

/* A virtual pointer for @p pOut. From version 2 each screen gets its own, and
 * the compositor maps it onto that screen, so an absolute position never has
 * to know where the screens sit in the layout. Before it there is one, mapped
 * across the whole layout - right for the single screen that version implies. */
static struct wl_proxy* DirectGate_WLR_Pointer(directgate_wlr_input_t *pInput, directgate_wlr_output_t *pOut)
{
    directgate_wlr_conn_t *pConn = &pInput->conn;
    if (pConn->pPointerManager == NULL) return NULL;

    struct wl_proxy **ppPointer = (pConn->nPointerVersion >= 2U && pOut != NULL) ? &pOut->pPointer : &pInput->pSharedPointer;
    if (*ppPointer != NULL) return *ppPointer;

    directgate_wlr_arg_t args[3];
    memset(args, 0, sizeof(args));

    if (ppPointer == &pInput->pSharedPointer)
    {
        args[0].pObject = pConn->pSeat;
        *ppPointer = g_wlr.marshalCtor(pConn->pPointerManager, DIRECTGATE_WLR_VPM_CREATE, args, &g_wlrPointerIface, pConn->nPointerVersion);
    }
    else
    {
        args[0].pObject = pConn->pSeat;
        args[1].pObject = pOut->pOutput;
        *ppPointer = g_wlr.marshalCtor(pConn->pPointerManager, DIRECTGATE_WLR_VPM_CREATE_WITH_OUTPUT, args, &g_wlrPointerIface, pConn->nPointerVersion);
    }

    return *ppPointer;
}

static struct wl_proxy* DirectGate_WLR_ActivePointer(directgate_wlr_input_t *pInput)
{
    if (pInput->pLastPointer != NULL) return pInput->pLastPointer;
    pInput->pLastPointer = DirectGate_WLR_Pointer(pInput, DirectGate_WLR_FindOutput(pInput, 0));
    return pInput->pLastPointer;
}

int DirectGate_WLR_PointerMotion(directgate_wlr_input_t *pInput, uint32_t nOutput, double nX, double nY)
{
    XCHECK_NL((pInput != NULL && !pInput->bBroken), XSTDERR);

    directgate_wlr_output_t *pOut = DirectGate_WLR_FindOutput(pInput, nOutput);
    if (pOut == NULL) return XSTDERR;

    struct wl_proxy *pPointer = DirectGate_WLR_Pointer(pInput, pOut);
    if (pPointer == NULL) return XSTDERR;

    double nMaxX = (double)(pOut->nWidth - 1), nMaxY = (double)(pOut->nHeight - 1);
    if (!(nX >= 0.0)) nX = 0.0;
    if (!(nY >= 0.0)) nY = 0.0;
    if (nX > nMaxX) nX = nMaxX;
    if (nY > nMaxY) nY = nMaxY;

    /* In eighths of a pixel: the protocol takes integers over an extent, and
     * a whole-pixel grid would round away the position the viewer asked for. */
    directgate_wlr_arg_t args[5];
    args[0].nUint = DirectGate_WLR_Now();
    args[1].nUint = (uint32_t)lrint(nX * 8.0);
    args[2].nUint = (uint32_t)lrint(nY * 8.0);
    args[3].nUint = (uint32_t)pOut->nWidth * 8U;
    args[4].nUint = (uint32_t)pOut->nHeight * 8U;

    g_wlr.marshal(pPointer, DIRECTGATE_WLR_VP_MOTION_ABSOLUTE, args);
    DirectGate_WLR_Request(pPointer, DIRECTGATE_WLR_VP_FRAME);
    pInput->pLastPointer = pPointer;

    return DirectGate_WLR_InputFlush(pInput);
}

int DirectGate_WLR_PointerMotionRelative(directgate_wlr_input_t *pInput, double nDx, double nDy)
{
    XCHECK_NL((pInput != NULL && !pInput->bBroken), XSTDERR);

    struct wl_proxy *pPointer = DirectGate_WLR_ActivePointer(pInput);
    if (pPointer == NULL) return XSTDERR;

    directgate_wlr_arg_t args[3];
    args[0].nUint = DirectGate_WLR_Now();
    args[1].nFixed = DirectGate_WLR_Fixed(nDx);
    args[2].nFixed = DirectGate_WLR_Fixed(nDy);

    g_wlr.marshal(pPointer, DIRECTGATE_WLR_VP_MOTION, args);
    DirectGate_WLR_Request(pPointer, DIRECTGATE_WLR_VP_FRAME);

    return DirectGate_WLR_InputFlush(pInput);
}

int DirectGate_WLR_PointerButton(directgate_wlr_input_t *pInput, int32_t nButton, xbool_t bPressed)
{
    XCHECK_NL((pInput != NULL && !pInput->bBroken && nButton > 0), XSTDERR);

    struct wl_proxy *pPointer = DirectGate_WLR_ActivePointer(pInput);
    if (pPointer == NULL) return XSTDERR;

    directgate_wlr_arg_t args[3];
    args[0].nUint = DirectGate_WLR_Now();
    args[1].nUint = (uint32_t)nButton;
    args[2].nUint = bPressed ? 1U : 0U;

    g_wlr.marshal(pPointer, DIRECTGATE_WLR_VP_BUTTON, args);
    DirectGate_WLR_Request(pPointer, DIRECTGATE_WLR_VP_FRAME);

    return DirectGate_WLR_InputFlush(pInput);
}

int DirectGate_WLR_PointerAxis(directgate_wlr_input_t *pInput, double nDx, double nDy)
{
    XCHECK_NL((pInput != NULL && !pInput->bBroken), XSTDERR);

    struct wl_proxy *pPointer = DirectGate_WLR_ActivePointer(pInput);
    if (pPointer == NULL) return XSTDERR;

    /* Continuous: the browser sends a distance, not wheel clicks, in the same
     * units the portal path forwards (about 10 per notch), and nothing about
     * it should start kinetic scrolling the way a finger source would. */
    directgate_wlr_arg_t args[3];
    args[0].nUint = DIRECTGATE_WLR_AXIS_CONTINUOUS;
    g_wlr.marshal(pPointer, DIRECTGATE_WLR_VP_AXIS_SOURCE, args);

    if (nDy != 0.0)
    {
        args[0].nUint = DirectGate_WLR_Now();
        args[1].nUint = DIRECTGATE_WLR_AXIS_VERTICAL;
        args[2].nFixed = DirectGate_WLR_Fixed(nDy);
        g_wlr.marshal(pPointer, DIRECTGATE_WLR_VP_AXIS, args);
    }

    if (nDx != 0.0)
    {
        args[0].nUint = DirectGate_WLR_Now();
        args[1].nUint = DIRECTGATE_WLR_AXIS_HORIZONTAL;
        args[2].nFixed = DirectGate_WLR_Fixed(nDx);
        g_wlr.marshal(pPointer, DIRECTGATE_WLR_VP_AXIS, args);
    }

    DirectGate_WLR_Request(pPointer, DIRECTGATE_WLR_VP_FRAME);
    return DirectGate_WLR_InputFlush(pInput);
}

int DirectGate_WLR_Keycode(directgate_wlr_input_t *pInput, int32_t nKeycode, xbool_t bPressed)
{
    XCHECK_NL((pInput != NULL && !pInput->bBroken && pInput->pKeyboard != NULL), XSTDERR);
    XCHECK_NL((nKeycode > 0 && nKeycode < 0x10000), XSTDERR);

    directgate_wlr_arg_t args[3];
    args[0].nUint = DirectGate_WLR_Now();
    args[1].nUint = (uint32_t)nKeycode;
    args[2].nUint = bPressed ? 1U : 0U;

    g_wlr.marshal(pInput->pKeyboard, DIRECTGATE_WLR_VK_KEY, args);

    /* wlroots takes a virtual keyboard's keys without working out what they
     * do to the modifiers, so a Shift that went down is only down once the
     * client says so. Tracked here against the same keymap, sent on change. */
    g_xkb.updateKey(pInput->pState, (uint32_t)nKeycode + 8U, bPressed ? DIRECTGATE_XKB_KEY_DOWN : DIRECTGATE_XKB_KEY_UP);
    DirectGate_WLR_SendModifiers(pInput);

    return DirectGate_WLR_InputFlush(pInput);
}

/* A key the host layout types @p nSym on with the modifiers held right now.
 * Lent keys are skipped: in the keymap the compositor has, they type
 * something else entirely. */
static uint32_t DirectGate_WLR_KeysymDirect(directgate_wlr_input_t *pInput, uint32_t nSym)
{
    uint32_t nMin = g_xkb.minKeycode(pInput->pKeymap);
    uint32_t nMax = g_xkb.maxKeycode(pInput->pKeymap);
    if (nMax > 255U) nMax = 255U;

    for (uint32_t nKeycode = nMin < 9U ? 9U : nMin; nKeycode <= nMax; nKeycode++)
    {
        if (g_xkb.oneSym(pInput->pState, nKeycode) != nSym) continue;
        if (DirectGate_WLR_IsSlot(pInput, nKeycode)) continue;
        return nKeycode - 8U;
    }

    return 0;
}

static xbool_t DirectGate_WLR_SlotHeld(const directgate_wlr_input_t *pInput, uint32_t nKeycode)
{
    for (uint32_t i = 0; i < pInput->nHeld; i++)
    {
        if (pInput->held[i].nEvdev + 8U == nKeycode) return XTRUE;
    }

    return XFALSE;
}

/* A lent key typing @p nSym, lending one if none does yet - the one used
 * longest ago, never one being held down. Each new loan rewrites the keymap,
 * which every client recompiles, so loans are kept for as long as possible. */
static uint32_t DirectGate_WLR_KeysymScratch(directgate_wlr_input_t *pInput, uint32_t nSym)
{
    directgate_wlr_slot_t *pPick = NULL;

    for (uint32_t i = 0; i < pInput->nSlots; i++)
    {
        directgate_wlr_slot_t *pSlot = &pInput->slots[i];
        if (pSlot->nSym == nSym)
        {
            pSlot->nUsed = ++pInput->nUseClock;
            return pSlot->nKeycode - 8U;
        }

        if (DirectGate_WLR_SlotHeld(pInput, pSlot->nKeycode)) continue;
        if (pPick == NULL || (!pSlot->nSym && pPick->nSym) || (!!pSlot->nSym == !!pPick->nSym && pSlot->nUsed < pPick->nUsed))
            pPick = pSlot;
    }

    char sSym[64];
    if (pPick == NULL || !DirectGate_WLR_KeysymSpelling(pInput, nSym, sSym, sizeof(sSym))) return 0;

    directgate_wlr_slot_t previous = *pPick;
    pPick->nSym = nSym;
    pPick->nUsed = ++pInput->nUseClock;
    xstrncpy(pPick->sSym, sizeof(pPick->sSym), sSym);

    if (DirectGate_WLR_UploadKeymap(pInput) != XSTDOK)
    {
        *pPick = previous;
        return 0;
    }

    return pPick->nKeycode - 8U;
}

int DirectGate_WLR_Keysym(directgate_wlr_input_t *pInput, int32_t nKeysym, xbool_t bPressed)
{
    XCHECK_NL((pInput != NULL && !pInput->bBroken), XSTDERR);

    if (pInput->pKeyboard == NULL)
    {
        pInput->bKeysymRefused = XTRUE;
        return XSTDERR;
    }

    uint32_t nSym = (uint32_t)nKeysym;

    /* Released on the key it was pressed on, whatever the keymap says now */
    if (!bPressed)
    {
        for (uint32_t i = 0; i < pInput->nHeld; i++)
        {
            if (pInput->held[i].nSym != nSym) continue;

            uint32_t nEvdev = pInput->held[i].nEvdev;
            pInput->held[i] = pInput->held[--pInput->nHeld];
            return DirectGate_WLR_Keycode(pInput, (int32_t)nEvdev, XFALSE);
        }

        return XSTDOK;
    }

    uint32_t nEvdev = 0;
    for (uint32_t i = 0; i < pInput->nHeld && !nEvdev; i++)
    {
        if (pInput->held[i].nSym == nSym) nEvdev = pInput->held[i].nEvdev;
    }

    if (!nEvdev) nEvdev = DirectGate_WLR_KeysymDirect(pInput, nSym);
    if (!nEvdev) nEvdev = DirectGate_WLR_KeysymScratch(pInput, nSym);

    if (!nEvdev)
    {
        pInput->bKeysymRefused = XTRUE;
        return XSTDERR;
    }

    xbool_t bTracked = XFALSE;
    for (uint32_t i = 0; i < pInput->nHeld; i++)
    {
        if (pInput->held[i].nSym == nSym) bTracked = XTRUE;
    }

    if (!bTracked && pInput->nHeld < DIRECTGATE_WLR_HELD_MAX)
    {
        pInput->held[pInput->nHeld].nSym = nSym;
        pInput->held[pInput->nHeld].nEvdev = nEvdev;
        pInput->nHeld++;
    }

    return DirectGate_WLR_Keycode(pInput, (int32_t)nEvdev, XTRUE);
}

xbool_t DirectGate_WLR_KeysymRefused(const directgate_wlr_input_t *pInput)
{
    return (pInput != NULL && pInput->bKeysymRefused) ? XTRUE : XFALSE;
}

void DirectGate_WLR_InputClose(directgate_wlr_input_t *pInput)
{
    if (pInput == NULL) return;

    /* Destroyed rather than just dropped with the connection, so the
     * compositor lets go of any key or button still held through them. */
    if (pInput->conn.pDisplay != NULL)
    {
        DirectGate_WLR_Release(&pInput->pKeyboard, DIRECTGATE_WLR_VK_DESTROY);
        DirectGate_WLR_Release(&pInput->pSharedPointer, DIRECTGATE_WLR_VP_DESTROY);

        for (uint32_t i = 0; i < pInput->conn.nOutputs; i++)
            DirectGate_WLR_Release(&pInput->conn.outputs[i].pPointer, DIRECTGATE_WLR_VP_DESTROY);
    }

    DirectGate_WLR_Disconnect(&pInput->conn);

    if (pInput->pState != NULL) g_xkb.stateUnref(pInput->pState);
    if (pInput->pKeymap != NULL) g_xkb.keymapUnref(pInput->pKeymap);
    if (pInput->pContext != NULL) g_xkb.contextUnref(pInput->pContext);

    free(pInput->pBaseText);
    free(pInput);
}

#endif /* DIRECTGATE_DESKTOP_HAS_WAYLAND */
