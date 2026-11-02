/*
 * The wlroots backend against a real wlroots compositor.
 *
 * Starts labwc or sway headless in a private runtime directory - the
 * compositor named by DIRECTGATE_WLR_COMPOSITOR, else the first of them on the
 * PATH - and puts a test client on it: one overlay surface per screen, painted
 * a known colour, recording every pointer and keyboard event that reaches it.
 * The unmodified agent code then does what it does on a Raspberry Pi: opens
 * the compositor, copies a screen (the pixels must be the client's colour, an
 * idle screen must cost no copies, a change must arrive), switches screens,
 * and injects input through the portal handle input.c drives - pointer motion
 * that lands on the right pixel of the right screen, buttons, scrolling, keys
 * by position with the modifier state the compositor never works out itself,
 * a character the layout has, and characters it does not (Georgian), which
 * must arrive on a lent key the client's own copy of the new keymap types
 * them with. Last, the compositor goes away and both halves have to say so.
 *
 * The client speaks Wayland through the same dlopen'd libwayland-client the
 * agent uses, so the test needs no Wayland headers to build. Skips (77) where
 * there is no compositor to start.
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "src/agent/desktop/wayland_wlr.c"

/* The agent declares libwayland's message, interface and argument types
 * itself so it needs no Wayland headers to build. Wherever the headers are
 * installed, the declarations are held to them here, at compile time. */
#if defined(__has_include)
#if __has_include(<wayland-util.h>)
#include <stddef.h>
#include <wayland-util.h>

#define SAME_FIELD(ours, field, theirs, tfield) \
    _Static_assert(offsetof(ours, field) == offsetof(theirs, tfield), #ours "." #field " sits where libwayland has it")

_Static_assert(sizeof(directgate_wlr_msg_t) == sizeof(struct wl_message), "wl_message has the same size");
SAME_FIELD(directgate_wlr_msg_t, pName, struct wl_message, name);
SAME_FIELD(directgate_wlr_msg_t, pSignature, struct wl_message, signature);
SAME_FIELD(directgate_wlr_msg_t, ppTypes, struct wl_message, types);

_Static_assert(sizeof(directgate_wlr_iface_t) == sizeof(struct wl_interface), "wl_interface has the same size");
SAME_FIELD(directgate_wlr_iface_t, pName, struct wl_interface, name);
SAME_FIELD(directgate_wlr_iface_t, nVersion, struct wl_interface, version);
SAME_FIELD(directgate_wlr_iface_t, nMethodCount, struct wl_interface, method_count);
SAME_FIELD(directgate_wlr_iface_t, pMethods, struct wl_interface, methods);
SAME_FIELD(directgate_wlr_iface_t, nEventCount, struct wl_interface, event_count);
SAME_FIELD(directgate_wlr_iface_t, pEvents, struct wl_interface, events);

_Static_assert(sizeof(directgate_wlr_arg_t) == sizeof(union wl_argument), "wl_argument has the same size");
_Static_assert(sizeof(((directgate_wlr_arg_t*)0)->nFixed) == sizeof(wl_fixed_t), "a fixed is as wide as wl_fixed_t");
#endif
#endif

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "wayland_wlr_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#define COLOUR_ONE   0x00336699U    /* XRGB: B 0x99, G 0x66, R 0x33 */
#define COLOUR_TWO   0x00C08040U
#define COLOUR_THREE 0x0011AA22U

#define GEORGIAN_AN  0x010010D0U    /* ა */
#define GEORGIAN_BAN 0x010010D1U    /* ბ */

static char g_sRoot[] = "/tmp/directgate_wlr.XXXXXX";
static char g_sLog[256];
static char g_sSocket[32];          /* labwc takes wayland-0, sway and Wayfire wayland-1 */
static pid_t g_nCompositor = -1;

/* ---- the compositor ----------------------------------------------------- */

static const char* find_compositor(xbool_t *pExplicit)
{
    static char sFound[512];
    const char *pEnv = getenv("DIRECTGATE_WLR_COMPOSITOR");
    *pExplicit = xstrused(pEnv) ? XTRUE : XFALSE;
    if (*pExplicit) return pEnv;

    const char *pPath = getenv("PATH");
    const char *pNames[] = { "labwc", "sway", NULL };

    for (int n = 0; pNames[n] != NULL && xstrused(pPath); n++)
    {
        const char *pDir = pPath;

        while (*pDir)
        {
            const char *pColon = strchr(pDir, ':');
            size_t nLength = pColon ? (size_t)(pColon - pDir) : strlen(pDir);

            snprintf(sFound, sizeof(sFound), "%.*s/%s", (int)nLength, pDir, pNames[n]);
            if (nLength && access(sFound, X_OK) == 0) return sFound;

            pDir += nLength;
            if (*pDir == ':') pDir++;
        }
    }

    return NULL;
}

static int start_compositor(const char *pPath)
{
    char sConfig[256];
    snprintf(sConfig, sizeof(sConfig), "%s/config", g_sRoot);
    snprintf(g_sLog, sizeof(g_sLog), "%s/compositor.log", g_sRoot);
    mkdir(sConfig, 0700);

    /* sway reads a config or falls back to the system one, which starts a
     * bar and more; this one only switches X off. */
    char sSway[300];
    snprintf(sSway, sizeof(sSway), "%s/sway.conf", sConfig);
    FILE *pFile = fopen(sSway, "w");
    if (pFile != NULL)
    {
        fputs("xwayland disable\n", pFile);
        fclose(pFile);
    }

    g_nCompositor = fork();
    if (g_nCompositor < 0) return -1;

    if (g_nCompositor == 0)
    {
        int nLog = open(g_sLog, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (nLog >= 0)
        {
            dup2(nLog, STDOUT_FILENO);
            dup2(nLog, STDERR_FILENO);
        }

        setenv("XDG_RUNTIME_DIR", g_sRoot, 1);
        setenv("XDG_CONFIG_HOME", sConfig, 1);
        setenv("WLR_BACKENDS", "headless", 1);
        setenv("WLR_RENDERER", "pixman", 1);
        setenv("WLR_HEADLESS_OUTPUTS", "2", 1);
        setenv("WLR_LIBINPUT_NO_DEVICES", "1", 1);
        unsetenv("WAYLAND_DISPLAY");
        unsetenv("WAYLAND_SOCKET");
        unsetenv("DISPLAY");

        if (strstr(pPath, "sway") != NULL) execl(pPath, pPath, "-c", sSway, (char*)NULL);
        else execl(pPath, pPath, (char*)NULL);
        _exit(127);
    }

    for (int i = 0; i < 500; i++)
    {
        for (int n = 0; n < 4; n++)
        {
            char sSocket[256];
            snprintf(sSocket, sizeof(sSocket), "%s/wayland-%d", g_sRoot, n);
            if (access(sSocket, F_OK) != 0) continue;

            snprintf(g_sSocket, sizeof(g_sSocket), "wayland-%d", n);
            return 0;
        }

        int nStatus = 0;
        if (waitpid(g_nCompositor, &nStatus, WNOHANG) == g_nCompositor)
        {
            g_nCompositor = -1;
            return -1;
        }

        usleep(10000);
    }

    return -1;
}

static void stop_compositor(void)
{
    if (g_nCompositor <= 0) return;

    kill(g_nCompositor, SIGTERM);
    for (int i = 0; i < 300 && waitpid(g_nCompositor, NULL, WNOHANG) == 0; i++) usleep(10000);

    kill(g_nCompositor, SIGKILL);
    waitpid(g_nCompositor, NULL, 0);
    g_nCompositor = -1;
}

static void show_log(void)
{
    FILE *pFile = fopen(g_sLog, "r");
    if (pFile == NULL) return;

    char sLine[512];
    fprintf(stderr, "wayland_wlr_smoke: compositor log follows\n");
    while (fgets(sLine, sizeof(sLine), pFile) != NULL) fputs(sLine, stderr);
    fclose(pFile);
}

static void remove_tree(void)
{
    char sCommand[512];
    snprintf(sCommand, sizeof(sCommand), "rm -rf '%s'", g_sRoot);
    if (system(sCommand) != 0) fprintf(stderr, "wayland_wlr_smoke: could not remove %s\n", g_sRoot);
}

/* ---- the test client ---------------------------------------------------- */

static const directgate_wlr_iface_t g_layerSurfaceIface;
/* wl_surface and wl_output are filled in once libwayland is loaded */
static const directgate_wlr_iface_t *g_layerTypes[] = { &g_layerSurfaceIface, NULL, NULL, NULL, NULL };

static const directgate_wlr_msg_t g_layerShellRequests[] = {
    { "get_layer_surface", "no?ous", g_layerTypes },
    { "destroy", "3", g_wlrNoTypes },
};

static const directgate_wlr_iface_t g_layerShellIface = { "zwlr_layer_shell_v1", 4, 2, g_layerShellRequests, 0, NULL };

static const directgate_wlr_msg_t g_layerSurfaceRequests[] = {
    { "set_size", "uu", g_wlrNoTypes },
    { "set_anchor", "u", g_wlrNoTypes },
    { "set_exclusive_zone", "i", g_wlrNoTypes },
    { "set_margin", "iiii", g_wlrNoTypes },
    { "set_keyboard_interactivity", "u", g_wlrNoTypes },
    { "get_popup", "o", g_wlrNoTypes },
    { "ack_configure", "u", g_wlrNoTypes },
    { "destroy", "", g_wlrNoTypes },
    { "set_layer", "2u", g_wlrNoTypes },
};

static const directgate_wlr_msg_t g_layerSurfaceEvents[] = {
    { "configure", "uuu", g_wlrNoTypes },
    { "closed", "", g_wlrNoTypes },
};

static const directgate_wlr_iface_t g_layerSurfaceIface = {
    "zwlr_layer_surface_v1", 4, 9, g_layerSurfaceRequests, 2, g_layerSurfaceEvents
};

typedef struct {
    uint32_t nOutputName;
    struct wl_proxy *pOutput;
    struct wl_proxy *pSurface;
    struct wl_proxy *pLayer;
    struct wl_proxy *pBuffer;
    uint32_t nWidth;
    uint32_t nHeight;
    uint32_t nSerial;
    int bConfigured;
} test_surface_t;

typedef struct {
    directgate_wlr_conn_t conn;     /* only its display is used */
    const directgate_wlr_iface_t *pCompositorIface;
    const directgate_wlr_iface_t *pSurfaceIface;
    const directgate_wlr_iface_t *pPointerIface;
    struct wl_proxy *pRegistry;
    struct wl_proxy *pCompositor;
    struct wl_proxy *pShm;
    struct wl_proxy *pSeat;
    struct wl_proxy *pLayerShell;
    struct wl_proxy *pPointer;
    struct wl_proxy *pKeyboard;
    uint32_t nCaps;
    test_surface_t surfaces[2];
    uint32_t nOutputs;

    struct wl_proxy *pEntered;
    double nX, nY;
    int nMotions, nButtons, nAxes;
    uint32_t nLastButton, nLastButtonState;
    double nLastAxis;

    char *pKeymap;
    int nKeymaps;
    int bFocused;
    int nKeys;
    uint32_t nLastKey, nLastKeyState;
    uint32_t nDepressed, nLocked;
} test_client_t;

static test_client_t g_client;

static int client_on_layer(const void *pImpl, void *pTarget, uint32_t nOpcode,
                           const directgate_wlr_msg_t *pMsg, directgate_wlr_arg_t *pArgs)
{
    (void)pImpl; (void)pMsg;
    test_surface_t *pSurface = (test_surface_t*)g_wlr.proxyData((struct wl_proxy*)pTarget);
    if (pSurface == NULL || nOpcode != 0) return 0;

    pSurface->nSerial = pArgs[0].nUint;
    pSurface->nWidth = pArgs[1].nUint;
    pSurface->nHeight = pArgs[2].nUint;
    pSurface->bConfigured = 1;
    return 0;
}

static int client_on_pointer(const void *pImpl, void *pTarget, uint32_t nOpcode,
                             const directgate_wlr_msg_t *pMsg, directgate_wlr_arg_t *pArgs)
{
    (void)pImpl; (void)pTarget; (void)pMsg;
    test_client_t *pClient = &g_client;

    switch (nOpcode)
    {
        case 0: /* enter */
            pClient->pEntered = (struct wl_proxy*)pArgs[1].pObject;
            pClient->nX = pArgs[2].nFixed / 256.0;
            pClient->nY = pArgs[3].nFixed / 256.0;
            pClient->nMotions++;
            break;
        case 2: /* motion */
            pClient->nX = pArgs[1].nFixed / 256.0;
            pClient->nY = pArgs[2].nFixed / 256.0;
            pClient->nMotions++;
            break;
        case 3: /* button */
            pClient->nButtons++;
            pClient->nLastButton = pArgs[2].nUint;
            pClient->nLastButtonState = pArgs[3].nUint;
            break;
        case 4: /* axis */
            pClient->nAxes++;
            pClient->nLastAxis = pArgs[2].nFixed / 256.0;
            break;
        default:
            break;
    }

    return 0;
}

static int client_on_keyboard(const void *pImpl, void *pTarget, uint32_t nOpcode,
                              const directgate_wlr_msg_t *pMsg, directgate_wlr_arg_t *pArgs)
{
    (void)pImpl; (void)pTarget; (void)pMsg;
    test_client_t *pClient = &g_client;

    switch (nOpcode)
    {
        case 0: /* keymap */
        {
            void *pMap = mmap(NULL, pArgs[2].nUint, PROT_READ, MAP_PRIVATE, pArgs[1].nFd, 0);
            if (pMap != MAP_FAILED)
            {
                free(pClient->pKeymap);
                pClient->pKeymap = strndup((const char*)pMap, pArgs[2].nUint);
                munmap(pMap, pArgs[2].nUint);
                pClient->nKeymaps++;
            }

            close(pArgs[1].nFd);
            break;
        }
        case 1: /* enter */
            pClient->bFocused = 1;
            break;
        case 2: /* leave */
            pClient->bFocused = 0;
            break;
        case 3: /* key */
            pClient->nKeys++;
            pClient->nLastKey = pArgs[2].nUint;
            pClient->nLastKeyState = pArgs[3].nUint;
            break;
        case 4: /* modifiers */
            pClient->nDepressed = pArgs[1].nUint;
            pClient->nLocked = pArgs[3].nUint;
            break;
        default:
            break;
    }

    return 0;
}

static int client_on_seat(const void *pImpl, void *pTarget, uint32_t nOpcode,
                          const directgate_wlr_msg_t *pMsg, directgate_wlr_arg_t *pArgs)
{
    (void)pImpl; (void)pTarget; (void)pMsg;
    test_client_t *pClient = &g_client;
    if (nOpcode != 0) return 0;

    pClient->nCaps = pArgs[0].nUint;
    directgate_wlr_arg_t args[1];
    memset(args, 0, sizeof(args));

    /* The seat gains a pointer and a keyboard only once the agent has made
     * its virtual ones, so they are asked for whenever they appear. */
    if ((pClient->nCaps & 1U) && pClient->pPointer == NULL)
    {
        uint32_t nVersion = g_wlr.proxyVersion(pClient->pSeat);
        pClient->pPointer = g_wlr.marshalCtor(pClient->pSeat, 0, args, pClient->pPointerIface, nVersion);
        g_wlr.addDispatcher(pClient->pPointer, client_on_pointer, pClient, pClient);
    }

    if ((pClient->nCaps & 2U) && pClient->pKeyboard == NULL)
    {
        pClient->pKeyboard = g_wlr.marshalCtor(pClient->pSeat, 1, args, g_wlr.pKeyboard, g_wlr.proxyVersion(pClient->pSeat));
        g_wlr.addDispatcher(pClient->pKeyboard, client_on_keyboard, pClient, pClient);
    }

    return 0;
}

static int client_on_registry(const void *pImpl, void *pTarget, uint32_t nOpcode,
                              const directgate_wlr_msg_t *pMsg, directgate_wlr_arg_t *pArgs)
{
    (void)pImpl; (void)pTarget; (void)pMsg;
    test_client_t *pClient = &g_client;
    if (nOpcode != 0) return 0;

    uint32_t nName = pArgs[0].nUint, nVersion = pArgs[2].nUint;
    const char *pIface = pArgs[1].pStr;
    directgate_wlr_arg_t args[4];
    memset(args, 0, sizeof(args));
    args[0].nUint = nName;

#define BIND(var, iface, version) \
    do { \
        args[1].pStr = (iface)->pName; args[2].nUint = (version); \
        var = g_wlr.marshalCtor(pClient->pRegistry, 0, args, (iface), (version)); \
    } while (0)

    if (xstrcmp(pIface, "wl_compositor")) BIND(pClient->pCompositor, pClient->pCompositorIface, 4U);
    else if (xstrcmp(pIface, "wl_shm")) BIND(pClient->pShm, g_wlr.pShm, 1U);
    else if (xstrcmp(pIface, "zwlr_layer_shell_v1"))
        BIND(pClient->pLayerShell, &g_layerShellIface, nVersion < 4U ? nVersion : 4U);
    else if (xstrcmp(pIface, "wl_seat") && pClient->pSeat == NULL)
    {
        BIND(pClient->pSeat, g_wlr.pSeat, nVersion < 5U ? nVersion : 5U);
        g_wlr.addDispatcher(pClient->pSeat, client_on_seat, pClient, pClient);
    }
    else if (xstrcmp(pIface, "wl_output") && pClient->nOutputs < 2)
    {
        test_surface_t *pSurface = &pClient->surfaces[pClient->nOutputs++];
        pSurface->nOutputName = nName;
        BIND(pSurface->pOutput, g_wlr.pOutput, 1U);
    }

#undef BIND
    return 0;
}

static int client_pump(int nTimeoutMs)
{
    return DirectGate_WLR_Pump(&g_client.conn, nTimeoutMs, -1);
}

/* Pumps the client until @p pCounter moves past @p nBefore. */
static int client_wait(const int *pCounter, int nBefore, int nTimeoutMs)
{
    uint64_t nDeadline = XTime_GetMonoMs() + (uint64_t)nTimeoutMs;
    while (*pCounter <= nBefore && XTime_GetMonoMs() < nDeadline) client_pump(20);
    return *pCounter > nBefore;
}

static void client_settle(int nMs)
{
    uint64_t nDeadline = XTime_GetMonoMs() + (uint64_t)nMs;
    while (XTime_GetMonoMs() < nDeadline) client_pump(10);
}

static int client_paint(test_surface_t *pSurface, uint32_t nColour)
{
    test_client_t *pClient = &g_client;
    size_t nSize = (size_t)pSurface->nWidth * pSurface->nHeight * 4U;
    int nFd = DirectGate_WLR_AnonFile(nSize);
    if (nFd < 0) return -1;

    uint32_t *pPixels = (uint32_t*)mmap(NULL, nSize, PROT_READ | PROT_WRITE, MAP_SHARED, nFd, 0);
    if ((void*)pPixels == MAP_FAILED)
    {
        close(nFd);
        return -1;
    }

    for (size_t i = 0; i < nSize / 4U; i++) pPixels[i] = nColour;
    munmap(pPixels, nSize);

    directgate_wlr_arg_t args[6];
    memset(args, 0, sizeof(args));
    args[1].nFd = nFd;
    args[2].nInt = (int32_t)nSize;
    struct wl_proxy *pPool = g_wlr.marshalCtor(pClient->pShm, 0, args, g_wlr.pShmPool, 1U);
    close(nFd);

    memset(args, 0, sizeof(args));
    args[2].nInt = (int32_t)pSurface->nWidth;
    args[3].nInt = (int32_t)pSurface->nHeight;
    args[4].nInt = (int32_t)pSurface->nWidth * 4;
    args[5].nUint = DIRECTGATE_WLR_SHM_XRGB8888;

    struct wl_proxy *pOld = pSurface->pBuffer;
    pSurface->pBuffer = g_wlr.marshalCtor(pPool, 0, args, g_wlr.pBuffer, 1U);
    DirectGate_WLR_Release(&pPool, 1);

    memset(args, 0, sizeof(args));
    args[0].pObject = pSurface->pBuffer;
    g_wlr.marshal(pSurface->pSurface, 1, args);                /* attach */

    args[0].nInt = 0;
    args[1].nInt = 0;
    args[2].nInt = (int32_t)pSurface->nWidth;
    args[3].nInt = (int32_t)pSurface->nHeight;
    g_wlr.marshal(pSurface->pSurface, 2, args);                /* damage */
    DirectGate_WLR_Request(pSurface->pSurface, 6);             /* commit */

    if (pOld != NULL) DirectGate_WLR_Release(&pOld, 0);
    return client_pump(0) == XSTDOK ? 0 : -1;
}

static int client_open(void)
{
    test_client_t *pClient = &g_client;
    memset(pClient, 0, sizeof(*pClient));

    pClient->pCompositorIface = (const directgate_wlr_iface_t*)dlsym(g_wlr.pHandle, "wl_compositor_interface");
    pClient->pSurfaceIface = (const directgate_wlr_iface_t*)dlsym(g_wlr.pHandle, "wl_surface_interface");
    pClient->pPointerIface = (const directgate_wlr_iface_t*)dlsym(g_wlr.pHandle, "wl_pointer_interface");
    if (pClient->pCompositorIface == NULL || pClient->pSurfaceIface == NULL || pClient->pPointerIface == NULL) return -1;

    pClient->conn.pDisplay = g_wlr.connect(g_sSocket);
    if (pClient->conn.pDisplay == NULL) return -1;

    directgate_wlr_arg_t args[5];
    memset(args, 0, sizeof(args));
    pClient->pRegistry = g_wlr.marshalCtor((struct wl_proxy*)pClient->conn.pDisplay, 1, args, g_wlr.pRegistry, 1U);
    g_wlr.addDispatcher(pClient->pRegistry, client_on_registry, pClient, pClient);

    if (DirectGate_WLR_Roundtrip(&pClient->conn, 2000) != XSTDOK) return -1;
    if (pClient->pCompositor == NULL || pClient->pShm == NULL || pClient->pLayerShell == NULL) return -1;
    if (pClient->nOutputs < 2) return -1;

    for (uint32_t i = 0; i < 2; i++)
    {
        test_surface_t *pSurface = &pClient->surfaces[i];

        memset(args, 0, sizeof(args));
        pSurface->pSurface = g_wlr.marshalCtor(pClient->pCompositor, 0, args, pClient->pSurfaceIface, 4U);

        g_layerTypes[1] = pClient->pSurfaceIface;
        g_layerTypes[2] = g_wlr.pOutput;

        memset(args, 0, sizeof(args));
        args[1].pObject = pSurface->pSurface;
        args[2].pObject = pSurface->pOutput;
        args[3].nUint = 3U;                     /* overlay */
        args[4].pStr = "directgate-test";
        pSurface->pLayer = g_wlr.marshalCtor(pClient->pLayerShell, 0, args, &g_layerSurfaceIface,
            g_wlr.proxyVersion(pClient->pLayerShell));

        g_wlr.addDispatcher(pSurface->pLayer, client_on_layer, pSurface, pSurface);

        memset(args, 0, sizeof(args));
        args[0].nUint = 15U;                    /* every edge: the whole screen */
        g_wlr.marshal(pSurface->pLayer, 1, args);

        args[0].nUint = (i == 0) ? 1U : 0U;     /* the first takes the keyboard */
        g_wlr.marshal(pSurface->pLayer, 4, args);
        DirectGate_WLR_Request(pSurface->pSurface, 6);
    }

    if (DirectGate_WLR_Roundtrip(&pClient->conn, 2000) != XSTDOK) return -1;

    for (uint32_t i = 0; i < 2; i++)
    {
        test_surface_t *pSurface = &pClient->surfaces[i];
        if (!pSurface->bConfigured || !pSurface->nWidth || !pSurface->nHeight) return -1;

        memset(args, 0, sizeof(args));
        args[0].nUint = pSurface->nSerial;
        g_wlr.marshal(pSurface->pLayer, 6, args);   /* ack_configure */

        if (client_paint(pSurface, i == 0 ? COLOUR_ONE : COLOUR_TWO) != 0) return -1;
    }

    return DirectGate_WLR_Roundtrip(&pClient->conn, 2000) == XSTDOK ? 0 : -1;
}

static void client_close(void)
{
    test_client_t *pClient = &g_client;
    if (pClient->conn.pDisplay == NULL) return;

    for (uint32_t i = 0; i < 2; i++)
    {
        DirectGate_WLR_Destroy(&pClient->surfaces[i].pBuffer);
        DirectGate_WLR_Destroy(&pClient->surfaces[i].pLayer);
        DirectGate_WLR_Destroy(&pClient->surfaces[i].pSurface);
        DirectGate_WLR_Destroy(&pClient->surfaces[i].pOutput);
    }

    DirectGate_WLR_Destroy(&pClient->pPointer);
    DirectGate_WLR_Destroy(&pClient->pKeyboard);
    DirectGate_WLR_Destroy(&pClient->pSeat);
    DirectGate_WLR_Destroy(&pClient->pLayerShell);
    DirectGate_WLR_Destroy(&pClient->pShm);
    DirectGate_WLR_Destroy(&pClient->pCompositor);
    DirectGate_WLR_Destroy(&pClient->pRegistry);

    g_wlr.disconnect(pClient->conn.pDisplay);
    pClient->conn.pDisplay = NULL;
}

/* ---- what the capture delivered ----------------------------------------- */

typedef struct {
    xsync_mutex_t lock;
    int nFrames;
    uint32_t nWidth, nHeight;
    uint8_t centre[4];
} test_frames_t;

static test_frames_t g_frames;

static void on_frame(void *pCtx, const directgate_wl_frame_t *pFrame)
{
    test_frames_t *pFrames = (test_frames_t*)pCtx;
    size_t nOffset = (size_t)(pFrame->nHeight / 2U) * pFrame->nStride + (size_t)(pFrame->nWidth / 2U) * 4U;
    const uint8_t *pPixel = pFrame->pPixels + nOffset;

    XSync_Lock(&pFrames->lock);
    pFrames->nFrames++;
    pFrames->nWidth = pFrame->nWidth;
    pFrames->nHeight = pFrame->nHeight;
    memcpy(pFrames->centre, pPixel, 4);
    XSync_Unlock(&pFrames->lock);
}

static int frames_count(void)
{
    XSync_Lock(&g_frames.lock);
    int nFrames = g_frames.nFrames;
    XSync_Unlock(&g_frames.lock);
    return nFrames;
}

/* Waits for a frame whose centre is @p nColour, in BGRA memory order. */
static int wait_colour(uint32_t nColour, int nTimeoutMs)
{
    uint64_t nDeadline = XTime_GetMonoMs() + (uint64_t)nTimeoutMs;

    while (XTime_GetMonoMs() < nDeadline)
    {
        XSync_Lock(&g_frames.lock);
        int bMatch = g_frames.nFrames > 0 && g_frames.centre[0] == (nColour & 0xFFU) &&
            g_frames.centre[1] == ((nColour >> 8) & 0xFFU) && g_frames.centre[2] == ((nColour >> 16) & 0xFFU);
        XSync_Unlock(&g_frames.lock);

        if (bMatch) return 1;
        client_pump(10);
    }

    return 0;
}

static int keysym_of(const char *pText, uint32_t nEvdev, uint32_t *pSym)
{
    struct xkb_context *pContext = g_xkb.contextNew(0);
    struct xkb_keymap *pKeymap = g_xkb.keymapFromString(pContext, pText, DIRECTGATE_XKB_TEXT_V1, 0);
    const uint32_t *pSyms = NULL;
    int nSyms = pKeymap != NULL ? g_xkb.symsByLevel(pKeymap, nEvdev + 8U, 0U, 0U, &pSyms) : 0;

    *pSym = (nSyms == 1 && pSyms != NULL) ? pSyms[0] : 0;
    if (pKeymap != NULL) g_xkb.keymapUnref(pKeymap);
    g_xkb.contextUnref(pContext);

    return pKeymap != NULL;
}

/* ---- the checks --------------------------------------------------------- */

static int check_capture(const directgate_wl_stream_t *pFirst, const directgate_wl_stream_t *pSecond)
{
    char sError[256] = { 0 };
    directgate_wlr_capture_t *pCapture = DirectGate_WLR_CaptureStart(pFirst->nNodeId, on_frame, &g_frames,
        sError, sizeof(sError));
    CHECK(pCapture != NULL, "a screen of the compositor can be copied");
    CHECK(DirectGate_WLR_CaptureWaitFormat(pCapture, 4000) == XSTDOK, "the compositor describes the screen");

    uint32_t nWidth = 0, nHeight = 0;
    CHECK(DirectGate_WLR_CaptureSize(pCapture, &nWidth, &nHeight), "the copy has a size");
    CHECK(nWidth == pFirst->nWidth && nHeight == pFirst->nHeight, "the size of the screen it was asked for");
    CHECK(wait_colour(COLOUR_ONE, 3000), "the first frame is what is on that screen, as BGRA");

    /* Nothing changes: a copy that waits for damage sends nothing at all. */
    client_settle(300);
    int nIdle = frames_count();
    client_settle(500);
    CHECK(frames_count() <= nIdle + 1, "an unchanged screen is not copied over and over");

    CHECK(client_paint(&g_client.surfaces[0], COLOUR_THREE) == 0, "repaint the screen");
    CHECK(wait_colour(COLOUR_THREE, 3000), "and the change arrives without being asked for");
    CHECK(!DirectGate_WLR_CaptureLost(pCapture, NULL, 0), "nothing is lost while it runs");

    /* An idle screen still gives a new viewer one whole frame. */
    int nBefore = frames_count();
    DirectGate_WLR_CaptureRefresh(pCapture);
    uint64_t nDeadline = XTime_GetMonoMs() + 3000U;
    while (frames_count() == nBefore && XTime_GetMonoMs() < nDeadline) client_pump(10);
    CHECK(frames_count() > nBefore, "a refresh delivers a frame of an unchanged screen");

    DirectGate_WLR_CaptureStop(pCapture);

    pCapture = DirectGate_WLR_CaptureStart(pSecond->nNodeId, on_frame, &g_frames, sError, sizeof(sError));
    CHECK(pCapture != NULL && DirectGate_WLR_CaptureWaitFormat(pCapture, 4000) == XSTDOK, "the other screen can be copied");
    CHECK(wait_colour(COLOUR_TWO, 3000), "and shows what is on the other screen");
    DirectGate_WLR_CaptureStop(pCapture);

    pCapture = DirectGate_WLR_CaptureStart(0xFFFFFFF0U, on_frame, &g_frames, sError, sizeof(sError));
    CHECK(pCapture == NULL && strstr(sError, "not connected") != NULL, "a screen that does not exist is refused, by name");

    return 0;
}

static int check_input(directgate_wl_portal_t *pPortal, const directgate_wl_stream_t *pFirst,
                       const directgate_wl_stream_t *pSecond)
{
    test_client_t *pClient = &g_client;

    /* The first motion makes the virtual pointer, which is what gives the
     * seat a pointer for the client to ask for at all. */
    DirectGate_WL_PortalPointerMotion(pPortal, pFirst->nNodeId, 10.0, 10.0);
    client_settle(200);
    CHECK(pClient->pPointer != NULL, "the seat gains a pointer once the agent has one");

    int nMotions = pClient->nMotions;
    CHECK(DirectGate_WL_PortalPointerMotion(pPortal, pFirst->nNodeId, 100.0, 50.0) == XSTDOK, "absolute motion is sent");
    CHECK(client_wait(&pClient->nMotions, nMotions, 2000), "and reaches the client");
    CHECK(pClient->pEntered == pClient->surfaces[0].pSurface, "on the screen it was addressed to");
    CHECK(fabs(pClient->nX - 100.0) < 0.6 && fabs(pClient->nY - 50.0) < 0.6, "at the pixel it was addressed to");

    nMotions = pClient->nMotions;
    CHECK(DirectGate_WL_PortalPointerMotion(pPortal, pSecond->nNodeId, 30.0, 40.0) == XSTDOK, "motion on the second screen");
    CHECK(client_wait(&pClient->nMotions, nMotions, 2000), "reaches the client");
    CHECK(pClient->pEntered == pClient->surfaces[1].pSurface, "on the second screen, wherever it sits in the layout");
    CHECK(fabs(pClient->nX - 30.0) < 0.6 && fabs(pClient->nY - 40.0) < 0.6, "at that screen's own pixel");

    nMotions = pClient->nMotions;
    DirectGate_WL_PortalPointerMotion(pPortal, pSecond->nNodeId, -5.0, 1e9);
    CHECK(client_wait(&pClient->nMotions, nMotions, 2000), "a position off the screen is still sent");
    CHECK(pClient->nX < 0.6 && fabs(pClient->nY - (double)(pSecond->nHeight - 1U)) < 0.6, "clamped to its edge");

    nMotions = pClient->nMotions;
    DirectGate_WL_PortalPointerMotion(pPortal, pSecond->nNodeId, 200.0, 100.0);
    client_wait(&pClient->nMotions, nMotions, 2000);
    nMotions = pClient->nMotions;
    CHECK(DirectGate_WL_PortalPointerMotionRelative(pPortal, 7.0, -3.0) == XSTDOK, "relative motion is sent");
    CHECK(client_wait(&pClient->nMotions, nMotions, 2000), "and arrives");
    CHECK(fabs(pClient->nX - 207.0) < 0.6 && fabs(pClient->nY - 97.0) < 0.6, "unaccelerated");

    int nButtons = pClient->nButtons;
    CHECK(DirectGate_WL_PortalPointerButton(pPortal, DirectGate_WL_PortalButtonCode(1), XTRUE) == XSTDOK, "press");
    CHECK(DirectGate_WL_PortalPointerButton(pPortal, DirectGate_WL_PortalButtonCode(1), XFALSE) == XSTDOK, "release");
    CHECK(client_wait(&pClient->nButtons, nButtons + 1, 2000), "both reach the client");
    CHECK(pClient->nLastButton == 0x110U && pClient->nLastButtonState == 0U, "as the left button, released last");

    int nAxes = pClient->nAxes;
    CHECK(DirectGate_WL_PortalPointerAxis(pPortal, 0.0, 10.0) == XSTDOK, "scrolling is sent");
    CHECK(client_wait(&pClient->nAxes, nAxes, 2000), "and arrives");
    CHECK(fabs(pClient->nLastAxis - 10.0) < 0.01, "down, by the amount sent - not inverted");

    /* The keyboard - and its keymap - exist from the open. */
    CHECK(pClient->pKeyboard != NULL && pClient->nKeymaps >= 1, "the client has the virtual keyboard's keymap");

    int nKeys = pClient->nKeys;
    CHECK(DirectGate_WL_PortalKeycode(pPortal, 30, XTRUE) == XSTDOK, "a key by position");
    CHECK(DirectGate_WL_PortalKeycode(pPortal, 30, XFALSE) == XSTDOK, "and its release");
    CHECK(client_wait(&pClient->nKeys, nKeys + 1, 2000), "reach the focused client");
    CHECK(pClient->bFocused && pClient->nLastKey == 30U && pClient->nLastKeyState == 0U, "as that key");

    /* The modifier state is the agent's to tell, not the compositor's. */
    DirectGate_WL_PortalKeycode(pPortal, 42, XTRUE);
    client_settle(150);
    CHECK(pClient->nDepressed & 1U, "a Shift held down is a Shift held down");
    DirectGate_WL_PortalKeycode(pPortal, 42, XFALSE);
    client_settle(150);
    CHECK(!(pClient->nDepressed & 1U), "and let go of");

    DirectGate_WL_PortalKeycode(pPortal, 58, XTRUE);
    DirectGate_WL_PortalKeycode(pPortal, 58, XFALSE);
    client_settle(150);
    CHECK(pClient->nLocked & 2U, "Caps Lock locks");
    DirectGate_WL_PortalKeycode(pPortal, 58, XTRUE);
    DirectGate_WL_PortalKeycode(pPortal, 58, XFALSE);
    client_settle(150);
    CHECK(!(pClient->nLocked & 2U), "and unlocks");

    /* A character the layout has goes in on its own key, keymap untouched. */
    int nKeymaps = pClient->nKeymaps;
    nKeys = pClient->nKeys;
    CHECK(DirectGate_WL_PortalKeysym(pPortal, 'b', XTRUE) == XSTDOK, "a character the layout has");
    DirectGate_WL_PortalKeysym(pPortal, 'b', XFALSE);
    CHECK(client_wait(&pClient->nKeys, nKeys + 1, 2000), "is typed");
    CHECK(pClient->nLastKey == 48U && pClient->nKeymaps == nKeymaps, "on its own key, without a new keymap");

    /* One it does not: a lent key, in a keymap the client is handed first. */
    const uint32_t georgian[2] = { GEORGIAN_AN, GEORGIAN_BAN };
    uint32_t lent[2] = { 0, 0 };

    for (int i = 0; i < 2; i++)
    {
        nKeys = pClient->nKeys;
        nKeymaps = pClient->nKeymaps;
        CHECK(DirectGate_WL_PortalKeysym(pPortal, (int32_t)georgian[i], XTRUE) == XSTDOK, "a Georgian letter is accepted");
        CHECK(client_wait(&pClient->nKeys, nKeys, 2000), "and typed");
        CHECK(pClient->nKeymaps > nKeymaps, "after a keymap that has it");
        lent[i] = pClient->nLastKey;

        uint32_t nSym = 0;
        CHECK(keysym_of(pClient->pKeymap, lent[i], &nSym), "the client can compile that keymap");
        CHECK(nSym == georgian[i], "and in it, the key pressed types the Georgian letter");

        nKeys = pClient->nKeys;
        DirectGate_WL_PortalKeysym(pPortal, (int32_t)georgian[i], XFALSE);
        CHECK(client_wait(&pClient->nKeys, nKeys, 2000) && pClient->nLastKey == lent[i] && !pClient->nLastKeyState,
            "it is released on the same key");
    }

    CHECK(lent[0] != lent[1], "two letters, two keys");

    nKeymaps = pClient->nKeymaps;
    nKeys = pClient->nKeys;
    DirectGate_WL_PortalKeysym(pPortal, (int32_t)GEORGIAN_AN, XTRUE);
    DirectGate_WL_PortalKeysym(pPortal, (int32_t)GEORGIAN_AN, XFALSE);
    CHECK(client_wait(&pClient->nKeys, nKeys + 1, 2000), "a letter typed again");
    CHECK(pClient->nKeymaps == nKeymaps && pClient->nLastKey == lent[0], "keeps its key, with no new keymap");

    /* The physical layout survived the loans. */
    uint32_t nSym = 0;
    CHECK(keysym_of(pClient->pKeymap, 30, &nSym) && nSym == 'a', "the key for 'a' still types 'a'");
    CHECK(!DirectGate_WL_PortalKeysymRefused(pPortal), "nothing was refused");

    return 0;
}

int main(void)
{
    xbool_t bExplicit = XFALSE;
    const char *pCompositor = find_compositor(&bExplicit);
    if (pCompositor == NULL)
    {
        puts("wayland_wlr_smoke: SKIP (no labwc or sway; set DIRECTGATE_WLR_COMPOSITOR)");
        return 77;
    }

    char sError[256] = { 0 };
    if (DirectGate_WLR_Load(sError, sizeof(sError)) != XSTDOK || DirectGate_WLR_XkbLoad(sError, sizeof(sError)) != XSTDOK)
    {
        printf("wayland_wlr_smoke: SKIP (%s)\n", sError);
        return 77;
    }

    CHECK(mkdtemp(g_sRoot) != NULL, "make a runtime directory");
    XSync_Init(&g_frames.lock);

    if (start_compositor(pCompositor) != 0)
    {
        show_log();
        stop_compositor();
        remove_tree();
        if (bExplicit) CHECK(0, "the compositor named by DIRECTGATE_WLR_COMPOSITOR starts");

        printf("wayland_wlr_smoke: SKIP (%s did not start)\n", pCompositor);
        return 77;
    }

    /* As the agent's service sees it: a runtime directory and no WAYLAND_DISPLAY,
     * so the socket is found the way it is on a Pi. */
    setenv("XDG_RUNTIME_DIR", g_sRoot, 1);
    unsetenv("WAYLAND_DISPLAY");

    int nResult = 1;

    do
    {
        directgate_wlr_input_t *pInput = DirectGate_WLR_InputOpen(sError, sizeof(sError));
        if (pInput == NULL) fprintf(stderr, "wayland_wlr_smoke: %s\n", sError);
        if (pInput == NULL) break;

        if (DirectGate_WLR_InputScreenCount(pInput) != 2 || !DirectGate_WLR_InputHasPointer(pInput) ||
            !DirectGate_WLR_InputHasKeyboard(pInput) || pInput->nSlots < 32)
        {
            fprintf(stderr, "wayland_wlr_smoke: the compositor opens with both screens, a pointer, a keyboard "
                "and spare keys: screens(%u), spare(%u)\n", DirectGate_WLR_InputScreenCount(pInput), pInput->nSlots);
            DirectGate_WLR_InputClose(pInput);
            break;
        }

        directgate_wl_stream_t first = *DirectGate_WLR_InputScreen(pInput, 0);
        directgate_wl_stream_t second = *DirectGate_WLR_InputScreen(pInput, 1);

        directgate_wl_portal_t *pPortal = DirectGate_WL_PortalFromWlr(pInput);
        if (pPortal == NULL || !DirectGate_WL_PortalHasInput(pPortal) || DirectGate_WL_PortalStreamCount(pPortal) != 2 ||
            DirectGate_WL_PortalNodeId(pPortal) != first.nNodeId)
        {
            fprintf(stderr, "wayland_wlr_smoke: the portal handle stands in for the compositor\n");
            DirectGate_WL_PortalClose(pPortal);
            break;
        }

        if (client_open() != 0)
        {
            fprintf(stderr, "wayland_wlr_smoke: the test client cannot put a surface on both screens\n");
            DirectGate_WL_PortalClose(pPortal);
            break;
        }

        if (check_capture(&first, &second) != 0 || check_input(pPortal, &first, &second) != 0)
        {
            DirectGate_WL_PortalClose(pPortal);
            break;
        }

        /* The compositor goes away under a running copy and a live keyboard. */
        directgate_wlr_capture_t *pCapture = DirectGate_WLR_CaptureStart(first.nNodeId, on_frame, &g_frames,
            sError, sizeof(sError));
        if (pCapture == NULL || DirectGate_WLR_CaptureWaitFormat(pCapture, 4000) != XSTDOK)
        {
            fprintf(stderr, "wayland_wlr_smoke: copy once more before the compositor goes\n");
            DirectGate_WLR_CaptureStop(pCapture);
            DirectGate_WL_PortalClose(pPortal);
            break;
        }

        stop_compositor();

        char sLost[256] = { 0 };
        uint64_t nDeadline = XTime_GetMonoMs() + 3000U;
        while (!DirectGate_WLR_CaptureLost(pCapture, sLost, sizeof(sLost)) && XTime_GetMonoMs() < nDeadline) usleep(10000);

        int bLostSaid = sLost[0] != '\0';
        int bInputSaid = DirectGate_WL_PortalKeycode(pPortal, 30, XTRUE) == XSTDERR;

        DirectGate_WLR_CaptureStop(pCapture);
        DirectGate_WL_PortalClose(pPortal);

        if (!bLostSaid || !bInputSaid)
        {
            fprintf(stderr, "wayland_wlr_smoke: a compositor that goes away is reported by the copy (%d) and the input (%d)\n",
                bLostSaid, bInputSaid);
            break;
        }

        nResult = 0;
    }
    while (0);

    if (nResult != 0) show_log();
    stop_compositor();
    client_close();

    free(g_client.pKeymap);
    remove_tree();

    if (nResult == 0) puts("wayland_wlr_smoke: OK");
    return nResult;
}
