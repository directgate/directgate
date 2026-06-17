/*!
 * @file directgate-agent/src/agent/desktop_linux.c
 * @brief Linux desktop monitor enumeration and preview capture backend.
 */

#include "desktop.h"

#if !defined(_WIN32) && !defined(__APPLE__)

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static xbool_t DirectGate_DesktopLinux_ReadDimensions(uint32_t *pWidth, uint32_t *pHeight)
{
    FILE *pPipe = popen("xdpyinfo 2>/dev/null | awk '/dimensions:/{print $2; exit}'", "r");
    if (pPipe == NULL) return XFALSE;

    char sLine[64] = { 0 };
    xbool_t bOk = XFALSE;
    if (fgets(sLine, sizeof(sLine), pPipe) != NULL)
    {
        unsigned int nWidth = 0;
        unsigned int nHeight = 0;
        if (sscanf(sLine, "%ux%u", &nWidth, &nHeight) == 2 && nWidth > 0 && nHeight > 0)
        {
            *pWidth = nWidth;
            *pHeight = nHeight;
            bOk = XTRUE;
        }
    }

    pclose(pPipe);
    return bOk;
}

static XSTATUS DirectGate_DesktopLinux_Enumerate(directgate_desktop_t *pDesktop)
{
    uint32_t nWidth = 0;
    uint32_t nHeight = 0;
    DirectGate_DesktopLinux_ReadDimensions(&nWidth, &nHeight);

    memset(pDesktop->monitors, 0, sizeof(pDesktop->monitors));
    pDesktop->nMonitorCount = 1;

    directgate_desktop_monitor_t *pMonitor = &pDesktop->monitors[0];
    xstrncpy(pMonitor->sId, sizeof(pMonitor->sId), "desktop-0");
    xstrncpy(pMonitor->sName, sizeof(pMonitor->sName), "Desktop");
    pMonitor->nX = 0;
    pMonitor->nY = 0;
    pMonitor->nWidth = nWidth;
    pMonitor->nHeight = nHeight;
    pMonitor->fScale = 1.0;
    pMonitor->bPrimary = XTRUE;

    if (!xstrused(pDesktop->sSelectedMonitorId))
        xstrncpy(pDesktop->sSelectedMonitorId, sizeof(pDesktop->sSelectedMonitorId), pMonitor->sId);

    return XSTDOK;
}

static xbool_t DirectGate_DesktopLinux_ReadFile(const char *pPath,
                                                directgate_desktop_preview_t *pPreview)
{
    FILE *pFile = fopen(pPath, "rb");
    if (pFile == NULL) return XFALSE;

    if (fseek(pFile, 0, SEEK_END) != 0)
    {
        fclose(pFile);
        return XFALSE;
    }

    long nLen = ftell(pFile);
    if (nLen <= 0)
    {
        fclose(pFile);
        return XFALSE;
    }
    rewind(pFile);

    pPreview->pData = (uint8_t*)malloc((size_t)nLen);
    if (pPreview->pData == NULL)
    {
        fclose(pFile);
        return XFALSE;
    }

    size_t nRead = fread(pPreview->pData, 1, (size_t)nLen, pFile);
    fclose(pFile);

    if (nRead != (size_t)nLen)
    {
        free(pPreview->pData);
        pPreview->pData = NULL;
        return XFALSE;
    }

    pPreview->nDataLen = (size_t)nLen;
    pPreview->eFormat = DIRECTGATE_DESKTOP_PREVIEW_PNG;
    return XTRUE;
}

static xbool_t DirectGate_DesktopLinux_RunCaptureCommand(const char *pTemplate,
                                                         const char *pPath)
{
    char sCmd[1024];
    snprintf(sCmd, sizeof(sCmd), pTemplate, pPath);

    int nStatus = system(sCmd);
    if (nStatus == -1) return XFALSE;
    if (!WIFEXITED(nStatus) || WEXITSTATUS(nStatus) != 0) return XFALSE;

    struct stat st;
    return (stat(pPath, &st) == 0 && st.st_size > 0) ? XTRUE : XFALSE;
}

static XSTATUS DirectGate_DesktopLinux_CapturePreview(directgate_desktop_t *pDesktop,
                                                      const char *pMonitorId,
                                                      uint32_t nMaxWidth,
                                                      directgate_desktop_preview_t *pPreview)
{
    (void)pDesktop;
    (void)pMonitorId;
    (void)nMaxWidth;

    char sBase[] = "/tmp/directgate-preview-XXXXXX";
    int nFd = mkstemp(sBase);
    if (nFd < 0) return XSTDERR;
    close(nFd);
    unlink(sBase);

    char sPath[sizeof(sBase) + 4];
    snprintf(sPath, sizeof(sPath), "%s.png", sBase);

    static const char *kCommands[] = {
        "grim -t png '%s' >/dev/null 2>&1",
        "gnome-screenshot -f '%s' >/dev/null 2>&1",
        "scrot '%s' >/dev/null 2>&1",
        "import -window root '%s' >/dev/null 2>&1",
    };

    xbool_t bCaptured = XFALSE;
    for (size_t i = 0; i < sizeof(kCommands) / sizeof(kCommands[0]); i++)
    {
        if (DirectGate_DesktopLinux_RunCaptureCommand(kCommands[i], sPath))
        {
            bCaptured = XTRUE;
            break;
        }
    }

    if (!bCaptured)
    {
        unlink(sPath);
        return XSTDERR;
    }

    XSTATUS nStatus = DirectGate_DesktopLinux_ReadFile(sPath, pPreview) ? XSTDOK : XSTDERR;
    unlink(sPath);

    if (nStatus == XSTDOK)
    {
        pPreview->nWidth = pDesktop->nMonitorCount > 0 ?
            XSTD_MAX(pDesktop->monitors[0].nWidth, 1U) : 1U;
        pPreview->nHeight = pDesktop->nMonitorCount > 0 ?
            XSTD_MAX(pDesktop->monitors[0].nHeight, 1U) : 1U;
    }

    return nStatus;
}

static XSTATUS DirectGate_DesktopLinux_SetSelectedMonitor(directgate_desktop_t *pDesktop,
                                                          const char *pMonitorId)
{
    return xstrcmp(pMonitorId, "desktop-0") || pDesktop->nMonitorCount == 1 ? XSTDOK : XSTDERR;
}

static XSTATUS DirectGate_DesktopLinux_UnsupportedStream(directgate_desktop_t *pDesktop)
{
    (void)pDesktop;
    return XSTDERR;
}

static XSTATUS DirectGate_DesktopLinux_UnsupportedPreset(directgate_desktop_t *pDesktop,
                                                         directgate_desktop_quality_t ePreset)
{
    (void)pDesktop;
    (void)ePreset;
    return XSTDERR;
}

static XSTATUS DirectGate_DesktopLinux_UnsupportedInput(directgate_desktop_t *pDesktop,
                                                        const directgate_desktop_input_t *pInput)
{
    (void)pDesktop;
    (void)pInput;
    return XSTDERR;
}

static const directgate_desktop_backend_ops_t g_desktopLinuxOps = {
    NULL,
    NULL,
    DirectGate_DesktopLinux_Enumerate,
    DirectGate_DesktopLinux_CapturePreview,
    DirectGate_DesktopLinux_UnsupportedStream,
    DirectGate_DesktopLinux_UnsupportedStream,
    DirectGate_DesktopLinux_UnsupportedPreset,
    DirectGate_DesktopLinux_UnsupportedStream,
    DirectGate_DesktopLinux_UnsupportedInput,
    DirectGate_DesktopLinux_SetSelectedMonitor,
};

const directgate_desktop_backend_ops_t* DirectGate_Desktop_GetPlatformBackend(void)
{
    return &g_desktopLinuxOps;
}

#endif
