/*!
 * @file directgate-agent/tests/desktop_frame_smoke.c
 * @brief Encode geometry, quality presets and the monitor table.
 *
 * Everything here decides how large a buffer the capture path allocates and
 * what the encoder is asked to produce, from numbers the browser supplies.
 * Two properties matter and neither fails loudly on its own: the result stays
 * inside the absolute encode ceiling whatever the viewer asks for (the frame
 * buffers are sized w * h * 4, which overflows a 32-bit size_t above it), and
 * a rejected request leaves the previous, valid geometry in place rather than
 * a half-applied one.
 */

#include <stdio.h>
#include <string.h>

#include "src/agent/desktop/desktop.c"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "desktop_frame_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

/* desktop.c reaches into the capture, audio and input units for teardown; the
 * geometry under test touches none of them. */
void DirectGate_Desktop_AudioStop(directgate_desktop_t *pDesktop) { (void)pDesktop; }
void DirectGate_Desktop_LinuxEncoder_StopDesktop(directgate_desktop_t *pDesktop) { (void)pDesktop; }
void DirectGate_Desktop_RestoreDisplayMode(directgate_desktop_t *pDesktop) { (void)pDesktop; }
void DirectGate_Desktop_ReleaseHeldKeys(directgate_desktop_t *pDesktop) { (void)pDesktop; }

static int g_nKeyframeRequests = 0;
void DirectGate_Desktop_LinuxEncoder_RequestKeyframe(directgate_session_t *pSession)
{
    (void)pSession;
    g_nKeyframeRequests++;
}

static int g_nSends = 0;
int DirectGate_Session_Send(directgate_session_t *pSession, xjson_obj_t *pHeader,
                            const uint8_t *pPayload, size_t nPayloadLength)
{
    (void)pSession; (void)pHeader; (void)pPayload; (void)nPayloadLength;
    g_nSends++;
    return 0;
}

static int test_names(void)
{
    CHECK(strcmp(DirectGate_Desktop_PresetName(DIRECTGATE_DESKTOP_PRESET_QUALITY), "quality") == 0,
        "the quality preset reports its own name");
    CHECK(strcmp(DirectGate_Desktop_PresetName(DIRECTGATE_DESKTOP_PRESET_LOW_LATENCY), "low-latency") == 0,
        "the low-latency preset reports its own name");
    CHECK(strcmp(DirectGate_Desktop_PresetName(DIRECTGATE_DESKTOP_PRESET_BALANCED), "balanced") == 0,
        "the balanced preset reports its own name");
    CHECK(strcmp(DirectGate_Desktop_PresetName((directgate_desktop_preset_t)99), "balanced") == 0,
        "an unknown preset reports the balanced name rather than nothing");

    CHECK(strcmp(DirectGate_Desktop_PipelineName(DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO), "webrtc-video") == 0,
        "the webrtc video pipeline reports its own name");
    CHECK(strcmp(DirectGate_Desktop_PipelineName(DIRECTGATE_DESKTOP_PIPELINE_H264_DC), "h264-datachannel") == 0,
        "the data-channel H.264 pipeline reports its own name");
    CHECK(strcmp(DirectGate_Desktop_PipelineName(DIRECTGATE_DESKTOP_PIPELINE_RAW), "raw-rgba") == 0,
        "the raw pipeline reports its own name");
    CHECK(strcmp(DirectGate_Desktop_PipelineName((directgate_desktop_pipeline_t)99), "raw-rgba") == 0,
        "an unknown pipeline reports the raw name rather than nothing");

    CHECK(strcmp(DirectGate_Desktop_ResizeModeName(DIRECTGATE_DESKTOP_RESIZE_DISPLAY), "display") == 0,
        "the display resize mode reports its own name");
    CHECK(strcmp(DirectGate_Desktop_ResizeModeName(DIRECTGATE_DESKTOP_RESIZE_SCALE), "scale") == 0,
        "the scale resize mode reports its own name");

    /* The reason strings end up in the status the viewer shows, so an empty
     * one has to become something a person can read. */
    directgate_desktop_t desktop;
    memset(&desktop, 0, sizeof(desktop));

    CHECK(strcmp(DirectGate_Desktop_GetReason(NULL), "desktop unavailable") == 0,
        "a missing desktop reports a readable reason");
    CHECK(strcmp(DirectGate_Desktop_GetReason(&desktop), "desktop unavailable") == 0,
        "a desktop with no reason set reports a readable reason");

    DirectGate_Desktop_SetReason(&desktop, "no X display");
    CHECK(strcmp(DirectGate_Desktop_GetReason(&desktop), "no X display") == 0,
        "a reason that was set is reported verbatim");
    DirectGate_Desktop_SetReason(&desktop, NULL);
    CHECK(strcmp(DirectGate_Desktop_GetReason(&desktop), "desktop unavailable") == 0,
        "clearing the reason falls back to the readable default");

    DirectGate_Desktop_SetFallbackReason(&desktop, "browser saw no video");
    CHECK(strcmp(desktop.sFallbackReason, "browser saw no video") == 0,
        "a fallback reason that was set is kept verbatim");
    DirectGate_Desktop_SetFallbackReason(&desktop, NULL);
    CHECK(desktop.sFallbackReason[0] == '\0',
        "clearing the fallback reason leaves it empty, not defaulted");

    DirectGate_Desktop_SetReason(NULL, "ignored");
    DirectGate_Desktop_SetFallbackReason(NULL, "ignored");
    return 0;
}

static int test_presets(void)
{
    directgate_desktop_t desktop;
    memset(&desktop, 0, sizeof(desktop));

    DirectGate_Desktop_ApplyPreset(&desktop, DIRECTGATE_DESKTOP_PRESET_LOW_LATENCY);
    CHECK(desktop.quality.nMaxEdge == 1280U && desktop.quality.nFps == 60U,
        "the low-latency preset is the 720p60 gaming path");
    CHECK(desktop.quality.bRealtime, "the low-latency preset asks the encoder for realtime hints");
    CHECK(desktop.nFps == desktop.quality.nFps,
        "the capture rate follows the preset rather than lagging a preset behind");
    CHECK(desktop.quality.nBaseBitrateKbps == desktop.quality.nBitrateKbps,
        "the preset records its own rate as the base the size scaling starts from");
    CHECK(desktop.nCurrentBitrateKbps == desktop.quality.nBitrateKbps,
        "the live rate starts at the preset target");
    CHECK(desktop.bRequestKeyframe,
        "a preset change asks for a keyframe so the viewer is not left on a stale GOP");

    DirectGate_Desktop_ApplyPreset(&desktop, DIRECTGATE_DESKTOP_PRESET_QUALITY);
    CHECK(desktop.quality.nMaxEdge == 1920U && desktop.quality.nFps == 30U,
        "the quality preset is the unscaled 1080p path");
    CHECK(!desktop.quality.bRealtime, "the quality preset trades latency hints for picture");

    /* Whatever the browser sends, an unrecognised preset has to land on a
     * working configuration, not on zeroes. */
    DirectGate_Desktop_ApplyPreset(&desktop, (directgate_desktop_preset_t)99);
    CHECK(desktop.quality.ePreset == DIRECTGATE_DESKTOP_PRESET_BALANCED,
        "an unknown preset is recorded as balanced rather than kept as-is");
    CHECK(desktop.quality.nMaxEdge == 1920U && desktop.quality.nFps == 30U &&
        desktop.quality.nBitrateKbps == 8000U,
        "an unknown preset gets the balanced settings");

    /* The ABR history belongs to the old rate; keeping it would let a preset
     * change inherit another preset's congestion evidence. */
    desktop.nAbrCleanEvidence = 5;
    desktop.nAbrHoldTicks = 5;
    desktop.nAbrLossReports = 5;
    DirectGate_Desktop_ApplyPreset(&desktop, DIRECTGATE_DESKTOP_PRESET_BALANCED);
    CHECK(!desktop.nAbrCleanEvidence && !desktop.nAbrHoldTicks && !desktop.nAbrLossReports,
        "a preset change clears the adaptive bitrate history");

    DirectGate_Desktop_ApplyPreset(NULL, DIRECTGATE_DESKTOP_PRESET_BALANCED);
    return 0;
}

static int test_bitrate_for_size(void)
{
    directgate_desktop_t desktop;
    memset(&desktop, 0, sizeof(desktop));
    DirectGate_Desktop_ApplyPreset(&desktop, DIRECTGATE_DESKTOP_PRESET_BALANCED);

    const uint32_t nBase = desktop.quality.nBaseBitrateKbps;

    CHECK(DirectGate_Desktop_BitrateForSize(NULL, 1920, 1080) == 0,
        "a missing desktop produces no bitrate");
    CHECK(DirectGate_Desktop_BitrateForSize(&desktop, 1280, 720) == nBase,
        "a frame below the reference size keeps the preset rate");
    CHECK(DirectGate_Desktop_BitrateForSize(&desktop, 1920, 1080) == nBase,
        "a frame at exactly the reference size keeps the preset rate");
    CHECK(DirectGate_Desktop_BitrateForSize(&desktop, 0, 0) == nBase,
        "a zero-area frame keeps the preset rate rather than dividing by it");

    uint32_t nScaled = DirectGate_Desktop_BitrateForSize(&desktop, 2560, 1440);
    CHECK(nScaled > nBase, "a frame above the reference size scales the rate up");
    CHECK(nScaled == (uint32_t)(((uint64_t)nBase * 2560 * 1440) / (1920ULL * 1080ULL)),
        "the rate scales with pixel count");

    /* Without the ceiling a video wall would ask a link for an arbitrary rate. */
    CHECK(DirectGate_Desktop_BitrateForSize(&desktop, 7680, 4320) == nBase * 2U,
        "a very large frame is capped at twice the preset rate");
    CHECK(DirectGate_Desktop_BitrateForSize(&desktop, 8192, 8192) == nBase * 2U,
        "the largest encodable frame is still capped at twice the preset rate");

    /* The scaling starts from the preset figure every time, so applying it
     * twice must not compound. */
    DirectGate_Desktop_ApplyBitrateForSize(&desktop, 2560, 1440);
    uint32_t nOnce = desktop.quality.nBitrateKbps;
    DirectGate_Desktop_ApplyBitrateForSize(&desktop, 2560, 1440);
    CHECK(desktop.quality.nBitrateKbps == nOnce,
        "scaling the rate for the same size twice does not compound");
    CHECK(desktop.nCurrentBitrateKbps == nOnce,
        "the live rate follows the scaled target");

    DirectGate_Desktop_ApplyBitrateForSize(&desktop, 1280, 720);
    CHECK(desktop.quality.nBitrateKbps == nBase,
        "shrinking the encode size returns the rate to the preset figure");

    memset(&desktop, 0, sizeof(desktop));
    CHECK(DirectGate_Desktop_BitrateForSize(&desktop, 1920, 1080) == 0,
        "a desktop with no preset applied produces no bitrate");
    DirectGate_Desktop_ApplyBitrateForSize(&desktop, 1920, 1080);
    CHECK(desktop.quality.nBitrateKbps == 0,
        "a bitrate that could not be computed is not written back");
    DirectGate_Desktop_ApplyBitrateForSize(NULL, 1920, 1080);

    return 0;
}

static int test_output_size(void)
{
    directgate_desktop_t desktop;
    uint32_t nWidth = 0;
    uint32_t nHeight = 0;

    memset(&desktop, 0, sizeof(desktop));
    desktop.ePipeline = DIRECTGATE_DESKTOP_PIPELINE_H264_DC;
    desktop.eResizeMode = DIRECTGATE_DESKTOP_RESIZE_SCALE;
    DirectGate_Desktop_ApplyPreset(&desktop, DIRECTGATE_DESKTOP_PRESET_QUALITY);

    DirectGate_Desktop_ComputeOutputSize(&desktop, 1920, 1080, &nWidth, &nHeight);
    CHECK(nWidth == 1920 && nHeight == 1080,
        "a source at the preset edge is encoded unscaled");

    DirectGate_Desktop_ComputeOutputSize(&desktop, 3840, 2160, &nWidth, &nHeight);
    CHECK(nWidth == 1920 && nHeight == 1080,
        "a source above the preset edge is scaled down keeping its aspect");

    DirectGate_Desktop_ComputeOutputSize(&desktop, 1080, 3840, &nWidth, &nHeight);
    CHECK(nHeight == 1920 && nWidth == 540,
        "a portrait source is limited on its own long edge");

    /* Zero is what an encoder that has not reported a size yet hands over. */
    DirectGate_Desktop_ComputeOutputSize(&desktop, 0, 0, &nWidth, &nHeight);
    CHECK(nWidth == 1 && nHeight == 1,
        "a zero-sized source produces a usable one-pixel frame, never zero");

    DirectGate_Desktop_ComputeOutputSize(NULL, 3840, 2160, &nWidth, &nHeight);
    CHECK(nWidth > 0 && nHeight > 0 && nWidth <= DIRECTGATE_DESKTOP_MAX_ENCODE_EDGE,
        "a missing desktop still produces a bounded frame");

    DirectGate_Desktop_ComputeOutputSize(&desktop, 1920, 1080, NULL, NULL);

    /* Display mode means the OS was already asked for this size, so a second
     * scaler would defeat the mode - but the absolute ceiling still applies. */
    desktop.eResizeMode = DIRECTGATE_DESKTOP_RESIZE_DISPLAY;
    DirectGate_Desktop_ComputeOutputSize(&desktop, 3840, 2160, &nWidth, &nHeight);
    CHECK(nWidth == 3840 && nHeight == 2160,
        "display mode encodes the captured size without a second scaler");

    DirectGate_Desktop_ComputeOutputSize(&desktop, 16384, 4096, &nWidth, &nHeight);
    CHECK(nWidth == DIRECTGATE_DESKTOP_MAX_ENCODE_EDGE && nHeight == 2048,
        "display mode is still held under the absolute encode ceiling");

    DirectGate_Desktop_ComputeOutputSize(&desktop, 4096, 16384, &nWidth, &nHeight);
    CHECK(nHeight == DIRECTGATE_DESKTOP_MAX_ENCODE_EDGE && nWidth == 2048,
        "the absolute encode ceiling applies to the tall axis too");

    DirectGate_Desktop_ComputeOutputSize(&desktop, 32768, 32768, &nWidth, &nHeight);
    CHECK(nWidth <= DIRECTGATE_DESKTOP_MAX_ENCODE_EDGE && nHeight <= DIRECTGATE_DESKTOP_MAX_ENCODE_EDGE,
        "a video wall on both axes is held under the ceiling on both axes");

    /* The browser's aspect-fit box. */
    desktop.eResizeMode = DIRECTGATE_DESKTOP_RESIZE_SCALE;
    desktop.nTargetWidth = 1280;
    desktop.nTargetHeight = 1280;
    DirectGate_Desktop_ComputeOutputSize(&desktop, 1920, 1080, &nWidth, &nHeight);
    CHECK(nWidth == 1280 && nHeight == 720,
        "a viewer box fits the source by its wider axis");

    desktop.nTargetWidth = 1920;
    desktop.nTargetHeight = 1080;
    DirectGate_Desktop_ComputeOutputSize(&desktop, 1280, 720, &nWidth, &nHeight);
    CHECK(nWidth == 1280 && nHeight == 720,
        "a viewer box larger than the source never asks the host to upscale");

    desktop.nTargetWidth = 8192;
    desktop.nTargetHeight = 8192;
    DirectGate_Desktop_ComputeOutputSize(&desktop, 16384, 16384, &nWidth, &nHeight);
    CHECK(nWidth <= DIRECTGATE_DESKTOP_MAX_ENCODE_EDGE && nHeight <= DIRECTGATE_DESKTOP_MAX_ENCODE_EDGE,
        "the largest viewer box a request can carry stays under the encode ceiling");

    /* The raw path converts every pixel on the CPU, so the balanced preset is
     * capped harder there than the preset's own edge. */
    memset(&desktop, 0, sizeof(desktop));
    desktop.ePipeline = DIRECTGATE_DESKTOP_PIPELINE_RAW;
    desktop.eResizeMode = DIRECTGATE_DESKTOP_RESIZE_SCALE;
    DirectGate_Desktop_ApplyPreset(&desktop, DIRECTGATE_DESKTOP_PRESET_BALANCED);
    DirectGate_Desktop_ComputeOutputSize(&desktop, 3840, 2160, &nWidth, &nHeight);
    CHECK(nWidth == DIRECTGATE_DESKTOP_RAW_BALANCED_EDGE,
        "the raw balanced path is capped below the preset edge");

    desktop.ePipeline = DIRECTGATE_DESKTOP_PIPELINE_H264_DC;
    DirectGate_Desktop_ComputeOutputSize(&desktop, 3840, 2160, &nWidth, &nHeight);
    CHECK(nWidth == 1920, "the encoded path keeps the preset edge");

    return 0;
}

static int test_frame_size(void)
{
    directgate_desktop_t desktop;
    memset(&desktop, 0, sizeof(desktop));
    DirectGate_Desktop_ApplyPreset(&desktop, DIRECTGATE_DESKTOP_PRESET_QUALITY);

    desktop.nScreenWidth = 3840;
    desktop.nScreenHeight = 2160;
    DirectGate_Desktop_ComputeFrameSize(&desktop);
    CHECK(desktop.nFrameWidth == 1920 && desktop.nFrameHeight == 1080,
        "with no capture rectangle the frame is derived from the screen");

    desktop.nCaptureWidth = 1280;
    desktop.nCaptureHeight = 720;
    DirectGate_Desktop_ComputeFrameSize(&desktop);
    CHECK(desktop.nFrameWidth == 1280 && desktop.nFrameHeight == 720,
        "a capture rectangle wins over the whole screen");

    memset(&desktop, 0, sizeof(desktop));
    DirectGate_Desktop_ComputeFrameSize(&desktop);
    CHECK(desktop.nFrameWidth > 0 && desktop.nFrameHeight > 0,
        "a desktop with no geometry at all still reports a usable frame size");

    uint32_t nWidth = 0;
    uint32_t nHeight = 0;
    DirectGate_Desktop_LimitFrameSize(&desktop, &nWidth, &nHeight);
    CHECK(nWidth > 0 && nHeight > 0, "limiting a zero frame produces a usable one");
    DirectGate_Desktop_LimitFrameSize(&desktop, NULL, NULL);

    return 0;
}

static int test_resize_request(void)
{
    directgate_desktop_t desktop;
    memset(&desktop, 0, sizeof(desktop));
    desktop.eResizeMode = DIRECTGATE_DESKTOP_RESIZE_SCALE;

    xjson_obj_t *pRoot = XJSON_NewObject(NULL, NULL, XFALSE);
    CHECK(pRoot != NULL, "build a resize request");

    XJSON_AddString(pRoot, "mode", "display");
    XJSON_AddString(pRoot, "resolution", "1920x1080");
    XJSON_AddU32(pRoot, "settingsRevision", 4);
    XJSON_AddU32(pRoot, "width", 1280);
    XJSON_AddU32(pRoot, "height", 720);

    DirectGate_Desktop_ReadResizeRequest(&desktop, pRoot);
    CHECK(desktop.eResizeMode == DIRECTGATE_DESKTOP_RESIZE_DISPLAY, "the resize mode is applied");
    CHECK(strcmp(desktop.sResolution, "1920x1080") == 0, "the requested resolution is recorded");
    CHECK(desktop.nSettingsRevision == 4, "the settings revision is recorded");
    CHECK(desktop.nTargetWidth == 1280 && desktop.nTargetHeight == 720,
        "a viewer box inside the bounds is applied");
    XJSON_FreeObject(pRoot);

    /* Every rejected field has to leave the previous, working value alone -
     * a half-applied request is what produces a frame nobody can decode. */
    struct {
        uint32_t nWidth;
        uint32_t nHeight;
        const char *pMsg;
    } refused[] = {
        { 0,     720,   "a request with no width is refused" },
        { 1280,  0,     "a request with no height is refused" },
        { 8193,  720,   "a width past the bound is refused" },
        { 1280,  8193,  "a height past the bound is refused" },
        { 65535, 65535, "a wildly oversized box is refused" }
    };

    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
    {
        pRoot = XJSON_NewObject(NULL, NULL, XFALSE);
        CHECK(pRoot != NULL, "build a refused resize request");
        XJSON_AddU32(pRoot, "width", refused[i].nWidth);
        XJSON_AddU32(pRoot, "height", refused[i].nHeight);
        DirectGate_Desktop_ReadResizeRequest(&desktop, pRoot);
        XJSON_FreeObject(pRoot);

        CHECK(desktop.nTargetWidth == 1280 && desktop.nTargetHeight == 720, refused[i].pMsg);
    }

    /* The largest box the bound allows is accepted exactly. */
    pRoot = XJSON_NewObject(NULL, NULL, XFALSE);
    CHECK(pRoot != NULL, "build a boundary resize request");
    XJSON_AddU32(pRoot, "width", 8192);
    XJSON_AddU32(pRoot, "height", 8192);
    DirectGate_Desktop_ReadResizeRequest(&desktop, pRoot);
    XJSON_FreeObject(pRoot);
    CHECK(desktop.nTargetWidth == 8192 && desktop.nTargetHeight == 8192,
        "a viewer box at exactly the bound is applied");

    /* An unknown mode leaves the current one, rather than falling to scale. */
    pRoot = XJSON_NewObject(NULL, NULL, XFALSE);
    CHECK(pRoot != NULL, "build a request with an unknown mode");
    XJSON_AddString(pRoot, "mode", "wobble");
    XJSON_AddU32(pRoot, "settingsRevision", 0);
    DirectGate_Desktop_ReadResizeRequest(&desktop, pRoot);
    XJSON_FreeObject(pRoot);
    CHECK(desktop.eResizeMode == DIRECTGATE_DESKTOP_RESIZE_DISPLAY,
        "an unknown resize mode leaves the active one alone");
    CHECK(desktop.nSettingsRevision == 4,
        "a zero settings revision does not roll the recorded one back");

    DirectGate_Desktop_ReadResizeRequest(NULL, NULL);
    DirectGate_Desktop_ReadResizeRequest(&desktop, NULL);
    return 0;
}

static int test_monitors(void)
{
    directgate_desktop_t desktop;
    memset(&desktop, 0, sizeof(desktop));

    DirectGate_Desktop_AddMonitor(&desktop, "all", "All displays", 0, 0, 3840, 1080, XFALSE);
    DirectGate_Desktop_AddMonitor(&desktop, "monitor-1", "Left", 0, 0, 1920, 1080, XTRUE);
    DirectGate_Desktop_AddMonitor(&desktop, "monitor-2", NULL, 1920, 0, 1920, 1080, XFALSE);
    CHECK(desktop.nMonitorCount == 3, "each monitor takes one slot");
    CHECK(strcmp(desktop.monitors[2].sName, desktop.monitors[2].sId) == 0,
        "a monitor with no name falls back to its id");

    /* A monitor with no usable geometry would hand the capture path a zero
     * rectangle, so it must not take a slot at all. */
    DirectGate_Desktop_AddMonitor(&desktop, "monitor-3", "Broken", 0, 0, 0, 1080, XFALSE);
    DirectGate_Desktop_AddMonitor(&desktop, "monitor-3", "Broken", 0, 0, 1920, 0, XFALSE);
    CHECK(desktop.nMonitorCount == 3, "a monitor with a zero edge is not recorded");

    DirectGate_Desktop_AddMonitor(NULL, "monitor-x", "x", 0, 0, 1920, 1080, XFALSE);

    while (desktop.nMonitorCount < DIRECTGATE_DESKTOP_MAX_MONITORS)
        DirectGate_Desktop_AddMonitor(&desktop, "filler", "Filler", 0, 0, 640, 480, XFALSE);

    DirectGate_Desktop_AddMonitor(&desktop, "overflow", "Overflow", 0, 0, 640, 480, XFALSE);
    CHECK(desktop.nMonitorCount == DIRECTGATE_DESKTOP_MAX_MONITORS,
        "a monitor past the table size is dropped rather than written past the end");

    CHECK(DirectGate_Desktop_FindMonitor(&desktop, "monitor-1") == &desktop.monitors[1],
        "a known monitor id resolves to its entry");
    CHECK(DirectGate_Desktop_FindMonitor(&desktop, "monitor-9") == NULL,
        "an unknown monitor id resolves to nothing");
    CHECK(DirectGate_Desktop_FindMonitor(&desktop, "") == NULL,
        "an empty monitor id resolves to nothing");
    CHECK(DirectGate_Desktop_FindMonitor(&desktop, NULL) == NULL,
        "a missing monitor id resolves to nothing");
    CHECK(DirectGate_Desktop_FindMonitor(NULL, "monitor-1") == NULL,
        "a missing desktop resolves no monitor");

    directgate_desktop_monitor_t *pMonitor = &desktop.monitors[1];
    DirectGate_Desktop_AddMonitorMode(pMonitor, 1920, 1080);
    DirectGate_Desktop_AddMonitorMode(pMonitor, 1920, 1080);
    CHECK(pMonitor->nModeCount == 1, "a repeated mode is recorded once");

    DirectGate_Desktop_AddMonitorMode(pMonitor, 1280, 720);
    CHECK(pMonitor->nModeCount == 2, "a distinct mode is recorded");
    DirectGate_Desktop_AddMonitorMode(pMonitor, 0, 720);
    DirectGate_Desktop_AddMonitorMode(pMonitor, 1280, 0);
    DirectGate_Desktop_AddMonitorMode(NULL, 1280, 720);
    CHECK(pMonitor->nModeCount == 2, "a mode with a zero edge is not recorded");

    for (uint32_t i = 0; pMonitor->nModeCount < DIRECTGATE_DESKTOP_MAX_MODES; i++)
        DirectGate_Desktop_AddMonitorMode(pMonitor, 100 + i, 100 + i);

    DirectGate_Desktop_AddMonitorMode(pMonitor, 4096, 4096);
    CHECK(pMonitor->nModeCount == DIRECTGATE_DESKTOP_MAX_MODES,
        "a mode past the table size is dropped rather than written past the end");

    /* Re-enumeration after a hot-plug rewinds the count and refills the table.
       The slot has to come back clean on its own: a mode list left over from
       whichever display held the slot before would be offered to the viewer as
       this display's, and every one of them would fail to set. */
    DirectGate_Desktop_AddMonitorMode(&desktop.monitors[0], 3840, 1080);
    desktop.monitors[0].nNativeId = 77;
    xstrncpy(desktop.monitors[0].sDeviceId, sizeof(desktop.monitors[0].sDeviceId), "77");

    desktop.nMonitorCount = 0;
    DirectGate_Desktop_AddMonitor(&desktop, "monitor-1", "Replacement", 0, 0, 1280, 1024, XTRUE);
    CHECK(desktop.monitors[0].nModeCount == 0,
        "a reused monitor slot does not inherit the previous display's modes");
    CHECK(desktop.monitors[0].nNativeId == 0,
        "a reused monitor slot does not inherit the previous display's native id");
    CHECK(desktop.monitors[0].sDeviceId[0] == '\0',
        "a reused monitor slot does not inherit the previous display's device id");
    CHECK(desktop.monitors[0].nWidth == 1280 && desktop.monitors[0].nHeight == 1024,
        "a reused monitor slot carries the new display's geometry");

    return 0;
}

static int test_capture_rect(void)
{
    directgate_desktop_t desktop;
    memset(&desktop, 0, sizeof(desktop));
    DirectGate_Desktop_ApplyPreset(&desktop, DIRECTGATE_DESKTOP_PRESET_QUALITY);
    desktop.nScreenWidth = 3840;
    desktop.nScreenHeight = 1080;

    DirectGate_Desktop_SetCapture(&desktop, "monitor-2", 1920, 0, 1920, 1080);
    CHECK(desktop.bCaptureReady, "setting a capture rectangle marks the capture ready");
    CHECK(desktop.nCaptureX == 1920 && desktop.nCaptureWidth == 1920,
        "the capture rectangle is recorded as given");
    CHECK(strcmp(desktop.sSelectedMonitor, "monitor-2") == 0, "the selected monitor is recorded");
    CHECK(desktop.nFrameWidth == 1920 && desktop.nFrameHeight == 1080,
        "setting the capture rectangle recomputes the frame size");

    /* A zero edge means "the whole screen", not "nothing". */
    DirectGate_Desktop_SetCapture(&desktop, NULL, 0, 0, 0, 0);
    CHECK(desktop.nCaptureWidth == 3840 && desktop.nCaptureHeight == 1080,
        "a capture rectangle with no size covers the whole screen");
    CHECK(strcmp(desktop.sSelectedMonitor, "all") == 0,
        "a capture with no monitor id selects all displays");
    DirectGate_Desktop_SetCapture(NULL, "all", 0, 0, 0, 0);

    /* Cursor positions are reported in screen space; when one monitor is being
     * captured the viewer must not be told about pixels outside it. */
    int nX = 0;
    int nY = 0;
    CHECK(!DirectGate_Desktop_ClampCursorToCapture(&desktop, &nX, &nY),
        "capturing all displays needs no cursor clamping");

    DirectGate_Desktop_SetCapture(&desktop, "monitor-2", 1920, 0, 1920, 1080);
    nX = 100; nY = 100;
    CHECK(DirectGate_Desktop_ClampCursorToCapture(&desktop, &nX, &nY),
        "a cursor left of the captured monitor is clamped");
    CHECK(nX == 1920 && nY == 100, "clamping moves only the axis that was outside");

    nX = 9000; nY = 9000;
    CHECK(DirectGate_Desktop_ClampCursorToCapture(&desktop, &nX, &nY),
        "a cursor past the captured monitor is clamped");
    CHECK(nX == 3839 && nY == 1079, "clamping lands on the last pixel inside the rectangle");

    nX = 2000; nY = 500;
    CHECK(!DirectGate_Desktop_ClampCursorToCapture(&desktop, &nX, &nY),
        "a cursor already inside the rectangle is reported unchanged");
    CHECK(nX == 2000 && nY == 500, "an unclamped cursor keeps its position");

    CHECK(!DirectGate_Desktop_ClampCursorToCapture(NULL, &nX, &nY),
        "a missing desktop clamps nothing");
    CHECK(!DirectGate_Desktop_ClampCursorToCapture(&desktop, NULL, NULL),
        "a missing cursor position clamps nothing");

    return 0;
}

static int test_backpressure(void)
{
    directgate_session_t session;
    memset(&session, 0, sizeof(session));

    CHECK(!DirectGate_Desktop_ShouldSkipForBackpressure(NULL),
        "a missing session never skips a frame");

    /* On the WebRTC video track the transport does its own pacing, so the
     * data-channel buffer is not the signal to act on. */
    session.desktop.ePipeline = DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO;
    CHECK(!DirectGate_Desktop_ShouldSkipForBackpressure(&session),
        "the webrtc video pipeline never skips on the data-channel buffer");

    /* With no data channel open there is nothing to be behind on. */
    session.desktop.ePipeline = DIRECTGATE_DESKTOP_PIPELINE_H264_DC;
    CHECK(DirectGate_WebRTC_GetBufferedAmount(&session.webrtc) < 0,
        "a closed data channel reports no buffered amount");
    CHECK(!DirectGate_Desktop_ShouldSkipForBackpressure(&session),
        "a closed data channel never skips a frame");

    /* Without a data channel the frames go out on the shared relay socket,
       whose queue nothing used to bound. Behind on it, a frame is dropped and
       the picture restarts from a keyframe once the relay has caught up. */
    xapi_session_t relay;
    memset(&relay, 0, sizeof(relay));
    XByteBuffer_Init(&relay.txBuffer, XSTDNON, XFALSE);
    session.pWsSession = &relay;

    const uint8_t sFrame[] = { 0, 0, 0, 1, 0x65, 0x88 };
    CHECK(!DirectGate_Desktop_RelayIsBacklogged(&session), "an empty relay queue is not backlogged");

    g_nSends = 0;
    g_nKeyframeRequests = 0;
    CHECK(DirectGate_Desktop_SendEncodedFrame(&session, sFrame, sizeof(sFrame), 64, 64, XTRUE, 1) == XAPI_CONTINUE,
        "a frame goes out on a relay that keeps up");
    CHECK(g_nSends == 1 && g_nKeyframeRequests == 0, "a relay that keeps up gets every frame");

    size_t nBacklog = 2U * 1024U * 1024U;
    uint8_t *pBacklog = (uint8_t*)calloc(1, nBacklog);
    CHECK(pBacklog != NULL, "allocate a stand-in relay backlog");
    CHECK(XByteBuffer_Add(&relay.txBuffer, pBacklog, nBacklog) > 0, "back the relay socket up");
    free(pBacklog);

    CHECK(DirectGate_Desktop_RelayIsBacklogged(&session), "a relay two megabytes behind is backlogged");
    CHECK(DirectGate_Desktop_SendEncodedFrame(&session, sFrame, sizeof(sFrame), 64, 64, XFALSE, 2) == XAPI_CONTINUE,
        "a frame for a backlogged relay is not an error");
    CHECK(g_nSends == 1, "nothing more is queued behind a backlogged relay");
    CHECK(g_nKeyframeRequests == 1, "a dropped frame asks the encoder for a fresh keyframe");

    XByteBuffer_Clear(&relay.txBuffer);
    session.pWsSession = NULL;
    return 0;
}

int main(void)
{
    if (test_names()) return 1;
    if (test_presets()) return 1;
    if (test_bitrate_for_size()) return 1;
    if (test_output_size()) return 1;
    if (test_frame_size()) return 1;
    if (test_resize_request()) return 1;
    if (test_monitors()) return 1;
    if (test_capture_rect()) return 1;
    if (test_backpressure()) return 1;

    puts("desktop_frame_smoke: OK");
    return 0;
}
