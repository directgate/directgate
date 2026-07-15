/*!
 * @file directgate-agent/src/agent/desktop_mac.m
 * @brief macOS ScreenCaptureKit + VideoToolbox H.264 encoder for desktop streaming.
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

#import <Foundation/Foundation.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <VideoToolbox/VideoToolbox.h>

#include <dlfcn.h>

#if __has_include(<ScreenCaptureKit/ScreenCaptureKit.h>)
#import <ScreenCaptureKit/ScreenCaptureKit.h>
#define DIRECTGATE_SCK_AVAILABLE 1
#else
#define DIRECTGATE_SCK_AVAILABLE 0
#endif

#include "desktop.h"
#include "session.h"

#if !DIRECTGATE_SCK_AVAILABLE

/* SDK too old to provide ScreenCaptureKit. The encoder API is still
 * compiled as failing stubs so desktop.c falls back to raw RGBA cleanly. */

void* DirectGate_Desktop_MacCaptureImage(int32_t nX, int32_t nY,
                                     uint32_t nWidth, uint32_t nHeight,
                                     char *pError, size_t nErrorSize)
{
    CGRect rect = CGRectMake((CGFloat)nX, (CGFloat)nY,
                             (CGFloat)nWidth, (CGFloat)nHeight);
    CGImageRef image = CGWindowListCreateImage(rect,
        kCGWindowListOptionOnScreenOnly, kCGNullWindowID,
        kCGWindowImageBoundsIgnoreFraming);
    if (image == NULL && pError != NULL && nErrorSize > 0)
        snprintf(pError, nErrorSize, "CoreGraphics screen capture failed.");
    return image;
}

int DirectGate_Desktop_MacEncoder_Start(directgate_session_t *pSession,
                                    int32_t nX, int32_t nY,
                                    uint32_t nWidth, uint32_t nHeight)
{
    (void)nX;
    (void)nY;
    (void)nWidth;
    (void)nHeight;

    if (pSession != NULL)
    {
        xstrncpy(pSession->desktop.sReason, sizeof(pSession->desktop.sReason),
            "ScreenCaptureKit is not available on this SDK; falling back to raw RGBA.");
    }

    return -1;
}

int DirectGate_Desktop_MacEncoder_UpdateRect(directgate_session_t *pSession,
                                        int32_t nX, int32_t nY,
                                        uint32_t nWidth, uint32_t nHeight)
{
    (void)pSession; (void)nX; (void)nY; (void)nWidth; (void)nHeight;
    return -1;
}

void DirectGate_Desktop_MacEncoder_ApplyQuality(directgate_session_t *pSession) { (void)pSession; }
void DirectGate_Desktop_MacEncoder_RequestKeyframe(directgate_session_t *pSession) { (void)pSession; }
void DirectGate_Desktop_MacEncoder_Stop(directgate_session_t *pSession) { (void)pSession; }
void DirectGate_Desktop_MacEncoder_StopDesktop(directgate_desktop_t *pDesktop) { (void)pDesktop; }
void DirectGate_Desktop_MacEncoder_SetBitrate(directgate_session_t *pSession, uint32_t nBitrateKbps)
{ (void)pSession; (void)nBitrateKbps; }

const char* DirectGate_Desktop_MacEncoder_LastError(const directgate_session_t *pSession)
{
    (void)pSession;
    return "ScreenCaptureKit is not available on this SDK.";
}

int DirectGate_Desktop_MacEncoder_DrainMain(directgate_session_t *pSession)
{
    (void)pSession;
    return XAPI_CONTINUE;
}

#else  /* DIRECTGATE_SCK_AVAILABLE */

typedef CGImageRef (*DirectGateLegacyCaptureFn)(CGRect, CGWindowListOption,
                                                CGWindowID, CGWindowImageOption);

static CGImageRef DirectGate_Desktop_MacCaptureLegacy(CGRect rect)
{
    /* Referencing CGWindowListCreateImage directly is a compile error with the
     * macOS 15 SDK. Resolve it only for systems older than ScreenCaptureKit's
     * screenshot API, where the symbol is still supported. */
    DirectGateLegacyCaptureFn capture = (DirectGateLegacyCaptureFn)dlsym(
        RTLD_DEFAULT, "CGWindowListCreateImage");
    return capture ? capture(rect, kCGWindowListOptionOnScreenOnly,
        kCGNullWindowID, kCGWindowImageBoundsIgnoreFraming) : NULL;
}

static CGImageRef DirectGate_Desktop_MacWaitForScreenshot(
    SCContentFilter *filter, SCStreamConfiguration *config,
    char *pError, size_t nErrorSize) API_AVAILABLE(macos(14.0));

static CGImageRef DirectGate_Desktop_MacWaitForScreenshot(
    SCContentFilter *filter, SCStreamConfiguration *config,
    char *pError, size_t nErrorSize)
{
    __block CGImageRef result = NULL;
    __block NSError *captureError = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    [SCScreenshotManager captureImageWithFilter:filter
                                   configuration:config
                               completionHandler:^(CGImageRef image, NSError *error) {
        if (image != NULL) result = CGImageRetain(image);
        captureError = error;
        dispatch_semaphore_signal(sem);
    }];

    if (dispatch_semaphore_wait(sem,
        dispatch_time(DISPATCH_TIME_NOW, 5LL * NSEC_PER_SEC)) != 0)
    {
        if (pError != NULL && nErrorSize > 0)
            snprintf(pError, nErrorSize, "ScreenCaptureKit screenshot timed out (5s).");
        return NULL;
    }

    if (result == NULL && pError != NULL && nErrorSize > 0)
        snprintf(pError, nErrorSize, "ScreenCaptureKit screenshot failed: %s",
            captureError ? captureError.localizedDescription.UTF8String : "unknown");
    return result;
}

void* DirectGate_Desktop_MacCaptureImage(int32_t nX, int32_t nY,
                                     uint32_t nWidth, uint32_t nHeight,
                                     char *pError, size_t nErrorSize)
{
    if (pError != NULL && nErrorSize > 0) pError[0] = '\0';
    if (nWidth == 0 || nHeight == 0)
    {
        if (pError != NULL && nErrorSize > 0)
            snprintf(pError, nErrorSize, "Empty macOS capture rectangle.");
        return NULL;
    }

    CGRect rect = CGRectMake((CGFloat)nX, (CGFloat)nY,
                             (CGFloat)nWidth, (CGFloat)nHeight);

    if (@available(macOS 15.2, *))
    {
        __block CGImageRef result = NULL;
        __block NSError *captureError = nil;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);

        [SCScreenshotManager captureImageInRect:rect
                              completionHandler:^(CGImageRef image, NSError *error) {
            if (image != NULL) result = CGImageRetain(image);
            captureError = error;
            dispatch_semaphore_signal(sem);
        }];

        if (dispatch_semaphore_wait(sem,
            dispatch_time(DISPATCH_TIME_NOW, 5LL * NSEC_PER_SEC)) != 0)
        {
            if (pError != NULL && nErrorSize > 0)
                snprintf(pError, nErrorSize, "ScreenCaptureKit screenshot timed out (5s).");
            return NULL;
        }

        if (result == NULL && pError != NULL && nErrorSize > 0)
            snprintf(pError, nErrorSize, "ScreenCaptureKit screenshot failed: %s",
                captureError ? captureError.localizedDescription.UTF8String : "unknown");
        return result;
    }

    if (@available(macOS 14.0, *))
    {
        __block SCShareableContent *content = nil;
        __block NSError *contentError = nil;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        [SCShareableContent getShareableContentExcludingDesktopWindows:NO
                                                  onScreenWindowsOnly:NO
                                             completionHandler:^(SCShareableContent *c,
                                                                 NSError *error) {
            content = c;
            contentError = error;
            dispatch_semaphore_signal(sem);
        }];

        if (dispatch_semaphore_wait(sem,
            dispatch_time(DISPATCH_TIME_NOW, 5LL * NSEC_PER_SEC)) != 0)
        {
            if (pError != NULL && nErrorSize > 0)
                snprintf(pError, nErrorSize, "ScreenCaptureKit content query timed out (5s).");
            return NULL;
        }

        SCDisplay *target = nil;
        for (SCDisplay *display in content.displays)
        {
            if (CGRectContainsPoint(display.frame, rect.origin) ||
                CGRectIntersectsRect(display.frame, rect))
            {
                target = display;
                break;
            }
        }

        if (contentError != nil || target == nil)
        {
            if (pError != NULL && nErrorSize > 0)
                snprintf(pError, nErrorSize, "ScreenCaptureKit content query failed: %s",
                    contentError ? contentError.localizedDescription.UTF8String : "no matching display");
            return NULL;
        }

        CGRect clipped = CGRectIntersection(rect, target.frame);
        SCContentFilter *filter = [[SCContentFilter alloc]
            initWithDisplay:target excludingWindows:@[]];
        SCStreamConfiguration *config = [[SCStreamConfiguration alloc] init];
        config.pixelFormat = kCVPixelFormatType_32BGRA;
        config.sourceRect = CGRectMake(clipped.origin.x - target.frame.origin.x,
            clipped.origin.y - target.frame.origin.y,
            clipped.size.width, clipped.size.height);
        config.width = (size_t)ceil(clipped.size.width);
        config.height = (size_t)ceil(clipped.size.height);
        config.scalesToFit = YES;
        config.showsCursor = YES;
        return DirectGate_Desktop_MacWaitForScreenshot(filter, config,
            pError, nErrorSize);
    }

    CGImageRef legacy = DirectGate_Desktop_MacCaptureLegacy(rect);
    if (legacy == NULL && pError != NULL && nErrorSize > 0)
        snprintf(pError, nErrorSize, "CoreGraphics screen capture failed.");
    return legacy;
}

@class DirectGateDesktopEncoder;

API_AVAILABLE(macos(12.3))
@interface DirectGateDesktopEncoder : NSObject <SCStreamDelegate, SCStreamOutput>
@property (nonatomic) directgate_session_t *session;          /* main thread only */
@property (nonatomic) directgate_desktop_t *desktop;           /* main thread only */
@property (nonatomic, strong) SCStream *stream;
@property (nonatomic, strong) dispatch_queue_t sampleQueue;
@property (nonatomic) VTCompressionSessionRef vtSession;
@property (nonatomic) CMVideoFormatDescriptionRef formatDesc;
@property (nonatomic) uint32_t encodeWidth;
@property (nonatomic) uint32_t encodeHeight;
@property (nonatomic) uint32_t captureWidth;
@property (nonatomic) uint32_t captureHeight;
@property (nonatomic) int32_t captureX;
@property (nonatomic) int32_t captureY;
@property (nonatomic) BOOL hasSentParameterSets;
@property (nonatomic) BOOL requestKeyframe;
@property (nonatomic) NSMutableData *encodedScratch;
@property (nonatomic, strong) NSMutableString *lastError;
@property (nonatomic) uint64_t framePtsCounter;
@property (nonatomic) CGDirectDisplayID displayId;
@property (nonatomic, strong) SCContentFilter *filter;
/* Mailbox between sample queue (producer) and main loop (consumer).
 * Older frames are dropped if the consumer is behind. */
@property (nonatomic, strong) NSLock *mailboxLock;
@property (nonatomic) NSMutableData *mailboxPayload;
@property (nonatomic) uint32_t mailboxWidth;
@property (nonatomic) uint32_t mailboxHeight;
@property (nonatomic) BOOL mailboxKeyframe;
@property (nonatomic) uint64_t mailboxPtsUs;
@property (nonatomic) BOOL mailboxHasFrame;
@end

static void DirectGateDesktopEncoder_SetError(DirectGateDesktopEncoder *enc, const char *msg)
{
    if (!enc || !msg) return;
    if (enc.lastError == nil) enc.lastError = [NSMutableString string];
    [enc.lastError setString:[NSString stringWithUTF8String:msg]];
    if (enc.desktop) xstrncpy(enc.desktop->sReason, sizeof(enc.desktop->sReason), msg);
}

static OSStatus DirectGateDesktopEncoder_EmitAnnexB(NSMutableData *out, const uint8_t *src, size_t len);

static void DirectGateDesktopEncoder_VTCallback(void *outputCallbackRefCon,
                                            void *sourceFrameRefCon,
                                            OSStatus status,
                                            VTEncodeInfoFlags infoFlags,
                                            CMSampleBufferRef sampleBuffer);

API_AVAILABLE(macos(12.3))
@implementation DirectGateDesktopEncoder

- (instancetype)init
{
    self = [super init];
    if (self)
    {
        _sampleQueue = dispatch_queue_create("directgate.desktop.capture", DISPATCH_QUEUE_SERIAL);
        _encodedScratch = [NSMutableData dataWithCapacity:256 * 1024];
        _hasSentParameterSets = NO;
        _requestKeyframe = YES;
        _vtSession = NULL;
        _formatDesc = NULL;
        _mailboxLock = [[NSLock alloc] init];
        _mailboxPayload = [NSMutableData dataWithCapacity:256 * 1024];
        _mailboxHasFrame = NO;
    }
    return self;
}

- (void)dealloc
{
    [self teardownEncoder];
    [self stopStream];
}

- (void)teardownEncoder
{
    if (_vtSession != NULL)
    {
        VTCompressionSessionInvalidate(_vtSession);
        CFRelease(_vtSession);
        _vtSession = NULL;
    }

    if (_formatDesc != NULL)
    {
        CFRelease(_formatDesc);
        _formatDesc = NULL;
    }

    _hasSentParameterSets = NO;
}

- (void)stopStream
{
    if (_stream)
    {
        SCStream *s = _stream;
        _stream = nil;
        [s stopCaptureWithCompletionHandler:^(NSError * _Nullable error){ (void)error; }];
    }
}

- (BOOL)createVTSessionWithError:(char *)errBuf bufSize:(size_t)bufSize
{
    if (_vtSession != NULL)
    {
        VTCompressionSessionInvalidate(_vtSession);
        CFRelease(_vtSession);
        _vtSession = NULL;
    }

    OSStatus status = VTCompressionSessionCreate(
        kCFAllocatorDefault,
        (int32_t)_encodeWidth, (int32_t)_encodeHeight,
        kCMVideoCodecType_H264,
        NULL, NULL, kCFAllocatorDefault,
        DirectGateDesktopEncoder_VTCallback,
        (__bridge void *)self,
        &_vtSession);

    if (status != noErr || _vtSession == NULL)
    {
        if (errBuf) snprintf(errBuf, bufSize,
            "VTCompressionSessionCreate failed (status=%d)", (int)status);
        return NO;
    }

    BOOL realtime = _desktop && _desktop->quality.bRealtime;
    VTSessionSetProperty(_vtSession, kVTCompressionPropertyKey_RealTime,
        realtime ? kCFBooleanTrue : kCFBooleanFalse);
    VTSessionSetProperty(_vtSession, kVTCompressionPropertyKey_AllowFrameReordering,
        kCFBooleanFalse);

    /* Main profile + CABAC is supported by every WebCodecs H.264 decoder
     * and gives ~10–15% better quality at the same bitrate vs Baseline —
     * which matters for readable text. We only step down to Baseline for
     * the low-latency preset where slice complexity matters more. */
    VTSessionSetProperty(_vtSession, kVTCompressionPropertyKey_ProfileLevel,
        realtime && (_desktop && _desktop->quality.ePreset == DIRECTGATE_DESKTOP_PRESET_LOW_LATENCY)
            ? kVTProfileLevel_H264_Baseline_AutoLevel
            : kVTProfileLevel_H264_Main_AutoLevel);

    if (!(realtime && (_desktop && _desktop->quality.ePreset == DIRECTGATE_DESKTOP_PRESET_LOW_LATENCY)))
    {
        VTSessionSetProperty(_vtSession, kVTCompressionPropertyKey_H264EntropyMode,
            kVTH264EntropyMode_CABAC);
    }

    uint32_t bitrateKbps = _desktop ? _desktop->quality.nBitrateKbps : 4000U;
    if (bitrateKbps == 0) bitrateKbps = 4000U;
    int32_t averageBitsPerSecond = (int32_t)(bitrateKbps * 1000U);
    CFNumberRef bitrateNum = CFNumberCreate(NULL, kCFNumberSInt32Type, &averageBitsPerSecond);
    VTSessionSetProperty(_vtSession, kVTCompressionPropertyKey_AverageBitRate, bitrateNum);
    CFRelease(bitrateNum);

    /* Cap the data rate so we don't blow past WebRTC backpressure on busy
     * frames. 1.5x the average is a reasonable burst. */
    int64_t dataLimit[2] = {
        (int64_t)((averageBitsPerSecond * 3) / 16),  /* bytes / 500ms */
        1
    };

    CFNumberRef bytes = CFNumberCreate(NULL, kCFNumberSInt64Type, &dataLimit[0]);
    CFNumberRef seconds = CFNumberCreate(NULL, kCFNumberSInt64Type, &dataLimit[1]);
    const void *valuesArr[2] = { bytes, seconds };
    CFArrayRef dataRateLimits = CFArrayCreate(NULL, valuesArr, 2, &kCFTypeArrayCallBacks);
    VTSessionSetProperty(_vtSession, kVTCompressionPropertyKey_DataRateLimits, dataRateLimits);
    CFRelease(dataRateLimits);
    CFRelease(bytes);
    CFRelease(seconds);

    uint32_t keyEvery = _desktop ? _desktop->quality.nKeyframeFrames : 60U;
    if (keyEvery == 0) keyEvery = 60U;
    int32_t maxKey = (int32_t)keyEvery;
    CFNumberRef keyInterval = CFNumberCreate(NULL, kCFNumberSInt32Type, &maxKey);
    VTSessionSetProperty(_vtSession, kVTCompressionPropertyKey_MaxKeyFrameInterval, keyInterval);
    CFRelease(keyInterval);

    uint32_t fps = _desktop ? _desktop->quality.nFps : 30U;
    if (fps == 0) fps = 30U;
    int32_t expectedFps = (int32_t)fps;
    CFNumberRef fpsNum = CFNumberCreate(NULL, kCFNumberSInt32Type, &expectedFps);
    VTSessionSetProperty(_vtSession, kVTCompressionPropertyKey_ExpectedFrameRate, fpsNum);
    CFRelease(fpsNum);

    /* Pin colour metadata so the decoder/compositor doesn't have to guess
     * the colour space of every decoded frame. Modern WebCodecs decoders
     * honour these tags and skip an extra colour conversion pass. */
    VTSessionSetProperty(_vtSession, kVTCompressionPropertyKey_ColorPrimaries,
        kCVImageBufferColorPrimaries_ITU_R_709_2);
    VTSessionSetProperty(_vtSession, kVTCompressionPropertyKey_TransferFunction,
        kCVImageBufferTransferFunction_ITU_R_709_2);
    VTSessionSetProperty(_vtSession, kVTCompressionPropertyKey_YCbCrMatrix,
        kCVImageBufferYCbCrMatrix_ITU_R_709_2);

    /* Tell VT this is a long-running stream so its rate controller settles
     * into steady-state rather than treating each frame as start-of-clip. */
    int32_t hint = (int32_t)(_desktop ? _desktop->quality.nFps * 4U : 120U);
    CFNumberRef morePending = CFNumberCreate(NULL, kCFNumberSInt32Type, &hint);
    VTSessionSetProperty(_vtSession,
        kVTCompressionPropertyKey_MoreFramesBeforeStart, kCFBooleanTrue);
    VTSessionSetProperty(_vtSession,
        kVTCompressionPropertyKey_MoreFramesAfterEnd, kCFBooleanTrue);
    CFRelease(morePending);

    VTCompressionSessionPrepareToEncodeFrames(_vtSession);
    _hasSentParameterSets = NO;
    _requestKeyframe = YES;
    return YES;
}

- (BOOL)startWithDisplay:(CGDirectDisplayID)display
                    rect:(CGRect)rect
                  errBuf:(char *)errBuf
                 bufSize:(size_t)bufSize
{
    _displayId = display;
    _captureX = (int32_t)floor(rect.origin.x);
    _captureY = (int32_t)floor(rect.origin.y);
    _captureWidth = (uint32_t)ceil(rect.size.width);
    _captureHeight = (uint32_t)ceil(rect.size.height);

    if (_captureWidth == 0 || _captureHeight == 0)
    {
        if (errBuf) snprintf(errBuf, bufSize, "Empty capture rectangle.");
        return NO;
    }

    _encodeWidth = _captureWidth;
    _encodeHeight = _captureHeight;

    DirectGate_Desktop_ComputeOutputSize(_desktop, _captureWidth, _captureHeight, &_encodeWidth, &_encodeHeight);
    if (_encodeWidth == 0 || _encodeHeight == 0)
    {
        _encodeWidth = _captureWidth;
        _encodeHeight = _captureHeight;
    }

    /* H.264 requires even dimensions; round down. */
    _encodeWidth  &= ~1U;
    _encodeHeight &= ~1U;
    if (_encodeWidth < 16) _encodeWidth = 16;
    if (_encodeHeight < 16) _encodeHeight = 16;

    if (![self createVTSessionWithError:errBuf bufSize:bufSize])
        return NO;

    /* Set up SCStream with the chosen display. */
    __block SCShareableContent *content = nil;
    __block NSError *contentError = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    [SCShareableContent getShareableContentExcludingDesktopWindows:NO
                                              onScreenWindowsOnly:NO
                                                 completionHandler:^(SCShareableContent * _Nullable c,
                                                                     NSError * _Nullable e) {
        content = c;
        contentError = e;
        dispatch_semaphore_signal(sem);
    }];

    /* 5s upper bound — first call to SCK can prompt the user. */
    if (dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 5LL * NSEC_PER_SEC)) != 0)
    {
        if (errBuf) snprintf(errBuf, bufSize, "ScreenCaptureKit content query timed out (5s).");
        return NO;
    }

    if (contentError || !content)
    {
        if (errBuf) snprintf(errBuf, bufSize, "ScreenCaptureKit content query failed: %s",
            contentError ? contentError.localizedDescription.UTF8String : "unknown");
        return NO;
    }

    SCDisplay *target = nil;
    for (SCDisplay *d in content.displays)
    {
        if (d.displayID == display) { target = d; break; }
    }

    if (!target && content.displays.count > 0)
        target = content.displays.firstObject;

    if (!target)
    {
        if (errBuf) snprintf(errBuf, bufSize, "No SCDisplay available for capture.");
        return NO;
    }

    _filter = [[SCContentFilter alloc] initWithDisplay:target excludingWindows:@[]];
    SCStreamConfiguration *config = [[SCStreamConfiguration alloc] init];

    /* The encoder consumes BGRA — let SCK do the colour conversion. */
    config.pixelFormat = kCVPixelFormatType_32BGRA;
    config.width  = _encodeWidth;
    config.height = _encodeHeight;
    config.minimumFrameInterval = CMTimeMake(1, (int32_t)(_desktop ? _desktop->quality.nFps : 30));
    config.queueDepth = 3;
    config.scalesToFit = YES;
    config.showsCursor = YES;

    _stream = [[SCStream alloc] initWithFilter:_filter
                                 configuration:config
                                      delegate:self];
    NSError *addError = nil;
    if (![_stream addStreamOutput:self
                              type:SCStreamOutputTypeScreen
                sampleHandlerQueue:_sampleQueue
                             error:&addError])
    {
        if (errBuf) snprintf(errBuf, bufSize, "SCStream addStreamOutput failed: %s",
            addError ? addError.localizedDescription.UTF8String : "unknown");
        return NO;
    }

    __block NSError *startError = nil;
    dispatch_semaphore_t startSem = dispatch_semaphore_create(0);

    [_stream startCaptureWithCompletionHandler:^(NSError * _Nullable e) {
        startError = e;
        dispatch_semaphore_signal(startSem);
    }];

    if (dispatch_semaphore_wait(startSem, dispatch_time(DISPATCH_TIME_NOW, 5LL * NSEC_PER_SEC)) != 0)
    {
        if (errBuf) snprintf(errBuf, bufSize, "SCStream startCapture timed out (5s).");
        return NO;
    }

    if (startError)
    {
        if (errBuf) snprintf(errBuf, bufSize, "SCStream startCapture failed: %s",
            startError.localizedDescription.UTF8String);
        return NO;
    }

    return YES;
}

- (void)applyQualityUpdate
{
    if (_vtSession == NULL) return;

    uint32_t bitrateKbps = _desktop ? _desktop->quality.nBitrateKbps : 4000U;
    if (bitrateKbps == 0) bitrateKbps = 4000U;
    int32_t bps = (int32_t)(bitrateKbps * 1000U);
    CFNumberRef bitrate = CFNumberCreate(NULL, kCFNumberSInt32Type, &bps);
    VTSessionSetProperty(_vtSession, kVTCompressionPropertyKey_AverageBitRate, bitrate);
    CFRelease(bitrate);

    uint32_t fps = _desktop ? _desktop->quality.nFps : 30U;
    if (fps == 0) fps = 30U;
    int32_t expectedFps = (int32_t)fps;
    CFNumberRef fpsNum = CFNumberCreate(NULL, kCFNumberSInt32Type, &expectedFps);
    VTSessionSetProperty(_vtSession, kVTCompressionPropertyKey_ExpectedFrameRate, fpsNum);
    CFRelease(fpsNum);

    uint32_t keyEvery = _desktop ? _desktop->quality.nKeyframeFrames : 60U;
    if (keyEvery == 0) keyEvery = 60U;
    int32_t maxKey = (int32_t)keyEvery;
    CFNumberRef keyInterval = CFNumberCreate(NULL, kCFNumberSInt32Type, &maxKey);
    VTSessionSetProperty(_vtSession, kVTCompressionPropertyKey_MaxKeyFrameInterval, keyInterval);
    CFRelease(keyInterval);

    if (_stream)
    {
        SCStreamConfiguration *config = [[SCStreamConfiguration alloc] init];
        config.pixelFormat = kCVPixelFormatType_32BGRA;
        config.width  = _encodeWidth;
        config.height = _encodeHeight;
        config.minimumFrameInterval = CMTimeMake(1, (int32_t)fps);
        config.queueDepth = 3;
        config.scalesToFit = YES;
        config.showsCursor = YES;
        [_stream updateConfiguration:config completionHandler:^(NSError * _Nullable e) { (void)e; }];
    }

    _requestKeyframe = YES;
}

- (void)applyBitrateOnly:(uint32_t)bitrateKbps
{
    /* Live bitrate step from the adaptive controller. Deliberately does
     * not request a keyframe: the encoder keeps the reference chain and
     * simply converges to the new rate, so a congested link is not hit
     * with an IDR burst on top of the loss that triggered the step. */
    if (_vtSession == NULL || bitrateKbps == 0) return;

    int32_t bps = (int32_t)(bitrateKbps * 1000U);
    CFNumberRef bitrate = CFNumberCreate(NULL, kCFNumberSInt32Type, &bps);
    VTSessionSetProperty(_vtSession, kVTCompressionPropertyKey_AverageBitRate, bitrate);
    CFRelease(bitrate);

    /* Keep the burst cap in step with the new average (same 1.5x budget as createVTSessionWithError). */
    int64_t dataLimit[2] = { (int64_t)(((int64_t)bps * 3) / 16), 1 };
    CFNumberRef bytes = CFNumberCreate(NULL, kCFNumberSInt64Type, &dataLimit[0]);
    CFNumberRef seconds = CFNumberCreate(NULL, kCFNumberSInt64Type, &dataLimit[1]);

    const void *valuesArr[2] = { bytes, seconds };
    CFArrayRef limits = CFArrayCreate(NULL, valuesArr, 2, &kCFTypeArrayCallBacks);
    VTSessionSetProperty(_vtSession, kVTCompressionPropertyKey_DataRateLimits, limits);

    CFRelease(limits);
    CFRelease(bytes);
    CFRelease(seconds);
}

- (void)markKeyframeRequested
{
    _requestKeyframe = YES;
}

#pragma mark - SCStreamOutput

- (void)stream:(SCStream *)stream
   didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
   ofType:(SCStreamOutputType)type
{
    if (type != SCStreamOutputTypeScreen) return;
    if (!CMSampleBufferIsValid(sampleBuffer)) return;
    if (_vtSession == NULL) return;

    /* Drop the incoming capture if the previous encoded frame hasn't been
     * picked up by the main loop yet. Because we did not call
     * VTCompressionSessionEncodeFrame, the encoder's reference chain is
     * unaffected — no keyframe is required on resume. */
    BOOL skipDueToBacklog = NO;
    [_mailboxLock lock];
    skipDueToBacklog = _mailboxHasFrame;
    [_mailboxLock unlock];
    if (skipDueToBacklog) return;

    /* Same logic for transport backpressure: skipping the capture leaves
     * the reference chain intact, so do not request a keyframe on the next
     * encode. */
    if (_session && DirectGate_Desktop_ShouldSkipForBackpressure(_session))
        return;

    CVImageBufferRef pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer);
    if (!pixelBuffer) return;

    /* Skip frames flagged as not visible / black by SCK. */
    CFArrayRef attachments = CMSampleBufferGetSampleAttachmentsArray(sampleBuffer, NO);
    if (attachments && CFArrayGetCount(attachments) > 0)
    {
        CFDictionaryRef attachment = (CFDictionaryRef)CFArrayGetValueAtIndex(attachments, 0);
        CFTypeRef statusValue = CFDictionaryGetValue(attachment, (__bridge CFStringRef)@"SCStreamFrameInfoStatus");
        if (statusValue && CFGetTypeID(statusValue) == CFNumberGetTypeID())
        {
            int statusInt = 0;
            CFNumberGetValue((CFNumberRef)statusValue, kCFNumberIntType, &statusInt);
            /* SCFrameStatusComplete == 0; anything else means "no new pixels". */
            if (statusInt != 0) return;
        }
    }

    CMTime pts = CMSampleBufferGetPresentationTimeStamp(sampleBuffer);
    if (!CMTIME_IS_VALID(pts))
        pts = CMTimeMake((int64_t)(++_framePtsCounter), 1000);

    NSDictionary *frameProps = nil;
    if (_requestKeyframe)
    {
        frameProps = @{ (__bridge NSString *)kVTEncodeFrameOptionKey_ForceKeyFrame : @YES };
        _requestKeyframe = NO;
    }

    OSStatus status = VTCompressionSessionEncodeFrame(
        _vtSession,
        pixelBuffer,
        pts,
        kCMTimeInvalid,
        (__bridge CFDictionaryRef)frameProps,
        NULL,
        NULL);

    if (status != noErr)
    {
        char buf[160];
        snprintf(buf, sizeof(buf), "VTCompressionSessionEncodeFrame failed (status=%d)", (int)status);
        DirectGateDesktopEncoder_SetError(self, buf);
    }
}

#pragma mark - SCStreamDelegate

- (void)stream:(SCStream *)stream didStopWithError:(NSError *)error
{
    (void)stream;
    if (error)
    {
        char buf[160];
        snprintf(buf, sizeof(buf), "SCStream stopped: %s", error.localizedDescription.UTF8String);
        DirectGateDesktopEncoder_SetError(self, buf);
    }
}

@end

/* Annex-B emission: convert AVCC-style 4-byte-length-prefixed NAL units into
 * Annex-B (0x00 00 00 01) sequences expected by browser WebCodecs decoders
 * configured with "avc1.*" + description = SPS/PPS, or by raw Annex-B feed. */
static OSStatus DirectGateDesktopEncoder_EmitAnnexB(NSMutableData *out, const uint8_t *src, size_t len)
{
    static const uint8_t startCode[4] = { 0x00, 0x00, 0x00, 0x01 };
    size_t cursor = 0;
    while (cursor + 4 <= len)
    {
        uint32_t nalSize = ((uint32_t)src[cursor] << 24)
                         | ((uint32_t)src[cursor + 1] << 16)
                         | ((uint32_t)src[cursor + 2] << 8)
                         |  (uint32_t)src[cursor + 3];
        cursor += 4;
        if (nalSize == 0 || cursor + nalSize > len) return -1;
        [out appendBytes:startCode length:sizeof(startCode)];
        [out appendBytes:src + cursor length:nalSize];
        cursor += nalSize;
    }
    return (cursor == len) ? noErr : -1;
}

API_AVAILABLE(macos(12.3))
static void DirectGateDesktopEncoder_HandleCompressed(DirectGateDesktopEncoder *enc,
                                                  CMSampleBufferRef sampleBuffer,
                                                  BOOL isKeyframe);

static void DirectGateDesktopEncoder_VTCallback(void *outputCallbackRefCon,
                                            void *sourceFrameRefCon,
                                            OSStatus status,
                                            VTEncodeInfoFlags infoFlags,
                                            CMSampleBufferRef sampleBuffer)
{
    (void)sourceFrameRefCon; (void)infoFlags;
    if (@available(macOS 12.3, *))
    {
        DirectGateDesktopEncoder *enc = (__bridge DirectGateDesktopEncoder *)outputCallbackRefCon;
        if (!enc) return;

        if (status != noErr || sampleBuffer == NULL || !CMSampleBufferDataIsReady(sampleBuffer))
            return;

        BOOL isKeyframe = YES;
        CFArrayRef attachments = CMSampleBufferGetSampleAttachmentsArray(sampleBuffer, NO);
        if (attachments && CFArrayGetCount(attachments) > 0)
        {
            CFDictionaryRef attachment = (CFDictionaryRef)CFArrayGetValueAtIndex(attachments, 0);
            if (CFDictionaryContainsKey(attachment, kCMSampleAttachmentKey_NotSync))
                isKeyframe = NO;
        }

        DirectGateDesktopEncoder_HandleCompressed(enc, sampleBuffer, isKeyframe);
    }
}

API_AVAILABLE(macos(12.3))
static void DirectGateDesktopEncoder_HandleCompressed(DirectGateDesktopEncoder *enc,
                                                  CMSampleBufferRef sampleBuffer,
                                                  BOOL isKeyframe)
{
    NSMutableData *out = enc.encodedScratch;
    [out setLength:0];

    /* Prepend SPS/PPS parameter sets on keyframes (or when we haven't sent
     * them yet). Browsers feeding raw Annex-B require parameter sets to
     * precede each IDR. */
    if (isKeyframe || !enc.hasSentParameterSets)
    {
        CMFormatDescriptionRef fmt = CMSampleBufferGetFormatDescription(sampleBuffer);
        size_t nparams = 0;
        int nalHeaderLen = 0;
        if (CMVideoFormatDescriptionGetH264ParameterSetAtIndex(fmt, 0, NULL, NULL, &nparams, &nalHeaderLen) == noErr)
        {
            static const uint8_t startCode[4] = { 0x00, 0x00, 0x00, 0x01 };
            for (size_t i = 0; i < nparams; i++)
            {
                const uint8_t *paramSet = NULL;
                size_t paramSize = 0;
                if (CMVideoFormatDescriptionGetH264ParameterSetAtIndex(fmt, i, &paramSet, &paramSize, NULL, NULL) == noErr)
                {
                    [out appendBytes:startCode length:sizeof(startCode)];
                    [out appendBytes:paramSet length:paramSize];
                }
            }
            enc.hasSentParameterSets = YES;
        }
    }

    CMBlockBufferRef blockBuffer = CMSampleBufferGetDataBuffer(sampleBuffer);
    if (!blockBuffer) return;

    size_t totalLen = 0;
    char *dataPtr = NULL;
    OSStatus rc = CMBlockBufferGetDataPointer(blockBuffer, 0, NULL, &totalLen, &dataPtr);
    if (rc != noErr || dataPtr == NULL) return;

    if (DirectGateDesktopEncoder_EmitAnnexB(out, (const uint8_t *)dataPtr, totalLen) != noErr)
        return;

    CMTime pts = CMSampleBufferGetPresentationTimeStamp(sampleBuffer);
    uint64_t ptsUs = 0;
    if (CMTIME_IS_VALID(pts))
        ptsUs = (uint64_t)(CMTimeGetSeconds(pts) * 1000000.0);

    /* Mailbox: copy the encoded NAL stream into the single-slot mailbox so
     * the main loop picks it up. The main loop owns DirectGate_Session_Send
     * (E2E counter, WebRTC + relay fallback), so we never call it here. */
    [enc.mailboxLock lock];
    [enc.mailboxPayload setLength:0];
    [enc.mailboxPayload appendBytes:out.bytes length:out.length];
    enc.mailboxWidth   = enc.encodeWidth;
    enc.mailboxHeight  = enc.encodeHeight;
    enc.mailboxKeyframe = isKeyframe;
    enc.mailboxPtsUs   = ptsUs;
    enc.mailboxHasFrame = YES;
    [enc.mailboxLock unlock];

    /* Wake the main loop via the existing timer pipe. */
    directgate_desktop_t *desktop = enc.desktop;
    if (desktop && desktop->nTimerWriteFd != XSOCK_INVALID)
    {
        const char wake = 'f';
        ssize_t w = write(desktop->nTimerWriteFd, &wake, sizeof(wake));
        (void)w;
    }
}

/* ------------------ C bridge ------------------ */

API_AVAILABLE(macos(12.3))
static DirectGateDesktopEncoder *encoderOf(directgate_session_t *pSession)
{
    if (!pSession) return nil;
    return (__bridge DirectGateDesktopEncoder *)pSession->desktop.pEncoder;
}

int DirectGate_Desktop_MacEncoder_Start(directgate_session_t *pSession,
                                    int32_t nX, int32_t nY,
                                    uint32_t nWidth, uint32_t nHeight)
{
    if (!pSession) return -1;
    if (@available(macOS 12.3, *))
    {
        DirectGate_Desktop_MacEncoder_Stop(pSession);

        DirectGateDesktopEncoder *enc = [[DirectGateDesktopEncoder alloc] init];
        enc.session = pSession;
        enc.desktop = &pSession->desktop;

        CGRect rect = CGRectMake((CGFloat)nX, (CGFloat)nY,
                                 (CGFloat)nWidth, (CGFloat)nHeight);
        /* Pick the display whose origin matches the rect origin (multi-monitor). */
        CGDirectDisplayID displays[DIRECTGATE_DESKTOP_MAX_MONITORS];
        uint32_t count = 0;
        CGDirectDisplayID picked = CGMainDisplayID();
        if (CGGetActiveDisplayList(DIRECTGATE_DESKTOP_MAX_MONITORS, displays, &count) == kCGErrorSuccess)
        {
            for (uint32_t i = 0; i < count; i++)
            {
                CGRect db = CGDisplayBounds(displays[i]);
                if (db.origin.x == nX && db.origin.y == nY)
                {
                    picked = displays[i];
                    break;
                }
            }
        }

        char err[160] = {0};
        if (![enc startWithDisplay:picked rect:rect errBuf:err bufSize:sizeof(err)])
        {
            xstrncpy(pSession->desktop.sReason, sizeof(pSession->desktop.sReason),
                err[0] ? err : "ScreenCaptureKit failed to start.");
            return -1;
        }

        pSession->desktop.pEncoder = (__bridge_retained void *)enc;
        return 0;
    }
    else
    {
        xstrncpy(pSession->desktop.sReason, sizeof(pSession->desktop.sReason),
            "ScreenCaptureKit requires macOS 12.3 or newer.");
        return -1;
    }
}

int DirectGate_Desktop_MacEncoder_UpdateRect(directgate_session_t *pSession,
                                        int32_t nX, int32_t nY,
                                        uint32_t nWidth, uint32_t nHeight)
{
    if (!pSession || !pSession->desktop.pEncoder) return -1;
    return DirectGate_Desktop_MacEncoder_Start(pSession, nX, nY, nWidth, nHeight);
}

void DirectGate_Desktop_MacEncoder_ApplyQuality(directgate_session_t *pSession)
{
    if (!pSession) return;
    if (@available(macOS 12.3, *))
    {
        DirectGateDesktopEncoder *enc = encoderOf(pSession);
        if (!enc) return;

        /* A preset switch can change quality.nMaxEdge, which changes the
         * encode resolution. VTCompressionSession and SCStream are created
         * at a fixed size, so recompute the dimensions the same way
         * startWithDisplay does and rebuild the whole capture+encode chain
         * when they differ; bitrate/fps/GOP-only updates apply live. */
        directgate_desktop_t *pDesktop = &pSession->desktop;
        uint32_t captureWidth = enc.captureWidth;
        uint32_t captureHeight = enc.captureHeight;
        int32_t captureX = enc.captureX;
        int32_t captureY = enc.captureY;

        uint32_t width = captureWidth;
        uint32_t height = captureHeight;
        DirectGate_Desktop_ComputeOutputSize(pDesktop, captureWidth, captureHeight,
            &width, &height);

        width  &= ~1U;
        height &= ~1U;

        if (width < 16) width = 16;
        if (height < 16) height = 16;

        if (width != enc.encodeWidth || height != enc.encodeHeight)
        {
            (void)DirectGate_Desktop_MacEncoder_Start(pSession,
                captureX, captureY, captureWidth, captureHeight);
            return;
        }

        [enc applyQualityUpdate];
    }
}

void DirectGate_Desktop_MacEncoder_SetBitrate(directgate_session_t *pSession, uint32_t nBitrateKbps)
{
    if (!pSession) return;
    if (@available(macOS 12.3, *))
    {
        DirectGateDesktopEncoder *enc = encoderOf(pSession);
        [enc applyBitrateOnly:nBitrateKbps];
    }
}

void DirectGate_Desktop_MacEncoder_RequestKeyframe(directgate_session_t *pSession)
{
    if (!pSession) return;
    if (@available(macOS 12.3, *))
    {
        DirectGateDesktopEncoder *enc = encoderOf(pSession);
        [enc markKeyframeRequested];
    }
}

void DirectGate_Desktop_MacEncoder_StopDesktop(directgate_desktop_t *pDesktop)
{
    if (!pDesktop || !pDesktop->pEncoder) return;
    if (@available(macOS 12.3, *))
    {
        DirectGateDesktopEncoder *enc = (__bridge_transfer DirectGateDesktopEncoder *)pDesktop->pEncoder;
        pDesktop->pEncoder = NULL;
        [enc teardownEncoder];
        [enc stopStream];
    }
    else
    {
        pDesktop->pEncoder = NULL;
    }
}

void DirectGate_Desktop_MacEncoder_Stop(directgate_session_t *pSession)
{
    if (!pSession) return;
    DirectGate_Desktop_MacEncoder_StopDesktop(&pSession->desktop);
}

const char* DirectGate_Desktop_MacEncoder_LastError(const directgate_session_t *pSession)
{
    if (!pSession) return "no session";
    if (xstrused(pSession->desktop.sReason)) return pSession->desktop.sReason;
    return "unknown";
}

/* Drain the mailbox: invoked from the main loop's DirectGate_Desktop_Process
 * once per timer-pipe wake-up. Sends every queued (≤ 1) encoded frame
 * through DirectGate_Session_Send. Returns XAPI_CONTINUE or a fatal status. */
int DirectGate_Desktop_MacEncoder_DrainMain(directgate_session_t *pSession)
{
    if (!pSession) return XAPI_CONTINUE;
    if (@available(macOS 12.3, *))
    {
        DirectGateDesktopEncoder *enc = encoderOf(pSession);
        if (!enc) return XAPI_CONTINUE;

        NSData *payload = nil;
        uint32_t w = 0, h = 0;
        BOOL keyframe = NO;
        uint64_t pts = 0;

        [enc.mailboxLock lock];
        if (enc.mailboxHasFrame)
        {
            payload = [NSData dataWithBytes:enc.mailboxPayload.bytes
                                     length:enc.mailboxPayload.length];
            w = enc.mailboxWidth;
            h = enc.mailboxHeight;
            keyframe = enc.mailboxKeyframe;
            pts = enc.mailboxPtsUs;
            enc.mailboxHasFrame = NO;
            [enc.mailboxPayload setLength:0];
        }
        [enc.mailboxLock unlock];

        if (payload && payload.length > 0)
        {
            return DirectGate_Desktop_SendEncodedFrame(pSession,
                (const uint8_t *)payload.bytes, payload.length,
                w, h, keyframe ? XTRUE : XFALSE, pts);
        }
    }

    return XAPI_CONTINUE;
}
#endif /* DIRECTGATE_SCK_AVAILABLE */
