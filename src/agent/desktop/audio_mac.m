/*!
 * @file directgate-agent/src/agent/desktop/audio_mac.m
 * @brief macOS system-audio capture backend (ScreenCaptureKit).
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
#import <CoreAudioTypes/CoreAudioTypes.h>
#import <ScreenCaptureKit/ScreenCaptureKit.h>

#include <pthread.h>
#include <time.h>
#include "audio.h"

#ifdef DIRECTGATE_DESKTOP_HAS_AUDIO

/* ScreenCaptureKit (macOS 13+) captures the system output mix directly via
 * SCStreamConfiguration.capturesAudio, so no virtual loopback device is needed
 * and only the default output is captured (never a microphone). SCK pushes
 * audio through the SCStreamOutput delegate on a dispatch queue; this bridges
 * that push model to the blocking BackendRead pull model with a ring buffer.
 * A minimal video configuration is required by SCStream but no screen output
 * handler is registered, so no frames are processed. */

#define DIRECTGATE_SCK_RING_FRAMES  (DIRECTGATE_AUDIO_SAMPLE_RATE * 2U) /* ~2 s */

@interface DirectGateAudioCapture : NSObject <SCStreamDelegate, SCStreamOutput>
{
@public
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int16_t *pRing;              /* interleaved S16 output samples */
    uint32_t nRingCap;
    uint32_t nRingHead;
    uint32_t nRingTail;
    uint32_t nRingCount;
}
@property (nonatomic, strong) SCStream *stream;
@property (nonatomic, strong) dispatch_queue_t queue;
- (BOOL)startWithError:(char *)pErr size:(size_t)nErrSize;
- (void)stop;
@end

@implementation DirectGateAudioCapture

- (instancetype)init
{
    self = [super init];
    if (self)
    {
        pthread_mutex_init(&lock, NULL);
        pthread_cond_init(&cond, NULL);
        nRingCap = DIRECTGATE_SCK_RING_FRAMES * DIRECTGATE_AUDIO_CHANNELS;
        pRing = (int16_t *)malloc((size_t)nRingCap * sizeof(int16_t));
        _queue = dispatch_queue_create("io.directgate.audio", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)dealloc
{
    free(pRing);
    pthread_cond_destroy(&cond);
    pthread_mutex_destroy(&lock);
}

/* Pushes one interleaved stereo S16 pair, dropping the oldest when full. */
- (void)pushL:(int16_t)nL r:(int16_t)nR
{
    pthread_mutex_lock(&lock);

    if (nRingCount + 2U > nRingCap)
    {
        nRingTail = (nRingTail + 2U) % nRingCap;
        nRingCount -= 2U;
    }

    pRing[nRingHead] = nL;
    pRing[(nRingHead + 1U) % nRingCap] = nR;
    nRingHead = (nRingHead + 2U) % nRingCap;
    nRingCount += 2U;

    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&lock);
}

static int16_t DirectGate_SCK_ClampS16(float fSample)
{
    float fScaled = fSample * 32767.0f;
    if (fScaled > 32767.0f) fScaled = 32767.0f;
    else if (fScaled < -32768.0f) fScaled = -32768.0f;
    return (int16_t)fScaled;
}

- (BOOL)startWithError:(char *)pErr size:(size_t)nErrSize
{
    if (@available(macOS 13.0, *))
    {
        if (pRing == NULL || _queue == NULL)
        {
            if (pErr) snprintf(pErr, nErrSize, "Failed to allocate audio capture resources.");
            return NO;
        }

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

        if (dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 5LL * NSEC_PER_SEC)) != 0)
        {
            if (pErr) snprintf(pErr, nErrSize, "ScreenCaptureKit content query timed out (5s).");
            return NO;
        }
        if (contentError || !content || content.displays.count == 0)
        {
            if (pErr) snprintf(pErr, nErrSize, "ScreenCaptureKit content query failed: %s",
                contentError ? contentError.localizedDescription.UTF8String : "no display");
            return NO;
        }

        SCDisplay *display = content.displays.firstObject;
        SCContentFilter *filter = [[SCContentFilter alloc] initWithDisplay:display excludingWindows:@[]];

        SCStreamConfiguration *config = [[SCStreamConfiguration alloc] init];
        config.capturesAudio = YES;
        config.sampleRate = DIRECTGATE_AUDIO_SAMPLE_RATE;
        config.channelCount = DIRECTGATE_AUDIO_CHANNELS;
        config.excludesCurrentProcessAudio = YES; /* never capture our own output */
        /* Minimal video: SCStream requires a display, but no screen output is
         * registered, so frames are never delivered or processed. */
        config.width = 2;
        config.height = 2;
        config.minimumFrameInterval = CMTimeMake(1, 1);
        config.queueDepth = 3;

        _stream = [[SCStream alloc] initWithFilter:filter configuration:config delegate:self];

        NSError *addError = nil;
        if (![_stream addStreamOutput:self
                                  type:SCStreamOutputTypeAudio
                    sampleHandlerQueue:_queue
                                 error:&addError])
        {
            if (pErr) snprintf(pErr, nErrSize, "SCStream addStreamOutput(audio) failed: %s",
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
            if (pErr) snprintf(pErr, nErrSize, "SCStream startCapture timed out (5s).");
            return NO;
        }

        if (startError)
        {
            if (pErr) snprintf(pErr, nErrSize, "SCStream startCapture failed: %s",
                startError.localizedDescription.UTF8String);
            return NO;
        }

        return YES;
    }

    if (pErr) snprintf(pErr, nErrSize, "System audio capture requires macOS 13 or newer.");
    return NO;
}

- (void)stop
{
    SCStream *s = _stream;
    _stream = nil;
    if (s == nil) return;

    dispatch_semaphore_t stopSem = dispatch_semaphore_create(0);
    [s stopCaptureWithCompletionHandler:^(NSError * _Nullable e) {
        (void)e;
        dispatch_semaphore_signal(stopSem);
    }];
    dispatch_semaphore_wait(stopSem, dispatch_time(DISPATCH_TIME_NOW, 3LL * NSEC_PER_SEC));

    /* Wake a blocked reader so BackendClose returns promptly. */
    pthread_mutex_lock(&lock);
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&lock);
}

#pragma mark - SCStreamOutput

- (void)stream:(SCStream *)stream
    didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
                   ofType:(SCStreamOutputType)type
{
    if (type != SCStreamOutputTypeAudio) return;
    if (!CMSampleBufferIsValid(sampleBuffer)) return;

    CMFormatDescriptionRef fmt = CMSampleBufferGetFormatDescription(sampleBuffer);
    if (fmt == NULL) return;
    const AudioStreamBasicDescription *asbd = CMAudioFormatDescriptionGetStreamBasicDescription(fmt);
    if (asbd == NULL) return;

    CMItemCount nFrames = CMSampleBufferGetNumSamples(sampleBuffer);
    if (nFrames <= 0) return;

    uint32_t nChannels = asbd->mChannelsPerFrame ? asbd->mChannelsPerFrame : 2U;
    BOOL bFloat = (asbd->mFormatFlags & kAudioFormatFlagIsFloat) != 0;
    BOOL bNonInterleaved = (asbd->mFormatFlags & kAudioFormatFlagIsNonInterleaved) != 0;
    uint32_t nBits = asbd->mBitsPerChannel ? asbd->mBitsPerChannel : 32U;

    struct { UInt32 mNumberBuffers; AudioBuffer mBuffers[8]; } abl;
    memset(&abl, 0, sizeof(abl));
    CMBlockBufferRef blockBuffer = NULL;
    size_t nNeeded = 0;
    OSStatus st = CMSampleBufferGetAudioBufferListWithRetainedBlockBuffer(
        sampleBuffer, &nNeeded, (AudioBufferList *)&abl, sizeof(abl),
        kCFAllocatorDefault, kCFAllocatorDefault,
        kCMSampleBufferFlag_AudioBufferList_Assure16ByteAlignment, &blockBuffer);
    if (st != noErr || blockBuffer == NULL) return;

    /* Only float32 (SCK's native audio format) is handled; other layouts are
     * ignored so a format surprise degrades to silence rather than noise. */
    if (bFloat && nBits == 32U)
    {
        if (bNonInterleaved && abl.mNumberBuffers >= 1)
        {
            const float *pL = (const float *)abl.mBuffers[0].mData;
            const float *pR = (abl.mNumberBuffers >= 2)
                ? (const float *)abl.mBuffers[1].mData : pL;
            for (CMItemCount i = 0; i < nFrames; i++)
                [self pushL:DirectGate_SCK_ClampS16(pL ? pL[i] : 0.0f)
                          r:DirectGate_SCK_ClampS16(pR ? pR[i] : 0.0f)];
        }
        else if (abl.mNumberBuffers >= 1 && abl.mBuffers[0].mData != NULL)
        {
            const float *p = (const float *)abl.mBuffers[0].mData;
            for (CMItemCount i = 0; i < nFrames; i++)
            {
                float fL = p[i * nChannels];
                float fR = (nChannels >= 2) ? p[i * nChannels + 1] : fL;
                [self pushL:DirectGate_SCK_ClampS16(fL) r:DirectGate_SCK_ClampS16(fR)];
            }
        }
    }

    CFRelease(blockBuffer);
}

- (void)stream:(SCStream *)stream didStopWithError:(NSError *)error
{
    (void)stream;
    (void)error;
}

@end

void* DirectGate_Audio_BackendOpen(uint32_t nSampleRate, uint32_t nChannels,
                                   char *pErr, size_t nErrSize)
{
    (void)nSampleRate;
    (void)nChannels;

    @autoreleasepool
    {
        DirectGateAudioCapture *pCapture = [[DirectGateAudioCapture alloc] init];
        if (![pCapture startWithError:pErr size:nErrSize])
            return NULL;

        xlogi("Opened desktop audio ScreenCaptureKit capture: rate(%u), channels(%u)",
            DIRECTGATE_AUDIO_SAMPLE_RATE, DIRECTGATE_AUDIO_CHANNELS);

        /* Transfer ownership to the C caller; BackendClose releases it. */
        return (void *)CFBridgingRetain(pCapture);
    }
}

int DirectGate_Audio_BackendRead(void *pBackend, int16_t *pBuf,
                                 uint32_t nFrames, uint32_t nChannels)
{
    XCHECK((pBackend != NULL && pBuf != NULL), XSTDERR);
    XCHECK((nFrames > 0 && nChannels > 0), XSTDERR);

    DirectGateAudioCapture *pCapture = (__bridge DirectGateAudioCapture *)pBackend;
    uint32_t nNeeded = nFrames * nChannels;
    uint32_t nGot = 0;

    pthread_mutex_lock(&pCapture->lock);

    /* Wait up to two frame periods for real samples; SCK pushes continuously
     * during playback, so a timeout only happens on silence - pad with silence
     * to keep a steady 20 ms cadence and let the worker observe a stop. */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t nNs = (uint64_t)ts.tv_nsec + (uint64_t)(2U * DIRECTGATE_AUDIO_FRAME_MS) * 1000000ULL;
    ts.tv_sec += (time_t)(nNs / 1000000000ULL);
    ts.tv_nsec = (long)(nNs % 1000000000ULL);

    while (pCapture->nRingCount < nNeeded)
    {
        if (pthread_cond_timedwait(&pCapture->cond, &pCapture->lock, &ts) != 0)
            break; /* timeout */
    }

    while (nGot < nNeeded && pCapture->nRingCount > 0)
    {
        pBuf[nGot++] = pCapture->pRing[pCapture->nRingTail];
        pCapture->nRingTail = (pCapture->nRingTail + 1U) % pCapture->nRingCap;
        pCapture->nRingCount--;
    }
    pthread_mutex_unlock(&pCapture->lock);

    while (nGot < nNeeded) pBuf[nGot++] = 0; /* silence pad */
    return XSTDOK;
}

void DirectGate_Audio_BackendClose(void *pBackend)
{
    if (pBackend == NULL) return;
    /* Reclaim the ownership transferred in BackendOpen; ARC releases when the
     * autorelease pool drains. */
    DirectGateAudioCapture *pCapture = (DirectGateAudioCapture *)CFBridgingRelease(pBackend);
    [pCapture stop];
    pCapture = nil;
}

#endif /* DIRECTGATE_DESKTOP_HAS_AUDIO */
