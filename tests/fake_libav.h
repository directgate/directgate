/*
 * Stand-ins for libavcodec, libavutil and libavfilter, for the GPU encoder tests.
 *
 * fake_libavcodec.c, fake_libavutil.c and fake_libavfilter.c are built as
 * shared libraries under the sonames the build's FFmpeg headers name and
 * linked into the test, so the agent's dlopen() of "libavcodec.so.N" and the
 * others finds them already loaded. Only the entry points hwenc.c reaches are
 * there. Contexts, frames, packets, buffers and filter graphs have FFmpeg's own
 * layout - hwenc.c reads and writes their fields - while the encoders, the GPU
 * devices they open, the conversion graph and the packets that come out of
 * them are whatever the test asks for.
 */

#ifndef DIRECTGATE_TESTS_FAKE_LIBAV_H
#define DIRECTGATE_TESTS_FAKE_LIBAV_H

#include <libavcodec/avcodec.h>
#include <libavutil/hwcontext.h>

#define FAKE_AV_MAX         8
#define FAKE_AV_MAX_PACKETS 16

/* What avcodec_receive_packet() answers next */
typedef enum {
    FAKE_AV_DELTA = 0,      /* a P slice; also the answer once the script runs out */
    FAKE_AV_KEY,            /* an IDR slice with no parameter sets in front of it */
    FAKE_AV_KEY_SPS,        /* an SPS, then an IDR slice */
    FAKE_AV_KEY_AUD,        /* an access unit delimiter, then an SPS and an IDR slice */
    FAKE_AV_KEY_BARE,       /* keyframe bytes without a single start code */
    FAKE_AV_EMPTY,          /* a packet with nothing in it */
    FAKE_AV_AGAIN,          /* EAGAIN: nothing out yet */
    FAKE_AV_FAIL            /* an error */
} fake_av_packet_t;

typedef struct {
    /* What the libraries have and do */
    const char *pEncoders[FAKE_AV_MAX];     /* encoder names this libavcodec has */
    const char *pDevices[FAKE_AV_MAX];      /* "type:device" that open, as "vaapi:" for VAAPI's default device */
    unsigned nCodecMajor;                   /* the major the libraries report, 0 for the headers' own */
    unsigned nUtilMajor;
    int bExtradata;                         /* an opened context carries Annex-B parameter sets */
    int bAvccExtradata;                     /* ... in the length-prefixed form instead */
    int bNoHwBuffer;                        /* av_hwframe_get_buffer() succeeds and hands back nothing */
    int bStrerrorFails;
    int nFailSends;                         /* this many frames are refused before they are taken again */
    fake_av_packet_t packets[FAKE_AV_MAX_PACKETS];
    int nPackets;
    unsigned nFilterMajor;                  /* libavfilter's major, 0 for the headers' own */
    int bNoScaleFilter;                     /* libavfilter has no scale_vaapi */
    int bScaleRejectsColour;                /* scale_vaapi predates the colour options */
    int bNoSinkFrames;                      /* a configured graph's output has no frame pool */
    int nSinkAgain;                         /* this many asks for a converted frame come back empty first */
    int nFailMaps;                          /* this many compositor frames are refused by the GPU */

    /* What the agent did */
    int nDeviceCreates;
    int nOpens;
    int nSends;
    int nOptions;
    enum AVPictureType eLastPict;
    int64_t nLastBitrate;                   /* the rate the last context opened at */
    int64_t nSendBitrate;                   /* and the one the last frame was sent at */
    int nLastFps;
    enum AVPixelFormat eLastPixFmt;
    char sLastOpened[32];
    int nMaps;                              /* compositor frames mapped onto the GPU */
    int nLastMapFd;                         /* and what the last one's descriptor said */
    uint64_t nLastMapModifier;
    int nLastMapPitch;
    int64_t nLastSourcePts;                 /* the timestamp the conversion graph was last given */
    char sScaleArgs[128];                   /* what the post-processor was last asked for */
} fake_av_t;

fake_av_t* fake_av(void);

/* Forgets the script and the record; what is still allocated stays counted */
void fake_av_reset(void);

/* The next call of the named entry point fails the way FFmpeg's does, or the n-th one from now */
void fake_av_fail_next(const char *pName);
void fake_av_fail_nth(const char *pName, int nNth);

/* Contexts, frames, packets and buffer references not freed yet */
int fake_av_live(void);

/* For a test whose encoder runs on a thread of its own: the libraries bump counters atomically and the test reads
   them with fake_av_get(); a budget or an encoder list the test changes while frames flow is set with these */
int fake_av_get(const int *pCounter);
void fake_av_set(int *pField, int nValue);
void fake_av_set_encoder(int nIndex, const char *pName);

/* Between the libraries */
int fake_av_should_fail(const char *pName);
void fake_av_count(int nDelta);
int fake_av_take(int *pBudget);             /* one from a "this many fail" budget, if any is left */
void fake_av_bump(int *pCounter);

#endif /* DIRECTGATE_TESTS_FAKE_LIBAV_H */
