/*
 * The libavutil part of fake_libav.h: buffers, frames, GPU devices and frame
 * pools, the DMA-BUF mapping, options, errors - and the state the parts share.
 */

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libavutil/avutil.h>
#include <libavutil/frame.h>
#include <libavutil/hwcontext_drm.h>
#include <libavutil/mem.h>
#include <libavutil/opt.h>

#include "fake_libav.h"

typedef struct {
    int nRefs;
    uint8_t *pData;
    void (*pFree)(void*, uint8_t*);     /* the owner's, for a buffer made around its memory */
    void *pOpaque;
} fake_av_buffer_t;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static fake_av_t g_av;
typedef struct {
    char sName[48];
    int nCountdown;
} fake_av_failure_t;

static fake_av_failure_t g_failures[FAKE_AV_MAX];
static int g_nLive;

/* ---------------- shared state ---------------- */

fake_av_t* fake_av(void)
{
    return &g_av;
}

void fake_av_reset(void)
{
    pthread_mutex_lock(&g_lock);
    memset(&g_av, 0, sizeof(g_av));
    memset(g_failures, 0, sizeof(g_failures));
    pthread_mutex_unlock(&g_lock);
}

void fake_av_fail_nth(const char *pName, int nNth)
{
    pthread_mutex_lock(&g_lock);

    for (int i = 0; i < FAKE_AV_MAX; i++)
    {
        if (g_failures[i].sName[0] != '\0') continue;
        strncpy(g_failures[i].sName, pName, sizeof(g_failures[i].sName) - 1);
        g_failures[i].nCountdown = nNth;
        break;
    }

    pthread_mutex_unlock(&g_lock);
}

void fake_av_fail_next(const char *pName)
{
    fake_av_fail_nth(pName, 1);
}

int fake_av_should_fail(const char *pName)
{
    int bFail = 0;
    pthread_mutex_lock(&g_lock);

    for (int i = 0; i < FAKE_AV_MAX && !bFail; i++)
    {
        if (strcmp(g_failures[i].sName, pName) != 0 || --g_failures[i].nCountdown > 0) continue;
        g_failures[i].sName[0] = '\0';
        bFail = 1;
    }

    pthread_mutex_unlock(&g_lock);
    return bFail;
}

void fake_av_count(int nDelta)
{
    pthread_mutex_lock(&g_lock);
    g_nLive += nDelta;
    pthread_mutex_unlock(&g_lock);
}

int fake_av_get(const int *pCounter)
{
    return __atomic_load_n(pCounter, __ATOMIC_SEQ_CST);
}

void fake_av_set(int *pField, int nValue)
{
    __atomic_store_n(pField, nValue, __ATOMIC_SEQ_CST);
}

void fake_av_set_encoder(int nIndex, const char *pName)
{
    __atomic_store_n(&g_av.pEncoders[nIndex], pName, __ATOMIC_SEQ_CST);
}

int fake_av_take(int *pBudget)
{
    int nLeft = __atomic_load_n(pBudget, __ATOMIC_SEQ_CST);
    while (nLeft > 0 && !__atomic_compare_exchange_n(pBudget, &nLeft, nLeft - 1, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {}
    return nLeft > 0;
}

void fake_av_bump(int *pCounter)
{
    __atomic_add_fetch(pCounter, 1, __ATOMIC_SEQ_CST);
}

int fake_av_live(void)
{
    pthread_mutex_lock(&g_lock);
    int nLive = g_nLive;
    pthread_mutex_unlock(&g_lock);
    return nLive;
}

/* ---------------- buffers ---------------- */

static AVBufferRef* fake_av_buffer_new(size_t nSize)
{
    fake_av_buffer_t *pBuffer = (fake_av_buffer_t*)calloc(1, sizeof(*pBuffer));
    AVBufferRef *pRef = (AVBufferRef*)calloc(1, sizeof(*pRef));
    uint8_t *pData = (uint8_t*)calloc(1, nSize ? nSize : 1);

    if (pBuffer == NULL || pRef == NULL || pData == NULL)
    {
        free(pBuffer);
        free(pRef);
        free(pData);
        return NULL;
    }

    pBuffer->nRefs = 1;
    pBuffer->pData = pData;
    pRef->buffer = (AVBuffer*)pBuffer;
    pRef->data = pData;
    pRef->size = nSize;

    fake_av_count(1);
    return pRef;
}

AVBufferRef* av_buffer_ref(const AVBufferRef *buf)
{
    if (buf == NULL || fake_av_should_fail("av_buffer_ref")) return NULL;

    AVBufferRef *pRef = (AVBufferRef*)calloc(1, sizeof(*pRef));
    if (pRef == NULL) return NULL;

    *pRef = *buf;
    ((fake_av_buffer_t*)buf->buffer)->nRefs++;
    fake_av_count(1);
    return pRef;
}

void av_buffer_unref(AVBufferRef **buf)
{
    if (buf == NULL || *buf == NULL) return;

    fake_av_buffer_t *pBuffer = (fake_av_buffer_t*)(*buf)->buffer;
    if (--pBuffer->nRefs == 0)
    {
        if (pBuffer->pFree != NULL) pBuffer->pFree(pBuffer->pOpaque, pBuffer->pData);
        else free(pBuffer->pData);
        free(pBuffer);
    }

    free(*buf);
    *buf = NULL;
    fake_av_count(-1);
}

/* av_buffer_create took an int length until libavutil 57 */
#if LIBAVUTIL_VERSION_MAJOR >= 57
AVBufferRef* av_buffer_create(uint8_t *data, size_t size, void (*free_cb)(void*, uint8_t*), void *opaque, int flags)
#else
AVBufferRef* av_buffer_create(uint8_t *data, int size, void (*free_cb)(void*, uint8_t*), void *opaque, int flags)
#endif
{
    (void)flags;
    if (fake_av_should_fail("av_buffer_create")) return NULL;

    fake_av_buffer_t *pBuffer = (fake_av_buffer_t*)calloc(1, sizeof(*pBuffer));
    AVBufferRef *pRef = (AVBufferRef*)calloc(1, sizeof(*pRef));
    if (pBuffer == NULL || pRef == NULL)
    {
        free(pBuffer);
        free(pRef);
        return NULL;
    }

    pBuffer->nRefs = 1;
    pBuffer->pData = data;
    pBuffer->pFree = free_cb;
    pBuffer->pOpaque = opaque;
    pRef->buffer = (AVBuffer*)pBuffer;
    pRef->data = data;
    pRef->size = size;

    fake_av_count(1);
    return pRef;
}

/* The agent frees nothing with it but the buffer source parameters fake_libavfilter.c counts as allocated */
void av_free(void *ptr)
{
    if (ptr == NULL) return;
    free(ptr);
    fake_av_count(-1);
}

/* ---------------- frames ---------------- */

AVFrame* av_frame_alloc(void)
{
    if (fake_av_should_fail("av_frame_alloc")) return NULL;

    AVFrame *pFrame = (AVFrame*)calloc(1, sizeof(*pFrame));
    if (pFrame == NULL) return NULL;

    pFrame->format = -1;
    fake_av_count(1);
    return pFrame;
}

void av_frame_unref(AVFrame *frame)
{
    if (frame == NULL) return;
    for (int i = 0; i < AV_NUM_DATA_POINTERS; i++) av_buffer_unref(&frame->buf[i]);
    av_buffer_unref(&frame->hw_frames_ctx);

    memset(frame->data, 0, sizeof(frame->data));
    memset(frame->linesize, 0, sizeof(frame->linesize));
    frame->pict_type = AV_PICTURE_TYPE_NONE;
    frame->pts = 0;
}

void av_frame_free(AVFrame **frame)
{
    if (frame == NULL || *frame == NULL) return;

    av_frame_unref(*frame);
    free(*frame);
    *frame = NULL;
    fake_av_count(-1);
}

/* NV12 only, which is all the agent asks for: a full-size luma plane and a half-height chroma plane after it */
int av_frame_get_buffer(AVFrame *frame, int align)
{
    (void)align;
    if (fake_av_should_fail("av_frame_get_buffer")) return AVERROR(ENOMEM);
    if (frame->width <= 0 || frame->height <= 0) return AVERROR(EINVAL);

    int nStride = (frame->width + 31) & ~31;
    frame->buf[0] = fake_av_buffer_new((size_t)nStride * (size_t)frame->height * 3U / 2U);
    if (frame->buf[0] == NULL) return AVERROR(ENOMEM);

    frame->data[0] = frame->buf[0]->data;
    frame->data[1] = frame->data[0] + (size_t)nStride * (size_t)frame->height;
    frame->linesize[0] = nStride;
    frame->linesize[1] = nStride;
    return 0;
}

int av_frame_ref(AVFrame *dst, const AVFrame *src)
{
    if (fake_av_should_fail("av_frame_ref")) return AVERROR(ENOMEM);

    for (int i = 0; i < AV_NUM_DATA_POINTERS; i++)
    {
        if (src->buf[i] == NULL) continue;
        if ((dst->buf[i] = av_buffer_ref(src->buf[i])) != NULL) continue;

        av_frame_unref(dst);
        return AVERROR(ENOMEM);
    }

    memcpy(dst->data, src->data, sizeof(dst->data));
    memcpy(dst->linesize, src->linesize, sizeof(dst->linesize));
    dst->format = src->format;
    dst->width = src->width;
    dst->height = src->height;
    dst->pts = src->pts;
    return 0;
}

int av_frame_make_writable(AVFrame *frame)
{
    (void)frame;
    return fake_av_should_fail("av_frame_make_writable") ? AVERROR(ENOMEM) : 0;
}

/* ---------------- GPU devices and frame pools ---------------- */

int av_hwdevice_ctx_create(AVBufferRef **device_ctx, enum AVHWDeviceType type, const char *device,
                           AVDictionary *opts, int flags)
{
    (void)opts;
    (void)flags;
    *device_ctx = NULL;
    g_av.nDeviceCreates++;

    char sWanted[96];
    snprintf(sWanted, sizeof(sWanted), "%s:%s", type == AV_HWDEVICE_TYPE_QSV ? "qsv" : "vaapi", device != NULL ? device : "");

    int bKnown = 0;
    for (int i = 0; i < FAKE_AV_MAX && g_av.pDevices[i] != NULL && !bKnown; i++)
        bKnown = strcmp(g_av.pDevices[i], sWanted) == 0;

    if (!bKnown) return AVERROR(ENODEV);

    *device_ctx = fake_av_buffer_new(sizeof(AVHWDeviceContext));
    if (*device_ctx == NULL) return AVERROR(ENOMEM);

    ((AVHWDeviceContext*)(*device_ctx)->data)->type = type;
    return 0;
}

AVBufferRef* av_hwframe_ctx_alloc(AVBufferRef *device_ctx)
{
    (void)device_ctx;
    if (fake_av_should_fail("av_hwframe_ctx_alloc")) return NULL;
    return fake_av_buffer_new(sizeof(AVHWFramesContext));
}

int av_hwframe_ctx_init(AVBufferRef *ref)
{
    (void)ref;
    return fake_av_should_fail("av_hwframe_ctx_init") ? AVERROR(EINVAL) : 0;
}

int av_hwframe_get_buffer(AVBufferRef *hwframe_ctx, AVFrame *frame, int flags)
{
    (void)flags;
    if (fake_av_should_fail("av_hwframe_get_buffer")) return AVERROR(ENOMEM);
    if (g_av.bNoHwBuffer) return 0;

    AVHWFramesContext *pFrames = (AVHWFramesContext*)hwframe_ctx->data;
    frame->buf[0] = fake_av_buffer_new(16);
    if (frame->buf[0] == NULL) return AVERROR(ENOMEM);

    frame->data[3] = frame->buf[0]->data;
    frame->format = pFrames->format;
    frame->width = pFrames->width;
    frame->height = pFrames->height;
    return 0;
}

int av_hwframe_transfer_data(AVFrame *dst, const AVFrame *src, int flags)
{
    (void)dst;
    (void)src;
    (void)flags;
    return fake_av_should_fail("av_hwframe_transfer_data") ? AVERROR(EIO) : 0;
}

/* A compositor's DMA-BUF onto a GPU surface: the mapping holds the descriptor for as long as it lives */
int av_hwframe_map(AVFrame *dst, const AVFrame *src, int flags)
{
    (void)flags;
    fake_av_bump(&g_av.nMaps);

    const AVDRMFrameDescriptor *pDesc = (const AVDRMFrameDescriptor*)src->data[0];
    if (pDesc != NULL)
    {
        g_av.nLastMapFd = pDesc->objects[0].fd;
        g_av.nLastMapModifier = pDesc->objects[0].format_modifier;
        g_av.nLastMapPitch = (int)pDesc->layers[0].planes[0].pitch;
    }

    if (fake_av_should_fail("av_hwframe_map")) return AVERROR(EIO);
    if (fake_av_take(&g_av.nFailMaps)) return AVERROR(EIO);
    if (src->buf[0] == NULL || (dst->buf[0] = av_buffer_ref(src->buf[0])) == NULL) return AVERROR(ENOMEM);

    dst->data[3] = dst->buf[0]->data;
    dst->width = src->width;
    dst->height = src->height;
    return 0;
}

/* ---------------- the rest ---------------- */

unsigned avutil_version(void)
{
    unsigned nMajor = g_av.nUtilMajor ? g_av.nUtilMajor : LIBAVUTIL_VERSION_MAJOR;
    return (nMajor << 16) | (LIBAVUTIL_VERSION_MINOR << 8) | LIBAVUTIL_VERSION_MICRO;
}

int av_opt_set(void *obj, const char *name, const char *val, int search_flags)
{
    (void)obj;
    (void)name;
    (void)val;
    (void)search_flags;
    g_av.nOptions++;
    return 0;
}

int av_strerror(int errnum, char *errbuf, size_t errbuf_size)
{
    if (g_av.bStrerrorFails) return -1;
    snprintf(errbuf, errbuf_size, "fake error %d", errnum);
    return 0;
}
