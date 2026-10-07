/*
 * A PipeWire video stream as the Wayland tests drive it through fake_pipewire.h:
 * formats as a compositor sends them, buffers as it fills them, and helpers
 * that deliver either on the stream's own loop thread, which is where the
 * agent receives them from a real PipeWire.
 */

#ifndef DIRECTGATE_TESTS_WAYLAND_STREAM_FIXTURE_H
#define DIRECTGATE_TESTS_WAYLAND_STREAM_FIXTURE_H

#include <string.h>

#include <spa/param/video/format-utils.h>
#include <spa/param/buffers.h>
#include <spa/pod/builder.h>

#include "fake_pipewire.h"

#define DRM_XRGB8888    0x34325258U
#define DRM_ARGB8888    0x34325241U
#define MOD_INVALID     0x00ffffffffffffffULL
#define MOD_LINEAR      0ULL

/* ---------------- formats as a compositor sends them ---------------- */

enum { MODIFIER_NONE, MODIFIER_FIXED, MODIFIER_CHOICE, MODIFIER_INT };

static const struct spa_pod* make_format(uint8_t *pBuf, size_t nSize, uint32_t nMediaType, uint32_t nFormat,
                                         uint32_t nWidth, uint32_t nHeight, int eModifier, uint64_t nModifier)
{
    struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(pBuf, (uint32_t)nSize);
    struct spa_pod_frame frames[2];

    spa_pod_builder_push_object(&builder, &frames[0], SPA_TYPE_OBJECT_Format, SPA_PARAM_Format);
    spa_pod_builder_add(&builder,
        SPA_FORMAT_mediaType,       SPA_POD_Id(nMediaType),
        SPA_FORMAT_mediaSubtype,    SPA_POD_Id(SPA_MEDIA_SUBTYPE_raw),
        SPA_FORMAT_VIDEO_format,    SPA_POD_Id(nFormat),
        SPA_FORMAT_VIDEO_size,      SPA_POD_Rectangle(&SPA_RECTANGLE(nWidth, nHeight)),
        SPA_FORMAT_VIDEO_framerate, SPA_POD_Fraction(&SPA_FRACTION(60, 1)), 0);

    if (eModifier == MODIFIER_FIXED)
    {
        spa_pod_builder_prop(&builder, SPA_FORMAT_VIDEO_modifier, SPA_POD_PROP_FLAG_MANDATORY);
        spa_pod_builder_long(&builder, (int64_t)nModifier);
    }
    else if (eModifier == MODIFIER_INT)
    {
        spa_pod_builder_prop(&builder, SPA_FORMAT_VIDEO_modifier, SPA_POD_PROP_FLAG_MANDATORY);
        spa_pod_builder_int(&builder, (int32_t)nModifier);
    }
    else if (eModifier == MODIFIER_CHOICE)
    {
        spa_pod_builder_prop(&builder, SPA_FORMAT_VIDEO_modifier, SPA_POD_PROP_FLAG_MANDATORY | SPA_POD_PROP_FLAG_DONT_FIXATE);
        spa_pod_builder_push_choice(&builder, &frames[1], SPA_CHOICE_Enum, 0);
        spa_pod_builder_long(&builder, (int64_t)nModifier);
        spa_pod_builder_long(&builder, (int64_t)MOD_INVALID);
        spa_pod_builder_long(&builder, (int64_t)MOD_LINEAR);
        spa_pod_builder_pop(&builder, &frames[1]);
    }

    return (const struct spa_pod*)spa_pod_builder_pop(&builder, &frames[0]);
}

/* ---------------- buffers as a compositor fills them ---------------- */

typedef struct {
    struct pw_buffer pw;
    struct spa_buffer spa;
    struct spa_data data[2];
    struct spa_chunk chunk;
    uint8_t pixels[12288];      /* room for a padded stride */
} buffer_t;

static void buffer_mapped(buffer_t *pBuf, uint32_t nOffset, int32_t nStride, uint32_t nSize, uint32_t nMax)
{
    memset(pBuf, 0, sizeof(*pBuf));
    pBuf->pw.buffer = &pBuf->spa;
    pBuf->spa.n_datas = 1;
    pBuf->spa.datas = pBuf->data;
    pBuf->data[0].type = SPA_DATA_MemPtr;
    pBuf->data[0].data = pBuf->pixels;
    pBuf->data[0].maxsize = nMax;
    pBuf->data[0].chunk = &pBuf->chunk;
    pBuf->chunk.offset = nOffset;
    pBuf->chunk.stride = nStride;
    pBuf->chunk.size = nSize;
    pBuf->pixels[nOffset] = 0x5a;
}

static void buffer_exported(buffer_t *pBuf, int64_t nFd, uint32_t nOffset, int32_t nStride, uint32_t nMax)
{
    buffer_mapped(pBuf, nOffset, nStride, 1, nMax);
    pBuf->data[0].type = SPA_DATA_DmaBuf;
    pBuf->data[0].data = NULL;
    pBuf->data[0].fd = nFd;
}

/* ---------------- what runs on the loop thread ---------------- */

typedef struct {
    fake_pw_stream_t *pStream;
    const struct spa_pod *pParam;
    uint32_t nId;
    buffer_t *pBuffers[4];
    int nBuffers;
    enum pw_stream_state eState;
    const char *pError;
} event_t;

static void run_param(void *pArg)
{
    event_t *pEvent = (event_t*)pArg;
    fake_pw_emit_param(pEvent->pStream, pEvent->nId, pEvent->pParam);
}

static void run_process(void *pArg)
{
    event_t *pEvent = (event_t*)pArg;
    for (int i = 0; i < pEvent->nBuffers; i++) fake_pw_queue(pEvent->pStream, &pEvent->pBuffers[i]->pw);
    fake_pw_emit_process(pEvent->pStream);
}

static void run_state(void *pArg)
{
    event_t *pEvent = (event_t*)pArg;
    fake_pw_emit_state(pEvent->pStream, pEvent->eState, pEvent->pError);
}

static void emit_param(fake_pw_stream_t *pStream, uint32_t nId, const struct spa_pod *pParam)
{
    event_t event = { .pStream = pStream, .nId = nId, .pParam = pParam };
    fake_pw_run(pStream, run_param, &event);
}

static void emit_buffer(fake_pw_stream_t *pStream, buffer_t *pBuffer)
{
    event_t event = { .pStream = pStream, .nBuffers = 1 };
    event.pBuffers[0] = pBuffer;
    fake_pw_run(pStream, run_process, &event);
}

static void emit_state(fake_pw_stream_t *pStream, enum pw_stream_state eState, const char *pError)
{
    event_t event = { .pStream = pStream, .eState = eState, .pError = pError };
    fake_pw_run(pStream, run_state, &event);
}

#endif /* DIRECTGATE_TESTS_WAYLAND_STREAM_FIXTURE_H */
