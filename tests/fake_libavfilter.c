/*
 * The libavfilter part of fake_libav.h: the GPU conversion graph the Wayland
 * zero-copy path builds - a buffer source, scale_vaapi and a buffer sink - with
 * FFmpeg's own context layout. A frame the source takes comes out of the sink's
 * pool at the size the post-processor was asked for.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libavfilter/avfilter.h>
#include <libavfilter/buffersink.h>
#include <libavfilter/buffersrc.h>
#include <libavutil/hwcontext.h>

#include "fake_libav.h"

typedef struct {
    int nPending;               /* frames the source took that the sink has not given back */
} fake_graph_t;

typedef struct {
    int bScale;
    int bSink;
    unsigned nWidth;            /* what the post-processor scales to, and so what the sink's pool holds */
    unsigned nHeight;
    AVBufferRef *pFrames;       /* the source's frames context, or the sink's pool */
} fake_filter_t;

static const AVFilter g_filters[] = {
    { .name = "buffer" },
    { .name = "scale_vaapi" },
    { .name = "buffersink" }
};

unsigned avfilter_version(void)
{
    unsigned nMajor = fake_av()->nFilterMajor ? fake_av()->nFilterMajor : LIBAVFILTER_VERSION_MAJOR;
    return (nMajor << 16) | (LIBAVFILTER_VERSION_MINOR << 8) | LIBAVFILTER_VERSION_MICRO;
}

const AVFilter* avfilter_get_by_name(const char *name)
{
    if (fake_av_should_fail("avfilter_get_by_name")) return NULL;
    if (fake_av()->bNoScaleFilter && strcmp(name, "scale_vaapi") == 0) return NULL;

    for (size_t i = 0; i < sizeof(g_filters) / sizeof(g_filters[0]); i++)
        if (strcmp(g_filters[i].name, name) == 0) return &g_filters[i];

    return NULL;
}

/* ---------------- graphs and the filters in them ---------------- */

AVFilterGraph* avfilter_graph_alloc(void)
{
    if (fake_av_should_fail("avfilter_graph_alloc")) return NULL;

    AVFilterGraph *pGraph = (AVFilterGraph*)calloc(1, sizeof(*pGraph));
    fake_graph_t *pState = (fake_graph_t*)calloc(1, sizeof(*pState));
    if (pGraph == NULL || pState == NULL)
    {
        free(pGraph);
        free(pState);
        return NULL;
    }

    pGraph->opaque = pState;
    fake_av_count(1);
    return pGraph;
}

void avfilter_graph_free(AVFilterGraph **graph)
{
    if (graph == NULL || *graph == NULL) return;
    AVFilterGraph *pGraph = *graph;

    for (unsigned i = 0; i < pGraph->nb_filters; i++)
    {
        AVFilterContext *pCtx = pGraph->filters[i];
        fake_filter_t *pFilter = (fake_filter_t*)pCtx->priv;

        av_buffer_unref(&pFilter->pFrames);
        av_buffer_unref(&pCtx->hw_device_ctx);
        free(pFilter);
        free(pCtx->name);
        free(pCtx);
    }

    free(pGraph->filters);
    free(pGraph->opaque);
    free(pGraph);
    *graph = NULL;
    fake_av_count(-1);
}

static AVFilterContext* fake_filter_new(AVFilterGraph *pGraph, const AVFilter *pFilter, const char *pName)
{
    AVFilterContext **ppFilters = (AVFilterContext**)realloc(pGraph->filters, sizeof(*ppFilters) * (pGraph->nb_filters + 1));
    if (ppFilters == NULL) return NULL;
    pGraph->filters = ppFilters;

    AVFilterContext *pCtx = (AVFilterContext*)calloc(1, sizeof(*pCtx));
    fake_filter_t *pState = (fake_filter_t*)calloc(1, sizeof(*pState));
    char *pCopy = strdup(pName != NULL ? pName : "");
    if (pCtx == NULL || pState == NULL || pCopy == NULL)
    {
        free(pCtx);
        free(pState);
        free(pCopy);
        return NULL;
    }

    pState->bScale = strcmp(pFilter->name, "scale_vaapi") == 0;
    pState->bSink = strcmp(pFilter->name, "buffersink") == 0;
    pCtx->filter = pFilter;
    pCtx->name = pCopy;
    pCtx->priv = pState;
    pCtx->graph = pGraph;
    pGraph->filters[pGraph->nb_filters++] = pCtx;
    return pCtx;
}

AVFilterContext* avfilter_graph_alloc_filter(AVFilterGraph *graph, const AVFilter *filter, const char *name)
{
    if (fake_av_should_fail("avfilter_graph_alloc_filter")) return NULL;
    return fake_filter_new(graph, filter, name);
}

int avfilter_init_str(AVFilterContext *ctx, const char *args)
{
    if (fake_av_should_fail("avfilter_init_str")) return AVERROR(EINVAL);

    fake_filter_t *pState = (fake_filter_t*)ctx->priv;
    if (!pState->bScale || args == NULL) return 0;

    fake_av_t *pAv = fake_av();
    snprintf(pAv->sScaleArgs, sizeof(pAv->sScaleArgs), "%s", args);
    if (pAv->bScaleRejectsColour && strstr(args, "out_color_matrix") != NULL) return AVERROR(EINVAL);

    if (sscanf(args, "w=%u:h=%u", &pState->nWidth, &pState->nHeight) != 2) return AVERROR(EINVAL);
    return 0;
}

int avfilter_graph_create_filter(AVFilterContext **filt_ctx, const AVFilter *filt, const char *name,
                                 const char *args, void *opaque, AVFilterGraph *graph_ctx)
{
    (void)opaque;
    *filt_ctx = NULL;
    if (fake_av_should_fail("avfilter_graph_create_filter")) return AVERROR(ENOMEM);

    /* A filter that fails to initialise stays in the graph, and goes with it */
    AVFilterContext *pCtx = fake_filter_new(graph_ctx, filt, name);
    if (pCtx == NULL) return AVERROR(ENOMEM);

    int nRet = avfilter_init_str(pCtx, args);
    if (nRet < 0) return nRet;

    *filt_ctx = pCtx;
    return 0;
}

int avfilter_link(AVFilterContext *src, unsigned srcpad, AVFilterContext *dst, unsigned dstpad)
{
    (void)srcpad;
    (void)dstpad;
    if (fake_av_should_fail("avfilter_link")) return AVERROR(EINVAL);

    /* The sink's pool takes the size of what feeds it */
    fake_filter_t *pFrom = (fake_filter_t*)src->priv;
    fake_filter_t *pTo = (fake_filter_t*)dst->priv;
    if (pTo->bSink)
    {
        pTo->nWidth = pFrom->nWidth;
        pTo->nHeight = pFrom->nHeight;
    }

    return 0;
}

int avfilter_graph_config(AVFilterGraph *graphctx, void *log_ctx)
{
    (void)log_ctx;
    if (fake_av_should_fail("avfilter_graph_config")) return AVERROR(EINVAL);
    if (fake_av()->bNoSinkFrames) return 0;

    for (unsigned i = 0; i < graphctx->nb_filters; i++)
    {
        fake_filter_t *pState = (fake_filter_t*)graphctx->filters[i]->priv;
        if (!pState->bSink) continue;

        pState->pFrames = av_hwframe_ctx_alloc(NULL);
        if (pState->pFrames == NULL) return AVERROR(ENOMEM);

        AVHWFramesContext *pFrames = (AVHWFramesContext*)pState->pFrames->data;
        pFrames->format = AV_PIX_FMT_VAAPI;
        pFrames->sw_format = AV_PIX_FMT_NV12;
        pFrames->width = (int)pState->nWidth;
        pFrames->height = (int)pState->nHeight;
    }

    return 0;
}

/* ---------------- the buffer source and sink ---------------- */

AVBufferSrcParameters* av_buffersrc_parameters_alloc(void)
{
    if (fake_av_should_fail("av_buffersrc_parameters_alloc")) return NULL;

    AVBufferSrcParameters *pParams = (AVBufferSrcParameters*)calloc(1, sizeof(*pParams));
    if (pParams == NULL) return NULL;

    pParams->format = -1;
    fake_av_count(1);
    return pParams;
}

int av_buffersrc_parameters_set(AVFilterContext *ctx, AVBufferSrcParameters *param)
{
    if (fake_av_should_fail("av_buffersrc_parameters_set")) return AVERROR(EINVAL);

    fake_filter_t *pState = (fake_filter_t*)ctx->priv;
    if (param->hw_frames_ctx == NULL) return 0;

    av_buffer_unref(&pState->pFrames);
    pState->pFrames = av_buffer_ref(param->hw_frames_ctx);
    return pState->pFrames != NULL ? 0 : AVERROR(ENOMEM);
}

/* Without AV_BUFFERSRC_FLAG_KEEP_REF the source takes the frame's references and leaves it empty */
int av_buffersrc_add_frame_flags(AVFilterContext *buffer_src, AVFrame *frame, int flags)
{
    (void)flags;
    if (fake_av_should_fail("av_buffersrc_add_frame_flags")) return AVERROR(EIO);

    fake_av()->nLastSourcePts = frame->pts;
    ((fake_graph_t*)buffer_src->graph->opaque)->nPending++;
    av_frame_unref(frame);
    return 0;
}

int av_buffersink_get_frame(AVFilterContext *ctx, AVFrame *frame)
{
    if (fake_av_should_fail("av_buffersink_get_frame")) return AVERROR(EIO);

    fake_av_t *pAv = fake_av();
    fake_graph_t *pGraph = (fake_graph_t*)ctx->graph->opaque;
    if (pAv->nSinkAgain > 0 || pGraph->nPending == 0)
    {
        if (pAv->nSinkAgain > 0) pAv->nSinkAgain--;
        return AVERROR(EAGAIN);
    }

    pGraph->nPending--;
    return av_hwframe_get_buffer(((fake_filter_t*)ctx->priv)->pFrames, frame, 0);
}

AVBufferRef* av_buffersink_get_hw_frames_ctx(const AVFilterContext *ctx)
{
    return ((const fake_filter_t*)ctx->priv)->pFrames;
}
