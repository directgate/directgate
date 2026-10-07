/*
 * The libpipewire-0.3 stand-in described in fake_pipewire.h. Built twice: as is,
 * and with FAKE_PW_PARTIAL, which leaves out an entry point the agent cannot do
 * without, the way an incomplete install would.
 */

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fake_pipewire.h"

#define FAKE_PW_MAX_STREAMS     32
#define FAKE_PW_MAX_TASKS       16
#define FAKE_PW_MAX_FAILURES    8

typedef struct {
    fake_pw_fn_t fnTask;
    void *pArg;
} fake_pw_task_t;

struct pw_thread_loop {
    pthread_mutex_t lock;
    pthread_cond_t signal;      /* pw_thread_loop_signal() and pw_thread_loop_timed_wait() */
    pthread_cond_t work;        /* a task was posted, or the thread is asked to stop */
    pthread_cond_t done;        /* a task ran */
    pthread_t thread;
    int bRunning;
    int bStop;
    fake_pw_task_t tasks[FAKE_PW_MAX_TASKS];
    unsigned long nPosted;
    unsigned long nDone;
    struct pw_loop loop;
};

struct pw_context {
    struct pw_thread_loop *pThreadLoop;
};

struct pw_core {
    struct pw_context *pContext;
    int nFd;
};

struct pw_stream {
    fake_pw_stream_t record;
};

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct pw_stream g_streams[FAKE_PW_MAX_STREAMS];
static int g_nStreams;
static char g_failures[FAKE_PW_MAX_FAILURES][64];
static int g_nLive;
static int g_nOpenFds;
static int g_nInits;

static int fake_pw_should_fail(const char *pName)
{
    int bFail = 0;
    pthread_mutex_lock(&g_lock);

    for (int i = 0; i < FAKE_PW_MAX_FAILURES && !bFail; i++)
    {
        if (strcmp(g_failures[i], pName) != 0) continue;
        g_failures[i][0] = '\0';
        bFail = 1;
    }

    pthread_mutex_unlock(&g_lock);
    return bFail;
}

static void fake_pw_count(int *pCounter, int nDelta)
{
    pthread_mutex_lock(&g_lock);
    *pCounter += nDelta;
    pthread_mutex_unlock(&g_lock);
}

/* ---------------- test control ---------------- */

void fake_pw_reset(void)
{
    pthread_mutex_lock(&g_lock);
    memset(g_streams, 0, sizeof(g_streams));
    memset(g_failures, 0, sizeof(g_failures));
    g_nStreams = 0;
    pthread_mutex_unlock(&g_lock);
}

void fake_pw_fail_next(const char *pName)
{
    pthread_mutex_lock(&g_lock);

    for (int i = 0; i < FAKE_PW_MAX_FAILURES; i++)
    {
        if (g_failures[i][0] != '\0') continue;
        strncpy(g_failures[i], pName, sizeof(g_failures[i]) - 1);
        break;
    }

    pthread_mutex_unlock(&g_lock);
}

fake_pw_stream_t* fake_pw_last_stream(void)
{
    pthread_mutex_lock(&g_lock);
    fake_pw_stream_t *pStream = g_nStreams > 0 ? &g_streams[g_nStreams - 1].record : NULL;
    pthread_mutex_unlock(&g_lock);
    return pStream;
}

fake_pw_stream_t* fake_pw_stream_for_node(uint32_t nNode)
{
    fake_pw_stream_t *pStream = NULL;
    pthread_mutex_lock(&g_lock);

    for (int i = g_nStreams - 1; i >= 0 && pStream == NULL; i--)
    {
        if (g_streams[i].record.nConnects > 0 && g_streams[i].record.nNode == nNode) pStream = &g_streams[i].record;
    }

    pthread_mutex_unlock(&g_lock);
    return pStream;
}

int fake_pw_stream_count(void)
{
    pthread_mutex_lock(&g_lock);
    int nCount = g_nStreams;
    pthread_mutex_unlock(&g_lock);
    return nCount;
}

/* The loop lock is held by the caller. Returns the ticket the task completes. */
static unsigned long fake_pw_post_locked(struct pw_thread_loop *pLoop, fake_pw_fn_t pFunc, void *pArg)
{
    while (pLoop->nPosted - pLoop->nDone >= FAKE_PW_MAX_TASKS) pthread_cond_wait(&pLoop->done, &pLoop->lock);

    pLoop->tasks[pLoop->nPosted % FAKE_PW_MAX_TASKS].fnTask = pFunc;
    pLoop->tasks[pLoop->nPosted % FAKE_PW_MAX_TASKS].pArg = pArg;
    pLoop->nPosted++;

    pthread_cond_broadcast(&pLoop->work);
    return pLoop->nPosted;
}

void fake_pw_run(fake_pw_stream_t *pStream, fake_pw_fn_t pFunc, void *pArg)
{
    struct pw_thread_loop *pLoop = pStream->pLoop;

    /* The loop is gone with its capture; what is left of the stream is only its record */
    if (pLoop == NULL)
    {
        pFunc(pArg);
        return;
    }

    pthread_mutex_lock(&pLoop->lock);

    /* A loop that is not running has no thread to go to: the caller is as good as one */
    if (!pLoop->bRunning)
    {
        pFunc(pArg);
        pthread_mutex_unlock(&pLoop->lock);
        return;
    }

    unsigned long nTicket = fake_pw_post_locked(pLoop, pFunc, pArg);
    while (pLoop->nDone < nTicket) pthread_cond_wait(&pLoop->done, &pLoop->lock);

    pthread_mutex_unlock(&pLoop->lock);
}

void fake_pw_emit_state(fake_pw_stream_t *pStream, enum pw_stream_state eState, const char *pError)
{
    if (pStream->pEvents != NULL && pStream->pEvents->state_changed != NULL)
        pStream->pEvents->state_changed(pStream->pData, PW_STREAM_STATE_PAUSED, eState, pError);
}

void fake_pw_emit_param(fake_pw_stream_t *pStream, uint32_t nId, const struct spa_pod *pParam)
{
    if (pStream->pEvents != NULL && pStream->pEvents->param_changed != NULL)
        pStream->pEvents->param_changed(pStream->pData, nId, pParam);
}

void fake_pw_emit_process(fake_pw_stream_t *pStream)
{
    if (pStream->pEvents != NULL && pStream->pEvents->process != NULL)
        pStream->pEvents->process(pStream->pData);
}

void fake_pw_queue(fake_pw_stream_t *pStream, struct pw_buffer *pBuffer)
{
    if (pStream->nQueued < FAKE_PW_MAX_QUEUE) pStream->pQueue[pStream->nQueued++] = pBuffer;
}

/* The record outlives the stream and its loop, so this takes the global lock rather than the loop's */
int fake_pw_returned(fake_pw_stream_t *pStream, struct pw_buffer *pBuffer)
{
    pthread_mutex_lock(&g_lock);

    int nCount = 0;
    for (int i = 0; i < pStream->nReturned; i++)
    {
        if (pStream->pReturned[i] == pBuffer) nCount++;
    }

    pthread_mutex_unlock(&g_lock);
    return nCount;
}

int fake_pw_updates(const fake_pw_stream_t *pStream)
{
    return __atomic_load_n(&pStream->nUpdates, __ATOMIC_SEQ_CST);
}

int fake_pw_destroyed(const fake_pw_stream_t *pStream)
{
    return __atomic_load_n(&pStream->bDestroyed, __ATOMIC_SEQ_CST);
}

int fake_pw_live(void)
{
    pthread_mutex_lock(&g_lock);
    int nLive = g_nLive;
    pthread_mutex_unlock(&g_lock);
    return nLive;
}

int fake_pw_open_fds(void)
{
    pthread_mutex_lock(&g_lock);
    int nOpen = g_nOpenFds;
    pthread_mutex_unlock(&g_lock);
    return nOpen;
}

int fake_pw_inits(void)
{
    pthread_mutex_lock(&g_lock);
    int nInits = g_nInits;
    pthread_mutex_unlock(&g_lock);
    return nInits;
}

/* ---------------- libpipewire ---------------- */

void pw_init(int *argc, char **argv[])
{
    (void)argc;
    (void)argv;
    fake_pw_count(&g_nInits, 1);
}

const char* pw_get_library_version(void)
{
    return "0.3.0-fake";
}

static void* fake_pw_loop_thread(void *pArg)
{
    struct pw_thread_loop *pLoop = (struct pw_thread_loop*)pArg;
    pthread_mutex_lock(&pLoop->lock);

    /* Everything posted runs before the thread ends, the way PipeWire finishes what it is in the middle of */
    for (;;)
    {
        if (pLoop->nDone < pLoop->nPosted)
        {
            fake_pw_task_t task = pLoop->tasks[pLoop->nDone % FAKE_PW_MAX_TASKS];
            task.fnTask(task.pArg);
            pLoop->nDone++;
            pthread_cond_broadcast(&pLoop->done);
            continue;
        }

        if (pLoop->bStop) break;
        pthread_cond_wait(&pLoop->work, &pLoop->lock);
    }

    pthread_mutex_unlock(&pLoop->lock);
    return NULL;
}

struct pw_thread_loop* pw_thread_loop_new(const char *name, const struct spa_dict *props)
{
    (void)name;
    (void)props;
    if (fake_pw_should_fail("pw_thread_loop_new")) return NULL;

    struct pw_thread_loop *pLoop = (struct pw_thread_loop*)calloc(1, sizeof(*pLoop));
    if (pLoop == NULL) return NULL;

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&pLoop->lock, &attr);
    pthread_mutexattr_destroy(&attr);

    pthread_cond_init(&pLoop->signal, NULL);
    pthread_cond_init(&pLoop->work, NULL);
    pthread_cond_init(&pLoop->done, NULL);

    fake_pw_count(&g_nLive, 1);
    return pLoop;
}

int pw_thread_loop_start(struct pw_thread_loop *loop)
{
    if (fake_pw_should_fail("pw_thread_loop_start")) return -EIO;
    if (pthread_create(&loop->thread, NULL, fake_pw_loop_thread, loop) != 0) return -EIO;

    loop->bRunning = 1;
    return 0;
}

void pw_thread_loop_stop(struct pw_thread_loop *loop)
{
    pthread_mutex_lock(&loop->lock);

    if (!loop->bRunning)
    {
        pthread_mutex_unlock(&loop->lock);
        return;
    }

    /* What a stream had on its way when the stop came still arrives */
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_nStreams; i++)
    {
        fake_pw_stream_t *pStream = &g_streams[i].record;
        if (pStream->pLoop != loop || pStream->fnOnStop == NULL) continue;

        fake_pw_post_locked(loop, pStream->fnOnStop, pStream->pOnStopArg);
        pStream->fnOnStop = NULL;
    }
    pthread_mutex_unlock(&g_lock);

    loop->bStop = 1;
    pthread_cond_broadcast(&loop->work);
    pthread_mutex_unlock(&loop->lock);

    pthread_join(loop->thread, NULL);

    pthread_mutex_lock(&loop->lock);
    loop->bRunning = 0;
    loop->bStop = 0;
    pthread_mutex_unlock(&loop->lock);
}

void pw_thread_loop_destroy(struct pw_thread_loop *loop)
{
    pw_thread_loop_stop(loop);

    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_nStreams; i++)
    {
        if (g_streams[i].record.pLoop == loop) g_streams[i].record.pLoop = NULL;
    }
    pthread_mutex_unlock(&g_lock);

    pthread_cond_destroy(&loop->done);
    pthread_cond_destroy(&loop->work);
    pthread_cond_destroy(&loop->signal);
    pthread_mutex_destroy(&loop->lock);

    free(loop);
    fake_pw_count(&g_nLive, -1);
}

void pw_thread_loop_lock(struct pw_thread_loop *loop)
{
    pthread_mutex_lock(&loop->lock);
}

void pw_thread_loop_unlock(struct pw_thread_loop *loop)
{
    pthread_mutex_unlock(&loop->lock);
}

void pw_thread_loop_signal(struct pw_thread_loop *loop, bool wait_for_accept)
{
    (void)wait_for_accept;
    pthread_cond_broadcast(&loop->signal);
}

int pw_thread_loop_timed_wait(struct pw_thread_loop *loop, int wait_max_sec)
{
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += wait_max_sec;

    return pthread_cond_timedwait(&loop->signal, &loop->lock, &deadline);
}

struct pw_loop* pw_thread_loop_get_loop(struct pw_thread_loop *loop)
{
    return &loop->loop;
}

struct pw_context* pw_context_new(struct pw_loop *main_loop, struct pw_properties *props, size_t user_data_size)
{
    (void)user_data_size;
    free(props);
    if (fake_pw_should_fail("pw_context_new")) return NULL;

    struct pw_context *pContext = (struct pw_context*)calloc(1, sizeof(*pContext));
    if (pContext == NULL) return NULL;

    pContext->pThreadLoop = (struct pw_thread_loop*)((char*)main_loop - offsetof(struct pw_thread_loop, loop));
    fake_pw_count(&g_nLive, 1);
    return pContext;
}

void pw_context_destroy(struct pw_context *context)
{
    free(context);
    fake_pw_count(&g_nLive, -1);
}

/* Takes the descriptor either way: it is closed on disconnect, and at once when the connection fails */
struct pw_core* pw_context_connect_fd(struct pw_context *context, int fd, struct pw_properties *properties,
                                      size_t user_data_size)
{
    (void)user_data_size;
    free(properties);

    struct pw_core *pCore = NULL;
    if (!fake_pw_should_fail("pw_context_connect_fd")) pCore = (struct pw_core*)calloc(1, sizeof(*pCore));

    if (pCore == NULL)
    {
        if (fd >= 0) close(fd);
        return NULL;
    }

    pCore->pContext = context;
    pCore->nFd = fd;

    fake_pw_count(&g_nLive, 1);
    if (fd >= 0) fake_pw_count(&g_nOpenFds, 1);
    return pCore;
}

int pw_core_disconnect(struct pw_core *core)
{
    if (core->nFd >= 0)
    {
        close(core->nFd);
        fake_pw_count(&g_nOpenFds, -1);
    }

    free(core);
    fake_pw_count(&g_nLive, -1);
    return 0;
}

struct pw_properties* pw_properties_new(const char *key, ...)
{
    va_list args;
    va_start(args, key);
    for (const char *pKey = key; pKey != NULL; pKey = va_arg(args, const char*)) (void)va_arg(args, const char*);
    va_end(args);

    return (struct pw_properties*)calloc(1, sizeof(struct pw_properties));
}

struct pw_stream* pw_stream_new(struct pw_core *core, const char *name, struct pw_properties *props)
{
    (void)name;
    free(props);
    if (fake_pw_should_fail("pw_stream_new")) return NULL;

    pthread_mutex_lock(&g_lock);
    struct pw_stream *pStream = g_nStreams < FAKE_PW_MAX_STREAMS ? &g_streams[g_nStreams++] : NULL;
    if (pStream != NULL)
    {
        memset(pStream, 0, sizeof(*pStream));
        pStream->record.pLoop = core->pContext->pThreadLoop;
        g_nLive++;
    }
    pthread_mutex_unlock(&g_lock);

    return pStream;
}

void pw_stream_destroy(struct pw_stream *stream)
{
    __atomic_store_n(&stream->record.bDestroyed, 1, __ATOMIC_SEQ_CST);
    fake_pw_count(&g_nLive, -1);
}

void pw_stream_add_listener(struct pw_stream *stream, struct spa_hook *listener,
                            const struct pw_stream_events *events, void *data)
{
    (void)listener;
    stream->record.pEvents = events;
    stream->record.pData = data;
}

static uint32_t fake_pw_keep(uint8_t (*pDst)[FAKE_PW_PARAM_SIZE], const struct spa_pod **params, uint32_t n_params)
{
    uint32_t nKept = 0;

    for (uint32_t i = 0; i < n_params && nKept < FAKE_PW_MAX_PARAMS; i++)
    {
        if (params[i] == NULL || SPA_POD_SIZE(params[i]) > FAKE_PW_PARAM_SIZE) continue;
        memcpy(pDst[nKept++], params[i], SPA_POD_SIZE(params[i]));
    }

    return nKept;
}

int pw_stream_connect(struct pw_stream *stream, enum pw_direction direction, uint32_t target_id,
                      enum pw_stream_flags flags, const struct spa_pod **params, uint32_t n_params)
{
    (void)direction;
    if (fake_pw_should_fail("pw_stream_connect")) return -EIO;

    fake_pw_stream_t *pRecord = &stream->record;
    pRecord->nConnectParams = fake_pw_keep(pRecord->connectParams, params, n_params);
    pRecord->nFlags = (uint32_t)flags;

    pthread_mutex_lock(&g_lock);
    pRecord->nNode = target_id;
    pRecord->nConnects++;
    pthread_mutex_unlock(&g_lock);

    return 0;
}

int pw_stream_disconnect(struct pw_stream *stream)
{
    stream->record.nDisconnects++;
    return 0;
}

int pw_stream_update_params(struct pw_stream *stream, const struct spa_pod **params, uint32_t n_params)
{
    fake_pw_stream_t *pRecord = &stream->record;
    pRecord->nUpdateParams = fake_pw_keep(pRecord->updateParams, params, n_params);
    __atomic_add_fetch(&pRecord->nUpdates, 1, __ATOMIC_SEQ_CST);
    return 0;
}

struct pw_buffer* pw_stream_dequeue_buffer(struct pw_stream *stream)
{
    fake_pw_stream_t *pRecord = &stream->record;
    if (pRecord->nQueued == 0) return NULL;

    struct pw_buffer *pBuffer = pRecord->pQueue[0];
    memmove(&pRecord->pQueue[0], &pRecord->pQueue[1], sizeof(pRecord->pQueue[0]) * (size_t)(--pRecord->nQueued));
    return pBuffer;
}

#ifndef FAKE_PW_PARTIAL
int pw_stream_queue_buffer(struct pw_stream *stream, struct pw_buffer *buffer)
{
    fake_pw_stream_t *pRecord = &stream->record;
    pthread_mutex_lock(&g_lock);
    if (pRecord->nReturned < FAKE_PW_MAX_RETURNED) pRecord->pReturned[pRecord->nReturned++] = buffer;
    pthread_mutex_unlock(&g_lock);
    return 0;
}
#endif

const char* pw_stream_state_as_string(enum pw_stream_state state)
{
    switch (state)
    {
        case PW_STREAM_STATE_ERROR: return "error";
        case PW_STREAM_STATE_UNCONNECTED: return "unconnected";
        case PW_STREAM_STATE_CONNECTING: return "connecting";
        case PW_STREAM_STATE_PAUSED: return "paused";
        case PW_STREAM_STATE_STREAMING: return "streaming";
        default: return "unknown";
    }
}
