/*
 * A stand-in for libpipewire-0.3, for the Wayland capture tests.
 *
 * fake_pipewire.c is built as a shared library under PipeWire's own soname and
 * linked into the test, so when the agent dlopen()s "libpipewire-0.3.so.0" it
 * gets this one, already loaded, and never a PipeWire that happens to be
 * installed. It has only the entry points wayland_capture.c reaches.
 *
 * The thread loop is a real thread with the recursive lock and the wait and
 * signal PipeWire documents. Nothing happens on a stream unless the test makes
 * it happen: fake_pw_run() puts a function on the stream's loop thread with
 * the loop locked, which is where PipeWire calls a stream's events from, and
 * the fake_pw_emit_*() calls made there are those events.
 */

#ifndef DIRECTGATE_TESTS_FAKE_PIPEWIRE_H
#define DIRECTGATE_TESTS_FAKE_PIPEWIRE_H

#include <pipewire/pipewire.h>

#define FAKE_PW_MAX_PARAMS      4
#define FAKE_PW_PARAM_SIZE      1024
#define FAKE_PW_MAX_QUEUE       16
#define FAKE_PW_MAX_RETURNED    256

typedef void (*fake_pw_fn_t)(void *pArg);

typedef struct fake_pw_stream_ {
    struct pw_thread_loop *pLoop;
    const struct pw_stream_events *pEvents;
    void *pData;

    /* What the agent asked for */
    uint32_t nNode;
    uint32_t nFlags;
    int nConnects;
    int nDisconnects;
    int bDestroyed;
    uint32_t nConnectParams;
    uint8_t connectParams[FAKE_PW_MAX_PARAMS][FAKE_PW_PARAM_SIZE];
    int nUpdates;
    uint32_t nUpdateParams;
    uint8_t updateParams[FAKE_PW_MAX_PARAMS][FAKE_PW_PARAM_SIZE];

    /* Buffers the next process() dequeues, oldest first, and the ones given back */
    struct pw_buffer *pQueue[FAKE_PW_MAX_QUEUE];
    int nQueued;
    struct pw_buffer *pReturned[FAKE_PW_MAX_RETURNED];
    int nReturned;

    /* Run on the loop thread when the loop is asked to stop, before it does */
    fake_pw_fn_t fnOnStop;
    void *pOnStopArg;
} fake_pw_stream_t;

/* Forgets every stream and failure; nothing may be running */
void fake_pw_reset(void);

/* The next call of the named entry point fails the way PipeWire's does */
void fake_pw_fail_next(const char *pName);

/* The stream made last, the one subscribed to a node, and how many were made */
fake_pw_stream_t* fake_pw_last_stream(void);
fake_pw_stream_t* fake_pw_stream_for_node(uint32_t nNode);
int fake_pw_stream_count(void);

/* Runs pFunc(pArg) on the stream's loop thread with the loop locked and returns once it has */
void fake_pw_run(fake_pw_stream_t *pStream, fake_pw_fn_t pFunc, void *pArg);

/* A stream's events, only from inside fake_pw_run() */
void fake_pw_emit_state(fake_pw_stream_t *pStream, enum pw_stream_state eState, const char *pError);
void fake_pw_emit_param(fake_pw_stream_t *pStream, uint32_t nId, const struct spa_pod *pParam);
void fake_pw_emit_process(fake_pw_stream_t *pStream);
void fake_pw_queue(fake_pw_stream_t *pStream, struct pw_buffer *pBuffer);

/* Whether a buffer was given back, and how many times */
int fake_pw_returned(fake_pw_stream_t *pStream, struct pw_buffer *pBuffer);

/* How many times the stream's params were updated, and whether it was destroyed; safe to poll from any thread */
int fake_pw_updates(const fake_pw_stream_t *pStream);
int fake_pw_destroyed(const fake_pw_stream_t *pStream);

/* Live loops, contexts and cores, and the portal descriptors still open: all zero once everything is stopped */
int fake_pw_live(void);
int fake_pw_open_fds(void);

/* pw_init() calls so far */
int fake_pw_inits(void);

#endif /* DIRECTGATE_TESTS_FAKE_PIPEWIRE_H */
