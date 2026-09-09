#include <pthread.h>
#include <errno.h>
#include <stdio.h>
static int fail_init, destroys;
static int test_attr_init(pthread_attr_t *attr)
{ return fail_init ? ENOMEM : pthread_attr_init(attr); }
static int test_attr_destroy(pthread_attr_t *attr)
{ destroys++; return pthread_attr_destroy(attr); }
#define pthread_attr_init test_attr_init
#define pthread_attr_destroy test_attr_destroy
#include "libxutils/src/sys/thread.c"
#undef pthread_attr_init
#undef pthread_attr_destroy
static void* worker(void *arg) { return arg; }
int main(void)
{
    xthread_t thread;
    fail_init = 1;
    if (XThread_Create(&thread, worker, NULL, 0) != XSTDERR || destroys != 0 || errno != ENOMEM)
    { fprintf(stderr, "thread_failure_smoke: initialization failure destroyed invalid attributes\n"); return 1; }
    fail_init = 0;
    XThread_Init(&thread);
    thread.functionCb = worker;
    thread.nStackSize = 1;
    if (XThread_Run(&thread) != XSTDERR || destroys != 1 || errno != EINVAL)
    { fprintf(stderr, "thread_failure_smoke: invalid stack size cleanup\n"); return 1; }
    int value = 42;
    if (XThread_Create(&thread, worker, &value, 0) != XSTDOK || XThread_Join(&thread) != &value)
    { fprintf(stderr, "thread_failure_smoke: valid worker\n"); return 1; }
    puts("thread_failure_smoke: OK");
    return 0;
}
