/* Simulated forks exercise child-only error cleanup without creating processes. */
#include "libxutils/src/net/api.h"
#include <sys/prctl.h>
#include <stdio.h>
static int forks, signals;
static pid_t test_fork(void) { return forks++ == 0 ? 111111 : 0; }
static int test_kill(pid_t pid, int sig) { (void)pid; (void)sig; signals++; return 0; }
static pid_t test_waitpid(pid_t pid, int *status, int options)
{ (void)status; (void)options; return pid; }
static int test_prctl(int option, ...) { (void)option; return 0; }
static int test_cpu_count(void) { return 0; }
#define fork test_fork
#define kill test_kill
#define waitpid test_waitpid
#define prctl test_prctl
#define XCPU_GetCount test_cpu_count
#include "libxutils/src/net/api.c"
#undef fork
#undef kill
#undef waitpid
#undef prctl
#undef XCPU_GetCount
int main(void)
{
    for (int affinity = 0; affinity < 2; affinity++)
    {
        xapi_t api = {0};
        api.bHaveEvents = api.bUseHashMap = api.events.bUseHash = XTRUE;
        api.events.nEventCount = 1; /* Empty map forces rebuild failure. */
        api.events.eventsMap.nPairCount = 1;
        forks = signals = 0;
        if (XAPI_InitWorkers(&api, 2, affinity) != XSTDERR || !api.bIsWorker ||
            api.pWorkerPIDs || api.nWorkerCount || signals)
        { fprintf(stderr, "api_worker_failure_smoke: child touched master worker state\n"); return 1; }
    }
    puts("api_worker_failure_smoke: OK");
    return 0;
}
