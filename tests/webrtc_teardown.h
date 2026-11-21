/*
 * DirectGate_WebRTC_Cleanup() for a test that exits soon after it.
 *
 * rtcCleanup() returns as soon as libdatachannel's teardown thread has set its
 * promise, and that detached thread is still ending then. A process that exits
 * under it has valgrind report what the thread still holds as lost: its
 * thread-local storage among them, which glibc may have handed down with the
 * stack of a thread that ended earlier (libjuice's poll thread, a pool worker),
 * so the allocation names that thread and no suppression can pin it down.
 * Waiting for the thread to be gone ends the race instead of excusing it.
 */

#ifndef DIRECTGATE_TESTS_WEBRTC_TEARDOWN_H
#define DIRECTGATE_TESTS_WEBRTC_TEARDOWN_H

#include <dirent.h>
#include <stdio.h>
#include <string.h>

#include "src/common/webrtc.h"

#define WEBRTC_TEARDOWN_WAIT_MS 5000U

/* Threads of this process by the name libdatachannel gives its teardown thread, -1 where that cannot be told */
static int webrtc_teardown_threads(void)
{
#ifdef __linux__
    DIR *pDir = opendir("/proc/self/task");
    if (pDir == NULL) return -1;

    int nCount = 0;
    struct dirent *pEntry;

    while ((pEntry = readdir(pDir)) != NULL)
    {
        if (pEntry->d_name[0] == '.') continue;

        char sPath[300];
        char sName[32] = { 0 };
        snprintf(sPath, sizeof(sPath), "/proc/self/task/%s/comm", pEntry->d_name);

        /* A thread that ended between the listing and here has no name to read */
        FILE *pFile = fopen(sPath, "r");
        if (pFile == NULL) continue;

        if (fgets(sName, sizeof(sName), pFile) != NULL && !strncmp(sName, "RTC cleanup", 11)) nCount++;
        fclose(pFile);
    }

    closedir(pDir);
    return nCount;
#else
    return -1;
#endif
}

/* The cleanup, and then the wait, by time, for the thread it started to be gone */
static void webrtc_cleanup_settled(void)
{
    DirectGate_WebRTC_Cleanup();

    uint64_t nDeadlineMs = XTime_GetMonoMs() + WEBRTC_TEARDOWN_WAIT_MS;
    while (webrtc_teardown_threads() > 0 && XTime_GetMonoMs() < nDeadlineMs) xusleep(1000);
}

#endif /* DIRECTGATE_TESTS_WEBRTC_TEARDOWN_H */
