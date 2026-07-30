/* Multi-ABI GPU encoder smoke test.
 *
 * hwenc.c is compiled once per libavcodec major the build knows about, and
 * hwenc_abi.c picks the variant matching whatever the host has installed. The
 * whole point of that machinery is that a package built on one distribution
 * still uses the GPU on another, and the only way it can fail is silently -
 * the agent just drops to software encoding. So this asserts the selection
 * actually happens against the real library on this machine.
 *
 * Skips (77) when the host has no libavcodec at all, which is the legitimate
 * software-only case; a host that does have one and still fails to select an
 * ABI is a genuine failure of the dispatch.
 */

#include "src/agent/desktop/hwenc.h"

#include <dirent.h>

/* True when any libavcodec.so.<major> exists in the usual library paths, so
 * the difference between "nothing installed" and "installed but not selected"
 * can be told apart. */
static int host_has_libavcodec(char *pFound, size_t nSize)
{
    static const char *pDirs[] = {
        "/usr/lib64", "/usr/lib",
        "/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
        "/usr/lib/arm-linux-gnueabihf", "/usr/lib/i386-linux-gnu"
    };

    for (size_t i = 0; i < sizeof(pDirs) / sizeof(pDirs[0]); i++)
    {
        DIR *pDir = opendir(pDirs[i]);
        if (pDir == NULL) continue;

        struct dirent *pEntry;
        while ((pEntry = readdir(pDir)) != NULL)
        {
            if (strncmp(pEntry->d_name, "libavcodec.so.", 14) != 0) continue;
            if (strchr(pEntry->d_name + 14, '.') != NULL) continue; /* the versioned real file */

            snprintf(pFound, nSize, "%s/%s", pDirs[i], pEntry->d_name);
            closedir(pDir);
            return 1;
        }

        closedir(pDir);
    }

    return 0;
}

int main(void)
{
#ifndef DIRECTGATE_HAVE_HWENC
    fprintf(stderr, "hwenc_abi_smoke: skipped: built without GPU encoding\n");
    return 77;
#else
    /* Comfortably larger than any directory above plus a dirent name, so the
       compiler can see the join cannot truncate. */
    char sFound[512] = {0};
    char sError[DIRECTGATE_DESKTOP_REASON_LEN] = {0};

    int nHostHas = host_has_libavcodec(sFound, sizeof(sFound));
    int nStatus = DirectGate_HWEnc_Load(sError, sizeof(sError));

    if (nStatus == XSTDOK)
    {
        const char *pVersion = DirectGate_HWEnc_Version();
        if (pVersion == NULL || strncmp(pVersion, "libavcodec ", 11) != 0)
        {
            fprintf(stderr, "hwenc_abi_smoke: loaded but reported no version: %s\n",
                pVersion ? pVersion : "(null)");
            return 1;
        }

        printf("hwenc_abi_smoke: selected %s\n", pVersion);
        return 0;
    }

    if (!nHostHas)
    {
        fprintf(stderr, "hwenc_abi_smoke: skipped: %s\n", sError);
        return 77;
    }

    /* The host has one and no variant took it: either this build covers the
       wrong majors or a variant is broken. Both are exactly what this test is
       here to catch, so do not let it pass as a skip. */
    fprintf(stderr, "hwenc_abi_smoke: %s is installed but no compiled ABI matched it: %s\n",
        sFound, sError);

    return 1;
#endif
}
