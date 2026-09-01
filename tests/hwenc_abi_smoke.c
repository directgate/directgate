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
 *
 * Then builds the Wayland zero-copy chain, which is the part with the most
 * that can go wrong on a given host: libavfilter, a scale_vaapi filter inside
 * it, a VAAPI device, a mapping frames context, the conversion graph, and an
 * encoder opened on that graph's own frame pool. All of it is optional - a
 * machine with no usable VAAPI keeps the copied path and the agent is none
 * the worse - so not having it is reported rather than failed. What is failed
 * is a chain that builds and then behaves wrongly.
 */

#include "src/agent/desktop/hwenc.h"

#include <dirent.h>

#if defined(__SANITIZE_ADDRESS__)
#define DIRECTGATE_HWENC_SMOKE_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define DIRECTGATE_HWENC_SMOKE_ASAN 1
#endif
#endif

#ifdef DIRECTGATE_HWENC_SMOKE_ASAN
/* Loading a GPU driver leaves allocations behind that this process does not
 * own and cannot free. Opening a VAAPI device makes libva dlopen the vendor's
 * driver and call into it, and a driver that fails to initialise - the
 * ordinary case on a hybrid box, where the first render node is not the one
 * that encodes - keeps what it allocated on the way. The stack is entirely
 * inside libva and the driver:
 *
 *     malloc <- iHD_drv_video.so <- __vaDriverInit <- vaInitialize
 *
 * so vaInitialize is what is excused here, and nothing above it. That matters:
 * every allocation this agent is responsible for - the frames contexts, the
 * conversion graph, the descriptor wrappers, the device references themselves
 * - reaches malloc without passing through libva's driver load, and still
 * fails the run. Excusing the libavutil entry point above it would have
 * covered the agent's own device references too. */
const char* __lsan_default_suppressions(void);
const char* __lsan_default_suppressions(void)
{
    return "leak:vaInitialize\n";
}
#endif

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

        char sImport[DIRECTGATE_DESKTOP_REASON_LEN] = {0};
        if (!DirectGate_HWEnc_ImportAvailable(sImport, sizeof(sImport)))
        {
            printf("hwenc_abi_smoke: zero-copy unavailable here: %s\n",
                sImport[0] ? sImport : "no reason reported");

            return 0;
        }

        directgate_desktop_quality_t quality;
        memset(&quality, 0, sizeof(quality));
        quality.nFps = 30U;
        quality.nBitrateKbps = 4000U;
        quality.nKeyframeFrames = 300U;

        /* XR24 is DRM_FORMAT_XRGB8888 and the modifier is the "whatever the
         * driver would have picked" one, which is exactly what the capture
         * side offers a compositor. The two sizes differ on purpose, so the
         * GPU has to scale as well as convert. */
        sImport[0] = '\0';
        directgate_hwenc_t *pEncoder = DirectGate_HWEnc_CreateImport(2560, 1440,
            0x34325258u, 0x00ffffffffffffffULL, 1920, 1080, &quality, sImport, sizeof(sImport));

        if (pEncoder == NULL)
        {
            /* A VAAPI device that decodes but does not encode ends up here,
             * and so does one whose driver will not scale to NV12. Both are
             * hosts the agent still works on. */
            printf("hwenc_abi_smoke: zero-copy could not be built here: %s\n",
                sImport[0] ? sImport : "no reason reported");

            return 0;
        }

        printf("hwenc_abi_smoke: zero-copy encoder is %s\n", DirectGate_HWEnc_Describe(pEncoder));

        /* Nothing has been imported yet, so this has no picture to re-encode
         * and must say so - rather than encode whatever the surface it was
         * given happens to contain. */
        xbyte_buffer_t encoded;
        xbool_t bKeyframe = XFALSE;
        XByteBuffer_Init(&encoded, XSTDNON, XFALSE);

        int nEncoded = DirectGate_HWEnc_EncodeImport(pEncoder, NULL, 0, XTRUE, &encoded, &bKeyframe);
        size_t nProduced = encoded.nUsed;

        XByteBuffer_Clear(&encoded);
        DirectGate_HWEnc_Destroy(pEncoder);

        if (nEncoded != XSTDNON || nProduced != 0)
        {
            fprintf(stderr, "hwenc_abi_smoke: zero-copy encoder produced %zu bytes before any frame (%d)\n",
                nProduced, nEncoded);

            return 1;
        }

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
