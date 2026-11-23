/*
 * Preloaded into dgcli by client_e2e_smoke: a file system without hard links (FAT, exFAT, some FUSE and network
 * mounts), where link() always fails, so dgcli has to fall back from its atomic no-clobber to a check and a rename.
 *
 *   SHIM_NO_HARDLINKS_MARK  a file created on the first call, so the test knows the shim was loaded and reached
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int link(const char *pOld, const char *pNew)
{
    (void)pOld;
    (void)pNew;

    const char *pMark = getenv("SHIM_NO_HARDLINKS_MARK");
    if (pMark != NULL)
    {
        int nFd = open(pMark, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
        if (nFd >= 0) close(nFd);
    }

    errno = EPERM;
    return -1;
}
