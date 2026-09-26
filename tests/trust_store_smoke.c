/*
 * Finding the host's TLS trust anchors when the location built into libcrypto
 * is wrong, and the identity probes when the password database has no entry.
 *
 * DirectGate_InitTrustStore only acts when the path compiled into libcrypto
 * holds nothing usable, which never happens on the machine that built it. So
 * the cases run in a child with its own user and mount namespaces: every
 * certificate directory is covered by an empty tmpfs, and exactly the layout
 * under test is put back. The same child runs as a uid the password database
 * has never heard of - the one situation in which the home directory and the
 * account name have only the environment to go on.
 *
 * Where unprivileged user namespaces are switched off, this skips.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "src/common/common.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "trust_store_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#ifdef __linux__

#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <openssl/x509.h>

/* No passwd entry anywhere has this uid. */
#define STRANGER_UID 54321

static int write_text(const char *pPath, const char *pText)
{
    FILE *pFile = fopen(pPath, "w");
    if (pFile == NULL) return 0;

    size_t nLen = strlen(pText);
    int nOk = fwrite(pText, 1, nLen, pFile) == nLen;
    return (fclose(pFile) == 0) && nOk;
}

/* mkdir -p, for directories inside the tmpfs mounts only. */
static int make_dirs(const char *pPath)
{
    char sPath[XPATH_MAX];
    snprintf(sPath, sizeof(sPath), "%s", pPath);

    for (char *pSlash = strchr(sPath + 1, '/'); ; pSlash = strchr(pSlash + 1, '/'))
    {
        if (pSlash != NULL) *pSlash = '\0';
        if (mkdir(sPath, 0755) != 0 && errno != EEXIST) return 0;
        if (pSlash == NULL) return 1;
        *pSlash = '/';
    }
}

/* The agent's own rule: a non-empty file, or a directory with something in it. */
static int usable(const char *pPath)
{
    struct stat status;
    if (pPath == NULL || pPath[0] == '\0' || stat(pPath, &status) != 0) return 0;
    if (S_ISREG(status.st_mode)) return status.st_size > 0;
    if (!S_ISDIR(status.st_mode)) return 0;

    DIR *pDir = opendir(pPath);
    if (pDir == NULL) return 0;

    int nFound = 0;
    struct dirent *pEntry;
    while (!nFound && (pEntry = readdir(pDir)) != NULL) nFound = (pEntry->d_name[0] != '.');

    closedir(pDir);
    return nFound;
}

static void hide(const char *pPath)
{
    struct stat status;
    if (stat(pPath, &status) != 0 || !S_ISDIR(status.st_mode)) return;
    (void)mount("tmpfs", pPath, "tmpfs", 0, "mode=0755");
}

static void clear_choice(void)
{
    unsetenv("SSL_CERT_FILE");
    unsetenv("SSL_CERT_DIR");
}

static int chosen(const char *pName, const char *pWant)
{
    const char *pValue = getenv(pName);
    if (pWant == NULL) return pValue == NULL;
    return pValue != NULL && strcmp(pValue, pWant) == 0;
}

static int trust_store_cases(const char *pDefaultFile, const char *pDefaultDir)
{
    /* Nothing anywhere: the agent says so and points OpenSSL at nothing. */
    clear_choice();
    DirectGate_InitTrustStore();
    CHECK(chosen("SSL_CERT_FILE", NULL) && chosen("SSL_CERT_DIR", NULL), "with no trust store anywhere nothing is chosen");

    /* Shapes that stat() would take for a trust store, none of which OpenSSL could use. */
    CHECK(make_dirs("/etc/ssl/certs"), "create an empty certificate directory");
    CHECK(write_text("/etc/ssl/certs/.keep", ""), "leave only a dot file in it");
    CHECK(write_text("/etc/ssl/ca-bundle.pem", ""), "create an empty bundle");
    CHECK(mkfifo("/etc/ssl/cert.pem", 0644) == 0, "put a fifo where a bundle should be");
    clear_choice();
    DirectGate_InitTrustStore();
    CHECK(chosen("SSL_CERT_FILE", NULL) && chosen("SSL_CERT_DIR", NULL),
        "an empty bundle, a fifo and a directory of dot files are not trust stores");

    /* A directory with certificates in it, when no bundle has any. */
    static const char *pDirs[] = { "/etc/ssl/certs", "/etc/pki/tls/certs" };
    const char *pUsedDir = NULL;
    for (size_t i = 0; i < sizeof(pDirs) / sizeof(pDirs[0]) && pUsedDir == NULL; i++)
    {
        char sAnchor[XPATH_MAX];
        snprintf(sAnchor, sizeof(sAnchor), "%s/anchor.pem", pDirs[i]);
        if (!make_dirs(pDirs[i]) || !write_text(sAnchor, "anchor\n")) continue;

        /* Where this directory is the built-in default, it proves nothing. */
        if (usable(pDefaultFile) || usable(pDefaultDir))
        {
            unlink(sAnchor);
            continue;
        }

        clear_choice();
        DirectGate_InitTrustStore();
        CHECK(chosen("SSL_CERT_FILE", NULL), "a directory is not taken for a bundle");
        CHECK(chosen("SSL_CERT_DIR", pDirs[i]), "a directory with certificates is used when no bundle has any");
        pUsedDir = pDirs[i];
    }

    /* A bundle wins over that directory: it needs no c_rehash to have been run. */
    CHECK(write_text("/etc/ssl/ca-bundle.pem", "bundle\n"), "fill the bundle");
    if (!usable(pDefaultFile) && !usable(pDefaultDir))
    {
        clear_choice();
        DirectGate_InitTrustStore();
        CHECK(chosen("SSL_CERT_FILE", "/etc/ssl/ca-bundle.pem"), "a bundle with something in it is used");
        CHECK(chosen("SSL_CERT_DIR", NULL), "with a bundle found, no directory is chosen as well");
    }

    /* Whatever the operator set is never second-guessed, however useless. */
    clear_choice();
    setenv("SSL_CERT_DIR", "/nowhere/at/all", 1);
    DirectGate_InitTrustStore();
    CHECK(chosen("SSL_CERT_FILE", NULL) && chosen("SSL_CERT_DIR", "/nowhere/at/all"), "an explicit SSL_CERT_DIR wins");

    clear_choice();
    setenv("SSL_CERT_FILE", "/nowhere/cert.pem", 1);
    DirectGate_InitTrustStore();
    CHECK(chosen("SSL_CERT_FILE", "/nowhere/cert.pem") && chosen("SSL_CERT_DIR", NULL), "an explicit SSL_CERT_FILE wins");

    /* And a usable built-in default is left alone, fallbacks or not. */
    char sParent[XPATH_MAX];
    snprintf(sParent, sizeof(sParent), "%s", pDefaultFile != NULL ? pDefaultFile : "");
    char *pSlash = strrchr(sParent, '/');
    if (pSlash != NULL && pSlash != sParent)
    {
        *pSlash = '\0';
        if (make_dirs(sParent) && write_text(pDefaultFile, "default\n"))
        {
            clear_choice();
            DirectGate_InitTrustStore();
            CHECK(chosen("SSL_CERT_FILE", NULL) && chosen("SSL_CERT_DIR", NULL), "a usable default is not overridden");
        }
    }

    (void)pUsedDir;
    return 0;
}

static int stranger_cases(void)
{
    /* nss can still know the uid (an LDAP or sssd domain); then there is nothing to prove. */
    if (getpwuid(getuid()) != NULL) return 0;

    char sBuf[XPATH_MAX];
    unsetenv("HOME");
    CHECK(DirectGate_GetHomeDir(sBuf, sizeof(sBuf)) == 0 && sBuf[0] == '\0',
        "with neither HOME nor a passwd entry there is no home directory");

    setenv("USER", "stranger", 1);
    CHECK(DirectGate_GetUserName(sBuf, sizeof(sBuf)) == strlen("stranger") && strcmp(sBuf, "stranger") == 0,
        "without a passwd entry the account name comes from USER");

    unsetenv("USER");
    CHECK(DirectGate_GetUserName(sBuf, sizeof(sBuf)) == 0 && sBuf[0] == '\0',
        "with neither a passwd entry nor USER there is no account name");
    return 0;
}

static int isolated_child(void)
{
    uid_t nOuterUid = getuid();
    gid_t nOuterGid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) return 77;

    /* The gid needs a mapping too: files created with an unmapped one fail with EOVERFLOW. */
    char sMap[64];
    snprintf(sMap, sizeof(sMap), "%u %u 1\n", (unsigned)STRANGER_UID, (unsigned)nOuterUid);
    if (!write_text("/proc/self/uid_map", sMap)) return 77;
    snprintf(sMap, sizeof(sMap), "%u %u 1\n", (unsigned)STRANGER_UID, (unsigned)nOuterGid);
    if (!write_text("/proc/self/setgroups", "deny") || !write_text("/proc/self/gid_map", sMap)) return 77;
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) return 77;

    const char *pDefaultFile = X509_get_default_cert_file();
    const char *pDefaultDir = X509_get_default_cert_dir();

    static const char *pRoots[] = { "/etc/ssl", "/etc/pki", "/etc/ca-certificates", "/opt/homebrew/etc", "/usr/local/etc" };
    for (size_t i = 0; i < sizeof(pRoots) / sizeof(pRoots[0]); i++) hide(pRoots[i]);
    if (usable(pDefaultDir)) hide(pDefaultDir);

    /* A default outside every root above, and not a directory to cover: nothing to test with. */
    if (usable(pDefaultFile) || usable(pDefaultDir)) return 77;

    if (trust_store_cases(pDefaultFile, pDefaultDir)) return 1;
    return stranger_cases();
}

int main(void)
{
    /* Without HOME, the home directory is the one in the password database. */
    char sSavedHome[XPATH_MAX] = { 0 };
    const char *pHome = getenv("HOME");
    if (pHome != NULL) snprintf(sSavedHome, sizeof(sSavedHome), "%s", pHome);

    unsetenv("HOME");
    struct passwd *pUser = getpwuid(getuid());
    if (pUser != NULL && pUser->pw_dir != NULL && pUser->pw_dir[0] != '\0')
    {
        char sHome[XPATH_MAX];
        CHECK(DirectGate_GetHomeDir(sHome, sizeof(sHome)) == strlen(pUser->pw_dir) && strcmp(sHome, pUser->pw_dir) == 0,
            "without HOME the passwd entry names the home directory");
    }
    if (sSavedHome[0] != '\0') setenv("HOME", sSavedHome, 1);

    pid_t nPid = fork();
    CHECK(nPid >= 0, "fork the isolated child");
    /* exit, not _exit: the child's coverage is written by its exit handlers. */
    if (nPid == 0) exit(isolated_child());

    int nStatus = 0;
    CHECK(waitpid(nPid, &nStatus, 0) == nPid, "wait for the isolated child");
    CHECK(WIFEXITED(nStatus), "the isolated child exits normally");

    if (WEXITSTATUS(nStatus) == 77)
    {
        puts("trust_store_smoke: no unprivileged user namespaces here, skipping");
        return 77;
    }

    CHECK(WEXITSTATUS(nStatus) == 0, "the isolated cases pass");
    puts("trust_store_smoke: OK");
    return 0;
}

#else

int main(void)
{
    puts("trust_store_smoke: needs Linux namespaces, skipping");
    return 77;
}

#endif /* __linux__ */
