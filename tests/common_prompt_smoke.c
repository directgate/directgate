/*
 * The interactive prompt helpers and the environment probes around them.
 *
 * Every prompt reads with fgets and the password one also drives termios, so
 * this drives them through a pseudo-terminal: a plain pipe or file makes
 * tcgetattr fail with ENOTTY and the read never happens. Nothing else in the
 * suite reaches these, and they are the front door of `directgate -i`.
 */

/* posix_openpt/grantpt/ptsname are XOPEN, not in the default ISO C view. */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "src/common/common.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "common_prompt_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

/* A pty whose master end is preloaded with the answers a prompt will read. */
typedef struct {
    int nMaster;
    int nSlave;
    int nSavedStdin;
} prompt_tty_t;

static int tty_open(prompt_tty_t *pTty, const char *pAnswers)
{
    pTty->nMaster = posix_openpt(O_RDWR | O_NOCTTY);
    if (pTty->nMaster < 0) return 0;

    if (grantpt(pTty->nMaster) != 0 || unlockpt(pTty->nMaster) != 0)
    {
        close(pTty->nMaster);
        return 0;
    }

    const char *pName = ptsname(pTty->nMaster);
    if (pName == NULL)
    {
        close(pTty->nMaster);
        return 0;
    }

    pTty->nSlave = open(pName, O_RDWR | O_NOCTTY);
    if (pTty->nSlave < 0)
    {
        close(pTty->nMaster);
        return 0;
    }

    size_t nLen = strlen(pAnswers);
    if (nLen > 0 && write(pTty->nMaster, pAnswers, nLen) != (ssize_t)nLen)
    {
        close(pTty->nSlave);
        close(pTty->nMaster);
        return 0;
    }

    pTty->nSavedStdin = dup(STDIN_FILENO);
    if (pTty->nSavedStdin < 0 || dup2(pTty->nSlave, STDIN_FILENO) < 0)
    {
        close(pTty->nSlave);
        close(pTty->nMaster);
        return 0;
    }

    clearerr(stdin);
    return 1;
}

static void tty_close(prompt_tty_t *pTty)
{
    dup2(pTty->nSavedStdin, STDIN_FILENO);
    close(pTty->nSavedStdin);
    close(pTty->nSlave);
    close(pTty->nMaster);
    clearerr(stdin);
}

int main(void)
{
    /* PathToSlash is a no-op off Windows but must still tolerate whatever it
       is handed, including a null pointer. */
    {
        char sPath[64];
        snprintf(sPath, sizeof(sPath), "C:\\Users\\kala\\dir");
        DirectGate_PathToSlash(sPath);
        CHECK(strlen(sPath) == strlen("C:\\Users\\kala\\dir"),
            "PathToSlash keeps the path length");
        DirectGate_PathToSlash(NULL);
    }

    /* The account name is what the file manager reports as owner on Windows
       and what the shell user defaults to elsewhere. */
    {
        char sUser[XSTR_MID];
        size_t nLen = DirectGate_GetUserName(sUser, sizeof(sUser));
        CHECK(nLen == strlen(sUser), "GetUserName returns the written length");
        CHECK(DirectGate_GetUserName(NULL, sizeof(sUser)) == 0,
            "GetUserName rejects a null buffer");
        CHECK(DirectGate_GetUserName(sUser, 0) == 0,
            "GetUserName rejects a zero-sized buffer");
    }

    /* Home directory resolution feeds the default config path. */
    {
        char sRoot[] = "/tmp/directgate_common_prompt_smoke.XXXXXX";
        CHECK(mkdtemp(sRoot) != NULL, "mkdtemp root");
        CHECK(setenv("HOME", sRoot, 1) == 0, "set HOME");

        char sHome[XPATH_MAX];
        size_t nLen = DirectGate_GetHomeDir(sHome, sizeof(sHome));
        CHECK(nLen > 0, "home directory resolves");
        CHECK(strcmp(sHome, sRoot) == 0, "home directory follows HOME");
        CHECK(DirectGate_GetHomeDir(NULL, sizeof(sHome)) == 0,
            "GetHomeDir rejects a null buffer");
    }

    /* Selecting a CA bundle must be safe to call more than once and must not
       trip over a missing or empty candidate. */
    DirectGate_InitTrustStore();
    DirectGate_InitTrustStore();

    /* Prompts. Skip rather than fail where no pty can be allocated: that is a
       property of the sandbox, not of the code under test. */
    {
        prompt_tty_t tty;
        if (!tty_open(&tty, "typed-value\n"))
        {
            puts("common_prompt_smoke: no pty available, skipping prompts");
            puts("common_prompt_smoke: OK");
            return 0;
        }

        char sValue[64] = {0};
        CHECK(DirectGate_PromptString("Label", sValue, sizeof(sValue), "", XTRUE),
            "PromptString accepts typed input");
        CHECK(strcmp(sValue, "typed-value") == 0, "PromptString stores the input");
        tty_close(&tty);
    }

    {
        /* An empty line takes the offered default. */
        prompt_tty_t tty;
        CHECK(tty_open(&tty, "\n"), "open pty for default answer");

        char sValue[64] = {0};
        CHECK(DirectGate_PromptString("Label", sValue, sizeof(sValue),
            "fallback", XTRUE), "PromptString falls back to the default");
        CHECK(strcmp(sValue, "fallback") == 0, "the default is stored");
        tty_close(&tty);
    }

    {
        /* An optional prompt may be answered with nothing at all. */
        prompt_tty_t tty;
        CHECK(tty_open(&tty, "\n"), "open pty for optional answer");

        char sValue[64] = {0};
        CHECK(DirectGate_PromptString("Label", sValue, sizeof(sValue), "", XFALSE),
            "an optional prompt accepts an empty answer");
        CHECK(sValue[0] == '\0', "an empty optional answer stays empty");
        tty_close(&tty);
    }

    {
        /* A required prompt with neither input nor default re-asks, so give it
           a blank line first and a real answer second. */
        prompt_tty_t tty;
        CHECK(tty_open(&tty, "\nfinally\n"), "open pty for re-ask");

        char sValue[64] = {0};
        CHECK(DirectGate_PromptString("Label", sValue, sizeof(sValue), "", XTRUE),
            "a required prompt re-asks until answered");
        CHECK(strcmp(sValue, "finally") == 0, "the second answer is stored");
        tty_close(&tty);
    }

    {
        /* Every accepted spelling of yes and no, then a rejected one. */
        prompt_tty_t tty;
        CHECK(tty_open(&tty, "y\nN\n1\n0\n\nmaybe\n"), "open pty for booleans");

        xbool_t bValue = XFALSE;
        CHECK(DirectGate_PromptBool("Flag", &bValue), "PromptBool reads y");
        CHECK(bValue, "y means true");

        CHECK(DirectGate_PromptBool("Flag", &bValue), "PromptBool reads N");
        CHECK(!bValue, "N means false");

        CHECK(DirectGate_PromptBool("Flag", &bValue), "PromptBool reads 1");
        CHECK(bValue, "1 means true");

        CHECK(DirectGate_PromptBool("Flag", &bValue), "PromptBool reads 0");
        CHECK(!bValue, "0 means false");

        bValue = XTRUE;
        CHECK(DirectGate_PromptBool("Flag", &bValue), "an empty answer is accepted");
        CHECK(bValue, "an empty answer keeps the current value");

        CHECK(!DirectGate_PromptBool("Flag", &bValue), "an unparsable answer fails");
        tty_close(&tty);
    }

    {
        prompt_tty_t tty;
        CHECK(tty_open(&tty, "4242\n\n"), "open pty for u16");

        uint16_t nValue = 7;
        CHECK(DirectGate_PromptU16("Number", &nValue), "PromptU16 reads a number");
        CHECK(nValue == 4242, "PromptU16 stores the number");

        CHECK(DirectGate_PromptU16("Number", &nValue), "an empty answer is accepted");
        CHECK(nValue == 4242, "an empty answer keeps the current value");
        tty_close(&tty);
    }

    {
        prompt_tty_t tty;
        CHECK(tty_open(&tty, "70000\n\n"), "open pty for u32");

        uint32_t nValue = 3;
        CHECK(DirectGate_PromptU32("Number", &nValue),
            "PromptU32 reads a value beyond 16 bits");
        CHECK(nValue == 70000u, "PromptU32 stores the number");

        CHECK(DirectGate_PromptU32("Number", &nValue), "an empty answer is accepted");
        CHECK(nValue == 70000u, "an empty answer keeps the current value");
        tty_close(&tty);
    }

    /* Null arguments must be refused rather than dereferenced. */
    CHECK(!DirectGate_PromptBool("Flag", NULL), "PromptBool rejects a null value");
    CHECK(!DirectGate_PromptBool(NULL, NULL), "PromptBool rejects a null label");
    CHECK(!DirectGate_PromptU16("Number", NULL), "PromptU16 rejects a null value");
    CHECK(!DirectGate_PromptU32("Number", NULL), "PromptU32 rejects a null value");
    CHECK(!DirectGate_PromptString("Label", NULL, 16, "", XFALSE),
        "PromptString rejects a null buffer");

    puts("common_prompt_smoke: OK");
    return 0;
}
