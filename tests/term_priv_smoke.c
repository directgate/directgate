#include "src/agent/term.c"

#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "term_priv_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

int main(void)
{
    directgate_term_t term;
    directgate_term_spawn_t spawn;
    memset(&term, 0, sizeof(term));
    xstrncpy(term.sShellUser, sizeof(term.sShellUser),
        "directgate-no-such-user-privdrop");

    CHECK(DirectGate_Term_ResolveShell(&term, &spawn) == XSTDERR,
        "missing configured shell user should fail closed");
    CHECK(spawn.ppEnv == NULL && spawn.pGroups == NULL,
        "a refused spawn leaves nothing allocated behind");

    struct passwd *pSelf = getpwuid(getuid());
    if (pSelf != NULL && xstrused(pSelf->pw_name))
    {
        char sUser[256], sHome[1024];
        xstrncpy(sUser, sizeof(sUser), pSelf->pw_name);
        xstrncpy(sHome, sizeof(sHome), pSelf->pw_dir);

        memset(&term, 0, sizeof(term));
        xstrncpy(term.sShellUser, sizeof(term.sShellUser), sUser);
        xstrncpy(term.sShellHome, sizeof(term.sShellHome), ".");

        /* What the shell inherits has to describe the account it runs as, not
           the process that started the agent. */
        setenv("HOME", "/directgate-not-this-home", 1);
        setenv("USER", "directgate-not-this-user", 1);

        CHECK(DirectGate_Term_ResolveShell(&term, &spawn) == XSTDOK,
            "the current user resolves for a spawn");
        CHECK(!spawn.bSwitchUser, "the current shell user does not require a privilege drop");
        CHECK(strcmp(spawn.sWorkDir, ".") == 0, "shell.home is the directory the shell starts in");
        CHECK(access(spawn.sShell, X_OK) == 0, "the resolved shell can be executed");

        xbool_t bHome = XFALSE, bUser = XFALSE, bLogName = XFALSE, bTerm = XFALSE;
        for (size_t i = 0; spawn.ppEnv != NULL && spawn.ppEnv[i] != NULL; i++)
        {
            const char *pEntry = spawn.ppEnv[i];
            CHECK(strstr(pEntry, "directgate-not-this") == NULL,
                "the agent's own identity variables are not passed to the shell");

            if (!strncmp(pEntry, "HOME=", 5) && !strcmp(pEntry + 5, sHome)) bHome = XTRUE;
            if (!strncmp(pEntry, "USER=", 5) && !strcmp(pEntry + 5, sUser)) bUser = XTRUE;
            if (!strncmp(pEntry, "LOGNAME=", 8) && !strcmp(pEntry + 8, sUser)) bLogName = XTRUE;
            if (!strcmp(pEntry, "TERM=xterm-256color")) bTerm = XTRUE;
        }

        CHECK(bHome && bUser && bLogName, "HOME, USER and LOGNAME name the account the shell runs as");
        CHECK(bTerm, "the shell gets the terminal type the viewer emulates");
        DirectGate_Term_FreeSpawn(&spawn);
    }

    puts("term_priv_smoke: OK");
    return 0;
}
