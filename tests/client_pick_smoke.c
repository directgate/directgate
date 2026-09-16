/*
 * The dgcli device picker, on the path a script or a pipe takes.
 *
 * Whenever stdin is not a terminal - CI, a pipe, a wrapper script - the arrow
 * key picker is replaced by a numbered prompt, and that prompt is the only
 * thing standing between a typo and connecting to the wrong machine. Every
 * case here is about which answer selects nothing: an index outside the list,
 * a device the account cannot connect to, junk, and end of input.
 *
 * Selecting the wrong device is not a cosmetic failure - it puts a remote
 * shell on a host the operator did not mean to touch.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "src/client/devices.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "client_pick_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

static char g_sRoot[] = "/tmp/directgate_client_pick.XXXXXX";
static char g_sInput[512];

/* Points stdin at a file holding what an operator would have typed. This also
 * makes isatty() false, which is exactly the branch under test. */
static int answer_with(const char *pText)
{
    FILE *pFile = fopen(g_sInput, "wb");
    if (pFile == NULL) return 0;

    if (pText != NULL && fwrite(pText, 1, strlen(pText), pFile) != strlen(pText))
    {
        fclose(pFile);
        return 0;
    }

    if (fclose(pFile) != 0) return 0;
    return freopen(g_sInput, "rb", stdin) != NULL;
}

static void add_device(directgate_device_list_t *pList, const char *pId, const char *pName,
                       xbool_t bOnline, xbool_t bConnectable, const char *pReason)
{
    directgate_device_t *pDevice = &pList->devices[pList->nCount++];
    memset(pDevice, 0, sizeof(*pDevice));

    xstrncpy(pDevice->sId, sizeof(pDevice->sId), pId);
    xstrncpy(pDevice->sName, sizeof(pDevice->sName), pName);
    if (pReason != NULL) xstrncpy(pDevice->sReason, sizeof(pDevice->sReason), pReason);

    pDevice->bOnline = bOnline;
    pDevice->bOwned = XTRUE;
    pDevice->bConnectable = bConnectable;
}

static int test_find(void)
{
    directgate_device_list_t list;
    memset(&list, 0, sizeof(list));

    add_device(&list, "11111111-1111-1111-1111-111111111111", "laptop", XTRUE, XTRUE, NULL);
    add_device(&list, "22222222-2222-2222-2222-222222222222", "laptop-spare", XTRUE, XTRUE, NULL);
    add_device(&list, "33333333-3333-3333-3333-333333333333", "server", XFALSE, XFALSE, "offline");

    CHECK(DirectGate_Devices_Find(&list, "22222222-2222-2222-2222-222222222222") == 1,
        "an exact device id resolves to its entry");
    CHECK(DirectGate_Devices_Find(&list, "server") == 2,
        "an exact device name resolves even when the device cannot be connected");
    CHECK(DirectGate_Devices_Find(&list, "serv") == 2,
        "a unique name prefix resolves to its entry");
    CHECK(DirectGate_Devices_Find(&list, "SERV") == 2,
        "a unique name prefix ignores case");

    /* "laptop" prefixes two devices, and guessing between them would connect
     * to a machine the operator did not name. The exact-name pass is
     * case-sensitive, so a differently-cased "LAPTOP" is a prefix too. */
    CHECK(DirectGate_Devices_Find(&list, "lap") == DIRECTGATE_DEVICE_NO_PICK,
        "an ambiguous name prefix resolves to nothing rather than guessing");
    CHECK(DirectGate_Devices_Find(&list, "LAPTOP") == DIRECTGATE_DEVICE_NO_PICK,
        "a differently-cased name that prefixes two devices resolves to nothing");
    CHECK(DirectGate_Devices_Find(&list, "laptop") == 0,
        "an exactly matching name wins over the devices it also prefixes");
    CHECK(DirectGate_Devices_Find(&list, "nothing") == DIRECTGATE_DEVICE_NO_PICK,
        "an unknown query resolves to nothing");
    CHECK(DirectGate_Devices_Find(&list, "") == DIRECTGATE_DEVICE_NO_PICK,
        "an empty query resolves to nothing");
    CHECK(DirectGate_Devices_Find(&list, NULL) == DIRECTGATE_DEVICE_NO_PICK,
        "a missing query resolves to nothing");
    CHECK(DirectGate_Devices_Find(NULL, "laptop") == DIRECTGATE_DEVICE_NO_PICK,
        "a missing list resolves to nothing");

    /* Printing is the "dgcli devices" output; it must survive every state a
     * device can be in, including one with no reason text behind it. */
    DirectGate_Devices_Print(&list);
    DirectGate_Devices_Print(NULL);

    return 0;
}

static int test_select(void)
{
    directgate_device_list_t list;
    memset(&list, 0, sizeof(list));

    CHECK(DirectGate_Devices_Select(NULL, "connect to") == DIRECTGATE_DEVICE_ABORTED,
        "selecting from a missing list aborts");
    CHECK(DirectGate_Devices_Select(&list, "connect to") == DIRECTGATE_DEVICE_ABORTED,
        "selecting from an empty list aborts");

    /* One device the account can use is not a choice worth asking about. */
    add_device(&list, "11111111-1111-1111-1111-111111111111", "laptop", XTRUE, XTRUE, NULL);
    CHECK(answer_with(""), "point stdin at an empty answer");
    CHECK(DirectGate_Devices_Select(&list, "connect to") == 0,
        "a single connectable device is chosen without asking");

    /* One device the account cannot use is not a choice at all. */
    list.devices[0].bConnectable = XFALSE;
    CHECK(answer_with("1\n"), "answer the prompt with the unusable device");
    CHECK(DirectGate_Devices_Select(&list, "connect to") == DIRECTGATE_DEVICE_ABORTED,
        "a device the account cannot connect to is never selected");

    list.devices[0].bConnectable = XTRUE;
    add_device(&list, "22222222-2222-2222-2222-222222222222", "server", XTRUE, XTRUE, NULL);
    add_device(&list, "33333333-3333-3333-3333-333333333333", "revoked", XFALSE, XFALSE, "revoked");

    CHECK(answer_with("2\n"), "answer the prompt with a valid choice");
    CHECK(DirectGate_Devices_Select(&list, "connect to") == 1,
        "a valid numbered choice selects that device");

    CHECK(answer_with("1\n"), "answer the prompt with the first device");
    CHECK(DirectGate_Devices_Select(&list, "connect to") == 0,
        "the numbering the prompt shows is one-based");

    struct {
        const char *pAnswer;
        const char *pMsg;
    } refused[] = {
        { "0\n",   "a choice below the list aborts rather than wrapping to the end" },
        { "4\n",   "a choice past the end of the list aborts" },
        { "-1\n",  "a negative choice aborts" },
        { "99\n",  "a wildly out-of-range choice aborts" },
        { "abc\n", "a non-numeric answer aborts" },
        { "\n",    "an empty answer aborts" },
        { "3\n",   "choosing a device the account cannot connect to aborts" },
        { NULL,    "end of input aborts rather than selecting the first device" }
    };

    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
    {
        CHECK(answer_with(refused[i].pAnswer != NULL ? refused[i].pAnswer : ""),
            "point stdin at a refused answer");
        CHECK(DirectGate_Devices_Select(&list, "connect to") == DIRECTGATE_DEVICE_ABORTED,
            refused[i].pMsg);
    }

    /* A number with trailing text still names one device unambiguously. */
    CHECK(answer_with("2 please\n"), "answer with a number and trailing text");
    CHECK(DirectGate_Devices_Select(&list, "connect to") == 1,
        "a numbered answer with trailing text still selects that device");

    /* The purpose is the verb in the heading; a missing one must not print a
     * null pointer at an operator about to pick a machine. */
    CHECK(answer_with("2\n"), "answer the prompt for the default purpose");
    CHECK(DirectGate_Devices_Select(&list, NULL) == 1,
        "a selection with no stated purpose still works");

    return 0;
}

int main(void)
{
    CHECK(mkdtemp(g_sRoot) != NULL, "make a scratch directory");
    snprintf(g_sInput, sizeof(g_sInput), "%s/answer", g_sRoot);

    int nStatus = test_find();
    if (!nStatus) nStatus = test_select();

    unlink(g_sInput);
    rmdir(g_sRoot);

    if (nStatus) return nStatus;

    puts("client_pick_smoke: OK");
    return 0;
}
