#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

#include <string.h> // memcpy
#include <stdlib.h> //realloc

#include <nfc/nfc.h>
#include <freefare.h>

#include "smart_node_config.h"
#include "keydiversification.h"

// Catch SIGINT and SIGTERM so we can do a clean exit
static int s_interrupted = 0;
static void s_signal_handler(int signal_value)
{
    s_interrupted = 1;
}

static void s_catch_signals (void)
{
    struct sigaction action;
    action.sa_handler = s_signal_handler;
    action.sa_flags = 0;
    sigemptyset (&action.sa_mask);
    sigaction (SIGINT, &action, NULL);
    sigaction (SIGTERM, &action, NULL);
}

int handle_tag(MifareTag tag, bool *tag_valid)
{
    const uint8_t errlimit = 3;
    int err = 0;
    /*
    uint32_t acl;
    uint32_t db_acl;
    bool revoked_found = false;
    */
    char errstr[] = "";
    uint8_t errcnt = 0;
    bool connected = false;
    MifareDESFireAID aid = mifare_desfire_aid_new(nfclock_aid[2] | (nfclock_aid[1] << 8) | (nfclock_aid[0] << 16));
    //printf("uint32 for aid: 0x%lx\n", (unsigned long)mifare_desfire_aid_get_aid(aid));

RETRY:
    if (err != 0)
    {
        // TODO: Retry only on RF-errors
        ++errcnt;
        // TODO: resolve error string
        if (errcnt > errlimit)
        {
            printf("failed (%s), retry-limit exceeded (%d/%d), skipping tag", errstr, errcnt, errlimit);
            goto FAIL;
        }
        printf("failed (%s), retrying (%d)", errstr, errcnt);
    }
    if (connected)
    {
        mifare_desfire_disconnect(tag);
        connected = false;
    }

    printf("Connecting, ");
    err = mifare_desfire_connect(tag);
    if (err < 0)
    {
        printf("Can't connect to Mifare DESFire target.");
        goto RETRY;
    }
    printf("done\n");
    connected = true;

    printf("Selecting application, ");
    err = mifare_desfire_select_application(tag, aid);
    if (err < 0)
    {
        printf("Can't select application.");
        goto RETRY;
    }
    printf("done\n");
    free(aid);


    // All checks done seems good
    mifare_desfire_disconnect(tag);
    *tag_valid = true;
    return 0;
FAIL:
    free(aid);
    if (connected)
    {
        mifare_desfire_disconnect(tag);
    }
    *tag_valid = false;
    return err;
}

int main(int argc, char *argv[])
{
    int error = EXIT_SUCCESS;

    nfc_context *nfc_ctx;
    nfc_init (&nfc_ctx);
    if (nfc_ctx == NULL)
    {
        errx(EXIT_FAILURE, "Unable to init libnfc (propbably malloc)");
    }


    // Connect to first by default, or to the connstring specified on CLI
    nfc_connstring connstring;
    nfc_device *device = NULL;
    if (argc == 2)
    {
        strncpy(connstring, argv[1], NFC_BUFSIZE_CONNSTRING);
        device = nfc_open (nfc_ctx, connstring);
        if (!device)
        {
            errx(EXIT_FAILURE, "Unable to open device %s", argv[1]);
        }
    }
    else
    {
        // TODO: This leaks memory but I have no idea what to do about it
        nfc_connstring devices[8];
        size_t device_count;
        device_count = nfc_list_devices(nfc_ctx, devices, 8);
        if (device_count <= 0)
        {
            errx (EXIT_FAILURE, "No NFC device found.");
        }
        for (size_t d = 0; d < device_count; ++d)
        {
            device = nfc_open (nfc_ctx, devices[d]);
            if (!device)
            {
                warn("nfc_open() failed for %s", devices[d]);
                error = EXIT_FAILURE;
                continue;
            }
            strncpy(connstring, devices[d], NFC_BUFSIZE_CONNSTRING);
            break;
        }
        if (error != EXIT_SUCCESS)
        {
            errx(error, "Could not open any device");
        }
    }
    printf("Using device %s\n", connstring);

    s_catch_signals();

    // Mainloop
    MifareTag *tags = NULL;
    while(!s_interrupted)
    {
        tags = freefare_get_tags(device);
        if (   !tags
            || !tags[0])
        {
            freefare_free_tags(tags);
            // Limit polling speed to 10Hz
            usleep(100 * 1000);
            //printf("Polling ...\n");
            continue;
        }

        bool valid_found = false;
        int tagerror = 0;
        for (int i = 0; (!error) && tags[i]; ++i)
        {
            char *tag_uid_str = freefare_get_tag_uid(tags[i]);
            if (DESFIRE != freefare_get_tag_type(tags[i]))
            {
                // Skip non DESFire tags
                printf("Skipping non DESFire tag %s\n", tag_uid_str);
                free (tag_uid_str);
                continue;
            }

            printf("Found DESFire tag %s\n", tag_uid_str);
            free (tag_uid_str);

            bool tag_valid = false;
            // TODO: Timeout this so the program does not hang if tag leaves at inopportune time
            tagerror = handle_tag(tags[i], &tag_valid);
            if (tagerror != 0)
            {
                tag_valid = false;
                continue;
            }
            if (tag_valid)
            {
                valid_found = true;
            }
        }
        freefare_free_tags(tags);
        if (valid_found)
        {
            printf("OK: valid tag found\n");
        }
        else
        {
            printf("ERROR: NO valid tag found\n");
        }

        // And if we had tags then wait half a sec before resuming polling again
        usleep(500 * 1000);
    }

    nfc_close (device);
    nfc_exit(nfc_ctx);
    exit(EXIT_SUCCESS);
}
