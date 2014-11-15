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

// Catch signals
static int s_interrupted = 0;
static void s_signal_handler (int signal_value)
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
        }
        freefare_free_tags(tags);
        // And if we had tags then wait half a sec before polling again
        usleep(500 * 1000);
    }

    nfc_close (device);
    nfc_exit(nfc_ctx);
    exit(EXIT_SUCCESS);
}
