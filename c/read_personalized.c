#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

#include <string.h> // memcpy
#include <stdlib.h> //realloc

#include <pthread.h>

#include <nfc/nfc.h>
#include <freefare.h>

#include "smart_node_config.h"
#include "keydiversification.h"
#include "helpers.h"

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
    uint8_t errcnt = 0;
    bool connected = false;
    MifareDESFireAID aid;
    MifareDESFireKey key;
    char *realuid_str = NULL;
    uint8_t diversified_key_data[16];
    uint32_t acl;
    uint32_t mid;

RETRY:
    if (err != 0)
    {
        if (realuid_str)
        {
            free(realuid_str);
            realuid_str = NULL;
        }
        // TODO: Retry only on RF-errors
        ++errcnt;
        // TODO: resolve error string
        if (errcnt > errlimit)
        {
            printf("failed (%s), retry-limit exceeded (%d/%d), skipping tag\n", freefare_strerror(tag), errcnt, errlimit);
            goto FAIL;
        }
        printf("failed (%s), retrying (%d)\n", freefare_strerror(tag), errcnt);
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
    aid = mifare_desfire_aid_new(nfclock_aid[0] | (nfclock_aid[1] << 8) | (nfclock_aid[2] << 16));
    err = mifare_desfire_select_application(tag, aid);
    if (err < 0)
    {
        free(aid);
        aid = NULL;
        printf("Can't select application.");
        goto RETRY;
    }
    printf("done\n");
    free(aid);
    aid = NULL;

    printf("Authenticating, ");
    key = mifare_desfire_aes_key_new_with_version((uint8_t*)&nfclock_uid_key, 0x0);
    err = mifare_desfire_authenticate(tag, nfclock_uid_keyid, key);
    if (err < 0)
    {
        free(key);
        key = NULL;
        printf("Can't Authenticate. ");
        goto RETRY;
    }
    free(key);
    key = NULL;
    printf("done\n");

    printf("Getting real UID, ");
    err = mifare_desfire_get_card_uid(tag, &realuid_str);
    if (err < 0)
    {
        printf("Can't get real UID. ");
        goto RETRY;
    }
    printf("%s\n", realuid_str);

    err = nfclock_diversify_key_aes128((uint8_t *)nfclock_acl_read_key_base, (uint8_t*)nfclock_aid, realuid_str, (uint8_t*)nfclock_sysid, sizeof(nfclock_sysid), diversified_key_data);
    if (err != 0)
    {
        printf("Can't calculate diversified key, failing\n");
        goto FAIL;
    }

    printf("Re-auth with ACL read key, ");
    key = mifare_desfire_aes_key_new_with_version((uint8_t*)diversified_key_data, 0x0);
    err = mifare_desfire_authenticate(tag, nfclock_acl_read_keyid, key);
    if (err < 0)
    {
        free(key);
        key = NULL;
        printf("Can't Authenticate. ");
        goto RETRY;
    }
    free(key);
    key = NULL;
    printf("done\n");

    printf("Reading ACL file, ");
    err = nfclock_read_uint32(tag, nfclock_acl_file_id, &acl);
    if (err < 0)
    {
        goto RETRY;
    }
    printf("done, got 0x%lx \n", (unsigned long)acl);


    printf("Reading member-id file, ");
    err = nfclock_read_uint32(tag, nfclock_mid_file_id, &mid);
    if (err < 0)
    {
        goto RETRY;
    }
    printf("done, got 0x%lx \n", (unsigned long)mid);

    // All checks done seems good
    if (realuid_str)
    {
        free(realuid_str);
        realuid_str = NULL;
    }
    mifare_desfire_disconnect(tag);
    *tag_valid = true;
    return 0;

FAIL:
    if (realuid_str)
    {
        free(realuid_str);
        realuid_str = NULL;
    }
    if (connected)
    {
        mifare_desfire_disconnect(tag);
    }
    *tag_valid = false;
    return err;
}


pthread_mutex_t tag_processing = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t tag_done = PTHREAD_COND_INITIALIZER;

struct thread_data {
   MifareTag tag;
   bool tag_valid;
   int  err;
};

void *handle_tag_pthread(void *threadarg)
{
    /* allow the thread to be killed at any time */
    int oldstate;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldstate);

    // Cast our data struct 
    struct thread_data *my_data;
    my_data = (struct thread_data *) threadarg;
    // Start processing
    my_data->err = handle_tag(my_data->tag, &my_data->tag_valid);

    // Signal done and return
    pthread_cond_signal(&tag_done);
    pthread_exit(NULL);
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
        // This will lose a few bytes of memory for some reason, the commented out frees below do not affect the result :(
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
                //free(devices[d]);
                printf("nfc_open() failed for %s", devices[d]);
                error = EXIT_FAILURE;
                continue;
            }
            strncpy(connstring, devices[d], NFC_BUFSIZE_CONNSTRING);
            //free(devices[d]);
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
        if (   !tags // allocation failed
            // The tag array ends with null element, if first one is null then array is empty
            || !tags[0])
        {
            if (tags)
            {
                // Free the empty array so we don't leak memory
                freefare_free_tags(tags);
                tags = NULL;
            }
            // Limit polling speed to 10Hz
            usleep(100 * 1000);
            //printf("Polling ...\n");
            continue;
        }

        bool valid_found = false;
        int err = 0;
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


            // pthreads initialization stuff
            struct timespec abs_time;
            pthread_t tid;
            pthread_mutex_lock(&tag_processing);
        
            /* pthread cond_timedwait expects an absolute time to wait until */
            clock_gettime(CLOCK_REALTIME, &abs_time);
            abs_time.tv_sec += 1;
        
            // Use this struct to pass data between thread and main
            struct thread_data tagdata;
            tagdata.tag = tags[i];
        
            err = pthread_create(&tid, NULL, handle_tag_pthread, (void *)&tagdata);
            if (err != 0)
            {
                printf("ERROR: pthread_create error %d\n", err);
                continue;
            }
        
            err = pthread_cond_timedwait(&tag_done, &tag_processing, &abs_time);
            if (err == ETIMEDOUT)
            {
                    printf("TIMED OUT\n");
                    pthread_cancel(tid);
                    pthread_join(tid, NULL);
                    pthread_mutex_unlock(&tag_processing);
                    continue;
            }
            pthread_join(tid, NULL);
            pthread_mutex_unlock(&tag_processing);
            if (err)
            {
                printf("ERROR: pthread_cond_timedwait error %d\n", err);
                continue;
            }

            if (tagdata.err != 0)
            {
                tagdata.tag_valid = false;
                continue;
            }
            if (tagdata.tag_valid)
            {
                valid_found = true;
            }
        }
        freefare_free_tags(tags);
        tags = NULL;
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
