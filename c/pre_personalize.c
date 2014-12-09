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

#include "pre-personalize_config.h"
#include "keydiversification.h"


uint8_t key_data_null[8]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
MifareDESFireKey null_des_key;

uint8_t key_data_null16[16]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
MifareDESFireKey null_aes_key;


uint8_t applicationsettings(uint8_t accesskey, bool frozen, bool req_auth_fileops, bool req_auth_dir, bool allow_master_key_chg)
{
    uint8_t ret = 0;
    ret |= accesskey << 4;
    if (frozen)
    {
        ret |= 1 << 3;
    }
    if (req_auth_fileops)
    {
        ret |= 1 << 2;
    }
    if (req_auth_dir)
    {
        ret |= 1 << 1;
    }
    if (allow_master_key_chg)
    {
        ret |= 1;
    }
    return ret;
}



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
    char errstr[] = "";
    uint8_t errcnt = 0;
    bool connected = false;
    MifareDESFireKey key;
    char *realuid_str = NULL;
    MifareDESFireAID aid;
    uint8_t diversified_key_data[16];
    /*
    uint8_t aclbytes[4];
    uint32_t acl;
    uint8_t midbytes[2];
    uint16_t mid;
    */

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
            printf("failed (%s), retry-limit exceeded (%d/%d), skipping tag\n", errstr, errcnt, errlimit);
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

    printf("Authenticating (null key), ");
    err = mifare_desfire_authenticate(tag, 0x0, null_des_key);
    if (err < 0)
    {
        goto RETRY;
    }
    printf("done\n");

    /**
     * TODO: enable random id here
     */

    printf("Getting real UID, ");
    err = mifare_desfire_get_card_uid(tag, &realuid_str);
    if (err < 0)
    {
        goto RETRY;
    }
    printf("%s\n", realuid_str);

    printf("Changing Card Master Key, ");
    key = mifare_desfire_aes_key_new_with_version((uint8_t*)&nfclock_cmk, 0x0);
    err = mifare_desfire_change_key(tag, 0, key, null_des_key);
    if (err < 0)
    {
        free(key);
        key = NULL;
        goto RETRY;
    }
    free(key);
    key = NULL;
    printf("done\n");

    printf("Creating application, ");
    aid = mifare_desfire_aid_new(nfclock_aid[0] | (nfclock_aid[1] << 8) | (nfclock_aid[2] << 16));
    // Settings are: only master key may change other keys, configuration is not locked, authentication required for everything, AMK change allowed and we have 4 keys in the application
    err = mifare_desfire_create_application_aes(tag, aid, applicationsettings(0, false, true, true, true), 4);
    if (err < 0)
    {
        free(aid);
        aid = NULL;
        goto RETRY;
    }
    printf("done\n");
    free(aid);
    aid = NULL;

    printf("Selecting application, ");
    aid = mifare_desfire_aid_new(nfclock_aid[0] | (nfclock_aid[1] << 8) | (nfclock_aid[2] << 16));
    err = mifare_desfire_select_application(tag, aid);
    if (err < 0)
    {
        free(aid);
        aid = NULL;
        goto RETRY;
    }
    printf("done\n");
    free(aid);
    aid = NULL;

    printf("Re-Authenticating (null AES key), ");
    err = mifare_desfire_authenticate_aes(tag, 0, null_aes_key);
    if (err < 0)
    {
        goto RETRY;
    }
    printf("done\n");

    printf("Changing Application Master Key, ");
    key = mifare_desfire_aes_key_new_with_version((uint8_t*)&nfclock_amk, 0x0);
    err = mifare_desfire_change_key(tag, 0, key, null_des_key);
    if (err < 0)
    {
        free(key);
        key = NULL;
        goto RETRY;
    }
    free(key);
    key = NULL;
    printf("done\n");

    printf("Re-Authenticating (AMK), ");
    key = mifare_desfire_aes_key_new_with_version((uint8_t*)&nfclock_amk, 0x0);
    err = mifare_desfire_authenticate_aes(tag, 0, key);
    if (err < 0)
    {
        goto RETRY;
    }
    printf("done\n");

    printf("Changing UID read key, ");
    key = mifare_desfire_aes_key_new_with_version((uint8_t*)&nfclock_uid_key, 0x0);
    err = mifare_desfire_change_key(tag, nfclock_uid_keyid, key, null_aes_key);
    if (err < 0)
    {
        free(key);
        key = NULL;
        goto RETRY;
    }
    free(key);
    key = NULL;
    printf("done\n");


    err = nfclock_diversify_key_aes128((uint8_t *)nfclock_acl_read_key_base, (uint8_t*)nfclock_aid, realuid_str, (uint8_t*)nfclock_sysid, sizeof(nfclock_sysid), diversified_key_data);
    if (err != 0)
    {
        printf("Can't calculate diversified ACL read key, failing\n");
        goto FAIL;
    }
    printf("Changing ACL read key, ");
    key = mifare_desfire_aes_key_new_with_version((uint8_t *)&diversified_key_data, 0x0);
    err = mifare_desfire_change_key(tag, nfclock_acl_read_keyid, key, null_aes_key);
    if (err < 0)
    {
        free(key);
        key = NULL;
        goto RETRY;
    }
    free(key);
    key = NULL;
    printf("done\n");


    err = nfclock_diversify_key_aes128((uint8_t *)nfclock_acl_write_key_base, (uint8_t*)nfclock_aid, realuid_str, (uint8_t*)nfclock_sysid, sizeof(nfclock_sysid), diversified_key_data);
    if (err != 0)
    {
        printf("Can't calculate diversified ACL write key, failing\n");
        goto FAIL;
    }
    printf("Changing ACL write key, ");
    key = mifare_desfire_aes_key_new_with_version((uint8_t *)&diversified_key_data, 0x0);
    err = mifare_desfire_change_key(tag, nfclock_acl_write_keyid, key, null_aes_key);
    if (err < 0)
    {
        free(key);
        key = NULL;
        goto RETRY;
    }
    free(key);
    key = NULL;
    printf("done\n");


/*

    printf("Reading ACL file, ");
    err = mifare_desfire_read_data (tag, nfclock_acl_file_id, 0, sizeof(aclbytes), aclbytes);
    if (err < 0)
    {
        printf("got %d as bytes read", err);
        goto RETRY;
    }
    acl = aclbytes[0] | (aclbytes[1] << 8) | (aclbytes[2] << 16) | (aclbytes[3] << 24);
    printf("done, got 0x%lx \n", (unsigned long)acl);


    printf("Reading member-id file, ");
    err = mifare_desfire_read_data (tag, nfclock_mid_file_id, 0, sizeof(midbytes), midbytes);
    if (err < 0)
    {
        printf("got %d as bytes read", err);
        goto RETRY;
    }
    mid = midbytes[0] | (midbytes[1] << 8);
    printf("done, got %d \n", mid);

*/
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

    null_des_key = mifare_desfire_des_key_new_with_version(key_data_null);
    null_aes_key = mifare_desfire_aes_key_new_with_version(key_data_null16, 0x0);

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
            printf("OK: tag pre-personalized\n");
        }
        else
        {
            printf("ERROR: problem pre-personalizing\n");
        }

        // And if we had tags then wait half a sec before resuming polling again
        usleep(2500 * 1000);
    }

    free(null_des_key);
    free(null_aes_key);
    nfc_close (device);
    nfc_exit(nfc_ctx);
    exit(EXIT_SUCCESS);
}
