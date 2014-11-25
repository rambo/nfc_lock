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
#include <zmq.h>

#include "smart_node_config.h"
#include "keydiversification.h"

#define ZMQ_NUM_IOTHREADS 1
#define ZMQ_DB_ORACLE_ADDRESS "tcp://localhost:7070"
// TODO: Configure this in a saner location
#define REQUIRE_ACL 0x1


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

// Reads the message body to a string, returns pointer you must free
char* msg_to_str(zmq_msg_t* msg)
{
    size_t size = zmq_msg_size(msg);
    if (size < 1)
    {
        return NULL;
    }
    char *string = malloc(size + 1);
    memcpy(string, zmq_msg_data(msg), size);
    string[size] = 0x0; // Force last byte to null
    return (string);
}
/**
 * Checks the given uid against the db oracle
 *
 * return -1 on general error, 0 if tag is ok, -2 for unknown -3 for revoked
 */
int uid_valid(char* uid, uint32_t *acl)
{
    int err;
    void *context = zmq_init(ZMQ_NUM_IOTHREADS);
    void *requester = zmq_socket(context, ZMQ_REQ);
    err = zmq_connect(requester, ZMQ_DB_ORACLE_ADDRESS);
    if (err != 0)
    {
        printf("ERROR: zmq_connect failed with %s\n", zmq_strerror(zmq_errno()));
        goto END;
    }

    zmq_msg_t request;
    int uidlen = strlen(uid);
    err = zmq_msg_init_size(&request, uidlen);
    if (err != 0)
    {
        printf("ERROR: zmq_msg_init_size failed with %s\n", zmq_strerror(zmq_errno()));
        goto END;
    }
    memcpy(zmq_msg_data(&request), uid, uidlen);
    err = zmq_send(requester, &request, 0);
    if (err != 0)
    {
        printf("ERROR: zmq_send failed with %s\n", zmq_strerror(zmq_errno()));
        goto END;
    }
    zmq_msg_close(&request);

    int partno = 0;
    while (1)
    {
        partno++;
        zmq_msg_t message;
        zmq_msg_init(&message);
        if (err != 0)
        {
            printf("ERROR: zmq_msg_init failed with %s\n", zmq_strerror(zmq_errno()));
            goto END;
        }
        err = zmq_recv(requester, &message, 0);
        if (err != 0)
        {
            zmq_msg_close (&message);
            printf("ERROR: zmq_recv failed with %s\n", zmq_strerror(zmq_errno()));
            goto END;
        }

        printf("Received part %d, %d bytes\n", partno, (int)zmq_msg_size(&message));

        // Read the body as string
        char* body = msg_to_str(&message);
        printf("==\n%s\n==\n", body);
        free(body);

        // Done with message
        zmq_msg_close (&message);
        
        // See if we have more parts
        int64_t more;
        size_t more_size = sizeof(more);
        err = zmq_getsockopt(requester, ZMQ_RCVMORE, &more, &more_size);
        if (err != 0)
        {
            printf("ERROR: zmq_getsockopt failed with %s\n", zmq_strerror(zmq_errno()));
            goto END;
        }
        if (!more)
        {
            break;
        }
    }
    printf("All %d parts received\n", partno);
    err = 0;
    // FIXME: Parse this from the ZMQ message
    *acl = 0x1;

END:
    zmq_close(requester);
    zmq_term(context);
    return err;
}

int handle_tag(MifareTag tag, bool *tag_valid)
{
    const uint8_t errlimit = 3;
    int err = 0;
    char errstr[] = "";
    uint8_t errcnt = 0;
    bool connected = false;
    MifareDESFireAID aid;
    MifareDESFireKey key;
    char *realuid_str = NULL;
    uint8_t diversified_key_data[16];
    uint8_t aclbytes[4];
    uint32_t acl;
    uint32_t db_acl;

    *tag_valid = false;

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
        printf("failed (%s), retrying (%d)\n", errstr, errcnt);
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

    err = uid_valid(realuid_str, &db_acl);
    if (err != 0)
    {
        switch (err)
        {
            case -3:
                // Revoked!
                // TODO: Overwrite the card ACL to 0x0
                printf("REVOKED card\n");
                goto FAIL;
                break;
            case -2:
                // Unknown card
                // PONDER: Should we overwrite the ACL here too ? probably...
                printf("Unknown card\n");
                goto FAIL;
                break;
            default:
                // Unknown error case
                printf("Don't know what error from uid_valid %d means\n", err);
                goto FAIL;
        }
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
    err = mifare_desfire_read_data (tag, nfclock_acl_file_id, 0, sizeof(aclbytes), aclbytes);
    if (err < 0)
    {
        printf("got %d as bytes read", err);
        goto RETRY;
    }
    acl = aclbytes[0] | (aclbytes[1] << 8) | (aclbytes[2] << 16) | (aclbytes[3] << 24);
    printf("done, got 0x%lx \n", (unsigned long)acl);

    if (acl != db_acl)
    {
        // TODO: Overwrite ACL file on card
    }
    
    if (db_acl & REQUIRE_ACL)
    {
        *tag_valid = true;
    }
    // All checks done seems good
    if (realuid_str)
    {
        free(realuid_str);
        realuid_str = NULL;
    }
    mifare_desfire_disconnect(tag);
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
