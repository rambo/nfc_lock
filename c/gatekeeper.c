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

#include "log.h"
#include "keydiversification.h"
#include "smart_node_helpers.h"
/**
 * Loaded by smart_node_helpers
#include "smart_node_config.h"
 */
#include "helpers.h"

#define ZMQ_NUM_IOTHREADS 5
// TODO: Configure these in a saner location
#define ZMQ_DB_ORACLE_ADDRESS "tcp://localhost:7070"
#define ZMQ_ANNOUNCER_ADDRESS "tcp://127.0.0.1:7071"
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

// Puts a string to a message, returns message pointer you must close (or null on failure)
int str_to_msg(char* send, zmq_msg_t* msg)
{
    int err;
    int len = strlen(send);
    err = zmq_msg_init_size(msg, len);
    if (err != 0)
    {
        log_error("zmq_msg_init_size failed with %s", zmq_strerror(zmq_errno()));
        return err;
    }
    memcpy(zmq_msg_data(msg), send, len);
    return 0;
}

int zmq_publish_result(void* publisher, char* uid, char* result)
{
    int err, bytes_sent;
    zmq_msg_t msgpart;
    // use the result as topic
    err = str_to_msg(result, &msgpart);
    if (err != 0)
    {
        zmq_msg_close(&msgpart);
        return err;
    }
    bytes_sent = zmq_msg_send(&msgpart, publisher, ZMQ_SNDMORE);
    zmq_msg_close(&msgpart);
    if (bytes_sent < 0)
    {
        log_error("zmq_msg_send1 failed with %s", zmq_strerror(zmq_errno()));
        return err;
    }

    // And UID as the message
    err = str_to_msg(uid, &msgpart);
    if (err != 0)
    {
        zmq_msg_close(&msgpart);
        return err;
    }
    bytes_sent = zmq_msg_send(&msgpart, publisher, 0);
    zmq_msg_close(&msgpart);
    if (bytes_sent < 0)
    {
        log_error("zmq_msg_send2 failed with %s", zmq_strerror(zmq_errno()));
        return err;
    }

    return 0;
}


/**
 * Checks the given uid against the db oracle
 *
 * return -1 on general error, 0 if tag is ok, -2 for unknown -3 for revoked
 */
int uid_valid(char* uid, uint32_t *acl)
{
  int err, bytes_sent;
    int card_ret = -1;
    void *zmq_context_uidvalid = zmq_init(ZMQ_NUM_IOTHREADS);
    void *requester = zmq_socket(zmq_context_uidvalid, ZMQ_REQ);
    err = zmq_connect(requester, ZMQ_DB_ORACLE_ADDRESS);
    if (err != 0)
    {
        log_error("zmq_connect failed with %s", zmq_strerror(zmq_errno()));
        goto END;
    }

    zmq_msg_t request;
    err = str_to_msg(uid, &request);
    if (err != 0)
    {
        zmq_msg_close(&request);
        goto END;
    }
    bytes_sent = zmq_msg_send( &request,requester,0);
    if (bytes_sent < 0)
    {
        log_error("zmq_msg_send3 failed with %s", zmq_strerror(zmq_errno()));
        goto END;
    }
    zmq_msg_close(&request);

    int partno = 0;
    while (1)
    {
        partno++;
        zmq_msg_t message;
        err = zmq_msg_init(&message);
        if (err < 0)
        {
            log_error("zmq_msg_init failed with %s", zmq_strerror(zmq_errno()));
            goto END;
        }
        err = zmq_msg_recv(&message, requester, 0);
	
        if (err < 0)
        {
            zmq_msg_close (&message);
            log_error("zmq_msg_recv failed with %s", zmq_strerror(zmq_errno()));
            goto END;
        }

        // Read the body as string
        char* body = msg_to_str(&message);

        switch(partno)
        {
            case 1:
                if (strcmp(body, "OK") == 0)
                {
                    card_ret = 0;
                    break;
                }
                if (strcmp(body, "NF") == 0)
                {
                    card_ret = -2;
                    break;
                }
                if (strcmp(body, "REV") == 0)
                {
                    card_ret = -3;
                    break;
                }
                log_error("Don't know what part %d body '%s' means", partno, body);
                break;
            case 2:
                switch(card_ret)
                {
                    case 0:
                        // Parse the ACL (hex-encoded) number
                        *acl = strtoul(body, NULL, 0);
                        break;
                    case -2:
                        // fall-through
                    case -3:
                        *acl = 0x0;
                        break;
                }
                break;
            default:
                log_error("Received message part %d, don't know what to do with it", partno);
                break;
        }

        // Done with message
        free(body);
        zmq_msg_close (&message);
        
        // See if we have more parts
        int64_t more;
        size_t more_size = sizeof(more);
        err = zmq_getsockopt(requester, ZMQ_RCVMORE, &more, &more_size);
        if (err != 0)
        {
            log_error("zmq_getsockopt failed with %s", zmq_strerror(zmq_errno()));
            goto END;
        }
        if (!more)
        {
            break;
        }
    }
    err = card_ret;
END:
    zmq_close(requester);
    zmq_term(zmq_context_uidvalid);
    return err;
}

int handle_tag(MifareTag tag, bool *tag_valid, void* publisher)
{
    const uint8_t errlimit = 3;
    int err = 0;
    uint8_t errcnt = 0;
    bool connected = false;
    MifareDESFireAID aid;
    MifareDESFireKey key;
    char *realuid_str = NULL;
    uint8_t diversified_key_data[16];
    uint32_t acl = 0;
    uint32_t db_acl= 0;
    size_t read = 0;
    uint8_t uint32bytes[4];

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
        if (errcnt > errlimit)
        {
            log_error("Operation failed (%s), retry-limit exceeded (%d/%d), skipping tag", freefare_strerror(tag), errcnt, errlimit);
            goto FAIL;
        }
        log_error("Operation failed (%s), retrying (%d)", freefare_strerror(tag), errcnt);
    }
    if (connected)
    {
        mifare_desfire_disconnect(tag);
        connected = false;
    }

    log_debug("Connecting ... ");
    err = mifare_desfire_connect(tag);
    if (err < 0)
    {
        goto RETRY;
    }
    log_debug("Connected");
    connected = true;

    log_debug("Selecting application ... ");
    aid = mifare_desfire_aid_new(nfclock_aid[0] | (nfclock_aid[1] << 8) | (nfclock_aid[2] << 16));
    err = mifare_desfire_select_application(tag, aid);
    if (err < 0)
    {
        free(aid);
        aid = NULL;
        goto RETRY;
    }
    log_debug("Application selected");
    free(aid);
    aid = NULL;

    log_debug("Authenticating ... ");
    key = mifare_desfire_aes_key_new_with_version((uint8_t*)&nfclock_uid_key, 0x0);
    err = mifare_desfire_authenticate(tag, nfclock_uid_keyid, key);
    if (err < 0)
    {
        free(key);
        key = NULL;
        goto RETRY;
    }
    free(key);
    key = NULL;
    log_debug("Authenticated");

    log_debug("Getting real UID ... ");
    err = mifare_desfire_get_card_uid(tag, &realuid_str);
    if (err < 0)
    {
        goto RETRY;
    }
    log_info("Got real UID %s", realuid_str);

    err = nfclock_diversify_key_aes128((uint8_t *)nfclock_acl_read_key_base, (uint8_t*)nfclock_aid, realuid_str, (uint8_t*)nfclock_sysid, sizeof(nfclock_sysid), diversified_key_data);
    if (err != 0)
    {
        log_error("Can't calculate diversified key, failing");
        goto FAIL;
    }

    err = uid_valid(realuid_str, &db_acl);
    if (err != 0)
    {
        switch (err)
        {
            // TODO: configure these magic numbers as constants or enum
            case -3:
                // Revoked!
                log_warning("REVOKED card %s", realuid_str);
                zmq_publish_result(publisher, realuid_str, "REVOKED");
                // Overwrite the card ACL to 0x0
                nfclock_overwrite_acl(tag, realuid_str, 0x0);
                goto FAIL;
                break;
            case -2:
                // Unknown card
                // PONDER: Should we overwrite the ACL here too ? probably...
                log_warning("Unknown card %s", realuid_str);
                zmq_publish_result(publisher, realuid_str, "UNKNOWN");
                // Overwrite the card ACL to 0x0
                nfclock_overwrite_acl(tag, realuid_str, 0x0);
                goto FAIL;
                break;
            default:
                // Unknown error case
                log_error("Don't know what error from uid_valid %d means", err);
                goto FAIL;
        }
    }
    //log_debug("db_acl=0x%lx \n", (unsigned long)db_acl);

    log_debug("Re-auth with ACL read key ...");
    key = mifare_desfire_aes_key_new_with_version((uint8_t*)diversified_key_data, 0x0);
    err = mifare_desfire_authenticate(tag, nfclock_acl_read_keyid, key);
    if (err < 0)
    {
        free(key);
        key = NULL;
        goto RETRY;
    }
    free(key);
    key = NULL;
    log_debug("Re-auth with ACL read key done");

    log_debug("Reading ACL file ... ");
    /** 
     * This triggers stack-smashing detector for some reason...
    err = nfclock_read_uint32(tag, nfclock_acl_file_id, &acl);
    if (err < 0)
    {
        goto RETRY;
    }
     */
    read = mifare_desfire_read_data(tag, nfclock_acl_file_id, 0, 4, uint32bytes);
    if (read < 4)
    {
        goto RETRY;
    }
    acl = (uint32bytes[0] | (uint32bytes[1] << 8) | (uint32bytes[2] << 16) | (uint32bytes[3] << 24));
    log_info("Read ACL file, got 0x%lx", (unsigned long)acl);

    if (acl != db_acl)
    {
        log_info("db_acl=0x%lx (overwriting to card)", (unsigned long)db_acl);
        nfclock_overwrite_acl(tag, realuid_str, db_acl);
    }
    
    if (db_acl & REQUIRE_ACL)
    {
        *tag_valid = true;
        err = 0;
        zmq_publish_result(publisher, realuid_str, "OK");
    }
    else
    {
        // Valid card but ACL not granted
        zmq_publish_result(publisher, realuid_str, "REFUSED");
        err = -4;
    }
    // All checks done seems good
    if (realuid_str)
    {
        free(realuid_str);
        realuid_str = NULL;
    }
    mifare_desfire_disconnect(tag);
    return err;
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
   void* zmq_socket;
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
    my_data->err = handle_tag(my_data->tag, &my_data->tag_valid, my_data->zmq_socket);

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
        // TODO: switch log and return
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
            // TODO: switch log and return
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
            // TODO: switch log and return
            errx (EXIT_FAILURE, "No NFC device found.");
        }
        for (size_t d = 0; d < device_count; ++d)
        {
            device = nfc_open (nfc_ctx, devices[d]);
            if (!device)
            {
                //free(devices[d]);
                log_error("nfc_open() failed for %s", devices[d]);
                error = EXIT_FAILURE;
                continue;
            }
            strncpy(connstring, devices[d], NFC_BUFSIZE_CONNSTRING);
            //free(devices[d]);
            break;
        }
        if (error != EXIT_SUCCESS)
        {
            // TODO: switch log and return
            errx(error, "Could not open any device");
        }
    }
    log_info("Using device %s", connstring);

    s_catch_signals();

    void *zmq_context_main = zmq_init(ZMQ_NUM_IOTHREADS);
    void *publisher = zmq_socket(zmq_context_main, ZMQ_PUB);
    error = zmq_bind(publisher, ZMQ_ANNOUNCER_ADDRESS);
    if (error != 0)
    {
        log_error("zmq_bind failed with %s", zmq_strerror(zmq_errno()));
        zmq_close(publisher);
        zmq_term(zmq_context_main);
        nfc_close (device);
        nfc_exit(nfc_ctx);
        return 1;
    }


    // Mainloop
    MifareTag *tags = NULL;
    while(!s_interrupted)
    {
        tags = freefare_get_tags(device);
        if (   !tags // allocation failed
            // The tag array ends with null element, if first one is null then array is empty
            || !tags[0])
        {
            // TODO: Check for device-level error (and/or check the device is still talking to us!) if we can't talk to the device exit with error!!!
            if (tags)
            {
                // Free the empty array so we don't leak memory
                freefare_free_tags(tags);
                tags = NULL;
            }
            // Limit polling speed to 10Hz
            usleep(100 * 1000);
            //log_debug("Polling ...");
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
                log_debug("Skipping non DESFire tag %s", tag_uid_str);
                free (tag_uid_str);
                continue;
            }

            log_debug("Found DESFire tag %s", tag_uid_str);
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
            tagdata.zmq_socket = publisher;
        
            err = pthread_create(&tid, NULL, handle_tag_pthread, (void *)&tagdata);
            if (err != 0)
            {
                log_error("pthread_create error %d", err);
                continue;
            }
        
            err = pthread_cond_timedwait(&tag_done, &tag_processing, &abs_time);
            if (err == ETIMEDOUT)
            {
                    log_error("Handler thread timed out");
                    pthread_cancel(tid);
                    pthread_join(tid, NULL);
                    pthread_mutex_unlock(&tag_processing);
                    continue;
            }
            pthread_join(tid, NULL);
            pthread_mutex_unlock(&tag_processing);
            if (err)
            {
                log_error("pthread_cond_timedwait error %d", err);
                continue;
            }

            if (tagdata.err != 0)
            {
                // Extra safety, we actually set this value already in the thread
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
            log_info("OK: valid tag found");
        }
        else
        {
            log_info("NO valid tag found");
        }

        // And if we had tags then wait half a sec before resuming polling again
        usleep(500 * 1000);
    }

    zmq_close(publisher);
    zmq_term(zmq_context_main);

    nfc_close (device);
    nfc_exit(nfc_ctx);

    exit(EXIT_SUCCESS);
}
