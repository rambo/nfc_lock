#include <zmq.h>
#include <zmq_utils.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        printf("Usage:\n  req_test tcp://localhost:7070 card_uid\n");
        return 1;
    }
    int err;

    void *context = zmq_ctx_new();
    void *requester = zmq_socket(context, ZMQ_REQ);
    err = zmq_connect(requester, argv[1]);
    if (err != 0)
    {
        printf("ERROR: zmq_connect failed with %d", errno);
        goto END;
    }

    zmq_msg_t request;
    int uidlen = strlen(argv[2]);
    err = zmq_msg_init_size(&request, uidlen);
    if (err != 0)
    {
        printf("ERROR: zmq_msg_init_size failed with %d", errno);
        goto END;
    }
    memcpy(zmq_msg_data(&request), argv[2], uidlen);
    printf("Sending request");
    zmq_msg_send(&request, requester, 0);
    zmq_msg_close(&request);

    printf("Waiting for response");
    int partno;
    while (1)
    {
        partno++;
        zmq_msg_t message;
        zmq_msg_init(&message);
        zmq_msg_recv(requester, &message, 0);

        printf("Received part %d, %d bytes", partno, message.size);

        zmq_msg_close (&message);
        int more;
        size_t more_size = sizeof(more);
        zmq_getsockopt (requester, ZMQ_RCVMORE, &more, &more_size);
        if (!more)
        {
            break;
        }
    }
    printf("All %d parts received", partno);

    
/*
int main (void)
{
    void *context = zmq_ctx_new ();

    //  Socket to talk to server
    printf ("Connecting to hello world server…\n");
    void *requester = zmq_socket (context, ZMQ_REQ);
    zmq_connect (requester, "tcp://localhost:5555");

    int request_nbr;
    for (request_nbr = 0; request_nbr != 10; request_nbr++) {
        zmq_msg_t request;
        zmq_msg_init_size (&request, 5);
        memcpy (zmq_msg_data (&request), "Hello", 5);
        printf ("Sending Hello %d…\n", request_nbr);
        zmq_msg_send (&request, requester, 0);
        zmq_msg_close (&request);

        zmq_msg_t reply;
        zmq_msg_init (&reply);
        zmq_msg_recv (&reply, requester, 0);
        printf ("Received World %d\n", request_nbr);
        zmq_msg_close (&reply);
    }
    zmq_close (requester);
    zmq_ctx_destroy (context);
    return 0;
}

*/
END:
    zmq_close(requester);
    zmq_ctx_destroy(context);
    return err;
}
