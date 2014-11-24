#include <zmq.h>
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

    return 0;
}
