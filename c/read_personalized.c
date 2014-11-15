#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <err.h>
#include <errno.h>

#include <string.h> // memcpy
#include <stdlib.h> //realloc

#include <nfc/nfc.h>
#include <freefare.h>

#include "smart_node_config.h"
#include "keydiversification.h"



int main(int argc, char *argv[])
{
    // Connect to first by default, or to the connstring specified on CLI
    nfc_connstring connstring;
    if (argc == 2)
    {
        strncpy(connstring, argv[1], NFC_BUFSIZE_CONNSTRING);
    }

    nfc_context *nfc_ctx;
    nfc_init (&nfc_ctx);
    if (nfc_ctx == NULL)
    {
        errx(EXIT_FAILURE, "Unable to init libnfc (propbably malloc)");
    }

    nfc_device *device = NULL;
    device = nfc_open (nfc_ctx, connstring);
    if (!device)
    {
        errx(EXIT_FAILURE, "Unable to open device");
    }

    
    nfc_exit(nfc_ctx);
    exit(EXIT_SUCCESS);
}
