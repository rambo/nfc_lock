#ifndef NFCLOCK_SMART_NODE_HELPERS_H
#define NFCLOCK_SMART_NODE_HELPERS_H

#include <stdbool.h>
#include <stdint.h>
#include <freefare.h>
#include <stdlib.h> //realloc

#include "keydiversification.h"
#include "smart_node_config.h"
#include "helpers.h"


int nfclock_overwrite_acl(MifareTag tag, char *realuid_str, uint32_t newacl);


#endif