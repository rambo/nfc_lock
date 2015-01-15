#include <stdbool.h>
#include <stdint.h>
#include "log.h"

int main(int argc, char *argv[])
{
    log_error("test %d", 1);
    log_warning("test %d", 2);
    log_info("test %d", 3);
    log_debug("test %d", 4);
    return 0;
}
