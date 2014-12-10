#include "helpers.h"

uint8_t nfclock_applicationsettings(uint8_t accesskey, bool frozen, bool req_auth_fileops, bool req_auth_dir, bool allow_master_key_chg)
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
