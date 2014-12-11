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

uint16_t nfclock_fileaccessrights(uint8_t readkey, uint8_t writekey, uint8_t rwkey, uint8_t aclkey)
{
    return MDAR(readkey, writekey, rwkey, aclkey);
}

int nfclock_write_uint32(MifareTag tag, uint8_t fileid, uint32_t data)
{
    uint8_t databytes[4];
    size_t wrote;

    databytes[0] = (data & 0x000000ff);
    databytes[1] = (data & 0x0000ff00) >> 8;
    databytes[2] = (data & 0x00ff0000) >> 16;
    databytes[3] = (data & 0xff000000) >> 24;
    wrote = mifare_desfire_write_data(tag, fileid, 0, 4, databytes);
    if (wrote < 4)
    {
        // TODO: how to raise a sane error
        return -1;
    }
    return 0;
}

int nfclock_read_uint32(MifareTag tag, uint8_t fileid, uint32_t *data)
{
    uint8_t databytes[4];
    size_t read;
    uint32_t tmpdata;

    read = mifare_desfire_read_data(tag, fileid, 0, 4, databytes);
    if (read < 4)
    {
        // TODO: how to raise a sane error
        return -1;
    }
    tmpdata = (databytes[0] | (databytes[1] << 8) | (databytes[2] << 16) | (databytes[3] << 24));
    printf("nfclock_read_uint32: got 0x%lx \n", (unsigned long)tmpdata);
    // This triggers *** stack smashing detected ***
    memcpy(data, &tmpdata, sizeof(tmpdata));
    /**
     * Same with this
    *data = tmpdata;
     */
    /**
     * And this
    *data = (databytes[0] | (databytes[1] << 8) | (databytes[2] << 16) | (databytes[3] << 24));
     */
    return 0;
}


