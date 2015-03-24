#include "smart_node_helpers.h"
#include "log.h"

int nfclock_overwrite_acl(MifareTag tag, char *realuid_str, uint32_t newacl)
{
    uint8_t diversified_key_data[16];
    MifareDESFireKey key;
    int err;

    err = nfclock_diversify_key_aes128((uint8_t *)nfclock_acl_write_key_base, (uint8_t*)nfclock_aid, realuid_str, (uint8_t*)nfclock_sysid, sizeof(nfclock_sysid), diversified_key_data);
    if (err != 0)
    {
        log_error("Can't calculate diversified ACL write key, failing");
        return err;
    }

    log_debug("Re-Authenticating (ACL write key) ... ");
    key = mifare_desfire_aes_key_new_with_version((uint8_t*)&diversified_key_data, 0x0);
    err = mifare_desfire_authenticate(tag, nfclock_acl_write_keyid, key);
    if (err < 0)
    {
        log_error("Re-Authenticating (ACL write key) failed, err %d (%s)", err, freefare_strerror(tag));
        free(key);
        key = NULL;
        return err;
    }
    free(key);
    key = NULL;
    log_debug("Re-Auth done");

    log_info("Writing ACL value (0x%lx) ... ", (unsigned long)newacl);
    err = nfclock_write_uint32(tag, nfclock_acl_file_id, newacl);
    if (err < 0)
    {
        log_error("Writing ACL value failed, err %d (%s)", err, freefare_strerror(tag));
        return err;
    }
    log_info("Writing done");
    return 0;
}

