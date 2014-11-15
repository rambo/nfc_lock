/**
 * AES-128 CMAC based key diversification
 */
#include "keydiversification.h"

/**
 * AES128 CMAC based diversification
 *
 * @param base_key pointer to The master key to diversify (as bytearray)
 * @param aid pointer to Application id (as bytearray)
 * @param uid pointer to Card UID (as bytearray, or null-terminated hex string, whatever libfreefare returns)
 * @param sysid pointer to the "System ID" (as bytearray) this can be anything as long as it's constant and not too long
 * @param new_key pointer to the array we will overwrite with new key data
 * @return int 0 for no errors, error code otherwise
 */
int nfclock_diversify_key_aes128(uint8_t base_key[AES_BLOCK_SIZE], uint8_t aid[AID_SIZE], uint8_t *uid, size_t uid_size, uint8_t *sysid, size_t sysid_size, uint8_t new_key[AES_BLOCK_SIZE])
{
    CMAC_CTX *ctx;
    int ret;
    ctx = CMAC_CTX_new();
    ret = CMAC_Init(ctx, base_key, AES_BLOCK_SIZE, EVP_aes_128_cbc(), NULL);
    // TODO: Check the meaning of the return values
    if (ret != 1)
    {
        return ret;
    }

    // Create the message size is 1 for marker byte, 3 for aid, then the sizes for UID and sysid
    uint16_t data_size = 1 + 3 + uid_size + sysid_size;
    uint8_t *data = malloc(data_size);
    data[0] = 0x01;
    memcpy(&data[1], uid, uid_size);
    memcpy(&data[1+uid_size], aid, AID_SIZE);
    memcpy(&data[1+uid_size+AID_SIZE], sysid, sysid_size);

    ret = CMAC_Update(ctx, data, data_size);
    // TODO: Check the meaning of the return values
    if (ret != 1)
    {
        free(data);
        return ret;
    }
    
    size_t size;
    ret = CMAC_Final(ctx, new_key, &size);
    if (ret != 1)
    {
        free(data);
        return ret;
    }
    (void)size;
    CMAC_CTX_free(ctx);
    free(data);
    return 0;
}
