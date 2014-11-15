/**
 * AES-128 CMAC based key diversification
 */
#include "keydiversification.h"

// For debugging
#include <stdio.h>

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
int nfclock_diversify_key_aes128(uint8_t base_key[AES_BLOCK_SIZE], uint8_t aid[3], uint8_t *uid, uint8_t *sysid, uint8_t new_key[AES_BLOCK_SIZE])
{
    CMAC_CTX *ctx;
    int ret;
    ctx = CMAC_CTX_new();
    ret = CMAC_Init(ctx, base_key, sizeof(base_key), EVP_aes_128_cbc(), NULL);
    // TODO: Check the meaning of the return values
    if (ret != 1)
    {
        return ret;
    }
    
    printf("DEBUG: in nfclock_diversify_key_aes128:\n");
    printf("  sizeof(base_key)=%d\n", sizeof(base_key));
    printf("  sizeof(aid)=%d\n", sizeof(aid));
    printf("  sizeof(uid)=%d\n", sizeof(uid));
    printf("  sizeof(sysid)=%d\n", sizeof(sysid));
    printf("  sizeof(new_key)=%d\n", sizeof(new_key));
    

    // Create the message
    uint8_t *data = malloc(1 + sizeof(uid) + sizeof(aid) + sizeof(sysid));
    data[0] = 0x01;
    memcpy(&data[1], uid, sizeof(uid));
    memcpy(&data[1+sizeof(uid)], aid, sizeof(aid));
    memcpy(&data[1+sizeof(uid)+sizeof(sysid)], sysid, sizeof(sysid));

    ret = CMAC_Update(ctx, data, sizeof(data));
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
