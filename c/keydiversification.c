/**
 * AES-128 CMAC based key diversification
 */
#include "keydiversification.h"

// Declare the hex conversion function (from http://stackoverflow.com/questions/18267803/how-to-correctly-convert-a-hex-string-to-byte-array-in-c)
static int nfclock_hex2data(uint8_t *data, const char *hexstring, size_t len);

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
int nfclock_diversify_key_aes128(uint8_t base_key[AES_BLOCK_SIZE], uint8_t aid[AID_SIZE], char *uid_str, uint8_t *sysid, size_t sysid_size, uint8_t new_key[AES_BLOCK_SIZE])
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
    size_t uid_size = strlen(uid_str)/2;
    uint8_t *uid = malloc(uid_size);
    ret = nfclock_hex2data(uid, uid_str, uid_size);
    if (ret != 0)
    {
        free(uid);
        return ret;
    }

    // Create the message size is 1 for marker byte, then the sizes for uid, aid and sysid
    uint16_t data_size = 1 + uid_size + AID_SIZE + sysid_size;
    uint8_t *data = malloc(data_size);
    data[0] = 0x01;
    memcpy(&data[1], uid, uid_size);
    memcpy(&data[1+uid_size], aid, AID_SIZE);
    memcpy(&data[1+uid_size+AID_SIZE], sysid, sysid_size);
    free(uid);

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

//from http://stackoverflow.com/questions/18267803/how-to-correctly-convert-a-hex-string-to-byte-array-in-c
//convert hexstring to len bytes of data
//returns 0 on success, -1 on error
//data is a buffer of at least len bytes
//hexstring is upper or lower case hexadecimal, NOT prepended with "0x"
static int nfclock_hex2data(uint8_t *data, const char *hexstring, size_t len)
{
    const char *pos = hexstring;
    char *endptr;
    size_t count = 0;

    if ((hexstring[0] == '\0') || (strlen(hexstring) % 2)) {
        //hexstring contains no data
        //or hexstring has an odd length
        return -1;
    }

    for(count = 0; count < len; count++) {
        char buf[5] = {'0', 'x', pos[0], pos[1], 0};
        data[count] = strtol(buf, &endptr, 0);
        pos += 2 * sizeof(char);

        if (endptr[0] != '\0') {
            //non-hexadecimal character encountered
            return -1;
        }
    }

    return 0;
}