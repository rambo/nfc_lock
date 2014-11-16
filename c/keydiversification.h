/**
 * AES-128 CMAC based key diversification
 */
#include <stdint.h>
#include <string.h> // memcpy
#include <stdlib.h> //realloc
#include <openssl/aes.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>

// Size of the AID array (just to avoid magic-numbers)
#define AID_SIZE 3

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
int nfclock_diversify_key_aes128(uint8_t base_key[AES_BLOCK_SIZE], uint8_t aid[AID_SIZE], char *uid_str, uint8_t *sysid, size_t sysid_size, uint8_t new_key[AES_BLOCK_SIZE]);
