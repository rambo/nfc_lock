/**
 * Test the key diversification algo with NXP Application Note AN10922 example data
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "keydiversification.h"

bool keys_equal(uint8_t *key_A, size_t size_A, uint8_t *key_B, size_t size_B)
{
    if (size_A != size_B)
    {
        return false;
    }
    for (size_t i=0; i < size_A; ++i)
    {
        if (key_A[i] != key_B[i])
        {
            return false;
        }
    }
    return true;
}

void pretty_print_key(uint8_t *tag, size_t size)
{
    size_t index;
    for (index = 0; index < size - 1; ++index)
    {
        printf("%02x", tag[index]);
        if ((index + 1) % 4 == 0)
        {
            printf(" ");
        }
    }
    printf("%02x\n", tag[size - 1]);
}

int main(int argc, char *argv[])
{
    // These could be constants too but emulate normal usage...
    uint8_t new_key[16]; // Don't bother including libcrypto just for the key size constant
    uint8_t expect_key[16] = { 0xA8, 0xDD, 0x63, 0xA3, 0xB8, 0x9D, 0x54, 0xB3, 0x7C, 0xA8, 0x02, 0x47, 0x3F, 0xDA, 0x91, 0x75 };
    uint8_t base_key[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    uint8_t aid[3] = { 0x30, 0x42, 0xF5 };
    uint8_t sysid[] = { 0x4E, 0x58, 0x50, 0x20, 0x41, 0x62, 0x75 };
    char uid[] = "04782E21801D80";

    int ret;
    int test_times = 1;
    if (argc == 2)
    {
        test_times = atoi(argv[1]);
    }

    // Do it a few times to test for memory issues
    for (int i=0; i < test_times; ++i)
    {
        ret = nfclock_diversify_key_aes128(base_key, aid, uid, sysid, sizeof(sysid), new_key);
        if (ret != 0)
        {
            printf("nfclock_diversify_key_aes128 returned %d\n", ret);
            // TODO: print message
            return 1;
        }        
        printf("expected: ");
        pretty_print_key(expect_key, sizeof(expect_key));
        printf("got:      ");
        pretty_print_key(new_key, sizeof(new_key));
        if (!keys_equal(new_key, sizeof(new_key), expect_key, sizeof(expect_key)))
        {
            printf("ERROR: new_key does not match expected key\n");
            return 1;
        }
    }

    return 0;
}