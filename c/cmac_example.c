/*
 * OpenSSL AES-128 CMAC example
 *
 * the example data is taken from:
 *
 * NIST, Recommendation for Block Cipher Modes of Operation: The CMAC
 * Mode for Authentication, Special Publication 800-38B
 *
 * http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf
 */

#include <stdio.h>
#include <openssl/aes.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>

static CMAC_CTX *ctx;

static const unsigned char key[AES_BLOCK_SIZE] =
  "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";

static const unsigned char data[64] =
  "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
  "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
  "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"
  "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10";

int main(void)
{
  int ret;

  ctx = CMAC_CTX_new();

  ret = CMAC_Init(ctx, key, sizeof(key), EVP_aes_128_cbc(), NULL);

  printf("CMAC_Init = %d\n", ret);

  ret = CMAC_Update(ctx, data, sizeof(data));

  printf("CMAC_Update = %d\n", ret);

  size_t size;
  unsigned char tag[AES_BLOCK_SIZE];
  ret = CMAC_Final(ctx, tag, &size);

  printf("CMAC_Final = %d, size = %u\n", ret, size);

  CMAC_CTX_free(ctx);

  printf("expected: 51f0bebf 7e3b9d92 fc497417 79363cfe\n"
         "got:      ");
  size_t index;
  for (index = 0; index < sizeof(tag) - 1; ++index) {
    printf("%02x", tag[index]);
    if ((index + 1) % 4 == 0) {
      printf(" ");
    }
  }
  printf("%02x\n", tag[sizeof(tag) - 1]);

  return 0;
}
