#include <stdio.h>

#include <openssl/sha.h>

#define PBKDF2_SYMBOL       fastpbkdf2_sha1
#define PBKDF2_BLOCKSZ      SHA_CBLOCK
#define PBKDF2_HASHSZ       SHA_DIGEST_LENGTH
#define PBKDF2_HASH_CTX     SHA_CTX
#define PBKDF2_HASH_INIT    SHA1_Init
#define PBKDF2_HASH_UPDATE  SHA1_Update
#define PBKDF2_HASH_FINAL   SHA1_Final
#include "superfast-pbkdf2.h"

int main(void)
{
  uint8_t out[20];
  int iterations = 1 << 22;
  fastpbkdf2_sha1((const void *) "password", 8,
                  (const void *) "saltsalt", 8,
                  iterations,
                  out, sizeof out);

  printf("SHA1,%d,", iterations);
  for (int i = 0; i < sizeof out; i++)
    printf("%02x", out[i]);
  printf("\n");

  return 0;
}
