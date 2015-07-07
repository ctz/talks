#include <stdio.h>

#include "pbkdf2.h"
#include "sha1.h"

int main(void)
{
  uint8_t out[20];
  int iterations = 1 << 22;
  cf_pbkdf2_hmac((const void *) "password", 8,
                 (const void *) "saltsalt", 8,
                 iterations,
                 out, sizeof out,
                 &cf_sha1);

  printf("SHA1,%d,", iterations);
  for (int i = 0; i < sizeof out; i++)
    printf("%02x", out[i]);
  printf("\n");

  return 0;
}
