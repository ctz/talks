#include <stdio.h>

#include "fastpbkdf2/fastpbkdf2.h"

int main(void)
{
  uint8_t out[20];
  int iterations = 1 << 22;
  fastpbkdf2_hmac_sha1((const void *) "password", 8,
                       (const void *) "saltsalt", 8,
                       iterations,
                       out, sizeof out);

  printf("SHA1,%d,", iterations);
  for (int i = 0; i < sizeof out; i++)
    printf("%02x", out[i]);
  printf("\n");

  return 0;
}
