#include <openssl/evp.h>

int main(void)
{
  unsigned char out[20];
  int iterations = 1 << 22;
  PKCS5_PBKDF2_HMAC_SHA1("password", 8,
                         (const unsigned char *) "saltsalt", 8,
                         iterations,
                         (int) sizeof(out), out);
  printf("SHA1,%d,", iterations);
  for (int i = 0; i < sizeof out; i++)
    printf("%02x", out[i]);
  printf("\n");
  return 0;
}
