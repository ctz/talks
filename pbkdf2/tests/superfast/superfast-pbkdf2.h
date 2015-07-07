/*
 * superfast-pbkdf2 - Optimal PBKDF2-HMAC calculation
 * Written in 2015 by Joseph Birr-Pixton <jpixton@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to the
 * public domain worldwide. This software is distributed without any
 * warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include <stdint.h>
#include <assert.h>
#include <string.h>

/* --- Public interface ---
 * You must provide the following definitions, then #include this
 * file. */

/* Name of the function this file defines.  See the definition
 * for the declaration. */
#ifndef PBKDF2_SYMBOL
# error "Define PBKDF2_SYMBOL to name the function"
#endif

/* The hash function's context type. */
#ifndef PBKDF2_HASH_CTX
# error "Define PBKDF2_HMAC_CTX to name the type of a hash function context"
#endif

/* The hash function's block and output size. */
#if !defined(PBKDF2_BLOCKSZ) || !defined(PBKDF2_HASHSZ)
# error "Define PBKDF2_BLOCKSZ as the hash function's input block size, and PBKDF2_HASHSZ as the hash function's output size"
#endif

/* The hash function's init/update/finish function names.
 *
 * These should have the following prototypes:
 * void PBKDF2_HASH_INIT(PBKDF2_HASH_CTX *ctx);
 * void PBKDF2_HASH_UPDATE(PBKDF2_HASH_CTX *ctx, const void *data, size_t ndata);
 * void PBKDF2_HASH_FINAL(uint8_t *out, PBKDF2_HASH_CTX *ctx);
 */
#if !defined(PBKDF2_HASH_INIT) || !defined(PBKDF2_HASH_UPDATE) || !defined(PBKDF2_HASH_FINAL)
# error "Define PBKDF2_HASH_INIT, PBKDF2_HASH_UPDATE and PBKDF2_HASH_FINAL to define hash function"
#endif

/* --- HMAC --- */
#define PBKDF2_HMAC_CTX     PBKDF2_SYMBOL ## _hmac
#define PBKDF2_HMAC_INIT    PBKDF2_SYMBOL ## _hmac_init
#define PBKDF2_HMAC_UPDATE  PBKDF2_SYMBOL ## _hmac_update
#define PBKDF2_HMAC_FINAL   PBKDF2_SYMBOL ## _hmac_final

typedef struct
{
  PBKDF2_HASH_CTX inner;
  PBKDF2_HASH_CTX outer;
} PBKDF2_HMAC_CTX;

static inline void PBKDF2_HMAC_INIT(PBKDF2_HMAC_CTX *ctx,
                                    const uint8_t *key, size_t nkey)
{
  /* Prepare key: */
  uint8_t k[PBKDF2_BLOCKSZ];

  /* Shorten long keys. */
  if (nkey > PBKDF2_BLOCKSZ)
  {
    PBKDF2_HASH_INIT(&ctx->inner);
    PBKDF2_HASH_UPDATE(&ctx->inner, key, nkey);
    PBKDF2_HASH_FINAL(k, &ctx->inner);

    key = k;
    nkey = PBKDF2_HASHSZ;
  }

  /* Standard doesn't cover case where blocksz < hashsz. */
  assert(nkey <= PBKDF2_BLOCKSZ);

  /* Right zero-pad short keys. */
  if (k != key)
    memcpy(k, key, nkey);
  if (PBKDF2_BLOCKSZ > nkey)
    memset(k + nkey, 0, PBKDF2_BLOCKSZ - nkey);

  /* Start inner hash computation */
  uint8_t blk_inner[PBKDF2_BLOCKSZ];
  uint8_t blk_outer[PBKDF2_BLOCKSZ];

  for (size_t i = 0; i < PBKDF2_BLOCKSZ; i++)
  {
    blk_inner[i] = 0x36 ^ k[i];
    blk_outer[i] = 0x5c ^ k[i];
  }

  PBKDF2_HASH_INIT(&ctx->inner);
  PBKDF2_HASH_UPDATE(&ctx->inner, blk_inner, sizeof blk_inner);

  /* And outer. */
  PBKDF2_HASH_INIT(&ctx->outer);
  PBKDF2_HASH_UPDATE(&ctx->outer, blk_outer, sizeof blk_outer);
}

static inline void PBKDF2_HMAC_UPDATE(PBKDF2_HMAC_CTX *ctx,
                                      const void *data, size_t ndata)
{
  PBKDF2_HASH_UPDATE(&ctx->inner, data, ndata);
}

static inline void PBKDF2_HMAC_FINAL(PBKDF2_HMAC_CTX *ctx,
                                     uint8_t out[PBKDF2_HASHSZ])
{
  PBKDF2_HASH_FINAL(out, &ctx->inner);
  PBKDF2_HASH_UPDATE(&ctx->outer, out, PBKDF2_HASHSZ);
  PBKDF2_HASH_FINAL(out, &ctx->outer);
}

/* --- PBKDF2 --- */

static inline void write32_be(uint32_t n, uint8_t out[4])
{
  out[0] = (n >> 24) & 0xff;
  out[1] = (n >> 16) & 0xff;
  out[2] = (n >> 8) & 0xff;
  out[3] = n & 0xff;
}

static void F(const PBKDF2_HMAC_CTX *startctx,
              uint32_t counter,
              const uint8_t *salt, size_t nsalt,
              uint32_t iterations,
              uint8_t *out)
{
  uint8_t U[PBKDF2_HASHSZ];
  
  uint8_t countbuf[4];
  write32_be(counter, countbuf);

  /* First iteration:
   *   U_1 = PRF(P, S || INT_32_BE(i))
   */
  PBKDF2_HMAC_CTX ctx = *startctx;
  PBKDF2_HMAC_UPDATE(&ctx, salt, nsalt);
  PBKDF2_HMAC_UPDATE(&ctx, countbuf, sizeof countbuf);
  PBKDF2_HMAC_FINAL(&ctx, U);
  memcpy(out, U, PBKDF2_HASHSZ);

  /* Subsequent iterations:
   *   U_c = PRF(P, U_{c-1})
   */
  for (uint32_t i = 1; i < iterations; i++)
  {
    ctx = *startctx;
    PBKDF2_HMAC_UPDATE(&ctx, U, PBKDF2_HASHSZ);
    PBKDF2_HMAC_FINAL(&ctx, U);
    for (size_t j = 0; j < PBKDF2_HASHSZ; j++)
      out[j] = out[j] ^ U[j];
  }
}

void PBKDF2_SYMBOL(const uint8_t *pw, size_t npw,
                   const uint8_t *salt, size_t nsalt,
                   uint32_t iterations,
                   uint8_t *out, size_t nout)
{
  uint32_t counter = 1;
  uint8_t block[PBKDF2_BLOCKSZ];

  assert(iterations);
  assert(out && nout);

  /* Starting point for inner loop. */
  PBKDF2_HMAC_CTX ctx;
  PBKDF2_HMAC_INIT(&ctx, pw, npw);

  while (nout)
  {
    F(&ctx, counter, salt, nsalt, iterations, block);

#define MIN(a, b) ((a) > (b)) ? (b) : (a)
    size_t taken = MIN(nout, PBKDF2_HASHSZ);
#undef MIN
    memcpy(out, block, taken);
    out += taken;
    nout -= taken;
    counter++;
  }
}

#undef PBKDF2_HMAC_CTX
#undef PBKDF2_HMAC_INIT
#undef PBKDF2_HMAC_UPDATE
#undef PBKDF2_HMAC_FINAL


