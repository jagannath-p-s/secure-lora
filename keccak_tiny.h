#pragma once
/*
 * ============================================================
 *  keccak_tiny.h  —  Minimal Keccak-1600 / SHA-3 / SHAKE
 * ============================================================
 *  Provides the hash primitives required by Kyber-512:
 *    sha3_256  — 32-byte digest
 *    sha3_512  — 64-byte digest
 *    shake128  — variable-length XOF
 *    shake256  — variable-length XOF
 *
 *  Based on the NIST Keccak reference specification.
 *  Written as a single header for Arduino / ESP32 compatibility.
 *  No dynamic allocation; all state on the stack.
 * ============================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// ─── Keccak constants ────────────────────────────────────────

/* 24 iota round constants for Keccak-f[1600] */
static const uint64_t keccak_rc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

#define ROTL64(x, n)  (((x) << (n)) | ((x) >> (64 - (n))))

// ─── Keccak-f[1600] permutation ──────────────────────────────
/*
 * Core 24-round Keccak permutation over a 5×5 matrix of 64-bit lanes.
 * The three steps θ, ρ+π, χ, ι are applied each round.
 * A[x + 5*y] = lane at column x, row y.
 */
static inline void keccak_f1600(uint64_t A[25])
{
    uint64_t C[5], D[5], B[25];
    int r;

    for (r = 0; r < 24; r++) {

        /* ── θ: column parity mixing ── */
        C[0] = A[0] ^ A[5] ^ A[10] ^ A[15] ^ A[20];
        C[1] = A[1] ^ A[6] ^ A[11] ^ A[16] ^ A[21];
        C[2] = A[2] ^ A[7] ^ A[12] ^ A[17] ^ A[22];
        C[3] = A[3] ^ A[8] ^ A[13] ^ A[18] ^ A[23];
        C[4] = A[4] ^ A[9] ^ A[14] ^ A[19] ^ A[24];

        D[0] = C[4] ^ ROTL64(C[1], 1);
        D[1] = C[0] ^ ROTL64(C[2], 1);
        D[2] = C[1] ^ ROTL64(C[3], 1);
        D[3] = C[2] ^ ROTL64(C[4], 1);
        D[4] = C[3] ^ ROTL64(C[0], 1);

        A[0]^=D[0]; A[5]^=D[0]; A[10]^=D[0]; A[15]^=D[0]; A[20]^=D[0];
        A[1]^=D[1]; A[6]^=D[1]; A[11]^=D[1]; A[16]^=D[1]; A[21]^=D[1];
        A[2]^=D[2]; A[7]^=D[2]; A[12]^=D[2]; A[17]^=D[2]; A[22]^=D[2];
        A[3]^=D[3]; A[8]^=D[3]; A[13]^=D[3]; A[18]^=D[3]; A[23]^=D[3];
        A[4]^=D[4]; A[9]^=D[4]; A[14]^=D[4]; A[19]^=D[4]; A[24]^=D[4];

        /* ── ρ + π: rotation and transposition (combined for speed) ──
         * B[π(x,y)] = ROTL64(A[x+5y], ρ(x,y))
         * where π(x,y) = (y, 2x+3y mod 5),  ρ offsets from spec §3.2.2
         */
        B[0]  =          A[0];          /* (0,0) rot   0 */
        B[10] = ROTL64(A[1],   1);      /* (1,0) rot   1 */
        B[20] = ROTL64(A[2],  62);      /* (2,0) rot  62 */
        B[5]  = ROTL64(A[3],  28);      /* (3,0) rot  28 */
        B[15] = ROTL64(A[4],  27);      /* (4,0) rot  27 */
        B[16] = ROTL64(A[5],  36);      /* (0,1) rot  36 */
        B[1]  = ROTL64(A[6],  44);      /* (1,1) rot  44 */
        B[11] = ROTL64(A[7],   6);      /* (2,1) rot   6 */
        B[21] = ROTL64(A[8],  55);      /* (3,1) rot  55 */
        B[6]  = ROTL64(A[9],  20);      /* (4,1) rot  20 */
        B[7]  = ROTL64(A[10],  3);      /* (0,2) rot   3 */
        B[17] = ROTL64(A[11], 10);      /* (1,2) rot  10 */
        B[2]  = ROTL64(A[12], 43);      /* (2,2) rot  43 */
        B[12] = ROTL64(A[13], 25);      /* (3,2) rot  25 */
        B[22] = ROTL64(A[14], 39);      /* (4,2) rot  39 */
        B[23] = ROTL64(A[15], 41);      /* (0,3) rot  41 */
        B[8]  = ROTL64(A[16], 45);      /* (1,3) rot  45 */
        B[18] = ROTL64(A[17], 15);      /* (2,3) rot  15 */
        B[3]  = ROTL64(A[18], 21);      /* (3,3) rot  21 */
        B[13] = ROTL64(A[19],  8);      /* (4,3) rot   8 */
        B[14] = ROTL64(A[20], 18);      /* (0,4) rot  18 */
        B[24] = ROTL64(A[21],  2);      /* (1,4) rot   2 */
        B[9]  = ROTL64(A[22], 61);      /* (2,4) rot  61 */
        B[19] = ROTL64(A[23], 56);      /* (3,4) rot  56 */
        B[4]  = ROTL64(A[24], 14);      /* (4,4) rot  14 */

        /* ── χ: non-linear S-box layer ──
         * A[i] = B[i] ^ (~B[(i+1)%5 in row] & B[(i+2)%5 in row])
         */
        A[0]  = B[0]  ^ ((~B[1])  & B[2]);
        A[1]  = B[1]  ^ ((~B[2])  & B[3]);
        A[2]  = B[2]  ^ ((~B[3])  & B[4]);
        A[3]  = B[3]  ^ ((~B[4])  & B[0]);
        A[4]  = B[4]  ^ ((~B[0])  & B[1]);
        A[5]  = B[5]  ^ ((~B[6])  & B[7]);
        A[6]  = B[6]  ^ ((~B[7])  & B[8]);
        A[7]  = B[7]  ^ ((~B[8])  & B[9]);
        A[8]  = B[8]  ^ ((~B[9])  & B[5]);
        A[9]  = B[9]  ^ ((~B[5])  & B[6]);
        A[10] = B[10] ^ ((~B[11]) & B[12]);
        A[11] = B[11] ^ ((~B[12]) & B[13]);
        A[12] = B[12] ^ ((~B[13]) & B[14]);
        A[13] = B[13] ^ ((~B[14]) & B[10]);
        A[14] = B[14] ^ ((~B[10]) & B[11]);
        A[15] = B[15] ^ ((~B[16]) & B[17]);
        A[16] = B[16] ^ ((~B[17]) & B[18]);
        A[17] = B[17] ^ ((~B[18]) & B[19]);
        A[18] = B[18] ^ ((~B[19]) & B[15]);
        A[19] = B[19] ^ ((~B[15]) & B[16]);
        A[20] = B[20] ^ ((~B[21]) & B[22]);
        A[21] = B[21] ^ ((~B[22]) & B[23]);
        A[22] = B[22] ^ ((~B[23]) & B[24]);
        A[23] = B[23] ^ ((~B[24]) & B[20]);
        A[24] = B[24] ^ ((~B[20]) & B[21]);

        /* ── ι: asymmetric round constant injection ── */
        A[0] ^= keccak_rc[r];
    }
}

// ─── Sponge helper ───────────────────────────────────────────
/*
 * Absorb `inlen` bytes from `in` into the sponge state with
 * rate `rate_bytes`, XOR-ing one lane-word at a time (little-endian).
 * Returns the fill level of the last block (0 means last block was full).
 */
static inline size_t keccak_absorb(uint64_t st[25],
                                   size_t   rate_bytes,
                                   const uint8_t *in, size_t inlen)
{
    size_t i;
    while (inlen >= rate_bytes) {
        /* XOR a full rate-block into the state */
        for (i = 0; i < rate_bytes / 8; i++) {
            uint64_t tmp = 0;
            memcpy(&tmp, in + i * 8, 8);   /* safe unaligned read */
            st[i] ^= tmp;
        }
        keccak_f1600(st);
        in    += rate_bytes;
        inlen -= rate_bytes;
    }
    return inlen;   /* remaining bytes (partial last block) */
}

/*
 * Pad and absorb the final partial block, then apply the padding:
 * SHA-3 uses 0x06 || … || 0x80, SHAKE uses 0x1f || … || 0x80.
 */
static inline void keccak_finalize(uint64_t st[25],
                                   size_t   rate_bytes,
                                   const uint8_t *tail, size_t taillen,
                                   uint8_t  pad_byte)
{
    uint8_t block[200];
    size_t  i;
    memset(block, 0, rate_bytes);
    memcpy(block, tail, taillen);
    block[taillen]          ^= pad_byte;       /* multi-rate padding begin */
    block[rate_bytes - 1]   ^= 0x80;           /* multi-rate padding end   */
    for (i = 0; i < rate_bytes / 8; i++) {
        uint64_t tmp = 0;
        memcpy(&tmp, block + i * 8, 8);
        st[i] ^= tmp;
    }
    keccak_f1600(st);
}

/*
 * Squeeze `outlen` bytes from the sponge state into `out`.
 */
static inline void keccak_squeeze(uint8_t *out, size_t outlen,
                                  uint64_t st[25], size_t rate_bytes)
{
    size_t i;
    while (outlen > 0) {
        size_t take = (outlen < rate_bytes) ? outlen : rate_bytes;
        for (i = 0; i < rate_bytes / 8 && i * 8 < take; i++) {
            size_t copy = ((i + 1) * 8 <= take) ? 8 : (take - i * 8);
            memcpy(out + i * 8, &st[i], copy);
        }
        out    += take;
        outlen -= take;
        if (outlen > 0) keccak_f1600(st);
    }
}

// ─── Public API ──────────────────────────────────────────────

/* SHA3-256: 256-bit (32-byte) hash.  rate = 136 bytes. */
static inline void sha3_256(uint8_t out[32],
                             const uint8_t *in, size_t inlen)
{
    uint64_t st[25] = {0};
    size_t rem = keccak_absorb(st, 136, in, inlen);
    keccak_finalize(st, 136, in + inlen - rem, rem, 0x06);
    keccak_squeeze(out, 32, st, 136);
}

/* SHA3-512: 512-bit (64-byte) hash.  rate = 72 bytes. */
static inline void sha3_512(uint8_t out[64],
                             const uint8_t *in, size_t inlen)
{
    uint64_t st[25] = {0};
    size_t rem = keccak_absorb(st, 72, in, inlen);
    keccak_finalize(st, 72, in + inlen - rem, rem, 0x06);
    keccak_squeeze(out, 64, st, 72);
}

/* SHAKE-128: variable-length XOF.  rate = 168 bytes. */
static inline void shake128(uint8_t *out, size_t outlen,
                             const uint8_t *in, size_t inlen)
{
    uint64_t st[25] = {0};
    size_t rem = keccak_absorb(st, 168, in, inlen);
    keccak_finalize(st, 168, in + inlen - rem, rem, 0x1f);
    keccak_squeeze(out, outlen, st, 168);
}

/* SHAKE-256: variable-length XOF.  rate = 136 bytes. */
static inline void shake256(uint8_t *out, size_t outlen,
                             const uint8_t *in, size_t inlen)
{
    uint64_t st[25] = {0};
    size_t rem = keccak_absorb(st, 136, in, inlen);
    keccak_finalize(st, 136, in + inlen - rem, rem, 0x1f);
    keccak_squeeze(out, outlen, st, 136);
}

/*
 * SHAKE-128 incremental absorb/squeeze context.
 * Used by Kyber's matrix expansion (GenerateMatrix) which feeds the
 * seed + two index bytes and then squeezes many coefficient-pairs.
 */
typedef struct {
    uint64_t st[25];
    uint8_t  buf[168];      /* partial block buffer */
    size_t   buf_fill;      /* bytes in buf[] so far */
} shake128_ctx;

static inline void shake128_init(shake128_ctx *ctx)
{
    memset(ctx->st, 0, sizeof(ctx->st));
    ctx->buf_fill = 0;
}

static inline void shake128_absorb(shake128_ctx *ctx,
                                   const uint8_t *in, size_t inlen)
{
    /* First drain anything already buffered */
    while (inlen > 0 && ctx->buf_fill < 168) {
        ctx->buf[ctx->buf_fill++] = *in++;
        inlen--;
    }
    if (ctx->buf_fill == 168) {
        size_t i;
        for (i = 0; i < 168 / 8; i++) {
            uint64_t tmp = 0;
            memcpy(&tmp, ctx->buf + i * 8, 8);
            ctx->st[i] ^= tmp;
        }
        keccak_f1600(ctx->st);
        ctx->buf_fill = 0;
    }
    /* Full blocks directly */
    size_t rem = keccak_absorb(ctx->st, 168, in, inlen);
    memcpy(ctx->buf, in + inlen - rem, rem);
    ctx->buf_fill = rem;
}

static inline void shake128_finalize(shake128_ctx *ctx)
{
    keccak_finalize(ctx->st, 168, ctx->buf, ctx->buf_fill, 0x1f);
    ctx->buf_fill = 0;
}

static inline void shake128_squeeze(shake128_ctx *ctx,
                                    uint8_t *out, size_t outlen)
{
    keccak_squeeze(out, outlen, ctx->st, 168);
}
