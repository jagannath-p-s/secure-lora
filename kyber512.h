#pragma once
/*
 * ============================================================
 *  kyber512.h  —  CRYSTALS-Kyber-512 KEM
 * ============================================================
 *  Post-quantum Key Encapsulation Mechanism (KEM) standardised
 *  as ML-KEM-512 in NIST FIPS 203 (2024).
 *
 *  Security level: Category 1 (≥ AES-128 classical, IND-CCA2)
 *  Quantum security: resistant to Shor's algorithm (no DH/RSA)
 *
 *  API
 *  ───
 *  kyber512_keypair(pk, sk)      — Alice generates her key pair
 *  kyber512_enc(ct, ss, pk)      — Bob encapsulates shared secret
 *  kyber512_dec(ss, ct, sk)      — Alice decapsulates shared secret
 *
 *  Sizes (bytes):
 *    KYBER512_PUBLICKEYBYTES  = 800
 *    KYBER512_SECRETKEYBYTES  = 1632
 *    KYBER512_CIPHERTEXTBYTES = 768
 *    KYBER512_SSBYTES         = 32
 *
 *  Implementation based on PQClean reference (public domain).
 *  Adapted for Arduino / ESP32 (C99, no dynamic allocation).
 *  Requires: keccak_tiny.h (for SHA3-256, SHA3-512, SHAKE128)
 * ============================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "keccak_tiny.h"
#include "esp_system.h"    /* esp_fill_random() */

// ─── Kyber-512 parameters ─────────────────────────────────────────────────
#define KYBER_K          2       /* module rank (2 = Kyber-512) */
#define KYBER_N        256       /* polynomial degree */
#define KYBER_Q       3329       /* modulus  q = 3329 */
#define KYBER_ETA1       3       /* CBD noise parameter for key gen */
#define KYBER_ETA2       2       /* CBD noise parameter for encryption */
#define KYBER_DU        10       /* compression bits for u vector */
#define KYBER_DV         4       /* compression bits for v poly */

/* Derived size constants */
#define KYBER_POLYBYTES        384   /* 256 coefficients × 12 bits / 8 */
#define KYBER_POLYVECBYTES     (KYBER_K * KYBER_POLYBYTES)   /* 768 */
#define KYBER_POLYCOMPRESSEDBYTES  128   /* DV=4 → 256×4/8 */
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * (KYBER_DU*KYBER_N/8)) /* 640 */
#define KYBER_SYMBYTES         32    /* size of hash outputs / seeds */
#define KYBER_SSBYTES          32    /* shared secret size */

/* Public sizes exposed to callers */
#define KYBER512_PUBLICKEYBYTES   (KYBER_POLYVECBYTES + KYBER_SYMBYTES) /* 800 */
#define KYBER512_SECRETKEYBYTES   (KYBER_POLYVECBYTES + KYBER512_PUBLICKEYBYTES + 2*KYBER_SYMBYTES) /* 1632 */
#define KYBER512_CIPHERTEXTBYTES  (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES) /* 768 */
#define KYBER512_SSBYTES          KYBER_SSBYTES /* 32 */

// ─── Polynomial type ──────────────────────────────────────────────────────
/*
 * A polynomial in Z_q[X]/(X^256+1).
 * Coefficients are signed 16-bit; they may be in different "forms"
 * (standard, Montgomery, or Barrett-reduced) depending on context.
 */
typedef struct { int16_t coeffs[KYBER_N]; } poly;

/* A vector of k=2 polynomials (the Kyber module lattice element) */
typedef struct { poly vec[KYBER_K]; } polyvec;

// ─── Reduction helpers ───────────────────────────────────────────────────

/*
 * Montgomery reduction: for a in [-q·2^15, q·2^15), return
 * r ≡ a·R^{-1} (mod q) with |r| ≤ q/2.  R = 2^16.
 * Uses the Montgomery trick: multiply by R^{-1} mod q = 169.
 */
static inline int16_t montgomery_reduce(int32_t a)
{
    /* q_inv = -q^{-1} mod 2^16 = 62209, i.e. q*q_inv ≡ -1 (mod 2^16) */
    int16_t t = (int16_t)((int16_t)a * (int16_t)62209);
    return (int16_t)((a - (int32_t)t * KYBER_Q) >> 16);
}

/*
 * Barrett reduction: for a in [-3·q/2, 3·q/2), return r ≡ a (mod q)
 * with |r| ≤ q/2.
 */
static inline int16_t barrett_reduce(int16_t a)
{
    /* v = round(2^26 / q) = 20159 */
    int16_t t = (int16_t)(((int32_t)20159 * a + (1<<25)) >> 26);
    return a - t * (int16_t)KYBER_Q;
}

/* Conditional subtract q: bring a in [0, 2q) down to [0, q). */
static inline int16_t csubq(int16_t a)
{
    a -= KYBER_Q;
    a += (a >> 15) & KYBER_Q;   /* if a<0 then add q back */
    return a;
}

// ─── NTT zeta table ──────────────────────────────────────────────────────
/*
 * Precomputed Montgomery-form powers of the primitive 256th root of unity
 * ζ=17 in Z_q.  zetas[i] = ζ^(br7(i)) · R (mod q) where br7 is
 * 7-bit bit-reversal.  Used for the forward NTT butterfly.
 */
static const int16_t kyber_zetas[128] = {
  -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
   -171,   622,  1577,   182,   962, -1202, -1474,  1468,
    573, -1325,   264,   383,  -829,  1458, -1602,  -130,
   -681,  1017,   732,   608, -1542,   411,  -205, -1571,
   1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
    516,    -8,  -320,  -666, -1618,  -162,   126,  1469,
   -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
   -398,   961, -1508,  -725,   448, -1065,   677, -1275,
  -1103,   430,   555,   843, -1251,   871,  1550,   105,
    422,   587,   177,  -235,  -291,  -460,  1574,  1653,
   -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
  -1590,   644,  -872,   349,   418,   329,  -156,   -75,
    817,  1097,   603,   610,  1322, -1285, -1465,   384,
  -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
  -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
   -108,  -308,   996,   991,   958, -1460,  1522,  1628
};

// ─── Number Theoretic Transform ───────────────────────────────────────────
/*
 * Forward NTT (Cooley-Tukey butterfly, in-place).
 * After this transform the polynomial's coefficients are in NTT domain
 * with Montgomery representation; the result is not bit-reversed.
 *
 * The Kyber NTT factors X^256+1 into 128 quadratic factors:
 *   X^256+1 = ∏_{i=0}^{127} (X^2 - ζ^{2br7(i)+1})
 */
static inline void poly_ntt(poly *r)
{
    int len, start, j, k = 1;
    int16_t t, zeta;

    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < 256; start += 2 * len) {
            zeta = kyber_zetas[k++];
            for (j = start; j < start + len; j++) {
                t = montgomery_reduce((int32_t)zeta * r->coeffs[j + len]);
                r->coeffs[j + len] = r->coeffs[j] - t;
                r->coeffs[j]       = r->coeffs[j] + t;
            }
        }
    }
}

/*
 * Inverse NTT (Gentleman-Sande butterfly, in-place).
 * Converts coefficients back from NTT domain.
 * Factor 1/128 and Montgomery conversion are applied implicitly
 * via the final loop multiplying by f = 1441 = (128)^{-1}·R^2 (mod q).
 */
static inline void poly_invntt_tomont(poly *r)
{
    int start, len, j, k = 127;
    int16_t t, zeta;
    /* f = mont^2 / 128 mod q (precomputed constant for final scaling) */
    const int16_t f = 1441;

    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < 256; start += 2 * len) {
            zeta = -kyber_zetas[k--];    /* inverse zeta (negate for INTT) */
            for (j = start; j < start + len; j++) {
                t = r->coeffs[j];
                r->coeffs[j]       = barrett_reduce(t + r->coeffs[j + len]);
                r->coeffs[j + len] = t - r->coeffs[j + len];
                r->coeffs[j + len] = montgomery_reduce((int32_t)zeta *
                                                        r->coeffs[j + len]);
            }
        }
    }

    /* Final scaling: multiply every coefficient by f = 1441 */
    for (j = 0; j < KYBER_N; j++)
        r->coeffs[j] = montgomery_reduce((int32_t)f * r->coeffs[j]);
}

// ─── Polynomial base multiplication in NTT domain ─────────────────────────
/*
 * Multiply two degree-2 "residue" polynomials modulo X^2 - ζ^2.
 * This is the building block for NTT-domain polynomial multiplication.
 * (a0 + a1 X)(b0 + b1 X) mod X^2 - zeta = (a0*b0 + a1*b1*zeta) + (a0*b1+a1*b0)X
 */
static inline void basemul(int16_t r[2], const int16_t a[2],
                            const int16_t b[2], int16_t zeta)
{
    r[0] = montgomery_reduce((int32_t)a[1] * b[1]);
    r[0] = montgomery_reduce((int32_t)r[0] * zeta);
    r[0] += montgomery_reduce((int32_t)a[0] * b[0]);
    r[1]  = montgomery_reduce((int32_t)a[0] * b[1]);
    r[1] += montgomery_reduce((int32_t)a[1] * b[0]);
}

/*
 * Multiply two polynomials in NTT domain.  Both inputs must be in NTT
 * form; output is in NTT form and ready for poly_invntt_tomont.
 */
static inline void poly_basemul_montgomery(poly *r, const poly *a, const poly *b)
{
    int i;
    for (i = 0; i < KYBER_N / 4; i++) {
        basemul(&r->coeffs[4*i],   &a->coeffs[4*i],   &b->coeffs[4*i],   kyber_zetas[64+i]);
        basemul(&r->coeffs[4*i+2], &a->coeffs[4*i+2], &b->coeffs[4*i+2], -kyber_zetas[64+i]);
    }
}

/* Barrett-reduce all coefficients of a polynomial into (-q/2, q/2]. */
static inline void poly_reduce(poly *r)
{
    int i;
    for (i = 0; i < KYBER_N; i++)
        r->coeffs[i] = barrett_reduce(r->coeffs[i]);
}

/* Convert polynomial from standard to Montgomery domain (× R mod q). */
static inline void poly_tomont(poly *r)
{
    int i;
    const int16_t f = (1ULL << 32) % KYBER_Q; /* = 1353 */
    for (i = 0; i < KYBER_N; i++)
        r->coeffs[i] = montgomery_reduce((int32_t)r->coeffs[i] * f);
}

static inline void poly_add(poly *r, const poly *a, const poly *b)
{
    int i;
    for (i = 0; i < KYBER_N; i++)
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

static inline void poly_sub(poly *r, const poly *a, const poly *b)
{
    int i;
    for (i = 0; i < KYBER_N; i++)
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

// ─── PolyVec operations ───────────────────────────────────────────────────

static inline void polyvec_ntt(polyvec *r)
{
    int i;
    for (i = 0; i < KYBER_K; i++) poly_ntt(&r->vec[i]);
}

static inline void polyvec_invntt_tomont(polyvec *r)
{
    int i;
    for (i = 0; i < KYBER_K; i++) poly_invntt_tomont(&r->vec[i]);
}

static inline void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b)
{
    int i;
    for (i = 0; i < KYBER_K; i++) poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}

static inline void polyvec_reduce(polyvec *r)
{
    int i;
    for (i = 0; i < KYBER_K; i++) poly_reduce(&r->vec[i]);
}

/*
 * Accumulate the inner product a^T b into r (NTT domain).
 * r += sum_{j} a[j] * b[j]
 */
static inline void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a,
                                                  const polyvec *b)
{
    int i;
    poly t;
    poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
    for (i = 1; i < KYBER_K; i++) {
        poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
        poly_add(r, r, &t);
    }
    poly_reduce(r);
}

// ─── Serialisation / deserialisation ─────────────────────────────────────
/*
 * Pack 256 12-bit coefficients (in [0, q)) into 384 bytes.
 * Format: 3 bytes hold 2 coefficients (12+12 bits).
 */
static inline void poly_tobytes(uint8_t r[KYBER_POLYBYTES], const poly *a)
{
    int i;
    uint16_t t0, t1;
    for (i = 0; i < KYBER_N / 2; i++) {
        t0 = (uint16_t)csubq(a->coeffs[2*i]);
        t1 = (uint16_t)csubq(a->coeffs[2*i+1]);
        r[3*i + 0] = (uint8_t)(t0 >> 0);
        r[3*i + 1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        r[3*i + 2] = (uint8_t)(t1 >> 4);
    }
}

static inline void poly_frombytes(poly *r, const uint8_t a[KYBER_POLYBYTES])
{
    int i;
    for (i = 0; i < KYBER_N / 2; i++) {
        r->coeffs[2*i]   = (int16_t)(((a[3*i+0]     ) | ((uint16_t)a[3*i+1] << 8)) & 0xFFF);
        r->coeffs[2*i+1] = (int16_t)(((a[3*i+1] >> 4) | ((uint16_t)a[3*i+2] << 4)) & 0xFFF);
    }
}

static inline void polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const polyvec *a)
{
    int i;
    for (i = 0; i < KYBER_K; i++)
        poly_tobytes(r + i * KYBER_POLYBYTES, &a->vec[i]);
}

static inline void polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES])
{
    int i;
    for (i = 0; i < KYBER_K; i++)
        poly_frombytes(&r->vec[i], a + i * KYBER_POLYBYTES);
}

// ─── Compression / decompression ─────────────────────────────────────────
/*
 * Compress poly to DV=4 bits per coefficient (128 bytes).
 * Compression maps q-range values to a smaller range, losing precision.
 * This is what allows Kyber to be compact (768 byte ciphertext for k=2).
 */
static inline void poly_compress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES], const poly *a)
{
    int i;
    uint8_t t[8];
    for (i = 0; i < KYBER_N / 8; i++) {
        int j;
        for (j = 0; j < 8; j++) {
            /* Map coefficient → [0, 2^DV): round(coeff * 2^DV / q) mod 2^DV */
            uint32_t u = (uint32_t)csubq(a->coeffs[8*i+j]);
            t[j] = (uint8_t)((((u << 4) + KYBER_Q/2) / KYBER_Q) & 15);
        }
        /* Pack eight 4-bit values into four bytes */
        r[4*i+0] = (uint8_t)(t[0] | (t[1] << 4));
        r[4*i+1] = (uint8_t)(t[2] | (t[3] << 4));
        r[4*i+2] = (uint8_t)(t[4] | (t[5] << 4));
        r[4*i+3] = (uint8_t)(t[6] | (t[7] << 4));
    }
}

static inline void poly_decompress(poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES])
{
    int i;
    for (i = 0; i < KYBER_N / 2; i++) {
        r->coeffs[2*i]   = (int16_t)((((a[i] & 15) * (uint32_t)KYBER_Q) + 8) >> 4);
        r->coeffs[2*i+1] = (int16_t)((((a[i] >> 4) * (uint32_t)KYBER_Q) + 8) >> 4);
    }
}

/*
 * Compress polyvec to DU=10 bits per coefficient (K*320 = 640 bytes).
 */
static inline void polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES],
                                    const polyvec *a)
{
    int i, j;
    uint16_t t[4];
    int idx = 0;
    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_N / 4; j++) {
            int l;
            for (l = 0; l < 4; l++) {
                uint32_t u = (uint32_t)csubq(a->vec[i].coeffs[4*j+l]);
                t[l] = (uint16_t)((((u << 10) + KYBER_Q/2) / KYBER_Q) & 0x3FF);
            }
            r[idx++] = (uint8_t)(t[0] >> 0);
            r[idx++] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
            r[idx++] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
            r[idx++] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
            r[idx++] = (uint8_t)(t[3] >> 2);
        }
    }
}

static inline void polyvec_decompress(polyvec *r,
                                      const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES])
{
    int i, j, idx = 0;
    uint16_t t[4];
    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_N / 4; j++) {
            t[0] = (uint16_t)( a[idx]         | ((uint16_t)a[idx+1] << 8));
            t[1] = (uint16_t)((a[idx+1] >> 2) | ((uint16_t)a[idx+2] << 6));
            t[2] = (uint16_t)((a[idx+2] >> 4) | ((uint16_t)a[idx+3] << 4));
            t[3] = (uint16_t)((a[idx+3] >> 6) | ((uint16_t)a[idx+4] << 2));
            idx += 5;
            int l;
            for (l = 0; l < 4; l++)
                r->vec[i].coeffs[4*j+l] = (int16_t)(((t[l] & 0x3FF) * (uint32_t)KYBER_Q + 512) >> 10);
        }
    }
}

// ─── Message encoding / decoding ─────────────────────────────────────────
/*
 * Encode a 32-byte message as a polynomial with coefficients in {0, q/2}.
 * Bit i of the message sets coefficient i of the poly to q/2 or 0.
 */
static inline void poly_frommsg(poly *r, const uint8_t msg[KYBER_SYMBYTES])
{
    int i, j;
    for (i = 0; i < KYBER_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            /* Broadcast bit (i*8+j) to -(m>>j&1) then mask with q/2 */
            int16_t mask = -((int16_t)((msg[i] >> j) & 1));
            r->coeffs[8*i+j] = mask & (int16_t)((KYBER_Q + 1) / 2);
        }
    }
}

/*
 * Decode a polynomial back to a 32-byte message: bit i = round(coeffs[i] / (q/2)).
 */
static inline void poly_tomsg(uint8_t msg[KYBER_SYMBYTES], const poly *a)
{
    int i, j;
    memset(msg, 0, KYBER_SYMBYTES);
    for (i = 0; i < KYBER_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            /* Round: t = (2*coeff + q/2) / q  →  0 or 1 */
            uint32_t t = (uint32_t)csubq(a->coeffs[8*i+j]);
            t = ((t << 1) + KYBER_Q/2) / KYBER_Q;
            msg[i] |= (uint8_t)((t & 1) << j);
        }
    }
}

// ─── Centered Binomial Distribution sampling ─────────────────────────────
/*
 * Sample a polynomial with small coefficients from eta=3 CBD.
 * Each coefficient c = Σ(bit[i]) - Σ(bit[i+eta]) for i in [0,eta).
 * Output coefficients are in {-eta, ..., +eta}.
 */
static inline void poly_cbd3(poly *r, const uint8_t buf[3 * KYBER_N / 4])
{
    /* eta=3: consume 3 bits for each of a and b → 6 bits per coefficient */
    int i, j;
    for (i = 0; i < KYBER_N / 4; i++) {
        uint32_t t = (uint32_t)buf[3*i] | ((uint32_t)buf[3*i+1] << 8) | ((uint32_t)buf[3*i+2] << 16);
        for (j = 0; j < 4; j++) {
            /* Extract 3-bit a and 3-bit b for this coefficient */
            uint32_t a = (t >> (6*j))   & 0x7;
            uint32_t b = (t >> (6*j+3)) & 0x7;
            /* popcount(3-bit value) = number of 1 bits */
            a = ((a >> 2) & 1) + ((a >> 1) & 1) + (a & 1);
            b = ((b >> 2) & 1) + ((b >> 1) & 1) + (b & 1);
            r->coeffs[4*i+j] = (int16_t)(a - b);
        }
    }
}

/*
 * Sample a polynomial with small coefficients from eta=2 CBD.
 * 4 bits per coefficient: a = b0+b1, b = b2+b3, coeff = a - b.
 */
static inline void poly_cbd2(poly *r, const uint8_t buf[2 * KYBER_N / 4])
{
    int i, j;
    for (i = 0; i < KYBER_N / 4; i++) {
        uint16_t t = (uint16_t)buf[2*i] | ((uint16_t)buf[2*i+1] << 8);
        for (j = 0; j < 4; j++) {
            uint16_t a = (t >> (4*j))     & 0x3;
            uint16_t b = (t >> (4*j + 2)) & 0x3;
            a = (a & 1) + (a >> 1);
            b = (b & 1) + (b >> 1);
            r->coeffs[4*i+j] = (int16_t)(a - b);
        }
    }
}

/* Generate noise polynomial using SHAKE-256(seed || nonce) */
static inline void poly_getnoise_eta1(poly *r, const uint8_t seed[KYBER_SYMBYTES],
                                      uint8_t nonce)
{
    /* eta1=3 → need 3*N/4 = 192 bytes of pseudorandom output */
    uint8_t buf[3 * KYBER_N / 4];
    uint8_t extkey[KYBER_SYMBYTES + 1];
    memcpy(extkey, seed, KYBER_SYMBYTES);
    extkey[KYBER_SYMBYTES] = nonce;
    shake256(buf, sizeof(buf), extkey, sizeof(extkey));
    poly_cbd3(r, buf);
}

static inline void poly_getnoise_eta2(poly *r, const uint8_t seed[KYBER_SYMBYTES],
                                      uint8_t nonce)
{
    /* eta2=2 → need 2*N/4 = 128 bytes of pseudorandom output */
    uint8_t buf[2 * KYBER_N / 4];
    uint8_t extkey[KYBER_SYMBYTES + 1];
    memcpy(extkey, seed, KYBER_SYMBYTES);
    extkey[KYBER_SYMBYTES] = nonce;
    shake256(buf, sizeof(buf), extkey, sizeof(extkey));
    poly_cbd2(r, buf);
}

// ─── Matrix generation ────────────────────────────────────────────────────
/*
 * Expand seed ρ into the public matrix A (or its transpose A^T).
 * Each entry A[i][j] is generated via SHAKE-128(ρ || j || i) (transposed)
 * or SHAKE-128(ρ || i || j) (normal form).
 *
 * The "rejection sampling" loop discards coefficients ≥ q.
 */
static inline void gen_matrix(polyvec a[KYBER_K], const uint8_t seed[KYBER_SYMBYTES],
                               int transposed)
{
    int i, j, cnt, pos;
    shake128_ctx xof;
    /*
     * Declare as static to move from stack to BSS — avoids stack overflow
     * on ESP32 Arduino (default 8 KB task stack).  Safe for single-threaded use.
     */
    static uint8_t buf[672];    /* 4 × 168 SHAKE blocks */
    uint8_t seed_ij[KYBER_SYMBYTES + 2];

    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_K; j++) {
            /* Seed the XOF with ρ || (row, col) */
            memcpy(seed_ij, seed, KYBER_SYMBYTES);
            if (transposed) { seed_ij[KYBER_SYMBYTES] = (uint8_t)i;
                              seed_ij[KYBER_SYMBYTES+1] = (uint8_t)j; }
            else            { seed_ij[KYBER_SYMBYTES] = (uint8_t)j;
                              seed_ij[KYBER_SYMBYTES+1] = (uint8_t)i; }

            shake128_init(&xof);
            shake128_absorb(&xof, seed_ij, KYBER_SYMBYTES + 2);
            shake128_finalize(&xof);
            shake128_squeeze(&xof, buf, sizeof(buf));

            cnt = 0; pos = 0;
            while (cnt < KYBER_N) {
                /* Extract two 12-bit values from three bytes */
                if (pos + 3 > (int)sizeof(buf)) {
                    shake128_squeeze(&xof, buf, sizeof(buf));
                    pos = 0;
                }
                uint16_t val0 = ((uint16_t)(buf[pos])   | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
                uint16_t val1 = ((uint16_t)(buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
                pos += 3;
                if (val0 < KYBER_Q) a[i].vec[j].coeffs[cnt++] = (int16_t)val0;
                if (cnt < KYBER_N && val1 < KYBER_Q) a[i].vec[j].coeffs[cnt++] = (int16_t)val1;
            }
        }
    }
}

// ─── IND-CPA PKE (inner encryption scheme) ───────────────────────────────
/*
 * Kyber IND-CPA key generation.
 *   pk = (A·s + e, ρ)   where A = GenMatrix(ρ), s,e ← CBD
 *   sk = s
 */
static inline void indcpa_keypair(uint8_t pk[KYBER512_PUBLICKEYBYTES],
                                  uint8_t sk[KYBER_POLYVECBYTES],
                                  const uint8_t seed[KYBER_SYMBYTES])
{
    /* Hash seed to get (ρ, σ): ρ expands A, σ expands s and e */
    uint8_t buf[2 * KYBER_SYMBYTES];
    sha3_512(buf, seed, KYBER_SYMBYTES);
    const uint8_t *rho   = buf;
    const uint8_t *sigma = buf + KYBER_SYMBYTES;

    /* Static locals: each polyvec is 1024 bytes — keep off the 8 KB ESP32 stack */
    static polyvec a[KYBER_K], s, e, pkpv;
    int i;

    gen_matrix(a, rho, 0);   /* A in normal form */

    /* Sample secret vector s ← CBD_eta1 */
    for (i = 0; i < KYBER_K; i++)
        poly_getnoise_eta1(&s.vec[i], sigma, (uint8_t)i);

    /* Sample error vector e ← CBD_eta1 */
    for (i = 0; i < KYBER_K; i++)
        poly_getnoise_eta1(&e.vec[i], sigma, (uint8_t)(KYBER_K + i));

    /* NTT-form s and e */
    polyvec_ntt(&s);
    polyvec_ntt(&e);

    /* Compute public key: pk = A·s + e  (matrix-vector product in NTT domain) */
    for (i = 0; i < KYBER_K; i++) {
        polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &s);
        poly_tomont(&pkpv.vec[i]);
    }
    polyvec_add(&pkpv, &pkpv, &e);
    polyvec_reduce(&pkpv);

    /* Serialise */
    polyvec_tobytes(sk, &s);                         /* sk = s (NTT form) */
    polyvec_tobytes(pk, &pkpv);                      /* pk part 1 = b */
    memcpy(pk + KYBER_POLYVECBYTES, rho, KYBER_SYMBYTES); /* pk part 2 = ρ */
}

/*
 * Kyber IND-CPA encryption.
 * Encrypt 32-byte message m under pk, using random coins.
 *   r, e1 ← CBD_eta1;  e2 ← CBD_eta2
 *   u = A^T·r + e1
 *   v = b^T·r + e2 + msg_poly
 *   ct = (Compress(u), Compress(v))
 */
static inline void indcpa_enc(uint8_t ct[KYBER512_CIPHERTEXTBYTES],
                               const uint8_t m[KYBER_SYMBYTES],
                               const uint8_t pk[KYBER512_PUBLICKEYBYTES],
                               const uint8_t coins[KYBER_SYMBYTES])
{
    /* Static locals to avoid stack overflow on constrained targets */
    static polyvec sp, pkpv, ep, at[KYBER_K], bp;
    poly v, k, epp;
    int i;
    const uint8_t *rho = pk + KYBER_POLYVECBYTES;

    /* Expand public key matrix A^T */
    gen_matrix(at, rho, 1);   /* transposed */

    polyvec_frombytes(&pkpv, pk);

    /* Sample ephemeral secret r and errors e1, e2 */
    for (i = 0; i < KYBER_K; i++)
        poly_getnoise_eta1(&sp.vec[i], coins, (uint8_t)i);
    for (i = 0; i < KYBER_K; i++)
        poly_getnoise_eta1(&ep.vec[i], coins, (uint8_t)(KYBER_K + i));
    poly_getnoise_eta2(&epp, coins, (uint8_t)(2 * KYBER_K));

    polyvec_ntt(&sp);

    /* u = A^T·r + e1 */
    for (i = 0; i < KYBER_K; i++) {
        polyvec_basemul_acc_montgomery(&bp.vec[i], &at[i], &sp);
        poly_tomont(&bp.vec[i]);
    }
    polyvec_invntt_tomont(&bp);
    polyvec_add(&bp, &bp, &ep);
    polyvec_reduce(&bp);

    /* v = pk_b^T · r + e2 + msg_poly */
    polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);
    poly_invntt_tomont(&v);
    poly_add(&v, &v, &epp);
    poly_frommsg(&k, m);
    poly_add(&v, &v, &k);
    poly_reduce(&v);

    /* Compress and write ciphertext */
    polyvec_compress(ct, &bp);
    poly_compress(ct + KYBER_POLYVECCOMPRESSEDBYTES, &v);
}

/*
 * Kyber IND-CPA decryption.
 * Recover 32-byte message m from ciphertext.
 *   m = Decompress(v) - s^T·Decompress(u)
 */
static inline void indcpa_dec(uint8_t m[KYBER_SYMBYTES],
                               const uint8_t ct[KYBER512_CIPHERTEXTBYTES],
                               const uint8_t sk[KYBER_POLYVECBYTES])
{
    static polyvec bp, skpv;
    poly v, mp;

    polyvec_decompress(&bp, ct);
    poly_decompress(&v, ct + KYBER_POLYVECCOMPRESSEDBYTES);
    polyvec_frombytes(&skpv, sk);

    polyvec_ntt(&bp);
    polyvec_basemul_acc_montgomery(&mp, &skpv, &bp);
    poly_invntt_tomont(&mp);

    poly_sub(&mp, &v, &mp);
    poly_reduce(&mp);
    poly_tomsg(m, &mp);
}

// ─── KEM public API ───────────────────────────────────────────────────────
/*
 * Kyber-512 Key Generation.
 * Generates a public/secret key pair.
 *
 * pk [out] : KYBER512_PUBLICKEYBYTES (800)  — share with the peer
 * sk [out] : KYBER512_SECRETKEYBYTES (1632) — keep secret
 *
 * sk layout: s_bytes || pk || H(pk) || z
 *   s_bytes = IND-CPA secret key  (768 B)
 *   pk       = public key         (800 B)
 *   H(pk)    = SHA3-256(pk)        (32 B)
 *   z        = random rejection seed(32 B)  ← for implicit rejection
 */
static inline void kyber512_keypair(uint8_t pk[KYBER512_PUBLICKEYBYTES],
                                    uint8_t sk[KYBER512_SECRETKEYBYTES])
{
    uint8_t seed[KYBER_SYMBYTES], z[KYBER_SYMBYTES];
    esp_fill_random(seed, KYBER_SYMBYTES);
    esp_fill_random(z,    KYBER_SYMBYTES);

    /* Generate IND-CPA keys */
    uint8_t *sk_cpa = sk;                                   /* 768 bytes */
    indcpa_keypair(pk, sk_cpa, seed);

    /* Append pk and its hash to sk for decapsulation */
    memcpy(sk + KYBER_POLYVECBYTES, pk, KYBER512_PUBLICKEYBYTES);
    sha3_256(sk + KYBER_POLYVECBYTES + KYBER512_PUBLICKEYBYTES, pk,
             KYBER512_PUBLICKEYBYTES);
    /* Append implicit-rejection seed z */
    memcpy(sk + KYBER512_SECRETKEYBYTES - KYBER_SYMBYTES, z, KYBER_SYMBYTES);
}

/*
 * Kyber-512 Encapsulation (run by the sender / Bob).
 * Generates a random shared secret `ss` and a ciphertext `ct`.
 * Send `ct` to Alice; `ss` is the shared secret.
 *
 * ct [out] : KYBER512_CIPHERTEXTBYTES (768)
 * ss [out] : KYBER512_SSBYTES         (32)
 * pk [in]  : Alice's public key       (800)
 */
static inline void kyber512_enc(uint8_t ct[KYBER512_CIPHERTEXTBYTES],
                                 uint8_t ss[KYBER512_SSBYTES],
                                 const uint8_t pk[KYBER512_PUBLICKEYBYTES])
{
    /* Sample a random 32-byte message m and hash it to get (m', coins)
     * The double-hash prevents the message from leaking directly. */
    uint8_t m[KYBER_SYMBYTES], kr[2 * KYBER_SYMBYTES], buf[KYBER_SYMBYTES + KYBER_SYMBYTES];

    esp_fill_random(m, KYBER_SYMBYTES);

    /* m' = H(m): hash message to prevent partial-key leakage */
    sha3_256(buf, m, KYBER_SYMBYTES);

    /* kr = G(m' || H(pk)) where G = SHA3-512 */
    sha3_256(buf + KYBER_SYMBYTES, pk, KYBER512_PUBLICKEYBYTES);
    sha3_512(kr, buf, 2 * KYBER_SYMBYTES);

    /* Encrypt: ct = Enc(pk, m'; coins = kr[32..63]) */
    indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES);

    /* ss = KDF(kr[0..31] || H(ct))  via SHA3-256 */
    sha3_256(kr + KYBER_SYMBYTES, ct, KYBER512_CIPHERTEXTBYTES);
    sha3_256(ss, kr, 2 * KYBER_SYMBYTES);
}

/*
 * Kyber-512 Decapsulation (run by the receiver / Alice).
 * Recovers the shared secret `ss` from ciphertext `ct` using `sk`.
 * Implements implicit rejection (Fujisaki-Okamoto transform): if the
 * ciphertext is invalid, a pseudorandom value is returned instead of
 * failing — this prevents timing-based CCA attacks.
 *
 * ss [out] : KYBER512_SSBYTES         (32)
 * ct [in]  : KYBER512_CIPHERTEXTBYTES (768)
 * sk [in]  : KYBER512_SECRETKEYBYTES  (1632)
 */
static inline void kyber512_dec(uint8_t ss[KYBER512_SSBYTES],
                                 const uint8_t ct[KYBER512_CIPHERTEXTBYTES],
                                 const uint8_t sk[KYBER512_SECRETKEYBYTES])
{
    const uint8_t *sk_cpa = sk;
    const uint8_t *pk     = sk + KYBER_POLYVECBYTES;
    const uint8_t *hpk    = pk + KYBER512_PUBLICKEYBYTES;
    const uint8_t *z      = hpk + KYBER_SYMBYTES;

    uint8_t m[KYBER_SYMBYTES], kr[2 * KYBER_SYMBYTES];
    uint8_t cmp[KYBER512_CIPHERTEXTBYTES];
    uint8_t buf[2 * KYBER_SYMBYTES];

    /* Decrypt to recover candidate message m */
    indcpa_dec(m, ct, sk_cpa);

    /* Recompute (K, coins) = G(m || H(pk)) */
    memcpy(buf, m, KYBER_SYMBYTES);
    memcpy(buf + KYBER_SYMBYTES, hpk, KYBER_SYMBYTES);
    sha3_512(kr, buf, 2 * KYBER_SYMBYTES);

    /* Re-encrypt with recovered m and verify */
    indcpa_enc(cmp, m, pk, kr + KYBER_SYMBYTES);

    /* Constant-time comparison to detect decryption failure */
    uint8_t fail = 0;
    int i;
    for (i = 0; i < KYBER512_CIPHERTEXTBYTES; i++)
        fail |= ct[i] ^ cmp[i];

    /* ss = SHA3-256(K || H(ct))  or  SHA3-256(z || H(ct)) if fail */
    sha3_256(kr + KYBER_SYMBYTES, ct, KYBER512_CIPHERTEXTBYTES);

    /* Use implicit rejection: mix in z on failure (constant-time select) */
    uint8_t mask = (uint8_t)(-(fail != 0));   /* 0xFF if fail, 0x00 if OK */
    for (i = 0; i < KYBER_SYMBYTES; i++)
        kr[i] = (kr[i] & ~mask) | (z[i] & mask);

    sha3_256(ss, kr, 2 * KYBER_SYMBYTES);
}
