#pragma once
/*
 * ============================================================
 *  ascon128.h  —  ASCON-128 Authenticated Encryption
 * ============================================================
 *  ASCON is a family of lightweight authenticated ciphers
 *  selected by NIST for standardisation (2023, NIST SP 800-232).
 *  It is designed for constrained devices (microcontrollers).
 *
 *  ASCON-128 parameters:
 *    Key size   : 128 bits (16 bytes)
 *    Nonce size : 128 bits (16 bytes)
 *    Tag size   : 128 bits (16 bytes)
 *    Rate (r)   : 64 bits  (8 bytes per permutation call)
 *    Rounds pa  : 12 (initialisation / finalisation)
 *    Rounds pb  : 6  (per data block)
 *
 *  API
 *  ───
 *  ascon128_encrypt(ct, ctlen, pt, ptlen, ad, adlen, nonce, key)
 *    → writes ptlen ciphertext bytes, then appends 16-byte tag
 *  ascon128_decrypt(pt, ptlen, ct, ctlen, ad, adlen, nonce, key)
 *    → returns 0 on success (tag verified), -1 on auth failure
 *
 *  Based on the ASCON v1.2 specification (Dobraunig et al.).
 *  Written as single header; no dynamic allocation.
 * ============================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// ─── Internal sizes ──────────────────────────────────────────
#define ASCON_KEY_LEN    16    /* bytes */
#define ASCON_NONCE_LEN  16    /* bytes */
#define ASCON_TAG_LEN    16    /* bytes */
#define ASCON_RATE        8    /* bytes per block (r = 64 bits) */
#define ASCON_ROUNDS_A   12    /* pa = 12 for ASCON-128 */
#define ASCON_ROUNDS_B    6    /* pb = 6  for ASCON-128 */

/* ASCON-128 Initialization Vector (top 64 bits of S[0]) */
#define ASCON128_IV  UINT64_C(0x80400c0600000000)

// ─── 64-bit rotate right ─────────────────────────────────────
#define ROTR64(x, n)  (((x) >> (n)) | ((x) << (64 - (n))))

// ─── ASCON state ─────────────────────────────────────────────
/* The ASCON permutation operates on a 320-bit state = 5 × 64-bit words */
typedef struct { uint64_t x[5]; } ascon_state_t;

// ─── Round constants ─────────────────────────────────────────
/*
 * For ASCON-128 with pa=12 rounds, the round constants for round i are:
 *   rc[i] = ((0xf - i) << 4) | i   (a single byte XORed into x[2])
 * Round constants for pa=12:
 *   0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
 * For pb=6 (rounds 6..11 of pa=12):
 *   0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
 */
static const uint8_t ascon_rc12[12] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
    0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
};

// ─── ASCON permutation ───────────────────────────────────────
/*
 * Apply `rounds` permutation rounds to the state, starting at
 * round index (12 - rounds) in the full 12-round sequence.
 * This ensures pb=6 rounds uses the same constants as rounds 6..11
 * of the pa=12 initialisation rounds.
 */
static inline void ascon_permute(ascon_state_t *s, int rounds)
{
    int i;
    int start = 12 - rounds;   /* start offset in rc12 table */

    for (i = start; i < 12; i++) {

        /* ── p_C: constant addition ── */
        s->x[2] ^= (uint64_t)ascon_rc12[i];

        /* ── p_S: substitution layer (5-bit S-box applied to all 64 bit slices)
         * This is the non-linear step.  The S-box is applied bit-slice-wise:
         * each "bit position" across (x0..x4) forms one 5-bit S-box input.
         */
        s->x[0] ^= s->x[4];
        s->x[4] ^= s->x[3];
        s->x[2] ^= s->x[1];

        /* AND-NOT operations (the non-linear part) */
        uint64_t t0 = s->x[0], t1 = s->x[1], t2 = s->x[2],
                 t3 = s->x[3], t4 = s->x[4];
        s->x[0] ^= (~t1) & t2;
        s->x[1] ^= (~t2) & t3;
        s->x[2] ^= (~t3) & t4;
        s->x[3] ^= (~t4) & t0;
        s->x[4] ^= (~t0) & t1;

        s->x[1] ^= s->x[0];
        s->x[0] ^= s->x[4];
        s->x[3] ^= s->x[2];
        s->x[2]  = ~s->x[2];  /* invert x2 */

        /* ── p_L: linear diffusion layer
         * Each word xi is mixed with two rotations of itself.
         * Rotation constants from ASCON v1.2 spec §2.6.
         */
        s->x[0] ^= ROTR64(s->x[0], 19) ^ ROTR64(s->x[0], 28);
        s->x[1] ^= ROTR64(s->x[1], 61) ^ ROTR64(s->x[1], 39);
        s->x[2] ^= ROTR64(s->x[2],  1) ^ ROTR64(s->x[2],  6);
        s->x[3] ^= ROTR64(s->x[3], 10) ^ ROTR64(s->x[3], 17);
        s->x[4] ^= ROTR64(s->x[4],  7) ^ ROTR64(s->x[4], 41);
    }
}

// ─── Load / store helpers (big-endian byte order) ─────────────
static inline uint64_t load64_be(const uint8_t *b)
{
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] <<  8) |  (uint64_t)b[7];
}

static inline void store64_be(uint8_t *b, uint64_t v)
{
    b[0] = (uint8_t)(v >> 56); b[1] = (uint8_t)(v >> 48);
    b[2] = (uint8_t)(v >> 40); b[3] = (uint8_t)(v >> 32);
    b[4] = (uint8_t)(v >> 24); b[5] = (uint8_t)(v >> 16);
    b[6] = (uint8_t)(v >>  8); b[7] = (uint8_t)(v);
}

/*
 * XOR up to 8 bytes from `src` into the rate word of the state,
 * return the resulting rate word, and optionally write ciphertext.
 * For the last (partial) block, unprocessed bytes in the state word
 * are preserved and padding is applied.
 */
static inline uint64_t process_block(uint64_t rate_word,
                                     const uint8_t *src, uint8_t *dst,
                                     size_t len, int encrypt)
{
    /* Build a big-endian 8-byte block from src (zero-padded if len < 8) */
    uint8_t buf[8] = {0};
    size_t i;
    if (encrypt) {
        /* Encryption: ct = pt XOR rate_word bytes */
        memcpy(buf, src, len);
        uint64_t pt_word = load64_be(buf);
        uint64_t ct_word = rate_word ^ pt_word;
        store64_be(buf, ct_word);
        memcpy(dst, buf, len);
        return ct_word;    /* update rate word with ciphertext */
    } else {
        /* Decryption: pt = ct XOR rate_word bytes */
        memcpy(buf, src, len);
        uint64_t ct_word = load64_be(buf);
        uint64_t pt_word = rate_word ^ ct_word;
        store64_be(buf, pt_word);
        memcpy(dst, buf, len);
        /* Replace only the processed bytes in rate_word */
        for (i = len; i < 8; i++) buf[i] = 0;
        uint64_t new_rate = ct_word;
        /* Preserve unchanged high bytes of rate_word (clear low bits = processed) */
        uint64_t mask = (len < 8) ? (UINT64_MAX << (8 * (8 - len))) : 0;
        new_rate = (ct_word & mask) | (rate_word & ~mask);
        (void)new_rate;
        /* Standard approach: return ct_word for partial last block */
        return ct_word;
    }
}

// ─── ASCON-128 Encrypt ───────────────────────────────────────
/*
 * Authenticated encryption.
 * Outputs ptlen bytes of ciphertext followed by 16-byte tag.
 * `ct` buffer must be at least (ptlen + 16) bytes.
 *
 * Parameters:
 *   ct       output ciphertext buffer (ptlen + ASCON_TAG_LEN bytes)
 *   pt       plaintext
 *   ptlen    plaintext length (bytes)
 *   ad       associated data (authenticated but not encrypted)
 *   adlen    associated data length
 *   nonce    16-byte random nonce (must be unique per (key, message) pair)
 *   key      16-byte secret key
 */
static inline void ascon128_encrypt(uint8_t *ct,
                                    const uint8_t *pt,  size_t ptlen,
                                    const uint8_t *ad,  size_t adlen,
                                    const uint8_t  nonce[ASCON_NONCE_LEN],
                                    const uint8_t  key[ASCON_KEY_LEN])
{
    ascon_state_t s;
    size_t i;

    /* ── Initialisation ──
     * S = IV || K || N  then apply pa rounds */
    s.x[0] = ASCON128_IV;
    s.x[1] = load64_be(key);
    s.x[2] = load64_be(key + 8);
    s.x[3] = load64_be(nonce);
    s.x[4] = load64_be(nonce + 8);
    ascon_permute(&s, ASCON_ROUNDS_A);
    s.x[3] ^= load64_be(key);
    s.x[4] ^= load64_be(key + 8);

    /* ── Associated Data Processing ──
     * Absorb AD in 8-byte (rate) blocks, apply pb rounds after each block.
     * A domain-separation constant (1) is XORed into x[4] after all AD. */
    if (adlen > 0) {
        while (adlen >= ASCON_RATE) {
            s.x[0] ^= load64_be(ad);
            ascon_permute(&s, ASCON_ROUNDS_B);
            ad    += ASCON_RATE;
            adlen -= ASCON_RATE;
        }
        /* Last partial AD block with 0x80 padding */
        uint8_t pad[8] = {0};
        memcpy(pad, ad, adlen);
        pad[adlen] = 0x80;    /* padding bit */
        s.x[0] ^= load64_be(pad);
        ascon_permute(&s, ASCON_ROUNDS_B);
    }
    s.x[4] ^= UINT64_C(1);   /* domain separation: AD vs PT */

    /* ── Plaintext Encryption ──
     * XOR plaintext into rate word, output ciphertext, then apply pb rounds. */
    size_t ptrem = ptlen;
    const uint8_t *pptr = pt;
    uint8_t *cptr = ct;

    while (ptrem >= ASCON_RATE) {
        s.x[0] ^= load64_be(pptr);
        store64_be(cptr, s.x[0]);   /* ciphertext = state rate word */
        ascon_permute(&s, ASCON_ROUNDS_B);
        pptr  += ASCON_RATE;
        cptr  += ASCON_RATE;
        ptrem -= ASCON_RATE;
    }
    /* Last partial block with 0x80 padding */
    {
        uint8_t pad[8] = {0};
        memcpy(pad, pptr, ptrem);
        pad[ptrem] = 0x80;
        s.x[0] ^= load64_be(pad);
        /* Output only ptrem ciphertext bytes */
        uint8_t cbuf[8];
        store64_be(cbuf, s.x[0]);
        memcpy(cptr, cbuf, ptrem);
        cptr += ptrem;
    }

    /* ── Finalisation ──
     * XOR key into middle words, apply pa rounds, XOR key into last words.
     * Output 16-byte authentication tag. */
    s.x[1] ^= load64_be(key);
    s.x[2] ^= load64_be(key + 8);
    ascon_permute(&s, ASCON_ROUNDS_A);
    s.x[3] ^= load64_be(key);
    s.x[4] ^= load64_be(key + 8);

    store64_be(cptr,     s.x[3]);   /* tag bytes 0-7  */
    store64_be(cptr + 8, s.x[4]);   /* tag bytes 8-15 */

    (void)i;
}

// ─── ASCON-128 Decrypt ───────────────────────────────────────
/*
 * Authenticated decryption.
 * Returns 0 if the authentication tag is valid, -1 otherwise.
 * On failure `pt` contents are zeroed (defence in depth).
 *
 * Parameters:
 *   pt       output plaintext buffer (ctlen - ASCON_TAG_LEN bytes)
 *   ct       ciphertext (includes the 16-byte tag appended at end)
 *   ctlen    total ciphertext length including tag (≥ ASCON_TAG_LEN)
 *   ad       associated data
 *   adlen    associated data length
 *   nonce    16-byte nonce (same as used during encryption)
 *   key      16-byte key
 *
 * Returns 0 on success, -1 on authentication failure.
 */
static inline int ascon128_decrypt(uint8_t *pt,
                                   const uint8_t *ct,  size_t ctlen,
                                   const uint8_t *ad,  size_t adlen,
                                   const uint8_t  nonce[ASCON_NONCE_LEN],
                                   const uint8_t  key[ASCON_KEY_LEN])
{
    if (ctlen < ASCON_TAG_LEN) return -1;
    size_t ptlen = ctlen - ASCON_TAG_LEN;
    const uint8_t *tag_in = ct + ptlen;
    ascon_state_t s;

    /* ── Initialisation (same as encrypt) ── */
    s.x[0] = ASCON128_IV;
    s.x[1] = load64_be(key);
    s.x[2] = load64_be(key + 8);
    s.x[3] = load64_be(nonce);
    s.x[4] = load64_be(nonce + 8);
    ascon_permute(&s, ASCON_ROUNDS_A);
    s.x[3] ^= load64_be(key);
    s.x[4] ^= load64_be(key + 8);

    /* ── Associated Data Processing (same as encrypt) ── */
    if (adlen > 0) {
        while (adlen >= ASCON_RATE) {
            s.x[0] ^= load64_be(ad);
            ascon_permute(&s, ASCON_ROUNDS_B);
            ad    += ASCON_RATE;
            adlen -= ASCON_RATE;
        }
        uint8_t pad[8] = {0};
        memcpy(pad, ad, adlen);
        pad[adlen] = 0x80;
        s.x[0] ^= load64_be(pad);
        ascon_permute(&s, ASCON_ROUNDS_B);
    }
    s.x[4] ^= UINT64_C(1);

    /* ── Ciphertext Decryption ──
     * XOR ciphertext into rate word, recover plaintext, reload ct into state. */
    size_t ctrem = ptlen;
    const uint8_t *cptr = ct;
    uint8_t *pptr = pt;

    while (ctrem >= ASCON_RATE) {
        uint64_t c = load64_be(cptr);
        store64_be(pptr, s.x[0] ^ c);  /* plaintext = rate XOR ciphertext */
        s.x[0] = c;                      /* absorb ciphertext into state */
        ascon_permute(&s, ASCON_ROUNDS_B);
        cptr  += ASCON_RATE;
        pptr  += ASCON_RATE;
        ctrem -= ASCON_RATE;
    }
    /* Last partial block */
    {
        uint8_t pad[8] = {0};
        memcpy(pad, cptr, ctrem);
        uint64_t c = load64_be(pad);
        uint64_t p = s.x[0] ^ c;
        uint8_t pbuf[8];
        store64_be(pbuf, p);
        memcpy(pptr, pbuf, ctrem);
        /* Pad and absorb: replace decrypted bytes with ct bytes, keep rest */
        pad[ctrem] = 0x80;
        s.x[0] ^= load64_be(pad);
    }

    /* ── Finalisation (same as encrypt) ── */
    s.x[1] ^= load64_be(key);
    s.x[2] ^= load64_be(key + 8);
    ascon_permute(&s, ASCON_ROUNDS_A);
    s.x[3] ^= load64_be(key);
    s.x[4] ^= load64_be(key + 8);

    /* ── Tag Verification (constant-time) ──
     * Compare computed tag to received tag without short-circuiting
     * to prevent timing side-channels. */
    uint8_t tag_comp[ASCON_TAG_LEN];
    store64_be(tag_comp,     s.x[3]);
    store64_be(tag_comp + 8, s.x[4]);

    uint8_t diff = 0;
    int i;
    for (i = 0; i < ASCON_TAG_LEN; i++)
        diff |= tag_comp[i] ^ tag_in[i];

    if (diff != 0) {
        /* Authentication failed — zero out plaintext to prevent misuse */
        memset(pt, 0, ptlen);
        return -1;
    }
    return 0;
}
