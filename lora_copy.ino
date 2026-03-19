/*
 * ============================================================
 *  Quantum-Secure LoRa Messenger  v3.0
 * ============================================================
 *  Hardware : ESP32 Dev Module + SX1276 LoRa + ILI9341 TFT
 *             (320 × 240 resistive touch, 2.8 inch)
 *
 *  Post-Quantum Hybrid Cryptographic Architecture
 *  ──────────────────────────────────────────────
 *  KEY EXCHANGE (per-session, quantum-resistant):
 *    • Kyber-512 (ML-KEM-512) — NIST FIPS 203
 *      Lattice-based KEM; resistant to Shor's algorithm.
 *      Outputs a 32-byte shared secret per session.
 *
 *  MESSAGE ENCRYPTION (per-message):
 *    • ASCON-128 — NIST Lightweight Crypto Standard (2023)
 *      128-bit key (first 16 bytes of Kyber shared secret)
 *      128-bit nonce (random, ESP32 hardware TRNG)
 *      128-bit authentication tag (tamper detection)
 *
 *  Key Exchange Flow
 *  ─────────────────
 *  1. At boot each node broadcasts PKT_KEM_INIT carrying its
 *     Kyber-512 public key (800 bytes, 4 LoRa fragments).
 *  2. Peer runs kyber512_enc(peer_pk) → sends PKT_KEM_RESP.
 *  3. Initiator runs kyber512_dec(ct, my_sk) → shared secret.
 *  4. ss[0..15] becomes the ASCON-128 session key.
 *  5. Press [KEY] on keyboard to re-initiate at any time.
 *
 *  Packet Layout (max 255 bytes)
 *  ─────────────────────────────
 *  [0-1]  NETWORK_ID        ← AAD (authenticated, not encrypted)
 *  [2]    dest_id            ← AAD
 *  [3]    src_id             ← AAD
 *  [4]    pkt_type           ← AAD
 *  [5-8]  seq_num u32 LE     ← AAD
 *
 *  PKT_MSG (0x01):
 *  [9-24] ASCON nonce (16 B)
 *  [25..] ciphertext + 16-byte ASCON tag
 *
 *  PKT_KEM_INIT (0x03) / PKT_KEM_RESP (0x04):
 *  [9]    frag_id      (0-based)
 *  [10]   frag_total
 *  [11..] up to 244 bytes of key data
 *
 *  Libraries needed (Arduino Library Manager):
 *    LoRa  by Sandeep Mistry
 *    TFT_eSPI  by Bodmer  (use the User_Setup.h from this folder)
 * ============================================================
 */

#include <FS.h>
#include <SPIFFS.h>
#include <SPI.h>
#include <TFT_eSPI.h>
#include <LoRa.h>
#include "esp_system.h"

/* Post-quantum crypto stack — include order matters */
#include "keccak_tiny.h"   /* SHA3-256 / SHA3-512 / SHAKE128 / SHAKE256     */
#include "kyber512.h"       /* Kyber-512 KEM  (uses keccak_tiny.h)           */
#include "ascon128.h"       /* ASCON-128 AEAD                                 */

#include "network_keys.h"   /* NETWORK_ID, NETWORK_KEY, MY_NODE_ID, FREQ … */

// ─── Hardware pins ──────────────────────────────────────────────────────────
#define LORA_SS   27
#define LORA_RST  25
#define LORA_DIO0 26

// ─── Screen ─────────────────────────────────────────────────────────────────
TFT_eSPI tft = TFT_eSPI();
#define SCREEN_W 320
#define SCREEN_H 240

// ─── UI layout ──────────────────────────────────────────────────────────────
//
//  y=0   ┌─────────────────────────────────┐
//        │ Status bar  16 px               │
//  y=16  ├─────────────────────────────────┤
//        │ Chat area   ~79 px (3 bubbles)  │
//  y=96  ├─────────────────────────────────┤
//        │ Text field  26 px               │
//  y=127 ├─────────────────────────────────┤
//        │ Keyboard    4 rows × 28 px      │
//  y=240 └─────────────────────────────────┘

#define STATUS_H       16
#define CHAT_Y         17
#define CHAT_BOT       95
#define MAX_MSGS        3
#define MSG_H          26

#define TEXT_X          4
#define TEXT_Y         99
#define TEXT_W        312
#define TEXT_H         26
#define MAX_TEXT       100

#define KEY_W          28
#define KEY_H          26
#define KEY_SPACING     2
#define TOTAL_KEYS     30

#define KB_ROW1       139
#define KB_ROW2       167
#define KB_ROW3       195
#define KB_ROW4       223

#define CALIBRATION_FILE "/TouchCalDat"

// ─── Crypto constants (ASCON-128) ───────────────────────────────────────────
#define NONCE_LEN        ASCON_NONCE_LEN   /* 16 bytes */
#define TAG_LEN          ASCON_TAG_LEN     /* 16 bytes */
#define SESSION_KEY_LEN  ASCON_KEY_LEN     /* 16 bytes (first 16 of Kyber SS) */

// ─── Packet types ───────────────────────────────────────────────────────────
#define PKT_MSG       0x01
#define PKT_PING      0x02
#define PKT_KEM_INIT  0x03
#define PKT_KEM_RESP  0x04

// ─── Packet offsets ─────────────────────────────────────────────────────────
#define PKT_AAD_LEN      9    /* bytes 0-8  = ASCON additional auth data */
#define PKT_NONCE_OFF    9    /* bytes 9-24 = 16-byte ASCON nonce        */
#define PKT_PAYLOAD_OFF 25    /* byte 25+   = ciphertext + tag           */
#define PKT_MIN_LEN     (PKT_PAYLOAD_OFF + 1 + TAG_LEN)  /* 42 */

#define PKT_KEM_FRAGID   9
#define PKT_KEM_FRAGTOT 10
#define PKT_KEM_DATAOFF 11
#define PKT_KEM_MAXDATA (255 - PKT_KEM_DATAOFF)  /* 244 bytes per fragment */

// ─── Kyber key material (static, never on stack) ────────────────────────────
static uint8_t kyber_pk[KYBER512_PUBLICKEYBYTES];   /* 800 B — share with peers */
static uint8_t kyber_sk[KYBER512_SECRETKEYBYTES];   /* 1632 B — keep secret     */
static bool    kyber_ready        = false;
static bool    pendingHandshake   = false;  /* set after keygen; cleared after TX */
static uint32_t handshakeAfterMs = 0;       /* millis() target for first broadcast */

// ─── KEM fragment reassembly ────────────────────────────────────────────────
static uint8_t kem_rx_buf[KYBER512_PUBLICKEYBYTES];  /* reused for pk and ct */
static uint8_t kem_rx_frag_seen[8];
static uint8_t kem_rx_src        = 0;
static uint8_t kem_rx_pkt_type   = 0;
static uint8_t kem_rx_frag_total = 0;

// ─── Per-peer session keys ──────────────────────────────────────────────────
#define MAX_PEERS 8
struct PeerSession {
    uint8_t id;
    uint8_t key[SESSION_KEY_LEN];
    bool    secure;
    bool    active;
};
static PeerSession sessions[MAX_PEERS];

static uint8_t *getSessionKey(uint8_t nodeId)
{
    for (int i = 0; i < MAX_PEERS; i++)
        if (sessions[i].active && sessions[i].id == nodeId)
            return sessions[i].key;
    /* Fallback: first 16 bytes of the pre-shared NETWORK_KEY */
    return (uint8_t *)NETWORK_KEY;
}

static bool isSecure(uint8_t nodeId)
{
    for (int i = 0; i < MAX_PEERS; i++)
        if (sessions[i].active && sessions[i].id == nodeId)
            return sessions[i].secure;
    return false;
}

static void storeSharedSecret(uint8_t nodeId, const uint8_t ss[KYBER512_SSBYTES])
{
    for (int i = 0; i < MAX_PEERS; i++) {
        if (sessions[i].active && sessions[i].id == nodeId) {
            memcpy(sessions[i].key, ss, SESSION_KEY_LEN);
            sessions[i].secure = true;
            Serial.printf("[KEM] Key updated for node 0x%02X\n", nodeId);
            return;
        }
    }
    for (int i = 0; i < MAX_PEERS; i++) {
        if (!sessions[i].active) {
            sessions[i].id = nodeId; sessions[i].active = true;
            sessions[i].secure = true;
            memcpy(sessions[i].key, ss, SESSION_KEY_LEN);
            Serial.printf("[KEM] New key for node 0x%02X\n", nodeId);
            return;
        }
    }
    Serial.println(F("[KEM] Session table full"));
}

// ─── Anti-replay table ──────────────────────────────────────────────────────
struct PeerState { uint8_t id; uint32_t last_seq; bool active; };
static PeerState peers[MAX_PEERS];

// ─── UI state ───────────────────────────────────────────────────────────────
static TFT_eSPI_Button button[TOTAL_KEYS];
static char     textBuffer[MAX_TEXT] = "";
static uint8_t  textIndex  = 0;
static bool     isNumMode  = false;   /* alpha ↔ number/symbol toggle */
static int16_t  lastRSSI   = 0;
static uint32_t txSeq      = 0;

struct Message { String text; bool isMine; };
static Message messages[MAX_MSGS];
static int     msgCount = 0;

// ─── Keyboard layouts ───────────────────────────────────────────────────────
/*
 * Row 4 (index 26-29): "123" toggles to number mode, "ABC" back to alpha.
 * The [KEY] button is on the keyboard in number mode and also available
 * by typing "KEY" + SEND in the text field.
 * This matches the working reference keyboard sketch exactly.
 */
static char *keysAlpha[] = {
    "Q","W","E","R","T","Y","U","I","O","P",
    "A","S","D","F","G","H","J","K","L",
    "Z","X","C","V","B","N","M",
    "123","SPC","DEL","SEND"
};
static char *keysNum[] = {
    "1","2","3","4","5","6","7","8","9","0",
    "-","/",":",";","(",")","$","&","@",
    ".",",","?","!","'","+","=",
    "KEY","SPC","DEL","SEND"
};

// ─── Forward declarations ───────────────────────────────────────────────────
void    initiateKyberHandshake();
void    handleKemFragment(uint8_t *pkt, int pkt_len);
bool    asconEncrypt(const uint8_t *nonce, const uint8_t *aad, size_t aadLen,
                     const uint8_t *pt, size_t ptLen,
                     uint8_t *ct_with_tag, const uint8_t *key);
bool    asconDecrypt(const uint8_t *nonce, const uint8_t *aad, size_t aadLen,
                     const uint8_t *ct_with_tag, size_t ctLen,
                     uint8_t *pt, const uint8_t *key);
void    sendSecureMessage(const char *msg);
void    handleLoRaPacket();
bool    checkAndUpdateSeq(uint8_t src_id, uint32_t seq);
void    updateStatusBar();
void    drawChatArea();
void    redrawChat();
void    drawTextField();
void    updateTextField();
void    drawKeyboard();
void    handleKey(String key);
void    addMessage(const String &text, bool isMine);
void    touch_calibrate();

// ═══════════════════════════════════════════════════════════════════════════
//  K Y B E R - 5 1 2   K E Y   E X C H A N G E
// ═══════════════════════════════════════════════════════════════════════════

/*
 * Broadcast our Kyber-512 public key (800 bytes) as 4 LoRa fragments.
 *
 * Fragment packet layout:
 *   [0-8]  standard header (network_id, dest, src, type, seq)
 *   [9]    fragment index   (0-based)
 *   [10]   total fragments
 *   [11..] up to 244 bytes of key material
 *
 * LoRa.endPacket(false) = synchronous TX — waits for DIO0 before the next
 * fragment.  This guarantees inter-fragment ordering on the air.
 * A 150 ms gap between fragments prevents the receiver's reassembly buffer
 * from filling while the previous fragment is still being radio-decoded.
 */
void initiateKyberHandshake()
{
    if (!kyber_ready) return;

    addMessage("KEY EXCHANGE...", true);
    Serial.println(F("[KEM] Broadcasting Kyber-512 public key..."));

    size_t  total      = KYBER512_PUBLICKEYBYTES;
    uint8_t frag_total = (uint8_t)((total + PKT_KEM_MAXDATA - 1) / PKT_KEM_MAXDATA);
    uint32_t seq       = txSeq++;

    for (uint8_t fid = 0; fid < frag_total; fid++) {
        uint8_t pkt[255];
        pkt[0] = NETWORK_ID[0];  pkt[1] = NETWORK_ID[1];
        pkt[2] = NETWORK_BCAST;  pkt[3] = (uint8_t)MY_NODE_ID;
        pkt[4] = PKT_KEM_INIT;
        memcpy(&pkt[5], &seq, 4);
        pkt[PKT_KEM_FRAGID]  = fid;
        pkt[PKT_KEM_FRAGTOT] = frag_total;

        size_t off   = (size_t)fid * PKT_KEM_MAXDATA;
        size_t dlen  = ((total - off) > PKT_KEM_MAXDATA)
                       ? PKT_KEM_MAXDATA : (total - off);
        memcpy(&pkt[PKT_KEM_DATAOFF], kyber_pk + off, dlen);

        /* Retry once if radio is busy */
        if (!LoRa.beginPacket()) { delay(50); if (!LoRa.beginPacket()) continue; }
        LoRa.write(pkt, PKT_KEM_DATAOFF + dlen);
        LoRa.endPacket(false);   /* synchronous TX — confirmed before next frag */

        Serial.printf("[KEM] Frag %d/%d sent (%u B)\n", fid+1, frag_total, (unsigned)dlen);
        delay(150);  /* inter-fragment gap — keeps receiver's buffer drain time safe */
    }
    Serial.println(F("[KEM] Broadcast done"));
}

/*
 * Receive and reassemble an incoming KEM fragment.
 *
 * PKT_KEM_INIT — peer's Kyber public key arriving in pieces.
 *   When all fragments arrive we run kyber512_enc() (Encapsulate) to produce
 *   (ciphertext, shared_secret), then unicast the ciphertext back as
 *   PKT_KEM_RESP.  The shared secret's first 16 bytes become the ASCON key.
 *
 * PKT_KEM_RESP — peer's Kyber ciphertext arriving in pieces.
 *   When all fragments arrive we run kyber512_dec() (Decapsulate) with our
 *   secret key to recover the shared secret the peer already has.
 */
void handleKemFragment(uint8_t *pkt, int pkt_len)
{
    if (pkt_len < PKT_KEM_DATAOFF + 1) return;

    uint8_t src        = pkt[3];
    uint8_t pkt_type   = pkt[4];
    uint8_t frag_id    = pkt[PKT_KEM_FRAGID];
    uint8_t frag_total = pkt[PKT_KEM_FRAGTOT];
    size_t  data_len   = (size_t)(pkt_len - PKT_KEM_DATAOFF);

    /* Sanity bounds */
    if (frag_id >= 8 || frag_total == 0 || frag_total > 8) return;
    if (data_len > PKT_KEM_MAXDATA) return;

    /* Reset reassembly buffer if this is a different sender or transaction */
    if (src != kem_rx_src || pkt_type != kem_rx_pkt_type) {
        memset(kem_rx_frag_seen, 0, sizeof(kem_rx_frag_seen));
        memset(kem_rx_buf,       0, sizeof(kem_rx_buf));
        kem_rx_src        = src;
        kem_rx_pkt_type   = pkt_type;
        kem_rx_frag_total = frag_total;
    }

    size_t offset = (size_t)frag_id * PKT_KEM_MAXDATA;
    if (offset + data_len > sizeof(kem_rx_buf)) return;
    memcpy(kem_rx_buf + offset, &pkt[PKT_KEM_DATAOFF], data_len);
    kem_rx_frag_seen[frag_id] = 1;

    /* Count received fragments */
    uint8_t seen = 0;
    for (int i = 0; i < frag_total; i++) seen += kem_rx_frag_seen[i];
    if (seen < frag_total) return;   /* still waiting for more */

    /* ── All fragments received ── */
    Serial.printf("[KEM] All %d frags from node 0x%02X — processing\n", frag_total, src);
    memset(kem_rx_frag_seen, 0, sizeof(kem_rx_frag_seen));

    if (pkt_type == PKT_KEM_INIT) {
        /* Encapsulate: produces (ciphertext, shared_secret) from peer's pk */
        addMessage("Encapsulating...", false);
        static uint8_t ct[KYBER512_CIPHERTEXTBYTES];   /* 768 B — static off stack */
        uint8_t ss[KYBER512_SSBYTES];                   /* 32 B  */
        kyber512_enc(ct, ss, kem_rx_buf);               /* ← post-quantum KEM      */
        storeSharedSecret(src, ss);

        /* Send ciphertext back as PKT_KEM_RESP fragments */
        size_t  ctotal     = KYBER512_CIPHERTEXTBYTES;
        uint8_t ftot       = (uint8_t)((ctotal + PKT_KEM_MAXDATA - 1) / PKT_KEM_MAXDATA);
        uint32_t rseq      = txSeq++;

        for (uint8_t fid = 0; fid < ftot; fid++) {
            uint8_t rpkt[255];
            rpkt[0] = NETWORK_ID[0]; rpkt[1] = NETWORK_ID[1];
            rpkt[2] = src;           /* unicast back to the initiator */
            rpkt[3] = (uint8_t)MY_NODE_ID;
            rpkt[4] = PKT_KEM_RESP;
            memcpy(&rpkt[5], &rseq, 4);
            rpkt[PKT_KEM_FRAGID]  = fid;
            rpkt[PKT_KEM_FRAGTOT] = ftot;

            size_t off  = (size_t)fid * PKT_KEM_MAXDATA;
            size_t dlen = ((ctotal - off) > PKT_KEM_MAXDATA)
                          ? PKT_KEM_MAXDATA : (ctotal - off);
            memcpy(&rpkt[PKT_KEM_DATAOFF], ct + off, dlen);

            if (LoRa.beginPacket()) {
                LoRa.write(rpkt, PKT_KEM_DATAOFF + dlen);
                LoRa.endPacket(false);
            }
            delay(150);
        }
        addMessage("KEM: key shared!", false);
        updateStatusBar();

    } else if (pkt_type == PKT_KEM_RESP) {
        /* Decapsulate: recovers the same shared secret the peer derived */
        if (!kyber_ready) { Serial.println(F("[KEM] No local keys")); return; }
        addMessage("Decapsulating...", false);
        uint8_t ss[KYBER512_SSBYTES];
        kyber512_dec(ss, kem_rx_buf, kyber_sk);   /* ← post-quantum KEM */
        storeSharedSecret(src, ss);
        addMessage("KEM: SECURE!", false);
        Serial.printf("[KEM] Secure session with node 0x%02X\n", src);
        updateStatusBar();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  A S C O N - 1 2 8   W R A P P E R S
// ═══════════════════════════════════════════════════════════════════════════

bool asconEncrypt(const uint8_t *nonce, const uint8_t *aad, size_t aadLen,
                  const uint8_t *pt, size_t ptLen,
                  uint8_t *ct_with_tag, const uint8_t *key)
{
    ascon128_encrypt(ct_with_tag, pt, ptLen, aad, aadLen, nonce, key);
    return true;
}

bool asconDecrypt(const uint8_t *nonce, const uint8_t *aad, size_t aadLen,
                  const uint8_t *ct_with_tag, size_t ctLen,
                  uint8_t *pt, const uint8_t *key)
{
    /* Pass ctLen (plaintext length) + TAG_LEN as total ciphertext length */
    return ascon128_decrypt(pt, ct_with_tag, ctLen + TAG_LEN,
                            aad, aadLen, nonce, key) == 0;
}

// ═══════════════════════════════════════════════════════════════════════════
//  L O R A   P R O T O C O L
// ═══════════════════════════════════════════════════════════════════════════

/*
 * Encrypt with ASCON-128 and transmit a message packet.
 *
 * Packet layout:
 *   [0-8]  header (AAD for ASCON authentication)
 *   [9-24] ASCON nonce (16 B random from TRNG)
 *   [25..] ASCON ciphertext
 *   [last 16] ASCON authentication tag
 *
 * LoRa.endPacket(true) = async TX — returns immediately so the loop is
 * not stalled while the radio transmits.
 */
void sendSecureMessage(const char *msg)
{
    /* "KEY" typed in text field → trigger Kyber key exchange */
    if (strcasecmp(msg, "KEY") == 0) {
        initiateKyberHandshake();
        return;
    }

    addMessage("Me: " + String(msg), true);

    char pt_buf[220];
    int  pt_len = snprintf(pt_buf, sizeof(pt_buf), "%s: %s", MY_NODE_NAME, msg);
    if (pt_len <= 0 || pt_len >= (int)sizeof(pt_buf)) return;

    uint8_t nonce[NONCE_LEN];
    esp_fill_random(nonce, NONCE_LEN);

    uint32_t seq = txSeq++;

    uint8_t pkt[255];
    pkt[0] = NETWORK_ID[0]; pkt[1] = NETWORK_ID[1];
    pkt[2] = NETWORK_BCAST; pkt[3] = (uint8_t)MY_NODE_ID;
    pkt[4] = PKT_MSG;
    memcpy(&pkt[5], &seq, 4);
    memcpy(&pkt[PKT_NONCE_OFF], nonce, NONCE_LEN);

    const uint8_t *key = getSessionKey(NETWORK_BCAST);

    uint8_t ct_tag[220 + TAG_LEN];
    asconEncrypt(nonce, pkt, PKT_AAD_LEN,
                 (uint8_t *)pt_buf, (size_t)pt_len,
                 ct_tag, key);

    memcpy(&pkt[PKT_PAYLOAD_OFF], ct_tag, (size_t)pt_len + TAG_LEN);
    size_t total = (size_t)(PKT_PAYLOAD_OFF + pt_len + TAG_LEN);

    if (!LoRa.beginPacket()) {
        Serial.println(F("[TX] Radio busy — dropped"));
        return;
    }
    LoRa.write(pkt, total);
    LoRa.endPacket(true);   /* async: returns immediately, no SPI poll loop */

    Serial.printf("[TX] seq=%lu len=%u key=%s\n",
                  (unsigned long)seq, (unsigned)total,
                  isSecure(NETWORK_BCAST) ? "KYBER-SS" : "PSK-FALLBACK");
}

/*
 * Poll LoRa for a received packet (called every loop iteration).
 * Non-blocking: returns immediately if nothing is available.
 */
void handleLoRaPacket()
{
    int pkt_len = LoRa.parsePacket();
    if (!pkt_len) return;

    uint8_t pkt[255];
    int rcv = 0;
    while (LoRa.available() && rcv < 255)
        pkt[rcv++] = LoRa.read();

    lastRSSI = LoRa.packetRssi();

    if (rcv < PKT_AAD_LEN + 2) return;

    /* Reject foreign networks */
    if (pkt[0] != NETWORK_ID[0] || pkt[1] != NETWORK_ID[1]) return;

    uint8_t  dest = pkt[2];
    uint8_t  src  = pkt[3];
    uint8_t  type = pkt[4];
    uint32_t seq  = 0;
    memcpy(&seq, &pkt[5], 4);

    if (src  == (uint8_t)MY_NODE_ID) return;   /* echo of own TX */
    if (dest != (uint8_t)NETWORK_BCAST && dest != (uint8_t)MY_NODE_ID) return;

    /* KEM handshake packets — no anti-replay check needed on key material */
    if (type == PKT_KEM_INIT || type == PKT_KEM_RESP) {
        handleKemFragment(pkt, rcv);
        return;
    }

    /* Anti-replay for data packets */
    if (!checkAndUpdateSeq(src, seq)) {
        Serial.printf("[RX] Replay node 0x%02X seq=%lu — dropped\n",
                      src, (unsigned long)seq);
        return;
    }

    if (type == PKT_MSG) {
        if (rcv < PKT_MIN_LEN) return;

        uint8_t *nonce  = &pkt[PKT_NONCE_OFF];
        size_t   ct_len = (size_t)(rcv - PKT_PAYLOAD_OFF - TAG_LEN);
        uint8_t *ct_tag = &pkt[PKT_PAYLOAD_OFF];
        const uint8_t *key = getSessionKey(src);

        uint8_t pt[220];
        memset(pt, 0, sizeof(pt));

        if (asconDecrypt(nonce, pkt, PKT_AAD_LEN, ct_tag, ct_len, pt, key)) {
            pt[ct_len] = '\0';
            Serial.printf("[RX] %s [%s]\n",
                          (char *)pt, isSecure(src) ? "KYBER+ASCON" : "PSK+ASCON");
            addMessage(String((char *)pt), false);
        } else {
            Serial.printf("[CRYPTO] Auth FAIL node 0x%02X\n", src);
            addMessage("[AUTH FAIL 0x" + String(src, HEX) + "]", false);
        }
        updateStatusBar();
    }
}

bool checkAndUpdateSeq(uint8_t src_id, uint32_t seq)
{
    for (int i = 0; i < MAX_PEERS; i++) {
        if (peers[i].active && peers[i].id == src_id) {
            if (seq <= peers[i].last_seq) return false;
            peers[i].last_seq = seq;
            return true;
        }
    }
    for (int i = 0; i < MAX_PEERS; i++) {
        if (!peers[i].active) {
            peers[i].id = src_id; peers[i].last_seq = seq;
            peers[i].active = true; return true;
        }
    }
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
//  U I
// ═══════════════════════════════════════════════════════════════════════════

void updateStatusBar()
{
    tft.fillRect(0, 0, SCREEN_W, STATUS_H - 1, tft.color565(8, 12, 35));
    tft.drawFastHLine(0, STATUS_H - 1, SCREEN_W, tft.color565(35, 55, 140));
    tft.setTextSize(1);

    tft.setTextColor(tft.color565(90, 190, 255));
    tft.setCursor(3, 4);
    tft.print(MY_NODE_NAME); tft.print(" #");
    char ids[4]; snprintf(ids, 4, "%02X", MY_NODE_ID); tft.print(ids);

    tft.setTextColor(tft.color565(60, 230, 90));
    tft.setCursor(74, 4);
    tft.print("[KYBER+ASCON]");

    tft.setTextColor(tft.color565(90, 90, 130));
    tft.setCursor(202, 4);
    tft.print("S:"); tft.print(txSeq);

    if (lastRSSI != 0) {
        tft.setTextColor((lastRSSI > -100) ? tft.color565(80, 255, 80)
                                            : tft.color565(255, 150, 50));
        tft.setCursor(260, 4);
        tft.print(lastRSSI); tft.print("d");
    }
}

void drawChatArea()
{
    tft.fillRect(0, CHAT_Y, SCREEN_W, CHAT_BOT - CHAT_Y + 1,
                 tft.color565(12, 12, 22));
    tft.drawFastHLine(0, CHAT_BOT + 1, SCREEN_W, TFT_DARKGREY);
}

void redrawChat()
{
    tft.fillRect(0, CHAT_Y, SCREEN_W, CHAT_BOT - CHAT_Y + 1,
                 tft.color565(12, 12, 22));
    tft.setTextSize(1);
    int y = CHAT_Y + 2;
    for (int i = 0; i < msgCount; i++) {
        String txt  = messages[i].text;
        bool   mine = messages[i].isMine;
        int maxCh = (SCREEN_W - 20) / 6;
        if ((int)txt.length() > maxCh) txt = txt.substring(0, maxCh - 2) + "..";
        int bW = txt.length() * 6 + 12;
        int bX = mine ? (SCREEN_W - bW - 3) : 3;
        uint16_t bg = mine ? tft.color565(0, 65, 120) : tft.color565(32, 32, 50);
        tft.fillRoundRect(bX, y, bW, MSG_H - 2, 4, bg);
        if (!mine) {
            tft.setTextColor(tft.color565(70, 220, 70));
            tft.setCursor(bX + 2, y + 2); tft.print("*");
            tft.setTextColor(TFT_WHITE);  tft.setCursor(bX + 10, y + 6);
        } else {
            tft.setTextColor(TFT_WHITE);  tft.setCursor(bX + 5, y + 6);
        }
        tft.print(txt);
        y += MSG_H;
    }
}

void drawTextField()
{
    tft.drawRoundRect(TEXT_X, TEXT_Y, TEXT_W, TEXT_H, 4, TFT_WHITE);
    updateTextField();
}

void updateTextField()
{
    tft.fillRoundRect(TEXT_X + 2, TEXT_Y + 2, TEXT_W - 4, TEXT_H - 4, 3, TFT_BLACK);
    tft.setTextColor(TFT_CYAN);
    tft.setTextSize(2);
    int maxCh = (TEXT_W - 16) / 12;
    int start = (textIndex > maxCh) ? (textIndex - maxCh) : 0;
    tft.setCursor(TEXT_X + 8, TEXT_Y + 6);
    tft.print(&textBuffer[start]);
}

void drawKeyboard()
{
    /* Clear only the keyboard area — prevents full-screen flicker */
    tft.fillRect(0, KB_ROW1 - KEY_H/2 - 2, SCREEN_W,
                 SCREEN_H - (KB_ROW1 - KEY_H/2 - 2),
                 tft.color565(20, 20, 25));

    char **layout = isNumMode ? keysNum : keysAlpha;
    int index = 0;

    /* Row 1 — 10 keys */
    int r1W = 10 * KEY_W + 9 * KEY_SPACING;
    int ox  = (SCREEN_W - r1W) / 2;
    for (int i = 0; i < 10; i++) {
        button[index].initButton(&tft,
            ox + i * (KEY_W + KEY_SPACING) + KEY_W / 2, KB_ROW1,
            KEY_W, KEY_H, TFT_DARKGREY, TFT_DARKCYAN, TFT_WHITE,
            layout[index], 1);
        button[index++].drawButton();
    }

    /* Row 2 — 9 keys */
    int r2W = 9 * KEY_W + 8 * KEY_SPACING;
    ox = (SCREEN_W - r2W) / 2;
    for (int i = 0; i < 9; i++) {
        button[index].initButton(&tft,
            ox + i * (KEY_W + KEY_SPACING) + KEY_W / 2, KB_ROW2,
            KEY_W, KEY_H, TFT_DARKGREY, TFT_DARKCYAN, TFT_WHITE,
            layout[index], 1);
        button[index++].drawButton();
    }

    /* Row 3 — 7 keys */
    int r3W = 7 * KEY_W + 6 * KEY_SPACING;
    ox = (SCREEN_W - r3W) / 2;
    for (int i = 0; i < 7; i++) {
        button[index].initButton(&tft,
            ox + i * (KEY_W + KEY_SPACING) + KEY_W / 2, KB_ROW3,
            KEY_W, KEY_H, TFT_DARKGREY, TFT_DARKCYAN, TFT_WHITE,
            layout[index], 1);
        button[index++].drawButton();
    }

    /*
     * Row 4 — special keys.
     * Width / colour matches the working reference keyboard sketch:
     *   "123"/"KEY"  50 px  navy
     *   "SPC"        80 px  green
     *   "DEL"        50 px  red
     *   "SEND"       60 px  navy
     */
    int bW[]  = { 50, 80, 50, 60 };
    int totW  = 50 + 80 + 50 + 60 + 3 * KEY_SPACING;
    int cx    = (SCREEN_W - totW) / 2;
    for (int i = 0; i < 4; i++) {
        uint16_t col =
            (i == 1) ? tft.color565(40, 150, 40)   /* SPC  — green */
          : (i == 2) ? tft.color565(200, 40, 40)   /* DEL  — red   */
          : TFT_NAVY;                               /* 123/KEY, SEND */
        button[index].initButton(&tft,
            cx + bW[i] / 2, KB_ROW4, bW[i], KEY_H,
            TFT_DARKGREY, col, TFT_WHITE, layout[index], 1);
        button[index++].drawButton();
        cx += bW[i] + KEY_SPACING;
    }
}

/*
 * Key press handler.
 * "123" / "ABC" toggle alpha ↔ number keyboard.
 * "KEY" (number layout, index 26) triggers Kyber key exchange.
 * Typing "KEY" + SEND in the text field also triggers key exchange.
 */
void handleKey(String key)
{
    if (key == "123" || key == "ABC") {
        /* Toggle keyboard mode and redraw */
        isNumMode = !isNumMode;
        drawKeyboard();
    }
    else if (key == "KEY") {
        /* Kyber-512 key exchange — runs synchronously but is quick to start */
        initiateKyberHandshake();
    }
    else if (key == "DEL") {
        if (textIndex > 0) textBuffer[--textIndex] = '\0';
        updateTextField();
    }
    else if (key == "SEND") {
        if (textIndex == 0) return;
        sendSecureMessage(textBuffer);
        /* Fully wipe buffer to prevent ghost characters on next send */
        memset(textBuffer, 0, sizeof(textBuffer));
        textIndex = 0;
        updateTextField();
        updateStatusBar();
    }
    else if (key == "SPC") {
        if (textIndex < MAX_TEXT - 1) {
            textBuffer[textIndex++] = ' ';
            textBuffer[textIndex]   = '\0';
        }
        updateTextField();
    }
    else {
        if (textIndex < MAX_TEXT - 1) {
            textBuffer[textIndex++] = key[0];
            textBuffer[textIndex]   = '\0';
        }
        updateTextField();
    }
}

void addMessage(const String &text, bool isMine)
{
    if (msgCount < MAX_MSGS) {
        messages[msgCount].text   = text;
        messages[msgCount].isMine = isMine;
        msgCount++;
    } else {
        for (int i = 0; i < MAX_MSGS - 1; i++) messages[i] = messages[i + 1];
        messages[MAX_MSGS - 1].text   = text;
        messages[MAX_MSGS - 1].isMine = isMine;
    }
    redrawChat();
}

/*
 * Touch calibration — matches the working reference sketch exactly.
 * Uses SPIFFS.begin() without auto-format flag; manually formats on failure.
 * Calibration data (10 bytes) is persisted in SPIFFS so the sequence
 * only runs once and never again until flash is erased.
 */
void touch_calibrate()
{
    uint16_t calData[5];

    /* Match the working sketch: begin without auto-format, format manually */
    if (!SPIFFS.begin()) {
        SPIFFS.format();
        SPIFFS.begin();
    }

    if (SPIFFS.exists(CALIBRATION_FILE)) {
        File f = SPIFFS.open(CALIBRATION_FILE, "r");
        if (f) { f.readBytes((char *)calData, 14); f.close(); }
        tft.setTouch(calData);
    } else {
        tft.fillScreen(TFT_BLACK);
        tft.setTextColor(TFT_WHITE); tft.setTextSize(2);
        tft.setCursor(20, 100);
        tft.println("Touch corners to calibrate");
        tft.calibrateTouch(calData, TFT_MAGENTA, TFT_BLACK, 15);
        File f = SPIFFS.open(CALIBRATION_FILE, "w");
        if (f) { f.write((const unsigned char *)calData, 14); f.close(); }
        Serial.println(F("[SPIFFS] Calibration saved"));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  S E T U P
// ═══════════════════════════════════════════════════════════════════════════
void setup()
{
    Serial.begin(115200);
    delay(300);
    Serial.println(F("\n[BOOT] Quantum-Secure LoRa Messenger v3.0"));
    Serial.printf("[BOOT] Node: %s  ID=0x%02X\n", MY_NODE_NAME, MY_NODE_ID);
    Serial.printf("[BOOT] Network: %s  Freq: %.0f Hz\n",
                  NETWORK_NAME, (double)NETWORK_FREQ);
    Serial.println(F("[BOOT] Crypto: Kyber-512 KEM + ASCON-128 AEAD"));

    memset(peers,            0, sizeof(peers));
    memset(sessions,         0, sizeof(sessions));
    memset(kem_rx_frag_seen, 0, sizeof(kem_rx_frag_seen));

    // ── LoRa ────────────────────────────────────────────────────────
    SPI.begin(18, 19, 23, 27);
    pinMode(LORA_SS,  OUTPUT); digitalWrite(LORA_SS,  HIGH);
    pinMode(LORA_RST, OUTPUT);
    digitalWrite(LORA_RST, LOW);  delay(10);
    digitalWrite(LORA_RST, HIGH); delay(10);

    LoRa.setPins(LORA_SS, LORA_RST, LORA_DIO0);
    LoRa.setSPIFrequency(125000);

    Serial.print(F("[LORA] Init... "));
    if (!LoRa.begin(NETWORK_FREQ)) {
        Serial.println(F("FAILED — check wiring"));
    } else {
        LoRa.setSpreadingFactor(7);
        LoRa.setSignalBandwidth(500E3);
        LoRa.setCodingRate4(5);
        LoRa.setTxPower(14);
        Serial.println(F("OK"));
    }

    // ── TFT ─────────────────────────────────────────────────────────
    tft.init();
    tft.setRotation(1);
    tft.setTextWrap(false);   /* never let text overflow into the keyboard area */
    touch_calibrate();

    tft.fillScreen(tft.color565(20, 20, 25));
    updateStatusBar();
    drawChatArea();
    drawTextField();
    drawKeyboard();
    Serial.println(F("[TFT] OK"));

    // ── Kyber-512 key generation ─────────────────────────────────────
    /*
     * Generate an ephemeral Kyber-512 keypair from the ESP32 hardware TRNG.
     * This is done AFTER the TFT is fully drawn so the screen is never blank.
     *
     * The broadcast of the public key is deferred to loop() via the
     * pendingHandshake flag so setup() returns immediately and the touch
     * input is already live by the time the radio starts transmitting.
     */
    Serial.println(F("[KEM] Generating Kyber-512 keypair..."));
    addMessage("Generating keys...", false);

    kyber512_keypair(kyber_pk, kyber_sk);
    kyber_ready = true;

    Serial.printf("[KEM] PK[0..7]: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                  kyber_pk[0], kyber_pk[1], kyber_pk[2], kyber_pk[3],
                  kyber_pk[4], kyber_pk[5], kyber_pk[6], kyber_pk[7]);

    addMessage("Kyber-512 ready!", false);

    /*
     * Schedule the first key exchange broadcast for 2 seconds after boot.
     * Running it inside loop() keeps setup() short and the UI responsive.
     */
    pendingHandshake  = true;
    handshakeAfterMs  = millis() + 2000;

    Serial.println(F("[BOOT] Ready. Key exchange in 2 s. Press [KEY] to re-exchange."));
}

// ═══════════════════════════════════════════════════════════════════════════
//  L O O P
// ═══════════════════════════════════════════════════════════════════════════
void loop()
{
    /* ── Deferred first key exchange ──
     * setup() set pendingHandshake after keygen.  We wait here in loop()
     * so setup() returns quickly and the screen is fully interactive.
     * The 2-second delay lets any peer finish booting and start listening.
     */
    if (pendingHandshake && millis() >= handshakeAfterMs) {
        pendingHandshake = false;
        initiateKyberHandshake();
    }

    /* ── Receive ── */
    handleLoRaPacket();

    /* ── Touch ──
     * Exact button-press detection pattern from the working reference sketch.
     * Two separate loops: first update all button states, then process events.
     * This prevents ghost presses when one button overlaps another.
     */
    uint16_t x, y;
    bool pressed = tft.getTouch(&x, &y);

    for (int i = 0; i < TOTAL_KEYS; i++) {
        if (pressed && button[i].contains(x, y)) button[i].press(true);
        else                                      button[i].press(false);
    }

    for (int i = 0; i < TOTAL_KEYS; i++) {
        if (button[i].justReleased()) {
            button[i].drawButton();   /* restore un-pressed appearance */
        }
        if (button[i].justPressed()) {
            button[i].drawButton(true);   /* show pressed (inverted) state */
            String val = isNumMode ? keysNum[i] : keysAlpha[i];
            handleKey(val);
            delay(100);   /* debounce — 100 ms matches working reference sketch */
        }
    }
}
