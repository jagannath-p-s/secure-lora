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
 *    • Kyber-512 (ML-KEM-512)  — NIST FIPS 203
 *      - Lattice-based Key Encapsulation Mechanism (KEM)
 *      - Resistant to Shor's algorithm (no discrete log / factoring)
 *      - Outputs a 32-byte shared secret per session
 *
 *  MESSAGE ENCRYPTION (per-message):
 *    • ASCON-128  — NIST Lightweight Crypto Standard (2023)
 *      - Authenticated Encryption with Associated Data (AEAD)
 *      - 128-bit key (first 16 bytes of Kyber shared secret)
 *      - 128-bit nonce  (random, from ESP32 hardware TRNG)
 *      - 128-bit authentication tag  (tamper detection)
 *
 *  Key Exchange Flow
 *  ─────────────────
 *  1. At boot each node broadcasts PKT_KEM_INIT carrying its
 *     Kyber-512 public key (800 bytes, split into 4 fragments).
 *  2. Any peer receiving PKT_KEM_INIT runs Kyber Encapsulate:
 *       (ciphertext, shared_secret) = kyber512_enc(peer_pk)
 *     Then sends PKT_KEM_RESP with the ciphertext (768 bytes).
 *  3. The initiator receives PKT_KEM_RESP and runs Decapsulate:
 *       shared_secret = kyber512_dec(ciphertext, my_sk)
 *     Both sides now hold the same 32-byte shared secret.
 *  4. The first 16 bytes of shared_secret become the ASCON-128
 *     session key for that peer.
 *  5. Type "KEY" + SEND at any time to re-initiate key exchange.
 *
 *  Packet Layout (binary, max 255 bytes)
 *  ──────────────────────────────────────
 *  [0-1]   NETWORK_ID[2]   ← AAD (authenticated, not encrypted)
 *  [2]     dest_id          ← AAD
 *  [3]     src_id           ← AAD
 *  [4]     pkt_type         ← AAD
 *  [5-8]   seq_num u32 LE   ← AAD
 *
 *  For PKT_MSG (type 0x01):
 *  [9-24]  nonce (16 B ASCON)
 *  [25..]  ciphertext (ASCON)
 *  [last 16] ASCON auth tag
 *
 *  For PKT_KEM_INIT (0x03) / PKT_KEM_RESP (0x04):
 *  [9]     frag_id        (0-based fragment index)
 *  [10]    frag_total     (total fragments for this key)
 *  [11..]  fragment data  (up to 244 bytes)
 *
 *  Required Libraries (Arduino Library Manager)
 *  ─────────────────────────────────────────────
 *  • LoRa      by Sandeep Mistry
 *  • TFT_eSPI  by Bodmer
 *  mbedTLS is bundled with ESP32 Arduino SDK (unused here;
 *  we use our own Keccak+Kyber+ASCON implementations).
 * ============================================================
 */

#include <FS.h>
#include <SPIFFS.h>
#include <SPI.h>
#include <TFT_eSPI.h>
#include <LoRa.h>
#include "esp_system.h"

/* Post-quantum crypto stack (order matters: keccak first) */
#include "keccak_tiny.h"   /* SHA3-256, SHA3-512, SHAKE128, SHAKE256 */
#include "kyber512.h"       /* Kyber-512 KEM (uses keccak_tiny.h)     */
#include "ascon128.h"       /* ASCON-128 AEAD                          */

#include "network_keys.h"   /* NETWORK_ID, NETWORK_KEY, node config    */

// ─── Hardware pins ───────────────────────────────────────────────
#define LORA_SS   27
#define LORA_RST  25
#define LORA_DIO0 26

// ─── Screen ──────────────────────────────────────────────────────
TFT_eSPI tft = TFT_eSPI();
#define SCREEN_W  320
#define SCREEN_H  240

// ─── Layout constants ────────────────────────────────────────────
#define STATUS_H      16
#define CHAT_Y        17
#define CHAT_BOT      95
#define MAX_MSGS       3
#define MSG_H         26
#define TEXT_X         4
#define TEXT_Y        99
#define TEXT_W       312
#define TEXT_H        23
#define MAX_TEXT     100
#define KEY_W         28
#define KEY_H         24
#define KEY_SPACING    2
#define TOTAL_KEYS    30
#define KB_ROW1      140
#define KB_ROW2      166
#define KB_ROW3      192
#define KB_ROW4      218
#define CALIBRATION_FILE "/TouchCalDat"

// ─── Crypto constants (ASCON-128) ────────────────────────────────
#define NONCE_LEN    ASCON_NONCE_LEN   /* 16 bytes */
#define TAG_LEN      ASCON_TAG_LEN     /* 16 bytes */
#define SESSION_KEY_LEN  ASCON_KEY_LEN /* 16 bytes (first 16 of KEM SS) */

// ─── Packet types ────────────────────────────────────────────────
#define PKT_MSG       0x01   /* Encrypted chat message        */
#define PKT_PING      0x02   /* Keepalive / presence          */
#define PKT_KEM_INIT  0x03   /* Kyber public key (fragmented) */
#define PKT_KEM_RESP  0x04   /* Kyber ciphertext (fragmented) */

// ─── Packet byte offsets ─────────────────────────────────────────
#define PKT_AAD_LEN      9   /* bytes 0-8 = additional authenticated data */
#define PKT_NONCE_OFF    9   /* bytes 9-24 = ASCON nonce (MSG packets) */
#define PKT_PAYLOAD_OFF 25   /* byte 25+ = ASCON ciphertext + tag */
#define PKT_MIN_LEN     (PKT_PAYLOAD_OFF + 1 + TAG_LEN)  /* 42 bytes */

/* KEM fragment packet offsets */
#define PKT_KEM_FRAGID   9   /* byte 9  = fragment index (0-based) */
#define PKT_KEM_FRAGTOT 10   /* byte 10 = total fragments */
#define PKT_KEM_DATAOFF 11   /* byte 11+ = fragment payload */
#define PKT_KEM_MAXDATA (255 - PKT_KEM_DATAOFF)  /* 244 bytes per fragment */

// ─── Kyber-512 key material ──────────────────────────────────────
/* Own long-term Kyber key pair (generated at boot, ephemeral) */
static uint8_t kyber_pk[KYBER512_PUBLICKEYBYTES];   /* 800 bytes - share with peers   */
static uint8_t kyber_sk[KYBER512_SECRETKEYBYTES];   /* 1632 bytes - keep secret        */
static bool    kyber_ready = false;                  /* true after keypair generated    */

/* Reassembly buffer for incoming KEM fragments (max 800 bytes for pk) */
static uint8_t  kem_rx_buf[KYBER512_PUBLICKEYBYTES]; /* reused for both pk and ct       */
static uint8_t  kem_rx_frag_seen[8];                 /* bitmask of received fragment IDs*/
static uint8_t  kem_rx_src        = 0;               /* sender node ID of incoming key  */
static uint8_t  kem_rx_pkt_type   = 0;               /* KEM_INIT or KEM_RESP            */
static uint8_t  kem_rx_frag_total = 0;               /* expected total fragments        */

// ─── Per-peer session keys (Kyber-derived) ───────────────────────
#define MAX_PEERS  8
struct PeerSession {
    uint8_t id;
    uint8_t key[SESSION_KEY_LEN];  /* ASCON-128 session key (16 bytes of Kyber SS) */
    bool    secure;                /* true = Kyber KEM completed for this peer */
    bool    active;
};
static PeerSession sessions[MAX_PEERS];

/* Look up session key for a peer, fall back to NETWORK_KEY if no KEM done */
static uint8_t *getSessionKey(uint8_t nodeId)
{
    for (int i = 0; i < MAX_PEERS; i++) {
        if (sessions[i].active && sessions[i].id == nodeId)
            return sessions[i].key;
    }
    /* No KEM session: use first 16 bytes of the pre-shared NETWORK_KEY */
    return (uint8_t *)NETWORK_KEY;
}

static bool isSecure(uint8_t nodeId)
{
    for (int i = 0; i < MAX_PEERS; i++)
        if (sessions[i].active && sessions[i].id == nodeId)
            return sessions[i].secure;
    return false;
}

/* Store (or update) the 32-byte Kyber shared secret for a peer.
 * First 16 bytes → ASCON session key. */
static void storeSharedSecret(uint8_t nodeId, const uint8_t ss[KYBER512_SSBYTES])
{
    /* Update existing */
    for (int i = 0; i < MAX_PEERS; i++) {
        if (sessions[i].active && sessions[i].id == nodeId) {
            memcpy(sessions[i].key, ss, SESSION_KEY_LEN);
            sessions[i].secure = true;
            Serial.printf("[KEM] Updated session key for node 0x%02X\n", nodeId);
            return;
        }
    }
    /* Insert new */
    for (int i = 0; i < MAX_PEERS; i++) {
        if (!sessions[i].active) {
            sessions[i].id     = nodeId;
            sessions[i].active = true;
            sessions[i].secure = true;
            memcpy(sessions[i].key, ss, SESSION_KEY_LEN);
            Serial.printf("[KEM] New session key installed for node 0x%02X\n", nodeId);
            return;
        }
    }
    Serial.println(F("[KEM] Session table full — key not stored"));
}

// ─── Anti-replay state ───────────────────────────────────────────
struct PeerState { uint8_t id; uint32_t last_seq; bool active; };
static PeerState peers[MAX_PEERS];

// ─── UI state ────────────────────────────────────────────────────
static TFT_eSPI_Button button[TOTAL_KEYS];
static char     textBuffer[MAX_TEXT] = "";
static uint8_t  textIndex  = 0;
static bool     isNumMode  = false;
static int16_t  lastRSSI   = 0;
static uint32_t txSeq      = 0;
static bool     kemActive  = false;  /* true while sending KEM_INIT */

struct Message { String text; bool isMine; };
static Message  messages[MAX_MSGS];
static int      msgCount = 0;

// ─── Keyboard layouts ────────────────────────────────────────────
static char *keysAlpha[] = {
  "Q","W","E","R","T","Y","U","I","O","P",
  "A","S","D","F","G","H","J","K","L",
  "Z","X","C","V","B","N","M",
  "KEY","SPC","DEL","SEND"
};
static char *keysNum[] = {
  "1","2","3","4","5","6","7","8","9","0",
  "-","/",":",";","(",")","$","&","@",
  ".",",","?","!","'","+","=",
  "KEY","SPC","DEL","SEND"
};

// ─── Forward declarations ────────────────────────────────────────
void    initiateKyberHandshake();
void    handleKemFragment(uint8_t *pkt, int pkt_len);
bool    asconEncrypt(const uint8_t *nonce, const uint8_t *aad, size_t aadLen,
                     const uint8_t *pt, size_t ptLen, uint8_t *ct_with_tag,
                     const uint8_t *key);
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

// ═══════════════════════════════════════════════════════════════
//  K Y B E R   K E Y   E X C H A N G E
// ═══════════════════════════════════════════════════════════════

/*
 * Send the local Kyber-512 public key to all peers (broadcast).
 * The 800-byte public key is split into ceil(800/244) = 4 fragments,
 * each sent as a separate PKT_KEM_INIT LoRa packet.
 *
 * Fragment packet structure (11 + data bytes):
 *   [0-8]  standard header (NETWORK_ID, dest, src, type, seq)
 *   [9]    fragment index (0-based)
 *   [10]   total fragments
 *   [11..] up to 244 bytes of key data
 */
void initiateKyberHandshake()
{
    if (!kyber_ready) {
        Serial.println(F("[KEM] Keys not ready"));
        return;
    }

    addMessage("KEY EXCHANGE...", true);
    Serial.println(F("[KEM] Broadcasting Kyber-512 public key..."));

    const uint8_t *data  = kyber_pk;
    size_t total_len     = KYBER512_PUBLICKEYBYTES;   /* 800 bytes */
    uint8_t frag_total   = (uint8_t)((total_len + PKT_KEM_MAXDATA - 1) / PKT_KEM_MAXDATA);
    uint32_t seq         = txSeq++;

    for (uint8_t frag_id = 0; frag_id < frag_total; frag_id++) {
        uint8_t pkt[255];

        /* Standard 9-byte header */
        pkt[0] = NETWORK_ID[0];
        pkt[1] = NETWORK_ID[1];
        pkt[2] = NETWORK_BCAST;
        pkt[3] = (uint8_t)MY_NODE_ID;
        pkt[4] = PKT_KEM_INIT;
        memcpy(&pkt[5], &seq, 4);

        /* Fragment header */
        pkt[PKT_KEM_FRAGID]  = frag_id;
        pkt[PKT_KEM_FRAGTOT] = frag_total;

        /* Fragment data */
        size_t offset   = (size_t)frag_id * PKT_KEM_MAXDATA;
        size_t remaining = total_len - offset;
        size_t data_len  = (remaining > PKT_KEM_MAXDATA) ? PKT_KEM_MAXDATA : remaining;
        memcpy(&pkt[PKT_KEM_DATAOFF], data + offset, data_len);

        size_t pkt_len = PKT_KEM_DATAOFF + data_len;

        if (!LoRa.beginPacket()) {
            Serial.printf("[KEM] TX frag %d: beginPacket failed\n", frag_id);
            delay(50);
            if (!LoRa.beginPacket()) continue;
        }
        LoRa.write(pkt, pkt_len);
        LoRa.endPacket(false);   /* synchronous: wait for TX done between fragments */

        Serial.printf("[KEM] Sent frag %d/%d  (%u bytes)\n",
                      frag_id + 1, frag_total, (unsigned)data_len);
        delay(120);   /* inter-fragment gap to avoid radio collision */
    }
    Serial.println(F("[KEM] Public key broadcast complete"));
}

/*
 * Handle an incoming KEM fragment (PKT_KEM_INIT or PKT_KEM_RESP).
 * Fragments are accumulated in kem_rx_buf using a bitmask.
 * Once all fragments are received, the full key material is processed:
 *   - PKT_KEM_INIT: run kyber512_enc() → send PKT_KEM_RESP
 *   - PKT_KEM_RESP: run kyber512_dec() → store session key
 */
void handleKemFragment(uint8_t *pkt, int pkt_len)
{
    if (pkt_len < PKT_KEM_DATAOFF + 1) return;

    uint8_t src        = pkt[3];
    uint8_t pkt_type   = pkt[4];
    uint8_t frag_id    = pkt[PKT_KEM_FRAGID];
    uint8_t frag_total = pkt[PKT_KEM_FRAGTOT];
    size_t  data_len   = (size_t)(pkt_len - PKT_KEM_DATAOFF);

    /* Validate fragment indices */
    if (frag_id >= 8 || frag_total == 0 || frag_total > 8) return;
    if (data_len > PKT_KEM_MAXDATA) return;

    /* Reset buffer if this is a new KEM transaction (different src or type) */
    if (src != kem_rx_src || pkt_type != kem_rx_pkt_type) {
        memset(kem_rx_frag_seen, 0, sizeof(kem_rx_frag_seen));
        memset(kem_rx_buf, 0, sizeof(kem_rx_buf));
        kem_rx_src        = src;
        kem_rx_pkt_type   = pkt_type;
        kem_rx_frag_total = frag_total;
    }

    /* Write fragment into reassembly buffer */
    size_t offset = (size_t)frag_id * PKT_KEM_MAXDATA;
    /* Bounds check against the largest possible payload */
    if (offset + data_len > sizeof(kem_rx_buf)) return;
    memcpy(kem_rx_buf + offset, &pkt[PKT_KEM_DATAOFF], data_len);
    kem_rx_frag_seen[frag_id] = 1;

    /* Check if all fragments have arrived */
    uint8_t seen = 0;
    for (int i = 0; i < frag_total; i++) seen += kem_rx_frag_seen[i];
    if (seen < frag_total) return;   /* still waiting */

    /* ─── All fragments received ─── */
    Serial.printf("[KEM] All %d fragments received from node 0x%02X\n", frag_total, src);
    memset(kem_rx_frag_seen, 0, sizeof(kem_rx_frag_seen));

    if (pkt_type == PKT_KEM_INIT) {
        /* ── Received a peer's Kyber public key ──
         * Run Encapsulate to produce (ciphertext, shared_secret).
         * Store the shared secret as our session key for this peer.
         * Send the ciphertext back as PKT_KEM_RESP fragments.
         */
        addMessage("KEM: got pk, encap...", false);

        uint8_t ct[KYBER512_CIPHERTEXTBYTES];   /* 768 bytes */
        uint8_t ss[KYBER512_SSBYTES];           /* 32 bytes  */
        kyber512_enc(ct, ss, kem_rx_buf);        /* encapsulate */
        storeSharedSecret(src, ss);             /* save session key */

        Serial.printf("[KEM] Encapsulated. Sending response to node 0x%02X\n", src);

        /* Send ciphertext back in PKT_KEM_RESP fragments */
        uint8_t frag_tot_resp = (uint8_t)((KYBER512_CIPHERTEXTBYTES + PKT_KEM_MAXDATA - 1)
                                           / PKT_KEM_MAXDATA);
        uint32_t seq = txSeq++;

        for (uint8_t fid = 0; fid < frag_tot_resp; fid++) {
            uint8_t rpkt[255];
            rpkt[0] = NETWORK_ID[0];  rpkt[1] = NETWORK_ID[1];
            rpkt[2] = src;            /* unicast back to initiator */
            rpkt[3] = (uint8_t)MY_NODE_ID;
            rpkt[4] = PKT_KEM_RESP;
            memcpy(&rpkt[5], &seq, 4);
            rpkt[PKT_KEM_FRAGID]  = fid;
            rpkt[PKT_KEM_FRAGTOT] = frag_tot_resp;

            size_t off  = (size_t)fid * PKT_KEM_MAXDATA;
            size_t rem  = (size_t)KYBER512_CIPHERTEXTBYTES - off;
            size_t dlen = (rem > PKT_KEM_MAXDATA) ? PKT_KEM_MAXDATA : rem;
            memcpy(&rpkt[PKT_KEM_DATAOFF], ct + off, dlen);

            if (LoRa.beginPacket()) {
                LoRa.write(rpkt, PKT_KEM_DATAOFF + dlen);
                LoRa.endPacket(false);
            }
            Serial.printf("[KEM] Sent resp frag %d/%d\n", fid + 1, frag_tot_resp);
            delay(120);
        }

        addMessage("KEM: key shared!", false);
        updateStatusBar();

    } else if (pkt_type == PKT_KEM_RESP) {
        /* ── Received a peer's Kyber ciphertext ──
         * Run Decapsulate to recover the shared secret.
         * Must match the shared secret the peer derived.
         */
        if (!kyber_ready) {
            Serial.println(F("[KEM] Cannot decaps: no local keys"));
            return;
        }

        addMessage("KEM: decap...", false);
        uint8_t ss[KYBER512_SSBYTES];
        kyber512_dec(ss, kem_rx_buf, kyber_sk);   /* decapsulate */
        storeSharedSecret(src, ss);

        addMessage("KEM: SECURE!", false);
        Serial.printf("[KEM] Decapsulated. Secure session with node 0x%02X\n", src);
        updateStatusBar();
    }
}

// ═══════════════════════════════════════════════════════════════
//  A S C O N - 1 2 8   W R A P P E R S
// ═══════════════════════════════════════════════════════════════

/*
 * ASCON-128 encryption wrapper.
 * Writes ptLen bytes of ciphertext followed by 16-byte tag into ct_with_tag.
 * ct_with_tag must be at least (ptLen + TAG_LEN) bytes.
 */
bool asconEncrypt(const uint8_t *nonce, const uint8_t *aad, size_t aadLen,
                  const uint8_t *pt, size_t ptLen,
                  uint8_t *ct_with_tag, const uint8_t *key)
{
    ascon128_encrypt(ct_with_tag, pt, ptLen, aad, aadLen, nonce, key);
    return true;
}

/*
 * ASCON-128 decryption wrapper.
 * ct_with_tag contains ctLen bytes of ciphertext followed by 16-byte tag.
 * Returns true on success (tag verified), false on authentication failure.
 */
bool asconDecrypt(const uint8_t *nonce, const uint8_t *aad, size_t aadLen,
                  const uint8_t *ct_with_tag, size_t ctLen,
                  uint8_t *pt, const uint8_t *key)
{
    return ascon128_decrypt(pt, ct_with_tag, ctLen + TAG_LEN,
                            aad, aadLen, nonce, key) == 0;
}

// ═══════════════════════════════════════════════════════════════
//  L O R A   P R O T O C O L
// ═══════════════════════════════════════════════════════════════

/*
 * Build, encrypt with ASCON-128, and transmit a message packet.
 * If the user typed "KEY", trigger the Kyber key exchange instead.
 *
 * MSG packet layout:
 *   [0-8]   header (AAD for ASCON: NETWORK_ID, dest, src, type, seq)
 *   [9-24]  ASCON nonce (16 bytes, random from TRNG)
 *   [25..]  ASCON ciphertext  (same length as plaintext)
 *   [last 16] ASCON authentication tag
 */
void sendSecureMessage(const char *msg)
{
    /* Special command: "KEY" re-initiates Kyber key exchange */
    if (strcasecmp(msg, "KEY") == 0) {
        initiateKyberHandshake();
        return;
    }

    /* Show in UI immediately (optimistic rendering) */
    addMessage("Me: " + String(msg), true);

    /* Build plaintext: "NODE_NAME: message" */
    char pt_buf[220];
    int pt_len = snprintf(pt_buf, sizeof(pt_buf), "%s: %s", MY_NODE_NAME, msg);
    if (pt_len <= 0 || pt_len >= (int)sizeof(pt_buf)) return;

    /* 16-byte random nonce from ESP32 hardware TRNG */
    uint8_t nonce[NONCE_LEN];
    esp_fill_random(nonce, NONCE_LEN);

    uint32_t seq = txSeq++;

    /* Assemble packet header (bytes 0-8 = AAD for ASCON) */
    uint8_t pkt[255];
    pkt[0] = NETWORK_ID[0];
    pkt[1] = NETWORK_ID[1];
    pkt[2] = NETWORK_BCAST;
    pkt[3] = (uint8_t)MY_NODE_ID;
    pkt[4] = PKT_MSG;
    memcpy(&pkt[5], &seq, 4);

    /* Embed nonce after header */
    memcpy(&pkt[PKT_NONCE_OFF], nonce, NONCE_LEN);

    /* Select session key: Kyber-derived if available, else NETWORK_KEY[0..15] */
    const uint8_t *key = getSessionKey(NETWORK_BCAST);
    /* For broadcast, use NETWORK_KEY (no per-peer key) */
    /* (In a unicast scenario you'd use getSessionKey(dest_id)) */

    /* ASCON-128 encrypt: AAD = pkt[0..8], ciphertext + tag at pkt[25..] */
    uint8_t ct_tag[220 + TAG_LEN];
    if (!asconEncrypt(nonce, pkt, PKT_AAD_LEN,
                      (uint8_t *)pt_buf, (size_t)pt_len,
                      ct_tag, key)) {
        Serial.println(F("[CRYPTO] Encrypt failed"));
        return;
    }

    /* Copy ciphertext + tag into packet */
    memcpy(&pkt[PKT_PAYLOAD_OFF], ct_tag, (size_t)pt_len + TAG_LEN);
    size_t total = (size_t)(PKT_PAYLOAD_OFF + pt_len + TAG_LEN);

    if (!LoRa.beginPacket()) {
        Serial.println(F("[TX] beginPacket failed — radio busy"));
        return;
    }
    LoRa.write(pkt, total);
    LoRa.endPacket(true);   /* async TX */

    Serial.printf("[TX] seq=%lu  len=%u  cipher=ASCON128  key=%s\n",
                  (unsigned long)seq, (unsigned)total,
                  isSecure(NETWORK_BCAST) ? "KYBER-SESSION" : "PSK-FALLBACK");
}

/*
 * Poll LoRa for received packets.
 * Routes to handleKemFragment() for handshake packets,
 * or ASCON decryption for message packets.
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
    Serial.printf("[RX] %d bytes  RSSI=%d dBm\n", rcv, lastRSSI);

    if (rcv < PKT_AAD_LEN + 2) {
        Serial.println(F("[RX] Packet too short — dropped"));
        return;
    }

    /* Network filter */
    if (pkt[0] != NETWORK_ID[0] || pkt[1] != NETWORK_ID[1]) {
        Serial.println(F("[RX] Wrong network ID — dropped"));
        return;
    }

    uint8_t  dest = pkt[2];
    uint8_t  src  = pkt[3];
    uint8_t  type = pkt[4];
    uint32_t seq  = 0;
    memcpy(&seq, &pkt[5], 4);

    /* Drop own echoes */
    if (src == (uint8_t)MY_NODE_ID) return;

    /* Accept broadcast or packets addressed to us */
    if (dest != (uint8_t)NETWORK_BCAST && dest != (uint8_t)MY_NODE_ID)
        return;

    /* Route by packet type */
    if (type == PKT_KEM_INIT || type == PKT_KEM_RESP) {
        /* Handshake packets: reassemble fragments and process */
        handleKemFragment(pkt, rcv);
        return;
    }

    /* Anti-replay check (only for MSG/PING) */
    if (!checkAndUpdateSeq(src, seq)) {
        Serial.printf("[RX] Replay from node 0x%02X seq=%lu — dropped\n",
                      src, (unsigned long)seq);
        return;
    }

    if (type == PKT_MSG) {
        if (rcv < PKT_MIN_LEN) {
            Serial.println(F("[RX] MSG too short — dropped"));
            return;
        }

        uint8_t *nonce  = &pkt[PKT_NONCE_OFF];
        size_t   ct_len = (size_t)(rcv - PKT_PAYLOAD_OFF - TAG_LEN);
        uint8_t *ct_tag = &pkt[PKT_PAYLOAD_OFF];

        /* Select decryption key: prefer Kyber session key if available */
        const uint8_t *key = getSessionKey(src);

        uint8_t pt[220];
        memset(pt, 0, sizeof(pt));

        if (asconDecrypt(nonce, pkt, PKT_AAD_LEN,
                         ct_tag, ct_len, pt, key)) {
            pt[ct_len] = '\0';
            Serial.printf("[RX] %s  [%s]\n",
                          (char *)pt,
                          isSecure(src) ? "KYBER+ASCON" : "PSK+ASCON");
            addMessage(String((char *)pt), false);
        } else {
            Serial.printf("[CRYPTO] ASCON Auth FAIL from node 0x%02X\n", src);
            addMessage("[AUTH FAIL 0x" + String(src, HEX) + "]", false);
        }
        updateStatusBar();
    }
}

/*
 * Anti-replay: accept (src, seq) only if seq > last accepted seq from src.
 */
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
            peers[i].id = src_id; peers[i].last_seq = seq; peers[i].active = true;
            return true;
        }
    }
    return true;
}

// ═══════════════════════════════════════════════════════════════
//  U I
// ═══════════════════════════════════════════════════════════════

void updateStatusBar()
{
    tft.fillRect(0, 0, SCREEN_W, STATUS_H - 1, tft.color565(8, 12, 35));
    tft.drawFastHLine(0, STATUS_H - 1, SCREEN_W, tft.color565(35, 55, 140));
    tft.setTextSize(1);

    /* Node name (left) */
    tft.setTextColor(tft.color565(90, 190, 255));
    tft.setCursor(3, 4);
    tft.print(MY_NODE_NAME);
    tft.print(" #");
    char id_str[4];
    snprintf(id_str, sizeof(id_str), "%02X", MY_NODE_ID);
    tft.print(id_str);

    /* Cipher suite badge (centre) — shows active crypto stack */
    tft.setTextColor(tft.color565(60, 230, 90));
    tft.setCursor(74, 4);
    tft.print("[KYBER+ASCON]");

    /* TX sequence (right of cipher badge) */
    tft.setTextColor(tft.color565(90, 90, 130));
    tft.setCursor(202, 4);
    tft.print("S:");
    tft.print(txSeq);

    /* RSSI (far right) */
    if (lastRSSI != 0) {
        bool good = (lastRSSI > -100);
        tft.setTextColor(good ? tft.color565(80, 255, 80)
                               : tft.color565(255, 150, 50));
        tft.setCursor(255, 4);
        tft.print(lastRSSI);
        tft.print("d");
    }
}

void drawChatArea()
{
    tft.fillRect(0, CHAT_Y, SCREEN_W, CHAT_BOT - CHAT_Y + 1, tft.color565(12, 12, 22));
    tft.drawFastHLine(0, CHAT_BOT + 1, SCREEN_W, TFT_DARKGREY);
}

void redrawChat()
{
    tft.fillRect(0, CHAT_Y, SCREEN_W, CHAT_BOT - CHAT_Y + 1, tft.color565(12, 12, 22));
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
            /* Green lock = ASCON authenticated */
            tft.setTextColor(tft.color565(70, 220, 70));
            tft.setCursor(bX + 2, y + 2); tft.print("*");
            tft.setTextColor(TFT_WHITE);
            tft.setCursor(bX + 10, y + 6);
        } else {
            tft.setTextColor(TFT_WHITE);
            tft.setCursor(bX + 5, y + 6);
        }
        tft.print(txt);
        y += MSG_H;
    }
}

void drawTextField()
{
    tft.drawRoundRect(TEXT_X, TEXT_Y, TEXT_W, TEXT_H, 3, tft.color565(35, 55, 150));
    updateTextField();
}

void updateTextField()
{
    tft.fillRoundRect(TEXT_X + 1, TEXT_Y + 1, TEXT_W - 2, TEXT_H - 2, 2, TFT_BLACK);
    tft.setTextColor(TFT_CYAN);
    tft.setTextSize(2);
    int maxCh = (TEXT_W - 12) / 12;
    int start = (textIndex > maxCh) ? (textIndex - maxCh) : 0;
    tft.setCursor(TEXT_X + 6, TEXT_Y + 4);
    tft.print(&textBuffer[start]);
}

void drawKeyboard()
{
    tft.fillRect(0, 126, SCREEN_W, SCREEN_H - 126, tft.color565(12, 12, 22));
    char **layout = isNumMode ? keysNum : keysAlpha;
    int index = 0;

    int r1W = 10 * KEY_W + 9 * KEY_SPACING;
    int ox  = (SCREEN_W - r1W) / 2;
    for (int i = 0; i < 10; i++) {
        button[index].initButton(&tft, ox + i*(KEY_W+KEY_SPACING)+KEY_W/2,
                                 KB_ROW1, KEY_W, KEY_H,
                                 TFT_DARKGREY, TFT_DARKCYAN, TFT_WHITE, layout[index], 1);
        button[index++].drawButton();
    }

    int r2W = 9 * KEY_W + 8 * KEY_SPACING;
    ox = (SCREEN_W - r2W) / 2;
    for (int i = 0; i < 9; i++) {
        button[index].initButton(&tft, ox + i*(KEY_W+KEY_SPACING)+KEY_W/2,
                                 KB_ROW2, KEY_W, KEY_H,
                                 TFT_DARKGREY, TFT_DARKCYAN, TFT_WHITE, layout[index], 1);
        button[index++].drawButton();
    }

    int r3W = 7 * KEY_W + 6 * KEY_SPACING;
    ox = (SCREEN_W - r3W) / 2;
    for (int i = 0; i < 7; i++) {
        button[index].initButton(&tft, ox + i*(KEY_W+KEY_SPACING)+KEY_W/2,
                                 KB_ROW3, KEY_W, KEY_H,
                                 TFT_DARKGREY, TFT_DARKCYAN, TFT_WHITE, layout[index], 1);
        button[index++].drawButton();
    }

    /* Row 4: KEY (blue), SPC (green), DEL (red), SEND (navy) */
    int bW[]  = {44, 76, 44, 56};
    int totW  = 44 + 76 + 44 + 56 + 3 * KEY_SPACING;
    int cx    = (SCREEN_W - totW) / 2;
    for (int i = 0; i < 4; i++) {
        uint16_t col =
          (i == 0) ? tft.color565(18, 18, 155)  /* KEY  — blue            */
        : (i == 1) ? tft.color565(18, 108, 18)  /* SPC  — green           */
        : (i == 2) ? tft.color565(155, 18, 18)  /* DEL  — red             */
        : TFT_NAVY;                              /* SEND — navy            */
        button[index].initButton(&tft, cx + bW[i]/2, KB_ROW4, bW[i], KEY_H,
                                 TFT_DARKGREY, col, TFT_WHITE, layout[index], 1);
        button[index++].drawButton();
        cx += bW[i] + KEY_SPACING;
    }
}

void handleKey(String key)
{
    if (key == "KEY") {
        /* Trigger Kyber key exchange immediately */
        initiateKyberHandshake();
    }
    else if (key == "DEL") {
        if (textIndex > 0) textBuffer[--textIndex] = '\0';
        updateTextField();
    }
    else if (key == "SEND") {
        if (textIndex == 0) return;
        sendSecureMessage(textBuffer);
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

// ─── Touch calibration ───────────────────────────────────────────
void touch_calibrate()
{
    uint16_t calData[5];
    if (!SPIFFS.begin(true)) { Serial.println(F("[SPIFFS] Mount failed")); return; }
    if (SPIFFS.exists(CALIBRATION_FILE)) {
        File f = SPIFFS.open(CALIBRATION_FILE, "r");
        if (f) { f.readBytes((char *)calData, 14); f.close(); }
        tft.setTouch(calData);
    } else {
        tft.fillScreen(TFT_BLACK);
        tft.setTextColor(TFT_WHITE); tft.setTextSize(2);
        tft.setCursor(20, 90);  tft.println("Touch Calibration");
        tft.setCursor(20, 115); tft.println("Tap each corner");
        tft.calibrateTouch(calData, TFT_MAGENTA, TFT_BLACK, 15);
        File f = SPIFFS.open(CALIBRATION_FILE, "w");
        if (f) { f.write((const unsigned char *)calData, 14); f.close(); }
        Serial.println(F("[SPIFFS] Calibration saved"));
    }
}

// ═══════════════════════════════════════════════════════════════
//  S E T U P
// ═══════════════════════════════════════════════════════════════
void setup()
{
    Serial.begin(115200);
    delay(500);
    Serial.println(F("\n[BOOT] Quantum-Secure LoRa Messenger v3.0"));
    Serial.printf("[BOOT] Node: %s  ID=0x%02X\n", MY_NODE_NAME, MY_NODE_ID);
    Serial.printf("[BOOT] Network: %s  Freq: %.0f Hz\n",
                  NETWORK_NAME, (double)NETWORK_FREQ);
    Serial.println(F("[BOOT] Crypto: Kyber-512 KEM + ASCON-128 AEAD"));

    /* Zero all state tables */
    memset(peers,    0, sizeof(peers));
    memset(sessions, 0, sizeof(sessions));
    memset(kem_rx_frag_seen, 0, sizeof(kem_rx_frag_seen));

    // ── LoRa ──────────────────────────────────────────────────
    SPI.begin(18, 19, 23, 27);
    pinMode(LORA_SS,  OUTPUT); digitalWrite(LORA_SS,  HIGH);
    pinMode(LORA_RST, OUTPUT);
    digitalWrite(LORA_RST, LOW);  delay(10);
    digitalWrite(LORA_RST, HIGH); delay(10);

    LoRa.setPins(LORA_SS, LORA_RST, LORA_DIO0);
    LoRa.setSPIFrequency(125000);

    Serial.print(F("[LORA] Init... "));
    if (!LoRa.begin(NETWORK_FREQ)) {
        Serial.println(F("FAILED"));
    } else {
        LoRa.setSpreadingFactor(7);
        LoRa.setSignalBandwidth(500E3);
        LoRa.setCodingRate4(5);
        LoRa.setTxPower(14);
        Serial.println(F("OK"));
    }

    // ── TFT ───────────────────────────────────────────────────
    tft.init();
    tft.setRotation(1);
    tft.setTextWrap(false);
    touch_calibrate();
    tft.fillScreen(tft.color565(12, 12, 22));
    updateStatusBar();
    drawChatArea();
    drawTextField();
    drawKeyboard();
    Serial.println(F("[TFT] OK"));

    // ── Kyber-512 Key Generation ───────────────────────────────
    /*
     * Generate an ephemeral Kyber-512 key pair using ESP32 hardware TRNG.
     * Public key (800 bytes) will be broadcast to peers.
     * Secret key (1632 bytes) stays in RAM — never transmitted.
     *
     * NOTE: On a production device you would persist the key pair in
     *       NVS (non-volatile storage) to survive reboots.  For this
     *       project we regenerate on every boot (ephemeral forward secrecy).
     */
    Serial.println(F("[KEM] Generating Kyber-512 key pair..."));
    addMessage("Generating keys...", false);

    kyber512_keypair(kyber_pk, kyber_sk);
    kyber_ready = true;

    Serial.printf("[KEM] Public key (first 8 bytes): %02X %02X %02X %02X %02X %02X %02X %02X\n",
                  kyber_pk[0], kyber_pk[1], kyber_pk[2], kyber_pk[3],
                  kyber_pk[4], kyber_pk[5], kyber_pk[6], kyber_pk[7]);
    Serial.println(F("[KEM] Keypair ready. Broadcasting public key in 2 s..."));

    addMessage("Keys ready! KYBER-512", false);

    /*
     * Wait briefly before broadcasting so the LoRa radio has fully settled
     * and any peer that is also booting has time to start listening.
     */
    delay(2000);
    initiateKyberHandshake();

    Serial.println(F("[BOOT] System ready."));
    Serial.println(F("[BOOT] Type 'KEY' + SEND to re-initiate key exchange."));
}

// ═══════════════════════════════════════════════════════════════
//  L O O P
// ═══════════════════════════════════════════════════════════════
void loop()
{
    handleLoRaPacket();

    uint16_t x, y;
    bool pressed = tft.getTouch(&x, &y);

    for (int i = 0; i < TOTAL_KEYS; i++)
        button[i].press(pressed && button[i].contains(x, y));

    for (int i = 0; i < TOTAL_KEYS; i++) {
        if (button[i].justReleased()) button[i].drawButton();
        if (button[i].justPressed()) {
            button[i].drawButton(true);
            handleKey(isNumMode ? keysNum[i] : keysAlpha[i]);
            delay(80);
        }
    }
}
