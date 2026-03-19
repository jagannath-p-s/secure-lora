#pragma once
/*
 * ============================================================
 *  network_keys.h  —  Quantum-Secure LoRa Messenger v3.0
 * ============================================================
 *
 *  Generated : 2026-03-19
 *  Network   : QSLM_NET
 *  Frequency : 868 MHz
 *
 *  Cryptographic Architecture
 *  ──────────────────────────
 *  KEY EXCHANGE : Kyber-512 (ML-KEM-512, NIST FIPS 203)
 *    • Lattice-based post-quantum KEM
 *    • Each node generates an ephemeral Kyber-512 keypair at boot
 *    • Peers exchange keys over LoRa (fragmented broadcast)
 *    • Shared secret (32 bytes) becomes the ASCON session key
 *
 *  MESSAGE ENCRYPTION : ASCON-128 (NIST SP 800-232)
 *    • Lightweight authenticated encryption (AEAD)
 *    • 128-bit key (first 16 bytes of Kyber shared secret)
 *    • 128-bit nonce per message (ESP32 hardware TRNG)
 *    • 128-bit authentication tag per message
 *
 *  FALLBACK : NETWORK_KEY (pre-shared, used before KEM completes)
 *    • First 16 bytes used as ASCON-128 key
 *    • Provides encrypted comms even before Kyber exchange
 *
 *  !! SECURITY WARNING !!
 *  Keep this file confidential. Never commit to public VCS.
 *  The NETWORK_KEY is a symmetric fallback — the real quantum
 *  security comes from the Kyber-512 session key exchange.
 *
 *  DEPLOYMENT STEPS
 *  ─────────────────
 *  For each device:
 *    1. Set MY_NODE_ID   (unique per device, 1-254)
 *    2. Set MY_NODE_NAME (display name, max 8 chars)
 *    3. Compile & flash with Arduino IDE.
 *  All devices share the same NETWORK_KEY, NETWORK_ID, NETWORK_FREQ.
 *  Kyber session keys are generated and exchanged automatically at boot.
 *
 *  NODE ASSIGNMENTS FOR THIS NETWORK
 *  ───────────────────────────────────
 *   ID 0x01  →  DISP1
 *   ID 0x02  →  DISP2
 *   ID 0x03  →  DISP3
 *   ID 0x04  →  DISP4
 *   ID 0x05  →  DISP5
 *
 *  To add more nodes: assign the next unused ID and flash.
 * ============================================================
 */

// ─── THIS DEVICE ─────────────────────────────────────────────────
//  << CHANGE these two values for each device you flash >>
#define MY_NODE_ID    1         /* Unique ID 1-254                    */
#define MY_NODE_NAME  "DISP1"  /* Display name, max 8 chars          */

// ─── NETWORK SETTINGS (same on ALL nodes) ────────────────────────
#define NETWORK_NAME  "QSLM_NET"
#define NETWORK_FREQ  868E6              /* LoRa carrier frequency (Hz)       */
#define NETWORK_BCAST 0xFF               /* Broadcast destination address     */

// ─── PRE-SHARED FALLBACK KEY (same on ALL nodes) ─────────────────
/*
 * 32-byte pre-shared key used as ASCON-128 fallback BEFORE a Kyber-512
 * session key is established (i.e. between boot and first key exchange).
 * Only the first 16 bytes are used as the ASCON-128 key.
 *
 * This key does NOT provide quantum security on its own — it exists
 * purely so that messages can be encrypted immediately at boot.
 * Once the Kyber-512 handshake completes, the session key derived
 * from the KEM shared secret replaces this key for that peer.
 *
 * Generate a fresh key with:  python3 keygen.py
 */
static const uint8_t NETWORK_KEY[32] = {
  0x42, 0x28, 0xE9, 0xDC, 0x49, 0x07, 0x80, 0x0F,
  0x1B, 0x87, 0x4F, 0xA6, 0x7D, 0x1C, 0x86, 0xE0,
  0x6B, 0x90, 0xE7, 0x60, 0xEF, 0x58, 0x8C, 0x8B,
  0x1A, 0x5D, 0x34, 0xAB, 0x4B, 0x94, 0xF3, 0x47
};

/* 2-byte network identifier — silently drops foreign-network packets */
static const uint8_t NETWORK_ID[2] = { 0xD2, 0xCB };
