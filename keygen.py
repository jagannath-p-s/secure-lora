#!/usr/bin/env python3
"""
keygen.py  —  Quantum-Secure LoRa Messenger v3.0  |  Key Generator
===================================================================
Generates a cryptographically secure pre-shared fallback key and
writes a ready-to-use network_keys.h for the ESP32 firmware.

The MAIN security (quantum resistance) comes from Kyber-512 KEM,
which is performed on-device at boot.  This script only generates
the fallback NETWORK_KEY used before the Kyber handshake completes.

Usage
-----
  python3 keygen.py                          # interactive wizard
  python3 keygen.py --nodes 3 --freq 915     # 3 nodes, 915 MHz
  python3 keygen.py --output my_keys.h       # custom output file
  python3 keygen.py --help

Security Architecture
---------------------
  BEFORE Kyber KEM:  ASCON-128(NETWORK_KEY[0:16])  ← symmetric fallback
  AFTER  Kyber KEM:  ASCON-128(kyber_ss[0:16])     ← quantum-secure session key

  Kyber-512 is performed automatically on-device at boot.  No Python
  tooling is needed for the quantum-secure key exchange.

Requirements
------------
  Python 3.6+  (no third-party packages needed)
"""

import os
import sys
import datetime
import argparse


BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║    Quantum-Secure LoRa Messenger v3.0  —  Key Generator      ║
║    Kyber-512 KEM  +  ASCON-128  |  Post-Quantum Secure       ║
╚══════════════════════════════════════════════════════════════╝
"""

FREQ_MAP = {
    "433": "433E6",
    "868": "868E6",
    "915": "915E6",
}

SECURITY_NOTE = """
POST-QUANTUM SECURITY ARCHITECTURE
────────────────────────────────────
  • Kyber-512 (ML-KEM-512, NIST FIPS 203)
    ─ Lattice-based Key Encapsulation Mechanism
    ─ Resistant to Shor's algorithm (no discrete log / factoring)
    ─ Performed ON-DEVICE at boot; not managed by this script
    ─ Each node generates ephemeral Kyber keypair from hardware TRNG
    ─ Shared secret → ASCON-128 session key (16 bytes)

  • ASCON-128 (NIST SP 800-232 Lightweight Crypto Standard)
    ─ Authenticated Encryption with Associated Data (AEAD)
    ─ 128-bit key, 128-bit nonce, 128-bit tag
    ─ Designed for constrained IoT devices

  • NETWORK_KEY (this script)
    ─ Symmetric fallback key used ONLY before Kyber KEM completes
    ─ Provides basic confidentiality during boot handshake period
    ─ Does NOT provide post-quantum security on its own
    ─ Quantum security comes entirely from the Kyber-512 KEM
"""


def urandom_key(n: int) -> bytes:
    """Return n cryptographically random bytes from the OS CSPRNG."""
    key = os.urandom(n)
    if len(key) != n:
        raise RuntimeError("OS CSPRNG returned fewer bytes than requested")
    return key


def bytes_to_c_array(data: bytes, per_line: int = 8) -> str:
    """Format a bytes object as a C hex-literal array body."""
    chunks = [data[i:i + per_line] for i in range(0, len(data), per_line)]
    lines  = ["  " + ", ".join(f"0x{b:02X}" for b in chunk)
              for chunk in chunks]
    return ",\n".join(lines)


def prompt(prompt_text: str, default: str = "") -> str:
    """Read a line from stdin, returning default on empty input."""
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"  {prompt_text}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    return val if val else default


HEADER_TEMPLATE = """\
#pragma once
/*
 * ============================================================
 *  network_keys.h  —  Quantum-Secure LoRa Messenger v3.0
 * ============================================================
 *
 *  Generated : {timestamp}
 *  Network   : {network_name}
 *  Frequency : {freq_mhz} MHz
 *
 *  Cryptographic Architecture
 *  ──────────────────────────
 *  KEY EXCHANGE : Kyber-512 (ML-KEM-512, NIST FIPS 203)
 *    Performed on-device at boot. Each node generates an ephemeral
 *    Kyber-512 keypair, broadcasts the public key, and derives a
 *    32-byte shared secret via the KEM encap/decap protocol.
 *
 *  MESSAGE ENCRYPTION : ASCON-128 (NIST SP 800-232)
 *    16-byte key from Kyber shared secret, 16-byte random nonce,
 *    16-byte authentication tag. Quantum-resistant session cipher.
 *
 *  FALLBACK : NETWORK_KEY (this file)
 *    Used as ASCON-128 key BEFORE Kyber KEM completes.
 *    Only the first 16 bytes are used as the ASCON key.
 *
 *  !! SECURITY WARNING !!
 *  Keep this file confidential. Never commit to public VCS.
 *
 *  DEPLOYMENT STEPS
 *  ─────────────────
 *  For each device:
 *    1. Set MY_NODE_ID   (unique per device, 1-254)
 *    2. Set MY_NODE_NAME (display name, max 8 chars)
 *    3. Compile & flash with Arduino IDE.
 *
 *  NODE ASSIGNMENTS FOR THIS NETWORK
 *  ───────────────────────────────────
{node_assignment_comment} *
 *  To add more nodes: assign the next unused ID and flash.
 * ============================================================
 */

// ─── THIS DEVICE ─────────────────────────────────────────────────
//  << CHANGE these two values for each device you flash >>
#define MY_NODE_ID    {first_node_id:<10}  // Unique ID 1-254
#define MY_NODE_NAME  "{first_node_name}"  // Max 8 chars

// ─── NETWORK SETTINGS (same on ALL nodes) ────────────────────────
#define NETWORK_NAME  "{network_name}"
#define NETWORK_FREQ  {freq_define:<12}    // LoRa carrier frequency (Hz)
#define NETWORK_BCAST 0xFF                 // Broadcast destination address

// ─── PRE-SHARED FALLBACK KEY (same on ALL nodes) ─────────────────
// 32-byte key used as ASCON-128 fallback BEFORE Kyber-512 KEM completes.
// Only the first 16 bytes are used as the ASCON-128 key.
// Quantum security comes from Kyber-512 (performed on-device at boot).
static const uint8_t NETWORK_KEY[32] = {{
{network_key_array}
}};

// 2-byte network identifier — silently drops foreign-network packets
static const uint8_t NETWORK_ID[2] = {{ {network_id_bytes} }};
"""


def parse_args():
    p = argparse.ArgumentParser(
        description="Generate network_keys.h for Quantum-Secure LoRa Messenger v3.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--network", default="",
                   help="Network name identifier (default: prompt)")
    p.add_argument("--freq", default="",
                   choices=list(FREQ_MAP.keys()),
                   help="LoRa frequency in MHz: 433 | 868 | 915")
    p.add_argument("--nodes", type=int, default=0,
                   help="Number of nodes to configure (default: prompt)")
    p.add_argument("--output", default="network_keys.h",
                   help="Output header file (default: network_keys.h)")
    return p.parse_args()


def main():
    args = parse_args()
    print(BANNER)

    network_name = args.network or prompt("Network name", "QSLM_NET")
    network_name = network_name[:16].upper().replace(" ", "_")

    freq_str = args.freq
    if not freq_str:
        freq_str = prompt("LoRa frequency MHz  (433 / 868 / 915)", "868")
        while freq_str not in FREQ_MAP:
            freq_str = prompt("  Invalid. Choose 433, 868, or 915", "868")

    n_nodes = args.nodes
    if n_nodes < 1:
        try:
            n_nodes = int(prompt("Number of nodes in this network", "2"))
        except ValueError:
            n_nodes = 2
    n_nodes = max(1, min(n_nodes, 254))

    print(f"\n  Configure {n_nodes} node(s):")
    node_names = []
    for i in range(n_nodes):
        default_name = f"DISP{i + 1}"
        name = prompt(f"    Node {i + 1} display name (max 8 chars)", default_name)
        node_names.append(name[:8].upper())

    print("\n  Generating cryptographic material from OS CSPRNG...")
    # 32-byte fallback pre-shared key (symmetric, not post-quantum)
    network_key = urandom_key(32)
    # 2-byte network tag for packet filtering
    network_id  = urandom_key(2)

    lines = [f" *   ID 0x{i + 1:02X}  →  {name}" for i, name in enumerate(node_names)]
    node_assignment_comment = "\n".join(lines) + "\n"

    header = HEADER_TEMPLATE.format(
        timestamp               = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        network_name            = network_name,
        freq_mhz                = freq_str,
        freq_define             = FREQ_MAP[freq_str],
        first_node_id           = 1,
        first_node_name         = node_names[0] if node_names else "DISP1",
        node_assignment_comment = node_assignment_comment,
        network_key_array       = bytes_to_c_array(network_key),
        network_id_bytes        = ", ".join(f"0x{b:02X}" for b in network_id),
    )

    output_path = args.output
    with open(output_path, "w") as fh:
        fh.write(header)
    os.chmod(output_path, 0o600)

    print(f"\n  ✓ Written to : {output_path}  (permissions: 600)")
    print(f"  ✓ Network    : {network_name}  @  {freq_str} MHz")
    print(f"  ✓ Network ID : {network_id.hex().upper()}")
    print(f"  ✓ Fallback K : {network_key[:8].hex().upper()}...  (256-bit, first 16 used as ASCON key)")
    print()
    print(SECURITY_NOTE)

    print("  NODE ASSIGNMENTS")
    print("  ─────────────────")
    for i, name in enumerate(node_names):
        print(f"    ID 0x{i + 1:02X} = {name}")

    print()
    print("  NEXT STEPS")
    print("  ───────────")
    print(f"  1. Copy {output_path} into your Arduino sketch folder.")
    print("  2. For each device, open network_keys.h and set:")
    print("       MY_NODE_ID    (unique per device)")
    print("       MY_NODE_NAME  (matching display name)")
    print("  3. Compile & flash each device with Arduino IDE.")
    print("  4. At boot each device auto-generates a Kyber-512 keypair")
    print("     and initiates the quantum-secure key exchange over LoRa.")
    print()
    print("  WARNING: Keep network_keys.h secret — it IS your fallback key.")
    print()


if __name__ == "__main__":
    main()
