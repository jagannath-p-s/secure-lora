# Quantum-Secure LoRa Messenger — v3.0

A post-quantum encrypted, off-grid chat device built on the **ESP32** microcontroller, **SX1276 LoRa** radio, and a **2.8-inch ILI9341 TFT touchscreen**.

Messages are encrypted with **ASCON-128** (NIST Lightweight Crypto Standard 2023) using session keys derived from a **Kyber-512** (ML-KEM-512, NIST FIPS 203) key exchange — making every conversation resistant to quantum computer attacks.

---

## Table of Contents

1. [How It Works](#how-it-works)
2. [Hardware Requirements](#hardware-requirements)
3. [Sketch File Structure](#sketch-file-structure)
4. [Setup Guide — Linux](#setup-guide--linux)
5. [Setup Guide — Windows](#setup-guide--windows)
6. [Setup Guide — macOS](#setup-guide--macos)
7. [Flashing Multiple Nodes](#flashing-multiple-nodes)
8. [Using the Device](#using-the-device)
9. [Security Architecture Deep Dive](#security-architecture-deep-dive)
10. [Troubleshooting](#troubleshooting)

---

## How It Works

### The Big Picture

Standard encrypted radios use classical cryptography (AES keys exchanged via ECDH or RSA). A sufficiently powerful quantum computer running **Shor's algorithm** can break ECDH/RSA in polynomial time, retroactively decrypting all recorded traffic. This project eliminates that risk.

```
┌─────────────────────────────────────────────────────────────┐
│                   BOOT SEQUENCE (once)                       │
│                                                             │
│  1. ESP32 hardware TRNG generates 64 random bytes           │
│  2. Kyber-512 expands them into a keypair:                  │
│       Public Key  (800 bytes) ── share with anyone          │
│       Secret Key (1632 bytes) ── never leaves device        │
│  3. Public key is broadcast over LoRa in 4 fragments        │
└─────────────────────────────────────────────────────────────┘
                            │
              (peer receives public key)
                            │
┌─────────────────────────────────────────────────────────────┐
│                 KEY ENCAPSULATION (peer side)                │
│                                                             │
│  4. Peer runs Kyber Encapsulate(your_public_key):           │
│       produces  ciphertext  (768 bytes)  → sent back        │
│       keeps     shared_secret (32 bytes) → private          │
└─────────────────────────────────────────────────────────────┘
                            │
           (you receive the 768-byte ciphertext)
                            │
┌─────────────────────────────────────────────────────────────┐
│                 KEY DECAPSULATION (your side)               │
│                                                             │
│  5. You run Kyber Decapsulate(ciphertext, your_secret_key): │
│       recovers  shared_secret (32 bytes) ← same as peer's   │
│  6. shared_secret[0..15] becomes the ASCON-128 session key  │
└─────────────────────────────────────────────────────────────┘
                            │
              (both sides now have the same key)
                            │
┌─────────────────────────────────────────────────────────────┐
│                  EVERY MESSAGE (ongoing)                     │
│                                                             │
│  7. Random 16-byte nonce from hardware TRNG                 │
│  8. ASCON-128 encrypts plaintext + authenticates header     │
│  9. 16-byte auth tag appended (tamper detection)            │
│ 10. Packet sent over LoRa                                   │
│ 11. Receiver decrypts; tag mismatch = silently dropped      │
└─────────────────────────────────────────────────────────────┘
```

### Why Kyber-512 is Quantum-Safe

Kyber's security is based on the **Module Learning With Errors (MLWE)** problem — a lattice problem. No known quantum algorithm (including Shor's or Grover's) can solve MLWE significantly faster than a classical computer. This is fundamentally different from ECDH/RSA, whose hardness assumptions (discrete logarithm, integer factoring) are broken by Shor's algorithm.

### Why ASCON-128

ASCON was selected by NIST in 2023 as the primary standard for lightweight authenticated encryption (NIST SP 800-232). It is:
- Designed specifically for microcontrollers and IoT devices
- Faster than AES on processors without AES hardware acceleration
- Provides both encryption and authentication in a single pass
- Constant-time (resistant to timing side-channel attacks)

### Packet Flow on the Wire

```
LoRa Packet (max 255 bytes)
┌──────────────────────────────────────────────────────────┐
│ [0-1]  Network ID   (2 B)  ← filters foreign networks   │
│ [2]    Destination  (1 B)  ← node ID or 0xFF broadcast  │
│ [3]    Source       (1 B)  ← sender node ID             │
│ [4]    Packet Type  (1 B)  ← 0x01 MSG / 0x03 KEM_INIT   │
│ [5-8]  Sequence     (4 B)  ← anti-replay counter        │
│─────── above 9 bytes = ASCON Additional Auth Data ──────│
│ [9-24] ASCON Nonce  (16 B) ← random, unique per message │
│ [25..] Ciphertext          ← ASCON-128 encrypted body   │
│ [last 16] Auth Tag  (16 B) ← ASCON authentication tag   │
└──────────────────────────────────────────────────────────┘

KEM Fragment Packet:
┌──────────────────────────────────────────────────────────┐
│ [0-8]  Header       (9 B)  ← same as above              │
│ [9]    Fragment ID  (1 B)  ← 0-based index              │
│ [10]   Total Frags  (1 B)  ← total fragments (4 for pk) │
│ [11..] Fragment Data        ← up to 244 bytes of key    │
└──────────────────────────────────────────────────────────┘
Kyber public key (800 B) → 4 fragments of ≤244 B each
Kyber ciphertext (768 B) → 4 fragments of ≤244 B each
```

---

## Hardware Requirements

| Component | Model | Notes |
|---|---|---|
| Microcontroller | ESP32 Dev Module | 30-pin or 38-pin, 4 MB flash minimum |
| LoRa Radio | SX1276 | Ra-01 / Ra-02 modules; 868 MHz (EU) or 915 MHz (US) |
| Display | ILI9341 TFT | 2.8 inch, 320×240, SPI, with resistive touch (XPT2046) |
| Power | USB or 3.7V LiPo | 500 mA minimum during TX |

### Wiring

```
ESP32 Pin  →  Peripheral
──────────────────────────────────────────────
GPIO 18    →  LoRa SCK  (SPI clock)
GPIO 19    →  LoRa MISO (SPI data in)
GPIO 23    →  LoRa MOSI (SPI data out)
GPIO 27    →  LoRa NSS  (chip select)
GPIO 25    →  LoRa RST  (reset)
GPIO 26    →  LoRa DIO0 (interrupt / TX done)

TFT SPI shares the same SCK/MISO/MOSI bus.
TFT CS / DC / RST pins are configured in User_Setup.h (TFT_eSPI library).
Touch CS is also in User_Setup.h.
```

> **Note:** The TFT_eSPI library requires you to configure pin numbers in its `User_Setup.h` file to match your specific wiring. See the [TFT_eSPI documentation](https://github.com/Bodmer/TFT_eSPI) for details.

---

## Sketch File Structure

```
lora_copy/
├── lora_copy.ino      Main firmware — UI, LoRa protocol, key exchange logic
├── network_keys.h     Per-network config: node ID, frequency, fallback key
├── keccak_tiny.h      Keccak-1600 permutation → SHA3-256/512, SHAKE128/256
├── kyber512.h         Kyber-512 KEM (keygen, encapsulate, decapsulate)
├── ascon128.h         ASCON-128 authenticated encryption / decryption
├── keygen.py          Python utility to regenerate network_keys.h
└── README.md          This file
```

All crypto is **self-contained** in the three `.h` files. No extra Arduino libraries for cryptography are needed.

---

## Setup Guide — Linux

### 1. Install Arduino IDE 2

```bash
# Download the AppImage from the official site
wget https://downloads.arduino.cc/arduino-ide/arduino-ide_2.3.2_Linux_64bit.AppImage
chmod +x arduino-ide_2.3.2_Linux_64bit.AppImage
./arduino-ide_2.3.2_Linux_64bit.AppImage
```

Or install via Flatpak:
```bash
flatpak install flathub cc.arduino.IDE2
```

### 2. Add ESP32 Board Support

1. Open Arduino IDE → **File → Preferences**
2. In **"Additional boards manager URLs"** paste:
   ```
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
3. Click **OK**
4. Open **Tools → Board → Boards Manager**
5. Search `esp32` → install **"esp32 by Espressif Systems"** (version 2.x or 3.x)

### 3. Install Required Libraries

Open **Tools → Manage Libraries** and install:

| Library | Author | Version |
|---|---|---|
| LoRa | Sandeep Mistry | latest |
| TFT_eSPI | Bodmer | latest |

### 4. Configure TFT_eSPI

The TFT_eSPI library needs to know your pin assignments:

1. Find the library folder:
   ```bash
   find ~/Arduino/libraries -name "User_Setup.h" -path "*/TFT_eSPI/*"
   ```
2. Open `User_Setup.h` and set your driver and pin numbers. For a typical ILI9341 2.8" display:
   ```cpp
   #define ILI9341_DRIVER
   #define TFT_CS   15    // your CS pin
   #define TFT_DC    2    // your DC/RS pin
   #define TFT_RST   4    // your RST pin (or -1 if tied to ESP32 RST)
   #define TOUCH_CS 21    // XPT2046 touch chip select
   #define SPI_FREQUENCY  27000000
   #define SPI_TOUCH_FREQUENCY  2500000
   ```
3. Save the file.

### 5. Add USB Serial Permissions

```bash
sudo usermod -a -G dialout $USER
# Log out and back in, or run:
newgrp dialout
```

### 6. Open and Configure the Sketch

1. Clone or copy the `lora_copy` folder to your Arduino sketchbook
2. Open `lora_copy.ino` in Arduino IDE
3. Open `network_keys.h` and set your node's values:
   ```cpp
   #define MY_NODE_ID    1       // unique per device (1–254)
   #define MY_NODE_NAME  "NODE1" // max 8 characters
   ```

### 7. Select Board and Port

- **Tools → Board → esp32 → ESP32 Dev Module**
- **Tools → Upload Speed → 921600**
- **Tools → Flash Size → 4MB (32Mb)**
- **Tools → Partition Scheme → Default 4MB with spiffs** ← important for touch calibration storage
- **Tools → Port** → select your device (usually `/dev/ttyUSB0` or `/dev/ttyACM0`)

### 8. Compile and Flash

Click the **Upload** button (→) or press `Ctrl+U`.

Expected compile time: **60–120 seconds** (first time; Kyber-512 is ~800 lines).

If compilation succeeds, open **Tools → Serial Monitor** at **115200 baud** to watch the boot log.

### 9. Generate a Fresh Network Key (Optional)

```bash
cd lora_copy/
python3 keygen.py
# Follow the prompts to set network name, frequency, and node count
# It overwrites network_keys.h with a new random key
```

---

## Setup Guide — Windows

### 1. Install Arduino IDE 2

1. Download the Windows installer from: https://www.arduino.cc/en/software
2. Run the `.exe` installer and follow the prompts.
3. Launch **Arduino IDE 2**.

### 2. Add ESP32 Board Support

1. **File → Preferences**
2. In **"Additional boards manager URLs"** paste:
   ```
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
3. Click **OK**
4. **Tools → Board → Boards Manager** → search `esp32` → install **"esp32 by Espressif Systems"**

> **Note:** The ESP32 board package downloads the Xtensa GCC compiler (~300 MB). This may take several minutes.

### 3. Install CP2102 / CH340 USB Driver

Most ESP32 dev boards use a USB-to-UART bridge chip. Windows 10/11 may auto-install drivers; if the COM port does not appear:

- **CP2102** driver: https://www.silabs.com/developers/usb-to-uart-bridge-vcp-drivers
- **CH340/CH341** driver: https://www.wch-ic.com/downloads/CH341SER_EXE.html

After installing, plug in your ESP32 and check **Device Manager → Ports (COM & LPT)** for the new COM port.

### 4. Install Required Libraries

**Tools → Manage Libraries**, install:
- `LoRa` by Sandeep Mistry
- `TFT_eSPI` by Bodmer

### 5. Configure TFT_eSPI

1. Find the library folder:
   ```
   C:\Users\<YourName>\Documents\Arduino\libraries\TFT_eSPI\User_Setup.h
   ```
2. Open it in Notepad++ or VS Code and configure driver + pins as described in the Linux section above.

### 6. Open and Configure the Sketch

1. Copy the `lora_copy` folder to your Arduino sketchbook:
   ```
   C:\Users\<YourName>\Documents\Arduino\lora_copy\
   ```
2. Open `lora_copy.ino` in Arduino IDE
3. Edit `network_keys.h` — set `MY_NODE_ID` and `MY_NODE_NAME`

### 7. Select Board and Port

- **Tools → Board → esp32 → ESP32 Dev Module**
- **Tools → Upload Speed → 921600**
- **Tools → Partition Scheme → Default 4MB with spiffs**
- **Tools → Port → COM3** (or whichever COM port appeared in Device Manager)

### 8. Compile and Flash

Click the **Upload** button. If you get a permission error or "Failed to connect":
1. Hold the **BOOT** button on your ESP32
2. Click Upload
3. Release BOOT once you see `Connecting...` in the output

### 9. Generate a Fresh Network Key (Optional)

Install Python 3 from https://www.python.org/downloads/ (check "Add Python to PATH").

Open **Command Prompt** in the sketch folder:
```cmd
cd C:\Users\<YourName>\Documents\Arduino\lora_copy
python keygen.py
```

---

## Setup Guide — macOS

### 1. Install Arduino IDE 2

Download the `.dmg` from https://www.arduino.cc/en/software, open it and drag **Arduino IDE** to your Applications folder.

### 2. Add ESP32 Board Support

1. **Arduino IDE → Preferences** (or `⌘,`)
2. In **"Additional boards manager URLs"** paste:
   ```
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
3. **Tools → Board → Boards Manager** → search `esp32` → install **"esp32 by Espressif Systems"**

### 3. Install USB Driver (if needed)

Newer Macs (macOS 10.15+) include CH340/CP2102 drivers. If your port does not appear:
- CP2102: https://www.silabs.com/developers/usb-to-uart-bridge-vcp-drivers
- CH340: https://github.com/adrianmihalko/ch340g-ch34g-ch34x-mac-os-x-driver

Your device will appear as `/dev/cu.usbserial-XXXX` or `/dev/cu.SLAB_USBtoUART`.

### 4. Install Required Libraries

**Tools → Manage Libraries** → install `LoRa` (Sandeep Mistry) and `TFT_eSPI` (Bodmer).

### 5. Configure TFT_eSPI

```bash
# Find User_Setup.h
find ~/Documents/Arduino/libraries -name "User_Setup.h" -path "*/TFT_eSPI/*"
```
Edit the file with your pin numbers (same configuration as Linux section).

### 6. Open and Configure the Sketch

Copy `lora_copy` to `~/Documents/Arduino/lora_copy/`, open `lora_copy.ino`, edit `network_keys.h`.

### 7. Select Board and Port

- **Tools → Board → esp32 → ESP32 Dev Module**
- **Tools → Upload Speed → 921600**
- **Tools → Partition Scheme → Default 4MB with spiffs**
- **Tools → Port → /dev/cu.usbserial-XXXX**

### 8. Compile and Flash

Click Upload. If connection fails, hold the ESP32 **BOOT** button while clicking Upload.

### 9. Generate a Fresh Network Key (Optional)

macOS ships with Python 3 (`python3` in Terminal):
```bash
cd ~/Documents/Arduino/lora_copy
python3 keygen.py
```

---

## Flashing Multiple Nodes

All nodes in the same network **share** the same `NETWORK_KEY`, `NETWORK_ID`, and `NETWORK_FREQ`. They **differ only** in `MY_NODE_ID` and `MY_NODE_NAME`.

**Workflow for a 3-node network:**

1. Run `python3 keygen.py` once on your computer to generate `network_keys.h`
2. For **Node 1**: edit `#define MY_NODE_ID 1` and `#define MY_NODE_NAME "ALICE"`, flash
3. For **Node 2**: edit `#define MY_NODE_ID 2` and `#define MY_NODE_NAME "BOB"`, flash
4. For **Node 3**: edit `#define MY_NODE_ID 3` and `#define MY_NODE_NAME "CAROL"`, flash
5. Power all three on — they auto-exchange Kyber keys and are immediately ready

> The Kyber key exchange is **ephemeral** — a fresh keypair is generated every boot. If a device reboots, it automatically re-initiates a new key exchange. This provides **forward secrecy**: compromising a device after a conversation does not reveal past messages.

---

## Using the Device

### First Boot

1. Power on — the display shows a touch calibration screen
2. Tap the four corner crosshairs with a stylus or fingernail
3. Calibration is saved to SPIFFS flash (never repeats unless you erase flash)

### Boot Sequence (Serial Monitor)

```
[BOOT] Quantum-Secure LoRa Messenger v3.0
[BOOT] Node: ALICE  ID=0x01
[BOOT] Network: QSLM_NET  Freq: 868000000 Hz
[BOOT] Crypto: Kyber-512 KEM + ASCON-128 AEAD
[LORA] Init... OK
[TFT]  OK
[KEM]  Generating Kyber-512 key pair...
[KEM]  Public key (first 8 bytes): 4A 2B 9C D1 ...
[KEM]  Keypair ready. Broadcasting public key in 2 s...
[KEM]  Sent frag 1/4  (244 bytes)
[KEM]  Sent frag 2/4  (244 bytes)
[KEM]  Sent frag 3/4  (244 bytes)
[KEM]  Sent frag 4/4  (68 bytes)
[KEM]  Public key broadcast complete
[BOOT] System ready.
```

### On-Screen Keyboard

```
┌─────────────────────────────────┐
│ ALICE #01  [KYBER+ASCON]  S:3   │  ← status bar
├─────────────────────────────────┤
│  * KEM: SECURE!                 │  ← chat bubbles
│           Me: Hello there →     │
├─────────────────────────────────┤
│ Type your message here...       │  ← text input field
├─────────────────────────────────┤
│  Q  W  E  R  T  Y  U  I  O  P  │
│   A  S  D  F  G  H  J  K  L    │  ← keyboard
│    Z  X  C  V  B  N  M         │
│ [KEY]  [  SPACE  ]  [DEL] [SEND]│
└─────────────────────────────────┘
```

| Button | Action |
|---|---|
| **KEY** | Immediately re-broadcast your Kyber-512 public key to re-establish a new quantum-secure session |
| **SPC** | Insert a space |
| **DEL** | Delete last character |
| **SEND** | Encrypt with ASCON-128 and transmit the message |

### Status Bar

```
ALICE #01   [KYBER+ASCON]   S:7   -95d
  │               │          │      │
  │               │          │      └─ last RSSI (dBm)
  │               │          └─ TX sequence counter
  │               └─ active cipher suite
  └─ node name and hex ID
```

- **Green badge `[KYBER+ASCON]`**: system is using Kyber-derived session keys + ASCON-128 encryption
- **RSSI green** if > −100 dBm, orange if weaker
- Incoming messages show a green `*` lock icon (ASCON tag verified)

### Typing the Special KEY Command

You can also type `KEY` in the text field and press **SEND** to trigger a key re-exchange — useful if you suspect a peer missed your boot broadcast.

---

## Security Architecture Deep Dive

### Kyber-512 Implementation (`kyber512.h`)

The implementation follows the CRYSTALS-Kyber reference spec exactly:

```
1. Key Generation
   seed (64 random bytes from ESP32 TRNG)
       │
       ├─→ SHA3-512(seed) → (ρ, σ)
       │
       ├─→ A = GenMatrix(ρ)       via SHAKE-128 rejection sampling
       ├─→ s ← CBD_η1(σ, 0..k-1) via SHAKE-256 + centered binomial dist.
       ├─→ e ← CBD_η1(σ, k..2k-1)
       │
       └─→ pk = (NTT(A) · NTT(s) + NTT(e), ρ)   [800 bytes]
           sk = (NTT(s), pk, H(pk), z)             [1632 bytes]

2. Encapsulate (run by peer who received pk)
   m (32 random bytes)
       │
       ├─→ m' = H(m)
       ├─→ (K, r) = G(m' ‖ H(pk))    via SHA3-512
       ├─→ ct = IND-CPA-Enc(pk, m'; coins=r)      [768 bytes]
       └─→ ss = SHA3-256(K ‖ H(ct))               [32 bytes]

3. Decapsulate (run by key owner)
   ct → IND-CPA-Dec(sk, ct) → m'
       → (K, r) = G(m' ‖ H(pk))
       → ct' = IND-CPA-Enc(pk, m'; r)
       → if ct == ct': ss = SHA3-256(K ‖ H(ct))   ← match
         else:         ss = SHA3-256(z ‖ H(ct))    ← implicit rejection
```

The **implicit rejection** (Fujisaki-Okamoto transform) means that a forged ciphertext returns a pseudorandom value rather than failing with an error — preventing timing-based CCA attacks.

### ASCON-128 Implementation (`ascon128.h`)

```
State: 320 bits = S[0..4] (five 64-bit words)

Initialisation:
  S = (IV ‖ K ‖ N)  then  pᵃ (12 rounds)  then  S[3,4] ^= K

Associated Data (header bytes 0–8):
  for each 8-byte block: S[0] ^= block,  then  pᵇ (6 rounds)
  S[4] ^= 1   (domain separation)

Encryption (plaintext):
  for each 8-byte block: ct = S[0] ^ pt,  S[0] = ct,  then  pᵇ

Finalisation:
  S[1,2] ^= K,  pᵃ,  S[3,4] ^= K
  tag = S[3] ‖ S[4]   (16 bytes)
```

The 9-byte LoRa header (Network ID, dest, src, type, seq) is fed as **Associated Data** — it is authenticated but not encrypted. This means any tampering with the header is detected by the tag, even though the header travels in plaintext.

### Keccak Implementation (`keccak_tiny.h`)

The Keccak-f[1600] permutation implements the θ, ρ+π, χ, ι steps:
- **θ**: column-parity mixing (XOR with rotated neighbours)
- **ρ+π**: rotation + transposition (combined in one pass for speed)
- **χ**: non-linear AND-NOT S-box (the only non-linear step)
- **ι**: asymmetric round constant injection (breaks symmetry)

24 rounds are applied per permutation call. SHA3 and SHAKE differ only in the domain-separation padding byte (0x06 vs 0x1f) and the output length.

### Anti-Replay Protection

Every packet carries a 32-bit sequence number. Each node maintains a table of `(peer_id, last_accepted_seq)`. A packet with `seq ≤ last_accepted_seq` is silently dropped. This prevents an attacker from recording a valid encrypted packet and replaying it.

### Fallback Mode

Before the Kyber handshake completes (first few seconds after boot), messages are encrypted with `ASCON-128(key = NETWORK_KEY[0..15])`. This is a symmetric pre-shared key — **not** quantum-secure — but it ensures the radio is never transmitting plaintext. The status bar still shows `[KYBER+ASCON]`; you can distinguish secure vs. fallback in the serial log:

```
[TX] seq=5  cipher=ASCON128  key=PSK-FALLBACK   ← before KEM
[TX] seq=6  cipher=ASCON128  key=KYBER-SESSION  ← after KEM
```

---

## Troubleshooting

### Sketch does not compile

| Error | Fix |
|---|---|
| `LoRa.h not found` | Install **LoRa** library by Sandeep Mistry |
| `TFT_eSPI.h not found` | Install **TFT_eSPI** library by Bodmer |
| `esp_system.h not found` | Ensure board is set to **ESP32 Dev Module** (not Arduino Uno etc.) |
| `stack overflow` at runtime | Increase stack in Arduino IDE: **Tools → Core Debug Level → None** and check RAM usage in compile output |
| Sketch too large | Use **Partition Scheme → Huge APP (3MB No OTA)** |

### LoRa radio not found

```
[LORA] Init... FAILED
```

- Check SPI wiring (SCK=18, MISO=19, MOSI=23, NSS=27, RST=25, DIO0=26)
- Ensure the SX1276 module is powered (3.3 V, **not** 5 V)
- Reduce SPI frequency: in `setup()` change `LoRa.setSPIFrequency(125000)` to `62500`

### Display blank or corrupted

- Verify `User_Setup.h` in TFT_eSPI library has the correct driver (`#define ILI9341_DRIVER`) and pin numbers
- Try rotation values 0–3 by changing `tft.setRotation(X)` in `setup()`

### Touch not responding

- Ensure `TOUCH_CS` is defined correctly in `User_Setup.h`
- Delete the calibration file to redo calibration:
  ```cpp
  // Temporarily add this to setup():
  SPIFFS.remove("/TouchCalDat");
  ```

### Kyber key exchange not completing

```
[KEM] All 4 fragments received from node 0x02
[KEM] Encapsulated. Sending response...
```
If you never see the second line on the peer:
- Ensure both nodes use the same `NETWORK_ID` and `NETWORK_FREQ`
- Increase the inter-fragment delay: change `delay(120)` to `delay(200)` in `initiateKyberHandshake()`
- Verify the peer's `LoRa.setSpreadingFactor`, `setSignalBandwidth`, and `setCodingRate4` match

### Messages decrypt as AUTH FAIL

```
[CRYPTO] ASCON Auth FAIL from node 0x02
```
- Nodes are using different `NETWORK_KEY` values — run `keygen.py` and re-flash all nodes
- The Kyber session may not have completed; wait for `KEM: SECURE!` before sending messages
- Check that `NETWORK_ID` matches on both nodes

### Python keygen.py not running

```bash
# Linux / macOS
python3 keygen.py

# Windows (if python3 not found)
python keygen.py

# If neither works, install Python 3 from https://www.python.org
```
