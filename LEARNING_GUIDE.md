# Learning Guide: Quantum-Secure LoRa Messenger

**A simplified guide** — builds from first principles so anyone can follow, regardless of background.

This guide explains how two small devices (like walkie-talkies, but with a screen and keyboard) can send messages that **even a future quantum computer cannot crack**. It walks through what “encryption” and “key exchange” mean, why today’s internet security might break in the future, and how this project addresses that — in plain language, with the same ideas that underpin post-quantum standards used in industry and research.

---

## Table of Contents

1. [The Big Idea: Sending a Secret Message](#1-the-big-idea-sending-a-secret-message)
2. [What Is Encryption?](#2-what-is-encryption)
3. [The Key Problem: How Do We Share the Key?](#3-the-key-problem-how-do-we-share-the-key)
4. [Why “Quantum” Changes Everything](#4-why-quantum-changes-everything)
5. [Our Solution: Kyber + ASCON](#5-our-solution-kyber--ascon)
6. [Step by Step: What Actually Happens](#6-step-by-step-what-actually-happens)
7. [Putting It All Together](#7-putting-it-all-together)
8. [Glossary](#8-glossary)
9. [Want to Go Deeper?](#9-want-to-go-deeper)

---

## 1. The Big Idea: Sending a Secret Message

Imagine two friends, **Alex** and **Sam**, each holding a small device with a screen and a keyboard. They are far apart (different rooms, or different buildings). They can’t shout — they can only send **radio waves** (like Wi‑Fi or walkie-talkies) between the devices.

- **Problem:** Anyone with a radio receiver could listen in and read their messages.
- **Goal:** Only Alex and Sam should be able to read what they send. Everyone else should see only gibberish.

That’s exactly what this project does: the devices **scramble** the message before sending it, and **only the two devices know how to unscramble it**. The scrambling is called **encryption**, and the “recipe” to unscramble is called the **key**.

---

## 2. What Is Encryption?

**Encryption** means turning readable text (like “Meet me at 3”) into unreadable data (like `a8#kL9$x2...`) using a **key**. If you have the key, you can reverse the process and get the original message back. If you don’t have the key, it looks like random noise.

### A Simple Analogy

- **Message** = a note you wrote on paper  
- **Key** = a secret rule (e.g. “replace every letter with the next one in the alphabet”)  
- **Encryption** = applying that rule so the note becomes “Nffu nf bu 3”  
- **Decryption** = applying the rule in reverse so “Nffu nf bu 3” becomes “Meet me at 3”  

In real cryptography we use math and computers so the rule is incredibly hard to guess. In this project we use **ASCON-128**: a modern cipher that scrambles the message in a way that is practically impossible to undo without the correct key.

### Why the Key Must Stay Secret

- If someone steals the key, they can read every message.
- So we never send the key over the radio in plain form. We only send **encrypted** messages.
- The hard part is: **how do Alex and Sam get the same key if they’ve never met and can only talk over the radio?** That’s the next section.

---

## 3. The Key Problem: How Do We Share the Key?

If Alex and Sam could meet in person, they could agree on a key secretly and remember it. But in this project they **only** have the radio. So we need a way to **agree on a secret key over the radio** even though eavesdroppers are listening.

### How the Internet Usually Does It (RSA / ECDH)

On the normal internet, we use **public-key cryptography**:

- One person has a **public key** (like a padlock) and a **private key** (the key that opens that padlock).
- They can give the padlock (public key) to anyone. Nobody can open it without the private key.
- So: Sam sends Alex a padlock. Alex puts the secret key inside a box and locks it with that padlock, then sends the box back. Only Sam has the key to the padlock, so only Sam can open the box and get the secret key.

The math behind this (things like **RSA** or **ECDH**) relies on problems that are **very hard for normal computers** — like factoring huge numbers or solving “discrete logarithm” problems. For decades that has been safe. But **quantum computers** change that.

---

## 4. Why “Quantum” Changes Everything

### What Is a Quantum Computer?

A **quantum computer** uses the weird rules of quantum physics (superposition, entanglement) to do some kinds of math **much faster** than a normal computer. They’re still rare and expensive, but labs and companies are building them.

### The Danger: Shor’s Algorithm

In the 1990s, a mathematician named **Peter Shor** showed that a large enough quantum computer could solve:

- **Factoring big numbers** (the hard part of RSA)
- **Discrete logarithm** (the hard part of ECDH)

in a reasonable time. So **every key that was ever exchanged using RSA or ECDH could one day be recovered** by someone who recorded the traffic and later gets a quantum computer. That’s called **“harvest now, decrypt later.”**

### What Stays Safe?

- **Symmetric encryption** (like AES or ASCON) where both sides already share a key: a quantum computer only makes it about **half as hard** (Grover’s algorithm), so using a **long enough key** (e.g. 128 or 256 bits) keeps it safe.
- **New “post-quantum” key exchange** that doesn’t rely on factoring or discrete log. Instead it uses other hard problems that **quantum computers don’t speed up much**. That’s what we use in this project.

---

## 5. Our Solution: Kyber + ASCON

We use **two** building blocks:

| Part | Name | Job |
|------|------|-----|
| **Key agreement** | **Kyber-512** | Lets the two devices agree on a **secret key** over the radio in a way that is safe even from a future quantum computer. |
| **Message scrambling** | **ASCON-128** | Uses that secret key to **encrypt** each message and to **check** that nobody tampered with it (authenticated encryption). |

### Why Two Pieces?

- **Kyber** is for **agreeing on a key** once (or when you press “KEY”). It’s slower and sends more data (hundreds of bytes), so we don’t use it for every single message.
- **ASCON** is for **scrambling messages** once both sides have the same key. It’s fast and only adds a small amount of extra data per message.

So the flow is: **Kyber gives both devices the same secret key → then ASCON uses that key to encrypt and authenticate every message.**

---

## 6. Step by Step: What Actually Happens

Here’s the flow in simple order. You can follow along while watching the device or the serial monitor.

### Phase A: Boot and Key Generation (Once per Power-On)

1. **Device turns on.**  
   Screen and touch come up. If it’s the first time, you calibrate the touch (tap the corners).

2. **Device creates a Kyber key pair.**  
   It uses random numbers from the chip (hardware TRNG) to create:
   - A **public key** (like a padlock) — 800 bytes. Safe to share.
   - A **secret key** (like the key to that padlock) — 1632 bytes. Never leaves the device.

3. **About 2 seconds later**, the device **broadcasts** its public key over the radio in **4 small pieces** (because one LoRa packet can’t hold 800 bytes at once).  
   So: “Here is my padlock.” Anyone on the same channel can receive it.

### Phase B: Key Exchange (When the Other Device Is Listening)

4. **The other device receives the 4 pieces** and glues them back into the full public key.

5. **That device runs Kyber “Encapsulate.”**  
   It takes the public key (the padlock) and:
   - Generates a random **shared secret** (32 bytes). This will become the key for ASCON.
   - Produces a **ciphertext** (768 bytes) that only the **first** device can “open” with its secret key.  
   So: “I’m putting the shared secret in a box and locking it with your padlock.”

6. **The second device sends that ciphertext back** (again in 4 fragments) and **saves** the shared secret as the ASCON key for the first device.

7. **The first device receives the 4 pieces**, glues them into the ciphertext, and runs Kyber “Decapsulate” with its **secret key**.  
   It recovers the **same** 32-byte shared secret.  
   So: “I opened the box with my key. Now I have the same secret you have.”

8. **Both devices now have the same 32 bytes.**  
   They use the **first 16 bytes** as the **ASCON key** for all messages between them. The key exchange is **post-quantum safe** because Kyber doesn’t rely on factoring or discrete log.

### Phase C: Sending Messages (Every Time Someone Types and Presses SEND)

9. **You type a message and press SEND.**

10. **The device:**
    - Picks a **random 16-byte nonce** (number used once) from the hardware random generator.
    - **Encrypts** the message with **ASCON-128** using: the agreed key, the nonce, and the packet header (so the header is authenticated too).
    - Sends over the radio: header + nonce + encrypted message + a **tag** (16 bytes) that proves the message wasn’t changed.

11. **The other device:**
    - Receives the packet.
    - **Decrypts** with ASCON using the same key and the nonce from the packet.
    - **Checks the tag.** If it’s wrong, someone tampered or the key is wrong → message is thrown away. If it’s right → message is shown on screen.

From here on, every message is encrypted and checked this way until someone presses **KEY** again to do a new key exchange.

---

## 7. Putting It All Together

A single picture of the whole story:

```
  ALEX's DEVICE                    RADIO (anyone can listen)              SAM's DEVICE

  1. Boot → create Kyber key pair
     (public key + secret key)

  2. Broadcast public key  ──────────→  (4 packets)  ──────────→  3. Receive; glue 4 pieces
     "Here's my padlock"                                              → full public key

                                                                     4. Kyber ENCAPSULATE
                                                                        → shared secret (keep)
                                                                        → ciphertext (send back)

  5. Receive ciphertext   ←──────────  (4 packets)   ←──────────  6. Send ciphertext
     (4 pieces)                                                                  

  6. Kyber DECAPSULATE
     → same shared secret
     (first 16 bytes = ASCON key)

  7. Both have same ASCON key ✓

  ─── Now every message is encrypted with ASCON ───

  8. Type "Hi!" → ASCON encrypt  ───→  (encrypted blob)  ───→  9. ASCON decrypt → "Hi!"
     with key + random nonce                                      check tag → show on screen
```

**Takeaways:**

- **Kyber** = post-quantum way to get the same secret key on both devices over the radio.
- **ASCON** = way to encrypt every message and detect tampering using that key.
- **Nonce** = random value per message so the same text encrypted twice looks different.
- **Tag** = short “signature” so the receiver knows the message wasn’t changed.

---

## 8. Glossary

| Term | Meaning |
|------|--------|
| **Encryption** | Scrambling a message so only someone with the key can read it. |
| **Decryption** | Unscrambling an encrypted message using the key. |
| **Key** | The secret value that controls how encryption/decryption works. |
| **Symmetric encryption** | Same key is used to encrypt and decrypt (e.g. ASCON, AES). |
| **Public key** | A value you can share; used to lock or encrypt something so only the holder of the matching private key can open it. |
| **Private/secret key** | The value you never share; used to unlock or decrypt what was locked with your public key. |
| **Key exchange** | A way for two parties to agree on a shared secret key even if others are listening. |
| **Post-quantum** | Safe against an attacker who has a large quantum computer (e.g. Kyber). |
| **KEM** | Key Encapsulation Mechanism — a way to send a shared secret by “wrapping” it so only the right party can “unwrap” it (e.g. Kyber). |
| **Nonce** | “Number used once” — a random value that makes each encryption different even for the same message. |
| **Tag** | A short extra piece of data that proves the message wasn’t changed (authenticated encryption). |
| **LoRa** | A long-range, low-power radio technology used by our devices to send packets. |
| **Fragment** | One of several pieces a large block of data (e.g. public key or ciphertext) is split into so it fits in small radio packets. |

---

## 9. Want to Go Deeper?

- **NIST Post-Quantum Cryptography:**  
  The US standards body ran a competition to choose post-quantum schemes. Kyber (ML-KEM) was selected. You can search for “NIST PQC” or “FIPS 203” for official info.

- **ASCON:**  
  Chosen by NIST for lightweight encryption. Search “NIST lightweight cryptography ASCON.”

- **LoRa:**  
  Search “LoRa modulation” or “LoRaWAN” to see how the radio part works.

- **Try it yourself:**  
  Change `MY_NODE_ID` and `MY_NODE_NAME` in `network_keys.h`, flash two devices, and watch the Serial Monitor while they do the key exchange and send messages. You’ll see the same steps as in this guide.

---

*This learning guide was written for the Quantum-Secure LoRa Messenger project.*
