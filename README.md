# Secure Client-Server Communication Protocol

A Python implementation of a secure communication system built from scratch, covering AES-CBC symmetric encryption, Diffie-Hellman key exchange, RSA-128 digital signatures, and a custom handshake protocol over TCP.

**Course:** Applied Cryptography — ENCS4320  
Department of Electrical and Computer Engineering  
**Team:** Lara Foqaha · Maysa Khanfar

---

## Overview

The project is implemented in two phases:

**Phase I** establishes encrypted communication using a static AES-128 key derived from the student ID.

**Phase II** replaces the static key with a dynamically negotiated session key, established through an authenticated Diffie-Hellman handshake using RSA digital signatures.

---

## Architecture

| File | Responsibility |
|------|----------------|
| `crypto.py` | AES-128 (from scratch), CBC mode, PKCS#7 padding, IV derivation |
| `dh.py` | Diffie-Hellman key generation, shared secret computation, session key derivation |
| `rsa128.py` | RSA-128 key generation (Miller-Rabin primality), signing, verification |
| `server.py` | TCP server — handshake handling, decryption, message loop |
| `client.py` | TCP client — handshake initiation, encryption, message sending |

---

## Phase I — AES-CBC Encrypted Communication

The client encrypts messages using AES-128 in CBC mode before transmission. The server decrypts them using the same key.

**Key derivation:** `AES_Key = MD5(student_id)` → 16-byte key  
**Reference IV:** `SHA256(student_id)[:16]` — incremented per message using a counter to guarantee IV freshness

The IV is transmitted alongside the ciphertext (`IV ‖ ciphertext`) and is not secret. Wireshark captures confirm no plaintext is visible on the wire.

---

## Phase II — Authenticated Key Exchange

Before any encrypted data is sent, the client and server perform a handshake:

1. **Client** generates an RSA-128 key pair and a DH private value `a`, computes `A = g^a mod p`, signs it with its RSA private key, and sends `CLIENT_HELLO` containing: client ID, RSA public key (n, e), DH value A, and signature.

2. **Server** verifies the client's signature, generates its own DH private value `b`, computes `B = g^b mod p`, signs it, and responds with `SERVER_HELLO`.

3. **Client** verifies the server's signature.

4. Both sides independently compute the shared secret and derive: `Session_Key = SHA256(shared_secret)[:16]`

The session key is never transmitted. Each session uses fresh ephemeral DH keys, providing **perfect forward secrecy**.

**DH parameters:**
```
p = F7E75FDC469067FFDC4E847C51F452DF (128-bit prime)
g = 2
```

---

## Security Properties

| Property | Mechanism | Validation |
|----------|-----------|------------|
| Confidentiality | AES-128 CBC with fresh IV per message | Wireshark shows only ciphertext payloads |
| Integrity | PKCS#7 padding validation on decryption | Tampered ciphertext causes padding error → server replies ERROR |
| Authenticity | RSA signatures over DH public values | Bad signature raises `BAD CLIENT SIGNATURE` and closes connection |
| Forward Secrecy | Ephemeral DH keys per session | Each session produces a different session key |

---

## Running

Start the server first, then the client in a separate terminal:

```bash
python server.py
python client.py
```

Both run on `127.0.0.1:5005`. The client prompts for messages; enter `q` to quit.

---

## Requirements

- Python 3.x
- Standard library only (`socket`, `struct`, `hashlib`, `secrets`)
- No external cryptography libraries — AES, RSA, and DH are implemented from scratch
