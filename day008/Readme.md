# Day 008 - Cryptography 101: Symmetric vs Asymmetric

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Foundations | **Difficulty:** Beginner

---

## 🧠 The Concept

Cryptography is the backbone of everything secure on the internet.

Your HTTPS connection. Your WhatsApp messages. Your bank transfer. Your SSH session into a server.

All of it relies on two fundamental ideas: **symmetric** and **asymmetric** encryption. Understanding the difference and when each is used is non-negotiable for any security professional.

---

## 🔑 Symmetric Encryption

One key. Does everything. Encrypts and decrypts.

```
Plaintext → [ENCRYPT with Key] → Ciphertext → [DECRYPT with Key] → Plaintext
```

Think of it like a padlock where the same key locks and unlocks it.

**Common algorithms:**
| Algorithm | Key Size | Status |
|-----------|----------|--------|
| AES-128 | 128-bit | ✅ Secure |
| AES-256 | 256-bit | ✅ Secure (gold standard) |
| 3DES | 168-bit | ⚠️ Legacy, being phased out |
| DES | 56-bit | ❌ Broken - never use |
| RC4 | Variable | ❌ Broken - never use |

**AES-256 is the standard.** Used in military communications, banking, VPNs, and disk encryption. At current computing power, brute-forcing AES-256 would take longer than the age of the universe.

**The problem with symmetric encryption:**

How do you securely share the key in the first place?

If Alice wants to send Bob an encrypted message, she needs to give Bob the key. But if an attacker is watching the network, they intercept the key too. Now they can decrypt everything.

This is called the **key distribution problem**. It's why symmetric encryption alone isn't enough.

---

## 🔐 Asymmetric Encryption

Two keys. A mathematically linked pair.

```
Public Key  → share with everyone, used to ENCRYPT
Private Key → keep secret, used to DECRYPT
```

What one key encrypts, only the other can decrypt.

```
Alice encrypts with Bob's PUBLIC key
      ↓
Only Bob's PRIVATE key can decrypt it
      ↓
Even Alice can't decrypt what she just sent
```

The magic: you can publish your public key to the entire world. Anyone can use it to send you a secret message. Only you can read it.

**Common algorithms:**
| Algorithm | Use Case | Status |
|-----------|----------|--------|
| RSA-2048 | Key exchange, signatures | ✅ Secure |
| RSA-4096 | High-security signatures | ✅ Very secure |
| ECC (P-256) | Efficient key exchange | ✅ Secure, faster than RSA |
| Diffie-Hellman | Key exchange | ✅ Secure |
| DSA | Digital signatures | ⚠️ Being replaced by ECDSA |

**The problem with asymmetric encryption:**

It's slow. Orders of magnitude slower than symmetric encryption.

Encrypting a large file with RSA would take forever compared to AES.

---

## 🤝 How They Work Together - The Hybrid Approach

Real-world systems use both. This is how TLS (HTTPS) works:

```
Step 1: Asymmetric encryption is used to securely exchange a key
        Browser uses server's public key to send a random secret
              ↓
Step 2: Both sides derive the same symmetric key from that secret
              ↓
Step 3: All actual data is encrypted with that symmetric key (AES)
              ↓
Result: Security of asymmetric + speed of symmetric
```

This is why HTTPS is both secure *and* fast. Best of both worlds.

---

## ✍️ Digital Signatures - Proving Identity

Asymmetric encryption works in reverse for signatures:

```
Sign:   Hash the message → Encrypt hash with PRIVATE key → Signature
Verify: Decrypt signature with PUBLIC key → Compare to message hash
```

If the hashes match, the message wasn't tampered with, and it really came from who they say.

Used in: code signing, SSL certificates, email (PGP/S-MIME), cryptocurrency transactions.

---

## ⚠️ Common Cryptography Mistakes

| Mistake | Consequence |
|---------|-------------|
| Using DES or RC4 | Data can be decrypted by attackers |
| Hardcoding keys in source code | Keys exposed in GitHub repos daily |
| Short RSA keys (< 2048-bit) | Factorable with modern hardware |
| Using ECB mode with AES | Identical plaintext blocks produce identical ciphertext — patterns leak |
| Rolling your own crypto | Almost always broken. Use established libraries. |

The last one is the most important rule in cryptography:

**Never roll your own crypto.**

Use `cryptography` in Python, `OpenSSL`, or `libsodium`. Smart people spent decades building these libraries. Don't try to reinvent them.

---

## 💻 The Code - Crypto Basics Demo

```python
"""
Day 008 - Cryptography Basics Demo
100 Days of Cybersecurity by Sudeep Ravichandran

Demonstrates symmetric (AES) and asymmetric (RSA) encryption
with the Python cryptography library.

Usage: python3 crypto_basics.py
Requires: pip install cryptography
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


# ─────────────────────────────────────────────
# PART 1: Symmetric Encryption (AES via Fernet)
# ─────────────────────────────────────────────

def symmetric_demo():
    print("=" * 50)
    print("SYMMETRIC ENCRYPTION (AES)")
    print("=" * 50)

    # Generate a symmetric key
    key = Fernet.generate_key()
    cipher = Fernet(key)
    print(f"Key generated: {key[:20]}... (keep this secret!)")

    # Encrypt a message
    message = b"This is a secret message"
    ciphertext = cipher.encrypt(message)
    print(f"\nOriginal : {message.decode()}")
    print(f"Encrypted: {ciphertext[:40]}...")

    # Decrypt it back
    decrypted = cipher.decrypt(ciphertext)
    print(f"Decrypted: {decrypted.decode()}")
    print("\n✓ Same key encrypted AND decrypted - that's symmetric.")


# ─────────────────────────────────────────────
# PART 2: Asymmetric Encryption (RSA)
# ─────────────────────────────────────────────

def asymmetric_demo():
    print("\n" + "=" * 50)
    print("ASYMMETRIC ENCRYPTION (RSA)")
    print("=" * 50)

    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    print("RSA-2048 key pair generated.")
    print("Public key  → share with everyone")
    print("Private key → never share this")

    # Encrypt with PUBLIC key
    message = b"Secret message for Bob"
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"\nOriginal : {message.decode()}")
    print(f"Encrypted with public key: {ciphertext[:30]}...")

    # Decrypt with PRIVATE key
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"Decrypted with private key: {decrypted.decode()}")
    print("\n✓ Public key encrypted, private key decrypted - that's asymmetric.")


# ─────────────────────────────────────────────
# PART 3: Digital Signature
# ─────────────────────────────────────────────

def signature_demo():
    print("\n" + "=" * 50)
    print("DIGITAL SIGNATURES")
    print("=" * 50)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    message = b"I authorise this transaction: $1000 to Alice"

    # Sign with PRIVATE key
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print(f"Message  : {message.decode()}")
    print(f"Signature: {signature[:30]}...")

    # Verify with PUBLIC key
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("\n✓ Signature valid - message is authentic and untampered.")
    except Exception:
        print("\n✗ Signature invalid - message was tampered with!")


if __name__ == "__main__":
    symmetric_demo()
    asymmetric_demo()
    signature_demo()
```

**To run:**
```bash
pip install cryptography
python3 crypto_basics.py
```

---

## 🔑 Key Takeaways

- Symmetric = one key, fast, great for bulk data but key sharing is the problem
- Asymmetric = two keys, slow, solves the key distribution problem
- Real systems (TLS/HTTPS) use both together - asymmetric to share a key, symmetric to encrypt data
- Never use DES, RC4, or ECB mode
- Never write your own crypto - use established libraries

---

## 📚 Resources to Go Deeper
- [Computerphile - Symmetric vs Asymmetric (YouTube)](https://www.youtube.com/watch?v=GSIDS_lvRv4)
- [Cryptography library for Python](https://cryptography.io/en/latest/)
- [Crypto101 - free crypto book](https://crypto101.io/)

---

## [⬅️ Day 007](../day007/) | [➡️ Day 009](../day009/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*