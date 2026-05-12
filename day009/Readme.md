# Day 009 - Hashing: How Passwords Are (and Shouldn't Be) Stored

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Foundations | **Difficulty:** Beginner

---

## 🧠 The Concept

In 2012, LinkedIn was breached.

117 million password hashes were stolen and published online.

Within days, 90% of them were cracked.

The reason? LinkedIn was storing passwords using SHA-1 - unsalted. A hashing algorithm designed for speed, not security.

Today: what hashing actually is, why the wrong choice costs millions of users their passwords, and what every system should be doing instead.

---

## 🔁 What is Hashing?

Hashing is a one-way function. You put data in - you get a fixed-length string out. You cannot reverse it.

```
"password123"  → SHA-256 → ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
"password124"  → SHA-256 → different hash entirely (avalanche effect)
"password123"  → SHA-256 → ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
```

Same input always produces the same output. One character change produces a completely different hash.

**This is different from encryption.** Encryption is reversible - you can decrypt it with a key. Hashing is not - there is no "unhash" operation.

---

## 🗄️ How Password Storage Works (The Right Way)

When you create an account:
```
1. You type: "mypassword"
2. Server hashes it: hash("mypassword") → "5f4dcc3b..."
3. Server stores ONLY the hash - never the plaintext
```

When you log in:
```
1. You type: "mypassword"
2. Server hashes what you typed: hash("mypassword") → "5f4dcc3b..."
3. Server compares to stored hash
4. Match → access granted. No match → denied.
```

The server never needs to know your actual password. It only needs to verify the hash matches.

---

## ⚠️ Why Fast Hashing Algorithms Are Dangerous for Passwords

MD5 and SHA-1 were designed to be fast for file integrity checks, not passwords.

Fast for verification = fast for cracking.

A modern GPU can compute:
```
MD5:    10,000,000,000 hashes/second  (10 billion)
SHA-1:   3,000,000,000 hashes/second  (3 billion)
bcrypt:          15,000 hashes/second  (15 thousand)
```

At 10 billion MD5 hashes per second, every 8-character password (lowercase + numbers) falls in under 2 minutes.

bcrypt at 15,000 hashes/second? That same password takes years.

**Speed is the enemy of password security.**

---

## 🧂 What is a Salt?

A salt is a random string added to the password before hashing.

```
Without salt:
hash("password123") → always the same hash
→ Attacker builds a lookup table (rainbow table) once, cracks everything

With salt:
hash("password123" + "xK9#mP2q") → unique hash for this user
hash("password123" + "aR7$nL5w") → completely different hash for another user
→ Attacker must crack each hash individually - lookup tables useless
```

Even if two users have the same password, their hashes will be different because their salts are different.

Salts are stored alongside the hash - they're not secret, just unique per user.

---

## 🏆 Password Hashing Algorithms Compared

| Algorithm | Speed | Salted | Recommended | Notes |
|-----------|-------|--------|-------------|-------|
| MD5 | ⚡ Very fast | ❌ No | ❌ Never | Broken, collision attacks |
| SHA-1 | ⚡ Fast | ❌ No | ❌ Never | LinkedIn's mistake |
| SHA-256 | ⚡ Fast | ❌ No | ❌ Never for passwords | Fine for file integrity |
| bcrypt | 🐢 Slow | ✅ Yes | ✅ Yes | Adjustable cost factor |
| scrypt | 🐢 Slow | ✅ Yes | ✅ Yes | Memory-hard |
| Argon2id | 🐢 Slow | ✅ Yes | ✅ Best | Won Password Hashing Competition |

**Argon2id is the current gold standard.** It's memory-hard (makes GPU cracking expensive) and time-hard (adjustable iterations). Use it if your stack supports it. Use bcrypt if not.

---

## 🌈 Rainbow Tables

A rainbow table is a precomputed lookup table of hash → plaintext pairs.

```
Hash: 5f4dcc3b5aa765d61d8327deb882cf99 → "password"
Hash: e10adc3949ba59abbe56e057f20f883e → "123456"
Hash: 25d55ad283aa400af464c76d713c07ad → "12345678"
```

Attackers compute these once and store them. Looking up a hash is instant.

**Salting defeats rainbow tables entirely** because the attacker would need a separate rainbow table for every possible salt value.

---

## 💻 The Code — Hash Demo

```python
"""
Day 009 - Password Hashing Demo
100 Days of Cybersecurity by Sudeep Ravichandran

Demonstrates why algorithm choice matters for password security.
Compares MD5, SHA-256, bcrypt, and Argon2 - timing each one.

Usage: python3 hash_demo.py
Requires: pip install bcrypt argon2-cffi
"""

import hashlib
import bcrypt
import time
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


PASSWORD = "mypassword123"


def demo_md5():
    print("=" * 50)
    print("MD5 (NEVER use for passwords)")
    print("=" * 50)
    start = time.perf_counter()
    hashed = hashlib.md5(PASSWORD.encode()).hexdigest()
    elapsed = time.perf_counter() - start
    print(f"Password : {PASSWORD}")
    print(f"Hash     : {hashed}")
    print(f"Time     : {elapsed * 1000:.4f}ms")
    print(f"⚠️  This runs billions of times per second on a GPU.")
    print(f"   Attacker can brute-force this in minutes.\n")


def demo_sha256():
    print("=" * 50)
    print("SHA-256 (fine for file integrity — not passwords)")
    print("=" * 50)
    start = time.perf_counter()
    hashed = hashlib.sha256(PASSWORD.encode()).hexdigest()
    elapsed = time.perf_counter() - start
    print(f"Password : {PASSWORD}")
    print(f"Hash     : {hashed}")
    print(f"Time     : {elapsed * 1000:.4f}ms")
    print(f"⚠️  Also too fast for passwords. LinkedIn used SHA-1 - same problem.\n")


def demo_bcrypt():
    print("=" * 50)
    print("bcrypt (good — slow by design)")
    print("=" * 50)

    # cost factor 12 is a good default — higher = slower = more secure
    start = time.perf_counter()
    hashed = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt(rounds=12))
    elapsed = time.perf_counter() - start

    print(f"Password : {PASSWORD}")
    print(f"Hash     : {hashed[:40]}...")
    print(f"Time     : {elapsed * 1000:.0f}ms")
    print(f"✓  Salt is built in. Cost factor is adjustable as hardware improves.")

    # Verify
    is_valid = bcrypt.checkpw(PASSWORD.encode(), hashed)
    print(f"Verified : {is_valid}\n")


def demo_argon2():
    print("=" * 50)
    print("Argon2id (best - current gold standard)")
    print("=" * 50)
    ph = PasswordHasher(
        time_cost=3,       # iterations
        memory_cost=65536, # 64MB RAM required - GPU cracking is expensive
        parallelism=2,
        hash_len=32
    )

    start = time.perf_counter()
    hashed = ph.hash(PASSWORD)
    elapsed = time.perf_counter() - start

    print(f"Password : {PASSWORD}")
    print(f"Hash     : {hashed[:50]}...")
    print(f"Time     : {elapsed * 1000:.0f}ms")
    print(f"✓  Memory-hard: requires 64MB RAM per attempt.")
    print(f"   GPUs have fast compute but limited memory - this kills GPU cracking.")

    # Verify
    try:
        ph.verify(hashed, PASSWORD)
        print(f"Verified : True")
    except VerifyMismatchError:
        print(f"Verified : False")


def demo_salt():
    print("\n" + "=" * 50)
    print("SALT DEMO - same password, different hashes")
    print("=" * 50)
    print(f"Password: '{PASSWORD}' hashed with bcrypt 3 times:\n")
    for i in range(3):
        hashed = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt())
        print(f"  Hash {i+1}: {hashed[:50]}...")
    print("\n✓  Three completely different hashes - same password.")
    print("   Rainbow tables are useless against salted hashes.")


if __name__ == "__main__":
    demo_md5()
    demo_sha256()
    demo_bcrypt()
    demo_argon2()
    demo_salt()

    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    print("MD5 / SHA-1 / SHA-256 → Never for passwords")
    print("bcrypt                 → Good, widely supported")
    print("Argon2id               → Best, use if possible")
```

**To run:**
```bash
pip install bcrypt argon2-cffi
python3 hash_demo.py
```

---

## 🔑 Key Takeaways

- Hashing is one-way - you verify, you don't decrypt
- Fast algorithms (MD5, SHA-1) are dangerous for passwords - they're too easy to brute-force
- Always use a slow, salted algorithm: bcrypt or Argon2id
- Salts defeat rainbow table attacks by making every hash unique
- LinkedIn's 2012 breach happened because they used unsalted SHA-1 - a completely avoidable mistake

---

## 📚 Resources to Go Deeper
- [HaveIBeenPwned](https://haveibeenpwned.com/) — check if your email appeared in a breach
- [Computerphile - Password Hashing (YouTube)](https://www.youtube.com/watch?v=8ZtInClXe1Q)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

---

## [⬅️ Day 008](../day008/) | [➡️ Day 010](../day010/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*