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
    print("SHA-256 (fine for file integrity - not passwords)")
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
    print("bcrypt (good - slow by design)")
    print("=" * 50)

    # cost factor 12 is a good default - higher = slower = more secure
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