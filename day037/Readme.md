# Day 037 - Password Cracking: Hashcat & John the Ripper

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

You have a hash. You need the password.

Whether you've dumped `/etc/shadow`, extracted SAM hashes, or found a hash in a database - the next step is cracking it.

Password cracking doesn't "decrypt" hashes - hashing is one-way. Instead, it hashes candidate passwords and compares the result to the target hash. Match found = password recovered.

Two tools dominate: **Hashcat** (GPU-based, fastest) and **John the Ripper** (flexible, great for formats Hashcat doesn't support).

---

## 🔑 Hash Identification

Before cracking - identify the hash type.

```bash
# hashid - identify hash format
hashid '$2y$10$D6mMnZHpBRuEelLMrMKtXe...'
# [+] Blowfish(OpenBSD) [Hashcat Mode: 3200]
# [+] bcrypt

# hash-identifier (Kali)
hash-identifier
# Enter hash → outputs likely types

# Manual identification
# $1$   → MD5 crypt
# $2y$  → bcrypt
# $5$   → SHA-256 crypt
# $6$   → SHA-512 crypt (most modern Linux /etc/shadow)
# 32 hex chars → MD5
# 40 hex chars → SHA-1
# 64 hex chars → SHA-256

# Hashcat example modes:
# 0    → MD5
# 100  → SHA-1
# 1400 → SHA-256
# 1800 → sha512crypt ($6$) - Linux shadow
# 3200 → bcrypt
# 1000 → NTLM (Windows)
# 5600 → NetNTLMv2 (Windows network auth)
# 13100 → Kerberoast (Active Directory)
```

---

## ⚡ Hashcat

GPU-accelerated. The fastest cracker available.

```bash
# Basic syntax
hashcat -m <mode> -a <attack> <hashfile> <wordlist>

# -m = hash mode (0=MD5, 1000=NTLM, 1800=sha512crypt...)
# -a = attack mode (0=dictionary, 3=brute force, 6=hybrid)

# ── Dictionary Attack (most common) ──────────
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000 ntlm_hashes.txt rockyou.txt         # Windows NTLM
hashcat -m 1800 shadow_hashes.txt rockyou.txt        # Linux SHA-512

# ── With Rules (much more effective) ─────────
# Rules mutate wordlist: add numbers, capitalise, substitute chars
hashcat -m 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule

# ── Brute Force ───────────────────────────────
# ?l=lowercase ?u=uppercase ?d=digit ?s=special ?a=all
hashcat -m 0 hashes.txt -a 3 ?d?d?d?d?d?d    # 6-digit PIN
hashcat -m 0 hashes.txt -a 3 ?u?l?l?l?d?d?d?s  # pattern
hashcat -m 0 hashes.txt -a 3 -i --pw-min=6 --pw-max=8 ?a?a?a?a?a?a?a?a

# ── Hybrid Attack ─────────────────────────────
# Wordlist + brute force suffix
hashcat -m 0 hashes.txt -a 6 rockyou.txt ?d?d?d?d  # word + 4 digits
hashcat -m 0 hashes.txt -a 7 ?d?d?d?d rockyou.txt  # 4 digits + word

# ── Useful flags ──────────────────────────────
--show          # show cracked passwords from potfile
--username      # input file has username:hash format
--force         # ignore warnings (use in VMs)
-O              # optimised kernels (faster, some limits)
-w 3            # workload profile (1-4, 3=high)
--status        # show progress during crack
--session name  # save/restore session

# ── Check results ─────────────────────────────
hashcat -m 0 hashes.txt --show
# hash:password pairs
```

---

## 🔨 John the Ripper

More flexible format support. Better for exotic hash types.

```bash
# Auto-detect format and crack
john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Specify format
john hashes.txt --format=md5crypt --wordlist=rockyou.txt
john hashes.txt --format=bcrypt --wordlist=rockyou.txt
john hashes.txt --format=NT --wordlist=rockyou.txt       # NTLM

# Show cracked passwords
john hashes.txt --show

# Incremental (brute force)
john hashes.txt --incremental

# Rules
john hashes.txt --wordlist=rockyou.txt --rules

# List available formats
john --list=formats | grep -i md5

# ── Format helpers ────────────────────────────
# Convert shadow file for John
unshadow /etc/passwd /etc/shadow > combined.txt
john combined.txt --wordlist=rockyou.txt

# Crack ZIP password
zip2john protected.zip > zip_hash.txt
john zip_hash.txt --wordlist=rockyou.txt

# Crack SSH private key passphrase
ssh2john id_rsa > ssh_hash.txt
john ssh_hash.txt --wordlist=rockyou.txt

# Crack PDF password
pdf2john document.pdf > pdf_hash.txt
john pdf_hash.txt --wordlist=rockyou.txt
```

---

## 🌈 Rainbow Tables vs Wordlists vs Rules

```
Rainbow Tables
→ Pre-computed hash:plaintext lookup
→ Fast lookup, huge storage requirement
→ Defeated by salting (Day 9)
→ Tools: RainbowCrack, ophcrack (Windows NTLM)

Wordlists
→ Hash every word, compare
→ rockyou.txt = 14M passwords from real breach
→ SecLists has specialised wordlists
→ Best starting point

Rules
→ Mutate wordlist entries algorithmically
→ "password" → "Password1!" → "p4ssw0rd" → "PASSWORD123"
→ 10x wordlist coverage without 10x storage
→ best64.rule covers most real-world patterns

Custom wordlists
→ CeWL: scrape target website for relevant words
→ Mentalist: generate targeted wordlists from personal info
→ Combine with rules for targeted attacks
```

---

## 🎯 Real-World Workflow

```bash
# Step 1: Identify hash type
hashid '$6$rounds=5000$salt$hash'
# sha512crypt, mode 1800

# Step 2: Quick win - try common passwords first
hashcat -m 1800 shadow.txt /usr/share/wordlists/rockyou.txt -O

# Step 3: Add rules if wordlist fails
hashcat -m 1800 shadow.txt rockyou.txt -r best64.rule -O

# Step 4: Custom wordlist from target info
cewl https://targetcompany.com -w company_words.txt
hashcat -m 1800 shadow.txt company_words.txt -r best64.rule

# Step 5: Targeted patterns (if you know password policy)
# "Must be 8+ chars, 1 uppercase, 1 number, 1 special"
hashcat -m 1800 shadow.txt -a 3 ?u?l?l?l?l?d?d?s

# Step 6: Check results
hashcat -m 1800 shadow.txt --show
```

---

## 💻 The Code - Hash Cracking Helper

```python
"""
Day 037 - Hash Cracking Helper
100 Days of Cybersecurity by Sudeep Ravichandran

Identifies hash types, generates hashcat commands,
and creates targeted wordlists.

Usage: python3 crack_guide.py <hash>
Requires: pip install hashid
"""

import sys
import hashlib
import re


HASHCAT_MODES = {
    "MD5":              ("0",    "Fast - try first"),
    "SHA-1":            ("100",  "Fast - try first"),
    "SHA-256":          ("1400", "Fast - try first"),
    "SHA-512":          ("1700", "Fast - try first"),
    "bcrypt":           ("3200", "Slow - GPU barely helps"),
    "sha512crypt":      ("1800", "Linux /etc/shadow - slow"),
    "md5crypt":         ("500",  "Linux /etc/shadow (old)"),
    "NTLM":             ("1000", "Windows - very fast"),
    "NetNTLMv2":        ("5600", "Windows network auth"),
    "Kerberoast":       ("13100","Active Directory"),
    "WPA-PBKDF2-PMKID": ("22000","WiFi - slow"),
}


def identify_hash(hash_str):
    """Basic hash identification by length and prefix."""
    h = hash_str.strip()
    results = []

    if h.startswith("$2y$") or h.startswith("$2b$") or h.startswith("$2a$"):
        results.append("bcrypt")
    elif h.startswith("$6$"):
        results.append("sha512crypt")
    elif h.startswith("$5$"):
        results.append("sha256crypt")
    elif h.startswith("$1$"):
        results.append("md5crypt")
    elif re.match(r'^[a-fA-F0-9]{32}$', h):
        results.append("MD5")
    elif re.match(r'^[a-fA-F0-9]{40}$', h):
        results.append("SHA-1")
    elif re.match(r'^[a-fA-F0-9]{64}$', h):
        results.append("SHA-256")
    elif re.match(r'^[a-fA-F0-9]{128}$', h):
        results.append("SHA-512")
    else:
        results.append("Unknown - use hashid or hash-identifier")

    return results


def generate_hashcat_commands(hash_type, hash_file="hashes.txt"):
    """Generate recommended hashcat commands for a hash type."""
    if hash_type not in HASHCAT_MODES:
        return []

    mode, note = HASHCAT_MODES[hash_type]
    commands = [
        f"# {hash_type} - {note}",
        f"hashcat -m {mode} {hash_file} /usr/share/wordlists/rockyou.txt",
        f"hashcat -m {mode} {hash_file} /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule",
        f"hashcat -m {mode} {hash_file} --show   # view results",
    ]
    return commands


def quick_hash(text, algorithm="md5"):
    """Hash a string - for testing/comparison."""
    h = hashlib.new(algorithm)
    h.update(text.encode())
    return h.hexdigest()


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 crack_guide.py <hash>")
        print("Example: python3 crack_guide.py 5f4dcc3b5aa765d61d8327deb882cf99")
        print("\nOr generate a test hash:")
        print("  python3 crack_guide.py --hash 'password' md5")
        sys.exit(1)

    if sys.argv[1] == "--hash":
        text = sys.argv[2] if len(sys.argv) > 2 else "password"
        algo = sys.argv[3] if len(sys.argv) > 3 else "md5"
        print(f"  {algo}: {quick_hash(text, algo)}")
        return

    target_hash = sys.argv[1]

    print("=" * 55)
    print("  Hash Cracking Helper - Day 037")
    print("  100 Days of Cybersecurity")
    print("=" * 55)
    print(f"\n  Hash: {target_hash[:50]}...")

    types = identify_hash(target_hash)
    print(f"\n[+] Identified as: {', '.join(types)}")

    for ht in types:
        cmds = generate_hashcat_commands(ht)
        if cmds:
            print(f"\n[+] Hashcat commands for {ht}:")
            for cmd in cmds:
                print(f"    {cmd}")

    print(f"\n[+] John the Ripper:")
    print(f"    john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt")
    print(f"    john hash.txt --show")

    print(f"\n[+] Wordlists to try:")
    print(f"    /usr/share/wordlists/rockyou.txt          (14M passwords)")
    print(f"    /usr/share/seclists/Passwords/            (specialised lists)")
    print(f"    cewl https://target.com -w custom.txt     (target-specific)")


if __name__ == "__main__":
    main()
```

**To run:**
```bash
pip install hashid
python3 crack_guide.py 5f4dcc3b5aa765d61d8327deb882cf99
```

---

## 🔑 Key Takeaways

- Never try to "decrypt" hashes - crack by hashing candidates and comparing
- Identify the hash type first - wrong mode wastes time
- Rockyou.txt + best64.rule covers the majority of real-world passwords
- Rules are more efficient than larger wordlists - same coverage, less storage
- John the Ripper handles more formats (ZIP, SSH keys, PDFs) - use it for those
- Bcrypt/Argon2 are slow by design - GPU acceleration barely helps

---

## 📚 Resources
- [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [SecLists password wordlists](https://github.com/danielmiessler/SecLists/tree/master/Passwords)
- [CrackStation (online - quick wins)](https://crackstation.net/)

---

## [⬅️ Day 036](../day036/) | [➡️ Day 038](../day038/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*