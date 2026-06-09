"""
Day 037 - Hash Cracking Helper
100 Days of Cybersecurity by Sudeep Ravichandran

Identifies hash types, generates hashcat commands,
and creates targeted wordlists.

Usage: python3 crack_guide.py <hash>
       python3 crack_guide.py --hash 'password' md5
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


def generate_commands(hash_type, hash_file="hashes.txt"):
    if hash_type not in HASHCAT_MODES:
        return []

    mode, note = HASHCAT_MODES[hash_type]
    return [
        f"# {hash_type} (mode {mode}) - {note}",
        f"hashcat -m {mode} {hash_file} /usr/share/wordlists/rockyou.txt",
        f"hashcat -m {mode} {hash_file} rockyou.txt -r /usr/share/hashcat/rules/best64.rule",
        f"hashcat -m {mode} {hash_file} --show",
    ]


def quick_hash(text, algorithm="md5"):
    try:
        h = hashlib.new(algorithm)
        h.update(text.encode())
        return h.hexdigest()
    except ValueError:
        return f"Unknown algorithm: {algorithm}"


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 crack_guide.py <hash>")
        print("       python3 crack_guide.py --hash 'text' [algorithm]")
        sys.exit(1)

    if sys.argv[1] == "--hash":
        text = sys.argv[2] if len(sys.argv) > 2 else "password"
        algo = sys.argv[3] if len(sys.argv) > 3 else "md5"
        result = quick_hash(text, algo)
        print(f"\n  {algo}('{text}') = {result}\n")
        return

    target = sys.argv[1]

    print("=" * 55)
    print("  Hash Cracking Helper - Day 037")
    print("  100 Days of Cybersecurity")
    print("=" * 55)
    print(f"\n  Hash: {target[:55]}")

    types = identify_hash(target)
    print(f"\n[+] Likely type: {', '.join(types)}")

    for ht in types:
        cmds = generate_commands(ht)
        if cmds:
            print(f"\n[+] Hashcat commands:")
            for cmd in cmds:
                print(f"    {cmd}")

    print(f"\n[+] John the Ripper:")
    print(f"    john hash.txt --wordlist=rockyou.txt")
    print(f"    john hash.txt --show")
    print(f"\n[+] Online lookup (quick wins):")
    print(f"    https://crackstation.net")
    print(f"    https://hashes.com/en/decrypt/hash")


if __name__ == "__main__":
    main()