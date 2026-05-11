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
from cryptography.hazmat.primitives import hashes


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