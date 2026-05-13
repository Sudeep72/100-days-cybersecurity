# Day 010 - PKI & Certificates: How HTTPS Actually Works

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Foundations | **Difficulty:** Beginner

---

## 🧠 The Concept

You open your bank's website.

There's a padlock in the address bar. Your browser says "Connection is secure."

But how does your browser actually know it's talking to your real bank and not an attacker pretending to be your bank?

That padlock is backed by an entire system called Public Key Infrastructure (PKI). Today we break it down.

---

## 🔐 The Problem PKI Solves

From Day 8, we know asymmetric encryption uses a public/private key pair.

But here's the gap: how do you know the public key you received actually belongs to who you think it does?

```
You want to connect to yourbank.com
An attacker intercepts your connection
Attacker sends you THEIR public key, claiming it's the bank's

You encrypt your data with the attacker's key
Attacker decrypts it
Attacker re-encrypts it with the real bank's key
Forwards it on

You think you're talking to the bank.
You're not.
```

This is a Man-in-the-Middle attack. PKI is what stops it.

---

## 🏛️ The Three Pieces of PKI

### 1. Digital Certificates
A digital certificate is a file that binds a public key to an identity.

It contains:
```
Subject:     yourbank.com
Public Key:  [the bank's actual public key]
Issuer:      DigiCert Inc (a trusted Certificate Authority)
Valid From:  2024-01-01
Valid Until: 2025-01-01
Signature:  [DigiCert's digital signature proving this is real]
```

Think of it like a passport - issued by a trusted authority, contains your identity, and has tamper-evident features.

---

### 2. Certificate Authorities (CAs)
A Certificate Authority is a trusted organisation that issues and signs certificates.

They verify that `yourbank.com` actually belongs to the bank before signing the certificate.

Major CAs: DigiCert, Let's Encrypt, Comodo, GlobalSign, Sectigo

Your browser and OS come pre-loaded with a list of ~150 trusted root CAs. If a certificate is signed by one of them, it's trusted.

```
Root CA (DigiCert)
    └── Intermediate CA
            └── yourbank.com certificate
```

This chain is called the **certificate chain of trust**.

---

### 3. Certificate Revocation
What happens if a certificate is compromised before it expires?

Two mechanisms exist:
- **CRL (Certificate Revocation List)** - a published list of revoked certificates. Browsers download and check it.
- **OCSP (Online Certificate Status Protocol)** - browser asks the CA in real time: "Is this certificate still valid?"

---

## 🤝 The TLS Handshake - Step by Step

This is what happens every time you visit an HTTPS site:

```
1. Client Hello
   Browser → Server: "I support TLS 1.3, here are my cipher suites"

2. Server Hello + Certificate
   Server → Browser: "Here's my certificate (signed by DigiCert)"

3. Certificate Verification
   Browser checks:
   ✓ Is the certificate signed by a trusted CA?
   ✓ Is the domain name on the cert the same as the site I'm visiting?
   ✓ Is the certificate expired?
   ✓ Has it been revoked?

4. Key Exchange
   Browser and server use asymmetric crypto to agree on a
   shared symmetric session key (without sending it directly)

5. Encrypted Channel Opens
   All further communication uses AES symmetric encryption
   (fast, secure, session-specific)
```

The whole handshake takes milliseconds. You never see it.

---

## ⚠️ Certificate-Based Attacks

| Attack | What Happens |
|--------|-------------|
| Fake CA | Attacker tricks an OS into trusting a rogue CA - can issue valid-looking certs for any domain |
| Certificate Pinning Bypass | App is supposed to only trust a specific cert - attacker bypasses the check |
| Expired Certificate | Site forgets to renew - users see scary warnings, may proceed anyway |
| Wildcard Cert Compromise | `*.company.com` cert stolen - attacker can impersonate any subdomain |
| Let's Encrypt Abuse | Attackers get valid HTTPS certs for phishing sites - padlock ≠ safe |

That last one is critical:

**The padlock means the connection is encrypted. It does NOT mean the site is legitimate.**

A phishing site at `paypa1.com` can have a valid HTTPS certificate. Your connection is encrypted to a criminal's server.

---

## 🔍 Reading a Real Certificate

You can inspect any website's certificate right now:

**In Chrome/Firefox:**
1. Click the padlock → "Connection is secure"
2. Click "Certificate is valid"
3. Read the issuer, validity dates, and Subject Alternative Names (SANs)

**In terminal:**
```bash
# View a site's full certificate chain
openssl s_client -connect google.com:443 -showcerts

# View certificate details
echo | openssl s_client -connect google.com:443 2>/dev/null \
  | openssl x509 -noout -text

# Check expiry date only
echo | openssl s_client -connect google.com:443 2>/dev/null \
  | openssl x509 -noout -dates

# Check who issued the certificate
echo | openssl s_client -connect google.com:443 2>/dev/null \
  | openssl x509 -noout -issuer -subject
```

---

## 💡 Key Takeaways

- PKI solves the "how do I know this public key is real?" problem
- Certificate Authorities are the trusted third parties that verify identity
- The TLS handshake uses asymmetric crypto to agree on a symmetric key - then AES takes over
- The padlock = encrypted connection, NOT a guarantee the site is safe
- Certificates expire - a lapsed cert is an instant security warning for users

---

## 📚 Resources to Go Deeper
- [How HTTPS Works (comic)](https://howhttps.works/)
- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/) - test any site's TLS config
- [Let's Encrypt - free certificates explained](https://letsencrypt.org/how-it-works/)

---

## [⬅️ Day 009](../day009/) | [➡️ Day 011](../day011/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*