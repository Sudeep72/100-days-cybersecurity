# Day 007 - File Permissions: Why One Misconfiguration Can Give Attackers Everything

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Foundations | **Difficulty:** Beginner

---

## 🧠 The Concept

Linux file permissions are one of those things that look simple on the surface.

Three letters. Three groups. A few numbers.

But misconfigurations in permissions are responsible for a huge number of real-world breaches - from exposed password files to full privilege escalation chains that hand an attacker root access on a server.

Today: how permissions work, what goes wrong, and how to audit for it.

---

## 🔐 How Linux Permissions Work

Every file and directory has three permission groups:

```
-rwxr-xr-- 1 sudeep staff 4096 May 10 09:00 script.sh
 ↑↑↑ ↑↑↑ ↑↑↑
 │││  │││  └── Others (everyone else)
 │││  └──────  Group  (members of 'staff')
 └──────────── Owner  (sudeep)
```

Each group gets three permissions:

```
r = read     (4) - can view the file
w = write    (2) - can modify the file
x = execute  (1) - can run the file
```

They combine as numbers:
```
rwx = 7    (4+2+1)
rw- = 6    (4+2+0)
r-x = 5    (4+0+1)
r-- = 4    (4+0+0)
--- = 0    (0+0+0)
```

So `chmod 755 file` means:
- Owner: rwx (7) - read, write, execute
- Group: r-x (5) - read and execute
- Others: r-x (5) - read and execute

---

## ⚠️ Dangerous Permission Misconfigurations

### 1. World-Writable Files
```bash
-rw-rw-rw- 1 root root /etc/crontab
```
Anyone on the system can modify this file.
If `/etc/crontab` is world-writable, an attacker adds a cron job that runs as root.
Game over.

```bash
# Find world-writable files
find / -type f -perm -o+w 2>/dev/null | grep -v proc
```

---

### 2. Weak Permissions on Sensitive Files
```bash
# These should NEVER be world-readable
/etc/shadow      → should be 640 (root:shadow only)
~/.ssh/id_rsa    → should be 600 (owner only)
config files with API keys → should be 600
```

If `/etc/shadow` is readable by everyone, an attacker grabs all the password hashes and cracks them offline.

---

### 3. SUID Binaries (Privilege Escalation Path)

SUID = Set User ID. When set on a binary, it runs as the **file owner** (often root) regardless of who executes it.

```bash
-rwsr-xr-x 1 root root /usr/bin/passwd
     ↑
     s = SUID bit set - this runs as root
```

`/usr/bin/passwd` needs SUID to change password hashes in `/etc/shadow`. That's legitimate.

But if a misconfigured or vulnerable binary has SUID set - an attacker can exploit it to get a root shell.

```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null
```

Then check each one against [GTFOBins](https://gtfobins.github.io/) - a list of binaries that can be exploited for privilege escalation.

---

### 4. SGID Binaries
Like SUID but runs as the **group** owner instead of the user owner.

```bash
# Find SGID binaries
find / -perm -2000 -type f 2>/dev/null
```

---

### 5. Writable Directories in PATH
If any directory in the PATH is writable by a non-root user, an attacker can plant a malicious binary with the same name as a system command.

```bash
echo $PATH
# /usr/local/bin:/usr/bin:/bin:/home/user/scripts

# If /home/user/scripts is writable, create a fake 'ls'
echo '/bin/bash' > /home/user/scripts/ls
chmod +x /home/user/scripts/ls
# Next time root runs 'ls' - they get a bash shell
```

---

## 💻 The Code - Permission Auditor

```bash
#!/bin/bash
# Day 007 - Permission Auditor
# 100 Days of Cybersecurity by Sudeep Ravichandran
#
# Audits a Linux system for dangerous permission misconfigurations.
# Use on systems you own or have permission to audit.
#
# Usage: bash perm_audit.sh

echo "========================================"
echo " Permission Auditor — Day 007"
echo " 100 Days of Cybersecurity"
echo "========================================"
echo ""

# ── Sensitive Files — Check Permissions ───
echo "[ SENSITIVE FILE PERMISSIONS ]"
sensitive_files=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/sudoers"
    "/etc/crontab"
    "$HOME/.ssh/id_rsa"
    "$HOME/.ssh/authorized_keys"
)

for f in "${sensitive_files[@]}"; do
    if [ -e "$f" ]; then
        perms=$(stat -c "%a %U:%G %n" "$f" 2>/dev/null)
        echo "  $perms"
    fi
done
echo ""

# ── World-Writable Files ──────────────────
echo "[ WORLD-WRITABLE FILES (dangerous) ]"
echo "  Searching... (this may take a moment)"
find /etc /var /usr /tmp -type f -perm -o+w 2>/dev/null \
    | grep -v "/proc" \
    | head -15 \
    | while read f; do echo "  ⚠  $f"; done
echo ""

# ── SUID Binaries ─────────────────────────
echo "[ SUID BINARIES ]"
echo "  Check each against GTFOBins: https://gtfobins.github.io"
find / -perm -4000 -type f 2>/dev/null \
    | while read f; do
        owner=$(stat -c "%U" "$f" 2>/dev/null)
        echo "  [SUID:$owner] $f"
    done
echo ""

# ── SGID Binaries ─────────────────────────
echo "[ SGID BINARIES ]"
find / -perm -2000 -type f 2>/dev/null \
    | while read f; do
        group=$(stat -c "%G" "$f" 2>/dev/null)
        echo "  [SGID:$group] $f"
    done
echo ""

# ── Writable PATH Directories ─────────────
echo "[ PATH DIRECTORY WRITE CHECK ]"
echo "  Current PATH: $PATH"
IFS=':' read -ra PATH_DIRS <<< "$PATH"
for dir in "${PATH_DIRS[@]}"; do
    if [ -w "$dir" ] 2>/dev/null; then
        echo "  ⚠  WRITABLE: $dir — hijacking risk"
    else
        echo "  ✓  $dir"
    fi
done
echo ""

# ── Crontab Check ─────────────────────────
echo "[ CRONTAB PERMISSIONS ]"
for cronfile in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
    if [ -e "$cronfile" ]; then
        perms=$(stat -c "%a" "$cronfile" 2>/dev/null)
        if [ "$perms" -gt "644" ] 2>/dev/null; then
            echo "  ⚠  Loose permissions ($perms): $cronfile"
        else
            echo "  ✓  $cronfile ($perms)"
        fi
    fi
done
echo ""

echo "========================================"
echo " Audit complete."
echo " Review any ⚠  items - these are your risk areas."
echo "========================================"
```

**To run:**
```bash
chmod +x perm_audit.sh
bash perm_audit.sh
```

---

## 🔑 Key Takeaways

- File permissions look simple - misconfigurations have real consequences
- `find / -perm -4000` finds SUID binaries - check every result against GTFOBins
- `/etc/shadow` readable by non-root users = all passwords are compromised
- A writable directory in PATH can let an attacker hijack system commands
- Default deny on sensitive files: `600` for private keys, `640` for shadow, `644` for most config

---

## 📚 Resources to Go Deeper
- [GTFOBins](https://gtfobins.github.io/) - SUID/SUDO exploitation reference
- [Linux Permissions explained - DigitalOcean](https://www.digitalocean.com/community/tutorials/linux-permissions-basic)
- [TryHackMe - Linux Privilege Escalation](https://tryhackme.com/room/linprivesc)

---

## [⬅️ Day 006](../day006/) | [➡️ Day 008](../day008/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*