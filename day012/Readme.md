# Day 012 - VPNs, Proxies, and Tor: What They Actually Hide (and What They Don't)

> **Challenge:** 100 Days of Cybersecurity | **Phase:** Foundations | **Difficulty:** Beginner

---

## 🧠 The Concept

"Just use a VPN and you're safe."

You've heard this. It's on every VPN ad. It's repeated constantly online.

It's also incomplete and misunderstood by most people who say it.

Today: what VPNs, proxies, and Tor actually do, where each one fails, and what an attacker (or investigator) can still see despite all of them.

---

## 🔒 VPN - Virtual Private Network

A VPN creates an encrypted tunnel between your device and a VPN server. All your traffic flows through that tunnel before reaching the internet.

```
Without VPN:
Your device → [ISP sees everything] → Website

With VPN:
Your device → [encrypted tunnel] → VPN Server → Website
               ISP sees only         VPN server sees your
               encrypted traffic     real IP + traffic
```

### What a VPN hides:
- Your real IP address from websites you visit
- Your traffic content from your ISP
- Your browsing from local network observers (coffee shop Wi-Fi)

### What a VPN does NOT hide:
- Your traffic from the VPN provider itself, they can see everything
- Your identity if you're logged into Google, Facebook, etc.
- Malware already on your device
- Your traffic if the VPN leaks (DNS leak, WebRTC leak, kill switch failure)
- You from a court order, most VPN providers will comply with legal requests

### The "No Logs" Problem
Many VPNs claim they keep no logs. Some lie.

In 2011, HideMyAss VPN claimed no logs, then handed user logs to the FBI.
In 2017, PureVPN claimed no logs, then provided logs that led to a stalker's conviction.

**The rule:** If a VPN provider can hand over your data, they have your data.

### VPN Protocols
| Protocol | Speed | Security | Use Case |
|----------|-------|----------|----------|
| WireGuard | ⚡ Fast | ✅ Strong | Best for most uses |
| OpenVPN | Medium | ✅ Strong | Reliable, open source |
| IKEv2/IPSec | Fast | ✅ Strong | Mobile (reconnects quickly) |
| L2TP/IPSec | Medium | ⚠️ Weaker | Legacy |
| PPTP | Fast | ❌ Broken | Never use |

---

## 🔀 Proxy - Traffic Forwarding

A proxy server forwards your requests on your behalf. Simpler than a VPN, usually no encryption.

```
Your device → Proxy Server → Website
Website sees proxy's IP, not yours
```

### Types of Proxies:
- **HTTP Proxy** - handles web traffic only. No encryption.
- **SOCKS5 Proxy** - handles any traffic (TCP/UDP). Faster, more flexible.
- **Transparent Proxy** - you don't even know it's there. ISPs use these.
- **Reverse Proxy** - sits in front of a server, not a client. Cloudflare is a reverse proxy.

### What a Proxy hides:
- Your IP from the destination website

### What a Proxy does NOT hide:
- Your traffic content (usually unencrypted)
- Your traffic from the proxy operator
- Your DNS queries (usually still go through your ISP)

Proxies are useful for bypassing geo-restrictions. They're not a security tool.

---

## 🧅 Tor - The Onion Router

Tor routes your traffic through three randomly selected volunteer-run nodes (relays) and wraps it in three layers of encryption - one layer peeled at each hop.

```
Your device
    → [Layer 1 encrypted] → Entry Node (knows your IP, not destination)
    → [Layer 2 encrypted] → Middle Node (knows nothing useful)
    → [Layer 3 encrypted] → Exit Node (knows destination, not your IP)
    → Website
```

Each node only knows the previous and next hop. No single node knows both where traffic came from AND where it's going.

### What Tor hides:
- Your IP from the destination website
- Your destination from your ISP (they see only that you're using Tor)
- Your traffic from any single observer

### What Tor does NOT hide:
- Traffic content at the exit node (if the site uses HTTP, not HTTPS)
- Timing attacks - a sophisticated attacker watching both your connection and the destination can correlate traffic patterns
- You if you log into accounts, enable JavaScript, or download files
- You from a global adversary (NSA-level surveillance)
- The fact that you're using Tor (your ISP can see this - use Tor bridges to hide it)

### Tor is Slow
Three hops across the world. Volunteer servers. It's not for streaming.

---

## ⚖️ Comparison Table

| | VPN | Proxy | Tor |
|--|-----|-------|-----|
| Hides IP | ✅ | ✅ | ✅ |
| Encrypts traffic | ✅ | ❌ (usually) | ✅ |
| Trusted third party | VPN provider | Proxy operator | Multiple relays |
| Speed | Fast | Fast | Slow |
| Anonymity level | Medium | Low | High (with caveats) |
| Legal grey area | No | No | Depends on use |
| Defeats global surveillance | ❌ | ❌ | Partially |

---

## 🕵️ What Investigators Actually See

This is the part people skip.

Even with a VPN + Tor, an investigator can still find you through:

- **Login accounts** - you logged into Gmail while using Tor once. That's enough.
- **Browser fingerprinting** - your browser has a unique fingerprint (screen size, fonts, extensions, language). VPNs don't change this.
- **Operational security (OPSEC) failures** - Ross Ulbricht (Silk Road founder) was identified partly because he posted about Silk Road on his personal accounts before it launched.
- **Exit node monitoring** - law enforcement runs Tor exit nodes
- **Payment trails** - Bitcoin is not anonymous. Blockchain analysis firms track transactions.
- **Malware** - if your device is compromised, none of this matters

**True anonymity is an operational discipline, not a tool you install.**

---

## 💻 Practical Commands

```bash
# Check your current public IP
curl ifconfig.me

# Check for DNS leaks (should show VPN's DNS, not your ISP's)
curl https://dns.google/resolve?name=whoami.akamai.net&type=A

# Test if Tor is working (should return Tor exit node IP)
# (requires Tor running locally on port 9050)
curl --socks5 127.0.0.1:9050 ifconfig.me

# Check WebRTC leak (in browser console)
# If this shows your real IP despite VPN - you have a WebRTC leak:
# Run in browser dev tools (F12 → Console):
# var pc = new RTCPeerConnection(); pc.createDataChannel('');
# pc.createOffer().then(o => pc.setLocalDescription(o));
# setTimeout(() => console.log(pc.localDescription.sdp), 1000);

# View your DNS resolver
nslookup myip.opendns.com resolver1.opendns.com
```

---

## 🔑 Key Takeaways

- VPNs hide your IP and encrypt traffic - from everyone except the VPN provider
- "No logs" claims are only as trustworthy as the company making them
- Proxies forward traffic but usually don't encrypt - not a security tool
- Tor provides the strongest anonymity but is slow, has caveats, and doesn't protect against OPSEC failures
- True anonymity requires discipline - tools are only part of it
- Your ISP can always see that you're using Tor or a VPN (just not what you're doing)

---

## 📚 Resources to Go Deeper
- [Tor Project - official docs](https://www.torproject.org/)
- [DNS Leak Test](https://www.dnsleaktest.com/)
- [PrivacyGuides.org - VPN recommendations](https://www.privacyguides.org/en/vpn/)

---

## [⬅️ Day 011](../day011/) | [➡️ Day 013](../day013/)

*Part of my [100 Days of Cybersecurity](../README.md) challenge.*