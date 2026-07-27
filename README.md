# Home Network Security Lab: pfSense + Suricata + CrowdSec

A documented, end-to-end build of a layered security setup for a home network,
running on a small home lab. This started as a simple "fix my gaming NAT" problem
and turned into a full defensive stack: a properly tuned firewall, an intrusion
detection system, and a distributed, community-powered blocking engine — all
architected to run on modest hardware.

This writeup is intended both as personal documentation and as a portfolio piece.
It focuses on the *why* behind each decision, not just the *how*.

---

## Table of Contents

1. [The Environment](#the-environment)
2. [Architecture Overview](#architecture-overview)
3. [Part 1 — pfSense Firewall & NAT](#part-1--pfsense-firewall--nat)
4. [Part 2 — Security Auditing the Public IP](#part-2--security-auditing-the-public-ip)
5. [Part 3 — Suricata IDS](#part-3--suricata-ids)
6. [Part 4 — CrowdSec Distributed Deployment](#part-4--crowdsec-distributed-deployment)
7. [Design Decisions & Trade-offs](#design-decisions--trade-offs)
8. [Day-to-Day Monitoring](#day-to-day-monitoring)
9. [What I Learned](#what-i-learned)

---

## The Environment

The network runs on a few pieces of home lab hardware, each with a clear role:

| Machine | Role |
|---|---|
| Mini PC (4 GB RAM) running Proxmox | Hypervisor host |
| pfSense (VM on Proxmox) | Firewall / router / IDS |
| Raspberry Pi (Docker) | Pi-hole (network-wide DNS + ad blocking) |
| Linux VM (Docker) | Nginx Proxy Manager + self-hosted services |

Internet connection is fiber via **PPPoE**. The firewall exposes a handful of
intentional inbound services (reverse-proxied web apps, a game, a remote-desktop
tool, and a WireGuard VPN-in), and everything else is closed by default.

A recurring theme in this build was **working within tight memory constraints** —
the host runs close to its RAM ceiling, which shaped several architectural
choices later on.

---

## Architecture Overview

```
                          Internet (PPPoE)
                                 |
                                 v
                   +--------------------------+
                   |         pfSense          |
                   |  - Firewall / NAT        |
                   |  - Suricata (IDS)        |
                   |  - CrowdSec bouncer      |  <-- enforces blocks
                   +--------------------------+
                                 |
                   LAN (192.168.x.0/24)
                    |            |            |
                    v            v            v
             +----------+  +----------+  +--------------+
             | Pi-hole  |  |   NPM    |  | Other LAN    |
             |  (DNS)   |  | + Crowd- |  | devices      |
             |          |  |  Sec     |  |              |
             |          |  | engine   |  |              |
             +----------+  +----------+  +--------------+
                            ^
                            |
                   decisions pulled by
                   the pfSense bouncer
```

The key architectural idea: **separate the "brain" from the "hands."**

- The **CrowdSec engine** (the brain) runs on the box where the important logs
  live — the Nginx Proxy Manager server. It analyzes traffic and decides who to block.
- The **CrowdSec bouncer** (the hands) runs on pfSense. It just enforces the
  decisions at the firewall edge.

This split keeps the heavy processing off the memory-constrained firewall.

---

## Part 1 — pfSense Firewall & NAT

### The original problem

The whole project kicked off with a classic symptom: a game reporting a
**strict NAT type**, which breaks matchmaking and voice chat. The same problem
showed up in a second game, which was the first useful clue — **if multiple
unrelated games all get strict NAT, it's not the game, it's the firewall.**

### Why PPSense + PPPoE needed special care

On a PPPoE connection, the pfSense WAN interface is the **PPPoE interface**, not
the physical network card. This matters because NAT and firewall rules have to be
applied to the correct interface, and it's an easy thing to get subtly wrong.

### The actual fix: Static Port Outbound NAT

The real cause of strict NAT was **source port randomization**. By default,
pfSense rewrites outgoing source ports, which confuses the NAT-type detection
that games rely on.

The fix was to switch Outbound NAT to **Hybrid mode** and add a rule for the
gaming device with **Static Port** enabled. This preserves the original source
port on outbound connections.

**Outbound NAT rule (conceptual):**

```
Firewall > NAT > Outbound  (Mode: Hybrid)

Interface:   WAN
Source:      <gaming device IP>/32
Translation: WAN address
Static Port: ENABLED
```

Combined with correctly forwarding the game's required ports (and enabling UPnP
for dynamic needs), this resolved the strict NAT across every affected game at
once.

**Lesson:** the fix for a game-specific symptom was a general firewall
misconfiguration. Always look for the common denominator.

---

## Part 2 — Security Auditing the Public IP

Once inbound services were being exposed, the natural next question was:
**"What does the internet actually see when it looks at my IP?"**

### Scanning my own public IP

Using `nmap` from a Kali VM on the network, I scanned my own public-facing IP to
audit the exposed surface:

```bash
# Basic scan of the most common ports
nmap -sS -Pn --top-ports 1000 <public-ip>

# Service/version detection on whatever came back open
nmap -sV -Pn -p <open-ports> <public-ip>
```

### What the scan revealed (and how I fixed it)

The scan surfaced two things I did **not** intend to expose:

**1. Port 53 (DNS) — open**

`nmap -sV` identified the service as **Unbound**, pfSense's DNS resolver. An
open, publicly reachable DNS resolver is a real problem — it can be abused as an
amplifier in DDoS attacks.

The interesting troubleshooting detail: Unbound was bound to **all interfaces**,
which meant it answered on the WAN IP directly. Because the traffic was destined
*for the firewall itself*, a normal WAN block rule wasn't enough — traffic to the
firewall's own services doesn't traverse the filter the same way pass-through
traffic does.

The correct fix was at the **application layer**, using Unbound's Access Lists to
refuse queries from outside the LAN:

```
Services > DNS Resolver > Access Lists

Allow  : 192.168.x.0/24   (LAN)
Refuse : 0.0.0.0/0        (everything else)
```

Verified from an external perspective — a DNS query to the public IP now times
out, while internal resolution still works perfectly.

**2. Port 443 (HTTPS) — open**

This turned out to be the **Nginx Proxy Manager** serving legitimate
reverse-proxied services (via DuckDNS dynamic DNS). This one was intentional and
expected — but the audit process is exactly what lets you tell "intentional" from
"oops" with confidence.

**Lesson:** *"open" in nmap doesn't automatically mean "vulnerable"* — a service
that responds but refuses to act (like Unbound returning REFUSED to outsiders) is
effectively protected. Understanding the difference is the whole game.

---

## Part 3 — Suricata IDS

With the perimeter tightened, the next layer was **visibility** — knowing when
something is probing or attacking the network.

### Setup

**Suricata** was installed on pfSense (via the built-in Package Manager) on the
**WAN interface**, in **IDS (alert-only) mode**. Deliberately *not* IPS/blocking
mode at first — you want to watch and tune before you let anything auto-drop
traffic, or you risk blocking your own legitimate services.

Rules used the free **ET Open** ruleset, focused on the categories that matter
most for an exposed host: scans, exploits, and malware.

### Reading the alerts: signal vs. noise

The single most valuable skill with an IDS is **triage** — most alerts are noise,
and you have to learn to tell them apart. Real examples from this deployment:

**Noise (suppressed):**
- `SURICATA QUIC failed decrypt` — normal encrypted Google/YouTube traffic that
  Suricata simply can't decrypt. Harmless.
- `STREAM excessive retransmissions` / `SYN/ACK ignored TFO` — normal TCP quirks
  and laggy connections. Not security events.

**Low-value but kept (blocked scans):**
- `ET SCAN Suspicious inbound to MySQL/MSSQL/PostgreSQL` — bots constantly
  scanning the internet for exposed databases. My firewall already dropped these;
  the alert just confirms it. This is the background radiation of being online.

**Actually worth attention:**
- `ET EXPLOIT Apache HTTP Server Path Traversal (CVE-2021-41773 / 42013)` —
  a genuine **exploit attempt** against port 80, which I *do* expose.

### Investigating a real exploit attempt

The Apache exploit alert is a good case study in *not panicking* but *verifying*:

- The exploit targets **Apache HTTP Server 2.4.49/2.4.50 specifically.**
- My exposed service is **Nginx Proxy Manager**, which is **not vulnerable** to
  this CVE.
- The attacker was blindly spraying the exploit at every IP with port 80 open —
  not targeting me specifically.

The takeaway: **direction and context matter.** An inbound exploit against a
service you don't run is noise. The alert I'd genuinely drop everything for is an
*outbound* connection from inside my network to a known-malicious host — that
would suggest an already-compromised device.

### Understanding severity

Suricata assigns a priority to each alert. Priority `1` against a port I actually
expose is my "look at this now" tier. Priority `2`/`3` scan and protocol noise is
the "glance and move on" tier.

---

## Part 4 — CrowdSec Distributed Deployment

Suricata tells you what's happening. **CrowdSec acts on it** — and, crucially,
taps into a global community of shared threat intelligence.

### Why CrowdSec, and the two big wins

1. **It watches the real attack surface.** By parsing the Nginx Proxy Manager
   access logs, CrowdSec sees actual application-layer attacks against the
   services I actually expose.
2. **Community blocklists.** When an IP attacks *any* CrowdSec user worldwide, it
   gets added to a shared list that everyone can preemptively block. You block
   known attackers *before they ever reach you.*

### The architecture decision that mattered most

CrowdSec has two parts that can be split across machines:

- **Security Engine** — the RAM-hungry brain (parses logs, holds the database,
  pulls community intel, makes decisions).
- **Firewall Bouncer** — a featherweight enforcer that just blocks IPs it's told to.

Because the firewall runs on a memory-constrained mini PC, putting the full
engine there was a non-starter. The clean solution — which is also just *good
architecture* — was:

- **Engine → on the NPM server** (where the important logs already live, so no
  cross-machine log shipping is needed).
- **Bouncer → on pfSense** (in CrowdSec's "Small" mode: bouncer only, no local
  engine, no log processor — minimal footprint).

This is the "separate the brain from the hands" idea in practice.

### Engine setup (Docker, on the NPM box)

The engine runs as a Docker container alongside NPM. Simplified compose:

```yaml
services:
  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: crowdsec
    environment:
      COLLECTIONS: "crowdsecurity/nginx-proxy-manager crowdsecurity/http-cve crowdsecurity/base-http-scenarios"
      GID: "1000"
    volumes:
      - ./config:/etc/crowdsec
      - ./data:/var/lib/crowdsec/data
      - /path/to/npm/data/logs:/var/log/npm:ro   # NPM logs, read-only
    ports:
      - "8080:8080"                                # LAPI, for the pfSense bouncer
    restart: unless-stopped
```

**Log acquisition** (`acquis.yaml`) — deliberately targeted at the live access
logs only, not the noisy cert-renewal logs or rotated archives:

```yaml
filenames:
  - /var/log/npm/proxy-host-*_access.log
  - /var/log/npm/fallback_http_access.log
labels:
  type: nginx
```

A useful debugging note from the build: CrowdSec tails logs from the **end** of
the file (only new entries), so the acquisition metrics look empty until fresh
traffic arrives. That's expected behavior, not a failure. File **permissions** on
the mounted logs were the other thing to watch — the container needs read access
to the host's log files.

### Bouncer setup (pfSense, "Small" mode)

The pfSense CrowdSec package is community-maintained and installed via a shell
script (it isn't in the official pfSense package repo). Configured as **Small**:

- Local API: **disabled**
- Log Processor: **disabled**
- Remediation Component (bouncer): **enabled**
- Remote LAPI: pointed at the engine on the NPM box (`http://<npm-box-ip>:8080/`)

Two credentials connect the bouncer to the engine:

- A **bouncer API key** (`cscli bouncers add ...`) — authenticates the enforcer.
- A **machine login/password** (`cscli machines add ...`) — registers pfSense as
  an agent to the remote API.

### Verifying it actually works

The bouncer connection, healthy and pulling on schedule:

```
$ cscli bouncers list
 Name              Valid  Last API pull         Type
 pfsense-firewall  ✔️      2026-..T18:40:40Z     crowdsec-firewall-bouncer
```

And the proof that matters — reading the **actual pf table** on pfSense, not just
the GUI:

```
$ pfctl -t crowdsec_blacklists -T show | wc -l
14534
```

**~14,500 known-malicious IPs** loaded into the firewall and dropped at the edge,
sourced from the community and refreshed automatically. The pfSense plugin manages
two auto-generated aliases (`crowdsec_blacklists` for IPv4 and
`crowdsec6_blacklists` for IPv6) — these are managed by the bouncer and should
never be edited by hand.

---

## Design Decisions & Trade-offs

| Decision | Reasoning |
|---|---|
| Engine on NPM box, not pfSense | Keeps heavy processing off the RAM-limited firewall; logs are already local |
| Bouncer in "Small" mode | Minimal footprint on the firewall — enforcement only |
| Suricata in IDS (alert-only) mode | Observe and tune before risking auto-blocking legitimate traffic |
| Fix DNS exposure via Access Lists, not firewall rules | Traffic to the firewall's own services needs an application-layer fix |
| Static Port Outbound NAT | Correct, targeted fix for strict NAT vs. blanket DMZ exposure |
| Keep scan alerts, suppress protocol noise | Preserve meaningful signal, cut the clutter |

---

## Day-to-Day Monitoring

**On the engine (NPM box):**

```bash
cscli metrics          # overview: parsing activity, decision counts
cscli decisions list   # who is currently blocked, and why
cscli alerts list      # what attacks have been detected
cscli bouncers list    # confirm the pfSense bouncer is still syncing
```

**On pfSense:**

```bash
pfctl -t crowdsec_blacklists -T show | wc -l   # confirm blocklist is loaded
```

For a visual dashboard, the engine can be enrolled in the free **CrowdSec
Console** (`app.crowdsec.net`), which gives web-based metrics, maps, and alert
history across the whole deployment.

---

## What I Learned

- **Symptoms lie about their causes.** A "gaming" problem was a firewall NAT
  misconfiguration; the fix had nothing to do with games.
- **Audit from the outside in.** Scanning your own public IP is the fastest way
  to find what you've accidentally exposed.
- **"Open" ≠ "vulnerable."** Context — what's actually listening, and whether it
  will act for a stranger — is everything.
- **An IDS is only as good as your triage.** Learning to separate noise from
  signal is the real skill, not just turning it on.
- **Architecture beats brute force.** The best solution to a resource constraint
  was a smarter design (splitting engine from bouncer), not bigger hardware.
- **Layers compound.** Firewall + IDS + community-powered blocking each cover a
  different gap. Together they're far stronger than any one alone.

---

## Stack Summary

**Firewall/Router:** pfSense (on Proxmox)
**IDS:** Suricata (ET Open ruleset, IDS mode)
**IPS/Blocking:** CrowdSec (distributed: engine + firewall bouncer)
**DNS/Ad-block:** Pi-hole
**Reverse Proxy:** Nginx Proxy Manager
**Recon/Testing:** nmap, Wireshark (Kali VM)

*All keys, credentials, public IPs, and internal specifics have been omitted or
genericized in this document.*
