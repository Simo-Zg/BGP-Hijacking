# Concepts & Technology Reference

---

## FRRouting (FRR)

FRRouting is a production-grade, open-source IP routing suite for Linux and Unix platforms.
It turns a standard server, VM, or container into a full router capable of handling entire
Internet routing tables.

**Key facts:**
- **Protocols:** BGP, OSPF (v2/v3), IS-IS, RIP, PIM (multicast), LDP (MPLS), BFD
- **Origin:** Fork of Quagga, created in 2016 to modernize the codebase
- **Architecture:** Each protocol runs as its own daemon (`bgpd`, `ospfd`…) coordinated by
  a central `zebra` daemon that interfaces with the OS kernel
- **Interface:** The `vtysh` shell uses a syntax intentionally close to **Cisco IOS**

> FRR is not a toy. Massive telecom companies and cloud providers run it on bare-metal switches
> in production data centers right now. The BGP packets in this Docker lab are mathematically
> identical to ones crossing the Atlantic Ocean.

---

## ExaBGP

ExaBGP is often called the **"Swiss Army knife of BGP"**. It is a BGP Speaker / Injector / Monitor
designed for automation and programmability.

**What it does:**
- Speaks the BGP protocol fluently
- Does **not** forward data packets (it is not a router)
- Receives every routing update and translates BGP's binary protocol into clean JSON
- Listens on `sys.stdout` for routing commands from Python scripts

**The three ExaBGP pipes:**

| Pipe | Direction | Purpose |
|------|-----------|---------|
| `sys.stdin` | ExaBGP → Python | BGP update feed (JSON) |
| `sys.stdout` | Python → ExaBGP | Routing commands (`announce route …`) |
| `sys.stderr` | Python → Terminal | Logs and alerts (ExaBGP ignores this) |

> **This lab's ExaBGP container is your own private RIPE Route Collector.**
> It does the exact same job on your micro-backbone that RIPE does on the global internet.

---

## GoRTR

GoRTR is an open-source **RPKI-to-Router (RTR) server** developed by Cloudflare.

**What it does:**
- Reads a ROA database (JSON or fetched from a validator like OctoRPKI)
- Validates the cryptographic signatures (disabled in this lab with `-verify=false`)
- Streams a clean, lightweight, **unencrypted** list of trusted routes to routers via the RTR protocol
- Used in production by Cloudflare and Telia

**Why routers don't do cryptography:**
> Even in a multi-million dollar real-world network, the router's CPU never touches an
> encryption key. It just asks the Validator server: *"What is the exact list?"*
> GoRTR does the math; the router does a simple string/integer comparison.

---

## RPKI (Resource Public Key Infrastructure)

RPKI is the cryptographic framework designed to secure Internet routing.
It verifies that IP prefixes are legitimately announced by authorized Autonomous Systems.

**Key components:**

| Component | Description |
|-----------|-------------|
| **ROA** (Route Origin Authorization) | Digitally signed object: "AS X may announce prefix P up to /N" |
| **Resource Certificate** | X.509 certificate linking IP/ASN to their holder, issued by an RIR |
| **Validator / Relying Party** | ISP server that downloads all ROAs, verifies signatures, and compiles a clean list |
| **RTR Protocol** | Lightweight protocol used to stream that clean list to routers |

**Benefits:**
- Mitigates IP hijacking and routing leaks
- Increases global routing trust
- Provides cryptographic, verifiable proof of routing authorization

**RIRs (Regional Internet Registries):** ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC

---

## The Real-World RPKI Cryptographic Flow

*From the global authority all the way down to the router dropping the packet.
No lab shortcuts — this is the pure production architecture.*

**Step 1 — Genesis (RIR and the Keys)**

The internet has five Regional Internet Registries (RIRs), like ARIN or RIPE. They act as
the ultimate Certificate Authorities (CAs). When a real company registers an IP block and
an ASN, the RIR issues them an X.509 **Resource Certificate**. This certificate contains a
Public Key and a Private Key. The RIR publicly vouches: "whoever holds this specific Private
Key is the legal owner of that specific IP block."

**Step 2 — Declaration (Signing the ROA)**

The company needs to tell the world which router is allowed to broadcast their IPs. They
write a digital rule: "I authorize AS 100 to announce `192.168.100.0/24` with a max length
of `/24`." They then take their Private Key and mathematically sign this rule. This signed
document is the **ROA (Route Origin Authorization)**. They upload it to the RIR's global,
public database.

**Step 3 — The Heavy Lifter (The Validator)**

A Tier-1 ISP runs a dedicated cryptographic server called a **Validator** (or Relying Party).
The Validator connects to the RIR databases and downloads every single ROA in the world.
It uses the global Public Keys to verify the mathematical signature on every single ROA.

- If a hacker forged a ROA, the public key math **fails**.
- If the ROA expired yesterday, it **fails**.
- The Validator throws away all garbage and keeps only cryptographically proven truths.

**Step 4 — Translation (RTR Protocol)**

Routers do **not** have the CPU power to decrypt and verify 400,000 digital certificates
every minute. So the Validator takes all the heavy cryptographic math, strips it away, and
compiles a clean, lightweight, unencrypted list of the rules (e.g., `AS 100 = 192.168.100.0/24`).
It streams this simple text list directly to the ISP's BGP router using the **RTR protocol**
— exactly what the GoRTR container does in this lab.

**Step 5 — Execution (The Router)**

The ISP Edge Router now has the simple list loaded into fast memory. When the attacker's
router tries to announce `192.168.100.0/25` from AS 300, the ISP Edge Router checks the
incoming route against the list. It sees the ASN is wrong and the subnet length is wrong.
Without doing any math at all, the router drops the attacker's packet into a black hole.

The chain of responsibility:
- The **company** handles the cryptography to prove their identity
- The **Validator** handles the cryptography to verify all identities
- The **router** just enforces the final list

---

## Who Is Responsible for the Defense? The Company or the ISP?

**The locus of protection determines the scope of protection.**

If a company (Victim) only implements protection on their own router, they are only protecting
their own employees from being routed to a hacker's fake server. But the rest of the world?
The rest of the world will still be sent to the hacker.

To protect **global customers**, the defense must happen at the **ISP level**.

This is why RPKI is so powerful. By publishing that ROA to the global Trust Anchors, you
are giving a cryptographic mandate to **every ISP on the planet**:
"Drop anyone else who claims to be me." The ISPs enforce the law so the company doesn't
have to fight the war themselves.

---

## Physical Location of the Monitor in the Real World

In this lab, ExaBGP sits on a Layer 2 switch directly next to the ISP router.

In the real world, a company rarely shares a physical Layer 2 switch with an ISP. Instead:

- **The Monitor Placement:** The ExaBGP monitor sits deep inside the company's secure
  datacenter (or a cloud provider like AWS/Azure).
- **The Peering:** The company establishes a **"Multihop eBGP" session** — a logical tunnel
  over the physical cables that allows the ExaBGP server to peer directly with the ISP's
  router from hundreds of miles away.

**What is Multihop eBGP?**

By default, eBGP uses a **TTL of 1**, which restricts peers to being directly connected
(physically on the same cable or virtual switch). The `ebgp-multihop` command increases this
TTL, allowing BGP neighbor sessions to form across multiple network hops, enabling an ExaBGP
monitor in a remote datacenter to peer directly with an ISP's border router.

---

## Enterprise BGP Monitoring Reality

Do large SaaS companies build custom Python scripts for BGP monitoring? **No.**
They pay tens of thousands of dollars per month for dedicated network observability platforms:

- **ThousandEyes** (Cisco)
- **Kentik**
- **Datadog Network Monitoring**
- **Catchpoint**

However, under the hood those multi-million dollar platforms are doing **exactly** what this
lab builds:
1. Ingest local BGP feeds (like our ExaBGP setup)
2. Query global route collectors (like the RIPE RIS API)
3. Parse the AS paths for anomalies
4. Fire webhooks to PagerDuty or Slack when something is wrong

By building this yourself, you are learning the exact underlying mechanics of how enterprise
tools work. This is top-tier engineering.

---

## Philosophy: The Broader Picture

### Is FRR a True Router?

**Yes.** FRRouting is not a toy or an emulator. It is a production-grade, open-source
routing suite. Massive telecom companies and cloud providers run FRR on bare-metal switches
in their data centers right now. The BGP packets flying around your Docker bridge networks
are mathematically identical to the ones crossing the Atlantic Ocean.

### Can We Create Our Own Internet Backbone? Is 3 Routers Enough?

Yes, and yes. "The Internet" is just a collection of routers that agreed to share routing
paths. We created a **micro-internet**. Three routers is the exact minimum required to prove
a transit hijack: an Origin (Victim), a Transit provider (ISP), and a Rogue actor (Attacker).

If the host machine had 256GB of RAM, we could spin up 500 FRR containers and build a
massive national backbone. The logic, the protocols, and the attack vectors would not change
one bit.

### Do You Need to Buy Real ASNs or IPs?

**No.** Absolutely not for this type of project.

RIPE is just an organization that plugged a bunch of listening nodes into the public internet
cables. You cannot use RIPE's public API to see your private lab for the same reason you
cannot use Google Maps to search for a hidden folder on your hard drive — RIPE doesn't have
a cable plugged into your Docker network.

**The "Aha!" Moment:** You don't need to use the RIPE RIS API because you just built your own.
What does RIPE use to collect all that global routing data? They use **Route Collectors** —
servers running ExaBGP (or Quagga/BIRD) that listen to BGP updates and dump them into a database.

The ExaBGP container deployed in Step 4 **is your own private RIPE collector**. It is doing
the exact same job on your micro-backbone that RIPE does on the global backbone. You have
successfully simulated the entire ecosystem from scratch.

This local collector is enough to test the lab's control-plane behavior without relying on
public route-collector visibility.

### RPKI Blind Spot

RPKI only validates Route Origin. A **Path Hijack** (where AS 300 advertises a path that
chains through a valid origin AS) is marked `VALID` by RPKI and let through. The Python
detection engine catches this by inspecting the **full AS-path**, not just the origin. This
is why the project rubric separately lists "Detect abnormal AS-path changes" as a distinct
deliverable — RPKI cannot satisfy this requirement.

### The Bouncer vs. The Police

Route-maps are **bouncers** — they check IDs at the front door (on incoming routes only).
Once a route is already inside the routing table, the bouncer does not patrol the bar.
A `clear ip bgp *` is the **fire alarm**: it forces every router to flush everything and
re-announce, letting the fully-armed bouncer check each route from scratch at the door.
