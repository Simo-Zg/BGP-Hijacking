# Step 1 & 2 — Topology Deployment & BGP Peering

---

## Step 1 — Deploy the Virtual Infrastructure

The lab uses three Docker containers running **FRRouting (FRR)**, each acting as a full BGP router.
`docker-compose.yml` is the blueprint that wires them together via isolated virtual networks.

```bash
# Boot all routers in the background
docker compose up -d
```

Once complete, the infrastructure is officially stable and all three virtual routers are running on the host.

### Verify L2 Connectivity

To officially close out Step 1, we verify that the virtual cables are actually passing traffic between the nodes. We use the central ISP router (`isp-r2`) to ping both the Victim and the Attacker.

```bash
# Drop into the shell of the ISP router
docker exec -it isp-r2 vtysh

# Check that FRR recognizes the IP addresses Docker assigned to it
show interface brief

# Ping the Victim (victim-r1)
ping 10.100.12.11

# Ping the Attacker (attacker-r3)
ping 10.100.23.13
```

If both pings succeed, the virtual cables are passing traffic correctly. **Step 1 complete.**

---

## Step 2 — Configure eBGP Sessions

Each router gets its own ASN. They exchange routing tables over **External BGP (eBGP)**.

| Router | ASN | Prefix | IP |
|--------|-----|--------|----|
| victim-r1 | AS 100 | 192.168.100.0/24 | 10.100.12.11 |
| isp-r2 | AS 200 | *(transit only)* | 10.100.12.12 / 10.100.23.12 |
| attacker-r3 | AS 300 | 192.168.200.0/24 | 10.100.23.13 |

> A **blackhole** static route is used so the router has something to advertise into BGP
> without needing physical servers downstream.

---

### 2.1 — Victim Router (AS 100)

```bash
docker exec -it victim-r1 vtysh
```

```
configure terminal

! Create the blackhole route for the legitimate prefix
ip route 192.168.100.0/24 blackhole

! Start BGP for AS 100
router bgp 100
 bgp router-id 10.100.12.11
 neighbor 10.100.12.12 remote-as 200

 address-family ipv4 unicast
  network 192.168.100.0/24
 exit-address-family
exit
exit
write memory
exit
```

---

### 2.2 — ISP Router (AS 200)

The ISP only acts as a transit provider — no prefix of its own to advertise.

```bash
docker exec -it isp-r2 vtysh
```

```
configure terminal
router bgp 200
 bgp router-id 10.100.12.12
 neighbor 10.100.12.11 remote-as 100
 neighbor 10.100.23.13 remote-as 300
exit
exit
write memory
exit
```

---

### 2.3 — Attacker Router (AS 300)

For now, the attacker behaves as a normal network citizen.

```bash
docker exec -it attacker-r3 vtysh
```

```
configure terminal
ip route 192.168.200.0/24 blackhole

router bgp 300
 bgp router-id 10.100.23.13
 neighbor 10.100.23.12 remote-as 200

 address-family ipv4 unicast
  network 192.168.200.0/24
 exit-address-family
exit
exit
write memory
exit
```

---

### 2.4 — Disable Strict Policy (All Routers)

Modern versions of FRRouting enforce a strict security default called `ebgp-requires-policy`.
This means that by default, an eBGP session will **completely drop all incoming and outgoing
route advertisements** unless you have explicitly configured a route-map (a filter) to permit them.
It is a "secure by default" posture designed to prevent accidental route leaks in production environments.

Since this is an isolated lab and we want routes to flow freely before we start hijacking them,
we need to disable this strict policy requirement on **all three routers**.

```bash
docker exec -it victim-r1 vtysh
```
```
configure terminal
router bgp 100
 no bgp ebgp-requires-policy
exit
exit
write memory
exit
```

Repeat for the ISP and the Attacker:

```bash
docker exec -it isp-r2 vtysh
configure terminal
router bgp 200
 no bgp ebgp-requires-policy
exit
exit
write memory
exit

docker exec -it attacker-r3 vtysh
configure terminal
router bgp 300
 no bgp ebgp-requires-policy
exit
exit
write memory
exit
```

---

### 2.5 — Understanding the BGP State Machine (Why Routes Were Missing)

After applying `no bgp ebgp-requires-policy`, you may notice the routing tables are still empty
even though the sessions show `Established` with a healthy `Up/Down` timer like `00:08:34`.

This is **expected behavior** and requires understanding how BGP works:

**BGP is an incredibly stable, "lazy" protocol by design.** It does not automatically resend
its entire routing table just because you changed a local configuration rule. It only sends
updates when a route actually changes or the session is restarted.

What happened:
- The routers established their peering sessions **before** `no bgp ebgp-requires-policy` was applied.
- The initial route advertisements were instantly blocked and dropped by the old security rule.
- After you changed the rule, the routers sat there happily peered — completely unaware that
  they were now allowed to share routes.
- BGP will never re-send the table unless forced to.

---

### 2.6 — Force BGP to Re-Advertise Routes

The solution is to perform a hard reset on all BGP sessions, which tears down every TCP
connection, flushes the routing table, and forces every router to re-send its full table from scratch.

```bash
docker exec -it isp-r2 vtysh

# Force a hard reset on all BGP sessions
clear ip bgp *
```

Wait approximately 5 seconds for the BGP state machine to tear down and rebuild the connections,
then verify:

```bash
# Check sessions and prefix counts
show bgp ipv4 unicast summary

# View the full populated routing table
show ip bgp
```

#### Expected Output

```
*>  192.168.100.0/24   10.100.12.11    0    0    100 i
*>  192.168.200.0/24   10.100.23.13    0    0    300 i
```

Both routes are marked `*>` meaning they are **fully validated and selected as the best paths**.
The `Up/Down` timer confirms the BGP handshake succeeded.

The core foundation is completely solid. **Step 2 is definitively complete.**
We are now standing at the threshold of the actual exploit.
