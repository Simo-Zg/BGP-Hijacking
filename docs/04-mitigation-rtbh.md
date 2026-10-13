# Step 5 - Mitigation: Trusted Counter-Route Injection

This lab uses a trusted ExaBGP counter-route as its default mitigation mechanism.

Historically this page called the behavior "RTBH". That was imprecise. True RTBH normally
uses the RFC 7999 BLACKHOLE community `65535:666` and causes traffic to be discarded by the
provider network. The current lab does something different: ExaBGP announces a replacement
route with community `65000:666`, and `isp-r2` raises local preference for routes from the
trusted ExaBGP neighbor.

## What Happens

| Component | Behavior |
|-----------|----------|
| `detect.py` | Detects a suspicious route for protected space, such as `192.168.100.0/25` from AS300. |
| ExaBGP | Receives a command on stdout: `announce route 192.168.100.0/25 next-hop 10.100.12.11 community [ 65000:666 ]`. |
| `isp-r2` | Applies `RM-EXABGP-IN` only to neighbor `10.100.12.14`, matches community `65000:666`, and sets local preference to `1000`. |
| Result | The ISP prefers the trusted counter-route over the attacker route when RPKI has not already rejected the attacker route. |

This is best described as local-preference based counter-route injection. It is useful for
teaching automated mitigation, BGP communities, and trusted route policy without adding a
data-plane blackhole implementation.

## ISP Configuration

The checked-in `configs/isp_frr.conf` contains:

```frr
bgp community-list standard COUNTER_ROUTE_TAG seq 5 permit 65000:666

route-map RM-EXABGP-IN permit 10
 match community COUNTER_ROUTE_TAG
 set local-preference 1000
exit

route-map RM-EXABGP-IN permit 20
exit

router bgp 200
 address-family ipv4 unicast
  neighbor 10.100.12.14 route-map RM-EXABGP-IN in
 exit-address-family
exit
```

The policy is intentionally scoped to ExaBGP only. Do not apply this local-preference boost
to the attacker neighbor; otherwise an attacker could tag their own route and receive the
same preference.

## Python/ExaBGP Contract

ExaBGP treats stdout from `detect.py` as BGP commands. Logs must go to stderr or files.

Valid command output:

```text
announce route 192.168.100.0/25 next-hop 10.100.12.11 community [ 65000:666 ]
```

Structured evidence is written to:

- `logs/detections.jsonl`
- `logs/mitigations.jsonl`
- `metrics/latency.csv`

## Verify The Counter-Route

To demonstrate this layer by itself, temporarily detach RPKI enforcement from the attacker
neighbor, clear BGP, and let the detector mitigate the hijack:

```bash
docker exec -it isp-r2 vtysh \
  -c "configure terminal" \
  -c "router bgp 200" \
  -c "address-family ipv4 unicast" \
  -c "no neighbor 10.100.23.13 route-map RM-RPKI-DROP in" \
  -c "end" \
  -c "clear ip bgp *"
```

Then inspect the route and logs:

```bash
docker exec -it isp-r2 vtysh -c "show ip route 192.168.100.0/25"
docker logs -f exabgp-monitor
type logs\detections.jsonl
type metrics\latency.csv
```

The `/25` should point toward `10.100.12.11` after mitigation if the counter-route is active.

Re-enable RPKI enforcement afterward:

```bash
docker exec -it isp-r2 vtysh \
  -c "configure terminal" \
  -c "router bgp 200" \
  -c "address-family ipv4 unicast" \
  -c "neighbor 10.100.23.13 route-map RM-RPKI-DROP in" \
  -c "end" \
  -c "clear ip bgp *"
```

## True RTBH As A Future Option

A real RTBH mode could be added as an explicit option later by using community `65535:666`
and configuring the ISP to discard matching traffic via a blackhole/discard route. That is
not enabled by default because it changes the data-plane behavior and would make the current
educational workflow less direct.
