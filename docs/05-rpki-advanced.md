# Advanced - RPKI / Route Origin Validation

This lab demonstrates Route Origin Validation (ROV) behavior with FRRouting and a local
GoRTR RTR/VRP source.

Important scope note: the lab uses private prefixes and private ASNs, so it cannot build a
real public RPKI certificate chain. GoRTR serves the local `rpki/roas.json` file with
`-verify=false -checktime=false`. This is appropriate for a private teaching lab, but it
should be described as simulated trust-chain RPKI/ROV behavior rather than production-grade
cryptographic validation.

## Local ROA/VRP Data

The lab VRP source is `rpki/roas.json`:

```json
{
  "roas": [
    {
      "asn": "AS100",
      "prefix": "192.168.100.0/24",
      "maxLength": 24
    }
  ]
}
```

This means:

- AS100 may originate `192.168.100.0/24`.
- More-specifics such as `192.168.100.0/25` are invalid because `maxLength` is `24`.
- AS300 originating any covered route is invalid.

## GoRTR Service

`docker-compose.yml` starts the local RTR server:

```yaml
rpki-server:
  image: cloudflare/gortr
  container_name: rpki-server
  command: -bind :8282 -verify=false -checktime=false -cache /app/roas.json
  volumes:
    - ./rpki:/app
  networks:
    link_r1_r2:
      ipv4_address: 10.100.12.15
```

FRR connects to this service on `10.100.12.15:8282`.

## ISP Enforcement

`configs/daemons` enables FRR's RPKI module:

```text
bgpd=yes
bgpd_options="-M rpki"
```

`configs/isp_frr.conf` connects to the cache, defines a route-map that drops invalid
routes, and applies it inbound from the attacker neighbor:

```frr
route-map RM-RPKI-DROP deny 10
 match rpki invalid
exit

route-map RM-RPKI-DROP permit 20
exit

router bgp 200
 address-family ipv4 unicast
  neighbor 10.100.23.13 route-map RM-RPKI-DROP in
 exit-address-family
exit

rpki
 rpki polling_period 60
 rpki cache tcp 10.100.12.15 8282 preference 1
exit
```

The important line is the inbound route-map on `10.100.23.13`, the attacker router. Without
that line, FRR may learn VRPs from GoRTR but still accept the invalid attacker route.

## Verification Commands

Start the lab:

```bash
docker compose up -d --build
docker compose ps
```

Check BGP and RPKI state:

```bash
docker exec -it isp-r2 vtysh -c "show bgp summary"
docker exec -it isp-r2 vtysh -c "show ip bgp"
docker exec -it isp-r2 vtysh -c "show rpki cache-connection"
docker exec -it isp-r2 vtysh -c "show rpki prefix-table"
docker exec -it isp-r2 vtysh -c "show bgp rpki invalid"
```

Confirm the invalid `/25` is not installed:

```bash
docker exec -it isp-r2 vtysh -c "show ip route 192.168.100.0/25"
```

Expected result with enforcement active:

```text
% Network not in table
```

The legitimate route should remain present:

```bash
docker exec -it isp-r2 vtysh -c "show ip route 192.168.100.0/24"
```

## Relationship To Python Detection

RPKI/ROV is preventive: it can reject an invalid origin route before Python mitigation is
needed. Python detection still matters because it checks route properties that RPKI does not,
including:

- More-specific announcements inside protected space.
- Unauthorized origin ASNs.
- Suspicious ASNs in the transit portion of the AS path.
- Missing AS_PATH data for protected prefixes.

RPKI checks origin authorization. It does not prove that the entire AS path is legitimate.

## Fail-Open Behavior

If the RTR cache is unavailable or still loading, FRR may mark routes as `not-found` rather
than `invalid`. The route-map above drops only `invalid`, so this is a fail-open behavior.
That is normal for many ROV deployments, but it means operators should validate cache state
and clear/re-advertise BGP routes after changing policies in a lab demonstration.

To force neighbors to resend routes:

```bash
docker exec -it isp-r2 vtysh -c "clear ip bgp *"
```

## Temporarily Disable Or Re-Enable RPKI Enforcement

Detach enforcement for a Python-only mitigation demo:

```bash
docker exec -it isp-r2 vtysh \
  -c "configure terminal" \
  -c "router bgp 200" \
  -c "address-family ipv4 unicast" \
  -c "no neighbor 10.100.23.13 route-map RM-RPKI-DROP in" \
  -c "end" \
  -c "write memory"
```

Re-enable enforcement:

```bash
docker exec -it isp-r2 vtysh \
  -c "configure terminal" \
  -c "router bgp 200" \
  -c "address-family ipv4 unicast" \
  -c "neighbor 10.100.23.13 route-map RM-RPKI-DROP in" \
  -c "end" \
  -c "clear ip bgp *"
```
