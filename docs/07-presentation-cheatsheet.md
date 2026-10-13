# Presentation Cheatsheet

This is a concise demo path for showing the lab without overstating what it does.

## Start The Lab

```bash
docker compose up -d --build
docker compose ps
docker exec -it isp-r2 vtysh -c "show bgp summary"
docker exec -it isp-r2 vtysh -c "show ip bgp"
```

## Demo 1 - Python Counter-Route Mitigation

Goal: show the detector catching the AS300 `/25` hijack and ExaBGP injecting a trusted
counter-route. This demonstrates the reactive control-plane layer.

Temporarily detach RPKI enforcement:

```bash
docker exec -it isp-r2 vtysh \
  -c "configure terminal" \
  -c "router bgp 200" \
  -c "address-family ipv4 unicast" \
  -c "no neighbor 10.100.23.13 route-map RM-RPKI-DROP in" \
  -c "end" \
  -c "clear ip bgp *"
```

Watch the monitor:

```bash
docker logs -f exabgp-monitor
```

Verify the counter-route and metrics:

```bash
docker exec -it isp-r2 vtysh -c "show ip route 192.168.100.0/25"
type logs\detections.jsonl
type logs\mitigations.jsonl
type metrics\latency.csv
```

Expected explanation:

- AS300 advertises the more-specific `192.168.100.0/25`.
- `detect.py` parses the full AS_PATH and flags the unauthorized origin.
- ExaBGP announces a trusted counter-route tagged `65000:666`.
- `isp-r2` raises local preference only for routes from the trusted ExaBGP neighbor.

This is not true RTBH. It redirects preference toward the victim next hop rather than
discarding traffic.

## Demo 2 - RPKI/ROV Prevention

Goal: show the ISP rejecting the attacker route through local Route Origin Validation.

Re-enable RPKI enforcement and force re-advertisement:

```bash
docker exec -it isp-r2 vtysh \
  -c "configure terminal" \
  -c "router bgp 200" \
  -c "address-family ipv4 unicast" \
  -c "neighbor 10.100.23.13 route-map RM-RPKI-DROP in" \
  -c "end" \
  -c "clear ip bgp *"
```

Verify RPKI state:

```bash
docker exec -it isp-r2 vtysh -c "show rpki cache-connection"
docker exec -it isp-r2 vtysh -c "show rpki prefix-table"
docker exec -it isp-r2 vtysh -c "show bgp rpki invalid"
docker exec -it isp-r2 vtysh -c "show ip route 192.168.100.0/25"
```

Expected explanation:

- The local VRP permits AS100 to originate `192.168.100.0/24` with max length `/24`.
- AS300 announcing `192.168.100.0/25` is RPKI invalid.
- The inbound `RM-RPKI-DROP` route-map on `10.100.23.13` rejects invalid routes.

## Key Talking Points

| Topic | Precise wording |
|-------|-----------------|
| RPKI scope | The lab simulates the trust chain with a local RTR/VRP source because private ASNs and prefixes cannot use public RPKI. |
| Python detection | The primary detector is deterministic: protected-prefix matching, origin validation, more-specific detection, and AS-path transit checks. |
| ML | The Random Forest is supervised route-classification using synthetic lab data, not unsupervised anomaly detection. |
| Mitigation | The default mitigation is trusted counter-route injection with local-preference policy, not true RTBH. |
| Logs | Evidence is persisted under `logs/` and `metrics/`. |
