---
title: Secure BGP Route Hijacking Detection & Mitigation System - Linux/WSL Runbook
aliases:
  - BGP Hijack Lab
  - Secure BGP Lab
  - BGP Hijack Lab Linux
tags:
  - bgp
  - frrouting
  - exabgp
  - rpki
  - docker
  - cybersecurity
  - linux
  - wsl
created: 2026-05-20
---

# Secure BGP Route Hijacking Detection & Mitigation System - Linux / WSL

This note is the Linux / WSL practical runbook for starting the lab, launching attacks, watching detection, validating mitigation, and returning the topology to a protected state.

> [!IMPORTANT]
> The lab uses private prefixes and private ASNs. RPKI behavior is demonstrated with a local GoRTR RTR/VRP source, not public production RPKI cryptographic validation.

## Topology

```text
victim-r1 AS100  <-->  isp-r2 AS200  <-->  attacker-r3 AS300
                         |
                    exabgp-monitor AS400
                         |
                    rpki-server
```

## Start

```bash
docker compose up -d --build
docker compose ps
docker exec isp-r2 vtysh -c "show bgp summary"
docker exec isp-r2 vtysh -c "show ip bgp"
```

Expected containers:

- `victim-r1`
- `isp-r2`
- `attacker-r3`
- `exabgp-monitor`
- `rpki-server`

## Linux Permission Fix

If Linux shows this error:

```text
PermissionError: [Errno 13] Permission denied: '/app/logs/bgp_updates.jsonl'
```

it means the bind-mounted host directory is not writable from inside the container. Windows Docker Desktop often hides this by presenting more permissive mount behavior; Linux preserves real ownership and permission bits.

Fix on the Linux host:

```bash
mkdir -p logs metrics
chmod -R u+rwX,go+rwX logs metrics
```

If the files are owned by another user:

```bash
sudo chown -R "$USER:$USER" logs metrics
chmod -R u+rwX,go+rwX logs metrics
```

Then restart:

```bash
docker compose restart exabgp-monitor
```

> [!NOTE]
> The monitor now falls back to `/tmp/bgp-lab` if the configured log mount is not writable, so ExaBGP should not crash. Fixing host permissions is still better because it keeps evidence in `logs/` and `metrics/`.

## RPKI Verification

```bash
docker exec isp-r2 vtysh -c "show rpki cache-connection"
docker exec isp-r2 vtysh -c "show rpki prefix-table"
docker exec isp-r2 vtysh -c "show bgp rpki invalid"
docker exec isp-r2 vtysh -c "show ip route 192.168.100.0/25"
```

Expected protected state:

```text
192.168.100.0/24 is valid and installed.
192.168.100.0/25 is not installed.
```

## Attack Runner

The helper script is:

```text
tools/bgp_attack_scenarios.sh
```

Run it from the project root:

```bash
bash tools/bgp_attack_scenarios.sh help
```

From WSL2 Kali, run it from the mounted project path:

```bash
cd /mnt/d/Projects/BGP
bash tools/bgp_attack_scenarios.sh subprefix-detect
```

If the Linux `docker` client cannot see Docker Desktop containers, the script automatically
tries `docker.exe`. You can force that explicitly:

```bash
DOCKER_BIN=docker.exe bash tools/bgp_attack_scenarios.sh subprefix-detect
```

## Scenario 0: Baseline / Reset

Use this before or after demos.

```bash
bash tools/bgp_attack_scenarios.sh baseline
```

What it does:

- Restores victim AS100 announcement for `192.168.100.0/24`.
- Withdraws attacker protected-prefix routes.
- Enables RPKI filtering on attacker neighbor `10.100.23.13`.
- Restarts ExaBGP so old mitigation routes are forgotten.
- Clears BGP so routes are re-evaluated.

## Scenario 1: Sub-Prefix Hijack Blocked By RPKI

```bash
bash tools/bgp_attack_scenarios.sh subprefix-rpki
```

Attack:

```text
AS300 announces 192.168.100.0/25
```

Expected:

```text
RPKI marks the route invalid.
ISP rejects it inbound.
Python may not log an alert because prevention happens first.
```

Verify:

```bash
docker exec isp-r2 vtysh -c "show ip bgp"
docker exec isp-r2 vtysh -c "show ip route 192.168.100.0/25"
```

Expected route result:

```text
% Network not in table
```

## Scenario 2: Sub-Prefix Hijack Detected And Mitigated

```bash
bash tools/bgp_attack_scenarios.sh subprefix-detect
```

Attack:

```text
AS300 announces 192.168.100.0/25
RPKI filtering is temporarily disabled for the demo.
```

Expected:

```text
Python detects unauthorized origin AS300.
ExaBGP injects a trusted counter-route from AS400.
ISP prefers the counter-route because local preference is 1000.
```

Watch:

```bash
docker logs -f exabgp-monitor
```

Verify:

```bash
docker exec isp-r2 vtysh -c "show ip bgp 192.168.100.0/25"
docker exec isp-r2 vtysh -c "show ip route 192.168.100.0/25"
tail -n 5 logs/detections.jsonl
tail -n 5 metrics/latency.csv
```

Expected best path:

```text
Path: 400
Next hop: 10.100.12.11
Local preference: 1000
Community: 65000:666
```

## Scenario 3: Exact-Prefix Unauthorized-Origin Hijack

```bash
bash tools/bgp_attack_scenarios.sh exact-origin-detect
```

Attack:

```text
Victim route is temporarily withdrawn.
AS300 announces 192.168.100.0/24.
RPKI filtering is temporarily disabled.
```

Expected:

```text
Python detects unauthorized origin AS300 for the protected /24.
```

Why withdraw the victim route?

```text
BGP normally advertises best paths. With the victim still active, the AS300 exact-prefix route may not be selected or exported to ExaBGP. Withdrawing the victim route makes the lab attack visible to the monitor.
```

## Scenario 4: AS-Path Spoof / Suspicious Transit

```bash
bash tools/bgp_attack_scenarios.sh path-spoof-detect
```

Attack:

```text
Victim route is temporarily withdrawn.
AS300 announces 192.168.100.0/24 with AS_PATH ending in AS100.
RPKI sees origin AS100 and can treat the route as valid.
Python detects AS300 in the transit path.
```

Expected detector reason:

```text
Suspicious transit ASN(s) in AS_PATH
```

This demonstrates why RPKI and AS-path inspection are complementary: RPKI validates origin, not the full path.

## Return To Protected State

```bash
bash tools/bgp_attack_scenarios.sh reset
```

Then confirm:

```bash
docker exec isp-r2 vtysh -c "show ip bgp"
docker exec isp-r2 vtysh -c "show ip route 192.168.100.0/25"
docker exec isp-r2 vtysh -c "show rpki cache-connection"
```

## Evidence Files

```bash
tail -n 5 logs/bgp_updates.jsonl
tail -n 5 logs/detections.jsonl
tail -n 5 logs/mitigations.jsonl
tail -n 5 metrics/latency.csv
```

If the Linux permission fallback was used:

```bash
docker exec exabgp-monitor sh -c "find /tmp/bgp-lab -type f -maxdepth 3 -print"
```

## Key Takeaways

- RPKI/ROV blocks invalid origin routes when the route-map is applied to the attacker neighbor.
- Python/ExaBGP detects protected-prefix abuse, unauthorized origins, more-specifics, and suspicious AS-path transit.
- The default mitigation is trusted counter-route injection, not true RTBH.
- `reset` after demos so RPKI is enabled and the victim route is restored.
