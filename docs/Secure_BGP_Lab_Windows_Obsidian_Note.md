---
title: Secure BGP Route Hijacking Detection & Mitigation System
aliases:
  - BGP Hijack Lab
  - Secure BGP Lab
tags:
  - bgp
  - frrouting
  - exabgp
  - rpki
  - cybersecurity
  - docker
  - networking-lab
  - windows
  - powershell
created: 2026-05-11
---

# Secure BGP Route Hijacking Detection & Mitigation System

This note is the Windows / PowerShell operator playbook for the Dockerized BGP hijack lab.

The lab demonstrates how a BGP sub-prefix hijack works, how to detect it from ExaBGP JSON updates, how to mitigate it with a trusted counter-route, and how to prevent it with local Route Origin Validation.

> [!IMPORTANT]
> The lab uses private prefixes and private ASNs. RPKI behavior is demonstrated with a local GoRTR RTR/VRP source. This is not public production-grade cryptographic RPKI because public RIR trust anchors cannot validate private lab resources.

## Topology

```text
victim-r1 AS100  <-->  isp-r2 AS200  <-->  attacker-r3 AS300
                         |
                    exabgp-monitor AS400
                         |
                    rpki-server
```

| Node | AS | IP | Role |
|---|---:|---|---|
| `victim-r1` | `100` | `10.100.12.11` | Legitimate origin for `192.168.100.0/24` |
| `isp-r2` | `200` | `10.100.12.12`, `10.100.23.12` | Transit router and policy enforcement point |
| `attacker-r3` | `300` | `10.100.23.13` | Announces the hijack `192.168.100.0/25` |
| `exabgp-monitor` | `400` | `10.100.12.14` | Receives BGP updates and injects trusted counter-routes |
| `rpki-server` | N/A | `10.100.12.15:8282` | GoRTR local RTR/VRP server |

## Core Scenario

The legitimate route is:

```text
192.168.100.0/24 originated by AS100
```

The attacker route is:

```text
192.168.100.0/25 originated by AS300
```

BGP prefers the most-specific matching route. Without RPKI filtering or mitigation, the `/25` wins for traffic inside `192.168.100.0` through `192.168.100.127`.

## Start The Lab

From the project root:

```powershell
cd D:\Projects\BGP
docker compose up -d --build
docker compose ps
```

Expected containers:

```text
victim-r1
isp-r2
attacker-r3
exabgp-monitor
rpki-server
```

## Check BGP Sessions

```powershell
docker exec isp-r2 vtysh -c "show bgp summary"
```

Expected peers:

| Neighbor | AS | Meaning |
|---|---:|---|
| `10.100.12.11` | `100` | Victim router |
| `10.100.23.13` | `300` | Attacker router |
| `10.100.12.14` | `400` | ExaBGP monitor |

If the session state shows a number under `State/PfxRcd`, the BGP session is established.

## Check Route Table

```powershell
docker exec isp-r2 vtysh -c "show ip bgp"
docker exec isp-r2 vtysh -c "show ip route"
```

With RPKI enforcement enabled, expected important routes:

```text
192.168.100.0/24 via 10.100.12.11
192.168.200.0/24 via 10.100.23.13
```

The hijack route should not be installed:

```powershell
docker exec isp-r2 vtysh -c "show ip route 192.168.100.0/25"
```

Expected:

```text
% Network not in table
```

## RPKI / ROV Prevention

The local VRP file is:

```text
rpki/roas.json
```

It says AS100 may originate `192.168.100.0/24` with max length `/24`.

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

This makes `192.168.100.0/25` invalid, even if AS100 announced it, because the max length is `/24`.

### Verify RPKI Cache

```powershell
docker exec isp-r2 vtysh -c "show rpki cache-connection"
docker exec isp-r2 vtysh -c "show rpki prefix-table"
```

Expected cache:

```text
rpki tcp cache 10.100.12.15 8282 pref 1 (connected)
```

Expected prefix table:

```text
192.168.100.0  24 - 24  100
```

### Verify Invalid Routes

```powershell
docker exec isp-r2 vtysh -c "show bgp rpki invalid"
```

This may be empty when filtering is active because the invalid attacker route is rejected inbound.

## Detection Engine

The monitor is:

```text
monitor/detect.py
```

The detector reads ExaBGP JSON updates from stdin and writes valid BGP commands to stdout.

> [!WARNING]
> Do not print normal logs to stdout from `detect.py`. ExaBGP treats stdout as a command channel. Logs must go to stderr or files.

### Detection Rules

The primary rules are deterministic:

| Rule                      | What It Catches                                       |
| ------------------------- | ----------------------------------------------------- |
| Protected-prefix overlap  | Any route touching `192.168.100.0/24`                 |
| Unauthorized origin       | Any protected route whose origin is not AS100         |
| More-specific hijack      | Any route inside `192.168.100.0/24` longer than `/24` |
| Suspicious transit ASN    | AS300 appearing before valid origin AS100             |
| Missing AS_PATH           | Protected route with no AS_PATH                       |
| Trusted mitigation origin | AS400 counter-routes are allowed to avoid loops       |

The optional Random Forest is only a secondary supervised route-classification signal using synthetic training data.

## Logs And Metrics

Host paths:

```text
logs/bgp_updates.jsonl
logs/detections.jsonl
logs/mitigations.jsonl
metrics/latency.csv
metrics/summary.md
```

Inspect logs on Windows PowerShell:

```powershell
Get-Content logs\bgp_updates.jsonl -Tail 5
Get-Content logs\detections.jsonl -Tail 5
Get-Content logs\mitigations.jsonl -Tail 5
Get-Content metrics\latency.csv -Tail 5
```

Inspect logs on Linux or WSL:

```bash
tail -n 5 logs/bgp_updates.jsonl
tail -n 5 logs/detections.jsonl
tail -n 5 logs/mitigations.jsonl
tail -n 5 metrics/latency.csv
```

## Attack Runner For Windows

The main attack helper is:

```text
tools/bgp_attack_scenarios.sh
```

Because the helper is a Bash script, the easiest Windows workflow is to run it through WSL2 Kali while still controlling Docker Desktop.

From Windows PowerShell:

```powershell
wsl -d kali-linux -- bash -lc "cd /mnt/d/Projects/BGP && DOCKER_BIN=docker.exe bash tools/bgp_attack_scenarios.sh help"
```

If your WSL Docker integration is enabled, `DOCKER_BIN=docker.exe` is optional. Keeping it in the command is useful on Windows because it forces the script to talk to Docker Desktop's Windows CLI.

### Attack Runner Scenarios

| Scenario | Purpose | Expected Result |
|---|---|---|
| `baseline` | Restore clean protected state | Victim `/24` is active, attacker protected routes are withdrawn, RPKI is enabled |
| `subprefix-rpki` | Launch AS300 `/25` hijack while RPKI is enabled | ISP rejects `192.168.100.0/25` |
| `subprefix-detect` | Disable RPKI temporarily and launch AS300 `/25` hijack | Python detects AS300 and injects trusted counter-route |
| `exact-origin-detect` | Withdraw victim route and let AS300 announce the exact `/24` | Python detects unauthorized origin AS300 |
| `path-spoof-detect` | Let AS300 announce `/24` with AS_PATH ending in AS100 | RPKI origin check can pass, Python detects AS300 as suspicious transit |
| `reset` | Return to protected baseline | RPKI enabled, victim `/24` restored, attacker protected routes withdrawn |

### Run The Main Attacks

```powershell
wsl -d kali-linux -- bash -lc "cd /mnt/d/Projects/BGP && DOCKER_BIN=docker.exe bash tools/bgp_attack_scenarios.sh baseline"
wsl -d kali-linux -- bash -lc "cd /mnt/d/Projects/BGP && DOCKER_BIN=docker.exe bash tools/bgp_attack_scenarios.sh subprefix-rpki"
wsl -d kali-linux -- bash -lc "cd /mnt/d/Projects/BGP && DOCKER_BIN=docker.exe bash tools/bgp_attack_scenarios.sh subprefix-detect"
wsl -d kali-linux -- bash -lc "cd /mnt/d/Projects/BGP && DOCKER_BIN=docker.exe bash tools/bgp_attack_scenarios.sh exact-origin-detect"
wsl -d kali-linux -- bash -lc "cd /mnt/d/Projects/BGP && DOCKER_BIN=docker.exe bash tools/bgp_attack_scenarios.sh path-spoof-detect"
wsl -d kali-linux -- bash -lc "cd /mnt/d/Projects/BGP && DOCKER_BIN=docker.exe bash tools/bgp_attack_scenarios.sh reset"
```

After any attack, verify from Windows PowerShell:

```powershell
docker exec isp-r2 vtysh -c "show ip bgp"
docker exec isp-r2 vtysh -c "show ip route 192.168.100.0/25"
docker logs --tail 80 exabgp-monitor
Get-Content logs\detections.jsonl -Tail 5
Get-Content logs\mitigations.jsonl -Tail 5
Get-Content metrics\latency.csv -Tail 5
```

## Attack Demo Mode 1: RPKI Prevention

This is the normal protected state.

### Step 1: Confirm RPKI Is Enabled On Attacker Neighbor

```powershell
docker exec isp-r2 vtysh -c "show running-config" | Select-String "10.100.23.13 route-map RM-RPKI-DROP"
```

Expected:

```text
neighbor 10.100.23.13 route-map RM-RPKI-DROP in
```

### Step 2: Clear BGP So Routes Are Re-Evaluated

```powershell
docker exec isp-r2 vtysh -c "clear ip bgp *"
```

### Step 3: Verify The Hijack Is Blocked

```powershell
docker exec isp-r2 vtysh -c "show ip bgp"
docker exec isp-r2 vtysh -c "show ip route 192.168.100.0/25"
```

Expected:

```text
192.168.100.0/24 is present and valid.
192.168.100.0/25 is not installed.
```

> [!NOTE]
> In this mode, Python may not log a detection event because the ISP rejects the invalid route before ExaBGP needs to mitigate it.

## Attack Demo Mode 2: Python Detection And Counter-Route Mitigation

Use this mode to prove the detector and mitigation path work.

> [!CAUTION]
> This intentionally disables RPKI enforcement on the attacker neighbor. Re-enable it afterward.

### Step 1: Temporarily Disable RPKI Filtering

```powershell
docker exec isp-r2 vtysh `
  -c "configure terminal" `
  -c "router bgp 200" `
  -c "address-family ipv4 unicast" `
  -c "no neighbor 10.100.23.13 route-map RM-RPKI-DROP in" `
  -c "end" `
  -c "clear ip bgp *"
```

Linux or WSL equivalent:

```bash
docker exec isp-r2 vtysh \
  -c "configure terminal" \
  -c "router bgp 200" \
  -c "address-family ipv4 unicast" \
  -c "no neighbor 10.100.23.13 route-map RM-RPKI-DROP in" \
  -c "end" \
  -c "clear ip bgp *"
```

### Step 2: Watch The Monitor

```powershell
docker logs -f exabgp-monitor
```

Expected detector event:

```text
[ALERT] Event 1: Unauthorized origin AS300; prefix=192.168.100.0/25; as_path=[200, 300]; action=mitigation_announced
```

### Step 3: Verify Counter-Route

```powershell
docker exec isp-r2 vtysh -c "show ip bgp 192.168.100.0/25"
docker exec isp-r2 vtysh -c "show ip route 192.168.100.0/25"
```

Expected best route:

```text
Path: 400
Next hop: 10.100.12.11
Local preference: 1000
Community: 65000:666
```

That means ExaBGP injected a trusted counter-route and the ISP preferred it over the attacker route.

### Step 4: Inspect Evidence

```powershell
Get-Content logs\detections.jsonl -Tail 1
Get-Content logs\mitigations.jsonl -Tail 1
Get-Content metrics\latency.csv -Tail 2
```

Expected detection JSONL fields:

```json
{
  "event_id": 1,
  "prefix": "192.168.100.0/25",
  "as_path": [200, 300],
  "origin_as": 300,
  "reason": "Unauthorized origin AS300",
  "action": "mitigation_announced",
  "mitigation_mode": "local_preference_counter_route"
}
```

## Attack Demo Mode 3: Exact-Prefix Unauthorized-Origin Hijack

This scenario shows that the detector is not limited to the more-specific `/25` case.

Run from Windows PowerShell:

```powershell
wsl -d kali-linux -- bash -lc "cd /mnt/d/Projects/BGP && DOCKER_BIN=docker.exe bash tools/bgp_attack_scenarios.sh exact-origin-detect"
```

Attack behavior:

```text
Victim AS100 route is temporarily withdrawn.
AS300 announces 192.168.100.0/24.
RPKI filtering is temporarily disabled for the demo.
```

Expected detector event:

```text
Unauthorized origin AS300
prefix=192.168.100.0/24
```

Verify:

```powershell
docker logs --tail 80 exabgp-monitor
docker exec isp-r2 vtysh -c "show ip bgp 192.168.100.0/24"
Get-Content logs\detections.jsonl -Tail 3
```

## Attack Demo Mode 4: AS-Path Spoof / Suspicious Transit

This scenario demonstrates why RPKI and AS-path inspection are complementary.

Run from Windows PowerShell:

```powershell
wsl -d kali-linux -- bash -lc "cd /mnt/d/Projects/BGP && DOCKER_BIN=docker.exe bash tools/bgp_attack_scenarios.sh path-spoof-detect"
```

Attack behavior:

```text
Victim AS100 route is temporarily withdrawn.
AS300 announces 192.168.100.0/24.
AS300 prepends AS100 so the AS_PATH ends in AS100.
RPKI can see origin AS100 as valid because RPKI validates origin only.
Python still detects AS300 in the transit path.
```

Expected detector event:

```text
Suspicious transit ASN(s) in AS_PATH: [300]
as_path=[200, 300, 100]
origin_as=100
```

Verify:

```powershell
docker logs --tail 80 exabgp-monitor
docker exec isp-r2 vtysh -c "show ip bgp 192.168.100.0/24"
Get-Content logs\detections.jsonl -Tail 5
Get-Content metrics\latency.csv -Tail 5
```

## Return To Protected State

After the Python-only demo, re-enable RPKI.

Restart ExaBGP first so it forgets the previously injected counter-route:

```powershell
docker compose restart exabgp-monitor
```

Re-attach the RPKI route-map:

```powershell
docker exec isp-r2 vtysh `
  -c "configure terminal" `
  -c "router bgp 200" `
  -c "address-family ipv4 unicast" `
  -c "neighbor 10.100.23.13 route-map RM-RPKI-DROP in" `
  -c "end" `
  -c "clear ip bgp *"
```

Confirm the attacker `/25` is gone:

```powershell
docker exec isp-r2 vtysh -c "show ip route 192.168.100.0/25"
```

Expected:

```text
% Network not in table
```

## Useful Commands

### Container State

```powershell
docker compose ps
docker logs --tail 80 exabgp-monitor
docker logs --tail 80 isp-r2
```

### BGP State

```powershell
docker exec isp-r2 vtysh -c "show bgp summary"
docker exec isp-r2 vtysh -c "show ip bgp"
docker exec isp-r2 vtysh -c "show ip route"
```

### RPKI State

```powershell
docker exec isp-r2 vtysh -c "show rpki cache-connection"
docker exec isp-r2 vtysh -c "show rpki prefix-table"
docker exec isp-r2 vtysh -c "show bgp rpki invalid"
```

### Running Config Checks

```powershell
docker exec isp-r2 vtysh -c "show running-config"
docker exec isp-r2 vtysh -c "show running-config" | Select-String "RM-RPKI-DROP|COUNTER_ROUTE_TAG|rpki cache|route-map"
```

### Tests

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest tests -v
```

Expected:

```text
10 passed
```

## How Mitigation Works

The Python monitor emits:

```text
announce route 192.168.100.0/25 next-hop 10.100.12.11 community [ 65000:666 ]
```

The ISP has:

```frr
bgp community-list standard COUNTER_ROUTE_TAG seq 5 permit 65000:666

route-map RM-EXABGP-IN permit 10
 match community COUNTER_ROUTE_TAG
 set local-preference 1000
exit

router bgp 200
 address-family ipv4 unicast
  neighbor 10.100.12.14 route-map RM-EXABGP-IN in
 exit-address-family
exit
```

This means:

| Step | Meaning |
|---|---|
| ExaBGP announces route | AS400 sends a trusted replacement route |
| Community `65000:666` | Lab-specific tag recognized by ISP |
| Local preference `1000` | ISP prefers this route over attacker route |
| Next hop `10.100.12.11` | Traffic is steered back toward victim |

> [!IMPORTANT]
> This is not true RTBH. True RTBH usually uses RFC 7999 BLACKHOLE community `65535:666` and discards traffic. This lab uses trusted counter-route injection.

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `bgpd` fails with `rpki\r` | CRLF line endings in FRR config | Normalize `configs/daemons` and FRR configs to LF |
| `show rpki cache-connection` is empty | GoRTR not running or FRR RPKI module not loaded | Check `rpki-server`, `configs/daemons`, and `docker logs isp-r2` |
| No detection event with RPKI enabled | RPKI blocked the route before Python saw a suspicious route to mitigate | Use Python-only demo mode |
| `/25` still installed after re-enabling RPKI | ExaBGP may still remember the counter-route | `docker compose restart exabgp-monitor`, then `clear ip bgp *` |
| ExaBGP warns about missing CLI named pipes | ExaBGP CLI is not configured | Harmless for this lab |
| First monitor boot is slow | Container installs Python dependencies at startup | Future improvement: build a custom monitor image |

## Clean Shutdown

```powershell
docker compose down
```

To remove containers and networks but keep local logs and metrics:

```powershell
docker compose down
```

To start fresh logs manually:

```powershell
Remove-Item logs\*.jsonl -Force
Remove-Item metrics\latency.csv -Force
```

## Suggested Presentation Flow

1. Start the lab and show topology.
2. Show RPKI cache connection and prefix table.
3. Show that `192.168.100.0/24` is valid.
4. Show that `192.168.100.0/25` is not installed.
5. Temporarily disable RPKI filtering.
6. Clear BGP and watch ExaBGP monitor logs.
7. Show detector event and latency metrics.
8. Show AS400 counter-route with local preference `1000`.
9. Re-enable RPKI and restart ExaBGP.
10. Show that the attacker `/25` is gone again.

## Key Takeaways

RPKI/ROV prevents unauthorized origin routes when the invalid-route policy is applied to the correct neighbor.

Python/ExaBGP detection adds visibility into full AS_PATH behavior and provides a programmable mitigation path.

Counter-route injection is useful for a lab demonstration, but it should not be mislabeled as true RTBH.

Persistent logs and metrics make the system testable, explainable, and easier to present.
