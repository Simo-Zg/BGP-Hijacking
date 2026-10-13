# BGP Hijack Lab - Project Overview

This project is a Dockerized lab for studying BGP route hijacking detection and mitigation.
It uses FRRouting, ExaBGP, Python, and a local GoRTR/VRP source to demonstrate:

- BGP peering between a victim AS, transit ISP AS, attacker AS, and ExaBGP monitor.
- A longest-prefix-match hijack where AS300 announces `192.168.100.0/25`.
- Route Origin Validation behavior using a local RTR/VRP server.
- Deterministic Python detection based on protected-prefix matching and full AS-path checks.
- Local-preference based counter-route injection from a trusted ExaBGP peer.
- Persistent JSONL logs and CSV latency metrics for review.

The lab keeps the original educational topology:

```text
victim-r1 AS100  <-->  isp-r2 AS200  <-->  attacker-r3 AS300
                         |
                    exabgp-monitor AS400
                         |
                    rpki-server
```

The legitimate victim prefix is `192.168.100.0/24` originated by AS100. The attacker
announces the more-specific hijack `192.168.100.0/25` from AS300.

## Lab Roadmap

| Step | File | Description |
|------|------|-------------|
| 1 | [01-topology-and-bgp-peering.md](01-topology-and-bgp-peering.md) | Deploy containers and verify BGP peering |
| 2 | [02-bgp-hijack-simulation.md](02-bgp-hijack-simulation.md) | Simulate the `/25` hijack from AS300 |
| 3 | [03-detection-exabgp-python.md](03-detection-exabgp-python.md) | Run ExaBGP plus Python route detection |
| 4 | [04-mitigation-rtbh.md](04-mitigation-rtbh.md) | Explain trusted counter-route mitigation and RTBH terminology |
| 5 | [05-rpki-advanced.md](05-rpki-advanced.md) | Demonstrate local RPKI/ROV enforcement with GoRTR |
| Advanced | [08-ml-anomaly-detection.md](08-ml-anomaly-detection.md) | Describe the optional supervised route-classification signal |

Additional deliverables:

- [Secure_BGP_Lab_Windows_Obsidian_Note.md](Secure_BGP_Lab_Windows_Obsidian_Note.md) keeps the original Windows / PowerShell Obsidian playbook style and adds the attack scenarios.
- [Secure_BGP_Lab_Linux_Obsidian_Note.md](Secure_BGP_Lab_Linux_Obsidian_Note.md) is the Linux / WSL Obsidian runbook with Linux permissions guidance and the same attacks.
- [Secure_BGP_Lab_Obsidian_Note.md](Secure_BGP_Lab_Obsidian_Note.md) remains as the original generic runbook copy for compatibility.
- [Secure_BGP_Route_Hijacking_Detection_Report.docx](Secure_BGP_Route_Hijacking_Detection_Report.docx) is a formatted project report covering architecture, RPKI, detection, mitigation, attacks, validation, and limitations.

## Defense Layers

| Layer | What it does | What it does not do |
|-------|--------------|---------------------|
| RPKI/ROV | Drops routes that the local VRP table marks `invalid`, such as AS300 announcing `192.168.100.0/25`. | It validates origin only; it does not inspect the full AS path. |
| Python/ExaBGP detection | Checks protected-prefix overlap, more-specifics, unauthorized origins, and suspicious transit ASNs. | It is a lab detector, not a replacement for production route policy and monitoring. |
| Counter-route mitigation | ExaBGP announces a trusted route tagged `65000:666`; the ISP raises local preference for that trusted peer. | This is not true RTBH by default because traffic is redirected toward the victim next hop, not discarded. |
| Optional ML signal | Runs supervised route classification using synthetic training data if `scikit-learn` is available. | It is not unsupervised anomaly detection and is not the primary defense. |

## RPKI Lab Scope

The lab implements Route Origin Validation behavior using a local RTR/VRP source. The
cryptographic trust chain is simulated because private lab prefixes and private ASNs cannot
be validated against the public RPKI hierarchy. GoRTR is run with `-verify=false` and
`-checktime=false` so FRR can learn the lab VRP entry from `rpki/roas.json`.

## Quick Start

```bash
docker compose up -d --build
docker compose ps
docker exec -it isp-r2 vtysh -c "show bgp summary"
docker exec -it isp-r2 vtysh -c "show ip bgp"
```

## Verify RPKI/ROV

```bash
docker exec -it isp-r2 vtysh -c "show rpki cache-connection"
docker exec -it isp-r2 vtysh -c "show rpki prefix-table"
docker exec -it isp-r2 vtysh -c "show bgp rpki invalid"
docker exec -it isp-r2 vtysh -c "show ip route 192.168.100.0/25"
```

With RPKI enforcement enabled on the attacker neighbor, `192.168.100.0/25` should be
rejected as invalid and should not appear as an installed route on `isp-r2`.

## Logs And Metrics

The ExaBGP monitor writes persistent evidence to:

- `logs/bgp_updates.jsonl` for observed BGP announcements.
- `logs/detections.jsonl` for suspicious route events.
- `logs/mitigations.jsonl` for emitted counter-route commands.
- `metrics/latency.csv` for arrival, detection, and mitigation timestamps.
- `metrics/summary.md` for a short explanation of the collected metrics.

The Docker Compose file mounts these directories into the monitor container so they persist
on the host.

### Linux Permission Note

If `exabgp-monitor` crashes with:

```text
PermissionError: [Errno 13] Permission denied: '/app/logs/bgp_updates.jsonl'
```

the Linux host permissions on `logs/` or `metrics/` are blocking writes from inside the
container. This may not appear on Windows because Docker Desktop handles bind-mounted file
permissions differently.

Fix it on the Linux host before starting the lab:

```bash
mkdir -p logs metrics
chmod -R u+rwX,go+rwX logs metrics
```

If files were created by another user or by `sudo`, use:

```bash
sudo chown -R "$USER:$USER" logs metrics
chmod -R u+rwX,go+rwX logs metrics
```

The monitor also has a safety fallback: if `/app/logs` or `/app/metrics` cannot be written,
it falls back to `/tmp/bgp-lab` and logs a warning instead of terminating ExaBGP. The host
permission fix above is still preferred because it preserves evidence in the project folder.

## Attack Scenarios

Use the attack runner to deliberately trigger the main BGP attack modes:

```bash
bash tools/bgp_attack_scenarios.sh baseline
bash tools/bgp_attack_scenarios.sh subprefix-rpki
bash tools/bgp_attack_scenarios.sh subprefix-detect
bash tools/bgp_attack_scenarios.sh exact-origin-detect
bash tools/bgp_attack_scenarios.sh path-spoof-detect
bash tools/bgp_attack_scenarios.sh reset
```

From WSL2 Kali, run the same commands from `/mnt/d/Projects/BGP`. The script first tries the
Linux `docker` client, then falls back to Docker Desktop's `docker.exe` when the Linux client
cannot see the Windows containers. You can force that behavior with:

```bash
DOCKER_BIN=docker.exe bash tools/bgp_attack_scenarios.sh subprefix-detect
```

Scenario meanings:

- `subprefix-rpki`: AS300 announces `192.168.100.0/25` while RPKI is enabled. The ISP should reject it.
- `subprefix-detect`: RPKI is temporarily disabled so Python detects AS300 and injects the trusted counter-route.
- `exact-origin-detect`: the victim route is temporarily withdrawn and AS300 announces `192.168.100.0/24`; Python detects unauthorized origin AS300.
- `path-spoof-detect`: the victim route is temporarily withdrawn and AS300 announces `192.168.100.0/24` with AS_PATH ending in AS100; RPKI sees the origin as valid, but Python detects suspicious transit AS300.
- `reset`: restores the protected baseline with RPKI filtering enabled.

After any detection scenario:

```bash
docker logs --tail 80 exabgp-monitor
tail -n 5 logs/detections.jsonl
tail -n 5 logs/mitigations.jsonl
tail -n 5 metrics/latency.csv
```

## Run Tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest tests -v
```

The tests focus on deterministic route-analysis behavior and structured logging helpers.

## Optional Extensions

RIPE RIS is best treated as a separate public-BGP extension. Private Docker prefixes and
private ASNs from this lab will not appear in public RIS collectors.

Scapy/data-plane probes are also intentionally left optional. They can be added later with
a client/victim service pair, but the current lab stays focused on BGP control-plane behavior.
