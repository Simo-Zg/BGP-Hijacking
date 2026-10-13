# Step 4 — Detection: ExaBGP + Python Anomaly Monitor

---

## Architecture Overview

```
  isp-r2 (AS 200)
       |
       |  eBGP session (live JSON feed)
       |
  exabgp-monitor (AS 400)  [10.100.12.14 on link_r1_r2 network]
       |
       |  stdin pipe (JSON BGP updates)
       |
  detect.py  <- parses full AS_PATH and protected-prefix updates
       |
       |  stdout pipe (routing commands back to ExaBGP)
       |
  ExaBGP injects counter-routes into the ISP
```

### Is ExaBGP a Router?

**No.** ExaBGP is what we call a "BGP Speaker" or a "BGP Injector/Monitor." It speaks the BGP
routing protocol fluently, but it does **not** forward data packets. If you tried to send a
ping or actual web traffic through it, the traffic would instantly drop. Its only job is to
sit at the table, shake hands with real routers, listen to the routing updates they share,
and optionally inject routing commands back.

### How It Is Wired

In Docker, a bridge network (like `link_r1_r2`) acts exactly like a physical, unmanaged
**Layer 2 switch** sitting on a desk. By adding `exabgp-monitor` to the `link_r1_r2` network,
we didn't run a direct, point-to-point cable. Instead, we virtually "plugged it into" the
same switch that `victim-r1` and `isp-r2` are already plugged into. They are all in the
same broadcast domain (`10.100.12.0/24`), meaning they can all freely talk to each other.

---

## Phase 4.1 — Create the Monitor Workspace

```bash
mkdir -p ~/bgp-hijack-lab/monitor
cd ~/bgp-hijack-lab
```

The `monitor/` directory holds two files:
- `detect.py` — the Python detection (and later, kill-switch) engine
- `exabgp.conf` — tells ExaBGP who to peer with and which Python script to pipe data to

---

## Phase 4.2 — ExaBGP Configuration (`monitor/exabgp.conf`)

This file tells ExaBGP to peer with the ISP router (`10.100.12.12`, AS 200) and map the
Python script to the BGP process. ExaBGP will feed every incoming BGP update as JSON into
the script via `stdin`.

> See [monitor/exabgp.conf](../monitor/exabgp.conf) for the live config.

---

## Phase 4.3 — Python Detection Engine (`monitor/detect.py`)

This is the route-analysis engine. It listens to ExaBGP, parses JSON updates, preserves the
full AS_PATH, and checks protected-prefix announcements with Python's `ipaddress` module.

Current deterministic checks include:

- Unauthorized origin AS for `192.168.100.0/24`.
- More-specific announcements inside the protected `/24`, such as `/25` or `/26`.
- Suspicious transit ASNs in the AS path, even when the origin remains AS100.
- Missing AS_PATH data for protected routes.

The optional Random Forest classifier is only a secondary supervised route-classification
signal. The rule-based checks remain the primary detection mechanism.

> See [monitor/detect.py](../monitor/detect.py) for the full script.

### Critical: The ExaBGP Communication Protocol

ExaBGP enforces a strict three-pipe API between itself and any Python script:

| Pipe | Direction | Used For |
|------|-----------|---------|
| `sys.stdin` | ExaBGP → Python | Live BGP update feed (formatted as JSON) |
| `sys.stdout` | Python → ExaBGP | Routing commands (`announce route ...`, `withdraw route ...`) |
| `sys.stderr` | Python → Terminal | Log messages and alerts — ExaBGP **ignores** this pipe entirely |

**All your log output MUST go to `sys.stderr`.** If anything is printed to `sys.stdout`
that is not a valid BGP routing command, ExaBGP will intercept it, attempt to parse it as
a route announcement, fail, and immediately kill the script.

### A Common Mistake (And Why It Crashes)

In an early version of `detect.py`, a startup message was printed using a standard `print()`
statement. By default, Python routes `print()` to `sys.stdout`.

When the script started, it printed: `BGP Monitor Active: Watching for anomalies...` directly
to `sys.stdout`. ExaBGP intercepted that text, attempted to parse it as a BGP routing command,
failed entirely, and instantly killed the script. It retried 5 times, and then shut down the
whole container.

**The fix:** force all logs and alerts to `sys.stderr`:

```python
import sys

# WRONG - will crash ExaBGP
print("BGP Monitor Active")

# CORRECT - ExaBGP safely ignores stderr
print("BGP Monitor Active", file=sys.stderr)
```

---

## Phase 4.4 — Deploy the Monitor Container

Add this service to `docker-compose.yml` (inside the `services:` block):

```yaml
exabgp-monitor:
  image: python:3.9-slim
  container_name: exabgp-monitor
  volumes:
    - ./monitor:/app
  command: sh -c "pip install exabgp && exabgp /app/exabgp.conf"
  networks:
    link_r1_r2:
      ipv4_address: 10.100.12.14
```

```bash
# Docker will leave your existing routers alone and simply build
# and attach the new exabgp-monitor container
docker compose up -d
```

Once the container is up, ExaBGP will be actively trying to peer with the ISP router,
but the ISP router doesn't know who AS 400 is yet. We need to log into `isp-r2` and
configure the neighbor connection — just like we did in Step 2 for the other routers.

---

## Phase 4.5 — Configure the ISP to Peer with the Monitor

```bash
docker exec -it isp-r2 vtysh
```

```
configure terminal
router bgp 200
 ! Add the ExaBGP monitor as a BGP peer (AS 400)
 neighbor 10.100.12.14 remote-as 400
exit
exit
write memory
exit
```

> Because `no bgp ebgp-requires-policy` was already applied globally on this router
> in Step 2, the new neighbor automatically inherits that permissive rule. No additional
> route-map configuration is needed at this stage.

---

## Phase 4.6 — Verify the Peering

```bash
docker exec -it isp-r2 vtysh
show bgp ipv4 unicast summary
```

You should now see **three neighbors** in the summary:

| Neighbor | AS | PfxRcv | PfxSnt | State |
|----------|----|--------|--------|-------|
| 10.100.12.11 | 100 | 1 | — | Established |
| 10.100.23.13 | 300 | 1 | — | Established |
| 10.100.12.14 | 400 | 0 | 3 | Established |

- `PfxSnt = 0` for ExaBGP is **expected** — it is a silent listener, advertising zero routes to the ISP.
- `PfxSnt = 3` from the ISP's perspective means it is pushing **all three network routes**
  directly into our Python script's `stdin` in real-time.

In BGP, seeing a number in the state column (instead of `Idle`, `Active`, etc.) means the
session is `Established`. The `0` in ExaBGP's row just means ExaBGP is advertising zero routes
to the ISP — which is perfect for a passive monitor.

**The monitor is officially online and ingesting the routing tables. Step 4 is complete.**

---

## View Live Logs

```bash
docker logs -f exabgp-monitor
```

Once the BGP hijack from Step 3 is active, `detect.py` will output alert messages to
`stderr`, which appear in the container logs.

Persistent evidence is also written on the host:

```bash
type logs\bgp_updates.jsonl
type logs\detections.jsonl
type logs\mitigations.jsonl
type metrics\latency.csv
```

On Linux or WSL, use `cat` instead of `type`.
