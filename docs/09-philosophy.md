# Design Philosophy

The lab is intentionally small, but it models real control-plane ideas:

- FRRouting provides real BGP speakers in containers.
- ExaBGP provides a programmable BGP monitor/injector.
- GoRTR provides a local RTR/VRP source for Route Origin Validation behavior.
- Python ties route observation, detection, mitigation commands, logs, and metrics together.

## Why A Local Lab Is Useful

Public route collectors such as RIPE RIS cannot see this private Docker topology. The lab
therefore builds its own local observation point with ExaBGP. That does not make it equivalent
to the public RIS ecosystem; it simply gives the lab a controlled BGP feed for teaching and
testing private routes.

## Why Use Multiple Layers

Each layer answers a different question:

| Layer | Question answered |
|-------|-------------------|
| RPKI/ROV | Is this origin AS authorized for this prefix and max length? |
| Python rules | Does this update touch protected space, use an unauthorized origin, contain a suspicious transit ASN, or advertise a more-specific? |
| Counter-route mitigation | Can a trusted internal peer inject a preferred route when a suspicious update is accepted? |
| Metrics/logs | How quickly did the system detect and emit a mitigation command? |

No single layer is complete. RPKI validates origin, not the entire AS path. Python detection is
only as good as its configured policy. Counter-route injection depends on trusted peering and
route policy. The point of the lab is to make those tradeoffs visible.

## What Not To Overclaim

Use precise engineering language:

- Say "Route Origin Validation behavior using a local RTR/VRP source", not production public
  cryptographic RPKI.
- Say "trusted counter-route injection", not true RTBH, unless a discard/blackhole policy is
  explicitly configured.
- Say "supervised route-classification using synthetic data", not unsupervised anomaly
  detection.
- Say "detects configured AS-path risks", not universal AS-path hijack detection.

## Good Next Extensions

Future work can add:

- A data-plane client/victim service pair to show traffic behavior before, during, and after
  the hijack.
- An optional true RTBH mode using RFC 7999 community `65535:666` and an ISP discard policy.
- A separate RIPE RIS script for public prefixes, clearly separated from this private lab.
- Additional tests that feed recorded ExaBGP JSON updates into `process_update`.
