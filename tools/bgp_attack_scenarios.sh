#!/usr/bin/env bash
set -euo pipefail

# Runtime attack/demo controller for the Secure BGP hijack lab.
# Run from the project root on Linux/WSL:
#   bash tools/bgp_attack_scenarios.sh subprefix-detect

ISP_CONTAINER="${ISP_CONTAINER:-isp-r2}"
VICTIM_CONTAINER="${VICTIM_CONTAINER:-victim-r1}"
ATTACKER_CONTAINER="${ATTACKER_CONTAINER:-attacker-r3}"
MONITOR_CONTAINER="${MONITOR_CONTAINER:-exabgp-monitor}"
DOCKER_BIN="${DOCKER_BIN:-}"

usage() {
  cat <<'USAGE'
Usage:
  bash tools/bgp_attack_scenarios.sh <scenario>

Scenarios:
  baseline
      Restore a clean protected state:
      - victim AS100 announces 192.168.100.0/24
      - attacker protected-prefix attacks are withdrawn
      - RPKI invalid-route filtering is enabled
      - ExaBGP monitor is restarted

  subprefix-rpki
      Launch the AS300 192.168.100.0/25 sub-prefix hijack while RPKI is enabled.
      Expected result: ISP rejects the invalid /25; Python may not need to mitigate.

  subprefix-detect
      Launch the AS300 192.168.100.0/25 sub-prefix hijack with RPKI filtering disabled.
      Expected result: Python detects unauthorized origin AS300 and injects a counter-route.

  exact-origin-detect
      Withdraw the victim route and make AS300 announce 192.168.100.0/24 with RPKI disabled.
      Expected result: Python detects an exact-prefix unauthorized-origin hijack.

  path-spoof-detect
      Withdraw the victim route and make AS300 announce 192.168.100.0/24 with AS_PATH
      prepended as "300 100". RPKI sees origin AS100 as valid, but Python should flag
      suspicious transit AS300 in the AS path.

  reset
      Same as baseline.

Verification helpers:
  docker exec isp-r2 vtysh -c "show bgp summary"
  docker exec isp-r2 vtysh -c "show ip bgp"
  docker exec isp-r2 vtysh -c "show ip bgp 192.168.100.0/25"
  docker logs -f exabgp-monitor
  tail -n 5 logs/detections.jsonl
  tail -n 5 metrics/latency.csv
USAGE
}

detect_docker() {
  if [[ -n "$DOCKER_BIN" ]]; then
    if "$DOCKER_BIN" ps >/dev/null 2>&1; then
      return
    fi
    echo "Configured DOCKER_BIN=$DOCKER_BIN cannot reach Docker." >&2
    exit 1
  fi

  if docker_can_see_lab docker; then
    DOCKER_BIN="docker"
    return
  fi

  # WSL without Docker Desktop integration often has a Linux docker client that
  # cannot see Windows containers. Fall back to Docker Desktop's Windows CLI.
  if docker_can_see_lab docker.exe; then
    DOCKER_BIN="docker.exe"
    return
  fi

  if docker_can_run docker; then
    DOCKER_BIN="docker"
    return
  fi

  if docker_can_run docker.exe; then
    DOCKER_BIN="docker.exe"
    return
  fi

  echo "Docker is not reachable from this shell." >&2
  echo "Start Docker Desktop, enable WSL integration, or run with DOCKER_BIN=docker.exe." >&2
  exit 1
}

docker_cmd() {
  "$DOCKER_BIN" "$@"
}

docker_can_run() {
  local candidate="$1"
  command -v "$candidate" >/dev/null 2>&1 && "$candidate" ps >/dev/null 2>&1
}

docker_can_see_lab() {
  local candidate="$1"
  docker_can_run "$candidate" && "$candidate" inspect "$ISP_CONTAINER" >/dev/null 2>&1
}

require_containers() {
  local missing=0
  for container in "$ISP_CONTAINER" "$VICTIM_CONTAINER" "$ATTACKER_CONTAINER" "$MONITOR_CONTAINER"; do
    if ! docker_cmd inspect "$container" >/dev/null 2>&1; then
      echo "Required container is not running or not visible: $container" >&2
      missing=1
    fi
  done

  if [[ "$missing" -ne 0 ]]; then
    echo "Start the lab first with: docker compose up -d --build" >&2
    exit 1
  fi
}

run_isp() {
  docker_cmd exec "$ISP_CONTAINER" vtysh "$@"
}

run_victim() {
  docker_cmd exec "$VICTIM_CONTAINER" vtysh "$@"
}

run_attacker() {
  docker_cmd exec "$ATTACKER_CONTAINER" vtysh "$@"
}

run_attacker_bgp_no() {
  run_attacker \
    -c "configure terminal" \
    -c "router bgp 300" \
    -c "address-family ipv4 unicast" \
    -c "$1" \
    -c "end" >/dev/null 2>&1 || true
}

run_attacker_global_no() {
  run_attacker \
    -c "configure terminal" \
    -c "$1" \
    -c "end" >/dev/null 2>&1 || true
}

clear_bgp() {
  run_isp -c "clear ip bgp *" >/dev/null
}

restart_monitor() {
  docker_cmd restart "$MONITOR_CONTAINER" >/dev/null
}

enable_rpki() {
  run_isp \
    -c "configure terminal" \
    -c "router bgp 200" \
    -c "address-family ipv4 unicast" \
    -c "neighbor 10.100.23.13 route-map RM-RPKI-DROP in" \
    -c "end" >/dev/null
}

disable_rpki() {
  run_isp \
    -c "configure terminal" \
    -c "router bgp 200" \
    -c "address-family ipv4 unicast" \
    -c "no neighbor 10.100.23.13 route-map RM-RPKI-DROP in" \
    -c "end" >/dev/null 2>&1 || true
}

restore_victim_origin() {
  run_victim \
    -c "configure terminal" \
    -c "ip route 192.168.100.0/24 blackhole" \
    -c "router bgp 100" \
    -c "address-family ipv4 unicast" \
    -c "network 192.168.100.0/24" \
    -c "end" >/dev/null
}

withdraw_victim_origin() {
  run_victim \
    -c "configure terminal" \
    -c "router bgp 100" \
    -c "address-family ipv4 unicast" \
    -c "no network 192.168.100.0/24" \
    -c "end" >/dev/null 2>&1 || true
}

withdraw_attacker_protected_routes() {
  run_attacker_bgp_no "no neighbor 10.100.23.12 route-map RM-PATH-SPOOF out"
  run_attacker_bgp_no "no network 192.168.100.0/25"
  run_attacker_bgp_no "no network 192.168.100.0/24"
  run_attacker_global_no "no route-map RM-PATH-SPOOF permit 10"
  run_attacker_global_no "no route-map RM-PATH-SPOOF permit 20"
  run_attacker_global_no "no ip prefix-list PL-PATH-SPOOF seq 5"
  run_attacker_global_no "no ip route 192.168.100.0/24 blackhole"
}

announce_subprefix_hijack() {
  run_attacker \
    -c "configure terminal" \
    -c "ip route 192.168.100.0/25 blackhole" \
    -c "router bgp 300" \
    -c "address-family ipv4 unicast" \
    -c "network 192.168.100.0/25" \
    -c "end" >/dev/null
}

announce_exact_origin_hijack() {
  run_attacker \
    -c "configure terminal" \
    -c "ip route 192.168.100.0/24 blackhole" \
    -c "router bgp 300" \
    -c "address-family ipv4 unicast" \
    -c "network 192.168.100.0/24" \
    -c "end" >/dev/null
}

announce_path_spoof() {
  run_attacker \
    -c "configure terminal" \
    -c "ip route 192.168.100.0/24 blackhole" \
    -c "ip prefix-list PL-PATH-SPOOF seq 5 permit 192.168.100.0/24" \
    -c "route-map RM-PATH-SPOOF permit 10" \
    -c "match ip address prefix-list PL-PATH-SPOOF" \
    -c "set as-path prepend 100" \
    -c "exit" \
    -c "route-map RM-PATH-SPOOF permit 20" \
    -c "exit" \
    -c "router bgp 300" \
    -c "address-family ipv4 unicast" \
    -c "neighbor 10.100.23.12 route-map RM-PATH-SPOOF out" \
    -c "network 192.168.100.0/24" \
    -c "end" >/dev/null
}

show_next_steps() {
  cat <<'NEXT'

Suggested verification:
  docker exec isp-r2 vtysh -c "show ip bgp"
  docker exec isp-r2 vtysh -c "show ip route 192.168.100.0/25"
  docker logs --tail 80 exabgp-monitor
  tail -n 5 logs/detections.jsonl
  tail -n 5 metrics/latency.csv

NEXT
}

scenario="${1:-}"

case "$scenario" in
  -h|--help|help|"")
    usage
    exit 0
    ;;
esac

detect_docker
require_containers

case "$scenario" in
  baseline|reset)
    echo "[*] Restoring clean protected baseline..."
    restart_monitor
    restore_victim_origin
    withdraw_attacker_protected_routes
    enable_rpki
    clear_bgp
    show_next_steps
    ;;
  subprefix-rpki)
    echo "[*] Launching sub-prefix hijack with RPKI enabled..."
    restart_monitor
    restore_victim_origin
    withdraw_attacker_protected_routes
    enable_rpki
    announce_subprefix_hijack
    clear_bgp
    show_next_steps
    ;;
  subprefix-detect)
    echo "[*] Launching sub-prefix hijack with RPKI disabled for Python mitigation demo..."
    restart_monitor
    restore_victim_origin
    withdraw_attacker_protected_routes
    disable_rpki
    announce_subprefix_hijack
    clear_bgp
    show_next_steps
    ;;
  exact-origin-detect)
    echo "[*] Launching exact-prefix unauthorized-origin hijack..."
    restart_monitor
    withdraw_attacker_protected_routes
    withdraw_victim_origin
    disable_rpki
    announce_exact_origin_hijack
    clear_bgp
    show_next_steps
    ;;
  path-spoof-detect)
    echo "[*] Launching AS-path spoof / suspicious-transit demo..."
    restart_monitor
    withdraw_attacker_protected_routes
    withdraw_victim_origin
    enable_rpki
    announce_path_spoof
    clear_bgp
    show_next_steps
    ;;
  *)
    echo "Unknown scenario: $scenario" >&2
    usage >&2
    exit 2
    ;;
esac
