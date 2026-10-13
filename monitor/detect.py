#!/usr/bin/env python3
"""ExaBGP route monitor for the Secure BGP hijack lab.

Only BGP commands are written to stdout. Human-readable logs go to stderr and
structured evidence is written to JSONL/CSV files.
"""

from __future__ import annotations

import csv
import json
import os
import random
import re
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from ipaddress import IPv4Network, ip_network
from pathlib import Path
from typing import Any, Iterable


# --- Lab policy -----------------------------------------------------------

PROTECTED_PREFIX = ip_network(os.getenv("BGP_LAB_PROTECTED_PREFIX", "192.168.100.0/24"))
AUTHORIZED_ORIGINS = {
    int(asn.strip())
    for asn in os.getenv("BGP_LAB_AUTHORIZED_ORIGINS", "100").split(",")
    if asn.strip()
}
SUSPICIOUS_ASNS = {
    int(asn.strip())
    for asn in os.getenv("BGP_LAB_SUSPICIOUS_ASNS", "300").split(",")
    if asn.strip()
}
TRUSTED_MITIGATION_ORIGINS = {
    int(asn.strip())
    for asn in os.getenv("BGP_LAB_TRUSTED_MITIGATION_ORIGINS", "400").split(",")
    if asn.strip()
}

VICTIM_NEXT_HOP = os.getenv("BGP_LAB_VICTIM_NEXT_HOP", "10.100.12.11")
COUNTER_ROUTE_COMMUNITY = os.getenv("BGP_LAB_COUNTER_ROUTE_COMMUNITY", "65000:666")
MITIGATION_MODE = "local_preference_counter_route"

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent if SCRIPT_DIR.name == "monitor" else SCRIPT_DIR
LOG_DIR = Path(os.getenv("BGP_LAB_LOG_DIR", PROJECT_ROOT / "logs"))
METRICS_DIR = Path(os.getenv("BGP_LAB_METRICS_DIR", PROJECT_ROOT / "metrics"))

BGP_UPDATES_FILE = LOG_DIR / "bgp_updates.jsonl"
DETECTIONS_FILE = LOG_DIR / "detections.jsonl"
MITIGATIONS_FILE = LOG_DIR / "mitigations.jsonl"
LATENCY_FILE = METRICS_DIR / "latency.csv"
SUMMARY_FILE = METRICS_DIR / "summary.md"

LATENCY_FIELDS = [
    "event_id",
    "prefix",
    "origin_as",
    "as_path",
    "arrival_ts",
    "detection_ts",
    "mitigation_ts",
    "detection_latency_ms",
    "mitigation_latency_ms",
    "result",
]

RANDOM_SEED = 42
random.seed(RANDOM_SEED)

mitigated_prefixes: set[str] = set()
_event_id = 0
ml_model: Any | None = None


def configure_output_paths(log_dir: Path, metrics_dir: Path) -> None:
    """Update output paths after validating/falling back from a bad mount."""
    global LOG_DIR, METRICS_DIR, BGP_UPDATES_FILE, DETECTIONS_FILE, MITIGATIONS_FILE
    global LATENCY_FILE, SUMMARY_FILE

    LOG_DIR = Path(log_dir)
    METRICS_DIR = Path(metrics_dir)
    BGP_UPDATES_FILE = LOG_DIR / "bgp_updates.jsonl"
    DETECTIONS_FILE = LOG_DIR / "detections.jsonl"
    MITIGATIONS_FILE = LOG_DIR / "mitigations.jsonl"
    LATENCY_FILE = METRICS_DIR / "latency.csv"
    SUMMARY_FILE = METRICS_DIR / "summary.md"


@dataclass(frozen=True)
class RouteAnalysis:
    prefix: str
    as_path: list[int]
    origin_as: int | None
    suspicious: bool
    reason: str
    touches_protected: bool
    more_specific: bool
    rule: str


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def iso_ts(epoch_seconds: float | None = None) -> str:
    if epoch_seconds is None:
        epoch_seconds = time.time()
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat()


def next_event_id() -> int:
    global _event_id
    _event_id += 1
    return _event_id


def parse_prefix(prefix_str: str) -> IPv4Network:
    return ip_network(prefix_str, strict=False)


def touches_protected_space(prefix_str: str) -> bool:
    candidate = parse_prefix(prefix_str)
    return (
        candidate.subnet_of(PROTECTED_PREFIX)
        or candidate.supernet_of(PROTECTED_PREFIX)
        or candidate.overlaps(PROTECTED_PREFIX)
    )


def is_more_specific_hijack(prefix_str: str) -> bool:
    candidate = parse_prefix(prefix_str)
    return candidate.subnet_of(PROTECTED_PREFIX) and candidate.prefixlen > PROTECTED_PREFIX.prefixlen


def analyze_route(prefix_str: str, as_path: Iterable[int | str]) -> RouteAnalysis:
    path = [int(asn) for asn in as_path]

    if not touches_protected_space(prefix_str):
        return RouteAnalysis(
            prefix=prefix_str,
            as_path=path,
            origin_as=path[-1] if path else None,
            suspicious=False,
            reason="Outside protected prefix",
            touches_protected=False,
            more_specific=False,
            rule="outside_protected_space",
        )

    if not path:
        return RouteAnalysis(
            prefix=prefix_str,
            as_path=path,
            origin_as=None,
            suspicious=True,
            reason="Missing AS_PATH for protected prefix",
            touches_protected=True,
            more_specific=is_more_specific_hijack(prefix_str),
            rule="missing_as_path",
        )

    origin_as = int(path[-1])
    more_specific = is_more_specific_hijack(prefix_str)

    if origin_as in TRUSTED_MITIGATION_ORIGINS:
        return RouteAnalysis(
            prefix=prefix_str,
            as_path=path,
            origin_as=origin_as,
            suspicious=False,
            reason=f"Trusted mitigation route from AS{origin_as}",
            touches_protected=True,
            more_specific=more_specific,
            rule="trusted_mitigation_origin",
        )

    if origin_as not in AUTHORIZED_ORIGINS:
        return RouteAnalysis(
            prefix=prefix_str,
            as_path=path,
            origin_as=origin_as,
            suspicious=True,
            reason=f"Unauthorized origin AS{origin_as}",
            touches_protected=True,
            more_specific=more_specific,
            rule="unauthorized_origin",
        )

    if more_specific:
        return RouteAnalysis(
            prefix=prefix_str,
            as_path=path,
            origin_as=origin_as,
            suspicious=True,
            reason=f"More-specific announcement inside protected prefix: {prefix_str}",
            touches_protected=True,
            more_specific=True,
            rule="more_specific_prefix",
        )

    unexpected_transit = [asn for asn in path[:-1] if int(asn) in SUSPICIOUS_ASNS]
    if unexpected_transit:
        return RouteAnalysis(
            prefix=prefix_str,
            as_path=path,
            origin_as=origin_as,
            suspicious=True,
            reason=f"Suspicious transit ASN(s) in AS_PATH: {unexpected_transit}",
            touches_protected=True,
            more_specific=False,
            rule="suspicious_transit_asn",
        )

    return RouteAnalysis(
        prefix=prefix_str,
        as_path=path,
        origin_as=origin_as,
        suspicious=False,
        reason="Route accepted",
        touches_protected=True,
        more_specific=False,
        rule="accepted",
    )


def _append_asns_from_value(value: Any, output: list[int]) -> None:
    if value is None:
        return
    if isinstance(value, int):
        output.append(value)
        return
    if isinstance(value, str):
        output.extend(int(number) for number in re.findall(r"\d+", value))
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _append_asns_from_value(item, output)
        return
    if isinstance(value, dict):
        if "value" in value:
            _append_asns_from_value(value["value"], output)
            return
        for key in sorted(value.keys(), key=lambda item: str(item)):
            _append_asns_from_value(value[key], output)


def normalize_as_path(raw_as_path: Any) -> list[int]:
    as_path: list[int] = []
    _append_asns_from_value(raw_as_path, as_path)
    return as_path


def extract_announcements(update: dict[str, Any]) -> list[dict[str, str]]:
    announcements: list[dict[str, str]] = []
    ipv4_unicast = update.get("announce", {}).get("ipv4 unicast", {})

    if not isinstance(ipv4_unicast, dict):
        return announcements

    for nexthop, prefixes in ipv4_unicast.items():
        if not isinstance(prefixes, list):
            continue
        for prefix_obj in prefixes:
            prefix = None
            if isinstance(prefix_obj, dict):
                prefix = prefix_obj.get("nlri") or prefix_obj.get("prefix")
            elif isinstance(prefix_obj, str):
                prefix = prefix_obj

            if prefix:
                announcements.append({"prefix": str(prefix), "nexthop": str(nexthop)})

    return announcements


def ensure_output_files(
    log_dir: Path | None = None,
    metrics_dir: Path | None = None,
    latency_file: Path | None = None,
) -> None:
    if log_dir is None:
        log_dir = LOG_DIR
    if metrics_dir is None:
        metrics_dir = METRICS_DIR
    if latency_file is None:
        latency_file = LATENCY_FILE

    try:
        _ensure_output_files(log_dir, metrics_dir, latency_file)
    except PermissionError as exc:
        fallback_root = Path(os.getenv("BGP_LAB_FALLBACK_OUTPUT_DIR", "/tmp/bgp-lab"))
        fallback_logs = fallback_root / "logs"
        fallback_metrics = fallback_root / "metrics"
        log(
            "[WARN] Cannot write to configured log/metrics mount "
            f"({exc}). Falling back to {fallback_root}. "
            "Fix host permissions on logs/ and metrics/ for persistent files."
        )
        configure_output_paths(fallback_logs, fallback_metrics)
        _ensure_output_files(LOG_DIR, METRICS_DIR, LATENCY_FILE)


def _ensure_output_files(log_dir: Path, metrics_dir: Path, latency_file: Path) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    metrics_dir.mkdir(parents=True, exist_ok=True)

    for path in (
        log_dir / "bgp_updates.jsonl",
        log_dir / "detections.jsonl",
        log_dir / "mitigations.jsonl",
    ):
        path.touch(exist_ok=True)

    if not latency_file.exists() or latency_file.stat().st_size == 0:
        with latency_file.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=LATENCY_FIELDS)
            writer.writeheader()

    summary_file = metrics_dir / "summary.md"
    if not summary_file.exists():
        summary_file.write_text(
            "# BGP Detection Metrics\n\n"
            "Generated by `monitor/detect.py`.\n\n"
            "- `latency.csv` records update arrival, detection, and mitigation timestamps.\n"
            "- Detection latency is measured from the ExaBGP update timestamp when present, "
            "or from the time the Python process reads stdin.\n"
            "- Mitigation latency is measured when a counter-route command is emitted to ExaBGP.\n",
            encoding="utf-8",
        )


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
    except PermissionError as exc:
        log(f"[WARN] Could not write JSONL event to {path}: {exc}")


def write_detection_event(path: Path, event: dict[str, Any]) -> None:
    append_jsonl(path, event)


def write_latency_row(path: Path, row: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        should_write_header = not path.exists() or path.stat().st_size == 0
        with path.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=LATENCY_FIELDS)
            if should_write_header:
                writer.writeheader()
            writer.writerow({field: row.get(field, "") for field in LATENCY_FIELDS})
    except PermissionError as exc:
        log(f"[WARN] Could not write latency row to {path}: {exc}")


def build_and_train_model() -> Any | None:
    """Build the optional supervised classifier used as a secondary signal."""
    try:
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier
    except Exception as exc:  # pragma: no cover - depends on optional runtime packages
        log(f"[ML ENGINE] Optional supervised classifier disabled: {exc}")
        return None

    np.random.seed(RANDOM_SEED)
    random.seed(RANDOM_SEED)
    log("[ML ENGINE] Training supervised RandomForest route classifier with synthetic data.")

    x_train: list[list[int]] = []
    y_train: list[int] = []

    for _ in range(400):
        x_train.append([1, 24, 100])
        y_train.append(1)
    for _ in range(50):
        x_train.append([2, 24, 100])
        y_train.append(1)
    for _ in range(50):
        x_train.append([2, 23, 100])
        y_train.append(1)

    known_safe_asns = AUTHORIZED_ORIGINS | TRUSTED_MITIGATION_ORIGINS | {200}
    for _ in range(1000):
        hostile_asn = random.randint(1, 65000)
        if hostile_asn in known_safe_asns:
            continue
        x_train.append([1, 25, hostile_asn])
        y_train.append(-1)
        x_train.append([2, 25, hostile_asn])
        y_train.append(-1)
        x_train.append([2, 24, hostile_asn])
        y_train.append(-1)

    for _ in range(100):
        x_train.append([1, 25, 100])
        y_train.append(-1)
    for _ in range(50):
        x_train.append([5, 24, 100])
        y_train.append(-1)
        x_train.append([6, 24, 100])
        y_train.append(-1)

    model = RandomForestClassifier(n_estimators=15, random_state=RANDOM_SEED)
    model.fit(x_train, y_train)
    log("[ML ENGINE] Training complete. Deterministic rules remain the primary control.")
    return model


def ml_flags_route(prefix: str, as_path: list[int], model: Any | None) -> bool:
    if model is None or not as_path:
        return False
    try:
        import numpy as np

        prefix_length = parse_prefix(prefix).prefixlen
        live_feature = np.array([[len(as_path), prefix_length, int(as_path[-1])]])
        return int(model.predict(live_feature)[0]) == -1
    except Exception as exc:  # pragma: no cover - defensive around optional ML deps
        log(f"[ML ENGINE] Classifier failed for {prefix}: {exc}")
        return False


def build_counter_route_command(prefix: str) -> str:
    return (
        f"announce route {prefix} next-hop {VICTIM_NEXT_HOP} "
        f"community [ {COUNTER_ROUTE_COMMUNITY} ]"
    )


def emit_exabgp_command(command: str) -> None:
    sys.stdout.write(command + "\n")
    sys.stdout.flush()


def _safe_arrival_ts(data: dict[str, Any], read_ts: float) -> float:
    try:
        return float(data.get("time", read_ts))
    except (TypeError, ValueError):
        return read_ts


def process_update(line: str, model: Any | None = None) -> None:
    line = line.strip()
    if not line or line == "done":
        return

    read_ts = time.time()

    try:
        data = json.loads(line)
    except json.JSONDecodeError as exc:
        log(f"[ERROR] Failed to parse ExaBGP JSON: {exc}. Raw input: {line}")
        return

    if data.get("type") != "update":
        return

    arrival_ts = _safe_arrival_ts(data, read_ts)
    update = data.get("neighbor", {}).get("message", {}).get("update", {})
    raw_as_path = update.get("attribute", {}).get("as-path")
    as_path = normalize_as_path(raw_as_path)
    announcements = extract_announcements(update)

    for announcement in announcements:
        prefix = announcement["prefix"]
        nexthop = announcement["nexthop"]
        analysis = analyze_route(prefix, as_path)
        detection_ts = time.time()

        append_jsonl(
            BGP_UPDATES_FILE,
            {
                "timestamp": iso_ts(detection_ts),
                "prefix": prefix,
                "nexthop": nexthop,
                "as_path": as_path,
                "origin_as": analysis.origin_as,
                "touches_protected": analysis.touches_protected,
            },
        )

        suspicious = analysis.suspicious
        reason = analysis.reason
        rule = analysis.rule

        if (
            not suspicious
            and analysis.touches_protected
            and analysis.origin_as not in TRUSTED_MITIGATION_ORIGINS
            and ml_flags_route(prefix, as_path, model)
        ):
            suspicious = True
            reason = "Supervised route classifier flagged synthetic risk pattern"
            rule = "supervised_classifier"

        if not suspicious:
            if analysis.touches_protected:
                log(f"[OK] {prefix} via AS_PATH {as_path}: {analysis.reason}")
            continue

        event_id = next_event_id()
        action = "already_mitigated"
        mitigation_ts: float | None = None

        if prefix not in mitigated_prefixes:
            mitigated_prefixes.add(prefix)
            command = build_counter_route_command(prefix)
            mitigation_ts = time.time()
            emit_exabgp_command(command)
            action = "mitigation_announced"

            append_jsonl(
                MITIGATIONS_FILE,
                {
                    "event_id": event_id,
                    "timestamp": iso_ts(mitigation_ts),
                    "prefix": prefix,
                    "as_path": as_path,
                    "origin_as": analysis.origin_as,
                    "action": action,
                    "mode": MITIGATION_MODE,
                    "command": command,
                },
            )

        detection_latency_ms = max((detection_ts - arrival_ts) * 1000, 0.0)
        mitigation_latency_ms = (
            max((mitigation_ts - arrival_ts) * 1000, 0.0) if mitigation_ts is not None else ""
        )

        event = {
            "event_id": event_id,
            "timestamp": iso_ts(detection_ts),
            "prefix": prefix,
            "as_path": as_path,
            "origin_as": analysis.origin_as,
            "reason": reason,
            "rule": rule,
            "action": action,
            "mitigation_mode": MITIGATION_MODE,
            "detection_latency_ms": round(detection_latency_ms, 3),
        }
        if mitigation_ts is not None:
            event["mitigation_latency_ms"] = round(float(mitigation_latency_ms), 3)

        write_detection_event(DETECTIONS_FILE, event)
        write_latency_row(
            LATENCY_FILE,
            {
                "event_id": event_id,
                "prefix": prefix,
                "origin_as": analysis.origin_as,
                "as_path": " ".join(str(asn) for asn in as_path),
                "arrival_ts": iso_ts(arrival_ts),
                "detection_ts": iso_ts(detection_ts),
                "mitigation_ts": iso_ts(mitigation_ts) if mitigation_ts else "",
                "detection_latency_ms": round(detection_latency_ms, 3),
                "mitigation_latency_ms": round(float(mitigation_latency_ms), 3)
                if mitigation_ts is not None
                else "",
                "result": action,
            },
        )

        log(
            f"[ALERT] Event {event_id}: {reason}; prefix={prefix}; "
            f"as_path={as_path}; action={action}; latency={detection_latency_ms:.3f} ms"
        )


def main() -> None:
    global ml_model
    ensure_output_files()
    ml_model = build_and_train_model()
    log(
        "[SYSTEM] BGP monitor active. Primary detection is deterministic AS-path/RPKI "
        "policy logic; optional ML is a supervised synthetic route classifier."
    )

    for line in sys.stdin:
        process_update(line, ml_model)


if __name__ == "__main__":
    main()
