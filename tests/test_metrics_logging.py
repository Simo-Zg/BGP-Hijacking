import csv
import json

from monitor.detect import write_detection_event, write_latency_row


def test_detection_event_is_written_to_jsonl(tmp_path):
    output = tmp_path / "detections.jsonl"
    event = {
        "event_id": 1,
        "timestamp": "2026-05-11T00:00:00+00:00",
        "prefix": "192.168.100.0/25",
        "as_path": [200, 300],
        "origin_as": 300,
        "reason": "Unauthorized origin AS300",
        "action": "mitigation_announced",
    }

    write_detection_event(output, event)

    lines = output.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0]) == event


def test_latency_row_is_written_to_csv(tmp_path):
    output = tmp_path / "latency.csv"

    write_latency_row(
        output,
        {
            "event_id": 1,
            "prefix": "192.168.100.0/25",
            "origin_as": 300,
            "as_path": "200 300",
            "arrival_ts": "2026-05-11T00:00:00+00:00",
            "detection_ts": "2026-05-11T00:00:00.001000+00:00",
            "mitigation_ts": "2026-05-11T00:00:00.002000+00:00",
            "detection_latency_ms": 1.0,
            "mitigation_latency_ms": 2.0,
            "result": "mitigation_announced",
        },
    )

    with output.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == 1
    assert rows[0]["prefix"] == "192.168.100.0/25"
    assert rows[0]["detection_latency_ms"] == "1.0"
    assert rows[0]["result"] == "mitigation_announced"
