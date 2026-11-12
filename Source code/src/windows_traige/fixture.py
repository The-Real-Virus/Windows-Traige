"""Redistributable, deterministic synthetic evidence content."""

from datetime import datetime, timedelta
from pathlib import Path
import tempfile

from .bundle import finalize, new_run, record
from .common import Invalid, check_cancel, encode, now, safe_path

DEFAULT = {
    "host": "SYNTHETIC-WORKSTATION", "observed": "2025-05-01T13:00:00Z",
    "process_created": "2025-05-01T12:55:00Z", "reused_created": "2025-05-01T13:03:00Z",
    "event_id": 7045, "channel": "System", "pid": 4420, "path": r"C:\Fixtures\demo-worker.exe",
    "remote_ip": "192.0.2.25", "remote_port": 443,
}


def create(directory, count=0, cancel=None):
    if not 0 <= count <= 1_000_000:
        raise Invalid("Synthetic record count is outside allowed bounds")
    directory = safe_path(directory)
    data = DEFAULT
    observed = data["observed"]
    acquired = "2025-05-01T13:00:15Z"
    source = "normalized/fixture.jsonl"
    pid = data["pid"]
    rows = [
        record("fixture-process", "process", source, acquired, data["process_created"],
               pid=pid, created=data["process_created"], path=data["path"]),
        record("fixture-reused-pid", "process", source, "2025-05-01T13:03:05Z", data["reused_created"],
               pid=pid, created=data["reused_created"], path=r"C:\Fixtures\second-worker.exe"),
        record("fixture-network", "network", source, observed, observed, pid=pid,
               remote_ip=data["remote_ip"], remote_port=data["remote_port"], protocol="TCP"),
        record("fixture-event", "event", source, acquired, observed, pid=pid, event_id=data["event_id"],
               event_record_id=42, channel=data["channel"], severity="Information",
               message="Synthetic service installation. <script>untrusted evidence</script>"),
    ]
    with tempfile.TemporaryDirectory(prefix=".incomplete-fixture-", dir=directory) as tmp:
        root = Path(tmp)
        (root / "normalized").mkdir()
        with (root / source).open("xb") as stream:
            for row in rows:
                stream.write(encode(row) + b"\n")
            base = datetime.fromisoformat(observed)
            for index in range(count):
                check_cancel(cancel)
                observed_at = (base + timedelta(seconds=index)).isoformat()
                row = record(f"fixture-bulk-{index}", "event", source, now(), observed_at,
                             event_id=1000 + index % 50, channel="Application", severity="Information",
                             message=f"Synthetic benchmark entry {index}")
                stream.write(encode(row) + b"\n")
        attempts = [
            {"collector": "fixture", "status": "Collected", "count": len(rows) + count},
            {"collector": "events-sysmon", "status": "Unavailable", "reason": "Synthetic absent channel"},
            {"collector": "events-security", "status": "Access Denied", "reason": "Synthetic access denial"},
        ]
        (root / "coverage.txt").write_text("Synthetic collection. Sysmon absent. Security denied.\n", encoding="utf-8")
        return finalize(directory, root, {"run": new_run(), "host": data["host"],
                                          "plan": {"profile": "fixture"}, "attempts": attempts}, cancel)
