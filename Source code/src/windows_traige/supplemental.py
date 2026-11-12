"""Intake of explicit local evidence from outside Windows Traige."""

import csv
import hashlib
import os
import stat
from dataclasses import asdict, dataclass
from contextlib import contextmanager
from functools import partial
from pathlib import Path

from . import bundle, netcapture
from .common import Invalid, check_cancel, decode, encode, now, safe_path, timestamp

LABELS = {
    "disk-image": "Disk image",
    "memory-capture": "Memory capture",
    "endpoint-telemetry": "Endpoint telemetry",
    "identity-activity": "Identity activity",
    "network-evidence": "Network evidence",
}
IMAGE_TYPES = {"disk-image", "memory-capture"}
MAX_EXPORT_BYTES = 64 * 1024 ** 2
MAX_NETWORK_BYTES = 512 * 1024 ** 2
MAX_INDEX_BYTES = 64 * 1024 ** 2
MAX_ROWS = 100_000
REQUIRED_DEVICE = {"Timestamp", "DeviceId", "DeviceName", "ActionType", "ReportId"}


@dataclass(frozen=True)
class OfflineReceipt:
    source_device: str
    output_device: str
    write_blocker: str
    sector_bytes: int
    source_bytes: int
    read_errors: int
    operator_verified: bool


@dataclass(frozen=True)
class Selection:
    kind: str
    path: str = ""
    checksum: str = ""
    source: str = ""
    tool: str = ""
    operator: str = ""
    captured: str = ""
    notes: str = ""
    size: int | None = None
    offline: OfflineReceipt | None = None


def validate_receipt(value):
    if not isinstance(value, OfflineReceipt) or value.operator_verified is not True:
        raise Invalid("Confirm the offline disk acquisition and its hardware write protection")
    devices = (value.source_device, value.output_device, value.write_blocker)
    if any(not isinstance(entry, str) or not entry.strip() or len(entry) > 150 or
           any(ord(ch) < 32 for ch in entry) for entry in devices):
        raise Invalid("Record the source disk, separate output disk and write blocker identifiers")
    if value.source_device.strip().casefold() == value.output_device.strip().casefold():
        raise Invalid("The source disk and output disk must be different devices")
    if (type(value.sector_bytes) is not int or value.sector_bytes not in {512, 4096} or
            type(value.source_bytes) is not int or not 0 < value.source_bytes <= bundle.MAX_ATTACHMENT_BYTES or
            value.source_bytes % value.sector_bytes or type(value.read_errors) is not int or
            not 0 <= value.read_errors <= value.source_bytes // value.sector_bytes):
        raise Invalid("Enter valid source geometry and the tool's reported read-error count")


def validate_offline(item):
    if item.kind != "disk-image":
        raise Invalid("Offline acquisition details apply to disk images")
    validate_receipt(item.offline)
    if not all((item.tool.strip(), item.operator.strip(), item.captured, item.checksum)):
        raise Invalid("Record the tool, operator, acquisition time and independent SHA-256 for offline imaging")


def validate(selections):
    kinds, paths = set(), set()
    planned = []
    for item in selections:
        if not isinstance(item, Selection) or item.kind not in LABELS or item.kind in kinds:
            raise Invalid("Choose each supplemental evidence type once")
        kinds.add(item.kind)
        for value in (item.source, item.tool, item.operator, item.notes):
            if not isinstance(value, str) or len(value) > 500 or any(ord(ch) < 32 for ch in value):
                raise Invalid("Use single-line evidence details up to 500 characters")
        path = safe_path(item.path) if item.path else None
        checksum = str(safe_path(item.checksum)) if item.checksum else ""
        if path is not None:
            key = os.path.normcase(str(path))
            if key in paths or key == os.path.normcase(checksum):
                raise Invalid("Select a distinct file for each evidence source and its checksum")
            paths.add(key)
        size = None
        if path and path.is_file():
            size = path.stat().st_size
        if item.offline is not None:
            validate_offline(item)
        planned.append(Selection(item.kind, str(path) if path else "", checksum, item.source, item.tool,
                                 item.operator, timestamp(item.captured) if item.captured else "", item.notes,
                                 size, item.offline))
    return tuple(planned)


def file_size(path, kind):
    suffix = path.suffix.lower().lstrip(".")
    if suffix not in bundle.ATTACHMENT_TYPES[kind]:
        expected = ", ".join("." + extension for extension in sorted(bundle.ATTACHMENT_TYPES[kind]))
        raise Invalid(f"Choose a supported {LABELS[kind].lower()} file ({expected})")
    info = path.stat()
    limit = (bundle.MAX_ATTACHMENT_BYTES if kind in IMAGE_TYPES else
             MAX_NETWORK_BYTES if kind == "network-evidence" else MAX_EXPORT_BYTES)
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
        raise Invalid("The supplied file is empty or exceeds the supported size")
    if kind == "disk-image" and info.st_size % 512:
        raise Invalid("A raw disk image must contain complete sectors")
    return info.st_size, suffix


def space_estimate(items):
    originals = snapshots = index = 0
    for item in items:
        if item.size:
            originals += item.size
            if item.kind not in IMAGE_TYPES:
                snapshots += item.size
                index += min(MAX_INDEX_BYTES, item.size * 8)
    return originals, snapshots + index * 2


def file_identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


@contextmanager
def open_original(path, identity):
    with safe_path(path).open("rb") as source:
        if file_identity(os.fstat(source.fileno())) != identity:
            raise Invalid("The evidence file changed before packaging")
        yield source
        if file_identity(os.fstat(source.fileno())) != identity:
            raise Invalid("The evidence file changed during packaging")


def source_stream(path, size, snapshot, cancel):
    """Hash an ordinary local file, optionally making an exact parser input copy."""
    h = hashlib.sha256()
    copied = 0
    with path.open("rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size != size:
            raise Invalid("The evidence file changed since selection")
        while block := source.read(1024 * 1024):
            check_cancel(cancel)
            copied += len(block)
            if copied > size:
                raise Invalid("The evidence file changed while it was being read")
            h.update(block)
            if snapshot is not None:
                snapshot.write(block)
        after = os.fstat(source.fileno())
    if copied != size or before.st_mtime_ns != after.st_mtime_ns:
        raise Invalid("The evidence file changed while it was being read")
    return h.hexdigest()


def text(value, field, *, required=False):
    if value is None and not required:
        return None
    if not isinstance(value, str) or len(value) > 2048 or (required and not value.strip()):
        raise Invalid(f"Invalid value in {field}")
    return value


def endpoint_rows(path):
    with path.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source, strict=True)
        columns = reader.fieldnames or []
        if (len(columns) != len(set(columns)) or len(columns) > 64 or not REQUIRED_DEVICE <= set(columns)):
            raise Invalid("Defender CSV needs Timestamp, DeviceId, DeviceName, ActionType and ReportId")
        for row in reader:
            if None in row:
                raise Invalid("A Defender CSV record has unexpected columns")
            fields = {
                "source_computer": text(row["DeviceName"], "DeviceName", required=True),
                "device_id": text(row["DeviceId"], "DeviceId", required=True),
                "action": text(row["ActionType"], "ActionType", required=True),
                "external_id": text(row["ReportId"], "ReportId", required=True),
                "channel": "Microsoft Defender XDR DeviceEvents",
                "source_line": reader.line_num,
            }
            observed = timestamp(text(row["Timestamp"], "Timestamp", required=True))
            yield "event", observed, fields


def identity_rows(path, notices):
    value = decode(path.read_bytes().decode("utf-8-sig"))
    if isinstance(value, dict):
        if value.get("@odata.nextLink"):
            notices.append("The Entra export indicates another page")
        value = value.get("value")
    if not isinstance(value, list):
        raise Invalid("Choose an Entra sign-in JSON array or a Graph export with a value array")
    for row in value:
        if not isinstance(row, dict):
            raise Invalid("Invalid Entra sign-in record")
        status = row.get("status") or {}
        if not isinstance(status, dict) or ("errorCode" in status and type(status["errorCode"]) is not int):
            raise Invalid("Invalid Entra sign-in status")
        fields = {
            "external_id": text(row.get("id"), "id", required=True),
            "account": text(row.get("userPrincipalName"), "userPrincipalName"),
            "application": text(row.get("appDisplayName"), "appDisplayName"),
            "ip": text(row.get("ipAddress"), "ipAddress"),
            "error_code": status.get("errorCode"),
            "channel": "Microsoft Entra sign-ins",
            "action": "Sign-in",
        }
        observed = timestamp(text(row.get("createdDateTime"), "createdDateTime", required=True))
        yield "event", observed, fields


def network_rows(path, cancel):
    for number, (observed, link, frame) in enumerate(netcapture.packets(path, cancel), 1):
        values = netcapture.connection(link, frame)
        if values is None:
            yield None
        else:
            yield "network", observed, dict(values, packet_number=number)


def normalize(path, target, member, item, started, cancel):
    kind = item.kind
    notices = []
    if kind == "endpoint-telemetry":
        rows = endpoint_rows(path)
    elif kind == "identity-activity":
        rows = identity_rows(path, notices)
    else:
        rows = network_rows(path, cancel)
    count = skipped = total = 0
    earliest = latest = None
    with target.open("xb") as out:
        for ordinal, value in enumerate(rows, 1):
            check_cancel(cancel)
            if ordinal > MAX_ROWS:
                notices.append("Index record limit reached")
                break
            if value is None:
                skipped += 1
                continue
            row_kind, observed, fields = value
            observed = timestamp(observed)
            if item.source and not fields.get("source_computer"):
                fields["source_computer"] = item.source
            row = bundle.record(f"{kind}-{ordinal}", row_kind, member, started, observed,
                                evidence_kind=kind, **fields)
            line = encode(row) + b"\n"
            if len(line) > bundle.MAX_LINE or total + len(line) > MAX_INDEX_BYTES:
                notices.append("Index byte limit reached")
                break
            out.write(line)
            count += 1
            total += len(line)
            earliest = min(earliest, observed) if earliest else observed
            latest = max(latest, observed) if latest else observed
    if skipped:
        notices.append(f"{skipped} packets were outside the supported connection index")
    return count, earliest, latest, notices


def acquire(item, payload, work, cancel, progress):
    """Return coverage and optional verified original payload for one selection."""
    started = now()
    attempt = {"collector": item.kind, "channel": None, "started": started, "privilege": "file input",
               "count": 0, "payloads": []}
    target = payload / "normalized" / f"{item.kind}.jsonl"
    attachment = original = None
    try:
        check_cancel(cancel)
        if not item.path:
            raise FileNotFoundError
        source = safe_path(item.path)
        size, suffix = file_size(source, item.kind)
        if item.size != size:
            raise Invalid("The evidence size changed since preview. Select the file again.")
        expected = bundle.external_hash(item.checksum or None)
        if progress:
            progress(f"Reading {LABELS[item.kind].lower()}", 0)
        member = f"attachments/{item.kind}.{suffix}"
        if item.kind in IMAGE_TYPES:
            identity = file_identity(source.stat())
            checksum = source_stream(source, size, None, cancel) if expected else None
            opener = partial(open_original, source, identity)
        else:
            file = work / f"{item.kind}.{suffix}"
            with file.open("xb") as snapshot:
                checksum = source_stream(source, size, snapshot, cancel)
            opener = partial(file.open, "rb")
        if expected and checksum != expected:
            raise Invalid("Detached SHA-256 does not match the supplied evidence")
        count, earliest, latest, notices = 0, None, None, []
        if item.offline is not None:
            receipt = item.offline
            if (size % receipt.sector_bytes or size > receipt.source_bytes or
                    (size != receipt.source_bytes and not receipt.read_errors)):
                raise Invalid("Image size disagrees with the offline acquisition record")
            if receipt.read_errors:
                notices.append(f"Offline imaging operator reported {receipt.read_errors:,} read errors")
        if item.kind not in IMAGE_TYPES:
            count, earliest, latest, notices = normalize(file, target, member, item, started, cancel)
        if item.kind in IMAGE_TYPES:
            count, earliest, latest = 1, item.captured or None, item.captured or None
        if item.kind in IMAGE_TYPES or not count:
            row = bundle.record(f"{item.kind}-original", "file", member, started, item.captured or None,
                                evidence_kind=item.kind, filename=source.name, size=size,
                                source_computer=item.source or (item.offline.source_device if item.offline else None),
                                tool=item.tool or None)
            target.write_bytes(encode(row) + b"\n")
        origin = {"kind": item.kind, "payload": member, "filename": source.name, "source": item.source,
                  "tool": item.tool, "operator": item.operator, "captured": item.captured or None,
                  "notes": item.notes, "start": earliest, "end": latest, "count": count,
                  "external": "matched" if expected else "not supplied", "received_utc": started}
        if item.offline:
            origin["offline"] = asdict(item.offline)
        attachment = bundle.Payload(size, opener, checksum)
        original = origin
        reason = ". ".join(notices)
        if not reason:
            reason = "Original file preserved" if count else "No records in the supplied export"
        attempt.update(status="Partial" if notices else "Collected", reason=reason,
                       count=count, payloads=[member, target.relative_to(payload).as_posix()])
    except FileNotFoundError:
        attempt.update(status="Unavailable", reason="Select an available evidence file and any supplied checksum")
    except PermissionError:
        attempt.update(status="Access Denied", reason="Windows denied access to the selected evidence file")
    except Invalid as exc:
        attempt.update(status="Failed", reason=str(exc))
    except (csv.Error, UnicodeError, OSError):
        attempt.update(status="Failed", reason="The evidence file could not be read as the selected format")
    if attachment is None:
        target.unlink(missing_ok=True)
    attempt["finished"] = now()
    return attempt, original, attachment
