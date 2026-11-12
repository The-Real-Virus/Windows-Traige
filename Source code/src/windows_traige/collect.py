"""Read-only collection planning and bounded evidence capture."""

import hashlib
import os
import platform
import socket
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path

from . import native, supplemental
from .bundle import MAX_ATTACHMENT_BYTES, MAX_LINE, finalize, new_run, record
from .common import Cancelled, Invalid, check_cancel, encode, now, require_space, safe_path, timestamp

EVENT_CHANNELS = {
    "events-system": "System",
    "events-application": "Application",
    "events-security": "Security",
    "events-defender": "Microsoft-Windows-Windows Defender/Operational",
    "events-powershell": "Microsoft-Windows-PowerShell/Operational",
    "events-sysmon": "Microsoft-Windows-Sysmon/Operational",
}
STANDARD_EVENT_IDS = tuple(EVENT_CHANNELS)
EXTENDED_EVENTS = {
    "events-tasks": "Microsoft-Windows-TaskScheduler/Operational",
    "events-wmi": "Microsoft-Windows-WMI-Activity/Operational",
    "events-rdp": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "events-code-integrity": "Microsoft-Windows-CodeIntegrity/Operational",
    "events-firewall": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "events-dns-client": "Microsoft-Windows-DNS-Client/Operational",
    "events-winrm": "Microsoft-Windows-WinRM/Operational",
    "events-applocker": "Microsoft-Windows-AppLocker/EXE and DLL",
}
EVENT_CHANNELS.update(EXTENDED_EVENTS)
VOLATILE = ("processes", "tcp", "udp")
QUICK = VOLATILE + ("events-system", "events-application", "host", "adapters")
STANDARD = VOLATILE + STANDARD_EVENT_IDS + (
    "host", "adapters", "volumes", "routes", "dns", "services", "tasks", "startup", "applications", "settings",
    "users", "groups", "sessions",
)
EXTENDED = STANDARD + tuple(EXTENDED_EVENTS) + ("neighbors", "dns-cache", "hotfixes", "firewall-profiles")
PROFILES = {"quick": QUICK, "standard": STANDARD, "extended": EXTENDED, "custom": ()}
FILE_LIMIT = 64 * 1024 ** 2
MAX_FILES = 32
MAX_TOTAL = 192 * 1024 ** 2
MAX_ROWS = 1000
PROTECTED_NAMES = {"sam", "security", "system", "ntds.dit", "login data", "cookies", "local state", "credentials",
                   ".env", "gemini-api-key.txt", "openai-api-key.txt", "anthropic-api-key.txt"}
PROTECTED_DIRS = {"appdata", "system32", "syswow64", "programdata", ".ssh", ".aws", ".gnupg"}
ALLOWED_CUSTOM = set(EXTENDED) | {"processes-sensitive", "files"}
TIMEOUT = 20


@dataclass(frozen=True)
class Plan:
    profile: str
    destination: str
    start: str
    end: str
    collectors: tuple
    custom_channels: tuple
    files: tuple
    hash_files: bool
    max_rows: int
    timeout_seconds: int
    max_payload_bytes: int
    sensitive: tuple
    evidence: tuple = ()


def plan(profile, destination, *, hours=24, collectors=(), channels=(), files=(),
         hash_files=False, process_arguments=False, max_rows=MAX_ROWS, evidence=()):
    if profile not in PROFILES or not 1 <= hours <= (168 if profile in {"custom", "extended"} else 24):
        raise Invalid("Unsupported profile or event window")
    if not 1 <= max_rows <= MAX_ROWS or len(files) > MAX_FILES or len(channels) > 24:
        raise Invalid("Collection limit is outside supported bounds")
    if (collectors or channels) and profile != "custom":
        raise Invalid("Select specific collectors and channels in Custom")
    if (files or process_arguments) and profile not in {"custom", "extended"}:
        raise Invalid("Explicit file or command-line scope requires Custom or Extended")
    destination = safe_path(destination)
    if not destination.is_dir():
        raise Invalid("Choose an existing local output directory")
    chosen = list(dict.fromkeys(collectors if profile == "custom" else PROFILES[profile]))
    if not set(chosen) <= ALLOWED_CUSTOM:
        raise Invalid("Unrecognized collector")
    if process_arguments:
        chosen = [item for item in chosen if item != "processes"]
        chosen.insert(0, "processes-sensitive")
    if "processes-sensitive" in chosen and not process_arguments:
        raise Invalid("Explicit command-line collection consent is required")
    if files and "files" not in chosen:
        chosen.append("files")
    if ("files" in chosen or hash_files) and not files:
        raise Invalid("Select one or more files")
    custom = tuple(dict.fromkeys(channels))
    for name in custom:
        if not native.CHANNEL.fullmatch(name):
            raise Invalid("Invalid custom event channel")
    evidence = supplemental.validate(evidence)
    if not chosen and not custom and not evidence:
        raise Invalid("Select at least one collection source")
    known_channels = {EVENT_CHANNELS[item].casefold() for item in chosen if item in EVENT_CHANNELS}
    custom = tuple(dict.fromkeys(name for name in custom if name.casefold() not in known_channels))
    priorities = {key: index for index, key in enumerate(
        ("processes", "processes-sensitive", "tcp", "udp", *EVENT_CHANNELS))}
    chosen.sort(key=lambda key: priorities.get(key, len(priorities)))
    sensitive = ["Local Windows identifiers and metadata"]
    if known_channels or custom:
        sensitive.append("Windows event XML may contain secrets and personal information")
    if process_arguments:
        sensitive.append("Process command lines")
    if files:
        sensitive.append("Selected file paths and metadata" + (" and SHA-256" if hash_files else ""))
    if "dns-cache" in chosen:
        sensitive.append("DNS cache entries")
    if evidence:
        sensitive.append("Selected supplemental originals may contain private records, file contents or secrets")
    end = now()
    start = timestamp((datetime.fromisoformat(end) - timedelta(hours=hours)).isoformat())
    return Plan(profile, str(destination), start, end, tuple(chosen), custom,
                tuple(str(safe_path(path)) for path in files), hash_files, max_rows, TIMEOUT,
                min(MAX_TOTAL, (len(chosen) + len(custom)) * 2 * native.MAX_OUTPUT), tuple(sensitive), evidence)


def selected_file(path, hash_file, cancel):
    path = safe_path(path)
    if (path.name.lower() in PROTECTED_NAMES or any(part.lower() in PROTECTED_DIRS for part in path.parts[1:-1])
            or path.suffix.lower() in {".pem", ".pfx", ".key", ".kdbx", ".p12"}):
        raise Invalid("Selected file is outside the permitted evidence catalog")
    if not path.is_file():
        raise Invalid("Selected path is not a regular local file")
    before = path.stat()
    checksum = None
    reason = ""
    if hash_file:
        if before.st_size > FILE_LIMIT:
            reason = "Selected file exceeded hash size limit"
        else:
            with path.open("rb") as stream:
                opened = os.fstat(stream.fileno())
                if (opened.st_ino, opened.st_dev) != (before.st_ino, before.st_dev):
                    raise Invalid("Selected file changed before acquisition")
                remaining = FILE_LIMIT + 1
                h = hashlib.sha256()
                while remaining and (block := stream.read(min(remaining, 1024 ** 2))):
                    check_cancel(cancel)
                    h.update(block)
                    remaining -= len(block)
                if remaining:
                    checksum = h.hexdigest()
                else:
                    reason = "Selected file exceeded hash size limit during acquisition"
            after = path.stat()
            if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
                checksum = None
                reason = "Selected file changed during acquisition"
    return {"path": str(path), "bytes": before.st_size, "sha256": checksum,
            "modified": datetime.fromtimestamp(before.st_mtime).astimezone().isoformat()}, reason


def inventory_records(key, scope, cancel):
    acquired = now()
    values = native.inventory(key, scope.max_rows, scope.timeout_seconds, cancel)
    reason = "Record limit reached" if len(values) > scope.max_rows else ""
    rows = []
    for fields in values[:scope.max_rows]:
        observed = acquired
        kind = "inventory"
        if key.startswith("processes"):
            kind, observed = "process", fields.get("created")
            fields["path_access"] = "reported" if fields.get("path") else "unavailable"
        elif key in ("tcp", "udp"):
            kind = "network"
            fields["protocol"] = key.upper()
        elif key == "host":
            kind = "host"
        elif key in ("users", "groups", "sessions"):
            kind = "account"
        rows.append((kind, observed, fields))
    return rows, reason


def attempt(source, scope, payload, cancel, remaining):
    key, channel = source
    started = now()
    normalized = f"normalized/{key}.jsonl"
    native_file = f"raw/{key}.evtx"
    evtx = payload / native_file
    target = payload / normalized
    count, status, reason, sources = 0, "Collected", "", []
    try:
        if remaining < 2 * native.MAX_OUTPUT:
            raise native.NativeError("Partial", "Total payload byte limit reached")
        acquired = now()
        if channel:
            events, reason = native.events(channel, scope.start, scope.end, scope.max_rows, scope.timeout_seconds,
                                           cancel, evtx)
            rows = [("event", observed, fields) for observed, fields in events]
        elif key == "files":
            rows = []
            for index, path in enumerate(scope.files):
                check_cancel(cancel)
                try:
                    metadata, detail = selected_file(path, scope.hash_files, cancel)
                    rows.append(("file", None, metadata))
                    sources.append({"index": index, "status": "Partial" if detail else "Collected", "reason": detail})
                except (Invalid, OSError) as exc:
                    state = "Access Denied" if isinstance(exc, PermissionError) else "Failed"
                    detail = str(exc) if isinstance(exc, Invalid) else "Windows file read failed"
                    sources.append({"index": index, "status": state, "reason": detail})
            if any(item["status"] != "Collected" for item in sources):
                reason = "One or more selected files were incomplete"
        else:
            rows, reason = inventory_records(key, scope, cancel)
        if rows:
            size = 0
            with target.open("xb") as stream:
                for index, (kind, observed, fields) in enumerate(rows):
                    check_cancel(cancel)
                    source_ref = native_file if evtx.exists() else normalized
                    row = record(f"{key}-{index}", kind, source_ref, acquired, observed, **fields)
                    line = encode(row) + b"\n"
                    if len(line) > MAX_LINE or size + len(line) > native.MAX_OUTPUT:
                        reason = "Normalized record or payload byte limit reached"
                        break
                    stream.write(line)
                    size += len(line)
                    count += 1
        if reason:
            status = "Partial"
        elif not count and channel:
            reason = "No events in the requested window"
    except Cancelled:
        status, reason = "Cancelled", "Operator cancelled"
    except native.NativeError as exc:
        status, reason = exc.status, exc.reason
    except PermissionError:
        status, reason = "Access Denied", "Windows denied the source or staging path"
    except (Invalid, OSError, ValueError):
        status, reason = "Failed", "Collector could not read or encode the source"
    return {"collector": key, "channel": channel, "status": status, "reason": reason, "count": count,
            "started": started, "finished": now(), "privilege": "administrator" if is_admin() else "standard",
            "selected_sources": sources, "payloads": [name for name in (normalized, native_file)
                                                     if (payload / name).exists()]}


def is_admin():
    if os.name != "nt":
        return False
    import ctypes
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def run(scope, cancel=None, progress=None):
    directory = safe_path(scope.destination)
    originals_size, temporary_size = supplemental.space_estimate(scope.evidence)
    if originals_size > MAX_ATTACHMENT_BYTES:
        raise Invalid("Combined originals exceed the evidence ZIP limit")
    require_space(directory, originals_size + temporary_size + scope.max_payload_bytes * 2 + 16 * 1024 ** 2)
    channel_sources = tuple((f"channel-{index}", name) for index, name in enumerate(scope.custom_channels))
    sources = tuple((key, EVENT_CHANNELS.get(key)) for key in scope.collectors) + channel_sources
    with tempfile.TemporaryDirectory(prefix=".incomplete-collection-", dir=directory) as tmp:
        root = Path(tmp)
        payload = root / "payload"
        work = root / "intake"
        work.mkdir()
        (payload / "normalized").mkdir(parents=True)
        (payload / "raw").mkdir()
        results = []
        remaining = scope.max_payload_bytes
        for index, source in enumerate(sources):
            if progress:
                progress(f"Collecting {source[1] or source[0]} ({index + 1}/{len(sources)})", index)
            result = attempt(source, scope, payload, cancel, remaining)
            results.append(result)
            remaining -= sum((payload / name).stat().st_size for name in result["payloads"])
        originals, attachments = [], {}
        for item in scope.evidence:
            result, origin, member = supplemental.acquire(item, payload, work, cancel, progress)
            if origin:
                if sum(entry.size for entry in attachments.values()) + member.size > MAX_ATTACHMENT_BYTES:
                    raise Invalid("Combined originals exceed the evidence ZIP limit")
                originals.append(origin)
                attachments[origin["payload"]] = member
            results.append(result)
        check_cancel(cancel)
        (payload / "coverage.txt").write_text("\n".join(
            f"{r['collector']}: {r['status']} ({r['count']}) {r['reason']}" for r in results
        ) + "\n", encoding="utf-8")
        (payload / "collection.jsonl").write_bytes(b"".join(encode(result) + b"\n" for result in results))
        recorded_plan = asdict(scope)
        recorded_plan.pop("destination")
        recorded_plan["evidence"] = [item.kind for item in scope.evidence]
        recorded_plan["files"] = [str(path) for path in scope.files]
        clock = datetime.now().astimezone()
        manifest = {"run": new_run(), "host": socket.gethostname(), "plan": recorded_plan, "attempts": results,
                    "attachments": originals,
                    "clock": {"collected_utc": now(), "local_offset": clock.strftime("%z"),
                              "local_zone": clock.tzname(), "architecture": platform.machine(),
                              "windows": platform.version()},
                    "privilege": "administrator" if is_admin() else "standard"}
        return finalize(directory, payload, manifest, cancel, attachments=attachments, progress=progress)
