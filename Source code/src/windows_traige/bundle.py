"""Versioned evidence archives with bounded, streaming verification."""

import hashlib
import re
import stat
import struct
import tempfile
import zipfile
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import BinaryIO, Callable
from uuid import uuid4

from . import VERSION
from .common import Invalid, check_cancel, decode, digest, encode, now, publish, require_space, safe_path, timestamp

SCHEMA = 2
LEGACY_SCHEMA = 1
MAX_MEMBERS = 512
MAX_MEMBER = 256 * 1024 ** 2
MAX_EXPANDED = 512 * 1024 ** 2
MAX_ATTACHMENTS = 5
MAX_ATTACHMENT_BYTES = 2 * 1024 ** 4
MAX_LINE = 1024 ** 2
MAX_MANIFEST = 2 * 1024 ** 2
MAX_ARCHIVE = MAX_ATTACHMENT_BYTES + MAX_EXPANDED + 2 * MAX_MANIFEST
MAX_RATIO = 1000
EOCD = struct.Struct("<4s4H2LH")
ZIP64_EOCD = struct.Struct("<4sQ2H2L4Q")
ZIP64_LOCATOR = struct.Struct("<4sLQL")
HASH = re.compile(r"[0-9a-f]{64}\Z")
TOKEN = re.compile(r"[a-zA-Z0-9_-]{1,96}\Z")
MEMBER = re.compile(r"[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*\.[a-zA-Z0-9]{1,8}\Z")
ATTACHMENT_TYPES = {
    "disk-image": {"dd", "img", "raw"},
    "memory-capture": {"raw", "mem"},
    "endpoint-telemetry": {"csv"},
    "identity-activity": {"json"},
    "network-evidence": {"pcap", "pcapng"},
}
KINDS = {"event", "process", "network", "host", "inventory", "account", "file"}
STATES = {"Collected", "Partial", "Access Denied", "Unavailable", "Failed", "Cancelled"}


@dataclass(frozen=True)
class Payload:
    size: int
    open_source: Callable[[], BinaryIO]
    expected: str | None = None


def record(identifier, kind, source, acquired, observed=None, **fields):
    return dict(id=identifier, kind=kind, source=source, acquired=timestamp(acquired),
                observed=timestamp(observed), fields=fields)


def records(stream, payloads, cancel=None):
    while line := stream.readline(MAX_LINE + 1):
        check_cancel(cancel)
        if len(line) > MAX_LINE or not line.endswith(b"\n"):
            raise Invalid("Invalid JSON Lines record length or missing delimiter")
        row = decode(line)
        if (not isinstance(row, dict) or not isinstance(row.get("id"), str) or
                not TOKEN.fullmatch(row["id"]) or row.get("kind") not in KINDS or
                not isinstance(row.get("source"), str) or row["source"] not in payloads or
                not isinstance(row.get("fields"), dict) or not row.get("acquired")):
            raise Invalid("Invalid normalized evidence record")
        row["acquired"] = timestamp(row["acquired"])
        row["observed"] = timestamp(row.get("observed"))
        yield row


def inspect_members(z):
    infos = z.infolist()
    if not 1 <= len(infos) <= MAX_MEMBERS:
        raise Invalid("Unsupported ZIP member count")
    total = large = 0
    seen = set()
    files = {}
    for info in infos:
        name = info.orig_filename
        lowered = name.lower()
        if (len(name) > 170 or not MEMBER.fullmatch(name) or lowered in seen or
                any(part.split(".")[0].lower() in {
                    "con", "prn", "aux", "nul", *(f"com{i}" for i in range(10)),
                    *(f"lpt{i}" for i in range(10))
                } for part in name.split("/")) or
                stat.S_IFMT(info.external_attr >> 16) not in {0, stat.S_IFREG} or
                info.flag_bits & 1 or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}):
            raise Invalid("Unsafe or unsupported ZIP member")
        if name.startswith("attachments/"):
            large += info.file_size
            if (large > MAX_ATTACHMENT_BYTES or info.compress_type != zipfile.ZIP_STORED or
                    info.file_size != info.compress_size):
                raise Invalid("ZIP exceeds attachment limits or contains compressed attachments")
        else:
            total += info.file_size
            if (info.file_size > MAX_MEMBER or total > MAX_EXPANDED or
                    info.file_size > MAX_RATIO * max(info.compress_size, 1)):
                raise Invalid("ZIP exceeds expansion limits")
        seen.add(lowered)
        files[name] = info
    if any(parent in seen for name in seen for parent in
           ("/".join(name.split("/")[:i]) for i in range(1, name.count("/") + 1))):
        raise Invalid("Conflicting ZIP member paths")
    if "manifest.json" not in files or files["manifest.json"].file_size > MAX_MANIFEST:
        raise Invalid("Missing or oversized root manifest")
    return files


def inspect_directory(stream, size):
    """Bound the ZIP directory before ZipFile allocates memory for it."""
    tail_size = min(size, EOCD.size + 65535)
    stream.seek(size - tail_size)
    tail = stream.read(tail_size)
    offset = tail.rfind(b"PK\x05\x06")
    if offset < 0 or len(tail) - offset < EOCD.size:
        raise Invalid("Invalid ZIP archive")
    _, disk, first_disk, local_count, count, directory_size, directory_start, comment = EOCD.unpack_from(tail, offset)
    end = size - tail_size + offset
    if offset + EOCD.size + comment != len(tail) or disk or first_disk or local_count != count:
        raise Invalid("Invalid or unsupported ZIP directory")
    if end >= ZIP64_EOCD.size + ZIP64_LOCATOR.size:
        locator_start = end - ZIP64_LOCATOR.size
        stream.seek(locator_start)
        locator = stream.read(ZIP64_LOCATOR.size)
        if locator.startswith(b"PK\x06\x07"):
            _, zip64_disk, start, disks = ZIP64_LOCATOR.unpack(locator)
            if zip64_disk or disks != 1 or start + ZIP64_EOCD.size != locator_start:
                raise Invalid("Invalid or unsupported ZIP64 directory")
            stream.seek(start)
            signature, length, _, _, disk, first_disk, local64, count64, size64, offset64 = \
                ZIP64_EOCD.unpack(stream.read(ZIP64_EOCD.size))
            if (signature != b"PK\x06\x06" or length != 44 or disk or first_disk or local64 != count64 or
                    count != min(count64, 0xffff) or directory_size != min(size64, 0xffffffff) or
                    directory_start != min(offset64, 0xffffffff)):
                raise Invalid("Invalid or unsupported ZIP64 directory")
            count, directory_size, directory_start, end = count64, size64, offset64, start
    if (not 1 <= count <= MAX_MEMBERS or
            directory_size > 2 * MAX_MANIFEST or directory_start + directory_size != end or
            directory_start < 1):
        raise Invalid("Invalid or unsupported ZIP directory")


def inspect_attachments(manifest, files):
    paths = {name for name in files if name.startswith("attachments/")}
    if manifest["schema"] == LEGACY_SCHEMA:
        if paths or manifest.get("attachments", []) != []:
            raise Invalid("Legacy bundles do not support attachments")
        return
    entries = manifest.get("attachments", [])
    if not isinstance(entries, list) or len(entries) > MAX_ATTACHMENTS:
        raise Invalid("Invalid attachment list")
    seen = set()
    for item in entries:
        if not isinstance(item, dict):
            raise Invalid("Invalid attachment metadata")
        kind, path = item.get("kind"), item.get("payload")
        if (not isinstance(kind, str) or kind not in ATTACHMENT_TYPES or not isinstance(path, str) or
                path not in paths or kind in seen or not any(
                    path == f"attachments/{kind}.{extension}" for extension in ATTACHMENT_TYPES[kind]) or
                files[path].file_size <= 0 or item.get("external") not in ("matched", "not supplied")):
            raise Invalid("Invalid attachment metadata")
        for key in ("filename", "source", "tool", "operator", "notes"):
            if key in item and (not isinstance(item[key], str) or len(item[key]) > 500 or
                                any(ord(ch) < 32 for ch in item[key])):
                raise Invalid("Invalid attachment provenance")
        for key in ("captured", "start", "end", "received_utc"):
            timestamp(item.get(key))
        seen.add(kind)
    if paths != {item["payload"] for item in entries}:
        raise Invalid("Attachment members do not match the manifest")


def inspect_manifest(z, files):
    manifest = decode(z.read("manifest.json"))
    if (not isinstance(manifest, dict) or type(manifest.get("schema")) is not int or
            manifest["schema"] not in {LEGACY_SCHEMA, SCHEMA}):
        raise Invalid("Unsupported evidence schema")
    for field in ("run", "host", "app_version"):
        if not isinstance(manifest.get(field), str) or not 1 <= len(manifest[field]) <= 255:
            raise Invalid(f"Invalid manifest {field}")
    attempts = manifest.get("attempts")
    if (not isinstance(manifest.get("plan"), dict) or not isinstance(attempts, list) or not attempts or
            any(not isinstance(item, dict) or item.get("status") not in STATES or
                not isinstance(item.get("collector"), str) for item in attempts) or not manifest.get("created")):
        raise Invalid("Invalid collection coverage")
    timestamp(manifest["created"])
    payloads = manifest.get("payloads")
    if not isinstance(payloads, dict) or set(payloads) != files.keys() - {"manifest.json"}:
        raise Invalid("Archive members do not match manifest")
    for name, expected in payloads.items():
        if (not isinstance(expected, dict) or type(expected.get("bytes")) is not int or
                files[name].file_size != expected["bytes"] or
                not isinstance(expected.get("sha256"), str) or not HASH.fullmatch(expected["sha256"])):
            raise Invalid("Invalid payload length or digest")
    inspect_attachments(manifest, files)
    return manifest


def external_hash(checksum):
    if checksum is None:
        return None
    path = safe_path(checksum)
    with path.open("rb") as stream:
        value = stream.read(1025)
    try:
        parts = value.decode("ascii").strip().split(maxsplit=1)
    except UnicodeDecodeError as exc:
        raise Invalid("Invalid detached SHA-256") from exc
    if len(value) > 1024 or not parts or not HASH.fullmatch(parts[0].lower()):
        raise Invalid("Invalid detached SHA-256")
    return parts[0].lower()


def verify_open(stream, expected=None, cancel=None, *, validate_records=True):
    size = stream.seek(0, 2)
    if size > MAX_ARCHIVE:
        raise Invalid("Archive exceeds file size limit")
    inspect_directory(stream, size)
    stream.seek(0)
    actual = digest(stream, cancel)
    if expected and actual != expected:
        raise Invalid("External SHA-256 mismatch")
    stream.seek(0)
    try:
        with zipfile.ZipFile(stream) as z:
            files = inspect_members(z)
            manifest = inspect_manifest(z, files)
            for name, info in manifest["payloads"].items():
                check_cancel(cancel)
                with z.open(name) as member:
                    if digest(member, cancel) != info["sha256"]:
                        raise Invalid(f"Payload digest mismatch for {name}")
                if validate_records and name.startswith("normalized/") and name.endswith(".jsonl"):
                    with z.open(name) as member:
                        for _ in records(member, manifest["payloads"], cancel):
                            pass
    except (zipfile.BadZipFile, NotImplementedError, UnicodeError) as exc:
        raise Invalid("Invalid ZIP archive") from exc
    return {"sha256": actual, "internal": "verified", "external": "matched" if expected else "not supplied",
            "verified_at": now(), "manifest": manifest,
            "interpretation": "Authenticity requires a digest from a trusted channel. Source accuracy is unverified."}


def verify(path, checksum=None, cancel=None):
    with safe_path(path).open("rb") as stream:
        return verify_open(stream, external_hash(checksum), cancel)


def finalize(directory, payload_root, manifest, cancel=None, *, attachments=None, progress=None):
    directory = safe_path(directory)
    run = manifest["run"]
    if not TOKEN.fullmatch(run):
        raise Invalid("Invalid run identity")
    manifest = dict(manifest, schema=SCHEMA, app_version=VERSION, created=now(), payloads={})
    paths = sorted(safe_path(path) for path in payload_root.rglob("*") if path.is_file())
    members = {path.relative_to(payload_root).as_posix(): Payload(path.stat().st_size, partial(path.open, "rb"))
               for path in paths}
    total = sum(entry.size for entry in members.values())
    extras = attachments or {}
    extra_size = sum(entry.size for entry in extras.values())
    if (total > MAX_EXPANDED or extra_size > MAX_ATTACHMENT_BYTES or len(members) + len(extras) >= MAX_MEMBERS or
            any(name in members or not name.startswith("attachments/") or not MEMBER.fullmatch(name)
                for name in extras)):
        raise Invalid("Evidence exceeds archive bounds")
    members.update(extras)
    require_space(directory, total + extra_size + 8 * 1024 ** 2)
    archive = directory / f"WindowsTraige-{VERSION}-{run}.zip"
    sidecar = archive.with_suffix(".sha256")
    with tempfile.TemporaryDirectory(prefix=".incomplete-", dir=directory) as temp:
        stage = Path(temp) / "archive.zip"
        with zipfile.ZipFile(stage, "x", compression=zipfile.ZIP_STORED) as z:
            for name, entry in members.items():
                check_cancel(cancel)
                info = zipfile.ZipInfo(name)
                info.file_size = entry.size
                with entry.open_source() as stream, z.open(info, "w") as out:
                    h = hashlib.sha256()
                    size = 0
                    while block := stream.read(1024 * 1024):
                        check_cancel(cancel)
                        size += len(block)
                        if size > entry.size:
                            raise Invalid(f"Evidence size changed while packaging {name}")
                        h.update(block)
                        out.write(block)
                        if progress and name in extras and (size % (64 * 1024 ** 2) == 0 or size == entry.size):
                            progress(f"Packing {name.rsplit('/', 1)[-1]}", size)
                actual = h.hexdigest()
                if size != entry.size or (entry.expected and actual != entry.expected):
                    raise Invalid(f"Evidence changed while packaging {name}")
                manifest["payloads"][name] = {"bytes": size, "sha256": actual}
            z.writestr("manifest.json", encode(manifest))
        result = verify(stage, cancel=cancel)
        side_stage = Path(temp) / "archive.sha256"
        side_stage.write_text(f"{result['sha256']}  {archive.name}\n", encoding="ascii")
        check_cancel(cancel)
        publish(side_stage, sidecar)
        try:
            publish(stage, archive)
        except BaseException:
            sidecar.unlink()
            raise
    return {"archive": str(archive), "checksum": str(sidecar), **result}


def new_run():
    return uuid4().hex
