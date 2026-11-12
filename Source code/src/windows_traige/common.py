"""Shared validation, serialization and filesystem boundaries."""

import hashlib
import json
import os
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath


class Invalid(ValueError):
    """An input failed validation."""


class Cancelled(Exception):
    """A cancellable operation was interrupted."""


def now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def timestamp(value):
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 40:
        raise Invalid("Invalid timestamp")
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError) as exc:
        raise Invalid("Use an ISO 8601 timestamp with a UTC offset") from exc


def encode(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def decode(raw):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Invalid("Duplicate JSON field")
            result[key] = value
        return result

    def invalid_constant(value):
        raise Invalid(f"Unsupported JSON constant {value}")

    try:
        return json.loads(raw, object_pairs_hook=object_pairs, parse_constant=invalid_constant)
    except (ValueError, RecursionError) as exc:
        raise Invalid("Invalid JSON") from exc


def check_cancel(cancel):
    if cancel and cancel.is_set():
        raise Cancelled("Operation cancelled")


def digest(stream, cancel=None):
    h = hashlib.sha256()
    while block := stream.read(1024 * 1024):
        check_cancel(cancel)
        h.update(block)
    return h.hexdigest()


def safe_path(path):
    """Reject UNC/device paths and all existing symlinks or reparse ancestors."""
    path = Path(os.path.abspath(path))
    if os.name == "nt" and (not path.drive or path.drive.startswith("\\") or
                            any(":" in part or part.endswith((".", " ")) or PureWindowsPath(part).is_reserved()
                                for part in path.parts[1:])):
        raise Invalid("Use an ordinary local drive path")
    for item in (*reversed(path.parents), path):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise Invalid("Reparse points are outside the allowed path")
    return path


def require_space(directory, minimum):
    if shutil.disk_usage(directory).free < minimum:
        raise Invalid("Insufficient free space at the selected destination")


def publish(stage, destination):
    """Publish a complete file atomically and reject an existing destination."""
    os.link(stage, destination)
