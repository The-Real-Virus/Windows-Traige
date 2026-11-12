"""Preserve and index archived Windows event logs without using live channels."""

import ctypes
import hashlib
import os
import tempfile
import time
import xml.etree.ElementTree as ET
from ctypes import wintypes
from pathlib import Path

from . import bundle, native
from .common import Invalid, check_cancel, encode, now, require_space, safe_path, timestamp

ORIGINAL = "raw/archived.evtx"
NORMALIZED = "normalized/archived.jsonl"
COLLECTOR = "archived-evtx"
MAX_FILE = 128 * 1024 ** 2
MAX_RECORDS = 100_000
READ_TIMEOUT = 120
EVT_QUERY_FILE_PATH = 0x2
EVT_QUERY_FORWARD_DIRECTION = 0x100
EVT_RENDER_EVENT_XML = 1
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NO_MORE_ITEMS = 259


def windows_api():
    if os.name != "nt":
        raise Invalid("Import archived Windows event logs on Windows")
    api = ctypes.WinDLL("wevtapi", use_last_error=True)
    handle, dword, pointer = wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p
    dword_ptr = ctypes.POINTER(dword)
    api.EvtQuery.argtypes = (handle, wintypes.LPCWSTR, wintypes.LPCWSTR, dword)
    api.EvtQuery.restype = handle
    api.EvtNext.argtypes = (handle, dword, ctypes.POINTER(handle), dword, dword, dword_ptr)
    api.EvtNext.restype = wintypes.BOOL
    api.EvtRender.argtypes = (handle, handle, dword, dword, pointer, dword_ptr, dword_ptr)
    api.EvtRender.restype = wintypes.BOOL
    api.EvtClose.argtypes = (handle,)
    api.EvtClose.restype = wintypes.BOOL
    return api


def render(api, handle):
    used, properties = wintypes.DWORD(), wintypes.DWORD()
    args = (ctypes.byref(used), ctypes.byref(properties))
    if api.EvtRender(None, handle, EVT_RENDER_EVENT_XML, 0, None, *args):
        raise Invalid("Windows returned an empty archived event")
    error = ctypes.get_last_error()
    if error != ERROR_INSUFFICIENT_BUFFER:
        raise Invalid(f"Windows could not render an archived event (error {error})")
    width = ctypes.sizeof(ctypes.c_wchar)
    if used.value < width or used.value > bundle.MAX_LINE or used.value % width:
        raise Invalid("An archived event exceeds the supported XML size or is malformed")
    buffer = ctypes.create_unicode_buffer(used.value // width)
    if not api.EvtRender(None, handle, EVT_RENDER_EVENT_XML, used.value, buffer, *args):
        raise Invalid(f"Windows could not render an archived event (error {ctypes.get_last_error()})")
    return buffer.value


def event_xml(path, cancel):
    api = windows_api()
    query = api.EvtQuery(None, str(path), "*", EVT_QUERY_FILE_PATH | EVT_QUERY_FORWARD_DIRECTION)
    if not query:
        raise Invalid(f"Windows could not open this EVTX (error {ctypes.get_last_error()})")
    deadline = time.monotonic() + READ_TIMEOUT
    handles = (wintypes.HANDLE * 32)()
    returned = wintypes.DWORD()
    try:
        while True:
            check_cancel(cancel)
            if time.monotonic() >= deadline:
                raise Invalid("EVTX reading exceeded the time limit. Export a smaller log.")
            if not api.EvtNext(query, len(handles), handles, 1000, 0, ctypes.byref(returned)):
                error = ctypes.get_last_error()
                if error == ERROR_NO_MORE_ITEMS:
                    break
                raise Invalid(f"Windows could not read this EVTX (error {error})")
            try:
                for index in range(returned.value):
                    check_cancel(cancel)
                    yield render(api, handles[index])
            finally:
                for index in range(returned.value):
                    api.EvtClose(handles[index])
    finally:
        api.EvtClose(query)


def stage_original(source, original, size, expected, cancel):
    h = hashlib.sha256()
    copied = 0
    with source.open("rb") as incoming, original.open("xb") as target:
        opened = os.fstat(incoming.fileno())
        while block := incoming.read(1024 ** 2):
            check_cancel(cancel)
            if copied == 0 and not block.startswith(b"ElfFile\0"):
                raise Invalid("This file does not have a Windows EVTX header")
            copied += len(block)
            if copied > size:
                raise Invalid("EVTX file changed while it was being copied")
            h.update(block)
            target.write(block)
        finished = os.fstat(incoming.fileno())
    if copied != size or opened.st_mtime_ns != finished.st_mtime_ns:
        raise Invalid("EVTX file changed while it was being copied")
    actual = h.hexdigest()
    if expected and actual != expected:
        raise Invalid("Detached SHA-256 does not match the original EVTX")
    return actual


def index(original, target, acquired, cancel, progress):
    channels, computers = set(), set()
    start = end = None
    count = total = 0
    stream = event_xml(original, cancel)
    try:
        with target.open("xb") as out:
            for count, xml in enumerate(stream, 1):
                if count > MAX_RECORDS:
                    raise Invalid("EVTX exceeds 100,000 events. Export a smaller log.")
                try:
                    event = ET.fromstring(xml)
                    system = event.find(native.EVENT_NS + "System")
                    channel = system.findtext(native.EVENT_NS + "Channel")
                    computer = system.findtext(native.EVENT_NS + "Computer")
                    time_node = system.find(native.EVENT_NS + "TimeCreated")
                    observed = timestamp(time_node.get("SystemTime")) if time_node is not None else None
                    fields = native.event_fields(event, system, channel, xml)
                except (ET.ParseError, ValueError, TypeError, AttributeError) as exc:
                    raise Invalid(f"Archived event {count} has unreadable system fields") from exc
                if channel:
                    channels.add(channel)
                if computer:
                    computers.add(computer)
                if observed:
                    start = min(start, observed) if start else observed
                    end = max(end, observed) if end else observed
                row = bundle.record(f"archived-{count}", "event", ORIGINAL, acquired, observed,
                                    source_computer=computer, **fields)
                line = encode(row) + b"\n"
                total += len(line)
                if len(line) > bundle.MAX_LINE or total > MAX_FILE:
                    raise Invalid("Archived event data exceeds the import size limit. Export a smaller log.")
                out.write(line)
                if progress and count % 512 == 0:
                    progress("Reading archived Windows events", count)
    finally:
        stream.close()
    return {"count": count, "channels": sorted(channels), "computers": sorted(computers),
            "start": start, "end": end}


def import_file(folder, path, checksum=None, cancel=None, progress=None):
    from .case import import_bundle

    folder, path = safe_path(folder), safe_path(path)
    if not path.is_file():
        raise Invalid("Select a saved local EVTX file")
    if folder.exists() and not folder.is_dir():
        raise Invalid("Choose a folder for the case")
    size = path.stat().st_size
    if not 4096 <= size <= MAX_FILE:
        raise Invalid("Use an EVTX between 4 KiB and 128 MiB. Export a smaller log if needed.")
    expected = bundle.external_hash(checksum)
    parent = folder if folder.is_dir() else folder.parent
    require_space(parent, size * 3 + 16 * 1024 ** 2)
    acquired = now()
    with tempfile.TemporaryDirectory(prefix=".incomplete-evtx-", dir=parent) as tmp:
        stage = Path(tmp)
        payload = stage / "payload"
        original, normalized = payload / ORIGINAL, payload / NORMALIZED
        original.parent.mkdir(parents=True)
        normalized.parent.mkdir()
        sha256 = stage_original(path, original, size, expected, cancel)
        details = index(original, normalized, acquired, cancel, progress)
        count = details["count"]
        source = dict(details, kind="evtx", filename=path.name, sha256=sha256, bytes=size,
                      external="matched" if expected else "not supplied")
        reason = "Imported saved EVTX" if count else "The saved EVTX contains no readable events"
        computers = details["computers"]
        host = computers[0][:255] if len(computers) == 1 else "Multiple computers" if computers else "Unknown computer"
        manifest = {
            "run": bundle.new_run(), "host": host, "plan": {"profile": COLLECTOR}, "source_evidence": source,
            "attempts": [{"collector": COLLECTOR, "status": "Collected", "reason": reason, "count": count,
                          "started": acquired, "finished": now(), "payloads": [ORIGINAL, NORMALIZED]}],
        }
        result = bundle.finalize(stage, payload, manifest, cancel)
        imported = import_bundle(folder, result["archive"], cancel=cancel, progress=progress,
                                 evtx_source=(sha256, source["external"]))
        return dict(imported, source_evidence=source)
