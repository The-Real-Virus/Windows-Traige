"""A read-only elevated Windows event worker over a local named pipe."""

import ctypes
import hmac
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from ctypes import wintypes
from datetime import datetime, timedelta
from functools import partial
from multiprocessing.connection import Client, Listener
from pathlib import Path
from queue import Empty, Queue

from . import collect, native
from .bundle import MAX_LINE, Payload, finalize, new_run, record, verify_open
from .common import Invalid, check_cancel, decode, encode, now, require_space, safe_path, timestamp

PIPE_PREFIX = r"\\.\pipe\WindowsTraige-"
PROTOCOL = re.compile(r"[0-9a-f]{32}\Z")
MAX_REPLY = 10 * 1024 ** 2


class ShellInfo(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD), ("hIcon", wintypes.HANDLE), ("hProcess", wintypes.HANDLE),
    ]


def peer(connection, fn):
    api = getattr(ctypes.WinDLL("kernel32", use_last_error=True), fn)
    api.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG))
    api.restype = wintypes.BOOL
    pid = wintypes.ULONG()
    if not api(connection.fileno(), ctypes.byref(pid)):
        raise OSError("Local IPC peer could not be authenticated")
    return pid.value


def receive(connection, timeout, maximum, cancel=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        check_cancel(cancel)
        if connection.poll(0.1):
            return decode(connection.recv_bytes(maximum))
    raise OSError("Local IPC response timed out")


def parse_request(request):
    if not isinstance(request, dict) or set(request) != {"run", "collectors", "start", "end", "limit"}:
        raise Invalid("Invalid elevated request")
    run, ids, limit = request["run"], request["collectors"], request["limit"]
    if (not isinstance(run, str) or not PROTOCOL.fullmatch(run) or not isinstance(ids, list) or
            not 0 < len(ids) <= len(collect.EVENT_CHANNELS) or
            any(not isinstance(key, str) or key not in collect.EVENT_CHANNELS for key in ids) or
            len(set(ids)) != len(ids) or type(limit) is not int or not 1 <= limit <= collect.MAX_ROWS):
        raise Invalid("Elevated request outside the collector catalog")
    start, end = timestamp(request["start"]), timestamp(request["end"])
    if not start or not end or not timedelta(0) < datetime.fromisoformat(end) - datetime.fromisoformat(start) <= timedelta(days=7):
        raise Invalid("Invalid elevated event window")
    return ids, start, end, limit


def worker_main(argv):
    """The elevated entry point accepts no paths, raw commands or write operations."""
    if len(argv) != 3 or not all(PROTOCOL.fullmatch(item) for item in argv[:2]) or not argv[2].isdecimal():
        return 3
    if not collect.is_admin():
        return 4
    pipe, nonce, owner = argv
    try:
        with Client(PIPE_PREFIX + pipe, family="AF_PIPE") as connection:
            if peer(connection, "GetNamedPipeServerProcessId") != int(owner):
                return 4
            connection.send_bytes(encode({"nonce": nonce}))
            request = receive(connection, 8, 8192)
            ids, start, end, limit = parse_request(request)
            for key in ids:
                channel, started = collect.EVENT_CHANNELS[key], now()
                result = {"collector": key, "channel": channel, "started": started,
                          "privilege": "administrator", "count": 0, "selected_sources": [], "payloads": []}
                rows = []
                try:
                    rows, reason = native.events(channel, start, end, limit, collect.TIMEOUT, None)
                    if rows:
                        raw_gap = "Elevated retry saved normalized events. Raw EVTX is unavailable in this retry."
                        reason = f"{reason}. {raw_gap}" if reason else raw_gap
                    result.update(status="Partial" if reason else "Collected",
                                  reason=reason or "No events in the requested window")
                except native.NativeError as exc:
                    result.update(status=exc.status, reason=exc.reason)
                result["finished"] = now()
                message = encode({"run": request["run"], "attempt": result, "rows": rows})
                if len(message) > MAX_REPLY:
                    result.update(status="Partial", reason="Elevated response exceeded the transfer limit")
                    message = encode({"run": request["run"], "attempt": result, "rows": []})
                connection.send_bytes(message)
        return 0
    except (OSError, EOFError, Invalid):
        return 4


def launch(parameters):
    executable = Path(sys.executable)
    if getattr(sys, "frozen", False):
        executable = executable.with_name("WindowsTraige.exe")
        args = parameters
    else:
        raise Invalid("Run the packaged executables for UAC retry")
    executable = safe_path(executable)
    if not executable.is_file():
        raise Invalid("The adjacent packaged WindowsTraige.exe is required for UAC retry")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    ole = ctypes.WinDLL("ole32")
    info = ShellInfo()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x00000040 | 0x00000100 | 0x00000400
    info.lpVerb = "runas"
    info.lpFile = str(executable)
    info.lpParameters = subprocess.list2cmdline(args)
    info.lpDirectory = str(native.system_directory())
    info.nShow = 0
    shell.ShellExecuteExW.argtypes = [ctypes.POINTER(ShellInfo)]
    shell.ShellExecuteExW.restype = wintypes.BOOL
    initialized = ole.CoInitializeEx(None, 2 | 4)
    try:
        if not shell.ShellExecuteExW(ctypes.byref(info)):
            code = ctypes.get_last_error()
            return None, "UAC declined" if code == 1223 else f"UAC launch failed (Windows status {code})"
    finally:
        if initialized in (0, 1):
            ole.CoUninitialize()
    if not info.hProcess:
        return None, "Windows did not supply an authenticated worker handle"
    return info.hProcess, ""


def exchange(request, cancel, progress):
    pipe, nonce = secrets.token_hex(16), secrets.token_hex(16)
    handoff = Queue(maxsize=1)
    abandoned = threading.Event()
    listener = Listener(PIPE_PREFIX + pipe, family="AF_PIPE")

    def accept():
        try:
            connection = listener.accept()
            if abandoned.is_set():
                connection.close()
            else:
                handoff.put_nowait(connection)
        except OSError:
            return

    worker = None
    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        if progress:
            progress("Waiting for Windows UAC consent", 0)
        worker, error = launch(["--elevated-event-worker", pipe, nonce, str(os.getpid())])
        if error:
            return [], error
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetProcessId.argtypes = (wintypes.HANDLE,)
        kernel.GetProcessId.restype = wintypes.DWORD
        pid = kernel.GetProcessId(worker)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            check_cancel(cancel)
            try:
                connection = handoff.get(timeout=0.1)
                break
            except Empty:
                continue
        else:
            return [], "Elevated worker did not connect"
        with connection:
            if not pid or peer(connection, "GetNamedPipeClientProcessId") != pid:
                return [], "Elevated worker identity could not be verified"
            hello = receive(connection, 5, 1024, cancel)
            if not isinstance(hello, dict) or not isinstance(hello.get("nonce"), str) or not hmac.compare_digest(hello["nonce"], nonce):
                return [], "Elevated worker session could not be verified"
            connection.send_bytes(encode(request))
            messages = []
            for key in request["collectors"]:
                if progress:
                    progress(f"Retrying {key}", len(messages))
                message = receive(connection, collect.TIMEOUT + 12, MAX_REPLY, cancel)
                if message["run"] != request["run"] or message["attempt"]["collector"] != key:
                    raise Invalid("Unexpected elevated response")
                messages.append(message)
            return messages, ""
    except (EOFError, OSError):
        return [], "Elevated worker connection failed or timed out"
    finally:
        abandoned.set()
        try:
            handoff.get_nowait().close()
        except Empty:
            pass
        listener.close()
        if worker:
            close = ctypes.WinDLL("kernel32").CloseHandle
            close.argtypes = (wintypes.HANDLE,)
            close(worker)


def retry(prior, out, cancel=None, progress=None):
    out = safe_path(out)
    if not out.is_dir():
        raise Invalid("Choose an existing retry output directory")
    with safe_path(prior).open("rb") as original:
        verified = verify_open(original, cancel=cancel)
        manifest = verified["manifest"]
        import socket
        if manifest["host"] != socket.gethostname():
            raise Invalid("Retry only a collection from this host")
        final = {item["collector"]: item for item in manifest["attempts"]}
        eligible = [key for key, item in final.items() if key in collect.EVENT_CHANNELS and
                    item["status"] == "Access Denied" and not item.get("payloads")]
        if not eligible:
            raise Invalid("No denied native event collectors are eligible for administrator retry")
        run = new_run()
        request = {"run": run, "collectors": eligible, "start": manifest["plan"].get("start"),
                   "end": manifest["plan"].get("end"), "limit": manifest["plan"].get("max_rows")}
        parse_request(request)
        attachments_size = sum(entry["bytes"] for name, entry in manifest["payloads"].items()
                               if name.startswith("attachments/"))
        total_size = sum(entry["bytes"] for entry in manifest["payloads"].values())
        require_space(out, 2 * total_size - attachments_size + 64 * 1024 ** 2)
        messages, error = exchange(request, cancel, progress)
        check_cancel(cancel)
        with tempfile.TemporaryDirectory(prefix=".incomplete-retry-", dir=out) as folder, zipfile.ZipFile(original) as z:
            root = Path(folder)
            attachments = {}
            for name, info in manifest["payloads"].items():
                check_cancel(cancel)
                if name in {"coverage.txt", "collection.jsonl"}:
                    continue
                if name.startswith("attachments/"):
                    attachments[name] = Payload(info["bytes"], partial(z.open, name), info["sha256"])
                    continue
                target = safe_path(root / name)
                target.parent.mkdir(exist_ok=True, parents=True)
                with z.open(name) as source, target.open("xb") as target_stream:
                    while block := source.read(1024 ** 2):
                        check_cancel(cancel)
                        target_stream.write(block)
            attempts = list(manifest["attempts"])
            if error:
                for key in eligible:
                    attempts.append(dict(final[key], reason=error, privilege="standard", finished=now()))
            for message in messages:
                attempt = message["attempt"]
                key = attempt["collector"]
                name = f"normalized/{key}-{run[:12]}.jsonl"
                if message["rows"]:
                    (root / "normalized").mkdir(exist_ok=True)
                    with (root / name).open("xb") as stream:
                        for index, (observed, fields) in enumerate(message["rows"]):
                            check_cancel(cancel)
                            row = record(f"{key}-{run[:12]}-{index}", "event", name,
                                         attempt["started"], observed, **fields)
                            line = encode(row) + b"\n"
                            if len(line) > MAX_LINE:
                                attempt.update(status="Partial", reason="Oversized event was skipped")
                                continue
                            stream.write(line)
                            attempt["count"] += 1
                    attempt["payloads"] = [name]
                attempts.append(attempt)
            (root / "coverage.txt").write_text("\n".join(
                f"{item['collector']}: {item['status']} {item['reason']}" for item in attempts
            ) + "\n", encoding="utf-8")
            (root / "collection.jsonl").write_bytes(b"".join(encode(item) + b"\n" for item in attempts))
            next_manifest = dict(manifest, run=run, attempts=attempts, prior_archive=verified["sha256"])
            return finalize(out, root, next_manifest, cancel, attachments=attachments, progress=progress)
