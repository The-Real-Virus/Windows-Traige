"""Bounded Windows collection adapters with fixed command templates."""

import base64
import ctypes
import os
import re
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from .common import Invalid, check_cancel, decode, timestamp

MAX_OUTPUT = 8 * 1024 ** 2
CHANNEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ./_-]{0,159}\Z")
EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


class NativeError(Exception):
    def __init__(self, status, reason):
        self.status, self.reason = status, reason
        super().__init__(reason)


def system_directory():
    if os.name != "nt":
        raise NativeError("Unavailable", "Windows host required")
    buf = ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(buf, len(buf)):
        raise NativeError("Failed", "Windows system directory is unavailable")
    return Path(buf.value)


def command(parts, timeout, cancel=None, watched=None):
    system = system_directory()
    exe = system / parts[0]
    env = dict(os.environ)
    env.update(PATH=str(system), PSModulePath=str(system / "WindowsPowerShell/v1.0/Modules"),
               SystemRoot=str(system.parent), WINDIR=str(system.parent))
    with subprocess.Popen([str(exe), *parts[1:]], cwd=system, env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          creationflags=subprocess.CREATE_NO_WINDOW) as process:
        output, errors = bytearray(), bytearray()
        oversized = threading.Event()

        def read(stream, target, maximum):
            while block := stream.read1(65536):
                if len(target) + len(block) > maximum:
                    oversized.set()
                    return
                target.extend(block)

        threads = [
            threading.Thread(target=read, args=(process.stdout, output, MAX_OUTPUT), daemon=True),
            threading.Thread(target=read, args=(process.stderr, errors, 16384), daemon=True),
        ]
        for reader in threads:
            reader.start()
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                check_cancel(cancel)
                if oversized.is_set() or (watched and watched.exists() and watched.stat().st_size > MAX_OUTPUT):
                    raise NativeError("Partial", "Byte limit reached")
                if time.monotonic() >= deadline:
                    raise NativeError("Partial", "Time limit reached")
                time.sleep(0.035)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            for reader in threads:
                reader.join(timeout=2)
        if oversized.is_set() or (watched and watched.exists() and watched.stat().st_size > MAX_OUTPUT):
            raise NativeError("Partial", "Byte limit reached")
        if process.returncode:
            details = as_text(errors).lower()
            if process.returncode in (5, 0x80070005) or any(
                phrase in details for phrase in ("access is denied", "access denied", "accessdenied", "0x80070005")
            ):
                raise NativeError("Access Denied", "Windows rejected access to the selected source")
            if process.returncode == 15007 or any(
                phrase in details for phrase in ("could not be found", "channel was not found", "not a valid channel")
            ):
                raise NativeError("Unavailable", "Windows event channel is missing")
            raise NativeError("Failed", f"Windows command returned status {process.returncode}")
        return bytes(output)


def as_text(value):
    raw = bytes(value)
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        # wevtutil el can prefix a UTF-16 marker to a single-byte channel list.
        if b"\x00" in raw[2:96]:
            return raw.decode("utf-16", errors="replace")
        raw = raw[2:]
    if b"\x00" in raw[:32]:
        return raw.decode("utf-16-le", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


QUERIES = {
    "processes": "Get-CimInstance Win32_Process | Select-Object @{n='pid';e={$_.ProcessId}}, "
                 "@{n='parent_pid';e={$_.ParentProcessId}},Name,@{n='path';e={$_.ExecutablePath}},"
                 "@{n='created';e={Utc $_.CreationDate}}",
    "processes-sensitive": "Get-CimInstance Win32_Process | Select-Object @{n='pid';e={$_.ProcessId}},"
                           "@{n='parent_pid';e={$_.ParentProcessId}},Name,@{n='path';e={$_.ExecutablePath}},"
                           "@{n='created';e={Utc $_.CreationDate}},CommandLine",
    "tcp": "Get-NetTCPConnection | Select-Object @{n='pid';e={$_.OwningProcess}},"
           "@{n='ip';e={$_.LocalAddress}},@{n='port';e={$_.LocalPort}},"
           "@{n='remote_ip';e={$_.RemoteAddress}},@{n='remote_port';e={$_.RemotePort}},"
           "@{n='state';e={[string]$_.State}}",
    "udp": "Get-NetUDPEndpoint | Select-Object @{n='pid';e={$_.OwningProcess}},"
           "@{n='ip';e={$_.LocalAddress}},@{n='port';e={$_.LocalPort}}",
    "host": "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,"
            "OSArchitecture,@{n='boot';e={Utc $_.LastBootUpTime}},@{n='timezone';e={[TimeZoneInfo]::Local.Id}},"
            "@{n='utc_offset_minutes';e={[TimeZoneInfo]::Local.GetUtcOffset([DateTimeOffset]::Now).TotalMinutes}}",
    "volumes": "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | "
               "Select-Object DeviceID,FileSystem,Size,FreeSpace",
    "adapters": "Get-NetIPConfiguration | Select-Object InterfaceAlias,InterfaceIndex,"
                "@{n='IPv4';e={@($_.IPv4Address.IPAddress)}},@{n='IPv6';e={@($_.IPv6Address.IPAddress)}}",
    "routes": "Get-NetRoute | Select-Object DestinationPrefix,NextHop,InterfaceIndex,RouteMetric",
    "dns": "Get-DnsClientServerAddress | Select-Object InterfaceAlias,InterfaceIndex,ServerAddresses",
    "dns-cache": "Get-DnsClientCache | Select-Object Entry,RecordName,Data,TimeToLive",
    "neighbors": "Get-NetNeighbor | Select-Object IPAddress,LinkLayerAddress,InterfaceIndex,"
                 "@{n='state';e={[string]$_.State}}",
    "services": "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,ProcessId",
    "tasks": "Get-ScheduledTask | Select-Object TaskName,TaskPath,@{n='state';e={[string]$_.State}}",
    "startup": "Get-CimInstance Win32_StartupCommand | Select-Object Name,Location",
    "applications": "Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
                    "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' | "
                    "Where-Object DisplayName | Select-Object DisplayName,DisplayVersion,Publisher",
    "settings": "Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' | "
                "Select-Object EditionID,DisplayVersion,CurrentBuild,UBR",
    "users": "Get-LocalUser | Select-Object Name,Enabled,@{n='sid';e={[string]$_.SID}},"
             "@{n='last_logon';e={Utc $_.LastLogon}}",
    "groups": "Get-LocalGroup | Select-Object Name,@{n='sid';e={[string]$_.SID}}",
    "sessions": "Get-CimInstance Win32_LogonSession -Filter 'LogonType=2 OR LogonType=10 OR LogonType=11' | "
                "Select-Object LogonId,LogonType,@{n='start';e={Utc $_.StartTime}}",
    "hotfixes": "Get-HotFix | Select-Object HotFixID,Description,@{n='installed';e={Utc $_.InstalledOn}}",
    "firewall-profiles": "Get-NetFirewallProfile | Select-Object Name,Enabled,LogAllowed,LogBlocked,"
                         "@{n='inbound';e={[string]$_.DefaultInboundAction}},"
                         "@{n='outbound';e={[string]$_.DefaultOutboundAction}}",
}

EVENT_DATA_FIELDS = {
    "ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName", "TargetUserName",
    "TargetDomainName", "SubjectUserName", "LogonType", "IpAddress", "IpPort", "WorkstationName",
    "Status", "SubStatus", "TaskName", "Threat Name", "Action Name", "Detection Time", "Path",
}


def inventory(collector, limit, timeout, cancel):
    fixed = QUERIES[collector]
    script = ("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
              "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); "
              "function Utc($v) { if ($v) { ([datetime]$v).ToUniversalTime().ToString('o') } }; "
              f"$result=@({fixed} | Select-Object -First {int(limit) + 1}); "
              "ConvertTo-Json -InputObject $result -Depth 5 -Compress")
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    raw = command(["WindowsPowerShell/v1.0/powershell.exe", "-NoLogo", "-NoProfile",
                   "-NonInteractive", "-EncodedCommand", encoded], timeout, cancel)
    rows = decode(raw.lstrip(b"\xef\xbb\xbf"))
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise NativeError("Failed", "Windows returned an unexpected inventory schema")
    return rows


def channels(cancel=None):
    result = command(["wevtutil.exe", "el", "/uni:true"], 12, cancel)
    names = sorted({name for line in as_text(result).splitlines() if CHANNEL.fullmatch(name := line.strip())})
    if not names:
        raise NativeError("Failed", "Windows did not return readable event channel names")
    return names


def event_filter(start, end):
    start, end = timestamp(start), timestamp(end)
    return f"*[System[TimeCreated[@SystemTime >= '{start}' and @SystemTime <= '{end}']]]"


def event_fields(event, system, channel, xml):
    level = system.findtext(EVENT_NS + "Level")
    execution = system.find(EVENT_NS + "Execution")
    process = execution.get("ProcessID") if execution is not None else None
    native_id = system.findtext(EVENT_NS + "EventRecordID")
    provider = system.find(EVENT_NS + "Provider")
    fields = {
        "channel": channel, "event_id": int(system.findtext(EVENT_NS + "EventID")),
        "event_record_id": int(native_id) if native_id and native_id.isdecimal() else None,
        "severity": {"0": "LogAlways", "1": "Critical", "2": "Error", "3": "Warning",
                     "4": "Information", "5": "Verbose"}.get(level, level),
        "pid": int(process) if process and process.isdecimal() else None,
        "pid_context": "event publisher execution context",
        "provider": provider.get("Name") if provider is not None else None,
        "xml": xml,
    }
    event_data = {node.get("Name"): (node.text or "")[:1024] for node in event.findall(
        f"{EVENT_NS}EventData/{EVENT_NS}Data") if node.get("Name") in EVENT_DATA_FIELDS and node.text}
    if event_data:
        fields["event_data"] = event_data
    return fields


def event_records(raw, channel, start, end):
    root = ET.fromstring(as_text(raw).strip() or "<Events/>")
    events = [root] if root.tag == EVENT_NS + "Event" else root.findall(EVENT_NS + "Event")
    result = []
    outside = 0
    for event in events:
        system = event.find(EVENT_NS + "System")
        if system is None:
            outside += 1
            continue
        observed = timestamp(system.find(EVENT_NS + "TimeCreated").get("SystemTime"))
        if not observed or not start <= observed <= end:
            outside += 1
            continue
        fields = event_fields(event, system, channel, ET.tostring(event, encoding="unicode"))
        result.append((observed, fields))
    return result, outside


def events(channel, start, end, limit, timeout, cancel, evtx=None):
    if not CHANNEL.fullmatch(channel):
        raise Invalid("Invalid Windows event channel")
    query = event_filter(start, end)
    raw = command(["wevtutil.exe", "qe", channel, "/q:" + query, "/f:xml", "/e:Events",
                   "/rd:true", f"/c:{limit + 1}", "/uni:true"], timeout, cancel)
    try:
        rows, outside = event_records(raw, channel, start, end)
    except (ET.ParseError, ValueError, TypeError, AttributeError) as exc:
        raise NativeError("Failed", "Windows event XML could not be parsed") from exc
    reason = "Event record limit reached" if len(rows) > limit else ""
    if outside:
        reason = f"{outside} malformed or out-of-window events excluded"
    if not rows and not reason:
        try:
            config = command(["wevtutil.exe", "gl", channel, "/f:xml", "/uni:true"], min(timeout, 5), cancel)
            root = ET.fromstring(as_text(config))
            enabled = root.get("enabled")
            if str(enabled).strip().lower() == "false":
                raise NativeError("Unavailable", "The event channel is disabled and returned no records in this window")
        except ET.ParseError:
            reason = "No records returned. Windows did not provide readable channel configuration"
    if evtx and rows and not reason:
        try:
            command(["wevtutil.exe", "epl", channel, str(evtx), "/q:" + query, "/ow:false"],
                    timeout, cancel, watched=evtx)
        except NativeError as exc:
            evtx.unlink(missing_ok=True)
            reason = f"Raw EVTX export {exc.status.lower()}: {exc.reason}"
    return rows[:limit], reason
