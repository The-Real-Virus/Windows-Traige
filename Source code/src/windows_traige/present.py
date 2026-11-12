"""Plain-language evidence views with the original data available separately."""

import json
import re
from collections import Counter
from pathlib import Path

from .supplemental import LABELS as SUPPLEMENTAL_LABELS

SOURCES = {
    **SUPPLEMENTAL_LABELS,
    "archived-evtx": "Saved Windows event log (EVTX)",
    "processes": "Running processes", "processes-sensitive": "Running processes and command lines",
    "tcp": "TCP connections", "udp": "UDP endpoints", "host": "Windows host information",
    "adapters": "Network adapters", "volumes": "Local volumes", "routes": "Network routes",
    "dns": "DNS configuration", "dns-cache": "DNS cache", "neighbors": "Network neighbors",
    "events-security": "Windows Security log", "events-system": "Windows System log",
    "events-application": "Windows Application log", "events-defender": "Microsoft Defender",
    "events-powershell": "PowerShell activity", "events-sysmon": "Sysmon",
    "events-tasks": "Scheduled task activity", "events-wmi": "WMI activity",
    "events-rdp": "Remote Desktop sessions", "events-code-integrity": "Code Integrity",
    "events-firewall": "Windows Firewall activity", "events-dns-client": "DNS client activity",
    "events-winrm": "Windows Remote Management", "events-applocker": "AppLocker executable rules",
    "hotfixes": "Installed Windows updates", "firewall-profiles": "Firewall profile settings",
    "files": "Selected files", "fixture": "Synthetic evidence",
}
LABELS = {
    "recorded_source": "Recorded source",
    "id": "Record ID", "event_id": "Event ID", "event_record_id": "Windows event record number",
    "observed": "Observed time (UTC)", "acquired": "Collected time (UTC)", "host": "Source computer",
    "archive": "Archive SHA-256", "sha256": "SHA-256", "run": "Collection run ID",
    "ip": "Local IP address", "remote_ip": "Remote IP address", "pid": "Process ID",
    "parent_pid": "Parent process ID", "created": "Creation time", "path": "File or executable path",
    "kind": "Record type", "source": "Source file", "xml": "Original Windows event XML",
    "external": "Detached SHA-256", "internal": "Member integrity",
}
EVENTS = {
    ("system", 7045): ("A service was installed", "Check the service name, executable and change records."),
    ("system", 104): ("An event log may have been cleared", "Preserve independent copies and check authorized maintenance."),
    ("security", 1102): ("The Security audit log was cleared", "Check the account and time, then preserve independent audit copies."),
    ("security", 4625): ("A logon attempt failed", "Review the account, logon type, source address and any nearby successful logon."),
    ("security", 4698): ("A scheduled task was created", "Check its author, action, trigger and approved change records."),
    ("security", 4720): ("A user account was created", "Confirm the account owner, creator and authorized provisioning."),
    ("microsoft-windows-windows defender/operational", 1116): (
        "Microsoft Defender recorded a detection", "Review the detected item, path and the associated remediation result."),
    ("microsoft-windows-windows defender/operational", 1117): (
        "Microsoft Defender recorded a remediation action", "Check the action result and whether related activity continued."),
    ("microsoft-windows-windows defender/operational", 5007): (
        "Microsoft Defender settings changed", "Check the setting and whether the change was authorized."),
}


def label(key):
    return LABELS.get(key, re.sub(r"(?<=[a-z])(?=[A-Z])", " ", str(key)).replace("_", " ").capitalize())


def source_label(key, channel=None):
    return SOURCES.get(key, channel or label(key))


def event_description(fields):
    channel = fields.get("channel")
    event = fields.get("event_id")
    if not isinstance(channel, str) or type(event) is not int:
        return None
    return EVENTS.get((channel.casefold(), event))


def plain(value, depth=0):
    if value is None:
        return "Not recorded"
    if value is True or value is False:
        return "Yes" if value else "No"
    if isinstance(value, list):
        if not value:
            return "None"
        return "\n\n".join(plain(item, depth + 1) for item in value)
    if isinstance(value, dict):
        lines = []
        for key, item in value.items():
            if key in {"ordinal", "xml"}:
                continue
            rendered = plain(item, depth + 1)
            if isinstance(item, (dict, list)):
                lines.append(f"{label(key)}\n" + "\n".join("  " + line for line in rendered.splitlines()))
            else:
                lines.append(f"{label(key)}: {rendered}")
        return "\n".join(lines) or "None"
    return str(value)


def record_text(row, links):
    fields = row["fields"]
    description = event_description(fields) if row["kind"] == "event" else None
    evidence_kind = fields.get("evidence_kind")
    title = (description[0] if description else source_label(evidence_kind)
             if isinstance(evidence_kind, str) and evidence_kind in SUPPLEMENTAL_LABELS else f"{label(row['kind'])} record")
    host_key = "recorded_source" if row["source"].startswith("attachments/") else "host"
    values = {host_key: row["host"], **{key: row.get(key) for key in ("observed", "acquired", "id", "source", "archive")}}
    sections = [title, plain(values), "Recorded details\n" + plain(fields)]
    if description:
        sections.append("What to review\n" + description[1])
    if fields.get("xml"):
        sections.append("Open Raw JSON for the original event XML.")
    if links["status"] != "unavailable":
        details = [links["status"].capitalize() + " process match. Review the source before drawing a conclusion."]
        for other in links["records"]:
            info = other["fields"]
            details.append(f"{other['id']} · Process ID {info.get('pid', 'unknown')} · {info.get('path') or 'Path unavailable'}")
        sections.append("Related processes\n" + "\n".join(details))
    return "\n\n".join(sections)


def attempts_text(attempts):
    latest = {item["collector"]: item for item in attempts}
    counts = Counter(item["status"] for item in latest.values())
    lines = ["Source coverage", ", ".join(f"{count} {status.lower()}" for status, count in sorted(counts.items()))]
    for key, item in latest.items():
        count = item.get("count", 0)
        entry = f"• {source_label(key, item.get('channel'))}: {item['status']} ({count} records)"
        if item.get("reason"):
            entry += f"\n  {item['reason']}"
        lines.append(entry)
    if len(attempts) > len(latest):
        lines.append("Open Raw JSON to review earlier attempts.")
    return "\n".join(lines)


def coverage_text(item):
    manifest = item["manifest"]
    origin = manifest.get("source_evidence")
    if isinstance(origin, dict) and origin.get("kind") == "evtx":
        return (f"Saved Windows log · {origin.get('filename', 'EVTX')}\n"
                f"Original EVTX SHA-256: {origin.get('sha256', 'unknown')}\n"
                f"Detached original EVTX SHA-256: {origin.get('external', 'unknown')}\n"
                f"Observed range (UTC): {origin.get('start') or 'unknown'} to {origin.get('end') or 'unknown'}\n"
                f"Run ID: {item['run']}\n\n" + attempts_text(manifest["attempts"]))
    text = (f"{item['host']} · {manifest['plan'].get('profile', 'unknown').title()} collection\n"
            f"Run ID: {item['run']}\nDetached checksum: {item['external']}\n\n"
            + attempts_text(manifest["attempts"]))
    for attachment in manifest.get("attachments", []):
        info = manifest["payloads"][attachment["payload"]]
        text += (f"\n\n{source_label(attachment['kind'])} · {attachment.get('filename', attachment['payload'])}"
                 f"\nOriginal SHA-256: {info['sha256']}\nSize: {info['bytes']:,} bytes"
                 f"\nDetached original SHA-256: {attachment['external']}")
        if attachment.get("start"):
            text += f"\nObserved range (UTC): {attachment['start']} to {attachment.get('end') or 'unknown'}"
    return text


def format_view(kind, data, raw=False):
    if raw:
        return json.dumps(data, ensure_ascii=False, indent=2)
    if kind == "record":
        return record_text(data["record"], data["process_links"])
    if kind == "plan":
        lines = [f"{data['profile'].title()} collection", f"Save evidence to {data['destination']}",
                 f"Events from {data['start']} through {data['end']} (UTC)",
                 f"Up to {data['max_rows']} records per source and {data['max_payload_bytes'] // (1024**2)} MiB of payload.",
                 "\nSelected sources"]
        lines.extend("• " + source_label(item) for item in data["collectors"])
        lines.extend("• " + item for item in data["custom_channels"])
        evidence = data.get("evidence", [])
        if evidence:
            lines.append("\nSupplemental originals for the same ZIP")
            for item in evidence:
                filename = Path(item["path"]).name if item.get("path") else "Choose a saved file"
                size = f"{item['size']:,} bytes" if item.get("size") is not None else "file unavailable"
                lines.append(f"• {source_label(item['kind'])} · {filename} · {size}")
            size = sum(item["size"] or 0 for item in evidence)
            lines.append(f"Selected originals total {size:,} bytes. The ZIP also includes collection data and an index.")
        if data["files"]:
            lines.extend("\nSelected files\n" + item for item in data["files"])
        lines.extend(["\nSensitive information in scope", *data["sensitive"]])
        return "\n".join(lines)
    if kind == "capture":
        return f"Evidence ZIP\n{data['archive']}\n\nDetached checksum\n{data['checksum']}\n\n" + attempts_text(data["coverage"])
    if kind == "coverage":
        if not data:
            return "Import a Windows Traige ZIP or saved EVTX to see coverage."
        return "\n\n".join(coverage_text(item) for item in data)
    if kind == "verification":
        return (f"Archive members: {data['internal']}\nDetached SHA-256: {data['external']}\n"
                f"Archive SHA-256: {data['sha256']}\n\n{data['interpretation']}\n\n"
                + attempts_text(data["manifest"]["attempts"]))
    if kind == "findings":
        if not data:
            return "There are no annotations yet. Select a record in the timeline and choose Add annotation."
        return "\n\n".join(
            f"{item['kind'].title()} {item['id']} · {item['reviewed'] or 'Awaiting review'}\n"
            f"{item['text']}\nRecord: {item['ref']}\nArchive: {item['digest']}" for item in data
        )
    return plain(data)
