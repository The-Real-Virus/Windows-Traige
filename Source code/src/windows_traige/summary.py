"""Offline case overview, review leads and incident-response guidance."""

from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory

from . import case
from .common import Invalid, decode, publish, safe_path
from .present import EVENTS, source_label
from .supplemental import LABELS as SUPPLEMENTAL_LABELS

RULES = (
    ("System", 7045), ("Security", 1102), ("Security", 4625), ("Security", 4698), ("Security", 4720),
    ("Microsoft-Windows-Windows Defender/Operational", 1116),
    ("Microsoft-Windows-Windows Defender/Operational", 1117),
    ("Microsoft-Windows-Windows Defender/Operational", 5007), ("System", 104),
)


def coverage_guidance(status, reason, channel, kind):
    detail = reason.lower()
    if kind in SUPPLEMENTAL_LABELS:
        if "sha-256" in detail:
            return "Ask the source owner for a fresh copy and a separately verified SHA-256."
        if "limit" in detail:
            return "Use a narrower source export when you need more indexed records. Review the preserved original locally."
        return "Review the selected source, file format and export time. Request a new export when the source is incomplete."
    if status == "Access Denied":
        if channel:
            return "Use an authorized administrator retry where offered, or ask for a saved EVTX from the source owner."
        return "Ask the source owner for authorized access or a copy of the evidence."
    if "limit" in detail or "oversized" in detail:
        return "For logs, use a narrower time window, increase the record limit within the app's bounds, or import a saved EVTX. For other sources, narrow the collection."
    if "disabled" in detail or status == "Unavailable":
        return "Confirm this source exists and was enabled during the incident. Ask for earlier exports or copies from a central log service."
    if "no events" in detail or "no records" in detail or "no readable events" in detail:
        return "Check the time window, source computer and retention. Look for an earlier export or compare independent sources."
    if "raw evtx" in detail:
        return "The timeline can use the saved event fields. Ask for a native EVTX export if you need the original log."
    return "Review the reason, rerun the affected collection if appropriate, or obtain the evidence from its owner."


def build(folder):
    with case.connect(folder) as conn:
        conn.execute("BEGIN")
        sources = [dict(row, manifest=decode(row["manifest"])) for row in
                   conn.execute("SELECT host, external, manifest FROM bundles ORDER BY imported")]
        totals = {row["kind"]: row["n"] for row in conn.execute("SELECT kind, COUNT(*) AS n FROM records GROUP BY kind")}
        times = conn.execute("SELECT MIN(observed), MAX(observed), COUNT(*) - COUNT(observed) FROM records").fetchone()
        highlights = []
        for channel, event_id in RULES:
            where = "event_id=? AND lower(channel)=?"
            args = (event_id, channel.lower())
            count = conn.execute(f"SELECT COUNT(*) FROM records WHERE {where}", args).fetchone()[0]
            if count:
                found = conn.execute(f"SELECT digest,ref,observed FROM records WHERE {where} ORDER BY observed DESC, ordinal DESC LIMIT 1",
                                     args).fetchone()
                title, guidance = EVENTS[(channel.lower(), event_id)]
                highlights.append(dict(found, title=title, guidance=guidance, count=count, event_id=event_id,
                                       channel=channel))
        gaps = []
        checks = Counter()
        archived = []
        supplemental = Counter()
        hosts = {row[0] for row in conn.execute("""
            SELECT DISTINCT json_extract(CAST(body AS TEXT), '$.fields.source_computer') FROM records
            WHERE source LIKE 'attachments/%' AND json_type(CAST(body AS TEXT), '$.fields.source_computer')='text'
        """) if row[0]}
        for source in sources:
            manifest = source["manifest"]
            origin = manifest.get("source_evidence")
            if isinstance(origin, dict) and origin.get("kind") == "evtx":
                archived.append(origin)
                computers = origin.get("computers", [])
                if isinstance(computers, list):
                    hosts.update(computer for computer in computers if isinstance(computer, str))
            elif any(item["collector"] not in SUPPLEMENTAL_LABELS for item in manifest["attempts"]):
                hosts.add(source["host"])
            supplemental.update(item["kind"] for item in manifest.get("attachments", []))
            latest = {item["collector"]: item for item in manifest["attempts"]}
            checks.update(item["status"] for item in latest.values())
            for key, item in latest.items():
                status, reason, channel = item["status"], str(item.get("reason") or ""), item.get("channel")
                if status == "Collected":
                    if not reason.startswith(("No events", "No records", "The saved EVTX contains no readable")):
                        continue
                    status = "No records returned"
                guidance = coverage_guidance(status, reason, channel, key)
                payloads = item.get("payloads")
                has_evtx = isinstance(payloads, list) and any(str(name).endswith(".evtx") for name in payloads)
                if (manifest.get("prior_archive") and item.get("privilege") == "administrator" and channel and
                        item.get("count") and not has_evtx and "raw evtx" not in reason.lower()):
                    raw_gap = "The retry saved normalized events only. Raw EVTX is unavailable."
                    reason = f"{reason.rstrip('. ')}. {raw_gap}" if reason else raw_gap
                gaps.append({"host": source["host"], "source": source_label(key, channel), "run": manifest["run"],
                             "status": status, "reason": reason.strip(), "guidance": guidance})
        return {"records": totals, "earliest": times[0], "latest": times[1], "unknown_times": times[2],
                "bundles": len(sources), "hosts": len(hosts), "archived_logs": archived, "supplemental": dict(supplemental),
                "matched_digests": sum(source["external"] == "matched" for source in sources),
                "coverage": dict(checks), "gaps": gaps, "highlights": highlights}


def text(summary):
    if not summary["bundles"]:
        return "Import a Windows Traige ZIP or a saved Windows EVTX log to build the case summary."
    n = sum(summary["records"].values())
    hosts = summary["hosts"]
    bundles = summary["bundles"]
    matched = summary["matched_digests"]
    lines = [
        "What was collected",
        f"{quantity(n, 'record')} in {quantity(bundles, 'evidence bundle')}. Recorded sources: {hosts:,}.",
        f"Detached checksum matched for {quantity(matched, 'bundle')}.",
    ]
    if summary["archived_logs"]:
        lines.append(f"Original EVTX preserved for {quantity(len(summary['archived_logs']), 'archived log')}.")
    for kind, count in summary.get("supplemental", {}).items():
        lines.append(f"{source_label(kind)} · {quantity(count, 'preserved original')}.")
    if summary["earliest"]:
        lines.append(f"Recorded activity spans {summary['earliest']} to {summary['latest']} (UTC).")
    if summary["unknown_times"]:
        lines.append(f"{summary['unknown_times']:,} records have no observed time.")
    lines.extend(f"• {quantity(count, kind + ' record')}" for kind, count in sorted(summary["records"].items()))
    lines.extend(["", "What the evidence says",
                  "Review leads come from the event channel and event ID. A match calls for context and corroboration."])
    if not summary["highlights"]:
        lines.append("No event matched the built-in review rules in the imported scope.")
    for lead in summary["highlights"]:
        lines.extend([
            f"• {lead['title']} · {lead['channel']} {lead['event_id']} · {quantity(lead['count'], 'matching record')}",
            f"  {lead['guidance']}", f"  Latest reference: {lead['digest']}/{lead['ref']}",
        ])
    lines.extend(["", "Evidence coverage and gaps"])
    if not summary["gaps"]:
        lines.append("No source gaps were reported for the selected capture. Compare its scope with the incident question.")
    else:
        for gap in summary["gaps"]:
            lines.append(f"• {gap['host']} · {gap['source']}: {gap['status']}. {gap['reason']}".rstrip())
            lines.append(f"  {gap['guidance']} Run {gap['run']}.")
    lines.extend(["", "What to do next",
                  "1. Preserve the evidence ZIPs and the separately held checksums. Record who acquired them and when.",
                  "2. Open the highlighted events. Compare times, accounts and source computers against approved changes and independent records.",
                  "3. Fill important gaps using approved logs, an endpoint security console, identity or network records, or a qualified responder. You can import saved Windows EVTX logs into this case.",
                  "4. If you suspect an active breach, contact your incident-response lead using a trusted channel. Follow the approved containment plan and preserve volatile evidence where safe.",
                  "5. Record verified findings, owners and next actions. Treat unresolved leads as hypotheses.",
                  "", "This overview describes the imported evidence. Use an analyst and independent sources to assess whether a breach occurred."])
    return "\n".join(lines)


def quantity(count, noun):
    return f"{count:,} {noun}" if count == 1 else f"{count:,} {noun}s"


def export(summary, target):
    target = safe_path(target)
    if target.suffix.lower() != ".txt":
        raise Invalid("Save the evidence summary as a .txt file")
    with TemporaryDirectory(prefix=".incomplete-summary-", dir=target.parent) as directory:
        stage = Path(directory) / "summary.txt"
        stage.write_text(text(summary) + "\n", encoding="utf-8")
        publish(stage, target)
    return str(target)
