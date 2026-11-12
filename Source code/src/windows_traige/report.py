"""Inert reports and selected record exports."""

import csv
import html
import tempfile
from pathlib import Path

from .case import annotations, audit_case, coverage, query
from .common import Invalid, digest, encode, now, publish, safe_path
from .present import plain, source_label


def safe_csv(value):
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


def export(case, destination, criteria=None, selected=None):
    destination = safe_path(destination)
    extension = destination.suffix.lower()
    if extension not in {".html", ".json", ".csv"}:
        raise Invalid("Report format must be HTML, JSON, or CSV")
    rows = query(case, **(criteria or {})) if selected is None else selected
    sources = coverage(case)
    notes = annotations(case)
    with tempfile.TemporaryDirectory(prefix=".incomplete-", dir=destination.parent) as temporary:
        stage = Path(temporary) / "report"
        if extension == ".html":
            stage.write_text(render(rows, sources, notes), encoding="utf-8")
        elif extension == ".json":
            stage.write_bytes(encode({"exported": now(), "sources": sources, "records": rows, "annotations": notes}))
        else:
            names = ("archive", "id", "host", "source", "kind", "observed", "acquired", "fields")
            with stage.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(names)
                for row in rows:
                    writer.writerow([safe_csv(encode(row[key]).decode() if key == "fields" else row.get(key)) for key in names])
        with stage.open("rb") as stream:
            checksum = digest(stream)
        publish(stage, destination)
    audit_case(case, "report", {"format": extension, "records": len(rows), "sha256": checksum})
    return {"path": str(destination), "records": len(rows), "sha256": checksum}


def render(rows, sources, notes):
    e = lambda x: html.escape(str(x), quote=True)
    parts = [
        '<!doctype html><html lang="en"><meta charset="utf-8">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">',
        "<title>Windows Traige case report</title>",
        "<style>body{font:1rem system-ui;margin:3em auto;padding:0 1em;max-width:75em}"
        "table{border-collapse:collapse;width:100%}td,th{padding:.6em;border-bottom:1px solid #aaa;"
        "text-align:left;overflow-wrap:anywhere}pre{white-space:pre-wrap}</style>",
        f"<h1>Windows Traige case report</h1><p>Exported {e(now())}. Records in this report: {len(rows)}.</p>",
        "<h2>Scope and verification</h2>",
    ]
    for bundle in sources:
        manifest = bundle["manifest"]
        parts.append(f"<h3>{e(bundle['host'])} / {e(bundle['run'])}</h3>"
                     f"<p>Archive SHA-256 {e(bundle['digest'])}. Internal consistency verified at import. "
                     f"Detached digest {e(bundle['external'])}.</p>")
        origin = manifest.get("source_evidence")
        if isinstance(origin, dict) and origin.get("kind") == "evtx":
            parts.append(f"<p>Original EVTX {e(origin.get('filename'))}. SHA-256 {e(origin.get('sha256'))}. "
                         f"Detached original SHA-256 {e(origin.get('external'))}.</p>")
        for attachment in manifest.get("attachments", []):
            info = manifest["payloads"][attachment["payload"]]
            parts.append(f"<p>{e(source_label(attachment['kind']))} {e(attachment.get('filename'))}. "
                         f"Original SHA-256 {e(info['sha256'])}. Detached original SHA-256 "
                         f"{e(attachment['external'])}.</p>")
        parts.append(f"<pre>{e(plain(manifest['plan']))}</pre><ul>")
        for attempt in manifest["attempts"]:
            parts.append(f"<li>{e(source_label(attempt['collector'], attempt.get('channel')))}: {e(attempt['status'])} "
                         f"{e(attempt.get('reason', ''))}</li>")
        parts.append("</ul>")
    parts.append("<h2>Records</h2><table><thead><tr><th>Observed UTC</th><th>Source</th>"
                 "<th>Details</th></tr></thead><tbody>")
    for row in rows:
        parts.append(f"<tr><td>{e(row['observed'] or 'Unknown')}</td><td>{e(row['host'])}<br>"
                     f"{e(row['source'])}<br>{e(row['archive'])}/{e(row['id'])}</td>"
                     f"<td><pre>{e(plain(row['fields']))}</pre></td></tr>")
    parts.append("</tbody></table><h2>Annotations and findings</h2><ul>")
    for note in notes:
        state = f"Reviewed by {note['reviewed']}" if note["reviewed"] else "Unreviewed"
        parts.append(f"<li>{e(note['kind'])} · {e(state)} · {e(note['author'] or 'Unknown author')}<br>"
                     f"{e(note['text'])}<br>{e(note['digest'])}/{e(note['ref'])}</li>")
    return "\n".join(parts + ["</ul></html>"])
