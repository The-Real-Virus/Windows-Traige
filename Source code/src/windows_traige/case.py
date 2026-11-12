"""Transactional local indexes and provenance-aware investigation."""

import hashlib
import os
import sqlite3
import tempfile
import zipfile
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path

from .bundle import HASH, MAX_ARCHIVE, external_hash, records, verify, verify_open
from .common import Invalid, check_cancel, decode, encode, now, publish, require_space, safe_path, timestamp

SQL = """
CREATE TABLE bundles (
    digest TEXT PRIMARY KEY, host TEXT NOT NULL, run TEXT NOT NULL, imported TEXT NOT NULL,
    external TEXT NOT NULL, manifest BLOB NOT NULL
);
CREATE TABLE records (
    ordinal INTEGER PRIMARY KEY, digest TEXT NOT NULL REFERENCES bundles(digest), ref TEXT NOT NULL,
    kind TEXT NOT NULL, source TEXT NOT NULL, acquired TEXT NOT NULL, observed TEXT, body BLOB NOT NULL,
    event_id INTEGER, channel TEXT, severity TEXT, pid INTEGER, path TEXT,
    ip TEXT, remote_ip TEXT, port INTEGER, remote_port INTEGER, created TEXT,
    UNIQUE(digest, ref)
);
CREATE INDEX timeline ON records(observed DESC, ordinal DESC);
CREATE INDEX event_query ON records(event_id, observed DESC);
CREATE INDEX process_query ON records(kind, pid, created, acquired);
CREATE INDEX channel_query ON records(channel, observed DESC);
CREATE TABLE annotations (
    id INTEGER PRIMARY KEY, digest TEXT NOT NULL, ref TEXT NOT NULL,
    kind TEXT NOT NULL, text TEXT NOT NULL, author TEXT, reviewed TEXT, at TEXT NOT NULL,
    FOREIGN KEY(digest, ref) REFERENCES records(digest, ref)
);
CREATE TABLE saved_filters (name TEXT PRIMARY KEY, criteria BLOB NOT NULL);
CREATE TABLE actions (id INTEGER PRIMARY KEY, at TEXT NOT NULL, action TEXT NOT NULL, detail BLOB NOT NULL);
PRAGMA user_version = 1;
"""


@contextmanager
def connect(case, write=False, create=False):
    case = safe_path(case)
    if create:
        case.mkdir(exist_ok=True)
    db = safe_path(case / "case.sqlite3")
    mode = "rwc" if create else "rw" if write else "ro"
    conn = sqlite3.connect(db.as_uri() + f"?mode={mode}", uri=True, timeout=2)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        if write:
            conn.execute("BEGIN IMMEDIATE")
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version == 0 and create:
            for statement in SQL.split(";"):
                if statement.strip():
                    conn.execute(statement)
        elif version != 1:
            raise Invalid("Unsupported case database schema")
        yield conn
        if write:
            conn.commit()
    finally:
        conn.close()


def audit(conn, action, detail):
    conn.execute("INSERT INTO actions(at, action, detail) VALUES (?,?,?)", (now(), action, encode(detail)))


def audit_case(case, action, detail):
    with connect(case, write=True) as conn:
        audit(conn, action, detail)


def typed(fields, key, datatype):
    value = fields.get(key)
    return value if type(value) is datatype else None


def values(archive, row):
    fields = row["fields"]
    return (
        archive, row["id"], row["kind"], row["source"], row["acquired"], row["observed"], encode(row),
        typed(fields, "event_id", int), typed(fields, "channel", str), typed(fields, "severity", str),
        typed(fields, "pid", int), typed(fields, "path", str), typed(fields, "ip", str),
        typed(fields, "remote_ip", str), typed(fields, "port", int), typed(fields, "remote_port", int),
        timestamp(fields.get("created")) if row["kind"] == "process" else None,
    )


def import_evidence(case, source, checksum=None, cancel=None, progress=None):
    suffix = Path(source).suffix.lower()
    if suffix == ".evtx":
        from .evtx import import_file
        return import_file(case, source, checksum, cancel, progress)
    if suffix != ".zip":
        raise Invalid("Select a Windows Traige ZIP or a saved Windows EVTX file")
    return import_bundle(case, source, checksum, cancel, progress)


def import_bundle(case, archive, checksum=None, cancel=None, progress=None, *, evtx_source=None):
    case, archive = safe_path(case), safe_path(archive)
    if not archive.is_file():
        raise Invalid("Select a local evidence ZIP")
    size = archive.stat().st_size
    if size > MAX_ARCHIVE:
        raise Invalid("Archive exceeds file size limit")
    expected = external_hash(checksum)
    require_space(case if case.exists() else case.parent, size + 16 * 1024 ** 2)
    with connect(case, write=True, create=True) as conn:
        source_dir = safe_path(case / "bundles")
        source_dir.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".incomplete-", dir=source_dir) as tmp:
            stage = Path(tmp) / "archive.zip"
            with archive.open("rb") as source, stage.open("x+b") as target:
                original = os.fstat(source.fileno())
                copied = 0
                while block := source.read(1024 ** 2):
                    check_cancel(cancel)
                    copied += len(block)
                    if copied > size:
                        raise Invalid("Evidence archive changed during import")
                    target.write(block)
                if copied != size or os.fstat(source.fileno()).st_mtime_ns != original.st_mtime_ns:
                    raise Invalid("Evidence archive changed during import")
                target.flush()
                result = verify_open(target, expected, cancel, validate_records=False)
                identity, manifest = result["sha256"], result["manifest"]
                if evtx_source:
                    original_sha256, external = evtx_source
                    conn.execute("""CREATE TABLE IF NOT EXISTS evtx_sources (
                        sha256 TEXT PRIMARY KEY, digest TEXT NOT NULL REFERENCES bundles(digest))""")
                    previous = conn.execute("""SELECT b.digest,b.external FROM evtx_sources s
                        JOIN bundles b ON s.digest=b.digest WHERE s.sha256=?""", (original_sha256,)).fetchone()
                    if previous:
                        original_identity = previous["digest"]
                        saved = safe_path(source_dir / (original_identity + ".zip"))
                        with saved.open("rb") as stream:
                            existing = verify_open(stream, original_identity, cancel, validate_records=False)
                        existing["external"] = previous["external"]
                        audit(conn, "duplicate-evtx-import", {"sha256": original_identity,
                                                             "source_sha256": original_sha256, "external": external})
                        return {"sha256": original_identity, "duplicate": True, "verification": existing}
                prior = conn.execute("SELECT external FROM bundles WHERE digest=?", (identity,)).fetchone()
                saved = safe_path(source_dir / (identity + ".zip"))
                if prior:
                    if verify(saved, cancel=cancel)["sha256"] != identity:
                        raise Invalid("Stored evidence has changed")
                    if expected and prior["external"] != "matched":
                        conn.execute("UPDATE bundles SET external='matched' WHERE digest=?", (identity,))
                    audit(conn, "duplicate-import", {"sha256": identity, "external": result["external"]})
                    return {"sha256": identity, "duplicate": True, "verification": result}
                index_size = sum(entry["bytes"] for name, entry in manifest["payloads"].items()
                                 if name.startswith("normalized/") and name.endswith(".jsonl"))
                require_space(case, index_size * 3 + 16 * 1024 ** 2)
                conn.execute("INSERT INTO bundles VALUES(?,?,?,?,?,?)",
                             (identity, manifest["host"], manifest["run"], now(), result["external"], encode(manifest)))
                if evtx_source:
                    conn.execute("INSERT INTO evtx_sources VALUES(?,?)", (original_sha256, identity))
                repeated = set()
                if manifest.get("attachments"):
                    conn.execute("""CREATE TABLE IF NOT EXISTS attachment_sources (
                        kind TEXT NOT NULL, sha256 TEXT NOT NULL, digest TEXT NOT NULL REFERENCES bundles(digest),
                        PRIMARY KEY(kind, sha256))""")
                    for item in manifest["attachments"]:
                        name = item["payload"]
                        source_hash = manifest["payloads"][name]["sha256"]
                        added = conn.execute("INSERT OR IGNORE INTO attachment_sources VALUES (?,?,?)",
                                             (item["kind"], source_hash, identity))
                        if not added.rowcount:
                            repeated.add(name)
                count = 0
                with zipfile.ZipFile(target) as z:
                    for name in manifest["payloads"]:
                        if not name.startswith("normalized/") or not name.endswith(".jsonl"):
                            continue
                        with z.open(name) as stream:
                            batch = []
                            for row in records(stream, manifest["payloads"], cancel):
                                if row["source"] in repeated:
                                    continue
                                batch.append(values(identity, row))
                                if len(batch) == 512:
                                    insert_batch(conn, batch)
                                    count += len(batch)
                                    batch.clear()
                                    if progress:
                                        progress("Indexing records", count)
                            insert_batch(conn, batch)
                            count += len(batch)
            check_cancel(cancel)
            if saved.exists():
                if verify(saved, cancel=cancel)["sha256"] != identity:
                    raise Invalid("Existing case evidence conflicts with this archive")
            else:
                publish(stage, saved)
            audit(conn, "import", {"sha256": identity, "external": result["external"], "records": count,
                                   "repeated_attachments": sorted(repeated)})
            return {"sha256": identity, "records": count, "duplicate": False, "verification": result}


def insert_batch(conn, batch):
    try:
        conn.executemany("""
            INSERT INTO records(digest,ref,kind,source,acquired,observed,body,event_id,channel,severity,
                                pid,path,ip,remote_ip,port,remote_port,created)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, batch)
    except (OverflowError, sqlite3.IntegrityError) as exc:
        raise Invalid("Duplicate or invalid normalized record key or field") from exc


def materialize(row):
    body = decode(row["body"])
    computer = typed(body["fields"], "source_computer", str)
    fallback = "Source not recorded" if body["source"].startswith("attachments/") else row["host"]
    return dict(body, archive=row["digest"], host=computer or fallback,
                run=row["run"], ordinal=row["ordinal"])


def query(case, *, kind=None, event_id=None, channel=None, severity=None, pid=None,
          path=None, ip=None, port=None, start=None, end=None, text=None,
          archive=None, offset=0, limit=100):
    if not 1 <= limit <= 1000 or not 0 <= offset <= 10_000_000:
        raise Invalid("Query pagination is outside supported bounds")
    start, end = timestamp(start), timestamp(end)
    if start and end and start > end:
        raise Invalid("Start must precede end")
    filters = [
        ("kind", "r.kind=? COLLATE NOCASE", kind), ("event", "r.event_id=?", event_id),
        ("channel", "r.channel=? COLLATE NOCASE", channel), ("severity", "r.severity=? COLLATE NOCASE", severity),
        ("pid", "r.pid=?", pid), ("path", "instr(lower(r.path),lower(?))>0", path),
        ("ip", "? IN (r.ip,r.remote_ip)", ip), ("port", "? IN (r.port,r.remote_port)", port),
        ("start", "r.observed>=?", start), ("end", "r.observed<=?", end),
        ("text", "instr(lower(CAST(r.body AS TEXT)),lower(?))>0", text),
        ("archive", "r.digest=?", archive),
    ]
    active = [(clause, value) for _, clause, value in filters if value is not None]
    where = " AND ".join(clause for clause, _ in active) or "1"
    arguments = [value for _, value in active] + [limit, offset]
    with connect(case) as conn:
        rows = conn.execute(f"""
            SELECT r.*,b.host,b.run FROM records r JOIN bundles b ON b.digest=r.digest
            WHERE {where} ORDER BY r.observed DESC,r.ordinal DESC LIMIT ? OFFSET ?
        """, arguments)
        return [materialize(row) for row in rows]


def coverage(case):
    with connect(case) as conn:
        return [dict(row, manifest=decode(row["manifest"])) for row in
                conn.execute("SELECT * FROM bundles ORDER BY imported")]


def get_record(case, identity, ref):
    with connect(case) as conn:
        row = conn.execute("""
            SELECT r.*,b.host,b.run FROM records r JOIN bundles b ON b.digest=r.digest
            WHERE r.digest=? AND r.ref=?
        """, (identity, ref)).fetchone()
        if row is None:
            raise Invalid("Record reference does not resolve")
        return materialize(row)


def export_original(case, identity, ref, destination, cancel=None):
    """Create a checked working copy of one supplemental original."""
    if not isinstance(identity, str) or not HASH.fullmatch(identity):
        raise Invalid("Invalid archive identity")
    row = get_record(case, identity, ref)
    name = row["source"]
    if not name.startswith("attachments/"):
        raise Invalid("Select a record backed by a supplemental original")
    destination = safe_path(destination)
    if destination.suffix.lower() != Path(name).suffix.lower() or destination.exists():
        raise Invalid("Choose a new filename with the original evidence extension")
    source = safe_path(Path(case) / "bundles" / (identity + ".zip"))
    with source.open("rb") as stream:
        manifest = verify_open(stream, expected=identity, cancel=cancel, validate_records=False)["manifest"]
        expected = manifest["payloads"][name]
        require_space(destination.parent, expected["bytes"])
        with zipfile.ZipFile(stream) as archive, tempfile.TemporaryDirectory(
                prefix=".incomplete-original-", dir=destination.parent) as tmp:
            stage = Path(tmp) / "working-copy"
            h = hashlib.sha256()
            with archive.open(name) as incoming, stage.open("xb") as out:
                while block := incoming.read(1024 * 1024):
                    check_cancel(cancel)
                    h.update(block)
                    out.write(block)
            actual = h.hexdigest()
            if actual != expected["sha256"]:
                raise Invalid("The working copy did not match the original checksum")
            check_cancel(cancel)
            publish(stage, destination)
    return {"path": str(destination), "sha256": actual, "bytes": expected["bytes"]}


def native_event(case, identity, ref, cancel=None):
    """Read one native event via Windows using the verified case copy."""
    if not HASH.fullmatch(identity):
        raise Invalid("Invalid archive identity")
    row = get_record(case, identity, ref)
    name = row["source"]
    from .evtx import NORMALIZED, ORIGINAL
    record_id = row["fields"].get("event_record_id")
    if (row["kind"] != "event" or not name.startswith("raw/") or not name.endswith(".evtx") or
            (name != ORIGINAL and type(record_id) is not int)):
        raise Invalid("This record has no native EVTX reference. Its parsed fields remain available.")
    directory = safe_path(case)
    source = safe_path(directory / "bundles" / (identity + ".zip"))
    with source.open("rb") as stream:
        verified = verify_open(stream, expected=identity, cancel=cancel, validate_records=False)
        if name == ORIGINAL:
            if NORMALIZED not in verified["manifest"]["payloads"]:
                raise Invalid("This archived record has no verified XML rendering")
            with zipfile.ZipFile(stream) as archive, archive.open(NORMALIZED) as normalized:
                for item in records(normalized, verified["manifest"]["payloads"], cancel):
                    xml = item["fields"].get("xml")
                    if item["id"] == ref and item["source"] == ORIGINAL and isinstance(xml, str):
                        return xml
            raise Invalid("This archived record has no verified XML rendering")
        with zipfile.ZipFile(stream) as archive, tempfile.TemporaryDirectory(prefix=".incomplete-view-", dir=directory) as tmp:
            local = Path(tmp) / "record.evtx"
            with archive.open(name) as member, local.open("xb") as target:
                while block := member.read(1024 ** 2):
                    check_cancel(cancel)
                    target.write(block)
            from .native import as_text, command
            query = f"*[System[EventRecordID={record_id}]]"
            return as_text(command(["wevtutil.exe", "qe", str(local), "/lf:true", "/q:" + query,
                                    "/f:xml", "/c:1", "/uni:true"], 15, cancel))


def correlate(case, row):
    pid = row["fields"].get("pid")
    if row["kind"] not in {"event", "network"} or type(pid) is not int or not row["observed"]:
        return {"status": "unavailable", "records": []}
    observed = datetime.fromisoformat(row["observed"])
    later = timestamp((observed + timedelta(seconds=120)).isoformat())
    with connect(case) as conn:
        candidates = conn.execute("""
            SELECT r.*,b.host,b.run FROM records r JOIN bundles b ON b.digest=r.digest
            WHERE r.kind='process' AND r.pid=? AND r.digest=? AND r.created<=?
                AND r.acquired BETWEEN ? AND ? ORDER BY r.created DESC LIMIT 16
        """, (pid, row["archive"], row["observed"], row["observed"], later)).fetchall()
        result = [materialize(candidate) for candidate in candidates]
    status = "time-based" if len(result) == 1 else "ambiguous" if result else "unavailable"
    return {"status": status, "records": result}


def annotate(case, archive, ref, kind, text, author=None):
    if kind not in {"note", "bookmark", "finding", "hypothesis"} or not 0 < len(text.strip()) <= 16_384:
        raise Invalid("Invalid annotation")
    with connect(case, write=True) as conn:
        if not conn.execute("SELECT 1 FROM records WHERE digest=? AND ref=?", (archive, ref)).fetchone():
            raise Invalid("Record reference does not resolve")
        result = conn.execute("""
            INSERT INTO annotations(digest,ref,kind,text,author,at) VALUES(?,?,?,?,?,?)
        """, (archive, ref, kind, text, author or None, now()))
        return result.lastrowid


def review(case, annotation, reviewer):
    if not reviewer.strip():
        raise Invalid("Provide the reviewer identity")
    with connect(case, write=True) as conn:
        found = conn.execute("UPDATE annotations SET reviewed=? WHERE id=? AND kind IN ('finding','hypothesis')",
                             (reviewer, annotation))
        if not found.rowcount:
            raise Invalid("Finding does not resolve")
        audit(conn, "review", {"annotation": annotation, "reviewer": reviewer})


def annotations(case):
    with connect(case) as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM annotations ORDER BY id")]


def save_filter(case, name, criteria):
    if not 0 < len(name.strip()) <= 100:
        raise Invalid("Name the saved filter")
    with connect(case, write=True) as conn:
        conn.execute("INSERT INTO saved_filters VALUES (?,?) ON CONFLICT(name) DO UPDATE SET criteria=excluded.criteria",
                     (name, encode(criteria)))


def saved_filters(case):
    with connect(case) as conn:
        return {row["name"]: decode(row["criteria"]) for row in conn.execute("SELECT * FROM saved_filters ORDER BY name")}
