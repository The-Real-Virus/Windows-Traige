"""Console interface for collection and case operations."""

import argparse
import json
import os
import sqlite3
import sys
from threading import Event

from . import VERSION, bundle, case, collect, fixture, native, present, report, summary, supplemental
from .common import Cancelled, Invalid

SUCCESS, PARTIAL, INVALID, DENIED, CANCELLED, FAILED = 0, 2, 3, 4, 5, 6


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(INVALID, f"{self.prog}: {message}\n")


def filters(parser):
    parser.add_argument("--kind", choices=sorted(bundle.KINDS))
    parser.add_argument("--event-id", type=int)
    parser.add_argument("--channel")
    parser.add_argument("--severity")
    parser.add_argument("--pid", type=int)
    parser.add_argument("--path")
    parser.add_argument("--ip")
    parser.add_argument("--port", type=int)
    parser.add_argument("--start", help="Earliest observed timestamp in ISO 8601 with offset")
    parser.add_argument("--end", help="Latest observed timestamp in ISO 8601 with offset")
    parser.add_argument("--text")
    parser.add_argument("--archive", help="Archive SHA-256")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--offset", type=int, default=0)


def arguments():
    parser = Parser(prog="WindowsTraige.Cli.exe", description="Collect and investigate local Windows evidence.")
    parser.add_argument("--version", action="version", version=f"Windows Traige {VERSION}")
    parser.add_argument("--pretty", action="store_true", help="Show plain text instead of JSON")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=Parser)
    capture = commands.add_parser("collect", help="Capture a scoped collection")
    capture.add_argument("--profile", choices=collect.PROFILES, default="standard")
    capture.add_argument("--out", required=True)
    capture.add_argument("--hours", type=int, default=24)
    capture.add_argument("--collector", action="append", default=[])
    capture.add_argument("--channel", action="append", default=[])
    capture.add_argument("--file", action="append", default=[])
    capture.add_argument("--hash-files", action="store_true")
    capture.add_argument("--process-arguments", action="store_true")
    capture.add_argument("--max-rows", type=int, default=collect.MAX_ROWS)
    capture.add_argument("--evidence", action="append", default=[], metavar="TYPE=FILE",
                         help="Add one of: " + ", ".join(supplemental.LABELS))
    capture.add_argument("--evidence-checksum", action="append", default=[], metavar="TYPE=FILE",
                         help="Use a separately supplied SHA-256 for the selected evidence type")
    capture.add_argument("--plan", action="store_true", help="Preview scope without collecting")
    capture.add_argument("--unattended", action="store_true", help="Forbid UAC prompts (the default)")
    capture.add_argument("--elevate", action="store_true", help="Offer UAC for eligible denied sources")
    commands.add_parser("channels", help="List Windows event channels")
    retry = commands.add_parser("retry", help="Retry eligible denied sources from a prior collection")
    retry.add_argument("bundle")
    retry.add_argument("--out", required=True)
    retry.add_argument("--elevate", action="store_true", required=True)
    synthetic = commands.add_parser("fixture", help="Create the redistributable synthetic case")
    synthetic.add_argument("--out", required=True)
    synthetic.add_argument("--count", type=int, default=0, help="Additional synthetic benchmark records")
    verify = commands.add_parser("verify", help="Check archive members and an optional detached digest")
    verify.add_argument("bundle")
    verify.add_argument("--checksum")
    imported = commands.add_parser("import", help="Verify and index a Windows Traige ZIP or saved Windows EVTX")
    imported.add_argument("bundle")
    imported.add_argument("--case", required=True)
    imported.add_argument("--checksum")
    original = commands.add_parser("save-original", help="Save a verified working copy of a supplemental original")
    original.add_argument("case")
    original.add_argument("--archive", required=True)
    original.add_argument("--record", required=True)
    original.add_argument("--out", required=True)
    search = commands.add_parser("query", help="Query records from a local case")
    search.add_argument("case")
    search.add_argument("--json", action="store_true", help="Return JSON instead of a record summary")
    filters(search)
    overview = commands.add_parser("summary", help="Review case coverage, evidence leads, and next steps")
    overview.add_argument("case")
    overview.add_argument("--json", action="store_true")
    exported = commands.add_parser("report", help="Export case coverage, records, and annotations")
    exported.add_argument("case")
    exported.add_argument("--out", required=True)
    filters(exported)
    note = commands.add_parser("annotate", help="Create a referenced local note or finding")
    note.add_argument("case")
    note.add_argument("--archive", required=True)
    note.add_argument("--record", required=True)
    note.add_argument("--kind", choices=["note", "bookmark", "finding", "hypothesis"], default="note")
    note.add_argument("--text", required=True)
    note.add_argument("--author")
    ai = commands.add_parser("ai", help="Ask an explicitly enabled provider using reviewed synthetic or case excerpts")
    ai.add_argument("case")
    ai.add_argument("--enable", action="store_true", required=True)
    ai.add_argument("--provider", choices=["openai", "anthropic", "gemini"], required=True)
    ai.add_argument("--model", required=True)
    ai.add_argument("--question", required=True)
    ai.add_argument("--record", action="append", default=[], metavar="ARCHIVE_SHA256/RECORD_ID")
    ai.add_argument("--approve-excerpts", metavar="SHA256",
                    help="Approve the exact provider, model, question, excerpt and tool scope printed by --preview")
    ai.add_argument("--preview", action="store_true")
    ai.add_argument("--tools", action="store_true", help="Allow read-only retrieval from the approved excerpt set")
    return parser


def status(result):
    latest = {item["collector"]: item["status"] for item in result["manifest"]["attempts"]}
    states = set(latest.values())
    if states == {"Collected"}:
        return SUCCESS
    if states == {"Access Denied"}:
        return DENIED
    return PARTIAL


def progress(phase, count):
    print(f"{phase} [{count}]", file=sys.stderr, flush=True)


def criteria(args):
    keys = ("kind", "event_id", "channel", "severity", "pid", "path", "ip", "port",
            "start", "end", "text", "archive", "limit", "offset")
    return {key: getattr(args, key) for key in keys}


def evidence_args(args):
    paths, checksums = {}, {}
    for values, target in ((args.evidence, paths), (args.evidence_checksum, checksums)):
        for value in values:
            kind, separator, path = value.partition("=")
            if kind not in supplemental.LABELS or kind in target or not separator or not path:
                raise Invalid("Use TYPE=FILE and specify each supplemental evidence type once")
            target[kind] = path
    if checksums.keys() - paths.keys():
        raise Invalid("Select the evidence file that the checksum belongs to")
    return tuple(supplemental.Selection(kind, path, checksums.get(kind, "")) for kind, path in paths.items())


def dispatch(args, cancel):
    match args.command:
        case "collect":
            if args.unattended and args.elevate:
                raise Invalid("Choose either unattended mode or elevation")
            scope = collect.plan(args.profile, args.out, hours=args.hours, collectors=args.collector,
                                 channels=args.channel, files=args.file, hash_files=args.hash_files,
                                 process_arguments=args.process_arguments, max_rows=args.max_rows,
                                 evidence=evidence_args(args))
            if args.plan:
                from dataclasses import asdict
                return asdict(scope), SUCCESS
            result = collect.run(scope, cancel, progress)
            if args.elevate and any(item["status"] == "Access Denied" for item in result["manifest"]["attempts"]):
                from .elevation import retry
                result = retry(result["archive"], args.out, cancel, progress)
            return result, status(result)
        case "retry":
            from .elevation import retry
            result = retry(args.bundle, args.out, cancel, progress)
            return result, status(result)
        case "channels":
            return {"channels": native.channels(cancel)}, SUCCESS
        case "fixture":
            return fixture.create(args.out, args.count, cancel), SUCCESS
        case "verify":
            return bundle.verify(args.bundle, args.checksum, cancel), SUCCESS
        case "import":
            return case.import_evidence(args.case, args.bundle, args.checksum, cancel, progress), SUCCESS
        case "save-original":
            return case.export_original(args.case, args.archive, args.record, args.out, cancel), SUCCESS
        case "query":
            return case.query(args.case, **criteria(args)), SUCCESS
        case "summary":
            return summary.build(args.case), SUCCESS
        case "report":
            return report.export(args.case, args.out, criteria(args)), SUCCESS
        case "annotate":
            return {"id": case.annotate(args.case, args.archive, args.record, args.kind, args.text, args.author)}, SUCCESS
        case "ai":
            from . import assistant
            excerpts = assistant.preview(args.case, args.record)
            approval = assistant.approval_digest(args.provider, args.model, args.question, excerpts, args.tools)
            if args.preview:
                return {"provider": args.provider, "model": args.model, "question": args.question,
                        "tools": args.tools, "excerpts": excerpts, "approval_sha256": approval}, SUCCESS
            if args.approve_excerpts != approval:
                raise Invalid("Run --preview and explicitly approve the displayed question and excerpts")
            key = os.environ.get(assistant.KEY_ENV[args.provider])
            if not key:
                raise Invalid("Supply the selected provider key in its documented environment variable")
            session = assistant.Session(args.provider, args.model, key)
            return session.ask(args.case, args.question, excerpts, args.tools, cancel), SUCCESS
    raise Invalid("Unknown command")


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    args = arguments().parse_args(argv)
    cancel = Event()
    import signal
    signal.signal(signal.SIGINT, lambda *_: cancel.set())
    try:
        result, code = dispatch(args, cancel)
        if args.command == "query" and not args.json:
            for row in result:
                print(f"{row['observed'] or 'Unknown'}  {row['kind']}  {row['host']}  {row['archive']}/{row['id']}")
        elif args.command == "summary" and not args.json:
            print(summary.text(result))
        elif args.pretty and not getattr(args, "json", False):
            view = "verification" if args.command == "verify" else "plan" if args.command == "collect" and args.plan else "generic"
            if args.command in {"collect", "retry", "fixture"} and "archive" in result:
                view = "capture"
                result = {"archive": result["archive"], "checksum": result["checksum"],
                          "coverage": result["manifest"]["attempts"]}
            print(present.format_view(view, result))
        else:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        return code
    except Invalid as exc:
        print(str(exc), file=sys.stderr)
        return INVALID
    except PermissionError:
        print("Access denied to the requested local path", file=sys.stderr)
        return DENIED
    except Cancelled as exc:
        print(str(exc), file=sys.stderr)
        return CANCELLED
    except native.NativeError as exc:
        print(exc.reason, file=sys.stderr)
        return DENIED if exc.status == "Access Denied" else FAILED
    except (OSError, sqlite3.Error) as exc:
        print(f"Operation failed ({type(exc).__name__})", file=sys.stderr)
        return FAILED


if __name__ == "__main__":
    raise SystemExit(main())
