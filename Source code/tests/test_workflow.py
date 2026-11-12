"""Focused fixture acceptance for evidence, analysis and assistant boundaries."""

import hashlib
import io
import json
import os
import sqlite3
import tempfile
import threading
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

from windows_traige import assistant, bundle, case, collect, credentials, elevation, evtx, fixture, native, present, report, summary
from windows_traige.common import Cancelled, Invalid


class Workflow(unittest.TestCase):
    def setUp(self):
        directory = Path(os.environ["WINDOWSTRAIGE_TEST_ROOT"])
        self.temp = tempfile.TemporaryDirectory(prefix="test-", dir=directory)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package = fixture.create(self.root)
        self.archive = self.package["archive"]
        self.checksum = self.package["checksum"]
        self.identity = self.package["sha256"]
        self.case = self.root / "Case with spaces"

    def open_case(self):
        return case.import_bundle(self.case, self.archive, self.checksum)

    def test_archived_evtx_provenance_and_deduplication(self):
        self.open_case()
        evidence = self.root / "Forwarded Events.evtx"
        raw = b"ElfFile\0" + b"\0" * 4088
        evidence.write_bytes(raw)
        checksum = evidence.with_suffix(".sha256")
        original_hash = hashlib.sha256(raw).hexdigest()
        checksum.write_text(original_hash, encoding="ascii")
        event = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
                 '<EventID>7045</EventID><Channel>System</Channel><Computer>{}</Computer>'
                 '<TimeCreated SystemTime="2026-01-01T00:00:00Z"/><EventRecordID>42</EventRecordID>'
                 '</System></Event>')
        logs = [event.format(host) for host in ("SourceOne", "SourceTwo")]
        with patch.object(evtx, "event_xml", side_effect=lambda *_: (xml for xml in logs)):
            imported = case.import_evidence(self.case, evidence, checksum)
            renamed = evidence.rename(self.root / "Renamed.EVTX")
            duplicate = case.import_evidence(self.case, renamed, checksum)
        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(duplicate["sha256"], imported["sha256"])
        self.assertEqual(imported["records"], 2)
        self.assertEqual(imported["verification"]["external"], "not supplied")
        origin = imported["source_evidence"]
        self.assertEqual((origin["sha256"], origin["external"]), (original_hash, "matched"))
        self.assertEqual(origin["start"], "2026-01-01T00:00:00.000000Z")
        archive = self.case / "bundles" / (imported["sha256"] + ".zip")
        with zipfile.ZipFile(archive) as z:
            self.assertEqual(z.read(evtx.ORIGINAL), raw)
        rows = case.query(self.case, archive=imported["sha256"])
        self.assertEqual({row["host"] for row in rows}, {"SourceOne", "SourceTwo"})
        self.assertEqual(case.native_event(self.case, imported["sha256"], "archived-2"), logs[1])
        self.assertEqual(summary.build(self.case)["archived_logs"], [origin])
        target = self.root / "archive-report.html"
        report.export(self.case, target)
        self.assertIn(original_hash, target.read_text(encoding="utf-8"))

    def test_archived_evtx_failed_validation_leaves_case_intact(self):
        self.open_case()
        file = self.root / "Invalid.evtx"
        file.write_bytes(b"broken" * 1024)
        checksum = file.with_suffix(".sha256")
        checksum.write_text("0" * 64, encoding="ascii")
        with self.assertRaisesRegex(Invalid, "header"):
            case.import_evidence(self.case, file)
        file.write_bytes(b"ElfFile\0" + b"\0" * 4088)
        with self.assertRaisesRegex(Invalid, "does not match"):
            case.import_evidence(self.case, file, checksum)
        with patch.object(evtx, "event_xml", side_effect=lambda *_: (xml for xml in ("<broken>",))):
            with self.assertRaisesRegex(Invalid, "unreadable"):
                case.import_evidence(self.case, file)
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(Cancelled):
            case.import_evidence(self.case, file, cancel=cancel)
        self.assertEqual(len(case.coverage(self.case)), 1)
        self.assertEqual(len(case.query(self.case)), 4)
        self.assertFalse(list(self.case.glob(".incomplete-*")))

    def test_integrity_and_changed_member(self):
        info = bundle.verify(self.archive, self.checksum)
        self.assertEqual((info["internal"], info["external"]), ("verified", "matched"))
        self.assertEqual(bundle.verify(self.archive)["external"], "not supplied")
        changed = self.root / "tampered.zip"
        with zipfile.ZipFile(self.archive) as source, zipfile.ZipFile(changed, "w") as target:
            for name in source.namelist():
                value = source.read(name)
                target.writestr(name, b"X" + value[1:] if name == "coverage.txt" else value)
        with self.assertRaisesRegex(Invalid, "Payload digest"):
            bundle.verify(changed)
        with self.assertRaisesRegex(Invalid, "External SHA"):
            bundle.verify(changed, self.checksum)

    def test_hostile_zip(self):
        for name in ("../escape.txt", "C:/escape.txt", "a\\b.txt", "/abs.txt", "cOn.txt"):
            with self.subTest(name=name):
                bad = self.root / "hostile.zip"
                with zipfile.ZipFile(bad, "w") as z:
                    z.writestr(name.replace("\\", "^"), "payload")
                if "\\" in name:
                    bad.write_bytes(bad.read_bytes().replace(b"^", b"\\"))
                with self.assertRaisesRegex(Invalid, "Unsafe"):
                    bundle.verify(bad)
        with zipfile.ZipFile(bad, "w") as z, warnings.catch_warnings():
            warnings.simplefilter("ignore")
            z.writestr("raw/a.txt", "one")
            z.writestr("raw/a.txt", "two")
        with self.assertRaisesRegex(Invalid, "Unsafe"):
            bundle.verify(bad)
        with zipfile.ZipFile(bad, "w") as z:
            item = zipfile.ZipInfo("raw/link.txt")
            item.create_system = 3
            item.external_attr = 0o120777 << 16
            z.writestr(item, "outside")
        with self.assertRaisesRegex(Invalid, "Unsafe"):
            bundle.verify(bad)
        with zipfile.ZipFile(bad, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
            z.writestr("raw/expansion.txt", b"A" * 4_000_000)
        with self.assertRaisesRegex(Invalid, "expansion"):
            bundle.verify(bad)
        bad.write_bytes(b"not a ZIP")
        with self.assertRaisesRegex(Invalid, "Invalid ZIP"):
            bundle.verify(bad)

    def test_invalid_schema_and_ambiguous_archive(self):
        invalid = self.root / "schema.zip"
        with zipfile.ZipFile(invalid, "w") as z:
            z.writestr("manifest.json", '{"schema":999}')
        with self.assertRaisesRegex(Invalid, "Unsupported evidence schema"):
            bundle.verify(invalid)
        with zipfile.ZipFile(invalid, "w") as z:
            z.writestr("MANIFEST.JSON", "")
            z.writestr("manifest.json", "")
        with self.assertRaisesRegex(Invalid, "Unsafe"):
            bundle.verify(invalid)

    def test_case_search_correlation_notes_duplicate_reports(self):
        result = self.open_case()
        self.assertEqual(result["records"], 4)
        event, = case.query(self.case, event_id=7045, channel="System", severity="Information")
        self.assertEqual((event["id"], event["fields"]["event_record_id"]), ("fixture-event", 42))
        self.assertEqual(case.query(self.case, event_id=7045, start="2025-05-01T13:00:01Z"), [])
        self.assertEqual(case.query(self.case, text="synthetic service")[0]["id"], "fixture-event")
        network, = case.query(self.case, ip="192.0.2.25", port=443)
        for row in (event, network):
            linked = case.correlate(self.case, row)
            self.assertEqual(linked["status"], "time-based")
            self.assertEqual([record["id"] for record in linked["records"]], ["fixture-process"])
        annotation = case.annotate(self.case, self.identity, "fixture-event", "finding", "<script>note</script>", "Operator")
        case.review(self.case, annotation, "Reviewer")
        case.save_filter(self.case, "System service", {"event_id": 7045})
        self.assertTrue(self.open_case()["duplicate"])
        self.assertEqual(case.saved_filters(self.case)["System service"], {"event_id": 7045})
        self.assertEqual(case.annotations(self.case)[0]["reviewed"], "Reviewer")
        self.assertEqual(len(case.query(self.case)), 4)
        target = self.root / "report.html"
        report.export(self.case, target, {"event_id": 7045})
        contents = target.read_text(encoding="utf-8")
        self.assertIn(self.identity + "/fixture-event", contents)
        self.assertIn("Synthetic absent channel", contents)
        self.assertIn("&lt;script&gt;note&lt;/script&gt;", contents)
        self.assertNotIn("<script>", contents)
        self.assertEqual(len(case.coverage(self.case)), 1)
        another = fixture.create(self.root)
        case.import_bundle(self.case, another["archive"])
        self.assertEqual(len(case.coverage(self.case)), 2)
        self.assertEqual(len(case.query(self.case, archive=self.identity)), 4)

    def test_cancellation_recovery_and_space(self):
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(Cancelled):
            case.import_bundle(self.case, self.archive, cancel=cancel)
        self.assertFalse(any(self.root.rglob(".incomplete-*")))
        self.assertEqual(self.open_case()["records"], 4)
        before = list(self.root.glob("*.zip"))
        with self.assertRaises(Cancelled):
            fixture.create(self.root, 10, cancel)
        self.assertEqual(list(self.root.glob("*.zip")), before)
        with patch("windows_traige.common.shutil.disk_usage", return_value=type("Disk", (), {"free": 0})()):
            with self.assertRaisesRegex(Invalid, "Insufficient"):
                self.open_case()

    def test_collection_fixture_permissions_and_bounds(self):
        scope = collect.plan("custom", self.root, collectors=("events-security", "events-sysmon"),
                             channels=("Application",), max_rows=1)

        def outcomes(channel, *_):
            if channel == "Security":
                raise native.NativeError("Access Denied", "Synthetic access denial")
            if "Sysmon" in channel:
                raise native.NativeError("Unavailable", "Synthetic absent channel")
            return [], ""

        with patch.object(native, "events", side_effect=outcomes):
            result = collect.run(scope)
        self.assertEqual([item["status"] for item in result["manifest"]["attempts"]],
                         ["Access Denied", "Unavailable", "Collected"])
        self.assertIn("No events", result["manifest"]["attempts"][2]["reason"])
        self.assertIn("TimeCreated", native.event_filter(scope.start, scope.end))
        with self.assertRaises(Invalid):
            collect.plan("custom", self.root, channels=("/clear",))
        with self.assertRaises(Invalid):
            collect.plan("standard", self.root, process_arguments=True)

    def test_event_window_excludes_outside(self):
        def xml(time):
            return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
                <EventID>42</EventID><EventRecordID>3</EventRecordID><TimeCreated SystemTime="{time}"/>
                </System></Event>"""
        raw = ("<Events>" + xml("2025-05-01T12:59:59Z") + xml("2025-05-01T13:00:00Z") + "</Events>").encode()
        rows, outside = native.event_records(raw, "System", "2025-05-01T13:00:00.000000Z", "2025-05-01T13:01:00.000000Z")
        self.assertEqual((len(rows), outside, rows[0][1]["event_record_id"]), (1, 1, 3))

    def test_elevated_catalog_deny_and_retry_ledger(self):
        scope = collect.plan("custom", self.root, collectors=("events-security", "events-system"))

        def outcomes(channel, *_):
            if channel == "Security":
                raise native.NativeError("Access Denied", "Fixture denial")
            return [], ""

        with patch.object(native, "events", side_effect=outcomes):
            result = collect.run(scope)
        with patch.object(elevation, "exchange", return_value=([], "UAC declined")) as exchange:
            updated = elevation.retry(result["archive"], self.root)
        self.assertEqual(exchange.call_args.args[0]["collectors"], ["events-security"])
        self.assertEqual(updated["manifest"]["prior_archive"], result["sha256"])
        self.assertEqual(updated["manifest"]["attempts"][-1]["reason"], "UAC declined")
        self.assertTrue(Path(result["archive"]).is_file())
        invalid = dict(exchange.call_args.args[0], collectors=["files"])
        with self.assertRaisesRegex(Invalid, "outside the collector catalog"):
            elevation.parse_request(invalid)

    def test_assistant_off_disclosure_and_adapter_contracts(self):
        self.open_case()
        reference = self.identity + "/fixture-event"
        approved = assistant.preview(self.case, [reference])
        self.assertNotIn("script", str(approved))
        for provider in assistant.HOSTS:
            with self.subTest(provider=provider):
                calls = []

                def stub(host, path, headers, body, cancel):
                    calls.append((host, path, headers, body))
                    if body is None:
                        if provider == "gemini":
                            return {"models": [{"name": "models/demo", "supportedGenerationMethods": ["generateContent"]}]}
                        if provider == "anthropic" and "after_id" not in path:
                            return {"data": [{"id": "first"}], "has_more": True, "last_id": "first"}
                        return {"data": [{"id": "demo"}]}
                    model_text = f"Observed the record [{reference}]."
                    data = json.loads(body)
                    args = {"reference": reference}
                    if provider == "openai":
                        if len(data["input"]) == 1 and "tools" in data:
                            return {"output": [{"type": "function_call", "call_id": "one", "name": assistant.TOOL_NAME,
                                                "arguments": json.dumps(args)}]}
                        return {"output": [{"type": "message", "content": [{"text": model_text}]}]}
                    if provider == "anthropic":
                        if len(data["messages"]) == 1 and "tools" in data:
                            return {"content": [{"type": "tool_use", "id": "one", "name": assistant.TOOL_NAME, "input": args}]}
                        return {"content": [{"type": "text", "text": model_text}]}
                    if len(data["contents"]) == 1 and "tools" in data:
                        return {"candidates": [{"content": {"role": "model", "parts": [
                            {"functionCall": {"name": assistant.TOOL_NAME, "args": args}}]}}]}
                    return {"candidates": [{"content": {"parts": [{"text": model_text}]}}]}

                session = assistant.Session(provider, "demo", "fake-key", request=stub, enabled=False)
                with self.assertRaisesRegex(Invalid, "disabled"):
                    session.discover()
                self.assertEqual(calls, [])
                session.enabled = True
                self.assertIn("demo", {model["id"] for model in session.discover()})
                result = session.ask(self.case, "What was observed?", approved, tools=True)
                self.assertEqual(result["citation_status"], "resolved")
                self.assertEqual(result["citations"], [reference])
                self.assertTrue(all(item[0] == assistant.HOSTS[provider] for item in calls))
                self.assertTrue(all(b"<script>" not in (item[3] or b"") for item in calls))
                result = session.ask(self.case, "What was observed?", approved)
                self.assertEqual(result["citation_status"], "resolved")
                session.disconnect()
                self.assertEqual(session.key, "")
        with case.connect(self.case) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM actions WHERE action='assistant-tool'").fetchone()[0], 3)

    def test_assistant_replay_denial_cancel_and_bad_model(self):
        self.open_case()
        reference = self.identity + "/fixture-event"
        approved = assistant.preview(self.case, [reference])
        staged = []

        def stub(host, path, headers, body, cancel):
            payload = json.loads(body)
            staged.append(payload)
            if len(staged) > 1:
                return {"output": [{"type": "message", "content": [
                    {"text": f"Hypothesis [{self.identity}/invented]"}]}]}
            return {"output": [
                {"type": "function_call", "call_id": str(i), "name": name,
                 "arguments": json.dumps({"reference": reference})}
                for i, name in enumerate((assistant.TOOL_NAME, assistant.TOOL_NAME, "run_command"))
            ]}

        session = assistant.Session("openai", "demo", "fake-key", request=stub)
        result = session.ask(self.case, "Summarize evidence", approved, tools=True)
        self.assertEqual(result["citation_status"], "unresolved")
        self.assertIn("Duplicate action", str(staged[1]))
        self.assertIn("Action outside approved scope", str(staged[1]))
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(Cancelled):
            session.discover(cancel)
        with self.assertRaisesRegex(Invalid, "exact model"):
            assistant.Session("gemini", "models/../bad", "fake-key")
        for status in (401, 404, 429):
            with patch.object(session, "request", side_effect=assistant.ProviderError(status)):
                with self.assertRaises(assistant.ProviderError):
                    session.discover()

    def test_assistant_proposal_scope_and_single_use(self):
        self.open_case()
        reference = self.identity + "/fixture-event"
        approved = assistant.preview(self.case, [reference])
        allowed = {item["reference"]: item for item in approved}
        session = assistant.Session("openai", "demo", "fake-key")
        request = {"operation": "finding", "reference": reference, "text": "Review this event"}
        result, _ = session.action(self.case, assistant.PROPOSAL, request, allowed)
        token = result["proposal"]
        self.assertEqual(case.annotations(self.case), [])
        with self.assertRaisesRegex(Invalid, "outside"):
            session.consume(token, self.root / "other")
        result, _ = session.action(self.case, assistant.PROPOSAL, request, allowed)
        token = result["proposal"]
        self.assertEqual(session.consume(token, self.case)["reference"], reference)
        with self.assertRaisesRegex(Invalid, "expired"):
            session.consume(token, self.case)
        self.assertEqual(session.action(self.case, assistant.PROPOSAL, dict(request, reference="unknown"), allowed),
                         (None, None))
        self.assertEqual(session.action(self.case, assistant.PROPOSAL,
                                        {"operation": "collect", "reference": "", "text": "C:/Windows"}, allowed),
                         (None, None))
        self.assertNotEqual(assistant.approval_digest("openai", "demo", "q", approved, False),
                            assistant.approval_digest("openai", "demo", "q", approved, True))

    def test_plain_and_raw_evidence_and_summary(self):
        self.open_case()
        row, = case.query(self.case, event_id=7045)
        display = {"record": row, "process_links": case.correlate(self.case, row)}
        pretty = present.format_view("record", display)
        self.assertIn("A service was installed", pretty)
        self.assertIn("Windows event record number: 42", pretty)
        self.assertIn("fixture-process", pretty)
        self.assertEqual(json.loads(present.format_view("record", display, True)), display)
        overview = summary.build(self.case)
        self.assertEqual(overview["records"], {"event": 1, "network": 1, "process": 2})
        self.assertEqual([item["status"] for item in overview["gaps"]], ["Unavailable", "Access Denied"])
        self.assertEqual(overview["highlights"][0]["ref"], "fixture-event")
        explanation = summary.text(overview)
        self.assertIn("What to do next", explanation)
        self.assertIn(self.identity + "/fixture-event", explanation)
        target = self.root / "summary.txt"
        summary.export(overview, target)
        with self.assertRaises(FileExistsError):
            summary.export(overview, target)

    def test_model_presets_and_chat_context_without_case(self):
        calls = []

        def stub(host, path, headers, body, cancel):
            calls.append((path, json.loads(body)))
            return {"candidates": [{"content": {"parts": [{"text": "A helpful answer"}]}}]}

        model = assistant.PRESETS["gemini"][0][1]
        session = assistant.Session("gemini", model, "fake-key", request=stub)
        history = [{"speaker": "You", "text": "Explain an EVTX file"}]
        result = session.ask(None, "How do I open one?", [], history=history)
        self.assertEqual(result["text"], "A helpful answer")
        self.assertIn(model, calls[0][0])
        self.assertEqual(calls[0][1]["contents"][0], {"role": "user", "parts": [{"text": history[0]["text"]}]})
        self.assertEqual(calls[0][1]["contents"][-1]["parts"][0]["text"], "How do I open one?")
        with self.assertRaisesRegex(Invalid, "Open a case"):
            session.ask(None, "Search", [], tools=True)
        keyfile = self.root / "synthetic-key.txt"
        keyfile.write_text("GEMINI_API_KEY='sample-key-value'", encoding="utf-8")
        self.assertEqual(credentials.from_file("gemini", keyfile), "sample-key-value")

    def test_forensic_catalog_extended_operational_channels(self):
        capture = collect.plan("extended", self.root)
        self.assertTrue(set(collect.EXTENDED_EVENTS) <= set(capture.collectors))
        self.assertFalse(set(collect.EXTENDED_EVENTS) & set(collect.plan("standard", self.root).collectors))
        self.assertTrue({"firewall-profiles", "hotfixes"} <= set(capture.collectors))
        with patch.object(native, "command", return_value=b"\xff\xfeApplication\r\nSystem\r\n"):
            self.assertEqual(native.channels(), ["Application", "System"])


if __name__ == "__main__":
    unittest.main()
