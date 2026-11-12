"""Verify original bytes, supplemental formats and the ZIP64 case workflow."""

import hashlib
import json
import os
import struct
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from windows_traige import bundle, case, collect, fixture, netcapture, summary, supplemental
from windows_traige.common import Cancelled, Invalid

TIMESTAMP = "2026-10-12T13:00:00Z"
FRAME = bytes.fromhex(
    "0000000000000000000000000800"
    "4500001c0000000040110000c0000201c6336402"
    "c00001bb00080000"
)


def pcap(packet=FRAME):
    return (struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
            + struct.pack("<IIII", 1_700_000_000, 123456, len(packet), len(packet)) + packet)


def pcapng():
    def block(kind, body, endian):
        length = len(body) + 12
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    def section(endian, frame):
        ticks = 1_700_000_000 * 1_000_000 + 123456
        return (
            block(0x0a0d0d0a, struct.pack(endian + "IHHq", 0x1a2b3c4d, 1, 0, -1), endian)
            + block(1, struct.pack(endian + "HHI", 1, 0, 65535), endian)
            + block(6, struct.pack(endian + "IIIII", 0, ticks >> 32, ticks & 0xffffffff, len(frame), len(frame))
                    + frame + b"\0" * (-len(frame) % 4), endian)
        )
    return section("<", FRAME) + section(">", FRAME)


class Supplemental(unittest.TestCase):
    def setUp(self):
        folder = Path(os.environ["WINDOWSTRAIGE_TEST_ROOT"])
        temp = tempfile.TemporaryDirectory(prefix="v2-", dir=folder)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def selected(self, kind, filename, data, **details):
        path = self.root / filename
        path.write_bytes(data)
        return supplemental.Selection(kind, str(path), **details)

    def test_five_types_in_one_archive_and_timeline(self):
        inputs = (
            self.selected("disk-image", "disk.img", b"Synthetic raw disk".ljust(2048, b"\0"), captured=TIMESTAMP),
            self.selected("memory-capture", "memory.raw", b"synthetic memory", tool="Fixture v1"),
            self.selected("endpoint-telemetry", "endpoint.csv",
                          f"Timestamp,DeviceId,DeviceName,ActionType,ReportId\n{TIMESTAMP},D1,ExamplePC,FileCreated,7\n".encode()),
            self.selected("identity-activity", "identity.json", json.dumps([{
                "id": "synthetic-sign-in", "createdDateTime": TIMESTAMP, "userPrincipalName": "test@example.invalid",
                "ipAddress": "192.0.2.7", "status": {"errorCode": 0}
            }]).encode()),
            self.selected("network-evidence", "network.pcapng", pcapng(), source="Example sensor"),
        )
        expected = {entry.kind: Path(entry.path).read_bytes() for entry in inputs}
        checksum = self.root / "trusted.sha256"
        checksum.write_text(hashlib.sha256(expected["disk-image"]).hexdigest(), encoding="ascii")
        inputs = (supplemental.Selection("disk-image", inputs[0].path, str(checksum), captured=TIMESTAMP), *inputs[1:])
        scope = collect.plan("custom", self.root, evidence=inputs)
        result = collect.run(scope)
        self.assertEqual(result["manifest"]["schema"], 2)
        origins = {entry["kind"]: entry for entry in result["manifest"]["attachments"]}
        self.assertEqual(set(origins), set(expected))
        self.assertEqual(origins["disk-image"]["external"], "matched")
        with zipfile.ZipFile(result["archive"]) as archive:
            for kind, original in expected.items():
                member = origins[kind]["payload"]
                self.assertEqual(archive.getinfo(member).compress_type, zipfile.ZIP_STORED)
                self.assertEqual(archive.read(member), original)
                self.assertEqual(result["manifest"]["payloads"][member]["sha256"], hashlib.sha256(original).hexdigest())
        folder = self.root / "Case"
        indexed = case.import_evidence(folder, result["archive"], result["checksum"])
        self.assertEqual(indexed["records"], 6)
        query = case.query(folder, kind="network", ip="198.51.100.2", port=443)
        self.assertEqual(len(query), 2)
        self.assertEqual(query[0]["observed"], "2023-11-14T22:13:20.123456Z")
        device = case.query(folder, channel="Microsoft Defender XDR DeviceEvents")[0]
        self.assertEqual((device["host"], device["fields"]["external_id"]), ("ExamplePC", "7"))
        sign_in = case.query(folder, channel="Microsoft Entra sign-ins")[0]
        self.assertEqual(sign_in["fields"]["error_code"], 0)
        self.assertEqual(sign_in["host"], "Source not recorded")
        overview = summary.build(folder)
        self.assertEqual(len(overview["supplemental"]), 5)
        self.assertEqual(overview["hosts"], 2)
        copy = self.root / "working.img"
        case.export_original(folder, indexed["sha256"], "disk-image-original", copy)
        self.assertEqual(copy.read_bytes(), expected["disk-image"])
        self.assertTrue(case.import_evidence(folder, result["archive"])["duplicate"])
        copy_again = collect.run(scope)
        self.assertEqual(case.import_evidence(folder, copy_again["archive"])["records"], 0)
        self.assertEqual(len(case.query(folder)), 6)
        self.assertEqual({entry.kind: Path(entry.path).read_bytes() for entry in inputs}, expected)

    def test_missing_corrupt_and_checksum_mismatch_are_visible(self):
        bad = self.selected("network-evidence", "broken.pcap", pcap()[:-1])
        memory = self.selected("memory-capture", "intact.raw", b"intact original")
        wrong = self.root / "wrong.sha256"
        wrong.write_text("0" * 64, encoding="ascii")
        memory = supplemental.Selection(memory.kind, memory.path, str(wrong))
        scope = collect.plan("custom", self.root, evidence=(bad, memory, supplemental.Selection("identity-activity")))
        result = collect.run(scope)
        outcomes = {row["collector"]: row for row in result["manifest"]["attempts"]}
        self.assertEqual(outcomes["network-evidence"]["status"], "Failed")
        self.assertIn("inside a record", outcomes["network-evidence"]["reason"])
        self.assertEqual(outcomes["memory-capture"]["status"], "Failed")
        self.assertIn("does not match", outcomes["memory-capture"]["reason"])
        self.assertEqual(outcomes["identity-activity"]["status"], "Unavailable")
        self.assertFalse(result["manifest"]["attachments"])
        self.assertEqual(Path(memory.path).read_bytes(), b"intact original")

    def test_zip64_directory_and_legacy_archive_compatibility(self):
        with patch.object(bundle, "SCHEMA", bundle.LEGACY_SCHEMA):
            legacy = fixture.create(self.root)
        indexed = case.import_evidence(self.root / "Legacy Case", legacy["archive"], legacy["checksum"])
        self.assertEqual(indexed["records"], 4)
        selection = self.selected("disk-image", "test.dd", b"x" * 2048)
        with patch.object(zipfile, "ZIP64_LIMIT", 1024):
            result = collect.run(collect.plan("custom", self.root, evidence=(selection,)))
        target = Path(result["archive"])
        data = target.read_bytes()
        self.assertIn(b"PK\x06\x06", data)
        self.assertEqual(bundle.verify(target, result["checksum"])["sha256"], result["sha256"])
        damaged = self.root / "broken-zip64.zip"
        at = data.index(b"PK\x06\x07")
        damaged.write_bytes(data[:at + 4] + b"\x01" + data[at + 5:])
        with self.assertRaisesRegex(Invalid, "ZIP64 directory"):
            bundle.verify(damaged)

    def test_guided_offline_receipt_keeps_operator_claims_and_read_errors(self):
        path = self.root / "offline.dd"
        path.write_bytes(b"\0" * 2048)
        checksum = self.root / "verified.sha256"
        checksum.write_text(hashlib.sha256(path.read_bytes()).hexdigest(), encoding="ascii")
        confirmed = supplemental.OfflineReceipt("Test source disk", "Different output", "Test blocker",
                                                512, 2048, 1, True)
        details = dict(kind="disk-image", path=str(path), checksum=str(checksum), tool="Example tool v1",
                       operator="Synthetic operator", captured=TIMESTAMP)
        item = supplemental.Selection(**details, offline=confirmed)
        result = collect.run(collect.plan("custom", self.root, evidence=(item,)))
        self.assertEqual(result["manifest"]["attachments"][0]["offline"]["source_device"], "Test source disk")
        self.assertEqual(result["manifest"]["attempts"][0]["status"], "Partial")
        self.assertIn("operator reported", result["manifest"]["attempts"][0]["reason"])
        same_disk = supplemental.OfflineReceipt("TEST SOURCE DISK", "test source disk", "Test blocker",
                                                 512, 2048, 0, True)
        with self.assertRaisesRegex(Invalid, "different devices"):
            collect.plan("custom", self.root, evidence=(supplemental.Selection(**details, offline=same_disk),))

    def test_cancellation_and_unsupported_network_metadata(self):
        packet = FRAME[:12] + b"\x08\x06" + FRAME[14:]
        selection = self.selected("network-evidence", "arp.pcap", pcap(packet))
        scope = collect.plan("custom", self.root, evidence=(selection,))
        token = threading.Event()
        token.set()
        with self.assertRaises(Cancelled):
            collect.run(scope, token)
        self.assertFalse(list(self.root.glob("*.zip")))
        self.assertFalse(list(self.root.glob(".incomplete-*")))
        result = collect.run(scope)
        self.assertEqual(result["manifest"]["attempts"][0]["status"], "Partial")
        self.assertIn("outside", result["manifest"]["attempts"][0]["reason"])
        self.assertEqual(len(list(netcapture.packets(Path(selection.path)))), 1)
