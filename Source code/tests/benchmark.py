"""Measure a native synthetic archive import and repeated indexed searches."""

import ctypes
import json
import sys
import tempfile
from ctypes import wintypes
from pathlib import Path
from time import perf_counter

from windows_traige import case, fixture


class Memory(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
        (field, ctypes.c_size_t) for field in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
        "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")
    ]


def peak():
    process = ctypes.windll.kernel32.GetCurrentProcess
    process.restype = wintypes.HANDLE
    usage = ctypes.windll.psapi.GetProcessMemoryInfo
    usage.argtypes = (wintypes.HANDLE, ctypes.POINTER(Memory), wintypes.DWORD)
    memory = Memory()
    if not usage(process(), ctypes.byref(memory), ctypes.sizeof(memory)):
        raise OSError("Windows process memory metrics unavailable")
    return memory.PeakWorkingSetSize


def main(root):
    with tempfile.TemporaryDirectory(prefix="benchmark-", dir=root) as tmp:
        directory = Path(tmp)
        generated = fixture.create(directory, 100000)
        before = peak()
        start = perf_counter()
        result = case.import_bundle(directory / "Case", generated["archive"], generated["checksum"])
        import_elapsed = perf_counter() - start
        imported_peak = peak()
        timings = []
        for i in range(50):
            start = perf_counter()
            rows = case.query(directory / "Case", event_id=1000 + i)
            timings.append((perf_counter() - start) * 1000)
            assert len(rows) == 100
        print(json.dumps({
            "records": result["records"], "bundle_bytes": Path(generated["archive"]).stat().st_size,
            "import_seconds": round(import_elapsed, 3), "peak_working_set_bytes_before_import": before,
            "peak_working_set_bytes_after_import": imported_peak,
            "search_median_ms": round(sorted(timings)[len(timings) // 2], 3),
            "search_max_ms": round(max(timings), 3), "searches": len(timings),
        }, indent=2))


if __name__ == "__main__":
    main(sys.argv[1])
