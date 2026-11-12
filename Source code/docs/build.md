# Building Windows Traige locally

Use Windows x64, PowerShell 7, and CPython 3.12.14 AMD64 with pip and venv. The script checks the Python version and machine architecture. The approved package was built with the preinstalled Codex runtime. A separate clean-source build with the public standalone Windows x64 distribution passed the packaged smoke and source tests. [Astral Python Build Standalone release](https://github.com/astral-sh/python-build-standalone/releases/tag/20260924)

If you need Python, extract the public `cpython-3.12.14+20260924-x86_64-pc-windows-msvc-install_only_stripped.tar.gz` archive and point `$Python` at the extracted `python\python.exe`. The archive's published SHA-256 is `C5BF8EDFE858C1DF9891BE498B5BBC8761D383DF5B9790658B088FEA4870433A`. [Official asset list](https://github.com/astral-sh/python-build-standalone/releases/expanded_assets/20260924)

From the repository's **Source code** folder, populate the local wheel cache. Set TEMP and TMP to a folder inside the checkout. The lock pins PySide6 Essentials 6.10.2, Shiboken 6.10.2, PyInstaller 6.22.3, and their dependencies. Pip checks wheel hashes against the lock.

```powershell
$Python = (Resolve-Path -LiteralPath (Read-Host 'Full path to Python 3.12.14 x64 python.exe')).Path
& $Python -B -c "import platform,sys; print(sys.platform, platform.machine(), platform.python_version())"
New-Item -ItemType Directory -Force environment/wheels,environment/tmp | Out-Null
$env:TEMP = (Resolve-Path environment/tmp).Path
$env:TMP = $env:TEMP
& $Python -B -m pip --isolated download --index-url https://pypi.org/simple --no-cache-dir --only-binary=:all: --require-hashes --dest environment/wheels -r packaging/requirements-win-x64.lock
& .\scripts\Build.ps1 -Python $Python -BuildId local-v2-001 -Fresh
& .\scripts\Verify.ps1 -BuildId local-v2-001 -RunId local-v2-smoke
```

Use a new build ID for each run. The build uses the local wheel cache without contacting PyPI. The output under artifacts/builds contains the portable archive, detached SHA-256, executable hashes and Authenticode status, and a sorted source file hash manifest. Compare the manifest hash for source identity. PyInstaller archives embed source paths and Windows metadata. ZIP entry timestamps reflect build time. Matching source inputs and dependencies are reproducible instructions. Byte-for-byte outputs require control of these additional inputs.

The build preserves the selected Python runtime's public TLS distrust policy when that interpreter requires it. The assistant validates the provider certificate and hostname against the operating system's trust configuration. The build script sets a fixed executable timestamp for reproducibility.

Extract the complete ZIP to a path with spaces. Launch WindowsTraige.exe or run WindowsTraige.Cli.exe --version. Each runtime directory must stay alongside the executables. Use the test procedure and actual result ledger before approving a release.

The app icon is checked in under `src/windows_traige/assets` and used by the Windows executable resources and Qt window. `scripts/app_icon.py` reproduces it with Pillow. For acceptance runs, set `WINDOWSTRAIGE_SETTINGS` to an INI path in your test output folder.

## Focused checks

```powershell
$env:PYTHONPATH = (Resolve-Path src).Path
$env:WINDOWSTRAIGE_TEST_ROOT = (New-Item -ItemType Directory -Force artifacts/qa/fixtures).FullName
& .\environment\build-local-v2-001\Scripts\python.exe -B -m unittest discover -s tests -v
```

Synthetic benchmarks use `tests/benchmark.py` with an existing test output folder. Generate a synthetic case using the packaged CLI `fixture` command. Keep private host collections, scratch data and credentials outside publication material.
