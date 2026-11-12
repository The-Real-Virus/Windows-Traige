# Native Windows x64, two onedir entry points with independent runtimes.
from pathlib import Path
import sys

packaging = Path(SPECPATH)
src = str(packaging.parent / "src")
icon = str(Path(src) / "windows_traige/assets/windows-traige.ico")
trust_policy = Path(sys.base_prefix) / "Lib/codex-rejected-cas.pem"
ssl_module = Path(sys.base_prefix) / "Lib/ssl.py"
needs_policy = ssl_module.is_file() and trust_policy.name in ssl_module.read_text(encoding="utf-8")
if needs_policy and not trust_policy.is_file():
    raise RuntimeError("The Python runtime is missing its required public TLS distrust policy")

def app(script, name, console, runtime):
    datas = [] if console else [(icon, "windows_traige/assets")]
    if needs_policy:
        datas.append((str(trust_policy), "."))
    analysis = Analysis([str(packaging / script)], pathex=[src], binaries=[], datas=datas,
                        hiddenimports=[], hookspath=[], runtime_hooks=[], excludes=[], noarchive=False)
    # Qt uses the Windows ICU ABI, provided by System32 on supported hosts.
    # A third-party DLL with the same name can expose an incompatible ICU ABI.
    analysis.binaries = [entry for entry in analysis.binaries
                         if Path(entry[0]).name.lower() not in {"icu.dll", "icuuc.dll", "icuin.dll"}]
    code = PYZ(analysis.pure)
    executable = EXE(code, analysis.scripts, [], exclude_binaries=True, name=name,
                     debug=False, bootloader_ignore_signals=False, strip=False, upx=False,
                     console=console, disable_windowed_traceback=True, contents_directory=runtime, icon=icon)
    return COLLECT(executable, analysis.binaries, analysis.datas, strip=False, upx=False, name=name)

gui = app("gui_entry.py", "WindowsTraige", False, "_internal")
cli = app("cli_entry.py", "WindowsTraige.Cli", True, "_cli_runtime")
