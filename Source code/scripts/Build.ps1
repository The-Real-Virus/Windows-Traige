[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Python,
    [string]$BuildId = ('win-x64-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')),
    [switch]$Fresh
)
$ErrorActionPreference = 'Stop'
if ($BuildId -notmatch '^[a-z0-9][a-z0-9-]{2,63}$') { throw 'Invalid build ID' }
$root = Split-Path -Parent $PSScriptRoot
$envRoot = Join-Path $root 'environment'
$stage = Join-Path $root "artifacts/builds/$BuildId"
if (Test-Path -LiteralPath $stage) { throw 'Build output already exists' }
New-Item -ItemType Directory -Path $stage | Out-Null
$env:TEMP = (New-Item -ItemType Directory -Force -Path (Join-Path $stage 'tmp')).FullName
$env:TMP = $env:TEMP
$env:PYINSTALLER_CONFIG_DIR = (Join-Path $stage 'pyinstaller-cache')
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:PIP_DISABLE_PIP_VERSION_CHECK = '1'
$env:PIP_CONFIG_FILE = 'NUL'
$env:SOURCE_DATE_EPOCH = ([DateTimeOffset]::Parse('2026-11-11T00:00:00Z')).ToUnixTimeSeconds().ToString()
$env:PYTHONPATH = $null
$env:PYTHONHOME = $null
$identity = & $Python -B -c "import platform,sys; print(sys.platform, platform.machine(), platform.python_version())"
if ($LASTEXITCODE -ne 0 -or $identity -ne 'win32 AMD64 3.12.14') {
    throw 'Windows x64 CPython 3.12.14 is required'
}
$venv = Join-Path $envRoot ('build-' + $BuildId)
if ($Fresh -or !(Test-Path -LiteralPath (Join-Path $envRoot 'build/Scripts/python.exe'))) {
    & $Python -B -m venv $venv
    if ($LASTEXITCODE) { throw 'Virtual environment creation failed' }
} else {
    $venv = Join-Path $envRoot 'build'
}
$venvPython = Join-Path $venv 'Scripts/python.exe'
$pythonBase = (& $venvPython -B -c "import sys; print(sys.base_prefix)").Trim()
$system = [Environment]::SystemDirectory
$env:PATH = @((Join-Path $venv 'Scripts'), (Join-Path $pythonBase 'DLLs'), $pythonBase, $system, (Split-Path -Parent $system)) -join ';'
$lock = Join-Path $root 'packaging/requirements-win-x64.lock'
$wheels = Join-Path $envRoot 'wheels'
& $venvPython -B -m pip --isolated install --no-index --find-links $wheels --no-cache-dir --only-binary=:all: --require-hashes -r $lock
if ($LASTEXITCODE) { throw 'Locked dependency installation failed' }
& $venvPython -B -m pip check
if ($LASTEXITCODE) { throw 'Dependency consistency check failed' }
& $venvPython -B -m PyInstaller --noconfirm --clean --distpath (Join-Path $stage 'dist') --workpath (Join-Path $stage 'work') (Join-Path $root 'packaging/windows-traige.spec')
if ($LASTEXITCODE) { throw 'PyInstaller failed' }

$release = Join-Path $stage 'WindowsTraige-v2.0-win-x64'
$gui = Join-Path $stage 'dist/WindowsTraige'
$cli = Join-Path $stage 'dist/WindowsTraige.Cli'
New-Item -ItemType Directory -Path $release | Out-Null
Copy-Item -LiteralPath (Join-Path $gui 'WindowsTraige.exe'),(Join-Path $gui '_internal'),
    (Join-Path $cli 'WindowsTraige.Cli.exe'),(Join-Path $cli '_cli_runtime') -Destination $release -Recurse
Copy-Item -LiteralPath (Join-Path $root 'docs/release-notes.md'),(Join-Path $root 'docs/third-party.md') -Destination $release
$notices = (New-Item -ItemType Directory -Path (Join-Path $release 'licenses')).FullName
$sitePackages = Join-Path $venv 'Lib/site-packages'
Get-ChildItem -LiteralPath $sitePackages -Directory -Filter '*.dist-info' | ForEach-Object {
    $distribution = $_
    $files = Get-ChildItem -LiteralPath $distribution.FullName -File -Recurse | Where-Object Name -Match '^(LICENSE|COPYING|NOTICE)'
    foreach ($file in $files) {
        $subpath = [IO.Path]::GetRelativePath($distribution.FullName, $file.FullName)
        $target = Join-Path (Join-Path $notices $distribution.Name) $subpath
        New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $target
    }
}
if (Test-Path -LiteralPath (Join-Path $pythonBase 'LICENSE.txt')) {
    Copy-Item -LiteralPath (Join-Path $pythonBase 'LICENSE.txt') -Destination (Join-Path $notices 'CPython-LICENSE.txt')
}
$bins = Get-ChildItem -LiteralPath $release -File -Filter '*.exe'
$bins | ForEach-Object {
    [PSCustomObject]@{ Name=$_.Name; SHA256=(Get-FileHash -LiteralPath $_.FullName).Hash; Authenticode=[string](Get-AuthenticodeSignature -LiteralPath $_.FullName).Status }
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stage 'executables.json') -Encoding utf8
$checksums = Get-ChildItem -LiteralPath $release -File -Recurse | Sort-Object FullName | ForEach-Object {
    $relative = [IO.Path]::GetRelativePath($release, $_.FullName).Replace('\','/')
    "$((Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant())  $relative"
}
$checksums | Set-Content -LiteralPath (Join-Path $release 'SHA256SUMS.txt') -Encoding ascii
$zip = $release + '.zip'
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($release, $zip, [IO.Compression.CompressionLevel]::Optimal, $true)
"$((Get-FileHash -LiteralPath $zip).Hash.ToLowerInvariant())  $([IO.Path]::GetFileName($zip))" | Set-Content -LiteralPath ($zip + '.sha256') -Encoding ascii
$sourceFiles = Get-ChildItem -LiteralPath (Join-Path $root 'src'),(Join-Path $root 'packaging'),(Join-Path $root 'scripts'),(Join-Path $root 'fixtures'),(Join-Path $root 'tests') -Recurse -File |
    Where-Object { $_.FullName -notmatch '[\\/]__pycache__[\\/]' } | Sort-Object FullName
$sourceFiles | ForEach-Object {
    "$((Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant())  $([IO.Path]::GetRelativePath($root, $_.FullName).Replace('\','/'))"
} | Set-Content -LiteralPath (Join-Path $stage 'source-files.sha256') -Encoding ascii
Get-FileHash -LiteralPath (Join-Path $stage 'source-files.sha256') | Format-List
Get-FileHash -LiteralPath $zip | Format-List
