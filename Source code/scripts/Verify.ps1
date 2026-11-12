[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BuildId,
    [Parameter(Mandatory)][string]$RunId
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
foreach ($identifier in $BuildId,$RunId) {
    if ($identifier -notmatch '^[a-z0-9][a-z0-9-]{2,63}$') { throw 'Invalid build or test ID' }
}
$root = Split-Path -Parent $PSScriptRoot
$build = Join-Path $root "artifacts/builds/$BuildId"
$zip = Join-Path $build 'WindowsTraige-v2.0-win-x64.zip'
$detached = (Get-Content -Raw -LiteralPath ($zip + '.sha256')).Split(' ')[0]
if ((Get-FileHash -LiteralPath $zip).Hash -ne $detached) { throw 'Release SHA-256 mismatch' }
$qa = Join-Path $root "artifacts/qa/$RunId"
if (Test-Path -LiteralPath $qa) { throw 'Test destination already exists' }
New-Item -ItemType Directory -Path $qa | Out-Null
$env:TEMP = (New-Item -ItemType Directory -Path (Join-Path $qa 'tmp')).FullName
$env:TMP = $env:TEMP
$env:PYTHONPATH = $null
$env:VIRTUAL_ENV = $null
$extracted = Join-Path $qa 'Portable Extraction With Spaces'
Expand-Archive -LiteralPath $zip -DestinationPath $extracted
$distribution = Join-Path $extracted 'WindowsTraige-v2.0-win-x64'
foreach ($line in Get-Content -LiteralPath (Join-Path $distribution 'SHA256SUMS.txt')) {
    $digest, $name = $line -split '  ', 2
    if ((Get-FileHash -LiteralPath (Join-Path $distribution $name)).Hash -ne $digest) {
        throw "Extracted file hash mismatch: $name"
    }
}
$cli = Join-Path $distribution 'WindowsTraige.Cli.exe'
$gui = Join-Path $distribution 'WindowsTraige.exe'
$steps = [System.Collections.Generic.List[object]]::new()
function Invoke-Cli([string[]]$Arguments, [int]$Expected = 0) {
    $output = & $cli @Arguments
    if ($LASTEXITCODE -ne $Expected) {
        throw "Unexpected CLI exit $LASTEXITCODE for $($Arguments[0]) (expected $Expected)"
    }
    $steps.Add([pscustomobject]@{Command=$Arguments[0];Exit=$LASTEXITCODE})
    return ($output | Out-String)
}
$version = (Invoke-Cli @('--version')).Trim()
if ($version -ne 'Windows Traige v2.0') { throw 'Version mismatch' }
$help = Invoke-Cli @('--help')
if ($help -notmatch 'collect' -or $help -notmatch 'verify' -or $help -notmatch 'report') { throw 'CLI help mismatch' }
$plan = Invoke-Cli @('collect','--profile','standard','--out',$qa,'--plan') | ConvertFrom-Json
if ($plan.profile -ne 'standard') { throw 'Plan preview failed' }
$evidence = Invoke-Cli @('fixture','--out',$qa) | ConvertFrom-Json
$checked = Invoke-Cli @('verify',$evidence.archive,'--checksum',$evidence.checksum) | ConvertFrom-Json
if ($checked.internal -ne 'verified' -or $checked.external -ne 'matched') { throw 'Verification failed' }
$bad = Join-Path $qa 'invalid.zip'
[IO.File]::WriteAllText($bad,'synthetic invalid ZIP')
$null = Invoke-Cli @('verify',$bad) 3
$case = Join-Path $qa 'Synthetic CLI Case'
$import = Invoke-Cli @('import',$evidence.archive,'--case',$case,'--checksum',$evidence.checksum) | ConvertFrom-Json
if ($import.records -ne 4) { throw 'Fixture record count mismatch' }
$null = Invoke-Cli @('annotate',$case,'--archive',$evidence.sha256,'--record','fixture-event','--text','Verified synthetic fixture')
$duplicate = Invoke-Cli @('import',$evidence.archive,'--case',$case) | ConvertFrom-Json
if (!$duplicate.duplicate) { throw 'Duplicate import was not detected' }
$query = Invoke-Cli @('query',$case,'--event-id','7045','--json') | ConvertFrom-Json
if ($query.id -ne 'fixture-event' -or $query.fields.event_record_id -ne 42) { throw 'Known record mismatch' }
$summary = Invoke-Cli @('summary',$case,'--json') | ConvertFrom-Json
if ($summary.highlights[0].ref -ne 'fixture-event' -or $summary.gaps.Count -ne 2) { throw 'Summary provenance mismatch' }
$summaryText = Invoke-Cli @('summary',$case)
if ($summaryText -notmatch 'What to do next' -or $summaryText -notmatch 'service was installed') {
    throw 'Plain-language summary mismatch'
}
$human = Invoke-Cli @('--pretty','verify',$evidence.archive,'--checksum',$evidence.checksum)
if ($human -notmatch 'Detached SHA-256: matched') { throw 'Plain-language verification mismatch' }
$preview = Invoke-Cli @('ai',$case,'--enable','--provider','gemini','--model','synthetic','--question','Summarize the synthetic event.','--record',($evidence.sha256 + '/fixture-event'),'--preview') | ConvertFrom-Json
if ($preview.excerpts.fields.event_id -ne 7045) { throw 'Assistant preview mismatch' }
$report = Join-Path $qa 'synthetic-cli-report.html'
$null = Invoke-Cli @('report',$case,'--out',$report)
if ((Get-Content -Raw -LiteralPath $report) -notmatch 'fixture-event' -or
    (Get-Content -Raw -LiteralPath $report) -notmatch 'Verified synthetic fixture') {
    throw 'Report provenance or annotation missing'
}
$smoke = [pscustomobject]@{
    BuildId=$BuildId; PackageSha256=$detached; Version=$version; Steps=$steps;
    Gui=$gui; Cli=$cli; Case=$case; Archive=$evidence.archive; Checksum=$evidence.checksum; Report=$report
}
$smoke | ConvertTo-Json -Depth 6 | Tee-Object -FilePath (Join-Path $qa 'packaged-cli-smoke.json')
