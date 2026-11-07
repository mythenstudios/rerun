# Host side of the Windows Sandbox tests (docs/09-testing.md, tier 3): builds the test binary
# and the release rerun.exe (the Sandbox has no toolchain), stages them, and starts the Sandbox
# with sandbox-test.wsb.
#
#   powershell -File scripts/sandbox-launch.ps1             # build, stage, start the Sandbox
#   powershell -File scripts/sandbox-launch.ps1 -StageOnly  # build and stage only
#
# This builds only; it never runs the ignored tests on the host (they refuse here anyway).
# Optional: put Procmon64.exe (Sysinternals, downloaded by you; nothing is committed) into
# target\sandbox\tools; the layer probes use it when present.

param([switch]$StageOnly)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$root = Join-Path $repo 'target\sandbox'
$bin = Join-Path $root 'bin'
$out = Join-Path $root 'out'
$tools = Join-Path $root 'tools'

function Assert-Plain([string]$path) {
    if ((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "refusing: $path is a reparse point (junction or link)"
    }
}

# Windows PowerShell 5.1 throws on native stderr under 'Stop': judge only the exit code.
Push-Location $repo
try {
    $ErrorActionPreference = 'Continue'
    $json = & cargo test -p rerun-core --lib --no-run --message-format=json 2>$null
    $exit = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($exit -ne 0) { throw 'cargo test --no-run failed (run it by hand to see why)' }
    # The release rerun.exe for the CLI round trip (P2-13, sandbox-cli.ps1); built only.
    $ErrorActionPreference = 'Continue'
    & cargo build -p rerun-cli --release 2>$null | Out-Null
    $exit = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($exit -ne 0) { throw 'cargo build -p rerun-cli --release failed (run it by hand to see why)' }
} finally { Pop-Location }
$cliExe = Join-Path $repo 'target\release\rerun.exe'
if (-not (Test-Path -LiteralPath $cliExe)) { throw "release rerun.exe missing: $cliExe" }
$exe = $json | ForEach-Object { try { $_ | ConvertFrom-Json } catch { $null } } |
    Where-Object { $_.reason -eq 'compiler-artifact' -and $_.profile.test -and $_.target.name -eq 'rerun-core' -and $_.target.kind -contains 'lib' -and $_.executable } |
    Select-Object -Last 1 -ExpandProperty executable
if (-not $exe) { throw 'could not locate the rerun-core lib test executable' }

foreach ($p in @($root, $bin, $out, $tools)) { Assert-Plain $p }
New-Item -ItemType Directory -Force -Path $bin, $out, $tools | Out-Null
# Clear the old results without a recursive delete: files only; a reparse point or a folder
# in there stops the script.
foreach ($item in Get-ChildItem -LiteralPath $out -Force) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "refusing: $($item.FullName) is a reparse point" }
    if ($item.PSIsContainer) { throw "unexpected folder in the output folder: $($item.FullName) (remove it by hand)" }
    Remove-Item -LiteralPath $item.FullName -Force
}
Copy-Item -LiteralPath $exe -Destination (Join-Path $bin 'rerun-core-tests.exe') -Force
Write-Host "staged $exe -> $bin\rerun-core-tests.exe"
Copy-Item -LiteralPath $cliExe -Destination (Join-Path $bin 'rerun.exe') -Force
Write-Host "staged $cliExe -> $bin\rerun.exe"
if (Test-Path -LiteralPath (Join-Path $tools 'Procmon64.exe')) { Write-Host 'Procmon64.exe found: the probes will use it' }
if ($StageOnly) { return }

$template = Get-Content -LiteralPath (Join-Path $repo 'scripts\sandbox-test.wsb') -Raw
$wsb = $template.Replace('@REPO@', [Security.SecurityElement]::Escape($repo))
$resolved = Join-Path $root 'sandbox-test.resolved.wsb'
Set-Content -LiteralPath $resolved -Value $wsb -Encoding UTF8
if (-not (Get-Command WindowsSandbox.exe -ErrorAction SilentlyContinue)) {
    throw 'Windows Sandbox is not installed (Windows Features: Windows Sandbox, then reboot)'
}
Write-Host "starting the Sandbox; results appear in $out (sandbox-test.log, result.json, probe-layers.md)"
Start-Process WindowsSandbox.exe -ArgumentList "`"$resolved`""
