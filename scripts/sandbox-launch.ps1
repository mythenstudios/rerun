# Host side of the Windows Sandbox tests (docs/09-testing.md, tier 3): builds the test binary
# (the Sandbox has no toolchain), stages it, and starts the Sandbox with sandbox-test.wsb.
#
#   powershell -File scripts/sandbox-launch.ps1             # build, stage, start the Sandbox
#   powershell -File scripts/sandbox-launch.ps1 -StageOnly  # build and stage only
#
# This builds only; it never runs the ignored tests on the host (they refuse here anyway).

param([switch]$StageOnly)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$bin = Join-Path $repo 'target\sandbox\bin'
$out = Join-Path $repo 'target\sandbox\out'

Push-Location $repo
try {
    $json = cargo test -p rerun-core --lib --no-run --message-format=json 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'cargo test --no-run failed' }
} finally { Pop-Location }
$exe = $json | ForEach-Object { try { $_ | ConvertFrom-Json } catch { $null } } |
    Where-Object { $_.reason -eq 'compiler-artifact' -and $_.profile.test -and $_.target.name -eq 'rerun-core' -and $_.target.kind -contains 'lib' -and $_.executable } |
    Select-Object -Last 1 -ExpandProperty executable
if (-not $exe) { throw 'could not locate the rerun-core lib test executable' }

New-Item -ItemType Directory -Force -Path $bin, $out | Out-Null
Get-ChildItem -LiteralPath $out -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
Copy-Item -LiteralPath $exe -Destination (Join-Path $bin 'rerun-core-tests.exe') -Force
Write-Host "staged $exe -> $bin\rerun-core-tests.exe"
if ($StageOnly) { return }

$wsb = (Get-Content -LiteralPath (Join-Path $repo 'scripts\sandbox-test.wsb') -Raw).Replace('@REPO@', $repo)
$resolved = Join-Path $repo 'target\sandbox\sandbox-test.resolved.wsb'
Set-Content -LiteralPath $resolved -Value $wsb -Encoding UTF8
if (-not (Get-Command WindowsSandbox.exe -ErrorAction SilentlyContinue)) {
    throw 'Windows Sandbox is not installed (Windows Features: Windows Sandbox, then reboot)'
}
Write-Host "starting the Sandbox; results appear in $out (sandbox-test.log, result.json)"
Start-Process WindowsSandbox.exe -ArgumentList "`"$resolved`""
