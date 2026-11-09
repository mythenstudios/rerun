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
    # The release rerun.exe and rerun-launch.exe for the CLI round trip (P2-13, P3-3e, sandbox-cli.ps1); built only.
    # One package per build: the same artifacts as the release builds of ci.yml (feature
    # unification of a combined -p build would change rerun-launch).
    foreach ($pkg in 'rerun-cli', 'rerun-launch') {
        $ErrorActionPreference = 'Continue'
        & cargo build -p $pkg --release 2>$null | Out-Null
        $exit = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        if ($exit -ne 0) { throw "cargo build -p $pkg --release failed (run it by hand to see why)" }
    }
} finally { Pop-Location }
# The 32-bit test program of the VirtualStore case (P4-0), built from the source in the repo (no
# third-party binary): no manifest, i686 (rust-toolchain.toml lists the target). Built into
# target\sandbox\stub, staged with the other binaries below.
$stubSrc = Join-Path $repo 'tests\support\vstore_stub.rs'
$stubExe = Join-Path $root 'stub\vstore-stub.exe'
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $stubExe) | Out-Null
$ErrorActionPreference = 'Continue'
& rustc --edition 2024 --target i686-pc-windows-msvc -C opt-level=s -o $stubExe $stubSrc 2>$null | Out-Null
$exit = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($exit -ne 0 -or -not (Test-Path -LiteralPath $stubExe)) { throw "building the VirtualStore test program failed (run: rustc --edition 2024 --target i686-pc-windows-msvc -o $stubExe $stubSrc)" }
$cliExe = Join-Path $repo 'target\release\rerun.exe'
$shimExe = Join-Path $repo 'target\release\rerun-launch.exe'
if (-not (Test-Path -LiteralPath $cliExe)) { throw "release rerun.exe missing: $cliExe" }
if (-not (Test-Path -LiteralPath $shimExe)) { throw "release rerun-launch.exe missing: $shimExe" }
$exe = $json | ForEach-Object { try { $_ | ConvertFrom-Json } catch { $null } } |
    Where-Object { $_.reason -eq 'compiler-artifact' -and $_.profile.test -and $_.target.name -in @('rerun_core', 'rerun-core') -and $_.target.kind -contains 'lib' -and $_.executable } |
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
Copy-Item -LiteralPath $shimExe -Destination (Join-Path $bin 'rerun-launch.exe') -Force
Write-Host "staged $shimExe -> $bin\rerun-launch.exe"
Copy-Item -LiteralPath $stubExe -Destination (Join-Path $bin 'vstore-stub.exe') -Force
Write-Host "staged $stubExe -> $bin\vstore-stub.exe"
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
