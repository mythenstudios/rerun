# CI entry of the sandbox suite (docs/09-testing.md, "Windows Sandbox suite"): runs the same
# scripts as the Windows Sandbox (sandbox-run.ps1, sandbox-cli.ps1) on a disposable
# GitHub-hosted runner. Refuses anywhere else: the suite writes the real HKCU and LocalAppData of
# the account that runs it, and creates a local user.
#
# Why two passes: the runner's administrator is elevated, and Rerun refuses every apply, revert
# and forget in an elevated process (S2) and plan in the CLI (user decision E3). So
#  1. non-elevated pass: a freshly created local standard user `rerunci` runs
#     `sandbox-run.ps1 -Ci` (the Rust sandbox tests, the CLI round trip, launch_method). A
#     standard user cannot hold an elevated token, so no trick is needed, and its profile and
#     HKCU are new, like a fresh Sandbox. A restricted token of the runner's administrator
#     (`runas /trustlevel`, SAFER) was rejected: in the Sandbox it kept the high integrity
#     label and `TokenElevation` still said elevated (docs/09). The process is started with
#     Start-Process -Credential (Secondary Logon); if that fails, with a scheduled task of that
#     user (run level limited). Both are tried, and the log says which one worked.
#  2. elevated pass: `sandbox-run.ps1 -Ci -CliOnly` as the runner's administrator; the only
#     thing checked is that `plan` refuses (exit 3) and nothing changes (E3).
# The wrapper's UAC restart (Sandbox only) is off with -Ci.
#
# Layout (the same paths as in the Sandbox, so the scripts need no second variant): C:\sandbox
# \scripts, \bin, \out; C:\RerunSandbox for the game folders. Results: C:\sandbox\out\
# nonelevated and \elevated (status.txt, result.json, cli.log, sandbox-test.log), uploaded by the
# workflow. The step fails (exit 1) unless both passes are as expected.
#
# Windows PowerShell 5.1 (the workflow step uses `shell: powershell`).

param(
    # Seconds the non-elevated pass may take before it is stopped.
    [int]$TimeoutSeconds = 1500
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$sb = 'C:\sandbox'
$game = 'C:\RerunSandbox'
$user = 'rerunci'

function Section([string]$s) { Write-Host ''; Write-Host "::group::$s"; Write-Host "=== $s" }
function EndSection { Write-Host '::endgroup::' }
function Fail([string]$s) { Write-Host "::error::$s"; $script:failed = $true }
$script:failed = $false

# ---- guard ------------------------------------------------------------------------------------
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = (New-Object Security.Principal.WindowsPrincipal($me)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "account $($me.Name), elevated=$elevated, GITHUB_ACTIONS=$env:GITHUB_ACTIONS, RUNNER_ENVIRONMENT=$env:RUNNER_ENVIRONMENT"
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    (($me.Name -split '\\')[-1]) -ne 'runneradmin' -or -not $elevated) {
    Write-Host '::error::refusing to run: this is not a GitHub-hosted runner as its elevated administrator (the suite writes the real HKCU and creates a user)'
    exit 2
}

# ---- stage ------------------------------------------------------------------------------------
Section 'stage binaries and scripts (C:\sandbox)'
# The binaries as the Sandbox gets them: rerun-core-tests.exe, rerun.exe, rerun-launch.exe in
# target\sandbox\bin (the builds of the previous workflow steps are reused from the cache).
& (Join-Path $PSScriptRoot 'sandbox-launch.ps1') -StageOnly
$staged = Join-Path $repo 'target\sandbox\bin'
foreach ($f in 'rerun-core-tests.exe', 'rerun.exe', 'rerun-launch.exe') {
    if (-not (Test-Path -LiteralPath (Join-Path $staged $f))) { throw "not staged: $f" }
}
New-Item -ItemType Directory -Force -Path "$sb\scripts", "$sb\bin", "$sb\out\nonelevated", "$sb\out\elevated", $game | Out-Null
Copy-Item -Path (Join-Path $repo 'scripts\sandbox-*.ps1') -Destination "$sb\scripts" -Force
Copy-Item -Path (Join-Path $staged '*.exe') -Destination "$sb\bin" -Force
Set-Content -LiteralPath "$sb\ci-host.txt" -Value 'github-hosted-runner' -Encoding ASCII
Get-ChildItem "$sb\scripts", "$sb\bin" | ForEach-Object { Write-Host ("{0,10} {1}" -f $_.Length, $_.FullName) }
EndSection

# ---- the standard user ------------------------------------------------------------------------
Section "create the standard user $user"
$chars = [char[]]'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
$rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
$bytes = New-Object byte[] 24
$rng.GetBytes($bytes)
$plain = (($bytes | ForEach-Object { $chars[$_ % $chars.Length] }) -join '') + '!aA1'
$secure = ConvertTo-SecureString $plain -AsPlainText -Force
if (Get-LocalUser -Name $user -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $user }
New-LocalUser -Name $user -Password $secure -PasswordNeverExpires -AccountNeverExpires -Description 'Rerun CI sandbox suite' | Out-Null
Add-LocalGroupMember -Group 'Users' -Member $user
# The staged folders: read and execute for the user, write only where it must (out, game folders).
foreach ($d in $sb, $game) { & icacls $d /inheritance:r | Out-Null }
& icacls $sb /grant 'SYSTEM:(OI)(CI)F' /grant 'Administrators:(OI)(CI)F' /grant "${user}:(OI)(CI)RX" | Out-Null
& icacls "$sb\out" /grant "${user}:(OI)(CI)M" | Out-Null
& icacls $game /grant 'SYSTEM:(OI)(CI)F' /grant 'Administrators:(OI)(CI)F' /grant "${user}:(OI)(CI)M" | Out-Null
Write-Host "user $user created (member of Users only)"
EndSection

# ---- pass 1: non-elevated ---------------------------------------------------------------------
Section "pass 1: non-elevated as $user (sandbox-run.ps1 -Ci)"
$out1 = "$sb\out\nonelevated"
$argList = "-NoProfile -ExecutionPolicy Bypass -File $sb\scripts\sandbox-run.ps1 -Ci -Out $out1"
$cred = New-Object Management.Automation.PSCredential(".\$user", $secure)
$how = ''
$proc = $null
try {
    Start-Service seclogon -ErrorAction SilentlyContinue
    $proc = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $argList `
        -Credential $cred -LoadUserProfile -UseNewEnvironment -WorkingDirectory $out1 -WindowStyle Hidden -PassThru
    $how = 'Start-Process -Credential'
} catch {
    Write-Host "Start-Process -Credential failed: $_"
    Write-Host 'falling back to a scheduled task of the user (run level limited)'
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $argList -WorkingDirectory $out1
    Register-ScheduledTask -TaskName 'RerunCiSandbox' -Action $action -User ".\$user" -Password $plain -RunLevel Limited -Force | Out-Null
    Start-ScheduledTask -TaskName 'RerunCiSandbox'
    $how = 'scheduled task'
}
Write-Host "started the pass with: $how"

# Follow status.txt while it runs, until the process ends, `done:` appears and the timeout.
$seen = 0
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$ended = $false
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 3
    $st = Join-Path $out1 'status.txt'
    if (Test-Path -LiteralPath $st) {
        $lines = @(Get-Content -LiteralPath $st)
        for ($i = $seen; $i -lt $lines.Count; $i++) { Write-Host "[status] $($lines[$i])" }
        $seen = $lines.Count
    }
    if ($proc) { $ended = $proc.HasExited }
    else { $ended = ((Get-ScheduledTask -TaskName 'RerunCiSandbox').State -ne 'Running') -and ($seen -gt 0) }
    if ($ended) { break }
}
if (-not $ended) {
    Fail "pass 1 did not finish within $TimeoutSeconds s (status.txt above shows how far it got)"
    if ($proc) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
}
Write-Host "pass 1 process ended: $ended"
EndSection

function Show-File([string]$path, [int]$tail = 0) {
    if (Test-Path -LiteralPath $path) {
        Write-Host "::group::$path"
        if ($tail -gt 0) { Get-Content -LiteralPath $path -Tail $tail } else { Get-Content -LiteralPath $path }
        Write-Host '::endgroup::'
    } else { Write-Host "(missing: $path)" }
}
Show-File "$out1\cli.log"
Show-File "$out1\sandbox-test.log"
Show-File "$out1\status.txt"

$r1 = $null
if (Test-Path -LiteralPath "$out1\result.json") { $r1 = Get-Content -LiteralPath "$out1\result.json" -Raw | ConvertFrom-Json }
Section 'pass 1: result'
if (-not $r1) {
    Fail 'pass 1 wrote no result.json'
} else {
    Write-Host ($r1 | ConvertTo-Json -Depth 6)
    if ($r1.elevated) { Fail "pass 1 ran elevated (user $($r1.user)): the non-elevated pass did not take effect" }
    if ($r1.error) { Fail "pass 1 error: $($r1.error)" }
    if ($r1.exit_code -ne 0 -or $r1.failed -ne 0) { Fail "pass 1: the sandbox tests failed (exit $($r1.exit_code), $($r1.failed) failed, $($r1.passed) passed; see sandbox-test.log)" }
    if ($r1.passed -lt 1) { Fail 'pass 1: no sandbox test ran' }
    if (-not $r1.cli -or -not $r1.cli.expected) { Fail 'pass 1: the CLI round trip is not as expected (see cli.log and cli.unchanged / cli.launch_method.failed above)' }
    if ($r1.cli -and $r1.cli.launch_method -and $r1.cli.launch_method.failed) { Fail "pass 1: launch_method checks failed: $($r1.cli.launch_method.failed -join ', ')" }
}
EndSection

# ---- pass 2: elevated -------------------------------------------------------------------------
Section 'pass 2: elevated as the runner administrator (sandbox-run.ps1 -Ci -CliOnly)'
$out2 = "$sb\out\elevated"
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$sb\scripts\sandbox-run.ps1" -Ci -CliOnly -Out $out2
Write-Host "pass 2 exit code $LASTEXITCODE"
EndSection
Show-File "$out2\cli.log"
Show-File "$out2\status.txt"
$r2 = $null
if (Test-Path -LiteralPath "$out2\result.json") { $r2 = Get-Content -LiteralPath "$out2\result.json" -Raw | ConvertFrom-Json }
Section 'pass 2: result'
if (-not $r2) {
    Fail 'pass 2 wrote no result.json'
} else {
    Write-Host ($r2 | ConvertTo-Json -Depth 6)
    if (-not $r2.elevated) { Fail 'pass 2 did not run elevated' }
    if (-not $r2.cli -or -not $r2.cli.expected) { Fail 'pass 2: the elevated refusal of plan (exit 3, nothing changed) is not as expected (see cli.log)' }
}
EndSection

# ---- clean up and verdict ---------------------------------------------------------------------
try { Unregister-ScheduledTask -TaskName 'RerunCiSandbox' -Confirm:$false -ErrorAction SilentlyContinue } catch { }
Section 'verdict'
if ($script:failed) { Write-Host '::error::sandbox suite FAILED (see the groups above and the sandbox-suite artifact)'; EndSection; exit 1 }
Write-Host 'sandbox suite passed (non-elevated and elevated pass)'
EndSection
exit 0
