# Runs inside Windows Sandbox (LogonCommand of sandbox-test.wsb). Not for the host: the tests
# it starts write to the real HKCU and LocalAppData of the account that runs them. They refuse
# anywhere but the Sandbox (RERUN_SANDBOX=1 and the WDAGUtilityAccount account), and so does
# this script.
#
# Results: C:\sandbox\out\sandbox-test.log (full output) and result.json (exit code, account,
# elevation, OS build, per-test counts, note, and under "cli" the CLI round trip of
# sandbox-cli.ps1 with its log cli.log). result.json is always written, also when the run
# fails. The Sandbox closes when the last window closes; the script ends with the result
# on screen and a pause, so close the Sandbox yourself.
#
# Rerun refuses every apply, revert and forget in an elevated process (S2, P2-13 E3). The
# Sandbox starts with UAC off (EnableLUA = 0): its administrator account has no split token,
# so the LogonCommand is elevated, and neither a scheduled task with the limited run level nor
# `runas /trustlevel:0x20000` gives a token that is not elevated (seen in the first runs,
# build 26100: the Basic User token keeps the high integrity label). So, when the session is
# elevated and UAC is off, the script turns UAC on (HKLM of the Sandbox) and restarts the
# Sandbox from inside; the Sandbox keeps its state across that restart and runs the
# LogonCommand again, now with the filtered token. If the session is still elevated with UAC
# on, the tests run elevated and result.json says so in "note".
#
# Windows PowerShell 5.1: native stderr is never redirected under $ErrorActionPreference =
# 'Stop' (that throws NativeCommandError); native calls go through Run-Native.

# CI (docs/09-testing.md, "Windows Sandbox suite"): scripts/ci-sandbox.ps1 runs this script on a
# disposable GitHub-hosted runner, twice: -Ci alone as the standard user rerunci (the
# non-elevated pass: the Rust tests and the CLI round trips) and -Ci -CliOnly as the runner's
# elevated administrator (the elevated pass: only the refusal of plan, user decision E3).
# With -Ci there is no UAC restart, no probes, no Explorer window and no pause, and the guard
# also accepts the CI accounts.
param(
    [switch]$Ci,
    [switch]$CliOnly,
    [string]$Out = 'C:\sandbox\out'
)

$ErrorActionPreference = 'Stop'
$out = $Out
$exe = 'C:\sandbox\bin\rerun-core-tests.exe'

# The guard (sandbox-guard.ps1): the environment, the account of the process token (not
# spoofable through the environment) and the script's own path in the mapped (Sandbox) or
# staged (CI) folder. It runs before every write; without -Ci this script writes HKLM and
# restarts the machine.
. 'C:\sandbox\scripts\sandbox-guard.ps1'
function Test-Here { Test-SandboxGuard -Script $PSCommandPath -Expected 'C:\sandbox\scripts\sandbox-run.ps1' -Ci ([bool]$Ci) }
if (-not (Test-Here)) {
    Write-Error "refusing to run: not the Windows Sandbox account and its mapped LogonCommand, nor the CI accounts with -Ci (USERNAME=$env:USERNAME, script $PSCommandPath, ci=$Ci)"
    exit 2
}
if ($Ci) { $env:RERUN_CI_SANDBOX = '1' }
New-Item -ItemType Directory -Force -Path $out | Out-Null

# Runs a native command with stderr merged into the output as plain text; sets $script:NativeExit.
function Run-Native {
    $ErrorActionPreference = 'Continue'
    $cmd = $args[0]
    $rest = @($args | Select-Object -Skip 1)
    & $cmd @rest 2>&1 | ForEach-Object { "$_" }
    $script:NativeExit = $LASTEXITCODE
}

# Every stage with its time in C:\sandbox\out\status.txt (visible on the host at once): after
# the restart from inside, Windows starts the LogonCommand without a visible window.
$status = Join-Path $out 'status.txt'
function Status([string]$s) {
    Add-Content -LiteralPath $status -Value "$(Get-Date -Format 'HH:mm:ss') $s"
    Write-Host $s
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$build = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
$started = Get-Date
$note = ''
Status "start: account $env:USERNAME, elevated=$elevated, build $build"

# Elevated session with UAC off: turn UAC on and restart the Sandbox (see the header).
$uacKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
# The marker lives on the Sandbox's own disk: it survives the restart from inside, and every
# fresh Sandbox starts without it (a copy in out\ is only for the record; a stale copy there
# from an earlier session blocked the restart once).
$marker = 'C:\RerunSandbox\uac-restart.txt'
if ($elevated -and -not $Ci) {
    $lua = (Get-ItemProperty -LiteralPath $uacKey -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
    if ($lua -ne 1 -and (Test-Path -LiteralPath $marker)) {
        # Restarted once already and UAC is still off: never loop.
        $note = 'the UAC restart did not take effect (EnableLUA is still off); running elevated, the writing tests are expected to fail'
        Status $note
    } elseif ($lua -ne 1) {
        if (-not (Test-Here)) { Write-Error 'refusing: guard failed before the HKLM write'; exit 2 }
        Set-ItemProperty -LiteralPath $uacKey -Name EnableLUA -Value 1 -Type DWord
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $marker) | Out-Null
        $line = "EnableLUA was $lua; set to 1 and restarted at $(Get-Date -Format o)"
        Set-Content -LiteralPath $marker -Value $line
        Set-Content -LiteralPath (Join-Path $out 'uac-restart.txt') -Value $line
        Status 'elevated and UAC off: UAC turned on, the Sandbox restarts in 10 s and runs again (without a visible window; follow status.txt)'
        Run-Native shutdown.exe /r /t 10 | Out-Null
        exit 0
    } else {
        $note = 'elevated although UAC is on -> Rerun refuses every apply, revert and forget (and the CLI also plan and every dry run); the writing tests are expected to fail'
        Write-Host $note
    }
}

$code = -1
$passed = 0
$failed = 0
$err = ''
# P2-13 (user decision E7 a), P3-3e: the CLI round trip and the launch_method round trip with the release rerun.exe, before the tests
# (its own game folder and registry key; a test that fails cannot block it).
$cli = $null
Status 'CLI round trip and launch_method round trip (cli.log)'
try {
    $cli = &'C:\sandbox\scripts\sandbox-cli.ps1' -Out $out -Elevated $elevated -Ci:$Ci
} catch {
    $cli = [ordered]@{ error = "$_"; expected = $false }
    Write-Host "CLI round trip failed: $_"
}
try {
    if ($CliOnly) { $code = 0; Status "sandbox tests skipped (-CliOnly: the elevated pass checks only the refusal of plan)" }
    else {
    if (-not (Test-Path -LiteralPath $exe)) { throw "test binary missing: $exe (run scripts/sandbox-launch.ps1 on the host)" }
    $env:RERUN_SANDBOX = '1'
    $env:RUST_BACKTRACE = '1'
    # One thread: the tests share the real HKCU keys of the VM. `sandbox_` selects the ignored
    # sandbox tests (module sys::win::tests::sandbox); `--ignored` is what makes them run.
    $log = Join-Path $out 'sandbox-test.log'
    Status 'sandbox tests (sandbox-test.log)'
    Run-Native $exe --ignored --test-threads=1 --nocapture 'sandbox_' | Tee-Object -FilePath $log
    $code = $script:NativeExit
    $text = Get-Content -LiteralPath $log -Raw
    $passed = ([regex]::Matches($text, '(?m)^test \S+ \.\.\. ok')).Count
    $failed = ([regex]::Matches($text, '(?m)^test \S+ \.\.\. FAILED')).Count
    }
} catch {
    $err = "$_"
    Write-Host "run failed: $err"
} finally {
    $result = [ordered]@{
        exit_code = $code
        passed    = $passed
        failed    = $failed
        user      = $env:USERNAME
        elevated  = $elevated
        note      = $note
        error     = $err
        os_build  = $build
        started   = $started.ToString('o')
        finished  = (Get-Date).ToString('o')
        cli       = $cli
        ci        = [bool]$Ci
        cli_only  = [bool]$CliOnly
    }
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $out 'result.json') -Encoding UTF8
}

# Facts for the compatibility layer (P2-11): a failure here never changes the test result.
if (-not $Ci) { Status 'layer probes (probe-layers.md)' }
if (-not $Ci) { try { & 'C:\sandbox\scripts\sandbox-probe-layers.ps1' -Out $out } catch { Write-Host "probe failed: $_" } }
Write-Host ''
Status "done: exit code $code, $passed passed, $failed failed, elevated=$elevated $note"
# A visible end in the Sandbox too: an Explorer window on the results (not in CI).
if (-not $Ci) { try { Start-Process -FilePath "$env:SystemRoot\explorer.exe" -ArgumentList $out } catch { } }
if ($cli) { Write-Host "CLI round trip: expected=$($cli.expected) (details in cli.log)" }
if ($passed -eq 0 -and $code -eq 0) { Write-Host 'WARNING: no test ran' }
# After the restart from inside there is no visible window to wait in (the Explorer window
# shows the end); only the first, visible run pauses.
if (-not $Ci -and -not (Test-Path -LiteralPath $marker)) {
    Read-Host 'Done. Press Enter to leave this window (close the Sandbox yourself)'
}
exit $code
