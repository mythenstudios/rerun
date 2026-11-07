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
# Rerun refuses every apply, revert and forget in an elevated process (S2, P2-13 E3). If this
# session is elevated, the
# script starts itself again as a scheduled task with the limited run level (-Worker) and waits
# for it; if that fails it runs the tests elevated and result.json says so.
#
# Windows PowerShell 5.1: native stderr is never redirected under $ErrorActionPreference =
# 'Stop' (that throws NativeCommandError); native calls go through Run-Native.

param([switch]$Worker)

$ErrorActionPreference = 'Stop'
$out = 'C:\sandbox\out'
$exe = 'C:\sandbox\bin\rerun-core-tests.exe'
$done = Join-Path $out 'worker.done'

if ($env:USERNAME -ne 'WDAGUtilityAccount' -or $env:USERPROFILE -notmatch '\\WDAGUtilityAccount\\?$') {
    Write-Error "refusing to run: this is not the Windows Sandbox account (USERNAME=$env:USERNAME, USERPROFILE=$env:USERPROFILE)"
    exit 2
}
New-Item -ItemType Directory -Force -Path $out | Out-Null

# Runs a native command with stderr merged into the output as plain text; sets $script:NativeExit.
function Run-Native {
    $ErrorActionPreference = 'Continue'
    $cmd = $args[0]
    $rest = @($args | Select-Object -Skip 1)
    & $cmd @rest 2>&1 | ForEach-Object { "$_" }
    $script:NativeExit = $LASTEXITCODE
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$build = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
$started = Get-Date
$note = ''

# Elevated session: try the tests de-elevated through a limited scheduled task.
if (-not $Worker -and $elevated) {
    Remove-Item -LiteralPath $done -ErrorAction SilentlyContinue
    try {
        $task = 'RerunSandboxTests'
        $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Worker"
        $pr = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
        Register-ScheduledTask -TaskName $task -Action $act -Principal $pr -Force | Out-Null
        Start-ScheduledTask -TaskName $task
        Write-Host 'session is elevated: tests run de-elevated in a scheduled task, waiting (up to 30 minutes)'
        $deadline = (Get-Date).AddMinutes(30)
        while (-not (Test-Path -LiteralPath $done) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 3 }
        if (Test-Path -LiteralPath $done) {
            Get-Content -LiteralPath (Join-Path $out 'result.json') | ForEach-Object { Write-Host $_ }
            Read-Host 'Done. Press Enter to leave this window (close the Sandbox yourself)'
            exit 0
        }
        $note = 'elevated session; the de-elevated task did not finish in time; running elevated'
    } catch {
        $note = "elevated session; de-elevation failed ($_); running elevated"
    }
    Write-Host $note
}
if ($elevated -and -not $note) {
    $note = 'elevated -> Rerun refuses every apply, revert and forget (and the CLI also plan and every dry run); the writing tests are expected to fail'
}

$code = -1
$passed = 0
$failed = 0
$err = ''
# P2-13 (user decision E7 a): the CLI round trip with the release rerun.exe, before the tests
# (its own game folder and registry key; a test that fails cannot block it).
$cli = $null
try {
    $cli = & 'C:\sandbox\scripts\sandbox-cli.ps1' -Out $out -Elevated $elevated
} catch {
    $cli = [ordered]@{ error = "$_"; expected = $false }
    Write-Host "CLI round trip failed: $_"
}
try {
    if (-not (Test-Path -LiteralPath $exe)) { throw "test binary missing: $exe (run scripts/sandbox-launch.ps1 on the host)" }
    $env:RERUN_SANDBOX = '1'
    $env:RUST_BACKTRACE = '1'
    # One thread: the tests share the real HKCU keys of the VM. `sandbox_` selects the ignored
    # sandbox tests (module sys::win::tests::sandbox); `--ignored` is what makes them run.
    $log = Join-Path $out 'sandbox-test.log'
    Run-Native $exe --ignored --test-threads=1 --nocapture 'sandbox_' | Tee-Object -FilePath $log
    $code = $script:NativeExit
    $text = Get-Content -LiteralPath $log -Raw
    $passed = ([regex]::Matches($text, '(?m)^test \S+ \.\.\. ok')).Count
    $failed = ([regex]::Matches($text, '(?m)^test \S+ \.\.\. FAILED')).Count
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
    }
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $out 'result.json') -Encoding UTF8
}

# Facts for the compatibility layer (P2-11): a failure here never changes the test result.
try { & 'C:\sandbox\scripts\sandbox-probe-layers.ps1' -Out $out } catch { Write-Host "probe failed: $_" }
Write-Host ''
Write-Host "exit code $code, $passed passed, $failed failed, elevated=$elevated $note (results in C:\sandbox\out)"
if ($cli) { Write-Host "CLI round trip: expected=$($cli.expected) (details in cli.log)" }
if ($passed -eq 0 -and $code -eq 0) { Write-Host 'WARNING: no test ran' }
if ($Worker) {
    Set-Content -LiteralPath $done -Value 'done'
    exit $code
}
Read-Host 'Done. Press Enter to leave this window (close the Sandbox yourself)'
exit $code
