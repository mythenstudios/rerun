# Runs inside Windows Sandbox (LogonCommand of sandbox-test.wsb). Not for the host: the tests
# it starts write to the real HKCU and LocalAppData of the account that runs them. They refuse
# anywhere but the Sandbox (RERUN_SANDBOX=1 and the WDAGUtilityAccount account), and so does
# this script.
#
# Results: C:\sandbox\out\sandbox-test.log (full output) and result.json (exit code, account,
# elevation, OS build, per-test counts). The Sandbox closes when the last window closes; the
# script ends with the result on screen and a pause, so close the Sandbox yourself.

$ErrorActionPreference = 'Stop'
$out = 'C:\sandbox\out'
$exe = 'C:\sandbox\bin\rerun-core-tests.exe'

if ($env:USERNAME -ne 'WDAGUtilityAccount') {
    Write-Error "refusing to run: this is not the Windows Sandbox account (USERNAME=$env:USERNAME)"
    exit 2
}
if (-not (Test-Path -LiteralPath $exe)) {
    Write-Error "test binary missing: $exe (run scripts/sandbox-launch.ps1 on the host)"
    exit 2
}
New-Item -ItemType Directory -Force -Path $out | Out-Null

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$build = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
$started = Get-Date

$env:RERUN_SANDBOX = '1'
$env:RUST_BACKTRACE = '1'
# One thread: the tests share the real HKCU keys of the VM. `sandbox_` selects the ignored
# sandbox tests (module sys::win::tests::sandbox); `--ignored` is what makes them run.
$log = Join-Path $out 'sandbox-test.log'
& $exe --ignored --test-threads=1 --nocapture 'sandbox_' *>&1 | Tee-Object -FilePath $log
$code = $LASTEXITCODE

$text = Get-Content -LiteralPath $log -Raw
$passed = ([regex]::Matches($text, '(?m)^test \S+ \.\.\. ok')).Count
$failed = ([regex]::Matches($text, '(?m)^test \S+ \.\.\. FAILED')).Count
$result = [ordered]@{
    exit_code = $code
    passed    = $passed
    failed    = $failed
    user      = $env:USERNAME
    elevated  = $elevated
    os_build  = $build
    started   = $started.ToString('o')
    finished  = (Get-Date).ToString('o')
}
$result | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $out 'result.json') -Encoding UTF8
# Facts for the compatibility layer (P2-11): a failure here never changes the test result.
try { & 'C:\sandbox\scripts\sandbox-probe-layers.ps1' -Out $out } catch { Write-Host "probe failed: $_" }
Write-Host ''
Write-Host "exit code $code, $passed passed, $failed failed, elevated=$elevated (results in C:\sandbox\out)"
if ($passed -eq 0 -and $code -eq 0) { Write-Host 'WARNING: no test ran' }
Read-Host 'Done. Press Enter to leave this window (close the Sandbox yourself)'
exit $code
