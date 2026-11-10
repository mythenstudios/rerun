# CI entry of the sandbox suite (docs/09-testing.md, "Windows Sandbox suite"): runs the same
# scripts as the Windows Sandbox (sandbox-run.ps1, sandbox-cli.ps1) on a disposable
# GitHub-hosted runner. Refuses anywhere else: the suite writes the real HKCU and LocalAppData of
# the account that runs it, and creates a local user.
#
# Why two passes: the runner's administrator is elevated, and Rerun refuses every apply, revert
# and forget in an elevated process (S2) and plan in the CLI (user decision E3). So
#  1. non-elevated pass: a freshly created local standard user `rerunci` runs
#     `sandbox-run.ps1 -Ci` (the Rust sandbox tests, among them the real package download of
#     P4-6, the CLI round trip, launch_method direct and watch). A
#     standard user cannot hold an elevated token, so no trick is needed, and its profile and
#     HKCU are new, like a fresh Sandbox. A restricted token of the runner's administrator
#     (`runas /trustlevel`, SAFER) was rejected: in the Sandbox it kept the high integrity
#     label and `TokenElevation` still said elevated (docs/09). The process is started as a
#     scheduled task of that user (run level limited, "Log on as a batch job" granted to it);
#     Start-Process -Credential died at once on the runner (presumably no desktop for the new logon).
#  2. elevated pass: `sandbox-run.ps1 -Ci -CliOnly` as the runner's administrator; the only
#     thing checked is that `plan` refuses (exit 3) and nothing changes (E3).
#  3. the runas probe of ADR 0023 section 7 (A4 S2), elevated: a HKCU exefile runas
#     redirection is measured with and without the HKLM class key (s2-probe.log, `MEASURED S2`).
#  4. the firewall write contract and the test-key helper (ADR 0023 sections 6 and 14, P4-5b),
#     elevated, last: real rules of group Rerun added and removed, the helper installed in
#     Program Files\Rerun and removed again (fw-contract.log, `MEASURED` lines).
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
foreach ($f in 'rerun-core-tests.exe', 'rerun.exe', 'rerun-launch.exe', 'vstore-stub.exe') {
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

# ---- the VirtualStore folder (P4-0) -----------------------------------------------------------
# As the runner's administrator, before pass 1: a folder under Program Files that a standard user
# cannot write (the inherited ACL: Users read and execute), with the 32-bit test program as
# game.exe and a settings.ini. Pass 1 starts that program as $user; its write is virtualized.
# Removed again at the end (and here first, if an earlier run left it).
$vsDir = 'C:\Program Files\RerunVsCase'
Section 'prepare the VirtualStore case folder (admin-only, under Program Files)'
if (Test-Path -LiteralPath $vsDir) { Remove-Item -LiteralPath $vsDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $vsDir | Out-Null
Copy-Item -LiteralPath "$sb\bin\vstore-stub.exe" -Destination "$vsDir\game.exe" -Force
[IO.File]::WriteAllText("$vsDir\settings.ini", "[Display]`r`nWidth=1280`r`nHeight=720`r`n", (New-Object Text.UTF8Encoding $false))
& icacls $vsDir
EndSection

# ---- pass 1: non-elevated ---------------------------------------------------------------------
Section "pass 1: non-elevated as $user (sandbox-run.ps1 -Ci)"
$out1 = "$sb\out\nonelevated"
$argList = "-NoProfile -ExecutionPolicy Bypass -File $sb\scripts\sandbox-run.ps1 -Ci -Out $out1"
# A scheduled task of the user (run level limited) is the primary way: Start-Process -Credential
# (Secondary Logon) from the runner's session without a desktop starts a child that dies at once
# (presumably no window station/desktop for the new logon; not measured); seen on the first CI run.
# A password task needs "Log on as a batch job", which Users lack on a client SKU by default:
# granted to this throwaway account on the throwaway runner only.
$how = 'scheduled task'
$cfg = Join-Path $env:RUNNER_TEMP 'secpol.inf'
$db = Join-Path $env:RUNNER_TEMP 'secpol.sdb'
& secedit /export /cfg $cfg /areas USER_RIGHTS | Out-Null
$sid = (Get-LocalUser -Name $user).SID.Value
$inf = Get-Content -LiteralPath $cfg
if ($inf -match '^SeBatchLogonRight') {
    $inf = $inf | ForEach-Object { if ($_ -match '^SeBatchLogonRight') { "$_,*$sid" } else { $_ } }
} else {
    $inf = $inf | ForEach-Object { $_; if ($_ -eq '[Privilege Rights]') { "SeBatchLogonRight = *$sid" } }
}
Set-Content -LiteralPath $cfg -Value $inf -Encoding Unicode
& secedit /configure /db $db /cfg $cfg /areas USER_RIGHTS | Out-Null
Write-Host "granted SeBatchLogonRight to $user (secedit exit $LASTEXITCODE)"
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $argList -WorkingDirectory $out1
Register-ScheduledTask -TaskName 'RerunCiSandbox' -Action $action -User "$env:COMPUTERNAME\$user" -Password $plain -RunLevel Limited -Force | Out-Null
$t0 = Get-Date
Start-ScheduledTask -TaskName 'RerunCiSandbox'
Write-Host "started the pass with: $how"

# Follow status.txt while it runs, until the task has run and is no longer running, or the timeout.
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
    $task = Get-ScheduledTask -TaskName 'RerunCiSandbox'
    $info = Get-ScheduledTaskInfo -TaskName 'RerunCiSandbox'
    $ran = $info.LastRunTime -and $info.LastRunTime -ge $t0.AddSeconds(-5)
    $ended = $ran -and ($task.State -ne 'Running') -and ($task.State -ne 'Queued')
    if ($ended) { break }
}
$info = Get-ScheduledTaskInfo -TaskName 'RerunCiSandbox'
Write-Host ("task last result: 0x{0:X8}, last run: {1}" -f $info.LastTaskResult, $info.LastRunTime)
if (-not $ended) {
    Fail "pass 1 did not finish within $TimeoutSeconds s (status.txt above shows how far it got)"
    Stop-ScheduledTask -TaskName 'RerunCiSandbox' -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process | Where-Object { try { (Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User -eq $user } catch { $false } } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
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
    if ($r1.cli -and $r1.cli.launch_watch -and $r1.cli.launch_watch.failed) { Fail "pass 1: launch_method watch checks failed: $($r1.cli.launch_watch.failed -join ', ')" }
    if ($r1.cli -and $r1.cli.launch_watch -and $r1.cli.launch_watch.error) { Fail "pass 1: launch_method watch error: $($r1.cli.launch_watch.error)" }

    # P4-0: the UAC state of the runner (a measurement, printed so the log and docs/09 can quote it).
    if ($r1.uac) {
        Write-Host ("MEASURED UAC (pass 1, runner): EnableLUA={0}, ConsentPromptBehaviorAdmin={1}, PromptOnSecureDesktop={2}, EnableVirtualization={3} (empty = value absent)" -f `
            $r1.uac.EnableLUA, $r1.uac.ConsentPromptBehaviorAdmin, $r1.uac.PromptOnSecureDesktop, $r1.uac.EnableVirtualization)
    } else { Fail 'pass 1: result.json has no uac object (the UAC state was not measured)' }

    # P4-0, SB-L7: a layer applies when the shim starts the exe with Steam's spelling of argv[0].
    $l7 = if ($r1.cli -and $r1.cli.launch_method) { $r1.cli.launch_method.sb_l7 } else { $null }
    if (-not $l7) { Fail 'pass 1: SB-L7 did not run (no cli.launch_method.sb_l7 in result.json)' }
    else {
        Write-Host ("MEASURED SB-L7: verdict={0}; rows: {1}" -f $l7.verdict, (($l7.rows.PSObject.Properties | ForEach-Object { "$($_.Name) = $($_.Value)" }) -join '; '))
        switch ($l7.verdict) {
            'applied' { Write-Host 'SB-L7: the layer applied for both shim spellings (upper and lower case of argv[0])' }
            'not_observable' { Write-Host "::warning::SB-L7 NOT VERIFIED: layers cannot be observed on this runner ($($l7.detail)). Nothing is claimed; the case stays open in docs/09-testing.md" }
            'not_applied' { Fail "SB-L7: a layer set for the exe does NOT apply when the shim starts it with another spelling of argv[0]: $($l7.detail)" }
            default { Fail "SB-L7: the probe failed (verdict $($l7.verdict)): $($l7.detail)" }
        }
    }

    # P4-0, the real VirtualStore case: i686 test program without a manifest as the standard user.
    $vs = if ($r1.cli) { $r1.cli.virtualstore } else { $null }
    if (-not $vs -or $vs -is [string]) { Fail 'pass 1: the VirtualStore case did not run (no cli.virtualstore object in result.json)' }
    else {
        Write-Host ("MEASURED VirtualStore: verdict={0}; stub exit {1} ({2}); copy exists={3}; real file unchanged={4}; plan warns={5}, names the copy={6}; copy path {7}" -f `
            $vs.verdict, $vs.stub_exit, $vs.stub_output, $vs.copy_exists, $vs.real_file_unchanged, $vs.plan_warns, $vs.plan_names_the_copy, $vs.copy)
        switch ($vs.verdict) {
            'ok' { Write-Host 'VirtualStore: a copy appeared under the user''s VirtualStore and plan --dry-run warned and named it' }
            'refused_admin_only' { Write-Host "::warning::VirtualStore: $($vs.detail)" }
            'not_virtualized' {
                # Measured (CI run 42664558936): UAC is on, yet the write is denied, not virtualized.
                # The suite runs as a scheduled task with a password (a batch logon), and Windows
                # virtualizes only interactive logons, so this runner cannot show the real case. It
                # is a gate for admin-only roots only (phase 6), checked there by hand.
                Write-Host "::warning::VirtualStore NOT VERIFIED: the write was not virtualized (batch logon of the scheduled task; EnableLUA=$($vs.uac.EnableLUA), EnableVirtualization=$($vs.uac.EnableVirtualization)); the real case stays open in docs/09-testing.md. $($vs.detail)"
            }
            'no_warning' { Fail "VirtualStore: $($vs.detail)" }
            default { Fail "VirtualStore: the case failed (verdict $($vs.verdict)): $($vs.detail)" }
        }
    }

    # P4-6 (ADR 0025): the real package download (sys::win::tests::http, a sandbox_ test of the run
    # above, as the standard user): GitHub release asset -> redirect -> cache, the hash measured.
    $dl = @()
    if (Test-Path -LiteralPath "$out1\sandbox-test.log") {
        $dl = @(Get-Content -LiteralPath "$out1\sandbox-test.log" | Where-Object { $_ -like 'MEASURED download*' })
    }
    if ($dl.Count -eq 0) { Fail 'pass 1: the package download test did not run or measured nothing (no MEASURED download line in sandbox-test.log)' }
    else { $dl | ForEach-Object { Write-Host "::notice::$_" } }

    # B12 b (ADR 0023): firewall rules readable by the standard user? A measurement, never a failure.
    $fw = if ($r1.cli) { $r1.cli.firewall_read } else { $null }
    if (-not $fw -or $fw -is [string]) { Write-Host '::warning::B12 b: the firewall read probe did not run (no cli.firewall_read object in result.json)' }
    else {
        Write-Host ("MEASURED firewall read (standard user): COM {0} (rules {1}; first rule {2}); CIM {3} (rules {4})" -f `
            $fw.com, $fw.com_count, $fw.com_fields, $fw.cim, $fw.cim_count)
    }
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

# ---- pass 3: the runas redirection probe (ADR 0023 section 7, A4 S2) ---------------------------
# Last: the probe points HKCU\Software\Classes\exefile\shell\runas\command of runneradmin to
# cmd.exe; the script deletes that runas key again afterwards, also after a failure.
# Elevated, ConsentPromptBehaviorAdmin = 0: no dialog.
Section 'pass 3: runas with a HKCU exefile redirection, with and without the HKLM class key'
$probeTest = 'sys::win::tests::elevation::sb_runas_redirection_and_the_class_key'
$env:RERUN_SANDBOX = '1'
$env:RERUN_CI_SANDBOX = '1'
$previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$redirect = 'HKCU:\Software\Classes\exefile\shell\runas'
$probe = @()
$probeCode = -1
try {
    $probe = @(& "$sb\bin\rerun-core-tests.exe" --ignored --exact $probeTest --nocapture --test-threads=1 2>&1 | ForEach-Object { "$_" })
    $probeCode = $LASTEXITCODE
} finally {
    # The redirection the probe planted goes again, also after a failure.
    Remove-Item -LiteralPath $redirect -Recurse -Force -ErrorAction SilentlyContinue
    $ErrorActionPreference = $previous
    Remove-Item Env:RERUN_SANDBOX, Env:RERUN_CI_SANDBOX -ErrorAction SilentlyContinue
}
if (Test-Path -LiteralPath $redirect) { Fail "pass 3: $redirect could not be removed" }
$probe | ForEach-Object { Write-Host $_ }
$probe | Where-Object { $_ -like 'MEASURED S2*' } | ForEach-Object { Write-Host "::notice::$_" }
Set-Content -LiteralPath "$sb\out\elevated\s2-probe.log" -Value $probe -Encoding UTF8
if ($probeCode -ne 0) { Fail 'pass 3: a runas start through the HKLM exefile class key was redirected, or the probe failed (see s2-probe.log)' }
EndSection

# ---- pass 4: the firewall write contract and the test-key helper (ADR 0023 sections 6, 14) -----
# Elevated, as the runner's administrator. Installs the TEST-KEY helper (the debug build with the
# feature test-key from the workflow step, ADR 0023 section 2, A4 S3) into
# C:\Program Files\Rerun, then runs two ignored tests of rerun-core-tests.exe:
#  - sb_firewall_write_contract: adds and removes real rules of group Rerun (the write contract:
#    facts read back, Remove with two rules of one name, the name's case, a missing name; the
#    product path add_all/remove_all for several program forms; name and program lengths; N8);
#  - sb_test_key_helper_removes_a_rule: starts the installed helper through Rerun's own start for
#    an unknown Topo of a test-key index (Refused(Topo)) and for the removal of a rule the test
#    added (Done, rule gone).
# Their MEASURED lines go to fw-contract.log and the log as notices. Afterwards, also after a
# failure: every rule of group Rerun, the helper folder and C:\RerunSandbox\fw are removed.
Section 'pass 4: the firewall write contract and the test-key helper (elevated)'
$helperSrc = Join-Path $repo 'target\debug\rerun-helper.exe'
$pfRerun = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'Rerun'
$fwDir = Join-Path $game 'fw'
$fwLog = @()
$env:RERUN_SANDBOX = '1'
$env:RERUN_CI_SANDBOX = '1'
$previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    if (-not (Test-Path -LiteralPath $helperSrc -PathType Leaf)) {
        Fail "pass 4: the test-key helper was not built: $helperSrc (workflow step 'build the sandbox binaries')"
    } else {
        if (Test-Path -LiteralPath $pfRerun) { Remove-Item -LiteralPath $pfRerun -Recurse -Force }
        New-Item -ItemType Directory -Path $pfRerun | Out-Null
        Copy-Item -LiteralPath $helperSrc -Destination (Join-Path $pfRerun 'rerun-helper.exe')
        New-Item -ItemType Directory -Force -Path $fwDir | Out-Null
        & icacls $pfRerun | ForEach-Object { Write-Host $_ }
        & icacls (Join-Path $pfRerun 'rerun-helper.exe') | ForEach-Object { Write-Host $_ }
        foreach ($t in 'sys::win::tests::firewall::sb_firewall_write_contract', 'sys::win::tests::firewall::sb_test_key_helper_removes_a_rule') {
            $out = @(& "$sb\bin\rerun-core-tests.exe" --ignored --exact $t --nocapture --test-threads=1 2>&1 | ForEach-Object { "$_" })
            $code = $LASTEXITCODE
            $out | ForEach-Object { Write-Host $_ }
            $out | Where-Object { $_ -like 'MEASURED*' } | ForEach-Object { Write-Host "::notice::$_" }
            $fwLog += "== $t (exit $code)"
            $fwLog += $out
            if ($code -ne 0) { Fail "pass 4: $t failed (exit $code; see fw-contract.log)" }
        }
    }
} finally {
    $ErrorActionPreference = $previous
    Remove-Item Env:RERUN_SANDBOX, Env:RERUN_CI_SANDBOX -ErrorAction SilentlyContinue
    $left = @(Get-NetFirewallRule -Group 'Rerun' -ErrorAction SilentlyContinue)
    if ($left.Count -gt 0) {
        Write-Host "removing $($left.Count) rule(s) of group Rerun left by pass 4: $(($left | ForEach-Object { $_.DisplayName }) -join '; ')"
        $left | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $pfRerun -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $fwDir -Recurse -Force -ErrorAction SilentlyContinue
}
Set-Content -LiteralPath "$sb\out\elevated\fw-contract.log" -Value $fwLog -Encoding UTF8
# The final check must not pass because the read failed: every rule is read with -ErrorAction Stop
# (an empty group would make -Group itself throw), and a failed read fails the pass.
try {
    $leftRules = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.Group -eq 'Rerun' })
    if ($leftRules.Count -gt 0) { Fail "pass 4: rules of group Rerun are left: $(($leftRules | ForEach-Object { $_.DisplayName }) -join '; ')" }
} catch {
    Fail "pass 4: the firewall could not be read for the final check: $($_.Exception.Message)"
}
if (Test-Path -LiteralPath $pfRerun) { Fail "pass 4: $pfRerun could not be removed" }
EndSection

# ---- clean up and verdict ---------------------------------------------------------------------
try { Unregister-ScheduledTask -TaskName 'RerunCiSandbox' -Confirm:$false -ErrorAction SilentlyContinue } catch { }
try { Remove-Item -LiteralPath $vsDir -Recurse -Force -ErrorAction SilentlyContinue } catch { }
Section 'verdict'
if ($script:failed) { Write-Host '::error::sandbox suite FAILED (see the groups above and the sandbox-suite artifact)'; EndSection; exit 1 }
Write-Host 'sandbox suite passed (non-elevated and elevated pass)'
EndSection
exit 0
