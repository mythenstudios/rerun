# [DEV] dialog test of the elevated helper (docs/09-testing.md, "Elevated helper on the developer
# machine"; ADR 0023 sections 7 and 14, audit A4 S2): the real UAC prompt through Rerun's own
# start (rerun_core::sys::win::WinElevation::run_helper: ShellExecuteExW, verb runas, the HKLM
# exefile class key), with the checks on the started process that make its exit code count.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\dev-helper-uac.ps1
#
# Run it in a normal (not administrator) PowerShell in the repository. About 4 minutes (most of
# it the two builds). Four administrator prompts, each named in the window title as
# "PROMPT n of 4"; the title always says what to click:
#  1. builds the release helper (the P4-2a scaffold: it drops its privileges, checks its
#     elevation and refuses every request; it changes nothing) and the rerun-core test binary;
#  2. PROMPT 1 of 4 (Windows PowerShell): installs the helper into C:\Program Files\Rerun
#     (scripts/dev-helper-common.ps1: refuses an existing folder that is not admin-only, hashes
#     the copy itself); then the script checks owner and DACL of the folder and the file;
#  3. PROMPT 2 of 4 (rerun-helper.exe, "unknown publisher") - click YES: the test
#     sys::win::tests::elevation::dev_uac_helper_dialog with RERUN_DEV_UAC=accept runs Rerun's
#     pre-check (policy::root::helper_image) and start; expected: the helper ran, its image
#     (read on the process handle) is the pre-checked file, its token is elevated, and the exit
#     code is Refused(Usage) 0x52110000;
#  4. PROMPT 3 of 4 (rerun-helper.exe again) - click NO: the same test with
#     RERUN_DEV_UAC=decline; expected: Declined (1223), nothing started;
#  5. PROMPT 4 of 4 (Windows PowerShell): removes C:\Program Files\Rerun again, always, also
#     after a failure, and checks that it is gone;
#  6. prints a summary (also copied to the clipboard).
#
# What it changes on the machine: only C:\Program Files\Rerun with rerun-helper.exe, created in
# step 2 and removed in step 5. Nothing is left behind (unless the removal prompt is declined:
# the summary then says FAIL and names the folder to delete). It never asks a question.

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'dev-helper-common.ps1')
$script:HelperTitle = 'Rerun DEV UAC test'
$testName = 'sys::win::tests::elevation::dev_uac_helper_dialog'

# Runs the [DEV] test with RERUN_DEV_UAC=$mode; returns @{ Verdict; S2 }.
function Invoke-DevTest([string]$mode) {
    $env:RERUN_DEV_UAC = $mode
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $lines = @()
    try {
        Push-Location $repo
        & cargo test -p rerun-core --lib --locked -- --ignored --exact $testName --nocapture --test-threads=1 2>&1 |
            ForEach-Object { $line = "$_"; Write-Host $line; $lines += $line }
        $code = $LASTEXITCODE
    } finally {
        Pop-Location
        $ErrorActionPreference = $previous
        Remove-Item Env:RERUN_DEV_UAC -ErrorAction SilentlyContinue
    }
    $result = $lines | Where-Object { $_ -like 'RERUN_DEV_UAC_RESULT:*' } | Select-Object -First 1
    $s2 = $lines | Where-Object { $_ -like 'RERUN_DEV_UAC_S2:*' } | Select-Object -First 1
    $panic = $lines | Where-Object { $_ -match 'panicked at|assertion' } | Select-Object -First 2
    $verdict = if ($code -eq 0 -and $result -like '*PASS*') {
        $result -replace '^RERUN_DEV_UAC_RESULT: ', ''
    } else {
        "FAIL: test exit $code $($panic -join ' ')"
    }
    return @{ Verdict = $verdict; S2 = $(if ($s2) { $s2 -replace '^RERUN_DEV_UAC_S2: ', '' } else { '(not reached)' }) }
}

# --- 0. preconditions ----------------------------------------------------------------------
Title 'checking preconditions'
Assert-NotElevated
$paths = Get-HelperPaths

$aclVerdict = 'FAIL: not checked'
$accept = @{ Verdict = 'FAIL: not run'; S2 = '(not run)' }
$decline = @{ Verdict = 'FAIL: not run'; S2 = '(not run)' }
$removal = 'FAIL: not run'
$stopped = $null
try {
    # --- 1. builds -------------------------------------------------------------------------
    $build = Build-Helper $repo
    Title 'building the rerun-core test binary (about 2 minutes)'
    Push-Location $repo
    try {
        & cargo test -p rerun-core --lib --locked --no-run
        if ($LASTEXITCODE -ne 0) { Fail "cargo test --no-run failed ($LASTEXITCODE)" }
    } finally { Pop-Location }

    # --- 2. install (prompt 1 of 4) --------------------------------------------------------
    Install-Helper $paths $build 'PROMPT 1 of 4'
    $aclVerdict = Get-AclVerdict $paths

    # --- 3. accept (prompt 2 of 4) ---------------------------------------------------------
    Title 'PROMPT 2 of 4: rerun-helper.exe (unknown publisher) - click YES'
    $accept = Invoke-DevTest 'accept'

    # --- 4. decline (prompt 3 of 4) --------------------------------------------------------
    Title 'PROMPT 3 of 4: rerun-helper.exe (unknown publisher) - click NO'
    $decline = Invoke-DevTest 'decline'
} catch {
    $stopped = $_.Exception.Message
} finally {
    # --- 5. removal (prompt 4 of 4), always ------------------------------------------------
    $removal = Remove-Helper $paths 'PROMPT 4 of 4'
}

# --- 6. summary ----------------------------------------------------------------------------
$parts = @($aclVerdict, $accept.Verdict, $decline.Verdict, $removal)
$overall = if ($stopped) {
    "FAIL: stopped: $stopped"
} elseif (@($parts | Where-Object { $_ -notlike 'PASS*' }).Count -eq 0) {
    'PASS: the UAC dialog test of P4-2b holds (accept: Refused(Usage) with the S2 checks; decline: 1223; removed)'
} else {
    'FAIL: see the lines above'
}
$summary = @(
    "Rerun DEV UAC dialog test (P4-2b, A4 S2), $(Get-Date -Format 'yyyy-MM-dd HH:mm')",
    "Windows build: $([Environment]::OSVersion.Version)",
    "installed: $($paths.Exe)",
    "admin-only check: $aclVerdict",
    "accept: $($accept.Verdict)",
    "accept, read on the process handle: $($accept.S2)",
    "decline: $($decline.Verdict)",
    "removal: $removal",
    "RESULT: $overall"
) -join [Environment]::NewLine
Write-Host ''
Write-Host $summary
try { Set-Clipboard -Value $summary } catch { }
Title "DONE: $($overall.Split(':')[0]) (summary in the clipboard)"
