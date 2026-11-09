# [DEV] validation chain of the elevated helper with the test-key helper (docs/09-testing.md,
# "Elevated helper on the developer machine"; ADR 0023 sections 2, 5 and 14, audit A4 S3): the
# real UAC prompt, then the real helper reads a real request by identity and verifies a signed
# index under the published test key.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\dev-helper-chain.ps1
#
# Run it in a normal (not administrator) PowerShell in the repository. About 4 minutes (most of
# it the two builds). Three administrator prompts, each named in the window title as
# "PROMPT n of 3"; the title always says what to click:
#  1. builds the TEST-KEY helper (a debug build with the feature test-key: it trusts the published
#     index test key; until P4-5b it changes nothing, every validated request ends in a refusal)
#     and the rerun-core test binary;
#  2. PROMPT 1 of 3 (Windows PowerShell): installs the helper into C:\Program Files\Rerun
#     (scripts/dev-helper-common.ps1: refuses an existing folder that is not this test's, hashes
#     the copy itself); then the script checks owner and DACL of the folder and the file;
#  3. PROMPT 2 of 3 (rerun-helper.exe, "unknown publisher") - click YES: the test
#     sys::win::tests::elevation::dev_helper_chain_with_the_test_key writes a request, an index
#     signed with the test key that names no Topo, and an empty game folder into a fresh test
#     folder below target\rerun-fs-contract (removed again by the test), and starts the helper
#     for it through Rerun's own start (WinElevation); expected: Refused(Topo) 0x52170000 (the
#     helper passed its own image check, its instance lock, read the request by its folder's
#     volume GUID and file ID with the right SHA-256 and build ID, verified the index and found
#     no such Topo). Refused(Index) 0x52160000 would mean a helper without the test key;
#  4. PROMPT 3 of 3 (Windows PowerShell): removes C:\Program Files\Rerun again, always, also
#     after a failure, and checks that it is gone: the test-key helper never stays installed;
#  5. prints a summary (also copied to the clipboard).
#
# What it changes on the machine: only C:\Program Files\Rerun with rerun-helper.exe, created in
# step 2 and removed in step 4, and a test folder below the repository's target\ folder, removed
# by the test itself. No firewall rule, no registry value, nothing in the user's Rerun folder.
# Nothing is left behind (unless the removal prompt is declined: the summary then says FAIL and
# names the folder to delete). It never asks a question.
#
# After an abort (Ctrl+C or a closed window) run the script again; it takes over an admin-only
# leftover folder (empty, or holding only the helper of this same build) and removes it at the
# end. Anything else in the Rerun folder of Program Files is left alone and named
# (dev-helper-common.ps1).

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'dev-helper-common.ps1')
$script:HelperTitle = 'Rerun DEV helper chain test'
$testName = 'sys::win::tests::elevation::dev_helper_chain_with_the_test_key'

# Runs the [DEV] test; returns its verdict line.
function Invoke-ChainTest {
    $env:RERUN_DEV_CHAIN = 'accept'
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
        Remove-Item Env:RERUN_DEV_CHAIN -ErrorAction SilentlyContinue
    }
    $result = $lines | Where-Object { $_ -like 'RERUN_DEV_CHAIN_RESULT:*' } | Select-Object -First 1
    $run = $lines | Where-Object { $_ -like 'RERUN_DEV_CHAIN_RUN:*' } | Select-Object -First 1
    $panic = $lines | Where-Object { $_ -match 'panicked at|assertion' } | Select-Object -First 2
    if ($code -eq 0 -and $result -like '*PASS*') {
        return ($result -replace '^RERUN_DEV_CHAIN_RESULT: ', '')
    }
    return "FAIL: test exit $code; got $(if ($run) { $run -replace '^RERUN_DEV_CHAIN_RUN: ', '' } else { '(no run)' }); $($panic -join ' ')"
}

# --- 0. preconditions ----------------------------------------------------------------------
Title 'checking preconditions'
Assert-NotElevated
$paths = Get-HelperPaths

$aclVerdict = 'FAIL: not checked'
$chain = 'FAIL: not run'
$removal = 'FAIL: not run'
$stopped = $null
try {
    # --- 1. builds -------------------------------------------------------------------------
    $build = Build-Helper $repo -TestKey
    Title 'building the rerun-core test binary (about 2 minutes)'
    Push-Location $repo
    try {
        & cargo test -p rerun-core --lib --locked --no-run
        if ($LASTEXITCODE -ne 0) { Fail "cargo test --no-run failed ($LASTEXITCODE)" }
    } finally { Pop-Location }

    # --- 2. install (prompt 1 of 3) --------------------------------------------------------
    Install-Helper $paths $build 'PROMPT 1 of 3'
    $aclVerdict = Get-AclVerdict $paths

    # --- 3. the chain (prompt 2 of 3) ------------------------------------------------------
    Title 'PROMPT 2 of 3: rerun-helper.exe (unknown publisher) - click YES'
    $chain = Invoke-ChainTest
} catch {
    $stopped = $_.Exception.Message
} finally {
    # --- 4. removal (prompt 3 of 3), always: the test-key helper never stays ----------------
    $removal = Remove-Helper $paths 'PROMPT 3 of 3'
}

# --- 5. summary ----------------------------------------------------------------------------
$parts = @($aclVerdict, $chain, $removal)
$overall = if ($stopped) {
    "FAIL: stopped: $stopped"
} elseif (@($parts | Where-Object { $_ -notlike 'PASS*' }).Count -eq 0) {
    "PASS: the test-key helper's chain holds up to step 3 (Refused(Topo) $(Hex $Topo)); removed"
} else {
    'FAIL: see the lines above'
}
$summary = @(
    "Rerun DEV helper chain test (P4-2c, A4 S3), $(Get-Date -Format 'yyyy-MM-dd HH:mm')",
    "Windows build: $([Environment]::OSVersion.Version)",
    "installed (test-key helper): $($paths.Exe)",
    "admin-only check: $aclVerdict",
    "chain: $chain",
    "removal: $removal",
    "RESULT: $overall"
) -join [Environment]::NewLine
Write-Host ''
Write-Host $summary
try { Set-Clipboard -Value $summary } catch { }
Title "DONE: $($overall.Split(':')[0]) (summary in the clipboard)"
