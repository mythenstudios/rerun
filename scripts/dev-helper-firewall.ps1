# [DEV] firewall round trip through the real UAC prompt and the test-key helper (docs/09-testing.md,
# "Elevated helper on the developer machine"; ADR 0023 section 14, P4-5b, user decision A of
# 2026-11-10): Rerun's own apply and revert of a firewall_rule plan, with the journal and the
# game in test folders below the repository's target\ folder.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\dev-helper-firewall.ps1
#
# Run it in a normal (not administrator) PowerShell in the repository. About 5 minutes (most of
# it the two builds). Five administrator prompts, each named in the window title ("PROMPT n of
# 5"); the title always says what to click. It never asks a question and checks itself.
#
# What it changes on the machine (the window shows this list again before the first prompt):
#  - C:\Program Files\Rerun\rerun-helper.exe: the TEST-KEY helper (a debug build with the feature
#    test-key, which trusts the published index test key), installed with prompt 1 and removed
#    with prompt 5, also after a failure (scripts/dev-helper-common.ps1);
#  - one outbound block rule of group "Rerun" in Windows Defender Firewall, named
#    "Rerun - dev-firewall - <transaction>-000", for a file game.exe that is no program (a minimal
#    PE header without code, it cannot run) in a fresh folder below target\rerun-fs-contract; it
#    exists only between prompt 3 (apply) and prompt 4 (revert). Prompt 5 also removes any rule
#    whose name starts with "Rerun - dev-firewall - " (left by an aborted run);
#  - test folders below target\rerun-fs-contract (the fake LocalAppData with Rerun's journal,
#    plans, request files and the test-key index; the game folder), removed by the test itself.
# Nothing in the real LocalAppData\Rerun, no registry value, no other firewall rule.
#
# Steps:
#  1. builds the test-key helper and the rerun-core test binary with the feature test-key;
#  2. PROMPT 1 of 5 (Windows PowerShell): installs the helper, then checks owner and DACL;
#  3. PROMPT 2 of 5 (rerun-helper.exe) - click NO: the test
#     sys::win::tests::dev_firewall::dev_helper_firewall_round_trip with RERUN_DEV_FIREWALL=decline:
#     the apply is rolled back (Declined; exit 4 in the CLI), no rule, the transaction closed;
#  4. PROMPTS 3 and 4 of 5 (rerun-helper.exe twice) - click YES both times: the same test with
#     RERUN_DEV_FIREWALL=accept: apply (prompt 3) adds the rule, the test reads it back (group
#     Rerun, outbound, block, the dummy game.exe) and verify says After; revert (prompt 4) removes
#     it, verify of the firewall finds none;
#  5. PROMPT 5 of 5 (Windows PowerShell): removes C:\Program Files\Rerun and any rule named
#     "Rerun - dev-firewall - *", also after a failure; then checks, without elevation, that the
#     folder, every such rule and the test folders are gone;
#  6. prints a summary (also copied to the clipboard).
#
# After an abort (Ctrl+C or a closed window) run the script again: it takes over an admin-only
# leftover helper folder of this build, and prompt 5 removes a leftover rule.

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'dev-helper-common.ps1')
$script:HelperTitle = 'Rerun DEV firewall round trip'
$testName = 'sys::win::tests::dev_firewall::dev_helper_firewall_round_trip'
$rulePrefix = 'Rerun - dev-firewall - '

# The rules of this test (read without elevation: a standard user can read the rules, docs/09).
function Get-DevRules {
    @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.DisplayName -like "$rulePrefix*" })
}

# Runs the [DEV] test in mode $mode; returns its verdict line.
function Invoke-FirewallTest([string]$mode) {
    $env:RERUN_DEV_FIREWALL = $mode
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $lines = @()
    try {
        Push-Location $repo
        & cargo test -p rerun-core --lib --features test-key --locked -- --ignored --exact $testName --nocapture --test-threads=1 2>&1 |
            ForEach-Object { $line = "$_"; Write-Host $line; $lines += $line }
        $code = $LASTEXITCODE
    } finally {
        Pop-Location
        $ErrorActionPreference = $previous
        Remove-Item Env:RERUN_DEV_FIREWALL -ErrorAction SilentlyContinue
    }
    $result = $lines | Where-Object { $_ -like 'RERUN_DEV_FW_RESULT:*' } | Select-Object -Last 1
    # The panic line and the message on the line after it.
    $panic = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match 'panicked at') {
            $panic += $lines[$i]
            if ($i + 1 -lt $lines.Count) { $panic += $lines[$i + 1] }
            break
        }
    }
    if ($code -eq 0 -and $result -like '*PASS*') {
        return ($result -replace '^RERUN_DEV_FW_RESULT: ', '')
    }
    $seen = ($lines | Where-Object { $_ -like 'RERUN_DEV_FW_*' }) -join ' | '
    return "FAIL ($mode): test exit $code; $seen; $($panic -join ' ')"
}

# The elevated part of prompt 5 besides the helper folder: every rule of this test's prefix.
$removeRules = @"
Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { `$_.DisplayName -like '$rulePrefix*' } | Remove-NetFirewallRule -ErrorAction SilentlyContinue
"@

# --- 0. preconditions ----------------------------------------------------------------------
Title 'checking preconditions'
Assert-NotElevated
$paths = Get-HelperPaths
$before = @(Get-DevRules)
Write-Host ''
Write-Host 'This test changes, and removes again:' -ForegroundColor Yellow
Write-Host "  - $($paths.Exe): the TEST-KEY helper (prompt 1 installs it, prompt 5 removes it)"
Write-Host "  - one outbound block rule of group Rerun named '$rulePrefix<transaction>-000' for a dummy game.exe"
Write-Host '    (no program) below target\rerun-fs-contract, only between prompt 3 (apply) and prompt 4 (revert)'
Write-Host '  - test folders below target\rerun-fs-contract (journal, plans, index, game), removed by the test'
Write-Host 'Prompts: 1 YES (install), 2 NO (the declined apply), 3 and 4 YES (apply, revert), 5 YES (removal).' -ForegroundColor Yellow
if ($before.Count -gt 0) { Write-Host "note: $($before.Count) rule(s) of an earlier run exist; prompt 5 removes them" }

$aclVerdict = 'FAIL: not checked'
$declined = 'FAIL: not run'
$accepted = 'FAIL: not run'
$removal = 'FAIL: not run'
$stopped = $null
try {
    # --- 1. builds -------------------------------------------------------------------------
    $build = Build-Helper $repo -TestKey
    Title 'building the rerun-core test binary with the feature test-key (about 2 minutes)'
    Push-Location $repo
    try {
        & cargo test -p rerun-core --lib --features test-key --locked --no-run
        if ($LASTEXITCODE -ne 0) { Fail "cargo test --no-run failed ($LASTEXITCODE)" }
    } finally { Pop-Location }

    # --- 2. install (prompt 1 of 5) --------------------------------------------------------
    Install-Helper $paths $build 'PROMPT 1 of 5'
    $aclVerdict = Get-AclVerdict $paths

    # --- 3. the declined apply (prompt 2 of 5) ---------------------------------------------
    Title 'PROMPT 2 of 5: rerun-helper.exe (unknown publisher) - click NO'
    $declined = Invoke-FirewallTest 'decline'

    # --- 4. apply and revert (prompts 3 and 4 of 5) ----------------------------------------
    Title 'PROMPTS 3 and 4 of 5: rerun-helper.exe twice (apply, then revert) - click YES both times'
    $accepted = Invoke-FirewallTest 'accept'
} catch {
    $stopped = $_.Exception.Message
} finally {
    # --- 5. removal (prompt 5 of 5), always: the helper and any rule of this test -----------
    $removal = Remove-Helper $paths 'PROMPT 5 of 5' $removeRules
}

# --- 6. the self-check, without elevation --------------------------------------------------
$left = 'FAIL: not checked'
try {
    $rules = @(Get-DevRules)
    $folders = @()
    $base = Join-Path $repo 'target\rerun-fs-contract'
    if (Test-Path -LiteralPath $base) { $folders = @(Get-ChildItem -LiteralPath $base -Directory | Where-Object { $_.Name -like '*-dev-fw' }) }
    if ($rules.Count -gt 0) {
        $left = "FAIL: rule(s) left: $(($rules | ForEach-Object { $_.DisplayName }) -join '; ') (remove them in wf.msc, outbound rules, group Rerun)"
    } elseif ($folders.Count -gt 0) {
        $left = "FAIL: test folder(s) left: $(($folders | ForEach-Object { $_.FullName }) -join '; ')"
    } else {
        $left = 'PASS: no rule named Rerun - dev-firewall - * and no test folder left'
    }
} catch {
    $left = "FAIL: the firewall could not be read for the check: $($_.Exception.Message)"
}

# --- summary -------------------------------------------------------------------------------
$parts = @($aclVerdict, $declined, $accepted, $removal, $left)
$overall = if ($stopped) {
    "FAIL: stopped: $stopped"
} elseif (@($parts | Where-Object { $_ -notlike 'PASS*' }).Count -eq 0) {
    'PASS: declined apply rolled back, apply added the rule, revert removed it; everything removed'
} else {
    'FAIL: see the lines above'
}
$summary = @(
    "Rerun DEV firewall round trip (P4-5b), $(Get-Date -Format 'yyyy-MM-dd HH:mm')",
    "Windows build: $([Environment]::OSVersion.Version)",
    "installed (test-key helper): $($paths.Exe)",
    "admin-only check: $aclVerdict",
    "declined apply: $declined",
    "apply and revert: $accepted",
    "removal: $removal",
    "left behind: $left",
    "RESULT: $overall"
) -join [Environment]::NewLine
Write-Host ''
Write-Host $summary
try { Set-Clipboard -Value $summary } catch { }
Title "DONE: $($overall.Split(':')[0]) (summary in the clipboard)"
