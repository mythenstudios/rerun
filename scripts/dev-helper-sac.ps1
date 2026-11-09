# [DEV] measurement for the elevated helper on the developer machine (docs/09-testing.md,
# "Elevated helper on the developer machine"; ADR 0023 section 14, audit A4 S12): does Smart App
# Control let the unsigned rerun-helper.exe run from C:\Program Files\Rerun?
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\dev-helper-sac.ps1
#
# Run it in a normal (not administrator) PowerShell in the repository. About 3 minutes (most of
# it the release build). Three administrator prompts, each named in the window title:
#  1. builds the release helper (cargo build -p rerun-helper --release; the P4-2a scaffold, which
#     changes nothing: it drops its privileges, checks its elevation and refuses every request);
#  2. PROMPT 1 of 3 (Windows PowerShell, by its full path): installs the helper into
#     C:\Program Files\Rerun (scripts/dev-helper-common.ps1, Install-Helper: refuses an existing
#     folder that is not admin-only, hashes the copy itself); then the script checks owner and
#     DACL of the folder and the file;
#  3. starts the installed helper without elevation: expected exit 0x52120000
#     (Refused(NotElevated)), or os error 4551 if Smart App Control blocks it;
#  4. PROMPT 2 of 3 (rerun-helper.exe, "unknown publisher"): starts it through the runas verb:
#     expected exit 0x52110000 (Refused(Usage)), or 4551; declining is recorded as such (1223);
#  5. PROMPT 3 of 3 (Windows PowerShell): removes C:\Program Files\Rerun again, always, also
#     after a failure, and checks that it is gone;
#  6. prints a summary (also copied to the clipboard): Smart App Control state, owner and the
#     admin-only check of the installed file, both results, the removal, and the Code Integrity
#     events of the run if readable.
#
# What it changes on the machine: only C:\Program Files\Rerun with rerun-helper.exe, created in
# step 2 and removed in step 5. Nothing is left behind (unless the removal prompt is declined:
# the summary then says FAIL and names the folder to delete). It never asks a question.
#
# After an abort (Ctrl+C or a closed window) run the script again; it takes over an admin-only
# leftover folder (empty, or holding only the helper of this same build) and removes it at the
# end. Anything else in the Rerun folder of Program Files is left alone and named
# (dev-helper-common.ps1).

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$started = Get-Date
. (Join-Path $PSScriptRoot 'dev-helper-common.ps1')

# Starts $path and waits; returns the exit code or the Win32 error of the start.
function Start-Measured([string]$path, [switch]$Elevate) {
    try {
        if ($Elevate) {
            $p = Start-Process -FilePath $path -ArgumentList '--scaffold' -Verb RunAs -PassThru -Wait
        } else {
            $p = Start-Process -FilePath $path -ArgumentList '--scaffold' -PassThru -Wait
        }
        return @{ Code = $p.ExitCode; Error = $null }
    } catch {
        $e = $_.Exception
        while ($e -and -not ($e -is [System.ComponentModel.Win32Exception])) { $e = $e.InnerException }
        if ($e) { return @{ Code = $null; Error = $e.NativeErrorCode } }
        return @{ Code = $null; Error = -1; Message = $_.Exception.Message }
    }
}

function Verdict($r, [int]$expected, [string]$name) {
    if ($null -ne $r.Code) {
        if ($r.Code -eq $expected) { return "PASS: exit $(Hex $r.Code) = $name" }
        return "FAIL: exit $(Hex $r.Code), expected $(Hex $expected) ($name)"
    }
    switch ($r.Error) {
        $ErrorSacBlocked { return "BLOCKED: os error 4551 (Smart App Control / application control policy)" }
        $ErrorCancelled { return "DECLINED: the administrator prompt was declined (1223)" }
        default { return "FAIL: start error $($r.Error) $($r.Message)" }
    }
}

# --- 0. preconditions ----------------------------------------------------------------------
Title 'checking preconditions'
Assert-NotElevated
$paths = Get-HelperPaths
$sac = '(unreadable)'
try {
    $v = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState -ErrorAction Stop
    $sac = switch ($v.VerifiedAndReputablePolicyState) { 0 { '0 (off)' } 1 { '1 (enforce)' } 2 { '2 (evaluation)' } default { "$_" } }
} catch { }

$installedHash = '(not installed)'
$owner = '(unreadable)'
$aclVerdict = 'FAIL: not checked'
$plainVerdict = 'FAIL: not run'
$elevatedVerdict = 'FAIL: not run'
$removal = 'FAIL: not run'
$stopped = $null
try {
    # --- 1. build, 2. install (prompt 1 of 3) ------------------------------------------------
    $build = Build-Helper $repo
    Install-Helper $paths $build 'PROMPT 1 of 3'
    $installedHash = $build.Hash
    try { $owner = (Get-Acl -LiteralPath $paths.Exe).Owner } catch { }
    $aclVerdict = Get-AclVerdict $paths

    # --- 3. non-elevated start ---------------------------------------------------------------
    Title 'starting the installed helper without elevation'
    $plainVerdict = Verdict (Start-Measured $paths.Exe) $NotElevated 'Refused(NotElevated)'

    # --- 4. runas start (prompt 2 of 3) ------------------------------------------------------
    Title 'PROMPT 2 of 3: rerun-helper.exe (unknown publisher) - click YES'
    $elevatedVerdict = Verdict (Start-Measured $paths.Exe -Elevate) $Usage 'Refused(Usage)'
} catch {
    $stopped = $_.Exception.Message
} finally {
    # --- 5. removal (prompt 3 of 3), always --------------------------------------------------
    $removal = Remove-Helper $paths 'PROMPT 3 of 3'
}

# --- 6. summary ----------------------------------------------------------------------------
$events = '(log not readable without administrator rights)'
try {
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; StartTime = $started } -ErrorAction Stop |
        Where-Object { $_.Message -match 'rerun-helper' }
    $events = if ($ev) { ($ev | ForEach-Object { "event $($_.Id) at $($_.TimeCreated.ToString('HH:mm:ss'))" }) -join '; ' } else { 'none for rerun-helper.exe' }
} catch [Exception] {
    if ($_.Exception.Message -match 'No events') { $events = 'none' }
}

$overall = if ($stopped) {
    "FAIL: stopped: $stopped"
} elseif ($plainVerdict -like 'PASS*' -and $elevatedVerdict -like 'PASS*') {
    'PASS: Smart App Control lets the unsigned helper run; the [DEV] helper steps can run on this machine'
} elseif ($plainVerdict -like 'BLOCKED*' -or $elevatedVerdict -like 'BLOCKED*') {
    'BLOCKED: Smart App Control blocks the unsigned helper; the [DEV] helper steps need a VM (ADR 0023 section 14)'
} else {
    'FAIL: see the lines above'
}
if (-not $stopped -and $aclVerdict -notlike 'PASS*' -and $overall -notlike 'FAIL*') {
    $overall = "FAIL: the install folder is not admin-only (Smart App Control: $($overall.Split(':')[0]))"
}
if ($removal -like 'FAIL*' -and $overall -notlike 'FAIL*') { $overall = "FAIL: $removal" }
$summary = @(
    "Rerun DEV helper measurement (A4 S12), $(Get-Date -Format 'yyyy-MM-dd HH:mm')",
    "Windows build: $([Environment]::OSVersion.Version)",
    "Smart App Control (VerifiedAndReputablePolicyState): $sac",
    "installed: $($paths.Exe)",
    "SHA-256: $installedHash (equal to the build)",
    "owner: $owner",
    "admin-only check: $aclVerdict",
    "non-elevated start: $plainVerdict",
    "runas start: $elevatedVerdict",
    "removal: $removal",
    "Code Integrity events: $events",
    "RESULT: $overall"
) -join [Environment]::NewLine
Write-Host ''
Write-Host $summary
try { Set-Clipboard -Value $summary } catch { }
Title "DONE: $($overall.Split(':')[0]) (summary in the clipboard)"
