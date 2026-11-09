# [DEV] measurement for the elevated helper on the developer machine (docs/09-testing.md,
# "Elevated helper on the developer machine"; ADR 0023 section 14, audit A4 S12): does Smart App
# Control let the unsigned rerun-helper.exe run from C:\Program Files\Rerun?
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\dev-helper-sac.ps1
#
# Run it in a normal (not administrator) PowerShell in the repository. About 3 minutes (most of
# it the release build). Two administrator prompts, each named in the window title:
#  1. builds the release helper (cargo build -p rerun-helper --release; the P4-2a scaffold, which
#     changes nothing: it drops its privileges, checks its elevation and refuses every request);
#  2. prompt 1 of 2 (Windows PowerShell, by its full path): the elevated part refuses a
#     C:\Program Files\Rerun that exists and is not admin-only (exit 3, nothing copied), else
#     creates it, copies the helper, hashes the copy itself and removes it if its SHA-256 is not
#     the built file's (exit 2); then the script checks owner and DACL of the folder and the
#     file (owner Administrators, SYSTEM or TrustedInstaller, no write right for anyone else);
#  3. starts the installed helper without elevation: expected exit 0x52120000
#     (Refused(NotElevated)), or os error 4551 if Smart App Control blocks it;
#  4. prompt 2 of 2 (rerun-helper.exe, "unknown publisher"): starts it through the runas verb:
#     expected exit 0x52110000 (Refused(Usage)), or 4551; declining the prompt is recorded as
#     such (1223);
#  5. prints a summary (also copied to the clipboard): Smart App Control state, owner and the
#     admin-only check of the installed file, both results, and the Code Integrity events of
#     the run if readable.
#
# It never asks a question. The helper stays installed (P4-2b uses it for the dialog test); to
# remove it, delete C:\Program Files\Rerun in an administrator PowerShell.

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$started = Get-Date

# ADR 0023 section 7, bound to rerun_core::elevate::HelperExit by elevate::tests.
$NotElevated = 0x52120000
$Usage = 0x52110000
$ErrorCancelled = 1223
$ErrorSacBlocked = 4551

function Title([string]$text) {
    $Host.UI.RawUI.WindowTitle = "Rerun DEV helper - $text"
    Write-Host ''
    Write-Host ">> $text" -ForegroundColor Cyan
}

function Fail([string]$text) {
    Title "STOPPED: $text"
    throw $text
}

function Hex([int]$code) {
    '0x{0:X8}' -f $code
}

# Starts $path and waits; returns "exit 0x..." or "error <n>" (the Win32 error of the start).
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
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail 'start this script from a normal (not administrator) PowerShell'
}
if (-not [Environment]::Is64BitProcess) { Fail 'start it from a 64-bit PowerShell' }
# The known folder (SHGetKnownFolderPath through .NET), not the environment.
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
if (-not $programFiles) { Fail 'Program Files folder not found' }
$installDir = Join-Path $programFiles 'Rerun'
$installed = Join-Path $installDir 'rerun-helper.exe'
$sac = '(unreadable)'
try {
    $v = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState -ErrorAction Stop
    $sac = switch ($v.VerifiedAndReputablePolicyState) { 0 { '0 (off)' } 1 { '1 (enforce)' } 2 { '2 (evaluation)' } default { "$_" } }
} catch { }

# --- 1. build ------------------------------------------------------------------------------
Title 'building the release helper (about 1 minute)'
Push-Location $repo
try {
    & cargo build -p rerun-helper --release --locked
    if ($LASTEXITCODE -ne 0) { Fail "cargo build failed ($LASTEXITCODE)" }
} finally { Pop-Location }
$built = Join-Path $repo 'target\release\rerun-helper.exe'
if (-not (Test-Path -LiteralPath $built -PathType Leaf)) { Fail "not built: $built" }
$builtHash = (Get-FileHash -LiteralPath $built -Algorithm SHA256).Hash

# --- 2. copy (prompt 1 of 2) ---------------------------------------------------------------
# The admin-only rule of ADR 0023 section 2 (ADR 0007 "Elevation"), checked here and in the
# elevated copy: owner Administrators, SYSTEM or TrustedInstaller; no Allow ACE granting a write
# right to any other SID (inherit-only CREATOR OWNER ACEs do not apply to the object itself).
# Returns '' when admin-only, else what is wrong.
$aclCheck = @'
function Test-AdminOnly([string]$path) {
    $admins = @('S-1-5-32-544', 'S-1-5-18', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    # WriteData/AddFile, AppendData/AddSubdirectory, WriteEA, DeleteChild, WriteAttributes,
    # Delete, WriteDAC, WriteOwner, GenericAll, GenericWrite.
    $write = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
    $sidType = [System.Security.Principal.SecurityIdentifier]
    $acl = Get-Acl -LiteralPath $path
    $problems = @()
    $owner = $acl.GetOwner($sidType).Value
    if ($admins -notcontains $owner) { $problems += "owner $owner" }
    foreach ($ace in $acl.GetAccessRules($true, $true, $sidType)) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        $sid = $ace.IdentityReference.Value
        if ($admins -contains $sid) { continue }
        # PropagationFlags.InheritOnly = 2.
        if ($sid -eq 'S-1-3-0' -and (([int]$ace.PropagationFlags -band 2) -ne 0)) { continue }
        if (([int]$ace.FileSystemRights) -band $write) { $problems += "$sid may write ($($ace.FileSystemRights))" }
    }
    return ($problems -join '; ')
}
'@
. ([scriptblock]::Create($aclCheck))

Title 'PROMPT 1 of 2: allow Windows PowerShell to copy the helper to Program Files\Rerun'
# Paths go into the elevated command as single-quoted literals: double every quote.
function Quote([string]$s) { "'" + ($s -replace "'", "''") + "'" }
$copy = $aclCheck + @"

`$ErrorActionPreference = 'Stop'
`$dir = $(Quote $installDir)
`$dst = $(Quote $installed)
try {
    # A folder that exists already must be admin-only before anything goes into it.
    if (Test-Path -LiteralPath `$dir) {
        if (Test-AdminOnly `$dir) { exit 3 }
    } else {
        New-Item -ItemType Directory -Path `$dir | Out-Null
    }
    Copy-Item -LiteralPath $(Quote $built) -Destination `$dst -Force
    if ((Get-FileHash -LiteralPath `$dst -Algorithm SHA256).Hash -ne '$builtHash') {
        Remove-Item -LiteralPath `$dst -Force
        exit 2
    }
    exit 0
} catch { exit 1 }
"@
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($copy))
$powershell = Join-Path $PSHOME 'powershell.exe'
try {
    $p = Start-Process -FilePath $powershell -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) -Verb RunAs -PassThru -Wait -WindowStyle Hidden
} catch {
    Fail "the copy was not started (prompt declined?): $($_.Exception.Message)"
}
switch ($p.ExitCode) {
    0 { }
    2 { Fail 'SHA-256 differs, installed copy removed' }
    3 { Fail "$installDir exists and is not admin-only: nothing copied (fix or delete it as administrator)" }
    default { Fail "the elevated copy failed (exit $($p.ExitCode))" }
}
if (-not (Test-Path -LiteralPath $installed -PathType Leaf)) { Fail "not installed: $installed" }
$installedHash = (Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash
if ($installedHash -ne $builtHash) { Fail 'the installed helper changed after the elevated check (SHA-256 differs)' }
$owner = '(unreadable)'
try { $owner = (Get-Acl -LiteralPath $installed).Owner } catch { }
$aclProblems = @()
foreach ($path in @($installDir, $installed)) {
    try {
        $why = Test-AdminOnly $path
        if ($why) { $aclProblems += "${path}: $why" }
    } catch {
        $aclProblems += "${path}: unreadable ($($_.Exception.Message))"
    }
}
$aclVerdict = if ($aclProblems.Count -eq 0) {
    'PASS: folder and file admin-only (owner and DACL)'
} else {
    'FAIL: not admin-only: ' + ($aclProblems -join ' | ')
}

# --- 3. non-elevated start -----------------------------------------------------------------
Title 'starting the installed helper without elevation'
$plain = Start-Measured $installed
$plainVerdict = Verdict $plain $NotElevated 'Refused(NotElevated)'

# --- 4. runas start (prompt 2 of 2) --------------------------------------------------------
Title 'PROMPT 2 of 2: rerun-helper.exe (unknown publisher) - allow it'
$elevated = Start-Measured $installed -Elevate
$elevatedVerdict = Verdict $elevated $Usage 'Refused(Usage)'

# --- 5. summary ----------------------------------------------------------------------------
$events = '(log not readable without administrator rights)'
try {
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; StartTime = $started } -ErrorAction Stop |
        Where-Object { $_.Message -match 'rerun-helper' }
    $events = if ($ev) { ($ev | ForEach-Object { "event $($_.Id) at $($_.TimeCreated.ToString('HH:mm:ss'))" }) -join '; ' } else { 'none for rerun-helper.exe' }
} catch [Exception] {
    if ($_.Exception.Message -match 'No events') { $events = 'none' }
}

$overall = if ($plainVerdict -like 'PASS*' -and $elevatedVerdict -like 'PASS*') {
    'PASS: Smart App Control lets the unsigned helper run; the [DEV] helper steps can run on this machine'
} elseif ($plainVerdict -like 'BLOCKED*' -or $elevatedVerdict -like 'BLOCKED*') {
    'BLOCKED: Smart App Control blocks the unsigned helper; the [DEV] helper steps need a VM (ADR 0023 section 14)'
} else {
    'FAIL: see the lines above'
}
if ($aclVerdict -notlike 'PASS*' -and $overall -notlike 'FAIL*') {
    $overall = "FAIL: the install folder is not admin-only (Smart App Control: $($overall.Split(':')[0]))"
}
$summary = @(
    "Rerun DEV helper measurement (A4 S12), $(Get-Date -Format 'yyyy-MM-dd HH:mm')",
    "Windows build: $([Environment]::OSVersion.Version)",
    "Smart App Control (VerifiedAndReputablePolicyState): $sac",
    "installed: $installed",
    "SHA-256: $installedHash (equal to the build)",
    "owner: $owner",
    "admin-only check: $aclVerdict",
    "non-elevated start: $plainVerdict",
    "runas start: $elevatedVerdict",
    "Code Integrity events: $events",
    "RESULT: $overall"
) -join [Environment]::NewLine
Write-Host ''
Write-Host $summary
try { Set-Clipboard -Value $summary } catch { }
Title "DONE: $($overall.Split(':')[0]) (summary in the clipboard)"
