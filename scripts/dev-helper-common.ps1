# Shared part of the [DEV] helper hand tests (docs/09-testing.md, "Elevated helper on the
# developer machine"; ADR 0023 section 14): dot-sourced by scripts/dev-helper-sac.ps1 and
# scripts/dev-helper-uac.ps1, never run on its own.
#
# What it changes on the machine, and only through the two elevated steps below, each started
# by its full path and named in the window title:
#  - Install-Helper: creates C:\Program Files\Rerun (the known folder, not the environment) and
#    copies the freshly built release rerun-helper.exe into it. The elevated part treats an
#    existing folder as foreign (exit 3: nothing copied, nothing removed) unless it is the
#    leftover of an aborted run of this build: no reparse point, admin-only, empty or holding
#    only rerun-helper.exe (no link) with the fresh build's SHA-256. It never copies over an
#    existing file, hashes the copy itself and removes it again if its SHA-256 is not the
#    build's (exit 2). Every elevated body first sets PSModulePath to $PSHOME\Modules.
#  - After an abort (Ctrl+C or a closed window) run the script again; it takes over an
#    admin-only leftover folder and removes it at the end.
#  - Remove-Helper: deletes rerun-helper.exe and then the folder (only if it is empty, never
#    through a link: a folder or file that is a reparse point is refused, exit 3). The callers
#    run it in a `finally`, so the helper is removed also after a failure, and then check that
#    the folder is gone.
# Windows PowerShell 5.1.

# ADR 0023 section 7, bound to rerun_core::elevate::HelperExit by elevate::tests.
$NotElevated = 0x52120000
$Usage = 0x52110000
$ErrorCancelled = 1223
$ErrorSacBlocked = 4551

$script:HelperTitle = 'Rerun DEV helper'
$script:HelperForeign = $false

function Title([string]$text) {
    $Host.UI.RawUI.WindowTitle = "$script:HelperTitle - $text"
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

# The first line of every elevated body: modules only from Windows PowerShell's own folder,
# never from the user's profile (a user-writable module path would run code elevated).
$script:ElevatedPrelude = @'
$env:PSModulePath = Join-Path $PSHOME 'Modules'

'@

# Paths go into an elevated command as single-quoted literals: double every quote.
function Quote([string]$s) { "'" + ($s -replace "'", "''") + "'" }

# The admin-only rule of ADR 0023 section 2 (ADR 0007 "Elevation"), the same as
# rerun_core::policy::root::admin_only: owner Administrators, SYSTEM or TrustedInstaller; no
# Allow ACE that applies to the object grants a write right to any other SID (inherit-only ACEs
# do not apply to the object itself). Returns '' when admin-only, else what is wrong.
$script:AclCheck = @'
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
        # PropagationFlags.InheritOnly = 2.
        if (([int]$ace.PropagationFlags -band 2) -ne 0) { continue }
        $sid = $ace.IdentityReference.Value
        if ($admins -contains $sid) { continue }
        if (([int]$ace.FileSystemRights) -band $write) { $problems += "$sid may write ($($ace.FileSystemRights))" }
    }
    return ($problems -join '; ')
}
'@
. ([scriptblock]::Create($script:AclCheck))

# Program Files\Rerun and the helper in it, from the known folder (SHGetKnownFolderPath through
# .NET), never the environment.
function Get-HelperPaths {
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    if (-not $programFiles) { Fail 'Program Files folder not found' }
    $dir = Join-Path $programFiles 'Rerun'
    return @{ Dir = $dir; Exe = (Join-Path $dir 'rerun-helper.exe') }
}

function Assert-NotElevated {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Fail 'start this script from a normal (not administrator) PowerShell'
    }
    if (-not [Environment]::Is64BitProcess) { Fail 'start it from a 64-bit PowerShell' }
}

# Builds the release helper (the P4-2a scaffold: it drops its privileges, checks its elevation
# and refuses every request; it changes nothing) and returns its path and SHA-256.
function Build-Helper([string]$repo) {
    Title 'building the release helper (about 1 minute)'
    Push-Location $repo
    try {
        & cargo build -p rerun-helper --release --locked
        if ($LASTEXITCODE -ne 0) { Fail "cargo build failed ($LASTEXITCODE)" }
    } finally { Pop-Location }
    $built = Join-Path $repo 'target\release\rerun-helper.exe'
    if (-not (Test-Path -LiteralPath $built -PathType Leaf)) { Fail "not built: $built" }
    return @{ Path = $built; Hash = (Get-FileHash -LiteralPath $built -Algorithm SHA256).Hash }
}

# Runs $body elevated in a hidden Windows PowerShell (by its full path); returns its exit code.
# A declined prompt throws.
function Invoke-Elevated([string]$body) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
    $powershell = Join-Path $PSHOME 'powershell.exe'
    $p = Start-Process -FilePath $powershell -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) -Verb RunAs -PassThru -Wait -WindowStyle Hidden
    return $p.ExitCode
}

# The elevated install (one prompt, named by $prompt in the window title). Throws on any
# failure. Sets $script:HelperForeign when the folder existed before and is not admin-only (exit
# 3): then it is not the test's, and the removal leaves it alone.
function Install-Helper($paths, $build, [string]$prompt) {
    Title "${prompt}: allow Windows PowerShell to install the helper to Program Files\Rerun"
    $body = $script:ElevatedPrelude + $script:AclCheck + @"

`$ErrorActionPreference = 'Stop'
`$dir = $(Quote $paths.Dir)
`$dst = $(Quote $paths.Exe)
`$link = [IO.FileAttributes]::ReparsePoint
try {
    # An existing folder is taken over only if it is the leftover of an aborted run of this
    # build: no reparse point, admin-only, holding nothing or exactly rerun-helper.exe (no link)
    # with the fresh build's SHA-256. Anything else is foreign (exit 3): nothing is copied over
    # it and nothing of it is removed.
    if (Test-Path -LiteralPath `$dir) {
        if (((Get-Item -LiteralPath `$dir -Force).Attributes -band `$link) -ne 0) { exit 3 }
        if (Test-AdminOnly `$dir) { exit 3 }
        foreach (`$i in @(Get-ChildItem -LiteralPath `$dir -Force)) {
            if (`$i.Name -ne 'rerun-helper.exe') { exit 3 }
        }
        if (Test-Path -LiteralPath `$dst) {
            if (((Get-Item -LiteralPath `$dst -Force).Attributes -band `$link) -ne 0) { exit 3 }
            if ((Get-FileHash -LiteralPath `$dst -Algorithm SHA256).Hash -ne '$($build.Hash)') { exit 3 }
            exit 0
        }
    } else {
        New-Item -ItemType Directory -Path `$dir | Out-Null
    }
    Copy-Item -LiteralPath $(Quote $build.Path) -Destination `$dst
    if ((Get-FileHash -LiteralPath `$dst -Algorithm SHA256).Hash -ne '$($build.Hash)') {
        Remove-Item -LiteralPath `$dst -Force
        exit 2
    }
    exit 0
} catch { exit 1 }
"@
    try {
        $code = Invoke-Elevated $body
    } catch {
        Fail "the install was not started (prompt declined?): $($_.Exception.Message)"
    }
    switch ($code) {
        0 { }
        2 { Fail 'SHA-256 differs, installed copy removed' }
        3 { $script:HelperForeign = $true; Fail "$($paths.Dir) existed and is not this test's (a link, not admin-only, other content, or a helper of another build): nothing copied, nothing removed (check and delete it as administrator)" }
        default { Fail "the elevated install failed (exit $code)" }
    }
    if (-not (Test-Path -LiteralPath $paths.Exe -PathType Leaf)) { Fail "not installed: $($paths.Exe)" }
    if ((Get-FileHash -LiteralPath $paths.Exe -Algorithm SHA256).Hash -ne $build.Hash) {
        Fail 'the installed helper changed after the elevated check (SHA-256 differs)'
    }
}

# Owner and DACL of the installed folder and file; 'PASS: ...' or 'FAIL: ...'.
function Get-AclVerdict($paths) {
    $problems = @()
    foreach ($path in @($paths.Dir, $paths.Exe)) {
        try {
            $why = Test-AdminOnly $path
            if ($why) { $problems += "${path}: $why" }
        } catch {
            $problems += "${path}: unreadable ($($_.Exception.Message))"
        }
    }
    if ($problems.Count -eq 0) { return 'PASS: folder and file admin-only (owner and DACL)' }
    return 'FAIL: not admin-only: ' + ($problems -join ' | ')
}

# The elevated removal (one prompt, named by $prompt), then the check that the folder is gone.
# Returns 'PASS: ...' or 'FAIL: ...'; never throws (it runs in a `finally`).
function Remove-Helper($paths, [string]$prompt) {
    if ($script:HelperForeign) { return "SKIPPED: $($paths.Dir) existed before the test and is not admin-only; left alone" }
    if (-not (Test-Path -LiteralPath $paths.Dir)) { return "PASS: $($paths.Dir) is gone (nothing to remove)" }
    Title "${prompt}: allow Windows PowerShell to remove Program Files\Rerun again"
    $body = $script:ElevatedPrelude + @"
`$ErrorActionPreference = 'Stop'
`$dir = $(Quote $paths.Dir)
`$dst = $(Quote $paths.Exe)
`$link = [IO.FileAttributes]::ReparsePoint
try {
    if (Test-Path -LiteralPath `$dir) {
        # Never through a link: a folder or file that is a reparse point is left alone.
        if (((Get-Item -LiteralPath `$dir -Force).Attributes -band `$link) -ne 0) { exit 3 }
        if (Test-Path -LiteralPath `$dst) {
            if (((Get-Item -LiteralPath `$dst -Force).Attributes -band `$link) -ne 0) { exit 3 }
            Remove-Item -LiteralPath `$dst -Force
        }
        # Only an empty folder: anything else in it is not the test's.
        [IO.Directory]::Delete(`$dir, `$false)
    }
    exit 0
} catch { exit 1 }
"@
    try {
        $code = Invoke-Elevated $body
    } catch {
        return "FAIL: the removal was not started (prompt declined?); delete $($paths.Dir) in an administrator PowerShell"
    }
    if (Test-Path -LiteralPath $paths.Dir) {
        return "FAIL: $($paths.Dir) is still there (removal exit $code); delete it in an administrator PowerShell"
    }
    return "PASS: $($paths.Dir) removed and gone"
}
