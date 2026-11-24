# Removes Rerun (alpha) again (P5-13d, ADR 0030): the installed copy in
# %LOCALAPPDATA%\Programs\Rerun or a portable copy, always the folder this script is in.
# Windows PowerShell 5.1, in a normal (not administrator) 64-bit PowerShell window:
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\Programs\Rerun\uninstall.ps1" [-KeepData]
#
# Step by step (each named in the window title):
#  1. Checks, nothing changed yet: not elevated, 64-bit; this folder is an installed copy
#     (install.json, only in %LOCALAPPDATA%\Programs\Rerun) or a portable one (payload.json),
#     not inside the data folder; no reparse point on the way; no Rerun program runs anywhere
#     (rerun-app, rerun, rerun-launch by name, whatever their folder: all copies share the data
#     folder, and a game Steam started with Rerun's launch option runs through rerun-launch.exe;
#     a path that cannot be read counts as running).
#  2. rerun.exe uninstall-check (only if rerun.exe is the file the manifest names): exit 5 =
#     changes of Rerun are still open; they are listed and the script stops with nothing
#     removed (undo them in Rerun, or forget them; the journal and backups an undo needs are in
#     the data folder). With -KeepData it goes on and keeps them for the next install (update).
#     Any other failure (Smart App Control included) stops too: Rerun cannot check.
#  3. Preview (rule 5): what uninstall-check warns about (games Steam may still start through
#     rerun-launch.exe: remove their launch option in Steam), the program files that go (only
#     files with the SHA-256 of the manifest; changed or foreign files stay and are named), the
#     Start-menu shortcut (only if it points to this folder's rerun-app.exe), Rerun's data folder
#     %LOCALAPPDATA%\Rerun with its size and top-level entries (kept with -KeepData, and kept
#     when this is a portable copy while an installed copy exists: they share it). One Enter
#     removes; closing the window cancels with nothing changed.
#  4. Removes the shortcut, then checks both again (no Rerun program runs, uninstall-check still
#     0, or 0 or 5 with -KeepData; otherwise it stops there), then the data folder (never
#     through a link: a reparse point anywhere in it stops before anything is removed, and each
#     entry is checked again while it is removed), the program files, the manifest, this script,
#     and the folder if it is empty then. Between the second check and the removal a few seconds
#     remain in which a Rerun started meanwhile is not seen (docs/06 #33).
#
# -Yes is for the Windows Sandbox suite only (scripts/sandbox-install.ps1): it skips the two
# Enter prompts and is refused unless RERUN_SANDBOX or RERUN_CI_SANDBOX is 1. Never the default;
# the window title still names every step.
#
# It never removes anything outside these paths and never touches Steam, a game folder, the
# registry or another account.

[CmdletBinding()]
param(
    [switch]$KeepData,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'
$script:Title = 'Rerun uninstall'
$here = $PSScriptRoot
$nameRule = '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
$errorSacBlocked = 4551
$rerunNames = @('rerun-app', 'rerun', 'rerun-launch')

function Title([string]$text) {
    $Host.UI.RawUI.WindowTitle = "$script:Title - $text"
    Write-Host ''
    Write-Host ">> $text" -ForegroundColor Cyan
}

function Fail([string]$text) {
    Title "STOPPED: $text"
    throw $text
}

function Sha256-File([string]$path) {
    $fs = [IO.File]::Open($path, 'Open', 'Read', 'Read')
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($sha.ComputeHash($fs)) -replace '-', '').ToLowerInvariant() } finally { $sha.Dispose() }
    } finally { $fs.Dispose() }
}

function Is-Link([string]$path) {
    return (Test-Path -LiteralPath $path) -and [bool]((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)
}

function Same-Path([string]$a, [string]$b) {
    return [string]::Equals([IO.Path]::GetFullPath($a).TrimEnd('\'), [IO.Path]::GetFullPath($b).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)
}

# $path is $dir or lies inside it.
function Is-Inside([string]$path, [string]$dir) {
    $p = [IO.Path]::GetFullPath($path).TrimEnd('\') + '\'
    $d = [IO.Path]::GetFullPath($dir).TrimEnd('\') + '\'
    return $p.StartsWith($d, [StringComparison]::OrdinalIgnoreCase)
}

function Start-Error($err) {
    $w = $err.Exception
    while ($w -and -not ($w -is [ComponentModel.Win32Exception])) { $w = $w.InnerException }
    if ($w) { return $w.NativeErrorCode }
    return $null
}

# A payload file name (ADR 0030): one segment of $nameRule, no trailing dot, no reserved DOS
# device name (also with an extension).
function Test-PayloadName([string]$n) {
    if ($n -cnotmatch $nameRule -or $n.EndsWith('.')) { return $false }
    return ($n.Split('.')[0] -notmatch '^(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$')
}

# install.json or payload.json: format 1, product Rerun, every file name a payload name, unique.
function Read-Manifest([string]$path) {
    if ((Is-Link $path) -or (Get-Item -LiteralPath $path -Force).Length -gt 65536) { Fail "not a plain manifest file: $path" }
    $m = [IO.File]::ReadAllText($path) | ConvertFrom-Json
    if ($m.format -ne 1 -or $m.product -ne 'Rerun') { Fail "not a Rerun manifest (format 1): $path" }
    $seen = @{}
    foreach ($f in @($m.files)) {
        if (-not (Test-PayloadName "$($f.name)")) { Fail "not a payload file name in ${path}: $($f.name)" }
        if ("$($f.sha256)" -cnotmatch '^[0-9a-f]{64}$') { Fail "not a SHA-256 in ${path}: $($f.name)" }
        $k = "$($f.name)".ToLowerInvariant()
        if ($k -eq 'install.json' -or $k -eq 'payload.json' -or $seen.ContainsKey($k)) { Fail "a file name the manifest may not list: $($f.name)" }
        $seen[$k] = $true
    }
    return $m
}

# The entries of one folder; a path Windows PowerShell 5.1 cannot handle (over 260 characters)
# is a clear failure, never a silent skip.
function List-Dir([string]$dir) {
    try { return @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop) }
    catch {
        $e = $_.Exception
        while ($e -and -not ($e -is [IO.PathTooLongException])) { $e = $e.InnerException }
        if ($e -or $_.Exception.Message -match 'too long|zu lang') {
            throw "a path below $dir is longer than Windows PowerShell 5.1 can handle (260 characters): shorten or remove it by hand"
        }
        throw
    }
}

# Size, files and reparse points of a folder tree, walked without following any link.
function Measure-Tree([string]$dir) {
    $r = @{ Bytes = [int64]0; Files = 0; Links = New-Object System.Collections.Generic.List[string] }
    if (Is-Link $dir) { $r.Links.Add($dir); return $r }
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($dir)
    while ($stack.Count -gt 0) {
        foreach ($c in (List-Dir $stack.Pop())) {
            if ($c.Attributes -band [IO.FileAttributes]::ReparsePoint) { $r.Links.Add($c.FullName) }
            elseif ($c.PSIsContainer) { $stack.Push($c.FullName) }
            else { $r.Bytes += $c.Length; $r.Files++ }
        }
    }
    return $r
}

# Removes a folder tree entry by entry, never through a link: the folder itself is checked before
# it is listed, every entry before it is removed, and a reparse point stops the removal there
# (what is removed by then stays removed and is reported). Non-recursive Directory.Delete: an
# empty folder only.
function Remove-Tree([string]$dir) {
    if (Is-Link $dir) { throw "a reparse point appeared: $dir" }
    foreach ($c in (List-Dir $dir)) {
        if ($c.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "a reparse point appeared: $($c.FullName)" }
        if ($c.PSIsContainer) {
            Remove-Tree $c.FullName
        } else {
            if ($c.Attributes -band [IO.FileAttributes]::ReadOnly) { $c.Attributes = $c.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly) }
            [IO.File]::Delete($c.FullName)
        }
    }
    if (Is-Link $dir) { throw "a reparse point appeared: $dir" }
    [IO.Directory]::Delete($dir, $false)
}

function Size-Text([int64]$b) {
    if ($b -ge 1GB) { return '{0:N1} GB' -f ($b / 1GB) }
    if ($b -ge 1MB) { return '{0:N1} MB' -f ($b / 1MB) }
    if ($b -ge 1KB) { return '{0:N1} KB' -f ($b / 1KB) }
    return "$b bytes"
}

# Every running Rerun program, whatever its folder (all copies share the data folder), and any
# process started from this folder. A process of Rerun's names whose path cannot be read counts.
function Get-RunningRerun {
    $running = @()
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        $path = $null
        try { $path = $p.Path } catch { $path = $null }
        if ($rerunNames -contains $p.ProcessName) {
            if ($path) { $running += $path } else { $running += "$($p.ProcessName) (pid $($p.Id), path unreadable)" }
        } elseif ($path -and (Is-Inside $path $here)) {
            $running += $path
        }
    }
    return , $running
}

function Assert-NotRunning([string]$when) {
    $running = Get-RunningRerun
    if ($running.Count -gt 0) {
        Fail "Rerun is running ($($running -join ', ')): close every Rerun window, and end a game Steam started through rerun-launch.exe; then run this script again. $when"
    }
}

# rerun.exe uninstall-check of this folder, only if rerun.exe is the manifest's file.
function Invoke-Check([string]$when) {
    $cliEntry = @($files | Where-Object { $_.name -eq 'rerun.exe' })
    $cli = Join-Path $here 'rerun.exe'
    if ($cliEntry.Count -ne 1 -or -not (Test-Path -LiteralPath $cli -PathType Leaf) -or (Is-Link $cli) -or (Sha256-File $cli) -ne $cliEntry[0].sha256) {
        Fail "rerun.exe is missing or not the installed file: Rerun cannot check for open changes. $when"
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $cli
    $psi.Arguments = 'uninstall-check'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = $here
    try { $p = [Diagnostics.Process]::Start($psi) }
    catch {
        if ((Start-Error $_) -eq $errorSacBlocked) {
            Fail "Smart App Control blocked rerun.exe (os error 4551); nothing was bypassed. Rerun cannot check for open changes. $when"
        }
        Fail "rerun.exe could not be started ($($_.Exception.Message)): Rerun cannot check for open changes. $when"
    }
    try {
        $o = $p.StandardOutput.ReadToEndAsync()
        $e = $p.StandardError.ReadToEndAsync()
        $p.WaitForExit()
        return @{ Code = $p.ExitCode; Out = $o.Result; Err = $e.Result }
    } finally { $p.Dispose() }
}

function Wait-Enter([string]$prompt) {
    if ($Yes) { Write-Host "$prompt (-Yes: the sandbox suite goes on)"; return }
    [void](Read-Host $prompt)
}

$exitCode = 1
try {
    # ---------- 1. checks ----------
    Title 'CHECKING (nothing is changed yet)'
    if ($Yes -and $env:RERUN_SANDBOX -ne '1' -and $env:RERUN_CI_SANDBOX -ne '1') {
        Fail '-Yes is for the Windows Sandbox suite only'
    }
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Fail 'start this script from a normal (not administrator) PowerShell'
    }
    if (-not [Environment]::Is64BitProcess) { Fail 'start it from a 64-bit PowerShell' }

    $lad = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    $startMenu = [Environment]::GetFolderPath([Environment+SpecialFolder]::Programs)
    if (-not $lad -or -not [IO.Path]::IsPathRooted($lad)) { Fail 'the LocalAppData folder is unknown' }
    $dest = Join-Path (Join-Path $lad 'Programs') 'Rerun'
    $data = Join-Path $lad 'Rerun'
    $lnk = if ($startMenu) { Join-Path $startMenu 'Rerun.lnk' } else { $null }
    if (Same-Path $here ([IO.Path]::GetPathRoot($here))) { Fail "refusing to work in a drive root: $here" }
    if (Is-Inside $here $data) { Fail "refusing: this copy lies inside Rerun's data folder $data. Nothing removed" }
    if (Is-Link $here) { Fail "refusing: $here is a reparse point (a link or junction)" }

    $installJson = Join-Path $here 'install.json'
    $payloadJson = Join-Path $here 'payload.json'
    $installed = Test-Path -LiteralPath $installJson
    $portable = Test-Path -LiteralPath $payloadJson
    if ($installed -and $portable) { Fail "$here holds both install.json and payload.json: nothing removed" }
    if (-not $installed -and -not $portable) { Fail "$here is no Rerun folder (neither install.json nor payload.json): nothing removed" }
    # The data folder is shared by every copy: a portable copy never removes it while an
    # installed copy exists (that one would lose its journal, profiles and index).
    $sharedKeep = $portable -and (Test-Path -LiteralPath (Join-Path $dest 'install.json'))
    $keep = $KeepData -or $sharedKeep
    if ($installed) {
        if (-not (Same-Path $here $dest)) { Fail "install.json outside $dest ($here): nothing removed" }
        if (Is-Link (Join-Path $lad 'Programs')) { Fail "refusing: $lad\Programs is a reparse point" }
        $manifestPath = $installJson
        $kind = 'the installed copy'
    } else {
        $manifestPath = $payloadJson
        $kind = 'the portable copy'
    }
    if (-not $keep -and (Is-Link $data)) { Fail "refusing: $data is a reparse point (a link or junction); remove it by hand or run with -KeepData. Nothing removed" }
    $m = Read-Manifest $manifestPath
    $files = @($m.files)
    if (@($files | Where-Object { $_.name -eq 'uninstall.ps1' }).Count -ne 1) { Fail "$manifestPath does not list uninstall.ps1" }
    Assert-NotRunning 'Nothing removed'

    # ---------- 2. uninstall-check ----------
    Title 'ASKING Rerun whether a change is still open'
    $check = Invoke-Check 'Nothing removed'
    $openKept = $false
    switch ($check.Code) {
        0 {}
        5 {
            Write-Host $check.Out.TrimEnd()
            if (-not $KeepData) {
                Fail 'changes of Rerun are still open (listed above): undo them in Rerun (or forget them), then run this script again. Nothing removed. (-KeepData removes the program and keeps them for the next install)'
            }
            $openKept = $true
        }
        default {
            if ($check.Out.Trim()) { Write-Host $check.Out.TrimEnd() }
            if ($check.Err.Trim()) { Write-Host $check.Err.TrimEnd() -ForegroundColor Yellow }
            Fail "Rerun cannot check for open changes (rerun.exe uninstall-check exit $($check.Code)). Nothing removed"
        }
    }

    # ---------- 3. preview ----------
    $go = @(); $stays = @()
    foreach ($f in $files) {
        $p = Join-Path $here $f.name
        if (-not (Test-Path -LiteralPath $p)) { continue }
        if ((Is-Link $p) -or -not (Test-Path -LiteralPath $p -PathType Leaf)) { $stays += "$($f.name) (not a plain file)"; continue }
        if ((Sha256-File $p) -eq $f.sha256) { $go += $f } else { $stays += "$($f.name) (changed since it was installed)" }
    }
    $listed = @($files | ForEach-Object { "$($_.name)".ToLowerInvariant() }) + @((Split-Path $manifestPath -Leaf).ToLowerInvariant())
    foreach ($c in (List-Dir $here)) {
        if ($listed -notcontains $c.Name.ToLowerInvariant()) { $stays += "$($c.Name) (not Rerun's)" }
    }
    $lnkGoes = $false
    $lnkNote = $null
    if ($lnk -and (Test-Path -LiteralPath $lnk)) {
        $t = $null
        if (-not (Is-Link $lnk)) { $t = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk).TargetPath }
        if ($t -and (Same-Path $t (Join-Path $here 'rerun-app.exe'))) { $lnkGoes = $true }
        elseif ($installed) { $lnkNote = "$lnk stays: it does not point to $here\rerun-app.exe" }
    }
    $dataExists = Test-Path -LiteralPath $data
    $dataInfo = $null
    if ($dataExists -and -not $keep) {
        if (-not (Test-Path -LiteralPath $data -PathType Container)) { Fail "$data is not a folder: nothing removed" }
        $dataInfo = Measure-Tree $data
        if ($dataInfo.Links.Count -gt 0) {
            Fail "Rerun's data folder holds a link or junction ($($dataInfo.Links -join ', ')), which this script never follows: remove it by hand, or run with -KeepData. Nothing removed"
        }
    }

    Title 'PREVIEW (nothing is changed yet)'
    Write-Host ''
    Write-Host "Removes $kind of Rerun $($m.version) in $here" -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'What Rerun says (rerun.exe uninstall-check):'
    foreach ($l in ($check.Out.TrimEnd() -split "`r?`n")) { Write-Host "  $l" }
    if ($check.Out -match 'warning: Steam may still start') {
        Write-Host ''
        Write-Host 'Steam launch options: the games above start through rerun-launch.exe. Once it is removed they no longer start until you remove the launch option in Steam (Properties > General > Launch options). This script never changes Steam.' -ForegroundColor Yellow
    }
    if ($openKept) {
        Write-Host ''
        Write-Host "Open changes stay recorded in $data (-KeepData): install Rerun again to undo them." -ForegroundColor Yellow
    }
    Write-Host ''
    Write-Host 'Program files removed:'
    foreach ($f in $go) { Write-Host ("  {0,-26} {1,10} bytes" -f $f.name, (Get-Item -LiteralPath (Join-Path $here $f.name) -Force).Length) }
    Write-Host "  $(Split-Path $manifestPath -Leaf)"
    foreach ($s in $stays) { Write-Host "  stays: $s" -ForegroundColor Yellow }
    if ($stays.Count -eq 0) { Write-Host "  then the folder $here" } else { Write-Host "  the folder $here stays (not empty)" }
    if ($lnkGoes) { Write-Host "Start-menu shortcut removed: $lnk" }
    elseif ($lnkNote) { Write-Host $lnkNote -ForegroundColor Yellow }
    if (-not $dataExists) {
        Write-Host "Rerun's data folder $data does not exist."
    } elseif ($sharedKeep) {
        Write-Host "Rerun's data folder STAYS: $data. Rerun is also installed in $dest and uses the same data folder (journal, launch profiles, index); uninstall that copy to remove it." -ForegroundColor Yellow
    } elseif ($KeepData) {
        Write-Host "Rerun's data folder stays (-KeepData): $data"
    } else {
        Write-Host "Rerun's data folder removed: $data ($(Size-Text $dataInfo.Bytes) in $($dataInfo.Files) files):" -ForegroundColor Yellow
        foreach ($c in (List-Dir $data | Sort-Object Name)) { Write-Host "  $($c.Name)$(if ($c.PSIsContainer) { '\' })" }
        Write-Host '  (journal and history, backups, launch profiles, downloaded packages, the index and its seq floor, settings; -KeepData keeps them)'
    }
    Write-Host 'Nothing else: no Steam setting, no game folder, no registry.'
    Write-Host ''
    if ($sharedKeep) { Title 'Enter = remove this portable copy (the data folder stays: Rerun is installed too), close the window = cancel' }
    elseif ($keep -or -not $dataExists) { Title 'Enter = remove the program (data folder stays), close the window = cancel' }
    else { Title 'Enter = remove the program AND the data folder, close the window = cancel' }
    Wait-Enter 'Press Enter to remove (close the window to cancel)'

    # ---------- 4. remove ----------
    Title 'REMOVING'
    # Out of this folder, so it can go once it is empty.
    Set-Location -LiteralPath $lad
    [Environment]::CurrentDirectory = $lad
    $removed = New-Object System.Collections.Generic.List[string]
    $failed = New-Object System.Collections.Generic.List[string]
    if ($lnkGoes) {
        try { [IO.File]::Delete($lnk); $removed.Add($lnk) } catch { $failed.Add("$lnk ($($_.Exception.Message))") }
    }
    # Both checks again, right before anything of the data or the program goes: a Rerun started
    # or a change applied while the preview waited stops here.
    Title 'CHECKING again before removing'
    $stopNote = 'Nothing else removed' + $(if ($lnkGoes) { " (the Start-menu shortcut is gone; install again to get it back)" } else { '' })
    Assert-NotRunning $stopNote
    $again = Invoke-Check $stopNote
    if (-not ($again.Code -eq 0 -or ($KeepData -and $again.Code -eq 5))) {
        Write-Host $again.Out.TrimEnd()
        Fail "rerun.exe uninstall-check says exit $($again.Code) now (it was $($check.Code)): something changed while the preview waited. $stopNote"
    }
    if ($dataExists -and -not $keep) {
        try {
            if (Is-Link $data) { throw "a reparse point appeared: $data" }
            Remove-Tree $data
            $removed.Add($data)
        } catch { $failed.Add("$data ($($_.Exception.Message))") }
    }
    if (Is-Link $here) { Fail "refusing: $here became a reparse point" }
    foreach ($f in $go) {
        $p = Join-Path $here $f.name
        try {
            if ((Is-Link $p) -or (Sha256-File $p) -ne $f.sha256) { $failed.Add("$p (changed meanwhile, stays)"); continue }
            $i = Get-Item -LiteralPath $p -Force
            if ($i.Attributes -band [IO.FileAttributes]::ReadOnly) { $i.Attributes = $i.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly) }
            [IO.File]::Delete($p)
            $removed.Add($p)
        } catch { $failed.Add("$p ($($_.Exception.Message))") }
    }
    if ($failed.Count -eq 0) {
        try { [IO.File]::Delete($manifestPath); $removed.Add($manifestPath) } catch { $failed.Add("$manifestPath ($($_.Exception.Message))") }
    } else {
        $failed.Add("$manifestPath (kept: something above stays, so this script can run again)")
    }
    if ((List-Dir $here).Count -eq 0) {
        try { [IO.Directory]::Delete($here, $false); $removed.Add($here) } catch { $failed.Add("$here ($($_.Exception.Message))") }
    }

    Title $(if ($failed.Count -eq 0) { 'DONE' } else { 'DONE, but not everything could be removed' })
    Write-Host ''
    foreach ($r in $removed) { Write-Host "  removed $r" }
    foreach ($s in $stays) { Write-Host "  stays: $here\$s" -ForegroundColor Yellow }
    foreach ($f in $failed) { Write-Host "  not removed: $f" -ForegroundColor Red }
    if ($keep -and $dataExists) { Write-Host "  kept: $data$(if ($sharedKeep) { ' (used by the installed copy)' } else { ' (-KeepData)' })" }
    if ($check.Out -match 'warning: Steam may still start') {
        Write-Host '  Remember the Steam launch options listed above: remove them in Steam.' -ForegroundColor Yellow
    }
    $exitCode = if ($failed.Count -eq 0) { 0 } else { 1 }
} catch {
    Write-Host ''
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
}
Wait-Enter 'Press Enter to close'
exit $exitCode
