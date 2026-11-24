# Removes Rerun (alpha) again (P5-13d, ADR 0030): the installed copy in
# %LOCALAPPDATA%\Programs\Rerun or a portable copy, always the folder this script is in.
# Windows PowerShell 5.1, in a normal (not administrator) 64-bit PowerShell window:
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\Programs\Rerun\uninstall.ps1" [-KeepData]
#
# Step by step (each named in the window title):
#  1. Checks, nothing changed yet: not elevated, 64-bit; this folder is an installed copy
#     (install.json, only in %LOCALAPPDATA%\Programs\Rerun) or a portable one (payload.json);
#     no reparse point on the way; no program of this folder runs (a game Steam started with
#     Rerun's launch option runs through rerun-launch.exe).
#  2. rerun.exe uninstall-check (only if rerun.exe is the file the manifest names): exit 5 =
#     changes of Rerun are still open; they are listed and the script stops with nothing
#     removed (undo them in Rerun, or forget them; the journal and backups an undo needs are in
#     the data folder). With -KeepData it goes on and keeps them for the next install (update).
#     Any other failure (Smart App Control included) stops too: Rerun cannot check.
#  3. Preview (rule 5): what uninstall-check warns about (games Steam may still start through
#     rerun-launch.exe: remove their launch option in Steam), the program files that go (only
#     files with the SHA-256 of the manifest; changed or foreign files stay and are named), the
#     Start-menu shortcut (only if it points to this folder's rerun-app.exe), Rerun's data folder
#     %LOCALAPPDATA%\Rerun with its size and top-level entries (kept with -KeepData). One Enter
#     removes; closing the window cancels with nothing changed.
#  4. Removes: the shortcut, the data folder (never through a link: a reparse point anywhere in
#     it stops before anything is removed, and each entry is checked again while it is
#     removed), the program files, the manifest, this script, the folder if it is empty then.
#
# It never removes anything outside these paths and never touches Steam, a game folder, the
# registry or another account.

[CmdletBinding()]
param(
    [switch]$KeepData
)

$ErrorActionPreference = 'Stop'
$script:Title = 'Rerun uninstall'
$here = $PSScriptRoot
$nameRule = '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
$errorSacBlocked = 4551

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

function Start-Error($err) {
    $w = $err.Exception
    while ($w -and -not ($w -is [ComponentModel.Win32Exception])) { $w = $w.InnerException }
    if ($w) { return $w.NativeErrorCode }
    return $null
}

# install.json or payload.json: format 1, product Rerun, every file name one segment, unique.
function Read-Manifest([string]$path) {
    if ((Is-Link $path) -or (Get-Item -LiteralPath $path -Force).Length -gt 65536) { Fail "not a plain manifest file: $path" }
    $m = [IO.File]::ReadAllText($path) | ConvertFrom-Json
    if ($m.format -ne 1 -or $m.product -ne 'Rerun') { Fail "not a Rerun manifest (format 1): $path" }
    $seen = @{}
    foreach ($f in @($m.files)) {
        if ("$($f.name)" -cnotmatch $nameRule) { Fail "not a payload file name in ${path}: $($f.name)" }
        if ("$($f.sha256)" -cnotmatch '^[0-9a-f]{64}$') { Fail "not a SHA-256 in ${path}: $($f.name)" }
        $k = "$($f.name)".ToLowerInvariant()
        if ($k -eq 'install.json' -or $k -eq 'payload.json' -or $seen.ContainsKey($k)) { Fail "a file name the manifest may not list: $($f.name)" }
        $seen[$k] = $true
    }
    return $m
}

# Size, files and reparse points of a folder tree, walked without following any link.
function Measure-Tree([string]$dir) {
    $r = @{ Bytes = [int64]0; Files = 0; Links = New-Object System.Collections.Generic.List[string] }
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($dir)
    while ($stack.Count -gt 0) {
        foreach ($c in @(Get-ChildItem -LiteralPath $stack.Pop() -Force)) {
            if ($c.Attributes -band [IO.FileAttributes]::ReparsePoint) { $r.Links.Add($c.FullName) }
            elseif ($c.PSIsContainer) { $stack.Push($c.FullName) }
            else { $r.Bytes += $c.Length; $r.Files++ }
        }
    }
    return $r
}

# Removes a folder tree entry by entry, never through a link: a reparse point met on the way
# stops the removal there (what is removed by then stays removed and is reported).
function Remove-Tree([string]$dir) {
    foreach ($c in @(Get-ChildItem -LiteralPath $dir -Force)) {
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

$exitCode = 1
try {
    # ---------- 1. checks ----------
    Title 'CHECKING (nothing is changed yet)'
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
    if (Is-Link $here) { Fail "refusing: $here is a reparse point (a link or junction)" }
    if (-not $KeepData -and (Is-Link $data)) { Fail "refusing: $data is a reparse point (a link or junction); remove it by hand or run with -KeepData" }

    $installJson = Join-Path $here 'install.json'
    $payloadJson = Join-Path $here 'payload.json'
    $installed = Test-Path -LiteralPath $installJson
    $portable = Test-Path -LiteralPath $payloadJson
    if ($installed -and $portable) { Fail "$here holds both install.json and payload.json: nothing removed" }
    if (-not $installed -and -not $portable) { Fail "$here is no Rerun folder (neither install.json nor payload.json): nothing removed" }
    if ($installed) {
        if (-not (Same-Path $here $dest)) { Fail "install.json outside $dest ($here): nothing removed" }
        if (Is-Link (Join-Path $lad 'Programs')) { Fail "refusing: $lad\Programs is a reparse point" }
        $manifestPath = $installJson
        $kind = 'the installed copy'
    } else {
        $manifestPath = $payloadJson
        $kind = 'the portable copy'
    }
    $m = Read-Manifest $manifestPath
    $files = @($m.files)
    if (@($files | Where-Object { $_.name -eq 'uninstall.ps1' }).Count -ne 1) { Fail "$manifestPath does not list uninstall.ps1" }

    # No program of this folder may run (an uninstall would fail half-way, and a game Steam
    # started through rerun-launch.exe would lose its shim). Same name but path unreadable:
    # cannot tell, so stop (fail closed).
    $running = @()
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        $path = $null
        try { $path = $p.Path } catch { $path = $null }
        if ($path -and $path.StartsWith($here.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { $running += $path }
        elseif (-not $path -and @('rerun-app', 'rerun', 'rerun-launch') -contains $p.ProcessName) { $running += "$($p.ProcessName) (pid $($p.Id), path unreadable)" }
    }
    if ($running.Count -gt 0) {
        Fail "Rerun is running ($($running -join ', ')): close Rerun, and end a game Steam started through rerun-launch.exe; then run this script again. Nothing removed"
    }

    # ---------- 2. uninstall-check ----------
    Title 'ASKING Rerun whether a change is still open'
    $cliEntry = @($files | Where-Object { $_.name -eq 'rerun.exe' })
    $cli = Join-Path $here 'rerun.exe'
    if ($cliEntry.Count -ne 1 -or -not (Test-Path -LiteralPath $cli -PathType Leaf) -or (Is-Link $cli) -or (Sha256-File $cli) -ne $cliEntry[0].sha256) {
        Fail "rerun.exe is missing or not the installed file: Rerun cannot check for open changes. Nothing removed"
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
            Fail 'Smart App Control blocked rerun.exe (os error 4551); nothing was bypassed. Rerun cannot check for open changes. Nothing removed'
        }
        Fail "rerun.exe could not be started ($($_.Exception.Message)): Rerun cannot check for open changes. Nothing removed"
    }
    try {
        $o = $p.StandardOutput.ReadToEndAsync()
        $e = $p.StandardError.ReadToEndAsync()
        $p.WaitForExit()
        $check = @{ Code = $p.ExitCode; Out = $o.Result; Err = $e.Result }
    } finally { $p.Dispose() }
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
    foreach ($c in @(Get-ChildItem -LiteralPath $here -Force)) {
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
    if ($dataExists -and -not $KeepData) {
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
    } elseif ($KeepData) {
        Write-Host "Rerun's data folder stays (-KeepData): $data"
    } else {
        Write-Host "Rerun's data folder removed: $data ($(Size-Text $dataInfo.Bytes) in $($dataInfo.Files) files):" -ForegroundColor Yellow
        foreach ($c in @(Get-ChildItem -LiteralPath $data -Force | Sort-Object Name)) { Write-Host "  $($c.Name)$(if ($c.PSIsContainer) { '\' })" }
        Write-Host '  (journal and history, backups, launch profiles, downloaded packages, the index, settings; -KeepData keeps them)'
    }
    Write-Host 'Nothing else: no Steam setting, no game folder, no registry.'
    Write-Host ''
    Title 'Enter = remove, close the window = cancel'
    [void](Read-Host 'Press Enter to remove (close the window to cancel)')

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
    if ($dataExists -and -not $KeepData) {
        try { Remove-Tree $data; $removed.Add($data) } catch { $failed.Add("$data ($($_.Exception.Message))") }
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
    if (@(Get-ChildItem -LiteralPath $here -Force).Count -eq 0) {
        try { [IO.Directory]::Delete($here, $false); $removed.Add($here) } catch { $failed.Add("$here ($($_.Exception.Message))") }
    }

    Title $(if ($failed.Count -eq 0) { 'DONE' } else { 'DONE, but not everything could be removed' })
    Write-Host ''
    foreach ($r in $removed) { Write-Host "  removed $r" }
    foreach ($s in $stays) { Write-Host "  stays: $here\$s" -ForegroundColor Yellow }
    foreach ($f in $failed) { Write-Host "  not removed: $f" -ForegroundColor Red }
    if ($KeepData -and $dataExists) { Write-Host "  kept: $data (-KeepData)" }
    if ($check.Out -match 'warning: Steam may still start') {
        Write-Host '  Remember the Steam launch options listed above: remove them in Steam.' -ForegroundColor Yellow
    }
    $exitCode = if ($failed.Count -eq 0) { 0 } else { 1 }
} catch {
    Write-Host ''
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
}
[void](Read-Host 'Press Enter to close')
exit $exitCode
