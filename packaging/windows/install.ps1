# Installs Rerun (alpha) for this Windows account, without administrator rights (P5-13d,
# ADR 0030). Windows PowerShell 5.1, in a normal (not administrator) 64-bit PowerShell window,
# from the payload folder (the folder this script is in):
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
#
# Step by step (each named in the window title):
#  1. Checks, nothing changed yet: not elevated, 64-bit; every file next to this script is as
#     payload.json says (plain file, size, SHA-256); the targets come from the known folders
#     (never the environment) and no reparse point is on the way. Rerun installed already
#     (install.json there) stops: to update, run its uninstall.ps1 -KeepData first. A folder
#     with anything else than files of this payload (the leftover of an interrupted install)
#     stops too: nothing of it is touched.
#  2. Preview (rule 5): every file with its size and SHA-256, the target folder, the Start-menu
#     shortcut, install.json, the index import, Rerun's data folder. One Enter installs;
#     closing the window cancels with nothing changed.
#  3. Copies the files into %LOCALAPPDATA%\Programs\Rerun (each hashed again), starts
#     rerun.exe --version and rerun-launch.exe without arguments (it starts nothing) to see
#     that Smart App Control lets them run, creates the Start-menu shortcut "Rerun", writes
#     install.json last of these, imports the signed index with rerun.exe index import (a
#     refused import is a note: the app then shows "no index"), and starts Rerun.
#  Any failure undoes the steps already done, newest first (only files with the SHA-256 it
#  copied, only folders it created and that are empty, only its own shortcut). Smart App
#  Control blocking a program (os error 4551) is such a failure: it is never bypassed.
#
# What it writes: the program folder, the shortcut, and (by rerun.exe) the index in
# %LOCALAPPDATA%\Rerun\index. No registry, no PATH, no service, no autostart, no Steam setting,
# no game folder, nothing elevated.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$script:Title = 'Rerun install'
$src = $PSScriptRoot
# One segment of a payload file name (ADR 0030), as scripts\alpha-build.ps1 writes them.
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

# The Win32 error of a failed process start, if it is one.
function Start-Error($err) {
    $w = $err.Exception
    while ($w -and -not ($w -is [ComponentModel.Win32Exception])) { $w = $w.InnerException }
    if ($w) { return $w.NativeErrorCode }
    return $null
}

# Starts $exe (no shell) and waits; returns exit code and output. Smart App Control blocking it
# (os error 4551) throws a failure that names it.
function Invoke-Exe([string]$exe, [string[]]$arguments, [string]$dir) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = (@($arguments | ForEach-Object {
                # Quoted as one argument: no quote, no control character, no trailing backslash.
                if ($_ -match '["\x00-\x1f]' -or $_.EndsWith('\')) { Fail "refusing an argument: $_" }
                '"' + $_ + '"'
            }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = $dir
    try { $p = [Diagnostics.Process]::Start($psi) }
    catch {
        if ((Start-Error $_) -eq $errorSacBlocked) {
            Fail "Smart App Control blocked $exe (os error 4551); nothing was bypassed"
        }
        throw
    }
    try {
        $o = $p.StandardOutput.ReadToEndAsync()
        $e = $p.StandardError.ReadToEndAsync()
        $p.WaitForExit()
        return @{ Code = $p.ExitCode; Out = $o.Result; Err = $e.Result }
    } finally { $p.Dispose() }
}

# payload.json: format 1, product Rerun, every file name one segment of the rule, unique.
function Read-Manifest([string]$path) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Is-Link $path)) { Fail "not found or not a plain file: $path" }
    if ((Get-Item -LiteralPath $path -Force).Length -gt 65536) { Fail "too large: $path" }
    $m = [IO.File]::ReadAllText($path) | ConvertFrom-Json
    if ($m.format -ne 1 -or $m.product -ne 'Rerun') { Fail "not a Rerun payload manifest (format 1): $path" }
    if ("$($m.version)" -notmatch '^[0-9A-Za-z.+-]{1,64}$' -or "$($m.build)" -notmatch '^[0-9A-Za-z.-]{1,64}$') { Fail "version or build not readable: $path" }
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

$exitCode = 1
$done = New-Object System.Collections.Generic.List[object]   # what to undo, oldest first
$committed = $false
try {
    # ---------- 1. checks ----------
    Title 'CHECKING (nothing is changed yet)'
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Fail 'start this script from a normal (not administrator) PowerShell: Rerun is installed for your account and never runs elevated'
    }
    if (-not [Environment]::Is64BitProcess) { Fail 'start it from a 64-bit PowerShell' }

    $m = Read-Manifest (Join-Path $src 'payload.json')
    $names = @($m.files | ForEach-Object { "$($_.name)" })
    foreach ($req in @('rerun-app.exe', 'rerun.exe', 'rerun-launch.exe', 'uninstall.ps1', 'install.ps1')) {
        if ($names -notcontains $req) { Fail "payload.json does not list $req" }
    }
    if ($names -contains 'rerun-helper.exe') { Fail 'this payload holds rerun-helper.exe, which the alpha never installs' }
    foreach ($f in @($m.files)) {
        $p = Join-Path $src $f.name
        if (-not (Test-Path -LiteralPath $p -PathType Leaf) -or (Is-Link $p)) { Fail "missing or not a plain file: $p" }
        if ((Get-Item -LiteralPath $p -Force).Length -ne [int64]$f.size -or (Sha256-File $p) -ne $f.sha256) {
            Fail "$($f.name) is not as payload.json says (size or SHA-256): the payload is damaged or changed"
        }
    }
    # install.ps1 stays in the payload; everything else is installed.
    $copy = @($m.files | Where-Object { $_.name -ne 'install.ps1' })
    $hasIndex = ($names -contains 'index.json') -and ($names -contains 'index.json.sig')

    $lad = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    $startMenu = [Environment]::GetFolderPath([Environment+SpecialFolder]::Programs)
    if (-not $lad -or -not [IO.Path]::IsPathRooted($lad)) { Fail 'the LocalAppData folder is unknown' }
    if (-not $startMenu -or -not [IO.Path]::IsPathRooted($startMenu)) { Fail 'the Start-menu folder is unknown' }
    $programs = Join-Path $lad 'Programs'
    $dest = Join-Path $programs 'Rerun'
    $data = Join-Path $lad 'Rerun'
    $lnk = Join-Path $startMenu 'Rerun.lnk'
    $appTarget = Join-Path $dest 'rerun-app.exe'
    if (Same-Path $src $dest) { Fail "this script runs from the install folder ${dest}: run the install.ps1 of a payload instead" }
    foreach ($p in @($lad, $programs, $dest, $startMenu, $lnk, $data)) {
        if (Is-Link $p) { Fail "refusing: $p is a reparse point (a link or junction)" }
    }

    $destExists = Test-Path -LiteralPath $dest
    $leftover = @()
    if ($destExists) {
        if (-not (Test-Path -LiteralPath $dest -PathType Container)) { Fail "$dest exists and is not a folder" }
        if (Test-Path -LiteralPath (Join-Path $dest 'install.json')) {
            Fail "Rerun is installed already in $dest. To update: run $dest\uninstall.ps1 -KeepData, then this script again"
        }
        $copyNames = @($copy | ForEach-Object { "$($_.name)".ToLowerInvariant() })
        foreach ($e in @(Get-ChildItem -LiteralPath $dest -Force)) {
            $plain = -not $e.PSIsContainer -and -not ($e.Attributes -band [IO.FileAttributes]::ReparsePoint)
            if (-not $plain -or $copyNames -notcontains $e.Name.ToLowerInvariant()) {
                Fail "$dest holds $($e.Name), which is not a file of this payload: nothing changed (remove the folder by hand if it is not needed)"
            }
            $leftover += $e.Name
        }
        $running = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($dest + '\', [StringComparison]::OrdinalIgnoreCase) })
        if ($running.Count -gt 0) { Fail "programs from $dest are running ($(@($running | ForEach-Object { $_.Path }) -join ', ')): end them first" }
    }

    $shell = New-Object -ComObject WScript.Shell
    $makeShortcut = $true
    $shortcutNote = "$lnk -> $appTarget"
    if (Test-Path -LiteralPath $lnk) {
        $old = $shell.CreateShortcut($lnk).TargetPath
        if ($old -and (Same-Path $old $appTarget)) {
            $shortcutNote = "$lnk -> $appTarget (replaces the leftover of an interrupted install)"
        } else {
            $makeShortcut = $false
            $shortcutNote = "none: $lnk exists and is not Rerun's (it points to '$old'); it stays as it is"
        }
    }

    # ---------- 2. preview ----------
    Title 'PREVIEW (nothing is changed yet)'
    Write-Host ''
    Write-Host "Rerun $($m.version) (build $($m.build)), unsigned alpha, from $src" -ForegroundColor Yellow
    Write-Host ''
    if ($leftover.Count -gt 0) {
        Write-Host "Copies into $dest (it holds files of an interrupted install: $($leftover -join ', '); they are replaced):"
    } elseif ($destExists) {
        Write-Host "Copies into $dest (exists, empty):"
    } else {
        Write-Host "Creates $dest and copies into it:"
    }
    foreach ($f in $copy) { Write-Host ("  {0,-26} {1,10} bytes  SHA-256 {2}" -f $f.name, $f.size, $f.sha256) }
    Write-Host "Writes $dest\install.json (what was installed; uninstall.ps1 removes exactly that)"
    Write-Host "Start-menu shortcut: $shortcutNote"
    if ($hasIndex) {
        Write-Host "Imports the signed index (seq $($m.index.seq), key $($m.index.key)) with rerun.exe index import into $data\index"
    } else {
        Write-Host 'No index in this payload (a test build): the app shows "no index"' -ForegroundColor Yellow
    }
    Write-Host "Rerun's data folder: $data (Rerun creates it on first use: journal, backups, launch profiles, packages, settings)"
    Write-Host 'Starts rerun.exe --version and rerun-launch.exe (no arguments, starts nothing) to see that Smart App Control lets them run, and starts Rerun at the end.'
    Write-Host 'Nothing else: no administrator, no registry, no PATH, no service, no autostart, no Steam setting, no game folder.'
    Write-Host ''
    Title 'Enter = install, close the window = cancel'
    [void](Read-Host 'Press Enter to install (close the window to cancel)')

    # ---------- 3. install ----------
    Title 'INSTALLING'
    foreach ($p in @($lad, $programs, $dest)) { if (Is-Link $p) { Fail "refusing: $p is a reparse point" } }
    if (-not (Test-Path -LiteralPath $programs)) {
        New-Item -ItemType Directory -Path $programs | Out-Null
        $done.Add(@{ Kind = 'dir'; Path = $programs })
    }
    if (-not (Test-Path -LiteralPath $dest)) {
        New-Item -ItemType Directory -Path $dest | Out-Null
        $done.Add(@{ Kind = 'dir'; Path = $dest })
    }
    if (Is-Link $dest) { Fail "refusing: $dest is a reparse point" }
    foreach ($f in $copy) {
        $to = Join-Path $dest $f.name
        if (Is-Link $to) { Fail "refusing: $to is a reparse point" }
        $done.Add(@{ Kind = 'file'; Path = $to; Sha = $f.sha256 })
        [IO.File]::Copy((Join-Path $src $f.name), $to, $true)
        if ((Sha256-File $to) -ne $f.sha256) { Fail "the copy of $($f.name) is not as payload.json says" }
        Write-Host "  copied $($f.name)"
    }

    Title 'CHECKING that Windows lets the programs run'
    $cli = Join-Path $dest 'rerun.exe'
    $r = Invoke-Exe $cli @('--version') $dest
    if ($r.Code -ne 0 -or $r.Out.Trim() -ne "rerun $($m.version)") { Fail "rerun.exe --version: exit $($r.Code), '$($r.Out.Trim())'" }
    Write-Host "  rerun.exe runs ($($r.Out.Trim()))"
    $r = Invoke-Exe (Join-Path $dest 'rerun-launch.exe') @() $dest
    if ($r.Code -ne 2) { Fail "rerun-launch.exe without arguments: exit $($r.Code), expected 2 (usage)" }
    Write-Host '  rerun-launch.exe runs'

    if ($makeShortcut) {
        if (Test-Path -LiteralPath $lnk) { Remove-Item -LiteralPath $lnk -Force }
        $done.Add(@{ Kind = 'lnk'; Path = $lnk })
        $s = $shell.CreateShortcut($lnk)
        $s.TargetPath = $appTarget
        $s.WorkingDirectory = $dest
        $s.IconLocation = "$appTarget,0"
        $s.Description = 'Rerun'
        $s.Save()
        Write-Host "  shortcut $lnk"
    }

    $record = [ordered]@{
        format   = 1
        product  = 'Rerun'
        version  = "$($m.version)"
        build    = "$($m.build)"
        files    = @($copy | ForEach-Object { [ordered]@{ name = "$($_.name)"; size = [int64]$_.size; sha256 = "$($_.sha256)" } })
        shortcut = $makeShortcut
    }
    $installJson = Join-Path $dest 'install.json'
    $done.Add(@{ Kind = 'record'; Path = $installJson })
    $json = ($record | ConvertTo-Json -Depth 5) -replace "`r`n", "`n"
    [IO.File]::WriteAllText($installJson, $json + "`n", (New-Object Text.UTF8Encoding($false)))

    $indexNote = 'no index in this payload: the app shows "no index"'
    if ($hasIndex) {
        Title 'IMPORTING the signed index'
        $r = Invoke-Exe $cli @('index', 'import', (Join-Path $dest 'index.json'), (Join-Path $dest 'index.json.sig')) $dest
        if ($r.Out.Trim()) { Write-Host $r.Out.TrimEnd() }
        if ($r.Err.Trim()) { Write-Host $r.Err.TrimEnd() -ForegroundColor Yellow }
        $indexNote = if ($r.Code -eq 0) { "imported (seq $($m.index.seq))" } else { "not imported (rerun.exe exit $($r.Code), see above): the app shows why" }
    }

    Title 'STARTING Rerun'
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $appTarget
    $psi.UseShellExecute = $false
    $psi.WorkingDirectory = $dest
    try {
        $app = [Diagnostics.Process]::Start($psi)
        if ($app) { $app.Dispose() }
    } catch {
        if ((Start-Error $_) -eq $errorSacBlocked) {
            Fail 'Smart App Control blocked rerun-app.exe (os error 4551); nothing was bypassed'
        }
        Write-Host "note: Rerun could not be started now: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    $committed = $true

    Title 'DONE'
    Write-Host ''
    Write-Host "Rerun $($m.version) is installed in $dest" -ForegroundColor Green
    if ($makeShortcut) { Write-Host "  Start menu: Rerun ($lnk)" }
    Write-Host "  index: $indexNote"
    Write-Host "  data:  $data"
    Write-Host "  remove: powershell -NoProfile -ExecutionPolicy Bypass -File `"$dest\uninstall.ps1`""
    $exitCode = 0
} catch {
    Write-Host ''
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    if (-not $committed -and $done.Count -gt 0) {
        Write-Host 'Undoing what this run did:' -ForegroundColor Yellow
        for ($i = $done.Count - 1; $i -ge 0; $i--) {
            $d = $done[$i]
            try {
                if (-not (Test-Path -LiteralPath $d.Path)) { continue }
                if (Is-Link $d.Path) { Write-Host "  stays (a reparse point now): $($d.Path)"; continue }
                switch ($d.Kind) {
                    'file' {
                        if ((Sha256-File $d.Path) -eq $d.Sha) { [IO.File]::Delete($d.Path); Write-Host "  removed $($d.Path)" }
                        else { Write-Host "  stays (not the copied file): $($d.Path)" }
                    }
                    'record' { [IO.File]::Delete($d.Path); Write-Host "  removed $($d.Path)" }
                    'lnk' {
                        $t = (New-Object -ComObject WScript.Shell).CreateShortcut($d.Path).TargetPath
                        if ($t -and (Same-Path $t $appTarget)) { [IO.File]::Delete($d.Path); Write-Host "  removed $($d.Path)" }
                        else { Write-Host "  stays (not Rerun's shortcut): $($d.Path)" }
                    }
                    'dir' {
                        if (@(Get-ChildItem -LiteralPath $d.Path -Force).Count -eq 0) { [IO.Directory]::Delete($d.Path, $false); Write-Host "  removed $($d.Path)" }
                        else { Write-Host "  stays (not empty): $($d.Path)" }
                    }
                }
            } catch { Write-Host "  could not undo $($d.Path): $($_.Exception.Message)" -ForegroundColor Red }
        }
        if ($hasIndex -and (Test-Path -LiteralPath (Join-Path $data 'index'))) {
            Write-Host "  an index imported by this run stays in $data\index (Rerun's data folder; uninstall.ps1 of a later install removes it)"
        }
    }
    $exitCode = 1
}
[void](Read-Host 'Press Enter to close')
exit $exitCode
