# [DEV] Check of the read-only GUI rerun-app on the developer machine (docs/09-testing.md,
# "[DEV] acceptance of P5-3"). Windows PowerShell 5.1, in a normal (not administrator) 64-bit
# PowerShell window, from the repository:
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\dev-app-check.ps1
#
# What it writes, and removes again (the list is also printed first):
#  - builds into target\dev-release\ (rerun-cli, rerun-workbench, rerun-app, all with the feature
#    test-key) with the profile dev-release: release optimisation, so the speed you see is the
#    shipped app's; debug assertions stay on because the test key demands them (ADR 0024), which
#    is why this is not the shipped release profile (that one cannot contain the test key).
#    Built with the Smart-App-Control-safe source replacement .dev\sac-build\sac.toml. If a build stops
#    with os error 4551 (Smart App Control) the script stops; it never tries to get around it.
#  - a fresh folder below %TEMP% with the index built from this repository and signed with the
#    test key (deleted at the end).
#  - <LocalAppData>\Rerun\index-test: Rerun's own index state of a TEST-KEY build, by
#    `rerun index import` (deleted at the end; the real <LocalAppData>\Rerun\index is never
#    touched). If index-test already holds anything the script refuses (run
#    scripts\dev-topo-roundtrip.ps1 -Cleanup first), so the end state is exactly the start state:
#    no index-test (or the empty folder that was there).
# Nothing else: no registry, no firewall, no Steam, no game folder, no profile, no journal.
#
# It starts the test-key rerun-app.exe, shows the checklist in the window title one step after
# the other while the app runs, and waits until you close the app. It asks nothing. What it
# measures itself (time to the first window, working set after 5 s, DLLs loaded from outside
# System32 and WinSxS, and the timing lines the test-key app writes to standard error: the
# jobs of the worker and the time from a click on a game to its page) and the checklist for
# you to report are in the summary, which is also copied to the clipboard. The cleanup runs in any case and reports PASS or FAIL.

# Optional apply test (P5-5a): -Game <folder of ONE Steam game you name>. The test-key app then
# runs with a real index, so it CAN apply a fix to that game. You apply the preselected fixes
# of that game in the app, look at the preview, and undo them again (steps F to H of the
# checklist). The script snapshots the game folder first (every file: length, read-only/hidden/
# system flags and SHA-256 (streamed, any size); timestamps are not compared, an undo does not
# restore them) and compares it when the app is closed: PASS only if it is bit-identical for
# what is hashed. What else it writes in this mode: Rerun's own records of the transaction
# (<AppDir>\plans, \journal, \profiles). It removes exactly those top-level folders at the end if
# they did not exist before, the game folder is identical again, and `rerun status` lists no open
# transaction; otherwise it leaves them and says so. Apply fixes to the named game only.
# Optional download test (P5-5b): -Game <folder> -Download. A fix whose package is not in Rerun's
# packages folder is ticked in the app, the consent dialog lists what would be downloaded, and
# "Download" fetches it from its source (GitHub) as the real app does: the script downloads
# nothing itself. Meant for Assassin's Creed: Director's Cut and EaglePatch from an EMPTY package
# cache, then apply and undo as in steps F to H. The script lists <AppDir>\cache and
# <AppDir>\packages before (every entry: name, kind, length; it refuses a link anywhere in them)
# and after the app is closed, and REPORTS what the app added: each archive in the cache (its name
# must equal its SHA-256, which the script computes again), each unpacked file. What was there
# before is never touched. What the app added is removed again, exactly those entries and then the
# folders that did not exist before, only if the game folder is identical again and `rerun status`
# lists no open transaction, so the test can be repeated from an empty cache; with -KeepDownloads
# it is kept and the summary says so. Entries that existed before and changed are never
# modified: the run FAILs and says which.
[CmdletBinding()]
param(
    [ValidateRange(5, 120)][int]$StepSeconds = 45,
    [string]$Game = '',
    [switch]$Download,
    [switch]$KeepDownloads
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'dev-helper-common.ps1')
$script:HelperTitle = 'Rerun DEV app check'

$lad = [Environment]::GetFolderPath('LocalApplicationData')
$appDir = Join-Path $lad 'Rerun'
$indexTest = Join-Path $appDir 'index-test'
$sacToml = Join-Path $repo '.dev\sac-build\sac.toml'
$cli = Join-Path $repo 'target\dev-release\rerun.exe'
$workbench = Join-Path $repo 'target\dev-release\rerun-workbench.exe'
$appExe = Join-Path $repo 'target\dev-release\rerun-app.exe'

# The summary line of `rerun status`: "<n> transactions: <a> not closed, <b> closed, <c> forgotten".
function Status-Counts([string]$out) {
    $m = [regex]::Match($out, '(\d+) not closed, (\d+) closed, (\d+) forgotten')
    if (-not $m.Success) { return $null }
    [pscustomobject]@{ NotClosed = [int]$m.Groups[1].Value; Closed = [int]$m.Groups[2].Value; Forgotten = [int]$m.Groups[3].Value }
}

function Sha256-File([string]$path) {
    $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite, Delete')
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($sha.ComputeHash($fs)) -replace '-', '').ToLowerInvariant() } finally { $sha.Dispose() }
    } finally { $fs.Dispose() }
}

function Is-Link([string]$path) {
    return (Test-Path -LiteralPath $path) -and [bool]((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)
}

# The top level of <AppDir> by name and kind: the cleanup proves nothing else appeared or went.
function Get-AppDirList {
    if (-not (Test-Path -LiteralPath $appDir)) { return @('<missing>') }
    return @(Get-ChildItem -LiteralPath $appDir -Force | Sort-Object Name | ForEach-Object { "$($_.Name)|$($_.PSIsContainer)" })
}

# Whether a folder holds no reparse point anywhere below it (a recursive delete must never
# follow a junction or symlink): walked item by item, links are not followed.
function Test-NoLinks([string]$path) {
    foreach ($c in Get-ChildItem -LiteralPath $path -Force) {
        if ($c.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
        if ($c.PSIsContainer -and -not (Test-NoLinks $c.FullName)) { return $false }
    }
    return $true
}

# The game folder as a table: relative path -> "length|flags|sha256" (SHA-256 of every file,
# streamed; "unreadable" if a file cannot be read, counted in $script:notHashed), and every folder. Timestamps are not part of it (ADR 0017).
function Get-GameSnapshot([string]$root) {
    $t = @{}
    $script:notHashed = 0
    $prefix = $root.TrimEnd('\') + '\'
    foreach ($f in Get-ChildItem -LiteralPath $root -Recurse -Force -File) {
        $rel = $f.FullName.Substring($prefix.Length).ToLowerInvariant()
        $flags = [int]($f.Attributes -band 7)
        # Every file, streamed, whatever its size; one that cannot be read is counted.
        try { $sha = Sha256-File $f.FullName } catch { $sha = 'unreadable'; $script:notHashed++ }
        $t["file:$rel"] = "$($f.Length)|$flags|$sha"
    }
    foreach ($d in Get-ChildItem -LiteralPath $root -Recurse -Force -Directory) {
        $t['dir:' + $d.FullName.Substring($prefix.Length).ToLowerInvariant()] = 'dir'
    }
    return $t
}

function Compare-GameSnapshot($a, $b) {
    $d = New-Object System.Collections.Generic.List[string]
    foreach ($k in $a.Keys) {
        if (-not $b.ContainsKey($k)) { $d.Add("gone: $k") }
        elseif ($a[$k] -ne $b[$k]) { $d.Add("changed: $k") }
    }
    foreach ($k in $b.Keys) { if (-not $a.ContainsKey($k)) { $d.Add("new: $k") } }
    return $d
}

# <AppDir>\cache and <AppDir>\packages as a table: relative path -> "file|length", "dir" or
# "link" (never followed). Used before and after the app ran, to report and to remove exactly
# what the app added (-Download).
function Get-TreeList([string]$root) {
    $t = @{}
    if (-not (Test-Path -LiteralPath $root)) { return $t }
    $prefix = $root.TrimEnd('\') + '\'
    foreach ($i in Get-ChildItem -LiteralPath $root -Recurse -Force) {
        $rel = $i.FullName.Substring($prefix.Length)
        if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) { $t[$rel] = 'link' }
        elseif ($i.PSIsContainer) { $t[$rel] = 'dir' }
        else { $t[$rel] = "file|$($i.Length)" }
    }
    return $t
}

function Quote-Arg([string]$a) {
    if ($a -match '^[A-Za-z0-9_.:/\\=-]+$') { return $a }
    if ($a.Contains('"') -or $a.EndsWith('\')) { Fail "refusing an argument: $a" }
    return '"' + $a + '"'
}

function Invoke-Exe([string]$exe, [string[]]$arguments) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = (@($arguments | ForEach-Object { Quote-Arg $_ }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = $repo
    $p = [Diagnostics.Process]::Start($psi)
    try {
        $o = $p.StandardOutput.ReadToEndAsync()
        $e = $p.StandardError.ReadToEndAsync()
        $p.WaitForExit()
        return @{ Code = $p.ExitCode; Out = $o.Result; Err = $e.Result }
    } finally { $p.Dispose() }
}

function Show-Output($r) {
    if ($r.Out) { Write-Host $r.Out.TrimEnd() }
    if ($r.Err.Trim()) { Write-Host $r.Err.TrimEnd() -ForegroundColor Yellow }
}

function Invoke-Build {
    Title 'BUILDING (a few minutes the first time)'
    Push-Location $repo
    try {
        $ErrorActionPreference = 'Continue'
        $lines = New-Object System.Collections.Generic.List[string]
        & cargo build --profile dev-release -p rerun-cli -p rerun-workbench -p rerun-app --features test-key --config $sacToml 2>&1 | ForEach-Object {
            $l = "$_"
            $lines.Add($l)
            Write-Host $l
        }
        $code = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
    } finally { Pop-Location }
    if ($code -ne 0) {
        if (($lines -join "`n") -match 'os error 4551') {
            Fail 'Smart App Control blocked a build step (os error 4551). Nothing was bypassed; stop here and report it'
        }
        Fail "cargo build failed ($code)"
    }
    foreach ($x in @($cli, $workbench, $appExe)) {
        if (-not (Test-Path -LiteralPath $x -PathType Leaf)) { Fail "not built: $x" }
    }
}

# ---------- state ----------
$summary = New-Object System.Collections.Generic.List[string]
$verdict = 'FAIL'
$errorText = $null
$tmp = $null
$touched = $false          # index-test may hold something of ours
$indexExisted = $false     # index-test was there (empty) before
$appProc = $null
$cleanup = 'not needed'
$firstWindowMs = $null
$workingSet = $null
$foreign = @{}
$exitCode = $null
$seq = $null
$traceText = ''
$gameBefore = $null        # the named game folder before the app ran (apply test)
$applyCheck = 'not run'
$cacheDir = Join-Path $appDir 'cache'
$packagesDir = Join-Path $appDir 'packages'
$dlBefore = $null          # cache and packages before the app ran (download test)
$downloadCheck = 'not run'
$downloadReport = New-Object System.Collections.Generic.List[string]

try {
    Title 'CHECKING the machine (nothing is changed yet)'
    Assert-NotElevated
    foreach ($x in @($sacToml, (Join-Path $repo 'Cargo.toml'))) {
        if (-not (Test-Path -LiteralPath $x -PathType Leaf)) { Fail "not found: $x" }
    }
    foreach ($p in @($appDir, $indexTest)) {
        if (Is-Link $p) { Fail "refusing: $p is a reparse point" }
    }
    if (Test-Path -LiteralPath $indexTest) {
        $held = @(Get-ChildItem -LiteralPath $indexTest -Force)
        if ($held.Count -gt 0) {
            Fail "$indexTest already holds an index: run scripts\dev-topo-roundtrip.ps1 -Cleanup first, then this script again"
        }
        $indexExisted = $true
    }
    $listBefore = Get-AppDirList
    if ($Download -and -not $Game) { Fail '-Download needs -Game (the game whose fix is downloaded and applied)' }
    if ($KeepDownloads -and -not $Download) { Fail '-KeepDownloads only goes with -Download' }
    if ($Game) {
        $Game = [IO.Path]::GetFullPath($Game).TrimEnd('\')
        if (-not (Test-Path -LiteralPath $Game -PathType Container)) { Fail "-Game: not a folder: $Game" }
        if (Is-Link $Game) { Fail "-Game: refusing a reparse point: $Game" }
        if ($Game -notmatch '\\steamapps\\common\\[^\\]+$') { Fail "-Game: not the folder of one Steam game (...\steamapps\common\<game>): $Game" }
        foreach ($p in @('plans', 'journal', 'profiles')) {
            if ($listBefore -contains "$p|True") { Write-Host "note: $appDir\$p exists already; it stays, whatever the test writes there" -ForegroundColor Yellow }
        }
    }
    if ($Download) {
        foreach ($p in @($cacheDir, $packagesDir)) {
            if (Is-Link $p) { Fail "refusing: $p is a reparse point" }
        }
        $dlBefore = @{ Cache = (Get-TreeList $cacheDir); Packages = (Get-TreeList $packagesDir); CacheExisted = (Test-Path -LiteralPath $cacheDir); PackagesExisted = (Test-Path -LiteralPath $packagesDir) }
        foreach ($k in @('Cache', 'Packages')) {
            foreach ($e in $dlBefore[$k].Keys) {
                if ($dlBefore[$k][$e] -eq 'link') { Fail "refusing: $k holds a reparse point ($e); remove it by hand first" }
            }
        }
        $held = @($dlBefore.Cache.Keys | Where-Object { $_ -ne 'lock' }).Count + @($dlBefore.Packages.Keys | Where-Object { $_ -ne '.lock' }).Count
        if ($held -gt 0) { Write-Host "note: $cacheDir and $packagesDir hold $held entries already; they stay, and a package that is there is not downloaded again (the test is then not from an empty cache)" -ForegroundColor Yellow }
    }

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('rerun-app-check-' + [Guid]::NewGuid().ToString('N'))
    Write-Host ''
    Write-Host 'What this run writes, and removes again:' -ForegroundColor Yellow
    Write-Host "  - builds into $repo\target (release-speed test-key rerun-cli, rerun-workbench, rerun-app; Smart-App-Control source replacement)"
    Write-Host "  - the test index (built from this repository, signed with the test key) in $tmp (deleted at the end)"
    Write-Host "  - $indexTest : Rerun's index state of a test-key build, by rerun index import (deleted at the end; the real index folder is never touched)"
    if ($Download) {
        Write-Host "  - DOWNLOAD TEST: when you press Download in the app it fetches ONE package from its source on the internet (GitHub) into $cacheDir and unpacks it into $packagesDir" -ForegroundColor Yellow
        if ($KeepDownloads) { Write-Host '    -KeepDownloads: what the app added there is KEPT (and listed in the summary)' }
        else { Write-Host '    what the app added there is listed in the summary and removed again (exactly those entries; what was there before is never touched)' }
    }
    if ($Game) {
        Write-Host "  - APPLY TEST: the app can apply fixes to ONE game, $Game (you apply and undo them in the app; the script compares the folder afterwards)" -ForegroundColor Yellow
        Write-Host "    and writes Rerun's records of that transaction in $appDir (plans, journal, profiles: removed again at the end if they were not there and the transaction is closed)"
        Write-Host '  - nothing else: no firewall, no Steam settings, no other game'
    } else {
        Write-Host '  - nothing else: no registry, no firewall, no Steam, no game folder, no profile, no journal'
    }
    Write-Host ''

    Invoke-Build

    # The app lists every transaction of this account on its Applied page and can undo them: with
    # one already there the test would show (and could touch) the real ones, so it stops here.
    # Closed (reverted) transactions are history and stay; only one that is not closed, forgotten
    # or listed by plain `rerun status` (it needs attention) stops the test.
    $r = Invoke-Exe $cli @('status')
    if ($r.Code -ne 0) { Fail "rerun status failed ($($r.Code))" }
    $counts = Status-Counts $r.Out
    if ($null -eq $counts) { Fail 'rerun status printed no transaction summary; nothing was changed' }
    if ($counts.NotClosed -gt 0 -or $counts.Forgotten -gt 0 -or $r.Out -match '(?m)^transaction [0-9]{8}-[0-9a-f]{16}') { Fail "Rerun holds a transaction that is not closed or was forgotten ($($counts.NotClosed) not closed, $($counts.Forgotten) forgotten); the app would show it. Nothing was changed. See rerun status" }

    # ---------- the test index ----------
    Title 'BUILDING the test index and importing it into index-test'
    New-Item -ItemType Directory -Path $tmp | Out-Null
    $index = Join-Path $tmp 'index.json'
    $seq = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $issued = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $r = Invoke-Exe $workbench @('index', 'build', '--seq', "$seq", '--issued', $issued, '--root', $repo, $index)
    Show-Output $r
    if ($r.Code -ne 0) { Fail "rerun-workbench index build failed ($($r.Code))" }
    $r = Invoke-Exe $workbench @('index', 'sign-test', $index)
    Show-Output $r
    if ($r.Code -ne 0) { Fail "rerun-workbench index sign-test failed ($($r.Code))" }
    $touched = $true
    $r = Invoke-Exe $cli @('index', 'import', $index, "$index.sig")
    Show-Output $r
    if ($r.Code -ne 0 -or $r.Out -notmatch '(?m)^index [0-9]+ imported') { Fail "rerun index import failed ($($r.Code))" }
    if (-not (Test-Path -LiteralPath (Join-Path $indexTest 'current.json') -PathType Leaf)) { Fail 'import left no current.json in index-test' }
    Write-Host "self-check: index seq $seq imported into index-test"

    # ---------- the app ----------
    Write-Host ''
    Write-Host 'CHECKLIST (the window title shows one step at a time, all repeat until you close the app):' -ForegroundColor Yellow
    $steps = @(
        "A: status bar shows index seq $seq and 'Test key build'",
        "B: open Assassin's Creed: Director's Cut: all 3 issues of its Topo listed; EaglePatch once under Fixes, with both issues it solves",
        'C: hover the maximise button (snap flyout); double-click it; press it and drag away (no toggle)',
        'D: keyboard only: Tab through navigation, search field (reached?), switch, rows; Enter opens a game',
        'E: speed: open a game at once after the start (while the list still fills), go back, open it again; switch Library, Applied, System, Library a few times: does anything wait?'
    )
    if ($Game) {
        $steps += "F: APPLY TEST, only this game: $Game. Open it. The preselected fixes are ticked (verified, affect this PC); a fix that needs a download or the helper says so and cannot be ticked. Read the preview: every file, value, the launch profile, the warnings. Press Copy launch option and paste it into Notepad (it is only text). Press Apply once.",
        'G: the game page and Applied now show ONE card with everything in it; Esc and Tab in the next dialog work; press UNDO on the card (NOT ''Close without undoing'', which is forget and leaves the change in place), read what it restores, press Undo this change. The card is gone.',
        'H: Apply is greyed out until the preview is shown; select a fix, deselect it: the preview follows. Do not apply anything else.'
    }
    if ($Download) {
        $steps += 'I: DOWNLOAD TEST, same game. A fix that needs a package (EaglePatch) says it needs a download first and is not ticked. Tick it: the dialog "These files will be downloaded" lists name, version, source, release URL, host, SHA-256, licence and that the file is checked after. Press Cancel: nothing is downloaded and the fix stays unticked.'
        $steps += 'J: tick it again and press Download: the progress shows the size while it runs; when done the fix is ticked and the preview lists the package files. Apply once, then UNDO on the card (not ''Close without undoing'') as in G. Optional: tick another time while offline (network cable or Wi-Fi off): the dialog says Rerun cannot reach the source and offers Try again.'
    }
    $steps += 'CLOSE the app when done (the script then compares the game folder and cleans up)'
    foreach ($s in $steps) { Write-Host "  $s" }
    Write-Host ''

    if ($Game) {
        Title 'READING the game folder (hashing every file; big games take a while)'
        $gameBefore = Get-GameSnapshot $Game
        Write-Host "self-check: $($gameBefore.Count) entries of $Game recorded"
    }

    Title 'STARTING the app'
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $appExe
    $psi.UseShellExecute = $false
    $psi.WorkingDirectory = $repo
    # The test-key app writes timing lines to standard error; they are read after it ends.
    $psi.RedirectStandardError = $true
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $appProc = [Diagnostics.Process]::Start($psi)
    $traceTask = $appProc.StandardError.ReadToEndAsync()
    while ($sw.Elapsed.TotalSeconds -lt 30 -and -not $appProc.HasExited) {
        $appProc.Refresh()
        if ($appProc.MainWindowHandle -ne [IntPtr]::Zero) { $firstWindowMs = [int]$sw.Elapsed.TotalMilliseconds; break }
        Start-Sleep -Milliseconds 20
    }
    if ($null -eq $firstWindowMs) { Fail 'the app showed no window within 30 s (or exited at once)' }
    Write-Host "first visible window after $firstWindowMs ms (release-speed build, target under 1 s)"

    $lastSample = [datetime]::MinValue
    $workDone = $false
    $exeFull = [IO.Path]::GetFullPath($appExe)
    while (-not $appProc.HasExited) {
        $elapsed = $sw.Elapsed.TotalSeconds
        $n = [int][math]::Floor($elapsed / $StepSeconds) % $steps.Count
        Title "$($steps[$n])"
        if (-not $workDone -and $elapsed -ge 5) {
            $appProc.Refresh()
            $workingSet = $appProc.WorkingSet64
            $workDone = $true
        }
        if (((Get-Date) - $lastSample).TotalSeconds -ge 5) {
            $lastSample = Get-Date
            try {
                foreach ($m in $appProc.Modules) {
                    $f = $m.FileName
                    if ([string]::Equals($f, $exeFull, [StringComparison]::OrdinalIgnoreCase)) { continue }
                    $sys = Join-Path $env:SystemRoot 'System32\'
                    $sxs = Join-Path $env:SystemRoot 'WinSxS\'
                    $wow = Join-Path $env:SystemRoot 'SysWOW64\'
                    if ($f.StartsWith($sys, [StringComparison]::OrdinalIgnoreCase) -or $f.StartsWith($sxs, [StringComparison]::OrdinalIgnoreCase) -or $f.StartsWith($wow, [StringComparison]::OrdinalIgnoreCase)) { continue }
                    $foreign[$f.ToLowerInvariant()] = $true
                }
            } catch { }
            $appProc.Refresh()
        }
        Start-Sleep -Milliseconds 500
    }
    $appProc.WaitForExit()
    $exitCode = $appProc.ExitCode
    $traceText = $traceTask.Result
    $verdict = 'PASS'
}
catch {
    $errorText = $_.Exception.Message
    $verdict = 'FAIL'
}
finally {
    $Host.UI.RawUI.WindowTitle = "$script:HelperTitle - CLEANING UP"
    if ($appProc -and -not $appProc.HasExited) { try { $appProc.Kill(); $appProc.WaitForExit() } catch { } }
    # The apply test: the named game folder against its snapshot, then Rerun's records of the
    # test (only folders that were not there before, only if the game folder is identical again
    # and `rerun status` lists no transaction), before the index cleanup compares the top level.
    if ($gameBefore) {
        try {
            $diff = @(Compare-GameSnapshot $gameBefore (Get-GameSnapshot $Game))
            $applyCheck = if ($diff.Count -eq 0) { 'PASS' } else { 'FAIL: the game folder differs: ' + (($diff | Select-Object -First 20) -join '; ') }
            $newDirs = @('plans', 'journal', 'profiles') | Where-Object {
                (Test-Path -LiteralPath (Join-Path $appDir $_) -PathType Container) -and ($listBefore -notcontains "$_|True")
            }
            if ($newDirs.Count -gt 0) {
                $kept = ''
                if ($applyCheck -ne 'PASS') { $kept = 'the game folder differs' }
                else {
                    $r = Invoke-Exe $cli @('status')
                    $after = if ($r.Code -eq 0) { Status-Counts $r.Out } else { $null }
                    if ($r.Code -ne 0) { $kept = "rerun status failed ($($r.Code))" }
                    elseif ($null -eq $after) { $kept = 'rerun status printed no transaction summary' }
                    elseif ($after.NotClosed -gt 0 -or $r.Out -match '(?m)^transaction [0-9]{8}-[0-9a-f]{16}') { $kept = 'rerun status lists a transaction that is not closed' }
                    elseif ($after.Forgotten -gt 0) { $kept = 'a transaction was closed without undoing (forgotten): its changes stay on disk' }
                }
                if ($kept) {
                    $applyCheck += " (Rerun's records kept in ${appDir}: $($newDirs -join ', '); $kept; undo the transaction with rerun revert, then remove them by hand)"
                    if ($applyCheck -notlike 'FAIL*') { $applyCheck = 'FAIL: ' + $applyCheck }
                } else {
                    foreach ($d in $newDirs) {
                        $p = Join-Path $appDir $d
                        if ((Is-Link $p) -or -not (Test-NoLinks $p)) { $applyCheck = "FAIL: $p holds a reparse point: left alone" } else { Remove-Item -LiteralPath $p -Recurse -Force }
                    }
                }
            }
        } catch { $applyCheck = "FAIL: apply check error: $($_.Exception.Message)" }
    }
    # The download test: report what the app added to the cache and the packages folder, then
    # remove exactly that (unless -KeepDownloads), but only when the game folder is identical
    # again and `rerun status` lists no open transaction. Nothing that was there before is
    # touched; an entry that was there and changed is never modified.
    if ($dlBefore) {
        try {
            $added = @{ Cache = New-Object System.Collections.Generic.List[string]; Packages = New-Object System.Collections.Generic.List[string] }
            $changed = New-Object System.Collections.Generic.List[string]
            $hasLink = $false
            $roots = @{ Cache = $cacheDir; Packages = $packagesDir }
            foreach ($k in @('Cache', 'Packages')) {
                if ((Test-Path -LiteralPath $roots[$k]) -and (Is-Link $roots[$k])) { $hasLink = $true; $downloadReport.Add("$k folder is a reparse point: left alone"); continue }
                $now = Get-TreeList $roots[$k]
                foreach ($e in $now.Keys) {
                    if ($now[$e] -eq 'link') { $hasLink = $true; $downloadReport.Add("$k\$e is a link: left alone") }
                    if (-not $dlBefore[$k].ContainsKey($e)) { $added[$k].Add($e) }
                    elseif ($dlBefore[$k][$e] -ne $now[$e]) { $changed.Add("$k\$e") }
                }
                foreach ($e in $dlBefore[$k].Keys) { if (-not $now.ContainsKey($e)) { $changed.Add("$k\$e (gone)") } }
            }
            # What was downloaded: every archive in the cache must be named by its own SHA-256.
            $bad = 0
            foreach ($e in ($added.Cache | Sort-Object)) {
                $f = Join-Path $cacheDir $e
                if ((Get-Item -LiteralPath $f -Force) -is [IO.DirectoryInfo]) { continue }
                if ($e -eq 'lock') { continue }
                $len = (Get-Item -LiteralPath $f -Force).Length
                $h = Sha256-File $f
                if ($h -eq $e) { $downloadReport.Add("downloaded: cache\$e  $len bytes  SHA-256 equals its name: ok") }
                else { $bad++; $downloadReport.Add("downloaded: cache\$e  $len bytes  SHA-256 is ${h}: NOT its name") }
            }
            foreach ($e in ($added.Packages | Sort-Object)) {
                if ($e -ne '.lock') {
                    $item = Get-Item -LiteralPath (Join-Path $packagesDir $e) -Force
                    if ($item -isnot [IO.DirectoryInfo]) { $downloadReport.Add("unpacked: packages\$e  $($item.Length) bytes") }
                }
            }
            if ($added.Cache.Count -eq 0 -and $added.Packages.Count -eq 0) { $downloadReport.Add('the app added nothing to the cache or the packages folder (nothing was downloaded, or it was there already)') }
            $verdictDl = 'PASS'
            if ($bad -gt 0) { $verdictDl = 'FAIL: an archive is not named by its SHA-256' }
            if ($changed.Count -gt 0) { $verdictDl = 'FAIL: entries that were there before changed (left alone): ' + (($changed | Select-Object -First 10) -join '; ') }
            if ($hasLink) { $verdictDl = 'FAIL: a link was found (left alone)' }
            if ($KeepDownloads) {
                $downloadCheck = "$verdictDl (kept as asked: -KeepDownloads)"
            } elseif ($verdictDl -ne 'PASS') {
                $downloadCheck = "$verdictDl; nothing was removed"
            } elseif ($applyCheck -ne 'PASS') {
                $downloadCheck = "$verdictDl; kept because the game folder check did not pass"
            } else {
                $r = Invoke-Exe $cli @('status')
                $after = if ($r.Code -eq 0) { Status-Counts $r.Out } else { $null }
                if ($null -eq $after -or $after.NotClosed -gt 0 -or $after.Forgotten -gt 0 -or $r.Out -match '(?m)^transaction [0-9]{8}-[0-9a-f]{16}') {
                    $downloadCheck = "$verdictDl; kept because rerun status lists a transaction that is not closed or was forgotten"
                } else {
                    # Files first, then folders (deepest first), exactly the entries that were added.
                    foreach ($k in @('Cache', 'Packages')) {
                        $files = @($added[$k] | Where-Object { -not ((Get-Item -LiteralPath (Join-Path $roots[$k] $_) -Force) -is [IO.DirectoryInfo]) })
                        $dirs = @($added[$k] | Where-Object { (Get-Item -LiteralPath (Join-Path $roots[$k] $_) -Force) -is [IO.DirectoryInfo] } | Sort-Object { $_.Length } -Descending)
                        foreach ($e in $files) { Remove-Item -LiteralPath (Join-Path $roots[$k] $e) -Force }
                        foreach ($e in $dirs) {
                            $d = Join-Path $roots[$k] $e
                            if (@(Get-ChildItem -LiteralPath $d -Force).Count -eq 0) { Remove-Item -LiteralPath $d -Force }
                            else { $downloadReport.Add("kept: $k\$e is not empty (something else wrote there)") }
                        }
                        $existed = if ($k -eq 'Cache') { $dlBefore.CacheExisted } else { $dlBefore.PackagesExisted }
                        if (-not $existed -and (Test-Path -LiteralPath $roots[$k]) -and @(Get-ChildItem -LiteralPath $roots[$k] -Force).Count -eq 0) { Remove-Item -LiteralPath $roots[$k] -Force }
                    }
                    $downloadCheck = "$verdictDl; what the app added was removed again"
                }
            }
        } catch { $downloadCheck = "FAIL: download check error: $($_.Exception.Message)" }
    }
    $problems = New-Object System.Collections.Generic.List[string]
    try {
        if ($touched) {
            if (Is-Link $indexTest) { $problems.Add("$indexTest is a reparse point: left alone") }
            elseif (Test-Path -LiteralPath $indexTest) { Remove-Item -LiteralPath $indexTest -Recurse -Force }
            if ($indexExisted) { New-Item -ItemType Directory -Path $indexTest | Out-Null }
        }
        if ($tmp -and (Test-Path -LiteralPath $tmp) -and -not (Is-Link $tmp)) { Remove-Item -LiteralPath $tmp -Recurse -Force }
        if ($tmp -and (Test-Path -LiteralPath $tmp)) { $problems.Add("$tmp is still there") }
        if ($touched) {
            $now = Get-Item -LiteralPath $indexTest -ErrorAction SilentlyContinue
            if ($indexExisted) {
                if (-not $now -or @(Get-ChildItem -LiteralPath $indexTest -Force).Count -ne 0) { $problems.Add('index-test is not the empty folder it was') }
            } elseif ($now) { $problems.Add('index-test is still there') }
            $a = $listBefore
            $b = Get-AppDirList
            if ($Download -and $KeepDownloads) {
                # Kept on purpose: cache and packages may be new.
                $a = @($a | Where-Object { $_ -notlike 'cache|*' -and $_ -notlike 'packages|*' })
                $b = @($b | Where-Object { $_ -notlike 'cache|*' -and $_ -notlike 'packages|*' })
            }
            if ((Compare-Object $a $b)) { $problems.Add("the top level of $appDir differs from before") }
        }
    } catch { $problems.Add("cleanup error: $($_.Exception.Message)") }
    if ($touched -or $tmp) {
        $cleanup = if ($problems.Count -eq 0) { 'PASS' } else { 'FAIL: ' + ($problems -join '; ') }
    }
}

# ---------- the summary ----------
$ws = if ($null -ne $workingSet) { ('{0:N1} MB' -f ($workingSet / 1MB)) } else { 'not measured' }
$fw = if ($null -ne $firstWindowMs) { "$firstWindowMs ms" } else { 'not measured' }
$summary.Add("Rerun DEV app check (index seq $seq, release-speed test-key build)")
if ($errorText) { $summary.Add("STOPPED: $errorText") }
$summary.Add("run: $verdict (app exit code $exitCode)")
$summary.Add("measured: first visible window $fw (release-speed build), working set after 5 s $ws")
$traceLines = @($traceText -split "`r?`n" | Where-Object { $_ -match '^\[\s*[0-9.]+ ms\]' })
# Where the start time goes (P5-5 preparation): the process age at main (what passed before main:
# loader, antivirus or Smart App Control scan of a freshly built exe) and the phases in main.
$exeKb = [int]((Get-Item $appExe).Length / 1KB)
$summary.Add("measured: start phases of the app ($exeKb KB exe; first launch after a build is often slower: run the check twice and compare):")
foreach ($l in ($traceLines | Where-Object { $_ -match '(main|ui): (entered|backend|window object|shown|event loop|window built)' } | Select-Object -First 12)) { $summary.Add("  $l") }
# The timing lines of the app: how long each job of the worker took, and click to page.
$clicks = @{}
foreach ($l in $traceLines) {
    if ($l -match '^\[\s*([0-9.]+) ms\] ui: game ([0-9]+) clicked') { $clicks[$matches[2]] = [double]$matches[1] }
    elseif ($l -match '^\[\s*([0-9.]+) ms\] ui: game ([0-9]+) shown' -and $clicks.ContainsKey($matches[2])) {
        $summary.Add(('measured: game {0}: click to page {1:N0} ms' -f $matches[2], ([double]$matches[1] - $clicks[$matches[2]])))
        $clicks.Remove($matches[2])
    }
}
foreach ($l in ($traceLines | Where-Object { $_ -match 'worker: ' } | Select-Object -First 40)) { $summary.Add("trace: $l") }
$foreignList = @($foreign.Keys | Sort-Object)
if ($null -ne $firstWindowMs) {
    if ($foreignList.Count -eq 0) { $summary.Add('measured: DLLs from outside System32/WinSxS/SysWOW64: none -> PASS') }
    else { $summary.Add('measured: DLLs from outside System32/WinSxS/SysWOW64 -> FAIL'); foreach ($f in $foreignList) { $summary.Add("  $f") } }
}
$summary.Add("cleanup (index-test, temp folder): $cleanup")
if ($Game) { $summary.Add("apply test ($Game, the folder compared with its snapshot; Rerun's records removed): $applyCheck; files not hashed (unreadable): $script:notHashed") }
if ($Download) {
    foreach ($l in $downloadReport) { $summary.Add("download test: $l") }
    $summary.Add("download test (cache and packages of <AppDir>, listed before and after): $downloadCheck")
}
$summary.Add('')
$summary.Add('By eye, report in the chat (ok / not ok, and what you saw):')
$summary.Add("  A status bar: index seq $seq and 'Test key build'")
$summary.Add("  B Assassin's Creed: Director's Cut: 3 issues listed; EaglePatch once under Fixes with both issues")
$summary.Add('  C maximise button: snap flyout on hover; double-click toggles; press and drag away does not toggle')
$summary.Add('  D keyboard only: navigation, search field reached, switch, rows, Enter opens a game')
$summary.Add('  E speed: a game opened at once after the start, back, opened again; Library, Applied, System, Library a few times: did anything wait? (and where)')
if ($Game) {
    $summary.Add('  F the preselection (verified, affects this PC), the preview (every file, value, launch profile, warnings), Copy launch option pasted into Notepad, Apply once')
    $summary.Add('  G one card on the game page and under Applied; Esc and Tab in the undo dialog; what Undo said it would restore')
    $summary.Add('  H Apply greyed out until the preview showed; selecting and deselecting a fix updated the preview')
}
if ($Download) {
    $summary.Add('  I the fix that needs a package is not ticked and says so; the consent dialog lists name, version, source, release URL, host, SHA-256, licence, and that it is checked after; Cancel downloaded nothing')
    $summary.Add('  J Download: progress with sizes, then the fix is ticked and the preview lists the package files; Apply once, Undo on the card; (optional) offline: "cannot reach the source" and Try again')
}
Set-Clipboard -Value ($summary -join "`r`n")
Write-Host ''
$summary | ForEach-Object { Write-Host $_ }
Write-Host ''
Write-Host 'Summary is in the clipboard.'
$final = if ($verdict -eq 'PASS' -and $cleanup -notlike 'FAIL*' -and $applyCheck -notlike 'FAIL*' -and $downloadCheck -notlike 'FAIL*') { 'DONE: the summary is in the clipboard, report it' } else { 'FAILED: the summary is in the clipboard, report it' }
Title $final
