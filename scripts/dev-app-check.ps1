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
[CmdletBinding()]
param(
    [ValidateRange(5, 120)][int]$StepSeconds = 45,
    [string]$Game = ''
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
    if ($Game) {
        $Game = [IO.Path]::GetFullPath($Game).TrimEnd('\')
        if (-not (Test-Path -LiteralPath $Game -PathType Container)) { Fail "-Game: not a folder: $Game" }
        if (Is-Link $Game) { Fail "-Game: refusing a reparse point: $Game" }
        if ($Game -notmatch '\\steamapps\\common\\[^\\]+$') { Fail "-Game: not the folder of one Steam game (...\steamapps\common\<game>): $Game" }
        foreach ($p in @('plans', 'journal', 'profiles')) {
            if ($listBefore -contains "$p|True") { Write-Host "note: $appDir\$p exists already; it stays, whatever the test writes there" -ForegroundColor Yellow }
        }
    }

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('rerun-app-check-' + [Guid]::NewGuid().ToString('N'))
    Write-Host ''
    Write-Host 'What this run writes, and removes again:' -ForegroundColor Yellow
    Write-Host "  - builds into $repo\target (release-speed test-key rerun-cli, rerun-workbench, rerun-app; Smart-App-Control source replacement)"
    Write-Host "  - the test index (built from this repository, signed with the test key) in $tmp (deleted at the end)"
    Write-Host "  - $indexTest : Rerun's index state of a test-key build, by rerun index import (deleted at the end; the real index folder is never touched)"
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
    $r = Invoke-Exe $cli @('status', '--all')
    if ($r.Code -ne 0) { Fail "rerun status failed ($($r.Code))" }
    if ($r.Out -match '[0-9]{8}-[0-9a-f]{16}') { Fail 'Rerun already holds a transaction (open, forgotten or cleanup pending); the app would show it. Nothing was changed. See rerun status --all' }

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
                    if ($r.Code -ne 0) { $kept = "rerun status failed ($($r.Code))" }
                    elseif ($r.Out -match '[0-9]{8}-[0-9a-f]{16}') { $kept = 'rerun status lists a transaction' }
                    else {
                        # "Close without undoing" (forget) leaves the changes on disk: the records stay.
                        $all = Invoke-Exe $cli @('status', '--all')
                        if ($all.Code -ne 0) { $kept = "rerun status --all failed ($($all.Code))" }
                        elseif ($all.Out -match '(?i)forgotten') { $kept = 'a transaction was closed without undoing (forgotten)' }
                    }
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
            if ((Compare-Object $listBefore (Get-AppDirList))) { $problems.Add("the top level of $appDir differs from before") }
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
# The timing lines of the app: how long each job of the worker took, and click to page.
$traceLines = @($traceText -split "`r?`n" | Where-Object { $_ -match '^\[\s*[0-9.]+ ms\]' })
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
Set-Clipboard -Value ($summary -join "`r`n")
Write-Host ''
$summary | ForEach-Object { Write-Host $_ }
Write-Host ''
Write-Host 'Summary is in the clipboard.'
$final = if ($verdict -eq 'PASS' -and $cleanup -notlike 'FAIL*' -and $applyCheck -notlike 'FAIL*') { 'DONE: the summary is in the clipboard, report it' } else { 'FAILED: the summary is in the clipboard, report it' }
Title $final
