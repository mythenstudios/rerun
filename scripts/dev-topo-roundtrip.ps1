# [DEV] Topo round trip on the developer machine (docs/09-testing.md, "Topo round trip on the
# developer machine"; plan P4-13, ADR 0024 amendment P4-13). Windows PowerShell 5.1, in a normal
# (not administrator) PowerShell window, from the repository:
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\dev-topo-roundtrip.ps1 -Prepare
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\dev-topo-roundtrip.ps1 -Case <name> -PlanSha256 <64 hex>
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\dev-topo-roundtrip.ps1 -RevertOnly <txn> [-WithHelper]
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\dev-topo-roundtrip.ps1 -Cleanup
#
# The cases come from a local file (default .claude\p4-13\cases.psd1; never committed, it holds
# paths of this machine; -CaseFile names another one, and -Prepare -Case <file.psd1> too):
#
#   @{ Cases = @(
#       @{ Name = 'tru-threads'; AppId = 8140; Picks = @('crash-many-threads/limit-threads')
#          GameFolder = 'D:\SteamLibrary\steamapps\common\Tomb Raider Underworld'
#          Game = 'steam'; Check = 'the game reaches the main menu'; Expect = @{ Threads = 8 }
#          Helper = $false }
#   ) }
#
# Per case: Name (a-z, 0-9, '-'), AppId, Picks (<issue>/<variant>, one or more), GameFolder
# (<library>\steamapps\common\<folder>), Game ('steam': started through Steam during the run;
# 'none': never started, the folder must come back strictly identical), Check (the instruction
# shown while the game runs), Expect (@{} or @{ Threads = <n> } or @{ ExcludeFirst = 'thread' |
# 'core' }: what the affinity of the running game must show), Helper ($true when the plan adds
# firewall rules; checked against the plan). Optional: UserData (a folder below Documents),
# Exe (the game's process, relative to GameFolder; default: the plan's main executable), Upc
# ($true: Ubisoft Connect must run and be signed in before the start).
#
# What it changes, and removes again (the list is also printed before anything happens):
#  -Prepare: builds into target\ (rerun-cli and rerun-workbench with the feature test-key, the
#    release rerun-launch, the test-key helper if a case needs it); copies rerun.exe,
#    rerun-launch.exe and (for firewall cases) helper\rerun-helper.exe to
#    %LOCALAPPDATA%\RerunTest\p4-13; writes target\dev-index\index.json(.sig), imports it into
#    <AppDir>\index-test (the test-key state; the real <AppDir>\index is never touched); stores
#    one plan per case in <AppDir>\plans (Rerun's own state, never deleted by a script); writes
#    .claude\p4-13\stage.json and S<n>-plans.txt. No game folder, no firewall rule, no profile.
#  -Case: applies exactly the plan the user released by its SHA-256 (rerun apply), lets you start
#    the game through Steam, reverts it (rerun revert) and compares four snapshots of the game
#    folder, the user data folder, Rerun's firewall rules, <AppDir>\profiles and <AppDir>\elevate.
#    For a firewall case it installs the test-key helper to Program Files\Rerun first and
#    removes it again in any case (4 administrator prompts, each named in the window title).
#    The launch option goes to the clipboard; you paste it in Steam and remove it again (the one
#    Enter of the run confirms that). Only the hash -Prepare stored for that case is accepted,
#    and a plan with a registry op is refused (the snapshots do not cover the registry yet).
#    The test-key helper stays installed while the game runs. Writes .claude\p4-13\results\<case>-<time>.txt.
#  -RevertOnly: rerun revert <txn> (with -WithHelper: helper installed before, removed after).
#  -Cleanup: deletes %LOCALAPPDATA%\RerunTest\p4-13 and <AppDir>\index-test (only when no
#    transaction is open, no launch profile exists, the staged rerun.exe is there and no helper
#    is installed; otherwise it deletes nothing). The journal and the plans stay.
#
# It never deletes a firewall rule or a journal entry past Rerun, never changes Steam's settings,
# never runs elevated itself; the instruction is always in the window title; no yes/no question.

[CmdletBinding()]
param(
    [switch]$Prepare,
    [string]$Case,
    [ValidatePattern('^[0-9a-f]{64}$')][string]$PlanSha256,
    [ValidatePattern('^[0-9]{8}-[0-9a-f]{16}$')][string]$RevertOnly,
    [switch]$WithHelper,
    [switch]$Cleanup,
    [string]$CaseFile,
    [ValidateRange(1, 99)][int]$Session = 1,
    [ValidateRange(1, 120)][int]$WaitMinutes = 20
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'dev-helper-common.ps1')
$script:HelperTitle = 'Rerun DEV topo round trip'

# ---------- rerun's output lines and exit codes ----------
# Bound to rerun's messages by crates/rerun-cli/src/tests.rs
# (`the_dev_topo_script_parses_rerun_s_lines`): change both together.
$script:Banner = 'rerun: TEST-KEY BUILD - trusts the published index test key; index state in index-test; never for real use'
$script:ReApplyWith = '^apply with: rerun apply (?<hash>[0-9a-f]{64})$'
$script:ReRevertWith = '^revert with: rerun revert (?<txn>[0-9]{8}-[0-9a-f]{16})$'
$script:ReReverted = '^transaction (?<txn>[0-9]{8}-[0-9a-f]{16}) reverted and closed$'
$script:ReOption = '^  (?<option>"(?<install>[^"]+)\\rerun-launch\.exe" --profile (?<id>[0-9a-f]{32}) %command%)$'
$script:ReProfile = '^     launch profile (?<id>[0-9a-f]{32}): method (?<method>[a-z]+), '
$script:ReMainExe = '^  main executable: (?<exe>.+)$'
$script:ReFirewallRule = '^  firewall rule: '
$script:ReNoTransactions = '^no transactions$'
$script:ReStatusCounts = '^[0-9]+ transactions?: (?<open>[0-9]+) not closed, [0-9]+ closed, [0-9]+ forgotten'
$script:ReOrphans = '^Rerun firewall rules'
$script:ReImported = '^index [0-9]+ imported'
$script:ReRegistryOp = '^op [0-9]+: (create key|set value|add tokens|set gpu preference): '
$script:ReRoot = '^root (?<index>[0-9]+): (?<path>.+)$'
$script:ReSteamRoot = '^  Steam app (?<app>[0-9]+), library: '
$ExitReport = 0
$ExitFatal = 1
$ExitUsage = 2
$ExitRefused = 3
$ExitRolledBack = 4
$ExitOpen = 5

# ---------- places ----------
$script:Local = Join-Path $repo '.claude\p4-13'
$script:StageFile = Join-Path $script:Local 'stage.json'
$script:Lad = [Environment]::GetFolderPath('LocalApplicationData')
$script:AppDir = Join-Path $script:Lad 'Rerun'
$script:StageParent = Join-Path $script:Lad 'RerunTest'
$script:Stage = Join-Path $script:StageParent 'p4-13'
$script:StagedRerun = Join-Path $script:Stage 'rerun.exe'
$script:StagedLaunch = Join-Path $script:Stage 'rerun-launch.exe'
$script:StagedHelperDir = Join-Path $script:Stage 'helper'
$script:StagedHelper = Join-Path $script:StagedHelperDir 'rerun-helper.exe'
$script:DevIndex = Join-Path $repo 'target\dev-index'

function Assert-Plain([string]$path) {
    if ((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Fail "refusing: $path is a reparse point (junction or link)"
    }
}

function Sha256-File([string]$path) {
    $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite, Delete')
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($sha.ComputeHash($fs)) -replace '-', '').ToLowerInvariant() } finally { $sha.Dispose() }
    } finally { $fs.Dispose() }
}

# One argument for a command line (CommandLineToArgvW rules); a quote in an argument stops.
function Quote-Arg([string]$a) {
    if ($a -match '^[A-Za-z0-9_.:/\\=-]+$') { return $a }
    if ($a.Contains('"')) { Fail "refusing an argument with a double quote: $a" }
    if ($a.EndsWith('\')) { $a += '\' }
    return '"' + $a + '"'
}

# Runs a program without a window; returns its exit code and its stdout and stderr (UTF-8).
function Invoke-Exe([string]$exe, [string[]]$arguments) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = (@($arguments | ForEach-Object { Quote-Arg $_ }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $psi.StandardOutputEncoding = $utf8
    $psi.StandardErrorEncoding = $utf8
    $psi.WorkingDirectory = $repo
    $p = [Diagnostics.Process]::Start($psi)
    try {
        $o = $p.StandardOutput.ReadToEndAsync()
        $e = $p.StandardError.ReadToEndAsync()
        $p.WaitForExit()
        return @{ Code = $p.ExitCode; Out = $o.Result; Err = $e.Result }
    } finally { $p.Dispose() }
}

function Lines([string]$text) {
    return @($text -split "`n" | ForEach-Object { $_.TrimEnd("`r") })
}

# The first line of $text that matches $re, as a Match; $null if none.
function Find-Line([string]$text, [string]$re) {
    foreach ($l in (Lines $text)) {
        $m = [regex]::Match($l, $re)
        if ($m.Success) { return $m }
    }
    return $null
}

# The staged rerun.exe; its first stderr line must be the banner of a test-key build.
function Invoke-Rerun([string[]]$arguments) {
    $r = Invoke-Exe $script:StagedRerun $arguments
    $first = (Lines $r.Err)[0]
    if ($first -ne $script:Banner) { Fail "the staged rerun.exe is not a test-key build (first stderr line: $first)" }
    $r.Err = ((Lines $r.Err) | Select-Object -Skip 1) -join "`n"
    return $r
}

function Show-Output($r) {
    if ($r.Out) { Write-Host $r.Out.TrimEnd() }
    if ($r.Err.Trim()) { Write-Host $r.Err.TrimEnd() -ForegroundColor Yellow }
}

function Assert-Built([string]$what, [string]$path) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Fail "not built: $what ($path)" }
}

function Invoke-Cargo([string[]]$arguments) {
    Push-Location $repo
    try {
        $ErrorActionPreference = 'Continue'
        & cargo @arguments
        $code = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
    } finally { Pop-Location }
    if ($code -ne 0) { Fail "cargo $($arguments -join ' ') failed ($code)" }
}

# ---------- the cases ----------
function Read-Cases([string]$path) {
    if (-not $path) { $path = Join-Path $script:Local 'cases.psd1' }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Fail "case file not found: $path" }
    $data = Import-PowerShellDataFile -LiteralPath $path
    if (-not $data.Cases) { Fail "${path}: no Cases" }
    $seen = @{}
    foreach ($c in $data.Cases) {
        if ("$($c.Name)" -notmatch '^[a-z0-9]+(-[a-z0-9]+)*$') { Fail "${path}: a case name is not a-z, 0-9 and '-': $($c.Name)" }
        if ($seen.ContainsKey($c.Name)) { Fail "${path}: case $($c.Name) twice" }
        $seen[$c.Name] = $true
        if (-not ($c.AppId -is [int]) -or $c.AppId -lt 1) { Fail "$($c.Name): AppId is not a Steam app ID" }
        if (@($c.Picks).Count -lt 1) { Fail "$($c.Name): no Picks" }
        foreach ($p in @($c.Picks)) { if ("$p" -notmatch '^[a-z0-9-]+/[a-z0-9-]+$') { Fail "$($c.Name): pick $p is not <issue>/<variant>" } }
        if ("$($c.GameFolder)" -notmatch '^[A-Za-z]:\\.+\\steamapps\\common\\[^\\]+$') { Fail "$($c.Name): GameFolder is not <library>\steamapps\common\<folder>" }
        if (-not (Test-Path -LiteralPath $c.GameFolder -PathType Container)) { Fail "$($c.Name): GameFolder not found: $($c.GameFolder)" }
        Assert-Plain $c.GameFolder
        if (@('steam', 'none') -notcontains $c.Game) { Fail "$($c.Name): Game is steam or none" }
        if (-not $c.Check) { Fail "$($c.Name): no Check" }
        if ($null -eq $c.Expect -or -not ($c.Expect -is [hashtable])) { Fail "$($c.Name): Expect is @{}, @{ Threads = n } or @{ ExcludeFirst = 'thread'|'core' }" }
        foreach ($k in $c.Expect.Keys) {
            if (@('Threads', 'ExcludeFirst') -notcontains $k) { Fail "$($c.Name): Expect.$k is unknown" }
        }
        if ($c.Expect.ContainsKey('Threads') -and (-not ($c.Expect.Threads -is [int]) -or $c.Expect.Threads -lt 1 -or $c.Expect.Threads -gt 4096)) { Fail "$($c.Name): Expect.Threads is 1 to 4096" }
        if ($c.Expect.ContainsKey('ExcludeFirst') -and @('thread', 'core') -notcontains $c.Expect.ExcludeFirst) { Fail "$($c.Name): Expect.ExcludeFirst is thread or core" }
        if (-not ($c.Helper -is [bool])) { Fail "$($c.Name): Helper is `$true or `$false" }
        if ($c.UserData -and ("$($c.UserData)" -match '(^|\\)\.\.?(\\|$)' -or "$($c.UserData)" -match '^[\\/]|:')) { Fail "$($c.Name): UserData is a folder below Documents (relative, no '..')" }
        if ($c.Exe -and ("$($c.Exe)" -match '(^|\\)\.\.?(\\|$)' -or "$($c.Exe)" -match '^[\\/]|:' -or "$($c.Exe)" -notmatch '\.exe$')) { Fail "$($c.Name): Exe is an .exe relative to GameFolder" }
    }
    return @($data.Cases)
}

# appmanifest_<id>.acf of the library the game folder is in: StateFlags and buildid.
function Read-Manifest($c) {
    $steamapps = Split-Path (Split-Path $c.GameFolder -Parent) -Parent
    $acf = Join-Path $steamapps "appmanifest_$($c.AppId).acf"
    if (-not (Test-Path -LiteralPath $acf -PathType Leaf)) { Fail "$($c.Name): $acf not found (AppId or GameFolder wrong?)" }
    $text = [IO.File]::ReadAllText($acf)
    $flags = [regex]::Match($text, '"StateFlags"\s+"([0-9]+)"')
    $build = [regex]::Match($text, '"buildid"\s+"([0-9]+)"')
    if (-not $flags.Success -or -not $build.Success) { Fail "${acf}: no StateFlags or buildid" }
    return @{ StateFlags = $flags.Groups[1].Value; BuildId = $build.Groups[1].Value }
}

# ---------- snapshots ----------
# Every entry below $root by its relative path (ordinal): 'D|<attrs>' for a folder, 'L|<attrs>'
# for a reparse point (never followed), 'F|<length>|<attrs>|<sha256>' for a file; <attrs> are
# read-only, hidden and system. A missing root is an empty map with the key '<missing>'.
function Get-TreeSnapshot([string]$root) {
    $map = New-Object 'System.Collections.Generic.SortedDictionary[string,string]' ([StringComparer]::Ordinal)
    if (-not (Test-Path -LiteralPath $root)) { $map['<missing>'] = 'missing'; return , $map }
    Assert-Plain $root
    $keep = [IO.FileAttributes]'ReadOnly, Hidden, System'
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push('')
    while ($stack.Count -gt 0) {
        $rel = $stack.Pop()
        $dir = if ($rel) { Join-Path $root $rel } else { $root }
        foreach ($i in ([IO.DirectoryInfo]::new($dir)).GetFileSystemInfos()) {
            $r = if ($rel) { "$rel\$($i.Name)" } else { $i.Name }
            $attrs = [int]($i.Attributes -band $keep)
            if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                $map[$r] = "L|$attrs"
            } elseif ($i -is [IO.DirectoryInfo]) {
                $map[$r] = "D|$attrs"
                $stack.Push($r)
            } else {
                $map[$r] = "F|$($i.Length)|$attrs|$(Sha256-File $i.FullName)"
            }
        }
    }
    return , $map
}

# Rerun's firewall rules (group Rerun or a display name starting with Rerun).
function Get-FirewallSnapshot {
    $map = New-Object 'System.Collections.Generic.SortedDictionary[string,string]' ([StringComparer]::Ordinal)
    foreach ($r in @(Get-NetFirewallRule | Where-Object { $_.Group -eq 'Rerun' -or $_.DisplayName -like 'Rerun*' })) {
        $program = ($r | Get-NetFirewallApplicationFilter).Program
        $map["$($r.DisplayName)|$($r.Name)"] = "$($r.Direction)|$($r.Action)|$($r.Enabled)|$program"
    }
    return , $map
}

function Get-Snapshot($c, [string]$userData) {
    $s = @{
        Game     = Get-TreeSnapshot $c.GameFolder
        Firewall = Get-FirewallSnapshot
        Profiles = Get-TreeSnapshot (Join-Path $script:AppDir 'profiles')
        Elevate  = Get-TreeSnapshot (Join-Path $script:AppDir 'elevate')
    }
    if ($userData) { $s.UserData = Get-TreeSnapshot $userData }
    return $s
}

# The keys whose values differ between two maps (also present in only one).
function Diff-Map($a, $b) {
    $keys = New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::Ordinal)
    foreach ($k in $a.Keys) { [void]$keys.Add($k) }
    foreach ($k in $b.Keys) { [void]$keys.Add($k) }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($k in $keys) {
        $va = $null; $vb = $null
        [void]$a.TryGetValue($k, [ref]$va)
        [void]$b.TryGetValue($k, [ref]$vb)
        if ($va -ne $vb) { $out.Add($k) }
    }
    return , $out
}

function Is-Empty($map) {
    return ($map.Count -eq 0) -or ($map.Count -eq 1 -and $map.ContainsKey('<missing>'))
}

# The snapshot code checks itself on a temporary folder: equal stays equal, one byte changed,
# one file added and one attribute set are each seen. The folder is removed again.
function Test-Snapshot {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("rerun-roundtrip-selftest-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        New-Item -ItemType Directory -Path (Join-Path $tmp 'sub') | Out-Null
        $f = Join-Path $tmp 'sub\a.bin'
        [IO.File]::WriteAllBytes($f, [byte[]](1, 2, 3, 4))
        $s0 = Get-TreeSnapshot $tmp
        if ((Diff-Map $s0 (Get-TreeSnapshot $tmp)).Count -ne 0) { Fail 'self-check: two snapshots of an unchanged folder differ' }
        [IO.File]::WriteAllBytes($f, [byte[]](1, 2, 3, 5))
        $d = Diff-Map $s0 (Get-TreeSnapshot $tmp)
        if ($d.Count -ne 1 -or $d[0] -ne 'sub\a.bin') { Fail 'self-check: one changed byte is not seen' }
        [IO.File]::WriteAllBytes($f, [byte[]](1, 2, 3, 4))
        [IO.File]::WriteAllBytes((Join-Path $tmp 'b.txt'), [byte[]]@())
        if ((Diff-Map $s0 (Get-TreeSnapshot $tmp)).Count -ne 1) { Fail 'self-check: an added file is not seen' }
        Remove-Item -LiteralPath (Join-Path $tmp 'b.txt') -Force
        (Get-Item -LiteralPath $f).Attributes = 'ReadOnly'
        if ((Diff-Map $s0 (Get-TreeSnapshot $tmp)).Count -ne 1) { Fail 'self-check: a read-only attribute is not seen' }
        (Get-Item -LiteralPath $f).Attributes = 'Normal'
        if ((Diff-Map $s0 (Get-TreeSnapshot $tmp)).Count -ne 0) { Fail 'self-check: the restored folder differs' }
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }
    if (Test-Path -LiteralPath $tmp) { Fail "self-check: $tmp was not removed" }
    Write-Host 'self-check: the snapshot sees one changed byte, an added file and an attribute'
}

# ---------- shared checks ----------
function Read-Stage {
    if (-not (Test-Path -LiteralPath $script:StageFile -PathType Leaf)) { Fail "no $script:StageFile: run -Prepare first" }
    return (Get-Content -LiteralPath $script:StageFile -Raw | ConvertFrom-Json)
}

# The staged binaries are the ones -Prepare built (SHA-256 against stage.json).
function Assert-Stage($stage, [bool]$helper) {
    foreach ($p in @($script:StageParent, $script:Stage, $script:StagedHelperDir)) { Assert-Plain $p }
    foreach ($x in @(@($script:StagedRerun, $stage.Rerun), @($script:StagedLaunch, $stage.Launch))) {
        if (-not (Test-Path -LiteralPath $x[0] -PathType Leaf)) { Fail "not staged: $($x[0]) (run -Prepare)" }
        Assert-Plain $x[0]
        if ((Sha256-File $x[0]) -ne $x[1]) { Fail "$($x[0]) is not the build of -Prepare (SHA-256 differs): run -Prepare again" }
    }
    if ($helper) {
        if (-not $stage.Helper) { Fail 'stage.json names no helper: -Prepare built none (no case with Helper = $true)' }
        if (-not (Test-Path -LiteralPath $script:StagedHelper -PathType Leaf)) { Fail "not staged: $script:StagedHelper (run -Prepare)" }
        Assert-Plain $script:StagedHelper
        if ((Sha256-File $script:StagedHelper) -ne $stage.Helper) { Fail "$script:StagedHelper is not the build of -Prepare: run -Prepare again" }
    }
    Write-Host 'self-check: the staged binaries are the ones -Prepare built'
}

# `rerun status`: the number of transactions not closed and the orphaned-rule lines.
function Get-RerunStatus {
    $r = Invoke-Rerun @('status')
    if ($r.Code -ne $ExitReport) { Show-Output $r; Fail "rerun status exited with $($r.Code)" }
    $open = 0
    if (-not (Find-Line $r.Out $script:ReNoTransactions)) {
        $m = Find-Line $r.Out $script:ReStatusCounts
        if (-not $m) { Show-Output $r; Fail 'rerun status: neither "no transactions" nor the counts line' }
        $open = [int]$m.Groups['open'].Value
    }
    $orphans = Find-Line ($r.Out + "`n" + $r.Err) $script:ReOrphans
    return @{ Open = $open; Orphans = [bool]$orphans; Text = $r.Out }
}

# A plan this script can judge: no registry op (the snapshots do not cover the registry yet, so
# a revert there could not be proven; registry_set, compat_layer and gpu_preference are refused
# until they are), and exactly one Steam root, which is the case's app and game folder.
function Assert-PlanFits($c, [string]$preview) {
    if (Find-Line $preview $script:ReRegistryOp) {
        Fail "$($c.Name): the plan changes the registry (registry_set, compat_layer or gpu_preference); this script's snapshots do not cover the registry yet, so it cannot prove the revert: refused"
    }
    $lines = @(Lines $preview)
    $games = @()
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $s = [regex]::Match($lines[$i], $script:ReSteamRoot)
        $r = [regex]::Match($lines[$i - 1], $script:ReRoot)
        if ($s.Success -and $r.Success) { $games += , @($s.Groups['app'].Value, $r.Groups['path'].Value) }
    }
    $folder = $c.GameFolder.TrimEnd('\')
    if ($games.Count -ne 1 -or $games[0][0] -ne "$($c.AppId)" -or -not [string]::Equals($games[0][1], $folder, [StringComparison]::OrdinalIgnoreCase)) {
        Fail "$($c.Name): the plan's Steam root is not app $($c.AppId) at $folder (roots: $(@($games | ForEach-Object { "app $($_[0]) at $($_[1])" }) -join '; '))"
    }
}

function Get-ExePath($c, [string]$preview) {
    $rel = $c.Exe
    if (-not $rel) {
        $m = Find-Line $preview $script:ReMainExe
        if (-not $m) { Fail "$($c.Name): the plan names no main executable; set Exe in the case" }
        $rel = $m.Groups['exe'].Value
    }
    return (Join-Path $c.GameFolder $rel)
}

function Get-Running([string]$exePath, [datetime]$after) {
    return @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
            try { $_.Path -and [string]::Equals($_.Path, $exePath, [StringComparison]::OrdinalIgnoreCase) -and $_.StartTime -gt $after } catch { $false }
        })
}

function Pop-Count([UInt64]$mask) {
    $n = 0
    while ($mask -ne 0) { $n += [int]($mask -band 1); $mask = $mask -shr 1 }
    return $n
}

function Read-Result([string]$path) {
    $map = @{}
    foreach ($line in ([IO.File]::ReadAllText($path) -split "`n")) {
        $i = $line.IndexOf('=')
        if ($i -gt 0) { $map[$line.Substring(0, $i)] = $line.Substring($i + 1) }
    }
    return $map
}

Add-Type -Namespace RerunDevTopo -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);
'@

function Write-Changes([string[]]$lines) {
    Write-Host ''
    Write-Host 'What this run changes, and removes again:' -ForegroundColor Yellow
    foreach ($l in $lines) { Write-Host "  - $l" }
    Write-Host ''
}

function Save-Summary([string[]]$summary, [string]$name) {
    $dir = Join-Path $script:Local 'results'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $file = Join-Path $dir ("{0}-{1}.txt" -f $name, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    [IO.File]::WriteAllText($file, (($summary -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
    Set-Clipboard -Value ($summary -join "`r`n")
    Write-Host ''
    $summary | ForEach-Object { Write-Host $_ }
    Write-Host ''
    Write-Host "Summary in the clipboard and in $file"
}

# ======================================================================
# -Prepare
# ======================================================================
function Invoke-Prepare {
    Title 'PREPARE: checking the inputs'
    Assert-NotElevated
    $cases = Read-Cases $(if ($Case) { $Case } else { $CaseFile })
    $needHelper = @($cases | Where-Object { $_.Helper }).Count -gt 0
    Write-Changes @(
        ('builds into target\ (rerun-cli and rerun-workbench with the feature test-key, rerun-launch release' + $(if ($needHelper) { ', the test-key helper' } else { '' }) + ')'),
        "copies the binaries to $script:Stage (removed by -Cleanup)",
        "writes $script:DevIndex and imports it into $script:AppDir\index-test (removed by -Cleanup; the real index is never touched)",
        "stores one plan per case in $script:AppDir\plans (Rerun's state; stays)",
        "writes $script:StageFile and the plan table under $script:Local; no game folder, no firewall rule, no profile"
    )
    $dirty = & git -C $repo status --porcelain -- crates Cargo.toml Cargo.lock
    if ($dirty) { Fail 'crates/, Cargo.toml or Cargo.lock have uncommitted changes: commit them first (the helper and the CLI must be one BUILD_ID)' }
    $commit = (& git -C $repo rev-parse HEAD).Trim()

    Title 'PREPARE: building (a few minutes)'
    Invoke-Cargo @('build', '-p', 'rerun-cli', '--features', 'test-key', '--locked')
    Invoke-Cargo @('build', '-p', 'rerun-launch', '--release', '--locked')
    Invoke-Cargo @('build', '-p', 'rerun-workbench', '--features', 'test-key', '--locked')
    $builtRerun = Join-Path $repo 'target\debug\rerun.exe'
    $builtLaunch = Join-Path $repo 'target\release\rerun-launch.exe'
    $workbench = Join-Path $repo 'target\debug\rerun-workbench.exe'
    foreach ($x in @(@('rerun.exe', $builtRerun), @('rerun-launch.exe', $builtLaunch), @('rerun-workbench.exe', $workbench))) { Assert-Built $x[0] $x[1] }
    $helperBuild = $null
    if ($needHelper) { $helperBuild = Build-Helper $repo -TestKey }

    Title 'PREPARE: staging the binaries'
    foreach ($p in @($script:StageParent, $script:Stage, $script:StagedHelperDir)) { Assert-Plain $p }
    New-Item -ItemType Directory -Force -Path $script:Stage | Out-Null
    foreach ($x in @(@($builtRerun, $script:StagedRerun), @($builtLaunch, $script:StagedLaunch))) {
        Assert-Plain $x[1]
        Copy-Item -LiteralPath $x[0] -Destination $x[1] -Force
    }
    $stage = [ordered]@{
        Commit  = $commit
        Built   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        Stage   = $script:Stage
        Rerun   = Sha256-File $script:StagedRerun
        Launch  = Sha256-File $script:StagedLaunch
        Helper  = $null
        # Case name -> the SHA-256 of the plan -Prepare stored for it (-Case refuses another).
        Plans   = [ordered]@{}
    }
    if ((Sha256-File $builtRerun) -ne $stage.Rerun -or (Sha256-File $builtLaunch) -ne $stage.Launch) { Fail 'a staged copy differs from its build' }
    if ($helperBuild) {
        New-Item -ItemType Directory -Force -Path $script:StagedHelperDir | Out-Null
        Assert-Plain $script:StagedHelper
        Copy-Item -LiteralPath $helperBuild.Path -Destination $script:StagedHelper -Force
        $stage.Helper = Sha256-File $script:StagedHelper
        if ($stage.Helper -ne $helperBuild.Hash.ToLowerInvariant()) { Fail 'the staged helper differs from its build' }
    } elseif (Test-Path -LiteralPath $script:StagedHelperDir) {
        Remove-Item -LiteralPath $script:StagedHelper -Force -ErrorAction SilentlyContinue
        [IO.Directory]::Delete($script:StagedHelperDir, $false)
    }
    New-Item -ItemType Directory -Force -Path $script:Local | Out-Null
    [IO.File]::WriteAllText($script:StageFile, ($stage | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))

    # Self-check: the staged rerun.exe is a test-key build (Invoke-Rerun checks the banner).
    $null = Get-RerunStatus
    Write-Host 'self-check: the staged rerun.exe writes the TEST-KEY banner first'

    Title 'PREPARE: the test index (build, sign with the test key, import into index-test)'
    New-Item -ItemType Directory -Force -Path $script:DevIndex | Out-Null
    $index = Join-Path $script:DevIndex 'index.json'
    $seq = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $issued = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $r = Invoke-Exe $workbench @('index', 'build', '--seq', "$seq", '--issued', $issued, '--root', $repo, $index)
    Show-Output $r
    if ($r.Code -ne 0) { Fail "rerun-workbench index build failed ($($r.Code))" }
    # sign-test never writes over a signature: the one of an earlier -Prepare goes first.
    $sig = "$index.sig"
    Assert-Plain $sig
    if (Test-Path -LiteralPath $sig) { Remove-Item -LiteralPath $sig -Force }
    $r = Invoke-Exe $workbench @('index', 'sign-test', $index)
    Show-Output $r
    if ($r.Code -ne 0) { Fail "rerun-workbench index sign-test failed ($($r.Code))" }
    $r = Invoke-Rerun @('index', 'import', $index, "$index.sig")
    Show-Output $r
    if ($r.Code -ne $ExitReport -or -not (Find-Line $r.Out $script:ReImported)) { Fail "rerun index import failed ($($r.Code))" }

    Title 'PREPARE: one plan per case'
    $table = New-Object System.Collections.Generic.List[string]
    $table.Add("P4-13 session S$Session plans ($issued, commit $commit, index seq $seq)")
    $table.Add('')
    $details = New-Object System.Collections.Generic.List[string]
    foreach ($c in $cases) {
        $m = Read-Manifest $c
        if ($m.StateFlags -ne '4') { Fail "$($c.Name): Steam reports StateFlags $($m.StateFlags), not 4 (fully installed): let Steam finish first" }
        $planArgs = @('plan', "$($c.AppId)")
        foreach ($p in @($c.Picks)) { $planArgs += @('--pick', $p) }
        $r = Invoke-Rerun $planArgs
        Show-Output $r
        if ($r.Code -ne $ExitReport) { Fail "$($c.Name): rerun plan exited with $($r.Code)" }
        $hm = Find-Line $r.Out $script:ReApplyWith
        if (-not $hm) { Fail "$($c.Name): no 'apply with' line: nothing was stored" }
        $hash = $hm.Groups['hash'].Value
        $file = Join-Path $script:AppDir "plans\$hash.json"
        if ((Sha256-File $file) -ne $hash) { Fail "$($c.Name): SHA-256 of $file is not $hash" }
        Assert-PlanFits $c $r.Out
        $stage.Plans[$c.Name] = $hash
        $fw = [bool](Find-Line $r.Out $script:ReFirewallRule)
        if ($fw -ne $c.Helper) { Fail "$($c.Name): the plan $(if ($fw) { 'adds' } else { 'adds no' }) firewall rules, the case says Helper = $($c.Helper)" }
        $om = Find-Line $r.Out $script:ReOption
        if ($om -and $om.Groups['install'].Value -ne $script:Stage) { Fail "$($c.Name): the launch option points to $($om.Groups['install'].Value), not $script:Stage" }
        $table.Add(("{0,-24} app {1,-8} game {2,-5} helper {3,-5} {4}  {5}" -f $c.Name, $c.AppId, $c.Game, $c.Helper, ($c.Picks -join ' + '), $hash))
        $details.Add('')
        $details.Add("---- $($c.Name): $(Split-Path $c.GameFolder -Leaf) (buildid $($m.BuildId)) ----")
        foreach ($l in (Lines $r.Out)) { $details.Add($l) }
    }
    [IO.File]::WriteAllText($script:StageFile, ($stage | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
    $table.Add('')
    $table.Add('Release each case in the chat with "apply" and its hash; a case runs with:')
    $table.Add('  scripts\dev-topo-roundtrip.ps1 -Case <name> -PlanSha256 <hash>')
    $all = @($table) + @($details)
    $file = Join-Path $script:Local "S$Session-plans.txt"
    [IO.File]::WriteAllText($file, (($all -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
    Set-Clipboard -Value ($all -join "`r`n")
    Write-Host ''
    $table | ForEach-Object { Write-Host $_ }
    Write-Host ''
    Write-Host "Table and previews in the clipboard and in $file"
    Title 'DONE: paste the table to Claude'
}

# ======================================================================
# -Case X -PlanSha256 H
# ======================================================================
function Invoke-Case {
    $rows = New-Object System.Collections.Generic.List[string]
    $notes = New-Object System.Collections.Generic.List[string]
    $st = @{ Txn = $null; Reverted = $false; Option = $null; OptionRemoved = $false; HelperUsed = $false; Stopped = $null; Verdict = $null; Launch = $null }
    $c = $null
    $paths = Get-HelperPaths
    function Row([string]$mark, [string]$name, [string]$detail) { $rows.Add(("{0,-5} {1,-22} {2}" -f $mark, $name, $detail)) }
    try {
        # ---------- B.1 self-checks (nothing changed yet) ----------
        Title 'CHECKING: the inputs (nothing is changed yet)'
        Assert-NotElevated
        $c = @(Read-Cases $CaseFile | Where-Object { $_.Name -eq $Case })
        if ($c.Count -ne 1) { Fail "no case $Case in the case file" }
        $c = $c[0]
        $stage = Read-Stage
        Assert-Stage $stage $c.Helper
        $stored = if ($stage.Plans) { $stage.Plans.$Case } else { $null }
        if ($stored -ne $PlanSha256) { Fail "plan $PlanSha256 is not the one -Prepare stored for case $Case ($(if ($stored) { $stored } else { 'none' })): nothing changed" }
        $planFile =Join-Path $script:AppDir "plans\$PlanSha256.json"
        foreach ($p in @($script:AppDir, (Join-Path $script:AppDir 'plans'), $planFile)) { Assert-Plain $p }
        if (-not (Test-Path -LiteralPath $planFile -PathType Leaf)) { Fail "plan $PlanSha256 is not stored: run -Prepare" }
        if ((Sha256-File $planFile) -ne $PlanSha256) { Fail "the SHA-256 of $planFile is not ${PlanSha256}: nothing changed" }
        Write-Host 'self-check: the stored plan hashes to the released SHA-256'
        $status = Get-RerunStatus
        if ($status.Open -ne 0) { Fail "rerun status: $($status.Open) transaction(s) not closed; finish them first" }
        if ($status.Orphans) { Fail 'rerun status lists Rerun firewall rules no transaction owns; look at them first' }
        $manifest0 = Read-Manifest $c
        if ($manifest0.StateFlags -ne '4') { Fail "Steam reports StateFlags $($manifest0.StateFlags), not 4: let Steam finish first" }
        Test-Snapshot

        # The plan's preview, with every check of the apply (a firewall plan before its helper is
        # installed may be refused here; its real check is the apply).
        $dry = Invoke-Rerun @('apply', $PlanSha256, '--dry-run')
        $preview = $dry.Out
        if ($dry.Code -ne $ExitReport -and -not ($c.Helper -and $dry.Code -eq $ExitRefused)) { Show-Output $dry; Fail "rerun apply --dry-run exited with $($dry.Code)" }
        Assert-PlanFits $c $preview
        if ([bool](Find-Line $preview $script:ReFirewallRule) -ne $c.Helper) { Fail "the plan and the case disagree about firewall rules (Helper = $($c.Helper))" }
        $exePath = Get-ExePath $c $preview
        if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) { Fail "the game's executable is not there: $exePath" }
        if ((Get-Running $exePath ([datetime]::MinValue)).Count -gt 0) { Fail "$exePath is running: quit the game first" }
        $pm = Find-Line $preview $script:ReProfile
        $method = if ($pm) { $pm.Groups['method'].Value } else { $null }
        $userData = $null
        if ($c.UserData) { $userData = Join-Path ([Environment]::GetFolderPath('MyDocuments')) $c.UserData }

        $changes = @(
            "the plan's operations below (rerun apply $PlanSha256), undone by rerun revert",
            ("snapshots (read only) of $($c.GameFolder)" + $(if ($userData) { ", $userData" } else { '' }) + ", Rerun's firewall rules, $script:AppDir\profiles and \elevate")
        )
        if ($c.Helper) { $changes += 'installs the test-key helper to Program Files\Rerun before the apply and removes it at the end (4 prompts)' }
        if ($c.Game -eq 'steam') { $changes += 'puts the launch option into the clipboard; you paste it in Steam and remove it again' }
        Write-Changes $changes
        foreach ($l in (Lines $preview)) { if ($l -match '^(op [0-9]+:|  firewall rule:|  program:|root [0-9]+:|     launch profile )') { Write-Host "  $l" } }

        # ---------- B.3 S0 ----------
        Title 'SNAPSHOT S0 (before the apply; large games take a minute)'
        $s0 = Get-Snapshot $c $userData
        if (-not (Is-Empty $s0.Elevate)) { Fail "$script:AppDir\elevate is not empty before the run" }

        # ---------- B.4/5 helper, apply ----------
        if ($c.Helper) {
            $st.HelperUsed = $true
            Install-Helper $paths @{ Path = $script:StagedHelper; Hash = $stage.Helper.ToUpperInvariant() } 'PROMPT 1 of 4'
        }
        if ($c.Helper) { Title 'PROMPT 2 of 4: allow rerun-helper.exe (YES) - applying' } else { Title 'APPLYING the plan' }
        $applyTime = Get-Date
        $a = Invoke-Rerun @('apply', $PlanSha256, '--yes')
        Show-Output $a
        $tm = Find-Line $a.Out $script:ReRevertWith
        if ($tm) { $st.Txn = $tm.Groups['txn'].Value }
        if ($a.Code -eq $ExitRolledBack) { $st.Verdict = 'FAIL'; Fail 'the apply failed and was rolled back (exit 4)' }
        if ($a.Code -ne $ExitReport -or -not $st.Txn) { $st.Verdict = 'FAIL'; Fail "the apply exited with $($a.Code)$(if (-not $st.Txn) { ' without a transaction' })" }
        Row 'info' 'transaction' $st.Txn
        # Every FAIL row of the round trip makes the verdict FAIL (the launch check stays apart).
        $fail = $false

        # ---------- B.6 S1 ----------
        Title 'SNAPSHOT S1 (after the apply)'
        $s1 = Get-Snapshot $c $userData
        $d01 = @{}
        foreach ($k in @('Game', 'UserData', 'Firewall', 'Profiles')) { if ($s0.ContainsKey($k)) { $d01[$k] = Diff-Map $s0[$k] $s1[$k] } }
        $total = 0
        foreach ($k in $d01.Keys) { $total += $d01[$k].Count }
        if ($total -eq 0) { $fail = $true }
        Row $(if ($total -gt 0) { 'PASS' } else { 'FAIL' }) 'apply changed' ("game {0}, user data {1}, firewall {2}, profiles {3}" -f $d01.Game.Count, $(if ($d01.UserData) { $d01.UserData.Count } else { 0 }), $d01.Firewall.Count, $d01.Profiles.Count)
        $om = Find-Line $a.Out $script:ReOption
        if ($om) {
            $st.Option = $om.Groups['option'].Value
            $okInstall = $om.Groups['install'].Value -eq $script:Stage
            if (-not $okInstall) { $fail = $true }
            Row $(if ($okInstall) { 'PASS' } else { 'FAIL' }) 'launch option' "install folder $($om.Groups['install'].Value)"
            $profileName = "$($om.Groups['id'].Value).profile"
            $okProfile = $s1.Profiles.ContainsKey($profileName)
            if (-not $okProfile) { $fail = $true }
            Row $(if ($okProfile) { 'PASS' } else { 'FAIL' }) 'profile written' $profileName
        }
        if ($c.Helper) {
            $mine = @($s1.Firewall.Keys | Where-Object { $_ -match ('^Rerun - [a-z0-9-]+ - ' + [regex]::Escape($st.Txn) + '-[0-9]{3}\|') })
            $programOk = $true
            foreach ($k in $mine) { if (-not ($s1.Firewall[$k].Split('|')[3]).StartsWith($c.GameFolder, [StringComparison]::OrdinalIgnoreCase)) { $programOk = $false } }
            $okRules = $mine.Count -gt 0 -and $programOk
            if (-not $okRules) { $fail = $true }
            Row $(if ($okRules) { 'PASS' } else { 'FAIL' }) 'firewall rules' "$($mine.Count) of transaction $($st.Txn), programs in the game folder: $programOk"
        }

        # ---------- B.7/8 the game ----------
        $s1b = $s1
        $upcOk = $true
        if ($c.Game -eq 'steam' -and $c.Upc) {
            Title 'START Ubisoft Connect and sign in (waiting for it, at most 10 minutes)'
            $upcDeadline = (Get-Date).AddMinutes(10)
            while (-not (Get-Process -Name 'upc', 'UbisoftConnect' -ErrorAction SilentlyContinue)) {
                if ((Get-Date) -gt $upcDeadline) { $upcOk = $false; break }
                Start-Sleep -Seconds 2
            }
            if (-not $upcOk) {
                $fail = $true
                # The launch option was never handed out: nothing to remove in Steam.
                $st.OptionRemoved = $true
                Row 'FAIL' 'ubisoft connect' 'did not start within 10 minutes: the game was not started, the plan is reverted'
                Title 'FAILED: Ubisoft Connect did not start within 10 minutes - reverting'
            }
        }
        if ($c.Game -eq 'steam' -and $upcOk) {
            $resultFile = $null
            $resultBefore = [datetime]::MinValue
            if ($st.Option) {
                Set-Clipboard -Value $st.Option
                Write-Host ''
                Write-Host "Launch option (in the clipboard): $($st.Option)" -ForegroundColor Yellow
                $resultFile = Join-Path $script:AppDir "launch\$($om.Groups['id'].Value).result"
                if (Test-Path -LiteralPath $resultFile) { $resultBefore = (Get-Item -LiteralPath $resultFile).LastWriteTimeUtc }
                Title "PASTE the launch option in Steam (Ctrl+V), then START $(Split-Path $c.GameFolder -Leaf) via Steam: $($c.Check)"
            } else {
                Title "START $(Split-Path $c.GameFolder -Leaf) via Steam: $($c.Check)"
            }
            # The process that still runs after the settle time is measured (a stub that hands
            # over to a launcher ends sooner; watch finds the second process, R3).
            $settle = if ($c.Upc -or $method -eq 'watch') { 20 } else { 8 }
            $deadline = (Get-Date).AddMinutes($WaitMinutes)
            $game = $null
            while (-not $game -and (Get-Date) -lt $deadline) {
                Start-Sleep -Seconds 1
                foreach ($p in (Get-Running $exePath $applyTime)) {
                    if (((Get-Date) - $p.StartTime).TotalSeconds -ge $settle) { $p.Refresh(); if (-not $p.HasExited) { $game = $p; break } }
                }
            }
            if (-not $game) {
                Row 'FAIL' 'game' "did not run for $settle s within $WaitMinutes minutes"
            } else {
                Row 'PASS' 'game' "running after $settle s (pid $($game.Id))"
                $launchOk = $true
                try {
                    $mask = [BitConverter]::ToUInt64([BitConverter]::GetBytes($game.ProcessorAffinity.ToInt64()), 0)
                    $count = Pop-Count $mask
                    $detail = ('0x{0:X} = {1} logical processors' -f $mask, $count)
                    if ($c.Expect.ContainsKey('Threads')) {
                        $ok = $count -eq $c.Expect.Threads
                        if (-not $ok) { $launchOk = $false }
                        Row $(if ($ok) { 'PASS' } else { 'FAIL' }) 'affinity' "$detail (expected $($c.Expect.Threads))"
                    } elseif ($c.Expect.ContainsKey('ExcludeFirst')) {
                        $cleared = if ($c.Expect.ExcludeFirst -eq 'core') { 3 } else { 1 }
                        $ok = ($mask -band [UInt64]1) -eq 0 -and ($cleared -eq 1 -or ($mask -band [UInt64]2) -eq 0)
                        if (-not $ok) { $launchOk = $false }
                        Row $(if ($ok) { 'PASS' } else { 'FAIL' }) 'affinity' "$detail (expected without CPU 0$(if ($cleared -eq 3) { ' and 1' }))"
                    } else {
                        Row 'info' 'affinity' $detail
                    }
                } catch { $launchOk = $false; Row 'FAIL' 'affinity' "cannot read: $($_.Exception.Message)" }
                try {
                    $inJob = $false
                    [void][RerunDevTopo.Native]::IsProcessInJob($game.Handle, [IntPtr]::Zero, [ref]$inJob)
                    Row 'info' 'in a job' "$inJob"
                } catch { Row 'info' 'in a job' "cannot read: $($_.Exception.Message)" }
                if ($resultFile) {
                    if ((Test-Path -LiteralPath $resultFile) -and (Get-Item -LiteralPath $resultFile).LastWriteTimeUtc -gt $resultBefore) {
                        $res = Read-Result $resultFile
                        $ok = $res['rule'] -eq 'applied' -and @('ok', 'narrowed') -contains $res['check']
                        if (-not $ok) { $launchOk = $false }
                        Row $(if ($ok) { 'PASS' } else { 'FAIL' }) 'launch result' "rule=$($res['rule']) check=$($res['check']) method=$($res['method']) cpu=$($res['cpu'])"
                    } else {
                        $launchOk = $false
                        Row 'FAIL' 'launch result' 'no result of this start (was the launch option pasted?)'
                    }
                }
                $st.Launch = $launchOk
                Title "GAME RUNNING - $($c.Check), then quit the game"
                while ((Get-Running $exePath $applyTime).Count -gt 0) { Start-Sleep -Seconds 2 }
                Title 'the game ended: waiting 10 s for its launcher'
                Start-Sleep -Seconds 10
            }
            if ($st.Option) {
                Title 'REMOVE the launch option in Steam, then press Enter'
                [void](Read-Host 'Press Enter once the launch option is removed in Steam')
                $st.OptionRemoved = $true
            }
            Title 'SNAPSHOT S1b (after the game)'
            $s1b = Get-Snapshot $c $userData
        }

        # ---------- B.9 revert ----------
        if ($c.Helper) { Title 'PROMPT 3 of 4: allow rerun-helper.exe (YES) - reverting' } else { Title 'REVERTING' }
        $v = Invoke-Rerun @('revert', $st.Txn, '--yes')
        Show-Output $v
        $vm = Find-Line $v.Out $script:ReReverted
        if ($v.Code -ne $ExitReport -or -not $vm -or $vm.Groups['txn'].Value -ne $st.Txn) { $st.Verdict = 'FAIL'; Fail "the revert exited with $($v.Code) without closing $($st.Txn)" }
        $st.Reverted = $true

        # ---------- B.10 S2 and the verdict ----------
        Title 'SNAPSHOT S2 (after the revert)'
        $s2 = Get-Snapshot $c $userData
        foreach ($k in @('Game', 'UserData')) {
            if (-not $s0.ContainsKey($k)) { continue }
            $label = if ($k -eq 'Game') { '<game>' } else { '<userdata>' }
            $byRerun = $d01[$k]
            $byGame = Diff-Map $s1[$k] $s1b[$k]
            $left = Diff-Map $s0[$k] $s2[$k]
            $bad = @(); $gameOnly = @()
            foreach ($p in $left) {
                if ($c.Game -eq 'none' -or $byRerun.Contains($p) -or -not $byGame.Contains($p)) { $bad += $p } else { $gameOnly += $p }
            }
            $both = @($byRerun | Where-Object { $byGame.Contains($_) })
            if ($bad.Count -gt 0 -or $both.Count -gt 0) { $fail = $true }
            Row $(if ($bad.Count -eq 0 -and $both.Count -eq 0) { 'PASS' } else { 'FAIL' }) "$label identical" ("{0} paths changed by Rerun and back; {1} not back; {2} written by the game" -f $byRerun.Count, $bad.Count, $gameOnly.Count)
            foreach ($p in $bad) { $notes.Add("not as before: $label\$p") }
            foreach ($p in $both) { $notes.Add("the game wrote a path Rerun changed: $label\$p") }
            foreach ($p in $gameOnly) { $notes.Add("written by the game, not by Rerun: $label\$p") }
        }
        foreach ($k in @('Firewall', 'Profiles')) {
            $d = Diff-Map $s0[$k] $s2[$k]
            if ($d.Count -gt 0) { $fail = $true }
            Row $(if ($d.Count -eq 0) { 'PASS' } else { 'FAIL' }) "$($k.ToLowerInvariant()) as before" "$($d.Count) differ"
            foreach ($p in $d) { $notes.Add("$($k.ToLowerInvariant()) not as before: $p") }
        }
        $elevateEmpty = Is-Empty $s2.Elevate
        if (-not $elevateEmpty) { $fail = $true }
        Row $(if ($elevateEmpty) { 'PASS' } else { 'FAIL' }) 'elevate empty' "$script:AppDir\elevate"
        $status = Get-RerunStatus
        $statusOk = $status.Open -eq 0 -and -not $status.Orphans
        if (-not $statusOk) { $fail = $true }
        Row $(if ($statusOk) { 'PASS' } else { 'FAIL' }) 'rerun status' "$($status.Open) not closed, orphaned rules: $($status.Orphans)"
        $manifest2 = Read-Manifest $c
        $steamSame = $manifest2.BuildId -eq $manifest0.BuildId -and $manifest2.StateFlags -eq $manifest0.StateFlags
        Row $(if ($steamSame) { 'PASS' } else { 'FAIL' }) 'steam unchanged' "buildid $($manifest0.BuildId) -> $($manifest2.BuildId), StateFlags $($manifest0.StateFlags) -> $($manifest2.StateFlags)"
        $st.Verdict = if (-not $steamSame) { 'INVALID' } elseif ($fail) { 'FAIL' } else { 'PASS' }
    } catch {
        $st.Stopped = $_.Exception.Message
        if (-not $st.Verdict) { $st.Verdict = if ($st.Txn) { 'FAIL' } else { 'STOPPED' } }
    } finally {
        if ($st.HelperUsed) {
            $removal = Remove-Helper $paths 'PROMPT 4 of 4'
            Row $(if ($removal.StartsWith('PASS')) { 'PASS' } else { 'FAIL' }) 'helper removed' $removal
            if (-not $removal.StartsWith('PASS') -and $st.Verdict -eq 'PASS') { $st.Verdict = 'FAIL' }
        }
        if ($st.Txn -and -not $st.Reverted) {
            $st.Verdict = 'FAIL'
            $notes.Add("transaction $($st.Txn) is still open: scripts\dev-topo-roundtrip.ps1 -RevertOnly $($st.Txn)$(if ($c -and $c.Helper) { ' -WithHelper' })")
        }
        if ($st.Option -and $c -and $c.Game -eq 'steam' -and -not $st.OptionRemoved) { $notes.Add("remove the launch option in Steam: $($st.Option)") }
        if ($st.Stopped) { $notes.Add("stopped: $($st.Stopped)") }
        $name = if ($c) { $c.Name } else { "$Case" }
        $launch = if ($null -eq $st.Launch) { 'not measured' } elseif ($st.Launch) { 'shown' } else { 'not shown' }
        $summary = @(
            "P4-13 topo round trip [DEV] $($st.Verdict)  $(Get-Date -Format 'yyyy-MM-dd HH:mm')",
            "case $name, plan $PlanSha256$(if ($c) { ", picks $($c.Picks -join ' + '), game $($c.Game)" })",
            "launch check: $launch"
        ) + @($rows) + @($notes | ForEach-Object { "note  $_" })
        $summary = @($summary | ForEach-Object {
                $t = $_
                if ($c) { $t = $t.Replace($c.GameFolder, '<game>') }
                $t.Replace($script:AppDir, '<AppDir>')
            })
        Save-Summary $summary $name
        Title "DONE: $($st.Verdict) (summary in the clipboard)"
    }
}

# ======================================================================
# -RevertOnly <txn>
# ======================================================================
function Invoke-RevertOnly {
    $paths = Get-HelperPaths
    $lines = New-Object System.Collections.Generic.List[string]
    $verdict = 'FAIL'
    $used = $false
    try {
        Title "CHECKING: before reverting $RevertOnly"
        Assert-NotElevated
        $stage = Read-Stage
        Assert-Stage $stage ([bool]$WithHelper)
        $changes = @("rerun revert $RevertOnly (what it undoes is shown below)")
        if ($WithHelper) { $changes += 'installs the test-key helper to Program Files\Rerun and removes it again (3 prompts)' }
        Write-Changes $changes
        $dry = Invoke-Rerun @('revert', $RevertOnly, '--dry-run')
        Show-Output $dry
        if ($WithHelper) {
            $used = $true
            Install-Helper $paths @{ Path = $script:StagedHelper; Hash = $stage.Helper.ToUpperInvariant() } 'PROMPT 1 of 3'
            Title 'PROMPT 2 of 3: allow rerun-helper.exe (YES) - reverting'
        } else {
            Title "REVERTING $RevertOnly"
        }
        $v = Invoke-Rerun @('revert', $RevertOnly, '--yes')
        Show-Output $v
        $vm = Find-Line $v.Out $script:ReReverted
        $ok = $v.Code -eq $ExitReport -and $vm -and $vm.Groups['txn'].Value -eq $RevertOnly
        $lines.Add("$(if ($ok) { 'PASS' } else { 'FAIL' })  revert exit $($v.Code)")
        $status = Get-RerunStatus
        $sok = $status.Open -eq 0 -and -not $status.Orphans
        $lines.Add("$(if ($sok) { 'PASS' } else { 'FAIL' })  rerun status: $($status.Open) not closed, orphaned rules: $($status.Orphans)")
        if ($ok -and $sok) { $verdict = 'PASS' }
    } catch {
        $lines.Add("stopped: $($_.Exception.Message)")
    } finally {
        if ($used) {
            $removal = Remove-Helper $paths 'PROMPT 3 of 3'
            $lines.Add($removal)
            if (-not $removal.StartsWith('PASS')) { $verdict = 'FAIL' }
        }
        Save-Summary (@("P4-13 revert only [DEV] $verdict  $RevertOnly  $(Get-Date -Format 'yyyy-MM-dd HH:mm')") + @($lines)) "revert-$RevertOnly"
        Title "DONE: $verdict (summary in the clipboard)"
    }
}

# ======================================================================
# -Cleanup
# ======================================================================
# Deletes the named files of $dir (never through a link) and then the folder if it is empty;
# anything else in it stops.
function Remove-Exactly([string]$dir, [string]$pattern) {
    if (-not (Test-Path -LiteralPath $dir)) { return }
    Assert-Plain $dir
    foreach ($i in @(Get-ChildItem -LiteralPath $dir -Force)) {
        if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "refusing: $($i.FullName) is a reparse point" }
        if ($i.PSIsContainer -or $i.Name -notmatch $pattern) { Fail "refusing: $($i.FullName) is not this test's; nothing removed there" }
    }
    foreach ($i in @(Get-ChildItem -LiteralPath $dir -Force)) { Remove-Item -LiteralPath $i.FullName -Force }
    [IO.Directory]::Delete($dir, $false)
    if (Test-Path -LiteralPath $dir) { Fail "$dir is still there" }
}

function Invoke-Cleanup {
    $verdict = 'FAIL'
    $lines = New-Object System.Collections.Generic.List[string]
    try {
        Title 'CLEANUP: checking'
        Assert-NotElevated
        $indexTest = Join-Path $script:AppDir 'index-test'
        Write-Changes @(
            "deletes $script:Stage (rerun.exe, rerun-launch.exe, helper\rerun-helper.exe)",
            "deletes $indexTest (the test-key index state)",
            "keeps $script:AppDir\journal and \plans (Rerun's state) and $script:Local"
        )
        # Fail closed: every check before the first deletion. Without the staged test-key rerun.exe
        # nothing can tell whether a transaction still needs index-test, so nothing is deleted.
        if (-not (Test-Path -LiteralPath $script:StagedRerun -PathType Leaf)) { Fail "no staged rerun.exe ($script:StagedRerun): rerun status cannot be asked, nothing deleted (run -Prepare first, or clean up by hand)" }
        Assert-Stage (Read-Stage) $false
        $status = Get-RerunStatus
        if ($status.Open -ne 0) { Fail "$($status.Open) transaction(s) not closed: revert them first (-RevertOnly <txn>); nothing deleted" }
        if ($status.Orphans) { Fail 'rerun status lists Rerun firewall rules no transaction owns: look at them first; nothing deleted' }
        $profiles = Join-Path $script:AppDir 'profiles'
        if ((Test-Path -LiteralPath $profiles) -and @(Get-ChildItem -LiteralPath $profiles -Force -Filter '*.profile').Count -gt 0) { Fail "a launch profile exists in ${profiles}: revert its transaction first; nothing deleted" }
        # The staged helper is what -RevertOnly -WithHelper installs and removes: keep it while a
        # helper is installed.
        $helper = Get-HelperPaths
        if (Test-Path -LiteralPath $helper.Dir) { Fail "$($helper.Dir) exists: run -RevertOnly <txn> -WithHelper (it removes the helper) or delete it in an administrator PowerShell; nothing deleted" }
        Remove-Exactly $script:StagedHelperDir '^rerun-helper\.exe$'
        Remove-Exactly $script:Stage '^rerun(-launch)?\.exe$'
        if ((Test-Path -LiteralPath $script:StageParent) -and @(Get-ChildItem -LiteralPath $script:StageParent -Force).Count -eq 0) { [IO.Directory]::Delete($script:StageParent, $false) }
        Remove-Exactly $indexTest '^([0-9a-f]{64}\.(json|sig)|current\.json|lock)$'
        $lines.Add("PASS  $script:Stage and $indexTest are gone")
        $verdict = 'PASS'
        $lines.Add('Remove every launch option with RerunTest\p4-13\rerun-launch.exe in Steam: the game would not start through it any more.')
    } catch {
        $lines.Add("stopped: $($_.Exception.Message)")
    } finally {
        Save-Summary (@("P4-13 cleanup [DEV] $verdict  $(Get-Date -Format 'yyyy-MM-dd HH:mm')") + @($lines)) 'cleanup'
        Title "DONE: $verdict (summary in the clipboard)"
    }
}

# ---------- dispatch ----------
$modes = @($Prepare.IsPresent, [bool]$PlanSha256, [bool]$RevertOnly, $Cleanup.IsPresent) | Where-Object { $_ }
if (@($modes).Count -ne 1) { Fail 'name exactly one of -Prepare, -Case <name> -PlanSha256 <hash>, -RevertOnly <txn>, -Cleanup' }
if ($PlanSha256 -and -not $Case) { Fail '-PlanSha256 needs -Case <name>' }
if ($WithHelper -and -not $RevertOnly) { Fail '-WithHelper goes with -RevertOnly' }
if ($Prepare) { Invoke-Prepare }
elseif ($PlanSha256) { Invoke-Case }
elseif ($RevertOnly) { Invoke-RevertOnly }
else { Invoke-Cleanup }
