# [DEV] measurement of rerun-launch with a Steam game on the developer machine
# (docs/09-testing.md, "Launch shim on the developer machine"; ADR 0022).
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\dev-launch-profile.ps1 -Exe "D:\SteamLibrary\steamapps\common\Game\game.exe"
#
# Optional: -Threads 8 (default), -Smt, -Mode hard|soft, -Priority none|normal|above_normal|high,
# -Launcher <path of rerun-launch.exe> (default: builds the release shim and copies it to
# %LOCALAPPDATA%\RerunTest\rerun-launch.exe, a fixed place for the launch option), -WaitMinutes 15,
# -Cold (D2, cold start right after a reboot: no build, no copy and no decode run through the
# shim before the game, so the game's start is the shim's first run since boot; uses the copy
# already in %LOCALAPPDATA%\RerunTest unless -Launcher names one).
#
# What it does, without a single question (the current instruction is in the window title):
#  1. checks itself: its profile writer against its copy of the codec golden (a Rust test binds
#     that copy to rerun-proto's golden);
#  2. writes the launch profile <LocalAppData>\Rerun\profiles\<id>.profile (format 1, UTF-8
#     without BOM, LF; creates Rerun and profiles if missing) and lets rerun-launch decode it (a
#     start of cmd.exe through the shim must record "path_mismatch", never "profile_invalid");
#  3. puts the Steam launch option into the clipboard; you paste it in Steam and start the game;
#  4. waits for the game (or for a result file of this start), checks affinity, job and
#     priority class about 8 s after its start and reads <LocalAppData>\Rerun\launch\<id>.result;
#  5. prints a summary (also copied to the clipboard) and deletes the profile. The result file
#     stays. It never changes Steam's settings: once the launch option is in the clipboard it
#     always ends with "remove the launch option in Steam", also when it stops early.
#
# Run it in a normal (not administrator) PowerShell: an elevated shim ignores the profile (M1).

param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [ValidateRange(1, 4096)][int]$Threads = 8,
    [switch]$Smt,
    [ValidateSet('hard', 'soft')][string]$Mode = 'hard',
    [ValidateSet('none', 'normal', 'above_normal', 'high')][string]$Priority = 'none',
    [string]$Launcher,
    [ValidateRange(1, 120)][int]$WaitMinutes = 15,
    [switch]$Cold
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$started = Get-Date
$profilePath = $null
$option = $null
$done = $null

function Title([string]$text) {
    $Host.UI.RawUI.WindowTitle = "Rerun DEV - $text"
    Write-Host ''
    Write-Host ">> $text" -ForegroundColor Cyan
}

function Fail([string]$text) {
    Title "STOPPED: $text"
    throw $text
}

function Assert-Plain([string]$path) {
    if ((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Fail "refusing: $path is a reparse point (junction or link)"
    }
}

# The launch profile exactly as rerun_proto::profile::encode writes it (format 1).
function Profile-Text([string]$exePath, [string]$bitness, [string]$priority, [int]$threads, [bool]$smt, [string]$mode) {
    $lines = @(
        'rerun-profile 1',
        'method=direct',
        "start=$exePath",
        "target=$exePath",
        "bitness=$bitness",
        "priority=$priority",
        'watch_timeout_s=120',
        'cpu=rule',
        'cpu.prefer=performance',
        'cpu.single_l3=true',
        'cpu.prefer_l3=none',
        ('cpu.smt=' + $(if ($smt) { 'true' } else { 'false' })),
        "cpu.mode=$mode",
        "cpu.max_threads=$threads"
    )
    return ($lines -join "`n") + "`n"
}

function Utf8-Bytes([string]$text) {
    return (New-Object System.Text.UTF8Encoding($false)).GetBytes($text)
}

function Same-Bytes([byte[]]$a, [byte[]]$b) {
    if ($a.Length -ne $b.Length) { return $false }
    for ($i = 0; $i -lt $a.Length; $i++) { if ($a[$i] -ne $b[$i]) { return $false } }
    return $true
}

# x86 or x64 from the PE header of the exe (machine 0x14c or 0x8664; anything else stops).
function Exe-Bitness([string]$path) {
    $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite, Delete')
    try {
        $buf = New-Object byte[] 4096
        $n = $fs.Read($buf, 0, $buf.Length)
    } finally { $fs.Dispose() }
    if ($n -lt 64 -or $buf[0] -ne 0x4D -or $buf[1] -ne 0x5A) { Fail "${path} is not an executable (no MZ header)" }
    $pe = [BitConverter]::ToInt32($buf, 0x3C)
    if ($pe -lt 64 -or $pe + 6 -gt $n) { Fail "${path}: PE header outside the first 4 KiB" }
    if ($buf[$pe] -ne 0x50 -or $buf[$pe + 1] -ne 0x45 -or $buf[$pe + 2] -ne 0 -or $buf[$pe + 3] -ne 0) { Fail "${path}: no PE signature" }
    $machine = [BitConverter]::ToUInt16($buf, $pe + 4)
    switch ($machine) {
        0x014C { return 'x86' }
        0x8664 { return 'x64' }
        default { Fail ("{0}: machine 0x{1:X4} is neither x86 nor x64" -f $path, $machine) }
    }
}

# The result file's last write time; MinValue while it does not exist (-Cold: no decode run).
function Result-Time([string]$path) {
    if (Test-Path -LiteralPath $path -PathType Leaf) { (Get-Item -LiteralPath $path).LastWriteTimeUtc } else { [DateTime]::MinValue }
}

function Read-Result([string]$path) {
    $map = @{}
    $text = [IO.File]::ReadAllText($path, (New-Object System.Text.UTF8Encoding($false)))
    foreach ($line in ($text -split "`n")) {
        $i = $line.IndexOf('=')
        if ($i -gt 0) { $map[$line.Substring(0, $i)] = $line.Substring($i + 1) }
    }
    return $map
}

function Pop-Count([UInt64]$mask) {
    $c = 0
    while ($mask -ne 0) { $c += [int]($mask -band 1); $mask = $mask -shr 1 }
    return $c
}

Add-Type -Namespace RerunDev -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);
'@

try {
    # ---------- 0: preconditions and the self-check of this script ----------
    Title 'checking the script and the inputs'
    $golden = "rerun-profile 1`nmethod=direct`nstart=C:\Program Files (x86)\Steam\steamapps\common\Far Cry 2\bin\FarCry2.exe`ntarget=C:\Program Files (x86)\Steam\steamapps\common\Far Cry 2\bin\FarCry2.exe`nbitness=x86`npriority=none`nwatch_timeout_s=120`ncpu=rule`ncpu.prefer=performance`ncpu.single_l3=true`ncpu.prefer_l3=none`ncpu.smt=false`ncpu.mode=hard`ncpu.max_threads=8`n"
    $mine = Profile-Text 'C:\Program Files (x86)\Steam\steamapps\common\Far Cry 2\bin\FarCry2.exe' 'x86' 'none' 8 $false 'hard'
    if (-not (Same-Bytes (Utf8-Bytes $mine) (Utf8-Bytes $golden))) { Fail 'self-check: the profile writer differs from the golden bytes of rerun-proto (crates/rerun-proto/src/profile/tests.rs)' }
    Write-Host 'self-check: profile writer equals the codec golden'

    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($admin) { Fail 'run this in a normal PowerShell, not as administrator (an elevated shim ignores the profile, M1)' }

    if ($Exe -notmatch '^[A-Za-z]:\\') { Fail "-Exe must be an absolute drive path (X:\...): $Exe" }
    if (-not $Exe.EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase)) { Fail "-Exe must be an .exe: $Exe" }
    if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) { Fail "game exe not found: $Exe" }
    $bitness = Exe-Bitness $Exe
    $exeName = [IO.Path]::GetFileNameWithoutExtension($Exe)

    if ($Cold -and -not $Launcher) {
        # -Cold: building or copying would put the shim into the file cache before the game starts.
        $Launcher = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'RerunTest\rerun-launch.exe'
    }
    if (-not $Launcher) {
        Title 'building the release shim (cargo build -p rerun-launch --release)'
        Push-Location $repo
        try {
            $ErrorActionPreference = 'Continue'
            & cargo build -p rerun-launch --release 2>$null | Out-Null
            $exit = $LASTEXITCODE
            $ErrorActionPreference = 'Stop'
        } finally { Pop-Location }
        if ($exit -ne 0) { Fail 'cargo build -p rerun-launch --release failed (run it by hand to see why)' }
        $built = Join-Path $repo 'target\release\rerun-launch.exe'
        # A fixed place, so the launch option stays valid across rebuilds and checkouts; under
        # LocalAppData because a standard user may not create folders in the root of C:.
        $fixed = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'RerunTest'
        Assert-Plain $fixed
        New-Item -ItemType Directory -Force -Path $fixed | Out-Null
        $Launcher = Join-Path $fixed 'rerun-launch.exe'
        Assert-Plain $Launcher
        Copy-Item -LiteralPath $built -Destination $Launcher -Force
        Write-Host "release shim copied to $Launcher"
    }
    if (-not (Test-Path -LiteralPath $Launcher -PathType Leaf)) { Fail "rerun-launch.exe not found: $Launcher" }
    $Launcher = (Resolve-Path -LiteralPath $Launcher).Path

    # ---------- 1: write the profile and let the shim decode it ----------
    Title 'writing the launch profile'
    $lad = [Environment]::GetFolderPath('LocalApplicationData')
    $rerun = Join-Path $lad 'Rerun'
    $profiles = Join-Path $rerun 'profiles'
    $launchDir = Join-Path $rerun 'launch'
    foreach ($p in @($rerun, $profiles, $launchDir)) { Assert-Plain $p }
    New-Item -ItemType Directory -Force -Path $profiles | Out-Null

    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $idBytes = New-Object byte[] 16
    $rng.GetBytes($idBytes)
    $id = -join ($idBytes | ForEach-Object { $_.ToString('x2') })
    $profilePath = Join-Path $profiles "$id.profile"
    $resultPath = Join-Path $launchDir "$id.result"

    $want = Utf8-Bytes (Profile-Text $Exe $bitness $Priority $Threads ([bool]$Smt) $Mode)
    if ($want.Length -gt 8192) { Fail 'the profile would exceed 8 KiB (path too long)' }
    [IO.File]::WriteAllBytes($profilePath, $want)
    $back = [IO.File]::ReadAllBytes($profilePath)
    if (-not (Same-Bytes $back $want)) { Fail "self-check: $profilePath does not read back byte for byte" }
    if ($back.Length -ge 3 -and $back[0] -eq 0xEF -and $back[1] -eq 0xBB -and $back[2] -eq 0xBF) { Fail 'self-check: the profile has a BOM' }
    if ([Array]::IndexOf($back, [byte]13) -ge 0) { Fail 'self-check: the profile has a CR' }
    Write-Host "profile written: $profilePath ($($back.Length) bytes, $bitness)"

    if ($Cold) {
        # The decode run below would be the shim's first start since boot, not the game's.
        Write-Host '-Cold: no decode run through the shim before the game (its result file checks the profile)'
        $selfCheckTime = [DateTime]::MinValue
    } else {
    Title 'letting rerun-launch decode the profile (cmd.exe /c exit 0)'
    $cmd = Join-Path ([Environment]::GetFolderPath('System')) 'cmd.exe'
    $p = Start-Process -FilePath $Launcher -ArgumentList @('--profile', $id, "`"$cmd`"", '/c', 'exit', '0') -PassThru -Wait -WindowStyle Hidden
    if ($p.ExitCode -ne 0) { Fail "self-check: rerun-launch with cmd.exe exited with $($p.ExitCode), expected 0" }
    if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) { Fail "self-check: no result file $resultPath (is the shim elevated, or LocalAppData redirected?)" }
    $r = Read-Result $resultPath
    if ($r['rule'] -ne 'skipped:path_mismatch') { Fail "self-check: the shim recorded rule=$($r['rule']), expected skipped:path_mismatch (profile_invalid means the profile does not decode)" }
    Write-Host 'self-check: rerun-launch decodes the profile (path_mismatch for cmd.exe, as expected)'
    $selfCheckTime = (Get-Item -LiteralPath $resultPath).LastWriteTimeUtc
    }

    # ---------- 2: the launch option ----------
    $option = "`"$Launcher`" --profile $id %command%"
    Set-Clipboard -Value $option
    Write-Host ''
    Write-Host 'Launch option (in the clipboard):' -ForegroundColor Yellow
    Write-Host "  $option"
    Write-Host "Steam > the game > Properties > Launch options: paste it (Ctrl+V), close the dialog, start the game."
    Title "STEP: paste the launch option in Steam (Ctrl+V) and start $exeName"

    # ---------- 3: wait for the game, or for a result of this start ----------
    # A launcher stub may end in under a second, before this loop sees it: the shim's result
    # file of this start (newer than the self-check's) ends the wait as well.
    $deadline = $started.AddMinutes($WaitMinutes)
    $game = $null
    $newResult = $false
    while (-not $game -and -not $newResult) {
        if ((Get-Date) -gt $deadline) { Fail "the game did not start within $WaitMinutes minutes" }
        # -Cold: a launcher that ends within a second must still be seen, for its start time.
        Start-Sleep -Milliseconds $(if ($Cold) { 100 } else { 1000 })
        $game = Get-Process -ErrorAction SilentlyContinue | Where-Object {
            try { $_.Path -and [string]::Equals($_.Path, $Exe, [StringComparison]::OrdinalIgnoreCase) -and $_.StartTime -gt $started } catch { $false }
        } | Select-Object -First 1
        $newResult = (Result-Time $resultPath) -gt $selfCheckTime
    }
    if ($game) {
        $gameStart = $game.StartTime
        Title "$exeName is running: checking in a few seconds (keep it running)"
        $wait = 8 - ((Get-Date) - $gameStart).TotalSeconds
        if ($wait -gt 0) { Start-Sleep -Milliseconds ([int]($wait * 1000)) }
    }

    # ---------- 4: check ----------
    $rows = New-Object System.Collections.Generic.List[string]
    $ok = $true
    function Row([string]$name, [bool]$pass, [string]$detail) {
        $mark = if ($pass) { 'PASS' } else { 'FAIL' }
        if (-not $pass) { $script:ok = $false }
        $rows.Add(("{0,-4}  {1,-16} {2}" -f $mark, $name, $detail))
    }
    function Info([string]$name, [string]$detail) { $rows.Add(("info  {0,-16} {1}" -f $name, $detail)) }

    # The result of this start first: newer than the self-check's, written about 5 s after the
    # start. Its `cpu=<mode>:<threads>:<of>` is what the shim selected on this machine, which
    # the affinity is compared with (it may be fewer than -Threads).
    $resultDeadline = (Get-Date).AddSeconds(15)
    while (((Result-Time $resultPath) -le $selfCheckTime) -and ((Get-Date) -lt $resultDeadline)) { Start-Sleep -Milliseconds 500 }
    $selected = $null
    $checkValue = ''
    if ((Result-Time $resultPath) -le $selfCheckTime) {
        Row 'result file' $false 'not written for this start (the shim did not run with this profile?)'
    } else {
        $r = Read-Result $resultPath
        $checkValue = "$($r['check'])"
        $parts = "$($r['cpu'])" -split ':'
        if ($parts.Count -eq 3 -and $parts[0] -eq $Mode) { $selected = [int]$parts[1] }
        Row 'result rule' ($r['rule'] -eq 'applied') "rule=$($r['rule'])"
        Row 'result check' (($r['check'] -eq 'ok') -or ($r['check'] -eq 'narrowed')) "check=$($r['check'])"
        Row 'result cpu' ($null -ne $selected -and $selected -ge 1 -and $selected -le $Threads) "cpu=$($r['cpu']) (asked: $Threads)"
        Info 'result file' $resultPath
    }

    $running = $false
    if ($game) {
        $game.Refresh()
        $running = -not $game.HasExited
    }
    Row 'game running' $running $(if ($running) { 'at the check' } else { 'ended before the check (crashed, or a launcher that starts the game as another process)' })
    if ($running) {
        $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$($game.Id)"
        $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($cim.ParentProcessId)" -ErrorAction SilentlyContinue
        $viaShim = $parent -and ($parent.Name -ieq 'rerun-launch.exe')
        Row 'started by shim' $viaShim $(if ($parent) { "parent: $($parent.Name)" } else { 'parent gone' })
        if ($viaShim) {
            Info 'shim cmdline' $parent.CommandLine
            $shimStart = (Get-Process -Id $parent.ProcessId -ErrorAction SilentlyContinue).StartTime
            if ($shimStart) { Info 'start delay' ("{0:N0} ms from rerun-launch to the game (D2: < 50 ms)" -f ($gameStart - $shimStart).TotalMilliseconds) }
        }

        try {
            $mask = [BitConverter]::ToUInt64([BitConverter]::GetBytes($game.ProcessorAffinity.ToInt64()), 0)
            $count = Pop-Count $mask
            $detail = ("0x{0:X} = {1} threads" -f $mask, $count)
            if ($Mode -eq 'hard') { Row 'affinity' (($count -eq $selected) -or ($checkValue -eq 'narrowed' -and $count -ge 1 -and $count -lt $selected)) "$detail (selected: $selected)" } else { Info 'affinity' "$detail (soft mode: CPU Sets, the mask stays whole)" }
        } catch { Row 'affinity' $false "cannot read: $($_.Exception.Message)" }

        try {
            $inJob = $false
            [void][RerunDev.Native]::IsProcessInJob($game.Handle, [IntPtr]::Zero, [ref]$inJob)
            if ($Mode -eq 'hard') { Row 'in a job' $inJob "$inJob" } else { Info 'in a job' "$inJob" }
        } catch { Row 'in a job' $false "cannot read: $($_.Exception.Message)" }

        try {
            $class = "$($game.PriorityClass)"
            $expected = @{ 'normal' = 'Normal'; 'above_normal' = 'AboveNormal'; 'high' = 'High' }[$Priority]
            if ($Priority -eq 'none') { Info 'priority class' $class } else { Row 'priority class' ($class -eq $expected) "$class (expected $expected)" }
        } catch { Row 'priority class' $false "cannot read: $($_.Exception.Message)" }
    }

    # ---------- 5: summary ----------
    $verdict = if ($ok) { 'PASS' } else { 'FAIL' }
    $summary = @(
        "rerun-launch [DEV] $verdict  $(Get-Date -Format 'yyyy-MM-dd HH:mm')",
        "game: $Exe ($bitness)",
        "rule: $Threads threads, smt=$([bool]$Smt), mode=$Mode, priority=$Priority, profile $id"
    ) + $rows
    Write-Host ''
    $summary | ForEach-Object { Write-Host $_ }
    Set-Clipboard -Value ($summary -join "`r`n")
    Write-Host ''
    Write-Host 'Summary copied to the clipboard. The profile is deleted; the result file stays.'
    $done = "DONE: $verdict"
} finally {
    if ($profilePath -and (Test-Path -LiteralPath $profilePath -PathType Leaf)) {
        Remove-Item -LiteralPath $profilePath -Force
        Write-Host "profile removed: $profilePath"
    }
    # Once the launch option was handed out, always end with the reminder (also after a stop,
    # a timeout or Ctrl+C): the script never changes Steam's settings itself.
    if ($option) {
        $state = if ($done) { $done } else { 'STOPPED' }
        Write-Host ''
        Write-Host "Remove the launch option in Steam (Properties > Launch options): $option" -ForegroundColor Yellow
        $Host.UI.RawUI.WindowTitle = "Rerun DEV - $state - remove the launch option in Steam"
    }
}
