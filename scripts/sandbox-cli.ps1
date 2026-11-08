# Runs inside Windows Sandbox only, called by sandbox-run.ps1 (P2-13, user decision E7 a): the
# CLI round trip with the release rerun.exe on the Sandbox account's real LocalAppData and
# HKCU: plan, apply --dry-run, apply --yes, status, revert --yes, status --all, on a game
# folder C:\RerunSandbox\cli\game with a copy of cmd.exe as its main executable, a local
# package, two registry values, an INI key and the compatibility-layer tokens of the add
# allowlist for game.exe (P2-11b). Before and after are compared (files with length, SHA-256
# and attributes; the registry key; the Layers value of game.exe). Never on the host: it
# refuses anywhere but the Sandbox account, and it writes the real HKCU and LocalAppData of
# whoever runs it.
#
# Returns an ordered hashtable for result.json (key "cli"): every command with its exit code,
# whether the folder and the registry are as before, and whether the result is as expected.
# Elevated, rerun refuses plan and everything after it (user decision E3, exit 3): that
# refusal is the expected result then, and nothing must have changed.

param(
    [Parameter(Mandatory = $true)][string]$Out,
    [Parameter(Mandatory = $true)][bool]$Elevated
)

$ErrorActionPreference = 'Stop'
# The account of the process token too (not spoofable through the environment), and the
# script's own path in the read-only mapped folder of the .wsb.
$tokenUser = ([Security.Principal.WindowsIdentity]::GetCurrent().Name -split '\\')[-1]
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or $env:USERPROFILE -notmatch '\\WDAGUtilityAccount\\?$' -or
    $tokenUser -ne 'WDAGUtilityAccount' -or $PSCommandPath -ne 'C:\sandbox\scripts\sandbox-cli.ps1') {
    throw "refusing to run: not the Windows Sandbox account and its mapped scripts (USERNAME=$env:USERNAME, token $tokenUser, script $PSCommandPath)"
}

$source = 'C:\sandbox\bin\rerun.exe'
$root = 'C:\RerunSandbox\cli'
# rerun.exe runs from a local copy: the mapped folder C:\sandbox\bin gives no usable directory
# handle, so Rerun cannot resolve its install folder there and refuses (seen in the first run).
$rerun = Join-Path $root 'bin\rerun.exe'
$game = Join-Path $root 'game'
$steps = Join-Path $root 'steps.json'
$pkg = Join-Path $env:LOCALAPPDATA 'Rerun\packages\cli-pack\1.0.0'
$regKey = 'HKCU:\Software\RerunSandboxCli'
# The compatibility-layer value of game.exe: its name is the canonical path (no junction here).
$layersKey = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers'
$layerName = Join-Path $game 'game.exe'
$layerTokens = 'DISABLEDXMAXIMIZEDWINDOWEDMODE', 'HIGHDPIAWARE'
$log = Join-Path $Out 'cli.log'
$utf8 = New-Object Text.UTF8Encoding $false

function Write-Plain([string]$path, [string]$text) {
    [IO.File]::WriteAllText($path, $text, $utf8)
}

# Files of the game folder (relative path, length, SHA-256, attributes), the registry key and
# the Layers value of game.exe (type and data; absent when the value or the key is).
function Get-State {
    $files = Get-ChildItem -LiteralPath $game -Recurse -Force | Sort-Object FullName | ForEach-Object {
        $rel = $_.FullName.Substring($game.Length)
        if ($_.PSIsContainer) { "dir $rel $($_.Attributes)" }
        else { "file $rel $($_.Length) $((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash) $($_.Attributes)" }
    }
    $reg = if (Test-Path -LiteralPath $regKey) {
        Get-ChildItem -LiteralPath $regKey -Recurse | ForEach-Object { $_.Name; ($_ | Get-ItemProperty | Out-String).Trim() }
    } else { 'registry key absent' }
    $layer = 'layer value absent'
    if (Test-Path -LiteralPath $layersKey) {
        $k = Get-Item -LiteralPath $layersKey
        $v = $k.GetValue($layerName, $null, 'DoNotExpandEnvironmentNames')
        if ($null -ne $v) { $layer = "layer $($k.GetValueKind($layerName)) [$v]" }
    }
    (@($files) + @($reg) + @($layer)) -join "`n"
}

# One rerun command: its output into cli.log, its exit code back.
function Invoke-Rerun {
    $ErrorActionPreference = 'Continue'
    Add-Content -LiteralPath $log -Value "`n> rerun $($args -join ' ')"
    $text = & $rerun @args 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
    Add-Content -LiteralPath $log -Value $text
    Add-Content -LiteralPath $log -Value "exit $code"
    [pscustomobject]@{ Code = $code; Text = ($text -join "`n") }
}

if (-not (Test-Path -LiteralPath $source)) { throw "rerun.exe missing: $source (run scripts/sandbox-launch.ps1 on the host)" }
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $rerun) | Out-Null
Copy-Item -LiteralPath $source -Destination $rerun -Force
# The launch shim next to it: Rerun's install folder is the folder of rerun.exe, and the launch
# option names rerun-launch.exe there (P3-3e).
if (Test-Path -LiteralPath 'C:\sandbox\bin\rerun-launch.exe') {
    Copy-Item -LiteralPath 'C:\sandbox\bin\rerun-launch.exe' -Destination (Join-Path (Split-Path -Parent $rerun) 'rerun-launch.exe') -Force
}
Set-Content -LiteralPath $log -Value "CLI round trip, elevated=$Elevated" -Encoding UTF8

# The fixture: a game with a copy of cmd.exe as its main executable (the Sandbox of build
# 26100 has no System32\notepad.exe), an old d3d9.dll and an INI file; the package with a new
# d3d9.dll and a new file.
New-Item -ItemType Directory -Force -Path $game, $pkg | Out-Null
Copy-Item -LiteralPath "$env:WINDIR\System32\cmd.exe" -Destination (Join-Path $game 'game.exe') -Force
Write-Plain (Join-Path $game 'd3d9.dll') 'old d3d9 of the game'
Write-Plain (Join-Path $game 'game.ini') "[Display]`r`nWidth=1280`r`nHeight=720`r`n"
Write-Plain (Join-Path $pkg 'd3d9.dll') 'new d3d9 of the package'
Write-Plain (Join-Path $pkg 'new.dll') 'new.dll of the package'
$sha = { param($f) (Get-FileHash -LiteralPath (Join-Path $pkg $f) -Algorithm SHA256).Hash.ToLowerInvariant() }
# Written by hand, not with ConvertTo-Json (Windows PowerShell 5.1 unrolls one-element arrays
# in some positions); the only escapes needed are the backslashes of the paths.
$folder = $game.Replace('\', '\\')
$json = @"
{"format":1,"game":{"folder":"$folder"},"main_exe":"game.exe","steps":[
{"file_install":{"package":"cli-pack","version":"1.0.0","files":[
{"from":"d3d9.dll","to":"d3d9.dll","sha256":"$(& $sha 'd3d9.dll')"},
{"from":"new.dll","to":"mods\\new.dll","sha256":"$(& $sha 'new.dll')"}]}},
{"registry_set":{"key":"HKCU\\Software\\RerunSandboxCli\\Game","values":[{"name":"Width","dword":1920},{"name":"Lang","sz":"en"}]}},
{"ini_set":{"file":"game.ini","values":[{"section":"Display","key":"Width","value":"1920"}]}},
{"compat_layer":{"exe":"game.exe","layers":["$($layerTokens -join '","')"]}}]}
"@
Write-Plain $steps $json
$before = Get-State

$runs = [ordered]@{}
$expected = $false
$p = Invoke-Rerun plan $steps
$runs.plan = $p.Code
if ($Elevated) {
    # E3: an elevated rerun stores no plan and changes nothing.
    $expected = ($p.Code -eq 3) -and ($p.Text -match 'runs as administrator')
} elseif ($p.Code -eq 0 -and $p.Text -match 'apply with: rerun apply ([0-9a-f]{64})') {
    $hash = $Matches[1]
    $runs.apply_dry_run = (Invoke-Rerun apply $hash --dry-run).Code
    # Nothing written, not even the journal folder or its lock (security review N3).
    $dryUnchanged = ((Get-State) -eq $before) -and
        (-not (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'Rerun\journal')))
    $a = Invoke-Rerun apply $hash --yes
    $runs.apply = $a.Code
    if ($a.Code -eq 0 -and $a.Text -match 'revert with: rerun revert ([0-9]{8}-[0-9a-f]{16})') {
        $txn = $Matches[1]
        $applied = Get-State
        # The tokens appended to a missing value: the prefix of the tab and the tokens in byte
        # order (P2-11b).
        $layerApplied = $applied.Contains("layer String [~ $($layerTokens -join ' ')]")
        $runs.status = (Invoke-Rerun status).Code
        $r = Invoke-Rerun revert $txn --yes
        $runs.revert = $r.Code
        $runs.status_all = (Invoke-Rerun status --all).Code
        $closed = $r.Text -match "transaction $txn reverted and closed"
        $expected = $dryUnchanged -and ($applied -ne $before) -and $closed -and $layerApplied -and
            (@($runs.Values) | Where-Object { $_ -ne 0 }).Count -eq 0
    }
}
$after = Get-State
$same = ($after -eq $before)
if (-not $same) {
    Add-Content -LiteralPath $log -Value "`nBEFORE:`n$before`nAFTER:`n$after"
}

# ---- launch_method (P3-3e) -------------------------------------------------------------------
# A mimicked Steam layout (HKCU SteamPath, libraryfolders.vdf, appmanifest_220.acf, a game folder
# with a copy of cmd.exe as start and main executable): plan --dry-run (nothing written), plan,
# apply (the profile exists, its bytes are the preview's), one start through rerun-launch.exe
# (result file, the mask of the child), revert (the profile is gone, the game folder and the
# profile files as before). Steam itself is not involved: the script passes the command the way
# Steam would after the launch option. Elevated, plan refuses (the section above) and this is
# skipped. The Steam registry value is put back at the end, also after a failure.
$launchExe = Join-Path (Split-Path -Parent $rerun) 'rerun-launch.exe'
$lmRoot = Join-Path $root 'steam'
$lmGame = Join-Path $lmRoot 'steamapps\common\G'
$lmExe = Join-Path $lmGame 'game.exe'
$lmSteps = Join-Path $root 'steps-lm.json'
$rerunDir = Join-Path $env:LOCALAPPDATA 'Rerun'
$profiles = Join-Path $rerunDir 'profiles'
$steamKey = 'HKCU:\Software\Valve\Steam'
# The ID of app 220 (plan::profile_id, pinned in the core and in the CLI tests).
$lmId = '323ad79fbc93ca3e73b0b152a5d44616'

# Files of a folder (relative path, length, SHA-256, attributes); `absent` when it is.
function Get-Tree([string]$dir) {
    if (-not (Test-Path -LiteralPath $dir)) { return 'absent' }
    $items = Get-ChildItem -LiteralPath $dir -Recurse -Force | Sort-Object FullName | ForEach-Object {
        $rel = $_.FullName.Substring($dir.Length)
        if ($_.PSIsContainer) { "dir $rel $($_.Attributes)" }
        else { "file $rel $($_.Length) $((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash) $($_.Attributes)" }
    }
    (@('present') + @($items)) -join "`n"
}
# The profile files only (the folder itself is created by the apply and stays, plan P3-3).
function Get-Profiles {
    if (-not (Test-Path -LiteralPath $profiles)) { return 'none' }
    (@(Get-ChildItem -LiteralPath $profiles -Force | Sort-Object Name | ForEach-Object {
        "$($_.Name) $($_.Length) $((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash) $($_.Attributes)"
    }) -join "`n")
}
function Get-Bits([int64]$mask) { $n = 0; while ($mask -ne 0) { $n += [int]($mask -band 1); $mask = $mask -shr 1 }; $n }

function Invoke-LaunchMethod {
    $lm = [ordered]@{ checks = [ordered]@{}; expected = $false; error = '' }
    $c = $lm.checks
    $hadKey = Test-Path -LiteralPath $steamKey
    $hadValue = $hadKey -and ($null -ne (Get-Item -LiteralPath $steamKey).GetValue('SteamPath', $null))
    $oldValue = if ($hadValue) { (Get-Item -LiteralPath $steamKey).GetValue('SteamPath', $null, 'DoNotExpandEnvironmentNames') }
    try {
        if (-not (Test-Path -LiteralPath $launchExe)) { throw "rerun-launch.exe missing: $launchExe (run scripts/sandbox-launch.ps1 on the host)" }
        New-Item -ItemType Directory -Force -Path $lmGame | Out-Null
        Copy-Item -LiteralPath "$env:WINDIR\System32\cmd.exe" -Destination $lmExe -Force
        $vdf = "`"libraryfolders`"`n{`n`t`"0`"`n`t{`n`t`t`"path`"`t`t`"$($lmRoot.Replace('\', '\\'))`"`n`t}`n}`n"
        Write-Plain (Join-Path $lmRoot 'steamapps\libraryfolders.vdf') $vdf
        $acf = "`"AppState`"`n{`n`t`"appid`"`t`t`"220`"`n`t`"name`"`t`t`"G`"`n`t`"StateFlags`"`t`t`"4`"`n`t`"installdir`"`t`t`"G`"`n}`n"
        Write-Plain (Join-Path $lmRoot 'steamapps\appmanifest_220.acf') $acf
        New-Item -Force -Path $steamKey | Out-Null
        Set-ItemProperty -LiteralPath $steamKey -Name SteamPath -Value $lmRoot -Type String
        Write-Plain $lmSteps '{"format":1,"game":{"steam":220},"main_exe":"game.exe","steps":[{"launch_method":{"method":"direct","start":"game.exe","cpu":{"max_threads":2}}}]}'
        Add-Content -LiteralPath $log -Value "`n=== launch_method (P3-3e) ==="

        $gameBefore = Get-Tree $lmRoot
        $profilesBefore = Get-Profiles
        $rerunBefore = Get-Tree $rerunDir
        $file = Join-Path $profiles "$lmId.profile"
        $c.no_profile_before = -not (Test-Path -LiteralPath $file)

        # plan --dry-run: the preview, nothing written (not under Rerun, not in the game folder).
        $d = Invoke-Rerun plan $lmSteps --dry-run
        $c.dry_run_exit = $d.Code
        $c.dry_run_writes_nothing = ((Get-Tree $rerunDir) -eq $rerunBefore) -and ((Get-Tree $lmRoot) -eq $gameBefore)
        $m = [regex]::Match($d.Text, '(?m)^\s+"(?<dir>[^"]+)\\rerun-launch\.exe" --profile (?<id>[0-9a-f]{32}) %command%\s*$')
        $c.preview_launch_option = $m.Success -and $m.Groups['id'].Value -eq $lmId -and
            $m.Groups['dir'].Value -eq (Split-Path -Parent $rerun)
        $c.preview_profile = $d.Text.Contains("launch profile ${lmId}: method direct, x64") -and
            $d.Text.Contains("start $lmExe") -and $d.Text.Contains('cpu max_threads 2')
        $c.preview_op = $d.Text.Contains("create file in root 1: $lmId.profile")
        $nm = [regex]::Match($d.Text, 'new: sha256 (?<sha>[0-9a-f]{64}), (?<len>\d+) bytes')
        $c.preview_bytes_found = $nm.Success
        $c.no_shim_warning = -not $d.Text.Contains('rerun-launch.exe is not in Rerun')

        $p = Invoke-Rerun plan $lmSteps
        $c.plan_exit = $p.Code
        $hm = [regex]::Match($p.Text, 'apply with: rerun apply ([0-9a-f]{64})')
        if ($p.Code -ne 0 -or -not $hm.Success) { throw 'plan did not store a plan (see cli.log)' }
        $h = $hm.Groups[1].Value
        $dh = [regex]::Match($d.Text, '(?m)^plan ([0-9a-f]{64})')
        $c.dry_run_hash_equals_plan_hash = $dh.Success -and $dh.Groups[1].Value -eq $h

        $a = Invoke-Rerun apply $h --yes
        $c.apply_exit = $a.Code
        $c.apply_says_paste = $a.Text.Contains('now paste the launch option shown in the preview into Steam')
        $c.profile_exists = Test-Path -LiteralPath $file -PathType Leaf
        $c.profile_bytes_are_the_previews = $false
        if ($c.profile_exists -and $nm.Success) {
            $c.profile_bytes_are_the_previews = ((Get-Item -LiteralPath $file).Length -eq [int]$nm.Groups['len'].Value) -and
                ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -eq $nm.Groups['sha'].Value)
        }
        $tm = [regex]::Match($a.Text, 'revert with: rerun revert ([0-9]{8}-[0-9a-f]{16})')
        if ($a.Code -ne 0 -or -not $tm.Success) { throw 'apply did not report a transaction (see cli.log)' }
        $txn = $tm.Groups[1].Value
        $v = Invoke-Rerun status
        $c.status_exit = $v.Code
        $c.game_folder_untouched_by_apply = (Get-Tree $lmRoot) -eq $gameBefore

        # One start the way Steam starts it after the launch option: the shim, then Steam's
        # command (argv[0] = the profile's start). cmd.exe holds the child for about 11 s so that
        # the check after about 5 s finds it running.
        $result = Join-Path $rerunDir "launch\$lmId.result"
        Remove-Item -LiteralPath $result -Force -ErrorAction SilentlyContinue
        $argLine = "--profile $lmId `"$lmExe`" /d /q /c ping -n 12 127.0.0.1 >nul"
        $shim = Start-Process -FilePath $launchExe -ArgumentList $argLine -PassThru
        $maskBits = -1
        $deadline = (Get-Date).AddSeconds(4)
        do {
            Start-Sleep -Milliseconds 250
            $child = Get-Process -Name game -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $lmExe } | Select-Object -First 1
        } while (-not $child -and (Get-Date) -lt $deadline)
        if ($child) { try { $maskBits = Get-Bits ([int64]$child.ProcessorAffinity) } catch { $maskBits = -2 } }
        $deadline = (Get-Date).AddSeconds(25)
        while (-not (Test-Path -LiteralPath $result) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
        $rtext = if (Test-Path -LiteralPath $result) { Get-Content -LiteralPath $result -Raw } else { '' }
        Add-Content -LiteralPath $log -Value "result file:`n$rtext`nchild mask bits: $maskBits"
        $c.result_file = $rtext -ne ''
        $c.result_profile = $rtext -match "(?m)^profile=$lmId\r?$"
        $c.result_rule_applied = $rtext -match '(?m)^rule=applied\r?$'
        $c.result_check_ok = $rtext -match '(?m)^check=ok\r?$'
        $cm = [regex]::Match($rtext, '(?m)^cpu=hard:(\d+):(\d+)\r?$')
        # The child in the job has the mask: as many bits as the result file says (one group).
        $c.child_has_the_mask = $cm.Success -and ($maskBits -eq [int]$cm.Groups[1].Value)
        $lm.child_mask_bits = $maskBits
        $lm.result = $rtext
        # Stop what is left of the start; the shim ends with its child.
        Get-Process -Name game, ping -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'ping' -or $_.Path -eq $lmExe } | Stop-Process -Force -ErrorAction SilentlyContinue
        if (-not $shim.WaitForExit(15000)) { Stop-Process -Id $shim.Id -Force -ErrorAction SilentlyContinue }

        $r = Invoke-Rerun revert $txn --yes
        $c.revert_exit = $r.Code
        $c.revert_closed = $r.Text -match "transaction $txn reverted and closed"
        $c.revert_names_the_option = $r.Text.Contains("rerun-launch.exe`" --profile $lmId %command%") -and
            $r.Text.Contains("(and any launch option with --profile $lmId)")
        $c.profile_removed = -not (Test-Path -LiteralPath $file)
        $c.profiles_folder_stays = Test-Path -LiteralPath $profiles -PathType Container
        $c.game_folder_as_before = (Get-Tree $lmRoot) -eq $gameBefore
        $c.profile_files_as_before = (Get-Profiles) -eq $profilesBefore
        $s = Invoke-Rerun status --all
        $c.status_all_exit = $s.Code

        $bad = @($c.GetEnumerator() | Where-Object {
            if ($_.Key -like '*_exit') { $_.Value -ne 0 } else { $_.Value -ne $true }
        } | ForEach-Object { $_.Key })
        $lm.failed = $bad
        $lm.expected = ($bad.Count -eq 0)
    } catch {
        $lm.error = "$_"
        Add-Content -LiteralPath $log -Value "launch_method failed: $_"
    } finally {
        # Put the Steam registry value back (the Sandbox is disposable, but the Rust tests are
        # not to see a stale key).
        try {
            if (-not $hadKey) { Remove-Item -LiteralPath $steamKey -Recurse -Force -ErrorAction SilentlyContinue }
            elseif ($hadValue) { Set-ItemProperty -LiteralPath $steamKey -Name SteamPath -Value $oldValue -Type String }
            else { Remove-ItemProperty -LiteralPath $steamKey -Name SteamPath -ErrorAction SilentlyContinue }
        } catch { }
    }
    $lm
}

$lm = $null
if (-not $Elevated) { $lm = Invoke-LaunchMethod }
[ordered]@{
    runs          = $runs
    unchanged     = $same
    expected      = ($expected -and $same -and ($Elevated -or $lm.expected))
    elevated      = $Elevated
    launch_method = if ($lm) { $lm } else { 'skipped: elevated' }
    note          = if ($Elevated) { 'elevated: the refusal (exit 3) of plan is the expected result' } else { '' }
}
