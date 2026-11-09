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
    [Parameter(Mandatory = $true)][bool]$Elevated,
    [switch]$Ci
)

$ErrorActionPreference = 'Stop'
# The shared guard (sandbox-guard.ps1): the account of the process token (not spoofable through
# the environment), the environment, the script's own path in the mapped (Sandbox) or staged
# (CI) folder, and with -Ci the CI marker.
. (Join-Path $PSScriptRoot 'sandbox-guard.ps1')  # the script's own copy: run from the repo on a host, its guard refuses
if (-not (Test-SandboxGuard -Script $PSCommandPath -Expected 'C:\sandbox\scripts\sandbox-cli.ps1' -Ci ([bool]$Ci))) {
    throw "refusing to run: not the Windows Sandbox account and its mapped scripts, nor the CI accounts with -Ci (USERNAME=$env:USERNAME, script $PSCommandPath, ci=$Ci)"
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
    # No folder and an empty folder both mean "no profile files": apply creates `profiles` and a
    # revert leaves it (Rerun-owned state, plan LM-T2); its existence is checked on its own.
    if (-not (Test-Path -LiteralPath $profiles)) { return '' }
    (@(Get-ChildItem -LiteralPath $profiles -Force | Sort-Object Name | ForEach-Object {
        "$($_.Name) $($_.Length) $((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash) $($_.Attributes)"
    }) -join "`n")
}
function Get-Bits([int64]$mask) { $n = 0; while ($mask -ne 0) { $n += [int]($mask -band 1); $mask = $mask -shr 1 }; $n }

# The Steam registry value as it was before a case (put back by Restore-SteamKey).
function Save-SteamKey {
    $hadKey = Test-Path -LiteralPath $steamKey
    $hadValue = $hadKey -and ($null -ne (Get-Item -LiteralPath $steamKey).GetValue('SteamPath', $null))
    $oldValue = if ($hadValue) { (Get-Item -LiteralPath $steamKey).GetValue('SteamPath', $null, 'DoNotExpandEnvironmentNames') }
    @{ HadKey = $hadKey; HadValue = $hadValue; OldValue = $oldValue }
}
# Puts the Steam registry value back (the Sandbox is disposable, but the Rust tests are not to
# see a stale key); never throws.
function Restore-SteamKey($saved) {
    try {
        if (-not $saved.HadKey) { Remove-Item -LiteralPath $steamKey -Recurse -Force -ErrorAction SilentlyContinue }
        elseif ($saved.HadValue) { Set-ItemProperty -LiteralPath $steamKey -Name SteamPath -Value $saved.OldValue -Type String }
        else { Remove-ItemProperty -LiteralPath $steamKey -Name SteamPath -ErrorAction SilentlyContinue }
    } catch { }
}
# The mimicked Steam layout of app 220: SteamPath, libraryfolders.vdf, appmanifest_220.acf and
# the game folder with a fresh copy of cmd.exe as game.exe.
function New-SteamLayout {
    if (-not (Test-Path -LiteralPath $launchExe)) { throw "rerun-launch.exe missing: $launchExe (run scripts/sandbox-launch.ps1 on the host)" }
    New-Item -ItemType Directory -Force -Path $lmGame | Out-Null
    Copy-Item -LiteralPath "$env:WINDIR\System32\cmd.exe" -Destination $lmExe -Force
    $vdf = "`"libraryfolders`"`n{`n`t`"0`"`n`t{`n`t`t`"path`"`t`t`"$($lmRoot.Replace('\', '\\'))`"`n`t}`n}`n"
    Write-Plain (Join-Path $lmRoot 'steamapps\libraryfolders.vdf') $vdf
    $acf = "`"AppState`"`n{`n`t`"appid`"`t`t`"220`"`n`t`"name`"`t`t`"G`"`n`t`"StateFlags`"`t`t`"4`"`n`t`"installdir`"`t`t`"G`"`n}`n"
    Write-Plain (Join-Path $lmRoot 'steamapps\appmanifest_220.acf') $acf
    New-Item -Force -Path $steamKey | Out-Null
    Set-ItemProperty -LiteralPath $steamKey -Name SteamPath -Value $lmRoot -Type String
}

# ---- SB-L7 (P4-0): a layer takes effect when the shim starts the exe with Steam's spelling ------
# A HIGHDPIAWARE layer under the canonical path of game.exe (the value name, case as written by
# the plan); the program is started (a) directly and (b) through rerun-launch.exe with an argv[0]
# that differs from it only in case (upper and lower; Steam spells the path as its library
# folder stores it). Observed the way SB-L2/SB-L3 observe layers: `__COMPAT_LAYER` in the
# environment of the started copy of cmd.exe. The verdict is a fact, not a pass:
#   applied          both shim spellings carry the layer
#   not_applied      the layer is observable (direct, canonical spelling) but a shim spelling lacks it
#   not_observable   the layer is not visible even for the direct canonical start, or the no-value
#                    control already shows one: this runner cannot show layers, nothing is claimed
#   error            the case itself failed (detail)
# ci-sandbox.ps1 fails on not_applied and error and prints a warning for not_observable.
function Invoke-SbL7 {
    $r = [ordered]@{ verdict = 'error'; layer = '~ HIGHDPIAWARE'; value_name = $lmExe; rows = [ordered]@{}; detail = '' }
    $outFile = Join-Path $root 'l7.txt'
    $spellings = [ordered]@{ canonical = $lmExe; upper = $lmExe.ToUpperInvariant(); lower = $lmExe.ToLowerInvariant() }
    $tail = "/d /q /c set __COMPAT_LAYER>$outFile"
    # One start; the row text is what the started copy saw, or why there is nothing to see.
    function Observe([bool]$viaShim, [string]$spelling) {
        Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
        if ($viaShim) { $proc = Start-Process -FilePath $launchExe -ArgumentList "--profile $lmId `"$spelling`" $tail" -PassThru }
        else { $proc = Start-Process -FilePath $spelling -ArgumentList $tail -PassThru }
        if (-not $proc.WaitForExit(20000)) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue; return 'timeout' }
        Start-Sleep -Milliseconds 300
        if (-not (Test-Path -LiteralPath $outFile)) { return "no output (exit $($proc.ExitCode))" }
        $t = [string](Get-Content -LiteralPath $outFile -Raw)
        $m = [regex]::Match($t, '__COMPAT_LAYER=(?<v>[^\r\n]*)')
        if ($m.Success) { return "set: $($m.Groups['v'].Value.Trim())" }
        'not set'
    }
    try {
        Remove-Item Env:\__COMPAT_LAYER -ErrorAction SilentlyContinue
        $r.rows.control_no_value = Observe $false $spellings.canonical
        $madeKey = -not (Test-Path -LiteralPath $layersKey)
        New-Item -Force -Path $layersKey | Out-Null
        New-ItemProperty -LiteralPath $layersKey -Name $lmExe -Value $r.layer -PropertyType String -Force | Out-Null
        foreach ($k in $spellings.Keys) { $r.rows["direct_$k"] = Observe $false $spellings[$k] }
        foreach ($k in 'upper', 'lower') { $r.rows["shim_$k"] = Observe $true $spellings[$k] }
        $has = { param($row) $row -match '^set: .*HighDpiAware' }
        if ($r.rows.control_no_value -notmatch '^not set$') {
            $r.verdict = 'not_observable'
            $r.detail = "the control without a layer value already shows: $($r.rows.control_no_value)"
        } elseif (-not (& $has $r.rows.direct_canonical)) {
            $r.verdict = 'not_observable'
            $r.detail = "a HIGHDPIAWARE value under the canonical path is not visible as __COMPAT_LAYER even for the direct canonical start: $($r.rows.direct_canonical)"
        } elseif ((& $has $r.rows.shim_upper) -and (& $has $r.rows.shim_lower)) {
            $r.verdict = 'applied'
        } else {
            $r.verdict = 'not_applied'
            $r.detail = "the layer is visible for the direct canonical start but not for every shim spelling: shim_upper = $($r.rows.shim_upper); shim_lower = $($r.rows.shim_lower)"
        }
    } catch {
        $r.detail = "$_"
    } finally {
        try {
            Remove-ItemProperty -LiteralPath $layersKey -Name $lmExe -ErrorAction SilentlyContinue
            # A Layers key this case created is removed again (an empty one is all that could be left).
            if ($madeKey -and (Test-Path -LiteralPath $layersKey) -and (Get-Item -LiteralPath $layersKey).ValueCount -eq 0 -and (Get-Item -LiteralPath $layersKey).SubKeyCount -eq 0) { Remove-Item -LiteralPath $layersKey -Force }
        } catch { }
        Get-Process -Name game, ping -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'ping' -or $_.Path -eq $lmExe } | Stop-Process -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
    }
    Add-Content -LiteralPath $log -Value ("`n=== SB-L7 (P4-0) ===`n" + (($r.rows.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join "`n") + "`nverdict: $($r.verdict) $($r.detail)")
    $r
}

function Invoke-LaunchMethod {
    $lm = [ordered]@{ checks = [ordered]@{}; expected = $false; error = '' }
    $c = $lm.checks
    $saved = Save-SteamKey
    try {
        New-SteamLayout
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
        $rtext = if (Test-Path -LiteralPath $result) { [string](Get-Content -LiteralPath $result -Raw) } else { '' }
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

        # SB-L7 while the profile exists (a measurement, never a check of `expected`).
        $lm.sb_l7 = Invoke-SbL7

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
        Restore-SteamKey $saved
    }
    $lm
}

# ---- launch_method watch (P3-4d, SB-W1 and SB-W2) --------------------------------------------
# The same Steam layout and app 220 (so the same profile ID), now with `method: watch` and the
# Ubisoft-like stub chain of plan P3-4 §7.6: Steam's entry is the game's own exe, the program the
# shim starts (game.exe, the stub) starts game.exe again and ends at once, and the second game.exe
# is the target. That the target is in the shim's own process tree here does not matter: the
# shim looks only at the image path, the creation time, the token and the PID of the program it
# started (which is never the target). `max_threads: 1` because the CI runner has 2 logical
# processors: with 2 the mask check could not tell a limited process from an unlimited one.
# SB-W2: a copy of game.exe started before the shim keeps its mask (only a new process is the
# target). Not here: `target_not_found` after the 120 s search (the fake tests in
# run::watch_tests cover it, and it would add two minutes to every CI run, plan §7.6).
#
# A7, a parent job: the CI pass runs as a scheduled task, and processes of a task are in the Task
# Scheduler's job, so the target is in a job before the shim joins it to its own (a nested job).
# Measured (run::watch::win_tests): a parent job without a CPU limit lets the nested job take
# effect (`applied`, `ok`); a parent job with another limit keeps its own, and the shim honestly
# reports `skipped:job_ineffective`. The check decides from what the runner shows: the copy of
# SB-W2, started by this script like the shim, has the processor mask of the parent job. With
# every logical processor in that mask the parent sets no narrower limit, so `job_ineffective`
# would be a regression and fails; only with a narrower mask is `job_ineffective` accepted (then
# the target must keep exactly the parent's mask, and nothing else counts as passed). Whether the
# script runs in a job at all is recorded as `in_job` (information, not a check).
$lwSteps = Join-Path $root 'steps-lw.json'

# IsProcessInJob of a process (any job); $null when it cannot be read. Information only.
function Test-InJob($proc) {
    try {
        if (-not ('RerunSandbox.JobQuery' -as [type])) {
            Add-Type -Namespace RerunSandbox -Name JobQuery -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);
'@ -ErrorAction Stop
        }
        $r = $false
        if ([RerunSandbox.JobQuery]::IsProcessInJob($proc.Handle, [IntPtr]::Zero, [ref]$r)) { return $r }
    } catch { }
    $null
}
function Get-Affinity($proc) {
    if (-not $proc) { return [int64]-1 }
    try { $proc.Refresh(); [int64]$proc.ProcessorAffinity } catch { [int64]-2 }
}

function Invoke-LaunchWatch {
    $lw = [ordered]@{ checks = [ordered]@{}; expected = $false; error = ''; outcome = '' }
    $c = $lw.checks
    $saved = Save-SteamKey
    $pre = $null
    $shim = $null
    try {
        New-SteamLayout
        Write-Plain $lwSteps '{"format":1,"game":{"steam":220},"main_exe":"game.exe","steps":[{"launch_method":{"method":"watch","start":"game.exe","cpu":{"max_threads":1}}}]}'
        Add-Content -LiteralPath $log -Value "`n=== launch_method watch (P3-4d, SB-W1, SB-W2) ==="

        $gameBefore = Get-Tree $lmRoot
        $profilesBefore = Get-Profiles
        $rerunBefore = Get-Tree $rerunDir
        $file = Join-Path $profiles "$lmId.profile"
        $c.no_profile_before = -not (Test-Path -LiteralPath $file)

        # plan --dry-run: the watch preview (start and target are the same game.exe, the stub
        # hint), nothing written.
        $d = Invoke-Rerun plan $lwSteps --dry-run
        $c.dry_run_exit = $d.Code
        $c.dry_run_writes_nothing = ((Get-Tree $rerunDir) -eq $rerunBefore) -and ((Get-Tree $lmRoot) -eq $gameBefore)
        $m = [regex]::Match($d.Text, '(?m)^\s+"(?<dir>[^"]+)\\rerun-launch\.exe" --profile (?<id>[0-9a-f]{32}) %command%\s*$')
        $c.preview_launch_option = $m.Success -and $m.Groups['id'].Value -eq $lmId -and
            $m.Groups['dir'].Value -eq (Split-Path -Parent $rerun)
        $c.preview_profile = $d.Text.Contains("launch profile ${lmId}: method watch, x64") -and
            $d.Text.Contains("start $lmExe`n     target $lmExe`n") -and $d.Text.Contains('cpu max_threads 1')
        $c.preview_stub_hint = $d.Text.Contains("hint: Steam starts the game's own program: watch looks for a second process of it")
        $c.preview_op = $d.Text.Contains("create file in root 1: $lmId.profile")
        $nm = [regex]::Match($d.Text, 'new: sha256 (?<sha>[0-9a-f]{64}), (?<len>\d+) bytes')
        $c.preview_bytes_found = $nm.Success
        $c.no_shim_warning = -not $d.Text.Contains('rerun-launch.exe is not in Rerun')

        $p = Invoke-Rerun plan $lwSteps
        $c.plan_exit = $p.Code
        $hm = [regex]::Match($p.Text, 'apply with: rerun apply ([0-9a-f]{64})')
        if ($p.Code -ne 0 -or -not $hm.Success) { throw 'plan did not store a plan (see cli.log)' }
        $h = $hm.Groups[1].Value
        $dh = [regex]::Match($d.Text, '(?m)^plan ([0-9a-f]{64})')
        $c.dry_run_hash_equals_plan_hash = $dh.Success -and $dh.Groups[1].Value -eq $h

        $a = Invoke-Rerun apply $h --yes
        $c.apply_exit = $a.Code
        $c.profile_exists = Test-Path -LiteralPath $file -PathType Leaf
        $c.profile_bytes_are_the_previews = $false
        if ($c.profile_exists -and $nm.Success) {
            $c.profile_bytes_are_the_previews = ((Get-Item -LiteralPath $file).Length -eq [int]$nm.Groups['len'].Value) -and
                ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -eq $nm.Groups['sha'].Value)
        }
        $tm = [regex]::Match($a.Text, 'revert with: rerun revert ([0-9]{8}-[0-9a-f]{16})')
        if ($a.Code -ne 0 -or -not $tm.Success) { throw 'apply did not report a transaction (see cli.log)' }
        $txn = $tm.Groups[1].Value
        $c.game_folder_untouched_by_apply = (Get-Tree $lmRoot) -eq $gameBefore

        $result = Join-Path $rerunDir "launch\$lmId.result"
        Remove-Item -LiteralPath $result -Force -ErrorAction SilentlyContinue
        # SB-W2: a copy of the game that runs before the shim starts (about 59 s, stopped below).
        # The pause keeps its creation time clear of the shim's (the search takes processes
        # created at or after the shim, and the clock has a coarse tick).
        $pre = Start-Process -FilePath $lmExe -ArgumentList '/d /q /c ping -n 60 127.0.0.1 >nul' -PassThru
        Start-Sleep -Milliseconds 1500
        $lps = [int]$env:NUMBER_OF_PROCESSORS
        $preBefore = Get-Affinity $pre
        $lw.in_job = Test-InJob $pre
        $lw.logical_processors = $lps
        $lw.parent_mask_bits = if ($preBefore -gt 0) { Get-Bits $preBefore } else { $preBefore }
        $parentNarrows = ($preBefore -gt 0) -and ((Get-Bits $preBefore) -lt $lps)
        $lw.parent_job_narrows = $parentNarrows

        # SB-W1: Steam's command is the stub: game.exe runs `start /b game.exe ...` and ends at
        # once; the second game.exe holds for about 14 s, so that the check about 5 s after it was
        # found sees it running.
        $since = Get-Date
        $argLine = "--profile $lmId `"$lmExe`" /d /q /c start `"`" /b `"$lmExe`" /d /q /c ping -n 15 127.0.0.1 >nul"
        $shim = Start-Process -FilePath $launchExe -ArgumentList $argLine -PassThru
        $deadline = $since.AddSeconds(40)
        while (-not (Test-Path -LiteralPath $result) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
        $lw.seconds_to_result = [math]::Round(((Get-Date) - $since).TotalSeconds, 1)
        # The file is complete when it appears (the existing direct case reads it the same way);
        # a short pause costs nothing.
        Start-Sleep -Milliseconds 250
        $rtext = if (Test-Path -LiteralPath $result) { [string](Get-Content -LiteralPath $result -Raw) } else { '' }
        # The target: a running game.exe created after the shim's start that is not the copy of
        # SB-W2 (the stub has ended by then).
        $target = Get-Process -Name game -ErrorAction SilentlyContinue | Where-Object {
            $_.Path -eq $lmExe -and $_.Id -ne $pre.Id -and $_.StartTime -gt $since
        } | Sort-Object StartTime | Select-Object -First 1
        $targetMask = Get-Affinity $target
        $preAfter = Get-Affinity $pre
        $targetBits = if ($targetMask -gt 0) { Get-Bits $targetMask } else { $targetMask }
        $shimLeft = [int][math]::Max(0, 20000 - ((Get-Date) - $since).TotalMilliseconds)
        $c.shim_ends_within_20_s = $shim.WaitForExit($shimLeft)
        Add-Content -LiteralPath $log -Value ("result file after $($lw.seconds_to_result) s:`n$rtext`n" +
            "logical processors $lps, in_job $($lw.in_job), mask before the shim of the earlier copy 0x$('{0:x}' -f $preBefore) " +
            "(after 0x$('{0:x}' -f $preAfter)), parent job narrows: $parentNarrows`n" +
            "target pid $(if ($target) { $target.Id } else { 'none' }), mask 0x$('{0:x}' -f $targetMask) ($targetBits bits); shim ended within 20 s: $($c.shim_ends_within_20_s)")
        $lw.result = $rtext
        $lw.target_mask_bits = $targetBits

        $c.result_file = $rtext -ne ''
        $c.result_profile = $rtext -match "(?m)^profile=$lmId\r?$"
        $c.result_method_watch = $rtext -match '(?m)^method=watch\r?$'
        $c.target_found = $null -ne $target
        $isApplied = $rtext -match '(?m)^rule=applied\r?$'
        $isIneffective = $rtext -match '(?m)^rule=skipped:job_ineffective\r?$'
        if ($isApplied -or -not $parentNarrows) {
            $lw.outcome = if ($isApplied) { 'applied' } elseif ($isIneffective) { 'job_ineffective' } else { 'other' }
            $c.result_rule_applied = $isApplied
            $c.result_check_ok = $rtext -match '(?m)^check=ok\r?$'
            $cm = [regex]::Match($rtext, '(?m)^cpu=hard:(\d+):(\d+)\r?$')
            $c.result_cpu_hard_1_of_all = $cm.Success -and ([int]$cm.Groups[1].Value -eq 1) -and ([int]$cm.Groups[2].Value -eq $lps)
            # The target in the job has the mask: one bit (max_threads 1).
            $c.target_has_one_bit = $targetBits -eq 1
        } else {
            # A7: the parent job limits the processors; the honest outcome is job_ineffective, and
            # the parent's limit stays in force on the target.
            $lw.outcome = if ($isIneffective) { 'job_ineffective' } else { 'other' }
            $c.result_job_ineffective_under_a_narrowing_parent = $isIneffective
            $c.target_keeps_the_parent_mask = $targetMask -eq $preBefore
        }
        # SB-W2: the copy that ran before the shim is not the target.
        $c.earlier_copy_keeps_its_mask = ($preBefore -gt 0) -and ($preAfter -eq $preBefore)

        $v = Invoke-Rerun status
        $c.status_exit = $v.Code
        $c.status_names_the_watch_target = $v.Text.Contains("method watch: the rule is for the game process found after the start, not the program Steam starts: $lmExe")

        # Stop what is left of the start and the earlier copy (with their ping).
        Get-Process -Name game, ping -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'ping' -or $_.Path -eq $lmExe } | Stop-Process -Force -ErrorAction SilentlyContinue
        if (-not $shim.WaitForExit(15000)) { Stop-Process -Id $shim.Id -Force -ErrorAction SilentlyContinue }

        $r = Invoke-Rerun revert $txn --yes
        $c.revert_exit = $r.Code
        $c.revert_closed = $r.Text -match "transaction $txn reverted and closed"
        $c.profile_removed = -not (Test-Path -LiteralPath $file)
        $c.profiles_folder_stays = Test-Path -LiteralPath $profiles -PathType Container
        $c.game_folder_as_before = (Get-Tree $lmRoot) -eq $gameBefore
        $c.profile_files_as_before = (Get-Profiles) -eq $profilesBefore
        $s = Invoke-Rerun status --all
        $c.status_all_exit = $s.Code

        $bad = @($c.GetEnumerator() | Where-Object {
            if ($_.Key -like '*_exit') { $_.Value -ne 0 } else { $_.Value -ne $true }
        } | ForEach-Object { $_.Key })
        $lw.failed = $bad
        $lw.expected = ($bad.Count -eq 0)
    } catch {
        $lw.error = "$_"
        Add-Content -LiteralPath $log -Value "launch_method watch failed: $_"
    } finally {
        # Also after a failure: no copy of game.exe or ping stays behind.
        Get-Process -Name game, ping -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'ping' -or $_.Path -eq $lmExe } | Stop-Process -Force -ErrorAction SilentlyContinue
        if ($shim -and -not $shim.HasExited) { Stop-Process -Id $shim.Id -Force -ErrorAction SilentlyContinue }
        Restore-SteamKey $saved
    }
    $lw
}

# ---- VirtualStore, the real case (P4-0) --------------------------------------------------------
# A 32-bit test program without a manifest (tests/support/vstore_stub.rs, built from source by
# sandbox-launch.ps1) writes settings.ini in its own folder under Program Files as the standard
# user: UAC file virtualization puts the copy into %LOCALAPPDATA%\VirtualStore\Program Files\...
# and `rerun plan --dry-run` for a step that manages that settings.ini must then warn and name
# the copy (P3-7). ci-sandbox.ps1 (as the runner's administrator) prepares the folder
# C:\Program Files\RerunVsCase with game.exe (the stub) and a settings.ini; this script never
# writes there, only the stub does, and it is refused or virtualized. Elsewhere (the Windows
# Sandbox) the folder is absent and the case is skipped.
# Verdict (a fact, like SB-L7):
#   ok                virtualized, the real file untouched, no warning before, a warning naming the copy after
#   not_virtualized   the stub's write was refused or left no copy: virtualization is off here
#                     (UAC state in `uac`; ci-sandbox.ps1 fails only when UAC is on)
#   no_warning        the copy exists and Rerun does not warn (a product bug)
#   skipped, error    detail says why
$vsDir = 'C:\Program Files\RerunVsCase'
function Invoke-VirtualStore {
    $v = [ordered]@{ verdict = 'error'; detail = ''; uac = Get-UacState; stub_exit = $null; stub_output = ''; copy = ''; plan_before = ''; plan_after = '' }
    $exe = Join-Path $vsDir 'game.exe'
    $ini = Join-Path $vsDir 'settings.ini'
    if (-not ((Test-Path -LiteralPath $exe) -and (Test-Path -LiteralPath $ini))) {
        $v.verdict = 'skipped'
        $v.detail = "$vsDir is not prepared (only ci-sandbox.ps1 prepares it, as the runner's administrator)"
        return $v
    }
    try {
        # The image: i686, no manifest (a manifest with a requestedExecutionLevel switches
        # virtualization off, so a stub that has one would measure nothing).
        $bytes = [IO.File]::ReadAllBytes($exe)
        $peAt = [BitConverter]::ToInt32($bytes, 0x3C)
        $machine = [BitConverter]::ToUInt16($bytes, $peAt + 4)
        $latin = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
        $v.image_machine = '0x{0:x}' -f $machine
        $v.image_manifest = $latin.Contains('requestedExecutionLevel') -or $latin.Contains('<assembly')
        if ($machine -ne 0x14c) { throw "the test program is not an i686 image (machine $($v.image_machine))" }
        if ($v.image_manifest) { throw 'the test program carries a manifest: it would not be virtualized' }

        $copy = Join-Path $env:LOCALAPPDATA 'VirtualStore\Program Files\RerunVsCase\settings.ini'
        $v.copy = $copy
        if (Test-Path -LiteralPath $copy) { throw "a VirtualStore copy exists before the stub ran: $copy" }
        $hashBefore = (Get-FileHash -LiteralPath $ini -Algorithm SHA256).Hash
        $folder = $vsDir.Replace('\', '\\')
        $vsSteps = Join-Path $root 'steps-vs.json'
        Write-Plain $vsSteps ('{"format":1,"game":{"folder":"' + $folder + '"},"main_exe":"game.exe","steps":[{"ini_set":{"file":"settings.ini","values":[{"section":"Display","key":"Width","value":"1920"}]}}]}')
        Add-Content -LiteralPath $log -Value "`n=== VirtualStore (P4-0) ==="
        $before = Invoke-Rerun plan $vsSteps --dry-run
        $v.plan_before = "exit $($before.Code)"
        if ($before.Code -ne 0) { throw "plan --dry-run for a folder under Program Files failed before the stub ran (exit $($before.Code)): $(($before.Text -split "`n" | Select-Object -First 3) -join ' | ')" }
        if ($before.Text.Contains('Windows keeps a VirtualStore copy')) { throw 'the plan warned about a VirtualStore copy before there was one' }

        $ErrorActionPreference = 'Continue'
        $o = & $exe 2>&1 | ForEach-Object { "$_" }
        $v.stub_exit = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        $v.stub_output = ($o -join ' ')
        Add-Content -LiteralPath $log -Value "stub exit $($v.stub_exit): $($v.stub_output)"
        $exists = Test-Path -LiteralPath $copy
        $unchanged = (Get-FileHash -LiteralPath $ini -Algorithm SHA256).Hash -eq $hashBefore
        $v.copy_exists = $exists
        $v.real_file_unchanged = $unchanged
        if ($v.stub_exit -ne 0 -or -not $exists) {
            $v.verdict = 'not_virtualized'
            $v.detail = "the stub exited $($v.stub_exit) ($($v.stub_output)); copy exists: $exists; real file unchanged: $unchanged. UAC: EnableLUA=$($v.uac.EnableLUA), EnableVirtualization=$($v.uac.EnableVirtualization)"
            return $v
        }
        if (-not $unchanged) { throw 'the stub changed the real settings.ini: the write was not virtualized but allowed (the folder is writable for this user)' }

        $after = Invoke-Rerun plan $vsSteps --dry-run
        $v.plan_after = "exit $($after.Code)"
        $warns = $after.Text.Contains('Windows keeps a VirtualStore copy')
        $names = $after.Text.IndexOf($copy, [StringComparison]::OrdinalIgnoreCase) -ge 0
        $v.plan_warns = $warns
        $v.plan_names_the_copy = $names
        if ($after.Code -eq 0 -and $warns -and $names) { $v.verdict = 'ok' }
        else {
            $v.verdict = 'no_warning'
            $v.detail = "a copy exists at $copy but plan --dry-run (exit $($after.Code)) warns: $warns, names the copy: $names (see cli.log)"
        }
    } catch {
        $v.detail = "$_"
    }
    $v
}

$lm = $null
$lw = $null
$vs = $null
if (-not $Elevated) {
    $lm = Invoke-LaunchMethod
    $lw = Invoke-LaunchWatch
    $vs = Invoke-VirtualStore
}
[ordered]@{
    runs          = $runs
    unchanged     = $same
    expected      = ($expected -and $same -and ($Elevated -or ($lm.expected -and $lw.expected)))
    elevated      = $Elevated
    launch_method = if ($lm) { $lm } else { 'skipped: elevated' }
    launch_watch  = if ($lw) { $lw } else { 'skipped: elevated' }
    virtualstore  = if ($vs) { $vs } else { 'skipped: elevated' }
    note          = if ($Elevated) { 'elevated: the refusal (exit 3) of plan is the expected result' } else { '' }
}
