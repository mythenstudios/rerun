# Runs inside Windows Sandbox or on the disposable CI runner only, called by sandbox-run.ps1 last
# (P5-13, ADR 0030, docs/09 "Alpha build, install and uninstall"): the alpha's install.ps1 and
# uninstall.ps1 on the real LocalAppData and Start menu of the test account, with -Yes (sandbox
# only: no Enter prompts, the app is not started). Never on the host: it refuses anywhere but the
# Sandbox account and the CI accounts, and uninstall.ps1 deletes the real %LOCALAPPDATA%\Rerun.
#
# The payload is built here from the staged binaries: rerun.exe and rerun-launch.exe as released,
# vstore-stub.exe as a stand-in rerun-app.exe (never started), install.ps1 and uninstall.ps1 as in
# packaging\windows, a payload.json without index. An existing %LOCALAPPDATA%\Rerun (from the
# earlier passes) is renamed aside first.
#
# Cases (each with its checks; result.json key "install"):
#  I9  elevated (pass 2 only): install refused, nothing written.
#  I1  install: every file with its SHA-256, install.json, the shortcut and its target,
#      rerun.exe --version from the install folder.
#  I3  an open transaction (an INI key applied with the installed rerun.exe): uninstall refused,
#      program folder, shortcut and data folder unchanged; then reverted.
#  K   uninstall -KeepData: program folder and shortcut gone, data folder identical; install again.
#  J1  a junction deep inside the data folder: uninstall refused, nothing removed anywhere, the
#      junction's target untouched.
#  J2  a junction at %LOCALAPPDATA%\Rerun itself: the same.
#  I10 full uninstall: exactly the program folder, the shortcut and the data folder are gone;
#      every other entry of LocalAppData, LocalAppData\Programs and the Start menu is as before.

param(
    [Parameter(Mandatory = $true)][string]$Out,
    [Parameter(Mandatory = $true)][bool]$Elevated,
    [switch]$Ci
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'sandbox-guard.ps1')  # the script's own copy: run from the repo on a host, its guard refuses
if (-not (Test-SandboxGuard -Script $PSCommandPath -Expected 'C:\sandbox\scripts\sandbox-install.ps1' -Ci ([bool]$Ci))) {
    throw "refusing to run: not the Windows Sandbox account and its mapped scripts, nor the CI accounts with -Ci (USERNAME=$env:USERNAME, script $PSCommandPath, ci=$Ci)"
}
# The scripts accept -Yes only with one of these set.
if ($Ci) { $env:RERUN_CI_SANDBOX = '1' } else { $env:RERUN_SANDBOX = '1' }

$bin = 'C:\sandbox\bin'
# Per account: pass 1 (rerunci) and pass 2 (runneradmin) run on the same runner.
$root = "C:\RerunSandbox\install-$env:USERNAME"
$payload = Join-Path $root 'payload'
$outside = Join-Path $root 'outside'
$game = Join-Path $root 'game'
$log = Join-Path $Out 'install.log'
$lad = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
$startMenu = [Environment]::GetFolderPath([Environment+SpecialFolder]::Programs)
$programs = Join-Path $lad 'Programs'
$dest = Join-Path $programs 'Rerun'
$data = Join-Path $lad 'Rerun'
$lnk = Join-Path $startMenu 'Rerun.lnk'
$utf8 = New-Object Text.UTF8Encoding $false
$ps = Join-Path $PSHOME 'powershell.exe'

function Log([string]$s) { Add-Content -LiteralPath $log -Value $s; Write-Host $s }

function Sha([string]$p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() }

# A tree as sorted lines (relative path, kind, length, SHA-256), never following a link.
function Get-Tree([string]$dir) {
    if (-not (Test-Path -LiteralPath $dir)) { return @('<absent>') }
    $i = Get-Item -LiteralPath $dir -Force
    if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) { return @('<link>') }
    $lines = New-Object System.Collections.Generic.List[string]
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($dir)
    while ($stack.Count -gt 0) {
        foreach ($c in @(Get-ChildItem -LiteralPath $stack.Pop() -Force)) {
            $rel = $c.FullName.Substring($dir.Length)
            if ($c.Attributes -band [IO.FileAttributes]::ReparsePoint) { $lines.Add("link $rel") }
            elseif ($c.PSIsContainer) { $lines.Add("dir $rel"); $stack.Push($c.FullName) }
            else { $lines.Add("file $rel $($c.Length) $(Sha $c.FullName)") }
        }
    }
    return @($lines | Sort-Object)
}

# The names in a folder except $skip.
function Get-Names([string]$dir, [string]$skip) {
    if (-not (Test-Path -LiteralPath $dir)) { return @() }
    return @(Get-ChildItem -LiteralPath $dir -Force | Where-Object { $_.Name -ne $skip } | ForEach-Object { $_.Name } | Sort-Object)
}

function Same($a, $b) { return (@($a) -join "`n") -eq (@($b) -join "`n") }

# Runs install.ps1 or uninstall.ps1 in a fresh Windows PowerShell; its exit code.
function Run-Script([string]$script, [string[]]$arguments) {
    Log ">> $script $($arguments -join ' ')"
    $ErrorActionPreference = 'Continue'
    $lines = @(& $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script @arguments 2>&1 | ForEach-Object { "$_" })
    $lines | ForEach-Object { Log "   $_" }
    $script:LastText = $lines -join "`n"
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    Log "   exit $code"
    return $code
}

function Run-Rerun([string[]]$arguments) {
    $ErrorActionPreference = 'Continue'
    $o = & (Join-Path $dest 'rerun.exe') @arguments 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    Log "   rerun $($arguments -join ' '): exit $code"
    $o | ForEach-Object { Log "     $_" }
    return @{ Code = $code; Out = ($o -join "`n") }
}

function Shortcut-Target {
    if (-not (Test-Path -LiteralPath $lnk)) { return $null }
    return (New-Object -ComObject WScript.Shell).CreateShortcut($lnk).TargetPath
}

$cases = New-Object System.Collections.Generic.List[object]
$failed = New-Object System.Collections.Generic.List[string]
function Case([string]$id, [bool]$ok, [string]$what) {
    $cases.Add([ordered]@{ id = $id; ok = $ok; what = $what })
    Log "CASE $id $(if ($ok) { 'ok' } else { 'FAILED' }): $what"
    if (-not $ok) { $failed.Add($id) }
}

Set-Content -LiteralPath $log -Value "install/uninstall cases, account $env:USERNAME, elevated=$Elevated"
try {
    # ---- the payload ----
    foreach ($p in @($root)) { if (Test-Path -LiteralPath $p) { throw "$p exists already" } }
    if (Test-Path -LiteralPath $dest) { throw "$dest exists already: the test needs a machine without an installed Rerun" }
    New-Item -ItemType Directory -Force -Path $payload, $outside, $game | Out-Null
    Copy-Item -LiteralPath (Join-Path $bin 'rerun.exe') -Destination (Join-Path $payload 'rerun.exe')
    Copy-Item -LiteralPath (Join-Path $bin 'rerun-launch.exe') -Destination (Join-Path $payload 'rerun-launch.exe')
    Copy-Item -LiteralPath (Join-Path $bin 'vstore-stub.exe') -Destination (Join-Path $payload 'rerun-app.exe')
    Copy-Item -LiteralPath (Join-Path $bin 'install.ps1') -Destination (Join-Path $payload 'install.ps1')
    Copy-Item -LiteralPath (Join-Path $bin 'uninstall.ps1') -Destination (Join-Path $payload 'uninstall.ps1')
    [IO.File]::WriteAllText((Join-Path $payload 'README.txt'), "sandbox payload`r`n", $utf8)
    $version = ((& (Join-Path $payload 'rerun.exe') --version) -replace '^rerun ', '').Trim()
    $entries = @(Get-ChildItem -LiteralPath $payload -Force | Sort-Object Name | ForEach-Object {
            '{{"name":"{0}","size":{1},"sha256":"{2}"}}' -f $_.Name, $_.Length, (Sha $_.FullName)
        })
    [IO.File]::WriteAllText((Join-Path $payload 'payload.json'), ('{{"format":1,"product":"Rerun","version":"{0}","build":"sandbox-test","files":[{1}],"index":null}}' -f $version, ($entries -join ',')), $utf8)
    Set-Content -LiteralPath (Join-Path $outside 'keep.txt') -Value 'outside the data folder: must survive'
    $outsideBefore = Get-Tree $outside

    if ($Elevated) {
        # I9: elevated, nothing written.
        $code = Run-Script (Join-Path $payload 'install.ps1') @('-Yes')
        Case 'I9' (($code -ne 0) -and -not (Test-Path -LiteralPath $dest) -and -not (Test-Path -LiteralPath $lnk)) 'install refused elevated, nothing written'
        return [ordered]@{ cases = $cases; failed = $failed; expected = ($failed.Count -eq 0) }
    }

    if (Test-Path -LiteralPath $data) {
        $aside = "$data-before-install-test"
        Rename-Item -LiteralPath $data -NewName (Split-Path $aside -Leaf)
        Log "moved the data folder of the earlier passes aside: $aside"
    }
    $ladBefore = Get-Names $lad 'Rerun'
    $programsBefore = Get-Names $programs 'Rerun'
    $startBefore = Get-Names $startMenu 'Rerun.lnk'

    # ---- I1 install ----
    $code = Run-Script (Join-Path $payload 'install.ps1') @('-Yes')
    $filesOk = $true
    foreach ($f in @(Get-ChildItem -LiteralPath $payload -Force | Where-Object { $_.Name -ne 'install.ps1' -and $_.Name -ne 'payload.json' })) {
        $t = Join-Path $dest $f.Name
        if (-not (Test-Path -LiteralPath $t) -or (Sha $t) -ne (Sha $f.FullName)) { $filesOk = $false; Log "   missing or different: $t" }
    }
    $target = Shortcut-Target
    $v = Run-Rerun @('--version')
    Case 'I1' (($code -eq 0) -and $filesOk -and (Test-Path -LiteralPath (Join-Path $dest 'install.json')) -and
        -not (Test-Path -LiteralPath (Join-Path $dest 'install.ps1')) -and $target -and ($target -eq (Join-Path $dest 'rerun-app.exe')) -and ($v.Code -eq 0)) 'install: files, install.json, shortcut, rerun --version'

    # ---- I3 open transaction ----
    Copy-Item -LiteralPath "$env:WINDIR\System32\cmd.exe" -Destination (Join-Path $game 'game.exe')
    [IO.File]::WriteAllText((Join-Path $game 'game.ini'), "[Display]`r`nWidth=1280`r`n", $utf8)
    $steps = Join-Path $root 'steps.json'
    $folder = $game.Replace('\', '\\')
    [IO.File]::WriteAllText($steps, ('{{"format":1,"game":{{"folder":"{0}"}},"main_exe":"game.exe","steps":[{{"ini_set":{{"file":"game.ini","values":[{{"section":"Display","key":"Width","value":"1920"}}]}}}}]}}' -f $folder), $utf8)
    $p = Run-Rerun @('plan', $steps)
    $hash = ([regex]::Match($p.Out, 'apply with: rerun apply ([0-9a-f]{64})')).Groups[1].Value
    $a = Run-Rerun @('apply', $hash, '--yes')
    $txn = ([regex]::Match($a.Out, 'revert with: rerun revert (\S+)')).Groups[1].Value
    $destBefore = Get-Tree $dest; $dataBefore = Get-Tree $data
    $code = Run-Script (Join-Path $dest 'uninstall.ps1') @('-Yes')
    Case 'I3' ($txn -and ($code -ne 0) -and ($script:LastText -match 'still open') -and (Same $destBefore (Get-Tree $dest)) -and (Same $dataBefore (Get-Tree $data)) -and (Shortcut-Target)) 'an open transaction stops the uninstall, nothing removed'
    $r = Run-Rerun @('revert', $txn, '--yes')
    if ($r.Code -ne 0) { Case 'I3-revert' $false 'the revert after I3' }

    # ---- K: -KeepData, then install again ----
    $dataBefore = Get-Tree $data
    $code = Run-Script (Join-Path $dest 'uninstall.ps1') @('-Yes', '-KeepData')
    Case 'K' (($code -eq 0) -and -not (Test-Path -LiteralPath $dest) -and -not (Test-Path -LiteralPath $lnk) -and (Same $dataBefore (Get-Tree $data))) 'uninstall -KeepData keeps the data folder identical'
    $code = Run-Script (Join-Path $payload 'install.ps1') @('-Yes')
    if ($code -ne 0) { Case 'K-reinstall' $false 'install again after -KeepData' }

    # ---- J1: a junction deep inside the data folder ----
    # In a folder Rerun does not use itself, so uninstall-check passes and the tree walk meets it.
    $deep = Join-Path $data 'zz-test\deeper\link'
    New-Item -ItemType Directory -Force -Path (Split-Path $deep) | Out-Null
    cmd.exe /c mklink /J "$deep" "$outside" | Out-Null
    $destBefore = Get-Tree $dest; $dataBefore = Get-Tree $data
    $code = Run-Script (Join-Path $dest 'uninstall.ps1') @('-Yes')
    Case 'J1' (($code -ne 0) -and ($script:LastText -match 'link or junction') -and (Same $outsideBefore (Get-Tree $outside)) -and (Same $destBefore (Get-Tree $dest)) -and (Same $dataBefore (Get-Tree $data)) -and (Shortcut-Target)) 'a junction inside the data folder stops the uninstall, nothing removed'
    cmd.exe /c rmdir "$deep" | Out-Null

    # ---- J2: a junction at %LOCALAPPDATA%\Rerun ----
    $real = "$data-real"
    Rename-Item -LiteralPath $data -NewName (Split-Path $real -Leaf)
    cmd.exe /c mklink /J "$data" "$outside" | Out-Null
    $destBefore = Get-Tree $dest
    $code = Run-Script (Join-Path $dest 'uninstall.ps1') @('-Yes')
    Case 'J2' (($code -ne 0) -and ($script:LastText -match 'reparse point') -and (Same $outsideBefore (Get-Tree $outside)) -and (Same $destBefore (Get-Tree $dest)) -and (Shortcut-Target)) 'a junction at the data folder stops the uninstall, nothing removed'
    cmd.exe /c rmdir "$data" | Out-Null
    Rename-Item -LiteralPath $real -NewName (Split-Path $data -Leaf)

    # ---- I10: full uninstall ----
    $code = Run-Script (Join-Path $dest 'uninstall.ps1') @('-Yes')
    Case 'I10' (($code -eq 0) -and -not (Test-Path -LiteralPath $dest) -and -not (Test-Path -LiteralPath $data) -and -not (Test-Path -LiteralPath $lnk) -and
        (Same $ladBefore (Get-Names $lad 'Rerun')) -and (Same $programsBefore (Get-Names $programs 'Rerun')) -and
        (Same $startBefore (Get-Names $startMenu 'Rerun.lnk')) -and (Same $outsideBefore (Get-Tree $outside))) 'full uninstall removes exactly the program folder, the shortcut and the data folder'
} catch {
    Log "ERROR: $_"
    $failed.Add("error: $_")
}
return [ordered]@{ cases = $cases; failed = $failed; expected = ($failed.Count -eq 0) }
