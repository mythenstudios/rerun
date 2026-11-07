# Runs inside Windows Sandbox only, called by sandbox-run.ps1 (P2-13, user decision E7 a): the
# CLI round trip with the release rerun.exe on the Sandbox account's real LocalAppData and
# HKCU: plan, apply --dry-run, apply --yes, status, revert --yes, status --all, on a game
# folder C:\RerunSandbox\cli\game with a copy of cmd.exe as its main executable, a local
# package, two registry values and an INI key. Before and after are compared (files with
# length, SHA-256 and attributes; the registry key). Never on the host: it refuses anywhere but
# the Sandbox account, and it writes the real HKCU and LocalAppData of whoever runs it.
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
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or $env:USERPROFILE -notmatch '\\WDAGUtilityAccount\\?$') {
    throw "refusing to run: this is not the Windows Sandbox account (USERNAME=$env:USERNAME)"
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
$log = Join-Path $Out 'cli.log'
$utf8 = New-Object Text.UTF8Encoding $false

function Write-Plain([string]$path, [string]$text) {
    [IO.File]::WriteAllText($path, $text, $utf8)
}

# Files of the game folder (relative path, length, SHA-256, attributes) and the registry key.
function Get-State {
    $files = Get-ChildItem -LiteralPath $game -Recurse -Force | Sort-Object FullName | ForEach-Object {
        $rel = $_.FullName.Substring($game.Length)
        if ($_.PSIsContainer) { "dir $rel $($_.Attributes)" }
        else { "file $rel $($_.Length) $((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash) $($_.Attributes)" }
    }
    $reg = if (Test-Path -LiteralPath $regKey) {
        Get-ChildItem -LiteralPath $regKey -Recurse | ForEach-Object { $_.Name; ($_ | Get-ItemProperty | Out-String).Trim() }
    } else { 'registry key absent' }
    (@($files) + @($reg)) -join "`n"
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
{"ini_set":{"file":"game.ini","values":[{"section":"Display","key":"Width","value":"1920"}]}}]}
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
        $runs.status = (Invoke-Rerun status).Code
        $r = Invoke-Rerun revert $txn --yes
        $runs.revert = $r.Code
        $runs.status_all = (Invoke-Rerun status --all).Code
        $closed = $r.Text -match "transaction $txn reverted and closed"
        $expected = $dryUnchanged -and ($applied -ne $before) -and $closed -and
            (@($runs.Values) | Where-Object { $_ -ne 0 }).Count -eq 0
    }
}
$after = Get-State
$same = ($after -eq $before)
if (-not $same) {
    Add-Content -LiteralPath $log -Value "`nBEFORE:`n$before`nAFTER:`n$after"
}
[ordered]@{
    runs      = $runs
    unchanged = $same
    expected  = ($expected -and $same)
    elevated  = $Elevated
    note      = if ($Elevated) { 'elevated: the refusal (exit 3) of plan is the expected result' } else { '' }
}
