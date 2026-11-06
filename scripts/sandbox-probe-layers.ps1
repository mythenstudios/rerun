# Windows Sandbox probes SB-L2 to SB-L4 for the compatibility layer (P2-11): they RECORD FACTS
# in C:\sandbox\out\probe-layers.md, they do not test Rerun code. Guarded like the tests:
# only in the Sandbox account with RERUN_SANDBOX=1 (sandbox-run.ps1 sets it).
#
# Writes HKCU\...\AppCompatFlags\Layers values for test copies of cmd.exe under
# C:\RerunSandbox\probe and removes them again.
#   SB-L2  which value-name path form Windows applies: canonical / junction / 8.3 path
#          (matrix: name form x launch form)
#   SB-L3  whether a value without the "~" prefix (or with "$") takes effect
#   SB-L4  whether the 32-bit registry view sees the same Layers value
# "Takes effect" is observed two ways in the launched copy of cmd.exe: `ver` (the WINXPSP3
# layer lies about the OS version) and whether __COMPAT_LAYER is in its environment.
# SB-L1 (what the Explorer tab writes) is manual: sandbox-layers-dump.ps1.

param([string]$Out = 'C:\sandbox\out')

$ErrorActionPreference = 'Stop'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or $env:RERUN_SANDBOX -ne '1') {
    Write-Error 'refusing to run: Windows Sandbox only (WDAGUtilityAccount and RERUN_SANDBOX=1)'
    exit 2
}
Remove-Item Env:\__COMPAT_LAYER -ErrorAction SilentlyContinue

$layers = 'HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers'
$base = 'C:\RerunSandbox\probe'
$real = Join-Path $base 'real'
$junc = Join-Path $base 'junc'
$report = New-Object System.Collections.Generic.List[string]
function Say([string]$s) { $report.Add($s) }

function Reg-Add([string]$name, [string]$data, [string]$view = '64') {
    & reg.exe add $layers /v $name /t REG_SZ /d $data /f "/reg:$view" | Out-Null
}
function Reg-Del([string]$name, [string]$view = '64') {
    & reg.exe delete $layers /v $name /f "/reg:$view" 2>&1 | Out-Null
}
function Reg-Query([string]$name, [string]$view = '64') {
    $r = & reg.exe query $layers /v $name "/reg:$view" 2>&1
    if ($LASTEXITCODE -ne 0) { return '<absent>' }
    return (($r | Where-Object { $_ -match 'REG_SZ' }) -join '; ').Trim()
}
function Observe([string]$exe) {
    $o = & $exe /c 'ver & set __COMPAT_LAYER' 2>&1 | Out-String
    $ver = ([regex]::Match($o, 'Version [0-9.]+')).Value
    $seen = if ($o -match '__COMPAT_LAYER=(.*)') { "set: $($Matches[1].Trim())" } else { 'not set' }
    return "$ver; __COMPAT_LAYER $seen"
}

Say '# Layers probes (SB-L2 to SB-L4)'
Say ''
Say ('Build: ' + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber + ', date ' + (Get-Date -Format o))
Say 'Facts only. Observation = `ver` output and `__COMPAT_LAYER` in the launched cmd.exe copy.'
Say ''

New-Item -ItemType Directory -Force -Path $real | Out-Null
if (Test-Path -LiteralPath $junc) { cmd /c rmdir "`"$junc`"" | Out-Null }
cmd /c mklink /J "`"$junc`"" "`"$real`"" | Out-Null
Copy-Item -LiteralPath "$env:SystemRoot\System32\cmd.exe" -Destination (Join-Path $real 'probe.exe') -Force
Copy-Item -LiteralPath "$env:SystemRoot\SysWOW64\cmd.exe" -Destination (Join-Path $real 'probe32.exe') -Force
$short = (New-Object -ComObject Scripting.FileSystemObject).GetFile((Join-Path $real 'probe.exe')).ShortPath
$forms = [ordered]@{
    canonical = (Join-Path $real 'probe.exe')
    junction  = (Join-Path $junc 'probe.exe')
    short83   = $short
}
Say '## Path forms'
foreach ($k in $forms.Keys) { Say ('- ' + $k + ': `' + $forms[$k] + '`') }
if ($short -eq $forms.canonical) { Say '- NOTE: no 8.3 name exists for the probe folder (short form equals the long one)' }
Say ''

Say '## Control (no value)'
Say ('- canonical launch: ' + (Observe $forms.canonical))
Say ''

function Cleanup {
    foreach ($f in $forms.Values) { Reg-Del $f }
    Reg-Del (Join-Path $real 'probe32.exe')
}

try {
    Say '## SB-L2: value name form x launch form (data `~ WINXPSP3`)'
    Say ''
    Say '| value name | launched via | observation |'
    Say '|---|---|---|'
    foreach ($nameForm in $forms.Keys) {
        foreach ($launch in $forms.Keys) {
            Cleanup
            Reg-Add $forms[$nameForm] '~ WINXPSP3'
            Say ("| $nameForm | $launch | " + (Observe $forms[$launch]) + ' |')
        }
    }
    Cleanup
    Say ''

    Say '## SB-L3: prefix of the data (canonical name, canonical launch)'
    Say ''
    Say '| data | observation |'
    Say '|---|---|'
    foreach ($data in @('~ WINXPSP3', 'WINXPSP3', '$ WINXPSP3', '~WINXPSP3', '~ RUNASINVOKER')) {
        Cleanup
        Reg-Add $forms.canonical $data
        Say ('| `' + $data + '` | ' + (Observe $forms.canonical) + ' |')
    }
    Cleanup
    Say ''

    Say '## SB-L4: registry views'
    Say ''
    $name = $forms.canonical
    Reg-Add $name '~ WINXPSP3' '64'
    Say ('- written with /reg:64, read /reg:64: ' + (Reg-Query $name '64'))
    Say ('- written with /reg:64, read /reg:32: ' + (Reg-Query $name '32'))
    Reg-Del $name '64'
    Reg-Add $name '~ WINXPSP3' '32'
    Say ('- written with /reg:32, read /reg:32: ' + (Reg-Query $name '32'))
    Say ('- written with /reg:32, read /reg:64: ' + (Reg-Query $name '64'))
    Reg-Del $name '32'
    Reg-Del $name '64'
    Say ('- after deleting through /reg:32 and /reg:64: ' + (Reg-Query $name '64'))
    Say ''
    $p32 = Join-Path $real 'probe32.exe'
    Reg-Add $p32 '~ WINXPSP3'
    Say ('- 32-bit cmd.exe copy, value written natively: ' + (Observe $p32))
    Reg-Del $p32
    Say ''
}
catch {
    Say ''
    Say ('PROBE FAILED: ' + $_)
}
finally {
    Cleanup
}

Say '## Left behind in the Layers key (should list nothing of ours)'
Say '```'
Say ((& reg.exe query $layers 2>&1 | Out-String).Trim())
Say '```'
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$report | Set-Content -LiteralPath (Join-Path $Out 'probe-layers.md') -Encoding UTF8
Write-Host ($report -join "`n")
