# Windows Sandbox probes SB-L2 to SB-L4 for the compatibility layer (P2-11): they RECORD FACTS
# in C:\sandbox\out\probe-layers.md, they do not test Rerun code. Guarded like the tests:
# only in the Sandbox account with RERUN_SANDBOX=1 (sandbox-run.ps1 sets it).
#
# Writes HKCU\...\AppCompatFlags\Layers values for test copies of cmd.exe under
# C:\RerunSandbox\probe and removes them again.
#   SB-L2  which value-name path form Windows applies: canonical / junction / 8.3 path
#          (matrix: name form x launch form), and whether the effect outlasts the removal of
#          the value (shim cache)
#   SB-L3  whether a value without the "~" prefix (or with "$") takes effect
#   SB-L4  whether the 32-bit registry view sees the same Layers value
# "Takes effect" is observed two ways: whether the launch of the 32-bit cmd.exe copy needs
# elevation (WINXPSP3 in a non-elevated session: Win32 740) and whether __COMPAT_LAYER is in
# the environment of the launched copy.
# Optional: C:\sandbox\tools\Procmon64.exe (Sysinternals, supplied by you, mapped read-only)
# records which Layers value name is queried at CreateProcess; the filtered CSV goes to
# procmon-layers.csv. SB-L1 (what the Explorer tab writes) is manual: sandbox-layers-dump.ps1.
#
# Windows PowerShell 5.1: native stderr is never redirected under $ErrorActionPreference =
# 'Stop'; native calls go through Run-Native, which judges only the exit code.

param([string]$Out = 'C:\sandbox\out')

$ErrorActionPreference = 'Stop'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or $env:USERPROFILE -notmatch '\\WDAGUtilityAccount\\?$' -or $env:RERUN_SANDBOX -ne '1') {
    Write-Error 'refusing to run: Windows Sandbox only (WDAGUtilityAccount, its profile and RERUN_SANDBOX=1)'
    exit 2
}
Remove-Item Env:\__COMPAT_LAYER -ErrorAction SilentlyContinue

$layers = 'HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers'
$base = 'C:\RerunSandbox\probe'
$real = Join-Path $base 'real'
$junc = Join-Path $base 'junc'
$procmon = 'C:\sandbox\tools\Procmon64.exe'
$report = New-Object System.Collections.Generic.List[string]
function Say([string]$s) { $report.Add($s) }

# Runs a native command, stderr merged as plain text; $script:NativeExit holds the exit code.
function Run-Native {
    $ErrorActionPreference = 'Continue'
    $cmd = $args[0]
    $rest = @($args | Select-Object -Skip 1)
    & $cmd @rest 2>&1 | ForEach-Object { "$_" }
    $script:NativeExit = $LASTEXITCODE
}
function Reg-Add([string]$name, [string]$data, [string]$view = '64') {
    Run-Native reg.exe add $layers /v $name /t REG_SZ /d $data /f "/reg:$view" | Out-Null
}
# A missing value is not an error.
function Reg-Del([string]$name, [string]$view = '64') {
    Run-Native reg.exe delete $layers /v $name /f "/reg:$view" | Out-Null
}
function Reg-Query([string]$name, [string]$view = '64') {
    $r = Run-Native reg.exe query $layers /v $name "/reg:$view"
    if ($script:NativeExit -ne 0) { return '<absent>' }
    return (($r | Where-Object { $_ -match 'REG_SZ' }) -join '; ').Trim()
}
# `ver` cannot be used: a cmd.exe copy outside System32 finds no MUI file and prints only
# "no message text for 0x2350" (seen in the first runs). The effect of WINXPSP3 on the
# 32-bit copy in a non-elevated session is that the launch needs elevation (Win32 740).
function Observe([string]$exe) {
    try {
        $o = (Run-Native $exe /c 'set __COMPAT_LAYER') | Out-String
    } catch {
        $w = $_.Exception
        while ($w -and -not ($w -is [ComponentModel.Win32Exception])) { $w = $w.InnerException }
        if ($w) { return "launch refused, Win32 $($w.NativeErrorCode)" }
        return 'launch failed: ' + ("$_" -split "`r?`n")[0]
    }
    $seen = if ($o -match '__COMPAT_LAYER=(.*)') { "set: $($Matches[1].Trim())" } else { 'not set' }
    return "launched; __COMPAT_LAYER $seen"
}

Say '# Layers probes (SB-L2 to SB-L4)'
Say ''
Say ('Build: ' + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber + ', date ' + (Get-Date -Format o))
Say 'Facts only. Observation = launched or refused (Win32 code; 740 = needs elevation) and `__COMPAT_LAYER` in the launched cmd.exe copy.'
Say ''

$forms = $null
function Cleanup {
    # Never throws: it runs in `finally`.
    try {
        if ($forms) { foreach ($f in $forms.Values) { Reg-Del $f } }
        Reg-Del (Join-Path $real 'probe64.exe')
    } catch { }
}

$pmlFile = Join-Path $Out 'procmon.pml'
$procmonOn = $false
try {
    New-Item -ItemType Directory -Force -Path $real | Out-Null
    if (Test-Path -LiteralPath $junc) { Run-Native cmd.exe /c rmdir $junc | Out-Null }
    Run-Native cmd.exe /c mklink /J $junc $real | Out-Null
    # The matrix uses the 32-bit cmd.exe: the first run (build 26100) showed that WINXPSP3 has
    # no effect on the 64-bit copy (RUNASINVOKER has). The 64-bit copy is the control row.
    Copy-Item -LiteralPath "$env:SystemRoot\SysWOW64\cmd.exe" -Destination (Join-Path $real 'probe.exe') -Force
    Copy-Item -LiteralPath "$env:SystemRoot\System32\cmd.exe" -Destination (Join-Path $real 'probe64.exe') -Force
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

    if (Test-Path -LiteralPath $procmon) {
        try {
            Remove-Item -LiteralPath $pmlFile -ErrorAction SilentlyContinue
            Start-Process -FilePath $procmon -ArgumentList '/AcceptEula', '/Quiet', '/Minimized', '/BackingFile', "`"$pmlFile`"" | Out-Null
            Start-Sleep -Seconds 8
            $procmonOn = $true
        } catch { Say ("- Process Monitor could not be started: $_"); Say '' }
    } else {
        Say '- Process Monitor not used: C:\sandbox\tools\Procmon64.exe is absent (put Procmon64.exe into target/sandbox/tools on the host to record which Layers value name is queried).'
        Say ''
    }

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

    Say '## SB-L2: after the value is removed (shim cache)'
    Say ''
    Reg-Add $forms.canonical '~ WINXPSP3'
    Say ('- value set, canonical launch: ' + (Observe $forms.canonical))
    Reg-Del $forms.canonical
    Say ('- value removed, canonical launch at once: ' + (Observe $forms.canonical))
    Start-Sleep -Seconds 5
    Say ('- value removed, canonical launch 5 s later: ' + (Observe $forms.canonical))
    Say ''

    Say '## SB-L3: prefix of the data (canonical name, canonical launch)'
    Say ''
    Say '| data | observation |'
    Say '|---|---|'
    foreach ($data in @('~ WINXPSP3', 'WINXPSP3', '$ WINXPSP3', '~WINXPSP3', '~ RUNASINVOKER', '~ WINXPSP3 RUNASINVOKER')) {
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
    $p64 = Join-Path $real 'probe64.exe'
    Reg-Add $p64 '~ WINXPSP3'
    Say ('- 64-bit cmd.exe copy, `~ WINXPSP3`: ' + (Observe $p64))
    Reg-Del $p64
    Reg-Add $p64 '~ RUNASINVOKER'
    Say ('- 64-bit cmd.exe copy, `~ RUNASINVOKER`: ' + (Observe $p64))
    Reg-Del $p64
    Say ''
}
catch {
    Say ''
    Say ('PROBE FAILED: ' + $_)
}
finally {
    Cleanup
    if ($procmonOn) {
        try {
            Run-Native $procmon /Terminate | Out-Null
            Start-Sleep -Seconds 3
            $csvFull = Join-Path $Out 'procmon-all.csv'
            Start-Process -FilePath $procmon -ArgumentList '/AcceptEula', '/Quiet', '/Minimized', '/OpenLog', "`"$pmlFile`"", '/SaveAs', "`"$csvFull`"" -Wait | Out-Null
            Run-Native $procmon /Terminate | Out-Null
            if (Test-Path -LiteralPath $csvFull) {
                $rows = Import-Csv -LiteralPath $csvFull | Where-Object { $_.Path -like '*AppCompatFlags\Layers*' -and $_.'Process Name' -match 'probe|cmd' }
                $rows | Export-Csv -LiteralPath (Join-Path $Out 'procmon-layers.csv') -NoTypeInformation -Encoding UTF8
                Remove-Item -LiteralPath $csvFull -ErrorAction SilentlyContinue
                Say "## Process Monitor: $(@($rows).Count) Layers queries by probe/cmd processes in procmon-layers.csv"
                Say '(the value name is the last path segment; compare it with the launch form of each SB-L2 row)'
                Say ''
            } else {
                Say '## Process Monitor: the CSV export failed; the raw log is procmon.pml'
                Say ''
            }
        } catch { Say ("## Process Monitor: post-processing failed: $_"); Say '' }
    }
}

Say '## Left behind in the Layers key (should list nothing of ours)'
Say '```'
Say ((Run-Native reg.exe query $layers | Out-String).Trim())
Say '```'
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$report | Set-Content -LiteralPath (Join-Path $Out 'probe-layers.md') -Encoding UTF8
Write-Host ($report -join "`n")
