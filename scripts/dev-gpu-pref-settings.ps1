# [DEV] measurement SB-G1 for gpu_preference (P4-11, docs/09-testing.md "SB-G1, manual"): what
# Settings > System > Display > Graphics writes below
# HKCU\Software\Microsoft\DirectX\UserGpuPreferences for one program, and whether Settings keeps
# the form Rerun writes (foreign pairs first, GpuPreference=2; appended; condition S4).
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\dev-gpu-pref-settings.ps1
#
# Run it in a normal (not administrator) PowerShell in the repository. About 4 minutes, no
# administrator prompt. The instruction of each step is in the window title and on a cleared
# screen; the script watches the value itself and moves on when the expected change is seen. It
# never asks a question; only steps 4 and 5 wait for Enter.
#
# What it changes on the machine: a copy of whoami.exe at
# %LOCALAPPDATA%\RerunTest\gpupref\RerunGpuPrefProbe.exe (never started; Settings only needs a
# path), and the one value Settings and step 5 write for that path. At the end, always (also
# after Ctrl+C), it deletes that value, the copy and its folder, and the DirectX and
# UserGpuPreferences keys only if it created them and they are empty. No other value is read by
# name or written; no security setting is touched.
#
# Step 4 (security review P4-11, finding 1): how Settings stores "a specific GPU" (Windows 11
# 24H2), offered only if the page lists adapters; recorded as INFO, judged by the reader.
#
# Output: tests\fixtures\gpu-pref\sb-g1-<date>.txt (the probe's path replaced by a neutral one,
# no user name), then a PASS/FAIL summary.

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$keyPath = 'Software\Microsoft\DirectX\UserGpuPreferences'
$dir = Join-Path $env:LOCALAPPDATA 'RerunTest\gpupref'
$probe = Join-Path $dir 'RerunGpuPrefProbe.exe'
$neutral = 'C:\Games\Probe\RerunGpuPrefProbe.exe'
$date = Get-Date -Format 'yyyy-MM-dd'
$out = Join-Path $repo "tests\fixtures\gpu-pref\sb-g1-$date.txt"
$build = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion')
$buildText = "$($build.CurrentBuild).$($build.UBR) ($($build.DisplayVersion))"
$log = New-Object System.Collections.Generic.List[string]
$results = [ordered]@{}

$hkcu = [Microsoft.Win32.Registry]::CurrentUser
$hadDirectX = $null -ne $hkcu.OpenSubKey('Software\Microsoft\DirectX')
$hadKey = $null -ne $hkcu.OpenSubKey($keyPath)

# The probe's value: @{ Kind; Data } or $null when absent.
function Read-Probe {
    $k = $hkcu.OpenSubKey($keyPath)
    if ($null -eq $k) { return $null }
    try {
        $v = $k.GetValue($probe, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($null -eq $v) { return $null }
        return @{ Kind = $k.GetValueKind($probe).ToString(); Data = [string]$v }
    } finally { $k.Close() }
}

function Show([string]$step, [string]$text) {
    $host.UI.RawUI.WindowTitle = "SB-G1 $step : $text"
    Clear-Host
    Write-Host "SB-G1 $step" -ForegroundColor Cyan
    Write-Host $text -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Programm: $probe"
    Write-Host "(Abbrechen: Strg+C, das Skript raeumt trotzdem auf)"
}

function Record([string]$label, $v) {
    if ($null -eq $v) { $line = "${label}: <absent>" }
    else { $line = "${label}: $($v.Kind) `"$($v.Data)`"" }
    $log.Add($line)
    Write-Host $line -ForegroundColor Green
}

# Waits until $cond is true for the probe's value; records every distinct value seen meanwhile.
function Watch([string]$label, [scriptblock]$cond, [int]$seconds = 240) {
    $last = '<start>'
    $until = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $until) {
        $v = Read-Probe
        $s = if ($null -eq $v) { '<absent>' } else { "$($v.Kind)|$($v.Data)" }
        if ($s -ne $last) { Record $label $v; $last = $s }
        if (& $cond $v) { return $v }
        Start-Sleep -Milliseconds 300
    }
    $log.Add("${label}: TIMEOUT after $seconds s")
    return $null
}

# Records every distinct value until Enter; returns the last value.
function Watch-UntilEnter([string]$label) {
    while ([Console]::KeyAvailable) { [void][Console]::ReadKey($true) }
    $last = '<start>'
    $v = $null
    while ($true) {
        $v = Read-Probe
        $s = if ($null -eq $v) { '<absent>' } else { "$($v.Kind)|$($v.Data)" }
        if ($s -ne $last) { Record $label $v; $last = $s }
        if ([Console]::KeyAvailable -and [Console]::ReadKey($true).Key -eq 'Enter') { return $v }
        Start-Sleep -Milliseconds 300
    }
}

function Has-Pref($v, [string]$n) { $null -ne $v -and $v.Data -match "(^|;)GpuPreference=$n;" }

try {
    if (Test-Path -LiteralPath $dir) { throw "Folder $dir exists already: remove it first (left from an earlier run?)" }
    New-Item -ItemType Directory -Path $dir | Out-Null
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\whoami.exe') -Destination $probe
    if ($null -ne (Read-Probe)) { throw "A value for $probe exists already" }
    $log.Add("SB-G1 gpu_preference, Settings > System > Display > Graphics")
    $log.Add("Windows build $buildText, $date")
    $log.Add("Probe path written as: $neutral")
    $log.Add("Keys before: DirectX=$hadDirectX UserGpuPreferences=$hadKey")
    Set-Clipboard -Value $probe
    Start-Process 'ms-settings:display-advancedgraphics'

    Show '1/6' 'Grafik: "Desktop-App hinzufuegen"/"Durchsuchen", Pfad ist in der Zwischenablage (Strg+V), hinzufuegen'
    $v = Watch '1 added' { param($v) $null -ne $v }
    $results['1 added'] = $null -ne $v

    Show '2/6' 'App anklicken, GPU-Einstellung auf "Hohe Leistung" stellen (ggf. Speichern)'
    $v = Watch '2 high performance' { param($v) Has-Pref $v 2 }
    $results['2 high performance = GpuPreference=2'] = $null -ne $v

    Show '3/6' 'Jetzt auf "Energiesparmodus" stellen'
    $v = Watch '3 power saving' { param($v) Has-Pref $v 1 }
    $results['3 power saving = GpuPreference=1'] = $null -ne $v

    Show '4/6' 'Falls angeboten: GPU-Einstellung auf eine bestimmte GPU (Grafikkarte mit Namen) stellen, dann hier Enter. Sonst nur Enter'
    $v = Watch-UntilEnter '4 specific GPU'
    $log.Add("INFO 4 specific GPU, last value: $(if ($null -eq $v) { '<absent>' } else { $v.Data })")

    Show '5/6' 'Fuer diese App "Auto HDR" und "Optimierungen fuer Spiele im Fenstermodus" je ein- und ausschalten (falls vorhanden), dann hier Enter'
    [void](Watch-UntilEnter '5 toggles')

    # S4: Rerun's form, foreign pairs first and GpuPreference=2; appended.
    $rerunForm = 'AutoHDREnable=1;SwapEffectUpgradeEnable=1;GpuPreference=2;'
    $k = $hkcu.CreateSubKey($keyPath)
    $k.SetValue($probe, $rerunForm, [Microsoft.Win32.RegistryValueKind]::String)
    $k.Close()
    Record '6 written by the script (Rerun form)' (Read-Probe)
    Start-Process 'ms-settings:display-advancedgraphics'
    Show '6/6' 'Einstellungen neu geoeffnet: App anklicken, GPU-Einstellung auf "Energiesparmodus" stellen'
    $v = Watch '6 after the change in Settings' { param($v) Has-Pref $v 1 }
    $results['6 Settings reads Rerun form and writes GpuPreference=1'] = $null -ne $v
    if ($null -ne $v) {
        $results['6 foreign pairs kept (AutoHDREnable, SwapEffectUpgradeEnable)'] =
            ($v.Data -match '(^|;)AutoHDREnable=1;') -and ($v.Data -match '(^|;)SwapEffectUpgradeEnable=1;')
        $results['6 value kind REG_SZ'] = $v.Kind -eq 'String'
    }
} catch {
    $log.Add("ERROR: $($_.Exception.Message)")
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    $host.UI.RawUI.WindowTitle = 'SB-G1: raeumt auf'
    $k = $hkcu.OpenSubKey($keyPath, $true)
    if ($null -ne $k) { $k.DeleteValue($probe, $false); $k.Close() }
    $results['cleanup: value removed'] = $null -eq (Read-Probe)
    if (-not $hadKey) {
        $k = $hkcu.OpenSubKey($keyPath)
        if ($null -ne $k -and $k.ValueCount -eq 0 -and $k.SubKeyCount -eq 0) {
            $k.Close(); $hkcu.DeleteSubKey($keyPath, $false)
        } elseif ($null -ne $k) { $k.Close() }
    }
    if (-not $hadDirectX) {
        $k = $hkcu.OpenSubKey('Software\Microsoft\DirectX')
        if ($null -ne $k -and $k.ValueCount -eq 0 -and $k.SubKeyCount -eq 0) {
            $k.Close(); $hkcu.DeleteSubKey('Software\Microsoft\DirectX', $false)
        } elseif ($null -ne $k) { $k.Close() }
    }
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
    $results['cleanup: probe folder removed'] = -not (Test-Path -LiteralPath $dir)

    $log.Add('')
    foreach ($r in $results.GetEnumerator()) {
        $log.Add("$(if ($r.Value) { 'PASS' } else { 'FAIL' }): $($r.Key)")
    }
    $text = ($log -join "`r`n").Replace($probe, $neutral).Replace($env:USERNAME, '<user>')
    Set-Content -LiteralPath $out -Value $text -Encoding UTF8
    Clear-Host
    $host.UI.RawUI.WindowTitle = 'SB-G1: fertig'
    Write-Host $text
    Write-Host ""
    Write-Host "Gespeichert: $out" -ForegroundColor Cyan
}
