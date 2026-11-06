# Windows Sandbox helper for SB-L1 (manual): dumps the Layers values of HKCU, both registry
# views, to C:\sandbox\out\layers-<label>.txt, so the Explorer compatibility tab's output can
# be compared before and after. Reads only; Sandbox only.
#
#   powershell -File C:\sandbox\scripts\sandbox-layers-dump.ps1 before
#   (set options in the file's Properties > Compatibility tab, OK)
#   powershell -File C:\sandbox\scripts\sandbox-layers-dump.ps1 after
param([Parameter(Mandatory)][string]$Label, [string]$Out = 'C:\sandbox\out')

$ErrorActionPreference = 'Stop'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or $env:USERPROFILE -notmatch '\\WDAGUtilityAccount\\?$') {
    Write-Error 'refusing to run: Windows Sandbox only'
    exit 2
}
if ($Label -notmatch '^[A-Za-z0-9_.-]+$') {
    Write-Error 'the label may hold letters, digits, _ . - only'
    exit 2
}

# Native stderr is merged as plain text (5.1 throws on redirected stderr under 'Stop').
function Run-Native {
    $ErrorActionPreference = 'Continue'
    $cmd = $args[0]
    $rest = @($args | Select-Object -Skip 1)
    & $cmd @rest 2>&1 | ForEach-Object { "$_" }
}

$layers = 'HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers'
$build = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
$lines = @("label: $Label", "time: $(Get-Date -Format o)", "build: $build")
foreach ($view in '64', '32') {
    $lines += ''
    $lines += "--- HKCU Layers, /reg:$view"
    $lines += (Run-Native reg.exe query $layers "/reg:$view" | Out-String).TrimEnd()
}
$lines += ''
$lines += '--- raw data, one value per line, quoted (spelling, spacing, case, order)'
$k = Get-Item -LiteralPath 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers' -ErrorAction SilentlyContinue
if ($k) {
    foreach ($n in $k.GetValueNames()) { $lines += ('"{0}" = "{1}"' -f $n, $k.GetValue($n)) }
} else {
    $lines += '<key absent>'
}
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$lines | Set-Content -LiteralPath (Join-Path $Out "layers-$Label.txt") -Encoding UTF8
$lines | ForEach-Object { Write-Host $_ }
