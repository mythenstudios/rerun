# [DEV] observation of a game's first start on the developer machine, without Rerun
# (P4-13 inventory session S1; docs/09-testing.md).
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\dev-first-start.ps1 -GameFolder "D:\SteamLibrary\steamapps\common\Game" -GameExe game.exe
#
# Optional: -UserDataFolder "<folder name below Documents>" -IniFile AC.ini (reports the INI the
# game writes: section headers and key names with values), -WaitMinutes 20, -OutDir <folder>
# (default: .dev\s1 in the repository, which is never committed).
#
# What it does, without a single question (the current instruction is in the window title):
#  1. remembers which processes run now, then asks you (window title) to start the game in Steam;
#  2. records every new process whose image lies in the game folder, below Steam or below
#     Ubisoft Connect, with its parent (name and image path, never the command line: launchers
#     pass sign-in tokens there), its start time and, while it runs, its affinity mask;
#  3. once the game executable ran and has ended (or after -WaitMinutes), it records how long the
#     game ran, lists what is below <Documents>\<UserDataFolder> and the keys of the INI file;
#  4. writes the report to <OutDir>\<exe>-<time>.txt and copies it to the clipboard.
#
# It changes nothing: no registry, no file outside <OutDir>, no Steam setting. Run it in a normal
# (not administrator) PowerShell window, not through "!" in the chat.

param(
    [Parameter(Mandatory = $true)][string]$GameFolder,
    [Parameter(Mandatory = $true)][string]$GameExe,
    [string]$UserDataFolder,
    [string]$IniFile,
    [ValidateRange(1, 120)][int]$WaitMinutes = 20,
    [string]$OutDir
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $OutDir) { $OutDir = Join-Path $repo '.dev\s1' }

function Title([string]$text) {
    $Host.UI.RawUI.WindowTitle = "Rerun DEV - $text"
    Write-Host ''
    Write-Host ">> $text" -ForegroundColor Cyan
}

function Fail([string]$text) {
    Title "STOPPED: $text"
    throw $text
}

# Self-check of the inputs before anything is observed.
if (-not (Test-Path -LiteralPath $GameFolder -PathType Container)) { Fail "game folder not found: $GameFolder" }
$GameFolder = (Resolve-Path -LiteralPath $GameFolder).Path.TrimEnd('\')
if ($GameExe -match '[\\/]') { Fail '-GameExe is a file name only (e.g. game.exe)' }
$exeHits = @(Get-ChildItem -LiteralPath $GameFolder -Recurse -Filter $GameExe -File -ErrorAction SilentlyContinue)
if ($exeHits.Count -eq 0) { Fail "$GameExe not found below $GameFolder" }
if ($IniFile -and -not $UserDataFolder) { Fail '-IniFile needs -UserDataFolder' }

$docs = [Environment]::GetFolderPath('MyDocuments')
$roots = @($GameFolder)
$steam = (Get-ItemProperty -Path 'HKCU:\Software\Valve\Steam' -Name SteamPath -ErrorAction SilentlyContinue).SteamPath
if ($steam) { $roots += ($steam -replace '/', '\').TrimEnd('\') }
foreach ($upc in @("${env:ProgramFiles(x86)}\Ubisoft\Ubisoft Game Launcher", "$env:ProgramFiles\Ubisoft\Ubisoft Game Launcher")) {
    if (Test-Path -LiteralPath $upc) { $roots += $upc }
}

function Under-Roots([string]$path) {
    if (-not $path) { return $false }
    foreach ($r in $roots) {
        if ($path.StartsWith($r + '\', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

$userDataBefore = $null
if ($UserDataFolder) {
    $udPath = Join-Path $docs $UserDataFolder
    $userDataBefore = Test-Path -LiteralPath $udPath
}

$known = @{}
foreach ($p in Get-CimInstance Win32_Process) { $known[[int]$p.ProcessId] = $true }

$seen = [ordered]@{}      # "pid" (string: an int key would index by position) -> record
$gameRan = $false
$gameGoneAt = $null
$deadline = (Get-Date).AddMinutes($WaitMinutes)

Title "START THE GAME IN STEAM NOW ($GameExe), reproduce the problem, then quit the game"

while ((Get-Date) -lt $deadline) {
    $procs = @(Get-CimInstance Win32_Process)
    $byPid = @{}
    foreach ($p in $procs) { $byPid[[int]$p.ProcessId] = $p }
    foreach ($p in $procs) {
        $id = [int]$p.ProcessId
        if ($known.ContainsKey($id) -or $seen.Contains("$id")) { continue }
        if (-not (Under-Roots $p.ExecutablePath)) { $known[$id] = $true; continue }
        $parent = $byPid[[int]$p.ParentProcessId]
        $seen["$id"] = [ordered]@{
            Name       = $p.Name
            Image      = $p.ExecutablePath
            Parent     = if ($parent) { "$($parent.Name) ($($parent.ExecutablePath))" } else { "pid $($p.ParentProcessId) (already ended)" }
            Started    = $p.CreationDate
            Ended      = $null
            Affinity   = $null
        }
    }
    $gameAlive = $false
    foreach ($key in @($seen.Keys)) {
        $id = [int]$key
        $rec = $seen[$key]
        if ($rec.Ended) { continue }
        if (-not $byPid.ContainsKey($id)) { $rec.Ended = Get-Date; continue }
        if (-not $rec.Affinity) {
            try { $rec.Affinity = '0x{0:X}' -f (Get-Process -Id $id -ErrorAction Stop).ProcessorAffinity.ToInt64() } catch { $rec.Affinity = 'unreadable' }
        }
        if ($rec.Name -ieq $GameExe) { $gameAlive = $true; $gameRan = $true }
    }
    if ($gameRan -and -not $gameAlive) {
        if (-not $gameGoneAt) { $gameGoneAt = Get-Date; Title 'GAME ENDED - waiting 10 s for launchers to settle' }
        if (((Get-Date) - $gameGoneAt).TotalSeconds -ge 10) { break }
    } elseif ($gameAlive) {
        $gameGoneAt = $null
        Title "GAME RUNNING - reproduce the problem, then quit the game"
    }
    Start-Sleep -Milliseconds 500
}

# Report.
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("Rerun DEV first start - $GameExe - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$lines.Add("game folder: $GameFolder")
$lines.Add("OS build: $([Environment]::OSVersion.Version); logical processors: $([Environment]::ProcessorCount)")
if (-not $gameRan) { $lines.Add("RESULT: $GameExe never ran within $WaitMinutes min") }
$lines.Add('')
$lines.Add('processes (in start order):')
foreach ($key in $seen.Keys) {
    $r = $seen[$key]
    $life = if ($r.Ended -and $r.Started) { '{0:N1} s' -f ($r.Ended - $r.Started).TotalSeconds } else { 'still running or unknown' }
    $rel = $r.Image
    if ($rel -and $rel.StartsWith($GameFolder + '\', [StringComparison]::OrdinalIgnoreCase)) { $rel = '<game>\' + $rel.Substring($GameFolder.Length + 1) }
    $lines.Add("- $($r.Name)  image: $rel")
    $lines.Add("    parent: $($r.Parent)")
    $lines.Add("    started: $($r.Started.ToString('HH:mm:ss.fff'))  lifetime: $life  affinity: $($r.Affinity)")
}
if ($UserDataFolder) {
    $lines.Add('')
    $udPath = Join-Path $docs $UserDataFolder
    $lines.Add("user data <Documents>\$UserDataFolder : existed before: $userDataBefore, exists now: $(Test-Path -LiteralPath $udPath)")
    if (Test-Path -LiteralPath $udPath) {
        foreach ($f in Get-ChildItem -LiteralPath $udPath -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 40) {
            $lines.Add("  $($f.FullName.Substring($udPath.Length + 1))  ($($f.Length) bytes)")
        }
        if ($IniFile) {
            $ini = Join-Path $udPath $IniFile
            if (Test-Path -LiteralPath $ini) {
                $lines.Add("$IniFile sections and keys:")
                foreach ($l in Get-Content -LiteralPath $ini -TotalCount 400) {
                    $t = $l.Trim()
                    if ($t -match '^\[.*\]$' -or $t -match '^[^;#=]+=') { $lines.Add("  $t") }
                }
            } else {
                $lines.Add("$IniFile : not found")
            }
        }
    }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$out = Join-Path $OutDir ("{0}-{1}.txt" -f [IO.Path]::GetFileNameWithoutExtension($GameExe), (Get-Date -Format 'yyyyMMdd-HHmmss'))
$text = $lines -join "`r`n"
Set-Content -LiteralPath $out -Value $text -Encoding UTF8
Set-Clipboard -Value $text
Write-Host $text
Title "DONE - report saved to $out and copied; report what you saw"
