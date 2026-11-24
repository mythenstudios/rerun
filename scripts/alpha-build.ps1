# Builds the unsigned per-user alpha of Rerun into dist\ (P5-13c, ADR 0030). Windows PowerShell
# 5.1, in a normal (not administrator) 64-bit PowerShell window, from the repository:
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\alpha-build.ps1 -Key <private key file>
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\alpha-build.ps1 -NoIndex
#
# -Key is for the developer alone, with the private release key from his offline storage (the
# stick). The key file is read by rerun-workbench only (which refuses a key inside a Git working
# tree or a OneDrive folder); it is never copied, printed or kept. AN AUTOMATED AGENT NEVER RUNS
# THIS SCRIPT WITH -Key, and never generates or reads a release key.
# -NoIndex builds a test payload without the signed index (for checks of the scripts, never for
# real use: the app then shows "no index"). One of the two is required; without either the
# script stops before building anything.
#
# Steps (each named in the window title):
#  1. Checks: not elevated, 64-bit; the version in Cargo.toml is 0.1.0-alpha.N; with -Key the
#     tracked sources (crates, Cargo.*, topos, packages, packaging, this script) are committed
#     and a release key is compiled in (catalog/key.rs RELEASE_KEYS; until P5-13a the slots are
#     empty and the release rerun.exe would refuse every index, so -Key stops here).
#  2. Release builds with the real `release` profile (never dev-release, never the test key), one
#     `cargo build -p` per binary as in CI (no feature unification), RERUN_BUILD_ID = the commit
#     (with "-dirty" for a test payload from uncommitted sources), and the Smart-App-Control-safe
#     source replacement .dev\sac-build\sac.toml. Output with "os error 4551" (Smart App Control)
#     stops the script; it never tries to get around it.
#  3. Hardening of exactly these binaries: the hardening tests of rerun-cli, rerun-launch and
#     rerun-app with RERUN_RELEASE_*_EXE pointing at them (as in CI: /DEPENDENTLOADFLAG:0x800,
#     the import lists, the asInvoker manifest, no index test key, no index-test folder or
#     test-key banner), `cargo tree` shows neither rerun-core/fake nor rerun-core/test-key in
#     rerun-cli and rerun-app, and `rerun.exe --version` names the version.
#  4. -Key only: rerun-workbench (built without the feature test-key) builds index.json from
#     topos\ and packages\ with seq = the Unix time and signs it with the key; the key ID it
#     prints must be one of RELEASE_KEYS and seq at least elevate::HELPER_MIN_SEQ.
#  5. The payload folder dist\rerun-<version>-<commit>[-dirty][-noindex]\: rerun-app.exe,
#     rerun.exe, rerun-launch.exe (no rerun-helper.exe, no rerun-cpu.asi, no rerun-workbench),
#     LICENSE, THIRD-PARTY-NOTICES.txt, README.txt, the signed index pair (-Key), payload.json
#     (every file with its size and SHA-256), then <folder>-portable.zip (the folder as it is)
#     and SHA256SUMS.txt; both checked against payload.json byte for byte.
#
# What it writes: target\ (the builds) and dist\ (gitignored). An earlier payload of the same
# name is replaced. Nothing outside the repository: no install, no import, no registry.

[CmdletBinding()]
param(
    [string]$Key = '',
    [switch]$NoIndex
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$script:Title = 'Rerun alpha build'
$sacToml = Join-Path $repo '.dev\sac-build\sac.toml'
$release = Join-Path $repo 'target\release'
$dist = Join-Path $repo 'dist'
# The files of the payload from the repository (name in the payload -> source), besides the
# binaries and the index.
$repoFiles = [ordered]@{
    'LICENSE'                 = (Join-Path $repo 'LICENSE')
    'THIRD-PARTY-NOTICES.txt' = (Join-Path $repo 'crates\rerun-app\assets\THIRD-PARTY-NOTICES.txt')
    'README.txt'              = (Join-Path $repo 'packaging\windows\README.txt')
}
$binaries = @(
    @{ Package = 'rerun-launch'; File = 'rerun-launch.exe'; Env = 'RERUN_RELEASE_LAUNCH_EXE' },
    @{ Package = 'rerun-cli'; File = 'rerun.exe'; Env = 'RERUN_RELEASE_CLI_EXE' },
    @{ Package = 'rerun-app'; File = 'rerun-app.exe'; Env = 'RERUN_RELEASE_APP_EXE' }
)
# One segment of a payload file name (ADR 0030): install.ps1 and uninstall.ps1 check the same rule.
$nameRule = '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'

function Title([string]$text) {
    $Host.UI.RawUI.WindowTitle = "$script:Title - $text"
    Write-Host ''
    Write-Host ">> $text" -ForegroundColor Cyan
}

function Fail([string]$text) {
    Title "STOPPED: $text"
    throw $text
}

function Sha256-File([string]$path) {
    $fs = [IO.File]::Open($path, 'Open', 'Read', 'Read')
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($sha.ComputeHash($fs)) -replace '-', '').ToLowerInvariant() } finally { $sha.Dispose() }
    } finally { $fs.Dispose() }
}

function Is-Link([string]$path) {
    return (Test-Path -LiteralPath $path) -and [bool]((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)
}

function Quote-Arg([string]$a) {
    if ($a -match '^[A-Za-z0-9_.:/\\=@+-]+$') { return $a }
    if ($a.Contains('"') -or $a.EndsWith('\')) { Fail "refusing an argument: $a" }
    return '"' + $a + '"'
}

# Runs a program (no shell), returns its exit code and output. A start Smart App Control blocks
# (Win32 error 4551) stops the script.
function Invoke-Exe([string]$exe, [string[]]$arguments) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = (@($arguments | ForEach-Object { Quote-Arg $_ }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = $repo
    try { $p = [Diagnostics.Process]::Start($psi) }
    catch {
        $w = $_.Exception
        while ($w -and -not ($w -is [ComponentModel.Win32Exception])) { $w = $w.InnerException }
        if ($w -and $w.NativeErrorCode -eq 4551) {
            Fail "Smart App Control blocked $exe (os error 4551). Nothing was bypassed; stop here and report it"
        }
        throw
    }
    try {
        $o = $p.StandardOutput.ReadToEndAsync()
        $e = $p.StandardError.ReadToEndAsync()
        $p.WaitForExit()
        return @{ Code = $p.ExitCode; Out = $o.Result; Err = $e.Result }
    } finally { $p.Dispose() }
}

# cargo with the given arguments from the repository, its output shown and kept; os error 4551
# anywhere in it stops the script.
function Invoke-Cargo([string]$what, [string[]]$arguments) {
    Push-Location $repo
    try {
        $ErrorActionPreference = 'Continue'
        $lines = New-Object System.Collections.Generic.List[string]
        & cargo @arguments 2>&1 | ForEach-Object {
            $l = "$_"
            $lines.Add($l)
            Write-Host $l
        }
        $code = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
    } finally { Pop-Location }
    $text = $lines -join "`n"
    if ($text -match 'os error 4551') {
        Fail "Smart App Control blocked a step of $what (os error 4551). Nothing was bypassed; stop here and report it"
    }
    if ($code -ne 0) { Fail "$what failed (cargo exit $code)" }
    return $text
}

# The key IDs of the release slots compiled into rerun-core (catalog/key.rs RELEASE_KEYS): the
# first 8 bytes of SHA-256 over each 32-byte public key, as rerun-workbench prints them.
function Get-ReleaseKeyIds {
    $src = [IO.File]::ReadAllText((Join-Path $repo 'crates\rerun-core\src\catalog\key.rs'))
    $m = [regex]::Match($src, 'pub const RELEASE_KEYS: \[Option<\[u8; 32\]>; 2\] =([^;]*);')
    if (-not $m.Success) { Fail 'RELEASE_KEYS not found in crates\rerun-core\src\catalog\key.rs' }
    $ids = @()
    foreach ($k in [regex]::Matches($m.Groups[1].Value, 'Some\(\[([^\]]*)\]\)')) {
        $bytes = @([regex]::Matches($k.Groups[1].Value, '0x([0-9a-fA-F]{2})') | ForEach-Object { [Convert]::ToByte($_.Groups[1].Value, 16) })
        if ($bytes.Count -ne 32) { Fail 'a RELEASE_KEYS slot is not 32 bytes' }
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $h = $sha.ComputeHash([byte[]]$bytes) } finally { $sha.Dispose() }
        $ids += (([BitConverter]::ToString($h, 0, 8)) -replace '-', '').ToLowerInvariant()
    }
    return , $ids
}

function Get-HelperMinSeq {
    $src = [IO.File]::ReadAllText((Join-Path $repo 'crates\rerun-core\src\elevate\mod.rs'))
    $m = [regex]::Match($src, 'pub const HELPER_MIN_SEQ: u64 = ([0-9_]+);')
    if (-not $m.Success) { Fail 'HELPER_MIN_SEQ not found in crates\rerun-core\src\elevate\mod.rs' }
    return [uint64]($m.Groups[1].Value -replace '_', '')
}

$exitCode = 1
try {
    # ---------- 1. checks ----------
    Title 'CHECKING (nothing is built yet)'
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Fail 'start this script from a normal (not administrator) PowerShell'
    }
    if (-not [Environment]::Is64BitProcess) { Fail 'start it from a 64-bit PowerShell' }
    if ($Key -and $NoIndex) { Fail '-Key and -NoIndex do not go together' }
    if (-not $Key -and -not $NoIndex) {
        Fail 'nothing built: pass -Key <private release key file> (the developer, with the key from his offline storage; never an automated agent), or -NoIndex for a test payload without the signed index'
    }
    foreach ($x in @($sacToml, (Join-Path $repo 'Cargo.toml'))) {
        if (-not (Test-Path -LiteralPath $x -PathType Leaf)) { Fail "not found: $x" }
    }
    foreach ($n in $repoFiles.Keys) {
        if (-not (Test-Path -LiteralPath $repoFiles[$n] -PathType Leaf)) { Fail "not found: $($repoFiles[$n])" }
    }
    $cargoToml = [IO.File]::ReadAllText((Join-Path $repo 'Cargo.toml'))
    $vm = [regex]::Match($cargoToml, '(?ms)^\[workspace\.package\]\r?\n(?:#[^\n]*\n)*version = "([^"]+)"')
    if (-not $vm.Success) { Fail 'the version of [workspace.package] not found in Cargo.toml' }
    $version = $vm.Groups[1].Value
    if ($version -notmatch '^0\.1\.0-alpha\.[1-9][0-9]*$') { Fail "the version is $version, not 0.1.0-alpha.N (Cargo.toml)" }

    Push-Location $repo
    try {
        $ErrorActionPreference = 'Continue'
        $commit = (& git rev-parse HEAD 2>$null | Out-String).Trim()
        $dirty = (& git status --porcelain --untracked-files=all -- crates Cargo.toml Cargo.lock topos packages packaging scripts/alpha-build.ps1 2>$null | Out-String).Trim()
        $ErrorActionPreference = 'Stop'
    } finally { Pop-Location }
    if ($commit -notmatch '^[0-9a-f]{40}$') { Fail 'not a Git checkout (git rev-parse HEAD)' }
    $buildId = $commit
    if ($dirty) {
        if ($Key) { Fail "uncommitted changes in the sources; commit them before a signed build:`n$dirty" }
        $buildId = "$commit-dirty"
        Write-Host "note: uncommitted changes in the sources; the build ID is $buildId" -ForegroundColor Yellow
    }

    $releaseIds = Get-ReleaseKeyIds
    $minSeq = Get-HelperMinSeq
    if ($Key) {
        if ($releaseIds.Count -eq 0) {
            Fail 'no release key is compiled in (RELEASE_KEYS in crates\rerun-core\src\catalog\key.rs is empty, P5-13a not done): the release rerun.exe would refuse the signed index'
        }
        $Key = [IO.Path]::GetFullPath($Key)
        if (-not (Test-Path -LiteralPath $Key -PathType Leaf)) { Fail "-Key: not a file: $Key" }
        if ($Key.StartsWith($repo.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { Fail '-Key: the private key must never be inside the repository' }
    }

    $short = $commit.Substring(0, 12)
    $name = "rerun-$version-$short"
    if ($dirty) { $name += '-dirty' }
    if ($NoIndex) { $name += '-noindex' }
    $out = Join-Path $dist $name
    $zip = Join-Path $dist "$name-portable.zip"
    foreach ($p in @($dist, $out)) { if (Is-Link $p) { Fail "refusing: $p is a reparse point" } }

    Write-Host ''
    Write-Host 'What this run writes:' -ForegroundColor Yellow
    Write-Host "  - release builds into $release (rerun-launch, rerun-cli, rerun-app; build ID $buildId)"
    Write-Host "  - test builds into $repo\target\ci (the hardening tests$(if ($Key) { ', rerun-workbench' }))"
    if ($Key) { Write-Host "  - the index, signed with the key in $Key (read by rerun-workbench only, never copied)" }
    else { Write-Host '  - no index (-NoIndex): a test payload, never for real use' -ForegroundColor Yellow }
    Write-Host "  - $out, $zip and $dist\SHA256SUMS.txt (an earlier payload of this name is replaced)"
    Write-Host '  - nothing else: nothing is installed or imported, no registry, nothing outside the repository'

    # ---------- 2. release builds ----------
    $oldBuildId = $env:RERUN_BUILD_ID
    $env:RERUN_BUILD_ID = $buildId
    try {
        foreach ($b in $binaries) {
            Title "BUILDING $($b.File) (release; the app takes several minutes)"
            Invoke-Cargo "the build of $($b.Package)" @('build', '-p', $b.Package, '--release', '--locked', '--config', $sacToml) | Out-Null
            $b.Path = Join-Path $release $b.File
            if (-not (Test-Path -LiteralPath $b.Path -PathType Leaf)) { Fail "not built: $($b.Path)" }
        }
    } finally { $env:RERUN_BUILD_ID = $oldBuildId }

    # ---------- 3. hardening ----------
    Title 'CHECKING the hardening of exactly these binaries'
    foreach ($p in @('rerun-cli', 'rerun-app')) {
        $tree = Invoke-Cargo "cargo tree of $p" @('tree', '-p', $p, '-e', 'normal,build,features', '-i', 'rerun-core', '--locked', '--config', $sacToml)
        foreach ($f in @('fake', 'test-key')) {
            if ($tree -match "feature `"$f`"") { Fail "$p enables rerun-core/$f" }
        }
    }
    $saved = @{}
    foreach ($b in $binaries) { $saved[$b.Env] = [Environment]::GetEnvironmentVariable($b.Env, 'Process'); [Environment]::SetEnvironmentVariable($b.Env, $b.Path, 'Process') }
    try {
        $t = Invoke-Cargo 'the hardening tests' @('test', '--profile', 'ci', '--locked', '--config', $sacToml, '-p', 'rerun-cli', '-p', 'rerun-launch', '-p', 'rerun-app', '--test', 'hardening', '--', '--nocapture')
    } finally {
        foreach ($b in $binaries) { [Environment]::SetEnvironmentVariable($b.Env, $saved[$b.Env], 'Process') }
    }
    if ($t -match 'not set: release binary not checked') { Fail 'a hardening test did not check the release binary' }
    foreach ($b in $binaries) {
        $text = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($b.Path))
        if ($text.Contains('TEST-KEY BUILD') -or $text.Contains('index-test')) { Fail "$($b.File) holds a test-key marker" }
    }
    $cli = ($binaries | Where-Object { $_.File -eq 'rerun.exe' }).Path
    $r = Invoke-Exe $cli @('--version')
    if ($r.Code -ne 0 -or $r.Out.Trim() -ne "rerun $version") { Fail "rerun.exe --version: exit $($r.Code), '$($r.Out.Trim())' (expected 'rerun $version')" }

    # ---------- 4. the signed index (-Key only) ----------
    $staging = Join-Path $dist ".staging-$name"
    if (Is-Link $staging) { Fail "refusing: $staging is a reparse point" }
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    $index = $null
    if ($Key) {
        Title 'BUILDING the index (rerun-workbench, without the test key)'
        Invoke-Cargo 'the build of rerun-workbench' @('build', '-p', 'rerun-workbench', '--profile', 'ci', '--locked', '--config', $sacToml) | Out-Null
        $workbench = Join-Path $repo 'target\ci\rerun-workbench.exe'
        $seq = [uint64][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        if ($seq -lt $minSeq) { Fail "seq $seq is below HELPER_MIN_SEQ $minSeq" }
        $issued = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        $bundle = Join-Path $staging 'index.json'
        $r = Invoke-Exe $workbench @('index', 'build', '--seq', "$seq", '--issued', $issued, '--root', $repo, $bundle)
        Write-Host $r.Out.TrimEnd()
        if ($r.Code -ne 0) { Fail "rerun-workbench index build failed ($($r.Code)): $($r.Err.Trim())" }
        Title 'SIGNING the index with the release key'
        $r = Invoke-Exe $workbench @('index', 'sign', $bundle, $Key)
        Write-Host $r.Out.TrimEnd()
        if ($r.Code -ne 0) { Fail "rerun-workbench index sign failed ($($r.Code)): $($r.Err.Trim())" }
        $sm = [regex]::Match($r.Out, ': seq (\d+), sha256 ([0-9a-f]{64}), key ([0-9a-f]{16})')
        if (-not $sm.Success) { Fail 'rerun-workbench index sign: unexpected output' }
        if ([uint64]$sm.Groups[1].Value -ne $seq) { Fail 'the signed seq is not the built one' }
        if ($releaseIds -notcontains $sm.Groups[3].Value) {
            Fail "the index was signed with key $($sm.Groups[3].Value), which is not in RELEASE_KEYS ($($releaseIds -join ', ')): the release rerun.exe would refuse it"
        }
        $index = [ordered]@{ seq = $seq; key = $sm.Groups[3].Value; sha256 = (Sha256-File $bundle) }
    }

    # ---------- 5. payload, zip, sums ----------
    Title 'WRITING the payload'
    foreach ($p in @($out, $zip)) {
        if (Test-Path -LiteralPath $p) {
            if (Is-Link $p) { Fail "refusing: $p is a reparse point" }
            Remove-Item -LiteralPath $p -Recurse -Force
        }
    }
    New-Item -ItemType Directory -Path $out -Force | Out-Null
    foreach ($b in $binaries) { Copy-Item -LiteralPath $b.Path -Destination (Join-Path $out $b.File) }
    foreach ($n in $repoFiles.Keys) { Copy-Item -LiteralPath $repoFiles[$n] -Destination (Join-Path $out $n) }
    if ($index) {
        Copy-Item -LiteralPath (Join-Path $staging 'index.json') -Destination (Join-Path $out 'index.json')
        Copy-Item -LiteralPath (Join-Path $staging 'index.json.sig') -Destination (Join-Path $out 'index.json.sig')
    }
    Remove-Item -LiteralPath $staging -Recurse -Force

    $files = @()
    foreach ($f in (Get-ChildItem -LiteralPath $out -Force | Sort-Object Name)) {
        if ($f.PSIsContainer -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint)) { Fail "not a plain file: $($f.FullName)" }
        if ($f.Name -cnotmatch $nameRule) { Fail "not a payload file name: $($f.Name)" }
        $files += [ordered]@{ name = $f.Name; size = [int64]$f.Length; sha256 = (Sha256-File $f.FullName) }
    }
    foreach ($forbidden in @('rerun-helper.exe', 'rerun-cpu.asi', 'rerun-workbench.exe')) {
        if (@($files | Where-Object { $_.name -eq $forbidden }).Count -gt 0) { Fail "$forbidden must not ship" }
    }
    $manifest = [ordered]@{
        format  = 1
        product = 'Rerun'
        version = $version
        build   = $buildId
        files   = $files
        index   = $index
    }
    $json = ($manifest | ConvertTo-Json -Depth 5) -replace "`r`n", "`n"
    [IO.File]::WriteAllText((Join-Path $out 'payload.json'), $json + "`n", (New-Object Text.UTF8Encoding($false)))

    # Self-check: the folder is exactly payload.json and its files, byte for byte.
    $read = [IO.File]::ReadAllText((Join-Path $out 'payload.json')) | ConvertFrom-Json
    $want = @($read.files | ForEach-Object { $_.name }) + @('payload.json') | Sort-Object
    $have = @(Get-ChildItem -LiteralPath $out -Force | ForEach-Object { $_.Name }) | Sort-Object
    if (($want -join '|') -ne ($have -join '|')) { Fail "the payload folder is not its manifest: $($have -join ', ')" }
    foreach ($f in $read.files) {
        $p = Join-Path $out $f.name
        if ((Get-Item -LiteralPath $p).Length -ne $f.size -or (Sha256-File $p) -ne $f.sha256) { Fail "$($f.name) is not as the manifest says" }
    }

    Title 'WRITING the portable zip'
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory($out, $zip, [IO.Compression.CompressionLevel]::Optimal, $true)
    $z = [IO.Compression.ZipFile]::OpenRead($zip)
    try {
        $entries = @($z.Entries | ForEach-Object { $_.FullName -replace '\\', '/' }) | Sort-Object
        $expect = @($have | ForEach-Object { "$name/$_" }) | Sort-Object
        if (($entries -join '|') -ne ($expect -join '|')) { Fail "the zip is not the payload folder: $($entries -join ', ')" }
        foreach ($e in $z.Entries) {
            $file = Join-Path $out (($e.FullName -replace '\\', '/').Substring($name.Length + 1))
            $s = $e.Open()
            try {
                $sha = [Security.Cryptography.SHA256]::Create()
                try { $h = ([BitConverter]::ToString($sha.ComputeHash($s)) -replace '-', '').ToLowerInvariant() } finally { $sha.Dispose() }
            } finally { $s.Dispose() }
            if ($h -ne (Sha256-File $file)) { Fail "the zip entry $($e.FullName) differs from the folder" }
        }
    } finally { $z.Dispose() }
    $sums = "$(Sha256-File $zip)  $name-portable.zip`n"
    [IO.File]::WriteAllText((Join-Path $dist 'SHA256SUMS.txt'), $sums, (New-Object Text.UTF8Encoding($false)))

    Title 'DONE'
    Write-Host ''
    Write-Host "Rerun $version (build $buildId)" -ForegroundColor Green
    Write-Host "  payload: $out"
    foreach ($f in $read.files) { Write-Host ("    {0,-26} {1,10}  {2}" -f $f.name, $f.size, $f.sha256) }
    Write-Host "  zip:     $zip"
    Write-Host "  sums:    $dist\SHA256SUMS.txt"
    if ($index) { Write-Host "  index:   seq $($index.seq), key $($index.key)" }
    else { Write-Host '  index:   none (-NoIndex test payload; the app shows "no index")' -ForegroundColor Yellow }
    Write-Host '  unsigned binaries: Smart App Control may block them at any time (README.txt)'
    $exitCode = 0
} catch {
    Write-Host ''
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
}
exit $exitCode
