# Dot-sourced by sandbox-run.ps1 and sandbox-cli.ps1: the one guard of the PowerShell side of
# the sandbox suite (the Rust side is sandbox_guard in sys/win/testfx.rs). Nothing here writes.
#
# Test-SandboxGuard answers whether this process may write the real HKCU and LocalAppData:
#  - the account of the process token (not spoofable through the environment) is the Windows
#    Sandbox account WDAGUtilityAccount, or, only with -Ci, one of the two accounts of the
#    disposable GitHub-hosted runner (runneradmin, and rerunci, the standard user that
#    scripts/ci-sandbox.ps1 creates for the non-elevated pass);
#  - USERNAME and USERPROFILE name that same account;
#  - the script itself runs from the mapped (Sandbox) or staged (CI) folder C:\sandbox\scripts;
#  - with -Ci also the marker C:\sandbox\ci-host.txt, written by ci-sandbox.ps1 (it checks
#    GITHUB_ACTIONS=true and RUNNER_ENVIRONMENT=github-hosted first). The marker states intent; it is
#    no lock (any user may create a folder in C:\). The lock is the account of the process token.

function Test-SandboxGuard {
    param(
        [Parameter(Mandatory = $true)][string]$Script,
        [Parameter(Mandatory = $true)][string]$Expected,
        [bool]$Ci = $false
    )
    $tokenUser = ([Security.Principal.WindowsIdentity]::GetCurrent().Name -split '\\')[-1]
    $accounts = @('WDAGUtilityAccount')
    if ($Ci) {
        $marker = 'C:\sandbox\ci-host.txt'
        if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) { return $false }
        if ((Get-Content -LiteralPath $marker -Raw).Trim() -ne 'github-hosted-runner') { return $false }
        $accounts += 'runneradmin', 'rerunci'
    }
    return ($accounts -contains $tokenUser -and $env:USERNAME -eq $tokenUser -and
        $env:USERPROFILE -match ('\\' + [regex]::Escape($tokenUser) + '\\?$') -and $Script -eq $Expected)
}

# The UAC policy of this machine (read only), so that a result that depends on it (UAC file
# virtualization, the shape of an elevation prompt) can be read later. A missing value is $null.
# EnableVirtualization is the policy value of the same name (absent = the default, on).
function Get-UacState {
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $p = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
    [ordered]@{
        EnableLUA                  = if ($p) { $p.EnableLUA } else { $null }
        ConsentPromptBehaviorAdmin = if ($p) { $p.ConsentPromptBehaviorAdmin } else { $null }
        PromptOnSecureDesktop      = if ($p) { $p.PromptOnSecureDesktop } else { $null }
        EnableVirtualization       = if ($p) { $p.EnableVirtualization } else { $null }
    }
}
