#Requires -Version 5.1

# Test-Prerequisites.ps1 - Pre-flight checks: administrator rights (required), OS and PowerShell version (warnings).

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Pre-flight checks. Throws if not running as Administrator (every hardening
        step needs it); OS and PowerShell version problems are warnings only.
    #>
    [CmdletBinding()]
    param([object]$State = $null)

    if (-not $State) { $State = Resolve-HardeningState -State $State }
    Write-Banner "Pre-flight Checks" -Style Inline -Log -State $State

    $allChecksPassed = $true

    # Check administrator privileges
    try {
        if (-not (Test-IsAdministrator)) {
            Write-Status -Level Error "Script must be run as Administrator" -LogMessage "Administrator privileges required" -State $State
            $allChecksPassed = $false
        } else {
            Write-Status -Level Success "Running with Administrator privileges" -LogMessage "Administrator privileges confirmed" -State $State
        }
    } catch {
        Write-Status -Level Error "Could not verify administrator privileges" -LogMessage "Could not verify administrator privileges: $($_.Exception.Message)" -State $State
        $allChecksPassed = $false
    }

    # Check OS compatibility
    try {
        if (-not $State.Context.OS) {
            Write-Status -Level Warning "OS not detected. OS-specific steps will be skipped." -LogMessage "OS not detected" -State $State
        } elseif ($State.Context.OS.OSVersion -eq "Unknown") {
            Write-Status -Level Warning "Unknown OS version detected. Some operations may not work correctly." -LogMessage "Unknown OS version detected" -State $State
        } else {
            Write-Status -Level Success "OS detected: $($State.Context.OS.OSVersion)" -State $State
        }
    } catch {
        Write-Status -Level Warning "OS detection failed" -LogMessage "OS detection failed: $($_.Exception.Message)" -State $State
    }

    # Check PowerShell version
    try {
        $psVersion = $PSVersionTable.PSVersion
        if ($psVersion.Major -lt 3) {
            Write-Status -Level Warning "PowerShell version $psVersion may not support all features" -LogMessage "PowerShell version $psVersion detected" -State $State
        } else {
            Write-Status -Level Success "PowerShell version: $psVersion" -State $State
        }
    } catch {
        Write-Status -Level Warning "Could not determine PowerShell version" -State $State
    }

    Write-Banner "Pre-flight Checks Complete" -Style Inline -Log -State $State

    if (-not $allChecksPassed) {
        throw "Must be run as Administrator (start PowerShell with 'Run as administrator')."
    }
}
