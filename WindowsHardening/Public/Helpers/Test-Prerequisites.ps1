#Requires -Version 5.1

# Test-Prerequisites.ps1 - Pre-flight checks: administrator rights (required), OS and PowerShell version (warnings).

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Pre-flight checks. Throws if not running as Administrator (every hardening
        step needs it); OS and PowerShell version problems are warnings only.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n=== Pre-flight Checks ===" -ForegroundColor Cyan
    Write-Log -Level "INFO" -Message "=== Pre-flight Checks ===" -Console

    $allChecksPassed = $true

    # Check administrator privileges
    try {
        if (-not (Test-IsAdministrator)) {
            Write-Host "[FAIL] Script must be run as Administrator" -ForegroundColor Red
            Write-Log -Level "ERROR" -Message "Administrator privileges required" -Console
            $allChecksPassed = $false
        } else {
            Write-Host "[PASS] Running with Administrator privileges" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "Administrator privileges confirmed"
        }
    } catch {
        Write-Host "[FAIL] Could not verify administrator privileges" -ForegroundColor Red
        Write-Log -Level "ERROR" -Message "Could not verify administrator privileges: $($_.Exception.Message)" -Console
        $allChecksPassed = $false
    }

    # Check OS compatibility
    try {
        if (-not $script:HardeningContext.OS) {
            Write-Host "[WARN] OS not detected. OS-specific steps will be skipped." -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "OS not detected"
        } elseif ($script:HardeningContext.OS.OSVersion -eq "Unknown") {
            Write-Host "[WARN] Unknown OS version detected. Some operations may not work correctly." -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "Unknown OS version detected"
        } else {
            Write-Host "[PASS] OS detected: $($script:HardeningContext.OS.OSVersion)" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "OS detected: $($script:HardeningContext.OS.OSVersion)"
        }
    } catch {
        Write-Host "[WARN] OS detection failed" -ForegroundColor Yellow
        Write-Log -Level "WARNING" -Message "OS detection failed: $($_.Exception.Message)"
    }

    # Check PowerShell version
    try {
        $psVersion = $PSVersionTable.PSVersion
        if ($psVersion.Major -lt 3) {
            Write-Host "[WARN] PowerShell version $psVersion may not support all features" -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "PowerShell version $psVersion detected"
        } else {
            Write-Host "[PASS] PowerShell version: $psVersion" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "PowerShell version: $psVersion"
        }
    } catch {
        Write-Host "[WARN] Could not determine PowerShell version" -ForegroundColor Yellow
        Write-Log -Level "WARNING" -Message "Could not determine PowerShell version"
    }

    Write-Host "`n=== Pre-flight Checks Complete ===" -ForegroundColor Cyan
    Write-Log -Level "INFO" -Message "=== Pre-flight Checks Complete ===" -Console

    if (-not $allChecksPassed) {
        throw "Must be run as Administrator (start PowerShell with 'Run as administrator')."
    }
}
