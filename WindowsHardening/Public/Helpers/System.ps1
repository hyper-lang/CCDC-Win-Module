#Requires -Version 5.1

# System.ps1 - Initialize-System, the module's single setup path: OS detection,
# logging, and context (required files, DC status). Idempotent, so every hardening
# step can call it (via Invoke-HardeningOperation) when run on its own.

function Initialize-System {
    <#
    .SYNOPSIS
        Detects the OS, starts a log file, and initializes the hardening context.
    .DESCRIPTION
        Runs once per session. Later calls return immediately unless -Force is given.
    .PARAMETER Force
        Re-run initialization (new log file, fresh operation counters).
    .PARAMETER LogPath
        Log directory, passed to Start-HardeningLog. Default: C:\Windows\Logs\Hardening.
    #>
    [CmdletBinding()]
    param(
        [switch]$Force,

        [string]$LogPath
    )

    if ($script:HardeningContext.Initialized -and -not $Force) {
        return
    }

    Write-Host "`nInitializing system..." -ForegroundColor Cyan

    # Set before Initialize-Context runs: it executes inside Invoke-HardeningOperation,
    # which calls Initialize-System whenever this flag is unset.
    $script:HardeningContext.Initialized = $true

    try {
        try {
            $script:HardeningContext.OS = Get-OperatingSystemInfo
        } catch {
            $script:HardeningContext.OS = $null
            Write-Host "[WARN] OS detection failed; OS-specific steps will be skipped: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        Start-HardeningLog -LogPath $LogPath
        Reset-OperationStatus
        Initialize-Context

        Write-Host "Initialization complete" -ForegroundColor Green
    } catch {
        $script:HardeningContext.Initialized = $false
        Write-Host "Initialization failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log -Level "ERROR" -Message "System initialization failed: $($_.Exception.Message)" -Console
        throw "System initialization failed: $($_.Exception.Message)"
    }
}
