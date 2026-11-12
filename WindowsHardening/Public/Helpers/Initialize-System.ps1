#Requires -Version 5.1

# Initialize-System.ps1 - The module's single setup path: logging and context. Idempotent, so every
# hardening step can call it (via Invoke-HardeningOperation) when run on its own.

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

        [string]$LogPath,

        [object]$State = $null
    )

    if ($State -and $State.Context.Initialized -and -not $Force) {
        return
    }

    if (-not $State) { $State = Resolve-HardeningState -State $State }
    if ($Force) {
        $State.RunId = [guid]::NewGuid().ToString()
        $State.StartedAt = [datetime]::UtcNow
        $State.Context.Initialized = $false
        $State.Results = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
        $State.LogEvents = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
    }
    Write-Host "`nInitializing system..." -ForegroundColor Cyan

    # Set before Initialize-Context runs: it executes inside Invoke-HardeningOperation,
    # which calls Initialize-System whenever this flag is unset.
    $State.Context.Initialized = $true

    try {
        try {
            $State.Context.OS = Get-OperatingSystemInfo -State $State
        } catch {
            $State.Context.OS = $null
            Write-Status -Level Warning "OS detection failed; OS-specific steps will be skipped: $($_.Exception.Message)" -State $State
        }

        # Before Start-HardeningLog, which writes it into the log header.
        try {
            $State.Context.CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        } catch {
            $State.Context.CurrentUser = $null
        }

        Start-HardeningLog -LogPath $LogPath -State $State
        Reset-OperationStatus -State $State
        Initialize-Context -State $State

        Write-Status -Level Success "Initialization complete" -State $State
        Flush-HardeningLog -State $State
    } catch {
        $State.Context.Initialized = $false
        Write-Status -Level Error "Initialization failed: $($_.Exception.Message)" -LogMessage "System initialization failed: $($_.Exception.Message)" -State $State
        Flush-HardeningLog -State $State
        throw "System initialization failed: $($_.Exception.Message)"
    }
}
