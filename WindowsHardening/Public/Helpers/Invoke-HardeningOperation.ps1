#Requires -Version 5.1

# Invoke-HardeningOperation.ps1 - The runner every hardening step executes inside.

function Invoke-HardeningOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OperationName,

        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,

        [string[]]$OSCompatibility = @(),

        [object]$State = $null,

        [string]$StepLabel,

        [string]$ProgressMessage = "",

        [string[]]$TargetComputerName = @()
    )

    # StepLabel belongs to this operation call so it cannot be overwritten by
    # another operation using the same run state.
    if (-not $State) {
        $State = Resolve-HardeningState -State $State
    }
    Initialize-System -State $State
    $stepLabel = $StepLabel

    Update-HardeningCounter -State $State -Counter Total
    $operationStartedAt = [datetime]::UtcNow
    $header = if ($stepLabel) { "[$stepLabel] $OperationName" } else { "[EXECUTING] $OperationName..." }

    # Check OS compatibility
    if ($OSCompatibility.Count -gt 0) {
        if ($State.Context.OS.OSFamily -notin $OSCompatibility) {
            $message = "Operation '$OperationName' is not compatible with $($State.Context.OS.OSVersion) (OS Family: $($State.Context.OS.OSFamily))"
            Write-Host "`n$header" -ForegroundColor Cyan
            Write-Status -Level Skip $message -State $State
            Update-HardeningCounter -State $State -Counter Skipped
            Add-HardeningWarning -State $State -Warning "[SKIPPED] $message"
            Set-OperationStatus $OperationName "Skipped - OS incompatible ($($State.Context.OS.OSFamily))" -State $State
            $State.Results.Enqueue([pscustomobject]@{ Operation = $OperationName; Status = 'Skipped'; Message = $message; StartedAt = $operationStartedAt; EndedAt = [datetime]::UtcNow })
            Flush-HardeningLog -State $State
            return
        }
    }

    try {
        Write-Host "`n$header" -ForegroundColor Cyan
        Write-Status -LogOnly "Starting operation: $OperationName$(if ($stepLabel) { " ($stepLabel)" })" -State $State
        if ($ProgressMessage) {
            Write-Status $ProgressMessage -State $State
        }
        if ($TargetComputerName.Count -gt 0) {
            Write-Status "Applying configuration for $($TargetComputerName -join ', ')..." -NoLog -State $State
        } elseif ($State.Context.OS) {
            Write-Status "Applying configuration for $($State.Context.OS.OSVersion)..." -NoLog -State $State
        }

        & $ScriptBlock

        Write-Status -Level Success "$OperationName completed successfully" -State $State
        Update-HardeningCounter -State $State -Counter Successful
        Set-OperationStatus $OperationName "Executed successfully" -State $State
        $State.Results.Enqueue([pscustomobject]@{ Operation = $OperationName; Status = 'Succeeded'; Message = ''; StartedAt = $operationStartedAt; EndedAt = [datetime]::UtcNow })

    } catch [System.OperationCanceledException] {
        # A step throws OperationCanceledException when the user backs out of it (e.g. Q at
        # a prompt): that is a skip, not a failure.
        Write-Status -Level Skip "$OperationName : $($_.Exception.Message)" -State $State
        Update-HardeningCounter -State $State -Counter Skipped
        Set-OperationStatus $OperationName "Skipped - $($_.Exception.Message)" -State $State
        $State.Results.Enqueue([pscustomobject]@{ Operation = $OperationName; Status = 'Skipped'; Message = $_.Exception.Message; StartedAt = $operationStartedAt; EndedAt = [datetime]::UtcNow })
    } catch {
        Write-Status -Level Error "$OperationName : $($_.Exception.Message)" -State $State
        Write-Status -Level Error -Tag 'ERROR DETAILS' "Exception Type: $($_.Exception.GetType().FullName)" -State $State
        if ($_.Exception.InnerException) {
            Write-Status -Level Error -Tag 'ERROR DETAILS' "Inner Exception: $($_.Exception.InnerException.Message)" -State $State
        }

        Update-HardeningCounter -State $State -Counter Failed
        Set-OperationStatus $OperationName "Failed with error: $($_.Exception.Message)" -State $State
        $State.Results.Enqueue([pscustomobject]@{ Operation = $OperationName; Status = 'Failed'; Message = $_.Exception.Message; StartedAt = $operationStartedAt; EndedAt = [datetime]::UtcNow })
    }

    # The operation wrapper is the caller/coordinator for its nested functions:
    # drain their events only after the operation has returned. Flush is serialized
    # per state, so simultaneous wrappers cannot append to the same file at once.
    Flush-HardeningLog -State $State
}
