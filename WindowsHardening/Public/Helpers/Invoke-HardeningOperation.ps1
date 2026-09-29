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

        [string]$ProgressMessage = ""
    )

    Initialize-System

    $script:OperationResults.Total++

    # Check OS compatibility
    if ($OSCompatibility.Count -gt 0) {
        if ($script:HardeningContext.OS.OSFamily -notin $OSCompatibility) {
            $message = "[SKIPPED] Operation '$OperationName' is not compatible with $($script:HardeningContext.OS.OSVersion) (OS Family: $($script:HardeningContext.OS.OSFamily))"
            Write-Host $message -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message $message -Console
            $script:OperationResults.Skipped++
            $script:OperationResults.Warnings += $message
            Set-OperationStatus $OperationName "Skipped - OS incompatible ($($script:HardeningContext.OS.OSFamily))"
            return
        }
    }

    try {
        Write-Host "`n[EXECUTING] $OperationName..." -ForegroundColor Cyan
        if ($ProgressMessage) {
            Write-Host "[INFO] $ProgressMessage" -ForegroundColor White
        }
        Write-Log -Level "INFO" -Message "Starting operation: $OperationName" -Console
        if ($script:HardeningContext.OS) {
            Write-Host "[INFO] Applying configuration for $($script:HardeningContext.OS.OSVersion)..." -ForegroundColor DarkGray
        }

        & $ScriptBlock

        $message = "[SUCCESS] $OperationName completed successfully"
        Write-Host $message -ForegroundColor Green
        Write-Log -Level "SUCCESS" -Message $message -Console
        $script:OperationResults.Successful++
        Set-OperationStatus $OperationName "Executed successfully"

    } catch {
        $errorMessage = "[FAILED] $OperationName : $($_.Exception.Message)"
        Write-Host $errorMessage -ForegroundColor Red
        Write-Host "[ERROR DETAILS] Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor DarkRed
        if ($_.Exception.InnerException) {
            Write-Host "[ERROR DETAILS] Inner Exception: $($_.Exception.InnerException.Message)" -ForegroundColor DarkRed
        }
        Write-Log -Level "ERROR" -Message $errorMessage -Console
        Write-Log -Level "ERROR" -Message "Exception Type: $($_.Exception.GetType().FullName)"
        if ($_.Exception.InnerException) {
            Write-Log -Level "ERROR" -Message "Inner Exception: $($_.Exception.InnerException.Message)"
        }

        $script:OperationResults.Failed++
        Set-OperationStatus $OperationName "Failed with error: $($_.Exception.Message)"
    }
}
