#Requires -Version 5.1

# Log.ps1 - Log file setup, Write-Log, and the per-function execution summary.

function Start-HardeningLog {
    [CmdletBinding()]
    param(
        [string]$LogPath
    )

    if ([string]::IsNullOrEmpty($LogPath)) {
        $LogPath = $script:DefaultLogPath
    }
    $script:HardeningContext.LogPath = $LogPath

    try {
        if (-not (Test-Path $LogPath)) {
            New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
            Write-Verbose "Created log directory: $LogPath"
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $logFileName = "Hardening_$timestamp.log"
        $script:LogFile = Join-Path $LogPath $logFileName

        $osInfo = $script:HardeningContext.OS
        $currentUser = if ($script:HardeningContext.ContainsKey('CurrentUser')) { $script:HardeningContext.CurrentUser } else { $null }

        $header = @"
========================================
Windows Hardening Script Execution Log
========================================
Start Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
OS Version: $($osInfo.OSVersion)
OS Build: $($osInfo.BuildNumber)
OS Edition: $($osInfo.Edition)
Is Server: $($osInfo.IsServer)
Is Server Core: $($osInfo.IsServerCore)
Current User: $currentUser
Script Version: 2.0
========================================

"@

        $header | Out-File -FilePath $script:LogFile -Encoding UTF8
        Write-Host "Log file created: $script:LogFile" -ForegroundColor Cyan

        $script:OperationResults = @{
            Total          = 0
            Successful     = 0
            Failed         = 0
            Skipped        = 0
            Warnings       = @()
        }

        $script:log = @{}

    } catch {
        Write-Warning "Failed to initialize logging: $($_.Exception.Message)"
        $script:LogFile = $null
    }
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL")]
        [string]$Level,

        [Parameter(Mandatory=$true)]
        [string]$Message,

        [switch]$Console
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    if ($script:LogFile) {
        try {
            $logEntry | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
        } catch {
            Write-Warning "Failed to write to log file: $($_.Exception.Message)"
        }
    }

    if ($Console -or $Level -in "ERROR", "CRITICAL", "WARNING") {
        $color = switch ($Level) {
            "SUCCESS" { "Green" }
            "WARNING" { "Yellow" }
            "ERROR"   { "Red" }
            "CRITICAL"{ "Red" }
            default   { "White" }
        }
        Write-Host $logEntry -ForegroundColor $color
    }
}

function Set-OperationStatus {
    param(
        [string]$Key,
        [string]$Value
    )
    $script:log[$Key] = $Value
}

# Operations listed in the run summary. Each name must match the -OperationName
# (or Set-OperationStatus key) its function uses.
$script:TrackedOperations = @(
    "Initialize Context",
    "Remove Admin Users", "Remove RDP Users", "Add RDP Users",
    "Zulu Passwords", "Add Competition Users", "Change Passwords", "Patch Mimikatz",
    "Configure Firewall", "Remove Remote Management",
    "Disable Unused Network Protocols", "Upgrade SMB",
    "Enable Advanced Auditing", "Configure Splunk", "EternalBlue Mitigated",
    "Set Execution Policy"
)

function Reset-OperationStatus {
    foreach ($func in $script:TrackedOperations) {
        Set-OperationStatus $func "Not executed"
    }
}

function Show-OperationSummary {
    Write-Banner "Script Execution Summary" -Width 60
    Write-Log -Level "INFO" -Message "=== Execution Summary ===" -Console

    if ($script:HardeningContext.OS) {
        $osInfo = $script:HardeningContext.OS
        Write-Host "`nOperating System:" -ForegroundColor Yellow
        Write-Host "  Version: $($osInfo.OSVersion)" -ForegroundColor White
        Write-Host "  Build: $($osInfo.BuildNumber)" -ForegroundColor White
        Write-Host "  Edition: $($osInfo.Edition)" -ForegroundColor White
        Write-Host "  Is Server: $($osInfo.IsServer)" -ForegroundColor White
        Write-Log -Level "INFO" -Message "OS: $($osInfo.OSVersion) (Build $($osInfo.BuildNumber))"
    }

    Write-Host "`nIndividual Operations:" -ForegroundColor Yellow
    foreach ($entry in $script:log.GetEnumerator()) {
        $status = $entry.Value
        $color = switch -Wildcard ($status) {
            "*successfully*" { "Green" }
            "*Enabled*"      { "Green" }
            "*Completed*"    { "Green" }
            "*Mitigated*"    { "Green" }
            "*Failed*"       { "Red" }
            "*Disabled*"     { "Red" }
            "*Skipped*"      { "Yellow" }
            default          { "White" }
        }
        Write-Host "  $($entry.Key): " -NoNewline -ForegroundColor White
        Write-Host $status -ForegroundColor $color
        Write-Log -Level "INFO" -Message "$($entry.Key): $status"
    }

    Write-Banner "Operation Statistics" -Width 60 -Color Cyan
    Write-Host "Total Operations Attempted: $($script:OperationResults.Total)" -ForegroundColor White
    Write-Host "  Successful Operations: $($script:OperationResults.Successful)" -ForegroundColor Green
    Write-Host "  Failed Operations: $($script:OperationResults.Failed)" -ForegroundColor Red
    Write-Host "  Skipped Operations: $($script:OperationResults.Skipped)" -ForegroundColor Yellow

    Write-Log -Level "INFO" -Message "Total Operations: $($script:OperationResults.Total)" -Console
    Write-Log -Level "INFO" -Message "Successful: $($script:OperationResults.Successful)" -Console
    Write-Log -Level "INFO" -Message "Failed: $($script:OperationResults.Failed)" -Console
    Write-Log -Level "INFO" -Message "Skipped: $($script:OperationResults.Skipped)" -Console

    if ($script:OperationResults.Skipped -gt 0) {
        Write-Host "`nSkipped Operations (with reasons):" -ForegroundColor Yellow
        $skippedOps = $script:log.GetEnumerator() | Where-Object { $_.Value -like "*Skipped*" }
        foreach ($op in $skippedOps) {
            Write-Host "  - $($op.Key): $($op.Value)" -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "Skipped: $($op.Key) - $($op.Value)"
        }
    }

    if ($script:OperationResults.Warnings.Count -gt 0) {
        Write-Banner "Warnings" -Style Inline -Color Yellow
        foreach ($warning in $script:OperationResults.Warnings) {
            Write-Host "  - $warning" -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "Warning: $warning" -Console
        }
    }

    Write-Host ("`n" + ("=" * 60)) -ForegroundColor Cyan
}
