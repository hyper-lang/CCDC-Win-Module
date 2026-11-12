#Requires -Version 5.1

# Log.ps1 - Log file setup, Write-Log (internal; use Write-Status), and the execution summary.

function Start-HardeningLog {
    [CmdletBinding()]
    param(
        [string]$LogPath,
        [object]$State = $null
    )

    if (-not $State) { $State = Resolve-HardeningState -State $State }

    if ([string]::IsNullOrEmpty($LogPath)) {
        $LogPath = $script:DefaultLogPath
    }
    $State.Context.LogPath = $LogPath

    try {
        if (-not (Test-Path $LogPath)) {
            New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
            Write-Verbose "Created log directory: $LogPath"
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $logFileName = "Hardening_$timestamp.log"
        $State.LogFile = Join-Path $LogPath $logFileName

        $osInfo = $State.Context.OS
        $currentUser = if ($State.Context.ContainsKey('CurrentUser')) { $State.Context.CurrentUser } else { $null }

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

        $header | Out-File -FilePath $State.LogFile -Encoding UTF8
        Write-Host "Log file created: $($State.LogFile)" -ForegroundColor Cyan

        $State.OperationResults = [pscustomobject]@{
            Total          = 0
            Successful     = 0
            Failed         = 0
            Skipped        = 0
            Warnings       = [System.Collections.Generic.List[string]]::new()
        }

        $State.Log = @{}

    } catch {
        Write-Warning "Failed to initialize logging: $($_.Exception.Message)"
        $State.LogFile = $null
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Appends a timestamped line to the log file. Internal: call Write-Status instead,
        which also handles the screen (Write-Status -LogOnly for log-only details).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL", "SKIP")]
        [string]$Level,

        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Message,

        [object]$State = $null,

        [datetime]$Timestamp = [datetime]::MinValue
    )

    if (-not $State -or -not $State.LogFile) {
        return
    }

    $syncRoot = if ($State.SyncRoot) { $State.SyncRoot } else { $null }
    if ($syncRoot) { [System.Threading.Monitor]::Enter($syncRoot) }
    try {
        $timeText = if ($Timestamp -ne [datetime]::MinValue) { $Timestamp.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss') } else { Get-Date -Format 'yyyy-MM-dd HH:mm:ss' }
        try {
            "[$timeText] [$Level] $Message" | Out-File -FilePath $State.LogFile -Append -Encoding UTF8
        } catch {
            Write-Warning "Failed to write to log file: $($_.Exception.Message)"
        }
    } finally {
        if ($syncRoot) { [System.Threading.Monitor]::Exit($syncRoot) }
    }
}

function Flush-HardeningLog {
    <#
    .SYNOPSIS
        Drains structured log events through one serialized writer for this run.
    #>
    [CmdletBinding()]
    param([object]$State = $null)

    if (-not $State) { $State = Resolve-HardeningState -State $State }
    if (-not $State.LogEvents -or -not $State.LogFile) { return }

    $syncRoot = if ($State.SyncRoot) { $State.SyncRoot } else { $null }
    if ($syncRoot) { [System.Threading.Monitor]::Enter($syncRoot) }
    try {
        $event = $null
        while ($State.LogEvents.TryDequeue([ref]$event)) {
            Write-Log -Level $event.Level.ToUpperInvariant() -Message $event.Message -State $State -Timestamp $event.Timestamp
            $event = $null
        }
    } finally {
        if ($syncRoot) { [System.Threading.Monitor]::Exit($syncRoot) }
    }
}

function Update-HardeningCounter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object]$State,
        [Parameter(Mandatory=$true)][ValidateSet('Total', 'Successful', 'Failed', 'Skipped')][string]$Counter,
        [int]$Increment = 1
    )

    $syncRoot = if ($State.SyncRoot) { $State.SyncRoot } else { $null }
    if ($syncRoot) { [System.Threading.Monitor]::Enter($syncRoot) }
    try {
        $State.OperationResults.$Counter = [int]$State.OperationResults.$Counter + $Increment
    } finally {
        if ($syncRoot) { [System.Threading.Monitor]::Exit($syncRoot) }
    }
}

function Add-HardeningWarning {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][object]$State, [Parameter(Mandatory=$true)][string]$Warning)

    $syncRoot = if ($State.SyncRoot) { $State.SyncRoot } else { $null }
    if ($syncRoot) { [System.Threading.Monitor]::Enter($syncRoot) }
    try {
        if ($State.OperationResults.Warnings -isnot [System.Collections.Generic.List[string]]) {
            $State.OperationResults.Warnings = [System.Collections.Generic.List[string]]::new([string[]]@($State.OperationResults.Warnings))
        }
        $State.OperationResults.Warnings.Add($Warning)
    } finally {
        if ($syncRoot) { [System.Threading.Monitor]::Exit($syncRoot) }
    }
}

function Get-HardeningSummarySnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][object]$State)

    $syncRoot = if ($State.SyncRoot) { $State.SyncRoot } else { $null }
    if ($syncRoot) { [System.Threading.Monitor]::Enter($syncRoot) }
    try {
        $statuses = @{}
        foreach ($entry in $State.Log.GetEnumerator()) { $statuses[$entry.Key] = $entry.Value }
        [pscustomobject]@{
            Total = $State.OperationResults.Total
            Successful = $State.OperationResults.Successful
            Failed = $State.OperationResults.Failed
            Skipped = $State.OperationResults.Skipped
            Warnings = [string[]]@($State.OperationResults.Warnings)
            Statuses = $statuses
        }
    } finally {
        if ($syncRoot) { [System.Threading.Monitor]::Exit($syncRoot) }
    }
}

function Set-OperationStatus {
    param(
        [string]$Key,
        [string]$Value,
        [object]$State = $null
    )
    if (-not $State) { $State = Resolve-HardeningState -State $State }
    $syncRoot = if ($State.SyncRoot) { $State.SyncRoot } else { $null }
    if ($syncRoot) { [System.Threading.Monitor]::Enter($syncRoot) }
    try {
        $State.Log[$Key] = $Value
    } finally {
        if ($syncRoot) { [System.Threading.Monitor]::Exit($syncRoot) }
    }
}

# Operations prelisted in the run summary before steps run. Standalone operations
# are added when invoked through Set-OperationStatus.
$script:TrackedOperations = @(
    "Initialize Context",
    "Link DC Allow AD GPO", "Link Domain Firewall GPO", "Link Domain GPO Update Interval",
    "Link Domain Good-GPO", "Link Splunk Server GPO", "Link Database Access GPO",
    "Link Web Server GPO", "Link Mail Server GPO", "Link WinRM Management GPO",
    "Link SSH Access GPO", "Link RDP Access GPO", "Link FTP Access GPO", "Link SMB Access GPO",
    "Refresh Group Policy",
    "Remove Admin Users", "Remove RDP Users", "Add RDP Users",
    "Change Administrator Password", "Zulu Passwords", "Add Competition Users", "Change Passwords", "Patch Mimikatz",
    "Configure Firewall", "Remove Remote Management",
    "Disable Unused Network Protocols", "Mitigate EternalBlue",
    "Enable Advanced Auditing", "Configure Splunk",
    "Set Execution Policy"
)

function Reset-OperationStatus {
    param([object]$State = $null)
    if (-not $State) { $State = Resolve-HardeningState -State $State }
    foreach ($func in $script:TrackedOperations) {
        Set-OperationStatus $func "Not executed" -State $State
    }
}

function Show-OperationSummary {
    param([object]$State = $null)
    if (-not $State) { $State = Resolve-HardeningState -State $State }
    Flush-HardeningLog -State $State
    $summary = Get-HardeningSummarySnapshot -State $State
    Write-Banner "Script Execution Summary" -Width 60 -State $State

    if ($State.Context.OS) {
        $osInfo = $State.Context.OS
        Write-Host "`nOperating System:" -ForegroundColor Yellow
        Write-Host "  Version: $($osInfo.OSVersion)" -ForegroundColor White
        Write-Host "  Build: $($osInfo.BuildNumber)" -ForegroundColor White
        Write-Host "  Edition: $($osInfo.Edition)" -ForegroundColor White
        Write-Host "  Is Server: $($osInfo.IsServer)" -ForegroundColor White
        Write-Status -LogOnly "OS: $($osInfo.OSVersion) (Build $($osInfo.BuildNumber))" -State $State
    }

    Write-Host "`nIndividual Operations:" -ForegroundColor Yellow
    foreach ($entry in $summary.Statuses.GetEnumerator()) {
        $status = $entry.Value
        # First match wins (break): failure and skip wording is checked before success
        # wording, since an error message can contain words like "completed".
        $color = switch -Wildcard ($status) {
            "Failed*"        { "Red"; break }
            "Skipped*"       { "Yellow"; break }
            "*successfully*" { "Green"; break }
            "*Enabled*"      { "Green"; break }
            "*Completed*"    { "Green"; break }
            "*Mitigated*"    { "Green"; break }
            "*Disabled*"     { "Red"; break }
            default          { "White" }
        }
        Write-Host "  $($entry.Key): " -NoNewline -ForegroundColor White
        Write-Host $status -ForegroundColor $color
        Write-Status -LogOnly "$($entry.Key): $status" -State $State
    }

    Write-Banner "Operation Statistics" -Width 60 -Color Cyan -State $State
    Write-Host "Total Operations Attempted: $($summary.Total)" -ForegroundColor White
    Write-Host "  Successful Operations: $($summary.Successful)" -ForegroundColor Green
    Write-Host "  Failed Operations: $($summary.Failed)" -ForegroundColor Red
    Write-Host "  Skipped Operations: $($summary.Skipped)" -ForegroundColor Yellow

    Write-Status -LogOnly "Total Operations: $($summary.Total)" -State $State
    Write-Status -LogOnly "Successful: $($summary.Successful)" -State $State
    Write-Status -LogOnly "Failed: $($summary.Failed)" -State $State
    Write-Status -LogOnly "Skipped: $($summary.Skipped)" -State $State

    if ($summary.Skipped -gt 0) {
        Write-Host "`nSkipped Operations (with reasons):" -ForegroundColor Yellow
        $skippedOps = $summary.Statuses.GetEnumerator() | Where-Object { $_.Value -like "Skipped*" }
        foreach ($op in $skippedOps) {
            Write-Host "  - $($op.Key): $($op.Value)" -ForegroundColor Yellow
            Write-Status -Level Skip -LogOnly "$($op.Key) - $($op.Value)" -State $State
        }
    }

    if ($summary.Warnings.Count -gt 0) {
        Write-Banner "Warnings" -Style Inline -Color Yellow -State $State
        foreach ($warning in $summary.Warnings) {
            Write-Host "  - $warning" -ForegroundColor Yellow
            Write-Status -Level Warning -LogOnly "$warning" -State $State
        }
    }

    Write-Host ("`n" + ("=" * 60)) -ForegroundColor Cyan
    Flush-HardeningLog -State $State
}
