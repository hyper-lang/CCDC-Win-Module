#Requires -Version 5.1

# Write-Status.ps1 - The one way the module reports what happened: a colored screen line
# plus the matching log line.

function Write-Status {
    <#
    .SYNOPSIS
        Writes a status line to the screen and the same message to the log file.
    .DESCRIPTION
        Screen: "  [<Tag or LEVEL>] <Message>", colored by level (Info white, Success green,
        Warning yellow, Error red, Skip dark gray). Log: "[time] [LEVEL] [Tag] <Message>".
    .PARAMETER Message
        What happened.
    .PARAMETER Level
        Info (default), Success, Warning, Error, or Skip.
    .PARAMETER Tag
        Subsystem shown instead of the level on screen, e.g. RDP or WinRM.
    .PARAMETER LogOnly
        Write only to the log file (details not worth showing on screen).
    .PARAMETER NoLog
        Write only to the screen.
    .PARAMETER LogMessage
        Log a different (usually more detailed) message than the screen shows.
    .EXAMPLE
        Write-Status -Level Success -Tag RDP "TermService stopped"
    .EXAMPLE
        Write-Status -LogOnly "Exception Type: $type"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowEmptyString()]
        [string]$Message,

        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Skip')]
        [string]$Level = 'Info',

        [string]$Tag,

        [switch]$LogOnly,

        [switch]$NoLog,

        [string]$LogMessage,

        [object]$State = $null
    )

    if (-not $LogOnly) {
        $color = switch ($Level) {
            'Success' { 'Green' }
            'Warning' { 'Yellow' }
            'Error'   { 'Red' }
            'Skip'    { 'DarkGray' }
            default   { 'White' }
        }
        $label = if ($Tag) { $Tag } else { $Level.ToUpper() }
        $syncRoot = if ($State.SyncRoot) { $State.SyncRoot } else { $null }
        if ($syncRoot) { [System.Threading.Monitor]::Enter($syncRoot) }
        try {
            Write-Host "  [$label] $Message" -ForegroundColor $color
        } finally {
            if ($syncRoot) { [System.Threading.Monitor]::Exit($syncRoot) }
        }
    }

    if (-not $NoLog) {
        $text = if ($PSBoundParameters.ContainsKey('LogMessage')) { $LogMessage } else { $Message }
        if ($Tag) { $text = "[$Tag] $text" }
        if ($State -and $State.LogFile) {
            # The caller/coordinator drains these records through Flush-HardeningLog,
            # which serializes file writes for this run.
            $State.LogEvents.Enqueue([pscustomobject]@{
                Timestamp = [datetime]::UtcNow
                Level = $Level
                Message = $text
            })
        }
    }
}
