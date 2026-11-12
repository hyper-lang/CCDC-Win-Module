#Requires -Version 5.1

# WindowsHardening Module Loader
# Dot-sources Public/**/*.ps1 then Dev/*.ps1 (sorted alphabetically)
# Caches machine OS information at import; per-run state is created by callers.

# Bundled data files (ports.json, patchURLs.json, wordlist.txt)
$script:DataPath = Join-Path $PSScriptRoot 'Data'
$script:DefaultLogPath = 'C:\Windows\Logs\Hardening'

# Build a fresh context for every run state. Only the immutable machine OS
# snapshot is cached at module scope; run-specific values stay on the state.
function New-HardeningContext {
    $context = @{
        OS                 = $null
        LogPath            = $null
        CurrentUser        = $null
        Ports              = $null
        Initialized        = $false
    }

    # OS details are machine-level and were historically detected at module
    # import. Copy the record so a new run state can use that cache without
    # sharing the mutable Context object (or the OS record itself).
    if ($script:ImportOsInfo) {
        $context.OS = [pscustomobject]@{}
        foreach ($property in $script:ImportOsInfo.PSObject.Properties) {
            $context.OS | Add-Member -MemberType NoteProperty -Name $property.Name -Value $property.Value
        }
    }

    return $context
}

# Import-time machine information cache, not run state.
$script:ImportOsInfo = $null

function New-HardeningRunState {
    [pscustomobject]@{
        RunId = [guid]::NewGuid().ToString()
        StartedAt = [datetime]::UtcNow
        Context = (New-HardeningContext)
        DataPath = $script:DataPath
        Results = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
        LogEvents = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
        OperationResults = [pscustomobject]@{ Total = 0; Successful = 0; Failed = 0; Skipped = 0; Warnings = [System.Collections.Generic.List[string]]::new() }
        LogFile = $null
        Log = @{}
        NextStepLabel = $null
        # Protects summary updates and serializes log-file writes for this run.
        SyncRoot = [object]::new()
    }
}

# Resolve an omitted state to a fresh per-invocation state. No module-level
# run state is retained; callers that coordinate multiple operations pass the
# returned object down through those calls.
function Resolve-HardeningState {
    [CmdletBinding()]
    param([object]$State)

    if ($State) { return $State }
    return New-HardeningRunState
}

# Dot-source Public functions (recursing into subfolders).
$publicPath = Join-Path $PSScriptRoot 'Public'
if (Test-Path $publicPath) {
    Get-ChildItem -Path $publicPath -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue |
        Sort-Object FullName |
        ForEach-Object {
            . $_.FullName
        }
}

# Dot-source Dev (R&D) functions
$devPath = Join-Path $PSScriptRoot 'Dev'
if (Test-Path $devPath) {
    Get-ChildItem -Path $devPath -Filter '*.ps1' -ErrorAction SilentlyContinue |
        Sort-Object Name |
        ForEach-Object {
            . $_.FullName
        }
}

# Detect the OS and DC status once, at import, so new states can copy the
# machine-level snapshot. Logging and
# data-file setup stay in Initialize-System, which runs on first use.
try {
    $null = Get-OperatingSystemInfo
} catch {
    Write-Warning "OS detection failed at import; OS-specific steps will be skipped: $($_.Exception.Message)"
}
