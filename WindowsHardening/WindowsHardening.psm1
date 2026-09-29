#Requires -Version 5.1

# WindowsHardening Module Loader
# Dot-sources Public/**/*.ps1 then Dev/*.ps1 (sorted alphabetically)
# Initializes $script:HardeningContext placeholder

# Bundled data files (ports.json, patchURLs.json, wordlist.txt, advancedAuditing.ps1)
$script:DataPath = Join-Path $PSScriptRoot 'Data'
$script:DefaultLogPath = 'C:\Windows\Logs\Hardening'

# Initialize the HardeningContext placeholder
$script:HardeningContext = @{
    OS                 = $null
    LogPath            = $null
    CurrentUser        = $null
    Ports              = $null
    Initialized        = $false
}

# Shared state for logging and operation tracking
$script:LogFile = $null
$script:log = @{}
$script:OperationResults = @{
    Total          = 0
    Successful     = 0
    Failed         = 0
    Skipped        = 0
    Warnings       = @()
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
