#Requires -Version 5.1

# Get-FileFromUrl.ps1 - File download helper.

function Get-FileFromUrl {
    param(
        [string]$Url,
        [string]$OutputPath
    )
    try {
        Write-Host "Downloading from $Url..." -ForegroundColor Green
        $ProgressPreference = 'SilentlyContinue'
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing
        $ProgressPreference = 'Continue'
        $true
    } catch {
        Write-Host "Failed to download file from $Url`nError: $($_.Exception.Message)" -ForegroundColor Red
        $false
    }
}
