<#
.SYNOPSIS
    Downloads the WindowsHardening module from GitHub and imports it into the
    current PowerShell session.
.DESCRIPTION
    Fetches the repository archive for -Ref, extracts it to a fresh folder under
    -Destination, allows unsigned scripts for this session only (Process scope),
    and imports WindowsHardening globally. Nothing is installed; the module is
    gone when the session ends (the extracted files stay in -Destination).
.PARAMETER Repo
    GitHub owner/repository. Default: hyper-lang/CCDC-Win-Module.
.PARAMETER Ref
    Branch, tag, or commit SHA to download. Default: main.
.PARAMETER Destination
    Folder to extract into. Replaced on every run. Default: $env:TEMP\CCDC-Win-Module.
.EXAMPLE
    irm https://raw.githubusercontent.com/hyper-lang/CCDC-Win-Module/main/loader.ps1 | iex
.EXAMPLE
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/hyper-lang/CCDC-Win-Module/main/loader.ps1))) -Ref v1.0.0
    # Pass parameters when loading straight from the web.
#>
[CmdletBinding()]
param(
    [string]$Repo = 'hyper-lang/CCDC-Win-Module',
    [string]$Ref = 'main',
    [string]$Destination = (Join-Path $env:TEMP 'CCDC-Win-Module')
)

# Run in a child scope so helper variables do not leak into the caller when piped to iex.
& {
    # Windows PowerShell 5.1 defaults to TLS 1.0/1.1, which GitHub rejects.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    # The module is unsigned; allow scripts for this session only. A Group Policy
    # setting overrides this and makes Set-ExecutionPolicy report an error.
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
    } catch {
        Write-Warning "Could not set Process execution policy: $($_.Exception.Message)"
    }

    $url = "https://github.com/$Repo/archive/$Ref.zip"
    $zip = Join-Path ([IO.Path]::GetTempPath()) "CCDC-Win-Module-$([guid]::NewGuid().ToString('N')).zip"

    Write-Host "Downloading $url" -ForegroundColor Cyan
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing -ErrorAction Stop

    try {
        if (Test-Path $Destination) {
            Remove-Item $Destination -Recurse -Force -ErrorAction Stop
        }
        Expand-Archive -Path $zip -DestinationPath $Destination -Force -ErrorAction Stop
    } finally {
        Remove-Item $zip -Force -ErrorAction Ignore
    }

    Get-ChildItem $Destination -Recurse -File | Unblock-File

    # The archive's top folder is named after the repo and ref (e.g. CCDC-Win-Module-main).
    $manifest = Get-ChildItem $Destination -Recurse -Filter 'WindowsHardening.psd1' | Select-Object -First 1
    if (-not $manifest) {
        throw "WindowsHardening.psd1 not found in the $Ref archive of $Repo"
    }

    Import-Module $manifest.FullName -Force -Global -ErrorAction Stop

    $module = Get-Module WindowsHardening
    Write-Host "Loaded WindowsHardening $($module.Version) from $($manifest.DirectoryName)" -ForegroundColor Green
    Write-Host "Run Invoke-WindowsHardening to start, or Get-Command -Module WindowsHardening to list commands." -ForegroundColor Green
}
