<#
.SYNOPSIS
    Downloads the WindowsHardening module from GitHub and imports it into the
    current PowerShell session.
.DESCRIPTION
    Downloads the archive of the module's own repository (-Repo) at -Ref, keeps only the
    module folder (-Path), and imports it. The module repository is small (the module
    plus its docs), so the whole archive is a quick download, and no GitHub API calls
    (or API rate limits) are involved.

    Other repositories, such as BYU-CCDC/public-ccdc-resources, include the module
    repository as a git submodule. GitHub leaves submodules out of archive downloads, so
    the loader always points at the module repository itself; this same file works no
    matter which repository it is fetched from.

    The module goes to a fresh -Destination folder; unsigned scripts are allowed for this
    session only (Process scope), and WindowsHardening is imported globally. Nothing is
    installed; the module is gone when the session ends (the files stay in -Destination).
.PARAMETER Repo
    GitHub owner/repository of the module itself. Default: hyper-lang/CCDC-Win-Module.
.PARAMETER Path
    Module folder inside that repository (the folder containing WindowsHardening.psd1).
    Default: WindowsHardening.
.PARAMETER Ref
    Branch, tag, or commit SHA to download. Default: main. For a competition, set this to
    the tag you declared, so the code stays frozen at what was submitted.
.PARAMETER Destination
    Folder to put the module in. Replaced on every run. Default: %TEMP%\CCDC-Win-Module.
.EXAMPLE
    irm https://raw.githubusercontent.com/hyper-lang/CCDC-Win-Module/main/loader.ps1 | iex
.EXAMPLE
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/hyper-lang/CCDC-Win-Module/main/loader.ps1))) -Ref v1.0.0
    # Pass parameters when loading straight from the web, e.g. to pin a tag or test a branch.
#>
[CmdletBinding()]
param(
    # The module's own repository (not a repository that includes it as a submodule:
    # GitHub archives leave submodules out).
    [string]$Repo = 'hyper-lang/CCDC-Win-Module',
    [string]$Path = 'WindowsHardening',

    [string]$Ref = 'main',
    [string]$Destination = (Join-Path ([IO.Path]::GetTempPath()) 'CCDC-Win-Module')
)

# Run in a child scope so helper variables do not leak into the caller when piped to iex.
& {
    # Windows PowerShell 5.1 defaults to TLS 1.0/1.1, which GitHub rejects.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    # The 5.1 progress bar makes downloads much slower.
    $ProgressPreference = 'SilentlyContinue'

    # The module is unsigned; allow scripts for this session only. A Group Policy
    # setting overrides this and makes Set-ExecutionPolicy report an error.
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
    } catch {
        Write-Warning "Could not set Process execution policy: $($_.Exception.Message)"
    }

    $url = "https://github.com/$Repo/archive/$Ref.zip"
    $work = Join-Path ([IO.Path]::GetTempPath()) "CCDC-Win-Module-$([guid]::NewGuid().ToString('N'))"
    $zip = "$work.zip"

    Write-Host "Downloading $url" -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri $url -OutFile $zip -UserAgent 'WindowsHardening-loader' -UseBasicParsing -ErrorAction Stop
    } catch {
        $status = try { [int]$_.Exception.Response.StatusCode } catch { 0 }
        if ($status -eq 404) {
            throw "Could not download $url : repository '$Repo' or ref '$Ref' not found"
        }
        throw "Could not download $url : $($_.Exception.Message)"
    }

    try {
        Expand-Archive -Path $zip -DestinationPath $work -Force -ErrorAction Stop

        # The archive holds one top folder, named after the repo and ref
        # (e.g. CCDC-Win-Module-main); the module folder is -Path inside it.
        $top = Get-ChildItem $work -Directory | Select-Object -First 1
        $source = if ($top) { Join-Path $top.FullName ($Path.Trim('/', '\')) }
        if (-not $source -or -not (Test-Path (Join-Path $source 'WindowsHardening.psd1'))) {
            throw "No WindowsHardening.psd1 in '$Path' of $Repo at '$Ref'. Check -Repo and -Path."
        }

        # Keep only the module folder.
        if (Test-Path $Destination) {
            Remove-Item $Destination -Recurse -Force -ErrorAction Stop
        }
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        Move-Item -Path $source -Destination (Join-Path $Destination 'WindowsHardening') -ErrorAction Stop
    } finally {
        Remove-Item $zip -Force -ErrorAction Ignore
        Remove-Item $work -Recurse -Force -ErrorAction Ignore
    }

    # Clear the downloaded-from-the-internet mark (Windows only; the cmdlet throws elsewhere).
    if ($env:OS -eq 'Windows_NT') {
        Get-ChildItem $Destination -Recurse -File | Unblock-File
    }

    $manifest = Join-Path (Join-Path $Destination 'WindowsHardening') 'WindowsHardening.psd1'
    Import-Module $manifest -Force -Global -ErrorAction Stop

    $module = Get-Module WindowsHardening
    Write-Host "Loaded WindowsHardening $($module.Version) from $Repo at '$Ref'" -ForegroundColor Green
    Write-Host "Run Invoke-WindowsHardening to start, or Get-Command -Module WindowsHardening to list commands." -ForegroundColor Green
}
