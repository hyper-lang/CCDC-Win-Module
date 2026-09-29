#Requires -Version 5.1

# Context.ps1 - Hardening context: prerequisite checks, DC detection, context initialization.

# -- Module constants ---------------------------------------------------------

$script:CcdcRepoUrl = 'https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/hardening/'
$script:RequiredFiles = @('ports.json', 'advancedAuditing.ps1', 'patchURLs.json', 'wordlist.txt')
$script:FallbackPorts = @{
    ports = @{
        '53'   = @{ description = 'DNS' }
        '3389' = @{ description = 'RDP' }
        '80'   = @{ description = 'HTTP' }
        '445'  = @{ description = 'SMB' }
        '139'  = @{ description = 'NetBIOS Session' }
        '22'   = @{ description = 'SSH' }
        '88'   = @{ description = 'Kerberos' }
        '67'   = @{ description = 'DHCP Server' }
        '68'   = @{ description = 'DHCP Client' }
        '135'  = @{ description = 'RPC' }
        '389'  = @{ description = 'LDAP' }
        '636'  = @{ description = 'LDAPS' }
        '3268' = @{ description = 'Global Catalog' }
        '3269' = @{ description = 'Global Catalog SSL' }
        '464'  = @{ description = 'Kerberos Change/Set Password' }
    }
}

function Test-IsDomainController {
    <#
    .SYNOPSIS
        Raw DC probe (NTDS service present). Callers should read the cached
        (Get-OperatingSystemInfo).IsDomainController instead of calling this.
    #>
    [CmdletBinding()]
    param()
    try {
        $ntds = Get-Service -Name ntds -ErrorAction Ignore
        return $ntds -ne $null
    } catch {
        return $false
    }
}

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Pre-flight checks. Throws if not running as Administrator (every hardening
        step needs it); OS and PowerShell version problems are warnings only.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n=== Pre-flight Checks ===" -ForegroundColor Cyan
    Write-Log -Level "INFO" -Message "=== Pre-flight Checks ===" -Console

    $allChecksPassed = $true

    # Check administrator privileges
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-Host "[FAIL] Script must be run as Administrator" -ForegroundColor Red
            Write-Log -Level "ERROR" -Message "Administrator privileges required" -Console
            $allChecksPassed = $false
        } else {
            Write-Host "[PASS] Running with Administrator privileges" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "Administrator privileges confirmed"
        }
    } catch {
        Write-Host "[FAIL] Could not verify administrator privileges" -ForegroundColor Red
        Write-Log -Level "ERROR" -Message "Could not verify administrator privileges: $($_.Exception.Message)" -Console
        $allChecksPassed = $false
    }

    # Check OS compatibility
    try {
        if (-not $script:HardeningContext.OS) {
            Write-Host "[WARN] OS not detected. OS-specific steps will be skipped." -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "OS not detected"
        } elseif ($script:HardeningContext.OS.OSVersion -eq "Unknown") {
            Write-Host "[WARN] Unknown OS version detected. Some operations may not work correctly." -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "Unknown OS version detected"
        } else {
            Write-Host "[PASS] OS detected: $($script:HardeningContext.OS.OSVersion)" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "OS detected: $($script:HardeningContext.OS.OSVersion)"
        }
    } catch {
        Write-Host "[WARN] OS detection failed" -ForegroundColor Yellow
        Write-Log -Level "WARNING" -Message "OS detection failed: $($_.Exception.Message)"
    }

    # Check PowerShell version
    try {
        $psVersion = $PSVersionTable.PSVersion
        if ($psVersion.Major -lt 3) {
            Write-Host "[WARN] PowerShell version $psVersion may not support all features" -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "PowerShell version $psVersion detected"
        } else {
            Write-Host "[PASS] PowerShell version: $psVersion" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "PowerShell version: $psVersion"
        }
    } catch {
        Write-Host "[WARN] Could not determine PowerShell version" -ForegroundColor Yellow
        Write-Log -Level "WARNING" -Message "Could not determine PowerShell version"
    }

    Write-Host "`n=== Pre-flight Checks Complete ===" -ForegroundColor Cyan
    Write-Log -Level "INFO" -Message "=== Pre-flight Checks Complete ===" -Console

    if (-not $allChecksPassed) {
        throw "Must be run as Administrator (start PowerShell with 'Run as administrator')."
    }
}

function Initialize-Context {
    [CmdletBinding()]
    param()

    Invoke-HardeningOperation -OperationName "Initialize Context" -ScriptBlock {
        # Data files ship in the module's Data folder; download only if one is missing
        if (-not (Test-Path $script:DataPath)) {
            New-Item -Path $script:DataPath -ItemType Directory -Force | Out-Null
        }
        foreach ($file in $script:RequiredFiles) {
            $filename = $(Split-Path -Path $file -Leaf)
            $target = Join-Path $script:DataPath $filename
            if (-not (Test-Path $target)) {
                Write-Host "Downloading $filename..." -ForegroundColor Cyan
                try {
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    Invoke-WebRequest -Uri "$script:CcdcRepoUrl/$file" -OutFile $target
                    Write-Log -Level "SUCCESS" -Message "Downloaded $filename"
                } catch {
                    # Non-fatal: each consumer checks for its own file (ports.json has a fallback).
                    Write-Host "[WARN] Failed to download $filename : $($_.Exception.Message)" -ForegroundColor Yellow
                    Write-Log -Level "WARNING" -Message "Failed to download $filename : $($_.Exception.Message)"
                }
            } else {
                Write-Verbose "File already exists: $filename"
            }
        }

        # Set current user
        $script:HardeningContext.CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        # Load port data
        $portsFile = Join-Path $script:DataPath 'ports.json'
        if (Test-Path $portsFile) {
            $script:HardeningContext.Ports = Get-Content -Path $portsFile -Raw | ConvertFrom-Json
            Write-Log -Level "INFO" -Message "Loaded ports configuration from ports.json"
        } else {
            $script:HardeningContext.Ports = $script:FallbackPorts
            Write-Log -Level "WARNING" -Message "ports.json not found, using fallback port definitions"
        }

        Write-Host "Context initialized successfully" -ForegroundColor Green
    }
}

function Get-HardeningContext {
    <#
    .SYNOPSIS
        Returns a snapshot of the module's current hardening context (DC status, OS,
        log path, etc.; DC status is OS.IsDomainController) as populated by Initialize-System / Initialize-Context.
    #>
    [CmdletBinding()]
    param()
    [PSCustomObject]$script:HardeningContext.Clone()
}
