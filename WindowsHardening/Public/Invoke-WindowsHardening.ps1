function Invoke-WindowsHardening {
    <#
    .SYNOPSIS
        Main entry point for Windows hardening operations.

    .DESCRIPTION
        Performs comprehensive Windows hardening with OS detection, prerequisite checks,
        and either quick-hardening or interactive menu mode.


    .PARAMETER QuickHarden
        Run the quick-hardening sequence and exit. Alias: -q.

    .PARAMETER SkipPasswordChange
        Skip password change during QuickHarden. Alias: -sp.

    .PARAMETER SkipRDP
        Skip Remove-RDP-Users during QuickHarden. Alias: -srdp.

    .PARAMETER FirewallPorts
        Ports to allow through the firewall. Alias: -f.

    .PARAMETER SaltPhrase
        Salt phrase for Zulu password generation, passed to quick-harden and the menu's
        password options. If omitted, Zulu prompts for it. Alias: -s.

    .PARAMETER LogPath
        Path for log files. Default: C:\Windows\Logs\Hardening.

    .PARAMETER PreserveManagementPort
        Keep WinRM reachable: firewall Allow rules for TCP 5985/5986 are kept and WinRM is not
        disabled. Applies to quick-harden and to the menu's firewall/network options. Use when
        applying hardening over WinRM so the session is not locked out.

    .PARAMETER SplunkIP
        Splunk server IP, used by quick-harden and the menu's Splunk option. If omitted, they
        prompt for it.
    .PARAMETER SkipSplunk
        When set, passed through to Start-QuickHarden so the Splunk installation step is skipped.
        Useful for non-interactive runs with no Splunk server (avoids the Read-Host prompt,
        which fails over WinRM).
    #>
    [CmdletBinding()]
    param(

        [Alias("q")]
        [switch]$QuickHarden,

        [Alias("sp")]
        [switch]$SkipPasswordChange,

        [Alias("srdp")]
        [switch]$SkipRDP,

        [Alias("f")]
        [string[]]$FirewallPorts,

        [Alias("s")]
        [string]$SaltPhrase,

        [string]$LogPath,

        [switch]$PreserveManagementPort,

        [string]$SplunkIP,

        [switch]$SkipSplunk
    )

    # -- FirewallPorts parsing ----------------------------------------------
    $ports = @()

    if ($null -ne $FirewallPorts -and $FirewallPorts.Count -gt 0) {
        try {
            $portStrings = @()
            foreach ($item in $FirewallPorts) {
                if (-not [string]::IsNullOrWhiteSpace($item)) {
                    $portStrings += $item.Split(',') | ForEach-Object { $_.Trim() } |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                }
            }

            $ports = @(
                $portStrings | ForEach-Object {
                    $port = [int]$_
                    if ($port -lt 1 -or $port -gt 65535) {
                        throw "Port $port is out of valid range (1-65535)"
                    }
                    $port
                }
            )

            if ($ports.Count -gt 0) {
                Write-Host "[INFO] Firewall ports provided via parameter: $($ports -join ', ')" -ForegroundColor Cyan
            }
        } catch {
            Write-Host "[ERROR] Failed to parse FirewallPorts parameter: $($_.Exception.Message)" -ForegroundColor Red
            throw "Invalid FirewallPorts parameter: $($_.Exception.Message)"
        }
    }

    # $global:Error: inside a module, $Error is a separate module-scoped (empty) collection.
    $errorCountAtStart = $global:Error.Count

    # -- Banner --------------------------------------------------------------
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Windows Hardening Script v2.0" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan

    # -- Initialize (OS detection, logging, context) -------------------------
    Initialize-System -Force -LogPath $LogPath

    $osInfo = $script:HardeningContext.OS
    if ($osInfo) {
        Write-Host "`nDetected Operating System:" -ForegroundColor Yellow
        Write-Host "  OS Version: $($osInfo.OSVersion)" -ForegroundColor White
        Write-Host "  Build Number: $($osInfo.BuildNumber)" -ForegroundColor White
        Write-Host "  Edition: $($osInfo.Edition)" -ForegroundColor White
        Write-Host "  Is Server: $($osInfo.IsServer)" -ForegroundColor White
        Write-Host "  Is Server Core: $($osInfo.IsServerCore)" -ForegroundColor White
        Write-Host ""
    } else {
        Write-Host "`n[ERROR] Failed to detect operating system." -ForegroundColor Red
        Write-Host "The script may not function correctly. Continue anyway? (y/n)" -ForegroundColor Yellow
        $continue = Read-Host
        if ($continue -ne "y") {
            throw "OS detection failed. Script aborted by user."
        }
    }

    # -- AD status display ---------------------------------------------------
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $isDomainJoined = $computerSystem.PartOfDomain

        Write-Host "`n========================================" -ForegroundColor Cyan
        if ($isDomainJoined) {
            $domain = $computerSystem.Domain
            Write-Host "  Active Directory Status: DOMAIN JOINED" -ForegroundColor Green
            Write-Host "  Domain: $domain" -ForegroundColor White
        } else {
            $workgroup = $computerSystem.Workgroup
            Write-Host "  Active Directory Status: NOT DOMAIN JOINED" -ForegroundColor Yellow
            Write-Host "  Workgroup: $workgroup" -ForegroundColor White
        }
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
    } catch {
        Write-Host "`n[WARNING] Failed to detect Active Directory status: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "Continuing with script execution..." -ForegroundColor Yellow
        Write-Host ""
    }

    # -- Pre-flight checks ---------------------------------------------------
    try {
        Test-Prerequisites
    } catch {
        Write-Host "`n[ERROR] Pre-flight checks failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log -Level "CRITICAL" -Message "Pre-flight checks failed: $($_.Exception.Message)" -Console
        throw "Pre-flight checks failed: $($_.Exception.Message)"
    }

    # -- QuickHarden path ----------------------------------------------------
    if ($QuickHarden) {
        Start-QuickHarden -SkipPasswordChange:$SkipPasswordChange -SkipRDP:$SkipRDP -SplunkIP $SplunkIP -FirewallPorts $ports -PreserveManagementPort:$PreserveManagementPort -SkipSplunk:$SkipSplunk -SaltPhrase $SaltPhrase
    } else {
        # -- Interactive menu loop --------------------------------------------
        Invoke-HardeningMenu -FirewallPorts $ports -PreserveManagementPort:$PreserveManagementPort -SplunkIP $SplunkIP -SaltPhrase $SaltPhrase
    }

    # -- Post-loop: final summary --------------------------------------------
    Write-Host "`n***Script Completed!!!***" -ForegroundColor Green
    Show-OperationSummary

    # $Error is newest-first, so this run's errors are the first (new count) entries
    $newErrorCount = $global:Error.Count - $errorCountAtStart
    if ($newErrorCount -gt 0) {
        try {
            $errorFile = "$env:USERPROFILE\Desktop\hard.txt"
            $global:Error[0..($newErrorCount - 1)] | Out-File $errorFile -Append -Encoding utf8
            Write-Log -Level "INFO" -Message "Errors written to $errorFile"
        } catch {
            Write-Log -Level "WARNING" -Message "Could not write errors to file: $($_.Exception.Message)"
        }
    }

    Write-Log -Level "INFO" -Message "=== Script Execution Completed ===" -Console
    Write-Log -Level "INFO" -Message "Log file location: $script:LogFile" -Console

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 60) -ForegroundColor Cyan
    if ($script:OperationResults.Failed -eq 0 -and $script:OperationResults.Skipped -eq 0) {
        Write-Host "[SUCCESS] Hardening completed successfully!" -ForegroundColor Green
        Write-Host "All $($script:OperationResults.Total) operation(s) completed without errors." -ForegroundColor Green
        Write-Log -Level "SUCCESS" -Message "=== Hardening completed successfully ===" -Console
    } elseif ($script:OperationResults.Failed -eq 0) {
        Write-Host "[SUCCESS] Hardening completed with warnings!" -ForegroundColor Green
        Write-Host "All operations completed, but $($script:OperationResults.Skipped) operation(s) were skipped (see details above)." -ForegroundColor Yellow
        Write-Log -Level "SUCCESS" -Message "=== Hardening completed with warnings ===" -Console
    } else {
        Write-Host "[WARNING] Hardening completed with errors - review the summary above" -ForegroundColor Yellow
        Write-Host "Failed Operations: $($script:OperationResults.Failed)" -ForegroundColor Red
        Write-Log -Level "ERROR" -Message "=== Hardening completed with errors ===" -Console
    }
    Write-Host ("=" * 60) -ForegroundColor Cyan
}
