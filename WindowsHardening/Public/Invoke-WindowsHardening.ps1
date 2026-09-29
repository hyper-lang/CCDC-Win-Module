function Invoke-WindowsHardening {
    <#
    .SYNOPSIS
        Runs the full hardening sequence: every section orchestrator, in order.
    .DESCRIPTION
        Starts a fresh log, shows the OS and AD status detected at module import,
        checks for administrator rights, then runs:

          1. Invoke-UserHardening          - admin removal, Zulu password rotation, RDP group
                                             reset, WDigest/LSA credential hardening
          2. Invoke-ServiceHardening       - SMB + unused network protocols
          3. Invoke-NetworkHardening       - firewall, remote-management teardown
          4. Install-Splunk                - unless -SkipSplunk
          5. Set-RestrictedExecutionPolicy - machine-wide Restricted

        Each step is wrapped in Invoke-HardeningOperation, so one failure is counted and
        reported without stopping the rest. Ends with the operation summary.

        Prompts only for what is not passed: the Zulu salt phrase (-SaltPhrase) and the
        Splunk server IP (-SplunkIP or -SkipSplunk). To pick individual steps instead,
        use Invoke-HardeningMenu.
    .PARAMETER SkipPasswordChange
        Skip Zulu account creation and password rotation. Alias: -sp.
    .PARAMETER SkipRDP
        Skip the RDP group reset and leave RDP enabled. Alias: -srdp.
    .PARAMETER FirewallPorts
        Ports to allow ("80, 443", @("80","443"), or 80,443). If omitted, a domain
        controller gets the common AD ports and any other machine gets Deny All only. Alias: -f.
    .PARAMETER SaltPhrase
        Salt phrase for Zulu password generation. If omitted, Zulu prompts for it. Alias: -s.
    .PARAMETER LogPath
        Path for log files. Default: C:\Windows\Logs\Hardening.
    .PARAMETER PreserveManagementPort
        Keep WinRM reachable: firewall Allow rules for TCP 5985/5986 are kept and WinRM is not
        disabled. Use when applying hardening over WinRM so the session is not locked out.
    .PARAMETER SplunkIP
        Splunk server IP. If omitted (and -SkipSplunk is not set), prompts for it.
    .PARAMETER SkipSplunk
        Skip the Splunk installation step (no prompt).
    .EXAMPLE
        Invoke-WindowsHardening -SaltPhrase 'a long passphrase' -SkipSplunk
        # Full run with no prompts.
    #>
    [CmdletBinding()]
    param(

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
    try {
        $ports = ConvertTo-PortList -Ports $FirewallPorts
    } catch {
        Write-Host "[ERROR] Failed to parse FirewallPorts parameter: $($_.Exception.Message)" -ForegroundColor Red
        throw "Invalid FirewallPorts parameter: $($_.Exception.Message)"
    }
    if ($ports.Count -gt 0) {
        Write-Host "[INFO] Firewall ports provided via parameter: $($ports -join ', ')" -ForegroundColor Cyan
    }

    # $global:Error: inside a module, $Error is a separate module-scoped (empty) collection.
    $errorCountAtStart = $global:Error.Count

    # -- Banner --------------------------------------------------------------
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Windows Hardening MODULE v1.0" -ForegroundColor Green
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

    # -- AD status display (detected at module import) ------------------------
    if ($osInfo) {
        Write-Host "`n========================================" -ForegroundColor Cyan
        if ($osInfo.IsDomainJoined) {
            Write-Host "  Active Directory Status: DOMAIN JOINED$(if ($osInfo.IsDomainController) { ' (Domain Controller)' })" -ForegroundColor Green
            Write-Host "  Domain: $($osInfo.Domain)" -ForegroundColor White
        } else {
            Write-Host "  Active Directory Status: NOT DOMAIN JOINED" -ForegroundColor Yellow
            Write-Host "  Workgroup: $($osInfo.Workgroup)" -ForegroundColor White
        }
        Write-Host "========================================" -ForegroundColor Cyan
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

    # -- Hardening sequence ---------------------------------------------------
    if ($SkipPasswordChange) {
        Write-Host "[NOTE] Password rotation will be skipped (-sp)" -ForegroundColor Yellow
    }
    if ($SkipRDP) {
        Write-Host "[NOTE] RDP group reset and RDP disable will be skipped (-srdp)" -ForegroundColor Yellow
    }

    Write-Host "`nStep 1/5: Hardening users and credentials..." -ForegroundColor Cyan
    Invoke-UserHardening -SkipPasswordChange:$SkipPasswordChange -SkipRDP:$SkipRDP -SaltPhrase $SaltPhrase

    Write-Host "`nStep 2/5: Hardening services (SMB + unused network protocols)..." -ForegroundColor Cyan
    Invoke-ServiceHardening

    Write-Host "`nStep 3/5: Hardening network and remote access..." -ForegroundColor Cyan
    Invoke-NetworkHardening -NonInteractive -FirewallPorts $ports -PreserveManagementPort:$PreserveManagementPort -SkipRDP:$SkipRDP

    Write-Host "`nStep 4/5: Configuring Splunk..." -ForegroundColor Cyan
    if ($SkipSplunk) {
        Write-Host "  [SKIPPED] Splunk configuration skipped (-SkipSplunk)" -ForegroundColor Yellow
        Write-Log -Level "INFO" -Message "Splunk configuration skipped per -SkipSplunk"
    } else {
        if ([string]::IsNullOrEmpty($SplunkIP)) {
            $SplunkIP = Read-Host "`nInput IP address of Splunk Server"
        }
        Install-Splunk -IP $SplunkIP
    }

    Write-Host "`nStep 5/5: Setting Execution Policy to Restricted..." -ForegroundColor Cyan
    Set-RestrictedExecutionPolicy

    Write-Host "`nAll sections applied. Next: enable Windows Defender, then run Windows Updates." -ForegroundColor Yellow

    # -- Final summary -------------------------------------------------------
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
