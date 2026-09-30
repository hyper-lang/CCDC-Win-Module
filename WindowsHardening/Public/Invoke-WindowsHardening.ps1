function Invoke-WindowsHardening {
    <#
    .SYNOPSIS
        Runs the full hardening sequence: every section orchestrator, in order.
    .DESCRIPTION
        Starts a fresh log, shows the OS and AD status detected at module import,
        checks for administrator rights, then runs:

          1. Invoke-UserHardening          - admin removal, Zulu password rotation, RDP group
                                             reset, WDigest credential hardening
          2. Invoke-ServiceHardening       - SMB + unused network protocols
          3. Invoke-NetworkHardening       - firewall, remote-management teardown
          4. Install-Splunk                - unless -SkipSplunk
          5. Set-RestrictedExecutionPolicy - machine-wide Restricted

        Each step is wrapped in Invoke-HardeningOperation, so one failure is counted and
        reported without stopping the rest. Ends with the operation summary.

        Prompts for what is not passed: the Zulu salt phrase (-SaltPhrase) and the Splunk
        server IP (-SplunkIP or -SkipSplunk). Before hardening starts it asks whether to
        disable RDP (unless -DisableRDP or -SkipRDP says), and at the firewall step it asks
        for extra ports to allow; -NoPrompt skips both questions. To pick individual steps instead, use
        Invoke-HardeningMenu.
    .PARAMETER SkipPasswordChange
        Skip Zulu account creation and password rotation. Alias: -sp.
    .PARAMETER SkipRDP
        Leave RDP enabled and skip the RDP group reset, without asking. Alias: -srdp.
    .PARAMETER DisableRDP
        Disable RDP and reset the RDP group, without asking. Alias: -drdp. With neither
        this nor -SkipRDP, the run asks up front; with -NoPrompt (or in a session that
        cannot prompt) it disables RDP.
    .PARAMETER FirewallPorts
        Ports to allow ("80, 443", @("80","443"), or 80,443). If omitted, a domain
        controller gets the common AD ports and any other machine gets Deny All only. Alias: -f.
    .PARAMETER AdditionalPorts
        Extra ports to allow on top of -FirewallPorts or the defaults above - e.g. a database
        or web port the box needs. Same formats as -FirewallPorts. Alias: -ap.
    .PARAMETER NoPrompt
        Don't ask whether to disable RDP (it is disabled unless -SkipRDP) or for extra
        firewall ports (only the defaults, -FirewallPorts, and -AdditionalPorts are used). Without it, the firewall step keeps those ports and then asks
        for extra ones. In a session that cannot prompt (e.g. over WinRM), the question is
        skipped with a warning.
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
        Invoke-WindowsHardening -SaltPhrase 'a long passphrase' -SkipSplunk -NoPrompt
        # Full run with no prompts.
    #>
    [CmdletBinding()]
    param(

        [Alias("sp")]
        [switch]$SkipPasswordChange,

        [Alias("srdp")]
        [switch]$SkipRDP,

        [Alias("drdp")]
        [switch]$DisableRDP,

        [Alias("f")]
        [string[]]$FirewallPorts,

        [Alias("ap")]
        [string[]]$AdditionalPorts,

        [switch]$NoPrompt,

        [Alias("s")]
        [string]$SaltPhrase,

        [string]$LogPath,

        [switch]$PreserveManagementPort,

        [string]$SplunkIP,

        [switch]$SkipSplunk
    )

    if ($SkipRDP -and $DisableRDP) {
        throw "-SkipRDP and -DisableRDP cannot be used together"
    }

    # -- FirewallPorts parsing ----------------------------------------------
    try {
        $ports = ConvertTo-PortList -Ports $FirewallPorts
        $extraPorts = ConvertTo-PortList -Ports $AdditionalPorts
    } catch {
        Write-Status -Level Error "Failed to parse FirewallPorts parameter: $($_.Exception.Message)"
        throw "Invalid FirewallPorts parameter: $($_.Exception.Message)"
    }
    if ($ports.Count -gt 0) {
        Write-Status "Firewall ports provided via parameter: $($ports -join ', ')"
    }
    if ($extraPorts.Count -gt 0) {
        Write-Status "Additional firewall ports: $($extraPorts -join ', ')"
    }

    # Check -SplunkIP now, so a typo fails before hardening starts rather than at step 4.
    if ($SplunkIP -and -not (Test-HostAddress ($SplunkIP -replace ':\d+$', ''))) {
        throw "Invalid -SplunkIP '$SplunkIP': not an IP address or host name"
    }

    # $global:Error: inside a module, $Error is a separate module-scoped (empty) collection.
    $errorCountAtStart = $global:Error.Count

    # -- Banner --------------------------------------------------------------
    Write-Banner "Windows Hardening MODULE v1.0"

    # -- Initialize (OS detection, logging, context) -------------------------
    Initialize-System -Force -LogPath $LogPath

    $osInfo = $script:HardeningContext.OS
    if ($osInfo) {
        Write-Banner "Detected Operating System" -Color Yellow -Body @(
            "OS Version: $($osInfo.OSVersion)"
            "Build Number: $($osInfo.BuildNumber)"
            "Edition: $($osInfo.Edition)"
            "Is Server: $($osInfo.IsServer)"
            "Is Server Core: $($osInfo.IsServerCore)"
        )
    } else {
        Write-Host ""
        Write-Status -Level Error "Failed to detect operating system."
        if ((Read-YesNo -Message "The script may not function correctly. Continue anyway? (y/n) ") -ne 'y') {
            throw "OS detection failed. Script aborted by user."
        }
    }

    # -- AD status display (detected at module import) ------------------------
    if ($osInfo) {
        if ($osInfo.IsDomainJoined) {
            Write-Banner "Active Directory Status: DOMAIN JOINED$(if ($osInfo.IsDomainController) { ' (Domain Controller)' })" -Body "Domain: $($osInfo.Domain)"
        } else {
            Write-Banner "Active Directory Status: NOT DOMAIN JOINED" -Body "Workgroup: $($osInfo.Workgroup)" -Color Yellow
        }
        Write-Host ""
    }

    # -- Pre-flight checks ---------------------------------------------------
    try {
        Test-Prerequisites
    } catch {
        Write-Host ""
        Write-Status -Level Error "Pre-flight checks failed: $($_.Exception.Message)"
        throw "Pre-flight checks failed: $($_.Exception.Message)"
    }

    # -- RDP: ask once, up front ---------------------------------------------
    # The answer is needed before step 1 (RDP group reset) and step 3 (RDP disable).
    # "No" means the same as -SkipRDP: RDP stays enabled and its group is not reset.
    if (-not $SkipRDP -and -not $DisableRDP) {
        if ($NoPrompt) {
            Write-Status "RDP will be disabled (-NoPrompt; pass -SkipRDP to keep it)"
        } else {
            Write-Host ""
            Write-Status -Level Warning "Disabling RDP ends any RDP session to this machine, including yours." -NoLog
            try {
                $rdpChoice = Read-Choice -Prompt "Disable RDP on this machine?" -Default 'Y' -Options @(
                    @{ Key = 'Y'; Label = 'Yes - disable RDP and reset the Remote Desktop Users group'; Value = 'disable' }
                    @{ Key = 'N'; Label = 'No  - keep RDP enabled and leave the group as is (same as -SkipRDP)'; Value = 'keep' }
                )
                $SkipRDP = $rdpChoice -eq 'keep'
            } catch {
                Write-Status -Level Warning "Cannot ask in this session; RDP will be disabled (pass -SkipRDP to keep it)" `
                    -LogMessage "RDP prompt unavailable: $($_.Exception.Message)"
            }
            Write-Status "RDP will be $(if ($SkipRDP) { 'kept' } else { 'disabled' }) (answered at the prompt)" -LogOnly
        }
    }

    # -- Hardening sequence ---------------------------------------------------
    if ($SkipPasswordChange) {
        Write-Status "Password rotation will be skipped (-sp)"
    }
    if ($SkipRDP) {
        Write-Status "RDP group reset and RDP disable will be skipped (RDP stays enabled)"
    }

    Write-Banner "Step 1/5: Hardening users and credentials" -Style Inline -Log
    Invoke-UserHardening -SkipPasswordChange:$SkipPasswordChange -SkipRDP:$SkipRDP -SaltPhrase $SaltPhrase

    Write-Banner "Step 2/5: Hardening services (SMB + unused network protocols)" -Style Inline -Log
    Invoke-ServiceHardening

    Write-Banner "Step 3/5: Hardening network and remote access" -Style Inline -Log
    Invoke-NetworkHardening -NonInteractive -Prompt:(-not $NoPrompt) -FirewallPorts $ports -AdditionalPorts $extraPorts -PreserveManagementPort:$PreserveManagementPort -SkipRDP:$SkipRDP

    Write-Banner "Step 4/5: Configuring Splunk" -Style Inline -Log
    if ($SkipSplunk) {
        Write-Status -Level Skip "Splunk configuration skipped (-SkipSplunk)" -LogMessage "Splunk configuration skipped per -SkipSplunk"
    } else {
        if ([string]::IsNullOrEmpty($SplunkIP)) {
            $SplunkIP = Read-HostAddress -Prompt "Splunk server IP"
        }
        Install-Splunk -IP $SplunkIP
    }

    Write-Banner "Step 5/5: Setting Execution Policy to Restricted" -Style Inline -Log
    Set-RestrictedExecutionPolicy

    Write-Host ""
    Write-Status -Level Warning "All sections applied. Next: enable Windows Defender, then run Windows Updates."

    # -- Final summary -------------------------------------------------------
    Write-Banner "Script Completed" -Style Inline -Color Green -Log
    Show-OperationSummary

    # $Error is newest-first, so this run's errors are the first (new count) entries
    $newErrorCount = $global:Error.Count - $errorCountAtStart
    if ($newErrorCount -gt 0) {
        try {
            $errorFile = "$env:USERPROFILE\Desktop\hard.txt"
            $global:Error[0..($newErrorCount - 1)] | Out-File $errorFile -Append -Encoding utf8
            Write-Status "Errors written to $errorFile" -LogOnly
        } catch {
            Write-Status -Level Warning "Could not write errors to file: $($_.Exception.Message)"
        }
    }

    Write-Status -LogOnly "=== Script Execution Completed ==="
    Write-Status "Log file location: $script:LogFile"

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 60) -ForegroundColor Cyan
    if ($script:OperationResults.Failed -eq 0 -and $script:OperationResults.Skipped -eq 0) {
        Write-Status -Level Success "Hardening completed successfully! All $($script:OperationResults.Total) operation(s) completed without errors." -LogMessage "=== Hardening completed successfully ==="
    } elseif ($script:OperationResults.Failed -eq 0) {
        Write-Status -Level Warning "Hardening completed with warnings! All operations completed, but $($script:OperationResults.Skipped) operation(s) were skipped (see details above)." -LogMessage "=== Hardening completed with warnings ==="
    } else {
        Write-Status -Level Error "Hardening completed with errors - review the summary above. Failed Operations: $($script:OperationResults.Failed)" -LogMessage "=== Hardening completed with errors ==="
    }
    Write-Host ("=" * 60) -ForegroundColor Cyan
}
