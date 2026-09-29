function Invoke-NetworkHardening {
    <#
    .SYNOPSIS
        Orchestrates all network and remote-access hardening in a single call.

    .DESCRIPTION
        Runs the full network hardening sequence in the recommended order:

          1. Set-FirewallConfiguration  - enables all profiles, blocks inbound, allows only
                                         specified ports; optionally preserves TCP 5985/5986
                                         for WinRM management.
          2. Remove-RemoteManagement    - stops and disables WinRM, Remote Registry, RDP,
                                         SSH (if present), and Telnet.

        The two steps are deliberately ordered: firewall perimeter closes first, then
        the services are torn down so there is no window where a service is killed but
        the port is still open.

        When -PreserveManagementPort is set (typically when applying hardening over
        WinRM), Remove-RemoteManagement is called with -SkipWinRM
        so the active management session is not severed.

    .PARAMETER PreserveManagementPort
        Keep firewall allow-rules for WinRM (TCP 5985/5986) and skip the WinRM teardown
        in Remove-RemoteManagement. Pass this when running remotely over WinRM.

    .PARAMETER NonInteractive
        Passed to Set-FirewallConfiguration: never prompt. Without -FirewallPorts,
        a DC gets the common AD ports and any other machine gets Deny All only.

    .PARAMETER FirewallPorts
        Ports to allow, passed to Set-FirewallConfiguration.

    .PARAMETER Prompt
        Passed to Set-FirewallConfiguration: keep the default ports, then ask for extra
        ports to allow on top of them. Works with -NonInteractive.

    .PARAMETER AdditionalPorts
        Extra ports allowed on top of -FirewallPorts or the defaults, passed to
        Set-FirewallConfiguration.

    .PARAMETER SkipRemoteManagement
        Skip the Remove-RemoteManagement step entirely.  Use when you want to
        apply the firewall but leave remote channels open for continued access.

    .PARAMETER SkipRDP
        When Remove-RemoteManagement runs, pass -SkipRDP so RDP is not disabled.
        Useful when the team still needs RDP access during the competition.

    .EXAMPLE
        Invoke-NetworkHardening
        # Full sequence: firewall, then shut down all remote management channels.

    .EXAMPLE
        Invoke-NetworkHardening -PreserveManagementPort
        # Firewall closes with WinRM 5985/5986 allowed; WinRM teardown skipped so remote
        # session survives.

    .EXAMPLE
        Invoke-NetworkHardening -SkipRemoteManagement
        # Firewall only; remote channels left running.
    #>
    [CmdletBinding()]
    param(
        [switch]$PreserveManagementPort,

        [switch]$NonInteractive,

        [switch]$Prompt,

        [int[]]$FirewallPorts,

        [int[]]$AdditionalPorts,

        [switch]$SkipRemoteManagement,

        [Alias('srdp')]
        [switch]$SkipRDP
    )

    Write-Banner "Network & Remote-Access Hardening"

    # Step 1: Firewall
    Write-Host "`n[Network 1/2] Configuring firewall..." -ForegroundColor Cyan
    Set-FirewallConfiguration -NonInteractive:$NonInteractive -Prompt:$Prompt -FirewallPorts $FirewallPorts -AdditionalPorts $AdditionalPorts -PreserveManagementPort:$PreserveManagementPort

    # Step 2: Remote management teardown
    if (-not $SkipRemoteManagement) {
        Write-Host "`n[Network 2/2] Removing remote management attack surface..." -ForegroundColor Cyan
        if ($PreserveManagementPort) {
            # Running over WinRM - keep WinRM alive, still disable RDP unless caller opts out
            if ($SkipRDP) {
                Remove-RemoteManagement -SkipWinRM -SkipRDP
            } else {
                Remove-RemoteManagement -SkipWinRM
            }
        } else {
            if ($SkipRDP) {
                Remove-RemoteManagement -SkipRDP
            } else {
                Remove-RemoteManagement
            }
        }
    } else {
        Write-Host "`n[Network 2/2] SKIPPED - remote management teardown (-SkipRemoteManagement)" -ForegroundColor Yellow
        Write-Log -Level "INFO" -Message "Invoke-NetworkHardening: Remove-RemoteManagement skipped"
    }

    Write-Host "`n[Network] Done." -ForegroundColor Green
    Write-Log -Level "INFO" -Message "Invoke-NetworkHardening completed"
}
