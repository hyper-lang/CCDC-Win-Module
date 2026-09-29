function Invoke-ServiceHardening {
    <#
    .SYNOPSIS
        Orchestrates all service hardening in a single call.

    .DESCRIPTION
        Runs the full service hardening sequence in the recommended order:

          1. Update-SMB                  - disables SMBv1, enforces SMBv2/3, enables
                                          SMB signing, and applies related registry
                                          hardening (prevents EternalBlue and related).
          2. Disable-UnusedNetworkProtocols - disables IPv6 on all active adapters and
                                          disables NetBIOS over TCP/IP.

        SMB hardening runs first so the network stack is secured before network
        adapter settings are changed.

    .PARAMETER SkipSMB
        Skip the Update-SMB step.

    .PARAMETER SkipNetworkProtocols
        Skip the Disable-UnusedNetworkProtocols step. Alias: -SkipNetworkServices.

    .EXAMPLE
        Invoke-ServiceHardening
        # Full sequence: SMB hardening then unused network protocols.

    .EXAMPLE
        Invoke-ServiceHardening -SkipSMB
        # Only disables unused network protocols; SMB left unchanged.
    #>
    [CmdletBinding()]
    param(
        [switch]$SkipSMB,

        [Alias('SkipNetworkServices')]
        [switch]$SkipNetworkProtocols
    )

    Write-Banner "Service Hardening"

    # Step 1: SMB hardening
    if (-not $SkipSMB) {
        $script:NextStepLabel = 'Services 1/2'
        Update-SMB
    } else {
        Write-Host ""
        Write-Status -Level Skip -Tag 'Services 1/2' "SKIPPED - SMB hardening (-SkipSMB)" -LogMessage "Invoke-ServiceHardening: SMB hardening skipped"
    }

    # Step 2: Disable unused network protocols (IPv6, NetBIOS)
    if (-not $SkipNetworkProtocols) {
        $script:NextStepLabel = 'Services 2/2'
        Disable-UnusedNetworkProtocols
    } else {
        Write-Host ""
        Write-Status -Level Skip -Tag 'Services 2/2' "SKIPPED - unused network protocols (-SkipNetworkProtocols)" -LogMessage "Invoke-ServiceHardening: Disable-UnusedNetworkProtocols skipped"
    }

    Write-Host ""
    Write-Status -Tag Services "Done." -LogMessage "Invoke-ServiceHardening completed"
}
