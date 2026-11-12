function Invoke-ServiceHardening {
    <#
    .SYNOPSIS
        Orchestrates all service hardening in a single call.

    .DESCRIPTION
        Runs the full service hardening sequence in the recommended order:

          1. Mitigate-EternalBlue        - disables SMBv1, enables SMBv2/3,
                                          and requires SMB signing (blocks SMB relay).
          2. Disable-UnusedNetworkProtocols - disables IPv6 on all active adapters and
                                          disables NetBIOS over TCP/IP.

        SMB hardening runs first so the network stack is secured before network
        adapter settings are changed.

    .PARAMETER SkipEternalBlueMitigation
        Skip the Mitigate-EternalBlue step.

    .PARAMETER SkipNetworkProtocols
        Skip the Disable-UnusedNetworkProtocols step. Alias: -SkipNetworkServices.

    .EXAMPLE
        Invoke-ServiceHardening
        # Full sequence: SMB hardening then unused network protocols.

    .EXAMPLE
        Invoke-ServiceHardening -SkipEternalBlueMitigation
        # Only disables unused network protocols; SMB left unchanged.
    #>
    [CmdletBinding()]
    param(
        [switch]$SkipEternalBlueMitigation,

        [Alias('SkipNetworkServices')]
        [switch]$SkipNetworkProtocols
    ,
        [object]$State = $null
    )

    if (-not $State) { $State = Resolve-HardeningState -State $State }
    Initialize-System -State $State

    Write-Banner "Service Hardening" -State $State

    # Step 1: SMB hardening
    if (-not $SkipEternalBlueMitigation) {
        Mitigate-EternalBlue -State $State -StepLabel 'Services 1/2'
    } else {
        Write-Host ""
        Write-Status -Level Skip -Tag 'Services 1/2' "SKIPPED - EternalBlue mitigation (-SkipEternalBlueMitigation)" -LogMessage "Invoke-ServiceHardening: EternalBlue mitigation skipped" -State $State
    }

    # Step 2: Disable unused network protocols (IPv6, NetBIOS)
    if (-not $SkipNetworkProtocols) {
        Disable-UnusedNetworkProtocols -State $State -StepLabel 'Services 2/2'
    } else {
        Write-Host ""
        Write-Status -Level Skip -Tag 'Services 2/2' "SKIPPED - unused network protocols (-SkipNetworkProtocols)" -LogMessage "Invoke-ServiceHardening: Disable-UnusedNetworkProtocols skipped" -State $State
    }

    Write-Host ""
    Write-Status -Tag Services "Done." -LogMessage "Invoke-ServiceHardening completed" -State $State
    Flush-HardeningLog -State $State
}
