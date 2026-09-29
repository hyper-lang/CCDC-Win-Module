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

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Service Hardening" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan

    # Step 1: SMB hardening
    if (-not $SkipSMB) {
        Write-Host "`n[Services 1/2] Hardening SMB configuration..." -ForegroundColor Cyan
        Update-SMB
    } else {
        Write-Host "`n[Services 1/2] SKIPPED - SMB hardening (-SkipSMB)" -ForegroundColor Yellow
        Write-Log -Level "INFO" -Message "Invoke-ServiceHardening: SMB hardening skipped"
    }

    # Step 2: Disable unused network protocols (IPv6, NetBIOS)
    if (-not $SkipNetworkProtocols) {
        Write-Host "`n[Services 2/2] Disabling unused network protocols (IPv6, NetBIOS)..." -ForegroundColor Cyan
        Disable-UnusedNetworkProtocols
    } else {
        Write-Host "`n[Services 2/2] SKIPPED - unused network protocols (-SkipNetworkProtocols)" -ForegroundColor Yellow
        Write-Log -Level "INFO" -Message "Invoke-ServiceHardening: Disable-UnusedNetworkProtocols skipped"
    }

    Write-Host "`n[Services] Done." -ForegroundColor Green
    Write-Log -Level "INFO" -Message "Invoke-ServiceHardening completed"
}

Set-Alias -Name Harden-Services -Value Invoke-ServiceHardening
