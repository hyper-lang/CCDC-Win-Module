#Requires -Version 5.1

<#
.SYNOPSIS
    Performs essential hardening steps automatically via section orchestrators.

.DESCRIPTION
    Executes a standardized quick-hardening sequence using the three section
    orchestrators, then installs Splunk and restricts the execution policy:

      Step 1 - Invoke-ServiceHardening  : SMB hardening + disable unused network protocols
      Step 2 - Invoke-UserHardening     : remove extra admins, reset RDP group, rotate
                                  passwords (Zulu), harden credentials (Mimikatz)
      Step 3 - Invoke-NetworkHardening   : configure firewall, remove remote management
      Step 4 - Install-Splunk   : SIEM agent deployment
      Step 5 - Set-RestrictedExecutionPolicy : execution policy to Restricted

    Non-interactive: all prompts are replaced by parameters. Interactive behavior
    is opt-in (menu mode via Invoke-HardeningMenu).

.PARAMETER SkipPasswordChange
    Skip the Set-ZuluPassword step inside Invoke-UserHardening.

.PARAMETER SkipRDP
    Skip the Remove-RDPUsers step inside Invoke-UserHardening, and pass -SkipRDP to
    Invoke-NetworkHardening so RDP is not disabled by Remove-RemoteManagement either.

.PARAMETER SplunkIP
    IP address of the Splunk server. If omitted, prompts via Read-Host.

.PARAMETER FirewallPorts
    Ports to allow through the firewall, passed to Invoke-NetworkHardening. If omitted, a
    domain controller gets the common AD ports and a local machine gets Deny All only.

.PARAMETER PreserveManagementPort
    Pass -PreserveManagementPort to Invoke-NetworkHardening so Allow rules for WinRM
    (TCP 5985/5986) are kept and WinRM teardown is skipped. Use when applying
    hardening over WinRM.

.PARAMETER SaltPhrase
    Salt phrase for Zulu password generation, passed to Invoke-UserHardening. If
    omitted, Zulu prompts for it.

.PARAMETER SkipSplunk
    Skip the Splunk installation step. Useful for non-interactive runs with no
    Splunk server (avoids the Read-Host prompt, which fails over WinRM).
#>
function Start-QuickHarden {
    [CmdletBinding()]
    param(
        [Alias('sp')]
        [switch]$SkipPasswordChange,

        [Alias('srdp')]
        [switch]$SkipRDP,

        [string]$SplunkIP,

        [int[]]$FirewallPorts,

        [switch]$PreserveManagementPort,

        [switch]$SkipSplunk,

        [string]$SaltPhrase
    )

    Invoke-HardeningOperation -OperationName "Quick Harden" -ScriptBlock {
        Write-Host "`n=== QUICK HARDENING STARTED ===" -ForegroundColor Green
        Write-Host "Running all hardening sections automatically..." -ForegroundColor Yellow
        if ($SkipPasswordChange) {
            Write-Host "[NOTE] Password rotation will be skipped (-sp)" -ForegroundColor Yellow
        }
        if ($SkipRDP) {
            Write-Host "[NOTE] RDP group reset and RDP disable will be skipped (-srdp)" -ForegroundColor Yellow
        }
        Write-Host ""

        # -- Step 1: Services ------------------------------------------------
        Write-Host "`nStep 1/5: Hardening services (SMB + unused network protocols)..." -ForegroundColor Cyan
        Invoke-ServiceHardening

        # -- Step 2: Users & Credentials -------------------------------------
        Write-Host "`nStep 2/5: Hardening users and credentials..." -ForegroundColor Cyan
        Invoke-UserHardening `
            -SkipPasswordChange:$SkipPasswordChange `
            -SkipRDP:$SkipRDP `
            -SaltPhrase $SaltPhrase

        # -- Step 3: Network & Remote Access ---------------------------------
        Write-Host "`nStep 3/5: Hardening network and remote access..." -ForegroundColor Cyan
        Invoke-NetworkHardening `
            -FromQuickHarden `
            -FirewallPorts $FirewallPorts `
            -PreserveManagementPort:$PreserveManagementPort `
            -SkipRDP:$SkipRDP

        # -- Step 4: Splunk ---------------------------------------------------
        Write-Host "`nStep 4/5: Configuring Splunk..." -ForegroundColor Cyan
        if ($SkipSplunk) {
            Write-Host "  [SKIPPED] Splunk configuration skipped (-SkipSplunk)" -ForegroundColor Yellow
            Write-Log -Level "INFO" -Message "Splunk configuration skipped per -SkipSplunk"
        } else {
            Write-Host "  [NOTE] User input may be required for Splunk configuration" -ForegroundColor Yellow
            if ([string]::IsNullOrEmpty($SplunkIP)) {
                $SplunkIP = Read-Host "`nInput IP address of Splunk Server"
            }
            Install-Splunk -IP $SplunkIP
        }

        # -- Step 5: Execution policy -----------------------------------------
        Write-Host "`nStep 5/5: Setting Execution Policy to Restricted..." -ForegroundColor Cyan
        Set-RestrictedExecutionPolicy

        Write-Host "`n=== QUICK HARDENING COMPLETED ===" -ForegroundColor Green
        Write-Host "All sections applied. Next: enable Windows Defender, then run Windows Updates." -ForegroundColor Yellow
    }
}
