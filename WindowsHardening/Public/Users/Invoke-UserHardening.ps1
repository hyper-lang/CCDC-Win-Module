function Invoke-UserHardening {
    <#
    .SYNOPSIS
        Orchestrates all user and credential hardening in a single call.

    .DESCRIPTION
        Runs the full user hardening sequence in the recommended order:

          1. Remove-AdminUsers      - strips unnecessary local/AD admin privileges
          2. Remove-RDPUsers        - clears the Remote Desktop Users group
          3. Set-ZuluPassword   - creates competition accounts and rotates all passwords
          4. Protect-Mimikatz       - hardens WDigest and LSA to block credential dumping

        Each step is independently wrapped in Invoke-HardeningOperation, so a failure
        in one step is logged and counted but does not abort the rest.  Use the skip
        parameters to omit individual steps when needed (e.g. during an RDP session
        where you want to keep your own RDP access temporarily).

        Pass -SaltPhrase to run Zulu non-interactively; without it, Zulu prompts.

    .PARAMETER SkipPasswordChange
        Skip the Set-ZuluPassword step (no account creation or password rotation).

    .PARAMETER SkipRDP
        Skip the Remove-RDPUsers step (leave the Remote Desktop Users group unchanged).

    .PARAMETER SaltPhrase
        Salt phrase for Zulu password generation. If omitted, Zulu prompts for it.

    .PARAMETER SkipAdminRemoval
        Skip the Remove-AdminUsers step.

    .PARAMETER SkipMimikatz
        Skip the Protect-Mimikatz (WDigest/LSA) step.

    .EXAMPLE
        Invoke-UserHardening
        # Full sequence: admin removal, RDP reset, passwords, credential hardening.

    .EXAMPLE
        Invoke-UserHardening -SkipPasswordChange -SkipRDP
        # Only removes extra admins and hardens credentials.  Useful when accounts
        # were already set up earlier in the competition.
    #>
    [CmdletBinding()]
    param(
        [Alias('sp')]
        [switch]$SkipPasswordChange,

        [Alias('srdp')]
        [switch]$SkipRDP,

        [Alias('sa')]
        [switch]$SkipAdminRemoval,

        [Alias('sm')]
        [switch]$SkipMimikatz,

        [string]$SaltPhrase
    )

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  User & Credential Hardening" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan

    # Step 1: Remove extra admin accounts
    if (-not $SkipAdminRemoval) {
        Write-Host "`n[Users 1/4] Removing extra admin users..." -ForegroundColor Cyan
        Remove-AdminUsers
    } else {
        Write-Host "`n[Users 1/4] SKIPPED - admin removal (-SkipAdminRemoval)" -ForegroundColor Yellow
        Write-Log -Level "INFO" -Message "Invoke-UserHardening: admin removal skipped"
    }

    # Step 2: Reset RDP group
    if (-not $SkipRDP) {
        Write-Host "`n[Users 2/4] Resetting Remote Desktop Users group..." -ForegroundColor Cyan
        Remove-RDPUsers
    } else {
        Write-Host "`n[Users 2/4] SKIPPED - RDP group reset (-SkipRDP)" -ForegroundColor Yellow
        Write-Log -Level "INFO" -Message "Invoke-UserHardening: RDP group reset skipped"
    }

    # Step 3: Create competition accounts and rotate passwords
    if (-not $SkipPasswordChange) {
        Write-Host "`n[Users 3/4] Creating competition users and rotating passwords (Zulu)..." -ForegroundColor Cyan
        # Wrapped like the other steps so a Zulu failure is counted but does not abort
        # the remaining user, network, and policy hardening.
        Invoke-HardeningOperation -OperationName "Zulu Passwords" -ScriptBlock {
            Set-ZuluPassword -Initial -SaltPhrase $SaltPhrase
        }
    } else {
        Write-Host "`n[Users 3/4] SKIPPED - password rotation (-SkipPasswordChange)" -ForegroundColor Yellow
        Write-Log -Level "INFO" -Message "Invoke-UserHardening: password rotation skipped"
    }

    # Step 4: Credential hardening (WDigest + LSA)
    if (-not $SkipMimikatz) {
        Write-Host "`n[Users 4/4] Hardening credentials (WDigest/LSA)..." -ForegroundColor Cyan
        Protect-Mimikatz
    } else {
        Write-Host "`n[Users 4/4] SKIPPED - credential hardening (-SkipMimikatz)" -ForegroundColor Yellow
        Write-Log -Level "INFO" -Message "Invoke-UserHardening: Protect-Mimikatz skipped"
    }

    Write-Host "`n[Users] Done." -ForegroundColor Green
    Write-Log -Level "INFO" -Message "Invoke-UserHardening completed"
}

Set-Alias -Name Harden-Users -Value Invoke-UserHardening
