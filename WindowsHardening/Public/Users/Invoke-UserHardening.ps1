function Invoke-UserHardening {
    <#
    .SYNOPSIS
        Orchestrates all user and credential hardening in a single call.

    .DESCRIPTION
        Runs the user and credential hardening steps. The full-run orchestrator calls the
        leaf functions directly so network and RDP steps can be interleaved in the desired order.

        Each step is independently wrapped in Invoke-HardeningOperation, so a failure
        in one step is logged and counted but does not abort the rest.  Use the skip
        parameters to omit individual steps when needed (e.g. during an RDP session
        where you want to keep your own RDP access temporarily).

        Pass -SaltPhrase for unattended password generation; without it, password functions prompt.

    .PARAMETER SkipPasswordChange
        Skip the Administrator password change, Zulu rotation, and CCDC user creation.

    .PARAMETER SkipRDP
        Skip the Remove-RDPUsers step (leave the Remote Desktop Users group unchanged).

    .PARAMETER SaltPhrase
        Salt phrase for Zulu password generation. If omitted, Zulu prompts for it.

    .PARAMETER SkipAdminRemoval
        Skip the Remove-AdminUsers step.

    .PARAMETER SkipMimikatz
        Skip the Protect-Mimikatz (WDigest) step.

    .EXAMPLE
        Invoke-UserHardening
        # Full sequence: Administrator password, admin cleanup, password rotation,
        # RDP group reset, credential hardening, then CCDC account creation.

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
    ,
        [object]$State = $null
    ,
        [string]$StepLabel
    )

    if (-not $State) { $State = Resolve-HardeningState -State $State }
    Initialize-System -State $State

    Write-Banner "User & Credential Hardening" -State $State

    # Step 1: Change the built-in Administrator password.
    if (-not $SkipPasswordChange) {
        Set-AdministratorPassword -SaltPhrase $SaltPhrase -State $State -StepLabel 'Users 1/6'
    } else {
        Write-Host ""
        Write-Status -Level Skip -Tag 'Users 1/6' "SKIPPED - Administrator password change (-SkipPasswordChange)" -LogMessage "Invoke-UserHardening: Administrator password change skipped" -State $State
    }

    # Step 2: Remove extra admin accounts.
    if (-not $SkipAdminRemoval) {
        Remove-AdminUsers -State $State -StepLabel 'Users 2/6'
    } else {
        Write-Host ""
        Write-Status -Level Skip -Tag 'Users 2/6' "SKIPPED - admin removal (-SkipAdminRemoval)" -LogMessage "Invoke-UserHardening: admin removal skipped" -State $State
    }

    # Step 3: Rotate eligible existing-user passwords.
    if (-not $SkipPasswordChange) {
        Set-ZuluPassword -SaltPhrase $SaltPhrase -State $State -StepLabel 'Users 3/6'
    } else {
        Write-Host ""
        Write-Status -Level Skip -Tag 'Users 3/6' "SKIPPED - password rotation (-SkipPasswordChange)" -LogMessage "Invoke-UserHardening: password rotation skipped" -State $State
    }

    # Step 4: Reset RDP group.
    if (-not $SkipRDP) {
        Remove-RDPUsers -State $State -StepLabel 'Users 4/6'
    } else {
        Write-Host ""
        Write-Status -Level Skip -Tag 'Users 4/6' "SKIPPED - RDP group reset (-SkipRDP)" -LogMessage "Invoke-UserHardening: RDP group reset skipped" -State $State
    }

    # Step 5: Credential hardening (WDigest).
    if (-not $SkipMimikatz) {
        Protect-Mimikatz -State $State -StepLabel 'Users 5/6'
    } else {
        Write-Host ""
        Write-Status -Level Skip -Tag 'Users 5/6' "SKIPPED - credential hardening (-SkipMimikatz)" -LogMessage "Invoke-UserHardening: Protect-Mimikatz skipped" -State $State
    }

    # Step 6: Create competition accounts after the more urgent credential cleanup.
    if (-not $SkipPasswordChange) {
        Create-CCDCUsers -SaltPhrase $SaltPhrase -State $State -StepLabel 'Users 6/6'
    } else {
        Write-Host ""
        Write-Status -Level Skip -Tag 'Users 6/6' "SKIPPED - CCDC account creation (-SkipPasswordChange)" -LogMessage "Invoke-UserHardening: CCDC account creation skipped" -State $State
    }

    Write-Host ""
    Write-Status -Tag Users "Done." -LogMessage "Invoke-UserHardening completed" -State $State
    Flush-HardeningLog -State $State
}
