function Invoke-UserHardening {
    <#
    .SYNOPSIS
        Orchestrates all user and credential hardening in a single call.

    .DESCRIPTION
        Runs the full user hardening sequence in the recommended order:

          1. Remove-AdminUsers      - strips unnecessary local/AD admin privileges
          2. Set-ZuluPassword       - rotates all passwords and creates competition accounts
          3. Remove-RDPUsers        - clears the Remote Desktop Users group
          4. Protect-Mimikatz       - disables WDigest credential caching (no plaintext passwords in LSASS memory)

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
        Skip the Protect-Mimikatz (WDigest) step.

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

    Write-Banner "User & Credential Hardening"

    # Step 1: Remove extra admin accounts
    if (-not $SkipAdminRemoval) {
        $script:NextStepLabel = 'Users 1/4'
        Remove-AdminUsers
    } else {
        Write-Host ""
        Write-Status -Level Skip -Tag 'Users 1/4' "SKIPPED - admin removal (-SkipAdminRemoval)" -LogMessage "Invoke-UserHardening: admin removal skipped"
    }

    # Step 2: Rotate passwords and create competition accounts (before the RDP reset and
    # the rest of the run, so stolen credentials stop working as early as possible)
    if (-not $SkipPasswordChange) {
        $script:NextStepLabel = 'Users 2/4'
        # Set-ZuluPassword runs as its own "Zulu Passwords" operation, so a failure is
        # counted but does not abort the remaining user, network, and policy hardening.
        Set-ZuluPassword -Initial -SaltPhrase $SaltPhrase
    } else {
        Write-Host ""
        Write-Status -Level Skip -Tag 'Users 2/4' "SKIPPED - password rotation (-SkipPasswordChange)" -LogMessage "Invoke-UserHardening: password rotation skipped"
    }

    # Step 3: Reset RDP group
    if (-not $SkipRDP) {
        $script:NextStepLabel = 'Users 3/4'
        Remove-RDPUsers
    } else {
        Write-Host ""
        Write-Status -Level Skip -Tag 'Users 3/4' "SKIPPED - RDP group reset (-SkipRDP)" -LogMessage "Invoke-UserHardening: RDP group reset skipped"
    }

    # Step 4: Credential hardening (WDigest)
    if (-not $SkipMimikatz) {
        $script:NextStepLabel = 'Users 4/4'
        Protect-Mimikatz
    } else {
        Write-Host ""
        Write-Status -Level Skip -Tag 'Users 4/4' "SKIPPED - credential hardening (-SkipMimikatz)" -LogMessage "Invoke-UserHardening: Protect-Mimikatz skipped"
    }

    Write-Host ""
    Write-Status -Tag Users "Done." -LogMessage "Invoke-UserHardening completed"
}
