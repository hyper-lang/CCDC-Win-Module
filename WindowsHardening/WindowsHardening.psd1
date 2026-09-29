@{
    RootModule        = 'WindowsHardening.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'a5b6951f-2e85-4915-bfd1-4fc3a779d13c'
    Author            = 'Aaron-M-Anderson, echo8358, deltabluejay, TheBushWookiee, zinkozapper, hyper-lang'
    CompanyName       = 'BYU CCDC'
    Description       = 'Comprehensive Windows hardening module with OS detection, user management, firewall configuration, and service hardening for AD and local environments.'

    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        # -- Public/ - entry points ------------------------------------------
        'Invoke-WindowsHardening'
        'Invoke-HardeningMenu'
        'Start-QuickHarden'

        # -- Public/Users/ ---------------------------------------------------
        'Invoke-UserHardening'
        'Set-ZuluPassword'
        'Write-ZuluLog'
        'Set-UserPassword'
        'Initialize-CompetitionUsers'
        'New-ADUserAccount'
        'Remove-AdminUsers'
        'Remove-RDPUsers'
        'Add-RDPUsers'
        'Protect-Mimikatz'

        # -- Public/Network/ -------------------------------------------------
        'Invoke-NetworkHardening'
        'Set-FirewallConfiguration'
        'Remove-RemoteManagement'

        # -- Public/Services/ ------------------------------------------------
        'Invoke-ServiceHardening'
        'Disable-UnusedNetworkProtocols'
        'Update-SMB'
        'Set-RestrictedExecutionPolicy'

        # -- Public/SIEM/ -----------------------------------------------------
        'Install-Splunk'

        # -- Public/Patching/ ------------------------------------------------
        'Install-EternalBluePatch'

        # -- Public/Messages/ - logging & prompts ----------------------------
        'Start-HardeningLog'
        'Write-Log'
        'Set-OperationStatus'
        'Reset-OperationStatus'
        'Show-OperationSummary'
        'Read-YesNo'
        'Read-CommaList'
        'Read-SecretInput'

        # -- Public/Helpers/ -------------------------------------------------
        'Initialize-System'
        'Initialize-Context'
        'Get-HardeningContext'
        'Test-Prerequisites'
        'Test-IsDomainController'
        'Get-OperatingSystemInfo'
        'Invoke-HardeningOperation'
        'Get-FileFromUrl'
        'Set-RegistryValue'
        'Show-Users'
        'New-Password'
        'ConvertTo-WordIndex'

        # -- Dev/ - experimental ---------------------------------------------
        'Backup-WindowsState'
        'Restore-WindowsState'
        'Get-LSARegistryValues'
        'Restore-LSAValues'
        'Restore-RegistrySecurityValues'
    )

    AliasesToExport = @(
        'Configure-Firewall'
        'Patch-Mimikatz'
        'Upgrade-SMB'

        # Previous function names
        'New-Zulu-Integration'
        'New-ZuluIntegration'
        'Harden-Users'
        'Harden-Network'
        'Harden-Services'
        'Disable-UnnecessaryServices'
        'Revert-WindowsState'
        'Print-Users'
        'Print-Log'
    )

    PrivateData = @{
        PSData = @{
            Tags       = @('Hardening', 'Security', 'Windows', 'Firewall', 'ActiveDirectory')
            ProjectUri = 'https://github.com/BYU-CCDC/public-ccdc-resources'
        }
    }
}
