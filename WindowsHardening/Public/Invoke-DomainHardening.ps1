function Invoke-DomainHardening {
    <#
    .SYNOPSIS
        Hardens a domain controller and links the competition GPOs for the domain.
    .DESCRIPTION
        Imports the Group Policy and Active Directory modules, prepares the GPO backup
        archive, then runs the account and policy sequence. Domain firewall and baseline
        GPOs are linked to the selected domain scopes; role firewall GPOs are security
        filtered to the selected computer accounts. The run ends by refreshing policy,
        configuring Splunk when requested, and creating CCDC accounts.

        Role policies are linked at the domain root and filtered to the exact selected
        computer accounts. Domain Splunk outbound applies to Domain Computers and
        Domain Controllers. The domain firewall policy (default Block in and out, plus
        NTP) applies to every computer; DC Allow AD layers the DC inbound and SYSVOL
        replication rules on top of it.
        WinRM is left running by this sequence.
    .PARAMETER SkipPasswordChange
        Skip the Administrator password change, Zulu rotation, and CCDC account creation.
    .PARAMETER SaltPhrase
        Salt phrase for generated passwords. If omitted, password functions prompt.
    .PARAMETER GpoZipPath
        Optional local path to gpos.zip. By default the archive is downloaded from the
        BYU-CCDC public-ccdc-resources repository.
    .PARAMETER GpoCachePath
        Folder used for the downloaded archive and extracted backups.
    .PARAMETER RoleServers
        Hashtable mapping role names (Database, Web, Mail) to computer names.
        WinRM may also be supplied to preserve management access on selected servers.
        If omitted, the run offers computer selections for each role. Use -NoPrompt to
        skip role assignments when running unattended.
    .PARAMETER WinRMRemoteAddress
        Remote address or CIDR entries allowed to manage selected WinRM servers.
        Defaults to LocalSubnet.
    .PARAMETER NoPrompt
        Skip server role selection prompts. If Splunk is not skipped, pass -SplunkIP.
    .PARAMETER SplunkIP
        Splunk indexer address. Prompts if omitted and Splunk installation is enabled.
    .PARAMETER SkipSplunk
        Skip the final Splunk installation step.
    .PARAMETER FirewallPortRulesToAdd
        Optional hashtables passed to Add-DomainFirewallPortRule. Each needs Name,
        ComputerName, and Port; Protocol, Direction, and RemoteAddress are optional.
    .PARAMETER FirewallPortRulesToRemove
        Names of previously added domain port rules to remove.
    .PARAMETER LogPath
        Path for log files. Default: C:\Windows\Logs\Hardening.
    .EXAMPLE
        Invoke-DomainHardening -SaltPhrase 'competition seed phrase' -SkipSplunk
        # Runs on a DC and interactively selects servers for role firewall policies.
    .EXAMPLE
        Invoke-DomainHardening -NoPrompt -RoleServers @{ Database = @('DB01'); Web = @('WEB01') } -SplunkIP '10.0.0.20'
        # Supplies server roles and Splunk address without prompts.
    #>
    [CmdletBinding()]
    param(
        [switch]$SkipPasswordChange,
        [string]$SaltPhrase,
        [string]$GpoZipPath,
        [string]$GpoCachePath,
        [hashtable]$RoleServers = @{},
        [string[]]$WinRMRemoteAddress = @('LocalSubnet'),
        [switch]$NoPrompt,
        [string]$SplunkIP,
        [switch]$SkipSplunk,
        [hashtable[]]$FirewallPortRulesToAdd = @(),
        [string[]]$FirewallPortRulesToRemove = @(),
        [string]$LogPath
    )

    if (-not $script:HardeningContext.OS -or -not $script:HardeningContext.OS.IsDomainController) {
        throw 'Invoke-DomainHardening must be run on a domain controller.'
    }
    if ($NoPrompt -and -not $SkipSplunk -and -not $SplunkIP) {
        throw 'Pass -SplunkIP or -SkipSplunk when using -NoPrompt.'
    }
    if ($SplunkIP -and -not (Test-HostAddress ($SplunkIP -replace ':\d+$', ''))) {
        throw "Invalid -SplunkIP '$SplunkIP': not an IP address or host name"
    }

    $errorCountAtStart = $global:Error.Count
    Write-Banner 'Domain Hardening'
    Initialize-System -Force -LogPath $LogPath

    try {
        Test-Prerequisites
        Initialize-CcdcGpoEnvironment -GpoZipPath $GpoZipPath -GpoCachePath $GpoCachePath | Out-Null
        $backupRoot = if ($GpoCachePath) { Join-Path $GpoCachePath 'Backups' } else { Join-Path ([System.IO.Path]::GetTempPath()) 'CCDC-GPOs\Backups' }
    } catch {
        Write-Status -Level Error "Domain hardening pre-flight failed: $($_.Exception.Message)"
        throw
    }

    if ($SkipPasswordChange) {
        Write-Status -Level Skip 'Administrator password change, Zulu rotation, and CCDC account creation skipped (-SkipPasswordChange)'
    } else {
        $script:NextStepLabel = 'Domain 1/13'
        Set-AdministratorPassword -SaltPhrase $SaltPhrase
    }

    $script:NextStepLabel = 'Domain 2/13'
    Remove-AdminUsers

    if ($SkipPasswordChange) {
        Write-Status -Level Skip 'Zulu password rotation skipped (-SkipPasswordChange)'
    } else {
        $script:NextStepLabel = 'Domain 3/13'
        Set-ZuluPassword -SaltPhrase $SaltPhrase
    }

    Write-Banner 'Link domain policies' -Style Inline -Log
    $script:NextStepLabel = 'Domain 4/13'
    Link-DcAllowAdGpo -BackupRoot $backupRoot

    $script:NextStepLabel = 'Domain 5/13'
    Link-DomainFirewallGpo -BackupRoot $backupRoot

    $script:NextStepLabel = 'Domain 6/13'
    Link-DomainSplunkOutboundGpo -BackupRoot $backupRoot

    $script:NextStepLabel = 'Domain 7/13'
    Link-DomainGpoUpdateInterval -BackupRoot $backupRoot

    $script:NextStepLabel = 'Domain 8/13'
    Link-DomainGoodGpo -BackupRoot $backupRoot

    $roleDefinitions = @(
        @{ Role = 'Database'; Label = 'Database'; Step = 'Domain 9/13' }
        @{ Role = 'Web';      Label = 'Web';      Step = 'Domain 9/13' }
        @{ Role = 'Mail';     Label = 'Mail';     Step = 'Domain 9/13' }
        @{ Role = 'WinRM';    Label = 'WinRM management'; Step = 'Domain 9/13' }
    )
    foreach ($definition in $roleDefinitions) {
        $servers = @()
        $roleKey = $definition.Role
        if ($RoleServers.ContainsKey($roleKey)) {
            $servers = @($RoleServers[$roleKey] | Where-Object { $_ })
        } elseif (-not $NoPrompt) {
            $computers = @(Get-ADComputer -Filter * -Properties OperatingSystem, Enabled, PrimaryGroupID -ErrorAction Stop |
                Where-Object { $_.Enabled -and $_.OperatingSystem -match 'Server' } |
                Sort-Object Name)
            if ($computers.Count -gt 0) {
                $optionNumber = 0
                $options = @($computers | ForEach-Object {
                    $optionNumber++
                    $dcMarker = if ($_.PrimaryGroupID -eq 516) { ' - domain controller' } else { '' }
                    @{ Key = "$optionNumber"; Label = "{0}{1}{2}" -f $_.Name, $(if ($_.OperatingSystem) { " - $($_.OperatingSystem)" } else { '' }), $dcMarker; Value = $_.Name }
                })
                $servers = Read-Choice -Title "$($definition.Label) servers" `
                    -Prompt "Select computers that need the $($definition.Label) policy" `
                    -Options $options -Multiple -AllowEmpty -Hint 'Enter one or more option numbers (for example 1,3); Enter = none'
                if ($null -eq $servers) { $servers = @() }
            }
        }

        if ($servers.Count -gt 0) {
            $script:NextStepLabel = $definition.Step
            if ($roleKey -eq 'WinRM') {
                Link-ServerWinRMGpo -ComputerName $servers -RemoteAddress $WinRMRemoteAddress
            } else {
                Link-ServerRoleGpo -Role $roleKey -ComputerName $servers -BackupRoot $backupRoot
            }
        } else {
            Write-Status -Level Skip "No $($definition.Label) servers selected; role GPO not linked" -LogMessage "No $($definition.Role) role servers selected"
        }
    }

    $script:NextStepLabel = 'Domain 10/13'
    foreach ($portRule in $FirewallPortRulesToAdd) {
        Add-DomainFirewallPortRule @portRule
    }
    foreach ($portRuleName in $FirewallPortRulesToRemove) {
        Remove-DomainFirewallPortRule -Name $portRuleName
    }
    if ($FirewallPortRulesToAdd.Count -eq 0 -and $FirewallPortRulesToRemove.Count -eq 0) {
        Write-Status -Level Skip 'No additional domain firewall port rules requested'
    }

    Write-Banner 'Refresh Group Policy' -Style Inline -Log
    $script:NextStepLabel = 'Domain 11/13'
    Invoke-HardeningOperation -OperationName 'Refresh Group Policy' -ScriptBlock {
        try {
            Invoke-CcdcGpUpdate
            Write-Status -Level Success 'gpupdate /force completed successfully'
        } catch {
            Write-Status -Level Warning "gpupdate /force failed; continuing: $($_.Exception.Message)" -LogMessage "gpupdate /force failed: $($_.Exception.Message)"
            throw
        }
    }

    Write-Banner 'Final configuration' -Style Inline -Log
    if ($SkipSplunk) {
        Write-Status -Level Skip 'Splunk installation skipped (-SkipSplunk)'
    } else {
        if (-not $SplunkIP) { $SplunkIP = Read-HostAddress -Prompt 'Splunk server IP' }
        $script:NextStepLabel = 'Domain 12/13'
        Install-Splunk -IP $SplunkIP
    }

    if ($SkipPasswordChange) {
        Write-Status -Level Skip 'CCDC account creation skipped (-SkipPasswordChange)'
    } else {
        $script:NextStepLabel = 'Domain 13/13'
        Create-CCDCUsers -SaltPhrase $SaltPhrase
    }

    Write-Banner 'Domain Hardening Complete' -Style Inline -Color Green -Log
    Show-OperationSummary
    $newErrorCount = $global:Error.Count - $errorCountAtStart
    if ($newErrorCount -gt 0) {
        Write-Status -Level Warning "$newErrorCount error record(s) were written during this run" -LogMessage "Domain hardening recorded $newErrorCount error record(s)"
    }
    Write-Status "Log file location: $script:LogFile"
}
