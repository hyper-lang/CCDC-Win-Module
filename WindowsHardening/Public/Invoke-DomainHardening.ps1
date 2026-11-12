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
        replication rules on top of it. The domain-wide baseline links are enforced so
        OU-linked GPOs and Block Inheritance cannot override them.
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
    .PARAMETER GpoBackupPath
        Parent folder for the timestamped backup of the domain's existing GPOs.
        Defaults to the hardening log folder.
    .PARAMETER RoleServers
        Hashtable mapping role names to computer names. Database creates an MSSQL firewall
        GPO (TCP 1433 and UDP 1434); Web and Mail use bundled firewall GPOs. WinRM, SSH,
        RDP, FTP, SMB, Ping, and SNMP create role GPOs. Service roles configure startup
        where applicable; RDP, SSH, and WinRM grant Domain Users membership in the
        corresponding local access group. Application and database permissions still
        require product-specific configuration.
        If omitted, the run offers computer selections for each role. Use -NoPrompt to
        skip role assignments when running unattended.
    .PARAMETER WinRMRemoteAddress
        Remote address or CIDR entries allowed to manage selected WinRM servers.
        Defaults to Any for WinRM GPOs linked by Invoke-DomainHardening.
    .PARAMETER RoleRemoteAddress
        Hashtable of remote address scopes for Database, WinRM, SSH, RDP, FTP, SMB, Ping,
        and SNMP roles, for example @{ RDP = 'LocalSubnet' }. Unlisted roles use Any
        (WinRM uses -WinRMRemoteAddress).
    .PARAMETER NoPrompt
        Skip server role selection prompts. If Splunk is not skipped, pass -SplunkIP.
    .PARAMETER SplunkIP
        Splunk indexer address. Prompts if omitted and Splunk installation is enabled.
    .PARAMETER SkipSplunk
        Skip the final Splunk installation step.
    .PARAMETER SkipSplunkOutbound
        Do not link the domain Splunk outbound firewall GPO. This does not skip Splunk
        installation; use -SkipSplunk separately to skip installation.
    .PARAMETER FirewallPortRulesToAdd
        Optional hashtables passed to Add-DomainFirewallPortRule. Each needs Name,
        ComputerName, and Port (ports and/or ranges such as '50000-50100'); Protocol,
        Direction, and RemoteAddress are optional.
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
    .EXAMPLE
        Invoke-DomainHardening -SkipSplunkOutbound -SkipSplunk
        # Runs the hardening sequence without linking Splunk egress or installing Splunk.
    #>
    [CmdletBinding()]
    param(
        [switch]$SkipPasswordChange,
        [string]$SaltPhrase,
        [string]$GpoZipPath,
        [string]$GpoCachePath,
        [string]$GpoBackupPath,
        [hashtable]$RoleServers = @{},
        [string[]]$WinRMRemoteAddress = @('Any'),
        [hashtable]$RoleRemoteAddress = @{},
        [switch]$NoPrompt,
        [string]$SplunkIP,
        [switch]$SkipSplunk,
        [switch]$SkipSplunkOutbound,
        [hashtable[]]$FirewallPortRulesToAdd = @(),
        [string[]]$FirewallPortRulesToRemove = @(),
        [string]$LogPath
    ,
        [object]$State = $null
    ,
        [string]$StepLabel
    )

    if (-not $State) { $State = Resolve-HardeningState -State $State }

    if (-not $State.Context.OS -or -not $State.Context.OS.IsDomainController) {
        throw 'Invoke-DomainHardening must be run on a domain controller.'
    }
    if ($NoPrompt -and -not $SkipSplunk -and -not $SplunkIP) {
        throw 'Pass -SplunkIP or -SkipSplunk when using -NoPrompt.'
    }
    if ($SplunkIP -and -not (Test-HostAddress ($SplunkIP -replace ':\d+$', ''))) {
        throw "Invalid -SplunkIP '$SplunkIP': not an IP address or host name"
    }

    $errorCountAtStart = $global:Error.Count
    Write-Banner 'Domain Hardening' -State $State
    Initialize-System -Force -LogPath $LogPath -State $State

    try {
        Test-Prerequisites -State $State
    } catch {
        Write-Status -Level Error "Domain hardening pre-flight failed: $($_.Exception.Message)" -State $State
        Flush-HardeningLog -State $State
        throw
    }

    if ($SkipPasswordChange) {
        Write-Status -Level Skip 'Administrator password change, Zulu rotation, and CCDC account creation skipped (-SkipPasswordChange)' -State $State
    } else {
        Set-AdministratorPassword -SaltPhrase $SaltPhrase -State $State -StepLabel 'Domain 1/13'
        Set-ZuluPassword -SaltPhrase $SaltPhrase -State $State -StepLabel 'Domain 2/13'
    }

    # Run password operations before downloading the packaged GPO archive or
    # explicitly importing the GroupPolicy/ActiveDirectory modules for GPO setup.
    try {
        Initialize-CcdcGpoEnvironment -GpoZipPath $GpoZipPath -GpoCachePath $GpoCachePath | Out-Null
        $backupRoot = if ($GpoCachePath) { Join-Path $GpoCachePath 'Backups' } else { Join-Path ([System.IO.Path]::GetTempPath()) 'CCDC-GPOs\Backups' }
        $domainGpoBackup = Backup-DomainGpos -Path $GpoBackupPath -State $State
        Write-Status "Pre-hardening domain GPO backup: $domainGpoBackup" -State $State
    } catch {
        Write-Status -Level Error "Domain hardening pre-flight failed: $($_.Exception.Message)" -State $State
        Flush-HardeningLog -State $State
        throw
    }

    Remove-AdminUsers -State $State -StepLabel 'Domain 3/13'

    Write-Banner 'Pre-linking VSS snapshot' -Style Inline -Log -State $State
    $null = New-HardeningVssSnapshot -State $State

    Write-Banner 'Link domain policies' -Style Inline -Log -State $State
    Link-DcAllowAdGpo -BackupRoot $backupRoot -State $State -StepLabel 'Domain 4/13'

    Link-DomainFirewallGpo -BackupRoot $backupRoot -State $State -StepLabel 'Domain 5/13'

    if ($SkipSplunkOutbound) {
        Write-Status -Level Skip 'Domain Splunk outbound firewall GPO skipped (-SkipSplunkOutbound)' -State $State
    } else {
        Link-DomainSplunkOutboundGpo -BackupRoot $backupRoot -State $State -StepLabel 'Domain 6/13'
    }

    Link-DomainGpoUpdateInterval -BackupRoot $backupRoot -State $State -StepLabel 'Domain 7/13'

    Link-DomainGoodGpo -BackupRoot $backupRoot -State $State -StepLabel 'Domain 8/13'

    $roleDefinitions = @(
        @{ Role = 'Database'; Label = 'Database'; Step = 'Domain 9/13' }
        @{ Role = 'Web';      Label = 'Web';      Step = 'Domain 9/13' }
        @{ Role = 'Mail';     Label = 'Mail';     Step = 'Domain 9/13' }
        @{ Role = 'WinRM';    Label = 'WinRM management'; Step = 'Domain 9/13' }
        @{ Role = 'SSH';      Label = 'SSH';      Step = 'Domain 9/13' }
        @{ Role = 'RDP';      Label = 'RDP';      Step = 'Domain 9/13' }
        @{ Role = 'FTP';      Label = 'FTP (IIS FTP service)'; Step = 'Domain 9/13' }
        @{ Role = 'SMB';      Label = 'SMB file sharing'; Step = 'Domain 9/13' }
        @{ Role = 'Ping';     Label = 'Ping'; Step = 'Domain 9/13' }
        @{ Role = 'SNMP';     Label = 'SNMP'; Step = 'Domain 9/13' }
    )
    foreach ($definition in $roleDefinitions) {
        $servers = @()
        $roleKey = $definition.Role
        if ($RoleServers.ContainsKey($roleKey)) {
            $servers = @($RoleServers[$roleKey] | Where-Object { $_ })
        } elseif (-not $NoPrompt) {
            $computers = @(Get-ADComputer -Filter * -Properties OperatingSystem, Enabled, PrimaryGroupID -ErrorAction Stop |
                Where-Object { $_.Enabled -and $_.OperatingSystem -match '^Windows (Server|10|11)\b' } |
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
                    -Options $options -Multiple -AllowEmpty -Hint 'Enter one or more option numbers (for example 1,3)' -State $State
                if ($null -eq $servers) { $servers = @() }
            }
        }

        if ($servers.Count -gt 0) {
            if ($roleKey -in @('Web', 'Mail')) {
                Link-ServerRoleGpo -Role $roleKey -ComputerName $servers -BackupRoot $backupRoot -State $State -StepLabel $definition.Step
            } else {
                $remoteAddress = if ($RoleRemoteAddress.ContainsKey($roleKey)) { @($RoleRemoteAddress[$roleKey]) }
                    elseif ($roleKey -eq 'WinRM') { $WinRMRemoteAddress }
                    else { $null }
                Link-ServerServiceGpo -Role $roleKey -ComputerName $servers -RemoteAddress $remoteAddress -State $State -StepLabel $definition.Step
            }
        } else {
            Write-Status -Level Skip "No $($definition.Label) servers selected; role GPO not linked" -LogMessage "No $($definition.Role) role servers selected" -State $State
        }
    }

    foreach ($portRule in $FirewallPortRulesToAdd) {
        Add-DomainFirewallPortRule @portRule -State $State -StepLabel 'Domain 10/13'
    }
    foreach ($portRuleName in $FirewallPortRulesToRemove) {
        Remove-DomainFirewallPortRule -Name $portRuleName -State $State -StepLabel 'Domain 10/13'
    }
    if ($FirewallPortRulesToAdd.Count -eq 0 -and $FirewallPortRulesToRemove.Count -eq 0) {
        Write-Status -Level Skip 'No additional domain firewall port rules requested' -State $State
    }

    Write-Banner 'Refresh Group Policy' -Style Inline -Log -State $State
    Invoke-HardeningOperation -State $State -OperationName 'Refresh Group Policy' -StepLabel 'Domain 11/13' -ScriptBlock {
        try {
            Invoke-CcdcGpUpdate
            Write-Status -Level Success 'gpupdate /force completed successfully' -State $State
        } catch {
            Write-Status -Level Warning "gpupdate /force failed; continuing: $($_.Exception.Message)" -LogMessage "gpupdate /force failed: $($_.Exception.Message)" -State $State
            throw
        }
    }

    Write-Banner 'Final configuration' -Style Inline -Log -State $State
    if ($SkipSplunk) {
        Write-Status -Level Skip 'Splunk installation skipped (-SkipSplunk)' -State $State
    } else {
        if (-not $SplunkIP) { $SplunkIP = Read-HostAddress -Prompt 'Splunk server IP' -State $State }
        Install-Splunk -IP $SplunkIP -State $State -StepLabel 'Domain 12/13'
    }

    if ($SkipPasswordChange) {
        Write-Status -Level Skip 'CCDC account creation skipped (-SkipPasswordChange)' -State $State
    } else {
        Create-CCDCUsers -SaltPhrase $SaltPhrase -State $State -StepLabel 'Domain 13/13'
    }

    Write-Banner 'Domain Hardening Complete' -Style Inline -Color Green -Log -State $State
    Show-OperationSummary -State $State
    $newErrorCount = $global:Error.Count - $errorCountAtStart
    if ($newErrorCount -gt 0) {
        Write-Status -Level Warning "$newErrorCount error record(s) were written during this run" -LogMessage "Domain hardening recorded $newErrorCount error record(s)" -State $State
    }
    Write-Status "Log file location: $($State.LogFile)" -State $State
    Flush-HardeningLog -State $State
}
