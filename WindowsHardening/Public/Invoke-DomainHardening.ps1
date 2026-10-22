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
        computer accounts. The domain firewall policy is filtered to Domain Computers,
        which excludes domain controllers. WinRM is left running by this sequence.
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
        Hashtable mapping role names (Splunk, Database, Web, Mail) to computer names.
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
        $script:NextStepLabel = 'Domain 1/11'
        Set-AdministratorPassword -SaltPhrase $SaltPhrase
    }

    $script:NextStepLabel = 'Domain 2/11'
    Remove-AdminUsers

    if ($SkipPasswordChange) {
        Write-Status -Level Skip 'Zulu password rotation skipped (-SkipPasswordChange)'
    } else {
        $script:NextStepLabel = 'Domain 3/11'
        Set-ZuluPassword -SaltPhrase $SaltPhrase
    }

    Write-Banner 'Link domain policies' -Style Inline -Log
    $script:NextStepLabel = 'Domain 4/11'
    Link-DcAllowAdGpo -BackupRoot $backupRoot

    $script:NextStepLabel = 'Domain 5/11'
    Link-DomainFirewallGpo -BackupRoot $backupRoot

    $script:NextStepLabel = 'Domain 6/11'
    Link-DomainGpoUpdateInterval -BackupRoot $backupRoot

    $script:NextStepLabel = 'Domain 7/11'
    Link-DomainGoodGpo -BackupRoot $backupRoot

    $roleDefinitions = @(
        @{ Role = 'Splunk';   Label = 'Splunk';   Step = 'Domain 8/11' }
        @{ Role = 'Database'; Label = 'Database'; Step = 'Domain 8/11' }
        @{ Role = 'Web';      Label = 'Web';      Step = 'Domain 8/11' }
        @{ Role = 'Mail';     Label = 'Mail';     Step = 'Domain 8/11' }
        @{ Role = 'WinRM';    Label = 'WinRM management'; Step = 'Domain 8/11' }
    )
    foreach ($definition in $roleDefinitions) {
        $servers = @()
        $roleKey = $definition.Role
        if ($RoleServers.ContainsKey($roleKey)) {
            $servers = @($RoleServers[$roleKey] | Where-Object { $_ })
        } elseif (-not $NoPrompt) {
            $domainControllerDns = @(Get-ADDomainController -Filter * -ErrorAction Stop | ForEach-Object { $_.ComputerObjectDN })
            $computers = @(Get-ADComputer -Filter * -Properties OperatingSystem, Enabled -ErrorAction Stop |
                Where-Object { $_.Enabled -and $_.OperatingSystem -match 'Server' -and $_.DistinguishedName -notin $domainControllerDns } |
                Sort-Object Name)
            if ($computers.Count -gt 0) {
                $options = @($computers | ForEach-Object {
                    @{ Key = "$($_.Name)"; Label = "{0}{1}" -f $_.Name, $(if ($_.OperatingSystem) { " - $($_.OperatingSystem)" } else { '' }); Value = $_.Name }
                })
                $servers = Read-Choice -Title "$($definition.Label) servers" `
                    -Prompt "Select computers that need the $($definition.Label) policy" `
                    -Options $options -Multiple -AllowEmpty -Hint 'Select server names; Enter = none'
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

    Write-Banner 'Refresh Group Policy' -Style Inline -Log
    $script:NextStepLabel = 'Domain 9/11'
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
        $script:NextStepLabel = 'Domain 10/11'
        Install-Splunk -IP $SplunkIP
    }

    if ($SkipPasswordChange) {
        Write-Status -Level Skip 'CCDC account creation skipped (-SkipPasswordChange)'
    } else {
        $script:NextStepLabel = 'Domain 11/11'
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
