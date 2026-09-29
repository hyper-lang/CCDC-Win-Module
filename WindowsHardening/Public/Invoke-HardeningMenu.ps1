function Invoke-HardeningMenu {
    <#
    .SYNOPSIS
        Interactive menu for running individual hardening steps or sections.
    .DESCRIPTION
        Loops until Q. Option 1 runs the full sequence (Invoke-WindowsHardening, which
        starts a new log); 2-4 run one section; 5-19 run single steps. Several options can
        be given at once (e.g. 9,10,13 or 13-15) and run in the order typed. With -Force
        and -Selection, runs one option and returns (no loop).
    #>
    [CmdletBinding()]
    param(
        [switch]$Force,

        [string]$Selection,

        [int[]]$FirewallPorts,

        [int[]]$AdditionalPorts,

        [switch]$PreserveManagementPort,

        [string]$SplunkIP,

        [string]$SaltPhrase
    )

    # Menu options, in display order. Key = what is typed (and what -Selection takes).
    $menuOptions = @(
        @{ Key = '1';  Section = 'Orchestrators (run a full section)'; Label = 'Harden Everything  - Invoke-WindowsHardening (all sections, new log)' }
        @{ Key = '2';  Section = 'Orchestrators (run a full section)'; Label = 'Harden Users       - admin removal, passwords, RDP reset, credentials' }
        @{ Key = '3';  Section = 'Orchestrators (run a full section)'; Label = 'Harden Network     - firewall + remove remote management' }
        @{ Key = '4';  Section = 'Orchestrators (run a full section)'; Label = 'Harden Services    - SMB hardening + disable unused network protocols' }
        @{ Key = '5';  Section = 'Users & Credentials'; Label = 'Change Passwords (Zulu - no initial setup)' }
        @{ Key = '6';  Section = 'Users & Credentials'; Label = 'Add Competition Users + rotate all passwords (Zulu -Initial)' }
        @{ Key = '7';  Section = 'Users & Credentials'; Label = 'Remove RDP Users   - clear Remote Desktop Users group' }
        @{ Key = '8';  Section = 'Users & Credentials'; Label = 'Add RDP Users      - interactively add users to RDP group' }
        @{ Key = '9';  Section = 'Users & Credentials'; Label = 'Remove Admin Users - strip extra local/AD admin privileges' }
        @{ Key = '10'; Section = 'Users & Credentials'; Label = 'Patch Mimikatz     - disable WDigest credential caching' }
        @{ Key = '11'; Section = 'Network & Remote Access'; Label = 'Configure Firewall' }
        @{ Key = '12'; Section = 'Network & Remote Access'; Label = 'Remove Remote Management - disable WinRM, RDP, Remote Registry, SSH' }
        @{ Key = '19'; Section = 'Network & Remote Access'; Label = 'Add Firewall Ports - open extra ports without resetting the firewall' }
        @{ Key = '13'; Section = 'Services'; Label = 'Disable Unused Network Protocols (IPv6, NetBIOS)' }
        @{ Key = '14'; Section = 'Services'; Label = 'Upgrade SMB (enable v2/3, disable v1, enforce signing)' }
        @{ Key = '15'; Section = 'Logging & Patching'; Label = 'Enable Advanced Auditing + Firewall Logging' }
        @{ Key = '16'; Section = 'Logging & Patching'; Label = 'Configure Splunk' }
        @{ Key = '17'; Section = 'Logging & Patching'; Label = 'Install EternalBlue Patch' }
        @{ Key = '18'; Section = 'Logging & Patching'; Label = 'Set Execution Policy to Restricted' }
        @{ Key = 'A';  Section = 'Misc'; Label = 'Re-run setup (check data files, new log file; OS/DC detection runs at import)' }
        @{ Key = '0';  Section = 'Misc'; Label = 'Print Execution Summary' }
    )

    function Invoke-MenuAction {
        param(
            [string]$Choice
        )

        switch ($Choice.ToUpper()) {
            '0'  { Show-OperationSummary }
            'A'  { Initialize-System -Force }

            # -- Orchestrators ------------------------------------------------
            '1'  {
                Write-Host "`n*** Harden Everything (all sections) ***" -ForegroundColor Magenta
                Invoke-WindowsHardening -FirewallPorts $FirewallPorts -AdditionalPorts $AdditionalPorts -PreserveManagementPort:$PreserveManagementPort -SplunkIP $SplunkIP -SaltPhrase $SaltPhrase
            }
            '2'  {
                Write-Host "`n*** Harden Users & Credentials ***" -ForegroundColor Magenta
                Invoke-UserHardening -SaltPhrase $SaltPhrase
            }
            '3'  {
                Write-Host "`n*** Harden Network & Remote Access ***" -ForegroundColor Magenta
                Invoke-NetworkHardening -FirewallPorts $FirewallPorts -AdditionalPorts $AdditionalPorts -PreserveManagementPort:$PreserveManagementPort
            }
            '4'  {
                Write-Host "`n*** Harden Services ***" -ForegroundColor Magenta
                Invoke-ServiceHardening
            }

            # -- Users & Credentials ------------------------------------------
            '5'  {
                Write-Host "`n*** Changing Passwords (Zulu) ***" -ForegroundColor Magenta
                Set-ZuluPassword -SaltPhrase $SaltPhrase
            }
            '6'  {
                Write-Host "`n*** Adding Competition Users + Rotating All Passwords ***" -ForegroundColor Magenta
                Set-ZuluPassword -Initial -SaltPhrase $SaltPhrase
            }
            '7'  {
                Write-Host "`n*** Removing all users from Remote Desktop Users group ***" -ForegroundColor Magenta
                Remove-RDPUsers
            }
            '8'  {
                Write-Host "`n*** Adding users to Remote Desktop Users group (interactive) ***" -ForegroundColor Magenta
                Add-RDPUsers
            }
            '9'  {
                Write-Host "`n*** Removing Extra Admin Users ***" -ForegroundColor Magenta
                Remove-AdminUsers
            }
            '10' {
                Write-Host "`n*** Patching Mimikatz (WDigest) ***" -ForegroundColor Magenta
                Protect-Mimikatz
            }

            # -- Network & Remote Access --------------------------------------
            '11' {
                Write-Host "`n*** Configuring Firewall ***" -ForegroundColor Magenta
                Set-FirewallConfiguration -FirewallPorts $FirewallPorts -AdditionalPorts $AdditionalPorts -PreserveManagementPort:$PreserveManagementPort
            }
            '12' {
                Write-Host "`n*** Removing Remote Management Channels ***" -ForegroundColor Magenta
                if ($PreserveManagementPort) {
                    Write-Host "This will disable RDP, Remote Registry, and SSH (WinRM kept: -PreserveManagementPort)." -ForegroundColor Yellow
                } else {
                    Write-Host "This will disable WinRM, RDP, Remote Registry, and SSH." -ForegroundColor Yellow
                }
                Write-Host "If you are connected via RDP or WinRM, your session may end." -ForegroundColor Yellow
                if ((Read-YesNo -Message "Continue? (y/n) ") -eq 'y') {
                    Remove-RemoteManagement -SkipWinRM:$PreserveManagementPort
                } else {
                    Write-Host "Cancelled." -ForegroundColor Yellow
                }
            }
            '19' {
                Write-Host "`n*** Adding Firewall Ports ***" -ForegroundColor Magenta
                Initialize-System   # loads ports.json so the list shows port descriptions
                $isDC = $script:HardeningContext.OS.IsDomainController
                $portInput = if ($AdditionalPorts) { $AdditionalPorts } else {
                    Read-Choice -Title "Ports to open" -Prompt "Ports" -Options @(Get-FirewallPortOptions) `
                        -Multiple -AllowCustom -AllowQuit `
                        -ValidateCustom { param($value) (ConvertTo-PortList -Ports $value)[0] }
                }
                if (-not $portInput) {
                    Write-Host "Cancelled." -ForegroundColor Yellow
                    return
                }
                $protocol = Read-Choice -Prompt "Protocol" -Default $(if ($isDC) { 'B' } else { 'T' }) -Options @(
                    @{ Key = 'T'; Label = 'TCP'; Value = 'TCP' }
                    @{ Key = 'U'; Label = 'UDP'; Value = 'UDP' }
                    @{ Key = 'B'; Label = 'Both'; Value = 'Both' }
                )
                Add-FirewallPort -Ports $portInput -Protocol $protocol
            }

            # -- Services -----------------------------------------------------
            '13' {
                Write-Host "`n*** Disabling Unused Network Protocols ***" -ForegroundColor Magenta
                Disable-UnusedNetworkProtocols
            }
            '14' {
                Write-Host "`n*** Upgrading SMB ***" -ForegroundColor Magenta
                Update-SMB
            }

            # -- Monitoring & Patching -----------------------------------------
            '15' {
                Write-Host "`n*** Enabling Advanced Auditing and Firewall Logging ***" -ForegroundColor Magenta
                Enable-AdvancedAuditing
                # Also set separately so logging is on even if auditing fails partway.
                try {
                    Set-NetFirewallProfile -Name Domain,Public,Private -LogAllowed True -LogBlocked True
                    Write-Host "Firewall logging enabled (allowed + blocked)" -ForegroundColor Green
                    Write-Log -Level "SUCCESS" -Message "Enabled firewall logging"
                } catch {
                    Write-Log -Level "WARNING" -Message "Could not enable firewall logging: $($_.Exception.Message)"
                }
            }
            '16' {
                Write-Host "`n*** Configuring Splunk ***" -ForegroundColor Magenta
                $ip = if ($SplunkIP) { $SplunkIP } else { Read-Host "`nInput IP address of Splunk Server" }
                # Default to this machine's version when it is one splunk.ps1 knows.
                $versions = '7', '8', '10', '11', '2012', '2016', '2019', '2022'
                $thisVersion = "$($script:HardeningContext.OS.OSFamily)" -replace '^(Server|Client)', ''
                $SplunkVersion = Read-Choice -Prompt "OS version" -AllowCustom `
                    -Options @($versions | ForEach-Object { @{ Key = $_; Label = $_ } }) `
                    -Default $(if ($thisVersion -in $versions) { $thisVersion })
                Install-Splunk -Version $SplunkVersion -IP $ip
            }
            '17' {
                Write-Host "`n*** Installing EternalBlue Patch ***" -ForegroundColor Magenta
                Install-EternalBluePatch
            }
            '18' {
                Write-Host "`n*** Setting Execution Policy to Restricted ***" -ForegroundColor Magenta
                Set-RestrictedExecutionPolicy
            }

            Default {
                Write-Host "Invalid selection: '$Choice'" -ForegroundColor Yellow
            }
        }
    }

    # Every option changes system settings; check before showing anything.
    if (-not (Test-IsAdministrator)) {
        throw "Invoke-HardeningMenu must be run as Administrator (start PowerShell with 'Run as administrator')."
    }

    if ($Force) {
        if ([string]::IsNullOrEmpty($Selection)) {
            Write-Host "Error: -Force requires -Selection parameter." -ForegroundColor Red
            return
        }
        try {
            Invoke-MenuAction -Choice $Selection
        } catch {
            Write-Host $_.Exception.Message -ForegroundColor Yellow
            Write-Host "Error Occurred..." -ForegroundColor Red
            Write-Log -Level "ERROR" -Message "Menu operation error: $($_.Exception.Message)" -Console
        }
        return
    }

    while ($true) {
        Write-Banner "Windows Hardening Menu" -Style Inline -Color Green
        Write-Host "Setup runs automatically on the first task; (A) re-runs it (new log file)." -ForegroundColor Yellow
        $choices = Read-Choice -Prompt "Selection" -Options $menuOptions -Multiple -AllowQuit -QuitLabel 'Quit'
        if ($null -eq $choices) { break }

        # Several options (e.g. 9,10,13) run in the order typed.
        foreach ($choice in $choices) {
            try {
                Invoke-MenuAction -Choice $choice
            } catch {
                Write-Host $_.Exception.Message -ForegroundColor Yellow
                Write-Host "Error Occurred..." -ForegroundColor Red
                Write-Log -Level "ERROR" -Message "Menu operation error: $($_.Exception.Message)" -Console
            }
        }

        Write-Host "`nPress Enter to return to menu..." -ForegroundColor DarkGray
        Read-Host | Out-Null
    }
}
