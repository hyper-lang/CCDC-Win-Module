function Invoke-HardeningMenu {
    <#
    .SYNOPSIS
        Interactive menu for running individual hardening steps or sections.
    .DESCRIPTION
        Loops until Q. Option 1 runs the full sequence (Invoke-WindowsHardening, which
        starts a new log); 2-4 run one section; 5-18 run single steps. With -Force and
        -Selection, runs one option and returns (no loop).
    #>
    [CmdletBinding()]
    param(
        [switch]$Force,

        [string]$Selection,

        [int[]]$FirewallPorts,

        [switch]$PreserveManagementPort,

        [string]$SplunkIP,

        [string]$SaltPhrase
    )

    function Show-Menu {
        Write-Host "`n==== Windows Hardening Menu ====" -ForegroundColor Green
        Write-Host "Setup runs automatically on the first task; (A) re-runs it (new log file)." -ForegroundColor Yellow

        Write-Host "`n--- Orchestrators (run a full section) ---" -ForegroundColor Magenta
        Write-Host "  1) Harden Everything  - Invoke-WindowsHardening (all sections, new log)"
        Write-Host "  2) Harden Users       - admin removal, passwords, RDP reset, credentials"
        Write-Host "  3) Harden Network     - firewall + remove remote management"
        Write-Host "  4) Harden Services    - SMB hardening + disable unused network protocols"

        Write-Host "`n--- Users & Credentials ---" -ForegroundColor Cyan
        Write-Host "  5) Change Passwords (Zulu - no initial setup)"
        Write-Host "  6) Add Competition Users + rotate all passwords (Zulu -Initial)"
        Write-Host "  7) Remove RDP Users   - clear Remote Desktop Users group"
        Write-Host "  8) Add RDP Users      - interactively add users to RDP group"
        Write-Host "  9) Remove Admin Users - strip extra local/AD admin privileges"
        Write-Host " 10) Patch Mimikatz     - disable WDigest credential caching"

        Write-Host "`n--- Network & Remote Access ---" -ForegroundColor Cyan
        Write-Host " 11) Configure Firewall"
        Write-Host " 12) Remove Remote Management - disable WinRM, RDP, Remote Registry, SSH"

        Write-Host "`n--- Services ---" -ForegroundColor Cyan
        Write-Host " 13) Disable Unused Network Protocols (IPv6, NetBIOS)"
        Write-Host " 14) Upgrade SMB (enable v2/3, disable v1, enforce signing)"

        Write-Host "`n--- Logging & Patching ---" -ForegroundColor Cyan
        Write-Host " 15) Enable Advanced Auditing + Firewall Logging"
        Write-Host " 16) Configure Splunk"
        Write-Host " 17) Install EternalBlue Patch"
        Write-Host " 18) Set Execution Policy to Restricted"

        Write-Host "`n--- Misc ---" -ForegroundColor Cyan
        Write-Host "  A) Re-run setup (check data files, new log file; OS/DC detection runs at import)"
        Write-Host "  0) Print Execution Summary"
        Write-Host ""
        Write-Host "  Q) Quit" -ForegroundColor DarkGray
    }

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
                Invoke-WindowsHardening -FirewallPorts $FirewallPorts -PreserveManagementPort:$PreserveManagementPort -SplunkIP $SplunkIP -SaltPhrase $SaltPhrase
            }
            '2'  {
                Write-Host "`n*** Harden Users & Credentials ***" -ForegroundColor Magenta
                Invoke-UserHardening -SaltPhrase $SaltPhrase
            }
            '3'  {
                Write-Host "`n*** Harden Network & Remote Access ***" -ForegroundColor Magenta
                Invoke-NetworkHardening -FirewallPorts $FirewallPorts -PreserveManagementPort:$PreserveManagementPort
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
                Set-FirewallConfiguration -FirewallPorts $FirewallPorts -PreserveManagementPort:$PreserveManagementPort
            }
            '12' {
                Write-Host "`n*** Removing Remote Management Channels ***" -ForegroundColor Magenta
                if ($PreserveManagementPort) {
                    Write-Host "This will disable RDP, Remote Registry, and SSH (WinRM kept: -PreserveManagementPort)." -ForegroundColor Yellow
                } else {
                    Write-Host "This will disable WinRM, RDP, Remote Registry, and SSH." -ForegroundColor Yellow
                }
                Write-Host "If you are connected via RDP or WinRM, your session may end." -ForegroundColor Yellow
                $confirm = Read-Host "Continue? (y/n)"
                if ($confirm -eq 'y') {
                    Remove-RemoteManagement -SkipWinRM:$PreserveManagementPort
                } else {
                    Write-Host "Cancelled." -ForegroundColor Yellow
                }
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
                $SplunkVersion = Read-Host "`nInput OS Version (7, 8, 10, 11, 2012, 2016, 2019, 2022)"
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
        Show-Menu
        $choice = Read-Host "Selection"
        if ($choice -match '^(?i)q$') { break }

        try {
            Invoke-MenuAction -Choice $choice
        } catch {
            Write-Host $_.Exception.Message -ForegroundColor Yellow
            Write-Host "Error Occurred..." -ForegroundColor Red
            Write-Log -Level "ERROR" -Message "Menu operation error: $($_.Exception.Message)" -Console
        }

        Write-Host "`nPress Enter to return to menu..." -ForegroundColor DarkGray
        Read-Host | Out-Null
    }
}
