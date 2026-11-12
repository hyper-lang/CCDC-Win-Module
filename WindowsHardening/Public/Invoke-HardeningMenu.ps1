function Invoke-HardeningMenu {
    <#
    .SYNOPSIS
        Interactive menu for running individual hardening steps or sections.
    .DESCRIPTION
        Loops until Q. The main screen lists the sections; a section letter (U, N, S, L, P)
        opens that section's options. Existing option numbers stay fixed and can be typed
        from any screen: 1 runs the full sequence (Invoke-WindowsHardening, which starts a new
        log), 2-4 run one section, 5-20 run single steps. Several options can be given at
        once (e.g. 9,10,13 or 13-15) and run in the order typed. With -Force and
        -Selection, runs one option and returns (no loop).
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
    ,
        [object]$State = $null
    )
    if (-not $State) { $State = Resolve-HardeningState -State $State }


    # Menu options. Key = what is typed (and what -Selection takes); keys never change, so
    # typed numbers, -Selection, and the README stay valid. Section = the sub-menu an option
    # appears in (in this order); options without one are on the main screen.
    $menuOptions = @(
        @{ Key = '1';  Label = 'Harden Everything  - Invoke-WindowsHardening (all sections, new log)' }
        @{ Key = '2';  Section = 'U'; Label = 'Harden Users       - run all user & credential steps (Invoke-UserHardening)' }
        @{ Key = '5';  Section = 'U'; Label = 'Change Existing User Passwords (Zulu)' }
        @{ Key = '6';  Section = 'U'; Label = 'Change Administrator Password' }
        @{ Key = '7';  Section = 'U'; Label = 'Remove RDP Users   - clear Remote Desktop Users group' }
        @{ Key = '8';  Section = 'U'; Label = 'Add RDP Users      - interactively add users to RDP group' }
        @{ Key = '9';  Section = 'U'; Label = 'Remove Admin Users - strip extra local/AD admin privileges' }
        @{ Key = '10'; Section = 'U'; Label = 'Patch Mimikatz     - disable WDigest credential caching' }
        @{ Key = '20'; Section = 'U'; Label = 'Create CCDC Users  - create local/domain competition accounts' }
        @{ Key = '3';  Section = 'N'; Label = 'Harden Network     - run all network steps (Invoke-NetworkHardening)' }
        @{ Key = '11'; Section = 'N'; Label = 'Configure Firewall' }
        @{ Key = '12'; Section = 'N'; Label = 'Remove Remote Management - disable WinRM, RDP, Remote Registry, SSH' }
        @{ Key = '19'; Section = 'N'; Label = 'Add Firewall Ports - open extra ports without resetting the firewall' }
        @{ Key = '4';  Section = 'S'; Label = 'Harden Services    - run all service steps (Invoke-ServiceHardening)' }
        @{ Key = '13'; Section = 'S'; Label = 'Disable Unused Network Protocols (IPv6, NetBIOS)' }
        @{ Key = '14'; Section = 'S'; Label = 'Mitigate EternalBlue (disable SMBv1, enforce signing)' }
        @{ Key = '18'; Section = 'S'; Label = 'Set Execution Policy to Restricted' }
        @{ Key = '15'; Section = 'L'; Label = 'Enable Advanced Auditing + Firewall Logging' }
        @{ Key = '16'; Section = 'L'; Label = 'Configure Splunk' }
        @{ Key = '17'; Section = 'P'; Label = 'Install EternalBlue Patch' }
        @{ Key = 'A';  Label = 'Re-run setup (new log file)' }
        @{ Key = '0';  Label = 'Print Execution Summary' }
    )

    # Sub-menus, in main-screen order. Letters must not clash with option keys (A, Q).
    $menuSections = [ordered]@{
        U = 'Users & Credentials'
        N = 'Network & Remote Access'
        S = 'Services'
        L = 'Logging'
        P = 'Patching'
    }

    # "2, 5-10" from the option keys in a section.
    function Format-KeyRange {
        param([string[]]$Keys)
        $numbers = @($Keys | ForEach-Object { [int]$_ } | Sort-Object)
        $parts = @()
        for ($i = 0; $i -lt $numbers.Count; $i++) {
            $first = $numbers[$i]
            while ($i + 1 -lt $numbers.Count -and $numbers[$i + 1] -eq $numbers[$i] + 1) { $i++ }
            $parts += if ($numbers[$i] -gt $first + 1) { "$first-$($numbers[$i])" }
                      elseif ($numbers[$i] -eq $first + 1) { "$first, $($numbers[$i])" }
                      else { "$first" }
        }
        $parts -join ', '
    }

    # Read-Choice options for one screen: that screen's options listed, every other option
    # hidden but still typeable (so any number works from any screen).
    function Get-ScreenOptions {
        param([string]$Section)
        $listed = @()
        $hidden = @()
        foreach ($option in $menuOptions) {
            $entry = @{ Key = $option.Key; Label = $option.Label; Value = $option.Key }
            if ("$($option.Section)" -eq $Section) { $listed += $entry } else { $entry.Hidden = $true; $hidden += $entry }
        }
        if (-not $Section) {
            # Main screen: sections after "Harden Everything", before A and 0.
            $sectionEntries = foreach ($letter in $menuSections.Keys) {
                $keys = @($menuOptions | Where-Object { $_.Section -eq $letter } | ForEach-Object { $_.Key })
                @{ Key = $letter; Label = "{0,-24} ({1})" -f $menuSections[$letter], (Format-KeyRange $keys); Value = "section:$letter" }
            }
            $listed = @($listed[0]) + @($sectionEntries) + @($listed | Select-Object -Skip 1)
        }
        $listed + $hidden
    }

    function Invoke-MenuAction {
        param(
            [string]$Choice
        ,
        [object]$State = $null
    )
    if (-not $State) { $State = Resolve-HardeningState -State $State }


        # Header from the option's label, also written to the log, so the log shows which
        # menu option ran (not only the operations inside it).
        $option = $menuOptions | Where-Object { $_.Key -eq $Choice.ToUpper() } | Select-Object -First 1
        if ($option) {
            Write-Banner ("Menu {0}: {1}" -f $option.Key, ($option.Label -replace '\s{2,}', ' ')) -Style Inline -Color Magenta -Log -State $State
        }

        switch ($Choice.ToUpper()) {
            '0'  { Show-OperationSummary -State $State }
            'A'  { Initialize-System -Force -State $State }

            # -- Orchestrators ------------------------------------------------
            '1'  {
                Invoke-WindowsHardening -FirewallPorts $FirewallPorts -AdditionalPorts $AdditionalPorts -PreserveManagementPort:$PreserveManagementPort -SplunkIP $SplunkIP -SaltPhrase $SaltPhrase -State $State
            }
            '2'  {
                Invoke-UserHardening -SaltPhrase $SaltPhrase -State $State
            }
            '3'  {
                Invoke-NetworkHardening -FirewallPorts $FirewallPorts -AdditionalPorts $AdditionalPorts -PreserveManagementPort:$PreserveManagementPort -State $State
            }
            '4'  {
                Invoke-ServiceHardening -State $State
            }

            # -- Users & Credentials ------------------------------------------
            '5'  {
                Set-ZuluPassword -SaltPhrase $SaltPhrase -State $State
            }
            '6'  {
                Set-AdministratorPassword -SaltPhrase $SaltPhrase -State $State
            }
            '7'  {
                Remove-RDPUsers -State $State
            }
            '8'  {
                Add-RDPUsers -State $State
            }
            '9'  {
                Remove-AdminUsers -State $State
            }
            '10' {
                Protect-Mimikatz -State $State
            }

            # -- Network & Remote Access --------------------------------------
            '11' {
                Set-FirewallConfiguration -FirewallPorts $FirewallPorts -AdditionalPorts $AdditionalPorts -PreserveManagementPort:$PreserveManagementPort -State $State
            }
            '12' {
                if ($PreserveManagementPort) {
                    Write-Host "This will disable RDP, Remote Registry, and SSH (WinRM kept: -PreserveManagementPort)." -ForegroundColor Yellow
                } else {
                    Write-Host "This will disable WinRM, RDP, Remote Registry, and SSH." -ForegroundColor Yellow
                }
                Write-Host "If you are connected via RDP or WinRM, your session may end." -ForegroundColor Yellow
                if ((Read-YesNo -Message "Continue? (y/n) " -State $State) -eq 'y') {
                    Remove-RemoteManagement -SkipWinRM:$PreserveManagementPort -State $State
                } else {
                    Write-Status -Level Skip "Cancelled" -State $State
                }
            }
            '19' {
                Initialize-System -State $State   # loads ports.json so the list shows port descriptions
                $isDC = $State.Context.OS.IsDomainController
                $portInput = if ($AdditionalPorts) { $AdditionalPorts } else {
                    Read-Choice -Title "Ports to open" -Prompt "Ports" -Options @(Get-FirewallPortOptions) -State $State `
                        -Multiple -AllowCustom -AllowQuit `
                        -ValidateCustom { param($value) (ConvertTo-PortList -Ports $value)[0] }
                }
                if (-not $portInput) {
                    Write-Status -Level Skip "Cancelled" -State $State
                    return
                }
                $protocol = Read-Choice -Prompt "Protocol" -Default $(if ($isDC) { 'B' } else { 'T' }) -Options @(
                    @{ Key = 'T'; Label = 'TCP'; Value = 'TCP' }
                    @{ Key = 'U'; Label = 'UDP'; Value = 'UDP' }
                    @{ Key = 'B'; Label = 'Both'; Value = 'Both' }
                ) -State $State
                Add-FirewallPort -Ports $portInput -Protocol $protocol -State $State
            }
            '20' {
                Create-CCDCUsers -SaltPhrase $SaltPhrase -State $State
            }

            # -- Services -----------------------------------------------------
            '13' {
                Disable-UnusedNetworkProtocols -State $State
            }
            '14' {
                Mitigate-EternalBlue -State $State
            }

            # -- Monitoring & Patching -----------------------------------------
            '15' {
                Enable-AdvancedAuditing -State $State
                # Also set separately so logging is on even if auditing fails partway.
                try {
                    Set-NetFirewallProfile -Name Domain,Public,Private -LogAllowed True -LogBlocked True
                    Write-Status -Level Success "Firewall logging enabled (allowed + blocked)" -LogMessage "Enabled firewall logging" -State $State
                } catch {
                    Write-Status -Level Warning "Could not enable firewall logging: $($_.Exception.Message)" -State $State
                }
            }
            '16' {
                $ip = if ($SplunkIP) { $SplunkIP } else { Read-HostAddress -Prompt "Splunk server IP" -State $State }
                # splunk.ps1 detects the Windows version itself.
                Install-Splunk -IP $ip -State $State
            }
            '17' {
                Install-EternalBluePatch -State $State
            }
            '18' {
                Set-RestrictedExecutionPolicy -State $State
            }

            Default {
                Write-Status -Level Warning "Invalid selection: '$Choice'" -NoLog -State $State
            }
        }
    }

    # Every option changes system settings; check before showing anything.
    if (-not (Test-IsAdministrator)) {
        throw "Invoke-HardeningMenu must be run as Administrator (start PowerShell with 'Run as administrator')."
    }

    if ($Force) {
        if ([string]::IsNullOrEmpty($Selection)) {
            Write-Status -Level Error "-Force requires -Selection" -NoLog -State $State
            return
        }
        try {
            Invoke-MenuAction -Choice $Selection -State $State
        } catch {
            Write-Status -Level Error "Menu option $Selection failed: $($_.Exception.Message)" -State $State
            Flush-HardeningLog -State $State
        }
        Flush-HardeningLog -State $State
        return
    }

    while ($true) {
        Write-Banner "Windows Hardening Menu" -Style Inline -Color Green -State $State
        Write-Host "Setup runs automatically on the first task; (A) re-runs it (new log file)." -ForegroundColor Yellow
        $picked = Read-Choice -Prompt "Selection" -Options (Get-ScreenOptions) -Multiple -AllowQuit -QuitLabel 'Quit' `
            -Hint 'a letter opens a section; option numbers work here too, e.g. 9,10,13 or 13-15' -State $State
        if ($null -eq $picked) { break }

        # Section letters open a sub-menu (Q there goes back); numbers run directly.
        # Everything runs in the order typed.
        $choices = @(foreach ($item in $picked) {
            if ("$item" -like 'section:*') {
                $letter = "$item".Substring(8)
                $sub = Read-Choice -Title $menuSections[$letter] -Prompt "Selection" -Options (Get-ScreenOptions -Section $letter) `
                    -Multiple -AllowQuit -QuitLabel 'Back' -Hint 'one or more, e.g. 9,10; any option number works here' -State $State
                if ($null -ne $sub) { $sub }
            } else {
                $item
            }
        })
        if ($choices.Count -eq 0) { continue }

        foreach ($choice in $choices) {
            try {
                Invoke-MenuAction -Choice $choice -State $State
            } catch {
                Write-Status -Level Error "Menu option $choice failed: $($_.Exception.Message)" -State $State
                Flush-HardeningLog -State $State
            }
        }
        Flush-HardeningLog -State $State

        Write-Host "`nPress Enter to return to menu..." -ForegroundColor DarkGray
        Read-Host | Out-Null
    }
    Flush-HardeningLog -State $State
}
