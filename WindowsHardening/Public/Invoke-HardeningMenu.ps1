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
    )

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
        @{ Key = 'B';  Label = 'Browse folders and run a function' }
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

    function Invoke-FolderBrowser {
        $publicPath = Join-Path $PSScriptRoot 'Public'
        $devPath = Join-Path $PSScriptRoot 'Dev'
        $folders = @(
            Get-ChildItem -Path $publicPath -Directory -ErrorAction SilentlyContinue |
                Where-Object Name -ne 'GPO' |
                Sort-Object Name |
                ForEach-Object { [pscustomobject]@{ Name = "Public/$($_.Name)"; Path = $_.FullName } }
        )
        if (Test-Path -LiteralPath $devPath -PathType Container) {
            $folders += [pscustomobject]@{ Name = 'Dev'; Path = $devPath }
        }

        $folderOptions = @($folders | ForEach-Object {
            @{ Key = $_.Name; Label = $_.Name; Value = $_.Path }
        })
        $folderPath = Read-Choice -Title 'Browse folders' -Prompt 'Folder' -Options $folderOptions -AllowQuit -QuitLabel 'Back'
        if (-not $folderPath) { return }

        $files = @(Get-ChildItem -Path $folderPath -Filter '*.ps1' -File -ErrorAction SilentlyContinue | Sort-Object Name)
        if (-not $files) {
            Write-Status -Level Warning 'No PowerShell scripts found in this folder.' -NoLog
            return
        }
        $scriptOptions = @($files | ForEach-Object {
            $functionName = $_.BaseName
            @{ Key = $functionName; Label = $functionName; Value = $functionName }
        })
        $functionName = Read-Choice -Title (Split-Path $folderPath -Leaf) -Prompt 'Function' -Options $scriptOptions -AllowQuit -QuitLabel 'Back'
        if (-not $functionName) { return }

        $command = Get-Command -Name $functionName -CommandType Function -ErrorAction SilentlyContinue
        if (-not $command) {
            Write-Status -Level Error "Function '$functionName' is not loaded in this module." -NoLog
            return
        }

        $arguments = @{}
        foreach ($parameter in $command.Parameters.Values) {
            if (-not $parameter.Attributes.Mandatory -or $parameter.Name -in @('Force','Confirm','WhatIf')) { continue }
            if ($parameter.ParameterType -eq [switch]) {
                $answer = Read-YesNo -Message "Enable -$($parameter.Name)? (y/n) "
                if ($answer -eq 'y') { $arguments[$parameter.Name] = $true }
                continue
            }
            if ($parameter.ParameterType -eq [securestring]) {
                $arguments[$parameter.Name] = Read-Host "Enter -$($parameter.Name)" -AsSecureString
                continue
            }
            $value = Read-Host "Enter -$($parameter.Name)"
            if ($parameter.ParameterType.IsArray) {
                $elementType = $parameter.ParameterType.GetElementType()
                $arguments[$parameter.Name] = @($value -split '\s*,\s*' | ForEach-Object { [System.Management.Automation.LanguagePrimitives]::ConvertTo($_, $elementType) })
            } else {
                $arguments[$parameter.Name] = [System.Management.Automation.LanguagePrimitives]::ConvertTo($value, $parameter.ParameterType)
            }
        }
        Write-Banner "Run $functionName" -Style Inline -Color Magenta -Log
        & $functionName @arguments
    }

    function Invoke-MenuAction {
        param(
            [string]$Choice
        )

        # Header from the option's label, also written to the log, so the log shows which
        # menu option ran (not only the operations inside it).
        $option = $menuOptions | Where-Object { $_.Key -eq $Choice.ToUpper() } | Select-Object -First 1
        if ($option) {
            Write-Banner ("Menu {0}: {1}" -f $option.Key, ($option.Label -replace '\s{2,}', ' ')) -Style Inline -Color Magenta -Log
        }

        switch ($Choice.ToUpper()) {
            '0'  { Show-OperationSummary }
            'A'  { Initialize-System -Force }
            'B'  { Invoke-FolderBrowser }

            # -- Orchestrators ------------------------------------------------
            '1'  {
                Invoke-WindowsHardening -FirewallPorts $FirewallPorts -AdditionalPorts $AdditionalPorts -PreserveManagementPort:$PreserveManagementPort -SplunkIP $SplunkIP -SaltPhrase $SaltPhrase
            }
            '2'  {
                Invoke-UserHardening -SaltPhrase $SaltPhrase
            }
            '3'  {
                Invoke-NetworkHardening -FirewallPorts $FirewallPorts -AdditionalPorts $AdditionalPorts -PreserveManagementPort:$PreserveManagementPort
            }
            '4'  {
                Invoke-ServiceHardening
            }

            # -- Users & Credentials ------------------------------------------
            '5'  {
                Set-ZuluPassword -SaltPhrase $SaltPhrase
            }
            '6'  {
                Set-AdministratorPassword -SaltPhrase $SaltPhrase
            }
            '7'  {
                Remove-RDPUsers
            }
            '8'  {
                Add-RDPUsers
            }
            '9'  {
                Remove-AdminUsers
            }
            '10' {
                Protect-Mimikatz
            }

            # -- Network & Remote Access --------------------------------------
            '11' {
                Set-FirewallConfiguration -FirewallPorts $FirewallPorts -AdditionalPorts $AdditionalPorts -PreserveManagementPort:$PreserveManagementPort
            }
            '12' {
                if ($PreserveManagementPort) {
                    Write-Host "This will disable RDP, Remote Registry, and SSH (WinRM kept: -PreserveManagementPort)." -ForegroundColor Yellow
                } else {
                    Write-Host "This will disable WinRM, RDP, Remote Registry, and SSH." -ForegroundColor Yellow
                }
                Write-Host "If you are connected via RDP or WinRM, your session may end." -ForegroundColor Yellow
                if ((Read-YesNo -Message "Continue? (y/n) ") -eq 'y') {
                    Remove-RemoteManagement -SkipWinRM:$PreserveManagementPort
                } else {
                    Write-Status -Level Skip "Cancelled"
                }
            }
            '19' {
                Initialize-System   # loads ports.json so the list shows port descriptions
                $isDC = $script:HardeningContext.OS.IsDomainController
                $portInput = if ($AdditionalPorts) { $AdditionalPorts } else {
                    Read-Choice -Title "Ports to open" -Prompt "Ports" -Options @(Get-FirewallPortOptions) `
                        -Multiple -AllowCustom -AllowQuit `
                        -ValidateCustom { param($value) (ConvertTo-PortList -Ports $value)[0] }
                }
                if (-not $portInput) {
                    Write-Status -Level Skip "Cancelled"
                    return
                }
                $protocol = Read-Choice -Prompt "Protocol" -Default $(if ($isDC) { 'B' } else { 'T' }) -Options @(
                    @{ Key = 'T'; Label = 'TCP'; Value = 'TCP' }
                    @{ Key = 'U'; Label = 'UDP'; Value = 'UDP' }
                    @{ Key = 'B'; Label = 'Both'; Value = 'Both' }
                )
                Add-FirewallPort -Ports $portInput -Protocol $protocol
            }
            '20' {
                Create-CCDCUsers -SaltPhrase $SaltPhrase
            }

            # -- Services -----------------------------------------------------
            '13' {
                Disable-UnusedNetworkProtocols
            }
            '14' {
                Mitigate-EternalBlue
            }

            # -- Monitoring & Patching -----------------------------------------
            '15' {
                Enable-AdvancedAuditing
                # Also set separately so logging is on even if auditing fails partway.
                try {
                    Set-NetFirewallProfile -Name Domain,Public,Private -LogAllowed True -LogBlocked True
                    Write-Status -Level Success "Firewall logging enabled (allowed + blocked)" -LogMessage "Enabled firewall logging"
                } catch {
                    Write-Status -Level Warning "Could not enable firewall logging: $($_.Exception.Message)"
                }
            }
            '16' {
                $ip = if ($SplunkIP) { $SplunkIP } else { Read-HostAddress -Prompt "Splunk server IP" }
                # splunk.ps1 detects the Windows version itself.
                Install-Splunk -IP $ip
            }
            '17' {
                Install-EternalBluePatch
            }
            '18' {
                Set-RestrictedExecutionPolicy
            }

            Default {
                Write-Status -Level Warning "Invalid selection: '$Choice'" -NoLog
            }
        }
    }

    # Every option changes system settings; check before showing anything.
    if (-not (Test-IsAdministrator)) {
        throw "Invoke-HardeningMenu must be run as Administrator (start PowerShell with 'Run as administrator')."
    }

    if ($Force) {
        if ([string]::IsNullOrEmpty($Selection)) {
            Write-Status -Level Error "-Force requires -Selection" -NoLog
            return
        }
        try {
            Invoke-MenuAction -Choice $Selection
        } catch {
            Write-Status -Level Error "Menu option $Selection failed: $($_.Exception.Message)"
        }
        return
    }

    while ($true) {
        Write-Banner "Windows Hardening Menu" -Style Inline -Color Green
        Write-Host "Setup runs automatically on the first task; (A) re-runs it (new log file)." -ForegroundColor Yellow
        $picked = Read-Choice -Prompt "Selection" -Options (Get-ScreenOptions) -Multiple -AllowQuit -QuitLabel 'Quit' `
            -Hint 'a letter opens a section; option numbers work here too, e.g. 9,10,13 or 13-15'
        if ($null -eq $picked) { break }

        # Section letters open a sub-menu (Q there goes back); numbers run directly.
        # Everything runs in the order typed.
        $choices = @(foreach ($item in $picked) {
            if ("$item" -like 'section:*') {
                $letter = "$item".Substring(8)
                $sub = Read-Choice -Title $menuSections[$letter] -Prompt "Selection" -Options (Get-ScreenOptions -Section $letter) `
                    -Multiple -AllowQuit -QuitLabel 'Back' -Hint 'one or more, e.g. 9,10; any option number works here'
                if ($null -ne $sub) { $sub }
            } else {
                $item
            }
        })
        if ($choices.Count -eq 0) { continue }

        foreach ($choice in $choices) {
            try {
                Invoke-MenuAction -Choice $choice
            } catch {
                Write-Status -Level Error "Menu option $choice failed: $($_.Exception.Message)"
            }
        }

        Write-Host "`nPress Enter to return to menu..." -ForegroundColor DarkGray
        Read-Host | Out-Null
    }
}
