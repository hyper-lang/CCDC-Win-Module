#Requires -Version 5.1

<#
.SYNOPSIS
    Configures Windows Firewall with mandatory Deny All Inbound rule and optional port allowances.

.DESCRIPTION
    This function consolidates all firewall configuration logic. It always creates a high-priority
    "Deny All Inbound" rule for security. It then handles three scenarios:

    - -FirewallPorts given: allows exactly those ports (no prompts).
    - -NonInteractive without ports: Deny All only for Local; common AD/DC ports for AD.
    - Neither: prompts for ports and confirmation.

    Domain-vs-Local branching is driven by $script:HardeningContext.OS.IsDomainController.

.PARAMETER FirewallPorts
    Ports to allow. When given, no prompts are shown and no ports are added automatically.

.PARAMETER NonInteractive
    Never prompt (used by Invoke-WindowsHardening).

.PARAMETER PreserveManagementPort
    When set, creates Allow rules for TCP 5986 (WinRM-HTTPS) and TCP 5985
    (WinRM-HTTP) after all existing rules are disabled, so a remote session
    applying this over WinRM does not lock itself out. The later port-rule loop
    skips both to avoid duplicates.
#>
function Set-FirewallConfiguration {
    [CmdletBinding()]
    param(
        [int[]]$FirewallPorts,

        [switch]$NonInteractive,

        [switch]$PreserveManagementPort
    )

    Invoke-HardeningOperation -OperationName "Configure Firewall" -ScriptBlock {
        try {
            $portsToAllow = @()
            $isDC = $script:HardeningContext.OS.IsDomainController

            if ($isDC) {
                $usualPorts = @(53, 3389, 80, 445, 139, 22, 88, 67, 68, 135, 139, 389, 636, 3268, 3269, 464) | Sort-Object
                $commonScored = @(53, 3389, 80, 22)
                $commonADorDC = @(53, 139, 88, 67, 68, 135, 139, 389, 445, 636, 3268, 3269, 464)
            }

            # Explicit ports: use exactly these
            if ($null -ne $FirewallPorts -and $FirewallPorts.Count -gt 0) {
                $portsToAllow = $FirewallPorts
                Write-Host "  [INFO] Using firewall ports from parameter: $($portsToAllow -join ', ')" -ForegroundColor Yellow
                Write-Log -Level "INFO" -Message "Using firewall ports from parameter: $($portsToAllow -join ', ')"
            }
            # Non-interactive without ports: AD ports on a DC, Deny All only on a local machine
            elseif ($NonInteractive) {
                if ($isDC) {
                    $portsToAllow = $commonADorDC
                    Write-Host "  [INFO] Using common AD ports: $($portsToAllow -join ', ')" -ForegroundColor Yellow
                } else {
                    Write-Host "  [INFO] No ports specified - applying Deny All Inbound rule only" -ForegroundColor Yellow
                }
            }
            # Interactive
            else {
                # Interactive prompt for ports
                $ready = $false
                :outer while ($true) {
                    $desigPorts = Read-CommaList -message "List needed port numbers for firewall config. Separate by commas."

                    if ($isDC) {
                        $usualPorts = @(53, 3389, 80, 445, 139, 22, 88, 67, 68, 135, 139, 389, 636, 3268, 3269, 464) | Sort-Object
                        $commonScored = @(53, 3389, 80, 22)
                        $commonADorDC = @(53, 139, 88, 67, 68, 135, 139, 389, 445, 636, 3268, 3269, 464)
                    } else {
                        $usualPorts = @(53, 3389, 80, 445, 139, 22, 88, 67, 68, 135, 139, 389, 636, 3268, 3269, 464) | Sort-Object
                        $commonScored = @(53, 3389, 80, 22)
                        $commonADorDC = @(139, 88, 67, 68, 135, 139, 389, 445, 636, 3268, 3269, 464)
                    }

                    Write-Host "All the following ports that we suggest are either common scored services, or usually needed for AD processes. We will say which is which. While this box isn't domain bound, AD ports have been left on the list in case this box gets bound later."

                    foreach ($item in $usualPorts) {
                        if ($desigPorts -notcontains $item) {
                            if ($item -in $commonScored) {
                                Write-Host "`nCommon Scored Service" -ForegroundColor Green
                            }
                            if ($item -in $commonADorDC) {
                                if ($isDC -and ($item -eq 445 -or $item -eq 53)) {
                                    Write-Host "`nCommon Scored Service" -ForegroundColor Green -NoNewline
                                    Write-Host " and" -ForegroundColor Cyan -NoNewline
                                    Write-Host " Common port needed for DC/AD processes" -ForegroundColor Red
                                } elseif (-not $isDC -and $item -eq 445) {
                                    Write-Host "`nCommon Scored Service" -ForegroundColor Green -NoNewline
                                    Write-Host " and" -ForegroundColor Cyan -NoNewline
                                    Write-Host " Common port needed for CD/AD processes" -ForegroundColor Red
                                } else {
                                    Write-Host "`nCommon port needed for DC/AD processes" -ForegroundColor Red
                                }
                            }
                            Write-Host "Need " -NoNewline
                            Write-Host "$item" -ForegroundColor Green -NoNewline
                            Write-Host ", " -NoNewline
                            Write-Host "$($script:HardeningContext.Ports.ports.$item.description)? " -ForegroundColor Cyan -NoNewline
                            Write-Host "(y/n)" -ForegroundColor Yellow
                            $confirmation = Read-Host

                            while($true) {
                                if ($confirmation.toLower() -eq "y") {
                                    $desigPorts = @($desigPorts) + $item
                                    break
                                }
                                if ($confirmation.toLower() -eq "n") {
                                    break
                                }
                            }
                        }
                    }

                    Write-Host "`n==== Designated Ports ====" -ForegroundColor Cyan
                    Write-Host ($desigPorts -join "`n") | Sort-Object

                    $confirmation = ""
                    while($true) {
                        $confirmation = Read-YesNo -Message "Are these ports correct (y/n)?"
                        if ($confirmation.toLower() -eq "y") {
                            $portsToAllow = $desigPorts
                            $ready = $true
                            break outer
                        }
                        if ($confirmation.toLower() -eq "n") {
                            $ready = $false
                            break
                        }
                    }
                }

                if ($ready -eq $false) {
                    Write-Log -Level "INFO" -Message "Firewall configuration skipped by user"
                    throw "Operation skipped by user"
                }
            }

            # Backup current firewall config
            $FirewallBackupPath = Join-Path $script:HardeningContext.LogPath 'fwback.wfw'
            Write-Host "Backing up current Windows Firewall policy to $FirewallBackupPath" -ForegroundColor Yellow
            try {
                netsh advfirewall export "$FirewallBackupPath" | Out-Null
                Write-Host "Backup successful. To restore, use: Import-NetFirewallPolicy -Path '$FirewallBackupPath'" -ForegroundColor Green
            } catch {
                Write-Host "Error during backup: $($_.Exception.Message). Continuing with rule modification." -ForegroundColor Red
            }

            # Enable the firewall profiles and disable all pre-existing inbound and outbound rules
            Set-NetFirewallProfile -All -Enabled True

            # Disable ALL rules (including any pre-existing ones). This must run BEFORE the
            # management-port Allow rules are created below, otherwise it would disable them
            # and a remote WinRM session applying this would lock itself out.
            Get-NetFirewallRule | Disable-NetFirewallRule

            # Create a new firewall rule to block all inbound traffic and allow outbound traffic
            Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow

            # Keep WinRM (5985 HTTP, 5986 HTTPS) reachable when hardening over a remote session.
            if ($PreserveManagementPort) {
                New-NetFirewallRule -DisplayName "Allow TCP 5986" -Direction Inbound -LocalPort 5986 -Action Allow -Protocol TCP -Enabled True
                Write-Log -Level "SUCCESS" -Message "Added TCP inbound rules for port 5986 (WinRM-HTTPS, preserved management port)"
                New-NetFirewallRule -DisplayName "Allow TCP 5985" -Direction Inbound -LocalPort 5985 -Action Allow -Protocol TCP -Enabled True
                Write-Log -Level "SUCCESS" -Message "Added TCP inbound rules for port 5985 (WinRM-HTTP, preserved management port)"
            }

            # If ports are specified, create Allow rules for them (with higher priority than Deny All so they're evaluated first)
            if ($portsToAllow.Count -gt 0) {
                Write-Host "  [ACTION] Creating Allow rules for specified ports..." -ForegroundColor White
                foreach ($port in $portsToAllow) {
                    # Skip the preserved management ports - their Allow rules were already created above.
                    if ($PreserveManagementPort -and ($port -eq 5986 -or $port -eq 5985)) {
                        continue
                    }

                    # Try to get description from the ports data, fallback to switch
                    $description = ""
                    if ($null -ne $script:HardeningContext.Ports -and $null -ne $script:HardeningContext.Ports.ports -and $null -ne $script:HardeningContext.Ports.ports.$port) {
                        $description = $script:HardeningContext.Ports.ports.$port.description
                    } else {
                        $description = switch ($port) {
                            22 { "SSH" }
                            53 { "DNS" }
                            80 { "HTTP" }
                            443 { "HTTPS" }
                            3389 { "RDP" }
                            5985 { "WinRM-HTTP" }
                            5986 { "WinRM-HTTPS" }
                            default { "Port-$port" }
                        }
                    }

                    if ($isDC) {
                        # AD: create both TCP and UDP Allow rules
                        New-NetFirewallRule -DisplayName "Allow TCP $port" -Direction Inbound -LocalPort $port -Action Allow -Protocol TCP -Enabled True
                        New-NetFirewallRule -DisplayName "Allow UDP $port" -Direction Inbound -LocalPort $port -Action Allow -Protocol UDP -Enabled True
                        Write-Log -Level "SUCCESS" -Message "Added inbound rules for port $port ($description)"
                    } else {
                        # Local: create TCP-only Allow rule
                        New-NetFirewallRule -DisplayName "Allow TCP $port" -Direction Inbound -LocalPort $port -Action Allow -Protocol TCP -Enabled True
                        Write-Log -Level "SUCCESS" -Message "Added TCP inbound rules for port $port ($description)"
                    }
                }
                Write-Host "  [SUCCESS] Allow rules created for ports: $($portsToAllow -join ', ')" -ForegroundColor Green
                Write-Log -Level "SUCCESS" -Message "Firewall configured with ports: $($portsToAllow -join ', ')"
            } else {
                if ($isDC) {
                    Write-Host "  [INFO] No ports specified - only AD rules applied" -ForegroundColor Yellow
                    Write-Log -Level "INFO" -Message "Firewall configured with AD rules only (no other ports allowed)"
                } else {
                    Write-Host "  [INFO] No ports specified - only Deny All Inbound rule applied" -ForegroundColor Yellow
                    Write-Log -Level "INFO" -Message "Firewall configured with Deny All Inbound rule only (no ports allowed)"
                }
            }

            # AD only: re-enable RPC and SMB rules restricted to LocalSubnet
            if ($isDC) {
                $rpcRules = Get-NetFirewallRule | Where-Object { $_.Name -like "*RPC*" -or $_.DisplayName -like "*135*" }
                if ($rpcRules) {
                    $rpcRules | Set-NetFirewallRule -RemoteAddress "LocalSubnet" -Enabled "True"
                }
                $smbRules = Get-NetFirewallRule | Where-Object { $_.Name -like "*SMB*" -or $_.DisplayName -like "*139*" -or $_.DisplayName -like "*445*" }
                if ($smbRules) {
                    $smbRules | Set-NetFirewallRule -RemoteAddress "LocalSubnet" -Enabled "True"
                }
            }

            Write-Host "Firewall configured successfully" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "Firewall configuration completed"
        } catch {
            if ($_.Exception.Message -ne "Operation skipped by user") {
                Write-Host "Firewall configuration failed: $($_.Exception.Message)" -ForegroundColor Red
                Write-Log -Level "ERROR" -Message "Firewall configuration failed: $($_.Exception.Message)"
            }
            throw
        }
    }
}

Set-Alias -Name Configure-Firewall -Value Set-FirewallConfiguration
