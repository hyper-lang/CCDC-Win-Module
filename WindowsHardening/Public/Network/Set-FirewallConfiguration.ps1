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

    -AdditionalPorts are added on top of whichever set was chosen.

    Existing "Allow <Protocol> <Port>" rules from earlier runs are re-enabled instead of
    duplicated, and enabled Block rules that would override an Allow rule are reported.
    To open a port later without resetting the firewall, use Add-FirewallPort.

    Domain-vs-Local branching is driven by $script:HardeningContext.OS.IsDomainController.

.PARAMETER FirewallPorts
    Ports to allow. When given, no prompts are shown and no ports are added automatically.

.PARAMETER AdditionalPorts
    Extra ports to allow on top of -FirewallPorts, the DC defaults, or the ports chosen at
    the prompt - e.g. a database or web port the box is known to need.

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

        [int[]]$AdditionalPorts,

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
            # Interactive: one multi-select prompt over the suggested ports; unlisted ports
            # can be typed too. On a DC, Enter keeps the AD ports; elsewhere Enter = none.
            else {
                $portOptions = @(Get-FirewallPortOptions -IsDC:$isDC)
                $defaultKeys = @($portOptions | Where-Object { $_.Default } | ForEach-Object { $_.Key })
                Write-Host "Suggested ports are common scored services and/or ports AD needs." -ForegroundColor DarkGray
                if (-not $isDC) {
                    Write-Host "AD ports are listed in case this box is joined to a domain later." -ForegroundColor DarkGray
                }

                $ready = $false
                while ($true) {
                    $desigPorts = Read-Choice -Title "Firewall Ports" -Prompt "Ports to allow" -Options $portOptions `
                        -Multiple -AllowCustom -AllowEmpty -AllowQuit -Default $defaultKeys `
                        -ValidateCustom { param($value) (ConvertTo-PortList -Ports $value)[0] }
                    if ($null -eq $desigPorts) { break }

                    Write-Banner "Designated Ports" -Style Inline
                    if ($desigPorts.Count -gt 0) {
                        Write-Host (($desigPorts | Sort-Object) -join ', ')
                    } else {
                        Write-Host "(none - Deny All Inbound only)"
                    }
                    if ((Read-YesNo -Message "Are these ports correct (y/n)? ") -eq 'y') {
                        $portsToAllow = $desigPorts
                        $ready = $true
                        break
                    }
                }

                if (-not $ready) {
                    Write-Log -Level "INFO" -Message "Firewall configuration skipped by user"
                    throw "Operation skipped by user"
                }
            }

            # Add-on ports; also validates, de-duplicates, and drops blank prompt entries
            $portsToAllow = @((ConvertTo-PortList -Ports (@($portsToAllow) + @($AdditionalPorts) | ForEach-Object { "$_" })) | Sort-Object -Unique)
            if ($AdditionalPorts.Count -gt 0) {
                Write-Host "  [INFO] Additional ports: $($AdditionalPorts -join ', ')" -ForegroundColor Yellow
                Write-Log -Level "INFO" -Message "Additional firewall ports: $($AdditionalPorts -join ', ')"
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
                $null = Set-FirewallAllowRule -Port 5986 -Protocol TCP
                Write-Log -Level "SUCCESS" -Message "Added TCP inbound rules for port 5986 (WinRM-HTTPS, preserved management port)"
                $null = Set-FirewallAllowRule -Port 5985 -Protocol TCP
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

                    $description = Get-FirewallPortDescription -Port $port

                    if ($isDC) {
                        # AD: create both TCP and UDP Allow rules
                        $null = Set-FirewallAllowRule -Port $port -Protocol TCP
                        $null = Set-FirewallAllowRule -Port $port -Protocol UDP
                        Write-Log -Level "SUCCESS" -Message "Added inbound rules for port $port ($description)"
                    } else {
                        # Local: create TCP-only Allow rule
                        $null = Set-FirewallAllowRule -Port $port -Protocol TCP
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
