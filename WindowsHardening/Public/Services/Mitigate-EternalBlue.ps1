function Mitigate-EternalBlue {
    [CmdletBinding()]
    param([object]$State = $null, [string]$StepLabel)
    if (-not $State) { $State = Resolve-HardeningState -State $State }


    $eternalBlueMitigationCompatible = @("Client8", "Client10", "Client11", "Server2012", "Server2012R2", "Server2016", "Server2019", "Server2022", "Server2025")

    Invoke-HardeningOperation -State $State -StepLabel $StepLabel -OperationName "Mitigate EternalBlue" -OSCompatibility $eternalBlueMitigationCompatible -ProgressMessage "Disabling SMBv1, enabling SMBv2/v3, and requiring SMB signing" -ScriptBlock {
        if (-not [bool](Get-Module -ListAvailable -Name SmbShare)) {
            Write-Status -Level Warning "SMB module not available. Attempting to import..." -State $State
            try {
                Import-Module SmbShare -ErrorAction Stop
                Write-Status -Level Success "Imported SMB module" -LogOnly -State $State
            } catch {
                Write-Status -Level Warning "Could not import SMB module. SMB configuration may not work correctly." -LogMessage "SMB module not available: $($_.Exception.Message)" -State $State
            }
        }

        try {
            Write-Status "Detecting current SMB configuration..." -State $State
            $smbConfig = Get-SmbServerConfiguration
            $smbv1Enabled = $smbConfig.EnableSMB1Protocol
            $smbv2Enabled = $smbConfig.EnableSMB2Protocol
            $smbv3Enabled = $null
            try {
                $smbv3Enabled = $smbConfig.EnableSMB3Protocol
            } catch {
                $smbv3Enabled = $null
            }
            $restart = $false
            $changed = $false

            Write-Status "Current SMB configuration:" -State $State
            Write-Status -Level $(if ($smbv1Enabled) { 'Warning' } else { 'Success' }) "SMBv1: $(if ($smbv1Enabled) { 'Enabled' } else { 'Disabled' })" -State $State
            Write-Status -Level $(if ($smbv2Enabled) { 'Success' } else { 'Warning' }) "SMBv2: $(if ($smbv2Enabled) { 'Enabled' } else { 'Disabled' })" -State $State
            if ($null -ne $smbv3Enabled) {
                Write-Status -Level $(if ($smbv3Enabled) { 'Success' } else { 'Warning' }) "SMBv3: $(if ($smbv3Enabled) { 'Enabled' } else { 'Disabled' })" -State $State
            }
            Write-Status -Level $(if ($smbConfig.RequireSecuritySignature) { 'Success' } else { 'Warning' }) "Signing required: $([bool]$smbConfig.RequireSecuritySignature)" -State $State

            if ($smbv2Enabled -eq $false) {
                Write-Status "Enabling SMBv2..." -State $State
                try {
                    Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
                    Write-Status -Level Success "SMBv2 enabled" -LogMessage "Enabled SMBv2/SMBv3" -State $State
                    $restart = $true
                } catch {
                    Write-Status -Level Error "SMB upgrade failed: $($_.Exception.Message)" -State $State
                    throw
                }
            } else {
                Write-Status "SMBv2 already enabled" -State $State
            }

            if ($smbv1Enabled -eq $true) {
                Write-Status "Disabling SMBv1 (vulnerable protocol)..." -State $State
                try {
                    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
                    Write-Status -Level Success "SMBv1 disabled" -LogMessage "Disabled SMBv1" -State $State
                    $restart = $true
                } catch {
                    Write-Status -Level Error "SMB upgrade failed: $($_.Exception.Message)" -State $State
                    throw
                }
            } else {
                Write-Status "SMBv1 already disabled" -State $State
            }

            # Require signing on the SMB server (blocks SMB relay). Every client since Windows
            # 2000 supports signing, and DCs already require it by default. Takes effect for
            # new connections; no restart needed.
            if (-not $smbConfig.RequireSecuritySignature -or -not $smbConfig.EnableSecuritySignature) {
                Write-Status "Requiring SMB signing..." -State $State
                Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force -ErrorAction Stop
                Write-Status -Level Success "SMB signing required" -LogMessage "Enabled and required SMB server signing" -State $State
                $changed = $true
            } else {
                Write-Status "SMB signing already required" -State $State
            }

            if ($restart -eq $true) {
                Write-Status -Level Warning "System restart recommended for SMB changes to take full effect" -LogMessage "System restart may be required for SMB changes" -State $State
            } elseif (-not $changed) {
                Write-Status -Level Success "SMB configuration is already optimal" -State $State
            }
        } catch {
            Write-Status -Level Error "SMB upgrade failed: $($_.Exception.Message)" -State $State
            throw
        }
    }
}
