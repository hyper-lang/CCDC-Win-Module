function Update-SMB {
    [CmdletBinding()]
    param()

    $smbUpgradeCompatible = @("Client8", "Client10", "Client11", "Server2012", "Server2012R2", "Server2016", "Server2019", "Server2022")

    Invoke-HardeningOperation -OperationName "Upgrade SMB" -OSCompatibility $smbUpgradeCompatible -ProgressMessage "Enabling SMBv2/v3 and disabling SMBv1 for improved security" -ScriptBlock {
        if (-not [bool](Get-Module -ListAvailable -Name SmbShare)) {
            Write-Status -Level Warning "SMB module not available. Attempting to import..."
            try {
                Import-Module SmbShare -ErrorAction Stop
                Write-Status -Level Success "Imported SMB module" -LogOnly
            } catch {
                Write-Status -Level Warning "Could not import SMB module. SMB configuration may not work correctly." -LogMessage "SMB module not available: $($_.Exception.Message)"
            }
        }

        try {
            Write-Status "Detecting current SMB configuration..."
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

            Write-Status "Current SMB Configuration:"
            if ($smbv1Enabled) {
                Write-Host "  SMBv1: Enabled" -ForegroundColor Red
            } else {
                Write-Host "  SMBv1: Disabled" -ForegroundColor Green
            }
            if ($smbv2Enabled) {
                Write-Host "  SMBv2: Enabled" -ForegroundColor Green
            } else {
                Write-Host "  SMBv2: Disabled" -ForegroundColor Yellow
            }
            if ($null -ne $smbv3Enabled) {
                if ($smbv3Enabled) {
                    Write-Host "  SMBv3: Enabled" -ForegroundColor Green
                } else {
                    Write-Host "  SMBv3: Disabled" -ForegroundColor Yellow
                }
            }

            if ($smbv2Enabled -eq $false) {
                Write-Status "Enabling SMBv2..."
                try {
                    Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
                    Write-Status -Level Success "SMBv2 enabled" -LogMessage "Enabled SMBv2/SMBv3"
                    $restart = $true
                } catch {
                    Write-Status -Level Error "SMB upgrade failed: $($_.Exception.Message)"
                    throw
                }
            } else {
                Write-Status "SMBv2 already enabled"
            }

            if ($smbv1Enabled -eq $true) {
                Write-Status "Disabling SMBv1 (vulnerable protocol)..."
                try {
                    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
                    Write-Status -Level Success "SMBv1 disabled" -LogMessage "Disabled SMBv1"
                    $restart = $true
                } catch {
                    Write-Status -Level Error "SMB upgrade failed: $($_.Exception.Message)"
                    throw
                }
            } else {
                Write-Status "SMBv1 already disabled"
            }

            if ($restart -eq $true) {
                Write-Status -Level Warning "System restart recommended for SMB changes to take full effect" -LogMessage "System restart may be required for SMB changes"
            } else {
                Write-Status -Level Success "SMB configuration is already optimal"
            }
        } catch {
            Write-Status -Level Error "SMB upgrade failed: $($_.Exception.Message)"
            throw
        }
    }
}
