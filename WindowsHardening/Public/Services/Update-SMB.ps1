function Update-SMB {
    [CmdletBinding()]
    param()

    $smbUpgradeCompatible = @("Client8", "Client10", "Client11", "Server2012", "Server2012R2", "Server2016", "Server2019", "Server2022")

    Invoke-HardeningOperation -OperationName "Upgrade SMB" -OSCompatibility $smbUpgradeCompatible -ProgressMessage "Enabling SMBv2/v3 and disabling SMBv1 for improved security" -ScriptBlock {
        if (-not [bool](Get-Module -ListAvailable -Name SmbShare)) {
            Write-Host "[WARNING] SMB module not available. Attempting to import..." -ForegroundColor Yellow
            try {
                Import-Module SmbShare -ErrorAction Stop
                Write-Log -Level "SUCCESS" -Message "Imported SMB module"
            } catch {
                Write-Host "[WARNING] Could not import SMB module. SMB configuration may not work correctly." -ForegroundColor Yellow
                Write-Log -Level "WARNING" -Message "SMB module not available: $($_.Exception.Message)"
            }
        }

        try {
            Write-Host "[INFO] Detecting current SMB configuration..." -ForegroundColor Cyan
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

            Write-Host "[INFO] Current SMB Configuration:" -ForegroundColor Cyan
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
                Write-Host "[ACTION] Enabling SMBv2..." -ForegroundColor Yellow
                try {
                    Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
                    Write-Host "[SUCCESS] SMBv2 enabled" -ForegroundColor Green
                    Write-Log -Level "SUCCESS" -Message "Enabled SMBv2/SMBv3"
                    $restart = $true
                } catch {
                    Write-Host "[FAILED] SMB upgrade failed: $($_.Exception.Message)" -ForegroundColor Red
                    Write-Log -Level "ERROR" -Message "SMB upgrade failed: $($_.Exception.Message)"
                    throw
                }
            } else {
                Write-Host "[INFO] SMBv2 already enabled" -ForegroundColor Green
                Write-Log -Level "INFO" -Message "SMBv2 already enabled"
            }

            if ($smbv1Enabled -eq $true) {
                Write-Host "[ACTION] Disabling SMBv1 (vulnerable protocol)..." -ForegroundColor Yellow
                try {
                    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
                    Write-Host "[SUCCESS] SMBv1 disabled" -ForegroundColor Green
                    Write-Log -Level "SUCCESS" -Message "Disabled SMBv1"
                    $restart = $true
                } catch {
                    Write-Host "[FAILED] SMB upgrade failed: $($_.Exception.Message)" -ForegroundColor Red
                    Write-Log -Level "ERROR" -Message "SMB upgrade failed: $($_.Exception.Message)"
                    throw
                }
            } else {
                Write-Host "[INFO] SMBv1 already disabled" -ForegroundColor Green
                Write-Log -Level "INFO" -Message "SMBv1 already disabled"
            }

            if ($restart -eq $true) {
                Write-Host "[WARNING] System restart recommended for SMB changes to take full effect" -ForegroundColor Yellow
                Write-Log -Level "WARNING" -Message "System restart may be required for SMB changes"
            } else {
                Write-Host "[SUCCESS] SMB configuration is already optimal" -ForegroundColor Green
            }
        } catch {
            Write-Host "[ERROR] SMB upgrade failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log -Level "ERROR" -Message "SMB upgrade failed: $($_.Exception.Message)" -Console
            throw
        }
    }
}
