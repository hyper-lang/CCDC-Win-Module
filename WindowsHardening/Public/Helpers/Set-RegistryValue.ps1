#Requires -Version 5.1

# Set-RegistryValue.ps1 - Registry helper with error handling and logging.

function Set-RegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [object]$Value,

        [Parameter(Mandatory=$true)]
        [ValidateSet("String", "DWord", "QWord", "MultiString", "ExpandString", "Binary")]
        [string]$PropertyType,

        [string]$OperationName = "Registry Operation",

        [switch]$CreatePathIfMissing
    )

    try {
        if (-not (Test-Path -Path $Path)) {
            if ($CreatePathIfMissing) {
                Write-Host "[INFO] Creating registry path: $Path" -ForegroundColor Cyan
                New-Item -Path $Path -Force | Out-Null
                Write-Log -Level "SUCCESS" -Message "Created registry path: $Path"
            } else {
                $message = "Registry path not found and CreatePathIfMissing not specified: $Path"
                Write-Host "[SKIPPED] $message" -ForegroundColor Yellow
                Write-Log -Level "WARNING" -Message "$OperationName - $message" -Console
                $script:OperationResults.Skipped++
                return $false
            }
        }

        $existingValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Ignore

        if ($null -ne $existingValue -and $existingValue.PSObject.Properties[$Name]) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value | Out-Null
            Write-Host "[SUCCESS] Updated registry value: $Path\$Name = $Value" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "Updated registry value: $Path\$Name = $Value"
        } else {
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force | Out-Null
            Write-Host "[SUCCESS] Created and set registry value: $Path\$Name = $Value" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "Created registry value: $Path\$Name = $Value"
        }

        return $true

    } catch {
        $errorMessage = "Failed to set registry value $Path\$Name : $($_.Exception.Message)"
        Write-Host "[ERROR] $errorMessage" -ForegroundColor Red
        Write-Log -Level "ERROR" -Message "$OperationName - $errorMessage" -Console
        throw
    }
}
