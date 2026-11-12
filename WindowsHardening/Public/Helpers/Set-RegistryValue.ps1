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

        [switch]$CreatePathIfMissing,

        [object]$State = $null
    )

    if (-not $State) { $State = Resolve-HardeningState -State $State }

    try {
        if (-not (Test-Path -Path $Path)) {
            if ($CreatePathIfMissing) {
                Write-Status "Creating registry path: $Path" -State $State
                New-Item -Path $Path -Force | Out-Null
                Write-Status -Level Success "Created registry path: $Path" -LogOnly -State $State
            } else {
                $message = "Registry path not found and CreatePathIfMissing not specified: $Path"
                Write-Status -Level Skip "$message" -LogMessage "$OperationName - $message" -State $State
                Update-HardeningCounter -State $State -Counter Skipped
                return $false
            }
        }

        $existingValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Ignore

        if ($null -ne $existingValue -and $existingValue.PSObject.Properties[$Name]) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value | Out-Null
            Write-Status -Level Success "Updated registry value: $Path\$Name = $Value" -State $State
        } else {
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force | Out-Null
            Write-Status -Level Success "Created and set registry value: $Path\$Name = $Value" -LogMessage "Created registry value: $Path\$Name = $Value" -State $State
        }

        return $true

    } catch {
        $errorMessage = "Failed to set registry value $Path\$Name : $($_.Exception.Message)"
        Write-Status -Level Error "$errorMessage" -LogMessage "$OperationName - $errorMessage" -State $State
        throw
    }
}
