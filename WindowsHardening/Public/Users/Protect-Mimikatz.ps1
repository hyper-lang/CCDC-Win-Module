function Protect-Mimikatz {
    [CmdletBinding()]
    param([object]$State = $null, [string]$StepLabel)
    if (-not $State) { $State = Resolve-HardeningState -State $State }


    $mimikatzCompatible = @(
        "Client7", "Client8", "Client10", "Client11",
        "Server2008", "Server2008R2", "Server2012", "Server2012R2",
        "Server2016", "Server2019", "Server2022", "Server2025"
    )

    Invoke-HardeningOperation -State $State -StepLabel $StepLabel -OperationName "Patch Mimikatz" -OSCompatibility $mimikatzCompatible -ProgressMessage "Disabling WDigest credential storage to prevent Mimikatz credential extraction" -ScriptBlock {
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"

        Write-Status "This patch disables WDigest credential storage (UseLogonCredential = 0)" -State $State
        Write-Status "This prevents Mimikatz from extracting plaintext credentials from memory" -State $State

        Set-RegistryValue -Path $registryPath -Name "UseLogonCredential" -Value 0 -PropertyType "DWord" -OperationName "Patch Mimikatz" -CreatePathIfMissing -State $State

        Write-Status -Level Warning "System restart recommended for changes to take full effect" -LogMessage "Mimikatz patch (WDigest) applied - UseLogonCredential set to 0" -State $State
    }
        Invoke-HardeningOperation -State $State -StepLabel $StepLabel -OperationName "Audit SeDebugPrivilege" -ProgressMessage "Checking which users have the SeDebugPrivilege right" -ScriptBlock {
        check-SeDebugPrivilege
    }
}

# ToDo: recursivly check for nested groups
function Check-SeDebugPrivilege {
    $policyFile = Join-Path $env:TEMP "SeDebugAudit.inf"

    try {
        & secedit.exe /export /cfg $policyFile /areas USER_RIGHTS | Out-Null

        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $policyFile)) {
            throw "Failed to export security policy."
        }

        $results = Select-String -Path $policyFile -Pattern '^\s*SeDebugPrivilege\s*='

        if ($results) {
            Write-Host ($results | Out-String)
            Write-Status -Level Warning "SeDebugPrivilege assignments found." `
                -LogMessage ($results | Out-String) -State $State
        }
        else {
            Write-Status "No SeDebugPrivilege assignments found." -State $State
        }
    }
    finally {
        Remove-Item $policyFile -ErrorAction SilentlyContinue
    }
}
