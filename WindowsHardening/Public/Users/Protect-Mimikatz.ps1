function Protect-Mimikatz {
    [CmdletBinding()]
    param()

    $mimikatzCompatible = @(
        "Client7", "Client8", "Client10", "Client11",
        "Server2008", "Server2008R2", "Server2012", "Server2012R2",
        "Server2016", "Server2019", "Server2022", "Server2025"
    )

    Invoke-HardeningOperation -OperationName "Patch Mimikatz" -OSCompatibility $mimikatzCompatible -ProgressMessage "Disabling WDigest credential storage to prevent Mimikatz credential extraction" -ScriptBlock {
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"

        Write-Status "This patch disables WDigest credential storage (UseLogonCredential = 0)"
        Write-Status "This prevents Mimikatz from extracting plaintext credentials from memory"

        Set-RegistryValue -Path $registryPath -Name "UseLogonCredential" -Value 0 -PropertyType "DWord" -OperationName "Patch Mimikatz" -CreatePathIfMissing

        Write-Host "Mimikatz (WDigest) patch applied successfully" -ForegroundColor Green
        Write-Status -Level Success "System restart recommended for changes to take full effect" -LogMessage "Mimikatz patch (WDigest) applied - UseLogonCredential set to 0"
    }
}
