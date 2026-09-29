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

        Write-Host "[INFO] This patch disables WDigest credential storage (UseLogonCredential = 0)" -ForegroundColor Cyan
        Write-Host "[INFO] This prevents Mimikatz from extracting plaintext credentials from memory" -ForegroundColor Cyan

        Set-RegistryValue -Path $registryPath -Name "UseLogonCredential" -Value 0 -PropertyType "DWord" -OperationName "Patch Mimikatz" -CreatePathIfMissing

        Write-Host "Mimikatz (WDigest) patch applied successfully" -ForegroundColor Green
        Write-Host "[INFO] System restart recommended for changes to take full effect" -ForegroundColor Yellow
        Write-Log -Level "SUCCESS" -Message "Mimikatz patch (WDigest) applied - UseLogonCredential set to 0"
    }
}
