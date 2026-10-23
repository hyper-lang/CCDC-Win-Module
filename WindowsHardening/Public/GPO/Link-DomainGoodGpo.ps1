function Link-DomainGoodGpo {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$BackupRoot)

    Invoke-HardeningOperation -OperationName 'Link Domain Good-GPO' -ScriptBlock {
        Invoke-CcdcGpoLinkOperation -Name 'Domain Good-GPO' -BackupRoot $BackupRoot -Target (Get-CcdcDomainRootDn) -Enforced
        # The bundled GPO enables FIPS mode, which blocks the MD5 that New-Password (Zulu,
        # -SaltPhrase) relies on. Set it to 0 rather than removing it: registry policy values
        # stay behind, so machines that already applied FIPS have to be switched back.
        Set-GPRegistryValue -Name 'Domain Good-GPO' -Key 'HKLM\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy' `
            -ValueName 'Enabled' -Type DWord -Value 0 -ErrorAction Stop | Out-Null
        # DCs accept a user's previous password over NTLM for 60 minutes after a change or
        # reset (KB 906305), which would leave rotated passwords usable. 0 disables that; only
        # DCs read the value.
        Set-GPRegistryValue -Name 'Domain Good-GPO' -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' `
            -ValueName 'OldPasswordAllowedPeriod' -Type DWord -Value 0 -ErrorAction Stop | Out-Null
    }
}
