function Link-DomainFirewallGpo {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$BackupRoot)

    Invoke-HardeningOperation -OperationName 'Link Domain Firewall GPO' -ScriptBlock {
        $target = Get-CcdcDomainRootDn
        Invoke-CcdcGpoLinkOperation -Name 'Domain Allow AD + Core + Default Block' -BackupRoot $BackupRoot `
            -Target $target -SecurityFilterGroup @('Domain Computers')
    }
}
