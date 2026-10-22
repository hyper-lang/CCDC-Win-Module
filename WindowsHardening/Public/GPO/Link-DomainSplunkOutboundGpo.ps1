function Link-DomainSplunkOutboundGpo {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$BackupRoot)

    Invoke-HardeningOperation -OperationName 'Link Domain Splunk Outbound GPO' -ScriptBlock {
        $target = Get-CcdcDomainRootDn
        Invoke-CcdcGpoLinkOperation -Name 'Domain Splomk' -BackupRoot $BackupRoot `
            -Target $target -SecurityFilterGroup @('Domain Computers', 'Domain Controllers') -Enforced
    }
}
