function Link-DomainGoodGpo {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$BackupRoot)

    Invoke-HardeningOperation -OperationName 'Link Domain Good-GPO' -ScriptBlock {
        Invoke-CcdcGpoLinkOperation -Name 'Domain Good-GPO' -BackupRoot $BackupRoot -Target (Get-CcdcDomainRootDn)
    }
}
