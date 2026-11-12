function Link-DomainSplunkOutboundGpo {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$BackupRoot,
        [object]$State = $null,
        [string]$StepLabel
    )
    if (-not $State) { $State = Resolve-HardeningState -State $State }


    Invoke-HardeningOperation -State $State -StepLabel $StepLabel -OperationName 'Link Domain Splunk Outbound GPO' -ScriptBlock {
        $target = Get-CcdcDomainRootDn
        Invoke-CcdcGpoLinkOperation -Name 'Domain Splomk' -BackupRoot $BackupRoot `
            -Target $target -SecurityFilterGroup @('Domain Computers', 'Domain Controllers') -Enforced -State $State
    }
}
