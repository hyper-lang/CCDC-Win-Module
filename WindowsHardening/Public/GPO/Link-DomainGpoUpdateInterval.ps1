function Link-DomainGpoUpdateInterval {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$BackupRoot,
        [object]$State = $null,
        [string]$StepLabel
    )
    if (-not $State) { $State = Resolve-HardeningState -State $State }


    Invoke-HardeningOperation -State $State -StepLabel $StepLabel -OperationName 'Link Domain GPO Update Interval' -ScriptBlock {
        Invoke-CcdcGpoLinkOperation -Name 'Domain GPO Update Interval' -BackupRoot $BackupRoot -Target (Get-CcdcDomainRootDn) -Enforced -State $State
    }
}
