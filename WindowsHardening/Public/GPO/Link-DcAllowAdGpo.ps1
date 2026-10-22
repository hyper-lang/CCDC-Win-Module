function Link-DcAllowAdGpo {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$BackupRoot)

    Invoke-HardeningOperation -OperationName 'Link DC Allow AD GPO' -ScriptBlock {
        $gpo = Import-CcdcGpo -Name 'DC Allow AD' -BackupRoot $BackupRoot
        $targets = Get-CcdcDomainControllersOu
        foreach ($target in $targets) {
            Add-CcdcGpoLink -Name $gpo.DisplayName -Target $target
        }
        Write-Status -Level Success "Imported 'DC Allow AD' and linked it to $($targets.Count) Domain Controllers OU(s)" `
            -LogMessage "Imported GPO 'DC Allow AD' and linked to $($targets -join '; ')"
    }
}
