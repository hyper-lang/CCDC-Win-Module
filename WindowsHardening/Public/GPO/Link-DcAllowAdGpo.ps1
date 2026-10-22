function Link-DcAllowAdGpo {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$BackupRoot)

    Invoke-HardeningOperation -OperationName 'Link DC Allow AD GPO' -ScriptBlock {
        if (-not (Get-Module -Name NetSecurity)) { Import-Module NetSecurity -ErrorAction Stop }
        $gpo = Import-CcdcGpo -Name 'DC Allow AD' -BackupRoot $BackupRoot
        $domain = Get-ADDomain -ErrorAction Stop
        Set-NetFirewallProfile -PolicyStore "$($domain.DNSRoot)\$($gpo.DisplayName)" -Profile Domain `
            -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow `
            -AllowLocalFirewallRules False -ErrorAction Stop
        $targets = Get-CcdcDomainControllersOu
        foreach ($target in $targets) {
            Add-CcdcGpoLink -Name $gpo.DisplayName -Target $target
        }
        Write-Status -Level Success "Imported 'DC Allow AD' and linked it to $($targets.Count) Domain Controllers OU(s)" `
            -LogMessage "Imported GPO 'DC Allow AD' and linked to $($targets -join '; ')"
    }
}
