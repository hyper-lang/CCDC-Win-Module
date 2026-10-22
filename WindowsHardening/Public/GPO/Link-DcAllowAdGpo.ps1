function Link-DcAllowAdGpo {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$BackupRoot)

    Invoke-HardeningOperation -OperationName 'Link DC Allow AD GPO' -ScriptBlock {
        # Firewall profiles come from the root-linked domain firewall GPO; this GPO layers
        # the DC-only allow rules on top of it.
        $gpo = Import-CcdcGpo -Name 'DC Allow AD' -BackupRoot $BackupRoot
        # SYSVOL replication: DFSR talks RPC between DCs from dfsrs.exe in both directions.
        Set-CcdcGpoFirewallRule -GpoName $gpo.DisplayName -Rule @{
            Name = 'CCDC-DFSR-RPC-In'; DisplayName = 'CCDC DFS Replication (RPC-In)'
            Direction = 'Inbound'; Protocol = 'TCP'; LocalPort = 'RPC'
            Program = '%SystemRoot%\system32\dfsrs.exe'
        }
        Set-CcdcGpoFirewallRule -GpoName $gpo.DisplayName -Rule @{
            Name = 'CCDC-DFSR-Out'; DisplayName = 'CCDC DFS Replication (TCP-Out)'
            Direction = 'Outbound'; Protocol = 'TCP'
            Program = '%SystemRoot%\system32\dfsrs.exe'
        }
        $targets = Get-CcdcDomainControllersOu
        foreach ($target in $targets) {
            Add-CcdcGpoLink -Name $gpo.DisplayName -Target $target
        }
        Write-Status -Level Success "Imported 'DC Allow AD' and linked it to $($targets.Count) Domain Controllers OU(s)" `
            -LogMessage "Imported GPO 'DC Allow AD' and linked to $($targets -join '; ')"
    }
}
