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
        # Tools on a DC that open their own RPC sessions to other DCs (Backup-GPO/Import-GPO
        # against the PDC on a rerun, repadmin) are stopped by the domain outbound Block; lsass
        # replication has its own rule. Firewall rules cannot name an AD group, so the DC
        # addresses are read from AD on every run; rerun after adding a DC or changing its IP.
        $dcAddresses = @(Get-ADDomainController -Filter * -ErrorAction Stop |
            ForEach-Object { $_.IPv4Address; $_.IPv6Address } | Where-Object { $_ } | Sort-Object -Unique)
        if ($dcAddresses.Count -eq 0) { throw 'No domain controller IP addresses were found in Active Directory.' }
        Set-CcdcGpoFirewallRule -GpoName $gpo.DisplayName -Rule @{
            Name = 'CCDC-DC-RPC-Out'; DisplayName = 'CCDC RPC to domain controllers (TCP-Out)'
            Direction = 'Outbound'; Protocol = 'TCP'; RemotePort = @('135', '49152-65535')
            RemoteAddress = $dcAddresses
        }
        Write-Status "Outbound RPC between domain controllers allowed for: $($dcAddresses -join ', ')"
        $targets = Get-CcdcDomainControllersOu
        foreach ($target in $targets) {
            Add-CcdcGpoLink -Name $gpo.DisplayName -Target $target -Enforced
        }
        Write-Status -Level Success "Imported 'DC Allow AD' and linked it to $($targets.Count) Domain Controllers OU(s)" `
            -LogMessage "Imported GPO 'DC Allow AD' and linked to $($targets -join '; ')"
    }
}
